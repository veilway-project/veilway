//! A local SOCKS5 and HTTP proxy for the apps' "proxy only" mode: programs that do not follow the VPN, or a browser sent through it alone, connect to a port on this device and their connections leave through the tunnel. Off unless an app starts it.
//!
//! Two ways to run it, with the same listener, login, limits and readers (`veilway_proto::proxy`, the code the node's proxy inbounds read their clients with):
//! `Local::in_tunnel` takes over a running `Tunnel`'s packet interface and opens each accepted connection as a TCP connection inside the tunnel, with a userspace TCP/IP stack that has the device's tunnel address. No system VPN, no TUN device. Names are looked up through the tunnel, by A and AAAA queries to the gateway (the node's resolver), never by the system. The platform layer must not read the tunnel's packets itself while this runs: the stack is their only reader.
//! `Local::alongside` is for a system VPN that already carries the device: connections are dialled with plain system sockets and names are resolved by the system (the VPN pins DNS to the tunnel). It takes the VPN's status and refuses connections while that is not `Connected`, and it refuses the device's own side of the network: link-local addresses (with the cloud metadata address), the listener's own address, and private ranges (RFC 1918, 100.64/10, fc00::/7) unless `allow_private` is set. The system has no portable list of the host's own addresses here, so what a LAN address reaches is held by the private ranges only.
//!
//! What it takes: SOCKS5 CONNECT with an address or a name, HTTP CONNECT, and plain `http://` requests (one request to a connection). `mixed` reads the first byte, 5 is SOCKS5 and anything else is HTTP. With a login set, SOCKS5 offers only username and password and HTTP needs `Proxy-Authorization: Basic`, both compared in constant time, a source that fails five times in a minute is refused for a minute, and 20 failed logins in a minute from all sources together close logins for the rest of that minute. Loopback sources share one address, so they count only in that total. Apps should always set a login (`LocalProxy::random_login`): any program on the device can reach a loopback port, and a browser page can send requests to it. A listen address that is not loopback is refused without a login, so a proxy reachable from the network is never open.
//! A connection is refused for a destination that is loopback, unspecified, multicast or broadcast, port 0, or an address of the tunnel stack itself, whether it was written or a name resolved to it.
//!
//! Known limits: no SOCKS5 UDP ASSOCIATE (answered "command not supported") and no BIND; plain HTTP and SOCKS5 are not encrypted on the way to the app, so a non-loopback listen address needs a network the user trusts; a connection that sits silent is closed after an hour; a DNS answer that does not fit one UDP datagram is used for the records it has; the stack has the same single path as the tunnel, so what the exit does not carry (UDP, ICMP) is not carried here either.
use crate::engine::Command;
use crate::local_stack::{self, Fail, Stack};
use crate::status::State as Phase;
use crate::{random, Event, Status, Tunnel};
use ring::hmac;
use socket2::SockRef;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{copy, copy_bidirectional, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, sleep_until, timeout, Instant};
use veilway_proto::proxy::http::{self, Body, MAX_CREDENTIAL, MAX_HEAD};
use veilway_proto::proxy::socks;
use veilway_proto::proxy::Target;
use veilway_proto::subscription::payload::{Network, Usage};

/// Failed logins from one source that block it, within `WINDOW`, and for how long it stays blocked after the last.
const FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(60);
/// Failed logins from all sources together that close logins for the rest of the window.
const GLOBAL: u32 = 20;
/// A connection with no byte either way for this long is closed.
const IDLE: Duration = Duration::from_secs(3600);
/// Sources whose failures are remembered at most, before the old ones are forgotten.
const SOURCES: usize = 1024;
/// One attempt at an address when the system connects, and how many addresses of a name are tried.
const ATTEMPT: Duration = Duration::from_secs(5);
const ADDRESSES: usize = 2;
/// The most a client may have sent before it is a request: the head of an HTTP request and what came with it.
const READ_CAP: usize = MAX_HEAD + 4096;
/// The most that is read from a client at once while a request body is carried.
const CHUNK: usize = 16384;
/// How often a login that failed is logged at most, so that a flood does not fill the log.
const LOG_EVERY: Duration = Duration::from_secs(10);

/// Which protocols the listener speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {Socks5, Http, Mixed}

/// What a local proxy is told once. It has no `Debug` so that its login cannot reach a log.
#[derive(Clone)]
pub struct LocalProxy {
	pub listen: SocketAddr,
	pub kind: Kind,
	/// A user name and a password, each 1 to 255 bytes, and the name without a colon (the pair as base64 must also fit `MAX_CREDENTIAL` for HTTP). When set, every connection must log in. Apps must set one, with `LocalProxy::random_login` unless the user chose their own: only a listen address that is not loopback is refused without it, because the check cannot know what else runs on the device.
	pub auth: Option<(String, String)>,
	/// Connections open at once, and from one source (an IPv4 address or an IPv6 /64).
	pub max_connections: usize,
	pub per_source: usize,
	/// Time for a client to get from its first byte to a request that is read and checked.
	pub handshake: Duration,
	/// Alongside a system VPN only: allow destinations in the private ranges (RFC 1918, 100.64/10, fc00::/7). Off by default, so that the proxy cannot be used to reach the device's own network.
	pub allow_private: bool,
}

impl LocalProxy {
	/// 256 connections, and from one source all of them on a loopback address and 32 on any other. 10 s to the request.
	pub fn new(listen: SocketAddr, kind: Kind) -> Self {Self {listen, kind, auth: None, max_connections: 256, per_source: if listen.ip().is_loopback() {256} else {32}, handshake: Duration::from_secs(10), allow_private: false}}

	/// A user name and a password of 20 letters and digits each, from the system's random source, for `auth`.
	pub fn random_login() -> (String, String) {
		const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let mut chars = Vec::with_capacity(64);
		while chars.len() < 40 {
			let mut bytes = [0u8; 64];
			random(&mut bytes).expect("the system has no random source");
			// 248 is the last multiple of 62 in a byte: the rest is dropped so that no character is likelier.
			chars.extend(bytes.iter().filter(|byte| **byte < 248).map(|byte| ALPHABET[usize::from(*byte % 62)] as char));
		}
		(chars[..20].iter().collect(), chars[20..40].iter().collect())
	}

	/// Whether this can be started: a listen address that is not loopback has a login, and a login can be sent by the protocols.
	pub fn check(&self) -> Result<(), Error> {
		if !self.listen.ip().is_loopback() && self.auth.is_none() {return Err(Error::Open)}
		if self.auth.as_ref().is_some_and(|(user, pass)| user.is_empty() || user.len() > 255 || user.contains(':') || pass.is_empty() || pass.len() > 255 || (user.len() + 1 + pass.len()).div_ceil(3) * 4 > MAX_CREDENTIAL) {return Err(Error::Login)}
		Ok(())
	}
}

/// Why a local proxy did not start.
#[derive(Debug)]
pub enum Error {
	/// The listen address is not loopback and no login is set.
	Open,
	/// The login cannot be used: empty, over 255 bytes, a user name with a colon, or too long for an HTTP credential.
	Login,
	/// The address could not be listened on.
	Listen(io::Error),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Open => f.write_str("a proxy that is not on a loopback address needs a user name and a password"),
			Error::Login => f.write_str("the user name and the password must be 1 to 255 bytes, together short enough for an HTTP credential, and the name has no colon"),
			Error::Listen(error) => write!(f, "the proxy could not listen: {error}"),
		}
	}
}

impl std::error::Error for Error {}

/// What a local proxy counted since it started. Everything but `open` only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
	/// Connections taken, and those open now.
	pub accepted: u64,
	pub open: usize,
	/// Connections turned away because the proxy held its `max_connections`, because the source held its `per_source`, and because the source was blocked for its failed logins (logins refused while logins are closed count here too).
	pub refused_limit: u64,
	pub refused_source: u64,
	pub refused_blocked: u64,
	/// Logins that were wrong, and requests that were not a request this proxy takes (malformed, BIND, UDP ASSOCIATE, too slow).
	pub login_failures: u64,
	pub bad_requests: u64,
	/// Destinations the proxy never connects to, and connections it could not open.
	pub refused_destination: u64,
	pub dial_failed: u64,
	/// Bytes of the clients' own data to their destinations (up) and back (down).
	pub up_bytes: u64,
	pub down_bytes: u64,
}

#[derive(Clone, Copy)]
enum Count {Accepted, Limit, Source, Blocked, Login, Bad, Destination, DialFailed, Up, Down}

impl Count {
	const ALL: usize = 10;
}

#[derive(Default)]
struct Table {
	/// Open connections, and by source.
	total: usize,
	by: HashMap<IpAddr, usize>,
	/// A source's first failed login of its window and how many it made in it.
	failures: HashMap<IpAddr, (Instant, u32)>,
	/// The first failed login of the window across all sources and how many there were.
	all: Option<(Instant, u32)>,
}

impl Table {
	fn blocked(&self, from: IpAddr, now: Instant) -> bool {self.failures.get(&from).is_some_and(|(first, failed)| *failed >= FAILURES && now.saturating_duration_since(*first) < WINDOW)}
}

struct State {
	counts: [AtomicU64; Count::ALL],
	table: Mutex<Table>,
	max: usize,
	per_source: usize,
	full: AtomicBool,
	failing: AtomicBool,
	logged: Mutex<Option<Instant>>,
}

/// A place among the connections, given back when it is dropped.
struct Slot {state: Arc<State>, source: IpAddr}

impl Drop for Slot {
	fn drop(&mut self) {
		let mut table = self.state.table.lock().unwrap_or_else(|e| e.into_inner());
		table.total -= 1;
		if let Some(held) = table.by.get_mut(&self.source) {
			*held -= 1;
			if *held == 0 {table.by.remove(&self.source);}
		}
		if table.total < self.state.max && self.state.full.swap(false, Ordering::Relaxed) {tracing::info!("local proxy: below its {} connections, taking new ones again", self.state.max)}
	}
}

/// An IPv4 address, or the /64 of an IPv6 one.
fn source(ip: IpAddr) -> IpAddr {
	match ip.to_canonical() {
		IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
		v4 => v4,
	}
}

impl State {
	fn new(config: &LocalProxy) -> State {State {counts: Default::default(), table: Mutex::default(), max: config.max_connections, per_source: config.per_source, full: AtomicBool::new(false), failing: AtomicBool::new(false), logged: Mutex::new(None)}}

	fn count(&self, count: Count) {self.add(count, 1)}

	fn add(&self, count: Count, by: u64) {self.counts[count as usize].fetch_add(by, Ordering::Relaxed);}

	/// A place for a connection from `ip`, or None with the refusal counted.
	fn admit(self: &Arc<State>, ip: IpAddr, now: Instant) -> Option<Slot> {
		let from = source(ip);
		let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
		if table.blocked(from, now) {
			self.count(Count::Blocked);
			return None;
		}
		if table.total >= self.max {
			self.count(Count::Limit);
			if !self.full.swap(true, Ordering::Relaxed) {tracing::info!("local proxy: {} connections are open, refusing new ones until some close", self.max)}
			return None;
		}
		let held = table.by.get(&from).copied().unwrap_or(0);
		if held >= self.per_source {
			self.count(Count::Source);
			return None;
		}
		table.total += 1;
		table.by.insert(from, held + 1);
		self.count(Count::Accepted);
		Some(Slot {state: self.clone(), source: from})
	}

	/// Whether a login from `ip` is looked at: not while the source is blocked, and not once the sources together failed `GLOBAL` times in the window. Asked right before each login is checked, because the connection was admitted before its failures were known.
	fn login_open(&self, ip: IpAddr, now: Instant) -> bool {
		let table = self.table.lock().unwrap_or_else(|e| e.into_inner());
		let shut = table.all.is_some_and(|(first, failed)| failed >= GLOBAL && now.saturating_duration_since(first) < WINDOW);
		if shut || table.blocked(source(ip), now) {
			drop(table);
			self.count(Count::Blocked);
			return false;
		}
		true
	}

	/// A wrong login from `ip`: counted, logged now and then, and the source blocked at the fifth in a window. A loopback source is never blocked by itself, since every program on the device shares it, and only counts in the total of all sources.
	fn failed(&self, ip: IpAddr, now: Instant) {
		self.count(Count::Login);
		let from = source(ip);
		let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
		let all = match table.all {
			Some((first, failed)) if now.saturating_duration_since(first) < WINDOW => (first, failed + 1),
			_ => (now, 1),
		};
		table.all = Some(all);
		let mut failed = all.1;
		if !from.is_loopback() {
			if table.failures.len() >= SOURCES {table.failures.retain(|_, (first, _)| now.saturating_duration_since(*first) < WINDOW)}
			let entry = table.failures.entry(from).or_insert((now, 0));
			if now.saturating_duration_since(entry.0) >= WINDOW {*entry = (now, 0)}
			entry.1 += 1;
			failed = entry.1;
		}
		drop(table);
		let mut logged = self.logged.lock().unwrap_or_else(|e| e.into_inner());
		if all.1 == GLOBAL {tracing::info!("local proxy: {GLOBAL} logins failed within {} s, logins are refused for the rest of that time", WINDOW.as_secs())}
		if (!from.is_loopback() && failed == FAILURES) || logged.is_none_or(|last| now.saturating_duration_since(last) >= LOG_EVERY) {
			*logged = Some(now);
			tracing::info!(%from, failed, "local proxy: a login was refused{}", if !from.is_loopback() && failed >= FAILURES {format!(", and the source is refused for {} s", WINDOW.as_secs())} else {String::new()});
		}
	}

	fn totals(&self) -> Totals {
		let get = |count: Count| self.counts[count as usize].load(Ordering::Relaxed);
		Totals {accepted: get(Count::Accepted), open: self.table.lock().unwrap_or_else(|e| e.into_inner()).total, refused_limit: get(Count::Limit), refused_source: get(Count::Source), refused_blocked: get(Count::Blocked), login_failures: get(Count::Login), bad_requests: get(Count::Bad), refused_destination: get(Count::Destination), dial_failed: get(Count::DialFailed), up_bytes: get(Count::Up), down_bytes: get(Count::Down)}
	}
}

/// The login, held as two keyed digests so that comparing never depends on where the bytes differ, and the lengths of the two are not told either.
struct Login {key: hmac::Key, user: hmac::Tag, pass: hmac::Tag}

impl Login {
	fn new(user: &str, pass: &str) -> Login {
		let mut bytes = [0u8; 32];
		let _ = random(&mut bytes);
		let key = hmac::Key::new(hmac::HMAC_SHA256, &bytes);
		Login {user: hmac::sign(&key, user.as_bytes()), pass: hmac::sign(&key, pass.as_bytes()), key}
	}

	fn check(&self, user: &[u8], pass: &[u8]) -> bool {hmac::verify(&self.key, user, self.user.as_ref()).is_ok() & hmac::verify(&self.key, pass, self.pass.as_ref()).is_ok()}
}

/// Whether the proxy connects to `ip`. `own` are the addresses of the stack that would connect.
fn allowed(ip: IpAddr, own: &[IpAddr]) -> bool {
	let ip = ip.to_canonical();
	!(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) || own.contains(&ip))
}

/// What the system dialer also refuses: link-local addresses (which holds the metadata address of the clouds) always, and private ranges (RFC 1918, 100.64/10 and fc00::/7) unless `private` is set. `ip` is canonical.
fn host_side(ip: IpAddr, private: bool) -> bool {
	match ip {
		IpAddr::V4(v4) => !(v4.is_link_local() || !private && (v4.is_private() || v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)),
		IpAddr::V6(v6) => !(v6.segments()[0] & 0xffc0 == 0xfe80 || !private && v6.segments()[0] & 0xfe00 == 0xfc00),
	}
}

/// How connections are opened: inside the tunnel by the stack, or by the system. `own` is the listener's address and `private` the setting of `allow_private`.
#[derive(Clone)]
enum Dialer {System {own: Arc<[IpAddr]>, private: bool}, Tunnel(Stack)}

/// An open connection to a destination, by either dialer. The flag of a tunnel connection says that it ended in a reset.
enum Upstream {System(TcpStream), Tunnel(DuplexStream, Arc<AtomicBool>)}

impl Dialer {
	/// Opens a connection to `target`. A name is resolved by the dialer's own way, the addresses that are not allowed are left out, and at most two of the rest are tried.
	async fn dial(&self, target: Target) -> Result<Upstream, Fail> {
		let (addresses, port) = match target {
			Target::Address(address) => (vec![address.ip()], address.port()),
			Target::Name(name, port) => (match self {
				Dialer::System {..} => timeout(ATTEMPT, lookup_host((name.as_str(), port))).await.map_err(|_| Fail::Timeout)?.map_err(|_| Fail::NotFound)?.map(|address| address.ip()).collect(),
				Dialer::Tunnel(stack) => stack.resolve(&name).await?,
			}, port),
		};
		let (own, private) = match self {Dialer::System {own, private} => (&**own, Some(*private)), Dialer::Tunnel(stack) => (&*stack.own, None)};
		let mut last = Fail::Forbidden;
		for ip in addresses.into_iter().filter(|ip| port != 0 && allowed(*ip, own) && private.is_none_or(|private| host_side(ip.to_canonical(), private))).take(ADDRESSES) {
			let to = SocketAddr::new(ip.to_canonical(), port);
			match self {
				Dialer::System {..} => match timeout(ATTEMPT, TcpStream::connect(to)).await {
					Ok(Ok(stream)) => {
						let _ = stream.set_nodelay(true);
						return Ok(Upstream::System(stream));
					}
					Ok(Err(error)) => last = if error.kind() == io::ErrorKind::ConnectionRefused {Fail::Refused} else {Fail::Unreachable},
					Err(_) => last = Fail::Timeout,
				},
				Dialer::Tunnel(stack) => match stack.connect(to).await {
					Ok((stream, reset)) => return Ok(Upstream::Tunnel(stream, reset)),
					Err(fail) => last = fail,
				},
			}
		}
		Err(last)
	}
}

/// What the handshake settled: where to connect, how the client is answered once it is connected, and the bytes to send first.
struct Asked {target: Target, front: Front, first: Vec<u8>}

enum Front {Socks, Connect, Plain(Body)}

/// `vpn` is the status of the system VPN that a proxy alongside it relies on.
struct Shared {config: LocalProxy, login: Option<Login>, dialer: Dialer, state: Arc<State>, vpn: Option<watch::Receiver<Status>>}

/// Reads more of the client's bytes, within the cap.
async fn more(client: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<()> {
	if buf.len() >= READ_CAP {return Err(io::ErrorKind::InvalidData.into())}
	let mut chunk = [0u8; 2048];
	let n = client.read(&mut chunk).await?;
	if n == 0 {return Err(io::ErrorKind::UnexpectedEof.into())}
	buf.extend_from_slice(&chunk[..n]);
	Ok(())
}

/// Closes the write side after an answer was written and discards what the client still sends, for up to 64 KiB and 1 s: closing with unread bytes makes the system reset the connection, and a reset can take the answer with it.
async fn linger(client: &mut TcpStream) {
	let _ = client.shutdown().await;
	let (mut sink, mut left) = ([0u8; 4096], 64 * 1024usize);
	let _ = timeout(Duration::from_secs(1), async {
		while left > 0 {
			match client.read(&mut sink).await {
				Ok(n) if n > 0 => left = left.saturating_sub(n),
				_ => break,
			}
		}
	}).await;
}

fn http_answer(status: &str, challenge: bool) -> Vec<u8> {format!("HTTP/1.1 {status}\r\n{}Connection: close\r\nContent-Length: 0\r\n\r\n", if challenge {"Proxy-Authenticate: Basic realm=\"veilway\"\r\n"} else {""}).into_bytes()}

/// Reads the client up to a request this proxy takes. None when the client was answered instead and the connection ends.
async fn handshake(shared: &Shared, client: &mut TcpStream, from: IpAddr) -> io::Result<Option<Asked>> {
	let mut buf = Vec::with_capacity(1024);
	while buf.is_empty() {more(client, &mut buf).await?}
	let socks5 = match shared.config.kind {Kind::Socks5 => true, Kind::Http => false, Kind::Mixed => buf[0] == 5};
	if socks5 {
		let used = loop {
			match socks::greeting(&buf) {
				Ok(Some((_, used))) => break used,
				Ok(None) => more(client, &mut buf).await?,
				Err(()) => {
					shared.state.count(Count::Bad);
					return Ok(None);
				}
			}
		};
		let method = if shared.login.is_some() {buf[2..used].contains(&2).then_some(2)} else {buf[2..used].contains(&0).then_some(0)};
		let Some(method) = method else {
			shared.state.count(Count::Bad);
			client.write_all(&[5, 0xff]).await?;
			return Ok(None);
		};
		client.write_all(&[5, method]).await?;
		buf.drain(..used);
		if let Some(login) = shared.login.as_ref() {
			let ((user, pass), used) = loop {
				match socks::credentials(&buf) {
					Ok(Some(read)) => break read,
					Ok(None) => more(client, &mut buf).await?,
					Err(()) => {
						shared.state.count(Count::Bad);
						client.write_all(&[1, 1]).await?;
						return Ok(None);
					}
				}
			};
			buf.drain(..used);
			if !shared.state.login_open(from, Instant::now()) {
				client.write_all(&[1, 1]).await?;
				return Ok(None);
			}
			if !login.check(&user, &pass) {
				shared.state.failed(from, Instant::now());
				client.write_all(&[1, 1]).await?;
				return Ok(None);
			}
			client.write_all(&[1, 0]).await?;
		}
		let (request, used) = loop {
			match socks::request(&buf) {
				Ok(Some(read)) => break read,
				Ok(None) => more(client, &mut buf).await?,
				Err(code) => {
					shared.state.count(Count::Bad);
					client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
					return Ok(None);
				}
			}
		};
		buf.drain(..used);
		if request.command != socks::CONNECT {
			shared.state.count(Count::Bad);
			client.write_all(&[5, socks::UNSUPPORTED_COMMAND, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
			return Ok(None);
		}
		return Ok(Some(Asked {target: request.target, front: Front::Socks, first: buf}));
	}
	let (mut request, used) = loop {
		match http::read(&buf) {
			Ok(Some(read)) => break read,
			Ok(None) => more(client, &mut buf).await?,
			Err(bad) => {
				shared.state.count(Count::Bad);
				client.write_all(&http_answer(bad.status(), false)).await?;
				return Ok(None);
			}
		}
	};
	if let Some(login) = shared.login.as_ref() {
		if request.authorization.is_some() && !shared.state.login_open(from, Instant::now()) {
			client.write_all(&http_answer("429 Too Many Requests", false)).await?;
			return Ok(None);
		}
		let given = request.authorization.as_deref().and_then(http::basic);
		if !given.is_some_and(|(user, pass)| login.check(&user, &pass)) {
			if request.authorization.is_some() {shared.state.failed(from, Instant::now())}
			client.write_all(&http_answer("407 Proxy Authentication Required", true)).await?;
			return Ok(None);
		}
	}
	if request.connect {return Ok(Some(Asked {target: request.target, front: Front::Connect, first: buf.split_off(used)}))}
	let taken = request.body.take(&buf[used..]);
	let mut first = request.head;
	first.extend_from_slice(&buf[used..used + taken]);
	Ok(Some(Asked {target: request.target, front: Front::Plain(request.body), first}))
}

/// One end of a connection while it is carried: every byte that is read is counted (`count`), the time of the last byte either way is kept for the idle timeout, and a read that ends where the stack says the connection was reset is an error, so that the other end is reset too instead of being closed cleanly.
struct Watched<S> {inner: S, state: Arc<State>, count: Count, seen: Arc<AtomicU64>, began: Instant, reset: Option<Arc<AtomicBool>>}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let before = buf.filled().len();
		let result = Pin::new(&mut self.inner).poll_read(cx, buf);
		if let Poll::Ready(Ok(())) = &result {
			let got = buf.filled().len() - before;
			if got > 0 {
				self.state.add(self.count, got as u64);
				self.seen.store(self.began.elapsed().as_millis() as u64, Ordering::Relaxed);
			} else if self.reset.as_ref().is_some_and(|reset| reset.load(Ordering::Relaxed)) {return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))}
		}
		result
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let result = Pin::new(&mut self.inner).poll_write(cx, buf);
		if matches!(result, Poll::Ready(Ok(n)) if n > 0) {self.seen.store(self.began.elapsed().as_millis() as u64, Ordering::Relaxed)}
		result
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_flush(cx)}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.inner).poll_shutdown(cx)}
}

/// Carries bytes both ways between the client and the destination, until either ends or nothing moves for `IDLE`. `first` goes to the destination before anything else. A plain request carries only what its framing says of the client's bytes, with the destination's answer coming back meanwhile (so `Expect: 100-continue` works), and then the answer up to the destination's close. A reset on either side resets the other.
async fn carry<S: AsyncRead + AsyncWrite + Unpin>(shared: &Shared, client: &mut TcpStream, up: &mut S, reset: Option<Arc<AtomicBool>>, first: Vec<u8>, body: Option<Body>) {
	let (seen, began) = (Arc::new(AtomicU64::new(0)), Instant::now());
	let mut client = Watched {inner: client, state: shared.state.clone(), count: Count::Up, seen: seen.clone(), began, reset: None};
	let mut up = Watched {inner: up, state: shared.state.clone(), count: Count::Down, seen: seen.clone(), began, reset};
	shared.state.add(Count::Up, first.len() as u64);
	if !first.is_empty() && up.write_all(&first).await.is_err() {return}
	let work = async {
		match body {
			None => copy_bidirectional(&mut client, &mut up).await.map(|_| ()),
			Some(mut body) => {
				let ((mut from_client, mut to_client), (mut from_up, mut to_up)) = (split(&mut client), split(&mut up));
				let upload = async {
					let mut buf = vec![0u8; CHUNK];
					while !body.done() {
						let n = from_client.read(&mut buf).await?;
						if n == 0 {return Err(io::ErrorKind::UnexpectedEof.into())}
						let used = body.take(&buf[..n]);
						to_up.write_all(&buf[..used]).await?;
					}
					Ok::<(), io::Error>(())
				};
				let download = async {
					copy(&mut from_up, &mut to_client).await?;
					let _ = to_client.shutdown().await;
					Ok::<(), io::Error>(())
				};
				tokio::try_join!(upload, download).map(|_| ())
			}
		}
	};
	let idle = async {
		loop {
			let due = began + Duration::from_millis(seen.load(Ordering::Relaxed)) + IDLE;
			if Instant::now() >= due {return}
			sleep_until(due).await;
		}
	};
	let ended = tokio::select! {result = work => Some(result), _ = idle => None};
	// An error is an abort, not a close: the client is reset, not told the data is complete.
	if !matches!(ended, Some(Ok(()))) {let _ = SockRef::from(&*client.inner).set_linger(Some(Duration::ZERO));}
}

async fn connection(shared: Arc<Shared>, mut client: TcpStream, peer: SocketAddr, _slot: Slot) {
	let _ = client.set_nodelay(true);
	let asked = match timeout(shared.config.handshake, handshake(&shared, &mut client, peer.ip())).await {
		Ok(Ok(Some(asked))) => asked,
		Ok(Ok(None)) => return linger(&mut client).await,
		Ok(Err(_)) => return,
		Err(_) => {
			shared.state.count(Count::Bad);
			return;
		}
	};
	let Asked {target, front, first} = asked;
	let dialed = if shared.vpn.as_ref().is_some_and(|vpn| !matches!(vpn.borrow().state, Phase::Connected {..})) {Err(Fail::Down)} else {shared.dialer.dial(target).await};
	let upstream = match dialed {
		Ok(upstream) => {
			if shared.state.failing.swap(false, Ordering::Relaxed) {tracing::info!("local proxy: connections are opening again")}
			upstream
		}
		Err(fail) => {
			if fail == Fail::Forbidden {
				shared.state.count(Count::Destination);
			} else {
				shared.state.count(Count::DialFailed);
				if !shared.state.failing.swap(true, Ordering::Relaxed) {tracing::info!(?fail, "local proxy: a connection could not be opened, and others may fail the same way")}
			}
			let answer = if matches!(front, Front::Socks) {vec![5, fail.socks(), 0, 1, 0, 0, 0, 0, 0, 0]} else {http_answer(fail.status(), false)};
			if client.write_all(&answer).await.is_ok() {linger(&mut client).await}
			return;
		}
	};
	let (body, answer) = match front {
		Front::Socks => (None, Some(&[5u8, 0, 0, 1, 0, 0, 0, 0, 0, 0][..])),
		Front::Connect => (None, Some(&b"HTTP/1.1 200 Connection Established\r\n\r\n"[..])),
		Front::Plain(body) => (Some(body), None),
	};
	if let Some(answer) = answer {if client.write_all(answer).await.is_err() {return}}
	match upstream {
		Upstream::System(mut stream) => carry(&shared, &mut client, &mut stream, None, first, body).await,
		Upstream::Tunnel(mut stream, reset) => carry(&shared, &mut client, &mut stream, Some(reset), first, body).await,
	}
}

async fn accept(shared: Arc<Shared>, listener: TcpListener) {
	let (mut connections, mut failing) = (JoinSet::new(), false);
	loop {
		tokio::select! {
			accepted = listener.accept() => match accepted {
				Ok((stream, peer)) => {
					failing = false;
					match shared.state.admit(peer.ip(), Instant::now()) {
						Some(slot) => {connections.spawn(connection(shared.clone(), stream, peer, slot));}
						None => {let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));}
					}
				}
				Err(error) => {
					if !failing {tracing::warn!("local proxy: the system did not accept a connection ({}). Connections are tried again every 200 ms", error.kind())}
					failing = true;
					sleep(Duration::from_millis(200)).await;
				}
			},
			Some(_) = connections.join_next(), if !connections.is_empty() => {}
		}
	}
}

/// What an app reaches of the tunnel a `Local` took over.
struct Control {commands: mpsc::UnboundedSender<Command>, status: watch::Receiver<Status>, events: broadcast::Sender<Event>}

struct Carried {control: Control, stop: oneshot::Sender<()>, task: JoinHandle<Status>}

/// A running local proxy. Dropping it stops the listener and the connections, and a tunnel it took over with them; `stop` gives the tunnel's last status.
pub struct Local {addr: SocketAddr, shared: Arc<Shared>, listener: JoinHandle<()>, carried: Option<Carried>}

impl Local {
	/// Starts the proxy on `tunnel`, which it takes over: from now on it is the only reader of the tunnel's packets, and the tunnel is reached through the methods below. Connections are opened inside the tunnel and fail at once while no session is open. On an error the tunnel comes back untouched.
	/// Called inside a tokio runtime.
	pub async fn in_tunnel(tunnel: Tunnel, config: LocalProxy) -> Result<Local, (Error, Tunnel)> {
		if let Err(error) = config.check() {return Err((error, tunnel))}
		let listener = match TcpListener::bind(config.listen).await {
			Ok(listener) => listener,
			Err(error) => return Err((Error::Listen(error), tunnel)),
		};
		let control = Control {commands: tunnel.commands.clone(), status: tunnel.status.clone(), events: tunnel.events.clone()};
		let (stack, stop, task) = local_stack::start(tunnel, config.max_connections);
		tracing::info!(listen = %config.listen, "local proxy: listening, connections go through the tunnel");
		Ok(Local::spawn(listener, config, Dialer::Tunnel(stack), None, Some(Carried {control, stop, task})))
	}

	/// Starts the proxy for a device that a system VPN already carries: connections are dialled by the system and names are resolved by it. `vpn` is that VPN's status: while it is not `Connected` new connections are refused (SOCKS5 reply 1, HTTP 503), so that nothing leaves outside the VPN. The listener's own address, link-local addresses and, unless `allow_private` is set, the private ranges are never connected to.
	pub async fn alongside(config: LocalProxy, vpn: watch::Receiver<Status>) -> Result<Local, Error> {
		config.check()?;
		let listener = TcpListener::bind(config.listen).await.map_err(Error::Listen)?;
		let own: Arc<[IpAddr]> = listener.local_addr().map(|address| address.ip().to_canonical()).into_iter().collect();
		tracing::info!(listen = %config.listen, "local proxy: listening, connections go out by the system");
		let dialer = Dialer::System {own, private: config.allow_private};
		Ok(Local::spawn(listener, config, dialer, Some(vpn), None))
	}

	fn spawn(listener: TcpListener, config: LocalProxy, dialer: Dialer, vpn: Option<watch::Receiver<Status>>, carried: Option<Carried>) -> Local {
		let addr = listener.local_addr().unwrap_or(config.listen);
		let shared = Arc::new(Shared {login: config.auth.as_ref().map(|(user, pass)| Login::new(user, pass)), state: Arc::new(State::new(&config)), config, dialer, vpn});
		Local {addr, listener: tokio::spawn(accept(shared.clone(), listener)), shared, carried}
	}

	/// The address it listens on, with the port the system gave when the config asked for 0.
	pub fn addr(&self) -> SocketAddr {self.addr}
	pub fn totals(&self) -> Totals {self.shared.state.totals()}
	/// The tunnel's status, when the proxy runs on one.
	pub fn status(&self) -> Option<Status> {self.carried.as_ref().map(|carried| carried.control.status.borrow().clone())}
	pub fn watch(&self) -> Option<watch::Receiver<Status>> {self.carried.as_ref().map(|carried| carried.control.status.clone())}
	pub fn events(&self) -> Option<broadcast::Receiver<Event>> {self.carried.as_ref().map(|carried| carried.control.events.subscribe())}
	/// What `Tunnel` offers an app that owns it, for the tunnel under this proxy. They do nothing for a proxy that runs alongside a system VPN.
	pub fn select_exit(&self, tag: Option<String>) {
		if let Dialer::Tunnel(stack) = &self.shared.dialer {stack.flush()}
		self.send(Command::Exit(tag));
	}

	pub fn connect_again(&self) {self.send(Command::Again)}
	pub fn moved(&self, network: String, networks: Vec<Network>) {self.send(Command::Moved(network, networks))}
	pub fn reprobe(&self) {self.send(Command::Reprobe)}
	pub fn refreshed(&self, usage: Option<Usage>) {self.send(Command::Refreshed(usage))}

	fn send(&self, command: Command) {
		if let Some(carried) = &self.carried {let _ = carried.control.commands.send(command);}
	}

	/// Stops listening, closes the connections and stops the tunnel it took over, and gives that tunnel's last status.
	pub async fn stop(mut self) -> Option<Status> {
		self.listener.abort();
		let carried = self.carried.take()?;
		let _ = carried.stop.send(());
		carried.task.await.ok()
	}
}

impl Drop for Local {
	fn drop(&mut self) {self.listener.abort()}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn config(auth: Option<(&str, &str)>) -> LocalProxy {
		let mut config = LocalProxy::new("127.0.0.1:0".parse().unwrap(), Kind::Mixed);
		config.auth = auth.map(|(user, pass)| (user.to_owned(), pass.to_owned()));
		config
	}

	fn vpn(connected: bool) -> (watch::Sender<Status>, watch::Receiver<Status>) {
		let mut status = Status::off(String::new(), 1400);
		if connected {status.state = Phase::Connected {exit: None}}
		watch::channel(status)
	}

	async fn start(config: LocalProxy) -> Local {Local::alongside(config, vpn(true).1).await.unwrap()}

	/// A connected client that has sent `bytes`, and what the proxy answered with.
	async fn ask(local: &Local, bytes: &[u8]) -> Vec<u8> {
		let mut client = TcpStream::connect(local.addr()).await.unwrap();
		client.write_all(bytes).await.unwrap();
		let mut answer = Vec::new();
		let _ = timeout(Duration::from_secs(5), client.read_to_end(&mut answer)).await;
		answer
	}

	#[test]
	fn a_listen_address_that_is_not_loopback_needs_a_login_and_the_login_must_be_sendable() {
		let on = |address: &str, auth: Option<(&str, &str)>| {
			let mut config = LocalProxy::new(address.parse().unwrap(), Kind::Socks5);
			config.auth = auth.map(|(user, pass)| (user.to_owned(), pass.to_owned()));
			config.check().is_ok()
		};
		assert!(on("127.0.0.1:1080", None) && on("[::1]:1080", None));
		for address in ["0.0.0.0:1080", "192.168.1.5:1080", "[::]:1080", "[fe80::1]:1080"] {
			assert!(!on(address, None), "{address} without a login");
			assert!(on(address, Some(("a", "b"))), "{address} with one");
		}
		assert!(!on("127.0.0.1:1", Some(("", "b"))) && !on("127.0.0.1:1", Some(("a", ""))) && !on("127.0.0.1:1", Some(("a:b", "c"))) && !on("127.0.0.1:1", Some((&"a".repeat(256), "c"))));
		assert!(!on("127.0.0.1:1", Some((&"a".repeat(255), &"p".repeat(255)))), "255 and 255 bytes do not fit an HTTP credential");
		assert!(!on("127.0.0.1:1", Some((&"a".repeat(200), &"p".repeat(190)))) && on("127.0.0.1:1", Some((&"a".repeat(200), &"p".repeat(180)))));
	}

	#[test]
	fn a_login_matches_only_the_exact_pair() {
		let login = Login::new("user", "pass");
		assert!(login.check(b"user", b"pass"));
		for (user, pass) in [(&b"user"[..], &b"pas"[..]), (b"use", b"pass"), (b"User", b"pass"), (b"user", b"passs"), (b"", b""), (b"pass", b"user")] {assert!(!login.check(user, pass), "{user:?} {pass:?}");}
	}

	#[test]
	fn what_is_not_a_place_to_connect_is_not_allowed() {
		let own: Vec<IpAddr> = vec!["100.64.0.2".parse().unwrap(), "fd00::2".parse().unwrap()];
		for ip in ["127.0.0.1", "127.9.9.9", "::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "::ffff:127.0.0.1", "::ffff:100.64.0.2", "100.64.0.2", "fd00::2"] {assert!(!allowed(ip.parse().unwrap(), &own), "{ip}");}
		for ip in ["93.184.216.34", "2606:4700::1111", "10.0.0.1", "100.64.0.3", "::ffff:93.184.216.34"] {assert!(allowed(ip.parse().unwrap(), &own), "{ip}");}
	}

	#[tokio::test]
	async fn a_source_holds_its_share_and_a_failing_one_is_blocked_for_a_while_and_then_let_in() {
		let mut config = config(None);
		(config.max_connections, config.per_source) = (3, 2);
		let (state, now) = (Arc::new(State::new(&config)), Instant::now());
		let (one, two): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
		let (a, b) = (state.admit(one, now).unwrap(), state.admit(one, now).unwrap());
		assert!(state.admit(one, now).is_none());
		let c = state.admit(two, now).unwrap();
		assert!(state.admit(two, now).is_none(), "the proxy is full");
		assert_eq!((state.totals().refused_source, state.totals().refused_limit, state.totals().open), (1, 1, 3));
		drop((a, b, c));
		assert_eq!(state.totals().open, 0);
		for _ in 0..FAILURES {state.failed(one, now)}
		assert!(state.admit(one, now + Duration::from_secs(30)).is_none() && state.admit(two, now).is_some());
		assert_eq!((state.totals().login_failures, state.totals().refused_blocked), (u64::from(FAILURES), 1));
		assert!(state.admit(one, now + WINDOW + Duration::from_secs(1)).is_some(), "a block does not last");
		let (six, other): (IpAddr, IpAddr) = ("2001:db8::1".parse().unwrap(), "2001:db8::ffff".parse().unwrap());
		for _ in 0..FAILURES {state.failed(six, now)}
		assert!(state.admit(other, now).is_none(), "a /64 is one source");
	}

	#[tokio::test]
	async fn the_proxy_refuses_what_it_does_not_carry_with_the_answers_of_the_protocols() {
		let local = start(config(Some(("user", "pass")))).await;
		// SOCKS5 offering only "no authentication" is not let in.
		assert_eq!(ask(&local, &[5, 1, 0]).await, [5, 0xff]);
		// A wrong password is refused by RFC 1929, a right one is let on to the request.
		assert_eq!(ask(&local, &[&[5, 1, 2][..], &[1, 4], b"user", &[4], b"nope"].concat()).await, [5, 2, 1, 1]);
		let login = [&[5, 1, 2][..], &[1, 4], b"user", &[4], b"pass"].concat();
		let with = |request: &[u8]| [login.clone(), request.to_vec()].concat();
		assert_eq!(ask(&local, &with(&[5, 2, 0, 1, 93, 184, 216, 34, 0, 80])).await, [5, 2, 1, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0], "BIND");
		assert_eq!(ask(&local, &with(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])).await, [5, 2, 1, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0], "UDP ASSOCIATE");
		assert_eq!(ask(&local, &with(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])).await, [5, 2, 1, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0], "loopback");
		assert_eq!(ask(&local, &with(&[5, 1, 0, 1, 93, 184, 216, 34, 0, 0])).await, [5, 2, 1, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0], "port 0");
		// HTTP asks for the login first, and a wrong one counts as a failure.
		let plain = b"GET http://93.184.216.34/ HTTP/1.1\r\n\r\n";
		assert!(ask(&local, plain).await.starts_with(b"HTTP/1.1 407 "));
		assert!(ask(&local, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpub3Bl\r\n\r\n").await.starts_with(b"HTTP/1.1 407 "));
		assert!(ask(&local, b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n").await.starts_with(b"HTTP/1.1 403 "));
		assert!(ask(&local, b"BREW / HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n").await.starts_with(b"HTTP/1.1 400 "));
		let totals = local.totals();
		assert_eq!((totals.login_failures, totals.refused_destination), (2, 3), "{totals:?}");
		assert_eq!(totals.bad_requests, 4, "{totals:?}");
	}

	#[tokio::test]
	async fn a_client_that_says_nothing_is_dropped_at_the_deadline_and_its_place_is_given_back() {
		let mut config = config(None);
		config.handshake = Duration::from_millis(200);
		let local = start(config).await;
		let mut client = TcpStream::connect(local.addr()).await.unwrap();
		client.write_all(&[5]).await.unwrap();
		let mut rest = Vec::new();
		assert!(timeout(Duration::from_secs(3), client.read_to_end(&mut rest)).await.is_ok());
		sleep(Duration::from_millis(100)).await;
		assert_eq!((local.totals().open, local.totals().bad_requests), (0, 1));
	}

	#[tokio::test]
	async fn a_proxy_that_is_not_loopback_does_not_start_without_a_login() {
		let config = LocalProxy::new("0.0.0.0:0".parse().unwrap(), Kind::Mixed);
		assert!(matches!(Local::alongside(config, vpn(true).1).await, Err(Error::Open)));
	}

	#[test]
	fn a_random_login_is_twenty_letters_and_digits_each_and_never_the_same_twice() {
		let ((user, pass), (other, _)) = (LocalProxy::random_login(), LocalProxy::random_login());
		assert!(user.len() == 20 && pass.len() == 20 && user != pass && user != other);
		assert!(user.chars().chain(pass.chars()).all(|c| c.is_ascii_alphanumeric()));
		let mut config = config(None);
		config.auth = Some((user, pass));
		assert!(config.check().is_ok());
	}

	#[test]
	fn the_system_dialer_keeps_off_the_hosts_own_side_of_the_network() {
		for ip in ["169.254.169.254", "169.254.1.1", "fe80::1", "10.0.0.1", "172.16.5.5", "192.168.1.1", "100.64.0.1", "100.127.255.1", "fd00::1", "fc00::1"] {assert!(!host_side(ip.parse().unwrap(), false), "{ip}");}
		for ip in ["169.254.169.254", "fe80::1"] {assert!(!host_side(ip.parse().unwrap(), true), "{ip} even when private is allowed");}
		for ip in ["10.0.0.1", "192.168.1.1", "100.64.0.1", "fd00::1"] {assert!(host_side(ip.parse().unwrap(), true), "{ip} when private is allowed");}
		for ip in ["93.184.216.34", "100.63.0.1", "100.128.0.1", "172.32.0.1", "2606:4700::1111"] {assert!(host_side(ip.parse().unwrap(), false), "{ip}");}
	}

	#[tokio::test]
	async fn loopback_failures_do_not_block_a_second_loopback_client_but_all_sources_together_close_logins() {
		let state = Arc::new(State::new(&config(None)));
		let (now, loopback, far): (Instant, IpAddr, IpAddr) = (Instant::now(), "127.0.0.1".parse().unwrap(), "192.0.2.9".parse().unwrap());
		for _ in 0..FAILURES + 3 {state.failed(loopback, now)}
		assert!(state.admit(loopback, now).is_some() && state.login_open(loopback, now), "loopback is not blocked by source");
		for _ in 0..GLOBAL - FAILURES - 3 {state.failed(loopback, now)}
		assert!(!state.login_open(far, now) && !state.login_open(loopback, now), "the total closes logins for everyone");
		assert!(state.admit(far, now).is_some(), "connections are still taken");
		assert!(state.login_open(far, now + WINDOW + Duration::from_secs(1)), "and it lasts one window");
		assert_eq!(state.totals().refused_blocked, 2);
		let far_state = Arc::new(State::new(&config(None)));
		for _ in 0..FAILURES {far_state.failed(far, now)}
		assert!(!far_state.login_open(far, now) && far_state.login_open("192.0.2.10".parse().unwrap(), now), "another source is let in");
	}

	#[tokio::test]
	async fn a_login_that_began_before_the_block_is_not_checked_once_logins_are_closed() {
		let local = start(config(Some(("user", "pass")))).await;
		let login = [&[5, 1, 2][..], &[1, 4], b"user", &[4], b"pass"].concat();
		for _ in 0..GLOBAL {assert_eq!(ask(&local, &[&[5, 1, 2][..], &[1, 4], b"user", &[4], b"nope"].concat()).await, [5, 2, 1, 1])}
		assert_eq!(ask(&local, &login).await, [5, 2, 1, 1], "the right login is refused too");
		assert!(ask(&local, b"CONNECT 93.184.216.34:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n").await.starts_with(b"HTTP/1.1 429 "));
		assert!(local.totals().refused_blocked >= 2, "{:?}", local.totals());
	}

	#[tokio::test]
	async fn alongside_a_vpn_nothing_is_dialled_while_it_is_not_connected_and_the_hosts_side_is_refused() {
		let (sender, receiver) = vpn(false);
		let local = Local::alongside(config(None), receiver).await.unwrap();
		let request = |ip: [u8; 4]| [&[5, 1, 0][..], &[5, 1, 0, 1], &ip, &[0, 80]].concat();
		assert_eq!(ask(&local, &request([93, 184, 216, 34])).await[2..], [5, 1, 0, 1, 0, 0, 0, 0, 0, 0], "down: general failure");
		assert!(ask(&local, b"GET http://93.184.216.34/ HTTP/1.1\r\n\r\n").await.starts_with(b"HTTP/1.1 503 "));
		sender.send_modify(|status| status.state = Phase::Connected {exit: None});
		for ip in [[10, 0, 0, 1], [169, 254, 169, 254], [100, 64, 0, 1], [192, 168, 0, 1]] {assert_eq!(ask(&local, &request(ip)).await[2..], [5, 2, 0, 1, 0, 0, 0, 0, 0, 0], "{ip:?}");}
		assert!(ask(&local, b"CONNECT [fd00::1]:80 HTTP/1.1\r\n\r\n").await.starts_with(b"HTTP/1.1 403 "));
		assert_eq!((local.totals().refused_destination, local.totals().dial_failed), (5, 2));
	}
}
