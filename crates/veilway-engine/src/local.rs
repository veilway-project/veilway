//! A local SOCKS5 and HTTP proxy for the apps' "proxy only" mode: programs that do not follow the VPN, or a browser sent through it alone, connect to a port on this device and their connections leave through the tunnel. Off unless an app starts it.
//!
//! Two ways to run it, with the same listener, login, limits and readers (`veilway_proto::proxy`, the code the node's proxy inbounds read their clients with):
//! `Local::in_tunnel` takes over a running `Tunnel`'s packet interface and opens each accepted connection as a TCP connection inside the tunnel, with a userspace TCP/IP stack that has the device's tunnel address. No system VPN, no TUN device. Names are looked up through the tunnel, by A and AAAA queries to the gateway (the node's resolver), never by the system. The platform layer must not read the tunnel's packets itself while this runs: the stack is their only reader.
//! `Local::alongside` is for a system VPN that already carries the device: connections are dialled with plain system sockets and names are resolved by the system (the VPN pins DNS to the tunnel).
//!
//! What it takes: SOCKS5 CONNECT with an address or a name, HTTP CONNECT, and plain `http://` requests (one request to a connection). `mixed` reads the first byte, 5 is SOCKS5 and anything else is HTTP. With a login set, SOCKS5 offers only username and password and HTTP needs `Proxy-Authorization: Basic`, both compared in constant time, and a source that fails five times in a minute is refused for a minute. A listen address that is not loopback is refused without a login, so a proxy reachable from the network is never open.
//! A connection is refused for a destination that is loopback, unspecified, multicast or broadcast, port 0, or an address of the tunnel stack itself, whether it was written or a name resolved to it.
//!
//! Known limits: no SOCKS5 UDP ASSOCIATE (answered "command not supported") and no BIND; plain HTTP and SOCKS5 are not encrypted on the way to the app, so a non-loopback listen address needs a network the user trusts; a connection that sits silent is closed after an hour in the tunnel mode only; a DNS answer that does not fit one UDP datagram is used for the records it has; the stack has the same single path as the tunnel, so what the exit does not carry (UDP, ICMP) is not carried here either.
use crate::engine::Command;
use crate::local_stack::{self, Fail, Stack};
use crate::{random, Event, Status, Tunnel};
use ring::hmac;
use socket2::SockRef;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{copy, copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout, Instant};
use veilway_proto::proxy::http::{self, Body, MAX_HEAD};
use veilway_proto::proxy::socks;
use veilway_proto::proxy::Target;
use veilway_proto::subscription::payload::{Network, Usage};

/// Failed logins from one source that block it, within `WINDOW`, and for how long it stays blocked after the last.
const FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(60);
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
	/// A user name and a password, each 1 to 255 bytes, and the name without a colon. When set, every connection must log in.
	pub auth: Option<(String, String)>,
	/// Connections open at once, and from one source (an IPv4 address or an IPv6 /64).
	pub max_connections: usize,
	pub per_source: usize,
	/// Time for a client to get from its first byte to a request that is read and checked.
	pub handshake: Duration,
}

impl LocalProxy {
	/// 256 connections, and from one source all of them on a loopback address and 32 on any other. 10 s to the request.
	pub fn new(listen: SocketAddr, kind: Kind) -> Self {Self {listen, kind, auth: None, max_connections: 256, per_source: if listen.ip().is_loopback() {256} else {32}, handshake: Duration::from_secs(10)}}

	/// Whether this can be started: a listen address that is not loopback has a login, and a login can be sent by the protocols.
	pub fn check(&self) -> Result<(), Error> {
		if !self.listen.ip().is_loopback() && self.auth.is_none() {return Err(Error::Open)}
		if self.auth.as_ref().is_some_and(|(user, pass)| user.is_empty() || user.len() > 255 || user.contains(':') || pass.is_empty() || pass.len() > 255) {return Err(Error::Login)}
		Ok(())
	}
}

/// Why a local proxy did not start.
#[derive(Debug)]
pub enum Error {
	/// The listen address is not loopback and no login is set.
	Open,
	/// The login cannot be used: empty, over 255 bytes, or a user name with a colon.
	Login,
	/// The address could not be listened on.
	Listen(io::Error),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Open => f.write_str("a proxy that is not on a loopback address needs a user name and a password"),
			Error::Login => f.write_str("the user name and the password must be 1 to 255 bytes, and the name has no colon"),
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
	/// Connections turned away because the proxy held its `max_connections`, because the source held its `per_source`, and because the source was blocked for its failed logins.
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
		if table.failures.get(&from).is_some_and(|(first, failed)| *failed >= FAILURES && now.saturating_duration_since(*first) < WINDOW) {
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

	/// A wrong login from `ip`: counted, logged now and then, and the source blocked at the fifth in a window.
	fn failed(&self, ip: IpAddr, now: Instant) {
		self.count(Count::Login);
		let from = source(ip);
		let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
		if table.failures.len() >= SOURCES {table.failures.retain(|_, (first, _)| now.saturating_duration_since(*first) < WINDOW)}
		let entry = table.failures.entry(from).or_insert((now, 0));
		if now.saturating_duration_since(entry.0) >= WINDOW {*entry = (now, 0)}
		entry.1 += 1;
		let failed = entry.1;
		drop(table);
		let mut logged = self.logged.lock().unwrap_or_else(|e| e.into_inner());
		if failed == FAILURES || logged.is_none_or(|last| now.saturating_duration_since(last) >= LOG_EVERY) {
			*logged = Some(now);
			tracing::info!(%from, failed, "local proxy: a login was refused{}", if failed >= FAILURES {format!(", and the source is refused for {} s", WINDOW.as_secs())} else {String::new()});
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

/// How connections are opened: inside the tunnel by the stack, or by the system.
#[derive(Clone)]
enum Dialer {System, Tunnel(Stack)}

/// An open connection to a destination, by either dialer.
enum Upstream {System(TcpStream), Tunnel(DuplexStream)}

impl Dialer {
	/// Opens a connection to `target`. A name is resolved by the dialer's own way, the addresses that are not allowed are left out, and at most two of the rest are tried.
	async fn dial(&self, target: Target) -> Result<Upstream, Fail> {
		let (addresses, port) = match target {
			Target::Address(address) => (vec![address.ip()], address.port()),
			Target::Name(name, port) => (match self {
				Dialer::System => timeout(ATTEMPT, lookup_host((name.as_str(), port))).await.map_err(|_| Fail::Timeout)?.map_err(|_| Fail::NotFound)?.map(|address| address.ip()).collect(),
				Dialer::Tunnel(stack) => stack.resolve(&name).await?,
			}, port),
		};
		let own: &[IpAddr] = match self {Dialer::System => &[], Dialer::Tunnel(stack) => &stack.own};
		let mut last = Fail::Forbidden;
		for ip in addresses.into_iter().filter(|ip| port != 0 && allowed(*ip, own)).take(ADDRESSES) {
			let to = SocketAddr::new(ip.to_canonical(), port);
			match self {
				Dialer::System => match timeout(ATTEMPT, TcpStream::connect(to)).await {
					Ok(Ok(stream)) => {
						let _ = stream.set_nodelay(true);
						return Ok(Upstream::System(stream));
					}
					Ok(Err(error)) => last = if error.kind() == io::ErrorKind::ConnectionRefused {Fail::Refused} else {Fail::Unreachable},
					Err(_) => last = Fail::Timeout,
				},
				Dialer::Tunnel(stack) => match stack.connect(to).await {
					Ok(stream) => return Ok(Upstream::Tunnel(stream)),
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

struct Shared {config: LocalProxy, login: Option<Login>, dialer: Dialer, state: Arc<State>}

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

/// Carries bytes both ways between the client and the destination. `first` goes to the destination before anything else. A plain request carries only what its framing says of the client's bytes, and then the destination's answer up to its close.
async fn carry<S: AsyncRead + AsyncWrite + Unpin>(shared: &Shared, client: &mut TcpStream, up: &mut S, first: Vec<u8>, body: Option<Body>) {
	if !first.is_empty() && up.write_all(&first).await.is_err() {return}
	let (mut sent, got) = (first.len() as u64, 0);
	let (sent, got) = match body {
		None => match copy_bidirectional(client, up).await {
			Ok((to, from)) => (sent + to, from),
			Err(_) => (sent, got),
		},
		Some(mut body) => {
			let mut buf = vec![0u8; CHUNK];
			while !body.done() {
				let Ok(n) = client.read(&mut buf).await else {return};
				if n == 0 {return}
				let used = body.take(&buf[..n]);
				if up.write_all(&buf[..used]).await.is_err() {return}
				sent += used as u64;
			}
			let from = copy(up, client).await.unwrap_or(0);
			let _ = client.shutdown().await;
			(sent, from)
		}
	};
	shared.state.add(Count::Up, sent);
	shared.state.add(Count::Down, got);
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
	let upstream = match shared.dialer.dial(target).await {
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
		Upstream::System(mut stream) => carry(&shared, &mut client, &mut stream, first, body).await,
		Upstream::Tunnel(mut stream) => carry(&shared, &mut client, &mut stream, first, body).await,
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
		let (stack, stop, task) = local_stack::start(tunnel);
		tracing::info!(listen = %config.listen, "local proxy: listening, connections go through the tunnel");
		Ok(Local::spawn(listener, config, Dialer::Tunnel(stack), Some(Carried {control, stop, task})))
	}

	/// Starts the proxy for a device that a system VPN already carries: connections are dialled by the system and names are resolved by it.
	pub async fn alongside(config: LocalProxy) -> Result<Local, Error> {
		config.check()?;
		let listener = TcpListener::bind(config.listen).await.map_err(Error::Listen)?;
		tracing::info!(listen = %config.listen, "local proxy: listening, connections go out by the system");
		Ok(Local::spawn(listener, config, Dialer::System, None))
	}

	fn spawn(listener: TcpListener, config: LocalProxy, dialer: Dialer, carried: Option<Carried>) -> Local {
		let addr = listener.local_addr().unwrap_or(config.listen);
		let shared = Arc::new(Shared {login: config.auth.as_ref().map(|(user, pass)| Login::new(user, pass)), state: Arc::new(State::new(&config)), config, dialer});
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
	pub fn select_exit(&self, tag: Option<String>) {self.send(Command::Exit(tag))}
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

	async fn start(config: LocalProxy) -> Local {Local::alongside(config).await.unwrap()}

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
		assert!(on("127.0.0.1:1", Some((&"a".repeat(255), &"p".repeat(255)))));
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
		assert!(matches!(Local::alongside(config).await, Err(Error::Open)));
	}
}
