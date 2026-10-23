//! Proxy inbounds: `socks5`, `http` and `mixed` listeners that let other software use this node as a plain proxy. Every connection logs in as a user, with that user's name and `proxy_password`, and then is a flow of that user like any other: it runs the same code the Xray add-on's hop runs after its own login (`xray::connect` and `xray::relay`), so the destination gate, the rules, the user's exits and entitlement, the quota and the counters of the user and of the exit all apply, and a user who is cut off loses the connection within a second. UDP ASSOCIATE is `xray_udp::associate`, with a relay on the node's own address that carries only what the client's IP address sends.
//! There is no way in without a login, and no method but username and password. Nothing here is encrypted, so an address that strangers reach is only taken with the operator's `public`, and is then a warning (config validation).
//! What the listener holds is bounded: connections in all and for each source, logins in flight, and a handshake that must finish in `HANDSHAKE`. A source that fails `FAILURES` logins to one user name within `WINDOW` is refused that name until the window is over, and answers to a name that many logins failed for are delayed, whoever asks. A loopback peer is a front the operator runs, with every user behind one address, so it is held to neither the share of a source nor the block. A login that fails is counted and said at info, at most once in `NOTED`, with no password in it. The passwords are compared as two tags of one key, which takes the same time whatever the guess is, and a name that is no user's takes it as well.
//! The front ends are `proxy_socks` and `proxy_http`, which read the bytes and do no IO. `mixed` looks at the first byte: 0x05 is SOCKS5, anything else is read as HTTP.
use super::plan::{Backend, Plan};
use super::proxy_http::{self, Body};
use super::proxy_socks as socks;
use super::route::Reason;
use super::tunnel::{reset, source};
use super::xray::{connect, relay, reply, Refused, Target};
use super::xray_owner::{self, Lookup};
use super::xray_udp::{self, Via};
use super::Shared;
use crate::config::{ProxyInbound, ProxyType, RuleTransport};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{sleep, timeout};

/// How long a connection has to log in and say what it wants, and to be written an answer.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Logins one source may fail to one user name within `WINDOW` before the inbound refuses that source that name until the window is over.
const FAILURES: u32 = 10;
/// Failures of a name the inbound answers at once, and the wait each failure beyond them adds to an answer for that name, up to `MAX_WAIT`.
const FREE_FAILURES: u32 = 2;
const WAIT: Duration = Duration::from_millis(100);
const MAX_WAIT: Duration = Duration::from_secs(2);
const WINDOW: Duration = Duration::from_secs(60);
/// Entries each failure table keeps. A new one that finds a table full takes the place of the oldest, so a flood of names cannot keep the count of another from growing.
const SOURCES: usize = 4096;
/// At most one line at info for refused logins in this long, which says how many there were.
const NOTED: Duration = Duration::from_secs(10);

/// Made anew for each run of the node: the tags in a plan are of this process and are never stored.
static KEY: LazyLock<hmac::Key> = LazyLock::new(|| {
	let mut key = [0u8; 32];
	SystemRandom::new().fill(&mut key).expect("the system has no random source");
	hmac::Key::new(hmac::HMAC_SHA256, &key)
});

/// What a proxy password comes to: the tag the plan keeps in the place of the password, and what a guess is turned into before it is compared with it.
pub fn tag(password: &[u8]) -> [u8; 32] {
	let mut out = [0u8; 32];
	out.copy_from_slice(hmac::sign(&KEY, password).as_ref());
	out
}

/// The destination a client names with a host and a port: an address, or a name in lower case that is resolved by the node. A name may hold letters, digits, hyphens, underscores and dots, up to 253 bytes, with no empty label. A trailing dot is dropped.
pub fn destination(host: &str, port: u16) -> Option<Target> {
	let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
	if let Ok(ip) = host.parse::<IpAddr>() {return Some(Target::Address(SocketAddr::new(ip, port)))}
	(!host.is_empty() && host.len() <= 253 && !host.starts_with('.') && !host.contains("..") && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))).then_some(Target::Name(host, port))
}

#[derive(Clone, Copy, Debug)]
enum Count {Opened, Login, Limit, Source, Busy, Blocked, Up, Down}

impl Count {
	const ALL: usize = 8;
}

/// What an inbound counted since it started. Everything but `open` only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
	/// Connections that were taken, and those open now.
	pub opened: u64,
	pub open: usize,
	/// Logins that were refused: no such user, a wrong password, a user the inbound does not admit.
	pub refused_logins: u64,
	/// Connections turned away because the inbound held its `connections`, because the source held its `per_source`, and because `handshakes` were in flight. Logins refused unheard because the source had failed too many to that name.
	pub refused_limit: u64,
	pub refused_source: u64,
	pub refused_busy: u64,
	pub refused_blocked: u64,
	/// Bytes the clients sent to their destinations (up) and got back (down), headers of a plain HTTP request included and the protocol's own handshake not.
	pub up_bytes: u64,
	pub down_bytes: u64,
}

#[derive(Default)]
struct Held {open: usize, by: HashMap<IpAddr, usize>}

/// Failures in a row of a login within `WINDOW`: when the count began, and how many.
type Streak = (Instant, u32);

#[derive(Default)]
struct Failed {by: HashMap<(IpAddr, String), Streak>, names: HashMap<String, Streak>, noted: Option<Instant>, since: u64}

/// Adds a failure to `key`. A count older than `WINDOW` starts over, and a table that is full gives up its oldest entry for a new key.
fn bump<K: Hash + Eq + Clone>(table: &mut HashMap<K, Streak>, key: &K, now: Instant) {
	if !table.contains_key(key) && table.len() >= SOURCES {
		table.retain(|_, (start, _)| now.saturating_duration_since(*start) < WINDOW);
		if table.len() >= SOURCES {
			let oldest = table.iter().min_by_key(|(_, (start, _))| *start).map(|(key, _)| key.clone());
			if let Some(oldest) = oldest {table.remove(&oldest);}
		}
	}
	let entry = table.entry(key.clone()).or_insert((now, 0));
	if now.saturating_duration_since(entry.0) >= WINDOW {*entry = (now, 0)}
	entry.1 += 1;
}

/// What a running inbound counts and holds.
#[derive(Default)]
pub struct State {counts: [AtomicU64; Count::ALL], held: Mutex<Held>, failed: Mutex<Failed>}

/// A place among the inbound's connections, given back when it is dropped.
struct Place {state: Arc<State>, source: Option<IpAddr>}

impl Drop for Place {
	fn drop(&mut self) {
		let mut held = self.state.held.lock().unwrap_or_else(|e| e.into_inner());
		held.open -= 1;
		let Some(source) = self.source else {return};
		if let Some(here) = held.by.get_mut(&source) {
			*here -= 1;
			if *here == 0 {held.by.remove(&source);}
		}
	}
}

impl State {
	fn count(&self, count: Count) {self.counts[count as usize].fetch_add(1, Ordering::Relaxed);}

	fn bytes(&self, up: bool, n: usize) {self.counts[if up {Count::Up} else {Count::Down} as usize].fetch_add(n as u64, Ordering::Relaxed);}

	/// A place for a connection from `ip`, or what to count when there is none: the inbound holds `most` connections, or the source holds `per`. A source is an IPv4 address or an IPv6 /64. A loopback peer is a local front with many users behind it and is held to `most` alone.
	fn admit(self: &Arc<State>, ip: IpAddr, most: usize, per: usize) -> Result<Place, Count> {
		let (from, mut held) = (source(ip), self.held.lock().unwrap_or_else(|e| e.into_inner()));
		let here = held.by.get(&from).copied().unwrap_or(0);
		if held.open >= most {return Err(Count::Limit)}
		if here >= per && !ip.is_loopback() {return Err(Count::Source)}
		held.open += 1;
		if ip.is_loopback() {return Ok(Place {state: self.clone(), source: None})}
		held.by.insert(from, here + 1);
		Ok(Place {state: self.clone(), source: Some(from)})
	}

	/// Whether `ip` has failed `FAILURES` logins to `name` within `WINDOW`. A loopback peer never has.
	fn blocked(&self, ip: IpAddr, name: &str, now: Instant) -> bool {
		!ip.is_loopback() && self.failed.lock().unwrap_or_else(|e| e.into_inner()).by.get(&(source(ip), name.to_string())).is_some_and(|(start, n)| now.saturating_duration_since(*start) < WINDOW && *n >= FAILURES)
	}

	/// How long an answer for `name` waits: nothing for the first failures within `WINDOW`, then `WAIT` more for each, up to `MAX_WAIT`. It is the name's, whoever asks, so guessing at one user from many addresses slows down as it goes, and a user is slowed for what is tried against their name.
	fn wait(&self, name: &str, now: Instant) -> Duration {
		let failures = self.failed.lock().unwrap_or_else(|e| e.into_inner()).names.get(name).filter(|(start, _)| now.saturating_duration_since(*start) < WINDOW).map_or(0, |(_, n)| *n);
		(WAIT * failures.saturating_sub(FREE_FAILURES)).min(MAX_WAIT)
	}

	/// A login to `name` from `ip` that was refused: counted, held against the source and the name, and said at info when no line was said for `NOTED`.
	fn refused(&self, tag: &str, ip: IpAddr, name: &str, now: Instant) {
		self.count(Count::Login);
		let said = {
			let mut failed = self.failed.lock().unwrap_or_else(|e| e.into_inner());
			if !ip.is_loopback() {bump(&mut failed.by, &(source(ip), name.to_string()), now)}
			bump(&mut failed.names, &name.to_string(), now);
			failed.since += 1;
			if failed.noted.is_none_or(|at| now.saturating_duration_since(at) >= NOTED) {
				failed.noted = Some(now);
				Some(std::mem::take(&mut failed.since))
			} else {None}
		};
		if let Some(n) = said {tracing::info!("inbound {tag}: {n} login(s) refused since the last line, the latest from {ip}")}
	}

	pub fn totals(&self) -> Totals {
		let get = |count: Count| self.counts[count as usize].load(Ordering::Relaxed);
		Totals {opened: get(Count::Opened), open: self.held.lock().unwrap_or_else(|e| e.into_inner()).open, refused_logins: get(Count::Login), refused_limit: get(Count::Limit), refused_source: get(Count::Source), refused_busy: get(Count::Busy), refused_blocked: get(Count::Blocked), up_bytes: get(Count::Up), down_bytes: get(Count::Down)}
	}
}

/// What a connection of one inbound shares: the node, the inbound as written, what it counts and how it asks for the code that carries a user's connections. The connections a user holds and the UDP they relay are counted in `Shared`, for every door together.
struct Door {shared: Arc<Shared>, inbound: ProxyInbound, state: Arc<State>, via: Arc<Via>}

impl Door {
	/// Whether a login of user `name` that was checked against `digest` still stands under `plan`: the user is there, with the same password, and the inbound still admits them. A reload that removes the inbound, the user or the password, or leaves the user out of `users` and `groups`, ends their connections here.
	fn holds(&self, plan: &Plan, name: &str, digest: [u8; 32]) -> bool {
		plan.users.iter().take(plan.people).position(|candidate| candidate.name == name).is_some_and(|at| plan.users[at].proxy == Some(digest) && plan.proxies.get(&self.inbound.tag).and_then(|may| may.get(at)).copied() == Some(true))
	}
}

/// Who logged in: the plan they were checked against, their place in it, the tag of the password they gave and what they asked for. `up` is what the client sent with its request, which goes to the destination first, and `body` how much more of what it sends belongs to a plain HTTP request: None for the other fronts, which carry everything.
struct Asked {plan: Arc<Plan>, at: usize, digest: [u8; 32], target: Target, up: Vec<u8>, body: Option<Body>}

/// The way a client is answered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Front {Socks, Connect, Plain}

enum Next {Carry(Front, Asked), Associate(Asked)}

/// The answer of an HTTP front end: a status line, no body, and the connection closed after it. With `challenge` it asks for the Basic login.
fn answer(status: &str, challenge: bool) -> String {format!("HTTP/1.1 {status}\r\n{}Connection: close\r\nContent-Length: 0\r\n\r\n", if challenge {"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"} else {""})}

/// Checks a login against the plan in force: the user is one the config has, their password is the one given, the inbound admits them. The plan, their place in it and the tag of the password are given back. A name no user has is compared against a tag of nothing, so that the time a refusal takes says neither.
fn login(shared: &Shared, inbound: &str, user: &[u8], password: &[u8]) -> Option<(Arc<Plan>, usize, [u8; 32])> {
	let plan = shared.plan();
	let (given, at) = (tag(password), std::str::from_utf8(user).ok().and_then(|name| plan.users.iter().take(plan.people).position(|candidate| candidate.name == name)));
	let expected = at.and_then(|at| plan.users[at].proxy);
	let same = hmac::verify(&KEY, &given, hmac::sign(&KEY, &expected.unwrap_or([0; 32])).as_ref()).is_ok();
	let at = at.filter(|at| same && expected.is_some() && plan.proxies.get(inbound).and_then(|may| may.get(*at)).copied() == Some(true))?;
	Some((plan, at, given))
}

/// `login` for a front end: a source that failed `FAILURES` logins to this name is refused without being heard, an answer for a name that many logins failed for waits, and a login that fails is held against both.
async fn check(door: &Door, peer: SocketAddr, user: &[u8], password: &[u8]) -> Option<(Arc<Plan>, usize, [u8; 32])> {
	let (name, now) = (String::from_utf8_lossy(&user[..user.len().min(64)]).to_string(), Instant::now());
	if door.state.blocked(peer.ip(), &name, now) {
		door.state.count(Count::Blocked);
		return None;
	}
	let wait = door.state.wait(&name, now);
	if !wait.is_zero() {sleep(wait).await}
	let found = login(&door.shared, &door.inbound.tag, user, password);
	if found.is_none() {door.state.refused(&door.inbound.tag, peer.ip(), &name, Instant::now())}
	found
}

/// Reads what more the client has sent, into `buf`.
async fn more(client: &mut TcpStream, buf: &mut Vec<u8>) -> anyhow::Result<()> {
	let mut chunk = [0u8; 4096];
	let n = client.read(&mut chunk).await?;
	anyhow::ensure!(n > 0, "closed in the middle of the handshake");
	buf.extend_from_slice(&chunk[..n]);
	Ok(())
}

/// RFC 1928 and RFC 1929: the greeting, the login and the request.
async fn socks_front(door: &Door, client: &mut TcpStream, buf: &mut Vec<u8>, peer: SocketAddr) -> anyhow::Result<Next> {
	let offers = loop {
		match socks::greeting(buf).map_err(|_| anyhow::anyhow!("not a socks5 greeting"))? {
			Some((offers, used)) => {
				buf.drain(..used);
				break offers;
			}
			None => more(client, buf).await?,
		}
	};
	if !offers {
		client.write_all(&[5, 0xff]).await?;
		anyhow::bail!("username and password was not offered");
	}
	client.write_all(&[5, 2]).await?;
	let (user, pass) = loop {
		match socks::credentials(buf).map_err(|_| anyhow::anyhow!("not a username and password"))? {
			Some((given, used)) => {
				buf.drain(..used);
				break given;
			}
			None => more(client, buf).await?,
		}
	};
	let Some((plan, at, digest)) = check(door, peer, &user, &pass).await else {
		client.write_all(&[1, 1]).await?;
		anyhow::bail!("login refused");
	};
	client.write_all(&[1, 0]).await?;
	let request = loop {
		match socks::request(buf) {
			Ok(Some((request, used))) => {
				buf.drain(..used);
				break request;
			}
			Ok(None) => more(client, buf).await?,
			Err(code) => {
				client.write_all(&reply(code)).await?;
				anyhow::bail!("user {}: request refused with {code}", plan.users[at].name);
			}
		}
	};
	if request.command == socks::ASSOCIATE && !door.inbound.udp() {
		client.write_all(&reply(socks::UNSUPPORTED_COMMAND)).await?;
		anyhow::bail!("user {}: udp is off", plan.users[at].name);
	}
	let asked = Asked {plan, at, digest, target: request.target, up: std::mem::take(buf), body: None};
	Ok(if request.command == socks::CONNECT {Next::Carry(Front::Socks, asked)} else {Next::Associate(asked)})
}

/// A CONNECT, or a request for an `http://` URI, with a Basic login. A request without a login gets the challenge and a request with a wrong one gets it too, and is counted.
async fn http_front(door: &Door, client: &mut TcpStream, buf: &mut Vec<u8>, peer: SocketAddr) -> anyhow::Result<Next> {
	let (request, used) = loop {
		match proxy_http::read(buf) {
			Ok(Some(done)) => break done,
			Ok(None) => more(client, buf).await?,
			Err(bad) => {
				client.write_all(answer(bad.status(), false).as_bytes()).await?;
				anyhow::bail!("a request that is not taken: {bad:?}");
			}
		}
	};
	buf.drain(..used);
	let found = match request.authorization.as_deref().and_then(proxy_http::basic) {
		Some((user, pass)) => check(door, peer, &user, &pass).await,
		None => None,
	};
	let Some((plan, at, digest)) = found else {
		// A header that is no login at all counts as a failure, which a request without one does not (a browser makes one first).
		if request.authorization.is_some() && proxy_http::basic(request.authorization.as_deref().unwrap_or_default()).is_none() {door.state.refused(&door.inbound.tag, peer.ip(), "", Instant::now())}
		client.write_all(answer("407 Proxy Authentication Required", true).as_bytes()).await?;
		anyhow::bail!("no login");
	};
	let (front, mut body, mut rest) = (if request.connect {Front::Connect} else {Front::Plain}, request.body, std::mem::take(buf));
	if front == Front::Plain {rest.truncate(body.take(&rest))}
	Ok(Next::Carry(front, Asked {plan, at, digest, target: request.target, up: [request.head, rest].concat(), body: (front == Front::Plain).then_some(body)}))
}

/// What a connection does once its client is logged in and has said what it wants.
async fn carry(door: &Door, mut client: TcpStream, front: Front, asked: Asked) -> anyhow::Result<()> {
	let (shared, Asked {plan, at, digest, target, up, body}) = (&door.shared, asked);
	let user = plan.users[at].name.clone();
	let refuse = async |client: &mut TcpStream, reason: Reason, code: u8| {
		shared.count(reason);
		let bytes = if front == Front::Socks {reply(code).to_vec()} else {answer(match code {2 => "403 Forbidden", 1 => "503 Service Unavailable", _ => "502 Bad Gateway"}, false).into_bytes()};
		let _ = timeout(HANDSHAKE, client.write_all(&bytes)).await;
	};
	if plan.users[at].denied.is_some() {
		refuse(&mut client, Reason::Entitlement, 2).await;
		anyhow::bail!("user {user}: cut off");
	}
	if matches!(&target, Target::Address(addr) if addr.port() == 0) || matches!(&target, Target::Name(_, 0)) {
		refuse(&mut client, Reason::Unparsable, 2).await;
		anyhow::bail!("user {user}: port 0");
	}
	let mut opened = match connect(shared, plan, at, target, &door.via, Some(if front == Front::Socks {RuleTransport::Socks5} else {RuleTransport::Http})).await {
		Ok(opened) => opened,
		Err(Refused {reason, code, why}) => {
			refuse(&mut client, reason, code).await;
			return Err(why);
		}
	};
	match front {
		Front::Socks => client.write_all(&reply(0)).await?,
		Front::Connect => client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?,
		Front::Plain => {}
	}
	let idle = match &opened.plan.exits[opened.exit].backend {
		Backend::Netstack {tcp_idle, ..} => Some(*tcp_idle),
		_ => None,
	};
	relay(shared, &mut opened, &mut client, &up, body, &|up, n| door.state.bytes(up, n), idle, &|now| door.holds(now, &user, digest), &door.via.label).await;
	Ok(())
}

async fn session(door: &Door, mut client: TcpStream, peer: SocketAddr, permit: OwnedSemaphorePermit) -> anyhow::Result<()> {
	let mut buf = Vec::new();
	// What `mixed` looks at to tell the two apart and the whole of the login share one deadline.
	let next = timeout(HANDSHAKE, async {
		let socks = match door.inbound.kind {
			ProxyType::Socks5 => true,
			ProxyType::Http => false,
			ProxyType::Mixed => {
				let mut first = [0u8; 1];
				anyhow::ensure!(client.peek(&mut first).await? == 1, "closed before it sent anything");
				first[0] == 5
			}
		};
		if socks {socks_front(door, &mut client, &mut buf, peer).await} else {http_front(door, &mut client, &mut buf, peer).await}
	}).await??;
	drop(permit);
	match next {
		Next::Carry(front, asked) => carry(door, client, front, asked).await,
		Next::Associate(Asked {plan, at, digest, target, ..}) => {
			let user = plan.users[at].name.clone();
			if plan.users[at].denied.is_some() {
				door.shared.count(Reason::Entitlement);
				let _ = timeout(HANDSHAKE, client.write_all(&reply(2))).await;
				anyhow::bail!("user {user}: cut off");
			}
			xray_udp::associate(door.shared.clone(), client, user.clone(), target, door.via.clone(), &|now| door.holds(now, &user, digest)).await
		}
	}
}

/// Starts the inbound: it accepts on its socket until the task is aborted, and the connections it has go with it.
pub(super) fn serve(shared: &Arc<Shared>, inbound: ProxyInbound, listener: Arc<TcpListener>, state: Arc<State>) -> AbortHandle {
	// A loopback inbound ties a datagram to the user id that owns the control connection, as the hop of Xray does, where the system tells who owns a socket. Any other inbound asks the client for the port it sends from.
	let owner = (cfg!(target_os = "linux") && inbound.loopback()).then(|| Arc::new(xray_owner::lookup) as Lookup);
	let via = Arc::new(Via {label: format!("inbound {}", inbound.tag), owner, inbound: Some(inbound.tag.clone())});
	let door = Arc::new(Door {shared: shared.clone(), inbound, state, via});
	tokio::spawn(accept(door, listener)).abort_handle()
}

async fn accept(door: Arc<Door>, listener: Arc<TcpListener>) {
	let (handshakes, mut sessions, mut failing) = (Arc::new(Semaphore::new(door.inbound.handshakes())), JoinSet::new(), false);
	loop {
		tokio::select! {
			accepted = listener.accept() => match accepted {
				Ok((stream, peer)) => {
					failing = false;
					let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
					let place = match door.state.admit(peer.ip(), door.inbound.connections(), door.inbound.per_source()) {
						Ok(place) => place,
						Err(count) => {
							door.state.count(count);
							reset(&stream);
							continue;
						}
					};
					let Ok(permit) = handshakes.clone().try_acquire_owned() else {
						door.state.count(Count::Busy);
						reset(&stream);
						continue;
					};
					door.state.count(Count::Opened);
					let door = door.clone();
					sessions.spawn(async move {
						if let Err(e) = session(&door, stream, peer, permit).await {tracing::debug!("{}: {e:#}", door.via.label)}
						drop(place);
					});
				}
				Err(e) => {
					if !failing {tracing::warn!("{}: the system did not accept a connection ({}). Connections are tried again every 200 ms", door.via.label, e.kind())}
					failing = true;
					sleep(Duration::from_millis(200)).await;
				}
			},
			Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn answers_for_a_name_slow_down_with_the_failures_to_it_and_not_with_those_to_another() {
		let (state, now) = (State::default(), Instant::now());
		let ip: IpAddr = "203.0.113.5".parse().unwrap();
		assert_eq!(state.wait("alice", now), Duration::ZERO);
		for _ in 0..FREE_FAILURES {state.refused("s", ip, "alice", now)}
		assert_eq!(state.wait("alice", now), Duration::ZERO, "the first failures are answered at once");
		for _ in 0..3 {state.refused("s", "198.51.100.9".parse().unwrap(), "alice", now)}
		assert_eq!(state.wait("alice", now), WAIT * 3, "a name slows down with failures from every source");
		assert_eq!(state.wait("bob", now), Duration::ZERO);
		for _ in 0..100 {state.refused("s", ip, "alice", now)}
		assert_eq!(state.wait("alice", now), MAX_WAIT);
		assert_eq!(state.wait("alice", now + WINDOW), Duration::ZERO, "a window that is over forgets");
		assert_eq!(state.totals().refused_logins, 105);
	}

	#[test]
	fn a_full_table_gives_up_its_oldest_entry_and_never_stops_counting_new_ones() {
		let (state, start) = (State::default(), Instant::now());
		for n in 0..SOURCES {state.refused("s", "203.0.113.5".parse().unwrap(), &format!("name{n}"), start + Duration::from_millis(n as u64))}
		let now = start + Duration::from_secs(1);
		for _ in 0..FAILURES {state.refused("s", "203.0.113.5".parse().unwrap(), "fresh", now)}
		assert!(state.blocked("203.0.113.5".parse().unwrap(), "fresh", now), "a source that found the table full was not counted");
		let failed = state.failed.lock().unwrap();
		assert!(failed.by.len() <= SOURCES && failed.names.len() <= SOURCES && !failed.names.contains_key("name0"), "the oldest entry was not the one that went");
	}

	#[test]
	fn a_loopback_peer_is_held_to_the_total_and_nothing_else() {
		let state = Arc::new(State::default());
		let loopback: IpAddr = "127.0.0.1".parse().unwrap();
		let places: Vec<_> = (0..3).map(|_| state.admit(loopback, 3, 1).unwrap()).collect();
		assert!(matches!(state.admit(loopback, 3, 1), Err(Count::Limit)));
		drop(places);
		let outside: IpAddr = "203.0.113.5".parse().unwrap();
		let _one = state.admit(outside, 3, 1).unwrap();
		assert!(matches!(state.admit(outside, 3, 1), Err(Count::Source)));
		assert!(state.blocked(loopback, "alice", Instant::now()) == false);
	}
}
