//! Proxy inbounds: `socks5`, `http` and `mixed` listeners that let other software use this node as a plain proxy. Every connection logs in as a user, with that user's name and `proxy_password`, and then is a flow of that user like any other: it runs the same code the Xray add-on's hop runs after its own login (`xray::connect` and `xray::relay`), so the destination gate, the rules, the user's exits and entitlement, the quota and the counters of the user and of the exit all apply, and a user who is cut off loses the connection within a second. UDP ASSOCIATE is `xray_udp::associate`, with a relay on the node's own address that carries only what the client's IP address sends.
//! There is no way in without a login, and no method but username and password. Nothing here is encrypted, so an address that strangers reach is only taken with the operator's `public`, and is then a warning (config validation).
//! What the listener holds is bounded: connections in all and for each source, logins in flight, and a handshake that must finish in `HANDSHAKE`. A source that fails `FAILURES` logins to one user name within `WINDOW` is refused that name until the window is over, and answers to a name that many logins failed for are delayed, whoever asks. A loopback peer is a front the operator runs, with every user behind one address, so it is held to neither the share of a source nor the block. A login that fails is counted and said at info, at most once in `NOTED`, with no password in it. The passwords are compared as two tags of one key, which takes the same time whatever the guess is, and a name that is no user's takes it as well.
//! The front ends are `veilway_proto::proxy::socks` and `veilway_proto::proxy::http`, which read the bytes and do no IO. `mixed` looks at the first byte: 0x05 is SOCKS5, anything else is read as HTTP.
use super::plan::{Backend, Plan};
use super::route::Reason;
use super::tunnel::{reset, source};
use super::xray::{connect, linger, relay, reply, Refused};
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
use veilway_proto::proxy::http::{self as proxy_http, Body};
use veilway_proto::proxy::{socks, Target};

/// How long a connection has to log in and say what it wants, and to be written an answer.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Logins one source may fail to one user name within `WINDOW` before the inbound refuses that source that name until the window is over.
const FAILURES: u32 = 10;
/// Failures of a name the inbound answers at once, and the wait each failure beyond them adds to an answer for that name, up to `MAX_WAIT`.
const FREE_FAILURES: u32 = 2;
const WAIT: Duration = Duration::from_millis(100);
const MAX_WAIT: Duration = Duration::from_secs(2);
const WINDOW: Duration = Duration::from_secs(60);
/// Entries each failure table keeps. A table that is full gives up the entry with the lowest count and never one that is blocked or at its longest wait, so a flood of new keys cannot push out a count that matters.
const SOURCES: usize = 4096;
/// How many user names one source may hold failure counts for. A source that tries more is refused every name until the window is over, which is also what keeps it from flooding the tables with names of its own making.
const NAMES_PER_SOURCE: u32 = 16;
/// Logins in flight one source may have, and the share of the inbound's `handshakes` that peers on loopback have together.
const SHAKING_PER_SOURCE: usize = 8;
/// How long a client has to send its first byte, inside `HANDSHAKE`.
const GREETING: Duration = Duration::from_secs(3);
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
	/// UDP datagrams dropped because they did not come from the address and port the client named for its association (or, with `udp_any_port`, from its address): what a client behind a NAT that rewrites ports is refused for.
	pub refused_udp_source: u64,
	/// Connections turned away because the inbound held its `connections`, because the source held its `per_source`, and because `handshakes` were in flight. Logins refused unheard because the source had failed too many to that name.
	pub refused_limit: u64,
	pub refused_source: u64,
	pub refused_busy: u64,
	pub refused_blocked: u64,
	/// Bytes the clients sent to their destinations (up) and got back (down), headers of a plain HTTP request included and the protocol's own handshake not.
	pub up_bytes: u64,
	pub down_bytes: u64,
}

/// `shaking` counts the logins in flight by source, with the peers on loopback together under None.
#[derive(Default)]
struct Held {open: usize, by: HashMap<IpAddr, usize>, shaking: HashMap<Option<IpAddr>, usize>}

/// Failures in a row of a login within `WINDOW`: when the count began, and how many.
type Streak = (Instant, u32);

#[derive(Default)]
struct Failed {by: HashMap<(IpAddr, String), Streak>, names: HashMap<String, Streak>, sources: HashMap<IpAddr, Streak>, noted: Option<Instant>, since: u64}

/// Whether a count is still inside its window.
fn live(streak: &Streak, now: Instant) -> bool {now.saturating_duration_since(streak.0) < WINDOW}

/// Adds a failure to `key` and says whether it is kept. A count older than `WINDOW` starts over. A table that is full forgets what is over first, then gives up the entry with the lowest count (the oldest of those), and never one at `protect` or more. When every entry is protected a new key is not kept.
fn bump<K: Hash + Eq + Clone>(table: &mut HashMap<K, Streak>, key: &K, now: Instant, protect: u32) -> bool {
	if !table.contains_key(key) && table.len() >= SOURCES {
		table.retain(|_, streak| live(streak, now));
		if table.len() >= SOURCES {
			let weakest = table.iter().filter(|(_, (_, n))| *n < protect).min_by_key(|(_, (start, n))| (*n, *start)).map(|(key, _)| key.clone());
			match weakest {
				Some(weakest) => drop(table.remove(&weakest)),
				None => return false,
			}
		}
	}
	let entry = table.entry(key.clone()).or_insert((now, 0));
	if !live(entry, now) {*entry = (now, 0)}
	entry.1 += 1;
	true
}

/// What a running inbound counts and holds. `mismatch` counts the datagrams of UDP associations that came from another source than the client named, which the relays count into it.
#[derive(Default)]
pub struct State {counts: [AtomicU64; Count::ALL], held: Mutex<Held>, failed: Mutex<Failed>, mismatch: Arc<AtomicU64>}

/// A place among the logins in flight, given back when it is dropped.
struct Shake {state: Arc<State>, key: Option<IpAddr>}

impl Drop for Shake {
	fn drop(&mut self) {
		let mut held = self.state.held.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(here) = held.shaking.get_mut(&self.key) {
			*here -= 1;
			if *here == 0 {held.shaking.remove(&self.key);}
		}
	}
}

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

	/// A place among the logins in flight: `total` in all, at most `SHAKING_PER_SOURCE` for a source, and for the peers on loopback together half of `total`. Idle clients that never log in cannot hold every place this way.
	fn shake(self: &Arc<State>, ip: IpAddr, total: usize) -> Option<Shake> {
		let key = (!ip.is_loopback()).then(|| source(ip));
		let most = if key.is_none() {(total / 2).max(1)} else {SHAKING_PER_SOURCE.min(total)};
		let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
		let here = held.shaking.entry(key).or_default();
		if *here >= most {return None}
		*here += 1;
		Some(Shake {state: self.clone(), key})
	}

	/// Whether `ip` has failed `FAILURES` logins to `name` within `WINDOW`, or has tried more than `NAMES_PER_SOURCE` names. A loopback peer never has.
	fn blocked(&self, ip: IpAddr, name: &str, now: Instant) -> bool {
		let (failed, from) = (self.failed.lock().unwrap_or_else(|e| e.into_inner()), source(ip));
		!ip.is_loopback() && (failed.by.get(&(from, name.to_string())).is_some_and(|streak| live(streak, now) && streak.1 >= FAILURES) || failed.sources.get(&from).is_some_and(|streak| live(streak, now) && streak.1 > NAMES_PER_SOURCE))
	}

	/// How long an answer for `name` waits: nothing for the first failures within `WINDOW`, then `WAIT` more for each, up to `MAX_WAIT`. It is the name's, whoever asks, so guessing at one user from many addresses slows down as it goes, and a user is slowed for what is tried against their name.
	fn wait(&self, name: &str, now: Instant) -> Duration {
		let failures = self.failed.lock().unwrap_or_else(|e| e.into_inner()).names.get(name).filter(|(start, _)| now.saturating_duration_since(*start) < WINDOW).map_or(0, |(_, n)| *n);
		(WAIT * failures.saturating_sub(FREE_FAILURES)).min(MAX_WAIT)
	}

	/// A login to `name` from `ip` that was refused: counted, held against the source and the name, and said at info when no line was said for `NOTED`, without the address or the name, which are at debug.
	fn refused(&self, tag: &str, ip: IpAddr, name: &str, now: Instant) {
		self.count(Count::Login);
		tracing::debug!("inbound {tag}: a login to {name} from {ip} was refused");
		let said = {
			let mut failed = self.failed.lock().unwrap_or_else(|e| e.into_inner());
			if !ip.is_loopback() {
				let (from, key) = (source(ip), (source(ip), name.to_string()));
				if !failed.sources.get(&from).is_some_and(|streak| live(streak, now) && streak.1 > NAMES_PER_SOURCE) {
					let known = failed.by.contains_key(&key);
					if bump(&mut failed.by, &key, now, FAILURES) && !known {bump(&mut failed.sources, &from, now, NAMES_PER_SOURCE + 1);}
				}
			}
			bump(&mut failed.names, &name.to_string(), now, FREE_FAILURES + (MAX_WAIT.as_millis() / WAIT.as_millis()) as u32);
			failed.since += 1;
			if failed.noted.is_none_or(|at| now.saturating_duration_since(at) >= NOTED) {
				failed.noted = Some(now);
				Some(std::mem::take(&mut failed.since))
			} else {None}
		};
		if let Some(n) = said {tracing::info!("inbound {tag}: {n} login(s) refused since the last line")}
	}

	pub fn totals(&self) -> Totals {
		let get = |count: Count| self.counts[count as usize].load(Ordering::Relaxed);
		Totals {opened: get(Count::Opened), open: self.held.lock().unwrap_or_else(|e| e.into_inner()).open, refused_logins: get(Count::Login), refused_udp_source: self.mismatch.load(Ordering::Relaxed), refused_limit: get(Count::Limit), refused_source: get(Count::Source), refused_busy: get(Count::Busy), refused_blocked: get(Count::Blocked), up_bytes: get(Count::Up), down_bytes: get(Count::Down)}
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

/// `login` for a front end: a source that failed `FAILURES` logins to this name, or tried too many names, is refused without being heard. A login that fails is held against the source and the name, and its refusal waits as long as the failures to that name say, which is after the password was checked, so a login that is right never waits for what others tried.
async fn check(door: &Door, peer: SocketAddr, user: &[u8], password: &[u8]) -> Option<(Arc<Plan>, usize, [u8; 32])> {
	let (name, now) = (String::from_utf8_lossy(&user[..user.len().min(64)]).to_string(), Instant::now());
	if door.state.blocked(peer.ip(), &name, now) {
		door.state.count(Count::Blocked);
		return None;
	}
	let found = login(&door.shared, &door.inbound.tag, user, password);
	if found.is_none() {
		let wait = door.state.wait(&name, now);
		door.state.refused(&door.inbound.tag, peer.ip(), &name, Instant::now());
		if !wait.is_zero() {sleep(wait).await}
	}
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
async fn carry(door: &Door, client: &mut TcpStream, front: Front, asked: Asked) -> anyhow::Result<()> {
	let (shared, Asked {plan, at, digest, target, up, body}) = (&door.shared, asked);
	let user = plan.users[at].name.clone();
	let refuse = async |client: &mut TcpStream, reason: Reason, code: u8| {
		shared.count(reason);
		let bytes = if front == Front::Socks {reply(code).to_vec()} else {answer(match code {2 => "403 Forbidden", 1 => "503 Service Unavailable", _ => "502 Bad Gateway"}, false).into_bytes()};
		let _ = timeout(HANDSHAKE, client.write_all(&bytes)).await;
	};
	if plan.users[at].denied.is_some() {
		refuse(client, Reason::Entitlement, 2).await;
		anyhow::bail!("user {user}: cut off");
	}
	if matches!(&target, Target::Address(addr) if addr.port() == 0) || matches!(&target, Target::Name(_, 0)) {
		refuse(client, Reason::Unparsable, 2).await;
		anyhow::bail!("user {user}: port 0");
	}
	let mut opened = match connect(shared, plan, at, target, &door.via, Some(if front == Front::Socks {RuleTransport::Socks5} else {RuleTransport::Http})).await {
		Ok(opened) => opened,
		Err(Refused {reason, code, why}) => {
			refuse(client, reason, code).await;
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
	relay(shared, &mut opened, client, &up, body, &|up, n| door.state.bytes(up, n), idle, &|now| door.holds(now, &user, digest), &door.via.label).await;
	Ok(())
}

async fn session(door: &Door, mut client: TcpStream, peer: SocketAddr, permit: (OwnedSemaphorePermit, Shake)) -> anyhow::Result<()> {
	let mut buf = Vec::new();
	// The first byte has `GREETING`, and it and the rest of the login, with what `mixed` looks at to tell the two apart, share `HANDSHAKE`.
	let next = timeout(HANDSHAKE, async {
		let mut first = [0u8; 1];
		anyhow::ensure!(timeout(GREETING, client.peek(&mut first)).await?? == 1, "closed before it sent anything");
		let socks = match door.inbound.kind {
			ProxyType::Socks5 => true,
			ProxyType::Http => false,
			ProxyType::Mixed => first[0] == 5,
		};
		if socks {socks_front(door, &mut client, &mut buf, peer).await} else {http_front(door, &mut client, &mut buf, peer).await}
	}).await;
	drop(permit);
	// A refusal is written, and the connection is then given a moment to be read before it closes, see `linger`.
	let next = match next {
		Ok(Ok(next)) => next,
		Ok(Err(e)) => {
			linger(&mut client).await;
			return Err(e);
		}
		Err(e) => return Err(e.into()),
	};
	match next {
		Next::Carry(front, asked) => {
			let carried = carry(door, &mut client, front, asked).await;
			if carried.is_err() {linger(&mut client).await}
			carried
		}
		Next::Associate(Asked {plan, at, digest, target, ..}) => {
			let user = plan.users[at].name.clone();
			if plan.users[at].denied.is_some() {
				door.shared.count(Reason::Entitlement);
				let _ = timeout(HANDSHAKE, client.write_all(&reply(2))).await;
				linger(&mut client).await;
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
	let via = Arc::new(Via {label: format!("inbound {}", inbound.tag), owner, inbound: Some(inbound.tag.clone()), any_port: inbound.udp_any_port == Some(true), mismatch: Some(state.mismatch.clone())});
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
					let (Ok(permit), Some(shake)) = (handshakes.clone().try_acquire_owned(), door.state.shake(peer.ip(), door.inbound.handshakes())) else {
						door.state.count(Count::Busy);
						reset(&stream);
						continue;
					};
					door.state.count(Count::Opened);
					let door = door.clone();
					sessions.spawn(async move {
						if let Err(e) = session(&door, stream, peer, (permit, shake)).await {tracing::debug!("{}: {e:#}", door.via.label)}
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
	fn a_flood_of_names_from_one_source_cannot_push_out_what_blocks_it() {
		let (state, start) = (State::default(), Instant::now());
		let ip: IpAddr = "203.0.113.5".parse().unwrap();
		for _ in 0..FAILURES {state.refused("s", ip, "alice", start)}
		assert!(state.blocked(ip, "alice", start));
		for n in 0..2 * SOURCES {state.refused("s", ip, &format!("name{n}"), start + Duration::from_millis(n as u64))}
		let now = start + Duration::from_secs(1);
		assert!(state.blocked(ip, "alice", now) && state.blocked(ip, "anyone", now), "a source that tried more names than it may was heard for another");
		let failed = state.failed.lock().unwrap();
		assert!(failed.by.len() <= NAMES_PER_SOURCE as usize + 1 && failed.names.len() <= SOURCES, "one source filled the tables: {} entries", failed.by.len());
	}

	#[test]
	fn a_flood_from_many_sources_gives_up_the_lowest_counts_and_keeps_a_slowed_name() {
		let (state, start) = (State::default(), Instant::now());
		let other: IpAddr = "198.51.100.9".parse().unwrap();
		for _ in 0..5 {state.refused("s", other, "alice", start)}
		assert_eq!(state.wait("alice", start), WAIT * 3);
		for n in 0..2 * SOURCES {state.refused("s", IpAddr::from([10, (n >> 16) as u8, (n >> 8) as u8, n as u8]), &format!("name{n}"), start + Duration::from_millis(n as u64))}
		assert_eq!(state.wait("alice", start + Duration::from_secs(1)), WAIT * 3, "a flood of names flushed the wait of a name");
		let failed = state.failed.lock().unwrap();
		assert!(failed.by.len() <= SOURCES && failed.names.len() <= SOURCES && failed.sources.len() <= SOURCES);
	}

	#[test]
	fn logins_in_flight_are_held_to_a_share_of_each_source_and_of_loopback() {
		let state = Arc::new(State::default());
		let outside: IpAddr = "203.0.113.5".parse().unwrap();
		let held: Vec<_> = (0..SHAKING_PER_SOURCE).map(|_| state.shake(outside, 256).unwrap()).collect();
		assert!(state.shake(outside, 256).is_none(), "one source held more logins than its share");
		assert!(state.shake("203.0.113.6".parse().unwrap(), 256).is_some(), "another source was held to it");
		drop(held);
		assert!(state.shake(outside, 256).is_some());
		let loopback: IpAddr = "127.0.0.1".parse().unwrap();
		let front: Vec<_> = (0..128).map(|_| state.shake(loopback, 256).unwrap()).collect();
		assert!(state.shake(loopback, 256).is_none(), "loopback peers took more than half");
		assert!(state.shake(outside, 256).is_some());
		drop(front);
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
