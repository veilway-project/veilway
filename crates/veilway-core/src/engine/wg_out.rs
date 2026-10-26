//! WireGuard outbounds (`outbounds[]` of type `wireguard`): another WireGuard server as the carrier of a `netstack` exit.
//! The node is a WireGuard client of it. One task for each outbound owns a UDP socket connected to the server, a boringtun tunnel and the timers, and moves packets between the socket and the userspace stack of `wg_stack`, which re-dials every flow of the exit from the outbound's own addresses. The server sees every flow in clear, and its answers are untrusted bytes that only a flow this node opened may receive (`wg_stack::admit`).
//! The server's name is looked up by the system's resolver, never through an exit, at start, every `RECHECK` and whenever the node starts a handshake again, and the last address stays while the name still resolves. An address that is loopback, in an inbound's pool or the node's own is refused, and so is a name that gives nothing else.
//! Health is read off the handshake. The outbound is up while one is younger than `UP_WITHIN`, down when an initiation has gone unanswered for `UNANSWERED` or a send failed, and idle otherwise, which says nothing against it. While it is down a new initiation is forced after 2 s, then 4 s, doubling to 60 s, forever: nothing latches. Every change between working and down is logged at info and drives the exits that use the outbound (`watch`). A flow that finds it down fails at once with the reason, and nothing goes around it.
use super::flows::tie;
use super::plan::{Backend, Outbound, Plan};
use super::upstream::forbidden;
use super::wg_stack::{self, Counters, Fail, Stack, Udp};
use super::{Event, Shared};
use crate::config::{self, random, Host};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use socket2::SockRef;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::DuplexStream;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::AbortHandle;
use tokio::time::{interval, MissedTickBehavior};

/// A handshake younger than this means the server answers.
const UP_WITHIN: Duration = Duration::from_secs(180);
/// An initiation that is not answered within this means the server does not.
const UNANSWERED: Duration = Duration::from_secs(20);
/// The wait before the first forced initiation of a down outbound, and the most it grows to.
const RETRY_FIRST: Duration = Duration::from_secs(2);
const RETRY_MOST: Duration = Duration::from_secs(60);
/// How often a name is looked up again, and how long the lookup may take.
const RECHECK: Duration = Duration::from_secs(300);
const LOOKUP: Duration = Duration::from_secs(5);
/// How often the tunnel's timers run.
const TIMERS: Duration = Duration::from_millis(250);
/// The largest datagram a tunnel is asked to write: an IP packet at its largest and the message around it.
const BUFFER: usize = 65_535 + 64;
/// The datagrams read from the stack before the socket is looked at again.
const BATCH: usize = 32;

/// Everything of an outbound that makes a running one different from another. Secrets are in it, so it has no `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Spec {
	pub server: config::HostPort,
	pub public_key: [u8; 32],
	pub private_key: [u8; 32],
	pub preshared_key: Option<[u8; 32]>,
	pub addresses: Vec<IpAddr>,
	pub mtu: u16,
	pub keepalive: u16,
	pub max_flows: usize,
	pub bind: Option<IpAddr>,
	pub interface: Option<String>,
	/// The pools of the inbounds, which no endpoint may be in.
	pub pools: Vec<IpNet>,
}

#[derive(Clone, PartialEq, Eq)]
enum State {Idle, Up, Down(String)}

/// What the task tells everybody else.
struct Link {state: Mutex<(State, Instant)>, flips: AtomicU64, endpoint: Mutex<Option<SocketAddr>>, handshake: Mutex<Option<Duration>>, changed: watch::Sender<u64>}

impl Link {
	/// Moves to `to`. A change between working and down is logged and counted and wakes the watcher, a move between idle and up is only noted.
	fn set(&self, tag: &str, to: State) {
		let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
		if state.0 == to {return}
		let was = std::mem::replace(&mut *state, (to.clone(), Instant::now()));
		let (before, endpoint) = (was.0, *self.endpoint.lock().unwrap_or_else(|e| e.into_inner()));
		match (&before, &to) {
			(State::Down(_), State::Down(_)) => {
				tracing::debug!("wireguard outbound {tag}: still down, now because: {}", if let State::Down(why) = &to {why} else {""});
				return;
			}
			(State::Down(_), _) => tracing::info!("wireguard outbound {tag}: the server answers again after {}s{}", was.1.elapsed().as_secs(), endpoint.map(|endpoint| format!(" at {endpoint}")).unwrap_or_default()),
			(_, State::Down(why)) => tracing::info!("wireguard outbound {tag}: down, so the exits that use it do not work and nothing leaves around it; a new handshake is tried after 2s, then after longer, up to every 60s: {why}"),
			(State::Idle, State::Up) => tracing::info!("wireguard outbound {tag}: up{}", endpoint.map(|endpoint| format!(", handshake with {endpoint}")).unwrap_or_default()),
			_ => tracing::debug!("wireguard outbound {tag}: idle, no handshake in {}s and no initiation unanswered", UP_WITHIN.as_secs()),
		}
		if matches!(before, State::Down(_)) || matches!(to, State::Down(_)) {
			self.flips.fetch_add(1, Ordering::Relaxed);
			self.changed.send_modify(|moved| *moved = moved.wrapping_add(1));
		}
	}
}

/// What `GET /v1/exits` says of an outbound.
#[derive(Clone, Debug)]
pub struct Report {pub up: bool, pub down_secs: Option<u64>, pub why: Option<String>, pub flips: u64, pub handshake_secs: Option<u64>, pub endpoint: Option<SocketAddr>, pub flows: usize, pub unsolicited: u64, pub full: u64, pub refused: u64}

/// One running WireGuard outbound. Its tasks end when the last plan that holds it is gone.
pub struct WgOut {pub tag: String, spec: Spec, stack: Stack, counters: Arc<Counters>, link: Arc<Link>, watched: AtomicBool, tasks: [AbortHandle; 2]}

impl PartialEq for WgOut {
	fn eq(&self, other: &WgOut) -> bool {std::ptr::eq(self, other)}
}

impl Eq for WgOut {}

impl Drop for WgOut {
	fn drop(&mut self) {for task in &self.tasks {task.abort()}}
}

impl WgOut {
	fn start(tag: &str, spec: Spec, is_local: fn(IpAddr) -> bool) -> WgOut {
		let (to_stack, from_wg) = mpsc::channel(wg_stack::QUEUE);
		let (to_wg, from_stack) = mpsc::channel(wg_stack::QUEUE);
		let (stack, stacked) = wg_stack::start(spec.addresses.clone(), usize::from(spec.mtu), spec.max_flows, from_wg, to_wg);
		let link = Arc::new(Link {state: Mutex::new((State::Idle, Instant::now())), flips: AtomicU64::new(0), endpoint: Mutex::new(None), handshake: Mutex::new(None), changed: watch::Sender::new(0)});
		let task = tokio::spawn(run(tag.to_string(), spec.clone(), is_local, link.clone(), from_stack, to_stack, stack.counters.clone()));
		WgOut {tag: tag.to_string(), counters: stack.counters.clone(), spec, stack, link, watched: AtomicBool::new(false), tasks: [stacked.abort_handle(), task.abort_handle()]}
	}

	/// Why the outbound cannot carry a flow right now. None while it is up or idle.
	pub fn down(&self) -> Option<String> {if let State::Down(why) = &self.link.state.lock().unwrap_or_else(|e| e.into_inner()).0 {Some(why.clone())} else {None}}

	/// Whether the outbound has an address of the family of `ip`: a flow to one of the other family is refused as unsupported.
	pub fn has(&self, ip: IpAddr) -> bool {self.spec.addresses.iter().any(|own| own.is_ipv4() == ip.is_ipv4())}

	/// A TCP connection to `to` from the outbound's address, or why there is none.
	pub async fn connect(&self, to: SocketAddr) -> Result<DuplexStream, String> {
		if let Some(why) = self.down() {return Err(format!("wireguard outbound {} is down: {why}", self.tag))}
		self.stack.connect(to).await.map_err(|fail| self.failed(fail))
	}

	/// A UDP flow to `to` from a port of the outbound's address, or why there is none.
	pub async fn udp(&self, to: SocketAddr) -> Result<Udp, String> {
		if let Some(why) = self.down() {return Err(format!("wireguard outbound {} is down: {why}", self.tag))}
		self.stack.udp(to).await.map_err(|fail| self.failed(fail))
	}

	fn failed(&self, fail: Fail) -> String {
		match fail {
			Fail::Down => format!("wireguard outbound {} has stopped", self.tag),
			Fail::Busy => format!("wireguard outbound {} has {} flows open, which is its max_flows", self.tag, self.spec.max_flows),
			Fail::Timeout => format!("wireguard outbound {}: the destination did not answer within 10s", self.tag),
			Fail::Refused => format!("wireguard outbound {}: the destination refused the connection", self.tag),
			Fail::Unsupported => format!("wireguard outbound {} has no address of the destination's family", self.tag),
		}
	}

	pub fn report(&self) -> Report {
		let (state, since) = self.link.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
		let down = if let State::Down(why) = &state {Some(why.clone())} else {None};
		Report {up: down.is_none(), down_secs: down.as_ref().map(|_| since.elapsed().as_secs()), why: down, flips: self.link.flips.load(Ordering::Relaxed), handshake_secs: self.link.handshake.lock().unwrap_or_else(|e| e.into_inner()).map(|age| age.as_secs()), endpoint: *self.link.endpoint.lock().unwrap_or_else(|e| e.into_inner()), flows: self.counters.flows.load(Ordering::Relaxed), unsolicited: self.counters.unsolicited.load(Ordering::Relaxed), full: self.counters.full.load(Ordering::Relaxed), refused: self.counters.refused.load(Ordering::Relaxed)}
	}
}

/// The WireGuard outbounds by tag. One registry lives as long as the engine, so a reload that leaves an outbound as it was keeps its tunnel, and one that changes it starts another. The old one runs until the new plan is in force (`supersede`), since a reload that fails leaves the old plan working.
pub struct WgOuts {is_local: fn(IpAddr) -> bool, running: Mutex<HashMap<String, Vec<(Spec, Weak<WgOut>)>>>}

impl Default for WgOuts {
	fn default() -> WgOuts {WgOuts::new(super::gate::is_local)}
}

impl WgOuts {
	pub fn new(is_local: fn(IpAddr) -> bool) -> WgOuts {WgOuts {is_local, running: Mutex::default()}}

	/// The running outbound `tag` when `spec` is what it runs with, and a new one, which starts its handshake at once, when it is not. Needs the runtime.
	pub fn get(&self, tag: &str, spec: Spec) -> Arc<WgOut> {
		let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
		let list = running.entry(tag.to_string()).or_default();
		list.retain(|(_, held)| held.strong_count() > 0);
		if let Some(held) = list.iter().filter(|(was, _)| *was == spec).find_map(|(_, held)| held.upgrade()) {return held}
		let out = Arc::new(WgOut::start(tag, spec.clone(), self.is_local));
		list.push((spec, Arc::downgrade(&out)));
		out
	}

	/// Stops every other tunnel of the tag of `current`, which the plan now in force holds. Two tunnels with one key would take the server's session from each other, and the flows of the old one end with the old plan's exit anyway.
	fn supersede(&self, current: &Arc<WgOut>) {
		let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
		let Some(list) = running.get_mut(&current.tag) else {return};
		list.retain(|(_, held)| match held.upgrade() {
			Some(out) if Arc::ptr_eq(&out, current) => true,
			Some(old) => {
				for task in &old.tasks {task.abort()}
				false
			}
			None => false,
		});
	}
}

fn tunnel(spec: &Spec) -> Tunn {
	let mut index = [0u8; 4];
	let _ = random(&mut index);
	Tunn::new(StaticSecret::from(spec.private_key), PublicKey::from(spec.public_key), spec.preshared_key, Some(spec.keepalive).filter(|secs| *secs > 0), u32::from_le_bytes(index) & 0x00ff_ffff, None)
}

/// The address to talk to, from what the server's name gives now. A server that is an address is that address if it is allowed. For a name, the address in use stays while the lookup still gives it, and a lookup that fails or gives nothing changes nothing. `Err` says why there is no address.
async fn resolve(spec: &Spec, is_local: fn(IpAddr) -> bool, current: Option<IpAddr>) -> Result<IpAddr, String> {
	let pools: Vec<(IpNet, usize)> = spec.pools.iter().map(|pool| (*pool, 0)).collect();
	let found: Vec<IpAddr> = match &spec.server.host {
		Host::Ip(ip) => vec![*ip],
		Host::Name(name) => match tokio::time::timeout(LOOKUP, tokio::net::lookup_host((name.as_str(), spec.server.port))).await {
			Ok(Ok(found)) => found.map(|address| address.ip()).collect(),
			Ok(Err(e)) => {
				tracing::debug!("the name of a wireguard outbound's server was not looked up: {}", e.kind());
				Vec::new()
			}
			Err(_) => {
				tracing::debug!("the name of a wireguard outbound's server was not looked up within {}s", LOOKUP.as_secs());
				Vec::new()
			}
		},
	};
	let allowed: Vec<IpAddr> = found.iter().copied().filter(|ip| forbidden(*ip, &pools, is_local, true).is_none()).collect();
	if found.is_empty() {return current.ok_or_else(|| "the server's name does not resolve".to_string())}
	current.filter(|ip| allowed.contains(ip)).or(allowed.first().copied()).ok_or_else(|| "the server's address is loopback, in an inbound's pool or the node's own, which the node never dials".to_string())
}

/// A UDP socket connected to the server, from `bind` and tied to `interface` when the outbound has them.
async fn open(spec: &Spec, to: SocketAddr) -> std::io::Result<UdpSocket> {
	let local = spec.bind.unwrap_or(if to.is_ipv4() {Ipv4Addr::UNSPECIFIED.into()} else {Ipv6Addr::UNSPECIFIED.into()});
	let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
	if let Some(name) = &spec.interface {tie(&SockRef::from(&socket), name, to.is_ipv4())?}
	socket.connect(to).await?;
	Ok(socket)
}

/// Looks the server up in a task of its own, so that a slow resolver holds no packet up.
fn look(spec: &Spec, is_local: fn(IpAddr) -> bool, current: Option<IpAddr>) -> oneshot::Receiver<Result<IpAddr, String>> {
	let (reply, answer) = oneshot::channel();
	let spec = spec.clone();
	tokio::spawn(async move {let _ = reply.send(resolve(&spec, is_local, current).await);});
	answer
}

async fn run(tag: String, spec: Spec, is_local: fn(IpAddr) -> bool, link: Arc<Link>, mut from_stack: mpsc::Receiver<Vec<u8>>, to_stack: mpsc::Sender<Vec<u8>>, counters: Arc<Counters>) {
	let (mut tunn, mut socket, mut address) = (tunnel(&spec), None::<UdpSocket>, None::<IpAddr>);
	let (mut inbuf, mut out, mut tick) = (vec![0u8; BUFFER], vec![0u8; BUFFER], interval(TIMERS));
	tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
	// Why the outbound cannot work and since when, which the first handshake after it ends. The first initiation not answered since the last handshake. The time of the next attempt while down and the wait after it. The last lookup of the name and the one in flight.
	let (mut fault, mut asked, mut retry, mut retry_at, mut looked, mut lookup) = (None::<(String, Instant)>, None::<Instant>, RETRY_FIRST, Instant::now(), None::<Instant>, None::<oneshot::Receiver<Result<IpAddr, String>>>);
	loop {
		// What this pass has to send, in the order the tunnel wrote it.
		let mut sending: Vec<Vec<u8>> = Vec::new();
		tokio::select! {
			received = async {match &socket {Some(socket) => socket.recv(&mut inbuf).await, None => std::future::pending().await}} => match received {
				Ok(n) => {
					let mut input = &inbuf[..n];
					loop {
						match tunn.decapsulate(None, input, &mut out) {
							TunnResult::WriteToNetwork(reply) => {
								sending.push(reply.to_vec());
								input = &[];
							}
							TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
								if to_stack.try_send(packet.to_vec()).is_err() {counters.full.fetch_add(1, Ordering::Relaxed);}
								break;
							}
							TunnResult::Done => break,
							TunnResult::Err(e) => {
								tracing::debug!("wireguard outbound {tag}: a datagram from the server was dropped: {e:?}");
								break;
							}
						}
					}
				}
				Err(e) => fault = Some((format!("the server's port refused a datagram: {}", e.kind()), Instant::now())),
			},
			Some(raw) = from_stack.recv() => {
				let (mut next, mut taken) = (Some(raw), 0);
				while let Some(raw) = next.take() {
					match tunn.encapsulate(&raw, &mut out) {
						TunnResult::WriteToNetwork(datagram) => sending.push(datagram.to_vec()),
						TunnResult::Err(e) => tracing::debug!("wireguard outbound {tag}: a packet of the stack was dropped: {e:?}"),
						_ => {}
					}
					taken += 1;
					if taken < BATCH {next = from_stack.try_recv().ok()}
				}
			}
			found = async {match lookup.as_mut() {Some(reply) => reply.await.unwrap_or_else(|_| Err("the lookup of the server's name ended".to_string())), None => std::future::pending().await}} => {
				lookup = None;
				match found {
					Ok(ip) if address == Some(ip) => {}
					Ok(ip) => match open(&spec, SocketAddr::new(ip, spec.server.port)).await {
						Ok(opened) => {
							(socket, address, fault, retry_at) = (Some(opened), Some(ip), None, Instant::now());
							*link.endpoint.lock().unwrap_or_else(|e| e.into_inner()) = Some(SocketAddr::new(ip, spec.server.port));
						}
						Err(e) => (socket, address, fault) = (None, None, Some((format!("the socket to the server was not opened: {}", e.kind()), Instant::now()))),
					},
					Err(reason) => (socket, address, fault) = (None, None, Some((reason, Instant::now()))),
				}
			}
			_ = tick.tick() => match tunn.update_timers(&mut out) {
				TunnResult::WriteToNetwork(datagram) => sending.push(datagram.to_vec()),
				TunnResult::Err(WireGuardError::ConnectionExpired) => tunn = tunnel(&spec),
				_ => {}
			},
		}
		let (now, age) = (Instant::now(), tunn.time_since_last_handshake());
		*link.handshake.lock().unwrap_or_else(|e| e.into_inner()) = age;
		if let (Some((_, at)), Some(age)) = (&fault, age) {
			if now.checked_sub(age).is_some_and(|shaken| shaken > *at) {fault = None}
		}
		let down = matches!(link.state.lock().unwrap_or_else(|e| e.into_inner()).0, State::Down(_));
		if age.is_some_and(|age| age < UP_WITHIN) && fault.is_none() {
			(asked, retry) = (None, RETRY_FIRST);
			link.set(&tag, State::Up);
		} else if let Some((why, _)) = &fault {
			link.set(&tag, State::Down(why.clone()));
		} else if asked.is_some_and(|since| now.duration_since(since) >= UNANSWERED) {
			link.set(&tag, State::Down(format!("the server did not answer a handshake for {}s", UNANSWERED.as_secs())));
		} else if !down {
			link.set(&tag, State::Idle);
		}
		let down = matches!(link.state.lock().unwrap_or_else(|e| e.into_inner()).0, State::Down(_));
		// An attempt: at the start, and while down on the schedule. The name is looked up again first, and a tunnel with no handshake behind it and none outstanding opens one.
		if now >= retry_at && (down || socket.is_none() || (asked.is_none() && age.is_none())) {
			if lookup.is_none() && (socket.is_none() || matches!(spec.server.host, Host::Name(_))) {
				(looked, lookup) = (Some(now), Some(look(&spec, is_local, address)));
			}
			if socket.is_some() {
				if let TunnResult::WriteToNetwork(datagram) = tunn.format_handshake_initiation(&mut out, true) {sending.push(datagram.to_vec())}
			}
			retry_at = now + retry;
			if down {retry = (retry * 2).min(RETRY_MOST)}
		}
		if lookup.is_none() && matches!(spec.server.host, Host::Name(_)) && looked.is_some_and(|at| now >= at + RECHECK) {(looked, lookup) = (Some(now), Some(look(&spec, is_local, address)))}
		if let Some(socket) = &socket {
			for datagram in sending {
				if datagram.first() == Some(&1) && asked.is_none() {asked = Some(now)}
				if let Err(e) = socket.send(&datagram).await {
					let why = format!("a datagram could not be sent to the server: {}", e.kind());
					link.set(&tag, State::Down(why.clone()));
					fault = Some((why, Instant::now()));
					break;
				}
			}
		}
	}
}

/// Gives a fresh outbound's exits their state and keeps them in step with it: one task for each outbound of the plan in force, started once, that follows the outbound's health. While it is down the exits that use it are not working and devices without a choice of exit leave through `routing.fallback`, and when it is up again they work again, which is logged and published like the proxy of a `socks5` exit (`flows::heard`). It ends when the outbound does.
pub(super) fn watch(shared: &Arc<Shared>, plan: &Plan) {
	for out in plan.exits.iter().filter_map(|exit| if let Backend::Netstack {outbound: Outbound::WireGuard(out), ..} = &exit.backend {Some(out)} else {None}) {
		plan.hops.wireguard.supersede(out);
		if out.watched.swap(true, Ordering::Relaxed) {continue}
		let (shared, held, mut changes) = (Arc::downgrade(shared), Arc::downgrade(out), out.link.changed.subscribe());
		tokio::spawn(async move {
			loop {
				let (Some(shared), Some(out)) = (shared.upgrade(), held.upgrade()) else {return};
				let (plan, down) = (shared.plan(), out.down());
				for exit in plan.exits.iter().filter(|exit| matches!(&exit.backend, Backend::Netstack {outbound: Outbound::WireGuard(of), ..} if Arc::ptr_eq(of, &out))) {
					let mut was = exit.state.down.lock().unwrap_or_else(|e| e.into_inner());
					if was.is_some() == down.is_some() {continue}
					*was = down.as_ref().map(|_| Instant::now());
					drop(was);
					exit.state.down_flips.fetch_add(1, Ordering::Relaxed);
					tracing::info!("exit {}: its wireguard outbound {} is {}, so the exit {}", exit.tag, out.tag, if down.is_none() {"up again"} else {"down"}, if down.is_none() {"works again and devices without a choice of exit leave through it again"} else {"does not work"});
					shared.publish(Event::ExitWorkingChanged {exit: exit.tag.clone(), working: down.is_none()});
					shared.control.health.send_modify(|moved| *moved = moved.wrapping_add(1));
				}
				drop((shared, out));
				if changes.changed().await.is_err() {return}
			}
		});
	}
}
