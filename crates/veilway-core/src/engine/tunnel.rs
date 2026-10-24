//! Tunnels (node links page, "Tunnels"): one TCP or UDP port of the entry forwarded to one address on the far side of a link, with no client and no user. The node listens on the tunnel's address and opens each connection, or each UDP session, inside the link.
//! "A flow from the entry's link address, like any user's flow": the source is the link's address and the source port is drawn from the entry's translation (`chain::Nat`), from the same range and the same table as users' flows, with the same rest time. What the far node answers is found there by that port and handed to the connection or session.
//! The exit cannot tell a tunnel's flow from a user's. Nothing here is charged to a user: "a tunnel belongs to the operator".
use super::netstack;
use super::chain::HOPS;
use super::plan::{Backend, Plan};
use super::route::Key;
use super::Shared;
use crate::config::{self, random, Protocol, TUNNEL_PER_CLIENT};
use etherparse::PacketBuilder;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp::{self, RecvError};
use smoltcp::time::Instant as Clock;
use smoltcp::wire::{HardwareAddress, IpCidr};
use socket2::SockRef;
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{interval, sleep, sleep_until, Instant, MissedTickBehavior};

/// "An opening that is not answered within 10 s closes the client's connection."
const CONNECT: Duration = Duration::from_secs(10);
/// "A connection with no byte either way for 1 hour is closed."
const IDLE: Duration = Duration::from_secs(3600);
/// "A session ends 60 s after the client last sent."
const SESSION: Duration = Duration::from_secs(60);
/// How often a connection looks at its link and its deadlines when nothing else wakes it, and how often the sessions of a UDP tunnel are looked at.
const TICK: Duration = Duration::from_secs(1);
/// What each side of the userspace TCP of a connection buffers. The memory is not touched until bytes are in it.
const WINDOW: usize = 131072;
/// The most that is read from the client or written to it at once.
const CHUNK: usize = 16384;
/// Packets from the link that wait for one connection, or for all the sessions of a UDP tunnel. One that finds it full is dropped and counted.
const QUEUE: usize = 256;
/// Packets the userspace stack has made that wait to be sent into the link.
const MADE: usize = 64;

/// "At most 16 of them for one source ... and at most 8 new ones per second for one source."
const NEW_PER_SECOND: u32 = 8;
/// "A TCP connection ... that has carried no byte in either direction 60 s after it opened is closed."
const SILENT: Duration = Duration::from_secs(60);
/// "A session's answers may come to at most 3 times the bytes the client sent since its last datagram plus 4096 bytes."
const ANSWER_FACTOR: usize = 3;
const ANSWER_BASE: usize = 4096;
/// Sources whose rate is remembered at most, before those that are over a second old are forgotten.
const RATES: usize = 4096;

/// What a tunnel counts. Everything but `open` only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
	/// TCP connections or UDP sessions that were taken, and those open now.
	pub opened: u64,
	pub open: usize,
	/// Refused (TCP) or dropped (UDP) because the client's address is in none of `sources`, because the tunnel is at its `max_connections`, because the source holds 16 already, because it opened 8 in the last second, while the `chain` exit is down, and because no translated port could be drawn.
	pub refused_sources: u64,
	pub refused_limit: u64,
	pub refused_client: u64,
	pub refused_rate: u64,
	pub refused_down: u64,
	pub refused_full: u64,
	/// TCP connections the far side did not open: refused, unreachable or not answered within 10 s.
	pub connect_failed: u64,
	/// TCP connections that a reset ended, the link going down or a reload, and those closed for silence.
	pub reset: u64,
	pub idled: u64,
	/// Packets from the link that a full queue, an unknown session or the answer budget could not take, and datagrams from a client that did not fit the link.
	pub dropped: u64,
	/// Bytes of the clients' own data towards the far side (up) and back (down), and inner IP packets sent into the link and taken out of it for the tunnel.
	pub up_bytes: u64,
	pub down_bytes: u64,
	pub up_packets: u64,
	pub down_packets: u64,
}

#[derive(Clone, Copy)]
enum Count {Opened, Sources, Limit, Client, Rate, Down, Full, ConnectFailed, Reset, Idled, Dropped, UpBytes, DownBytes, UpPackets, DownPackets}

impl Count {
	const ALL: usize = 15;
}

/// What a reload can change in a running tunnel: who may connect and how many.
#[derive(Default)]
struct Live {sources: Option<Vec<IpNet>>, most: usize}

/// "One source (an IPv4 address or an IPv6 /64, as on the transports page)."
pub(super) fn source(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V4(_) => ip,
		IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
	}
}

#[derive(Default)]
struct Clients {
	/// Open connections and sessions by the order they were taken in, each with its source and the flag that tells it to close.
	open: BTreeMap<u64, (IpAddr, Arc<AtomicBool>)>,
	next: u64,
	by: HashMap<IpAddr, usize>,
	/// Each source's start of its second and the connections it took in it.
	rates: HashMap<IpAddr, (Instant, u32)>,
}

/// What a running tunnel counts and holds.
#[derive(Default)]
pub struct State {
	counts: [AtomicU64; Count::ALL],
	live: Mutex<Live>,
	clients: Mutex<Clients>,
}

/// A place among the tunnel's connections or sessions, given back when it is dropped. `closed` is set when a reload closes it.
struct Slot {state: Arc<State>, seq: u64, source: IpAddr, closed: Arc<AtomicBool>}

impl Drop for Slot {
	fn drop(&mut self) {
		let mut clients = self.state.clients.lock().unwrap_or_else(|e| e.into_inner());
		clients.open.remove(&self.seq);
		if let Some(held) = clients.by.get_mut(&self.source) {
			*held -= 1;
			if *held == 0 {clients.by.remove(&self.source);}
		}
	}
}

impl State {
	/// The state of a tunnel as `tunnel` has it: nothing open.
	pub fn new(tunnel: &config::Tunnel) -> State {
		let state = State::default();
		*state.live.lock().unwrap_or_else(|e| e.into_inner()) = Live {sources: tunnel.sources.as_ref().map(|list| list.iter().map(|source| source.0).collect()), most: tunnel.limit() as usize};
		state
	}

	fn count(&self, count: Count) {self.add(count, 1)}

	fn add(&self, count: Count, by: usize) {self.counts[count as usize].fetch_add(by as u64, Ordering::Relaxed);}

	/// A packet that came out of the link for this tunnel, and whether its queue took it.
	pub(super) fn arrived(&self, queued: bool) {self.count(if queued {Count::DownPackets} else {Count::Dropped})}

	/// "Anyone who reaches the address, unless `sources` lists networks."
	fn allowed(&self, ip: IpAddr) -> bool {self.live.lock().unwrap_or_else(|e| e.into_inner()).sources.as_ref().is_none_or(|list| list.iter().any(|net| net.contains(&ip)))}

	/// "`max_connections` TCP connections or UDP sessions at once per tunnel, at most 16 of them for one source, and at most 8 new ones per second for one source." A refusal is counted here, and so is a client that `sources` does not list.
	fn admit(self: &Arc<State>, client: IpAddr, now: Instant) -> Option<Slot> {
		let (most, listed) = {
			let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
			(live.most, live.sources.as_ref().is_none_or(|list| list.iter().any(|net| net.contains(&client))))
		};
		if !listed {
			self.count(Count::Sources);
			return None;
		}
		let (mut clients, from) = (self.clients.lock().unwrap_or_else(|e| e.into_inner()), source(client));
		let held = clients.by.get(&from).copied().unwrap_or(0);
		if clients.open.len() >= most {
			self.count(Count::Limit);
			return None;
		}
		if held >= TUNNEL_PER_CLIENT {
			self.count(Count::Client);
			return None;
		}
		if clients.rates.len() >= RATES {clients.rates.retain(|_, (start, _)| now.saturating_duration_since(*start) < Duration::from_secs(1))}
		let rate = clients.rates.entry(from).or_insert((now, 0));
		if now.saturating_duration_since(rate.0) >= Duration::from_secs(1) {*rate = (now, 0)}
		if rate.1 >= NEW_PER_SECOND {
			self.count(Count::Rate);
			return None;
		}
		rate.1 += 1;
		let (seq, closed) = (clients.next, Arc::new(AtomicBool::new(false)));
		clients.next += 1;
		clients.open.insert(seq, (client, closed.clone()));
		clients.by.insert(from, held + 1);
		Some(Slot {state: self.clone(), seq, source: from, closed})
	}

	/// "A narrower `sources` closes the connections and sessions from sources it no longer lists, and a lower `max_connections` closes the newest ones past it." The ones to close are told, and close within a second.
	pub(super) fn retune(&self, tunnel: &config::Tunnel) {
		let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
		*live = Live {sources: tunnel.sources.as_ref().map(|list| list.iter().map(|source| source.0).collect()), most: tunnel.limit() as usize};
		let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
		let mut kept = 0;
		for (from, closed) in clients.open.values() {
			if live.sources.as_ref().is_some_and(|list| !list.iter().any(|net| net.contains(from))) {
				closed.store(true, Ordering::Relaxed);
			} else if kept >= live.most {
				closed.store(true, Ordering::Relaxed);
			} else {
				kept += 1;
			}
		}
	}

	pub fn totals(&self) -> Totals {
		let get = |count: Count| self.counts[count as usize].load(Ordering::Relaxed);
		Totals {
			opened: get(Count::Opened), open: self.clients.lock().unwrap_or_else(|e| e.into_inner()).open.len(),
			refused_sources: get(Count::Sources), refused_limit: get(Count::Limit), refused_client: get(Count::Client), refused_rate: get(Count::Rate), refused_down: get(Count::Down), refused_full: get(Count::Full),
			connect_failed: get(Count::ConnectFailed), reset: get(Count::Reset), idled: get(Count::Idled), dropped: get(Count::Dropped),
			up_bytes: get(Count::UpBytes), down_bytes: get(Count::DownBytes), up_packets: get(Count::UpPackets), down_packets: get(Count::DownPackets),
		}
	}
}

/// What a UDP session may still be answered with: "at most 3 times the bytes the client sent since its last datagram plus 4096 bytes". Each datagram of the client starts it again, and an answer that does not fit what is left is refused.
struct Budget(usize);

impl Budget {
	fn sent(&mut self, bytes: usize) {self.0 = ANSWER_FACTOR * bytes + ANSWER_BASE}

	fn answer(&mut self, bytes: usize) -> bool {
		if bytes > self.0 {return false}
		self.0 -= bytes;
		true
	}
}

/// The socket a tunnel listens on. It outlives the tunnel that was first made for it: a reload that changes a tunnel and keeps its address hands the same socket on.
#[derive(Clone)]
pub enum Bound {Tcp(Arc<TcpListener>), Udp(Arc<UdpSocket>)}

/// A translated port of a link held for a connection or session, given up when it is dropped.
struct Mapping {shared: Arc<Shared>, link: [u8; 16], protocol: u8, target: SocketAddr, port: u16}

impl Drop for Mapping {
	fn drop(&mut self) {self.shared.nat.forget(self.link, self.protocol, self.target, self.port)}
}

/// How a connection or session finds its link.
enum How<'a> {
	/// A new one: "for each connection or session, the rule for parallel links, hashed over the client's address and port".
	Pick(&'a Key),
	/// One that stays on the link it has, by the link's id: "A connection stays on its link and is reset when that link goes down."
	Stay(&'a [u8; 16]),
}

/// The exit a tunnel names and the link it uses, as indexes into the plan. None while the exit is gone or no `chain` exit any more, and while no link of it is up, or the link a connection stays on is not.
fn route(shared: &Shared, plan: &Plan, exit: &str, how: How) -> Option<(usize, usize)> {
	let at = plan.exits.iter().position(|candidate| candidate.tag == exit)?;
	let Backend::Chain {links} = &plan.exits[at].backend else {return None};
	let mut up = links.iter().copied().filter(|link| plan.up(*link));
	match how {
		How::Pick(key) => up.max_by_key(|link| shared.nat.rank(key, &plan.links[*link].id)),
		How::Stay(id) => up.find(|link| plan.links[*link].id == *id),
	}.map(|link| (at, link))
}

/// Closes the client's connection with a reset, as a refusal does.
pub(super) fn reset(stream: &TcpStream) {let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));}

/// Starts the tunnel: it accepts on its socket until the task is aborted, and the connections it has go with it.
pub(super) fn serve(shared: &Arc<Shared>, tunnel: config::Tunnel, bound: Bound, state: Arc<State>) -> AbortHandle {
	let (shared, tunnel) = (shared.clone(), Arc::new(tunnel));
	match bound {
		Bound::Tcp(listener) => tokio::spawn(accept(shared, tunnel, listener, state)).abort_handle(),
		Bound::Udp(socket) => tokio::spawn(datagrams(shared, tunnel, socket, state)).abort_handle(),
	}
}

async fn accept(shared: Arc<Shared>, tunnel: Arc<config::Tunnel>, listener: Arc<TcpListener>, state: Arc<State>) {
	let (mut connections, mut failing) = (JoinSet::new(), false);
	loop {
		tokio::select! {
			accepted = listener.accept() => match accepted {
				Ok((stream, peer)) => {
					failing = false;
					// "The connection or datagram from another address is refused (TCP) or dropped (UDP) and counted."
					if let Some(slot) = state.admit(peer.ip(), Instant::now()) {
						connections.spawn(connection(shared.clone(), tunnel.clone(), stream, peer, slot));
					} else {
						reset(&stream);
					}
				}
				Err(e) => {
					if !failing {tracing::warn!("tunnel {}: the system did not accept a connection ({}). Connections are tried again every 200 ms", tunnel.tag, e.kind())}
					failing = true;
					sleep(Duration::from_millis(200)).await;
				}
			},
			Some(_) = connections.join_next(), if !connections.is_empty() => {}
		}
	}
}

/// What ended a connection.
#[derive(PartialEq, Eq)]
enum Ended {Graceful, Unopened, Reset, Idle}

/// One TCP connection: "The entry ends the client's TCP connection with the system's TCP, and opens its own TCP connection inside the link with a userspace TCP stack. Bytes are copied both ways, a half close is passed on, and a reset on either side resets the other."
async fn connection(shared: Arc<Shared>, tunnel: Arc<config::Tunnel>, mut stream: TcpStream, peer: SocketAddr, slot: Slot) {
	let (state, target) = (slot.state.clone(), tunnel.target.0);
	let key = Key {protocol: Protocol::TCP, src: peer.ip(), dst: target.ip(), sport: peer.port(), dport: target.port()};
	let plan = shared.plan();
	// "While the `chain` exit is down, a connection is refused at once ... and counted."
	let Some((_, link)) = route(&shared, &plan, &tunnel.exit, How::Pick(&key)) else {
		state.count(Count::Down);
		return reset(&stream);
	};
	let (id, mtu, address) = (plan.links[link].id, plan.links[link].mtu(), plan.links[link].address(target.is_ipv4()));
	drop(plan);
	let Some(address) = address else {
		state.count(Count::Down);
		return reset(&stream);
	};
	let (queue, mut arrivals) = mpsc::channel(QUEUE);
	let Some(port) = shared.nat.tunnel(id, Protocol::TCP, target, queue, state.clone()) else {
		state.count(Count::Full);
		return reset(&stream);
	};
	let _mapping = Mapping {shared: shared.clone(), link: id, protocol: Protocol::TCP, target, port};
	let (started, mut seed) = (Instant::now(), [0u8; 8]);
	let clock = || Clock::from_micros(started.elapsed().as_micros() as i64);
	let mut device = Wire {rx: VecDeque::new(), tx: Vec::new(), mtu: usize::from(mtu)};
	let _ = random(&mut seed);
	let mut config = Config::new(HardwareAddress::Ip);
	config.random_seed = u64::from_le_bytes(seed);
	let mut iface = Interface::new(config, &mut device, clock());
	// Every address is on the link: the interface has no neighbours to ask and no route to look up. "The segment size the entry announces fits the link's MTU": the stack sizes its segments from the device's.
	iface.update_ip_addrs(|addresses| {let _ = addresses.push(IpCidr::new(address.into(), 0));});
	let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; WINDOW]), tcp::SocketBuffer::new(vec![0u8; WINDOW]));
	socket.set_nagle_enabled(false);
	socket.set_hop_limit(Some(HOPS));
	if socket.connect(iface.context(), target, (address, port)).is_err() {
		state.count(Count::Full);
		return reset(&stream);
	}
	state.count(Count::Opened);
	let mut sockets = SocketSet::new(Vec::new());
	let handle = sockets.add(socket);
	let (mut connected, mut client_eof, mut far_fin, mut far_done) = (false, false, false, false);
	let (mut inbuf, mut out, mut written, mut idle_at) = (vec![0u8; CHUNK], Vec::<u8>::new(), 0usize, started + SILENT);
	let ended = {
		let (mut reader, mut writer) = stream.split();
		'bridge: loop {
			let plan = shared.plan();
			// "A connection stays on its link and is reset when that link goes down."
			let Some((exit, link)) = route(&shared, &plan, &tunnel.exit, How::Stay(&id)) else {break Ended::Reset};
			iface.poll(clock(), &mut device, &mut sockets);
			let mut sent = true;
			for raw in std::mem::take(&mut device.tx) {
				sent = sent && shared.tunnelled(&plan, exit, link, raw).await;
				if sent {state.count(Count::UpPackets)}
			}
			if !sent {break Ended::Reset}
			let now = Instant::now();
			let socket = sockets.get_mut::<tcp::Socket>(handle);
			let at = socket.state();
			if !connected {
				if socket.may_send() {
					connected = true;
				} else if at == tcp::State::Closed || now >= started + CONNECT {
					socket.abort();
					break Ended::Unopened;
				}
			}
			if connected {
				// States past the far side's FIN: with it received, the far side has no more to say.
				far_fin |= matches!(at, tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait);
				if at == tcp::State::Closed && !(far_fin && client_eof) {break Ended::Reset}
				if now >= idle_at || slot.closed.load(Ordering::Relaxed) {break if now >= idle_at {Ended::Idle} else {Ended::Reset}}
				if out.is_empty() && !far_done {
					let taken = socket.recv(|data| {
						let taken = data.len().min(CHUNK);
						out.extend_from_slice(&data[..taken]);
						(taken, ())
					});
					// With the far side's FIN and every byte before it taken, the half close goes on to the client.
					if matches!(taken, Err(RecvError::Finished)) {
						far_done = true;
						let _ = writer.shutdown().await;
					}
				}
				if matches!(at, tcp::State::Closed | tcp::State::TimeWait) && far_done && client_eof && out.is_empty() {break Ended::Graceful}
			}
			let socket = sockets.get_mut::<tcp::Socket>(handle);
			let room = if connected && !client_eof && socket.may_send() {(socket.send_capacity() - socket.send_queue()).min(CHUNK)} else {0};
			let wake = [iface.poll_delay(clock(), &sockets).map(|delay| now + Duration::from_micros(delay.total_micros())), Some(now + TICK), Some(if connected {idle_at} else {started + CONNECT})].into_iter().flatten().min().unwrap_or(now);
			tokio::select! {
				Some(raw) = arrivals.recv() => {
					let mut packets = vec![raw];
					while packets.len() < QUEUE {
						let Ok(more) = arrivals.try_recv() else {break};
						packets.push(more);
					}
					for raw in packets {
						// An error from the far side's path, found by the packet it quotes: a destination that cannot be reached ends the connection. "Packet too big" and the rest are the stack's to ignore, since its segments fit the link.
						match netstack::parse(&raw).and_then(|packet| packet.icmp.map(|icmp| (packet.protocol, icmp))) {
							Some((Protocol::ICMP, (3, code))) if code != 4 => break 'bridge Ended::Reset,
							Some((Protocol::ICMPV6, (1, _))) => break 'bridge Ended::Reset,
							Some(_) => {}
							None => device.rx.push_back(raw),
						}
					}
				}
				read = reader.read(&mut inbuf[..room]), if room > 0 => match read {
					Ok(0) => {
						client_eof = true;
						sockets.get_mut::<tcp::Socket>(handle).close();
					}
					Ok(n) => {
						idle_at = Instant::now() + IDLE;
						state.add(Count::UpBytes, n);
						let _ = sockets.get_mut::<tcp::Socket>(handle).send_slice(&inbuf[..n]);
					}
					Err(_) => sockets.get_mut::<tcp::Socket>(handle).abort(),
				},
				wrote = writer.write(&out[written..]), if !out.is_empty() => match wrote {
					Ok(n) if n > 0 => {
						idle_at = Instant::now() + IDLE;
						state.add(Count::DownBytes, n);
						written += n;
						if written == out.len() {
							out.clear();
							written = 0;
						}
					}
					_ => sockets.get_mut::<tcp::Socket>(handle).abort(),
				},
				_ = sleep_until(wake) => {}
			}
		}
	};
	if ended != Ended::Graceful {
		// "A reset on either side resets the other": the far side is told when the link can carry it, and the client always.
		sockets.get_mut::<tcp::Socket>(handle).abort();
		iface.poll(clock(), &mut device, &mut sockets);
		let plan = shared.plan();
		if let Some((exit, link)) = route(&shared, &plan, &tunnel.exit, How::Stay(&id)) {
			for raw in std::mem::take(&mut device.tx) {
				if shared.tunnelled(&plan, exit, link, raw).await {state.count(Count::UpPackets)}
			}
		}
		reset(&stream);
	}
	state.count(match ended {
		Ended::Unopened => Count::ConnectFailed,
		Ended::Reset => Count::Reset,
		Ended::Idle => Count::Idled,
		Ended::Graceful => return,
	});
}

/// The packets of one connection's userspace stack: what arrived from the link waits in `rx`, and what the stack made waits in `tx` to be sent into the link.
pub(super) struct Wire {pub(super) rx: VecDeque<Vec<u8>>, pub(super) tx: Vec<Vec<u8>>, pub(super) mtu: usize}

pub(super) struct Received(Vec<u8>);

pub(super) struct Made<'a>(&'a mut Vec<Vec<u8>>);

impl phy::RxToken for Received {
	fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {f(&self.0)}
}

impl phy::TxToken for Made<'_> {
	fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
		let mut raw = vec![0u8; len];
		let result = f(&mut raw);
		self.0.push(raw);
		result
	}
}

impl Device for Wire {
	type RxToken<'a> = Received where Self: 'a;
	type TxToken<'a> = Made<'a> where Self: 'a;

	fn receive(&mut self, _: Clock) -> Option<(Received, Made<'_>)> {
		if self.tx.len() >= MADE {return None}
		let raw = self.rx.pop_front()?;
		Some((Received(raw), Made(&mut self.tx)))
	}

	fn transmit(&mut self, _: Clock) -> Option<Made<'_>> {if self.tx.len() >= MADE {None} else {Some(Made(&mut self.tx))}}

	fn capabilities(&self) -> DeviceCapabilities {
		let mut capabilities = DeviceCapabilities::default();
		capabilities.medium = Medium::Ip;
		capabilities.max_transmission_unit = self.mtu;
		capabilities
	}
}

/// One UDP session of a client: "A session per client address and port, with its own translated port."
struct Session {link: [u8; 16], port: u16, last: Instant, budget: Budget, _mapping: Mapping, slot: Slot}

/// A UDP tunnel: every datagram of a client goes into the link from the session of that client's address and port, and what the far side answers on that session's port goes back to the client from the tunnel's socket.
async fn datagrams(shared: Arc<Shared>, tunnel: Arc<config::Tunnel>, socket: Arc<UdpSocket>, state: Arc<State>) {
	let target = tunnel.target.0;
	let (queue, mut arrivals) = mpsc::channel::<Vec<u8>>(QUEUE);
	let (mut sessions, mut ports) = (HashMap::<SocketAddr, Session>::new(), HashMap::<u16, SocketAddr>::new());
	let (mut buf, mut tick) = (vec![0u8; 65535], interval(TICK));
	tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
	loop {
		tokio::select! {
			received = socket.recv_from(&mut buf) => {
				let Ok((n, client)) = received else {
					sleep(Duration::from_millis(50)).await;
					continue;
				};
				if !state.allowed(client.ip()) {
					state.count(Count::Sources);
					continue;
				}
				let plan = shared.plan();
				if !sessions.contains_key(&client) {
					let key = Key {protocol: Protocol::UDP, src: client.ip(), dst: target.ip(), sport: client.port(), dport: target.port()};
					let Some((_, link)) = route(&shared, &plan, &tunnel.exit, How::Pick(&key)) else {
						state.count(Count::Down);
						continue;
					};
					let Some(slot) = state.admit(client.ip(), Instant::now()) else {continue};
					let id = plan.links[link].id;
					let Some(port) = shared.nat.tunnel(id, Protocol::UDP, target, queue.clone(), state.clone()) else {
						state.count(Count::Full);
						continue;
					};
					state.count(Count::Opened);
					ports.insert(port, client);
					sessions.insert(client, Session {link: id, port, last: Instant::now(), budget: Budget(0), _mapping: Mapping {shared: shared.clone(), link: id, protocol: Protocol::UDP, target, port}, slot});
				}
				let Some(session) = sessions.get_mut(&client) else {continue};
				let Some((exit, link)) = route(&shared, &plan, &tunnel.exit, How::Stay(&session.link)) else {
					state.count(Count::Down);
					ports.remove(&session.port);
					sessions.remove(&client);
					continue;
				};
				session.budget.sent(n);
				let of = &plan.links[link];
				let Some(address) = of.address(target.is_ipv4()) else {
					state.count(Count::Down);
					continue;
				};
				// "A datagram larger than the link carries is dropped and counted."
				if n + if target.is_ipv4() {28} else {48} > usize::from(of.mtu()) {
					state.count(Count::Dropped);
					continue;
				}
				let mut raw = Vec::with_capacity(n + 48);
				let built = match (address, target.ip()) {
					(IpAddr::V4(from), IpAddr::V4(to)) => PacketBuilder::ipv4(from.octets(), to.octets(), HOPS).udp(session.port, target.port()).write(&mut raw, &buf[..n]),
					(IpAddr::V6(from), IpAddr::V6(to)) => PacketBuilder::ipv6(from.octets(), to.octets(), HOPS).udp(session.port, target.port()).write(&mut raw, &buf[..n]),
					_ => continue,
				};
				if built.is_ok() && shared.tunnelled(&plan, exit, link, raw).await {
					session.last = Instant::now();
					state.add(Count::UpBytes, n);
					state.count(Count::UpPackets);
				} else {
					state.count(Count::Dropped);
				}
			}
			Some(raw) = arrivals.recv() => {
				// "A datagram from the link reaches a client only when it answers that client's session, by the tunnel's target address and port": the translation has matched the address and the port already, and the packet's destination port names the session.
				let Some(packet) = netstack::parse(&raw).filter(|packet| packet.protocol == Protocol::UDP && !packet.fragment && packet.len >= packet.upper + 8) else {continue};
				let Some(client) = ports.get(&packet.dport).copied() else {
					state.count(Count::Dropped);
					continue;
				};
				let payload = &raw[packet.upper + 8..packet.len];
				// "What is past that is dropped and counted, so that a forged client address does not make the entry a reflector."
				if !sessions.get_mut(&client).is_some_and(|session| session.budget.answer(payload.len())) {
					state.count(Count::Dropped);
					continue;
				}
				if socket.send_to(payload, client).await.is_ok() {state.add(Count::DownBytes, payload.len())}
			}
			_ = tick.tick() => {
				let (plan, now) = (shared.plan(), Instant::now());
				sessions.retain(|_, session| {
					let keep = !session.slot.closed.load(Ordering::Relaxed) && now.saturating_duration_since(session.last) < SESSION && route(&shared, &plan, &tunnel.exit, How::Stay(&session.link)).is_some();
					if !keep {ports.remove(&session.port);}
					keep
				});
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_source_is_an_ipv4_address_or_an_ipv6_64() {
		assert_eq!(source("192.0.2.7".parse().unwrap()), "192.0.2.7".parse::<IpAddr>().unwrap());
		assert_eq!(source("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap()), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
		assert_eq!(source("2001:db8:1:3::1".parse().unwrap()), "2001:db8:1:3::".parse::<IpAddr>().unwrap());
	}

	#[test]
	fn a_source_opens_eight_a_second_holds_sixteen_and_a_tunnel_holds_its_most() {
		let mut written: config::Tunnel = serde_json::from_value(serde_json::json!({"tag": "t", "protocol": "tcp", "listen": "127.0.0.1:1", "exit": "far", "target": "93.184.216.34:1", "max_connections": 20})).unwrap();
		let (state, start, one) = (Arc::new(State::new(&written)), Instant::now(), "192.0.2.1".parse::<IpAddr>().unwrap());
		let mut held: Vec<Slot> = (0..8).map(|_| state.admit(one, start).unwrap()).collect();
		assert!(state.admit(one, start + Duration::from_millis(900)).is_none(), "a ninth in one second was let in");
		assert_eq!(state.totals().refused_rate, 1);
		held.extend((0..8).map(|_| state.admit(one, start + Duration::from_millis(1100)).unwrap()));
		assert!(state.admit(one, start + Duration::from_millis(2200)).is_none());
		assert_eq!((state.totals().refused_client, state.totals().open), (1, 16));
		let (a, b, c) = ("2001:db8::1".parse().unwrap(), "2001:db8::2".parse().unwrap(), "2001:db8:0:1::1".parse().unwrap());
		held.extend((0..4).map(|_| state.admit(a, start).unwrap()));
		assert_eq!(state.totals().open, 20);
		assert!(state.admit(c, start).is_none());
		assert_eq!(state.totals().refused_limit, 1);
		held.pop();
		assert!(state.admit(b, start + Duration::from_secs(5)).is_some());
		written.max_connections = Some(2);
		state.retune(&written);
		let told: Vec<bool> = held.iter().map(|slot| slot.closed.load(Ordering::Relaxed)).collect();
		assert_eq!(told.iter().filter(|closed| !**closed).count(), 2);
		assert!(!told[0] && !told[1] && told[2..].iter().all(|closed| *closed));
	}

	#[test]
	fn answers_are_three_times_what_the_client_sent_since_its_last_datagram_and_4096() {
		let mut budget = Budget(0);
		budget.sent(100);
		assert!(budget.answer(4396));
		assert!(!budget.answer(1));
		budget.sent(0);
		assert!(budget.answer(4096) && !budget.answer(1));
		budget.sent(1);
		assert!(!budget.answer(4100) && budget.answer(4099));
	}
}
