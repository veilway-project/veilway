//! Management through a node link (`protocol/panel-nodes.md` of the docs, threat model 5.19): the node that manages calls the control API of the other one inside the link's WireGuard session, over TCP to port 47874 on the other node's own link address.
//! Nothing listens on an interface. On the node that is managed (`manage: "by_peer"`) the one branch at the top of `Shared::ingress` hands a TCP packet from that link's peer to that address and port to a userspace TCP stack, and the accepted stream goes to whoever holds `Engine::managed`, which is the control API with its allowlist. On the node that manages (`manage: "peer"`) the same branch hands the answers of the connections it opened to those connections, and nothing else: it has no listener, so a connection attempt from the other node is never taken.
//! Who is calling is the link's WireGuard session (`Plan::link_of`), never an address. A management packet is never a flow of the flow table, never translated by `chain::Nat`, never charged to a user or a link's quota and never meets a rule: the hook runs before every one of those, and the addresses it looks at are link addresses, which no user can send to and no answer to a user's flow comes from.
//! One connection serves one request. The reader of the answer is strict and bounded: it takes HTTP/1.1 with a `Content-Length`, three headers (`content-length`, `etag`, `content-type`) and nothing else, and what is larger or odd ends the connection.
use super::chain::HOPS;
use super::netstack;
use super::plan::{Carrier, Plan};
use super::tunnel::Wire;
use super::{link, Shared};
use crate::config::{random, Config, LinkManage, Protocol};
use smoltcp::iface::{Config as Iface, Interface, SocketSet};
use smoltcp::socket::tcp::{self, RecvError};
use smoltcp::time::Instant as Clock;
use smoltcp::wire::{HardwareAddress, IpCidr};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep_until, timeout, Instant};

/// The port inside the link, fixed. 47873 is the control channel of a device.
pub const PORT: u16 = 47874;
/// "SYN answered within 10 s", for both sides: a connection that is not open by then is given up.
const CONNECT: Duration = Duration::from_secs(10);
/// How long a request waits for one of the four places of its link before the answer is `busy`.
const WAIT: Duration = Duration::from_secs(5);
/// A connection with no byte either way for this long is closed. An upstream preview waits 75 s for its answer, so it is longer than that.
const IDLE: Duration = Duration::from_secs(120);
const TICK: Duration = Duration::from_secs(1);
/// What each side of the userspace TCP of a connection buffers, and the window of the pipe to whoever serves the stream. The memory is not touched until bytes are in it.
const WINDOW: usize = 262144;
const CHUNK: usize = 16384;
/// Packets from the link that wait for one connection. One that finds it full is dropped and counted.
const QUEUE: usize = 256;
/// Connections at once for one link, on each side.
pub const PER_LINK: usize = 4;
/// "4 MiB request body" and "8 MiB answer body".
pub const BODY: usize = 4 << 20;
pub const ANSWER: usize = 8 << 20;
/// The most a request line and headers, or an answer's, may take.
const HEAD: usize = 16 << 10;
const HEADERS: usize = 64;
/// The ports a connection of the node that manages is made from.
const EPHEMERAL: u16 = 49152;

/// What the management connections of one link count. Everything but `open` only grows.
#[derive(Default)]
pub struct Counters {opened: AtomicU64, open: AtomicU64, refused: AtomicU64, failed: AtomicU64, reset: AtomicU64, idled: AtomicU64, dropped: AtomicU64, denied: AtomicU64, up_bytes: AtomicU64, down_bytes: AtomicU64, last: AtomicU64}

/// `Counters` as they are read: connections taken and open now, refused (a fifth connection, a connection attempt to the node that manages, no control API to serve, a stray packet), failed to open (reset or silent), ended by a reset, closed for silence, packets that a full queue dropped, requests turned away for their route, and the bytes of the stream up (sent into the link) and down (taken out of it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {pub opened: u64, pub open: u64, pub refused: u64, pub failed: u64, pub reset: u64, pub idled: u64, pub dropped: u64, pub denied: u64, pub up_bytes: u64, pub down_bytes: u64}

impl Counters {
	pub fn totals(&self) -> Totals {
		let get = |count: &AtomicU64| count.load(Ordering::Relaxed);
		Totals {opened: get(&self.opened), open: get(&self.open), refused: get(&self.refused), failed: get(&self.failed), reset: get(&self.reset), idled: get(&self.idled), dropped: get(&self.dropped), denied: get(&self.denied), up_bytes: get(&self.up_bytes), down_bytes: get(&self.down_bytes)}
	}

	/// A refusal is logged for the first and then for every 256th: the packets are a peer's to send.
	fn refuse(&self, tag: &str, why: &str) {
		if self.refused.fetch_add(1, Ordering::Relaxed) % 256 == 0 {tracing::info!("link {tag}: management refused: {why} ({} refused so far)", self.refused.load(Ordering::Relaxed))}
	}

	/// Says each change between a link whose management works and one whose does not, with what happened.
	fn works(&self, tag: &str, ok: bool, why: &str) {
		let now = if ok {1} else {2};
		if self.last.swap(now, Ordering::Relaxed) != now {tracing::info!("link {tag}: management {}{}", if ok {"works"} else {"does not work"}, if why.is_empty() {String::new()} else {format!(": {why}")})}
	}
}

/// A stream the node that is managed serves: one request of the node that manages, from the link `tag`.
pub struct Managed {pub tag: String, pub id: [u8; 16], pub stream: DuplexStream}

/// What the engine holds for management: the connections of the links by the link's id and the port the other node's packets name, the way to whoever serves the streams, and the places of each link on the node that manages.
#[derive(Default)]
pub struct State {
	conns: Mutex<HashMap<([u8; 16], u16), mpsc::Sender<Vec<u8>>>>,
	sink: Mutex<Option<mpsc::Sender<Managed>>>,
	gates: Mutex<HashMap<[u8; 16], Arc<Semaphore>>>,
}

impl State {
	/// Whoever serves management takes the streams from here, and the one before it no longer does. A node that has none refuses every connection.
	pub fn serve(&self) -> mpsc::Receiver<Managed> {
		let (to, from) = mpsc::channel(PER_LINK);
		*self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(to);
		from
	}
}

/// What a request to the other node asks for. `path` and `query` are held to a short list of characters.
pub struct Request {pub method: String, pub path: String, pub query: Option<String>, pub if_match: Option<String>, pub content_type: Option<String>, pub body: Vec<u8>, pub within: Duration}

/// What came back: the status, `etag` and `content-type` when it had them, and the body.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {pub status: u16, pub etag: Option<String>, pub content_type: Option<String>, pub body: Vec<u8>}

/// Why a request did not get an answer.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// The config has no enabled node link of that tag.
	NoLink,
	/// The link does not have `manage: "peer"` here.
	NotManaged,
	/// The link is not up. Nothing was sent. With the state it is reported in, since when, and what its dialler's last attempt came to.
	Down {status: link::Status, since: Duration, failed: Option<link::Status>},
	/// Four connections are open and none was freed in 5 s.
	Busy,
	/// The connection was reset: the other node does not serve management, or has no control API.
	Refused,
	/// No answer to the connection within 10 s, or the deadline passed.
	Silent,
	/// The request is not one this node sends: a method, a path or a header that is not in the short list, or a body over 4 MiB.
	BadRequest,
	/// The answer is over 8 MiB.
	TooLarge,
	/// The answer is not HTTP/1.1 with a length, or has a header twice, or is cut short.
	BadAnswer,
}

/// What a config pushed through the managing link does to that link, see `standing`.
#[derive(Debug, PartialEq, Eq)]
pub enum Standing {
	/// The link is there as it was, in what the other node's management depends on.
	Kept,
	/// The document has no link with that id.
	Removed,
	/// The document has it, and something the management depends on is not as it was.
	Changed(&'static str),
}

/// "A document in which that link is missing, disabled, or has a different `id`, `direction`, keys, addresses, `manage`, `transport_secret`, `inbound` or `peer`, or an inbound that differs in what the link is carried by (its whole content: the key, the transports and their listen addresses)." `running` is the config in force and `id` the link the request came through.
pub fn standing(running: &Config, pushed: &Config, id: [u8; 16]) -> Standing {
	let Some(held) = running.links.iter().find(|link| link.id.0 == id) else {return Standing::Kept};
	let Some(now) = pushed.links.iter().find(|link| link.id.0 == id) else {return Standing::Removed};
	let inbound = |config: &Config| held.inbound.as_ref().and_then(|tag| config.inbounds.iter().find(|inbound| inbound.tag == *tag)).cloned();
	match () {
		_ if now.enabled == Some(false) => Standing::Changed("it is disabled"),
		_ if now.manage != held.manage => Standing::Changed("its manage is not what it was"),
		_ if now.direction != held.direction => Standing::Changed("its direction is not what it was"),
		_ if now.addresses != held.addresses => Standing::Changed("its addresses are not what they were"),
		_ if now.inbound != held.inbound => Standing::Changed("its inbound is not what it was"),
		_ if inbound(running) != inbound(pushed) => Standing::Changed("the inbound it is carried by is not what it was"),
		_ if now.public_key != held.public_key || now.private_key != held.private_key => Standing::Changed("its keys are not what they were"),
		_ if now.transport_secret != held.transport_secret => Standing::Changed("its transport secret is not what it was"),
		_ if now.peer != held.peer => Standing::Changed("its peer is not what it was"),
		_ => Standing::Kept,
	}
}

/// How a connection begins: by opening one to the other node, or by taking one it is dialled with.
enum Mode {
	Dial {mine: IpAddr, theirs: IpAddr, port: u16},
	Serve {own: IpAddr, handoff: DuplexStream, tag: String},
}

/// A place in the table of connections, given back when it is dropped.
struct Held {shared: Arc<Shared>, key: ([u8; 16], u16), state: Arc<link::State>}

impl Drop for Held {
	fn drop(&mut self) {
		self.shared.manage.conns.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.key);
		self.state.manage.open.fetch_sub(1, Ordering::Relaxed);
	}
}

/// What ended a connection.
#[derive(PartialEq, Eq)]
enum Ended {Graceful, Unopened, Refused, Reset, Idle}

/// Where a link is in the plan now, held to what the connection was made for: the link of that id, still managed in the same direction and up. A reload that changed the plan does not end a connection, and one that took the link away or changed what it is does.
fn find(plan: &Plan, id: &[u8; 16], role: LinkManage) -> Option<usize> {
	plan.links.iter().position(|link| link.id == *id && matches!(link.carrier, Carrier::Paired) && link.manage == Some(role)).filter(|at| plan.up(*at))
}

/// The packets of one connection, from its first to its last: a userspace TCP stack on the link's address, bridged to a pipe. For `Mode::Dial` the first packet is the SYN the stack makes, for `Mode::Serve` it is the SYN that is waiting in `arrivals`.
#[allow(clippy::too_many_arguments)]
async fn bridge(shared: Arc<Shared>, id: [u8; 16], mode: Mode, mut arrivals: mpsc::Receiver<Vec<u8>>, stream: DuplexStream, held: Held, mut told: Option<oneshot::Sender<Result<(), Error>>>, _permit: Option<OwnedSemaphorePermit>) {
	let (role, address) = match &mode {Mode::Dial {mine, ..} => (LinkManage::Peer, *mine), Mode::Serve {own, ..} => (LinkManage::ByPeer, *own)};
	let (state, mtu) = (&held.state.manage, shared.plan().links.iter().find(|link| link.id == id).map_or(1280, |link| link.mtu()));
	let (started, mut seed) = (Instant::now(), [0u8; 8]);
	let clock = || Clock::from_micros(started.elapsed().as_micros() as i64);
	let mut device = Wire {rx: Default::default(), tx: Vec::new(), mtu: usize::from(mtu)};
	let _ = random(&mut seed);
	let mut config = Iface::new(HardwareAddress::Ip);
	config.random_seed = u64::from_le_bytes(seed);
	let mut iface = Interface::new(config, &mut device, clock());
	// Every address is on the link: the interface has no neighbours to ask and no route to look up.
	iface.update_ip_addrs(|addresses| {let _ = addresses.push(IpCidr::new(address.into(), 0));});
	let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; WINDOW]), tcp::SocketBuffer::new(vec![0u8; WINDOW]));
	socket.set_nagle_enabled(false);
	socket.set_hop_limit(Some(HOPS));
	let began = match &mode {
		Mode::Dial {mine, theirs, port} => socket.connect(iface.context(), (*theirs, PORT), (*mine, *port)).is_ok(),
		Mode::Serve {own, ..} => socket.listen((*own, PORT)).is_ok(),
	};
	let (mut handoff, tag) = if let Mode::Serve {handoff, tag, ..} = mode {(Some(handoff), tag)} else {(None, String::new())};
	if !began {
		state.failed.fetch_add(1, Ordering::Relaxed);
		if let Some(told) = told.take() {let _ = told.send(Err(Error::Refused));}
		return;
	}
	let mut sockets = SocketSet::new(Vec::new());
	let handle = sockets.add(socket);
	let (mut connected, mut client_eof, mut far_fin, mut far_done) = (false, false, false, false);
	let (mut inbuf, mut out, mut written, mut idle_at) = (vec![0u8; CHUNK], Vec::<u8>::new(), 0usize, started + CONNECT);
	let ended = {
		let (mut reader, mut writer) = split(stream);
		'bridge: loop {
			let plan = shared.plan();
			let Some(at) = find(&plan, &id, role) else {break Ended::Reset};
			iface.poll(clock(), &mut device, &mut sockets);
			let mut sent = true;
			for raw in std::mem::take(&mut device.tx) {sent = sent && shared.into_link(&plan, at, &raw).await}
			if !sent {break Ended::Reset}
			let now = Instant::now();
			let socket = sockets.get_mut::<tcp::Socket>(handle);
			let at_state = socket.state();
			if !connected {
				if socket.may_send() {
					connected = true;
					idle_at = now + IDLE;
					if let Some(told) = told.take() {
						state.works(&plan.links[at].tag, true, "");
						let _ = told.send(Ok(()));
					} else if let Some(stream) = handoff.take() {
						// Whoever serves management has no place for it, or there is none: the connection is reset.
						if !shared.manage.sink.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|sink| sink.try_send(Managed {tag: tag.clone(), id, stream}).is_ok()) {
							state.refuse(&tag, "the control API does not take it");
							socket.abort();
							iface.poll(clock(), &mut device, &mut sockets);
							for raw in std::mem::take(&mut device.tx) {shared.into_link(&plan, at, &raw).await;}
							return;
						}
					}
					state.opened.fetch_add(1, Ordering::Relaxed);
				} else if at_state == tcp::State::Closed || now >= started + CONNECT {
					socket.abort();
					break if at_state == tcp::State::Closed {Ended::Refused} else {Ended::Unopened};
				}
			}
			if connected {
				far_fin |= matches!(at_state, tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait);
				if at_state == tcp::State::Closed && !(far_fin && client_eof) {break Ended::Reset}
				if now >= idle_at {break Ended::Idle}
				if out.is_empty() && !far_done {
					let taken = socket.recv(|data| {
						let taken = data.len().min(CHUNK);
						out.extend_from_slice(&data[..taken]);
						(taken, ())
					});
					if matches!(taken, Err(RecvError::Finished)) {
						far_done = true;
						let _ = writer.shutdown().await;
					}
				}
				if matches!(at_state, tcp::State::Closed | tcp::State::TimeWait) && far_done && client_eof && out.is_empty() {break Ended::Graceful}
			}
			let socket = sockets.get_mut::<tcp::Socket>(handle);
			let room = if connected && !client_eof && socket.may_send() {(socket.send_capacity() - socket.send_queue()).min(CHUNK)} else {0};
			let wake = [iface.poll_delay(clock(), &sockets).map(|delay| now + Duration::from_micros(delay.total_micros())), Some(now + TICK), Some(if connected {idle_at} else {started + CONNECT})].into_iter().flatten().min().unwrap_or(now);
			tokio::select! {
				Some(raw) = arrivals.recv() => {
					device.rx.push_back(raw);
					while device.rx.len() < QUEUE {
						let Ok(more) = arrivals.try_recv() else {break};
						device.rx.push_back(more);
					}
				}
				read = reader.read(&mut inbuf[..room]), if room > 0 => match read {
					Ok(0) => {
						client_eof = true;
						sockets.get_mut::<tcp::Socket>(handle).close();
					}
					Ok(n) => {
						idle_at = Instant::now() + IDLE;
						state.up_bytes.fetch_add(n as u64, Ordering::Relaxed);
						let _ = sockets.get_mut::<tcp::Socket>(handle).send_slice(&inbuf[..n]);
					}
					Err(_) => sockets.get_mut::<tcp::Socket>(handle).abort(),
				},
				wrote = writer.write(&out[written..]), if !out.is_empty() => match wrote {
					Ok(n) if n > 0 => {
						idle_at = Instant::now() + IDLE;
						state.down_bytes.fetch_add(n as u64, Ordering::Relaxed);
						written += n;
						if written == out.len() {
							out.clear();
							written = 0;
						}
					}
					// Nobody reads the stream any more: the connection is over, and what is left of the other node's answer is not kept.
					_ => break 'bridge Ended::Reset,
				},
				_ = sleep_until(wake) => {}
			}
		}
	};
	if ended != Ended::Graceful {
		// A reset on either side resets the other: the other node is told when the link can carry it.
		sockets.get_mut::<tcp::Socket>(handle).abort();
		iface.poll(clock(), &mut device, &mut sockets);
		let plan = shared.plan();
		if let Some(at) = find(&plan, &id, role) {for raw in std::mem::take(&mut device.tx) {shared.into_link(&plan, at, &raw).await;}}
	}
	match ended {
		Ended::Unopened | Ended::Refused => {
			state.failed.fetch_add(1, Ordering::Relaxed);
			if let Some(told) = told.take() {
				let name = shared.plan().links.iter().find(|link| link.id == id).map_or_else(String::new, |link| link.tag.clone());
				state.works(&name, false, if ended == Ended::Refused {"the other node reset the connection: it does not serve management, or runs without a control API"} else {"the other node did not answer within 10 s"});
				let _ = told.send(Err(if ended == Ended::Refused {Error::Refused} else {Error::Silent}));
			}
		}
		Ended::Reset => drop(state.reset.fetch_add(1, Ordering::Relaxed)),
		Ended::Idle => drop(state.idled.fetch_add(1, Ordering::Relaxed)),
		Ended::Graceful => {}
	}
}

impl Shared {
	/// The branch at the top of `ingress` for a packet that came through link `link`: whether it was management's, and so nobody else's. `raw` is the whole packet.
	pub(super) async fn manage_ingress(self: &Arc<Self>, plan: &Arc<Plan>, link: usize, raw: &[u8]) -> bool {
		let of = &plan.links[link];
		let Some(role) = of.manage else {return false};
		let Some(packet) = netstack::parse(raw).filter(|packet| packet.protocol == Protocol::TCP && !packet.fragment) else {return false};
		let Some((mine, theirs)) = of.management(packet.dst.is_ipv4()) else {return false};
		// The other node's own address, to this node's own address. What is not is a user's, or another link's, or nothing, and goes on as it always did.
		if packet.dst != mine || packet.src != theirs {return false}
		let (counters, flags) = (&of.state.manage, raw.get(packet.upper + 13).copied().filter(|_| packet.upper + 14 <= packet.len).unwrap_or(0));
		let (key, syn) = (of.id, flags & 0x12 == 0x02);
		if role == LinkManage::Peer {
			// Only the answers of connections this node opened. A connection attempt from the other node has no listener: it is counted and dropped, as every other packet to a link address is.
			let queue = if packet.sport == PORT {self.manage.conns.lock().unwrap_or_else(|e| e.into_inner()).get(&(key, packet.dport)).cloned()} else {None};
			match queue {
				Some(queue) => {
					of.state.traffic.down(packet.len);
					if queue.try_send(raw[..packet.len].to_vec()).is_err() {counters.dropped.fetch_add(1, Ordering::Relaxed);}
				}
				None => {
					if syn {
						counters.refuse(&of.tag, "the other node tried to open a connection to this node, which has no listener");
						return false;
					}
					// What answers a connection that has ended is told so, as any TCP does, so that the other node does not retransmit to nobody.
					if packet.sport != PORT {return false}
					counters.dropped.fetch_add(1, Ordering::Relaxed);
					if let Some(rst) = netstack::tcp_rst(&raw[..packet.len]) {self.into_link(plan, link, &rst).await;}
					return true;
				}
			}
			return true;
		}
		if packet.dport != PORT {return false}
		of.state.traffic.down(packet.len);
		let known = self.manage.conns.lock().unwrap_or_else(|e| e.into_inner()).get(&(key, packet.sport)).cloned();
		if let Some(queue) = known {
			if queue.try_send(raw[..packet.len].to_vec()).is_err() {counters.dropped.fetch_add(1, Ordering::Relaxed);}
			return true;
		}
		// A segment of no connection is answered with a reset, and only a SYN opens one.
		if !syn {
			counters.dropped.fetch_add(1, Ordering::Relaxed);
			if let Some(rst) = netstack::tcp_rst(&raw[..packet.len]) {self.into_link(plan, link, &rst).await;}
			return true;
		}
		let admitted = {
			let mut conns = self.manage.conns.lock().unwrap_or_else(|e| e.into_inner());
			let (open, sink) = (conns.keys().filter(|(id, _)| *id == key).count(), self.manage.sink.lock().unwrap_or_else(|e| e.into_inner()).is_some());
			if open >= PER_LINK || !sink {
				counters.refuse(&of.tag, if sink {"a fifth connection"} else {"no control API serves management on this node"});
				None
			} else {
				let (queue, arrivals) = mpsc::channel(QUEUE);
				let _ = queue.try_send(raw[..packet.len].to_vec());
				conns.insert((key, packet.sport), queue);
				counters.open.fetch_add(1, Ordering::Relaxed);
				Some(arrivals)
			}
		};
		match admitted {
			Some(arrivals) => {
				let (ours, handoff) = duplex(WINDOW);
				tokio::spawn(bridge(self.clone(), key, Mode::Serve {own: mine, handoff, tag: of.tag.clone()}, arrivals, ours, Held {shared: self.clone(), key: (key, packet.sport), state: of.state.clone()}, None, None));
			}
			None => if let Some(rst) = netstack::tcp_rst(&raw[..packet.len]) {self.into_link(plan, link, &rst).await;},
		}
		true
	}

	/// One request through link `tag` to the other node's control API, which is what the relay route of the control API is. The link must have `manage: "peer"` and be up, and what is not so is answered at once with nothing sent.
	pub(super) async fn manage_request(self: &Arc<Self>, tag: &str, request: Request) -> Result<Answer, Error> {
		let started = Instant::now();
		let valid = |text: &str, allowed: fn(u8) -> bool, most: usize| text.len() <= most && text.bytes().all(allowed);
		let path = |byte: u8| byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte);
		let query = |byte: u8| byte.is_ascii_alphanumeric() || b"-._~=&%+,".contains(&byte);
		let header = |byte: u8| (0x20..0x7f).contains(&byte);
		if !["GET", "PUT", "POST", "DELETE", "PATCH"].contains(&request.method.as_str()) || !request.path.starts_with('/') || request.path.split('/').skip(1).any(|segment| segment.is_empty() || segment == "." || segment == "..") || !valid(&request.path, path, 512) || request.query.as_deref().is_some_and(|text| !valid(text, query, 256)) || [&request.if_match, &request.content_type].into_iter().flatten().any(|text| !valid(text, header, 256)) || request.body.len() > BODY {return Err(Error::BadRequest)}
		let plan = self.plan();
		let Some(at) = plan.links.iter().position(|link| matches!(link.carrier, Carrier::Paired) && link.tag == tag) else {return Err(Error::NoLink)};
		let of = &plan.links[at];
		if of.manage != Some(LinkManage::Peer) {return Err(Error::NotManaged)}
		if !plan.up(at) {
			let (status, since) = of.state.status();
			return Err(Error::Down {status, since, failed: of.state.failed()});
		}
		let Some((mine, theirs)) = of.management(true).or_else(|| of.management(false)) else {return Err(Error::NotManaged)};
		let (id, state) = (of.id, of.state.clone());
		drop(plan);
		let gate = self.manage.gates.lock().unwrap_or_else(|e| e.into_inner()).entry(id).or_insert_with(|| Arc::new(Semaphore::new(PER_LINK))).clone();
		let Ok(Ok(permit)) = timeout(WAIT, gate.acquire_owned()).await else {return Err(Error::Busy)};
		let (queue, arrivals) = mpsc::channel(QUEUE);
		let port = {
			let mut conns = self.manage.conns.lock().unwrap_or_else(|e| e.into_inner());
			let mut drawn = None;
			for _ in 0..64 {
				let mut bytes = [0u8; 2];
				let _ = random(&mut bytes);
				let port = EPHEMERAL + u16::from_le_bytes(bytes) % (u16::MAX - EPHEMERAL + 1);
				if !conns.contains_key(&(id, port)) {
					drawn = Some(port);
					break;
				}
			}
			let Some(port) = drawn else {return Err(Error::Busy)};
			conns.insert((id, port), queue);
			state.manage.open.fetch_add(1, Ordering::Relaxed);
			port
		};
		let (ours, mut stream) = duplex(WINDOW);
		let (told, opened) = oneshot::channel();
		tokio::spawn(bridge(self.clone(), id, Mode::Dial {mine, theirs, port}, arrivals, ours, Held {shared: self.clone(), key: (id, port), state}, Some(told), Some(permit)));
		match timeout(CONNECT + TICK, opened).await {
			Ok(Ok(Ok(()))) => {}
			Ok(Ok(Err(e))) => return Err(e),
			_ => return Err(Error::Silent),
		}
		timeout(request.within.saturating_sub(started.elapsed()), exchange(&mut stream, &request)).await.unwrap_or(Err(Error::Silent))
	}

	/// The request turned away for its route, counted for the link.
	pub(super) fn manage_denied(&self, tag: &str) {
		if let Some(link) = self.plan().links.iter().find(|link| matches!(link.carrier, Carrier::Paired) && link.tag == tag) {link.state.manage.denied.fetch_add(1, Ordering::Relaxed);}
	}

	/// How long ago the last WireGuard handshake of link `tag` completed on this node, None when it has none.
	pub(super) fn manage_heard(&self, tag: &str) -> Option<Duration> {
		let plan = self.plan();
		plan.links.iter().position(|link| matches!(link.carrier, Carrier::Paired) && link.tag == tag).and_then(|at| plan.handshake(at))
	}

	/// Ends the session of link `tag` when this node dials it, and forgets its WireGuard session, so the next session opens with a handshake under the config in force. A link this node listens for has nothing to end here: the node that dials it makes the new session.
	pub(super) fn manage_renew(&self, tag: &str) {
		let plan = self.plan();
		let Some(link) = plan.links.iter().find(|link| matches!(link.carrier, Carrier::Paired) && link.tag == tag && link.dialled.is_some()) else {return};
		plan.inbounds[link.inbound].tunnel.lock().wg.drop_sessions(&link.key);
		link.state.renew.notify_one();
		tracing::info!("link {tag}: a config was pushed through it, so its session ends and the next one opens with a handshake");
	}
}

/// One request and its answer on a stream, read as hostile input: HTTP/1.1 with a `Content-Length`, bounded, three headers kept.
async fn exchange(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), request: &Request) -> Result<Answer, Error> {
	let mut head = format!("{} {}{}{} HTTP/1.1\r\nhost: veilway\r\nconnection: close\r\n", request.method, request.path, if request.query.is_some() {"?"} else {""}, request.query.as_deref().unwrap_or(""));
	if let Some(tag) = &request.if_match {head.push_str(&format!("if-match: {tag}\r\n"))}
	if let Some(kind) = &request.content_type {head.push_str(&format!("content-type: {kind}\r\n"))}
	if request.method == "PUT" || request.method == "POST" || !request.body.is_empty() {head.push_str(&format!("content-length: {}\r\n", request.body.len()))}
	head.push_str("\r\n");
	stream.write_all(head.as_bytes()).await.map_err(|_| Error::Refused)?;
	stream.write_all(&request.body).await.map_err(|_| Error::Refused)?;
	stream.flush().await.map_err(|_| Error::Refused)?;
	let (mut buf, mut chunk) = (Vec::new(), vec![0u8; CHUNK]);
	let end = loop {
		if let Some(at) = buf.windows(4).position(|window| window == b"\r\n\r\n") {break at}
		if buf.len() > HEAD {return Err(Error::BadAnswer)}
		match stream.read(&mut chunk).await {
			Ok(0) | Err(_) => return Err(Error::BadAnswer),
			Ok(n) => buf.extend_from_slice(&chunk[..n]),
		}
	};
	if end > HEAD {return Err(Error::BadAnswer)}
	let (status, etag, content_type, length) = read_head(&buf[..end])?;
	let mut body = buf.split_off(end + 4);
	let length = length.unwrap_or(0);
	while body.len() < length {
		match stream.read(&mut chunk).await {
			Ok(0) | Err(_) => return Err(Error::BadAnswer),
			Ok(n) => body.extend_from_slice(&chunk[..n]),
		}
	}
	body.truncate(length);
	Ok(Answer {status, etag, content_type, body})
}

/// The head of an answer, without its blank line: the status, `etag`, `content-type` and the length of the body. Anything else of it is dropped, and what is not strictly HTTP/1.1 is refused: a status outside 200 to 599, a header without a name or with a control character, a folded line, a header of the three twice, any `transfer-encoding`, no `content-length` where a body is possible, a length that is not digits.
fn read_head(head: &[u8]) -> Result<(u16, Option<String>, Option<String>, Option<usize>), Error> {
	if !head.is_ascii() || head.iter().any(|byte| (*byte < 0x20 && *byte != b'\r' && *byte != b'\n' && *byte != b'\t') || *byte == 0x7f) {return Err(Error::BadAnswer)}
	let text = std::str::from_utf8(head).map_err(|_| Error::BadAnswer)?;
	let mut lines = text.split("\r\n");
	let status = lines.next().and_then(|line| line.strip_prefix("HTTP/1.1 ")).filter(|rest| rest.len() == 3 || rest.as_bytes().get(3) == Some(&b' ')).and_then(|rest| rest[..3].parse::<u16>().ok()).filter(|status| (200..600).contains(status)).ok_or(Error::BadAnswer)?;
	let (mut etag, mut kind, mut length, mut count) = (None, None, None, 0);
	for line in lines {
		count += 1;
		let (name, value) = line.split_once(':').ok_or(Error::BadAnswer)?;
		if count > HEADERS || name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)) || line.contains(['\r', '\n']) {return Err(Error::BadAnswer)}
		let value = value.trim_matches([' ', '\t']);
		let slot = match name.to_ascii_lowercase().as_str() {
			"content-length" => &mut length,
			"etag" => &mut etag,
			"content-type" => &mut kind,
			"transfer-encoding" => return Err(Error::BadAnswer),
			_ => continue,
		};
		if slot.replace(value.to_string()).is_some() {return Err(Error::BadAnswer)}
	}
	let length = match length {
		Some(digits) if !digits.is_empty() && digits.len() <= 10 && digits.bytes().all(|byte| byte.is_ascii_digit()) => Some(digits.parse::<usize>().map_err(|_| Error::BadAnswer)?),
		Some(_) => return Err(Error::BadAnswer),
		None if status == 204 || status == 304 => None,
		None => return Err(Error::BadAnswer),
	};
	if length.is_some_and(|length| length > ANSWER) {return Err(Error::TooLarge)}
	if [&etag, &kind].into_iter().flatten().any(|text| text.len() > 256) {return Err(Error::BadAnswer)}
	Ok((status, etag, kind, length))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn head(text: &str) -> Result<(u16, Option<String>, Option<String>, Option<usize>), Error> {read_head(text.as_bytes())}

	#[test]
	fn an_answer_with_a_length_is_read_and_only_three_headers_are_kept() {
		assert_eq!(head("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nETag: \"abc\"\r\ncontent-type: application/json\r\nset-cookie: a=b\r\nx-other: 1"), Ok((200, Some("\"abc\"".into()), Some("application/json".into()), Some(12))));
		assert_eq!(head("HTTP/1.1 204\r\nconnection: close"), Ok((204, None, None, None)));
	}

	#[test]
	fn what_is_not_strict_http_is_refused() {
		let bad = ["HTTP/1.0 200 OK\r\ncontent-length: 1", "HTTP/1.1 100 Continue\r\ncontent-length: 1", "HTTP/1.1 700 X\r\ncontent-length: 1", "HTTP/1.1 2000 X\r\ncontent-length: 1", "HTTP/1.1 200 OK", "HTTP/1.1 200 OK\r\ncontent-length: 1\r\ncontent-length: 1", "HTTP/1.1 200 OK\r\ncontent-length: +1", "HTTP/1.1 200 OK\r\ncontent-length: 1x", "HTTP/1.1 200 OK\r\ncontent-length: 1\r\ntransfer-encoding: chunked", "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n folded: x", "HTTP/1.1 200 OK\r\ncontent-length: 1\r\nno colon here", "HTTP/1.1 200 OK\r\ncontent-length: 1\r\netag: a\r\netag: b", "HTTP/1.1 200 OK\r\ncontent-length: 1\r\ncontent-type: a\u{0}b", "HTTP/1.1 200 OK\r\ncontent-length: \u{e9}", "HTTP/1.1 200 OK\r\ncontent-length: 99999999999"];
		for text in bad {assert!(matches!(head(text), Err(Error::BadAnswer | Error::TooLarge)), "{text:?} was taken");}
	}

	#[test]
	fn a_length_over_eight_mib_is_too_large_and_exactly_eight_mib_is_not() {
		assert_eq!(head(&format!("HTTP/1.1 200 OK\r\ncontent-length: {}", ANSWER + 1)), Err(Error::TooLarge));
		assert!(head(&format!("HTTP/1.1 200 OK\r\ncontent-length: {ANSWER}")).is_ok());
	}

	#[test]
	fn more_than_sixty_four_headers_are_refused() {
		let many = (0..HEADERS + 1).map(|n| format!("x-{n}: 1")).collect::<Vec<_>>().join("\r\n");
		assert_eq!(head(&format!("HTTP/1.1 200 OK\r\ncontent-length: 1\r\n{many}")), Err(Error::BadAnswer));
	}

	async fn talk(answer: &'static [u8]) -> Result<Answer, Error> {
		let (mut ours, mut theirs) = duplex(1 << 16);
		tokio::spawn(async move {
			let mut asked = vec![0u8; 4096];
			let _ = theirs.read(&mut asked).await;
			let _ = theirs.write_all(answer).await;
			let _ = theirs.shutdown().await;
		});
		exchange(&mut ours, &Request {method: "GET".into(), path: "/v1/status".into(), query: None, if_match: None, content_type: None, body: Vec::new(), within: Duration::from_secs(5)}).await
	}

	#[tokio::test]
	async fn the_body_is_cut_to_its_length_and_a_short_one_is_refused() {
		assert_eq!(talk(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nokEXTRA").await, Ok(Answer {status: 200, etag: None, content_type: None, body: b"ok".to_vec()}));
		assert_eq!(talk(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nok").await, Err(Error::BadAnswer));
		assert_eq!(talk(b"HTTP/1.1 200 OK\r\ncontent-length: 5").await, Err(Error::BadAnswer));
		assert_eq!(talk(b"garbage\r\n\r\n").await, Err(Error::BadAnswer));
	}

	#[test]
	fn a_pushed_config_may_not_change_what_management_depends_on() {
		let key = |byte: u8| veilway_wg::encode_key(&[byte; 32]);
		let mut doc = serde_json::json!({
			"version": 1, "dns": {"servers": ["1.1.1.1:53"]}, "inbounds": [{"tag": "links", "type": "veilway", "private_key": key(0x11), "address": ["10.9.0.1/24"], "transports": [{"type": "udp-obfs", "listen": "127.0.0.1:9"}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}], "exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}], "routing": {"default": "main", "rules": []}, "users": [],
			"links": [{"tag": "far", "id": "AAECAwQFBgcICQoLDA0ODw", "direction": "forward", "addresses": {"dialler": ["10.9.0.2"], "listener": ["10.9.0.3"]}, "manage": "by_peer", "transport_secret": key(0x41), "inbound": "links", "public_key": key(0x31), "exits": ["main"]}]
		});
		let running = Config::parse(doc.to_string().as_bytes()).unwrap();
		let id = running.links[0].id.0;
		let pushed = |change: &dyn Fn(&mut serde_json::Value)| {
			let mut next = doc.clone();
			change(&mut next);
			standing(&running, &Config::parse(next.to_string().as_bytes()).unwrap(), id)
		};
		assert_eq!(pushed(&|_| {}), Standing::Kept);
		assert_eq!(pushed(&|next| next["links"][0]["exits"] = serde_json::json!(["main"])), Standing::Kept);
		assert_eq!(pushed(&|next| next["links"] = serde_json::json!([])), Standing::Removed);
		assert_eq!(pushed(&|next| next["links"][0]["enabled"] = serde_json::json!(false)), Standing::Changed("it is disabled"));
		assert_eq!(pushed(&|next| next["links"][0]["addresses"]["dialler"] = serde_json::json!(["10.9.0.9"])), Standing::Changed("its addresses are not what they were"));
		assert_eq!(pushed(&|next| drop(next["links"][0].as_object_mut().unwrap().remove("manage"))), Standing::Changed("its manage is not what it was"));
		assert_eq!(pushed(&|next| next["links"][0]["public_key"] = serde_json::json!(key(0x32))), Standing::Changed("its keys are not what they were"));
		assert_eq!(pushed(&|next| next["links"][0]["transport_secret"] = serde_json::json!(key(0x42))), Standing::Changed("its transport secret is not what it was"));
		assert_eq!(pushed(&|next| next["inbounds"][0]["transports"][0]["listen"] = serde_json::json!("127.0.0.1:10")), Standing::Changed("the inbound it is carried by is not what it was"));
		assert_eq!(pushed(&|next| next["inbounds"][0]["private_key"] = serde_json::json!(key(0x12))), Standing::Changed("the inbound it is carried by is not what it was"));
		let mut reversed = running.clone();
		reversed.links[0].direction = crate::config::LinkDirection::Reverse;
		assert_eq!(standing(&running, &reversed, id), Standing::Changed("its direction is not what it was"));
		doc["links"][0]["id"] = serde_json::json!("AQECAwQFBgcICQoLDA0ODw");
		assert_eq!(standing(&running, &Config::parse(doc.to_string().as_bytes()).unwrap(), id), Standing::Removed);
	}
}
