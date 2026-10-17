//! The carrier of a legacy profile ("How traffic reaches Xray"): no WireGuard, no transport and no control channel. The device's packets enter a userspace stack (the vendored `ipstack`), and each TCP flow it accepts becomes a SOCKS5 `CONNECT` to Xray's loopback inbound, each UDP flow an `UDP ASSOCIATE` of its own, both with the run's login. The destination is always the address the stack saw. Names are not looked at: the system's resolver is pinned to the gateway address by the platform, and a query to it goes through Xray to a public resolver.
//!
//! The carrier does not run Xray. A supervisor that does (the helper) tells it through `Live` whether Xray is up. While it is not, the tunnel stays, open flows are reset, new ones fail at once with a reset and UDP is dropped. Nothing is let out, since nothing here opens a socket but to the loopback address of the hop.
//!
//! Everything that comes out of the device passes `packets::Front` first: ICMP echo to the gateway is answered, every other ICMP and every protocol that is not TCP or UDP is dropped and counted, and fragments are put together under a cap.
use crate::packets::{self, Front, Taken};
use crate::socks::{self, Fail};
use crate::status::{Counters, State, Status, XrayCounters, XrayView};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use veilway_proto::subscription::payload::Network;

pub use crate::status::XraySay;

/// The tunnel's MTU.
pub const MTU: u16 = 1400;
/// Open TCP flows through Xray, and open UDP flows.
pub const TCP_MAX: usize = 1024;
pub const UDP_MAX: usize = 256;
/// A UDP flow that is idle this long ends, and one to port 53 ends after the shorter wait.
const UDP_IDLE: Duration = Duration::from_secs(60);
const DNS_IDLE: Duration = Duration::from_secs(10);
/// A TCP flow with one side closed ends after this.
const HALF_CLOSED: Duration = Duration::from_secs(60);
/// How long a resolver is waited for over UDP before the same query goes over TCP, and over TCP before the other resolver.
const DNS_WAIT: Duration = Duration::from_secs(5);
/// "8 flows in a row failed over at least 30 s with none carried."
const SILENT_FLOWS: u32 = 8;
const SILENT_FOR: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_secs(1);
const BUFFER: usize = 16 << 10;
const DNS_ANSWER: usize = 4096;
const OVERHEAD_V6: usize = 48;
const QUEUE: usize = 1024;

/// The tunnel's own addresses: the device's and the gateway's, one of each family. The gateway answers a ping and is the resolver the platform pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addresses {pub device: [IpAddr; 2], pub gateway: [IpAddr; 2]}

// The first and last address of a network, as numbers of its family.
fn span(address: IpAddr, prefix: u8) -> (u128, u128) {
	let (value, bits) = match address {
		IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
		IpAddr::V6(ip) => (u128::from(ip), 128),
	};
	let host = if bits == 32 {u128::from(u32::MAX) >> u32::from(prefix)} else {u128::MAX >> u32::from(prefix)};
	(value & !host, value | host)
}

/// The tunnel's addresses: `198.18.0.2` for the device and `198.18.0.1` for the gateway (a /30), and `fdfe:7665:6c77::2` and `::1`. If a network of the device overlaps the range it takes `198.19.0.0/30` instead, and if that overlaps too there are none and the connect fails with the reason.
pub fn addresses(own: &[Network]) -> Option<Addresses> {
	[[198, 18, 0, 0], [198, 19, 0, 0]].iter().find_map(|base| {
		let [a, b, c, _] = *base;
		let v6 = IpAddr::from([0xfdfe_u16, 0x7665, 0x6c77, 0, 0, 0, 0, 1]);
		let (low, high) = span(IpAddr::from(*base), 30);
		let (low6, high6) = span(v6, 126);
		let free = own.iter().all(|network| {
			let (start, end) = span(network.address(), network.prefix());
			let (low, high) = if network.address().is_ipv4() {(low, high)} else {(low6, high6)};
			end < low || start > high
		});
		free.then(|| Addresses {device: [IpAddr::from([a, b, c, 2]), IpAddr::from([0xfdfe_u16, 0x7665, 0x6c77, 0, 0, 0, 0, 2])], gateway: [IpAddr::from([a, b, c, 1]), v6]})
	})
}

/// What the supervisor of Xray tells the carrier, and the carrier tells the app of it. The supervisor flips `set_up` after the first SOCKS handshake with the login has worked, and again whenever the child ends or its local check fails twice.
pub struct Live {
	up: watch::Sender<bool>,
	restarts: AtomicU64,
	last_restart: AtomicU64,
	say: Mutex<Option<XraySay>>,
}

impl Live {
	pub fn new() -> Arc<Self> {Arc::new(Self {up: watch::channel(false).0, restarts: AtomicU64::new(0), last_restart: AtomicU64::new(0), say: Mutex::new(None)})}
	/// Xray answers the SOCKS handshake, or does not. Going up clears the reason it was not.
	pub fn set_up(&self, up: bool) {
		if up {*self.say.lock().unwrap() = None}
		self.up.send_replace(up);
	}
	/// Xray was started again, at this Unix time.
	pub fn restarted(&self, at: u64) {
		self.restarts.fetch_add(1, Ordering::Relaxed);
		self.last_restart.store(at, Ordering::Relaxed);
	}
	/// Why Xray is not up, when it is something other than a restart: it could not start.
	pub fn explain(&self, say: XraySay) {*self.say.lock().unwrap() = Some(say)}
}

/// The run of failed flows that makes "the server is not answering": at least `SILENT_FLOWS` in a row over at least `SILENT_FOR`, with none carried since. The first carried flow clears it.
#[derive(Default)]
struct Streak {failed: u32, since: Option<Instant>}

impl Streak {
	fn failed(&mut self, now: Instant) {
		self.failed = self.failed.saturating_add(1);
		self.since.get_or_insert(now);
	}
	fn carried(&mut self) {*self = Self::default()}
	fn silent(&self, now: Instant) -> bool {self.failed >= SILENT_FLOWS && self.since.is_some_and(|since| now.duration_since(since) >= SILENT_FOR)}
}

#[derive(Default)]
struct Counts {packets_sent: AtomicU64, packets_received: AtomicU64, bytes_sent: AtomicU64, bytes_received: AtomicU64, flow_sent: AtomicU64, flow_received: AtomicU64, failed: AtomicU64, carried: AtomicU64, unsupported: AtomicU64, udp_dropped: AtomicU64}

fn add(counter: &AtomicU64, by: u64) {counter.fetch_add(by, Ordering::Relaxed);}

fn read(counter: &AtomicU64) -> u64 {counter.load(Ordering::Relaxed)}

struct Shared {
	socks: SocketAddr,
	login: String,
	addresses: Addresses,
	resolvers: [IpAddr; 2],
	live: Arc<Live>,
	relay_ok: RelayCheck,
	out: mpsc::Sender<Vec<u8>>,
	tcp: Arc<Semaphore>,
	udp: Arc<Semaphore>,
	counts: Counts,
	streak: Mutex<Streak>,
}

impl Shared {
	fn up(&self) -> bool {*self.live.up.borrow()}
	// A flow that failed counts toward "not answering" only while Xray is up: while it restarts the cause is known.
	fn failed(&self) {
		if !self.up() {return}
		add(&self.counts.failed, 1);
		self.streak.lock().unwrap().failed(Instant::now());
	}
	fn carried(&self) {
		add(&self.counts.carried, 1);
		self.streak.lock().unwrap().carried();
	}
	fn send(&self, packet: Option<Vec<u8>>) {
		let Some(packet) = packet else {return};
		add(&self.counts.packets_received, 1);
		add(&self.counts.bytes_received, packet.len() as u64);
		let _ = self.out.try_send(packet);
	}
	fn gateway(&self, address: IpAddr) -> bool {self.addresses.gateway.contains(&address)}
	fn view(&self, was_up: bool) -> XrayView {
		let (up, silent) = (self.up(), self.streak.lock().unwrap().silent(Instant::now()));
		let restarts = read(&self.live.restarts);
		let last = self.live.last_restart.load(Ordering::Relaxed);
		let say = if up {silent.then_some(XraySay::NotAnswering)} else {(*self.live.say.lock().unwrap()).or_else(|| (was_up || restarts > 0).then_some(XraySay::Restarting))};
		XrayView {counters: XrayCounters {open_tcp: (TCP_MAX - self.tcp.available_permits()) as u32, open_udp: (UDP_MAX - self.udp.available_permits()) as u32, failed_flows: read(&self.counts.failed), carried_flows: read(&self.counts.carried), bytes_sent: read(&self.counts.flow_sent), bytes_received: read(&self.counts.flow_received), unsupported_packets: read(&self.counts.unsupported), dropped_udp_flows: read(&self.counts.udp_dropped), restarts, last_restart: (last != 0).then_some(last)}, say}
	}
}

/// Packet-boundary preserving device for the stack: one read is one IP packet from the device and one write is one packet for it.
struct Device {rx: mpsc::Receiver<Vec<u8>>, shared: Arc<Shared>}

impl AsyncRead for Device {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		loop {
			match self.rx.poll_recv(cx) {
				Poll::Ready(Some(packet)) if packet.len() <= buf.remaining() => {
					buf.put_slice(&packet);
					return Poll::Ready(Ok(()));
				}
				Poll::Ready(Some(_)) => {}
				// A closed channel parks the stack instead of spinning on an empty read.
				_ => return Poll::Pending,
			}
		}
	}
}

impl AsyncWrite for Device {
	fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		self.shared.send(Some(buf.to_vec()));
		Poll::Ready(Ok(buf.len()))
	}
	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {Poll::Ready(Ok(()))}
	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {Poll::Ready(Ok(()))}
}

/// Whether a UDP relay Xray named is Xray's own. The platform reads who holds the socket.
pub type RelayCheck = Arc<dyn Fn(SocketAddr) -> bool + Send + Sync>;

/// What a carrier is made of.
pub struct Params {
	/// The connection's name, as the app shows it.
	pub name: String,
	/// Xray's inbound on the loopback address, and the login of this run.
	pub socks: SocketAddr,
	pub login: String,
	pub addresses: Addresses,
	/// The public resolvers a query to the gateway is forwarded to, in order.
	pub resolvers: [IpAddr; 2],
	pub live: Arc<Live>,
	/// Asked about the address of every UDP relay before a datagram goes to it. A relay it refuses fails the flow.
	pub relay_ok: RelayCheck,
}

/// One carrier. Dropping it stops it; `stop` waits for the flows to be closed first.
pub struct XrayTunnel {
	into: mpsc::Sender<Vec<u8>>,
	out: mpsc::Receiver<Vec<u8>>,
	status: watch::Receiver<Status>,
	stop: watch::Sender<bool>,
	task: JoinHandle<()>,
}

impl XrayTunnel {
	/// Starts the carrier. Called inside a tokio runtime. It carries nothing until `Live::set_up(true)`.
	pub fn start(params: Params) -> Self {
		let ((into, from), (out_tx, out), (stop, stopped)) = (mpsc::channel(QUEUE), mpsc::channel(QUEUE), watch::channel(false));
		let (status_tx, status) = watch::channel(Status {xray: Some(XrayView::default()), state: State::Connecting {attempt: None, wait: None}, ..Status::off(params.name.clone(), MTU)});
		let shared = Arc::new(Shared {socks: params.socks, login: params.login, addresses: params.addresses, resolvers: params.resolvers, live: params.live, relay_ok: params.relay_ok, out: out_tx, tcp: Arc::new(Semaphore::new(TCP_MAX)), udp: Arc::new(Semaphore::new(UDP_MAX)), counts: Counts::default(), streak: Mutex::new(Streak::default())});
		Self {into, out, status, stop, task: tokio::spawn(run(shared, params.name, from, status_tx, stopped))}
	}
	pub fn status(&self) -> Status {self.status.borrow().clone()}
	pub fn watch(&self) -> watch::Receiver<Status> {self.status.clone()}
	/// Hands one IP packet from the device to the carrier. False when it was dropped because the queue is full.
	pub fn send(&self, packet: Vec<u8>) -> bool {self.into.try_send(packet).is_ok()}
	/// The next IP packet for the device, or None when the carrier has stopped.
	pub async fn recv(&mut self) -> Option<Vec<u8>> {self.out.recv().await}
	/// Closes the flows, stops, and gives the last status.
	pub async fn stop(mut self) -> Status {
		let _ = self.stop.send(true);
		let _ = (&mut self.task).await;
		self.status.borrow().clone()
	}
}

impl Drop for XrayTunnel {
	fn drop(&mut self) {self.task.abort()}
}

async fn run(shared: Arc<Shared>, name: String, mut from: mpsc::Receiver<Vec<u8>>, status: watch::Sender<Status>, mut stopped: watch::Receiver<bool>) {
	let (to_stack, stack_rx) = mpsc::channel(QUEUE);
	let mut config = IpStackConfig::default();
	if config.mtu(MTU).is_err() {return}
	config.udp_timeout(UDP_IDLE);
	let mut stack = IpStack::new(config, Device {rx: stack_rx, shared: shared.clone()});
	let (mut front, mut flows, mut tick, mut up) = (Front::new(shared.addresses.gateway), JoinSet::new(), tokio::time::interval(TICK), shared.live.up.subscribe());
	let mut was_up = *up.borrow_and_update();
	let publish = |was_up: bool| {
		let view = shared.view(was_up);
		let counts = &shared.counts;
		let state = if shared.up() {State::Connected {exit: None}} else if was_up {State::Reconnecting {attempt: None, wait: None}} else {State::Connecting {attempt: None, wait: None}};
		let counters = Counters {packets_sent: read(&counts.packets_sent), packets_received: read(&counts.packets_received), bytes_sent: read(&counts.bytes_sent), bytes_received: read(&counts.bytes_received), ..Counters::default()};
		status.send_if_modified(|current| {
			let next = Status {state, xray: Some(view), counters, ..Status::off(name.clone(), MTU)};
			let changed = *current != next;
			*current = next;
			changed
		});
	};
	loop {
		tokio::select! {
			packet = from.recv() => {
				let Some(packet) = packet else {break};
				add(&shared.counts.packets_sent, 1);
				add(&shared.counts.bytes_sent, packet.len() as u64);
				match front.take(packet, std::time::Instant::now()) {
					Taken::Stack(packet) => {let _ = to_stack.try_send(packet);}
					Taken::Reply(packet) => shared.send(Some(packet)),
					Taken::Held => {}
					Taken::Unsupported => add(&shared.counts.unsupported, 1),
				}
			}
			accepted = stack.accept() => {
				let Ok(accepted) = accepted else {break};
				match accepted {
					IpStackStream::Tcp(stream) => match shared.tcp.clone().try_acquire_owned() {
						Ok(permit) => drop(flows.spawn(tcp_flow(shared.clone(), stream, permit))),
						Err(_) => {
							shared.failed();
							shared.send(refuse(&stream));
						}
					},
					IpStackStream::Udp(stream) => match shared.udp.clone().try_acquire_owned() {
						Ok(permit) => drop(flows.spawn(udp_flow(shared.clone(), stream, permit))),
						Err(_) => add(&shared.counts.udp_dropped, 1),
					},
					_ => add(&shared.counts.unsupported, 1),
				}
			}
			Some(_) = flows.join_next(), if !flows.is_empty() => {}
			changed = up.changed() => {
				if changed.is_err() {break}
				was_up |= *up.borrow_and_update();
				publish(was_up);
			}
			_ = tick.tick() => publish(was_up),
			_ = stopped.changed() => break,
		}
	}
	flows.shutdown().await;
	drop(stack);
	publish(was_up);
	status.send_modify(|current| current.state = State::Off);
}

// Waits until Xray is down. The guard `wait_for` gives is not `Send`, so it is dropped in here.
async fn down(up: &mut watch::Receiver<bool>) {let _ = up.wait_for(|up| !*up).await;}

// The reset that ends a TCP flow of the stack, built from where the stack has got to.
fn refuse(stream: &IpStackTcpStream) -> Option<Vec<u8>> {
	let (seq, ack) = stream.send_state().next();
	packets::reset(stream.local_addr(), stream.peer_addr(), seq, ack)
}

// Copies until the end of `from`, then closes `to` for writing. Every chunk is counted by `count`.
async fn pump(mut from: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin, count: impl Fn(u64)) -> io::Result<()> {
	let mut buffer = vec![0u8; BUFFER];
	loop {
		let read = from.read(&mut buffer).await?;
		if read == 0 {return to.shutdown().await}
		to.write_all(&buffer[..read]).await?;
		count(read as u64);
	}
}

// Where a TCP flow goes: the address the stack saw. A flow to the gateway is a DNS query over TCP and goes to the public resolvers, one after the other, and a flow to any other port of the gateway goes nowhere.
fn targets(shared: &Shared, peer: SocketAddr) -> Vec<SocketAddr> {
	if !shared.gateway(peer.ip()) {return vec![peer]}
	if peer.port() == 53 {shared.resolvers.iter().map(|ip| SocketAddr::new(*ip, 53)).collect()} else {Vec::new()}
}

async fn tcp_flow(shared: Arc<Shared>, stream: IpStackTcpStream, _permit: OwnedSemaphorePermit) {
	let (local, peer, state) = (stream.local_addr(), stream.peer_addr(), stream.send_state());
	let reset = |shared: &Shared| {
		let (seq, ack) = state.next();
		shared.send(packets::reset(local, peer, seq, ack));
	};
	let mut up = shared.live.up.subscribe();
	if !*up.borrow_and_update() {return reset(&shared)}
	let mut connected = None;
	let mut unreachable = false;
	for target in targets(&shared, peer) {
		match socks::connect(shared.socks, &shared.login, target).await {
			Ok(remote) => {
				connected = Some(remote);
				break;
			}
			Err(fail) => {
				if let Fail::Io(error) = &fail {tracing::debug!(kind = ?error.kind(), "a connection to the hop failed")}
				unreachable |= matches!(fail, Fail::Unreachable);
			}
		}
	}
	let Some(remote) = connected else {
		if shared.gateway(peer.ip()) && peer.port() != 53 {return reset(&shared)}
		shared.failed();
		if unreachable {
			// The stack has taken the device's SYN, which carried the sequence number before the one it now expects.
			shared.send(packets::unreachable(shared.addresses.gateway[usize::from(local.is_ipv6())], local, peer, Some(state.next().1.wrapping_sub(1))));
		}
		return reset(&shared);
	};
	let (mut device_read, mut device_write) = tokio::io::split(stream);
	let (mut server_read, mut server_write) = remote.into_split();
	let (sent, received) = (AtomicU64::new(0), AtomicU64::new(0));
	let counts = &shared.counts;
	let both = async {
		let toward = pump(&mut device_read, &mut server_write, |bytes| {
			sent.fetch_add(bytes, Ordering::Relaxed);
			add(&counts.flow_sent, bytes);
		});
		let back = pump(&mut server_read, &mut device_write, |bytes| {
			if received.fetch_add(bytes, Ordering::Relaxed) == 0 {shared.carried()}
			add(&counts.flow_received, bytes);
		});
		tokio::pin!(toward, back);
		// One side finishing cleanly leaves the other the half-closed wait to finish too. An error ends both.
		let first = tokio::select! {
			done = &mut toward => (done, true),
			done = &mut back => (done, false),
		};
		match first {
			(Err(error), _) => Err(error),
			(Ok(()), side) => match tokio::time::timeout(HALF_CLOSED, async {if side {(&mut back).await} else {(&mut toward).await}}).await {
				Ok(done) => done,
				Err(_) => Err(io::ErrorKind::TimedOut.into()),
			},
		}
	};
	let ended = tokio::select! {
		done = both => done,
		// Xray went down: every open flow is reset at once.
		_ = down(&mut up) => Err(io::ErrorKind::ConnectionReset.into()),
	};
	if received.load(Ordering::Relaxed) == 0 && sent.load(Ordering::Relaxed) > 0 {shared.failed()}
	if ended.is_err() {reset(&shared)}
}

// A query over TCP to one resolver: the two-byte length, then the message, as DNS over TCP frames it.
async fn dns_tcp(shared: &Shared, target: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
	let exchange = async {
		let mut remote = socks::connect(shared.socks, &shared.login, target).await.ok()?;
		remote.write_all(&(query.len() as u16).to_be_bytes()).await.ok()?;
		remote.write_all(query).await.ok()?;
		let mut length = [0u8; 2];
		remote.read_exact(&mut length).await.ok()?;
		let mut answer = vec![0u8; usize::from(u16::from_be_bytes(length))];
		remote.read_exact(&mut answer).await.ok()?;
		Some(answer)
	};
	tokio::time::timeout(DNS_WAIT * 2, exchange).await.ok().flatten()
}

// A query over UDP to one resolver, through an association of its own. None when there is no association or no answer in time.
async fn dns_udp(shared: &Shared, target: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
	let association = socks::associate(shared.socks, &shared.login, &*shared.relay_ok).await.ok()?;
	association.relay.send(&socks::wrap(target, query)).await.ok()?;
	let mut buffer = vec![0u8; DNS_ANSWER + 32];
	let answer = tokio::time::timeout(DNS_WAIT, association.relay.recv(&mut buffer)).await.ok()?.ok()?;
	socks::unwrap(&buffer[..answer]).map(|(_, data)| data.to_vec())
}

// An answer that does not fit the tunnel's packets is not clipped: the device gets the header alone with the truncated bit set and no records, which tells its resolver to ask again over TCP.
fn truncated(answer: &[u8]) -> Option<Vec<u8>> {
	let mut head = answer.get(..12)?.to_vec();
	head[2] |= 0x82;
	head[4..12].fill(0);
	Some(head)
}

// The resolvers in order, each over UDP and then over TCP when the association failed or nothing came back.
async fn lookup(shared: &Shared, query: &[u8]) -> Option<Vec<u8>> {
	for resolver in shared.resolvers {
		let target = SocketAddr::new(resolver, 53);
		let answer = match dns_udp(shared, target, query).await {
			Some(answer) => Some(answer),
			None => dns_tcp(shared, target, query).await,
		};
		if answer.is_some() {return answer}
	}
	None
}

async fn udp_flow(shared: Arc<Shared>, mut stream: IpStackUdpStream, _permit: OwnedSemaphorePermit) {
	let (local, peer) = (stream.local_addr(), stream.peer_addr());
	let mut up = shared.live.up.subscribe();
	if !*up.borrow_and_update() || (shared.gateway(peer.ip()) && peer.port() != 53) {return add(&shared.counts.udp_dropped, 1)}
	let (limit, mut datagram) = (usize::from(MTU) - OVERHEAD_V6, vec![0u8; 2048]);
	if shared.gateway(peer.ip()) {
		// Each query is its own exchange, and the flow ends when it has been quiet for the DNS wait.
		while let Ok(Ok(read)) = tokio::time::timeout(DNS_IDLE, stream.read(&mut datagram)).await {
			if read == 0 {break}
			add(&shared.counts.flow_sent, read as u64);
			let answer = tokio::select! {
				answer = lookup(&shared, &datagram[..read]) => answer,
				_ = down(&mut up) => return,
			};
			let Some(answer) = answer.and_then(|answer| if answer.len() <= limit {Some(answer)} else {truncated(&answer)}) else {
				shared.failed();
				continue;
			};
			add(&shared.counts.flow_received, answer.len() as u64);
			shared.carried();
			if stream.write_all(&answer).await.is_err() {break}
		}
		return;
	}
	let association = match socks::associate(shared.socks, &shared.login, &*shared.relay_ok).await {
		Ok(association) => association,
		Err(fail) => {
			shared.failed();
			if matches!(fail, Fail::Unreachable) {shared.send(packets::unreachable(shared.addresses.gateway[usize::from(local.is_ipv6())], local, peer, None))}
			return;
		}
	};
	let (mut control, relay, mut heard, mut buffer) = (association.control, association.relay, false, vec![0u8; 65535]);
	let (idle, mut closed) = (tokio::time::sleep(UDP_IDLE), [0u8; 1]);
	tokio::pin!(idle);
	loop {
		tokio::select! {
			read = stream.read(&mut datagram) => {
				let Ok(read) = read else {break};
				if read == 0 {break}
				if relay.send(&socks::wrap(peer, &datagram[..read])).await.is_err() {break}
				add(&shared.counts.flow_sent, read as u64);
				idle.as_mut().reset(Instant::now() + UDP_IDLE);
			}
			received = relay.recv(&mut buffer) => {
				let Ok(received) = received else {break};
				let Some((_, data)) = socks::unwrap(&buffer[..received]).filter(|(_, data)| data.len() <= limit) else {continue};
				if stream.write_all(data).await.is_err() {break}
				add(&shared.counts.flow_received, data.len() as u64);
				if !heard {
					heard = true;
					shared.carried();
				}
				idle.as_mut().reset(Instant::now() + UDP_IDLE);
			}
			// The association lasts as long as its control connection.
			_ = control.read(&mut closed) => break,
			_ = &mut idle => break,
			_ = down(&mut up) => break,
		}
	}
	if !heard {shared.failed()}
}

#[cfg(test)]
mod tests;
