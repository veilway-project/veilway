//! The userspace TCP/IP stack of a WireGuard outbound: one task that owns a smoltcp interface with the outbound's addresses, between the packets the tunnel decrypts and the packets it encrypts. A flow of the exit is a TCP socket of this stack whose bytes reach the flow's task through a `DuplexStream`, or a UDP socket on a port of its own, so the code that relays a flow is the code that relays a system socket.
//! The code of the TCP flows is the one of `veilway-engine`'s `local_stack`, copied and not shared: that one is the client's hot path, and a patch release does not touch it for a node feature.
//! The server on the other end sees every flow and may send anything. The stack never listens, and a packet it did not ask for is dropped before the interface sees it, so there is no RST, no ICMP error and no echo reply for a hostile peer to learn from: `admit` is the one gate, and the only packets that pass it belong to a flow this task has open, from the address and port that flow was made for.
use super::tunnel::Wire;
use crate::config::{random, MAX_TCP_IDLE_SECS};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as Clock;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
#[cfg(feature = "bench")]
use etherparse::PacketBuilder;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};

/// Packets that wait to be handed to the stack or to the tunnel, in each direction.
pub(super) const QUEUE: usize = 1024;
/// An opening that the far side does not answer within this is given up.
const CONNECT: Duration = Duration::from_secs(10);
/// A connection with no byte either way for this long is closed, which only matters when the flow's own idle time is longer.
const IDLE: Duration = Duration::from_secs(MAX_TCP_IDLE_SECS as u64 + 60);
/// How often the task looks at its deadlines when nothing else wakes it.
const TICK: Duration = Duration::from_secs(5);
/// What a connection's socket buffers coming in and going out, and its pipe to the flow's task. A receive buffer over 64 KiB turns on window scaling.
const RECEIVE: usize = 131_072;
const SEND: usize = 65_536;
const PIPE: usize = 32768;
/// A socket that hears nothing for `DEAD` is aborted, and a quiet but live one is probed every `PROBE`.
const DEAD: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(60);
const PROBE: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(20);
/// The most that is moved at once between a socket and its pipe.
const CHUNK: usize = 16384;
/// The datagrams a UDP flow holds on each side, and the bytes of each.
const DATAGRAMS: usize = 16;
const DATAGRAM: usize = 2048;
/// The datagrams that wait between a UDP flow's task and the stack, in each direction.
const UDP_QUEUE: usize = 64;
/// The flows that only the node's own DNS lookups may use, or a quarter of `max_flows` when that is less, so users filling the stack never leave the resolver without a way out.
const RESERVED: usize = 16;
/// The most of an outbound's flows that one user may hold is a quarter of `max_flows`, and never fewer than this.
const SHARE_LEAST: usize = 16;
/// Header bytes of a UDP datagram inside an IP packet.
const UDP_HEADERS: usize = 28;
const UDP_HEADERS_V6: usize = 48;

/// Why a connection or a flow was not made. The caller says the reason in its log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fail {
	/// The task is gone, which is when the outbound is.
	Down,
	/// `max_flows` flows are open, or no port is free.
	Busy,
	Timeout,
	/// The far side answered with a reset.
	Refused,
	/// The outbound has no address of the destination's family.
	Unsupported,
}

/// What the stack counts, for `GET /v1/exits` and for the tests.
#[derive(Default)]
pub(super) struct Counters {
	/// The flows open now, TCP and UDP.
	pub flows: AtomicUsize,
	/// Packets from the server that no flow of the stack asked for, and were dropped without an answer.
	pub unsolicited: AtomicU64,
	/// Packets dropped because a queue was full, in either direction.
	pub full: AtomicU64,
	/// Flows refused because `max_flows` were open.
	pub refused: AtomicU64,
}

/// The way to the stack for as many flows as want one.
#[derive(Clone)]
pub(super) struct Stack {commands: mpsc::Sender<Command>, pub counters: Arc<Counters>}

/// A UDP flow: what the flow's task sends goes out from a port of the stack to the one destination, and what that destination sends back comes out of `recv`.
pub struct Udp {to: mpsc::Sender<Vec<u8>>, from: mpsc::Receiver<Vec<u8>>, wake: Arc<Wake>, most: usize}

impl Udp {
	/// Whether the datagram was taken. False when the stack is gone, when it is full, which drops it like a full queue anywhere, and when it is too large for the MTU, which the stack would never send whole.
	pub fn send(&self, datagram: &[u8]) -> bool {
		let taken = datagram.len() <= self.most && self.to.try_send(datagram.to_vec()).is_ok();
		self.wake.0.notify_one();
		taken
	}

	/// None when the stack ended the flow or is gone.
	pub async fn recv(&mut self) -> Option<Vec<u8>> {self.from.recv().await}
}

/// The stack finds out that a flow was dropped when it is woken, which is now.
impl Drop for Udp {
	fn drop(&mut self) {self.wake.0.notify_one()}
}

/// Whose a flow is, which decides how many of them it may hold: a user (index in the plan's users) has its share, the node's own sockets (the decoy of a `tls` transport) count as one holder, and a DNS lookup of the node's resolver may also use the reserved places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {User(usize), Node, Dns}

enum Command {
	Connect(SocketAddr, Who, oneshot::Sender<Result<DuplexStream, Fail>>),
	Udp(SocketAddr, Who, oneshot::Sender<Result<Udp, Fail>>),
}

impl Stack {
	/// A stack that is gone: everything asked of it fails as `Fail::Down`. What an outbound holds before its first stack runs.
	pub(super) fn closed() -> Stack {Stack {commands: mpsc::channel(1).0, counters: Arc::default()}}

	/// A TCP connection inside the tunnel. The stream is the far side's, already open.
	pub(super) async fn connect(&self, to: SocketAddr, who: Who) -> Result<DuplexStream, Fail> {
		let (reply, answer) = oneshot::channel();
		self.commands.send(Command::Connect(to, who, reply)).await.map_err(|_| Fail::Down)?;
		answer.await.map_err(|_| Fail::Down)?
	}

	/// A UDP flow to `to` from a port of the stack.
	pub(super) async fn udp(&self, to: SocketAddr, who: Who) -> Result<Udp, Fail> {
		let (reply, answer) = oneshot::channel();
		self.commands.send(Command::Udp(to, who, reply)).await.map_err(|_| Fail::Down)?;
		answer.await.map_err(|_| Fail::Down)?
	}
}

/// What `admit` knows of a packet it lets in: the protocol, where it came from and the port it is for.
pub(super) type Tuple = (u8, SocketAddr, u16);

/// The one gate of the stack: the tuple of a packet that is a whole TCP segment or UDP datagram for one of `own`, and none for anything else. Fragments, extension headers, ICMP, other protocols, a destination that is not the outbound's own address and a packet that does not parse are all `None`. Reads only what it checks and never panics on any bytes.
pub(super) fn admit(raw: &[u8], own: &[IpAddr]) -> Option<Tuple> {
	let (protocol, source, destination, payload): (IpProtocol, IpAddr, IpAddr, &[u8]) = match raw.first()? >> 4 {
		4 => {
			let packet = Ipv4Packet::new_checked(raw).ok()?;
			if packet.more_frags() || packet.frag_offset() != 0 || packet.header_len() < 20 {return None}
			(packet.next_header(), packet.src_addr().into(), packet.dst_addr().into(), packet.payload())
		}
		6 => {
			let packet = Ipv6Packet::new_checked(raw).ok()?;
			(packet.next_header(), packet.src_addr().into(), packet.dst_addr().into(), packet.payload())
		}
		_ => return None,
	};
	if !own.contains(&destination) {return None}
	let (source_port, destination_port) = match protocol {
		IpProtocol::Tcp => {
			let segment = TcpPacket::new_checked(payload).ok()?;
			(segment.src_port(), segment.dst_port())
		}
		IpProtocol::Udp => {
			let datagram = UdpPacket::new_checked(payload).ok()?;
			(datagram.src_port(), datagram.dst_port())
		}
		_ => return None,
	};
	Some((u8::from(protocol), SocketAddr::new(source, source_port), destination_port))
}

/// Wakes the task when a pipe it polled is ready, or when a UDP flow has handed it a datagram.
struct Wake(Notify);

impl std::task::Wake for Wake {
	fn wake(self: Arc<Self>) {self.0.notify_one()}

	fn wake_by_ref(self: &Arc<Self>) {self.0.notify_one()}
}

/// A port from 33000 up, which is above where the node's own sockets are drawn and below where the systems draw theirs.
fn draw_port() -> u16 {
	let mut bytes = [0u8; 2];
	let _ = random(&mut bytes);
	33000 + u16::from_le_bytes(bytes) % 27000
}

struct Flow {who: Who, handle: SocketHandle, port: u16, remote: SocketAddr, app: DuplexStream, peer: Option<DuplexStream>, reply: Option<oneshot::Sender<Result<DuplexStream, Fail>>>, started: Instant, idle_at: Instant, out: Vec<u8>, written: usize, client_eof: bool, far_done: bool, shut: bool, done: bool}

struct UdpFlow {who: Who, handle: SocketHandle, port: u16, remote: SocketAddr, from: mpsc::Receiver<Vec<u8>>, to: mpsc::Sender<Vec<u8>>, done: bool}

/// The smoltcp interface for the outbound's addresses. Every address is on the link: there are no neighbours to ask and no route to look up.
fn interface(device: &mut Wire, mtu: usize, own: &[IpAddr], now: Clock) -> Interface {
	device.mtu = mtu;
	let mut seed = [0u8; 8];
	let _ = random(&mut seed);
	let mut config = Config::new(HardwareAddress::Ip);
	config.random_seed = u64::from_le_bytes(seed);
	let mut iface = Interface::new(config, device, now);
	iface.update_ip_addrs(|addresses| {for address in own {let _ = addresses.push(IpCidr::new((*address).into(), 0));}});
	iface
}

/// Starts the stack with `own` as its addresses, at most `max_flows` flows at once, packets of at most `mtu` bytes, the packets the tunnel decrypted from `from_wg` and the ones to encrypt into `to_wg`. The task ends when it is aborted: the owner holds the handle.
pub(super) fn start(own: Vec<IpAddr>, mtu: usize, max_flows: usize, from_wg: mpsc::Receiver<Vec<u8>>, to_wg: mpsc::Sender<Vec<u8>>) -> (Stack, JoinHandle<()>) {
	let (commands, input) = mpsc::channel(64);
	let (counters, own): (Arc<Counters>, Arc<[IpAddr]>) = (Arc::default(), own.into());
	(Stack {commands, counters: counters.clone()}, tokio::spawn(run(own, mtu, max_flows, input, from_wg, to_wg, counters)))
}

async fn run(own: Arc<[IpAddr]>, mtu: usize, max_flows: usize, mut commands: mpsc::Receiver<Command>, mut from_wg: mpsc::Receiver<Vec<u8>>, to_wg: mpsc::Sender<Vec<u8>>, counters: Arc<Counters>) {
	let (started, wake) = (Instant::now(), Arc::new(Wake(Notify::new())));
	let waker = Waker::from(wake.clone());
	let clock = || Clock::from_micros(started.elapsed().as_micros() as i64);
	let mut device = Wire {rx: VecDeque::new(), tx: Vec::new(), mtu: 0};
	let mut iface = interface(&mut device, mtu, &own, clock());
	let mut sockets = SocketSet::new(Vec::new());
	let (mut flows, mut datagrams, mut buf) = (Vec::<Flow>::new(), Vec::<UdpFlow>::new(), vec![0u8; CHUNK]);
	// The flows by what a packet of theirs is known by, and the ports in use: a UDP socket takes whatever comes to its port, so a port is never given to two flows.
	let (mut known, mut ports) = (HashSet::<Tuple>::new(), HashSet::<u16>::new());
	loop {
		let now = Instant::now();
		iface.poll(clock(), &mut device, &mut sockets);
		for flow in datagrams.iter_mut() {
			let socket = sockets.get_mut::<udp::Socket>(flow.handle);
			while socket.can_send() {
				match flow.from.try_recv() {
					Ok(datagram) => {let _ = socket.send_slice(&datagram, IpEndpoint::from(flow.remote));}
					Err(mpsc::error::TryRecvError::Disconnected) => {
						flow.done = true;
						break;
					}
					Err(_) => break,
				}
			}
			if flow.to.is_closed() {flow.done = true}
			while let Ok((data, meta)) = socket.recv() {
				if meta.endpoint != IpEndpoint::from(flow.remote) {continue}
				if flow.to.try_send(data.to_vec()).is_err() {counters.full.fetch_add(1, Ordering::Relaxed);}
			}
		}
		// The context is not Send, so it lives only as long as the pass over the connections.
		let progress = {
			let (mut cx, mut progress) = (Context::from_waker(&waker), false);
			for flow in flows.iter_mut() {
				let socket = sockets.get_mut::<tcp::Socket>(flow.handle);
				if flow.reply.is_some() {
					if socket.may_send() {
						if let (Some(reply), Some(peer)) = (flow.reply.take(), flow.peer.take()) {let _ = reply.send(Ok(peer));}
						flow.idle_at = now + IDLE;
					} else if socket.state() == tcp::State::Closed || now >= flow.started + CONNECT || flow.reply.as_ref().is_some_and(|reply| reply.is_closed()) {
						let fail = if now >= flow.started + CONNECT {Fail::Timeout} else {Fail::Refused};
						socket.abort();
						if let Some(reply) = flow.reply.take() {let _ = reply.send(Err(fail));}
						flow.done = true;
					}
					if flow.reply.is_some() || flow.done {continue}
				}
				if now >= flow.idle_at {
					socket.abort();
					flow.done = true;
					continue;
				}
				if !flow.out.is_empty() {
					match Pin::new(&mut flow.app).poll_write(&mut cx, &flow.out[flow.written..]) {
						Poll::Ready(Ok(n)) if n > 0 => {
							progress = true;
							flow.idle_at = now + IDLE;
							flow.written += n;
							if flow.written == flow.out.len() {
								flow.out.clear();
								flow.written = 0;
							}
						}
						Poll::Ready(_) => {
							socket.abort();
							flow.done = true;
							continue;
						}
						Poll::Pending => {}
					}
				}
				// An empty write fails once the flow's end was dropped. Unless the far side's close was already delivered, that is an abort and the far side is told with a reset.
				if flow.out.is_empty() && !flow.shut && matches!(Pin::new(&mut flow.app).poll_write(&mut cx, &[]), Poll::Ready(Err(_))) {
					socket.abort();
					flow.done = true;
					continue;
				}
				if flow.out.is_empty() && !flow.far_done {
					let taken = socket.recv(|data| {
						let taken = data.len().min(CHUNK);
						flow.out.extend_from_slice(&data[..taken]);
						(taken, ())
					});
					progress |= !flow.out.is_empty();
					if matches!(taken, Err(tcp::RecvError::Finished)) {flow.far_done = true}
				}
				if flow.far_done && flow.out.is_empty() && !flow.shut {flow.shut = Pin::new(&mut flow.app).poll_shutdown(&mut cx).is_ready()}
				let room = if !flow.client_eof && socket.may_send() {(socket.send_capacity() - socket.send_queue()).min(CHUNK)} else {0};
				if room > 0 {
					let mut read = ReadBuf::new(&mut buf[..room]);
					match Pin::new(&mut flow.app).poll_read(&mut cx, &mut read) {
						Poll::Ready(Ok(())) if read.filled().is_empty() => {
							flow.client_eof = true;
							socket.close();
						}
						Poll::Ready(Ok(())) => {
							progress = true;
							flow.idle_at = now + IDLE;
							let _ = socket.send_slice(read.filled());
						}
						Poll::Ready(Err(_)) => {
							socket.abort();
							flow.done = true;
							continue;
						}
						Poll::Pending => {}
					}
				}
				if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) && socket.recv_queue() == 0 && flow.out.is_empty() && (flow.shut || !flow.far_done) {flow.done = true}
			}
			progress
		};
		iface.poll(clock(), &mut device, &mut sockets);
		for raw in device.tx.drain(..) {
			if to_wg.try_send(raw).is_err() {counters.full.fetch_add(1, Ordering::Relaxed);}
		}
		flows.retain(|flow| {
			if flow.done {
				known.remove(&(6, flow.remote, flow.port));
				ports.remove(&flow.port);
				sockets.remove(flow.handle);
			}
			!flow.done
		});
		datagrams.retain(|flow| {
			if flow.done {
				known.remove(&(17, flow.remote, flow.port));
				ports.remove(&flow.port);
				sockets.remove(flow.handle);
			}
			!flow.done
		});
		counters.flows.store(flows.len() + datagrams.len(), Ordering::Relaxed);
		if progress || !device.rx.is_empty() {wake.0.notify_one()}
		let wake_at = [iface.poll_delay(clock(), &sockets).map(|delay| now + Duration::from_micros(delay.total_micros())), Some(now + TICK)].into_iter().flatten().min().unwrap_or(now);
		tokio::select! {
			received = from_wg.recv(), if device.rx.len() < QUEUE => {
				let Some(raw) = received else {break};
				let mut more = Some(raw);
				while let Some(raw) = more.take() {
					match admit(&raw, &own) {
						Some(tuple) if known.contains(&tuple) => device.rx.push_back(raw),
						_ => {counters.unsolicited.fetch_add(1, Ordering::Relaxed);}
					}
					if device.rx.len() < QUEUE {more = from_wg.try_recv().ok()}
				}
			}
			Some(command) = commands.recv() => {
				let (to, who) = match &command {Command::Connect(to, who, _) | Command::Udp(to, who, _) => (*to, *who)};
				let (open, mine) = (flows.len() + datagrams.len(), flows.iter().map(|flow| flow.who).chain(datagrams.iter().map(|flow| flow.who)).filter(|held| *held == who).count());
				// Everyone but the resolver stops short of the reserved places, and a user stops at its share.
				let taken = open >= max_flows || (who != Who::Dns && (open >= max_flows - (max_flows / 4).min(RESERVED) || mine >= SHARE_LEAST.max(max_flows / 4)));
				let port = (0..16).map(|_| draw_port()).find(|port| !ports.contains(port));
				let local = own.iter().find(|address| address.is_ipv4() == to.is_ipv4()).copied();
				let refuse = |command: Command, fail: Fail| match command {
					Command::Connect(_, _, reply) => drop(reply.send(Err(fail))),
					Command::Udp(_, _, reply) => drop(reply.send(Err(fail))),
				};
				let (Some(local), Some(port)) = (local, port) else {
					refuse(command, if local.is_none() {Fail::Unsupported} else {Fail::Busy});
					continue;
				};
				if taken {
					counters.refused.fetch_add(1, Ordering::Relaxed);
					refuse(command, Fail::Busy);
					continue;
				}
				match command {
					Command::Connect(to, who, reply) => {
						let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; RECEIVE]), tcp::SocketBuffer::new(vec![0u8; SEND]));
						socket.set_nagle_enabled(false);
						socket.set_timeout(Some(DEAD));
						socket.set_keep_alive(Some(PROBE));
						if socket.connect(iface.context(), to, (local, port)).is_err() {
							let _ = reply.send(Err(Fail::Busy));
							continue;
						}
						let (app, peer) = duplex(PIPE);
						ports.insert(port);
						known.insert((6, to, port));
						flows.push(Flow {who, handle: sockets.add(socket), port, remote: to, app, peer: Some(peer), reply: Some(reply), started: Instant::now(), idle_at: Instant::now() + IDLE, out: Vec::new(), written: 0, client_eof: false, far_done: false, shut: false, done: false});
					}
					Command::Udp(to, who, reply) => {
						let mut socket = udp::Socket::new(udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; DATAGRAMS], vec![0u8; DATAGRAMS * DATAGRAM]), udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; DATAGRAMS], vec![0u8; DATAGRAMS * DATAGRAM]));
						if socket.bind(IpListenEndpoint {addr: Some(IpAddress::from(local)), port}).is_err() {
							let _ = reply.send(Err(Fail::Busy));
							continue;
						}
						let ((out_to, out_from), (in_to, in_from)) = (mpsc::channel(UDP_QUEUE), mpsc::channel(UDP_QUEUE));
						ports.insert(port);
						known.insert((17, to, port));
						datagrams.push(UdpFlow {who, handle: sockets.add(socket), port, remote: to, from: out_from, to: in_to, done: false});
						let _ = reply.send(Ok(Udp {to: out_to, from: in_from, wake: wake.clone(), most: mtu.saturating_sub(if to.is_ipv4() {UDP_HEADERS} else {UDP_HEADERS_V6})}));
					}
				}
			}
			_ = wake.0.notified() => {}
			_ = sleep_until(wake_at) => {}
		}
	}
	for flow in &mut flows {
		sockets.get_mut::<tcp::Socket>(flow.handle).abort();
		if let Some(reply) = flow.reply.take() {let _ = reply.send(Err(Fail::Down));}
	}
}

/// What the fuzz target `wg_stack` drives: the stack on packets in memory, as the tunnel would hand them after decrypting. The stack has one TCP flow open and one UDP flow, to one destination, and `input` is cut into packets by a length byte before each. A packet whose first byte is `0xff` or `0xfe` is not taken as it is: the rest of it picks the flags, the numbers and the payload of a TCP segment or a UDP datagram that the destination would send on the open flow, so that the state machines see segments that belong to a connection.
/// Whatever comes, nothing may panic, the stack may hold at most `max_flows` flows, and every packet it makes must be a whole TCP or UDP packet from one of its own addresses to the destination, no larger than the MTU, and never an answer to anything it did not ask for: no ICMP, no packet to another address.
#[cfg(feature = "bench")]
pub async fn drive(input: &[u8]) -> Result<(), String> {
	let (own, remote) = ([IpAddr::from([10, 64, 0, 2]), IpAddr::from([0xfd00u16, 0x64, 0, 0, 0, 0, 0, 2])], SocketAddr::from(([198, 51, 100, 7], 443)));
	let ((to_stack, from_wg), (to_wg, mut from_stack)) = (mpsc::channel(QUEUE), mpsc::channel(QUEUE));
	let (stack, task) = start(own.to_vec(), 1420, 4, from_wg, to_wg);
	let connecting = tokio::spawn({let stack = stack.clone(); async move {stack.connect(remote, Who::Node).await}});
	let flow = stack.udp(remote, Who::Node).await.map_err(|fail| format!("{fail:?}"))?;
	flow.send(b"fuzz");
	let (mut tcp, mut udp) = (None::<(u16, u32)>, None::<u16>);
	let mut input = input;
	let drain = async |from_stack: &mut mpsc::Receiver<Vec<u8>>, tcp: &mut Option<(u16, u32)>, udp: &mut Option<u16>| -> Result<(), String> {
		tokio::time::sleep(Duration::from_millis(5)).await;
		while let Ok(raw) = from_stack.try_recv() {
			let packet = Ipv4Packet::new_checked(&raw[..]).map_err(|_| "a packet of the stack is no IPv4 packet".to_string())?;
			if packet.src_addr() != Ipv4Address::new(10, 64, 0, 2) || packet.dst_addr() != Ipv4Address::new(198, 51, 100, 7) || raw.len() > 1420 || packet.more_frags() {return Err(format!("a packet of the stack is not from an own address to the destination, whole and within the MTU: {raw:?}"))}
			match packet.next_header() {
				IpProtocol::Tcp => {
					let segment = TcpPacket::new_checked(packet.payload()).map_err(|_| "a segment of the stack does not read".to_string())?;
					if segment.syn() && !segment.ack() {*tcp = Some((segment.src_port(), segment.seq_number().0 as u32))}
				}
				IpProtocol::Udp => *udp = Some(UdpPacket::new_checked(packet.payload()).map_err(|_| "a datagram of the stack does not read".to_string())?.src_port()),
				other => return Err(format!("the stack made a packet of protocol {other}")),
			}
		}
		Ok(())
	};
	drain(&mut from_stack, &mut tcp, &mut udp).await?;
	if let Some((port, seq)) = tcp {
		let mut synack = Vec::new();
		PacketBuilder::ipv4([198, 51, 100, 7], [10, 64, 0, 2], 64).tcp(443, port, 7000, 65535).syn().ack(seq.wrapping_add(1)).write(&mut synack, &[]).map_err(|e| e.to_string())?;
		let _ = to_stack.send(synack).await;
	}
	while let Some((length, rest)) = input.split_first() {
		let (record, rest) = rest.split_at(usize::from(*length).min(rest.len()));
		input = rest;
		let mut raw = record.to_vec();
		if let (Some(&kind @ (0xff | 0xfe)), [a, b, c, d, e, f, payload @ ..]) = (record.first(), record.get(1..).unwrap_or(&[])) {
			let (number, other) = (u32::from_be_bytes([*a, *b, *c, *d]), u32::from_be_bytes([*c, *d, *e, *f]));
			raw = Vec::new();
			if kind == 0xff {
				let Some((port, seq)) = tcp else {continue};
				let mut builder = PacketBuilder::ipv4([198, 51, 100, 7], [10, 64, 0, 2], 64).tcp(443, port, 7001u32.wrapping_add(number), (other >> 16) as u16);
				if e & 1 != 0 {builder = builder.fin()}
				if e & 2 != 0 {builder = builder.syn()}
				if e & 4 != 0 {builder = builder.rst()}
				if e & 8 != 0 {builder = builder.psh()}
				if e & 16 != 0 {builder = builder.ack(seq.wrapping_add(1).wrapping_add(other))}
				builder.write(&mut raw, payload).map_err(|e| e.to_string())?;
			} else {
				let Some(port) = udp else {continue};
				PacketBuilder::ipv4([198, 51, 100, 7], [10, 64, 0, 2], 64).udp(443, port).write(&mut raw, payload).map_err(|e| e.to_string())?;
			}
		}
		let _ = to_stack.send(raw).await;
		drain(&mut from_stack, &mut tcp, &mut udp).await?;
		if stack.counters.flows.load(Ordering::Relaxed) > 4 {return Err("more flows than max_flows".to_string())}
	}
	connecting.abort();
	drop(flow);
	task.abort();
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::time::timeout;

	const OWN: [u8; 4] = [10, 64, 0, 2];
	const REMOTE: [u8; 4] = [198, 51, 100, 7];

	macro_rules! build {($builder:expr, $payload:expr) => {{
		let mut packet = Vec::new();
		$builder.write(&mut packet, $payload).unwrap();
		packet
	}}}

	fn own() -> IpAddr {OWN.into()}

	fn remote(port: u16) -> SocketAddr {SocketAddr::new(REMOTE.into(), port)}

	/// The stack with the channels a test plays the tunnel on: what is sent into `to_stack` is what the tunnel decrypted, and `from_stack` holds what the stack wants encrypted.
	fn stack(addresses: Vec<IpAddr>, max_flows: usize) -> (Stack, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, JoinHandle<()>) {
		let ((to_stack, from_wg), (to_wg, from_stack)) = (mpsc::channel(QUEUE), mpsc::channel(QUEUE));
		let (stack, task) = start(addresses, 1420, max_flows, from_wg, to_wg);
		(stack, to_stack, from_stack, task)
	}

	/// The next packet of the stack that satisfies `wanted`, within a second.
	async fn next<T>(from_stack: &mut mpsc::Receiver<Vec<u8>>, wanted: impl Fn(&SlicedPacket) -> Option<T>) -> T {
		timeout(Duration::from_secs(1), async {
			loop {
				let raw = from_stack.recv().await.expect("the stack ended");
				if let Some(found) = SlicedPacket::from_ip(&raw).ok().and_then(|packet| wanted(&packet)) {return found}
			}
		}).await.expect("the stack sent no such packet")
	}

	/// The source port and the sequence number of the stack's opening segment.
	async fn syn(from_stack: &mut mpsc::Receiver<Vec<u8>>) -> (u16, u32) {
		next(from_stack, |packet| match &packet.transport {Some(TransportSlice::Tcp(tcp)) if tcp.syn() => Some((tcp.source_port(), tcp.sequence_number())), _ => None}).await
	}

	/// Lets the stack's task run: it answers a packet in a pass or two.
	async fn settle() {tokio::time::sleep(Duration::from_millis(200)).await}

	#[test]
	fn admit_lets_in_a_whole_segment_or_datagram_for_an_own_address_and_nothing_else() {
		let tcp = build!(PacketBuilder::ipv4(REMOTE, OWN, 64).tcp(443, 33000, 1, 1000).syn(), &[]);
		assert_eq!(admit(&tcp, &[own()]), Some((6, remote(443), 33000)));
		let udp = build!(PacketBuilder::ipv4(REMOTE, OWN, 64).udp(53, 40000), b"answer");
		assert_eq!(admit(&udp, &[own()]), Some((17, remote(53), 40000)));
		assert_eq!(admit(&udp, &["10.64.0.3".parse().unwrap()]), None, "a packet for another address");
		assert_eq!(admit(&udp, &[]), None);
		let echo = build!(PacketBuilder::ipv4(REMOTE, OWN, 64).icmpv4_echo_request(1, 1), b"ping");
		assert_eq!(admit(&echo, &[own()]), None, "ICMP is never let in: no echo reply, no error to learn from");
		let mut fragment = udp.clone();
		fragment[6] |= 0x20;
		assert_eq!(admit(&fragment, &[own()]), None, "a first fragment");
		let mut later = udp.clone();
		later[7] = 1;
		assert_eq!(admit(&later, &[own()]), None, "a later fragment");
		let mut other = udp.clone();
		other[9] = 47;
		assert_eq!(admit(&other, &[own()]), None, "another protocol");
		let v6 = [0xfd, 0, 0, 0x64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
		let both = [own(), IpAddr::from(v6)];
		let tcp6 = build!(PacketBuilder::ipv6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], v6, 64).tcp(443, 33001, 1, 1000).syn(), &[]);
		assert_eq!(admit(&tcp6, &both), Some((6, SocketAddr::new("2001:db8::1".parse().unwrap(), 443), 33001)));
		assert_eq!(admit(&tcp6, &[own()]), None, "an IPv6 packet for an outbound with no IPv6 address");
		let mut extension = tcp6.clone();
		extension[6] = 0;
		assert_eq!(admit(&extension, &both), None, "an extension header");
		for cut in [0, 1, 19, 20, 27, 28, tcp.len() - 1] {assert_eq!(admit(&tcp[..cut], &[own()]), None, "{cut} bytes");}
		assert_eq!(admit(&[0x45], &[own()]), None);
		assert_eq!(admit(&[0x60; 30], &both), None);
		assert_eq!(admit(&[0x00; 40], &both), None);
		// Bytes of a real packet changed and cut at random: nothing panics.
		let mut seed = 0x9e3779b97f4a7c15u64;
		for _ in 0..20000 {
			let mut raw = if seed & 1 == 0 {tcp.clone()} else {udp.clone()};
			for _ in 0..3 {
				seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
				let at = (seed >> 33) as usize % raw.len();
				raw[at] = (seed >> 17) as u8;
			}
			raw.truncate((seed >> 40) as usize % (raw.len() + 1));
			let _ = admit(&raw, &both);
		}
	}

	#[tokio::test]
	async fn a_connection_opens_carries_bytes_and_is_heard_from_its_own_peer_only() {
		let (stack, to_stack, mut from_stack, task) = stack(vec![own()], 16);
		let connecting = tokio::spawn({let stack = stack.clone(); async move {stack.connect(remote(443), Who::Node).await}});
		let (port, seq) = syn(&mut from_stack).await;
		// The right answer from the wrong port, and a segment of no connection at all: dropped, counted, never answered.
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).tcp(444, port, 5000, 65535).syn().ack(seq + 1), &[])).await.unwrap();
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).tcp(443, port + 1, 5000, 65535).syn().ack(seq + 1), &[])).await.unwrap();
		settle().await;
		assert_eq!(stack.counters.unsolicited.load(Ordering::Relaxed), 2);
		assert!(from_stack.try_recv().is_err(), "the stack answered a packet it never asked for");
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).tcp(443, port, 5000, 65535).syn().ack(seq + 1), &[])).await.unwrap();
		let mut stream = timeout(Duration::from_secs(1), connecting).await.expect("the connection did not open").unwrap().expect("the connection was refused");
		assert_eq!(stack.counters.flows.load(Ordering::Relaxed), 1);
		stream.write_all(b"hello").await.unwrap();
		let sent_at = next(&mut from_stack, |packet| match &packet.transport {Some(TransportSlice::Tcp(tcp)) if tcp.payload() == b"hello" => Some(tcp.sequence_number()), _ => None}).await;
		assert_eq!(sent_at, seq + 1);
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).tcp(443, port, 5001, 65535).ack(seq + 6), b"world")).await.unwrap();
		let mut back = [0u8; 5];
		timeout(Duration::from_secs(1), stream.read_exact(&mut back)).await.expect("nothing came back").unwrap();
		assert_eq!(&back, b"world");
		task.abort();
	}

	#[tokio::test]
	async fn a_reset_from_the_far_side_refuses_the_connection_and_frees_its_place() {
		let (stack, to_stack, mut from_stack, task) = stack(vec![own()], 16);
		let connecting = tokio::spawn({let stack = stack.clone(); async move {stack.connect(remote(81), Who::Node).await}});
		let (port, seq) = syn(&mut from_stack).await;
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).tcp(81, port, 0, 0).rst().ack(seq + 1), &[])).await.unwrap();
		let refused = timeout(Duration::from_secs(1), connecting).await.expect("the reset was not heard").unwrap();
		assert_eq!(refused.err(), Some(Fail::Refused));
		settle().await;
		assert_eq!(stack.counters.flows.load(Ordering::Relaxed), 0, "a refused connection holds a place");
		task.abort();
	}

	#[tokio::test]
	async fn flows_past_max_flows_and_of_a_family_without_an_address_are_refused() {
		let (stack, _to_stack, mut from_stack, task) = stack(vec![own()], 2);
		let held: Vec<_> = (0..2).map(|at| {let stack = stack.clone(); tokio::spawn(async move {stack.connect(remote(1000 + at), Who::Node).await})}).collect();
		syn(&mut from_stack).await;
		syn(&mut from_stack).await;
		assert_eq!(stack.connect(remote(2000), Who::Node).await.err(), Some(Fail::Busy));
		assert_eq!(stack.udp(remote(2000), Who::Node).await.err(), Some(Fail::Busy), "a UDP flow counts as one");
		assert_eq!(stack.counters.refused.load(Ordering::Relaxed), 2);
		assert_eq!(stack.connect(SocketAddr::new("2001:db8::1".parse().unwrap(), 80), Who::Node).await.err(), Some(Fail::Unsupported));
		assert_eq!(stack.udp(SocketAddr::new("2001:db8::1".parse().unwrap(), 80), Who::Node).await.err(), Some(Fail::Unsupported));
		assert_eq!(stack.counters.refused.load(Ordering::Relaxed), 2, "a family it has no address of is no flow refused for max_flows");
		for flow in held {flow.abort()}
		task.abort();
	}

	#[tokio::test]
	async fn one_user_holds_a_quarter_of_the_flows_and_the_reserved_places_are_the_resolvers() {
		let (stack, _to_stack, _from_stack, task) = stack(vec![own()], 64);
		let held: Vec<_> = (0..48).map(|at| {let stack = stack.clone(); tokio::spawn(async move {stack.connect(remote(1000 + at), Who::User(usize::from(at) / 16)).await})}).collect();
		settle().await;
		assert_eq!(stack.counters.flows.load(Ordering::Relaxed), 48);
		assert_eq!(stack.connect(remote(2000), Who::User(0)).await.err(), Some(Fail::Busy), "a user past its share of a quarter");
		assert_eq!(stack.udp(remote(2000), Who::User(1)).await.err(), Some(Fail::Busy), "a UDP flow counts for the user's share");
		assert_eq!(stack.connect(remote(2001), Who::User(3)).await.err(), Some(Fail::Busy), "the reserved places are not for users: three users hold all the rest");
		assert_eq!(stack.connect(remote(2002), Who::Node).await.err(), Some(Fail::Busy), "nor for the node's own sockets");
		let lookup = tokio::spawn({let stack = stack.clone(); async move {stack.udp(remote(53), Who::Dns).await}});
		let flow = timeout(Duration::from_secs(1), lookup).await.expect("the lookup waited").unwrap();
		assert!(flow.is_ok(), "the resolver was refused a reserved place");
		for flow in held {flow.abort()}
		task.abort();
	}

	#[tokio::test]
	async fn a_udp_datagram_over_the_mtu_is_not_taken() {
		let (stack, _to_stack, _from_stack, task) = stack(vec![own()], 16);
		let flow = stack.udp(remote(53), Who::Node).await.unwrap();
		assert!(flow.send(&[1u8; 1392]));
		assert!(!flow.send(&[1u8; 1393]), "a datagram that would not fit in one packet of 1420 bytes");
		task.abort();
	}

	#[tokio::test]
	async fn a_udp_flow_sends_from_a_port_of_its_own_and_hears_only_its_destination() {
		let (stack, to_stack, mut from_stack, task) = stack(vec![own()], 16);
		let mut flow = stack.udp(remote(53), Who::Node).await.unwrap();
		assert!(flow.send(b"question"));
		let port = next(&mut from_stack, |packet| match &packet.transport {Some(TransportSlice::Udp(udp)) if udp.payload() == b"question" && udp.destination_port() == 53 => Some(udp.source_port()), _ => None}).await;
		assert!(port >= 33000);
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).udp(54, port), b"wrong port")).await.unwrap();
		to_stack.send(build!(PacketBuilder::ipv4([198, 51, 100, 8], OWN, 64).udp(53, port), b"wrong host")).await.unwrap();
		settle().await;
		assert!(timeout(Duration::from_millis(100), flow.recv()).await.is_err(), "a datagram from another source reached the flow");
		assert_eq!(stack.counters.unsolicited.load(Ordering::Relaxed), 2);
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).udp(53, port), b"answer")).await.unwrap();
		assert_eq!(timeout(Duration::from_secs(1), flow.recv()).await.expect("no answer").as_deref(), Some(&b"answer"[..]));
		drop(flow);
		settle().await;
		assert_eq!(stack.counters.flows.load(Ordering::Relaxed), 0, "a dropped flow holds a place");
		to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).udp(53, port), b"late")).await.unwrap();
		settle().await;
		assert_eq!(stack.counters.unsolicited.load(Ordering::Relaxed), 3, "an answer to a flow that ended is unasked like any other");
		task.abort();
	}

	#[tokio::test]
	async fn a_burst_the_flow_does_not_read_is_dropped_and_the_stack_keeps_going() {
		let (stack, to_stack, mut from_stack, task) = stack(vec![own()], 16);
		let mut flow = stack.udp(remote(53), Who::Node).await.unwrap();
		assert!(flow.send(b"first"));
		let port = next(&mut from_stack, |packet| match &packet.transport {Some(TransportSlice::Udp(udp)) if udp.payload() == b"first" => Some(udp.source_port()), _ => None}).await;
		for _ in 0..200 {to_stack.send(build!(PacketBuilder::ipv4(REMOTE, OWN, 64).udp(53, port), &[7u8; 100])).await.unwrap();}
		settle().await;
		let mut heard = 0;
		while timeout(Duration::from_millis(50), flow.recv()).await.is_ok_and(|datagram| datagram.is_some()) {heard += 1}
		assert!(heard > 0 && heard < 200, "{heard}: the socket of a flow is bounded");
		assert!(flow.send(b"again"), "the stack stopped taking datagrams");
		next(&mut from_stack, |packet| match &packet.transport {Some(TransportSlice::Udp(udp)) if udp.payload() == b"again" => Some(()), _ => None}).await;
		task.abort();
	}

	// The harness of the fuzz target, run on a fixed input of whole records, segments built from flags and raw bytes: it holds its own invariants.
	#[tokio::test(start_paused = true)]
	async fn the_fuzz_driver_holds_on_segments_of_the_open_flows_and_on_raw_bytes() {
		let (mut input, mut seed) = (Vec::new(), 0x2545f4914f6cdd1du64);
		for at in 0..300u32 {
			seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			let bytes = (seed >> 24).to_be_bytes();
			let record: Vec<u8> = match at % 3 {
				0 => [&[0xffu8][..], &bytes[..], &[0x11, 0x22, (at % 32) as u8][..], b"payload"].concat(),
				1 => [&[0xfeu8][..], &bytes[..], &[1, 2, 3, 4][..], b"datagram"].concat(),
				_ => bytes.to_vec(),
			};
			input.push(record.len() as u8);
			input.extend_from_slice(&record);
		}
		drive(&input).await.unwrap();
	}
}
