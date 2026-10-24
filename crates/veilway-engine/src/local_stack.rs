//! The userspace TCP/IP stack of the local proxy: one task that owns a `Tunnel`'s packet interface and runs a smoltcp interface on it, with the device's own tunnel addresses. A connection of the proxy is a TCP socket of this stack, and its bytes reach the proxy task through a `DuplexStream`, so the code that relays them is the code that relays a system socket.
//! Names are looked up here too: A and AAAA queries go over UDP to the gateway of the profile, which is the node's resolver, from a UDP socket of this stack. Nothing here uses the system's resolver or sockets.
//! The device's packets are the whole of what the task sees: it does not touch the control channel, which the engine runs on its own TCP before a packet reaches the platform's interface. The ports of the stack's connections are drawn from 33000 up, above the engine's own.
use crate::local_dns::{self, Bad};
use crate::status::{State, Status};
use crate::{random, Tunnel};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as Clock;
use smoltcp::wire::{HardwareAddress, IpCidr, IpEndpoint};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};

/// An opening that the far side does not answer within this is given up.
const CONNECT: Duration = Duration::from_secs(10);
/// A connection with no byte either way for this long is closed.
const IDLE: Duration = Duration::from_secs(3600);
/// How often the task looks at its deadlines when nothing else wakes it.
const TICK: Duration = Duration::from_secs(1);
/// What each side of a connection buffers, in the socket and in the pipe to the proxy task.
const WINDOW: usize = 131072;
/// The most that is moved at once between a socket and its pipe.
const CHUNK: usize = 16384;
/// Packets that wait to be handed to the stack, and that the stack made and waits to send.
const QUEUE: usize = 256;
const MADE: usize = 64;
/// The most connections and lookups at once, and the names remembered.
const FLOWS: usize = 1024;
const LOOKUPS: usize = 32;
const CACHE: usize = 256;
/// A lookup is asked again once after `RETRY` and given up after `LOOKUP`. An answer is kept for its TTL, within these bounds.
const RETRY: Duration = Duration::from_secs(2);
const LOOKUP: Duration = Duration::from_secs(5);
const KEEP: (u64, u64) = (10, 300);

/// Why a connection or a lookup gave nothing. The proxy answers its client from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
	/// The tunnel has no open session, or it ended.
	Down,
	/// The stack is full: too many connections or lookups, or no free port.
	Busy,
	Timeout,
	/// The far side refused or the path has no route.
	Refused,
	Unreachable,
	/// The name does not exist.
	NotFound,
	/// The destination is one the proxy never connects to.
	Forbidden,
}

impl Fail {
	/// The reply code of RFC 1928.
	pub(crate) fn socks(self) -> u8 {match self {Fail::Forbidden => 2, Fail::Refused => 5, Fail::Unreachable | Fail::NotFound | Fail::Timeout => 4, Fail::Down | Fail::Busy => 1}}
	/// The status line an HTTP client is answered with.
	pub(crate) fn status(self) -> &'static str {match self {Fail::Forbidden => "403 Forbidden", Fail::Timeout => "504 Gateway Timeout", Fail::Down | Fail::Busy => "503 Service Unavailable", _ => "502 Bad Gateway"}}
}

type Connected = oneshot::Sender<Result<DuplexStream, Fail>>;

enum Command {
	Connect(SocketAddr, Connected),
	Resolve(String, oneshot::Sender<Result<Vec<IpAddr>, Fail>>),
}

/// The way to the stack, for as many proxy connections as want one. `own` are the device's addresses in the tunnel.
#[derive(Clone)]
pub(crate) struct Stack {commands: mpsc::Sender<Command>, pub(crate) own: Arc<[IpAddr]>}

impl Stack {
	/// A TCP connection inside the tunnel. The stream is the far side's, already open.
	pub(crate) async fn connect(&self, to: SocketAddr) -> Result<DuplexStream, Fail> {
		let (reply, answer) = oneshot::channel();
		self.commands.send(Command::Connect(to, reply)).await.map_err(|_| Fail::Down)?;
		answer.await.map_err(|_| Fail::Down)?
	}

	/// The addresses of a name from the node's resolver, IPv4 first, only of the families the device has.
	pub(crate) async fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, Fail> {
		let (reply, answer) = oneshot::channel();
		self.commands.send(Command::Resolve(name.to_owned(), reply)).await.map_err(|_| Fail::Down)?;
		answer.await.map_err(|_| Fail::Down)?
	}
}

/// Wakes the task when a pipe it polled is ready.
struct Wake(Notify);

impl std::task::Wake for Wake {
	fn wake(self: Arc<Self>) {self.0.notify_one()}

	fn wake_by_ref(self: &Arc<Self>) {self.0.notify_one()}
}

/// A port from 33000 up, which is above where the engine draws its own and below where the systems draw theirs.
fn draw_port() -> u16 {
	let mut bytes = [0u8; 2];
	let _ = random(&mut bytes);
	33000 + u16::from_le_bytes(bytes) % 27000
}

struct Flow {handle: SocketHandle, port: u16, app: DuplexStream, peer: Option<DuplexStream>, reply: Option<Connected>, started: Instant, idle_at: Instant, out: Vec<u8>, written: usize, client_eof: bool, far_done: bool, shut: bool, done: bool}

struct Lookup {name: String, pending: Vec<(u16, u16)>, found: Vec<(IpAddr, u32)>, failed: bool, started: Instant, retried: bool, reply: Option<oneshot::Sender<Result<Vec<IpAddr>, Fail>>>}

/// Starts the stack on `tunnel`. The task ends when `stop` is sent or dropped or when the tunnel does, and gives the tunnel's last status.
pub(crate) fn start(tunnel: Tunnel) -> (Stack, oneshot::Sender<()>, JoinHandle<Status>) {
	let (commands, input) = mpsc::channel(64);
	let (stop, stopped) = oneshot::channel();
	let own: Arc<[IpAddr]> = tunnel.device.clone().into();
	(Stack {commands, own}, stop, tokio::spawn(run(tunnel, input, stopped)))
}

async fn run(mut tunnel: Tunnel, mut commands: mpsc::Receiver<Command>, mut stop: oneshot::Receiver<()>) -> Status {
	let (own, server) = (tunnel.device.clone(), tunnel.gateways.first().map(|gateway| IpEndpoint::new((*gateway).into(), 53)));
	let (started, wake) = (Instant::now(), Arc::new(Wake(Notify::new())));
	let waker = Waker::from(wake.clone());
	let clock = || Clock::from_micros(started.elapsed().as_micros() as i64);
	let mut device = Wire {rx: VecDeque::new(), tx: Vec::new(), mtu: usize::from(tunnel.status.borrow().mtu)};
	let mut seed = [0u8; 8];
	let _ = random(&mut seed);
	let mut config = Config::new(HardwareAddress::Ip);
	config.random_seed = u64::from_le_bytes(seed);
	let mut iface = Interface::new(config, &mut device, clock());
	// Every address is on the link: there are no neighbours to ask and no route to look up.
	iface.update_ip_addrs(|addresses| {for address in &own {let _ = addresses.push(IpCidr::new((*address).into(), 0));}});
	let mut sockets = SocketSet::new(Vec::new());
	let mut resolver = udp::Socket::new(udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16 * 1500]), udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 16 * 1500]));
	let _ = resolver.bind(draw_port());
	let resolver = sockets.add(resolver);
	let (mut flows, mut lookups, mut cache, mut buf) = (Vec::<Flow>::new(), Vec::<Lookup>::new(), HashMap::<String, (Instant, Vec<IpAddr>)>::new(), vec![0u8; CHUNK]);
	loop {
		device.mtu = usize::from(tunnel.status.borrow().mtu);
		let now = Instant::now();
		iface.poll(clock(), &mut device, &mut sockets);
		let socket = sockets.get_mut::<udp::Socket>(resolver);
		while let Ok((data, meta)) = socket.recv() {
			if Some(meta.endpoint) != server {continue}
			let Some(id) = data.get(..2).map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]])) else {continue};
			let Some((lookup, at)) = lookups.iter_mut().find_map(|lookup| lookup.pending.iter().position(|(asked, _)| *asked == id).map(|at| (lookup, at))) else {continue};
			match local_dns::answer(data, id, &lookup.name, lookup.pending[at].1) {
				Ok(records) => lookup.found.extend(records),
				Err(Bad::Unrelated) => continue,
				Err(Bad::NotFound) => {}
				Err(Bad::Failed) => lookup.failed = true,
			}
			lookup.pending.remove(at);
		}
		for lookup in lookups.iter_mut() {
			if lookup.reply.as_ref().is_some_and(|reply| reply.is_closed()) {lookup.pending.clear()}
			if !lookup.retried && !lookup.pending.is_empty() && now >= lookup.started + RETRY {
				lookup.retried = true;
				for (id, kind) in &lookup.pending {
					if let (Some(message), Some(server)) = (local_dns::query(*id, &lookup.name, *kind), server) {let _ = sockets.get_mut::<udp::Socket>(resolver).send_slice(&message, server);}
				}
			}
		}
		lookups.retain_mut(|lookup| {
			if !lookup.pending.is_empty() && now < lookup.started + LOOKUP {return true}
			let Some(reply) = lookup.reply.take() else {return false};
			let mut addresses: Vec<IpAddr> = lookup.found.iter().map(|(address, _)| *address).collect();
			addresses.sort_by_key(IpAddr::is_ipv6);
			addresses.dedup();
			let result = if !addresses.is_empty() {
				let ttl = lookup.found.iter().map(|(_, ttl)| u64::from(*ttl)).min().unwrap_or(0).clamp(KEEP.0, KEEP.1);
				if cache.len() >= CACHE {
					cache.retain(|_, (expires, _)| *expires > now);
					if cache.len() >= CACHE {cache.clear()}
				}
				cache.insert(lookup.name.clone(), (now + Duration::from_secs(ttl), addresses.clone()));
				Ok(addresses)
			} else if !lookup.pending.is_empty() {
				tracing::info!(name = %lookup.name, "the node's resolver did not answer a lookup of the local proxy within {} s", LOOKUP.as_secs());
				Err(Fail::Timeout)
			} else if lookup.failed {
				Err(Fail::Unreachable)
			} else {
				Err(Fail::NotFound)
			};
			let _ = reply.send(result);
			false
		});
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
		for raw in device.tx.drain(..) {tunnel.send(raw);}
		flows.retain(|flow| {
			if flow.done {sockets.remove(flow.handle);}
			!flow.done
		});
		if progress || !device.rx.is_empty() {wake.0.notify_one()}
		let wake_at = [iface.poll_delay(clock(), &sockets).map(|delay| now + Duration::from_micros(delay.total_micros())), Some(now + TICK)].into_iter().flatten().min().unwrap_or(now);
		tokio::select! {
			received = tunnel.out.recv(), if device.rx.len() < QUEUE => match received {
				Some(raw) => {
					device.rx.push_back(raw);
					while device.rx.len() < QUEUE {
						let Ok(more) = tunnel.out.try_recv() else {break};
						device.rx.push_back(more);
					}
				}
				None => break,
			},
			Some(command) = commands.recv() => {
				let (now, up) = (Instant::now(), matches!(tunnel.status.borrow().state, State::Connected {..}));
				match command {
					Command::Connect(to, reply) => {
						let local = own.iter().find(|address| address.is_ipv4() == to.is_ipv4()).copied();
						let port = (0..16).map(|_| draw_port()).find(|port| flows.iter().all(|flow| flow.port != *port));
						let (Some(local), Some(port)) = (local, port) else {
							let _ = reply.send(Err(if local.is_none() {Fail::Unreachable} else {Fail::Busy}));
							continue;
						};
						if !up || flows.len() >= FLOWS {
							let _ = reply.send(Err(if up {Fail::Busy} else {Fail::Down}));
							continue;
						}
						let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; WINDOW]), tcp::SocketBuffer::new(vec![0u8; WINDOW]));
						socket.set_nagle_enabled(false);
						if socket.connect(iface.context(), to, (local, port)).is_err() {
							let _ = reply.send(Err(Fail::Busy));
							continue;
						}
						let (app, peer) = duplex(WINDOW);
						flows.push(Flow {handle: sockets.add(socket), port, app, peer: Some(peer), reply: Some(reply), started: Instant::now(), idle_at: Instant::now() + IDLE, out: Vec::new(), written: 0, client_eof: false, far_done: false, shut: false, done: false});
					}
					Command::Resolve(name, reply) => {
						if let Some((_, addresses)) = cache.get(&name).filter(|(expires, _)| *expires > now) {
							let _ = reply.send(Ok(addresses.clone()));
							continue;
						}
						if !up || lookups.len() >= LOOKUPS {
							let _ = reply.send(Err(if up {Fail::Busy} else {Fail::Down}));
							continue;
						}
						let kinds = [(own.iter().any(IpAddr::is_ipv4), local_dns::A), (own.iter().any(IpAddr::is_ipv6), local_dns::AAAA)];
						let queries: Option<Vec<(u16, u16, Vec<u8>)>> = kinds.into_iter().filter(|(wanted, _)| *wanted).map(|(_, kind)| {
							let mut id = [0u8; 2];
							let _ = random(&mut id);
							let id = u16::from_le_bytes(id);
							local_dns::query(id, &name, kind).map(|message| (id, kind, message))
						}).collect();
						let (Some(server), Some(queries)) = (server, queries) else {
							let _ = reply.send(Err(Fail::NotFound));
							continue;
						};
						if queries.iter().all(|(_, _, message)| sockets.get_mut::<udp::Socket>(resolver).send_slice(message, server).is_ok()) {
							lookups.push(Lookup {name, pending: queries.into_iter().map(|(id, kind, _)| (id, kind)).collect(), found: Vec::new(), failed: false, started: Instant::now(), retried: false, reply: Some(reply)});
						} else {
							let _ = reply.send(Err(Fail::Busy));
						}
					}
				}
			}
			_ = wake.0.notified() => {}
			_ = sleep_until(wake_at) => {}
			_ = &mut stop => break,
		}
	}
	for flow in &mut flows {
		sockets.get_mut::<tcp::Socket>(flow.handle).abort();
		if let Some(reply) = flow.reply.take() {let _ = reply.send(Err(Fail::Down));}
	}
	for lookup in &mut lookups {if let Some(reply) = lookup.reply.take() {let _ = reply.send(Err(Fail::Down));}}
	iface.poll(clock(), &mut device, &mut sockets);
	for raw in device.tx.drain(..) {tunnel.send(raw);}
	tunnel.stop().await
}

/// The packets of the stack: what arrived waits in `rx`, and what the stack made waits in `tx` to be sent into the tunnel.
struct Wire {rx: VecDeque<Vec<u8>>, tx: Vec<Vec<u8>>, mtu: usize}

struct Received(Vec<u8>);

struct Made<'a>(&'a mut Vec<Vec<u8>>);

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
