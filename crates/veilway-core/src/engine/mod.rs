//! The engine: one WireGuard tunnel per inbound, every decrypted packet checked and routed, and TCP and UDP flows re-dialled by a userspace stack through the outbound of the exit they were routed to.
//! Only an `l3` exit uses a TUN device and kernel routing, and only for the flows that were routed to it.
pub mod dns;
mod flows;
pub mod gate;
pub mod icmp;
mod inbound;
pub mod l3;
pub mod netstack;
pub mod plan;
pub mod resolver;
pub mod route;

pub use plan::Plan;
pub use route::Reason;

use crate::config::{Config, Transport, DEFAULT_TCP_IDLE_SECS, DEFAULT_UDP_IDLE_SECS};
use anyhow::Context;
use inbound::{Peers, Tunnel};
use ipstack::{IpStack, IpStackConfig, TcpConfig};
use netstack::PacketDev;
use plan::{Backend, Fallback};
use resolver::Resolver;
use route::Flows;
use socket2::{Domain, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use veilway_wg::ws::{self, TlsFiles};
use veilway_wg::Wg;

/// Packets in flight between a tunnel and its stack in either direction.
const QUEUE: usize = 4096;
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// What `start` needs besides the config document.
pub struct Options {
	/// The directory of the config file. Paths in the config are relative to it.
	pub dir: PathBuf,
	/// Whether an address belongs to this host, for the destination gate. Tests replace it to reach a responder on the machine they run on.
	pub is_local: fn(IpAddr) -> bool,
}

impl Options {
	pub fn new(dir: impl Into<PathBuf>) -> Options {Options {dir: dir.into(), is_local: gate::is_local}}
}

/// Inner IP packets and their bytes. Up is from the user's device into the node, down is towards it.
#[derive(Default)]
pub struct Traffic {up_packets: AtomicU64, up_bytes: AtomicU64, down_packets: AtomicU64, down_bytes: AtomicU64}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {pub up_packets: u64, pub up_bytes: u64, pub down_packets: u64, pub down_bytes: u64}

impl Traffic {
	fn up(&self, bytes: usize) {
		self.up_packets.fetch_add(1, Ordering::Relaxed);
		self.up_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
	}

	fn down(&self, bytes: usize) {
		self.down_packets.fetch_add(1, Ordering::Relaxed);
		self.down_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
	}

	pub fn totals(&self) -> Totals {
		Totals {up_packets: self.up_packets.load(Ordering::Relaxed), up_bytes: self.up_bytes.load(Ordering::Relaxed), down_packets: self.down_packets.load(Ordering::Relaxed), down_bytes: self.down_bytes.load(Ordering::Relaxed)}
	}
}

/// What the node's resolver did with the DNS queries of its tunnels since start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsTotals {
	/// Answered with what a server said.
	pub answered: u64,
	/// Answered REFUSED: a rule, the destination gate, a block exit, or an exit the user may not use.
	pub refused: u64,
	/// Answered SERVFAIL because no server answered.
	pub failed: u64,
	/// Port 53 traffic that was not a DNS query, dropped without an answer.
	pub malformed: u64,
	/// Turned away because the user already had too many queries waiting.
	pub throttled: u64,
}

/// Indexed like the users, inbounds and exits of the plan.
struct Counters {users: Vec<Traffic>, inbounds: Vec<Traffic>, exits: Vec<Traffic>, drops: [AtomicU64; Reason::COUNT]}

impl Counters {
	fn count(&self, reason: Reason) {self.drops[reason as usize].fetch_add(1, Ordering::Relaxed);}
}

/// What the engine has learnt about an exit's upstream while running.
#[derive(Default)]
struct ExitState {
	/// When the upstream last refused a UDP ASSOCIATE. It expires, see `flows::UDP_RETRY`.
	no_udp: Mutex<Option<Instant>>,
	/// Switches between "relays udp" and "does not", in either direction.
	udp_flips: AtomicU64,
}

/// Everything the engine's tasks share.
pub struct Shared {
	plan: RwLock<Arc<Plan>>,
	tunnels: Vec<Tunnel>,
	flows: Flows,
	counters: Counters,
	resolver: Resolver,
	exits: Vec<ExitState>,
	/// For each exit with an l3 backend, the way into its interface.
	l3: Vec<Option<l3::Port>>,
	/// The ICMP errors each device may still be sent, indexed like the devices of the plan.
	limits: Vec<Mutex<icmp::Limit>>,
	/// Pings that leave from the node's own address, by the device's address, the destination and the identifier the device chose, each with its device, that device's user and the way to its socket.
	pings: Mutex<HashMap<(IpAddr, IpAddr, u16), (usize, usize, mpsc::Sender<Vec<u8>>)>>,
	/// One for all `ws` listeners.
	relays: Arc<ws::Stats>,
	is_local: fn(IpAddr) -> bool,
}

impl Shared {
	/// The plan in force. A task takes it once per packet or flow and works on that one value.
	pub fn plan(&self) -> Arc<Plan> {self.plan.read().unwrap_or_else(|e| e.into_inner()).clone()}
}

/// A running engine. Its tasks live until the process exits, and `shutdown` takes back what it set up on the host. Dropping it does so too, without waiting for the l3 tasks to end.
pub struct Engine {shared: Arc<Shared>, l3: Vec<l3::Running>}

impl Engine {
	/// Stops every l3 exit and removes its interface, routes and firewall rules from the host. Everything else the engine holds goes with the process.
	pub async fn shutdown(self) {
		for exit in self.l3 {exit.close().await}
	}

	pub fn plan(&self) -> Arc<Plan> {self.shared.plan()}

	pub fn user(&self, name: &str) -> Option<Totals> {self.plan().users.iter().position(|user| user.name == name).map(|i| self.shared.counters.users[i].totals())}

	pub fn inbound(&self, tag: &str) -> Option<Totals> {self.plan().inbounds.iter().position(|inbound| inbound.tag == tag).map(|i| self.shared.counters.inbounds[i].totals())}

	pub fn exit(&self, tag: &str) -> Option<Totals> {self.plan().exits.iter().position(|exit| exit.tag == tag).map(|i| self.shared.counters.exits[i].totals())}

	/// Packets dropped or refused for `reason` since start.
	pub fn dropped(&self, reason: Reason) -> u64 {self.shared.counters.drops[reason as usize].load(Ordering::Relaxed)}

	/// How often the upstream of an exit switched between relaying UDP and not.
	pub fn udp_flips(&self, exit: &str) -> Option<u64> {self.plan().exits.iter().position(|e| e.tag == exit).map(|i| self.shared.exits[i].udp_flips.load(Ordering::Relaxed))}

	/// WebSocket connections dropped because they never finished the upgrade.
	pub fn ws_stalled(&self) -> u64 {self.shared.relays.stalled.load(Ordering::Relaxed)}

	/// WebSocket connections refused at accept: a listener was full, or one source had too many unfinished upgrades.
	pub fn ws_refused(&self) -> u64 {self.shared.relays.refused.load(Ordering::Relaxed)}

	pub fn dns(&self) -> DnsTotals {
		let resolver = &self.shared.resolver;
		DnsTotals {answered: resolver.answered.load(Ordering::Relaxed), refused: resolver.refused.load(Ordering::Relaxed), failed: resolver.failed.load(Ordering::Relaxed), malformed: resolver.malformed.load(Ordering::Relaxed), throttled: resolver.throttled.load(Ordering::Relaxed)}
	}

	/// Names the node remembers for a user right now: those the user resolved through it whose answer has not expired.
	pub fn dns_names(&self, user: &str) -> Option<usize> {self.plan().users.iter().position(|u| u.name == user).map(|i| self.shared.resolver.names(i).names(Instant::now()))}

	/// Clears what the node remembers of one user's DNS answers. False when there is no such user.
	pub fn forget_names(&self, user: &str) -> bool {self.plan().users.iter().position(|u| u.name == user).map(|i| self.shared.resolver.names(i).clear()).is_some()}

	/// Flows in the flow table right now.
	pub fn flows(&self) -> usize {self.shared.flows.len()}
}

/// A bound socket that is not listening yet. IPv6 sockets are always IPv6-only, so a wildcard address of one family never takes the port of the other.
fn bind(addr: SocketAddr, kind: Type) -> io::Result<Socket> {
	let socket = Socket::new(Domain::for_address(addr), kind, None)?;
	if addr.is_ipv6() {socket.set_only_v6(true)?}
	// Lets a restarted node take its port back from connections in TIME_WAIT. On Windows the same option would let another process share the port.
	#[cfg(not(windows))]
	if kind == Type::STREAM {socket.set_reuse_address(true)?}
	socket.set_nonblocking(true)?;
	socket.bind(&addr.into())?;
	Ok(socket)
}

/// Brings up every listener and task of a validated config and returns once they are bound.
pub async fn start(config: &Config, options: Options) -> anyhow::Result<Engine> {
	let plan = Plan::new(config, OffsetDateTime::now_utc())?;
	// One stack serves every exit, so it runs on the longest idle times and each flow's handler enforces its own exit's. A DNS flow waits for its answer longer than a short `udp_idle_secs` allows.
	let idle = |pick: fn(&Backend) -> Option<Duration>, default: u32| plan.exits.iter().filter_map(|exit| pick(&exit.backend)).max().unwrap_or(Duration::from_secs(default.into()));
	let tcp_idle = idle(|backend| if let Backend::Netstack {tcp_idle, ..} = backend {Some(*tcp_idle)} else {None}, DEFAULT_TCP_IDLE_SECS);
	let udp_idle = idle(|backend| if let Backend::Netstack {udp_idle, ..} = backend {Some(*udp_idle)} else {None}, DEFAULT_UDP_IDLE_SECS);
	let (mut tunnels, mut stacks) = (Vec::new(), Vec::new());
	let mut relays: Vec<(SocketAddr, Option<TlsFiles>, Vec<(String, SocketAddr)>)> = Vec::new();
	for inbound in &plan.inbounds {
		let mut wg = Wg::new(inbound.private_key);
		for device in &inbound.peers {wg.add_peer(plan.devices[*device].public_key, plan.devices[*device].preshared_key, None)?;}
		let (mut sockets, mut shown, mut loopback) = (Vec::new(), Vec::new(), None);
		for transport in &inbound.transports {
			match transport {
				Transport::Udp {listen} => {
					let socket = bind(listen.0, Type::DGRAM).and_then(|socket| UdpSocket::from_std(socket.into())).with_context(|| format!("inbound `{}`: cannot listen on udp {}", inbound.tag, listen.0))?;
					sockets.push(Arc::new(socket));
					shown.push(format!("udp {}", listen.0));
				}
				Transport::Ws {listen, path, tls} => {
					// Every ws transport of an inbound forwards its frames to one private loopback socket of that inbound.
					let target = match loopback {
						Some(target) => target,
						None => {
							let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
							let target = socket.local_addr()?;
							sockets.push(Arc::new(socket));
							*loopback.insert(target)
						}
					};
					match relays.iter_mut().find(|(addr, ..)| *addr == listen.0) {
						Some((_, _, routes)) => routes.push((path.clone(), target)),
						None => relays.push((listen.0, tls.as_ref().map(|tls| TlsFiles {cert: options.dir.join(&tls.cert), key: options.dir.join(&tls.key)}), vec![(path.clone(), target)])),
					}
					shown.push(format!("{} {}{path}", if tls.is_some() {"wss"} else {"ws"}, listen.0));
				}
			}
		}
		let (to_stack, from_wg) = mpsc::channel::<Vec<u8>>(QUEUE);
		let (to_wg, from_stack) = mpsc::channel::<Vec<u8>>(QUEUE);
		let (mut stack_config, mut tcp) = (IpStackConfig::default(), TcpConfig::default());
		tcp.timeout = tcp_idle;
		stack_config.mtu_unchecked(inbound.mtu).packet_information(false).udp_timeout(udp_idle.max(resolver::FLOW_IDLE)).with_tcp_config(tcp);
		stacks.push((IpStack::new(stack_config, PacketDev::new(from_wg, to_wg)), from_stack));
		tracing::info!("inbound {}: public key {}, {}, {} peer(s)", inbound.tag, veilway_wg::encode_key(&wg.public_key()), shown.join(", "), inbound.peers.len());
		tunnels.push(Tunnel {peers: Mutex::new(Peers {via: vec![0; inbound.peers.len()], wg}), sockets, to_stack});
	}
	let (mut serving, relay_stats) = (Vec::new(), Arc::<ws::Stats>::default());
	for (addr, tls, routes) in relays {
		let listener = bind(addr, Type::STREAM).and_then(|socket| {
			socket.listen(1024)?;
			TcpListener::from_std(socket.into())
		}).with_context(|| format!("cannot listen on ws {addr}"))?;
		serving.push(ws::relay(listener, tls, routes, ws::MAX_CONNS, relay_stats.clone()).with_context(|| format!("ws {addr}: cannot load the certificate or its key"))?);
	}
	// Return traffic finds its interface by the routes of the pools, and two interfaces cannot both have those. Telling them apart takes policy routing, which is not built.
	let mut wired = plan.exits.iter().enumerate().filter(|(_, exit)| matches!(exit.backend, Backend::L3 {..}));
	let (wired, second) = (wired.next(), wired.next());
	if let (Some((_, first)), Some((_, second))) = (wired, second) {anyhow::bail!("exits `{}` and `{}` both have an l3 backend: this build runs one l3 exit per node, so remove one of them", first.tag, second.tag)}
	let (mut l3, mut from_tunnels, tun_mtu): (Vec<Option<l3::Port>>, _, _) = (plan.exits.iter().map(|_| None).collect(), None, plan.inbounds.iter().map(|inbound| inbound.mtu).min().unwrap_or(crate::config::DEFAULT_MTU));
	for exit in &plan.exits {
		match &exit.backend {
			Backend::Netstack {outbound: plan::Outbound::Socks5(_), ..} => tracing::info!("exit {}: netstack through a socks5 proxy", exit.tag),
			Backend::Netstack {..} => tracing::info!("exit {}: netstack, direct from this node", exit.tag),
			Backend::L3 {masquerade, ..} => if !masquerade && plan.hijack {tracing::warn!("exit {}: l3 without masquerade carries no query of the node's resolver, so dns fails for flows routed to it unless a rule sends the dns servers on port 53 to another exit", exit.tag)},
			Backend::Block => tracing::info!("exit {}: block", exit.tag),
		}
		if let Backend::Netstack {icmp_echo: Fallback::Direct, ..} = &exit.backend {
			icmp::ping_socket(true).map_err(|e| anyhow::anyhow!("exit `{}`: \"icmp_echo\": \"direct\" needs unprivileged ping sockets, which this system does not give the node ({e}); on Linux the node's group has to be inside net.ipv4.ping_group_range", exit.tag))?;
			if plan.pools.iter().any(|(pool, _)| pool.addr().is_ipv6()) && icmp::ping_socket(false).is_err() {tracing::warn!("exit {}: this system gives the node no ping socket for ipv6, so ipv6 pings through the exit get no answer", exit.tag)}
		}
	}
	if let Some((at, _)) = wired {
		let (to, from) = mpsc::channel(QUEUE);
		(l3[at], from_tunnels) = (Some(l3::Port {to, mtu: tun_mtu}), Some((at, from)));
	}
	let counters = Counters {
		users: plan.users.iter().map(|_| Traffic::default()).collect(),
		inbounds: plan.inbounds.iter().map(|_| Traffic::default()).collect(),
		exits: plan.exits.iter().map(|_| Traffic::default()).collect(),
		drops: Default::default(),
	};
	let (exits, resolver, limits) = (plan.exits.iter().map(|_| ExitState::default()).collect(), Resolver::new(&plan), plan.devices.iter().map(|_| Mutex::new(icmp::Limit::new(Instant::now()))).collect());
	let shared = Arc::new(Shared {plan: RwLock::new(Arc::new(plan)), tunnels, flows: Flows::default(), counters, resolver, exits, l3, limits, pings: Mutex::default(), relays: relay_stats, is_local: options.is_local});
	// The last thing that can fail, so that a start that fails leaves no interface and no rule behind.
	let l3 = from_tunnels.map(|(at, from)| l3::Running::start(&shared, &shared.plan(), at, from, tun_mtu)).transpose()?.into_iter().collect();
	for (at, (stack, from_stack)) in stacks.into_iter().enumerate() {inbound::spawn(&shared, at, stack, from_stack)}
	for relay in serving {tokio::spawn(relay);}
	tokio::spawn({
		let shared = shared.clone();
		async move {
			let mut tick = tokio::time::interval(SWEEP_EVERY);
			loop {
				tick.tick().await;
				shared.flows.sweep();
			}
		}
	});
	Ok(Engine {shared, l3})
}
