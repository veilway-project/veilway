//! What the node holds on the host, and how a config gets there: `prepare` takes everything a config needs that the node does not hold yet while the running config keeps working, and `commit` puts the config in force in one step.
//! A start is the same two steps from nothing. Nothing in here can fail once `prepare` has returned, and when `prepare` fails it has left nothing behind.
use super::icmp::{self, Kind};
use super::inbound::{self, Peers, Tunnel};
use super::netstack::{self, PacketDev};
use super::plan::{self, Backend, Carrier, Denied, Fallback, Holder, Outbound, Plan, User};
use super::route::{self, By, Decision, Ended, Key};
use super::limits::Clock;
use super::upstream::{self, UpstreamState};
use super::upstream_state::{UpstreamFile, UpstreamVault};
use super::{certificate, control, faketls, l3, link, obfs, proxy, replay, stream, tunnel, CutOff, Event, Over, Shared, QUEUE};
use crate::config::{loops, Certificate, Config, ProxyInbound, RuleTransport, Upstream, Host as Named, Http2, Protocol, Tls, Transport, Tunnel as Forwarded, TunnelProtocol, DEFAULT_MTU, DEFAULT_SESSIONS, DEFAULT_SITE_PORT, DEFAULT_SITE_RATE, DEFAULT_SITE_RELAYED, MAX_NAMES_LOGGED, MAX_TCP_IDLE_SECS, MAX_UDP_IDLE_SECS};
use anyhow::anyhow;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use etherparse::PacketBuilder;
use ipnet::IpNet;
use ipstack::{IpStack, IpStackConfig, TcpConfig};
#[cfg(target_os = "linux")]
use rustix::net::sockopt;
use socket2::{Domain, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::{lookup_host, TcpListener, UdpSocket};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use veilway_proto::control::{ByeReason, NodeMessage, PORT};
use veilway_proto::subscription::{DeviceSecret, Secret};
use veilway_wg::ws::{self, TlsFiles};
use veilway_wg::Wg;

/// How much longer than the longest idle time a config may set the userspace stack keeps a quiet flow, in seconds. Each flow's handler ends it first, at the idle time of its own exit.
const STACK_MARGIN: u64 = 60;
/// How often and how far apart `bind` tries an address again that the node has only just given back.
const REBIND_TRIES: u32 = 50;
const REBIND_EVERY: Duration = Duration::from_millis(20);
/// How long the name of a decoy origin may take to resolve, at start and at a reload.
const RESOLVE: Duration = Duration::from_secs(5);

/// A task that ends when this is dropped.
struct Task(AbortHandle);

impl Drop for Task {
	fn drop(&mut self) {self.0.abort()}
}

/// What a UDP socket is read for: the tunnel of a `udp` transport, which takes WireGuard datagrams as they are, or the listener of a `udp-obfs` transport with its sessions.
enum Reader {Plain(Arc<Tunnel>), Obfs(Arc<obfs::Listener>)}

/// Transports page, "MTU", "No outer fragmentation": "On a `veilway` inbound, the client and the node send every outer packet of a datagram transport with fragmentation prohibited. A packet that does not fit the path is lost, not fragmented."
/// With `whole` the socket sets "do not fragment" on everything it sends and never fragments by a path MTU it has learnt, so neither the host nor a router cuts a packet. Without it the socket is put back to what the system does by itself.
/// Only Linux has this here: no dependency of the tree sets the option of another system without `unsafe`. There a `veilway` inbound is told at start that its packets may be fragmented.
#[cfg(target_os = "linux")]
pub(super) fn fragmenting(socket: &UdpSocket, v6: bool, whole: bool) -> io::Result<()> {
	Ok(if v6 {sockopt::set_ipv6_mtu_discover(socket, if whole {sockopt::Ipv6PathMtuDiscovery::PROBE} else {sockopt::Ipv6PathMtuDiscovery::WANT})?} else {sockopt::set_ip_mtu_discover(socket, if whole {sockopt::Ipv4PathMtuDiscovery::PROBE} else {sockopt::Ipv4PathMtuDiscovery::WANT})?})
}

#[cfg(not(target_os = "linux"))]
pub(super) fn fragmenting(_: &UdpSocket, _: bool, whole: bool) -> io::Result<()> {if whole {Err(io::ErrorKind::Unsupported.into())} else {Ok(())}}

/// A tunnel as it runs: its tasks, and the loopback socket every `ws` transport of the inbound relays to, with its address and the task that reads it. An inbound without a `ws` transport has none.
struct Running {tunnel: Arc<Tunnel>, _tasks: Vec<Task>, loopback: Option<(SocketAddr, Arc<UdpSocket>, Task)>}

/// One address `ws` transports listen on: the end its listener is told through, and the routes it serves, each with the path, the `tls` of its transport, its tunnel and the number that tells it from an earlier route.
struct Relay {served: watch::Sender<Arc<ws::Served>>, routes: Vec<(String, Option<Tls>, Arc<Tunnel>, u64)>}

/// A tunnel as it runs: the tunnel with its defaults written out, what it counts, the socket it listens on and the task that accepts on it, which takes every connection of the tunnel with it.
struct Forward {config: Forwarded, links: Vec<String>, state: Arc<tunnel::State>, bound: tunnel::Bound, _task: Task}

/// A proxy inbound as it runs: the inbound with its defaults written out, the socket it listens on, what it counts and the task that accepts on it, which takes every connection of the inbound with it.
struct Proxy {config: ProxyInbound, listener: Arc<TcpListener>, state: Arc<proxy::State>, _task: Task}

/// The l3 exit as it runs.
pub struct Wired {wanted: l3::Wanted, port: l3::Port, queue: l3::Queue, pub running: l3::Running}

pub struct Host {
	/// The directory of the config file.
	dir: PathBuf,
	/// The config the plan in force was compiled from.
	config: Option<Arc<Config>>,
	/// Every `udp` and `udp-obfs` transport by its listen address: its socket, and the task that reads it with what it reads it for.
	/// An address the next config uses again is never bound a second time. Its socket goes to whichever tunnel and transport has it then.
	udp: HashMap<SocketAddr, (Arc<UdpSocket>, Option<(Task, Reader)>)>,
	ws: HashMap<SocketAddr, Relay>,
	/// Every stream listener by its listen address, with the tasks that accept on it and learn the header fields of its upgrade answer. It lives for as long as a config has a `tls` transport on the address, and its sessions with it.
	tls: HashMap<SocketAddr, (Arc<stream::Listener>, [Task; 2])>,
	/// Every `faketls` listener by its listen address, with the task that accepts on it. It lives for as long as a config has a `faketls` transport on the address, and its sessions with it.
	faketls: HashMap<SocketAddr, (Arc<faketls::Listener>, [Task; 2])>,
	/// By the tag of the inbound.
	tunnels: HashMap<String, Running>,
	/// Shared with the `Engine`, which takes it out when it shuts down or is dropped: the interface, its routes and its firewall table go with the engine, while everything else here serves on.
	pub l3: Arc<Mutex<Option<Wired>>>,
	/// The number the last new `ws` route was given.
	routes: u64,
	/// The listen addresses the last commit gave back to the host.
	released: HashSet<SocketAddr>,
	/// The tunnel of each node link this node dials, by the tag of its place among the inbounds of a plan, with what it was made for: the link's key, the other node's key and the MTU. A link that keeps all three keeps its tunnel and its sessions.
	shapes: HashMap<String, ([u8; 32], [u8; 32], u16)>,
	/// The task that dials each link, by the link's tag, with what it dials: the tunnel, the link's id and keys and secret, its MTU and the other node's transports. Anything else is a new task.
	diallers: HashMap<String, (Arc<link::Dialler>, Task, Arc<Tunnel>, ([u8; 16], [u8; 32], [u8; 32], [u8; 32], u16, u64, Option<Arc<plan::Upstream>>))>,
	/// The tunnels of the config in force that are enabled, by tag.
	forwards: HashMap<String, Forward>,
	/// The proxy inbounds of the config in force, by tag.
	proxies: HashMap<String, Proxy>,
	/// The state file of the upstreams, with what a test puts in place of the node's own network for them. None for a node that was given no path.
	upstream_file: Option<(Arc<UpstreamFile>, upstream::Hooks)>,
	/// The task of each upstream that runs, by tag, with the config it runs and its state. An upstream that is the same, with the same state, keeps its task and its tunnel through a reload.
	upstreams: HashMap<String, (Upstream, Option<upstream::Reach>, Arc<UpstreamState>, Task)>,
	/// The upstreams the operator removed through the API while the config in force still names them, by tag, with what is needed to tell the provider again. None of them runs again until a config that does not name them, or names another link or device, has been in force: a removed device must not enrol itself anew. The state file carries the same fact as a tombstone, so a restart finds it too.
	left: HashMap<String, (Upstream, Option<upstream::Reach>, Arc<UpstreamState>)>,
}

/// What `prepare` took for a config that is not in force yet. Dropping it gives all of it back.
pub struct Staged {
	plan: Plan,
	config: Arc<Config>,
	udp: Vec<(SocketAddr, Arc<UdpSocket>)>,
	ws: Vec<(SocketAddr, TcpListener)>,
	/// For every address `ws` transports listen on, what its certificate files hold now.
	acceptors: HashMap<SocketAddr, Option<ws::Acceptor>>,
	/// The stream listeners the node does not have yet, and for every address stream transports listen on, what its certificate files hold now, when it ends TLS, and where its decoy origin is now.
	tls: Vec<(SocketAddr, TcpListener)>,
	streams: HashMap<SocketAddr, (Option<ws::Acceptor>, SocketAddr)>,
	/// The `faketls` listeners the node does not have yet, and for every address a `faketls` transport listens on, where its site is now: the address of the config, or what its name resolved to.
	borrowed: Vec<(SocketAddr, TcpListener)>,
	sites: HashMap<SocketAddr, (SocketAddr, Option<(String, Arc<Outbound>)>)>,
	/// The self-signed certificates of those listeners, each with whether it was made now.
	certified: Vec<(certificate::Made, bool)>,
	/// The tunnels that are new or restart, each with its stack and what the stack sends back.
	tunnels: Vec<(Arc<Tunnel>, IpStack, Receiver<Vec<u8>>)>,
	loopbacks: Vec<(Arc<Tunnel>, SocketAddr, Arc<UdpSocket>)>,
	/// The tunnels that are new or changed, with their defaults written out, each with the socket it listens on.
	forwards: Vec<(Forwarded, tunnel::Bound)>,
	/// The proxy inbounds that are new or changed, each with the socket it listens on.
	proxies: Vec<(ProxyInbound, Arc<TcpListener>)>,
	l3: Option<Wired>,
	/// The upstreams of the config that are enabled, each with the config it runs, how the node reaches its provider, its state and the vault of its document.
	upstreams: Vec<(Upstream, Option<upstream::Reach>, Arc<UpstreamState>, UpstreamVault)>,
}

/// A bound socket that is not listening yet. IPv6 sockets are always IPv6-only, so a wildcard address of one family never takes the port of the other.
/// `released` says the node itself gave this address back in its last commit. The task that held the old socket ends a moment after it is told to, so such an address is tried again for a while when it is still taken.
pub(super) async fn bind(addr: SocketAddr, kind: Type, released: bool) -> io::Result<Socket> {
	let mut tries = if released {REBIND_TRIES} else {1};
	loop {
		let bound = Socket::new(Domain::for_address(addr), kind, None).and_then(|socket| {
			if addr.is_ipv6() {socket.set_only_v6(true)?}
			// Lets a restarted node take its port back from connections in TIME_WAIT. On Windows the same option would let another process share the port.
			#[cfg(not(windows))]
			if kind == Type::STREAM {socket.set_reuse_address(true)?}
			socket.set_nonblocking(true)?;
			socket.bind(&addr.into())?;
			Ok(socket)
		});
		match bound {
			Err(e) if e.kind() == io::ErrorKind::AddrInUse && tries > 1 => tries -= 1,
			bound => return bound,
		}
		tokio::time::sleep(REBIND_EVERY).await;
	}
}

/// The tags of the links of the `chain` exit a tunnel names, in the config's order. A change to them closes the tunnel's connections.
fn chain_links(config: &Config, exit: &str) -> Vec<String> {
	config.exits.iter().find(|candidate| candidate.tag == exit).and_then(|candidate| if let crate::config::Backend::Chain(chain) = &candidate.backend {Some(chain.links.clone())} else {None}).unwrap_or_default()
}

/// What tells the device of a flow that the flow was ended from the node's side, and the tunnel address it goes to: a reset for TCP, as from the host the device was talking to, and for UDP an ICMP error from the gateway.
/// Other protocols have nothing at the device that an error without the packet it answers could end. None as well when the device no longer holds the address the flow came from.
pub(super) fn farewell(plan: &Plan, flow: &Ended) -> Option<(Holder, Vec<u8>)> {
	let from = plan.by_address.get(&flow.key.src).copied().filter(|from| plan.devices[from.device].public_key == flow.device)?;
	let packet = match flow.key.protocol {
		Protocol::TCP => flow.heard.and_then(|heard| route::tcp_reset(&flow.key, heard)),
		Protocol::UDP => {
			let mut raw = Vec::new();
			let built = match (flow.key.src, flow.key.dst) {
				(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(flow.key.sport, flow.key.dport).write(&mut raw, &[]),
				(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(flow.key.sport, flow.key.dport).write(&mut raw, &[]),
				_ => return None,
			};
			let gateway = plan.gateway(from.inbound, flow.key.src.is_ipv4());
			built.ok().and_then(|_| netstack::parse(&raw)).zip(gateway).and_then(|(packet, gateway)| icmp::error(&raw, &packet, Kind::Prohibited, gateway, &plan.pools))
		}
		_ => None,
	};
	Some(from).zip(packet)
}

impl Host {
	pub fn new(dir: PathBuf) -> Host {Host {dir, config: None, udp: HashMap::new(), ws: HashMap::new(), tls: HashMap::new(), faketls: HashMap::new(), tunnels: HashMap::new(), l3: Arc::default(), routes: 0, released: HashSet::new(), shapes: HashMap::new(), diallers: HashMap::new(), forwards: HashMap::new(), proxies: HashMap::new(), upstream_file: None, upstreams: HashMap::new(), left: HashMap::new()}}

	/// Ends the task of every upstream, and with it its tunnel: the node is going away, and a device of a provider should not stay connected from a node that is not there.
	pub fn stop_upstreams(&mut self) {self.upstreams.clear()}

	/// Takes the upstream `tag` off the host for its removal: its task ends, with its tunnel, a tombstone in the state file keeps it from being enrolled again, and a config that still names it does not start it, see `left`. With it what the removal needs. The same call again after a removal that the provider did not confirm gives the same, so the provider can be told again. None when the config in force has no such upstream.
	pub fn release_upstream(&mut self, tag: &str) -> Option<(Arc<UpstreamState>, UpstreamVault, Option<upstream::Reach>, upstream::Hooks)> {
		let (file, hooks) = self.upstream_file.as_ref()?;
		let (written, reach, state) = self.upstreams.get(tag).map(|(written, reach, state, _)| (written.clone(), reach.clone(), state.clone())).or_else(|| self.left.get(tag).cloned())?;
		let secret: [u8; 16] = URL_SAFE_NO_PAD.decode(written.device_secret.expose()).ok().and_then(|bytes| bytes.try_into().ok())?;
		let vault = file.vault(&written.tag, written.link.expose(), Secret::new(written.private_key.expose().0), DeviceSecret::new(secret));
		self.upstreams.remove(tag);
		if let Err(error) = file.mark_left(tag, state.bound()) {tracing::warn!("upstream {tag}: the removal could not be written to the state file, so a restart may enrol the device again: {error}")}
		self.left.insert(tag.to_owned(), (written, reach.clone(), state.clone()));
		Some((state, vault, reach, hooks.clone()))
	}

	/// Gives the host the state file of the upstreams. A config with an enabled upstream is not started, and not reloaded into, without one.
	pub fn with_upstreams(mut self, path: Option<PathBuf>, hooks: upstream::Hooks) -> Host {
		self.upstream_file = path.map(|path| (UpstreamFile::new(path), hooks));
		self
	}

	/// Takes from the host what `config` needs and the node does not hold yet: binds every new listener, reads every certificate again, builds the tunnels that are new or named in `restart`, and brings up the l3 interface.
	/// The running config keeps working through all of it. An error names tags and field paths, never a value from the document, and leaves nothing behind.
	pub async fn prepare(&mut self, shared: &Arc<Shared>, config: &Arc<Config>, restart: &[&str]) -> anyhow::Result<Staged> {
		// A message names an inbound by its place in the document the config was read from.
		self.stage(shared, config, restart).await.map_err(|e| anyhow!("{}", config.remap(&format!("{e:#}"))))
	}

	async fn stage(&mut self, shared: &Arc<Shared>, config: &Arc<Config>, restart: &[&str]) -> anyhow::Result<Staged> {
		let (old, mut fresh) = (shared.plan(), Vec::new());
		// The tunnel of every inbound, and behind them the tunnel of every enabled link this node dials, in the order of the config: a link this node dials has a tunnel of its own, whose one peer is the other node.
		let dialled: Vec<(String, [u8; 32], [u8; 32], u16)> = config.links.iter().filter(|link| link.enabled != Some(false)).filter_map(|link| Some((format!("link:{}", link.tag), link.private_key.as_ref()?.expose().0, link.peer.as_ref()?.inbound_public_key.0, link.mtu(&config.inbounds)))).collect();
		let tunnels = config.inbounds.iter().map(|inbound| (inbound.tag.clone(), inbound.private_key.expose().0, inbound.mtu(), self.tunnels.get(&inbound.tag).filter(|_| !restart.contains(&inbound.tag.as_str())).map(|running| running.tunnel.clone()))).chain(dialled.iter().map(|(tag, private, other, mtu)| (tag.clone(), *private, *mtu, self.tunnels.get(tag).filter(|_| self.shapes.get(tag) == Some(&(*private, *other, *mtu))).map(|running| running.tunnel.clone())))).map(|(tag, private, mtu, running)| match running {
			Some(running) => running,
			None => {
				let (to_stack, from_wg) = mpsc::channel::<Vec<u8>>(QUEUE);
				let (to_wg, from_stack) = mpsc::channel::<Vec<u8>>(QUEUE);
				let (mut stack, mut tcp) = (IpStackConfig::default(), TcpConfig::default());
				// A tunnel outlives the exits of the config it started under, so its stack waits longer than any exit may ask and each flow's handler keeps the time of its own exit.
				tcp.timeout = Duration::from_secs(u64::from(MAX_TCP_IDLE_SECS) + STACK_MARGIN);
				stack.mtu_unchecked(mtu).packet_information(false).udp_timeout(Duration::from_secs(u64::from(MAX_UDP_IDLE_SECS) + STACK_MARGIN)).with_tcp_config(tcp);
				let tunnel = Arc::new(Tunnel::new(tag, Peers {wg: Wg::new(private), via: Vec::new()}, to_stack));
				fresh.push((tunnel.clone(), IpStack::new(stack, PacketDev::new(from_wg, to_wg)), from_stack));
				tunnel
			}
		}).collect();
		// The upstreams: a state for each enabled one, the one it has now where the tag, the link and the device are the same.
		let mut upstreams = Vec::new();
		for (i, written) in config.upstreams.iter().enumerate().filter(|(_, written)| written.on()) {
			let (file, _) = self.upstream_file.as_ref().ok_or_else(|| anyhow!("upstreams[{i}]: upstream `{}` needs the state file of the upstreams, and the node was started without a path for one", written.tag))?;
			let secret: [u8; 16] = URL_SAFE_NO_PAD.decode(written.device_secret.expose()).ok().and_then(|bytes| bytes.try_into().ok()).ok_or_else(|| anyhow!("the config names something it does not define; it was not validated"))?;
			let vault = file.vault(&written.tag, written.link.expose(), Secret::new(written.private_key.expose().0), DeviceSecret::new(secret));
			let state = self.upstreams.get(&written.tag).map(|(_, _, state, _)| state).filter(|state| state.bound() == vault.bound()).cloned().unwrap_or_else(|| UpstreamState::new(&written.tag, vault.id(), vault.bound()));
			upstreams.push((written.effective(), None, state, vault));
		}
		let mut plan = Plan::new(config, (shared.now)(), &old, tunnels, &upstreams.iter().map(|(_, _, state, _)| state.clone()).collect::<Vec<_>>())?;
		for (written, reach, ..) in &mut upstreams {*reach = written.via.as_deref().map(|tag| upstream::reach(&config.outbounds, &plan.latency, &plan.hops, tag).ok_or_else(|| anyhow!("the config names something it does not define; it was not validated"))).transpose()?}
		for (tunnel, ..) in &fresh {
			let (Some(at), mut peers) = (plan.inbound_of(tunnel), tunnel.lock()) else {continue};
			for device in plan.devices.iter().filter(|device| device.inbounds.contains(&at)) {peers.add(device.public_key, device.preshared_key)}
			for link in plan.links.iter().filter(|link| link.inbound == at && link.denied.is_none()) {peers.add(link.key, None)}
		}
		// "`veilway run` refuses to start a config that has an obfuscated transport" without a replay file it can write and lock. The memory is taken once, by the first config that needs it, and kept for as long as the process runs.
		if let (Some(i), None) = (plan.inbounds.iter().position(|inbound| inbound.native.is_some()), shared.replay.get()) {
			let path = shared.replay_path.clone().ok_or_else(|| anyhow!("inbounds[{i}].transports: inbound `{}` has an obfuscated transport, which needs a replay file, and the node was started without a path for one", plan.inbounds[i].tag))?;
			let (capacity, now) = (config.replay.cache(), replay::seconds((shared.now)()));
			let guard = Arc::new(tokio::task::spawn_blocking(move || replay::Guard::open(&path, capacity, now)).await.map_err(|e| anyhow!("the replay file could not be opened: {e}"))??);
			if shared.replay.set(guard.clone()).is_ok() {tokio::spawn(guard.run(shared.now));}
		}
		let (mut udp, mut relays, mut acceptors, mut loopbacks) = (Vec::new(), Vec::<(SocketAddr, TcpListener)>::new(), HashMap::new(), Vec::<(Arc<Tunnel>, SocketAddr, Arc<UdpSocket>)>::new());
		let (mut listeners, mut streams, mut certified) = (Vec::<(SocketAddr, TcpListener)>::new(), HashMap::<SocketAddr, (Option<ws::Acceptor>, SocketAddr)>::new(), Vec::new());
		let (mut borrowed, mut sites) = (Vec::<(SocketAddr, TcpListener)>::new(), HashMap::<SocketAddr, (SocketAddr, Option<(String, Arc<Outbound>)>)>::new());
		for (i, inbound) in plan.inbounds.iter().enumerate() {
			for (t, transport) in inbound.transports.iter().enumerate().filter(|(_, transport)| transport.on()) {
				match transport {
					Transport::Udp {listen, ..} | Transport::UdpObfs {listen, ..} if !self.udp.contains_key(&listen.0) => udp.push((listen.0, Arc::new(bind(listen.0, Type::DGRAM, self.released.contains(&listen.0)).await.and_then(|socket| UdpSocket::from_std(socket.into())).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].listen: inbound `{}` cannot listen there over udp: {}", inbound.tag, e.kind()))?))),
					Transport::Udp {..} | Transport::UdpObfs {..} => {}
					Transport::Tls {listen, decoy, ..} | Transport::WsNative {listen, decoy, ..} | Transport::WsPlain {listen, decoy, ..} | Transport::Fronted {listen, decoy, ..} | Transport::FrontedShaped {listen, decoy, ..} => {
						if !self.tls.contains_key(&listen.0) && !listeners.iter().any(|(addr, _)| *addr == listen.0) {
							listeners.push((listen.0, bind(listen.0, Type::STREAM, self.released.contains(&listen.0)).await.and_then(|socket| {
								socket.listen(1024)?;
								TcpListener::from_std(socket.into())
							}).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].listen: inbound `{}` cannot listen there over tcp: {}", inbound.tag, e.kind()))?));
						}
						// Once for each address, on every reload: the certificate is read again, and the name of the decoy origin is resolved again ("resolved once per reload"). Transports that share an address have the same files and the same origin.
						if streams.contains_key(&listen.0) {continue}
						// "A native `ws` or `fronted` listener never ends TLS itself. A listener where the node ends TLS is `tls`."
						let acceptor = match transport {
							Transport::Tls {tls: Certificate::Files(tls), ..} => {
								let files = TlsFiles {cert: self.dir.join(&tls.cert), key: self.dir.join(&tls.key)};
								#[cfg(unix)]
								if std::fs::metadata(&files.key).is_ok_and(|meta| std::os::unix::fs::MetadataExt::mode(&meta) & 0o077 != 0) {tracing::warn!("inbounds[{i}].transports[{t}].tls.key: group or others can read the key file of inbound {}. Whoever reads it can answer for the node's name: restrict it (chmod 600)", inbound.tag)}
								Some(ws::acceptor(&files).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].tls: inbound `{}` cannot load its certificate: {e:#}", inbound.tag))?)
							}
							// The key is made on the first start and kept. The certificate is read again on every reload, and made anew when it is due.
							Transport::Tls {tls: Certificate::SelfSigned(own), ..} => {
								let (made, fresh) = certificate::ensure(certificate::files(&self.dir, &certificate::stem(&inbound.tag, &inbound.transports, t)), listen.0, own.name.as_deref(), (shared.now)()).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].tls.self_signed: inbound `{}` has no self-signed certificate: {e:#}", inbound.tag))?;
								let acceptor = ws::acceptor(&made.files).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].tls.self_signed: inbound `{}` cannot load the certificate the node made: {e:#}", inbound.tag))?;
								certified.push((made, fresh));
								Some(acceptor)
							}
							_ => None,
						};
						let acceptor = acceptor.map(|acceptor| if matches!(transport, Transport::Tls {http2: Some(Http2::On), ..}) {stream::offering_h2(&acceptor)} else {acceptor});
						let origin = match &decoy.origin.0.host {
							Named::Ip(ip) => SocketAddr::new(*ip, decoy.origin.0.port),
							Named::Name(name) => tokio::time::timeout(RESOLVE, lookup_host((name.as_str(), decoy.origin.0.port))).await.ok().and_then(Result::ok).and_then(|mut found| found.next()).ok_or_else(|| anyhow!("inbounds[{i}].transports[{t}].decoy.origin: the name of the decoy origin of inbound `{}` does not resolve", inbound.tag))?,
						};
						// "Validation refuses an origin whose address and port equal a listen address of the node, since requests would loop", and this is where a name is held to it.
						if plan.inbounds.iter().flat_map(|inbound| &inbound.transports).any(|other| !other.datagram() && loops(other.listen(), origin)) {anyhow::bail!("inbounds[{i}].transports[{t}].decoy.origin: the decoy origin of inbound `{}` resolves to an address and port the node itself listens on, so every request of a stranger would come back to the node", inbound.tag)}
						streams.insert(listen.0, (acceptor, origin));
					}
					Transport::FakeTls {listen, site, ..} => {
						if !self.faketls.contains_key(&listen.0) && !borrowed.iter().any(|(addr, _)| *addr == listen.0) {
							borrowed.push((listen.0, bind(listen.0, Type::STREAM, self.released.contains(&listen.0)).await.and_then(|socket| {
								socket.listen(1024)?;
								TcpListener::from_std(socket.into())
							}).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].listen: inbound `{}` cannot listen there over tcp: {}", inbound.tag, e.kind()))?));
						}
						// Once for each address, on every reload: "The name is resolved once per reload."
						let address = match site.address {
							Some(address) => address.0,
							None => tokio::time::timeout(RESOLVE, lookup_host((site.host.as_str(), site.port.unwrap_or(DEFAULT_SITE_PORT)))).await.ok().and_then(Result::ok).and_then(|mut found| found.next()).ok_or_else(|| anyhow!("inbounds[{i}].transports[{t}].site.host: the name of the site of inbound `{}` does not resolve", inbound.tag))?,
						};
						// A site at an address and port the node itself listens on would send every stranger's connection back to the node.
						if plan.inbounds.iter().flat_map(|inbound| &inbound.transports).any(|other| !other.datagram() && loops(other.listen(), address)) {anyhow::bail!("inbounds[{i}].transports[{t}].site.host: the site of inbound `{}` is an address and port the node itself listens on, so every stranger's connection would come back to the node", inbound.tag)}
						let outbound = site.outbound.as_ref().map(|tag| Outbound::of(&config.outbounds, &plan.latency, &plan.hops, tag).map(|found| (tag.clone(), Arc::new(found))).ok_or_else(|| anyhow!("inbounds[{i}].transports[{t}].site.outbound: inbound `{}` names no outbound `{tag}`", inbound.tag))).transpose()?;
						sites.insert(listen.0, (address, outbound));
					}
					Transport::Ws {listen, tls, ..} => {
						if !self.ws.contains_key(&listen.0) && !relays.iter().any(|(addr, _)| *addr == listen.0) {
							relays.push((listen.0, bind(listen.0, Type::STREAM, self.released.contains(&listen.0)).await.and_then(|socket| {
								socket.listen(1024)?;
								TcpListener::from_std(socket.into())
							}).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].listen: inbound `{}` cannot listen there over tcp: {}", inbound.tag, e.kind()))?));
						}
						// Read again on every reload, once for each address: transports that share one have the same files.
						if !acceptors.contains_key(&listen.0) {
							acceptors.insert(listen.0, tls.as_ref().map(|tls| ws::acceptor(&TlsFiles {cert: self.dir.join(&tls.cert), key: self.dir.join(&tls.key)})).transpose().map_err(|e| anyhow!("inbounds[{i}].transports[{t}].tls: inbound `{}` cannot load its certificate: {e:#}", inbound.tag))?);
						}
						// Every ws transport of an inbound forwards its frames to one private loopback socket of that inbound.
						if !loopbacks.iter().any(|(tunnel, ..)| Arc::ptr_eq(tunnel, &inbound.tunnel)) && !self.tunnels.get(&inbound.tag).is_some_and(|running| Arc::ptr_eq(&running.tunnel, &inbound.tunnel) && running.loopback.is_some()) {
							let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.and_then(|socket| Ok((socket.local_addr()?, socket))).map_err(|e| anyhow!("inbound `{}`: no loopback socket for its ws transports: {}", inbound.tag, e.kind()))?;
							loopbacks.push((inbound.tunnel.clone(), socket.0, Arc::new(socket.1)));
						}
					}
				}
			}
		}
		// Node links page, "Tunnels": one whose entry did not change keeps its listener. One that is new, or changed, binds its address now, or takes the socket of the one it replaces on the same address and protocol.
		let mut forwards = Vec::new();
		for (i, written) in config.tunnels.iter().enumerate().filter(|(_, written)| written.on()) {
			let (written, udp) = (written.effective(), written.protocol == TunnelProtocol::Udp);
			if self.forwards.get(&written.tag).is_some_and(|running| running.config.core() == written.core() && running.links == chain_links(config, &written.exit)) {continue}
			let listen = written.listen.0;
			let bound = match self.forwards.values().find(|running| running.config.listen == written.listen && running.config.protocol == written.protocol) {
				Some(running) => running.bound.clone(),
				None if udp => tunnel::Bound::Udp(Arc::new(bind(listen, Type::DGRAM, self.released.contains(&listen)).await.and_then(|socket| UdpSocket::from_std(socket.into())).map_err(|e| anyhow!("tunnels[{i}].listen: tunnel `{}` cannot listen there over udp: {}", written.tag, e.kind()))?)),
				None => tunnel::Bound::Tcp(Arc::new(bind(listen, Type::STREAM, self.released.contains(&listen)).await.and_then(|socket| {
					socket.listen(1024)?;
					TcpListener::from_std(socket.into())
				}).map_err(|e| anyhow!("tunnels[{i}].listen: tunnel `{}` cannot listen there over tcp: {}", written.tag, e.kind()))?)),
			};
			forwards.push((written, bound));
		}
		// Proxy inbounds: one that did not change keeps its listener and its connections. One that is new, or changed, binds its address now, or takes the socket of the one it replaces on the same address.
		let mut proxies = Vec::new();
		for (i, written) in config.proxies.iter().enumerate().filter(|(_, written)| written.on()) {
			let written = written.effective();
			if self.proxies.get(&written.tag).is_some_and(|running| running.config == written) {continue}
			let listen = written.listen.0;
			let listener = match self.proxies.values().find(|running| running.config.listen == written.listen) {
				Some(running) => running.listener.clone(),
				None => Arc::new(bind(listen, Type::STREAM, self.released.contains(&listen)).await.and_then(|socket| {
					socket.listen(1024)?;
					TcpListener::from_std(socket.into())
				}).map_err(|e| anyhow!("inbounds[{}].listen: inbound `{}` cannot listen there over tcp: {}", config.inbounds.len() + i, written.tag, e.kind()))?),
			};
			proxies.push((written, listener));
		}
		// A missing interface may come later, a PPP or VPN link for one, so it is a warning here and each flow fails until it is there. A system that cannot tie a socket to an interface at all is refused.
		for exit in &plan.exits {
			if let Backend::Netstack {outbound: Outbound::Direct {interface: Some(name), ..}, ..} = &exit.backend {
				if !super::flows::INTERFACES {anyhow::bail!("exit `{}` leaves through an outbound tied to the network interface {name}, which needs Linux or macOS: remove its `interface`, or run the node on Linux", exit.tag)}
				if !super::flows::has_interface(name) {tracing::warn!("exit {}: its outbound is tied to the network interface {name}, which this host does not have now, so its flows fail until it does", exit.tag)}
			}
		}
		// Return traffic finds its interface by the routes of the pools, and two interfaces cannot both have those. Telling them apart takes policy routing, which is not built.
		let wanted = {
			let mut wired = plan.exits.iter().enumerate().filter_map(|(at, exit)| if let Backend::L3 {interface, masquerade} = &exit.backend {Some((at, exit, interface, masquerade))} else {None});
			let (first, second) = (wired.next(), wired.next());
			if let (Some((_, first, ..)), Some((_, second, ..))) = (first, second) {anyhow::bail!("exits `{}` and `{}` both have an l3 backend: this build runs one l3 exit per node, so remove one of them", first.tag, second.tag)}
			first.map(|(at, exit, interface, masquerade)| {
				// The links that may leave through the exit count into it: "the link's `mtu` counts into the MTU of an `l3` exit's interface, so that the kernel does not hand back packets the link cannot carry". The entry's link address of a link this node dials lies in no pool of this node, so it is routed to the interface by itself.
				let using: Vec<&plan::Link> = plan.links.iter().filter(|link| link.user.is_some_and(|user| plan.users[user].entitled.as_ref().is_none_or(|list| list.contains(&at)))).collect();
				let mut pools: Vec<IpNet> = plan.pools.iter().map(|(pool, _)| pool.trunc()).chain(using.iter().filter(|link| !link.listener).flat_map(|link| link.addresses.iter().map(|address| IpNet::from(*address)))).collect();
				pools.sort();
				pools.dedup();
				(at, l3::Wanted {tag: exit.tag.clone(), interface: interface.clone(), masquerade: *masquerade, pools, mtu: plan.inbounds.iter().take(plan.listening).map(|inbound| inbound.mtu).chain(using.iter().map(|link| link.mtu)).min().unwrap_or(DEFAULT_MTU)})
			})
		};
		for exit in &plan.exits {
			if let Backend::Netstack {icmp_echo: Fallback::Direct, ..} = &exit.backend {icmp::ping_socket(true).map_err(|e| anyhow!("exit `{}`: \"icmp_echo\": \"direct\" needs unprivileged ping sockets, which this system does not give the node ({}); on Linux the node's group has to be inside net.ipv4.ping_group_range", exit.tag, e.kind()))?;}
		}
		let mut staged = None;
		if let Some((at, wanted)) = wanted {
			// An exit that is down and wanted as it is does not stand in the way of the reload, which may be the one that cuts a user off: it stays down and tries now, whatever wait it was in.
			let runs = self.l3.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|wired| wired.wanted == wanted).map(|wired| {
				if wired.port.health.down.lock().unwrap_or_else(|e| e.into_inner()).is_some() {wired.running.retry_now()}
				wired.port.clone()
			});
			if let Some(port) = runs {plan.l3 = Some((at, port))} else {
				// The pools can be routed to one interface only, so an interface that runs and is not the one wanted goes first, and with it whatever try to bring it up was waiting. This is the last thing that can fail,
				// and when it does that interface is brought back on the queue the running config still writes to. Should that fail as well, the exit of the running config is down and tried again until it is up, see `l3::Running::start`.
				let previous = self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();
				let previous = match previous {
					Some(Wired {wanted, port, queue, running}) => {
						running.close().await;
						Some((wanted, port, queue))
					}
					None => None,
				};
				let (to, from) = mpsc::channel(QUEUE);
				let (port, queue) = (l3::Port {to, mtu: wanted.mtu, health: Arc::default()}, Arc::new(tokio::sync::Mutex::new(from)));
				match l3::Running::start(shared, &wanted, queue.clone(), port.health.clone(), false) {
					Ok(running) => {
						plan.l3 = Some((at, port.clone()));
						staged = Some(Wired {wanted, port, queue, running});
					}
					Err(e) => {
						if let Some((wanted, port, queue)) = previous {
							match l3::Running::start(shared, &wanted, queue.clone(), port.health.clone(), true) {
								Ok(running) => *self.l3.lock().unwrap_or_else(|e| e.into_inner()) = Some(Wired {wanted, port, queue, running}),
								// Only where no l3 exit can run at all, and there none was running.
								Err(again) => tracing::error!("exit {}: its interface was closed for a reload that then failed and cannot be brought back: {again:#}", wanted.tag),
							}
						}
						return Err(e);
					}
				}
			}
		}
		Ok(Staged {plan, config: config.clone(), udp, ws: relays, acceptors, tls: listeners, streams, borrowed, sites, certified, tunnels: fresh, loopbacks, forwards, proxies, l3: staged, upstreams})
	}

	/// Puts what `prepare` staged in force: the plan in one step, see `switch`, then the tasks and listeners that go with it. What the config no longer names is stopped and given back to the host.
	pub fn commit(&mut self, shared: &Arc<Shared>, staged: Staged) {
		let Staged {plan, config, udp, ws: relays, mut acceptors, tls: listeners, streams, borrowed, sites, certified, tunnels, loopbacks, forwards, proxies, l3, upstreams} = staged;
		// A reload of the bytes that already run stages the running config itself. With no tunnel and no interface to start there is nothing to switch to:
		// the plan in force stays, no flow is judged again, and all that follows here is the certificates that were read again.
		let same = tunnels.is_empty() && l3.is_none() && self.config.as_ref().is_some_and(|running| Arc::ptr_eq(running, &config));
		let (old, plan) = if same {(shared.plan(), shared.plan())} else {self.switch(shared, plan, true)};
		self.config = Some(config);
		// Dropping the interface of an exit that is gone takes its routes and its firewall table with it.
		if plan.l3.is_none() || l3.is_some() {*self.l3.lock().unwrap_or_else(|e| e.into_inner()) = l3}
		for (tunnel, stack, from_stack) in tunnels {
			let (public, peers) = {
				let peers = tunnel.lock();
				(peers.wg.public_key(), peers.wg.peers().count())
			};
			tracing::info!("inbound {}: tunnel up, public key {}, {peers} peer(s)", tunnel.tag, veilway_wg::encode_key(&public));
			let tasks = inbound::serve(shared, &tunnel, stack, from_stack).into_iter().map(Task).collect();
			self.tunnels.insert(tunnel.tag.clone(), Running {tunnel, _tasks: tasks, loopback: None});
		}
		self.tunnels.retain(|tag, _| plan.inbounds.iter().any(|inbound| inbound.tag == *tag));
		self.shapes = plan.links.iter().filter(|link| link.dialled.is_some()).map(|link| (plan.inbounds[link.inbound].tag.clone(), (plan.inbounds[link.inbound].private_key, link.key, link.mtu))).collect();
		// A link this node dials is dialled while it is enabled and not cut off. One that is the same link through the same tunnel keeps its task and its session, and any other task ends here, with its session.
		let mut diallers = std::mem::take(&mut self.diallers);
		for link in plan.links.iter().filter(|link| link.denied.is_none() && link.dialled.is_some()) {
			let (Some(dialled), tunnel) = (&link.dialled, &plan.inbounds[link.inbound].tunnel) else {continue};
			let shape = (link.id, link.key, link.identity, link.secret, link.mtu, veilway_transport::choice::digest(&dialled.transports), dialled.via.clone());
			let kept = diallers.remove(&link.tag).filter(|(_, _, was, of)| Arc::ptr_eq(was, tunnel) && *of == shape);
			let running = kept.unwrap_or_else(|| {
				tracing::info!("link {}: dialling the other node, over {} transport(s) in its order", link.tag, dialled.transports.len());
				let (dialler, task) = link::dial(shared, tunnel.clone(), link.tag.clone(), dialled.clone(), link.state.clone());
				(dialler, Task(task), tunnel.clone(), shape)
			});
			self.diallers.insert(link.tag.clone(), running);
		}
		for tag in diallers.keys() {tracing::info!("link {tag}: no longer dialled")}
		// An upstream runs while it is enabled. One that is the same upstream with the same state keeps its task and its tunnel, and any other task ends here, with its session. The entry of an upstream that is gone leaves the state file, so that its transport secrets do not stay in it.
		let mut running = std::mem::take(&mut self.upstreams);
		if let Some((file, hooks)) = &self.upstream_file {
			let kept: Vec<(String, [u8; 32])> = upstreams.iter().map(|(written, _, state, _)| (written.tag.clone(), state.bound())).collect();
			self.left.clear();
			for (written, reach, state, vault) in upstreams {
				if vault.left() {
					state.down("the operator removed this device from the provider: remove the upstream from the config");
					self.left.insert(written.tag.clone(), (written, reach, state));
					continue;
				}
				// Only `exit` may differ for a task to be kept: the running upstream is asked for the other exit and the tunnel stays.
				let before = running.remove(&written.tag);
				let replaced = before.as_ref().is_some_and(|(_, _, was_state, _)| Arc::ptr_eq(was_state, &state));
				let kept = before.filter(|(was, was_reach, was_state, _)| Upstream {exit: written.exit.clone(), ..was.clone()} == written && *was_reach == reach && Arc::ptr_eq(was_state, &state));
				if kept.as_ref().is_some_and(|(was, ..)| was.exit != written.exit) {state.want(written.exit.clone())}
				let task = kept.map(|(.., task)| task).unwrap_or_else(|| {
					tracing::info!("upstream {}: running the provider's subscription as the carrier of an exit", written.tag);
					// The tunnel of the task that ended is gone: nothing is carried until the new one says so.
					if replaced {state.down("the config of the upstream changed, so its tunnel is made again")}
					Task(upstream::run(shared, written.clone(), reach.clone(), state.clone(), vault, hooks.clone()))
				});
				self.upstreams.insert(written.tag.clone(), (written, reach, state, task));
			}
			if let Err(error) = file.retain(&kept.iter().map(|(tag, bound)| (tag.as_str(), *bound)).collect::<Vec<_>>()) {tracing::warn!("the state file of the upstreams could not be cleaned of the upstreams that are gone: {error}")}
		}
		for tag in running.keys() {tracing::info!("upstream {tag}: no longer run")}
		for (tunnel, addr, socket) in loopbacks {
			if let Some(running) = self.tunnels.get_mut(&tunnel.tag) {running.loopback = Some((addr, socket.clone(), Task(inbound::read(shared, tunnel, socket, Over::Ws))))}
		}
		// For each UDP address: its tunnel, the session pool of a `udp-obfs` transport, and whether what leaves it must never be fragmented, with the inbound to say so of.
		let (mut wanted, mut routes): (HashMap<SocketAddr, (&Arc<Tunnel>, Option<usize>, bool, &str)>, HashMap<SocketAddr, Vec<(String, Option<Tls>, Arc<Tunnel>, u64)>>) = Default::default();
		for inbound in &plan.inbounds {
			for transport in inbound.transports.iter().filter(|transport| transport.on()) {
				match transport {
					Transport::Udp {listen, ..} => drop(wanted.insert(listen.0, (&inbound.tunnel, None, inbound.veilway, inbound.tag.as_str()))),
					Transport::UdpObfs {listen, limits, ..} => drop(wanted.insert(listen.0, (&inbound.tunnel, Some(limits.and_then(|limits| limits.sessions).unwrap_or(DEFAULT_SESSIONS) as usize), true, inbound.tag.as_str()))),
					Transport::Ws {listen, path, tls, ..} => {
						// A transport that is as it was keeps its number, and with the number the connections it has. Any other is a new route.
						let id = self.ws.get(&listen.0).and_then(|relay| relay.routes.iter().find(|(was, files, tunnel, _)| was == path && files == tls && Arc::ptr_eq(tunnel, &inbound.tunnel))).map(|(.., id)| *id).unwrap_or_else(|| {
							self.routes += 1;
							self.routes
						});
						routes.entry(listen.0).or_default().push((path.clone(), tls.clone(), inbound.tunnel.clone(), id));
					}
					Transport::Tls {..} | Transport::WsNative {..} | Transport::WsPlain {..} | Transport::Fronted {..} | Transport::FrontedShaped {..} | Transport::FakeTls {..} => {}
				}
			}
		}
		// What each stream listener serves from here on: the certificate and the origin as `prepare` found them, and one route for each `tls`, native `ws` or `fronted` transport on its address. Transports that share an address have one decoy, one list of proxies and one set of pools, which the first of them gives.
		let mut serving: HashMap<SocketAddr, stream::Served> = HashMap::new();
		for (inbound, written) in plan.inbounds.iter().zip(self.config.iter().flat_map(|config| &config.inbounds)) {
			for transport in inbound.transports.iter().filter(|transport| transport.on()) {
				let (Some(decoy), Some((acceptor, origin)), cookie) = (transport.decoy(), streams.get(&transport.listen()), written.upgrade_cookie.clone().unwrap_or_default()) else {continue};
				let (route, limits) = match transport {
					Transport::Tls {path, limits, ..} => (stream::Route::tls(path.clone(), inbound.tunnel.clone(), cookie, written.upgrade_headers(true)), *limits),
					Transport::WsNative {path, limits, ..} => (stream::Route::ws(path.clone(), inbound.tunnel.clone(), cookie, written.upgrade_headers(false)), *limits),
					Transport::WsPlain {path, limits, transport_keys, ..} => (stream::Route::ws_plain(path.clone(), inbound.tunnel.clone(), cookie, written.upgrade_headers(false), transport_keys.iter().map(|key| key.0).collect()), *limits),
					Transport::Fronted {path, limits, ..} => (stream::Route::fronted(path.clone(), inbound.tunnel.clone()), *limits),
					Transport::FrontedShaped {path, limits, shape, ..} => match shape.resolve() {
						Ok(shape) => (stream::Route::fronted_shaped(path.clone(), inbound.tunnel.clone(), Arc::new(shape)), *limits),
						Err(_) => continue,
					},
					_ => continue,
				};
				serving.entry(transport.listen()).or_insert_with(|| stream::Served {acceptor: acceptor.clone(), routes: Vec::new(), origin: stream::Origin::Tcp(*origin), proxy: decoy.proxy_protocol == Some(true), host: decoy.origin.host(), pools: stream::Pools::of(limits), h2: matches!(transport, Transport::Tls {http2: Some(Http2::On), ..}), front: transport.proxied().map(|proxied| stream::Front::of(proxied.trusted.iter().map(|proxy| proxy.0).collect(), proxied.header.map(str::to_string), proxied.limits, plan.inbounds.iter().flat_map(|other| &other.transports).any(|other| other.on() && other.listen() == transport.listen() && other.proxied().is_some_and(|other| other.shape.is_some_and(|shape| shape.down.mode == crate::config::ShapeMode::Sse)))))}).routes.push(route);
			}
		}
		// What each `faketls` listener serves from here on: the site, the names a hello may carry, the key of the transport and the limits of the transport.
		let mut borrowing: HashMap<SocketAddr, faketls::Served> = HashMap::new();
		for inbound in &plan.inbounds {
			for transport in inbound.transports.iter().filter(|transport| transport.on()) {
				let (Transport::FakeTls {listen, site, transport_key, limits, ..}, Some((address, outbound))) = (transport, sites.get(&transport.listen())) else {continue};
				borrowing.insert(listen.0, faketls::Served {tunnel: inbound.tunnel.clone(), key: transport_key.0, host: site.host.clone(), names: std::iter::once(&site.host).chain(site.names.iter().flatten()).map(|name| name.as_bytes().to_vec()).collect(), site: *address, outbound: outbound.clone(), relayed: limits.and_then(|limits| limits.relayed).unwrap_or(DEFAULT_SITE_RELAYED) as usize, rate: limits.and_then(|limits| limits.site_rate).unwrap_or(DEFAULT_SITE_RATE)});
			}
		}
		self.released = self.udp.keys().filter(|addr| !wanted.contains_key(addr)).chain(self.ws.keys().filter(|addr| !routes.contains_key(addr))).chain(self.tls.keys().filter(|addr| !serving.contains_key(addr))).chain(self.faketls.keys().filter(|addr| !borrowing.contains_key(addr))).copied().collect();
		// "A tunnel whose entry did not change keeps its connections. One that changed or went away closes its listener and its connections." The socket of a changed tunnel that keeps its address is handed on, so its address is not given back.
		let named: Vec<Forwarded> = self.config.iter().flat_map(|config| &config.tunnels).filter(|written| written.on()).map(Forwarded::effective).collect();
		let (mut stopped, current) = (Vec::new(), self.config.clone());
		self.forwards.retain(|tag, running| {
			let kept = named.iter().any(|written| written.core() == running.config.core() && current.as_ref().is_some_and(|config| chain_links(config, &written.exit) == running.links));
			if !kept {stopped.push((tag.clone(), running.config.listen.0))}
			kept
		});
		// A tunnel that only changed who may connect or how many is told, and closes what the change leaves out.
		for written in &named {
			if let Some(running) = self.forwards.get_mut(&written.tag).filter(|running| running.config != *written) {
				running.state.retune(written);
				running.config = written.clone();
			}
		}
		for (written, bound) in forwards {
			tracing::info!("tunnel {}: {} on {} to {} through exit {}, at most {} at once", written.tag, if written.protocol == TunnelProtocol::Udp {"udp"} else {"tcp"}, written.listen.0, plan.show(written.target.0), written.exit, written.limit());
			let state = Arc::new(tunnel::State::new(&written));
			self.forwards.insert(written.tag.clone(), Forward {links: current.as_ref().map(|config| chain_links(config, &written.exit)).unwrap_or_default(), config: written.clone(), state: state.clone(), bound: bound.clone(), _task: Task(tunnel::serve(shared, written, bound, state))});
		}
		for (tag, listen) in stopped {
			if !self.forwards.values().any(|running| running.config.listen.0 == listen) {self.released.insert(listen);}
			if !self.forwards.contains_key(&tag) {tracing::info!("tunnel {tag}: closed, with every connection it had")}
		}
		// The same for a proxy inbound: one that is as it was keeps its connections, and one that changed or went away closes its listener task and with it every connection. The socket of a changed one that keeps its address is handed on.
		let named: Vec<ProxyInbound> = self.config.iter().flat_map(|config| &config.proxies).filter(|written| written.on()).map(ProxyInbound::effective).collect();
		let mut stopped = Vec::new();
		self.proxies.retain(|tag, running| {
			let kept = named.iter().any(|written| *written == running.config);
			if !kept {stopped.push((tag.clone(), running.config.listen.0))}
			kept
		});
		for (written, listener) in proxies {
			let (state, may) = (Arc::new(proxy::State::default()), plan.proxies.get(&written.tag).map_or(0, |may| may.iter().filter(|may| **may).count()));
			tracing::info!("inbound {}: {} on {}, {} user(s) may log in, at most {} connections ({} for one source){}", written.tag, match written.kind {crate::config::ProxyType::Socks5 => "socks5", crate::config::ProxyType::Http => "http", crate::config::ProxyType::Mixed => "mixed"}, written.listen.0, may, written.connections(), written.per_source(), if written.kind == crate::config::ProxyType::Http {String::new()} else {format!(", udp {}", if written.udp() {"on"} else {"off"})});
			self.proxies.insert(written.tag.clone(), Proxy {config: written.clone(), listener: listener.clone(), state: state.clone(), _task: Task(proxy::serve(shared, written, listener, state))});
		}
		for (tag, listen) in stopped {
			if !self.proxies.values().any(|running| running.config.listen.0 == listen) {self.released.insert(listen);}
			if !self.proxies.contains_key(&tag) {tracing::info!("inbound {tag}: closed, with every connection it had")}
		}
		*shared.proxies.lock().unwrap_or_else(|e| e.into_inner()) = self.config.iter().flat_map(|config| &config.proxies).filter_map(|written| self.proxies.get(&written.tag).map(|running| (written.tag.clone(), running.state.clone()))).collect();
		*shared.tunnels.lock().unwrap_or_else(|e| e.into_inner()) = self.config.iter().flat_map(|config| &config.tunnels).filter_map(|written| self.forwards.get(&written.tag).map(|running| (written.tag.clone(), running.state.clone()))).collect();
		// A listener whose address the config still has is told what it serves now, and keeps every session whose transport is as it was. One whose address nobody has any more closes with everything it holds.
		self.tls.retain(|addr, (listener, _)| match serving.remove(addr) {
			Some(served) => {
				listener.serve(served);
				true
			}
			None => {
				listener.close();
				false
			}
		});
		for (addr, socket) in listeners {
			let Some(served) = serving.remove(&addr) else {continue};
			match &served.front {
				None => tracing::info!("stream listener {addr}: tls, {} path(s), at most {} established sessions, {} undecided connections and {} relayed to the decoy origin at {}", served.routes.len(), served.pools.sessions, served.pools.undecided, served.pools.relayed, served.host),
				Some(front) => tracing::info!("stream listener {addr}: behind the operator's web server, {} path(s) of ws and fronted, at most {} established sessions of which {} fronted, {} connections of {} trusted proxies or networks of them, and {} requests of one source waiting for the decoy origin at {}, of {} in all", served.routes.len(), served.pools.sessions, front.fronted, front.connections, front.trusted.len(), front.per_source, served.host, front.waiting()),
			}
			let listener = shared.stream.listen(addr, served);
			self.tls.insert(addr, (listener.clone(), [Task(stream::accept(shared, listener.clone(), socket)), Task(stream::learn(&listener))]));
		}
		// A listener whose address the config still has is told what it serves now, and keeps every session whose transport key is as it was. One whose address nobody has any more closes with everything it holds.
		self.faketls.retain(|addr, (listener, _)| match borrowing.remove(addr) {
			Some(served) => {
				listener.serve(served);
				true
			}
			None => {
				listener.close();
				false
			}
		});
		for (addr, socket) in borrowed {
			let Some(served) = borrowing.remove(&addr) else {continue};
			tracing::info!("faketls listener {addr}: alpha, new and unreviewed. Whoever is not a user is relayed to the site {}{}, at most {} at once and {} new connections a second to it, and a user gets a handshake the node makes with the sizes and times of the site's own flight, copied live from its answer to the user's hello and from probes of the site (eight now, two seconds apart, then one every 6 h). Nothing of this has been measured against a real site, so this build is Detectable", served.host, served.outbound.as_ref().map_or_else(String::new, |(tag, _)| format!(" through outbound {tag}")), served.relayed, served.rate);
			let listener = shared.faketls.listen(addr, served, Clock::of((shared.now)()).ms);
			self.faketls.insert(addr, (listener.clone(), [Task(faketls::probing(shared, &listener)), Task(faketls::accept(shared, listener.clone(), socket))]));
		}
		// The pin is said at every start and reload: it is what the operator copies into profiles, and the log is where a node without the control API shows it.
		for (made, fresh) in &certified {tracing::info!("stream listener {}: tls with a self-signed certificate the node {}, valid until {}, pin {}", made.listen, if *fresh {"made now"} else {"keeps"}, OffsetDateTime::from_unix_timestamp(made.not_after).map_or_else(|_| made.not_after.to_string(), |at| at.date().to_string()), made.pin_text())}
		*shared.certificates.lock().unwrap_or_else(|e| e.into_inner()) = certified.into_iter().map(|(made, _)| made).collect();
		for (addr, socket) in udp {self.udp.insert(addr, (socket, None));}
		// A socket is read for the tunnel and the transport that have its address now. One whose address nobody has any more is closed, and so is its reader. A `udp-obfs` listener that keeps its tunnel keeps its sessions.
		self.udp.retain(|addr, (socket, reader)| match wanted.get(addr) {
			Some((tunnel, pool, whole, tag)) => {
				let fresh = reader.is_none();
				match (pool, reader.as_ref().map(|(_, reader)| reader)) {
					(None, Some(Reader::Plain(of))) if Arc::ptr_eq(of, tunnel) => {}
					(Some(pool), Some(Reader::Obfs(listener))) if Arc::ptr_eq(&listener.tunnel, tunnel) => listener.resize(*pool),
					(None, _) => *reader = Some((Task(inbound::read(shared, (*tunnel).clone(), socket.clone(), Over::Udp)), Reader::Plain((*tunnel).clone()))),
					(Some(pool), _) => {
						let listener = shared.obfs.listen((*tunnel).clone(), *pool);
						tracing::info!("inbound {tag}: udp-obfs on {addr}, at most {pool} established sessions");
						*reader = Some((Task(obfs::read(shared, listener.clone(), socket.clone())), Reader::Obfs(listener)));
					}
				}
				if let Err(e) = fragmenting(socket, addr.is_ipv6(), *whole) {
					if fresh {tracing::warn!("inbound {tag}: fragmentation of what leaves {addr} could not be prohibited ({}), so a packet that does not fit the path may be fragmented and an MTU probe may be confirmed over a path that fragments it", e.kind())}
				}
				true
			}
			None => false,
		});
		if let Some(config) = &self.config {shared.limits.per_source(config.replay.per_source())}
		if let Some((replay, config)) = shared.replay.get().zip(self.config.as_ref()).filter(|(replay, config)| replay.capacity() != config.replay.cache()) {tracing::warn!("replay.cache: the replay memory was started with room for {} proofs and the config now says {}. It keeps what it was started with until the node starts again", replay.capacity(), config.replay.cache())}
		for running in self.tunnels.values_mut() {
			if !routes.values().flatten().any(|(.., tunnel, _)| Arc::ptr_eq(tunnel, &running.tunnel)) {running.loopback = None}
		}
		for (addr, listener) in relays {
			let (served, watching) = watch::channel(Arc::new(ws::Served {acceptor: None, routes: Vec::new()}));
			tokio::spawn(ws::relay_served(listener, watching, ws::MAX_CONNS, shared.relays.clone()));
			self.ws.insert(addr, Relay {served, routes: Vec::new()});
		}
		// A listener is told what to serve through its `served`, and when that is dropped it closes with every connection it has.
		self.ws.retain(|addr, _| routes.contains_key(addr));
		for (addr, list) in routes {
			let Some(relay) = self.ws.get_mut(&addr) else {continue};
			let serving = list.iter().filter_map(|(path, _, tunnel, id)| Some(ws::Route {path: path.clone(), target: self.tunnels.get(&tunnel.tag)?.loopback.as_ref()?.0, id: *id})).collect();
			relay.served.send_replace(Arc::new(ws::Served {acceptor: acceptors.remove(&addr).flatten(), routes: serving}));
			relay.routes = list;
		}
		for exit in plan.exits.iter().filter(|exit| !old.exits.iter().any(|was| was.tag == exit.tag)) {
			match &exit.backend {
				Backend::Netstack {outbound: Outbound::Socks5(_), ..} => tracing::info!("exit {}: netstack through a socks5 proxy", exit.tag),
				Backend::Netstack {..} => tracing::info!("exit {}: netstack, direct from this node", exit.tag),
				Backend::L3 {masquerade, ..} => if !masquerade && plan.hijack {tracing::warn!("exit {}: l3 without masquerade carries no query of the node's resolver, so dns fails for flows routed to it unless a rule sends the dns servers on port 53 to another exit", exit.tag)},
				Backend::Block => tracing::info!("exit {}: block", exit.tag),
				Backend::Chain {links} => tracing::info!("exit {}: chain, leaves from another node through {} link(s)", exit.tag, links.len()),
			}
			if matches!(exit.backend, Backend::Netstack {icmp_echo: Fallback::Direct, ..}) && plan.pools.iter().any(|(pool, _)| pool.addr().is_ipv6()) && icmp::ping_socket(false).is_err() {tracing::warn!("exit {}: this system gives the node no ping socket for ipv6, so ipv6 pings through the exit get no answer", exit.tag)}
		}
	}

	/// Makes every self-signed certificate that is due anew with its key, which needs no new pin, and has its listener answer with it from the next connection on. A key that is gone or changed stops the renewal, and so does anything else that fails: it is tried again an hour later, and the listener keeps the certificate it has. The list is not held while files are read and written.
	pub fn renew(&self, shared: &Arc<Shared>) {
		let now = (shared.now)();
		let due: Vec<certificate::Made> = shared.certificates.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|made| made.due(now.unix_timestamp())).cloned().collect();
		for made in due {
			let result = certificate::renew(&made, now).and_then(|renewed| Ok((ws::acceptor(&renewed.files)?, renewed)));
			let mut held = shared.certificates.lock().unwrap_or_else(|e| e.into_inner());
			let Some(slot) = held.iter_mut().find(|slot| slot.listen == made.listen && slot.files.key == made.files.key) else {continue};
			match result {
				Ok((acceptor, renewed)) => {
					if let Some((listener, _)) = self.tls.get(&made.listen) {listener.certify(acceptor)}
					tracing::info!("stream listener {}: its self-signed certificate was made anew with the same key, valid until {}, pin {}", made.listen, OffsetDateTime::from_unix_timestamp(renewed.not_after).map_or_else(|_| renewed.not_after.to_string(), |at| at.date().to_string()), renewed.pin_text());
					*slot = renewed;
				}
				Err(e) => {
					slot.retry = now.unix_timestamp() + certificate::RETRY;
					tracing::warn!("stream listener {}: its self-signed certificate is due and could not be made anew: {e:#}. It is tried again in an hour, and the listener serves the one it has until then", made.listen);
				}
			}
		}
	}

	/// Cuts off the users whose `expires_at` has passed or whose quota was spent since the plan in force was made, and lets those in again whose quota period has started over:
	/// the config that runs is compiled again at the present time, with the counts as they are now, and switched to.
	pub fn expire(&mut self, shared: &Arc<Shared>) {
		let (Some(config), old) = (&self.config, shared.plan()) else {return};
		match Plan::new(config, (shared.now)(), &old, old.inbounds.iter().map(|inbound| inbound.tunnel.clone()).collect(), &old.upstreams()) {
			Ok(mut plan) => {
				plan.l3 = old.l3.clone();
				self.switch(shared, plan, false);
			}
			Err(e) => tracing::error!("the running config could not be compiled again to cut off the users that expired or ran out of quota: {e:#}"),
		}
	}

	/// Puts `plan` in force in one step and returns the plan it replaced and the new one. With the flow table locked from start to end:
	/// every live flow is decided again and ends unless the new plan decides the same for it through an exit that is still the same exit, the device of each flow that ends is told once (a TCP reset, or an ICMP error for UDP),
	/// the devices that are cut off lose their session keys, and the plan is swapped. After that their user's DNS memory is cleared and each is logged.
	/// This is the one cut-off path: a device is cut off when the new plan no longer has it as it was, whatever the reason. A user who runs out of quota comes through here too, denied by `Plan::new` like one who expired, see `plan::Denied`.
	/// The state file is written right after a switch that cut a user off for their quota or left a user's name behind, so neither waits for the next write.
	/// `reloaded` says the plan may come from another config than the one before it. A plan that only cuts users off or lets them in again changes nothing the control channel told anybody who is still there.
	fn switch(&self, shared: &Arc<Shared>, plan: Plan, reloaded: bool) -> (Arc<Plan>, Arc<Plan>) {
		let (old, plan) = (shared.plan(), Arc::new(plan));
		let users: HashMap<&str, &User> = plan.users.iter().map(|user| (user.name.as_str(), user)).collect();
		// A device is the same device while it has the same key, the same user, the same addresses and the same preshared key. Any other device of the old plan is cut off.
		// Next to the reason stands what the control channel says of it in a `bye` ("Being cut off"). A device whose addresses or preshared key changed is none of the four cases a `bye` has, so it is told nothing and finds out as it did before.
		let cut: HashMap<[u8; 32], (&str, Option<ByeReason>)> = old.devices.iter().filter_map(|was| {
			let name = old.users[was.user].name.as_str();
			// The record of a link is the same while its link is: same key, same addresses, not cut off.
			if was.link.is_some() {return plan.by_key.get(&was.public_key).map(|at| &plan.devices[*at]).filter(|is| is.link.is_some() && is.addresses == was.addresses).is_none().then_some((was.public_key, ("its link was removed, changed or cut off", None)))}
			Some((was.public_key, match plan.by_key.get(&was.public_key).map(|at| &plan.devices[*at]) {
				Some(is) if plan.users[is.user].name != name => ("its key was given to another user", Some(ByeReason::Disabled)),
				Some(is) if is.addresses != was.addresses => ("its addresses changed", None),
				Some(is) if is.preshared_key != was.preshared_key => ("its preshared key changed", None),
				Some(_) => return None,
				None => match users.get(name).map(|user| user.denied) {
					None => ("the user was removed", Some(ByeReason::Disabled)),
					Some(Some(Denied::Disabled)) => ("the user was disabled", Some(ByeReason::Disabled)),
					Some(Some(Denied::Expired)) => ("the user expired", Some(ByeReason::Expired)),
					Some(Some(Denied::Quota)) => ("the user ran out of quota", Some(ByeReason::Quota)),
					Some(None) => ("the device was removed", Some(ByeReason::Disabled)),
				},
			}))
		}).collect();
		// Where each exit of the old plan is in the new one, when it is the same exit there: same tag, same backend, same outbound.
		let tags: HashMap<&str, usize> = plan.exits.iter().enumerate().map(|(at, exit)| (exit.tag.as_str(), at)).collect();
		let alike = |was: Fallback, is: Fallback| if let (Fallback::Via(was), Fallback::Via(is)) = (was, is) {old.exits[was].tag == plan.exits[is].tag} else {was == is};
		let exits: Vec<Option<usize>> = old.exits.iter().map(|was| tags.get(was.tag.as_str()).copied().filter(|at| was.outbound == plan.exits[*at].outbound && match (&was.backend, &plan.exits[*at].backend) {
			(Backend::Netstack {outbound, tcp_idle, udp_idle, icmp_echo, udp, other}, Backend::Netstack {outbound: now, tcp_idle: tcp, udp_idle: quiet, icmp_echo: echo, udp: datagrams, other: rest}) => outbound == now && tcp_idle == tcp && udp_idle == quiet && alike(*icmp_echo, *echo) && alike(*udp, *datagrams) && alike(*other, *rest),
			(Backend::L3 {interface, masquerade}, Backend::L3 {interface: now, masquerade: nat}) => interface == now && masquerade == nat,
			(Backend::Block, Backend::Block) => true,
			// A flow stays on its link while the link stays: one whose link is gone from the exit is refused at its next packet, see `chain`.
			(Backend::Chain {..}, Backend::Chain {..}) => true,
			_ => false,
		})).collect();
		let judge = |key: &Key, device: &[u8; 32], user: &str, decision: Decision, names: &[Arc<str>], transport: Option<RuleTransport>| {
			if cut.contains_key(device) {return None}
			// A flow belongs to a user and a device. It lives on only where that device still holds the address it came from, in the tunnel it came through.
			let (is, was) = (plan.by_address.get(&key.src).copied()?, old.by_address.get(&key.src).copied()?);
			let holder = &plan.devices[is.device];
			if holder.public_key != *device || plan.users[holder.user].name != user || !Arc::ptr_eq(&plan.inbounds[is.inbound].tunnel, &old.inbounds[was.inbound].tunnel) {return None}
			match (decision, shared.decide(&plan, is.inbound, is.device, key, names, transport)) {
				(Decision::Deliver, Decision::Deliver) => Some(Decision::Deliver),
				(Decision::Dns, Decision::Dns) => Some(Decision::Dns),
				// A control connection lives on while its inbound is still a `veilway` inbound and its device still has the secret it proved, which is looked at once the plan is in force.
				(Decision::Control, Decision::Control) => Some(Decision::Control),
				(Decision::Exit {exit: was, by}, Decision::Exit {exit, by: now}) if exits.get(was).copied().flatten() == Some(exit) => {
					// What its handler has since made of a TCP or UDP flow (through the proxy, around it, or by way of another exit) stands, for as long as that other exit is the same exit and one of the user's.
					let by = if let By::Via(target) = by {By::Via(exits.get(target).copied().flatten().filter(|target| plan.users[holder.user].entitled.as_ref().is_none_or(|list| list.contains(target)))?)} else {by};
					(key.protocol == Protocol::TCP || key.protocol == Protocol::UDP || by == now).then_some(Decision::Exit {exit, by})
				}
				_ => None,
			}
		};
		let started = Instant::now();
		let (out, pings, ended) = shared.flows.recheck(plan.generation, judge, |ended: Vec<Ended>| {
			let (mut out, mut pings) = (Vec::new(), HashSet::new());
			for flow in &ended {
				if flow.key.protocol == Protocol::ICMP || flow.key.protocol == Protocol::ICMPV6 {pings.insert((flow.key.src, flow.key.dst));}
				let Some(from) = old.by_address.get(&flow.key.src).copied().filter(|from| old.devices[from.device].public_key == flow.device) else {continue};
				let (inbound, device) = (&old.inbounds[from.inbound], &old.devices[from.device]);
				// "It first sends, on every authenticated connection of that device, a last `usage` if the cause is quota, and then `bye` with the reason. It does this on a best effort: the cut-off does not wait for it."
				// The connection's own task could only write it after this switch, when the keys are gone, so it is written here in its place, as the last segment of the connection, see `route::tcp_last`.
				// It is written where the stack stands on the connection, behind everything the stack has sent, whether the device has acknowledged that or not.
				let bye = cut.get(&flow.device).and_then(|(_, reason)| *reason).filter(|_| flow.key.protocol == Protocol::TCP && flow.key.dport == PORT && old.control(from.inbound, flow.key.dst)).zip(device.control.last(&flow.key)).and_then(|(reason, next)| {
					let mut last = Vec::new();
					if reason == ByeReason::Quota {NodeMessage::Usage(control::usage(&old.users[device.user])).encode(&mut last).ok()?}
					NodeMessage::Bye {reason}.encode(&mut last).ok()?;
					route::tcp_last(&flow.key, next, &last)
				});
				// The reset goes out under the session the device still has, which is why this comes before the keys are dropped.
				let packet = bye.clone().or_else(|| farewell(&old, flow).map(|(_, packet)| packet));
				let (Some(packet), mut peers, mut datagrams) = (packet, inbound.tunnel.lock(), Vec::new()) else {continue};
				let Some(peer) = peers.wg.index(&flow.device).filter(|peer| peers.wg.time_since_last_handshake(*peer).is_some()) else {continue};
				let Some(route) = peers.route(peer) else {continue};
				peers.wg.encapsulate(peer, &packet, &mut datagrams);
				// Counted where it is written into the tunnel of a device that has a session, and nowhere before.
				if bye.is_some() {shared.control.counters.byes.fetch_add(1, Ordering::Relaxed);}
				shared.spend(&old.users[old.devices[from.device].user], false, packet.len());
				inbound.traffic.down(packet.len());
				out.extend(datagrams.into_iter().map(|datagram| (inbound.tunnel.clone(), route.clone(), datagram, bye.is_some())));
			}
			for was in old.devices.iter().filter(|was| cut.contains_key(&was.public_key)) {
				let is = plan.by_key.get(&was.public_key).map(|at| &plan.devices[*at]);
				for at in &was.inbounds {
					let tunnel = &old.inbounds[*at].tunnel;
					// A device that stays a peer of this tunnel under the same keys loses its sessions only. Any other is no peer of it from here on, and its handshakes are refused.
					let stays = is.is_some_and(|is| is.preshared_key == was.preshared_key && is.inbounds.iter().any(|at| Arc::ptr_eq(&plan.inbounds[*at].tunnel, tunnel)));
					let mut peers = tunnel.lock();
					if stays {peers.wg.drop_sessions(&was.public_key);} else {peers.wg.remove_peer(&was.public_key);}
				}
			}
			// A device that is no longer in an inbound it was in, because the inbound is not enabled, is no peer of its tunnel: its sessions go and its handshakes are refused.
			for was in old.devices.iter().filter(|was| !cut.contains_key(&was.public_key)) {
				let Some(is) = plan.by_key.get(&was.public_key).map(|at| &plan.devices[*at]) else {continue};
				for at in was.inbounds.iter().filter(|at| !is.inbounds.iter().any(|now| Arc::ptr_eq(&plan.inbounds[*now].tunnel, &old.inbounds[**at].tunnel))) {old.inbounds[*at].tunnel.lock().wg.remove_peer(&was.public_key);}
			}
			for device in &plan.devices {
				for at in &device.inbounds {
					let mut peers = plan.inbounds[*at].tunnel.lock();
					if peers.wg.index(&device.public_key).is_none() {peers.add(device.public_key, device.preshared_key)}
				}
			}
			// A link is a peer while it is the same link through the same tunnel. Any other loses its sessions here: "The sessions and the tunnel are dropped within one second on the node that removed it."
			for was in old.links.iter().filter(|was| was.denied.is_none() && matches!(was.carrier, Carrier::Paired)) {
				let tunnel = &old.inbounds[was.inbound].tunnel;
				let stays = plan.links.iter().any(|is| is.denied.is_none() && matches!(is.carrier, Carrier::Paired) && is.id == was.id && is.key == was.key && is.identity == was.identity && is.secret == was.secret && is.addresses == was.addresses && Arc::ptr_eq(&plan.inbounds[is.inbound].tunnel, tunnel));
				if !stays {
					tunnel.lock().wg.remove_peer(&was.key);
					tracing::info!("link {}: its sessions are dropped: the link was removed, changed or cut off", was.tag);
				}
			}
			for link in plan.links.iter().filter(|link| link.denied.is_none() && matches!(link.carrier, Carrier::Paired)) {
				let mut peers = plan.inbounds[link.inbound].tunnel.lock();
				if peers.wg.index(&link.key).is_none() {peers.add(link.key, None)}
			}
			// `Plan::new` held each count against the period the plan was compiled in without touching it. The plan is in force from here, so this is where a count whose period is over starts over,
			// and where a period the state file has more than one whole period after the node's clock is put right at start.
			let now = (shared.now)().unix_timestamp();
			for user in &plan.users {user.state.roll(&user.name, user.period.map(|period| (plan.starts[period as usize], super::usage::SPANS[period as usize])), now)}
			plan.shown.store(plan.log_destinations, Ordering::Relaxed);
			*shared.plan.write().unwrap_or_else(|e| e.into_inner()) = plan.clone();
			(out, pings, ended.len())
		});
		// The plan is in force by now, which is the order `control::State::recheck` counts on: every exit a device chose is held against the `exits` its user has from here on, and one that is not among them is dropped.
		// The plan before the first one holds what the state file remembered, so this is also where a file that names an exit the user may not use is put right.
		let gone: Vec<(&str, &str, Arc<str>)> = plan.devices.iter().filter(|_| reloaded).filter_map(|device| device.control.recheck(&plan, &plan.users[device.user]).map(|tag| (plan.users[device.user].name.as_str(), device.name.as_str(), tag))).collect();
		shared.control.counters.exits_dropped.fetch_add(gone.len() as u64, Ordering::Relaxed);
		for (user, device, tag) in gone.iter().take(MAX_NAMES_LOGGED) {tracing::info!("user {user} device {device}: its exit selection {tag} is dropped: that is no exit of the user's `exits` any more, so the device leaves through the user's exit");}
		if gone.len() > MAX_NAMES_LOGGED {tracing::info!("{} more devices had their exit selection dropped", gone.len() - MAX_NAMES_LOGGED)}
		// A control connection proved one transport secret. When the config no longer has that secret for the device, the connection ends, like the `udp-obfs` session that was opened with it does below (protocol overview, "Rotation").
		// The WireGuard session of a `udp` transport was opened with no secret, so it stays.
		for (was, is) in old.devices.iter().filter(|was| !cut.contains_key(&was.public_key)).filter_map(|was| plan.by_key.get(&was.public_key).map(|at| (was, &plan.devices[*at]))).filter(|(was, is)| was.secrets != is.secrets) {
			let ended = is.control.revoke(&is.secrets);
			if ended > 0 {tracing::info!("user {} device {}: {ended} control connection(s) ended, the transport secret they proved is no longer in the config", plan.users[is.user].name, was.name)}
		}
		// Every open control connection looks at what it told its device, and sends what this plan changed of it.
		if reloaded {shared.control.plans.send_replace(plan.generation);}
		// Every packet of every user waits while the flow table is locked, so how long that was is always said.
		tracing::info!("a plan was put in force: the flow table was locked for {:?} while every live flow was decided again", started.elapsed());
		// Never waited for: a socket that cannot take a reset right now loses it, like any packet on a full queue. They leave before the sessions of a native transport end below, which is the only way they could reach a device that came over one.
		for (tunnel, route, datagram, control) in &out {route.try_send(tunnel, datagram, *control)}
		// One cut-off path for the native transports too: every `udp-obfs` and every stream session of a device that was cut off above ends here, whatever the reason was, and so does one whose device is no longer in its inbound or whose transport secret the plan no longer has.
		// A device that was cut off lost its WireGuard sessions, and with them the tunnel's memory of the handshakes it has seen. A session that lived on would take a recorded initiation for a new one (threat model G18), so none does.
		// The plan is in force by now, and with it a tag table that no longer holds a removed secret, so no opening packet under it is accepted from here on.
		let revoked = shared.limits.cut(&plan, |device| cut.contains_key(device));
		if revoked > 0 {tracing::info!("{revoked} session(s) of the obfuscated transports ended: their device was cut off, or the config no longer has the transport secret or the transport key they were opened with")}
		// "Validation refuses a config in which two tags of one inbound are equal" is kept here, where the tags are: a tag that another secret had is left out of the table and said at once.
		for (tag, collisions) in plan.inbounds.iter().filter_map(|inbound| inbound.native.as_ref().map(|native| (&inbound.tag, native.tags().collisions))).filter(|(_, collisions)| *collisions > 0) {shared.obfs.collided(tag, collisions)}
		// The flows went first and the memory goes after them, which is the order `resolver::answer` counts on.
		for was in old.devices.iter().filter(|was| cut.contains_key(&was.public_key)) {old.users[was.user].state.names().clear()}
		// A user whose queries go to other servers from here on forgets what the servers before told them, so no `domain` rule goes on matching by the word of a resolver that is no longer theirs.
		// It is looked at inbound by inbound, for the inbound of the same tag: the servers of the list a device's queries go to through it, in whatever order. Another list of the same servers changes nothing, and the same list with other servers does.
		// The plan is in force by now, which is the order `resolver::answer` counts on.
		let mut moved: Vec<(&str, &str)> = Vec::new();
		for (was, is) in old.devices.iter().filter(|was| !cut.contains_key(&was.public_key)).filter_map(|was| plan.by_key.get(&was.public_key).map(|at| (was, &plan.devices[*at]))) {
			let name = old.users[was.user].name.as_str();
			// The devices of a user stand together, so the last name is the only one to look at.
			let left = was.inbounds.iter().map(|at| (old.inbounds[*at].tag.as_str(), &old.dns[old.dns_of(was.user, *at)])).find(|(tag, list)| !is.inbounds.iter().any(|at| plan.inbounds[*at].tag == *tag && plan.dns[plan.dns_of(is.user, *at)].same(list))).filter(|_| moved.last().is_none_or(|(last, _)| *last != name));
			if let Some((tag, _)) = left {
				old.users[was.user].state.names().clear();
				moved.push((name, tag));
			}
		}
		shared.pings.lock().unwrap_or_else(|e| e.into_inner()).retain(|(src, dst, _), (device, ..)| !cut.contains_key(device) && !pings.contains(&(*src, *dst)));
		// An exit that is not what it was has an upstream nothing is known about.
		for (was, at) in old.exits.iter().zip(&exits) {
			if at.is_none() && was.state.no_udp.lock().unwrap_or_else(|e| e.into_inner()).take().is_some() && tags.contains_key(was.tag.as_str()) {shared.publish(Event::ExitUdpChanged {exit: was.tag.clone(), udp: true})}
			if at.is_none() && was.state.down.lock().unwrap_or_else(|e| e.into_inner()).take().is_some() && tags.contains_key(was.tag.as_str()) {shared.publish(Event::ExitWorkingChanged {exit: was.tag.clone(), working: true})}
		}
		for (was, reason) in old.devices.iter().filter(|was| was.link.is_none()).filter_map(|was| cut.get(&was.public_key).map(|(reason, _)| (was, reason))).take(MAX_NAMES_LOGGED) {
			tracing::info!("user {} device {}: cut off, {reason}: its session keys and its flows are gone and the user's dns memory is cleared", old.users[was.user].name, was.name);
		}
		if cut.len() > MAX_NAMES_LOGGED {tracing::info!("{} more devices were cut off", cut.len() - MAX_NAMES_LOGGED)}
		for (name, tag) in moved.iter().take(MAX_NAMES_LOGGED) {
			tracing::info!("user {name}: the dns servers for their queries through inbound {tag} are not the ones they were, so the user's dns memory is cleared");
		}
		if moved.len() > MAX_NAMES_LOGGED {tracing::info!("{} more users had their dns memory cleared because their dns servers changed", moved.len() - MAX_NAMES_LOGGED)}
		if ended > 0 {tracing::info!("{ended} flow(s) ended with the config they were routed by")}
		// A user is an event when what `denied` says of them turns, not when one of their devices changes. The plan before the first one holds what the state file remembered and nobody was connected under it.
		for was in old.users.iter().filter(|was| old.generation > 0 && was.link.is_none()) {
			match (was.denied, users.get(was.name.as_str()).map(|is| is.denied)) {
				(None, None) => shared.publish(Event::UserCutOff {user: was.name.clone(), reason: CutOff::Removed}),
				(None, Some(Some(denied))) => shared.publish(Event::UserCutOff {user: was.name.clone(), reason: match denied {
					Denied::Disabled => CutOff::Disabled,
					Denied::Expired => CutOff::Expired,
					Denied::Quota => CutOff::Quota,
				}}),
				(Some(_), Some(None)) => shared.publish(Event::UserRestored {user: was.name.clone()}),
				_ => {}
			}
		}
		if old.users.iter().any(|was| users.get(was.name.as_str()).is_none_or(|is| is.denied == Some(Denied::Quota) && was.denied != is.denied)) {shared.save.notify_one()}
		(old, plan)
	}
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
	use super::*;

	// Transports page, "MTU", "No outer fragmentation": what the node sets on the socket of a datagram transport of a `veilway` inbound, and takes back when the address goes to another kind of inbound.
	#[tokio::test]
	async fn the_sockets_of_a_veilway_inbound_never_fragment() {
		let (v4, v6) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::from_std(bind("[::1]:0".parse().unwrap(), Type::DGRAM, false).await.unwrap().into()).unwrap());
		fragmenting(&v4, false, true).unwrap();
		fragmenting(&v6, true, true).unwrap();
		assert_eq!((sockopt::ip_mtu_discover(&v4).unwrap(), sockopt::ipv6_mtu_discover(&v6).unwrap()), (sockopt::Ipv4PathMtuDiscovery::PROBE, sockopt::Ipv6PathMtuDiscovery::PROBE));
		// A datagram of the largest size still leaves on loopback, whose MTU is above it: the option forbids fragmenting, not sending.
		let to = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		assert_eq!(v4.send_to(&[0; 1452], to.local_addr().unwrap()).await.unwrap(), 1452);
		fragmenting(&v4, false, false).unwrap();
		fragmenting(&v6, true, false).unwrap();
		assert_eq!((sockopt::ip_mtu_discover(&v4).unwrap(), sockopt::ipv6_mtu_discover(&v6).unwrap()), (sockopt::Ipv4PathMtuDiscovery::WANT, sockopt::Ipv6PathMtuDiscovery::WANT));
	}
}
