//! What the node holds on the host, and how a config gets there: `prepare` takes everything a config needs that the node does not hold yet while the running config keeps working, and `commit` puts the config in force in one step.
//! A start is the same two steps from nothing. Nothing in here can fail once `prepare` has returned, and when `prepare` fails it has left nothing behind.
use super::icmp::{self, Kind};
use super::inbound::{self, Peers, Tunnel};
use super::netstack::{self, PacketDev};
use super::plan::{Backend, Denied, Fallback, Outbound, Plan, User};
use super::route::{self, By, Decision, Ended, Key};
use super::{l3, CutOff, Event, Over, Shared, QUEUE};
use crate::config::{Config, Protocol, Tls, Transport, DEFAULT_MTU, MAX_NAMES_LOGGED, MAX_TCP_IDLE_SECS, MAX_UDP_IDLE_SECS};
use anyhow::anyhow;
use etherparse::PacketBuilder;
use ipnet::IpNet;
use ipstack::{IpStack, IpStackConfig, TcpConfig};
use socket2::{Domain, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use veilway_wg::ws::{self, TlsFiles};
use veilway_wg::Wg;

/// How much longer than the longest idle time a config may set the userspace stack keeps a quiet flow, in seconds. Each flow's handler ends it first, at the idle time of its own exit.
const STACK_MARGIN: u64 = 60;
/// How often and how far apart `bind` tries an address again that the node has only just given back.
const REBIND_TRIES: u32 = 50;
const REBIND_EVERY: Duration = Duration::from_millis(20);

/// A task that ends when this is dropped.
struct Task(AbortHandle);

impl Drop for Task {
	fn drop(&mut self) {self.0.abort()}
}

/// A tunnel as it runs: its tasks, and the loopback socket every `ws` transport of the inbound relays to, with its address and the task that reads it. An inbound without a `ws` transport has none.
struct Running {tunnel: Arc<Tunnel>, _tasks: Vec<Task>, loopback: Option<(SocketAddr, Arc<UdpSocket>, Task)>}

/// One address `ws` transports listen on: the end its listener is told through, and the routes it serves, each with the path, the `tls` of its transport, its tunnel and the number that tells it from an earlier route.
struct Relay {served: watch::Sender<Arc<ws::Served>>, routes: Vec<(String, Option<Tls>, Arc<Tunnel>, u64)>}

/// The l3 exit as it runs.
pub struct Wired {wanted: l3::Wanted, port: l3::Port, queue: l3::Queue, pub running: l3::Running}

pub struct Host {
	/// The directory of the config file.
	dir: PathBuf,
	/// The config the plan in force was compiled from.
	config: Option<Arc<Config>>,
	/// Every `udp` transport by its listen address: its socket, and the task that reads it with the tunnel it reads it for.
	/// An address the next config uses again is never bound a second time. Its socket goes to whichever tunnel has it then.
	udp: HashMap<SocketAddr, (Arc<UdpSocket>, Option<(Task, Arc<Tunnel>)>)>,
	ws: HashMap<SocketAddr, Relay>,
	/// By the tag of the inbound.
	tunnels: HashMap<String, Running>,
	/// Shared with the `Engine`, which takes it out when it shuts down or is dropped: the interface, its routes and its firewall table go with the engine, while everything else here serves on.
	pub l3: Arc<Mutex<Option<Wired>>>,
	/// The number the last new `ws` route was given.
	routes: u64,
	/// The listen addresses the last commit gave back to the host.
	released: HashSet<SocketAddr>,
}

/// What `prepare` took for a config that is not in force yet. Dropping it gives all of it back.
pub struct Staged {
	plan: Plan,
	config: Arc<Config>,
	udp: Vec<(SocketAddr, Arc<UdpSocket>)>,
	ws: Vec<(SocketAddr, TcpListener)>,
	/// For every address `ws` transports listen on, what its certificate files hold now.
	acceptors: HashMap<SocketAddr, Option<ws::Acceptor>>,
	/// The tunnels that are new or restart, each with its stack and what the stack sends back.
	tunnels: Vec<(Arc<Tunnel>, IpStack, Receiver<Vec<u8>>)>,
	loopbacks: Vec<(Arc<Tunnel>, SocketAddr, Arc<UdpSocket>)>,
	l3: Option<Wired>,
}

/// A bound socket that is not listening yet. IPv6 sockets are always IPv6-only, so a wildcard address of one family never takes the port of the other.
/// `released` says the node itself gave this address back in its last commit. The task that held the old socket ends a moment after it is told to, so such an address is tried again for a while when it is still taken.
async fn bind(addr: SocketAddr, kind: Type, released: bool) -> io::Result<Socket> {
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

impl Host {
	pub fn new(dir: PathBuf) -> Host {Host {dir, config: None, udp: HashMap::new(), ws: HashMap::new(), tunnels: HashMap::new(), l3: Arc::default(), routes: 0, released: HashSet::new()}}

	/// Takes from the host what `config` needs and the node does not hold yet: binds every new listener, reads every certificate again, builds the tunnels that are new or named in `restart`, and brings up the l3 interface.
	/// The running config keeps working through all of it. An error names tags and field paths, never a value from the document, and leaves nothing behind.
	pub async fn prepare(&mut self, shared: &Arc<Shared>, config: &Arc<Config>, restart: &[&str]) -> anyhow::Result<Staged> {
		let (old, mut fresh) = (shared.plan(), Vec::new());
		let tunnels = config.inbounds.iter().map(|inbound| match self.tunnels.get(&inbound.tag).filter(|_| !restart.contains(&inbound.tag.as_str())) {
			Some(running) => running.tunnel.clone(),
			None => {
				let (to_stack, from_wg) = mpsc::channel::<Vec<u8>>(QUEUE);
				let (to_wg, from_stack) = mpsc::channel::<Vec<u8>>(QUEUE);
				let (mut stack, mut tcp) = (IpStackConfig::default(), TcpConfig::default());
				// A tunnel outlives the exits of the config it started under, so its stack waits longer than any exit may ask and each flow's handler keeps the time of its own exit.
				tcp.timeout = Duration::from_secs(u64::from(MAX_TCP_IDLE_SECS) + STACK_MARGIN);
				stack.mtu_unchecked(inbound.mtu.unwrap_or(DEFAULT_MTU)).packet_information(false).udp_timeout(Duration::from_secs(u64::from(MAX_UDP_IDLE_SECS) + STACK_MARGIN)).with_tcp_config(tcp);
				let tunnel = Arc::new(Tunnel {tag: inbound.tag.clone(), peers: Mutex::new(Peers {wg: Wg::new(inbound.private_key.expose().0), via: Vec::new()}), to_stack});
				fresh.push((tunnel.clone(), IpStack::new(stack, PacketDev::new(from_wg, to_wg)), from_stack));
				tunnel
			}
		}).collect();
		let mut plan = Plan::new(config, (shared.now)(), &old, tunnels)?;
		for (tunnel, ..) in &fresh {
			let (Some(at), mut peers) = (plan.inbound_of(tunnel), tunnel.lock()) else {continue};
			for device in plan.devices.iter().filter(|device| device.inbounds.contains(&at)) {peers.add(device.public_key, device.preshared_key)}
		}
		let (mut udp, mut relays, mut acceptors, mut loopbacks) = (Vec::new(), Vec::<(SocketAddr, TcpListener)>::new(), HashMap::new(), Vec::<(Arc<Tunnel>, SocketAddr, Arc<UdpSocket>)>::new());
		for (i, inbound) in plan.inbounds.iter().enumerate() {
			for (t, transport) in inbound.transports.iter().enumerate() {
				match transport {
					Transport::Udp {listen} if !self.udp.contains_key(&listen.0) => udp.push((listen.0, Arc::new(bind(listen.0, Type::DGRAM, self.released.contains(&listen.0)).await.and_then(|socket| UdpSocket::from_std(socket.into())).map_err(|e| anyhow!("inbounds[{i}].transports[{t}].listen: inbound `{}` cannot listen there over udp: {}", inbound.tag, e.kind()))?))),
					Transport::Udp {..} => {}
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
		// Return traffic finds its interface by the routes of the pools, and two interfaces cannot both have those. Telling them apart takes policy routing, which is not built.
		let wanted = {
			let mut wired = plan.exits.iter().enumerate().filter_map(|(at, exit)| if let Backend::L3 {interface, masquerade} = &exit.backend {Some((at, exit, interface, masquerade))} else {None});
			let (first, second) = (wired.next(), wired.next());
			if let (Some((_, first, ..)), Some((_, second, ..))) = (first, second) {anyhow::bail!("exits `{}` and `{}` both have an l3 backend: this build runs one l3 exit per node, so remove one of them", first.tag, second.tag)}
			first.map(|(at, exit, interface, masquerade)| {
				let mut pools: Vec<IpNet> = plan.pools.iter().map(|(pool, _)| pool.trunc()).collect();
				pools.sort();
				(at, l3::Wanted {tag: exit.tag.clone(), interface: interface.clone(), masquerade: *masquerade, pools, mtu: plan.inbounds.iter().map(|inbound| inbound.mtu).min().unwrap_or(DEFAULT_MTU)})
			})
		};
		for exit in &plan.exits {
			if let Backend::Netstack {icmp_echo: Fallback::Direct, ..} = &exit.backend {icmp::ping_socket(true).map_err(|e| anyhow!("exit `{}`: \"icmp_echo\": \"direct\" needs unprivileged ping sockets, which this system does not give the node ({}); on Linux the node's group has to be inside net.ipv4.ping_group_range", exit.tag, e.kind()))?;}
		}
		let mut staged = None;
		if let Some((at, wanted)) = wanted {
			let runs = self.l3.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|wired| wired.wanted == wanted).map(|wired| wired.port.clone());
			if let Some(port) = runs {plan.l3 = Some((at, port))} else {
				// The pools can be routed to one interface only, so an interface that runs and is not the one wanted goes first. This is the last thing that can fail,
				// and when it does that interface is brought back on the queue the running config still writes to.
				let previous = self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();
				let previous = match previous {
					Some(Wired {wanted, port, queue, running}) => {
						running.close().await;
						Some((wanted, port, queue))
					}
					None => None,
				};
				let (to, from) = mpsc::channel(QUEUE);
				let (port, queue) = (l3::Port {to, mtu: wanted.mtu}, Arc::new(tokio::sync::Mutex::new(from)));
				match l3::Running::start(shared, &wanted, queue.clone()) {
					Ok(running) => {
						plan.l3 = Some((at, port.clone()));
						staged = Some(Wired {wanted, port, queue, running});
					}
					Err(e) => {
						if let Some((wanted, port, queue)) = previous {
							match l3::Running::start(shared, &wanted, queue.clone()) {
								Ok(running) => *self.l3.lock().unwrap_or_else(|e| e.into_inner()) = Some(Wired {wanted, port, queue, running}),
								Err(again) => tracing::error!("exit {}: its interface was closed for a reload that then failed and could not be brought back, so the exit carries nothing until a reload succeeds: {again:#}", wanted.tag),
							}
						}
						return Err(e);
					}
				}
			}
		}
		Ok(Staged {plan, config: config.clone(), udp, ws: relays, acceptors, tunnels: fresh, loopbacks, l3: staged})
	}

	/// Puts what `prepare` staged in force: the plan in one step, see `switch`, then the tasks and listeners that go with it. What the config no longer names is stopped and given back to the host.
	pub fn commit(&mut self, shared: &Arc<Shared>, staged: Staged) {
		let Staged {plan, config, udp, ws: relays, mut acceptors, tunnels, loopbacks, l3} = staged;
		// A reload of the bytes that already run stages the running config itself. With no tunnel and no interface to start there is nothing to switch to:
		// the plan in force stays, no flow is judged again, and all that follows here is the certificates that were read again.
		let same = tunnels.is_empty() && l3.is_none() && self.config.as_ref().is_some_and(|running| Arc::ptr_eq(running, &config));
		let (old, plan) = if same {(shared.plan(), shared.plan())} else {self.switch(shared, plan)};
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
		for (tunnel, addr, socket) in loopbacks {
			if let Some(running) = self.tunnels.get_mut(&tunnel.tag) {running.loopback = Some((addr, socket.clone(), Task(inbound::read(shared, tunnel, socket, Over::Ws))))}
		}
		let (mut wanted, mut routes): (HashMap<SocketAddr, &Arc<Tunnel>>, HashMap<SocketAddr, Vec<(String, Option<Tls>, Arc<Tunnel>, u64)>>) = Default::default();
		for inbound in &plan.inbounds {
			for transport in &inbound.transports {
				match transport {
					Transport::Udp {listen} => drop(wanted.insert(listen.0, &inbound.tunnel)),
					Transport::Ws {listen, path, tls} => {
						// A transport that is as it was keeps its number, and with the number the connections it has. Any other is a new route.
						let id = self.ws.get(&listen.0).and_then(|relay| relay.routes.iter().find(|(was, files, tunnel, _)| was == path && files == tls && Arc::ptr_eq(tunnel, &inbound.tunnel))).map(|(.., id)| *id).unwrap_or_else(|| {
							self.routes += 1;
							self.routes
						});
						routes.entry(listen.0).or_default().push((path.clone(), tls.clone(), inbound.tunnel.clone(), id));
					}
				}
			}
		}
		self.released = self.udp.keys().filter(|addr| !wanted.contains_key(addr)).chain(self.ws.keys().filter(|addr| !routes.contains_key(addr))).copied().collect();
		for (addr, socket) in udp {self.udp.insert(addr, (socket, None));}
		// A socket is read for the tunnel that has its address now. One whose address nobody has any more is closed, and so is its reader.
		self.udp.retain(|addr, (socket, reader)| match wanted.get(addr) {
			Some(tunnel) => {
				if !reader.as_ref().is_some_and(|(_, of)| Arc::ptr_eq(of, tunnel)) {*reader = Some((Task(inbound::read(shared, (*tunnel).clone(), socket.clone(), Over::Udp)), (*tunnel).clone()))}
				true
			}
			None => false,
		});
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
			}
			if matches!(exit.backend, Backend::Netstack {icmp_echo: Fallback::Direct, ..}) && plan.pools.iter().any(|(pool, _)| pool.addr().is_ipv6()) && icmp::ping_socket(false).is_err() {tracing::warn!("exit {}: this system gives the node no ping socket for ipv6, so ipv6 pings through the exit get no answer", exit.tag)}
		}
	}

	/// Cuts off the users whose `expires_at` has passed or whose quota was spent since the plan in force was made, and lets those in again whose quota period has started over:
	/// the config that runs is compiled again at the present time, with the counts as they are now, and switched to.
	pub fn expire(&mut self, shared: &Arc<Shared>) {
		let (Some(config), old) = (&self.config, shared.plan()) else {return};
		match Plan::new(config, (shared.now)(), &old, old.inbounds.iter().map(|inbound| inbound.tunnel.clone()).collect()) {
			Ok(mut plan) => {
				plan.l3 = old.l3.clone();
				self.switch(shared, plan);
			}
			Err(e) => tracing::error!("the running config could not be compiled again to cut off the users that expired or ran out of quota: {e:#}"),
		}
	}

	/// Puts `plan` in force in one step and returns the plan it replaced and the new one. With the flow table locked from start to end:
	/// every live flow is decided again and ends unless the new plan decides the same for it through an exit that is still the same exit, the device of each flow that ends is told once (a TCP reset, or an ICMP error for UDP),
	/// the devices that are cut off lose their session keys, and the plan is swapped. After that their user's DNS memory is cleared and each is logged.
	/// This is the one cut-off path: a device is cut off when the new plan no longer has it as it was, whatever the reason. A user who runs out of quota comes through here too, denied by `Plan::new` like one who expired, see `plan::Denied`.
	/// The state file is written right after a switch that cut a user off for their quota or left a user's name behind, so neither waits for the next write.
	fn switch(&self, shared: &Arc<Shared>, plan: Plan) -> (Arc<Plan>, Arc<Plan>) {
		let (old, plan) = (shared.plan(), Arc::new(plan));
		let users: HashMap<&str, &User> = plan.users.iter().map(|user| (user.name.as_str(), user)).collect();
		// A device is the same device while it has the same key, the same user, the same addresses and the same preshared key. Any other device of the old plan is cut off.
		let cut: HashMap<[u8; 32], &str> = old.devices.iter().filter_map(|was| {
			let name = old.users[was.user].name.as_str();
			Some((was.public_key, match plan.by_key.get(&was.public_key).map(|at| &plan.devices[*at]) {
				Some(is) if plan.users[is.user].name != name => "its key was given to another user",
				Some(is) if is.addresses != was.addresses => "its addresses changed",
				Some(is) if is.preshared_key != was.preshared_key => "its preshared key changed",
				Some(_) => return None,
				None => match users.get(name).map(|user| user.denied) {
					None => "the user was removed",
					Some(Some(Denied::Disabled)) => "the user was disabled",
					Some(Some(Denied::Expired)) => "the user expired",
					Some(Some(Denied::Quota)) => "the user ran out of quota",
					Some(None) => "the device was removed",
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
			_ => false,
		})).collect();
		let judge = |key: &Key, device: &[u8; 32], user: &str, decision: Decision, names: &[Arc<str>]| {
			if cut.contains_key(device) {return None}
			// A flow belongs to a user and a device. It lives on only where that device still holds the address it came from, in the tunnel it came through.
			let (is, was) = (plan.by_address.get(&key.src).copied()?, old.by_address.get(&key.src).copied()?);
			let holder = &plan.devices[is.device];
			if holder.public_key != *device || plan.users[holder.user].name != user || !Arc::ptr_eq(&plan.inbounds[is.inbound].tunnel, &old.inbounds[was.inbound].tunnel) {return None}
			match (decision, shared.decide(&plan, is.inbound, holder.user, key, names)) {
				(Decision::Deliver, Decision::Deliver) => Some(Decision::Deliver),
				(Decision::Dns, Decision::Dns) => Some(Decision::Dns),
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
				let inbound = &old.inbounds[from.inbound];
				// The reset goes out under the session the device still has, which is why this comes before the keys are dropped. Other protocols have nothing at the device that an error without the packet it answers could end.
				let packet = match flow.key.protocol {
					Protocol::TCP => flow.heard.and_then(|heard| route::tcp_reset(&flow.key, heard)),
					Protocol::UDP => {
						let mut raw = Vec::new();
						let built = match (flow.key.src, flow.key.dst) {
							(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(flow.key.sport, flow.key.dport).write(&mut raw, &[]),
							(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(flow.key.sport, flow.key.dport).write(&mut raw, &[]),
							_ => continue,
						};
						let gateway = inbound.pools.iter().map(|pool| pool.addr()).find(|gateway| gateway.is_ipv4() == flow.key.src.is_ipv4());
						built.ok().and_then(|_| netstack::parse(&raw)).zip(gateway).and_then(|(packet, gateway)| icmp::error(&raw, &packet, Kind::Prohibited, gateway, &old.pools))
					}
					_ => None,
				};
				let (Some(packet), mut peers, mut datagrams) = (packet, inbound.tunnel.lock(), Vec::new()) else {continue};
				let Some(peer) = peers.wg.index(&flow.device).filter(|peer| peers.wg.time_since_last_handshake(*peer).is_some()) else {continue};
				let Some((endpoint, socket)) = peers.wg.endpoint(peer).zip(peers.via.get(peer).and_then(|(socket, _)| socket.upgrade())) else {continue};
				peers.wg.encapsulate(peer, &packet, &mut datagrams);
				shared.spend(&old.users[old.devices[from.device].user], false, packet.len());
				inbound.traffic.down(packet.len());
				out.extend(datagrams.into_iter().map(|datagram| (socket.clone(), endpoint, datagram)));
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
			for device in &plan.devices {
				for at in &device.inbounds {
					let mut peers = plan.inbounds[*at].tunnel.lock();
					if peers.wg.index(&device.public_key).is_none() {peers.add(device.public_key, device.preshared_key)}
				}
			}
			// `Plan::new` held each count against the period the plan was compiled in without touching it. The plan is in force from here, so this is where a count whose period is over starts over.
			for user in &plan.users {
				if let Some(period) = user.period {user.state.roll(plan.starts[period as usize])}
			}
			plan.shown.store(plan.log_destinations, Ordering::Relaxed);
			*shared.plan.write().unwrap_or_else(|e| e.into_inner()) = plan.clone();
			(out, pings, ended.len())
		});
		// Every packet of every user waits while the flow table is locked, so how long that was is always said.
		tracing::info!("a plan was put in force: the flow table was locked for {:?} while every live flow was decided again", started.elapsed());
		// Never waited for: a socket that cannot take a reset right now loses it, like any packet on a full queue.
		for (socket, endpoint, datagram) in &out {let _ = socket.try_send_to(datagram, *endpoint);}
		// The flows went first and the memory goes after them, which is the order `resolver::answer` counts on.
		for was in old.devices.iter().filter(|was| cut.contains_key(&was.public_key)) {old.users[was.user].state.names().clear()}
		shared.pings.lock().unwrap_or_else(|e| e.into_inner()).retain(|(src, dst, _), (device, ..)| !cut.contains_key(device) && !pings.contains(&(*src, *dst)));
		// An exit that is not what it was has an upstream nothing is known about.
		for (was, at) in old.exits.iter().zip(&exits) {
			if at.is_none() && was.state.no_udp.lock().unwrap_or_else(|e| e.into_inner()).take().is_some() && tags.contains_key(was.tag.as_str()) {shared.publish(Event::ExitUdpChanged {exit: was.tag.clone(), udp: true})}
		}
		for (was, reason) in old.devices.iter().filter_map(|was| cut.get(&was.public_key).map(|reason| (was, reason))).take(MAX_NAMES_LOGGED) {
			tracing::info!("user {} device {}: cut off, {reason}: its session keys and its flows are gone and the user's dns memory is cleared", old.users[was.user].name, was.name);
		}
		if cut.len() > MAX_NAMES_LOGGED {tracing::info!("{} more devices were cut off", cut.len() - MAX_NAMES_LOGGED)}
		if ended > 0 {tracing::info!("{ended} flow(s) ended with the config they were routed by")}
		// A user is an event when what `denied` says of them turns, not when one of their devices changes. The plan before the first one holds what the state file remembered and nobody was connected under it.
		for was in old.users.iter().filter(|_| old.generation > 0) {
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
