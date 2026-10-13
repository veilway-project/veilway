//! One inbound at run time: its WireGuard tunnel, the sockets it is reached over, and the path every decrypted packet takes before it may go anywhere.
use super::icmp::{self, Kind};
use super::netstack::{self, Packet};
use super::plan::{Action, Backend, Fallback, Holder, Outbound, Plan};
use super::route::{self, By, Decision, Key, Reason, FLOW_IDLE};
use super::{flows, gate, l3, resolver, Shared};
use crate::config::Protocol;
use ipstack::{IpStack, IpStackStream};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::AbortHandle;
use veilway_wg::{Wg, MAX_PACKET};

const TIMER_EVERY: Duration = Duration::from_millis(250);
/// The FIN and RST bits in the flags byte of a TCP header, which is its 14th.
const TCP_FLAGS: usize = 13;
const FIN_OR_RST: u8 = 0x05;

pub struct Peers {
	pub wg: Wg,
	/// For each peer index, the socket its last authenticated datagram came in on. Replies leave through that one, and nowhere once its transport is gone.
	pub via: Vec<Weak<UdpSocket>>,
}

impl Peers {
	/// Makes a device a peer. It fails only for a key that already is one, which validation rules out.
	pub fn add(&mut self, public_key: [u8; 32], preshared_key: Option<[u8; 32]>) {
		match self.wg.add_peer(public_key, preshared_key, None) {
			Ok(peer) => {
				if self.via.len() <= peer {self.via.resize(peer + 1, Weak::new())}
				self.via[peer] = Weak::new();
			}
			Err(e) => tracing::error!("a device could not be made a peer of its tunnel: {e}"),
		}
	}
}

/// The tunnel of one inbound. It lives for as long as the inbound keeps its tag, key, pools and MTU, across reloads, and its sessions with it.
pub struct Tunnel {
	pub tag: String,
	pub peers: Mutex<Peers>,
	pub to_stack: Sender<Vec<u8>>,
}

impl Tunnel {
	pub fn lock(&self) -> MutexGuard<'_, Peers> {self.peers.lock().unwrap_or_else(|e| e.into_inner())}
}

impl Shared {
	/// Encrypts one IP packet for the device that holds an address and sends it where that device was last heard from.
	/// The device is found by its public key, so a holder from a plan that has been replaced never reaches whoever took its place.
	/// A device without a live session is sent nothing: a peer that is given a packet then keeps it for the next handshake, and a device that was cut off or has only just been added would get what was meant for the session before.
	pub(super) async fn send(&self, plan: &Plan, to: Holder, packet: &[u8]) {
		let (inbound, device, mut out) = (&plan.inbounds[to.inbound], &plan.devices[to.device], Vec::new());
		let route = {
			let mut peers = inbound.tunnel.lock();
			let Some(peer) = peers.wg.index(&device.public_key).filter(|peer| peers.wg.time_since_last_handshake(*peer).is_some()) else {return};
			peers.wg.encapsulate(peer, packet, &mut out);
			peers.wg.endpoint(peer).zip(peers.via.get(peer).and_then(Weak::upgrade))
		};
		let Some((endpoint, socket)) = route else {return};
		self.spend(&plan.users[device.user], false, packet.len());
		inbound.traffic.down(packet.len());
		for datagram in &out {let _ = socket.send_to(datagram, endpoint).await;}
	}

	/// Sends the device that sent `raw` the ICMP error for it, from the gateway of the tunnel it came through, which is the router that turned it away. Each device is sent only so many, see `icmp::Limit`.
	async fn icmp_error(&self, plan: &Plan, to: Holder, raw: &[u8], packet: &Packet, kind: Kind) {
		let Some(gateway) = plan.inbounds[to.inbound].pools.iter().map(|pool| pool.addr()).find(|gateway| gateway.is_ipv4() == packet.src.is_ipv4()) else {return};
		let Some(error) = icmp::error(raw, packet, kind, gateway, &plan.pools) else {return};
		if !plan.devices[to.device].limit.lock().unwrap_or_else(|e| e.into_inner()).take(Instant::now()) {return self.count(Reason::IcmpLimited)}
		self.send(plan, to, &error).await
	}

	/// Counts a packet that is not carried. When the flow is to be answered, TCP gets a reset and everything else the ICMP error that matches the reason.
	async fn refuse(&self, plan: &Plan, from: Holder, raw: &[u8], packet: &Packet, reason: Reason, answer: bool) {
		self.count(reason);
		if !answer {return}
		if packet.protocol == Protocol::TCP {
			if let Some(rst) = netstack::tcp_rst(raw) {self.send(plan, from, &rst).await}
			return;
		}
		let kind = match (reason, packet.protocol) {
			(Reason::Unreachable, _) => Kind::Host,
			(Reason::Unsupported, Protocol::UDP) => Kind::Port,
			// A ping the exit's policy rejects is a ping somebody forbade, not a protocol nobody speaks.
			(Reason::Unsupported, Protocol::ICMP | Protocol::ICMPV6) => Kind::Prohibited,
			(Reason::Unsupported, _) => Kind::Protocol,
			_ => Kind::Prohibited,
		};
		self.icmp_error(plan, from, raw, packet, kind).await
	}

	/// What is to be done with a flow of `user` that came in on inbound `at`, by the gate, the rules and the exits of `plan`. `names` is what the user had resolved to the destination when the flow began.
	/// A new flow is decided here from its first packet, and when the plan changes every live flow is decided again from its key, so the two can never disagree.
	pub(super) fn decide(&self, plan: &Plan, at: usize, user: usize, key: &Key, names: &[Arc<str>]) -> Decision {
		let (transport, gateway) = (key.protocol == Protocol::TCP || key.protocol == Protocol::UDP, plan.is_gateway(key.dst));
		// A flow of ICMP is known by its type and code, which stand where the ports of another flow do.
		let icmp = (key.protocol == Protocol::ICMP || key.protocol == Protocol::ICMPV6).then_some((key.sport as u8, key.dport as u8));
		let dport = if icmp.is_some() {0} else {key.dport};
		// A gateway answers DNS and nothing else. With hijack on, every UDP and TCP port 53 flow is DNS for the node wherever it was sent.
		let dns = dport == 53 && transport && (gateway || plan.hijack);
		let local = !dns && !gateway && plan.pool_of(key.dst).is_some();
		if (gateway && !dns) || (!dns && !local && gate::refused(key.dst, &plan.pools)) {return Decision::Refuse {reason: Reason::Gate, reset: true}}
		// The resolver routes each query of a DNS flow by itself, by the server it goes to and the name it asks for.
		if dns {return Decision::Dns}
		// A flow may only leave through an exit in its user's `exits`, whatever chose it. That is final: the flow is rejected and never falls through to another rule.
		let entitled = |exit: usize| plan.users[user].entitled.as_ref().is_none_or(|list| list.contains(&exit));
		match route::evaluate(plan, at, user, key.dst, key.protocol, dport, icmp, &|patterns| names.iter().any(|name| patterns.iter().any(|pattern| pattern.matches(name)))) {
			Action::Block => Decision::Refuse {reason: Reason::Rule, reset: false},
			Action::Reject => Decision::Refuse {reason: Reason::Rule, reset: true},
			// Traffic between users never leaves through an exit: any outcome but a refusal is delivery inside the node.
			_ if local => Decision::Deliver,
			// The node's own addresses are known only to the host.
			_ if (self.is_local)(key.dst) => Decision::Refuse {reason: Reason::Gate, reset: true},
			action => {
				let exit = if let Action::Exit(exit) = action {*exit} else {plan.users[user].exit.unwrap_or(plan.default_exit)};
				match &plan.exits[exit].backend {
					_ if !entitled(exit) => Decision::Refuse {reason: Reason::Entitlement, reset: true},
					Backend::Block => Decision::Refuse {reason: Reason::BlockExit, reset: false},
					Backend::L3 {..} => Decision::Exit {exit, by: By::Backend},
					Backend::Netstack {outbound: Outbound::Direct {bind: Some(bind)}, ..} if bind.is_ipv4() != key.dst.is_ipv4() => Decision::Refuse {reason: Reason::Unsupported, reset: true},
					// Whether the proxy relays UDP is only known once the flow's handler has asked it, so the `udp` policy is applied there, see `flows::run`.
					Backend::Netstack {..} if transport => Decision::Exit {exit, by: By::Backend},
					Backend::Netstack {icmp_echo, other, ..} => match if matches!((key.protocol, icmp), (Protocol::ICMP, Some((netstack::ECHO_REQUEST_V4, 0))) | (Protocol::ICMPV6, Some((netstack::ECHO_REQUEST_V6, 0)))) {*icmp_echo} else {*other} {
						Fallback::Local => Decision::Exit {exit, by: By::Local},
						Fallback::Direct => Decision::Exit {exit, by: By::Direct},
						// The spec's "whatever chose it: a rule, the user's exit, default, or a via" is read as: the exit a `via` hands the flow to must be in the user's `exits` as well as the one the rules chose.
						// The destination has passed the gate of both exits by now, because the gate is one list for every exit and was checked above.
						Fallback::Via(target) if !entitled(target) => Decision::Refuse {reason: Reason::Entitlement, reset: true},
						// The target's own `unsupported` is never consulted: only an l3 exit carries these, and any other target rejects them.
						Fallback::Via(target) if matches!(plan.exits[target].backend, Backend::L3 {..}) => Decision::Exit {exit, by: By::Via(target)},
						Fallback::Drop => Decision::Refuse {reason: Reason::Unsupported, reset: false},
						_ => Decision::Refuse {reason: Reason::Unsupported, reset: true},
					},
				}
			}
		}
	}

	/// One decrypted packet from the device with the public key `peer`, which came in on inbound `at`, in the order the checks must happen: parse, source, destination, route.
	async fn ingress(self: &Arc<Self>, plan: &Arc<Plan>, at: usize, peer: [u8; 32], mut raw: Vec<u8>) {
		// A device this plan does not know was cut off between its packet being decrypted and now.
		let Some(&device) = plan.by_key.get(&peer) else {return self.count(Reason::Stale)};
		let (from, user) = (Holder {device, inbound: at}, plan.devices[device].user);
		self.spend(&plan.users[user], true, raw.len());
		plan.inbounds[at].traffic.up(raw.len());
		let Some(packet) = netstack::parse(&raw) else {return self.count(Reason::Unparsable)};
		if packet.fragment {return self.count(Reason::Fragment)}
		raw.truncate(packet.len);
		// A device speaks only from its own address in the tunnel the packet arrived through.
		if plan.by_address.get(&packet.src) != Some(&from) {
			tracing::debug!("inbound {}: a device of user {} sent from an address that is not its own", plan.inbounds[at].tag, plan.users[user].name);
			return self.count(Reason::SpoofedSource);
		}
		let transport = packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP;
		let gateway = plan.is_gateway(packet.dst);
		let dns = packet.dport == 53 && transport && (gateway || plan.hijack);
		let local = !dns && !gateway && plan.pool_of(packet.dst).is_some();
		// The gate is asked for every packet, so what it refuses takes no place in the flow table.
		if (gateway && !dns) || (!dns && !local && gate::refused(packet.dst, &plan.pools)) {return self.refuse(plan, from, &raw, &packet, Reason::Gate, true).await}
		let (key, heard) = (Key::of(&packet), if packet.protocol == Protocol::TCP {route::heard(&raw, packet.upper)} else {None});
		// The answer to a flow that was delivered between users belongs to that flow, whatever the rules say about the other direction.
		// It is looked for first: a refusal remembered for this side's own earlier try must not shut the answer out.
		let (id, decision) = if local && key.reversed().and_then(|back| self.flows.get(&back, plan.generation, None)).is_some_and(|(_, decision)| decision == Decision::Deliver) {(0, Decision::Deliver)}
		else if let Some(known) = self.flows.get(&key, plan.generation, heard) {known} else {
			let names = if dns {Vec::new()} else {plan.users[user].state.names().of(packet.dst, Instant::now())};
			let decision = self.decide(plan, at, user, &key, &names);
			let id = match self.flows.insert(key, plan.devices[device].public_key, &plan.users[user].name, decision, names, heard, plan.generation) {
				Ok(id) => id,
				Err(reason) => return self.count(reason),
			};
			tracing::debug!("inbound {}: user {}: new flow, protocol {} to {}: {decision:?}", plan.inbounds[at].tag, plan.users[user].name, packet.protocol, plan.show(SocketAddr::new(packet.dst, packet.dport)));
			(id, decision)
		};
		self.carry(plan, from, raw, &packet, key, id, decision).await
	}

	/// Does with one packet of a flow what the flow's decision says. `from` is the device that sent it and `id` the flow's entry in the table.
	#[allow(clippy::too_many_arguments)]
	pub(super) async fn carry(self: &Arc<Self>, plan: &Arc<Plan>, from: Holder, raw: Vec<u8>, packet: &Packet, key: Key, id: u64, decision: Decision) {
		let transport = packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP;
		match decision {
			Decision::Refuse {reason, reset} => self.refuse(plan, from, &raw, packet, reason, reset).await,
			Decision::Deliver => {
				let to = plan.by_address.get(&packet.dst).copied().filter(|to| {
					let peers = plan.inbounds[to.inbound].tunnel.lock();
					peers.wg.index(&plan.devices[to.device].public_key).is_some_and(|peer| peers.wg.time_since_last_handshake(peer).is_some())
				});
				match to {
					// The sender is in a tunnel, so it can be told what does fit.
					Some(to) if raw.len() > usize::from(plan.inbounds[to.inbound].mtu) => {
						self.count(Reason::TooBig);
						self.icmp_error(plan, from, &raw, packet, Kind::TooBig(plan.inbounds[to.inbound].mtu)).await
					}
					Some(to) => self.send(plan, to, &raw).await,
					None => self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await,
				}
			}
			Decision::Dns => if plan.inbounds[from.inbound].tunnel.to_stack.try_send(raw).is_err() {self.count(Reason::QueueFull)},
			Decision::Exit {exit, by} => {
				// An exit counts a packet where the packet is handed to it, so one that is dropped on the way counts for none, and only the exit that carries it counts it: what a `via` hands on is the traffic of the exit it was handed to.
				let (carrier, len) = (if let By::Via(target) = by {target} else {exit}, raw.len());
				match (by, &plan.exits[carrier].backend) {
					(By::Local, _) => match netstack::echo_reply(&raw, packet) {
						Some(reply) => {
							plan.exits[exit].traffic.up(len);
							plan.exits[exit].traffic.down(reply.len());
							self.send(plan, from, &reply).await;
						}
						None => self.count(Reason::Unsupported),
					},
					// One ping socket for each identifier a device pings a destination under, because the kernel answers a socket only with the replies to its own identifier.
					(By::Direct, _) if !transport => {
						let Some(message) = raw.get(packet.upper..).filter(|message| message.len() >= 8) else {return self.count(Reason::Unparsable)};
						let ping = (packet.src, packet.dst, u16::from_be_bytes([message[4], message[5]]));
						let (device, user, mut pings) = (plan.devices[from.device].public_key, plan.users[plan.devices[from.device].user].name.as_str(), self.pings.lock().unwrap_or_else(|e| e.into_inner()));
						match pings.get(&ping) {
							Some((.., to)) => if to.try_send(message.to_vec()).is_ok() {plan.exits[exit].traffic.up(len)} else {self.count(Reason::QueueFull)},
							None if pings.len() >= icmp::MAX_PINGS || pings.values().filter(|(_, of, _)| **of == *user).count() >= icmp::MAX_PINGS_PER_USER || pings.values().filter(|(of, ..)| *of == device).count() >= icmp::MAX_PINGS_PER_DEVICE => self.count(Reason::FlowTableFull),
							None => {
								let (to, requests) = mpsc::channel(icmp::PING_QUEUE);
								let _ = to.try_send(message.to_vec());
								plan.exits[exit].traffic.up(len);
								pings.insert(ping, (device, Arc::from(user), to));
								tokio::spawn(icmp::ping(self.clone(), plan.clone(), exit, from, ping, requests));
							}
						}
					}
					(By::Backend | By::Via(_), Backend::L3 {..}) => {
						let Some((_, port)) = plan.l3.as_ref().filter(|(wired, _)| *wired == carrier) else {return self.count(Reason::Unsupported)};
						// The sender is in a tunnel, so it can be told what does fit.
						if raw.len() > usize::from(port.mtu) {
							self.count(Reason::TooBig);
							return self.icmp_error(plan, from, &raw, packet, Kind::TooBig(port.mtu)).await;
						}
						if packet.protocol == Protocol::TCP && raw.get(packet.upper + TCP_FLAGS).is_some_and(|flags| flags & FIN_OR_RST != 0) {self.flows.track(&key, id, FLOW_IDLE, true)}
						if port.to.try_send(raw).is_ok() {plan.exits[carrier].traffic.up(len)} else {self.count(Reason::QueueFull)}
					}
					// A TCP segment is the exit's once the exit's stack has it. A datagram is counted by the handler of its flow, see `flows::run`: only there is it known whether an outbound took it, and which.
					_ if transport => if plan.inbounds[from.inbound].tunnel.to_stack.try_send(raw).is_err() {self.count(Reason::QueueFull)} else if packet.protocol == Protocol::TCP {plan.exits[carrier].traffic.up(len)},
					_ => self.count(Reason::Unsupported),
				}
			}
		}
	}

	/// One packet the kernel routed into the interface of l3 exit `exit`. Whoever can reach the host can aim packets at it, so a packet is delivered only to the device that holds its destination address,
	/// and only as the answer to a live flow of that device which left through this exit: the flow's own reverse, or an ICMP error that quotes a packet of the flow. Everything else is counted and dropped.
	#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
	pub(super) async fn returned(&self, plan: &Plan, exit: usize, mut raw: Vec<u8>) {
		let Some(packet) = netstack::parse(&raw) else {return self.count(Reason::Unparsable)};
		if packet.fragment {return self.count(Reason::Fragment)}
		raw.truncate(packet.len);
		let Some(to) = plan.by_address.get(&packet.dst).copied() else {return self.count(Reason::NoFlow)};
		// Destination unreachable, time exceeded and parameter problem, and for ICMPv6 packet too big as well.
		let error = matches!((packet.protocol, packet.icmp), (Protocol::ICMP, Some((3 | 11 | 12, _))) | (Protocol::ICMPV6, Some((1..=4, _))));
		let key = if error {raw.get(packet.upper + 8..).and_then(netstack::quoted).filter(|quoted| quoted.src == packet.dst && !quoted.fragment).map(|quoted| Key::of(&quoted))} else {Key::of(&packet).reversed()};
		let (key, id, by) = match key.and_then(|key| self.flows.get(&key, plan.generation, None).map(|flow| (key, flow))) {
			Some((key, (id, Decision::Exit {exit: chosen, by}))) if (chosen == exit && by == By::Backend) || by == By::Via(exit) => (key, id, by),
			_ => return self.count(Reason::NoFlow),
		};
		// The interface has the smallest MTU of all inbounds, so this only happens when the host was set up otherwise. The sender is out on the network and gets no answer from here.
		if raw.len() > usize::from(plan.inbounds[to.inbound].mtu) {return self.count(Reason::TooBig)}
		// A flow a `via` handed over is kept by its handler. Any other lives by what its packets say: long once the far side has answered, short again after a FIN or RST.
		if by == By::Backend && !error {
			let (idle, closing) = match packet.protocol {
				Protocol::TCP => (l3::TCP_IDLE, raw.get(packet.upper + TCP_FLAGS).is_some_and(|flags| flags & FIN_OR_RST != 0)),
				Protocol::UDP => (l3::UDP_IDLE, false),
				_ => (FLOW_IDLE, false),
			};
			self.flows.track(&key, id, idle, closing);
		}
		// For this exit alone, which carried it, whichever exit the rules chose for the flow.
		plan.exits[exit].traffic.down(raw.len());
		self.send(plan, to, &raw).await
	}
}

/// Reads one socket for one tunnel until the handle it returns is aborted: a `udp` transport's own socket, or the loopback socket the `ws` transports of the inbound relay to.
pub fn read(shared: &Arc<Shared>, tunnel: Arc<Tunnel>, socket: Arc<UdpSocket>) -> AbortHandle {
	let shared = shared.clone();
	tokio::spawn(async move {
		let mut buf = vec![0u8; MAX_PACKET];
		let (mut net_out, mut ip_out) = (Vec::new(), Vec::new());
		loop {
			let Ok((n, from)) = socket.recv_from(&mut buf).await else {continue};
			net_out.clear();
			ip_out.clear();
			// The peer is taken by its key while the tunnel is still locked: its index may be another device's a moment later.
			let peer = {
				let mut peers = tunnel.lock();
				let received = peers.wg.recv_authenticated(from, &buf[..n], &mut net_out, &mut ip_out);
				if let Some((peer, true)) = received {
					if let Some(via) = peers.via.get_mut(peer) {*via = Arc::downgrade(&socket)}
				}
				received.and_then(|(peer, _)| peers.wg.key(peer))
			};
			for datagram in &net_out {let _ = socket.send_to(datagram, from).await;}
			let Some(peer) = peer else {continue};
			let plan = shared.plan();
			let Some(at) = plan.inbound_of(&tunnel) else {continue};
			for packet in ip_out.drain(..) {shared.ingress(&plan, at, peer, packet).await}
		}
	}).abort_handle()
}

/// Starts what a tunnel needs besides its sockets: the stack's replies, the WireGuard timers and the flows the stack accepts. They run until the handles are aborted.
pub fn serve(shared: &Arc<Shared>, tunnel: &Arc<Tunnel>, mut stack: IpStack, mut from_stack: Receiver<Vec<u8>>) -> Vec<AbortHandle> {
	// Stack -> peer: the reply goes to the device that holds its destination address in this tunnel, when the flow it answers is that device's.
	let replies = tokio::spawn({
		let (shared, tunnel) = (shared.clone(), tunnel.clone());
		async move {
			while let Some(raw) = from_stack.recv().await {
				let plan = shared.plan();
				let Some(packet) = netstack::parse(&raw) else {continue};
				let Some(to) = plan.by_address.get(&packet.dst).copied().filter(|to| Arc::ptr_eq(&plan.inbounds[to.inbound].tunnel, &tunnel)) else {continue};
				// The stack answers by address and knows nothing of reloads. An answer is only for the device whose live flow it answers: after a reload that address may be another device's, and the flow is over.
				let Some((_, decision)) = Key::of(&packet).reversed().and_then(|key| shared.flows.owned(&key, plan.generation)).filter(|(owner, _)| *owner == plan.devices[to.device].public_key) else {
					shared.count(Reason::Stale);
					continue;
				};
				// A datagram was counted when the handler of its flow took it from an outbound. A TCP flow is always carried by the exit the rules chose.
				if let (Protocol::TCP, Decision::Exit {exit, ..}) = (packet.protocol, decision) {plan.exits[exit].traffic.down(raw.len())}
				shared.send(&plan, to, &raw).await;
			}
		}
	});
	let timers = tokio::spawn({
		let tunnel = tunnel.clone();
		async move {
			let mut tick = tokio::time::interval(TIMER_EVERY);
			let mut out = Vec::new();
			loop {
				tick.tick().await;
				out.clear();
				let targets: Vec<Option<(SocketAddr, Arc<UdpSocket>)>> = {
					let mut peers = tunnel.lock();
					peers.wg.update_timers(&mut out);
					out.iter().map(|(peer, _)| peers.wg.endpoint(*peer).zip(peers.via.get(*peer).and_then(Weak::upgrade))).collect()
				};
				for ((_, datagram), target) in out.iter().zip(targets) {
					if let Some((endpoint, socket)) = target {let _ = socket.send_to(datagram, endpoint).await;}
				}
			}
		}
	});
	// Accepted flows: the routing decision made for the first packet is waiting in the flow table.
	let accepted = tokio::spawn({
		let (shared, tunnel) = (shared.clone(), tunnel.clone());
		async move {
			loop {
				let stream = match stack.accept().await {
					Ok(stream) => stream,
					Err(e) => return tracing::error!("inbound {}: the userspace stack stopped: {e}", tunnel.tag),
				};
				let (protocol, src, dst) = match &stream {
					IpStackStream::Tcp(s) => (Protocol::TCP, s.local_addr(), s.peer_addr()),
					IpStackStream::Udp(s) => (Protocol::UDP, s.local_addr(), s.peer_addr()),
					_ => continue,
				};
				let (plan, key) = (shared.plan(), Key {protocol, src: src.ip(), dst: dst.ip(), sport: src.port(), dport: dst.port()});
				let Some(from) = plan.by_address.get(&key.src).copied().filter(|from| Arc::ptr_eq(&plan.inbounds[from.inbound].tunnel, &tunnel)) else {continue};
				let mtu = plan.inbounds[from.inbound].mtu;
				match shared.flows.get(&key, plan.generation, None) {
					Some((id, Decision::Exit {exit, by})) => drop(tokio::spawn(flows::run(shared.clone(), plan, key, id, exit, by, from, stream, mtu))),
					Some((id, Decision::Dns)) => drop(tokio::spawn(resolver::serve(shared.clone(), key, id, plan.devices[from.device].public_key, stream, mtu))),
					_ => {}
				}
			}
		}
	});
	vec![replies.abort_handle(), timers.abort_handle(), accepted.abort_handle()]
}
