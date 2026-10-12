//! One inbound at run time: its WireGuard tunnel, the sockets it is reached over, and the path every decrypted packet takes before it may go anywhere.
use super::icmp::{self, Kind};
use super::netstack::{self, Packet};
use super::plan::{Action, Backend, Fallback, Holder, Outbound, Plan};
use super::route::{self, By, Decision, Key, Reason, FLOW_IDLE};
use super::{flows, gate, l3, resolver, Shared};
use crate::config::Protocol;
use ipstack::{IpStack, IpStackStream};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver, Sender};
use veilway_wg::{Wg, MAX_PACKET};

const TIMER_EVERY: Duration = Duration::from_millis(250);
/// The FIN and RST bits in the flags byte of a TCP header, which is its 14th.
const TCP_FLAGS: usize = 13;
const FIN_OR_RST: u8 = 0x05;

pub struct Peers {
	pub wg: Wg,
	/// For each peer, the socket its last authenticated datagram came in on. Replies leave through that one.
	pub via: Vec<usize>,
}

pub struct Tunnel {
	pub peers: Mutex<Peers>,
	/// One socket per `udp` transport, and one on loopback that every `ws` transport of the inbound relays to.
	pub sockets: Vec<Arc<UdpSocket>>,
	pub to_stack: Sender<Vec<u8>>,
}

impl Tunnel {
	fn lock(&self) -> MutexGuard<'_, Peers> {self.peers.lock().unwrap_or_else(|e| e.into_inner())}
}

impl Shared {
	/// Encrypts one IP packet for the device that holds an address and sends it where that device was last heard from.
	pub(super) async fn send(&self, plan: &Plan, to: Holder, packet: &[u8]) {
		let tunnel = &self.tunnels[to.inbound];
		let mut out = Vec::new();
		let route = {
			let mut peers = tunnel.lock();
			peers.wg.encapsulate(to.peer, packet, &mut out);
			peers.wg.endpoint(to.peer).map(|endpoint| (endpoint, peers.via[to.peer]))
		};
		let Some((endpoint, via)) = route else {return};
		self.counters.users[plan.devices[to.device].user].down(packet.len());
		self.counters.inbounds[to.inbound].down(packet.len());
		for datagram in &out {let _ = tunnel.sockets[via].send_to(datagram, endpoint).await;}
	}

	/// Sends the device that sent `raw` the ICMP error for it, from the gateway of the tunnel it came through, which is the router that turned it away. Each device is sent only so many, see `icmp::Limit`.
	async fn icmp_error(&self, plan: &Plan, to: Holder, raw: &[u8], packet: &Packet, kind: Kind) {
		let Some(gateway) = plan.inbounds[to.inbound].pools.iter().map(|pool| pool.addr()).find(|gateway| gateway.is_ipv4() == packet.src.is_ipv4()) else {return};
		let Some(error) = icmp::error(raw, packet, kind, gateway, &plan.pools) else {return};
		if !self.limits[to.device].lock().unwrap_or_else(|e| e.into_inner()).take(Instant::now()) {return self.counters.count(Reason::IcmpLimited)}
		self.send(plan, to, &error).await
	}

	/// Counts a packet that is not carried. When the flow is to be answered, TCP gets a reset and everything else the ICMP error that matches the reason.
	async fn refuse(&self, plan: &Plan, from: Holder, raw: &[u8], packet: &Packet, reason: Reason, answer: bool) {
		self.counters.count(reason);
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

	/// One decrypted packet from peer `peer` of inbound `at`, in the order the checks must happen: parse, source, destination, route.
	async fn ingress(self: &Arc<Self>, plan: &Arc<Plan>, at: usize, peer: usize, mut raw: Vec<u8>) {
		let Some(&device) = plan.inbounds[at].peers.get(peer) else {return};
		let (from, user, counters) = (Holder {device, inbound: at, peer}, plan.devices[device].user, &self.counters);
		counters.users[user].up(raw.len());
		counters.inbounds[at].up(raw.len());
		let Some(packet) = netstack::parse(&raw) else {return counters.count(Reason::Unparsable)};
		if packet.fragment {return counters.count(Reason::Fragment)}
		raw.truncate(packet.len);
		// A device speaks only from its own address in the tunnel the packet arrived through.
		if plan.by_address.get(&packet.src) != Some(&from) {
			tracing::debug!("inbound {}: a device of user {} sent from an address that is not its own", plan.inbounds[at].tag, plan.users[user].name);
			return counters.count(Reason::SpoofedSource);
		}
		let transport = packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP;
		let gateway = plan.is_gateway(packet.dst);
		// A gateway answers DNS and nothing else. With hijack on, every UDP and TCP port 53 flow is DNS for the node wherever it was sent.
		let dns = packet.dport == 53 && transport && (gateway || plan.hijack);
		let local = !dns && !gateway && plan.pool_of(packet.dst).is_some();
		if (gateway && !dns) || (!dns && !local && gate::refused(packet.dst, &plan.pools)) {return self.refuse(plan, from, &raw, &packet, Reason::Gate, true).await}
		let key = Key::of(&packet);
		// The answer to a flow that was delivered between users belongs to that flow, whatever the rules say about the other direction.
		// It is looked for first: a refusal remembered for this side's own earlier try must not shut the answer out.
		let (id, decision) = if local && key.reversed().and_then(|back| self.flows.get(&back)).is_some_and(|(_, decision)| decision == Decision::Deliver) {(0, Decision::Deliver)}
		else if let Some(known) = self.flows.get(&key) {known} else {
			// A flow may only leave through an exit in its user's `exits`, whatever chose it. That is final: the flow is rejected and never falls through to another rule.
			let entitled = |exit: usize| plan.users[user].entitled.as_ref().is_none_or(|list| list.contains(&exit));
			// The resolver routes each query of a DNS flow by itself, by the server it goes to and the name it asks for.
			let decision = if dns {Decision::Dns} else {match route::evaluate(plan, at, user, packet.dst, packet.protocol, packet.dport, packet.icmp, &|patterns| self.resolver.names(user).matches(packet.dst, patterns, Instant::now())) {
				Action::Block => Decision::Refuse {reason: Reason::Rule, reset: false},
				Action::Reject => Decision::Refuse {reason: Reason::Rule, reset: true},
				// Traffic between users never leaves through an exit: any outcome but a refusal is delivery inside the node.
				_ if local => Decision::Deliver,
				// The node's own addresses are known only to the host.
				_ if (self.is_local)(packet.dst) => Decision::Refuse {reason: Reason::Gate, reset: true},
				action => {
					let exit = if let Action::Exit(exit) = action {*exit} else {plan.users[user].exit.unwrap_or(plan.default_exit)};
					match &plan.exits[exit].backend {
						_ if !entitled(exit) => Decision::Refuse {reason: Reason::Entitlement, reset: true},
						Backend::Block => Decision::Refuse {reason: Reason::BlockExit, reset: false},
						Backend::L3 {..} => Decision::Exit {exit, by: By::Backend},
						Backend::Netstack {outbound: Outbound::Direct {bind: Some(bind)}, ..} if bind.is_ipv4() != packet.dst.is_ipv4() => Decision::Refuse {reason: Reason::Unsupported, reset: true},
						// Whether the proxy relays UDP is only known once the flow's handler has asked it, so the `udp` policy is applied there, see `flows::run`.
						Backend::Netstack {..} if transport => Decision::Exit {exit, by: By::Backend},
						Backend::Netstack {icmp_echo, other, ..} => match if packet.echo_request() {*icmp_echo} else {*other} {
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
			}};
			let Ok(id) = self.flows.insert(key, plan.devices[device].public_key, &plan.users[user].name, decision) else {return counters.count(Reason::FlowTableFull)};
			tracing::debug!("inbound {}: user {}: new flow, protocol {} to {}: {decision:?}", plan.inbounds[at].tag, plan.users[user].name, packet.protocol, plan.show(SocketAddr::new(packet.dst, packet.dport)));
			(id, decision)
		};
		if let Decision::Exit {exit, ..} = decision {counters.exits[exit].up(raw.len())}
		self.carry(plan, from, raw, &packet, key, id, decision).await
	}

	/// Does with one packet of a flow what the flow's decision says. `from` is the device that sent it and `id` the flow's entry in the table.
	#[allow(clippy::too_many_arguments)]
	pub(super) async fn carry(self: &Arc<Self>, plan: &Arc<Plan>, from: Holder, raw: Vec<u8>, packet: &Packet, key: Key, id: u64, decision: Decision) {
		let (counters, transport) = (&self.counters, packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP);
		match decision {
			Decision::Refuse {reason, reset} => self.refuse(plan, from, &raw, packet, reason, reset).await,
			Decision::Deliver => {
				let to = plan.by_address.get(&packet.dst).copied().filter(|to| self.tunnels[to.inbound].lock().wg.time_since_last_handshake(to.peer).is_some());
				match to {
					// The sender is in a tunnel, so it can be told what does fit.
					Some(to) if raw.len() > usize::from(plan.inbounds[to.inbound].mtu) => {
						counters.count(Reason::TooBig);
						self.icmp_error(plan, from, &raw, packet, Kind::TooBig(plan.inbounds[to.inbound].mtu)).await
					}
					Some(to) => self.send(plan, to, &raw).await,
					None => self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await,
				}
			}
			Decision::Dns => if self.tunnels[from.inbound].to_stack.try_send(raw).is_err() {counters.count(Reason::QueueFull)},
			Decision::Exit {exit, by} => {
				// What a `via` hands on counts for the exit that carries it as well as for the one the rules chose.
				let carrier = if let By::Via(target) = by {
					counters.exits[target].up(raw.len());
					target
				} else {exit};
				match (by, &plan.exits[carrier].backend) {
					(By::Local, _) => match netstack::echo_reply(&raw, packet) {
						Some(reply) => {
							counters.exits[exit].down(reply.len());
							self.send(plan, from, &reply).await;
						}
						None => counters.count(Reason::Unsupported),
					},
					// One ping socket for each identifier a device pings a destination under, because the kernel answers a socket only with the replies to its own identifier.
					(By::Direct, _) if !transport => {
						let Some(message) = raw.get(packet.upper..).filter(|message| message.len() >= 8) else {return counters.count(Reason::Unparsable)};
						let ping = (packet.src, packet.dst, u16::from_be_bytes([message[4], message[5]]));
						let (user, mut pings) = (plan.devices[from.device].user, self.pings.lock().unwrap_or_else(|e| e.into_inner()));
						match pings.get(&ping) {
							Some((.., to)) => if to.try_send(message.to_vec()).is_err() {counters.count(Reason::QueueFull)},
							None if pings.len() >= icmp::MAX_PINGS || pings.values().filter(|(_, of, _)| *of == user).count() >= icmp::MAX_PINGS_PER_USER || pings.values().filter(|(device, ..)| *device == from.device).count() >= icmp::MAX_PINGS_PER_DEVICE => counters.count(Reason::FlowTableFull),
							None => {
								let (to, requests) = mpsc::channel(icmp::PING_QUEUE);
								let _ = to.try_send(message.to_vec());
								pings.insert(ping, (from.device, user, to));
								tokio::spawn(icmp::ping(self.clone(), plan.clone(), exit, from, ping, requests));
							}
						}
					}
					(By::Backend | By::Via(_), Backend::L3 {..}) => {
						let Some(port) = &self.l3[carrier] else {return counters.count(Reason::Unsupported)};
						// The sender is in a tunnel, so it can be told what does fit.
						if raw.len() > usize::from(port.mtu) {
							counters.count(Reason::TooBig);
							return self.icmp_error(plan, from, &raw, packet, Kind::TooBig(port.mtu)).await;
						}
						if packet.protocol == Protocol::TCP && raw.get(packet.upper + TCP_FLAGS).is_some_and(|flags| flags & FIN_OR_RST != 0) {self.flows.track(&key, id, FLOW_IDLE, true)}
						if port.to.try_send(raw).is_err() {counters.count(Reason::QueueFull)}
					}
					_ if transport => if self.tunnels[from.inbound].to_stack.try_send(raw).is_err() {counters.count(Reason::QueueFull)},
					_ => counters.count(Reason::Unsupported),
				}
			}
		}
	}

	/// One packet the kernel routed into the interface of l3 exit `exit`. Whoever can reach the host can aim packets at it, so a packet is delivered only to the device that holds its destination address,
	/// and only as the answer to a live flow of that device which left through this exit: the flow's own reverse, or an ICMP error that quotes a packet of the flow. Everything else is counted and dropped.
	#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
	pub(super) async fn returned(&self, plan: &Plan, exit: usize, mut raw: Vec<u8>) {
		let counters = &self.counters;
		let Some(packet) = netstack::parse(&raw) else {return counters.count(Reason::Unparsable)};
		if packet.fragment {return counters.count(Reason::Fragment)}
		raw.truncate(packet.len);
		let Some(to) = plan.by_address.get(&packet.dst).copied() else {return counters.count(Reason::NoFlow)};
		// Destination unreachable, time exceeded and parameter problem, and for ICMPv6 packet too big as well.
		let error = matches!((packet.protocol, packet.icmp), (Protocol::ICMP, Some((3 | 11 | 12, _))) | (Protocol::ICMPV6, Some((1..=4, _))));
		let key = if error {raw.get(packet.upper + 8..).and_then(netstack::quoted).filter(|quoted| quoted.src == packet.dst && !quoted.fragment).map(|quoted| Key::of(&quoted))} else {Key::of(&packet).reversed()};
		let (key, id, chosen, by) = match key.and_then(|key| self.flows.get(&key).map(|flow| (key, flow))) {
			Some((key, (id, Decision::Exit {exit: chosen, by}))) if (chosen == exit && by == By::Backend) || by == By::Via(exit) => (key, id, chosen, by),
			_ => return counters.count(Reason::NoFlow),
		};
		// The interface has the smallest MTU of all inbounds, so this only happens when the host was set up otherwise. The sender is out on the network and gets no answer from here.
		if raw.len() > usize::from(plan.inbounds[to.inbound].mtu) {return counters.count(Reason::TooBig)}
		// A flow a `via` handed over is kept by its handler. Any other lives by what its packets say: long once the far side has answered, short again after a FIN or RST.
		if by == By::Backend && !error {
			let (idle, closing) = match packet.protocol {
				Protocol::TCP => (l3::TCP_IDLE, raw.get(packet.upper + TCP_FLAGS).is_some_and(|flags| flags & FIN_OR_RST != 0)),
				Protocol::UDP => (l3::UDP_IDLE, false),
				_ => (FLOW_IDLE, false),
			};
			self.flows.track(&key, id, idle, closing);
		}
		counters.exits[exit].down(raw.len());
		if chosen != exit {counters.exits[chosen].down(raw.len())}
		self.send(plan, to, &raw).await
	}
}

/// Starts the tasks of inbound `at`: one reader per socket, the stack's replies, the WireGuard timers and the flows the stack accepts.
pub fn spawn(shared: &Arc<Shared>, at: usize, mut stack: IpStack, mut from_stack: Receiver<Vec<u8>>) {
	for (via, socket) in shared.tunnels[at].sockets.iter().cloned().enumerate() {
		let shared = shared.clone();
		tokio::spawn(async move {
			let mut buf = vec![0u8; MAX_PACKET];
			let (mut net_out, mut ip_out) = (Vec::new(), Vec::new());
			loop {
				let Ok((n, from)) = socket.recv_from(&mut buf).await else {continue};
				net_out.clear();
				ip_out.clear();
				let peer = {
					let mut peers = shared.tunnels[at].lock();
					let received = peers.wg.recv_authenticated(from, &buf[..n], &mut net_out, &mut ip_out);
					if let Some((peer, true)) = received {peers.via[peer] = via}
					received.map(|(peer, _)| peer)
				};
				for datagram in &net_out {let _ = socket.send_to(datagram, from).await;}
				let Some(peer) = peer else {continue};
				let plan = shared.plan();
				for packet in ip_out.drain(..) {shared.ingress(&plan, at, peer, packet).await}
			}
		});
	}
	// Stack -> peer: the reply goes to whoever holds its destination address in this tunnel.
	tokio::spawn({
		let shared = shared.clone();
		async move {
			while let Some(raw) = from_stack.recv().await {
				let plan = shared.plan();
				let Some(packet) = netstack::parse(&raw) else {continue};
				let Some(to) = plan.by_address.get(&packet.dst).copied().filter(|to| to.inbound == at) else {continue};
				if let Some((_, Decision::Exit {exit, by})) = Key::of(&packet).reversed().and_then(|key| shared.flows.get(&key)) {
					shared.counters.exits[exit].down(raw.len());
					if let By::Via(target) = by {shared.counters.exits[target].down(raw.len())}
				}
				shared.send(&plan, to, &raw).await;
			}
		}
	});
	tokio::spawn({
		let shared = shared.clone();
		async move {
			let mut tick = tokio::time::interval(TIMER_EVERY);
			let mut out = Vec::new();
			loop {
				tick.tick().await;
				out.clear();
				let targets: Vec<Option<(SocketAddr, usize)>> = {
					let mut peers = shared.tunnels[at].lock();
					peers.wg.update_timers(&mut out);
					out.iter().map(|(peer, _)| peers.wg.endpoint(*peer).map(|endpoint| (endpoint, peers.via[*peer]))).collect()
				};
				for ((_, datagram), target) in out.iter().zip(targets) {
					if let Some((endpoint, via)) = target {let _ = shared.tunnels[at].sockets[via].send_to(datagram, endpoint).await;}
				}
			}
		}
	});
	// Accepted flows: the routing decision made for the first packet is waiting in the flow table.
	tokio::spawn({
		let shared = shared.clone();
		async move {
			loop {
				let stream = match stack.accept().await {
					Ok(stream) => stream,
					Err(e) => return tracing::error!("inbound {}: the userspace stack stopped: {e}", shared.plan().inbounds[at].tag),
				};
				let (protocol, src, dst) = match &stream {
					IpStackStream::Tcp(s) => (Protocol::TCP, s.local_addr(), s.peer_addr()),
					IpStackStream::Udp(s) => (Protocol::UDP, s.local_addr(), s.peer_addr()),
					_ => continue,
				};
				let (plan, key) = (shared.plan(), Key {protocol, src: src.ip(), dst: dst.ip(), sport: src.port(), dport: dst.port()});
				let (mtu, from) = (plan.inbounds[at].mtu, plan.by_address.get(&key.src).copied());
				match (shared.flows.get(&key), from) {
					(Some((id, Decision::Exit {exit, by})), Some(from)) => drop(tokio::spawn(flows::run(shared.clone(), plan, key, id, exit, by, from, stream, mtu))),
					(Some((id, Decision::Dns)), Some(from)) => drop(tokio::spawn(resolver::serve(shared.clone(), plan.clone(), key, id, at, plan.devices[from.device].user, stream, mtu))),
					_ => {}
				}
			}
		}
	});
}
