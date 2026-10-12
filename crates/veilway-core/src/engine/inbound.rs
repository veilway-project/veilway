//! One inbound at run time: its WireGuard tunnel, the sockets it is reached over, and the path every decrypted packet takes before it may go anywhere.
use super::netstack;
use super::plan::{Action, Backend, Holder, Outbound, Plan};
use super::route::{self, Decision, Key, Reason};
use super::{flows, gate, resolver, Shared};
use crate::config::{Policy, Protocol};
use ipstack::{IpStack, IpStackStream};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use veilway_wg::{Wg, MAX_PACKET};

const TIMER_EVERY: Duration = Duration::from_millis(250);

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
	async fn send(&self, plan: &Plan, to: Holder, packet: &[u8]) {
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

	/// Counts a packet that is not carried and, when the flow is to be answered, resets it if it is TCP. Everything else is dropped for now.
	async fn refuse(&self, plan: &Plan, from: Holder, raw: &[u8], reason: Reason, reset: bool) {
		self.counters.count(reason);
		if let Some(rst) = netstack::tcp_rst(raw).filter(|_| reset) {self.send(plan, from, &rst).await}
	}

	/// One decrypted packet from peer `peer` of inbound `at`, in the order the checks must happen: parse, source, destination, route.
	async fn ingress(&self, plan: &Plan, at: usize, peer: usize, mut raw: Vec<u8>) {
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
		if (gateway && !dns) || (!dns && !local && gate::refused(packet.dst, &plan.pools)) {return self.refuse(plan, from, &raw, Reason::Gate, true).await}
		let key = Key::of(&packet);
		// The answer to a flow that was delivered between users belongs to that flow, whatever the rules say about the other direction.
		// It is looked for first: a refusal remembered for this side's own earlier try must not shut the answer out.
		let decision = if local && key.reversed().and_then(|back| self.flows.get(&back)).is_some_and(|(_, decision)| decision == Decision::Deliver) {Decision::Deliver}
		else if let Some((_, decision)) = self.flows.get(&key) {decision} else {
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
						// Entitlement is final: the flow is rejected and never falls through to another rule.
						_ if plan.users[user].entitled.as_ref().is_some_and(|list| !list.contains(&exit)) => Decision::Refuse {reason: Reason::Entitlement, reset: true},
						Backend::Block => Decision::Refuse {reason: Reason::BlockExit, reset: false},
						Backend::Netstack {outbound: Outbound::Direct {bind: Some(bind)}, ..} if bind.is_ipv4() != packet.dst.is_ipv4() => Decision::Refuse {reason: Reason::Unsupported, reset: true},
						Backend::Netstack {..} => Decision::Exit {exit},
					}
				}
			}};
			if self.flows.insert(key, plan.devices[device].public_key, &plan.users[user].name, decision).is_err() {return counters.count(Reason::FlowTableFull)}
			tracing::debug!("inbound {}: user {}: new flow, protocol {} to {}: {decision:?}", plan.inbounds[at].tag, plan.users[user].name, packet.protocol, plan.show(SocketAddr::new(packet.dst, packet.dport)));
			decision
		};
		match decision {
			Decision::Refuse {reason, reset} => self.refuse(plan, from, &raw, reason, reset).await,
			Decision::Deliver => {
				let to = plan.by_address.get(&packet.dst).copied().filter(|to| raw.len() <= usize::from(plan.inbounds[to.inbound].mtu) && self.tunnels[to.inbound].lock().wg.time_since_last_handshake(to.peer).is_some());
				match to {
					Some(to) => self.send(plan, to, &raw).await,
					None => self.refuse(plan, from, &raw, Reason::Unreachable, true).await,
				}
			}
			Decision::Dns => if self.tunnels[at].to_stack.try_send(raw).is_err() {counters.count(Reason::QueueFull)},
			Decision::Exit {exit} if transport => {
				counters.exits[exit].up(raw.len());
				if self.tunnels[at].to_stack.try_send(raw).is_err() {counters.count(Reason::QueueFull)}
			}
			Decision::Exit {exit, ..} => {
				counters.exits[exit].up(raw.len());
				// A netstack exit carries TCP and UDP only. Of its `unsupported` policy only ping answered by the node is built so far:
				// the ICMP errors of `reject`, and `direct` and `via`, go here.
				let reply = match &plan.exits[exit].backend {
					Backend::Netstack {icmp_echo: Policy::Local, ..} => netstack::echo_reply(&raw, &packet),
					_ => None,
				};
				match reply {
					Some(reply) => {
						counters.exits[exit].down(reply.len());
						self.send(plan, from, &reply).await;
					}
					None => counters.count(Reason::Unsupported),
				}
			}
		}
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
				if let Some((_, Decision::Exit {exit, ..})) = Key::of(&packet).reversed().and_then(|key| shared.flows.get(&key)) {shared.counters.exits[exit].down(raw.len())}
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
					(Some((id, Decision::Exit {exit})), _) => drop(tokio::spawn(flows::run(shared.clone(), plan, key, id, exit, stream, mtu))),
					(Some((id, Decision::Dns)), Some(from)) => drop(tokio::spawn(resolver::serve(shared.clone(), plan.clone(), key, id, at, plan.devices[from.device].user, stream, mtu))),
					_ => {}
				}
			}
		}
	});
}
