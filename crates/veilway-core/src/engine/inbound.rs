//! One inbound at run time: its WireGuard tunnel, the sockets it is reached over, and the path every decrypted packet takes before it may go anywhere.
use super::icmp::{self, Kind};
use super::netstack::{self, Packet};
use super::netstack::Fit;
use super::plan::{Action, Backend, Fallback, Holder, Outbound, Plan};
use super::obfs::{self, Room};
use super::route::{self, By, Decision, Key, Reason, FLOW_IDLE};
use super::{chain, control, faketls, flows, gate, l3, link, resolver, stream, Over, Shared};
use crate::config::{Protocol, RuleTransport};
use ipstack::{IpStack, IpStackStream};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::AbortHandle;
use veilway_proto::control::PORT;
use veilway_wg::{Wg, MAX_PACKET};

const TIMER_EVERY: Duration = Duration::from_millis(250);
/// How far apart the log lines of sends that fail are.
const UNSENT_EVERY: Duration = Duration::from_secs(60);
/// The FIN and RST bits in the flags byte of a TCP header, which is its 14th.
const TCP_FLAGS: usize = 13;
const FIN_OR_RST: u8 = 0x05;

/// How a peer's last authenticated datagram reached its tunnel, which is the way replies leave: a socket that carries WireGuard as it is, a `udp-obfs` session on a socket, or the session of a stream transport on its connection. Nothing leaves once the transport, or the session, is gone.
#[derive(Clone)]
pub enum Via {None, Socket(Weak<UdpSocket>, Over), Obfs(Weak<UdpSocket>, Weak<obfs::Session>), Stream(Weak<stream::Session>), FakeTls(Weak<faketls::Session>), Dial(Weak<link::Dialler>)}

/// A way to a peer that is there right now.
#[derive(Clone)]
/// `Dial` is the session of a node link this node dials, which the client's side of the transports holds.
pub enum Route {Socket(Arc<UdpSocket>, SocketAddr), Obfs(Arc<UdpSocket>, Arc<obfs::Session>), Stream(Arc<stream::Session>), FakeTls(Arc<faketls::Session>), Dial(Arc<link::Dialler>)}

impl Route {
	/// Whether what leaves this way travels in chunks, whose padding goes by what a datagram holds.
	pub fn padded(&self) -> bool {matches!(self, Route::Obfs(..) | Route::Stream(..) | Route::FakeTls(..))}

	/// Sends one WireGuard datagram. `control` says it holds a control channel packet, which a session of an obfuscated transport pads wide like a handshake message (transports page, "Padding", rule 2), and `room` how large a `udp-obfs` session may make its packet.
	/// `tunnel` is the peer's, which counts a datagram no socket took. A stream session never waits: its connection has a queue, and a datagram the queue has no room for is dropped and counted.
	pub async fn send(&self, tunnel: &Arc<Tunnel>, datagram: &[u8], control: bool, room: Room) {
		match self {
			Route::Socket(socket, to) => tunnel.sent(socket.send_to(datagram, *to).await),
			Route::Obfs(socket, session) => session.send(tunnel, socket, datagram, control, room).await,
			Route::Stream(session) => session.push(datagram, control),
			Route::FakeTls(session) => session.push(datagram, control),
			Route::Dial(dialler) => dialler.push(datagram),
		}
	}

	/// `send` that never waits: a socket that cannot take the datagram right now loses it, like any packet on a full queue, and it is counted like any that was not sent.
	pub fn try_send(&self, tunnel: &Tunnel, datagram: &[u8], control: bool) {
		match self {
			Route::Socket(socket, to) => tunnel.sent(socket.try_send_to(datagram, *to)),
			Route::Obfs(socket, session) => if let Some(sealed) = session.seal(Some(datagram), control, Room::Inbound) {tunnel.sent(socket.try_send_to(&sealed, session.source))},
			Route::Stream(session) => session.push(datagram, control),
			Route::FakeTls(session) => session.push(datagram, control),
			Route::Dial(dialler) => dialler.push(datagram),
		}
	}
}

pub struct Peers {
	pub wg: Wg,
	/// For each peer index, how its last authenticated datagram came in.
	pub via: Vec<Via>,
}

impl Peers {
	/// Makes a device a peer. It fails only for a key that already is one, which validation rules out.
	pub fn add(&mut self, public_key: [u8; 32], preshared_key: Option<[u8; 32]>) {
		match self.wg.add_peer(public_key, preshared_key, None) {
			Ok(peer) => {
				if self.via.len() <= peer {self.via.resize(peer + 1, Via::None)}
				self.via[peer] = Via::None;
			}
			Err(e) => tracing::error!("a device could not be made a peer of its tunnel: {e}"),
		}
	}

	pub fn heard(&mut self, peer: usize, via: Via) {
		if let Some(slot) = self.via.get_mut(peer) {*slot = via}
	}

	/// Where a datagram for the peer goes right now. None for a peer that was never heard, or whose transport or session is gone.
	pub fn route(&self, peer: usize) -> Option<Route> {
		match self.via.get(peer)? {
			Via::None => None,
			Via::Socket(socket, _) => socket.upgrade().zip(self.wg.endpoint(peer)).map(|(socket, to)| Route::Socket(socket, to)),
			Via::Obfs(socket, session) => socket.upgrade().zip(session.upgrade().filter(|session| session.live())).map(|(socket, session)| Route::Obfs(socket, session)),
			Via::Stream(session) => session.upgrade().filter(|session| session.live()).map(Route::Stream),
			Via::FakeTls(session) => session.upgrade().filter(|session| session.live()).map(Route::FakeTls),
			Via::Dial(dialler) => dialler.upgrade().map(Route::Dial),
		}
	}

	/// The kind of transport the peer was last heard over, while that is still there.
	pub fn over(&self, peer: usize) -> Option<Over> {
		match self.via.get(peer)? {
			Via::None | Via::Dial(_) => None,
			Via::Socket(socket, over) => (socket.strong_count() > 0).then_some(*over),
			Via::Obfs(socket, session) => (socket.strong_count() > 0 && session.upgrade().is_some_and(|session| session.live())).then_some(Over::UdpObfs),
			Via::Stream(session) => session.upgrade().filter(|session| session.live()).map(|session| session.over),
			Via::FakeTls(session) => session.upgrade().filter(|session| session.live()).map(|_| Over::FakeTls),
		}
	}
}

/// The tunnel of one inbound. It lives for as long as the inbound keeps its tag, key, pools and MTU, across reloads, and its sessions with it.
pub struct Tunnel {
	pub tag: String,
	pub peers: Mutex<Peers>,
	pub to_stack: Sender<Vec<u8>>,
	/// Datagrams the node made for a device of the tunnel and could not hand to a socket, and when that was last logged.
	pub unsent: AtomicU64,
	pub said: Mutex<Option<Instant>>,
}

impl Tunnel {
	pub fn new(tag: String, peers: Peers, to_stack: Sender<Vec<u8>>) -> Tunnel {Tunnel {tag, peers: Mutex::new(peers), to_stack, unsent: AtomicU64::new(0), said: Mutex::default()}}

	pub fn lock(&self) -> MutexGuard<'_, Peers> {self.peers.lock().unwrap_or_else(|e| e.into_inner())}

	/// Takes what a socket said to a datagram of the node: a send that failed is counted, and logged at info when it is the first, or the first in a minute. A socket of a `veilway` inbound never fragments, so a packet above what the host's interface carries fails here and nowhere else.
	pub fn sent(&self, result: io::Result<usize>) {
		let Err(e) = result else {return};
		let failed = self.unsent.fetch_add(1, Ordering::Relaxed) + 1;
		let said = self.said.lock().unwrap_or_else(|e| e.into_inner()).replace(Instant::now());
		if said.is_none_or(|said| said.elapsed() >= UNSENT_EVERY) {tracing::info!("inbound {}: a packet for a device could not be sent ({}), {failed} since start. A packet larger than the host's interface carries is refused by the system on a veilway inbound, which never fragments: lower the inbound's mtu if this goes on", self.tag, e.kind())}
	}
}

impl Shared {
	/// Encrypts one IP packet for the device that holds an address and sends it where that device was last heard from.
	/// The device is found by its public key, so a holder from a plan that has been replaced never reaches whoever took its place.
	/// A device without a live session is sent nothing: a peer that is given a packet then keeps it for the next handshake, and a device that was cut off or has only just been added would get what was meant for the session before.
	/// A packet above the MTU the device set on the control channel is one the node wrote or forwards as its sender would have: it is fragmented the way the sending host does it, IPv4 or IPv6 (control channel page, "What the node does with a device's MTU").
	/// That covers what the stack of a netstack exit builds, UDP and TCP alike: the stack cuts its segments to the inbound's `mtu` and knows nothing of a device's. Whoever forwards a packet somebody else sent decides by `netstack::forward` before it comes here.
	/// A device that set no MTU is sent every packet as it is, as before there was a control channel. The answer is the bytes that went into the tunnel, fragment headers included, and 0 for a device without a session.
	pub(super) async fn send(&self, plan: &Plan, to: Holder, packet: &[u8]) -> usize {
		let Some(mtu) = plan.devices[to.device].control.mtu().filter(|mtu| packet.len() > usize::from(*mtu)) else {return self.transmit(plan, to, packet).await};
		let (pieces, mut sent) = (netstack::fragments(packet, mtu, Some(plan.devices[to.device].control.fragment())), 0);
		if pieces.is_empty() {self.count(Reason::TooBig)}
		for piece in &pieces {sent += self.transmit(plan, to, piece).await}
		sent
	}

	/// `send` for a packet that goes out whole whatever MTU the device set: what `send` has cut to fit, and what was forwarded by the device's MTU already.
	pub(super) async fn transmit(&self, plan: &Plan, to: Holder, packet: &[u8]) -> usize {self.emit(plan, to, packet, Room::Mtu(plan.mtu_of(to))).await}

	/// An MTU probe: it goes out whole and at exactly its own size on every datagram transport, so what arrives says what the path carries.
	pub(super) async fn probe(&self, plan: &Plan, to: Holder, packet: &[u8]) -> usize {self.emit(plan, to, packet, Room::Exact).await}

	async fn emit(&self, plan: &Plan, to: Holder, packet: &[u8], room: Room) -> usize {
		let (inbound, device, mut out) = (&plan.inbounds[to.inbound], &plan.devices[to.device], Vec::new());
		let link = device.link.map(|link| &plan.links[link]);
		// "Nothing is fragmented for a link, in either direction. The other node drops fragments", and "both nodes lower the segment size in every TCP opening packet that crosses the link".
		if link.is_some_and(|link| packet.len() > usize::from(link.mtu)) {
			self.count(Reason::TooBig);
			return 0;
		}
		let clamped = link.and_then(|link| netstack::parse(packet).filter(|parsed| parsed.protocol == Protocol::TCP).map(|parsed| {
			let mut raw = packet.to_vec();
			chain::clamp(&mut raw, &parsed, link.mtu);
			raw
		}));
		let packet = clamped.as_deref().unwrap_or(packet);
		let route = {
			let mut peers = inbound.tunnel.lock();
			let Some(peer) = peers.wg.index(&plan.peer_of(to.device)).filter(|peer| peers.wg.time_since_last_handshake(*peer).is_some()) else {return 0};
			peers.wg.encapsulate(peer, packet, &mut out);
			peers.route(peer)
		};
		let Some(route) = route else {return 0};
		self.spend(&plan.users[device.user], false, packet.len());
		inbound.traffic.down(packet.len());
		if let Some(link) = link {link.state.traffic.up(packet.len())}
		// What the control channel sends is a TCP segment from the gateway's control port.
		let control = route.padded() && netstack::parse(packet).is_some_and(|parsed| parsed.protocol == Protocol::TCP && parsed.sport == PORT && plan.control(to.inbound, parsed.src));
		for datagram in &out {route.send(&inbound.tunnel, datagram, control, room).await}
		packet.len()
	}

	/// Sends the device that sent `raw` the ICMP error for it, from the gateway of the tunnel it came through, which is the router that turned it away. Each device is sent only so many, see `icmp::Limit`.
	pub(super) async fn icmp_error(&self, plan: &Plan, to: Holder, raw: &[u8], packet: &Packet, kind: Kind) {
		let Some(gateway) = plan.gateway(to.inbound, packet.src.is_ipv4()) else {return};
		let Some(error) = icmp::error(raw, packet, kind, gateway, &plan.pools) else {return};
		if !plan.devices[to.device].limit.lock().unwrap_or_else(|e| e.into_inner()).take(Instant::now()) {return self.count(Reason::IcmpLimited)}
		self.send(plan, to, &error).await;
	}

	/// Counts a packet that is not carried. When the flow is to be answered, TCP gets a reset and everything else the ICMP error that matches the reason.
	pub(super) async fn refuse(&self, plan: &Plan, from: Holder, raw: &[u8], packet: &Packet, reason: Reason, answer: bool) {
		self.count(reason);
		if !answer {return}
		if packet.protocol == Protocol::TCP {
			// A link is sent so many resets, from the same share as its ICMP errors.
			if plan.devices[from.device].link.is_some() && !plan.devices[from.device].limit.lock().unwrap_or_else(|e| e.into_inner()).take(Instant::now()) {return self.count(Reason::IcmpLimited)}
			if let Some(rst) = netstack::tcp_rst(raw) {self.send(plan, from, &rst).await;}
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

	/// What is to be done with a flow of `device` that came in on inbound `at`, by the gate, the rules and the exits of `plan`. `names` is what the user had resolved to the destination when the flow began.
	/// A new flow is decided here from its first packet, and when the plan changes every live flow is decided again from its key, so the two can never disagree.
	pub(super) fn decide(&self, plan: &Plan, at: usize, device: usize, key: &Key, names: &[Arc<str>], session: Option<RuleTransport>) -> Decision {
		let (transport, gateway, user, linked) = (key.protocol == Protocol::TCP || key.protocol == Protocol::UDP, plan.is_gateway(key.dst), plan.devices[device].user, plan.devices[device].link);
		// Before the rules and before any exit, the way gateway DNS is: no rule can block, redirect or open it, and `dns.hijack` has nothing to say about it. Only the gateway of the inbound the flow came in through answers, and only on a `veilway` inbound. A link "is never served the control channel".
		if key.protocol == Protocol::TCP && key.dport == PORT && plan.control(at, key.dst) && linked.is_none() {return Decision::Control}
		// A flow of ICMP is known by its type and code, which stand where the ports of another flow do.
		let icmp = (key.protocol == Protocol::ICMP || key.protocol == Protocol::ICMPV6).then_some((key.sport as u8, key.dport as u8));
		let dport = if icmp.is_some() {0} else {key.dport};
		// A gateway answers DNS, ping (in `ingress`), the control channel on a `veilway` inbound, and nothing else. With hijack on, every UDP and TCP port 53 flow is DNS for the node wherever it was sent.
		// "`dns.hijack` does not apply to a link. Its DNS traffic was already answered by the entry's resolver, which chose its own servers, and it is routed like any other flow."
		let dns = linked.is_none() && dport == 53 && transport && (gateway || plan.hijack);
		let local = !dns && !gateway && plan.pool_of(key.dst).is_some();
		if (gateway && !dns) || (!dns && !local && gate::refused(key.dst, &plan.pools)) || plan.linked.contains(&key.dst) || linked.is_some_and(|link| plan.barred(link, key.dst)) {return Decision::Refuse {reason: Reason::Gate, reset: true}}
		// The resolver routes each query of a DNS flow by itself, by the server it goes to and the name it asks for.
		if dns {return Decision::Dns}
		// A flow may only leave through an exit in its user's `exits`, whatever chose it. That is final: the flow is rejected and never falls through to another rule.
		let entitled = |exit: usize| plan.users[user].entitled.as_ref().is_none_or(|list| list.contains(&exit));
		match self.action(plan, at, user, key, names, session) {
			Action::Block => Decision::Refuse {reason: Reason::Rule, reset: false},
			Action::Reject => Decision::Refuse {reason: Reason::Rule, reset: true},
			// Traffic between users never leaves through an exit: any outcome but a refusal is delivery inside the node.
			_ if local => Decision::Deliver,
			action => {
				let exit = if let Action::Exit(exit) = action {*exit} else {plan.exit_of(device)};
				match &plan.exits[exit].backend {
					_ if !entitled(exit) => Decision::Refuse {reason: Reason::Entitlement, reset: true},
					Backend::Block => Decision::Refuse {reason: Reason::BlockExit, reset: false},
					// "The engine also refuses, at the moment it decides a flow, to send a packet that arrived from a link into a link", unless the link has `allow_chain`. Never into an upstream, which is one device on another provider's account.
					Backend::Chain {links} if linked.is_some_and(|link| !plan.links[link].chain || plan.upstream_backed(links)) => Decision::Refuse {reason: Reason::Gate, reset: true},
					// The gateway of an upstream's profile is the engine's own: its control channel and its probes are there, and no flow of a user shares a tuple with them.
					Backend::Chain {links} if plan.reaches_upstream(links, key.dst) => Decision::Refuse {reason: Reason::Gate, reset: true},
					Backend::L3 {..} | Backend::Chain {..} => Decision::Exit {exit, by: By::Backend},
					Backend::Netstack {outbound: Outbound::Direct {bind: Some(bind), ..}, ..} if bind.is_ipv4() != key.dst.is_ipv4() => Decision::Refuse {reason: Reason::Unsupported, reset: true},
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

	/// One decrypted packet from the device with the public key `peer`, which came in on inbound `at` over a session of `session`, in the order the checks must happen: parse, source, destination, route.
	pub(super) async fn ingress(self: &Arc<Self>, plan: &Arc<Plan>, at: usize, peer: [u8; 32], mut raw: Vec<u8>, session: Option<RuleTransport>) {
		// What comes out of a node link this node is the entry half of answers flows it sent, or is dropped. What comes out of one it is the exit half of is held to the link's record as a device's packets are held to the device: "The exit treats the link as one peer and trusts nothing it says."
		let linked = plan.link_of(at, &peer);
		// Management through the link, before the entry half's early return and every rule: see `manage`.
		if let Some(link) = linked.filter(|link| plan.links[*link].manage.is_some()) {if self.manage_ingress(plan, link, &raw).await {return}}
		if let Some(link) = linked.filter(|link| plan.links[*link].entry) {return self.chain_back(plan, link, raw).await}
		// A device this plan does not know was cut off between its packet being decrypted and now, and so was a link.
		let Some(device) = linked.map_or_else(|| plan.by_key.get(&peer).copied(), |link| plan.links[link].device) else {return self.count(Reason::Stale)};
		let (from, user) = (Holder {device, inbound: at}, plan.devices[device].user);
		self.spend(&plan.users[user], true, raw.len());
		plan.inbounds[at].traffic.up(raw.len());
		if let Some(link) = linked {plan.links[link].state.traffic.down(raw.len())}
		let Some(packet) = netstack::parse(&raw) else {return self.count(Reason::Unparsable)};
		if packet.fragment {return self.count(Reason::Fragment)}
		raw.truncate(packet.len);
		// A device speaks only from its own address in the tunnel the packet arrived through, and a link from the entry's link address: "A hostile entry cannot send from any address but one."
		if plan.by_address.get(&packet.src) != Some(&from) {
			tracing::debug!("inbound {}: {} sent from an address that is not its own", plan.inbounds[at].tag, if linked.is_some() {"a link".to_string()} else {format!("a device of user {}", plan.users[user].name)});
			if let Some(link) = linked {plan.links[link].state.dropped.fetch_add(1, Ordering::Relaxed);}
			return self.count(Reason::SpoofedSource);
		}
		if let Some(link) = linked {chain::clamp(&mut raw, &packet, plan.links[link].mtu)}
		let transport = packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP;
		let gateway = plan.is_gateway(packet.dst);
		let dns = linked.is_none() && packet.dport == 53 && transport && (gateway || plan.hijack);
		let local = !dns && !gateway && plan.pool_of(packet.dst).is_some();
		// The control channel of a `veilway` inbound, at the gateway the packet came in through. Its UDP port takes MTU probes and nothing else, and answers none of them over UDP, so a datagram to it is no flow.
		let control = linked.is_none() && transport && packet.dport == PORT && plan.control(at, packet.dst);
		if control && packet.protocol == Protocol::UDP {return self.probed(plan, from, &raw, &packet)}
		if control {self.own(&plan.users[user], raw.len())}
		// The gateway of the inbound a device came in through answers its ping itself, before any rule or exit, so an app can tell that its tunnel carries packets with no exit at all. A link has no gateway to ping.
		if gateway && linked.is_none() && packet.echo_request() && plan.inbounds[at].pools.iter().any(|pool| pool.addr() == packet.dst) {
			match netstack::echo_reply(&raw, &packet) {
				Some(reply) => {
					self.charge(&plan.users[user], true, raw.len());
					self.charge(&plan.users[user], false, reply.len());
					self.send(plan, from, &reply).await;
				}
				None => self.count(Reason::Unparsable),
			}
			return;
		}
		// The gate is asked for every packet, so what it refuses takes no place in the flow table. A link address is never a destination, and what is always refused for a link is refused here too.
		if !control && ((gateway && !dns) || (!dns && !local && gate::refused(packet.dst, &plan.pools)) || plan.linked.contains(&packet.dst) || linked.is_some_and(|link| plan.barred(link, packet.dst))) {
			if let Some(link) = linked {plan.links[link].state.dropped.fetch_add(1, Ordering::Relaxed);}
			return self.refuse(plan, from, &raw, &packet, Reason::Gate, true).await;
		}
		let (key, heard) = (Key::of(&packet), if packet.protocol == Protocol::TCP {route::heard(&raw, packet.upper)} else {None});
		// The answer to a flow that was delivered between users belongs to that flow, whatever the rules say about the other direction.
		// It is looked for first: a refusal remembered for this side's own earlier try must not shut the answer out.
		let (id, decision) = if local && key.reversed().and_then(|back| self.flows.get(&back, plan.generation, None)).is_some_and(|(_, decision)| decision == Decision::Deliver) {(0, Decision::Deliver)}
		else if let Some(known) = self.flows.sent(&key, plan.generation, heard) {known} else {
			let names = if dns || control {Vec::new()} else {plan.users[user].state.names().of(packet.dst, Instant::now())};
			// `session` is the transport of the session that carried this packet, as its reader knows it. It stays with the flow: it decides the flow here and when a reload decides it again, whatever the device is on by then.
			let decision = self.decide(plan, at, device, &key, &names, session);
			let id = match self.flows.capped(key, plan.devices[device].public_key, &plan.users[user].name, decision, names, session, heard, plan.generation, if linked.is_some() {plan.users[user].flows} else {route::MAX_FLOWS_PER_DEVICE}, plan.users[user].flows, linked.is_some()) {
				Ok(id) => id,
				// "When the exit's cap for the link is reached, the exit refuses the flow with an ICMP error or a reset", within the link's share of them.
				Err(Reason::FlowTableFull) if linked.is_some() => return self.refuse(plan, from, &raw, &packet, Reason::FlowTableFull, true).await,
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
		let (transport, user) = (packet.protocol == Protocol::TCP || packet.protocol == Protocol::UDP, &plan.users[plan.devices[from.device].user]);
		match decision {
			Decision::Refuse {reason, reset} => self.refuse(plan, from, &raw, packet, reason, reset).await,
			Decision::Deliver => {
				if !self.police(user, true, raw.len()) {return}
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
					// A device that set a smaller MTU is a link of that size: what may be fragmented is, and the sender of the rest is told. The MTU is read once, and what was decided by it goes out as decided.
					Some(to) => {
						let mtu = plan.mtu_of(to);
						match netstack::forward(&raw, mtu) {
							Fit::Whole => drop(self.transmit(plan, to, &raw).await),
							Fit::Pieces(pieces) => for piece in &pieces {self.transmit(plan, to, piece).await;},
							Fit::TooBig => {
								self.count(Reason::TooBig);
								self.icmp_error(plan, from, &raw, packet, Kind::TooBig(mtu)).await
							}
						}
					}
					None => self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await,
				}
			}
			Decision::Dns | Decision::Control => {
				self.charge(user, true, raw.len());
				if plan.inbounds[from.inbound].tunnel.to_stack.try_send(raw).is_err() {self.count(Reason::QueueFull)}
			}
			Decision::Exit {exit, by} => {
				// An exit counts a packet where the packet is handed to it, so one that is dropped on the way counts for none, and only the exit that carries it counts it: what a `via` hands on is the traffic of the exit it was handed to.
				let (carrier, len) = (if let By::Via(target) = by {target} else {exit}, raw.len());
				// What the node answers itself is only charged. A TCP segment into the exit's stack is slowed down where its stream is held, see `flows::run`. Anything else over the rate is dropped here.
				if by == By::Local {self.charge(user, true, len)} else if !(packet.protocol == Protocol::TCP && matches!(plan.exits[carrier].backend, Backend::Netstack {..})) && !self.police(user, true, len) {return}
				match (by, &plan.exits[carrier].backend) {
					(By::Local, _) => match netstack::echo_reply(&raw, packet) {
						Some(reply) => {
							plan.exits[exit].traffic.up(len);
							plan.exits[exit].traffic.down(reply.len());
							self.charge(user, false, reply.len());
							self.send(plan, from, &reply).await;
						}
						None => self.count(Reason::Unsupported),
					},
					// One ping socket for each identifier a device pings a destination under, because the kernel answers a socket only with the replies to its own identifier.
					(By::Direct, _) if !transport => {
						let Some(message) = raw.get(packet.upper..).filter(|message| message.len() >= 8) else {return self.count(Reason::Unparsable)};
						let ping = (packet.src, packet.dst, u16::from_be_bytes([message[4], message[5]]));
						let (device, user, linked, mut pings) = (plan.devices[from.device].public_key, plan.users[plan.devices[from.device].user].name.as_str(), plan.devices[from.device].link.is_some(), self.pings.lock().unwrap_or_else(|e| e.into_inner()));
						match pings.get(&ping) {
							Some((.., to)) => if to.try_send(message.to_vec()).is_ok() {plan.exits[exit].traffic.up(len)} else {self.count(Reason::QueueFull)},
							None if pings.len() >= icmp::MAX_PINGS || pings.values().filter(|(_, of, _)| **of == *user).count() >= if linked {icmp::LINK_PINGS} else {icmp::MAX_PINGS_PER_USER} || pings.values().filter(|(of, ..)| *of == device).count() >= if linked {icmp::LINK_PINGS} else {icmp::MAX_PINGS_PER_DEVICE} => self.count(Reason::FlowTableFull),
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
						// The flow keeps its exit while the interface is down and never moves to another: its device is told, a reset for TCP and host unreachable for the rest.
						if port.health.down.lock().unwrap_or_else(|e| e.into_inner()).is_some() {return self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await}
						// The sender is in a tunnel, so it can be told what does fit.
						if raw.len() > usize::from(port.mtu) {
							self.count(Reason::TooBig);
							return self.icmp_error(plan, from, &raw, packet, Kind::TooBig(port.mtu)).await;
						}
						if packet.protocol == Protocol::TCP && raw.get(packet.upper + TCP_FLAGS).is_some_and(|flags| flags & FIN_OR_RST != 0) {self.flows.track(&key, id, FLOW_IDLE, true)}
						if port.to.try_send(raw).is_ok() {plan.exits[carrier].traffic.up(len)} else {self.count(Reason::QueueFull)}
					}
					(By::Backend, Backend::Chain {..}) => self.chained(plan, from, raw, packet, key, id, carrier).await,
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
		if !self.police(&plan.users[plan.devices[to.device].user], false, raw.len()) {return}
		// For this exit alone, which carried it, whichever exit the rules chose for the flow.
		plan.exits[exit].traffic.down(raw.len());
		// The device may have set a smaller MTU than its inbound has, and then the node is the router in front of a link of that size: IPv4 that allows it is fragmented, and the sender of anything else is sent "fragmentation needed" or "packet too big" with that MTU,
		// from the gateway of the device's tunnel, back through the interface the packet came in by and within the ICMP errors the device may cause. Whether that error reaches the sender is the host's forwarding and NAT to say: with `masquerade` the kernel has to take it for an answer to the flow it translates.
		let mtu = plan.mtu_of(to);
		// "Nothing is fragmented for a link": what does not fit a link goes back to its sender as too big.
		match netstack::forward(&raw, mtu) {
			Fit::Pieces(_) if plan.devices[to.device].link.is_some() => self.too_big(plan, exit, to, &raw, &packet, mtu),
			Fit::Whole => drop(self.transmit(plan, to, &raw).await),
			Fit::Pieces(pieces) => for piece in &pieces {self.transmit(plan, to, piece).await;},
			Fit::TooBig => self.too_big(plan, exit, to, &raw, &packet, mtu),
		}
	}

	/// What `returned` does with a packet the device or the link it goes to cannot take: "fragmentation needed" or "packet too big" back to its sender, through the interface it came in by.
	fn too_big(&self, plan: &Plan, exit: usize, to: Holder, raw: &[u8], packet: &Packet, mtu: u16) {
		self.count(Reason::TooBig);
		let gateway = plan.gateway(to.inbound, packet.src.is_ipv4());
		let Some(error) = gateway.and_then(|gateway| icmp::error(raw, packet, Kind::TooBig(mtu), gateway, &plan.pools)) else {return};
		// A share of its own: whoever sends the device large packets from outside must not use up the errors the device is owed for what it sends itself.
		if !plan.devices[to.device].control.outside() {return self.count(Reason::IcmpLimited)}
		let (Some((_, port)), len) = (plan.l3.as_ref().filter(|(wired, _)| *wired == exit), error.len()) else {return};
		// It leaves through the exit towards a sender outside the tunnel, so the exit counts it and the user, whose tunnel never carries it, does not.
		if port.to.try_send(error).is_ok() {plan.exits[exit].traffic.up(len)} else {self.count(Reason::QueueFull)}
	}
}

/// Reads one socket for one tunnel until the handle it returns is aborted: a `udp` transport's own socket, or the loopback socket the `ws` transports of the inbound relay to. `over` says which of the two it is.
pub fn read(shared: &Arc<Shared>, tunnel: Arc<Tunnel>, socket: Arc<UdpSocket>, over: Over) -> AbortHandle {
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
				if let Some((peer, true)) = received {peers.heard(peer, Via::Socket(Arc::downgrade(&socket), over))}
				received.and_then(|(peer, _)| peers.wg.key(peer))
			};
			for datagram in &net_out {tunnel.sent(socket.send_to(datagram, from).await)}
			let Some(peer) = peer else {continue};
			let plan = shared.plan();
			let Some(at) = plan.inbound_of(&tunnel) else {continue};
			for packet in ip_out.drain(..) {shared.ingress(&plan, at, peer, packet, Some(over.rule())).await}
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
				// A TCP flow of a limited user was slowed down by the handler of its flow. A datagram over the rate is dropped here, and DNS and the control channel are only charged.
				let user = &plan.users[plan.devices[to.device].user];
				match decision {
					Decision::Dns | Decision::Control => shared.charge(user, false, raw.len()),
					_ if packet.protocol == Protocol::UDP && !shared.police(user, false, raw.len()) => continue,
					_ => {}
				}
				// A datagram was counted when the handler of its flow took it from an outbound. A TCP flow is always carried by the exit the rules chose.
				if let (Protocol::TCP, Decision::Exit {exit, ..}) = (packet.protocol, decision) {plan.exits[exit].traffic.down(raw.len())}
				// What the control channel sends is counted as its own with the bytes that really went out, the headers of fragments included.
				let sent = shared.send(&plan, to, &raw).await;
				if decision == Decision::Control {shared.own(&plan.users[plan.devices[to.device].user], sent)}
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
				let targets: Vec<Option<Route>> = {
					let mut peers = tunnel.lock();
					peers.wg.update_timers(&mut out);
					out.iter().map(|(peer, _)| peers.route(*peer)).collect()
				};
				// What WireGuard's own timers send: a keepalive or a handshake message, never a packet of the control channel.
				for ((_, datagram), target) in out.iter().zip(targets) {
					if let Some(route) = target {route.send(&tunnel, datagram, false, Room::Inbound).await}
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
					Some((id, Decision::Control)) => drop(tokio::spawn(control::serve(shared.clone(), key, id, plan.devices[from.device].public_key, stream))),
					_ => {}
				}
			}
		}
	});
	vec![replies.abort_handle(), timers.abort_handle(), accepted.abort_handle()]
}
