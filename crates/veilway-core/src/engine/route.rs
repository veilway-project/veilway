//! Routing: the rules a flow's first packet is matched against, and the bounded table that keeps the decision for the rest of the flow.
use super::gate;
use super::netstack::{Packet, ECHO_REPLY_V4, ECHO_REPLY_V6, ECHO_REQUEST_V4, ECHO_REQUEST_V6};
use super::plan::{Action, IpMatch, Plan};
use crate::config::Protocol;
use ipnet::IpNet;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Flows the table carries: in total, per user across all their devices, and per device. A user may have many devices, so the
/// device share alone would let one user take the whole table, and the total is far above one user's share so that it takes many users to reach it.
pub const MAX_FLOWS: usize = 65536;
pub const MAX_FLOWS_PER_USER: usize = 1024;
pub const MAX_FLOWS_PER_DEVICE: usize = 512;
/// Refused flows remembered at once. They are counted apart from the flows above and the oldest gives way to a new one.
pub const MAX_REFUSALS: usize = 4096;
/// How long a flow is kept after its last packet while no handler holds it: a flow delivered between users, or one the stack has not accepted yet.
pub const FLOW_IDLE: Duration = Duration::from_secs(30);
/// The same for a flow that carries nothing: one that was refused, or one whose handler has ended and only sees stragglers. Short, so such flows do not use up a device's share of the table.
pub const CLOSED_IDLE: Duration = Duration::from_secs(10);

/// Why a packet was not carried. Each has a counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
	Unparsable,
	Fragment,
	SpoofedSource,
	/// The destination gate: a gateway on anything but DNS, loopback, link-local, the node itself and the like.
	Gate,
	/// A `block` or `reject` rule.
	Rule,
	/// The exit that was chosen is not in the user's `exits`.
	Entitlement,
	FlowTableFull,
	/// A tunnel address no connected device holds.
	Unreachable,
	/// Traffic the chosen exit cannot carry.
	Unsupported,
	/// An exit with a `block` backend.
	BlockExit,
	/// The queue into the userspace stack was full.
	QueueFull,
}

impl Reason {
	pub const COUNT: usize = 11;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
	/// Leaves through this exit. `dns` relays it to the configured resolver instead of the address it was sent to.
	Exit {exit: usize, dns: bool},
	/// Handed to the device that holds the destination address.
	Deliver,
	Refuse {reason: Reason, reset: bool},
}

/// What tells one flow from another: the 5-tuple for TCP, UDP and SCTP, and for ICMP the type and code in the place of the ports,
/// so that a rule on either decides for each kind of message by itself. Anything else is one flow per address pair and protocol, with both ports zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {pub protocol: u8, pub src: IpAddr, pub dst: IpAddr, pub sport: u16, pub dport: u16}

impl Key {
	pub fn of(packet: &Packet) -> Key {
		let (sport, dport) = packet.icmp.map_or((packet.sport, packet.dport), |(kind, code)| (u16::from(kind), u16::from(code)));
		Key {protocol: packet.protocol, src: packet.src, dst: packet.dst, sport, dport}
	}

	/// The flow this one answers. For ICMP only an echo reply answers anything, the echo request: were every message the answer
	/// to every other, one message the rules allow would open the way back for those they refuse.
	pub fn reversed(&self) -> Option<Key> {
		let (sport, dport) = match (self.protocol, u8::try_from(self.sport)) {
			(Protocol::ICMP, Ok(ECHO_REPLY_V4)) => (u16::from(ECHO_REQUEST_V4), self.dport),
			(Protocol::ICMPV6, Ok(ECHO_REPLY_V6)) => (u16::from(ECHO_REQUEST_V6), self.dport),
			(Protocol::ICMP | Protocol::ICMPV6, _) => return None,
			_ => (self.dport, self.sport),
		};
		Some(Key {protocol: self.protocol, src: self.dst, dst: self.src, sport, dport})
	}
}

/// `owner` is the device and the user a carried flow counts against. A refusal has none: it counts against nobody.
struct Entry {id: u64, owner: Option<([u8; 32], Arc<str>)>, decision: Decision, seen: Instant, idle: Duration}

#[derive(Default)]
struct Table {
	flows: HashMap<Key, Entry>,
	per_device: HashMap<[u8; 32], usize>,
	per_user: HashMap<Arc<str>, usize>,
	/// Entries that are not refusals.
	carried: usize,
	/// Refusals in the order they were made, by key and entry id. One that has expired stays here until the next sweep.
	refusals: VecDeque<(Key, u64)>,
	next: u64,
}

impl Table {
	fn remove(&mut self, key: &Key) {
		let Some(Entry {owner: Some((device, user)), ..}) = self.flows.remove(key) else {return};
		self.carried -= 1;
		if let Some(count) = self.per_device.get_mut(&device) {
			*count -= 1;
			if *count == 0 {self.per_device.remove(&device);}
		}
		if let Some(count) = self.per_user.get_mut(&user) {
			*count -= 1;
			if *count == 0 {self.per_user.remove(&user);}
		}
	}
}

/// The flow table. A device is counted by its public key and a user by name, which is what identifies them across reloads.
#[derive(Default)]
pub struct Flows {table: Mutex<Table>}

impl Flows {
	fn lock(&self) -> std::sync::MutexGuard<'_, Table> {self.table.lock().unwrap_or_else(|e| e.into_inner())}

	/// The decision of a live flow and the id of its entry. Looking a flow up counts as traffic on it, except on a refusal,
	/// which ends a fixed time after it was made so that retrying cannot keep it alive past a change of the rules that apply.
	pub fn get(&self, key: &Key) -> Option<(u64, Decision)> {
		let mut table = self.lock();
		match table.flows.get_mut(key) {
			Some(entry) if entry.seen.elapsed() <= entry.idle => {
				if entry.owner.is_some() {entry.seen = Instant::now()}
				Some((entry.id, entry.decision))
			}
			Some(_) => {
				table.remove(key);
				None
			}
			None => None,
		}
	}

	/// Records the decision for a new flow. Err when the table, the user's share of it or the device's is full, which a refusal never is:
	/// it is remembered only to spare the rules, so it takes the place of the oldest refusal and no room from a flow that carries something.
	pub fn insert(&self, key: Key, device: [u8; 32], user: &str, decision: Decision) -> Result<(), ()> {
		let mut table = self.lock();
		// A flow that expired a moment ago may still sit here until the next sweep.
		table.remove(&key);
		table.next += 1;
		let id = table.next;
		let (owner, idle) = if matches!(decision, Decision::Refuse {..}) {
			while table.flows.len() - table.carried >= MAX_REFUSALS {
				let Some((oldest, id)) = table.refusals.pop_front() else {break};
				if table.flows.get(&oldest).is_some_and(|entry| entry.id == id) {table.flows.remove(&oldest);}
			}
			table.refusals.push_back((key, id));
			(None, CLOSED_IDLE)
		} else {
			if table.carried >= MAX_FLOWS || table.per_user.get(user).is_some_and(|count| *count >= MAX_FLOWS_PER_USER) || table.per_device.get(&device).is_some_and(|count| *count >= MAX_FLOWS_PER_DEVICE) {return Err(())}
			let user = table.per_user.get_key_value(user).map_or_else(|| Arc::from(user), |(name, _)| name.clone());
			*table.per_device.entry(device).or_default() += 1;
			*table.per_user.entry(user.clone()).or_default() += 1;
			table.carried += 1;
			(Some((device, user)), FLOW_IDLE)
		};
		table.flows.insert(key, Entry {id, owner, decision, seen: Instant::now(), idle});
		Ok(())
	}

	/// Sets how long the entry `id` outlives its last packet. A handler raises it while it runs and lowers it when it ends.
	pub fn hold(&self, key: &Key, id: u64, idle: Duration) {
		if let Some(entry) = self.lock().flows.get_mut(key).filter(|entry| entry.id == id) {entry.idle = idle}
	}

	/// Returns once the flow has seen no packet in either direction for `idle`, or its entry is gone.
	pub async fn quiet(&self, key: Key, id: u64, idle: Duration) {
		loop {
			let Some(seen) = self.lock().flows.get(&key).filter(|entry| entry.id == id).map(|entry| entry.seen) else {return};
			let Some(left) = idle.checked_sub(seen.elapsed()).filter(|left| !left.is_zero()) else {return};
			tokio::time::sleep(left).await;
		}
	}

	pub fn sweep(&self) {
		let (mut guard, now) = (self.lock(), Instant::now());
		let expired: Vec<Key> = guard.flows.iter().filter(|(_, entry)| now.saturating_duration_since(entry.seen) > entry.idle).map(|(key, _)| *key).collect();
		for key in &expired {guard.remove(key)}
		let Table {flows, refusals, ..} = &mut *guard;
		refusals.retain(|(key, id)| flows.get(key).is_some_and(|entry| entry.id == *id));
	}

	pub fn len(&self) -> usize {self.lock().flows.len()}

	pub fn is_empty(&self) -> bool {self.len() == 0}
}

/// The action of the first enabled rule that matches a flow from `user` on `inbound` to `dst`, or `user` when none does.
pub fn evaluate(plan: &Plan, inbound: usize, user: usize, dst: IpAddr, protocol: u8, dport: u16, icmp: Option<(u8, u8)>) -> &Action {
	let ports = [Protocol::TCP, Protocol::UDP, Protocol::SCTP].contains(&protocol);
	let pool = plan.pool_of(dst).filter(|_| !plan.is_gateway(dst));
	// An IPv6 address that carries an IPv4 address reaches that address, so a rule on a network covers both.
	let carried = if let IpAddr::V6(v6) = dst {gate::embedded(v6)} else {[None; 2]};
	let within = |net: &IpNet| net.contains(&dst) || carried.iter().flatten().any(|v4| net.contains(&IpAddr::V4(*v4)));
	let matches = |entry: &IpMatch| match entry {
		IpMatch::Net(net) => within(net),
		// Addresses inside an inbound pool belong to the `tunnel:` names alone.
		IpMatch::Private => plan.pool_of(dst).is_none() && plan.private.iter().any(within),
		IpMatch::Users => pool.is_some(),
		IpMatch::Tunnel(tunnel) => pool == Some(*tunnel),
	};
	plan.rules.iter().find(|rule| {
		// No name memory yet: a rule with a domain condition never matches.
		!rule.domain
			&& rule.inbound.as_ref().is_none_or(|list| list.contains(&inbound))
			&& rule.user.as_ref().is_none_or(|list| list.contains(&user))
			&& rule.group.as_ref().is_none_or(|list| list.iter().any(|group| plan.users[user].groups.contains(group)))
			&& rule.ip.as_ref().is_none_or(|list| list.iter().any(matches))
			&& rule.protocol.as_ref().is_none_or(|list| list.contains(&protocol))
			&& rule.port.as_ref().is_none_or(|list| ports && list.iter().any(|(lo, hi)| (*lo..=*hi).contains(&dport)))
			&& rule.icmp_type.as_ref().is_none_or(|list| icmp.is_some_and(|(kind, _)| list.contains(&kind)))
			&& rule.icmp_code.as_ref().is_none_or(|list| icmp.is_some_and(|(_, code)| list.contains(&code)))
	}).map_or(&Action::User, |rule| &rule.action)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn key(sport: u16) -> Key {Key {protocol: 6, src: "10.7.0.2".parse().unwrap(), dst: "1.1.1.1".parse().unwrap(), sport, dport: 443}}

	const REFUSED: Decision = Decision::Refuse {reason: Reason::Rule, reset: true};

	#[test]
	fn the_table_is_bounded_per_device_per_user_and_in_total() {
		let flows = Flows::default();
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(key(sport), [1; 32], "a", Decision::Deliver).unwrap()}
		assert!(flows.insert(key(60000), [1; 32], "a", Decision::Deliver).is_err(), "one device went over its share");
		// However many devices a user has, their flows together stay inside the user's share.
		for device in 2..=16u8 {
			for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {
				let _ = flows.insert(Key {dport: u16::from(device), ..key(sport)}, [device; 32], "a", Decision::Deliver);
			}
		}
		assert_eq!(flows.len(), MAX_FLOWS_PER_USER, "one user went over their share");
		flows.insert(key(60000), [50; 32], "b", Decision::Deliver).unwrap();
		for user in 0..(MAX_FLOWS / MAX_FLOWS_PER_USER) as u16 {
			for flow in 0..MAX_FLOWS_PER_USER {
				let device = [(user >> 8) as u8, user as u8, (flow / MAX_FLOWS_PER_DEVICE) as u8].repeat(11);
				let _ = flows.insert(Key {dport: 1000 + user, ..key(flow as u16)}, device[..32].try_into().unwrap(), &format!("user-{user}"), Decision::Deliver);
			}
		}
		assert_eq!(flows.len(), MAX_FLOWS);
		assert!(flows.insert(key(61000), [99; 32], "c", Decision::Deliver).is_err(), "the table went over its size");
	}

	#[test]
	fn a_refusal_takes_no_room_from_a_flow() {
		let flows = Flows::default();
		// More refusals than fit, all from one device: none is turned away and none counts against the device or its user.
		for sport in 0..(MAX_REFUSALS + 100) as u16 {flows.insert(key(sport), [1; 32], "a", REFUSED).unwrap()}
		assert_eq!(flows.len(), MAX_REFUSALS);
		assert!(flows.get(&key(0)).is_none() && flows.get(&key(99)).is_none(), "the oldest refusals did not give way");
		assert_eq!(flows.get(&key(100)).map(|(_, decision)| decision), Some(REFUSED));
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(Key {dport: 80, ..key(sport)}, [1; 32], "a", Decision::Deliver).unwrap()}
		assert_eq!(flows.len(), MAX_REFUSALS + MAX_FLOWS_PER_DEVICE);
		// A full share turns a flow away, never a refusal.
		assert!(flows.insert(Key {dport: 81, ..key(1)}, [1; 32], "a", Decision::Deliver).is_err());
		flows.insert(Key {dport: 81, ..key(1)}, [1; 32], "a", REFUSED).unwrap();
		assert_eq!(flows.len(), MAX_REFUSALS + MAX_FLOWS_PER_DEVICE, "a refusal past the limit did not replace the oldest one");
	}

	#[test]
	fn a_flow_expires_when_idle_and_frees_its_slot() {
		let flows = Flows::default();
		flows.insert(key(1), [1; 32], "a", Decision::Deliver).unwrap();
		let (id, decision) = flows.get(&key(1)).unwrap();
		assert_eq!(decision, Decision::Deliver);
		flows.hold(&key(1), id + 1, Duration::ZERO);
		assert!(flows.get(&key(1)).is_some(), "another entry's id changed this one");
		flows.hold(&key(1), id, Duration::ZERO);
		std::thread::sleep(Duration::from_millis(5));
		flows.sweep();
		assert!(flows.is_empty());
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(key(sport), [1; 32], "a", Decision::Deliver).unwrap()}
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(Key {dport: 80, ..key(sport)}, [2; 32], "a", Decision::Deliver).unwrap()}
	}

	#[test]
	fn a_reversed_key_is_the_reply() {
		let reply = key(40000).reversed().unwrap();
		assert_eq!((reply.src, reply.dst, reply.sport, reply.dport), (key(0).dst, key(0).src, 443, 40000));
		assert_eq!(reply.reversed(), Some(key(40000)));
		let other = Key {protocol: 47, sport: 0, dport: 0, ..key(0)};
		assert_eq!(other.reversed().and_then(|back| back.reversed()), Some(other));
	}

	#[test]
	fn icmp_flows_are_told_apart_by_type_and_code() {
		let packet = |protocol, kind, code| Packet {src: "10.7.0.2".parse().unwrap(), dst: "10.7.0.3".parse().unwrap(), protocol, sport: 0, dport: 0, icmp: Some((kind, code)), fragment: false, upper: 20, len: 28};
		let (request, reply) = (Key::of(&packet(Protocol::ICMP, 8, 0)), Key::of(&packet(Protocol::ICMP, 0, 0)));
		assert_ne!(request, reply, "two icmp types shared one flow");
		assert_ne!(Key::of(&packet(Protocol::ICMP, 3, 1)), Key::of(&packet(Protocol::ICMP, 3, 3)), "two icmp codes shared one flow");
		// Only an echo reply answers a flow, and the flow it answers is the echo request the other way.
		assert_eq!(reply.reversed(), Some(Key {src: request.dst, dst: request.src, ..request}));
		assert_eq!(request.reversed(), None, "an echo request passed for the answer to an echo reply");
		assert_eq!(Key::of(&packet(Protocol::ICMP, 3, 1)).reversed(), None);
		let (request, reply) = (Key::of(&packet(Protocol::ICMPV6, 128, 0)), Key::of(&packet(Protocol::ICMPV6, 129, 0)));
		assert_eq!(reply.reversed(), Some(Key {src: request.dst, dst: request.src, ..request}));
		assert_eq!(request.reversed(), None);
	}
}
