//! Routing: the rules a flow's first packet is matched against, and the bounded table that keeps the decision for the rest of the flow.
use super::gate;
use super::netstack::{Packet, ECHO_REPLY_V4, ECHO_REPLY_V6, ECHO_REQUEST_V4, ECHO_REQUEST_V6};
use super::plan::{Action, IpMatch, Pattern, Plan};
use crate::config::Protocol;
use etherparse::{PacketBuilder, TcpHeader};
use ipnet::IpNet;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

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
	/// The queue into the userspace stack or into an l3 exit's interface was full.
	QueueFull,
	/// A packet the kernel routed into an l3 exit's interface that answers no live flow which left through that exit.
	NoFlow,
	/// Larger than the MTU of the tunnel or the interface it was going to.
	TooBig,
	/// Not a packet: an ICMP error the node owed a device and did not send, because that device had used up its share of them.
	IcmpLimited,
	/// Met a config that was replaced while the packet was on its way through the node. The device sends it again.
	Stale,
}

impl Reason {
	pub const COUNT: usize = 15;
}

/// How a flow leaves through its exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum By {
	/// The exit's own backend: the userspace stack and the outbound of a netstack exit, the interface of an l3 exit.
	Backend,
	/// The proxy of a netstack exit, for a UDP flow that proxy has given an association: from then on the flow leaves through it or not at all.
	Proxy,
	/// A ping the node answers itself.
	Local,
	/// From the node's own address around the exit's proxy: an unprivileged ping socket, or a UDP socket.
	Direct,
	/// Handed to this other exit, whose own `unsupported` policy is never consulted.
	Via(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
	/// Leaves through this exit, which is the one the rules chose and the one the user's `exits` were checked for.
	Exit {exit: usize, by: By},
	/// Tunnel DNS: the node's own resolver answers it, and each query on the flow is routed by itself.
	Dns,
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

/// What a device last said on a TCP flow, as the reset that ends the flow needs it: the sequence number the device expects next (zero while it has acknowledged nothing) and the one it has sent up to.
pub type Heard = Option<(u32, u32)>;

/// What `raw`, a TCP segment from a device, says for a reset of its flow. `upper` is where its TCP header starts.
pub fn heard(raw: &[u8], upper: usize) -> Heard {
	let tcp = raw.get(upper..upper + 14)?;
	let (seq, ack, flags) = (u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]), u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]), tcp[13]);
	let payload = raw.len().saturating_sub(upper + usize::from(tcp[12] >> 4) * 4) as u32;
	Some((if flags & 0x10 != 0 {ack} else {0}, seq.wrapping_add(payload).wrapping_add(u32::from(flags & 0x02 != 0)).wrapping_add(u32::from(flags & 0x01 != 0))))
}

/// The reset that ends a TCP flow from the far side, as the device would get it from the host it was talking to.
pub fn tcp_reset(key: &Key, (seq, ack): (u32, u32)) -> Option<Vec<u8>> {
	let mut header = TcpHeader::new(key.dport, key.sport, seq, 0);
	(header.rst, header.ack, header.acknowledgment_number) = (true, true, ack);
	let builder = match (key.dst, key.src) {
		(IpAddr::V4(from), IpAddr::V4(to)) => PacketBuilder::ipv4(from.octets(), to.octets(), 64),
		(IpAddr::V6(from), IpAddr::V6(to)) => PacketBuilder::ipv6(from.octets(), to.octets(), 64),
		_ => return None,
	}.tcp_header(header);
	let mut out = Vec::with_capacity(builder.size(0));
	builder.write(&mut out, &[]).ok()?;
	Some(out)
}

/// `owner` is the device and the user a carried flow counts against. A refusal has none: it counts against nobody.
/// `closing` is set once a TCP flow that no handler watches has shown a FIN or RST. `names` is what the user had resolved to the destination when the flow began, which is what `domain` rules saw.
struct Entry {id: u64, owner: Option<([u8; 32], Arc<str>)>, decision: Decision, seen: Instant, idle: Duration, closing: bool, names: Vec<Arc<str>>, heard: Heard}

/// A flow that a change of the config ended, for whoever tells its device.
pub struct Ended {pub key: Key, pub device: [u8; 32], pub heard: Heard}

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
	/// The generation of the plan whose indexes the decisions are in.
	generation: u64,
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
/// A decision names exits by their index in one plan, so everyone who reads or writes one says which plan they hold (`generation`), and is turned away when the table has moved on to another.
#[derive(Default)]
pub struct Flows {table: Mutex<Table>, wake: Notify}

impl Flows {
	fn lock(&self) -> std::sync::MutexGuard<'_, Table> {self.table.lock().unwrap_or_else(|e| e.into_inner())}

	/// The decision of a live flow and the id of its entry. Looking a flow up counts as traffic on it, except on a refusal,
	/// which ends a fixed time after it was made so that retrying cannot keep it alive past a change of the rules that apply.
	/// `heard` is what a TCP segment from the device says, see `Heard`. None leaves what the flow has.
	pub fn get(&self, key: &Key, generation: u64, heard: Heard) -> Option<(u64, Decision)> {
		let mut table = self.lock();
		if table.generation != generation {return None}
		match table.flows.get_mut(key) {
			Some(entry) if entry.seen.elapsed() <= entry.idle => {
				if entry.owner.is_some() {entry.seen = Instant::now()}
				if heard.is_some() {entry.heard = heard}
				Some((entry.id, entry.decision))
			}
			Some(_) => {
				table.remove(key);
				None
			}
			None => None,
		}
	}

	/// The public key of the device a live flow belongs to, and the flow's decision. It counts as traffic on the flow, like `get`. A refusal belongs to nobody and gives None.
	pub fn owned(&self, key: &Key, generation: u64) -> Option<([u8; 32], Decision)> {
		let mut table = self.lock();
		if table.generation != generation {return None}
		let entry = table.flows.get_mut(key).filter(|entry| entry.seen.elapsed() <= entry.idle)?;
		let device = entry.owner.as_ref()?.0;
		entry.seen = Instant::now();
		Some((device, entry.decision))
	}

	/// Records the decision for a new flow and returns the id of its entry. Err when the table, the user's share of it or the device's is full, which a refusal never is:
	/// it is remembered only to spare the rules, so it takes the place of the oldest refusal and no room from a flow that carries something.
	#[allow(clippy::too_many_arguments)]
	pub fn insert(&self, key: Key, device: [u8; 32], user: &str, decision: Decision, names: Vec<Arc<str>>, heard: Heard, generation: u64) -> Result<u64, Reason> {
		let mut table = self.lock();
		if table.generation != generation {return Err(Reason::Stale)}
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
			if table.carried >= MAX_FLOWS || table.per_user.get(user).is_some_and(|count| *count >= MAX_FLOWS_PER_USER) || table.per_device.get(&device).is_some_and(|count| *count >= MAX_FLOWS_PER_DEVICE) {return Err(Reason::FlowTableFull)}
			let user = table.per_user.get_key_value(user).map_or_else(|| Arc::from(user), |(name, _)| name.clone());
			*table.per_device.entry(device).or_default() += 1;
			*table.per_user.entry(user.clone()).or_default() += 1;
			table.carried += 1;
			(Some((device, user)), FLOW_IDLE)
		};
		table.flows.insert(key, Entry {id, owner, decision, seen: Instant::now(), idle, closing: false, names, heard});
		Ok(id)
	}

	/// Replaces the decision of the entry `id`. Only the handler of a UDP flow does this, once, when its exit's proxy turns out to have no UDP:
	/// the entry keeps its place and its owner, so a flow that is refused this way stays refused for as long as its packets keep coming.
	/// False when the handler's plan is no longer the one in force. Its decision means nothing to the table then, and the handler ends the flow.
	pub fn decide(&self, key: &Key, id: u64, decision: Decision, generation: u64) -> bool {
		let mut table = self.lock();
		if table.generation != generation {return false}
		if let Some(entry) = table.flows.get_mut(key).filter(|entry| entry.id == id) {entry.decision = decision}
		true
	}

	/// Ties the entry `id` to the proxy of its exit, which the handler of a UDP flow does the moment that proxy gives it an association.
	/// Only a flow that still waits for that answer changes. One the policy has sent another way stays there. False as for `decide`.
	pub fn pin(&self, key: &Key, id: u64, generation: u64) -> bool {
		let mut table = self.lock();
		if table.generation != generation {return false}
		if let Some(Entry {decision: Decision::Exit {by: by @ By::Backend, ..}, ..}) = table.flows.get_mut(key).filter(|entry| entry.id == id) {*by = By::Proxy}
		true
	}

	/// Whether the entry `id` is still in the table.
	pub fn holds(&self, key: &Key, id: u64) -> bool {self.lock().flows.get(key).is_some_and(|entry| entry.id == id)}

	/// The reset that tells the device the TCP flow of entry `id` is over. None for any other flow and for an entry that is gone.
	pub fn reset(&self, key: &Key, id: u64) -> Option<Vec<u8>> {
		let heard = self.lock().flows.get(key).filter(|entry| entry.id == id && key.protocol == Protocol::TCP)?.heard?;
		tcp_reset(key, heard)
	}

	/// Goes through every flow when a new plan takes over, with the table locked from the first flow to the end of `then`, so no packet meets a table that is half in one plan and half in the other.
	/// `judge` is given a flow's key, its device and user, its decision in the old plan and the names it began with. It answers with the decision in the new plan when the flow lives on, and None ends the flow.
	/// Remembered refusals are forgotten, since the next packet is to be decided afresh. `then` gets the flows that ended and puts the new plan, of `generation`, in force.
	pub fn recheck<R>(&self, generation: u64, mut judge: impl FnMut(&Key, &[u8; 32], &str, Decision, &[Arc<str>]) -> Option<Decision>, then: impl FnOnce(Vec<Ended>) -> R) -> R {
		let mut table = self.lock();
		let (keys, mut ended): (Vec<Key>, Vec<Ended>) = (table.flows.keys().copied().collect(), Vec::new());
		for key in keys {
			let Some(entry) = table.flows.get_mut(&key) else {continue};
			let kept = match (&entry.owner, entry.decision) {
				(None, _) | (_, Decision::Refuse {..}) => None,
				(Some((device, user)), decision) => {
					let kept = judge(&key, device, user, decision, &entry.names);
					if kept.is_none() {ended.push(Ended {key, device: *device, heard: entry.heard})}
					kept
				}
			};
			match kept {
				Some(decision) => entry.decision = decision,
				None => table.remove(&key),
			}
		}
		table.refusals.clear();
		table.generation = generation;
		let done = then(ended);
		drop(table);
		// Every handler looks at its flow again, and those whose flow is gone end.
		self.wake.notify_waiters();
		done
	}

	/// For a flow no handler watches, one through an l3 exit: how long its packets say to keep it. Once it is `closing` it stays short-lived whatever follows.
	pub fn track(&self, key: &Key, id: u64, idle: Duration, closing: bool) {
		if let Some(entry) = self.lock().flows.get_mut(key).filter(|entry| entry.id == id) {
			entry.closing |= closing;
			entry.idle = if entry.closing {FLOW_IDLE} else {idle};
		}
	}

	/// Sets how long the entry `id` outlives its last packet. A handler raises it while it runs and lowers it when it ends.
	pub fn hold(&self, key: &Key, id: u64, idle: Duration) {
		if let Some(entry) = self.lock().flows.get_mut(key).filter(|entry| entry.id == id) {entry.idle = idle}
	}

	/// Returns once the flow has seen no packet in either direction for `idle`, or its entry is gone, which it is within a moment of a reload that ends the flow.
	pub async fn quiet(&self, key: Key, id: u64, idle: Duration) {
		loop {
			// Listening before looking, so a reload between the look and the wait is not missed.
			let mut woken = pin!(self.wake.notified());
			woken.as_mut().enable();
			let Some(seen) = self.lock().flows.get(&key).filter(|entry| entry.id == id).map(|entry| entry.seen) else {return};
			let Some(left) = idle.checked_sub(seen.elapsed()).filter(|left| !left.is_zero()) else {return};
			tokio::select! {
				_ = tokio::time::sleep(left) => {}
				_ = woken => {}
			}
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
/// `named` answers a `domain` condition: whether the flow goes to a name one of the patterns matches. It is asked last, and only by a rule that matched in everything else.
#[allow(clippy::too_many_arguments)]
pub fn evaluate<'a>(plan: &'a Plan, inbound: usize, user: usize, dst: IpAddr, protocol: u8, dport: u16, icmp: Option<(u8, u8)>, named: &dyn Fn(&[Pattern]) -> bool) -> &'a Action {
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
		rule.inbound.as_ref().is_none_or(|list| list.contains(&inbound))
			&& rule.user.as_ref().is_none_or(|list| list.contains(&user))
			&& rule.group.as_ref().is_none_or(|list| list.iter().any(|group| plan.users[user].groups.contains(group)))
			&& rule.ip.as_ref().is_none_or(|list| list.iter().any(matches))
			&& rule.protocol.as_ref().is_none_or(|list| list.contains(&protocol))
			&& rule.port.as_ref().is_none_or(|list| ports && list.iter().any(|(lo, hi)| (*lo..=*hi).contains(&dport)))
			&& rule.icmp_type.as_ref().is_none_or(|list| icmp.is_some_and(|(kind, _)| list.contains(&kind)))
			&& rule.icmp_code.as_ref().is_none_or(|list| icmp.is_some_and(|(_, code)| list.contains(&code)))
			&& rule.domain.as_ref().is_none_or(|list| named(list))
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
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(key(sport), [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).unwrap();}
		assert!(flows.insert(key(60000), [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).is_err(), "one device went over its share");
		// However many devices a user has, their flows together stay inside the user's share.
		for device in 2..=16u8 {
			for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {
				let _ = flows.insert(Key {dport: u16::from(device), ..key(sport)}, [device; 32], "a", Decision::Deliver, Vec::new(), None, 0);
			}
		}
		assert_eq!(flows.len(), MAX_FLOWS_PER_USER, "one user went over their share");
		flows.insert(key(60000), [50; 32], "b", Decision::Deliver, Vec::new(), None, 0).unwrap();
		for user in 0..(MAX_FLOWS / MAX_FLOWS_PER_USER) as u16 {
			for flow in 0..MAX_FLOWS_PER_USER {
				let device = [(user >> 8) as u8, user as u8, (flow / MAX_FLOWS_PER_DEVICE) as u8].repeat(11);
				let _ = flows.insert(Key {dport: 1000 + user, ..key(flow as u16)}, device[..32].try_into().unwrap(), &format!("user-{user}"), Decision::Deliver, Vec::new(), None, 0);
			}
		}
		assert_eq!(flows.len(), MAX_FLOWS);
		assert!(flows.insert(key(61000), [99; 32], "c", Decision::Deliver, Vec::new(), None, 0).is_err(), "the table went over its size");
	}

	#[test]
	fn a_refusal_takes_no_room_from_a_flow() {
		let flows = Flows::default();
		// More refusals than fit, all from one device: none is turned away and none counts against the device or its user.
		for sport in 0..(MAX_REFUSALS + 100) as u16 {flows.insert(key(sport), [1; 32], "a", REFUSED, Vec::new(), None, 0).unwrap();}
		assert_eq!(flows.len(), MAX_REFUSALS);
		assert!(flows.get(&key(0), 0, None).is_none() && flows.get(&key(99), 0, None).is_none(), "the oldest refusals did not give way");
		assert_eq!(flows.get(&key(100), 0, None).map(|(_, decision)| decision), Some(REFUSED));
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(Key {dport: 80, ..key(sport)}, [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).unwrap();}
		assert_eq!(flows.len(), MAX_REFUSALS + MAX_FLOWS_PER_DEVICE);
		// A full share turns a flow away, never a refusal.
		assert!(flows.insert(Key {dport: 81, ..key(1)}, [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).is_err());
		flows.insert(Key {dport: 81, ..key(1)}, [1; 32], "a", REFUSED, Vec::new(), None, 0).unwrap();
		assert_eq!(flows.len(), MAX_REFUSALS + MAX_FLOWS_PER_DEVICE, "a refusal past the limit did not replace the oldest one");
	}

	#[test]
	fn a_flow_expires_when_idle_and_frees_its_slot() {
		let flows = Flows::default();
		flows.insert(key(1), [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).unwrap();
		let (id, decision) = flows.get(&key(1), 0, None).unwrap();
		assert_eq!(decision, Decision::Deliver);
		flows.hold(&key(1), id + 1, Duration::ZERO);
		assert!(flows.get(&key(1), 0, None).is_some(), "another entry's id changed this one");
		flows.hold(&key(1), id, Duration::ZERO);
		std::thread::sleep(Duration::from_millis(5));
		flows.sweep();
		assert!(flows.is_empty());
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(key(sport), [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).unwrap();}
		for sport in 0..MAX_FLOWS_PER_DEVICE as u16 {flows.insert(Key {dport: 80, ..key(sport)}, [2; 32], "a", Decision::Deliver, Vec::new(), None, 0).unwrap();}
	}

	#[test]
	fn a_flow_no_handler_watches_is_kept_by_what_its_packets_say() {
		let flows = Flows::default();
		let leaves = Decision::Exit {exit: 0, by: By::Backend};
		let id = flows.insert(key(1), [1; 32], "a", leaves, Vec::new(), None, 0).unwrap();
		let idle = |flows: &Flows| flows.lock().flows.get(&key(1)).map(|entry| entry.idle);
		assert_eq!(idle(&flows), Some(FLOW_IDLE));
		flows.track(&key(1), id, Duration::from_secs(7200), false);
		assert_eq!(idle(&flows), Some(Duration::from_secs(7200)));
		flows.track(&key(1), id + 1, Duration::ZERO, true);
		assert_eq!(idle(&flows), Some(Duration::from_secs(7200)), "another entry's id changed this one");
		// After a FIN or RST the last acknowledgements must not make the flow long-lived again.
		flows.track(&key(1), id, Duration::from_secs(7200), true);
		flows.track(&key(1), id, Duration::from_secs(7200), false);
		assert_eq!(idle(&flows), Some(FLOW_IDLE));
		// An association ties the flow to its proxy. One that was already sent around the proxy is not taken back.
		flows.pin(&key(1), id + 1, 0);
		assert_eq!(flows.get(&key(1), 0, None), Some((id, leaves)), "another entry's id changed this one");
		flows.pin(&key(1), id, 0);
		assert_eq!(flows.get(&key(1), 0, None), Some((id, Decision::Exit {exit: 0, by: By::Proxy})));
		for around in [Decision::Exit {exit: 0, by: By::Direct}, Decision::Exit {exit: 0, by: By::Via(1)}, Decision::Refuse {reason: Reason::Unsupported, reset: false}] {
			flows.decide(&key(1), id, around, 0);
			flows.pin(&key(1), id, 0);
			assert_eq!(flows.get(&key(1), 0, None), Some((id, around)));
		}
		flows.decide(&key(1), id, leaves, 0);
		let refused = Decision::Refuse {reason: Reason::Unsupported, reset: true};
		flows.decide(&key(1), id + 1, refused, 0);
		assert_eq!(flows.get(&key(1), 0, None), Some((id, leaves)));
		flows.decide(&key(1), id, refused, 0);
		assert_eq!(flows.get(&key(1), 0, None), Some((id, refused)));
		// It still holds its place in the device's share, unlike a refusal the rules made.
		for sport in 2..=MAX_FLOWS_PER_DEVICE as u16 {flows.insert(key(sport), [1; 32], "a", leaves, Vec::new(), None, 0).unwrap();}
		assert!(flows.insert(key(60000), [1; 32], "a", leaves, Vec::new(), None, 0).is_err());
	}

	#[test]
	fn a_new_plan_keeps_or_ends_each_flow_and_turns_away_whoever_holds_the_old_one() {
		let flows = Flows::default();
		let (stays, goes) = (flows.insert(key(1), [1; 32], "a", Decision::Exit {exit: 0, by: By::Backend}, vec![Arc::from("example.com")], Some((7, 9)), 0).unwrap(), flows.insert(key(2), [2; 32], "b", Decision::Deliver, Vec::new(), Some((3, 4)), 0).unwrap());
		flows.insert(key(3), [1; 32], "a", REFUSED, Vec::new(), None, 0).unwrap();
		assert_eq!(flows.get(&key(1), 0, Some((70, 90))), Some((stays, Decision::Exit {exit: 0, by: By::Backend})));
		let mut judged = Vec::new();
		let ended = flows.recheck(1, |key, device, user, decision, names| {
			judged.push((key.sport, *device, user.to_string(), decision, names.len()));
			// The first flow lives on under the index its exit has in the new plan.
			(key.sport == 1).then_some(Decision::Exit {exit: 5, by: By::Backend})
		}, |ended| ended.iter().map(|flow| (flow.key, flow.device, flow.heard)).collect::<Vec<_>>());
		judged.sort_by_key(|flow| flow.0);
		assert_eq!(judged, [(1, [1; 32], "a".to_string(), Decision::Exit {exit: 0, by: By::Backend}, 1), (2, [2; 32], "b".to_string(), Decision::Deliver, 0)], "a remembered refusal was judged, or a flow was not");
		assert_eq!(ended, [(key(2), [2; 32], Some((3, 4)))]);
		// Whoever still holds the old plan finds nothing and leaves nothing behind.
		assert!(flows.get(&key(1), 0, None).is_none() && !flows.decide(&key(1), stays, Decision::Deliver, 0) && !flows.pin(&key(1), stays, 0));
		assert_eq!(flows.insert(key(4), [1; 32], "a", Decision::Deliver, Vec::new(), None, 0), Err(Reason::Stale));
		// A flow is its device's under the plan in force only, and one that ended is nobody's.
		assert_eq!((flows.owned(&key(1), 1), flows.owned(&key(1), 0), flows.owned(&key(2), 1)), (Some(([1; 32], Decision::Exit {exit: 5, by: By::Backend})), None, None));
		assert_eq!((flows.get(&key(1), 1, None), flows.len(), flows.holds(&key(1), stays), flows.holds(&key(2), goes)), (Some((stays, Decision::Exit {exit: 5, by: By::Backend})), 1, true, false));
		// The reset of the flow that stayed carries what its device said last.
		let reset = flows.reset(&key(1), stays).unwrap();
		assert_eq!((&reset[12..16], &reset[16..20], &reset[20..24], &reset[24..32], reset[33] & 0x14), (&[1, 1, 1, 1][..], &[10, 7, 0, 2][..], &[1, 187, 0, 1][..], &[0, 0, 0, 70, 0, 0, 0, 90][..], 0x14));
		assert!(flows.reset(&key(2), goes).is_none() && flows.reset(&key(1), stays + 1).is_none());
		// The user whose flow ended has their share of the table back.
		for sport in 10..10 + MAX_FLOWS_PER_DEVICE as u16 {flows.insert(key(sport), [2; 32], "b", Decision::Deliver, Vec::new(), None, 1).unwrap();}
	}

	#[test]
	fn what_a_segment_says_is_what_its_reset_needs() {
		let mut header = TcpHeader::new(40000, 443, 1000, 65535);
		(header.ack, header.acknowledgment_number, header.fin) = (true, 5000, true);
		let mut raw = Vec::new();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).tcp_header(header).write(&mut raw, b"abc").unwrap();
		assert_eq!(heard(&raw, 20), Some((5000, 1004)), "the fin and the payload were not counted");
		let mut syn = TcpHeader::new(40000, 443, 1000, 65535);
		syn.syn = true;
		raw.clear();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).tcp_header(syn).write(&mut raw, &[]).unwrap();
		assert_eq!((heard(&raw, 20), heard(&raw[..30], 20)), (Some((0, 1001)), None));
	}

	#[tokio::test]
	async fn a_handler_is_woken_when_its_flow_ends() {
		let flows = Arc::new(Flows::default());
		let id = flows.insert(key(1), [1; 32], "a", Decision::Deliver, Vec::new(), None, 0).unwrap();
		let waiting = tokio::spawn({
			let flows = flows.clone();
			async move {flows.quiet(key(1), id, Duration::from_secs(3600)).await}
		});
		tokio::time::sleep(Duration::from_millis(50)).await;
		assert!(!waiting.is_finished());
		flows.recheck(1, |_, _, _, _, _| None, |_| ());
		tokio::time::timeout(Duration::from_secs(2), waiting).await.expect("the handler of a flow that ended kept waiting").unwrap();
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
