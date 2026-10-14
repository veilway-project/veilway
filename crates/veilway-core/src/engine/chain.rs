//! The entry half of node links (node links page, "Translation at the entry"): an exit of the backend `chain`, which sends what is routed to it into a link and delivers only what answers a flow it sent.
//! "The entry translates every flow to the link's address, as a home router does": the exit is given one address for the whole link, and never a user's tunnel address, key or name. The translation is a second index beside the flow table, bounded by it, and a flow keeps its translation for as long as the flow table keeps the flow.
//! What comes back from the link is hostile: whoever runs the exit can send anything into its tunnel. A packet is delivered only to the device whose live flow it answers, rewritten back by that flow's translation, and everything else is dropped and counted.
use super::{dns, flows};
use super::icmp::Kind;
use super::netstack::{self, Fit, Packet, ECHO_REPLY_V4, ECHO_REPLY_V6, ECHO_REQUEST_V4, ECHO_REQUEST_V6};
use super::obfs::Room;
use super::plan::{Backend, Holder, Plan};
use super::route::{By, Decision, Flows, Key, Reason, FLOW_IDLE, MAX_FLOWS};
use super::{l3, Shared};
use crate::config::{random, Protocol};
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher, RandomState};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// "Translated ports and echo identifiers at the entry: 1024 to 65535, drawn at random."
pub const PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;
/// "Rest before a translated port is used again for the same remote address and port: 120 s."
pub const REST: Duration = Duration::from_secs(120);
/// "Hop limit the entry writes on a packet it sends into a link: 64."
pub const HOPS: u8 = 64;
/// How often a port is drawn for a new flow before the flow is refused: "Ports are drawn at random from about 64,000, so a clash is rare."
const DRAWS: usize = 32;
/// Echo identifiers one ping flow of a device holds at once. A flow of ICMP is known by its type and code alone, so its identifiers are bounded here and not by the flow table.
const ECHOES: usize = 16;
/// How long an echo identifier is kept after its last request or reply.
const ECHO_IDLE: Duration = Duration::from_secs(30);
/// Translations kept at once, and ports kept at rest: the flow table's size, and some room besides for the node's own lookups and for ports that rest.
const MAPPED: usize = MAX_FLOWS + 4096;
const RESTING: usize = 4 * MAX_FLOWS;
/// How long one lookup of the node's resolver waits for its answer through a link, as it waits through any exit.
const LOOKUP: Duration = Duration::from_secs(5);
/// How often the log is told again that ports went without their rest.
const TOLD: Duration = Duration::from_secs(60);

/// The far end of a translated flow inside one link, as an answer from the link names it: the link, the protocol, the remote address and port, and the translated port (or echo identifier). A port of 0 is a protocol without ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Far {link: [u8; 16], protocol: u8, remote: IpAddr, rport: u16, port: u16}

/// Whose a translation is: a flow of a device, by its key, its echo identifier plus one (0 for anything but a ping) and the id of its entry in the flow table, with the device and the user an identifier past the flow's first is counted against (see `Flows::echo`), or a lookup of the node's own resolver, which waits for its one answer.
enum Owner {Flow(Key, u32, u64, Option<([u8; 32], Arc<str>)>), Own(Option<oneshot::Sender<Vec<u8>>>)}

struct Mapped {far: Far, owner: Owner, seen: Instant}

#[derive(Default)]
struct Table {
	/// By the flow's key and echo identifier.
	out: HashMap<(Key, u32), Far>,
	back: HashMap<Far, Mapped>,
	/// Echo identifiers held by each ping flow.
	echoes: HashMap<Key, usize>,
	/// Ports that rest, until when.
	resting: HashMap<Far, Instant>,
	/// Ports that went without their rest because `resting` was full, and how many of them the log was last told of, when.
	unrested: u64,
	told: (u64, Option<Instant>),
}

impl Table {
	/// Gives up a translation, and says whom an echo identifier it held was counted against, for the caller to give back with `Flows::unecho` once this table is unlocked.
	fn release(&mut self, far: &Far, now: Instant) -> Option<([u8; 32], Arc<str>)> {
		let mapped = self.back.remove(far)?;
		// "When a flow has gone, its port is not given to a new flow to the same remote address and port before the rest time has passed, because the exit forgets flows by its own clock and may still hold the old one." A port of a protocol without ports holds nothing the exit could still hold apart.
		if far.port != 0 {
			if self.resting.len() < RESTING {self.resting.insert(*far, now + REST);} else {self.unrested += 1}
		}
		let Owner::Flow(key, ident, _, charged) = mapped.owner else {return None};
		self.out.remove(&(key, ident));
		if let Some(count) = self.echoes.get_mut(&key) {
			*count -= 1;
			if *count == 0 {self.echoes.remove(&key);}
		}
		charged
	}

	fn free(&self, far: &Far, now: Instant) -> bool {!self.back.contains_key(far) && self.resting.get(far).is_none_or(|until| *until <= now)}
}

/// The translations of every `chain` exit of the node. A flow's key is the node's own, so one table serves every link: the answers of a link are looked for under that link alone.
/// Its lock is never held while the flow table's is taken: what charges or gives back a place of the flow table (`Flows::echo`, `Flows::unecho`, `Flows::held`) is called with this table unlocked, so the two locks have no order to keep.
pub struct Nat {
	table: Mutex<Table>,
	/// What the rendezvous hash of "the flow rule" is keyed with, drawn at start. Nothing of it is on the wire.
	spread: RandomState,
}

impl Default for Nat {
	fn default() -> Nat {Nat {table: Mutex::default(), spread: RandomState::new()}}
}

/// Why a flow has no translation.
#[derive(Debug, PartialEq, Eq)]
pub enum Unmapped {
	/// "Another user's packet to the same remote address under the same protocol is refused with an ICMP error until the first flow has gone idle", and so is a ping flow with more echo identifiers than it may hold, or than its device's or its user's share of the flow table has room for.
	Held,
	/// No port could be drawn, or the table is full.
	Full,
}

impl Nat {
	fn lock(&self) -> MutexGuard<'_, Table> {self.table.lock().unwrap_or_else(|e| e.into_inner())}

	/// The link and the translated port of a flow, while its entry `id` in the flow table is the one it was made for. A translation of an entry that is gone is dropped here.
	pub fn of_flow(&self, key: &Key, ident: u32, id: u64, flows: &Flows) -> Option<([u8; 16], u16)> {
		let (mut table, now) = (self.lock(), Instant::now());
		let far = *table.out.get(&(*key, ident))?;
		match table.back.get_mut(&far) {
			Some(mapped) if matches!(mapped.owner, Owner::Flow(_, _, of, _) if of == id) => {
				mapped.seen = now;
				Some((far.link, far.port))
			}
			_ => {
				let charged = table.release(&far, now);
				drop(table);
				if let Some((device, user)) = charged {flows.unecho(&device, &user)}
				None
			}
		}
	}

	/// Gives up the translation of a flow whose link has left its exit, so that its next packet makes a new one.
	pub fn end(&self, key: &Key, ident: u32, flows: &Flows) {
		let mut table = self.lock();
		let charged = table.out.get(&(*key, ident)).copied().and_then(|far| table.release(&far, Instant::now()));
		drop(table);
		if let Some((device, user)) = charged {flows.unecho(&device, &user)}
	}

	/// Makes a translation for a flow inside `link`. `ports` says whether its protocol has ports or echo identifiers to draw.
	pub fn map(&self, key: &Key, ident: u32, id: u64, link: [u8; 16], ports: bool, flows: &Flows) -> Result<u16, Unmapped> {
		let held = if ident != 0 {self.lock().echoes.get(key).copied().unwrap_or(0)} else {0};
		if held >= ECHOES {return Err(Unmapped::Held)}
		// An echo identifier past a ping flow's first takes a place in its device's and its user's share of the flow table, as a flow does: identifiers are otherwise bounded only per destination. It is taken before this table is locked, and given back if no translation comes of it.
		let charged = if held > 0 {Some(flows.echo(key, id).ok_or(Unmapped::Held)?)} else {None};
		let (mut table, now) = (self.lock(), Instant::now());
		let drawn = 'drawn: {
			if table.back.len() >= MAPPED {break 'drawn Err(Unmapped::Full)}
			let (protocol, rport) = (key.protocol, if key.protocol == Protocol::ICMP || key.protocol == Protocol::ICMPV6 || !ports {0} else {key.dport});
			if !ports {
				let far = Far {link, protocol, remote: key.dst, rport: 0, port: 0};
				break 'drawn if table.back.contains_key(&far) {Err(Unmapped::Held)} else {Ok(far)};
			}
			for _ in 0..DRAWS {
				let mut bytes = [0u8; 2];
				if random(&mut bytes).is_err() {break}
				let far = Far {link, protocol, remote: key.dst, rport, port: u16::from_be_bytes(bytes) % (PORTS.end() - PORTS.start() + 1).max(1) + PORTS.start()};
				if table.free(&far, now) {break 'drawn Ok(far)}
			}
			Err(Unmapped::Full)
		};
		let far = match drawn {
			Ok(far) => far,
			Err(unmapped) => {
				drop(table);
				if let Some((device, user)) = charged {flows.unecho(&device, &user)}
				return Err(unmapped);
			}
		};
		table.out.insert((*key, ident), far);
		table.back.insert(far, Mapped {far, owner: Owner::Flow(*key, ident, id, charged), seen: now});
		if ident != 0 {*table.echoes.entry(*key).or_default() += 1}
		Ok(far.port)
	}

	/// The flow an answer from `link` belongs to: its key and echo identifier, with the id of its entry in the flow table. A lookup of the node's own resolver is handed its answer here, `payload` being what came back, and gives None.
	fn back(&self, link: [u8; 16], protocol: u8, remote: IpAddr, rport: u16, port: u16, payload: Option<&[u8]>) -> Option<(Key, u32, u64)> {
		let mut table = self.lock();
		let far = Far {link, protocol, remote, rport, port};
		let mapped = table.back.get_mut(&far)?;
		mapped.seen = Instant::now();
		match &mut mapped.owner {
			Owner::Flow(key, ident, id, _) => Some((*key, *ident, *id)),
			Owner::Own(waiting) => {
				if let (Some(waiting), Some(payload)) = (waiting.take(), payload) {let _ = waiting.send(payload.to_vec());}
				None
			}
		}
	}

	/// A port for one lookup of the node's resolver through `link`, and where its answer comes. It is held until the answer has come or the lookup has given up, see `forget`.
	fn own(&self, link: [u8; 16], server: SocketAddr) -> Option<(u16, oneshot::Receiver<Vec<u8>>)> {
		let (mut table, now, (tell, told)) = (self.lock(), Instant::now(), oneshot::channel());
		if table.back.len() >= MAPPED {return None}
		for _ in 0..DRAWS {
			let mut bytes = [0u8; 2];
			random(&mut bytes).ok()?;
			let far = Far {link, protocol: Protocol::UDP, remote: server.ip(), rport: server.port(), port: u16::from_be_bytes(bytes) % (PORTS.end() - PORTS.start() + 1) + PORTS.start()};
			if table.free(&far, now) {
				table.back.insert(far, Mapped {far, owner: Owner::Own(Some(tell)), seen: now});
				return Some((far.port, told));
			}
		}
		None
	}

	fn forget(&self, link: [u8; 16], server: SocketAddr, port: u16) {self.lock().release(&Far {link, protocol: Protocol::UDP, remote: server.ip(), rport: server.port(), port}, Instant::now());}

	/// Once a second: a translation goes with its flow, an echo identifier after it has been quiet, and a port at rest when its time is over.
	pub fn sweep(&self, flows: &Flows) {
		// The flow table is asked once, and under no lock of this table, which every packet of every link waits on. A translation made in between is not in `dead` and waits for the next sweep.
		let owned: Vec<(Key, u64)> = self.lock().back.values().filter_map(|mapped| match mapped.owner {Owner::Flow(key, _, id, _) => Some((key, id)), Owner::Own(_) => None}).collect::<HashSet<_>>().into_iter().collect();
		let dead: HashSet<(Key, u64)> = owned.iter().zip(flows.held(&owned)).filter(|(_, held)| !held).map(|(flow, _)| *flow).collect();
		let (mut table, now) = (self.lock(), Instant::now());
		let gone: Vec<Far> = table.back.values().filter(|mapped| match mapped.owner {
			Owner::Flow(key, ident, id, _) => dead.contains(&(key, id)) || (ident != 0 && now.saturating_duration_since(mapped.seen) > ECHO_IDLE),
			Owner::Own(_) => now.saturating_duration_since(mapped.seen) > LOOKUP * 2,
		}).map(|mapped| mapped.far).collect();
		let charged: Vec<([u8; 32], Arc<str>)> = gone.iter().filter_map(|far| table.release(far, now)).collect();
		table.resting.retain(|_, until| *until > now);
		if table.unrested > table.told.0 && table.told.1.is_none_or(|at| now.saturating_duration_since(at) >= TOLD) {
			tracing::warn!("node links: {} translated ports in all were given up without their {}s of rest, because {RESTING} ports already rested. A new flow may be given a port the exit still holds for an old one", table.unrested, REST.as_secs());
			table.told = (table.unrested, Some(now));
		}
		drop(table);
		for (device, user) in charged {flows.unecho(&device, &user)}
	}

	/// The translations one link holds, which are its flows at the entry.
	pub fn of(&self, link: &[u8; 16]) -> usize {self.lock().back.keys().filter(|far| far.link == *link).count()}

	/// "For each link the entry hashes the flow together with the link's id and takes the link with the highest result."
	fn rank(&self, key: &Key, link: &[u8; 16]) -> u64 {
		let mut hasher = self.spread.build_hasher();
		hasher.write(&[key.protocol]);
		for part in [key.src, key.dst] {
			match part {
				IpAddr::V4(v4) => hasher.write(&v4.octets()),
				IpAddr::V6(v6) => hasher.write(&v6.octets()),
			}
		}
		hasher.write(&[&key.sport.to_be_bytes()[..], &key.dport.to_be_bytes(), link].concat());
		hasher.finish()
	}
}

/// The internet checksum of RFC 1071 over `parts` taken as one run of bytes.
fn internet(parts: &[&[u8]]) -> u16 {
	let (mut sum, mut odd) = (0u32, None);
	for byte in parts.iter().flat_map(|part| part.iter()) {
		match odd.take() {
			None => odd = Some(*byte),
			Some(high) => sum += u32::from(u16::from_be_bytes([high, *byte])),
		}
	}
	if let Some(high) = odd {sum += u32::from(high) << 8}
	while sum >> 16 != 0 {sum = (sum & 0xffff) + (sum >> 16)}
	!(sum as u16)
}

/// Corrects the checksum at `at` for `old` bytes that became `new` ones, both of an even length (RFC 1624).
fn adjust(raw: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
	let Some(field) = raw.get(at..at + 2) else {return};
	let mut sum = u32::from(!u16::from_be_bytes([field[0], field[1]]));
	for pair in old.chunks(2) {sum += u32::from(!u16::from_be_bytes([pair[0], pair[1]]))}
	for pair in new.chunks(2) {sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]))}
	while sum >> 16 != 0 {sum = (sum & 0xffff) + (sum >> 16)}
	raw[at..at + 2].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

/// CRC32c (Castagnoli), the checksum of SCTP over its whole packet (RFC 9260, appendix A).
fn crc32c(bytes: &[u8]) -> u32 {!bytes.iter().fold(!0u32, |crc, byte| (0..8).fold(crc ^ u32::from(*byte), |crc, _| if crc & 1 == 1 {crc >> 1 ^ 0x82f6_3b78} else {crc >> 1}))}

/// The offsets of the checksum of the upper layer of a packet, by protocol, where it covers the addresses or a port. ICMP has one that covers neither, and SCTP one over its whole packet, which `fix` makes anew.
fn checksum(protocol: u8) -> Option<usize> {
	match protocol {
		Protocol::TCP => Some(16),
		Protocol::UDP => Some(6),
		Protocol::ICMP | Protocol::ICMPV6 => Some(2),
		_ => None,
	}
}

/// Puts `address` and `port` in the place of the source (`source`) or the destination of `raw`, a packet `packet` describes, with every checksum that covers them corrected. The port is the port of TCP, UDP and SCTP and the identifier of an echo request or reply, and None leaves it as it is.
/// False, with nothing changed, for a packet that does not hold every field this touches, which a packet an ICMP error quotes may not: it is cut wherever its sender cut it.
fn rewrite(raw: &mut [u8], packet: &Packet, source: bool, address: IpAddr, port: Option<u16>) -> bool {
	let (v4, upper) = (packet.src.is_ipv4(), packet.upper);
	let at = match (v4, source) {
		(true, true) => 12,
		(true, false) => 16,
		(false, true) => 8,
		(false, false) => 24,
	};
	let new: Vec<u8> = match address {
		IpAddr::V4(v4) => v4.octets().to_vec(),
		IpAddr::V6(v6) => v6.octets().to_vec(),
	};
	// A protocol without ports has nothing a port could go into.
	let port = port.filter(|_| matches!(packet.protocol, Protocol::TCP | Protocol::UDP | Protocol::SCTP | Protocol::ICMP | Protocol::ICMPV6));
	let needed = match packet.protocol {
		Protocol::TCP => 18,
		Protocol::UDP => 8,
		Protocol::SCTP => 12,
		Protocol::ICMP | Protocol::ICMPV6 => if port.is_some() {6} else {4},
		_ => 0,
	};
	if new.len() != if v4 {4} else {16} || raw.len() < upper + needed || packet.len > raw.len() || (v4 && raw.len() < usize::from(raw[0] & 0x0f) * 4) {return false}
	let old = raw[at..at + new.len()].to_vec();
	raw[at..at + new.len()].copy_from_slice(&new);
	// The checksum of TCP, UDP and ICMPv6 covers the addresses, by the pseudo header, and ICMP's does not. A UDP datagram over IPv4 that has no checksum keeps none.
	let unsummed = packet.protocol == Protocol::UDP && v4 && raw[upper + 6..upper + 8] == [0, 0];
	if matches!(packet.protocol, Protocol::TCP | Protocol::UDP | Protocol::ICMPV6) && !unsummed {adjust(raw, upper + checksum(packet.protocol).unwrap_or(0), &old, &new)}
	if let Some(port) = port {
		let field = match packet.protocol {
			Protocol::ICMP | Protocol::ICMPV6 => upper + 4,
			_ if source => upper,
			_ => upper + 2,
		};
		let old = [raw[field], raw[field + 1]];
		raw[field..field + 2].copy_from_slice(&port.to_be_bytes());
		if let Some(sum) = checksum(packet.protocol).filter(|_| !unsummed) {adjust(raw, upper + sum, &old, &port.to_be_bytes())}
	}
	// A UDP checksum that comes to zero is written as all ones, since zero says there is none.
	if packet.protocol == Protocol::UDP && !unsummed && raw[upper + 6..upper + 8] == [0, 0] {raw[upper + 6..upper + 8].copy_from_slice(&[0xff, 0xff])}
	fix(raw, packet);
	true
}

/// Puts the device's own address and port back into `quote`, the packet an ICMP error quotes, which `quoted` describes: as `rewrite` does, when the quote holds all that its checksums cover.
/// A quote that is cut has a checksum past its end, or one over a packet it holds only part of, and neither can be corrected: only the addresses, the port and the IPv4 header's checksum are put back there. False when the quote does not hold what it names.
fn unquote(quote: &mut [u8], quoted: &Packet, address: IpAddr, port: Option<u16>) -> bool {
	let (v4, upper) = (quoted.src.is_ipv4(), quoted.upper);
	// `quoted.len` is where the quote was cut. A checksum that is corrected by the fields that change only needs to be inside the quote, and one made over the whole packet (SCTP's) needs the whole packet as its IP header gives its length.
	let whole = if v4 {quote.get(2..4).map(|len| usize::from(u16::from_be_bytes([len[0], len[1]])))} else {quote.get(4..6).map(|len| 40 + usize::from(u16::from_be_bytes([len[0], len[1]])))};
	if checksum(quoted.protocol).map_or(whole.is_some_and(|whole| quote.len() >= whole), |sum| quote.len() >= upper + (sum + 2).max(6)) {return rewrite(quote, quoted, true, address, port)}
	let new: Vec<u8> = match address {
		IpAddr::V4(v4) => v4.octets().to_vec(),
		IpAddr::V6(v6) => v6.octets().to_vec(),
	};
	let (at, header) = (if v4 {12..16} else {8..24}, if v4 {usize::from(quote.first().map_or(0, |first| first & 0x0f)) * 4} else {40});
	if new.len() != at.len() || quote.len() < at.end {return false}
	quote[at].copy_from_slice(&new);
	if let (Some(port), Some(field)) = (port, quote.get_mut(if quoted.icmp.is_some() {upper + 4..upper + 6} else {upper..upper + 2})) {field.copy_from_slice(&port.to_be_bytes())}
	if v4 && quote.len() >= header {
		quote[10..12].copy_from_slice(&[0, 0]);
		let sum = internet(&[&quote[..header]]);
		quote[10..12].copy_from_slice(&sum.to_be_bytes());
	}
	true
}

/// The checksums that are made anew rather than corrected: the IPv4 header's, and SCTP's over its whole packet.
fn fix(raw: &mut [u8], packet: &Packet) {
	let header = usize::from(raw[0] & 0x0f) * 4;
	if packet.src.is_ipv4() && raw.len() >= header {
		raw[10..12].copy_from_slice(&[0, 0]);
		let sum = internet(&[&raw[..header]]);
		raw[10..12].copy_from_slice(&sum.to_be_bytes());
	}
	if packet.protocol == Protocol::SCTP && raw.len() >= packet.upper + 12 && packet.len <= raw.len() {
		let at = packet.upper + 8;
		raw[at..at + 4].copy_from_slice(&[0; 4]);
		let sum = crc32c(&raw[packet.upper..packet.len]);
		raw[at..at + 4].copy_from_slice(&sum.to_le_bytes());
	}
}

/// "Fields that are rewritten on every packet sent into a link, because they show which device a packet came from: the hop limit is set to the one value in the table of numbers, the IPv4 identification field is drawn anew, the IPv6 flow label is set to zero, and the traffic class is set to zero with its two congestion bits kept."
fn fields(raw: &mut [u8], packet: &Packet) {
	if packet.src.is_ipv4() {
		let mut id = [0u8; 2];
		let _ = random(&mut id);
		(raw[1], raw[8]) = (raw[1] & 0x03, HOPS);
		raw[4..6].copy_from_slice(&id);
	} else {
		let class = (raw[0] & 0x0f) << 4 | raw[1] >> 4;
		(raw[0], raw[1], raw[2], raw[3], raw[7]) = (0x60, (class & 0x03) << 4, 0, 0, HOPS);
	}
	fix(raw, packet);
}

/// "Both nodes lower the segment size in every TCP opening packet that crosses the link, in both directions, to what fits the link's MTU." `raw` is a TCP segment `packet` describes.
pub fn clamp(raw: &mut [u8], packet: &Packet, mtu: u16) {
	let upper = packet.upper;
	if packet.protocol != Protocol::TCP || raw.get(upper + 13).is_none_or(|flags| flags & 0x02 == 0) {return}
	let (most, end) = (mtu.saturating_sub(if packet.src.is_ipv4() {40} else {60}), (upper + usize::from(raw[upper + 12] >> 4) * 4).min(packet.len));
	let mut at = upper + 20;
	while at < end {
		match raw[at] {
			0 => return,
			1 => at += 1,
			kind => {
				let size = usize::from(*raw.get(at + 1).unwrap_or(&0));
				if size < 2 || at + size > end {return}
				if kind == 2 && size == 4 && u16::from_be_bytes([raw[at + 2], raw[at + 3]]) > most {
					let old = [raw[at + 2], raw[at + 3]];
					raw[at + 2..at + 4].copy_from_slice(&most.to_be_bytes());
					adjust(raw, upper + 16, &old, &most.to_be_bytes());
				}
				at += size;
			}
		}
	}
}

impl Shared {
	/// Sends one IP packet into link `link`, which must be up. False when it went nowhere: the tunnel has no session with the other node, or no way to it.
	pub(super) async fn into_link(&self, plan: &Plan, link: usize, packet: &[u8]) -> bool {
		let (of, mut out) = (&plan.links[link], Vec::new());
		let tunnel = &plan.inbounds[of.inbound].tunnel;
		let route = {
			let mut peers = tunnel.lock();
			let Some(peer) = peers.wg.index(&of.key).filter(|peer| peers.wg.time_since_last_handshake(*peer).is_some()) else {return false};
			peers.wg.encapsulate(peer, packet, &mut out);
			peers.route(peer)
		};
		let Some(route) = route else {return false};
		let unsent = tunnel.unsent.load(std::sync::atomic::Ordering::Relaxed);
		for datagram in &out {route.send(tunnel, datagram, false, Room::Mtu(of.mtu)).await}
		// A link's inbound carries links alone, so a send the system refused on it now was one of this link's: the size warning.
		if of.listener && tunnel.unsent.load(std::sync::atomic::Ordering::Relaxed) > unsent {of.state.warn(&of.tag)}
		of.state.traffic.up(packet.len());
		true
	}

	/// One packet of a flow of the device `from` that was routed to `exit`, a `chain` exit, in the order of the page: the flow's link, the translation, the size, the fields, and into the link. Usage was counted per user before any of it, when the packet came in.
	#[allow(clippy::too_many_arguments)]
	pub(super) async fn chained(self: &Arc<Self>, plan: &Arc<Plan>, from: Holder, mut raw: Vec<u8>, packet: &Packet, key: Key, id: u64, exit: usize) {
		let Backend::Chain {links} = &plan.exits[exit].backend else {return};
		// An echo request is translated by its identifier, and so is a protocol with ports by its port. Any other message of ICMP a device sends would quote a packet with its own tunnel address in it, which the exit must not be given, so it does not leave.
		let (ports, ident) = match (packet.protocol, packet.icmp) {
			(Protocol::TCP | Protocol::UDP | Protocol::SCTP, _) => (true, 0),
			(Protocol::ICMP, Some((ECHO_REQUEST_V4, 0))) | (Protocol::ICMPV6, Some((ECHO_REQUEST_V6, 0))) => (true, u32::from(u16::from_be_bytes([raw[packet.upper + 4], raw[packet.upper + 5]])) + 1),
			(Protocol::ICMP | Protocol::ICMPV6, _) => return self.count(Reason::Unsupported),
			_ => (false, 0),
		};
		let mapped = self.nat.of_flow(&key, ident, id, &self.flows).map(|(link, port)| (links.iter().copied().find(|at| plan.links[*at].id == link), port));
		let (link, port) = match mapped {
			// "A flow stays on its link. When that link goes down the flow is reset, and it is not moved to another link, because its translated address belongs to the link."
			Some((Some(link), port)) if plan.up(link) => (link, port),
			Some((Some(_), _)) => return self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await,
			// A link that a reload took off the exit holds the flow no longer: it ends here, so that a device which ignores the refusal starts a new flow on a link that is up with its next packet.
			Some((None, _)) => {
				self.nat.end(&key, ident, &self.flows);
				self.flows.end(&[(key, id)], plan.generation);
				return self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await;
			}
			// "A new flow goes to one of the links that are up by the rule the transports page has for parallel connections."
			None => {
				let Some(link) = links.iter().copied().filter(|at| plan.up(*at)).max_by_key(|at| self.nat.rank(&key, &plan.links[*at].id)) else {
					// "While it is down, every flow routed to it is refused with the ICMP error or reset that an unreachable exit gives, new and live flows alike, and the refusal is counted. Nothing routed to it leaves through another exit."
					return self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await;
				};
				match self.nat.map(&key, ident, id, plan.links[link].id, ports, &self.flows) {
					Ok(port) => (link, port),
					Err(Unmapped::Held | Unmapped::Full) => return self.refuse(plan, from, &raw, packet, Reason::FlowTableFull, true).await,
				}
			}
		};
		let of = &plan.links[link];
		let Some(address) = of.addresses.iter().copied().find(|address| address.is_ipv4() == packet.src.is_ipv4()) else {return self.refuse(plan, from, &raw, packet, Reason::Unsupported, true).await};
		// "Nothing is fragmented for a link, in either direction. A packet that does not fit the link is dropped, and its sender gets the ICMP error with the link's MTU: the user's device from the entry."
		if raw.len() > usize::from(of.mtu) {
			self.count(Reason::TooBig);
			return self.icmp_error(plan, from, &raw, packet, Kind::TooBig(of.mtu)).await;
		}
		clamp(&mut raw, packet, of.mtu);
		rewrite(&mut raw, packet, true, address, ports.then_some(port));
		fields(&mut raw, packet);
		if packet.protocol == Protocol::TCP && raw.get(packet.upper + 13).is_some_and(|flags| flags & 0x05 != 0) {self.flows.track(&key, id, FLOW_IDLE, true)}
		let len = raw.len();
		if self.into_link(plan, link, &raw).await {plan.exits[exit].traffic.up(len)} else {self.refuse(plan, from, &raw, packet, Reason::Unreachable, true).await}
	}

	/// One packet that came out of link `link`, of which this node is the entry half. "From the link it accepts only a packet whose destination is its link address and that answers a remembered flow. Everything else from the link is dropped and counted."
	pub(super) async fn chain_back(&self, plan: &Plan, link: usize, mut raw: Vec<u8>) {
		let of = &plan.links[link];
		let lost = |reason: Reason| {
			of.state.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			self.count(reason);
		};
		of.state.traffic.down(raw.len());
		let Some(packet) = netstack::parse(&raw) else {return lost(Reason::Unparsable)};
		if packet.fragment {return lost(Reason::Fragment)}
		raw.truncate(packet.len);
		if !of.addresses.contains(&packet.dst) {return lost(Reason::NoFlow)}
		// Destination unreachable, time exceeded and parameter problem, and for ICMPv6 packet too big as well: found by the packet they quote, which is one the entry sent.
		let error = matches!((packet.protocol, packet.icmp), (Protocol::ICMP, Some((3 | 11 | 12, _))) | (Protocol::ICMPV6, Some((1..=4, _))));
		let found = if error {
			let Some(quoted) = raw.get(packet.upper + 8..).and_then(netstack::quoted).filter(|quoted| quoted.src == packet.dst && !quoted.fragment) else {return lost(Reason::NoFlow)};
			let (rport, port) = match quoted.icmp {
				Some((ECHO_REQUEST_V4 | ECHO_REQUEST_V6, 0)) => (0, raw.get(packet.upper + 8 + quoted.upper + 4..packet.upper + 8 + quoted.upper + 6).map_or(0, |ident| u16::from_be_bytes([ident[0], ident[1]]))),
				Some(_) => return lost(Reason::NoFlow),
				None if quoted.sport == 0 && quoted.dport == 0 && !matches!(quoted.protocol, Protocol::TCP | Protocol::UDP | Protocol::SCTP) => (0, 0),
				None => (quoted.dport, quoted.sport),
			};
			self.nat.back(of.id, quoted.protocol, quoted.dst, rport, port, None).map(|found| (found, Some(quoted)))
		} else {
			let (rport, port) = match packet.icmp {
				Some((ECHO_REPLY_V4 | ECHO_REPLY_V6, 0)) => (0, u16::from_be_bytes([raw[packet.upper + 4], raw[packet.upper + 5]])),
				Some(_) => return lost(Reason::NoFlow),
				None => (packet.sport, packet.dport),
			};
			// The answer to a lookup of the node's own resolver ends here: it is handed to the lookup and goes to no device.
			let payload = (packet.protocol == Protocol::UDP).then(|| &raw[packet.upper + 8..]);
			self.nat.back(of.id, packet.protocol, packet.src, rport, port, payload).map(|found| (found, None))
		};
		let Some(((key, ident, id), quoted)) = found else {return lost(Reason::NoFlow)};
		// The flow must still live as the entry the translation was made for, routed to the exit this link is behind, and its device must still hold the address it came from. An answer keeps the flow alive only while its device keeps sending on it, see `Flows::answered`.
		let (Some((owner, Decision::Exit {exit, by: By::Backend})), Some(to)) = (self.flows.answered(&key, id, plan.generation), plan.by_address.get(&key.src).copied()) else {return lost(Reason::NoFlow)};
		if Some(exit) != of.exit || plan.devices[to.device].public_key != owner {return lost(Reason::NoFlow)}
		let echo = ident.checked_sub(1).map(|ident| ident as u16);
		match quoted {
			// "ICMP errors that arrive for a translated flow are found by the packet they quote, translated back, quote included and with the quote's checksum corrected, and delivered to the user's device."
			Some(quoted) => {
				let at = packet.upper + 8;
				let mut quote = raw[at..].to_vec();
				if !unquote(&mut quote, &quoted, key.src, echo.or((quoted.sport != 0).then_some(key.sport))) {return lost(Reason::NoFlow)}
				raw[at..].copy_from_slice(&quote);
				rewrite(&mut raw, &packet, false, key.src, None);
				// The checksum of the error covers the quote, which changed by more than a field: it is made anew.
				raw[packet.upper + 2..packet.upper + 4].copy_from_slice(&[0, 0]);
				let sum = match key.src {
					IpAddr::V4(_) => internet(&[&raw[packet.upper..]]),
					IpAddr::V6(to) => internet(&[&raw[8..24], &to.octets(), &((raw.len() - packet.upper) as u32).to_be_bytes(), &[0, 0, 0, 58], &raw[packet.upper..]]),
				};
				raw[packet.upper + 2..packet.upper + 4].copy_from_slice(&sum.to_be_bytes());
			}
			None => {
				rewrite(&mut raw, &packet, false, key.src, echo.or((packet.sport != 0 || packet.dport != 0).then_some(key.sport)));
				clamp(&mut raw, &packet, of.mtu);
				// A flow no handler watches lives by what its packets say, as one through an l3 exit does.
				let (idle, closing) = match packet.protocol {
					Protocol::TCP => (l3::TCP_IDLE, raw.get(packet.upper + 13).is_some_and(|flags| flags & 0x05 != 0)),
					Protocol::UDP => (l3::UDP_IDLE, false),
					_ => (FLOW_IDLE, false),
				};
				self.flows.track(&key, id, idle, closing);
			}
		}
		plan.exits[exit].traffic.down(raw.len());
		// The device may have a smaller MTU than the link. What it set is held to as for any packet from outside, and what cannot reach it is dropped: its sender is out of reach, on the far side of the link.
		match netstack::forward(&raw, plan.mtu_of(to)) {
			Fit::Whole => drop(self.transmit(plan, to, &raw).await),
			Fit::Pieces(pieces) => for piece in &pieces {self.transmit(plan, to, piece).await;},
			Fit::TooBig => self.count(Reason::TooBig),
		}
	}

	/// One query of the node's resolver to `server` through `exit`, a `chain` exit, and its answer. "The entry's resolver sends its lookups through the exit a flow was routed to. Through a link these are packets like any other: their source is the entry's link address, they take a translated port, and they count against the exit's cap for the link."
	/// It goes over UDP alone: a node has no stream of its own inside a link, so an answer the server truncated, as it is asked to when the answer would not fit the link, stays truncated. None when no link is up or nothing answered within the time any lookup has.
	pub(super) async fn lookup_through(&self, plan: &Plan, exit: usize, server: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
		let Backend::Chain {links} = &plan.exits[exit].backend else {return None};
		let link = links.iter().copied().filter(|at| plan.up(*at)).max_by_key(|at| self.nat.rank(&Key {protocol: Protocol::UDP, src: server.ip(), dst: server.ip(), sport: 53, dport: server.port()}, &plan.links[*at].id))?;
		let of = &plan.links[link];
		let address = of.addresses.iter().copied().find(|address| address.is_ipv4() == server.is_ipv4())?;
		// The query goes out under an id the node draws for it, as every lookup of the node's resolver does, and only a response under that id is the answer.
		let (mut asked, mut id) = (query.to_vec(), [0u8; 2]);
		random(&mut id).ok()?;
		asked.get_mut(..2)?.copy_from_slice(&id);
		// The answer comes back as one datagram, which the exit drops when it is larger than the link: a query that offers more than the link carries offers what it carries, so the server truncates what would not fit.
		dns::edns(&mut asked, of.mtu.saturating_sub(if server.is_ipv4() {28} else {48}));
		let (port, answer) = self.nat.own(of.id, server)?;
		let mut raw = Vec::new();
		let built = match (address, server.ip()) {
			(IpAddr::V4(from), IpAddr::V4(to)) => etherparse::PacketBuilder::ipv4(from.octets(), to.octets(), HOPS).udp(port, server.port()).write(&mut raw, &asked),
			(IpAddr::V6(from), IpAddr::V6(to)) => etherparse::PacketBuilder::ipv6(from.octets(), to.octets(), HOPS).udp(port, server.port()).write(&mut raw, &asked),
			_ => return None,
		};
		let sent = built.is_ok() && raw.len() <= usize::from(of.mtu) && self.into_link(plan, link, &raw).await;
		if sent {plan.exits[exit].traffic.up(query.len())}
		let answer = if sent {tokio::time::timeout(LOOKUP, answer).await.ok().and_then(Result::ok)} else {None};
		self.nat.forget(of.id, server, port);
		let mut answer = answer.filter(|answer| flows::answers(&asked, answer))?;
		answer.get_mut(..2)?.copy_from_slice(query.get(..2)?);
		Some(answer)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use super::super::route::{MAX_FLOWS_PER_DEVICE, MAX_FLOWS_PER_USER};
	use etherparse::{PacketBuilder, PacketHeaders, TcpHeader, TcpOptionElement};

	fn verified(raw: &[u8]) {
		// etherparse checks nothing by itself, so each checksum is made here once more and compared.
		let packet = netstack::parse(raw).unwrap();
		if packet.src.is_ipv4() {assert_eq!(internet(&[&raw[..usize::from(raw[0] & 0x0f) * 4]]), 0, "the IPv4 header checksum")}
		let body = &raw[packet.upper..packet.len];
		let pseudo = match (packet.src, packet.dst) {
			(IpAddr::V4(src), IpAddr::V4(dst)) => [&src.octets()[..], &dst.octets(), &[0, packet.protocol], &(body.len() as u16).to_be_bytes()].concat(),
			(IpAddr::V6(src), IpAddr::V6(dst)) => [&src.octets()[..], &dst.octets(), &(body.len() as u32).to_be_bytes(), &[0, 0, 0, packet.protocol]].concat(),
			_ => unreachable!(),
		};
		match packet.protocol {
			Protocol::TCP | Protocol::ICMPV6 => assert_eq!(internet(&[&pseudo, body]), 0, "the checksum of protocol {}", packet.protocol),
			Protocol::UDP if !(packet.src.is_ipv4() && body[6..8] == [0, 0]) => assert_eq!(internet(&[&pseudo, body]), 0, "the UDP checksum"),
			Protocol::ICMP => assert_eq!(internet(&[body]), 0, "the ICMP checksum"),
			Protocol::SCTP => {
				let mut zeroed = body.to_vec();
				zeroed[8..12].copy_from_slice(&[0; 4]);
				assert_eq!(crc32c(&zeroed).to_le_bytes(), body[8..12], "the SCTP checksum");
			}
			_ => {}
		}
	}

	#[test]
	fn crc32c_is_the_one_of_rfc_3720() {
		// RFC 3720, B.4: 32 bytes of zero, and 32 bytes of 0xff.
		assert_eq!((crc32c(&[0; 32]), crc32c(&[0xff; 32])), (0x8a91_36aa, 0x62a8_ab43));
	}

	#[test]
	fn a_translated_packet_keeps_every_checksum_and_loses_what_tells_its_device() {
		let (link, user) = ("10.9.0.2".parse::<IpAddr>().unwrap(), [10, 7, 0, 2]);
		let mut syn = TcpHeader::new(40000, 443, 1, 65535);
		syn.syn = true;
		syn.set_options(&[TcpOptionElement::MaximumSegmentSize(1460), TcpOptionElement::Noop, TcpOptionElement::WindowScale(7)]).unwrap();
		let mut packets = Vec::new();
		for builder in [PacketBuilder::ipv4(user, [93, 184, 216, 34], 61)] {
			let mut raw = Vec::new();
			builder.tcp_header(syn.clone()).write(&mut raw, &[]).unwrap();
			packets.push(raw);
		}
		let mut udp = Vec::new();
		PacketBuilder::ipv4(user, [93, 184, 216, 34], 61).udp(40000, 53).write(&mut udp, b"query").unwrap();
		packets.push(udp);
		let mut zero = packets[1].clone();
		zero[26..28].copy_from_slice(&[0, 0]);
		packets.push(zero);
		let mut ping = Vec::new();
		PacketBuilder::ipv4(user, [93, 184, 216, 34], 61).icmpv4_echo_request(7, 1).write(&mut ping, b"ping").unwrap();
		packets.push(ping);
		let mut sctp = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 61, 132, 0, 0, 10, 7, 0, 2, 93, 184, 216, 34, 0x9c, 0x40, 0x0b, 0x59, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 4];
		let total = sctp.len() as u16;
		sctp[2..4].copy_from_slice(&total.to_be_bytes());
		packets.push(sctp);
		for mut raw in packets {
			let packet = netstack::parse(&raw).unwrap();
			let ident = packet.icmp.is_some();
			rewrite(&mut raw, &packet, true, link, Some(5000));
			fields(&mut raw, &packet);
			clamp(&mut raw, &packet, 1390);
			verified(&raw);
			let after = netstack::parse(&raw).unwrap();
			assert_eq!((after.src, raw[8], raw[1]), (link, HOPS, 0), "protocol {}", packet.protocol);
			if ident {assert_eq!(raw[24..26], 5000u16.to_be_bytes())} else {assert_eq!(after.sport, 5000)}
			if packet.protocol == Protocol::UDP && raw[26..28] == [0, 0] {continue}
			if packet.protocol == Protocol::TCP {
				let headers = PacketHeaders::from_ip_slice(&raw).unwrap();
				let Some(etherparse::TransportHeader::Tcp(tcp)) = headers.transport else {panic!("no tcp")};
				assert!(tcp.options_iterator().any(|option| matches!(option, Ok(TcpOptionElement::MaximumSegmentSize(1350)))), "the segment size was not lowered");
			}
			// And back, as an answer: the device's own address and port.
			let back = netstack::parse(&raw).unwrap();
			let mut answer = raw.clone();
			rewrite(&mut answer, &back, false, IpAddr::from([10, 7, 0, 3]), Some(40000));
			verified(&answer);
		}
	}

	// What an ICMP error from a hostile exit quotes is cut wherever the exit cut it. Every cut of every kind of packet the entry sent is put back as its device sent it, as far as the quote holds it: the addresses, the port or echo identifier and the IPv4 header whole, and every checksum when the quote is whole.
	#[test]
	fn a_quote_cut_anywhere_is_put_back_as_the_device_sent_it() {
		let (user, user6, dst, dst6) = ([10, 7, 0, 2], [0xfd; 16], [93, 184, 216, 34], [0x20; 16]);
		let mut sent = Vec::new();
		for (protocol, body) in [(Protocol::SCTP, vec![0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 4]), (47, vec![0, 0, 0x08, 0, 1, 2, 3, 4])] {
			let mut raw = [&[0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, protocol, 0, 0][..], &user, &dst, &body].concat();
			let total = raw.len() as u16;
			raw[2..4].copy_from_slice(&total.to_be_bytes());
			let packet = netstack::parse(&raw).unwrap();
			fix(&mut raw, &packet);
			sent.push(raw);
		}
		for v4 in [true, false] {
			let ip = || if v4 {PacketBuilder::ipv4(user, dst, 64)} else {PacketBuilder::ipv6(user6, dst6, 64)};
			let (mut tcp, mut udp, mut ping) = (Vec::new(), Vec::new(), Vec::new());
			ip().tcp(40000, 443, 1, 65535).write(&mut tcp, b"some data").unwrap();
			ip().udp(40000, 443).write(&mut udp, b"a datagram").unwrap();
			if v4 {ip().icmpv4_echo_request(7, 1).write(&mut ping, b"ping").unwrap()} else {ip().icmpv6_echo_request(7, 1).write(&mut ping, b"ping").unwrap()}
			sent.extend([tcp, udp, ping]);
		}
		let mut unsummed = sent[3].clone();
		unsummed[26..28].copy_from_slice(&[0, 0]);
		sent.push(unsummed);
		for device in sent {
			let packet = netstack::parse(&device).unwrap();
			let v4 = packet.src.is_ipv4();
			let port = match packet.protocol {
				Protocol::ICMP | Protocol::ICMPV6 => Some(7),
				Protocol::TCP | Protocol::UDP | Protocol::SCTP => Some(40000),
				_ => None,
			};
			let mut translated = device.clone();
			assert!(rewrite(&mut translated, &packet, true, if v4 {IpAddr::from([10, 9, 0, 3])} else {"fd00:9::3".parse().unwrap()}, port.map(|_| 5000)));
			let (address, field, header) = (if v4 {12..16} else {8..24}, if port == Some(7) {packet.upper + 4..packet.upper + 6} else {packet.upper..packet.upper + 2}, if v4 {20} else {40});
			for cut in 0..=translated.len() {
				let mut quote = translated[..cut].to_vec();
				let Some(quoted) = netstack::quoted(&quote) else {continue};
				assert!(unquote(&mut quote, &quoted, packet.src, port), "a quote of {cut} bytes of protocol {} was not put back", packet.protocol);
				let what = format!("a quote of {cut} bytes of protocol {}", packet.protocol);
				assert_eq!(quote[address.clone()], device[address.clone()], "{what}: the address");
				if port.is_some() && cut >= field.end {assert_eq!(quote[field.clone()], device[field.clone()], "{what}: the port")}
				if v4 && cut >= header {assert_eq!(quote[..header], device[..header], "{what}: the IPv4 header")}
				if cut == device.len() {verified(&quote)}
			}
		}
	}

	#[test]
	fn an_ipv6_packet_loses_its_flow_label_and_traffic_class_but_its_congestion_bits() {
		let mut raw = Vec::new();
		PacketBuilder::ipv6([0xfd; 16], [0x20; 16], 3).udp(40000, 443).write(&mut raw, b"data").unwrap();
		(raw[0], raw[1], raw[2], raw[3]) = (0x6b, 0x9f, 0x12, 0x34);
		let packet = netstack::parse(&raw).unwrap();
		rewrite(&mut raw, &packet, true, "fd00:9::2".parse().unwrap(), Some(2000));
		fields(&mut raw, &packet);
		verified(&raw);
		// Traffic class 0xb9: its two congestion bits are 01.
		assert_eq!((raw[0], raw[1], raw[2], raw[3], raw[7]), (0x60, 0x10, 0, 0, HOPS));
	}

	#[test]
	fn a_flow_keeps_its_translation_and_a_port_rests_after_it() {
		let (nat, flows) = (Nat::default(), super::super::route::Flows::default());
		let key = Key {protocol: Protocol::UDP, src: "10.7.0.2".parse().unwrap(), dst: "93.184.216.34".parse().unwrap(), sport: 40000, dport: 443};
		let id = flows.insert(key, [1; 32], "a", Decision::Exit {exit: 0, by: By::Backend}, Vec::new(), None, 0).unwrap();
		let port = nat.map(&key, 0, id, [7; 16], true, &flows).unwrap();
		assert!(PORTS.contains(&port));
		assert_eq!((nat.of_flow(&key, 0, id, &flows), nat.of_flow(&key, 0, id + 1, &flows), nat.of(&[7; 16])), (Some(([7; 16], port)), None, 0));
		let id = flows.insert(key, [1; 32], "a", Decision::Exit {exit: 0, by: By::Backend}, Vec::new(), None, 0).unwrap();
		let port = nat.map(&key, 0, id, [7; 16], true, &flows).unwrap();
		assert_eq!((nat.back([7; 16], Protocol::UDP, key.dst, 443, port, None), nat.back([8; 16], Protocol::UDP, key.dst, 443, port, None), nat.back([7; 16], Protocol::UDP, key.dst, 444, port, None)), (Some((key, 0, id)), None, None));
		// Without ports one flow holds the remote address under the protocol, and another flow is refused until it has gone.
		let (gre, other) = (Key {protocol: 47, sport: 0, dport: 0, ..key}, Key {protocol: 47, sport: 0, dport: 0, src: "10.7.0.3".parse().unwrap(), ..key});
		let held = flows.insert(gre, [1; 32], "a", Decision::Exit {exit: 0, by: By::Backend}, Vec::new(), None, 0).unwrap();
		assert_eq!((nat.map(&gre, 0, held, [7; 16], false, &flows), nat.map(&other, 0, 99, [7; 16], false, &flows)), (Ok(0), Err(Unmapped::Held)));
		flows.end(&[(gre, held)], 0);
		nat.sweep(&flows);
		assert_eq!(nat.map(&other, 0, 99, [7; 16], false, &flows), Ok(0));
		// A ping flow holds at most so many identifiers.
		let ping = Key {protocol: Protocol::ICMP, sport: 8, dport: 0, ..key};
		let pinging = flows.insert(ping, [1; 32], "a", Decision::Exit {exit: 0, by: By::Backend}, Vec::new(), None, 0).unwrap();
		for ident in 1..=ECHOES as u32 {nat.map(&ping, ident, pinging, [7; 16], true, &flows).unwrap();}
		assert_eq!(nat.map(&ping, 999, pinging, [7; 16], true, &flows), Err(Unmapped::Held));
		// The port of a flow that ended rests and is not drawn again for the same remote address and port.
		flows.end(&[(key, id)], 0);
		nat.sweep(&flows);
		assert_eq!(nat.back([7; 16], Protocol::UDP, key.dst, 443, port, None), None);
		assert!(!nat.lock().free(&Far {link: [7; 16], protocol: Protocol::UDP, remote: key.dst, rport: 443, port}, Instant::now()));
		assert!(nat.lock().free(&Far {link: [7; 16], protocol: Protocol::UDP, remote: key.dst, rport: 443, port}, Instant::now() + REST));
	}

	#[test]
	fn echo_identifiers_take_places_in_the_shares_of_the_device_and_the_user() {
		let (nat, flows, exit) = (Nat::default(), Flows::default(), Decision::Exit {exit: 0, by: By::Backend});
		let ping = |to: usize| Key {protocol: Protocol::ICMP, src: "10.7.0.2".parse().unwrap(), dst: IpAddr::from([93, 184, (to >> 8) as u8, to as u8]), sport: 8, dport: 0};
		// One device pings host after host with every identifier a ping flow may hold. Its flows and identifiers together never pass its share, and past it new flows and new identifiers alike are refused.
		let (mut held, mut ids) = (0, Vec::new());
		for to in 0..MAX_FLOWS_PER_DEVICE {
			let Ok(id) = flows.insert(ping(to), [1; 32], "a", exit, Vec::new(), None, 0) else {break};
			ids.push((ping(to), id));
			held += (1..=ECHOES as u32).filter(|ident| nat.map(&ping(to), *ident, id, [7; 16], true, &flows).is_ok()).count();
		}
		assert_eq!((held, ids.len()), (MAX_FLOWS_PER_DEVICE, MAX_FLOWS_PER_DEVICE.div_ceil(ECHOES)), "a device held more echo identifiers than its share has places");
		// Another device of another user is not touched by it.
		assert!(flows.insert(ping(9999), [2; 32], "b", exit, Vec::new(), None, 0).is_ok());
		// When the flows end, every place comes back: the user then has all of their share for two devices of theirs.
		flows.end(&ids, 0);
		nat.sweep(&flows);
		let taken = (0..MAX_FLOWS_PER_USER + 1).filter(|to| flows.insert(Key {protocol: Protocol::UDP, sport: 1, dport: 2, ..ping(*to)}, [3 + (*to % 2) as u8; 32], "a", exit, Vec::new(), None, 0).is_ok()).count();
		assert_eq!(taken, MAX_FLOWS_PER_USER, "the places of the echo identifiers did not all come back");
	}
}
