//! The path MTU of a node link (node links page, "MTU"): the largest packet that crosses the path between the two nodes in both directions, found by probing inside the link's own WireGuard session. The link's configured `mtu` is the ceiling and the found size lowers it, never raises it.
//! A probe is an ICMP or ICMPv6 echo request padded to the probe size, sent from the dialler's link address to the same address: a forward link gives the node that is dialled no address of its own, so the dialler's is the one both nodes know. Either node may send one, and the other answers every such request with a reply of the same size, without forwarding it anywhere. A size passes when the reply of exactly that size comes back with this walk's identifier, sequence number and token, so one round trip proves both directions.
//! Nothing answered, not even 1280, means the other node is old or does not answer, and the configured `mtu` stays: an old node must never be made slower by this.
use super::netstack::{self, ECHO_REPLY_V4, ECHO_REPLY_V6};
use super::plan::Plan;
use super::{link, Shared};
use crate::config::{random, Protocol};
use etherparse::PacketBuilder;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use veilway_proto::control::{self, MTU_MIN};

/// A probe that is not answered in this long is lost, and one retry follows before its size fails.
const WAIT: Duration = Duration::from_secs(2);
/// The pause before each probe after the first.
const SPACING: Duration = Duration::from_millis(200);
/// Probes in one walk, whatever happens.
const PROBES: usize = 16;
/// A walk starts this often while the link is up, and its first probe is the size in use, so a path that has not changed costs one round trip.
pub const EVERY: Duration = Duration::from_secs(600);
/// Walks the size warning asks for are at least this far apart.
pub const GAP: Duration = Duration::from_secs(60);
/// A link answers at most 20 probes at once and then one every 500 ms.
const ANSWERS: u32 = 20;
const REFILL: u128 = 500;

/// What a walk asks of its driver.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
	/// Send a probe whose whole IP packet is `size` bytes, with this sequence number.
	Probe {seq: u16, size: u16},
	/// The walk is over: the largest size that passed, or None when none did.
	Done(Option<u16>),
}

/// The walk, with no socket and no clock of its own. The configured `mtu` is tried first and the table of sizes below it follows, largest first. A size fails after a lost probe and one lost retry, and the first size that passes ends the walk.
pub struct Walk {sizes: Vec<u16>, at: usize, seq: u16, probes: usize, retried: bool, waiting: bool, due: Instant}

impl Walk {
	/// None when `ceiling` is below 1280, where there is nothing to find.
	pub fn start(ceiling: u16, now: Instant) -> Option<Walk> {
		let sizes: Vec<u16> = control::probe_sizes(ceiling, MTU_MIN).collect();
		(!sizes.is_empty()).then(|| Walk {sizes, at: 0, seq: 0, probes: 0, retried: false, waiting: false, due: now})
	}

	/// When `poll` has something to do.
	pub fn due(&self) -> Instant {self.due}

	pub fn poll(&mut self, now: Instant) -> Option<Action> {
		if now < self.due {return None}
		if self.waiting {
			(self.waiting, self.due) = (false, now + SPACING);
			if self.retried {(self.retried, self.at) = (false, self.at + 1)} else {self.retried = true}
			return (self.at >= self.sizes.len()).then_some(Action::Done(None));
		}
		if self.probes >= PROBES {return Some(Action::Done(None))}
		(self.seq, self.probes, self.waiting, self.due) = (self.seq.wrapping_add(1), self.probes + 1, true, now + WAIT);
		Some(Action::Probe {seq: self.seq, size: self.sizes[self.at]})
	}

	/// A reply came: only the one for the probe in hand, at the size it was sent, ends the walk.
	pub fn answered(&mut self, seq: u16, size: u16) -> Option<Action> {
		if !self.waiting || seq != self.seq || size != self.sizes[self.at] {return None}
		self.waiting = false;
		Some(Action::Done(Some(size)))
	}
}

/// What a link keeps of its probing. The found size is stored with the `mtu` it was found under, so a reload that changes `mtu` does not apply a size found for another.
#[derive(Default)]
pub struct Probing {
	found: AtomicU32,
	pub(super) walking: AtomicBool,
	pub(super) walked: Mutex<Option<Instant>>,
	/// The size warning wants a walk now.
	pub(super) asked: AtomicBool,
	silent: AtomicBool,
	/// The walk in hand: its identifier, its token and where matching replies go.
	active: Mutex<Option<(u16, [u8; 8], mpsc::Sender<(u16, u16)>)>>,
	answers: Mutex<Option<(u32, Instant)>>,
}

impl Probing {
	/// The link's `mtu` that is in force: `mtu`, lowered by the size found for it.
	pub fn effective(&self, mtu: u16) -> u16 {self.found(mtu).map_or(mtu, |found| found.min(mtu))}

	/// The largest size that passed in both directions at the last walk that found one, for this `mtu`.
	pub fn found(&self, mtu: u16) -> Option<u16> {
		let found = self.found.load(Ordering::Relaxed);
		(found != 0 && (found >> 16) as u16 == mtu).then_some(found as u16)
	}
}

/// The echo request of a probe: `size` bytes in all, from and to `address`, with the token and then zeros as its data.
fn request(address: IpAddr, id: u16, seq: u16, size: u16, token: &[u8; 8]) -> Option<Vec<u8>> {
	let (mut out, headers) = (Vec::new(), if address.is_ipv4() {28} else {48});
	let data = [token.as_slice(), &vec![0u8; usize::from(size).checked_sub(headers + 8)?]].concat();
	match address {
		IpAddr::V4(address) => PacketBuilder::ipv4(address.octets(), address.octets(), 64).icmpv4_echo_request(id, seq).write(&mut out, &data).ok()?,
		IpAddr::V6(address) => PacketBuilder::ipv6(address.octets(), address.octets(), 64).icmpv6_echo_request(id, seq).write(&mut out, &data).ok()?,
	}
	Some(out)
}

/// The sequence number and the size of an echo reply that carries this walk's identifier and token and nothing else: the data must be the token and zeros, exactly as sent. What the other node says is hostile input.
fn answer(raw: &[u8], packet: &netstack::Packet, id: u16, token: &[u8; 8]) -> Option<(u16, u16)> {
	let body = raw.get(packet.upper..packet.len).filter(|body| body.len() >= 16)?;
	(u16::from_be_bytes([body[4], body[5]]) == id && body[8..16] == token[..] && body[16..].iter().all(|byte| *byte == 0)).then(|| u16::try_from(packet.len).ok().map(|size| (u16::from_be_bytes([body[6], body[7]]), size)))?
}

impl Shared {
	/// The branch of `ingress` for what came out of link `link`: an echo request or reply from the dialler's link address to itself is a probe, and nobody else's. A request is answered at once, within the limit, with a reply of its size, never larger than the link's configured `mtu`. A reply goes to the walk that holds its identifier, if there is one, and is dropped if not. True when the packet was a probe.
	pub(super) async fn probe_ingress(&self, plan: &Plan, link: usize, raw: &[u8]) -> bool {
		let of = &plan.links[link];
		let Some(packet) = netstack::parse(raw).filter(|packet| !packet.fragment && packet.src == packet.dst && of.dialler.contains(&packet.dst)) else {return false};
		let reply = matches!((packet.protocol, packet.icmp), (Protocol::ICMP, Some((ECHO_REPLY_V4, 0))) | (Protocol::ICMPV6, Some((ECHO_REPLY_V6, 0))));
		if !packet.echo_request() && !reply {return false}
		let probing = &of.state.probing;
		if reply {
			let active = probing.active.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|(id, token, tx)| (*id, *token, tx.clone()));
			match active.and_then(|(id, token, tx)| answer(raw, &packet, id, &token).map(|found| (tx, found))) {
				Some((tx, found)) => drop(tx.try_send(found)),
				None => {of.state.dropped.fetch_add(1, Ordering::Relaxed);}
			}
			return true;
		}
		let allowed = {
			let mut bucket = probing.answers.lock().unwrap_or_else(|e| e.into_inner());
			let (tokens, since) = bucket.unwrap_or((ANSWERS, Instant::now()));
			let gained = u32::try_from(since.elapsed().as_millis() / REFILL).unwrap_or(u32::MAX);
			let (tokens, since) = if gained > 0 {(tokens.saturating_add(gained).min(ANSWERS), Instant::now())} else {(tokens, since)};
			*bucket = Some((tokens.saturating_sub(1), since));
			tokens > 0
		};
		match netstack::echo_reply(raw, &packet).filter(|reply| allowed && packet.len <= usize::from(of.mtu) && reply.len() == packet.len) {
			Some(reply) => {let _ = self.into_link(plan, link, &reply).await;}
			None => {of.state.dropped.fetch_add(1, Ordering::Relaxed);}
		}
		true
	}
}

/// One walk of link `id`, as a task. It ends early, with nothing changed, when the link goes or comes down, and says every change of the size in force.
pub(super) async fn walk(shared: Arc<Shared>, id: [u8; 16], state: Arc<link::State>) {
	let probing = &state.probing;
	let outcome = async {
		let (mut seed, (tx, mut replies)) = ([0u8; 10], mpsc::channel(8));
		random(&mut seed).ok()?;
		let (probe, token) = (u16::from_le_bytes([seed[0], seed[1]]), <[u8; 8]>::try_from(&seed[2..]).ok()?);
		let (tag, ceiling) = {
			let plan = shared.plan();
			let of = plan.links.iter().find(|link| link.id == id)?;
			(of.tag.clone(), of.mtu)
		};
		let mut walk = Walk::start(ceiling, Instant::now())?;
		*probing.active.lock().unwrap_or_else(|e| e.into_inner()) = Some((probe, token, tx));
		loop {
			let action = tokio::select! {
				Some((seq, size)) = replies.recv() => walk.answered(seq, size),
				_ = tokio::time::sleep(walk.due().saturating_duration_since(Instant::now())) => walk.poll(Instant::now()),
			};
			match action {
				Some(Action::Probe {seq, size}) => {
					let plan = shared.plan();
					let at = plan.links.iter().position(|link| link.id == id).filter(|at| plan.up(*at))?;
					let address = plan.links[at].dialler.iter().find(|address| address.is_ipv4()).or(plan.links[at].dialler.first())?;
					// A probe the tunnel cannot send is a lost one.
					if let Some(packet) = request(*address, probe, seq, size, &token) {let _ = shared.into_link(&plan, at, &packet).await;}
				}
				Some(Action::Done(found)) => return Some((tag, ceiling, found)),
				None => {}
			}
		}
	}.await;
	*probing.active.lock().unwrap_or_else(|e| e.into_inner()) = None;
	probing.asked.store(false, Ordering::Relaxed);
	probing.walking.store(false, Ordering::Relaxed);
	let Some((tag, ceiling, found)) = outcome else {return};
	match found {
		Some(size) => {
			let before = probing.effective(ceiling);
			probing.found.store(u32::from(ceiling) << 16 | u32::from(size), Ordering::Relaxed);
			probing.silent.store(false, Ordering::Relaxed);
			let now = probing.effective(ceiling);
			if before != now {tracing::info!("link {tag}: the path between the two nodes carries packets of {size} bytes in both directions, so the link's mtu in force is {now} (it was {before}, and the configured mtu is {ceiling}). It is probed again every {}s, and goes back up when the path allows it", EVERY.as_secs())}
		}
		None => if !probing.silent.swap(true, Ordering::Relaxed) {tracing::info!("link {tag}: the other node answered no size probe, not even one of {MTU_MIN} bytes, so it is an older node or does not answer them. The link keeps its mtu of {}, and is probed again every {}s", probing.effective(ceiling), EVERY.as_secs())},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::BTreeSet;
	use std::net::Ipv4Addr;

	// Drives a walk against a path that carries packets up to `limit` bytes, or none. `lose_first` loses the first probe of every size, to see that the retry carries it.
	fn run(ceiling: u16, limit: Option<u16>, lose_first: bool) -> (Option<u16>, usize, BTreeSet<u16>) {
		let (mut now, mut walk, mut asked, mut sizes) = (Instant::now(), Walk::start(ceiling, Instant::now()).unwrap(), 0, BTreeSet::new());
		let mut last = 0;
		loop {
			now = now.max(walk.due());
			match walk.poll(now) {
				Some(Action::Probe {seq, size}) => {
					asked += 1;
					sizes.insert(size);
					let first = size != last;
					last = size;
					if limit.is_some_and(|limit| size <= limit) && !(lose_first && first) {
						if let Some(Action::Done(found)) = walk.answered(seq, size) {return (found, asked, sizes)}
					}
				}
				Some(Action::Done(found)) => return (found, asked, sizes),
				None => {}
			}
		}
	}

	#[test]
	fn a_path_that_carries_the_ceiling_costs_one_probe() {
		assert_eq!(run(1420, Some(1500), false).0, Some(1420));
		assert_eq!(run(1420, Some(1500), false).1, 1);
		assert_eq!(run(1280, Some(1280), false), (Some(1280), 1, BTreeSet::from([1280])));
	}

	#[test]
	fn a_path_that_carries_less_finds_the_largest_size_of_the_table_that_passes() {
		assert_eq!(run(1420, Some(1350), false).0, Some(1320));
		assert_eq!(run(1420, Some(1390), false).0, Some(1390));
		assert_eq!(run(1440, Some(1420), false).0, Some(1420));
		assert_eq!(run(1420, Some(1280), false).0, Some(1280));
		assert_eq!(run(1500, Some(1281), false).0, Some(1280));
		assert_eq!(run(1390, Some(1300), false).0, Some(1280));
		// A ceiling that is not in the table is the first size, and the table follows below it.
		assert_eq!(run(1400, Some(1395), false).0, Some(1390));
	}

	#[test]
	fn a_size_fails_after_a_lost_probe_and_one_retry_and_a_lost_probe_alone_fails_nothing() {
		let (found, asked, sizes) = run(1420, Some(1350), false);
		assert_eq!((found, asked, sizes.len()), (Some(1320), 7, 4), "two probes for each size that failed and one for the size that passed");
		assert_eq!(run(1420, Some(1500), true), (Some(1420), 2, BTreeSet::from([1420])));
		assert_eq!(run(1420, Some(1350), true).0, Some(1320));
	}

	#[test]
	fn nothing_answered_keeps_the_configured_mtu_and_never_asks_more_than_16_times() {
		for ceiling in [1280, 1390, 1420, 1500, 9000] {
			let (found, asked, _) = run(ceiling, None, false);
			assert!(found.is_none() && asked <= PROBES, "{ceiling}: {found:?} {asked}");
		}
		assert_eq!(run(1420, Some(1279), false).0, None, "a path below 1280 is the same as silence");
		assert!(Walk::start(1279, Instant::now()).is_none());
	}

	#[test]
	fn a_reply_that_is_not_the_one_asked_for_is_ignored() {
		let now = Instant::now();
		let mut walk = Walk::start(1420, now).unwrap();
		assert!(walk.answered(1, 1420).is_none(), "nothing is asked yet");
		assert_eq!(walk.poll(now), Some(Action::Probe {seq: 1, size: 1420}));
		for (seq, size) in [(2, 1420), (0, 1420), (1, 1390), (1, 1419), (1, 1421)] {assert!(walk.answered(seq, size).is_none(), "{seq} {size}")}
		assert_eq!(walk.answered(1, 1420), Some(Action::Done(Some(1420))));
		assert!(walk.answered(1, 1420).is_none(), "a second reply is no answer");
	}

	#[test]
	fn a_probe_is_exactly_its_size_and_only_its_own_reply_is_an_answer() {
		let token = [9u8; 8];
		for address in [IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), "fd00::2".parse().unwrap()] {
			for size in [1280u16, 1390, 1420] {
				let mut raw = request(address, 77, 3, size, &token).unwrap();
				let packet = netstack::parse(&raw).unwrap();
				assert!(packet.echo_request() && packet.src == address && packet.dst == address && packet.len == usize::from(size), "{address} {size}");
				let mut reply = netstack::echo_reply(&raw, &packet).unwrap();
				let parsed = netstack::parse(&reply).unwrap();
				assert_eq!(answer(&reply, &parsed, 77, &token), Some((3, size)));
				assert_eq!(answer(&reply, &parsed, 78, &token), None, "another identifier");
				assert_eq!(answer(&reply, &parsed, 77, &[1; 8]), None, "another token");
				let last = reply.len() - 1;
				reply[last] = 1;
				assert_eq!(answer(&reply, &parsed, 77, &token), None, "data that is not what was sent");
				raw.truncate(packet.upper + 10);
				assert!(netstack::parse(&raw).is_none() || answer(&raw, &packet, 77, &token).is_none());
			}
		}
		assert!(request(IpAddr::V4(Ipv4Addr::LOCALHOST), 1, 1, 20, &token).is_none());
	}

	#[test]
	fn the_found_size_lowers_the_mtu_it_was_found_for_and_no_other() {
		let probing = Probing::default();
		assert_eq!((probing.effective(1420), probing.found(1420)), (1420, None));
		probing.found.store(1420 << 16 | 1320, Ordering::Relaxed);
		assert_eq!((probing.effective(1420), probing.found(1420)), (1320, Some(1320)));
		assert_eq!((probing.effective(1390), probing.found(1390)), (1390, None), "a reload that changed mtu has to find it again");
		probing.found.store(1420 << 16 | 1420, Ordering::Relaxed);
		assert_eq!(probing.effective(1420), 1420);
	}
}
