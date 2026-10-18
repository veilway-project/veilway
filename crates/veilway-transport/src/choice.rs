//! Which candidate and which transport come next, and after which wait (transports page, "Choosing a candidate", "Transport fallback", "Refusals and clocks").
//!
//! Everything here is a function over state the caller keeps and stores: `Network` for each network a profile was used on, `Standing` for the profile. Time is Unix seconds on the device's clock, and random numbers come from the caller's source. Nothing here dials, waits or stores.
//!
//! `Network` and `Standing` are untrusted input. They come back from a file that may be damaged or written under another clock, and they were made for a list of transports that a refresh may have changed since. Every function here first drops what cannot be true: a time in the future, a mark that would last longer than a mark can, and everything but consent when the list of transports is another one. No value in them can hold a candidate or a transport back for longer than an hour, or make anything panic.
//!
//! How the pieces go together. `plan` gives the transports a client may try, in order, and the classes it has to ask the user about first. For a stream transport, `candidates` gives the one or two candidates to open now (the second 250 ms after the first, both with the same WireGuard datagram, the loser closed). `outcome` takes how an attempt or a session ended and says whether the same candidate is tried again, or the next one, and after which wait. When a transport has no candidate left, `fallback` gives the wait before the next transport and sets it aside if its candidates were unreachable. `reset` is "the user asks to connect again".
//! The kill switch is not here and does not depend on any of it: between attempts nothing leaves the device but the transport's own connection.
use crate::{End, Ended, Unreachable};
use std::time::Duration;
use veilway_proto::subscription::payload::Transport;
use veilway_proto::{uniform, NoRandom, Random};

/// "Set aside for 1 hour", and the hour of the candidate budget.
pub const HOUR: u64 = 3_600;
/// "The last working one remembered for 7 days", and how long a datagram transport counts as one that worked here.
pub const WEEK: u64 = 7 * 86_400;
/// "Clock offset from `Date`: kept for at most 24 h."
pub const OFFSET_KEPT: u64 = 86_400;
/// "2 in flight, 250 ms apart."
pub const IN_FLIGHT: usize = 2;
pub const STAGGER: Duration = Duration::from_millis(250);
/// "6 distinct per hour per network."
pub const DISTINCT: usize = 6;
/// "A candidate is tried at most 3 times in a row, the first attempt included, before the client moves on."
pub const ROW: u32 = 3;
/// "3 per round": transports tried before the backoff between rounds.
pub const ROUND: u32 = 3;
/// "Silence on a datagram transport that worked on this network within the last 7 days: retried for 90 s in all."
pub const SILENCE: u64 = 90;
/// How long a session must have stayed open for the reconnect wait to return to its start. A path that lets a session open and cuts it at once would otherwise be dialled again every second for ever.
pub const LIVED: u64 = 60;
/// After this many sessions in a row that were lost before they had lived that long, the client moves on to the next candidate.
pub const FLAPS: u32 = 3;
// How many entries of a list are kept of a state that was read back: more than any honest run writes.
const KEPT: usize = 64;

/// The class of a transport, "from strongest to weakest": what fallback and consent are based on. It is fixed by the table of the transports page and is not a rating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {Cover, NoCover, Exposed, Plain}

pub fn class(transport: &Transport) -> Class {
	match transport {
		Transport::Tls(_) | Transport::Ws(_) | Transport::Fronted(_) | Transport::FrontedShaped(..) | Transport::FakeTls {..} => Class::Cover,
		Transport::UdpObfs(_) => Class::NoCover,
		Transport::Udp(_) => Class::Plain,
	}
}

/// What ties a `Network` and a `Standing` to the list of transports they were made for: their places in it mean nothing in another list. It tells lists apart and protects nothing.
pub fn digest(transports: &[Transport]) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325u64;
	let mut take = |bytes: &[u8]| {
		for byte in bytes.iter().chain(&[0xff]) {hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)}
	};
	for transport in transports {
		let (kind, endpoints, stream) = match transport {
			Transport::Udp(endpoints) => (0u8, &endpoints[..], None),
			Transport::UdpObfs(endpoints) => (1, &endpoints[..], None),
			Transport::Tls(stream) => (2, &[][..], Some(stream)),
			Transport::Ws(stream) => (3, &[][..], Some(stream)),
			Transport::Fronted(stream) => (4, &[][..], Some(stream)),
			Transport::FrontedShaped(stream, _) => (5, &[][..], Some(stream)),
			Transport::FakeTls {..} => (6, &[][..], None),
		};
		take(&[kind]);
		// A new key, a new address or a new site is another transport too.
		if let Transport::FakeTls {key, candidates} = transport {
			take(key);
			for candidate in candidates {
				take(candidate.address.address().to_string().as_bytes());
				take(candidate.sni.as_bytes());
			}
		}
		// A shape that changes is another transport for everything that is remembered about this one.
		if let Transport::FrontedShaped(_, shape) = transport {take(shape.to_string().as_bytes())}
		for endpoint in endpoints {take(endpoint.address().to_string().as_bytes())}
		if let Some(stream) = stream {
			take(stream.path.as_bytes());
			for candidate in &stream.candidates {
				take(candidate.address.address().to_string().as_bytes());
				for name in [candidate.sni.as_deref(), Some(&candidate.host[..]), candidate.verify_name.as_deref()] {take(name.unwrap_or_default().as_bytes())}
				take(candidate.ech.as_deref().unwrap_or_default());
				for pin in &candidate.pins {take(pin)}
			}
		}
	}
	hash
}

/// What a client remembers of one network for one profile. A network is "identified by what the system exposes", which is the caller's to find out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Network {
	/// `digest` of the transports this was made for.
	pub profile: u64,
	/// The transport and candidate (or endpoint) that last worked, and when.
	pub worked: Option<(usize, usize, u64)>,
	/// What is set aside as unreachable, and until when: a candidate of a transport, or with None the whole transport. "The mark expires", an hour after it was made at the latest.
	pub aside: Vec<(usize, Option<usize>, u64)>,
	/// The distinct candidates tried in the last hour, each with the time of its first try.
	pub tried: Vec<(usize, usize, u64)>,
	/// A datagram transport that worked here and has gone silent, and since when.
	pub silent: Option<(usize, u64)>,
}

/// What a client keeps for a profile on every network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Standing {
	/// `digest` of the transports this was made for.
	pub profile: u64,
	/// Refusals since a session last opened or the user last asked to connect: what the refusal wait doubles by.
	pub refusals: u32,
	/// The candidates that refused, each with how often in a row. "With two candidates in flight each has its own count of three."
	pub rows: Vec<(usize, usize, u32)>,
	/// Sessions lost since one last stayed open for `LIVED`: what the reconnect wait doubles by.
	pub losses: u32,
	/// When the session that is open, or was open last, opened.
	pub opened: Option<u64>,
	/// Sessions in a row that were lost before they had lived `LIVED`.
	pub short: u32,
	/// The last attempt ended as `End::Unanswered` and was given its one retry.
	pub unanswered: bool,
	/// The classes the user agreed to for this profile. "The answer is stored per profile and class and can be withdrawn."
	pub consent: Vec<Class>,
	/// The clock offset a pinned candidate's `Date` gave, in seconds, and when it was taken.
	pub offset: Option<(i64, u64)>,
	/// The next attempt is made on the device's clock though an offset is held: a candidate without a pin refused, and an offset that has gone stale can be shed in no other way.
	pub bare: bool,
}

// A state as it may be used at `now` for the transports of `profile`: see the head of this module.
fn sound(network: &mut Network, standing: &mut Standing, profile: u64, now: u64) {
	if network.profile != profile {*network = Network {profile, ..Network::default()}}
	if standing.profile != profile {*standing = Standing {profile, consent: std::mem::take(&mut standing.consent), ..Standing::default()}}
	network.aside.retain(|(_, _, until)| *until > now && *until <= now.saturating_add(HOUR));
	network.tried.retain(|(_, _, when)| *when <= now && now < when.saturating_add(HOUR));
	network.worked = network.worked.filter(|(_, _, when)| *when <= now && now < when.saturating_add(WEEK));
	// A silence that was not followed up within the hour is over: the next one starts its 90 s anew.
	network.silent = network.silent.filter(|(_, since)| *since <= now && now < since.saturating_add(HOUR));
	standing.offset = standing.offset.filter(|(_, taken)| *taken <= now && now - taken <= OFFSET_KEPT);
	standing.opened = standing.opened.filter(|opened| *opened <= now);
	// A list far longer than any run writes is no list of a run.
	if network.aside.len() > KEPT {network.aside.clear()}
	if network.tried.len() > KEPT {network.tried.clear()}
	if standing.rows.len() > KEPT {standing.rows.clear()}
	standing.consent.truncate(KEPT);
}

/// Whether a transport may be used under the client's `alpha_transports` setting: "No `faketls` candidate is dialed until it is on." Every other transport may.
pub fn usable(transport: &Transport, alpha: bool) -> bool {alpha || !matches!(transport, Transport::FakeTls {..})}

/// The transports of a profile a client may try now, in the order to try them, and the classes it must ask about before it may use them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {pub order: Vec<usize>, pub ask: Vec<Class>}

/// "The client uses a transport of a lower class than the best class in the profile only when the user has agreed to that class for this profile. This covers the first attempt as well as fallback."
/// The order is the provider's. The transport that last worked on this network comes first, and with `stream_first` "the client tries every cover transport before any other". Where the two disagree `stream_first` wins. A transport that is set aside is left out, unless that would leave none: "The last transport of a profile that the client is allowed to use is never set aside."
/// A `faketls` transport is left out while `alpha` is off, and the best class is then the best of the others: the profile is planned as if it did not list it.
pub fn plan(transports: &[Transport], stream_first: bool, network: &Network, standing: &Standing, now: u64, alpha: bool) -> Plan {
	let (mut network, mut standing) = (network.clone(), standing.clone());
	sound(&mut network, &mut standing, digest(transports), now);
	let Some(best) = transports.iter().filter(|transport| usable(transport, alpha)).map(class).min() else {return Plan::default()};
	let (mut ask, mut order): (Vec<Class>, Vec<usize>) = (transports.iter().filter(|transport| usable(transport, alpha)).map(class).filter(|class| *class > best && !standing.consent.contains(class)).collect(), (0..transports.len()).filter(|at| usable(&transports[*at], alpha) && (class(&transports[*at]) == best || standing.consent.contains(&class(&transports[*at])))).collect());
	ask.sort();
	ask.dedup();
	if let Some(first) = network.worked.and_then(|(worked, _, _)| order.iter().position(|at| *at == worked)) {order[..=first].rotate_right(1)}
	if stream_first {order.sort_by_key(|at| class(&transports[*at]) != Class::Cover)}
	let free: Vec<usize> = order.iter().copied().filter(|at| !network.aside.iter().any(|(transport, candidate, _)| transport == at && candidate.is_none())).collect();
	Plan {order: if free.is_empty() {order} else {free}, ask}
}

/// What to do about the candidates of one transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
	/// Open these now: one, or two with the second `STAGGER` after the first.
	Try(Vec<usize>),
	/// "At most 6 distinct candidates are tried per hour per network. When that is spent the client waits, and says so": until this moment, which is never more than an hour away.
	Wait(u64),
	/// Every candidate that is not set aside was passed after its refusals. The transport is reachable: `fallback` is asked for the wait and told to mark nothing, since "a refusal never sets a transport aside".
	Passed,
	/// Every candidate is set aside as unreachable: `fallback` is asked, and marks the transport.
	Nothing,
}

// The place of a candidate in the walk of one installation.
fn place(seed: u64, transport: usize, candidate: usize) -> u64 {seed.to_le_bytes().iter().chain(&(transport as u64).to_le_bytes()).chain(&(candidate as u64).to_le_bytes()).fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3))}

/// The candidates of `transport`, which has `count` of them, to open next. `profile` is `digest` of the profile's transports.
/// "The client keeps, per network, the candidate that last worked, and tries it first and alone. If there is none, or it is unreachable, the client walks the list in an order that is random per installation and fixed between attempts": `seed` is the installation's, drawn once and kept.
/// `passed` are the candidates this walk moved on from after three refusals in a row, which are not set aside. `last` says this is the only transport `plan` gave: then the marks of its candidates are passed over when none is free, since the client "keeps trying it", and a candidate that was unreachable a minute ago is the only thing there is to try. What is picked is counted against the hour's budget here.
pub fn candidates(network: &mut Network, profile: u64, transport: usize, count: usize, passed: &[usize], last: bool, seed: u64, now: u64) -> Pick {
	sound(network, &mut Standing {profile, ..Standing::default()}, profile, now);
	let marked = |candidate: &usize| network.aside.iter().any(|(at, aside, _)| *at == transport && *aside == Some(*candidate));
	let (open, free): (Vec<usize>, Vec<usize>) = ((0..count).filter(|candidate| !marked(candidate)).collect(), (0..count).filter(|candidate| !marked(candidate) && !passed.contains(candidate)).collect());
	let mut walk = match network.worked.filter(|(at, candidate, _)| *at == transport && free.contains(candidate)) {
		Some((_, candidate, _)) => vec![candidate],
		None if free.is_empty() && open.is_empty() && last => (0..count).filter(|candidate| !passed.contains(candidate)).collect(),
		None => free,
	};
	// Where marks are passed over, the candidate whose mark is oldest comes first, so that the walk goes round and does not stay with its first two.
	walk.sort_by_key(|candidate| (network.aside.iter().filter(|(at, aside, _)| *at == transport && *aside == Some(*candidate)).map(|(_, _, until)| *until).max(), place(seed, transport, *candidate)));
	let (mut picked, nothing) = (Vec::new(), walk.is_empty());
	for candidate in walk {
		let known = network.tried.iter().any(|(at, tried, _)| (*at, *tried) == (transport, candidate));
		if picked.len() < IN_FLIGHT && (known || network.tried.len() < DISTINCT) {
			if !known {network.tried.push((transport, candidate, now))}
			picked.push(candidate);
		}
	}
	match network.tried.iter().map(|(_, _, when)| when.saturating_add(HOUR)).min() {
		_ if nothing && (!open.is_empty() || last) => Pick::Passed,
		_ if nothing => Pick::Nothing,
		Some(until) if picked.is_empty() => Pick::Wait(until),
		_ => Pick::Try(picked),
	}
}

/// What follows an attempt or a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
	/// Nothing: the session is open, or the caller closed it. "While the current candidate works, no other is tried."
	Rest,
	/// The same candidate again, after this wait.
	Again(Duration),
	/// The next candidate of the transport, after this wait. `candidates` says which, or that the transport has none left, and then `fallback` is asked.
	Move(Duration),
}

// A number of milliseconds doubled `times` times, up to a top.
fn doubled(millis: u64, times: u32, top: u64) -> u64 {millis.saturating_mul(1u64.checked_shl(times).unwrap_or(u64::MAX)).min(top)}

// "Each multiplied by a number drawn uniformly from 0.5 to 1.5."
fn half(millis: u64, random: &mut Random) -> Result<Duration, NoRandom> {Ok(Duration::from_millis(millis * u64::from(uniform(500, 1_500, random)?) / 1_000))}

/// "Refusal wait: uniform 60 to 120 s, doubled after every refusal up to 3600 s." `refusals` counts this one.
pub fn refusal_wait(refusals: u32, random: &mut Random) -> Result<Duration, NoRandom> {Ok(Duration::from_millis(doubled(uniform(60_000, 120_000, random)?.into(), refusals.saturating_sub(1), 3_600_000)))}

/// "Reconnect after a lost session: 1 s doubling to 60 s, each multiplied by a number drawn uniformly from 0.5 to 1.5." `losses` counts this one.
pub fn reconnect_wait(losses: u32, random: &mut Random) -> Result<Duration, NoRandom> {half(doubled(1_000, losses.saturating_sub(1), 60_000), random)}

/// "A wait drawn uniformly from 2 to 10 s between transports."
pub fn transport_wait(random: &mut Random) -> Result<Duration, NoRandom> {Ok(Duration::from_millis(uniform(2_000, 10_000, random)?.into()))}

/// "3 per round, then 30 s doubling to 900 s, each multiplied by a number drawn uniformly from 0.5 to 1.5." `rounds` counts the round that just ended.
pub fn round_wait(rounds: u32, random: &mut Random) -> Result<Duration, NoRandom> {half(doubled(30_000, rounds.saturating_sub(1), 900_000), random)}

/// "The client opens the second and later connections one at a time, each after a delay drawn uniformly from 1 to 5 s."
pub fn connection_wait(random: &mut Random) -> Result<Duration, NoRandom> {Ok(Duration::from_millis(uniform(1_000, 5_000, random)?.into()))}

/// Takes in how the attempt at candidate (or endpoint) `candidate` of `transport` went: `None` for a session that opened, and otherwise how it ended. `profile` is `digest` of the profile's transports.
/// - A session that opens is remembered for the network, and the refusal wait returns to its start. The reconnect wait does not: it does when a session has stayed open for `LIVED`.
/// - A refusal "does not mark the candidate or the transport as failed, and does not spend the candidate budget". The same candidate is tried again after the refusal wait, at most 3 times in a row, each candidate with its own count, and then the client moves on after the wait without setting it aside. An offset in it becomes the clock offset: it is there only when the candidate was pinned. A refusal without one while an offset is held makes the next attempt one on the device's clock, and if that one opens the offset is dropped.
/// - `End::Unanswered` is tried again at once, once, and the WireGuard layer must then open with a handshake initiation. A second one in a row is an unreachable candidate.
/// - An unreachable candidate "is then not tried again on that network for 1 hour". A certificate that fails its candidate's check, a pin that does not match on a self-signed candidate included, is one: the client moves on at once, and it never counts as a refusal, since the answer was not authenticated. Silence on a datagram transport that worked here within 7 days is tried again with the reconnect waits "for 90 s in all" first.
/// - What is the device's own state marks nothing and waits the reconnect wait: `End::Offline`, and a certificate that is not valid at the time the device's clock shows.
/// - A session that was open and is lost is opened again after the reconnect wait, and after `FLAPS` sessions in a row that did not live `LIVED` the client moves on.
pub fn outcome(network: &mut Network, standing: &mut Standing, profile: u64, transport: usize, candidate: usize, ended: Option<Ended>, now: u64, random: &mut Random) -> Result<Next, NoRandom> {
	sound(network, standing, profile, now);
	let (recent, bare, unanswered, at) = (network.worked.is_some_and(|(worked, _, _)| worked == transport), std::mem::take(&mut standing.bare), std::mem::take(&mut standing.unanswered), |row: &(usize, usize, u32)| (row.0, row.1) == (transport, candidate));
	Ok(match ended {
		None => {
			// An attempt on the device's clock that the node took: the offset was stale.
			if bare {standing.offset = None}
			(network.worked, network.silent, standing.refusals, standing.opened) = (Some((transport, candidate, now)), None, 0, Some(now));
			standing.rows.clear();
			Next::Rest
		}
		Some(Ended::Refused(refusal)) => {
			network.tried.retain(|(at, tried, _)| (*at, *tried) != (transport, candidate));
			// "Taken again after any later refusal on a pinned candidate, so that a stale offset does not outlive the fault that caused it."
			match refusal.offset {
				Some(offset) => standing.offset = Some((offset, now)),
				None => standing.bare = standing.offset.is_some() && !bare,
			}
			let row = standing.rows.iter().find(|row| at(row)).map_or(1, |row| row.2.saturating_add(1));
			standing.rows.retain(|row| !at(row));
			if row < ROW {standing.rows.push((transport, candidate, row))}
			standing.refusals = standing.refusals.saturating_add(1);
			let wait = refusal_wait(standing.refusals, random)?;
			if row < ROW {Next::Again(wait)} else {Next::Move(wait)}
		}
		// The node took the proof and does not know the tunnel, as after its restart: once more, at once, and with a handshake initiation.
		Some(Ended::Closed(End::Unanswered)) if !unanswered => {
			standing.unanswered = true;
			Next::Again(Duration::ZERO)
		}
		// "That covers a node that refuses for some tens of seconds after a crash. The doubling refusal wait is not used for silence."
		Some(Ended::Unreachable(Unreachable::Silence)) if recent && now < network.silent.get_or_insert((transport, now)).1.saturating_add(SILENCE) => {
			standing.losses = standing.losses.saturating_add(1);
			Next::Again(reconnect_wait(standing.losses, random)?)
		}
		// The device's own state: no route, no socket, or a clock outside the certificate's validity. Nothing is known of the candidate.
		Some(Ended::Closed(End::Offline) | Ended::Unreachable(Unreachable::CertificateTime)) => {
			standing.losses = standing.losses.saturating_add(1);
			Next::Again(reconnect_wait(standing.losses, random)?)
		}
		Some(Ended::Unreachable(_) | Ended::Closed(End::Unanswered)) => {
			let until = now.saturating_add(HOUR);
			network.aside.retain(|(at, aside, _)| (*at, *aside) != (transport, Some(candidate)));
			network.aside.push((transport, Some(candidate), until));
			network.silent = None;
			// "The mark and its expiry are logged at info, so that no failure is remembered forever." Places in the profile, never an address or a name.
			tracing::info!(transport, candidate, until, "a candidate is unreachable and set aside");
			Next::Move(Duration::ZERO)
		}
		Some(Ended::Closed(End::Asked)) => Next::Rest,
		Some(Ended::Closed(_)) => {
			// A session that stayed open gives the waits back. One that was cut soon after it opened does not, and after a few of those in a row another candidate is due.
			match standing.opened.take().map(|opened| now - opened >= LIVED) {
				Some(true) => (standing.losses, standing.short) = (0, 0),
				Some(false) => standing.short = standing.short.saturating_add(1),
				None => {}
			}
			standing.losses = standing.losses.saturating_add(1);
			let wait = reconnect_wait(standing.losses, random)?;
			if standing.short >= FLAPS {
				standing.short = 0;
				Next::Move(wait)
			} else {Next::Again(wait)}
		}
	})
}

/// A transport has no candidate left to try. With `mark` (`Pick::Nothing`: its candidates were unreachable) it is unreachable on this network: "Sets an unreachable transport aside for that network for 1 hour, then tries it again. The last transport of a profile that the client is allowed to use is never set aside." Without it (`Pick::Passed`) nothing is marked.
/// `order` is `Plan::order` as it was before this call, `tried` the transports tried in this round with this one, and `rounds` the rounds that ended with nothing, this one included if it ends here. The wait before the next transport: 2 to 10 s, and after the third of a round the backoff between rounds.
pub fn fallback(network: &mut Network, profile: u64, order: &[usize], transport: usize, mark: bool, tried: u32, rounds: u32, now: u64, random: &mut Random) -> Result<Duration, NoRandom> {
	sound(network, &mut Standing {profile, ..Standing::default()}, profile, now);
	if mark && order.iter().any(|at| *at != transport) {
		let until = now.saturating_add(HOUR);
		network.aside.push((transport, None, until));
		tracing::info!(transport, until, "a transport is unreachable and set aside");
	}
	if tried >= ROUND || order.len() <= 1 {round_wait(rounds, random)} else {transport_wait(random)}
}

/// "The user asks to connect again": every mark, every count and every wait starts over. The hour's budget of candidates stays, since it is what keeps a client from sweeping a list, and consent and the clock offset stay.
pub fn reset(network: &mut Network, standing: &mut Standing) {
	(network.aside, network.silent) = (Vec::new(), None);
	(standing.refusals, standing.rows, standing.losses, standing.short, standing.unanswered, standing.bare) = (0, Vec::new(), 0, 0, false, false);
}

/// The clock a proof is made with: the device's, and the offset when one is held, was taken within the last 24 h and the next attempt is not one on the device's clock. "It never changes the system clock."
pub fn clock(device: u64, standing: &Standing) -> u64 {standing.offset.filter(|(_, taken)| !standing.bare && *taken <= device && device - taken <= OFFSET_KEPT).map_or(device, |(offset, _)| device.saturating_add_signed(offset))}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{random, Answer, Refusal};
	use veilway_proto::subscription::payload::{Dial, Stream};

	fn transports(kinds: &[&str]) -> Vec<Transport> {
		kinds.iter().map(|kind| match *kind {
			"udp" => Transport::Udp(vec![Dial::parse("192.0.2.10:51820").unwrap()]),
			"udp-obfs" => Transport::UdpObfs(vec![Dial::parse("192.0.2.10:51821").unwrap()]),
			"tls" => Transport::Tls(Stream {path: "/assets/app-1.js".into(), candidates: Vec::new()}),
			"ws" => Transport::Ws(Stream {path: "/assets/app-2.js".into(), candidates: Vec::new()}),
			"faketls" => Transport::FakeTls {key: [0x45; 32], candidates: Vec::new()},
			_ => Transport::Fronted(Stream {path: "/assets/app-3.js".into(), candidates: Vec::new()}),
		}).collect()
	}

	const NOW: u64 = 1_700_000_000;
	// The digest of the profile the states of these tests are for. The tests of `plan` use the digest of their own lists.
	const P: u64 = 77;
	const REFUSED: Option<Ended> = Some(Ended::Refused(Refusal {answer: Answer::Status(404), offset: None}));
	const NO_ROUTE: Option<Ended> = Some(Ended::Unreachable(Unreachable::Connect));
	const LOST: Option<Ended> = Some(Ended::Closed(End::Lost));

	fn states() -> (Network, Standing) {(Network {profile: P, ..Network::default()}, Standing {profile: P, ..Standing::default()})}

	#[test]
	fn a_lower_class_needs_the_users_yes_for_the_first_attempt_too() {
		let (listed, network, mut standing) = (transports(&["udp-obfs", "tls", "udp", "fronted"]), Network::default(), Standing::default());
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false), Plan {order: vec![1, 3], ask: vec![Class::NoCover, Class::Plain]});
		// Agreeing to one class is not agreeing to another, and the provider's order holds once the user agreed.
		standing.consent.push(Class::NoCover);
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false), Plan {order: vec![0, 1, 3], ask: vec![Class::Plain]});
		assert_eq!(plan(&listed, true, &network, &standing, NOW, false).order, [1, 3, 0]);
		standing.consent.push(Class::Plain);
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false), Plan {order: vec![0, 1, 2, 3], ask: vec![]});
		// A profile whose best class is not cover needs no question for that class.
		assert_eq!(plan(&transports(&["udp-obfs", "udp"]), false, &network, &Standing::default(), NOW, false), Plan {order: vec![0], ask: vec![Class::Plain]});
		assert_eq!(plan(&[], false, &network, &standing, NOW, false), Plan::default());
		assert!(Class::Cover < Class::NoCover && Class::NoCover < Class::Exposed && Class::Exposed < Class::Plain);
	}

	#[test]
	fn a_faketls_transport_is_never_planned_while_alpha_transports_is_off() {
		let (listed, network) = (transports(&["faketls", "udp-obfs"]), Network::default());
		// Off: the profile is planned as if it had `udp-obfs` alone, which is then its best class and needs no question.
		assert_eq!(plan(&listed, false, &network, &Standing::default(), NOW, false), Plan {order: vec![1], ask: vec![]});
		assert_eq!(plan(&transports(&["faketls"]), false, &network, &Standing::default(), NOW, false), Plan::default());
		// On: `faketls` is a cover transport and comes first, and `udp-obfs` needs the user's yes.
		assert_eq!(plan(&listed, false, &network, &Standing::default(), NOW, true), Plan {order: vec![0], ask: vec![Class::NoCover]});
		assert_eq!((usable(&listed[0], false), usable(&listed[0], true), usable(&listed[1], false)), (false, true, true));
		assert_eq!(class(&listed[0]), Class::Cover);
	}

	#[test]
	fn what_worked_here_comes_first_for_a_week_and_what_is_set_aside_is_left_out() {
		let listed = transports(&["tls", "ws", "udp-obfs", "fronted"]);
		let (mut network, standing) = (Network {profile: digest(&listed), ..Network::default()}, Standing {profile: digest(&listed), consent: vec![Class::NoCover], ..Standing::default()});
		network.worked = Some((2, 0, NOW - 100));
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false).order, [2, 0, 1, 3]);
		assert_eq!(plan(&listed, true, &network, &standing, NOW, false).order, [0, 1, 3, 2]);
		assert_eq!(plan(&listed, false, &network, &standing, NOW - 100 + WEEK, false).order, [0, 1, 2, 3]);
		network.worked = Some((3, 1, NOW));
		assert_eq!(plan(&listed, true, &network, &standing, NOW, false).order, [3, 0, 1, 2]);
		network.aside = vec![(3, None, NOW + 50), (0, Some(1), NOW + 50)];
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false).order, [0, 1, 2]);
		assert_eq!(plan(&listed, false, &network, &standing, NOW + 50, false).order, [3, 0, 1, 2]);
		// Every transport but one set aside, and consent for that one withdrawn: an allowed transport is still given.
		network.aside = vec![(0, None, NOW + 50), (1, None, NOW + 50), (3, None, NOW + 50)];
		assert_eq!((plan(&listed, false, &network, &standing, NOW, false).order, plan(&listed, false, &network, &Standing {consent: Vec::new(), ..standing.clone()}, NOW, false).order), (vec![2], vec![3, 0, 1]));
	}

	#[test]
	fn candidates_are_walked_two_at_a_time_in_one_order_and_six_an_hour() {
		let (mut network, mut standing) = states();
		let Pick::Try(first) = candidates(&mut network, P, 1, 16, &[], false, 7, NOW) else {panic!("nothing to try")};
		assert_eq!(first.len(), 2);
		// "Fixed between attempts", and another order on another installation.
		assert_eq!(candidates(&mut network.clone(), P, 1, 16, &[], false, 7, NOW + 1), Pick::Try(first.clone()));
		let orders: Vec<Pick> = (0..8).map(|seed| candidates(&mut Network::default(), P, 1, 16, &[], false, seed, NOW)).collect();
		assert!(orders.iter().any(|order| *order != orders[0]));
		// Unreachable ones are set aside and the walk goes on, until six distinct ones were tried in the hour.
		let mut seen = first.clone();
		for candidate in &first {assert_eq!(outcome(&mut network, &mut standing, P, 1, *candidate, NO_ROUTE, NOW, &mut random), Ok(Next::Move(Duration::ZERO)))}
		for _ in 0..2 {
			let Pick::Try(next) = candidates(&mut network, P, 1, 16, &[], false, 7, NOW + 10) else {panic!("nothing to try")};
			assert!(next.len() == 2 && next.iter().all(|candidate| !seen.contains(candidate)));
			for candidate in &next {outcome(&mut network, &mut standing, P, 1, *candidate, NO_ROUTE, NOW + 10, &mut random).unwrap();}
			seen.extend(next);
		}
		assert_eq!(candidates(&mut network, P, 1, 16, &[], false, 7, NOW + 20), Pick::Wait(NOW + HOUR));
		// An hour on, the budget and the marks are both over.
		assert!(matches!(candidates(&mut network, P, 1, 16, &[], false, 7, NOW + HOUR + 10), Pick::Try(next) if next == first));
		assert!(network.aside.is_empty());
		// A transport whose every candidate is set aside has nothing to try, and one whose candidates were all passed after refusals is told apart from it: it is not unreachable.
		let mut small = states().0;
		for candidate in 0..2 {outcome(&mut small, &mut standing, P, 0, candidate, NO_ROUTE, NOW, &mut random).unwrap();}
		assert_eq!(candidates(&mut small, P, 0, 2, &[], false, 7, NOW + 1), Pick::Nothing);
		assert_eq!(candidates(&mut states().0, P, 0, 2, &[0, 1], false, 7, NOW + 1), Pick::Passed);
		assert_eq!(candidates(&mut small, P, 0, 3, &[2], false, 7, NOW + 1), Pick::Passed);
	}

	// "The last transport of a profile that the client is allowed to use is never set aside: the client keeps trying it."
	#[test]
	fn on_the_last_transport_the_marks_of_its_candidates_do_not_leave_the_client_with_nothing() {
		let (mut network, mut standing) = states();
		for candidate in 0..2 {assert_eq!(outcome(&mut network, &mut standing, P, 0, candidate, NO_ROUTE, NOW, &mut random), Ok(Next::Move(Duration::ZERO)))}
		assert_eq!(candidates(&mut network.clone(), P, 0, 2, &[], false, 7, NOW + 60), Pick::Nothing);
		assert!(matches!(candidates(&mut network, P, 0, 2, &[], true, 7, NOW + 60), Pick::Try(picked) if picked.len() == 2));
		// Still under the budget of the hour: a seventh candidate waits, and no longer than the hour.
		let mut many = states().0;
		for candidate in 0..16 {outcome(&mut many, &mut standing, P, 0, candidate, NO_ROUTE, NOW, &mut random).unwrap();}
		for round in 1..=3 {
			let Pick::Try(picked) = candidates(&mut many, P, 0, 16, &[], true, 7, NOW + 5 * round) else {panic!("nothing to try on the last transport")};
			for candidate in picked {outcome(&mut many, &mut standing, P, 0, candidate, NO_ROUTE, NOW + 5 * round, &mut random).unwrap();}
		}
		// The walk went round: six distinct candidates were tried, and the seventh has to wait for the hour's budget while the six are tried again.
		let known: Vec<usize> = many.tried.iter().map(|(_, candidate, _)| *candidate).collect();
		assert_eq!((known.len(), known.iter().collect::<std::collections::HashSet<_>>().len()), (6, 6));
		assert!(matches!(candidates(&mut many, P, 0, 16, &[], true, 7, NOW + 20), Pick::Try(picked) if picked.len() == 2 && picked.iter().all(|candidate| known.contains(candidate))));
		// A failure of the device marks nothing: the router that reboots costs the reconnect wait and not an hour.
		let (mut network, mut standing) = states();
		for offline in [Some(Ended::Closed(End::Offline)), Some(Ended::Unreachable(Unreachable::CertificateTime))] {assert!(matches!(outcome(&mut network, &mut standing, P, 0, 0, offline, NOW, &mut random), Ok(Next::Again(wait)) if wait.as_secs() <= 3))}
		assert!(network.aside.is_empty());
	}

	// "A certificate that fails the check of its candidate, including a pin that does not match, makes that candidate unreachable for this attempt, at once and with no refusal wait, and the client moves on. It never counts as the node refusing the device." Self-signed or not.
	#[test]
	fn a_certificate_that_does_not_match_moves_on_at_once_and_is_no_refusal() {
		let (mut network, mut standing) = states();
		standing.offset = Some((30, NOW - 10));
		outcome(&mut network, &mut standing, P, 1, 0, REFUSED, NOW, &mut random).unwrap();
		let (refusals, rows) = (standing.refusals, standing.rows.clone());
		assert_eq!(outcome(&mut network, &mut standing, P, 1, 1, Some(Ended::Unreachable(Unreachable::Certificate)), NOW, &mut random), Ok(Next::Move(Duration::ZERO)));
		// No refusal is counted and no wait doubles. The offset a pinned answer gave stays, since an answer that was not authenticated says nothing of the clock.
		assert_eq!((standing.refusals, standing.rows.clone(), standing.offset, standing.bare), (refusals, rows, Some((30, NOW - 10)), false));
		assert_eq!(network.aside, [(1, Some(1), NOW + HOUR)]);
		assert!(matches!(candidates(&mut network, P, 1, 2, &[], false, 7, NOW + 1), Pick::Try(picked) if picked == [0]));
	}

	// A clock that stepped back, and a state file that is damaged: no value in it holds anything for longer than a mark lasts.
	#[test]
	fn times_that_cannot_be_true_are_dropped() {
		let listed = transports(&["tls", "ws"]);
		let (profile, mut standing) = (digest(&listed), Standing {profile: digest(&listed), ..Standing::default()});
		let mut network = Network {profile, ..Network::default()};
		// Marked and spent under a clock a year ahead.
		let ahead = NOW + 365 * 86_400;
		for candidate in 0..6 {
			candidates(&mut network, profile, 0, 16, &[], false, 7, ahead);
			outcome(&mut network, &mut standing, profile, 0, candidate, NO_ROUTE, ahead, &mut random).unwrap();
		}
		fallback(&mut network, profile, &[0, 1], 0, true, 1, 0, ahead, &mut random).unwrap();
		outcome(&mut network, &mut standing, profile, 1, 3, None, ahead, &mut random).unwrap();
		assert_eq!(plan(&listed, false, &network, &standing, ahead, false).order, [1]);
		// The clock is set right: everything is free again, and the candidate remembered from the future is no memory.
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false).order, [0, 1]);
		assert!(matches!(candidates(&mut network, profile, 0, 16, &[], false, 7, NOW), Pick::Try(picked) if picked.len() == 2));
		assert_eq!((network.aside.len(), network.tried.len(), network.worked), (0, 2, None));
		// The worst a file can hold.
		let mut network = Network {profile, worked: Some((0, 0, u64::MAX)), aside: vec![(0, Some(0), u64::MAX), (0, None, u64::MAX), (1, None, NOW + HOUR + 1)], tried: vec![(0, 0, u64::MAX); 6], silent: Some((0, u64::MAX))};
		let mut standing = Standing {profile, refusals: u32::MAX, rows: vec![(0, 0, u32::MAX); 3], losses: u32::MAX, opened: Some(u64::MAX), short: u32::MAX, offset: Some((i64::MIN, u64::MAX)), ..Standing::default()};
		assert_eq!((plan(&listed, false, &network, &standing, NOW, false).order, clock(NOW, &standing)), (vec![0, 1], NOW));
		assert!(matches!(candidates(&mut network, profile, 0, 4, &[], false, 7, NOW), Pick::Try(_)));
		for ended in [REFUSED, LOST, NO_ROUTE, None, Some(Ended::Closed(End::Unanswered))] {outcome(&mut network, &mut standing, profile, 0, 0, ended, NOW, &mut random).unwrap();}
		assert!(network.aside.iter().all(|(_, _, until)| *until <= NOW + HOUR));
		// A list far longer than any run writes is no list.
		let mut network = Network {profile, aside: vec![(0, Some(1), NOW + 5); 1_000], ..Network::default()};
		assert!(matches!(candidates(&mut network, profile, 0, 2, &[], false, 7, NOW), Pick::Try(picked) if picked.len() == 2));
	}

	// A subscription refresh that adds or reorders transports: the places of the old list mean nothing in the new one.
	#[test]
	fn a_state_made_for_another_list_of_transports_is_dropped_but_for_consent() {
		let (before, after) = (transports(&["tls", "udp-obfs"]), transports(&["udp-obfs", "tls", "ws"]));
		let (mut network, mut standing) = (Network {profile: digest(&before), ..Network::default()}, Standing {profile: digest(&before), consent: vec![Class::NoCover], ..Standing::default()});
		outcome(&mut network, &mut standing, digest(&before), 1, 0, None, NOW, &mut random).unwrap();
		outcome(&mut network, &mut standing, digest(&before), 0, 0, NO_ROUTE, NOW, &mut random).unwrap();
		assert_eq!(plan(&before, false, &network, &standing, NOW + 1, false).order, [1, 0]);
		// In the new list place 1 is `tls`: it is not promoted for what `udp-obfs` did, and its candidate 0 is not marked for what another candidate did. The user's yes to the class holds.
		assert_eq!(plan(&after, false, &network, &standing, NOW + 1, false), Plan {order: vec![0, 1, 2], ask: vec![]});
		assert!(matches!(candidates(&mut network, digest(&after), 1, 1, &[], false, 7, NOW + 1), Pick::Try(picked) if picked == [0]));
		outcome(&mut network, &mut standing, digest(&after), 1, 0, REFUSED, NOW + 1, &mut random).unwrap();
		assert_eq!((network.worked, network.aside.len(), standing.consent.clone(), standing.profile), (None, 0, vec![Class::NoCover], digest(&after)));
		assert_ne!(digest(&before), digest(&after));
		assert_ne!(digest(&transports(&["tls"])), digest(&transports(&["ws"])));
	}

	#[test]
	fn the_candidate_that_worked_is_tried_first_and_alone() {
		let (mut network, mut standing) = states();
		assert_eq!(outcome(&mut network, &mut standing, P, 1, 5, None, NOW, &mut random), Ok(Next::Rest));
		assert_eq!(candidates(&mut network, P, 1, 16, &[], false, 7, NOW + 60), Pick::Try(vec![5]));
		// Not for another transport, not after a week, and not once it is unreachable.
		assert!(matches!(candidates(&mut network.clone(), P, 2, 16, &[], false, 7, NOW + 60), Pick::Try(picked) if picked.len() == 2));
		assert!(matches!(candidates(&mut network.clone(), P, 1, 16, &[], false, 7, NOW + WEEK), Pick::Try(picked) if picked.len() == 2));
		outcome(&mut network, &mut standing, P, 1, 5, NO_ROUTE, NOW + 60, &mut random).unwrap();
		assert!(matches!(candidates(&mut network, P, 1, 16, &[], false, 7, NOW + 61), Pick::Try(picked) if picked.len() == 2 && !picked.contains(&5)));
	}

	#[test]
	fn a_refusal_marks_nothing_spends_nothing_and_doubles_its_wait() {
		let (mut network, mut standing) = states();
		let Pick::Try(picked) = candidates(&mut network, P, 0, 4, &[], false, 7, NOW) else {panic!("nothing to try")};
		let mut waits = Vec::new();
		for attempt in 1..=3 {
			let next = outcome(&mut network, &mut standing, P, 0, picked[0], REFUSED, NOW, &mut random).unwrap();
			let (Next::Again(wait) | Next::Move(wait)) = next else {panic!("a refusal without a wait")};
			// "Tried at most 3 times in a row, the first attempt included", and then on without a mark.
			assert_eq!(matches!(next, Next::Again(_)), attempt < 3);
			waits.push(wait.as_secs());
		}
		assert!((60..=120).contains(&waits[0]) && (120..=240).contains(&waits[1]) && (240..=480).contains(&waits[2]), "{waits:?}");
		assert!(network.aside.is_empty() && !network.tried.iter().any(|(_, tried, _)| *tried == picked[0]));
		// "Up to 3600 s", for as long as refusals continue on the profile, whichever candidate gives them.
		for _ in 0..20 {outcome(&mut network, &mut standing, P, 0, picked[1], REFUSED, NOW, &mut random).unwrap();}
		assert_eq!(refusal_wait(standing.refusals, &mut random), Ok(Duration::from_secs(3_600)));
		assert_eq!(refusal_wait(u32::MAX, &mut random), Ok(Duration::from_secs(3_600)));
		// "The wait returns to its start when a session opens", and so does it when the user asks to connect again.
		outcome(&mut network, &mut standing, P, 0, picked[1], None, NOW, &mut random).unwrap();
		assert_eq!((standing.refusals, standing.rows.len()), (0, 0));
		assert!(matches!(outcome(&mut network, &mut standing, P, 0, picked[1], REFUSED, NOW, &mut random), Ok(Next::Again(wait)) if (60..=120).contains(&wait.as_secs())));
		outcome(&mut network, &mut standing, P, 0, picked[0], NO_ROUTE, NOW, &mut random).unwrap();
		standing.consent.push(Class::NoCover);
		reset(&mut network, &mut standing);
		assert_eq!((network.aside.len(), standing.refusals, standing.rows.len(), standing.losses, standing.consent.len()), (0, 0, 0, 0, 1));
	}

	// "At most 2 candidates are in flight": each has its own count of three.
	#[test]
	fn two_candidates_that_refuse_in_turn_each_reach_their_third() {
		let (mut network, mut standing) = states();
		let mut moved = Vec::new();
		for round in 1..=3 {
			for candidate in 0..2 {
				if matches!(outcome(&mut network, &mut standing, P, 0, candidate, REFUSED, NOW, &mut random).unwrap(), Next::Move(_)) {moved.push((round, candidate))}
			}
		}
		assert_eq!((moved, standing.refusals), (vec![(3, 0), (3, 1)], 6));
	}

	#[test]
	fn the_clock_offset_comes_from_a_pinned_refusal_and_is_kept_a_day() {
		let (mut network, mut standing, dated) = (states().0, states().1, |offset| Some(Ended::Refused(Refusal {answer: Answer::Status(404), offset: Some(offset)})));
		assert_eq!(clock(NOW, &standing), NOW);
		// A refusal without an offset (no pin) leaves the clock alone.
		outcome(&mut network, &mut standing, P, 0, 0, REFUSED, NOW, &mut random).unwrap();
		assert_eq!((standing.offset, standing.bare), (None, false));
		outcome(&mut network, &mut standing, P, 0, 0, dated(500), NOW, &mut random).unwrap();
		assert_eq!((standing.offset, clock(NOW + 30, &standing)), (Some((500, NOW)), NOW + 530));
		assert_eq!((clock(NOW + OFFSET_KEPT, &standing), clock(NOW + OFFSET_KEPT + 1, &standing), clock(NOW - 1, &standing)), (NOW + OFFSET_KEPT + 500, NOW + OFFSET_KEPT + 1, NOW - 1));
		// "Taken again after any later refusal on a pinned candidate": a clock that was set right in between loses the offset.
		outcome(&mut network, &mut standing, P, 0, 0, dated(-2), NOW + 602, &mut random).unwrap();
		assert_eq!((standing.offset, clock(NOW + 700, &standing)), (Some((-2, NOW + 602)), NOW + 698));
	}

	// An offset that went stale while the pinned candidate cannot be reached: a refusal on a candidate without a pin is followed by one attempt on the device's clock.
	#[test]
	fn a_stale_offset_is_shed_by_one_attempt_on_the_devices_clock() {
		let (mut network, mut standing) = states();
		standing.offset = Some((900, NOW));
		outcome(&mut network, &mut standing, P, 1, 0, REFUSED, NOW + 10, &mut random).unwrap();
		assert_eq!((standing.bare, clock(NOW + 100, &standing)), (true, NOW + 100));
		// That attempt is refused too: the offset is in use again, and the attempt after that is not one on the device's clock a second time in a row.
		outcome(&mut network, &mut standing, P, 1, 0, REFUSED, NOW + 100, &mut random).unwrap();
		assert_eq!((standing.bare, clock(NOW + 200, &standing)), (false, NOW + 1_100));
		outcome(&mut network, &mut standing, P, 1, 0, REFUSED, NOW + 200, &mut random).unwrap();
		assert!(standing.bare);
		// It opens: the node took a proof made on the device's clock, so the offset was wrong, and it goes.
		outcome(&mut network, &mut standing, P, 1, 0, None, NOW + 300, &mut random).unwrap();
		assert_eq!((standing.offset, standing.bare), (None, false));
		// A session that opens with the offset keeps it.
		standing.offset = Some((900, NOW));
		outcome(&mut network, &mut standing, P, 1, 0, None, NOW + 400, &mut random).unwrap();
		assert_eq!(standing.offset, Some((900, NOW)));
	}

	// "A proof that was accepted and is followed by silence, on a session the client opened with a keepalive": once more at once, and nothing is marked.
	#[test]
	fn a_proof_that_was_taken_and_not_answered_is_tried_once_more_at_once() {
		let (mut network, mut standing, unanswered) = (states().0, states().1, Some(Ended::Closed(End::Unanswered)));
		assert_eq!(outcome(&mut network, &mut standing, P, 0, 0, unanswered, NOW, &mut random), Ok(Next::Again(Duration::ZERO)));
		assert!(network.aside.is_empty() && standing.unanswered && standing.losses == 0);
		// The retry opens, with an initiation: nothing is left of it.
		outcome(&mut network, &mut standing, P, 0, 0, None, NOW + 1, &mut random).unwrap();
		assert!(!standing.unanswered);
		// A second one in a row is no node that restarted.
		outcome(&mut network, &mut standing, P, 0, 0, unanswered, NOW + 2, &mut random).unwrap();
		assert_eq!(outcome(&mut network, &mut standing, P, 0, 0, unanswered, NOW + 12, &mut random), Ok(Next::Move(Duration::ZERO)));
		assert_eq!(network.aside, [(0, Some(0), NOW + 12 + HOUR)]);
	}

	#[test]
	fn silence_on_a_datagram_transport_that_worked_here_is_tried_for_ninety_seconds() {
		let (mut network, mut standing, silence) = (states().0, states().1, Some(Ended::Unreachable(Unreachable::Silence)));
		// One that never worked here is unreachable at once.
		assert_eq!(outcome(&mut network.clone(), &mut standing, P, 2, 0, silence, NOW, &mut random), Ok(Next::Move(Duration::ZERO)));
		outcome(&mut network, &mut standing, P, 2, 0, None, NOW, &mut random).unwrap();
		let (mut now, mut waits) = (NOW + 1_000, Vec::new());
		let moved = loop {
			match outcome(&mut network, &mut standing, P, 2, 0, silence, now, &mut random).unwrap() {
				Next::Again(wait) => waits.push(wait.as_millis() as u64),
				next => break next,
			}
			now += 10 + waits[waits.len() - 1] / 1_000;
		};
		// The reconnect waits, 1 s doubling to 60 s and each half as long again at most, and not the refusal wait.
		assert!(waits.len() >= 3 && waits.iter().enumerate().all(|(at, wait)| (500 << at.min(6)..=1_500 << at.min(6)).contains(wait) && *wait <= 90_000), "{waits:?}");
		assert_eq!((moved, now >= NOW + 1_000 + SILENCE, standing.refusals), (Next::Move(Duration::ZERO), true, 0));
		assert_eq!(network.aside, [(2, Some(0), now + HOUR)]);
		// A silence that was left alone for more than an hour is not taken up where it stood: its 90 s start anew.
		let mut network = Network {profile: P, worked: Some((2, 0, NOW)), silent: Some((2, NOW)), ..Network::default()};
		assert!(matches!(outcome(&mut network, &mut standing, P, 2, 0, silence, NOW + 2 * HOUR, &mut random), Ok(Next::Again(_))));
		assert_eq!(network.silent, Some((2, NOW + 2 * HOUR)));
	}

	#[test]
	fn a_lost_session_comes_back_after_a_wait_that_doubles_to_a_minute() {
		let (mut network, mut standing) = states();
		let waits: Vec<u128> = (0..10).map(|_| match outcome(&mut network, &mut standing, P, 0, 0, LOST, NOW, &mut random).unwrap() {
			Next::Again(wait) => wait.as_millis(),
			next => panic!("{next:?}"),
		}).collect();
		for (at, wait) in waits.iter().enumerate() {assert!((500u128 << at.min(6)).min(30_000) <= *wait && *wait <= (1_500u128 << at.min(6)).min(90_000), "{waits:?}")}
		assert!(network.aside.is_empty());
		assert_eq!(outcome(&mut network, &mut standing, P, 0, 0, Some(Ended::Closed(End::Asked)), NOW, &mut random), Ok(Next::Rest));
	}

	// A path that lets a session open and cuts it at once: the client must not dial every second for ever.
	#[test]
	fn a_session_that_opens_and_is_cut_at_once_waits_longer_each_time_and_moves_on() {
		let (mut network, mut standing, mut now, mut answers) = (states().0, states().1, NOW, Vec::new());
		for _ in 0..20 {
			assert_eq!(outcome(&mut network, &mut standing, P, 0, 0, None, now, &mut random), Ok(Next::Rest));
			now += 2;
			answers.push(outcome(&mut network, &mut standing, P, 0, 0, LOST, now, &mut random).unwrap());
		}
		let waits: Vec<u128> = answers.iter().map(|next| match next {
			Next::Again(wait) | Next::Move(wait) => wait.as_millis(),
			Next::Rest => 0,
		}).collect();
		for (at, wait) in waits.iter().enumerate() {assert!((500u128 << at.min(6)).min(30_000) <= *wait, "{waits:?}")}
		assert_eq!(answers.iter().enumerate().filter(|(_, next)| matches!(next, Next::Move(_))).map(|(at, _)| at).collect::<Vec<_>>(), [2, 5, 8, 11, 14, 17]);
		// A session that stays open for a minute gives the wait back.
		outcome(&mut network, &mut standing, P, 0, 0, None, now, &mut random).unwrap();
		assert!(matches!(outcome(&mut network, &mut standing, P, 0, 0, LOST, now + LIVED, &mut random), Ok(Next::Again(wait)) if wait.as_millis() <= 1_500));
		assert_eq!((standing.losses, standing.short), (1, 0));
	}

	#[test]
	fn an_unreachable_transport_is_set_aside_unless_it_is_the_last() {
		let listed = transports(&["tls", "ws", "fronted"]);
		let (profile, standing) = (digest(&listed), Standing {profile: digest(&listed), ..Standing::default()});
		let mut network = Network {profile, ..Network::default()};
		let order = plan(&listed, false, &network, &standing, NOW, false).order;
		let wait = fallback(&mut network, profile, &order, 0, true, 1, 0, NOW, &mut random).unwrap();
		assert!((2..=10).contains(&wait.as_secs()), "{wait:?}");
		let order = plan(&listed, false, &network, &standing, NOW, false).order;
		assert_eq!(order, [1, 2]);
		// A transport whose candidates only refused is passed and not marked: "A refusal never sets a transport aside."
		fallback(&mut network, profile, &order, 1, false, 2, 0, NOW, &mut random).unwrap();
		assert_eq!(plan(&listed, false, &network, &standing, NOW, false).order, [1, 2]);
		fallback(&mut network, profile, &order, 1, true, 2, 0, NOW, &mut random).unwrap();
		let order = plan(&listed, false, &network, &standing, NOW, false).order;
		// The third of the round, and the last the client may use: it stays, and the backoff between rounds follows.
		let wait = fallback(&mut network, profile, &order, 2, true, 3, 1, NOW, &mut random).unwrap();
		assert!((15..=45).contains(&wait.as_secs()), "{wait:?}");
		assert_eq!((plan(&listed, false, &network, &standing, NOW, false).order, plan(&listed, false, &network, &standing, NOW + HOUR, false).order), (vec![2], vec![0, 1, 2]));
		assert!((450..=1_350).contains(&round_wait(40, &mut random).unwrap().as_secs()));
		assert!((1..=5).contains(&connection_wait(&mut random).unwrap().as_secs()));
	}
}
