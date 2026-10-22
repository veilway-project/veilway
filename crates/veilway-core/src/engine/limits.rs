//! What the native transports of a node share (transports page, "Numbers that are judgement calls", "Session activity and timers", "Verifying" step 7): the allowance of accepted proofs of every device and every source, the sessions a device has across all of its transports, their timers, and the one path that ends them when the node cuts a device off.
//! A session of any transport is known here by its `Seat`. The limits are the node's and not a listener's: "Pending sessions per device: 2" and "Sessions per device: 8" count a device's `udp-obfs` and stream sessions together.
//! Nothing here does IO. The order of locks is the replay memory, then a listener's own table, then these limits, and the lock of a tunnel is never held with any of them.
use super::inbound::Tunnel;
use super::plan::{Plan, Proved};
use super::replay;
use crate::config::{ProofRate, DEFAULT_PROOFS_PER_SOURCE};
use ring::digest::{digest, SHA256};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Notify;
use veilway_proto::session::{FIRST_PACKET, PENDING};

/// "Sessions per device: 8." A device at this limit replaces its own oldest session once the new one is established.
pub const DEVICE_SESSIONS: usize = 8;
/// "Sessions per device: 8, of which at most 2 `fronted`." A device at this limit replaces its own oldest `fronted` session once the new one is established, as it does at the limit of all its sessions: each `fronted` session keeps a response for its device, so they are the ones a device is held to fewer of.
pub const DEVICE_FRONTED: usize = 2;
/// "Accepted proofs per device: burst 16, then 1 a second."
pub const DEVICE_PROOFS: ProofRate = ProofRate {burst: 16, rate: 1};
/// "WireGuard handshake initiations per session: burst 3, then 1 a second."
pub const SESSION_HANDSHAKES: ProofRate = ProofRate {burst: 3, rate: 1};
/// How many sources the node keeps a rate for at once. A source is in the table only after a proof of a device was accepted from it, and leaves when its allowance is whole again, so only devices of the config fill it. When it is full, a proof from a source that is not in it is refused.
pub const MAX_SOURCES: usize = 65536;
/// How many of the handshake initiations a session took to WireGuard it remembers, to drop one of them that comes again without charging the session's allowance.
const INITIATIONS: usize = 8;

/// The node's clock as a listener reads it: Unix time in milliseconds for its timers and in seconds for the replay rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {pub ms: i64, pub secs: u64}

impl Clock {
	pub fn of(now: OffsetDateTime) -> Clock {Clock {ms: (now.unix_timestamp_nanos() / 1_000_000) as i64, secs: replay::seconds(now)}}
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
	/// No WireGuard packet of its device authenticated within the first tunnel packet deadline.
	Deadline,
	/// No activity for the idle time of the transport.
	Idle,
	/// The node used up the numbers one key may seal with.
	Packets,
	/// A newer session of the same source and device took its place: a pending one at once, an established one after it stayed readable for 10 s.
	Replaced,
	/// Its device was at its session limit and established another.
	Displaced,
	/// The config no longer has its device as it was, or the transport secret it was opened with.
	Revoked,
	/// The connection of a stream session closed, or its peer closed the session.
	Closed,
	/// A chunk of a stream session did not open, or a limit inside the session was broken.
	Invalid,
	/// The config no longer has the transport the session came in by.
	Unserved,
}

pub const ENDS: usize = Ended::Unserved as usize + 1;

/// An allowance of `burst` at once and `rate` a second, in thousandths.
pub struct Bucket {left: u64, at: i64}

impl Bucket {
	pub fn full(of: ProofRate, now: i64) -> Bucket {Bucket {left: u64::from(of.burst) * 1000, at: now}}

	/// Fills up for the time since it was last looked at. A clock that stepped back fills nothing.
	pub fn fill(&mut self, of: ProofRate, now: i64) -> &mut Bucket {
		(self.left, self.at) = (self.left.saturating_add((now.saturating_sub(self.at).max(0) as u64).saturating_mul(u64::from(of.rate))).min(u64::from(of.burst) * 1000), now);
		self
	}

	pub fn has(&self) -> bool {self.left >= 1000}

	/// Spends one, when there is one.
	pub fn take(&mut self) -> bool {
		let has = self.has();
		if has {self.left -= 1000}
		has
	}

	fn whole(&self, of: ProofRate) -> bool {self.left >= u64::from(of.burst) * 1000}
}

const WAITING: u8 = 0;
const LIVE: u8 = 1;
const RETIRED: u8 = 2;
const OVER: u8 = 3;

/// One session of a native transport as the node's limits know it: whose it is, which secret opened it, how far it has come and when it was last active.
/// It is pending until a WireGuard packet of its device has authenticated on it, then established: live, or retired when a newer session took over and it is only still readable.
pub struct Seat {
	/// The WireGuard public key of the device the proof named. Only its packets are read on the session.
	pub device: [u8; 32],
	pub secret: Proved,
	/// The node transport key the session's stream proof opened under, private half, whose holder can rebuild the session's chunk keys. None on `udp-obfs`, which has none. Never logged and never shown.
	pub key: Option<[u8; 32]>,
	pub tunnel: Arc<Tunnel>,
	phase: AtomicU8,
	/// The established sessions of the listener it belongs to.
	pool: Arc<AtomicI64>,
	/// The established `fronted` sessions of that listener, for a session of that transport and no other.
	polled: Option<Arc<AtomicI64>>,
	/// The established `fronted-shaped` sessions of that listener, for a session of that transport and no other. Such a session is counted in `polled` too.
	shaped: Option<Arc<AtomicI64>>,
	/// The counters of its transport, by `Ended`.
	ended: Arc<[AtomicU64; ENDS]>,
	/// "The node ends a session with no activity for" this long, in milliseconds.
	idle: i64,
	/// When the proof was accepted and when the session was last active, in Unix milliseconds, and when it became established.
	pub opened: AtomicI64,
	pub active: AtomicI64,
	pub since: AtomicI64,
	/// Wakes the one task of a stream session when the session has ended.
	gone: Notify,
}

impl Seat {
	/// A pending session whose proof is about to be taken to the limits. `pool` counts the established sessions of its listener, `polled` those of them that are `fronted` or `fronted-shaped` when this is one, `shaped` those that are `fronted-shaped`, and `idle` is the idle time of its transport.
	#[allow(clippy::too_many_arguments)]
	pub fn new(device: [u8; 32], secret: Proved, key: Option<[u8; 32]>, tunnel: Arc<Tunnel>, pool: Arc<AtomicI64>, polled: Option<Arc<AtomicI64>>, shaped: Option<Arc<AtomicI64>>, ended: Arc<[AtomicU64; ENDS]>, idle: Duration, now: i64) -> Arc<Seat> {Arc::new(Seat {device, secret, key, tunnel, phase: AtomicU8::new(WAITING), pool, polled, shaped, ended, idle: idle.as_millis() as i64, opened: AtomicI64::new(now), active: AtomicI64::new(now), since: AtomicI64::new(now), gone: Notify::new()})}

	fn phase(&self) -> u8 {self.phase.load(Ordering::Acquire)}

	pub fn pending(&self) -> bool {self.phase() == WAITING}

	/// Established and the one its device is answered on.
	pub fn live(&self) -> bool {self.phase() == LIVE}

	/// Established: live, or only still readable.
	pub fn established(&self) -> bool {matches!(self.phase(), LIVE | RETIRED)}

	pub fn over(&self) -> bool {self.phase() == OVER}

	/// A newer session took over what this one was answered on. It stays readable until its listener ends it.
	pub fn retire(&self) {let _ = self.phase.compare_exchange(LIVE, RETIRED, Ordering::AcqRel, Ordering::Acquire);}

	/// Ends the session, once. Nothing is read or sent on it from here on, and whoever keeps it takes it out of its table.
	pub fn end(&self, why: Ended) {
		let was = self.phase.swap(OVER, Ordering::AcqRel);
		if was == OVER {return}
		if was != WAITING {
			self.pool.fetch_sub(1, Ordering::Relaxed);
			if let Some(polled) = &self.polled {polled.fetch_sub(1, Ordering::Relaxed);}
			if let Some(shaped) = &self.shaped {shaped.fetch_sub(1, Ordering::Relaxed);}
		}
		self.ended[why as usize].fetch_add(1, Ordering::Relaxed);
		self.gone.notify_one();
	}

	/// Returns once the session has ended. One task waits here at the most.
	pub async fn gone(&self) {
		while !self.over() {self.gone.notified().await}
	}
}

/// What became of a pending session that a WireGuard packet of its device authenticated on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seated {
	Established,
	/// The pool of its listener has no place, and its device gives none up in that pool. The session stays pending and ends at its deadline.
	Full,
	/// It ended meanwhile, or is established already.
	Gone,
}

/// Why the limits have no room for a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spent {
	/// The device has 2 pending sessions.
	Pending,
	/// The device's or the source's allowance of accepted proofs is spent.
	DeviceRate,
	SourceRate,
}

/// The allowance of handshake initiations of one session, and the hashes of the last `INITIATIONS` it took to WireGuard. One of those again is a recorded packet, which WireGuard would drop as a repeat: it is dropped here first, and costs the allowance nothing.
pub struct Handshakes(Mutex<(Bucket, VecDeque<[u8; 32]>)>);

/// What a session does with a handshake initiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initiation {Taken, Repeat, Excess}

impl Handshakes {
	pub fn new(now: i64) -> Handshakes {Handshakes(Mutex::new((Bucket::full(SESSION_HANDSHAKES, now), VecDeque::new())))}

	/// "Excess messages are dropped silently and counted." An initiation the session took to WireGuard before is dropped before the allowance is charged:
	/// "The replay rule comes before any rate limit is charged. Otherwise one old token from a log, sent once a second, would keep a device's allowance empty", and with it the device from its next rekey.
	pub fn admit(&self, initiation: &[u8], now: i64) -> Initiation {
		let (hash, mut handshakes) = (digest(&SHA256, initiation), self.0.lock().unwrap_or_else(|e| e.into_inner()));
		let (allowance, taken) = &mut *handshakes;
		if taken.iter().any(|taken| taken[..] == *hash.as_ref()) {return Initiation::Repeat}
		if !allowance.fill(SESSION_HANDSHAKES, now).take() {return Initiation::Excess}
		if taken.len() >= INITIATIONS {taken.pop_front();}
		taken.push_back(std::array::from_fn(|at| hash.as_ref()[at]));
		Initiation::Taken
	}
}

/// What a device has across every listener: its allowance of accepted proofs, its allowance of proofs that a limit refused and that are recorded as spent all the same, and its sessions.
struct Account {proofs: Bucket, refused: Bucket, seats: Vec<Weak<Seat>>}

impl Account {
	fn new(now: i64) -> Account {Account {proofs: Bucket::full(DEVICE_PROOFS, now), refused: Bucket::full(DEVICE_PROOFS, now), seats: Vec::new()}}
}

/// "A source is an IPv4 address or an IPv6 /64."
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {V4([u8; 4]), V6([u8; 8])}

impl Source {
	pub fn of(ip: IpAddr) -> Source {
		match ip {
			IpAddr::V4(v4) => Source::V4(v4.octets()),
			IpAddr::V6(v6) => Source::V6(std::array::from_fn(|at| v6.octets()[at])),
		}
	}
}

#[derive(Default)]
struct Limits {devices: HashMap<[u8; 32], Account>, sources: HashMap<Source, Bucket>}

/// The limits per device and per source of the whole node.
pub struct State {
	limits: Mutex<Limits>,
	/// `replay.per_source` of the config in force.
	burst: AtomicU32,
	rate: AtomicU32,
}

impl Default for State {
	fn default() -> State {State {limits: Mutex::default(), burst: AtomicU32::new(DEFAULT_PROOFS_PER_SOURCE.burst), rate: AtomicU32::new(DEFAULT_PROOFS_PER_SOURCE.rate)}}
}

impl State {
	fn limits(&self) -> MutexGuard<'_, Limits> {self.limits.lock().unwrap_or_else(|e| e.into_inner())}

	/// `replay.per_source` of a config that is put in force.
	pub fn per_source(&self, of: ProofRate) {
		self.burst.store(of.burst, Ordering::Relaxed);
		self.rate.store(of.rate, Ordering::Relaxed);
	}

	/// Step 7 of "Verifying", which the replay rule calls last and only for a proof it would accept: "The rate limits for that device and for that source have room, and the device has fewer than 2 pending sessions. They are charged only now."
	/// Nothing is spent unless all of it has room, and then `seat` is one of the device's pending sessions from this moment, so that two proofs that come at once never both find the device's second place free.
	/// `replaced` is a pending session this proof takes the place of, which does not count against the device.
	pub fn charge(&self, seat: &Arc<Seat>, from: IpAddr, now: i64, replaced: Option<&Arc<Seat>>) -> Result<(), Spent> {
		let (mut limits, of, source) = (self.limits(), ProofRate {burst: self.burst.load(Ordering::Relaxed), rate: self.rate.load(Ordering::Relaxed)}, Source::of(from));
		let Limits {devices, sources} = &mut *limits;
		let account = devices.entry(seat.device).or_insert_with(|| Account::new(now));
		account.seats.retain(|held| held.upgrade().is_some_and(|held| !held.over()));
		if account.seats.iter().filter_map(Weak::upgrade).filter(|held| held.pending() && !replaced.is_some_and(|replaced| Arc::ptr_eq(replaced, held))).count() >= PENDING {return Err(Spent::Pending)}
		if !account.proofs.fill(DEVICE_PROOFS, now).has() {return Err(Spent::DeviceRate)}
		if !sources.contains_key(&source) && sources.len() >= MAX_SOURCES {return Err(Spent::SourceRate)}
		let bucket = sources.entry(source).or_insert_with(|| Bucket::full(of, now));
		if !bucket.fill(of, now).has() {return Err(Spent::SourceRate)}
		bucket.left -= 1000;
		account.proofs.left -= 1000;
		account.seats.push(Arc::downgrade(seat));
		Ok(())
	}

	/// The allowance a device has for proofs that a limit refused and that are recorded as spent all the same, as large as the one for accepted proofs. Whether there was one to spend.
	pub fn refuse(&self, device: [u8; 32], now: i64) -> bool {self.limits().devices.entry(device).or_insert_with(|| Account::new(now)).refused.fill(DEVICE_PROOFS, now).take()}

	/// Makes a pending session established, the moment a WireGuard packet of its device has authenticated on it. `cap` is how many established sessions its listener holds.
	/// "Only an established session counts against the device's session limit, and only at the moment it becomes established does it replace the device's oldest session when the limit is reached."
	/// The device's sessions are counted, the session goes live and the oldest gives way under one hold of the limits, so two listeners never both find room for a device's eighth session.
	/// `fronted` is how many established `fronted` sessions its listener holds, which only a session of that transport is held to. A device's third `fronted` session takes the place of its oldest `fronted` one, which makes room among its eight as well.
	/// `shaped` is the same for the `fronted-shaped` sessions among them, and holds a session of that transport to its own pool the same way.
	pub fn establish(&self, seat: &Arc<Seat>, cap: usize, fronted: usize, shaped: usize, now: i64) -> Seated {
		let limits = self.limits();
		let held: Vec<Arc<Seat>> = limits.devices.get(&seat.device).map(|account| account.seats.iter().filter_map(Weak::upgrade).filter(|held| held.established()).collect()).unwrap_or_default();
		let polling = seat.polled.is_some() && held.iter().filter(|held| held.polled.is_some()).count() >= DEVICE_FRONTED;
		let oldest = held.iter().filter(|one| if polling {one.polled.is_some()} else {held.len() >= DEVICE_SESSIONS}).min_by_key(|held| held.since.load(Ordering::Relaxed));
		// A pool that filled up since the proof was accepted, or that a reload made smaller than what it holds: nothing is displaced for the session. The one place it may still take is the one its device's oldest session gives up in this same pool.
		if seat.pool.load(Ordering::Relaxed) >= cap as i64 && !oldest.is_some_and(|oldest| Arc::ptr_eq(&oldest.pool, &seat.pool)) {return Seated::Full}
		if seat.polled.as_ref().is_some_and(|polled| polled.load(Ordering::Relaxed) >= fronted as i64 && !oldest.and_then(|oldest| oldest.polled.as_ref()).is_some_and(|gives| Arc::ptr_eq(gives, polled))) {return Seated::Full}
		if seat.shaped.as_ref().is_some_and(|counted| counted.load(Ordering::Relaxed) >= shaped as i64 && !oldest.and_then(|oldest| oldest.shaped.as_ref()).is_some_and(|gives| Arc::ptr_eq(gives, counted))) {return Seated::Full}
		if seat.phase.compare_exchange(WAITING, LIVE, Ordering::AcqRel, Ordering::Acquire).is_err() {return Seated::Gone}
		if let Some(oldest) = oldest {oldest.end(Ended::Displaced)}
		seat.pool.fetch_add(1, Ordering::Relaxed);
		if let Some(polled) = &seat.polled {polled.fetch_add(1, Ordering::Relaxed);}
		if let Some(counted) = &seat.shaped {counted.fetch_add(1, Ordering::Relaxed);}
		seat.since.store(now, Ordering::Relaxed);
		Seated::Established
	}

	/// Once a second: every session whose time is over ends, and an allowance that is whole again is forgotten.
	pub fn sweep(&self, now: Clock) {
		let (mut limits, of) = (self.limits(), ProofRate {burst: self.burst.load(Ordering::Relaxed), rate: self.rate.load(Ordering::Relaxed)});
		limits.devices.retain(|_, account| {
			for seat in account.seats.iter().filter_map(Weak::upgrade) {
				// A clock that stepped back must not keep a session for as long as it stepped: the session's times are brought back with it.
				seat.opened.fetch_min(now.ms, Ordering::Relaxed);
				seat.active.fetch_min(now.ms, Ordering::Relaxed);
				// "A pending session that is not established within the first tunnel packet deadline is ended", and "the node ends a session with no activity for" the idle time of its transport.
				if seat.pending() && now.ms - seat.opened.load(Ordering::Relaxed) >= FIRST_PACKET.as_millis() as i64 {seat.end(Ended::Deadline)}
				if seat.established() && now.ms - seat.active.load(Ordering::Relaxed) >= seat.idle {seat.end(Ended::Idle)}
			}
			account.seats.retain(|seat| seat.upgrade().is_some_and(|seat| !seat.over()));
			!account.seats.is_empty() || !account.proofs.fill(DEVICE_PROOFS, now.ms).whole(DEVICE_PROOFS) || !account.refused.fill(DEVICE_PROOFS, now.ms).whole(DEVICE_PROOFS)
		});
		limits.sources.retain(|_, bucket| !bucket.fill(of, now.ms).whole(of));
	}

	/// The one cut-off path of the native transports. Ends every session of a device that `cut` says the node has just cut off, for whatever reason, and every session whose device the plan no longer has in the session's inbound or whose transport secret the plan no longer has for that device:
	/// "When the old one is removed, sessions opened with it are dropped within one second, by the path that cuts off a disabled user." A device that is cut off loses its WireGuard sessions, and no session of a native transport outlives them.
	/// It runs once the plan is in force, so the tag table that could still open such a session is gone by then. How many ended.
	pub fn cut(&self, plan: &Plan, cut: impl Fn(&[u8; 32]) -> bool) -> usize {
		let seats: Vec<Arc<Seat>> = self.limits().devices.values().flat_map(|account| account.seats.iter().filter_map(Weak::upgrade)).filter(|seat| !seat.over()).collect();
		let mut ended = 0;
		for seat in seats {
			let at = plan.inbound_of(&seat.tunnel);
			// "When a node transport key is removed, sessions opened with it are dropped within one second, by the same path": removing it is the operator's one answer to a key that leaked.
			let keyed = seat.key.is_none_or(|key| at.and_then(|at| plan.inbounds[at].native.as_ref()).is_some_and(|native| native.holds(&key)));
			// A node link this node is dialled for is held to the same: the session of a link that was removed or changed ends with it.
			if cut(&seat.device) || !keyed || !at.is_some_and(|at| plan.holds(at, &seat.device, &seat.secret.0)) {
				seat.end(Ended::Revoked);
				ended += 1;
			}
		}
		ended
	}
}
