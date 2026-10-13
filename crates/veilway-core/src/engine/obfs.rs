//! The `udp-obfs` transport on the node (transports page, "`udp-obfs`", "Session activity and timers" and "WireGuard on an obfuscated transport"): one listener for each socket, its sessions, and the limits a proof is held to.
//! The packets themselves are `veilway_proto::udp_obfs`'s and the replay rule is `veilway_proto::replay`'s. What is here is the state machine around them, and it does no IO: `Listener::datagram` says what to send and what came out of the tunnel, and `read` does the sending.
//! Whatever is not a valid packet for this node gets silence: nothing is sent, nothing is logged, and a counter says why.
//! Time is the node's wall clock, which a test moves. A clock that steps back lets a session live at most one more of its own time limits, and one that steps ahead ends sessions early, whose clients open new ones.
use super::inbound::{Peers, Tunnel, Via};
use super::plan::{Derived, Native, Plan, Proved};
use super::replay::{self, Guard};
use super::Shared;
use crate::config::{ProofRate, DEFAULT_PROOFS_PER_SOURCE};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use veilway_proto::chunk::{ChunkError, Padding};
use veilway_proto::replay::{Decision, Refusal, WRITE_DEADLINE};
use veilway_proto::session::{self, Transport, ECHO, FIRST_PACKET, LONE_KEEPALIVE, PENDING};
use veilway_proto::udp_obfs::{self, Receiver, Sender, DATA_MIN, OLD_READABLE, OVERHEAD, SOURCE_SESSIONS};
use veilway_proto::NoRandom;
use veilway_wg::{Wg, MAX_PACKET};

/// "Sessions per device: 8." A device at this limit replaces its own oldest session once the new one is established.
pub const DEVICE_SESSIONS: usize = 8;
/// "Accepted proofs per device: burst 16, then 1 a second."
pub const DEVICE_PROOFS: ProofRate = ProofRate {burst: 16, rate: 1};
/// "WireGuard handshake initiations per session: burst 3, then 1 a second."
pub const SESSION_HANDSHAKES: ProofRate = ProofRate {burst: 3, rate: 1};
/// How many sources the node keeps a rate for at once. A source is in the table only after a proof of a device was accepted from it, and leaves when its allowance is whole again, so only devices of the config fill it. When it is full, a proof from a source that is not in it is refused.
pub const MAX_SOURCES: usize = 65536;
/// How many opening packets a listener keeps at once for the write of a higher limit, each for the write deadline at the most. Only a packet that a device in the tag table sealed is kept, and the largest is about 16 kB.
pub const HELD: usize = 64;
/// How many of the handshake initiations a session took to WireGuard it remembers, to drop one of them that comes again without charging the session's allowance.
const INITIATIONS: usize = 8;
/// How many echoes of one session wait for their delay at once. A device sends an idle keepalive every 10 seconds at the most, and an echo waits 3 at the most.
const MAX_ECHOES: u8 = 4;
/// A tag table that is swapped in later than this after its epoch began is counted and logged as late. The table before it holds the tags of the new epoch too, so nobody is refused for it until a whole epoch has passed.
pub const LATE: u64 = 10;
/// How often the task of `tables` looks whether the epoch has changed.
const TABLE_EVERY: Duration = Duration::from_millis(250);

/// The node's clock as a listener reads it: Unix time in milliseconds for its timers and in seconds for the replay rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {pub ms: i64, pub secs: u64}

impl Clock {
	pub fn of(now: OffsetDateTime) -> Clock {Clock {ms: (now.unix_timestamp_nanos() / 1_000_000) as i64, secs: replay::seconds(now)}}
}

/// How large a session may make the packet around one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Room {
	/// Up to the inbound's `mtu` and the 62 bytes of the envelope: "On `udp-obfs` no packet is larger than `mtu` + 62 bytes."
	Inbound,
	/// The same for a device that set a smaller MTU on the control channel: padding must not make a packet larger than the path was found to carry.
	Mtu(u16),
	/// No padding at all, for an MTU probe.
	Exact,
}

/// Why a datagram was dropped. This is for the node's counters: whoever sent it gets silence whatever it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
	/// Shorter than the smallest data packet.
	Short,
	/// No data packet of a session at its source, and its tag is not in the tag table. Every datagram of a stranger ends here, at the cost of one HMAC and one lookup.
	Unknown,
	/// Its tag is in the table and it does not open as an opening packet of that device, or is none the specification allows. Whoever sent it holds the inbound's mask key and a tag of this epoch without the secret, or the packet was changed on its way.
	Unopened,
	/// The replay rule: outside the window, at or below the floor, used before, or the cache is full.
	Window,
	Floor,
	Seen,
	CacheFull,
	/// Above the written limit, and not kept for the write that raises it: the listener keeps `HELD` such packets, each for at most the write deadline.
	Limit,
	/// The node takes no proof right now: it has no replay memory, or the memory waits for its file.
	NoReplay,
	/// The source has sessions of 4 other devices.
	SourceDevices,
	/// The listener's session pool is full.
	Pool,
	/// The device has 2 pending sessions.
	Pending,
	/// The device's or the source's allowance of accepted proofs is spent.
	DeviceRate,
	SourceRate,
	/// A handshake initiation above the session's allowance.
	Handshakes,
	/// A datagram inside a session that WireGuard did not take as a packet of the session's device: another device's, a replay, or not authentic.
	Tunnel,
	/// Something the node had to send did not fit, or the system gave no random bytes.
	Unsendable,
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
	/// No WireGuard packet of its device authenticated within the first tunnel packet deadline.
	Deadline,
	/// No activity for the idle time of the transport.
	Idle,
	/// The node sent 2^31 packets on it.
	Packets,
	/// A newer session of the same source and device took its place: a pending one at once, an established one after it stayed readable for 10 s.
	Replaced,
	/// Its device was at its session limit and established another.
	Displaced,
	/// The config no longer has its device as it was, or the transport secret it was opened with.
	Revoked,
}

const DROPS: usize = Dropped::Unsendable as usize + 1;
const ENDS: usize = Ended::Revoked as usize + 1;

#[derive(Default)]
struct Counters {dropped: [AtomicU64; DROPS], ended: [AtomicU64; ENDS], opened: AtomicU64, established: AtomicU64, sent: AtomicU64, waited: AtomicU64, spent: AtomicU64, rebuilds: AtomicU64, late: AtomicU64, failed: AtomicU64, collisions: AtomicU64}

/// What the `udp-obfs` listeners did since start, and what they hold right now. Everything but `pending`, `sessions` and `tags` only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObfsTotals {
	/// Sessions whose proof was accepted and on which WireGuard has not authenticated yet, right now.
	pub pending: usize,
	/// Established sessions right now, those that are only still readable included.
	pub sessions: usize,
	/// Epoch tags in the tables of all inbounds right now.
	pub tags: usize,
	/// Opening packets that were accepted, and sessions that became established.
	pub opened: u64,
	pub established: u64,
	/// Packets the listeners made for a socket: every one is a data packet of an established session. A node that only strangers talk to has 0 here.
	pub sent: u64,
	/// Opening packets that were kept for the write of a higher limit and taken to the replay rule again when it had ended.
	pub waited: u64,
	/// Opening packets the replay rule had nothing against and a limit refused, whose salt was recorded as spent so that nobody who saw the packet can use it later. One the device's allowance for that had no room for is in the limit's own counter and not here.
	pub spent: u64,
	pub short: u64,
	pub unknown: u64,
	pub open_failed: u64,
	pub window: u64,
	pub floor: u64,
	pub seen: u64,
	pub cache_full: u64,
	pub limit: u64,
	pub no_replay: u64,
	pub source_devices: u64,
	pub pool: u64,
	pub pending_full: u64,
	pub device_rate: u64,
	pub source_rate: u64,
	pub handshakes: u64,
	pub tunnel: u64,
	pub unsendable: u64,
	pub ended_deadline: u64,
	pub ended_idle: u64,
	pub ended_packets: u64,
	pub ended_replaced: u64,
	pub ended_displaced: u64,
	pub ended_revoked: u64,
	/// How often a tag table was built for a new epoch, how often that was late, and tags that were left out because another secret had them.
	pub table_rebuilds: u64,
	pub table_rebuilds_late: u64,
	/// Builds of a tag table that did not end, after which the table before stays in force and the build is tried again.
	pub table_build_failures: u64,
	pub tag_collisions: u64,
}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| NoRandom)}

/// An allowance of `burst` at once and `rate` a second, in thousandths.
struct Bucket {left: u64, at: i64}

impl Bucket {
	fn full(of: ProofRate, now: i64) -> Bucket {Bucket {left: u64::from(of.burst) * 1000, at: now}}

	/// Fills up for the time since it was last looked at. A clock that stepped back fills nothing.
	fn fill(&mut self, of: ProofRate, now: i64) -> &mut Bucket {
		(self.left, self.at) = (self.left.saturating_add((now.saturating_sub(self.at).max(0) as u64).saturating_mul(u64::from(of.rate))).min(u64::from(of.burst) * 1000), now);
		self
	}

	fn has(&self) -> bool {self.left >= 1000}

	/// Spends one, when there is one.
	fn take(&mut self) -> bool {
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

/// One `udp-obfs` association: a source address and port, a device, and the two keys its opening packet gave.
pub struct Session {
	pub source: SocketAddr,
	/// The WireGuard public key of the device the opening packet named. Only its packets are read on the session.
	pub device: [u8; 32],
	secret: Proved,
	receiver: Mutex<Receiver>,
	sender: Mutex<Sender>,
	/// Pending until a WireGuard packet of the device has authenticated on it, then established: live, or retired when a newer session of the same source and device took over and it is only still readable.
	phase: AtomicU8,
	/// The established sessions of the listener it belongs to.
	pool: Arc<AtomicI64>,
	counters: Arc<Counters>,
	/// The size of the opening packet: "The first answer is no larger than the opening packet it answers."
	budget: usize,
	answered: AtomicBool,
	/// The inbound's `mtu`, and the MTU the device was last sent a packet by, which is less when the device set one on the control channel. What WireGuard sends by itself is padded within that one too.
	mtu: u16,
	path: AtomicU16,
	/// When the proof was accepted and when the session was last active, in Unix milliseconds, and when it became established.
	opened: AtomicI64,
	active: AtomicI64,
	since: AtomicI64,
	sent: AtomicU64,
	/// Echoes that wait for their delay to pass, `MAX_ECHOES` at most.
	echoes: AtomicU8,
	/// The allowance of handshake initiations, and the hashes of the last `INITIATIONS` the session took to WireGuard. One of those again is a recorded packet, which WireGuard would drop as a repeat: it is dropped here first, and costs the device's allowance nothing.
	handshakes: Mutex<(Bucket, VecDeque<[u8; 32]>)>,
}

impl Session {
	fn phase(&self) -> u8 {self.phase.load(Ordering::Acquire)}

	/// Established and the one its device is answered on.
	pub fn live(&self) -> bool {self.phase() == LIVE}

	fn over(&self) -> bool {self.phase() == OVER}

	/// How many packets the node has sent on it.
	pub fn sent(&self) -> u64 {self.sent.load(Ordering::Relaxed)}

	/// Ends the session, once. It is taken out of its listener's table at that listener's next sweep, and nothing is read or sent on it from here on.
	fn end(&self, why: Ended) {
		let was = self.phase.swap(OVER, Ordering::AcqRel);
		if was == OVER {return}
		if was != WAITING {self.pool.fetch_sub(1, Ordering::Relaxed);}
		self.counters.ended[why as usize].fetch_add(1, Ordering::Relaxed);
	}

	/// Sends one WireGuard datagram the node has for the session's device. "A chunk that would hold exactly one WireGuard keepalive is held back for the lone keepalive delay": on a datagram transport a chunk holds one datagram, so the keepalive leaves by itself when the delay is over.
	/// WireGuard makes a keepalive for a peer once in several seconds at the most, so no more of them wait at once than there are sessions.
	pub async fn send(self: &Arc<Self>, tunnel: &Arc<Tunnel>, socket: &Arc<UdpSocket>, datagram: &[u8], wide: bool, room: Room) {
		if datagram.len() == 32 && datagram[0] == 4 {
			let (session, tunnel, socket, datagram) = (self.clone(), tunnel.clone(), socket.clone(), datagram.to_vec());
			tokio::spawn(async move {
				tokio::time::sleep(session::delay(&LONE_KEEPALIVE, &mut random).unwrap_or_default()).await;
				if let Some(sealed) = session.seal(Some(&datagram), wide, room) {tunnel.sent(socket.send_to(&sealed, session.source).await)}
			});
		} else if let Some(sealed) = self.seal(Some(datagram), wide, room) {tunnel.sent(socket.send_to(&sealed, self.source).await)}
	}

	/// One data packet around `datagram`, or the padding-only packet for None. None when the session is not established, has ended, or the packet cannot be made.
	/// "The node sends nothing on a pending session", and the first packet it sends on an established one is the first answer, which is no larger than the opening packet: a datagram that does not fit that goes unsent and a padding-only packet takes its place.
	/// `wide` says the datagram holds a control channel packet. A WireGuard handshake message is padded wide whatever it says.
	pub fn seal(&self, datagram: Option<&[u8]>, wide: bool, room: Room) -> Option<Vec<u8>> {
		if !matches!(self.phase(), LIVE | RETIRED) {return None}
		let (handshake, needed, mut out) = (datagram.is_some_and(|datagram| matches!(datagram.first(), Some(1 | 2))), datagram.map_or(DATA_MIN, |datagram| datagram.len() + 2 + DATA_MIN), Vec::new());
		let mut sender = self.sender.lock().unwrap_or_else(|e| e.into_inner());
		let first = !self.answered.swap(true, Ordering::AcqRel);
		if let Room::Mtu(mtu) = room {self.path.store(mtu.min(self.mtu), Ordering::Relaxed)}
		// A datagram WireGuard made is sent whole even where padding has no room left, so `needed` is the least any room allows but that of the first answer.
		let max =if first {self.budget} else if room == Room::Exact {needed} else {needed.max(usize::from(self.path.load(Ordering::Relaxed)) + OVERHEAD)};
		let sealed = match sender.seal(datagram, wide || handshake, max, &mut random, &mut out) {
			Err(ChunkError::Size) if first && datagram.is_some() => {
				self.counters.dropped[Dropped::Unsendable as usize].fetch_add(1, Ordering::Relaxed);
				sender.seal(None, false, max, &mut random, &mut out)
			}
			sealed => sealed,
		};
		drop(sender);
		match sealed {
			Ok(()) => {
				self.sent.fetch_add(1, Ordering::Relaxed);
				self.counters.sent.fetch_add(1, Ordering::Relaxed);
				Some(out)
			}
			// "The node ends a session at 2^31 sent. The last case is counted and logged at info. The client then meets silence and opens a new session."
			Err(ChunkError::Number) => {
				if !self.over() {tracing::info!("udp-obfs: a session reached the {} packets one key may seal and is ended. Its client opens a new one", udp_obfs::KEY_PACKETS)}
				self.end(Ended::Packets);
				None
			}
			Err(_) => {
				self.counters.dropped[Dropped::Unsendable as usize].fetch_add(1, Ordering::Relaxed);
				None
			}
		}
	}
}

/// What one source address and port has of one device: "Sessions are kept per source address and port and per device."
struct Slot {device: [u8; 32], pending: Option<Arc<Session>>, live: Option<Arc<Session>>, old: Option<(Arc<Session>, i64)>}

impl Slot {
	/// Drops what has ended, and the session that was only still readable once its time is over. Whether anything is left.
	fn tidy(&mut self, now: i64) -> bool {
		if let Some((old, until)) = &self.old {
			if *until <= now {old.end(Ended::Replaced)}
		}
		if self.pending.as_ref().is_some_and(|session| session.over()) {self.pending = None}
		if self.live.as_ref().is_some_and(|session| session.over()) {self.live = None}
		if self.old.as_ref().is_some_and(|(session, _)| session.over()) {self.old = None}
		self.pending.is_some() || self.live.is_some() || self.old.is_some()
	}
}

/// The `udp-obfs` transport of one socket for one tunnel. It lives for as long as the socket is read for that tunnel, across reloads, and its sessions with it.
pub struct Listener {
	pub tunnel: Arc<Tunnel>,
	sessions: Mutex<HashMap<SocketAddr, Vec<Slot>>>,
	pool: Arc<AtomicI64>,
	/// `limits.sessions` of the transport: "Sessions: 16,384 per listen address."
	cap: AtomicUsize,
	/// Opening packets that the replay rule had nothing against but the written limit, each with its source and when it came: they wait for the write that raises the limit and are taken to the rule again when it has ended. `HELD` at the most, and none twice.
	held: Mutex<VecDeque<(SocketAddr, Vec<u8>, i64)>>,
}

/// What a device has across every listener: its allowance of accepted proofs, its allowance of proofs that a limit refused and that are recorded as spent all the same, and its sessions.
struct Account {proofs: Bucket, refused: Bucket, sessions: Vec<Weak<Session>>}

impl Account {
	fn new(now: i64) -> Account {Account {proofs: Bucket::full(DEVICE_PROOFS, now), refused: Bucket::full(DEVICE_PROOFS, now), sessions: Vec::new()}}
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Source {V4([u8; 4]), V6([u8; 8])}

impl Source {
	/// "A source is an IPv4 address or an IPv6 /64."
	fn of(ip: IpAddr) -> Source {
		match ip {
			IpAddr::V4(v4) => Source::V4(v4.octets()),
			IpAddr::V6(v6) => Source::V6(std::array::from_fn(|at| v6.octets()[at])),
		}
	}
}

#[derive(Default)]
struct Limits {devices: HashMap<[u8; 32], Account>, sources: HashMap<Source, Bucket>}

/// What every `udp-obfs` listener of the node shares: the limits per device and per source, which are the node's and not a listener's, and the counters.
pub struct State {
	listeners: Mutex<Vec<Weak<Listener>>>,
	limits: Mutex<Limits>,
	counters: Arc<Counters>,
	/// `replay.per_source` of the config in force.
	burst: AtomicU32,
	rate: AtomicU32,
}

impl Default for State {
	fn default() -> State {State {listeners: Mutex::default(), limits: Mutex::default(), counters: Arc::default(), burst: AtomicU32::new(DEFAULT_PROOFS_PER_SOURCE.burst), rate: AtomicU32::new(DEFAULT_PROOFS_PER_SOURCE.rate)}}
}

/// Buffers one reader keeps between datagrams, and what the last datagram left in them: `out` is what to send to its source, in order, and `ip` the IP packets that came out of the tunnel.
#[derive(Default)]
pub struct Work {scratch: Vec<u8>, net: Vec<Vec<u8>>, pub ip: Vec<Vec<u8>>, pub out: Vec<Vec<u8>>}

/// What a datagram did that held an authentic WireGuard packet of a session's device.
pub struct Handled {
	/// The device, by its WireGuard public key, for the packets in `Work::ip`.
	pub device: [u8; 32],
	/// Set when the chunk held only a WireGuard keepalive and nothing was sent back: the session to echo on, and how many packets the node had sent on it by then.
	pub echo: Option<(Arc<Session>, u64)>,
}

impl State {
	/// Counts a datagram that was dropped. It has done nothing, which is what the answer says to whoever handled it.
	fn dropped<T>(&self, why: Dropped) -> Option<T> {
		self.counters.dropped[why as usize].fetch_add(1, Ordering::Relaxed);
		None
	}

	fn limits(&self) -> MutexGuard<'_, Limits> {self.limits.lock().unwrap_or_else(|e| e.into_inner())}

	fn listeners(&self) -> Vec<Arc<Listener>> {
		let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
		listeners.retain(|listener| listener.strong_count() > 0);
		listeners.iter().filter_map(Weak::upgrade).collect()
	}

	/// A listener for `tunnel` that holds at most `cap` established sessions.
	pub fn listen(&self, tunnel: Arc<Tunnel>, cap: usize) -> Arc<Listener> {
		let listener = Arc::new(Listener {tunnel, sessions: Mutex::default(), pool: Arc::default(), cap: AtomicUsize::new(cap), held: Mutex::default()});
		self.listeners.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::downgrade(&listener));
		listener
	}

	/// `replay.per_source` of a config that is put in force.
	pub fn per_source(&self, of: ProofRate) {
		self.burst.store(of.burst, Ordering::Relaxed);
		self.rate.store(of.rate, Ordering::Relaxed);
	}

	/// Once a second: every session whose time is over ends, what has ended leaves the tables, and an allowance that is whole again is forgotten.
	pub fn sweep(&self, now: Clock) {
		for listener in self.listeners() {
			listener.sessions().retain(|_, slots| {
				for slot in slots.iter_mut() {
					// A clock that stepped back must not keep a session for as long as it stepped: the session's times are brought back with it.
					for session in [slot.pending.as_ref(), slot.live.as_ref(), slot.old.as_ref().map(|(session, _)| session)].into_iter().flatten() {
						session.opened.fetch_min(now.ms, Ordering::Relaxed);
						session.active.fetch_min(now.ms, Ordering::Relaxed);
						// "A pending session that is not established within the first tunnel packet deadline is ended", and "the node ends a session with no activity for 180 s".
						if session.phase() == WAITING && now.ms - session.opened.load(Ordering::Relaxed) >= FIRST_PACKET.as_millis() as i64 {session.end(Ended::Deadline)}
						if session.phase() != WAITING && now.ms - session.active.load(Ordering::Relaxed) >= Transport::UdpObfs.idle().as_millis() as i64 {session.end(Ended::Idle)}
					}
				}
				slots.retain_mut(|slot| slot.tidy(now.ms));
				!slots.is_empty()
			});
			// An opening packet that waited for a limit longer than a write may take is dropped: no write has ended for it, and the node cannot write.
			let mut held = listener.held.lock().unwrap_or_else(|e| e.into_inner());
			let kept = held.len();
			held.retain(|(.., came)| now.ms.saturating_sub(*came) < WRITE_DEADLINE.as_millis() as i64);
			self.counters.dropped[Dropped::Limit as usize].fetch_add((kept - held.len()) as u64, Ordering::Relaxed);
		}
		let (mut limits, of) = (self.limits(), ProofRate {burst: self.burst.load(Ordering::Relaxed), rate: self.rate.load(Ordering::Relaxed)});
		limits.devices.retain(|_, account| {
			account.sessions.retain(|session| session.upgrade().is_some_and(|session| !session.over()));
			!account.sessions.is_empty() || !account.proofs.fill(DEVICE_PROOFS, now.ms).whole(DEVICE_PROOFS) || !account.refused.fill(DEVICE_PROOFS, now.ms).whole(DEVICE_PROOFS)
		});
		limits.sources.retain(|_, bucket| !bucket.fill(of, now.ms).whole(of));
	}

	/// Ends every session of a device that `cut` says the node has just cut off, for whatever reason, and every session whose device the plan no longer has in the session's inbound or whose transport secret the plan no longer has for that device:
	/// "When the old one is removed, sessions opened with it are dropped within one second, by the path that cuts off a disabled user." A device that is cut off loses its WireGuard sessions, and no `udp-obfs` session of it outlives them.
	/// It runs once the plan is in force, so the tag table that could still open such a session is gone by then. How many ended.
	pub fn cut(&self, plan: &Plan, cut: impl Fn(&[u8; 32]) -> bool) -> usize {
		let mut ended = 0;
		for listener in self.listeners() {
			let at = plan.inbound_of(&listener.tunnel);
			for session in listener.sessions().values().flatten().flat_map(|slot| [slot.pending.as_ref(), slot.live.as_ref(), slot.old.as_ref().map(|(session, _)| session)]).flatten().filter(|session| !session.over()) {
				let device = plan.by_key.get(&session.device).map(|device| &plan.devices[*device]);
				if cut(&session.device) || !device.zip(at).is_some_and(|(device, at)| device.inbounds.contains(&at) && device.secrets.contains(&session.secret.0)) {
					session.end(Ended::Revoked);
					ended += 1;
				}
			}
		}
		ended
	}

	/// Says and counts the tags of a table that another secret had already and that were left out, for the plan that is put in force and for the table of a new epoch.
	pub fn collided(&self, inbound: &str, collisions: usize) {
		self.counters.collisions.fetch_add(collisions as u64, Ordering::Relaxed);
		tracing::error!("inbound {inbound}: {collisions} epoch tag(s) of one transport secret equal a tag of another and are left out of the tag table, so their device cannot open a session in that epoch. Two random secrets never do this: replace the secrets of the inbound's devices");
	}

	pub fn totals(&self, plan: &Plan) -> ObfsTotals {
		let (mut pending, mut sessions) = (0, 0);
		for listener in self.listeners() {
			for session in listener.sessions().values().flatten().flat_map(|slot| [slot.pending.as_ref(), slot.live.as_ref(), slot.old.as_ref().map(|(session, _)| session)]).flatten() {
				match session.phase() {
					WAITING => pending += 1,
					LIVE | RETIRED => sessions += 1,
					_ => {}
				}
			}
		}
		let (dropped, ended, count) = (|why: Dropped| self.counters.dropped[why as usize].load(Ordering::Relaxed), |why: Ended| self.counters.ended[why as usize].load(Ordering::Relaxed), |counter: &AtomicU64| counter.load(Ordering::Relaxed));
		ObfsTotals {
			pending, sessions,
			tags: plan.inbounds.iter().filter_map(|inbound| inbound.native.as_ref()).map(|native| native.tags().table.len()).sum(),
			opened: count(&self.counters.opened), established: count(&self.counters.established), sent: count(&self.counters.sent), waited: count(&self.counters.waited), spent: count(&self.counters.spent),
			short: dropped(Dropped::Short), unknown: dropped(Dropped::Unknown), open_failed: dropped(Dropped::Unopened), window: dropped(Dropped::Window), floor: dropped(Dropped::Floor), seen: dropped(Dropped::Seen), cache_full: dropped(Dropped::CacheFull), limit: dropped(Dropped::Limit), no_replay: dropped(Dropped::NoReplay),
			source_devices: dropped(Dropped::SourceDevices), pool: dropped(Dropped::Pool), pending_full: dropped(Dropped::Pending), device_rate: dropped(Dropped::DeviceRate), source_rate: dropped(Dropped::SourceRate), handshakes: dropped(Dropped::Handshakes), tunnel: dropped(Dropped::Tunnel), unsendable: dropped(Dropped::Unsendable),
			ended_deadline: ended(Ended::Deadline), ended_idle: ended(Ended::Idle), ended_packets: ended(Ended::Packets), ended_replaced: ended(Ended::Replaced), ended_displaced: ended(Ended::Displaced), ended_revoked: ended(Ended::Revoked),
			table_rebuilds: count(&self.counters.rebuilds), table_rebuilds_late: count(&self.counters.late), table_build_failures: count(&self.counters.failed), tag_collisions: count(&self.counters.collisions),
		}
	}
}

impl Listener {
	fn sessions(&self) -> MutexGuard<'_, HashMap<SocketAddr, Vec<Slot>>> {self.sessions.lock().unwrap_or_else(|e| e.into_inner())}

	/// `limits.sessions` of a config that is put in force. Sessions above a smaller number stay until they end.
	pub fn resize(&self, cap: usize) {self.cap.store(cap, Ordering::Relaxed)}

	/// The opening packets that wait for a higher limit, each with its source and when it came, taken out to go through `datagram` again now that a write of the replay file has ended. One the limit is still below is kept again by `datagram` until the write deadline has passed for it.
	pub fn waiting(&self) -> Vec<(SocketAddr, Vec<u8>, i64)> {self.held.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()}

	/// Step 7 of "Verifying" and the rest of step 6 of the node state machine, which the replay rule calls last and only for a packet it would accept: "The rate limits for that device and for that source have room, and the device has fewer than 2 pending sessions. They are charged only now."
	/// Nothing is spent unless all of it has room. `why` is set when there is none.
	fn charge(&self, state: &State, from: SocketAddr, device: [u8; 32], now: i64, why: &mut Dropped) -> bool {
		// "A source that already has sessions of 4 other devices: drop." A pending session of the same source and device is the one this packet takes the place of, so it does not count against the device.
		let replaced = {
			let mut sessions = self.sessions();
			let slots = sessions.get_mut(&from);
			if let Some(slots) = slots {
				slots.retain_mut(|slot| slot.tidy(now));
				if slots.len() >= SOURCE_SESSIONS && !slots.iter().any(|slot| slot.device == device) {
					*why = Dropped::SourceDevices;
					return false;
				}
				slots.iter().find(|slot| slot.device == device).and_then(|slot| slot.pending.clone())
			} else {None}
		};
		// "A full session table refuses new proofs."
		if self.pool.load(Ordering::Relaxed) >= self.cap.load(Ordering::Relaxed) as i64 {
			*why = Dropped::Pool;
			return false;
		}
		let (mut limits, of, source) = (state.limits(), ProofRate {burst: state.burst.load(Ordering::Relaxed), rate: state.rate.load(Ordering::Relaxed)}, Source::of(from.ip()));
		let Limits {devices, sources} = &mut *limits;
		let account = devices.entry(device).or_insert_with(|| Account::new(now));
		account.sessions.retain(|session| session.upgrade().is_some_and(|session| !session.over()));
		if account.sessions.iter().filter_map(Weak::upgrade).filter(|session| session.phase() == WAITING && !replaced.as_ref().is_some_and(|replaced| Arc::ptr_eq(replaced, session))).count() >= PENDING {
			*why = Dropped::Pending;
			return false;
		}
		if !account.proofs.fill(DEVICE_PROOFS, now).has() {
			*why = Dropped::DeviceRate;
			return false;
		}
		if !sources.contains_key(&source) && sources.len() >= MAX_SOURCES {
			*why = Dropped::SourceRate;
			return false;
		}
		let bucket = sources.entry(source).or_insert_with(|| Bucket::full(of, now));
		if !bucket.fill(of, now).has() {
			*why = Dropped::SourceRate;
			return false;
		}
		bucket.left -= 1000;
		account.proofs.left -= 1000;
		true
	}

	/// Makes a pending session established, the moment a WireGuard packet of its device has authenticated on it. False when it may not be: it was replaced or ended meanwhile, or the listener's pool has no place.
	/// "Only an established session counts against the device's session limit, and only at the moment it becomes established does it replace the device's oldest session when the limit is reached."
	fn establish(&self, state: &State, session: &Arc<Session>, now: Clock) -> bool {
		let mut sessions = self.sessions();
		let Some(slot) = sessions.get_mut(&session.source).and_then(|slots| slots.iter_mut().find(|slot| slot.device == session.device)) else {return false};
		if !slot.pending.as_ref().is_some_and(|pending| Arc::ptr_eq(pending, session)) {return false}
		{
			// The device's sessions are counted, the session goes live and the oldest gives way under one hold of the limits, so two listeners never both find room for a device's eighth session.
			let limits = state.limits();
			let held: Vec<Arc<Session>> = limits.devices.get(&session.device).map(|account| account.sessions.iter().filter_map(Weak::upgrade).filter(|held| matches!(held.phase(), LIVE | RETIRED)).collect()).unwrap_or_default();
			let oldest = held.iter().filter(|_| held.len() >= DEVICE_SESSIONS).min_by_key(|held| held.since.load(Ordering::Relaxed));
			// A pool that filled up since the proof was accepted, or that a reload made smaller than what it holds: the session stays pending and ends at its deadline, and nothing is displaced for it. The one place it may still take is the one its device's oldest session gives up in this same pool.
			if self.pool.load(Ordering::Relaxed) >= self.cap.load(Ordering::Relaxed) as i64 && !oldest.is_some_and(|oldest| Arc::ptr_eq(&oldest.pool, &self.pool)) {
				state.counters.dropped[Dropped::Pool as usize].fetch_add(1, Ordering::Relaxed);
				return false;
			}
			if session.phase.compare_exchange(WAITING, LIVE, Ordering::AcqRel, Ordering::Acquire).is_err() {return false}
			if let Some(oldest) = oldest {oldest.end(Ended::Displaced)}
		}
		self.pool.fetch_add(1, Ordering::Relaxed);
		session.since.store(now.ms, Ordering::Relaxed);
		state.counters.established.fetch_add(1, Ordering::Relaxed);
		slot.pending = None;
		// "Keep an older established session of the same source and device readable for 10 s before removing it. No other device's session is touched."
		if let Some(before) = slot.live.replace(session.clone()) {
			let _ = before.phase.compare_exchange(LIVE, RETIRED, Ordering::AcqRel, Ordering::Acquire);
			if let Some((older, _)) = slot.old.replace((before, now.ms + OLD_READABLE.as_millis() as i64)) {older.end(Ended::Replaced)}
		}
		true
	}

	/// Everything the node does with one datagram from `from`, short of IO, in the order of "Node state machine, for every datagram". `native` is what the plan in force holds for the listener's inbound, and `replay` the node's replay memory.
	/// What comes back is None for everything that held no authentic WireGuard packet of a session's device. Whatever is to be sent to `from` is in `work.out`, and it is empty for everything that is no packet of a device: "A prober that does not hold a device secret gets no reply, whatever it sends and however often."
	/// A stranger's datagram costs one look at the sessions of its source, one HMAC and one table lookup. Nothing here allocates by what a datagram says, and no lock is held across another's IO: there is none in here.
	/// `held` is None for a datagram off the socket, and for an opening packet that waited for a limit it is when it came, see `waiting`.
	#[allow(clippy::too_many_arguments)]
	pub fn datagram(self: &Arc<Self>, state: &State, native: &Native, replay: Option<&Guard>, socket: &Weak<UdpSocket>, from: SocketAddr, packet: &[u8], held: Option<i64>, now: Clock, work: &mut Work) -> Option<Handled> {
		let Work {scratch, net, ip, out} = work;
		net.clear();
		ip.clear();
		out.clear();
		// 1. "Shorter than 28 bytes: drop."
		if packet.len() < DATA_MIN {return state.dropped(Dropped::Short)}
		// 2. "If the source address and port have sessions, try the datagram as a data packet of each, and of a session one of them replaced if that is still readable. On success process the chunk and stop."
		let known: Vec<Arc<Session>> = self.sessions().get(&from).map(|slots| slots.iter().flat_map(|slot| [slot.live.clone(), slot.pending.clone(), slot.old.as_ref().filter(|(_, until)| *until > now.ms).map(|(session, _)| session.clone())]).flatten().filter(|session| !session.over()).collect()).unwrap_or_default();
		for session in &known {
			let opened = session.receiver.lock().unwrap_or_else(|e| e.into_inner()).open(packet, scratch);
			if let Ok(datagram) = opened {return self.tunnelled(state, socket, session, datagram, now, net, ip, out)}
		}
		// 3. "Shorter than 76 bytes: drop." 4. The mask and the table: "A miss: drop." 5. The packet opened under the key of the device the tag named: "A failure: drop."
		let tags = native.tags();
		let Some(named) = native.node.find(packet, &tags.table) else {return state.dropped(Dropped::Unknown)};
		let Ok(opening) = native.node.unseal(named, packet, scratch) else {return state.dropped(Dropped::Unopened)};
		// 6. "Check the version and the zero bytes, the timestamp and the salt against the replay rule, and the rate limits. Any failure: drop."
		// A packet the replay rule has nothing against and a limit refuses is recorded as spent all the same, and opens no session: left unrecorded it would be good for whoever saw it on its way, from any address, until its timestamp left the window.
		// What is recorded so has an allowance of its own for each device, as large as the one for accepted proofs, so that a device which sends more than it may fills the cache no faster than twice what the specification allows it. Beyond that the packet is dropped unrecorded.
		let (mut why, mut refused, device) = (Dropped::NoReplay, false, opening.device.public);
		let decision = replay.and_then(|replay| replay.with(|memory| opening.accept(memory, now.secs, |_| {
			refused = !self.charge(state, from, device, now.ms, &mut why);
			!refused || state.limits().devices.entry(device).or_insert_with(|| Account::new(now.ms)).refused.fill(DEVICE_PROOFS, now.ms).take()
		})));
		let accepted = match decision {
			Some(Decision::Accepted(_)) if refused => {
				state.counters.spent.fetch_add(1, Ordering::Relaxed);
				return state.dropped(why);
			}
			Some(Decision::Accepted(accepted)) => accepted,
			None => return state.dropped(Dropped::NoReplay),
			// The packet is good but for a limit the node is about to write. Dropped here, it would be good a moment later for whoever saw it and sent it again, from any address, a second before its device tries again.
			// So it is kept, and taken to the rule again from its own source when the write has ended: then it is the one that is recorded, and a copy is refused as seen. Nothing waits for the write on the way here. A copy of a packet that is kept is not kept twice.
			Some(Decision::Raise(limit, _)) => {
				if let Some(replay) = replay {replay.want(limit)}
				let (came, mut waiting) = (held.unwrap_or(now.ms), self.held.lock().unwrap_or_else(|e| e.into_inner()));
				if now.ms.saturating_sub(came) >= WRITE_DEADLINE.as_millis() as i64 || waiting.len() >= HELD || waiting.iter().any(|(_, kept, _)| kept[16..48] == packet[16..48]) {return state.dropped(Dropped::Limit)}
				if held.is_none() {state.counters.waited.fetch_add(1, Ordering::Relaxed);}
				waiting.push_back((from, packet.to_vec(), came));
				return None;
			}
			Some(Decision::Refused(refusal)) => {
				if let (Refusal::Floor, Some(replay)) = (refusal, replay) {replay.refused_at_floor()}
				return state.dropped(match refusal {
					Refusal::Window => Dropped::Window,
					Refusal::Floor => Dropped::Floor,
					Refusal::Seen => Dropped::Seen,
					Refusal::Full => Dropped::CacheFull,
					Refusal::Limited => why,
				});
			}
		};
		// 7. "Record the salt. Create a pending session for this source and this device, in place of a pending session of the same source and device if there is one, and process the chunk."
		let Ok(padding) = Padding::new(native.wide, native.normal, &mut random) else {return state.dropped(Dropped::Unsendable)};
		let session = Arc::new(Session {
			source: from, device, secret: accepted.device.id, receiver: Mutex::new(Receiver::new(accepted.keys.c2s)), sender: Mutex::new(Sender::new(accepted.keys.s2c, padding)), phase: AtomicU8::new(WAITING), pool: self.pool.clone(), counters: state.counters.clone(),
			budget: packet.len(), answered: AtomicBool::new(false), mtu: native.mtu, path: AtomicU16::new(native.mtu), opened: AtomicI64::new(now.ms), active: AtomicI64::new(now.ms), since: AtomicI64::new(now.ms), sent: AtomicU64::new(0), echoes: AtomicU8::new(0), handshakes: Mutex::new((Bucket::full(SESSION_HANDSHAKES, now.ms), VecDeque::new())),
		});
		{
			let mut sessions = self.sessions();
			let slots = sessions.entry(from).or_default();
			let at = slots.iter().position(|slot| slot.device == device).unwrap_or_else(|| {
				slots.push(Slot {device, pending: None, live: None, old: None});
				slots.len() - 1
			});
			if let Some(before) = slots[at].pending.replace(session.clone()) {before.end(Ended::Replaced)}
		}
		if let Some(account) = state.limits().devices.get_mut(&device) {account.sessions.push(Arc::downgrade(&session))}
		state.counters.opened.fetch_add(1, Ordering::Relaxed);
		self.tunnelled(state, socket, &session, Some(accepted.datagram), now, net, ip, out)
	}

	/// Steps 8 and 9: what a chunk that opened on a session holds goes to the tunnel as a datagram of the session's device and of no other.
	#[allow(clippy::too_many_arguments)]
	fn tunnelled(&self, state: &State, socket: &Weak<UdpSocket>, session: &Arc<Session>, datagram: Option<&[u8]>, now: Clock, net: &mut Vec<Vec<u8>>, ip: &mut Vec<Vec<u8>>, out: &mut Vec<Vec<u8>>) -> Option<Handled> {
		// A padding-only chunk holds nothing. It is no activity: a recorded one opens again.
		let datagram = datagram?;
		// "Excess messages are dropped silently and counted." An initiation the session took to WireGuard before is a recorded packet sent again, which WireGuard would drop as a repeat. It is dropped here, before the allowance is charged:
		// "The replay rule comes before any rate limit is charged. Otherwise one old token from a log, sent once a second, would keep a device's allowance empty", and with it the device from its next rekey.
		if datagram.first() == Some(&1) {
			let (hash, mut handshakes) = (digest(&SHA256, datagram), session.handshakes.lock().unwrap_or_else(|e| e.into_inner()));
			let (allowance, taken) = &mut *handshakes;
			if taken.iter().any(|taken| taken[..] == *hash.as_ref()) {return state.dropped(Dropped::Tunnel)}
			if !allowance.fill(SESSION_HANDSHAKES, now.ms).take() {return state.dropped(Dropped::Handshakes)}
			if taken.len() >= INITIATIONS {taken.pop_front();}
			taken.push_back(std::array::from_fn(|at| hash.as_ref()[at]));
		}
		let bound = {
			let mut peers = self.tunnel.lock();
			let bound = peers.wg.recv_bound(&session.device, session.source, datagram, net, ip).filter(|bound| bound.proven);
			// "A peer's endpoint moves between sessions only after a packet authenticated under that peer's keys." A session that is only still readable is read, and what WireGuard answers to a packet on it goes back on it, but the device's endpoint does not move to it: what the node has for the device goes out on the session that replaced it.
			if let Some(bound) = bound.filter(|_| session.live()) {peers.heard(bound.peer, Via::Obfs(socket.clone(), Arc::downgrade(session)))}
			bound
		};
		let Some(bound) = bound else {
			net.clear();
			ip.clear();
			return state.dropped(Dropped::Tunnel);
		};
		// "On `udp-obfs` only a chunk that holds a WireGuard packet which authenticates is activity."
		session.active.store(now.ms, Ordering::Relaxed);
		if session.phase() == WAITING {
			// "If it does not, send nothing. An older session stays as it was, and the pending one ends at its deadline."
			if !self.establish(state, session, now) {
				net.clear();
				ip.clear();
				return None;
			}
			let mut peers = self.tunnel.lock();
			if peers.wg.index(&session.device) == Some(bound.peer) {peers.heard(bound.peer, Via::Obfs(socket.clone(), Arc::downgrade(session)))}
		}
		// "At the moment a session becomes established it sends one chunk on it: the WireGuard handshake response when an initiation established it, and otherwise a padding-only chunk."
		if net.is_empty() && !session.answered.load(Ordering::Acquire) {out.extend(session.seal(None, false, Room::Inbound))}
		for datagram in net.drain(..) {out.extend(session.seal(Some(&datagram), false, Room::Inbound))}
		// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay, unless it sent something else in that time."
		// Each keepalive has its own echo and its own delay, and a session has only so many waiting at once, whatever its device sends.
		let mut echo = None;
		if bound.keepalive && out.is_empty() && session.live() {
			if session.echoes.fetch_add(1, Ordering::AcqRel) < MAX_ECHOES {echo = Some((session.clone(), session.sent()))} else {session.echoes.fetch_sub(1, Ordering::AcqRel);}
		}
		Some(Handled {device: session.device, echo})
	}
}

/// One datagram of a `udp-obfs` socket from its listener to the network and the tunnel: what the listener wants sent is sent to the datagram's source, and what came out of the tunnel goes the way every decrypted packet goes. `held` is as for `Listener::datagram`.
async fn handle(shared: &Arc<Shared>, listener: &Arc<Listener>, socket: &Arc<UdpSocket>, from: SocketAddr, packet: &[u8], held: Option<i64>, work: &mut Work) {
	let plan = shared.plan();
	let Some((at, native)) = plan.inbound_of(&listener.tunnel).and_then(|at| plan.inbounds[at].native.as_ref().map(|native| (at, native))) else {return};
	let handled = listener.datagram(&shared.obfs, native, shared.replay.get().map(|guard| &**guard), &Arc::downgrade(socket), from, packet, held, Clock::of((shared.now)()), work);
	for sealed in &work.out {listener.tunnel.sent(socket.send_to(sealed, from).await)}
	let Some(handled) = handled else {return};
	if let Some((session, mark)) = handled.echo {
		let (socket, tunnel) = (socket.clone(), listener.tunnel.clone());
		tokio::spawn(async move {
			tokio::time::sleep(session::delay(&ECHO, &mut random).unwrap_or_default()).await;
			session.echoes.fetch_sub(1, Ordering::AcqRel);
			if session.sent() != mark {return}
			if let Some(sealed) = session.seal(None, false, Room::Inbound) {tunnel.sent(socket.send_to(&sealed, session.source).await)}
		});
	}
	for packet in work.ip.drain(..) {shared.ingress(&plan, at, handled.device, packet).await}
}

/// Reads the socket of one `udp-obfs` transport until the handle it returns is aborted. Between datagrams it takes the opening packets that waited for a higher limit to the replay rule again, whenever a write of the replay file has ended.
pub fn read(shared: &Arc<Shared>, listener: Arc<Listener>, socket: Arc<UdpSocket>) -> AbortHandle {
	let shared = shared.clone();
	tokio::spawn(async move {
		let (mut buf, mut work, mut writes) = (vec![0u8; MAX_PACKET], Work::default(), shared.replay.get().map(|replay| replay.writes()));
		loop {
			let ended = async {
				match &mut writes {
					Some(writes) => writes.changed().await.is_ok(),
					None => std::future::pending().await,
				}
			};
			tokio::select! {
				received = socket.recv_from(&mut buf) => if let Ok((n, from)) = received {handle(&shared, &listener, &socket, from, &buf[..n], None, &mut work).await},
				ended = ended => {
					if !ended {writes = None}
					for (from, packet, came) in listener.waiting() {handle(&shared, &listener, &socket, from, &packet, Some(came), &mut work).await}
				}
			}
		}
	}).abort_handle()
}

/// Keeps the tag table of every inbound at the epoch the clock is in: "It is rebuilt on reload and when the epoch changes, away from the packet path, and swapped in whole." A reload builds its own with its plan, so this task only follows the clock.
/// A table that is swapped in more than `LATE` seconds into its epoch is counted and logged, and so is one whose predecessor did not hold the new epoch at all, which refused every client until now.
pub async fn tables(shared: Arc<Shared>) {
	let (mut tick, mut failed) = (tokio::time::interval(TABLE_EVERY), None::<(usize, u64)>);
	loop {
		tick.tick().await;
		let (plan, epoch) = (shared.plan(), udp_obfs::epoch(replay::seconds((shared.now)())));
		for at in 0..plan.inbounds.len() {
			let Some(before) = plan.inbounds[at].native.as_ref().map(|native| native.tags().epoch).filter(|before| *before != epoch) else {continue};
			let (building, secs) = (plan.clone(), replay::seconds((shared.now)()));
			let built = tokio::task::spawn_blocking(move || building.inbounds[at].native.as_ref().map(|native| native.build(secs))).await;
			let (Ok(Some(tags)), Some(native)) = (built, plan.inbounds[at].native.as_ref()) else {
				// The table before stays, and holds the tags of the epoch that has begun. It is tried again at the next look, and said once for each epoch it fails in.
				shared.obfs.counters.failed.fetch_add(1, Ordering::Relaxed);
				if failed.replace((at, epoch)) != Some((at, epoch)) {tracing::error!("inbound {}: the tag table for epoch {epoch} could not be built, so the one before stays in force and the build is tried again. If none is built within this epoch, every opening packet is refused from the next", plan.inbounds[at].tag)}
				continue;
			};
			let (into, behind, collisions, size) = (tags.epoch, replay::seconds((shared.now)()).saturating_sub(tags.epoch.saturating_mul(udp_obfs::EPOCH)), tags.collisions, tags.table.len());
			native.swap(tags);
			shared.obfs.counters.rebuilds.fetch_add(1, Ordering::Relaxed);
			if collisions > 0 {shared.obfs.collided(&plan.inbounds[at].tag, collisions)}
			if before.abs_diff(into) > 1 {
				shared.obfs.counters.late.fetch_add(1, Ordering::Relaxed);
				tracing::error!("inbound {}: its tag table was built for epoch {before} and the clock is in epoch {into}, so every opening packet was refused until now. The clock stepped, or the node was held up for minutes", plan.inbounds[at].tag);
			} else if behind > LATE {
				shared.obfs.counters.late.fetch_add(1, Ordering::Relaxed);
				tracing::warn!("inbound {}: its tag table of {size} tags for epoch {into} is in force {behind}s after that epoch began. Nobody was refused for it: the table before held this epoch too. A table that is a whole epoch late refuses every client", plan.inbounds[at].tag);
			}
		}
	}
}

/// A listener with all it needs and no socket, no engine and no file, for the fuzz target of the datagram path and for tests of the state machine alone: a node never has one.
#[doc(hidden)]
pub struct Bench {listener: Arc<Listener>, state: State, native: Native, replay: Guard, work: Work}

#[doc(hidden)]
impl Bench {
	/// An inbound with the private key `inbound` and one device for each entry of `devices`: its WireGuard public key and its transport secrets. `cap` is the listener's session pool and `now` the wall clock in Unix seconds.
	pub fn new(inbound: [u8; 32], devices: &[([u8; 32], Vec<[u8; 32]>)], cap: usize, now: u64) -> Bench {
		let (public, mut peers) = (veilway_wg::public_key(&inbound), Peers {wg: Wg::new(inbound), via: Vec::new()});
		for (device, _) in devices {peers.add(*device, None)}
		let (state, keys) = (State::default(), devices.iter().flat_map(|(device, secrets)| secrets.iter().map(|secret| Arc::new(Derived::new(secret, &public, device)))).collect());
		let listener = state.listen(Arc::new(Tunnel::new("bench".to_string(), peers, mpsc::channel(1).0)), cap);
		Bench {listener, state, native: Native::new(&public, None, 1390, keys, now), replay: Guard::unwritten(1024, now), work: Work::default()}
	}

	/// One datagram from `from` at the wall clock `now`, in Unix milliseconds. What the node would send back to `from`, and how many IP packets came out of the tunnel.
	pub fn datagram(&mut self, from: SocketAddr, packet: &[u8], now: i64) -> (&[Vec<u8>], usize) {
		let clock = Clock {ms: now, secs: (now / 1000).max(0) as u64};
		let handled = self.listener.datagram(&self.state, &self.native, Some(&self.replay), &Weak::new(), from, packet, None, clock, &mut self.work);
		(&self.work.out, if handled.is_some() {self.work.ip.len()} else {0})
	}

	/// What the node's timers do once a second at the wall clock `now`, in Unix milliseconds: sessions whose time is over end, the tag table follows the epoch, and the limit of the replay memory follows the clock and what proofs asked for, with every write going through.
	/// Then the opening packets that waited for a limit go to the replay rule again. For each of them: its source, the packet, what the node would send back to that source, and how many IP packets came out of the tunnel.
	pub fn tick(&mut self, now: i64) -> Vec<(SocketAddr, Vec<u8>, Vec<Vec<u8>>, usize)> {
		let clock = Clock {ms: now, secs: (now / 1000).max(0) as u64};
		self.state.sweep(clock);
		if self.native.tags().epoch != udp_obfs::epoch(clock.secs) {self.native.swap(self.native.build(clock.secs))}
		self.replay.serve(clock.secs);
		self.listener.waiting().into_iter().map(|(from, packet, came)| {
			let handled = self.listener.datagram(&self.state, &self.native, Some(&self.replay), &Weak::new(), from, &packet, Some(came), clock, &mut self.work);
			(from, packet, self.work.out.clone(), if handled.is_some() {self.work.ip.len()} else {0})
		}).collect()
	}

	pub fn totals(&self) -> ObfsTotals {
		let mut totals = self.state.totals(&Plan::default());
		totals.tags = self.native.tags().table.len();
		totals
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const NODE: [u8; 32] = [0x10; 32];
	const KEYS: [[u8; 32]; 2] = [[0x21; 32], [0x22; 32]];
	const TIME: i64 = 1_700_000_000_000;
	const MAX: usize = 1390 + OVERHEAD;

	fn from(port: u16) -> SocketAddr {SocketAddr::from(([192, 0, 2, 1], port))}

	/// A device's WireGuard and what it needs to open sessions with `secret`.
	fn device(n: usize, secret: [u8; 32]) -> (Wg, udp_obfs::Client) {
		let mut wg = Wg::new(KEYS[n]);
		wg.add_peer(veilway_wg::public_key(&NODE), None, None).unwrap();
		(wg, udp_obfs::Client::new(&secret, &veilway_wg::public_key(&NODE)))
	}

	/// An opening packet around `datagram` with the timestamp of `now`, and the two directions of its session.
	fn opening(client: &udp_obfs::Client, datagram: &[u8], now: i64) -> (Vec<u8>, Sender, Receiver) {
		let (mut packet, padding) = (Vec::new(), Padding::new(1023, 255, &mut random).unwrap());
		let keys = client.open((now / 1000) as u64, datagram, &padding, MAX, &mut random, &mut packet).unwrap();
		(packet, Sender::new(keys.c2s, padding), Receiver::new(keys.s2c))
	}

	// The state machine alone, with no socket and no file: what the fuzz target `obfs_listener` drives with any input is driven here the way a device and a stranger drive it.
	#[test]
	fn a_listener_answers_its_device_once_and_nobody_else() {
		let mut bench = Bench::new(NODE, &[(veilway_wg::public_key(&KEYS[0]), vec![[0xa0; 32]]), (veilway_wg::public_key(&KEYS[1]), vec![[0xa1; 32]])], 4, TIME as u64 / 1000);
		let ((mut a, wrap), (mut b, _), mut net) = (device(0, [0xa0; 32]), device(1, [0xa1; 32]), Vec::new());
		// How many packets the node sends for a datagram, and how many it takes out of the tunnel.
		let did = |bench: &mut Bench, port: u16, packet: &[u8]| {
			let (out, carried) = bench.datagram(from(port), packet, TIME);
			(out.len(), carried)
		};
		// A stranger's bytes of any size, and an opening packet under a secret the node does not have.
		for size in [0, 27, 28, 76, 148, 1400] {assert_eq!(did(&mut bench, 1, &vec![7; size]), (0, 0))}
		a.encapsulate(0, &[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1], &mut net);
		let (stranger, ..) = opening(&udp_obfs::Client::new(&[0xee; 32], &veilway_wg::public_key(&NODE)), &net[0], TIME);
		assert_eq!((did(&mut bench, 1, &stranger), bench.totals().unknown, bench.totals().short), ((0, 0), 5, 2));
		// Device A's secret around device B's initiation: a pending session, and silence.
		let mut other = Vec::new();
		b.encapsulate(0, &[0x45; 20], &mut other);
		let (foreign, ..) = opening(&wrap, &other[0], TIME);
		assert_eq!((did(&mut bench, 2, &foreign), bench.totals().pending, bench.totals().tunnel), ((0, 0), 1, 1));
		// Device A's own: one answer, no larger than the opening packet, which is the handshake response under the session's key.
		let (packet, mut tx, mut rx) = opening(&wrap, &net[0], TIME);
		let (answers, mut scratch) = (bench.datagram(from(3), &packet, TIME).0.to_vec(), Vec::new());
		assert!(answers.len() == 1 && answers[0].len() <= packet.len(), "{} answers to an opening packet of {} bytes", answers.len(), packet.len());
		let response = rx.open(&answers[0], &mut scratch).unwrap().expect("a padding-only first answer to an initiation").to_vec();
		assert_eq!((response.len(), response[0], bench.totals().sessions, bench.totals().established), (92, 2, 1, 1));
		// The device's WireGuard takes the response and sends its keepalive and the packet that waited, each in a data packet.
		let (mut back, mut carried) = (Vec::new(), 0);
		a.recv_from_network(from(443), &response, &mut back, &mut Vec::new());
		for datagram in &back {
			let mut sealed = Vec::new();
			tx.seal(Some(datagram), false, MAX, &mut random, &mut sealed).unwrap();
			carried += did(&mut bench, 3, &sealed).1;
			// The same data packet again opens, and WireGuard refuses what is in it.
			assert_eq!(did(&mut bench, 3, &sealed), (0, 0));
		}
		assert_eq!((carried, back.len()), (1, 2));
		// The opening packet again, from its source and from another: it is spent.
		assert_eq!((did(&mut bench, 3, &packet), did(&mut bench, 4, &packet), bench.totals().seen), ((0, 0), (0, 0), 2));
		// The pending session ends at its deadline, and the established one after its idle time.
		bench.tick(TIME + 10_000);
		assert_eq!((bench.totals().pending, bench.totals().ended_deadline, bench.totals().sessions), (0, 1, 1));
		bench.tick(TIME + 190_000);
		assert_eq!((bench.totals().sessions, bench.totals().ended_idle), (0, 1));
		// Nothing but the one answer to the device was ever made for a socket.
		assert_eq!(bench.totals().sent, 1);
	}

	/// A device of the bench with a session that its opening packet around a handshake initiation established from port 3, and the handshake finished on it.
	fn established(bench: &mut Bench) -> (Wg, udp_obfs::Client, Sender, Receiver) {
		let ((mut a, wrap), mut net, mut scratch, mut back) = (device(0, [0xa0; 32]), Vec::new(), Vec::new(), Vec::new());
		a.encapsulate(0, &[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1], &mut net);
		let (packet, mut tx, mut rx) = opening(&wrap, &net[0], TIME);
		let answers = bench.datagram(from(3), &packet, TIME).0.to_vec();
		let response = rx.open(&answers[0], &mut scratch).unwrap().unwrap().to_vec();
		a.recv_from_network(from(443), &response, &mut back, &mut Vec::new());
		for datagram in &back {
			let mut sealed = Vec::new();
			tx.seal(Some(datagram), false, MAX, &mut random, &mut sealed).unwrap();
			bench.datagram(from(3), &sealed, TIME);
		}
		(a, wrap, tx, rx)
	}

	// "The replay rule comes before any rate limit is charged. Otherwise one old token from a log, sent once a second, would keep a device's allowance empty." The same holds for a session's allowance of handshake initiations and a recorded data packet that holds one.
	#[test]
	fn a_recorded_initiation_sent_again_costs_the_session_nothing_of_its_allowance() {
		let (node, mut bench) = (veilway_wg::public_key(&NODE), Bench::new(NODE, &[(veilway_wg::public_key(&KEYS[0]), vec![[0xa0; 32]])], 4, TIME as u64 / 1000));
		let (mut a, _, mut tx, _) = established(&mut bench);
		// A rekey: a fresh initiation in a data packet, which somebody records.
		let rekey = |a: &mut Wg, tx: &mut Sender| {
			let (mut net, mut sealed) = (Vec::new(), Vec::new());
			a.drop_sessions(&node);
			a.encapsulate(0, &[0x45; 20], &mut net);
			tx.seal(Some(&net[0]), true, MAX, &mut random, &mut sealed).unwrap();
			sealed
		};
		let recorded = rekey(&mut a, &mut tx);
		assert_eq!(bench.datagram(from(3), &recorded, TIME).0.len(), 1, "the rekey was not answered");
		// The recorded packet again and again from the session's source: silence, and nothing spent.
		for _ in 0..20 {assert!(bench.datagram(from(3), &recorded, TIME).0.is_empty())}
		assert_eq!((bench.totals().handshakes, bench.totals().tunnel), (0, 20));
		// The device's own next initiation is answered, and the one after it. Then its allowance of 3 at once is spent, the opening packet's among them, and one more is dropped for it.
		for expected in [1, 0] {assert_eq!(bench.datagram(from(3), &rekey(&mut a, &mut tx), TIME + 400).0.len(), expected)}
		assert_eq!(bench.totals().handshakes, 1);
	}

	// An opening packet above the written limit is kept, not dropped: when the limit is written it is taken to the rule from its own source, so it is the one that is recorded and whoever sends a copy from elsewhere is refused. A packet a limit refuses is recorded as spent as well.
	#[test]
	fn an_opening_packet_that_waits_for_the_limit_or_is_refused_by_a_limit_is_good_for_nobody_else() {
		let mut bench = Bench::new(NODE, &[(veilway_wg::public_key(&KEYS[0]), vec![[0xa0; 32]])], 4, TIME as u64 / 1000);
		let ((mut a, wrap), mut net) = (device(0, [0xa0; 32]), Vec::new());
		a.encapsulate(0, &[0x45; 20], &mut net);
		// The device's clock is 40 seconds ahead, which is above the limit and inside the window.
		let (packet, ..) = opening(&wrap, &net[0], TIME + 40_000);
		assert!(bench.datagram(from(3), &packet, TIME).0.is_empty());
		// A copy from somebody who saw it, before the write has ended: neither answered nor kept a second time.
		assert!(bench.datagram(from(9), &packet, TIME).0.is_empty());
		assert_eq!((bench.totals().waited, bench.totals().limit, bench.totals().opened), (1, 1, 0));
		// The write ends: the original is answered at its own source, and the copy is refused as seen wherever it comes from.
		let again = bench.tick(TIME + 100);
		assert_eq!((again.len(), again[0].0, again[0].2.len(), bench.totals().opened, bench.totals().established), (1, from(3), 1, 1, 1));
		assert!(bench.datagram(from(9), &packet, TIME + 200).0.is_empty() && bench.datagram(from(3), &packet, TIME + 200).0.is_empty());
		assert_eq!((bench.totals().seen, bench.totals().established), (2, 1));
		// The pool of a second bench has no place: an opening packet is refused for it, and is spent all the same.
		let mut full = Bench::new(NODE, &[(veilway_wg::public_key(&KEYS[0]), vec![[0xa0; 32]])], 0, TIME as u64 / 1000);
		let (mut net, mut later) = (Vec::new(), Vec::new());
		a.drop_sessions(&veilway_wg::public_key(&NODE));
		a.encapsulate(0, &[0x45; 20], &mut net);
		let (refused, ..) = opening(&wrap, &net[0], TIME);
		assert!(full.datagram(from(3), &refused, TIME).0.is_empty() && full.datagram(from(9), &refused, TIME).0.is_empty());
		assert_eq!((full.totals().pool, full.totals().spent, full.totals().seen, full.totals().opened), (1, 1, 1, 0));
		// What is recorded so has its own allowance for each device, 16 at once: beyond it a refused packet is dropped unrecorded, so a device that sends more than it may does not fill the cache with them.
		for _ in 0..20 {
			a.drop_sessions(&veilway_wg::public_key(&NODE));
			a.encapsulate(0, &[0x45; 20], &mut later);
			assert!(full.datagram(from(3), &opening(&wrap, &later.pop().unwrap(), TIME).0, TIME).0.is_empty());
		}
		assert_eq!((full.totals().pool, full.totals().spent), (21, 16));
	}
}
