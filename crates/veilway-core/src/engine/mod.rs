//! The engine: one WireGuard tunnel per inbound, every decrypted packet checked and routed, and TCP and UDP flows re-dialled by a userspace stack through the outbound of the exit they were routed to.
//! Only an `l3` exit uses a TUN device and kernel routing, and only for the flows that were routed to it.
pub mod dns;
mod flows;
pub mod gate;
mod host;
pub mod icmp;
mod inbound;
pub mod l3;
pub mod netstack;
pub mod plan;
pub mod resolver;
pub mod route;
pub mod usage;

pub use plan::{Denied, Plan};
pub use route::Reason;

use crate::config::{Applied, ApplyError, Config, Diff, Revision, Snapshot, Store};
use host::Host;
use resolver::{Names, Resolver};
use route::Flows;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc, Notify, Semaphore};
use tokio::time::MissedTickBehavior;
use veilway_wg::ws;

/// Packets in flight between a tunnel and its stack in either direction.
const QUEUE: usize = 4096;
/// How often the engine looks at the clock for users whose `expires_at` has passed, and at every user's count for a quota that is spent or a quota period that has started over.
/// A user is cut off within this long of that moment, plus the time the cut-off itself takes.
const EXPIRY_EVERY: Duration = Duration::from_millis(250);
/// The flow table is swept once in this many looks at the clock, which is once a second.
const SWEEP_EVERY: u32 = 4;

/// Events the engine keeps for a listener that has not read them yet. A listener that falls further behind loses the oldest.
pub const MAX_EVENTS: usize = 1024;
/// How long an apply through the control API waits for the config file to be written before it says the file was not saved.
const SAVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a user who could connect no longer can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CutOff {Disabled, Expired, Quota, Removed}

/// Where a reload stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {Validate, Prepare}

/// Something the engine did that somebody watching the node wants to hear of at once. None carries a secret, a destination or a DNS name: only tags, user names and counts.
#[derive(Clone, Debug)]
pub enum Event {
	/// A reload or an apply put a new config in force.
	ConfigApplied {generation: u64, revision: Revision, diff: Arc<Diff>},
	/// A reload or an apply was refused and the running config stays. `errors` counts what validation found, and is 1 for a prepare that failed.
	ConfigRefused {stage: Stage, errors: usize},
	/// A user who could connect was cut off: by a reload, by the clock or by their quota.
	UserCutOff {user: String, reason: CutOff},
	/// A user who was denied may connect again: enabled by a reload, or their quota period started over.
	UserRestored {user: String},
	/// The upstream of an exit stopped relaying UDP (`udp` false) or relays it again.
	ExitUdpChanged {exit: String, udp: bool},
}

/// How a device's last authenticated datagram reached its inbound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {Udp, Ws}

/// A device as a peer of one inbound, as `Engine::peers` gives it.
#[derive(Clone, Debug)]
pub struct Peer {
	pub user: String,
	pub device: String,
	pub public_key: [u8; 32],
	pub inbound: String,
	/// How long ago the session it has was made. None without a session.
	pub handshake: Option<Duration>,
	/// None without a session, or when the transport it came over is gone.
	pub over: Option<Over>,
	/// The flows the device has in the flow table, through all its inbounds together.
	pub flows: usize,
}

/// What the engine knows of the upstream of one exit, as `Engine::exit_health` gives it.
#[derive(Clone, Debug)]
pub struct ExitHealth {
	pub exit: String,
	/// How long ago the upstream last refused to relay UDP. The mark is tried again after a minute and goes when the upstream relays UDP again. None for an upstream that has refused nothing, which every exit without a SOCKS5 proxy is.
	pub no_udp: Option<Duration>,
	pub udp_flips: u64,
}

/// What `start` needs besides the config document.
pub struct Options {
	/// The directory of the config file. Paths in the config are relative to it.
	pub dir: PathBuf,
	/// Whether an address belongs to this host, for the destination gate. Tests replace it to reach a responder on the machine they run on.
	pub is_local: fn(IpAddr) -> bool,
	/// The node's clock, which `expires_at` and the quota periods are held against. Tests replace it to move time.
	pub now: fn() -> OffsetDateTime,
	/// The revision of the bytes the config was parsed from, so that a reload of the same file is known to change nothing. Without it the first reload counts as a change.
	pub revision: Option<Revision>,
	/// Whether `reload_from` takes a file that group or others can read, as `--allow-readable-config` says at start.
	pub allow_readable: bool,
	/// The state file, which carries every user's usage across restarts, see `usage`. It is not relative to `dir`. Without one usage is kept in memory and gone with the process.
	pub state: Option<PathBuf>,
}

impl Options {
	pub fn new(dir: impl Into<PathBuf>) -> Options {Options {dir: dir.into(), is_local: gate::is_local, now: OffsetDateTime::now_utc, revision: None, allow_readable: false, state: None}}
}

/// Inner IP packets and their bytes. Up is from the user's device into the node, down is towards it.
#[derive(Default)]
pub struct Traffic {up_packets: AtomicU64, up_bytes: AtomicU64, down_packets: AtomicU64, down_bytes: AtomicU64}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {pub up_packets: u64, pub up_bytes: u64, pub down_packets: u64, pub down_bytes: u64}

impl Traffic {
	fn up(&self, bytes: usize) {
		self.up_packets.fetch_add(1, Ordering::Relaxed);
		self.up_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
	}

	fn down(&self, bytes: usize) {
		self.down_packets.fetch_add(1, Ordering::Relaxed);
		self.down_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
	}

	pub fn totals(&self) -> Totals {
		Totals {up_packets: self.up_packets.load(Ordering::Relaxed), up_bytes: self.up_bytes.load(Ordering::Relaxed), down_packets: self.down_packets.load(Ordering::Relaxed), down_bytes: self.down_bytes.load(Ordering::Relaxed)}
	}
}

/// What the node's resolver did with the DNS queries of its tunnels since start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsTotals {
	/// Answered with what a server said.
	pub answered: u64,
	/// Answered REFUSED: a rule, the destination gate, a block exit, or an exit the user may not use.
	pub refused: u64,
	/// Answered SERVFAIL because no server answered.
	pub failed: u64,
	/// Port 53 traffic that was not a DNS query, dropped without an answer.
	pub malformed: u64,
	/// Turned away because the user already had too many queries waiting.
	pub throttled: u64,
}

/// What the engine has learnt about an exit's upstream while running. It belongs to the exit's tag and outlives a reload that keeps the tag.
#[derive(Default)]
pub struct ExitState {
	/// When the upstream last refused a UDP ASSOCIATE. It expires, see `flows::UDP_RETRY`.
	no_udp: Mutex<Option<Instant>>,
	/// Switches between "relays udp" and "does not", in either direction.
	udp_flips: AtomicU64,
}

/// One user's counters as `Engine::counters` gives them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
	pub name: String,
	/// Everything the user sent and received since the state file first knew the name, or since start without a state file.
	pub traffic: Totals,
	/// Bytes in both directions since `period_start`, which is what `quota_bytes` is held against.
	pub used_bytes: u64,
	/// When the count last started over, in Unix seconds. 0 for a user who never had a `quota_period`.
	pub period_start: i64,
	pub quota_bytes: Option<u64>,
	pub denied: Option<Denied>,
}

impl Usage {
	fn of(user: &plan::User) -> Usage {Usage {name: user.name.clone(), traffic: user.state.traffic.totals(), used_bytes: user.state.used(), period_start: user.state.since.load(Ordering::Relaxed), quota_bytes: user.quota, denied: user.denied}}
}

/// Every counter of the node at one moment, in the order of the config. They are totals: whoever asks twice works out the rates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {pub users: Vec<Usage>, pub inbounds: Vec<(String, Totals)>, pub exits: Vec<(String, Totals)>}

/// What the engine keeps for a user while it runs. It belongs to the user's name: a reload that keeps the name keeps this, wherever the user stands in the list, and the state file carries the counts in it over a restart.
pub struct UserState {
	pub traffic: Traffic,
	/// Bytes of inner IP traffic in both directions since `since`. It counts whether or not the user has a quota, so a quota that is given later is held against what was used.
	used: AtomicU64,
	/// The start of the quota period `used` belongs to, in Unix seconds. It only ever moves forward, so a clock that steps back starts no count over.
	since: AtomicI64,
	/// What the user resolved through the node. Nothing in it is ever read for another user.
	names: Mutex<Names>,
	/// The queries of the user that may still wait for an upstream at once.
	in_flight: Semaphore,
}

impl Default for UserState {
	fn default() -> UserState {UserState {traffic: Traffic::default(), used: AtomicU64::new(0), since: AtomicI64::new(0), names: Mutex::default(), in_flight: Semaphore::new(resolver::MAX_IN_FLIGHT)}}
}

impl UserState {
	pub fn names(&self) -> MutexGuard<'_, Names> {self.names.lock().unwrap_or_else(|e| e.into_inner())}

	pub fn used(&self) -> u64 {self.used.load(Ordering::Relaxed)}

	/// Starts the count over when `start`, the start of the quota period the clock is in, lies after the period the count belongs to. Whoever sees the new period first does it, once.
	pub fn roll(&self, start: i64) {if self.since.fetch_max(start, Ordering::Relaxed) < start {self.used.store(0, Ordering::Relaxed)}}
}

/// Everything the engine's tasks share. What belongs to one user, device, inbound or exit hangs off the plan instead, see `plan`.
pub struct Shared {
	plan: RwLock<Arc<Plan>>,
	flows: Flows,
	drops: [AtomicU64; Reason::COUNT],
	resolver: Resolver,
	/// Pings that leave from the node's own address, by the device's address, the destination and the identifier the device chose, each with the public key of its device, the name of that device's user and the way to its socket.
	pings: Mutex<HashMap<(IpAddr, IpAddr, u16), ([u8; 32], Arc<str>, mpsc::Sender<Vec<u8>>)>>,
	/// One for all `ws` listeners.
	relays: Arc<ws::Stats>,
	is_local: fn(IpAddr) -> bool,
	now: fn() -> OffsetDateTime,
	/// Wakes the task that looks at the clock: a packet has taken a user across their quota.
	over: Notify,
	/// Wakes the task that writes the state file before its time has come.
	save: Notify,
	saver: tokio::sync::Mutex<usage::Saver>,
	/// Writes of the state file that failed since start.
	unwritten: AtomicU64,
	events: broadcast::Sender<Event>,
}

impl Shared {
	/// Never waits and never fails: with nobody listening the event is gone, and a listener that is too slow loses its oldest.
	fn publish(&self, event: Event) {let _ = self.events.send(event);}

	/// The plan in force. A task takes it once per packet or flow and works on that one value.
	pub fn plan(&self) -> Arc<Plan> {self.plan.read().unwrap_or_else(|e| e.into_inner()).clone()}

	fn count(&self, reason: Reason) {self.drops[reason as usize].fetch_add(1, Ordering::Relaxed);}

	/// Counts one inner IP packet of a user, towards the node (`up`) or towards the device, for the user's totals and against their quota. Every packet comes through here, whatever becomes of it, so traffic that is refused or answered by the node counts.
	/// It is atomics only. The one packet that takes the count across the quota wakes the task that cuts the user off, and any crossing that is missed is seen at that task's next look, `EXPIRY_EVERY` later at most.
	fn spend(&self, user: &plan::User, up: bool, bytes: usize) {
		if up {user.state.traffic.up(bytes)} else {user.state.traffic.down(bytes)}
		let before = user.state.used.fetch_add(bytes as u64, Ordering::Relaxed);
		if user.quota.is_some_and(|quota| before < quota && before.saturating_add(bytes as u64) >= quota) {self.over.notify_one()}
	}
}

/// A running engine. Its tasks live until the process exits and go on serving the config they have, and `shutdown` takes back what an l3 exit set up on the host. Dropping it does so too, without waiting for the l3 tasks to end.
pub struct Engine {shared: Arc<Shared>, store: Arc<Store>, host: Arc<tokio::sync::Mutex<Host>>, l3: Arc<Mutex<Option<host::Wired>>>, started: Instant, written: Arc<Mutex<u64>>}

/// Says what became of a reload to whoever listens for events. `before` is the generation that ran when it began: bytes that already ran put nothing in force and are no event, and neither is a reload that was turned away for its base revision.
fn announce(shared: &Shared, before: u64, result: &Result<Applied, ApplyError<anyhow::Error>>) {
	match result {
		Ok(applied) if applied.snapshot.generation != before => shared.publish(Event::ConfigApplied {generation: applied.snapshot.generation, revision: applied.snapshot.revision, diff: Arc::new(applied.diff.clone())}),
		Err(ApplyError::Invalid(report)) => shared.publish(Event::ConfigRefused {stage: Stage::Validate, errors: report.errors.len() + report.more_errors}),
		Err(ApplyError::Prepare(_)) => shared.publish(Event::ConfigRefused {stage: Stage::Prepare, errors: 1}),
		_ => {}
	}
}

/// `config::save` off the runtime's own threads, and given up on after `SAVE_TIMEOUT`. A write that was given up on is not stopped: it runs to its end, and the file may still come to hold what it was said not to.
/// `written` is the generation of the last config that went to the file, and each write holds it from its start to its end. So two writes never run at once, however long the first takes,
/// and one whose turn comes after a newer config was written leaves the file alone: the file never goes back to an older config.
async fn persist(file: PathBuf, bytes: Vec<u8>, generation: u64, written: Arc<Mutex<u64>>) -> io::Result<()> {
	tokio::time::timeout(SAVE_TIMEOUT, tokio::task::spawn_blocking(move || {
		let mut written = written.lock().unwrap_or_else(|e| e.into_inner());
		if *written > generation {return Err(io::Error::other("a newer config was written to the file first"))}
		crate::config::save(&file, &bytes)?;
		*written = generation;
		Ok(())
	})).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?.unwrap_or_else(|e| Err(io::Error::other(e)))
}

impl Drop for Engine {
	fn drop(&mut self) {self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();}
}

impl Engine {
	/// Stops the l3 exit and removes its interface, routes and firewall rules from the host, then writes the state file one last time. Everything else the engine holds goes with the process.
	/// The host comes first and the write is given `usage::LAST_WRITE` and no longer: a disk that hangs must not leave the firewall rules of a node that is going away in place.
	pub async fn shutdown(self) {
		let wired = self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();
		if let Some(wired) = wired {wired.running.close().await}
		if tokio::time::timeout(usage::LAST_WRITE, usage::save(&self.shared, true)).await.is_err() {tracing::error!("the state file was not written within {}s of the shutdown, so usage since its last write is lost", usage::LAST_WRITE.as_secs())}
	}

	/// Puts a new config document in force: it is parsed and validated, everything it needs from the host is prepared while the running config keeps working, and then it replaces that config in one step.
	/// With `base`, the reload is refused unless that is the revision that runs. Any error leaves the running config whole. An error of the prepare step names tags and field paths and never a value from the document.
	pub async fn reload(&self, document: Vec<u8>, base: Option<Revision>) -> Result<Applied, ApplyError<anyhow::Error>> {self.put(document, base, None).await.map(|(applied, _)| applied)}

	/// What an apply through the control API does: `reload` on the revision the caller read, and then the document is written to `file`, the config file the node was started with, so that a restart comes back with it.
	/// The write happens before any other reload can begin, so a `SIGHUP` never reads the file of the config before. The second value is how the write went: when it failed the config is in force all the same and the file still holds the one before.
	pub async fn apply(&self, document: Vec<u8>, base: Revision, file: &Path) -> Result<(Applied, io::Result<()>), ApplyError<anyhow::Error>> {self.put(document, Some(base), Some(file.to_path_buf())).await}

	async fn put(&self, document: Vec<u8>, base: Option<Revision>, file: Option<PathBuf>) -> Result<(Applied, io::Result<()>), ApplyError<anyhow::Error>> {
		let (shared, store, host, written) = (self.shared.clone(), self.store.clone(), self.host.clone(), self.written.clone());
		// On a task of its own: whoever asked may stop waiting, and a reload that is dropped halfway would leave the host between two configs.
		tokio::spawn(async move {
			let (before, mut saved, mut copy) = (store.current().generation, None, file.as_ref().map(|_| document.clone()));
			let result = store.apply(document, base, async |snapshot: &Snapshot, diff: &Diff| {
				apply(&shared, &host, snapshot, diff).await?;
				if let Some((file, bytes)) = file.clone().zip(copy.take()) {saved = Some(persist(file, bytes, snapshot.generation, written.clone()).await)}
				Ok(())
			}).await;
			// Bytes that already run went through no prepare. They are written all the same: this is how an apply whose write failed is tried again.
			if let (Ok(applied), Some((file, bytes))) = (&result, file.zip(copy)) {saved = Some(persist(file, bytes, applied.snapshot.generation, written).await)}
			announce(&shared, before, &result);
			result.map(|applied| (applied, saved.unwrap_or(Ok(()))))
		}).await.unwrap_or_else(|_| Err(ApplyError::Prepare(anyhow::anyhow!("the reload did not run to its end"))))
	}

	/// What `SIGHUP` does: reads the config file again and puts it in force like `reload`. A file whose bytes already run still has its certificates read again.
	/// A file that cannot be read or does not validate is logged once, with the paths of the fields that are wrong.
	pub async fn reload_from(&self, path: &Path) -> Result<Applied, ApplyError<anyhow::Error>> {
		let (shared, store, host, path) = (self.shared.clone(), self.store.clone(), self.host.clone(), path.to_path_buf());
		tokio::spawn(async move {
			let before = store.current().generation;
			let result = store.reload_from(&path, async |snapshot: &Snapshot, diff: &Diff| apply(&shared, &host, snapshot, diff).await).await;
			announce(&shared, before, &result);
			result
		}).await.unwrap_or_else(|_| Err(ApplyError::Prepare(anyhow::anyhow!("the reload did not run to its end"))))
	}

	/// The config that runs, with its revision.
	pub fn snapshot(&self) -> Snapshot {self.store.current()}

	/// What the engine says happened, from now on: see `Event`. Whoever reads slower than events come loses the oldest and is told how many, and the engine never waits for a reader.
	pub fn events(&self) -> broadcast::Receiver<Event> {self.shared.events.subscribe()}

	/// How long the engine has run.
	pub fn uptime(&self) -> Duration {self.started.elapsed()}

	/// Every device that may connect right now, once for each inbound it has an address in, with what its tunnel knows of it, inbound by inbound. The devices of a user who is denied are not peers and not in it.
	/// With `only`, the devices of the user of that name, and nothing of any other device is looked at.
	/// A tunnel is locked once, for as long as it takes to read two values for each of its devices that was asked for. That lock is the one every packet of the inbound takes, so whoever polls this holds no packet up for longer.
	pub fn peers(&self, only: Option<&str>) -> Vec<Peer> {
		let plan = self.plan();
		let user = only.map(|name| plan.users.iter().position(|user| user.name == name));
		if user == Some(None) {return Vec::new()}
		let mut asked = vec![Vec::new(); plan.inbounds.len()];
		for (at, device) in plan.devices.iter().enumerate().filter(|(_, device)| user.flatten().is_none_or(|user| device.user == user)) {
			for inbound in &device.inbounds {asked[*inbound].push(at)}
		}
		// The flow table is locked once for everybody, or once for each device of the one user: never for a copy of all of it to answer for a few.
		let (flows, mut out) = (only.is_none().then(|| self.shared.flows.per_device()), Vec::new());
		for (inbound, asked) in plan.inbounds.iter().zip(&asked).filter(|(_, asked)| !asked.is_empty()) {
			let seen: Vec<(Option<Duration>, Option<Over>)> = {
				let peers = inbound.tunnel.lock();
				asked.iter().map(|at| {
					let peer = peers.wg.index(&plan.devices[*at].public_key);
					let handshake = peer.and_then(|peer| peers.wg.time_since_last_handshake(peer));
					(handshake, peer.filter(|_| handshake.is_some()).and_then(|peer| peers.via.get(peer)).filter(|(socket, _)| socket.strong_count() > 0).map(|(_, over)| *over))
				}).collect()
			};
			out.extend(asked.iter().zip(seen).map(|(at, (handshake, over))| {
				let device = &plan.devices[*at];
				Peer {user: plan.users[device.user].name.clone(), device: device.name.clone(), public_key: device.public_key, inbound: inbound.tag.clone(), handshake, over, flows: flows.as_ref().map_or_else(|| self.shared.flows.of_device(&device.public_key), |flows| flows.get(&device.public_key).copied().unwrap_or(0))}
			}));
		}
		out
	}

	/// What the engine has learnt about the upstream of each exit, in the order of the config.
	pub fn exit_health(&self) -> Vec<ExitHealth> {
		self.plan().exits.iter().map(|exit| ExitHealth {exit: exit.tag.clone(), no_udp: exit.state.no_udp.lock().unwrap_or_else(|e| e.into_inner()).map(|since| since.elapsed()), udp_flips: exit.state.udp_flips.load(Ordering::Relaxed)}).collect()
	}

	pub fn plan(&self) -> Arc<Plan> {self.shared.plan()}

	pub fn user(&self, name: &str) -> Option<Totals> {self.plan().users.iter().find(|user| user.name == name).map(|user| user.state.traffic.totals())}

	pub fn inbound(&self, tag: &str) -> Option<Totals> {self.plan().inbounds.iter().find(|inbound| inbound.tag == tag).map(|inbound| inbound.traffic.totals())}

	pub fn exit(&self, tag: &str) -> Option<Totals> {self.plan().exits.iter().find(|exit| exit.tag == tag).map(|exit| exit.traffic.totals())}

	/// The counters of every user, inbound and exit of the config that runs, taken from one plan. A counter belongs to a name or a tag and goes on counting across reloads for as long as the config keeps that name or tag.
	/// An exit counts what is handed to it and what is taken from it, as inner IP packets: a TCP segment when the exit's stack takes it or gives it, a datagram when the exit's outbound takes it or gives it,
	/// a packet when the queue of the l3 interface takes it or the interface gives it to a live flow, a ping the node answers or sends on, and a DNS message of the node's resolver, which has no headers of a device around it.
	/// What is refused or dropped before that counts for no exit, and a flow that a `via` policy moved counts for the exit that carries it and not for the exit the rules chose.
	pub fn counters(&self) -> Counters {
		let plan = self.plan();
		Counters {
			users: plan.users.iter().map(Usage::of).collect(),
			inbounds: plan.inbounds.iter().map(|inbound| (inbound.tag.clone(), inbound.traffic.totals())).collect(),
			exits: plan.exits.iter().map(|exit| (exit.tag.clone(), exit.traffic.totals())).collect(),
		}
	}

	/// The counters of one user of the config that runs, as `counters` has them, without those of anybody else.
	pub fn usage(&self, name: &str) -> Option<Usage> {self.plan().users.iter().find(|user| user.name == name).map(Usage::of)}

	/// Writes of the state file that failed since start. While it grows, a node that stops loses what its users have used since the last write that went through.
	pub fn state_write_failures(&self) -> u64 {self.shared.unwritten.load(Ordering::Relaxed)}

	/// Packets dropped or refused for `reason` since start.
	pub fn dropped(&self, reason: Reason) -> u64 {self.shared.drops[reason as usize].load(Ordering::Relaxed)}

	/// How often the upstream of an exit switched between relaying UDP and not.
	pub fn udp_flips(&self, exit: &str) -> Option<u64> {self.plan().exits.iter().find(|e| e.tag == exit).map(|exit| exit.state.udp_flips.load(Ordering::Relaxed))}

	/// WebSocket connections dropped because they never finished the upgrade.
	pub fn ws_stalled(&self) -> u64 {self.shared.relays.stalled.load(Ordering::Relaxed)}

	/// WebSocket connections refused at accept: a listener was full, or one source had too many unfinished upgrades.
	pub fn ws_refused(&self) -> u64 {self.shared.relays.refused.load(Ordering::Relaxed)}

	pub fn dns(&self) -> DnsTotals {
		let resolver = &self.shared.resolver;
		DnsTotals {answered: resolver.answered.load(Ordering::Relaxed), refused: resolver.refused.load(Ordering::Relaxed), failed: resolver.failed.load(Ordering::Relaxed), malformed: resolver.malformed.load(Ordering::Relaxed), throttled: resolver.throttled.load(Ordering::Relaxed)}
	}

	/// Names the node remembers for a user right now: those the user resolved through it whose answer has not expired.
	pub fn dns_names(&self, user: &str) -> Option<usize> {self.plan().users.iter().find(|u| u.name == user).map(|user| user.state.names().names(Instant::now()))}

	/// Clears what the node remembers of one user's DNS answers. False when there is no such user.
	pub fn forget_names(&self, user: &str) -> bool {self.plan().users.iter().find(|u| u.name == user).map(|user| user.state.names().clear()).is_some()}

	/// Flows in the flow table right now.
	pub fn flows(&self) -> usize {self.shared.flows.len()}
}

/// The prepare step of a reload and, when nothing in it failed, the commit right behind it. `diff` says which tunnels restart.
async fn apply(shared: &Arc<Shared>, host: &tokio::sync::Mutex<Host>, snapshot: &Snapshot, diff: &Diff) -> anyhow::Result<()> {
	let restart: Vec<&str> = diff.inbound_changes.iter().filter(|change| change.restart).map(|change| change.tag.as_str()).collect();
	let mut host = host.lock().await;
	let staged = host.prepare(shared, &snapshot.config, &restart).await?;
	host.commit(shared, staged);
	Ok(())
}

/// Brings up every listener and task of a validated config and returns once they are bound.
pub async fn start(config: &Config, options: Options) -> anyhow::Result<Engine> {
	let report = config.validate(false);
	anyhow::ensure!(report.errors.is_empty(), "the config has {} errors: validate it before it is started", report.errors.len() + report.more_errors);
	let mut store = Store::new(config.clone(), options.revision.unwrap_or_else(|| Revision::of(&[])), report);
	store.allow_readable = options.allow_readable;
	// What the state file remembers goes in as the users of a plan that was never in force. The first plan takes each user's state from it by name, the way every later plan takes it from the one before, and a name the config no longer has is left behind.
	// A path the node may not write to is no path from here on: usage then lives in memory, as it does without a state file.
	let (remembered, state) = options.state.map_or((Vec::new(), None), |path| {
		let (users, writable) = usage::load(&path);
		(users, writable.then_some(path))
	});
	let remembered = Plan {users: remembered.into_iter().map(|(name, state)| plan::User {name, groups: Vec::new(), entitled: None, exit: None, quota: None, period: None, denied: Some(Denied::Disabled), state: Arc::new(state)}).collect(), ..Plan::default()};
	let shared = Arc::new(Shared {plan: RwLock::new(Arc::new(remembered)), flows: Flows::default(), drops: Default::default(), resolver: Resolver::default(), pings: Mutex::default(), relays: Arc::default(), is_local: options.is_local, now: options.now, over: Notify::new(), save: Notify::new(), saver: tokio::sync::Mutex::new(usage::Saver {path: state.clone(), written: Vec::new(), failing: None}), unwritten: AtomicU64::new(0), events: broadcast::Sender::new(MAX_EVENTS)});
	// A start is a reload from nothing: everything the config names is new, and a failure leaves nothing behind.
	let mut host = Host::new(options.dir);
	let staged = host.prepare(&shared, &store.current().config, &[]).await?;
	host.commit(&shared, staged);
	let (l3, host) = (host.l3.clone(), Arc::new(tokio::sync::Mutex::new(host)));
	tokio::spawn({
		let (shared, host) = (shared.clone(), host.clone());
		async move {
			let (mut tick, mut ticks) = (tokio::time::interval(EXPIRY_EVERY), 0u32);
			loop {
				tokio::select! {
					_ = tick.tick() => {
						ticks = ticks.wrapping_add(1);
						if ticks % SWEEP_EVERY == 0 {shared.flows.sweep()}
					}
					_ = shared.over.notified() => {}
				}
				// Held against the clock again at every tick, never slept towards, so a clock that jumps ahead cuts a user off as promptly as time that passes.
				let (plan, now) = (shared.plan(), (shared.now)());
				let starts = usage::starts(now);
				// A count whose period is over starts over here, for the plan in force, which is what brings it below the quota.
				// A user's count has turned when the quota is spent and the user is not denied for it, or the user is denied for it and the count is below the quota again.
				let turned = plan.users.iter().any(|user| user.quota.is_some_and(|quota| {
					if let Some(period) = user.period {user.state.roll(starts[period as usize])}
					matches!((user.denied, user.state.used() >= quota), (None, true) | (Some(Denied::Quota), false))
				}));
				if turned || plan.next_expiry.is_some_and(|at| at <= now) {host.lock().await.expire(&shared)}
			}
		}
	});
	if state.is_some() {
		tokio::spawn({
			let shared = shared.clone();
			async move {
				// The first write comes at once: it drops the entries of users the config no longer names, and says at start when the file cannot be written.
				let mut tick = tokio::time::interval(usage::WRITE_EVERY);
				tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
				loop {
					tokio::select! {
						_ = tick.tick() => {}
						_ = shared.save.notified() => {}
					}
					usage::save(&shared, false).await;
				}
			}
		});
	}
	Ok(Engine {shared, store: Arc::new(store), host, l3, started: Instant::now(), written: Arc::default()})
}
