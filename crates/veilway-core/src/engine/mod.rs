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

pub use plan::Plan;
pub use route::Reason;

use crate::config::{Applied, ApplyError, Config, Diff, Revision, Snapshot, Store};
use host::Host;
use resolver::{Names, Resolver};
use route::Flows;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::{mpsc, Semaphore};
use veilway_wg::ws;

/// Packets in flight between a tunnel and its stack in either direction.
const QUEUE: usize = 4096;
/// How often the engine looks at the clock for users whose `expires_at` has passed. A user is cut off within this long of that moment, plus the time the cut-off itself takes.
const EXPIRY_EVERY: Duration = Duration::from_millis(250);
/// The flow table is swept once in this many looks at the clock, which is once a second.
const SWEEP_EVERY: u32 = 4;

/// What `start` needs besides the config document.
pub struct Options {
	/// The directory of the config file. Paths in the config are relative to it.
	pub dir: PathBuf,
	/// Whether an address belongs to this host, for the destination gate. Tests replace it to reach a responder on the machine they run on.
	pub is_local: fn(IpAddr) -> bool,
	/// The node's clock, which `expires_at` is held against. Tests replace it to move time.
	pub now: fn() -> OffsetDateTime,
	/// The revision of the bytes the config was parsed from, so that a reload of the same file is known to change nothing. Without it the first reload counts as a change.
	pub revision: Option<Revision>,
	/// Whether `reload_from` takes a file that group or others can read, as `--allow-readable-config` says at start.
	pub allow_readable: bool,
}

impl Options {
	pub fn new(dir: impl Into<PathBuf>) -> Options {Options {dir: dir.into(), is_local: gate::is_local, now: OffsetDateTime::now_utc, revision: None, allow_readable: false}}
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

/// What the engine keeps for a user while it runs. It belongs to the user's name: a reload that keeps the name keeps this, wherever the user stands in the list.
pub struct UserState {
	pub traffic: Traffic,
	/// What the user resolved through the node. Nothing in it is ever read for another user.
	names: Mutex<Names>,
	/// The queries of the user that may still wait for an upstream at once.
	in_flight: Semaphore,
}

impl Default for UserState {
	fn default() -> UserState {UserState {traffic: Traffic::default(), names: Mutex::default(), in_flight: Semaphore::new(resolver::MAX_IN_FLIGHT)}}
}

impl UserState {
	pub fn names(&self) -> MutexGuard<'_, Names> {self.names.lock().unwrap_or_else(|e| e.into_inner())}
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
}

impl Shared {
	/// The plan in force. A task takes it once per packet or flow and works on that one value.
	pub fn plan(&self) -> Arc<Plan> {self.plan.read().unwrap_or_else(|e| e.into_inner()).clone()}

	fn count(&self, reason: Reason) {self.drops[reason as usize].fetch_add(1, Ordering::Relaxed);}
}

/// A running engine. Its tasks live until the process exits and go on serving the config they have, and `shutdown` takes back what an l3 exit set up on the host. Dropping it does so too, without waiting for the l3 tasks to end.
pub struct Engine {shared: Arc<Shared>, store: Arc<Store>, host: Arc<tokio::sync::Mutex<Host>>, l3: Arc<Mutex<Option<host::Wired>>>}

impl Drop for Engine {
	fn drop(&mut self) {self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();}
}

impl Engine {
	/// Stops the l3 exit and removes its interface, routes and firewall rules from the host. Everything else the engine holds goes with the process.
	pub async fn shutdown(self) {
		let wired = self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();
		if let Some(wired) = wired {wired.running.close().await}
	}

	/// Puts a new config document in force: it is parsed and validated, everything it needs from the host is prepared while the running config keeps working, and then it replaces that config in one step.
	/// With `base`, the reload is refused unless that is the revision that runs. Any error leaves the running config whole. An error of the prepare step names tags and field paths and never a value from the document.
	pub async fn reload(&self, document: Vec<u8>, base: Option<Revision>) -> Result<Applied, ApplyError<anyhow::Error>> {
		let (shared, store, host) = (self.shared.clone(), self.store.clone(), self.host.clone());
		// On a task of its own: whoever asked may stop waiting, and a reload that is dropped halfway would leave the host between two configs.
		tokio::spawn(async move {store.apply(document, base, async |snapshot: &Snapshot, diff: &Diff| apply(&shared, &host, snapshot, diff).await).await}).await.unwrap_or_else(|_| Err(ApplyError::Prepare(anyhow::anyhow!("the reload did not run to its end"))))
	}

	/// What `SIGHUP` does: reads the config file again and puts it in force like `reload`. A file whose bytes already run still has its certificates read again.
	/// A file that cannot be read or does not validate is logged once, with the paths of the fields that are wrong.
	pub async fn reload_from(&self, path: &Path) -> Result<Applied, ApplyError<anyhow::Error>> {
		let (shared, store, host, path) = (self.shared.clone(), self.store.clone(), self.host.clone(), path.to_path_buf());
		tokio::spawn(async move {store.reload_from(&path, async |snapshot: &Snapshot, diff: &Diff| apply(&shared, &host, snapshot, diff).await).await}).await.unwrap_or_else(|_| Err(ApplyError::Prepare(anyhow::anyhow!("the reload did not run to its end"))))
	}

	/// The config that runs, with its revision.
	pub fn snapshot(&self) -> Snapshot {self.store.current()}

	pub fn plan(&self) -> Arc<Plan> {self.shared.plan()}

	pub fn user(&self, name: &str) -> Option<Totals> {self.plan().users.iter().find(|user| user.name == name).map(|user| user.state.traffic.totals())}

	pub fn inbound(&self, tag: &str) -> Option<Totals> {self.plan().inbounds.iter().find(|inbound| inbound.tag == tag).map(|inbound| inbound.traffic.totals())}

	pub fn exit(&self, tag: &str) -> Option<Totals> {self.plan().exits.iter().find(|exit| exit.tag == tag).map(|exit| exit.traffic.totals())}

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
	let shared = Arc::new(Shared {plan: RwLock::default(), flows: Flows::default(), drops: Default::default(), resolver: Resolver::default(), pings: Mutex::default(), relays: Arc::default(), is_local: options.is_local, now: options.now});
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
				tick.tick().await;
				ticks = ticks.wrapping_add(1);
				if ticks % SWEEP_EVERY == 0 {shared.flows.sweep()}
				// Held against the clock again at every tick, never slept towards, so a clock that jumps ahead cuts a user off as promptly as time that passes.
				if shared.plan().next_expiry.is_some_and(|at| at <= (shared.now)()) {host.lock().await.expire(&shared)}
			}
		}
	});
	Ok(Engine {shared, store: Arc::new(store), host, l3})
}
