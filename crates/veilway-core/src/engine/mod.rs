//! The engine: one WireGuard tunnel per inbound, every decrypted packet checked and routed, and TCP and UDP flows re-dialled by a userspace stack through the outbound of the exit they were routed to.
//! Only an `l3` exit uses a TUN device and kernel routing, and only for the flows that were routed to it.
pub mod certificate;
mod chain;
pub mod control;
pub mod dns;
pub mod faketls;
mod flows;
pub mod gate;
mod host;
pub mod icmp;
mod inbound;
pub mod l3;
pub mod limits;
pub mod link;
pub mod netstack;
pub mod obfs;
pub mod plan;
pub mod probe;
pub mod proxy;
pub mod proxy_http;
pub mod proxy_socks;
pub mod replay;
pub mod resolver;
pub mod route;
pub mod stream;
pub mod tunnel;
pub mod upstream;
pub mod upstream_state;
pub mod usage;
pub mod xray;
pub mod xray_out;
mod xray_owner;
mod xray_udp;
#[cfg(unix)]
mod xray_trojan;
#[cfg(target_os = "linux")]
pub mod xray_host;

pub use control::ControlTotals;
pub use faketls::FakeTlsTotals;
pub use obfs::ObfsTotals;
pub use stream::StreamTotals;
pub use proxy::Totals as ProxyTotals;
pub use tunnel::Totals as TunnelTotals;
pub use plan::{Denied, Plan};
pub use replay::{ReplayStatus, Reset};
pub use route::Reason;

use crate::config::{Applied, ApplyError, Config, Diff, Revision, RuleTransport, Snapshot, Store};
use host::Host;
use rustls::RootCertStore;
use resolver::{Names, Resolver};
use route::Flows;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};
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
	/// The proxy of an exit stopped letting the node in (`working` false), or lets it in again. Devices without a selection leave through another exit meanwhile.
	ExitWorkingChanged {exit: String, working: bool},
	/// The operator started a user's quota count over, see `Engine::reset_usage`. With `totals` what the user sent and received in all went back to zero as well.
	/// A user who was out of quota is let in by it, which is a `UserRestored` right behind this.
	UsageReset {user: String, totals: bool},
}

/// How a device's last authenticated datagram reached its inbound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Over {
	Udp,
	/// The `ws` of a `wireguard` inbound, which relays WireGuard datagrams as they are.
	Ws,
	UdpObfs,
	Tls,
	/// The native `ws` of a `veilway` inbound, behind the operator's web server.
	WsNative,
	/// The `ws-plain` transport of a `veilway` inbound: the native `ws` session over plain HTTP, with its token in a cookie.
	WsPlain,
	Fronted,
	/// The `fronted-shaped` transport of a `veilway` inbound.
	FrontedShaped,
	/// The borrowed-site `faketls` transport of a `veilway` inbound.
	FakeTls,
}

impl Over {
	/// The name a routing rule's `transport` condition gives it. A `ws` of either kind is `ws`.
	pub fn rule(self) -> RuleTransport {
		match self {
			Over::Udp => RuleTransport::Udp,
			Over::Ws | Over::WsNative => RuleTransport::Ws,
			Over::UdpObfs => RuleTransport::UdpObfs,
			Over::Tls => RuleTransport::Tls,
			Over::WsPlain => RuleTransport::WsPlain,
			Over::Fronted => RuleTransport::Fronted,
			Over::FrontedShaped => RuleTransport::FrontedShaped,
			Over::FakeTls => RuleTransport::Faketls,
		}
	}
}

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
	/// The exit the device chose on the control channel for the action `"user"`. None for a device that chose none, which leaves through its user's exit.
	pub exit: Option<String>,
	/// The authenticated control connections the device has open, through all its inbounds together.
	pub control: usize,
	/// The MTU the device set on the control channel. None for a device that set none, whose tunnel has the `mtu` of its inbound.
	pub mtu: Option<u16>,
}

/// One node link as `Engine::links` gives it.
#[derive(Clone, Debug)]
pub struct LinkReport {
	pub tag: String,
	pub id: [u8; 16],
	/// Whether this node is the entry half, and whether it is the node the link connects to.
	pub entry: bool,
	pub listener: bool,
	pub status: link::Status,
	/// How long the link has been in that state.
	pub since: Duration,
	/// How long ago its tunnel last completed a handshake. None without a session.
	pub handshake: Option<Duration>,
	/// On the node that dials: the kind of transport it is at, and the places of that transport and its candidate or endpoint in the other node's list.
	pub transport: Option<(&'static str, usize, usize)>,
	pub flows: usize,
	/// Inner packets: up is what this node sent into the link, down what it took out.
	pub traffic: Totals,
	pub dropped: u64,
	pub flips: u64,
	pub warning: bool,
	/// On the exit half: a link this node cut off for its quota or its expiry.
	pub denied: Option<Denied>,
	/// On the entry half: the `chain` exit the link is behind.
	pub exit: Option<String>,
}

/// What the engine knows of the upstream of one exit, as `Engine::exit_health` gives it.
#[derive(Clone, Debug)]
pub struct ExitHealth {
	pub exit: String,
	/// How long ago the upstream last refused to relay UDP. The mark is tried again after a minute and goes when the upstream relays UDP again. None for an upstream that has refused nothing, which every exit without a SOCKS5 proxy is.
	pub no_udp: Option<Duration>,
	pub udp_flips: u64,
	/// For an exit with an l3 backend: how long its interface has been down, None inside while it is up. None for every other exit.
	pub interface_down: Option<Option<Duration>>,
	/// How often the interface of an l3 exit switched between up and down.
	pub interface_flips: u64,
	/// For an exit through a SOCKS5 proxy: how long the proxy has not let the node in. None while it does, and for every other exit.
	pub proxy_down: Option<Duration>,
	/// How often such an exit switched between working and not.
	pub proxy_flips: u64,
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
	/// The replay file, which carries the replay memory of the obfuscated transports across restarts, see `replay`. It is not relative to `dir`. A config with an obfuscated transport is not started, and not reloaded into, without one that the node can write.
	pub replay: Option<PathBuf>,
	/// The range, in milliseconds, the control channel draws the shortest time between two `usage` pushes of one connection from. It is `veilway_proto::control::USAGE_PUSH`, 30 to 90 s, and tests replace it so as not to wait that long.
	pub usage_push: RangeInclusive<u32>,
	/// The certificates the TLS of a node link this node dials must lead to. None is the Mozilla root list, and tests give the root of the certificates they make.
	pub roots: Option<Arc<RootCertStore>>,
	/// The folder the Xray add-on is installed in, see `xray`. Without one a config with an `xray` section keeps the node running and Xray not started.
	pub addons: Option<PathBuf>,
	/// The unix socket of the Xray host, which starts Xray as a user of its own, see `xray`. Without one a config with an `xray` section keeps the node running and Xray not started.
	pub xray_socket: Option<PathBuf>,
	/// The folder the node and Xray share the sockets of the Xray outbounds in, which a group of Xray's user lets the node enter. Defaults to `/run/veilway-xray-out`.
	pub xray_dir: Option<PathBuf>,
	/// How long the probes of the site of a `faketls` transport wait at each step. Tests replace it so as not to wait that long.
	pub probes: veilway_transport::probe::Patience,
	/// The state file of the upstreams, which keeps the signed document of each with its keys, see `upstream_state`. It is not relative to `dir`. A config with an enabled upstream is not started, and not reloaded into, without one that the node can write.
	pub upstreams: Option<PathBuf>,
	/// What a test puts in place of the node's own network for the upstreams.
	pub upstream: upstream::Hooks,
}

impl Options {
	pub fn new(dir: impl Into<PathBuf>) -> Options {Options {dir: dir.into(), is_local: gate::is_local, now: OffsetDateTime::now_utc, revision: None, allow_readable: false, state: None, replay: None, usage_push: veilway_proto::control::USAGE_PUSH, roots: None, addons: None, xray_socket: None, xray_dir: None, probes: Default::default(), upstreams: None, upstream: Default::default()}}
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
	/// Since when the proxy of a `socks5` exit has not let the node in. Meanwhile the exit is not working, and devices without a selection leave through another exit. It goes when the proxy lets the node in again, which a check every `flows::DOWN_RETRY` tries.
	down: Mutex<Option<Instant>>,
	/// Connections in a row the proxy did not let in, and when the first of them was.
	failing: Mutex<(u32, Option<Instant>)>,
	/// Switches between working and not working, in either direction.
	down_flips: AtomicU64,
}

impl ExitState {
	/// False while the proxy of a `socks5` exit does not let the node in.
	pub fn working(&self) -> bool {self.down.lock().unwrap_or_else(|e| e.into_inner()).is_none()}
}

/// One user's counters as `Engine::counters` gives them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
	pub name: String,
	/// Everything the user sent and received since the state file first knew the name, or since start without a state file.
	pub traffic: Totals,
	/// Bytes in both directions since `period_start`, which is what `quota_bytes` is held against.
	pub used_bytes: u64,
	/// When the count last started over, in Unix seconds. 0 for a user who never had a `quota_period`, or who had none when their usage was last reset.
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
	/// The start of the quota period `used` belongs to, in Unix seconds. It moves back in two cases only: when it lies more than one whole period after the node's clock (or after it at all, for a user without a `quota_period`), see `roll`, and when the operator resets the user's usage.
	since: AtomicI64,
	/// What the user resolved through the node. Nothing in it is ever read for another user.
	names: Mutex<Names>,
	/// The queries of the user that may still wait for an upstream at once.
	in_flight: Semaphore,
	/// Bytes of the control channel's own inner packets, which are in `traffic` and in `used` like any others. They are counted once more here so that the channel can tell what the user carried from what it sent itself.
	control: AtomicU64,
}

impl Default for UserState {
	fn default() -> UserState {UserState {traffic: Traffic::default(), used: AtomicU64::new(0), since: AtomicI64::new(0), names: Mutex::default(), in_flight: Semaphore::new(resolver::MAX_IN_FLIGHT), control: AtomicU64::new(0)}}
}

impl UserState {
	pub fn names(&self) -> MutexGuard<'_, Names> {self.names.lock().unwrap_or_else(|e| e.into_inner())}

	pub fn used(&self) -> u64 {self.used.load(Ordering::Relaxed)}

	/// Holds the count of the user called `name` against the clock, which stands at `now`. `period` is the start of the quota period the clock is in and the longest such a period lasts, see `usage::SPANS`, None for a user without a `quota_period`. All of it is in Unix seconds.
	/// A period that began more than one whole period after `now` is one no clock of this node can have started and then stepped back from by less than a period: a state file said so, or the clock was wrong by more than a period. It is not trusted, and a count that waited for it to end would wait for as long as the clock was wrong by.
	/// So the count is given the period the clock is in and keeps what it holds, which is said once, in a warning. The price is a clock that steps back by more than a period and comes forward again: the count then starts over with the period it comes forward into.
	/// A period that began after `now` by one period or less is left as it is. It ends within one period at the latest, and so a clock that steps back by less than a period and comes forward again starts no count over and gives nobody their quota again.
	/// Without a `quota_period` nothing ever starts over, so there is no such price: any start after `now` goes to 0.
	/// Otherwise the count starts over when the start of the period the clock is in lies after the period it belongs to. Whoever sees the new period first does it, once.
	pub fn roll(&self, name: &str, period: Option<(i64, i64)>, now: i64) {
		let since = self.since.load(Ordering::Relaxed);
		if since > period.map_or(now, |(_, span)| now.saturating_add(span)) {
			let start = period.map_or(0, |(start, _)| start);
			if self.since.compare_exchange(since, start, Ordering::Relaxed, Ordering::Relaxed).is_ok() {tracing::warn!("user {name}: their quota period was said to have begun at {since}, which is {}s after the node's clock{}, so it is not trusted: the period is the one the clock is in, from {start}, and the {} bytes counted so far stay counted", since.saturating_sub(now), if period.is_some() {" and more than one whole period"} else {""}, self.used())}
		} else if let Some((start, _)) = period {
			if self.since.fetch_max(start, Ordering::Relaxed) < start {self.used.store(0, Ordering::Relaxed)}
		}
	}
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
	control: control::Channel,
	/// What the `udp-obfs` listeners share.
	obfs: obfs::State,
	/// The limits per device and per source, which every native transport is held to together.
	limits: limits::State,
	/// What the stream listeners share.
	stream: stream::State,
	/// What the `faketls` listeners share.
	faketls: faketls::State,
	/// The replay memory, from the first config with an obfuscated transport on. It belongs to the process: no reload empties it or gives it back.
	replay: OnceLock<Arc<replay::Guard>>,
	/// Where the replay file is. None for a node that was given no path, which starts no obfuscated transport.
	replay_path: Option<PathBuf>,
	/// The translations of the `chain` exits, see `chain`.
	nat: chain::Nat,
	/// What the TLS of a node link this node dials is validated against.
	roots: Arc<RootCertStore>,
	/// Held once more by every dialler task of a node link while it runs, so that its count says how many still dial: a link a reload removed must stop within a second.
	dialling: Arc<()>,
	/// The self-signed certificates the node made for the `tls` listeners of the config in force, by listen address.
	certificates: Mutex<Vec<certificate::Made>>,
	/// The tunnels that run, in the order of the config, with what each counts.
	tunnels: Mutex<Vec<(String, Arc<tunnel::State>)>>,
	/// The connections each user holds through the hop of Xray and every proxy inbound together, and the UDP they relay: one count for all of those doors, so that a user's cap is the user's and not each door's.
	open: Arc<xray::Open>,
	udp: Arc<xray_udp::Limits>,
	/// The proxy inbounds that run, in the order of the config, with what each counts.
	proxies: Mutex<Vec<(String, Arc<proxy::State>)>>,
	/// The subscriptions of other providers the operator was shown, which wait for the config that names them, see `upstream`.
	previews: upstream::Previews,
}

impl Shared {
	/// What an engine shares before any of its tasks run. `plan` is the plan before the first one, which holds what the state file remembered, `state` the state file when the node may write one, and `replay` where the replay file is.
	fn new(plan: Plan, is_local: fn(IpAddr) -> bool, now: fn() -> OffsetDateTime, state: Option<PathBuf>, replay: Option<PathBuf>, usage_push: RangeInclusive<u32>, roots: Arc<RootCertStore>) -> Shared {
		Shared {plan: RwLock::new(Arc::new(plan)), flows: Flows::default(), drops: Default::default(), resolver: Resolver::default(), pings: Mutex::default(), relays: Arc::default(), is_local, now, over: Notify::new(), save: Notify::new(), saver: tokio::sync::Mutex::new(usage::Saver {path: state, written: Vec::new(), failing: None, left_out: 0}), unwritten: AtomicU64::new(0), events: broadcast::Sender::new(MAX_EVENTS), control: control::Channel::new(usage_push), obfs: obfs::State::default(), limits: limits::State::default(), stream: stream::State::default(), faketls: faketls::State::default(), replay: OnceLock::new(), replay_path: replay, nat: chain::Nat::default(), roots, dialling: Arc::default(), certificates: Mutex::default(), tunnels: Mutex::default(), proxies: Mutex::default(), open: Arc::default(), udp: Arc::new(xray_udp::Limits::new(xray_udp::MAX_ASSOCIATIONS_PER_USER, xray_udp::MAX_ASSOCIATIONS, xray_udp::MAX_FLOWS, xray_udp::MAX_FLOWS_PER_USER)), previews: upstream::Previews::new(upstream::Hooks::default())}
	}

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
pub struct Engine {shared: Arc<Shared>, store: Arc<Store>, host: Arc<tokio::sync::Mutex<Host>>, l3: Arc<Mutex<Option<host::Wired>>>, started: Instant, written: Arc<Mutex<u64>>, addons: Option<PathBuf>, xray: (Arc<tokio::sync::Notify>, tokio::task::JoinHandle<()>)}

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

// The replay memory of an engine that is dropped without `shutdown` is left as a kill leaves it: nothing more is accepted or written, and the lock of the file is given back.
impl Drop for Engine {
	fn drop(&mut self) {
		self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();
		self.xray.1.abort();
		if let Some(replay) = self.shared.replay.get() {replay.abandon()}
	}
}

impl Engine {
	/// Stops the l3 exit and removes its interface, routes and firewall rules from the host, then writes the state file one last time. Everything else the engine holds goes with the process.
	/// The host comes first and the write is given `usage::LAST_WRITE` and no longer: a disk that hangs must not leave the firewall rules of a node that is going away in place.
	/// Before any of that every open control connection is told to say `bye`, on a best effort: the byes are given `control::BYE_WAIT` to leave and no longer.
	pub async fn shutdown(mut self) {
		// Xray goes first: it is killed and awaited before anything else is let go, so it never serves a user the node has stopped counting.
		self.xray.0.notify_one();
		let _ = tokio::time::timeout(Duration::from_secs(10), &mut self.xray.1).await;
		self.host.lock().await.stop_upstreams();
		if self.shared.dismiss() > 0 {tokio::time::sleep(control::BYE_WAIT).await}
		let wired = self.l3.lock().unwrap_or_else(|e| e.into_inner()).take();
		if let Some(wired) = wired {wired.running.close().await}
		// A clean stop of the replay memory: no proof is taken from here on, and its cache goes to the replay file. It waits no longer than `replay::LAST_WRITE` itself, next to the state file's last write and not after it.
		let replay = async {
			if let Some(replay) = self.shared.replay.get() {replay.stop().await}
		};
		if tokio::join!(tokio::time::timeout(usage::LAST_WRITE, usage::save(&self.shared, true)), replay).0.is_err() {tracing::error!("the state file was not written within {}s of the shutdown, so usage since its last write is lost", usage::LAST_WRITE.as_secs())}
	}

	/// The first step of `shutdown` as something to call from any thread, without the runtime and without the engine: it takes back at once what the l3 exit set up on the host, and does nothing when a `shutdown` has done so or is doing so.
	/// It is for a stop that has run out of time. Whoever holds it does not keep the engine alive.
	pub fn restorer(&self) -> impl Fn() + Clone + Send + 'static {
		let l3 = self.l3.clone();
		move || drop(l3.lock().unwrap_or_else(|e| e.into_inner()).take())
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

	/// Whether the Xray add-on's executable is in the add-on folder. Whether it is the pinned one is checked when it is started.
	pub fn xray_installed(&self) -> bool {self.addons.as_deref().is_some_and(|addons| xray::binary(addons).is_file())}

	/// Why the Xray outbound `tag` cannot carry a flow right now: the add-on is not installed or not running, Xray ended, or its server's name does not resolve to an address the node may dial. None when it carries.
	pub fn xray_outbound_down(&self, tag: &str) -> Option<String> {self.plan().hops.get(tag).reason()}

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
					(handshake, peer.filter(|_| handshake.is_some()).and_then(|peer| peers.over(peer)))
				}).collect()
			};
			out.extend(asked.iter().zip(seen).map(|(at, (handshake, over))| {
				let device = &plan.devices[*at];
				Peer {user: plan.users[device.user].name.clone(), device: device.name.clone(), public_key: device.public_key, inbound: inbound.tag.clone(), handshake, over, flows: flows.as_ref().map_or_else(|| self.shared.flows.of_device(&device.public_key), |flows| flows.get(&device.public_key).copied().unwrap_or(0)), exit: plan.chosen(*at, device.control.selected().as_deref()).map(|exit| plan.exits[exit].tag.clone()), control: device.control.open(), mtu: device.control.mtu()}
			}));
		}
		out
	}

	/// What the engine has learnt about the upstream of each exit, in the order of the config.
	pub fn exit_health(&self) -> Vec<ExitHealth> {
		let plan = self.plan();
		plan.exits.iter().enumerate().map(|(at, exit)| {
			let health = plan.l3.as_ref().filter(|(wired, _)| *wired == at).map(|(_, port)| &port.health);
			ExitHealth {exit: exit.tag.clone(), no_udp: exit.state.no_udp.lock().unwrap_or_else(|e| e.into_inner()).map(|since| since.elapsed()), udp_flips: exit.state.udp_flips.load(Ordering::Relaxed), interface_down: health.map(|health| health.down.lock().unwrap_or_else(|e| e.into_inner()).map(|since| since.elapsed())), interface_flips: health.map_or(0, |health| health.flips.load(Ordering::Relaxed)), proxy_down: exit.state.down.lock().unwrap_or_else(|e| e.into_inner()).map(|since| since.elapsed()), proxy_flips: exit.state.down_flips.load(Ordering::Relaxed)}
		}).collect()
	}

	/// The last measured proxy latency of each SOCKS5 outbound that has one, by tag, and when it was measured.
	pub fn latencies(&self) -> HashMap<String, (Duration, SystemTime)> {self.plan().latency.iter().filter_map(|(tag, latency)| latency.get().map(|measured| (tag.clone(), measured))).collect()}

	pub fn plan(&self) -> Arc<Plan> {self.shared.plan()}

	pub fn user(&self, name: &str) -> Option<Totals> {
		let plan = self.plan();
		plan.users.iter().take(plan.people).find(|user| user.name == name).map(|user| user.state.traffic.totals())
	}

	pub fn inbound(&self, tag: &str) -> Option<Totals> {self.plan().inbounds.iter().find(|inbound| inbound.tag == tag).map(|inbound| inbound.traffic.totals())}

	pub fn exit(&self, tag: &str) -> Option<Totals> {self.plan().exits.iter().find(|exit| exit.tag == tag).map(|exit| exit.traffic.totals())}

	/// The counters of every user, inbound and exit of the config that runs, taken from one plan. A counter belongs to a name or a tag and goes on counting across reloads for as long as the config keeps that name or tag.
	/// An exit counts what is handed to it and what is taken from it, as inner IP packets: a TCP segment when the exit's stack takes it or gives it, a datagram when the exit's outbound takes it or gives it,
	/// a packet when the queue of the l3 interface takes it or the interface gives it to a live flow, a ping the node answers or sends on, and a DNS message of the node's resolver, which has no headers of a device around it.
	/// What is refused or dropped before that counts for no exit, and a flow that a `via` policy moved counts for the exit that carries it and not for the exit the rules chose.
	pub fn counters(&self) -> Counters {
		let plan = self.plan();
		Counters {
			users: plan.users.iter().take(plan.people).map(Usage::of).collect(),
			// A proxy inbound counts bytes only: what its clients sent to their destinations and got back. Its connections and refusals are in `Engine::proxies`.
			inbounds: plan.inbounds.iter().take(plan.listening).map(|inbound| (inbound.tag.clone(), inbound.traffic.totals())).chain(self.shared.proxies.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(tag, state)| (tag.clone(), Totals {up_bytes: state.totals().up_bytes, down_bytes: state.totals().down_bytes, ..Totals::default()}))).collect(),
			exits: plan.exits.iter().map(|exit| (exit.tag.clone(), exit.traffic.totals())).collect(),
		}
	}

	/// The counters of one user of the config that runs, as `counters` has them, without those of anybody else.
	pub fn usage(&self, name: &str) -> Option<Usage> {
		let plan = self.plan();
		plan.users.iter().take(plan.people).find(|user| user.name == name).map(Usage::of)
	}

	/// The dialler tasks of node links that still run, those of links that a reload removed included until they have stopped.
	pub fn diallers(&self) -> usize {Arc::strong_count(&self.shared.dialling) - 1}

	/// Every enabled node link of the config that runs, in its order, with its state and its numbers. No key and no secret.
	pub fn links(&self) -> Vec<LinkReport> {
		let plan = self.plan();
		plan.links.iter().enumerate().filter(|(_, link)| matches!(link.carrier, plan::Carrier::Paired)).map(|(at, link)| {
			let (status, since) = link.state.status();
			LinkReport {
				tag: link.tag.clone(), id: link.id, entry: link.entry, listener: link.listener, status, since, handshake: plan.handshake(at),
				transport: link.dialled.as_ref().zip(link.state.at()).map(|(dialled, (transport, candidate))| (match dialled.transports.get(transport) {
					Some(veilway_proto::subscription::payload::Transport::Udp(_)) => "udp",
					Some(veilway_proto::subscription::payload::Transport::UdpObfs(_)) => "udp-obfs",
					Some(veilway_proto::subscription::payload::Transport::Tls(_)) => "tls",
					_ => "ws",
				}, transport, candidate)),
				flows: link::flows(&self.shared, &plan, at), traffic: link.state.traffic.totals(), dropped: link.state.dropped.load(Ordering::Relaxed), flips: link.state.flips.load(Ordering::Relaxed), warning: link.state.warning(), denied: link.denied, exit: link.exit.map(|exit| plan.exits[exit].tag.clone()),
			}
		}).collect()
	}

	/// Every enabled upstream of the config that runs, in its order, with its state, its reason when it is not up and its numbers. No key, no secret and no link.
	pub fn upstreams(&self) -> Vec<upstream::Report> {self.plan().upstreams().iter().map(|state| state.report()).collect()}

	/// Asks the tunnel of the upstream `tag` to connect now, as the user's "connect again" does for a client: false when the config that runs has no such upstream.
	pub fn upstream_again(&self, tag: &str) -> bool {self.plan().upstreams().iter().find(|state| state.tag == tag).map(|state| state.again()).is_some()}

	/// Fetches the subscription of another provider with the device the operator made, for the operator to look at before a config names it, see `upstream::preview`. The fetch takes a place at the provider, and runs to its end whether or not whoever asked keeps waiting.
	pub async fn upstream_preview(&self, request: upstream::PreviewRequest) -> Result<upstream::Reviewing, upstream::PreviewError> {
		let (shared, snapshot) = (self.shared.clone(), self.snapshot());
		tokio::spawn(async move {upstream::preview(&shared, &snapshot.config.outbounds, request).await}).await.unwrap_or_else(|_| Err(upstream::PreviewError::Provider("the fetch did not finish".into())))
	}

	/// The operator declines the preview `id`: the provider releases the place. False when no such preview waits.
	pub async fn upstream_decline(&self, id: &str) -> bool {upstream::decline(&self.shared, id).await}

	/// The operator removes the upstream `tag`: the provider is told the device left, for at most ten seconds, and the document is removed from the state file. Whether the provider confirmed. None when the config in force has no such upstream.
	pub async fn upstream_leave(&self, tag: &str) -> Option<bool> {
		let (state, vault, reach, hooks) = self.host.lock().await.release_upstream(tag)?;
		Some(upstream::leave(&self.shared, &state, &vault, reach.as_ref(), &hooks).await)
	}

	/// The operator's yes to a move of the provider's endpoint and to new refresh hosts, see `UpstreamState::confirm`. None when the config in force has no such upstream.
	pub async fn upstream_confirm(&self, tag: &str, moving: bool, hosts: bool) -> Option<io::Result<(bool, bool)>> {
		let state = self.plan().upstreams().into_iter().find(|state| state.tag == tag)?;
		Some(state.confirm(moving, hosts).await)
	}

	/// Starts the quota count of the user called `name` over at the operator's word: `used_bytes` is 0 and `period_start` is the start of the quota period the clock is in, or 0 for a user without a `quota_period`.
	/// What the user sent and received in all is a record of the node and not of the quota, so it stays unless `totals` is set, which zeroes those four counters as well. Nothing else of the user is touched: sessions, flows and DNS memory stay.
	/// A user who was out of quota is let in before this returns, through the same path as a quota period that starts over, with no reload. The state file is written before this returns as well,
	/// for at most `usage::LAST_WRITE`: a write that fails or hangs is counted and logged like any other and tried again at the next one, and the reset is in force all the same.
	/// It is the same call however often it is made. None when the config that runs has no such user, and then nothing was changed.
	pub async fn reset_usage(&self, name: &str, totals: bool) -> Option<Usage> {
		// Held so that no reload puts another plan in force halfway. Nothing between here and the switch waits, so whoever stops waiting for this leaves no reset half done.
		let mut host = self.host.lock().await;
		let plan = self.shared.plan();
		let user = plan.users.iter().take(plan.people).find(|user| user.name == name)?;
		let (state, start) = (&user.state, user.period.map_or(0, |period| usage::starts((self.shared.now)())[period as usize]));
		let used = state.used.swap(0, Ordering::Relaxed);
		state.since.store(start, Ordering::Relaxed);
		if totals {
			for counter in [&state.traffic.up_packets, &state.traffic.up_bytes, &state.traffic.down_packets, &state.traffic.down_bytes] {counter.store(0, Ordering::Relaxed)}
		}
		tracing::info!("user {name}: usage reset: the quota count went from {used} bytes to 0 and its period starts at {start}, the totals of what the user sent and received were {}{}", if totals {"zeroed"} else {"kept"}, if user.denied == Some(Denied::Quota) {", and the user was out of quota and may connect again"} else {""});
		self.shared.publish(Event::UsageReset {user: name.to_string(), totals});
		if user.denied == Some(Denied::Quota) {host.expire(&self.shared)}
		drop(host);
		if tokio::time::timeout(usage::LAST_WRITE, usage::save(&self.shared, false)).await.is_err() {tracing::error!("user {name}: the state file was not written within {}s of the usage reset. The reset is in force and the write is tried again", usage::LAST_WRITE.as_secs())}
		self.usage(name)
	}

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

	/// What the control channel of the `veilway` inbounds did since start.
	pub fn control(&self) -> ControlTotals {self.shared.control.totals()}

	/// Datagrams the node made for a device and no socket took, over every transport of every inbound of the config that runs. A socket of a `veilway` inbound never fragments, so a packet larger than the host's interface carries is counted here and not sent.
	pub fn send_failures(&self) -> u64 {self.plan().inbounds.iter().map(|inbound| inbound.tunnel.unsent.load(Ordering::Relaxed)).sum()}

	/// What the `udp-obfs` transports did since start, and the sessions and tags they hold right now.
	pub fn obfs(&self) -> ObfsTotals {self.shared.obfs.totals(&self.plan())}

	/// What the stream listeners did since start, and the connections and sessions they hold right now.
	pub fn stream(&self) -> StreamTotals {self.shared.stream.totals()}

	/// What the `faketls` listeners did since start, and what they hold right now.
	pub fn faketls(&self) -> FakeTlsTotals {self.shared.faketls.totals()}

	/// What each proxy inbound has counted since it started, in the order of the config. An inbound that a reload changed starts counting over.
	pub fn proxies(&self) -> Vec<(String, ProxyTotals)> {self.shared.proxies.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(tag, state)| (tag.clone(), state.totals())).collect()}

	/// Every tunnel that runs, in the order of the config, with what it counted since it started. A tunnel that a reload changed starts counting over.
	pub fn tunnels(&self) -> Vec<(String, TunnelTotals)> {self.shared.tunnels.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(tag, state)| (tag.clone(), state.totals())).collect()}

	/// The self-signed certificates the node made for its `tls` listeners, each with the pin a profile carries for it.
	pub fn certificates(&self) -> Vec<certificate::Made> {self.shared.certificates.lock().unwrap_or_else(|e| e.into_inner()).clone()}

	/// The replay memory of the obfuscated transports right now. None for a node that never ran one, which keeps no replay memory.
	pub fn replay(&self) -> Option<ReplayStatus> {self.shared.replay.get().map(|replay| replay.status(replay::seconds((self.shared.now)())))}

	/// `veilway replay reset`: empties the replay cache and sets the floor and the limit to the node's clock plus the proof window, written before the next proof is accepted. Nothing else of the node is touched, usage and quotas included.
	/// It costs every client one refusal period of the window, and a proof that was accepted with a timestamp above the new floor can be used once more. None for a node without a replay memory.
	pub async fn reset_replay(&self) -> Option<Reset> {
		let replay = self.shared.replay.get()?.clone();
		Some(replay.reset().await)
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
	let store = Arc::new(store);
	// What the state file remembers goes in as the users of a plan that was never in force. The first plan takes each user's state from it by name, the way every later plan takes it from the one before, and a name the config no longer has is left behind.
	// A path the node may not write to is no path from here on: usage then lives in memory, as it does without a state file.
	let (remembered, chosen, state) = options.state.map_or((Vec::new(), Vec::new(), None), |path| {
		let (users, devices, writable) = usage::load(&path);
		(users, devices, writable.then_some(path))
	});
	let remembered = Plan {states: chosen.into_iter().map(|(device, exit)| (device, (0, Arc::new(control::State::remembered(&exit))))).collect(), users: remembered.into_iter().map(|(name, state)| plan::User {name, groups: Vec::new(), entitled: None, exit: None, dns: None, quota: None, period: None, expires: None, denied: Some(Denied::Disabled), state: Arc::new(state), link: None, flows: route::MAX_FLOWS_PER_USER, proxy: None}).collect(), ..Plan::default()};
	let roots = options.roots.unwrap_or_else(|| Arc::new(RootCertStore {roots: webpki_roots::TLS_SERVER_ROOTS.to_vec()}));
	let mut shared = Shared::new(remembered, options.is_local, options.now, state.clone(), options.replay, options.usage_push, roots);
	shared.previews = upstream::Previews::new(options.upstream.clone());
	let shared = Arc::new(shared);
	shared.faketls.set_patience(options.probes);
	// A start is a reload from nothing: everything the config names is new, and a failure leaves nothing behind. A replay file that was taken before the failure is given back as a kill gives it back.
	let dir = options.dir.clone();
	let mut host = Host::new(options.dir).with_upstreams(options.upstreams, options.upstream);
	let staged = match host.prepare(&shared, &store.current().config, &[]).await {
		Ok(staged) => staged,
		Err(e) => {
			if let Some(replay) = shared.replay.get() {replay.abandon()}
			return Err(e);
		}
	};
	host.commit(&shared, staged);
	tokio::spawn(obfs::tables(shared.clone()));
	let (l3, host) = (host.l3.clone(), Arc::new(tokio::sync::Mutex::new(host)));
	tokio::spawn({
		let (shared, host) = (shared.clone(), host.clone());
		async move {
			let (mut tick, mut ticks) = (tokio::time::interval(EXPIRY_EVERY), 0u32);
			loop {
				tokio::select! {
					_ = tick.tick() => {
						ticks = ticks.wrapping_add(1);
						if ticks % SWEEP_EVERY == 0 {
							shared.flows.sweep();
							shared.tend();
							let clock = limits::Clock::of((shared.now)());
							shared.limits.sweep(clock);
							shared.obfs.sweep(clock);
							shared.stream.sweep();
							shared.nat.sweep(&shared.flows);
							shared.check_links();
							// A reload that holds the host does not hold up this task: the renewal waits for the next sweep.
							if shared.certificates.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|made| made.due((shared.now)().unix_timestamp())) {if let Ok(host) = host.try_lock() {host.renew(&shared)}}
						}
					}
					_ = shared.over.notified() => {}
				}
				// Held against the clock again at every tick, never slept towards, so a clock that jumps ahead cuts a user off as promptly as time that passes.
				let (plan, now) = (shared.plan(), (shared.now)());
				let (starts, clock) = (usage::starts(now), now.unix_timestamp());
				// A count whose period is over starts over here, for the plan in force, which is what brings it below the quota. Every user is looked at, with or without a quota: a period that lies too far after the clock is put right for all of them.
				// A user's count has turned when the quota is spent and the user is not denied for it, or the user is denied for it and the count is below the quota again.
				let turned = plan.users.iter().fold(false, |turned, user| {
					user.state.roll(&user.name, user.period.map(|period| (starts[period as usize], usage::SPANS[period as usize])), clock);
					turned | user.quota.is_some_and(|quota| matches!((user.denied, user.state.used() >= quota), (None, true) | (Some(Denied::Quota), false)))
				});
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
	let stopped = Arc::new(tokio::sync::Notify::new());
	let xray = (stopped.clone(), tokio::spawn(xray::run(shared.clone(), store.clone(), dir, options.xray_socket, options.xray_dir.unwrap_or_else(|| PathBuf::from("/run/veilway-xray-out")), stopped)));
	Ok(Engine {shared, store, host, l3, started: Instant::now(), written: Arc::default(), addons: options.addons, xray})
}
