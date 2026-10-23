//! Another provider's Veilway subscription as the carrier of an exit (upstreams page): the client engine (`veilway-engine`) runs inside the node for one device of the subscription, and a `chain` link behind it is the exit. What the node hands the link goes into the engine's tunnel, and what comes out of the tunnel is handed to `chain_back`, which delivers only what answers a live flow of a device that was routed through the exit and drops the rest. Translation, answers, ICMP, MSS and the refusal of a down carrier are `chain`'s, unchanged.
//! Everything the provider sends is hostile: its document, the transports it lists, its control channel and the packets of its tunnel. A document is accepted only under the signing key the operator confirmed, every dial address of a profile is held to `forbidden` before the engine sees the profile, only a lower MTU is applied, notices are plain text, and the exit is down, and what is routed to it refused as unreachable, whenever anything is wrong. It never falls back to the provider's default exit or to another exit of the node: that is `routing.fallback`'s, and the operator's.
//! Nothing latches. A failed step waits and is tried again, with the wait growing to an hour and no further, a node that cut the device off is asked again at a fixed pace, and each change of state is logged once, at info, with its reason.
//! The document is refreshed in a task of its own, at the document's interval held between an hour and a day. A refresh that changes what the tunnel was made from (the profile's keys, addresses or dial candidates) makes the tunnel again after the same checks as a start, and one that does not leaves it alone. A key rotation is taken only from a document signed by a key that is held, a move of the endpoint and new refresh hosts wait for the operator, and a refusal or a document that ran out takes the exit down and is tried again every hour, and every day after a day. The operator looks at a provider before any config names it (`preview`) and removes one with `leave`.
use super::flows;
use super::gate;
use super::link;
use super::plan::{self, Carrier, Latency, Outbound};
use super::upstream_state::{bind, UpstreamVault};
use super::xray_out::Hops;
use super::{Shared, Totals, QUEUE};
use crate::config::{self, random, Rating, Upstream, UpstreamClass};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::IpNet;
use socket2::{SockAddr, SockRef};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use veilway_engine::import::{self, Fetcher, ImportError, Library, RefreshFailed, Resolve, Reviewed, Trust, Vault};
use veilway_transport::Hook;
use veilway_engine::{Agree, Class, Event, Settings, StartError, State, Status, Store, Tunnel};
use veilway_proto::control::ExitStatus;
use veilway_transport::choice;
use veilway_proto::subscription::client::{Changes, Device, Failure, Held, Offer, Refreshed, Source, Stored};
use veilway_proto::subscription::envelope::SigningKey;
use veilway_proto::subscription::link::Link as SubscriptionLink;
use veilway_proto::subscription::payload::{self, Network, Profile, RatingCap, Transport};
use veilway_proto::subscription::{DeviceSecret, Secret};

/// The longest wait between two tries of a step that failed.
const WAIT_MAX: Duration = Duration::from_secs(3600);
/// The first wait after a step failed.
const WAIT_FIRST: Duration = Duration::from_secs(30);
/// How long a tunnel that the provider stopped or that has nothing to try waits before it is asked to connect again, when it would not by itself: the longest wait a refusal has, so that nothing stays down for ever on the word of a moment.
const ASK_AGAIN: Duration = Duration::from_secs(3600);
/// The lowest MTU a provider's own number is taken at, unless its profile is lower: "never below 1280".
const MTU_FLOOR: u16 = 1280;
/// Notices kept for the status, and the longest one in characters.
const NOTICES: usize = 8;
const NOTICE_CHARS: usize = 200;
/// Exits of the provider kept for the status, and the longest tag in characters.
const OFFERED: usize = 16;
const TAG_CHARS: usize = 64;
/// The longest provider name and host in characters, for the status.
const PROVIDER_CHARS: usize = 80;
const HOST_CHARS: usize = 200;
/// The shortest and the longest time between two refreshes of a subscription that carries, whatever the document asks for.
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);
/// How long a preview of a subscription waits for the config that names it, before the place it took at the provider is given back.
pub const PREVIEW_TTL: Duration = Duration::from_secs(600);
/// The most previews that wait at once.
pub const PREVIEWS_MAX: usize = 4;
/// The longest the provider is given to answer that a device left.
pub const LEAVE_WAIT: Duration = Duration::from_secs(10);

/// How the node reaches a provider when the config names a `via` for the upstream: through the proxy chain of a `socks5` outbound, for the fetch and for the connections of the TCP transports (the datagram transports cannot go through it and are not used), or from the address or interface a `direct` outbound binds its sockets to.
#[derive(Clone, PartialEq)]
pub enum Reach {Direct {bind: Option<IpAddr>, interface: Option<String>}, Socks(Arc<plan::Upstream>)}

/// The outbound `tag` of the config as the node reaches a provider through it. None for a tag that is no `direct`, `socks5` or `xray` outbound, which validation does not let through.
pub fn reach(outbounds: &[config::Outbound], latency: &HashMap<String, Arc<Latency>>, hops: &Hops, tag: &str) -> Option<Reach> {
	match Outbound::of(outbounds, latency, hops, tag)? {
		Outbound::Direct {bind, interface} => Some(Reach::Direct {bind, interface}),
		Outbound::Socks5(up) => Some(Reach::Socks(Arc::new(up))),
	}
}

/// What a test puts in place of the node's own network: the resolver the fetch looks up its endpoint with, how long a node that was cut off waits before it asks again, and where the addresses of a profile really are.
#[derive(Clone, Default)]
pub struct Hooks {
	pub resolve: Option<Resolve>,
	pub retry: Option<Duration>,
	/// How long a subscription waits before it is refreshed again, in place of the document's interval and of the hour and the day a refused or failing one waits.
	pub refresh: Option<Duration>,
	/// How long a preview waits for its config.
	pub preview: Option<Duration>,
	#[cfg(feature = "upstream-tests")]
	pub redirect: Option<veilway_engine::Redirect>,
}

/// What an upstream is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
	/// No document is held yet, and the first one is being fetched.
	Fetching,
	/// A document is held and the tunnel is being made, or is making a session.
	Connecting,
	/// The tunnel carries, and when the config names an exit of the provider that exit is the one in use.
	Up,
	/// Nothing is carried, for the reason given. It is tried again by itself.
	Down,
}

impl Phase {
	/// The name the control API gives the phase.
	pub fn name(self) -> &'static str {
		match self {
			Phase::Fetching => "fetching",
			Phase::Connecting => "connecting",
			Phase::Up => "up",
			Phase::Down => "down",
		}
	}
}

/// What the carrier of one upstream knows, for the status. Nothing in it is a key, a secret, a token or a link.
#[derive(Clone, Debug)]
pub struct Report {
	pub tag: String,
	pub id: [u8; 16],
	pub phase: Phase,
	/// Plain words for why the phase is what it is. Empty while it is up.
	pub reason: String,
	/// How long the phase has lasted.
	pub since: Duration,
	/// The profile in use, and the transport it is connected over.
	pub profile: Option<String>,
	pub transport: Option<&'static str>,
	/// The exit of the provider in use, once the provider says which.
	pub exit: Option<String>,
	/// The exits the provider offers, as it names them.
	pub offered: Vec<String>,
	pub notices: Vec<String>,
	/// What the provider says the device has used and has: bytes used, bytes allowed (0 for no limit).
	pub usage: Option<(u64, u64)>,
	/// The largest packet the carrier takes now. 0 until a profile is in use.
	pub mtu: u16,
	/// Packets handed to the tunnel and packets it had no room or no session for, and flows refused because the carrier was down.
	pub sent: u64,
	pub unsent: u64,
	pub refused: u64,
	pub traffic: Totals,
	/// Packets out of the tunnel that answered no live flow of a device, and were dropped.
	pub dropped: u64,
	/// Changes between up and not up, and starts of the tunnel over again.
	pub flips: u64,
	pub starts: u64,
	/// The provider's name for itself, as its document says, cleaned of control and direction characters.
	pub provider: Option<String>,
	/// The fingerprint of the signing key the document in force is signed under. After a rotation it is the new one, which the config's `signing_key` and link do not name.
	pub signing_key: Option<String>,
	/// When the document held stops being current, and when it was last refreshed, in Unix seconds.
	pub expires_at: Option<u64>,
	pub refreshed_at: Option<u64>,
	/// Why the last refresh failed. None once one has gone through.
	pub refresh_error: Option<String>,
	/// A move of the subscription's endpoint, and refresh hosts, that the provider announced and the operator has not confirmed. The old endpoint and hosts are used meanwhile.
	pub pending_move: Option<String>,
	pub pending_hosts: Vec<String>,
	/// Refreshes that went through and refreshes that failed.
	pub refreshes: u64,
	pub refresh_failures: u64,
}

struct Live {
	phase: Phase,
	reason: String,
	since: Instant,
	up: Option<Instant>,
	profile: Option<String>,
	transport: Option<&'static str>,
	exit: Option<String>,
	offered: Vec<String>,
	notices: Vec<String>,
	usage: Option<(u64, u64)>,
	warned: bool,
	/// What the proxy chain of `via` last said of a dial: None while it carries, else the cause.
	chain: Option<String>,
	provider: Option<String>,
	signing_key: Option<String>,
	expires: Option<u64>,
	/// When a refresh was last tried, whatever it came to. It is kept here and not by the task, so that a provider that ends the tunnel often cannot keep the refresh from ever being due.
	attempted: Instant,
	/// What the document says the account has used and has, which is what the status shows until the provider's control channel says more.
	document_usage: Option<(u64, u64)>,
	refreshed: Option<u64>,
	/// Why the last refresh failed, kept to log a change of it once.
	failing: Option<String>,
	/// The reason of a signed refusal that has not been lifted by a refresh: the exit stays down and the tunnel is not made.
	refusal: Option<String>,
	/// Set when no profile of the document in force could be started: a refresh is tried before the next start, since a newer document may be what makes one usable.
	unusable: bool,
	moving: Option<String>,
	hosts: Vec<String>,
}

/// What the node keeps of one upstream while it runs. It belongs to the upstream's tag, link and device, and a reload that keeps all three keeps it, with the tunnel it carries.
pub struct UpstreamState {
	pub tag: String,
	/// The id of the link the upstream is: 16 random bytes, kept in the state file with the document.
	pub id: [u8; 16],
	bound: [u8; 32],
	/// The counters every link has, which `chain` counts into.
	pub link: Arc<link::State>,
	mtu: AtomicU16,
	/// The device addresses of the profile in use, which are the entry's addresses in the link, and the gateways of that profile.
	addresses: RwLock<Arc<[IpAddr]>>,
	gateways: RwLock<Arc<[IpAddr]>>,
	out: mpsc::Sender<Vec<u8>>,
	inbox: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
	/// Woken by `again`: the operator asks the tunnel to connect now.
	wake: tokio::sync::Notify,
	/// Woken when the operator confirms a move: the subscription is refreshed now, which tries the confirmed endpoint first.
	refresh: tokio::sync::Notify,
	/// The subscription this upstream holds, shared by the task that runs it and by the operator's answers. Open once the task has first looked at the state file.
	library: tokio::sync::Mutex<Option<Library>>,
	live: Mutex<Live>,
	sent: AtomicU64,
	unsent: AtomicU64,
	refused: AtomicU64,
	flips: AtomicU64,
	starts: AtomicU64,
	refreshes: AtomicU64,
	refresh_failures: AtomicU64,
}

impl UpstreamState {
	/// A state for the upstream `tag`, whose link and device are bound by `bound` (see `UpstreamVault::bound`).
	pub fn new(tag: &str, id: [u8; 16], bound: [u8; 32]) -> Arc<UpstreamState> {
		let (out, inbox) = mpsc::channel(QUEUE);
		let live = Live {phase: Phase::Fetching, reason: String::new(), since: Instant::now(), up: None, profile: None, transport: None, exit: None, offered: Vec::new(), notices: Vec::new(), usage: None, warned: false, chain: None, provider: None, signing_key: None, expires: None, attempted: Instant::now(), document_usage: None, refreshed: None, failing: None, refusal: None, unusable: false, moving: None, hosts: Vec::new()};
		Arc::new(UpstreamState {tag: tag.to_owned(), id, bound, link: Arc::default(), mtu: AtomicU16::new(u16::MAX), addresses: RwLock::new(Arc::from(Vec::new())), gateways: RwLock::new(Arc::from(Vec::new())), out, inbox: tokio::sync::Mutex::new(inbox), wake: tokio::sync::Notify::new(), refresh: tokio::sync::Notify::new(), library: tokio::sync::Mutex::new(None), live: Mutex::new(live), sent: AtomicU64::new(0), unsent: AtomicU64::new(0), refused: AtomicU64::new(0), flips: AtomicU64::new(0), starts: AtomicU64::new(0), refreshes: AtomicU64::new(0), refresh_failures: AtomicU64::new(0)})
	}

	/// The hash of the link and the device the state was made for.
	pub fn bound(&self) -> [u8; 32] {self.bound}

	fn live(&self) -> std::sync::MutexGuard<'_, Live> {self.live.lock().unwrap_or_else(|e| e.into_inner())}

	/// Whether the carrier takes packets: the tunnel is connected and the exit of the provider is the one the config names.
	pub fn up(&self) -> bool {self.live().up.is_some()}

	/// How long the carrier has been up, None while it is not.
	pub fn carrying(&self) -> Option<Duration> {self.live().up.map(|since| since.elapsed())}

	/// The largest packet the carrier takes: the profile's MTU, lowered by what the engine found, and never raised.
	pub fn mtu(&self) -> u16 {self.mtu.load(Ordering::Relaxed)}

	/// The entry's addresses in the link: the device addresses of the profile in use, none before one is.
	pub fn addresses(&self) -> Arc<[IpAddr]> {self.addresses.read().unwrap_or_else(|e| e.into_inner()).clone()}

	/// The gateways of the profile in use, where the engine's control channel and probes go.
	pub fn gateways(&self) -> Arc<[IpAddr]> {self.gateways.read().unwrap_or_else(|e| e.into_inner()).clone()}

	/// Hands a packet to the task that owns the tunnel. False when its queue is full.
	pub fn send(&self, packet: &[u8]) -> bool {
		let queued = self.out.try_send(packet.to_vec()).is_ok();
		if !queued {self.unsent.fetch_add(1, Ordering::Relaxed);}
		queued
	}

	/// Asks the tunnel to connect again now: every mark, count and wait of the engine starts over. The operator's "try again"; nothing else asks it before the pace of `ASK_AGAIN`.
	pub fn again(&self) {self.wake.notify_one()}

	/// What the proxy chain of `via` did on its last dial: `None` when it carried the connection, else the cause. Logged at info when it changes.
	fn carried(&self, cause: Option<String>) {
		let mut live = self.live();
		if live.chain == cause {return}
		match &cause {
			Some(cause) => tracing::info!("upstream {}: the chain does not carry the connection: {cause}", self.tag),
			None => tracing::info!("upstream {}: the chain carries the connection again", self.tag),
		}
		live.chain = cause;
	}

	/// A flow was refused because the carrier was down.
	pub fn refused(&self) {self.refused.fetch_add(1, Ordering::Relaxed);}

	/// What the carrier knows, for the status.
	pub fn report(&self) -> Report {
		let live = self.live();
		let mtu = self.mtu();
		Report {tag: self.tag.clone(), id: self.id, phase: live.phase, reason: live.reason.clone(), since: live.since.elapsed(), profile: live.profile.clone(), transport: live.transport, exit: live.exit.clone(), offered: live.offered.clone(), notices: live.notices.clone(), usage: live.usage.or(live.document_usage), mtu: if mtu == u16::MAX {0} else {mtu}, sent: self.sent.load(Ordering::Relaxed), unsent: self.unsent.load(Ordering::Relaxed), refused: self.refused.load(Ordering::Relaxed), traffic: self.link.traffic.totals(), dropped: self.link.dropped.load(Ordering::Relaxed), flips: self.flips.load(Ordering::Relaxed), starts: self.starts.load(Ordering::Relaxed), provider: live.provider.clone(), signing_key: live.signing_key.clone(), expires_at: live.expires, refreshed_at: live.refreshed, refresh_error: live.failing.clone(), pending_move: live.moving.clone(), pending_hosts: live.hosts.clone(), refreshes: self.refreshes.load(Ordering::Relaxed), refresh_failures: self.refresh_failures.load(Ordering::Relaxed)}
	}

	/// Moves to `phase` for `reason`, and says so when either changed. Packets are taken in `Phase::Up` alone.
	fn change(&self, phase: Phase, reason: impl Into<String>) {
		let (mut live, reason) = (self.live(), reason.into());
		if live.phase == phase && live.reason == reason {return}
		let was = live.up.is_some();
		if live.phase != phase {live.since = Instant::now()}
		live.up = if phase == Phase::Up {live.up.or(Some(Instant::now()))} else {None};
		if was != live.up.is_some() {self.flips.fetch_add(1, Ordering::Relaxed);}
		if phase != Phase::Up {
			live.transport = None;
			live.exit = None;
		}
		tracing::info!("upstream {}: {}{}{}", self.tag, phase.name(), if reason.is_empty() {""} else {": "}, reason);
		(live.phase, live.reason) = (phase, reason);
	}

	pub(super) fn down(&self, reason: impl Into<String>) {self.change(Phase::Down, reason)}

	/// A profile is in use: its device addresses and gateways, and its MTU, which is where the carrier's MTU starts.
	fn profile(&self, profile: &Profile) {
		*self.addresses.write().unwrap_or_else(|e| e.into_inner()) = profile.device.addresses.clone().into();
		*self.gateways.write().unwrap_or_else(|e| e.into_inner()) = profile.gateways.clone().into();
		self.mtu.store(profile.mtu, Ordering::Relaxed);
		self.live().profile = Some(profile.id.clone());
	}

	/// Takes the MTU the engine found when it is lower than the one in force and inside the bounds, and says so.
	fn lower(&self, found: u16, profile: u16) {
		let wanted = found.clamp(MTU_FLOOR.min(profile), profile);
		if self.mtu.fetch_min(wanted, Ordering::Relaxed) > wanted {tracing::info!("upstream {}: the provider's tunnel carries packets of {wanted} bytes at most, so the link is lowered to that", self.tag)}
	}

	/// Sets the gateways the carrier reports, which a profile in use does.
	#[cfg(test)]
	pub(super) fn known_gateways(&self, gateways: &[IpAddr]) {*self.gateways.write().unwrap_or_else(|e| e.into_inner()) = gateways.to_vec().into()}

	/// How long the upstream has been down, None while it is not.
	fn down_for(&self) -> Option<Duration> {Some(self.live()).filter(|live| live.phase == Phase::Down).map(|live| live.since.elapsed())}

	/// Reads what the status shows of the document held: the provider's name, when it stops being current, and the move and the refresh hosts that wait for the operator.
	fn read(live: &mut Live, held: Option<&Held>) {
		let Some(held) = held else {return};
		let subscription = held.subscription();
		live.provider = Some(plain(subscription.provider.as_str(), PROVIDER_CHARS));
		live.signing_key = held.keys().first().map(|key| key.fingerprint().to_string());
		live.expires = Some(subscription.expires_at);
		live.document_usage = subscription.usage.as_ref().map(|usage| (usage.used_bytes, usage.quota_bytes));
		live.moving = held.asking().map(|asked| plain(&asked.key(), HOST_CHARS));
		live.hosts = held.waiting().iter().take(OFFERED).map(|host| plain(host, HOST_CHARS)).collect();
	}

	/// What a refresh came to: counted, its time kept, the move and the hosts that wait for the operator read again, and a change of its outcome logged once. `Ok` holds what the new document changed, none for the same one again. `Err` holds the reason and whether the provider refused: a refusal holds the exit down until a refresh lifts it.
	fn learned(&self, library: &Library, at: u64, result: Result<(Refreshed, Source), RefreshFailed>) -> Result<Option<Changes>, (String, bool)> {
		match result {
			Ok((refreshed, source)) => {
				self.refreshes.fetch_add(1, Ordering::Relaxed);
				let mut live = self.live();
				if live.failing.take().is_some() | live.refusal.take().is_some() {tracing::info!("upstream {}: the subscription is refreshed again", self.tag)}
				(live.refreshed, live.attempted) = (Some(at), Instant::now());
				Self::read(&mut live, library.held().first());
				match refreshed {
					Refreshed::Unchanged => Ok(None),
					Refreshed::Updated(changes) => {
						tracing::info!("upstream {}: the subscription is refreshed from the {}{}{}{}{}", self.tag, source.as_str(), if changes.rotated {", and the provider renewed its signing key"} else {""}, if changes.moved {", and its endpoint moved to the one the operator confirmed"} else {""}, if changes.moving {", and the provider asks to move it to another endpoint, which waits for the operator"} else {""}, if changes.hosts.is_empty() {""} else {", and the provider added refresh hosts, which wait for the operator"});
						Ok(Some(changes))
					}
				}
			}
			Err(failed) => {
				self.refresh_failures.fetch_add(1, Ordering::Relaxed);
				let refused = matches!(failed.error, ImportError::Subscription(Failure::Refused(_)));
				let reason = format!("the subscription could not be refreshed: {}", failed.error.text());
				let mut live = self.live();
				live.attempted = Instant::now();
				if live.failing.as_deref() != Some(reason.as_str()) {tracing::info!("upstream {}: {reason}", self.tag)}
				live.failing = Some(reason.clone());
				if refused {live.refusal = Some(reason.clone())}
				Err((reason, refused))
			}
		}
	}

	/// The operator's yes to the move of the endpoint and to the refresh hosts the provider announced, each only when `moving` and `hosts` ask for it. What each says it did: false when nothing waited for it. A move that was confirmed is tried at once by a refresh, which goes to the new endpoint first.
	pub async fn confirm(&self, moving: bool, hosts: bool) -> io::Result<(bool, bool)> {
		let mut guard = self.library.lock().await;
		let Some(library) = guard.as_mut() else {return Ok((false, false))};
		let (seen, waiting) = library.held().first().map(|held| (held.asking().map(|asked| asked.key()), held.waiting())).unwrap_or_default();
		let (moved, hosted) = (moving && seen.is_some(), hosts && !waiting.is_empty());
		if let (true, Some(seen)) = (moved, &seen) {library.answer_move(0, seen, true)?}
		if hosted {library.answer_hosts(0, &waiting.iter().map(String::as_str).collect::<Vec<_>>(), &[])?}
		Self::read(&mut self.live(), library.held().first());
		drop(guard);
		if moved || hosted {tracing::info!("upstream {}: the operator confirmed {}", self.tag, match (moved, hosted) {(true, true) => "the move of the endpoint and the new refresh hosts", (true, false) => "the move of the endpoint", _ => "the new refresh hosts"})}
		if moved {self.refresh.notify_one()}
		Ok((moved, hosted))
	}
}

/// Whether `key` is the key the operator confirmed, written as its fingerprint or as the key itself.
fn trusts(confirmed: &str, key: &SigningKey) -> bool {key.fingerprint().to_string() == confirmed || URL_SAFE_NO_PAD.encode(key.bytes()) == confirmed}

/// Text from a provider for a person to read: control characters, zero-width and line-separator characters and the characters that reorder text are taken out, and what is left is cut to `most` characters.
fn plain(text: &str, most: usize) -> String {
	text.chars().filter(|c| !c.is_control() && !matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')).take(most).collect()
}

/// Why a dial address of a provider's profile is refused, None when it may be dialled: "dial targets from the upstream profile are refused when loopback, link-local, multicast, unspecified, IPv4-mapped, the node's own addresses or its inbound pools, or private unless `allow_private`". A provider that could steer the node's dials at its own host or its networks would have the node reach what only the node can.
pub fn forbidden(address: IpAddr, pools: &[(IpNet, usize)], is_local: fn(IpAddr) -> bool, allow_private: bool) -> Option<&'static str> {
	if gate::refused(address, pools) {Some("loopback, link-local, multicast, unspecified, IPv4-mapped or inside an inbound pool of the node")}
	else if is_local(address) {Some("an address of the node itself")}
	else if !allow_private && payload::private(address) {Some("a private address, and `allow_private` is off")}
	else {None}
}

/// Whether every address the profile can be dialled at passes `forbidden`. The error says how many do not and why, never which. Checked before the profile goes to the engine, at start and again whenever the document changes.
pub fn dialable(profile: &Profile, pools: &[(IpNet, usize)], is_local: fn(IpAddr) -> bool, allow_private: bool) -> Result<(), String> {
	let refused: Vec<&'static str> = veilway_engine::nodes(&profile.transports, true).into_iter().filter_map(|(address, _)| forbidden(address.ip(), pools, is_local, allow_private)).collect();
	match refused.first() {
		None => Ok(()),
		Some(why) => Err(format!("{} of the dial addresses of the profile are refused as {why}, so the profile is not used", refused.len())),
	}
}

/// The class of transport a config class stands for.
fn class(class: UpstreamClass) -> Class {
	match class {
		UpstreamClass::Cover => Class::Cover,
		UpstreamClass::NoCover => Class::NoCover,
		UpstreamClass::Exposed => Class::Exposed,
		UpstreamClass::Plain => Class::Plain,
	}
}

/// Why a profile could not be started, in plain words.
fn why(error: &StartError) -> &'static str {
	match error {
		StartError::NoProfile => "the document has no such profile",
		StartError::Permit | StartError::NoKey => "the profile has no key this node can use",
		StartError::Unsafe => "the profile is marked unsafe, and the node does not use such a profile",
		StartError::Private => "the profile dials a private address, and `allow_private` is off",
		StartError::Ask(_) | StartError::Nothing => "nothing the profile lists is a way of connecting the operator allowed",
		StartError::Alpha => "what the profile lists is in alpha, and the node does not use that",
	}
}

/// How one run of the upstream ended, for the wait before the next.
enum Ended {
	/// Something went wrong or the tunnel ended: how long it carried, if it did.
	Lost(Option<Duration>),
	/// The provider refused the subscription or the document ran out: nothing is carried until a refresh says otherwise, and the refresh is tried every hour, and every day once a day of trouble has passed.
	Held,
	/// A refresh changed what the tunnel was made from: it is made again at once, after the checks of a start.
	Changed,
}

/// What a refresh task hands back: what the new document changed or why it failed (and whether the provider refused), and the document held then.
type Done = (Result<Option<Changes>, (String, bool)>, Option<Held>);

/// How long the subscription waits before it is refreshed again. While the exit carries it is the document's interval, held between an hour and a day. While it does not, it is an hour for the first day of trouble and a day after that: nothing latches, and a provider that said no is not asked faster than that. `jitter` adds up to a fifth.
fn refresh_wait(interval: u32, failing: Option<Duration>, jitter: u8) -> Duration {
	let base = match failing {
		None => Duration::from_secs(u64::from(interval)).clamp(HOUR, DAY),
		Some(failing) if failing < DAY => HOUR,
		Some(_) => DAY,
	};
	base + base / 5 * u32::from(jitter) / 255
}

/// What the fetches of an upstream and its tunnel dial with. Through a `socks5` outbound it is the proxy chain, which looks a name up itself, so that the node's own resolver never sees which provider is asked. Through a `direct` one it is sockets tied to the outbound's address or interface.
fn fetcher(shared: &Arc<Shared>, reach: Option<&Reach>, hooks: &Hooks, carried: impl Fn(Option<String>) + Send + Sync + Clone + 'static) -> Fetcher {
	let mut fetcher = Fetcher::new(shared.roots.clone(), None);
	match reach {
		None => {}
		Some(Reach::Socks(via)) => (fetcher.connect, fetcher.named) = (Some(link::through(via.clone(), carried.clone())), Some(link::through_name(via.clone(), carried))),
		Some(Reach::Direct {bind, interface}) => fetcher.socket = Some(direct(*bind, interface.clone())),
	}
	if let Some(resolve) = &hooks.resolve {fetcher.resolve = resolve.clone()} else {
		// The system's resolver already refuses loopback and link-local. A name of the provider that comes to an address of this node itself would send the fetch at the node's own services.
		let (inner, is_local) = (fetcher.resolve.clone(), shared.is_local);
		fetcher.resolve = Arc::new(move |host, port| {
			let inner = inner.clone();
			Box::pin(async move {inner(host, port).await.map(|found| found.into_iter().filter(|address| !is_local(address.ip())).collect())})
		});
	}
	fetcher
}

/// Starts the task of an upstream: it fetches the subscription when none is held, runs the tunnel of a profile, refreshes the document, and carries packets between the tunnel and the link until the handle is aborted.
pub(super) fn run(shared: &Arc<Shared>, config: Upstream, reach: Option<Reach>, state: Arc<UpstreamState>, vault: UpstreamVault, hooks: Hooks) -> AbortHandle {tokio::spawn(carry(shared.clone(), config, reach, state, vault, hooks)).abort_handle()}

async fn carry(shared: Arc<Shared>, config: Upstream, reach: Option<Reach>, state: Arc<UpstreamState>, vault: UpstreamVault, hooks: Hooks) {
	// Held for as long as the task lives: a task that replaces this one finds the queue free.
	let mut inbox = state.inbox.lock().await;
	let (mut failed, mut held_since) = (0u32, None::<Instant>);
	loop {
		state.starts.fetch_add(1, Ordering::Relaxed);
		let ended = attempt(&shared, &config, reach.as_ref(), &state, &vault, &hooks, &mut inbox).await;
		let mut jitter = [0u8; 1];
		let _ = random(&mut jitter);
		let wait = match ended {
			Ended::Changed => {
				(failed, held_since) = (0, None);
				Duration::ZERO
			}
			// The refresh that may lift a refusal is the pace of its own: an hour, and a day after a day.
			Ended::Held => {
				failed = 0;
				hooks.refresh.or(hooks.retry).unwrap_or_else(|| refresh_wait(0, Some(held_since.get_or_insert_with(Instant::now).elapsed()), jitter[0]))
			}
			Ended::Lost(lived) => {
				held_since = None;
				// A run that carried for a while starts the waits over, and one that never did makes them longer, to an hour.
				failed = if lived.is_some_and(|lived| lived >= WAIT_FIRST) {0} else {failed.saturating_add(1)};
				let wait = hooks.retry.unwrap_or_else(|| WAIT_FIRST.saturating_mul(1 << failed.saturating_sub(1).min(7)).min(WAIT_MAX));
				wait + wait / 10 * u32::from(jitter[0]) / 255
			}
		};
		tokio::select! {
			_ = tokio::time::sleep(wait) => {}
			_ = state.wake.notified() => {}
		}
	}
}

/// One run of the upstream: the document, the profile, the tunnel and the packets between it and the link, until the tunnel ends or something goes wrong. Whatever it came to is the state's: the reason is logged and kept.
async fn attempt(shared: &Arc<Shared>, config: &Upstream, reach: Option<&Reach>, state: &Arc<UpstreamState>, vault: &UpstreamVault, hooks: &Hooks, inbox: &mut mpsc::Receiver<Vec<u8>>) -> Ended {
	let now = || (shared.now)().unix_timestamp().max(0) as u64;
	let fail = |reason: String| -> Ended {
		state.down(reason);
		Ended::Lost(None)
	};
	if vault.left() {return fail("the operator removed this device from the provider: remove the upstream from the config".into())}
	let Ok(SubscriptionLink::Native(native)) = SubscriptionLink::parse(config.link.expose()) else {return fail("the link of the upstream is not a native subscription link".into())};
	if !trusts(&config.signing_key, &native.key()) {return fail("the key in the link is not the one the operator confirmed".into())}
	let fetcher = fetcher(shared, reach, hooks, {let state = state.clone(); move |cause| state.carried(cause)});
	let held = {
		let mut guard = state.library.lock().await;
		if guard.is_none() {
			match Library::open(Box::new(vault.clone())) {
				Ok((library, damaged)) => {
					if !damaged.is_empty() {tracing::info!("upstream {}: the document in the state file does not verify under its held keys any more, so it is fetched again with the same device", state.tag)}
					*guard = Some(library);
				}
				Err(error) => return fail(format!("the state file of the upstreams cannot be used: {error}")),
			}
		}
		let Some(library) = guard.as_mut() else {return fail("the library of the upstream could not be opened".into())};
		if library.held().is_empty() {
			state.change(Phase::Fetching, "no document is held, so it is fetched with this node's device");
			if let Err(reason) = fetch(shared, &fetcher, library, config, state, native.key().fingerprint().to_string(), now()).await {return fail(reason)}
		}
		let Some(mut held) = library.held().first().cloned() else {return fail("the document was fetched and could not be kept".into())};
		// A document that can no longer be connected on, or one the provider refused, is refreshed before a tunnel is made: it is the refresh that lifts a refusal or finds a newer document.
		let refresh_first = {
			let mut live = state.live();
			live.refusal.is_some() | std::mem::take(&mut live.unusable)
		};
		if refresh_first || held.connect(now()).is_err() {
			let result = fetcher.refresh_from(library, 0, now()).await;
			let learned = state.learned(library, now(), result);
			if let Some(fresh) = library.held().first() {held = fresh.clone()}
			let refusal = state.live().refusal.clone();
			if refusal.is_some() || held.connect(now()).is_err() {
				state.down(refusal.or(learned.err().map(|(reason, _)| reason)).unwrap_or_else(|| "the document is out of date, and the provider has not answered with a newer one".into()));
				return Ended::Held;
			}
		}
		UpstreamState::read(&mut state.live(), Some(&held));
		held
	};
	state.change(Phase::Connecting, "choosing a profile");
	let plan = shared.plan();
	let (allow_private, mut last) = (config.allow_private == Some(true), String::from("the document has no profile"));
	let (store, allowed) = (Arc::new(Store::volatile()), std::iter::once(Class::Cover).chain(config.allow.iter().map(|allowed| class(*allowed))).collect::<Vec<_>>());
	let clock = shared.clone();
	let mut settings = Settings::new(store.clone(), Arc::new(move || (clock.now)().unix_timestamp().max(0) as u64), shared.roots.clone(), "node".into());
	(settings.socket, settings.connect) = (fetcher.socket.clone(), fetcher.connect.clone());
	settings.networks = plan.pools.iter().filter_map(|(pool, _)| Network::new(pool.network(), pool.prefix_len())).collect();
	#[cfg(feature = "upstream-tests")]
	if let Some(redirect) = &hooks.redirect {settings = settings.with_redirect(redirect.clone())}
	let Ok(permit) = held.connect(now()) else {return fail("the document is out of date, and the provider has not answered with a newer one".into())};
	for profile in held.subscription().profiles.iter().filter(|profile| config.profile.as_deref().is_none_or(|wanted| profile.id == wanted)) {
		if let Err(reason) = dialable(profile, &plan.pools, shared.is_local, allow_private) {
			last = reason;
			continue;
		}
		if settings.connect.is_some() && profile.transports.iter().all(|transport| matches!(transport, Transport::Udp(_) | Transport::UdpObfs(_))) {
			last = "the profile lists only datagram transports, which cannot go through the proxy chain of `via`".into();
			continue;
		}
		let best = profile.transports.iter().filter(|transport| choice::usable(transport, false)).map(choice::class).min();
		if best.is_some_and(|best| !allowed.contains(&best)) {
			last = "the best way of connecting the profile lists is one the operator did not allow".into();
			continue;
		}
		let key = veilway_engine::store::profile_key(held.id().as_str(), &profile.id);
		for each in [Class::Cover, Class::NoCover, Class::Exposed, Class::Plain] {if allowed.contains(&each) {store.agree(&key, each)} else {store.decline(&key, each)}}
		match Tunnel::start(settings.clone(), &held, &profile.id, &permit, Agree {private: allow_private, unsafe_profile: false}) {
			Ok(tunnel) => return drive(shared, config, state, tunnel, profile, inbox, &fetcher, &held, hooks).await,
			Err(error) => last = why(&error).into(),
		}
	}
	// Nothing in the document can be started: only a newer one may change that, so the next start refreshes first, and waits as a refusal does.
	state.live().unusable = true;
	state.down(last);
	Ended::Held
}

/// What is done to every socket of the engine and the fetcher when the config's `via` is a `direct` outbound: tied to its interface and bound to its address, as the sockets of its exit are.
fn direct(bind: Option<IpAddr>, interface: Option<String>) -> Hook {
	Arc::new(move |socket: SockRef<'_>| {
		if let Some(name) = &interface {flows::tie(&socket, name, socket.local_addr().map(|address| address.is_ipv4()).unwrap_or(true))?}
		if let Some(bind) = bind {socket.bind(&SockAddr::from(SocketAddr::new(bind, 0)))?}
		Ok(())
	})
}

/// Takes the first document of the subscription: the one the operator was shown in a preview of this very link and device, when it is still kept, else one fetched with this node's device, which is the device the operator made for it and the provider knows. Either must be signed by the key the operator confirmed, and is kept.
async fn fetch(shared: &Arc<Shared>, fetcher: &Fetcher, library: &mut Library, config: &Upstream, state: &UpstreamState, signer: String, now: u64) -> Result<(), String> {
	let reviewed = match shared.previews.take(state.bound()) {
		Some(reviewed) => {
			tracing::info!("upstream {}: the document the operator was shown is used, so the provider is not asked again", state.tag);
			reviewed
		}
		None => {
			let Ok(Offer::Native(offer)) = import::open(config.link.expose()) else {return Err("the link of the upstream is not a native subscription link".into())};
			let secret: [u8; 16] = URL_SAFE_NO_PAD.decode(config.device_secret.expose()).ok().and_then(|bytes| bytes.try_into().ok()).ok_or("the device secret of the upstream is not 16 bytes")?;
			let device = Device::restore(Secret::new(config.private_key.expose().0), DeviceSecret::new(secret));
			let fetching = import::proceed(offer, Some(device)).map_err(|error| error.text().to_owned())?;
			fetcher.fetch(&fetching, library, now, &[]).await.map_err(|error| format!("the subscription could not be fetched: {}", error.text()))?
		}
	};
	let sent = reviewed.review.fingerprint().to_string();
	if sent != signer {
		fetcher.decline(reviewed).await;
		return Err(format!("the document the provider sent is signed by another key than the one the operator confirmed: if the provider rotated its signing key, the new key is {sent}, and the operator must confirm it and use the provider's new link"));
	}
	fetcher.accept(reviewed, None, library).await.map_err(|error| format!("the subscription could not be kept: {}", error.text()))?;
	Ok(())
}

/// Refreshes the subscription in a task of its own, so that the packets of the tunnel go on while the provider answers.
async fn refresh(shared: Arc<Shared>, state: Arc<UpstreamState>, fetcher: Fetcher) -> Option<Done> {
	let now = || (shared.now)().unix_timestamp().max(0) as u64;
	let mut guard = state.library.lock().await;
	let library = guard.as_mut()?;
	let result = fetcher.refresh_from(library, 0, now()).await;
	Some((state.learned(library, now(), result), library.held().first().cloned()))
}

/// What the task asks of the tunnel and when: the exit of the provider the config names is asked for once for each connection, and again when the answer was no and `ASK_AGAIN` has passed.
struct Pace {asked: Option<Instant>, idle: Option<Instant>}

/// Runs the tunnel of `profile`, carrying packets both ways and refreshing the document, until it ends. Dropping the tunnel ends its session.
#[allow(clippy::too_many_arguments)]
async fn drive(shared: &Arc<Shared>, config: &Upstream, state: &Arc<UpstreamState>, mut tunnel: Tunnel, profile: &Profile, inbox: &mut mpsc::Receiver<Vec<u8>>, fetcher: &Fetcher, held: &Held, hooks: &Hooks) -> Ended {
	state.profile(profile);
	let (started, mut carried, mut held) = (Instant::now(), false, held.clone());
	let (mut status, mut events, mut tick, mut pace) = (tunnel.watch(), tunnel.events(), tokio::time::interval(Duration::from_secs(1)), Pace {asked: None, idle: None});
	// Ends with this function, and takes a refresh that is still waiting for the provider with it.
	let (mut refreshing, mut jitter) = (tokio::task::JoinSet::<Option<Done>>::new(), [0u8; 1]);
	let _ = random(&mut jitter);
	loop {
		tokio::select! {
			Some(packet) = inbox.recv() => {
				if state.up() && tunnel.send(packet) {state.sent.fetch_add(1, Ordering::Relaxed);} else {state.unsent.fetch_add(1, Ordering::Relaxed);}
			}
			packet = tunnel.recv() => {
				let Some(packet) = packet else {break};
				let plan = shared.plan();
				// Whatever the tunnel yields is for `chain_back` to judge. While the carrier is not up nothing is, so a provider that sends packets in a state it was not asked for is not heard.
				match plan.links.iter().position(|link| matches!(&link.carrier, Carrier::Upstream(other) if Arc::ptr_eq(other, state))) {
					Some(at) if state.up() => shared.chain_back(&plan, at, packet).await,
					_ => {state.link.dropped.fetch_add(1, Ordering::Relaxed);}
				}
			}
			changed = status.changed() => {
				if changed.is_err() {break}
				let now = status.borrow_and_update().clone();
				judge(config, state, &tunnel, &now, profile, &mut pace);
				carried |= state.up();
			}
			event = events.recv() => {
				// A provider that refuses the exit the config names is not asked again until the pace has passed.
				if let (Ok(Event::Exit {status: ExitStatus::Refused, ..}), Some(wanted)) = (event, config.exit.as_deref()) {
					state.down(format!("the provider refused the exit {}", plain(wanted, TAG_CHARS)));
					pace.asked = Some(Instant::now());
				}
			}
			_ = state.wake.notified() => {
				tracing::info!("upstream {}: the tunnel is asked to connect again by the operator", state.tag);
				(pace.idle, pace.asked) = (None, None);
				tunnel.connect_again();
			}
			_ = state.refresh.notified() => {
				if refreshing.is_empty() {refreshing.spawn(refresh(shared.clone(), state.clone(), fetcher.clone()));}
			}
			Some(done) = refreshing.join_next() => {
				let _ = random(&mut jitter);
				let Ok(Some((learned, fresh))) = done else {continue};
				if let Some(fresh) = fresh {held = fresh}
				match learned {
					// A new document leaves a tunnel that is up alone, unless it changes what the tunnel was made from: the profile's keys, addresses or dial candidates. Then the checks of a start run again, `dialable` among them, and the tunnel is made from the new document.
					Ok(Some(_)) => {
						let changed = held.subscription().profiles.iter().find(|other| other.id == profile.id).is_none_or(|now| (&now.inbound_public_key, &now.device, &now.gateways, now.mtu, &now.transport_public_key, &now.transports, now.stream_first, now.parallel, &now.padding, now.rating_cap, now.min_control_version) != (&profile.inbound_public_key, &profile.device, &profile.gateways, profile.mtu, &profile.transport_public_key, &profile.transports, profile.stream_first, profile.parallel, &profile.padding, profile.rating_cap, profile.min_control_version));
						if changed {
							tracing::info!("upstream {}: the new document changes the profile in use, so the tunnel is made again from it", state.tag);
							// No tunnel exists from here to the next start: what is routed here is refused, and the flows that ran into the old session or its gateways end, so each is judged again against the new profile.
							state.down("the new document changes the profile in use, so the tunnel is made again");
							let ended = shared.nat.end_link(&state.id, &shared.flows);
							shared.flows.end(&ended, shared.plan().generation);
							return Ended::Changed;
						}
					}
					Ok(None) | Err((_, false)) => {}
					Err((reason, true)) => {
						state.down(reason);
						return Ended::Held;
					}
				}
			}
			_ = tick.tick() => {
				let now = status.borrow().clone();
				// A tunnel the provider stopped for good, or that has nothing to try, is asked to connect again at the pace, so that nothing is down for ever on the word of a moment.
				let idle = matches!(now.state, State::Stopped {retry: veilway_engine::Retry::Asked, ..} | State::Failed);
				pace.idle = if idle {pace.idle.or(Some(Instant::now()))} else {None};
				if pace.idle.is_some_and(|since| since.elapsed() >= ASK_AGAIN) {
					pace.idle = Some(Instant::now());
					tracing::info!("upstream {}: the tunnel is asked to connect again", state.tag);
					tunnel.connect_again();
				}
				if pace.asked.is_some_and(|at| at.elapsed() >= ASK_AGAIN) {pace.asked = None}
				judge(config, state, &tunnel, &now, profile, &mut pace);
				carried |= state.up();
				let since_refresh = state.live().attempted.elapsed();
				if refreshing.is_empty() && since_refresh >= hooks.refresh.unwrap_or_else(|| refresh_wait(held.subscription().update_interval, state.down_for(), jitter[0])) {refreshing.spawn(refresh(shared.clone(), state.clone(), fetcher.clone()));}
				if held.connect((shared.now)().unix_timestamp().max(0) as u64).is_err() {
					state.down("the document is out of date, and the provider has not answered with a newer one");
					return Ended::Held;
				}
			}
		}
	}
	state.down("the tunnel ended");
	Ended::Lost(carried.then(|| started.elapsed()))
}

/// Judges the status of the tunnel: whether the carrier is up, and what the status says besides.
fn judge(config: &Upstream, state: &Arc<UpstreamState>, tunnel: &Tunnel, status: &Status, profile: &Profile, pace: &mut Pace) {
	if !matches!(status.state, State::Connected {..}) {
		pace.asked = None;
		match &status.state {
			State::Stopped {reason, ..} => state.down(format!("the provider stopped the connection: {}", reason.say().text())),
			State::Failed => state.down(status.say.map_or("nothing can be done until the connection is asked for again".to_owned(), |say| say.text().to_owned())),
			_ => state.change(Phase::Connecting, status.say.map_or(String::new(), |say| say.text().to_owned())),
		}
		return;
	}
	state.lower(status.mtu, profile.mtu);
	{
		let mut live = state.live();
		live.offered = status.exits.iter().take(OFFERED).map(|exit| plain(&exit.tag, TAG_CHARS)).collect();
		live.notices = status.notices.iter().take(NOTICES).map(|notice| plain(&notice.text, NOTICE_CHARS)).collect();
		live.usage = status.usage.map(|usage| (usage.used_bytes, usage.quota_bytes));
		live.transport = status.connection.as_ref().map(|connection| connection.transport);
		let nearly = status.usage.is_some_and(|usage| usage.quota_bytes > 0 && usage.used_bytes.saturating_mul(10) >= usage.quota_bytes.saturating_mul(9));
		if nearly && !live.warned {tracing::warn!("upstream {}: 90% of the data the provider allows this device is used", state.tag)}
		live.warned = nearly;
	}
	let Some(wanted) = config.exit.as_deref() else {
		let shown = status.exits.iter().find(|exit| exit.selected || exit.configured).map(|exit| plain(&exit.tag, TAG_CHARS));
		{
			let mut live = state.live();
			if shown.is_some() && live.exit != shown {tracing::info!("upstream {}: the exit of the provider in use is {}", state.tag, shown.as_deref().unwrap_or_default())}
			live.exit = shown;
		}
		return state.change(Phase::Up, "");
	};
	// The exit the config names, or nothing: the provider's own default is never an answer. Until the provider has said which exits it offers, and until it says this one is in use, the carrier is down.
	if !status.control || status.exits.is_empty() {return state.change(Phase::Connecting, "waiting for the exits the provider offers")}
	match status.exits.iter().find(|exit| exit.tag == wanted) {
		None => state.down(format!("the provider does not offer the exit {}", plain(wanted, TAG_CHARS))),
		Some(exit) if exit.selected => {
			state.live().exit = Some(plain(wanted, TAG_CHARS));
			state.change(Phase::Up, "");
		}
		Some(_) => {
			if pace.asked.is_none() {
				tunnel.select_exit(Some(wanted.to_owned()));
				pace.asked = Some(Instant::now());
			}
			state.change(Phase::Connecting, format!("asking the provider for the exit {}", plain(wanted, TAG_CHARS)));
		}
	}
}

/// An empty vault: what the review of a document is made against, since the document is kept nowhere until a config names it.
struct Nothing;

impl Vault for Nothing {
	fn load(&self) -> io::Result<Vec<Stored>> {Ok(Vec::new())}

	fn save(&self, _: &[Stored]) -> io::Result<()> {Ok(())}
}

/// A document the operator was shown, with what it takes to give its place at the provider back.
struct Pending {id: String, bound: [u8; 32], reviewed: Reviewed, fetcher: Fetcher}

/// The documents the operator has been shown and has not yet answered with a config, in memory: at most `PREVIEWS_MAX`, each for `PREVIEW_TTL`. A preview takes a place at the provider, so one that is declined or runs out is released there, and a config that names the same link and device takes its document and asks the provider for nothing.
pub struct Previews {hooks: Hooks, pending: Mutex<Vec<Pending>>, fetching: AtomicUsize}

/// A place among the previews, taken before the provider is asked and given back when the preview is kept or fails.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
	fn drop(&mut self) {self.0.fetch_sub(1, Ordering::Relaxed);}
}

impl Previews {
	pub fn new(hooks: Hooks) -> Previews {Previews {hooks, pending: Mutex::new(Vec::new()), fetching: AtomicUsize::new(0)}}

	/// The document kept for the link and device `bound` names, for the config that came to name them.
	fn take(&self, bound: [u8; 32]) -> Option<Reviewed> {
		let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
		pending.iter().position(|kept| kept.bound == bound).map(|at| pending.remove(at).reviewed)
	}

	fn release(&self, id: &str) -> Option<Pending> {
		let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
		pending.iter().position(|kept| kept.id == id).map(|at| pending.remove(at))
	}

	/// Takes a place for a preview that is about to be fetched, counting the ones kept and the ones being fetched, so that no more than `PREVIEWS_MAX` places at the provider are taken at once. None when all are taken.
	fn reserve(&self) -> Option<Slot<'_>> {
		let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
		if pending.len() + self.fetching.load(Ordering::Relaxed) >= PREVIEWS_MAX {return None}
		self.fetching.fetch_add(1, Ordering::Relaxed);
		Some(Slot(&self.fetching))
	}

	/// How many previews wait.
	pub fn waiting(&self) -> usize {self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()}
}

/// What the operator hands over to see a provider's subscription: the link, and the key and the secret the panel made for this node's device with it, in the forms the config writes them.
#[derive(Clone)]
pub struct PreviewRequest {pub link: String, pub private_key: String, pub device_secret: String, pub via: Option<String>, pub allow_private: bool}

/// Why a preview was not made.
#[derive(Debug, PartialEq, Eq)]
pub enum PreviewError {
	/// A part of the request does not read: which, in words that hold none of its value.
	Invalid(&'static str),
	/// The provider could not be asked, or what it answered did not pass the checks: the plain words for the reason.
	Provider(String),
	/// `PREVIEWS_MAX` previews already wait.
	Full,
}

/// A profile of a document as the operator sees it before saying yes.
#[derive(Clone, Debug)]
pub struct ReviewedProfile {
	pub id: String,
	pub name: String,
	/// The transports of the profile, by kind, in its order.
	pub transports: Vec<&'static str>,
	/// The classes of those transports, which the operator's `allow` is answered against.
	pub classes: Vec<UpstreamClass>,
	pub rating: Rating,
	/// The private addresses the profile names to dial.
	pub private: Vec<IpAddr>,
	pub mtu: u16,
	/// The exits the provider lists for the profile, as tag and name.
	pub exits: Vec<(String, String)>,
	/// Why this node would not use the profile under the settings of the request, None when it would.
	pub refused: Option<String>,
}

/// A document the provider answered with, verified under the key of the link and kept for `ttl`.
#[derive(Clone, Debug)]
pub struct Reviewing {
	pub id: String,
	pub ttl: Duration,
	pub fingerprint: String,
	pub provider: String,
	pub serial: u64,
	pub expires_at: u64,
	/// Bytes used and allowed (0 for no limit), and when the account ends (0 for never), as the provider says.
	pub quota: Option<(u64, u64)>,
	pub account_expires_at: u64,
	/// How many devices the account may have (0 for no limit) and how many the document lists.
	pub device_limit: u16,
	pub devices: usize,
	pub classes: Vec<UpstreamClass>,
	pub profiles: Vec<ReviewedProfile>,
}

/// Asks the provider for the document of a link with the device the operator made, which takes a place there: the fetch is the enrollment, and it is made from this node, so the provider sees the node's address and never the panel's. The document is verified under the key of the link and kept in memory under an id, for the operator's answer. Nothing is written to the config or the state file.
pub async fn preview(shared: &Arc<Shared>, outbounds: &[config::Outbound], request: PreviewRequest) -> Result<Reviewing, PreviewError> {
	let previews = &shared.previews;
	let slot = previews.reserve().ok_or(PreviewError::Full)?;
	let key: config::Key = serde_json::from_value(serde_json::Value::String(request.private_key.clone())).map_err(|_| PreviewError::Invalid("private_key is not a WireGuard key"))?;
	let secret: [u8; 16] = URL_SAFE_NO_PAD.decode(request.device_secret.as_bytes()).ok().and_then(|bytes| bytes.try_into().ok()).ok_or(PreviewError::Invalid("device_secret is not 16 bytes as 22 characters of base64url"))?;
	let Ok(Offer::Native(offer)) = import::open(&request.link) else {return Err(PreviewError::Invalid("link is not a native veilway://sub/ subscription link"))};
	let device = Device::restore(Secret::new(key.0), DeviceSecret::new(secret));
	let bound = bind(&request.link, device.public());
	let plan = shared.plan();
	let reach = match request.via.as_deref() {
		Some(tag) => Some(self::reach(outbounds, &plan.latency, &plan.hops, tag).ok_or(PreviewError::Invalid("via names no direct, socks5 or xray outbound of the running config"))?),
		None => None,
	};
	let fetcher = fetcher(shared, reach.as_ref(), &previews.hooks, |_| {});
	let fetching = import::proceed(offer, Some(device)).map_err(|error| PreviewError::Provider(error.text().to_owned()))?;
	let now = (shared.now)().unix_timestamp().max(0) as u64;
	let (empty, _) = Library::open(Box::new(Nothing)).map_err(|_| PreviewError::Provider("no library could be opened".into()))?;
	let reviewed = match fetcher.fetch(&fetching, &empty, now, &[]).await {
		Ok(reviewed) => reviewed,
		Err(error) => {
			// An answer that failed its checks may have left a place pending: it is released. A refusal took none.
			if matches!(error, ImportError::Subscription(failure) if !matches!(failure, Failure::Refused(_))) {fetcher.abandon(fetching, &[]).await}
			return Err(PreviewError::Provider(error.text().to_owned()));
		}
	};
	let id = {
		let mut bytes = [0u8; 16];
		random(&mut bytes).map_err(|_| PreviewError::Provider("no random bytes".into()))?;
		URL_SAFE_NO_PAD.encode(bytes)
	};
	let ttl = previews.hooks.preview.unwrap_or(PREVIEW_TTL);
	let reviewing = review(&id, ttl, &reviewed, shared, request.allow_private);
	{
		let mut pending = previews.pending.lock().unwrap_or_else(|e| e.into_inner());
		// The same link and device again is the same place at the provider: the older review is replaced, not released.
		pending.retain(|kept| kept.bound != bound);
		pending.push(Pending {id: id.clone(), bound, reviewed, fetcher});
		drop(slot);
	}
	tracing::info!("upstreams: a subscription was fetched for the operator to look at, and its place at the provider is kept for {} s", ttl.as_secs());
	tokio::spawn({
		let shared = shared.clone();
		async move {
			tokio::time::sleep(ttl).await;
			if let Some(kept) = shared.previews.release(&id) {
				tracing::info!("upstreams: no config came for the subscription the operator was shown, so its place at the provider is given back");
				kept.fetcher.decline(kept.reviewed).await;
			}
		}
	});
	Ok(reviewing)
}

/// The operator says no to the preview `id`: the provider is told to release the place, and nothing is kept. False when no such preview waits, which is also what a preview that was taken by a config or ran out looks like.
pub async fn decline(shared: &Arc<Shared>, id: &str) -> bool {
	let Some(kept) = shared.previews.release(id) else {return false};
	tracing::info!("upstreams: the operator declined the subscription it was shown, so its place at the provider is given back");
	kept.fetcher.decline(kept.reviewed).await;
	true
}

/// The document `reviewed` as the operator reads it: what is the provider's claim is cleaned of control and direction characters and cut, and what the node itself works out (the class and the rating of a transport, the private addresses, whether the profile would be used) is the node's.
fn review(id: &str, ttl: Duration, reviewed: &Reviewed, shared: &Arc<Shared>, allow_private: bool) -> Reviewing {
	let subscription = reviewed.review.subscription();
	let plan = shared.plan();
	let profiles: Vec<ReviewedProfile> = subscription.profiles.iter().map(|profile| {
		let mut private: Vec<IpAddr> = veilway_engine::nodes(&profile.transports, true).into_iter().map(|(address, _)| address.ip()).filter(|address| payload::private(*address)).collect();
		private.dedup();
		let mut classes: Vec<UpstreamClass> = profile.transports.iter().map(|transport| match choice::class(transport) {Class::Cover => UpstreamClass::Cover, Class::NoCover => UpstreamClass::NoCover, Class::Exposed => UpstreamClass::Exposed, Class::Plain => UpstreamClass::Plain}).collect();
		classes.dedup();
		ReviewedProfile {
			id: plain(&profile.id, TAG_CHARS),
			name: plain(profile.name.as_str(), PROVIDER_CHARS),
			transports: profile.transports.iter().map(|transport| match transport {Transport::Udp(_) => "udp", Transport::UdpObfs(_) => "udp-obfs", Transport::Tls(_) => "tls", Transport::Ws(_) => "ws", Transport::Fronted(_) => "fronted", Transport::FrontedShaped(..) => "fronted-shaped", Transport::FakeTls {..} => "faketls", _ => "ws-plain"}).collect(),
			classes,
			rating: if profile.rating_cap == Some(RatingCap::Unsafe) {Rating::Unsafe} else {Rating::Detectable},
			private,
			mtu: profile.mtu,
			exits: profile.exits.iter().take(OFFERED).map(|exit| (plain(&exit.tag, TAG_CHARS), plain(exit.name.as_str(), PROVIDER_CHARS))).collect(),
			refused: dialable(profile, &plan.pools, shared.is_local, allow_private).err(),
		}
	}).collect();
	let mut classes: Vec<UpstreamClass> = profiles.iter().flat_map(|profile| profile.classes.iter().copied()).collect();
	classes.sort_by_key(|class| *class as u8);
	classes.dedup();
	Reviewing {
		id: id.to_owned(), ttl,
		fingerprint: reviewed.review.fingerprint().to_string(),
		provider: plain(subscription.provider.as_str(), PROVIDER_CHARS),
		serial: subscription.serial,
		expires_at: subscription.expires_at,
		quota: subscription.usage.as_ref().map(|usage| (usage.used_bytes, usage.quota_bytes)),
		account_expires_at: subscription.usage.as_ref().map_or(0, |usage| usage.expires_at),
		device_limit: subscription.usage.as_ref().map_or(0, |usage| usage.device_limit),
		devices: subscription.devices.len(),
		classes, profiles,
	}
}

/// The operator removes the upstream: the provider is told that this device left, for at most `LEAVE_WAIT`, and when it said it took the word the document and its keys are removed from the state file. When it did not, the document stays, so that the same call again can tell it again. Whether the provider said it took the word. A config that is still in force and names the upstream does not bring it back, not even after a restart: the host wrote a tombstone, and the task is not started until a config that does not name the upstream, or names another link or device, has been in force.
pub async fn leave(shared: &Arc<Shared>, state: &Arc<UpstreamState>, vault: &UpstreamVault, reach: Option<&Reach>, hooks: &Hooks) -> bool {
	let now = (shared.now)().unix_timestamp().max(0) as u64;
	let fetcher = fetcher(shared, reach, hooks, {let state = state.clone(); move |cause| state.carried(cause)});
	let mut guard = state.library.lock().await;
	if guard.is_none() {
		if let Ok((library, _)) = Library::open(Box::new(vault.clone())) {*guard = Some(library)}
	}
	let Some(library) = guard.as_mut() else {return false};
	let leaving = library.held().first().and_then(|held| held.leave().map(|request| (request, held.id().clone(), held.targets().into_iter().map(|target| (target.url.clone(), target.pins.to_vec(), target.keys.to_vec())).collect::<Vec<_>>(), held.private_addresses().to_vec())));
	let mut told = false;
	if let Some((request, id, targets, allowed)) = leaving {
		told = tokio::time::timeout(LEAVE_WAIT, async {
			for (url, pins, keys) in &targets {
				if import::ask(&fetcher, &request, url, &Trust::of(pins), keys, &allowed, now).await.is_ok() {return true}
			}
			false
		}).await.unwrap_or(false);
		if told {
			if let Err(error) = library.remove(&id) {tracing::warn!("upstream {}: the document could not be removed from the state file: {error}", state.tag)}
		}
	}
	state.down("the operator removed this device from the provider: remove the upstream from the config");
	tracing::info!("upstream {}: the operator removed the device, and the provider {}", state.tag, if told {"confirmed it"} else {"could not be told: its place stays until the provider removes it"});
	told
}

#[cfg(test)]
mod tests {
	use super::*;

	fn local(address: IpAddr) -> bool {address == "192.0.2.77".parse::<IpAddr>().unwrap()}

	fn pools() -> Vec<(IpNet, usize)> {vec![("10.7.0.1/24".parse().unwrap(), 0), ("fd7a:115c:a1e0::1/64".parse().unwrap(), 0)]}

	#[test]
	fn what_a_provider_may_not_steer_the_nodes_dials_at_is_refused() {
		for refused in ["127.0.0.1", "127.9.9.9", "::1", "169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "0.1.2.3", "::ffff:203.0.113.9", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "10.7.0.2", "fd7a:115c:a1e0::5", "192.0.2.77"] {
			assert!(forbidden(refused.parse().unwrap(), &pools(), local, true).is_some(), "{refused} must be refused even with allow_private");
		}
		for private in ["10.1.2.3", "172.16.0.9", "192.168.1.1", "100.64.0.1", "fd00::1"] {
			assert!(forbidden(private.parse().unwrap(), &pools(), local, false).is_some(), "{private} is private");
			assert!(forbidden(private.parse().unwrap(), &pools(), local, true).is_none(), "{private} is allowed with allow_private");
		}
		// The ranges of documentation are private to a dial address, as the engine reads them: with `allow_private` they pass, and without it they do not.
		for open in ["203.0.113.9", "198.51.100.7", "2001:db8::9"] {
			assert!(forbidden(open.parse().unwrap(), &pools(), local, true).is_none(), "{open}");
			assert!(forbidden(open.parse().unwrap(), &pools(), local, false).is_some(), "{open}");
		}
	}

	#[test]
	fn text_from_a_provider_loses_control_and_direction_characters_and_is_cut() {
		assert_eq!(plain("a\u{202e}b\u{0007}c\nd\u{2066}e\u{200f}f", 100), "abcdef");
		assert_eq!(plain("a\u{200b}b\u{200c}c\u{200d}d\u{feff}e\u{2028}f\u{2029}g", 100), "abcdefg");
		assert_eq!(plain(&"x".repeat(500), NOTICE_CHARS).chars().count(), NOTICE_CHARS);
		assert_eq!(plain("\u{1b}[31mred", 100), "[31mred");
	}

	#[test]
	fn the_mtu_only_goes_down_and_stays_inside_its_bounds() {
		let state = UpstreamState::new("a", [1; 16], [2; 32]);
		assert_eq!((state.mtu(), state.report().mtu), (u16::MAX, 0));
		state.mtu.store(1390, Ordering::Relaxed);
		for (found, wanted) in [(1500, 1390), (1390, 1390), (1300, 1300), (1400, 1300), (1200, 1280), (0, 1280), (1280, 1280), (1290, 1280)] {
			state.lower(found, 1390);
			assert_eq!(state.mtu(), wanted, "after {found}");
		}
		let small = UpstreamState::new("b", [1; 16], [2; 32]);
		small.mtu.store(1100, Ordering::Relaxed);
		small.lower(1000, 1100);
		assert_eq!(small.mtu(), 1100, "a profile below 1280 is the floor itself");
	}

	#[test]
	fn the_refresh_waits_an_hour_to_a_day_while_it_carries_and_an_hour_then_a_day_while_it_does_not() {
		let secs = |wait: Duration| wait.as_secs();
		// The document's interval, clamped to an hour and a day.
		for (interval, wanted) in [(900, 3600), (3600, 3600), (7200, 7200), (86_400, 86_400), (604_800, 86_400)] {assert_eq!(secs(refresh_wait(interval, None, 0)), wanted, "interval {interval}")}
		// Trouble, whatever the document asks for: an hour for the first day, then a day, never faster.
		for interval in [900, 604_800] {
			assert_eq!(secs(refresh_wait(interval, Some(Duration::ZERO), 0)), 3600);
			assert_eq!(secs(refresh_wait(interval, Some(Duration::from_secs(86_399)), 0)), 3600);
			assert_eq!(secs(refresh_wait(interval, Some(DAY), 0)), 86_400);
			assert_eq!(secs(refresh_wait(interval, Some(Duration::from_secs(30 * 86_400)), 0)), 86_400);
		}
		// The jitter adds up to a fifth and never takes away.
		assert_eq!(secs(refresh_wait(3600, None, 255)), 4320);
		assert!((0..=255u8).all(|jitter| (3600..=4320).contains(&secs(refresh_wait(3600, None, jitter)))));
	}

	#[test]
	fn the_phase_names_are_the_ones_the_api_will_use() {
		assert_eq!([Phase::Fetching, Phase::Connecting, Phase::Up, Phase::Down].map(Phase::name), ["fetching", "connecting", "up", "down"]);
	}
}
