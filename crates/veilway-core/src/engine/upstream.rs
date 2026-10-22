//! Another provider's Veilway subscription as the carrier of an exit (upstreams page): the client engine (`veilway-engine`) runs inside the node for one device of the subscription, and a `chain` link behind it is the exit. What the node hands the link goes into the engine's tunnel, and what comes out of the tunnel is handed to `chain_back`, which delivers only what answers a live flow of a device that was routed through the exit and drops the rest. Translation, answers, ICMP, MSS and the refusal of a down carrier are `chain`'s, unchanged.
//! Everything the provider sends is hostile: its document, the transports it lists, its control channel and the packets of its tunnel. A document is accepted only under the signing key the operator confirmed, every dial address of a profile is held to `forbidden` before the engine sees the profile, only a lower MTU is applied, notices are plain text, and the exit is down, and what is routed to it refused as unreachable, whenever anything is wrong. It never falls back to the provider's default exit or to another exit of the node: that is `routing.fallback`'s, and the operator's.
//! Nothing latches. A failed step waits and is tried again, with the wait growing to an hour and no further, a node that cut the device off is asked again at a fixed pace, and each change of state is logged once, at info, with its reason.
use super::flows;
use super::gate;
use super::link;
use super::plan::{self, Carrier, Latency, Outbound};
use super::upstream_state::UpstreamVault;
use super::{Shared, Totals, QUEUE};
use crate::config::{self, random, Upstream, UpstreamClass};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::IpNet;
use socket2::{Domain, SockAddr, SockRef};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use veilway_engine::import::{self, Fetcher, Library, Resolve};
use veilway_transport::{Connect, Hook};
use veilway_engine::{Agree, Class, Event, Settings, StartError, State, Status, Store, Tunnel};
use veilway_proto::control::ExitStatus;
use veilway_transport::choice;
use veilway_proto::subscription::client::{Device, Offer};
use veilway_proto::subscription::envelope::SigningKey;
use veilway_proto::subscription::link::Link as SubscriptionLink;
use veilway_proto::subscription::payload::{self, Network, Profile, Transport};
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

/// How the node reaches a provider when the config names a `via` for the upstream: through the proxy chain of a `socks5` outbound, for the fetch and for the connections of the TCP transports (the datagram transports cannot go through it and are not used), or from the address or interface a `direct` outbound binds its sockets to.
#[derive(Clone, PartialEq)]
pub enum Reach {Direct {bind: Option<IpAddr>, interface: Option<String>}, Socks(Arc<plan::Upstream>)}

/// The outbound `tag` of the config as the node reaches a provider through it. None for a tag that is no `direct` or `socks5` outbound, which validation does not let through.
pub fn reach(outbounds: &[config::Outbound], latency: &HashMap<String, Arc<Latency>>, tag: &str) -> Option<Reach> {
	match Outbound::of(outbounds, latency, tag)? {
		Outbound::Direct {bind, interface} => Some(Reach::Direct {bind, interface}),
		Outbound::Socks5(up) => Some(Reach::Socks(Arc::new(up))),
	}
}

/// What a test puts in place of the node's own network: the resolver the fetch looks up its endpoint with, how long a node that was cut off waits before it asks again, and where the addresses of a profile really are.
#[derive(Clone, Default)]
pub struct Hooks {
	pub resolve: Option<Resolve>,
	pub retry: Option<Duration>,
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
	live: Mutex<Live>,
	sent: AtomicU64,
	unsent: AtomicU64,
	refused: AtomicU64,
	flips: AtomicU64,
	starts: AtomicU64,
}

impl UpstreamState {
	/// A state for the upstream `tag`, whose link and device are bound by `bound` (see `UpstreamVault::bound`).
	pub fn new(tag: &str, id: [u8; 16], bound: [u8; 32]) -> Arc<UpstreamState> {
		let (out, inbox) = mpsc::channel(QUEUE);
		let live = Live {phase: Phase::Fetching, reason: String::new(), since: Instant::now(), up: None, profile: None, transport: None, exit: None, offered: Vec::new(), notices: Vec::new(), usage: None, warned: false, chain: None};
		Arc::new(UpstreamState {tag: tag.to_owned(), id, bound, link: Arc::default(), mtu: AtomicU16::new(u16::MAX), addresses: RwLock::new(Arc::from(Vec::new())), gateways: RwLock::new(Arc::from(Vec::new())), out, inbox: tokio::sync::Mutex::new(inbox), wake: tokio::sync::Notify::new(), live: Mutex::new(live), sent: AtomicU64::new(0), unsent: AtomicU64::new(0), refused: AtomicU64::new(0), flips: AtomicU64::new(0), starts: AtomicU64::new(0)})
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
		Report {tag: self.tag.clone(), id: self.id, phase: live.phase, reason: live.reason.clone(), since: live.since.elapsed(), profile: live.profile.clone(), transport: live.transport, exit: live.exit.clone(), offered: live.offered.clone(), notices: live.notices.clone(), usage: live.usage, mtu: if mtu == u16::MAX {0} else {mtu}, sent: self.sent.load(Ordering::Relaxed), unsent: self.unsent.load(Ordering::Relaxed), refused: self.refused.load(Ordering::Relaxed), traffic: self.link.traffic.totals(), dropped: self.link.dropped.load(Ordering::Relaxed), flips: self.flips.load(Ordering::Relaxed), starts: self.starts.load(Ordering::Relaxed)}
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

	fn down(&self, reason: impl Into<String>) {self.change(Phase::Down, reason)}

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
}

/// Whether `key` is the key the operator confirmed, written as its fingerprint or as the key itself.
fn trusts(confirmed: &str, key: &SigningKey) -> bool {key.fingerprint().to_string() == confirmed || URL_SAFE_NO_PAD.encode(key.bytes()) == confirmed}

/// Text from a provider for a person to read: control characters and the characters that reorder text are taken out, and what is left is cut to `most` characters.
fn plain(text: &str, most: usize) -> String {
	text.chars().filter(|c| !c.is_control() && !matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).take(most).collect()
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

/// Starts the task of an upstream: it fetches the subscription when none is held, runs the tunnel of a profile, and carries packets between the tunnel and the link until the handle is aborted.
pub(super) fn run(shared: &Arc<Shared>, config: Upstream, reach: Option<Reach>, state: Arc<UpstreamState>, vault: UpstreamVault, hooks: Hooks) -> AbortHandle {tokio::spawn(carry(shared.clone(), config, reach, state, vault, hooks)).abort_handle()}

async fn carry(shared: Arc<Shared>, config: Upstream, reach: Option<Reach>, state: Arc<UpstreamState>, vault: UpstreamVault, hooks: Hooks) {
	// Held for as long as the task lives: a task that replaces this one finds the queue free.
	let mut inbox = state.inbox.lock().await;
	let mut failed = 0u32;
	loop {
		state.starts.fetch_add(1, Ordering::Relaxed);
		let lived = attempt(&shared, &config, reach.as_ref(), &state, &vault, &hooks, &mut inbox).await;
		// A run that carried for a while starts the waits over, and one that never did makes them longer, to an hour.
		failed = if lived.is_some_and(|lived| lived >= WAIT_FIRST) {0} else {failed.saturating_add(1)};
		let mut jitter = [0u8; 1];
		let _ = random(&mut jitter);
		let wait = hooks.retry.unwrap_or_else(|| WAIT_FIRST.saturating_mul(1 << failed.saturating_sub(1).min(7)).min(WAIT_MAX));
		tokio::time::sleep(wait + wait / 10 * u32::from(jitter[0]) / 255).await;
	}
}

/// One run of the upstream: the document, the profile, the tunnel and the packets between it and the link, until the tunnel ends or something goes wrong. How long it carried, if it did. Whatever it came to is the state's: the reason is logged and kept.
async fn attempt(shared: &Arc<Shared>, config: &Upstream, reach: Option<&Reach>, state: &Arc<UpstreamState>, vault: &UpstreamVault, hooks: &Hooks, inbox: &mut mpsc::Receiver<Vec<u8>>) -> Option<Duration> {
	let now = || (shared.now)().unix_timestamp().max(0) as u64;
	let fail = |reason: String| -> Option<Duration> {
		state.down(reason);
		None
	};
	let (mut library, damaged) = match Library::open(Box::new(vault.clone())) {
		Ok(opened) => opened,
		Err(error) => return fail(format!("the state file of the upstreams cannot be used: {error}")),
	};
	if !damaged.is_empty() {tracing::info!("upstream {}: the document in the state file does not verify under its held keys any more, so it is fetched again with the same device", state.tag)}
	let Ok(SubscriptionLink::Native(native)) = SubscriptionLink::parse(config.link.expose()) else {return fail("the link of the upstream is not a native subscription link".into())};
	if !trusts(&config.signing_key, &native.key()) {return fail("the key in the link is not the one the operator confirmed".into())}
	let (socket, connect): (Option<Hook>, Option<Connect>) = match reach {
		None => (None, None),
		Some(Reach::Socks(via)) => (None, Some(link::through(via.clone(), {let state = state.clone(); move |cause| state.carried(cause)}))),
		Some(Reach::Direct {bind, interface}) => (Some(direct(*bind, interface.clone())), None),
	};
	if library.held().is_empty() {
		state.change(Phase::Fetching, "no document is held, so it is fetched with this node's device");
		let mut fetcher = Fetcher {connect: connect.clone(), ..Fetcher::new(shared.roots.clone(), socket.clone())};
		if let Some(resolve) = &hooks.resolve {fetcher.resolve = resolve.clone()}
		if let Err(reason) = fetch(&fetcher, &mut library, config, native.key().fingerprint().to_string(), now()).await {return fail(reason)}
	}
	let Some(held) = library.held().first() else {return fail("the document was fetched and could not be kept".into())};
	if !held.keys().iter().any(|key| trusts(&config.signing_key, key)) {return fail("the document is no longer signed by the key the operator confirmed".into())}
	state.change(Phase::Connecting, "choosing a profile");
	let plan = shared.plan();
	let (allow_private, mut last) = (config.allow_private == Some(true), String::from("the document has no profile"));
	let (store, allowed) = (Arc::new(Store::volatile()), std::iter::once(Class::Cover).chain(config.allow.iter().map(|allowed| class(*allowed))).collect::<Vec<_>>());
	let clock = shared.clone();
	let mut settings = Settings::new(store.clone(), Arc::new(move || (clock.now)().unix_timestamp().max(0) as u64), shared.roots.clone(), "node".into());
	(settings.socket, settings.connect) = (socket, connect);
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
		match Tunnel::start(settings.clone(), held, &profile.id, &permit, Agree {private: allow_private, unsafe_profile: false}) {
			Ok(tunnel) => return drive(shared, config, state, tunnel, profile, inbox).await,
			Err(error) => last = why(&error).into(),
		}
	}
	fail(last)
}

/// What is done to every socket of the engine and the fetcher when the config's `via` is a `direct` outbound: tied to its interface and bound to its address, as the sockets of its exit are.
fn direct(bind: Option<IpAddr>, interface: Option<String>) -> Hook {
	Arc::new(move |socket: SockRef<'_>| {
		if let Some(name) = &interface {flows::tie(&socket, name, socket.domain()? == Domain::IPV4)?}
		if let Some(bind) = bind {socket.bind(&SockAddr::from(SocketAddr::new(bind, 0)))?}
		Ok(())
	})
}

/// Fetches the subscription with this node's device, which is the device the operator made for it and the provider knows, and keeps it. The document must be signed by the key the operator confirmed.
async fn fetch(fetcher: &Fetcher, library: &mut Library, config: &Upstream, signer: String, now: u64) -> Result<(), String> {
	let Ok(Offer::Native(offer)) = import::open(config.link.expose()) else {return Err("the link of the upstream is not a native subscription link".into())};
	let secret: [u8; 16] = URL_SAFE_NO_PAD.decode(config.device_secret.expose()).ok().and_then(|bytes| bytes.try_into().ok()).ok_or("the device secret of the upstream is not 16 bytes")?;
	let device = Device::restore(Secret::new(config.private_key.expose().0), DeviceSecret::new(secret));
	let fetching = import::proceed(offer, Some(device)).map_err(|error| error.text().to_owned())?;
	let reviewed = fetcher.fetch(&fetching, library, now, &[]).await.map_err(|error| format!("the subscription could not be fetched: {}", error.text()))?;
	if reviewed.review.fingerprint().to_string() != signer {
		fetcher.decline(reviewed).await;
		return Err("the document the provider sent is not signed by the key the operator confirmed".into());
	}
	fetcher.accept(reviewed, None, library).await.map_err(|error| format!("the subscription could not be kept: {}", error.text()))?;
	Ok(())
}

/// What the task asks of the tunnel and when: the exit of the provider the config names is asked for once for each connection, and again when the answer was no and `ASK_AGAIN` has passed.
struct Pace {asked: Option<Instant>, idle: Option<Instant>}

/// Runs the tunnel of `profile`, carrying packets both ways, until it ends. How long it carried.
async fn drive(shared: &Arc<Shared>, config: &Upstream, state: &Arc<UpstreamState>, mut tunnel: Tunnel, profile: &Profile, inbox: &mut mpsc::Receiver<Vec<u8>>) -> Option<Duration> {
	state.profile(profile);
	let (started, mut carried) = (Instant::now(), false);
	let (mut status, mut events, mut tick, mut pace) = (tunnel.watch(), tunnel.events(), tokio::time::interval(Duration::from_secs(1)), Pace {asked: None, idle: None});
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
			}
		}
	}
	state.down("the tunnel ended");
	carried.then(|| started.elapsed())
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
		state.live().exit = status.exits.iter().find(|exit| exit.selected || exit.configured).map(|exit| plain(&exit.tag, TAG_CHARS));
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
	fn the_phase_names_are_the_ones_the_api_will_use() {
		assert_eq!([Phase::Fetching, Phase::Connecting, Phase::Up, Phase::Down].map(Phase::name), ["fetching", "connecting", "up", "down"]);
	}
}
