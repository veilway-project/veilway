//! The platform-free core of the client engine (protocol pages: transports, control channel, subscription format).
//!
//! A `Tunnel` takes an accepted subscription and one of its profiles and runs one tunnel to a node: it chooses candidates and races two of them as the client rules say, opens a transport session, runs WireGuard over it, and exposes the tunnel as a packet interface, whole IP packets in and whole IP packets out, for a platform layer to connect to a TUN device. Over the tunnel it runs the device's side of the control channel: exits and their selection, usage, notices, `bye` and MTU discovery. `import` is the flow that brings a subscription in: a link, the user's yes, the fetch, the confirmation and the storing.
//!
//! What is not here: any operating system layer. There is no TUN device, no route, no DNS change and no kill switch. The platform keeps the kill switch in force around this engine ("between attempts nothing leaves the device but the transport's own connection"), and every socket the engine opens is handed to the `Settings::socket` hook before it is connected, so that the platform can let exactly those through. A pinned subscription endpoint is checked by its pins alone, see `import`. The platform also supplies the `import::Vault` that keeps the subscriptions' secrets (the engine ships no vault that is safe to use), and the list of the device's own networks.
//!
//! What an app gets (`Status`) has no rating or class word in it. A candidate being tried is given by its place in the signed profile and nothing else, and the reasons for what went wrong are `Say`, plain words with a stable code.
#![forbid(unsafe_code)]
// The `testing` and `unencrypted-vault` features are for tests: the first lets a wait be skipped and a dial be re-pointed after its checks, the second keeps the subscriptions' secrets in a plain file. A build without debug assertions has neither, unless it is a fuzz build or says in so many words (`--cfg veilway_release_tests`) that it is a test run.
#[cfg(all(any(feature = "testing", feature = "unencrypted-vault"), not(debug_assertions), not(test), not(fuzzing), not(veilway_release_tests)))]
compile_error!("the `testing` and `unencrypted-vault` features of veilway-engine are for tests and are not allowed in a release build");

mod carry;
mod channel;
/// The reader of what a node sends after the opening, for the fuzz targets.
#[cfg(feature = "fuzz")]
pub use channel::{Event as ChannelEvent, Reader};
mod engine;
pub mod lan;
pub mod bundle;
pub mod import;
/// Public with the `fuzz` feature, for the fuzz targets that feed it bytes.
#[cfg(feature = "fuzz")]
pub mod ip;
#[cfg(not(feature = "fuzz"))]
mod ip;
pub mod local;
mod local_dns;
mod local_stack;
mod mtu;
/// Public with the `fuzz` feature, for the fuzz targets that feed it packets.
#[cfg(feature = "fuzz")]
pub mod packets;
#[cfg(not(feature = "fuzz"))]
mod packets;
mod socks;
pub mod status;
pub mod store;
#[cfg(feature = "fuzz")]
pub mod tcp;
#[cfg(not(feature = "fuzz"))]
mod tcp;
mod wire;
pub mod xray;

use engine::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use veilway_proto::subscription::client::{Held, Permit};
use veilway_proto::subscription::payload::{Network, RatingCap, Transport, Usage};
use veilway_proto::subscription::Tag;
use veilway_proto::NoRandom;
use veilway_transport::choice;
use veilway_transport::{Connect, Hook, Link};

pub use status::{Attempt, Check, Connection, Counters, Event, ExitView, NoticeView, Retry, Say, State, Status, Stop, UsageView, XrayCounters, XraySay, XrayView};
pub use xray::XrayTunnel;
pub use store::Store;
pub use veilway_transport::choice::Class;
pub use veilway_transport::Clock;

/// The system's secure random source, as `veilway-proto` takes one.
pub(crate) fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), bytes).map_err(|_| NoRandom)}

use std::{future::Future, net::{IpAddr, SocketAddr}, pin::Pin, time::Duration};

/// How a wait is made. A test hands in its own to run the client's waits, which are seconds and minutes long, against a clock it moves itself. Only with the `testing` feature: a wait that returns at once removes every backoff of the client rules, and no build that ships has the field.
pub type Pause = Arc<dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Where an address of a profile is really dialled. A profile cannot name a loopback address, so a test that runs a node on one says so here. Only with the `testing` feature, since it re-points a dial after the checks of the address were made; nothing a profile, a node or a subscription says can set it.
pub type Redirect = Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>;

/// What a tunnel is given by the platform and the app, once. Made with `new` and changed as its fields are.
#[derive(Clone)]
#[non_exhaustive]
pub struct Settings {
	/// What the client remembers between runs.
	pub store: Arc<Store>,
	/// The device's clock in Unix seconds, as it is.
	pub clock: Clock,
	/// The certificates a TLS chain must lead to: the platform's, or `webpki_roots`' through `roots`.
	pub roots: Arc<rustls::RootCertStore>,
	/// What is done to every socket after it is made and before it is connected: keep it out of the tunnel, bind it to an interface, mark it for the firewall. A failure ends the attempt and nothing is dialled.
	pub socket: Option<Hook>,
	/// The device's own networks at the start, the addresses it holds on interfaces that are not a tunnel and the default gateway. "Skipped at each connect: an address inside one of the device's own networks." `Tunnel::moved` gives the list again at every change of network.
	pub networks: Vec<Network>,
	/// Dials the stream of a TCP transport on the caller's behalf, through a proxy chain, in place of a socket of the engine. With it the datagram transports (`udp`, `udp-obfs`) are not used: they cannot go through a proxy chain. A node that runs the engine for another provider's subscription sets it when its config names a proxy for it.
	pub connect: Option<Connect>,
	/// A description of the network the device is on, "what the system exposes": interface type, gateway address, wireless network name or operator code. It is kept only as a hash.
	pub network: String,
	/// The languages of the app, in order of preference, for the texts a signed profile has in several.
	pub languages: Vec<Tag>,
	/// Filled by `Tunnel::start`: the way for an app to reach the tunnel a platform layer runs for it (`select_exit`).
	pub handle: Handle,
	// The hooks of the tests. The field is in every build, so that `Settings` is the same struct in all of them; it can be set only with the `testing` feature.
	hooks: Hooks,
}

#[derive(Clone, Default)]
struct Hooks {pause: Option<Pause>, redirect: Option<Redirect>}

impl Settings {
	/// The settings of a tunnel with the three things every platform has: where the client remembers things, the device's clock and the roots. The rest starts empty and is set as the fields are: the hook for the sockets, the device's own networks, the app's languages.
	pub fn new(store: Arc<Store>, clock: Clock, roots: Arc<rustls::RootCertStore>, network: String) -> Self {Self {store, clock, roots, socket: None, networks: Vec::new(), connect: None, network, languages: Vec::new(), handle: Handle::default(), hooks: Hooks::default()}}
	/// Makes the waits of the client rules with `pause` and not with the runtime's sleep. Only with the `testing` feature.
	#[cfg(feature = "testing")]
	pub fn with_pause(mut self, pause: Pause) -> Self {
		self.hooks.pause = Some(pause);
		self
	}
	/// Re-points every dial after the checks of its address. Only with the `testing` feature.
	#[cfg(feature = "testing")]
	pub fn with_redirect(mut self, redirect: Redirect) -> Self {
		self.hooks.redirect = Some(redirect);
		self
	}
}

/// The commands of the running tunnel, for an app whose platform layer owns the `Tunnel`. It is empty until a tunnel started with these settings, and a command to a tunnel that ended is dropped (`false`).
#[derive(Clone, Default)]
pub struct Handle(Arc<std::sync::Mutex<Option<mpsc::UnboundedSender<Command>>>>);

impl Handle {
	fn send(&self, command: Command) -> bool {self.0.lock().unwrap().as_ref().is_some_and(|sender| sender.send(command).is_ok())}
	pub fn select_exit(&self, tag: Option<String>) -> bool {self.send(Command::Exit(tag))}
	pub fn connect_again(&self) -> bool {self.send(Command::Again)}
	/// The device is idle (screen off, Doze) or is not: see `Tunnel::low_power`.
	pub fn low_power(&self, on: bool) -> bool {self.send(Command::LowPower(on))}
}

/// The roots of the Mozilla list, for a platform that has none of its own.
pub fn default_roots() -> Arc<rustls::RootCertStore> {Arc::new(rustls::RootCertStore {roots: webpki_roots::TLS_SERVER_ROOTS.to_vec()})}

/// What the user said yes to for this start. Each is asked of the user first, and a start without it does not happen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Agree {
	/// "This profile connects to a private address", once per profile. With the yes, such an address is dialled even when it is inside the device's own networks. A public address inside them is never dialled.
	pub private: bool,
	/// The plain warning for an Unsafe profile was shown and the user tapped once.
	pub unsafe_profile: bool,
}

/// Why a tunnel was not started. Nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
	/// The subscription has no profile of that id.
	NoProfile,
	/// The permit was given for another subscription.
	Permit,
	/// The profile has no transport secret or no device key this build can use.
	NoKey,
	/// The profile is Unsafe. The app shows its plain warning and starts again with `Agree::unsafe_profile`.
	Unsafe,
	/// The profile names a private address. The app asks, and starts again with `Agree::private`.
	Private,
	/// The classes of way of connecting the user was not yet asked about. The app asks in plain words (`ask_text`), stores the answer with `Store::agree` or `Store::decline`, and starts again.
	Ask(Vec<Class>),
	/// Nothing the profile lists can be used: no transport this build can open, or none the user agreed to.
	Nothing,
	/// What the profile lists that could be used is in alpha (`faketls`), and `alpha_transports` is off. The app shows `ALPHA_WARNING`, and with the user's yes calls `Store::set_alpha_transports` and starts again.
	Alpha,
}

impl std::fmt::Display for StartError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "tunnel not started: {self:?}")}
}

impl std::error::Error for StartError {}

/// The question to put to the user for a class, "in plain words". It names no class and no rating.
pub fn ask_text(class: Class) -> &'static str {
	match class {
		Class::Cover => "Use the connection that looks like ordinary web traffic?",
		Class::NoCover => "On some networks the only way through may be one that does not look like web traffic. Someone watching the network can tell that something unusual is going on, though not what. Allow it for this connection?",
		Class::Exposed => "On some networks the only way through may be a plain web connection that nothing hides. The network can see this server's name and can tell that you use this app, and when and how much, now and later in its records. It cannot see what you send. If this transport's key ever leaks, it ties all of your device's plain connections together. Allow it for this connection?",
		Class::Plain => "On some networks the only way through may be a plain tunnel that is easy to recognise as a VPN. Someone watching the network can tell that you are using one. Allow it for this connection?",
	}
}

/// What the app says before the user turns on `alpha_transports` the first time, in plain words. It names no class and no rating.
pub const ALPHA_WARNING: &str = "This way of connecting is still being tested and has not been reviewed by anyone outside the project. It makes the connection look like a visit to a real website, and that website has not agreed to it. Turn it on only if you accept that.";

/// One tunnel. Dropping it stops it; `stop` waits for the session to be closed first.
pub struct Tunnel {
	commands: mpsc::UnboundedSender<Command>,
	status: watch::Receiver<Status>,
	events: broadcast::Sender<Event>,
	into: mpsc::Sender<Vec<u8>>,
	out: mpsc::Receiver<Vec<u8>>,
	refused: Arc<AtomicU64>,
	woke: Arc<AtomicU64>,
	task: JoinHandle<()>,
	device: Vec<IpAddr>,
	gateways: Vec<IpAddr>,
}

impl Tunnel {
	/// Starts a tunnel for a profile of an accepted subscription. `permit` is the answer of `Held::connect`, which asks for the user's confirmation when the document is long out of date. Called inside a tokio runtime. It returns at once: `status` says how it goes.
	pub fn start(settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree) -> Result<Self, StartError> {
		let subscription = held.subscription();
		if permit.id() != held.id() {return Err(StartError::Permit)}
		let at = subscription.profiles.iter().position(|candidate| candidate.id == profile).ok_or(StartError::NoProfile)?;
		let profile = &subscription.profiles[at];
		let key = profile.device.private_key.clone().or_else(|| held.device().map(|device| device.private().clone())).ok_or(StartError::NoKey)?;
		let link = Link::of(profile).ok_or(StartError::NoKey)?;
		if profile.rating_cap == Some(RatingCap::Unsafe) && !agree.unsafe_profile {return Err(StartError::Unsafe)}
		let alpha = settings.store.alpha_transports();
		if !agree.private && profile.transports.iter().filter(|transport| choice::usable(transport, alpha)).any(|transport| addresses(transport).iter().any(|address| address.private())) {return Err(StartError::Private)}
		for drop in &profile.dropped {tracing::info!(profile = %profile.id, transport = drop.transport, count = drop.count, reason = drop.cause.word(), "part of the profile was left out because it did not read")}
		let capped = held.capped().iter().filter(|(of, _, _)| *of == at).count();
		if capped > 0 {tracing::info!(profile = %profile.id, count = capped, "cover candidates share an address with a datagram endpoint of the subscription: their rating is at most Detectable")}
		let (store_key, now) = (store::profile_key(held.id().as_str(), &profile.id), (settings.clock)());
		let (mut kept, hosts) = (settings.store.kept(&store_key), choice::plain_hosts(&profile.transports));
		if kept.standing.exposed != hosts {
			settings.store.bind_plain(&store_key, hosts);
			kept = settings.store.kept(&store_key);
		}
		let (stream_first, network) = (kept.stream_first.unwrap_or(profile.stream_first), kept.network(&store::network_key(settings.store.seed(), &settings.network)));
		let mut plan = choice::plan(&profile.transports, stream_first, &network, &kept.standing, now, alpha);
		if settings.connect.is_some() {plan.order.retain(|at| !matches!(profile.transports[*at], Transport::Udp(_) | Transport::UdpObfs(_)))}
		let ask: Vec<Class> = plan.ask.into_iter().filter(|class| !kept.declined.contains(class)).collect();
		if !ask.is_empty() {return Err(StartError::Ask(ask))}
		// Alpha is the reason only if turning it on would give something to try.
		if plan.order.is_empty() {return Err(if !alpha && !choice::plan(&profile.transports, stream_first, &network, &kept.standing, now, true).order.is_empty() {StartError::Alpha} else {StartError::Nothing})}
		let (commands, input) = mpsc::unbounded_channel();
		// The user's saved choice for this subscription goes in first, so the node is asked for it once the control channel opens.
		if let Some(tag) = settings.store.exit_choice(held.id().as_str()) {let _ = commands.send(Command::Exit(Some(tag)));}
		*settings.handle.0.lock().unwrap() = Some(commands.clone());
		let ((into, from), (to, out), (events, _), refused, woke) = (mpsc::channel(engine::QUEUE), mpsc::channel(engine::QUEUE), broadcast::channel(64), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
		let (status_tx, status) = watch::channel(Status::off(profile.name.as_str().to_owned(), profile.mtu));
		let (device, gateways) = (profile.device.addresses.clone(), profile.gateways.clone());
		let core = engine::Core::new(engine::Parts {settings, profile: profile.clone(), subscription: Arc::new(subscription.clone()), link, key, store_key, kept, commands: input, from_platform: from, to_platform: to, status: status_tx, events: events.clone(), refused: refused.clone(), woke: woke.clone(), private: agree.private});
		Ok(Self {commands, status, events, into, out, refused, woke, task: tokio::spawn(core.run()), device, gateways})
	}
	/// The device's addresses inside the tunnel and the gateways, one per family in the same order, as the signed profile gives them. The gateway answers DNS.
	pub fn addresses(&self) -> (&[IpAddr], &[IpAddr]) {(&self.device, &self.gateways)}
	/// The state of the tunnel and everything an app shows of it.
	/// Wakeups of the timer loops so far, as they happen: the status carries the count only when something else changed.
	pub fn ticks(&self) -> u64 {self.woke.load(Ordering::Relaxed)}
	pub fn status(&self) -> Status {self.status.borrow().clone()}
	/// The status as something to wait on: it changes at every state change and about once a second while the counters move.
	pub fn watch(&self) -> watch::Receiver<Status> {self.status.clone()}
	/// Things that happen once.
	pub fn events(&self) -> broadcast::Receiver<Event> {self.events.subscribe()}
	/// Hands one IP packet from the device to the tunnel. False when it was dropped because the queue is full. Packets handed in while no session is open are dropped and counted: the kill switch is the platform's, and nothing leaves the device outside the tunnel.
	pub fn send(&self, packet: Vec<u8>) -> bool {
		let queued = self.into.try_send(packet).is_ok();
		if !queued {self.refused.fetch_add(1, Ordering::Relaxed);}
		queued
	}
	/// The next IP packet out of the tunnel for the device, or None when the tunnel has stopped.
	pub async fn recv(&mut self) -> Option<Vec<u8>> {self.out.recv().await}
	/// Asks the node for this exit, or for none. Applied once the control channel is open, and a node that refuses is told in `Event::Exit`.
	pub fn select_exit(&self, tag: Option<String>) {let _ = self.commands.send(Command::Exit(tag));}
	/// "The user asks to connect again": every mark, count and wait starts over, and a stop by the node that waits is ended. The hour's budget of new addresses and the user's answers stay.
	pub fn connect_again(&self) {let _ = self.commands.send(Command::Again);}
	/// The device's network changed. `network` describes the new one, as `Settings::network` does, and `networks` are its own networks as they are now, as `Settings::networks` has them: a candidate inside them is not dialled from here on, and a session to one is ended.
	pub fn moved(&self, network: String, networks: Vec<Network>) {let _ = self.commands.send(Command::Moved(network, networks));}
	/// The system reported that a packet was too big for the path: the MTU is confirmed again at once. What the report says of a size is never used.
	pub fn reprobe(&self) {let _ = self.commands.send(Command::Reprobe);}
	/// The device is idle (screen off, Doze) or is not. While it is, an idle tunnel wakes every 2 s instead of every second, and the idle keepalive of a stream transport (`tls`, `ws`, `ws-plain`, `faketls`, a streaming `fronted` shape) is drawn from the top 10 s of the range the profile allows, never above 60 s. `udp` and `udp-obfs` are not slowed down in what they send: a NAT binding of a mobile network may expire sooner. Leaving low power restores both at once, and a new session starts in the state last set.
	pub fn low_power(&self, on: bool) {let _ = self.commands.send(Command::LowPower(on));}
	/// A refreshed subscription brought new numbers. A stop for a used-up quota or an expired account ends when they show the cause is gone.
	pub fn refreshed(&self, usage: Option<Usage>) {let _ = self.commands.send(Command::Refreshed(usage));}
	/// Hands the tunnel a message as if the node had sent it over the control channel, to see what the engine does with one it should not believe. Only with the `testing` feature.
	#[cfg(feature = "testing")]
	pub fn inject(&self, message: veilway_proto::control::NodeMessage) {let _ = self.commands.send(Command::Inject(message));}
	/// Stops the tunnel, closing its session the way its transport closes one, and gives the last status.
	pub async fn stop(self) -> Status {
		let _ = self.commands.send(Command::Stop);
		let _ = self.task.await;
		self.status.borrow().clone()
	}
}

/// What a platform layer carries packets of: a tunnel to a node, or the carrier of a legacy profile through Xray. They answer to the same calls, so the loop that moves packets between the device and the engine is written once.
pub enum Carrier {
	Native(Tunnel),
	Xray(XrayTunnel),
}

impl Carrier {
	pub fn status(&self) -> Status {match self {Self::Native(tunnel) => tunnel.status(), Self::Xray(tunnel) => tunnel.status()}}
	pub fn watch(&self) -> watch::Receiver<Status> {match self {Self::Native(tunnel) => tunnel.watch(), Self::Xray(tunnel) => tunnel.watch()}}
	pub fn send(&self, packet: Vec<u8>) -> bool {match self {Self::Native(tunnel) => tunnel.send(packet), Self::Xray(tunnel) => tunnel.send(packet)}}
	pub async fn recv(&mut self) -> Option<Vec<u8>> {match self {Self::Native(tunnel) => tunnel.recv().await, Self::Xray(tunnel) => tunnel.recv().await}}
	/// The device's networks changed. The carrier of a legacy profile has nothing to redo: Xray's own socket is kept out of the tunnel by the platform.
	pub fn moved(&self, network: String, networks: Vec<Network>) {if let Self::Native(tunnel) = self {tunnel.moved(network, networks)}}
	/// The device is idle or is not. The carrier of a legacy profile has no timers of its own to slow down.
	pub fn low_power(&self, on: bool) {if let Self::Native(tunnel) = self {tunnel.low_power(on)}}
	pub async fn stop(self) -> Status {match self {Self::Native(tunnel) => tunnel.stop().await, Self::Xray(tunnel) => tunnel.stop().await}}
}

/// Where the transports of a profile are dialled, each with whether it is TCP, none twice: what the platform's kill switch lets the engine's own sockets out to. A transport the engine will not dial, `faketls` while `alpha` is off, is not listed.
pub fn nodes(transports: &[Transport], alpha: bool) -> Vec<(std::net::SocketAddr, bool)> {
	let mut found = Vec::new();
	for transport in transports.iter().filter(|transport| choice::usable(transport, alpha)) {
		let tcp = !matches!(transport, Transport::Udp(_) | Transport::UdpObfs(_));
		for dial in addresses(transport) {
			if !found.contains(&(dial.address(), tcp)) {found.push((dial.address(), tcp))}
		}
	}
	found
}

// The dial addresses a transport of a profile lists.
fn addresses(transport: &Transport) -> Vec<veilway_proto::subscription::payload::Dial> {
	match transport {
		Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) => endpoints.clone(),
		Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _) => stream.candidates.iter().map(|candidate| candidate.address).collect(),
		Transport::FakeTls {candidates, ..} => candidates.iter().map(|candidate| candidate.address).collect(),
		Transport::WsPlain {stream, ..} => stream.candidates.iter().map(|candidate| candidate.address).collect(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_proto::subscription::payload::{Borrowed, Dial};

	fn dial(text: &str) -> Dial {Dial::parse(text).unwrap()}

	#[test]
	fn the_kill_switch_opens_no_address_of_a_transport_the_engine_will_not_dial() {
		let borrowed = |address: &str| Borrowed {address: dial(address), sni: "www.example.com".into()};
		let transports = [Transport::Udp(vec![dial("192.0.2.10:51820"), dial("192.0.2.10:51820")]), Transport::FakeTls {key: [0x45; 32], candidates: vec![borrowed("192.0.2.20:443"), borrowed("192.0.2.10:51820")]}];
		// Off, the borrowed site's candidates are not there at all, and the doubled endpoint is one.
		assert_eq!(nodes(&transports, false), [("192.0.2.10:51820".parse().unwrap(), false)]);
		// On, they are, by TCP, and the same address and port by UDP is another entry.
		assert_eq!(nodes(&transports, true), [("192.0.2.10:51820".parse().unwrap(), false), ("192.0.2.20:443".parse().unwrap(), true), ("192.0.2.10:51820".parse().unwrap(), true)]);
	}
}
