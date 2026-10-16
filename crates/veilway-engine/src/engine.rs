//! The task of a tunnel: the loop that chooses a candidate, races two of them, opens a session and carries the tunnel, and goes on with the next candidate, the next transport and the next round as the client rules say, for as long as the user wants to be connected.
//!
//! The choices themselves are `choice`'s, over state this task owns and writes to the store after every change of consequence. What this loop adds is the order of things around them: a race of two candidates 250 ms apart with one WireGuard datagram for both, the waits that each outcome asks for (interrupted by the user), the bye of the node that stops the loop until its reason is gone, and the account of every state change in the log.
//! No failure is latched for ever. A candidate that is set aside comes back within the hour, a refusal is tried again after its wait, a transport that was set aside is tried again after an hour, and the loop never ends by itself while the user wants the connection. Every state change is logged at info with the places in the profile it concerns and never an address or a name.
use crate::carry::Carrier;
use crate::status::{Attempt, Connection, Counters, Event, Retry, Say, State, Status, Stop};
use crate::store::{Kept, Store};
use crate::wire::{Shared, Wire};
use crate::{random, Settings};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, watch};
use veilway_proto::subscription::payload::{Dial, Network as OwnNetwork, Profile, Subscription, Transport, Usage};
use veilway_proto::subscription::Secret;
use veilway_transport::choice::{self, Network, Next, Pick, Standing, HOUR, STAGGER};
use veilway_transport::{End, Ended, Env, Link, Refuse, Session, State as Opened, Target, Unreachable};

/// How many packets wait between the platform and the tunnel in each direction.
pub(crate) const QUEUE: usize = 1024;

/// What the app and the platform tell a running tunnel.
pub(crate) enum Command {
	Stop,
	Again,
	Exit(Option<String>),
	Moved(String, Vec<OwnNetwork>),
	Reprobe,
	Refreshed(Option<Usage>),
	/// A message of the node that the test hands the tunnel (`Tunnel::inject`).
	#[cfg(feature = "testing")]
	Inject(veilway_proto::control::NodeMessage),
}

/// What a command did to the loop that read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reaction {None, Stop, Again, Moved}

/// A stop by the node and what it waits for.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Hold {pub stop: Stop, pub until: Option<u64>}

/// How a wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rested {Done, Stop, Again}

/// Why a carried session or an attempt is over for the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {Over, Stop, Again, Bye}

/// What an attempt left behind: how each candidate that is over ended, in the order it ended, and why the loop is asked to look again.
pub(crate) struct Done {pub ended: Vec<(usize, Ended)>, pub why: Why, pub say: Option<Say>, pub opened: bool}

pub(crate) struct Parts {
	pub settings: Settings,
	pub profile: Profile,
	pub subscription: Arc<Subscription>,
	pub link: Link,
	pub key: Secret<32>,
	pub store_key: String,
	pub kept: Kept,
	pub commands: mpsc::UnboundedReceiver<Command>,
	pub from_platform: mpsc::Receiver<Vec<u8>>,
	pub to_platform: mpsc::Sender<Vec<u8>>,
	pub status: watch::Sender<Status>,
	pub events: broadcast::Sender<Event>,
	pub refused: Arc<AtomicU64>,
	/// The user said yes to "this profile connects to a private address" for this start.
	pub private: bool,
}

pub(crate) struct Core {
	pub settings: Settings,
	/// The device's own networks as they are now: the list of `Settings` at the start, and the one `Tunnel::moved` gave after.
	pub networks: Vec<OwnNetwork>,
	/// With the user's yes to a private address, a private address inside the device's own networks is dialled like any other private one. A public address inside them is skipped at every connect, yes or not: a network that claims a public address as its own is the TunnelCrack LocalNet attack.
	pub consented: bool,
	pub profile: Profile,
	pub subscription: Arc<Subscription>,
	pub link: Link,
	pub transports: Vec<Transport>,
	pub digest: u64,
	pub store_key: String,
	pub net_key: String,
	pub seed: u64,
	pub wire: Shared,
	pub network: Network,
	pub standing: Standing,
	pub kept: Kept,
	pub offset: Arc<AtomicI64>,
	pub status: Status,
	pub status_tx: watch::Sender<Status>,
	pub events: broadcast::Sender<Event>,
	pub refused: Arc<AtomicU64>,
	pub commands: mpsc::UnboundedReceiver<Command>,
	pub from_platform: mpsc::Receiver<Vec<u8>>,
	pub to_platform: mpsc::Sender<Vec<u8>>,
	pub counters: Counters,
	pub hold: Option<Hold>,
	pub rounds: u32,
	pub connected_once: bool,
	pub reason: Option<Say>,
	pub warn: Option<Say>,
	pub wanted: Option<Option<String>>,
	pub reprobe: bool,
	/// Messages a test handed the tunnel, read as the node's at the next tick.
	#[cfg(feature = "testing")]
	pub injected: Vec<veilway_proto::control::NodeMessage>,
}

// How many candidates a transport of a profile lists.
fn count(transport: &Transport) -> usize {
	match transport {
		Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) => endpoints.len(),
		Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => stream.candidates.len(),
	}
}

// What the user is told of how an attempt or a session ended, if it is worth telling.
fn say_of(ended: &Ended) -> Option<Say> {
	match ended {
		Ended::Refused(refusal) if refusal.offset.is_some_and(|offset| offset.unsigned_abs() > 60) => Some(Say::ClockWrong),
		Ended::Refused(_) => Some(Say::Refused),
		Ended::Unreachable(Unreachable::Certificate) => Some(Say::CertificateMismatch),
		Ended::Unreachable(Unreachable::CertificateTime) => Some(Say::CertificateTime),
		Ended::Unreachable(Unreachable::Silence) => Some(Say::Silence),
		Ended::Unreachable(_) => Some(Say::Unreachable),
		Ended::Closed(End::Offline) => Some(Say::Offline),
		Ended::Closed(End::Random | End::Source) => Some(Say::Random),
		Ended::Closed(End::Unanswered | End::Asked) => None,
		Ended::Closed(_) => Some(Say::Lost),
	}
}

// A pick that was never opened gives its place in the hour's budget back, but only if the very call to `choice::candidates` that picked it added the place: a candidate that was dialled earlier in the hour keeps its place, or a seventh distinct candidate could be dialled inside the hour.
fn untracked(network: &mut Network, transport: usize, candidate: usize, added: &[usize]) {
	if added.contains(&candidate) {network.tried.retain(|(at, tried, _)| (*at, *tried) != (transport, candidate))}
}

// Whether a candidate is passed for being inside the device's own networks. The user's yes to a private address covers a candidate that is private itself, and never a public one.
fn skipped(consented: bool, address: &Dial, networks: &[OwnNetwork]) -> bool {address.own(networks) && !(consented && address.private())}

impl Core {
	pub(crate) fn new(parts: Parts) -> Self {
		let Parts {settings, profile, subscription, link, key, store_key, kept, commands, from_platform, to_platform, status, events, refused, private} = parts;
		let (transports, seed) = (profile.transports.clone(), settings.store.seed());
		let net_key = crate::store::network_key(seed, &settings.network);
		let wire = Shared::new(Wire::new(key, link.inbound, profile.device.preshared_key.clone()));
		let initial = status.borrow().clone();
		Self {consented: private, networks: settings.networks.clone(), digest: choice::digest(&transports), network: kept.network(&net_key), standing: kept.standing.clone(), net_key, transports, seed, wire, offset: Arc::new(AtomicI64::new(0)), status: initial, status_tx: status, events, refused, commands, from_platform, to_platform, counters: Counters::default(), hold: None, rounds: 0, connected_once: false, reason: None, warn: None, wanted: None, reprobe: false, #[cfg(feature = "testing")] injected: Vec::new(), settings, profile, subscription, link, store_key, kept}
	}
	pub(crate) fn unix(&self) -> u64 {(self.settings.clock)()}
	// The device's clock and the offset a pinned candidate's answer gave, which is what proofs are made with.
	fn env(&self) -> Env {
		let (device, offset) = (self.settings.clock.clone(), self.offset.clone());
		Env {now: Arc::new({
			let device = device.clone();
			move || device().saturating_add_signed(offset.load(Ordering::Relaxed))
		}), device, roots: self.settings.roots.clone(), socket: self.settings.socket.clone()}
	}
	fn offset_update(&self, now: u64) {self.offset.store(choice::clock(now, &self.standing) as i64 - now as i64, Ordering::Relaxed)}
	pub(crate) fn publish(&mut self) {
		self.status.counters = self.counters;
		self.status.counters.dropped_full += self.refused.load(Ordering::Relaxed);
		self.status.say = self.reason.or(self.warn);
		self.status_tx.send_if_modified(|status| {
			let changed = *status != self.status;
			if changed {*status = self.status.clone()}
			changed
		});
	}
	/// Moves the tunnel to a state and says so at info.
	pub(crate) fn change(&mut self, state: State, reason: Option<Say>) {
		if self.status.state != state || self.reason != reason {tracing::info!(?state, ?reason, "tunnel state");}
		match &state {
			State::Off | State::Failed | State::Stopped {..} => self.status.connection = None,
			State::Connecting {..} | State::Reconnecting {..} => if let Some(connection) = &mut self.status.connection {connection.since = None},
			State::Connected {..} => {}
		}
		self.status.state = state;
		self.reason = reason;
		self.publish();
	}
	// The state of a tunnel that has no session, as the user sees it: a first connection or a lost one.
	pub(crate) fn connecting(&self, attempt: Option<Attempt>, wait: Option<u64>) -> State {if self.connected_once {State::Reconnecting {attempt, wait}} else {State::Connecting {attempt, wait}}}
	/// Writes what changed to the store, and the file in the background. The engine writes its own fields and no others: the user's answers (consent, a declined class, `stream_first`) are the store's, may have been changed while the tunnel ran, and are never written back from what the tunnel read at its start.
	pub(crate) fn save(&mut self) {
		self.kept.networks.retain(|(key, _)| *key != self.net_key);
		self.kept.networks.insert(0, (self.net_key.clone(), self.network.clone()));
		let (store, key, standing, networks, mtus) = (self.settings.store.clone(), self.store_key.clone(), self.standing.clone(), self.kept.networks.clone(), self.kept.mtus.clone());
		store.update(&key, |kept| {
			let consent = std::mem::take(&mut kept.standing.consent);
			(kept.standing, kept.networks, kept.mtus) = (standing, networks, mtus);
			kept.standing.consent = consent;
		});
		tokio::task::spawn_blocking(move || {
			if let Err(error) = flush(&store) {tracing::warn!(%error, "the saved state could not be written");}
		});
	}
	/// Reads the user's answers again, which they may have changed since the last look: from here on the plan, the fallback and the choice of a transport are made under them.
	pub(crate) fn answers(&mut self) {
		let (consent, declined, stream_first) = self.settings.store.answers(&self.store_key);
		(self.standing.consent, self.kept.declined, self.kept.stream_first) = (consent, declined, stream_first);
	}
	/// Whether a transport may be used now: it is of the best class the profile lists, or the user agreed to its class. Asked of the session in hand as well, so that a class withdrawn while the tunnel runs ends it.
	pub(crate) fn allowed(&self, transport: usize) -> bool {
		let class = choice::class(&self.transports[transport]);
		self.transports.iter().map(choice::class).min().is_some_and(|best| class == best) || self.standing.consent.contains(&class)
	}
	pub(crate) fn stream_first(&self) -> bool {self.kept.stream_first.unwrap_or(self.profile.stream_first)}
	fn sleep(&self, wait: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
		if let Some(pause) = &self.settings.hooks.pause {return pause(wait)}
		Box::pin(tokio::time::sleep(wait))
	}
	/// What a command does to the loop. The state it changes is the loop's own, and what it asks for is read at the next look.
	pub(crate) fn command(&mut self, command: Command) -> Reaction {
		match command {
			Command::Stop => Reaction::Stop,
			Command::Again => {
				choice::reset(&mut self.network, &mut self.standing);
				self.hold = None;
				tracing::info!("the user asks to connect again: marks, counts and waits start over");
				Reaction::Again
			}
			Command::Exit(tag) => {
				self.wanted = Some(tag);
				Reaction::None
			}
			Command::Moved(description, networks) => {
				self.save();
				self.net_key = crate::store::network_key(self.seed, &description);
				(self.network, self.networks) = (self.kept.network(&self.net_key), networks);
				tracing::info!("the device's network changed");
				Reaction::Moved
			}
			#[cfg(feature = "testing")]
			Command::Inject(message) => {
				self.injected.push(message);
				Reaction::None
			}
			Command::Reprobe => {
				self.reprobe = true;
				Reaction::None
			}
			Command::Refreshed(usage) => {
				let now = self.unix();
				let released = match (self.hold, usage) {
					(Some(Hold {stop: Stop::Quota, ..}), Some(usage)) => usage.quota_bytes == 0 || usage.used_bytes < usage.quota_bytes,
					(Some(Hold {stop: Stop::Expired, ..}), Some(usage)) => usage.expires_at == 0 || usage.expires_at > now,
					_ => false,
				};
				if released {
					self.hold = None;
					tracing::info!("a refreshed subscription shows that the node's reason for stopping is gone");
					Reaction::Again
				} else {Reaction::None}
			}
		}
	}
	/// Waits, and keeps the platform's queue empty meanwhile: nothing it hands in goes anywhere while there is no session.
	pub(crate) async fn rest(&mut self, wait: Duration) -> Rested {
		let mut sleep = self.sleep(wait);
		loop {
			tokio::select! {
				_ = &mut sleep => return Rested::Done,
				command = self.commands.recv() => match command.map_or(Reaction::Stop, |command| self.command(command)) {
					Reaction::Stop => return Rested::Stop,
					Reaction::Again | Reaction::Moved => return Rested::Again,
					Reaction::None => {}
				},
				Some(_) = self.from_platform.recv() => self.counters.dropped_offline += 1,
			}
		}
	}
	/// The state of the tunnel while it waits `wait` for the next try, with the reason it is shown.
	async fn waits(&mut self, wait: Duration, reason: Option<Say>) -> Rested {
		let until = self.unix() + wait.as_secs();
		let state = self.connecting(None, Some(until));
		self.change(state, reason);
		self.rest(wait).await
	}
	pub(crate) async fn run(mut self) {
		let state = self.connecting(None, None);
		self.change(state, None);
		self.campaign().await;
		self.change(State::Off, None);
		self.save();
		let store = self.settings.store.clone();
		let _ = tokio::task::spawn_blocking(move || flush(&store)).await;
	}
	// The loop: rounds of transports, each with its candidates, until the user stops it.
	async fn campaign(&mut self) {
		'campaign: loop {
			if self.hold.is_some() {
				let rested = self.hold_wait().await;
				self.hold = None;
				if rested == Rested::Stop {return}
			}
			self.answers();
			let plan = choice::plan(&self.transports, self.stream_first(), &self.network, &self.standing, self.unix());
			if plan.order.is_empty() {
				self.change(State::Failed, Some(Say::NothingToTry));
				match self.rest(Duration::from_secs(365 * 86_400)).await {
					Rested::Stop => return,
					_ => continue 'campaign,
				}
			}
			let mut tried = 0u32;
			for transport in plan.order.iter().copied() {
				tried += 1;
				let (candidates, mut retry, mut added) = (count(&self.transports[transport]), Vec::new(), Vec::<usize>::new());
				// "Skipped at each connect: an address inside one of the device's own networks", unless the user agreed to a private address for this profile. They are passed before a pick is made, so that they take no place of the hour's budget and no attempt is counted for them.
				let mut passed: Vec<usize> = (0..candidates).filter(|candidate| self.own(transport, *candidate)).collect();
				if self.consented && !passed.is_empty() {tracing::info!(transport, ?passed, "a public address inside the device's own networks is not dialled, even after the yes to a private address: the network claims it as its own")}
				let unreachable = loop {
					// A class the user withdrew since the last look is not used for the next attempt.
					self.answers();
					if !self.allowed(transport) {continue 'campaign}
					let picks: Vec<usize> = if retry.is_empty() {
						let now = self.unix();
						let known: Vec<usize> = self.network.tried.iter().filter(|(at, _, _)| *at == transport).map(|(_, tried, _)| *tried).collect();
						match choice::candidates(&mut self.network, self.digest, transport, candidates, &passed, plan.order.len() == 1, self.seed, now) {
							Pick::Try(picks) => {
								added = picks.iter().copied().filter(|pick| !known.contains(pick)).collect();
								picks
							}
							Pick::Wait(until) => {
								let wait = Duration::from_secs(until.saturating_sub(self.unix()).clamp(1, HOUR));
								match self.waits(wait, Some(Say::BudgetSpent)).await {
									Rested::Stop => return,
									Rested::Again => continue 'campaign,
									Rested::Done => continue,
								}
							}
							Pick::Passed => break false,
							Pick::Nothing => break true,
						}
					} else {
						added.clear();
						std::mem::take(&mut retry)
					};
					let picks: Vec<usize> = picks.into_iter().filter(|pick| !self.own(transport, *pick)).collect();
					if picks.is_empty() {continue}
					let done = self.attempt(transport, picks, &added).await;
					match done.why {
						Why::Stop => return,
						Why::Again | Why::Bye => continue 'campaign,
						Why::Over => {}
					}
					let mut wait = Duration::ZERO;
					for (candidate, ended) in done.ended.iter().copied() {
						let next = match self.settle(transport, candidate, ended) {
							Ok(next) => next,
							Err(_) => {
								self.change(State::Failed, Some(Say::Random));
								match self.rest(Duration::from_secs(365 * 86_400)).await {
									Rested::Stop => return,
									_ => continue 'campaign,
								}
							}
						};
						match next {
							Next::Again(after) => {
								retry.push(candidate);
								wait = wait.max(after);
							}
							Next::Move(after) => {
								if matches!(ended, Ended::Refused(_)) {passed.push(candidate)}
								wait = wait.max(after);
							}
							Next::Rest => {}
						}
					}
					if done.say.is_some() {self.reason = done.say}
					// On the last transport the marks of its candidates are passed over and a candidate that failed at once comes straight back: an attempt that did not open waits at least the wait between transports, or a refused connection would be made again at once and for ever. Only the one retry of a node that forgot the tunnel goes at once.
					if wait.is_zero() && plan.order.len() == 1 && !done.opened && !done.ended.iter().any(|(_, ended)| *ended == Ended::Closed(End::Unanswered)) {wait = choice::transport_wait(&mut random).unwrap_or(Duration::from_secs(2))}
					self.save();
					if wait > Duration::ZERO {
						match self.waits(wait, self.reason).await {
							Rested::Stop => return,
							Rested::Again => continue 'campaign,
							Rested::Done => {}
						}
					}
				};
				let now = self.unix();
				let wait = choice::fallback(&mut self.network, self.digest, &plan.order, transport, unreachable, tried, self.rounds + 1, now, &mut random).unwrap_or(Duration::from_secs(30));
				self.save();
				match self.waits(wait, self.reason).await {
					Rested::Stop => return,
					Rested::Again => continue 'campaign,
					Rested::Done => {}
				}
			}
			self.rounds = self.rounds.saturating_add(1);
		}
	}
	// A stop by the node: the loop does nothing until its reason is gone, the user asks, or the time the reason names has come.
	async fn hold_wait(&mut self) -> Rested {
		let Some(hold) = self.hold else {return Rested::Done};
		self.change(State::Stopped {reason: hold.stop, retry: hold.until.map_or(Retry::Asked, Retry::At)}, Some(hold.stop.say()));
		let wait = hold.until.map_or(Duration::from_secs(365 * 86_400), |until| Duration::from_secs(until.saturating_sub(self.unix())));
		self.rest(wait).await
	}
	pub(crate) fn own(&self, transport: usize, candidate: usize) -> bool {
		let found = match &self.transports[transport] {
			Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) => endpoints.get(candidate).map(|dial| skipped(self.consented, dial, &self.networks)),
			Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => stream.candidates.get(candidate).map(|found| skipped(self.consented, &found.address, &self.networks)),
		};
		found.unwrap_or(false)
	}
	// A candidate that was picked and never opened has not been tried: it takes no place of the hour's budget.
	pub(crate) fn untrack(&mut self, transport: usize, candidate: usize, added: &[usize]) {untracked(&mut self.network, transport, candidate, added)}
	// Takes in how an attempt or a session ended: what `choice` remembers of it, the counters, and the reason the user is shown.
	pub(crate) fn settle(&mut self, transport: usize, candidate: usize, ended: Ended) -> Result<Next, veilway_proto::NoRandom> {
		let now = self.unix();
		let next = choice::outcome(&mut self.network, &mut self.standing, self.digest, transport, candidate, Some(ended), now, &mut random);
		self.offset_update(now);
		self.account(&ended, candidate, transport);
		// "The node no longer knows the tunnel, as after its restart": the next attempt opens with a handshake initiation. So does the one after silence on a datagram transport, which the page treats as a block or a node that is down: if the node was restarted, a keepalive of a tunnel it forgot would be silence again for as long as it is tried, and an initiation costs nothing.
		if matches!(ended, Ended::Closed(End::Unanswered) | Ended::Unreachable(Unreachable::Silence)) {self.wire.lock().fresh()}
		next
	}
	// What an attempt that ended is added to: the counters, the user's reason, and the mark's line in the log.
	fn account(&mut self, ended: &Ended, candidate: usize, transport: usize) {
		match ended {
			Ended::Refused(_) => self.counters.refused += 1,
			Ended::Unreachable(_) | Ended::Closed(End::Unanswered) => {
				self.counters.unreachable += 1;
				self.counters.set_aside += 1;
			}
			Ended::Closed(End::Offline) => self.counters.offline += 1,
			Ended::Closed(End::Asked) => {}
			Ended::Closed(_) => self.counters.lost += 1,
		}
		if let Some(say) = say_of(ended) {self.reason = Some(say)}
		tracing::info!(transport, candidate, ?ended, "an attempt ended");
	}
	fn open(&self, transport: usize, candidate: usize, env: &Env) -> Result<Session, Ended> {
		#[allow(unused_mut)]
		let Some(mut target) = Target::of(&self.transports[transport], candidate) else {return Err(Ended::Unreachable(Unreachable::Connect))};
		if let Some(redirect) = &self.settings.hooks.redirect {
			match &mut target {
				Target::UdpObfs(address) => *address = redirect(*address),
				Target::Tls {candidate, ..} | Target::Ws {candidate, ..} | Target::Fronted {candidate, ..} => candidate.address = redirect(candidate.address),
			}
		}
		Session::parallel(&self.link, target, self.profile.parallel, env.clone(), self.wire.source()).map_err(|refuse| {
			tracing::warn!(transport, candidate, ?refuse, "a candidate cannot be dialled as the profile has it");
			// A root store that is empty is a fault of the device, and no verdict on a candidate.
			if refuse == Refuse::Roots {Ended::Closed(End::Offline)} else {Ended::Unreachable(Unreachable::Connect)}
		})
	}
	// The socket of a candidate of plain `udp`, made by the transport library's own function: let through the hook before it is connected, and with fragmentation of what it sends prohibited where the system has the option.
	async fn plain(&self, transport: usize, candidate: usize) -> Result<UdpSocket, Ended> {
		let Transport::Udp(endpoints) = &self.transports[transport] else {return Err(Ended::Unreachable(Unreachable::Connect))};
		#[allow(unused_mut)]
		let Some(mut to) = endpoints.get(candidate).map(|endpoint| endpoint.address()) else {return Err(Ended::Unreachable(Unreachable::Connect))};
		if let Some(redirect) = &self.settings.hooks.redirect {to = redirect(to)}
		veilway_transport::udp::bound(to, &self.settings.socket).await.map_err(|_| Ended::Closed(End::Offline))
	}
	// One attempt: one candidate, or two raced. A candidate that wins is carried for as long as its session lasts.
	async fn attempt(&mut self, transport: usize, picks: Vec<usize>, added: &[usize]) -> Done {
		let state = self.connecting(Some(Attempt {transport, candidates: picks.clone()}), None);
		self.status.connection = Connection::of(&self.transports[transport], picks[0]);
		self.change(state, self.reason);
		if matches!(self.transports[transport], Transport::Udp(_)) {
			// One socket and one session: a second pick is not tried, and takes no place of the hour's budget.
			let candidate = picks[0];
			for other in &picks[1..] {self.untrack(transport, *other, added)}
			self.counters.attempts += 1;
			self.publish();
			let carrier = match self.plain(transport, candidate).await {
				Ok(socket) => Carrier::Plain(socket, vec![0u8; 65_536]),
				Err(ended) => return Done {ended: vec![(candidate, ended)], why: Why::Over, say: None, opened: false},
			};
			// The first datagram is sent at once, and the session is opened when a datagram of the node has authenticated.
			let first = self.wire.lock().want(veilway_transport::Want::First);
			if let (Carrier::Plain(socket, _), Some(first)) = (&carrier, first) {let _ = socket.send(&first).await;}
			return self.carried(carrier, transport, candidate, false, Vec::new()).await;
		}
		let env = self.env();
		self.wire.lock().race();
		let (mut racers, mut ended, mut second, mut stagger) = (Vec::<(usize, Session)>::new(), Vec::new(), picks.get(1).copied(), Box::pin(tokio::time::sleep(STAGGER)));
		self.counters.attempts += 1;
		self.publish();
		match self.open(transport, picks[0], &env) {
			Ok(session) => racers.push((picks[0], session)),
			Err(error) => ended.push((picks[0], error)),
		}
		let mut winner = None;
		loop {
			let mut at = 0;
			while at < racers.len() {
				match racers[at].1.state() {
					Opened::Established if winner.is_none() => {
						winner = Some(at);
						at += 1;
					}
					Opened::Ended(error) => {
						let (candidate, _) = racers.remove(at);
						ended.push((candidate, error));
						if winner.is_some_and(|won| won >= at) {winner = winner.map(|won| won - 1)}
					}
					_ => at += 1,
				}
			}
			if winner.is_some() || (racers.is_empty() && second.is_none()) {break}
			// A class the user withdrew during the attempt is not dialled on: what is open is dropped and the loop plans again.
			self.answers();
			if !self.allowed(transport) {
				self.wire.lock().settle();
				if let Some(unopened) = second {self.untrack(transport, unopened, added)}
				return Done {ended: Vec::new(), why: Why::Again, say: None, opened: false};
			}
			// The sessions are looked at again every 20 ms, and the second candidate is opened when its stagger is over.
			tokio::select! {
				_ = tokio::time::sleep(Duration::from_millis(20)) => {}
				_ = &mut stagger, if second.is_some() => {
					let candidate = second.take().unwrap_or_default();
					self.counters.attempts += 1;
					self.publish();
					match self.open(transport, candidate, &env) {
						Ok(session) => racers.push((candidate, session)),
						Err(error) => ended.push((candidate, error)),
					}
				}
				command = self.commands.recv() => match command.map_or(Reaction::Stop, |command| self.command(command)) {
					// A network that changed in the middle of a race ends it: what the candidates met was on the network before, and the next attempt is made under the new one.
					reaction @ (Reaction::Stop | Reaction::Again | Reaction::Moved) => {
						self.wire.lock().settle();
						if let Some(unopened) = second {self.untrack(transport, unopened, added)}
						return Done {ended: Vec::new(), why: if reaction == Reaction::Stop {Why::Stop} else {Why::Again}, say: None, opened: false};
					}
					Reaction::None => {}
				},
				Some(_) = self.from_platform.recv() => self.counters.dropped_offline += 1,
			}
		}
		self.wire.lock().settle();
		let Some(winner) = winner else {return Done {ended, why: Why::Over, say: None, opened: false}};
		// "That candidate wins and the other is closed."
		let (candidate, session) = racers.swap_remove(winner);
		drop(racers);
		// What the other candidate met is taken in now and not when the session ends, so that a mark does not wait for a session that may last for days.
		if let Some(unopened) = second {self.untrack(transport, unopened, added)}
		for (other, error) in ended {
			if self.settle(transport, other, error).is_err() {tracing::warn!("the random source failed while an attempt was taken in");}
		}
		self.save();
		self.carried(Carrier::Native(session), transport, candidate, true, Vec::new()).await
	}
}

fn flush(store: &Store) -> std::io::Result<()> {store.flush()}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_pick_that_was_never_opened_gives_back_only_the_place_it_took() {
		let mut network = Network {tried: vec![(0, 1, 100), (0, 2, 200), (1, 1, 300)], ..Network::default()};
		// Candidate 1 of transport 0 was dialled earlier in the hour, and this pick only named it again.
		untracked(&mut network, 0, 1, &[2]);
		assert_eq!(network.tried.len(), 3);
		// Candidate 2 was added by this pick and was never opened.
		untracked(&mut network, 0, 2, &[2]);
		assert_eq!(network.tried, [(0, 1, 100), (1, 1, 300)]);
		// The same number in another transport is another candidate.
		untracked(&mut network, 0, 1, &[1]);
		assert_eq!(network.tried, [(1, 1, 300)]);
	}

	#[test]
	fn the_yes_to_a_private_address_dials_a_private_candidate_in_an_own_network_and_never_a_public_one() {
		let own = vec![OwnNetwork::new("10.99.0.7".parse().unwrap(), 24).unwrap(), OwnNetwork::new("203.0.114.9".parse().unwrap(), 24).unwrap()];
		let (private, public, elsewhere) = (Dial::parse("10.99.0.2:5002").unwrap(), Dial::parse("203.0.114.5:443").unwrap(), Dial::parse("10.50.0.2:5002").unwrap());
		assert!(skipped(false, &private, &own) && skipped(false, &public, &own));
		assert!(!skipped(true, &private, &own), "a private candidate in an own network is dialled after the yes");
		assert!(skipped(true, &public, &own), "a public candidate the network claims as its own stays skipped");
		assert!(!skipped(false, &elsewhere, &own) && !skipped(true, &elsewhere, &own));
	}
}
