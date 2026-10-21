//! The node's side of the control channel (protocol, "Control channel"): a TCP connection a device opens to the gateway address of a `veilway` inbound, inside its tunnel, and the UDP port next to it that takes MTU probes.
//! Who is asking is the device that holds the tunnel address the connection came from, in the tunnel it came through. Nothing a message says changes that. Every byte is read by `veilway-proto`, and what that crate leaves to its caller is enforced here: the two pools of connections, the deadline, the rate limits, the bounds of every value and the "Allowed" column.
//! A connection that breaks any of it is closed with no message and counted.
use super::icmp;
use super::netstack::Packet;
use super::plan::{Action, Backend, Device, Holder, Plan, User};
use super::route::{Decision, Key, CLOSED_IDLE};
use super::{Over, Shared};
use crate::config::{NoticeSeverity, Protocol, QuotaPeriod};
use etherparse::PacketBuilder;
use ipstack::{IpStackStream, TcpSendState};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Notify};
use veilway_proto::control::{self, kind, Addresses, ByeReason, ClientMessage, ErrorCode, ExitStatus, Load, NodeMessage, Period, Severity, Token, AUTHENTICATED, DEVICE_MTU_LIFE, MESSAGE_BURST, MESSAGE_REFILL, PORT, PREFACE, PROBES, PROBE_RUN_INTERVAL, PROBE_TOKEN_LIFE, SET_EXIT_BURST, SET_EXIT_REFILL, UNAUTHENTICATED};
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::{NodeOpening, OpenError, DEADLINE};
use veilway_proto::NoRandom;

/// How long one write to a connection may wait for the device to take it. A device that stops reading loses the connection and holds nothing else up.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the flow of an open connection is kept without a packet. The channel is silent while nothing changes, so this is far above any quiet time that means something.
const HELD: Duration = Duration::from_secs(30 * 86_400);
/// What waits for one connection from outside its own task: confirmations of probes, and the word that the node is stopping. One more is dropped.
const PUSHES: usize = PROBES + 1;
/// How often a connection whose next `usage` is due looks whether the numbers have changed.
const USAGE_LOOK: Duration = Duration::from_secs(1);
/// Lines one device can have written to the log at info at once, and how long it takes to earn one more, see `State::say`.
const SAID_BURST: u32 = 6;
const SAID_REFILL: Duration = Duration::from_secs(30);
/// How long a node that is stopping gives the `bye` of its open connections to leave.
pub(super) const BYE_WAIT: Duration = Duration::from_millis(100);

/// What the control channel did since the node started, as `Engine::control` gives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlTotals {
	/// TCP connections to the control port that the node took.
	pub accepted: u64,
	/// Connections that proved a transport secret of their device.
	pub authenticated: u64,
	/// Connections closed for a wrong credential, or for one made with a secret the config no longer has.
	pub auth_failed: u64,
	/// Connections closed for a wrong preface, an unknown type, a malformed body, a message that is not allowed where it came, or a value outside its bounds.
	pub malformed: u64,
	/// Connections closed because the opening exchange was not done in time.
	pub timed_out: u64,
	/// Connections closed to make room for a newer one of the same device.
	pub replaced: u64,
	/// Requests answered "rate limited".
	pub rate_limited: u64,
	/// `set_exit` requests that changed or cleared a device's exit, and those refused for a tag the user may not use or that no exit has.
	pub exits_selected: u64,
	pub exits_refused: u64,
	/// Selections dropped because a reload took the exit away from the user, or because the device's state file entry named no exit of theirs.
	pub exits_dropped: u64,
	/// MTU probe runs started, probes from devices that were confirmed, and probes the node sent.
	pub probe_runs: u64,
	pub probes_confirmed: u64,
	pub probes_sent: u64,
	/// UDP datagrams to the probe port that were no probe of a live run.
	pub probes_refused: u64,
	/// `set_mtu` requests that were taken.
	pub mtus_set: u64,
	/// `bye` messages written before a cut-off or a stop.
	pub byes: u64,
	/// Authenticated connections open right now.
	pub open: u64,
}

#[derive(Default)]
pub(super) struct Counters {accepted: AtomicU64, authenticated: AtomicU64, auth_failed: AtomicU64, malformed: AtomicU64, timed_out: AtomicU64, replaced: AtomicU64, rate_limited: AtomicU64, exits_selected: AtomicU64, exits_refused: AtomicU64, pub(super) exits_dropped: AtomicU64, probe_runs: AtomicU64, probes_confirmed: AtomicU64, probes_sent: AtomicU64, probes_refused: AtomicU64, mtus_set: AtomicU64, pub(super) byes: AtomicU64, open: AtomicU64}

/// What the engine's tasks share for the control channel.
pub(super) struct Channel {
	pub(super) counters: Counters,
	/// The generation of the plan in force. Every open connection looks at its snapshot again when it moves.
	pub(super) plans: watch::Sender<u64>,
	/// Moves when an exit starts or stops working between reloads, so that every open connection looks at its catalogue again.
	pub(super) health: watch::Sender<u64>,
	/// The devices with a connection or an MTU of their own, each with the last moment it was seen to have a WireGuard session. Only these are looked at when the engine sweeps.
	watched: Mutex<HashMap<[u8; 32], (Arc<State>, Instant)>>,
	/// `Options::usage_push`.
	usage_push: RangeInclusive<u32>,
}

impl Channel {
	pub(super) fn new(usage_push: RangeInclusive<u32>) -> Channel {Channel {counters: Counters::default(), plans: watch::Sender::new(0), health: watch::Sender::new(0), watched: Mutex::default(), usage_push}}

	/// When the next `usage` of a connection is due at the earliest: "not sooner than a time drawn uniformly from 30 to 90 s after the last one". A random source that fails gives the longest wait.
	fn next_usage(&self) -> Instant {Instant::now() + Duration::from_millis(veilway_proto::uniform(*self.usage_push.start(), *self.usage_push.end(), &mut random).unwrap_or(*self.usage_push.end()).into())}

	pub(super) fn totals(&self) -> ControlTotals {
		let (counters, load) = (&self.counters, |counter: &AtomicU64| counter.load(Ordering::Relaxed));
		ControlTotals {accepted: load(&counters.accepted), authenticated: load(&counters.authenticated), auth_failed: load(&counters.auth_failed), malformed: load(&counters.malformed), timed_out: load(&counters.timed_out), replaced: load(&counters.replaced), rate_limited: load(&counters.rate_limited), exits_selected: load(&counters.exits_selected), exits_refused: load(&counters.exits_refused), exits_dropped: load(&counters.exits_dropped), probe_runs: load(&counters.probe_runs), probes_confirmed: load(&counters.probes_confirmed), probes_sent: load(&counters.probes_sent), probes_refused: load(&counters.probes_refused), mtus_set: load(&counters.mtus_set), byes: load(&counters.byes), open: load(&counters.open)}
	}
}

/// What reaches a connection from outside its own task.
enum Push {
	/// A probe of the run this connection started came in.
	Ack {seq: u8, size: u16},
	/// The node is stopping.
	Bye(ByeReason),
}

/// So many at once, then one more each `refill`.
struct Bucket {left: u32, since: Instant}

impl Bucket {
	fn take(&mut self, burst: u32, refill: Duration) -> bool {
		let now = Instant::now();
		let earned = (now.saturating_duration_since(self.since).as_millis() / refill.as_millis().max(1)).min(u128::from(burst)) as u32;
		// What was earned is taken with the time it took, so the part of a refill that has passed already still counts towards the next one. A full bucket earns nothing while it is full.
		if earned > 0 {(self.left, self.since) = ((self.left + earned).min(burst), if self.left + earned >= burst {now} else {self.since + refill * earned})}
		if self.left == 0 {return false}
		self.left -= 1;
		true
	}
}

/// One connection of a device. `secret` is the transport secret it proved, None until it has. `stream` says where the stack stands on it, for the `bye` that `Host::switch` writes in the stack's place.
struct Conn {id: u64, flow: Key, secret: Option<[u8; 32]>, to: mpsc::Sender<Push>, closed: Arc<Notify>, stream: TcpSendState}

/// One MTU probe run: its token, the connection that asked for it with the gateway address that connection came to, and what is left of it. A probe counts only at that gateway, so a device with addresses in two inbounds probes the tunnel it asked about.
struct Run {token: Token, conn: u64, gateway: IpAddr, started: Instant, max: u16, up: usize, down: usize, to: mpsc::Sender<Push>}

/// What a device holds while it has connections. "Hold memory: a token, a selection, an MTU value and six connections per device."
/// `said` and `unsaid` bound what the device can have written to the log at info, see `State::say`. `outside` is the share of "too big" errors that packets from outside an `l3` exit may cause on the device's behalf, apart from the ICMP errors the device is sent itself.
struct Inner {waiting: VecDeque<Conn>, open: VecDeque<Conn>, next: u64, messages: Bucket, exits: Bucket, run: Option<Run>, said: Bucket, unsaid: u32, outside: icmp::Limit}

/// What the control channel keeps for one device. It belongs to the device's public key and goes from plan to plan with it, see `Plan::states`.
#[derive(Default)]
pub struct State {
	/// The tag of the exit the device chose for the action `"user"`. It is held against the plan in force whenever it is read, see `Plan::exit_of`, so a tag that is no exit of the user any more chooses nothing.
	selection: Mutex<Option<Arc<str>>>,
	/// The MTU the device set, 0 for none.
	mtu: AtomicU16,
	/// The identification of the next packet the node fragments for this device as its sender. It starts at a random value when the device sets an MTU, and it is the device's own: a counter shared by all devices would tell each of them how many packets of the others were fragmented.
	fragmented: AtomicU32,
	/// None until the device opens its first connection.
	inner: Mutex<Option<Box<Inner>>>,
}

impl State {
	/// A device the state file remembers an exit for.
	pub(super) fn remembered(exit: &str) -> State {State {selection: Mutex::new(Some(Arc::from(exit))), ..State::default()}}

	fn selection(&self) -> MutexGuard<'_, Option<Arc<str>>> {self.selection.lock().unwrap_or_else(|e| e.into_inner())}

	fn inner(&self) -> MutexGuard<'_, Option<Box<Inner>>> {self.inner.lock().unwrap_or_else(|e| e.into_inner())}

	/// The tag the device chose, whether or not it is an exit of the user under the plan in force.
	pub fn selected(&self) -> Option<Arc<str>> {self.selection().clone()}

	pub fn mtu(&self) -> Option<u16> {Some(self.mtu.load(Ordering::Relaxed)).filter(|mtu| *mtu != 0)}

	/// Authenticated connections the device has open.
	pub fn open(&self) -> usize {self.inner().as_ref().map_or(0, |inner| inner.open.len())}

	/// Where the stack stands on `flow` when that is an authenticated connection of the device: the sequence number of the next byte it would send, and the one it expects from the device.
	pub(super) fn last(&self, flow: &Key) -> Option<(u32, u32)> {self.inner().as_ref().and_then(|inner| inner.open.iter().find(|conn| conn.flow == *flow)).map(|conn| conn.stream.next())}

	/// The identification for one packet the node fragments for this device.
	pub(super) fn fragment(&self) -> u32 {self.fragmented.fetch_add(1, Ordering::Relaxed)}

	/// Whether one more "too big" error may go out to a sender beyond an `l3` exit for a packet that did not fit this device's MTU.
	pub(super) fn outside(&self) -> bool {self.inner().as_mut().is_some_and(|inner| inner.outside.take(Instant::now()))}

	/// Writes a line about something the device did. A device opens and closes connections, changes its exit and sets its MTU as often as the limits let it, so only so many of these lines are written at info: `SAID_BURST` at once, then one every `SAID_REFILL`.
	/// The rest go to debug, and the next line at info says how many there were.
	fn say(&self, line: &str) {
		let unsaid = self.inner().as_mut().map_or(Some(0), |inner| {
			if inner.said.take(SAID_BURST, SAID_REFILL) {Some(std::mem::take(&mut inner.unsaid))} else {
				inner.unsaid = inner.unsaid.saturating_add(1);
				None
			}
		});
		match unsaid {
			Some(0) => tracing::info!("{line}"),
			Some(unsaid) => tracing::info!("{line} ({unsaid} more lines about this device's control channel went to debug before this one)"),
			None => tracing::debug!("{line}"),
		}
	}

	/// Forgets a chosen exit that `plan` no longer lets `user` use, and says which it was. This is the one place a selection is dropped by anything but the device, and `Host::switch` calls it with `plan` already in force:
	/// a `set_exit` takes the plan in force with this same lock held, so it either wrote before this looked or decides by the plan this one decided by.
	pub(super) fn recheck(&self, plan: &Plan, user: &User) -> Option<Arc<str>> {
		let mut selection = self.selection();
		let kept = selection.as_ref().is_some_and(|tag| plan.exits.iter().position(|exit| *exit.tag == **tag).is_some_and(|exit| user.entitled.as_ref().is_none_or(|list| list.contains(&exit))));
		if kept {None} else {selection.take()}
	}

	/// Ends the connections that proved a secret which is not in `secrets` any more. How many that were.
	pub(super) fn revoke(&self, secrets: &[[u8; 32]]) -> usize {
		let mut inner = self.inner();
		let Some(inner) = inner.as_mut() else {return 0};
		let gone: Vec<&Conn> = inner.open.iter().filter(|conn| conn.secret.is_none_or(|secret| !secrets.contains(&secret))).collect();
		for conn in &gone {conn.closed.notify_one()}
		gone.len()
	}

	/// Tells every authenticated connection to say `bye` and go. How many were told.
	fn dismiss(&self, reason: ByeReason) -> usize {self.inner().as_ref().map_or(0, |inner| inner.open.iter().filter(|conn| conn.to.try_send(Push::Bye(reason)).is_ok()).count())}

	/// Drops the device's MTU and ends every connection it has: it has had no WireGuard session for `DEVICE_MTU_LIFE`, or it is no device of the config any more. Whether there was an MTU to drop.
	fn forget(&self) -> bool {
		if let Some(inner) = self.inner().as_ref() {
			for conn in inner.waiting.iter().chain(&inner.open) {conn.closed.notify_one()}
		}
		self.mtu.swap(0, Ordering::Relaxed) != 0
	}
}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| NoRandom)}

/// The smallest MTU of a device's tunnel: 1280 when it has an IPv6 address, as IPv6 needs, and 1080 when it has IPv4 addresses only.
fn floor(device: &Device) -> u16 {control::mtu_floor(device.addresses.iter().any(IpAddr::is_ipv6))}

/// One message appended to what a connection writes next. A message this crate cannot write is one no client would read: it is left out and said once, since nothing a device sent can cause it.
fn put(out: &mut Vec<u8>, message: &NodeMessage) {
	if let Err(e) = message.encode(out) {tracing::error!("control channel: a message of type {:#04x} could not be written and was left out: {e}", message.kind())}
}

/// The `usage` of a user as the control channel reports it. Times before 1970 are 0, which also means "none".
pub(super) fn usage(user: &User) -> control::Usage {
	let (totals, positive) = (user.state.traffic.totals(), |seconds: i64| u64::try_from(seconds).unwrap_or(0));
	control::Usage {
		used_bytes: user.state.used(),
		quota_bytes: user.quota.unwrap_or(0),
		period: match user.period {
			None => Period::None,
			Some(QuotaPeriod::Daily) => Period::Daily,
			Some(QuotaPeriod::Weekly) => Period::Weekly,
			Some(QuotaPeriod::Monthly) => Period::Monthly,
		},
		period_start: positive(user.state.since.load(Ordering::Relaxed)),
		expires_at: user.expires.map_or(0, positive),
		up_bytes: totals.up_bytes,
		down_bytes: totals.down_bytes,
	}
}

/// What a connection last sent of its snapshot, to tell what a reload changed for the device. `node_time` moves by itself and is not part of it.
#[derive(PartialEq)]
struct Sent {mtu: u16, v4: Option<Addresses<std::net::Ipv4Addr>>, v6: Option<Addresses<std::net::Ipv6Addr>>, exits: Vec<control::Exit>, notices: Vec<(NoticeSeverity, String)>}

/// What a `usage` push is held against: the user's bytes without those of the control channel itself, and what else the message says.
/// Without the first, each push would be the change that calls for the next, and so would every MTU probe, and an idle tunnel would carry a `usage` every minute.
struct Mark {carried: u64, used: u64, quota: u64, period: Period, start: u64, expires: u64}

impl Mark {
	fn of(user: &User, told: &control::Usage) -> Mark {Mark {carried: told.up_bytes.saturating_add(told.down_bytes).saturating_sub(user.state.control.load(Ordering::Relaxed)), used: told.used_bytes, quota: told.quota_bytes, period: told.period, start: told.period_start, expires: told.expires_at}}

	/// Whether the numbers are others than at `last`: the user carried something (a count that is lower is a packet of the channel that was not yet counted as its own when `last` was taken, never traffic that undid itself), their count was started over, or the config gave them another quota, period or expiry.
	fn moved(&self, last: &Mark) -> bool {self.carried > last.carried || self.used < last.used || (self.quota, self.period, self.start, self.expires) != (last.quota, last.period, last.start, last.expires)}
}

impl Shared {
	/// Counts `bytes` of an inner packet of the control channel for its user, next to the totals `spend` already counted it in.
	pub(super) fn own(&self, user: &User, bytes: usize) {user.state.control.fetch_add(bytes as u64, Ordering::Relaxed);}

	/// The devices that have a connection or an MTU of their own are looked at once a second: one that is no device of the config any more, or that has had no WireGuard session for `DEVICE_MTU_LIFE`, loses both.
	pub(super) fn tend(&self) {
		let (plan, now) = (self.plan(), Instant::now());
		self.control.watched.lock().unwrap_or_else(|e| e.into_inner()).retain(|key, (state, seen)| {
			let device = plan.by_key.get(key).map(|at| &plan.devices[*at]);
			let live = device.is_some_and(|device| device.inbounds.iter().any(|at| {
				let peers = plan.inbounds[*at].tunnel.lock();
				peers.wg.index(key).is_some_and(|peer| peers.wg.time_since_last_handshake(peer).is_some())
			}));
			if live {*seen = now}
			if (device.is_none() || now.saturating_duration_since(*seen) >= DEVICE_MTU_LIFE) && state.forget() {
				if let Some(device) = device {tracing::info!("user {} device {}: no wireguard session for {}s, so the mtu it set is forgotten and its tunnel has the mtu of its inbound again", plan.users[device.user].name, device.name, DEVICE_MTU_LIFE.as_secs())}
			}
			state.mtu().is_some() || state.inner().as_ref().is_some_and(|inner| !inner.waiting.is_empty() || !inner.open.is_empty())
		});
	}

	/// Tells every open connection that the node is stopping. How many were told.
	pub(super) fn dismiss(&self) -> usize {self.control.watched.lock().unwrap_or_else(|e| e.into_inner()).values().map(|(state, _)| state.dismiss(ByeReason::Stopping)).sum()}

	/// A device that was removed and added again has another state than the one that was watched, and that one is the one to look at from here on.
	fn watch(&self, device: [u8; 32], state: &Arc<State>) {
		let mut watched = self.control.watched.lock().unwrap_or_else(|e| e.into_inner());
		if !watched.get(&device).is_some_and(|(was, _)| Arc::ptr_eq(was, state)) {watched.insert(device, (state.clone(), Instant::now()));}
	}

	/// What `plan` has the channel say to the device `from`: its `session`, its catalogue and the notices. The catalogue holds the exits of the user's `exits` and nothing of how any of them leaves.
	fn snapshot(&self, plan: &Plan, from: Holder) -> Sent {
		let (device, inbound) = (&plan.devices[from.device], &plan.inbounds[from.inbound]);
		let (user, chosen) = (&plan.users[device.user], device.control.selected());
		let pair = |v4: bool| device.addresses.iter().copied().find(|address| address.is_ipv4() == v4 && inbound.pools.iter().any(|pool| pool.contains(address))).zip(inbound.pools.iter().map(|pool| pool.addr()).find(|gateway| gateway.is_ipv4() == v4));
		// "The user's configured exit" is the exit a device without a selection leaves through: the user's `exit`, or `routing.default` for a user without one, and while that is not working the exit of `routing.fallback` it leaves through instead.
		let configured = plan.automatic(device.user);
		Sent {
			mtu: plan.mtu_of(from),
			v4: if let Some((IpAddr::V4(device), IpAddr::V4(gateway))) = pair(true) {Some(Addresses {device, gateway})} else {None},
			v6: if let Some((IpAddr::V6(device), IpAddr::V6(gateway))) = pair(false) {Some(Addresses {device, gateway})} else {None},
			exits: plan.exits.iter().enumerate().filter(|(at, _)| user.entitled.as_ref().is_none_or(|list| list.contains(at))).map(|(at, exit)| control::Exit {
				tag: exit.tag.clone(),
				name: exit.name.as_str().into(),
				country: exit.country,
				all_protocols: matches!(exit.backend, Backend::L3 {..}),
				selected: chosen.as_deref() == Some(exit.tag.as_str()),
				configured: at == configured,
				working: plan.working(at),
				// Nothing measures load yet.
				load: Load::Unknown,
			}).collect(),
			notices: plan.notices.clone(),
		}
	}

	/// One UDP datagram a device sent to the probe port of its gateway: a probe of its live run is confirmed on the connection that started the run, and anything else is counted and gets nothing. No UDP ever leaves in answer.
	pub(super) fn probed(&self, plan: &Plan, from: Holder, raw: &[u8], packet: &Packet) {
		let (counters, device) = (&self.control.counters, &plan.devices[from.device]);
		self.own(&plan.users[device.user], raw.len());
		// The size of a probe is that of its whole IP packet, and a packet with options or extension headers has not the payload a probe of its size has, so `read_probe` refuses it.
		let confirmed = u16::try_from(raw.len()).ok().and_then(|size| control::read_probe(raw.get(packet.upper + 8..)?, size, packet.src.is_ipv6()).ok().map(|(token, seq)| (token, seq, size))).is_some_and(|(token, seq, size)| {
			let mut inner = device.control.inner();
			let Some(run) = inner.as_mut().and_then(|inner| inner.run.as_mut()).filter(|run| run.token == token && run.gateway == packet.dst && run.started.elapsed() < PROBE_TOKEN_LIFE && run.up < PROBES && (floor(device)..=run.max).contains(&size)) else {return false};
			run.up += 1;
			run.to.try_send(Push::Ack {seq, size}).is_ok()
		});
		(if confirmed {&counters.probes_confirmed} else {&counters.probes_refused}).fetch_add(1, Ordering::Relaxed);
	}

	/// The action the rules of `plan` give a flow of `user` that came in on inbound `at`. `names` is what the user had resolved to the destination when the flow began.
	pub(super) fn action<'a>(&self, plan: &'a Plan, at: usize, user: usize, key: &Key, names: &[Arc<str>]) -> &'a Action {
		let icmp = (key.protocol == Protocol::ICMP || key.protocol == Protocol::ICMPV6).then_some((key.sport as u8, key.dport as u8));
		super::route::evaluate(plan, at, user, key.dst, key.protocol, if icmp.is_some() {0} else {key.dport}, icmp, &|patterns| names.iter().any(|name| patterns.iter().any(|pattern| pattern.matches(name))))
	}
}

/// Why a connection ended.
enum End {
	/// The device closed it, or stopped taking what the node writes.
	Peer,
	/// Its flow is gone: a reload or a cut-off ended it, or its device is no longer who it was.
	Gone,
	/// A newer connection took its place, the secret it proved was removed, or its device has no session any more.
	Closed,
	Auth,
	Malformed,
	Slow,
	/// The node said `bye`.
	Bye,
}

/// Runs one connection to the control port, which the stack accepted for the device with the public key `device`, to its end.
pub async fn serve(shared: Arc<Shared>, key: Key, id: u64, device: [u8; 32], stream: IpStackStream) {
	let IpStackStream::Tcp(mut stream) = stream else {return};
	let (plan, accepted, counters) = (shared.plan(), Instant::now(), &shared.control.counters);
	let Some(from) = plan.by_address.get(&key.src).copied().filter(|from| plan.devices[from.device].public_key == device && plan.control(from.inbound, key.dst)) else {return};
	let (state, secrets, tag, inbound) = (plan.devices[from.device].control.clone(), plan.devices[from.device].secrets.clone(), plan.inbounds[from.inbound].tag.clone(), plan.inbounds[from.inbound].public_key);
	let (who, mut reloads, mut health) = (format!("user {} device {}", plan.users[plan.devices[from.device].user].name, plan.devices[from.device].name), shared.control.plans.subscribe(), shared.control.health.subscribe());
	drop(plan);
	counters.accepted.fetch_add(1, Ordering::Relaxed);
	let ((to, mut pushes), closed, authenticated) = (mpsc::channel(PUSHES), Arc::new(Notify::new()), AtomicBool::new(false));
	// "Connections per device that have not authenticated: 4. A fifth replaces the oldest."
	let conn = {
		let mut inner = state.inner();
		let inner = inner.get_or_insert_with(|| Box::new(Inner {waiting: VecDeque::new(), open: VecDeque::new(), next: 0, messages: Bucket {left: MESSAGE_BURST, since: accepted}, exits: Bucket {left: SET_EXIT_BURST, since: accepted}, run: None, said: Bucket {left: SAID_BURST, since: accepted}, unsaid: 0, outside: icmp::Limit::new(accepted)}));
		inner.next += 1;
		if inner.waiting.len() >= UNAUTHENTICATED {
			if let Some(oldest) = inner.waiting.pop_front() {oldest.closed.notify_one()}
			counters.replaced.fetch_add(1, Ordering::Relaxed);
		}
		inner.waiting.push_back(Conn {id: inner.next, flow: key, secret: None, to: to.clone(), closed: closed.clone(), stream: stream.send_state()});
		inner.next
	};
	shared.watch(device, &state);
	shared.flows.hold(&key, id, DEADLINE + super::flows::HOLD_MARGIN);
	let end = async {
		let (mut buffer, mut out, mut opening, mut keys) = ([0u8; 256], Vec::new(), NodeOpening::new(Duration::ZERO), None::<Vec<ControlKey>>);
		// "Time to finish authentication: 10 s from the TCP accept on the node." A device that sends its bytes one at a time keeps the flow alive and not the exchange.
		let (opened, rest) = loop {
			tokio::select! {
				biased;
				_ = closed.notified() => return End::Closed,
				_ = shared.flows.quiet(key, id, HELD) => return End::Gone,
				_ = tokio::time::sleep_until((accepted + DEADLINE).into()) => return End::Slow,
				read = stream.read(&mut buffer) => {
					let Some(count) = read.ok().filter(|count| *count > 0) else {return End::Peer};
					let mut input = &buffer[..count];
					out.clear();
					// `k_ctl` is made for the device the connection came from and for the inbound it came through, so the secret of any other device proves nothing here.
					// It is made when the first bytes are those a client begins with, and not for a connection that says nothing or begins like a browser.
					if keys.is_none() && !PREFACE.starts_with(&input[..count.min(PREFACE.len())]) {return End::Malformed}
					let keys = keys.get_or_insert_with(|| secrets.iter().map(|secret| ControlKey::derive(secret, &inbound, &device)).collect());
					let step = opening.receive(accepted.elapsed(), keys, &mut input, &mut random, &mut out);
					let rest = input.to_vec();
					if !out.is_empty() && !tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&out)).await.is_ok_and(|done| done.is_ok()) {return End::Peer}
					match step {
						Ok(Some(opened)) => break (opened, rest),
						Ok(None) => {}
						Err(OpenError::Auth) => return End::Auth,
						Err(OpenError::Deadline) => return End::Slow,
						Err(_) => return End::Malformed,
					}
				}
			}
		};
		let (secret, mut messages) = (secrets[opened.key], opened.messages);
		// A reload may have taken the secret away while the exchange ran, and such a connection is one a stranger's would be. The plan in force is taken with the pools locked: `Host::switch` ends the connections of a removed secret after its plan is in force, so it either finds this one or this one finds its plan.
		// "Authenticated connections per device: 2. A third replaces the oldest."
		{
			let (mut inner, plan) = (state.inner(), shared.plan());
			let (Some(inner), true) = (inner.as_mut(), plan.by_key.get(&device).is_some_and(|at| plan.devices[*at].secrets.contains(&secret))) else {return End::Auth};
			let Some(mut entry) = inner.waiting.iter().position(|entry| entry.id == conn).and_then(|at| inner.waiting.remove(at)) else {return End::Closed};
			if inner.open.len() >= AUTHENTICATED {
				if let Some(oldest) = inner.open.pop_front() {oldest.closed.notify_one()}
				counters.replaced.fetch_add(1, Ordering::Relaxed);
			}
			entry.secret = Some(secret);
			inner.open.push_back(entry);
		}
		authenticated.store(true, Ordering::Relaxed);
		counters.authenticated.fetch_add(1, Ordering::Relaxed);
		counters.open.fetch_add(1, Ordering::Relaxed);
		state.say(&format!("{who}: control channel open through inbound {tag}"));
		shared.flows.hold(&key, id, HELD + super::flows::HOLD_MARGIN);
		let (mut sent, mut mark, mut usage_due, mut pending, mut doubted) = (None::<Sent>, None::<Mark>, Instant::now(), rest, false);
		// The first round sends the snapshot, unasked. After it every round waits for one thing, writes what it calls for, and looks at the plan in force anew.
		let mut wanted = Some(None::<ClientMessage>);
		loop {
			let plan = shared.plan();
			let Some(from) = plan.by_address.get(&key.src).copied().filter(|from| plan.devices[from.device].public_key == device && plan.control(from.inbound, key.dst)) else {return End::Gone};
			let user = &plan.users[plan.devices[from.device].user];
			out.clear();
			match wanted.take() {
				// The whole snapshot: after the opening, and for a `refresh`.
				Some(None) | Some(Some(ClientMessage::Refresh)) => {
					let now = shared.snapshot(&plan, from);
					put(&mut out, &NodeMessage::Session(control::Session {node_time: u64::try_from((shared.now)().unix_timestamp()).unwrap_or(0), mtu: now.mtu, v4: now.v4, v6: now.v6}));
					match control::catalogue(&now.exits) {
						Ok(parts) => for part in &parts {put(&mut out, part)},
						Err(e) => tracing::error!("control channel: the exit catalogue of {who} could not be written and was left out: {e}"),
					}
					let told = usage(user);
					let marked = Mark::of(user, &told);
					put(&mut out, &NodeMessage::Usage(told));
					put(&mut out, &NodeMessage::Notices(now.notices.iter().map(|(severity, text)| control::Notice {severity: if *severity == NoticeSeverity::Warning {Severity::Warning} else {Severity::Information}, text: text.as_str().into()}).collect()));
					// "In version 1 the node may always send an empty list": nothing in this build knows the profile's candidates.
					put(&mut out, &NodeMessage::Hints(Vec::new()));
					(sent, mark, usage_due) = (Some(now), Some(marked), shared.control.next_usage());
				}
				Some(Some(ClientMessage::SetExit {tag: asked})) => {
					// Its own limit on top of the one for every message: "3 at once, then 1 every 5 s". A `set_exit` over it is answered with the status made for it, not with `error`.
					let within = state.inner().as_mut().is_some_and(|inner| inner.exits.take(SET_EXIT_BURST, SET_EXIT_REFILL));
					if !within {
						counters.rate_limited.fetch_add(1, Ordering::Relaxed);
						put(&mut out, &NodeMessage::ExitResult {status: ExitStatus::RateLimited, tag: plan.chosen(from.device, state.selected().as_deref()).map_or_else(String::new, |exit| plan.exits[exit].tag.clone())});
					} else {
						// The plan in force is taken with the selection locked, which is what `State::recheck` counts on. `plan` may be the one before it.
						let (status, now) = {
							let (mut selection, plan) = (state.selection(), shared.plan());
							let Some(at) = plan.by_key.get(&device).copied() else {return End::Gone};
							// "Both cases look the same, so the channel does not reveal which tags exist."
							let allowed = asked.is_empty() || plan.chosen(at, Some(&asked)).is_some();
							if allowed {*selection = (!asked.is_empty()).then(|| Arc::from(asked.as_str()))}
							(if allowed {ExitStatus::Selected} else {ExitStatus::Refused}, plan.chosen(at, selection.as_deref()).map(|exit| plan.exits[exit].tag.clone()))
						};
						put(&mut out, &NodeMessage::ExitResult {status, tag: now.clone().unwrap_or_default()});
						if status == ExitStatus::Selected {
							// The device knows what it chose, so the catalogue is not sent again for it at the next reload. The state file takes the choice at its next write: one that is lost with a node that is killed before then costs a device one more `set_exit`,
							// and a write for every request would have every device rewrite the whole file as often as it likes.
							for exit in sent.iter_mut().flat_map(|sent| &mut sent.exits) {exit.selected = now.as_deref() == Some(exit.tag.as_str())}
							counters.exits_selected.fetch_add(1, Ordering::Relaxed);
							state.say(&format!("{who}: {}", now.as_ref().map_or_else(|| "its exit selection was cleared".to_string(), |tag| format!("exit {tag} selected"))));
							// "The node rechecks only that device's flows, at most 512, and does it without holding the flow table's lock for the whole check": the flows are copied out, judged against the rules with no lock held, and ended by key and id, which wakes their handlers and no other.
							// What ends is a flow the rules send to `"user"` that leaves through another exit than the device has now. A flow a rule pinned to a named exit is not touched, and neither is one that is on the right exit already.
							// A reload that came in between judged the flows by the selection before this one and moved the table on, and then the copy finds nothing: so it is done once more under the plan that is in force after it.
							let mut ended = 0;
							for _ in 0..2 {
								let plan = shared.plan();
								let Some(from) = plan.by_address.get(&key.src).copied().filter(|from| plan.devices[from.device].public_key == device) else {return End::Gone};
								let (user, leaves) = (plan.devices[from.device].user, plan.exit_of(from.device));
								let stale: Vec<(Key, u64)> = shared.flows.of(&device, plan.generation).into_iter().filter(|(flow, _, decision, names)| matches!(decision, Decision::Exit {exit, ..} if *exit != leaves) && plan.by_address.get(&flow.src).is_some_and(|holder| holder.device == from.device && matches!(shared.action(&plan, holder.inbound, user, flow, names), Action::User))).map(|(flow, entry, ..)| (flow, entry)).collect();
								let gone = shared.flows.end(&stale, plan.generation);
								ended += gone.len();
								for flow in &gone {
									let Some((holder, packet)) = super::host::farewell(&plan, flow) else {continue};
									// What the channel does to the device's flows is the channel's doing, and no traffic of the user's to push a `usage` for.
									shared.own(&plan.users[user], packet.len());
									shared.send(&plan, holder, &packet).await;
								}
								if shared.plan().generation == plan.generation {break}
							}
							if ended > 0 {state.say(&format!("{who}: {ended} flow(s) that followed its exit selection ended, and their next packets leave through the exit it has now"))}
						} else {counters.exits_refused.fetch_add(1, Ordering::Relaxed);}
					}
				}
				Some(Some(ClientMessage::ProbeStart)) => {
					// "It applies on `udp` and `udp-obfs`. On a stream transport nothing fragments, the node answers `probe_start` with `error` code 2." The two are named and everything else is refused, so a transport that is added later is refused until somebody decides otherwise: over a stream no probe is ever lost, and a run would put a burst of fixed sizes on a transport whose sizes are meant to say little.
					let datagram = {
						let peers = plan.inbounds[from.inbound].tunnel.lock();
						peers.wg.index(&device).and_then(|peer| peers.over(peer)).is_some_and(|over| matches!(over, Over::Udp | Over::UdpObfs))
					};
					let mut token = [0u8; 8];
					let started = datagram && random(&mut token).is_ok();
					// "1 per device per 60 s": a run that is open or began less than that ago is in the way of the next.
					let busy = started && state.inner().as_mut().is_none_or(|inner| {
						if inner.run.as_ref().is_some_and(|run| run.started.elapsed() < PROBE_RUN_INTERVAL) {return true}
						inner.run = Some(Run {token: Token(token), conn, gateway: key.dst, started: Instant::now(), max: plan.inbounds[from.inbound].mtu, up: 0, down: 0, to: to.clone()});
						false
					});
					if !started {put(&mut out, &NodeMessage::Error {code: ErrorCode::NotApplicable, answers: kind::PROBE_START})} else if busy {put(&mut out, &NodeMessage::Error {code: ErrorCode::Busy, answers: kind::PROBE_START})} else {
						counters.probe_runs.fetch_add(1, Ordering::Relaxed);
						put(&mut out, &NodeMessage::ProbeToken {token: Token(token), max_size: plan.inbounds[from.inbound].mtu});
					}
				}
				Some(Some(ClientMessage::ProbeDown {seq, size, port})) => {
					// "Only after a `probe_token` was received on this connection and while that token is live", and at most 16 in a run. The size is held to what the token said, and what is outside is no value of the field.
					let run = state.inner().as_mut().and_then(|inner| inner.run.as_mut()).filter(|run| run.conn == conn && run.started.elapsed() < PROBE_TOKEN_LIFE && run.down < PROBES).map(|run| {
						run.down += 1;
						(run.token, run.max)
					});
					match run {
						None => put(&mut out, &NodeMessage::Error {code: ErrorCode::NotApplicable, answers: kind::PROBE_DOWN}),
						// Control channel page, "MTU discovery": "the node accepts a `size` from the tunnel's smallest MTU to `max_size` and nothing else". The page names no answer for another size, so it is taken for a malformed body, and so is port 0, which no datagram can be sent to.
						Some((_, max)) if !(floor(&plan.devices[from.device])..=max).contains(&size) || port == 0 => return End::Malformed,
						Some((token, _)) => {
							// "A downstream probe goes only to the requesting device's own tunnel address": the address this connection came from, from the gateway it came to.
							let (mut payload, mut raw) = (Vec::new(), Vec::with_capacity(usize::from(size)));
							let built = control::probe(&token, seq, size, key.src.is_ipv6(), &mut payload).is_ok() && match (key.dst, key.src) {
								(IpAddr::V4(gateway), IpAddr::V4(address)) => PacketBuilder::ipv4(gateway.octets(), address.octets(), 64).udp(PORT, port).write(&mut raw, &payload).is_ok(),
								(IpAddr::V6(gateway), IpAddr::V6(address)) => PacketBuilder::ipv6(gateway.octets(), address.octets(), 64).udp(PORT, port).write(&mut raw, &payload).is_ok(),
								_ => false,
							};
							if built && raw.len() == usize::from(size) {
								counters.probes_sent.fetch_add(1, Ordering::Relaxed);
								shared.own(user, raw.len());
								// Whole, whatever MTU the device has set, and with no padding around it on `udp-obfs`: a probe that was cut to fit, or that left larger than it was made, would confirm nothing.
								shared.probe(&plan, from, &raw).await;
							}
						}
					}
				}
				Some(Some(ClientMessage::SetMtu {mtu})) => {
					// "`set_mtu` is accepted from the tunnel's smallest MTU to the inbound's `mtu`." One outside that changes nothing, and the answer says what is in force.
					if (floor(&plan.devices[from.device])..=plan.inbounds[from.inbound].mtu).contains(&mtu) {
						counters.mtus_set.fetch_add(1, Ordering::Relaxed);
						let was = state.mtu.swap(mtu, Ordering::Relaxed);
						// The identifications of the packets that are fragmented from here on start where nobody can guess.
						let mut start = [0u8; 4];
						if was == 0 && random(&mut start).is_ok() {state.fragmented.store(u32::from_be_bytes(start), Ordering::Relaxed)}
						if was != mtu {state.say(&format!("{who}: the mtu of its tunnel is {mtu} from here on, set by the device"))}
						shared.watch(device, &state);
					}
					// The device was told, so the next reload does not send it a `session` for this.
					if let Some(sent) = sent.as_mut() {sent.mtu = plan.mtu_of(from)}
					put(&mut out, &NodeMessage::MtuResult {mtu: plan.mtu_of(from)});
				}
				None => {}
			}
			drop(plan);
			if !out.is_empty() && !tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&out)).await.is_ok_and(|done| done.is_ok()) {return End::Peer}
			// What the device sent behind the message that was just answered comes first, one message at a time, so what the node holds for a connection is one answer.
			let mut input = &pending[..];
			match messages.read(&mut input) {
				Err(_) => return End::Malformed,
				Ok(Some(message)) => {
					pending = input.to_vec();
					// "Messages from one device: 10 at once, then 1 a second." One over it is answered with a 5 byte `error` and does nothing else.
					let within = state.inner().as_mut().is_some_and(|inner| inner.messages.take(MESSAGE_BURST, MESSAGE_REFILL));
					if within {wanted = Some(Some(message))} else {
						counters.rate_limited.fetch_add(1, Ordering::Relaxed);
						out.clear();
						put(&mut out, &NodeMessage::Error {code: ErrorCode::RateLimited, answers: message.kind()});
						if !tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&out)).await.is_ok_and(|done| done.is_ok()) {return End::Peer}
					}
					continue;
				}
				Ok(None) => pending.clear(),
			}
			out.clear();
			tokio::select! {
				biased;
				_ = closed.notified() => return End::Closed,
				_ = shared.flows.quiet(key, id, HELD) => return End::Gone,
				push = pushes.recv() => match push {
					Some(Push::Ack {seq, size}) => put(&mut out, &NodeMessage::ProbeAck {seq, size}),
					Some(Push::Bye(reason)) => {
						put(&mut out, &NodeMessage::Bye {reason});
						counters.byes.fetch_add(1, Ordering::Relaxed);
						let _ = tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&out)).await;
						return End::Bye;
					}
					None => return End::Closed,
				},
				// "A new `session`, `exits` or `notices` is sent when a reload changed it for this device", and only then, or when an exit started or stopped working.
				changed = async {tokio::select! {changed = reloads.changed() => changed.is_ok(), changed = health.changed() => changed.is_ok()}} => {
					if !changed {return End::Gone}
					let plan = shared.plan();
					let Some(from) = plan.by_address.get(&key.src).copied().filter(|from| plan.devices[from.device].public_key == device && plan.control(from.inbound, key.dst)) else {return End::Gone};
					let (now, was) = (shared.snapshot(&plan, from), sent.as_ref());
					if was.is_none_or(|was| (was.mtu, was.v4, was.v6) != (now.mtu, now.v4, now.v6)) {put(&mut out, &NodeMessage::Session(control::Session {node_time: u64::try_from((shared.now)().unix_timestamp()).unwrap_or(0), mtu: now.mtu, v4: now.v4, v6: now.v6}))}
					if was.is_none_or(|was| was.exits != now.exits) {
						if let Ok(parts) = control::catalogue(&now.exits) {
							for part in &parts {put(&mut out, part)}
						}
					}
					if was.is_none_or(|was| was.notices != now.notices) {put(&mut out, &NodeMessage::Notices(now.notices.iter().map(|(severity, text)| control::Notice {severity: if *severity == NoticeSeverity::Warning {Severity::Warning} else {Severity::Information}, text: text.as_str().into()}).collect()))}
					sent = Some(now);
				}
				// "The node sends a new `usage` when the numbers changed since the last one, and not sooner than the time in the table of numbers. Nothing is pushed while nothing changes."
				_ = tokio::time::sleep_until(usage_due.into()) => {
					let plan = shared.plan();
					let Some(user) = plan.by_key.get(&device).map(|at| &plan.users[plan.devices[*at].user]) else {return End::Gone};
					let told = usage(user);
					let now = Mark::of(user, &told);
					// A packet of the channel itself is counted for the user first and as the channel's own a moment later, and a look between the two takes it for the user's. So a change is believed when the next look still sees it.
					if mark.as_ref().is_some_and(|mark| !now.moved(mark)) || !std::mem::replace(&mut doubted, true) {
						doubted &= mark.as_ref().is_none_or(|mark| now.moved(mark));
						usage_due = Instant::now() + USAGE_LOOK;
					} else {
						put(&mut out, &NodeMessage::Usage(told));
						(mark, usage_due, doubted) = (Some(now), shared.control.next_usage(), false);
					}
				}
				read = stream.read(&mut buffer) => {
					let Some(count) = read.ok().filter(|count| *count > 0) else {return End::Peer};
					pending = buffer[..count].to_vec();
					wanted = None;
					continue;
				}
			}
			if !out.is_empty() && !tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&out)).await.is_ok_and(|done| done.is_ok()) {return End::Peer}
		}
	}.await;
	// A connection that was replaced is out of its pool already.
	if let Some(inner) = state.inner().as_mut() {
		inner.waiting.retain(|entry| entry.id != conn);
		inner.open.retain(|entry| entry.id != conn);
	}
	let was_open = authenticated.load(Ordering::Relaxed);
	if was_open {counters.open.fetch_sub(1, Ordering::Relaxed);}
	match end {
		End::Auth => drop(counters.auth_failed.fetch_add(1, Ordering::Relaxed)),
		End::Malformed => drop(counters.malformed.fetch_add(1, Ordering::Relaxed)),
		End::Slow => drop(counters.timed_out.fetch_add(1, Ordering::Relaxed)),
		_ => {}
	}
	let why = match end {
		End::Peer => "the device closed it",
		End::Gone => "its flow ended",
		End::Closed => "a newer connection took its place, its secret was removed or its device has no session",
		End::Auth => "the credential was wrong",
		End::Malformed => "a message was malformed or not allowed",
		End::Slow => "the opening exchange was not done in time",
		End::Bye => "the node said bye",
	};
	if was_open {state.say(&format!("{who}: control channel closed, {why}"))} else {tracing::debug!("{who}: a control connection that never authenticated closed, {why}")}
	// A `bye` and an end the device began are finished the way TCP finishes. Everything else is "closes the connection with no message": the stack says nothing when its stream is dropped, so the device is reset from here.
	if matches!(end, End::Bye | End::Peer) {let _ = tokio::time::timeout(WRITE_TIMEOUT, stream.shutdown()).await;} else {
		drop(stream);
		let plan = shared.plan();
		if let Some((reset, from)) = shared.flows.reset(&key, id).zip(plan.by_address.get(&key.src).copied().filter(|from| plan.devices[from.device].public_key == device)) {
			shared.own(&plan.users[plan.devices[from.device].user], reset.len());
			shared.send(&plan, from, &reset).await;
		}
	}
	shared.flows.hold(&key, id, CLOSED_IDLE);
}
