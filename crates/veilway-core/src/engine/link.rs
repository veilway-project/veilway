//! Node links at run time (node links page, "Lifetime"): what the node knows of each link, the state it reports, and the task that dials a link this node dials.
//! On the wire a link is nothing new: "one device session on a native transport, with WireGuard inside". The node that is dialled has the link as a peer of a `veilway` inbound, and everything the listeners do for a device they do for it. The node that dials has a tunnel for the link alone, whose one peer is the other node, and reaches it with the client's side of the transports (`veilway-transport`), by the client's rules for candidates, refusals and waits (`choice`), with no user to ask: "the listener's operator decided which transports the offer lists, and the dialler's operator accepted them at pairing".
//! What a link carries is not here: `chain` is the entry half, and the exit half is the path every decrypted packet takes, with the link's own limits.
use super::flows::{self, Stop};
use super::inbound::{Tunnel, Via};
use super::linkmtu;
use super::plan::{self, Dialled, Plan, Upstream};
use super::{Shared, Traffic};
use crate::config::{random, RuleTransport};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::task::AbortHandle;
use veilway_engine::import::Named;
use veilway_proto::session::{self, KEEPALIVE, REKEY};
use veilway_proto::subscription::payload::Transport;
use veilway_transport::choice::{self, Class, Network, Next, Pick, Standing};
use veilway_transport::{connector, Connect, End, Ended, Env, Kind, Session, Source, State as Opened, Target, Unreachable, Want, ATTEMPT};
use veilway_wg::MAX_PACKET;

/// "Up: a WireGuard handshake completed within the last 180 s."
pub const UP: Duration = Duration::from_secs(180);
/// "A link reported as ended or misconfigured: after 24 h of nothing but refusals, or 24 h without a handshake. From then on the dialler tries once a day."
pub const ENDED: Duration = Duration::from_secs(86_400);
/// "A size warning on a link: cleared 600 s after the last report."
pub const WARNED: Duration = Duration::from_secs(600);
/// Datagrams of a link's tunnel that wait for the dialler's session. One that finds the queue full is dropped and counted: "Drop, do not queue."
const QUEUE: usize = 256;

/// What a node reports of a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
	Up,
	/// "The dialler is trying, or the listener has not heard a handshake yet."
	Connecting,
	/// "Dialler only: no candidate answers."
	Unreachable,
	/// "Dialler only: the listener answers and does not accept the proof."
	Refused,
	/// Dialler only: the other node's certificate has a key that matches none of the pins of the candidate. Not a network problem: the other node has a new key, and the link has to be paired again.
	PinMismatch,
	/// "Ended or misconfigured", and a link this node itself cut off for its quota or its expiry.
	Ended,
}

impl Status {
	/// The name the control API gives the state. It is part of that API and does not change.
	pub fn name(self) -> &'static str {
		match self {
			Status::Up => "up",
			Status::Connecting => "connecting",
			Status::Unreachable => "unreachable",
			Status::Refused => "refused",
			Status::PinMismatch => "pin_mismatch",
			Status::Ended => "ended",
		}
	}
}

/// What the node has learnt of one link while running. It belongs to the link's id and key and outlives a reload that keeps both.
pub struct State {
	/// The state the link is reported in, and since when.
	status: Mutex<(Status, Instant)>,
	/// Changes of that state, in any direction.
	pub flips: AtomicU64,
	/// Inner IP packets and their bytes: up is what this node sent into the link, down what it took out of it.
	pub traffic: Traffic,
	/// Packets that came out of the link and were not carried: on the entry half what answers no flow or is not for the link's address, on the exit half what the gate, the rules or a limit refused.
	pub dropped: AtomicU64,
	/// On the exit half: packets this node forwarded from the link into another link, which only a link with `allow_chain` has.
	pub chained: AtomicU64,
	/// On the exit half: packets that would have crossed a fourth link and were dropped, and when that was last said.
	hopped: (AtomicU64, Mutex<Option<Instant>>),
	/// When the link was last up, or since when the node has had it.
	heard: Mutex<Instant>,
	/// What the dialler's last attempt came to when it failed, and the transport and candidate it is at, as places in the other node's list.
	attempt: Mutex<(Option<Status>, Option<(usize, usize)>)>,
	/// When the system last refused an outer packet of the link for its size.
	warned: Mutex<Option<Instant>>,
	/// When a pin mismatch was last said, so that a link that dials again and again says it once in `WARNED`.
	pinned: Mutex<Option<Instant>>,
	/// The cause a proxy chain last gave for not carrying the link, None while it carries it. Each change is logged once.
	chain: Mutex<Option<String>>,
	/// What the management connections of the link count, see `manage`.
	pub manage: super::manage::Counters,
	/// The path MTU found by probing and what keeps it up to date, see `linkmtu`.
	pub probing: linkmtu::Probing,
	/// Ends the session the dialler has now, so that the next one opens with a handshake, see `manage_renew`.
	pub renew: Notify,
}

impl Default for State {
	fn default() -> State {State {status: Mutex::new((Status::Connecting, Instant::now())), flips: AtomicU64::new(0), traffic: Traffic::default(), dropped: AtomicU64::new(0), chained: AtomicU64::new(0), hopped: Default::default(), heard: Mutex::new(Instant::now()), attempt: Mutex::default(), warned: Mutex::default(), pinned: Mutex::default(), chain: Mutex::default(), manage: Default::default(), probing: Default::default(), renew: Notify::new()}}
}

impl State {
	/// The state, and how long the link has been in it.
	pub fn status(&self) -> (Status, Duration) {
		let status = self.status.lock().unwrap_or_else(|e| e.into_inner());
		(status.0, status.1.elapsed())
	}

	/// What the dialler's last attempt came to when it failed: the state the link is reported in until an attempt succeeds.
	pub fn failed(&self) -> Option<Status> {self.attempt.lock().unwrap_or_else(|e| e.into_inner()).0}

	/// The transport and the candidate or endpoint the dialler is at.
	pub fn at(&self) -> Option<(usize, usize)> {self.attempt.lock().unwrap_or_else(|e| e.into_inner()).1}

	/// "Up, with a size warning": "the system has reported packet too big for the link's own outer packets, which suggests the link's `mtu` is too high for the path". "Anyone on the path can forge such a report, which is why it only warns and changes nothing."
	pub fn warning(&self) -> bool {self.warned.lock().unwrap_or_else(|e| e.into_inner()).is_some_and(|at| at.elapsed() < WARNED)}

	pub(super) fn warn(&self, tag: &str) {
		// A walk sends packets larger than the path on purpose, and says what it found itself.
		if self.probing.walking.load(Ordering::Relaxed) {return}
		self.probing.asked.store(true, Ordering::Relaxed);
		if self.warned.lock().unwrap_or_else(|e| e.into_inner()).replace(Instant::now()).is_none_or(|before| before.elapsed() >= WARNED) {tracing::info!("link {tag}: the system refused an outer packet of the link for its size, so the link's mtu is likely too high for the path between the two nodes. Full-size packets are lost until it is lowered on both nodes. The warning clears {}s after the last such report", WARNED.as_secs())}
	}

	/// One packet of the link dropped for its hop limit: said at warn at most once in `WARNED`.
	pub(super) fn hopped(&self, tag: &str) {
		self.dropped.fetch_add(1, Ordering::Relaxed);
		let total = self.hopped.0.fetch_add(1, Ordering::Relaxed) + 1;
		if self.hopped.1.lock().unwrap_or_else(|e| e.into_inner()).replace(Instant::now()).is_none_or(|before| before.elapsed() >= WARNED) {tracing::warn!("link {tag}: packets from this link would cross a fourth link, {total} dropped so far: a loop between links?")}
	}

	fn mismatch(&self, tag: &str) {
		if self.pinned.lock().unwrap_or_else(|e| e.into_inner()).replace(Instant::now()).is_none_or(|before| before.elapsed() >= WARNED) {tracing::warn!("link {tag}: the other node's key no longer matches the pin (pin mismatch, not a network problem). Pair the link again")}
	}

	fn tried(&self, failed: Option<Status>, at: Option<(usize, usize)>) {*self.attempt.lock().unwrap_or_else(|e| e.into_inner()) = (failed, at)}

	/// What the chain of the link did on its last dial: `None` when it carried the connection, else the cause. Logged at info when it changes.
	fn carried(&self, tag: &str, cause: Option<String>) {
		let mut last = self.chain.lock().unwrap_or_else(|e| e.into_inner());
		if *last == cause {return}
		match &cause {
			Some(cause) => tracing::info!("link {tag}: the chain does not carry the link: {cause}"),
			None => tracing::info!("link {tag}: the chain carries the link again"),
		}
		*last = cause;
	}
}

impl Shared {
	/// Once a second: holds every link's state against its tunnel and says each change, "logged at info with the link's tag, and counted". Nothing is latched: a link is up again the moment its tunnel has a handshake, with no action by anyone.
	pub(super) fn check_links(self: &Arc<Self>) {
		let plan = self.plan();
		for (at, link) in plan.links.iter().enumerate().filter(|(_, link)| matches!(link.carrier, plan::Carrier::Paired)) {
			let (state, now, up) = (&link.state, Instant::now(), plan.up(at));
			// "Up" for two seconds before the first walk, so the other node has the session too; then every `linkmtu::EVERY`, and at once when the size warning asks, at most once in `linkmtu::GAP`.
			let (was, since) = state.status();
			let walked = *state.probing.walked.lock().unwrap_or_else(|e| e.into_inner());
			if up && was == Status::Up && since >= Duration::from_secs(2) && walked.is_none_or(|at| at.elapsed() >= linkmtu::EVERY || (state.probing.asked.load(Ordering::Relaxed) && at.elapsed() >= linkmtu::GAP)) && !state.probing.walking.swap(true, Ordering::Relaxed) {
				*state.probing.walked.lock().unwrap_or_else(|e| e.into_inner()) = Some(now);
				tokio::spawn(linkmtu::walk(self.clone(), link.id, state.clone()));
			}
			let quiet = {
				let mut heard = state.heard.lock().unwrap_or_else(|e| e.into_inner());
				if up {*heard = now}
				now.saturating_duration_since(*heard)
			};
			let next = if up {Status::Up} else if link.denied.is_some() || quiet >= ENDED {Status::Ended} else {state.attempt.lock().unwrap_or_else(|e| e.into_inner()).0.filter(|_| link.dialled.is_some()).unwrap_or(Status::Connecting)};
			let mut status = state.status.lock().unwrap_or_else(|e| e.into_inner());
			if status.0 == next {continue}
			tracing::info!("link {}: {} after {}s of {}{}", link.tag, next.name(), status.1.elapsed().as_secs(), status.0.name(), match (next, link.denied, link.exit) {
				(Status::Ended, Some(denied), _) => format!(": this node cut it off ({denied:?})"),
				(Status::Ended, None, _) => format!(": no handshake for {} hours. The other node has ended the link or one of the two is misconfigured{}", ENDED.as_secs() / 3600, if link.dialled.is_some() {", and this node tries once a day from here on"} else {""}),
				(Status::Up, ..) => String::new(),
				(_, _, Some(exit)) if !plan.exits.get(exit).is_some_and(|exit| matches!(&exit.backend, super::plan::Backend::Chain {links} if links.iter().any(|other| plan.up(*other)))) => format!(": exit {} is down, and what is routed to it is answered as unreachable", plan.exits[exit].tag),
				_ => String::new(),
			});
			state.flips.fetch_add(1, Ordering::Relaxed);
			// A link that comes up again is walked again, whatever the last walk was.
			if next == Status::Up {*state.probing.walked.lock().unwrap_or_else(|e| e.into_inner()) = None}
			*status = (next, now);
		}
	}
}

/// The dial of the stream of a TCP transport through the proxy chain `via`, before the deadline of the attempt. `carried` is told after every dial whether the chain carried the connection, with the cause when it did not, and the failure is classified as the transport wants it: where the chain stopped, and whether it timed out there.
pub(super) fn through(via: Arc<Upstream>, carried: impl Fn(Option<String>) + Send + Sync + 'static) -> Connect {
	let carried = Arc::new(carried);
	connector(move |to, deadline| {
		let (via, carried) = (via.clone(), carried.clone());
		async move {
			match flows::dial_until(&via, to, deadline).await {
				Ok(stream) => {
					carried(None);
					Ok(stream)
				}
				Err(failure) => {
					carried(Some(failure.describe()));
					Err(match (&failure.stop, failure.timeout) {
						(Stop::First(_), _) | (Stop::Hop(_), true) => End::Offline.into(),
						(Stop::Hop(_), false) | (Stop::Target, false) => Ended::Unreachable(Unreachable::Connect),
						(Stop::Target, true) => Ended::Unreachable(Unreachable::Timeout),
					})
				}
			}
		}
	})
}

/// `through` for a host name: the last proxy of the chain looks the name up, so the node's own resolver never sees it. What the chain says of a dial is told to `carried` as in `through`.
pub(super) fn through_name(via: Arc<Upstream>, carried: impl Fn(Option<String>) + Send + Sync + 'static) -> Named {
	let carried = Arc::new(carried);
	Arc::new(move |host, port, deadline| {
		let (via, carried) = (via.clone(), carried.clone());
		Box::pin(async move {
			match flows::dial_host_until(&via, host, port, deadline).await {
				Ok(stream) => {
					carried(None);
					Ok(stream)
				}
				Err(failure) => {
					carried(Some(failure.describe()));
					Err(std::io::Error::other("the chain did not carry the connection"))
				}
			}
		})
	})
}

/// The way into the session of a link this node dials. The tunnel of the link sends through it whatever it has for the other node, and a datagram that finds no room is dropped and counted.
pub struct Dialler {out: mpsc::Sender<(Vec<u8>, bool)>, pub unsent: AtomicU64}

impl Dialler {
	/// `probe` marks a datagram of a size probe, which a transport sends with no padding.
	pub fn push(&self, datagram: &[u8], probe: bool) {
		if self.out.try_send((datagram.to_vec(), probe)).is_err() {self.unsent.fetch_add(1, Ordering::Relaxed);}
	}
}

/// What carries the datagrams of one attempt: a session of the client's side of the native transports, or for plain `udp`, which "is WireGuard itself and needs no transport", a socket.
enum Carrier {Native(Session), Plain(UdpSocket)}

/// One session to one candidate, from the dial to its end. `opened` is told once, when the session is one: a chunk of the node opened on a native transport, and a datagram of the other node authenticated on plain `udp`.
#[allow(clippy::too_many_arguments)]
async fn session(shared: &Arc<Shared>, tunnel: &Arc<Tunnel>, me: &Weak<Dialler>, tag: &str, dialled: &Dialled, state: &Arc<State>, queue: &mut mpsc::Receiver<(Vec<u8>, bool)>, transport: usize, candidate: usize, env: Env, opened: &mut (dyn FnMut() + Send)) -> Ended {
	let (key, mut made) = (dialled.link.inbound, Vec::new());
	// "Through an outbound": the stream TCP transports dial over is the proxy chain's. The chain's failure is what the transport is told, by where it stopped and whether it timed out there.
	let connect = dialled.via.clone().map(|via| through(via, {let (state, tag) = (state.clone(), tag.to_string()); move |cause| state.carried(&tag, cause)}));
	let source: Source = Arc::new(Mutex::new({
		let tunnel = tunnel.clone();
		// "A keepalive of a tunnel that is already up, or else a fresh handshake initiation." The dialler of a link is the client of the transports page, so it also starts a new handshake once the last one is older than the client rekey point (60 to 110 s, drawn again after each), and WireGuard, which only rekeys on data, does not give an idle link up at 180 s.
		// Unlike an app, a link with no session sends an initiation on an idle keepalive too: the session it rides is still open, and waiting for the listener's idle limit to end it kept a quiet link down for minutes.
		let draw = || session::delay(&REKEY, &mut random).unwrap_or(Duration::from_secs(85));
		let rekey = Mutex::new(draw());
		move |_: Want| {
			let (mut peers, mut out) = (tunnel.lock(), Vec::new());
			let peer = peers.wg.index(&key)?;
			let mut point = rekey.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
			match peers.wg.time_since_last_handshake(peer) {
				Some(age) if age <= *point => peers.wg.encapsulate(peer, &[], &mut out),
				_ => {
					*point = draw();
					peers.wg.initiate(peer, &mut out);
				}
			}
			out.pop()
		}
	}));
	let (to, mut carrier) = match (&dialled.transports[transport], Target::of(&dialled.transports[transport], candidate, &dialled.link).map(|target| target.via(connect.clone()))) {
		(_, Some(target)) => match Session::open(&dialled.link, target, env, source.clone()) {
			Ok(session) => (SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), Carrier::Native(session)),
			// What the client's side refuses before it dials is a fault of the link's entry in the config, which validation does not let through. It is said, and held against the candidate like one that cannot be reached.
			Err(refused) => {
				tracing::warn!("link {tag}: transport {} of the other node cannot be dialled as the config has it ({refused})", transport + 1);
				return Ended::Unreachable(Unreachable::Connect);
			}
		},
		(Transport::Udp(endpoints), None) => {
			let Some(to) = endpoints.get(candidate).map(|endpoint| endpoint.address()) else {return Ended::Unreachable(Unreachable::Connect)};
			let local: SocketAddr = if to.is_ipv4() {(Ipv4Addr::UNSPECIFIED, 0).into()} else {(Ipv6Addr::UNSPECIFIED, 0).into()};
			let socket = match UdpSocket::bind(local).await {
				Ok(socket) if socket.connect(to).await.is_ok() => socket,
				_ => return Ended::Closed(End::Offline),
			};
			// "The client and the node send every outer packet of a datagram transport with fragmentation prohibited."
			let _ = super::host::fragmenting(&socket, to.is_ipv6(), true);
			if let Some(first) = source.lock().ok().and_then(|mut source| source(Want::First)) {let _ = socket.send(&first).await;}
			(to, Carrier::Plain(socket))
		}
		_ => return Ended::Unreachable(Unreachable::Connect),
	};
	// From here the tunnel's own packets for the other node, its timers' among them, leave through this session.
	{
		let mut peers = tunnel.lock();
		if let Some(peer) = peers.wg.index(&key) {peers.heard(peer, Via::Dial(me.clone()))}
	}
	let (started, mut live, mut announced, mut full, mut buf, mut tick) = (Instant::now(), false, false, 0u64, vec![0u8; MAX_PACKET], tokio::time::interval(Duration::from_secs(1)));
	// Plain `udp` has no transport to ask for an idle keepalive, so this asks the source itself, which is also where the rekey comes from.
	let mut idle = Instant::now() + session::delay(&KEEPALIVE, &mut random).unwrap_or(Duration::from_secs(30));
	loop {
		let received = async {
			match &mut carrier {
				Carrier::Native(session) => session.recv().await,
				Carrier::Plain(socket) => loop {
					// An error on a connected socket is an ICMP error for an earlier datagram. Whether the other node is there is for the time limits below to say.
					if let Ok(n) = socket.recv(&mut buf).await {break Ok(buf[..n].to_vec())}
				},
			}
		};
		tokio::select! {
			received = received => {
				let datagram = match received {
					Ok(datagram) => datagram,
					Err(ended) => return ended,
				};
				let (bound, mut carried) = {
					let (mut peers, mut carried) = (tunnel.lock(), Vec::new());
					(peers.wg.recv_bound(&key, to, &datagram, &mut made, &mut carried), carried)
				};
				for answer in made.drain(..) {
					match &carrier {
						Carrier::Native(session) => full += u64::from(!session.send(answer, Kind::Handshake)),
						Carrier::Plain(socket) => drop(socket.send(&answer).await),
					}
				}
				if !bound.is_some_and(|bound| bound.proven) {continue}
				// The node that listens keeps sending on the session it had until a datagram of this one arrives, so the first proof of a session is answered with a keepalive at once.
				if !announced {
					announced = true;
					let mut keepalive = Vec::new();
					{
						let mut peers = tunnel.lock();
						if let Some(peer) = peers.wg.index(&key) {peers.wg.encapsulate(peer, &[], &mut keepalive)}
					}
					for datagram in keepalive {
						match &carrier {
							Carrier::Native(session) => full += u64::from(!session.send(datagram, Kind::Packet {flow: 0, control: false})),
							Carrier::Plain(socket) => drop(socket.send(&datagram).await),
						}
					}
				}
				if !live && matches!(carrier, Carrier::Plain(_)) {
					live = true;
					opened();
				}
				let plan = shared.plan();
				let Some(at) = plan.inbound_of(tunnel) else {continue};
				for packet in carried.drain(..) {shared.ingress(&plan, at, key, packet, Some(match &dialled.transports[transport] {
					Transport::Udp(_) => RuleTransport::Udp,
					Transport::UdpObfs(_) => RuleTransport::UdpObfs,
					Transport::Tls(_) => RuleTransport::Tls,
					Transport::Ws(_) => RuleTransport::Ws,
					Transport::Fronted(_) => RuleTransport::Fronted,
					Transport::FrontedShaped(..) => RuleTransport::FrontedShaped,
					Transport::FakeTls {..} => RuleTransport::Faketls,
					Transport::WsPlain {..} => RuleTransport::WsPlain,
				})).await}
			}
			Some((datagram, probe)) = queue.recv() => {
				// A handshake initiation of a tunnel that has had no handshake for as long as a link may be quiet is one WireGuard's timer made "because the node stopped answering": on `udp-obfs` it opens a new session, and on a stream it wants an answer or the session is lost.
				let kind = match datagram.first() {
					_ if probe => Kind::Probe,
					Some(1) if !shared.plan().inbound_of(tunnel).and_then(|at| shared.plan().inbounds[at].link).is_some_and(|link| shared.plan().up(link)) => Kind::Stalled,
					Some(1..=3) => Kind::Handshake,
					_ => Kind::Packet {flow: 0, control: false},
				};
				match &carrier {
					Carrier::Native(session) => full += u64::from(!session.send(datagram, kind)),
					Carrier::Plain(socket) => {
						#[cfg(unix)]
						if socket.send(&datagram).await.is_err_and(|e| e.raw_os_error() == Some(libc::EMSGSIZE)) {state.warn(tag)}
						#[cfg(not(unix))]
						let _ = socket.send(&datagram).await;
					}
				}
			}
			_ = state.renew.notified() => return Ended::Closed(End::Asked),
			_ = tick.tick() => match &carrier {
				Carrier::Native(session) => {
					if !live && session.state() == Opened::Established {
						live = true;
						opened();
					}
					// What the session dropped and this task did not see refused for a full queue was refused for its size, by the session or by the system.
					if session.numbers().dropped > full {
						full = session.numbers().dropped;
						state.warn(tag);
					}
				}
				// Plain `udp` has no session to say that it ended: silence at the start is an endpoint that does not answer, and a tunnel that has gone quiet for as long as a link may is a session that is lost.
				Carrier::Plain(socket) => {
					let quiet = !shared.plan().inbound_of(tunnel).and_then(|at| shared.plan().inbounds[at].link).is_some_and(|link| shared.plan().up(link));
					if !live && started.elapsed() >= ATTEMPT {return Ended::Unreachable(Unreachable::Silence)}
					if live && quiet {return Ended::Closed(End::Lost)}
					if live && Instant::now() >= idle {
						idle = Instant::now() + session::delay(&KEEPALIVE, &mut random).unwrap_or(Duration::from_secs(30));
						if let Some(datagram) = source.lock().ok().and_then(|mut source| source(Want::Keepalive)) {let _ = socket.send(&datagram).await;}
					}
				}
			},
		}
	}
}

/// Dials one link for as long as the handle it returns is not aborted: transport by transport and candidate by candidate, as `choice` says, with the waits of the client rules, which this adds no numbers of its own to.
/// Nothing is remembered for ever: a candidate that is set aside comes back within the hour, a refusal is tried again after its wait, and a link that has been quiet for a day is still tried once a day.
pub fn dial(shared: &Arc<Shared>, tunnel: Arc<Tunnel>, tag: String, dialled: Arc<Dialled>, state: Arc<State>) -> (Arc<Dialler>, AbortHandle) {
	let ((out, mut queue), shared) = (mpsc::channel(QUEUE), shared.clone());
	let dialler = Arc::new(Dialler {out, unsent: AtomicU64::new(0)});
	let (me, dialling) = (Arc::downgrade(&dialler), shared.dialling.clone());
	let task = tokio::spawn(async move {
		let _dialling = dialling;
		// There is no user to ask, so every class of transport the other node listed is agreed to.
		let (mut network, mut standing, profile) = (Network::default(), Standing {consent: vec![Class::Cover, Class::NoCover, Class::Exposed, Class::Plain], ..Standing::default()}, choice::digest(&dialled.transports));
		let udp = dialled.transports.iter().filter(|transport| matches!(transport, Transport::Udp(_) | Transport::UdpObfs(_))).count();
		if dialled.via.is_some() && udp > 0 {tracing::info!("link {tag}: {udp} udp transport(s) of the other node are not usable through via, and are skipped")}
		let (mut seed, offset, key, clock) = ([0u8; 8], Arc::new(AtomicI64::new(0)), dialled.link.inbound, shared.now);
		let _ = random(&mut seed);
		let now = move || clock().unix_timestamp().max(0) as u64;
		// A link that is reported as ended is tried once a day, "because the address it dials may by then be someone else's".
		let rest = |wait: Duration, state: &State| if state.status().0 == Status::Ended {wait.max(ENDED)} else {wait};
		// Sessions in a row that opened and ended before `choice::LIVED`.
		let (mut rounds, mut quick) = (0u32, 0u32);
		loop {
			let (mut order, mut tried) = (choice::plan(&dialled.transports, false, &network, &standing, now(), false).order, 0u32);
			order.retain(|transport| dialled.via.is_none() || !matches!(dialled.transports[*transport], Transport::Udp(_) | Transport::UdpObfs(_)));
			for transport in order.iter().copied() {
				let (count, mut passed) = (match &dialled.transports[transport] {
					Transport::Udp(list) | Transport::UdpObfs(list) => list.len(),
					Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _) => stream.candidates.len(),
					Transport::FakeTls {candidates, ..} => candidates.len(),
					Transport::WsPlain {stream, ..} => stream.candidates.len(),
				}, Vec::new());
				tried += 1;
				let unreachable = loop {
					let candidate = match choice::candidates(&mut network, profile, transport, count, &passed, order.len() == 1, u64::from_le_bytes(seed), now()) {
						Pick::Try(picked) => picked[0],
						Pick::Wait(until) => {
							tokio::time::sleep(Duration::from_secs(until.saturating_sub(now()).clamp(1, choice::HOUR))).await;
							continue;
						}
						Pick::Passed => break false,
						Pick::Nothing => break true,
					};
					loop {
						let failed = state.attempt.lock().unwrap_or_else(|e| e.into_inner()).0;
						state.tried(failed, Some((transport, candidate)));
						// The clock proofs are made with is the node's, and the offset a pinned candidate's answer gave while one is held.
						let env = Env {device: Arc::new(now), now: Arc::new({
							let offset = offset.clone();
							move || now().saturating_add_signed(offset.load(Ordering::Relaxed))
						}), roots: shared.roots.clone(), socket: None};
						let (mut open, began) = (false, Instant::now());
						let ended = session(&shared, &tunnel, &me, &tag, &dialled, &state, &mut queue, transport, candidate, env, &mut || open = true).await;
						// The tunnel's packets have nowhere to go until the next session, and what waited for this one is not for the next.
						while queue.try_recv().is_ok() {}
						// "The node no longer knows the tunnel, as after its restart": the next attempt opens with a handshake initiation.
						if ended == Ended::Closed(End::Unanswered) {tunnel.lock().wg.drop_sessions(&key);}
						let mut next = Ok(Next::Rest);
						if open {next = choice::outcome(&mut network, &mut standing, profile, transport, candidate, None, now(), &mut random)}
						if next.is_ok() {next = choice::outcome(&mut network, &mut standing, profile, transport, candidate, Some(ended), now(), &mut random)}
						offset.store(choice::clock(now(), &standing) as i64 - now() as i64, Ordering::Relaxed);
						if ended == Ended::Unreachable(Unreachable::Pin) {state.mismatch(&tag)}
						state.tried(match ended {
							Ended::Refused(_) => Some(Status::Refused),
							Ended::Unreachable(Unreachable::Pin) => Some(Status::PinMismatch),
							Ended::Unreachable(_) | Ended::Closed(End::Unanswered | End::Offline) => Some(Status::Unreachable),
							Ended::Closed(_) => None,
						}, None);
						quick = if open && began.elapsed() < Duration::from_secs(choice::LIVED) {quick.saturating_add(1)} else {0};
						// A node that keeps closing the session soon after it opened is said at info at the first of those and at each doubling of their count, so one that does it all day leaves a few lines and not one a second.
						if quick <= 1 || quick.is_power_of_two() {tracing::info!("link {tag}: the session over transport {} of the other node ended ({ended:?}){}", transport + 1, if quick > 1 {format!(" soon after it opened, {quick} times in a row")} else if open {" after it was open".to_string()} else {" before it opened".to_string()})} else {tracing::debug!("link {tag}: the session over transport {} of the other node ended soon after it opened, {quick} times in a row", transport + 1)}
						// On the last transport the marks of its candidates are passed over and the one that just failed comes straight back. A dial that fails at once, a refused connection, would then be made again at once and for ever, so an attempt that did not open waits at least the wait between transports. Only the one retry of a node that forgot the tunnel goes at once.
						let next = next.map(|next| match next {
							Next::Again(wait) | Next::Move(wait) if !open && ended != Ended::Closed(End::Unanswered) => {
								let least = choice::transport_wait(&mut random).unwrap_or(Duration::from_secs(2));
								if matches!(next, Next::Again(_)) {Next::Again(wait.max(least))} else {Next::Move(wait.max(least))}
							}
							next => next,
						});
						match next {
							Ok(Next::Again(wait)) => tokio::time::sleep(rest(wait, &state)).await,
							Ok(Next::Move(wait)) => {
								if matches!(ended, Ended::Refused(_)) {passed.push(candidate)}
								tokio::time::sleep(rest(wait, &state)).await;
								break;
							}
							// A session nobody asked to close does not rest, and a random source that failed is no reason to stop dialling: both wait as a lost session does, the reconnect wait of the client rules, doubled for each session in a row that the other node closed soon after it opened.
							Ok(Next::Rest) | Err(_) => tokio::time::sleep(rest(choice::reconnect_wait(quick.max(1), &mut random).unwrap_or(Duration::ZERO).max(Duration::from_secs(1)), &state)).await,
						}
					}
				};
				tokio::time::sleep(rest(choice::fallback(&mut network, profile, &order, transport, unreachable, tried, rounds + 1, now(), &mut random).unwrap_or(Duration::from_secs(30)), &state)).await;
			}
			rounds = rounds.saturating_add(1);
			// A plan that holds no transport is a list of the other node's that this build can dial none of.
			if order.is_empty() {tokio::time::sleep(ENDED).await}
		}
	});
	(dialler, task.abort_handle())
}

/// The numbers of the links of a plan the control API reports, see `Engine::links`.
pub(super) fn flows(shared: &Shared, plan: &Plan, at: usize) -> usize {
	let link = &plan.links[at];
	if link.entry {shared.nat.of(&link.id)} else {shared.flows.of_device(&link.identity)}
}
