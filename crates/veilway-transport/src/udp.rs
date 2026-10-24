//! The client of `udp-obfs` (transports page, "`udp-obfs`", "Client state machine").
//!
//! `Machine` is the state machine without a socket and without a clock of its own: packets, moments and the WireGuard layer are handed to it, which is how its tests and its fuzz target drive it. `run` is the socket around it.
//!
//! Who makes what: the WireGuard layer makes every WireGuard datagram, the opening one and the idle keepalive included (`Want`). This module decides when one is due and wraps it.
//!
//! Outer packets are sent with fragmentation prohibited ("No outer fragmentation"). On Linux and Android the socket is put into the probing mode of path MTU discovery, the option the node sets. On other systems no dependency of the tree sets the option without `unsafe`: it is not set, a line at warn says so once for each session, and the rule is not kept there.
use crate::{lone, pause, random, wide, Ask, End, Ended, Hook, Kind, Link, Port, Unreachable, Want, ATTEMPT};
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::net::sockopt;
use socket2::SockRef;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, sleep_until, Instant};
use veilway_proto::chunk::{ChunkError, Padding};
use veilway_proto::session::{LIVENESS, LONE_KEEPALIVE};
use veilway_proto::udp_obfs::{self, Client, Receiver, Sender, DATA_MIN, OLD_READABLE, OVERHEAD, RETRIES};

/// What one call to the machine works with: the clock (`Clock`) and the moment, the WireGuard layer, and where the packets to send are put.
pub struct Io<'a> {pub time: u64, pub now: Instant, pub source: &'a mut (dyn FnMut(Want) -> Option<Vec<u8>> + Send), pub out: &'a mut Vec<Vec<u8>>}

// The two directions of one session.
struct Live {tx: Sender, rx: Receiver}

// The opening packets of one attempt, at most four of them: the first and "again after 1, 2 and 4 s". Each has keys of its own, and the first whose answer opens is the session.
struct Attempt {started: Instant, tries: Vec<Live>}

// A lone keepalive on its way out, and whether it is the idle keepalive, which wants a chunk back.
struct Held {datagram: Vec<u8>, at: Instant, idle: bool}

/// The client state machine of one `udp-obfs` session and the sessions that follow it at the same node.
pub struct Machine {client: Client, bounds: (u32, u32), keepalive: RangeInclusive<u32>, max: usize, full: usize, live: Option<Live>, old: Vec<(Receiver, Instant)>, attempt: Option<Attempt>, spare: Option<(Vec<Live>, Instant)>, idle: Instant, awaiting: Option<Instant>, held: Option<Held>, established: bool, scratch: Vec<u8>, dropped: u64}

// When the next opening packet of an attempt is due, if one is.
fn retry(attempt: &Attempt) -> Option<Instant> {RETRIES.get(..attempt.tries.len()).map(|waits| attempt.started + waits.iter().sum::<Duration>())}

impl Machine {
	pub fn new(link: &Link, now: Instant) -> Self {Self {client: Client::new(link.secret.expose(), &link.inbound), bounds: (link.padding.wide_max, link.padding.normal_max), keepalive: link.padding.keepalive.clone(), max: usize::from(link.mtu) + OVERHEAD, full: usize::from(link.mtu) + OVERHEAD, live: None, old: Vec::new(), attempt: None, spare: None, idle: now, awaiting: None, held: None, established: false, scratch: Vec::new(), dropped: 0}}
	/// Whether a chunk of the node has opened on a session of this machine.
	pub fn established(&self) -> bool {self.established}
	/// The tunnel's MTU now: no packet is padded above it and 62 bytes, and never above the profile's `mtu` and 62.
	pub fn room(&mut self, mtu: u16) {self.max = (usize::from(mtu) + OVERHEAD).min(self.full)}
	/// Datagrams that were not sent since the last call: no session to carry them, or a size no packet of this link holds.
	pub fn dropped(&mut self) -> u64 {std::mem::take(&mut self.dropped)}
	/// Sends an opening packet around `datagram`. `fresh` starts a new attempt, with its own 1, 2 and 4 s. Otherwise the packet is one more of the attempt that runs.
	pub fn open(&mut self, datagram: &[u8], fresh: bool, io: &mut Io) -> Result<(), End> {
		let (padding, mut packet) = (Padding::new(self.bounds.0, self.bounds.1, &mut random).map_err(|_| End::Random)?, Vec::new());
		let keys = self.client.open(io.time, datagram, &padding, self.max, &mut random, &mut packet).map_err(|error| if error == ChunkError::Random {End::Random} else {End::Source})?;
		if fresh {self.attempt = None}
		// A new attempt: what an attempt before it left over is gone, and so is the wait for a keepalive's answer, which the attempt's own end takes the place of.
		if self.attempt.is_none() {(self.spare, self.awaiting) = (None, None)}
		let attempt = self.attempt.get_or_insert_with(|| Attempt {started: io.now, tries: Vec::new()});
		if attempt.tries.len() > RETRIES.len() {return Ok(())}
		attempt.tries.push(Live {tx: Sender::new(keys.c2s, padding), rx: Receiver::new(keys.s2c)});
		io.out.push(packet);
		Ok(())
	}
	// An opening packet around what the WireGuard layer gives for one: "a fresh salt and a fresh WireGuard datagram of the same kind".
	fn reopen(&mut self, fresh: bool, io: &mut Io) -> Result<(), End> {
		let datagram = (io.source)(Want::First).ok_or(End::Source)?;
		self.open(&datagram, fresh, io)
	}
	/// The network changed under the socket: one of the cases an opening packet is sent in.
	pub fn moved(&mut self, io: &mut Io) -> Result<(), End> {self.reopen(true, io)}
	/// A datagram from the node's address. `Some` when it opened under a session of this machine, with the WireGuard datagram in it or none for padding alone. Everything else is dropped without a word.
	/// "It switches to the new keys when the first answer of the new session opens, and keeps the old session readable for 10 s after that."
	pub fn received(&mut self, packet: &[u8], now: Instant) -> Option<Option<Vec<u8>>> {
		if let Some(live) = &mut self.live {
			if let Ok(datagram) = live.rx.open(packet, &mut self.scratch) {
				self.awaiting = None;
				return Some(datagram.map(<[u8]>::to_vec));
			}
		}
		// The opening packets of the attempt that runs, and behind them the ones an attempt that was won left over, the newest first in each.
		let mut won = None;
		for (spare, tries) in [(false, self.attempt.as_mut().map(|attempt| &mut attempt.tries)), (true, self.spare.as_mut().filter(|(_, until)| now < *until).map(|(tries, _)| tries))] {
			for (at, live) in tries.map(|tries| tries.iter_mut().enumerate().rev()).into_iter().flatten() {
				if won.is_none() {won = live.rx.open(packet, &mut self.scratch).ok().map(|datagram| (spare, at, datagram.map(<[u8]>::to_vec)))}
			}
		}
		if let Some((spare, at, datagram)) = won {
			let (mut tries, until) = if spare {self.spare.take()?} else {(self.attempt.take()?.tries, now + ATTEMPT)};
			// An opening packet that was sent after this one may still reach the node, which then moves to the session it opens: the newer ones stay readable for as long as an attempt lasts.
			let newer = tries.split_off(at + 1);
			self.spare = Some((newer, until)).filter(|(newer, _)| !newer.is_empty());
			let new = tries.pop()?;
			// The session before stays readable for its 10 s, and so do the opening packets that were sent before the one that won: opening packets that carry keepalives can establish at the node in another order than they were sent, and what the node then sends is read. Nothing switches to them: a recorded packet must not move the session in use.
			self.old.extend(self.live.replace(new).into_iter().chain(tries).map(|live| (live.rx, now + OLD_READABLE)));
			let excess = self.old.len().saturating_sub(2 * RETRIES.len());
			self.old.drain(..excess);
			(self.established, self.awaiting, self.idle) = (true, None, now + pause(&self.keepalive).unwrap_or(LIVENESS));
			return Some(datagram);
		}
		// On `udp-obfs` a recorded packet opens again, so a packet that opens says less than a chunk on a stream does: the echo is padding alone and cannot be told from a replay. The page's rule for the idle keepalive is "no chunk back", and that is what is kept.
		self.old.iter_mut().filter(|(_, until)| now < *until).find_map(|(rx, _)| rx.open(packet, &mut self.scratch).ok().map(|datagram| datagram.map(<[u8]>::to_vec)))
	}
	/// One WireGuard datagram of the caller. "Every other WireGuard datagram travels in a data packet, rekey handshakes included": only a `Stalled` one opens a session.
	pub fn send(&mut self, datagram: &[u8], kind: Kind, io: &mut Io) -> Result<(), End> {
		if kind == Kind::Stalled {return self.open(datagram, false, io)}
		// A datagram transport has nothing a lone keepalive could join: it is held back for its delay and sent alone.
		if lone(datagram) && self.held.is_none() {
			self.held = Some(Held {datagram: datagram.to_vec(), at: io.now + pause(&LONE_KEEPALIVE)?, idle: false});
			return Ok(());
		}
		// A probe is sealed with no padding at all: the packet is the probe's size and 62 bytes, whatever the tunnel's MTU is now.
		let max = if kind == Kind::Probe {datagram.len() + 2 + DATA_MIN} else {self.max};
		self.seal(datagram, wide(kind, datagram), max, io)
	}
	// A data packet on the session in use: "While it waits for the first answer of a new session, the client keeps sending and receiving on the session it had."
	fn seal(&mut self, datagram: &[u8], wide: bool, max: usize, io: &mut Io) -> Result<(), End> {
		let (Some(live), mut packet) = (&mut self.live, Vec::new()) else {
			self.dropped += 1;
			return Ok(());
		};
		match live.tx.seal(Some(datagram), wide, max, &mut random, &mut packet) {
			Ok(()) => io.out.push(packet),
			Err(ChunkError::Random) => return Err(End::Random),
			Err(ChunkError::Number) => return Err(End::Exhausted),
			Err(_) => self.dropped += 1,
		}
		self.idle = io.now + pause(&self.keepalive)?;
		Ok(())
	}
	/// What is due at `io.now`: a held keepalive, the next opening packet of an attempt or its end, a new session after 2^30 packets or after an idle keepalive nobody answered, and the idle keepalive itself.
	/// An attempt whose opening packets all went unanswered is silence: `Unreachable` when no session was ever open here, `Lost` otherwise.
	pub fn tick(&mut self, io: &mut Io) -> Result<(), Ended> {
		self.old.retain(|(_, until)| io.now < *until);
		if self.spare.as_ref().is_some_and(|(_, until)| io.now >= *until) {self.spare = None}
		if let Some(held) = self.held.take_if(|held| io.now >= held.at) {
			self.seal(&held.datagram, false, self.max, io)?;
			if held.idle && self.live.is_some() {self.awaiting.get_or_insert(io.now + LIVENESS);}
		}
		if let Some(attempt) = &self.attempt {
			// "Opening packet with no answer": the page does not say how long the last one waits. It is given what is left of the 10 s a transport gets, which is 3 s.
			if io.now >= attempt.started + ATTEMPT {return Err(if self.established {Ended::Closed(End::Lost)} else {Ended::Unreachable(Unreachable::Silence)})}
			if retry(attempt).is_some_and(|at| io.now >= at) {self.reopen(false, io)?}
		} else if self.awaiting.is_some_and(|at| io.now >= at) || self.live.as_ref().is_some_and(|live| udp_obfs::renew(live.tx.sent(), live.rx.received())) {
			self.awaiting = None;
			self.reopen(true, io)?;
		} else if io.now >= self.idle && self.live.is_some() && self.held.is_none() {
			self.idle = io.now + pause(&self.keepalive)?;
			if let Some(datagram) = (io.source)(Want::Keepalive) {self.held = Some(Held {datagram, at: io.now + pause(&LONE_KEEPALIVE)?, idle: true})}
		}
		Ok(())
	}
	/// The next moment `tick` has something to do.
	pub fn deadline(&self) -> Instant {[self.held.as_ref().map(|held| held.at), self.attempt.as_ref().map(|attempt| retry(attempt).unwrap_or(attempt.started + ATTEMPT)), self.awaiting, self.live.as_ref().filter(|_| self.attempt.is_none() && self.held.is_none()).map(|_| self.idle)].into_iter().flatten().min().unwrap_or(self.idle + ATTEMPT)}
}

/// Whether this system can prohibit fragmentation of what a datagram socket sends. Where it cannot, `bound` says so in the log, and a caller that probes the path's MTU has no use for the probes: they would be fragmented, not lost.
pub const DONT_FRAGMENT: bool = cfg!(any(target_os = "linux", target_os = "android"));

// A socket for one node, with fragmentation of what it sends prohibited where the system has the option. The caller's hook has the socket before it is connected. Every failure here is the device's: no socket, no address, no route, or a hook that said no.
pub async fn bound(to: SocketAddr, hook: &Option<Hook>) -> std::io::Result<UdpSocket> {
	let socket = if to.is_ipv4() {UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?} else {UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?};
	if let Some(hook) = hook {hook(SockRef::from(&socket))?}
	// A connected socket takes datagrams from the node's address and port alone.
	socket.connect(to).await?;
	#[cfg(any(target_os = "linux", target_os = "android"))]
	if to.is_ipv4() {sockopt::set_ip_mtu_discover(&socket, sockopt::Ipv4PathMtuDiscovery::PROBE)?} else {sockopt::set_ipv6_mtu_discover(&socket, sockopt::Ipv6PathMtuDiscovery::PROBE)?}
	#[cfg(not(any(target_os = "linux", target_os = "android")))]
	tracing::warn!("fragmentation of outer packets cannot be prohibited on this system: a packet above the path's size is fragmented, not lost");
	Ok(socket)
}

enum Event {Packet(std::io::Result<usize>), Send(Vec<u8>, Kind), Ask(Option<Ask>), Timer}

pub(crate) async fn run(port: &mut Port, link: &Link, to: SocketAddr) -> Ended {
	let hook = port.env.socket.clone();
	let Ok(mut socket) = bound(to, &hook).await else {return End::Offline.into()};
	// The largest packet of the node is the `mtu` and 62 bytes, far below this. A longer datagram is cut by the system and then does not open.
	let (mut machine, mut out, mut buf, mut failed, source, clock) = (Machine::new(link, Instant::now()), Vec::new(), [0u8; 2048], false, port.source.clone(), port.env.now.clone());
	let mut ask = move |want| source.lock().ok().and_then(|mut source| source(want));
	if let Err(end) = machine.reopen(true, &mut Io {time: clock(), now: Instant::now(), source: &mut ask, out: &mut out}) {return end.into()}
	loop {
		for packet in out.drain(..) {
			// A packet the host refuses for its size is not sent and is counted. Every other error of a send is the path's, and silence is how the path's failures are met.
			if socket.send(&packet).await.is_ok() {port.sent(1)} else {port.dropped(1)}
		}
		let event = tokio::select! {
			got = socket.recv(&mut buf) => Event::Packet(got),
			sent = port.out.recv() => sent.map_or(Event::Ask(None), |(datagram, kind)| Event::Send(datagram, kind)),
			asked = port.ask.recv() => Event::Ask(asked),
			_ = sleep_until(machine.deadline()) => Event::Timer,
		};
		// An error of a connected datagram socket is an ICMP message somebody sent, and says nothing a timer does not find out. One is passed over. From the second in a row the loop rests 10 ms before it reads again, so that a socket that only gives errors does not spin, and whoever forges one error now and then stops nothing.
		let again = matches!(event, Event::Packet(Err(_)));
		if again && failed {sleep(Duration::from_millis(10)).await}
		failed = again;
		let mut io = Io {time: clock(), now: Instant::now(), source: &mut ask, out: &mut out};
		let done = match event {
			Event::Packet(Ok(size)) => {
				if let Some(inner) = machine.received(&buf[..size], io.now) {
					port.heard();
					if let Some(datagram) = inner {port.deliver(&datagram)}
				}
				Ok(())
			}
			Event::Packet(Err(_)) => Ok(()),
			Event::Send(datagram, kind) => {
				machine.room(port.shared.room.load(Ordering::Relaxed));
				machine.send(&datagram, kind, &mut io)
			}
			// The moment the network changes is a moment without a route as often as not: that is the device's state and no verdict on the node.
			Event::Ask(Some(Ask::Moved)) => match bound(to, &hook).await {
				Ok(fresh) => {
					socket = fresh;
					machine.moved(&mut io)
				}
				Err(_) => return End::Offline.into(),
			},
			// There is nothing to say to the node: a session of `udp-obfs` ends by its idle time. What the caller handed over before it closed goes out first.
			Event::Ask(Some(Ask::Power)) => Ok(()),
			Event::Ask(_) => {
				while let Ok((datagram, kind)) = port.out.try_recv() {
					if machine.send(&datagram, kind, &mut io).is_err() {break}
				}
				for packet in out.drain(..) {let _ = socket.send(&packet).await;}
				return Ended::Closed(End::Asked);
			}
			Event::Timer => Ok(()),
		};
		if let Err(ended) = done.map_err(Ended::from).and_then(|()| machine.tick(&mut io)) {return ended}
		port.dropped(machine.dropped());
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;
	use veilway_proto::subscription::payload::Padding as Bounds;
	use veilway_proto::subscription::Secret;

	const TIME: u64 = 1_700_000_000;

	// "No outer fragmentation": the socket of plain `udp` and of `udp-obfs` alike is made here, and the system is told to probe the path and never to fragment.
	#[cfg(any(target_os = "linux", target_os = "android"))]
	#[tokio::test]
	async fn the_socket_of_a_datagram_transport_is_made_with_fragmentation_prohibited() {
		let socket = bound("127.0.0.1:9".parse().unwrap(), &None).await.unwrap();
		assert_eq!(sockopt::ip_mtu_discover(&socket).unwrap(), sockopt::Ipv4PathMtuDiscovery::PROBE);
		assert!(DONT_FRAGMENT);
		// The caller's hook has the socket before it is connected, and a hook that says no is a device that cannot dial.
		let refused: Hook = Arc::new(|_| Err(std::io::Error::other("no")));
		assert!(bound("127.0.0.1:9".parse().unwrap(), &Some(refused)).await.is_err());
	}

	fn link() -> Link {Link {inbound: [1; 32], device: [2; 32], secret: Secret::new([3; 32]), node: None, mtu: 1390, padding: Bounds {wide_max: 1023, normal_max: 255, keepalive: 20_000..=40_000}, borrowed: Default::default()}}

	// The WireGuard layer of a test: a handshake initiation in shape for an opening, a keepalive in shape for the idle keepalive, and a count of how often each was asked.
	fn source(asked: &mut (usize, usize)) -> impl FnMut(Want) -> Option<Vec<u8>> + '_ {
		move |want| match want {
			Want::First => {
				asked.0 += 1;
				Some([&[1, 0, 0, 0][..], &[asked.0 as u8; 144]].concat())
			}
			Want::Keepalive => {
				asked.1 += 1;
				Some([&[4, 0, 0, 0][..], &[0; 28]].concat())
			}
		}
	}

	// The node's side of one opening packet: the datagram in it and the two directions of its session, by the keys the client would have. The client's keys are private to it, so the node here is `veilway-proto`'s own.
	fn node(packet: &[u8]) -> (Vec<u8>, Sender, Receiver) {
		use veilway_proto::keys::{Device, Table, TagKey};
		use veilway_proto::replay::{Decision, Replay, Started};
		let (mut table, mut scratch, tags) = (Table::new(), Vec::new(), TagKey::derive(&[3; 32], &[1; 32]));
		for epoch in udp_obfs::epochs(TIME) {assert!(table.epoch(tags.epoch_tag(epoch), Device::derive((), &[3; 32], &[1; 32], &[2; 32])));}
		let opening = udp_obfs::Node::new(&[1; 32]).open(packet, &table, &mut scratch).expect("the node does not open the client's opening packet");
		let Started::NoFile(pending) = Replay::start(None, TIME - 100, 9) else {panic!("a start without a file")};
		let mut replay = pending.written();
		assert!(replay.raise(TIME + 20).is_some());
		replay.written();
		let Decision::Accepted(accepted) = opening.accept(&mut replay, TIME, |_| true) else {panic!("the replay rule refused a fresh opening packet")};
		(accepted.datagram.to_vec(), Sender::new(accepted.keys.s2c, Padding::new(1023, 255, &mut random).unwrap()), Receiver::new(accepted.keys.c2s))
	}

	fn answer(tx: &mut Sender, datagram: Option<&[u8]>) -> Vec<u8> {
		let mut packet = Vec::new();
		tx.seal(datagram, false, 1452, &mut random, &mut packet).unwrap();
		packet
	}

	#[test]
	fn an_opening_packet_is_sent_again_after_1_2_and_4_seconds_and_then_the_attempt_is_lost() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		let mut sent = vec![0];
		for millis in (100..=9_900).step_by(100) {
			assert_eq!(machine.tick(&mut Io {time: TIME, now: start + Duration::from_millis(millis), source: &mut ask, out: &mut out}), Ok(()));
			if out.len() > sent.len() {sent.push(millis)}
		}
		assert_eq!(sent, [0, 1_000, 3_000, 7_000]);
		assert_eq!(machine.deadline(), start + ATTEMPT);
		assert_eq!(machine.tick(&mut Io {time: TIME, now: start + ATTEMPT, source: &mut ask, out: &mut out}), Err(Ended::Unreachable(Unreachable::Silence)));
		// "With a fresh salt and a fresh WireGuard datagram of the same kind", and never smaller than a first answer.
		let opened: Vec<Vec<u8>> = out.iter().map(|packet| node(packet).0).collect();
		assert!(out.iter().all(|packet| packet.len() >= udp_obfs::FIRST_ANSWER) && (0..4).all(|at| opened[at][4] == at as u8 + 1));
		assert!((0..4).all(|one| (one + 1..4).all(|other| out[one][16..48] != out[other][16..48])));
		drop(ask);
		assert_eq!(asked, (4, 0));
	}

	#[test]
	fn the_old_session_stays_in_use_until_the_first_answer_of_the_new_one_opens() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		let (_, mut first_tx, mut first_rx) = node(&out[0]);
		// Before the first answer there is no session to send on, and nothing is sent outside one.
		machine.send(&[4; 64], Kind::Packet {flow: 0, control: false}, &mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		assert_eq!((out.len(), machine.dropped(), machine.established()), (1, 1, false));
		assert_eq!(machine.received(&answer(&mut first_tx, Some(&[2; 92])), start), Some(Some(vec![2; 92])));
		assert!(machine.established());
		// A second session is asked for. Until its answer opens, what is sent is sent on the first.
		let later = start + Duration::from_secs(50);
		machine.moved(&mut Io {time: TIME, now: later, source: &mut ask, out: &mut out}).unwrap();
		let (_, mut second_tx, mut second_rx) = node(&out[1]);
		machine.send(&[4; 64], Kind::Packet {flow: 0, control: false}, &mut Io {time: TIME, now: later, source: &mut ask, out: &mut out}).unwrap();
		let mut scratch = Vec::new();
		assert_eq!(first_rx.open(&out[2], &mut scratch).map(|datagram| datagram.map(<[u8]>::len)), Ok(Some(64)));
		assert!(second_rx.open(&out[2], &mut scratch).is_err());
		assert_eq!(machine.received(&answer(&mut second_tx, None), later), Some(None));
		machine.send(&[4; 64], Kind::Packet {flow: 0, control: false}, &mut Io {time: TIME, now: later, source: &mut ask, out: &mut out}).unwrap();
		assert_eq!(second_rx.open(&out[3], &mut scratch).map(|datagram| datagram.map(<[u8]>::len)), Ok(Some(64)));
		// "Keeps the old session readable for 10 s after that", and not longer.
		assert_eq!(machine.received(&answer(&mut first_tx, Some(&[4; 48])), later + Duration::from_secs(9)), Some(Some(vec![4; 48])));
		assert_eq!(machine.received(&answer(&mut first_tx, Some(&[4; 48])), later + Duration::from_secs(10)), None);
		assert_eq!(machine.received(&answer(&mut second_tx, Some(&[4; 48])), later + Duration::from_secs(10)), Some(Some(vec![4; 48])));
	}

	// An answer that comes late: the second opening packet has left by then and reaches the node too, which moves to the session it opens.
	#[test]
	fn a_newer_opening_packet_of_the_attempt_stays_readable_after_an_older_one_was_answered() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		machine.tick(&mut Io {time: TIME, now: start + Duration::from_secs(1), source: &mut ask, out: &mut out}).unwrap();
		let ((_, mut first_tx, mut first_rx), (_, mut second_tx, mut second_rx), late, mut scratch) = (node(&out[0]), node(&out[1]), start + Duration::from_millis(1_100), Vec::new());
		assert_eq!(machine.received(&answer(&mut first_tx, Some(&[2; 92])), late), Some(Some(vec![2; 92])));
		machine.send(&[4; 64], Kind::Packet {flow: 0, control: false}, &mut Io {time: TIME, now: late, source: &mut ask, out: &mut out}).unwrap();
		assert!(first_rx.open(&out[2], &mut scratch).is_ok());
		// The node's first answer on the second session opens, and from then on that session is the one in use. The first stays readable for its 10 s.
		assert_eq!(machine.received(&answer(&mut second_tx, Some(&[2; 92])), late), Some(Some(vec![2; 92])));
		machine.send(&[4; 64], Kind::Packet {flow: 0, control: false}, &mut Io {time: TIME, now: late, source: &mut ask, out: &mut out}).unwrap();
		assert!(second_rx.open(&out[3], &mut scratch).is_ok() && first_rx.open(&out[3], &mut scratch).is_err());
		assert_eq!(machine.received(&answer(&mut first_tx, Some(&[4; 48])), late + Duration::from_secs(9)), Some(Some(vec![4; 48])));
		// The attempt is over with its first answer: no opening packet follows, and nothing is lost when its 10 s pass.
		for second in 2..19 {assert_eq!(machine.tick(&mut Io {time: TIME, now: start + Duration::from_secs(second), source: &mut ask, out: &mut out}), Ok(()))}
		assert_eq!(out.len(), 4);
	}

	#[test]
	fn an_idle_keepalive_that_nobody_answers_opens_a_new_session_and_an_answered_one_does_not() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		let (_, mut tx, mut rx) = node(&out[0]);
		machine.received(&answer(&mut tx, Some(&[2; 92])), start).unwrap();
		// The keepalive goes out after a send silence of 20 to 40 s and its own delay of up to 3 s, in a data packet.
		let (mut now, mut scratch) = (start, Vec::new());
		while out.len() == 1 {
			now += Duration::from_millis(100);
			machine.tick(&mut Io {time: TIME, now, source: &mut ask, out: &mut out}).unwrap();
		}
		assert!((20_000..=43_100).contains(&(now - start).as_millis()), "an idle keepalive after {:?}", now - start);
		assert_eq!(rx.open(&out[1], &mut scratch).map(|datagram| datagram.map(<[u8]>::len)), Ok(Some(32)));
		// The node's echo within 10 s: no opening packet follows.
		machine.received(&answer(&mut tx, None), now + Duration::from_secs(3)).unwrap();
		for step in 0..150 {machine.tick(&mut Io {time: TIME, now: now + Duration::from_millis(100 * step), source: &mut ask, out: &mut out}).unwrap()}
		assert_eq!(out.len(), 2);
		// The next one gets nothing back: 10 s later an opening packet with a fresh datagram is sent, and when that attempt is lost the session is lost.
		while out.len() == 2 {
			now += Duration::from_millis(100);
			machine.tick(&mut Io {time: TIME, now, source: &mut ask, out: &mut out}).unwrap();
		}
		let sent = now;
		let ended = loop {
			now += Duration::from_millis(100);
			if let Err(ended) = machine.tick(&mut Io {time: TIME, now, source: &mut ask, out: &mut out}) {break ended}
		};
		assert_eq!(ended, Ended::Closed(End::Lost));
		assert_eq!((now - sent, out.len()), (LIVENESS + ATTEMPT, 7));
		assert!(out[3..].iter().all(|packet| node(packet).0[0] == 1));
	}

	#[test]
	fn a_lower_tunnel_mtu_caps_the_padding_and_a_probe_carries_none() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		let (_, mut tx, mut rx) = node(&out[0]);
		machine.received(&answer(&mut tx, Some(&[2; 92])), start).unwrap();
		// The probes found 1080: wide or not, no packet is padded above 1080 and 62 bytes, and a datagram of that size still goes.
		machine.room(1080);
		let mut scratch = Vec::new();
		for round in 0..200u32 {
			let mut io = Io {time: TIME, now: start, source: &mut ask, out: &mut out};
			machine.send(&[4; 900], Kind::Packet {flow: 7, control: round % 2 == 0}, &mut io).unwrap();
		}
		machine.send(&[4; 1112], Kind::Packet {flow: 7, control: false}, &mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		assert!(out[1..].iter().all(|packet| packet.len() <= 1080 + 62 && rx.open(packet, &mut scratch).is_ok()) && out.len() == 202);
		// A probe above the tunnel's MTU goes at its own size, the probe and 62 bytes, and a room above the profile's is held to it.
		machine.send(&[4; 1422], Kind::Probe, &mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		machine.send(&[4; 1032], Kind::Probe, &mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		assert_eq!((out[202].len(), out[203].len()), (1422 + 30, 1032 + 30));
		machine.room(1500);
		machine.send(&[4; 1423], Kind::Packet {flow: 7, control: false}, &mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		assert_eq!((out.len(), machine.dropped()), (204, 1));
	}

	#[test]
	fn only_what_the_page_lists_opens_a_session() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		let (_, mut tx, mut rx) = node(&out[0]);
		machine.received(&answer(&mut tx, Some(&[2; 92])), start).unwrap();
		// An upload with nothing coming back but the node's own keepalives, rekey handshakes included, stays in data packets.
		let (mut now, mut scratch) = (start, Vec::new());
		for round in 0..600 {
			now += Duration::from_millis(500);
			let mut io = Io {time: TIME, now, source: &mut ask, out: &mut out};
			machine.send(&[4; 1422], Kind::Packet {flow: 7, control: false}, &mut io).unwrap();
			if round % 150 == 0 {machine.send(&[1; 148], Kind::Handshake, &mut io).unwrap()}
			machine.tick(&mut io).unwrap();
		}
		assert!(out[1..].iter().all(|packet| rx.open(packet, &mut scratch).is_ok()) && out.len() == 605);
		// A full-size inner packet carries no padding: the packet is the `mtu` and 62 bytes, and one byte more is not sent at all.
		assert!(out[1..].iter().any(|packet| packet.len() == 1452) && out.iter().all(|packet| packet.len() <= 1452));
		machine.send(&[4; 1423], Kind::Packet {flow: 7, control: false}, &mut Io {time: TIME, now, source: &mut ask, out: &mut out}).unwrap();
		assert_eq!((out.len(), machine.dropped()), (605, 1));
		// WireGuard's own timer started a handshake because the node stopped answering: that one travels in an opening packet.
		machine.send(&[1; 148], Kind::Stalled, &mut Io {time: TIME, now, source: &mut ask, out: &mut out}).unwrap();
		assert_eq!(node(&out[605]).0, [1; 148]);
		drop(ask);
		assert_eq!(asked.0, 1);
	}

	#[test]
	fn what_is_no_packet_of_a_session_changes_nothing() {
		let (start, mut asked, mut out) = (Instant::now(), (0, 0), Vec::new());
		let mut machine = Machine::new(&link(), start);
		let mut ask = source(&mut asked);
		machine.moved(&mut Io {time: TIME, now: start, source: &mut ask, out: &mut out}).unwrap();
		let (_, mut tx, _) = node(&out[0]);
		let good = answer(&mut tx, Some(&[2; 92]));
		for packet in [&[][..], &[0; 27], &[0; 28], &[0xff; 1500], &out[0], &good[..good.len() - 1]] {assert_eq!(machine.received(packet, start), None)}
		for bit in 0..good.len() * 8 {
			let mut changed = good.clone();
			changed[bit / 8] ^= 1 << (bit % 8);
			assert_eq!(machine.received(&changed, start), None);
		}
		assert!(!machine.established());
		assert_eq!(machine.received(&good, start), Some(Some(vec![2; 92])));
		// A packet that was recorded opens again, which is harmless: WireGuard refuses what is in it.
		assert_eq!(machine.received(&good, start), Some(Some(vec![2; 92])));
	}
}
