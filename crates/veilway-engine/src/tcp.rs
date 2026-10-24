//! The client end of one TCP connection inside the tunnel, as a state machine with no socket and no clock of its own: the control channel is plain TCP to the gateway, and a platform-free engine has no operating system to open it with.
//!
//! This is the smallest TCP that carries a few short messages over a path that can lose and reorder packets, which a UDP-based tunnel is. It has a handshake, one retransmission timer with a doubling wait, cumulative acknowledgments, in-order delivery (a segment that arrives ahead of its turn is dropped and the sender's timer brings it again), the peer's window, a fixed window of its own and the peer's FIN or RST. It has no congestion control beyond a small flight, no window scaling, no selective acknowledgment, no timestamps and no keepalive: the channel is a few kilobytes a minute at most.
//! It never accepts a connection. The ports and addresses of a segment are matched by the caller before `receive`, and a segment that does not fit the connection's numbers is answered with an acknowledgment or dropped, never trusted.
use crate::ip;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::Instant;

/// How much a caller may have written and not yet seen acknowledged.
pub const BUFFER: usize = 16_384;
/// What is in flight at most: a few segments, which is all a channel that sends a message at a time needs.
const FLIGHT: usize = 4;
/// "Window" this end advertises: what it can take at once. Whatever the caller has not read is taken off.
const WINDOW: usize = 65_535;
const FIRST_WAIT: Duration = Duration::from_millis(1_000);
const LAST_WAIT: Duration = Duration::from_millis(8_000);
/// Sends of one segment or SYN in a row that go unanswered before the connection is given up.
const TRIES: u32 = 8;

/// How a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
	/// The peer reset it, or reset the SYN.
	Reset,
	/// The peer closed its side in order. Whatever it sent before is still to be read.
	Fin,
	/// Nothing was acknowledged for `TRIES` sends.
	Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {SynSent, Open, Over(Closed)}

// `a` is before `b` in the circle of sequence numbers.
fn before(a: u32, b: u32) -> bool {(a.wrapping_sub(b) as i32) < 0}

pub struct Conn {
	local: (IpAddr, u16),
	remote: (IpAddr, u16),
	state: State,
	// Unacknowledged sequence number, next to send, next expected from the peer.
	una: u32,
	next: u32,
	expected: u32,
	peer_window: usize,
	mss: usize,
	// What the caller wrote and the peer has not acknowledged: the first `next - una` bytes were sent.
	pending: VecDeque<u8>,
	received: Vec<u8>,
	tries: u32,
	wait: Duration,
	due: Option<Instant>,
}

impl std::fmt::Debug for Conn {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "Conn({:?}, {} unacknowledged)", self.state, self.pending.len())}
}

impl Conn {
	/// Sends the SYN. `mss` is the largest segment this end takes: the tunnel's MTU less the headers of its family.
	pub fn open(local: (IpAddr, u16), remote: (IpAddr, u16), start: u32, mss: u16, now: Instant, out: &mut Vec<Vec<u8>>) -> Self {
		let conn = Self {local, remote, state: State::SynSent, una: start, next: start.wrapping_add(1), expected: 0, peer_window: 0, mss: usize::from(mss), pending: VecDeque::new(), received: Vec::new(), tries: 0, wait: FIRST_WAIT, due: Some(now + FIRST_WAIT)};
		out.extend(ip::tcp(local, remote, start, 0, ip::SYN, WINDOW as u16, Some(mss), &[]));
		conn
	}
	pub fn local(&self) -> (IpAddr, u16) {self.local}
	/// Whether the handshake is done and the connection is not over.
	pub fn is_open(&self) -> bool {self.state == State::Open}
	pub fn closed(&self) -> Option<Closed> {if let State::Over(closed) = self.state {Some(closed)} else {None}}
	pub fn due(&self) -> Option<Instant> {self.due}
	/// What arrived in order and was not read before.
	pub fn read(&mut self) -> Vec<u8> {std::mem::take(&mut self.received)}
	fn window(&self) -> u16 {WINDOW.saturating_sub(self.received.len()) as u16}
	fn flags(&self, flags: u8, sequence: u32, data: &[u8], out: &mut Vec<Vec<u8>>) {out.extend(ip::tcp(self.local, self.remote, sequence, self.expected, flags, self.window(), None, data))}
	// Sends what the window and the flight allow.
	fn flush(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
		if self.state != State::Open {return}
		let limit = self.peer_window.min(FLIGHT * self.mss);
		loop {
			let sent = self.next.wrapping_sub(self.una) as usize;
			let size = self.mss.min(self.pending.len() - sent).min(limit.saturating_sub(sent));
			if size == 0 {
				// A peer that closed its window with data waiting is asked again by the timer, one byte at a time: a window that is never opened again ends the connection by the same tries as any silence, and is not a connection that is open for ever.
				if limit == 0 && sent == 0 && !self.pending.is_empty() && self.due.is_none() {self.due = Some(now + self.wait)}
				break;
			}
			let data: Vec<u8> = self.pending.iter().skip(sent).take(size).copied().collect();
			self.flags(ip::ACK | ip::PSH, self.next, &data, out);
			self.next = self.next.wrapping_add(size as u32);
			if self.due.is_none() {self.due = Some(now + self.wait)}
		}
	}
	/// Takes bytes to send. False, and nothing taken, when more than `BUFFER` would be waiting or the connection is not open.
	pub fn write(&mut self, data: &[u8], now: Instant, out: &mut Vec<Vec<u8>>) -> bool {
		if self.state != State::Open || self.pending.len() + data.len() > BUFFER {return false}
		self.pending.extend(data);
		self.flush(now, out);
		true
	}
	/// Takes one TCP segment that is for this connection.
	pub fn receive(&mut self, segment: &ip::Segment<'_>, now: Instant, out: &mut Vec<Vec<u8>>) {
		match self.state {
			State::Over(_) => {}
			State::SynSent => {
				let answered = segment.flags & ip::ACK != 0 && segment.acknowledgment == self.next;
				if segment.flags & ip::RST != 0 {
					if answered {self.state = State::Over(Closed::Reset)}
				} else if segment.flags & ip::SYN != 0 && answered {
					(self.una, self.expected, self.peer_window, self.tries, self.wait, self.due) = (self.next, segment.sequence.wrapping_add(1), usize::from(segment.window), 0, FIRST_WAIT, None);
					if let Some(mss) = segment.mss {self.mss = self.mss.min(usize::from(mss).max(536))}
					self.state = State::Open;
					self.flags(ip::ACK, self.next, &[], out);
				}
			}
			State::Open => {
				if segment.flags & ip::RST != 0 {
					// Only a reset that fits the window is believed, so that a stray one does not end a connection.
					if segment.sequence.wrapping_sub(self.expected) < WINDOW as u32 {self.state = State::Over(Closed::Reset)}
					return;
				}
				if segment.flags & ip::ACK != 0 && before(self.una, segment.acknowledgment) && !before(self.next, segment.acknowledgment) {
					let acknowledged = segment.acknowledgment.wrapping_sub(self.una) as usize;
					self.pending.drain(..acknowledged.min(self.pending.len()));
					(self.una, self.tries, self.wait) = (segment.acknowledgment, 0, FIRST_WAIT);
					self.due = if self.una == self.next {None} else {Some(now + self.wait)};
				}
				if segment.flags & ip::ACK != 0 {self.peer_window = usize::from(segment.window)}
				let mut answer = false;
				if !segment.data.is_empty() || segment.flags & (ip::FIN | ip::SYN) != 0 {
					answer = true;
					// The part of the segment that is new, if it starts where the stream is or before.
					let skip = self.expected.wrapping_sub(segment.sequence) as usize;
					if skip <= segment.data.len() && (self.expected.wrapping_sub(segment.sequence) as i32) >= 0 {
						let fresh = &segment.data[skip..];
						if self.received.len() + fresh.len() <= WINDOW {
							self.received.extend_from_slice(fresh);
							self.expected = self.expected.wrapping_add(fresh.len() as u32);
							if segment.flags & ip::FIN != 0 {
								self.expected = self.expected.wrapping_add(1);
								self.state = State::Over(Closed::Fin);
							}
						}
					}
				}
				if answer {self.flags(ip::ACK, self.next, &[], out)}
				self.flush(now, out);
			}
		}
	}
	/// Sends again what is due.
	pub fn poll(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
		if self.due.is_none_or(|due| now < due) || matches!(self.state, State::Over(_)) {return}
		self.tries += 1;
		if self.tries >= TRIES {
			self.state = State::Over(Closed::Timeout);
			self.due = None;
			return;
		}
		self.wait = (self.wait * 2).min(LAST_WAIT);
		self.due = Some(now + self.wait);
		if self.state == State::SynSent {
			out.extend(ip::tcp(self.local, self.remote, self.una, 0, ip::SYN, WINDOW as u16, Some(self.mss as u16), &[]));
		} else {
			// With nothing in flight the bytes waiting are held back by the peer's window: one byte goes as a probe, and counts as sent.
			let inflight = self.next.wrapping_sub(self.una) as usize;
			let probing = inflight == 0;
			let data: Vec<u8> = self.pending.iter().take(if probing {1} else {self.mss.min(inflight)}).copied().collect();
			self.flags(ip::ACK | ip::PSH, self.una, &data, out);
			if probing {self.next = self.next.wrapping_add(data.len() as u32)}
		}
	}
	/// Ends the connection with a reset, which is all the channel ever needs to say when it is done.
	pub fn reset(&mut self, out: &mut Vec<Vec<u8>>) {
		if self.state == State::Open {self.flags(ip::RST | ip::ACK, self.next, &[], out)}
		self.state = State::Over(Closed::Reset);
		self.due = None;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::Ipv4Addr;

	const A: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), 40000);
	const B: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)), 47873);

	// What a segment of `packet` says, with its payload owned by the caller.
	fn parts(packet: &[u8]) -> (u32, u32, u8, Vec<u8>) {
		let found = ip::header(packet).unwrap();
		let segment = ip::segment(&packet[found.payload]).unwrap();
		(segment.sequence, segment.acknowledgment, segment.flags, segment.data.to_vec())
	}

	// A peer's reply as the segment of a packet.
	fn from_peer(sequence: u32, acknowledgment: u32, flags: u8, data: &[u8]) -> Vec<u8> {ip::tcp(B, A, sequence, acknowledgment, flags, 65535, Some(1200), data).unwrap()}

	fn feed(conn: &mut Conn, packet: &[u8], now: Instant) -> Vec<Vec<u8>> {
		let (mut out, found) = (Vec::new(), ip::header(packet).unwrap());
		conn.receive(&ip::segment(&packet[found.payload]).unwrap(), now, &mut out);
		out
	}

	fn opened(now: Instant) -> Conn {
		let mut out = Vec::new();
		let mut conn = Conn::open(A, B, 100, 1300, now, &mut out);
		assert_eq!(parts(&out[0]).2, ip::SYN);
		let answer = feed(&mut conn, &from_peer(5000, 101, ip::SYN | ip::ACK, &[]), now);
		assert_eq!((conn.is_open(), parts(&answer[0]).2, parts(&answer[0]).0, parts(&answer[0]).1), (true, ip::ACK, 101, 5001));
		conn
	}

	#[test]
	fn a_handshake_sends_and_receives_in_order_and_takes_the_smaller_segment_size() {
		let now = Instant::now();
		let mut conn = opened(now);
		let mut out = Vec::new();
		assert!(conn.write(b"hello", now, &mut out));
		assert_eq!(parts(&out[0]), (101, 5001, ip::ACK | ip::PSH, b"hello".to_vec()));
		assert!(feed(&mut conn, &from_peer(5001, 106, ip::ACK, &[]), now).is_empty());
		assert_eq!(conn.due(), None);
		let answer = feed(&mut conn, &from_peer(5001, 106, ip::ACK | ip::PSH, b"world"), now);
		assert_eq!((parts(&answer[0]).1, conn.read()), (5006, b"world".to_vec()));
		// A segment that arrives ahead of its turn is not kept, and the acknowledgment still says where the stream is. The same bytes again later are taken once.
		let answer = feed(&mut conn, &from_peer(5100, 106, ip::ACK, b"later"), now);
		assert_eq!((parts(&answer[0]).1, conn.read()), (5006, Vec::new()));
		feed(&mut conn, &from_peer(5006, 106, ip::ACK, b"abc"), now);
		feed(&mut conn, &from_peer(5006, 106, ip::ACK, b"abc"), now);
		let answer = feed(&mut conn, &from_peer(5007, 106, ip::ACK, b"bcde"), now);
		assert_eq!((parts(&answer[0]).1, conn.read()), (5011, b"abcde".to_vec()));
		// A large write is cut at the segment size the peer announced, and no more than a flight is out at once.
		let mut out = Vec::new();
		assert!(conn.write(&vec![7; 6_000], now, &mut out));
		let sizes: Vec<usize> = out.iter().map(|packet| parts(packet).3.len()).collect();
		assert_eq!(sizes, [1200, 1200, 1200, 1200]);
		let more = feed(&mut conn, &from_peer(5010, 106 + 2400, ip::ACK, &[]), now);
		assert_eq!(more.len(), 1);
		assert!(!conn.write(&vec![0; super::BUFFER], now, &mut Vec::new()));
	}

	#[test]
	fn what_is_lost_is_sent_again_with_a_longer_wait_and_given_up_after_eight_tries() {
		let now = Instant::now();
		let mut out = Vec::new();
		let mut conn = Conn::open(A, B, 7, 1300, now, &mut out);
		let mut waits = Vec::new();
		while conn.closed().is_none() {
			let at = conn.due().unwrap();
			waits.push(at - now);
			conn.poll(at, &mut out);
		}
		assert_eq!(conn.closed(), Some(Closed::Timeout));
		assert_eq!(waits.windows(2).map(|pair| (pair[1] - pair[0]).as_secs()).collect::<Vec<_>>(), [2, 4, 8, 8, 8, 8, 8]);
		assert_eq!(out.len(), 8);
		// The same on an open connection: the oldest unacknowledged segment again, and an acknowledgment gives the first wait back.
		let mut conn = opened(now);
		let mut out = Vec::new();
		conn.write(b"abc", now, &mut out);
		conn.poll(now + Duration::from_secs(1), &mut out);
		assert_eq!(parts(&out[1]), (101, 5001, ip::ACK | ip::PSH, b"abc".to_vec()));
		conn.poll(now + Duration::from_secs(1) + Duration::from_millis(100), &mut out);
		assert_eq!(out.len(), 2);
		feed(&mut conn, &from_peer(5001, 104, ip::ACK, &[]), now);
		assert_eq!(conn.due(), None);
	}

	#[test]
	fn a_reset_or_a_fin_ends_it_and_a_stray_segment_does_not() {
		let now = Instant::now();
		let mut conn = opened(now);
		// A reset far outside the window, a segment for a connection that never was, and an acknowledgment of what was never sent.
		feed(&mut conn, &from_peer(5001 + 70_000, 101, ip::RST, &[]), now);
		feed(&mut conn, &from_peer(5001, 9999, ip::ACK, &[]), now);
		assert!(conn.is_open());
		feed(&mut conn, &from_peer(5001, 101, ip::ACK | ip::FIN, b"bye"), now);
		assert_eq!((conn.closed(), conn.read()), (Some(Closed::Fin), b"bye".to_vec()));
		let mut conn = opened(now);
		feed(&mut conn, &from_peer(5001, 101, ip::RST, &[]), now);
		assert_eq!(conn.closed(), Some(Closed::Reset));
		let mut out = Vec::new();
		let mut refused = Conn::open(A, B, 100, 1300, now, &mut out);
		feed(&mut refused, &from_peer(0, 101, ip::RST | ip::ACK, &[]), now);
		assert_eq!(refused.closed(), Some(Closed::Reset));
		// A reset that does not answer the SYN is none.
		let mut guessed = Conn::open(A, B, 100, 1300, now, &mut out);
		feed(&mut guessed, &from_peer(0, 5, ip::RST | ip::ACK, &[]), now);
		assert!(guessed.closed().is_none());
		let mut out = Vec::new();
		let mut open = opened(now);
		open.reset(&mut out);
		assert_eq!((parts(&out[0]).2, open.closed()), (ip::RST | ip::ACK, Some(Closed::Reset)));
	}

	#[test]
	fn a_peer_that_closes_its_window_is_probed_and_then_given_up_and_one_that_opens_it_gets_what_waited() {
		let now = Instant::now();
		let mut out = Vec::new();
		let mut conn = Conn::open(A, B, 100, 1300, now, &mut out);
		let closed = ip::tcp(B, A, 5000, 101, ip::SYN | ip::ACK, 0, Some(1200), &[]).unwrap();
		feed(&mut conn, &closed, now);
		out.clear();
		assert!(conn.write(b"hello", now, &mut out) && out.is_empty());
		// The timer is armed, and what it sends is one byte at the number the data starts at, again and again until the tries are used.
		let mut at = now;
		let mut probes = 0;
		while conn.closed().is_none() {
			at = conn.due().expect("a connection with data waiting and a closed window has no timer");
			conn.poll(at, &mut out);
			probes += 1;
		}
		assert_eq!((conn.closed(), probes, parts(&out[0]).3), (Some(Closed::Timeout), TRIES as usize, b"h".to_vec()));
		assert!(at > now);
		// The same, and the peer opens its window: the byte it took is acknowledged and the rest follows.
		let mut out = Vec::new();
		let mut conn = Conn::open(A, B, 100, 1300, now, &mut out);
		feed(&mut conn, &closed, now);
		out.clear();
		conn.write(b"hello", now, &mut out);
		conn.poll(conn.due().unwrap(), &mut out);
		assert_eq!(parts(&out[0]), (101, 5001, ip::ACK | ip::PSH, b"h".to_vec()));
		let more = feed(&mut conn, &from_peer(5001, 102, ip::ACK, &[]), now);
		assert_eq!(parts(&more[0]), (102, 5001, ip::ACK | ip::PSH, b"ello".to_vec()));
	}

	#[test]
	fn sequence_numbers_wrap_around() {
		let now = Instant::now();
		let mut out = Vec::new();
		let mut conn = Conn::open(A, B, u32::MAX - 2, 1300, now, &mut out);
		feed(&mut conn, &from_peer(u32::MAX, u32::MAX - 1, ip::SYN | ip::ACK, &[]), now);
		assert!(conn.is_open());
		let mut out = Vec::new();
		conn.write(b"abcdef", now, &mut out);
		assert_eq!(parts(&out[0]).0, u32::MAX - 1);
		feed(&mut conn, &from_peer(0, 4, ip::ACK, &[]), now);
		assert_eq!(conn.due(), None);
		let answer = feed(&mut conn, &from_peer(0, 4, ip::ACK, b"xy"), now);
		assert_eq!((parts(&answer[0]).1, conn.read()), (2, b"xy".to_vec()));
	}
}
