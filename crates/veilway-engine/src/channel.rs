//! The device's end of one control channel connection (control channel page): the TCP connection to the gateway inside the tunnel, the opening exchange, and the messages after it, as a state machine over IP packets.
//!
//! It opens nothing by itself and applies nothing. It gives the engine what the node said, in the form the page allows: the messages the client reads, a catalogue only as a whole that passed its rules, and the five snapshot messages (`session`, `exits`, `usage`, `notices`, `hints`) no faster than "at most 1 of each kind every 5 s", a newer one replacing one that waits. Answers to the device's own requests and `bye` are given as they come. Every failure closes the connection and applies nothing from the message that caused it; what the engine does next is its own.
//! The credential is made again for every connection, from the device's transport secret. The channel does not retry: a connection that failed is one `Failure`, and the next connection is the engine's decision.
use crate::ip;
use crate::tcp::{self, Conn};
use std::net::IpAddr;
use tokio::time::Instant;
use veilway_proto::control::{kind, Catalogue, ClientMessage, DecodeError, Exit, Hint, NodeMessage, NodeMessages, Notice, Session, Usage, APPLY_INTERVAL, PORT, VERSION};
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::{ClientOpening, OpenError, DEADLINE};
use veilway_proto::subscription::Secret;
use veilway_proto::Random;

/// What the node said, ready to be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
	/// The node's credential was verified. The snapshot follows.
	Open,
	Session(Session),
	/// A whole catalogue that passed the page's rules.
	Catalogue(Vec<Exit>),
	Usage(Usage),
	Notices(Vec<Notice>),
	Hints(Vec<Hint>),
	/// An answer to a request, or `bye`.
	Answer(NodeMessage),
}

/// Why a connection is over. The engine tells the user what it can of it and decides when to open another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
	/// The opening exchange failed: a version, the credential, a message out of turn, or the time.
	Opening(OpenError),
	/// The node sent what a node does not: the connection was closed and nothing of the message was applied.
	Message(DecodeError),
	/// The connection itself ended or never opened.
	Tcp(tcp::Closed),
	/// A request could not be written or its connection could not take it.
	Request,
}

// The five kinds that are applied no faster than `APPLY_INTERVAL`.
const KINDS: usize = 5;

fn slot(event: &Event) -> Option<usize> {
	match event {
		Event::Session(_) => Some(0),
		Event::Catalogue(_) => Some(1),
		Event::Usage(_) => Some(2),
		Event::Notices(_) => Some(3),
		Event::Hints(_) => Some(4),
		_ => None,
	}
}

/// What follows the node's credential: its messages, a catalogue put together, and the limit on how fast the snapshot is applied.
pub struct Reader {messages: NodeMessages, catalogue: Catalogue, last: [Option<Instant>; KINDS], waiting: [Option<Event>; KINDS], failed: Option<DecodeError>}

impl Reader {
	pub fn new(messages: NodeMessages) -> Self {Self {messages, catalogue: Catalogue::default(), last: [None; KINDS], waiting: Default::default(), failed: None}}
	// Puts an event through the limit.
	fn apply(&mut self, event: Event, now: Instant, events: &mut Vec<Event>) {
		// A `bye` ends the connection, and what was held back for the limit is applied with it: the last `usage` that comes before a cut-off for a quota is what the engine works the next period out from.
		if matches!(event, Event::Answer(NodeMessage::Bye {..})) {
			for at in 0..KINDS {
				if let Some(held) = self.waiting[at].take() {
					self.last[at] = Some(now);
					events.push(held);
				}
			}
		}
		let Some(at) = slot(&event) else {return events.push(event)};
		if self.last[at].is_none_or(|last| now >= last + APPLY_INTERVAL) {
			(self.last[at], self.waiting[at]) = (Some(now), None);
			events.push(event);
		} else {
			self.waiting[at] = Some(event);
		}
	}
	/// Reads the messages in `data`. An error is final: nothing of the message that caused it was applied.
	pub fn feed(&mut self, data: &[u8], now: Instant, events: &mut Vec<Event>) -> Result<(), DecodeError> {
		if let Some(error) = self.failed {return Err(error)}
		let mut input = data;
		while let Some(message) = self.messages.read(&mut input).inspect_err(|error| self.failed = Some(*error))? {
			let event = match message {
				NodeMessage::Session(session) => Event::Session(session),
				NodeMessage::Exits {last, entries} => match self.catalogue.add(last, entries).inspect_err(|error| self.failed = Some(*error))? {
					Some(whole) => Event::Catalogue(whole),
					None => continue,
				},
				NodeMessage::Usage(usage) => Event::Usage(usage.clamped()),
				NodeMessage::Notices(notices) => Event::Notices(notices),
				NodeMessage::Hints(hints) => Event::Hints(hints),
				// "A client that receives an `error` naming any other type" than the requests it sends "closes the connection." The engine never sends `refresh`.
				NodeMessage::Error {answers, ..} if answers == kind::REFRESH => {
					self.failed = Some(DecodeError::Value);
					return Err(DecodeError::Value);
				}
				other => Event::Answer(other),
			};
			self.apply(event, now, events);
		}
		Ok(())
	}
	// When something held back is next due.
	fn due(&self) -> Option<Instant> {(0..KINDS).filter(|at| self.waiting[*at].is_some()).filter_map(|at| self.last[at].map(|last| last + APPLY_INTERVAL)).min()}
	// Gives what was held back and is due now.
	pub fn poll(&mut self, now: Instant, events: &mut Vec<Event>) {
		for at in 0..KINDS {
			if self.waiting[at].is_some() && self.last[at].is_some_and(|last| now >= last + APPLY_INTERVAL) {
				self.last[at] = Some(now);
				events.extend(self.waiting[at].take());
			}
		}
	}
}

enum Phase {
	Closed,
	Connecting(Conn),
	Opening {conn: Conn, opening: ClientOpening, began: Instant},
	Open {conn: Conn, reader: Reader},
}

pub struct Channel {secret: Secret<32>, inbound: [u8; 32], device: [u8; 32], min_version: u8, local: IpAddr, gateway: IpAddr, origin: Instant, phase: Phase}

impl std::fmt::Debug for Channel {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.write_str(match self.phase {Phase::Closed => "Channel(closed)", Phase::Connecting(_) => "Channel(connecting)", Phase::Opening {..} => "Channel(opening)", Phase::Open {..} => "Channel(open)"})}
}

impl Channel {
	/// A channel for the device at `local`, to the gateway at `gateway`, with the device's transport secret and the profile's `min_control_version`. `now` starts its clock.
	pub fn new(secret: Secret<32>, inbound: [u8; 32], device: [u8; 32], min_version: u8, local: IpAddr, gateway: IpAddr, now: Instant) -> Self {Self {secret, inbound, device, min_version, local, gateway, origin: now, phase: Phase::Closed}}
	pub fn is_open(&self) -> bool {matches!(self.phase, Phase::Open {..})}
	/// The local port of the connection, which the engine matches incoming segments by.
	pub fn port(&self) -> Option<u16> {
		match &self.phase {
			Phase::Closed => None,
			Phase::Connecting(conn) | Phase::Opening {conn, ..} | Phase::Open {conn, ..} => Some(conn.local().1),
		}
	}
	/// Sends the SYN from `port`. A profile that asks for a newer control channel than this build speaks is refused before anything is sent ("Versions", rule 0).
	pub fn connect(&mut self, port: u16, start: u32, mss: u16, now: Instant, out: &mut Vec<Vec<u8>>) -> Result<(), Failure> {
		if self.min_version > VERSION {return Err(Failure::Opening(OpenError::ClientTooOld))}
		self.phase = Phase::Connecting(Conn::open((self.local, port), (self.gateway, PORT), start, mss, now, out));
		Ok(())
	}
	/// Ends the connection with a reset.
	pub fn close(&mut self, out: &mut Vec<Vec<u8>>) {
		if let Phase::Connecting(conn) | Phase::Opening {conn, ..} | Phase::Open {conn, ..} = &mut self.phase {conn.reset(out)}
		self.phase = Phase::Closed;
	}
	/// Writes a request. False when the channel is not open or the connection cannot take it.
	pub fn send(&mut self, message: &ClientMessage, now: Instant, out: &mut Vec<Vec<u8>>) -> bool {
		let (Phase::Open {conn, ..}, mut bytes) = (&mut self.phase, Vec::new()) else {return false};
		message.encode(&mut bytes).is_ok() && conn.write(&bytes, now, out)
	}
	/// Takes a TCP segment of this connection. Whatever it brings goes to `events`, and a connection it ends is the `Err`.
	pub fn receive(&mut self, segment: &ip::Segment<'_>, now: Instant, random: &mut Random, out: &mut Vec<Vec<u8>>, events: &mut Vec<Event>) -> Result<(), Failure> {
		if let Phase::Connecting(conn) | Phase::Opening {conn, ..} | Phase::Open {conn, ..} = &mut self.phase {conn.receive(segment, now, out)}
		self.advance(now, random, out, events)
	}
	/// When `poll` next has something to do: a segment to send again, a message held back by the limit, an opening that runs out of time. None when nothing is waiting on the clock.
	pub fn due(&self) -> Option<Instant> {
		match &self.phase {
			Phase::Closed => None,
			Phase::Connecting(conn) => conn.due(),
			Phase::Opening {conn, began, ..} => conn.due().into_iter().chain([*began + DEADLINE]).min(),
			Phase::Open {conn, reader} => conn.due().into_iter().chain(reader.due()).min(),
		}
	}
	/// Sends again what is due, gives what was held back, and ends an opening that took too long.
	pub fn poll(&mut self, now: Instant, random: &mut Random, out: &mut Vec<Vec<u8>>, events: &mut Vec<Event>) -> Result<(), Failure> {
		if let Phase::Connecting(conn) | Phase::Opening {conn, ..} | Phase::Open {conn, ..} = &mut self.phase {conn.poll(now, out)}
		if let Phase::Open {reader, ..} = &mut self.phase {reader.poll(now, events)}
		self.advance(now, random, out, events)
	}
	// Moves the phases on as far as the bytes and the time allow. A failure leaves the channel closed, after a reset where there was a connection to reset.
	fn advance(&mut self, now: Instant, random: &mut Random, out: &mut Vec<Vec<u8>>, events: &mut Vec<Event>) -> Result<(), Failure> {
		loop {
			match std::mem::replace(&mut self.phase, Phase::Closed) {
				Phase::Closed => return Ok(()),
				Phase::Connecting(mut conn) => {
					if let Some(closed) = conn.closed() {return Err(Failure::Tcp(closed))}
					if !conn.is_open() {
						self.phase = Phase::Connecting(conn);
						return Ok(());
					}
					let (mut hello, key) = (Vec::new(), ControlKey::derive(self.secret.expose(), &self.inbound, &self.device));
					let opening = match ClientOpening::start(key, self.min_version, now.saturating_duration_since(self.origin), random, &mut hello) {
						Ok(opening) => opening,
						Err(error) => {
							conn.reset(out);
							return Err(Failure::Opening(error));
						}
					};
					if !conn.write(&hello, now, out) {
						conn.reset(out);
						return Err(Failure::Request);
					}
					self.phase = Phase::Opening {conn, opening, began: now};
				}
				Phase::Opening {mut conn, mut opening, began} => {
					let data = conn.read();
					let (mut input, mut reply) = (&data[..], Vec::new());
					let opened = match opening.receive(now.saturating_duration_since(self.origin), &mut input, &mut reply) {
						Ok(opened) => opened,
						Err(error) => {
							conn.reset(out);
							return Err(Failure::Opening(error));
						}
					};
					if !reply.is_empty() && !conn.write(&reply, now, out) {
						conn.reset(out);
						return Err(Failure::Request);
					}
					let Some(opened) = opened else {
						if let Some(closed) = conn.closed() {return Err(Failure::Tcp(closed))}
						if now >= began + DEADLINE {
							conn.reset(out);
							return Err(Failure::Opening(OpenError::Deadline));
						}
						self.phase = Phase::Opening {conn, opening, began};
						return Ok(());
					};
					events.push(Event::Open);
					let mut reader = Reader::new(opened.messages);
					// What followed the node's credential in the same segments is the start of the snapshot.
					if let Err(error) = reader.feed(input, now, events) {
						conn.reset(out);
						return Err(Failure::Message(error));
					}
					self.phase = Phase::Open {conn, reader};
				}
				Phase::Open {mut conn, mut reader} => {
					let data = conn.read();
					if let Err(error) = reader.feed(&data, now, events) {
						conn.reset(out);
						return Err(Failure::Message(error));
					}
					// What the node sent before it closed is read first, and then the close is the end.
					if let Some(closed) = conn.closed() {return Err(Failure::Tcp(closed))}
					self.phase = Phase::Open {conn, reader};
					return Ok(());
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;
	use veilway_proto::control::{self, ByeReason, ExitStatus, Load};
	use veilway_proto::opening::NodeOpening;
	use veilway_proto::NoRandom;

	const SECRET: [u8; 32] = [0xa0; 32];
	const INBOUND: [u8; 32] = [3; 32];
	const DEVICE: [u8; 32] = [4; 32];

	fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
		for (at, byte) in bytes.iter_mut().enumerate() {*byte = (at * 7 + 1) as u8}
		Ok(())
	}

	// A reader that has come out of an opening exchange with a node, which is the only way to one.
	fn reader() -> Reader {
		let key = || ControlKey::derive(&SECRET, &INBOUND, &DEVICE);
		let (mut hello, mut node_out, mut auth, mut auth_ok) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
		let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut random, &mut hello).unwrap();
		let mut node = NodeOpening::new(Duration::ZERO);
		let mut input = &hello[..];
		let keys = [key()];
		assert!(node.receive(Duration::ZERO, &keys, &mut input, &mut random, &mut node_out).unwrap().is_none());
		let mut input = &node_out[..];
		assert!(client.receive(Duration::ZERO, &mut input, &mut auth).unwrap().is_none());
		let mut input = &auth[..];
		assert!(node.receive(Duration::ZERO, &keys, &mut input, &mut random, &mut auth_ok).unwrap().is_some());
		let mut input = &auth_ok[..];
		Reader::new(client.receive(Duration::ZERO, &mut input, &mut Vec::new()).unwrap().unwrap().messages)
	}

	fn wire(messages: &[NodeMessage]) -> Vec<u8> {
		let mut bytes = Vec::new();
		for message in messages {message.encode(&mut bytes).unwrap()}
		bytes
	}

	fn exit(tag: &str, selected: bool) -> control::Exit {control::Exit {tag: tag.into(), name: "name".into(), country: None, all_protocols: true, selected, configured: false, working: true, load: Load::Unknown}}

	fn usage(used: u64) -> NodeMessage {NodeMessage::Usage(control::Usage {used_bytes: used, quota_bytes: 0, period: control::Period::None, period_start: 0, expires_at: 0, up_bytes: u64::MAX, down_bytes: 0})}

	#[test]
	fn the_snapshot_is_applied_no_faster_than_every_five_seconds_and_a_newer_message_replaces_a_waiting_one() {
		let (mut reader, now, mut events) = (reader(), Instant::now(), Vec::new());
		reader.feed(&wire(&[usage(1), NodeMessage::Notices(vec![]), usage(2), usage(3)]), now, &mut events).unwrap();
		// The first of each kind is applied at once, the numbers are clamped, and the other two wait with only the newer left.
		assert_eq!(events.len(), 2);
		assert!(matches!(&events[0], Event::Usage(usage) if usage.used_bytes == 1 && usage.up_bytes == control::USAGE_CLAMP));
		events.clear();
		reader.poll(now + Duration::from_secs(4), &mut events);
		assert!(events.is_empty());
		reader.poll(now + APPLY_INTERVAL, &mut events);
		assert!(matches!(&events[..], [Event::Usage(usage)] if usage.used_bytes == 3));
		// Answers and `bye` are handled as they come, however many there are, and a `bye` brings what was held back with it.
		events.clear();
		reader.feed(&wire(&[usage(4)]), now + Duration::from_secs(5), &mut events).unwrap();
		reader.feed(&wire(&[usage(5)]), now + Duration::from_secs(6), &mut events).unwrap();
		reader.feed(&wire(&[NodeMessage::Bye {reason: ByeReason::Quota}]), now + Duration::from_secs(7), &mut events).unwrap();
		assert!(matches!(&events[..], [Event::Usage(held), Event::Answer(NodeMessage::Bye {..})] if held.used_bytes == 5), "{events:?}");
		events.clear();
		reader.feed(&wire(&[NodeMessage::ExitResult {status: ExitStatus::Selected, tag: "a".into()}, NodeMessage::ExitResult {status: ExitStatus::Refused, tag: "a".into()}, NodeMessage::Bye {reason: ByeReason::Quota}]), now + Duration::from_secs(5), &mut events).unwrap();
		assert_eq!(events.len(), 3);
		// A message that comes in pieces, a byte at a time, is the same message.
		events.clear();
		for byte in wire(&[NodeMessage::MtuResult {mtu: 1300}]) {reader.feed(&[byte], now + Duration::from_secs(6), &mut events).unwrap()}
		assert_eq!(events, [Event::Answer(NodeMessage::MtuResult {mtu: 1300})]);
	}

	#[test]
	fn a_catalogue_is_applied_whole_and_one_that_breaks_its_rules_is_dropped_and_ends_the_connection() {
		let (mut reader, now, mut events, mut again) = (reader(), Instant::now(), Vec::new(), reader());
		let entries: Vec<control::Exit> = (0..70).map(|at| exit(&format!("e{at}"), at == 3)).collect();
		reader.feed(&wire(&control::catalogue(&entries).unwrap()), now, &mut events).unwrap();
		assert!(matches!(&events[..], [Event::Catalogue(whole)] if whole.len() == 70));
		// The first message of a catalogue alone shows nothing, and a repeated tag ends it.
		let mut bytes = Vec::new();
		NodeMessage::Exits {last: false, entries: (0..64).map(|at| exit(&format!("e{at}"), false)).collect()}.encode(&mut bytes).unwrap();
		let mut seen = Vec::new();
		again.feed(&bytes, now, &mut seen).unwrap();
		assert!(seen.is_empty());
		let mut bytes = Vec::new();
		NodeMessage::Exits {last: true, entries: vec![exit("e0", false)]}.encode(&mut bytes).unwrap();
		assert_eq!(again.feed(&bytes, now, &mut seen), Err(DecodeError::Value));
		assert!(seen.is_empty());
		// An error is final.
		assert_eq!(again.feed(&wire(&[usage(1)]), now, &mut seen), Err(DecodeError::Value));
	}

	// "A client that receives an `error` naming any other type closes the connection": the engine sends no `refresh`.
	#[test]
	fn an_error_that_names_a_request_the_client_never_sent_ends_the_connection() {
		let (now, mut events) = (Instant::now(), Vec::new());
		for (answers, ends) in [(control::kind::SET_EXIT, false), (control::kind::PROBE_START, false), (control::kind::PROBE_DOWN, false), (control::kind::SET_MTU, false), (control::kind::REFRESH, true)] {
			let mut reader = reader();
			let result = reader.feed(&wire(&[NodeMessage::Error {code: control::ErrorCode::Busy, answers}]), now, &mut events);
			assert_eq!(result.is_err(), ends, "{answers:#x}");
			if ends {assert!(reader.feed(&wire(&[usage(1)]), now, &mut events).is_err())}
		}
	}

	#[test]
	fn what_a_node_does_not_send_ends_the_connection_and_applies_nothing() {
		let (now, mut events) = (Instant::now(), Vec::new());
		// An unknown type, a body that is not its layout, a `bye` with a reason there is none of, and a notice count above the limit.
		for bytes in [vec![0, 1, 0x77], vec![0, 4, 0x98, 5, 0, 0], vec![0, 2, 0x99, 9], vec![0, 4, 0x94, 0x09, 0, 0]] {
			let mut reader = reader();
			assert!(reader.feed(&bytes, now, &mut events).is_err(), "{bytes:?}");
			assert!(reader.feed(&wire(&[usage(1)]), now, &mut events).is_err());
		}
		assert!(events.is_empty());
		// A hello after the opening is an unknown type like any other.
		assert!(reader().feed(&[0, 34, 0x01], now, &mut events).is_err());
	}

	#[test]
	fn a_channel_says_when_it_next_needs_a_tick() {
		let (now, mut out) = (Instant::now(), Vec::new());
		let mut channel = Channel::new(Secret::new(SECRET), INBOUND, DEVICE, 1, "10.7.0.2".parse().unwrap(), "10.7.0.1".parse().unwrap(), now);
		assert_eq!(channel.due(), None);
		channel.connect(40000, 1, 1200, now, &mut out).unwrap();
		assert_eq!(channel.due(), Some(now + Duration::from_millis(1_000)));
	}
}
