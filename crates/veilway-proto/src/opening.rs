//! The opening exchange of a control channel connection (control channel page, "Opening a connection", "The credential" and "Versions"), both sides, as state machines over bytes: no socket, no clock, no random source of their own.
//!
//! ```text
//! transcript = "veilway v1 control auth" || preface || hello || hello_reply
//! client_mac = HMAC-SHA-256(key = k_ctl, message = 0x01 || transcript)
//! node_mac   = HMAC-SHA-256(key = k_ctl, message = 0x02 || transcript)
//! ```
//!
//! Each machine takes exactly the bytes of the exchange from its input and leaves what follows untouched. The decoder for the rest of the connection is part of what an exchange gives when it opens, and there is no other way to one: a peer that has proven nothing is read through nothing but these machines, which keep at most 36 bytes of it.
use crate::{control::{kind, ClientMessages, DecodeError, Frames, NodeMessages, PREFACE, VERSION}, keys::{ControlKey, CONTROL_AUTH}, Random};
use std::{ops::RangeInclusive, time::Duration};

/// "Time to finish authentication: 10 s from the TCP accept on the node, and 10 s from the TCP connection being open on the client."
pub const DEADLINE: Duration = Duration::from_secs(10);
/// A device has at most this many transport secrets at once (overview, "Rotation"), so a node checks a MAC against at most this many keys.
pub const KEYS: usize = 2;
// The direction byte in front of the transcript.
const CLIENT: u8 = 0x01;
const NODE: u8 = 0x02;

/// Why an exchange failed. Each side closes the connection and sends nothing about the cause. An error is final: every later call gives it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
	/// The bytes are not the preface or not a message of the exchange.
	Decode(DecodeError),
	/// A message of the exchange at the wrong point of it.
	Unexpected,
	/// The client only: the signed profile demands a `min_control_version` above what this client speaks. Nothing was sent. The app needs an update: here the app is too old, not the node.
	ClientTooOld,
	/// The client only: the node answered a version below `min_control_version` of the signed profile. The user is told the node is too old, and no lower version is tried.
	NodeTooOld,
	/// The node: the client offered version 0. The client: the node answered version 0 or one above the offer, which breaks the protocol and is not an old node.
	Version,
	/// The node: no secret of the device gives this `client_mac`. The client: the node's credential is wrong, so nothing it sent is applied and the user is told the control channel could not be verified.
	Auth,
	/// The exchange did not finish in time. The client treats the channel as unavailable.
	Deadline,
	/// The node only: it was given more keys than a device can have secrets.
	Keys,
	/// The random source failed.
	Random,
	/// The exchange is over and was asked to go on.
	Finished,
}

impl std::fmt::Display for OpenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "control channel opening: {self:?}")}
}

impl std::error::Error for OpenError {}

#[derive(Debug, Clone, Copy)]
enum Step {
	// The client waits for `hello_reply`, the node for `hello`.
	First,
	// The client waits for `auth_ok`, the node for `auth`. Holds the version.
	Second(u8),
	Open,
	Failed(OpenError),
}

// The four messages of the exchange have one `length` each: a version and a number, or a MAC. Anything longer is refused at its third byte, and every other type is unknown here.
fn lengths(kind: u8) -> Option<RangeInclusive<usize>> {
	match kind {
		kind::HELLO | kind::HELLO_REPLY => Some(34..=34),
		kind::AUTH | kind::AUTH_OK => Some(33..=33),
		_ => None,
	}
}

// Appends `hello`, `hello_reply`, `auth` or `auth_ok`: the `length`, the type, then the version and the number, or the MAC.
fn write(kind: u8, version: Option<u8>, bytes: &[u8; 32], out: &mut Vec<u8>) {
	out.extend_from_slice(&[0x00, 33 + u8::from(version.is_some()), kind]);
	out.extend(version);
	out.extend_from_slice(bytes);
}

/// What the client holds when the exchange has opened.
#[derive(Debug)]
pub struct ClientOpened {
	/// The version both sides speak from here on.
	pub version: u8,
	/// The reader for everything the node sends from here on, the snapshot first.
	pub messages: NodeMessages,
}

/// What the node holds when the exchange has opened.
#[derive(Debug)]
pub struct NodeOpened {
	/// The version both sides speak from here on.
	pub version: u8,
	/// Which of the device's keys, by its position in the list the node passed, gave the client's MAC.
	pub key: usize,
	/// The reader for the client's requests.
	pub messages: ClientMessages,
}

/// The client's side.
#[derive(Debug)]
pub struct ClientOpening {frames: Frames, transcript: Vec<u8>, key: ControlKey, min_version: u8, opened: Duration, step: Step}

impl ClientOpening {
	/// Appends the preface and `hello` to `out`. `key` is the device's `k_ctl`, `min_version` is `min_control_version` of the signed profile, and `now` is the moment the TCP connection is open, on any clock that only moves forward. Every later `now` is on the same clock.
	/// A profile that demands more than this client speaks is refused here, before anything is written ("Versions", rule 0).
	pub fn start(key: ControlKey, min_version: u8, now: Duration, random: &mut Random, out: &mut Vec<u8>) -> Result<Self, OpenError> {
		if min_version > VERSION {return Err(OpenError::ClientTooOld)}
		let mut nonce = [0; 32];
		random(&mut nonce).map_err(|_| OpenError::Random)?;
		let mut transcript = [&[CLIENT][..], CONTROL_AUTH, &PREFACE[..]].concat();
		write(kind::HELLO, Some(VERSION), &nonce, &mut transcript);
		out.extend_from_slice(&transcript[1 + CONTROL_AUTH.len()..]);
		Ok(Self {frames: Frames::new(lengths, false), transcript, key, min_version, opened: now, step: Step::First})
	}
	/// When the client gives up on an exchange that has not opened: the caller's timer. `receive` refuses from this moment on.
	pub fn deadline(&self) -> Duration {self.opened.saturating_add(DEADLINE)}
	/// Takes the node's bytes from the front of `input`. After `hello_reply` it appends `auth` to `out`. After an `auth_ok` with the node's credential it gives the version and the reader for the rest. Whatever is left in `input` is the snapshot, which only that reader reads.
	/// `None` means more bytes are needed.
	pub fn receive(&mut self, now: Duration, input: &mut &[u8], out: &mut Vec<u8>) -> Result<Option<ClientOpened>, OpenError> {
		let deadline = self.deadline();
		let result = (|| -> Result<Option<ClientOpened>, OpenError> {loop {
			match self.step {
				Step::Failed(error) => return Err(error),
				Step::Open => return Err(OpenError::Finished),
				_ => {}
			}
			if now >= deadline {return Err(OpenError::Deadline)}
			let Some(message) = self.frames.read(input).map_err(OpenError::Decode)? else {return Ok(None)};
			match (self.step, message) {
				(Step::First, [_, _, kind::HELLO_REPLY, version, ..]) => {
					// "Versions", rule 3: an answer above the offer, or 0, breaks the protocol. One below what the profile demands is an old node.
					if *version == 0 || *version > VERSION {return Err(OpenError::Version)}
					if *version < self.min_version {return Err(OpenError::NodeTooOld)}
					self.transcript.extend_from_slice(message);
					write(kind::AUTH, None, &self.key.mac(&self.transcript), out);
					self.step = Step::Second(*version);
				}
				(Step::Second(version), [_, _, kind::AUTH_OK, mac @ ..]) => {
					self.transcript[0] = NODE;
					if !<&[u8; 32]>::try_from(mac).is_ok_and(|mac| self.key.verify(&self.transcript, mac)) {return Err(OpenError::Auth)}
					self.step = Step::Open;
					return Ok(Some(ClientOpened {version, messages: NodeMessages::new()}));
				}
				_ => return Err(OpenError::Unexpected),
			}
		}})();
		if let Err(error) = result {self.step = Step::Failed(error)}
		result
	}
}

/// The node's side, for one accepted connection.
#[derive(Debug)]
pub struct NodeOpening {frames: Frames, transcript: Vec<u8>, accepted: Duration, step: Step}

impl NodeOpening {
	/// `now` is the time of the TCP accept, on any clock that only moves forward. Every later `now` is on the same clock.
	pub fn new(now: Duration) -> Self {Self {frames: Frames::new(lengths, true), transcript: [&[CLIENT][..], CONTROL_AUTH, &PREFACE[..]].concat(), accepted: now, step: Step::First}}
	/// When the node closes the connection if the exchange has not opened: the caller's timer. `receive` refuses from this moment on.
	pub fn deadline(&self) -> Duration {self.accepted.saturating_add(DEADLINE)}
	/// Takes the client's bytes from the front of `input`. After `hello` it appends `hello_reply` to `out`. After an `auth` that one of `keys` verifies it appends `auth_ok` under that key, and gives the version, which key it was and the reader for the client's requests. `None` means more bytes are needed.
	/// `keys` are the `k_ctl` of every transport secret of the device the connection came from, one or two, and the same on every call. The MAC is checked against all of them, always all, in constant time each. More than two is refused before a byte is read.
	pub fn receive(&mut self, now: Duration, keys: &[ControlKey], input: &mut &[u8], random: &mut Random, out: &mut Vec<u8>) -> Result<Option<NodeOpened>, OpenError> {
		let deadline = self.deadline();
		let result = (|| -> Result<Option<NodeOpened>, OpenError> {loop {
			match self.step {
				Step::Failed(error) => return Err(error),
				Step::Open => return Err(OpenError::Finished),
				_ => {}
			}
			if keys.len() > KEYS {return Err(OpenError::Keys)}
			if now >= deadline {return Err(OpenError::Deadline)}
			let Some(message) = self.frames.read(input).map_err(OpenError::Decode)? else {return Ok(None)};
			match (self.step, message) {
				(Step::First, [_, _, kind::HELLO, max_version, ..]) => {
					// "Versions", rule 2: the lower of the client's highest and this node's highest, and a close if that would be 0.
					let version = (*max_version).min(VERSION);
					if version == 0 {return Err(OpenError::Version)}
					let mut nonce = [0; 32];
					random(&mut nonce).map_err(|_| OpenError::Random)?;
					self.transcript.extend_from_slice(message);
					let reply = self.transcript.len();
					write(kind::HELLO_REPLY, Some(version), &nonce, &mut self.transcript);
					out.extend_from_slice(&self.transcript[reply..]);
					self.step = Step::Second(version);
				}
				(Step::Second(version), [_, _, kind::AUTH, mac @ ..]) => {
					let mac: &[u8; 32] = mac.try_into().map_err(|_| OpenError::Decode(DecodeError::Body))?;
					let matched = keys.iter().enumerate().fold(None, |found, (index, key)| if key.verify(&self.transcript, mac) && found.is_none() {Some((index, key))} else {found});
					let Some((index, key)) = matched else {return Err(OpenError::Auth)};
					self.transcript[0] = NODE;
					write(kind::AUTH_OK, None, &key.mac(&self.transcript), out);
					self.step = Step::Open;
					return Ok(Some(NodeOpened {version, key: index, messages: ClientMessages::new()}));
				}
				_ => return Err(OpenError::Unexpected),
			}
		}})();
		if let Err(error) = result {self.step = Step::Failed(error)}
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::control::{ByeReason, ClientMessage, NodeMessage};

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn key() -> ControlKey {ControlKey::derive(&std::array::from_fn(|i| i as u8), &std::array::from_fn(|i| 32 + i as u8), &std::array::from_fn(|i| 64 + i as u8))}

	fn filled(value: u8) -> impl FnMut(&mut [u8]) -> Result<(), crate::NoRandom> {
		move |bytes: &mut [u8]| {
			bytes.fill(value);
			Ok(())
		}
	}

	// Expected MACs come from tests/vectors.py, which uses only Python's hmac and hashlib, with S = 00..1f, inbound_pub = 20..3f, device_pub = 40..5f, a client nonce of c1 bytes and a node nonce of 4e bytes.
	#[test]
	fn the_exchange_byte_for_byte() {
		let (mut up, mut down) = (Vec::new(), Vec::new());
		let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut filled(0xc1), &mut up).unwrap();
		assert_eq!(hex(&up), format!("00565743544c0000002201{}{}", "01", "c1".repeat(32)));
		let mut node = NodeOpening::new(Duration::ZERO);
		assert!(node.receive(Duration::from_secs(1), &[key()], &mut &up[..], &mut filled(0x4e), &mut down).unwrap().is_none());
		assert_eq!(hex(&down), format!("00228101{}", "4e".repeat(32)));
		up.clear();
		assert!(client.receive(Duration::from_secs(1), &mut &down[..], &mut up).unwrap().is_none());
		assert_eq!(hex(&up), "002102363831371300d967c96f3d060054f8c63aa59edba400358dadd9b078557f755e");
		down.clear();
		// A request follows `auth` in the same bytes, and the snapshot follows `auth_ok`: both are left for the readers the exchange gives.
		up.extend_from_slice(&[0x00, 0x01, 0x10]);
		let mut input = &up[..];
		let mut opened = node.receive(Duration::from_secs(2), &[key()], &mut input, &mut filled(0x4e), &mut down).unwrap().unwrap();
		assert_eq!((opened.version, opened.key, input), (1, 0, &[0x00, 0x01, 0x10][..]));
		assert_eq!(opened.messages.read(&mut input), Ok(Some(ClientMessage::Refresh)));
		assert_eq!(hex(&down), "0021826b900f92583b8f93c37e86f2a9d70aba03f0dfd04d3170a32d505c4933bce278");
		down.extend_from_slice(&[0x00, 0x02, 0x99, 0x04]);
		let mut input = &down[..];
		let mut opened = client.receive(Duration::from_secs(2), &mut input, &mut up).unwrap().unwrap();
		assert_eq!((opened.version, input), (1, &[0x00, 0x02, 0x99, 0x04][..]));
		assert_eq!(opened.messages.read(&mut input), Ok(Some(NodeMessage::Bye {reason: ByeReason::Stopping})));
		assert_eq!(client.receive(Duration::from_secs(2), &mut input, &mut up).unwrap_err(), OpenError::Finished);
		assert_eq!(node.receive(Duration::from_secs(2), &[key()], &mut &[][..], &mut filled(0x4e), &mut Vec::new()).unwrap_err(), OpenError::Finished);
	}

	// "A changed `max_version` or `version` in the opening exchange makes both MACs fail": the transcript covers both bytes, and the direction byte keeps one side's MAC from serving as the other's.
	#[test]
	fn both_macs_cover_both_version_bytes_and_the_direction() {
		let mut transcript = [&[CLIENT][..], CONTROL_AUTH, &PREFACE[..]].concat();
		write(kind::HELLO, Some(1), &[0xc1; 32], &mut transcript);
		write(kind::HELLO_REPLY, Some(1), &[0x4e; 32], &mut transcript);
		let client_mac = key().mac(&transcript);
		transcript[0] = NODE;
		let node_mac = key().mac(&transcript);
		assert_ne!(client_mac, node_mac);
		// The version bytes: `max_version` right after the type of `hello`, `version` right after the type of `hello_reply`.
		let (max_version, version) = (1 + CONTROL_AUTH.len() + 8 + 3, 1 + CONTROL_AUTH.len() + 8 + 36 + 3);
		assert_eq!((transcript[max_version], transcript[version], transcript.len()), (1, 1, 1 + 24 + 8 + 36 + 36));
		for index in [max_version, version] {
			let mut changed = transcript.clone();
			changed[index] = 2;
			assert!(!key().verify(&changed, &node_mac));
			changed[0] = CLIENT;
			assert!(!key().verify(&changed, &client_mac));
		}
	}

	// Before an exchange has opened there is no reader with the limit of a whole direction: a machine keeps one message of the exchange and refuses a longer one at its third byte.
	#[test]
	fn a_peer_that_has_proven_nothing_is_read_36_bytes_at_a_time() {
		for head in [[0x10, 0x00, kind::HELLO], [0x00, 0x23, kind::HELLO], [0x00, 0x22, kind::AUTH], [0x00, 0x21, kind::HELLO]] {
			let (mut node, bytes) = (NodeOpening::new(Duration::ZERO), [&PREFACE[..], &head, &[0; 5000]].concat());
			let mut input = &bytes[..];
			assert_eq!(node.receive(Duration::ZERO, &[key()], &mut input, &mut filled(0x4e), &mut Vec::new()).unwrap_err(), OpenError::Decode(DecodeError::Length));
			assert_eq!((bytes.len() - input.len(), node.frames.buffer.len()), (11, 3));
		}
		let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut filled(0xc1), &mut Vec::new()).unwrap();
		let bytes = [&[0xff, 0xff, kind::HELLO_REPLY][..], &[0; 5000]].concat();
		let mut input = &bytes[..];
		assert_eq!(client.receive(Duration::ZERO, &mut input, &mut Vec::new()).unwrap_err(), OpenError::Decode(DecodeError::Length));
		assert_eq!((bytes.len() - input.len(), client.frames.buffer.len()), (3, 3));
		// The snapshot before `auth_ok`: a `bye` is no message of the exchange, so nothing reads it.
		let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut filled(0xc1), &mut Vec::new()).unwrap();
		assert_eq!(client.receive(Duration::ZERO, &mut &[0x00, 0x02, 0x99, 0x04][..], &mut Vec::new()).unwrap_err(), OpenError::Decode(DecodeError::Type));
	}
}
