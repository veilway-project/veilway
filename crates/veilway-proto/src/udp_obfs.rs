//! The packets of `udp-obfs` (transports page, "`udp-obfs`"): the opening packet that starts a session and the data packets that follow, both sides.
//!
//! ```text
//! opening = (epoch tag XOR mask) (16) || salt (32) || Seal(k_open, nonce 0, aad = the 48 bytes before, 0x01 || 0 0 0 || timestamp (8) || chunk plaintext)
//! data    = nonce (12, random) || Seal(k_c2s or k_s2c, nonce, no aad, chunk plaintext)
//! ```
//!
//! This module opens and seals packets. `Node::open` says whether a datagram is an opening packet of a device, and gives no key. `Opening::accept` takes it through the replay rule and the caller's limits, and only then gives the datagram and the keys out. The rest of the node's state machine is the caller's: which sessions a source address has, and when a session is established.
use crate::{chunk::{self, ChunkError, Padding, MAX_PLAINTEXT, TAG}, keys::{ChunkKey, Device, MaskKey, ObfsKey, Salted, TagKey, Tags}, replay::{Decision, Kind, Replay, Verdict}, Random, Refused};
use ring::aead::{Aad, Nonce};
use std::{fmt, time::Duration};

/// The one version of the opening packet.
pub const VERSION: u8 = 1;
/// "Epoch: 120 s."
pub const EPOCH: u64 = 120;
/// The smallest data packet: a nonce and the tag of an empty chunk. "Shorter than 28 bytes: drop."
pub const DATA_MIN: usize = 12 + TAG;
/// The smallest opening packet: the masked tag, the salt, the 12 bytes in front of the chunk and the tag. "Shorter than 76 bytes: drop."
pub const OPENING_MIN: usize = 16 + 32 + 12 + TAG;
/// A WireGuard handshake response of 92 bytes in a data packet with no padding: the nonce, the length, the response and the tag. A client makes no opening packet smaller than this, so that the node's first answer, which is no larger than the opening packet, always has room for it.
pub const FIRST_ANSWER: usize = DATA_MIN + 2 + 92;
/// What a full-size inner packet gains on its way into a data packet: 32 bytes from WireGuard, then the nonce, the length and the tag. "On `udp-obfs` no packet is larger than `mtu` + 62 bytes."
pub const OVERHEAD: usize = 32 + 12 + 2 + TAG;
/// "The client opens a new session at 2^30 sent or received."
pub const CLIENT_PACKETS: u64 = 1 << 30;
/// "The node ends a session at 2^31 sent." No key seals more packets than this, on either side: it is the bound under which random nonces are safe.
pub const KEY_PACKETS: u64 = 1 << 31;
/// "Opening packet with no answer: sent again after 1, 2 and 4 s, then the attempt is lost."
pub const RETRIES: [Duration; 3] = [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)];
/// "Old `udp-obfs` session after a new one from the same source: readable for 10 s."
pub const OLD_READABLE: Duration = Duration::from_secs(10);
/// "Sessions at one `udp-obfs` source address and port: 4", each of another device.
pub const SOURCE_SESSIONS: usize = 4;

/// The epoch number of a moment: "Unix time in seconds divided by 120, rounded down."
pub fn epoch(time: u64) -> u64 {time / EPOCH}

/// The epochs whose tags a node's table holds at a moment: "the previous, current and next epoch".
pub fn epochs(time: u64) -> [u64; 3] {[epoch(time).saturating_sub(1), epoch(time), epoch(time).saturating_add(1)]}

/// "The client opens a new session at 2^30 sent or received."
pub fn renew(sent: u64, received: u64) -> bool {sent >= CLIENT_PACKETS || received >= CLIENT_PACKETS}

/// The two keys of a session, from the salt of its opening packet.
#[derive(Debug)]
pub struct Keys {
	/// `k_c2s`: data packets from client to node.
	pub c2s: ChunkKey,
	/// `k_s2c`: data packets from node to client.
	pub s2c: ChunkKey,
}

/// What a device holds to open sessions on one inbound.
pub struct Client {tags: TagKey, obfs: ObfsKey, mask: MaskKey}

impl Client {
	/// `secret` is the device transport secret, `inbound_pub` the inbound's WireGuard public key.
	pub fn new(secret: &[u8; 32], inbound_pub: &[u8; 32]) -> Self {Self {tags: TagKey::derive(secret, inbound_pub), obfs: ObfsKey::derive(secret, inbound_pub), mask: MaskKey::derive(inbound_pub)}}
	/// Appends an opening packet to `out` and gives the keys of the session it starts. `datagram` is the one WireGuard datagram it holds: "a handshake initiation, or a keepalive of a tunnel that is already up. It never holds user data."
	/// `timestamp` is Unix time in seconds on the client's clock, with the offset from "Refusals and clocks" when one is held, and the epoch number comes from the same value. `padding` is the padding of the direction the session will send in, and `max` the largest packet the path may get, `mtu` + 62. "On `udp-obfs` the opening packet is always padded wide and is not one of the 16: the 16 are counted over data packets."
	/// On an error nothing is appended.
	pub fn open(&self, timestamp: u64, datagram: &[u8], padding: &Padding, max: usize, random: &mut Random, out: &mut Vec<u8>) -> Result<Keys, ChunkError> {
		if !(chunk::MIN_ITEM..=chunk::MAX_ITEM).contains(&datagram.len()) {return Err(ChunkError::Item)}
		let (used, limit) = (2 + datagram.len(), max.saturating_sub(OPENING_MIN).min(MAX_PLAINTEXT));
		if used > limit {return Err(ChunkError::Size)}
		// The node's first answer is no larger than this packet, and the largest thing it has to say first is a handshake response in a data packet, `FIRST_ANSWER` bytes. Padding is raised to that where a keepalive and a small draw would leave the packet below it.
		let (padding, mut plaintext, mut header) = (padding.draw(true, used, limit, random)?.max(FIRST_ANSWER.saturating_sub(OPENING_MIN + used).min(limit - used)), Vec::new(), [VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
		chunk::write(&[datagram], padding, &mut plaintext)?;
		header[4..].copy_from_slice(&timestamp.to_be_bytes());
		self.seal(self.tags.epoch_tag(epoch(timestamp)), &header, &plaintext, random, out)
	}
	/// An opening packet whose 12 bytes in front of the chunk, whose chunk plaintext and whose epoch are whatever the caller says, for fuzzing what a node does behind the tag of the packet.
	#[cfg(fuzzing)]
	pub fn forge(&self, epoch: u64, header: &[u8; 12], plaintext: &[u8], random: &mut Random, out: &mut Vec<u8>) -> Result<Keys, ChunkError> {self.seal(self.tags.epoch_tag(epoch), header, plaintext, random, out)}
	// Appends the packet that names the device by `tag` and holds `header` and `plaintext`, under a fresh salt.
	fn seal(&self, tag: [u8; 16], header: &[u8; 12], plaintext: &[u8], random: &mut Random, out: &mut Vec<u8>) -> Result<Keys, ChunkError> {
		let mut salt = [0; 32];
		random(&mut salt)?;
		let (start, mask, (open, salted)) = (out.len(), self.mask.mask(&salt), self.obfs.opening(&salt));
		out.extend(tag.iter().zip(mask).map(|(tag, mask)| tag ^ mask));
		out.extend_from_slice(&salt);
		out.extend_from_slice(header);
		out.extend_from_slice(plaintext);
		let (head, body) = out[start..].split_at_mut(48);
		// "`k_open` seals exactly one message, because `salt` is fresh, so the fixed nonce is used once per key."
		let Ok(tag) = open.0.seal_in_place_separate_tag(Nonce::assume_unique_for_key([0; 12]), Aad::from(&*head), body) else {
			out.truncate(start);
			return Err(ChunkError::Crypto);
		};
		out.extend_from_slice(tag.as_ref());
		let [c2s, s2c] = salted.data();
		Ok(Keys {c2s, s2c})
	}
}

impl fmt::Debug for Client {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Client(..)")}
}

/// An opening packet that a device in the table sealed (node state machine, steps 4 and 5, and the version and zero bytes of step 6). It is not accepted, and it gives neither its datagram nor a key: those come from `accept`, which takes it through the replay rule and the caller's limits.
pub struct Opening<'a, T> {
	/// The device the epoch tag named, with the secret the tag came from.
	pub device: &'a Device<T>,
	/// The timestamp of the packet, Unix seconds. It is not compared with the epoch of the tag: the tag says which secret sealed the packet and for which epochs the node knows it, and the replay rule alone judges the timestamp.
	pub timestamp: u64,
	// The salt is the key of this packet in the replay cache.
	salt: [u8; 32],
	datagram: &'a [u8],
	salted: Salted,
}

// The datagram is tunnel traffic and stays out of a log line.
impl<T: fmt::Debug> fmt::Debug for Opening<'_, T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Opening({:?}, timestamp {}, ..)", self.device, self.timestamp)}
}

impl<'a, T> Opening<'a, T> {
	/// The rest of step 6 and step 7 of the node state machine: the replay rule at the wall clock `now`, then `charge`, which is the caller's rate limits and its rule that a source has sessions of at most 4 devices. `charge` is called only when the replay rule would accept, spends what it spends, and says whether there was room.
	/// When all hold, the salt is in the replay cache, and the datagram and the keys of the session are given out. On `Raise` nothing was charged or recorded: "On `udp-obfs` nothing waits: the packet is dropped, and the client's next opening packet finds the limit raised." The caller starts the write and drops what comes back.
	pub fn accept(self, replay: &mut Replay, now: u64, charge: impl FnOnce(&'a Device<T>) -> bool) -> Decision<Accepted<'a, T>, Self> {
		match replay.accept(Kind::Opening, &self.salt, self.timestamp, now, || charge(self.device)) {
			Verdict::Accept => {
				let [c2s, s2c] = self.salted.data();
				Decision::Accepted(Accepted {device: self.device, timestamp: self.timestamp, datagram: self.datagram, keys: Keys {c2s, s2c}})
			}
			Verdict::Raise(limit) => Decision::Raise(limit, self),
			Verdict::Refuse(refusal) => Decision::Refused(refusal),
		}
	}
}

/// An accepted opening packet: a pending session of this device at the packet's source.
pub struct Accepted<'a, T> {
	pub device: &'a Device<T>,
	pub timestamp: u64,
	/// The one WireGuard datagram of the packet, to process on the new session. It has authenticated nothing yet: the session is pending until WireGuard says it has.
	pub datagram: &'a [u8],
	pub keys: Keys,
}

impl<T: fmt::Debug> fmt::Debug for Accepted<'_, T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Accepted({:?}, timestamp {}, ..)", self.device, self.timestamp)}
}

/// What a node holds to open opening packets on one inbound.
#[derive(Debug)]
pub struct Node {mask: MaskKey}

impl Node {
	pub fn new(inbound_pub: &[u8; 32]) -> Self {Self {mask: MaskKey::derive(inbound_pub)}}
	/// Opens a datagram as an opening packet and finds its device in `tags` with one lookup, as an epoch tag. `tags` holds the epoch tags of the epochs the node accepts, so this function reads no clock: a table that is not rebuilt when the epoch changes refuses every client two minutes later. `scratch` is where the packet is opened.
	///
	/// "A datagram from a stranger costs the node one HMAC and one table lookup. A datagram whose unmasked tag is in the table costs one key derivation and one decryption more." A miss ends here, and the two keys of the data packets are not derived before a packet is accepted. The node answers nothing on any of these paths, so there is no timing to make equal. The answer to everything that is not an opening packet of a device in the table is the one `Refused`, and the caller drops the datagram.
	pub fn open<'a, T>(&self, packet: &[u8], tags: &'a impl Tags<T>, scratch: &'a mut Vec<u8>) -> Result<Opening<'a, T>, Refused> {self.unseal(self.find(packet, tags).ok_or(Refused)?, packet, scratch)}
	/// The first half of `open`, steps 3 and 4 of the node state machine: the device the masked tag of a datagram names, at the cost of one HMAC and one lookup. A node that counts a tag miss apart from a packet that then does not open calls this and `unseal`. It still answers nothing on either.
	pub fn find<'a, T>(&self, packet: &[u8], tags: &'a impl Tags<T>) -> Option<&'a Device<T>> {
		if packet.len() < OPENING_MIN || packet.len() > OPENING_MIN + MAX_PLAINTEXT {return None}
		let mask = self.mask.mask(&std::array::from_fn(|index| packet[16 + index]));
		tags.find_epoch(&std::array::from_fn(|index| packet[index] ^ mask[index]))
	}
	/// The second half of `open`, step 5 and the version and zero bytes of step 6, for the device `find` gave for this same datagram.
	pub fn unseal<'a, T>(&self, device: &'a Device<T>, packet: &[u8], scratch: &'a mut Vec<u8>) -> Result<Opening<'a, T>, Refused> {
		if packet.len() < OPENING_MIN || packet.len() > OPENING_MIN + MAX_PLAINTEXT {return Err(Refused)}
		let salt: [u8; 32] = std::array::from_fn(|index| packet[16 + index]);
		let (open, salted) = device.obfs.opening(&salt);
		scratch.clear();
		scratch.extend_from_slice(&packet[48..]);
		#[cfg(test)]
		crate::trace::op("aead open");
		let plaintext: &'a [u8] = open.0.open_in_place(Nonce::assume_unique_for_key([0; 12]), Aad::from(&packet[..48]), scratch).map_err(|_| Refused)?;
		let ([VERSION, 0, 0, 0, timestamp @ ..], chunk) = plaintext.split_first_chunk::<12>().ok_or(Refused)? else {return Err(Refused)};
		// "The chunk plaintext holds exactly one WireGuard datagram."
		let mut items = chunk::parse(chunk).map_err(|_| Refused)?;
		let (Some(datagram), None) = (items.next(), items.next()) else {return Err(Refused)};
		Ok(Opening {device, timestamp: u64::from_be_bytes(*timestamp), salt, datagram, salted})
	}
}

/// The sending direction of a session: data packets under one key, each with a fresh random nonce.
#[derive(Debug)]
pub struct Sender {key: ChunkKey, padding: Padding, sent: u64}

impl Sender {
	pub fn new(key: ChunkKey, padding: Padding) -> Self {Self {key, padding, sent: 0}}
	/// How many packets this key has sealed. A client opens a new session when `renew` says so.
	pub fn sent(&self) -> u64 {self.sent}
	/// Appends one data packet to `out`: the nonce, then the sealed chunk. "A chunk holds one WireGuard datagram or none": `None` gives the padding-only packet.
	/// `wide` says that the datagram is a WireGuard handshake message or holds a control channel packet. The first 16 packets are padded wide whatever it says. `max` is the largest packet that may be sent: `mtu` + 62, or for a node's first answer the size of the opening packet it answers. Padding is lowered to fit, "so a full-size inner packet carries none".
	/// On an error nothing is appended and nothing is counted. `Number` is final: the key has sealed 2^31 packets, and the session must end.
	pub fn seal(&mut self, datagram: Option<&[u8]>, wide: bool, max: usize, random: &mut Random, out: &mut Vec<u8>) -> Result<(), ChunkError> {
		if self.sent >= KEY_PACKETS {return Err(ChunkError::Number)}
		if datagram.is_some_and(|datagram| !(chunk::MIN_ITEM..=chunk::MAX_ITEM).contains(&datagram.len())) {return Err(ChunkError::Item)}
		let (used, limit) = (datagram.map_or(0, |datagram| 2 + datagram.len()), max.checked_sub(DATA_MIN).ok_or(ChunkError::Size)?.min(MAX_PLAINTEXT));
		if used > limit {return Err(ChunkError::Size)}
		let (padding, mut nonce, start) = (self.padding.draw(chunk::wide(self.sent, wide, false), used, limit, random)?, [0; 12], out.len());
		random(&mut nonce)?;
		out.extend_from_slice(&nonce);
		let sealed = chunk::write(datagram.as_slice(), padding, out).and_then(|()| self.key.0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut out[start + 12..]).map_err(|_| ChunkError::Crypto));
		match sealed {
			Ok(tag) => out.extend_from_slice(tag.as_ref()),
			Err(error) => {
				out.truncate(start);
				return Err(error);
			}
		}
		self.sent += 1;
		Ok(())
	}
}

/// The receiving direction of a session. A data packet has no number, so one that was recorded opens again: "That is harmless: what is inside is a WireGuard datagram, and WireGuard rejects a replayed one." A packet that opens is therefore no activity of the session until its datagram has authenticated.
#[derive(Debug)]
pub struct Receiver {key: ChunkKey, received: u64}

impl Receiver {
	pub fn new(key: ChunkKey) -> Self {Self {key, received: 0}}
	/// How many packets have opened under this key, replays included.
	pub fn received(&self) -> u64 {self.received}
	/// Opens a datagram as a data packet of this session and gives its WireGuard datagram, or `None` for a padding-only packet. `packet` is left as it came, so a node can try it on the next session of the same source. `scratch` is where it is opened.
	/// The answer to everything else is the one `Refused`, and the datagram is dropped silently, or tried as an opening packet.
	pub fn open<'a>(&mut self, packet: &[u8], scratch: &'a mut Vec<u8>) -> Result<Option<&'a [u8]>, Refused> {
		if packet.len() < DATA_MIN || packet.len() > DATA_MIN + MAX_PLAINTEXT {return Err(Refused)}
		let (nonce, sealed) = packet.split_first_chunk::<12>().ok_or(Refused)?;
		scratch.clear();
		scratch.extend_from_slice(sealed);
		let plaintext: &'a [u8] = self.key.0.open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::empty(), scratch).map_err(|_| Refused)?;
		// "A chunk holds one WireGuard datagram or none."
		let mut items = chunk::parse(plaintext).map_err(|_| Refused)?;
		let (datagram, None) = (items.next(), items.next()) else {return Err(Refused)};
		self.received = self.received.saturating_add(1);
		Ok(datagram)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{chunk::{NORMAL_DEFAULT, WIDE_DEFAULT}, replay::{Refusal, Started}, trace, NoRandom};

	const TIME: u64 = 1_700_000_000;
	// The largest packet of an inbound with an `mtu` of 1390.
	const MAX: usize = 1390 + 62;

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {(std::array::from_fn(|i| i as u8), std::array::from_fn(|i| 32 + i as u8), std::array::from_fn(|i| 64 + i as u8))}

	// The datagram of the vectors: 32 bytes, a WireGuard keepalive in shape.
	fn item() -> [u8; 32] {std::array::from_fn(|i| if i < 4 {[4, 0, 0, 0][i]} else {i as u8 - 4})}

	// Gives out the listed draws in order, each of exactly the size that is asked for, then fails.
	fn script<'a>(draws: &'a [&'a [u8]]) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> + 'a {
		let mut draws = draws.iter();
		move |bytes: &mut [u8]| {
			bytes.copy_from_slice(draws.next().filter(|draw| draw.len() == bytes.len()).ok_or(NoRandom)?);
			Ok(())
		}
	}

	fn seeded(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> {
		let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
		move |bytes: &mut [u8]| {
			for byte in bytes {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = (state >> 32) as u8;
			}
			Ok(())
		}
	}

	// Padding with a base of `base`.
	fn padding(base: u32) -> Padding {Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut script(&[&base.to_be_bytes()])).unwrap()}

	// A table that writes its lookups into the trace.
	struct Table(crate::keys::Table<Device<u32>>);

	impl Tags<u32> for Table {
		fn find_device(&self, tag: &[u8; 16]) -> Option<&Device<u32>> {self.0.find_device(tag)}
		fn find_epoch(&self, tag: &[u8; 16]) -> Option<&Device<u32>> {
			trace::op("lookup");
			self.0.find_epoch(tag)
		}
		fn find_hour(&self, tag: &[u8; 16]) -> Option<&Device<u32>> {self.0.find_hour(tag)}
	}

	// The device of the vectors as number 7 and a second device as number 8, each with its device tag, as a node with a stream transport would have it, and its tags for the three epochs around `time`.
	fn table(time: u64) -> Table {
		let ((_, inbound, _), mut table) = (inputs(), crate::keys::Table::new());
		for (id, secret, device) in [(7, inputs().0, inputs().2), (8, [0xb1; 32], [0xb0; 32])] {
			assert!(table.device(TagKey::derive(&secret, &inbound).device_tag(), Device::derive(id, &secret, &inbound, &device)));
			for epoch in epochs(time) {assert!(table.epoch(TagKey::derive(&secret, &inbound).epoch_tag(epoch), Device::derive(id, &secret, &inbound, &device)))}
		}
		Table(table)
	}

	fn client() -> Client {Client::new(&inputs().0, &inputs().1)}

	fn node() -> Node {Node::new(&inputs().1)}

	// A replay memory whose floor is `TIME - 40` and whose written limit is `TIME + 20`.
	fn replay() -> Replay {
		let Started::NoFile(pending) = Replay::start(None, TIME - 100, 9) else {panic!("a start without a file")};
		let mut replay = pending.written();
		assert!(replay.raise(TIME + 20).is_some());
		replay.written();
		replay
	}

	// Expected bytes come from tests/vectors.py: S = 00..1f, inbound_pub = 20..3f, a salt of 0xa5 bytes, the timestamp 1,700,000,000, a nonce of b0..bb, and in both packets the datagram above with 15 bytes of padding.
	#[test]
	fn an_opening_packet_and_a_data_packet_byte_for_byte() {
		let (ten, mut packet, mut data, table) = (10u32.to_be_bytes(), vec![0xee], Vec::new(), table(TIME));
		let keys = client().open(TIME, &item(), &padding(5), MAX, &mut script(&[&ten, &[0xa5; 32]]), &mut packet).unwrap();
		assert_eq!(hex(&packet[1..]), "3419fa47d7004263191f091d1304ae4ca5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5654991b07e2ec8eccb133bb9b322aac205ee562deb9222958b1024a2f115735d53574a4aaf5a6662046abb91568b052e24e0b1167b549fbeeb6c62b045f9e8a21550df04b93c1466d94aa495e6");
		let nonce: [u8; 12] = std::array::from_fn(|i| 0xb0 + i as u8);
		let mut sender = Sender::new(keys.c2s, padding(5));
		sender.seal(Some(&item()), false, MAX, &mut script(&[&ten, &nonce]), &mut data).unwrap();
		assert_eq!(hex(&data), "b0b1b2b3b4b5b6b7b8b9babbed366e2c4da2fceb05d974b4a6dee10bd8a44ec7550f28229e36016b42b7b976d6a7775dd349132a3fb327a72d48803d9759d79c8e74b84684d3a41681de98d1f1");
		let (mut scratch, mut second, mut replay) = (Vec::new(), Vec::new(), replay());
		let opening = node().open(&packet[1..], &table, &mut scratch).unwrap();
		assert_eq!((opening.device.id, opening.timestamp, opening.salt), (7, TIME, [0xa5; 32]));
		let Decision::Accepted(opening) = opening.accept(&mut replay, TIME, |device| device.id == 7) else {panic!("an opening packet was not accepted")};
		assert_eq!((opening.device.id, opening.timestamp, opening.datagram), (7, TIME, &item()[..]));
		let mut receiver = Receiver::new(opening.keys.c2s);
		assert_eq!(receiver.open(&data, &mut second), Ok(Some(&item()[..])));
		// The node's direction: its first answer is a padding-only packet, or one with a handshake response, and no larger than the opening packet.
		let (mut answer, mut third) = (Vec::new(), Vec::new());
		let mut back = Sender::new(opening.keys.s2c, padding(63));
		back.seal(None, false, packet.len() - 1, &mut seeded(1), &mut answer).unwrap();
		assert!(answer.len() < packet.len());
		assert_eq!(Receiver::new(keys.s2c).open(&answer, &mut third), Ok(None));
		assert_eq!(receiver.open(&answer, &mut third), Err(Refused));
	}

	// The node's first answer is no larger than the opening packet, so an opening packet around a keepalive with the smallest padding still leaves room for a handshake response. And the two halves of `open` tell a tag the table does not have from a packet that names a device and does not open.
	#[test]
	fn an_opening_packet_has_room_for_a_handshake_response_and_a_miss_is_told_from_a_packet_that_does_not_open() {
		let (zero, table, mut scratch) = (0u32.to_be_bytes(), table(TIME), Vec::new());
		for (base, max) in [(0, MAX), (0, 115), (63, MAX)] {
			let mut packet = Vec::new();
			client().open(TIME, &item(), &padding(base), max, &mut script(&[&zero, &[0xa5; 32]]), &mut packet).unwrap();
			assert_eq!(packet.len(), if max == 115 {115} else {FIRST_ANSWER.max(OPENING_MIN + 34 + base as usize)}, "base {base}, at most {max}");
		}
		assert_eq!(FIRST_ANSWER, 122);
		let mut packet = Vec::new();
		client().open(TIME, &item(), &padding(5), MAX, &mut seeded(3), &mut packet).unwrap();
		assert!(node().find(&packet, &table).is_some_and(|device| device.id == 7) && node().unseal(node().find(&packet, &table).unwrap(), &packet, &mut scratch).is_ok());
		let (mut tag, mut body) = (packet.clone(), packet.clone());
		(tag[0], body[60]) = (tag[0] ^ 1, body[60] ^ 1);
		assert!(node().find(&tag, &table).is_none() && node().open(&tag, &table, &mut scratch).is_err());
		assert!(node().find(&body, &table).is_some() && node().unseal(node().find(&body, &table).unwrap(), &body, &mut scratch).is_err() && node().open(&body, &table, &mut scratch).is_err());
		assert!(node().find(&packet[..75], &table).is_none());
	}

	#[test]
	fn the_epoch_is_120_seconds_and_a_table_holds_three() {
		assert_eq!((epoch(0), epoch(119), epoch(120), epoch(TIME)), (0, 0, 1, 14_166_666));
		assert_eq!((epochs(TIME), epochs(0), epochs(u64::MAX)), ([14_166_665, 14_166_666, 14_166_667], [0, 0, 1], [u64::MAX / 120 - 1, u64::MAX / 120, u64::MAX / 120 + 1]));
		let (mut packet, mut scratch) = (Vec::new(), Vec::new());
		client().open(TIME, &item(), &padding(0), MAX, &mut seeded(1), &mut packet).unwrap();
		// A node whose clock is one epoch behind or ahead still has the tag. Two epochs away it has not.
		for (shift, known) in [(0i64, true), (-120, true), (120, true), (-240, false), (240, false)] {assert_eq!(node().open(&packet, &table(TIME.wrapping_add_signed(shift)), &mut scratch).is_ok(), known, "a node clock {shift} s away")}
	}

	// "A datagram from a stranger costs the node one HMAC and one table lookup. A datagram whose unmasked tag is in the table costs one key derivation and one decryption more." Shown through hooks in the functions that do the work: a miss stops after the lookup, every hit that is refused does what a packet that opens does, and the keys of the data packets are derived only when a packet is accepted. A datagram of a size no opening packet has costs nothing.
	#[test]
	fn a_miss_costs_a_mask_and_a_lookup_and_every_hit_costs_the_same() {
		let (table, miss, hit, mut scratch, mut good) = (table(TIME), vec!["hmac mask", "lookup"], vec!["hmac mask", "lookup", "hkdf open", "aead open"], Vec::new(), Vec::new());
		client().open(TIME, &item(), &padding(0), MAX, &mut seeded(1), &mut good).unwrap();
		let forged = |client: &Client, tag: [u8; 16], header: [u8; 12], plaintext: &[u8]| {
			let mut packet = Vec::new();
			client.seal(tag, &header, plaintext, &mut seeded(2), &mut packet).unwrap();
			packet
		};
		let (header, one, own, stranger) = ([1, 0, 0, 0, 0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00], [&[0, 32][..], &item()].concat(), client().tags.epoch_tag(epoch(TIME)), Client::new(&[0x99; 32], &inputs().1));
		let mut refused = vec![
			("zero bytes", vec![0; OPENING_MIN], &miss),
			("random bytes", vec![0x5a; 300], &miss),
			("a device that is not in the table", forged(&stranger, stranger.tags.epoch_tag(epoch(TIME)), header, &one), &miss),
			("another inbound", forged(&Client::new(&inputs().0, &[0x99; 32]), own, header, &one), &miss),
			("an epoch the table does not hold", forged(&client(), client().tags.epoch_tag(epoch(TIME) + 2), header, &one), &miss),
			// "A device tag is valid only in a stream proof and an epoch tag only on an opening packet." The table holds this device tag, for stream proofs.
			("the device tag in front of an opening packet", forged(&client(), client().tags.device_tag(), header, &one), &miss),
			("the tag of another device in the table", forged(&client(), TagKey::derive(&[0xb1; 32], &inputs().1).epoch_tag(epoch(TIME)), header, &one), &hit),
			("a secret of zero bytes", forged(&Client::new(&[0; 32], &inputs().1), own, header, &one), &hit),
			("version 2", forged(&client(), own, [2, 0, 0, 0, 0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00], &one), &hit),
			("version 0", forged(&client(), own, [0; 12], &one), &hit),
			("no datagram", forged(&client(), own, header, &[0; 40]), &hit),
			("an empty chunk", forged(&client(), own, header, &[]), &hit),
			("two datagrams", forged(&client(), own, header, &[&one[..], &one].concat()), &hit),
			("a datagram of 31 bytes", forged(&client(), own, header, &[&[0, 31][..], &[7; 31]].concat()), &hit),
			("a length past the end", forged(&client(), own, header, &[&[0, 40][..], &[7; 39]].concat()), &hit),
		];
		for zero in 1..4 {
			let mut header = header;
			header[zero] = 1;
			refused.push(("a zero byte that is set", forged(&client(), own, header, &one), &hit));
		}
		// A changed bit in the masked tag or in the salt gives another tag, which is in no table. Behind them it is the seal that fails.
		for bit in (0..good.len() * 8).step_by(7) {
			let mut changed = good.clone();
			changed[bit / 8] ^= 1 << (bit % 8);
			refused.push(("a changed bit", changed, if bit < 48 * 8 {&miss} else {&hit}));
		}
		trace::take();
		let (opening, mut replay) = (node().open(&good, &table, &mut scratch).unwrap(), replay());
		assert_eq!(trace::take(), hit);
		assert!(matches!(opening.accept(&mut replay, TIME, |_| true), Decision::Accepted(_)));
		assert_eq!(trace::take(), ["hkdf data"]);
		// The control: a forged packet with nothing wrong in it opens, under the tag of the next epoch as well.
		assert!(node().open(&forged(&client(), client().tags.epoch_tag(epoch(TIME) + 1), header, &one), &table, &mut scratch).is_ok_and(|opening| opening.timestamp == TIME));
		trace::take();
		for (what, packet, expected) in &refused {
			assert_eq!(node().open(packet, &table, &mut scratch).map(|opening| opening.device.id), Err(Refused), "{what}");
			assert_eq!(&trace::take(), *expected, "{what}");
		}
		for packet in [&good[..OPENING_MIN - 1], &[], &vec![0; OPENING_MIN + MAX_PLAINTEXT + 1]] {
			assert_eq!(node().open(packet, &table, &mut scratch).map(|opening| opening.device.id), Err(Refused));
			assert!(trace::take().is_empty());
		}
	}

	// The rest of the node's step 6, and step 7: the datagram and the keys come out of the replay rule and the limits, and of nothing else.
	#[test]
	fn an_opening_packet_gives_its_keys_once_and_only_through_the_replay_rule() {
		let (table, mut replay, mut scratch, mut second) = (table(TIME), replay(), Vec::new(), Vec::new());
		let packet = |timestamp: u64, seed: u64| {
			let mut packet = Vec::new();
			client().open(timestamp, &item(), &padding(0), MAX, &mut seeded(seed), &mut packet).unwrap();
			packet
		};
		let first = packet(TIME, 1);
		// The limits have no room: nothing is recorded, and the same packet is good when they have.
		assert!(matches!(node().open(&first, &table, &mut scratch).unwrap().accept(&mut replay, TIME, |_| false), Decision::Refused(Refusal::Limited)));
		assert!(matches!(node().open(&first, &table, &mut scratch).unwrap().accept(&mut replay, TIME, |_| true), Decision::Accepted(_)));
		// A recorded opening packet sent again from another address: it opens, and the replay rule refuses it before a limit is asked.
		assert!(matches!(node().open(&first, &table, &mut scratch).unwrap().accept(&mut replay, TIME + 1, |_| panic!("a replay was charged")), Decision::Refused(Refusal::Seen)));
		// The timestamp is the replay rule's to judge, whatever epoch the tag is of: a packet of this epoch with a timestamp a minute and a second old is refused there.
		let mut old = Vec::new();
		client().seal(client().tags.epoch_tag(epoch(TIME)), &[1, 0, 0, 0, 0, 0, 0, 0, 0x65, 0x53, 0xf0, 0xc3], &[&[0, 32][..], &item()].concat(), &mut seeded(3), &mut old).unwrap();
		assert!(matches!(node().open(&old, &table, &mut scratch).unwrap().accept(&mut replay, TIME, |_| panic!("an old packet was charged")), Decision::Refused(Refusal::Window)));
		// A client whose clock runs ahead, at a node whose table still has its epoch: "the packet is dropped, and the client's next opening packet finds the limit raised."
		let Decision::Raise(limit, dropped) = node().open(&packet(TIME + 30, 4), &table, &mut scratch).unwrap().accept(&mut replay, TIME, |_| panic!("a packet above the limit was charged")) else {panic!("no write was asked for")};
		assert_eq!((limit, format!("{dropped:?}")), (TIME + 50, format!("Opening(Device(7, ..), timestamp {}, ..)", TIME + 30)));
		assert!(replay.raise(limit).is_some());
		replay.written();
		let Decision::Accepted(accepted) = node().open(&packet(TIME + 31, 5), &table, &mut second).unwrap().accept(&mut replay, TIME + 1, |_| true) else {panic!("the next opening packet was not accepted")};
		assert_eq!((accepted.datagram, format!("{accepted:?}"), replay.len()), (&item()[..], format!("Accepted(Device(7, ..), timestamp {}, ..)", TIME + 31), 2));
	}

	#[test]
	fn an_opening_packet_holds_one_datagram_and_fits_the_path() {
		let (client, mut out) = (client(), vec![0xee]);
		assert_eq!(client.open(TIME, &[7; 31], &padding(0), MAX, &mut seeded(1), &mut out).unwrap_err(), ChunkError::Item);
		assert_eq!(client.open(TIME, &[7; 1601], &padding(0), 9000, &mut seeded(1), &mut out).unwrap_err(), ChunkError::Item);
		assert_eq!(client.open(TIME, &[7; 148], &padding(0), OPENING_MIN + 149, &mut seeded(1), &mut out).unwrap_err(), ChunkError::Size);
		assert_eq!(client.open(TIME, &item(), &padding(0), 0, &mut seeded(1), &mut out).unwrap_err(), ChunkError::Size);
		assert_eq!(client.open(TIME, &item(), &padding(0), MAX, &mut script(&[&[0; 4]]), &mut out).unwrap_err(), ChunkError::Random);
		assert_eq!(out, [0xee]);
		// Padding is lowered to what the path takes: with room for the datagram alone there is none.
		client.open(TIME, &[7; 148], &padding(63), OPENING_MIN + 150, &mut seeded(1), &mut out).unwrap();
		assert_eq!(out.len() - 1, OPENING_MIN + 150);
		// "An opening packet of `udp-obfs` has a larger envelope, 78 bytes."
		assert_eq!(OPENING_MIN + 2, 78);
		assert_eq!((DATA_MIN + 2, OVERHEAD), (30, 62));
		for seed in 0..50 {
			let mut packet = Vec::new();
			client.open(TIME, &[7; 148], &padding(9), MAX, &mut seeded(seed), &mut packet).unwrap();
			assert!((OPENING_MIN + 150 + 9..=OPENING_MIN + 150 + 1023).contains(&packet.len()) && packet.len() <= MAX);
		}
	}

	#[test]
	fn data_packets_keep_their_limits() {
		let key = || ChunkKey::new(&[0x33; 32]);
		let (mut sender, mut receiver, mut out, mut scratch) = (Sender::new(key(), padding(0)), Receiver::new(key()), vec![0xee], Vec::new());
		assert_eq!(sender.seal(Some(&[7; 31]), false, MAX, &mut seeded(1), &mut out), Err(ChunkError::Item));
		assert_eq!(sender.seal(Some(&[7; 1601]), false, 9000, &mut seeded(1), &mut out), Err(ChunkError::Item));
		assert_eq!(sender.seal(Some(&[7; 1422]), false, MAX - 1, &mut seeded(1), &mut out), Err(ChunkError::Size));
		assert_eq!(sender.seal(None, false, DATA_MIN - 1, &mut seeded(1), &mut out), Err(ChunkError::Size));
		assert_eq!(sender.seal(None, false, DATA_MIN, &mut seeded(1), &mut out), Ok(()));
		assert_eq!((sender.sent(), out.len() - 1), (1, DATA_MIN));
		out.truncate(1);
		assert_eq!(sender.seal(Some(&item()), false, MAX, &mut script(&[&[0; 4]]), &mut out), Err(ChunkError::Random));
		assert_eq!((sender.sent(), &out[..]), (1, &[0xee][..]));
		// "Full-size inner packets give datagrams of exactly `mtu` + 62 bytes": a full-size packet carries no padding.
		sender.seal(Some(&[7; 1422]), true, MAX, &mut seeded(1), &mut out).unwrap();
		assert_eq!(out.len() - 1, MAX);
		assert_eq!(receiver.open(&out[1..], &mut scratch), Ok(Some(&[7; 1422][..])));
		// A recorded packet opens again, and counts as received each time. Nothing here calls that activity.
		assert_eq!(receiver.open(&out[1..], &mut scratch), Ok(Some(&[7; 1422][..])));
		assert_eq!(receiver.received(), 2);
		for packet in [&out[1..DATA_MIN], &[], &out[2..], &vec![0; DATA_MIN + MAX_PLAINTEXT + 1]] {assert_eq!(receiver.open(packet, &mut scratch), Err(Refused))}
		for bit in 0..(out.len() - 1) * 8 {
			let mut changed = out[1..].to_vec();
			changed[bit / 8] ^= 1 << (bit % 8);
			assert_eq!(receiver.open(&changed, &mut scratch), Err(Refused), "bit {bit}");
		}
		assert_eq!(receiver.received(), 2);
		// The first 16 packets are padded wide, from the base: here the base is 40 and every draw is 0.
		let (mut sender, zero) = (Sender::new(key(), padding(40)), [0; 4]);
		let sizes: Vec<usize> = (0..18).map(|_| {
			let mut packet = Vec::new();
			sender.seal(Some(&item()), false, MAX, &mut script(&[&zero, &[9; 12]]), &mut packet).unwrap();
			packet.len() - DATA_MIN - 34
		}).collect();
		assert_eq!(sizes, [[40; 16].as_slice(), &[0, 0]].concat());
	}

	// A chunk that a stream transport would take is no data packet when it holds two datagrams, and a packet with a bad item is dropped like any other.
	#[test]
	fn a_data_packet_holds_one_datagram_or_none() {
		let key = || ChunkKey::new(&[0x33; 32]);
		for (plaintext, expected) in [(vec![], Ok(None)), (vec![0; 9], Ok(None)), ([&[0, 32][..], &item(), &[0; 5]].concat(), Ok(Some(item()))), ([&[0, 32][..], &item(), &[0, 32], &item()].concat(), Err(Refused)), ([&[0, 31][..], &[7; 31]].concat(), Err(Refused)), ([&[0, 32][..], &item(), &[0, 9, 1]].concat(), Err(Refused))] {
			let (mut packet, mut scratch) = ([&[0x10; 12][..], &plaintext].concat(), Vec::new());
			let tag = key().0.seal_in_place_separate_tag(Nonce::assume_unique_for_key([0x10; 12]), Aad::empty(), &mut packet[12..]).unwrap();
			packet.extend_from_slice(tag.as_ref());
			assert_eq!(Receiver::new(key()).open(&packet, &mut scratch).map(|datagram| datagram.map(<[u8]>::to_vec)), expected.map(|datagram| datagram.map(|datagram| datagram.to_vec())));
		}
	}

	#[test]
	fn a_key_seals_no_more_than_its_packet_limit() {
		let (mut sender, mut out) = (Sender::new(ChunkKey::new(&[0x33; 32]), padding(0)), Vec::new());
		sender.sent = CLIENT_PACKETS - 1;
		assert!(!renew(sender.sent(), 0) && renew(CLIENT_PACKETS, 0) && renew(0, CLIENT_PACKETS) && !renew(CLIENT_PACKETS - 1, CLIENT_PACKETS - 1));
		sender.sent = KEY_PACKETS - 1;
		sender.seal(None, false, MAX, &mut seeded(1), &mut out).unwrap();
		let size = out.len();
		assert_eq!(sender.seal(None, false, MAX, &mut seeded(1), &mut out), Err(ChunkError::Number));
		assert_eq!(sender.seal(Some(&item()), true, MAX, &mut seeded(1), &mut out), Err(ChunkError::Number));
		assert_eq!((sender.sent(), out.len()), (KEY_PACKETS, size));
	}

	#[test]
	fn nothing_secret_is_printed() {
		assert_eq!((format!("{:?}", client()), format!("{:?}", node())), ("Client(..)".to_owned(), "Node { mask: MaskKey(..) }".to_owned()));
	}
}
