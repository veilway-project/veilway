//! Chunk framing and padding (transports page, "The chunk", "Padding" and "Datagram and stream transports").
//!
//! A chunk is one ChaCha20-Poly1305 message whose plaintext is a list of items, each a 2 byte length and one WireGuard datagram, followed by padding. `write` and `parse` are the plaintext alone. `Sealer` and `Opener` are one direction of a `tls` or `ws` session, with the counter nonce and empty associated data.
//!
//! Two transports do not use `Opener`. `udp-obfs` seals with random nonces (`udp_obfs`). `fronted` advances its chunk numbers only when a whole request is accepted and must leave the session exactly as it was when any chunk of a body fails, while `Opener` advances per chunk and ends for good on its first failure: `fronted::Opener` opens the chunks of a body at tentative numbers and commits them together. Both use `write`, `parse` and `nonce` as they are, and `fronted` seals with `Sealer`.
use crate::{keys::ChunkKey, uniform, NoRandom, Random};
use ring::aead::{Aad, Nonce};
use std::{fmt, ops::RangeInclusive};

/// "Chunk plaintext: at most 16,000 bytes."
pub const MAX_PLAINTEXT: usize = 16_000;
/// The smallest datagram inside a chunk: the smallest WireGuard message, a keepalive ("The chunk", reading rule 2).
pub const MIN_ITEM: usize = 32;
/// "Datagram inside a chunk: at most 1,600 bytes."
pub const MAX_ITEM: usize = 1_600;
/// The ChaCha20-Poly1305 tag.
pub const TAG: usize = 16;
/// The largest sealed chunk, 16,016 bytes: a longer WebSocket message ends the session ("WebSocket session").
pub const MAX_SEALED: usize = MAX_PLAINTEXT + TAG;
/// "Datagrams in one chunk: at most 470", which follows from the smallest item: 2 bytes of length and 32 of datagram.
pub const MAX_ITEMS: usize = MAX_PLAINTEXT / (2 + MIN_ITEM);
/// "A sender closes the session before it would send chunk number 2^60, and a receiver closes the session instead of accepting a chunk with that number." Numbers below this are used, this one never is.
pub const NUMBERS: u64 = 1 << 60;
/// Wide padding goes on the first 16 chunks of each direction ("Padding", rule 2).
pub const WIDE_CHUNKS: u64 = 16;
/// "Session padding base: uniform 0 to 63 bytes, drawn once per session and direction."
pub const BASE: RangeInclusive<u32> = 0..=63;
/// The bounds inside which a profile or a config may set the upper bound of wide padding.
pub const WIDE_BOUNDS: RangeInclusive<u32> = 512..=1023;
/// The upper bound of wide padding unless it is set.
pub const WIDE_DEFAULT: u32 = 1023;
/// The bounds inside which a profile or a config may set the upper bound of normal padding.
pub const NORMAL_BOUNDS: RangeInclusive<u32> = 64..=255;
/// The upper bound of normal padding unless it is set.
pub const NORMAL_DEFAULT: u32 = 255;

/// Why a chunk was not sealed or not opened. A receiver treats every one of these the same way: the stream session ends, a datagram is dropped ("The chunk", rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkError {
	/// An item is shorter than 32 bytes or longer than 1,600, or its length runs past the end of the plaintext.
	Item,
	/// The plaintext or the sealed chunk is outside the size limits.
	Size,
	/// The direction has used all of its chunk numbers.
	Number,
	/// The chunk does not open under this key at this number.
	Crypto,
	/// A padding bound is outside what the specification allows.
	Bounds,
	/// The random source failed.
	Random,
}

impl From<NoRandom> for ChunkError {
	fn from(_: NoRandom) -> Self {Self::Random}
}

impl fmt::Display for ChunkError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "chunk: {self:?}")}
}

impl std::error::Error for ChunkError {}

/// The counter nonce of stream transports: 4 zero bytes, then the chunk number of that direction in little-endian ("Datagram and stream transports").
pub fn nonce(number: u64) -> [u8; 12] {
	let mut nonce = [0; 12];
	nonce[4..].copy_from_slice(&number.to_le_bytes());
	nonce
}

/// Appends a chunk plaintext to `out`: every item with its length, then `padding` zero bytes. Nothing is written when an item or the total is outside the limits.
pub fn write(items: &[&[u8]], padding: usize, out: &mut Vec<u8>) -> Result<(), ChunkError> {
	let mut size = padding;
	for item in items {
		if !(MIN_ITEM..=MAX_ITEM).contains(&item.len()) {return Err(ChunkError::Item)}
		size = size.checked_add(2 + item.len()).ok_or(ChunkError::Size)?;
	}
	if size > MAX_PLAINTEXT {return Err(ChunkError::Size)}
	out.reserve(size + TAG);
	for item in items {
		out.extend_from_slice(&(item.len() as u16).to_be_bytes());
		out.extend_from_slice(item);
	}
	out.resize(out.len() + padding, 0);
	Ok(())
}

/// Reads a chunk plaintext by the reading rules of "The chunk": items until fewer than 2 bytes remain or a `length` of 0, which means "no more items". A `length` from 1 to 31 or above 1,600 makes the chunk invalid.
/// The whole plaintext is checked before the first item is given out, so an invalid chunk yields no item at all. Nothing is copied or allocated.
pub fn parse(plaintext: &[u8]) -> Result<Items<'_>, ChunkError> {
	if plaintext.len() > MAX_PLAINTEXT {return Err(ChunkError::Size)}
	let mut rest = plaintext;
	while let [high, low, tail @ ..] = rest {
		let length = usize::from(u16::from_be_bytes([*high, *low]));
		if length == 0 {break}
		if !(MIN_ITEM..=MAX_ITEM).contains(&length) {return Err(ChunkError::Item)}
		rest = tail.get(length..).ok_or(ChunkError::Item)?;
	}
	Ok(Items(plaintext))
}

/// The datagrams of one chunk, in order. A chunk with none is the padding-only chunk.
#[derive(Clone)]
pub struct Items<'a>(&'a [u8]);

// The datagrams are tunnel traffic, so a log line gets their number and nothing of them.
impl fmt::Debug for Items<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Items({})", self.clone().count())}
}

impl<'a> Iterator for Items<'a> {
	type Item = &'a [u8];
	fn next(&mut self) -> Option<&'a [u8]> {
		let [high, low, tail @ ..] = self.0 else {return None};
		let length = usize::from(u16::from_be_bytes([*high, *low]));
		if length == 0 || length > tail.len() {return None}
		let (item, rest) = tail.split_at(length);
		self.0 = rest;
		Some(item)
	}
}

/// Whether a chunk gets wide padding ("Padding", rule 2): it is one of the first 16 of its direction, or it holds a WireGuard handshake message, or it holds a control channel packet. The sender built those datagrams, so it is the sender that knows.
pub fn wide(number: u64, handshake: bool, control: bool) -> bool {number < WIDE_CHUNKS || handshake || control}

/// The padding ranges of one direction of one session, with the base that side drew for it.
#[derive(Debug, Clone)]
pub struct Padding {base: u32, wide_max: u32, normal_max: u32}

impl Padding {
	/// Draws the session's base. The two upper bounds come from the profile (client) or the config (node), or are `WIDE_DEFAULT` and `NORMAL_DEFAULT`.
	pub fn new(wide_max: u32, normal_max: u32, random: &mut Random) -> Result<Self, ChunkError> {
		if !WIDE_BOUNDS.contains(&wide_max) || !NORMAL_BOUNDS.contains(&normal_max) {return Err(ChunkError::Bounds)}
		Ok(Self {base: uniform(*BASE.start(), *BASE.end(), random)?, wide_max, normal_max})
	}
	/// The base this side drew: the least wide padding of this direction.
	pub fn base(&self) -> u32 {self.base}
	/// The padding of one chunk whose items take `used` bytes with their lengths: drawn from the range that applies, then lowered to what still fits `limit`, the largest plaintext of the transport ("Padding", rule 1).
	pub fn draw(&self, wide: bool, used: usize, limit: usize, random: &mut Random) -> Result<usize, NoRandom> {
		let drawn = if wide {uniform(self.base, self.wide_max, random)?} else {uniform(0, self.normal_max, random)?};
		Ok((drawn as usize).min(limit.saturating_sub(used)))
	}
}

/// The sending direction of a `tls` or `ws` session: the key, the chunk number and the padding. Every chunk gets the next number, so no nonce is used twice under the key.
#[derive(Debug)]
pub struct Sealer {key: ChunkKey, number: u64, padding: Padding}

impl Sealer {
	pub fn new(key: ChunkKey, padding: Padding) -> Self {Self {key, number: 0, padding}}
	/// The number the next chunk gets.
	pub fn number(&self) -> u64 {self.number}
	/// Appends one sealed chunk to `out`: the ciphertext of the items and their padding, then the tag. `wide` says that an item is a WireGuard handshake message or holds a control channel packet. The first 16 chunks are padded wide whatever it says.
	/// On an error nothing is appended and no number is used. `Item`, `Size` and `Random` leave the sealer as it was, since nothing reached the wire. `Number` is final: every later call gives it again, and the session must be closed.
	pub fn seal(&mut self, items: &[&[u8]], wide: bool, random: &mut Random, out: &mut Vec<u8>) -> Result<(), ChunkError> {
		if self.number >= NUMBERS {return Err(ChunkError::Number)}
		let used = items.iter().try_fold(0usize, |sum, item| sum.checked_add(2 + item.len())).ok_or(ChunkError::Size)?;
		let padding = self.padding.draw(self::wide(self.number, wide, false), used, MAX_PLAINTEXT, random)?;
		let start = out.len();
		write(items, padding, out)?;
		let sealed = self.key.0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(self.number)), Aad::empty(), &mut out[start..]);
		let Ok(tag) = sealed else {
			out.truncate(start);
			return Err(ChunkError::Crypto);
		};
		out.extend_from_slice(tag.as_ref());
		self.number += 1;
		Ok(())
	}
}

/// The receiving direction of a `tls` or `ws` session. A chunk opens only at the expected number, so a chunk that opens cannot be a replay ("Session activity and timers", "Activity").
#[derive(Debug)]
pub struct Opener {key: ChunkKey, number: u64, failed: Option<ChunkError>}

impl Opener {
	pub fn new(key: ChunkKey) -> Self {Self {key, number: 0, failed: None}}
	/// The number the next chunk must have.
	pub fn number(&self) -> u64 {self.number}
	/// Opens one sealed chunk in place and gives its datagrams. An error ends the session, the same way for every cause, and leaves bytes in `sealed` that mean nothing.
	/// The first error is final: every later call gives it again and opens nothing, so a caller that goes on cannot be offered a second forgery at the same number.
	pub fn open<'a>(&mut self, sealed: &'a mut [u8]) -> Result<Items<'a>, ChunkError> {
		let opened = match self.failed {
			Some(error) => Err(error),
			None if self.number >= NUMBERS => Err(ChunkError::Number),
			None if sealed.len() < TAG || sealed.len() > MAX_SEALED => Err(ChunkError::Size),
			None => match self.key.0.open_in_place(Nonce::assume_unique_for_key(nonce(self.number)), Aad::empty(), sealed) {
				Ok(plaintext) => parse(plaintext),
				Err(_) => Err(ChunkError::Crypto),
			},
		};
		match &opened {
			Ok(_) => self.number += 1,
			Err(error) => self.failed = Some(*error),
		}
		opened
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn key() -> ChunkKey {ChunkKey::new(&std::array::from_fn(|i| i as u8))}

	// The smallest datagram, a WireGuard keepalive in shape: 32 bytes that start with `fill`.
	fn item(fill: u8) -> [u8; 32] {[fill; 32]}

	// Gives out the listed four-byte draws in order, then fails.
	fn fixed(draws: &[u32]) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> + '_ {
		let mut draws = draws.iter();
		move |bytes: &mut [u8]| {
			bytes.copy_from_slice(&draws.next().ok_or(NoRandom)?.to_be_bytes());
			Ok(())
		}
	}

	// A sealer and an opener of one direction, with a padding base of 0 and `draws` for what follows.
	fn pair(draws: &[u32]) -> (Sealer, Opener, impl FnMut(&mut [u8]) -> Result<(), NoRandom> + '_) {
		let sealer = Sealer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut fixed(&[0])).unwrap());
		(sealer, Opener::new(key()), fixed(draws))
	}

	#[test]
	fn the_nonce_is_four_zero_bytes_and_a_little_endian_counter() {
		assert_eq!(nonce(0), [0; 12]);
		assert_eq!(nonce(0x0102030405060708), [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]);
	}

	#[test]
	fn the_plaintext_is_items_then_zero_padding() {
		let mut out = vec![0xee];
		write(&[&item(0xaa), &[0xbb; 33]], 4, &mut out).unwrap();
		assert_eq!(out, [&[0xee, 0, 32][..], &[0xaa; 32], &[0, 33], &[0xbb; 33], &[0; 4]].concat());
		assert_eq!(parse(&out[1..]).unwrap().collect::<Vec<_>>(), [&[0xaa; 32][..], &[0xbb; 33]]);
	}

	#[test]
	fn the_reading_rules() {
		let one = [&[0, 32][..], &item(7)].concat();
		assert_eq!(parse(&[]).unwrap().count(), 0);
		assert_eq!(parse(&[0]).unwrap().count(), 0);
		assert_eq!(parse(&[0; 300]).unwrap().count(), 0);
		assert_eq!(parse(&one).unwrap().collect::<Vec<_>>(), [&item(7)]);
		// Fewer than 2 bytes remain after the item, so the last byte is padding whatever it holds.
		assert_eq!(parse(&[&one[..], &[9]].concat()).unwrap().count(), 1);
		// A length of 0 means "no more items", and the receiver ignores what follows it.
		assert_eq!(parse(&[&one[..], &[0, 0, 0xff, 0xff, 0xff]].concat()).unwrap().count(), 1);
		assert_eq!(parse(&[&[0, 0][..], &one].concat()).unwrap().count(), 0);
		// A length that runs past the end, alone and after a good item.
		assert_eq!(parse(&one[..33]).unwrap_err(), ChunkError::Item);
		assert_eq!(parse(&[&one[..], &[0, 40], &[1; 39]].concat()).unwrap_err(), ChunkError::Item);
		// A length from 1 to 31 is no WireGuard message, even when the bytes are there.
		for short in [1, 3, 31] {assert_eq!(parse(&[&[0, short][..], &[1; 40]].concat()).unwrap_err(), ChunkError::Item, "a length of {short}")}
		assert_eq!(parse(&[&one[..], &[0, 31], &[1; 31]].concat()).unwrap_err(), ChunkError::Item);
		let mut long = vec![0x06, 0x41];
		long.resize(2 + 1601, 1);
		assert_eq!(parse(&long).unwrap_err(), ChunkError::Item);
		long[..2].copy_from_slice(&[0x06, 0x40]);
		assert_eq!(parse(&long[..1602]).unwrap().next().map(<[u8]>::len), Some(1600));
		assert_eq!(parse(&[0; MAX_PLAINTEXT + 1]).unwrap_err(), ChunkError::Size);
	}

	#[test]
	fn the_writer_refuses_what_a_reader_would_refuse() {
		let mut out = Vec::new();
		assert_eq!(write(&[&[]], 0, &mut out), Err(ChunkError::Item));
		assert_eq!(write(&[&item(1), &[0; 31]], 0, &mut out), Err(ChunkError::Item));
		assert_eq!(write(&[&[0; 1601]], 0, &mut out), Err(ChunkError::Item));
		assert_eq!(write(&[&[0; 1600][..]; 10], 0, &mut out), Err(ChunkError::Size));
		assert_eq!(write(&[&[1; 1600][..]; 9], MAX_PLAINTEXT - 9 * 1602 + 1, &mut out), Err(ChunkError::Size));
		assert_eq!(write(&[], usize::MAX, &mut out), Err(ChunkError::Size));
		assert!(out.is_empty());
		write(&[&[1; 1600][..]; 9], MAX_PLAINTEXT - 9 * 1602, &mut out).unwrap();
		assert_eq!((out.len(), parse(&out).unwrap().count()), (MAX_PLAINTEXT, 9));
		// 470 of the smallest item fill a chunk to 20 bytes below its limit, and one more does not fit.
		assert_eq!(MAX_ITEMS, 470);
		out.clear();
		write(&[&item(1)[..]; MAX_ITEMS], 0, &mut out).unwrap();
		assert_eq!((out.len(), parse(&out).unwrap().count()), (15_980, MAX_ITEMS));
		assert_eq!(write(&[&item(1)[..]; MAX_ITEMS + 1], 0, &mut out), Err(ChunkError::Size));
	}

	// Expected bytes come from tests/vectors.py: a ChaCha20-Poly1305 written out in plain Python from RFC 8439 and checked there against the RFC's own vector. Key 00..1f, no associated data, chunk numbers 0, 1 and 0x0102030405060708.
	#[test]
	fn a_sealed_chunk_byte_for_byte() {
		// The base is 5. The first chunk draws 10 above it, so 15 bytes of padding. The second draws 0, so the base alone. The third is past the first 16 and draws 7 of normal padding.
		let draws = [5, 10, 0, 7];
		let mut random = fixed(&draws);
		let mut sealer = Sealer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap());
		let first: [u8; 32] = std::array::from_fn(|i| if i < 4 {[4, 0, 0, 0][i]} else {i as u8 - 4});
		let second: [u8; 48] = std::array::from_fn(|i| 100 + i as u8);
		let (mut zero, mut one, mut high) = (Vec::new(), Vec::new(), Vec::new());
		sealer.seal(&[&first, &second], false, &mut random, &mut zero).unwrap();
		assert_eq!(hex(&zero), "18984631ade6a6d011625864a944462ef2bafff8efa24b4dfeebe8073c226d456813085db58b5a3af5e8324f08636e53ebd1842daa282fb9755330044de824b2c273af5f23cf1452e42e0064a503fcb4f0b2eda547eabeb7f3e09c30ce80e3e284a8023b2649b1b348a12a94250c0ebe1fa611");
		sealer.seal(&[], false, &mut random, &mut one).unwrap();
		assert_eq!(hex(&one), "9f57f35fb5fdddcc23f6cedafca16f86b3d2e98763");
		assert_eq!(sealer.number(), 2);
		sealer.number = 0x0102030405060708;
		sealer.seal(&[&first], false, &mut random, &mut high).unwrap();
		assert_eq!(hex(&high), "f069a9e4ab39ea1966a82ec9757f69b1ea0dfec9864b558f4526b348ff15bfc4436700bdd23209f910a56e57180aa3bddf0d047f4c9a5e453f");
		let mut opener = Opener::new(key());
		assert_eq!(opener.open(&mut zero).unwrap().collect::<Vec<_>>(), [&first[..], &second]);
		assert_eq!(opener.open(&mut one).unwrap().count(), 0);
		assert_eq!(opener.number(), 2);
		opener.number = 0x0102030405060708;
		assert_eq!(opener.open(&mut high).unwrap().collect::<Vec<_>>(), [&first]);
	}

	#[test]
	fn a_chunk_opens_only_at_its_own_number_and_under_its_own_key() {
		let (mut sealer, mut opener, mut random) = pair(&[0; 4]);
		let (mut first, mut second) = (Vec::new(), Vec::new());
		sealer.seal(&[&item(1)], false, &mut random, &mut first).unwrap();
		sealer.seal(&[&item(2)], false, &mut random, &mut second).unwrap();
		assert_eq!(Opener::new(key()).open(&mut second.clone()).unwrap_err(), ChunkError::Crypto);
		assert_eq!(Opener::new(ChunkKey::new(&[9; 32])).open(&mut first.clone()).unwrap_err(), ChunkError::Crypto);
		assert_eq!(Opener::new(key()).open(&mut [0; 15]).unwrap_err(), ChunkError::Size);
		assert_eq!(Opener::new(key()).open(&mut vec![0; MAX_SEALED + 1]).unwrap_err(), ChunkError::Size);
		assert_eq!(opener.open(&mut first.clone()).unwrap().collect::<Vec<_>>(), [&item(1)]);
		assert_eq!(opener.open(&mut second.clone()).unwrap().collect::<Vec<_>>(), [&item(2)]);
		// The same chunk again is a replay: the number has moved on.
		assert_eq!(opener.open(&mut second).unwrap_err(), ChunkError::Crypto);
	}

	// After 1,000 failed opens the next genuine chunk must not open: one failure ends the direction.
	#[test]
	fn an_opener_that_failed_once_opens_nothing_more() {
		for (bad, error) in [(vec![0; 40], ChunkError::Crypto), (vec![0; 15], ChunkError::Size), (vec![0; MAX_SEALED + 1], ChunkError::Size)] {
			let (mut sealer, mut opener, mut random) = pair(&[0; 4]);
			let (mut first, mut second) = (Vec::new(), Vec::new());
			sealer.seal(&[&item(1)], false, &mut random, &mut first).unwrap();
			sealer.seal(&[&item(2)], false, &mut random, &mut second).unwrap();
			assert_eq!(opener.open(&mut first).unwrap().count(), 1);
			for _ in 0..1000 {assert_eq!(opener.open(&mut bad.clone()).unwrap_err(), error)}
			assert_eq!(opener.open(&mut second).unwrap_err(), error);
			assert_eq!(opener.number(), 1);
		}
		// A chunk that opens and holds a bad item ends it the same way.
		let mut sealed = [&[0, 32][..], &item(7), &[0, 9, 1]].concat();
		let tag = key().0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(0)), Aad::empty(), &mut sealed).unwrap();
		sealed.extend_from_slice(tag.as_ref());
		let (mut sealer, mut opener, mut random) = pair(&[0; 4]);
		let mut good = Vec::new();
		sealer.seal(&[&item(1)], false, &mut random, &mut good).unwrap();
		assert_eq!(opener.open(&mut sealed).unwrap_err(), ChunkError::Item);
		assert_eq!(opener.open(&mut good).unwrap_err(), ChunkError::Item);
	}

	#[test]
	fn every_flipped_bit_of_a_sealed_chunk_is_refused() {
		let (mut sealer, _, mut random) = pair(&[0; 2]);
		let mut sealed = Vec::new();
		sealer.seal(&[&item(3)], false, &mut random, &mut sealed).unwrap();
		for bit in 0..sealed.len() * 8 {
			let mut changed = sealed.clone();
			changed[bit / 8] ^= 1 << (bit % 8);
			assert_eq!(Opener::new(key()).open(&mut changed).unwrap_err(), ChunkError::Crypto, "bit {bit}");
		}
		assert_eq!(Opener::new(key()).open(&mut sealed.clone()[..40]).unwrap_err(), ChunkError::Crypto);
		assert_eq!(Opener::new(key()).open(&mut sealed).unwrap().count(), 1);
	}

	#[test]
	fn the_numbers_of_a_direction_run_out_for_both_sides() {
		let (mut sealer, mut opener, mut random) = pair(&[0; 4]);
		sealer.number = NUMBERS - 1;
		opener.number = NUMBERS - 1;
		let mut out = Vec::new();
		sealer.seal(&[], false, &mut random, &mut out).unwrap();
		assert_eq!(opener.open(&mut out.clone()).unwrap().count(), 0);
		// A chunk sealed at 2^60 by a sender that broke the rule is not accepted.
		let mut beyond = Vec::new();
		let tag = key().0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(NUMBERS)), Aad::empty(), &mut beyond).unwrap();
		beyond.extend_from_slice(tag.as_ref());
		assert_eq!(opener.open(&mut beyond).unwrap_err(), ChunkError::Number);
		assert_eq!(sealer.seal(&[], false, &mut random, &mut out), Err(ChunkError::Number));
		assert_eq!(sealer.seal(&[], false, &mut random, &mut out), Err(ChunkError::Number));
		assert_eq!(out.len(), TAG);
	}

	// A sealer keeps working after an error that put nothing on the wire, and the number it did not use is the next one.
	#[test]
	fn a_refused_seal_uses_no_number() {
		let (mut sealer, mut opener, mut random) = pair(&[0; 2]);
		let mut out = Vec::new();
		assert_eq!(sealer.seal(&[&[1; 31]], false, &mut random, &mut out), Err(ChunkError::Item));
		assert_eq!(sealer.seal(&[&item(1)], false, &mut |_: &mut [u8]| Err(NoRandom), &mut out), Err(ChunkError::Random));
		assert_eq!((sealer.number(), out.len()), (0, 0));
		sealer.seal(&[&item(1)], false, &mut random, &mut out).unwrap();
		assert_eq!(opener.open(&mut out).unwrap().count(), 1);
	}

	#[test]
	fn padding_follows_the_rules() {
		assert_eq!(Padding::new(511, 255, &mut fixed(&[0])).unwrap_err(), ChunkError::Bounds);
		assert_eq!(Padding::new(1024, 255, &mut fixed(&[0])).unwrap_err(), ChunkError::Bounds);
		assert_eq!(Padding::new(1023, 63, &mut fixed(&[0])).unwrap_err(), ChunkError::Bounds);
		assert_eq!(Padding::new(1023, 256, &mut fixed(&[0])).unwrap_err(), ChunkError::Bounds);
		assert_eq!(Padding::new(1023, 255, &mut fixed(&[])).unwrap_err(), ChunkError::Random);
		let padding = Padding::new(512, 64, &mut fixed(&[63])).unwrap();
		assert_eq!(padding.base, 63);
		// 450 values from 63 to 512, 65 values from 0 to 64.
		assert_eq!(padding.draw(true, 0, MAX_PLAINTEXT, &mut fixed(&[449])), Ok(512));
		assert_eq!(padding.draw(true, 0, MAX_PLAINTEXT, &mut fixed(&[450])), Ok(63));
		assert_eq!(padding.draw(false, 0, MAX_PLAINTEXT, &mut fixed(&[64])), Ok(64));
		assert_eq!(padding.draw(false, 0, MAX_PLAINTEXT, &mut fixed(&[65])), Ok(0));
		// Lowered to what still fits: a full chunk carries none.
		assert_eq!(padding.draw(true, MAX_PLAINTEXT - 100, MAX_PLAINTEXT, &mut fixed(&[449])), Ok(100));
		assert_eq!(padding.draw(true, MAX_PLAINTEXT, MAX_PLAINTEXT, &mut fixed(&[449])), Ok(0));
		assert_eq!(padding.draw(true, 1500, 1402, &mut fixed(&[449])), Ok(0));
		assert!(wide(0, false, false) && wide(15, false, false) && !wide(16, false, false) && wide(16, true, false) && wide(16, false, true));
	}

	#[test]
	fn the_sixteenth_chunk_is_the_last_wide_one_by_position() {
		// Base 40. Every later draw is 0: wide padding is then the base, normal padding is nothing.
		let draws = [40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		let mut random = fixed(&draws);
		let mut sealer = Sealer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap());
		let mut sizes = Vec::new();
		for hinted in [false; 17].into_iter().chain([true, false]) {
			let mut out = Vec::new();
			sealer.seal(&[&item(1)], hinted, &mut random, &mut out).unwrap();
			sizes.push(out.len() - TAG - 34);
		}
		assert_eq!(sizes, [[40; 16].as_slice(), &[0, 40, 0]].concat());
	}

	#[test]
	fn the_datagrams_stay_out_of_debug_output() {
		let plaintext = [&[0, 32][..], &item(0xab), &[0, 32], &item(0xcd)].concat();
		assert_eq!(format!("{:?}", parse(&plaintext).unwrap()), "Items(2)");
	}
}
