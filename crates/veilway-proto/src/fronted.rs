//! The request target and the bodies of `fronted` (transports page, "`fronted`", "Layout" and "State machine").
//!
//! A body, in both directions, is a sequence of sealed chunks, each behind a 2 byte length. `Opener` opens a whole body or none of it: "Chunk numbers advance only when the request is accepted", and a body that fails leaves the session exactly as it was, so that anyone who learns a session id cannot disturb the session.
use crate::{chunk::{self, ChunkError, Items, Sealer, MAX_SEALED, NUMBERS, TAG, WIDE_BOUNDS}, keys::ChunkKey, Random};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::aead::{Aad, Nonce};
use std::time::Duration;

/// The smallest body: one padding-only chunk behind its length. "Exactly one `Content-Length`, from 18 to 65,536."
pub const BODY_MIN: usize = 2 + TAG;
/// "`fronted` body: at most 65,536 bytes in each direction."
pub const BODY_MAX: usize = 65_536;
/// "Body of a `fronted` request: 10 s to arrive."
pub const BODY_TIME: Duration = Duration::from_secs(10);
/// "`fronted` hold: 250 ms."
pub const HOLD: Duration = Duration::from_millis(250);
/// "`fronted` request number: at most 10 decimal digits, at most 4,294,967,295." A client opens a new session before its number would pass this.
pub const REQUEST_MAX: u32 = u32::MAX;
// The session id as text: 16 bytes in base64url without padding.
const SID_TEXT: usize = 22;

/// The query of a later request, `<sid>.<n>`: the session id and the request number, "1 for the first request after the opening one". `None` for a number that has none.
pub fn later_query(sid: &[u8; 16], number: u32) -> Option<String> {(number > 0).then(|| format!("{}.{number}", URL_SAFE_NO_PAD.encode(sid)))}

/// Reads the query of a request target as that of a later request: 22 characters of base64url that decode to 16 bytes, a dot, and a number of "at most 10 digits, no leading zero, at most 4,294,967,295". `None` for everything else. Whether the session id is one the node knows is the caller's lookup.
pub fn later(query: &[u8]) -> Option<([u8; 16], u32)> {
	let (text, [b'.', digits @ ..]) = query.split_at_checked(SID_TEXT)? else {return None};
	// 18 bytes is what the decoder asks for 22 characters. A session id has one text: a last character with bits that belong to no byte is refused.
	let mut sid = [0; 18];
	if URL_SAFE_NO_PAD.decode_slice(text, &mut sid) != Ok(16) || digits.is_empty() || digits.len() > 10 || digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {return None}
	let number = digits.iter().fold(0u64, |number, digit| number * 10 + u64::from(digit - b'0'));
	Some((std::array::from_fn(|index| sid[index]), u32::try_from(number).ok()?))
}

/// Appends one chunk to a body: its length, then the chunk as `sealer` seals it. `wide` is as for `Sealer::seal`.
/// A chunk that might not fit the body with the most padding it can draw is refused with `Size`, before a chunk number is used: the caller sends the body it has and puts the chunk in the next one. Every other error is the sealer's, and nothing is appended on any.
pub fn append(sealer: &mut Sealer, items: &[&[u8]], wide: bool, random: &mut Random, body: &mut Vec<u8>) -> Result<(), ChunkError> {
	let (start, used) = (body.len(), items.iter().try_fold(0usize, |sum, item| sum.checked_add(2 + item.len())).ok_or(ChunkError::Size)?);
	if start.saturating_add(2 + TAG + *WIDE_BOUNDS.end() as usize).saturating_add(used) > BODY_MAX {return Err(ChunkError::Size)}
	body.extend_from_slice(&[0; 2]);
	if let Err(error) = sealer.seal(items, wide, random, body) {
		body.truncate(start);
		return Err(error);
	}
	let length = (body.len() - start - 2) as u16;
	body[start..start + 2].copy_from_slice(&length.to_be_bytes());
	Ok(())
}

/// Why a body was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
	/// The body is not a sequence of chunks that all open at the expected numbers. Nothing changed: the session is exactly as it was, and the request takes the unauthenticated path.
	Refused,
	/// Every chunk opened and one of them is invalid, so it "can only have come from the session's client". The session is over, for this and every later call, and the request takes the unauthenticated path.
	Ended(ChunkError),
}

impl std::fmt::Display for BodyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "fronted body: {self:?}")}
}

impl std::error::Error for BodyError {}

/// The receiving direction of a `fronted` session: the node's for request bodies, the client's for response bodies.
#[derive(Debug)]
pub struct Opener {key: ChunkKey, number: u64, ended: Option<ChunkError>}

impl Opener {
	pub fn new(key: ChunkKey) -> Self {Self {key, number: 0, ended: None}}
	/// The number the first chunk of the next accepted body must have.
	pub fn number(&self) -> u64 {self.number}
	/// Opens every chunk of a body at the numbers that follow the last accepted body, without moving on: the numbers advance when the caller commits what this gives, and a caller that drops it has changed nothing.
	/// `body` is left as it came, since a request that is refused is forwarded to the decoy origin as it arrived, and a repeat is compared with it. `scratch` is where the chunks are opened, and the datagrams that are given out lie in it.
	///
	/// A body in which any chunk does not open is `Refused` whatever its other chunks hold, and only a body whose chunks all open can end the session by an invalid one ("State machine", steps 6 and 7).
	/// A body is authenticated chunk by chunk and not as a whole. The first chunks of a body are a body too, and so are two bodies one after the other, so a front can deliver a prefix of what the client sent. It can also drop the request, and either costs the session and nothing else. The length of a body is the request's `Content-Length`, which is the caller's to check.
	pub fn open<'s, 'a>(&'s mut self, body: &[u8], scratch: &'a mut Vec<u8>) -> Result<Opened<'s, 'a>, BodyError> {
		if let Some(error) = self.ended {return Err(BodyError::Ended(error))}
		if !(BODY_MIN..=BODY_MAX).contains(&body.len()) {return Err(BodyError::Refused)}
		scratch.clear();
		scratch.extend_from_slice(body);
		let (mut plaintexts, mut at, mut number) = (Vec::new(), 0, self.number);
		while at < scratch.len() {
			let [high, low] = *scratch.get(at..at + 2).ok_or(BodyError::Refused)? else {return Err(BodyError::Refused)};
			let end = at + 2 + usize::from(u16::from_be_bytes([high, low]));
			// A length "16 to 16,016" that stays inside the body, at a number below 2^60: "a receiver closes the session instead of accepting a chunk with that number", and here nothing is accepted.
			if !(TAG..=MAX_SEALED).contains(&(end - at - 2)) || number >= NUMBERS {return Err(BodyError::Refused)}
			let sealed = scratch.get_mut(at + 2..end).ok_or(BodyError::Refused)?;
			self.key.0.open_in_place(Nonce::assume_unique_for_key(chunk::nonce(number)), Aad::empty(), sealed).map_err(|_| BodyError::Refused)?;
			plaintexts.push(at + 2..end - TAG);
			(at, number) = (end, number + 1);
		}
		let (opened, mut chunks): (&'a [u8], _) = (scratch, Vec::with_capacity(plaintexts.len()));
		for plaintext in plaintexts {
			match chunk::parse(&opened[plaintext]) {
				Ok(items) => chunks.push(items),
				Err(error) => {
					self.ended = Some(error);
					return Err(BodyError::Ended(error));
				}
			}
		}
		Ok(Opened {opener: self, number, chunks})
	}
}

/// A body whose chunks all opened and are valid, not yet accepted.
#[derive(Debug)]
pub struct Opened<'s, 'a> {opener: &'s mut Opener, number: u64, chunks: Vec<Items<'a>>}

impl<'a> Opened<'_, 'a> {
	/// The chunks of the body, in order, each with its datagrams.
	pub fn chunks(&self) -> &[Items<'a>] {&self.chunks}
	/// The request is accepted: the chunk numbers advance past this body, and a repeat of it no longer opens.
	pub fn commit(self) -> Vec<Items<'a>> {
		self.opener.number = self.number;
		self.chunks
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{chunk::{Padding, NORMAL_DEFAULT, WIDE_DEFAULT}, NoRandom};

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn key() -> ChunkKey {ChunkKey::new(&std::array::from_fn(|i| i as u8))}

	fn item(fill: u8) -> [u8; 32] {[fill; 32]}

	// Gives out the listed four-byte draws in order, then fails.
	fn fixed(draws: &[u32]) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> + '_ {
		let mut draws = draws.iter();
		move |bytes: &mut [u8]| {
			bytes.copy_from_slice(&draws.next().ok_or(NoRandom)?.to_be_bytes());
			Ok(())
		}
	}

	// A sealer with a padding base of 0 whose every later draw is 0, so a chunk past the first 16 has no padding and one before has none either.
	fn sealer() -> Sealer {Sealer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut fixed(&[0])).unwrap())}

	// A body of one chunk for each list of items.
	fn body(sealer: &mut Sealer, chunks: &[&[&[u8]]]) -> Vec<u8> {
		let mut body = Vec::new();
		for items in chunks {append(sealer, items, false, &mut fixed(&[0]), &mut body).unwrap()}
		body
	}

	// A chunk the session's key seals at `number` around any plaintext, behind its length: what only the session's client can make.
	fn sealed(number: u64, plaintext: &[u8]) -> Vec<u8> {
		let mut chunk = plaintext.to_vec();
		let tag = key().0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(chunk::nonce(number)), Aad::empty(), &mut chunk).unwrap();
		[&((chunk.len() + TAG) as u16).to_be_bytes()[..], &chunk, tag.as_ref()].concat()
	}

	fn datagrams(chunks: &[Items<'_>]) -> Vec<Vec<Vec<u8>>> {chunks.iter().map(|items| items.clone().map(<[u8]>::to_vec).collect()).collect()}

	// Expected bytes come from tests/vectors.py: the two chunks of the chunk vectors, each behind its length. Key 00..1f, chunk numbers 0 and 1, a base of 5 and draws of 10 and 0.
	#[test]
	fn a_body_byte_for_byte() {
		let draws = [5, 10, 0];
		let mut random = fixed(&draws);
		let mut sealer = Sealer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap());
		let (first, second, mut body, mut scratch): ([u8; 32], [u8; 48], _, _) = (std::array::from_fn(|i| if i < 4 {[4, 0, 0, 0][i]} else {i as u8 - 4}), std::array::from_fn(|i| 100 + i as u8), vec![0xee], Vec::new());
		append(&mut sealer, &[&first, &second], false, &mut random, &mut body).unwrap();
		append(&mut sealer, &[], false, &mut random, &mut body).unwrap();
		assert_eq!(hex(&body[1..]), "007318984631ade6a6d011625864a944462ef2bafff8efa24b4dfeebe8073c226d456813085db58b5a3af5e8324f08636e53ebd1842daa282fb9755330044de824b2c273af5f23cf1452e42e0064a503fcb4f0b2eda547eabeb7f3e09c30ce80e3e284a8023b2649b1b348a12a94250c0ebe1fa61100159f57f35fb5fdddcc23f6cedafca16f86b3d2e98763");
		let mut opener = Opener::new(key());
		let opened = opener.open(&body[1..], &mut scratch).unwrap();
		assert_eq!(datagrams(opened.chunks()), [vec![first.to_vec(), second.to_vec()], vec![]]);
		assert_eq!(datagrams(&opened.commit()), [vec![first.to_vec(), second.to_vec()], vec![]]);
		assert_eq!(opener.number(), 2);
	}

	#[test]
	fn the_query_of_a_later_request() {
		let sid: [u8; 16] = std::array::from_fn(|i| i as u8);
		assert_eq!(later_query(&sid, 7).as_deref(), Some("AAECAwQFBgcICQoLDA0ODw.7"));
		assert_eq!((later_query(&sid, 0), later_query(&sid, REQUEST_MAX).as_deref()), (None, Some("AAECAwQFBgcICQoLDA0ODw.4294967295")));
		assert_eq!(later(b"AAECAwQFBgcICQoLDA0ODw.7"), Some((sid, 7)));
		assert_eq!(later(b"AAECAwQFBgcICQoLDA0ODw.4294967295"), Some((sid, REQUEST_MAX)));
		assert_eq!(later(b"_-ECAwQFBgcICQoLDA0ODw.10").map(|(sid, number)| (sid[0], number)), Some((0xff, 10)));
		// "At most 10 digits, no leading zero, at most 4,294,967,295", and a session id of exactly 16 bytes in its one text.
		for query in [&b""[..], b"AAECAwQFBgcICQoLDA0ODw", b"AAECAwQFBgcICQoLDA0ODw.", b"AAECAwQFBgcICQoLDA0ODw.0", b"AAECAwQFBgcICQoLDA0ODw.07", b"AAECAwQFBgcICQoLDA0ODw.4294967296", b"AAECAwQFBgcICQoLDA0ODw.12345678901", b"AAECAwQFBgcICQoLDA0ODw.+7", b"AAECAwQFBgcICQoLDA0ODw.7 ", b"AAECAwQFBgcICQoLDA0ODw.7.1", b"AAECAwQFBgcICQoLDA0ODw-7", b"AAECAwQFBgcICQoLDA0OD.7", b"AAECAwQFBgcICQoLDA0ODwA.7", b"AAECAwQFBgcICQoLDA0ODx.7", b"AAECAwQFBgcICQoLDA0OD=.7", b"AAECAwQFBgcICQoLDA0OD+.7", b"AAECAwQFBgcICQoLDA0ODw==.7"] {assert_eq!(later(query), None, "{:?}", String::from_utf8_lossy(query))}
	}

	// "Chunk numbers advance only when the request is accepted", and "a live session it named is left exactly as it was".
	#[test]
	fn a_body_is_opened_whole_or_not_at_all() {
		let (mut sealer, mut opener, mut scratch) = (sealer(), Opener::new(key()), Vec::new());
		let (first, second) = (body(&mut sealer, &[&[&item(1)], &[&item(2), &item(3)]]), body(&mut sealer, &[&[], &[&item(4)]]));
		// Opened and not committed, any number of times: nothing moved.
		for _ in 0..3 {assert_eq!(datagrams(opener.open(&first, &mut scratch).unwrap().chunks()), [vec![item(1).to_vec()], vec![item(2).to_vec(), item(3).to_vec()]])}
		assert_eq!(opener.number(), 0);
		// The body of the request after next does not open, and changes nothing.
		assert_eq!(opener.open(&second, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused));
		assert_eq!(opener.open(&first, &mut scratch).unwrap().commit().len(), 2);
		assert_eq!(opener.number(), 2);
		// A repeat of an accepted body no longer opens: the caller answers it from the stored response, by comparing the bytes.
		assert_eq!(opener.open(&first, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused));
		assert_eq!(datagrams(&opener.open(&second, &mut scratch).unwrap().commit()), [vec![], vec![item(4).to_vec()]]);
		assert_eq!(opener.number(), 4);
	}

	// A stranger who learns a session id sends whatever it likes: every one of these leaves the session as it was, after which the real body still opens.
	#[test]
	fn nothing_a_stranger_sends_disturbs_a_session() {
		let (mut sealer, mut opener, mut scratch) = (sealer(), Opener::new(key()), Vec::new());
		let good = body(&mut sealer, &[&[&item(1)], &[&item(2)]]);
		let mut strangers = vec![Vec::new(), vec![0; BODY_MIN - 1], vec![0; BODY_MIN], vec![0xff; 600], vec![0; BODY_MAX], vec![0; BODY_MAX + 1], [&good[..], &[0]].concat(), [&good[..], &[0, 16]].concat(), [&good[..], &[0, 15], &[0; 15]].concat(), [&good[..], &[0, 16], &[0; 16]].concat(), good[..good.len() - 1].to_vec(), good[..51].to_vec(), [&[0x3e, 0x91][..], &[0; 16_017]].concat(), [&good[52..], &good[..52]].concat()];
		for bit in 0..good.len() * 8 {
			let mut changed = good.clone();
			changed[bit / 8] ^= 1 << (bit % 8);
			strangers.push(changed);
		}
		// A chunk the client sealed for another place in the stream, and a good chunk followed by one that does not open even though it holds a bad item.
		strangers.push([&good[..], &sealed(3, &[0; 4])].concat());
		strangers.push([&sealed(0, &[0, 9, 1])[..], &[0, 16], &[0; 16]].concat());
		for body in &strangers {
			assert_eq!(opener.open(body, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused), "a body of {} bytes", body.len());
			assert_eq!(opener.number(), 0);
		}
		assert_eq!(opener.open(&good, &mut scratch).unwrap().commit().len(), 2);
	}

	// "A chunk that opens and is invalid (a bad item length) came from the session's client. The session is ended."
	#[test]
	fn an_invalid_chunk_from_the_client_ends_the_session() {
		for (bad, error) in [(vec![0, 9, 1], ChunkError::Item), (vec![0, 31, 7, 7], ChunkError::Item), ([&[0x06, 0x41][..], &[7; 1601]].concat(), ChunkError::Item)] {
			let (mut sealer, mut opener, mut scratch) = (sealer(), Opener::new(key()), Vec::new());
			let good = body(&mut sealer, &[&[&item(1)]]);
			assert_eq!(opener.open(&[&sealed(0, &[0; 3])[..], &sealed(1, &bad)].concat(), &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Ended(error)));
			// Over for good: the body that would have opened is answered the same way.
			assert_eq!(opener.open(&good, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Ended(error)));
			assert_eq!(opener.open(&[], &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Ended(error)));
			assert_eq!(opener.number(), 0);
		}
	}

	#[test]
	fn a_body_stays_inside_65536_bytes() {
		let (mut sealer, mut body, mut opener, mut scratch) = (sealer(), Vec::new(), Opener::new(key()), Vec::new());
		let full = [&[7; 1600][..]; 9];
		// Four chunks of the largest kind fit. A fifth might not, with the padding it may draw, and is refused before a number is used.
		for _ in 0..4 {append(&mut sealer, &full, false, &mut fixed(&[0]), &mut body).unwrap()}
		let size = body.len();
		assert_eq!(append(&mut sealer, &full, false, &mut fixed(&[0]), &mut body), Err(ChunkError::Size));
		assert_eq!((sealer.number(), body.len()), (4, size));
		// The sealer's own refusals leave the body as it was too.
		assert_eq!(append(&mut sealer, &[&[7; 31]], false, &mut fixed(&[0]), &mut body), Err(ChunkError::Item));
		assert_eq!(append(&mut sealer, &[&item(1)], false, &mut fixed(&[]), &mut body), Err(ChunkError::Random));
		assert_eq!((sealer.number(), body.len()), (4, size));
		while append(&mut sealer, &[&item(1)], false, &mut fixed(&[0]), &mut body).is_ok() {}
		assert!(body.len() <= BODY_MAX && body.len() > BODY_MAX - 1100);
		assert_eq!(opener.open(&body, &mut scratch).unwrap().commit().len() as u64, sealer.number());
		// A chunk at number 2^60 is never accepted.
		let (mut last, mut scratch) = (Opener::new(key()), Vec::new());
		last.number = NUMBERS - 1;
		assert_eq!(last.open(&[&sealed(NUMBERS - 1, &[])[..], &sealed(NUMBERS, &[])].concat(), &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused));
		assert_eq!(last.open(&sealed(NUMBERS - 1, &[]), &mut scratch).unwrap().commit().len(), 1);
		assert_eq!(last.open(&sealed(NUMBERS, &[]), &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused));
	}
}
