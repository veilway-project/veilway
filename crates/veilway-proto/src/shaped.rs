//! The requests and answers of `fronted-shaped` (shapes page, "Numbering", "Upstream" and "The node's state machine"): chunk numbers `n` times 4,096 plus an index, the late answer, and the one canonical encoding of a request's data in a body, a query, a path or a header field.
//!
//! The chunks are those of `chunk` and `fronted`, and so is the framing of a list of them. What this page changes is where a chunk gets its number and where the list goes. Nothing here keeps state between requests: a session's window of request numbers, its stored answers and its counters are the caller's.
//!
//! A request has one encoding. The node reads a target strictly (`Target::read`) and decodes the data only when `Target::data` is asked for it, and a spelling that has a twin is not read at all, so that a copy of a request cannot look new and a new request cannot look like a copy.
use crate::{chunk::{self, ChunkError, Items, Padding, MAX_PLAINTEXT, MAX_SEALED, NUMBERS, TAG}, fronted::{self, BodyError, BODY_MAX, BODY_MIN}, keys::ChunkKey, request::Line, shape::{In, Shape}, uniform, NoRandom, Random};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::aead::{Aad, Nonce};
use std::ops::RangeInclusive;
use subtle::ConstantTimeEq;

/// "In a shaped session the number of a chunk is `n` times 4,096 plus `i`."
pub const PER_REQUEST: u64 = 4_096;
/// "At most 4,095 data chunks, numbered 0 to 4,094."
pub const CHUNKS: usize = 4_095;
/// "Index 4,095 is reserved for the late answer and is used for nothing else."
pub const LATE_INDEX: u64 = 4_095;
/// "Largest chunk number: 4,294,967,295 times 4,096 plus 4,095, which is 2^44 - 1."
pub const NUMBER_MAX: u64 = (u32::MAX as u64) * PER_REQUEST + LATE_INDEX;
/// "No stream": the one item of a chunk, 32 bytes, that tells the node a client has left its stream and the node is to drop it. Its first byte is no WireGuard message type, so the item is never a datagram, and a chunk that holds it is authenticated like any other.
pub const NO_STREAM: [u8; 32] = {
	let mut item = [0; 32];
	item[0] = 0xfe;
	item
};
/// "Late answer: one chunk of 80 bytes: a plaintext of 64 zero bytes, sealed at index 4,095."
pub const LATE_PLAINTEXT: usize = 64;
pub const LATE_SIZE: usize = LATE_PLAINTEXT + TAG;
/// "Request number window: 64 below the highest accepted number and 64 above, so 129 numbers are tracked."
pub const WINDOW: u32 = 64;
pub const TRACKED: usize = 2 * WINDOW as usize + 1;
/// "Requests in flight: 1 to 4 and one stream, per session."
pub const IN_FLIGHT: usize = 4;
/// "Data of a request, decoded: at most 65,536 bytes."
pub const DATA_MAX: usize = BODY_MAX;
/// "Segment of a path: the client draws each uniformly from 8 to 64 characters, the last 1 to 64. The node accepts 1 to 64 characters for every segment."
pub const SEGMENT: RangeInclusive<u32> = 8..=64;
pub const SEGMENT_MAX: usize = 64;
// Characters of base64 that stand for one group of 3 bytes.
const BASE64_GROUP: usize = 4;

/// The number of the chunk `index` of request `n`, for a chunk of data: `None` from index 4,095, which is the late answer's alone (`late_number`), so no caller seals at that nonce by a slip.
pub fn number(n: u32, index: u64) -> Option<u64> {(index < LATE_INDEX).then(|| u64::from(n) * PER_REQUEST + index)}

/// The number of the late answer of request `n`: index 4,095.
pub fn late_number(n: u32) -> u64 {u64::from(n) * PER_REQUEST + LATE_INDEX}

/// How many bytes `encoded` characters of unpadded base64url decode to, or `None` for a length no base64 text has. Computed from the length alone, so a caller checks it before it allocates.
pub fn decoded_len(encoded: usize) -> Option<usize> {(encoded % BASE64_GROUP != 1).then(|| encoded / BASE64_GROUP * 3 + [0, 0, 1, 2][encoded % BASE64_GROUP])}

fn sextet(byte: u8) -> Option<u8> {
	match byte {
		b'A'..=b'Z' => Some(byte - b'A'),
		b'a'..=b'z' => Some(byte - b'a' + 26),
		b'0'..=b'9' => Some(byte - b'0' + 52),
		b'-' => Some(62),
		b'_' => Some(63),
		_ => None,
	}
}

// Whether `length` characters that end in `last` are the one canonical text of some bytes: a length base64 has, and "the unused bits of the last character are zero".
fn canonical(length: usize, last: Option<u8>) -> bool {
	match (length % BASE64_GROUP, last) {
		(0, _) => true,
		(2, Some(last)) => sextet(last).is_some_and(|value| value & 0x0f == 0),
		(3, Some(last)) => sextet(last).is_some_and(|value| value & 0x03 == 0),
		_ => false,
	}
}

/// The list of framed chunks as base64url without padding, "in its one canonical form".
pub fn encode(data: &[u8]) -> String {URL_SAFE_NO_PAD.encode(data)}

/// The bytes of a canonical base64url text without padding, or `None` for what is not one: a character outside the alphabet (a padding character, `+` and `/` included), a length no base64 has, last bits that are set, or more than 65,536 bytes. The decoded length is checked from the encoded length before anything is allocated.
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
	if decoded_len(text.len()).is_none_or(|size| size > DATA_MAX) || !text.iter().all(|byte| sextet(*byte).is_some()) || !canonical(text.len(), text.last().copied()) {return None}
	URL_SAFE_NO_PAD.decode(text).ok()
}

/// "In `path` the data is cut at random into segments of 8 to 64 characters, joined by `/`." The last segment is what is left, 1 to 64 characters, so a text of 64 characters or fewer is one segment.
pub fn segments(text: &str, random: &mut Random) -> Result<String, NoRandom> {
	let (mut out, mut rest) = (String::with_capacity(text.len() + text.len() / *SEGMENT.start() as usize + 1), text);
	while rest.len() > SEGMENT_MAX {
		let (head, tail) = rest.split_at(uniform(*SEGMENT.start(), *SEGMENT.end(), random)? as usize);
		out.push_str(head);
		out.push('/');
		rest = tail;
	}
	out.push_str(rest);
	Ok(out)
}

/// The most bytes of data one request of this shape carries, for a `path` of the transport and a `who` of this many characters (the token of an opening request, or `<sid>.<n>`): what is left of the limit after the rest of the target, as base64 and, for `path`, with a slash after every 8 characters at the worst. Not above 65,536.
pub fn capacity(shape: &Shape, path: usize, who: usize) -> usize {
	let target = shape.up.limit.saturating_sub(path + 1 + who + 1);
	let characters = match shape.up.place {
		In::Body => return shape.up.limit.min(DATA_MAX),
		In::Query => target,
		In::Path => target * 8 / 9,
		In::Header => shape.up.limit,
	};
	(characters / BASE64_GROUP * 3 + [0, 0, 1, 2][characters % BASE64_GROUP]).min(DATA_MAX)
}

/// A request as the client writes it, before its other header fields: the request target, the value of the header field `up.name` (for `header`), and the body (for `body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts {
	pub target: String,
	pub header: Option<String>,
	pub body: Vec<u8>,
}

impl Parts {
	/// The request of `data` (a list of framed chunks) in this shape. `path` is the transport's, and `who` is the token or `<sid>.<n>`. The caller has held `data` to `capacity`, and a request that is over its limit all the same is `None`. A `path` shape cuts the text into segments at random (`segments`), and draws from `random` for nothing else.
	pub fn build(shape: &Shape, path: &str, who: &str, data: &[u8], random: &mut Random) -> Result<Option<Parts>, NoRandom> {
		let text = encode(data);
		let parts = match shape.up.place {
			In::Body => Parts {target: format!("{path}?{who}"), header: None, body: data.to_vec()},
			In::Query => Parts {target: format!("{path}?{who}.{text}"), header: None, body: Vec::new()},
			In::Path => Parts {target: format!("{path}/{who}/{}", segments(&text, random)?), header: None, body: Vec::new()},
			In::Header => Parts {target: format!("{path}?{who}"), header: Some(text), body: Vec::new()},
		};
		let over = match shape.up.place {
			In::Body => parts.body.len() > shape.up.limit || parts.body.len() < BODY_MIN,
			In::Header => parts.header.as_ref().is_some_and(|value| value.len() > shape.up.limit),
			In::Query | In::Path => parts.target.len() > shape.up.limit,
		};
		Ok((!over && data.len() <= DATA_MAX).then_some(parts))
	}
}

/// Who a request says it is from: the opening request with the text of its proof, or a later one with the session id and the request number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who<'a> {
	Opening(&'a [u8]),
	Later([u8; 16], u32),
}

/// Where the data of a request that is read from its target lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Data<'a> {
	Body,
	/// Base64url text as it stands.
	Text(&'a [u8]),
	/// Segments with slashes between them.
	Segments(&'a [u8]),
}

/// A request target (or target and header value) that is in the one form its shape allows. Whether the `sid` is one the node knows, and whether a token is a proof, are the caller's lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
	pub who: Who<'a>,
	data: Data<'a>,
}

// `<sid>.<n>` or `<token>` at the front of `text`, and what follows its end. `more` says whether data may follow behind a dot.
fn who(text: &[u8], more: bool) -> Option<(Who<'_>, Option<&[u8]>)> {
	let first = text.iter().position(|byte| *byte == b'.').unwrap_or(text.len());
	if first == 22 && text.len() > first {
		let digits = text[first + 1..].iter().position(|byte| *byte == b'.').unwrap_or(text.len() - first - 1);
		let (sid, number) = fronted::later(&text[..first + 1 + digits])?;
		let rest = &text[first + 1 + digits..];
		return match (rest, more) {
			([], _) => Some((Who::Later(sid, number), None)),
			([b'.', data @ ..], true) if !data.is_empty() => Some((Who::Later(sid, number), Some(data))),
			_ => None,
		};
	}
	// A token is base64url in its one form: no `%`, `&`, `=` or `+` stands in a target that is read.
	if first == 0 || !text[..first].iter().all(|byte| sextet(*byte).is_some()) {return None}
	match (text.get(first), more) {
		(None, _) => Some((Who::Opening(text), None)),
		(Some(_), true) if first + 1 < text.len() => Some((Who::Opening(&text[..first]), Some(&text[first + 1..]))),
		_ => None,
	}
}

// Whether `text` is data: characters of the base64url alphabet, in a length and with a last character that make one canonical text, of 18 to 65,536 bytes.
fn data_ok(characters: usize, last: Option<u8>) -> bool {canonical(characters, last) && decoded_len(characters).is_some_and(|size| (BODY_MIN..=DATA_MAX).contains(&size))}

impl<'a> Target<'a> {
	/// Reads the target of a request line of a transport with this shape and `path`, and the value of its header field when the shape has one (`http::field_once` of the head). `None` when the request is not one of the shape in its one form:
	/// - The path is the transport's, whole (`body`, `query`, `header`) or as a prefix with a slash behind it (`path`). It is compared in constant time.
	/// - The query is exactly the form of the page: `<sid>.<n>` or `<token>` for `body` and `header`, with `.<data>` behind it for `query`, and none for `path`. No other parameter, and no `&`, `=`, `+` or `%`, since the characters of every part are held to the alphabet.
	/// - `<n>` is as `fronted::later` reads it. In `path` the first segment after the transport's path is `<sid>.<n>` or `<token>` and holds no data, and every segment after it has 1 to 64 characters of the alphabet.
	/// - The whole target is at most `up.limit` bytes for `query` and `path`, the value of the header field has no blank at either end, and the data is 18 to 65,536 bytes in its one canonical form.
	/// Nothing is decoded and nothing is allocated here.
	pub fn read(shape: &Shape, path: &[u8], line: &Line<'a>, header: Option<&'a [u8]>) -> Option<Target<'a>> {
		let up = &shape.up;
		if line.verb != up.method.as_bytes() {return None}
		match up.place {
			In::Body | In::Header => {
				let same = line.path.len() == path.len() && bool::from(line.path.ct_eq(path));
				let (who, _) = who(line.query?, false)?;
				if !same {return None}
				match (up.place, header) {
					(In::Body, None) => Some(Target {who, data: Data::Body}),
					(In::Header, Some(value)) if !value.is_empty() && value.len() <= up.limit && data_ok(value.len(), value.last().copied()) && value.iter().all(|byte| sextet(*byte).is_some()) => Some(Target {who, data: Data::Text(value)}),
					_ => None,
				}
			}
			In::Query => {
				let same = line.path.len() == path.len() && bool::from(line.path.ct_eq(path));
				let (who, data) = who(line.query?, true)?;
				let data = data?;
				(same && header.is_none() && line.path.len() + 1 + line.query?.len() <= up.limit && data.iter().all(|byte| sextet(*byte).is_some()) && data_ok(data.len(), data.last().copied())).then_some(Target {who, data: Data::Text(data)})
			}
			In::Path => {
				let rest = line.path.get(path.len() + 1..).filter(|_| line.query.is_none() && header.is_none() && line.path.len() > path.len() && bool::from(line.path[..path.len()].ct_eq(path)) && line.path[path.len()] == b'/')?;
				let first = rest.iter().position(|byte| *byte == b'/')?;
				let (who, _) = who(&rest[..first], false)?;
				let segments = &rest[first + 1..];
				let (mut characters, mut last) = (0, None);
				for segment in segments.split(|byte| *byte == b'/') {
					if segment.is_empty() || segment.len() > SEGMENT_MAX || !segment.iter().all(|byte| sextet(*byte).is_some()) {return None}
					(characters, last) = (characters + segment.len(), segment.last().copied());
				}
				(line.path.len() <= up.limit && data_ok(characters, last)).then_some(Target {who, data: Data::Segments(segments)})
			}
		}
	}

	/// Whether the data is in the body of the request and not in the target.
	pub fn bodied(&self) -> bool {self.data == Data::Body}

	/// The data of a request whose data is in its target or header: the bytes the text decodes to, which the repeat test of the page runs on. `None` for a `body` shape, whose data is the body.
	pub fn data(&self) -> Option<Vec<u8>> {
		match self.data {
			Data::Body => None,
			Data::Text(text) => decode(text),
			Data::Segments(segments) => decode(&segments.iter().copied().filter(|byte| *byte != b'/').collect::<Vec<u8>>()),
		}
	}
}

/// Opens the chunks of a request or a polled answer: every chunk of `data` at the numbers `n` times 4,096, then one more for each. The rule of `fronted::Opener::open`, for any request number: a refusal changes nothing, and `Ended` is a chunk that opened and is invalid. At most 4,095 chunks, so index 4,095 is never opened here.
pub fn open<'a>(key: &ChunkKey, n: u32, data: &[u8], scratch: &'a mut Vec<u8>) -> Result<Vec<Items<'a>>, BodyError> {fronted::open_body(key, u64::from(n) * PER_REQUEST, data, scratch, CHUNKS)}

/// Opens one sealed chunk in place at `number`, as an event of a stream is opened. The number of an event is the stream request's `n` times 4,096 plus the event's place in its stream, which the reader counts and the wire does not say.
pub fn open_one<'a>(key: &ChunkKey, number: u64, sealed: &'a mut [u8]) -> Result<Items<'a>, ChunkError> {
	if number >= NUMBERS || !(TAG..=MAX_SEALED).contains(&sealed.len()) {return Err(ChunkError::Size)}
	key.0.open_in_place(Nonce::assume_unique_for_key(chunk::nonce(number)), Aad::empty(), sealed).map_err(|_| ChunkError::Crypto).and_then(|plaintext| chunk::parse(plaintext))
}

/// Whether `body` is the late answer of request `n`: 80 bytes that open at index 4,095 of `n` to 64 zero bytes. Any other chunk at that index is refused.
pub fn is_late(key: &ChunkKey, n: u32, body: &[u8]) -> bool {
	let mut sealed = [0; LATE_SIZE];
	body.len() == LATE_SIZE && {
		sealed.copy_from_slice(body);
		key.0.open_in_place(Nonce::assume_unique_for_key(chunk::nonce(late_number(n))), Aad::empty(), &mut sealed).is_ok_and(|plaintext| plaintext.len() == LATE_PLAINTEXT && plaintext.iter().all(|byte| *byte == 0))
	}
}

/// The sending direction of a shaped session: the key, the padding and how many chunks it has sealed, which is what decides whether a chunk is padded wide ("wide padding on the first 16 chunks of each direction"). A sender seals a chunk once, at its number, and keeps the bytes for every repeat.
#[derive(Debug)]
pub struct Writer {key: ChunkKey, padding: Padding, sealed: u64}

impl Writer {
	pub fn new(key: ChunkKey, padding: Padding) -> Self {Self {key, padding, sealed: 0}}

	/// How many chunks of data this direction has sealed.
	pub fn sealed(&self) -> u64 {self.sealed}

	/// Appends one chunk to a body: its length, then the chunk sealed at index `index` of request `n`. `wide` says it holds a handshake message or a control packet. `limit` is how long the body may be in all: the padding is drawn within what is left of it, so a chunk whose items fit always fits.
	/// `Size` for items that do not fit the body or an index of 4,095 or more, `Item` and `Random` from the chunk. Nothing is appended and nothing is counted on an error.
	pub fn append(&mut self, n: u32, index: usize, items: &[&[u8]], wide: bool, limit: usize, random: &mut Random, body: &mut Vec<u8>) -> Result<(), ChunkError> {
		let used = items.iter().try_fold(0usize, |sum, item| sum.checked_add(2 + item.len())).ok_or(ChunkError::Size)?;
		let room = limit.saturating_sub(body.len() + 2 + TAG).min(MAX_PLAINTEXT);
		if index >= CHUNKS || used > room {return Err(ChunkError::Size)}
		let (start, padding) = (body.len(), self.padding.draw(chunk::wide(self.sealed, wide, false), used, room, random)?);
		body.extend_from_slice(&[0; 2]);
		if let Err(error) = chunk::write(items, padding, body) {
			body.truncate(start);
			return Err(error);
		}
		let Ok(tag) = self.key.0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(chunk::nonce(number(n, index as u64).ok_or(ChunkError::Size)?)), Aad::empty(), &mut body[start + 2..]) else {
			body.truncate(start);
			return Err(ChunkError::Crypto);
		};
		body.extend_from_slice(tag.as_ref());
		let length = (body.len() - start - 2) as u16;
		body[start..start + 2].copy_from_slice(&length.to_be_bytes());
		self.sealed += 1;
		Ok(())
	}

	/// Appends one chunk without a frame, as an event of a stream holds it: the chunk sealed at index `index` of request `n`, in `out`. The rest is as for `append`, and the chunk is the sealed bytes alone.
	pub fn seal(&mut self, n: u32, index: usize, items: &[&[u8]], wide: bool, random: &mut Random, out: &mut Vec<u8>) -> Result<(), ChunkError> {
		let start = out.len();
		self.append(n, index, items, wide, 2 + MAX_SEALED, random, out)?;
		out.drain(start..start + 2);
		Ok(())
	}

	/// The late answer of request `n`, byte for byte: 64 zero bytes sealed at index 4,095 of `n`. Sealing it again gives the same 80 bytes, so any number of them for one `n` are the same bytes, and it is not counted among the chunks.
	pub fn late(&self, n: u32) -> [u8; LATE_SIZE] {
		let mut sealed = [0; LATE_SIZE];
		let tag = self.key.0.seal_in_place_separate_tag(Nonce::assume_unique_for_key(chunk::nonce(late_number(n))), Aad::empty(), &mut sealed[..LATE_PLAINTEXT]).expect("64 bytes seal under a 32 byte key");
		sealed[LATE_PLAINTEXT..].copy_from_slice(tag.as_ref());
		sealed
	}
}

/// How many frames and chunks of a list there are in all, or `None` when the list is not framed: the check of step 5 that runs before any chunk is opened ("a request with more than 4,095 chunks, a frame length outside 16 to 16,016, or a frame that runs past the data is refused here").
pub fn framed(data: &[u8]) -> Option<usize> {
	let (mut at, mut count) = (0, 0);
	while at < data.len() {
		let length = usize::from(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]));
		at += 2 + length;
		count += 1;
		if !(TAG..=MAX_SEALED).contains(&length) || at > data.len() || count > CHUNKS {return None}
	}
	(count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{chunk::{NORMAL_DEFAULT, WIDE_DEFAULT}, request::Method, shape::Given};

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

	// Draws that are always 0, so every padding is the least it can be and every cut the shortest.
	fn zero(bytes: &mut [u8]) -> Result<(), NoRandom> {
		bytes.fill(0);
		Ok(())
	}

	// A source of draws that are all over their range.
	fn spread() -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> {
		let mut state = 0x9e3779b97f4a7c15u64;
		move |bytes: &mut [u8]| {
			for byte in bytes {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = state as u8;
			}
			Ok(())
		}
	}

	fn writer() -> Writer {Writer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut fixed(&[0])).unwrap())}

	fn given<'a>(method: &'a str, place: &'a str, name: Option<&'a str>) -> Given<'a> {Given {method, place, name, limit: None, inflight: None, gather: None, mode: "poll", down_gather: None, life: None, fallback: None}}

	fn shape(method: &str, place: &str, name: Option<&str>) -> Shape {Shape::resolve(&given(method, place, name)).unwrap()}

	const SID: &str = "AAECAwQFBgcICQoLDA0ODw";

	const PATH: &str = "/assets/sync-90be44f1.js";

	// The framed chunks of one request, as the client builds them.
	fn data(count: usize) -> Vec<u8> {
		let (mut writer, mut body) = (writer(), Vec::new());
		for index in 0..count {writer.append(3, index, &[&item(index as u8)], false, BODY_MAX, &mut zero, &mut body).unwrap()}
		body
	}

	// The line of a request with this target.
	fn line(method: &str, target: &str) -> Vec<u8> {format!("{method} {target} HTTP/1.1\r\n").into_bytes()}

	fn read(shape: &Shape, target: &str, header: Option<&[u8]>) -> Option<Target<'static>> {
		let bytes: &'static [u8] = Box::leak(line(&shape.up.method, target).into_boxed_slice());
		Target::read(shape, PATH.as_bytes(), &Line::parse_any(bytes)?, header.map(|value| &*Box::leak(value.to_vec().into_boxed_slice())))
	}

	#[test]
	fn the_number_of_a_chunk_is_n_times_4096_plus_its_index() {
		assert_eq!((number(0, 0), number(1, 0), number(7, 4_094), number(7, 4_095)), (Some(0), Some(4_096), Some(7 * 4_096 + 4_094), None));
		// "The largest number is 4,294,967,295 times 4,096 plus 4,095, which is 2^44 - 1, far below the 2^60 at which a session closes."
		assert_eq!((late_number(u32::MAX), NUMBER_MAX), ((1 << 44) - 1, (1 << 44) - 1));
		assert_eq!(NUMBER_MAX, u64::from(u32::MAX) * 4_096 + 4_095);
		assert!(NUMBER_MAX < NUMBERS);
		// An index past the last is the late answer's, never another request's number.
		assert_eq!((number(5, 4_096), number(5, 4_095)), (None, None));
	}

	#[test]
	fn a_chunk_opens_only_at_the_numbers_of_its_request() {
		let (body, mut scratch) = (data(3), Vec::new());
		assert_eq!(open(&key(), 3, &body, &mut scratch).unwrap().len(), 3);
		// "An answer to request `n` opens only at the numbers of `n`": the other requests' bodies, and the same chunks one place off.
		for n in [0, 2, 4, 1_000, u32::MAX] {assert_eq!(open(&key(), n, &body, &mut scratch).map(|chunks| chunks.len()), Err(BodyError::Refused), "request {n}")}
		let (mut writer, mut shifted) = (writer(), Vec::new());
		writer.append(3, 1, &[&item(0)], false, BODY_MAX, &mut zero, &mut shifted).unwrap();
		assert_eq!(open(&key(), 3, &shifted, &mut scratch).map(|chunks| chunks.len()), Err(BodyError::Refused));
	}

	#[test]
	fn a_request_built_twice_is_the_same_bytes() {
		// "The code must have a test that builds every request twice and compares."
		for count in [1, 2, 9] {
			let (first, second) = (data(count), data(count));
			assert_eq!(first, second);
			for (method, place, name) in [("POST", "body", None), ("GET", "query", None), ("GET", "path", None), ("GET", "header", Some("X-Hint"))] {
				let shape = shape(method, place, name);
				let build = || Parts::build(&shape, PATH, &format!("{SID}.5"), &first, &mut zero).unwrap().unwrap();
				assert_eq!(build(), build(), "{place}");
			}
		}
	}

	#[test]
	fn the_late_answer_is_80_bytes_and_the_same_every_time() {
		let (first, second) = (writer().late(9), writer().late(9));
		assert_eq!((first.len(), first), (80, second));
		assert_ne!(writer().late(9), writer().late(10));
		// It is a chunk at index 4,095 of its `n` whose plaintext is 64 zero bytes, and no other chunk is.
		assert!(is_late(&key(), 9, &first) && !is_late(&key(), 10, &first) && !is_late(&key(), 9, &first[..79]) && !is_late(&key(), 9, &[&first[..], &[0]].concat()));
		let mut changed = first;
		changed[3] ^= 1;
		assert!(!is_late(&key(), 9, &changed));
		// A chunk at another index of the same `n` is not the late answer.
		let (mut other, mut sealed) = (writer(), Vec::new());
		other.seal(9, 0, &[], false, &mut zero, &mut sealed).unwrap();
		assert!(!is_late(&key(), 9, &sealed));
		// Sealing it does not count as a chunk, so the first 16 chunks stay wide.
		assert_eq!(writer().sealed(), 0);
		// It opens as a chunk with no datagram.
		let mut copy = first;
		assert_eq!(open_one(&key(), late_number(9), &mut copy).unwrap().count(), 0);
	}

	#[test]
	fn a_writer_pads_within_what_the_request_can_hold() {
		let (mut writer, mut body, big) = (writer(), Vec::new(), [7u8; 1_450]);
		// 1,450 bytes of datagram and a limit of 1,500: the wide padding the first chunks would draw is cut to what is left, and the chunk fits.
		writer.append(1, 0, &[&big], true, 1_500, &mut |bytes: &mut [u8]| {bytes.fill(0xff); Ok(())}, &mut body).unwrap();
		assert!(body.len() <= 1_500 && body.len() >= 2 + TAG + 2 + 1_450, "{}", body.len());
		// What does not fit is `Size`, and nothing is appended or counted.
		let before = (body.len(), writer.sealed());
		assert_eq!(writer.append(1, 1, &[&big], false, 1_500, &mut zero, &mut body), Err(ChunkError::Size));
		assert_eq!((body.len(), writer.sealed()), before);
		// The index of the late answer is never used by a chunk of data.
		assert_eq!(writer.append(1, 4_095, &[], false, BODY_MAX, &mut zero, &mut body), Err(ChunkError::Size));
		assert_eq!(writer.append(1, 1, &[&[0; 31]], false, BODY_MAX, &mut zero, &mut body), Err(ChunkError::Item));
		assert_eq!((body.len(), writer.sealed()), before);
	}

	#[test]
	fn the_first_16_chunks_are_wide_and_a_handshake_is_too() {
		let mut writer = Writer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut fixed(&[40])).unwrap());
		let mut sizes = Vec::new();
		for index in 0..18 {
			let mut body = Vec::new();
			writer.append(1, index, &[&item(1)], false, BODY_MAX, &mut zero, &mut body).unwrap();
			sizes.push(body.len());
		}
		// With draws of 0, a wide chunk has the session base (40) and a normal one none.
		assert!(sizes[..16].iter().all(|size| *size == 2 + 2 + 32 + 40 + TAG) && sizes[16..].iter().all(|size| *size == 2 + 2 + 32 + TAG), "{sizes:?}");
		let mut body = Vec::new();
		writer.append(1, 18, &[&item(1)], true, BODY_MAX, &mut zero, &mut body).unwrap();
		assert_eq!(body.len(), 2 + 2 + 32 + 40 + TAG);
	}

	#[test]
	fn data_is_one_canonical_text() {
		assert_eq!(decode(b"AAAA"), Some(vec![0, 0, 0]));
		assert_eq!(decode(b"AA"), Some(vec![0]));
		assert_eq!(decode(b"-_-_"), Some(vec![0xfb, 0xff, 0xbf]));
		for text in [&b"AB"[..], b"AC", b"AAB", b"AAC", b"AAAAB", b"A", b"AAAAA", b"AAA=", b"AA==", b"AAAA=", b"+AAA", b"/AAA", b"AA A", b"AAAA\n", b"AAAA ", b"\xc3\xa9AA", b"AA\0A", b"%41AA"] {assert_eq!(decode(text), None, "{:?}", String::from_utf8_lossy(text))}
		// The length is checked before anything is allocated: one character over the encoded size of 65,536 bytes is refused, and the largest is taken.
		assert_eq!((decoded_len(87_382), decoded_len(87_383), decoded_len(87_381)), (Some(65_536), Some(65_537), None));
		assert_eq!(decode(&vec![b'A'; 87_382]).map(|bytes| bytes.len()), Some(65_536));
		assert_eq!(decode(&vec![b'A'; 87_383]), None);
		assert_eq!(decode(&vec![b'A'; 1 << 22]), None);
		for size in 0..200usize {
			let bytes: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
			assert_eq!(decode(encode(&bytes).as_bytes()), Some(bytes), "{size} bytes");
		}
	}

	#[test]
	fn a_path_is_cut_in_segments_of_8_to_64_with_the_rest_last() {
		let text = "x".repeat(300);
		let cut = segments(&text, &mut zero).unwrap();
		let lengths: Vec<usize> = cut.split('/').map(str::len).collect();
		assert_eq!(lengths, [vec![8; 30], vec![60]].concat());
		assert_eq!(segments(&"y".repeat(64), &mut zero).unwrap(), "y".repeat(64));
		assert_eq!(segments("", &mut zero).unwrap(), "");
		// Every cut of a random source stays inside the rules and joins back to the text.
		let mut random = spread();
		let mut seen = [false; 57];
		for size in [1, 63, 64, 65, 72, 129, 1_000, 5_000] {
			let text = "z".repeat(size);
			let cut = segments(&text, &mut random).unwrap();
			let parts: Vec<&str> = cut.split('/').collect();
			assert!(parts.iter().all(|part| (1..=64).contains(&part.len())) && parts[..parts.len() - 1].iter().all(|part| part.len() >= 8) && cut.replace('/', "") == text, "{size}");
			for part in &parts[..parts.len() - 1] {seen[part.len() - 8] = true}
		}
		assert!(seen.iter().filter(|seen| **seen).count() > 30);
	}

	#[test]
	fn a_target_reads_back_in_each_placement() {
		let body = data(2);
		for (method, place, name) in [("POST", "body", None), ("GET", "query", None), ("GET", "path", None), ("GET", "header", Some("X-Hint")), ("DELETE", "query", None), ("DELETE", "body", None)] {
			let shape = shape(method, place, name);
			for who in [format!("{SID}.5"), "T".repeat(200)] {
				let parts = Parts::build(&shape, PATH, &who, &body, &mut zero).unwrap().unwrap();
				let read = read(&shape, &parts.target, parts.header.as_deref().map(str::as_bytes)).unwrap_or_else(|| panic!("{place} {who}"));
				let wanted = if who.len() == 200 {Who::Opening(who.as_bytes())} else {Who::Later(std::array::from_fn(|i| i as u8), 5)};
				assert_eq!(read.who, wanted, "{place}");
				assert_eq!((read.bodied(), read.data()), (place == "body", (place != "body").then(|| body.clone())));
			}
		}
		assert_eq!(Line::parse_any(&line("DELETE", PATH)).unwrap().method, Method::Other);
	}

	#[test]
	fn a_path_cut_two_ways_is_the_same_data_and_a_second_spelling_is_not_read() {
		let (shape, body) = (shape("GET", "path", None), vec![7u8; 99]);
		let text = encode(&body);
		let cut = |lengths: &[usize]| {
			let (mut out, mut rest) = (Vec::new(), text.as_str());
			for length in lengths {
				let (head, tail) = rest.split_at(*length);
				out.push(head);
				rest = tail;
			}
			out.push(rest);
			out.join("/")
		};
		let who = format!("{SID}.2");
		let data = |target: String| read(&shape, &target, None).and_then(|read| read.data());
		// "The same data in a path cut two ways", also at the shortest and the longest segment.
		for lengths in [&[64, 64][..], &[8, 56, 30], &[1, 64, 64], &[64, 1, 64, 1], &[8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]] {assert_eq!(data(format!("{PATH}/{who}/{}", cut(lengths))), Some(body.clone()), "{lengths:?}")}
		let (a, b) = (&text[..8], &text[8..68]);
		let good = format!("{PATH}/{who}/{a}/{b}");
		assert!(read(&shape, &good, None).is_some());
		let long = "A".repeat(68);
		let refused = [
			("an empty segment", format!("{PATH}/{who}/{a}//{b}")),
			("a trailing slash", format!("{good}/")),
			("a leading slash on the data", format!("{PATH}/{who}//{a}/{b}")),
			("a dot segment", format!("{PATH}/{who}/./{a}/{b}")),
			("two dots", format!("{PATH}/{who}/../{a}/{b}")),
			("a segment of 68", format!("{PATH}/{who}/{long}")),
			("a percent-escape", format!("{PATH}/{who}/{a}/%41{b}")),
			("a plus", format!("{PATH}/{who}/{a}/+{}", &b[1..])),
			("padding", format!("{good}=")),
			("a query", format!("{good}?x=1")),
			("no data", format!("{PATH}/{who}")),
			("no data and a slash", format!("{PATH}/{who}/")),
			("data in the first segment", format!("{PATH}/{who}.{a}/{b}")),
			("a leading zero in n", format!("{PATH}/{SID}.02/{a}/{b}")),
			("n of 0", format!("{PATH}/{SID}.0/{a}/{b}")),
			("n over 4,294,967,295", format!("{PATH}/{SID}.4294967296/{a}/{b}")),
			("another path", format!("/assets/sync-90be44f2.js/{who}/{a}/{b}")),
			("the path alone", format!("{PATH}/")),
			("a longer path", format!("{PATH}x/{who}/{a}/{b}")),
			("data of 17 bytes", format!("{PATH}/{who}/{}", encode(&[0; 17]))),
			("a length no base64 has", format!("{PATH}/{who}/{a}/{}", &b[..53])),
		];
		for (case, target) in refused {assert!(read(&shape, &target, None).is_none(), "{case}")}
		// The last character with a bit set that belongs to no byte: 100 bytes are 134 characters and the last one has 4 unused bits.
		let text = encode(&[7u8; 100]);
		let mut last = text.clone().into_bytes();
		let tail = last.len() - 1;
		last[tail] = b'B';
		let last = String::from_utf8(last).unwrap();
		assert!(read(&shape, &format!("{PATH}/{who}/{}/{}/{}", &text[..60], &text[60..120], &text[120..]), None).is_some());
		assert!(read(&shape, &format!("{PATH}/{who}/{}/{}/{}", &last[..60], &last[60..120], &last[120..]), None).is_none());
	}

	#[test]
	fn a_query_has_one_form() {
		let (shape, body) = (shape("GET", "query", None), vec![7u8; 100]);
		let text = encode(&body);
		let look = |target: String| read(&shape, &target, None).map(|read| (read.who, read.data()));
		assert_eq!(look(format!("{PATH}?{SID}.7.{text}")), Some((Who::Later(std::array::from_fn(|i| i as u8), 7), Some(body.clone()))));
		let refused = [
			("no data", format!("{PATH}?{SID}.7")),
			("a dot and no data", format!("{PATH}?{SID}.7.")),
			("padding", format!("{PATH}?{SID}.7.{text}=")),
			("a percent-escape", format!("{PATH}?{SID}.7.%41{text}")),
			("another parameter", format!("{PATH}?{SID}.7.{text}&a=1")),
			("a parameter before", format!("{PATH}?a=1&{SID}.7.{text}")),
			("an equals sign", format!("{PATH}?{SID}.7.{text}=x")),
			("a plus", format!("{PATH}?{SID}.7.+{text}")),
			("a second dot in the data", format!("{PATH}?{SID}.7.{}.{}", &text[..8], &text[8..])),
			("a leading zero in n", format!("{PATH}?{SID}.07.{text}")),
			("n of 0", format!("{PATH}?{SID}.0.{text}")),
			("n of 11 digits", format!("{PATH}?{SID}.12345678901.{text}")),
			("a short sid", format!("{PATH}?{}.7.{text}", &SID[..21])),
			("data of 17 bytes", format!("{PATH}?{SID}.7.{}", encode(&[0; 17]))),
			("the wrong path", format!("/other-path-12345?{SID}.7.{text}")),
			("no query", PATH.to_string()),
		];
		for (case, target) in refused {assert_eq!(look(target), None, "{case}")}
		// "At the limit and one byte over": the whole target is at most 4,000 bytes.
		let room = |size: usize| format!("{PATH}?{SID}.7.{}", "A".repeat(size - PATH.len() - 1 - SID.len() - 3));
		assert!(look(room(4_000)).is_some() && look(room(4_001)).is_none() && look(room(3_998)).is_some());
		// A method that is not the shape's, and a header value that is no business of a `query` shape.
		let bytes = line("POST", &format!("{PATH}?{SID}.7.{text}"));
		assert_eq!(Target::read(&shape, PATH.as_bytes(), &Line::parse_any(&bytes).unwrap(), None), None);
		let bytes = line("GET", &format!("{PATH}?{SID}.7.{text}"));
		assert_eq!(Target::read(&shape, PATH.as_bytes(), &Line::parse_any(&bytes).unwrap(), Some(b"AAAA")), None);
	}

	#[test]
	fn a_header_and_a_body_shape_have_the_who_in_the_query_and_the_data_elsewhere() {
		let text = encode(&[7u8; 100]);
		let header = Shape::resolve(&Given {limit: Some(1_024), ..given("GET", "header", Some("X-Hint"))}).unwrap();
		let target = format!("{PATH}?{SID}.7");
		assert!(read(&header, &target, Some(text.as_bytes())).is_some());
		for value in [None, Some(&b""[..]), Some(&b" AAAA"[..]), Some(&b"AAAA="[..]), Some(&b"AB"[..]), Some(&b"AAAA\r"[..]), Some(&b"AAAA.AAAA"[..])] {assert!(read(&header, &target, value).is_none(), "{value:?}")}
		// "A header value at the limit and one byte over."
		assert!(read(&header, &target, Some("A".repeat(1_024).as_bytes())).is_some() && read(&header, &target, Some("A".repeat(1_028).as_bytes())).is_none());
		let post = shape("POST", "body", None);
		let token = "T".repeat(150);
		for bad in ["T%41", "T&a=1", "T+T", "T="] {assert!(read(&post, &format!("{PATH}?{bad}"), None).is_none(), "{bad}")}
		assert_eq!(read(&post, &target, None).map(|read| (read.who, read.bodied())), Some((Who::Later(std::array::from_fn(|i| i as u8), 7), true)));
		// Data behind the dots of a `body` shape is a second spelling of nothing.
		for target in [format!("{PATH}?{SID}.7.{text}"), format!("{PATH}?{SID}.7."), PATH.to_string(), format!("{PATH}?{SID}.07"), format!("{PATH}?{token}.AAAA")] {assert!(read(&post, &target, None).is_none(), "{target}")}
		// The opening request carries its token, which holds no dot.
		assert_eq!(read(&post, &format!("{PATH}?{token}"), None).map(|read| read.who), Some(Who::Opening(token.as_bytes())));
		// A header value is no business of a `body` shape.
		assert!(read(&post, &target, Some(b"AAAA")).is_none());
	}

	#[test]
	fn the_capacity_follows_the_limit() {
		let who = SID.len() + 2;
		assert_eq!(capacity(&shape("POST", "body", None), PATH.len(), who), 65_536);
		// (4,000 - 24 - 1 - 24 - 1) characters, three quarters of them.
		let characters = 4_000 - PATH.len() - 1 - who - 1;
		let query = capacity(&shape("GET", "query", None), PATH.len(), who);
		assert_eq!(query, characters / 4 * 3 + [0, 0, 1, 2][characters % 4]);
		assert!((2_900..3_000).contains(&query), "{query}");
		let walk = capacity(&shape("GET", "path", None), PATH.len(), who);
		assert!(walk < query && walk > 2_500, "{walk}");
		assert_eq!(capacity(&shape("GET", "header", Some("X-A")), PATH.len(), who), 3_000 / 4 * 3);
		// Whatever fits the capacity builds within the limit, and a little more does not, whatever the cut.
		for (place, name) in [("query", None), ("path", None), ("header", Some("X-A"))] {
			let shape = shape("GET", place, name);
			let size = capacity(&shape, PATH.len(), who);
			let parts = Parts::build(&shape, PATH, &format!("{SID}.5"), &vec![7; size], &mut zero).unwrap().unwrap();
			assert!(parts.target.len() <= 4_000 && parts.header.as_ref().is_none_or(|value| value.len() <= 3_000), "{place}");
			assert!(place == "path" || Parts::build(&shape, PATH, &format!("{SID}.5"), &vec![7; size + 4], &mut zero).unwrap().is_none(), "{place}");
		}
	}

	#[test]
	fn the_frames_of_a_list_are_checked_before_any_chunk_is_opened() {
		let body = data(3);
		assert_eq!(framed(&body), Some(3));
		assert_eq!(framed(&[]), None);
		assert_eq!(framed(&body[..body.len() - 1]), None);
		assert_eq!(framed(&[&body[..], &[0, 15], &[0; 15]].concat()), None);
		assert_eq!(framed(&[&body[..], &[0, 16], &[0; 16]].concat()), Some(4));
		assert_eq!(framed(&[0x3e, 0x91, 0, 0]), None);
		assert_eq!(framed(&[0]), None);
		// 4,095 chunks are the most a list holds, and a 4,096th is refused.
		let many = |count: usize| [&[0u8, 16][..], &[0; 16]].concat().repeat(count);
		assert_eq!((framed(&many(4_095)), framed(&many(4_096))), (Some(4_095), None));
	}

	#[test]
	fn the_index_of_the_late_answer_is_never_a_chunk_of_data() {
		let (mut writer, mut body, mut scratch) = (writer(), Vec::new(), Vec::new());
		for index in 0..3_000 {writer.append(2, index, &[], false, BODY_MAX, &mut zero, &mut body).unwrap()}
		assert!(body.len() <= BODY_MAX);
		assert_eq!(open(&key(), 2, &body, &mut scratch).unwrap().len(), 3_000);
		// The count limit of a list is the opener's: 3,000 chunks are refused where 2,999 is the most.
		assert_eq!(fronted::open_body(&key(), number(2, 0).unwrap(), &body, &mut scratch, 2_999).map(|chunks| chunks.len()), Err(BodyError::Refused));
		assert_eq!(fronted::open_body(&key(), number(2, 0).unwrap(), &body, &mut scratch, 3_000).unwrap().len(), 3_000);
		// The sender never seals a chunk of data at index 4,095, and the late answer, put in a list as a chunk, is not at the number its place needs.
		assert_eq!(writer.append(2, 4_095, &[], false, BODY_MAX, &mut zero, &mut body), Err(ChunkError::Size));
		let mut late = data(3);
		late.extend_from_slice(&[0, 80]);
		late.extend_from_slice(&writer.late(3));
		assert_eq!(open(&key(), 3, &late, &mut scratch).map(|chunks| chunks.len()), Err(BodyError::Refused));
	}
}
