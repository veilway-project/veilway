//! The stream of `fronted-shaped` (shapes page, "The stream" and "How the client reads a stream"): the head of the node's answer, the events and heartbeats it writes inside the chunked coding, and the reader the client puts every byte of the answer through.
//!
//! The reader is incremental and checks every limit before it grows a buffer: a chunk-size line of at most 18 bytes with no extension, a chunk of at most 65,536 bytes, no trailer, a line of at most 21,362 bytes before its ending, an event of 24 to 21,356 characters of canonical base64 with padding, and at most 4,095 events. A fault is final, and a reader that failed gives the same fault for every later byte.
use crate::{chunk::{MAX_SEALED, TAG}, uniform, NoRandom, Random};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{ops::RangeInclusive, time::Duration};

/// "A stream ends after 4,095 events, numbered 0 to 4,094, so that index 4,095 stays the late answer's."
pub const EVENTS: usize = 4_095;
/// "An event is the line `data: ` and 24 to 21,356 characters of standard base64 with padding": a sealed chunk of 16 to 16,016 bytes.
pub const EVENT_TEXT: RangeInclusive<usize> = 24..=21_356;
/// "A line of at most 21,362 bytes before its ending", which is `data: ` and the longest event.
pub const LINE_MAX: usize = 21_362;
/// "A chunk-size line of at most 18 bytes": 16 digits and the line end.
pub const SIZE_LINE: usize = 18;
const SIZE_DIGITS: u8 = 16;
/// "A chunk of at most 65,536 bytes."
pub const CHUNK_MAX: usize = 65_536;
/// "After a silence drawn uniformly from 10 to 25 s the node writes a comment line", in milliseconds.
pub const BEAT_AFTER: RangeInclusive<u32> = 10_000..=25_000;
/// "A colon, a space and 8 to 40 characters from `a-z 0-9`."
pub const BEAT_TEXT: RangeInclusive<u32> = 8..=40;
/// "The node ends a stream by itself at 3,600 s."
pub const LIFE_MAX: Duration = Duration::from_secs(3_600);
/// "The node answers a stream request with status `200` and these fields", and no other field of its own.
pub const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\n\r\n";
/// The last chunk of the chunked coding, with no trailer: "completing its chunked body".
pub const END: &[u8] = b"0\r\n\r\n";

/// The text of one event: `data: `, the sealed chunk in standard base64 with padding, and an empty line.
pub fn event(sealed: &[u8]) -> Vec<u8> {[b"data: ", STANDARD.encode(sealed).as_bytes(), b"\n\n"].concat()}

/// The text of one heartbeat: a comment line of a colon, a space and 8 to 40 characters from `a-z 0-9`, and an empty line. It is not sealed and holds nothing.
pub fn beat(random: &mut Random) -> Result<Vec<u8>, NoRandom> {
	let mut line = b": ".to_vec();
	for _ in 0..uniform(*BEAT_TEXT.start(), *BEAT_TEXT.end(), random)? {line.push(b"abcdefghijklmnopqrstuvwxyz0123456789"[uniform(0, 35, random)? as usize])}
	line.extend_from_slice(b"\n\n");
	Ok(line)
}

/// Appends `data` as one chunk of the chunked coding: its size in hexadecimal, a line end, the data and a line end.
pub fn chunked(data: &[u8], out: &mut Vec<u8>) {
	out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
	out.extend_from_slice(data);
	out.extend_from_slice(b"\r\n");
}

/// Why a stream ended as a stream that did not work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
	/// The chunked coding is not the one the page allows: a size line that is too long, has an extension or a character that is no digit, a chunk over 65,536 bytes, a trailer, or a byte behind the last chunk.
	Chunked,
	/// A line over its limit.
	Line,
	/// A line that is no event and no comment, an event that does not decode as canonical base64 into a sealed chunk, a second `data:` line in one event, or a comment inside an event.
	Event,
	/// More than 4,095 events.
	Count,
}

impl std::fmt::Display for Fault {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "stream: {self:?}")}
}

impl std::error::Error for Fault {}

#[derive(Debug, Clone, Copy)]
enum Coding {
	/// Inside the digits of a chunk size.
	Size {value: usize, digits: u8},
	/// Behind the CR of a chunk size.
	SizeEnd(usize),
	Data(usize),
	/// Behind the data of a chunk, and whether the CR was read.
	DataEnd(bool),
	/// Behind the size 0, and whether the CR was read: the line end of the last chunk, and no trailer.
	Last(bool),
	Done,
}

/// The reader of the body of a stream answer: the chunked coding, then lines, then events. It keeps less than one line and no more than one event.
#[derive(Debug)]
pub struct Reader {coding: Coding, line: Vec<u8>, pending: Option<Vec<u8>>, beating: bool, events: usize, failed: Option<Fault>}

impl Default for Reader {
	fn default() -> Self {Self::new()}
}

impl Reader {
	pub fn new() -> Self {Self {coding: Coding::Size {value: 0, digits: 0}, line: Vec::new(), pending: None, beating: false, events: 0, failed: None}}

	/// How many events have been read.
	pub fn events(&self) -> usize {self.events}

	/// Takes the next bytes of the body as they came and appends the sealed chunk of every event they complete to `out`, in order. True when the last chunk has been read: the stream is over, and any byte behind it is a fault.
	/// The result does not depend on how the bytes are cut into pieces. A fault is final.
	pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Vec<u8>>) -> Result<bool, Fault> {
		if let Some(fault) = self.failed {return Err(fault)}
		let read = self.read(bytes, out);
		if let Err(fault) = read {self.failed = Some(fault)}
		read
	}

	fn read(&mut self, bytes: &[u8], out: &mut Vec<Vec<u8>>) -> Result<bool, Fault> {
		let mut at = 0;
		loop {
			self.coding = match self.coding {
				Coding::Done => return if at < bytes.len() {Err(Fault::Chunked)} else {Ok(true)},
				Coding::Data(0) => Coding::DataEnd(false),
				Coding::Data(left) => {
					let take = left.min(bytes.len() - at);
					if take == 0 {return Ok(false)}
					self.lines(&bytes[at..at + take], out)?;
					at += take;
					Coding::Data(left - take)
				}
				state => {
					let Some(byte) = bytes.get(at).copied() else {return Ok(false)};
					at += 1;
					match (state, byte) {
						(Coding::Size {value, digits}, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F') if digits < SIZE_DIGITS && value * 16 + (byte as char).to_digit(16).unwrap_or(0) as usize <= CHUNK_MAX => Coding::Size {value: value * 16 + (byte as char).to_digit(16).unwrap_or(0) as usize, digits: digits + 1},
						(Coding::Size {value, digits}, b'\r') if digits > 0 => Coding::SizeEnd(value),
						(Coding::SizeEnd(0), b'\n') => Coding::Last(false),
						(Coding::SizeEnd(size), b'\n') => Coding::Data(size),
						(Coding::DataEnd(false), b'\r') => Coding::DataEnd(true),
						(Coding::DataEnd(true), b'\n') => Coding::Size {value: 0, digits: 0},
						(Coding::Last(false), b'\r') => Coding::Last(true),
						(Coding::Last(true), b'\n') => Coding::Done,
						_ => return Err(Fault::Chunked),
					}
				}
			};
		}
	}

	// The data of a chunk, as lines. A line is never joined with the next across more than its limit.
	fn lines(&mut self, data: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), Fault> {
		for byte in data {
			if *byte == b'\n' {
				let line = std::mem::take(&mut self.line);
				self.complete(line.strip_suffix(b"\r").unwrap_or(&line), out)?;
			} else if self.line.len() > LINE_MAX || (self.line.len() == LINE_MAX && *byte != b'\r') {
				return Err(Fault::Line);
			} else {
				self.line.push(*byte);
			}
		}
		Ok(())
	}

	fn complete(&mut self, line: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), Fault> {
		match (line.is_empty(), self.pending.take(), self.beating) {
			(true, Some(sealed), _) => {
				if self.events >= EVENTS {return Err(Fault::Count)}
				self.events += 1;
				out.push(sealed);
			}
			(true, None, true) => self.beating = false,
			(true, None, false) | (false, Some(_), _) | (false, None, true) => return Err(Fault::Event),
			(false, None, false) => match line.strip_prefix(b"data: ") {
				Some(text) => self.pending = Some(sealed(text)?),
				None if line.first() == Some(&b':') => self.beating = true,
				None => return Err(Fault::Event),
			},
		}
		Ok(())
	}
}

// The sealed chunk an event line holds: canonical standard base64 with padding of 24 to 21,356 characters, which decode to 16 to 16,016 bytes. The length of the text is checked before anything is decoded, and the length of the chunk after.
fn sealed(text: &[u8]) -> Result<Vec<u8>, Fault> {
	if !EVENT_TEXT.contains(&text.len()) || text.len() % 4 != 0 {return Err(Fault::Event)}
	STANDARD.decode(text).ok().filter(|decoded| (TAG..=MAX_SEALED).contains(&decoded.len())).ok_or(Fault::Event)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn zero(bytes: &mut [u8]) -> Result<(), NoRandom> {
		bytes.fill(0);
		Ok(())
	}

	// The body of a stream as the node writes it: each text in a chunk of its own.
	fn body(texts: &[&[u8]], last: bool) -> Vec<u8> {
		let mut out = Vec::new();
		for text in texts {chunked(text, &mut out)}
		if last {out.extend_from_slice(END)}
		out
	}

	fn read(bytes: &[u8]) -> (Result<bool, Fault>, Vec<Vec<u8>>) {
		let (mut reader, mut out) = (Reader::new(), Vec::new());
		(reader.feed(bytes, &mut out), out)
	}

	// The same bytes in pieces of `size`: the result, and what came out, must be the whole's.
	fn pieces(bytes: &[u8], size: usize) -> (Result<bool, Fault>, Vec<Vec<u8>>) {
		let (mut reader, mut out, mut result) = (Reader::new(), Vec::new(), Ok(false));
		for piece in bytes.chunks(size) {
			result = reader.feed(piece, &mut out);
			if result.is_err() {break}
		}
		(result, out)
	}

	fn sealed_of(size: usize, fill: u8) -> Vec<u8> {vec![fill; size]}

	#[test]
	fn the_head_is_the_five_fields_of_the_page() {
		let text = String::from_utf8_lossy(HEAD);
		assert_eq!(text.split("\r\n").collect::<Vec<_>>(), ["HTTP/1.1 200 OK", "Content-Type: text/event-stream", "Cache-Control: no-cache", "X-Accel-Buffering: no", "Transfer-Encoding: chunked", "", ""]);
	}

	#[test]
	fn an_event_is_a_data_line_and_an_empty_line() {
		assert_eq!(event(&[0, 1, 2]), b"data: AAEC\n\n");
		assert_eq!(event(&[0xff; 16]), [&b"data: "[..], STANDARD.encode([0xff; 16]).as_bytes(), b"\n\n"].concat());
		// The largest sealed chunk gives the longest line.
		assert_eq!(event(&sealed_of(16_016, 7)).len(), 6 + 21_356 + 2);
		let beats: Vec<Vec<u8>> = (0..5).map(|index| beat(&mut |bytes: &mut [u8]| {bytes.fill(index); Ok(())}).unwrap()).collect();
		assert!(beats.iter().all(|beat| beat.starts_with(b": ") && beat.ends_with(b"\n\n") && (8..=40).contains(&(beat.len() - 4)) && beat[2..beat.len() - 2].iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())));
		assert_eq!(beat(&mut zero).unwrap().len(), 4 + 8);
	}

	#[test]
	fn events_and_heartbeats_are_read_in_order_whole_or_in_pieces() {
		let (first, second) = (sealed_of(16, 1), sealed_of(100, 2));
		let wire = body(&[&event(&first), b": hello there\n\n", &event(&second)], true);
		let expected = (Ok(true), vec![first.clone(), second.clone()]);
		assert_eq!(read(&wire), expected);
		// Cut at every byte, and in every size of piece: "an `sse` answer cut at every byte of the chunked coding".
		for size in 1..40 {assert_eq!(pieces(&wire, size), expected, "pieces of {size}")}
		for cut in 0..wire.len() {
			let (mut reader, mut out) = (Reader::new(), Vec::new());
			assert_eq!(reader.feed(&wire[..cut], &mut out), Ok(false), "{cut}");
			assert_eq!(reader.feed(&wire[cut..], &mut out), Ok(true), "{cut}");
			assert_eq!(out, expected.1, "{cut}");
		}
		// Not over before the last chunk, and an event is not given before its empty line.
		assert_eq!(read(&wire[..wire.len() - 5]).0, Ok(false));
		assert_eq!(read(&body(&[b"data: AAAAAAAAAAAAAAAAAAAAAA==\n"], false)), (Ok(false), vec![]));
		// One chunk may hold many lines, and an event may be spread over many chunks.
		let joined = body(&[&[event(&first), event(&second)].concat()], true);
		assert_eq!(read(&joined), expected);
		let mut spread = Vec::new();
		for byte in event(&first) {chunked(&[byte], &mut spread)}
		assert_eq!(read(&spread), (Ok(false), vec![first]));
	}

	#[test]
	fn a_line_ends_with_lf_or_crlf() {
		let sealed = sealed_of(16, 9);
		let text = event(&sealed);
		let crlf = String::from_utf8(text.clone()).unwrap().replace('\n', "\r\n").into_bytes();
		assert_eq!(read(&body(&[&crlf], false)), (Ok(false), vec![sealed.clone()]));
		assert_eq!(read(&body(&[&text], false)), (Ok(false), vec![sealed.clone()]));
		// A CR alone is no line end, and stays in the line, where it is no base64.
		assert_eq!(read(&body(&[&text.iter().map(|byte| if *byte == b'\n' {b'\r'} else {*byte}).collect::<Vec<_>>()], false)), (Ok(false), vec![]));
		let cr = [&b"data: "[..], STANDARD.encode(&sealed).as_bytes(), b"\r\n\r\n"].concat();
		assert_eq!(read(&body(&[&cr], false)), (Ok(false), vec![sealed]));
	}

	#[test]
	fn a_line_of_21362_bytes_is_the_most() {
		let longest = event(&sealed_of(16_016, 3));
		assert_eq!(longest.len() - 2, 21_362);
		assert_eq!(read(&body(&[&longest], true)), (Ok(true), vec![sealed_of(16_016, 3)]));
		// With CR LF the same line is read.
		let mut crlf = longest[..longest.len() - 2].to_vec();
		crlf.extend_from_slice(b"\r\n\r\n");
		assert_eq!(read(&body(&[&crlf], true)), (Ok(true), vec![sealed_of(16_016, 3)]));
		// One byte over: a comment line of 21,363 bytes, and a data line of 21,363 bytes.
		let comment = |size: usize| [&b":"[..], &vec![b'x'; size - 1], b"\n\n"].concat();
		assert_eq!(read(&body(&[&comment(21_362)], true)), (Ok(true), vec![]));
		for size in [21_363, 21_364, 65_000] {assert_eq!(read(&body(&[&comment(size)], true)).0, Err(Fault::Line), "{size}")}
		assert_eq!(pieces(&body(&[&comment(21_363)], true), 7).0, Err(Fault::Line));
		// A line is never joined with the next: no line ending for 21,363 bytes is a fault before the ending comes.
		assert_eq!(read(&body(&[&vec![b':'; 21_363]], false)).0, Err(Fault::Line));
		assert_eq!(read(&body(&[&vec![b':'; 21_362]], false)).0, Ok(false));
		// An event of 21,360 characters is over the limit of 21,356.
		assert!(read(&body(&[&[&b"data: "[..], &vec![b'A'; 21_360], b"\n\n"].concat()], true)).0.is_err());
	}

	#[test]
	fn what_is_no_event_ends_the_stream() {
		let good = event(&sealed_of(16, 1));
		let text = |wire: &[u8]| String::from_utf8_lossy(wire).into_owned();
		let cases: Vec<(&str, Vec<u8>)> = vec![
			("another field", b"event: x\n\n".to_vec()),
			("an id line", b"id: 5\n\n".to_vec()),
			("a retry line", b"retry: 100\n\n".to_vec()),
			("no space after the colon", b"data:AAAAAAAAAAAAAAAAAAAAAA==\n\n".to_vec()),
			("an upper case field", b"DATA: AAAAAAAAAAAAAAAAAAAAAA==\n\n".to_vec()),
			("an empty line alone", b"\n".to_vec()),
			("an empty line after an event", [&good[..], b"\n"].concat()),
			("two data lines", [&good[..good.len() - 1], &good[..]].concat()),
			("a comment inside an event", [&good[..good.len() - 1], b": x\n\n"].concat()),
			("an event inside a comment", [&b": x\n"[..], &good[..]].concat()),
			("an unpadded event", b"data: AAAAAAAAAAAAAAAAAAAAAA\n\n".to_vec()),
			("a url-safe event", b"data: -_-_-_-_-_-_-_-_-_-_-_==\n\n".to_vec()),
			("a bit set after the data", b"data: AAAAAAAAAAAAAAAAAAAAAB==\n\n".to_vec()),
			("padding in the middle", b"data: AAAAAAAA==AAAAAAAAAAAA==\n\n".to_vec()),
			("a space in the event", b"data: AAAAAAAAAAAA AAAAAAAAAA==\n\n".to_vec()),
			("a sealed chunk of 15 bytes", event(&sealed_of(15, 1))),
			("a sealed chunk of 16,017 bytes", event(&sealed_of(16_017, 1))),
			("an empty event", b"data: \n\n".to_vec()),
		];
		for (case, wire) in cases {
			let framed = body(&[&wire], true);
			let (result, _) = read(&framed);
			assert!(matches!(result, Err(Fault::Event | Fault::Line)), "{case}: {} gave {result:?}", text(&wire));
			assert_eq!(pieces(&framed, 3).0, result, "{case} in pieces");
		}
	}

	#[test]
	fn a_stream_of_more_than_4095_events_is_a_fault() {
		let one = event(&sealed_of(16, 1));
		let many = |count: usize| body(&vec![&one[..]; count], false);
		assert_eq!(read(&many(4_095)).1.len(), 4_095);
		let (result, out) = read(&many(4_096));
		assert_eq!((result, out.len()), (Err(Fault::Count), 4_095));
		// The fault is final: more bytes give it again and nothing comes out.
		let (mut reader, mut out) = (Reader::new(), Vec::new());
		assert_eq!(reader.feed(&many(4_096), &mut out), Err(Fault::Count));
		assert_eq!((reader.feed(&body(&[&one], false), &mut out), reader.feed(&[], &mut out), out.len()), (Err(Fault::Count), Err(Fault::Count), 4_095));
	}

	#[test]
	fn the_chunked_coding_is_the_one_of_the_page() {
		let one = event(&sealed_of(16, 1));
		let size = format!("{:x}\r\n", one.len());
		let good = [size.as_bytes(), &one, b"\r\n0\r\n\r\n"].concat();
		assert_eq!(read(&good).0, Ok(true));
		let cases: Vec<(&str, Vec<u8>)> = vec![
			("an extension", [format!("{:x};ext=1\r\n", one.len()).as_bytes(), &one, b"\r\n0\r\n\r\n"].concat()),
			("a trailer", [size.as_bytes(), &one, b"\r\n0\r\nX-A: b\r\n\r\n"].concat()),
			("a trailer without a field", [size.as_bytes(), &one, b"\r\n0\r\n\r\n\r\n"].concat()),
			("no empty line behind the last chunk", [size.as_bytes(), &one, b"\r\n0\r\nx"].concat()),
			("a size line with LF only", [format!("{:x}\n", one.len()).as_bytes(), &one, b"\r\n0\r\n\r\n"].concat()),
			("a size that is no digit", b"zz\r\n".to_vec()),
			("an empty size", b"\r\n".to_vec()),
			("a space in the size", [format!("{:x} \r\n", one.len()).as_bytes(), &one].concat()),
			("a minus", b"-1\r\n".to_vec()),
			("no line end behind the data", [size.as_bytes(), &one, b"x0\r\n\r\n"].concat()),
			("LF only behind the data", [size.as_bytes(), &one, b"\n0\r\n\r\n"].concat()),
			("a byte behind the last chunk", [&good[..], b"x"].concat()),
			("a chunk of 65,537 bytes", b"10001\r\n".to_vec()),
			("a size of 17 digits", b"00000000000000000\r\n".to_vec()),
			("a huge size", b"ffffffffffffffff\r\n".to_vec()),
		];
		for (case, wire) in cases {
			let (result, _) = read(&wire);
			assert_eq!(result.err(), Some(Fault::Chunked), "{case}");
			assert_eq!(pieces(&wire, 1).0.err(), Some(Fault::Chunked), "{case} byte by byte");
		}
		// A size line of 18 bytes (16 digits and the line end) is the longest, with leading zeros; a chunk of 65,536 bytes is the largest.
		assert_eq!(read(b"0000000000010000\r\n").0, Ok(false));
		assert_eq!(read(b"10000\r\n").0, Ok(false));
		assert_eq!(read(b"00000000000000000\r\n").0, Err(Fault::Chunked));
		// A chunk of 65,536 bytes of comment lines is fine, 65,536 bytes of nothing in particular is not read as more than it is.
		let big = [vec![b':'; 65_535], b"\n".to_vec()].concat();
		assert_eq!(read(&[b"10000\r\n"[..].to_vec(), big].concat()).0, Err(Fault::Line));
	}

	#[test]
	fn a_chunk_ends_where_its_size_says_even_inside_a_line() {
		// The lines are not tied to the chunks: a line may be cut by a chunk end and goes on in the next.
		let text = event(&sealed_of(16, 5));
		let (head, tail) = text.split_at(10);
		assert_eq!(read(&body(&[head, tail], true)), (Ok(true), vec![sealed_of(16, 5)]));
	}
}
