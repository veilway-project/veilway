//! HTTP/1.1 as the proxy path of a stream listener reads it (transports page, "Accept state machine", "Trusted proxy peer"): where a request and where its answer ends, and the address a trusted proxy forwards.
//! Nothing here writes or changes a byte. A request that is not a user's is handed to the decoy origin as it was read, so all the node has to know is how many bytes of the connection belong to it. It reads that more strictly than a web server does:
//! whatever two readers of HTTP could take two ways (a line end that is no CR LF, a folded line, a length written twice or with a sign, a coding besides `chunked`, a chunk with an extension) is not read at all. The answer is then "cannot tell", and the caller stops telling requests apart on that connection.
//! That is how the node and the origin never disagree about where a request ends: where they could, the node no longer has an opinion.
use std::net::IpAddr;

/// How much of an answer's head is kept to find where the answer ends. An answer whose head is longer is one the node cannot tell the end of.
pub const ANSWER_HEAD_MAX: usize = 65_536;
// A length of at most 19 digits is below 2^64, and a chunk size of at most 16 is too. A length above 2^63 - 1 is one a reader that counts with a sign wraps or refuses, so it is not read here either.
const LENGTH_DIGITS: usize = 19;
const LENGTH_MAX: u64 = i64::MAX as u64;
const SIZE_DIGITS: u8 = 16;

/// Where the body of a message ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
	/// There is none.
	None,
	/// After this many bytes: one `Content-Length`.
	Length(u64),
	/// After the last chunk and its trailer: `Transfer-Encoding: chunked`.
	Chunked,
	/// Where the connection ends, which only an answer may say.
	Close,
}

/// The node cannot tell where a message ends. It is final for the connection the message is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsure;

/// What the head of a request says about the request and its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
	/// The bytes of the request line, its line end included. 0 for a head without a line end.
	pub line: usize,
	/// The method is `HEAD`, whose answer has no body whatever its head says.
	pub bodiless: bool,
	/// The method is `CONNECT`, whose answer may turn the connection into a tunnel.
	pub tunnel: bool,
	/// Where the request ends. None when that cannot be told with certainty: the head is not strictly HTTP/1.1, or says its length in a way two readers could take differently.
	pub body: Option<Framing>,
}

// The characters of a method and of a field name (RFC 9110, "token").
fn token(byte: u8) -> bool {byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)}

/// The end of the first head in `bytes`: the place behind its empty line.
pub fn head_end(bytes: &[u8]) -> Option<usize> {bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4)}

// The lines of a head without their line ends, up to the empty line. None for a head with a CR or LF that is not part of a CR LF, with a NUL, or without the empty line at its end.
fn lines(head: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
	let inner = head.strip_suffix(b"\r\n\r\n")?;
	let sound = inner.iter().enumerate().all(|(at, byte)| match byte {
		b'\r' => inner.get(at + 1) == Some(&b'\n'),
		b'\n' => at > 0 && inner[at - 1] == b'\r',
		0 => false,
		_ => true,
	});
	sound.then(|| inner.split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line)))
}

// A field line as its name and its value without the blanks around it. None for a line that is no field: no colon, a name that is no token, which a folded line and a blank before the colon both are.
fn field(line: &[u8]) -> Option<(&[u8], &[u8])> {
	let colon = line.iter().position(|byte| *byte == b':')?;
	let (name, mut value) = (&line[..colon], &line[colon + 1..]);
	while let [b' ' | b'\t', rest @ ..] | [rest @ .., b' ' | b'\t'] = value {value = rest}
	(!name.is_empty() && name.iter().all(|byte| token(*byte))).then_some((name, value))
}

// What the fields of a head say about the body behind it, for a head that says one thing only: no body, one length in plain digits, or `chunked` alone. `fields` are the lines behind the first.
fn framing<'a>(fields: impl Iterator<Item = &'a [u8]>) -> Option<(Option<u64>, bool)> {
	let (mut length, mut chunked) = (None, false);
	for line in fields {
		let (name, value) = field(line)?;
		// A name that differs from one of the two only by `_` for `-` is the same field to software that hands header fields on as variables, and another field to software that does not.
		if name.contains(&b'_') && [&b"content-length"[..], b"transfer-encoding"].iter().any(|framing| name.len() == framing.len() && name.iter().zip(*framing).all(|(byte, wanted)| byte.to_ascii_lowercase() == *wanted || (*byte, *wanted) == (b'_', b'-'))) {return None}
		if name.eq_ignore_ascii_case(b"content-length") {
			if length.is_some() || value.is_empty() || value.len() > LENGTH_DIGITS || !value.iter().all(u8::is_ascii_digit) {return None}
			length = Some(value.iter().fold(0u64, |length, digit| length * 10 + u64::from(digit - b'0'))).filter(|length| *length <= LENGTH_MAX);
			if length.is_none() {return None}
		} else if name.eq_ignore_ascii_case(b"transfer-encoding") {
			if chunked || !value.eq_ignore_ascii_case(b"chunked") {return None}
			chunked = true;
		}
	}
	(length.is_none() || !chunked).then_some((length, chunked))
}

/// Reads the head of a request, which ends with its empty line. The method is read from whatever the head begins with, so that the answer to a head the node cannot read is still followed as far as it can be.
/// "A request with both `Content-Length` and `Transfer-Encoding`, with more than one `Content-Length`, with a `Transfer-Encoding` other than exactly `chunked`" is one whose end cannot be told, and so is every head that is not written exactly as HTTP/1.1 writes it.
pub fn request(head: &[u8]) -> Request {
	let (line, method) = (head.windows(2).position(|window| window == b"\r\n").map_or(0, |at| at + 2), head.split(|byte| *byte == b' ').next().unwrap_or_default());
	let (bodiless, tunnel) = (method == b"HEAD", method == b"CONNECT");
	let body = lines(head).and_then(|mut lines| {
		let mut parts = lines.next()?.split(|byte| *byte == b' ');
		let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
		if parts.next().is_some() || tunnel || method.is_empty() || !method.iter().all(|byte| token(*byte)) || target.is_empty() || !target.iter().all(|byte| (0x21..=0x7e).contains(byte)) || version != b"HTTP/1.1" {return None}
		Some(match framing(lines)? {
			(Some(length), _) => Framing::Length(length),
			(None, true) => Framing::Chunked,
			(None, false) => Framing::None,
		})
	});
	Request {line, bodiless, tunnel, body}
}

/// The address a trusted proxy says a request came from: "the rightmost address in the header named by `client_address_header` that is not itself inside `trusted_proxies`. If the header is absent or unreadable, it is the peer", which is None here.
/// `name` is the header's name and `trusted` says whether an address is inside `trusted_proxies`. Fields of that name are one list in the order they stand in. An entry is an address as it is written, an IPv6 address also inside brackets, and an IPv4 address inside an IPv6 one is the IPv4 address.
/// An entry that is no address, to the right of every address that is not a proxy's, makes the header unreadable. What stands to the left of the answer is whatever a visitor sent to the first proxy, and is never read.
pub fn forwarded(head: &[u8], name: &[u8], trusted: impl Fn(IpAddr) -> bool) -> Option<IpAddr> {
	let mut source = None;
	for (_, value) in lines(head)?.skip(1).filter_map(field).filter(|(field, _)| field.eq_ignore_ascii_case(name)) {
		for entry in value.split(|byte| *byte == b',') {
			let text = std::str::from_utf8(entry).ok().map(|text| text.trim_matches([' ', '\t']));
			let address = text.and_then(|text| text.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')).unwrap_or(text).parse::<IpAddr>().ok()).map(|address| address.to_canonical());
			source = match address {
				Some(address) if trusted(address) => source,
				address => address,
			};
		}
	}
	source
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
	Done,
	Close,
	Unsure,
	Length(u64),
	/// Inside the digits of a chunk size.
	Size {value: u64, digits: u8},
	/// Behind the CR of a chunk size.
	SizeEnd(u64),
	Data(u64),
	/// Behind the data of a chunk, and whether the CR was read.
	DataEnd(bool),
	/// Inside the trailer: whether the line so far is empty, and whether its CR was read.
	Trailer {empty: bool, cr: bool},
}

/// Follows the body of one message through the bytes of its connection, without keeping any of them.
#[derive(Debug, Clone)]
pub struct Body(State);

impl Body {
	pub fn new(framing: Framing) -> Body {
		Body(match framing {
			Framing::None => State::Done,
			Framing::Length(length) => State::Length(length),
			Framing::Chunked => State::Size {value: 0, digits: 0},
			Framing::Close => State::Close,
		})
	}

	/// Takes the next bytes of the connection: how many of them belong to the body, and whether the body is complete with them. Bytes behind a complete body are not looked at.
	/// A chunked body is read as RFC 9112 writes it and no other way: a size in hexadecimal digits alone, CR LF, the data, CR LF, and behind the last chunk a trailer of lines that each end with CR LF. Anything else is `Unsure`, now and at every later call.
	pub fn feed(&mut self, bytes: &[u8]) -> Result<(usize, bool), Unsure> {
		let mut at = 0;
		loop {
			self.0 = match self.0 {
				State::Done => return Ok((at, true)),
				State::Close => return Ok((bytes.len(), false)),
				State::Unsure => return Err(Unsure),
				State::Length(0) => State::Done,
				State::Data(0) => State::DataEnd(false),
				State::Length(left) | State::Data(left) => {
					let take = left.min((bytes.len() - at) as u64);
					if take == 0 {return Ok((at, false))}
					at += take as usize;
					if matches!(self.0, State::Length(_)) {State::Length(left - take)} else {State::Data(left - take)}
				}
				state => {
					let Some(byte) = bytes.get(at).copied() else {return Ok((at, false))};
					at += 1;
					match (state, byte) {
						(State::Size {value, digits}, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F') if digits < SIZE_DIGITS => State::Size {value: value << 4 | u64::from((byte as char).to_digit(16).unwrap_or(0)), digits: digits + 1},
						(State::Size {value, digits}, b'\r') if digits > 0 => State::SizeEnd(value),
						(State::SizeEnd(0), b'\n') => State::Trailer {empty: true, cr: false},
						(State::SizeEnd(size), b'\n') => State::Data(size),
						(State::DataEnd(false), b'\r') => State::DataEnd(true),
						(State::DataEnd(true), b'\n') => State::Size {value: 0, digits: 0},
						(State::Trailer {empty, cr: false}, b'\r') => State::Trailer {empty, cr: true},
						(State::Trailer {empty: true, cr: true}, b'\n') => State::Done,
						(State::Trailer {empty: false, cr: true}, b'\n') => State::Trailer {empty: true, cr: false},
						(State::Trailer {empty, cr: false}, byte) if byte != b'\n' && byte != 0 && !(empty && matches!(byte, b' ' | b'\t')) => State::Trailer {empty: false, cr: false},
						_ => {
							self.0 = State::Unsure;
							return Err(Unsure);
						}
					}
				}
			};
		}
	}
}

/// What the bytes of an origin's connection say about the answer to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
	/// The answer is not complete.
	More,
	/// The answer is complete with this many of the bytes that were just fed.
	Done(usize),
	/// From here on the connection itself is the answer: it ends where the connection ends (no length, or a protocol the origin switched to), or the node cannot tell where it ends. No request behind this one is told apart.
	Open,
}

/// Follows the answer to one request through the bytes of the origin's connection. It keeps the head of the answer while that is not complete, at most `ANSWER_HEAD_MAX` bytes, and nothing of a body.
#[derive(Debug)]
pub struct Response {bodiless: bool, tunnel: bool, head: Vec<u8>, body: Option<Body>, open: bool, last: bool}

impl Response {
	/// For the answer to a request with these two flags of its head, see `Request`.
	pub fn new(bodiless: bool, tunnel: bool) -> Response {Response {bodiless, tunnel, head: Vec::new(), body: None, open: false, last: false}}

	/// The origin said this answer is the last on its connection: `Connection: close`, or an answer of HTTP/1.0 without `Connection: keep-alive`. It is known once the head of the answer was read.
	pub fn last(&self) -> bool {self.last}

	/// Takes the next bytes the origin sent. An interim answer (`100 Continue` and the others below 200) is passed over, and the answer is the one behind it.
	/// The body is where RFC 9112 says: none behind a `HEAD`, a `204` and a `304`, the connection itself behind a `101` and behind a `2xx` to a `CONNECT`, else `chunked`, else the one `Content-Length`, else the rest of the connection. A head that says two of these, or is not written as HTTP/1.1 writes it, is `Open`.
	pub fn feed(&mut self, bytes: &[u8]) -> Answer {
		let mut at = 0;
		loop {
			if self.open {return Answer::Open}
			if let Some(body) = &mut self.body {
				return match body.feed(&bytes[at..]) {
					Ok((taken, true)) => Answer::Done(at + taken),
					Ok(_) => Answer::More,
					Err(Unsure) => {
						self.open = true;
						Answer::Open
					}
				};
			}
			let before = self.head.len();
			self.head.extend_from_slice(&bytes[at..at + (bytes.len() - at).min(ANSWER_HEAD_MAX - before)]);
			let from = before.saturating_sub(3);
			let Some(end) = head_end(&self.head[from..]).map(|end| from + end) else {
				self.open = self.head.len() >= ANSWER_HEAD_MAX;
				return if self.open {Answer::Open} else {Answer::More};
			};
			at += end - before;
			self.head.truncate(end);
			let read = lines(&self.head).and_then(|mut lines| {
				let status = lines.next()?;
				let code = status.strip_prefix(b"HTTP/1.1 ").or_else(|| status.strip_prefix(b"HTTP/1.0 ")).filter(|rest| rest.len() >= 3 && rest[..3].iter().all(u8::is_ascii_digit) && matches!(rest.get(3), None | Some(b' '))).map(|rest| rest[..3].iter().fold(0u16, |code, digit| code * 10 + u16::from(digit - b'0')))?;
				let said = framing(lines)?;
				Some(match (code, said) {
					(101, _) => Some(Framing::Close),
					(100..=199, _) => None,
					(200..=299, _) if self.tunnel => Some(Framing::Close),
					(204 | 304, _) => Some(Framing::None),
					_ if self.bodiless => Some(Framing::None),
					(_, (Some(length), _)) => Some(Framing::Length(length)),
					(_, (None, true)) => Some(Framing::Chunked),
					(_, (None, false)) => Some(Framing::Close),
				})
			});
			if let (Some(Some(_)), Some(mut lines)) = (read, lines(&self.head)) {
				let (old, mut options) = (lines.next().is_some_and(|status| status.starts_with(b"HTTP/1.0")), lines.filter_map(field).filter(|(name, _)| name.eq_ignore_ascii_case(b"connection")).flat_map(|(_, value)| value.split(|byte| *byte == b',')).map(<[u8]>::trim_ascii));
				self.last = if old {!options.any(|option| option.eq_ignore_ascii_case(b"keep-alive"))} else {options.any(|option| option.eq_ignore_ascii_case(b"close"))};
			}
			self.head.clear();
			match read {
				Some(None) => {}
				Some(Some(framing)) if framing != Framing::Close => self.body = Some(Body::new(framing)),
				_ => self.open = true,
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn body(head: &str) -> Option<Framing> {request(head.as_bytes()).body}

	#[test]
	fn a_request_ends_where_its_head_says_and_nowhere_else() {
		assert_eq!(request(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), Request {line: 16, bodiless: false, tunnel: false, body: Some(Framing::None)});
		assert_eq!(body("POST /f HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n"), Some(Framing::Length(5)));
		assert_eq!(body("POST /f HTTP/1.1\r\ncontent-length:\t 0 \r\n\r\n"), Some(Framing::Length(0)));
		assert_eq!(body("POST /f HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n"), Some(Framing::Chunked));
		assert_eq!(body("DELETE /f?x=1 HTTP/1.1\r\n\r\n"), Some(Framing::None));
		// A length up to 2^63 - 1 is read, and one above it is not: a reader that counts with a sign takes it another way.
		assert_eq!((body("POST / HTTP/1.1\r\nContent-Length: 9223372036854775807\r\n\r\n"), body("POST / HTTP/1.1\r\nContent-Length: 9223372036854775808\r\n\r\n"), body(&format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", "9".repeat(19)))), (Some(Framing::Length(9_223_372_036_854_775_807)), None, None));
		// "A request with both `Content-Length` and `Transfer-Encoding`, with more than one `Content-Length`, with a `Transfer-Encoding` other than exactly `chunked`": the node cannot tell, whatever order they stand in.
		for head in [
			"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n",
			"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n", "POST / HTTP/1.1\r\nTransfer-Encoding:\r\n\r\n",
			"POST / HTTP/1.1\r\nContent_Length: 5\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: 5\r\ntransfer_encoding: chunked\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: 0x5\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: 5 5\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length:\r\n\r\n", "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
			// A line end that is no CR LF, a folded line, a blank before the colon, a line that is no field, a NUL.
			"GET / HTTP/1.1\nHost: a\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\n\r\n", "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", "GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n", "GET / HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n", "GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n", "GET / HTTP/1.1\r\nno colon here\r\n\r\n", "GET / HTTP/1.1\r\n: empty\r\n\r\n", "GET / HTTP/1.1\r\nX: a\0b\r\n\r\n",
			// A request line that is not a method, a target and `HTTP/1.1` with one blank between them.
			"GET / HTTP/1.0\r\n\r\n", "GET / HTTP/2\r\n\r\n", "GET  / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1 \r\n\r\n", "GET /a b HTTP/1.1\r\n\r\n", "GET /\t HTTP/1.1\r\n\r\n", " GET / HTTP/1.1\r\n\r\n", "G(T / HTTP/1.1\r\n\r\n", "GET /\u{e9} HTTP/1.1\r\n\r\n", "GET HTTP/1.1\r\n\r\n", "\r\n\r\n", "CONNECT a:1 HTTP/1.1\r\n\r\n",
			// No empty line at the end.
			"GET / HTTP/1.1\r\nHost: a\r\n", "", "GET",
		] {assert_eq!(body(head), None, "{head:?}")}
		// The method is read whatever the rest is like.
		assert_eq!((request(b"HEAD / HTTP/1.0\r\n\r\n").bodiless, request(b"CONNECT a:1 HTTP/1.1\r\n\r\n").tunnel, request(b"HEAD").bodiless, request(b"HEADER / HTTP/1.1\r\n\r\n").bodiless, request(b"GET /").line), (true, true, true, false, 0));
		assert_eq!((head_end(b"a\r\n\r\nb\r\n\r\n"), head_end(b"a\r\n\r"), head_end(b"\r\n\r\n")), (Some(5), None, Some(4)));
	}

	// The bytes of a body, fed in pieces of every size: how many belong to it, and that the end is found at the same byte.
	fn follow(framing: Framing, bytes: &[u8]) -> Vec<Result<(usize, bool), Unsure>> {
		(1..=bytes.len().max(1)).map(|size| {
			let (mut body, mut taken) = (Body::new(framing), 0);
			for piece in bytes.chunks(size) {
				match body.feed(piece) {
					Ok((count, true)) => return Ok((taken + count, true)),
					Ok((count, false)) => {
						assert_eq!(count, piece.len());
						taken += count;
					}
					Err(Unsure) => {
						assert_eq!(body.feed(b"0\r\n\r\n"), Err(Unsure));
						return Err(Unsure);
					}
				}
			}
			Ok((taken, false))
		}).collect()
	}

	fn all(framing: Framing, bytes: &[u8], expected: Result<(usize, bool), Unsure>) {
		for (size, got) in follow(framing, bytes).into_iter().enumerate() {assert_eq!(got, expected, "{:?} in pieces of {}", String::from_utf8_lossy(bytes), size + 1)}
	}

	#[test]
	fn a_body_is_followed_to_its_last_byte() {
		all(Framing::None, b"GET / HTTP/1.1\r\n", Ok((0, true)));
		all(Framing::Length(5), b"helloGET /", Ok((5, true)));
		all(Framing::Length(5), b"hell", Ok((4, false)));
		all(Framing::Length(0), b"next", Ok((0, true)));
		all(Framing::Close, b"anything at all", Ok((15, false)));
		all(Framing::Chunked, b"5\r\nhello\r\n0\r\n\r\nGET /", Ok((15, true)));
		all(Framing::Chunked, b"5\r\nhello\r\nA\r\n0123456789\r\n000\r\nX-Sum: 1\r\nY: 2\r\n\r\nnext", Ok((48, true)));
		all(Framing::Chunked, b"0\r\n\r\n", Ok((5, true)));
		all(Framing::Chunked, b"fF\r\n", Ok((4, false)));
		all(Framing::Chunked, b"5\r\nhel", Ok((6, false)));
		// The data of a chunk is not read: a line end inside it is data.
		all(Framing::Chunked, b"4\r\n\r\n\r\n\r\n0\r\n\r\n", Ok((14, true)));
		// "A malformed chunk size", an extension, a blank, a bare line end, data that is longer than its size, a folded trailer: none is read.
		for bytes in [&b"5;ext=1\r\nhello\r\n0\r\n\r\n"[..], b"5 \r\nhello\r\n0\r\n\r\n", b" 5\r\nhello\r\n0\r\n\r\n", b"\r\nhello\r\n", b"0x5\r\nhello\r\n0\r\n\r\n", b"-5\r\nhello\r\n", b"5\nhello\r\n0\r\n\r\n", b"5\r\rhello\r\n", b"5\r\nhelloX\r\n0\r\n\r\n", b"5\r\nhello\n0\r\n\r\n", b"00000000000000005\r\nhello\r\n0\r\n\r\n", b"g\r\n", b"0\r\nX: 1\n\r\n", b"0\r\nX: 1\r\n fold\r\n\r\n", b"0\r\nX: \0\r\n\r\n", b"0\r\n\n"] {all(Framing::Chunked, bytes, Err(Unsure))}
	}

	// What a tracker says after every byte of `bytes`, fed in pieces of `size`: the answer at the end, and where it was found complete.
	fn answer(bodiless: bool, tunnel: bool, bytes: &[u8]) -> Answer {
		let mut seen = None;
		for size in 1..=bytes.len().max(1) {
			let (mut response, mut fed, mut last) = (Response::new(bodiless, tunnel), 0, Answer::More);
			for piece in bytes.chunks(size) {
				last = match response.feed(piece) {
					Answer::Done(count) => Answer::Done(fed + count),
					other => other,
				};
				fed += piece.len();
				if last != Answer::More {break}
			}
			assert!(seen.is_none_or(|seen| seen == last), "{:?}: {seen:?} and then {last:?} in pieces of {size}", String::from_utf8_lossy(bytes));
			seen = Some(last);
		}
		seen.unwrap_or(Answer::More)
	}

	#[test]
	fn an_answer_ends_where_its_head_says() {
		assert_eq!(answer(false, false, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1"), Answer::Done(43));
		assert_eq!(answer(false, false, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"), Answer::More);
		assert_eq!(answer(false, false, b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"), Answer::Done(45));
		assert_eq!(answer(false, false, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), Answer::Done(62));
		assert_eq!(answer(false, false, b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"), Answer::Done(40));
		assert_eq!(answer(false, false, b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok"), Answer::Done(37));
		// No body behind a `HEAD`, a `204` and a `304`, whatever length the head names.
		assert_eq!(answer(true, false, b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"), Answer::Done(40));
		assert_eq!(answer(false, false, b"HTTP/1.1 204 No Content\r\n\r\n"), Answer::Done(27));
		assert_eq!(answer(false, false, b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n"), Answer::Done(48));
		// "`Expect: 100-continue`": the interim answer is passed over.
		assert_eq!(answer(false, false, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Answer::Done(65));
		assert_eq!(answer(false, false, b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"), Answer::More);
		// The connection is the answer: no length, a protocol the origin switched to, a tunnel.
		assert_eq!(answer(false, false, b"HTTP/1.1 200 OK\r\nServer: a\r\n\r\nbody to the end"), Answer::Open);
		assert_eq!(answer(false, false, b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x01a"), Answer::Open);
		assert_eq!(answer(false, true, b"HTTP/1.1 200 Connection established\r\n\r\n"), Answer::Open);
		assert_eq!(answer(false, true, b"HTTP/1.1 405 Not Allowed\r\nContent-Length: 0\r\n\r\n"), Answer::Done(47));
		// What the node cannot tell the end of.
		for bytes in [&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", b"HTTP/2 200\r\n\r\n", b"HTTP/1.1 20 OK\r\n\r\n", b"HTTP/1.1 2000 OK\r\n\r\n", b"hello\r\n\r\n", b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n", b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x\r\nhello\r\n0\r\n\r\n"] {assert_eq!(answer(false, false, bytes), Answer::Open, "{:?}", String::from_utf8_lossy(bytes))}
		// Whether the origin said the answer is its last on the connection.
		for (head, last) in [("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false), ("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", true), ("HTTP/1.1 200 OK\r\nconnection: Keep-Alive, CLOSE\r\nContent-Length: 0\r\n\r\n", true), ("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n", false), ("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", true), ("HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n", false), ("HTTP/1.1 100 Continue\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false)] {
			let mut response = Response::new(false, false);
			assert_eq!((response.feed(head.as_bytes()), response.last()), (Answer::Done(head.len()), last), "{head:?}");
		}
		// A head that never ends is given up at the bound, and nothing more is kept.
		let mut endless = Response::new(false, false);
		assert_eq!(endless.feed(b"HTTP/1.1 200 OK\r\n"), Answer::More);
		for _ in 0..ANSWER_HEAD_MAX / 1024 {endless.feed(&[b'a'; 1024]);}
		assert_eq!((endless.feed(b"a"), endless.head.len() <= ANSWER_HEAD_MAX), (Answer::Open, true));
	}

	#[test]
	fn the_source_is_the_rightmost_address_that_is_no_proxys() {
		let trusted = |address: IpAddr| address.is_loopback() || matches!(address, IpAddr::V4(v4) if v4.octets()[0] == 10);
		let source = |head: &str| forwarded(head.as_bytes(), b"X-Forwarded-For", trusted).map(|address| address.to_string());
		assert_eq!(source("GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7\r\n\r\n").as_deref(), Some("198.51.100.7"));
		assert_eq!(source("GET / HTTP/1.1\r\nx-forwarded-for: 203.0.113.9, 198.51.100.7 , 10.0.0.1,127.0.0.1\r\n\r\n").as_deref(), Some("198.51.100.7"));
		// Fields of the name are one list, and what a visitor wrote stands to the left of what the proxies added.
		assert_eq!(source("GET / HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1, not an address\r\nHost: a\r\nX-Forwarded-For: 2001:db8::7, 10.0.0.1\r\n\r\n").as_deref(), Some("2001:db8::7"));
		assert_eq!(source("GET / HTTP/1.1\r\nX-Forwarded-For: [2001:db8::7]\r\n\r\n").as_deref(), Some("2001:db8::7"));
		assert_eq!(source("GET / HTTP/1.1\r\nX-Forwarded-For: ::ffff:198.51.100.7\r\n\r\n").as_deref(), Some("198.51.100.7"));
		// "If the header is absent or unreadable, it is the peer": no field, only proxies, and an entry that is no address where the source would stand.
		for head in ["GET / HTTP/1.1\r\nHost: a\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For: 10.0.0.1, 127.0.0.1\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7, unknown\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7, 198.51.100.8:4000, 10.0.0.1\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For:\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7,\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For : 198.51.100.7\r\n\r\n", "GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7"] {assert_eq!(source(head), None, "{head:?}")}
		// A forged address inside `trusted_proxies` is passed over like a proxy's, so it names nobody.
		assert_eq!(source("GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7, 127.0.0.1\r\n\r\n").as_deref(), Some("198.51.100.7"));
	}
}
