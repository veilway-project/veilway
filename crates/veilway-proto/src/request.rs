//! The request line of a stream listener (transports page, "Accept state machine"): the test that decides, byte by byte and with no secret, whether a line can still be a user's, and the parts of a complete line. No header field is read here, and nothing is compared with a configured path except in `Line::path_is`.
use std::{fmt, time::Duration};
use subtle::ConstantTimeEq;

/// "Request line: at most 4,096 bytes, at most 10 s." The line end counts.
pub const LINE_MAX: usize = 4_096;
pub const LINE_TIME: Duration = Duration::from_secs(10);
/// "Request head of a user: at most 16,384 bytes, at most 10 s."
pub const HEAD_MAX: usize = 16_384;
pub const HEAD_TIME: Duration = Duration::from_secs(10);
/// "Request path: at least 12 characters."
pub const PATH_MIN: usize = 12;
// What follows the request target.
const ENDING: &[u8] = b" HTTP/1.1\r\n";

/// The two methods a candidate line may have. A `GET` can open a WebSocket session, a `POST` is a `fronted` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {Get, Post}

/// What the bytes read so far say about a request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
	/// The line is a candidate and not complete.
	More,
	/// "Forward at once": a byte arrived that makes the line no candidate, or the size limit was reached. The peer is not a user.
	Forward,
	/// The line is complete and is a candidate. It has this many bytes, the line end included, and is evaluated now.
	Line(usize),
}

/// The secret-free test of a request line (step 3): "The line is a candidate while it can still become `GET /` or `POST /`, then characters that are legal in a request target, then ` HTTP/1.1` and a line end."
/// The characters of a request target are those of RFC 3986 for a path and a query: letters, digits and `-._~!$&'()*+,;=:@/?%`. A line end is CR LF. Web servers take more than this, and whatever they take beyond it is forwarded to one.
#[derive(Debug, Clone, Default)]
pub struct Scanner {read: usize, post: bool, ending: usize, scan: Option<Scan>}

impl Scanner {
	pub fn new() -> Self {Self::default()}
	/// Takes the next bytes of the connection, as they arrive. The answer is final once it is `Forward` or `Line`: later bytes are not looked at, and belong to the decoy origin or to the request head.
	pub fn feed(&mut self, bytes: &[u8]) -> Scan {
		for byte in bytes {
			if self.scan.is_some() {break}
			let prefix: &[u8] = if self.post {b"POST /"} else {b"GET /"};
			let fits = match self.read {
				0 => {
					self.post = *byte == b'P';
					matches!(byte, b'G' | b'P')
				}
				at if at < prefix.len() => *byte == prefix[at],
				_ if self.ending > 0 => *byte == ENDING[self.ending],
				_ => matches!(byte, b' ' | b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@' | b'/' | b'?' | b'%'),
			};
			if self.read >= prefix.len() && (self.ending > 0 || *byte == b' ') {self.ending += 1}
			self.read += 1;
			self.scan = if !fits {Some(Scan::Forward)} else if self.ending == ENDING.len() {Some(Scan::Line(self.read))} else if self.read >= LINE_MAX {Some(Scan::Forward)} else {None};
		}
		self.scan.unwrap_or(Scan::More)
	}
}

/// A complete request line that passed the test.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Line<'a> {
	pub method: Method,
	/// The request target up to its first `?`. It starts with `/`.
	pub path: &'a [u8],
	/// What follows the first `?`: the candidate token, or the session id and request number of `fronted`. Nothing here says it is either.
	pub query: Option<&'a [u8]>,
}

impl<'a> Line<'a> {
	/// The parts of a request line, the line end included. `None` for bytes that `Scanner` would not call a complete line.
	pub fn parse(line: &'a [u8]) -> Option<Self> {
		if Scanner::new().feed(line) != Scan::Line(line.len()) {return None}
		let (method, skip) = if line[0] == b'P' {(Method::Post, 5)} else {(Method::Get, 4)};
		let mut parts = line[skip..line.len() - ENDING.len()].splitn(2, |byte| *byte == b'?');
		Some(Self {method, path: parts.next()?, query: parts.next()})
	}
	/// Whether the path is this configured path, compared in constant time over its whole length: "Stopping at the first difference from the path would show a prober, by timing, how much of the path it had guessed." A path of another length is told apart at once, so the length of a configured path can show. A listener with more than one path uses `path_among`.
	pub fn path_is(&self, path: &[u8]) -> bool {self.path.ct_eq(path).into()}
	/// Which of the listener's configured paths the path is, by its place in `paths`, the first if two are equal. Every path is compared, each as `path_is` compares, whatever the ones before it gave: an `any` over `path_is` would stop at the first match and show which path it was.
	pub fn path_among(&self, paths: &[&[u8]]) -> Option<usize> {paths.iter().enumerate().fold(None, |found, (index, path)| if bool::from(self.path.ct_eq(path)) & found.is_none() {Some(index)} else {found})}
}

// The path is known to subscribers only and the query is a token or a session id, so neither is printed.
impl fmt::Debug for Line<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Line({:?}, ..)", self.method)}
}

#[cfg(test)]
mod tests {
	use super::*;

	// What a scanner says after `bytes`, and how many of them it had read when it said so: fed one byte at a time, as the bytes of a connection arrive.
	fn scan(bytes: &[u8]) -> (Scan, usize) {
		let mut scanner = Scanner::new();
		for (index, byte) in bytes.iter().enumerate() {
			let scan = scanner.feed(&[*byte]);
			if scan != Scan::More {return (scan, index + 1)}
		}
		(Scan::More, bytes.len())
	}

	#[test]
	fn a_line_is_a_candidate_while_it_can_still_become_a_request() {
		assert_eq!(scan(b"GET /a HTTP/1.1\r\n"), (Scan::Line(17), 17));
		assert_eq!(scan(b"POST /a?b HTTP/1.1\r\nHost: x\r\n\r\n"), (Scan::Line(20), 20));
		assert_eq!(scan(b"GET / HTTP/1.1\r\n"), (Scan::Line(16), 16));
		// Every prefix of a candidate is one, and nothing is decided before the last byte.
		for size in 0..17 {assert_eq!(scan(&b"GET /a HTTP/1.1\r\n"[..size]), (Scan::More, size))}
		// "Forward at once when a byte arrives that makes the line no candidate": at that byte, not at the end of the line.
		for (bytes, at) in [(&b"HEAD / HTTP/1.1\r\n"[..], 1), (b"GEX / HTTP/1.1\r\n", 3), (b"get / HTTP/1.1\r\n", 1), (b"POST/ HTTP/1.1\r\n", 5), (b"PUT / HTTP/1.1\r\n", 2), (b"GET a HTTP/1.1\r\n", 5), (b"GET  / HTTP/1.1\r\n", 5), (b"GET /a b HTTP/1.1\r\n", 8), (b"GET /a HTTP/1.0\r\n", 15), (b"GET /a HTTP/2\r\n", 13), (b"GET /a http/1.1\r\n", 8), (b"GET /a HTTP/1.1\n", 16), (b"GET /a HTTP/1.1\r\r\n", 17), (b"GET /a HTTP/1.1 \r\n", 16), (b"GET /a\r\n", 7), (b"GET /a\x00 HTTP/1.1\r\n", 7), (b"GET /\xc3\xa9 HTTP/1.1\r\n", 6), (b"GET /a\" HTTP/1.1\r\n", 7), (b"GET /a#b HTTP/1.1\r\n", 7), (b"GET /[a] HTTP/1.1\r\n", 6), (b"\x16\x03\x01\x02\x00", 1), (b"\r\nGET / HTTP/1.1\r\n", 1)] {assert_eq!(scan(bytes), (Scan::Forward, at), "{:?}", String::from_utf8_lossy(bytes))}
		// Every character RFC 3986 allows in a path and a query, and the characters of a token and of a session id with its number.
		assert_eq!(scan(b"GET /AZaz09-._~!$&'()*+,;=:@/?% HTTP/1.1\r\n").0, Scan::Line(42));
	}

	#[test]
	fn the_line_end_counts_toward_4096_bytes() {
		let line = |size: usize| [&b"GET /"[..], &vec![b'a'; size - 16], b" HTTP/1.1\r\n"].concat();
		assert_eq!(scan(&line(LINE_MAX)), (Scan::Line(LINE_MAX), LINE_MAX));
		// One byte longer: the limit is reached at byte 4,096, before the line could end.
		assert_eq!(scan(&line(LINE_MAX + 1)), (Scan::Forward, LINE_MAX));
		assert_eq!(scan(&[&b"GET /"[..], &vec![b'a'; 9000]].concat()), (Scan::Forward, LINE_MAX));
	}

	#[test]
	fn an_answer_is_final_and_does_not_depend_on_the_pieces() {
		let bytes = b"POST /path?query HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
		for size in 1..bytes.len() {
			let mut scanner = Scanner::new();
			let scans: Vec<Scan> = bytes.chunks(size).map(|piece| scanner.feed(piece)).collect();
			assert!(scans.iter().all(|scan| [Scan::More, Scan::Line(27)].contains(scan)) && scans.last() == Some(&Scan::Line(27)), "pieces of {size}");
			assert_eq!((scanner.feed(b"\x00"), scanner.feed(&[])), (Scan::Line(27), Scan::Line(27)));
		}
		let mut scanner = Scanner::new();
		assert_eq!((scanner.feed(b"GET /a\x00"), scanner.feed(b" HTTP/1.1\r\n"), scanner.feed(&[])), (Scan::Forward, Scan::Forward, Scan::Forward));
		assert_eq!(Scanner::new().feed(&[]), Scan::More);
	}

	#[test]
	fn the_parts_of_a_line() {
		let line = Line::parse(b"GET /some/path?abc.7 HTTP/1.1\r\n").unwrap();
		assert_eq!((line.method, line.path, line.query), (Method::Get, &b"/some/path"[..], Some(&b"abc.7"[..])));
		assert_eq!(Line::parse(b"POST /p HTTP/1.1\r\n"), Some(Line {method: Method::Post, path: b"/p", query: None}));
		// An empty query is there, and a second `?` belongs to the query.
		assert_eq!(Line::parse(b"GET /p? HTTP/1.1\r\n").unwrap().query, Some(&b""[..]));
		assert_eq!(Line::parse(b"GET /p?a?b HTTP/1.1\r\n").map(|line| (line.path, line.query)), Some((&b"/p"[..], Some(&b"a?b"[..]))));
		assert_eq!(Line::parse(b"GET /?x HTTP/1.1\r\n").map(|line| (line.path, line.query)), Some((&b"/"[..], Some(&b"x"[..]))));
		// Only a whole line, and nothing after it.
		for bytes in [&b""[..], b"GET /p HTTP/1.1\r", b"GET /p HTTP/1.1\r\nHost: x\r\n", b"GET /p\x00 HTTP/1.1\r\n", b"HEAD /p HTTP/1.1\r\n"] {assert_eq!(Line::parse(bytes), None)}
	}

	#[test]
	fn a_path_is_compared_whole_and_not_printed() {
		let line = Line::parse(b"GET /a-path-of-a-transport?token HTTP/1.1\r\n").unwrap();
		assert!(line.path_is(b"/a-path-of-a-transport"));
		for other in [&b"/a-path-of-a-transporT"[..], b"/A-path-of-a-transport", b"/a-path-of-a-transpor", b"/a-path-of-a-transport/", b"", b"/a-path-of-a-transport?token"] {assert!(!line.path_is(other))}
		assert_eq!(format!("{line:?}"), "Line(Get, ..)");
		assert_eq!(line.path_among(&[b"/another-path", b"/a-path-of-a-transport", b"/a-path-of-a-transport"]), Some(1));
		assert_eq!((line.path_among(&[b"/another-path", b"/a-path-of-a-transpor"]), line.path_among(&[])), (None, None));
	}
}
