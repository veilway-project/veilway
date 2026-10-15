//! What the client reads of HTTP/1.1: the head of the answer to an upgrade request, and the answer to a `fronted` request (transports page, "WebSocket session", "`fronted`", "Refusals and clocks").
//!
//! The readers are pure and are what the fuzz targets drive. They read strictly and inside fixed bounds: a head ends within 16,384 bytes or is none, a line end is CR LF, and a `fronted` answer has one `Content-Length` of plain digits and exactly that many bytes behind its head.
//! Of an answer the client trusts its status, `Sec-WebSocket-Accept` and its length, and `Date` on a pinned connection. "It ignores the cookie and every other header field of the answer, stores none of them, and never sends the cookie back."
use crate::Answer;
use std::ops::Range;
use tokio::io::{AsyncRead, AsyncReadExt};
use veilway_proto::fronted::{BODY_MAX, BODY_MIN};
use veilway_proto::websocket;

/// The bound of an answer's head, the one the node keeps for the request head of a user. The page gives the client none of its own.
pub const HEAD_MAX: usize = 16_384;

/// The Chrome major version that `fingerprint.rs` imitates. Every header that names a version says this one.
pub(crate) const CHROME: &str = "155";

/// The client's own platform in a Chrome request: the part of the User-Agent in brackets, the client hint for the platform, the mobile hint, and the User-Agent's word for a phone. Chosen by the compile target, so a build claims only its own platform's browser.
#[cfg(target_os = "windows")]
pub(crate) const PLATFORM: (&str, &str, &str, &str) = ("Windows NT 10.0; Win64; x64", "\"Windows\"", "?0", "");
#[cfg(target_os = "macos")]
pub(crate) const PLATFORM: (&str, &str, &str, &str) = ("Macintosh; Intel Mac OS X 10_15_7", "\"macOS\"", "?0", "");
#[cfg(target_os = "android")]
pub(crate) const PLATFORM: (&str, &str, &str, &str) = ("Linux; Android 10; K", "\"Android\"", "?1", "Mobile ");
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "android")))]
pub(crate) const PLATFORM: (&str, &str, &str, &str) = ("X11; Linux x86_64", "\"Linux\"", "?0", "");

/// The User-Agent line of a Chrome request on this platform.
pub(crate) fn user_agent() -> String {
	let (agent, _, _, mobile) = PLATFORM;
	format!("User-Agent: Mozilla/5.0 ({agent}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME}.0.0.0 {mobile}Safari/537.36\r\n")
}

/// The head of an answer: its status and its field lines, which are read where one is asked for.
#[derive(Debug, Clone, Copy)]
pub struct Head<'a> {
	pub status: u16,
	/// Whether the status line says HTTP/1.1. A front's own error may say 1.0, and is a refusal all the same.
	pub current: bool,
	fields: &'a [u8],
}

/// Where the first head in `bytes` ends: behind its empty line.
pub fn end(bytes: &[u8]) -> Option<usize> {bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4)}

/// Reads a head that ends with its empty line. None for what is no answer of HTTP/1: a status line that is not `HTTP/1.x`, a blank and three digits, a line end that is no CR LF, a NUL, or a field line without a name.
pub fn head(bytes: &[u8]) -> Option<Head<'_>> {
	let inner = bytes.strip_suffix(b"\r\n\r\n").filter(|_| bytes.len() <= HEAD_MAX && end(bytes) == Some(bytes.len()))?;
	if !inner.iter().enumerate().all(|(at, byte)| match byte {
		b'\r' => inner.get(at + 1) == Some(&b'\n'),
		b'\n' => at > 0 && inner[at - 1] == b'\r',
		0 => false,
		_ => true,
	}) {return None}
	let (line, fields) = inner.split_at(inner.iter().position(|byte| *byte == b'\r').unwrap_or(inner.len()));
	let [b'H', b'T', b'T', b'P', b'/', b'1', b'.', minor @ (b'0' | b'1'), b' ', digits @ ..] = line else {return None};
	let (code, rest) = digits.split_first_chunk::<3>()?;
	if !code.iter().all(u8::is_ascii_digit) || !matches!(rest.first(), None | Some(b' ')) {return None}
	let head = Head {status: code.iter().fold(0, |status, digit| status * 10 + u16::from(digit - b'0')), current: *minor == b'1', fields};
	head.lines().all(|line| line.iter().position(|byte| *byte == b':').is_some_and(|colon| colon > 0 && line[..colon].iter().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)))).then_some(head)
}

impl<'a> Head<'a> {
	fn lines(&self) -> impl Iterator<Item = &'a [u8]> {self.fields.split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line)).filter(|line| !line.is_empty())}
	/// The values of every field of this name, without the blanks around them.
	pub fn values(&self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
		self.lines().filter_map(move |line| {
			let (found, mut value) = line.split_at(line.iter().position(|byte| *byte == b':')?);
			value = &value[1..];
			while let [b' ' | b'\t', rest @ ..] | [rest @ .., b' ' | b'\t'] = value {value = rest}
			found.eq_ignore_ascii_case(name.as_bytes()).then_some(value)
		})
	}
	/// The value of a field that stands in the head exactly once.
	pub fn one(&self, name: &'a str) -> Option<&'a [u8]> {
		let mut values = self.values(name);
		values.next().filter(|_| values.next().is_none())
	}
	/// Whether the answer says its connection is over with it: a `Connection` field with `close` among its values.
	pub fn closes(&self) -> bool {self.values("connection").flat_map(|value| value.split(|byte| *byte == b',')).any(|option| option.trim_ascii().eq_ignore_ascii_case(b"close"))}
	/// `Date` in Unix seconds, when the head has exactly one and it is written in the one format a server writes (RFC 9110, IMF-fixdate). The caller reads it on a pinned connection alone.
	pub fn date(&self) -> Option<u64> {self.one("date").and_then(date)}
	/// Whether this is the answer that opens a WebSocket session for the request with `key`: "The client checks `Sec-WebSocket-Accept` as RFC 6455 requires and ends the attempt if it is wrong."
	pub fn upgraded(&self, key: &[u8]) -> Result<(), Answer> {
		if self.status != 101 || !self.current {return Err(Answer::Status(self.status))}
		// The request offers Chrome's `permessage-deflate`, which the client cannot read: an answer that takes up any extension ends the attempt.
		if self.one("sec-websocket-accept") == Some(websocket::accept(key).as_bytes()) && self.values("sec-websocket-extensions").next().is_none() {Ok(())} else {Err(Answer::Accept)}
	}
}

/// Reads `Sun, 06 Nov 1994 08:49:37 GMT` as Unix seconds. None for every other writing, for a date that does not exist and for one before 1970.
pub fn date(text: &[u8]) -> Option<u64> {
	let [_, _, _, b',', b' ', d1, d2, b' ', m1, m2, m3, b' ', y1, y2, y3, y4, b' ', h1, h2, b':', n1, n2, b':', s1, s2, b' ', b'G', b'M', b'T'] = text else {return None};
	let number = |digits: &[&u8]| digits.iter().try_fold(0u64, |number, digit| digit.is_ascii_digit().then(|| number * 10 + u64::from(**digit - b'0')));
	let (day, year, hour, minute, second) = (number(&[d1, d2])?, number(&[y1, y2, y3, y4])?, number(&[h1, h2])?, number(&[n1, n2])?, number(&[s1, s2])?);
	let month = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"].iter().position(|name| **name == [*m1, *m2, *m3])? as u64 + 1;
	let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
	if year < 1970 || day == 0 || day > [31, if leap {29} else {28}, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month as usize - 1] || hour > 23 || minute > 59 || second > 59 {return None}
	// Days from 1970 to a civil date, counted from the first of March so that the leap day is the last of its year.
	let (shifted, turned) = (if month < 3 {year - 1} else {year}, (month + 9) % 12);
	let days = shifted * 365 + shifted / 4 - shifted / 100 + shifted / 400 + (turned * 153 + 2) / 5 + day - 1 - 719_468;
	Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Reads the answer to a `fronted` request from the bytes that came so far: `Ok(None)` while it is not all there, and then where its body lies. An answer that is no `200` is `Status`. A `200` with a `Transfer-Encoding`, with no `Content-Length` or more than one, with a length that is not 18 to 65,536 in plain digits, or with a byte behind its body is `Body`: "exactly one `Content-Length`", and one request is in flight, so nothing follows an answer.
pub fn response(bytes: &[u8]) -> Result<Option<Range<usize>>, Answer> {
	let Some(whole) = whole(bytes)? else {return Ok(None)};
	if bytes.len() > whole {return Err(Answer::Body)}
	Ok(end(bytes).filter(|_| bytes.len() == whole).map(|end| end..whole))
}

/// How many bytes the answer to a `fronted` request has in all, head and body, once its head is there: `Ok(None)` before that. The verdicts on the head are those of `response`. A reader that knows this number need not look at the answer again before that many bytes came.
pub fn whole(bytes: &[u8]) -> Result<Option<usize>, Answer> {
	let Some(end) = end(bytes).filter(|end| *end <= HEAD_MAX) else {return if bytes.len() >= HEAD_MAX {Err(Answer::NotHttp)} else {Ok(None)}};
	let head = head(&bytes[..end]).ok_or(Answer::NotHttp)?;
	if head.status != 200 || !head.current {return Err(Answer::Status(head.status))}
	let length = head.one("content-length").filter(|digits| (1..=5).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit) && head.values("transfer-encoding").next().is_none() && head.values("content-encoding").all(|coding| coding.eq_ignore_ascii_case(b"identity"))).ok_or(Answer::Body)?;
	let length = length.iter().fold(0usize, |length, digit| length * 10 + usize::from(digit - b'0'));
	if (BODY_MIN..=BODY_MAX).contains(&length) {Ok(Some(end + length))} else {Err(Answer::Body)}
}

/// Whether `bytes`, to which `count` bytes were just added, now hold the empty line that ends a head. Only the new bytes and the three before them are looked at, so a head that arrives byte by byte is searched once and not once for each byte.
pub(crate) fn headed(bytes: &[u8], count: usize) -> bool {bytes[bytes.len().saturating_sub(count + 3)..].windows(4).any(|window| window == b"\r\n\r\n")}

/// How reading an answer ended before the answer was whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
	/// The peer said so, inside the TLS session: an answer that is none, or a `close_notify`.
	Said(Answer),
	/// The connection was reset, or ended without a `close_notify`. Nothing vouches for who did that.
	Cut,
}

/// Reads from `io` into `buf` until `buf` holds a head, and gives where it ends. A connection that is closed in order first is `Closed` when nothing came and `NotHttp` otherwise, and so is a head that does not end inside its bound. One that ends any other way is `Cut`. The caller sets the time.
pub(crate) async fn answer(io: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>) -> Result<usize, Stop> {
	let (mut read, mut found) = ([0u8; 4096], headed(buf, buf.len()));
	loop {
		if let Some(end) = end(buf).filter(|_| found) {return Ok(end)}
		if buf.len() >= HEAD_MAX {return Err(Stop::Said(Answer::NotHttp))}
		match io.read(&mut read[..(HEAD_MAX - buf.len()).min(4096)]).await {
			Ok(0) => return Err(Stop::Said(if buf.is_empty() {Answer::Closed} else {Answer::NotHttp})),
			Ok(count) => {
				buf.extend_from_slice(&read[..count]);
				found = headed(buf, count);
			}
			Err(_) => return Err(Stop::Cut),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY: &[u8] = b"dGhlIHNhbXBsZSBub25jZQ==";

	#[test]
	fn the_upgrade_answer_is_its_status_and_its_accept_value() {
		let good = b"HTTP/1.1 101 Switching Protocols\r\nServer: decoy/1.0\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSet-Cookie: sid=abc\r\n\r\n";
		let head = head(good).unwrap();
		assert_eq!((head.status, head.upgraded(KEY), head.date()), (101, Ok(()), Some(784_111_777)));
		// The name of a field in any case, blanks around its value, and no other field asked about.
		assert_eq!(super::head(b"HTTP/1.1 101 \r\nsec-websocket-ACCEPT:\t s3pPLMBiTxaQ9kYGzzhZRbK+xOo= \r\n\r\n").unwrap().upgraded(KEY), Ok(()));
		assert_eq!(super::head(b"HTTP/1.1 101\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").unwrap().upgraded(KEY), Ok(()));
		// A wrong value, none, two, and the right value under another status or another version.
		for (answer, wanted) in [(&b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOO=\r\n\r\n"[..], Answer::Accept), (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", Answer::Accept), (b"HTTP/1.1 101 OK\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", Answer::Accept), (b"HTTP/1.1 200 OK\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", Answer::Status(200)), (b"HTTP/1.0 101 OK\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", Answer::Status(101)), (b"HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n", Answer::Status(404))] {assert_eq!(super::head(answer).unwrap().upgraded(KEY), Err(wanted), "{}", String::from_utf8_lossy(answer))}
	}

	#[test]
	fn what_is_no_head_of_http_is_none() {
		for bytes in [&b""[..], b"\r\n\r\n", b"HTTP/1.1 101 OK\r\n", b"HTTP/2 200\r\n\r\n", b"HTTP/1.2 200 OK\r\n\r\n", b"http/1.1 200 OK\r\n\r\n", b"HTTP/1.1 20 OK\r\n\r\n", b"HTTP/1.1 2000 OK\r\n\r\n", b"HTTP/1.1 20a OK\r\n\r\n", b"HTTP/1.1  200 OK\r\n\r\n", b"HTTP/1.1 200 OK\nA: b\r\n\r\n", b"HTTP/1.1 200 OK\r\nA: b\rc\r\n\r\n", b"HTTP/1.1 200 OK\r\nA: \0\r\n\r\n", b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n", b"HTTP/1.1 200 OK\r\n: b\r\n\r\n", b"HTTP/1.1 200 OK\r\nA : b\r\n\r\n", b"HTTP/1.1 200 OK\r\n folded\r\n\r\n", b"\x16\x03\x01\x02\x00\r\n\r\n"] {assert!(head(bytes).is_none(), "{:?}", String::from_utf8_lossy(bytes))}
		assert!(head(&[&b"HTTP/1.1 200 OK\r\nA: "[..], &vec![b'a'; HEAD_MAX], b"\r\n\r\n"].concat()).is_none());
		assert_eq!(head(b"HTTP/1.0 503 Service Unavailable\r\n\r\n").map(|head| (head.status, head.current)), Some((503, false)));
	}

	#[test]
	fn a_date_is_read_in_one_format() {
		assert_eq!(date(b"Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
		assert_eq!(date(b"Tue, 14 Nov 2023 22:13:20 GMT"), Some(1_700_000_000));
		assert_eq!(date(b"Thu, 29 Feb 2024 23:59:59 GMT"), Some(1_709_251_199));
		assert_eq!(date(b"Fri, 01 Mar 2024 00:00:00 GMT"), Some(1_709_251_200));
		assert_eq!(date(b"Fri, 31 Dec 2100 23:59:59 GMT"), Some(4_133_980_799));
		for text in [&b""[..], b"Tue, 14 Nov 2023 22:13:20 UTC", b"Tue, 14 Nov 2023 22:13:20 GMT ", b"Tuesday, 14-Nov-23 22:13:20 GMT", b"Tue Nov 14 22:13:20 2023", b"Tue, 14 Nov 2023 24:13:20 GMT", b"Tue, 14 Nov 2023 22:60:20 GMT", b"Tue, 14 Nov 2023 22:13:60 GMT", b"Tue, 31 Nov 2023 22:13:20 GMT", b"Wed, 29 Feb 2023 00:00:00 GMT", b"Tue, 00 Nov 2023 22:13:20 GMT", b"Tue, 14 nov 2023 22:13:20 GMT", b"Tue, 14 Nov 1969 22:13:20 GMT", b"Tue, +4 Nov 2023 22:13:20 GMT", b"Tue, 14 Nov 2023 22:13:2\xd9 GMT"] {assert_eq!(date(text), None, "{:?}", String::from_utf8_lossy(text))}
		// Two `Date` fields are no date.
		assert_eq!(head(b"HTTP/1.1 404 Not Found\r\nDate: Tue, 14 Nov 2023 22:13:20 GMT\r\ndate: Tue, 14 Nov 2023 22:13:20 GMT\r\n\r\n").unwrap().date(), None);
	}

	#[test]
	fn a_fronted_answer_is_a_200_with_one_length_and_exactly_that_many_bytes() {
		let answer = |head: &str, body: usize| [head.as_bytes(), &vec![7; body]].concat();
		let good = answer("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 18\r\n\r\n", 18);
		assert_eq!(response(&good), Ok(Some(good.len() - 18..good.len())));
		for cut in 0..good.len() {assert_eq!(response(&good[..cut]), Ok(None), "{cut} bytes")}
		assert_eq!(response(&answer("HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n", 65_536)).map(|body| body.map(|body| body.len())), Ok(Some(65_536)));
		// One byte behind the body, and every way to say a length that is none.
		assert_eq!(response(&[&good[..], &[0]].concat()), Err(Answer::Body));
		for head in ["HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nContent-Length: 18\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: +18\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0x12\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 000018\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 18, 18\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n"] {assert_eq!(response(&answer(head, 18)), Err(Answer::Body), "{head:?}")}
		assert_eq!(response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\nnothing here\n"), Err(Answer::Status(404)));
		assert_eq!(response(b"HTTP/1.0 200 OK\r\nContent-Length: 18\r\n\r\n"), Err(Answer::Status(200)));
		assert_eq!(response(b"HTTP/1.1 100 Continue\r\n\r\n"), Err(Answer::Status(100)));
		assert_eq!(response(b"garbage\r\n\r\n"), Err(Answer::NotHttp));
		// A head that never ends is given up at its bound, and not one byte later.
		assert_eq!(response(&vec![b'a'; HEAD_MAX - 1]), Ok(None));
		assert_eq!(response(&vec![b'a'; HEAD_MAX]), Err(Answer::NotHttp));
		assert_eq!(response(&[&b"HTTP/1.1 200 OK\r\nA: "[..], &vec![b'a'; HEAD_MAX], b"\r\n\r\n"].concat()), Err(Answer::NotHttp));
	}
}
