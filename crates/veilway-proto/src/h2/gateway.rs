//! What the node does when it is an HTTP/2 server toward a stranger and an HTTP/1.1 client toward the decoy origin (http2 page, "Accept state machine on HTTP/2", item 6, and "Security considerations", "Gateway translation").
//! A request is turned into HTTP/1.1 text only from fields that were checked, and everything RFC 9113 calls malformed (sections 8.1.2, 8.2 and 8.3) is refused before a byte goes upstream. The origin's answer is turned back the same way. Nothing here does IO.
use super::Fields;
use crate::http::{field, framing, lines, token, Framing, Unsure};

/// Why a request is not passed on. The stream is reset with PROTOCOL_ERROR whatever the reason, and the reason is for the tests and the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

/// A request the origin may be sent: its head in HTTP/1.1, and what the body behind it must be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
	/// The request line and the fields, up to and with the empty line.
	pub head: Vec<u8>,
	/// The one `content-length` the stream carried, as a number. The DATA bytes are counted against it.
	pub length: Option<u64>,
	/// No length and a body that may follow: the body goes to the origin in chunks the node sizes itself.
	pub chunked: bool,
	/// An extended CONNECT for `websocket`, sent as an HTTP/1.1 upgrade with a key the node drew.
	pub upgrade: bool,
	/// The method is `HEAD`, so the answer has no body whatever its head says.
	pub bodiless: bool,
}

// Fields RFC 9113 (section 8.2.2) forbids on HTTP/2, which a request must not carry and an answer must lose.
const CONNECTION: [&[u8]; 5] = [b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"];
const LENGTH_DIGITS: usize = 19;

// `host` or `host:port` with no userinfo and no blank: a registered name, an IPv4 address or a bracketed IPv6 address, and a port of up to five digits.
fn authority(value: &[u8]) -> bool {
	if value.is_empty() || value.len() > 255 || !value.iter().all(|byte| byte.is_ascii_alphanumeric() || b"-._~%:[]".contains(byte)) {return false}
	let port = if value[0] == b'[' {
		let Some(close) = value.iter().position(|byte| *byte == b']') else {return false};
		match &value[close + 1..] {
			[] => return close > 1,
			[b':', port @ ..] => port,
			_ => return false,
		}
	} else {
		let mut parts = value.split(|byte| *byte == b':');
		let (host, port, more) = (parts.next(), parts.next(), parts.next());
		if more.is_some() || host.is_none_or(<[u8]>::is_empty) || value.contains(&b'[') || value.contains(&b']') {return false}
		match port {
			None => return true,
			Some(port) => port,
		}
	};
	(1..=5).contains(&port.len()) && port.iter().all(u8::is_ascii_digit)
}

// A value holds no NUL, CR or LF, and does not begin or end with a blank (RFC 9113, section 8.2.1).
fn value_ok(value: &[u8]) -> bool {!value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) && !matches!(value.first(), Some(b' ' | b'\t')) && !matches!(value.last(), Some(b' ' | b'\t'))}

/// Turns a decoded header list into the request the origin is sent. `ended` says the HEADERS frame carried END_STREAM, and `key` is the `Sec-WebSocket-Key` the node drew for an extended CONNECT.
pub fn request(fields: &Fields, ended: bool, key: &str) -> Result<Request, Refusal> {
	let (mut method, mut scheme, mut path, mut host_of, mut protocol) = (None::<&[u8]>, None::<&[u8]>, None::<&[u8]>, None::<&[u8]>, None::<&[u8]>);
	let (mut regular, mut host, mut length, mut cookies, mut rest) = (false, None::<&[u8]>, None::<u64>, Vec::<&[u8]>::new(), Vec::<u8>::new());
	for (name, value) in fields {
		if name.first() == Some(&b':') {
			if regular {return Err(Refusal("a pseudo-header after a regular field"))}
			let slot = match name.as_slice() {
				b":method" => &mut method,
				b":scheme" => &mut scheme,
				b":path" => &mut path,
				b":authority" => &mut host_of,
				b":protocol" => &mut protocol,
				_ => return Err(Refusal("an unknown or response pseudo-header")),
			};
			if slot.replace(value).is_some() || !value_ok(value) {return Err(Refusal("a pseudo-header twice, or one with a bad value"))}
			continue;
		}
		regular = true;
		if name.is_empty() || !name.iter().all(|byte| token(*byte) && !byte.is_ascii_uppercase()) {return Err(Refusal("a field name that is no lowercase token"))}
		if !value_ok(value) {return Err(Refusal("a field value with a line end, a NUL or an edge blank"))}
		match name.as_slice() {
			b"host" => if host.replace(value).is_some() {return Err(Refusal("two host fields"))},
			b"te" => if value != b"trailers" {return Err(Refusal("te other than trailers"))},
			b"cookie" => cookies.push(value),
			b"content-length" => {
				if length.is_some() || value.is_empty() || value.len() > LENGTH_DIGITS || !value.iter().all(u8::is_ascii_digit) {return Err(Refusal("a content-length that is not one number"))}
				length = Some(value.iter().fold(0u64, |length, digit| length * 10 + u64::from(digit - b'0'))).filter(|length| *length <= i64::MAX as u64);
				if length.is_none() {return Err(Refusal("a content-length above 2^63 - 1"))}
			}
			// The node draws its own key, and a client that sent one is not speaking RFC 8441.
			b"sec-websocket-key" | b"sec-websocket-accept" => return Err(Refusal("a websocket key on HTTP/2")),
			other if CONNECTION.contains(&other) => return Err(Refusal("a connection-specific field")),
			_ => {
				rest.extend_from_slice(name);
				rest.extend_from_slice(b": ");
				rest.extend_from_slice(value);
				rest.extend_from_slice(b"\r\n");
			}
		}
	}
	let (Some(method), Some(scheme), Some(path), Some(host_of)) = (method, scheme, path, host_of) else {return Err(Refusal("a missing pseudo-header"))};
	if method.is_empty() || !method.iter().all(|byte| token(*byte)) {return Err(Refusal("a method that is no token"))}
	if scheme.is_empty() || !scheme.iter().all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(byte)) {return Err(Refusal("a bad scheme"))}
	if !authority(host_of) || host.is_some_and(|host| !host.eq_ignore_ascii_case(host_of)) {return Err(Refusal("an authority that is bad or differs from host"))}
	let upgrade = match (method, protocol) {
		(b"CONNECT", None) => return Err(Refusal("a plain CONNECT")),
		(b"CONNECT", Some(b"websocket")) => true,
		(_, None) => false,
		_ => return Err(Refusal("a protocol other than websocket, or on another method")),
	};
	if path.is_empty() || !path.iter().all(|byte| (0x21..=0x7e).contains(byte)) || (path[0] != b'/' && (path != b"*" || method != b"OPTIONS")) {return Err(Refusal("a bad path"))}
	if upgrade && ended {return Err(Refusal("an extended CONNECT with no stream behind it"))}
	if ended && length.is_some_and(|length| length > 0) {return Err(Refusal("a content-length and no body"))}
	let mut head = Vec::with_capacity(rest.len() + path.len() + 128);
	head.extend_from_slice(if upgrade {b"GET"} else {method});
	head.extend_from_slice(b" ");
	head.extend_from_slice(path);
	head.extend_from_slice(b" HTTP/1.1\r\nHost: ");
	head.extend_from_slice(host_of);
	head.extend_from_slice(b"\r\n");
	head.extend_from_slice(&rest);
	if !cookies.is_empty() {head.extend_from_slice(&[b"cookie: ".as_slice(), &cookies.join(&b"; "[..]), b"\r\n"].concat())}
	let chunked = length.is_none() && !ended && !upgrade;
	if let Some(length) = length {head.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes())} else if chunked {head.extend_from_slice(b"Transfer-Encoding: chunked\r\n")}
	if upgrade {head.extend_from_slice(format!("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {key}\r\n").as_bytes())} else {head.extend_from_slice(b"Connection: close\r\n")}
	head.extend_from_slice(b"\r\n");
	Ok(Request {head, length, chunked, upgrade, bodiless: method == b"HEAD"})
}

/// The origin's answer as HTTP/2 has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
	pub status: u16,
	/// Names in lowercase, and without the fields HTTP/2 forbids.
	pub fields: Fields,
	/// Where the body ends. An interim answer (1xx but 101) has none and is skipped by the caller.
	pub framing: Framing,
}

/// Reads the head of an answer, which ends with its empty line, as strictly as `http::Response` reads it, and turns it into the fields of a HEADERS frame. A `101` for an upgrade the node asked for becomes `200`, loses its `sec-websocket-accept` (RFC 8441, section 5) and has the connection itself as its body. `None` for a head that is not read: a bad status line, a field that is no field, two ways of saying the length, or a `101` nobody asked for.
pub fn response(head: &[u8], bodiless: bool, upgraded: bool) -> Option<Answer> {
	let mut lines = lines(head)?;
	let status = lines.next()?;
	let rest = status.strip_prefix(b"HTTP/1.1 ").or_else(|| status.strip_prefix(b"HTTP/1.0 ")).filter(|rest| rest.len() >= 3 && rest[..3].iter().all(u8::is_ascii_digit) && matches!(rest.get(3), None | Some(b' ')))?;
	let code = rest[..3].iter().fold(0u16, |code, digit| code * 10 + u16::from(digit - b'0'));
	let all: Vec<&[u8]> = lines.collect();
	let said = framing(all.iter().copied())?;
	if code == 101 && !upgraded {return None}
	let mut fields = Fields::new();
	for line in &all {
		let (name, value) = field(line)?;
		let name = name.to_ascii_lowercase();
		if CONNECTION.contains(&name.as_slice()) || (code == 101 && matches!(name.as_slice(), b"sec-websocket-accept" | b"content-length")) {continue}
		fields.push((name, value.to_vec()));
	}
	let framing = match (code, said) {
		(101, _) => Framing::Close,
		(100..=199 | 204 | 304, _) => Framing::None,
		_ if bodiless => Framing::None,
		(_, (Some(length), _)) => Framing::Length(length),
		(_, (None, true)) => Framing::Chunked,
		(_, (None, false)) => Framing::Close,
	};
	Some(Answer {status: if code == 101 {200} else {code}, fields, framing})
}

enum Step {Size, Extension, SizeLf, Data(u64), DataCr, DataLf, Trailer(usize), TrailerLf(bool), Done}

/// The body of a chunked answer, read as `http::Body` reads it, with the data handed out: the chunk sizes, their extensions and the trailer are taken off and dropped. A chunk size of more than 16 digits, a line end that is no CR LF and a trailer over 16,384 bytes are refused.
pub struct Chunked {step: Step, size: u64, digits: u8, trailer: usize}

impl Chunked {
	pub fn new() -> Chunked {Chunked {step: Step::Size, size: 0, digits: 0, trailer: 0}}
	/// Takes the next bytes, appends the data in them to `out`, and says how many bytes were used and whether the body ended in them. Bytes after the end are not used.
	pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<u8>) -> Result<(usize, bool), Unsure> {
		let mut at = 0;
		while at < bytes.len() {
			let byte = bytes[at];
			match self.step {
				Step::Done => break,
				Step::Data(left) => {
					let take = (left.min((bytes.len() - at) as u64)) as usize;
					out.extend_from_slice(&bytes[at..at + take]);
					at += take;
					self.step = if left == take as u64 {Step::DataCr} else {Step::Data(left - take as u64)};
					continue;
				}
				Step::Size => match byte {
					b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' if self.digits < 16 => {
						self.size = self.size << 4 | u64::from((byte as char).to_digit(16).unwrap_or(0));
						self.digits += 1;
					}
					b';' if self.digits > 0 => self.step = Step::Extension,
					b'\r' if self.digits > 0 => self.step = Step::SizeLf,
					_ => return Err(Unsure),
				},
				Step::Extension => match byte {
					b'\r' => self.step = Step::SizeLf,
					b'\n' | 0 => return Err(Unsure),
					_ => {}
				},
				Step::SizeLf if byte == b'\n' => {
					self.step = if self.size == 0 {Step::Trailer(0)} else {Step::Data(self.size)};
					(self.size, self.digits) = (0, 0);
				}
				Step::DataCr if byte == b'\r' => self.step = Step::DataLf,
				Step::DataLf if byte == b'\n' => self.step = Step::Size,
				Step::Trailer(line) => match byte {
					b'\r' => self.step = Step::TrailerLf(line == 0),
					b'\n' | 0 => return Err(Unsure),
					_ => {
						self.trailer += 1;
						if self.trailer > 16_384 {return Err(Unsure)}
						self.step = Step::Trailer(line + 1);
					}
				},
				Step::TrailerLf(empty) if byte == b'\n' => self.step = if empty {Step::Done} else {Step::Trailer(0)},
				_ => return Err(Unsure),
			}
			at += 1;
		}
		Ok((at, matches!(self.step, Step::Done)))
	}
}

impl Default for Chunked {
	fn default() -> Self {Self::new()}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn list(items: &[(&str, &str)]) -> Fields {items.iter().map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec())).collect()}

	fn get() -> Vec<(&'static str, &'static str)> {vec![(":method", "GET"), (":scheme", "https"), (":path", "/a?b=1"), (":authority", "site.example"), ("user-agent", "x"), ("accept", "*/*")]}

	fn with(extra: &[(&'static str, &'static str)]) -> Fields {list(&[get(), extra.to_vec()].concat())}

	#[test]
	fn a_plain_request_becomes_http_1_1_with_one_host_and_one_connection_close() {
		let request = request(&list(&get()), true, "k").unwrap();
		assert_eq!(String::from_utf8(request.head).unwrap(), "GET /a?b=1 HTTP/1.1\r\nHost: site.example\r\nuser-agent: x\r\naccept: */*\r\nConnection: close\r\n\r\n");
		assert_eq!((request.length, request.chunked, request.upgrade), (None, false, false));
	}

	#[test]
	fn the_framing_is_the_nodes_own() {
		let post = |extra: &[(&'static str, &'static str)], ended: bool| request(&list(&[vec![(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "a:8443")], extra.to_vec()].concat()), ended, "k");
		let text = |request: Request| String::from_utf8(request.head).unwrap();
		assert!(text(post(&[("content-length", "5")], false).unwrap()).contains("Content-Length: 5\r\nConnection: close"));
		assert!(text(post(&[], false).unwrap()).contains("Transfer-Encoding: chunked\r\nConnection: close"));
		assert!(!text(post(&[], true).unwrap()).contains("Transfer-Encoding"));
		assert!(text(post(&[("content-length", "0")], true).unwrap()).contains("Content-Length: 0\r\n"));
		assert_eq!(post(&[("content-length", "5")], true), Err(Refusal("a content-length and no body")));
		for length in ["", "-1", "+1", "0x5", "1 ", "9223372036854775808", "99999999999999999999"] {assert!(post(&[("content-length", length)], false).is_err(), "{length:?}")}
		assert!(post(&[("content-length", "1"), ("content-length", "1")], false).is_err());
	}

	#[test]
	fn cookies_are_joined_as_rfc_9113_says() {
		let request = request(&with(&[("cookie", "a=1"), ("cookie", "b=2")]), true, "k").unwrap();
		assert!(String::from_utf8(request.head).unwrap().contains("cookie: a=1; b=2\r\n"));
	}

	#[test]
	fn each_refused_field_and_pseudo_header_case_is_refused() {
		for bad in [
			with(&[("connection", "close")]), with(&[("keep-alive", "1")]), with(&[("proxy-connection", "x")]), with(&[("transfer-encoding", "chunked")]), with(&[("upgrade", "websocket")]), with(&[("te", "gzip")]),
			with(&[("host", "other.example")]), with(&[("host", "site.example"), ("host", "site.example")]), with(&[("X-Upper", "1")]), with(&[("bad name", "1")]), with(&[("", "1")]), with(&[("a", "x\r\nb: y")]), with(&[("a", "x\ny")]), with(&[("a", "x\0")]), with(&[("a", " x")]), with(&[("a", "x\t")]),
			with(&[("sec-websocket-key", "k")]), with(&[(":path", "/")]), with(&[(":status", "200")]),
			list(&[(":method", "GET"), (":scheme", "https"), (":path", "/")]), list(&[(":method", "GET"), (":scheme", "https"), (":authority", "a")]), list(&[(":scheme", "https"), (":path", "/"), (":authority", "a")]), list(&[(":method", "GET"), (":path", "/"), (":authority", "a")]),
			list(&[(":method", "GET"), (":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), (":bogus", "x")]),
			list(&[("x", "1"), (":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
			list(&[(":method", "CONNECT"), (":authority", "a:443")]), list(&[(":method", "CONNECT"), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
			list(&[(":method", "CONNECT"), (":protocol", "other"), (":scheme", "https"), (":path", "/"), (":authority", "a")]), list(&[(":method", "GET"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
			list(&[(":method", "G ET"), (":scheme", "https"), (":path", "/"), (":authority", "a")]), list(&[(":method", ""), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
			list(&[(":method", "GET"), (":scheme", "https"), (":path", ""), (":authority", "a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "a"), (":authority", "a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/a b"), (":authority", "a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/a\u{e9}"), (":authority", "a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/a\x01"), (":authority", "a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "*"), (":authority", "a")]),
			list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "u@a")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a b")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a:b")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a:1:2")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a:123456")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "[::1")]), list(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "[]")]),
		] {assert!(request(&bad, true, "k").is_err(), "{bad:?}")}
		assert!(request(&list(&[(":method", "OPTIONS"), (":scheme", "https"), (":path", "*"), (":authority", "[::1]:8443")]), true, "k").is_ok());
		assert!(request(&with(&[("te", "trailers"), ("host", "SITE.example")]), true, "k").is_ok());
	}

	#[test]
	fn an_extended_connect_for_websocket_is_a_get_upgrade_with_the_nodes_key() {
		let connect = list(&[(":method", "CONNECT"), (":protocol", "websocket"), (":scheme", "https"), (":path", "/ws"), (":authority", "a"), ("sec-websocket-version", "13"), ("origin", "https://a")]);
		let request = request(&connect, false, "S0VZ").unwrap();
		assert_eq!(String::from_utf8(request.head).unwrap(), "GET /ws HTTP/1.1\r\nHost: a\r\nsec-websocket-version: 13\r\norigin: https://a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: S0VZ\r\n\r\n");
		assert!(request.upgrade && !request.chunked);
		assert!(super::request(&connect, true, "S0VZ").is_err());
	}

	#[test]
	fn an_answer_loses_what_http_2_forbids_and_keeps_the_rest() {
		let answer = response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nKeep-Alive: timeout=5\r\nContent-Length: 5\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n", false, false).unwrap();
		assert_eq!((answer.status, answer.framing), (200, Framing::Length(5)));
		assert_eq!(answer.fields, list(&[("content-type", "text/html"), ("content-length", "5"), ("set-cookie", "a=1"), ("set-cookie", "b=2")]));
		assert_eq!(response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false, false).unwrap().framing, Framing::Chunked);
		assert_eq!(response(b"HTTP/1.1 200 OK\r\n\r\n", false, false).unwrap().framing, Framing::Close);
		assert_eq!(response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", true, false).unwrap().framing, Framing::None);
		assert_eq!(response(b"HTTP/1.1 304 Not Modified\r\n\r\n", false, false).unwrap().framing, Framing::None);
		assert_eq!(response(b"HTTP/1.1 100 Continue\r\n\r\n", false, false).unwrap().framing, Framing::None);
		for bad in ["HTTP/2 200 OK\r\n\r\n", "HTTP/1.1 20 OK\r\n\r\n", "HTTP/1.1 200 OK\n\r\n", "HTTP/1.1 200 OK\r\nBad Field: 1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", "HTTP/1.1 101 Switching\r\n\r\n"] {assert!(response(bad.as_bytes(), false, false).is_none(), "{bad:?}")}
		let upgraded = response(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\nServer: s\r\n\r\n", false, true).unwrap();
		assert_eq!((upgraded.status, upgraded.framing, upgraded.fields), (200, Framing::Close, list(&[("server", "s")])));
	}

	// The same bytes fed in pieces of every size give the same data and the same end.
	fn dechunk(bytes: &[u8]) -> Vec<Result<(Vec<u8>, usize, bool), Unsure>> {
		(1..=bytes.len()).map(|size| {
			let (mut body, mut out, mut used) = (Chunked::new(), Vec::new(), 0);
			for piece in bytes.chunks(size) {
				match body.feed(piece, &mut out) {
					Ok((count, true)) => return Ok((out, used + count, true)),
					Ok((count, false)) => used += count,
					Err(Unsure) => return Err(Unsure),
				}
			}
			Ok((out, used, false))
		}).collect()
	}

	#[test]
	fn a_chunked_body_is_unwrapped_the_same_way_in_pieces_of_every_size() {
		let whole = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
		for got in dechunk(&[&whole[..], b"GET /next"].concat()) {assert_eq!(got, Ok((b"hello world".to_vec(), whole.len(), true)))}
		for got in dechunk(b"0\r\n\r\n") {assert_eq!(got, Ok((Vec::new(), 5, true)))}
		for got in dechunk(b"3\r\nabc\r\n") {assert_eq!(got, Ok((b"abc".to_vec(), 8, false)))}
		for bad in [&b"x\r\n"[..], b"\r\n", b"5\n", b"5\r\nhelloXX", b"5\r\nhello\n", b"11111111111111111\r\n", b"-1\r\n", b"0\r\nTrailer\n\r\n", b"0\r\nA: b\r\n\rX"] {assert!(dechunk(bad).iter().all(Result::is_err), "{bad:?}")}
	}
}
