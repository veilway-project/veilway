//! The HTTP of a proxy inbound without any IO: `read` takes the bytes received so far and says that it needs more (`None`), that it has one whole request head and how many bytes it used, or why the head is refused. A request is attacker input, so the reader is strict, and everything it holds is bounded: the head is at most `MAX_HEAD` bytes with at most `MAX_HEADERS` fields.
//! What it takes is a CONNECT with a `host:port` target, or a request for an absolute `http://` URI. A request with an origin-form target, a `https://` URI, a URI with userinfo or a fragment, an obsolete folded line, both `Content-Length` and `Transfer-Encoding`, two `Content-Length` or two `Proxy-Authorization` fields, a bare CR or LF, a control character or a field name that is no token is refused whole.
//! A plain request is forwarded with its request line in origin form, its `Host` made from the URI (whatever the client sent is dropped), the fields of the hop (`Proxy-Authorization`, `Proxy-Connection`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`) left out and `Connection: close` in their place. So one request is carried to a connection, and the node keeps no state between two.
use super::{destination, Target};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::net::Ipv6Addr;

/// The most a request head may take, request line and fields together with the empty line after them.
pub const MAX_HEAD: usize = 8192;
pub const MAX_HEADERS: usize = 64;
/// The longest `Proxy-Authorization` credential taken, as base64: a user name of 64 characters and a password of 128 come to 256.
/// The most bytes of a base64 `Proxy-Authorization` credential that `basic` reads.
pub const MAX_CREDENTIAL: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum Bad {Malformed, TooLarge}

impl Bad {
	/// The status line text the client is answered with.
	pub fn status(&self) -> &'static str {match self {Bad::Malformed => "400 Bad Request", Bad::TooLarge => "431 Request Header Fields Too Large"}}
}

/// One request head, read. `head` is what goes to the destination of a plain request (empty for a CONNECT), `body` says how much of what follows it belongs to the request, and `authorization` is the value of its `Proxy-Authorization` field, if it had one.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {pub connect: bool, pub target: Target, pub authorization: Option<Vec<u8>>, pub head: Vec<u8>, pub body: Body}

/// How much of what a client sends after the head of a plain request belongs to that request: the bytes its `Content-Length` counts, the chunks of its `Transfer-Encoding: chunked` up to the empty line after the trailers, or nothing. Whatever comes after that is the client's next request, which the node never carries: it ends a connection after one request, and what a client wrote for the next one has the `Proxy-Authorization` of its login in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body(Framing);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Framing {
	Length(u64),
	/// A chunk size line: the size so far, the bytes of the line so far, and whether an extension has begun.
	Size {n: u64, line: u16, ext: bool},
	SizeLf(u64),
	Data(u64),
	DataCr,
	DataLf,
	/// The trailer lines: the bytes of the current line and of all of them.
	Trailer {line: usize, all: usize},
	TrailerLf {line: usize, all: usize},
	Done,
}

/// The longest chunk size line (with its extensions) and the most the trailers may take.
const MAX_CHUNK_LINE: u16 = 1024;
const MAX_TRAILER: usize = 8192;

impl Body {
	/// A body that is over already.
	pub fn none() -> Body {Body(Framing::Done)}

	/// Whether the request is complete. A chunked body that breaks its own rules is over as well, at the byte that broke them.
	pub fn done(&self) -> bool {self.0 == Framing::Done}

	/// How many of the first bytes of `data` belong to the request. The rest, and anything that comes later, do not.
	pub fn take(&mut self, data: &[u8]) -> usize {
		let mut used = 0;
		while used < data.len() {
			let (byte, left) = (data[used], (data.len() - used) as u64);
			match &mut self.0 {
				Framing::Done => break,
				Framing::Length(wanted) | Framing::Data(wanted) => {
					let n = (*wanted).min(left);
					used += n as usize;
					*wanted -= n;
					if *wanted == 0 {self.0 = if matches!(self.0, Framing::Length(_)) {Framing::Done} else {Framing::DataCr}}
					continue;
				}
				Framing::Size {n, line, ext} => match byte {
					b'\r' if *line > 0 => self.0 = Framing::SizeLf(*n),
					b';' if *line > 0 => *ext = true,
					_ if *ext && *line < MAX_CHUNK_LINE && (byte >= 0x20 || byte == b'\t') && byte != 0x7f => *line += 1,
					b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' if !*ext && *n >> 40 == 0 && *line < MAX_CHUNK_LINE => {
						*n = *n << 4 | u64::from((byte as char).to_digit(16).unwrap_or(0));
						*line += 1;
					}
					_ => {
						self.0 = Framing::Done;
						break;
					}
				},
				Framing::SizeLf(n) => match (byte, *n) {
					(b'\n', 0) => self.0 = Framing::Trailer {line: 0, all: 0},
					(b'\n', n) => self.0 = Framing::Data(n),
					_ => {
						self.0 = Framing::Done;
						break;
					}
				},
				Framing::DataCr if byte == b'\r' => self.0 = Framing::DataLf,
				Framing::DataLf if byte == b'\n' => self.0 = Framing::Size {n: 0, line: 0, ext: false},
				Framing::Trailer {line, all} => {
					if *all >= MAX_TRAILER || (byte != b'\r' && (byte < 0x20 && byte != b'\t' || byte == 0x7f)) {
						self.0 = Framing::Done;
						break;
					}
					self.0 = if byte == b'\r' {Framing::TrailerLf {line: *line, all: *all + 1}} else {Framing::Trailer {line: *line + 1, all: *all + 1}};
				}
				Framing::TrailerLf {line, all} if byte == b'\n' => self.0 = if *line == 0 {Framing::Done} else {Framing::Trailer {line: 0, all: *all + 1}},
				_ => {
					self.0 = Framing::Done;
					break;
				}
			}
			used += 1;
		}
		used
	}
}

fn token(byte: u8) -> bool {byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)}

fn trim(mut value: &[u8]) -> &[u8] {
	while let [b' ' | b'\t', rest @ ..] = value {value = rest}
	while let [rest @ .., b' ' | b'\t'] = value {value = rest}
	value
}

/// The host and port of an authority, `host`, `host:port` or `[v6]:port`, with `default` for a port that is not written. The host is as it was written, in lower case and with no brackets, and whether it was an IPv6 address.
fn authority(text: &str, default: Option<u16>) -> Option<(String, u16, bool)> {
	let (host, port, v6) = match text.strip_prefix('[') {
		Some(rest) => {
			let (host, tail) = rest.split_once(']')?;
			host.parse::<Ipv6Addr>().ok()?;
			(host, if tail.is_empty() {None} else {Some(tail.strip_prefix(':')?)}, true)
		}
		None => match text.rsplit_once(':') {
			Some((host, port)) if !host.contains(':') => (host, Some(port), false),
			Some(_) => return None,
			None => (text, None, false),
		},
	};
	let port = match port {
		Some(port) if !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) => port.parse::<u16>().ok().filter(|port| *port != 0)?,
		Some(_) => return None,
		None => default?,
	};
	(!host.is_empty()).then(|| (host.to_ascii_lowercase(), port, v6))
}

/// Reads one request head from the start of `buf`.
pub fn read(buf: &[u8]) -> Result<Option<(Request, usize)>, Bad> {
	let Some(end) = buf[..buf.len().min(MAX_HEAD)].windows(4).position(|window| window == b"\r\n\r\n") else {return if buf.len() >= MAX_HEAD {Err(Bad::TooLarge)} else {Ok(None)}};
	let head = &buf[..end];
	if head.iter().any(|b| (*b < 0x20 && !matches!(*b, b'\t' | b'\r' | b'\n')) || *b == 0x7f) {return Err(Bad::Malformed)}
	for (i, b) in head.iter().enumerate() {
		if (*b == b'\n' && (i == 0 || head[i - 1] != b'\r')) || (*b == b'\r' && head.get(i + 1) != Some(&b'\n')) {return Err(Bad::Malformed)}
	}
	let mut lines = head.split(|b| *b == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
	let mut parts = lines.next().ok_or(Bad::Malformed)?.split(|b| *b == b' ');
	let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {return Err(Bad::Malformed)};
	if method.is_empty() || method.len() > 32 || !method.iter().all(|b| token(*b)) || !matches!(version, b"HTTP/1.1" | b"HTTP/1.0") || target.is_empty() || !target.iter().all(|b| (0x21..=0x7e).contains(b)) {return Err(Bad::Malformed)}
	let (mut authorization, mut length, mut chunked, mut kept) = (None, None, false, Vec::new());
	for (count, line) in lines.enumerate() {
		if count >= MAX_HEADERS {return Err(Bad::TooLarge)}
		if matches!(line.first(), Some(b' ' | b'\t')) {return Err(Bad::Malformed)}
		let colon = line.iter().position(|b| *b == b':').ok_or(Bad::Malformed)?;
		let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
		if name.is_empty() || !name.iter().all(|b| token(*b)) {return Err(Bad::Malformed)}
		match name.to_ascii_lowercase().as_slice() {
			b"host" | b"proxy-connection" | b"connection" | b"keep-alive" | b"upgrade" | b"te" | b"trailer" | b"proxy-authenticate" => {}
			b"proxy-authorization" => if authorization.replace(value.to_vec()).is_some() {return Err(Bad::Malformed)},
			b"content-length" => {
				if length.is_some() || value.is_empty() || value.len() > 18 || !value.iter().all(u8::is_ascii_digit) {return Err(Bad::Malformed)}
				length = std::str::from_utf8(value).ok().and_then(|digits| digits.parse::<u64>().ok());
				kept.push((name, value));
			}
			b"transfer-encoding" => {
				// The request has to end where its framing says, so a coding that does not end in `chunked` has no end the node can find.
				if chunked || !value.rsplit(|b| *b == b',').next().is_some_and(|last| trim(last).eq_ignore_ascii_case(b"chunked")) {return Err(Bad::Malformed)}
				chunked = true;
				kept.push((name, value));
			}
			_ => kept.push((name, value))
		}
	}
	if length.is_some() && chunked {return Err(Bad::Malformed)}
	let target = std::str::from_utf8(target).map_err(|_| Bad::Malformed)?;
	let request = if method == b"CONNECT" {
		let (host, port, _) = authority(target, None).ok_or(Bad::Malformed)?;
		Request {connect: true, target: destination(&host, port).ok_or(Bad::Malformed)?, authorization, head: Vec::new(), body: Body::none()}
	} else {
		let rest = target.get(..7).filter(|scheme| scheme.eq_ignore_ascii_case("http://")).map(|_| &target[7..]).ok_or(Bad::Malformed)?;
		if rest.contains('#') {return Err(Bad::Malformed)}
		let (text, path) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
		if text.contains('@') {return Err(Bad::Malformed)}
		let (host, port, v6) = authority(text, Some(80)).ok_or(Bad::Malformed)?;
		let shown = format!("{}{}", if v6 {format!("[{host}]")} else {host.clone()}, if port == 80 {String::new()} else {format!(":{port}")});
		let path = if path.is_empty() {"/".to_string()} else if path.starts_with('?') {format!("/{path}")} else {path.to_string()};
		let mut out = method.to_vec();
		out.extend_from_slice(format!(" {path} HTTP/1.1\r\nHost: {shown}\r\n").as_bytes());
		for (name, value) in kept {out.extend_from_slice(&[name, &b": "[..], value, &b"\r\n"[..]].concat())}
		out.extend_from_slice(b"Connection: close\r\n\r\n");
		let body = if chunked {Body(Framing::Size {n: 0, line: 0, ext: false})} else {Body(length.filter(|length| *length > 0).map_or(Framing::Done, Framing::Length))};
		Request {connect: false, target: destination(&host, port).ok_or(Bad::Malformed)?, authorization, head: out, body}
	};
	Ok(Some((request, end + 4)))
}

/// The user name and password of a `Proxy-Authorization` field with the Basic scheme, split at the first colon. None for any other scheme, a credential that is not base64, one without a colon and one that is too long to be a user's.
pub fn basic(value: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
	let space = value.iter().position(|b| *b == b' ')?;
	let (scheme, encoded) = (&value[..space], trim(&value[space..]));
	if !scheme.eq_ignore_ascii_case(b"basic") || encoded.len() > MAX_CREDENTIAL {return None}
	let decoded = STANDARD.decode(encoded).ok()?;
	let colon = decoded.iter().position(|b| *b == b':')?;
	Some((decoded[..colon].to_vec(), decoded[colon + 1..].to_vec()))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn one(text: &str) -> Result<Request, Bad> {read(text.as_bytes()).map(|read| read.expect("the head is whole").0)}

	#[test]
	fn a_connect_names_its_destination() {
		let request = one("CONNECT Example.COM:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic YTpi\r\n\r\n").unwrap();
		assert_eq!((request.connect, request.target, request.authorization.as_deref(), request.head.len()), (true, Target::Name("example.com".to_string(), 443), Some(&b"Basic YTpi"[..]), 0));
		assert_eq!(one("CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n").unwrap().target, Target::Address("[2606:4700::1111]:443".parse().unwrap()));
		assert_eq!(one("CONNECT 93.184.216.34:8443 HTTP/1.0\r\n\r\n").unwrap().target, Target::Address("93.184.216.34:8443".parse().unwrap()));
		for target in ["example.com", "example.com:", "example.com:0", "example.com:65536", "example.com:44a", ":443", "[::1]", "a:b:443", "[::1:443", "[nothing]:443", "http://example.com:443", "/", "*", "exa mple.com:443", "ex@mple.com:443"] {
			assert!(one(&format!("CONNECT {target} HTTP/1.1\r\n\r\n")).is_err(), "{target}");
		}
	}

	#[test]
	fn a_plain_request_is_rewritten_for_the_origin() {
		let text = "GET http://Example.com/a/b?c=d HTTP/1.1\r\nHost: evil.example\r\nProxy-Authorization: Basic YTpi\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nKeep-Alive: 5\r\nAccept:  */*  \r\nX-Y: z\r\n\r\n";
		let (request, used) = read(text.as_bytes()).unwrap().unwrap();
		assert_eq!(used, text.len());
		assert_eq!((request.connect, &request.target, request.authorization.as_deref()), (false, &Target::Name("example.com".to_string(), 80), Some(&b"Basic YTpi"[..])));
		assert_eq!(String::from_utf8(request.head).unwrap(), "GET /a/b?c=d HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nX-Y: z\r\nConnection: close\r\n\r\n");
		assert_eq!(String::from_utf8(one("GET http://example.com:8080 HTTP/1.1\r\n\r\n").unwrap().head).unwrap(), "GET / HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n");
		assert_eq!(String::from_utf8(one("POST http://[::1]?q HTTP/1.0\r\nContent-Length: 4\r\n\r\n").unwrap().head).unwrap(), "POST /?q HTTP/1.1\r\nHost: [::1]\r\nContent-Length: 4\r\nConnection: close\r\n\r\n");
		assert_eq!(String::from_utf8(one("GET HTTP://Example.com:80/x HTTP/1.1\r\n\r\n").unwrap().head).unwrap(), "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", "the scheme is not case sensitive");
	}

	#[test]
	fn what_is_not_a_proxy_request_is_refused() {
		for text in [
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"GET https://example.com/ HTTP/1.1\r\n\r\n",
			"GET ftp://example.com/ HTTP/1.1\r\n\r\n",
			"GET http://user:pass@example.com/ HTTP/1.1\r\n\r\n",
			"GET http://example.com/#frag HTTP/1.1\r\n\r\n",
			"GET http:///x HTTP/1.1\r\n\r\n",
			"GET http://example.com:0/ HTTP/1.1\r\n\r\n",
			"GET http://exa mple.com/ HTTP/1.1\r\n\r\n",
			"GET http://example.com/ HTTP/2.0\r\n\r\n",
			"GET http://example.com/\r\n\r\n",
			"GET  http://example.com/ HTTP/1.1\r\n\r\n",
			"GET http://example.com/ HTTP/1.1 \r\n\r\n",
			"G(T http://example.com/ HTTP/1.1\r\n\r\n",
			"\r\nGET http://example.com/ HTTP/1.1\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\nHost: a\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nHost: a\rb\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nA: b\r\n folded\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nA: b\r\n\tfolded\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nA : b\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\n: b\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nA b\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nA: b\0\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nA: b\x7f\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\ntransfer-encoding: chunked\r\nCONTENT-LENGTH: 4\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nContent-Length: 4, 4\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nContent-Length: \r\n\r\n",
			"GET http://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic YTpi\r\nProxy-Authorization: Basic YTpi\r\n\r\n",
		] {
			assert_eq!(one(text), Err(Bad::Malformed), "{text:?}");
		}
	}

	#[test]
	fn the_head_is_bounded() {
		assert_eq!(read(b"GET http://example.com/ HTTP/1.1\r\n"), Ok(None));
		let mut big = b"GET http://example.com/ HTTP/1.1\r\nA: ".to_vec();
		big.resize(MAX_HEAD - 3, b'a');
		assert_eq!(read(&big), Ok(None), "a head that may still end in bounds is waited for");
		big.resize(MAX_HEAD, b'a');
		assert_eq!(read(&big), Err(Bad::TooLarge), "a head that fills the limit and does not end is refused");
		let mut whole = b"GET http://example.com/ HTTP/1.1\r\nA: ".to_vec();
		whole.resize(MAX_HEAD - 4, b'a');
		whole.extend_from_slice(b"\r\n\r\n");
		assert_eq!(whole.len(), MAX_HEAD);
		assert!(read(&whole).is_ok(), "a head of exactly the limit is taken");
		whole.insert(whole.len() - 4, b'a');
		assert_eq!(read(&whole), Err(Bad::TooLarge), "a head one byte over is not");
		let many = |n: usize| format!("GET http://example.com/ HTTP/1.1\r\n{}\r\n", "A: b\r\n".repeat(n));
		assert!(one(&many(MAX_HEADERS)).is_ok());
		assert_eq!(one(&many(MAX_HEADERS + 1)), Err(Bad::TooLarge));
	}

	#[test]
	fn bytes_after_the_head_are_not_read() {
		let (_, used) = read(b"GET http://example.com/ HTTP/1.1\r\n\r\nGET http://other.example/ HTTP/1.1\r\n\r\n").unwrap().unwrap();
		assert_eq!(used, "GET http://example.com/ HTTP/1.1\r\n\r\n".len());
	}

	#[test]
	fn a_body_ends_where_its_framing_says() {
		let ends = |head: &str, data: &[u8]| {
			let mut request = one(head).unwrap();
			let used = request.body.take(data);
			(used, request.body.done())
		};
		assert_eq!(ends("GET http://a.example/ HTTP/1.1\r\n\r\n", b"GET next"), (0, true), "a request with no body takes nothing after its head");
		assert_eq!(ends("POST http://a.example/ HTTP/1.1\r\nContent-Length: 4\r\n\r\n", b"abcdNEXT"), (4, true));
		assert_eq!(ends("POST http://a.example/ HTTP/1.1\r\nContent-Length: 4\r\n\r\n", b"ab"), (2, false));
		assert_eq!(ends("POST http://a.example/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n", b"x"), (0, true));
		let chunked = "POST http://a.example/ HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n";
		assert_eq!(ends(chunked, b"4\r\nabcd\r\n0\r\n\r\nNEXT"), (14, true));
		assert_eq!(ends(chunked, b"4;x=y\r\nabcd\r\nA\r\n0123456789\r\n0\r\nT: v\r\nU: w\r\n\r\nNEXT"), (45, true));
		assert_eq!(ends(chunked, b"4\r\nab"), (5, false));
		let mut pieces = one(chunked).unwrap().body;
		let whole = b"3\r\nabc\r\n0\r\n\r\nNEXT";
		let used: usize = whole.iter().map(|byte| pieces.take(&[*byte])).sum();
		assert_eq!((used, pieces.done()), (13, true), "a body read byte by byte ends at the same place");
		for broken in [&b"g\r\n"[..], b"\r\n", b"4\r\nabcdX\r\n", b"4\rX", b"0\r\n\rX", b"fffffffffffffffff\r\n", &[b'4'; 2000][..], &[&b"1;"[..], &[b'a'; 2000]].concat()] {
			let mut body = one(chunked).unwrap().body;
			body.take(broken);
			assert!(body.done() || broken.len() < 8, "{broken:?} was taken as a body");
		}
		for rough in [&b"4;a\nb\r\n"[..], b"4;a\x01b\r\n", b"4;a\x7fb\r\n", b"0\r\nT: a\nU: b\r\n\r\n", b"0\r\nT: \x00\r\n\r\n", b"0\r\nT: \x7f\r\n\r\n"] {
			let mut body = one(chunked).unwrap().body;
			let used = body.take(rough);
			assert!(body.done() && used < rough.len() - 2, "{rough:?} was taken as a body");
		}
		let mut trailers = one(chunked).unwrap().body;
		assert!(trailers.take(&[&b"0\r\n"[..], &[b'a'; 9000]].concat()) < 9000 && trailers.done(), "a trailer without an end was taken");
	}

	#[test]
	fn a_coding_with_no_end_to_find_is_refused() {
		for coding in ["gzip", "chunked, gzip", "identity", "chunked;q=1", ""] {
			assert_eq!(one(&format!("POST http://a.example/ HTTP/1.1\r\nTransfer-Encoding: {coding}\r\n\r\n")).err(), Some(Bad::Malformed), "{coding:?}");
		}
		assert_eq!(one("POST http://a.example/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n").err(), Some(Bad::Malformed));
	}

	#[test]
	fn basic_credentials_are_split_at_the_first_colon() {
		assert_eq!(basic(b"Basic YTpi"), Some((b"a".to_vec(), b"b".to_vec())));
		assert_eq!(basic(b"basic   YTpiOmM="), Some((b"a".to_vec(), b"b:c".to_vec())));
		for bad in [&b"Bearer YTpi"[..], b"Basic", b"Basic !!", b"Basic YQ==", b"YTpi", b""] {assert_eq!(basic(bad), None, "{bad:?}");}
		assert_eq!(basic(&[b"Basic ".to_vec(), vec![b'A'; MAX_CREDENTIAL + 4]].concat()), None);
	}
}
