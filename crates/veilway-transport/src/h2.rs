//! HTTP/2 for `fronted`, `fronted-shaped`, `tls` and `ws` (http2 page): the connection a client speaks to a front or to a node that offers `h2`, with Chrome's first frames and fields, a request as one stream after another, and WebSocket over HTTP/2 (RFC 8441).
//! The frames and HPACK are `veilway_proto::h2`'s. They are not a library's because Chrome is recognised by the order of its SETTINGS and of its pseudo-headers, which a library fixes for itself.
//! Everything the server sends is hostile input: a frame over 16,384 bytes, a header block over 65,536 bytes or whose decoded fields pass 16,384, a body over `BODY_MAX`, a PUSH_PROMISE and a frame the connection cannot make sense of end the attempt, and nothing is allocated from a length the peer chose.
//! The HTTP/1.1 text of `fronted.rs` and `shaped.rs` is kept as the single place a request is built: `fields` turns it into the HTTP/2 request, and the answer is turned back into HTTP/1.1 text, so that the code that reads answers is the same on both.
use crate::fingerprint::Stream;
use crate::http::Stop;
use crate::{Answer, Front};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::time::{sleep_until, timeout, Instant};
use veilway_proto::h2::{self as frames, Decoder, Encoder, Fields, Header};
use veilway_proto::websocket::CLOSE_WAIT;

/// Everything of Chrome's HTTP/2 that the client sends, in one table. DRAFT: these are taken from published descriptions of recent Chrome versions and are replaced by a dated capture of Chrome 155 on each platform before the client sends them (http2 page, "Chrome's HTTP/2" and "Still to measure"). Nothing outside this table is Chrome's.
pub(crate) mod chrome {
	/// SETTINGS in Chrome's order: `HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `INITIAL_WINDOW_SIZE`, `MAX_HEADER_LIST_SIZE`. To capture: the set, the order, and whether `MAX_CONCURRENT_STREAMS` is there.
	pub const SETTINGS: [(u16, u32); 4] = [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)];
	/// The WINDOW_UPDATE on stream 0 that follows, which makes the connection window 15,728,640. To capture: the value.
	pub const WINDOW_UPDATE: u32 = 15_663_105;
	/// The pseudo-headers of a request, in order. For an extended CONNECT `:protocol` is added behind them: its place is to be captured from a Chrome that opens a WebSocket on a reused connection.
	pub const PSEUDO: [&str; 4] = [":method", ":authority", ":scheme", ":path"];
	pub const PROTOCOL: &str = ":protocol";
	/// The regular fields of a request in the order of the HTTP/2 capture. A field that is not named here goes behind them in the order it was written in. To capture: the order for a `fetch()` POST and for a WebSocket.
	pub const FIELDS: [&str; 19] = ["content-length", "sec-ch-ua-platform", "pragma", "cache-control", "user-agent", "sec-ch-ua", "content-type", "sec-ch-ua-mobile", "accept", "origin", "sec-websocket-version", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language", "sec-websocket-extensions", "priority"];
	/// The RFC 9218 `priority` field of a `fetch()` of this purpose. To capture.
	pub const PRIORITY: &str = "u=1, i";
	/// The credit returned at once to the server for what was read, in bytes. To capture: the sizes and thresholds.
	pub const CREDIT: i64 = 32_768;
}

/// "Wait for the server's first SETTINGS frame: 10 s after the TLS handshake."
pub(crate) const SETTINGS_WAIT: Duration = Duration::from_secs(10);
/// "A candidate that lacks extended CONNECT, or answered `421`: remembered for 1 hour, then tried again."
const MARK_FOR: Duration = Duration::from_secs(3_600);
/// "New connection before the stream id passes 2^30."
const STREAM_LAST: u32 = 1 << 30;
/// The largest frame, a header block and the decoded fields the client reads, and the body of one answer.
const FRAME_MAX: usize = frames::FRAME_MAX;
const BLOCK_MAX: usize = 65_536;
const FIELDS_MAX: usize = 16_384;
pub(crate) const BODY_MAX: usize = 1 << 20;
/// How much a request body may be: "the lesser of 65,536 bytes and the stream window the server announced."
const REQUEST_BODY: i64 = 65_536;

/// Why a candidate has no HTTP/2 WebSocket for a while.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
	/// The server never announced extended CONNECT, or picked `http/1.1` from a list that began with `h2`.
	NoConnect,
	/// A `421 Misdirected Request` to an open request.
	Misdirected,
}

// The candidates that have no HTTP/2 WebSocket, by dial address and `host`, until when. Kept in memory, so a restart tries again, which is the safe side of "a latch always expires".
static MARKS: Mutex<Vec<((std::net::SocketAddr, String), Mark, Instant)>> = Mutex::new(Vec::new());

/// Whether the candidate is marked, and why. A mark that has run out is forgotten, and that is logged.
pub(crate) fn marked(candidate: &Front) -> Option<Mark> {
	let key = (candidate.address, candidate.host.clone());
	let mut marks = MARKS.lock().unwrap_or_else(|e| e.into_inner());
	let now = Instant::now();
	marks.retain(|(known, _, until)| {
		let live = *until > now;
		if !live {tracing::info!(host = %known.1, "the mark that kept HTTP/2 WebSocket off this candidate has run out; it is tried again")}
		live
	});
	marks.iter().find(|(known, _, _)| *known == key).map(|(_, why, _)| *why)
}

/// Marks the candidate for an hour, and logs it at info.
pub(crate) fn mark(candidate: &Front, why: Mark) {
	tracing::info!(host = %candidate.host, why = ?why, "no HTTP/2 WebSocket on this candidate for an hour");
	let key = (candidate.address, candidate.host.clone());
	let mut marks = MARKS.lock().unwrap_or_else(|e| e.into_inner());
	marks.retain(|(known, _, _)| *known != key);
	marks.push((key, why, Instant::now() + MARK_FOR));
}

/// The fields of an HTTP/2 request, made from the HTTP/1.1 request text this crate builds: the pseudo-headers in Chrome's order, then the regular fields in Chrome's order, without `Host`, `Connection`, `Keep-Alive` and `Upgrade` (never sent on HTTP/2) and without a cookie. `authority` is the candidate's `host` with the port of its address when that is not 443. With `connect` the method is the extended CONNECT of RFC 8441 for `websocket`, and `Sec-WebSocket-Key` is left out. The body of the text, if any, is not read: the range of its start is given.
pub(crate) fn fields(request: &[u8], authority: &str, connect: bool) -> Option<(Fields, usize)> {
	let end = crate::http::end(request)?;
	let mut lines = request[..end].split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
	let mut start = lines.next()?.split(|byte| *byte == b' ');
	let (method, target) = (start.next()?, start.next()?);
	let mut regular: Fields = Vec::new();
	for line in lines.filter(|line| !line.is_empty()) {
		let colon = line.iter().position(|byte| *byte == b':')?;
		let (name, value) = (line[..colon].to_ascii_lowercase(), line[colon + 1..].trim_ascii());
		if matches!(name.as_slice(), b"host" | b"connection" | b"keep-alive" | b"upgrade" | b"proxy-connection" | b"cookie" | b"transfer-encoding") || name == b"sec-websocket-key" {continue}
		regular.push((name, value.to_vec()));
	}
	if !connect {regular.push((b"priority".to_vec(), chrome::PRIORITY.as_bytes().to_vec()))}
	let rank = |name: &[u8]| chrome::FIELDS.iter().position(|known| known.as_bytes() == name).unwrap_or(chrome::FIELDS.len());
	regular.sort_by_key(|(name, _)| rank(name));
	let mut list: Fields = vec![(chrome::PSEUDO[0].into(), if connect {b"CONNECT".to_vec()} else {method.to_vec()}), (chrome::PSEUDO[1].into(), authority.into()), (chrome::PSEUDO[2].into(), b"https".to_vec()), (chrome::PSEUDO[3].into(), target.to_vec())];
	if connect {list.push((chrome::PROTOCOL.into(), b"websocket".to_vec()))}
	list.extend(regular);
	Some((list, end))
}

/// Why the connection cannot go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
	/// Reset, or ended without a `close_notify`: anyone on the path can cause that.
	Cut,
	/// Closed in order.
	Closed,
	/// The server sent what no HTTP/2 server sends, or went past a bound of the client's.
	Fault,
}

/// One HTTP/2 connection with at most one stream open at a time, which is all `fronted` and a WebSocket need.
pub(crate) struct Conn<T> {
	io: T,
	inbox: Vec<u8>,
	out: Vec<u8>,
	decoder: Decoder,
	encoder: Encoder,
	next: u32,
	/// What may still be sent on the connection and on the one open stream, and the stream window a new stream starts with.
	window: i64,
	stream_window: i64,
	initial: i64,
	/// The server's SETTINGS were read, and whether it announced extended CONNECT.
	settled: bool,
	connect: bool,
	/// A GOAWAY: the last stream id it processed, and its error code.
	goaway: Option<(u32, u32)>,
	owed_connection: i64,
	owed_stream: i64,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Conn<T> {
	/// The preface, Chrome's SETTINGS and its connection WINDOW_UPDATE, held back and written with whatever is sent first, as Chrome writes them in one flight with its first request.
	pub(crate) fn new(io: T) -> Conn<T> {
		let mut out = frames::PREFACE.to_vec();
		frames::settings(&chrome::SETTINGS, &mut out);
		frames::window_update(0, chrome::WINDOW_UPDATE, &mut out);
		Conn {io, inbox: Vec::new(), out, decoder: Decoder::new(chrome::SETTINGS[0].1 as usize), encoder: Encoder::new(), next: 1, window: i64::from(frames::WINDOW_DEFAULT), stream_window: 0, initial: i64::from(frames::WINDOW_DEFAULT), settled: false, connect: false, goaway: None, owed_connection: 0, owed_stream: 0}
	}

	/// The most a request body may be: the lesser of 65,536 bytes and the stream window the server announced.
	pub(crate) fn limit(&self) -> usize {REQUEST_BODY.min(self.initial).max(0) as usize}

	/// Whether the connection must not carry another request: the server said it is going away, or the stream ids are nearly used up.
	pub(crate) fn spent(&self) -> bool {self.goaway.is_some() || self.next > STREAM_LAST}

	async fn flush(&mut self) -> Result<(), Fail> {
		if self.out.is_empty() {return Ok(())}
		let written = self.io.write_all(&self.out).await.is_ok() && self.io.flush().await.is_ok();
		self.out.clear();
		if written {Ok(())} else {Err(Fail::Cut)}
	}

	// The next whole frame. A frame larger than the default size, which this client never lets the server raise, ends the connection.
	async fn read(&mut self) -> Result<(Header, Vec<u8>), Fail> {
		let mut chunk = vec![0u8; 16_384];
		loop {
			if self.inbox.len() >= frames::HEADER {
				let header = Header::parse(self.inbox[..frames::HEADER].try_into().map_err(|_| Fail::Fault)?);
				if header.len > FRAME_MAX {return Err(Fail::Fault)}
				if self.inbox.len() >= frames::HEADER + header.len {
					let payload = self.inbox[frames::HEADER..frames::HEADER + header.len].to_vec();
					self.inbox.drain(..frames::HEADER + header.len);
					return Ok((header, payload));
				}
			}
			match self.io.read(&mut chunk).await {
				Ok(0) => return Err(Fail::Closed),
				Ok(count) => self.inbox.extend_from_slice(&chunk[..count]),
				Err(_) => return Err(Fail::Cut),
			}
		}
	}

	// Takes the frames of the connection itself and gives back the ones of a stream. SETTINGS and PING are answered with the next write, in one flight with the frame that is due.
	fn control(&mut self, header: Header, payload: Vec<u8>) -> Result<Option<(Header, Vec<u8>)>, Fail> {
		match header.kind {
			frames::SETTINGS => {
				if header.stream != 0 {return Err(Fail::Fault)}
				if header.flags & frames::ACK != 0 {return if payload.is_empty() {Ok(None)} else {Err(Fail::Fault)}}
				for (id, value) in frames::read_settings(&payload).ok_or(Fail::Fault)? {
					match id {
						frames::HEADER_TABLE_SIZE => self.encoder.resize(value as usize),
						frames::INITIAL_WINDOW_SIZE if value > frames::WINDOW_MAX => return Err(Fail::Fault),
						frames::INITIAL_WINDOW_SIZE => {
							self.stream_window += i64::from(value) - self.initial;
							self.initial = i64::from(value);
						}
						frames::ENABLE_CONNECT_PROTOCOL => self.connect = value == 1,
						_ => {}
					}
				}
				self.settled = true;
				frames::frame(frames::SETTINGS, frames::ACK, 0, &[], &mut self.out);
				Ok(None)
			}
			frames::PING => {
				if header.stream != 0 || payload.len() != 8 {return Err(Fail::Fault)}
				if header.flags & frames::ACK == 0 {frames::frame(frames::PING, frames::ACK, 0, &payload, &mut self.out)}
				Ok(None)
			}
			frames::GOAWAY => {
				if header.stream != 0 || payload.len() < 8 {return Err(Fail::Fault)}
				self.goaway = Some((u32::from_be_bytes(payload[..4].try_into().map_err(|_| Fail::Fault)?) & frames::WINDOW_MAX, u32::from_be_bytes(payload[4..8].try_into().map_err(|_| Fail::Fault)?)));
				Ok(None)
			}
			frames::WINDOW_UPDATE if header.stream == 0 => {
				let increment = i64::from(u32::from_be_bytes(payload.as_slice().try_into().map_err(|_| Fail::Fault)?) & frames::WINDOW_MAX);
				self.window += increment;
				if increment == 0 || self.window > i64::from(frames::WINDOW_MAX) {return Err(Fail::Fault)}
				Ok(None)
			}
			frames::PUSH_PROMISE => Err(Fail::Fault),
			frames::PRIORITY => Ok(None),
			_ => Ok(Some((header, payload))),
		}
	}

	// Reads frames until the server's SETTINGS were read: false when they did not come within `wait`. A connection that was told of a SETTINGS already is settled at once.
	pub(crate) async fn settle(&mut self, wait: Duration) -> Result<bool, Fail> {
		self.flush().await?;
		let until = Instant::now() + wait;
		while !self.settled {
			let Ok(read) = timeout(until.saturating_duration_since(Instant::now()), self.read()).await else {return Ok(false)};
			let (header, payload) = read?;
			self.control(header, payload)?;
		}
		Ok(true)
	}

	/// Whether the server announced extended CONNECT. Meaningful after `settle`.

	// The fields of one header block, from a HEADERS frame to its END_HEADERS. A list over the client's bound ends the connection.
	async fn block(&mut self, header: Header, payload: Vec<u8>) -> Result<Fields, Fail> {
		let mut bytes = frames::unpad(header.flags, &payload, true).ok_or(Fail::Fault)?.to_vec();
		let mut done = header.flags & frames::END_HEADERS != 0;
		while !done {
			let (next, more) = self.read().await?;
			if next.kind != frames::CONTINUATION || next.stream != header.stream {return Err(Fail::Fault)}
			bytes.extend_from_slice(&more);
			if bytes.len() > BLOCK_MAX {return Err(Fail::Fault)}
			done = next.flags & frames::END_HEADERS != 0;
		}
		self.decoder.decode(&bytes, FIELDS_MAX).map_err(|_| Fail::Fault)
	}

	// A HEADERS frame of a stream that is not the one being read, closed or never opened: its block is decoded all the same, because the table is shared, and the stream is reset as closed.
	async fn stray(&mut self, header: Header, payload: Vec<u8>) -> Result<(), Fail> {
		self.block(header, payload).await?;
		frames::rst_stream(header.stream, frames::STREAM_CLOSED, &mut self.out);
		self.flush().await
	}

	// A stream: HEADERS with this list, and the body in DATA frames within the windows, with END_STREAM on the last when `end`.
	async fn open(&mut self, list: &Fields, end: bool) -> Result<u32, Fail> {
		let id = self.next;
		self.next += 2;
		self.stream_window = self.initial;
		let block = self.encoder.encode(&list.iter().map(|(name, value)| (name.as_slice(), value.as_slice())).collect::<Vec<_>>());
		frames::headers(id, &block, end, &mut self.out);
		self.flush().await?;
		Ok(id)
	}

	// Credit for what was read, at the threshold of the table.
	async fn credit(&mut self, id: u32, count: usize) -> Result<(), Fail> {
		self.owed_connection += count as i64;
		self.owed_stream += count as i64;
		if self.owed_connection >= chrome::CREDIT {
			frames::window_update(0, std::mem::take(&mut self.owed_connection) as u32, &mut self.out);
			if self.owed_stream > 0 {frames::window_update(id, std::mem::take(&mut self.owed_stream) as u32, &mut self.out)}
			self.flush().await?;
		}
		Ok(())
	}

	// Sends `body` on the stream, waiting for window credit by reading frames, which only the server's WINDOW_UPDATE ends the wait of.
	async fn send(&mut self, id: u32, body: &[u8], end: bool) -> Result<(), Fail> {
		let mut at = 0;
		loop {
			let room = self.window.min(self.stream_window).min(FRAME_MAX as i64);
			let left = body.len() - at;
			if left == 0 {
				if end {
					frames::frame(frames::DATA, frames::END_STREAM, id, &[], &mut self.out);
					self.flush().await?;
				}
				return Ok(());
			}
			if room <= 0 {
				self.flush().await?;
				let (header, payload) = self.read().await?;
				if let Some((header, payload)) = self.control(header, payload)? {
					match header.kind {
						frames::WINDOW_UPDATE if header.stream == id => {
							self.stream_window += i64::from(u32::from_be_bytes(payload.as_slice().try_into().map_err(|_| Fail::Fault)?) & frames::WINDOW_MAX);
							if self.stream_window > i64::from(frames::WINDOW_MAX) {return Err(Fail::Fault)}
						}
						frames::RST_STREAM if header.stream == id => return Err(Fail::Cut),
						_ => {}
					}
				}
				continue;
			}
			let take = (room as usize).min(left);
			self.window -= take as i64;
			self.stream_window -= take as i64;
			frames::frame(frames::DATA, if end && take == left {frames::END_STREAM} else {0}, id, &body[at..at + take], &mut self.out);
			at += take;
			if at == body.len() && !end {return self.flush().await}
		}
	}

	/// One request and its answer, the answer as HTTP/1.1 text in `buf` (so that the readers of `fronted` and `shaped` are the same on both versions). The body of the answer is the range that comes back, and the bool says the connection must not be used again.
	/// A `RST_STREAM`, a GOAWAY that did not process the stream and a connection that ends are `Cut`: the caller sends the identical bytes again on a new connection. `transfer-encoding` and a `content-length` that does not match are malformed on HTTP/2 (RFC 9113, sections 8.1.1 and 8.2.2) and refused.
	pub(crate) async fn exchange(&mut self, request: &[u8], authority: &str, buf: &mut Vec<u8>, written: &mut bool) -> Result<(Range<usize>, bool), Stop> {
		let (list, body_at) = fields(request, authority, false).ok_or(Stop::Said(Answer::NotHttp))?;
		let stop = |fail: Fail| match fail {Fail::Cut => Stop::Cut, Fail::Closed => Stop::Said(Answer::Closed), Fail::Fault => Stop::Said(Answer::NotHttp)};
		let body = &request[body_at..];
		let id = self.open(&list, body.is_empty()).await.map_err(stop)?;
		if !body.is_empty() {self.send(id, body, true).await.map_err(stop)?}
		*written = true;
		let (mut status, mut answer, mut payload, mut ended) = (None::<String>, Fields::new(), Vec::new(), false);
		self.owed_stream = 0;
		while !ended {
			let (header, bytes) = self.read().await.map_err(stop)?;
			let Some((header, bytes)) = self.control(header, bytes).map_err(stop)? else {
				if self.goaway.is_some_and(|(last, _)| last < id) {return Err(Stop::Cut)}
				self.flush().await.map_err(stop)?;
				continue;
			};
			if header.stream != id {
				if header.kind == frames::DATA {self.credit(0, bytes.len()).await.map_err(stop)?}
				if header.kind == frames::HEADERS {self.stray(header, bytes).await.map_err(stop)?}
				continue;
			}
			match header.kind {
				frames::HEADERS => {
					let end = header.flags & frames::END_STREAM != 0;
					let list = self.block(header, bytes).await.map_err(stop)?;
					if status.is_none() {
						let (pseudo, rest): (Vec<_>, Vec<_>) = list.into_iter().partition(|(name, _)| name.first() == Some(&b':'));
						if pseudo.len() != 1 || pseudo[0].0 != b":status" {return Err(Stop::Said(Answer::NotHttp))}
						let text = String::from_utf8(pseudo[0].1.clone()).ok().filter(|text| text.len() == 3 && text.bytes().all(|byte| byte.is_ascii_digit())).ok_or(Stop::Said(Answer::NotHttp))?;
						// An interim answer is passed over: the answer is the one behind it.
						if text.starts_with('1') {continue}
						(status, answer) = (Some(text), rest);
					}
					ended |= end;
				}
				frames::DATA => {
					let data = frames::unpad(header.flags, &bytes, false).ok_or(Stop::Said(Answer::NotHttp))?;
					payload.extend_from_slice(data);
					if payload.len() > BODY_MAX {return Err(Stop::Said(Answer::NotHttp))}
					self.credit(id, bytes.len()).await.map_err(stop)?;
					ended |= header.flags & frames::END_STREAM != 0;
				}
				frames::RST_STREAM => return Err(Stop::Cut),
				_ => {}
			}
		}
		let status = status.ok_or(Stop::Said(Answer::NotHttp))?;
		let mut lengths = answer.iter().filter(|(name, _)| name == b"content-length");
		if let Some((_, value)) = lengths.next() {
			if lengths.next().is_some() || std::str::from_utf8(value).ok().and_then(|value| value.parse::<usize>().ok()) != Some(payload.len()) {return Err(Stop::Said(Answer::NotHttp))}
		}
		if answer.iter().any(|(name, _)| name == b"transfer-encoding" || name == b"connection" || name == b"keep-alive") {return Err(Stop::Said(Answer::NotHttp))}
		buf.clear();
		buf.extend_from_slice(format!("HTTP/1.1 {status} \r\n").as_bytes());
		for (name, value) in &answer {
			if name != b"content-length" {
				buf.extend_from_slice(name);
				buf.extend_from_slice(b": ");
				buf.extend_from_slice(value);
				buf.extend_from_slice(b"\r\n");
			}
		}
		buf.extend_from_slice(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes());
		let start = buf.len();
		buf.extend_from_slice(&payload);
		Ok((start..buf.len(), self.spent()))
	}

	/// Whether the server has sent anything nobody asked for since the last answer, or the connection ended: such a connection is given up before a request is written to it.
	pub(crate) async fn stale(&mut self) -> bool {
		if self.spent() {return true}
		loop {
			match timeout(Duration::ZERO, self.read()).await {
				Err(_) => return false,
				Ok(Err(_)) => return true,
				Ok(Ok((header, payload))) => {
					if self.control(header, payload).is_err() {return true}
					if self.goaway.is_some() {return true}
				}
			}
		}
	}

	/// Ends the connection as Chrome does: GOAWAY with NO_ERROR, then `close_notify`, then TCP.
	pub(crate) async fn close(&mut self) {
		frames::goaway(0, frames::NO_ERROR, &mut self.out);
		let _ = timeout(Duration::from_secs(1), async {
			let _ = self.flush().await;
			self.io.shutdown().await
		}).await;
	}
}

/// What the answer to an extended CONNECT was.
#[derive(Debug)]
pub(crate) enum Opened {
	/// A `200`: the stream carries the WebSocket from here on. `abnormal` is set when the pipe ends for anything but the peer's close in order.
	Ready(DuplexStream, Arc<AtomicBool>),
	/// A `421 Misdirected Request`.
	Misdirected,
	/// The server did not announce extended CONNECT, or did not send its SETTINGS in time. No request was sent.
	NoConnect,
	/// Any other status, with the fields of the answer for the `Date`.
	Status(u16),
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Conn<T> {
	/// Sends the extended CONNECT `list` and reads its answer. On a `200` the connection is handed to a task that carries the stream's DATA frames to and from the pipe it returns: WebSocket frames in, WebSocket frames out. A `RST_STREAM` before the answer is `Cut`.
	pub(crate) async fn websocket(mut self, list: &Fields) -> Result<Opened, Fail> {
		if !self.settle(SETTINGS_WAIT).await? || !self.connect {
			self.close().await;
			return Ok(Opened::NoConnect);
		}
		let id = self.open(list, false).await?;
		loop {
			let (header, payload) = self.read().await?;
			let Some((header, payload)) = self.control(header, payload)? else {
				if self.goaway.is_some_and(|(last, _)| last < id) {return Err(Fail::Cut)}
				self.flush().await?;
				continue;
			};
			if header.stream != id {
				if header.kind == frames::HEADERS {self.stray(header, payload).await?}
				continue;
			}
			match header.kind {
				frames::HEADERS => {
					let list = self.block(header, payload).await?;
					let pseudo: Vec<_> = list.into_iter().filter(|(name, _)| name.first() == Some(&b':')).collect();
					if pseudo.len() != 1 || pseudo[0].0 != b":status" {return Err(Fail::Fault)}
					let status = String::from_utf8(pseudo[0].1.clone()).ok().and_then(|text| text.parse::<u16>().ok()).ok_or(Fail::Fault)?;
					if status < 200 {continue}
					if status == 421 {
						self.close().await;
						return Ok(Opened::Misdirected);
					}
					if status != 200 {
						self.close().await;
						return Ok(Opened::Status(status));
					}
					break;
				}
				frames::RST_STREAM => return Err(Fail::Cut),
				_ => {}
			}
		}
		let (ours, theirs) = duplex(65_536);
		let abnormal = Arc::new(AtomicBool::new(false));
		tokio::spawn(pump(self, id, theirs, abnormal.clone()));
		Ok(Opened::Ready(ours, abnormal))
	}
}

// The stream of a WebSocket: what the client writes into the pipe goes out in DATA frames, and DATA frames go into the pipe. "Closing: the sender writes a Close frame, then END_STREAM. It waits up to 5 s for the peer's Close frame and the peer's END_STREAM, then sends RST_STREAM with NO_ERROR if the stream is still open. The client then closes the connection." The pipe's end is the client's END_STREAM.
async fn pump<T: AsyncRead + AsyncWrite + Unpin + Send>(mut conn: Conn<T>, id: u32, pipe: DuplexStream, abnormal: Arc<AtomicBool>) {
	let (mut from_client, mut to_client) = split(pipe);
	let (mut buf, mut local_ended, mut remote_ended, mut broken, mut until) = (vec![0u8; FRAME_MAX], false, false, false, None::<Instant>);
	conn.owed_connection = 0;
	conn.owed_stream = 0;
	loop {
		if local_ended && remote_ended {break}
		let room = conn.window.min(conn.stream_window).clamp(0, FRAME_MAX as i64) as usize;
		tokio::select! {
			biased;
			read = conn.read() => {
				let Ok((header, payload)) = read else {
					broken = true;
					break;
				};
				let Ok(taken) = conn.control(header, payload) else {
					broken = true;
					break;
				};
				let Some((header, payload)) = taken else {
					if conn.flush().await.is_err() {
						broken = true;
						break;
					}
					if conn.goaway.is_some_and(|(_, code)| code != frames::NO_ERROR) {
						broken = true;
						break;
					}
					continue;
				};
				if header.stream != id {
					if header.kind == frames::HEADERS && conn.stray(header, payload).await.is_err() {
						broken = true;
						break;
					}
					continue;
				}
				match header.kind {
					// Trailers: decoded to keep the table in step, and dropped.
					frames::HEADERS => {
						if conn.block(header, payload).await.is_err() {
							broken = true;
							break;
						}
					}
					frames::DATA => {
						let Some(data) = frames::unpad(header.flags, &payload, false) else {
							broken = true;
							break;
						};
						if !data.is_empty() && to_client.write_all(data).await.is_err() {
							local_ended = true;
							remote_ended = true;
						}
						if conn.credit(id, payload.len()).await.is_err() {
							broken = true;
							break;
						}
						if header.flags & frames::END_STREAM != 0 {
							remote_ended = true;
							let _ = to_client.shutdown().await;
						}
					}
					frames::WINDOW_UPDATE => {
						let Ok(bytes) = payload.as_slice().try_into() else {
							broken = true;
							break;
						};
						conn.stream_window += i64::from(u32::from_be_bytes(bytes) & frames::WINDOW_MAX);
						if conn.stream_window > i64::from(frames::WINDOW_MAX) {
							broken = true;
							break;
						}
					}
					// A reset or a GOAWAY with the connection still alive, without the node's Close frame, is the end of the session and says nothing of who ended it.
					frames::RST_STREAM => {
						broken = true;
						break;
					}
					_ => {}
				}
			}
			read = from_client.read(&mut buf[..room.max(1)]), if !local_ended && room > 0 => match read {
				Ok(count) if count > 0 => {
					conn.window -= count as i64;
					conn.stream_window -= count as i64;
					frames::frame(frames::DATA, 0, id, &buf[..count], &mut conn.out);
					if conn.flush().await.is_err() {
						broken = true;
						break;
					}
				}
				_ => {
					local_ended = true;
					frames::frame(frames::DATA, frames::END_STREAM, id, &[], &mut conn.out);
					until = Some(Instant::now() + CLOSE_WAIT);
					if conn.flush().await.is_err() {
						broken = true;
						break;
					}
				}
			},
			_ = async {match until {Some(until) => sleep_until(until).await, None => std::future::pending().await}} => break,
		}
	}
	// The stream's end is not the peer's close in order when the connection broke or the server reset it.
	if broken {abnormal.store(true, Ordering::Relaxed)}
	if !broken && !remote_ended {frames::rst_stream(id, frames::NO_ERROR, &mut conn.out)}
	if !broken {conn.close().await}
	drop(to_client);
}

/// The connection of a stream attempt that offers `h2`: HTTP/2 when the server picked it, else the TLS stream as it is.
pub(crate) enum Wire {
	Plain(Stream),
	Two(Box<Conn<Stream>>),
}

impl Wire {
	/// The connection the handshake leaves: HTTP/2 when it picked `h2`.
	pub(crate) fn of(io: Stream) -> Wire {if io.0.ssl().selected_alpn_protocol() == Some(b"h2") {Wire::Two(Box::new(Conn::new(io)))} else {Wire::Plain(io)}}

	/// One request and its answer, as HTTP/1.1 text, on whichever version the connection speaks. `authority` is the `Host` of the candidate.
	pub(crate) async fn exchange(&mut self, request: &[u8], authority: &str, buf: &mut Vec<u8>, written: &mut bool) -> Result<(Range<usize>, bool), Stop> {
		match self {
			Wire::Plain(io) => crate::fronted::exchange(io, request, buf, written).await,
			Wire::Two(conn) => conn.exchange(request, authority, buf, written).await,
		}
	}

	/// How large the body of the next request may be at most.
	pub(crate) fn limit(&self) -> usize {match self {Wire::Plain(_) => veilway_proto::fronted::BODY_MAX, Wire::Two(conn) => conn.limit().min(veilway_proto::fronted::BODY_MAX)}}

	/// Whether the connection was given up by the other side since the last answer: a byte nobody asked for, a GOAWAY, or its end.
	pub(crate) async fn stale(&mut self) -> bool {
		match self {
			Wire::Plain(io) => timeout(Duration::ZERO, io.read(&mut [0u8; 1])).await.is_ok(),
			Wire::Two(conn) => conn.stale().await,
		}
	}

	/// The end of a connection kept for the next request: in order.
	pub(crate) async fn close(&mut self) {
		match self {
			Wire::Plain(io) => drop(timeout(Duration::from_secs(1), io.shutdown()).await),
			Wire::Two(conn) => conn.close().await,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn text(list: &Fields) -> Vec<String> {list.iter().map(|(name, value)| format!("{}: {}", String::from_utf8_lossy(name), String::from_utf8_lossy(value))).collect()}

	async fn frame(io: &mut DuplexStream) -> (Header, Vec<u8>) {
		let mut head = [0u8; frames::HEADER];
		io.read_exact(&mut head).await.unwrap();
		let header = Header::parse(&head);
		let mut payload = vec![0u8; header.len];
		io.read_exact(&mut payload).await.unwrap();
		(header, payload)
	}

	// The preface, SETTINGS and the connection's WINDOW_UPDATE, then the first HEADERS: what a server sees of a new connection.
	async fn greeting(io: &mut DuplexStream) -> (Vec<(u16, u32)>, Fields) {
		let mut preface = [0u8; 24];
		io.read_exact(&mut preface).await.unwrap();
		assert_eq!(&preface, frames::PREFACE);
		let (settings, payload) = frame(io).await;
		assert_eq!(settings.kind, frames::SETTINGS);
		let entries = frames::read_settings(&payload).unwrap().collect();
		let (window, payload) = frame(io).await;
		assert_eq!((window.kind, window.stream, payload.as_slice()), (frames::WINDOW_UPDATE, 0, &15_663_105u32.to_be_bytes()[..]));
		let (headers, block) = frame(io).await;
		assert_eq!((headers.kind, headers.stream, headers.flags & frames::END_STREAM), (frames::HEADERS, 1, frames::END_STREAM));
		(entries, Decoder::new(4_096).decode(&block, 65_536).unwrap())
	}

	// The kind of every frame in `bytes`, in order.
	fn kinds(mut bytes: &[u8]) -> Vec<u8> {
		let mut kinds = Vec::new();
		while bytes.len() >= frames::HEADER {
			let header = Header::parse(bytes[..frames::HEADER].try_into().unwrap());
			kinds.push(header.kind);
			bytes = &bytes[(frames::HEADER + header.len).min(bytes.len())..];
		}
		kinds
	}

	#[test]
	fn a_request_takes_chromes_fields_in_chromes_order_and_no_others() {
		let request = b"POST /p?t HTTP/1.1\r\nHost: front.example\r\nConnection: keep-alive\r\nContent-Length: 4\r\nUser-Agent: x\r\nAccept: */*\r\nCookie: a=1\r\nSec-WebSocket-Key: k\r\n\r\nbody";
		let (list, end) = fields(request, "front.example", false).unwrap();
		assert_eq!(text(&list), [":method: POST", ":authority: front.example", ":scheme: https", ":path: /p?t", "content-length: 4", "user-agent: x", "accept: */*", "priority: u=1, i"]);
		assert_eq!(&request[end..], b"body");
		let connect = b"GET /p?t HTTP/1.1\r\nHost: front.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: k\r\n\r\n";
		let (list, _) = fields(connect, "front.example", true).unwrap();
		assert_eq!(text(&list), [":method: CONNECT", ":authority: front.example", ":scheme: https", ":path: /p?t", ":protocol: websocket", "sec-websocket-version: 13"]);
	}

	#[tokio::test]
	async fn a_request_and_its_answer_cross_one_stream_and_come_back_as_http_1_1_text() {
		let (client, mut server) = duplex(65_536);
		let server = tokio::spawn(async move {
			let greeted = greeting(&mut server).await;
			let mut out = Vec::new();
			frames::settings(&[], &mut out);
			let block = Encoder::new().encode(&[(b":status", b"200"), (b"content-length", b"2"), (b"server", b"raw")]);
			frames::headers(1, &block, false, &mut out);
			frames::frame(frames::DATA, frames::END_STREAM, 1, b"ok", &mut out);
			server.write_all(&out).await.unwrap();
			// The server's end stays open: the client still flushes the SETTINGS it owes.
			(greeted, server)
		});
		let mut conn = Conn::new(client);
		let (mut buf, mut written) = (Vec::new(), false);
		let (body, close) = match conn.exchange(b"GET /p HTTP/1.1\r\nHost: front.example\r\n\r\n", "front.example", &mut buf, &mut written).await {
			Ok(answer) => answer,
			Err(Stop::Cut) => panic!("cut"),
			Err(Stop::Said(answer)) => panic!("{answer:?}"),
		};
		let ((entries, list), _server) = server.await.unwrap();
		assert_eq!(entries, [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)]);
		assert_eq!(text(&list), [":method: GET", ":authority: front.example", ":scheme: https", ":path: /p", "priority: u=1, i"]);
		assert_eq!((&buf[body], close, written), (&b"ok"[..], false, true));
		assert!(buf.starts_with(b"HTTP/1.1 200 \r\n") && buf.windows(12).any(|window| window == b"server: raw\r") && buf.ends_with(b"\r\n\r\nok"), "{}", String::from_utf8_lossy(&buf));
	}

	#[tokio::test]
	async fn a_post_body_goes_in_data_frames_and_the_answer_ends_at_its_end_stream() {
		let (client, mut server) = duplex(65_536);
		let server = tokio::spawn(async move {
			let mut preface = [0u8; 24];
			server.read_exact(&mut preface).await.unwrap();
			let (_, _) = frame(&mut server).await;
			let (_, _) = frame(&mut server).await;
			let (headers, block) = frame(&mut server).await;
			let (data, body) = frame(&mut server).await;
			let list = Decoder::new(4_096).decode(&block, 65_536).unwrap();
			assert_eq!((headers.kind, headers.stream, headers.flags & frames::END_STREAM), (frames::HEADERS, 1, 0));
			assert_eq!((data.kind, data.stream, data.flags & frames::END_STREAM, body.as_slice()), (frames::DATA, 1, frames::END_STREAM, &b"abc"[..]));
			let mut out = Vec::new();
			frames::headers(1, &Encoder::new().encode(&[(b":status", b"200"), (b"content-length", b"4")]), false, &mut out);
			frames::frame(frames::DATA, 0, 1, b"ye", &mut out);
			frames::frame(frames::DATA, frames::END_STREAM, 1, b"s!", &mut out);
			server.write_all(&out).await.unwrap();
			(list, server)
		});
		let mut conn = Conn::new(client);
		let (mut buf, mut written) = (Vec::new(), false);
		let (body, _) = match conn.exchange(b"POST /p HTTP/1.1\r\nHost: front.example\r\nContent-Length: 3\r\n\r\nabc", "front.example", &mut buf, &mut written).await {
			Ok(answer) => answer,
			Err(Stop::Cut) => panic!("cut"),
			Err(Stop::Said(answer)) => panic!("{answer:?}"),
		};
		let (list, _server) = server.await.unwrap();
		assert_eq!(text(&list), [":method: POST", ":authority: front.example", ":scheme: https", ":path: /p", "content-length: 3", "priority: u=1, i"]);
		assert_eq!(&buf[body], b"yes!");
		assert!(buf.windows(18).any(|window| window == b"Content-Length: 4\r"));
	}

	#[tokio::test]
	async fn a_server_that_does_not_announce_extended_connect_gets_no_request() {
		let (client, mut server) = duplex(65_536);
		let server = tokio::spawn(async move {
			let mut preface = [0u8; 24];
			server.read_exact(&mut preface).await.unwrap();
			let mut out = Vec::new();
			frames::settings(&[(frames::HEADER_TABLE_SIZE, 4_096)], &mut out);
			server.write_all(&out).await.unwrap();
			let mut rest = Vec::new();
			server.read_to_end(&mut rest).await.unwrap();
			rest
		});
		let list = vec![(b":method".to_vec(), b"CONNECT".to_vec())];
		assert!(matches!(Conn::new(client).websocket(&list).await, Ok(Opened::NoConnect)));
		let sent = server.await.unwrap();
		assert!(!kinds(&sent).contains(&frames::HEADERS) && kinds(&sent).last() == Some(&frames::GOAWAY));
	}

	#[tokio::test]
	async fn a_421_to_the_extended_connect_is_a_misdirected_request_and_nothing_is_retried_on_the_connection() {
		let (client, mut server) = duplex(65_536);
		let server = tokio::spawn(async move {
			let mut preface = [0u8; 24];
			server.read_exact(&mut preface).await.unwrap();
			let mut out = Vec::new();
			frames::settings(&[(frames::ENABLE_CONNECT_PROTOCOL, 1)], &mut out);
			server.write_all(&out).await.unwrap();
			let mut seen = Vec::new();
			loop {
				let (header, _) = frame(&mut server).await;
				seen.push((header.kind, header.stream));
				if header.kind == frames::HEADERS {break}
			}
			assert_eq!(seen.last(), Some(&(frames::HEADERS, 1)));
			assert!(seen.contains(&(frames::WINDOW_UPDATE, 0)));
			let mut out = Vec::new();
			frames::headers(1, &Encoder::new().encode(&[(b":status", b"421")]), true, &mut out);
			server.write_all(&out).await.unwrap();
		});
		let list = vec![(b":method".to_vec(), b"CONNECT".to_vec()), (b":protocol".to_vec(), b"websocket".to_vec())];
		assert!(matches!(Conn::new(client).websocket(&list).await, Ok(Opened::Misdirected)));
		server.await.unwrap();
	}
}
