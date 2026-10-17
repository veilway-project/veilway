//! The client of `fronted-shaped` (shapes page, "Upstream", "Downstream" and "The client"): HTTP/1.1 requests over TLS to the front in the shape the profile names, with up to `up.inflight` of them in flight, polled answers or one stream of events, and the tunnel's datagrams in chunks numbered `n` times 4,096 plus an index.
//!
//! The opening request carries the proof and is sent once, as in `fronted`, and when `down.mode` is `sse` it is a stream request: its answer is the first stream. The session reads the shape from the profile and builds every request from it. It does not look at the node's answers to learn a shape, and it never builds two requests under one `n`: a request is sealed once, its bytes are kept until it is answered, and what has to go again goes as those bytes. A stream request is never resent, a new one takes a new `n`.
//! A stream that does not work is not latched: the session polls, the candidate is marked for an hour, and the mark is logged and ends. "Nothing is latched for good."
//! Every answer is read inside bounds that are checked before a buffer grows: the head of an answer, its length, the chunked coding of a stream, its lines and its events.
use crate::fronted::{exchange, slower, spread, POLL};
use crate::http::{self, Stop, CHROME, PLATFORM};
use crate::{fingerprint::Stream as Conn, lone, pause, random, tls, unasked, wide, Answer, Ask, End, Ended, Fault, Front, Hook, Kind, Link, Port, Refusal, Unreachable, Want, ATTEMPT};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rustls::RootCertStore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{ChunkError, Padding, MAX_ITEMS, MAX_PLAINTEXT, TAG};
use veilway_proto::proof::{self, Name};
use veilway_proto::session::{LIVENESS, LONE_KEEPALIVE};
use veilway_proto::shape::Shape;
use veilway_proto::shaped::{self as wire, Parts, Writer};
use veilway_proto::sse;

/// "Stream with no byte: the client ends it after 60 s."
const SILENCE: Duration = Duration::from_secs(60);
/// "Wait for the first event: 5 s from the opening request."
const FIRST_EVENT: Duration = Duration::from_secs(5);
/// "Streams that end early: 3 in a row that lasted under 10 s each end the stream attempt."
const SHORT: Duration = Duration::from_secs(10);
const SHORT_RUN: usize = 3;
/// "Retry of a stream after a fallback: 1 hour on that network, with the candidate that failed."
const RETRY: Duration = Duration::from_secs(3_600);
/// "Opens a new session before `n` would pass 4,000,000,000."
const NUMBER_LAST: u32 = 4_000_000_000;
/// How many messages of the streams wait for the session at most: a stream that is read faster than the session takes its events waits, and the TCP connection with it.
const EVENTS: usize = 64;
// How often the bytes of one later request are sent again on a new connection, inside the 10 s the request has.
const REPEATS: usize = 3;

// The candidates whose streams did not work, and until when: what a later session on the same candidate starts from. A session that is told the network moved forgets its candidate's mark.
static MARKS: Mutex<Vec<(SocketAddr, Instant)>> = Mutex::new(Vec::new());

// Until when the candidate at `address` is marked, if it is. A mark that has run out is forgotten.
fn marked(address: SocketAddr) -> Option<Instant> {
	let mut marks = MARKS.lock().unwrap_or_else(|e| e.into_inner());
	marks.retain(|(_, until)| *until > Instant::now());
	marks.iter().find(|(marked, _)| *marked == address).map(|(_, until)| *until)
}

// How a stream, or the start of one, came to its end.
enum Over {
	/// The front or the node answered with something that is no event stream and no answer a session goes on after: a status other than 200, bytes that are no HTTP.
	Refused(Answer),
	/// A `200` that is no stream: another content type, a length, a coding or a `Transfer-Encoding` other than `chunked`. "A stream that did not start."
	Unstarted,
	/// A limit of the reader was broken.
	Broke,
	/// 60 s without a byte.
	Silent,
	/// The connection ended or was reset.
	Cut,
	/// The last chunk of the stream was read: the node ended it, as it ends a stream that is replaced, runs out of life or events.
	Ended,
	/// The connection could not be made.
	Dial(Ended),
	/// The request was written and no head came in the time the stream has for it.
	Late,
	/// The session told the task to stop.
	Gone,
}

// What a flight comes to: the answer of a request that is no stream request, with the connection to keep, or how a stream ended.
enum Flown {
	Answer(u32, Option<Conn>, Result<Vec<u8>, Ended>),
	Stream(u32, Over),
}

// What a stream task tells the session while it runs.
enum Msg {
	/// The head of the stream is there and is right: this request is answered.
	Head(u32),
	/// An event: the stream request's number, its place in its stream, the sealed chunk.
	Event(u32, usize, Vec<u8>),
}

// A stream while it is the live one, and what ends it.
struct Live {number: u32, since: Instant, kill: Arc<Notify>}

// What the session knows of a request in flight beyond its bytes: whether it asks for a stream, and how many datagrams it carries.
struct Meta {stream: bool, taken: usize}

// Writes one request, reads the head of the answer within `wait` of the moment the request left, and checks it is the head of an event stream. What is left of the bytes read behind the head comes back with the connection, and so does the moment the request was written.
async fn start(candidate: &Front, roots: &Arc<RootCertStore>, hook: &Option<Hook>, request: &[u8], deadline: Instant, wait: Duration) -> Result<(Conn, Vec<u8>, Instant), Over> {
	let mut io = tls::dial(candidate, roots, hook, deadline, false).await.map_err(Over::Dial)?;
	if io.write_all(request).await.is_err() || io.flush().await.is_err() {return Err(Over::Cut)}
	let (mut buf, written) = (Vec::new(), Instant::now());
	let end = match timeout_at(written + wait, http::answer(&mut io, &mut buf)).await {
		Ok(Ok(end)) => end,
		Ok(Err(Stop::Said(answer))) => return Err(Over::Refused(answer)),
		Ok(Err(Stop::Cut)) => return Err(Over::Cut),
		Err(_) => return Err(Over::Late),
	};
	let head = http::head(&buf[..end]).ok_or(Over::Refused(Answer::NotHttp))?;
	match http::stream_head(&head) {
		Ok(()) => Ok((io, buf.split_off(end), written)),
		Err(Answer::Body) => Err(Over::Unstarted),
		Err(answer) => Err(Over::Refused(answer)),
	}
}

// Reads a stream to its end and tells the session each event as it completes. The reader's limits are the page's, and 60 s without a byte is the end.
async fn pump(mut io: Conn, mut pending: Vec<u8>, number: u32, tx: &mpsc::Sender<Msg>, kill: &Notify) -> Over {
	let (mut reader, mut events, mut bytes) = (sse::Reader::new(), Vec::new(), vec![0u8; 16_384]);
	loop {
		if !pending.is_empty() {
			let result = reader.feed(&pending, &mut events);
			pending.clear();
			let first = reader.events() - events.len();
			for (offset, sealed) in events.drain(..).enumerate() {
				if tx.send(Msg::Event(number, first + offset, sealed)).await.is_err() {return Over::Gone}
			}
			match result {
				Ok(true) => return Over::Ended,
				Ok(false) => {}
				Err(_) => return Over::Broke,
			}
		}
		tokio::select! {
			biased;
			_ = kill.notified() => return Over::Gone,
			read = timeout(SILENCE, io.read(&mut bytes)) => match read {
				Err(_) => return Over::Silent,
				Ok(Ok(0) | Err(_)) => return Over::Cut,
				Ok(Ok(count)) => pending.extend_from_slice(&bytes[..count]),
			},
		}
	}
}

// One request and its answer, on a connection that is kept from the one before or made now. "A request whose connection failed is sent again as the identical bytes on a new connection, up to 3 times inside 10 s." Without a valid answer inside `limit` the session is lost.
async fn flight(candidate: Front, roots: Arc<RootCertStore>, hook: Option<Hook>, mut conn: Option<Conn>, request: Vec<u8>, number: u32, limit: Instant) -> Flown {
	let (mut buf, mut repeats) = (Vec::new(), 0);
	let answered = timeout_at(limit, async {
		loop {
			if conn.is_none() {conn = Some(tls::dial(&candidate, &roots, &hook, limit, false).await.map_err(|_| Ended::Closed(End::Lost))?)}
			let Some(io) = conn.as_mut() else {return Err(Ended::Closed(End::Lost))};
			match exchange(io, &request, &mut buf, &mut false).await {
				Ok((body, close)) => {
					if close {conn = None}
					return Ok(buf[body].to_vec());
				}
				Err(Stop::Said(Answer::Closed) | Stop::Cut) if repeats < REPEATS => (conn, repeats) = (None, repeats + 1),
				Err(Stop::Said(Answer::Closed | Answer::Status(_)) | Stop::Cut) => return Err(Ended::Closed(End::Lost)),
				Err(_) => return Err(Ended::Closed(End::Fault(Fault::Response))),
			}
		}
	}).await.unwrap_or(Err(End::Lost.into()));
	Flown::Answer(number, conn, answered)
}

/// A request as Chrome's `fetch` from a page of the same host writes it, with the differences the page names: the method of the shape, `Content-Type` and `Content-Length` only with a body, the header field of a `header` shape, and `Accept: text/event-stream` with `Cache-Control: no-cache` on a stream request. Chrome sends no `Origin` with a same-origin `GET`.
pub(crate) fn http_request(shape: &Shape, host: &str, parts: &Parts, stream: bool) -> Vec<u8> {
	let (_, platform, mobile, _) = PLATFORM;
	let (length, kind) = if shape.bodied() {(format!("Content-Length: {}\r\n", parts.body.len()), "Content-Type: application/octet-stream\r\n")} else {(String::new(), "")};
	let custom = match (&shape.up.name, &parts.header) {
		(Some(name), Some(value)) => format!("{name}: {value}\r\n"),
		_ => String::new(),
	};
	let (accept, cache) = if stream {("text/event-stream", "Cache-Control: no-cache\r\n")} else {("*/*", "")};
	let origin = if shape.up.method == "GET" {String::new()} else {format!("Origin: https://{host}\r\n")};
	[format!("{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n{length}sec-ch-ua-platform: {platform}\r\n{}sec-ch-ua: \"Google Chrome\";v=\"{CHROME}\", \"Chromium\";v=\"{CHROME}\", \"Not(A:Brand\";v=\"24\"\r\n{kind}sec-ch-ua-mobile: {mobile}\r\n{custom}Accept: {accept}\r\n{cache}{origin}Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nReferer: https://{host}/\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n", shape.up.method, parts.target, http::user_agent()).as_bytes(), &parts.body].concat()
}

// A time drawn from a range of seconds, as the page writes the length of a stream.
fn seconds(range: &std::ops::RangeInclusive<u32>) -> Duration {pause(&(range.start().saturating_mul(1_000)..=range.end().saturating_mul(1_000))).unwrap_or_default()}

pub(crate) async fn run(port: &mut Port, link: &Link, path: &str, candidate: &Front, shape: &Shape) -> Ended {
	let (dialled, Some(node), host) = (Instant::now() + ATTEMPT, link.node, tls::host(candidate)) else {return End::Source.into()};
	// Everything the session needs of others is taken before anything is dialled.
	let (Ok(proof), Ok(padding), Some(first)) = (proof::Client::new(&node, link.secret.expose(), &link.inbound, &link.device).prove(Name::FrontedShaped, (port.env.now)(), &mut random), Padding::new(link.padding.wide_max, link.padding.normal_max, &mut random), port.want(Want::First)) else {return End::Source.into()};
	let (roots, hook, keepalive, sid) = (port.env.roots.clone(), port.env.socket.clone(), lone(&first), URL_SAFE_NO_PAD.encode(proof.keys.sid));
	let (mut writer, s2c) = (Writer::new(proof.keys.c2s, padding), proof.keys.s2c);
	// "It opens a session with an opening request that is a stream request when `down.mode` is `sse`." A candidate whose streams did not work lately is polled until the mark runs out.
	let mut retry_at = marked(candidate.address).filter(|_| shape.streamed());
	let mut streaming = shape.streamed() && retry_at.is_none();
	let mut body = Vec::new();
	if writer.append(0, 0, &[&first], wide(Kind::Packet {flow: 0, control: false}, &first), wire::capacity(shape, path.len(), proof.token.len()), &mut random, &mut body).is_err() {return End::Source.into()}
	let Ok(Some(parts)) = Parts::build(shape, path, &proof.token, &body, &mut random) else {return End::Source.into()};
	let (request, mut scratch) = (http_request(shape, &host, &parts, streaming), Vec::new());
	// The opening request. A session is open "when a chunk from the node has opened", and the node's first answer comes when WireGuard has authenticated. Its 10 s run from the moment the request is written.
	let opening = async {
		if streaming {
			// "The opening request's stream must answer with its head and first event within 5 s of the client sending it."
			match start(candidate, &roots, &hook, &request, Instant::now() + ATTEMPT, FIRST_EVENT).await {
				Ok(stream) => Ok((None, Some(stream))),
				Err(Over::Late) => Ok((None, None)),
				Err(Over::Refused(answer)) => Err(Ended::Refused(Refusal {answer, offset: None})),
				Err(Over::Unstarted) => Err(Ended::Refused(Refusal {answer: Answer::Body, offset: None})),
				Err(Over::Dial(ended)) => Err(ended),
				Err(_) => Err(Ended::Unreachable(Unreachable::Cut)),
			}
		} else {
			let (mut io, mut written, mut buf) = (tls::dial(candidate, &roots, &hook, dialled, false).await?, false, Vec::new());
			match timeout(ATTEMPT, exchange(&mut io, &request, &mut buf, &mut written)).await {
				Ok(Ok((body, close))) => Ok((Some((io, buf[body].to_vec(), close)), None)),
				Ok(Err(Stop::Said(answer))) => Err(Ended::Refused(Refusal {answer, offset: None})),
				Ok(Err(Stop::Cut)) => Err(Ended::Unreachable(Unreachable::Cut)),
				// The proof was taken if it arrived, and a node that knows the tunnel answers. Silence behind a keepalive is a node that does not.
				Err(_) if written && keepalive => Err(End::Unanswered.into()),
				Err(_) => Err(Ended::Unreachable(Unreachable::Timeout)),
			}
		}
	};
	// A session that is closed or dropped while it opens stops here.
	let (answered, stream) = match unasked(&mut port.ask, opening).await {
		Some(Ok(opened)) => opened,
		Some(Err(ended)) => return ended,
		None => return End::Asked.into(),
	};
	let (mut flights, (tx, mut msgs), mut pool, mut meta, mut kills) = (JoinSet::<Flown>::new(), mpsc::channel::<Msg>(EVENTS), Vec::<Conn>::new(), HashMap::<u32, Meta>::new(), HashMap::<u32, Arc<Notify>>::new());
	let (mut live, mut first_deadline, mut inflight, mut renew_at): (Option<Live>, Option<Instant>, usize, Option<Instant>) = (None, None, 0, None);
	let ended = 'session: {
		// Set when the client goes from a stream to polling: the first request after it carries "no stream", so that the node drops a stream a front is keeping open (the held answer of a CDN that buffers) and puts the data in the answers.
		let mut leave = false;
		let (polled, streamed) = (answered.is_some(), stream.is_some());
		if let Some((io, body, close)) = answered {
			// A polled answer to the opening request: the node's first chunks, at the numbers of request 0.
			if !close {pool.push(io)}
			match wire::open(&s2c, 0, &body, &mut scratch) {
				Ok(chunks) => {
					port.heard();
					port.sent(1);
					for datagram in chunks.into_iter().flatten() {port.deliver(datagram)}
				}
				Err(_) => break 'session Ended::Refused(Refusal {answer: Answer::Body, offset: None}),
			}
		}
		// "If there is nothing, the client ends the stream's connection and goes on with `poll` for this session." The opening request is not sent again, and the datagram it carried is lost with its answer: WireGuard sends the initiation again.
		if streaming && !polled && !streamed {
			if !shape.down.fallback {break 'session End::Lost.into()}
			let until = Instant::now() + RETRY;
			MARKS.lock().unwrap_or_else(|e| e.into_inner()).push((candidate.address, until));
			tracing::info!("fronted-shaped: the stream gave nothing in time, polling for an hour");
			(streaming, retry_at, leave) = (false, Some(until), true);
			port.sent(1);
		}
		if let Some((io, left, written)) = stream {
			port.sent(1);
			let (stream_tx, kill) = (tx.clone(), Arc::new(Notify::new()));
			let watched = kill.clone();
			flights.spawn(async move {Flown::Stream(0, pump(io, left, 0, &stream_tx, &watched).await)});
			kills.insert(0, kill.clone());
			let life = seconds(&shape.down.life);
			live = Some(Live {number: 0, since: Instant::now(), kill});
			(first_deadline, renew_at) = (Some(written + FIRST_EVENT), Some(Instant::now() + life.saturating_sub(pause(&(0..=3_000)).unwrap_or_default())));
		}
		// "A client never polls faster than the first wait": the first poll too comes a wait after the answer before it.
		let (mut number, mut wait, mut pending, mut held, mut gather_at, mut due, mut closing) = (0u32, POLL, Vec::<(Vec<u8>, Kind)>::new(), None::<(Vec<u8>, Instant)>, None::<Instant>, Instant::now() + POLL, false);
		let (mut waiting_stream, mut short) = (false, 0usize);
		if live.is_some() {due = Instant::now() + pause(&link.padding.keepalive).unwrap_or_default()}
		loop {
			let now = Instant::now();
			// "If 3 streams in a row last under 10 s each, the client stops asking for streams for this session and polls", with a mark that runs out in an hour.
			if streaming && short >= SHORT_RUN {
				if !shape.down.fallback {break 'session End::Lost.into()}
				let until = now + RETRY;
				MARKS.lock().unwrap_or_else(|e| e.into_inner()).push((candidate.address, until));
				tracing::info!("fronted-shaped: streams do not work on this candidate, polling for an hour");
				(streaming, retry_at, short, leave) = (false, Some(until), 0, true);
				if let Some(live) = live.take() {live.kill.notify_one()}
			}
			if leave {
				leave = false;
				pending.insert(0, (wire::NO_STREAM.to_vec(), Kind::Packet {flow: 0, control: false}));
				gather_at.get_or_insert(now);
			}
			// What goes out now: a stream request when the stream is due or gone, the datagrams that waited the gather time, and a poll or a keepalive when the session has been silent for its wait. Never more requests than `up.inflight`, a stream request waiting for its answer among them.
			while inflight < usize::from(shape.up.inflight) && number < NUMBER_LAST {
				let stream_due = streaming && !waiting_stream && (live.is_none() || renew_at.is_some_and(|at| at <= now));
				let data_due = !pending.is_empty() && gather_at.is_some_and(|at| at <= now);
				let silent = due <= now && pending.is_empty() && if streaming {live.is_some()} else {inflight == 0};
				if !(stream_due || data_due || silent) {break}
				pending.extend(held.take().map(|(datagram, _)| (datagram, Kind::Packet {flow: 0, control: false})));
				let (who, mut request_body) = (format!("{sid}.{}", number + 1), Vec::new());
				let capacity = wire::capacity(shape, path.len(), who.len());
				// The datagrams that wait, in chunks of what one chunk holds or what is left of the request, for as long as chunks fit the request. One padding-only chunk when nothing waits.
				let (mut taken, mut index) = (0, 0);
				while taken < pending.len() {
					let (mut count, mut used, room) = (0, 0, capacity.saturating_sub(request_body.len() + 2 + TAG).min(MAX_PLAINTEXT));
					for (datagram, _) in &pending[taken..] {
						if used + 2 + datagram.len() > room || count == MAX_ITEMS {break}
						(count, used) = (count + 1, used + 2 + datagram.len());
					}
					if count == 0 {break}
					let items: Vec<&[u8]> = pending[taken..taken + count].iter().map(|(datagram, _)| &datagram[..]).collect();
					match writer.append(number + 1, index, &items, pending[taken..taken + count].iter().any(|(datagram, kind)| wide(*kind, datagram)), capacity, &mut random, &mut request_body) {
						Ok(()) => (taken, index) = (taken + count, index + 1),
						Err(ChunkError::Size) => break,
						Err(_) => break 'session End::Random.into(),
					}
				}
				// A datagram that cannot fit a request of this shape even alone is dropped and counted, not tried for ever. Nothing was sealed under this number, so it is still the next one.
				if taken == 0 && !pending.is_empty() {
					pending.remove(0);
					port.dropped(1);
					continue;
				}
				if taken == 0 && writer.append(number + 1, 0, &[], false, capacity, &mut random, &mut request_body).is_err() {break 'session End::Exhausted.into()}
				number += 1;
				pending.drain(..taken);
				port.sent(taken);
				let Ok(Some(parts)) = Parts::build(shape, path, &who, &request_body, &mut random) else {break 'session End::Exhausted.into()};
				let (request, limit) = (http_request(shape, &host, &parts, stream_due), Instant::now() + LIVENESS);
				meta.insert(number, Meta {stream: stream_due, taken});
				inflight += 1;
				if stream_due {
					// "A stream request is never repeated": it is written once, and a stream that does not start is replaced by a new request with a new `n`.
					waiting_stream = true;
					let (candidate, roots, hook, stream_tx, kill) = (candidate.clone(), roots.clone(), hook.clone(), tx.clone(), Arc::new(Notify::new()));
					kills.insert(number, kill.clone());
					flights.spawn(async move {
						match start(&candidate, &roots, &hook, &request, limit, LIVENESS).await {
							Ok((io, left, _)) => {
								let _ = stream_tx.send(Msg::Head(number)).await;
								Flown::Stream(number, pump(io, left, number, &stream_tx, &kill).await)
							}
							Err(over) => Flown::Stream(number, over),
						}
					});
				} else {
					// Whatever a front sent since the last answer, nobody asked for: a connection with a byte waiting on it, or one that has ended, is given up before the request is written.
					let mut conn = pool.pop();
					if let Some(io) = conn.as_mut() {
						if timeout(Duration::ZERO, io.read(&mut [0u8; 1])).await.is_ok() {conn = None}
					}
					flights.spawn(flight(candidate.clone(), roots.clone(), hook.clone(), conn, request, number, limit));
				}
				gather_at = if pending.is_empty() {None} else {Some(now)};
				due = Instant::now() + if streaming {pause(&link.padding.keepalive).unwrap_or_default()} else {spread(wait).unwrap_or(POLL)};
			}
			if closing && pending.is_empty() && held.is_none() && inflight == 0 {break 'session End::Asked.into()}
			if number >= NUMBER_LAST && inflight == 0 {break 'session End::Exhausted.into()}
			let next = [gather_at.filter(|_| !pending.is_empty()), Some(due), held.as_ref().map(|held| held.1), first_deadline, renew_at.filter(|_| streaming && !waiting_stream), retry_at.filter(|_| !streaming)].into_iter().flatten().min().unwrap_or(now + POLL);
			tokio::select! {
				sent = port.out.recv(), if !closing => match sent {
					None => closing = true,
					Some((datagram, _)) if !port.fits(&datagram) => port.dropped(1),
					Some((datagram, _)) if lone(&datagram) && held.is_none() => match pause(&LONE_KEEPALIVE) {
						Ok(delay) => held = Some((datagram, Instant::now() + delay)),
						Err(end) => break 'session end.into(),
					},
					Some(sent) => {
						pending.push(sent);
						if gather_at.is_none() {
							match pause(&shape.up.gather) {
								Ok(gather) => gather_at = Some(Instant::now() + gather),
								Err(end) => break 'session end.into(),
							}
						}
					}
				},
				asked = port.ask.recv() => match asked {
					// The network moved: what was learnt about streams on the old one is not carried over.
					Some(Ask::Moved) => MARKS.lock().unwrap_or_else(|e| e.into_inner()).retain(|(address, _)| *address != candidate.address),
					_ => closing = true,
				},
				Some(done) = flights.join_next(), if !flights.is_empty() => {
					let Ok(flown) = done else {continue};
					match flown {
						Flown::Answer(n, conn, result) => {
							inflight = inflight.saturating_sub(1);
							let Some(request) = meta.remove(&n) else {continue};
							let body = match result {
								Ok(body) => body,
								Err(ended) => break 'session ended,
							};
							if let Some(io) = conn {pool.push(io)}
							// "A late answer is a valid answer."
							let chunks: Vec<Vec<u8>> = if body.len() == wire::LATE_SIZE && wire::is_late(&s2c, n, &body) {Vec::new()} else {
								match wire::open(&s2c, n, &body, &mut scratch) {
									Ok(chunks) => chunks.into_iter().flatten().map(<[u8]>::to_vec).collect(),
									Err(_) => break 'session End::Fault(Fault::Chunk).into(),
								}
							};
							port.heard();
							let empty = chunks.is_empty();
							for datagram in &chunks {port.deliver(datagram)}
							// "`fronted` poll wait": it returns to its start after an answer that carried a datagram and after a request that carried one.
							wait = slower(wait, empty && request.taken == 0);
							if !streaming {due = Instant::now() + spread(wait).unwrap_or(POLL)}
						}
						Flown::Stream(n, over) => {
							kills.remove(&n);
							// A stream request that was never answered leaves its place among the requests in flight; one that was answered left it at its head.
							let unanswered = meta.remove(&n).is_some_and(|request| request.stream);
							if unanswered {
								inflight = inflight.saturating_sub(1);
								waiting_stream = false;
							}
							let ours = live.as_ref().is_some_and(|live| live.number == n);
							// A stream that was replaced or told to stop ends all the same, and is no failure.
							if matches!(over, Over::Gone) || (!ours && !unanswered) {continue}
							let lasted = live.as_ref().filter(|_| ours).map(|live| live.since.elapsed());
							if ours {live = None}
							// "A request that gets no valid answer within 10 s, or an answer other than `200` with something it can open, makes the session lost."
							match &over {
								Over::Refused(_) | Over::Dial(_) => break 'session End::Lost.into(),
								_ => {}
							}
							// "A stream that ends, resets, has no byte for 60 s or breaks a reading limit is replaced by a new stream request at once, with a new `n`. If 3 streams in a row last under 10 s each, the client stops asking for streams for this session and polls."
							// A stream request that got no head in 10 s is a stream that does not work here: the session polls, and is not lost.
							short = if matches!(over, Over::Late) {SHORT_RUN} else if lasted.is_none_or(|lasted| lasted < SHORT) {short + 1} else {0};
						}
					}
				}
				Some(msg) = msgs.recv() => match msg {
					Msg::Head(n) => {
						// "The old one ends when the new one has answered": the newer stream is the live one from here.
						(inflight, waiting_stream) = (inflight.saturating_sub(1), false);
						meta.remove(&n);
						let (life, early) = (seconds(&shape.down.life), pause(&(0..=3_000)).unwrap_or_default());
						if let Some(kill) = kills.get(&n).cloned() {
							if let Some(older) = live.replace(Live {number: n, since: Instant::now(), kill}) {older.kill.notify_one()}
						}
						renew_at = Some(Instant::now() + life.saturating_sub(early));
					}
					Msg::Event(n, index, mut sealed) => match wire::number(n, index as u64).ok_or(ChunkError::Size).and_then(|number| wire::open_one(&s2c, number, &mut sealed)) {
						Ok(items) => {
							port.heard();
							first_deadline = None;
							for datagram in items {port.deliver(datagram)}
						}
						// "An event that does not decode or open ends the stream and counts as a stream that did not work."
						Err(_) => {
							// An error kill, not a replacement: the stream is dead, and the session does not go on believing it is the live one.
							if let Some(kill) = kills.get(&n) {kill.notify_one()}
							if live.as_ref().is_some_and(|live| live.number == n) {live = None}
							short += 1;
						}
					},
				},
				_ = sleep_until(next) => {
					if first_deadline.is_some_and(|at| at <= Instant::now()) {
						// "If there is nothing, the client ends the stream's connection and goes on with `poll` for this session."
						first_deadline = None;
						if !shape.down.fallback {break 'session End::Lost.into()}
						if let Some(live) = live.take() {live.kill.notify_one()}
						let until = Instant::now() + RETRY;
						MARKS.lock().unwrap_or_else(|e| e.into_inner()).push((candidate.address, until));
						tracing::info!("fronted-shaped: the stream gave no event in time, polling for an hour");
						(streaming, retry_at, leave) = (false, Some(until), true);
					}
					if !streaming && retry_at.is_some_and(|at| at <= Instant::now()) {
						tracing::info!("fronted-shaped: asking for a stream again");
						(streaming, retry_at, short) = (true, None, 0);
					}
					if held.as_ref().is_some_and(|held| held.1 <= Instant::now()) && gather_at.is_none() {gather_at = Some(Instant::now())}
				}
			}
		}
	};
	// A session of `fronted-shaped` has nothing to say at its end: the node forgets it after its idle time. The connections are closed.
	flights.abort_all();
	ended
}

#[cfg(test)]
mod tests {
	use super::*;

	fn shape(text: &str) -> Shape {Shape::parse(text.as_bytes()).unwrap()}

	fn head(shape: &Shape, stream: bool) -> String {
		let parts = Parts {target: "/assets/sync.js?abc.7".into(), header: shape.up.name.as_ref().map(|_| "AAAA".to_string()), body: if shape.bodied() {vec![7; 40]} else {Vec::new()}};
		let request = http_request(shape, "front.example", &parts, stream);
		String::from_utf8_lossy(&request[..request.len() - parts.body.len()]).into_owned()
	}

	fn names(head: &str) -> Vec<&str> {head.split("\r\n").skip(1).filter_map(|line| line.split_once(": ").map(|(name, _)| name)).collect()}

	#[test]
	fn a_request_is_chromes_fetch_with_the_differences_the_page_names() {
		let post = head(&shape(r#"{"up":{"method":"POST","in":"body"},"down":{"mode":"poll"}}"#), false);
		assert!(post.starts_with("POST /assets/sync.js?abc.7 HTTP/1.1\r\nHost: front.example\r\nConnection: keep-alive\r\nContent-Length: 40\r\n"), "{post}");
		assert_eq!(names(&post), ["Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"], "{post}");
		assert!(post.contains("Accept: */*\r\n") && !post.contains("event-stream") && !post.contains("Cache-Control"));
		// A request without a body has neither `Content-Type` nor `Content-Length`, and a same-origin GET has no `Origin`, as Chrome's has none.
		let get = head(&shape(r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll"}}"#), false);
		assert!(get.starts_with("GET /assets/sync.js?abc.7 HTTP/1.1\r\n") && !get.contains("Content-") && !get.contains("Origin"), "{get}");
		assert_eq!(names(&get), ["Host", "Connection", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"], "{get}");
		// A custom method keeps its `Origin`, and a header shape carries its field.
		let custom = head(&shape(r#"{"up":{"method":"DELETE","in":"header","name":"X-Hint"},"down":{"mode":"poll"}}"#), false);
		assert!(custom.starts_with("DELETE ") && custom.contains("X-Hint: AAAA\r\n") && custom.contains("Origin: https://front.example\r\n") && !custom.contains("Content-Length"), "{custom}");
		// A request that asks for a stream says so as `EventSource` and a streaming `fetch` do.
		let stream = head(&shape(r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"sse"}}"#), true);
		assert!(stream.contains("Accept: text/event-stream\r\nCache-Control: no-cache\r\n") && !stream.contains("Accept: */*"), "{stream}");
		// Exactly one length, and the fields are Chrome's.
		assert_eq!(post.to_ascii_lowercase().matches("content-length").count(), 1);
		assert!(post.contains(&format!("Chrome/{CHROME}.0.0.0 ")) && post.contains("Origin: https://front.example\r\n") && post.contains("Referer: https://front.example/\r\n"));
	}

	#[tokio::test(start_paused = true)]
	async fn a_mark_of_a_stream_that_did_not_work_runs_out_in_an_hour() {
		let address: SocketAddr = "192.0.2.77:443".parse().unwrap();
		assert_eq!(marked(address), None);
		let until = Instant::now() + RETRY;
		MARKS.lock().unwrap().push((address, until));
		assert_eq!(marked(address), Some(until));
		// Another candidate is not marked, and the mark is there until the hour is over.
		assert_eq!(marked("192.0.2.78:443".parse().unwrap()), None);
		tokio::time::advance(RETRY - Duration::from_secs(1)).await;
		assert_eq!(marked(address), Some(until));
		tokio::time::advance(Duration::from_secs(2)).await;
		assert_eq!(marked(address), None);
		assert!(!MARKS.lock().unwrap().iter().any(|(marked, _)| *marked == address));
	}
}
