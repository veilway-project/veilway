//! The client of `fronted` (transports page, "`fronted`", "State machine", the client's four rules): HTTP/1.1 requests over TLS to the front, one in flight, with the tunnel's datagrams in the bodies.
//!
//! The opening request carries the proof and is sent once: "A CDN's repeat of an opening request is therefore refused as a replay." Anything but a `200` with a body the session opens is a refusal there, when the TLS session vouches for it: an answer, or a `close_notify`. A connection that is reset or ends without one is cut, which anyone on the path can do, and is unreachable.
//! An opening request that was written whole and is followed by 10 s of silence is unreachable when the session opened with a handshake initiation, and `End::Unanswered` when it opened with a keepalive: the node took the proof and does not know the tunnel.
//! A later request is numbered, and when its connection ends before its answer is whole, the identical bytes go out again on a new connection, since the node answers a repeat from the response it stored. Without a valid answer inside 10 s the session is dropped. So is it by an answer that is not a `200`: the node no longer knows the session.
//! A connection is kept from one request to the next unless the answer says `Connection: close`, and unless the front sent a byte nobody asked for in between: one request is in flight, so nothing stands between two answers.
//! There is no idle keepalive: "the client's polling is the activity, and the response to each request is the sign of life."
use crate::h2::Wire;
use crate::http::{self, Stop, CHROME, HEAD_MAX, PLATFORM};
use crate::{lone, pause, random, tls, unasked, wide, Answer, Ask, End, Ended, Fault, Front, Kind, Link, Port, Refusal, Unreachable, Want, ATTEMPT};
use std::ops::Range;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{ChunkError, Padding, Sealer, MAX_ITEMS, MAX_PLAINTEXT};
use veilway_proto::fronted::{self, Opener, BODY_MAX, REQUEST_MAX};
use veilway_proto::proof::{self, Name};
use veilway_proto::session::{LIVENESS, LONE_KEEPALIVE};
use veilway_proto::subscription::payload::Http2;
use veilway_proto::uniform;

/// "`fronted` poll wait: 100 ms, multiplied by 1.5 per empty response up to 5 s."
pub(crate) const POLL: Duration = Duration::from_millis(100);
pub(crate) const POLL_MAX: Duration = Duration::from_secs(5);
/// "At least one poll a minute", whatever the waits come to.
pub(crate) const POLL_LEAST: Duration = Duration::from_secs(60);
// How often the bytes of one later request are sent again on a new connection, inside the 10 s the request has.
const REPEATS: usize = 3;

// One request with a body: "Both bodies are sent with `Content-Type: application/octet-stream` and a `Content-Length`", and exactly one of the latter.
// The other fields are those of Chrome's `fetch` from a page of the same host. Chrome's `Accept-Encoding` too: the node's answers are `application/octet-stream` of sealed bytes, which fronts do not compress, and an answer that comes with a content coding is refused as a fault.
fn post(path: &str, query: &str, host: &str, body: &[u8]) -> Vec<u8> {
	let (_, platform, mobile, _) = PLATFORM;
	// Google Chrome's brand list for its major version, from Chromium's GREASE algorithm (user_agent_utils.cc, seed = the major version): the permuted order and the "Not(A:Brand" name and version follow from 155. A Chromium build sends the same list without the first brand, which is how the capture was read.
	[format!("POST {path}?{query} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\nContent-Length: {}\r\nsec-ch-ua-platform: {platform}\r\n{}sec-ch-ua: \"Google Chrome\";v=\"{CHROME}\", \"Chromium\";v=\"{CHROME}\", \"Not(A:Brand\";v=\"24\"\r\nContent-Type: application/octet-stream\r\nsec-ch-ua-mobile: {mobile}\r\nAccept: */*\r\nOrigin: https://{host}\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nReferer: https://{host}/\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n", body.len(), http::user_agent()).as_bytes(), body].concat()
}

// Writes one request and reads its answer into `buf`, which then holds nothing else. `written` is set when the request has left whole. Where the body of a `200` lies and whether the answer ends its connection, or how the exchange stopped: by what the peer said, a `close_notify` included, or cut.
// The head is searched as it arrives and read once, and the answer is looked at again only when all of its bytes are there: a front that sends an answer byte by byte costs a read for each byte and no more.
pub(crate) async fn exchange(io: &mut (impl AsyncRead + AsyncWrite + Unpin), request: &[u8], buf: &mut Vec<u8>, written: &mut bool) -> Result<(Range<usize>, bool), Stop> {
	let (mut read, mut found, mut whole) = (vec![0u8; 16_384], false, None);
	buf.clear();
	if io.write_all(request).await.is_err() || io.flush().await.is_err() {return Err(Stop::Cut)}
	*written = true;
	loop {
		if whole.is_none() && (found || buf.len() >= HEAD_MAX) {whole = http::whole(buf).map_err(Stop::Said)?}
		if whole.is_some_and(|whole| buf.len() >= whole) {
			let body = http::response(buf).map_err(Stop::Said)?.ok_or(Stop::Said(Answer::Body))?;
			return Ok((body.clone(), http::head(&buf[..body.start]).is_some_and(|head| head.closes())));
		}
		match io.read(&mut read).await {
			Ok(0) => return Err(Stop::Said(Answer::Closed)),
			Ok(count) => {
				buf.extend_from_slice(&read[..count]);
				found |= http::headed(buf, count);
			}
			Err(_) => return Err(Stop::Cut),
		}
	}
}

/// The wait before the next poll: the first wait after an answer that carried something, and half as long again, up to 5 s, after one that did not.
pub(crate) fn slower(wait: Duration, empty: bool) -> Duration {if empty {wait.mul_f64(1.5).min(POLL_MAX)} else {POLL}}

// "Each wait multiplied by a number drawn uniformly from 0.75 to 1.25."
pub(crate) fn spread(wait: Duration) -> Result<Duration, End> {Ok((wait * uniform(750, 1250, &mut random).map_err(|_| End::Random)? / 1000).min(POLL_LEAST))}

pub(crate) async fn run(port: &mut Port, link: &Link, path: &str, candidate: &Front) -> Ended {
	let (dialled, Some(node), host) = (Instant::now() + ATTEMPT, link.node, tls::host(candidate)) else {return End::Source.into()};
	// Everything the session needs of others is taken before anything is dialled.
	let (Ok(proof), Ok(padding), Some(first)) = (proof::Client::new(&node, link.secret.expose(), &link.inbound, &link.device).prove(Name::Fronted, (port.env.now)(), &mut random), Padding::new(link.padding.wide_max, link.padding.normal_max, &mut random), port.want(Want::First)) else {return End::Source.into()};
	let (mut sealer, mut opener, mut body, mut buf, mut scratch) = (Sealer::new(proof.keys.c2s, padding), Opener::new(proof.keys.s2c), Vec::new(), Vec::new(), Vec::new());
	if fronted::append(&mut sealer, &[&first], wide(Kind::Packet {flow: 0, control: false}, &first), &mut random, &mut body).is_err() {return End::Source.into()}
	let (request, roots, hook, keepalive, h2) = (post(path, &proof.token, &host, &body), port.env.roots.clone(), port.env.socket.clone(), lone(&first), candidate.http2 != Http2::Off);
	// The opening request. A session is open "when a chunk from the node has opened", and the node's first answer comes when WireGuard has authenticated. Its 10 s run from the moment the request is written.
	let opening = async {
		let (mut io, mut written) = (Wire::of(tls::dial(candidate, &roots, &hook, dialled, h2).await?), false);
		match timeout(ATTEMPT, io.exchange(&request, &host, &mut buf, &mut written)).await {
			Ok(Ok((body, close))) => Ok((io, body, close)),
			Ok(Err(Stop::Said(answer))) => Err(Ended::Refused(Refusal {answer, offset: None})),
			Ok(Err(Stop::Cut)) => Err(Ended::Unreachable(Unreachable::Cut)),
			// The proof was taken if it arrived, and a node that knows the tunnel answers. Silence behind a keepalive is a node that does not.
			Err(_) if written && keepalive => Err(End::Unanswered.into()),
			Err(_) => Err(Ended::Unreachable(Unreachable::Timeout)),
		}
	};
	// A session that is closed or dropped while it opens stops here.
	let (io, opened, close) = match unasked(&mut port.ask, opening).await {
		Some(Ok(opened)) => opened,
		Some(Err(ended)) => return ended,
		None => return End::Asked.into(),
	};
	let mut io = Some(io).filter(|_| !close);
	let ended = 'session: {
		match opener.open(&buf[opened], &mut scratch) {
			Ok(opened) => {
				port.heard();
				port.sent(1);
				for datagram in opened.commit().into_iter().flatten() {port.deliver(datagram)}
			}
			// No candidate of `fronted` has a pin, so no `Date` is read here.
			Err(_) => break 'session Ended::Refused(Refusal {answer: Answer::Body, offset: None}),
		}
		// "A client never polls faster than the first wait": the first poll too comes a wait after the answer before it.
		// `closing` says the caller closed the session: what it handed over before is sent in one more request, and then the session is over.
		let (mut number, mut wait, mut pending, mut held, mut due, mut closing) = (0u32, POLL, Vec::<(Vec<u8>, Kind)>::new(), None::<(Vec<u8>, Instant)>, Instant::now() + POLL, false);
		loop {
			// "Sends at once when it has data and no request is in flight. When idle it polls with the waits." A lone keepalive is no data: it joins the next request, or goes when its delay is over.
			while pending.is_empty() && !closing {
				tokio::select! {
					sent = port.out.recv() => match sent {
						None => closing = true,
						Some((datagram, _)) if !port.fits(&datagram) => port.dropped(1),
						Some((datagram, _)) if lone(&datagram) && held.is_none() => match pause(&LONE_KEEPALIVE) {
							Ok(delay) => held = Some((datagram, Instant::now() + delay)),
							Err(end) => break 'session end.into(),
						},
						Some(sent) => pending.push(sent),
					},
					asked = port.ask.recv() => closing |= !matches!(asked, Some(Ask::Moved | Ask::Power)),
					_ = sleep_until(held.as_ref().map_or(due, |held| held.1.min(due))) => break,
				}
			}
			while let Ok((datagram, kind)) = port.out.try_recv() {if port.fits(&datagram) {pending.push((datagram, kind))} else {port.dropped(1)}}
			pending.extend(held.take().map(|(datagram, _)| (datagram, Kind::Packet {flow: 0, control: false})));
			if closing && pending.is_empty() {break 'session End::Asked.into()}
			// "Opens a new session before `n` would pass its limit."
			if number == REQUEST_MAX {break 'session End::Exhausted.into()}
			number += 1;
			// The body: the waiting datagrams in chunks of what one chunk holds, for as long as chunks fit the body, and one padding-only chunk when nothing waits. What does not fit goes in the next request, at once.
			body.clear();
			let mut taken = 0;
			loop {
				let (mut count, mut used) = (0, 0);
				for (datagram, _) in &pending[taken..] {
					if used + 2 + datagram.len() > MAX_PLAINTEXT || count == MAX_ITEMS {break}
					(count, used) = (count + 1, used + 2 + datagram.len());
				}
				let items: Vec<&[u8]> = pending[taken..taken + count].iter().map(|(datagram, _)| &datagram[..]).collect();
				match fronted::append_within(&mut sealer, &items, pending[taken..taken + count].iter().any(|(datagram, kind)| wide(*kind, datagram)), &mut random, &mut body, io.as_ref().map_or(BODY_MAX, Wire::limit)) {
					Ok(()) => taken += count,
					Err(ChunkError::Size) => break,
					Err(ChunkError::Number) => break 'session End::Exhausted.into(),
					Err(_) => break 'session End::Random.into(),
				}
				if taken == pending.len() {break}
			}
			pending.drain(..taken);
			port.sent(taken);
			let Some(query) = fronted::later_query(&proof.keys.sid, number) else {break 'session End::Exhausted.into()};
			let (request, limit) = (post(path, &query, &host, &body), Instant::now() + LIVENESS);
			// Whatever a front sent since the last answer, nobody asked for: a connection with a byte waiting on it, or one that has ended, is given up before the request is written, and the request goes on a new one.
			if let Some(conn) = io.as_mut() {
				if conn.stale().await {io = None}
			}
			// "Drops the session when a request gets no response within 10 s, or anything but a 200 with a body it can open."
			let asked = timeout_at(limit, async {
				let mut repeats = 0;
				loop {
					if io.is_none() {io = Some(Wire::of(tls::dial(candidate, &roots, &hook, limit, h2).await.map_err(|_| Ended::Closed(End::Lost))?))}
					let Some(conn) = io.as_mut() else {return Err(Ended::Closed(End::Lost))};
					match conn.exchange(&request, &host, &mut buf, &mut false).await {
						Ok((body, close)) => {
							if close {io = None}
							return Ok(body);
						}
						// The connection ended under the request, as a front ends one it kept for too long: the identical bytes are sent again, and the node answers them once.
						Err(Stop::Said(Answer::Closed) | Stop::Cut) if repeats < REPEATS => (io, repeats) = (None, repeats + 1),
						Err(Stop::Said(Answer::Closed | Answer::Status(_)) | Stop::Cut) => return Err(Ended::Closed(End::Lost)),
						Err(_) => return Err(Ended::Closed(End::Fault(Fault::Response))),
					}
				}
			});
			// A request that is in flight is waited for, also when the caller closes meanwhile: one request is in flight, and its 10 s are its bound.
			let answered = {
				tokio::pin!(asked);
				loop {
					tokio::select! {
						answered = &mut asked => break answered.unwrap_or(Err(End::Lost.into())),
						said = port.ask.recv(), if !closing => closing |= !matches!(said, Some(Ask::Moved | Ask::Power)),
					}
				}
			};
			let body = match answered {
				Ok(body) => body,
				Err(ended) => break 'session ended,
			};
			let chunks = match opener.open(&buf[body], &mut scratch) {
				Ok(opened) => opened.commit(),
				Err(_) => break 'session End::Fault(Fault::Chunk).into(),
			};
			port.heard();
			let mut empty = true;
			for datagram in chunks.into_iter().flatten() {
				empty = false;
				port.deliver(datagram);
			}
			// "`fronted` poll wait": the page says when the wait grows and not when it returns to its start. Here it does after an answer that carried a datagram and after a request that carried one, since what was sent is likely to be answered soon.
			wait = slower(wait, empty && taken == 0);
			due = match spread(wait) {
				Ok(spread) => Instant::now() + spread,
				Err(end) => break 'session end.into(),
			};
		}
	};
	// A session of `fronted` has nothing to say at its end: the node forgets it after its idle time. The connection is closed in order.
	if let Some(mut io) = io {io.close().await}
	ended
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_poll_waits() {
		let mut wait = POLL;
		let mut waits = Vec::new();
		for _ in 0..12 {
			wait = slower(wait, true);
			waits.push(wait.as_millis());
		}
		assert_eq!(waits, [150, 225, 337, 506, 759, 1139, 1708, 2562, 3844, 5000, 5000, 5000]);
		assert_eq!(slower(POLL_MAX, false), POLL);
		// "Each wait multiplied by a number drawn uniformly from 0.75 to 1.25": the longest is 6.25 s, far below the node's idle time of 60 s and the client's 10 s.
		for _ in 0..500 {
			let (short, long) = (spread(POLL).unwrap(), spread(POLL_MAX).unwrap());
			assert!((75..=125).contains(&short.as_millis()) && (3_750..=6_250).contains(&long.as_millis()), "{short:?} {long:?}");
		}
		assert_eq!(spread(Duration::from_secs(600)), Ok(POLL_LEAST));
	}

	#[test]
	fn a_request_has_exactly_one_length() {
		let request = post("/assets/sync.js", "token", "front.example", &[7; 40]);
		let head = String::from_utf8_lossy(&request[..request.len() - 40]).into_owned();
		assert_eq!(head.to_ascii_lowercase().matches("content-length").count(), 1);
		assert!(head.starts_with("POST /assets/sync.js?token HTTP/1.1\r\nHost: front.example\r\nConnection: keep-alive\r\nContent-Length: 40\r\n"), "{head}");
	}

	#[test]
	fn a_request_has_chromes_fields_in_chromes_order() {
		let request = post("/assets/sync.js", "token", "front.example", &[7; 40]);
		let head = String::from_utf8_lossy(&request[..request.len() - 40]).into_owned();
		let names: Vec<&str> = head.split("\r\n").skip(1).filter_map(|line| line.split_once(": ").map(|(name, _)| name)).collect();
		assert_eq!(names, ["Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"], "{head}");
		assert!(head.contains(&format!("Chrome/{CHROME}.0.0.0 ")) && head.contains(&format!("sec-ch-ua: \"Google Chrome\";v=\"{CHROME}\"")), "{head}");
		assert!(head.contains("Origin: https://front.example\r\n") && head.contains("Referer: https://front.example/\r\n"), "{head}");
	}
}
