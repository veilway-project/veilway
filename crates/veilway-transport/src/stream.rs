//! The client of `tls` and `ws` (transports page, "WebSocket session", "Closing", "`tls`", "`ws`"): one connection, one upgrade request with a fresh proof, and then chunks in masked binary frames.
//!
//! The two transports are one session here. They differ in the name the proof is made for and in what `tls` (the module) checks of the certificate, and in nothing else.
//!
//! How an attempt is classified ("Refusals and clocks", rule 0, and "Transport fallback", rule 1):
//! - No connection, a failed TLS handshake or a certificate that is not accepted: `Unreachable`.
//! - Over validated TLS, any HTTP answer but the expected one, a close with no answer, or bytes that are no answer: `Refused`. A `101` with a wrong accept value is an answer other than the expected one. So is a `101` after which the session is closed before a chunk of the node opened.
//! - A close counts only when the TLS session vouches for it: a `close_notify`, or a WebSocket Close frame. A connection that is reset, or ends without one, at any point after the handshake and before a chunk of the node, is `Unreachable::Cut`: anyone on the path can cause it, and a refusal would hold the client on a candidate that is blocked.
//! - No answer in time: `Unreachable`, since a transport gets 10 s "to carry a chunk from the node". A `101` and no chunk in time is the same when the session opened with a handshake initiation, which a node that took the proof answers. When it opened with a keepalive it is `End::Unanswered`: the node took the proof and does not know the tunnel, as after its restart, and the candidate is tried again at once with an initiation. The 10 s run from the moment the request is written.
//! - A device that cannot dial at all (no route, no socket, a socket hook that failed) is `End::Offline`, and a certificate outside its validity at the device's time is `Unreachable::CertificateTime`: neither is held against the candidate.
//!
//! An open session is lost when its connection ends, when an idle keepalive gets no chunk back within 10 s, and when a handshake WireGuard started because the node stopped answering (`Kind::Stalled`) gets none either: a connection that goes dark without a reset is noticed by that and by nothing else while the caller keeps sending.
use crate::http::{self, Stop, HEAD_MAX};
use crate::{lone, pause, random, tls, unasked, wide, Answer, Ask, End, Ended, Fault, Front, Kind, Link, Port, Refusal, State, Unreachable, Want, ATTEMPT};
use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{ChunkError, Items, Opener, Padding, Sealer, MAX_ITEMS, MAX_PLAINTEXT, MAX_SEALED, TAG};
use veilway_proto::keys::ChunkKey;
use veilway_proto::proof::{self, Name};
use veilway_proto::session::{LIVENESS, LONE_KEEPALIVE};
use veilway_proto::websocket::{self, Header, BINARY, CLOSE, CLOSE_WAIT, NORMAL, PING, PONG};

/// Reads the header of the frame `bytes` begins with, as a client takes one from a node: `Ok(None)` while the header is not all there. The verdict falls at the header, before a byte of the payload is waited for.
/// "A message longer than 16,016 bytes, a text message or a fragmented message ends the session", and so does a frame with a mask, which no server sends, and a binary message too short to be a sealed chunk.
pub fn frame(bytes: &[u8]) -> Result<Option<Header>, Fault> {
	let Some(header) = websocket::header(bytes).map_err(|_| Fault::Frame)? else {return Ok(None)};
	match header.opcode {
		_ if header.mask.is_some() => Err(Fault::Frame),
		BINARY if header.fin && (TAG as u64..=MAX_SEALED as u64).contains(&header.payload) => Ok(Some(header)),
		CLOSE | PING | PONG => Ok(Some(header)),
		_ => Err(Fault::Frame),
	}
}

/// What a frame of the node is to the client.
#[derive(Debug)]
pub enum Read<'a> {
	/// One chunk, with its datagrams: it opened at the number it had to have.
	Chunk(Items<'a>),
	/// A ping, with the payload its pong repeats.
	Ping(&'a [u8]),
	Pong,
	Close,
}

/// The receiving side of a session as the client has it: the bytes of the connection behind the upgrade answer go in, and frames come out, each binary one opened as the next chunk. It keeps one frame at the most, and the first fault is final.
#[derive(Debug)]
pub struct Reader {buf: Vec<u8>, done: usize, opener: Opener, failed: Option<Fault>}

impl Reader {
	/// `key` is `k_s2c`, and `rest` what came behind the head of the upgrade answer.
	pub fn new(key: ChunkKey, rest: Vec<u8>) -> Self {Self {buf: rest, done: 0, opener: Opener::new(key), failed: None}}
	pub fn feed(&mut self, bytes: &[u8]) {self.buf.extend_from_slice(bytes)}
	/// How many bytes are kept: never more than one frame and what one read brought behind it.
	pub fn kept(&self) -> usize {self.buf.len() - self.done}
	/// The next whole frame, or `Ok(None)` when more bytes are needed. A fault ends the session, for this and every later call.
	pub fn next(&mut self) -> Result<Option<Read<'_>>, Fault> {
		if let Some(fault) = self.failed {return Err(fault)}
		self.buf.drain(..std::mem::take(&mut self.done));
		let header = match frame(&self.buf) {
			Ok(Some(header)) if self.buf.len() >= header.size + header.payload as usize => header,
			Ok(_) => return Ok(None),
			Err(fault) => return Err(*self.failed.insert(fault)),
		};
		self.done = header.size + header.payload as usize;
		let payload = &mut self.buf[header.size..self.done];
		Ok(Some(match header.opcode {
			// "The node proves it holds the transport private key by sending a chunk the client can open."
			BINARY => match self.opener.open(payload) {
				Ok(items) => Read::Chunk(items),
				Err(_) => return Err(*self.failed.insert(Fault::Chunk)),
			},
			PING => Read::Ping(payload),
			CLOSE => Read::Close,
			_ => Read::Pong,
		}))
	}
}

// One masked frame, with a fresh key as RFC 6455 asks of a client.
fn masked(opcode: u8, payload: &[u8], out: &mut Vec<u8>) -> Result<(), End> {
	let mut key = [0; 4];
	random(&mut key).map_err(|_| End::Random)?;
	websocket::frame(opcode, payload, Some(key), out);
	Ok(())
}

pub(crate) async fn run(port: &mut Port, link: &Link, name: Name, path: &str, candidate: &Front) -> Ended {
	let (dialled, Some(node)) = (Instant::now() + ATTEMPT, link.node) else {return End::Source.into()};
	// Everything a session needs of others is taken before anything is dialled: the WireGuard layer is never asked for a session nobody holds any more. "The client creates a new HPKE context for every proof and never reuses one."
	let (Ok(proof), Ok(padding), Some(first), mut nonce) = (proof::Client::new(&node, link.secret.expose(), &link.inbound, &link.device).prove(name, (port.env.now)(), &mut random), Padding::new(link.padding.wide_max, link.padding.normal_max, &mut random), port.want(Want::First), [0; 16]) else {return End::Source.into()};
	if random(&mut nonce).is_err() {return End::Random.into()}
	let (key, roots, hook, device, keepalive) = (STANDARD.encode(nonce), port.env.roots.clone(), port.env.socket.clone(), port.env.device.clone(), lone(&first));
	let request = format!("GET {path}?{} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n", proof.token, tls::host(candidate));
	// The dial, the request and its answer. The 10 s for the answer and for the node's first chunk run from the moment the request is written: the node's own 10 s for a session it took run from about then.
	let opening = async {
		let (mut io, mut buf) = (tls::dial(candidate, &roots, &hook, dialled).await?, Vec::with_capacity(HEAD_MAX));
		match timeout_at(dialled, async {io.write_all(request.as_bytes()).await.is_ok() && io.flush().await.is_ok()}).await {
			Ok(true) => {}
			Ok(false) => return Err(Ended::Unreachable(Unreachable::Cut)),
			Err(_) => return Err(Ended::Unreachable(Unreachable::Timeout)),
		}
		let deadline = Instant::now() + ATTEMPT;
		// A close the TLS session vouches for is a refusal. A connection that is reset, or ends without one, is cut: anyone on the path can do that.
		match timeout_at(deadline, http::answer(&mut io, &mut buf)).await {
			Ok(Ok(end)) => Ok((io, buf, end, deadline, device())),
			Ok(Err(Stop::Said(answer))) => Err(Ended::Refused(Refusal {answer, offset: None})),
			Ok(Err(Stop::Cut)) => Err(Ended::Unreachable(Unreachable::Cut)),
			Err(_) => Err(Ended::Unreachable(Unreachable::Timeout)),
		}
	};
	// A session that is closed or dropped while it opens stops here: no proof leaves the device after that.
	let (io, mut buf, end, deadline, read_at) = match unasked(&mut port.ask, opening).await {
		Some(Ok(opened)) => opened,
		Some(Err(ended)) => return ended,
		None => return End::Asked.into(),
	};
	let Some(head) = http::head(&buf[..end]) else {return Ended::Refused(Refusal {answer: Answer::NotHttp, offset: None})};
	// "Only after the certificate matched a pin from the profile, the client may read the `Date` header of the decoy's answer." The difference is taken against the device's own clock, as it stood when the head was read.
	if let Err(answer) = head.upgraded(key.as_bytes()) {return Ended::Refused(Refusal {answer, offset: head.date().filter(|_| !candidate.pins.is_empty()).map(|date| i64::try_from(date).unwrap_or(i64::MAX).saturating_sub(i64::try_from(read_at).unwrap_or(i64::MAX)))})}
	buf.drain(..end);
	let ((mut rd, mut wr), mut sealer, mut reader, mut read) = (tokio::io::split(io), Sealer::new(proof.keys.c2s, padding), Reader::new(proof.keys.s2c, buf), vec![0u8; 16_384]);
	// `batch` is what the next chunk holds, and `flush` that it goes out even if it is a lone keepalive. `held` is a lone keepalive on its way out, with whether it is the idle one. `awaiting` is until when a chunk of the node must have come: after an idle keepalive, and after a handshake WireGuard started because the node stopped answering.
	let (mut batch, mut flush, mut held, mut awaiting, mut carry, mut established, mut idle) = (vec![(first, Kind::Packet {flow: 0, control: false})], true, None::<(Vec<u8>, Instant, bool)>, None::<Instant>, None::<(Vec<u8>, Kind)>, false, deadline);
	// `next` is a datagram the caller handed over while the task waited, and `closing` that the caller closed the session. `gone` says the connection is over, so there is nobody to close the session with, and `cut` that it ended with nothing to vouch for who ended it.
	let (mut next, mut closing, mut gone, mut cut) = (None::<(Vec<u8>, Kind)>, false, false, false);
	let ended = 'session: loop {
		batch.extend(carry.take());
		// "The sender puts every datagram that is waiting at the moment it writes into one chunk, up to the limit, and never waits for more."
		let mut used: usize = batch.iter().map(|(datagram, _)| 2 + datagram.len()).sum();
		while let Some((datagram, kind)) = next.take().or_else(|| port.out.try_recv().ok()) {
			if !port.fits(&datagram) {
				port.dropped(1);
			} else if used + 2 + datagram.len() > MAX_PLAINTEXT - 34 || batch.len() + 1 >= MAX_ITEMS {
				carry = Some((datagram, kind));
				break;
			} else {
				used += 2 + datagram.len();
				batch.push((datagram, kind));
			}
		}
		// What the caller handed over before it closed the session is sent before the session is closed, a keepalive on its way out included.
		if closing {
			batch.extend(held.take().map(|(datagram, _, _)| (datagram, Kind::Packet {flow: 0, control: false})));
			flush = true;
		}
		// "A chunk that would hold exactly one WireGuard keepalive is held back for the lone keepalive delay and joins whatever else is sent in that time." The first chunk of a session is not held: the session is pending until it arrives.
		if let ([(datagram, _)], false, None) = (&batch[..], flush, &held) {
			if lone(datagram) {
				let Ok(delay) = pause(&LONE_KEEPALIVE) else {break End::Random.into()};
				held = batch.pop().map(|(datagram, _)| (datagram, Instant::now() + delay, false));
			}
		}
		if !batch.is_empty() {
			batch.extend(held.take().map(|(datagram, _, _)| (datagram, Kind::Packet {flow: 0, control: false})));
			let (items, mut sealed, mut out): (Vec<&[u8]>, _, _) = (batch.iter().map(|(datagram, _)| &datagram[..]).collect(), Vec::new(), Vec::new());
			match sealer.seal(&items, batch.iter().any(|(datagram, kind)| wide(*kind, datagram)), &mut random, &mut sealed) {
				Ok(()) => {}
				// "A sender closes the session before it would send chunk number 2^60."
				Err(ChunkError::Number) => break End::Exhausted.into(),
				Err(ChunkError::Random) => break End::Random.into(),
				Err(_) => break End::Source.into(),
			}
			if let Err(end) = masked(BINARY, &sealed, &mut out) {break end.into()}
			// A peer that does not read for as long as the liveness limit is one that is gone.
			if !timeout(LIVENESS, async {wr.write_all(&out).await.is_ok() && wr.flush().await.is_ok()}).await.unwrap_or(false) {
				(gone, cut) = (true, true);
				break End::Lost.into();
			}
			// "WireGuard reports the node silent": a handshake its own timer started wants a chunk back like an idle keepalive does, or a connection that went dark with no reset would carry the tunnel's packets nowhere for as long as the caller keeps sending.
			if batch.iter().any(|(_, kind)| *kind == Kind::Stalled) {awaiting.get_or_insert(Instant::now() + LIVENESS);}
			port.sent(batch.len());
			batch.clear();
			let Ok(silence) = pause(&link.padding.keepalive) else {break End::Random.into()};
			(flush, idle) = (false, Instant::now() + silence);
		}
		if closing {
			if carry.is_none() {break End::Asked.into()}
			continue;
		}
		// Every whole frame that is there. A frame is judged by its header, so no more than one frame is ever kept.
		loop {
			match reader.next() {
				// "The client does not treat a session as open before that."
				Ok(Some(Read::Chunk(items))) => {
					(established, awaiting) = (true, None);
					port.heard();
					for datagram in items {port.deliver(datagram)}
				}
				// "Neither side sends WebSocket pings. On an established session a received ping is answered with a pong, as RFC 6455 requires."
				Ok(Some(Read::Ping(payload))) if established => {
					let mut out = Vec::new();
					if let Err(end) = masked(PONG, payload, &mut out) {break 'session end.into()}
					if !timeout(LIVENESS, async {wr.write_all(&out).await.is_ok() && wr.flush().await.is_ok()}).await.unwrap_or(false) {
						(gone, cut) = (true, true);
						break 'session End::Lost.into();
					}
				}
				Ok(Some(Read::Close)) => break 'session End::Peer.into(),
				Ok(Some(Read::Pong | Read::Ping(_))) => {}
				Ok(None) => break,
				Err(fault) => break 'session End::Fault(fault).into(),
			}
		}
		// The idle keepalive is not due while a keepalive is on its way out already.
		let timer = [held.as_ref().map(|held| held.1), awaiting, if !established {Some(deadline)} else if held.is_none() {Some(idle)} else {None}].into_iter().flatten().min().unwrap_or(idle);
		tokio::select! {
			got = rd.read(&mut read) => match got {
				Ok(count) if count > 0 => reader.feed(&read[..count]),
				// The end of the connection: in order, with the TLS session's `close_notify`, or cut.
				got => {
					(gone, cut) = (true, got.is_err());
					break End::Lost.into();
				}
			},
			sent = port.out.recv() => match sent {
				Some(sent) => next = Some(sent),
				None => closing = true,
			},
			asked = port.ask.recv() => closing |= !matches!(asked, Some(Ask::Moved)),
			_ = sleep_until(timer) => {
				let now = Instant::now();
				// "Gives each transport 10 s to carry a chunk from the node." The proof was taken, so a node that knows the tunnel answers: silence behind a handshake initiation is the path's. Behind a keepalive it is a node that no longer has the tunnel, and that is neither a refusal nor a block.
				if !established && now >= deadline {break if keepalive {End::Unanswered.into()} else {Ended::Unreachable(Unreachable::Timeout)}}
				// "An idle keepalive got no chunk back within 10 s", and the same for a handshake WireGuard started because the node stopped answering.
				if awaiting.is_some_and(|until| now >= until) {break End::Lost.into()}
				if let Some((datagram, _, waited)) = held.take_if(|held| now >= held.1) {
					batch.push((datagram, Kind::Packet {flow: 0, control: false}));
					flush = true;
					if waited {awaiting.get_or_insert(now + LIVENESS);}
				} else if established && held.is_none() && now >= idle {
					// "When it has sent nothing for the idle keepalive time, it asks the WireGuard layer for one keepalive datagram and sends it in a chunk."
					let (Ok(silence), Ok(delay)) = (pause(&link.padding.keepalive), pause(&LONE_KEEPALIVE)) else {break End::Random.into()};
					idle = now + silence;
					held = port.want(Want::Keepalive).map(|datagram| (datagram, now + delay, true));
				}
			}
		}
	};
	// The upgrade was answered and the session ended before a chunk of the node opened. Cut, it is the path's doing. Closed in order, by a Close frame or a `close_notify`, the node or what stands in front of it was reached and it is no session: a refusal, but for a session that opened with a keepalive, where it is the node's own deadline for a tunnel it does not know.
	let told = match ended {
		Ended::Closed(End::Peer | End::Lost) if !established && cut => Ended::Unreachable(Unreachable::Cut),
		Ended::Closed(End::Peer | End::Lost) if !established && keepalive => End::Unanswered.into(),
		Ended::Closed(End::Peer | End::Lost) if !established => Ended::Refused(Refusal {answer: Answer::Unopened, offset: None}),
		ended => ended,
	};
	// The caller is told now. What follows is owed to the peer and can take 5 s.
	port.state.send_replace(State::Ended(told));
	// "Either side ends a session with a WebSocket Close frame with status 1000 and no reason, waits up to 5 s for the peer's Close frame, then closes TLS and TCP in the normal order whether or not it came. The same close is used for every cause."
	// A connection that ended has nobody to say it to. One that only went quiet is closed like every other.
	if !gone {
		let mut out = Vec::new();
		let said = masked(CLOSE, &NORMAL, &mut out).is_ok() && timeout(CLOSE_WAIT, async {wr.write_all(&out).await.is_ok() && wr.flush().await.is_ok()}).await.unwrap_or(false);
		if said && ended != Ended::Closed(End::Peer) {
			// What still comes is read as before and thrown away: nothing of it reaches the caller. The wait is over at the peer's Close frame, at the end of the connection, and at the first thing that is no frame of a session.
			let _ = timeout(CLOSE_WAIT, async {
				loop {
					match reader.next() {
						Ok(Some(Read::Close)) | Err(_) => return,
						Ok(Some(_)) => continue,
						Ok(None) => {}
					}
					match rd.read(&mut read).await {
						Ok(count) if count > 0 => reader.feed(&read[..count]),
						_ => return,
					}
				}
			}).await;
		}
		let _ = timeout(CLOSE_WAIT, wr.shutdown()).await;
	}
	told
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_frame_of_the_node_is_one_unmasked_binary_message_of_a_chunks_size() {
		let framed = |opcode: u8, size: usize, key: Option<[u8; 4]>| {
			let mut out = Vec::new();
			websocket::frame(opcode, &vec![7; size], key, &mut out);
			out
		};
		for size in [16, 17, 125, 126, 16_016] {assert_eq!(frame(&framed(BINARY, size, None)).map(|header| header.map(|header| header.payload)), Ok(Some(size as u64)))}
		for opcode in [CLOSE, PING, PONG] {assert!(frame(&framed(opcode, 2, None)).unwrap().is_some())}
		// The verdict falls at the header: a frame of 2^62 bytes is refused in ten bytes.
		assert!(frame(&[0x82, 127, 0x40, 0, 0, 0, 0, 0, 0, 0]).is_err());
		for bad in [framed(BINARY, 15, None), framed(BINARY, 0, None), framed(BINARY, 16_017, None), framed(BINARY, 70_000, None), framed(BINARY, 32, Some([1, 2, 3, 4])), framed(PING, 2, Some([1, 2, 3, 4])), framed(websocket::TEXT, 32, None), framed(websocket::CONTINUATION, 32, None), vec![0x02, 32], vec![0xc2, 32], vec![0x83, 0], vec![0x89, 126, 0, 200]] {assert!(frame(&bad).is_err(), "{:?}", &bad[..bad.len().min(4)])}
		let good = framed(BINARY, 300, None);
		for cut in 0..4 {assert_eq!(frame(&good[..cut]), Ok(None))}
	}
}
