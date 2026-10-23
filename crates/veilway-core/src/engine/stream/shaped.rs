//! The session of `fronted-shaped` on the proxy path (shapes page, "Numbering", "Downstream", "The node's state machine"): requests in the shape the transport names, each answered from the data the node has for the device, or all answered with a padding-only chunk while one event stream carries the data.
//!
//! A session is a row of its listener's table of shaped sessions that requests name by their `sid`. It keeps the window of request numbers it tracks, the answers it stored for repeats, the node's side of the chunks (a `Writer`, which seals at the number of the request) and the queue of what the node has for the device. Nothing in it changes but under the hand of a request whose every chunk opened at the numbers of its `n`, or of the proof that opened the session: "a request that does not open changes nothing".
use super::*;
use crate::config::ProofRate;
use tokio::sync::Mutex as AsyncMutex;
use veilway_proto::keys::ChunkKey;
use veilway_proto::chunk::MAX_ITEM;
use veilway_proto::shape::Shape;
use veilway_proto::shaped::{self as wire, Target, Writer, CHUNKS, IN_FLIGHT, WINDOW};
use veilway_proto::sse;

/// "Stream requests accepted: burst 4, then 1 a second, per session. A request beyond it takes the unauthenticated path."
const STREAMS: ProofRate = ProofRate {burst: 4, rate: 1};
/// "Repeats answered: burst 16, then 8 a second, per session. A repeat beyond it takes the unauthenticated path."
const REPEATS: ProofRate = ProofRate {burst: 16, rate: 8};
/// "Downstream queue: 128 datagrams of at most 1,600 bytes, drop on overflow."
pub(super) const QUEUE: usize = 128;
/// "Stored answers: the last 4 accepted requests of a session, in 65,536 bytes in all. An answer that would not fit alone is not stored."
const STORED: u64 = 4;
const STORED_BYTES: usize = 65_536;
/// A repeat is answered, from the stored answer or with the late one, only this long after the request was accepted (a CDN's retry comes within seconds): an older one is a logged URL played again, and gets the decoy's answer.
const REPEAT_AGE: i64 = 15_000;
/// "Unsent bytes of a stream: at most 65,536 on the node."
const UNSENT: usize = 65_536;
/// How much of a body is asked for at once. The buffer grows with the bytes that arrive and is never sized from the length the request claims.
const GROW: usize = 8_192;

/// What is known of one of the request numbers a session tracks: "whether it was accepted, whether it was a stream request, and the length and SHA-256 of its data", and the answer it got while the node still has it.
struct Slot {seq: u64, stream: bool, length: usize, hash: [u8; 32], at: i64, answer: Option<Arc<Vec<u8>>>, size: usize}

struct State {
	c2s: Arc<ChunkKey>,
	writer: Writer,
	/// "The node keeps per session the highest accepted `n`."
	highest: u32,
	/// How many requests were accepted, which orders the slots by acceptance.
	accepted: u64,
	/// "Nothing is kept for a number outside the window": at most 129 numbers.
	slots: BTreeMap<u32, Slot>,
	/// Requests whose chunks opened and whose answer is not stored yet, a stream request not counted once it has its answer.
	flying: usize,
	/// The live stream, if there is one: its number among this session's streams and what ends it.
	stream: Option<(u64, Arc<Notify>)>,
	streams: u64,
	repeats: Bucket,
	starts: Bucket,
	/// A chunk of the session's client opened and was invalid: the session is over.
	ended: bool,
}

/// What waits to go to the device. Held by the one request that drains it at a time: the stream, or the request that has no stream to give its data to.
struct Queue {waiting: mpsc::Receiver<(Vec<u8>, bool)>, held: VecDeque<(Vec<u8>, bool)>, lone: Option<Instant>}

impl Queue {
	/// Takes what waits in the channel into `held`, as much as the node keeps unsent: "Unsent bytes of a stream: at most 65,536 on the node", and "downstream queue: 128 datagrams of at most 1,600 bytes". What does not fit stays in the channel, which drops on overflow, so a session never holds more than the channel's 204,800 bytes and these 65,536 together.
	fn fill(&mut self) {
		let mut bytes: usize = self.held.iter().map(|(datagram, _)| 2 + datagram.len()).sum();
		while self.held.len() < QUEUE && bytes + 2 + MAX_ITEM <= UNSENT {
			let Ok(next) = self.waiting.try_recv() else {break};
			bytes += 2 + next.0.len();
			self.held.push_back(next);
		}
	}
}

/// One `fronted-shaped` session.
pub(super) struct Shaped {
	pub id: u64,
	pub route: u64,
	pub session: Arc<Session>,
	shape: Arc<Shape>,
	handshakes: Handshakes,
	state: Mutex<State>,
	queue: AsyncMutex<Queue>,
}

/// Who asked: the opening request of a proof that was just accepted, which makes the session, or a later request that names a session of this listener, with its number.
pub(super) enum Asked {
	Opening(Accepted),
	Later(Arc<Shaped>, u32),
}

/// Counts a request as in flight from the moment its body starts to be read (the opening request: from its proof) until its answer is stored, however it ends. The count is made under the session's lock before the guard exists.
struct Flying<'a>(&'a Shaped);

impl Drop for Flying<'_> {
	fn drop(&mut self) {
		let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
		state.flying = state.flying.saturating_sub(1);
	}
}

/// A stream while it is the live one. Gives its place back when it is over, however it ended.
struct Live<'a> {shaped: &'a Shaped, listener: &'a Listener, id: u64}

impl Drop for Live<'_> {
	fn drop(&mut self) {
		self.listener.streams.fetch_sub(1, Ordering::Relaxed);
		let mut state = self.shaped.state.lock().unwrap_or_else(|e| e.into_inner());
		if state.stream.as_ref().is_some_and(|(id, _)| *id == self.id) {state.stream = None}
	}
}

/// What a request that opened comes to.
enum Verdict {
	/// It was accepted: the datagrams it carried, and whether it asks for a stream.
	New(Vec<Vec<u8>>, bool),
	/// An accepted request that came again with the same data: the answer it got, or the late answer.
	Repeat(Option<Arc<Vec<u8>>>),
}

/// One request of a shaped transport that passed steps 1 and 2 of its state machine: the head is right and the target is in the one form of its shape. The opening request makes the session here, and a later request names one of this listener's. `total` is how far the request reaches in `buf`: the head and, for `body`, the body behind it.
/// From step 3 on: nothing of the session is looked at or touched until the data is whole. Then, with the session held and nothing waited for: a stream request that was accepted is a stranger's whatever it carries, a repeat is known by the length and the SHA-256 of its decoded data, and anything else must open chunk by chunk at the numbers of its `n`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve(shared: &Arc<Shared>, listener: &Arc<Listener>, served: &Served, way: &Front, from_proxy: &mut ReadHalf<Stream>, to_proxy: &mut WriteHalf<Stream>, buf: &mut Vec<u8>, filled: &mut usize, eof: &mut bool, end: usize, total: usize, line: usize, source: IpAddr, route: &Route, asked: Asked) -> Poll {
	// The head is copied once: the target is read from the copy, and `buf` is free to grow behind it.
	let (head, deadline) = (buf[..end].to_vec(), Instant::now() + BODY_TIME);
	let wanted = http::field_once(&head, b"accept").is_some_and(|value| value.eq_ignore_ascii_case(b"text/event-stream"));
	let Some(target) = route.shape.as_ref().and_then(|shape| Line::parse_any(&head[..line]).and_then(|parsed| Target::read(shape, route.path.as_bytes(), &parsed, shape.up.name.as_deref().and_then(|name| http::field_once(&head, name.as_bytes()))))) else {
		// The head was read once already and was right, so this is not reached; an accepted proof is not left pending if it is.
		if let Asked::Opening(accepted) = &asked {accepted.seat.end(Ended::Invalid)}
		return Poll::Stranger(Stranger::Proof, None);
	};
	let reserved;
	let (shaped, n, place) = match asked {
		// 3. "The proof is verified and spent as before." An accepted proof is spent and creates a pending session, whatever happens next.
		Asked::Opening(accepted) => {
			let (route, id, (queue, waiting), seat) = (&served.routes[accepted.route], listener.ids.fetch_add(1, Ordering::Relaxed), mpsc::channel(QUEUE), accepted.seat);
			listener.counters.count(Count::Proofs);
			let (Ok(padding), Some(shape)) = (Padding::new(accepted.wide, accepted.normal, &mut random), route.shape.clone()) else {
				seat.end(Ended::Closed);
				return Poll::Stranger(Stranger::Body, None);
			};
			let shaped = Arc::new(Shaped {id, route: route.id, session: Arc::new(Session {seat: seat.clone(), over: route.over, queue, counters: listener.counters.clone()}), shape, handshakes: Handshakes::new(Clock::of((shared.now)()).ms), state: Mutex::new(State {c2s: Arc::new(accepted.keys.c2s), writer: Writer::new(accepted.keys.s2c, padding), highest: 0, accepted: 0, slots: BTreeMap::new(), flying: 1, stream: None, streams: 0, repeats: Bucket::full(REPEATS, Clock::of((shared.now)()).ms), starts: Bucket::full(STREAMS, Clock::of((shared.now)()).ms), ended: false}), queue: AsyncMutex::new(Queue {waiting, held: VecDeque::new(), lone: None})});
			listener.sessions().insert(id, (route.id, seat.clone()));
			// A session id is 16 bytes from the exporter of a fresh proof. Should one ever be a live session's, that session is left alone and the new one is nobody's.
			let taken = match listener.shaped().entry(accepted.keys.sid) {
				Entry::Occupied(_) => true,
				Entry::Vacant(free) => {
					free.insert(shaped.clone());
					false
				}
			};
			// A reload, or the end of the listener, between the request and now.
			if taken || listener.closed.load(Ordering::Acquire) || !listener.served().routes.iter().any(|kept| kept.id == route.id) {seat.end(Ended::Unserved)}
			if taken {
				listener.sessions().remove(&id);
				return Poll::Stranger(Stranger::Session, None);
			}
			reserved = true;
			(shaped, 0, None)
		}
		// 4. "`sid` known. `n` is not more than 64 below the highest accepted number, and not more than 64 above it." A request that cannot be accepted is not read any further: a number that was a stream request, a request over the limit of 4 in flight, and a number outside the window. A number that is tracked and was no stream request may be a repeat, which is not a request in flight.
		Asked::Later(shaped, n) => {
			// A request that may be new takes one of the four places from here on, while its body is read, so that no more than four bodies of a session are read at once. A number that is tracked may be a repeat, which is not a request in flight.
			let ordered = {
				let mut state = shaped.state.lock().unwrap_or_else(|e| e.into_inner());
				let fits = !shaped.session.seat.over() && !state.ended && n.saturating_add(WINDOW) >= state.highest && n <= state.highest.saturating_add(WINDOW);
				let place = match state.slots.get(&n) {
					Some(slot) => !slot.stream,
					None => state.flying < IN_FLIGHT,
				};
				let counts = fits && place && !state.slots.contains_key(&n);
				if counts {state.flying += 1}
				(fits && place).then_some(counts)
			};
			let Some(counted) = ordered else {return Poll::Stranger(Stranger::Session, None)};
			reserved = counted;
			let place = if target.bodied() {Some(enter(listener, Listener::decoys, Source::of(source), way.waiting(), way.per_source))} else {None};
			(shaped, n, place)
		}
	};
	let (seat, opening) = (&shaped.session.seat, n == 0);
	let flying = reserved.then(|| Flying(&shaped));
	// 5. "Read whole within 10 s before anything of it is used." For `body` the buffer grows with the bytes that arrive, and never from the length the request names.
	let arrived = loop {
		if *filled >= total || !target.bodied() {break true}
		if *eof {break false}
		if buf.len() < (*filled + GROW).min(total) {buf.resize((*filled + GROW).min(total), 0)}
		let limit = buf.len().min(total);
		tokio::select! {
			biased;
			_ = async {
				match &place {
					Some(place) => place.bump.notified().await,
					None => std::future::pending().await,
				}
			} => {
				listener.cut();
				return Poll::Lost;
			}
			// Only the opening request waits on its session: it is the one request the session has.
			_ = seat.gone(), if opening => break false,
			read = from_proxy.read(&mut buf[*filled..limit]) => match read {
				Ok(read) if read > 0 => *filled += read,
				Ok(_) => *eof = true,
				Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => *eof = true,
				Err(_) => {
					if opening {
						seat.end(Ended::Closed);
						listener.forget_shaped(&shaped);
					}
					return Poll::Lost;
				}
			},
			_ = sleep_until(deadline) => break false,
		}
	};
	// 6 to 8, with the session held and nothing waited for.
	let now = Clock::of((shared.now)());
	let decoded = if arrived && !target.bodied() {target.data()} else {None};
	let data: &[u8] = if target.bodied() {&buf[end..total.min(*filled)]} else {decoded.as_deref().unwrap_or_default()};
	let mut scratch = Vec::new();
	let verdict = if !arrived || wire::framed(data).is_none() {Err(Stranger::Body)} else {
		// Neither the hash nor the opening of a chunk runs under the session's lock: it is taken to look at the number, and again to decide.
		let (known, key) = {
			let state = shaped.state.lock().unwrap_or_else(|e| e.into_inner());
			(state.slots.get(&n).map(|slot| (slot.stream, slot.length, slot.hash, slot.at, slot.answer.clone())), state.c2s.clone())
		};
		match known {
			// "If `n` was accepted as a stream request, the request takes the unauthenticated path here, whatever its data, before any repeat test." 8. A repeat has the same length and SHA-256 of its decoded data, and comes within 15 s of the request it repeats.
			Some((stream, length, hash, at, answer)) => {
				let same = !stream && length == data.len() && hash.as_slice() == digest(&SHA256, data).as_ref();
				let mut state = shaped.state.lock().unwrap_or_else(|e| e.into_inner());
				if seat.over() || state.ended || stream {Err(Stranger::Session)} else if !same || now.ms - at > REPEAT_AGE || !state.repeats.fill(REPEATS, now.ms).take() {Err(Stranger::Body)} else {Ok(Verdict::Repeat(answer))}
			}
			None if flying.is_none() => Err(Stranger::Session),
			// 6. "Every chunk must open under `k_c2s` at `n` times 4,096, then one more for each. If any does not, nothing is processed, and the session is as it was."
			None => match wire::open(&key, n, data, &mut scratch) {
				Ok(chunks) => {
					let hash: [u8; 32] = digest(&SHA256, data).as_ref().try_into().unwrap_or_default();
					// "The opening request is a stream request too" when the client asks for a stream by `Accept`: a client that polls a candidate for an hour after streams failed on it sends none, and its opening request is answered as any other.
					let stream = shaped.shape.streamed() && wanted;
					let mut state = shaped.state.lock().unwrap_or_else(|e| e.into_inner());
					if seat.over() || state.ended || state.slots.contains_key(&n) || n.saturating_add(WINDOW) < state.highest || n > state.highest.saturating_add(WINDOW) {Err(Stranger::Session)} else if stream && !state.starts.fill(STREAMS, now.ms).take() {
						listener.counters.count(Count::ShapedLimited);
						Err(Stranger::Session)
					} else {
						let datagrams: Vec<Vec<u8>> = chunks.into_iter().flatten().map(<[u8]>::to_vec).collect();
						state.accepted += 1;
						let (seq, highest) = (state.accepted, state.highest.max(n));
						state.highest = highest;
						state.slots.insert(n, Slot {seq, stream, length: data.len(), hash, at: now.ms, answer: None, size: 0});
						// "The last 4 accepted requests" keep their answers, and a number below the window is forgotten.
						state.slots.retain(|key, _| key.saturating_add(WINDOW) >= highest);
						for slot in state.slots.values_mut() {if slot.seq + STORED <= seq {(slot.answer, slot.size) = (None, 0)}}
						// "A request is activity when its chunks have opened."
						seat.active.store(now.ms, Ordering::Relaxed);
						Ok(Verdict::New(datagrams, stream))
					}
				}
				Err(BodyError::Refused) => Err(Stranger::Body),
				// 7. "A chunk that is invalid, in a body whose every chunk opened, came from the session's client. The session is ended and the request takes the unauthenticated path."
				Err(BodyError::Ended(_)) => {
					shaped.state.lock().unwrap_or_else(|e| e.into_inner()).ended = true;
					seat.end(Ended::Invalid);
					Err(Stranger::Body)
				}
			},
		}
	};
	let (datagrams, stream) = match verdict {
		Err(why) => {
			// "For an opening request the pending session is dropped at once."
			if opening {
				seat.end(Ended::Invalid);
				listener.forget_shaped(&shaped);
			}
			return Poll::Stranger(why, place);
		}
		// "It gets the stored answer if the node still has it, and otherwise the late answer: `200`, a `Content-Length` of 80 and the one chunk of "Numbering" at index 4,095."
		Ok(Verdict::Repeat(stored)) => {
			drop(place);
			let response = match stored {
				Some(response) => {
					listener.counters.count(Count::ShapedRepeats);
					response
				}
				None => {
					listener.counters.count(Count::ShapedLate);
					let late = shaped.state.lock().unwrap_or_else(|e| e.into_inner()).writer.late(n);
					Arc::new([POLLED.as_bytes(), b"80\r\n\r\n", &late].concat())
				}
			};
			return if to_proxy.write_all(&response).await.is_ok() && to_proxy.flush().await.is_ok() {Poll::Answered} else {Poll::Lost};
		}
		Ok(Verdict::New(datagrams, stream)) => (datagrams, stream),
	};
	// The request is the session's own from here on.
	drop(place);
	listener.counters.count(Count::ShapedPolls);
	let (Some(flying), mut net, mut ip) = (flying, Vec::new(), Vec::new()) else {return Poll::Stranger(Stranger::Session, None)};
	// "No stream": a chunk item of the client that tells the node to drop its live stream, because the client has left it and a front may be keeping it open all the same. It is authenticated like the chunk it is in, and it is no WireGuard message.
	let mut left = false;
	for datagram in &datagrams {
		if datagram.as_slice() == wire::NO_STREAM {left = true} else {take(shared, listener, served, &shaped.session, &shaped.handshakes, SocketAddr::new(source, 0), now, datagram, &mut net, &mut ip);}
	}
	if !ip.is_empty() {
		let plan = shared.plan();
		if let Some(at) = plan.inbound_of(&seat.tunnel) {
			for packet in ip.drain(..) {shared.ingress(&plan, at, seat.device, packet, Some(shaped.session.over.rule())).await}
		}
	}
	// "For the opening request, the node sends nothing, not even the head, until the session is established, as in the classic form." A session that is pending has this one request, and waits for the first tunnel packet deadline.
	if seat.pending() {
		seat.gone().await;
		listener.forget_shaped(&shaped);
		return Poll::Stranger(Stranger::Unestablished, None);
	}
	// What WireGuard answers to the request goes to the device first of all: through the stream if there is one, and in the answer if not.
	for datagram in &net {shaped.session.push(datagram, false)}
	if stream {return live(listener, &shaped, flying, from_proxy, to_proxy, buf, filled, eof, n).await}
	// 9. "If the session has a live stream, all downstream data goes to the stream, and the answer to every other request is `200` with a `Content-Length` and one padding-only chunk at index 0, given at once without the hold."
	let mut body = Vec::new();
	if left {
		if let Some((_, older)) = shaped.state.lock().unwrap_or_else(|e| e.into_inner()).stream.take() {older.notify_one()}
	}
	let streaming = shaped.state.lock().unwrap_or_else(|e| e.into_inner()).stream.is_some();
	// A request that finds the queue in another's hands has nothing to carry: the one that has it answers with the data.
	// A stream that was just told to leave gives the queue up within a moment, and the answer waits for it.
	let queue = if streaming {None} else if left {timeout(Duration::from_secs(2), shaped.queue.lock()).await.ok()} else {shaped.queue.try_lock().ok()};
	if let Some(mut queue) = queue {
		// "The node answers an accepted request as soon as it has downstream data for the session, and otherwise after the hold time."
		let hold = Instant::now() + HOLD;
		let withheld = loop {
			queue.fill();
			// "A chunk that would hold exactly one WireGuard keepalive is held back for the lone keepalive delay and joins whatever else is sent in that time."
			let lone = queue.held.len() == 1 && queue.held[0].0.len() == 32 && queue.held[0].0[0] == 4;
			if !lone {queue.lone = None} else if queue.lone.is_none() {queue.lone = Some(Instant::now() + session::delay(&LONE_KEEPALIVE, &mut random).unwrap_or_default())}
			let withheld = queue.lone.is_some_and(|until| until > Instant::now());
			if seat.over() || Instant::now() >= hold || (!queue.held.is_empty() && !withheld) {break withheld}
			let wake = queue.lone.map_or(hold, |until| until.min(hold));
			tokio::select! {
				_ = seat.gone() => {}
				Some(next) = queue.waiting.recv() => queue.held.push_back(next),
				_ = sleep_until(wake) => {}
			}
		};
		// "The answer holds at most 65,536 bytes of frames and at most 4,095 chunks, and the rest waits in the queue." What does not fit this answer waits for the next request.
		let (mut state, mut index) = (shaped.state.lock().unwrap_or_else(|e| e.into_inner()), 0);
		while !withheld && !queue.held.is_empty() && index < CHUNKS {
			let (mut count, mut size) = (0, 0);
			while count < queue.held.len().min(MAX_ITEMS) && size + 2 + queue.held[count].0.len() <= MAX_PLAINTEXT {
				size += 2 + queue.held[count].0.len();
				count += 1;
			}
			let (items, wide): (Vec<&[u8]>, bool) = (queue.held.iter().take(count).map(|(datagram, _)| datagram.as_slice()).collect(), queue.held.iter().take(count).any(|(datagram, wide)| *wide || matches!(datagram.first(), Some(1 | 2))));
			match state.writer.append(n, index, &items, wide, BODY_MAX, &mut random, &mut body) {
				Ok(()) => {
					listener.counters.count(Count::Chunks);
					index += 1;
				}
				Err(ChunkError::Size) if !body.is_empty() => break,
				// "A sender closes the session before it would send chunk number 2^60": the numbers of a request cannot run out, and the count is kept all the same.
				Err(ChunkError::Number) => seat.end(Ended::Packets),
				Err(_) => {}
			}
			queue.held.drain(..count.max(1));
		}
	}
	// "A request or response with nothing to carry holds one padding-only chunk, so no body is ever empty."
	if body.is_empty() {
		let sealed = shaped.state.lock().unwrap_or_else(|e| e.into_inner()).writer.append(n, 0, &[], false, BODY_MAX, &mut random, &mut body);
		if sealed.is_err() {
			seat.end(Ended::Packets);
			return Poll::Stranger(Stranger::Body, None);
		}
		listener.counters.count(Count::Chunks);
	}
	// "The node fixes the bytes of an answer when it first builds it, and the stored answer is that sealed text": stored before it is written, so that a repeat of a request whose answer never reached the front is answered too.
	let response = Arc::new([POLLED.as_bytes(), body.len().to_string().as_bytes(), b"\r\n\r\n", &body].concat());
	{
		let mut state = shaped.state.lock().unwrap_or_else(|e| e.into_inner());
		// "The last 4 accepted requests of a session, in 65,536 bytes in all. An answer that would not fit alone is not stored": the oldest answers give way first.
		let fresh = state.slots.get(&n).is_some_and(|slot| slot.seq + STORED > state.accepted);
		if fresh && body.len() <= STORED_BYTES {
			let mut older: Vec<(u64, u32, usize)> = state.slots.iter().filter(|(key, slot)| **key != n && slot.answer.is_some()).map(|(key, slot)| (slot.seq, *key, slot.size)).collect();
			older.sort();
			let mut kept: usize = older.iter().map(|(.., size)| size).sum();
			for (_, key, size) in older {
				if kept + body.len() <= STORED_BYTES {break}
				if let Some(slot) = state.slots.get_mut(&key) {(slot.answer, slot.size) = (None, 0)}
				kept -= size;
			}
			if let Some(slot) = state.slots.get_mut(&n) {(slot.answer, slot.size) = (Some(response.clone()), body.len())}
		}
	}
	if to_proxy.write_all(&response).await.is_ok() && to_proxy.flush().await.is_ok() {Poll::Answered} else {Poll::Lost}
}

/// The answer to a stream request (shapes page, "The stream"): the head, then one event for every chunk of what the node has for the device, a heartbeat after a silence, and the end of the chunked body when the stream is replaced, runs out of life or events, or the session is over.
/// "A newer stream replaces the older": the head of this one is written first, and then the older one is told to finish. The datagrams that went into the stream are its own and are never written twice.
#[allow(clippy::too_many_arguments)]
async fn live(listener: &Arc<Listener>, shaped: &Arc<Shaped>, flying: Flying<'_>, from_proxy: &mut ReadHalf<Stream>, to_proxy: &mut WriteHalf<Stream>, buf: &mut [u8], filled: &mut usize, eof: &mut bool, n: u32) -> Poll {
	let seat = &shaped.session.seat;
	let headed = put(to_proxy, seat, sse::HEAD).await;
	// "In flight is a request whose chunks have opened and whose answer has not been sent": a stream request is answered by its head, and the four requests besides a stream are the others.
	drop(flying);
	if !headed {return Poll::Lost}
	let kill = Arc::new(Notify::new());
	let id = {
		let mut state = shaped.state.lock().unwrap_or_else(|e| e.into_inner());
		state.streams += 1;
		let id = state.streams;
		if let Some((_, older)) = state.stream.replace((id, kill.clone())) {older.notify_one()}
		id
	};
	listener.streams.fetch_add(1, Ordering::Relaxed);
	listener.counters.count(Count::ShapedStreams);
	let _live = Live {shaped, listener, id};
	let mut queue = shaped.queue.lock().await;
	let (down, start, mut events, mut fresh) = (&shaped.shape.down, Instant::now(), 0usize, false);
	let mut beat = Instant::now() + session::delay(&sse::BEAT_AFTER, &mut random).unwrap_or_default();
	// "Unsent bytes of a stream: at most 65,536 on the node." An event is written before the next is sealed, so what is unsent is one event of 21,364 bytes at the most, and what waits for a reader that is slow is the queue of 128 datagrams, which drops on overflow.
	let mut out = Vec::new();
	let lost = loop {
		if events >= sse::EVENTS || start.elapsed() >= sse::LIFE_MAX || seat.over() {break false}
		queue.fill();
		let lone = queue.held.len() == 1 && queue.held[0].0.len() == 32 && queue.held[0].0[0] == 4;
		if !lone {queue.lone = None} else if queue.lone.is_none() {queue.lone = Some(Instant::now() + session::delay(&LONE_KEEPALIVE, &mut random).unwrap_or_default())}
		let withheld = queue.lone.is_some_and(|until| until > Instant::now());
		if !queue.held.is_empty() && !withheld {
			// "The gather time per event, from `down.gather`, applied when the queue was empty so that a packet that arrives alone is not sent at the instant it arrives."
			if fresh {
				fresh = false;
				let gather = session::delay(&down.gather, &mut random).unwrap_or_default();
				tokio::select! {
					biased;
					_ = kill.notified() => break false,
					_ = seat.gone() => break false,
					_ = tokio::time::sleep(gather) => {}
				}
				queue.fill();
			}
			// "Each event is one line `data: ` followed by one sealed chunk": the datagrams that were waiting, up to the chunk limit.
			let (mut count, mut size) = (0, 0);
			while count < queue.held.len().min(MAX_ITEMS) && size + 2 + queue.held[count].0.len() <= MAX_PLAINTEXT {
				size += 2 + queue.held[count].0.len();
				count += 1;
			}
			let (items, wide): (Vec<&[u8]>, bool) = (queue.held.iter().take(count).map(|(datagram, _)| datagram.as_slice()).collect(), queue.held.iter().take(count).any(|(datagram, wide)| *wide || matches!(datagram.first(), Some(1 | 2))));
			let mut sealed = Vec::new();
			let result = shaped.state.lock().unwrap_or_else(|e| e.into_inner()).writer.seal(n, events, &items, wide, &mut random, &mut sealed);
			queue.held.drain(..count.max(1));
			match result {
				Ok(()) => {
					out.clear();
					sse::chunked(&sse::event(&sealed), &mut out);
					listener.counters.count(Count::Chunks);
					listener.counters.count(Count::ShapedEvents);
					events += 1;
					// A write that a newer stream cuts short leaves half a chunk on the connection, and the connection is closed: the older stream is replaced all the same.
					let written = tokio::select! {
						biased;
						_ = kill.notified() => break true,
						written = put(to_proxy, seat, &out) => written,
					};
					if !written {break true}
					beat = Instant::now() + session::delay(&sse::BEAT_AFTER, &mut random).unwrap_or_default();
				}
				Err(ChunkError::Number) => seat.end(Ended::Packets),
				Err(_) => {}
			}
			continue;
		}
		let wake = queue.lone.map_or(beat, |until| until.min(beat));
		tokio::select! {
			biased;
			_ = kill.notified() => break false,
			_ = seat.gone() => break false,
			// Bytes of the next request are kept where the connection reads its requests; the end of the connection ends the stream.
			read = async {
				if *filled < buf.len() {from_proxy.read(&mut buf[*filled..]).await} else {std::future::pending().await}
			} => match read {
				Ok(read) if read > 0 => *filled += read,
				Ok(_) => {
					*eof = true;
					break true;
				}
				Err(_) => break true,
			},
			_ = sleep_until(start + sse::LIFE_MAX) => break false,
			got = queue.waiting.recv() => match got {
				Some(next) => {
					fresh = queue.held.is_empty();
					queue.held.push_back(next);
				}
				None => break false,
			},
			_ = sleep_until(wake) => {
				if Instant::now() >= beat {
					// "After a silence drawn uniformly from 10 to 25 s the node writes a comment line": it is not sealed and holds nothing.
					let Ok(text) = sse::beat(&mut random) else {break false};
					out.clear();
					sse::chunked(&text, &mut out);
					listener.counters.count(Count::ShapedBeats);
					// A write that a newer stream cuts short leaves half a chunk on the connection, and the connection is closed: the older stream is replaced all the same.
					let written = tokio::select! {
						biased;
						_ = kill.notified() => break true,
						written = put(to_proxy, seat, &out) => written,
					};
					if !written {break true}
					beat = Instant::now() + session::delay(&sse::BEAT_AFTER, &mut random).unwrap_or_default();
				}
			}
		}
	};
	if lost || seat.over() {return Poll::Lost}
	if put(to_proxy, seat, sse::END).await {Poll::Answered} else {Poll::Lost}
}
