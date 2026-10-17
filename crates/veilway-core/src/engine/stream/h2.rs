//! HTTP/2 on a `tls` listener (http2 page, "The node: `tls`"): the node is an HTTP/2 server toward the peer and decides every stream on its own. A stream that is an extended CONNECT with a proof is a user's session, and anything else is a stranger's request that is turned into HTTP/1.1 for the decoy origin, one upstream connection for each stream.
//! The frames are `veilway_proto::h2`'s and the translation is its `gateway`. What is here is the connection: the reader that counts every frame and every stream, the writer that owns HPACK's encoder and the order of the frames, the two windows of each direction, and the tasks of the streams.
//! Nothing is taken on trust from a library: the header block's size and time, the decoded list, the first HEADERS, the streams opened, the streams that ended early whoever reset them, the frames that carry nothing, the control frames not yet answered, the streams in flight, the upstream connections they hold and the answer bytes held are all counted here.
use super::*;
use tokio::io::split;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use veilway_proto::h2::{self as frames, gateway, Decoder, Encoder, Fields, Header as FrameHeader};
use veilway_proto::http::{head_end, Framing, ANSWER_HEAD_MAX};

const STREAMS_MAX: usize = 100;
const HEADER_TABLE: u32 = 4_096;
const FIRST_HEADERS: Duration = Duration::from_secs(10);
const BLOCK_TIME: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(300);
const ZERO_WINDOW: Duration = Duration::from_secs(30);
const WRITE_TIME: Duration = Duration::from_secs(30);
const FRAME_TIME: Duration = Duration::from_secs(30);
const OWED: usize = 100;
/// Upstream connections of the strangers' streams of one client connection, and of one that has proved a user.
const UPSTREAM: usize = 6;
const UPSTREAM_USER: usize = 1;
const UPSTREAM_SOURCE: usize = 16;
const CONNECTIONS_SOURCE: usize = 4;
/// The answer bytes held for strangers: a stream never holds more than one read of `READ` bytes, so its 262,144 are not reached, and the other two are counted.
const HELD_CONNECTION: usize = 1_048_576;
const HELD_LISTENER: usize = 67_108_864;
const READ: usize = 16_384;
/// The windows once a stream has proved to be a user's: 6,291,456 for a stream and 15,728,640 for the connection.
const USER_STREAM_WINDOW: u32 = 6_291_456;
const USER_CONNECTION_WINDOW: u32 = 15_728_640;
const OPENED: (usize, Duration) = (200, Duration::from_secs(10));
const EARLY: (usize, Duration) = (100, Duration::from_secs(30));
const EMPTY: (usize, Duration) = (1_000, Duration::from_secs(10));

/// What a listener keeps of its HTTP/2 connections: for each direct source its connections, oldest first, and the upstream connections they hold, and the answer bytes held for strangers.
#[derive(Default)]
pub(super) struct Book {sources: Mutex<HashMap<IpAddr, Source>>, held: AtomicUsize}

#[derive(Default)]
struct Source {connections: VecDeque<(u64, Arc<Notify>)>, upstream: usize}

impl Book {
	fn sources(&self) -> MutexGuard<'_, HashMap<IpAddr, Source>> {self.sources.lock().unwrap_or_else(|e| e.into_inner())}
}

// A connection's place among its source's. Dropping it gives the place back.
struct Sourced {listener: Arc<Listener>, ip: IpAddr, id: u64}

impl Drop for Sourced {
	fn drop(&mut self) {
		let mut sources = self.listener.h2.sources();
		if let Some(source) = sources.get_mut(&self.ip) {
			source.connections.retain(|(id, _)| *id != self.id);
			if source.connections.is_empty() && source.upstream == 0 {sources.remove(&self.ip);}
		}
	}
}

// One of the 16 upstream connections of a source.
struct Upstream {listener: Arc<Listener>, ip: IpAddr}

impl Drop for Upstream {
	fn drop(&mut self) {
		let mut sources = self.listener.h2.sources();
		if let Some(source) = sources.get_mut(&self.ip) {
			source.upstream = source.upstream.saturating_sub(1);
			if source.connections.is_empty() && source.upstream == 0 {sources.remove(&self.ip);}
		}
	}
}

// Answer bytes read from an origin and not yet written to the peer.
struct Hold {wire: Arc<Wire>, listener: Arc<Listener>, bytes: usize}

impl Drop for Hold {
	fn drop(&mut self) {
		self.wire.held.fetch_sub(self.bytes, Ordering::Relaxed);
		self.listener.h2.held.fetch_sub(self.bytes, Ordering::Relaxed);
	}
}

// At most `limit` hits inside `span`.
struct Tally {limit: usize, span: Duration, hits: VecDeque<Instant>}

impl Tally {
	fn new((limit, span): (usize, Duration)) -> Tally {Tally {limit, span, hits: VecDeque::new()}}
	fn hit(&mut self) -> bool {
		let now = Instant::now();
		while self.hits.front().is_some_and(|at| now.duration_since(*at) > self.span) {self.hits.pop_front();}
		self.hits.push_back(now);
		self.hits.len() > self.limit
	}
}

// The window of one receiving side: what the peer may still send, and the credit owed to it that has not been sent yet.
struct Recv {window: AtomicI64, owed: AtomicI64}

impl Recv {
	fn new(window: i64) -> Recv {Recv {window: AtomicI64::new(window), owed: AtomicI64::new(0)}}
}

// The windows toward the peer: what the node may still send on the connection and on each stream.
struct Windows {connection: i64, streams: HashMap<u32, i64>}

enum Out {
	Raw(Vec<u8>),
	// A SETTINGS or PING answer: counted among the control frames the peer is owed until it is written.
	Owed(Vec<u8>),
	Headers(u32, Fields, bool),
	Table(usize),
	Close(Vec<u8>),
}

enum Event {Done(u32), Proved(oneshot::Sender<()>), Stranger}

enum Outcome {Complete, Aborted, Cancelled}

struct Wire {
	out: mpsc::Sender<Out>,
	windows: Mutex<Windows>,
	wake: Notify,
	connection: Recv,
	/// The window a new stream starts with, for the credit thresholds.
	initial: AtomicI64,
	trip: watch::Sender<Option<u32>>,
	owed: Arc<AtomicUsize>,
	held: AtomicUsize,
	opened: Mutex<Tally>,
	early: Mutex<Tally>,
	empty: Mutex<Tally>,
	proved: AtomicBool,
	events: mpsc::UnboundedSender<Event>,
	counters: Arc<Counters>,
}

impl Wire {
	fn windows(&self) -> MutexGuard<'_, Windows> {self.windows.lock().unwrap_or_else(|e| e.into_inner())}
	fn tripped(&self, code: u32, count: Count) {
		if self.trip.send_if_modified(|was| if was.is_none() {*was = Some(code); true} else {false}) {
			tracing::info!("an HTTP/2 connection of a stream listener is closed with GOAWAY {code:#x}: a bound on its streams, frames or header block was passed");
			self.counters.count(count)
		}
	}
	fn early(&self) {if self.early.lock().unwrap_or_else(|e| e.into_inner()).hit() {self.tripped(frames::ENHANCE_YOUR_CALM, Count::H2Rapid)}}
	fn empty(&self) {if self.empty.lock().unwrap_or_else(|e| e.into_inner()).hit() {self.tripped(frames::ENHANCE_YOUR_CALM, Count::H2Flood)}}
	async fn queue(&self, item: Out) {let _ = self.out.send(item).await;}
	async fn reset(&self, id: u32, code: u32) {
		self.windows().streams.remove(&id);
		self.wake.notify_waiters();
		let mut bytes = Vec::new();
		frames::rst_stream(id, code, &mut bytes);
		self.queue(Out::Raw(bytes)).await;
	}
	// Returns window to the peer as bytes are used up, at a threshold, for the connection and for the stream.
	async fn credit(&self, id: u32, stream: Option<&Recv>, count: usize) {
		let threshold = (self.initial.load(Ordering::Relaxed) / 2).clamp(1, READ as i64);
		for (recv, at) in [Some((&self.connection, 0)), stream.map(|stream| (stream, id))].into_iter().flatten() {
			let owed = recv.owed.fetch_add(count as i64, Ordering::Relaxed) + count as i64;
			if owed >= threshold {
				let give = recv.owed.swap(0, Ordering::Relaxed);
				if give > 0 {
					recv.window.fetch_add(give, Ordering::Relaxed);
					let mut bytes = Vec::new();
					frames::window_update(at, give as u32, &mut bytes);
					self.queue(Out::Raw(bytes)).await;
				}
			}
		}
	}
	// Waits until the node may send on the stream, and says how much, at most `want` and one frame. None when the stream is gone or the window stayed shut for `patience`.
	async fn room(&self, id: u32, want: usize, patience: Option<Duration>) -> Option<usize> {
		let until = patience.map(|patience| Instant::now() + patience);
		loop {
			let woken = self.wake.notified();
			tokio::pin!(woken);
			woken.as_mut().enable();
			{
				let windows = self.windows();
				let stream = *windows.streams.get(&id)?;
				let room = windows.connection.min(stream);
				if room > 0 {return Some((room as usize).min(want).min(frames::FRAME_MAX))}
			}
			match until {
				Some(until) => if timeout_at(until, woken).await.is_err() {return None},
				None => woken.await,
			}
		}
	}
	// Sends `bytes` as DATA frames within the windows, END_STREAM on the last when `end`. False when the stream went away or its window stayed shut.
	async fn data(&self, id: u32, bytes: &[u8], end: bool, patience: Option<Duration>) -> bool {
		let mut at = 0;
		loop {
			let left = bytes.len() - at;
			if left == 0 && !end {return true}
			let take = if left == 0 {0} else {
				let Some(room) = self.room(id, left, patience).await else {return false};
				let mut windows = self.windows();
				let connection = windows.connection.max(0) as usize;
				let Some(stream) = windows.streams.get_mut(&id) else {return false};
				let take = room.min(connection).min((*stream).max(0) as usize);
				if take == 0 {continue}
				*stream -= take as i64;
				windows.connection -= take as i64;
				take
			};
			let mut frame = Vec::with_capacity(take + frames::HEADER);
			frames::frame(frames::DATA, if end && at + take == bytes.len() {frames::END_STREAM} else {0}, id, &bytes[at..at + take], &mut frame);
			self.queue(Out::Raw(frame)).await;
			at += take;
			if at == bytes.len() {return true}
		}
	}
	// Reserves what one read of an origin may hold against the connection's and the listener's bounds, waiting for them.
	async fn hold(self: &Arc<Self>, listener: &Arc<Listener>, count: usize, patience: Duration) -> Option<Hold> {
		let until = Instant::now() + patience;
		loop {
			let woken = self.wake.notified();
			tokio::pin!(woken);
			woken.as_mut().enable();
			if self.held.load(Ordering::Relaxed) + count <= HELD_CONNECTION && listener.h2.held.load(Ordering::Relaxed) + count <= HELD_LISTENER {
				self.held.fetch_add(count, Ordering::Relaxed);
				listener.h2.held.fetch_add(count, Ordering::Relaxed);
				return Some(Hold {wire: self.clone(), listener: listener.clone(), bytes: count});
			}
			if timeout_at(until, woken).await.is_err() {return None}
		}
	}
}

// Everything a stream's task shares with its connection.
struct Ctx {
	shared: Arc<Shared>,
	listener: Arc<Listener>,
	served: Arc<Served>,
	wire: Arc<Wire>,
	peer: SocketAddr,
	local: SocketAddr,
	upstream: Arc<Semaphore>,
	/// Whether TLS 1.3 was negotiated: a proof on an older version is not a user's.
	modern: bool,
}

// Resolves when the peer has reset the stream or the connection is gone. A helper so that the guard of the watch is not held across an await.
async fn gone(cancel: &mut watch::Receiver<bool>) {let _ = cancel.wait_for(|cancelled| *cancelled).await.map(|_| ());}

enum Read {Frame(FrameHeader, Vec<u8>), Gone, Oversize}

async fn reader(mut rd: ReadHalf<Stream>, to: mpsc::Sender<Read>) {
	let mut head = [0u8; frames::HEADER];
	loop {
		if rd.read_exact(&mut head).await.is_err() {
			let _ = to.send(Read::Gone).await;
			return;
		}
		let header = FrameHeader::parse(&head);
		if header.len > frames::FRAME_MAX {
			let _ = to.send(Read::Oversize).await;
			return;
		}
		let mut payload = vec![0u8; header.len];
		if !timeout(FRAME_TIME, rd.read_exact(&mut payload)).await.is_ok_and(|read| read.is_ok()) {
			let _ = to.send(Read::Gone).await;
			return;
		}
		if to.send(Read::Frame(header, payload)).await.is_err() {return}
	}
}

async fn writer(mut wr: WriteHalf<Stream>, mut out: mpsc::Receiver<Out>, owed: Arc<AtomicUsize>) {
	let (mut encoder, mut bytes, mut closing) = (Encoder::new(), Vec::new(), false);
	while let Some(item) = out.recv().await {
		bytes.clear();
		let mut next = Some(item);
		let mut owes = 0;
		let mut taken = 0;
		while let Some(item) = next.take() {
			match item {
				Out::Raw(raw) => bytes.extend_from_slice(&raw),
				Out::Owed(raw) => {
					bytes.extend_from_slice(&raw);
					owes += 1;
				}
				Out::Headers(id, fields, end) => {
					let block = encoder.encode(&fields.iter().map(|(name, value)| (name.as_slice(), value.as_slice())).collect::<Vec<_>>());
					frames::headers(id, &block, end, &mut bytes);
				}
				Out::Table(size) => encoder.resize(size),
				Out::Close(raw) => {
					bytes.extend_from_slice(&raw);
					closing = true;
				}
			}
			taken += 1;
			if closing || taken == 64 {break}
			next = out.try_recv().ok();
		}
		let written = timeout(WRITE_TIME, async {wr.write_all(&bytes).await?; wr.flush().await}).await.is_ok_and(|written| written.is_ok());
		owed.fetch_sub(owes, Ordering::Relaxed);
		if !written || closing {break}
	}
	let _ = timeout(CLOSE_WAIT, wr.shutdown()).await;
}

// One header block being collected: from a HEADERS frame to the CONTINUATION frame that ends it.
struct Block {stream: u32, bytes: Vec<u8>, ended: bool, since: Instant}

// A stream the reader keeps while its task runs: the way to the task, and what the reader needs to hold the peer to its windows.
struct Open {tx: Option<mpsc::Sender<Vec<u8>>>, cancel: watch::Sender<bool>, recv: Arc<Recv>, answered: Arc<AtomicBool>, reset: bool}

fn goaway(last: u32, code: u32) -> Vec<u8> {
	let mut bytes = Vec::new();
	frames::goaway(last, code, &mut bytes);
	bytes
}

/// One HTTP/2 connection of a direct peer, after its TLS handshake chose `h2`, until it ends. `place` is its place in the undecided pool until its first stream is decided.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve(shared: Arc<Shared>, listener: Arc<Listener>, served: Arc<Served>, io: Stream, modern: bool, peer: SocketAddr, local: SocketAddr, place: Place) {
	listener.counters.count(Count::H2Connections);
	let (rd, wr) = split(io);
	let (out, out_rx) = mpsc::channel(128);
	let (events, mut events_rx) = mpsc::unbounded_channel();
	let (trip, mut tripped) = watch::channel(None);
	let owed = Arc::new(AtomicUsize::new(0));
	let wire = Arc::new(Wire {
		out, windows: Mutex::new(Windows {connection: i64::from(frames::WINDOW_DEFAULT), streams: HashMap::new()}), wake: Notify::new(), connection: Recv::new(i64::from(frames::WINDOW_DEFAULT)), initial: AtomicI64::new(i64::from(frames::WINDOW_DEFAULT)), trip, owed: owed.clone(), held: AtomicUsize::new(0),
		opened: Mutex::new(Tally::new(OPENED)), early: Mutex::new(Tally::new(EARLY)), empty: Mutex::new(Tally::new(EMPTY)), proved: AtomicBool::new(false), events, counters: listener.counters.clone(),
	});
	let writing = tokio::spawn(writer(wr, out_rx, owed));
	// The node's SETTINGS at once, the same for everyone: the defaults for the windows, so none of them is sent.
	let mut greeting = Vec::new();
	frames::settings(&[(frames::HEADER_TABLE_SIZE, HEADER_TABLE), (frames::MAX_CONCURRENT_STREAMS, STREAMS_MAX as u32), (frames::MAX_HEADER_LIST_SIZE, frames::HEADER_LIST as u32), (frames::ENABLE_CONNECT_PROTOCOL, 1)], &mut greeting);
	wire.queue(Out::Raw(greeting)).await;
	let (bump, kill, ip, cid) = (place.bump.clone(), Arc::new(Notify::new()), peer.ip(), listener.ids.fetch_add(1, Ordering::Relaxed));
	{
		let mut sources = listener.h2.sources();
		let source = sources.entry(ip).or_default();
		source.connections.push_back((cid, kill.clone()));
		// "A direct source may hold at most 4 relayed HTTP/2 connections": over that the one that was there longest is closed.
		while source.connections.len() > CONNECTIONS_SOURCE {
			if let Some((_, oldest)) = source.connections.pop_front() {oldest.notify_one()}
		}
	}
	let _sourced = Sourced {listener: listener.clone(), ip, id: cid};
	let (frames_tx, mut frames_rx) = mpsc::channel(32);
	let (mut rd, mut pending) = (rd, Some(place));
	let mut preface = [0u8; 24];
	// The preface, inside the time the first HEADERS has. A client that sends anything else after choosing `h2` gets a GOAWAY of the node's own.
	let started = Instant::now();
	let sent = match timeout(FIRST_HEADERS, rd.read_exact(&mut preface)).await {
		Ok(Ok(_)) => preface == *frames::PREFACE,
		Ok(Err(_)) => return writing.abort(),
		Err(_) => {
			wire.queue(Out::Close(goaway(0, frames::NO_ERROR))).await;
			let _ = timeout(CLOSE_WAIT, writing).await;
			return;
		}
	};
	if !sent {
		wire.queue(Out::Close(goaway(0, frames::PROTOCOL_ERROR))).await;
		let _ = timeout(CLOSE_WAIT, writing).await;
		return;
	}
	let reading = tokio::spawn(reader(rd, frames_tx));
	let ctx = Arc::new(Ctx {shared, listener, served, wire: wire.clone(), peer, local, upstream: Arc::new(Semaphore::new(UPSTREAM)), modern});
	let (mut decoder, mut streams, mut tasks, mut block, mut last) = (Decoder::new(HEADER_TABLE as usize), HashMap::<u32, Open>::new(), JoinSet::new(), None::<Block>, 0u32);
	let (mut undecided, mut relayed, mut quiet) = (true, None::<(Relaying<'_>, Arc<Relayed>)>, Instant::now());
	let mut peer_initial = i64::from(frames::WINDOW_DEFAULT);
	let mut tick = tokio::time::interval(Duration::from_secs(1));
	let code = loop {
		let due = [undecided.then_some(started + FIRST_HEADERS), block.as_ref().map(|block| block.since + BLOCK_TIME), (streams.is_empty() && block.is_none()).then_some(quiet + IDLE)].into_iter().flatten().min();
		tokio::select! {
			biased;
			_ = bump.notified(), if undecided => break frames::NO_ERROR,
			_ = kill.notified() => break frames::NO_ERROR,
			_ = async {match &relayed {Some((_, slot)) => slot.kill.notified().await, None => std::future::pending().await}} => break frames::NO_ERROR,
			_ = tripped.changed() => break (*tripped.borrow()).unwrap_or(frames::INTERNAL_ERROR),
			_ = tick.tick() => if ctx.listener.closed.load(Ordering::Acquire) {break frames::NO_ERROR},
			_ = async {match due {Some(due) => sleep_until(due).await, None => std::future::pending().await}} => {
				if undecided && started.elapsed() >= FIRST_HEADERS {break frames::NO_ERROR}
				if streams.is_empty() && block.is_none() && quiet.elapsed() >= IDLE {break frames::NO_ERROR}
				if block.as_ref().is_some_and(|block| block.since.elapsed() >= BLOCK_TIME) {break frames::ENHANCE_YOUR_CALM}
			}
			event = events_rx.recv() => match event {
				Some(Event::Done(id)) => {
					streams.remove(&id);
					ctx.wire.windows().streams.remove(&id);
					quiet = Instant::now();
				}
				Some(Event::Stranger) if undecided => {
					undecided = false;
					relayed = Some(relay_slot(&ctx, cid));
				}
				Some(Event::Stranger) => {}
				Some(Event::Proved(acked)) => {
					undecided = false;
					if !ctx.wire.proved.swap(true, Ordering::Relaxed) {
						// Only a user's connection is told of the larger windows, by a second SETTINGS and a WINDOW_UPDATE.
						ctx.upstream.forget_permits(UPSTREAM - UPSTREAM_USER);
						let (stream_delta, connection_delta) = (i64::from(USER_STREAM_WINDOW) - ctx.wire.initial.swap(i64::from(USER_STREAM_WINDOW), Ordering::Relaxed), i64::from(USER_CONNECTION_WINDOW - frames::WINDOW_DEFAULT));
						for open in streams.values() {open.recv.window.fetch_add(stream_delta, Ordering::Relaxed);}
						ctx.wire.connection.window.fetch_add(connection_delta, Ordering::Relaxed);
						let mut bytes = Vec::new();
						frames::settings(&[(frames::INITIAL_WINDOW_SIZE, USER_STREAM_WINDOW)], &mut bytes);
						frames::window_update(0, connection_delta as u32, &mut bytes);
						ctx.wire.queue(Out::Raw(bytes)).await;
					}
					let _ = acked.send(());
					}
				None => break frames::INTERNAL_ERROR,
			},
			read = frames_rx.recv() => {
				let (header, payload) = match read {
					Some(Read::Frame(header, payload)) => (header, payload),
					Some(Read::Oversize) => break frames::FRAME_SIZE_ERROR,
					Some(Read::Gone) | None => {
						writing.abort();
						reading.abort();
						tasks.abort_all();
						return;
					}
				};
				// Frames that carry nothing, and any frame on a stream that is over, count against the empty-frame limit.
				if header.stream != 0 && header.stream <= last && !streams.contains_key(&header.stream) {ctx.wire.empty()}
				if payload.is_empty() && matches!(header.kind, frames::DATA | frames::CONTINUATION | frames::RST_STREAM) {ctx.wire.empty()}
				if let Some((_, slot)) = &relayed {slot.last.store(Clock::of((ctx.shared.now)()).ms, Ordering::Relaxed)}
				if block.is_some() && header.kind != frames::CONTINUATION {break frames::PROTOCOL_ERROR}
				match header.kind {
					frames::HEADERS => {
						if header.stream == 0 || header.stream % 2 == 0 {break frames::PROTOCOL_ERROR}
						let Some(fragment) = frames::unpad(header.flags, &payload, true) else {break frames::PROTOCOL_ERROR};
						if fragment.len() > frames::HEADER_LIST {break frames::ENHANCE_YOUR_CALM}
						block = Some(Block {stream: header.stream, bytes: fragment.to_vec(), ended: header.flags & frames::END_STREAM != 0, since: Instant::now()});
					}
					frames::CONTINUATION => {
						let Some(open) = block.as_mut().filter(|open| open.stream == header.stream) else {break frames::PROTOCOL_ERROR};
						if open.bytes.len() + payload.len() > frames::HEADER_LIST {break frames::ENHANCE_YOUR_CALM}
						open.bytes.extend_from_slice(&payload);
					}
					frames::DATA => {
						if header.stream == 0 {break frames::PROTOCOL_ERROR}
						let size = payload.len() as i64;
						if ctx.wire.connection.window.fetch_sub(size, Ordering::Relaxed) < size {break frames::FLOW_CONTROL_ERROR}
						if header.stream > last {break frames::PROTOCOL_ERROR}
						let Some(data) = frames::unpad(header.flags, &payload, false) else {break frames::PROTOCOL_ERROR};
						let padding = payload.len() - data.len();
						let Some(open) = streams.get_mut(&header.stream) else {
							// A stream that is over: its bytes were counted against the connection, and the credit for them is returned at once.
							ctx.wire.credit(0, None, payload.len()).await;
							continue;
						};
						if open.recv.window.fetch_sub(size, Ordering::Relaxed) < size {break frames::FLOW_CONTROL_ERROR}
						if padding > 0 {ctx.wire.credit(header.stream, Some(&open.recv), padding).await}
						let ended = header.flags & frames::END_STREAM != 0;
						match open.tx.as_ref() {
							None => {
								if !open.reset {
									open.reset = true;
									ctx.wire.reset(header.stream, frames::STREAM_CLOSED).await;
								}
								ctx.wire.credit(header.stream, Some(&open.recv), data.len()).await;
							}
							Some(tx) => {
								if !data.is_empty() && tx.try_send(data.to_vec()).is_err() {
									open.tx = None;
									open.cancel.send_replace(true);
									open.reset = true;
									ctx.wire.reset(header.stream, frames::ENHANCE_YOUR_CALM).await;
									ctx.wire.early();
								} else if ended {open.tx = None}
							}
						}
					}
					frames::RST_STREAM => {
						if payload.len() != 4 {break frames::FRAME_SIZE_ERROR}
						if header.stream == 0 || header.stream > last {break frames::PROTOCOL_ERROR}
						if let Some(open) = streams.get_mut(&header.stream) {
							open.tx = None;
							open.cancel.send_replace(true);
							ctx.wire.windows().streams.remove(&header.stream);
							ctx.wire.wake.notify_waiters();
							// A stream that ends before its answer was whole counts, whoever ended it.
							if !open.answered.load(Ordering::Relaxed) {ctx.wire.early()}
						}
					}
					frames::SETTINGS => {
						if header.stream != 0 {break frames::PROTOCOL_ERROR}
						if header.flags & frames::ACK != 0 {
							if !payload.is_empty() {break frames::FRAME_SIZE_ERROR}
							continue;
						}
						let Some(entries) = frames::read_settings(&payload) else {break frames::FRAME_SIZE_ERROR};
						let mut code = None;
						for (id, value) in entries {
							match id {
								frames::HEADER_TABLE_SIZE => ctx.wire.queue(Out::Table(value as usize)).await,
								frames::ENABLE_PUSH if value > 1 => code = Some(frames::PROTOCOL_ERROR),
								frames::INITIAL_WINDOW_SIZE if value > frames::WINDOW_MAX => code = Some(frames::FLOW_CONTROL_ERROR),
								frames::INITIAL_WINDOW_SIZE => {
									let mut windows = ctx.wire.windows();
									let delta = i64::from(value) - peer_initial;
									peer_initial = i64::from(value);
									for window in windows.streams.values_mut() {*window += delta}
									if windows.streams.values().any(|window| *window > i64::from(frames::WINDOW_MAX)) {code = Some(frames::FLOW_CONTROL_ERROR)}
									drop(windows);
									ctx.wire.wake.notify_waiters();
								}
								frames::MAX_FRAME_SIZE if !(frames::FRAME_MAX as u32..=0x00ff_ffff).contains(&value) => code = Some(frames::PROTOCOL_ERROR),
								_ => {}
							}
						}
						if let Some(code) = code {break code}
						if ctx.wire.owed.fetch_add(1, Ordering::Relaxed) >= OWED {break frames::ENHANCE_YOUR_CALM}
						let mut ack = Vec::new();
						frames::frame(frames::SETTINGS, frames::ACK, 0, &[], &mut ack);
						ctx.wire.queue(Out::Owed(ack)).await;
					}
					frames::PING => {
						if header.stream != 0 {break frames::PROTOCOL_ERROR}
						if payload.len() != 8 {break frames::FRAME_SIZE_ERROR}
						if header.flags & frames::ACK == 0 {
							if ctx.wire.owed.fetch_add(1, Ordering::Relaxed) >= OWED {break frames::ENHANCE_YOUR_CALM}
							let mut ack = Vec::new();
							frames::frame(frames::PING, frames::ACK, 0, &payload, &mut ack);
							ctx.wire.queue(Out::Owed(ack)).await;
						}
					}
					frames::WINDOW_UPDATE => {
						if payload.len() != 4 {break frames::FRAME_SIZE_ERROR}
						let increment = i64::from(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & frames::WINDOW_MAX);
						// Every session's connection sends them; a connection that is not one has no reason to.
						if !ctx.wire.proved.load(Ordering::Relaxed) {ctx.wire.empty()}
						if header.stream > last {break frames::PROTOCOL_ERROR}
						if increment == 0 {
							if header.stream == 0 {break frames::PROTOCOL_ERROR}
							if let Some(open) = streams.get_mut(&header.stream) {
								if !open.reset {
									open.reset = true;
									ctx.wire.reset(header.stream, frames::PROTOCOL_ERROR).await;
								}
							}
							continue;
						}
						let mut over = false;
						{
							let mut windows = ctx.wire.windows();
							if header.stream == 0 {
								windows.connection += increment;
								if windows.connection > i64::from(frames::WINDOW_MAX) {break frames::FLOW_CONTROL_ERROR}
							} else if let Some(window) = windows.streams.get_mut(&header.stream) {
								*window += increment;
								over = *window > i64::from(frames::WINDOW_MAX);
							}
						}
						if over {
							ctx.wire.reset(header.stream, frames::FLOW_CONTROL_ERROR).await;
							continue;
						}
						ctx.wire.wake.notify_waiters();
					}
					frames::PRIORITY => {
						if payload.len() != 5 {break frames::FRAME_SIZE_ERROR}
						if header.stream == 0 {break frames::PROTOCOL_ERROR}
						ctx.wire.empty();
					}
					frames::PUSH_PROMISE => break frames::PROTOCOL_ERROR,
					frames::GOAWAY => break frames::NO_ERROR,
					_ => ctx.wire.empty(),
				}
				if header.kind == frames::HEADERS || header.kind == frames::CONTINUATION {
					if header.flags & frames::END_HEADERS == 0 {continue}
					let Some(done) = block.take() else {continue};
					let Ok(fields) = decoder.decode(&done.bytes, frames::HEADER_LIST) else {break frames::COMPRESSION_ERROR};
					if let Some(open) = streams.get_mut(&done.stream) {
						// Trailers: counted against the header limit by the decoder, and dropped. They must end the stream.
						if !done.ended || open.tx.is_none() {
							open.tx = None;
							ctx.wire.reset(done.stream, if done.ended {frames::STREAM_CLOSED} else {frames::PROTOCOL_ERROR}).await;
							ctx.wire.early();
						} else {open.tx = None}
						continue;
					}
					if done.stream <= last {
						ctx.wire.reset(done.stream, frames::STREAM_CLOSED).await;
						continue;
					}
					last = done.stream;
					if ctx.wire.opened.lock().unwrap_or_else(|e| e.into_inner()).hit() {break frames::ENHANCE_YOUR_CALM}
					// A list with no fields has no pseudo-header to decide by.
					if fields.is_empty() {
						ctx.listener.counters.count(Count::H2Refused);
						ctx.wire.reset(done.stream, frames::PROTOCOL_ERROR).await;
						ctx.wire.empty();
						continue;
					}
					if streams.len() >= STREAMS_MAX || ctx.listener.h2.held.load(Ordering::Relaxed) >= HELD_LISTENER {
						ctx.wire.reset(done.stream, frames::REFUSED_STREAM).await;
						ctx.wire.early();
						continue;
					}
					let (tx, rx) = mpsc::channel(256);
					let (cancel, cancelled) = watch::channel(false);
					let (recv, answered) = (Arc::new(Recv::new(ctx.wire.initial.load(Ordering::Relaxed))), Arc::new(AtomicBool::new(false)));
					ctx.wire.windows().streams.insert(done.stream, peer_initial);
					streams.insert(done.stream, Open {tx: if done.ended {None} else {Some(tx)}, cancel, recv: recv.clone(), answered: answered.clone(), reset: false});
					let place = pending.take();
					tasks.spawn(task(ctx.clone(), done.stream, fields, done.ended, rx, cancelled, recv, answered, place));
				}
			}
		}
	};
	drop(relayed);
	if code == frames::ENHANCE_YOUR_CALM && tripped.borrow().is_none() {ctx.listener.counters.count(Count::H2Limit)}
	ctx.wire.queue(Out::Close(goaway(last, code))).await;
	let _ = timeout(CLOSE_WAIT, writing).await;
	reading.abort();
	tasks.abort_all();
}

// A relayed connection in the pool: the same displacement rule as an HTTP/1.1 stranger's, one place for the connection. "Relayed: the relayed connection that has been idle longest is closed."
fn relay_slot(ctx: &Ctx, id: u64) -> (Relaying<'_>, Arc<Relayed>) {
	let now = Clock::of((ctx.shared.now)()).ms;
	let slot = Arc::new(Relayed {last: AtomicI64::new(now), kill: Notify::new()});
	let mut relayed = ctx.listener.relayed();
	if relayed.len() >= ctx.served.pools.relayed {
		let idlest = relayed.iter().min_by_key(|(_, held)| held.last.load(Ordering::Relaxed)).filter(|(_, held)| now.saturating_sub(held.last.load(Ordering::Relaxed)) >= RELAY_IDLE.as_millis() as i64).map(|(id, _)| *id);
		if let Some((_, evicted)) = idlest.or_else(|| relayed.keys().next().copied()).and_then(|evicted| relayed.remove_entry(&evicted)) {
			evicted.kill.notify_one();
			ctx.listener.counters.count(Count::Evicted);
		}
	}
	relayed.insert(id, slot.clone());
	drop(relayed);
	(Relaying {listener: &ctx.listener, id}, slot)
}

#[allow(clippy::too_many_arguments)]
async fn task(ctx: Arc<Ctx>, id: u32, fields: Fields, ended: bool, rx: mpsc::Receiver<Vec<u8>>, mut cancel: watch::Receiver<bool>, recv: Arc<Recv>, answered: Arc<AtomicBool>, place: Option<Place>) {
	let outcome = decide(&ctx, id, fields, ended, rx, &mut cancel, &recv, &answered, place).await;
	if matches!(outcome, Outcome::Aborted) {ctx.wire.early()}
	let _ = ctx.wire.events.send(Event::Done(id));
}

// Evaluates the stream at the end of its header block: steps 1 to 4 of "Verifying" for every extended CONNECT for `websocket`, with a dummy line for every other stream, so that the work does not tell them apart.
#[allow(clippy::too_many_arguments)]
async fn decide(ctx: &Arc<Ctx>, id: u32, fields: Fields, ended: bool, rx: mpsc::Receiver<Vec<u8>>, cancel: &mut watch::Receiver<bool>, recv: &Arc<Recv>, answered: &Arc<AtomicBool>, place: Option<Place>) -> Outcome {
	let get = |name: &[u8]| fields.iter().find(|(known, _)| known == name).map(|(_, value)| value.as_slice());
	let target = [b"GET ".as_slice(), get(b":path").unwrap_or_default(), b" HTTP/1.1\r\n"].concat();
	let candidate = get(b":method") == Some(b"CONNECT") && get(b":protocol") == Some(b"websocket") && !ended && fields.iter().map(|(name, value)| name.len() + value.len() + 4).sum::<usize>() <= HEAD_MAX && Line::parse(&target).is_some();
	let line = if candidate {target} else {b"GET /a HTTP/1.1\r\n".to_vec()};
	let proved = prove(&ctx.shared, &ctx.listener, &ctx.served, &line, &[], |route| candidate && ctx.modern && route.over == Over::Tls, ctx.peer.ip(), place.as_ref()).await;
	match proved {
		Ok(accepted) => {
			drop(place);
			ctx.listener.counters.count(Count::Proofs);
			ctx.listener.counters.count(Count::H2Users);
			let (acked, sent) = oneshot::channel();
			let _ = ctx.wire.events.send(Event::Proved(acked));
			let _ = sent.await;
			user(ctx, id, &fields, line, accepted, rx, cancel, recv, answered).await
		}
		Err(why) => {
			ctx.listener.counters.strangers[why as usize].fetch_add(1, Ordering::Relaxed);
			drop(place);
			ctx.listener.counters.count(Count::H2Strangers);
			let _ = ctx.wire.events.send(Event::Stranger);
			stranger(ctx, id, &fields, ended, rx, cancel, recv, answered).await
		}
	}
}

// A user's stream: the session of `tls` runs over a pipe, as if the peer had sent the HTTP/1.1 upgrade of "WebSocket session". Its answer head is turned into a HEADERS frame, and from there the WebSocket frames travel in DATA frames as they would in TLS records.
#[allow(clippy::too_many_arguments)]
async fn user(ctx: &Arc<Ctx>, id: u32, fields: &Fields, line: Vec<u8>, accepted: Accepted, mut rx: mpsc::Receiver<Vec<u8>>, cancel: &mut watch::Receiver<bool>, recv: &Arc<Recv>, answered: &Arc<AtomicBool>) -> Outcome {
	let mut key = [0u8; 16];
	if random(&mut key).is_err() {return Outcome::Aborted}
	let version: Vec<&[u8]> = fields.iter().filter(|(name, _)| name == b"sec-websocket-version").map(|(_, value)| value.as_slice()).collect();
	let mut head = line.clone();
	head.extend_from_slice(format!("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\n", base64::engine::general_purpose::STANDARD.encode(key)).as_bytes());
	if let [version] = version[..] {
		head.extend_from_slice(b"Sec-WebSocket-Version: ");
		head.extend_from_slice(version);
		head.extend_from_slice(b"\r\n");
	}
	head.extend_from_slice(b"\r\n");
	let (ours, theirs) = tokio::io::duplex(65_536);
	let (filled, line) = (head.len(), line.len());
	let (shared, listener, served, peer) = (ctx.shared.clone(), ctx.listener.clone(), ctx.served.clone(), ctx.peer);
	tokio::spawn(async move {session(&shared, &listener, &served, Box::new(ours), peer, head, filled, line, accepted).await});
	let (mut from_session, mut to_session) = split(theirs);
	let (wire, mut buf, mut read) = (&ctx.wire, Vec::new(), vec![0u8; READ]);
	let up = async {
		while let Some(data) = rx.recv().await {
			let count = data.len();
			if to_session.write_all(&data).await.is_err() {return}
			wire.credit(id, Some(recv), count).await;
		}
		let _ = to_session.shutdown().await;
		std::future::pending::<()>().await
	};
	let down = async {
		// The answer head the session wrote, until its empty line.
		let end = loop {
			if let Some(end) = head_end(&buf) {break end}
			if buf.len() > HEAD_MAX {return false}
			match timeout(HEAD_TIME, from_session.read(&mut read)).await {
				Ok(Ok(count)) if count > 0 => buf.extend_from_slice(&read[..count]),
				_ => return false,
			}
		};
		let Some(answer) = gateway::response(&buf[..end], false, true) else {return false};
		let mut list = vec![(b":status".to_vec(), b"200".to_vec())];
		list.extend(answer.fields);
		wire.queue(Out::Headers(id, list, false)).await;
		let rest = buf.split_off(end);
		if !rest.is_empty() && !wire.data(id, &rest, false, None).await {return false}
		loop {
			let Some(room) = wire.room(id, READ, None).await else {return false};
			match from_session.read(&mut read[..room]).await {
				Ok(count) if count > 0 => if !wire.data(id, &read[..count], false, None).await {return false},
				_ => return true,
			}
		}
	};
	let finished = tokio::select! {
		biased;
		_ = gone(cancel) => return Outcome::Cancelled,
		_ = up => return Outcome::Cancelled,
		finished = down => finished,
	};
	if !finished {
		wire.reset(id, frames::CANCEL).await;
		return Outcome::Complete;
	}
	// The session is over and has said its Close. END_STREAM follows, and the peer gets the time of the close to end its side.
	wire.data(id, &[], true, None).await;
	answered.store(true, Ordering::Relaxed);
	let _ = timeout(CLOSE_WAIT, async {while rx.recv().await.is_some() {}}).await;
	if !*cancel.borrow() {wire.reset(id, frames::NO_ERROR).await}
	Outcome::Complete
}

// Writes to the origin within a time, and says whether it all went.
async fn put_origin(to_origin: &mut WriteHalf<Stream>, bytes: &[u8]) -> bool {timeout(HEAD_TIME, to_origin.write_all(bytes)).await.is_ok_and(|written| written.is_ok())}

// A stranger's stream: the request is checked and turned into HTTP/1.1 for the decoy origin, on a connection of its own that is closed after the answer, and the answer is turned back and handed to the peer at the pace of its windows.
#[allow(clippy::too_many_arguments)]
async fn stranger(ctx: &Arc<Ctx>, id: u32, fields: &Fields, ended: bool, mut rx: mpsc::Receiver<Vec<u8>>, cancel: &mut watch::Receiver<bool>, recv: &Arc<Recv>, answered: &Arc<AtomicBool>) -> Outcome {
	let (wire, listener) = (&ctx.wire, &ctx.listener);
	let mut key = [0u8; 16];
	if random(&mut key).is_err() {return Outcome::Aborted}
	let Ok(request) = gateway::request(fields, ended, &base64::engine::general_purpose::STANDARD.encode(key)) else {
		listener.counters.count(Count::H2Refused);
		wire.reset(id, frames::PROTOCOL_ERROR).await;
		return Outcome::Aborted;
	};
	// A stream that has to wait for an upstream connection waits for as long as the origin may take to connect, and is then refused.
	let permit = tokio::select! {
		biased;
		_ = gone(cancel) => return Outcome::Cancelled,
		permit = timeout(DECOY_CONNECT, ctx.upstream.clone().acquire_owned()) => match permit {
			Ok(Ok(permit)) => permit,
			_ => {
				wire.reset(id, frames::REFUSED_STREAM).await;
				return Outcome::Aborted;
			}
		},
	};
	let upstream = {
		let mut sources = listener.h2.sources();
		let source = sources.entry(ctx.peer.ip()).or_default();
		if source.upstream >= UPSTREAM_SOURCE {None} else {
			source.upstream += 1;
			Some(Upstream {listener: listener.clone(), ip: ctx.peer.ip()})
		}
	};
	let Some(upstream) = upstream else {
		wire.reset(id, frames::REFUSED_STREAM).await;
		return Outcome::Aborted;
	};
	let _held = (permit, upstream);
	let dialled = tokio::select! {
		biased;
		_ = gone(cancel) => return Outcome::Cancelled,
		dialled = ctx.served.origin.dial(if ctx.served.proxy {Proxy::Peer(ctx.peer, ctx.local)} else {Proxy::None}) => dialled,
	};
	let Ok(origin) = dialled else {
		// "The stream is reset with CANCEL and counted as `decoy_down`", and the connection stays.
		listener.counters.count(Count::DecoyDown);
		listener.decoy(false);
		wire.reset(id, frames::CANCEL).await;
		return Outcome::Aborted;
	};
	listener.decoy(true);
	listener.counters.count(Count::Relayed);
	let (mut from_origin, mut to_origin) = split(origin);
	if !put_origin(&mut to_origin, &request.head).await {
		wire.reset(id, frames::CANCEL).await;
		return Outcome::Aborted;
	}
	let (mut seen, mut open, mut ready, mut head, mut read, mut framing, mut chunks, mut left) = (0u64, !ended, !request.upgrade, Vec::new(), vec![0u8; READ], None::<Framing>, gateway::Chunked::new(), 0u64);
	loop {
		let reading = async {
			// Before the answer head is whole, a read is the origin's own head and takes no room. After it, a read takes what the windows and the bounds allow, and waits for them.
			if framing.is_none() {return from_origin.read(&mut read).await.map(|count| (count, None))}
			let (Some(room), Some(hold)) = (wire.room(id, READ, Some(ZERO_WINDOW)).await, wire.hold(listener, READ, ZERO_WINDOW).await) else {return Err(io::Error::from(io::ErrorKind::TimedOut))};
			from_origin.read(&mut read[..room]).await.map(|count| (count, Some(hold)))
		};
		tokio::select! {
			biased;
			_ = gone(cancel) => return Outcome::Cancelled,
			// An extended CONNECT's DATA waits for the origin's 101.
			item = rx.recv(), if open && ready => match item {
				Some(data) => {
					seen += data.len() as u64;
					if request.length.is_some_and(|length| seen > length) {
						wire.reset(id, frames::PROTOCOL_ERROR).await;
						return Outcome::Aborted;
					}
					let written = if request.chunked {put_origin(&mut to_origin, &[format!("{:x}\r\n", data.len()).as_bytes(), &data, b"\r\n"].concat()).await} else {put_origin(&mut to_origin, &data).await};
					if !written {
						wire.reset(id, frames::CANCEL).await;
						return Outcome::Aborted;
					}
					wire.credit(id, Some(recv), data.len()).await;
				}
				None => {
					open = false;
					if request.length.is_some_and(|length| seen != length) {
						wire.reset(id, frames::PROTOCOL_ERROR).await;
						return Outcome::Aborted;
					}
					if request.chunked && !put_origin(&mut to_origin, b"0\r\n\r\n").await {
						wire.reset(id, frames::CANCEL).await;
						return Outcome::Aborted;
					}
					if request.upgrade {let _ = to_origin.shutdown().await;}
				}
			},
			got = reading => {
				let Ok((count, hold)) = got else {
					wire.reset(id, frames::CANCEL).await;
					return Outcome::Aborted;
				};
				let mut data = Vec::new();
				if framing.is_none() {
					head.extend_from_slice(&read[..count]);
					// The head of an answer, an interim one passed over, until the final one is whole.
					loop {
						let Some(end) = head_end(&head) else {
							if count == 0 || head.len() > ANSWER_HEAD_MAX {
								wire.reset(id, frames::CANCEL).await;
								return Outcome::Aborted;
							}
							break;
						};
						let Some(answer) = gateway::response(&head[..end], request.bodiless, request.upgrade) else {
							wire.reset(id, frames::CANCEL).await;
							return Outcome::Aborted;
						};
						if request.upgrade && answer.status >= 200 && !answer.switched {
							wire.reset(id, frames::CANCEL).await;
							return Outcome::Aborted;
						}
						ready |= answer.switched;
						if answer.status < 200 {
							head.drain(..end);
							continue;
						}
						let mut list = vec![(b":status".to_vec(), answer.status.to_string().into_bytes())];
						list.extend(answer.fields);
						wire.queue(Out::Headers(id, list, answer.framing == Framing::None)).await;
						if let Framing::Length(length) = answer.framing {left = length}
						framing = Some(answer.framing);
						data = head.split_off(end);
						head.clear();
						break;
					}
					if framing.is_none() {continue}
				} else {data = read[..count].to_vec()}
				let _hold = hold;
				let mut out = Vec::new();
				let last = match framing {
					Some(Framing::None) => true,
					Some(Framing::Length(_)) => {
						let take = (data.len() as u64).min(left) as usize;
						out.extend_from_slice(&data[..take]);
						left -= take as u64;
						left == 0
					}
					Some(Framing::Chunked) => match chunks.feed(&data, &mut out) {
						Ok((_, done)) => done,
						Err(_) => {
							wire.reset(id, frames::CANCEL).await;
							return Outcome::Aborted;
						}
					},
					_ => {
						out = data;
						count == 0
					}
				};
				// The answer was whole at its head (a `204`, a `HEAD`), or this data ends it, or the origin closed an answer that ends where the connection does.
				if framing != Some(Framing::None) && !wire.data(id, &out, last, Some(ZERO_WINDOW)).await {
					wire.reset(id, frames::CANCEL).await;
					return Outcome::Aborted;
				}
				if last {
					answered.store(true, Ordering::Relaxed);
					if open {wire.reset(id, frames::NO_ERROR).await}
					return Outcome::Complete;
				}
				if count == 0 {
					// The origin closed before its answer was whole.
					wire.reset(id, frames::CANCEL).await;
					return Outcome::Aborted;
				}
			}
		}
	}
}
