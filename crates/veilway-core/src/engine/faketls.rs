//! The listener of the `faketls` transport (borrowed-site page, "Strangers: the relay to the site", "What the node answers with", "Pools", "Errors", "Probes and replays" and "The session"): ALPHA, new and unreviewed.
//! The node holds no certificate. A connection that proves itself inside its ClientHello (`veilway_proto::faketls`) gets a TLS 1.3 handshake the node writes itself (`veilway_proto::flight`) and then a session of frames, and every other connection is relayed byte for byte to the real site the operator named.
//! The node writes no byte of its own to a stranger, in any state. It reads the start of a connection as the records of a ClientHello within the limits of the page (4 records, 8,192 bytes of handshake, 3 s from the first byte), and forwards at the first byte that makes it no candidate.
//!
//! The flight. At start, on a reload that changes the site and every 6 h the node probes the site (`veilway_transport::probe`) and keeps the last 32 shapes it got, none older than 7 days. A hello that opens is forwarded to the early connection, the site's answer to it is read, and the node's flight is written with the record sizes, grouping and offsets of that answer (the live copy), holding the messages of the kept shape whose size is nearest. Where there is no live answer the flight is one kept shape's, and where there is none either it is a made-up one, counted. After the client's Finished the tickets and the first application data records come from the shape, with its times, and a close, a record that fails to decrypt and a silent connection get the reaction the site showed.
//! After 24 h with no successful probe the node takes no proof and relays everything, until a probe succeeds. A flight for a hello that opened and got no session is answered from a token bucket per source and per listener, and a hello over it is closed with no answer.
//!
//! What this build does not do, and the page says it must:
//! - The timing of the flight is the live answer's only after the node has the whole answer: it takes the answer for complete when its size is one a kept shape has, or 50 ms after its last byte, so a flight whose size no shape has starts that much later than the site's.
//! - The signature of the CertificateVerify is not deterministic (RFC 6979): `ring` draws its nonce from the system.
//! - The hybrid group is answered only for a hello whose hybrid share the client made keys for, and a site that chooses a group the hello has no share for gets a kept shape of another group.
//! - `veilway doctor` does not check the site yet.
use super::inbound::{Tunnel, Via};
use super::limits::{Bucket, Clock, Ended, Handshakes, Initiation, Seat, Seated, Source, Spent, ENDS};
use super::flows::{connect_from, dial_conn, Conn};
use super::plan::{Native, Outbound, Proved};
use super::stream::{random, relay, Relayed, Stream, Undecided, DECOY_CONNECT, HELD, RELAY_IDLE, SEND_QUEUE, TLS_HANDSHAKE};
use super::Shared;
use crate::config::{ProofRate, DEFAULT_SESSIONS, DEFAULT_UNDECIDED, DEFAULT_UNDECIDED_PER_SOURCE};
use ring::rand::SystemRandom;
use socket2::SockRef;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::{sleep, sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{self, Padding, MAX_ITEMS, MAX_PLAINTEXT};
use veilway_proto::faketls::{Opened, Outcome};
use veilway_proto::flight::{afterwards, answer, answers, open, Ending, Made, Opening, Parser, Pending, React, Shape, Stream as Messages, Wire as Item, MOST_RECORDS};
use veilway_proto::replay::{Decision, Refusal, WRITE_DEADLINE};
use veilway_proto::session::{self, Transport, ECHO, LONE_KEEPALIVE};
use veilway_proto::tls13::{Keys, Suite, HEADER, RECORD, TAG};
use veilway_proto::uniform;
use veilway_transport::mlkem;
use veilway_transport::probe::{probe_over, Mode, Patience};

/// "ClientHello read: at most 8,192 bytes of handshake in at most 4 records."
const HELLO_BYTES: usize = 8192;
const HELLO_RECORDS: usize = 4;
/// "Hello hold: 3 s from the first byte of a record that can still be a ClientHello."
const HELLO_HOLD: Duration = Duration::from_secs(3);
/// What RFC 8446 section 5.1 allows a record to hold.
const RECORD_MAX: usize = 16_384;
/// "New connections to the site: burst 64, then 16 a second for a listener."
const SITE_BURST: u32 = 64;
/// "Strangers relayed to the site: 8 for one source", and "Hellos that open and are refused (decoy sessions): at most 2 for one source".
const STRANGERS_PER_SOURCE: usize = 8;
const DECOYS_PER_SOURCE: usize = 2;
/// "Either side sends a TLS `close_notify`, waits up to 5 s for the other, and closes TCP."
const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// How far apart the log lines of a state that lasts are: "log at warn at most once a minute".
const SAY_AGAIN: Duration = Duration::from_secs(60);
/// The connections a listener holds beyond its pools: those that are being closed, and proofs that wait for a limit.
const SPARE: usize = 2 * HELD;
const READ: usize = 4096;
/// How many echoes of one session wait for their delay at once.
const MAX_ECHOES: usize = 4;
/// "Probes of the site: 8 at start and on reload, 2 s apart, then one every 6 h."
const PROBES: usize = 8;
const PROBE_EVERY: Duration = Duration::from_secs(6 * 3600);
/// "Shapes kept: the last 32 successful probes, none older than 7 days."
const SHAPES: usize = 32;
const SHAPES_FOR: u64 = 7 * 24 * 3600;
/// "No successful probe: after 24 h the node stops accepting proofs, and relays everything, until a probe succeeds."
const NO_PROBE: Duration = Duration::from_secs(24 * 3600);
/// "Live copy: the site connection is kept until the site's flight for the forwarded hello has arrived, at most 5 s, then closed."
const LIVE_COPY: Duration = Duration::from_secs(5);
/// Judgement calls of this build that the page's table does not name. How long after the last byte of the site's answer the node takes the flight for complete when the sizes of the shapes it kept do not say so, and how long a user waits at the most for the connection to the site that was opened at accept before the node answers from shapes.
const SETTLE: Duration = Duration::from_millis(50);
const LIVE_CONNECT: Duration = Duration::from_millis(400);
/// "A token bucket for refused-proof flights per source and per listener": a burst of 4 and one a second for a source, a burst of 64 and 16 a second for a listener, the numbers of the node's connections to the site. Judgement calls. The table of sources is emptied when it passes the size below.
const FLIGHTS_SOURCE: ProofRate = ProofRate {burst: 4, rate: 1};
const FLIGHTS_LISTENER: ProofRate = ProofRate {burst: 64, rate: 16};
const SOURCES_MOST: usize = 16_384;
/// The longest a reaction of a shape is waited for, and what a connection that sent nothing is given when no shape says how long the site waits.
const REACT_MOST: Duration = Duration::from_secs(120);
/// About 1.1 MB: the most of a site's answer that a live copy takes in.
const LIVE_MOST: usize = 1_100_000;
const SILENT: React = React {after: Duration::from_secs(60), alert: None, ending: Ending::Fin};

/// Why a connection was not taken for a user's session. For the node's counters: the peer is given the site's answer, or a flight it cannot read, whatever it is, and nothing here is ever said to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
	/// A byte arrived that makes the bytes no candidate for a ClientHello, or a limit of the hello was reached.
	Syntax,
	/// The hello was not complete within the hold.
	Slow,
	/// The peer closed its side before its hello was complete.
	Closed,
	/// Decided at once to make room in the undecided pool.
	Displaced,
	/// The site said something, or closed its connection, while the hello was not complete: the site's own decision, which the peer is given at that moment.
	Origin,
	/// A complete hello that is no proof: another name, no proof in it, a proof that does not open, or a listener without a key to open it with.
	Hello,
	/// No probe of the site has succeeded for 24 h, so no proof is taken and everything is relayed.
	Stale,
	/// A hello that opened and was refused, from a source or a listener whose allowance of flights is spent: relayed to the site.
	Spent,
	/// From here on the hello opened: the node answers with a flight whose leaf is random, and opens no session. The carrier opened and a later check of steps 4 to 6 said no.
	Refused,
	Window,
	Floor,
	Seen,
	CacheFull,
	/// Above the written limit, and the write that raises it did not end within its deadline, or too many proofs waited for one.
	Limit,
	/// The node takes no proof right now: it has no replay memory, or the memory waits for its file.
	NoReplay,
	/// The listener's session pool is full.
	Pool,
	/// The device has 2 pending sessions.
	Pending,
	DeviceRate,
	SourceRate,
}

const WHYS: usize = Why::SourceRate as usize + 1;

#[derive(Clone, Copy)]
enum Count {Accepted, AcceptFailed, Broken, HandshakeFailed, HandshakeSlow, Early, Skipped, Relayed, Evicted, SiteDown, SiteBudget, Decoys, Proofs, Waited, Established, EstablishFull, Handshakes, Tunnel, QueueFull, Probes, ProbeFailed, Live, Kept, Generic, LiveMiss, FlightsSpent, Idled, Chunks}

const COUNTS: usize = Count::Chunks as usize + 1;

pub struct Counters {counts: [AtomicU64; COUNTS], whys: [AtomicU64; WHYS], ended: Arc<[AtomicU64; ENDS]>}

impl Default for Counters {
	fn default() -> Self {Counters {counts: std::array::from_fn(|_| AtomicU64::new(0)), whys: std::array::from_fn(|_| AtomicU64::new(0)), ended: Arc::default()}}
}

impl Counters {
	fn count(&self, what: Count) {self.counts[what as usize].fetch_add(1, Ordering::Relaxed);}
}

/// What the `faketls` listeners did since start, and what they hold right now. Everything but the first four only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FakeTlsTotals {
	/// Connections that have not been decided yet, right now.
	pub undecided: usize,
	/// Connections relayed to the site right now, and flights answered to a hello that opened and got no session.
	pub relayed: usize,
	/// Sessions whose proof was accepted and on which WireGuard has not authenticated yet, right now.
	pub pending: usize,
	/// Established sessions right now.
	pub sessions: usize,
	/// Connections the listeners took from the system, and failures to take one.
	pub accepted: u64,
	pub accept_failed: u64,
	/// Connections that broke before they were decided.
	pub broken: u64,
	/// TLS handshakes the node made that failed, and that did not finish in time.
	pub handshake_failed: u64,
	pub handshake_slow: u64,
	/// Connections to the site opened at accept, and connections that were taken without one because the budget for new connections to the site had no room.
	pub early_connections: u64,
	pub early_skipped: u64,
	/// Decided "not a user" and handed to the site, by the class of the reason.
	pub stranger_syntax: u64,
	pub stranger_slow: u64,
	pub stranger_closed: u64,
	pub stranger_displaced: u64,
	pub stranger_origin: u64,
	pub stranger_hello: u64,
	/// Hellos that opened and were answered with a flight of a random leaf and no session, by reason.
	pub refused_hello: u64,
	pub refused_window: u64,
	pub refused_floor: u64,
	pub refused_seen: u64,
	pub refused_cache_full: u64,
	pub refused_limit: u64,
	pub refused_no_replay: u64,
	pub refused_pool: u64,
	pub refused_pending: u64,
	pub refused_device_rate: u64,
	pub refused_source_rate: u64,
	/// Flights that were answered to a hello that opened and got no session.
	pub decoys: u64,
	/// Connections relayed to the site, relayed connections closed to make room for another, strangers closed with no answer because the site could not be reached, and because the budget for new connections to the site had no room.
	pub relays: u64,
	pub relays_evicted: u64,
	pub site_down: u64,
	pub site_budget: u64,
	/// Proofs that were accepted, those among all proofs that waited for the write of a higher limit, and sessions that became established.
	pub proofs_accepted: u64,
	pub proofs_waited: u64,
	pub established: u64,
	/// Sessions that could not become established because the session pool had filled up since their proof was accepted.
	pub establish_full: u64,
	/// Inside sessions: handshake initiations above a session's allowance, datagrams WireGuard did not take as a packet of the session's device, datagrams for a device dropped because the send queue of its connection was full, and frames the node sent.
	pub handshakes: u64,
	pub tunnel: u64,
	pub queue_full: u64,
	pub chunks_sent: u64,
	/// Probes of the site that kept a shape, probes that failed, and the shapes kept right now.
	pub probes: u64,
	pub probe_failed: u64,
	pub shapes: usize,
	/// Flights of hellos that opened, by what they were made from: the site's live answer, one kept shape, or a made-up one; and those that had a live answer no shape fitted.
	pub flights_live: u64,
	pub flights_kept: u64,
	pub flights_generic: u64,
	pub flights_live_miss: u64,
	/// Flights that were not answered because the allowance of the source or the listener was spent, and connections closed as a site closes one that sent nothing.
	pub flights_spent: u64,
	pub idled: u64,
	/// Connections relayed because no probe had succeeded for 24 h.
	pub stranger_stale: u64,
	/// Connections relayed because their flight was over the allowance of their source or listener.
	pub stranger_spent: u64,
	pub ended_deadline: u64,
	pub ended_idle: u64,
	pub ended_packets: u64,
	pub ended_displaced: u64,
	pub ended_revoked: u64,
	pub ended_closed: u64,
	pub ended_invalid: u64,
	pub ended_unserved: u64,
}

/// What a `faketls` listener serves at one moment, from the transport of the config and what `prepare` found. A connection takes it once, when it is accepted, and works on that one value.
pub struct Served {
	/// The tunnel of the inbound the transport belongs to, and the private key of the transport, which tells its `Borrowed` apart from another of the inbound.
	pub tunnel: Arc<Tunnel>,
	pub key: [u8; 32],
	/// `site.host`, which is the name of the throwaway leaf, and every name a hello may carry: the host first, then `site.names`.
	pub host: String,
	pub names: Vec<Vec<u8>>,
	/// The address of the site, from `site.address` or from the name when `prepare` resolved it.
	pub site: SocketAddr,
	/// `site.outbound`: its tag and the outbound as the engine dials through it. Every connection to the site leaves by it when it is set.
	pub outbound: Option<(String, Arc<Outbound>)>,
	/// `limits.relayed` and `limits.site_rate`.
	pub relayed: usize,
	pub rate: u32,
}

/// The next whole record in `raw`, taken out of it. Err for a header that no record has, before a byte of its body is waited for.
fn take_record(raw: &mut Vec<u8>) -> Result<Option<([u8; HEADER], Vec<u8>)>, ()> {
	let Some(&[kind, major, minor, high, low]) = raw.first_chunk::<HEADER>() else {return Ok(None)};
	let size = usize::from(u16::from_be_bytes([high, low]));
	if !(20..=23).contains(&kind) || major != 3 || size == 0 || size > RECORD {return Err(())}
	if raw.len() < HEADER + size {return Ok(None)}
	let body = raw[HEADER..HEADER + size].to_vec();
	raw.drain(..HEADER + size);
	Ok(Some(([kind, major, minor, high, low], body)))
}

/// The TLS 1.3 record layer of a session, after the handshake: what is written is cut into records of its own (`write` takes at most 16,384 bytes, so a frame is one record), and what is read is the content of the application data records. A `close_notify` from the peer reads as the end of the stream, an end of the connection without one as `UnexpectedEof`, and a record that does not open, or any other thing, as `InvalidData`.
struct Wire {tcp: TcpStream, send: Keys, receive: Keys, raw: Vec<u8>, plain: Vec<u8>, at: usize, out: Vec<u8>, sent: usize, closed: bool, ended: bool}

impl Wire {
	fn new(tcp: TcpStream, send: Keys, receive: Keys, raw: Vec<u8>) -> Wire {Wire {tcp, send, receive, raw, plain: Vec::new(), at: 0, out: Vec::new(), sent: 0, closed: false, ended: false}}

	fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		while self.sent < self.out.len() {
			match Pin::new(&mut self.tcp).poll_write(cx, &self.out[self.sent..]) {
				Poll::Ready(Ok(count)) => self.sent += count,
				Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
				Poll::Pending => return Poll::Pending,
			}
		}
		self.out.clear();
		self.sent = 0;
		Poll::Ready(Ok(()))
	}

	/// Seals `plaintext` as one record of its own of content type `kind` and writes it. The tickets and the first application data records of a shape are written so.
	async fn record(&mut self, kind: u8, plaintext: &[u8]) -> io::Result<()> {
		if !self.send.seal(kind, plaintext, 0, &mut self.out) {return Err(io::Error::other("the keys of the session are used up"))}
		self.flush().await
	}
}

impl AsyncRead for Wire {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		loop {
			if self.at < self.plain.len() {
				let take = (self.plain.len() - self.at).min(buf.remaining());
				buf.put_slice(&self.plain[self.at..self.at + take]);
				self.at += take;
				return Poll::Ready(Ok(()));
			}
			if self.ended {return Poll::Ready(Ok(()))}
			match take_record(&mut self.raw) {
				Err(()) => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
				Ok(Some((header, mut body))) => {
					// The compatibility `change_cipher_spec` of RFC 8446 appendix D.4 is passed over.
					if header[0] == 20 && body == [1] {continue}
					let this = &mut *self;
					match (header[0], this.receive.open(&header, &mut body)) {
						(23, Some((23, data))) => (this.plain, this.at) = (data.to_vec(), 0),
						(23, Some((21, [1, 0]))) => this.ended = true,
						_ => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
					}
				}
				Ok(None) => {
					let mut scratch = [0u8; 4096];
					let mut read = ReadBuf::new(&mut scratch);
					match Pin::new(&mut self.tcp).poll_read(cx, &mut read) {
						Poll::Ready(Ok(())) if read.filled().is_empty() => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
						Poll::Ready(Ok(())) => self.raw.extend_from_slice(read.filled()),
						Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
						Poll::Pending => return Poll::Pending,
					}
				}
			}
		}
	}
}

impl AsyncWrite for Wire {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		if let Poll::Ready(Err(error)) = self.drain(cx) {return Poll::Ready(Err(error))}
		if !self.out.is_empty() {return Poll::Pending}
		let take = buf.len().min(16_384);
		let this = &mut *self;
		if !this.send.seal(23, &buf[..take], 0, &mut this.out) {return Poll::Ready(Err(io::Error::other("the keys of the session are used up")))}
		Poll::Ready(Ok(take))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.drain(cx) {
			Poll::Ready(Ok(())) => Pin::new(&mut self.tcp).poll_flush(cx),
			other => other,
		}
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		if !self.closed {
			let this = &mut *self;
			if this.send.seal(21, &[1, 0], 0, &mut this.out) {this.closed = true}
		}
		match self.drain(cx) {
			Poll::Ready(Ok(())) => Pin::new(&mut self.tcp).poll_shutdown(cx),
			other => other,
		}
	}
}

/// "The node answers a close_notify after the time that a kept shape shows for the site", and the same for a record that fails to decrypt and a connection that sent nothing: waits, sends the alert the site sent (sealed under `send` when the session has keys, bytes of the same length that look the same before) and ends the connection the way the site did, with a FIN or a reset.
async fn react(tcp: &mut TcpStream, send: Option<&mut Keys>, how: &React) {
	sleep(how.after.min(REACT_MOST)).await;
	if let Some((size, level, description)) = how.alert {
		let mut out = Vec::new();
		if !send.is_some_and(|keys| keys.seal(21, &[level, description], size.saturating_sub(TAG + 3), &mut out)) {
			out = vec![23, 3, 3, (size >> 8) as u8, size as u8];
			out.resize(HEADER + size, 0);
			let _ = random(&mut out[HEADER..]);
		}
		let _ = tcp.write_all(&out).await;
	}
	match how.ending {
		Ending::Fin => drop(tcp.shutdown().await),
		Ending::Reset => drop(SockRef::from(&*tcp).set_linger(Some(Duration::ZERO))),
	}
}

/// Which reaction of a site a connection is given.
#[derive(Clone, Copy)]
enum Which {Notified, Garbage, Idle}

/// One burst of the site's answer as it arrived: when (from the moment the hello was written to the site), its records, and the ServerHello's choices if the burst has the ServerHello.
struct Heard {at: Duration, wire: Vec<Item>, hello: Option<(Suite, u16, bool)>}

enum Event {Heard(Heard), End, Bad}

/// "Live copy": the hello written to the connection opened at accept, and the site's answer to it read as it arrives. `events` gives each burst when it comes, and `End` when the flight is complete: its encrypted bytes are as many as a kept shape's, or a record the size of a Finished came last, or encrypted records came and then nothing for `quiet` (at least twice the round trip the probes measured, so that a flight of more than one window is not cut; before the first encrypted record the wait is the 5 s), or 5 s have passed, or the site ended the connection. `Bad` says the answer is no flight the client could take (see `MAX_FLIGHT`). The connection stays open until the `Live` is dropped, as a client that went away, or `finish` hands it back with every byte the site sent.
struct Live {events: mpsc::UnboundedReceiver<Event>, stop: Arc<Notify>, task: Option<JoinHandle<Option<(Stream, Vec<u8>)>>>, base: Instant}

impl Live {
	fn start(mut site: Stream, sent: Vec<u8>, session: Vec<u8>, known: Vec<usize>, quiet: Duration) -> Live {
		let (stop, base) = (Arc::new(Notify::new()), Instant::now());
		let (events, receiver) = mpsc::unbounded_channel();
		let held = stop.clone();
		let task = tokio::spawn(async move {
			if site.write_all(&sent).await.is_err() || site.flush().await.is_err() {return None}
			let (mut parser, mut raw, mut buf, mut last, end, mut ended) = (Parser::new(&session, MOST_RECORDS), Vec::new(), vec![0u8; 65_536], Instant::now(), base + LIVE_COPY, false);
			loop {
				if ended {
					held.notified().await;
					return Some((site, raw));
				}
				tokio::select! {
					biased;
					_ = held.notified() => return Some((site, raw)),
					got = timeout_at(if parser.sealed() == 0 {end} else {(last + quiet).min(end)}, site.read(&mut buf)) => match got {
						Ok(Ok(count)) if count > 0 => {
							raw.extend_from_slice(&buf[..count]);
							last = Instant::now();
							let first = parser.hello().is_none();
							match parser.feed(&buf[..count]) {
								Ok(wire) => {
									let finished = wire.iter().rev().find_map(|item| if let Item::Sealed(size) = item {Some(*size)} else {None}).zip(parser.hello()).is_some_and(|(size, (suite, ..))| size == 4 + suite.hash_len() + TAG + 1);
									if !wire.is_empty() {let _ = events.send(Event::Heard(Heard {at: base.elapsed(), wire, hello: parser.hello().filter(|_| first)}));}
									ended = finished || (parser.sealed() > 0 && known.contains(&parser.total())) || raw.len() > LIVE_MOST;
								}
								Err(()) => {
									let _ = events.send(Event::Bad);
									ended = true;
								}
							}
						}
						_ => ended = true,
					},
				}
				if ended {let _ = events.send(Event::End);}
			}
		});
		Live {events: receiver, stop, task: Some(task), base}
	}

	/// Stops reading and gives back the site's connection and every byte it sent.
	async fn finish(mut self) -> Option<(Stream, Vec<u8>)> {
		self.stop.notify_one();
		self.task.take()?.await.ok().flatten()
	}
}

impl Drop for Live {
	fn drop(&mut self) {
		if let Some(task) = &self.task {task.abort()}
	}
}

/// What a copy of the site's flight came to.
enum Copy {
	/// The handshake waits for the client's Finished, and the shape the messages are of.
	Done(Pending, Arc<Shape>),
	/// Nothing was written to the user: the flight is made from the shapes instead.
	Nothing,
	/// Something was written, and the flight cannot be finished: the connection is lost.
	Broken,
}

/// The newest kept shape whose encrypted records begin with sizes within 3 bytes of the ones that have arrived: its flight is what the rest is expected to be.
fn predict(kept: &[Arc<Shape>], arrived: &[usize]) -> Option<Arc<Shape>> {
	kept.iter().find(|shape| {
		let sealed = shape.flight.sealed();
		sealed.len() >= arrived.len() && sealed.iter().zip(arrived).all(|(shown, made)| shown.abs_diff(*made) <= 3)
	}).cloned()
}

/// "The site's answer to this hello": the node's flight written as the site's arrives. The ServerHello and the compatibility record go out the moment the site's do. The messages are sealed into each encrypted record as it arrives, if a kept shape begins with the records so far (its flight says how large the messages are to be, and 8 bytes of slack take the difference a signature makes), and each burst goes out at the offset it came at. Otherwise the records are held until the flight is complete and the messages are made to fit them. The flight is whole when the live reader says so, and a flight that came out other than the shape said is lost, not passed off as whole.
async fn copy(listener: &Listener, served: &Served, tcp: &mut TcpStream, hello: &[u8], seed: &[u8; 40], live: &mut Live, now: u64) -> Copy {
	let (rng, kept) = (SystemRandom::new(), listener.shapes(now));
	let (mut opening, mut stream, mut chosen, mut arrived, mut held, mut written) = (None::<Opening>, None::<Messages>, None::<Arc<Shape>>, Vec::<usize>::new(), Vec::<usize>::new(), false);
	let lost = |written: bool| if written {Copy::Broken} else {Copy::Nothing};
	loop {
		let heard = match live.events.recv().await {
			Some(Event::Heard(heard)) => heard,
			Some(Event::Bad) => return lost(written),
			_ => break,
		};
		if opening.is_none() {
			let Some((suite, group, key_first)) = heard.hello else {return Copy::Nothing};
			opening = open(hello, suite, group, key_first, &mut random, &mut |key| mlkem::encap(key)).filter(|made| heard.wire.contains(&Item::Hello(made.size())));
			if opening.is_none() {return Copy::Nothing}
		}
		let mut out = Vec::new();
		for item in heard.wire {
			match item {
				Item::Hello(_) => out.extend_from_slice(opening.as_ref().map_or(&[], Opening::record)),
				Item::Ccs => out.extend_from_slice(&[20, 3, 3, 0, 1, 1]),
				Item::Sealed(size) => {
					arrived.push(size);
					if stream.is_none() && held.is_empty() {
						if let Some(shape) = predict(&kept, &arrived) {
							let capacity = shape.flight.sealed().iter().map(|size| size - TAG - 1).sum::<usize>().saturating_sub(8);
							stream = opening.as_ref().and_then(|opening| opening.messages(&shape, seed, &served.host, capacity, &rng, &mut random));
							chosen = stream.as_ref().map(|_| shape);
						}
					}
					match stream.as_mut() {
						Some(stream) => match stream.seal(size) {
							Some(record) => out.extend_from_slice(&record),
							None => return lost(written),
						},
						None => held.push(size),
					}
				}
			}
		}
		if !out.is_empty() {
			sleep_until(live.base + heard.at).await;
			if tcp.write_all(&out).await.is_err() || tcp.flush().await.is_err() {return Copy::Broken}
			written = true;
		}
	}
	let Some(opening) = opening else {return Copy::Nothing};
	if let (Some(stream), Some(shape)) = (stream, chosen) {return if stream.left() == 0 {Copy::Done(stream.pending(), shape)} else {lost(written)}};
	let capacity: usize = held.iter().map(|size| size - TAG - 1).sum();
	let mut shapes = kept;
	shapes.sort_by_key(|shape| shape.flight.total().abs_diff(held.iter().sum::<usize>()));
	shapes.push(listener.generic.clone());
	let Some((mut stream, shape)) = shapes.into_iter().find_map(|shape| opening.messages(&shape, seed, &served.host, capacity, &rng, &mut random).map(|stream| (stream, shape))) else {return lost(written)};
	let mut out = Vec::new();
	for size in held {
		match stream.seal(size) {
			Some(record) => out.extend_from_slice(&record),
			None => return lost(written),
		}
	}
	if stream.left() != 0 || tcp.write_all(&out).await.is_err() || tcp.flush().await.is_err() {return Copy::Broken}
	Copy::Done(stream.pending(), shape)
}

/// Reads the start of a connection as the records of a ClientHello, as the bytes arrive, and says at the first byte that makes them no candidate: a record of type 22 with a version of 0x0301 or 0x0303 and a length within a record, holding a ClientHello that fits the limits. This test uses no secret.
#[derive(Default)]
struct Scanner {header: Vec<u8>, left: usize, records: usize, message: Vec<u8>, want: Option<usize>}

enum Scan {More, Forward, Hello}

impl Scanner {
	fn feed(&mut self, mut bytes: &[u8]) -> Scan {
		while !bytes.is_empty() {
			if self.left == 0 {
				let take = (5 - self.header.len()).min(bytes.len());
				self.header.extend_from_slice(&bytes[..take]);
				bytes = &bytes[take..];
				if self.header[0] != 22 || self.header.get(1).is_some_and(|major| *major != 3) || self.header.get(2).is_some_and(|minor| !matches!(minor, 1 | 3)) {return Scan::Forward}
				let Some(&[_, _, _, high, low]) = self.header.first_chunk::<5>() else {continue};
				let size = usize::from(u16::from_be_bytes([high, low]));
				if size == 0 || size > RECORD_MAX || self.records == HELLO_RECORDS || self.want.is_some_and(|want| self.message.len() + size > want) {return Scan::Forward}
				(self.left, self.records) = (size, self.records + 1);
				self.header.clear();
			} else {
				let take = self.left.min(bytes.len());
				self.message.extend_from_slice(&bytes[..take]);
				(self.left, bytes) = (self.left - take, &bytes[take..]);
				if self.message.first().is_some_and(|kind| *kind != 1) {return Scan::Forward}
				if self.want.is_none() && self.message.len() >= 4 {
					let want = 4 + (usize::from(self.message[1]) << 16 | usize::from(self.message[2]) << 8 | usize::from(self.message[3]));
					// A record that holds more than the message needs is no ClientHello of a browser either.
					if want > HELLO_BYTES || self.message.len() + self.left > want {return Scan::Forward}
					self.want = Some(want);
				}
				if self.left == 0 {
					if self.want == Some(self.message.len()) {return Scan::Hello}
					if self.records == HELLO_RECORDS {return Scan::Forward}
				}
			}
		}
		Scan::More
	}
}

/// One connection in the undecided pool. Dropping it takes it out, wherever it has got to.
struct Place {listener: Arc<Listener>, id: u64, source: Source, bump: Arc<Notify>}

impl Drop for Place {
	fn drop(&mut self) {self.listener.undecided().leave(self.id, self.source);}
}

/// The relayed pool: strangers that are relayed to the site and hellos that opened and got a flight and no session, each with its source and whether it is the second kind.
#[derive(Default)]
struct Pool {all: BTreeMap<u64, (Source, bool, Arc<Relayed>)>, by_source: HashMap<Source, VecDeque<u64>>}

impl Pool {
	fn leave(&mut self, id: u64) {
		let Some((source, ..)) = self.all.remove(&id) else {return};
		if let Some(ids) = self.by_source.get_mut(&source) {
			ids.retain(|held| *held != id);
			if ids.is_empty() {self.by_source.remove(&source);}
		}
	}
}

/// Takes a connection out of the relayed pool when it is over.
struct Relaying<'a> {listener: &'a Listener, id: u64}

impl Drop for Relaying<'_> {
	fn drop(&mut self) {self.listener.relayed().leave(self.id);}
}

/// Takes a session out of its listener's table when its connection is over.
struct Registered<'a> {listener: &'a Listener, id: u64}

impl Drop for Registered<'_> {
	fn drop(&mut self) {self.listener.sessions().remove(&self.id);}
}

/// Takes a place among the proofs of a listener that wait for a limit, and gives it back when it is dropped.
struct Held<'a>(&'a AtomicUsize);

impl Drop for Held<'_> {
	fn drop(&mut self) {self.0.fetch_sub(1, Ordering::Relaxed);}
}

/// One session: a connection, a device, and the queue of what the node has for that device.
pub struct Session {seat: Arc<Seat>, queue: mpsc::Sender<(Vec<u8>, bool)>, counters: Arc<Counters>}

impl Session {
	/// Established and the one its device is answered on.
	pub fn live(&self) -> bool {self.seat.live()}

	/// Hands the session one WireGuard datagram for its device. `wide` says it holds a packet of the control channel.
	/// "Drop, do not queue. Each connection has a send queue of 256 datagrams. When it is full, new datagrams are dropped and counted."
	pub fn push(&self, datagram: &[u8], wide: bool) {
		if self.queue.try_send((datagram.to_vec(), wide)).is_err() {self.counters.count(Count::QueueFull)}
	}
}

/// The listener of one address. It lives for as long as a config has a `faketls` transport on that address, across reloads, and its sessions with it.
pub struct Listener {
	pub addr: SocketAddr,
	served: RwLock<Arc<Served>>,
	undecided: Mutex<Undecided>,
	relayed: Mutex<Pool>,
	/// Every session with the key of its transport, pending or established, by the number of its connection.
	sessions: Mutex<HashMap<u64, ([u8; 32], Arc<Seat>)>>,
	/// The established sessions.
	pool: Arc<AtomicI64>,
	/// Proofs that wait for the write of a higher limit.
	waiting: AtomicUsize,
	ids: AtomicU64,
	/// One permit for each connection the listener holds, in whatever state. With none left the listener stops accepting.
	room: Arc<Semaphore>,
	permits: Mutex<usize>,
	/// "New connections to the site: burst 64, then `limits.site_rate` a second."
	budget: Mutex<Bucket>,
	/// When it was last said that the site cannot be reached, that the budget has no room, and that the relayed pool is full.
	said: Mutex<[Option<Instant>; 6]>,
	/// The shapes that probes kept, and the buckets of the flights that open no session: the listener's, and one for each source.
	kept: Mutex<Kept>,
	flights: Mutex<(Bucket, HashMap<Source, Bucket>)>,
	/// Wakes the task that probes: the site changed.
	reprobe: Notify,
	/// The made-up site of this listener, drawn once: what a flight is made from where there is no shape.
	generic: Arc<Shape>,
	closed: AtomicBool,
	counters: Arc<Counters>,
}

/// What every `faketls` listener of the node shares: the counters, and the way to each of them.
#[derive(Default)]
pub struct State {listeners: Mutex<Vec<Weak<Listener>>>, counters: Arc<Counters>, patience: Mutex<Patience>}

impl State {
	/// A listener on `addr` that serves what `served` says, with the wall clock `now` in Unix milliseconds for its budget of connections to the site.
	/// How long probes wait: tests make it short.
	pub fn set_patience(&self, patience: Patience) {*self.patience.lock().unwrap_or_else(|e| e.into_inner()) = patience}

	fn patience(&self) -> Patience {*self.patience.lock().unwrap_or_else(|e| e.into_inner())}

	pub fn listen(&self, addr: SocketAddr, served: Served, now: i64) -> Arc<Listener> {
		let permits = DEFAULT_UNDECIDED as usize + served.relayed + DEFAULT_SESSIONS as usize + SPARE;
		let budget = Bucket::full(ProofRate {burst: SITE_BURST, rate: served.rate}, now);
		let listener = Arc::new(Listener {addr, served: RwLock::new(Arc::new(served)), undecided: Mutex::default(), relayed: Mutex::default(), sessions: Mutex::default(), pool: Arc::default(), waiting: AtomicUsize::new(0), ids: AtomicU64::new(1), room: Arc::new(Semaphore::new(permits)), permits: Mutex::new(permits), budget: Mutex::new(budget), said: Mutex::default(), kept: Mutex::new(Kept {shapes: VecDeque::new(), ok: now, site: None}), flights: Mutex::new((Bucket::full(FLIGHTS_LISTENER, now), HashMap::new())), reprobe: Notify::new(), generic: Arc::new(Shape::generic((now / 1000) as u64, &mut random)), closed: AtomicBool::new(false), counters: self.counters.clone()});
		let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
		listeners.retain(|listener| listener.strong_count() > 0);
		listeners.push(Arc::downgrade(&listener));
		listener
	}

	pub fn totals(&self) -> FakeTlsTotals {
		let listeners: Vec<Arc<Listener>> = self.listeners.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect();
		let (mut undecided, mut relayed, mut pending, mut sessions, mut shapes) = (0, 0, 0, 0, 0);
		for listener in &listeners {
			undecided += listener.undecided().all.len();
			relayed += listener.relayed().all.len();
			shapes += listener.kept().shapes.len();
			for (_, seat) in listener.sessions().values() {
				if seat.pending() {pending += 1} else if seat.established() {sessions += 1}
			}
		}
		let (count, why, ended) = (|what: Count| self.counters.counts[what as usize].load(Ordering::Relaxed), |why: Why| self.counters.whys[why as usize].load(Ordering::Relaxed), |why: Ended| self.counters.ended[why as usize].load(Ordering::Relaxed));
		FakeTlsTotals {
			undecided, relayed, pending, sessions, shapes,
				probes: count(Count::Probes), probe_failed: count(Count::ProbeFailed), flights_live: count(Count::Live), flights_kept: count(Count::Kept), flights_generic: count(Count::Generic), flights_live_miss: count(Count::LiveMiss), flights_spent: count(Count::FlightsSpent), idled: count(Count::Idled), stranger_stale: why(Why::Stale), stranger_spent: why(Why::Spent),
			accepted: count(Count::Accepted), accept_failed: count(Count::AcceptFailed), broken: count(Count::Broken), handshake_failed: count(Count::HandshakeFailed), handshake_slow: count(Count::HandshakeSlow), early_connections: count(Count::Early), early_skipped: count(Count::Skipped),
			stranger_syntax: why(Why::Syntax), stranger_slow: why(Why::Slow), stranger_closed: why(Why::Closed), stranger_displaced: why(Why::Displaced), stranger_origin: why(Why::Origin), stranger_hello: why(Why::Hello),
			refused_hello: why(Why::Refused), refused_window: why(Why::Window), refused_floor: why(Why::Floor), refused_seen: why(Why::Seen), refused_cache_full: why(Why::CacheFull), refused_limit: why(Why::Limit), refused_no_replay: why(Why::NoReplay), refused_pool: why(Why::Pool), refused_pending: why(Why::Pending), refused_device_rate: why(Why::DeviceRate), refused_source_rate: why(Why::SourceRate),
			decoys: count(Count::Decoys), relays: count(Count::Relayed), relays_evicted: count(Count::Evicted), site_down: count(Count::SiteDown), site_budget: count(Count::SiteBudget),
			proofs_accepted: count(Count::Proofs), proofs_waited: count(Count::Waited), established: count(Count::Established), establish_full: count(Count::EstablishFull),
			handshakes: count(Count::Handshakes), tunnel: count(Count::Tunnel), queue_full: count(Count::QueueFull), chunks_sent: count(Count::Chunks),
			ended_deadline: ended(Ended::Deadline), ended_idle: ended(Ended::Idle), ended_packets: ended(Ended::Packets), ended_displaced: ended(Ended::Displaced), ended_revoked: ended(Ended::Revoked), ended_closed: ended(Ended::Closed), ended_invalid: ended(Ended::Invalid), ended_unserved: ended(Ended::Unserved),
		}
	}
}

impl Listener {
	fn undecided(&self) -> MutexGuard<'_, Undecided> {self.undecided.lock().unwrap_or_else(|e| e.into_inner())}

	fn relayed(&self) -> MutexGuard<'_, Pool> {self.relayed.lock().unwrap_or_else(|e| e.into_inner())}

	fn sessions(&self) -> MutexGuard<'_, HashMap<u64, ([u8; 32], Arc<Seat>)>> {self.sessions.lock().unwrap_or_else(|e| e.into_inner())}

	/// What the listener serves right now.
	pub fn served(&self) -> Arc<Served> {self.served.read().unwrap_or_else(|e| e.into_inner()).clone()}

	/// Puts in force what a config has for the listener's address. A session whose transport key is not the one in force, or whose tunnel is not the inbound's now, ends. Connections that are relayed stay as they are: the site they are connected to answers them.
	pub fn serve(&self, served: Served) {
		for (key, seat) in self.sessions().values() {
			if *key != served.key || !Arc::ptr_eq(&seat.tunnel, &served.tunnel) {seat.end(Ended::Unserved)}
		}
		// The permits follow the pools. A smaller pool takes back only the permits no connection holds right now.
		let (wanted, mut permits) = (DEFAULT_UNDECIDED as usize + served.relayed + DEFAULT_SESSIONS as usize + SPARE, self.permits.lock().unwrap_or_else(|e| e.into_inner()));
		if wanted > *permits {self.room.add_permits(wanted - *permits)}
		*permits = if wanted < *permits {*permits - self.room.forget_permits(*permits - wanted)} else {wanted};
		let old = std::mem::replace(&mut *self.served.write().unwrap_or_else(|e| e.into_inner()), Arc::new(served));
		let current = self.served();
		if old.host != current.host || old.site != current.site || old.outbound.as_ref().map(|(tag, _)| tag) != current.outbound.as_ref().map(|(tag, _)| tag) {self.reprobe.notify_one()}
	}

	/// The end of a listener whose address no config has any more: its sessions end, and so does every connection it holds.
	pub fn close(&self) {
		self.closed.store(true, Ordering::Release);
		for (_, seat) in self.sessions().values() {seat.end(Ended::Unserved)}
		for (_, bump) in self.undecided().all.values() {bump.notify_one()}
		for (_, _, relayed) in self.relayed().all.values() {relayed.kill.notify_one()}
	}

	/// Takes one of the new connections to the site, when the budget has room. "When it is spent, no early connection is opened and users are still served."
	fn spend(&self, rate: u32, now: i64) -> bool {self.budget.lock().unwrap_or_else(|e| e.into_inner()).fill(ProofRate {burst: SITE_BURST, rate}, now).take()}

	/// Whether a state that lasts, by the number of it (the site cannot be reached, the budget has no room, the relayed pool is full), may be said now: once a minute at the most.
	fn say(&self, which: usize) -> bool {
		let mut said = self.said.lock().unwrap_or_else(|e| e.into_inner());
		let due = said[which].is_none_or(|at| at.elapsed() >= SAY_AGAIN);
		if due {said[which] = Some(Instant::now())}
		due
	}

	/// Takes a place in the relayed pool: "Strangers may displace strangers", at most 8 of one source, at most 2 of its decoy sessions, and `total` in all, where a decoy session counts as a relayed connection.
	/// "The relayed connection that has been idle longest is closed. If none has been idle for the time in the table of numbers, the oldest is closed." The evicted ones are out of the pool before this returns.
	fn relaying(&self, source: Source, decoy: bool, total: usize, now: i64) -> (Relaying<'_>, Arc<Relayed>) {
		let (id, slot, mut pool) = (self.ids.fetch_add(1, Ordering::Relaxed), Arc::new(Relayed {last: AtomicI64::new(now), kill: Notify::new()}), self.relayed());
		let kind: Vec<u64> = pool.by_source.get(&source).map(|ids| ids.iter().copied().filter(|held| pool.all.get(held).is_some_and(|(_, other, _)| *other == decoy)).collect()).unwrap_or_default();
		let mut evicted: Vec<u64> = kind.first().copied().filter(|_| kind.len() >= if decoy {DECOYS_PER_SOURCE} else {STRANGERS_PER_SOURCE}).into_iter().collect();
		if pool.all.len() - evicted.len() >= total {
			// One look at every connection of the pool, with the pool held: `limits.relayed` is 65,536 at the most for that reason.
			let idlest = pool.all.iter().filter(|(held, _)| !evicted.contains(held)).min_by_key(|(_, (_, _, held))| held.last.load(Ordering::Relaxed)).filter(|(_, (_, _, held))| now.saturating_sub(held.last.load(Ordering::Relaxed)) >= RELAY_IDLE.as_millis() as i64).map(|(held, _)| *held);
			evicted.extend(idlest.or_else(|| pool.all.keys().find(|held| !evicted.contains(held)).copied()));
		}
		for held in &evicted {
			if let Some((_, _, gone)) = pool.all.get(held) {gone.kill.notify_one()}
			pool.leave(*held);
			self.counters.count(Count::Evicted);
		}
		pool.all.insert(id, (source, decoy, slot.clone()));
		pool.by_source.entry(source).or_default().push_back(id);
		drop(pool);
		if !evicted.is_empty() && self.say(2) {tracing::warn!("faketls listener {}: its relayed pool is full, so a relayed connection was closed to make room. Saying so once a minute while it lasts", self.addr)}
		(Relaying {listener: self, id}, slot)
	}

	/// Step 9 of "Verifying" for a proof, which the replay rule calls last and only for a proof it would accept: the pool of sessions, then the rate limits of the device and the source and its pending sessions.
	fn charge(&self, shared: &Shared, seat: &Arc<Seat>, from: IpAddr, now: i64, cap: usize, why: &mut Why) -> bool {
		if self.pool.load(Ordering::Relaxed) >= cap as i64 {
			*why = Why::Pool;
			return false;
		}
		match shared.limits.charge(seat, from, now, None) {
			Ok(()) => true,
			Err(spent) => {
				*why = match spent {
					Spent::Pending => Why::Pending,
					Spent::DeviceRate => Why::DeviceRate,
					Spent::SourceRate => Why::SourceRate,
				};
				false
			}
		}
	}
	/// A flight over the allowance of its source or listener: closed with no answer, counted, and said at most once a minute.
	fn spent(&self) {
		self.counters.count(Count::FlightsSpent);
		if self.say(5) {tracing::warn!("faketls listener {}: a flight for a hello that opened and got no session was not answered because the allowance of its source or of the listener was spent, so that connection was relayed to the site, with what the site had sent for it. Users are not affected. {} since start. Saying so once a minute while it lasts", self.addr, self.counters.counts[Count::FlightsSpent as usize].load(Ordering::Relaxed))}
	}

	fn kept(&self) -> MutexGuard<'_, Kept> {self.kept.lock().unwrap_or_else(|e| e.into_inner())}

	/// "No successful probe: after 24 h the node stops accepting proofs": whether the last probe that succeeded, or the start, is that long ago.
	fn stale(&self, now: i64) -> bool {self.kept().stale(now)}

	/// The encrypted bytes of the flights of the shapes kept, which tell a live answer that it is complete.
	fn known(&self) -> Vec<usize> {self.kept().shapes.iter().map(|shape| shape.flight.total()).collect()}

	/// The shapes kept, the newest first, none older than 7 days.
	fn shapes(&self, now: u64) -> Vec<Arc<Shape>> {
		let mut kept = self.kept();
		kept.prune(now);
		kept.shapes.iter().rev().cloned().collect()
	}

	/// How long a live answer must be quiet to be taken for whole: at least twice the round trip the probes measured, and never less than `SETTLE`.
	fn quiet(&self) -> Duration {self.kept().shapes.iter().map(|shape| shape.rtt * 2).max().unwrap_or_default().max(SETTLE)}

	/// What the newest shape that has one shows for `which`, or what a made-up site would do.
	fn reaction(&self, which: Which) -> React {
		let found = self.kept().shapes.iter().rev().find_map(|shape| match which {
			Which::Notified => shape.notified,
			Which::Garbage => shape.garbage,
			Which::Idle => shape.idle,
		});
		let generic = &self.generic;
		found.or(match which {
			Which::Notified => generic.notified,
			Which::Garbage => generic.garbage,
			Which::Idle => None,
		}).unwrap_or(SILENT)
	}

	/// "A token bucket for refused-proof flights per source and per listener": whether a flight that opens no session may be answered now. Both buckets are charged, or neither.
	fn flight_allowed(&self, source: Source, now: i64) -> bool {
		let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
		if flights.1.len() >= SOURCES_MOST {flights.1.clear()}
		let (listener, sources) = &mut *flights;
		let own = sources.entry(source).or_insert_with(|| Bucket::full(FLIGHTS_SOURCE, now));
		let allowed = own.fill(FLIGHTS_SOURCE, now).has() & listener.fill(FLIGHTS_LISTENER, now).has();
		if allowed {
			own.take();
			listener.take();
		}
		allowed
	}

	/// The node's flight for `hello` where it is not copied live (borrowed-site page, "The flight"): from one kept shape picked at random, else from the made-up one. What it came from is the third part.
	fn compose(&self, served: &Served, hello: &[u8], seed: &[u8; 40], now: u64) -> Option<(Made, Arc<Shape>, Used)> {
		let (kept, rng) = (self.shapes(now), SystemRandom::new());
		let write = |shape: &Arc<Shape>| answer(hello, &shape.flight, shape, seed, &served.host, &rng, &mut random, &mut |key| mlkem::encap(key)).map(|made| (made, shape.clone()));
		let start = uniform(0, kept.len().saturating_sub(1) as u32, &mut random).unwrap_or(0) as usize;
		if let Some((made, shape)) = kept.iter().cycle().skip(start).take(kept.len()).filter(|shape| answers(hello, shape.flight.group)).find_map(write) {return Some((made, shape, Used::Kept))}
		write(&self.generic).map(|(made, shape)| (made, shape, Used::Generic))
	}

	/// One probe of the site, and what it changes: a shape kept, a state that ended said, a failure counted and said at most once a minute.
	async fn probe_once(&self, shared: &Shared, round: usize) {
		let (served, patience, now) = (self.served(), shared.faketls.patience(), Clock::of((shared.now)()));
		let mode = [Mode::Wait, Mode::Notify, Mode::Garbage][round % 3];
		let opened = Instant::now();
		let probed = match reach(&served).await {
			Ok(tcp) => probe_over(tcp, opened.elapsed(), &served.host, mode, now.secs, patience).await.map_err(str::to_string),
			Err(e) if served.outbound.is_some() => Err(format!("the connection failed, {e}")),
			Err(e) if e.kind() == io::ErrorKind::TimedOut => Err("the connection timed out".to_string()),
			Err(_) => Err("the connection was refused".to_string()),
		};
		match probed {
			Ok(shape) => {
				let mut kept = self.kept();
				let (was_stale, size) = (kept.stale(now.ms), shape.flight.total());
				let (suite, group) = (shape.flight.suite, shape.flight.group);
				kept.push(shape, now);
				(kept.ok, kept.site) = (now.ms, Some((served.host.clone(), served.site)));
				let count = kept.shapes.len();
				drop(kept);
				self.counters.count(Count::Probes);
				if was_stale {tracing::info!("faketls listener {}: a probe of the site succeeded, so proofs are taken again", self.addr)}
				else if count == 1 {tracing::info!("faketls listener {}: probed the site {}{}: {suite:?}, group {group:#06x}, {size} encrypted bytes in its flight. {PROBES} probes are made at start, then one every 6 h, and the last {SHAPES} are kept", self.addr, served.host, through(&served))}
			}
			Err(why) => {
				self.counters.count(Count::ProbeFailed);
				if self.say(3) {tracing::warn!("faketls listener {}: a probe of the site {}{} failed: {why}. The flight of a user is then copied from the live answer of the site alone, or from an older shape. Saying so once a minute while it lasts", self.addr, served.host, through(&served))}
			}
		}
	}
}

/// What a log line adds when the connections to the site leave by an outbound.
fn through(served: &Served) -> String {served.outbound.as_ref().map_or_else(String::new, |(tag, _)| format!(" through outbound {tag}"))}

/// What the flight of a user was made from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Used {Kept, Generic}

/// The shapes of the site that probes kept, newest last, and when the last probe succeeded or the listener started (in the node's milliseconds), and which site they are of.
struct Kept {shapes: VecDeque<Arc<Shape>>, ok: i64, site: Option<(String, SocketAddr)>}

impl Kept {
	fn stale(&self, now: i64) -> bool {now.saturating_sub(self.ok) > NO_PROBE.as_millis() as i64}

	/// "None older than 7 days."
	fn prune(&mut self, now: u64) {self.shapes.retain(|shape| now.saturating_sub(shape.taken) <= SHAPES_FOR)}

	/// "The last 32 successful probes."
	fn push(&mut self, shape: Shape, now: Clock) {
		self.prune(now.secs);
		self.shapes.push_back(Arc::new(shape));
		while self.shapes.len() > SHAPES {self.shapes.pop_front();}
	}
}

/// The task that probes the site of a listener until the listener is gone: "8 at start and on reload, 2 s apart, then one every 6 h". A reload that changes the site starts the eight again, and forgets the shapes of the old site.
pub fn probing(shared: &Arc<Shared>, listener: &Arc<Listener>) -> AbortHandle {
	let (shared, listener) = (shared.clone(), Arc::downgrade(listener));
	tokio::spawn(async move {
		let mut round = 0;
		'burst: loop {
			for index in 0..PROBES {
				let Some(strong) = listener.upgrade().filter(|strong| !strong.closed.load(Ordering::Acquire)) else {return};
				if index > 0 {sleep(shared.faketls.patience().gap).await}
				let served = strong.served();
				{
					let mut kept = strong.kept();
					if kept.site.as_ref().is_some_and(|site| *site != (served.host.clone(), served.site)) {
						kept.shapes.clear();
					}
					kept.site = Some((served.host.clone(), served.site));
				}
				strong.probe_once(&shared, round).await;
				round += 1;
			}
			loop {
				let Some(strong) = listener.upgrade().filter(|strong| !strong.closed.load(Ordering::Acquire)) else {return};
				tokio::select! {
					_ = sleep(PROBE_EVERY) => {
						strong.probe_once(&shared, round).await;
						round += 1;
					}
					_ = strong.reprobe.notified() => continue 'burst,
				}
			}
		}
	}).abort_handle()
}

/// One connection to the site, within the connect timeout: from the node's own address, or through `site.outbound` as an exit with that outbound dials a destination. An outbound that is down fails the connection, and the node's own address is never the fallback.
async fn reach(served: &Served) -> io::Result<Stream> {
	let site = served.site;
	let Some((tag, outbound)) = &served.outbound else {
		let tcp = timeout(DECOY_CONNECT, TcpStream::connect(site)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
		let _ = tcp.set_nodelay(true);
		return Ok(Box::new(tcp));
	};
	let failed = |why: String| io::Error::other(format!("outbound {tag}: {why}"));
	let conn = match &**outbound {
		Outbound::Socks5(up) => dial_conn(up, site, Instant::now() + DECOY_CONNECT).await.map_err(|failure| failed(failure.error.to_string()))?,
		Outbound::WireGuard(out) if out.has(site.ip()) => Conn::Stack(timeout(DECOY_CONNECT, out.connect(site)).await.map_err(|_| failed("timed out".to_string()))?.map_err(failed)?),
		Outbound::WireGuard(_) => return Err(failed("its address is of the other family".to_string())),
		Outbound::Direct {bind: Some(bind), ..} if bind.is_ipv4() != site.is_ipv4() => return Err(failed("its address is of the other family".to_string())),
		Outbound::Direct {bind, interface} => Conn::Tcp(timeout(DECOY_CONNECT, connect_from(*bind, interface.as_deref(), site)).await.map_err(|_| failed("timed out".to_string()))?.map_err(|e| failed(e.kind().to_string()))?),
	};
	if let Conn::Tcp(tcp) = &conn {let _ = tcp.set_nodelay(true);}
	Ok(Box::new(conn))
}

/// Accepts on the socket of one listener until the handle it returns is aborted.
/// "The node never closes a connection at accept because of a count. If it cannot take more connections, it stops accepting and leaves new ones in the system's queue, as a busy server does": a connection is taken from the system only when the listener has a permit for it.
/// A full undecided pool is no reason to wait: its oldest connection is decided at once and the new one takes the place.
pub fn accept(shared: &Arc<Shared>, listener: Arc<Listener>, socket: TcpListener) -> AbortHandle {
	let shared = shared.clone();
	tokio::spawn(async move {
		loop {
			let Ok(permit) = listener.room.clone().acquire_owned().await else {return};
			let (tcp, peer) = match socket.accept().await {
				Ok(accepted) => accepted,
				Err(_) => {
					listener.counters.count(Count::AcceptFailed);
					tokio::time::sleep(Duration::from_millis(50)).await;
					continue;
				}
			};
			listener.counters.count(Count::Accepted);
			let (served, by, source, id, bump) = (listener.served(), Instant::now(), Source::of(peer.ip()), listener.ids.fetch_add(1, Ordering::Relaxed), Arc::new(Notify::new()));
			{
				// "The oldest undecided connection is decided as not a user at once. The same happens to a source's oldest undecided connection when that source reaches its share." Whoever is displaced is out of the pool before the new one is in.
				let mut undecided = listener.undecided();
				if let Some(displaced) = undecided.by_source.get(&source).filter(|ids| ids.len() >= DEFAULT_UNDECIDED_PER_SOURCE as usize).and_then(|ids| ids.front().copied()) {
					if let Some((_, bump)) = undecided.all.get(&displaced) {bump.notify_one()}
					undecided.leave(displaced, source);
				}
				while undecided.all.len() >= DEFAULT_UNDECIDED as usize {
					let Some((displaced, (of, bump))) = undecided.all.first_key_value().map(|(displaced, (of, bump))| (*displaced, (*of, bump.clone()))) else {break};
					bump.notify_one();
					undecided.leave(displaced, of);
				}
				undecided.all.insert(id, (source, bump.clone()));
				undecided.by_source.entry(source).or_default().push_back(id);
			}
			let place = Place {listener: listener.clone(), id, source, bump};
			tokio::spawn(conn(shared.clone(), listener.clone(), served, tcp, peer, place, permit, by));
		}
	}).abort_handle()
}

/// One accepted TCP connection, from its first byte to the decision and what follows it: the relay to the site for a stranger, a flight of a random leaf for a hello that opened and was refused, and a session for a user.
#[allow(clippy::too_many_arguments)]
async fn conn(shared: Arc<Shared>, listener: Arc<Listener>, served: Arc<Served>, mut tcp: TcpStream, peer: SocketAddr, place: Place, _room: OwnedSemaphorePermit, by: Instant) {
	let _ = tcp.set_nodelay(true);
	// 1. "If the budget for new connections to the site has room, open one connection to the site now, with the connect timeout, and watch it." It is never waited for before the decision, so a site that cannot be reached touches no user.
	let early = listener.spend(served.rate, Clock::of((shared.now)()).ms);
	listener.counters.count(if early {Count::Early} else {Count::Skipped});
	let mut dial = Box::pin(reach(&served));
	let (mut origin, mut said, mut scanner, mut buf, mut read, mut heard, mut hold) = (None::<io::Result<Stream>>, None::<io::Result<usize>>, Scanner::default(), Vec::new(), [0u8; READ], [0u8; READ], None::<Instant>);
	// "A close timer for silent connections": with no connection to the site to close this one on the site's schedule, the node closes it as a site does that has been sent nothing.
	let silent = Instant::now() + listener.reaction(Which::Idle).after.min(REACT_MOST);
	// 2. "Read the hello", and 3. "Forward at once when a byte arrives that makes the bytes no candidate, or when a limit or the hold is reached."
	// The peer's bytes are looked at before the site's, so a hello that is complete is always looked at.
	let decided = loop {
		tokio::select! {
			biased;
			_ = place.bump.notified() => break Err(Why::Displaced),
			dialed = &mut dial, if early && origin.is_none() => origin = Some(dialed),
			got = tcp.read(&mut read) => match got {
				Ok(0) => break Err(Why::Closed),
				Ok(count) => {
					hold.get_or_insert_with(|| Instant::now() + HELLO_HOLD);
					buf.extend_from_slice(&read[..count]);
					match scanner.feed(&read[..count]) {
						Scan::More => {}
						Scan::Forward => break Err(Why::Syntax),
						Scan::Hello => break Ok(std::mem::take(&mut scanner.message)),
					}
				}
				Err(_) => return listener.counters.count(Count::Broken),
			},
			// A site that says something, or closes, while the hello is not complete has decided the connection as it decides a direct visitor's, and the peer is given that at that moment.
			got = async {
				match origin.as_mut() {
					Some(Ok(site)) => site.read(&mut heard).await,
					_ => std::future::pending().await,
				}
			}, if matches!(origin, Some(Ok(_))) => {
				said = Some(got);
				break Err(Why::Origin);
			}
			_ = sleep_until(hold.unwrap_or_else(Instant::now)), if hold.is_some() => break Err(Why::Slow),
			_ = sleep_until(silent), if !early && hold.is_none() => {
				listener.counters.count(Count::Idled);
				react(&mut tcp, None, &React {after: Duration::ZERO, ..listener.reaction(Which::Idle)}).await;
				return;
			}
		}
	};
	let why = match decided {
		Err(why) => why,
		// 4. "A complete hello. Verify as above."
		Ok(message) => {
			let (plan, now) = (shared.plan(), Clock::of((shared.now)()));
			let found = plan.inbound_of(&served.tunnel).and_then(|at| plan.inbounds[at].native.as_ref()).and_then(|native| native.borrowed.iter().find(|borrowed| borrowed.key == served.key).map(|borrowed| (native, borrowed)));
			let (names, tags) = (served.names.iter().map(Vec::as_slice).collect::<Vec<_>>(), found.map(|(native, _)| native.tags()));
			if listener.stale(now.ms) {
				if listener.say(4) {tracing::warn!("faketls listener {}: no probe of the site has succeeded for 24 h, so no proof is taken and everything is relayed to the site, which shows a copy of a user's hello the site's own flight. It ends at the next probe that succeeds. Saying so once a minute while it lasts", listener.addr)}
				Why::Stale
			} else {
				match found.zip(tags.as_ref()).map(|((native, borrowed), tags)| (native, borrowed.node.open(&message, &names, &tags.table))) {
					Some((native, outcome)) if !matches!(outcome, Outcome::Stranger) => {
						let opened = if let Outcome::Proved(opened) = outcome {Some(opened)} else {None};
						// "A token bucket for refused-proof flights per source and per listener": a hello that opened and is refused at step 4, 5 or 6 asks for a flight before the site is sent a byte of it. One over its allowance is a stranger's from here on: relayed to the site as it came.
						if opened.is_none() && !listener.flight_allowed(Source::of(peer.ip()), now.ms) {
							listener.spent();
							Why::Spent
						} else {
							// "A line that passed steps 1 to 6 is a device's": from there on the connection is no stranger's, and no stranger's connection displaces it.
							drop(place);
							let derived = opened.as_ref().map_or([0; 40], |opened| opened.seed);
							// "Write the hello, unchanged, to the early connection if there is one, read the site's flight without answering it": a connection that is not open within a moment is none, and the flight comes from the shapes.
							let site = match origin {
								Some(Ok(site)) => Some(site),
								Some(Err(_)) => None,
								None if early => timeout(LIVE_CONNECT, &mut dial).await.ok().and_then(Result::ok),
								None => None,
							};
							let live = site.map(|site| Live::start(site, buf.clone(), message[39..71].to_vec(), listener.known(), listener.quiet()));
							let proved = match opened {
								Some(opened) => prove(&shared, &listener, &served, native, opened, peer.ip()).await,
								None => Err(Why::Refused),
							};
							match proved {
								Ok(accepted) => {
									listener.counters.count(Count::Proofs);
									match flight(&shared, &listener, &served, tcp, &message, &derived, live, by, false).await {
										Ok((wire, extras)) => session(&shared, &listener, &served, wire, extras, peer, accepted).await,
										Err(count) => {
											accepted.seat.end(Ended::Closed);
											listener.counters.count(count);
										}
									}
								}
								Err(why) => decoy(&shared, &listener, &served, tcp, message, peer, why, by, live).await,
							}
							return;
						}
					}
					_ => Why::Hello,
				}
			}
		}
	};
	// 5. "A stranger. Take the early connection, or open one now if the budget has room, and write every byte read so far to the site, unchanged. Then relay both directions byte for byte."
	listener.counters.whys[why as usize].fetch_add(1, Ordering::Relaxed);
	drop(place);
	let (_relaying, slot) = listener.relaying(Source::of(peer.ip()), false, served.relayed, Clock::of((shared.now)()).ms);
	if listener.closed.load(Ordering::Acquire) {return}
	let site = match origin {
		Some(dialed) => Some(dialed),
		None if early => tokio::select! {
			biased;
			_ = slot.kill.notified() => return,
			dialed = &mut dial => Some(dialed),
		},
		None if listener.spend(served.rate, Clock::of((shared.now)()).ms) => tokio::select! {
			biased;
			_ = slot.kill.notified() => return,
			dialed = reach(&served) => Some(dialed),
		},
		None => None,
	};
	match site {
		Some(Ok(site)) => {
			listener.counters.count(Count::Relayed);
			// What the site said before the peer's hello was complete, and whether it closed or reset behind that.
			let (first, open) = match &said {
				None => (0, Ok(true)),
				Some(Ok(count)) => (*count, Ok(*count > 0)),
				Some(Err(e)) => (0, Err(e.kind())),
			};
			let io: Stream = Box::new(tcp);
			relay(shared.now, io, site, &buf, &heard[..first], open, &slot).await
		}
		// "If the site cannot be reached, close the peer's connection, count it as `site_down`, and log at warn at most once a minute", and the same with `site_budget` where the budget has no room. Nothing was written to the peer.
		failed => {
			listener.counters.count(if failed.is_some() {Count::SiteDown} else {Count::SiteBudget});
			if failed.is_some() && listener.say(0) {tracing::warn!("faketls listener {}: its site{} cannot be reached{}, so whoever is not a user is closed with no answer, which shows the node for as long as it lasts. Users are not affected. {} such connections since start. Saying so once a minute while it lasts", listener.addr, through(&served), match &failed {Some(Err(e)) if served.outbound.is_some() => format!(": {e}"), _ => String::new()}, listener.counters.counts[Count::SiteDown as usize].load(Ordering::Relaxed))}
			if failed.is_none() && listener.say(1) {tracing::warn!("faketls listener {}: the budget for new connections to its site has no room, so a stranger that needs one is closed with no answer. Users are not affected. {} such connections since start. Saying so once a minute while it lasts", listener.addr, listener.counters.counts[Count::SiteBudget as usize].load(Ordering::Relaxed))}
			tokio::select! {
				biased;
				_ = slot.kill.notified() => {}
				_ = tcp.shutdown() => {}
			}
		}
	}
}

/// Steps 7 to 9 of "Verifying" for a hello that opened: the replay rule, then the limits of the device and the source, as the stream listeners take a proof.
/// A proof that is valid in every other way and lies above the limit asks for a limit 20 s above its timestamp, and waits for that write to end, for at most the deadline, and is then asked again.
/// A proof that the rule would accept and a limit refuses is recorded as spent all the same, within the device's allowance, and opens no session: left unrecorded it would be good for whoever saw it on its way, from any address, until its timestamp left the window.
async fn prove(shared: &Arc<Shared>, listener: &Listener, served: &Served, native: &Native, mut opened: Opened<'_, Proved>, from: IpAddr) -> Result<Accepted, Why> {
	let Some(replay) = shared.replay.get() else {return Err(Why::NoReplay)};
	let (device, now) = (opened.device.public, Clock::of((shared.now)()));
	// The session as the limits will know it. It is one of its device's sessions from the moment the limits are charged for it, and nobody's when they are not.
	let seat = Seat::new(device, opened.device.id, None, served.tunnel.clone(), listener.pool.clone(), None, None, listener.counters.ended.clone(), Transport::Tls.idle(), now.ms);
	let (mut writes, mut waiting): (_, Option<(Instant, Held)>) = (replay.writes(), None);
	loop {
		// A write that ends after the rule was asked is one this proof has not seen yet, and wakes it.
		writes.borrow_and_update();
		let (now, mut why, mut refused) = (Clock::of((shared.now)()), Why::NoReplay, false);
		opened = match replay.with(|memory| opened.accept(memory, now.secs, |_| {
			refused = !listener.charge(shared, &seat, from, now.ms, DEFAULT_SESSIONS as usize, &mut why);
			!refused || shared.limits.refuse(device, now.ms)
		})) {
			None => return Err(Why::NoReplay),
			Some(Decision::Accepted(_)) if refused => return Err(why),
			// The first tunnel packet deadline runs from here, "10 s after the proof was accepted", and not from before a wait for a limit.
			Some(Decision::Accepted(_)) => {
				seat.opened.store(now.ms, Ordering::Relaxed);
				seat.active.store(now.ms, Ordering::Relaxed);
				return Ok(Accepted {seat, wide: native.wide, normal: native.normal});
			}
			Some(Decision::Refused(refusal)) => {
				if refusal == Refusal::Floor {replay.refused_at_floor()}
				return Err(match refusal {
					Refusal::Window => Why::Window,
					Refusal::Floor => Why::Floor,
					Refusal::Seen => Why::Seen,
					Refusal::Full => Why::CacheFull,
					Refusal::Limited => why,
				});
			}
			Some(Decision::Raise(limit, back)) => {
				replay.want(limit);
				if waiting.is_none() {
					if listener.waiting.fetch_add(1, Ordering::Relaxed) >= HELD {
						listener.waiting.fetch_sub(1, Ordering::Relaxed);
						return Err(Why::Limit);
					}
					listener.counters.count(Count::Waited);
					waiting = Some((Instant::now() + WRITE_DEADLINE, Held(&listener.waiting)));
				}
				back
			}
		};
		let Some((until, _)) = &waiting else {return Err(Why::Limit)};
		if !matches!(timeout_at(*until, writes.changed()).await, Ok(Ok(()))) {return Err(Why::Limit)}
	}
}

/// A proof that was accepted: the pending session it opened and the upper bounds of the node's padding.
struct Accepted {seat: Arc<Seat>, wide: u32, normal: u32}

/// The node's side of the handshake (borrowed-site page, "The flight"): written with `veilway_proto::flight` as the live answer of the site arrives when there is one (`live`, see `copy`) and from kept shapes when there is not, with no ticket the client could use and no resumption. The deadline is the handshake deadline of the stream listeners, from the accept of `tcp`.
/// For a hello that opened and was accepted the seed is the one only the client can compute, so it matches the leaf it derives. For a hello that opened and was refused it is drawn at random, so that nothing matches and nothing can be read.
/// A client whose Finished is none, or whose first record does not open, is given the site's reaction to garbage and counted. A refused hello (`decoy`) that then goes silent is given the site's reaction to a silent connection when the shape says the site would have ended it, and not before. On success the session's record layer, and the tickets and first application data records of the shape with the time each is due.
#[allow(clippy::too_many_arguments)]
async fn flight(shared: &Shared, listener: &Listener, served: &Served, mut tcp: TcpStream, hello: &[u8], seed: &[u8; 40], mut live: Option<Live>, by: Instant, decoy: bool) -> Result<(Wire, Vec<(Instant, u8, Vec<u8>)>), Count> {
	let (failed, now, idle) = (Count::HandshakeFailed, Clock::of((shared.now)()).secs, listener.reaction(Which::Idle));
	let copied = match live.as_mut() {
		Some(live) => timeout_at(by + TLS_HANDSHAKE, copy(listener, served, &mut tcp, hello, seed, live, now)).await.unwrap_or(Copy::Broken),
		None => Copy::Nothing,
	};
	let (mut pending, shape) = match copied {
		Copy::Done(pending, shape) => {
			listener.counters.count(Count::Live);
			(pending, shape)
		}
		Copy::Broken => {
			listener.counters.count(Count::LiveMiss);
			return Err(failed);
		}
		Copy::Nothing => {
			if live.is_some() {listener.counters.count(Count::LiveMiss)}
			let Some((made, shape, used)) = listener.compose(served, hello, seed, now) else {return Err(failed)};
			listener.counters.count(if used == Used::Kept {Count::Kept} else {Count::Generic});
			// "Wait. Before each record the node waits until the offset of the kept shape, less the time it has already spent."
			let started = Instant::now();
			let writing = async {
				for (at, bytes) in &made.bursts {
					sleep_until(started + *at).await;
					tcp.write_all(bytes).await?;
					tcp.flush().await?;
				}
				Ok::<_, io::Error>(())
			};
			if !matches!(timeout_at(by + TLS_HANDSHAKE, writing).await, Ok(Ok(()))) {return Err(failed)}
			(made.pending, shape)
		}
	};
	drop(live);
	let (deadline, mut raw) = (if decoy {Instant::now() + idle.after.min(REACT_MOST)} else {by + TLS_HANDSHAKE}, Vec::new());
	let reading = async {
		let mut buf = [0u8; READ];
		loop {
			match take_record(&mut raw) {
				Ok(Some((header, mut body))) => match header[0] {
					20 if body == [1] => continue,
					23 => return Ok(match pending.keys().open(&header, &mut body) {
						Some((22, plain)) => Some(plain.to_vec()),
						_ => None,
					}),
					_ => return Ok(None),
				},
				Ok(None) => {}
				Err(()) => return Ok(None),
			}
			match tcp.read(&mut buf).await {
				Ok(count) if count > 0 => raw.extend_from_slice(&buf[..count]),
				_ => return Err(failed),
			}
		}
	};
	let finished = match timeout_at(deadline, reading).await {
		Ok(finished) => finished?,
		Err(_) => {
			if decoy {react(&mut tcp, None, &React {after: Duration::ZERO, ..idle}).await}
			return Err(Count::HandshakeSlow);
		}
	};
	let Some(established) = finished.and_then(|plain| pending.finish(&plain)) else {
		react(&mut tcp, None, &listener.reaction(Which::Garbage)).await;
		return Err(failed);
	};
	let at = Instant::now();
	let extras = afterwards(&shape, &mut random).map_err(|_| failed)?.into_iter().map(|(after, kind, plain)| (at + after, kind, plain)).collect();
	Ok((Wire::new(tcp, established.send, established.receive, raw), extras))
}

/// A hello that opened and got no session: "Answers with a flight of the node with a random leaf", then ignores what the peer sends that decrypts and answers a `close_notify`, a record that fails to decrypt and silence as the site does. It is held in the relayed pool, at most 2 for one source. Over the allowance of its source or listener it is relayed to the site as a stranger is, with what the site has sent for it already.
#[allow(clippy::too_many_arguments)]
async fn decoy(shared: &Arc<Shared>, listener: &Listener, served: &Served, tcp: TcpStream, hello: Vec<u8>, peer: SocketAddr, why: Why, by: Instant, live: Option<Live>) {
	listener.counters.whys[why as usize].fetch_add(1, Ordering::Relaxed);
	let now = Clock::of((shared.now)());
	// A hello the replay rule or a limit refused asks for its flight here. One that failed a check of the proof itself was charged before it was forwarded.
	if why != Why::Refused && !listener.flight_allowed(Source::of(peer.ip()), now.ms) {
		listener.spent();
		let (_relaying, slot) = listener.relaying(Source::of(peer.ip()), false, served.relayed, now.ms);
		if let Some((site, raw)) = match live {
			Some(live) => live.finish().await,
			None => None,
		} {
			listener.counters.count(Count::Relayed);
			let io: Stream = Box::new(tcp);
			relay(shared.now, io, site, &[], &raw, Ok(true), &slot).await;
		}
		return;
	}
	let (_relaying, slot) = listener.relaying(Source::of(peer.ip()), true, served.relayed, now.ms);
	let mut seed = [0u8; 40];
	if listener.closed.load(Ordering::Acquire) || random(&mut seed).is_err() {return}
	tokio::select! {
		biased;
		_ = slot.kill.notified() => {}
		_ = async {
			match flight(shared, listener, served, tcp, &hello, &seed, live, by, true).await {
				Ok((mut wire, _)) => {
					listener.counters.count(Count::Decoys);
					let (idle, mut read) = (listener.reaction(Which::Idle), [0u8; READ]);
					loop {
						tokio::select! {
							got = wire.read(&mut read) => match got {
								Ok(count) if count > 0 => {}
								Ok(_) => return react(&mut wire.tcp, Some(&mut wire.send), &listener.reaction(Which::Notified)).await,
								Err(error) if error.kind() == io::ErrorKind::InvalidData => return react(&mut wire.tcp, Some(&mut wire.send), &listener.reaction(Which::Garbage)).await,
								Err(_) => return,
							},
							_ = sleep(idle.after.min(REACT_MOST)) => return react(&mut wire.tcp, Some(&mut wire.send), &React {after: Duration::ZERO, ..idle}).await,
						}
					}
				}
				Err(count) => listener.counters.count(count),
			}
		} => {}
	}
}

/// Writes bytes to a user and sees them out of the TLS layer's own buffer. False when the session ended meanwhile or the connection broke.
async fn put(writer: &mut (impl AsyncWrite + Unpin), seat: &Seat, bytes: &[u8]) -> bool {
	tokio::select! {
		biased;
		_ = seat.gone() => false,
		written = async {
			writer.write_all(bytes).await?;
			writer.flush().await
		} => written.is_ok(),
	}
}

/// Writes what the node has for a session as one frame: a 2 byte length, then a chunk plaintext of the items and their padding. TLS is the only encryption. A frame is one TLS record, and holds 1 to 16,000 bytes of chunk.
/// A chunk with a WireGuard handshake message is padded wide, like one with a packet of the control channel. The write is given up when the session ends meanwhile, so a peer that stops reading holds no session open past its cut-off.
async fn send(writer: &mut (impl AsyncWrite + Unpin), session: &Session, padding: &Padding, sent: &mut u64, items: &[&[u8]], wide: bool, out: &mut Vec<u8>) -> Result<(), End> {
	out.clear();
	out.extend_from_slice(&[0, 0]);
	let wide = chunk::wide(*sent, wide || items.iter().any(|item| matches!(item.first(), Some(1 | 2))), false);
	let Ok(extra) = padding.draw(wide, items.iter().map(|item| 2 + item.len()).sum(), MAX_PLAINTEXT, &mut random) else {return Ok(())};
	// A frame of no byte is none, so a chunk with no item has padding.
	if chunk::write(items, if items.is_empty() {extra.max(1)} else {extra}, out).is_err() {return Ok(())}
	let size = (out.len() - 2) as u16;
	out[..2].copy_from_slice(&size.to_be_bytes());
	*sent += 1;
	session.counters.count(Count::Chunks);
	if put(writer, &session.seat, out).await {Ok(())} else {Err(End::Lost)}
}

/// One WireGuard datagram that came in on a session, from the frame it travelled in to the tunnel. What WireGuard answers to it goes to `net` and what it carried to `ip`.
/// Whether it was a keepalive, for a packet of the session's device. None for a datagram that is none, or that the session's allowance of handshakes has no room for: it leaves nothing behind.
#[allow(clippy::too_many_arguments)]
fn take(shared: &Shared, listener: &Listener, session: &Arc<Session>, handshakes: &Handshakes, peer: SocketAddr, now: Clock, datagram: &[u8], net: &mut Vec<Vec<u8>>, ip: &mut Vec<Vec<u8>>) -> Option<bool> {
	let seat = &session.seat;
	// "Excess messages are dropped silently and counted", and an initiation the session took before is dropped before the allowance is charged.
	if datagram.first() == Some(&1) {
		match handshakes.admit(datagram, now.ms) {
			Initiation::Taken => {}
			Initiation::Repeat => {
				listener.counters.count(Count::Tunnel);
				return None;
			}
			Initiation::Excess => {
				listener.counters.count(Count::Handshakes);
				return None;
			}
		}
	}
	// "Binding. A session belongs to the one device its proof named." What WireGuard does not take as a packet of that device leaves nothing behind.
	let (answers, carried) = (net.len(), ip.len());
	let bound = {
		let mut peers = seat.tunnel.lock();
		let bound = peers.wg.recv_bound(&seat.device, peer, datagram, net, ip).filter(|bound| bound.proven);
		// "A peer's endpoint moves between sessions only after a packet authenticated under that peer's keys."
		if let Some(bound) = bound.filter(|_| seat.live()) {peers.heard(bound.peer, Via::FakeTls(Arc::downgrade(session)))}
		bound
	};
	// "A session is pending until a WireGuard packet of its device has authenticated on it." A pool that has filled up since the proof leaves the session pending, and it ends at its deadline.
	let seated = match bound {
		None => None,
		Some(bound) if seat.pending() => match shared.limits.establish(seat, DEFAULT_SESSIONS as usize, usize::MAX, usize::MAX, now.ms) {
			Seated::Established => {
				listener.counters.count(Count::Established);
				tracing::info!("faketls listener {}: a session is established", listener.addr);
				let mut peers = seat.tunnel.lock();
				if peers.wg.index(&seat.device) == Some(bound.peer) {peers.heard(bound.peer, Via::FakeTls(Arc::downgrade(session)))}
				Some(bound)
			}
			full => {
				if full == Seated::Full {listener.counters.count(Count::EstablishFull)}
				None
			}
		},
		Some(bound) => Some(bound),
	};
	if seated.is_none() {
		if bound.is_none() {listener.counters.count(Count::Tunnel)}
		net.truncate(answers);
		ip.truncate(carried);
	}
	seated.map(|bound| bound.keepalive)
}

/// How the loop of a session came to its end.
#[derive(Debug)]
enum End {
	/// The session was ended from outside: a timer, a cut-off, a reload.
	Gone,
	/// The connection is gone, so nothing more can be said on it.
	Lost,
	/// A record came that does not open, or is none that a session has.
	Broken,
	/// The peer sent its `close_notify`, or its end of the connection.
	Peer,
	Local(Ended),
}

/// A connection whose proof was accepted and whose handshake the node has made, from the first frame to the close (borrowed-site page, "The session"; transports page, "Session activity and timers", "WireGuard on an obfuscated transport" and "Closing").
async fn session(shared: &Arc<Shared>, listener: &Arc<Listener>, served: &Served, mut wire: Wire, extras: Vec<(Instant, u8, Vec<u8>)>, peer: SocketAddr, accepted: Accepted) {
	let (seat, id, began) = (accepted.seat, listener.ids.fetch_add(1, Ordering::Relaxed), Instant::now());
	listener.sessions().insert(id, (served.key, seat.clone()));
	let _registered = Registered {listener, id};
	// A reload, or the end of the listener, between the accept of the connection and now.
	let current = listener.served();
	if listener.closed.load(Ordering::Acquire) || current.key != served.key || !Arc::ptr_eq(&current.tunnel, &served.tunnel) {seat.end(Ended::Unserved)}
	let Ok(padding) = Padding::new(accepted.wide, accepted.normal, &mut random) else {return seat.end(Ended::Closed)};
	let (queue, mut waiting) = mpsc::channel(SEND_QUEUE);
	let session = Arc::new(Session {seat: seat.clone(), queue, counters: listener.counters.clone()});
	// The tickets and the first application data records of the shape, with the time each is due. They are sealed when they are written, so that they are never out of order with a frame.
	let mut extras: VecDeque<(Instant, u8, Vec<u8>)> = extras.into();
	let (mut inbuf, mut read, mut out, mut sent, handshakes) = (Vec::<u8>::new(), vec![0u8; RECORD_MAX], Vec::new(), 0u64, Handshakes::new(Clock::of((shared.now)()).ms));
	// What waits to go to the device: datagrams with whether they hold a packet of the control channel, when a lone keepalive among them is sent at the latest, one the last frame had no room for, and the echoes that are owed with the number of frames sent at the time each was owed.
	let (mut held, mut flush, mut carry, mut echoes, mut net, mut ip): (Vec<(Vec<u8>, bool)>, Option<Instant>, Option<(Vec<u8>, bool)>, Vec<(Instant, u64)>, Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), None, None, Vec::new(), Vec::new(), Vec::new());
	let end = 'session: loop {
		// Every whole frame that has arrived. A frame with a bad length, or a chunk that is invalid, ends the session: "A receiver that gets a frame with a bad length, or a chunk plaintext that is invalid, ends the session."
		loop {
			if seat.over() {break 'session End::Gone}
			let Some(&[high, low]) = inbuf.first_chunk::<2>() else {break};
			let size = usize::from(u16::from_be_bytes([high, low]));
			if size == 0 || size > MAX_PLAINTEXT {break 'session End::Local(Ended::Invalid)}
			if inbuf.len() < 2 + size {break}
			let Ok(items) = chunk::parse(&inbuf[2..2 + size]) else {break 'session End::Local(Ended::Invalid)};
			// Every frame that is valid is activity, padding-only frames included.
			let (now, pending, mut datagrams, mut keepalive) = (Clock::of((shared.now)()), seat.pending(), 0, false);
			seat.active.store(now.ms, Ordering::Relaxed);
			for datagram in items {
				datagrams += 1;
				if let Some(lone) = take(shared, listener, &session, &handshakes, peer, now, datagram, &mut net, &mut ip) {keepalive = lone}
			}
			// "At the moment a session becomes established it sends one chunk on it: the WireGuard handshake response when an initiation established it, and otherwise a padding-only chunk."
			// What WireGuard answers goes out at once, with whatever waited for a lone keepalive's delay to pass.
			let (first, answered) = (pending && seat.established(), !net.is_empty());
			if first || answered {
				let items: Vec<&[u8]> = net.iter().map(Vec::as_slice).chain(held.iter().map(|(datagram, _)| datagram.as_slice())).collect();
				if let Err(why) = send(&mut wire, &session, &padding, &mut sent, &items, held.iter().any(|(_, wide)| *wide), &mut out).await {break 'session why}
				held.clear();
				net.clear();
				flush = None;
			}
			// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay, unless it sent something else in that time."
			if datagrams == 1 && keepalive && !first && !answered && seat.live() && echoes.len() < MAX_ECHOES {echoes.push((Instant::now() + session::delay(&ECHO, &mut random).unwrap_or_default(), sent))}
			if !ip.is_empty() {
				let plan = shared.plan();
				if let Some(at) = plan.inbound_of(&seat.tunnel) {
					for packet in ip.drain(..) {shared.ingress(&plan, at, seat.device, packet, Some(super::Over::FakeTls.rule())).await}
				}
				ip.clear();
			}
			inbuf.drain(..2 + size);
		}
		let due = echoes.iter().map(|(at, _)| *at).min();
		tokio::select! {
			_ = seat.gone() => break End::Gone,
			got = wire.read(&mut read) => match got {
				Ok(count) if count > 0 => inbuf.extend_from_slice(&read[..count]),
				// The end of the connection with its `close_notify` reads as the end of the stream, and one without it as an error.
				Ok(_) => break End::Peer,
				// A record that does not open is garbage, which the site answers in its own way.
				Err(error) if error.kind() == io::ErrorKind::InvalidData => break End::Broken,
				Err(_) => break End::Lost,
			},
			Some(next) = waiting.recv(), if carry.is_none() => carry = Some(next),
			_ = sleep_until(flush.unwrap_or_else(Instant::now)), if flush.is_some() => flush = Some(Instant::now()),
			_ = sleep_until(extras.front().map_or_else(Instant::now, |(at, ..)| *at)), if !extras.is_empty() => {
				let Some((_, kind, plain)) = extras.pop_front() else {continue};
				if wire.record(kind, &plain).await.is_err() {break End::Lost}
			}
			_ = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
				// An echo that is due, unless the node sent something since the keepalive it answers.
				let now = Instant::now();
				let owed = echoes.iter().any(|(at, mark)| *at <= now && *mark == sent);
				echoes.retain(|(at, _)| *at > now);
				if owed && seat.live() {
					if let Err(why) = send(&mut wire, &session, &padding, &mut sent, &[], false, &mut out).await {break why}
				}
			}
		}
		// "The sender puts every datagram that is waiting at the moment it writes into one chunk, up to the limit, and never waits for more."
		let mut size: usize = held.iter().map(|(datagram, _)| 2 + datagram.len()).sum();
		while let Some((datagram, wide)) = carry.take().or_else(|| waiting.try_recv().ok()) {
			if held.len() >= MAX_ITEMS || size + 2 + datagram.len() > MAX_PLAINTEXT {
				carry = Some((datagram, wide));
				break;
			}
			size += 2 + datagram.len();
			held.push((datagram, wide));
		}
		// "A chunk that would hold exactly one WireGuard keepalive is held back for the lone keepalive delay and joins whatever else is sent in that time."
		if held.len() == 1 && carry.is_none() && held[0].0.len() == 32 && held[0].0[0] == 4 && flush.is_none() {flush = Some(Instant::now() + session::delay(&LONE_KEEPALIVE, &mut random).unwrap_or_default())}
		if !held.is_empty() && (held.len() > 1 || carry.is_some() || flush.is_none_or(|at| at <= Instant::now())) {
			let items: Vec<&[u8]> = held.iter().map(|(datagram, _)| datagram.as_slice()).collect();
			if let Err(why) = send(&mut wire, &session, &padding, &mut sent, &items, held.iter().any(|(_, wide)| *wide), &mut out).await {break why}
			held.clear();
			flush = None;
		}
	};
	seat.end(if let End::Local(why) = end {why} else {Ended::Closed});
	tracing::info!("faketls listener {}: a session ended after {}s: {end:?}", listener.addr, began.elapsed().as_secs());
	if matches!(end, End::Lost) {return}
	// "Either side sends a TLS `close_notify`, waits up to 5 s for the other, and closes TCP. The same close is used for every cause." The session is over before any of that: nothing more of the connection goes to the tunnel, and nothing of the tunnel to the connection.
	let closing = async {
		// What the node had handed to the session before it was ended from outside is its last word to the device: the reset of a flow, or the `bye` of the control channel before a cut-off. It was made before the cut, and one frame of it still leaves.
		if matches!(end, End::Gone) {
			let mut size: usize = held.iter().map(|(datagram, _)| 2 + datagram.len()).sum();
			while let Some((datagram, wide)) = carry.take().or_else(|| waiting.try_recv().ok()).filter(|(datagram, _)| held.len() < MAX_ITEMS && size + 2 + datagram.len() <= MAX_PLAINTEXT) {
				size += 2 + datagram.len();
				held.push((datagram, wide));
			}
			let items: Vec<&[u8]> = held.iter().map(|(datagram, _)| datagram.as_slice()).collect();
			let extra = padding.draw(true, items.iter().map(|item| 2 + item.len()).sum(), MAX_PLAINTEXT, &mut random).unwrap_or(0);
			out.clear();
			out.extend_from_slice(&[0, 0]);
			if !items.is_empty() && chunk::write(&items, extra, &mut out).is_ok() {
				let size = (out.len() - 2) as u16;
				out[..2].copy_from_slice(&size.to_be_bytes());
				if wire.write_all(&out).await.is_err() || wire.flush().await.is_err() {return}
			}
		}
		// "The node answers a close_notify after the time that a kept shape shows for the site", and a record that does not open, or a chunk that breaks the protocol, as it answers garbage.
		match end {
			End::Peer => return react(&mut wire.tcp, Some(&mut wire.send), &listener.reaction(Which::Notified)).await,
			End::Broken | End::Local(Ended::Invalid) => return react(&mut wire.tcp, Some(&mut wire.send), &listener.reaction(Which::Garbage)).await,
			_ => {}
		}
		if wire.shutdown().await.is_err() {return}
		while wire.read(&mut read).await.is_ok_and(|count| count > 0) {}
	};
	let _ = timeout(CLOSE_WAIT + REACT_MOST, closing).await;
}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_proto::tls13::write_server_hello;

	const SESSION: [u8; 32] = [7; 32];

	// A ServerHello of X25519 and the compatibility record, then encrypted-looking records of the given body sizes.
	fn flight(sizes: &[usize]) -> Vec<u8> {
		let hello = write_server_hello(&SESSION, Suite::Aes128, veilway_proto::tls13::X25519, false, &[3; 32], &[4; 32]);
		let mut out = [&[22, 3, 3, 0, hello.len() as u8][..], &hello, &[20, 3, 3, 0, 1, 1]].concat();
		for size in sizes {out.extend_from_slice(&[&[23, 3, 3, (size >> 8) as u8, *size as u8][..], &vec![0x5a; *size]].concat())}
		out
	}

	// A live copy against a site that reads the hello and then writes each part after its wait.
	async fn live(parts: Vec<(Duration, Vec<u8>)>, quiet: Duration) -> Live {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		tokio::spawn(async move {
			let (mut stream, _) = listener.accept().await.unwrap();
			let mut sink = [0u8; 64];
			let _ = stream.read(&mut sink).await;
			for (wait, bytes) in parts {
				sleep(wait).await;
				if stream.write_all(&bytes).await.is_err() {return}
			}
			while stream.read(&mut sink).await.is_ok_and(|count| count > 0) {}
		});
		Live::start(Box::new(TcpStream::connect(addr).await.unwrap()), vec![22, 3, 1, 0, 1, 1], SESSION.to_vec(), Vec::new(), quiet)
	}

	// The encrypted records the events gave before the flight was said to be whole, whether it was said bad, and how long the wait for that took.
	async fn gather(live: &mut Live) -> (usize, bool, Duration) {
		let (started, mut sealed) = (Instant::now(), 0);
		loop {
			match live.events.recv().await {
				Some(Event::Heard(heard)) => sealed += heard.wire.iter().filter(|item| matches!(item, Item::Sealed(_))).count(),
				Some(Event::Bad) => return (sealed, true, started.elapsed()),
				_ => return (sealed, false, started.elapsed()),
			}
		}
	}

	fn record(size: usize) -> Vec<u8> {[&[23u8, 3, 3, (size >> 8) as u8, size as u8][..], &vec![1; size]].concat()}

	#[tokio::test]
	async fn a_flight_is_whole_when_it_is_quiet_for_longer_than_the_round_trips_say_and_not_before() {
		let parts = || vec![(Duration::ZERO, flight(&[1200])), (Duration::from_millis(150), record(600))];
		let (mut patient, mut hasty) = (live(parts(), Duration::from_millis(500)).await, live(parts(), Duration::from_millis(40)).await);
		assert_eq!(gather(&mut patient).await.0, 2);
		assert_eq!(gather(&mut hasty).await.0, 1);
	}

	#[tokio::test]
	async fn nothing_is_whole_before_an_encrypted_record_has_come() {
		let mut late = live(vec![(Duration::ZERO, flight(&[])), (Duration::from_millis(300), record(600))], Duration::from_millis(40)).await;
		assert_eq!(gather(&mut late).await.0, 1);
	}

	#[tokio::test]
	async fn a_record_the_size_of_a_finished_ends_the_flight_at_once() {
		let mut whole = live(vec![(Duration::ZERO, flight(&[1200, 4 + 32 + 17]))], Duration::from_secs(30)).await;
		let (sealed, bad, waited) = gather(&mut whole).await;
		assert_eq!((sealed, bad), (2, false));
		assert!(waited < Duration::from_secs(2), "{waited:?}");
	}

	#[tokio::test]
	async fn a_flight_above_what_the_client_takes_is_bad_and_an_answer_is_read_to_a_cap_and_no_further() {
		let mut huge = live(vec![(Duration::ZERO, flight(&[16_000; 10]))], Duration::from_millis(200)).await;
		assert!(gather(&mut huge).await.1);
		let mut endless = live(vec![(Duration::ZERO, [flight(&[1000]), vec![0; 3_000_000]].concat())], Duration::from_secs(30)).await;
		assert!(!gather(&mut endless).await.1);
		let (_, raw) = endless.finish().await.unwrap();
		assert!(raw.len() <= LIVE_MOST + 65_536, "{} bytes were read", raw.len());
	}
}
