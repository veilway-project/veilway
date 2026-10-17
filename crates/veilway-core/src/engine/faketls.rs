//! The listener of the `faketls` transport (borrowed-site page, "Strangers: the relay to the site", "What the node answers with", "Pools", "Errors", "Probes and replays" and "The session"): ALPHA, new and unreviewed.
//! The node holds no certificate. A connection that proves itself inside its ClientHello (`veilway_proto::faketls`) gets a TLS 1.3 handshake the node makes and then a session of frames, and every other connection is relayed byte for byte to the real site the operator named.
//! The node writes no byte of its own to a stranger, in any state. It reads the start of a connection as the records of a ClientHello within the limits of the page (4 records, 8,192 bytes of handshake, 3 s from the first byte), and forwards at the first byte that makes it no candidate.
//!
//! What this build does not do, and the page says it must (the first two are what a paired comparison tells apart, and a censor can run one):
//! - No shape of the site is probed or kept (no probe at start, none every 6 h, no 24 h rule). The node never learns what the site's flight looks like.
//! - There is no live copy. The early connection is closed when the connection turns out to be a user's, and the hello is never forwarded to the site, so the flight is not timed or sized after the site's answer to that hello.
//! - The flight is rustls' own: its record sizes, grouping and timing are not the site's, its EncryptedExtensions are rustls', its chain is the throwaway leaf alone, it offers one ALPN list of its own (`h2`, `http/1.1`) and it sends no ticket. It never sends a HelloRetryRequest, offers no hybrid group and no SHA-384 suite, so a hello that carries no X25519 share is a stranger's.
//! - After the handshake a closed session, a refused hello and a connection that breaks the protocol get the closes rustls gives, not the site's timing and not its kind of close.
//! - A frame is one record on the sending side. rustls does not tell where a record ended on the reading side, so a frame is read from the byte stream by its length prefix.
use super::inbound::{Tunnel, Via};
use super::limits::{Bucket, Clock, Ended, Handshakes, Initiation, Seat, Seated, Source, Spent, ENDS};
use super::plan::{Native, Proved};
use super::stream::{random, relay, Relayed, Stream, Undecided, DECOY_CONNECT, HELD, RELAY_IDLE, SEND_QUEUE, TLS_HANDSHAKE};
use super::Shared;
use crate::config::{ProofRate, DEFAULT_SESSIONS, DEFAULT_UNDECIDED, DEFAULT_UNDECIDED_PER_SOURCE};
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::crypto::ring::{cipher_suite, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::ServerConfig;
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
use tokio::task::AbortHandle;
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use veilway_proto::chunk::{self, Padding, MAX_ITEMS, MAX_PLAINTEXT};
use veilway_proto::faketls::{leaf_key, Opened, Outcome};
use veilway_proto::replay::{Decision, Refusal, WRITE_DEADLINE};
use veilway_proto::session::{self, Transport, ECHO, LONE_KEEPALIVE};

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
enum Count {Accepted, AcceptFailed, Broken, HandshakeFailed, HandshakeSlow, Early, Skipped, Relayed, Evicted, SiteDown, SiteBudget, Decoys, Proofs, Waited, Established, EstablishFull, Handshakes, Tunnel, QueueFull, Chunks}

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
	/// `limits.relayed` and `limits.site_rate`.
	pub relayed: usize,
	pub rate: u32,
}

/// Waits until the bytes of the connection have been read before it reads the socket: what the node read of a hello, which rustls reads again as the start of its handshake.
struct Prefixed {prefix: Vec<u8>, at: usize, tcp: TcpStream}

impl AsyncRead for Prefixed {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		if self.at < self.prefix.len() {
			let take = (self.prefix.len() - self.at).min(buf.remaining());
			buf.put_slice(&self.prefix[self.at..self.at + take]);
			self.at += take;
			return Poll::Ready(Ok(()));
		}
		Pin::new(&mut self.tcp).poll_read(cx, buf)
	}
}

impl AsyncWrite for Prefixed {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {Pin::new(&mut self.tcp).poll_write(cx, buf)}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.tcp).poll_flush(cx)}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.tcp).poll_shutdown(cx)}
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
	said: Mutex<[Option<Instant>; 3]>,
	closed: AtomicBool,
	provider: Arc<CryptoProvider>,
	counters: Arc<Counters>,
}

/// What every `faketls` listener of the node shares: the counters, and the way to each of them.
#[derive(Default)]
pub struct State {listeners: Mutex<Vec<Weak<Listener>>>, counters: Arc<Counters>}

impl State {
	/// A listener on `addr` that serves what `served` says, with the wall clock `now` in Unix milliseconds for its budget of connections to the site.
	pub fn listen(&self, addr: SocketAddr, served: Served, now: i64) -> Arc<Listener> {
		let permits = DEFAULT_UNDECIDED as usize + served.relayed + DEFAULT_SESSIONS as usize + SPARE;
		let provider = Arc::new(CryptoProvider {cipher_suites: vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256, cipher_suite::TLS13_AES_128_GCM_SHA256], kx_groups: vec![kx_group::X25519], ..rustls::crypto::ring::default_provider()});
		let budget = Bucket::full(ProofRate {burst: SITE_BURST, rate: served.rate}, now);
		let listener = Arc::new(Listener {addr, served: RwLock::new(Arc::new(served)), undecided: Mutex::default(), relayed: Mutex::default(), sessions: Mutex::default(), pool: Arc::default(), waiting: AtomicUsize::new(0), ids: AtomicU64::new(1), room: Arc::new(Semaphore::new(permits)), permits: Mutex::new(permits), budget: Mutex::new(budget), said: Mutex::default(), closed: AtomicBool::new(false), provider, counters: self.counters.clone()});
		let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
		listeners.retain(|listener| listener.strong_count() > 0);
		listeners.push(Arc::downgrade(&listener));
		listener
	}

	pub fn totals(&self) -> FakeTlsTotals {
		let listeners: Vec<Arc<Listener>> = self.listeners.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect();
		let (mut undecided, mut relayed, mut pending, mut sessions) = (0, 0, 0, 0);
		for listener in &listeners {
			undecided += listener.undecided().all.len();
			relayed += listener.relayed().all.len();
			for (_, seat) in listener.sessions().values() {
				if seat.pending() {pending += 1} else if seat.established() {sessions += 1}
			}
		}
		let (count, why, ended) = (|what: Count| self.counters.counts[what as usize].load(Ordering::Relaxed), |why: Why| self.counters.whys[why as usize].load(Ordering::Relaxed), |why: Ended| self.counters.ended[why as usize].load(Ordering::Relaxed));
		FakeTlsTotals {
			undecided, relayed, pending, sessions,
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
		*self.served.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(served);
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
}

/// One connection to the site, within the connect timeout.
async fn reach(site: SocketAddr) -> io::Result<TcpStream> {
	let tcp = timeout(DECOY_CONNECT, TcpStream::connect(site)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
	let _ = tcp.set_nodelay(true);
	Ok(tcp)
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
	let mut dial = Box::pin(reach(served.site));
	let (mut origin, mut said, mut scanner, mut buf, mut read, mut heard, mut hold) = (None::<io::Result<TcpStream>>, None::<io::Result<usize>>, Scanner::default(), Vec::new(), [0u8; READ], [0u8; READ], None::<Instant>);
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
		}
	};
	let why = match decided {
		Err(why) => why,
		// 4. "A complete hello. Verify as above."
		Ok(message) => {
			let plan = shared.plan();
			let found = plan.inbound_of(&served.tunnel).and_then(|at| plan.inbounds[at].native.as_ref()).and_then(|native| native.borrowed.iter().find(|borrowed| borrowed.key == served.key).map(|borrowed| (native, borrowed)));
			let (names, tags) = (served.names.iter().map(Vec::as_slice).collect::<Vec<_>>(), found.map(|(native, _)| native.tags()));
			match found.zip(tags.as_ref()).map(|((native, borrowed), tags)| (native, borrowed.node.open(&message, &names, &tags.table))) {
				Some((native, Outcome::Proved(opened))) => {
					// "A line that passed steps 1 to 6 is a device's": from there on the connection is no stranger's, and no stranger's connection displaces it.
					drop((dial, origin, place));
					let (seed, proved) = (opened.seed, prove(&shared, &listener, &served, native, opened, peer.ip()).await);
					match proved {
						Ok(accepted) => {
							listener.counters.count(Count::Proofs);
							match flight(&listener, &served, tcp, buf, &seed, by).await {
								Ok(tls) => session(&shared, &listener, &served, tls, peer, accepted).await,
								Err(count) => {
									accepted.seat.end(Ended::Closed);
									listener.counters.count(count);
								}
							}
						}
						Err(why) => decoy(&shared, &listener, &served, tcp, buf, peer, why, by).await,
					}
					return;
				}
				Some((_, Outcome::Refused)) => {
					drop((dial, origin, place));
					decoy(&shared, &listener, &served, tcp, buf, peer, Why::Refused, by).await;
					return;
				}
				_ => Why::Hello,
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
			dialed = reach(served.site) => Some(dialed),
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
			let (io, site): (Stream, Stream) = (Box::new(tcp), Box::new(site));
			relay(shared.now, io, site, &buf, &heard[..first], open, &slot).await
		}
		// "If the site cannot be reached, close the peer's connection, count it as `site_down`, and log at warn at most once a minute", and the same with `site_budget` where the budget has no room. Nothing was written to the peer.
		failed => {
			listener.counters.count(if failed.is_some() {Count::SiteDown} else {Count::SiteBudget});
			if failed.is_some() && listener.say(0) {tracing::warn!("faketls listener {}: its site cannot be reached, so whoever is not a user is closed with no answer, which shows the node for as long as it lasts. Users are not affected. {} such connections since start. Saying so once a minute while it lasts", listener.addr, listener.counters.counts[Count::SiteDown as usize].load(Ordering::Relaxed))}
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

/// The node's side of the handshake (borrowed-site page, "The flight"): TLS 1.3 with the two suites and the one group the client answers with, a throwaway P-256 leaf for the site's name made from `seed`, no client certificate, no ticket and no resumption.
/// For a hello that opened and was accepted the seed is the one only the client can compute, so it matches the leaf it derives. For a hello that opened and was refused it is drawn at random, so that nothing matches and nothing can be read.
/// `tcp` has given up the `prefix` already, which rustls reads again as the start of its handshake. The deadline is the handshake deadline of the stream listeners, from the accept of `tcp`.
async fn flight(listener: &Listener, served: &Served, tcp: TcpStream, prefix: Vec<u8>, seed: &[u8; 40], by: Instant) -> Result<TlsStream<Prefixed>, Count> {
	let failed = Count::HandshakeFailed;
	let (Some((pkcs8, _)), Ok(mut params)) = (leaf_key(seed), CertificateParams::new(vec![served.host.clone()])) else {return Err(failed)};
	params.distinguished_name.push(DnType::CommonName, served.host.clone());
	let Ok(cert) = KeyPair::try_from(&pkcs8[..]).and_then(|key| params.self_signed(&key)) else {return Err(failed)};
	let Ok(builder) = ServerConfig::builder_with_provider(listener.provider.clone()).with_protocol_versions(&[&rustls::version::TLS13]) else {return Err(failed)};
	let Ok(mut config) = builder.with_no_client_auth().with_single_cert(vec![cert.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8))) else {return Err(failed)};
	config.send_tls13_tickets = 0;
	config.max_early_data_size = 0;
	config.session_storage = Arc::new(NoServerSessionStorage {});
	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	match timeout_at(by + TLS_HANDSHAKE, TlsAcceptor::from(Arc::new(config)).accept(Prefixed {prefix, at: 0, tcp})).await {
		Ok(Ok(tls)) => Ok(tls),
		Ok(Err(_)) => Err(failed),
		Err(_) => Err(Count::HandshakeSlow),
	}
}

/// A hello that opened and got no session: "Answers with a flight of the node with a random leaf", then closes the session after the handshake. It is held in the relayed pool, at most 2 for one source, and no limit is charged for it.
#[allow(clippy::too_many_arguments)]
async fn decoy(shared: &Arc<Shared>, listener: &Listener, served: &Served, tcp: TcpStream, prefix: Vec<u8>, peer: SocketAddr, why: Why, by: Instant) {
	listener.counters.whys[why as usize].fetch_add(1, Ordering::Relaxed);
	let (_relaying, slot) = listener.relaying(Source::of(peer.ip()), true, served.relayed, Clock::of((shared.now)()).ms);
	let mut seed = [0u8; 40];
	if listener.closed.load(Ordering::Acquire) || random(&mut seed).is_err() {return}
	tokio::select! {
		biased;
		_ = slot.kill.notified() => {}
		_ = async {
			match flight(listener, served, tcp, prefix, &seed, by).await {
				Ok(mut tls) => {
					listener.counters.count(Count::Decoys);
					let _ = timeout(CLOSE_WAIT, tls.shutdown()).await;
					let _ = timeout(CLOSE_WAIT, async {while tls.read(&mut [0u8; READ]).await.is_ok_and(|count| count > 0) {}}).await;
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
	/// The peer sent its `close_notify`, or its end of the connection.
	Peer,
	Local(Ended),
}

/// A connection whose proof was accepted and whose handshake the node has made, from the first frame to the close (borrowed-site page, "The session"; transports page, "Session activity and timers", "WireGuard on an obfuscated transport" and "Closing").
async fn session(shared: &Arc<Shared>, listener: &Arc<Listener>, served: &Served, tls: TlsStream<Prefixed>, peer: SocketAddr, accepted: Accepted) {
	let (seat, id, began) = (accepted.seat, listener.ids.fetch_add(1, Ordering::Relaxed), Instant::now());
	listener.sessions().insert(id, (served.key, seat.clone()));
	let _registered = Registered {listener, id};
	// A reload, or the end of the listener, between the accept of the connection and now.
	let current = listener.served();
	if listener.closed.load(Ordering::Acquire) || current.key != served.key || !Arc::ptr_eq(&current.tunnel, &served.tunnel) {seat.end(Ended::Unserved)}
	let Ok(padding) = Padding::new(accepted.wide, accepted.normal, &mut random) else {return seat.end(Ended::Closed)};
	let (queue, mut waiting) = mpsc::channel(SEND_QUEUE);
	let session = Arc::new(Session {seat: seat.clone(), queue, counters: listener.counters.clone()});
	let (mut reader, mut writer) = tokio::io::split(tls);
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
				if let Err(why) = send(&mut writer, &session, &padding, &mut sent, &items, held.iter().any(|(_, wide)| *wide), &mut out).await {break 'session why}
				held.clear();
				net.clear();
				flush = None;
			}
			// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay, unless it sent something else in that time."
			if datagrams == 1 && keepalive && !first && !answered && seat.live() && echoes.len() < MAX_ECHOES {echoes.push((Instant::now() + session::delay(&ECHO, &mut random).unwrap_or_default(), sent))}
			if !ip.is_empty() {
				let plan = shared.plan();
				if let Some(at) = plan.inbound_of(&seat.tunnel) {
					for packet in ip.drain(..) {shared.ingress(&plan, at, seat.device, packet).await}
				}
				ip.clear();
			}
			inbuf.drain(..2 + size);
		}
		let due = echoes.iter().map(|(at, _)| *at).min();
		tokio::select! {
			_ = seat.gone() => break End::Gone,
			got = reader.read(&mut read) => match got {
				Ok(count) if count > 0 => inbuf.extend_from_slice(&read[..count]),
				// The end of the connection with its `close_notify` reads as the end of the stream, and one without it as an error.
				Ok(_) => break End::Peer,
				Err(_) => break End::Lost,
			},
			Some(next) = waiting.recv(), if carry.is_none() => carry = Some(next),
			_ = sleep_until(flush.unwrap_or_else(Instant::now)), if flush.is_some() => flush = Some(Instant::now()),
			_ = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
				// An echo that is due, unless the node sent something since the keepalive it answers.
				let now = Instant::now();
				let owed = echoes.iter().any(|(at, mark)| *at <= now && *mark == sent);
				echoes.retain(|(at, _)| *at > now);
				if owed && seat.live() {
					if let Err(why) = send(&mut writer, &session, &padding, &mut sent, &[], false, &mut out).await {break why}
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
			if let Err(why) = send(&mut writer, &session, &padding, &mut sent, &items, held.iter().any(|(_, wide)| *wide), &mut out).await {break why}
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
				if writer.write_all(&out).await.is_err() || writer.flush().await.is_err() {return}
			}
		}
		if writer.shutdown().await.is_err() || matches!(end, End::Peer) {return}
		while reader.read(&mut read).await.is_ok_and(|count| count > 0) {}
	};
	let _ = timeout(CLOSE_WAIT, closing).await;
}
