//! The stream listener of the node (transports page, "Stream listeners: what `tls`, `ws` and `fronted` share", "WebSocket session", "Closing" and "`tls`"): one listener for each address, its four pools, the accept state machine of a direct peer, the handoff to the decoy origin, and the session that follows an accepted proof.
//! The request line test, the proof, the chunks and the frames are `veilway_proto`'s, and the limits per device and per source are `limits`'. What is here is the state machine around them and its IO.
//! Whoever is not a user is handed to the operator's own web server with every byte it sent, and from then on the node reads nothing of the connection as a protocol. The node composes no byte for such a peer: no status line, no header and no error page.
//! What it cannot hide is stated on the transports page and not here: the TLS handshake of a `tls` listener is the node's own, which is why `tls` is rated Detectable, an answer through the node is later than one from the origin by a hop, and a request line that arrives slowly is held until its end.
//! Timers of a session follow the node's wall clock, as those of `udp-obfs` do. The deadlines of a connection that has proven nothing follow the runtime's clock.
#[cfg(feature = "bench")]
use super::inbound::Peers;
use super::inbound::{Tunnel, Via};
use super::limits::{Clock, Ended, Handshakes, Initiation, Seat, Seated, Source, Spent, ENDS};
use super::plan::{Native, Plan, Tags};
#[cfg(feature = "bench")]
use super::replay::Guard;
use super::{Over, Shared};
#[cfg(feature = "bench")]
use crate::config::Config;
use crate::config::{DEFAULT_RELAYED, DEFAULT_SESSIONS, DEFAULT_UNDECIDED, DEFAULT_UNDECIDED_PER_SOURCE};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::ProtocolVersion;
use socket2::SockRef;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;
use time::{OffsetDateTime, UtcOffset};
#[cfg(feature = "bench")]
use tokio::io::DuplexStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::AbortHandle;
#[cfg(feature = "bench")]
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{ChunkError, Opener, Padding, Sealer, MAX_ITEMS, MAX_PLAINTEXT, MAX_SEALED};
use veilway_proto::proof::{Name, SessionKeys};
use veilway_proto::replay::{Decision, Refusal, WRITE_DEADLINE};
use veilway_proto::request::{Line, Method, Scan, Scanner, HEAD_MAX, HEAD_TIME, LINE_MAX, LINE_TIME};
use veilway_proto::session::{self, Transport, ECHO, LONE_KEEPALIVE};
use veilway_proto::websocket::{self, BINARY, CLOSE, CLOSE_WAIT, CONTROL_MAX, NORMAL, PING, PONG};
use veilway_proto::{uniform, NoRandom};
use veilway_wg::ws::Acceptor;
#[cfg(feature = "bench")]
use veilway_wg::Wg;

/// "TLS handshake deadline: 10 s from accept."
pub const TLS_HANDSHAKE: Duration = Duration::from_secs(10);
/// "Decoy connect timeout: 5 s."
pub const DECOY_CONNECT: Duration = Duration::from_secs(5);
/// "Idle time before a relayed connection may be closed for room: 60 s."
pub const RELAY_IDLE: Duration = Duration::from_secs(60);
/// "Stream send queue: 256 datagrams per connection."
pub const SEND_QUEUE: usize = 256;
/// "Upgrade header learning: once at start and on reload, again every 60 s while it has failed."
pub const LEARN_AGAIN: Duration = Duration::from_secs(60);
/// "Cookie value on the upgrade answer: 16 to 96 characters."
const COOKIE: RangeInclusive<u32> = 16..=96;
/// How many proofs of one listener wait at once for the write of a higher limit, each for the write deadline at the most. The page gives this number to a `udp-obfs` listener and none to a stream listener, where each such proof holds a connection: the same one is taken here.
pub const HELD: usize = 64;
/// How many echoes of one session wait for their delay at once.
const MAX_ECHOES: usize = 4;
/// How much of the origin's answer to the node's own request is read for its header fields, how many of them are kept, and how long the request may take.
const LEARN_HEAD: usize = 16_384;
const LEARN_FIELDS: usize = 64;
const LEARN_TIME: Duration = Duration::from_secs(10);
/// What each direction of a relayed connection is read into.
const RELAY_BUFFER: usize = 16 * 1024;
/// How far apart the log lines of a decoy origin that stays unreachable are: "log at warn at most once a minute".
const SAY_AGAIN: Duration = Duration::from_secs(60);
/// The connections a listener holds beyond its pools: those that are being closed, and proofs that wait for a limit.
const SPARE: usize = 2 * HELD;

/// Whatever a connection runs over: a TLS session the node ends, a plain TCP connection, or a pipe in memory.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {
	/// Makes the end of the connection a reset where it is a socket's: what the peer is given when the origin reset the connection it was relayed to.
	fn reset(&self) {}
}

impl Io for TcpStream {
	fn reset(&self) {let _ = SockRef::from(self).set_linger(Some(Duration::ZERO));}
}

impl Io for tokio_rustls::server::TlsStream<TcpStream> {
	fn reset(&self) {self.get_ref().0.reset()}
}

#[cfg(feature = "bench")]
impl Io for DuplexStream {}

type Stream = Box<dyn Io>;

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| NoRandom)}

/// Why a peer was decided as "not a user". This is for the node's counters: the peer gets the decoy origin's answer whatever it is, and nothing here is ever said to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stranger {
	/// A byte arrived that makes the request line no candidate, or the line reached its size limit.
	Syntax,
	/// The request line was not complete within its time.
	Slow,
	/// The peer closed its side before its request line was complete.
	Closed,
	/// Decided at once to make room in the undecided pool, for the listener or for its source's share.
	Displaced,
	/// The origin said something, or closed its connection, while the request line was not complete: the origin's own decision, which the peer is given at that moment.
	Origin,
	/// A candidate line that is no proof of a device of the listener: steps 1 to 4 of "Verifying" said no, whichever of them it was.
	Proof,
	/// A proof of a device that the replay rule refused: outside the window, at or below the floor, used before, or the cache is full.
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
	/// The device's or the source's allowance of accepted proofs is spent.
	DeviceRate,
	SourceRate,
}

const STRANGERS: usize = Stranger::SourceRate as usize + 1;

#[derive(Clone, Copy)]
enum Count {Accepted, AcceptFailed, Broken, HandshakeFailed, HandshakeSlow, HandshakeDisplaced, Relayed, Evicted, DecoyDown, Proofs, Waited, HeadRefused, Established, EstablishFull, Handshakes, Tunnel, QueueFull, Chunks, Learned, LearnFailed}

const COUNTS: usize = Count::LearnFailed as usize + 1;

#[derive(Default)]
pub struct Counters {counts: [AtomicU64; COUNTS], strangers: [AtomicU64; STRANGERS], ended: Arc<[AtomicU64; ENDS]>}

impl Counters {
	fn count(&self, what: Count) {self.counts[what as usize].fetch_add(1, Ordering::Relaxed);}
}

/// What the stream listeners did since start, and what they hold right now. Everything but the first four only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamTotals {
	/// Connections that have not been decided yet, right now: inside their TLS handshake or their request line.
	pub undecided: usize,
	/// Connections that are relayed to a decoy origin right now.
	pub relayed: usize,
	/// Sessions whose proof was accepted and on which WireGuard has not authenticated yet, right now.
	pub pending: usize,
	/// Established sessions right now.
	pub sessions: usize,
	/// Connections the listeners took from the system, and failures to take one.
	pub accepted: u64,
	pub accept_failed: u64,
	/// Connections that broke before they were decided: reset inside their request line, or gone before the node had looked at them. Nothing was relayed for them.
	pub broken: u64,
	/// TLS handshakes that failed, that did not finish in time, and that were closed to make room in the undecided pool.
	pub handshake_failed: u64,
	pub handshake_slow: u64,
	pub handshake_displaced: u64,
	/// Decided "not a user", by the class of the reason: a line that cannot be a request of a user, one that was not complete in time, a peer that closed first, a connection decided to make room, and a candidate line that is no proof of a device.
	pub stranger_syntax: u64,
	pub stranger_slow: u64,
	pub stranger_closed: u64,
	pub stranger_displaced: u64,
	pub stranger_proof: u64,
	/// Connections the origin decided before their request line was complete, by answering or by closing.
	pub stranger_origin: u64,
	/// Proofs of a device that were refused all the same, by reason. Each took the decoy path too.
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
	/// Connections that were connected to a decoy origin and relayed, relayed connections that were closed to make room for another, and strangers that were closed with no answer because the origin could not be reached.
	pub relays: u64,
	pub relays_evicted: u64,
	pub decoy_down: u64,
	/// Proofs that were accepted, those among all proofs that waited for the write of a higher limit, users whose request head was over a limit or no WebSocket upgrade, and sessions that became established.
	pub proofs_accepted: u64,
	pub proofs_waited: u64,
	pub head_refused: u64,
	pub established: u64,
	/// Sessions that could not become established because the session pool had filled up since their proof was accepted.
	pub establish_full: u64,
	/// Inside sessions: handshake initiations above a session's allowance, datagrams WireGuard did not take as a packet of the session's device, datagrams for a device that were dropped because the send queue of its connection was full, and chunks the node sent.
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
	/// How often the header fields of an upgrade answer were learnt from a decoy origin, and how often that failed.
	pub upgrade_learned: u64,
	pub upgrade_learn_failed: u64,
}

/// Where the decoy origin of a listener is.
#[derive(Clone)]
pub enum Origin {
	Tcp(SocketAddr),
	/// A pipe in memory, whose other end goes to whoever plays the origin: for a harness without sockets. No build of a node has it.
	#[cfg(feature = "bench")]
	#[doc(hidden)]
	Memory(mpsc::UnboundedSender<DuplexStream>),
}

/// The PROXY protocol header, version 2, of a TCP connection from `from` to `at`, as the node writes it at the start of a connection to a decoy origin that expects one. The two addresses are of one family in it, so an IPv4 address next to an IPv6 one is written in its mapped form.
pub fn proxy_header(from: SocketAddr, at: SocketAddr) -> Vec<u8> {
	let mut header = b"\r\n\r\n\0\r\nQUIT\n\x21".to_vec();
	match (from.ip(), at.ip()) {
		(IpAddr::V4(from), IpAddr::V4(at)) => header.extend_from_slice(&[&[0x11, 0, 12][..], &from.octets(), &at.octets()].concat()),
		(from, at) => header.extend_from_slice(&[&[0x21, 0, 36][..], &match from {IpAddr::V4(v4) => v4.to_ipv6_mapped(), IpAddr::V6(v6) => v6}.octets(), &match at {IpAddr::V4(v4) => v4.to_ipv6_mapped(), IpAddr::V6(v6) => v6}.octets()].concat()),
	}
	header.extend_from_slice(&[from.port().to_be_bytes(), at.port().to_be_bytes()].concat());
	header
}

/// Whose address the PROXY protocol header of a connection to the origin carries: "On the direct path the header carries the peer's address. On the node's own requests it carries the node's address."
#[derive(Clone, Copy)]
enum Proxy {None, Own, Peer(SocketAddr, SocketAddr)}

impl Origin {
	/// One connection to the origin, within the connect timeout, with the PROXY protocol header written first when the listener sends one.
	async fn dial(&self, proxy: Proxy) -> io::Result<Stream> {
		match self {
			Origin::Tcp(to) => {
				let mut tcp = timeout(DECOY_CONNECT, TcpStream::connect(to)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
				let _ = tcp.set_nodelay(true);
				let named = match proxy {
					Proxy::None => None,
					Proxy::Own => Some((tcp.local_addr()?, *to)),
					Proxy::Peer(from, at) => Some((from, at)),
				};
				if let Some((from, at)) = named {tcp.write_all(&proxy_header(from, at)).await?}
				Ok(Box::new(tcp))
			}
			#[cfg(feature = "bench")]
			Origin::Memory(origins) => {
				let (ours, theirs) = tokio::io::duplex(RELAY_BUFFER);
				origins.send(theirs).map_err(|_| io::Error::from(io::ErrorKind::ConnectionRefused))?;
				Ok(Box::new(ours))
			}
		}
	}
}

/// One transport of a listener: the path its proofs arrive on and the tunnel they open.
pub struct Route {
	/// Tells the route from every other the listener ever had. A session ends when its route is no longer served.
	id: u64,
	pub path: String,
	pub tunnel: Arc<Tunnel>,
	/// The name of the transport inside the proof, the method its requests have, the kind of session it gives and the timers of that session.
	pub name: Name,
	pub method: Method,
	pub over: Over,
	pub transport: Transport,
	/// `upgrade_cookie` and `upgrade_headers` of its inbound.
	pub cookie: String,
	pub headers: Vec<String>,
}

impl Route {
	/// The route of a `tls` transport.
	pub fn tls(path: String, tunnel: Arc<Tunnel>, cookie: String, headers: Vec<String>) -> Route {Route {id: 0, path, tunnel, name: Name::Tls, method: Method::Get, over: Over::Tls, transport: Transport::Tls, cookie, headers}}
}

/// The pools of one listener (transports page, "Node capacity numbers").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pools {pub sessions: usize, pub undecided: usize, pub per_source: usize, pub relayed: usize}

impl Pools {
	pub fn of(limits: Option<crate::config::TransportLimits>) -> Pools {
		let limits = limits.unwrap_or_default();
		Pools {sessions: limits.sessions.unwrap_or(DEFAULT_SESSIONS) as usize, undecided: limits.undecided.unwrap_or(DEFAULT_UNDECIDED) as usize, per_source: limits.undecided_per_source.unwrap_or(DEFAULT_UNDECIDED_PER_SOURCE) as usize, relayed: limits.relayed.unwrap_or(DEFAULT_RELAYED) as usize}
	}
}

/// What a listener serves at one moment. A connection takes it once, when it is accepted, and works on that one value.
pub struct Served {
	/// What ends TLS on the listener. None for a listener that reads plain HTTP, which a harness has and a `tls` transport never.
	pub acceptor: Option<Acceptor>,
	pub routes: Vec<Route>,
	pub origin: Origin,
	/// `decoy.proxy_protocol`: "It is all connections or none."
	pub proxy: bool,
	/// What the node's own requests to the origin carry as `Host`.
	pub host: String,
	pub pools: Pools,
}

/// One connection in the undecided pool. Dropping it takes the connection out, wherever it has got to.
struct Place {listener: Arc<Listener>, id: u64, source: Source, bump: Arc<Notify>}

impl Drop for Place {
	fn drop(&mut self) {self.listener.undecided().leave(self.id, self.source);}
}

#[derive(Default)]
struct Undecided {all: BTreeMap<u64, (Source, Arc<Notify>)>, by_source: HashMap<Source, VecDeque<u64>>}

impl Undecided {
	/// Takes a connection out. Whether it was still in.
	fn leave(&mut self, id: u64, source: Source) -> bool {
		if let Some(ids) = self.by_source.get_mut(&source) {
			ids.retain(|held| *held != id);
			if ids.is_empty() {self.by_source.remove(&source);}
		}
		self.all.remove(&id).is_some()
	}
}

/// One connection in the relayed pool: when a byte last crossed it, in Unix milliseconds, and what closes it when the pool needs its place.
struct Relayed {last: AtomicI64, kill: Notify}

/// One session of a stream transport: a connection, a device, and the queue of what the node has for that device.
pub struct Session {
	pub seat: Arc<Seat>,
	pub over: Over,
	queue: mpsc::Sender<(Vec<u8>, bool)>,
	counters: Arc<Counters>,
}

impl Session {
	/// Established and the one its device is answered on.
	pub fn live(&self) -> bool {self.seat.live()}

	/// Hands the session one WireGuard datagram for its device. `wide` says it holds a control channel packet.
	/// "Drop, do not queue. Each connection has a send queue of 256 datagrams. When it is full, new datagrams are dropped and counted."
	pub fn push(&self, datagram: &[u8], wide: bool) {
		if self.queue.try_send((datagram.to_vec(), wide)).is_err() {self.counters.count(Count::QueueFull)}
	}
}

/// The stream listener of one address. It lives for as long as a config has a stream transport on that address, across reloads, and its connections with it.
pub struct Listener {
	pub addr: SocketAddr,
	served: RwLock<Arc<Served>>,
	undecided: Mutex<Undecided>,
	relayed: Mutex<BTreeMap<u64, Arc<Relayed>>>,
	/// Every session with its route, pending or established, by the number of its connection.
	sessions: Mutex<HashMap<u64, (u64, Arc<Seat>)>>,
	/// The established sessions.
	pool: Arc<AtomicI64>,
	/// Proofs that wait for the write of a higher limit.
	waiting: AtomicUsize,
	ids: AtomicU64,
	/// One permit for each connection the listener holds, in whatever state. With none left the listener stops accepting.
	room: Arc<Semaphore>,
	permits: Mutex<usize>,
	/// What the decoy origin sent for each header field of its answer to the node's own request, first values only. None while that has not been learnt.
	learned: RwLock<Option<Arc<Vec<(String, String)>>>>,
	relearn: Notify,
	/// When it was last said that the decoy origin cannot be reached. None while it can.
	down: Mutex<Option<Instant>>,
	closed: AtomicBool,
	counters: Arc<Counters>,
}

/// What every stream listener of the node shares: the counters, and the way to each of them.
#[derive(Default)]
pub struct State {listeners: Mutex<Vec<Weak<Listener>>>, counters: Arc<Counters>}

impl State {
	/// A listener on `addr` that serves nothing yet.
	pub fn listen(&self, addr: SocketAddr, served: Served) -> Arc<Listener> {
		let permits = served.pools.undecided + served.pools.relayed + served.pools.sessions + SPARE;
		let listener = Arc::new(Listener {addr, served: RwLock::new(Arc::new(Served {acceptor: None, routes: Vec::new(), origin: served.origin.clone(), proxy: served.proxy, host: String::new(), pools: served.pools})), undecided: Mutex::default(), relayed: Mutex::default(), sessions: Mutex::default(), pool: Arc::default(), waiting: AtomicUsize::new(0), ids: AtomicU64::new(1), room: Arc::new(Semaphore::new(permits)), permits: Mutex::new(permits), learned: RwLock::default(), relearn: Notify::new(), down: Mutex::default(), closed: AtomicBool::new(false), counters: self.counters.clone()});
		listener.serve(served);
		let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
		listeners.retain(|listener| listener.strong_count() > 0);
		listeners.push(Arc::downgrade(&listener));
		listener
	}

	pub fn totals(&self) -> StreamTotals {
		let listeners: Vec<Arc<Listener>> = self.listeners.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect();
		let (mut undecided, mut relayed, mut pending, mut sessions) = (0, 0, 0, 0);
		for listener in &listeners {
			undecided += listener.undecided().all.len();
			relayed += listener.relayed().len();
			for (_, seat) in listener.sessions().values() {
				if seat.pending() {pending += 1} else if seat.established() {sessions += 1}
			}
		}
		let (count, stranger, ended) = (|what: Count| self.counters.counts[what as usize].load(Ordering::Relaxed), |why: Stranger| self.counters.strangers[why as usize].load(Ordering::Relaxed), |why: Ended| self.counters.ended[why as usize].load(Ordering::Relaxed));
		StreamTotals {
			undecided, relayed, pending, sessions,
			accepted: count(Count::Accepted), accept_failed: count(Count::AcceptFailed), broken: count(Count::Broken), handshake_failed: count(Count::HandshakeFailed), handshake_slow: count(Count::HandshakeSlow), handshake_displaced: count(Count::HandshakeDisplaced),
			stranger_syntax: stranger(Stranger::Syntax), stranger_slow: stranger(Stranger::Slow), stranger_closed: stranger(Stranger::Closed), stranger_displaced: stranger(Stranger::Displaced), stranger_proof: stranger(Stranger::Proof), stranger_origin: stranger(Stranger::Origin),
			refused_window: stranger(Stranger::Window), refused_floor: stranger(Stranger::Floor), refused_seen: stranger(Stranger::Seen), refused_cache_full: stranger(Stranger::CacheFull), refused_limit: stranger(Stranger::Limit), refused_no_replay: stranger(Stranger::NoReplay), refused_pool: stranger(Stranger::Pool), refused_pending: stranger(Stranger::Pending), refused_device_rate: stranger(Stranger::DeviceRate), refused_source_rate: stranger(Stranger::SourceRate),
			relays: count(Count::Relayed), relays_evicted: count(Count::Evicted), decoy_down: count(Count::DecoyDown),
			proofs_accepted: count(Count::Proofs), proofs_waited: count(Count::Waited), head_refused: count(Count::HeadRefused), established: count(Count::Established), establish_full: count(Count::EstablishFull),
			handshakes: count(Count::Handshakes), tunnel: count(Count::Tunnel), queue_full: count(Count::QueueFull), chunks_sent: count(Count::Chunks),
			ended_deadline: ended(Ended::Deadline), ended_idle: ended(Ended::Idle), ended_packets: ended(Ended::Packets), ended_displaced: ended(Ended::Displaced), ended_revoked: ended(Ended::Revoked), ended_closed: ended(Ended::Closed), ended_invalid: ended(Ended::Invalid), ended_unserved: ended(Ended::Unserved),
			upgrade_learned: count(Count::Learned), upgrade_learn_failed: count(Count::LearnFailed),
		}
	}
}

/// A proof that was accepted: the route it came in by, the pending session it opened, and the keys of that session.
struct Accepted {route: usize, seat: Arc<Seat>, keys: SessionKeys, wide: u32, normal: u32}

/// Takes a place among the proofs of a listener that wait for a limit, and gives it back when it is dropped.
struct Held<'a>(&'a AtomicUsize);

impl Drop for Held<'_> {
	fn drop(&mut self) {self.0.fetch_sub(1, Ordering::Relaxed);}
}

/// Takes a session out of its listener's table when its connection is over.
struct Registered<'a> {listener: &'a Listener, id: u64}

impl Drop for Registered<'_> {
	fn drop(&mut self) {self.listener.sessions().remove(&self.id);}
}

/// Takes a connection out of the relayed pool when it is over.
struct Relaying<'a> {listener: &'a Listener, id: u64}

impl Drop for Relaying<'_> {
	fn drop(&mut self) {self.listener.relayed().remove(&self.id);}
}

impl Listener {
	fn undecided(&self) -> MutexGuard<'_, Undecided> {self.undecided.lock().unwrap_or_else(|e| e.into_inner())}

	fn relayed(&self) -> MutexGuard<'_, BTreeMap<u64, Arc<Relayed>>> {self.relayed.lock().unwrap_or_else(|e| e.into_inner())}

	fn sessions(&self) -> MutexGuard<'_, HashMap<u64, (u64, Arc<Seat>)>> {self.sessions.lock().unwrap_or_else(|e| e.into_inner())}

	/// What the listener serves right now.
	pub fn served(&self) -> Arc<Served> {self.served.read().unwrap_or_else(|e| e.into_inner()).clone()}

	/// Puts in force what a config has for the listener's address: the certificate as its files hold it now, the routes, the decoy origin and the pools. A route that is as it was keeps its sessions, and a session of any other ends.
	/// Connections that are relayed stay as they are: the origin they are connected to is the one that answers them. The header fields of the upgrade answer are learnt again: "once at start and on reload".
	pub fn serve(&self, mut served: Served) {
		let before = self.served();
		for route in &mut served.routes {
			route.id = before.routes.iter().find(|was| was.path == route.path && Arc::ptr_eq(&was.tunnel, &route.tunnel) && was.name == route.name).map_or_else(|| self.ids.fetch_add(1, Ordering::Relaxed), |was| was.id);
		}
		for (route, seat) in self.sessions().values() {
			if !served.routes.iter().any(|kept| kept.id == *route) {seat.end(Ended::Unserved)}
		}
		// The permits follow the pools. Smaller pools take back only the permits no connection holds right now, so the listener may hold more connections than the new pools ask for until the next reload counts again.
		let (wanted, mut permits) = (served.pools.undecided + served.pools.relayed + served.pools.sessions + SPARE, self.permits.lock().unwrap_or_else(|e| e.into_inner()));
		if wanted > *permits {self.room.add_permits(wanted - *permits)}
		*permits = if wanted < *permits {*permits - self.room.forget_permits(*permits - wanted)} else {wanted};
		*self.served.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(served);
		self.relearn.notify_one();
	}

	/// The end of a listener whose address no config has any more: its sessions end, and so does every connection it holds.
	pub fn close(&self) {
		self.closed.store(true, Ordering::Release);
		for (_, seat) in self.sessions().values() {seat.end(Ended::Unserved)}
		for (_, bump) in self.undecided().all.values() {bump.notify_one()}
		for relayed in self.relayed().values() {relayed.kill.notify_one()}
	}

	/// Says once, and once a minute at the most, that the decoy origin cannot be reached, and once when it can be again.
	fn decoy(&self, reached: bool) {
		let mut down = self.down.lock().unwrap_or_else(|e| e.into_inner());
		match (reached, *down) {
			(true, Some(_)) => {
				*down = None;
				tracing::info!("stream listener {}: its decoy origin is reached again", self.addr);
			}
			(false, said) if said.is_none_or(|said| said.elapsed() >= SAY_AGAIN) => {
				*down = Some(Instant::now());
				tracing::warn!("stream listener {}: its decoy origin cannot be reached, so whoever is not a user is closed with no answer, which shows the node for as long as it lasts. Users are not affected. {} such connections since start. Saying so once a minute while it lasts", self.addr, self.counters.counts[Count::DecoyDown as usize].load(Ordering::Relaxed));
			}
			_ => {}
		}
	}

	/// Step 7 of "Verifying" for a stream proof, which the replay rule calls last and only for a proof it would accept. "Session: New proofs are refused and take the unauthenticated path."
	fn charge(&self, shared: &Shared, seat: &Arc<Seat>, from: IpAddr, now: i64, cap: usize, why: &mut Stranger) -> bool {
		if self.pool.load(Ordering::Relaxed) >= cap as i64 {
			*why = Stranger::Pool;
			return false;
		}
		match shared.limits.charge(seat, from, now, None) {
			Ok(()) => true,
			Err(spent) => {
				*why = match spent {
					Spent::Pending => Stranger::Pending,
					Spent::DeviceRate => Stranger::DeviceRate,
					Spent::SourceRate => Stranger::SourceRate,
				};
				false
			}
		}
	}

	/// The upgrade answer (transports page, "WebSocket session"): "these lines, in this order". None when the system gave no random bytes for the cookie.
	fn answer(&self, route: &Route, key: &[u8], now: OffsetDateTime) -> Option<Vec<u8>> {
		let (learned, now, mut answer, mut cookie) = (self.learned.read().unwrap_or_else(|e| e.into_inner()).clone(), now.to_offset(UtcOffset::UTC), b"HTTP/1.1 101 Switching Protocols\r\n".to_vec(), [0u8; 72]);
		for name in &route.headers {
			let known = learned.as_ref().and_then(|fields| fields.iter().find(|(known, _)| known.eq_ignore_ascii_case(name)));
			// "For `Date` the node writes the current time in the standard HTTP format. For every other name it writes the value the decoy origin sent for that field, spelled as the origin spelled the name. A field the origin did not send is left out."
			// While the origin's answer is not known, "the node sends only `Date` from the list".
			if name.eq_ignore_ascii_case("date") {
				answer.extend_from_slice(format!("{}: {}, {:02} {} {} {:02}:{:02}:{:02} GMT\r\n", known.map_or(name.as_str(), |(spelled, _)| spelled), ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][usize::from(now.weekday().number_days_from_monday())], now.day(), ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][usize::from(u8::from(now.month())) - 1], now.year(), now.hour(), now.minute(), now.second()).as_bytes());
			} else if let Some((spelled, value)) = known {answer.extend_from_slice(format!("{spelled}: {value}\r\n").as_bytes())}
		}
		// "One `Set-Cookie` field. Its value is random base64url text of a random length. It carries no meaning. It exists so that the answer's length varies."
		random(&mut cookie).ok()?;
		let length = uniform(*COOKIE.start(), *COOKIE.end(), &mut random).ok()? as usize;
		answer.extend_from_slice(format!("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSet-Cookie: {}={}\r\n\r\n", websocket::accept(key), route.cookie, &URL_SAFE_NO_PAD.encode(cookie)[..length]).as_bytes());
		Some(answer)
	}
}

/// Accepts on the socket of one listener until the handle it returns is aborted.
/// "The node never closes a connection at accept because of a count. If it cannot take more connections, it stops accepting and leaves new ones in the system's queue, as a busy server does": a connection is taken from the system only when the listener has a permit for it.
/// A full undecided pool is no reason to wait: its oldest connection is decided at once and the new one takes the place, so a count of the pools is never above its limit.
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
			let served = listener.served();
			let place = enter(&listener, Source::of(peer.ip()), served.pools);
			tokio::spawn(direct(shared.clone(), listener.clone(), served, tcp, peer, place, permit));
		}
	}).abort_handle()
}

/// Puts a new connection into the undecided pool: "Accepted from a direct peer, no decision yet."
/// "The oldest undecided connection is decided as not a user at once. The same happens to a source's oldest undecided connection when that source reaches its share." Whoever is displaced is out of the pool before this returns.
/// Only connections that have proven nothing are in this pool, so only strangers are ever displaced: "Strangers may displace strangers. Nothing a stranger does displaces a session."
fn enter(listener: &Arc<Listener>, source: Source, pools: Pools) -> Place {
	let (id, bump, mut undecided) = (listener.ids.fetch_add(1, Ordering::Relaxed), Arc::new(Notify::new()), listener.undecided());
	if let Some(displaced) = undecided.by_source.get(&source).filter(|ids| ids.len() >= pools.per_source).and_then(|ids| ids.front().copied()) {
		if let Some((_, bump)) = undecided.all.get(&displaced) {bump.notify_one()}
		undecided.leave(displaced, source);
	}
	while undecided.all.len() >= pools.undecided {
		let Some((displaced, (of, bump))) = undecided.all.first_key_value().map(|(displaced, (of, bump))| (*displaced, (*of, bump.clone()))) else {break};
		bump.notify_one();
		undecided.leave(displaced, of);
	}
	undecided.all.insert(id, (source, bump.clone()));
	undecided.by_source.entry(source).or_default().push_back(id);
	drop(undecided);
	Place {listener: listener.clone(), id, source, bump}
}

/// One accepted TCP connection of a direct peer, from the TLS handshake on. Step 1: "TLS, if this listener ends it, within the handshake deadline. A handshake that does not finish in time, or whose connection is displaced from the undecided pool before it finishes, is closed."
/// How ordinary servers close in that case is on the list to measure: the connection is dropped here as the system closes it.
async fn direct(shared: Arc<Shared>, listener: Arc<Listener>, served: Arc<Served>, tcp: TcpStream, peer: SocketAddr, place: Place, _room: OwnedSemaphorePermit) {
	let _ = tcp.set_nodelay(true);
	let Ok(local) = tcp.local_addr() else {return listener.counters.count(Count::Broken)};
	let (io, user): (Stream, bool) = match &served.acceptor {
		Some(acceptor) => {
			let handshake = tokio::select! {
				biased;
				_ = place.bump.notified() => Err(Count::HandshakeDisplaced),
				done = timeout(TLS_HANDSHAKE, acceptor.accept(tcp)) => match done {
					Ok(Ok(tls)) => Ok(tls),
					Ok(Err(_)) => Err(Count::HandshakeFailed),
					Err(_) => Err(Count::HandshakeSlow),
				},
			};
			match handshake {
				// "`tls`: WebSocket inside TLS 1.3." A client ends its attempt unless TLS 1.3 was negotiated, so a proof that arrives under an older version is not a user's, and is verified with the same work as one that is.
				Ok(tls) => {
					let modern = tls.get_ref().1.protocol_version() == Some(ProtocolVersion::TLSv1_3);
					(Box::new(tls), modern)
				}
				Err(count) => return listener.counters.count(count),
			}
		}
		None => (Box::new(tcp), true),
	};
	conn(shared, listener, served, io, peer, local, user, place).await
}

/// The accept state machine of a direct peer from step 2 on, over whatever carries the connection. `user` says whether the connection can be a user's at all.
#[allow(clippy::too_many_arguments)]
async fn conn(shared: Arc<Shared>, listener: Arc<Listener>, served: Arc<Served>, mut io: Stream, peer: SocketAddr, local: SocketAddr, user: bool, place: Place) {
	// 2. "Open one connection to the decoy origin now, before anything is read. This lets the origin's own timers run from the moment a direct visitor's would." It is started here and never waited for before step 7, so an origin that cannot be reached touches no user.
	// Once it is open it is watched: an origin that says something or closes while the request line is not complete has decided the connection as it decides a direct visitor's, and the peer is given that at that moment and not at the node's own limit.
	// The peer's bytes are looked at first, so a line that is complete is always evaluated. The price is the one the transports page names: an origin that closes connections before a request arrives can cost a user an attempt.
	let mut dial = Box::pin(served.origin.dial(if served.proxy {Proxy::Peer(peer, local)} else {Proxy::None}));
	let (mut origin, mut early, mut said, mut buf, mut filled, mut scanner, deadline): (Option<io::Result<Stream>>, _, _, _, _, _, _) = (None, vec![0u8; LINE_MAX], None::<io::Result<usize>>, vec![0u8; LINE_MAX], 0, Scanner::new(), Instant::now() + LINE_TIME);
	// 3. "Read the request line, byte by byte as it arrives." 4. "Forward at once when a byte arrives that makes the line no candidate, or when a limit is reached."
	let line = loop {
		tokio::select! {
			biased;
			_ = place.bump.notified() => break Err(Stranger::Displaced),
			dialed = &mut dial, if origin.is_none() => origin = Some(dialed),
			read = io.read(&mut buf[filled..]) => match read {
				Ok(0) => break Err(Stranger::Closed),
				Ok(read) => {
					filled += read;
					match scanner.feed(&buf[filled - read..filled]) {
						Scan::More => {}
						Scan::Forward => break Err(Stranger::Syntax),
						Scan::Line(line) => break Ok(line),
					}
				}
				// A peer that closes without the closing message of TLS has closed its side all the same.
				Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break Err(Stranger::Closed),
				Err(_) => return listener.counters.count(Count::Broken),
			},
			heard = async {
				match origin.as_mut() {
					Some(Ok(origin)) => origin.read(&mut early).await,
					_ => std::future::pending().await,
				}
			}, if matches!(origin, Some(Ok(_))) => {
				said = Some(heard);
				break Err(Stranger::Origin);
			}
			_ = sleep_until(deadline) => break Err(Stranger::Slow),
		}
	};
	// 5. "Evaluate, at the end of the request line."
	let proved = match line {
		Ok(line) => prove(&shared, &listener, &served, &buf[..line], user, peer.ip(), &place).await.map(|accepted| (line, accepted)),
		Err(why) => Err(why),
	};
	match proved {
		// 6. "A user. Read the rest of the request head within its limits, close the decoy connection unused, and continue with WebSocket session."
		Ok((line, accepted)) => {
			drop((dial, origin, place));
			listener.counters.count(Count::Proofs);
			session(&shared, &listener, &served, io, peer, buf, filled, line, accepted).await
		}
		// 7. "Not a user. If the decoy connection is open, write every byte read so far to it, unchanged, then relay both directions until either side closes."
		Err(why) => {
			listener.counters.strangers[why as usize].fetch_add(1, Ordering::Relaxed);
			drop(place);
			// "Relayed: the relayed connection that has been idle longest is closed, both sides. If none has been idle for the time in the table of numbers, the oldest is closed."
			let (id, slot, now) = (listener.ids.fetch_add(1, Ordering::Relaxed), Arc::new(Relayed {last: AtomicI64::new(Clock::of((shared.now)()).ms), kill: Notify::new()}), Clock::of((shared.now)()).ms);
			{
				let mut relayed = listener.relayed();
				if relayed.len() >= served.pools.relayed {
					// One look at every connection of the pool, with the pool held: `limits.relayed` is 65,536 at the most for that reason.
					let idlest = relayed.iter().min_by_key(|(_, held)| held.last.load(Ordering::Relaxed)).filter(|(_, held)| now.saturating_sub(held.last.load(Ordering::Relaxed)) >= RELAY_IDLE.as_millis() as i64).map(|(id, _)| *id);
					if let Some((_, evicted)) = idlest.or_else(|| relayed.keys().next().copied()).and_then(|evicted| relayed.remove_entry(&evicted)) {
						evicted.kill.notify_one();
						listener.counters.count(Count::Evicted);
					}
				}
				relayed.insert(id, slot.clone());
			}
			let _relaying = Relaying {listener: &listener, id};
			if listener.closed.load(Ordering::Acquire) {return}
			let origin = match origin {
				Some(dialed) => dialed,
				None => tokio::select! {
					biased;
					_ = slot.kill.notified() => return,
					dialed = &mut dial => dialed,
				},
			};
			match origin {
				Ok(origin) => {
					listener.decoy(true);
					listener.counters.count(Count::Relayed);
					// What the origin said before the peer's line was complete, and whether it closed or reset behind that.
					let (first, open) = match &said {
						None => (0, Ok(true)),
						Some(Ok(heard)) => (*heard, Ok(*heard > 0)),
						Some(Err(e)) => (0, Err(e.kind())),
					};
					relay(shared.now, io, origin, &buf[..filled], &early[..first], open, &slot).await
				}
				// "If the origin could not be reached, close the peer's connection, count it as `decoy_down`, and log at warn at most once a minute." Nothing was written to the peer, so the close has nothing to wait for but its own few bytes.
				Err(_) => {
					listener.counters.count(Count::DecoyDown);
					listener.decoy(false);
					tokio::select! {
						biased;
						_ = slot.kill.notified() => {}
						_ = io.shutdown() => {}
					}
				}
			}
		}
	}
}

/// Steps 1 to 7 of "Verifying" for one complete candidate request line from `from`. `user` says whether a line on this connection can be a user's at all.
/// "The node verifies as in Verifying, for every candidate line, with dummy inputs when the line cannot be a user's. Only a `GET` for the path of a `tls` transport on this listener can be a user's."
/// The path is compared with every path of the listener, and the token is opened under the keys of every route of the listener, whichever path the line has: the work of a line does not say which path it had, or whether it had one of them.
/// What that work does not make equal is on the transports page under "Timing", and nothing is added here to hide it.
/// A line that passed steps 1 to 4 is a device's, and `place` is given up for it: from there on the connection is no stranger's, and no stranger's connection displaces it.
async fn prove(shared: &Arc<Shared>, listener: &Listener, served: &Served, line: &[u8], user: bool, from: IpAddr, place: &Place) -> Result<Accepted, Stranger> {
	let Some(line) = Line::parse(line) else {return Err(Stranger::Syntax)};
	let (plan, paths): (Arc<Plan>, Vec<&[u8]>) = (shared.plan(), served.routes.iter().map(|route| route.path.as_bytes()).collect());
	let (at, query) = (line.path_among(&paths), line.query.unwrap_or_default());
	let natives: Vec<Option<(&Native, Arc<Tags>)>> = served.routes.iter().map(|route| plan.inbound_of(&route.tunnel).and_then(|inbound| plan.inbounds[inbound].native.as_ref()).map(|native| (native, native.tags()))).collect();
	let mut found = None;
	for (index, (route, native)) in served.routes.iter().zip(&natives).enumerate() {
		let Some((prover, tags)) = native.as_ref().and_then(|(native, tags)| Some((native.prover.as_ref()?, tags))) else {continue};
		if let Ok(opened) = prover.node.open((user && at == Some(index) && line.method == route.method).then_some(route.name), query, &tags.table) {found = Some((index, opened))}
	}
	let Some((index, mut opened)) = found else {return Err(Stranger::Proof)};
	place.listener.undecided().leave(place.id, place.source);
	let ((route, native), now) = ((&served.routes[index], natives[index].as_ref().map(|(native, _)| *native)), Clock::of((shared.now)()));
	let (Some(native), Some(replay)) = (native, shared.replay.get()) else {return Err(Stranger::NoReplay)};
	// The session as the limits will know it. It is one of its device's sessions from the moment the limits are charged for it, and nobody's when they are not.
	// It remembers the node transport key its token opened under as well as the device secret: its chunk keys come from that key too, so the session ends when the config no longer has it.
	let seat = Seat::new(opened.device.public, opened.device.id, native.prover.as_ref().and_then(|prover| prover.keys.get(opened.key).copied()), route.tunnel.clone(), listener.pool.clone(), listener.counters.ended.clone(), route.transport.idle(), now.ms);
	let (mut writes, mut waiting): (_, Option<(Instant, Held)>) = (replay.writes(), None);
	loop {
		// A write that ends after the rule was asked is one this proof has not seen yet, and wakes it.
		writes.borrow_and_update();
		let (now, mut why) = (Clock::of((shared.now)()), Stranger::NoReplay);
		opened = match replay.with(|memory| opened.accept(memory, now.secs, |_| listener.charge(shared, &seat, from, now.ms, served.pools.sessions, &mut why))) {
			None => return Err(Stranger::NoReplay),
			// The first tunnel packet deadline runs from here, "10 s after the proof was accepted", and not from before a wait for a limit.
			Some(Decision::Accepted(accepted)) => {
				seat.opened.store(now.ms, Ordering::Relaxed);
				seat.active.store(now.ms, Ordering::Relaxed);
				return Ok(Accepted {route: index, seat, keys: accepted.keys, wide: native.wide, normal: native.normal});
			}
			Some(Decision::Refused(refusal)) => {
				if refusal == Refusal::Floor {replay.refused_at_floor()}
				return Err(match refusal {
					Refusal::Window => Stranger::Window,
					Refusal::Floor => Stranger::Floor,
					Refusal::Seen => Stranger::Seen,
					Refusal::Full => Stranger::CacheFull,
					Refusal::Limited => why,
				});
			}
			// "A proof that is valid in every other way and lies above the limit asks for a limit 20 s above its timestamp. On a stream transport the proof waits for that write to end, for at most the deadline in the table of numbers, and is then asked again from step 5 of Verifying. If the deadline passes first it is refused."
			Some(Decision::Raise(limit, back)) => {
				replay.want(limit);
				if waiting.is_none() {
					if listener.waiting.fetch_add(1, Ordering::Relaxed) >= HELD {
						listener.waiting.fetch_sub(1, Ordering::Relaxed);
						return Err(Stranger::Limit);
					}
					listener.counters.count(Count::Waited);
					waiting = Some((Instant::now() + WRITE_DEADLINE, Held(&listener.waiting)));
				}
				back
			}
		};
		let Some((until, _)) = &waiting else {return Err(Stranger::Limit)};
		if !matches!(timeout_at(*until, writes.changed()).await, Ok(Ok(()))) {return Err(Stranger::Limit)}
	}
}

/// Seals what the node has for a session into one chunk, which is one binary WebSocket message, and writes it: "One binary WebSocket message is one sealed chunk." A chunk with a WireGuard handshake message is padded wide, like one with a packet of the control channel.
/// The write is given up when the session ends meanwhile, so a peer that stops reading holds no session open past its cut-off.
async fn send(writer: &mut WriteHalf<Stream>, session: &Session, sealer: &mut Sealer, items: &[&[u8]], wide: bool, sealed: &mut Vec<u8>, out: &mut Vec<u8>) -> Result<(), End> {
	sealed.clear();
	out.clear();
	match sealer.seal(items, wide || items.iter().any(|item| matches!(item.first(), Some(1 | 2))), &mut random, sealed) {
		Ok(()) => {}
		// "A sender closes the session before it would send chunk number 2^60."
		Err(ChunkError::Number) => return Err(End::Local(Ended::Packets)),
		// Nothing reached the wire and the sealer is as it was.
		Err(_) => return Ok(()),
	}
	websocket::frame(BINARY, sealed, None, out);
	session.counters.count(Count::Chunks);
	// A write that was given up may have left half a frame on the wire, and nothing can be said behind that: the connection is closed with no Close frame.
	if put(writer, &session.seat, out).await {Ok(())} else {Err(End::Lost)}
}

/// Writes bytes to a user and sees them out of the TLS layer's own buffer, which a write alone leaves them in when the socket is full: without that the last chunk of a burst would wait in the node for the next one. False when the session ended meanwhile or the connection broke.
async fn put(writer: &mut WriteHalf<Stream>, seat: &Seat, bytes: &[u8]) -> bool {
	tokio::select! {
		biased;
		_ = seat.gone() => false,
		written = async {
			writer.write_all(bytes).await?;
			writer.flush().await
		} => written.is_ok(),
	}
}

/// How the loop of a session came to its end.
enum End {
	/// The session was ended from outside: a timer, a cut-off, a reload.
	Gone,
	/// The connection is gone, so nothing more can be said on it.
	Lost,
	/// The peer sent its Close frame.
	Peer,
	Local(Ended),
}

/// A connection whose proof was accepted, from the rest of its request head to its close (transports page, step 6 of the accept state machine, "WebSocket session", "WireGuard on an obfuscated transport" and "Closing").
/// `buf` holds what was read so far, `filled` bytes of it, and the request line is its first `line` bytes.
#[allow(clippy::too_many_arguments)]
async fn session(shared: &Arc<Shared>, listener: &Arc<Listener>, served: &Served, mut io: Stream, peer: SocketAddr, mut buf: Vec<u8>, mut filled: usize, line: usize, accepted: Accepted) {
	let (route, seat, id) = (&served.routes[accepted.route], accepted.seat, listener.ids.fetch_add(1, Ordering::Relaxed));
	listener.sessions().insert(id, (route.id, seat.clone()));
	let _registered = Registered {listener, id};
	// A reload, or the end of the listener, between the accept of the connection and now.
	if listener.closed.load(Ordering::Acquire) || !listener.served().routes.iter().any(|kept| kept.id == route.id) {seat.end(Ended::Unserved)}
	// "Request head of a user: at most 16,384 bytes, at most 10 s." The head ends with an empty line.
	buf.resize(HEAD_MAX, 0);
	let (deadline, mut searched) = (Instant::now() + HEAD_TIME, line - 2);
	let end = loop {
		if let Some(at) = buf[searched..filled].windows(4).position(|window| window == b"\r\n\r\n") {break Some(searched + at + 4)}
		searched = filled.saturating_sub(3).max(line - 2);
		if filled == HEAD_MAX {break None}
		tokio::select! {
			biased;
			_ = seat.gone() => break None,
			read = io.read(&mut buf[filled..]) => match read {
				Ok(read) if read > 0 => filled += read,
				_ => break None,
			},
			_ = sleep_until(deadline) => break None,
		}
	};
	// "The node requires `Upgrade: websocket`, `Sec-WebSocket-Version: 13` and a `Sec-WebSocket-Key`, and ignores every other header field, including `Origin`."
	let answer = end.and_then(|end| {
		let (mut upgrade, mut version, mut key) = (false, false, None);
		for field in buf[line..end].split(|byte| *byte == b'\n') {
			let Some(colon) = field.iter().position(|byte| *byte == b':') else {continue};
			let (name, value) = (&field[..colon], field[colon + 1..].trim_ascii());
			if name.eq_ignore_ascii_case(b"upgrade") {upgrade |= value.eq_ignore_ascii_case(b"websocket")} else if name.eq_ignore_ascii_case(b"sec-websocket-version") {version |= value == b"13"} else if name.eq_ignore_ascii_case(b"sec-websocket-key") && !value.is_empty() && key.is_none() {key = Some(value)}
		}
		listener.answer(route, key.filter(|_| upgrade && version)?, (shared.now)())
	});
	// "If the head is over a limit or is not a WebSocket upgrade as that section requires, close the connection: `close_notify` where the node ends TLS, then FIN, with no HTTP answer. No WebSocket exists yet, so no WebSocket close is sent."
	let (Some(answer), Some(end), Ok(padding)) = (answer, end, Padding::new(accepted.wide, accepted.normal, &mut random)) else {
		seat.end(Ended::Closed);
		listener.counters.count(Count::HeadRefused);
		let _ = timeout(CLOSE_WAIT, io.shutdown()).await;
		return;
	};
	buf.copy_within(end..filled, 0);
	filled -= end;
	let (queue, mut waiting) = mpsc::channel(SEND_QUEUE);
	let session = Arc::new(Session {seat: seat.clone(), over: route.over, queue, counters: listener.counters.clone()});
	let (mut reader, mut writer) = tokio::io::split(io);
	let (mut opener, mut sealer, mut sealed, mut out, handshakes) = (Opener::new(accepted.keys.c2s), Sealer::new(accepted.keys.s2c, padding), Vec::new(), Vec::new(), Handshakes::new(Clock::of((shared.now)()).ms));
	// What waits to go to the device: datagrams with whether they hold a packet of the control channel, when a lone keepalive among them is sent at the latest, one the last chunk had no room for, and the echoes that are owed with the chunk number each was owed at.
	let (mut held, mut flush, mut carry, mut echoes, mut net, mut ip): (Vec<(Vec<u8>, bool)>, Option<Instant>, Option<(Vec<u8>, bool)>, Vec<(Instant, u64)>, Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), None, None, Vec::new(), Vec::new(), Vec::new());
	if !put(&mut writer, &seat, &answer).await {return seat.end(Ended::Closed)}
	let end = 'session: loop {
		// Every whole frame that has arrived. A frame is decided by its header, before its payload is waited for: "A message longer than 16,016 bytes, a text message or a fragmented message ends the session", and a client masks every frame.
		loop {
			if seat.over() {break 'session End::Gone}
			let header = match websocket::header(&buf[..filled]) {
				Ok(Some(header)) => header,
				Ok(None) => break,
				Err(_) => break 'session End::Local(Ended::Invalid),
			};
			let Some(mask) = header.mask.filter(|_| header.fin && matches!(header.opcode, BINARY | CLOSE | PING | PONG) && header.payload <= (if header.opcode == BINARY {MAX_SEALED} else {CONTROL_MAX}) as u64) else {break 'session End::Local(Ended::Invalid)};
			let total = header.size + header.payload as usize;
			if filled < total {break}
			websocket::mask(mask, &mut buf[header.size..total]);
			match header.opcode {
				CLOSE => break 'session End::Peer,
				// "A received ping is answered with a pong, as RFC 6455 requires", on an established session: "The node sends nothing on a pending session."
				PING if seat.established() => {
					out.clear();
					websocket::frame(PONG, &buf[header.size..total], None, &mut out);
					if !put(&mut writer, &seat, &out).await {break 'session End::Lost}
				}
				PING | PONG => {}
				_ => {
					// "A chunk that does not decrypt, or that decrypts and is invalid, ends the session on `tls` and `ws`."
					let Ok(items) = opener.open(&mut buf[header.size..total]) else {break 'session End::Local(Ended::Invalid)};
					// "On `tls`, `ws` and `fronted` every chunk has a number, so any chunk that opens at the expected number is activity, padding-only chunks included."
					let (now, pending, mut datagrams, mut keepalive) = (Clock::of((shared.now)()), seat.pending(), 0, false);
					seat.active.store(now.ms, Ordering::Relaxed);
					for datagram in items {
						datagrams += 1;
						// "Excess messages are dropped silently and counted", and an initiation the session took before is dropped before the allowance is charged, see `Handshakes::admit`.
						if datagram.first() == Some(&1) {
							match handshakes.admit(datagram, now.ms) {
								Initiation::Taken => {}
								Initiation::Repeat => {
									listener.counters.count(Count::Tunnel);
									continue;
								}
								Initiation::Excess => {
									listener.counters.count(Count::Handshakes);
									continue;
								}
							}
						}
						// "Binding. A session belongs to the one device its proof named." What WireGuard does not take as a packet of that device leaves nothing behind.
						let (answers, carried) = (net.len(), ip.len());
						let bound = {
							let mut peers = seat.tunnel.lock();
							let bound = peers.wg.recv_bound(&seat.device, peer, datagram, &mut net, &mut ip).filter(|bound| bound.proven);
							// "A peer's endpoint moves between sessions only after a packet authenticated under that peer's keys."
							if let Some(bound) = bound.filter(|_| seat.live()) {peers.heard(bound.peer, Via::Stream(Arc::downgrade(&session)))}
							bound
						};
						// "A session is pending until a WireGuard packet of its device has authenticated on it." A pool that has filled up since the proof leaves the session pending, and it ends at its deadline.
						let seated = match bound {
							None => None,
							Some(bound) if seat.pending() => match shared.limits.establish(&seat, served.pools.sessions, now.ms) {
								Seated::Established => {
									listener.counters.count(Count::Established);
									let mut peers = seat.tunnel.lock();
									if peers.wg.index(&seat.device) == Some(bound.peer) {peers.heard(bound.peer, Via::Stream(Arc::downgrade(&session)))}
									Some(bound)
								}
								full => {
									if full == Seated::Full {listener.counters.count(Count::EstablishFull)}
									None
								}
							},
							Some(bound) => Some(bound),
						};
						match seated {
							Some(bound) => keepalive = bound.keepalive,
							None => {
								if bound.is_none() {listener.counters.count(Count::Tunnel)}
								net.truncate(answers);
								ip.truncate(carried);
							}
						}
					}
					// "At the moment a session becomes established it sends one chunk on it: the WireGuard handshake response when an initiation established it, and otherwise a padding-only chunk."
					// What WireGuard answers goes out at once, with whatever waited for a lone keepalive's delay to pass.
					let (first, answered) = (pending && seat.established(), !net.is_empty());
					if first || answered {
						let items: Vec<&[u8]> = net.iter().map(Vec::as_slice).chain(held.iter().map(|(datagram, _)| datagram.as_slice())).collect();
						if let Err(why) = send(&mut writer, &session, &mut sealer, &items, held.iter().any(|(_, wide)| *wide), &mut sealed, &mut out).await {break 'session why}
						held.clear();
						net.clear();
						flush = None;
					}
					// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay, unless it sent something else in that time." Each keepalive has its own echo, and a session has only so many waiting at once.
					if datagrams == 1 && keepalive && !first && !answered && seat.live() && echoes.len() < MAX_ECHOES {echoes.push((Instant::now() + session::delay(&ECHO, &mut random).unwrap_or_default(), sealer.number()))}
					if !ip.is_empty() {
						let plan = shared.plan();
						if let Some(at) = plan.inbound_of(&seat.tunnel) {
							for packet in ip.drain(..) {shared.ingress(&plan, at, seat.device, packet).await}
						}
						ip.clear();
					}
				}
			}
			buf.copy_within(total..filled, 0);
			filled -= total;
		}
		let due = echoes.iter().map(|(at, _)| *at).min();
		tokio::select! {
			_ = seat.gone() => break End::Gone,
			read = reader.read(&mut buf[filled..]) => match read {
				Ok(read) if read > 0 => filled += read,
				_ => break End::Lost,
			},
			Some(next) = waiting.recv(), if carry.is_none() => carry = Some(next),
			_ = sleep_until(flush.unwrap_or_else(Instant::now)), if flush.is_some() => flush = Some(Instant::now()),
			_ = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
				// An echo that is due, unless the node sent something since the keepalive it answers.
				let now = Instant::now();
				let owed = echoes.iter().any(|(at, mark)| *at <= now && *mark == sealer.number());
				echoes.retain(|(at, _)| *at > now);
				if owed && seat.live() {
					if let Err(why) = send(&mut writer, &session, &mut sealer, &[], false, &mut sealed, &mut out).await {break why}
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
			if let Err(why) = send(&mut writer, &session, &mut sealer, &items, held.iter().any(|(_, wide)| *wide), &mut sealed, &mut out).await {break why}
			held.clear();
			flush = None;
		}
	};
	// "Either side ends a session with a WebSocket Close frame with status 1000 and no reason, waits up to 5 s for the peer's Close frame, then closes TLS and TCP in the normal order whether or not it came. The same close is used for every cause, so the cause cannot be read from the close."
	// The session is over before any of that: nothing more of the connection goes to the tunnel, and nothing of the tunnel to the connection.
	seat.end(if let End::Local(why) = end {why} else {Ended::Closed});
	if matches!(end, End::Lost) {return}
	let closing = async {
		out.clear();
		// What the node had handed to the session before it was ended from outside is its last word to the device: the reset of a flow, or the `bye` of the control channel before a cut-off. It was made before the cut, and one chunk of it still leaves.
		if matches!(end, End::Gone) {
			let mut size: usize = held.iter().map(|(datagram, _)| 2 + datagram.len()).sum();
			while let Some((datagram, wide)) = carry.take().or_else(|| waiting.try_recv().ok()).filter(|(datagram, _)| held.len() < MAX_ITEMS && size + 2 + datagram.len() <= MAX_PLAINTEXT) {
				size += 2 + datagram.len();
				held.push((datagram, wide));
			}
			let items: Vec<&[u8]> = held.iter().map(|(datagram, _)| datagram.as_slice()).collect();
			sealed.clear();
			if !items.is_empty() && sealer.seal(&items, true, &mut random, &mut sealed).is_ok() {websocket::frame(BINARY, &sealed, None, &mut out)}
		}
		websocket::frame(CLOSE, &NORMAL, None, &mut out);
		if writer.write_all(&out).await.is_err() || writer.flush().await.is_err() || matches!(end, End::Peer) {return}
		loop {
			match websocket::header(&buf[..filled]) {
				Ok(Some(header)) if header.payload > MAX_SEALED as u64 => return,
				Ok(Some(header)) if filled >= header.size + header.payload as usize => {
					if header.opcode == CLOSE {return}
					buf.copy_within(header.size + header.payload as usize..filled, 0);
					filled -= header.size + header.payload as usize;
				}
				Ok(_) => match reader.read(&mut buf[filled..]).await {
					Ok(read) if read > 0 => filled += read,
					_ => return,
				},
				Err(_) => return,
			}
		}
	};
	let _ = timeout(CLOSE_WAIT, closing).await;
	let _ = timeout(CLOSE_WAIT, writer.shutdown()).await;
}

/// The decoy handoff (step 7): every byte the peer sent so far goes to the origin unchanged, then both directions are relayed blindly. "The node reads nothing more as a protocol on this connection, so there is no second reading of the bytes for the origin to disagree with."
/// When the origin closes, the peer is closed the same way: the closing message of TLS where the node ends TLS, then FIN. A peer that closes only its side is told to the origin as that, and the origin's answer still reaches it.
/// "There is no limit per source on relayed connections of direct peers and no limit on their size or lifetime. The origin is the operator's own, and its limits decide." `slot` closes the connection when the pool needs its place.
/// `first` is what the origin said before the peer's request line was complete, which the peer is given before anything else, and `open` whether the origin's connection was still open behind it: false when it closed, and the kind of the error when it broke.
/// Everything the origin sends is written out to the peer, through the TLS layer's own buffer, before the node waits for anything else: the end of an answer never stays in the node until the next one. Towards the origin there is no such buffer: it is a plain socket.
/// When the origin has closed, the peer is closed once all of that was handed on, however long the peer takes to read it: only the pool's own rule ends a relayed connection early, and one that is closed for room is closed at once, with no wait. An origin that reset its connection resets the peer's.
async fn relay(now: fn() -> OffsetDateTime, io: Stream, origin: Stream, sent: &[u8], first: &[u8], open: Result<bool, io::ErrorKind>, slot: &Relayed) {
	let ((mut from_peer, mut to_peer), (mut from_origin, mut to_origin)) = (tokio::io::split(io), tokio::io::split(origin));
	let (evicted, reset) = {
		// Up ends with whether the origin's answer is still to be waited for: it is unless the peer's connection broke. An origin that has closed is sent nothing.
		let up = async {
			let mut buf = vec![0u8; RELAY_BUFFER];
			if open != Ok(true) || to_origin.write_all(sent).await.is_err() {return true}
			loop {
				match from_peer.read(&mut buf).await {
					Ok(read) if read > 0 => {
						slot.last.store(Clock::of(now()).ms, Ordering::Relaxed);
						if to_origin.write_all(&buf[..read]).await.is_err() {return true}
					}
					Err(e) if e.kind() != io::ErrorKind::UnexpectedEof => return false,
					// The peer closed its side, with the closing message of TLS or without it. The origin is told so, and may still answer.
					_ => {
						let _ = to_origin.shutdown().await;
						return true;
					}
				}
			}
		};
		// Down ends with whether the origin reset its connection.
		let down = async {
			let mut buf = vec![0u8; RELAY_BUFFER];
			if !first.is_empty() && (to_peer.write_all(first).await.is_err() || to_peer.flush().await.is_err()) {return false}
			match open {
				Ok(true) => {}
				Ok(false) => return false,
				Err(kind) => return kind == io::ErrorKind::ConnectionReset,
			}
			loop {
				match from_origin.read(&mut buf).await {
					Ok(read) if read > 0 => {
						if to_peer.write_all(&buf[..read]).await.is_err() || to_peer.flush().await.is_err() {return false}
						slot.last.store(Clock::of(now()).ms, Ordering::Relaxed);
					}
					Ok(_) => return false,
					Err(e) => return e.kind() == io::ErrorKind::ConnectionReset,
				}
			}
		};
		tokio::pin!(up, down);
		// What the origin has sent, or that it has closed, is looked at before anything is written to it.
		tokio::select! {
			biased;
			_ = slot.kill.notified() => (true, false),
			reset = &mut down => (false, reset),
			wait = &mut up => if wait {
				tokio::select! {
					biased;
					_ = slot.kill.notified() => (true, false),
					reset = &mut down => (false, reset),
				}
			} else {(false, false)},
		}
	};
	if evicted {return}
	if reset {return from_peer.unsplit(to_peer).reset()}
	tokio::select! {
		biased;
		_ = slot.kill.notified() => {}
		_ = to_peer.shutdown() => {}
	}
}

/// Learns the header fields of the upgrade answer for one listener until the handle it returns is aborted: "The node learns the origin's values by one `GET /` to the origin at start and on every reload. If that request fails, the node sends only `Date` from the list, logs at warn, and tries again every 60 s until it succeeds, logging at info when it does. Nothing else about the origin's responses is copied."
/// "The node's own requests to the origin carry the host of the `decoy.origin` URL as `Host`."
pub fn learn(listener: &Arc<Listener>) -> AbortHandle {
	let held = listener.clone();
	tokio::spawn(async move {
		let mut failing = false;
		loop {
			// At the start and at every reload, which is whenever the listener is told what it serves, and while it fails every 60 s.
			tokio::select! {
				_ = held.relearn.notified() => {}
				_ = tokio::time::sleep(LEARN_AGAIN), if failing => {}
			}
			let served = held.served();
			let asked = timeout(LEARN_TIME, async {
				let (mut origin, mut head, mut filled) = (served.origin.dial(if served.proxy {Proxy::Own} else {Proxy::None}).await?, vec![0u8; LEARN_HEAD], 0);
				origin.write_all(format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", served.host).as_bytes()).await?;
				let end = loop {
					if let Some(end) = head[..filled].windows(4).position(|window| window == b"\r\n\r\n") {break end}
					if filled == head.len() {return Err(io::Error::from(io::ErrorKind::InvalidData))}
					match origin.read(&mut head[filled..]).await? {
						0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
						read => filled += read,
					}
				};
				let mut lines = head[..end].split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
				if !lines.next().is_some_and(|status| status.starts_with(b"HTTP/1.")) {return Err(io::Error::from(io::ErrorKind::InvalidData))}
				// "A field the origin sent more than once is written once, with its first value." Only a name and a value that can stand in a header field as they are are kept.
				let mut fields: Vec<(String, String)> = Vec::new();
				for line in lines {
					let Some((Ok(name), Ok(value))) = line.iter().position(|byte| *byte == b':').map(|colon| (std::str::from_utf8(&line[..colon]), std::str::from_utf8(line[colon + 1..].trim_ascii()))) else {continue};
					if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') && !value.bytes().any(|byte| byte.is_ascii_control()) && fields.len() < LEARN_FIELDS && !fields.iter().any(|(known, _)| known.eq_ignore_ascii_case(name)) {fields.push((name.to_string(), value.to_string()))}
				}
				Ok(fields)
			}).await.unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)));
			let learned = asked.is_ok();
			*held.learned.write().unwrap_or_else(|e| e.into_inner()) = asked.ok().map(Arc::new);
			held.counters.count(if learned {Count::Learned} else {Count::LearnFailed});
			if learned && failing {tracing::info!("stream listener {}: the header fields of its upgrade answer are learnt from the decoy origin again", held.addr)}
			if !learned && !failing {tracing::warn!("stream listener {}: the decoy origin did not answer the node's own request, so the upgrade answer carries only Date of its upgrade_headers. Trying again every {}s", held.addr, LEARN_AGAIN.as_secs())}
			failing = !learned;
		}
	}).abort_handle()
}

/// A listener with all it needs and no socket and no file, for the fuzz target of the unauthenticated path and for tests of the state machine alone. It is built only with the `bench` feature, which no build of a node has. The origin is whoever takes the pipes from `origin`.
#[cfg(feature = "bench")]
#[doc(hidden)]
pub struct Bench {pub shared: Arc<Shared>, listener: Arc<Listener>, origins: mpsc::UnboundedReceiver<DuplexStream>}

#[cfg(feature = "bench")]
#[doc(hidden)]
impl Bench {
	/// A node on `document`, a config with one `veilway` inbound that has a `tls` transport, whose listener reads plain HTTP from pipes in memory. `pools` are the listener's and `now` is the node's clock.
	pub fn new(document: &str, pools: Pools, now: fn() -> OffsetDateTime) -> anyhow::Result<Bench> {
		let config = Config::parse(document.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?;
		let inbound = config.inbounds.first().ok_or_else(|| anyhow::anyhow!("no inbound"))?;
		let (to_stack, _) = mpsc::channel(1);
		let tunnel = Arc::new(Tunnel::new(inbound.tag.clone(), Peers {wg: Wg::new(inbound.private_key.expose().0), via: Vec::new()}, to_stack));
		let plan = Plan::new(&config, now(), &Plan::default(), vec![tunnel.clone()])?;
		for device in &plan.devices {tunnel.lock().add(device.public_key, device.preshared_key)}
		let shared = Arc::new(Shared::new(plan, super::gate::is_local, now, None, None, veilway_proto::control::USAGE_PUSH));
		let _ = shared.replay.set(Arc::new(Guard::unwritten(config.replay.cache(), super::replay::seconds(now()))));
		let ((origin, origins), path) = (mpsc::unbounded_channel(), config.inbounds[0].transports.iter().find_map(|transport| if let crate::config::Transport::Tls {path, ..} = transport {Some(path.clone())} else {None}).ok_or_else(|| anyhow::anyhow!("no tls transport"))?);
		let listener = shared.stream.listen(SocketAddr::from(([127, 0, 0, 1], 443)), Served {acceptor: None, routes: vec![Route::tls(path, tunnel, inbound.upgrade_cookie.clone().unwrap_or_default(), inbound.upgrade_headers())], origin: Origin::Memory(origin), proxy: false, host: String::new(), pools});
		Ok(Bench {shared, listener, origins})
	}

	/// A connection of a direct peer at `peer`, as the listener's accept takes it: the peer's end of it, and the task that serves it.
	pub fn connect(&self, peer: SocketAddr) -> (DuplexStream, JoinHandle<()>) {
		let ((ours, theirs), served) = (tokio::io::duplex(RELAY_BUFFER), self.listener.served());
		let place = enter(&self.listener, Source::of(peer.ip()), served.pools);
		self.listener.counters.count(Count::Accepted);
		(theirs, tokio::spawn(conn(self.shared.clone(), self.listener.clone(), served, Box::new(ours), peer, self.listener.addr, true, place)))
	}

	/// The next connection the node opened to the origin, when there is one.
	pub fn origin(&mut self) -> Option<DuplexStream> {self.origins.try_recv().ok()}

	/// What the node's timers do once a second: sessions whose time is over end, and the limit of the replay memory follows the clock and what proofs asked for, with every write going through.
	pub fn tick(&self) {
		let clock = Clock::of((self.shared.now)());
		self.shared.limits.sweep(clock);
		if let Some(replay) = self.shared.replay.get() {replay.serve(clock.secs)}
	}

	pub fn totals(&self) -> StreamTotals {self.shared.stream.totals()}
}
