//! The stream listener of the node (transports page, "Stream listeners: what `tls`, `ws` and `fronted` share", "WebSocket session", "Closing" and "`tls`"): one listener for each address, its four pools, the accept state machine of a direct peer, the handoff to the decoy origin, and the session that follows an accepted proof.
//! The request line test, the proof, the chunks and the frames are `veilway_proto`'s, and the limits per device and per source are `limits`'. What is here is the state machine around them and its IO.
//! Whoever is not a user is handed to the operator's own web server with every byte it sent, and from then on the node reads nothing of the connection as a protocol. The node composes no byte for such a peer: no status line, no header and no error page.
//! What it cannot hide is stated on the transports page and not here: the TLS handshake of a `tls` listener is the node's own, which is why `tls` is rated Detectable, an answer through the node is later than one from the origin by a hop, and a request line that arrives slowly is held until its end.
//! Timers of a session follow the node's wall clock, as those of `udp-obfs` do. The deadlines of a connection that has proven nothing follow the runtime's clock.
//! A `ws` or `fronted` listener is the other kind: it is meant for the operator's own web server, whose connections carry the requests of many visitors one after another. Such a connection is read request by request (`front`). A request that is not a user's is handed to the origin as it was read, head and body,
//! and the answer is handed back as the origin sent it. The node follows both only to know where they end (`veilway_proto::http`), and where it cannot tell with certainty it stops telling requests apart on that connection: it relays to the end of the answer and closes. A `fronted` session is a row in the listener's table that requests come to (`Polling`).
#[cfg(feature = "bench")]
use super::inbound::Peers;
use super::inbound::{Tunnel, Via};
use super::limits::{Bucket, Clock, Ended, Handshakes, Initiation, Seat, Seated, Source, Spent, ENDS};
use super::plan::{Native, Plan, Tags};
#[cfg(feature = "bench")]
use super::replay::Guard;
use super::{Over, Shared};
#[cfg(feature = "bench")]
use crate::config::Config;
use crate::config::{DEFAULT_DECOY_REQUESTS, DEFAULT_FRONTED_SESSIONS, DEFAULT_RELAYED, DEFAULT_SESSIONS, DEFAULT_SHAPED_SESSIONS, DEFAULT_UNDECIDED, DEFAULT_UNDECIDED_PER_SOURCE, MAX_PROXY_CONNECTIONS};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::IpNet;
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::ProtocolVersion;
use socket2::SockRef;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;
use time::{OffsetDateTime, UtcOffset};
use tokio::io::DuplexStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::AbortHandle;
#[cfg(feature = "bench")]
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{ChunkError, Opener, Padding, Sealer, MAX_ITEMS, MAX_PLAINTEXT, MAX_SEALED};
use veilway_proto::fronted::{self, BodyError, BODY_MAX, BODY_MIN, BODY_TIME, HOLD};
use veilway_proto::http::{self, Answer, Framing};
use veilway_proto::proof::{Name, SessionKeys};
use veilway_proto::replay::{Decision, Refusal, WRITE_DEADLINE};
use veilway_proto::request::{Line, Method, Scan, Scanner, HEAD_MAX, HEAD_TIME, LINE_MAX, LINE_TIME};
use veilway_proto::session::{self, Transport, ECHO, LONE_KEEPALIVE};
use veilway_proto::shape::Shape;
use veilway_proto::shaped::{Target, Who};
use veilway_proto::websocket::{self, BINARY, CLOSE, CLOSE_WAIT, CONTROL_MAX, NORMAL, PING, PONG};
use veilway_proto::{uniform, NoRandom};
use veilway_wg::ws::Acceptor;
#[cfg(feature = "bench")]
use veilway_wg::Wg;

mod h2;
mod shaped;

/// "TLS handshake deadline: 10 s from accept."
pub const TLS_HANDSHAKE: Duration = Duration::from_secs(10);
/// "Decoy connect timeout: 5 s."
pub const DECOY_CONNECT: Duration = Duration::from_secs(5);
/// "Idle time before a relayed connection may be closed for room: 60 s."
pub const RELAY_IDLE: Duration = Duration::from_secs(60);
/// "Wait between requests on a trusted proxy's connection: 300 s."
pub const PROXY_IDLE: Duration = Duration::from_secs(300);
/// How much of a request head that is over its size limit is still read, only to find the address its proxy named. Such a head is handed on as bytes whatever it holds, and nothing in it can make a user.
/// A web server takes heads of several times the node's limit (nginx: four buffers of 8 k), and the address a stranger is known to the origin by must not depend on how long its head is.
const SOURCE_HEAD: usize = 65_536;
/// The head of the answer to a `fronted` request, before the length of its body: "with status 200", and "both bodies are sent with `Content-Type: application/octet-stream` and a `Content-Length`". The web server in front adds what it adds to every answer.
const POLLED: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ";
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

impl Io for DuplexStream {}

pub(super) type Stream = Box<dyn Io>;

pub(super) fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| NoRandom)}

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
	/// On the proxy path: a request head above its size limit, or not complete within its time.
	Head,
	/// A `fronted` request that names no session the node has, a number that is not the next one or the last one again, or a session with another request in flight.
	Session,
	/// A `fronted` request whose body did not arrive in time, did not open as chunks of its session, or was a repeat with another body.
	Body,
	/// The opening request of a `fronted` session that no WireGuard packet of its device established.
	Unestablished,
}

const STRANGERS: usize = Stranger::Unestablished as usize + 1;

#[derive(Clone, Copy)]
enum Count {Accepted, AcceptFailed, Broken, HandshakeFailed, HandshakeSlow, HandshakeDisplaced, Relayed, Evicted, DecoyDown, Proofs, Waited, HeadRefused, Established, EstablishFull, Handshakes, Tunnel, QueueFull, Chunks, Learned, LearnFailed, Proxied, Requests, Unnamed, ProxyIdle, Forwarded, Unframed, Cut, Polls, Repeats, Legacy, Redialed, OriginDropped, ShapedPolls, ShapedRepeats, ShapedLate, ShapedStreams, ShapedEvents, ShapedBeats, ShapedLimited, H2Connections, H2Users, H2Strangers, H2Refused, H2Rapid, H2Flood, H2Limit}

const COUNTS: usize = Count::H2Limit as usize + 1;

pub struct Counters {counts: [AtomicU64; COUNTS], strangers: [AtomicU64; STRANGERS], ended: Arc<[AtomicU64; ENDS]>}

impl Default for Counters {
	fn default() -> Self {Counters {counts: std::array::from_fn(|_| AtomicU64::new(0)), strangers: Default::default(), ended: Arc::default()}}
}

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
	/// The proxy path of the `ws` and `fronted` listeners, right now: connections of trusted proxies, requests on them that are in a decoy origin's hands or whose body is still read without proof of who sent it, and established `fronted` sessions.
	pub proxies: usize,
	pub decoys: usize,
	pub fronted: usize,
	/// Connections that were taken from a trusted proxy, requests that were read on them, those among them on a listener with a `client_address_header` in which that header named no source, so that the proxy itself stood for it, and connections that were closed after 300 s without a request.
	pub proxy_accepted: u64,
	pub proxy_requests: u64,
	pub proxy_unnamed: u64,
	pub proxy_idle: u64,
	/// Requests that were handed to a decoy origin, those among them the node could not tell the end of, whose connection carried no request after them, and connections that were closed because their source, or all strangers together, had too many requests waiting.
	pub forwards: u64,
	pub forwards_unframed: u64,
	pub forwards_cut: u64,
	/// Requests of the proxy path decided "not a user" for a reason only that path has: a head over its limits, a `fronted` request that names no session or comes out of order or while another is in flight, one whose body was late or did not open, and an opening request whose session was never established.
	pub stranger_head: u64,
	pub stranger_session: u64,
	pub stranger_body: u64,
	pub stranger_unestablished: u64,
	/// `fronted` requests that were accepted, and repeats of the last accepted request that were answered with the stored response.
	pub polls: u64,
	pub poll_repeats: u64,
	/// Requests of trusted proxies whose line says `HTTP/1.0`. None of them can be a user's, so a web server that speaks HTTP/1.0 to the node shuts every user out, and this is where that shows.
	pub proxy_http10: u64,
	/// Requests that were sent to the origin a second time, on a new connection, because the connection that was kept from the request before turned out closed, and connections to the origin that were dropped between two requests because the origin said something or closed them there.
	pub forwards_redialed: u64,
	pub origin_dropped: u64,
	/// `fronted-shaped` sessions that are established right now, which `fronted` counts as well, and event streams that are live right now.
	pub shaped: usize,
	pub streams: usize,
	/// `fronted-shaped` requests that were accepted, repeats of them answered with the stored answer and repeats answered with the late answer, event streams that were started, events and heartbeats written to them, and stream requests that their session's allowance had no room for.
	pub shaped_polls: u64,
	pub shaped_repeats: u64,
	pub shaped_late: u64,
	pub shaped_streams: u64,
	pub shaped_events: u64,
	pub shaped_beats: u64,
	pub shaped_limited: u64,
	/// HTTP/2 connections of a `tls` listener, streams on them that were a user's and a stranger's, streams reset as malformed or over a bound before anything went upstream, and connections closed with GOAWAY for a rapid reset (streams that ended before their answer, whoever reset them), for a flood of frames that carry nothing or of streams opened, and for any other bound (a header block's size or time, the control frames not yet answered).
	pub h2_connections: u64,
	pub h2_users: u64,
	pub h2_strangers: u64,
	pub h2_refused: u64,
	pub h2_rapid: u64,
	pub h2_flood: u64,
	pub h2_limit: u64,
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

/// The acceptor with `h2` in its ALPN list ahead of `http/1.1`, for a listener whose `tls` transports have `http2` on. A client that offers `http/1.1` alone still gets what it got before.
pub fn offering_h2(acceptor: &Acceptor) -> Acceptor {
	let mut config = (*acceptor.config().clone()).clone();
	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	Acceptor::from(Arc::new(config))
}

/// One transport of a listener: the path its proofs arrive on and the tunnel they open.
#[derive(Clone)]
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
	/// `upgrade_cookie` and `upgrade_headers` of its inbound. On a `ws-plain` route the cookie is the one the token is read from, and none is set.
	pub cookie: String,
	pub headers: Vec<String>,
	/// The private halves of the keys of a `ws-plain` route, which tell its prover from the inbound's. Empty on every other route.
	pub keys: Vec<[u8; 32]>,
	/// The shape of a `fronted-shaped` route, which decides how its requests are read and answered.
	pub shape: Option<Arc<Shape>>,
}

impl Route {
	/// The route of a `tls` transport.
	pub fn tls(path: String, tunnel: Arc<Tunnel>, cookie: String, headers: Vec<String>) -> Route {Route {id: 0, path, tunnel, name: Name::Tls, method: Method::Get, over: Over::Tls, transport: Transport::Tls, cookie, headers, keys: Vec::new(), shape: None}}

	/// The route of a native `ws` transport: the session of `tls`, opened by a request that came through the operator's web server.
	pub fn ws(path: String, tunnel: Arc<Tunnel>, cookie: String, headers: Vec<String>) -> Route {Route {id: 0, path, tunnel, name: Name::Ws, method: Method::Get, over: Over::WsNative, transport: Transport::Ws, cookie, headers, keys: Vec::new(), shape: None}}

	/// The route of a `ws-plain` transport: the session of the native `ws`, opened by a request whose token is in a cookie, with a proof that names `ws-plain` and keys of the transport's own. The answer sets no cookie.
	pub fn ws_plain(path: String, tunnel: Arc<Tunnel>, cookie: String, headers: Vec<String>, keys: Vec<[u8; 32]>) -> Route {Route {id: 0, path, tunnel, name: Name::WsPlain, method: Method::Get, over: Over::WsPlain, transport: Transport::Ws, cookie, headers, keys, shape: None}}

	/// The route of a `fronted` transport, whose requests are `POST`s and whose answers are no upgrade.
	pub fn fronted(path: String, tunnel: Arc<Tunnel>) -> Route {Route {id: 0, path, tunnel, name: Name::Fronted, method: Method::Post, over: Over::Fronted, transport: Transport::Fronted, cookie: String::new(), headers: Vec::new(), keys: Vec::new(), shape: None}}

	/// The route of a `fronted-shaped` transport: requests in the shape it names, in a method that may be any, and answers that are no upgrade. Its proofs carry a name of their own, so none of another transport's opens here.
	pub fn fronted_shaped(path: String, tunnel: Arc<Tunnel>, shape: Arc<Shape>) -> Route {Route {id: 0, path, tunnel, name: Name::FrontedShaped, method: Method::Other, over: Over::FrontedShaped, transport: Transport::Fronted, cookie: String::new(), headers: Vec::new(), keys: Vec::new(), shape: Some(shape)}}
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

/// What makes a listener one of the proxy path: the web server in front of it, and the pools that path has (transports page, "Pools and what happens when one is full").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Front {
	/// `trusted_proxies`. A peer inside them is a proxy, and "a peer outside them is a direct peer that is never a user and always goes to the decoy".
	pub trusted: Vec<IpNet>,
	/// `client_address_header`. None for a listener that takes every request to come from its proxy.
	pub header: Option<String>,
	/// "Proxy connections: twice the `fronted` sessions", "`fronted` sessions: 4,096", and "one source may have 16 requests in flight to the decoy".
	pub connections: usize,
	pub fronted: usize,
	/// "Shaped sessions: 256 per listen address, counted among the 1,024 `fronted` sessions."
	pub shaped: usize,
	pub per_source: usize,
}

impl Front {
	/// `stream` says the listener has a shaped transport whose answers come on a stream: "Proxy connections: three times the shaped `sse` sessions, where the classic form uses twice the sessions", because each of those holds a connection for its stream and the front may open one more for each request in flight.
	pub fn of(trusted: Vec<IpNet>, header: Option<String>, limits: Option<crate::config::TransportLimits>, stream: bool) -> Front {
		let (limits, fronted) = (limits.unwrap_or_default(), limits.and_then(|limits| limits.fronted_sessions).unwrap_or(DEFAULT_FRONTED_SESSIONS));
		let shaped = limits.shaped_sessions.unwrap_or(DEFAULT_SHAPED_SESSIONS);
		let connections = if stream {(2 * fronted).max(3 * shaped)} else {2 * fronted};
		Front {trusted, header, connections: limits.proxy_connections.unwrap_or(connections.min(MAX_PROXY_CONNECTIONS)) as usize, fronted: fronted as usize, shaped: shaped as usize, per_source: limits.decoy_requests_per_source.unwrap_or(DEFAULT_DECOY_REQUESTS) as usize}
	}

	/// How many requests of strangers may be in a decoy origin's hands at once, whatever their sources: half the proxy pool. The transports page gives a share to each source and none to all of them, and with that alone enough sources hold every proxy connection, after which the web server in front is left waiting and no user's request arrives.
	/// With this bound, strangers hold half of the pool at the most, and the default pool of twice the `fronted` sessions leaves each of those a connection for its one request in flight. Over it, the connection with the oldest waiting request of any stranger is closed.
	pub fn waiting(&self) -> usize {(self.connections / 2).max(1)}

	fn trusts(&self, peer: IpAddr) -> bool {self.trusted.iter().any(|net| net.contains(&peer.to_canonical()))}
}

/// What a listener serves at one moment. A connection takes it once, when it is accepted, and works on that one value. A proxy connection takes it again for every request.
pub struct Served {
	/// What ends TLS on the listener. None for a listener that reads plain HTTP: one of the proxy path, or a harness.
	pub acceptor: Option<Acceptor>,
	pub routes: Vec<Route>,
	pub origin: Origin,
	/// `decoy.proxy_protocol`: "It is all connections or none."
	pub proxy: bool,
	/// What the node's own requests to the origin carry as `Host`.
	pub host: String,
	pub pools: Pools,
	/// Set for a `ws` or `fronted` listener. "A listener serves one kind of peer."
	pub front: Option<Front>,
	/// `http2` of the listener's `tls` transports: whether the node offers `h2` next to `http/1.1` once it ends TLS.
	pub h2: bool,
}

/// One connection in the undecided pool, or one request of the proxy path among those that wait with nothing proven. Dropping it takes it out, wherever it has got to.
struct Place {listener: Arc<Listener>, table: fn(&Listener) -> MutexGuard<'_, Undecided>, id: u64, source: Source, bump: Arc<Notify>}

impl Drop for Place {
	fn drop(&mut self) {(self.table)(&self.listener).leave(self.id, self.source);}
}

#[derive(Default)]
pub(super) struct Undecided {pub(super) all: BTreeMap<u64, (Source, Arc<Notify>)>, pub(super) by_source: HashMap<Source, VecDeque<u64>>}

impl Undecided {
	/// Takes a connection out. Whether it was still in.
	pub(super) fn leave(&mut self, id: u64, source: Source) -> bool {
		if let Some(ids) = self.by_source.get_mut(&source) {
			ids.retain(|held| *held != id);
			if ids.is_empty() {self.by_source.remove(&source);}
		}
		self.all.remove(&id).is_some()
	}
}

/// One connection in the relayed pool: when a byte last crossed it, in Unix milliseconds, and what closes it when the pool needs its place.
pub(super) struct Relayed {pub(super) last: AtomicI64, pub(super) kill: Notify}

/// What only the one request in flight of a `fronted` session has: the node's side of the chunks, the session's allowance of handshakes, and what waits to go to the device.
struct Turn {sealer: Sealer, handshakes: Handshakes, waiting: mpsc::Receiver<(Vec<u8>, bool)>, held: VecDeque<(Vec<u8>, bool)>, lone: Option<Instant>}

/// What a `fronted` session is between two requests. Nothing here changes but under the hand of a request whose every chunk opened at the expected numbers, or of the proof that opened the session: "a live session it named is left exactly as it was".
struct Polled {
	/// Taken by the request in flight for as long as it is: "no other request of that session may be in flight".
	turn: Option<Box<Turn>>,
	opener: fronted::Opener,
	/// The number of the last accepted request, 0 for the opening one, with the length and the SHA-256 of its body and the response it got: "The node stores one response per session, for the repeat."
	/// The body is kept only to know a repeat by, and its digest does that: the response, a body of at most 65,536 bytes, is all of that size a session keeps between two requests. None for the opening request, which has no repeat.
	number: u32,
	body: Option<(usize, [u8; 32])>,
	response: Option<Arc<Vec<u8>>>,
}

/// One `fronted` session: a row of its listener's table that requests name by its `sid`, with the queue of what the node has for its device.
struct Polling {id: u64, route: u64, session: Arc<Session>, state: Mutex<Polled>}

/// A place in the proxy pool, which counts its connection among those of trusted proxies for as long as the connection has it.
struct Lease {_place: OwnedSemaphorePermit, held: Arc<AtomicI64>}

impl Drop for Lease {
	fn drop(&mut self) {self.held.fetch_sub(1, Ordering::Relaxed);}
}

/// The connection to the decoy origin that a proxy connection keeps between two requests it handed there, and whose address its PROXY protocol header named.
struct Kept {read: ReadHalf<Stream>, write: WriteHalf<Stream>, source: IpAddr}

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
	/// The proxy pool: one permit for each connection of a trusted proxy. "The node stops accepting on that listener and leaves new connections in the system's queue" when none is left.
	proxies: Arc<Semaphore>,
	seats: Mutex<usize>,
	/// How many connections of trusted proxies hold a place of that pool right now. The accept loop has one more in hand while it waits for the next connection.
	fronts: Arc<AtomicI64>,
	/// The requests of the proxy path that wait with nothing proven: in a decoy origin's hands, or with a body still to come that nothing has vouched for. Each can close its connection, and the oldest of a source, or of all, does when there are too many.
	decoys: Mutex<Undecided>,
	/// Every `fronted` session by its `sid`, pending or established, and how many of them are established.
	polling: Mutex<HashMap<[u8; 16], Arc<Polling>>>,
	polled: Arc<AtomicI64>,
	/// Every `fronted-shaped` session by its `sid`, pending or established, how many of them are established (they are counted in `polled` as well), and how many event streams are live.
	shaped: Mutex<HashMap<[u8; 16], Arc<shaped::Shaped>>>,
	shaped_pool: Arc<AtomicI64>,
	streams: AtomicI64,
	/// What the decoy origin sent for each header field of its answer to the node's own request, first values only. None while that has not been learnt.
	learned: RwLock<Option<Arc<Vec<(String, String)>>>>,
	relearn: Notify,
	/// When it was last said that the decoy origin cannot be reached. None while it can.
	down: Mutex<Option<Instant>>,
	closed: AtomicBool,
	/// Wakes every proxy connection when the listener closes.
	shut: Notify,
	counters: Arc<Counters>,
	/// What the listener keeps of its HTTP/2 connections.
	h2: h2::Book,
}

/// What every stream listener of the node shares: the counters, and the way to each of them.
#[derive(Default)]
pub struct State {listeners: Mutex<Vec<Weak<Listener>>>, counters: Arc<Counters>}

impl State {
	/// A listener on `addr` that serves nothing yet.
	pub fn listen(&self, addr: SocketAddr, served: Served) -> Arc<Listener> {
		let seats = served.front.as_ref().map_or(0, |front| front.connections);
		let permits = served.pools.undecided + served.pools.relayed + served.pools.sessions + SPARE + seats;
		let listener = Arc::new(Listener {addr, served: RwLock::new(Arc::new(Served {acceptor: None, routes: Vec::new(), origin: served.origin.clone(), proxy: served.proxy, host: String::new(), pools: served.pools, front: served.front.clone(), h2: served.h2})), undecided: Mutex::default(), relayed: Mutex::default(), sessions: Mutex::default(), pool: Arc::default(), waiting: AtomicUsize::new(0), ids: AtomicU64::new(1), room: Arc::new(Semaphore::new(permits)), permits: Mutex::new(permits), proxies: Arc::new(Semaphore::new(seats)), seats: Mutex::new(seats), fronts: Arc::default(), decoys: Mutex::default(), polling: Mutex::default(), polled: Arc::default(), shaped: Mutex::default(), shaped_pool: Arc::default(), streams: AtomicI64::new(0), learned: RwLock::default(), relearn: Notify::new(), down: Mutex::default(), closed: AtomicBool::new(false), shut: Notify::new(), counters: self.counters.clone(), h2: h2::Book::default()});
		listener.serve(served);
		let mut listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
		listeners.retain(|listener| listener.strong_count() > 0);
		listeners.push(Arc::downgrade(&listener));
		listener
	}

	/// Once a second: a `fronted` session that has ended leaves its listener's table. Nothing else holds such a session between two requests, so nothing else could take it out.
	pub fn sweep(&self) {
		let listeners: Vec<Arc<Listener>> = self.listeners.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect();
		for listener in &listeners {
			let over: Vec<Arc<Polling>> = listener.polling().values().filter(|polling| polling.session.seat.over()).cloned().collect();
			for polling in &over {listener.forget(polling)}
			let over: Vec<Arc<shaped::Shaped>> = listener.shaped().values().filter(|shaped| shaped.session.seat.over()).cloned().collect();
			for shaped in &over {listener.forget_shaped(shaped)}
		}
	}

	pub fn totals(&self) -> StreamTotals {
		let listeners: Vec<Arc<Listener>> = self.listeners.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect();
		let (mut undecided, mut relayed, mut pending, mut sessions, mut proxies, mut decoys, mut fronted, mut shaped, mut streams) = (0, 0, 0, 0, 0, 0, 0, 0, 0);
		for listener in &listeners {
			undecided += listener.undecided().all.len();
			relayed += listener.relayed().len();
			proxies += listener.fronts.load(Ordering::Relaxed).max(0) as usize;
			decoys += listener.decoys().all.len();
			fronted += listener.polled.load(Ordering::Relaxed).max(0) as usize;
			shaped += listener.shaped_pool.load(Ordering::Relaxed).max(0) as usize;
			streams += listener.streams.load(Ordering::Relaxed).max(0) as usize;
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
			proxies, decoys, fronted, proxy_accepted: count(Count::Proxied), proxy_requests: count(Count::Requests), proxy_unnamed: count(Count::Unnamed), proxy_idle: count(Count::ProxyIdle), forwards: count(Count::Forwarded), forwards_unframed: count(Count::Unframed), forwards_cut: count(Count::Cut),
			stranger_head: stranger(Stranger::Head), stranger_session: stranger(Stranger::Session), stranger_body: stranger(Stranger::Body), stranger_unestablished: stranger(Stranger::Unestablished), polls: count(Count::Polls), poll_repeats: count(Count::Repeats),
			proxy_http10: count(Count::Legacy), forwards_redialed: count(Count::Redialed), origin_dropped: count(Count::OriginDropped),
			shaped, streams, shaped_polls: count(Count::ShapedPolls), shaped_repeats: count(Count::ShapedRepeats), shaped_late: count(Count::ShapedLate), shaped_streams: count(Count::ShapedStreams), shaped_events: count(Count::ShapedEvents), shaped_beats: count(Count::ShapedBeats), shaped_limited: count(Count::ShapedLimited), h2_connections: count(Count::H2Connections), h2_users: count(Count::H2Users), h2_strangers: count(Count::H2Strangers), h2_refused: count(Count::H2Refused), h2_rapid: count(Count::H2Rapid), h2_flood: count(Count::H2Flood), h2_limit: count(Count::H2Limit),
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

	fn decoys(&self) -> MutexGuard<'_, Undecided> {self.decoys.lock().unwrap_or_else(|e| e.into_inner())}

	fn polling(&self) -> MutexGuard<'_, HashMap<[u8; 16], Arc<Polling>>> {self.polling.lock().unwrap_or_else(|e| e.into_inner())}

	fn shaped(&self) -> MutexGuard<'_, HashMap<[u8; 16], Arc<shaped::Shaped>>> {self.shaped.lock().unwrap_or_else(|e| e.into_inner())}

	/// Gives a connection of a trusted proxy the place in the proxy pool that was taken for it.
	fn lease(&self, place: OwnedSemaphorePermit) -> Lease {
		self.fronts.fetch_add(1, Ordering::Relaxed);
		Lease {_place: place, held: self.fronts.clone()}
	}

	/// Counts a connection of the proxy path that is closed at once, because its source or all strangers together had too many requests waiting, or because the listener closed.
	fn cut(&self) -> Handed {
		self.counters.count(Count::Cut);
		Handed::Cut
	}

	/// Takes a `fronted` session out of the listener's tables, whatever became of it.
	fn forget(&self, polling: &Arc<Polling>) {
		self.polling().retain(|_, held| !Arc::ptr_eq(held, polling));
		self.sessions().remove(&polling.id);
	}

	/// Takes a `fronted-shaped` session out of the listener's tables, whatever became of it.
	fn forget_shaped(&self, shaped: &Arc<shaped::Shaped>) {
		self.shaped().retain(|_, held| !Arc::ptr_eq(held, shaped));
		self.sessions().remove(&shaped.id);
	}

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
		let seats = served.front.as_ref().map_or(0, |front| front.connections);
		for (room, held, wanted) in [(&self.room, &self.permits, served.pools.undecided + served.pools.relayed + served.pools.sessions + SPARE + seats), (&self.proxies, &self.seats, seats)] {
			let mut permits = held.lock().unwrap_or_else(|e| e.into_inner());
			if wanted > *permits {room.add_permits(wanted - *permits)}
			*permits = if wanted < *permits {*permits - room.forget_permits(*permits - wanted)} else {wanted};
		}
		*self.served.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(served);
		self.relearn.notify_one();
	}

	/// A certificate the node made anew under the config in force: the next connection is answered with it, and nothing else changes. What runs keeps the certificate it was accepted with.
	pub fn certify(&self, acceptor: Acceptor) {
		let mut served = self.served.write().unwrap_or_else(|e| e.into_inner());
		*served = Arc::new(Served {acceptor: Some(if served.h2 {offering_h2(&acceptor)} else {acceptor}), routes: served.routes.clone(), origin: served.origin.clone(), proxy: served.proxy, host: served.host.clone(), pools: served.pools, front: served.front.clone(), h2: served.h2});
	}

	/// The end of a listener whose address no config has any more: its sessions end, and so does every connection it holds.
	pub fn close(&self) {
		self.closed.store(true, Ordering::Release);
		for (_, seat) in self.sessions().values() {seat.end(Ended::Unserved)}
		for (_, bump) in self.undecided().all.values().chain(self.decoys().all.values()) {bump.notify_one()}
		for relayed in self.relayed().values() {relayed.kill.notify_one()}
		self.shut.notify_waiters();
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
	/// `fronted` is the pool of `fronted` sessions for a proof that opens one, which is held to both.
	#[allow(clippy::too_many_arguments)]
	fn charge(&self, shared: &Shared, seat: &Arc<Seat>, from: IpAddr, now: i64, cap: usize, fronted: Option<usize>, shaped: Option<usize>, why: &mut Stranger) -> bool {
		if self.pool.load(Ordering::Relaxed) >= cap as i64 || fronted.is_some_and(|fronted| self.polled.load(Ordering::Relaxed) >= fronted as i64) || shaped.is_some_and(|shaped| self.shaped_pool.load(Ordering::Relaxed) >= shaped as i64) {
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
		// "One `Set-Cookie` field. Its value is random base64url text of a random length. It carries no meaning. It exists so that the answer's length varies." A `ws-plain` answer has none: a path that watches the cookie would read it, and a value that the client never sends back is a tell.
		let jar = if route.over == Over::WsPlain {String::new()} else {
			random(&mut cookie).ok()?;
			let length = uniform(*COOKIE.start(), *COOKIE.end(), &mut random).ok()? as usize;
			format!("Set-Cookie: {}={}\r\n", route.cookie, &URL_SAFE_NO_PAD.encode(cookie)[..length])
		};
		answer.extend_from_slice(format!("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{jar}\r\n", websocket::accept(key)).as_bytes());
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
			// "Proxy: The node stops accepting on that listener and leaves new connections in the system's queue." A listener of the proxy path takes a connection from the system only when its proxy pool has a place for it, whoever it then turns out to be from.
			let seat = if listener.served().front.is_some() {listener.proxies.clone().acquire_owned().await.ok()} else {None};
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
			// The peer of the socket decides, and nothing it sends does: "a peer outside them is a direct peer that is never a user and always goes to the decoy." It gives its place in the proxy pool back at once.
			match seat.filter(|_| served.front.as_ref().is_some_and(|front| front.trusts(peer.ip()))) {
				Some(seat) => {
					listener.counters.count(Count::Proxied);
					let _ = tcp.set_nodelay(true);
					let Ok(local) = tcp.local_addr() else {
						listener.counters.count(Count::Broken);
						continue;
					};
					tokio::spawn(front(shared.clone(), listener.clone(), Box::new(tcp), peer, local, listener.lease(seat), permit));
				}
				None => {
					let place = enter(&listener, Listener::undecided, Source::of(peer.ip()), served.pools.undecided, served.pools.per_source);
					tokio::spawn(direct(shared.clone(), listener.clone(), served, tcp, peer, place, permit));
				}
			}
		}
	}).abort_handle()
}

/// Puts a new connection into the undecided pool: "Accepted from a direct peer, no decision yet."
/// "The oldest undecided connection is decided as not a user at once. The same happens to a source's oldest undecided connection when that source reaches its share." Whoever is displaced is out of the pool before this returns.
/// Only connections that have proven nothing are in this pool, so only strangers are ever displaced: "Strangers may displace strangers. Nothing a stranger does displaces a session."
/// The requests of the proxy path that wait with nothing proven are held the same way, in a table of their own: "one source may have 16 requests in flight to the decoy. Over that, the proxy connection that carries that source's oldest waiting request is closed."
fn enter(listener: &Arc<Listener>, table: fn(&Listener) -> MutexGuard<'_, Undecided>, source: Source, all: usize, per_source: usize) -> Place {
	let (id, bump, mut undecided) = (listener.ids.fetch_add(1, Ordering::Relaxed), Arc::new(Notify::new()), table(listener));
	if let Some(displaced) = undecided.by_source.get(&source).filter(|ids| ids.len() >= per_source).and_then(|ids| ids.front().copied()) {
		if let Some((_, bump)) = undecided.all.get(&displaced) {bump.notify_one()}
		undecided.leave(displaced, source);
	}
	while undecided.all.len() >= all {
		let Some((displaced, (of, bump))) = undecided.all.first_key_value().map(|(displaced, (of, bump))| (*displaced, (*of, bump.clone()))) else {break};
		bump.notify_one();
		undecided.leave(displaced, of);
	}
	undecided.all.insert(id, (source, bump.clone()));
	undecided.by_source.entry(source).or_default().push_back(id);
	drop(undecided);
	Place {listener: listener.clone(), table, id, source, bump}
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
					// "For a connection where TLS chose `h2`": the node is an HTTP/2 server for it, and decides every stream on its own.
					if served.h2 && tls.get_ref().1.alpn_protocol() == Some(b"h2") {return h2::serve(shared, listener, served, Box::new(tls), modern, peer, local, place).await}
					(Box::new(tls), modern)
				}
				Err(count) => return listener.counters.count(count),
			}
		}
		// A listener of the proxy path reads plain HTTP, and whoever reaches it from outside `trusted_proxies` is never a user: its line is verified with the same work and with dummy inputs. Only a harness has a listener that is neither.
		None => (Box::new(tcp), served.front.is_none()),
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
		Ok(line) => prove(&shared, &listener, &served, &buf[..line], &[], &[], |route| user && route.over == Over::Tls, peer.ip(), Some(&place)).await.map(|accepted| (line, accepted)),
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
/// `head` is the whole head of a request of the proxy path, and empty where there is none: a `ws-plain` route reads its token from the one cookie of it, and a request with anything in its query is not a user's there.
/// `able` says of a route whether a line on this connection can be a user's on it at all, by what is known besides the line: the kind of peer, and on the proxy path the head of the request. On the proxy path "a `GET` for a `ws` path or a `POST` for a `fronted` path can be a user's", and `from` is the source its proxy named.
async fn prove(shared: &Arc<Shared>, listener: &Listener, served: &Served, line: &[u8], head: &[u8], targets: &[Option<Target<'_>>], able: impl Fn(&Route) -> bool, from: IpAddr, place: Option<&Place>) -> Result<Accepted, Stranger> {
	let Some(line) = Line::parse_any(line) else {return Err(Stranger::Syntax)};
	let (plan, paths): (Arc<Plan>, Vec<&[u8]>) = (shared.plan(), served.routes.iter().map(|route| route.path.as_bytes()).collect());
	let (at, query) = (line.path_among(&paths), line.query.unwrap_or_default());
	let natives: Vec<Option<(&Native, Arc<Tags>)>> = served.routes.iter().map(|route| plan.inbound_of(&route.tunnel).and_then(|inbound| plan.inbounds[inbound].native.as_ref()).map(|native| (native, native.tags()))).collect();
	let mut found = None;
	for (index, (route, native)) in served.routes.iter().zip(&natives).enumerate() {
		let Some((prover, tags)) = native.as_ref().and_then(|(native, tags)| Some((native.prover_for(&route.keys)?, tags))) else {continue};
		// A route with a shape reads its own target: the text of a proof is the one of an opening request in the form of the shape, and a later request is no proof. The others take the query of the line on their path and with their method, and none of them takes a line over 4,096 bytes.
		let candidate = match (&route.shape, targets.get(index)) {
			(Some(_), Some(Some(target))) => if let Who::Opening(token) = target.who {Some(token)} else {None},
			(Some(_), _) => None,
			(None, _) if route.over == Over::WsPlain => (able(route) && at == Some(index) && line.method == route.method && line.query.is_none()).then(|| http::cookie_once(head, route.cookie.as_bytes())).flatten(),
			(None, _) => (able(route) && at == Some(index) && line.method == route.method).then_some(query),
		};
		if let Ok(opened) = prover.node.open(candidate.map(|_| route.name), candidate.unwrap_or(query), &tags.table) {found = Some((index, opened))}
	}
	let Some((index, mut opened)) = found else {return Err(Stranger::Proof)};
	if let Some(place) = place {(place.table)(&place.listener).leave(place.id, place.source);}
	let ((route, native), now) = ((&served.routes[index], natives[index].as_ref().map(|(native, _)| *native)), Clock::of((shared.now)()));
	let (Some(native), Some(replay)) = (native, shared.replay.get()) else {return Err(Stranger::NoReplay)};
	// The session as the limits will know it. It is one of its device's sessions from the moment the limits are charged for it, and nobody's when they are not.
	// It remembers the node transport key its token opened under as well as the device secret: its chunk keys come from that key too, so the session ends when the config no longer has it.
	let polled = matches!(route.over, Over::Fronted | Over::FrontedShaped).then(|| (listener.polled.clone(), served.front.as_ref().map_or(0, |front| front.fronted)));
	let shaped = route.shape.as_ref().map(|_| (listener.shaped_pool.clone(), served.front.as_ref().map_or(0, |front| front.shaped)));
	let seat = Seat::new(opened.device.public, opened.device.id, native.prover_for(&route.keys).and_then(|prover| prover.keys.get(opened.key).copied()), route.tunnel.clone(), listener.pool.clone(), polled.as_ref().map(|(polled, _)| polled.clone()), shaped.as_ref().map(|(shaped, _)| shaped.clone()), listener.counters.ended.clone(), route.transport.idle(), now.ms);
	let (mut writes, mut waiting): (_, Option<(Instant, Held)>) = (replay.writes(), None);
	loop {
		// A write that ends after the rule was asked is one this proof has not seen yet, and wakes it.
		writes.borrow_and_update();
		let (now, mut why) = (Clock::of((shared.now)()), Stranger::NoReplay);
		opened = match replay.with(|memory| opened.accept(memory, now.secs, |_| listener.charge(shared, &seat, from, now.ms, served.pools.sessions, polled.as_ref().map(|(_, cap)| *cap), shaped.as_ref().map(|(_, cap)| *cap), &mut why))) {
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

/// One WireGuard datagram that came in on a session, from the chunk it travelled in to the tunnel (transports page, "WireGuard on an obfuscated transport"). What WireGuard answers to it goes to `net` and what it carried to `ip`.
/// Whether it was a keepalive, for a packet of the session's device. None for a datagram that is none, or that the session's allowance of handshakes has no room for: it leaves nothing behind.
#[allow(clippy::too_many_arguments)]
fn take(shared: &Shared, listener: &Listener, served: &Served, session: &Arc<Session>, handshakes: &Handshakes, peer: SocketAddr, now: Clock, datagram: &[u8], net: &mut Vec<Vec<u8>>, ip: &mut Vec<Vec<u8>>) -> Option<bool> {
	let seat = &session.seat;
	// "Excess messages are dropped silently and counted", and an initiation the session took before is dropped before the allowance is charged, see `Handshakes::admit`.
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
		if let Some(bound) = bound.filter(|_| seat.live()) {peers.heard(bound.peer, Via::Stream(Arc::downgrade(session)))}
		bound
	};
	// "A session is pending until a WireGuard packet of its device has authenticated on it." A pool that has filled up since the proof leaves the session pending, and it ends at its deadline.
	let seated = match bound {
		None => None,
		Some(bound) if seat.pending() => match shared.limits.establish(seat, served.pools.sessions, served.front.as_ref().map_or(usize::MAX, |front| front.fronted), served.front.as_ref().map_or(usize::MAX, |front| front.shaped), now.ms) {
			Seated::Established => {
				listener.counters.count(Count::Established);
				let mut peers = seat.tunnel.lock();
				if peers.wg.index(&seat.device) == Some(bound.peer) {peers.heard(bound.peer, Via::Stream(Arc::downgrade(session)))}
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
						if let Some(lone) = take(shared, listener, served, &session, &handshakes, peer, now, datagram, &mut net, &mut ip) {keepalive = lone}
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
pub(super) async fn relay(now: fn() -> OffsetDateTime, io: Stream, origin: Stream, sent: &[u8], first: &[u8], open: Result<bool, io::ErrorKind>, slot: &Relayed) {
	let ((mut from_peer, mut to_peer), (mut from_origin, mut to_origin)) = (tokio::io::split(io), tokio::io::split(origin));
	// What a peer or an origin does to its connection is theirs to say; anything else, such as a system out of buffers, is logged.
	let odd = |e: &io::Error| !matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof);
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
					Err(e) if e.kind() != io::ErrorKind::UnexpectedEof => {
						if odd(&e) {tracing::info!("a relayed connection ended because reading from the peer failed with {e:?}")}
						return false;
					}
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
						if let Err(e) = async {to_peer.write_all(&buf[..read]).await?; to_peer.flush().await}.await {
							if odd(&e) {tracing::info!("a relayed connection ended because writing to the peer failed with {e:?}, with the origin's answer not yet all handed on")}
							return false;
						}
						slot.last.store(Clock::of(now()).ms, Ordering::Relaxed);
					}
					Ok(_) => return false,
					Err(e) => {
						if odd(&e) {tracing::info!("a relayed connection ended because reading from the origin failed with {e:?}")}
						return e.kind() == io::ErrorKind::ConnectionReset;
					}
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

/// One connection of a trusted proxy, request by request (transports page, "Accept state machine", "Trusted proxy peer"). `seat` is its place in the proxy pool, which it gives back when it ends or becomes the connection of a WebSocket session.
/// "It is never closed to make room for a direct peer": what closes it is its proxy, the origin behind a request it carried, 300 s without a request, or the rule for strangers' requests.
/// Between two requests that went to the origin it keeps the connection it opened there, and watches it. Whatever the origin does on that connection while no request is in its hands (a byte, a close, a reset) answers nothing the proxy asked: the origin's connection is dropped, nothing is passed on, and the proxy's connection stays.
/// The proxy's next request may be a user's, and an origin that says `408` on a quiet connection, or closes it by its keep-alive timer, would otherwise put that in front of a user. With no node in between the web server in front would own that quiet upstream connection and discard it the same way.
/// A request of a user ends it too: the origin's connection is closed unused, because the origin never saw the request.
async fn front(shared: Arc<Shared>, listener: Arc<Listener>, io: Stream, peer: SocketAddr, local: SocketAddr, seat: Lease, _room: OwnedSemaphorePermit) {
	let ((mut from_proxy, mut to_proxy), mut buf, mut filled, mut eof, mut kept, mut early) = (tokio::io::split(io), vec![0u8; HEAD_MAX], 0, false, None::<Kept>, [0u8; 1]);
	loop {
		// A `fronted` body is read behind its head, into room that is given back with the request.
		if filled <= HEAD_MAX && buf.len() != HEAD_MAX {
			buf.resize(HEAD_MAX, 0);
			buf.shrink_to(HEAD_MAX);
		}
		// 1. "Read the whole request head, within the limits for a head. The proxy has buffered it already, so waiting for it adds no delay that a prober could measure." The time of a head runs from its first byte, and before that the connection waits for its next request.
		let (idle, mut limit, shut) = (Instant::now() + PROXY_IDLE, (filled > 0).then(|| Instant::now() + HEAD_TIME), listener.shut.notified());
		tokio::pin!(shut);
		shut.as_mut().enable();
		if listener.closed.load(Ordering::Acquire) {return}
		let whole = loop {
			if let Some(end) = http::head_end(&buf[..filled.min(HEAD_MAX)]) {break Ok(end)}
			if filled >= HEAD_MAX {break Err(Stranger::Head)}
			if eof {
				if filled == 0 {return}
				break Err(Stranger::Closed);
			}
			tokio::select! {
				biased;
				_ = &mut shut => return,
				read = from_proxy.read(&mut buf[filled..]) => match read {
					Ok(read) if read > 0 => {
						filled += read;
						limit.get_or_insert_with(|| Instant::now() + HEAD_TIME);
					}
					Ok(_) => eof = true,
					Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => eof = true,
					Err(_) => return listener.counters.count(Count::Broken),
				},
				_ = async {
					match kept.as_mut() {
						Some(kept) => drop(kept.read.read(&mut early).await),
						None => std::future::pending().await,
					}
				}, if kept.is_some() => {
					listener.counters.count(Count::OriginDropped);
					kept = None;
				}
				_ = sleep_until(limit.unwrap_or(idle)) => {
					if limit.is_some() {break Err(Stranger::Head)}
					// "A proxy connection is closed after 300 s without a request."
					listener.counters.count(Count::ProxyIdle);
					let _ = timeout(CLOSE_WAIT, to_proxy.shutdown()).await;
					return;
				}
			}
		};
		// A head over the size limit is nobody's, and is handed on as the bytes it is. It is still read on, to where it ends, to `SOURCE_HEAD` bytes or to the end of its time, for one thing only: the address its proxy named.
		// Without that a stranger with a long head would be the proxy itself to the origin, in its log, in its limits and in whatever it grants its own host. Nothing that is read here decides who is a user.
		let mut headed = whole.ok();
		if whole.is_err() && filled >= HEAD_MAX {
			buf.resize(SOURCE_HEAD, 0);
			let mut seen = HEAD_MAX - 3;
			headed = loop {
				if let Some(end) = http::head_end(&buf[seen..filled]) {break Some(seen + end)}
				seen = filled - 3;
				if filled >= SOURCE_HEAD || eof {break None}
				tokio::select! {
					biased;
					_ = &mut shut => return,
					read = from_proxy.read(&mut buf[filled..]) => match read {
						Ok(read) if read > 0 => filled += read,
						Ok(_) => eof = true,
						Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => eof = true,
						Err(_) => return listener.counters.count(Count::Broken),
					},
					_ = sleep_until(limit.unwrap_or(idle)) => break None,
				}
			};
		}
		listener.counters.count(Count::Requests);
		let served = listener.served();
		let Some(way) = &served.front else {return};
		// The list in force now decides, not the one the connection was accepted under: a proxy that a reload took out of `trusted_proxies` is a direct peer from its next request on, "never a user", and believed about nobody's address.
		let trusted = way.trusts(peer.ip());
		// "A head that is over the size limit or not complete in time is not a user: forward what was read", which then is all the node has of it, and is not told apart from what follows it.
		let end = whole.unwrap_or(filled);
		let mut request = http::request(&buf[..end]);
		if whole.is_err() {request.body = None}
		// A web server that speaks HTTP/1.0 to the node hands on no request a user could have sent, and nothing else would say so.
		if trusted && buf[..request.line].ends_with(b" HTTP/1.0\r\n") {listener.counters.count(Count::Legacy)}
		// 2. "The source for every limit and log line is the rightmost address in the header named by `client_address_header` that is not itself inside `trusted_proxies`. If the header is absent or unreadable, it is the peer."
		let named = headed.filter(|_| trusted).and_then(|head| way.header.as_ref().and_then(|name| http::forwarded(&buf[..head], name.as_bytes(), |address| way.trusts(address))));
		if named.is_none() && way.header.is_some() && trusted {listener.counters.count(Count::Unnamed)}
		let source = named.unwrap_or(peer.ip().to_canonical());
		// 3. "Evaluate the request line as a direct peer's is evaluated, with that source. Here a `GET` for a `ws` path or a `POST` for a `fronted` path can be a user's. Steps 1 to 4 of Verifying run for every request": for every one whose line passes the test that uses no secret, as for a direct peer.
		// What makes a request no user's by its head is known before that and changes none of the work: on `fronted`, step 1 of its state machine, "exactly one `Content-Length`, from 18 to 65,536, and no `Transfer-Encoding`", and on `ws` a head that is HTTP/1.1 as the node reads it, with no body.
		let (framed, line) = (matches!(request.body, Some(Framing::Length(length)) if (BODY_MIN as u64..=BODY_MAX as u64).contains(&length)), &buf[..request.line]);
		// A shaped route reads its own head: "for `body`: exactly one `Content-Length`, 18 to `up.limit`, no `Transfer-Encoding`. For the others: no body, so no `Content-Length` other than 0, no `Transfer-Encoding`." Its request line may be up to 4,096 bytes, or 8,192 when `up.limit` is above 4,000, and that of every other route stays at 4,096.
		let able = |route: &Route| trusted && request.line <= route.shape.as_ref().map_or(LINE_MAX, |shape| shape.line_max()) && match &route.shape {
			Some(shape) if shape.bodied() => matches!(request.body, Some(Framing::Length(length)) if (BODY_MIN as u64..=shape.up.limit as u64).contains(&length)),
			Some(_) => matches!(request.body, Some(Framing::None | Framing::Length(0))),
			None if route.over == Over::Fronted => framed,
			None => request.body == Some(Framing::None),
		};
		// Only a listener with a shaped route reads a line the scanner would not call a candidate, and then only up to the limit of a shaped route.
		let parsed = Line::parse_any(line).filter(|_| served.routes.iter().any(|route| route.shape.is_some()));
		let targets: Vec<Option<Target>> = served.routes.iter().map(|route| route.shape.as_ref().zip(parsed.as_ref()).filter(|_| able(route)).and_then(|(shape, parsed)| Target::read(shape, route.path.as_bytes(), parsed, shape.up.name.as_deref().and_then(|name| http::field_once(&buf[..end], name.as_bytes()))))).collect();
		let proved = match whole {
			Err(why) => Err(why),
			// What no route of the listener could accept gets the decoy's answer at once, as on a listener without shaped routes: a line over the longest any route allows for its method, and a method that no shaped route has.
			Ok(_) if parsed.is_none() && Scanner::new().feed(line) != Scan::Line(request.line) => Err(Stranger::Syntax),
			Ok(_) if parsed.is_some_and(|parsed| !(matches!(parsed.method, Method::Get | Method::Post) && request.line <= LINE_MAX) && !served.routes.iter().any(|route| route.shape.as_ref().is_some_and(|shape| shape.up.method.as_bytes() == parsed.verb && request.line <= shape.line_max()))) => Err(Stranger::Syntax),
			Ok(_) => prove(&shared, &listener, &served, line, &buf[..end], &targets, able, source, None).await,
		};
		// 4. A request of a shaped route that is a user's: the opening request of a proof that was accepted, or a later request whose `sid` is a session of this listener, on the route of that session.
		let (proved, shaped_ask) = match proved {
			Ok(accepted) if served.routes[accepted.route].shape.is_some() => {
				let index = accepted.route;
				(Err(Stranger::Proof), Some((index, shaped::Asked::Opening(accepted))))
			}
			Err(Stranger::Proof) if trusted => {
				let found = targets.iter().enumerate().find_map(|(index, target)| match target.as_ref()?.who {
					Who::Later(sid, number) => Some((index, sid, number)),
					Who::Opening(_) => None,
				});
				(Err(Stranger::Proof), found.and_then(|(index, sid, number)| {
					let session = listener.shaped().get(&sid).cloned()?;
					(session.route == served.routes[index].id).then_some((index, shaped::Asked::Later(session, number)))
				}))
			}
			other => (other, None),
		};
		let (asked, mut why) = match proved {
			// 4. "A user. For a WebSocket open, the connection leaves the proxy pool: continue with WebSocket session. A head that is not a WebSocket upgrade closes the connection with no HTTP answer."
			Ok(accepted) if served.routes[accepted.route].over != Over::Fronted => {
				listener.counters.count(Count::Proofs);
				drop((kept, seat));
				return session(&shared, &listener, &served, from_proxy.unsplit(to_proxy), SocketAddr::new(source, 0), buf, filled, request.line, accepted).await;
			}
			Ok(accepted) => {
				listener.counters.count(Count::Proofs);
				(Some(Ok(accepted)), Stranger::Proof)
			}
			// "`fronted`", "State machine", step 2: "a later request (`<path>?<sid>.<n>`)", whose `sid` "must be known". It is looked up only for a `POST` to a `fronted` path of this listener whose head passed step 1.
			Err(Stranger::Proof) if framed && trusted => (Line::parse(line).filter(|line| line.method == Method::Post).and_then(|line| {
				let paths: Vec<&[u8]> = served.routes.iter().map(|route| route.path.as_bytes()).collect();
				let (route, (sid, number)) = (&served.routes[line.path_among(&paths)?], fronted::later(line.query?)?);
				let polling = listener.polling().get(&sid).cloned()?;
				(route.over == Over::Fronted && polling.route == route.id).then_some(Err((polling, number)))
			}), Stranger::Proof),
			Err(why) => (None, why),
		};
		let (mut place, mut shaped_why) = (None, None);
		if let Some((index, ask)) = shaped_ask {
			let total = end + match request.body {
				Some(Framing::Length(length)) if served.routes[index].shape.as_ref().is_some_and(|shape| shape.bodied()) => length as usize,
				_ => 0,
			};
			match shaped::serve(&shared, &listener, &served, way, &mut from_proxy, &mut to_proxy, &mut buf, &mut filled, &mut eof, end, total, request.line, source, &served.routes[index], ask).await {
				// "A request that is answered: the node returns to step 1."
				Poll::Answered => {
					kept = None;
					buf.copy_within(total..filled, 0);
					filled -= total;
					continue;
				}
				Poll::Lost => return,
				Poll::Stranger(reason, waiting) => (shaped_why, place) = (Some(reason), waiting),
			}
		}
		if let (Some(asked), Some(Framing::Length(length))) = (asked, request.body) {
			let total = end + length as usize;
			match poll(&shared, &listener, &served, way, &mut from_proxy, &mut to_proxy, &mut buf, &mut filled, &mut eof, end, total, source, asked).await {
				// "A `fronted` request is handled as `fronted` says, and the node returns to step 1."
				Poll::Answered => {
					kept = None;
					buf.copy_within(total..filled, 0);
					filled -= total;
					continue;
				}
				Poll::Lost => return,
				Poll::Stranger(reason, waiting) => (why, place) = (reason, waiting),
			}
		}
		// 5. "Not a user. Forward this request to a connection to the decoy origin and relay its response, then return to step 1."
		let why = shaped_why.unwrap_or(why);
		listener.counters.strangers[why as usize].fetch_add(1, Ordering::Relaxed);
		match forward(&listener, &served, way, &mut from_proxy, &mut to_proxy, &mut buf, &mut filled, &mut eof, end, request, kept.take(), source, local, place).await {
			Handed::Next(origin) => kept = origin,
			Handed::Close => {
				let _ = timeout(CLOSE_WAIT, to_proxy.shutdown()).await;
				return;
			}
			Handed::Reset => return from_proxy.unsplit(to_proxy).reset(),
			Handed::Cut => return,
		}
	}
}

/// How a request that was handed to the decoy origin left its proxy connection.
enum Handed {
	/// The answer is complete and the proxy keeps its connection. The origin's stays with the proxy connection for its next request, unless the origin ended it behind the answer.
	Next(Option<Kept>),
	/// The origin closed its connection, or the node no longer knows where a request begins: the proxy's is closed, once all of the answer was handed on.
	Close,
	/// The origin reset its connection, and the proxy's is reset.
	Reset,
	/// The proxy's connection broke, or was closed to make room: it is dropped as it is.
	Cut,
}

/// How the request side of a forwarded request ended.
enum Up {
	/// The whole request is with the origin and its answer is complete.
	Whole,
	/// The proxy closed its side, and the origin was told so.
	Shut,
	/// The origin takes no more of what the proxy sends.
	Unsent,
	Broken,
}

/// How the answer side of a forwarded request ended.
enum Down {
	/// The origin closed its connection, with everything it sent handed on.
	Closed,
	/// The answer is complete and nothing behind it on this connection can be told apart.
	Finished,
	/// The answer is complete, the request was whole, and the origin then said something or ended its connection: its connection is dropped and the proxy's goes on.
	Dropped,
	Reset,
	Broken,
}

/// Hands one request of a proxy connection to the decoy origin, and the origin's answer back (step 5 of the proxy path). This is HTTP forwarding with nothing written by the node: the head goes to the origin byte for byte as it was read, the body behind it as far as its framing says, and the answer comes back as the origin sent it, to where its framing says it ends.
/// "Forwarding uses an existing HTTP/1.1 implementation. Header fields are passed in order, except hop-by-hop fields" is not followed: an implementation that parses a head and writes it again changes it (case, order, blanks, folded lines), and what a stranger gets would then be the node's reading of its request and not the request. The proxy in front and the origin behind both speak HTTP/1.1 to each other, so the hop-by-hop fields the proxy wrote for its upstream are the origin's to read.
/// "A request with both `Content-Length` and `Transfer-Encoding`, with more than one `Content-Length`, with a `Transfer-Encoding` other than exactly `chunked`, or that the implementation refuses, closes both connections with no response" is not followed either: the origin answers such a request itself, and a proxy that got no answer where the site gives a `400` would show the node.
/// Such a request, and every other the node cannot tell the end of (`http::request`), is relayed as the bytes it is, with everything the proxy sends behind it, to the end of the origin's answer, and then the proxy's connection is closed: the node never guesses where the next request starts, so it cannot disagree with the origin about it.
/// `end` is how many bytes of `buf` are the head, `kept` the connection to the origin this proxy connection kept from its last request, and `place` the request's place among those that wait, when it has one already. One source has only so many of those, and so have all strangers together (`Front::waiting`).
#[allow(clippy::too_many_arguments)]
async fn forward(listener: &Arc<Listener>, served: &Served, way: &Front, from_proxy: &mut ReadHalf<Stream>, to_proxy: &mut WriteHalf<Stream>, buf: &mut [u8], filled: &mut usize, eof: &mut bool, end: usize, request: http::Request, kept: Option<Kept>, source: IpAddr, local: SocketAddr, place: Option<Place>) -> Handed {
	let place = place.unwrap_or_else(|| enter(listener, Listener::decoys, Source::of(source), way.waiting(), way.per_source));
	listener.counters.count(Count::Forwarded);
	// "On the proxy path it carries the source taken from the forwarded-address header": a connection to the origin has named one address, so with `proxy_protocol` it carries the requests of that address only. The header has no port of the visitor's, and the PROXY protocol header says 0 for it.
	let (mut origin, mut relay, mut first) = (kept.filter(|kept| !served.proxy || kept.source == source).map(|kept| (kept.read, kept.write)), vec![0u8; RELAY_BUFFER], 0);
	// A connection that was kept may have been closed by the origin a moment ago, with the word of it still on its way: a web server in front would send its request once more on a new one, and so does the node, once.
	// It can only do so for a request that is whole in the buffer, which is tried on the kept connection without being taken out of it. Nothing back, or the end of the connection, and the request goes to a new connection as if the old one had never been.
	let entire = origin.as_ref().and(request.body).and_then(|framing| http::Body::new(framing).feed(&buf[end..*filled]).ok()).filter(|(_, complete)| *complete).map(|(taken, _)| end + taken);
	if let (Some((from, to)), Some(entire)) = (origin.as_mut(), entire) {
		let heard = tokio::select! {
			biased;
			_ = place.bump.notified() => return listener.cut(),
			heard = async {
				to.write_all(&buf[..entire]).await?;
				from.read(&mut relay).await
			} => heard,
		};
		match heard {
			Ok(read) if read > 0 => first = read,
			_ => {
				listener.counters.count(Count::Redialed);
				origin = None;
			}
		}
	}
	// `sent` says the whole request is with the origin already, and `first` how much of its answer was read.
	let (sent, taken) = (first > 0, if first > 0 {entire.unwrap_or(end)} else {end});
	let (mut from_origin, mut to_origin) = match origin {
		Some(origin) => origin,
		None => {
			let dialed = tokio::select! {
				biased;
				_ = place.bump.notified() => return listener.cut(),
				dialed = served.origin.dial(if served.proxy {Proxy::Peer(SocketAddr::new(source, 0), local)} else {Proxy::None}) => dialed,
			};
			// "If the origin cannot be reached, the proxy connection is closed with no response, counted as `decoy_down`. The front then gives the visitor its own error, as it would if the site were down."
			let Ok(origin) = dialed else {
				listener.counters.count(Count::DecoyDown);
				listener.decoy(false);
				return Handed::Close;
			};
			listener.decoy(true);
			tokio::io::split(origin)
		}
	};
	// `blind` says the node no longer tells requests apart on this connection, `whole` that all of the request is with the origin, `done` that its answer is complete, and `shut` that the origin was told the proxy closed its side. Each side of the exchange wakes the other when it changes one.
	let (blind, whole, done, shut, turned) = (AtomicBool::new(request.body.is_none()), AtomicBool::new(sent), AtomicBool::new(false), AtomicBool::new(false), Notify::new());
	let (get, set) = (|flag: &AtomicBool| flag.load(Ordering::Relaxed), |flag: &AtomicBool| flag.store(true, Ordering::Relaxed));
	if get(&blind) {listener.counters.count(Count::Unframed)}
	let ended = {
		let up = async {
			let mut body = http::Body::new(request.body.unwrap_or(Framing::Close));
			// `head` is how many bytes at the start of the buffer are the head and still to be written. It goes out in one write with whatever of the body came with it: an origin that reads a head and what follows it at once must not get the two apart because the node stood between. HAProxy answers a head with two framings one way when its body is there and another way when it is not.
			let mut head = if sent {0} else {end};
			if sent {
				buf.copy_within(taken..*filled, 0);
				*filled -= taken;
			}
			loop {
				// How much of what was read belongs to this request: all of it once the node no longer tells, and else what the framing of the body says.
				let take = head + if get(&blind) {*filled - head} else if get(&whole) {0} else {
					match body.feed(&buf[head..*filled]) {
						Ok((taken, complete)) => {
							whole.store(complete, Ordering::Relaxed);
							taken
						}
						Err(_) => {
							listener.counters.count(Count::Unframed);
							set(&blind);
							*filled - head
						}
					}
				};
				if take > 0 {
					if to_origin.write_all(&buf[..take]).await.is_err() {return Up::Unsent}
					buf.copy_within(take..*filled, 0);
					(*filled, head) = (*filled - take, 0);
				}
				if get(&whole) && get(&done) && !get(&blind) {return Up::Whole}
				// A proxy that closed its side has closed it for the origin once nothing it sent is left that the origin has not got. Requests it sent behind this one are still to be read, and are answered first.
				if *eof && (get(&blind) || !get(&whole) || *filled == 0) {
					let _ = to_origin.shutdown().await;
					set(&shut);
					return Up::Shut;
				}
				// With the request whole, the proxy is still read for as far as the buffer goes, so that its close is seen while the origin takes its time: what comes is its next request, which stays where it is.
				if *eof || *filled == buf.len() {
					turned.notified().await;
					continue;
				}
				tokio::select! {
					_ = turned.notified() => {}
					read = from_proxy.read(&mut buf[*filled..]) => match read {
						Ok(read) if read > 0 => *filled += read,
						Ok(_) => *eof = true,
						Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => *eof = true,
						Err(_) => return Up::Broken,
					},
				}
			}
		};
		let down = async {
			let (mut answer, mut open, mut read) = (http::Response::new(request.bodiless, request.tunnel), false, first);
			loop {
				if read == 0 {
					read = match from_origin.read(&mut relay).await {
						Ok(read) if read > 0 => read,
						// With the request whole and its answer complete, the exchange is over and the origin has no request in its hands: what it does then is not passed on, whichever of the two is seen first here, that or the end of the exchange.
						_ if get(&done) && get(&whole) => return Down::Dropped,
						Ok(_) => return Down::Closed,
						Err(e) => return if e.kind() == io::ErrorKind::ConnectionReset {Down::Reset} else {Down::Closed},
					};
				}
				// Bytes behind a complete answer are no answer to anything the proxy asked: they are what the origin made of a body, or of a request the node could not tell the end of. The proxy never gets them, on a connection its next request may be a user's on. While the request is still being sent, both connections end here.
				if get(&done) {return if get(&whole) {Down::Dropped} else {Down::Finished}}
				let said = if open {Answer::Open} else {answer.feed(&relay[..read])};
				let give = if let Answer::Done(used) = said {used} else {read};
				// "Every byte the origin sent is written out to the peer before the node waits for anything else": every byte of the answer, and none behind its last.
				if to_proxy.write_all(&relay[..give]).await.is_err() || to_proxy.flush().await.is_err() {return Down::Broken}
				match said {
					Answer::More => {}
					// The end of the first answer ends the exchange when the node no longer tells requests apart, when the proxy closed its side, when the origin sent more than the answer, and when the origin said the answer is its last (`Connection: close`), so that the proxy's connection is closed with the answer and not a moment later by chance.
					Answer::Done(used) if used < read || answer.last() || get(&blind) || get(&shut) => return Down::Finished,
					Answer::Done(_) => {
						set(&done);
						turned.notify_one();
					}
					// The connection itself is the answer, to where the origin ends it.
					Answer::Open => {
						open = true;
						set(&blind);
						turned.notify_one();
					}
				}
				read = 0;
			}
		};
		tokio::pin!(up, down);
		tokio::select! {
			biased;
			_ = place.bump.notified() => None,
			down = &mut down => Some(Ok(down)),
			up = &mut up => match up {
				Up::Whole => Some(Err(true)),
				Up::Broken => Some(Err(false)),
				// The origin's answer is still handed on, to its end.
				Up::Shut | Up::Unsent => if get(&done) {Some(Ok(Down::Finished))} else {
					tokio::select! {
						biased;
						_ = place.bump.notified() => None,
						down = &mut down => Some(Ok(down)),
					}
				},
			},
		}
	};
	match ended {
		None => listener.cut(),
		Some(Err(true)) => Handed::Next(Some(Kept {read: from_origin, write: to_origin, source})),
		Some(Ok(Down::Dropped)) => {
			listener.counters.count(Count::OriginDropped);
			Handed::Next(None)
		}
		Some(Err(false)) | Some(Ok(Down::Broken)) => Handed::Cut,
		Some(Ok(Down::Reset)) => Handed::Reset,
		Some(Ok(Down::Closed | Down::Finished)) => Handed::Close,
	}
}

/// What became of a `fronted` request.
enum Poll {
	/// It was answered: `200` with what the node had for the device.
	Answered,
	/// It takes the unauthenticated path, for this reason, with its place among the requests that wait if it has one. Whatever was read of it is where it was read to.
	Stranger(Stranger, Option<Place>),
	/// The proxy's connection is gone.
	Lost,
}

/// One `fronted` request that passed steps 1 to 4 of its state machine as far as its head goes (transports page, "`fronted`", "State machine"): the opening request of a proof that was just accepted, which makes the session here, or a later request that names a session of this listener, with its number.
/// From step 5 on: the body is read whole into `buf` behind the head, up to `total` bytes in all, and nothing of the session is looked at or touched until all of it is there. Then, with the session held and nothing waited for: a repeat is known by its bytes, and anything else must open chunk by chunk at the expected numbers.
/// "If any chunk does not open, nothing of the body is processed. For a later request the session stays as it was, so a stranger who learns a `sid` cannot disturb it." The only things a request that proves nothing touches are its own connection and its own place among the requests that wait, which is what bounds how many bodies can be read at once for somebody who learnt a `sid`.
/// "Request `n` + 1 that arrives while request `n` is still held is not queued: it takes the unauthenticated path." A request is in flight from the moment its chunks opened to the moment its answer is stored, and no longer.
#[allow(clippy::too_many_arguments)]
async fn poll(shared: &Arc<Shared>, listener: &Arc<Listener>, served: &Served, way: &Front, from_proxy: &mut ReadHalf<Stream>, to_proxy: &mut WriteHalf<Stream>, buf: &mut Vec<u8>, filled: &mut usize, eof: &mut bool, end: usize, total: usize, source: IpAddr, asked: Result<Accepted, (Arc<Polling>, u32)>) -> Poll {
	let (deadline, opening) = (Instant::now() + BODY_TIME, asked.is_ok());
	let (polling, number, place) = match asked {
		// 3. "An accepted proof is spent and creates a pending session, whatever happens next."
		Ok(accepted) => {
			let (route, id, (queue, waiting), seat) = (&served.routes[accepted.route], listener.ids.fetch_add(1, Ordering::Relaxed), mpsc::channel(SEND_QUEUE), accepted.seat);
			let Ok(padding) = Padding::new(accepted.wide, accepted.normal, &mut random) else {
				seat.end(Ended::Closed);
				return Poll::Stranger(Stranger::Body, None);
			};
			let polling = Arc::new(Polling {id, route: route.id, session: Arc::new(Session {seat: seat.clone(), over: route.over, queue, counters: listener.counters.clone()}), state: Mutex::new(Polled {turn: Some(Box::new(Turn {sealer: Sealer::new(accepted.keys.s2c, padding), handshakes: Handshakes::new(Clock::of((shared.now)()).ms), waiting, held: VecDeque::new(), lone: None})), opener: fronted::Opener::new(accepted.keys.c2s), number: 0, body: None, response: None})});
			listener.sessions().insert(id, (route.id, seat.clone()));
			// A session id is 16 bytes from the exporter of a fresh proof. Should one ever be a live session's, that session is left alone and the new one is nobody's.
			let taken = match listener.polling().entry(accepted.keys.sid) {
				Entry::Occupied(_) => true,
				Entry::Vacant(free) => {
					free.insert(polling.clone());
					false
				}
			};
			// A reload, or the end of the listener, between the request and now.
			if taken || listener.closed.load(Ordering::Acquire) || !listener.served().routes.iter().any(|kept| kept.id == route.id) {seat.end(Ended::Unserved)}
			if taken {
				listener.sessions().remove(&id);
				return Poll::Stranger(Stranger::Session, None);
			}
			(polling, 0, None)
		}
		// 4. "The `sid` must be known, no other request of that session may be in flight, and `n` must be one more than the last accepted, or equal to it for a repeat." Whoever sends this has proven nothing yet, so the session is only looked at: a request that cannot be the next one or the last one is not read any further.
		Err((polling, number)) => {
			let ordered = {
				let state = polling.state.lock().unwrap_or_else(|e| e.into_inner());
				!polling.session.seat.over() && state.turn.is_some() && (state.number.checked_add(1) == Some(number) || state.number == number)
			};
			if !ordered {return Poll::Stranger(Stranger::Session, None)}
			(polling, number, Some(enter(listener, Listener::decoys, Source::of(source), way.waiting(), way.per_source)))
		}
	};
	let seat = &polling.session.seat;
	// 5. "The node reads the whole body, which must arrive within 10 s, before it acts on any of it."
	if buf.len() < total {buf.resize(total, 0)}
	let arrived = loop {
		if *filled >= total {break true}
		if *eof {break false}
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
			// Only the opening request waits on its session: it is the one request the session has. A request that has proven nothing must not take the word meant for the one in flight.
			_ = seat.gone(), if opening => break false,
			read = from_proxy.read(&mut buf[*filled..]) => match read {
				Ok(read) if read > 0 => *filled += read,
				Ok(_) => *eof = true,
				Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => *eof = true,
				Err(_) => {
					if opening {
						seat.end(Ended::Closed);
						listener.forget(&polling);
					}
					return Poll::Lost;
				}
			},
			_ = sleep_until(deadline) => break false,
		}
	};
	// 6 to 8, with the session held and nothing waited for.
	let now = Clock::of((shared.now)());
	let verdict = if !arrived {Err(Stranger::Body)} else {
		let (mut state, mut scratch) = (polling.state.lock().unwrap_or_else(|e| e.into_inner()), Vec::new());
		let (Polled {turn, opener, number: last, body: stored, response}, body) = (&mut *state, &buf[end..total]);
		if seat.over() || turn.is_none() {Err(Stranger::Session)} else if number > 0 && number == *last {
			// 8. "A repeat of the last accepted request with the same body gets the stored response again, because a CDN may retry." It is known by its bytes, before anything is opened: a body that was accepted does not open a second time.
			response.clone().filter(|_| stored.is_some_and(|(length, hash)| length == body.len() && hash.as_slice() == digest(&SHA256, body).as_ref())).map(Ok).ok_or(Stranger::Body)
		} else if !opening && last.checked_add(1) != Some(number) {Err(Stranger::Session)} else {
			// 6. "Every chunk of the body must open under `k_c2s` at the expected chunk numbers. Chunk numbers advance only when the request is accepted."
			match opener.open(body, &mut scratch) {
				Ok(opened) => {
					let datagrams: Vec<Vec<u8>> = opened.commit().into_iter().flatten().map(<[u8]>::to_vec).collect();
					(*last, *response, *stored) = (number, None, (!opening).then(|| (body.len(), <[u8; 32]>::try_from(digest(&SHA256, body).as_ref()).unwrap_or_default())));
					// "A session is active at a moment when the receiver accepts from it a chunk that cannot be a replay": on `fronted`, "an accepted request".
					seat.active.store(now.ms, Ordering::Relaxed);
					turn.take().map(|turn| Err((turn, datagrams))).ok_or(Stranger::Session)
				}
				Err(BodyError::Refused) => Err(Stranger::Body),
				// 7. "A chunk that is invalid, in a body whose every chunk opened, came from the session's client. The session is ended and the request takes the unauthenticated path."
				Err(BodyError::Ended(_)) => {
					seat.end(Ended::Invalid);
					Err(Stranger::Body)
				}
			}
		}
	};
	let (turn, datagrams) = match verdict {
		Err(why) => {
			// "For an opening request the pending session is dropped at once."
			if opening {
				seat.end(Ended::Invalid);
				listener.forget(&polling);
			}
			return Poll::Stranger(why, place);
		}
		Ok(Ok(response)) => {
			drop(place);
			listener.counters.count(Count::Repeats);
			return if to_proxy.write_all(&response).await.is_ok() && to_proxy.flush().await.is_ok() {Poll::Answered} else {Poll::Lost};
		}
		Ok(Err(accepted)) => accepted,
	};
	// The request is the session's own from here on, and the one in flight. Its turn goes back to the session however this ends.
	drop(place);
	listener.counters.count(Count::Polls);
	let (mut flight, mut net, mut ip) = (Flight {polling: &polling, turn: Some(turn)}, Vec::new(), Vec::new());
	let Some(turn) = flight.turn.as_deref_mut() else {return Poll::Lost};
	for datagram in &datagrams {take(shared, listener, served, &polling.session, &turn.handshakes, SocketAddr::new(source, 0), now, datagram, &mut net, &mut ip);}
	if !ip.is_empty() {
		let plan = shared.plan();
		if let Some(at) = plan.inbound_of(&seat.tunnel) {
			for packet in ip.drain(..) {shared.ingress(&plan, at, seat.device, packet).await}
		}
	}
	// "Its first answer on a new session comes when the session is established, as on every transport", and "the node sends nothing on a pending session". A session that is pending has this one request and can get no other while it is held, so it waits for the first tunnel packet deadline, and is then nobody's.
	if seat.pending() {
		seat.gone().await;
		listener.forget(&polling);
		return Poll::Stranger(Stranger::Unestablished, None);
	}
	// 9. "The node answers an accepted request as soon as it has downstream data for the session, and otherwise after the hold time, with status 200." What WireGuard answers to the request goes first.
	for datagram in net.drain(..).rev() {turn.held.push_front((datagram, false))}
	let hold = Instant::now() + HOLD;
	let withheld = loop {
		while turn.held.len() < MAX_ITEMS {
			let Ok(next) = turn.waiting.try_recv() else {break};
			turn.held.push_back(next);
		}
		// "A chunk that would hold exactly one WireGuard keepalive is held back for the lone keepalive delay and joins whatever else is sent in that time."
		let lone = turn.held.len() == 1 && turn.held[0].0.len() == 32 && turn.held[0].0[0] == 4;
		if !lone {turn.lone = None} else if turn.lone.is_none() {turn.lone = Some(Instant::now() + session::delay(&LONE_KEEPALIVE, &mut random).unwrap_or_default())}
		let withheld = turn.lone.is_some_and(|until| until > Instant::now());
		if seat.over() || Instant::now() >= hold || (!turn.held.is_empty() && !withheld) {break withheld}
		tokio::select! {
			_ = seat.gone() => {}
			Some(next) = turn.waiting.recv() => turn.held.push_back(next),
			_ = sleep_until(turn.lone.map_or(hold, |until| until.min(hold))) => {}
		}
	};
	// "The sender puts every datagram that is waiting at the moment it writes into one chunk, up to the limit, and never waits for more." What does not fit this body waits for the next request.
	let mut body = Vec::new();
	while !withheld && !turn.held.is_empty() {
		let (mut count, mut size) = (0, 0);
		while count < turn.held.len().min(MAX_ITEMS) && size + 2 + turn.held[count].0.len() <= MAX_PLAINTEXT {
			size += 2 + turn.held[count].0.len();
			count += 1;
		}
		let (items, wide): (Vec<&[u8]>, bool) = (turn.held.iter().take(count).map(|(datagram, _)| datagram.as_slice()).collect(), turn.held.iter().take(count).any(|(datagram, wide)| *wide || matches!(datagram.first(), Some(1 | 2))));
		match fronted::append(&mut turn.sealer, &items, wide, &mut random, &mut body) {
			Ok(()) => listener.counters.count(Count::Chunks),
			Err(ChunkError::Size) if !body.is_empty() => break,
			// "A sender closes the session before it would send chunk number 2^60."
			Err(ChunkError::Number) => seat.end(Ended::Packets),
			Err(_) => {}
		}
		turn.held.drain(..count.max(1));
	}
	// "A request or response with nothing to carry holds one padding-only chunk, so no body is ever empty."
	if body.is_empty() {
		if fronted::append(&mut turn.sealer, &[], false, &mut random, &mut body).is_err() {
			seat.end(Ended::Packets);
			return Poll::Stranger(Stranger::Body, None);
		}
		listener.counters.count(Count::Chunks);
	}
	// "The node stores one response per session, for the repeat": stored before it is written, so a repeat of a request whose answer never reached the front is answered too.
	let response = Arc::new([POLLED.as_bytes(), body.len().to_string().as_bytes(), b"\r\n\r\n", &body].concat());
	{
		let mut state = polling.state.lock().unwrap_or_else(|e| e.into_inner());
		(state.response, state.turn) = (Some(response.clone()), flight.turn.take());
	}
	if to_proxy.write_all(&response).await.is_ok() && to_proxy.flush().await.is_ok() {Poll::Answered} else {Poll::Lost}
}

/// Gives the turn of a `fronted` session back when the request that took it is over, however it ended.
struct Flight<'a> {polling: &'a Polling, turn: Option<Box<Turn>>}

impl Drop for Flight<'_> {
	fn drop(&mut self) {
		if let Some(turn) = self.turn.take() {self.polling.state.lock().unwrap_or_else(|e| e.into_inner()).turn = Some(turn)}
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
			// A listener whose upgrade answers take nothing from the origin asks it nothing: "The default list is empty on a `ws` listener", and a `fronted` transport has no upgrade answer.
			if !served.routes.iter().flat_map(|route| &route.headers).any(|name| !name.eq_ignore_ascii_case("date")) {
				failing = false;
				continue;
			}
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
	/// A node on `document`, a config whose first inbound is a `veilway` inbound with `tls` transports, or with `ws` and `fronted` ones, whose one listener reads plain HTTP from pipes in memory. `pools` are the listener's and `now` is the node's clock. The pools of the proxy path are the document's.
	pub fn new(document: &str, pools: Pools, now: fn() -> OffsetDateTime) -> anyhow::Result<Bench> {
		let config = Config::parse(document.as_bytes()).map_err(|e| anyhow::anyhow!("{e}"))?;
		let inbound = config.inbounds.first().ok_or_else(|| anyhow::anyhow!("no inbound"))?;
		let (to_stack, _) = mpsc::channel(1);
		let tunnel = Arc::new(Tunnel::new(inbound.tag.clone(), Peers {wg: Wg::new(inbound.private_key.expose().0), via: Vec::new()}, to_stack));
		let plan = Plan::new(&config, now(), &Plan::default(), vec![tunnel.clone()])?;
		for device in &plan.devices {tunnel.lock().add(device.public_key, device.preshared_key)}
		let shared = Arc::new(Shared::new(plan, super::gate::is_local, now, None, None, veilway_proto::control::USAGE_PUSH, Arc::new(rustls::RootCertStore::empty())));
		let _ = shared.replay.set(Arc::new(Guard::unwritten(config.replay.cache(), super::replay::seconds(now()))));
		let ((origin, origins), cookie) = (mpsc::unbounded_channel(), inbound.upgrade_cookie.clone().unwrap_or_default());
		let routes: Vec<Route> = inbound.transports.iter().filter_map(|transport| match transport {
			crate::config::Transport::Tls {path, ..} => Some(Route::tls(path.clone(), tunnel.clone(), cookie.clone(), inbound.upgrade_headers(true))),
			crate::config::Transport::WsNative {path, ..} => Some(Route::ws(path.clone(), tunnel.clone(), cookie.clone(), inbound.upgrade_headers(false))),
			crate::config::Transport::WsPlain {path, transport_keys, ..} => Some(Route::ws_plain(path.clone(), tunnel.clone(), cookie.clone(), inbound.upgrade_headers(false), transport_keys.iter().map(|key| key.0).collect())),
			crate::config::Transport::Fronted {path, ..} => Some(Route::fronted(path.clone(), tunnel.clone())),
			crate::config::Transport::FrontedShaped {path, shape, ..} => shape.resolve().ok().map(|shape| Route::fronted_shaped(path.clone(), tunnel.clone(), Arc::new(shape))),
			_ => None,
		}).collect();
		anyhow::ensure!(!routes.is_empty(), "no stream transport");
		let front = inbound.transports.iter().find_map(|transport| transport.proxied()).map(|proxied| Front::of(proxied.trusted.iter().map(|proxy| proxy.0).collect(), proxied.header.map(str::to_string), proxied.limits, inbound.transports.iter().any(|other| other.proxied().is_some_and(|other| other.shape.is_some_and(|shape| shape.down.mode == crate::config::ShapeMode::Sse)))));
		let listener = shared.stream.listen(SocketAddr::from(([127, 0, 0, 1], 443)), Served {acceptor: None, routes, origin: Origin::Memory(origin), proxy: false, host: String::new(), pools, front, h2: false});
		Ok(Bench {shared, listener, origins})
	}

	/// A connection of a trusted proxy at `peer`, as the accept of a `ws` or `fronted` listener takes it. None when the proxy pool has no place for it, where a listener leaves the connection in the system's queue.
	pub fn proxy(&self, peer: SocketAddr) -> Option<(DuplexStream, JoinHandle<()>)> {
		let ((ours, theirs), seat, room) = (tokio::io::duplex(RELAY_BUFFER), self.listener.proxies.clone().try_acquire_owned().ok()?, self.listener.room.clone().try_acquire_owned().ok()?);
		self.listener.counters.count(Count::Accepted);
		self.listener.counters.count(Count::Proxied);
		Some((theirs, tokio::spawn(front(self.shared.clone(), self.listener.clone(), Box::new(ours), peer, self.listener.addr, self.listener.lease(seat), room))))
	}

	/// A connection of a direct peer at `peer`, as the listener's accept takes it: the peer's end of it, and the task that serves it.
	pub fn connect(&self, peer: SocketAddr) -> (DuplexStream, JoinHandle<()>) {
		let ((ours, theirs), served) = (tokio::io::duplex(RELAY_BUFFER), self.listener.served());
		let (place, user) = (enter(&self.listener, Listener::undecided, Source::of(peer.ip()), served.pools.undecided, served.pools.per_source), served.front.is_none());
		self.listener.counters.count(Count::Accepted);
		(theirs, tokio::spawn(conn(self.shared.clone(), self.listener.clone(), served, Box::new(ours), peer, self.listener.addr, user, place)))
	}

	/// The next connection the node opened to the origin, when there is one.
	pub fn origin(&mut self) -> Option<DuplexStream> {self.origins.try_recv().ok()}

	/// What the node's timers do once a second: sessions whose time is over end, and the limit of the replay memory follows the clock and what proofs asked for, with every write going through.
	pub fn tick(&self) {
		let clock = Clock::of((self.shared.now)());
		self.shared.limits.sweep(clock);
		self.shared.stream.sweep();
		if let Some(replay) = self.shared.replay.get() {replay.serve(clock.secs)}
	}

	pub fn totals(&self) -> StreamTotals {self.shared.stream.totals()}
}
