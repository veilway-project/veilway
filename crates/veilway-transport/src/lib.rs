//! The client's side of the native transports (transports page of the protocol): `udp-obfs`, `tls`, `ws`, `ws-plain`, `fronted` and `faketls`, behind one `Session`.
//!
//! A session carries WireGuard datagrams between a device and a node and nothing else. There is no WireGuard here, no TUN device, no routing, no DNS and no control channel: the caller hands datagrams in with `Session::send` and takes them out with `Session::recv`.
//! Two things only the WireGuard layer can make are asked of it through `Source`: the datagram a session opens with ("a handshake initiation, or a keepalive of a tunnel that is already up") and the idle keepalive. The rekey point of the transports page is the WireGuard layer's own business and is not here.
//!
//! Everything fails closed. An error ends the session and `recv` gives it as an `Ended`: nothing is sent outside a session, there is no retry without a proof, and no check is loosened after a failure. A certificate that does not validate, or does not match a pin where the candidate has one, ends the attempt, and there is no switch that turns a check off. A certificate that signed itself is refused with its pin, unless the signed profile marks the candidate `self_signed`: then the pin alone is the check and the handshake must be signed with the pinned key (see `tls`). Nothing the server sends puts a candidate on that path.
//!
//! How an attempt ended is what the caller's next step hangs on, so it is told by who could have caused it. A refusal is what the TLS session vouches for: an answer that is no session, or a close in order. A connection that is reset or ends without one is unreachable, since anyone on the path can do that. A fault of the device itself (no route, no socket, a socket hook that failed, a clock outside the certificate's validity) is told apart from both and held against no candidate. A proof that was taken and followed by silence, on a session that opened with a keepalive, is a node that no longer knows the tunnel: `End::Unanswered`, after which the caller's `Source` must give a handshake initiation.
//! Every socket is the crate's own, and the caller has each one before it is connected (`Env::socket`), to keep it out of its tunnel and to let its firewall know it.
//!
//! What is not here, and must not be read into it:
//! - The TLS ClientHello is the one of `rustls`. It does not look like a browser's and is recognisable as this library's, and it offers `http/1.1` alone. The transports page plans a browser's TLS library configured from a fingerprint pack ("Client TLS and HTTP fingerprint"), which waits for a measurement and is not built. The header fields of the requests are a fixed short list for the same reason.
//! - Encrypted Client Hello is not built: a candidate with `ech` is refused before anything is dialled, since dialling it without would show the name the profile meant to hide.
//! - The appearance layer of `ws-plain` is not built. Plain `udp` is WireGuard itself and needs no transport. `ws-plain` has no TLS: no certificate, no pin and no server name, and a session is open only when a chunk of the node has opened.
//! - Which candidate and which transport come next, and after which wait, is decided by the functions of `choice` over state the caller keeps. Nothing here stores anything.
//!
//! Every byte from the network is hostile: a node, a front and the path are all in the threat model. Heads, frames and bodies are read inside fixed bounds of size and time, nothing is allocated by a length the peer chose, and no error holds a byte of input.
#![deny(unsafe_code)]

pub mod choice;
pub mod faketls;
mod fingerprint;
mod fronted;
mod h2;
#[cfg(test)]
mod hello_test;
pub mod http;
pub mod mlkem;
mod parallel;
pub mod probe;
mod shaped;
pub mod stream;
mod tls;
pub use tls::pin_only;
pub mod udp;

use ring::rand::{SecureRandom, SystemRandom};
use rustls::RootCertStore;
use socket2::SockRef;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use veilway_proto::chunk::{self, MAX_ITEM, MIN_ITEM};
use veilway_proto::faketls::Client as FakeTlsClient;
use veilway_proto::proof::Name;
use veilway_proto::shape::Shape;
use veilway_proto::subscription::payload::{Candidate, Http2, Padding, Profile, Transport};
use veilway_proto::subscription::Secret;
use veilway_proto::{session, NoRandom};

/// "Stream send queue: 256 datagrams per connection." A datagram that finds it full is dropped and counted, on every transport.
pub const QUEUE: usize = 256;
/// What an attempt gets to carry a chunk from the node: "10 s per transport" of transport fallback and "10 s each" of the candidate attempts. Connecting, TLS and the answer to the request share it.
pub const ATTEMPT: Duration = Duration::from_secs(10);
// How many datagrams wait for a caller that does not read. Beyond it they are dropped and counted, so that a slow reader costs the tunnel packets and not the session its timers.
const INBOX: usize = 1024;

/// A clock in Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// What a caller does to every socket of a session after it is made and before it is connected, for TCP and UDP alike: keep it out of its own tunnel, bind it to an interface, mark it for its firewall. A failure ends the attempt as `End::Offline`, and nothing is dialled.
pub type Hook = Arc<dyn Fn(SockRef<'_>) -> std::io::Result<()> + Send + Sync>;

/// Dials one address on the caller's behalf, through a proxy chain, before the deadline of the attempt: the stream a TCP transport of a link with a `via` runs over. It replaces the socket and its hook. What it fails with is the caller's classification of the failure: `End::Offline` where the node's own path failed, `Unreachable::Connect` where a candidate or a proxy after the first refused, and `Unreachable::Timeout` where the destination did not answer in time.
pub type Connect = Arc<dyn Fn(SocketAddr, Instant) -> Pin<Box<dyn Future<Output = Result<TcpStream, Ended>> + Send>> + Send + Sync>;

/// A `Connect` from a function that dials one address before a deadline.
pub fn connector<F: Future<Output = Result<TcpStream, Ended>> + Send + 'static>(dial: impl Fn(SocketAddr, Instant) -> F + Send + Sync + 'static) -> Connect {Arc::new(move |to, deadline| Box::pin(dial(to, deadline)))}

/// What a session asks of the WireGuard layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
	/// The datagram a session opens with: a keepalive of a tunnel that is already up, or else a fresh handshake initiation. It is asked again for every opening packet of `udp-obfs`, which wants "a fresh WireGuard datagram of the same kind". While two candidates are raced the caller gives both the same one. It is asked once for a stream session, before anything is dialled. After a session ended as `End::Unanswered` the node does not know the tunnel, and what is given must be a handshake initiation.
	First,
	/// One keepalive of the tunnel, for the idle keepalive. None while the tunnel has no session to send under.
	Keepalive,
}

/// The WireGuard layer as a session needs it. None ends a session that cannot open without the datagram, and skips an idle keepalive.
pub type Source = Arc<Mutex<dyn FnMut(Want) -> Option<Vec<u8>> + Send>>;

/// What the sessions of one profile share. `now` is per profile and must not be shared between profiles: an offset one node's `Date` gave would move the proofs sent to another.
#[derive(Clone)]
pub struct Env {
	/// The device's clock as it is, with no offset. A clock offset is measured against it at the moment an answer's head is read.
	pub device: Clock,
	/// The clock proofs and opening packets are made with: `choice::clock` over this profile's `Standing`, which is the device's clock and the offset when one is held.
	pub now: Clock,
	/// The certificates a TLS chain must lead to: the platform's, or a list the caller ships. An empty store refuses every stream target before anything is dialled. Certificate validity is checked against the system's clock by the TLS library, never against `now`.
	pub roots: Arc<RootCertStore>,
	pub socket: Option<Hook>,
}

/// What a device holds for one inbound of a node: the fields of a profile every transport of it shares.
#[derive(Clone)]
pub struct Link {
	/// `inbound_pub`, the inbound's WireGuard public key.
	pub inbound: [u8; 32],
	/// `device_pub`, the device's WireGuard public key.
	pub device: [u8; 32],
	/// The device transport secret: "The client uses the first."
	pub secret: Secret<32>,
	/// The node transport public key, which `tls`, `ws` and `fronted` seal their proofs to. A `faketls` transport has its own, and never uses this one.
	pub node: Option<[u8; 32]>,
	pub mtu: u16,
	pub padding: Padding,
	/// The `faketls` clients of this link, one for each key of a `faketls` transport (`faketls::client`), shared by every clone of the link.
	pub borrowed: faketls::Clients,
}

impl Link {
	pub fn of(profile: &Profile) -> Option<Self> {Some(Self {inbound: profile.inbound_public_key, device: profile.device.public_key, secret: profile.device.transport_secrets.first()?.clone(), node: profile.transport_public_key, mtu: profile.mtu, padding: profile.padding.clone(), borrowed: faketls::Clients::default()})}
}

impl fmt::Debug for Link {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Link(..)")}
}

/// A candidate of a stream transport as it is used ("Fronting options"): the address that is dialled as it is, the server name that is shown, the `Host` of the request, and what the certificate is held against. The three names are separate fields and are never derived from one another.
/// Whether an address may be dialled at all is decided before this: a profile is read into `Dial`, and the checks made at each connect (`Dial::own`, `Dial::private`) are the caller's.
#[derive(Clone)]
pub struct Front {
	pub address: SocketAddr,
	/// None: no server name is sent, and the certificate must be valid for `verify_name`.
	pub sni: Option<String>,
	pub host: String,
	pub verify_name: Option<String>,
	/// The SHA-256 of a SubjectPublicKeyInfo, each. With one or more the candidate is a pinned one.
	pub pins: Vec<[u8; 32]>,
	/// The candidate carries an Encrypted Client Hello configuration. Such a candidate is refused here.
	pub ech: bool,
	/// `self_signed` of the signed profile: the certificate is trusted through `pins` alone, with no chain, name or date checked. Only a `tls` candidate with pins and no `verify_name` may have it.
	pub self_signed: bool,
	/// `http2` of the candidate: whether the client offers `h2`, and whether `tls` and `ws` first try WebSocket over HTTP/2.
	pub http2: Http2,
	/// Set by `Target::via`: the TCP connection to `address` comes from this instead of a socket of the device's own.
	pub connect: Option<Connect>,
}

impl Front {
	pub fn of(candidate: &Candidate) -> Self {Self {address: candidate.address.address(), sni: candidate.sni.clone(), host: candidate.host.clone(), verify_name: candidate.verify_name.clone(), pins: candidate.pins.clone(), ech: candidate.ech.is_some(), self_signed: candidate.self_signed, http2: candidate.http2, connect: None}}
}

impl fmt::Debug for Front {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Front({} pins{})", self.pins.len(), if self.self_signed {", self-signed"} else {""})}
}

/// Where one session goes: one endpoint of a `udp-obfs` transport, or one candidate of a stream transport with the transport's path.
#[derive(Clone)]
pub enum Target {
	UdpObfs(SocketAddr),
	Tls {path: String, candidate: Front},
	Ws {path: String, candidate: Front},
	Fronted {path: String, candidate: Front},
	/// A `fronted` whose requests and answers are in the shape the profile names (shapes page).
	FrontedShaped {path: String, candidate: Front, shape: Shape},
	/// A `faketls` candidate: the real site's name in `sni`, and the one `Client` of the link for the transport's key (`faketls::client`), which every attempt and every connection to that key shares.
	FakeTls {candidate: Front, client: Arc<Mutex<FakeTlsClient>>},
	/// A `ws-plain` candidate: the `ws` session over plain HTTP, made with the transport's own `key`, and the token in the cookie named `cookie`.
	WsPlain {path: String, candidate: Front, key: [u8; 32], cookie: String},
}

impl Target {
	/// Makes a stream target dial through `connect` (a link whose `via` names a proxy chain). A UDP target is left as it is.
	pub fn via(mut self, connect: Option<Connect>) -> Self {
		if let (Some(connect), Self::Tls {candidate, ..} | Self::Ws {candidate, ..} | Self::WsPlain {candidate, ..} | Self::Fronted {candidate, ..} | Self::FrontedShaped {candidate, ..}) = (connect, &mut self) {candidate.connect = Some(connect)}
		self
	}
	/// Endpoint or candidate `at` of a transport of a profile, for `link`. None for plain `udp`, which is not served here, and for a place the transport does not have.
	/// A `faketls` target is made with the key of its own transport, and never with `Link::node`.
	pub fn of(transport: &Transport, at: usize, link: &Link) -> Option<Self> {
		Some(match transport {
			Transport::Udp(_) => return None,
			Transport::UdpObfs(endpoints) => Self::UdpObfs(endpoints.get(at)?.address()),
			Transport::Tls(stream) => Self::Tls {path: stream.path.clone(), candidate: Front::of(stream.candidates.get(at)?)},
			Transport::Ws(stream) => Self::Ws {path: stream.path.clone(), candidate: Front::of(stream.candidates.get(at)?)},
			Transport::WsPlain {key, cookie, stream} => Self::WsPlain {path: stream.path.clone(), candidate: Front::of(stream.candidates.get(at)?), key: *key, cookie: cookie.clone()},
			Transport::Fronted(stream) => Self::Fronted {path: stream.path.clone(), candidate: Front::of(stream.candidates.get(at)?)},
			Transport::FrontedShaped(stream, shape) => Self::FrontedShaped {path: stream.path.clone(), candidate: Front::of(stream.candidates.get(at)?), shape: shape.clone()},
			Transport::FakeTls {key, candidates} => {
				let found = candidates.get(at)?;
				Self::FakeTls {candidate: Front {address: found.address.address(), sni: Some(found.sni.clone()), host: String::new(), verify_name: None, pins: Vec::new(), ech: false, self_signed: false, http2: Default::default(), connect: None}, client: faketls::client(link, key)}
			}
		})
	}
	/// The transport's name, the one thing of a target a log line gets.
	pub fn name(&self) -> &'static str {
		match self {
			Self::UdpObfs(_) => "udp-obfs",
			Self::Tls {..} => "tls",
			Self::Ws {..} => "ws",
			Self::WsPlain {..} => "ws-plain",
			Self::Fronted {..} => "fronted",
			Self::FrontedShaped {..} => "fronted-shaped",
			Self::FakeTls {..} => "faketls",
		}
	}
}

impl fmt::Debug for Target {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Target({})", self.name())}
}

/// What the caller knows of a datagram and the transport cannot see. A WireGuard keepalive needs no mark: it is known by its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
	/// Tunnel traffic. `flow` is `flow` of the inner packet, which keeps "one inner flow on one connection and in order" when several are open. `control` says the inner packet is one of the control channel, which is padded wide.
	Packet {flow: u32, control: bool},
	/// A WireGuard handshake message, a rekey included: padded wide, and sent "on the connection that has been open longest".
	Handshake,
	/// A handshake initiation WireGuard's own timer made "because the node stopped answering". On `udp-obfs` it travels in an opening packet. On a stream it is a handshake message that wants a chunk back within the liveness limit, or the session is lost, and with several connections it goes on the one a chunk was last heard on.
	Stalled,
	/// An MTU probe of the control channel: sent as it is, with no padding, since a probe that left larger than it was made would confirm nothing.
	Probe,
}

/// Why a session is not, or is no longer, one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
	/// Over validated TLS the node or its front answered and it was not a session ("Refusals and clocks"). The candidate is reachable: it is not marked and spends no budget.
	Refused(Refusal),
	/// No connection, a TLS failure, a certificate that was not accepted, a timeout, or silence on `udp-obfs`.
	Unreachable(Unreachable),
	/// A session that was opened and is over, or one that could not be tried at all.
	Closed(End),
}

/// A refusal. The node never says why it refuses, so the class is what the client saw, and the causes (clock, quota, a restart, a rate limit, a removed device) cannot be told apart by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
	pub answer: Answer,
	/// The clock offset the answer's `Date` gives, in seconds: the `Date` less the device's clock at the moment the head was read. It is there "only after the certificate matched a pin from the profile" and never otherwise.
	/// Nothing bounds it: whoever holds a pinned key can name any time, and spoils with it the proofs this profile sends, to its own node, for the 24 h an offset is kept.
	pub offset: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
	/// An HTTP answer with a status that is not the expected one.
	Status(u16),
	/// "A close with no answer", and one the TLS session vouches for: a `close_notify`.
	Closed,
	/// Bytes that are no HTTP answer, or a head beyond its bound.
	NotHttp,
	/// A `101` whose `Sec-WebSocket-Accept` is missing, repeated or wrong.
	Accept,
	/// A `200` to the opening request of `fronted` whose body is not one the session opens.
	Body,
	/// The upgrade was answered and the session closed, by a Close frame or a `close_notify`, before a chunk of the node opened.
	Unopened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
	/// No TCP connection, or no socket.
	Connect,
	/// The TLS handshake failed for something that is no verdict on the certificate.
	Tls,
	/// The certificate did not pass its candidate's check: it did not validate for the name, matched no pin of the candidate, or on a self-signed candidate the handshake was not signed with the pinned key. On `faketls` it is the leaf not being the one the client derives, or the handshake not being signed with it: the real site, an interceptor, or a node that refused the hello, and the node's refusal cannot be told from the other two. It is never the node refusing the device, since nothing of the answer was authenticated: the app says "the server's certificate does not match this profile; the network may be interfering".
	Certificate,
	/// The certificate is not valid at the time the device's clock shows: it ran out, or is not valid yet. The attempt ends as for any certificate that is not accepted. It marks nothing, since the first thing to check is the device's clock.
	CertificateTime,
	/// After the TLS handshake and before a whole answer, the connection was reset or ended without a `close_notify`. Anyone on the path can cause that, so it is no refusal.
	Cut,
	/// Connected, and no answer or no chunk of the node within `ATTEMPT`.
	Timeout,
	/// No opening packet of `udp-obfs` was answered.
	Silence,
	/// On `ws-plain`, where nothing vouches for who answered: the connection was answered and it was not a session (another status, bytes that are no answer, a close or a forged frame before the node's first chunk). It is not a refusal, since the network can write it, and it touches none of the refusal waits.
	Answered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
	/// The caller closed it or dropped it.
	Asked,
	/// The peer closed it in order.
	Peer,
	/// The connection ended, a liveness limit passed, or the node no longer knows the session.
	Lost,
	/// The peer sent what no peer of this protocol sends.
	Fault(Fault),
	/// A chunk number, a request number or a packet count is used up: a new session is due.
	Exhausted,
	/// The proof was taken (a `101` with the right accept value, or an opening request of `fronted` that was written whole) and no chunk of the node followed, on a session that opened with a keepalive: the node no longer knows the tunnel, as after its restart. The candidate is tried again at once, and the WireGuard layer must then open with a handshake initiation.
	Unanswered,
	/// The device itself could not dial: no route, no address, no socket, or the caller's socket hook failed. It says nothing about the candidate.
	Offline,
	/// The WireGuard layer gave no datagram to open with, or one no chunk can hold.
	Source,
	/// The system's random source failed.
	Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
	/// A WebSocket frame that is masked, fragmented, text, too long or no frame. On `faketls`: a record that is none of a session's or does not open, or a frame with a length that is not the record's.
	Frame,
	/// A chunk that does not open at its number, or opens and is invalid.
	Chunk,
	/// An answer to a later `fronted` request that is no `200` with one length and exactly that many bytes.
	Response,
}

impl From<End> for Ended {
	fn from(end: End) -> Self {Self::Closed(end)}
}

impl fmt::Display for Ended {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "session: {self:?}")}
}

impl std::error::Error for Ended {}

/// What a caller can watch of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
	/// Dialling, or waiting for the node's first chunk.
	Opening,
	/// "A chunk from the node has opened": WireGuard has authenticated on this path.
	Established,
	Ended(Ended),
}

/// Why a session was not started. Nothing was dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refuse {
	/// The candidate has an Encrypted Client Hello configuration, which this build cannot use.
	Ech,
	/// A `tls` candidate without a pin.
	Pins,
	/// A self-signed candidate on another transport than `tls`, or with a `verify_name`: a profile never has one, and the pin-only check is for nothing else.
	SelfSigned,
	/// A stream transport on a link without a node transport key.
	NodeKey,
	/// Padding bounds or a keepalive range outside what a profile may set.
	Padding,
	/// A server name that is none.
	Name,
	/// The root store is empty: a fault of the device, and no verdict on a candidate.
	Roots,
	/// A `host` or a `path` with a blank, a line end, a control character or a `?` in it, which would write another request than the one meant.
	Request,
	/// A `faketls` or `ws-plain` candidate with a pin, a self-signed mark, a server name or a `verify_name`, none of which these take: the first holds the leaf against the key the client derives, the second has no TLS. Also a `ws-plain` cookie name that is none.
	Candidate,
}

impl fmt::Display for Refuse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "transport: {self:?}")}
}

impl std::error::Error for Refuse {}

/// The numbers of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numbers {
	/// The largest WireGuard datagram the session carries: the profile's `mtu` and WireGuard's 32 bytes. A larger one is dropped and counted, never cut.
	pub datagram: usize,
	/// Datagrams sent and received.
	pub sent: u64,
	pub received: u64,
	/// Datagrams dropped: a full queue, a size outside the limits, a packet the host refused for its size, a caller that does not read.
	pub dropped: u64,
	/// When a chunk of the node last opened.
	pub heard: Option<Instant>,
}

pub(crate) struct Shared {datagram: usize, room: AtomicU16, low_power: AtomicBool, sent: AtomicU64, received: AtomicU64, dropped: AtomicU64, heard: Mutex<Option<Instant>>}

pub(crate) enum Ask {Close, Moved, Power}

/// One session's ends as its task holds them.
pub(crate) struct Port {pub out: mpsc::Receiver<(Vec<u8>, Kind)>, pub input: mpsc::Sender<Vec<u8>>, pub ask: mpsc::UnboundedReceiver<Ask>, pub state: watch::Sender<State>, pub shared: Arc<Shared>, pub last: Arc<Mutex<Option<Instant>>>, pub source: Source, pub env: Env}

impl Port {
	pub fn want(&self, want: Want) -> Option<Vec<u8>> {self.source.lock().ok().and_then(|mut source| source(want))}
	/// A chunk of the node opened.
	pub fn heard(&self) {
		for heard in [&self.shared.heard, &*self.last] {
			if let Ok(mut heard) = heard.lock() {*heard = Some(Instant::now())}
		}
		if *self.state.borrow() == State::Opening {
			tracing::info!("a session is established");
			self.state.send_replace(State::Established);
		}
	}
	pub fn deliver(&self, datagram: &[u8]) {
		// Counted before it is handed over, so that whoever reads the datagram finds it counted.
		self.shared.received.fetch_add(1, Ordering::Relaxed);
		if self.input.try_send(datagram.to_vec()).is_err() {
			self.shared.received.fetch_sub(1, Ordering::Relaxed);
			self.shared.dropped.fetch_add(1, Ordering::Relaxed);
		}
	}
	pub fn sent(&self, count: usize) {self.shared.sent.fetch_add(count as u64, Ordering::Relaxed);}
	pub fn dropped(&self, count: u64) {self.shared.dropped.fetch_add(count, Ordering::Relaxed);}
	/// Whether a datagram is one a chunk of this link can hold.
	pub fn fits(&self, datagram: &[u8]) -> bool {(MIN_ITEM..=self.shared.datagram).contains(&datagram.len())}
}

/// The ends of a session its owner holds: the caller, or the task of several connections.
pub(crate) struct Member {pub out: mpsc::Sender<(Vec<u8>, Kind)>, pub ask: mpsc::UnboundedSender<Ask>, pub state: watch::Receiver<State>, pub last: Arc<Mutex<Option<Instant>>>, pub task: JoinHandle<()>}

/// Runs what opens a session, unless the caller closes or drops the session first: then nothing more is dialled, written or asked of anyone, and None comes back. `opening` must not touch the session's requests itself.
pub(crate) async fn unasked<T>(ask: &mut mpsc::UnboundedReceiver<Ask>, opening: impl std::future::Future<Output = T>) -> Option<T> {
	tokio::pin!(opening);
	loop {
		tokio::select! {
			done = &mut opening => return Some(done),
			asked = ask.recv() => if !matches!(asked, Some(Ask::Moved | Ask::Power)) {return None},
		}
	}
}

/// A session to a node over one transport, or over several connections of one.
pub struct Session {member: Member, input: mpsc::Receiver<Vec<u8>>, shared: Arc<Shared>}

impl fmt::Debug for Session {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Session({:?})", self.state())}
}

/// The system's secure random source, as `veilway-proto` takes one.
pub(crate) fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| NoRandom)}

/// The range the idle keepalive of a stream is drawn from. While the device is in low power it is the top 10 s of the range the profile allows: 50 to 60 s for a profile that keeps the default, and the last 10 s of its own range when the profile set one, so the draw never passes what the provider chose and never passes 60 s.
pub(crate) fn keepalive_range(link: &Link, low_power: bool) -> RangeInclusive<u32> {
	let (start, end) = (*link.padding.keepalive.start(), *link.padding.keepalive.end());
	if !low_power {return link.padding.keepalive.clone()}
	let top = if link.padding.keepalive == session::KEEPALIVE {*session::KEEPALIVE_BOUNDS.end()} else {end};
	top.saturating_sub(10_000).max(start)..=top
}

/// A time drawn uniformly from a range of milliseconds.
pub(crate) fn pause(range: &RangeInclusive<u32>) -> Result<Duration, End> {session::delay(range, &mut random).map_err(|_| End::Random)}

/// "A chunk that would hold exactly one WireGuard keepalive": a data message of 32 bytes, which is one with nothing inside.
pub(crate) fn lone(datagram: &[u8]) -> bool {datagram.len() == 32 && datagram[0] == 4}

/// Whether a datagram is padded wide: "every chunk that holds a WireGuard handshake message, and every chunk that holds a control channel packet". A handshake message is also known by its first byte.
pub(crate) fn wide(kind: Kind, datagram: &[u8]) -> bool {matches!(kind, Kind::Handshake | Kind::Stalled | Kind::Packet {control: true, ..}) || matches!(datagram.first(), Some(1..=3))}

/// The flow of an inner IP packet for `Kind::Packet`: "a hash of the inner packet's addresses, protocol and ports". A later fragment and a protocol without ports give the hash of the addresses and the protocol, and what is no IP packet gives 0.
pub fn flow(packet: &[u8]) -> u32 {
	let (addresses, protocol, rest) = match packet.first().map(|first| first >> 4) {
		Some(4) if packet.len() >= 20 => {
			let header = usize::from(packet[0] & 0x0f) * 4;
			// Ports are read from a first fragment alone: every other fragment has none.
			(&packet[12..20], packet[9], if u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff == 0 {packet.get(header.max(20)..)} else {None})
		}
		Some(6) if packet.len() >= 40 => (&packet[8..40], packet[6], packet.get(40..)),
		_ => return 0,
	};
	let ports = rest.filter(|_| matches!(protocol, 6 | 17 | 132)).and_then(|rest| rest.get(..4)).unwrap_or_default();
	// FNV-1a. It spreads flows over connections and protects nothing.
	addresses.iter().chain([protocol].iter()).chain(ports).fold(0x811c_9dc5u32, |hash, byte| (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193))
}

// What `open` and `parallel` check before anything is dialled.
fn check(link: &Link, target: &Target, env: &Env) -> Result<(), Refuse> {
	if chunk::Padding::new(link.padding.wide_max, link.padding.normal_max, &mut random).is_err() || session::keepalive(link.padding.keepalive.clone()).is_none() {return Err(Refuse::Padding)}
	// A `faketls` target holds the client of its own transport's key, so it needs no `Link::node`.
	if let Target::FakeTls {candidate, ..} = target {
		if candidate.ech {return Err(Refuse::Ech)}
		if candidate.self_signed || !candidate.pins.is_empty() || candidate.verify_name.is_some() {return Err(Refuse::Candidate)}
		return tls::name(candidate).map(|_| ());
	}
	// A `ws-plain` target has no TLS and no roots, and needs no `Link::node`: its key is its own.
	if let Target::WsPlain {path, candidate, cookie, ..} = target {
		if candidate.ech || candidate.self_signed || !candidate.pins.is_empty() || candidate.verify_name.is_some() || candidate.sni.is_some() || cookie.is_empty() || !cookie.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {return Err(Refuse::Candidate)}
		if [path, &candidate.host].iter().any(|text| text.is_empty() || text.bytes().any(|byte| byte <= b' ' || byte == 0x7f || byte == b'?')) || !path.starts_with('/') {return Err(Refuse::Request)}
		return Ok(());
	}
	let (Target::Tls {path, candidate} | Target::Ws {path, candidate} | Target::Fronted {path, candidate} | Target::FrontedShaped {path, candidate, ..}) = target else {return Ok(())};
	if link.node.is_none() {return Err(Refuse::NodeKey)}
	if candidate.self_signed && (!matches!(target, Target::Tls {..}) || candidate.verify_name.is_some()) {return Err(Refuse::SelfSigned)}
	// A self-signed candidate's check reads no root.
	if env.roots.is_empty() && !candidate.self_signed {return Err(Refuse::Roots)}
	if candidate.ech {return Err(Refuse::Ech)}
	// "Every candidate must have `pins`" on `tls`: the pin is asked on top of a chain that validates, never in its place, except where the signed profile marks the candidate self-signed.
	if matches!(target, Target::Tls {..}) && candidate.pins.is_empty() {return Err(Refuse::Pins)}
	// A profile's host and path were read by `veilway-proto`. A target a caller built by hand was not, and both go into a request as they are.
	if [path, &candidate.host].iter().any(|text| text.is_empty() || text.bytes().any(|byte| byte <= b' ' || byte == 0x7f || byte == b'?')) || !path.starts_with('/') {return Err(Refuse::Request)}
	tls::name(candidate).map(|_| ())
}

// Starts the task of one session. Its datagrams go to `input`, which several connections of one tunnel share.
pub(crate) fn launch(link: Link, target: Target, count: usize, env: Env, source: Source, input: mpsc::Sender<Vec<u8>>, shared: Arc<Shared>) -> Member {
	let ((out, queued), (ask, asked), (state, watched), last) = (mpsc::channel(QUEUE), mpsc::unbounded_channel(), watch::channel(State::Opening), Arc::new(Mutex::new(None)));
	let heard = last.clone();
	let task = tokio::spawn(async move {
		let (mut port, transport) = (Port {out: queued, input, ask: asked, state, shared, last: heard, source, env}, target.name());
		let ended = match &target {
			Target::Tls {..} | Target::Ws {..} | Target::FakeTls {..} if count > 1 => parallel::run(&mut port, &link, &target, count).await,
			Target::UdpObfs(to) => udp::run(&mut port, &link, *to).await,
			Target::Tls {path, candidate} => stream::run(&mut port, &link, Name::Tls, path, candidate, None).await,
			Target::Ws {path, candidate} => stream::run(&mut port, &link, Name::Ws, path, candidate, None).await,
			Target::WsPlain {path, candidate, key, cookie} => stream::run(&mut port, &Link {node: Some(*key), ..link.clone()}, Name::WsPlain, path, candidate, Some(cookie)).await,
			Target::Fronted {path, candidate} => fronted::run(&mut port, &link, path, candidate).await,
			Target::FrontedShaped {path, candidate, shape} => shaped::run(&mut port, &link, path, candidate, shape).await,
			Target::FakeTls {candidate, client} => faketls::run(&mut port, &link, client, candidate).await,
		};
		// No address and no name: a log line at info says which transport and how it ended.
		tracing::info!(transport, ?ended, "a session ended");
		port.state.send_replace(State::Ended(ended));
	});
	Member {out, ask, state: watched, last, task}
}

impl Session {
	/// Opens a session to `target` and returns at once: the session is `Opening` until a chunk of the node has opened, and `state` and `recv` say how it went. Called inside a tokio runtime.
	pub fn open(link: &Link, target: Target, env: Env, source: Source) -> Result<Session, Refuse> {Self::parallel(link, target, 1, env, source)}
	/// The same over up to `connections` connections of `tls`, `ws` or `faketls`, the profile's `parallel`: "Each connection is its own session with its own proof and keys, for the same device", the second and later ones opened "one at a time, each after a delay drawn uniformly from 1 to 5 s". Every other transport has one.
	pub fn parallel(link: &Link, target: Target, connections: u8, env: Env, source: Source) -> Result<Session, Refuse> {
		check(link, &target, &env)?;
		let ((input, inbox), shared) = (mpsc::channel(INBOX), Arc::new(Shared {datagram: (usize::from(link.mtu) + 32).min(MAX_ITEM), room: AtomicU16::new(link.mtu), low_power: AtomicBool::new(false), sent: AtomicU64::new(0), received: AtomicU64::new(0), dropped: AtomicU64::new(0), heard: Mutex::new(None)}));
		Ok(Session {member: launch(link.clone(), target, usize::from(connections.clamp(1, 4)), env, source, input, shared.clone()), input: inbox, shared})
	}
	/// Hands one WireGuard datagram to the session. False when it was dropped because the queue is full or the session is over: "Drop, do not queue." Nothing is ever sent outside the session.
	pub fn send(&self, datagram: Vec<u8>, kind: Kind) -> bool {
		let queued = !matches!(self.state(), State::Ended(_)) && self.member.out.try_send((datagram, kind)).is_ok();
		if !queued {self.shared.dropped.fetch_add(1, Ordering::Relaxed);}
		queued
	}
	/// The next WireGuard datagram from the node, or how the session ended. After an `Ended` every later call gives it again.
	pub async fn recv(&mut self) -> Result<Vec<u8>, Ended> {
		loop {
			// What the session delivered before it ended is given out first. Its end is told when it is known, which on a stream is before the peer's Close frame has been waited for.
			if let Ok(datagram) = self.input.try_recv() {return Ok(datagram)}
			// The end is set after the last datagram was handed over, so one more look finds whatever came between the look above and the end.
			if let State::Ended(ended) = self.state() {return self.input.try_recv().map_err(|_| ended)}
			tokio::select! {
				got = self.input.recv() => return got.ok_or_else(|| self.ended()),
				changed = self.member.state.changed() => if changed.is_err() {return Err(self.ended())},
			}
		}
	}
	/// Closes the session the way its transport closes one and gives how it ended.
	pub async fn close(mut self) -> Ended {
		let _ = self.member.ask.send(Ask::Close);
		let _ = (&mut self.member.task).await;
		self.ended()
	}
	/// The device's network interface or address changed. `udp-obfs` sends an opening packet from a new socket. A stream transport loses its connection by itself and says so.
	pub fn moved(&self) {let _ = self.member.ask.send(Ask::Moved);}
	/// The tunnel's MTU now, the profile's or a lower one the probes found. `udp-obfs` pads no packet above it and 62 bytes, so that padding never makes a packet the path drops.
	pub fn room(&self, mtu: u16) {self.shared.room.store(mtu, Ordering::Relaxed)}
	/// The device is idle (screen off, Doze) or is not. Stream transports with an idle keepalive draw it from the top of the profile's range while it is, and `udp-obfs` does not change: the NAT bindings of mobile networks may expire sooner than the range's top.
	pub fn low_power(&self, on: bool) {
		self.shared.low_power.store(on, Ordering::Relaxed);
		let _ = self.member.ask.send(Ask::Power);
	}
	pub fn state(&self) -> State {*self.member.state.borrow()}
	/// The state as something to wait on.
	pub fn watch(&self) -> watch::Receiver<State> {self.member.state.clone()}
	pub fn numbers(&self) -> Numbers {Numbers {datagram: self.shared.datagram, sent: self.shared.sent.load(Ordering::Relaxed), received: self.shared.received.load(Ordering::Relaxed), dropped: self.shared.dropped.load(Ordering::Relaxed), heard: self.shared.heard.lock().ok().and_then(|heard| *heard)}}
	// A task that is gone without a word was stopped with its runtime.
	fn ended(&self) -> Ended {if let State::Ended(ended) = self.state() {ended} else {Ended::Closed(End::Lost)}}
}

impl Drop for Session {
	fn drop(&mut self) {let _ = self.member.ask.send(Ask::Close);}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_flow_is_its_addresses_protocol_and_ports() {
		let v4 = |source: u8, protocol: u8, fragment: u16, port: u16| [&[0x45, 0, 0, 40, 0, 0][..], &fragment.to_be_bytes(), &[64, protocol, 0, 0, 10, 7, 0, source, 93, 184, 216, 34], &port.to_be_bytes(), &[0, 80, 9, 9, 9, 9]].concat();
		assert_eq!(flow(&v4(2, 6, 0, 4000)), flow(&v4(2, 6, 0, 4000)));
		assert_ne!(flow(&v4(2, 6, 0, 4000)), flow(&v4(2, 6, 0, 4001)));
		assert_ne!(flow(&v4(2, 6, 0, 4000)), flow(&v4(3, 6, 0, 4000)));
		assert_ne!(flow(&v4(2, 6, 0, 4000)), flow(&v4(2, 17, 0, 4000)));
		// A later fragment and a protocol without ports are told apart by addresses and protocol alone.
		assert_eq!(flow(&v4(2, 6, 185, 4000)), flow(&v4(2, 6, 185, 4001)));
		assert_eq!(flow(&v4(2, 1, 0, 4000)), flow(&v4(2, 1, 0, 4001)));
		let v6 = |port: u16| [&[0x60, 0, 0, 0, 0, 8, 17, 64][..], &[1; 16], &[2; 16], &port.to_be_bytes(), &[0, 53, 0, 8, 0, 0]].concat();
		assert_ne!(flow(&v6(5000)), flow(&v6(5001)));
		for packet in [&[][..], &[0x45], &[0x45; 19], &[0x60; 39], &[0x10; 60]] {assert_eq!(flow(packet), 0)}
		// A header length that lies stays inside the packet.
		assert_eq!(flow(&[&[0x4f][..], &[0; 19]].concat()), flow(&[&[0x4f][..], &[0; 19]].concat()));
	}

	#[test]
	fn a_keepalive_and_a_handshake_are_known_without_a_mark() {
		let plain = Kind::Packet {flow: 0, control: false};
		assert!(lone(&[4; 32]) && !lone(&[4; 48]) && !lone(&[1; 32]));
		assert!(wide(plain, &[1; 148]) && wide(plain, &[2; 92]) && !wide(plain, &[4; 64]) && wide(Kind::Packet {flow: 0, control: true}, &[4; 64]) && wide(Kind::Handshake, &[4; 64]) && wide(Kind::Stalled, &[4; 64]));
	}

	#[test]
	fn the_idle_keepalive_of_low_power_is_the_top_of_the_range_and_never_past_the_profile() {
		let link = |keepalive: RangeInclusive<u32>| Link {inbound: [1; 32], device: [2; 32], secret: Secret::new([3; 32]), node: None, mtu: 1390, padding: Padding {wide_max: 1023, normal_max: 255, keepalive}, borrowed: Default::default()};
		assert_eq!(keepalive_range(&link(session::KEEPALIVE), false), 20_000..=40_000);
		assert_eq!(keepalive_range(&link(session::KEEPALIVE), true), 50_000..=60_000);
		assert_eq!(keepalive_range(&link(10_000..=60_000), true), 50_000..=60_000);
		assert_eq!(keepalive_range(&link(15_000..=25_000), true), 15_000..=25_000);
		assert_eq!(keepalive_range(&link(30_000..=50_000), true), 40_000..=50_000);
		assert_eq!(keepalive_range(&link(30_000..=50_000), false), 30_000..=50_000);
		for range in [10_000..=20_000, 15_000..=25_000, 30_000..=50_000, 10_000..=60_000, 55_000..=60_000] {assert!(session::keepalive(keepalive_range(&link(range), true)).is_some())}
	}
}
