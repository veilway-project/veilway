//! The `tls` transport of a `veilway` inbound, end to end: a boringtun peer whose datagrams travel in chunks inside WebSocket frames inside TLS, against a node that is started the way `veilway run` starts it, with a real small web server as its decoy origin.
//! The heart of it is the differential test: whoever is not a user must get from the node what the origin itself gives, byte for byte.
//! The node's clock is each test's own, so a test that needs minutes to pass moves the clock and waits for the node's next look at it. Every node has a replay file and a certificate in a directory of its own.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::digest::{digest, SHA256};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{json, Value};
use socket2::SockRef;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use veilway_core::config::{Config, Diff, REDACTED};
use veilway_core::engine::stream::{Bench, Pools};
use veilway_core::{Engine, Options, Over, StreamTotals};
use veilway_proto::chunk::{Opener, Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::control::{kind, ClientMessage, ErrorCode, NodeMessage, PORT};
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::ClientOpening;
use veilway_proto::proof::{self, Name};
use veilway_proto::replay::WINDOW;
use veilway_proto::websocket::{self, BINARY, CLOSE};
use veilway_proto::{udp_obfs, NoRandom};

const GATEWAY: [u8; 4] = [10, 7, 0, 1];
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
// Keys and secrets of tests are fixed patterns, and no secret of anything real. Device `n` has the private key `KEYS[n]`, the tunnel address 10.7.0.(2 + n) and the transport secret `secret(n)`.
const NODE: [u8; 32] = [0x10; 32];
const KEYS: [[u8; 32]; 6] = [[0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32], [0x25; 32], [0x26; 32]];
/// The node transport key of the inbound, private half, and the one it is rotated to.
const TRANSPORT: [u8; 32] = [0x51; 32];
const ROTATED: [u8; 32] = [0x52; 32];
/// The path of the `tls` transport, which the origin serves nothing at.
const PATH: &str = "/assets/app-3f9c2e71.js";
const SECOND: Duration = Duration::from_secs(1);
/// What a quiet connection is given to stay quiet in.
const QUIET: Duration = Duration::from_millis(500);
/// What the test origin gives a peer to send its request head in, which is below the 10 s the node gives a request line.
const HEAD: Duration = Duration::from_secs(2);
/// The key of the upgrade request of every test client, and the page and the miss of the test origin.
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const PAGE: &str = "<html>the operator's own site</html>\n";
const MISS: &str = "nothing here\n";
/// Port 0 is no listen port of a config, so every listener of a test node takes the next one from here.
static NEXT_PORT: AtomicU16 = AtomicU16::new(27000);
/// Every log line of the process, at info.
static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static LOGGING: Once = Once::new();

struct Sink;

impl Write for Sink {
	fn write(&mut self, line: &[u8]) -> std::io::Result<usize> {
		LOGS.lock().unwrap().extend_from_slice(line);
		Ok(line.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {Ok(())}
}

fn logged(text: &str) -> bool {String::from_utf8_lossy(&LOGS.lock().unwrap()).contains(text)}

fn listen() -> SocketAddr {SocketAddr::from((Ipv4Addr::LOCALHOST, NEXT_PORT.fetch_add(1, Ordering::SeqCst)))}

fn text(key: &[u8; 32]) -> String {veilway_wg::encode_key(key)}

fn public(private: &[u8; 32]) -> [u8; 32] {veilway_wg::public_key(private)}

fn secret(device: usize) -> [u8; 32] {[0xa0 + device as u8; 32]}

fn address(device: usize) -> [u8; 4] {[10, 7, 0, 2 + device as u8]}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for part in bytes.chunks_mut(32) {part.copy_from_slice(&veilway_wg::generate_key()[..part.len()])}
	Ok(())
}

/// The clock of one test's node: the real one and however far the test has moved it ahead.
#[derive(Clone, Copy)]
struct Time {ahead: &'static AtomicI64, now: fn() -> OffsetDateTime}

impl Time {
	fn secs(&self) -> u64 {(self.now)().unix_timestamp() as u64}
}

/// A clock of its own for the test that calls it: tests run side by side, and one that moves time must not move another's.
macro_rules! time {
	() => {{
		static AHEAD: AtomicI64 = AtomicI64::new(0);
		fn now() -> OffsetDateTime {OffsetDateTime::now_utc() + time::Duration::seconds(AHEAD.load(Ordering::SeqCst))}
		Time {ahead: &AHEAD, now}
	}};
}

/// A SOCKS5 proxy without authentication that answers every CONNECT with `main` and then holds the connection open.
async fn proxy() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {return};
			tokio::spawn(async move {
				let (mut hello, mut head, mut target, mut sink) = ([0u8; 2], [0u8; 4], [0u8; 6], [0u8; 256]);
				if client.read_exact(&mut hello).await.is_err() {return}
				let mut methods = vec![0u8; usize::from(hello[1])];
				if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut head).await.is_err() || client.read_exact(&mut target).await.is_err() {return}
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() || client.write_all(b"main").await.is_err() {return}
				while client.read(&mut sink).await.is_ok_and(|count| count > 0) {}
			});
		}
	});
	addr
}

/// The operator's own web site: a real HTTP/1.1 server (hyper) with one page, a miss for every other path, and its own limit on how long a request head may take. Everything it does to a connection is its own doing, which is what the node has to pass on.
struct Site {addr: SocketAddr, connections: Arc<AtomicUsize>, requests: Arc<AtomicUsize>, written: Arc<AtomicUsize>, task: JoinHandle<()>}

impl Drop for Site {
	fn drop(&mut self) {self.task.abort()}
}

/// A site on `listener`. It answers `delay` after a request came, and gives a request head `head` to arrive in.
fn site_on(listener: TcpListener, delay: Duration, head: Duration) -> Site {
	let (addr, connections, requests) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
	let task = tokio::spawn({
		let (connections, requests) = (connections.clone(), requests.clone());
		async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else {return};
				connections.fetch_add(1, Ordering::SeqCst);
				let requests = requests.clone();
				tokio::spawn(async move {
					let page = service_fn(move |request: Request<Incoming>| {
						let requests = requests.clone();
						async move {
							requests.fetch_add(1, Ordering::SeqCst);
							tokio::time::sleep(delay).await;
							let found = request.method() == hyper::Method::GET && request.uri().path() == "/";
							Ok::<_, Infallible>(Response::builder().status(if found {200} else {404}).header("server", "decoy/1.0").header("x-site", "one").header("x-site", "two").body(Full::new(Bytes::from(if found {PAGE} else {MISS}))).unwrap())
						}
					});
					let _ = hyper::server::conn::http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(head).half_close(true).serve_connection(TokioIo::new(stream), page).await;
				});
			}
		}
	});
	Site {addr, connections, requests, written: Arc::default(), task}
}

/// How long the origin written by hand waits for a request head before it says so and closes.
const RAW_HEAD: Duration = Duration::from_millis(1500);
/// The length of the head it writes before a body of the size it was asked for.
const BULK_HEAD: usize = "HTTP/1.1 200 OK\r\nContent-Length: 0000000000\r\n\r\n".len();

/// An origin written by hand, for what a real server does only when it is made to. A request head that is not there in time gets a `408` and a close.
/// `GET /big/<bytes>/<keep|close>` is answered with that many bytes, counted in `written` as they are written, and the connection is then kept or closed. `/echo` is the upgrade of a WebSocket endpoint of the site's own, which sends back whatever comes.
/// `/reset` is half an answer and then a reset. `/early` is answered before its body was read, with the origin taking the rest of the upload as a web server with a lingering close does. Everything else gets an empty answer and a close.
async fn raw() -> Site {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, connections, written) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
	let task = tokio::spawn({
		let (connections, written) = (connections.clone(), written.clone());
		async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else {return};
				connections.fetch_add(1, Ordering::SeqCst);
				let written = written.clone();
				tokio::spawn(async move {
					let (mut head, mut filled) = (vec![0u8; 8192], 0);
					let whole = timeout(RAW_HEAD, async {
						while !head[..filled].windows(4).any(|window| window == b"\r\n\r\n") {
							match stream.read(&mut head[filled..]).await {
								Ok(read) if read > 0 => filled += read,
								_ => return false,
							}
						}
						true
					}).await;
					match whole {
						Ok(true) => {}
						Ok(false) => return,
						Err(_) => return drop(stream.write_all(b"HTTP/1.1 408 Request Timeout\r\nServer: raw\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await),
					}
					let line = String::from_utf8_lossy(&head[..filled]).lines().next().unwrap_or_default().to_string();
					let mut parts = line.split(' ').nth(1).unwrap_or_default().split('/').skip(1);
					match parts.next() {
						Some("big") => {
							let (body, keep) = (parts.next().unwrap().parse::<usize>().unwrap(), parts.next() == Some("keep"));
							let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {body:010}\r\n\r\n").as_bytes()).await;
							let (block, mut left) = (vec![0x61u8; 16 * 1024], body);
							while left > 0 {
								let size = left.min(block.len());
								if stream.write_all(&block[..size]).await.is_err() {return}
								written.fetch_add(size, Ordering::SeqCst);
								left -= size;
							}
							if keep {tokio::time::sleep(Duration::from_secs(60)).await}
						}
						Some("echo") => {
							if stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.is_err() {return}
							let mut said = [0u8; 4096];
							while let Ok(read) = stream.read(&mut said).await {
								if read == 0 || stream.write_all(&said[..read]).await.is_err() {return}
							}
						}
						Some("reset") => {
							let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhalf of it").await;
							tokio::time::sleep(Duration::from_millis(300)).await;
							let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));
						}
						Some("early") => {
							let (_, _, mut rest) = (stream.write_all(b"HTTP/1.1 413 Payload Too Large\r\nServer: raw\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await, stream.shutdown().await, vec![0u8; 65536]);
							while stream.read(&mut rest).await.is_ok_and(|read| read > 0) {}
						}
						_ => drop(stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await),
					}
				});
			}
		}
	});
	Site {addr, connections, requests: Arc::default(), written, task}
}

/// Asks for `body` bytes, reads nothing for `stall`, then reads until all came, the connection ended, or nothing came for `quiet`, with a rest of `pace` after every read. How many bytes came.
async fn fetch<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, body: usize, keep: bool, stall: Duration, quiet: Duration, pace: Duration) -> usize {
	io.write_all(format!("GET /big/{body}/{} HTTP/1.1\r\nHost: node.test\r\n\r\n", if keep {"keep"} else {"close"}).as_bytes()).await.unwrap();
	io.flush().await.unwrap();
	tokio::time::sleep(stall).await;
	let (mut buf, mut got) = (vec![0u8; 16384], 0);
	while got < BULK_HEAD + body {
		match timeout(quiet, io.read(&mut buf)).await {
			Ok(Ok(read)) if read > 0 => got += read,
			_ => break,
		}
		if !pace.is_zero() {tokio::time::sleep(pace).await}
	}
	got
}

async fn site() -> Site {site_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), Duration::ZERO, HEAD)}

/// A site that keeps a quiet connection for longer than a test takes, for the tests that count connections.
async fn patient() -> Site {site_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), Duration::ZERO, Duration::from_secs(60))}

/// A new directory for one test.
fn scratch(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-tls-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// Writes the replay file a node leaves that was killed with this floor and this limit: a head without the clean mark and without entries, and its hash.
fn seed(path: &Path, floor: u64, limit: u64) {
	let body = [&b"VWREPLAY"[..], &1u32.to_be_bytes(), &[0; 4], &floor.to_be_bytes(), &limit.to_be_bytes(), &0u32.to_be_bytes()].concat();
	std::fs::write(path, [&body[..], digest(&SHA256, &body).as_ref()].concat()).unwrap();
}

/// Writes a new self-signed certificate for `node.test` with its key into `dir`, mode 600, and gives what a client needs to trust exactly that certificate.
fn certify(dir: &Path) -> TlsConnector {
	let _ = rustls::crypto::ring::default_provider().install_default();
	let made = rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap();
	for (name, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
		std::fs::write(dir.join(name), pem).unwrap();
		#[cfg(unix)]
		std::fs::set_permissions(dir.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
	let mut roots = RootCertStore::empty();
	roots.add(CertificateDer::from(made.cert.der().to_vec())).unwrap();
	TlsConnector::from(Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()))
}

/// A document with one `veilway` inbound `home` on 10.7.0.1/24 that is reached over `tls` at `listen` with the decoy origin `origin`, one exit through `proxy`, and the users `a` to `f` with one device each.
fn document(proxy: SocketAddr, listen: SocketAddr, origin: SocketAddr) -> Value {
	let names = ["a", "b", "c", "d", "e", "f"];
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [text(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [{"type": "tls", "listen": listen.to_string(), "path": PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": format!("http://{origin}")}}]}],
		"outbounds": [{"tag": "main-proxy", "type": "socks5", "server": proxy.to_string()}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "main-proxy"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": (0..KEYS.len()).map(|device| json!({"name": names[device], "exits": "all", "devices": [{"name": "phone", "public_key": text(&public(&KEYS[device])), "transport_secrets": [text(&secret(device))], "addresses": [Ipv4Addr::from(address(device)).to_string()]}]})).collect::<Vec<_>>()
	})
}

fn parsed(doc: &Value) -> Config {
	let config = Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("the test config does not parse: {e}"));
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	config
}

struct Node {engine: Engine, addr: SocketAddr, doc: Value, dir: PathBuf, time: Time, site: Site, connector: TlsConnector}

/// Starts an engine on `doc` with its files in `dir` and the clock of `time`.
async fn start(doc: &Value, dir: &Path, time: Time) -> anyhow::Result<Engine> {
	LOGGING.call_once(|| tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_writer(|| Sink).init());
	veilway_core::start(&parsed(doc), Options {now: time.now, replay: Some(dir.join("replay")), ..Options::new(dir)}).await
}

/// Starts a node on `document` after `change` had its way with it, with the origin `site` for its decoy. Its replay file is one a node left that was killed 100 seconds ago, so it takes proofs from its first moment.
async fn launch_at(test: &str, time: Time, site: Site, change: impl FnOnce(&mut Value)) -> Node {
	let (dir, addr) = (scratch(test), listen());
	let connector = certify(&dir);
	let mut doc = document(proxy().await, addr, site.addr);
	change(&mut doc);
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let engine = start(&doc, &dir, time).await.unwrap();
	Node {engine, addr, doc, dir, time, site, connector}
}

/// The same with a site of its own, whose answer the node has learnt the header fields of when this returns.
async fn launch(test: &str, time: Time, change: impl FnOnce(&mut Value)) -> Node {
	let node = launch_at(test, time, site().await, change).await;
	eventually("the node did not learn the header fields of its origin", || node.totals().upgrade_learned > 0).await;
	node
}

impl Node {
	fn totals(&self) -> StreamTotals {self.engine.stream()}

	async fn reload(&mut self, change: impl FnOnce(&mut Value)) {
		change(&mut self.doc);
		parsed(&self.doc);
		self.engine.reload(self.doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
	}

	/// Moves the node's clock ahead and waits until the replay memory has written a limit for the new time, as the node's timer does within a second.
	async fn advance(&self, secs: i64) {
		self.time.ahead.fetch_add(secs, Ordering::SeqCst);
		eventually("the replay limit did not follow the clock", || self.engine.replay().is_some_and(|replay| replay.limit >= self.time.secs())).await;
	}

	/// A TLS connection to the node from `from`, as anybody can make one.
	async fn dial(&self, from: IpAddr) -> TlsStream<TcpStream> {
		let socket = TcpSocket::new_v4().unwrap();
		socket.bind(SocketAddr::new(from, 0)).unwrap();
		self.connector.connect(ServerName::try_from("node.test").unwrap(), socket.connect(self.addr).await.unwrap()).await.unwrap()
	}

	/// What a stranger gets for `request` through the node, and whether the connection was closed behind it.
	async fn ask(&self, request: &[u8]) -> (String, bool) {
		let (answer, closed) = play(self.dial(Ipv4Addr::LOCALHOST.into()).await, &[Step::Send(request.to_vec())], SECOND).await;
		(String::from_utf8_lossy(&answer).into_owned(), closed)
	}

	fn device(&self, n: usize) -> Device {Device::new(n, secret(n), &TRANSPORT, self.addr, self.connector.clone())}
}

/// Waits for something the engine does on its own time.
async fn eventually(what: &str, done: impl Fn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(8);
	while !done() {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// The upgrade request of a client for `path` with `token`.
fn upgrade(path: &str, token: &str) -> Vec<u8> {format!("GET {path}?{token} HTTP/1.1\r\nHost: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n").into_bytes()}

/// One thing a peer does to a connection.
enum Step {Send(Vec<u8>), Wait(u64), Finish}

/// Does `steps` to a connection and then reads it to its end. What came, and whether the connection was closed from the other side before nothing had come for `patience`.
async fn play<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, steps: &[Step], patience: Duration) -> (Vec<u8>, bool) {
	let (mut got, mut buf) = (Vec::new(), vec![0u8; 65536]);
	for step in steps {
		match step {
			Step::Send(bytes) => {
				let _ = io.write_all(bytes).await;
				let _ = io.flush().await;
			}
			Step::Wait(millis) => tokio::time::sleep(Duration::from_millis(*millis)).await,
			Step::Finish => drop(io.shutdown().await),
		}
	}
	loop {
		match timeout(patience, io.read(&mut buf)).await {
			Ok(Ok(count)) if count > 0 => got.extend_from_slice(&buf[..count]),
			Ok(_) => return (got, true),
			Err(_) => return (got, false),
		}
	}
}

/// A device that reaches its tunnel over `tls`. What it receives and nobody asked for yet waits in `inbox`.
struct Device {n: usize, tunn: Tunn, prover: proof::Client, node: SocketAddr, connector: TlsConnector, from: IpAddr, io: Option<TlsStream<TcpStream>>, tx: Option<Sealer>, rx: Option<Opener>, buf: Vec<u8>, inbox: VecDeque<Vec<u8>>, closed: bool, token: String}

impl Device {
	/// Device `n` with the transport secret `secret`, which seals its proofs to the node transport key whose private half is `transport`.
	fn new(n: usize, secret: [u8; 32], transport: &[u8; 32], node: SocketAddr, connector: TlsConnector) -> Device {
		Device {n, tunn: Tunn::new(StaticSecret::from(KEYS[n]), PublicKey::from(public(&NODE)), None, None, 0, None), prover: proof::Client::new(&proof::public_key(transport), &secret, &public(&NODE), &public(&KEYS[n])), node, connector, from: Ipv4Addr::LOCALHOST.into(), io: None, tx: None, rx: None, buf: Vec::new(), inbox: VecDeque::new(), closed: false, token: String::new()}
	}

	/// A fresh WireGuard handshake initiation.
	fn initiation(&mut self) -> Vec<u8> {
		let mut scratch = vec![0u8; 2048];
		let TunnResult::WriteToNetwork(init) = self.tunn.format_handshake_initiation(&mut scratch, true) else {panic!("no handshake initiation")};
		init.to_vec()
	}

	/// The WireGuard datagram around one IP packet, or a keepalive for none, under the session the tunnel has.
	fn sealed(&mut self, packet: &[u8]) -> Vec<u8> {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn.encapsulate(packet, &mut out) else {panic!("the tunnel has no session to send under")};
		datagram.to_vec()
	}

	/// A new connection with the upgrade request for `path`, its proof made for `name` with the timestamp `at`. What the node answered up to the end of its head, or all of it when the connection closed first. On a `101` the session's keys are the device's from here on.
	async fn open_as(&mut self, path: &str, name: Name, at: u64) -> String {
		let socket = TcpSocket::new_v4().unwrap();
		socket.bind(SocketAddr::new(self.from, 0)).unwrap();
		let mut io = self.connector.connect(ServerName::try_from("node.test").unwrap(), socket.connect(self.node).await.unwrap()).await.unwrap();
		let proof = self.prover.prove(name, at, &mut random).unwrap();
		io.write_all(&upgrade(path, &proof.token)).await.unwrap();
		let (mut head, mut buf) = (Vec::new(), vec![0u8; 4096]);
		let end = loop {
			if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {break end + 4}
			match timeout(Duration::from_secs(4), io.read(&mut buf)).await {
				Ok(Ok(count)) if count > 0 => head.extend_from_slice(&buf[..count]),
				_ => break head.len(),
			}
		};
		(self.buf, self.closed, self.token) = (head.split_off(end), false, proof.token);
		if head.starts_with(b"HTTP/1.1 101 ") {(self.tx, self.rx) = (Some(Sealer::new(proof.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap())), Some(Opener::new(proof.keys.s2c)))}
		self.io = Some(io);
		String::from_utf8_lossy(&head).into_owned()
	}

	async fn open(&mut self, at: u64) -> String {self.open_as(PATH, Name::Tls, at).await}

	/// One chunk with these WireGuard datagrams, in one masked binary frame.
	async fn put(&mut self, datagrams: &[&[u8]]) {
		let (mut sealed, mut out) = (Vec::new(), Vec::new());
		self.tx.as_mut().expect("no session").seal(datagrams, false, &mut random, &mut sealed).unwrap();
		websocket::frame(BINARY, &sealed, Some([0x3a, 0x5c, 0x11, 0x7e]), &mut out);
		let _ = self.io.as_mut().unwrap().write_all(&out).await;
	}

	/// The next chunk of the node: the WireGuard datagrams in it, none for a padding-only chunk. None when nothing came in time or the session was closed, which `closed` then says.
	async fn chunk(&mut self, budget: Duration) -> Option<Vec<Vec<u8>>> {
		let (deadline, mut read) = (Instant::now() + budget, vec![0u8; 32768]);
		loop {
			if let Some(header) = websocket::header(&self.buf).expect("the node sent what is no frame").filter(|header| self.buf.len() >= header.size + header.payload as usize) {
				let mut frame: Vec<u8> = self.buf.drain(..header.size + header.payload as usize).collect();
				assert!(header.fin && header.mask.is_none(), "a frame of the node that is masked or in pieces");
				match header.opcode {
					BINARY => return Some(self.rx.as_mut()?.open(&mut frame[header.size..]).expect("the node sent a chunk that does not open").map(<[u8]>::to_vec).collect()),
					CLOSE => {
						// "A WebSocket Close frame with status 1000 and no reason."
						assert_eq!(frame[header.size..], [0x03, 0xe8]);
						self.closed = true;
						return None;
					}
					_ => continue,
				}
			}
			match timeout(deadline.checked_duration_since(Instant::now())?, self.io.as_mut()?.read(&mut read)).await {
				Ok(Ok(count)) if count > 0 => self.buf.extend_from_slice(&read[..count]),
				Ok(_) => {
					self.closed = true;
					return None;
				}
				Err(_) => return None,
			}
		}
	}

	/// Whether the node closes the session within `budget`: its Close frame, or the end of the connection.
	async fn ends(&mut self, budget: Duration) -> bool {
		let deadline = Instant::now() + budget;
		while !self.closed && Instant::now() < deadline {self.chunk(deadline.saturating_duration_since(Instant::now())).await;}
		self.closed
	}

	/// Opens a session and finishes a WireGuard handshake on it. False when the node did not take the proof or did not answer.
	async fn try_connect(&mut self, at: u64) -> bool {
		if !self.open(at).await.starts_with("HTTP/1.1 101 ") {return false}
		let init = self.initiation();
		self.put(&[&init]).await;
		let Some(answer) = self.chunk(SECOND).await else {return false};
		let (Some(response), mut out) = (answer.first(), vec![0u8; 2048]) else {return false};
		let TunnResult::WriteToNetwork(keepalive) = self.tunn.decapsulate(None, response, &mut out) else {panic!("the first answer held no handshake response")};
		let keepalive = keepalive.to_vec();
		self.put(&[&keepalive]).await;
		true
	}

	async fn connect(&mut self, time: Time) {assert!(self.try_connect(time.secs()).await, "the node did not take its device")}

	/// One IP packet into the tunnel.
	async fn send(&mut self, packet: &[u8]) {
		let datagram = self.sealed(packet);
		self.put(&[&datagram]).await;
	}

	/// The next IP packet `wanted` picks, from the inbox or from the tunnel. Every other packet stays in the inbox.
	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let (deadline, mut found) = (Instant::now() + budget, None);
		loop {
			for datagram in self.chunk(deadline.checked_duration_since(Instant::now())?).await? {
				let mut input: &[u8] = &datagram;
				loop {
					let mut out = vec![0u8; 2048];
					match self.tunn.decapsulate(None, input, &mut out) {
						TunnResult::WriteToNetwork(reply) => {
							let reply = reply.to_vec();
							self.put(&[&reply]).await;
							input = &[];
						}
						TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
							if wanted(packet) && found.is_none() {found = Some(packet.to_vec())} else {self.inbox.push_back(packet.to_vec())}
							break;
						}
						_ => break,
					}
				}
			}
			if found.is_some() {return found}
		}
	}

	/// Opens a TCP connection to `PUBLIC` from the device's tunnel address and reads what the exit's proxy says first. None when the SYN gets no answer.
	async fn leaves(&mut self, sport: u16) -> Option<String> {
		let (mut syn, mut out, n) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new(), self.n);
		syn.syn = true;
		PacketBuilder::ipv4(address(n), PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (answer, _) = segment(&self.recv(SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (80, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		let (mut ack, mut out) = (TcpHeader::new(sport, 80, 1001, 65535), Vec::new());
		(ack.ack, ack.acknowledgment_number) = (true, answer.sequence_number.wrapping_add(1));
		PacketBuilder::ipv4(address(n), PUBLIC, 64).tcp_header(ack).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (_, said) = segment(&self.recv(Duration::from_secs(3), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (80, sport) && !data.is_empty())).await?)?;
		let (mut rst, mut out) = (TcpHeader::new(sport, 80, 1001, 0), Vec::new());
		rst.rst = true;
		PacketBuilder::ipv4(address(n), PUBLIC, 64).tcp_header(rst).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		Some(String::from_utf8(said).unwrap())
	}
}

fn segment(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	Some((tcp, if let PayloadSlice::Tcp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

/// An answer with the one header field that follows the clock made the same on both sides: "the answers are byte-identical apart from headers the spec says may differ", which for a relayed answer is none, and `Date` is the origin's own clock at two moments.
fn undated(answer: &[u8]) -> String {String::from_utf8_lossy(answer).split("\r\n").map(|line| if line.to_ascii_lowercase().starts_with("date:") {"date: (the origin's clock)"} else {line}).collect::<Vec<_>>().join("\r\n")}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_its_tunnel_and_everything_of_the_engine_works_over_it() {
	let time = time!();
	let node = launch("happy", time, |_| {}).await;
	let mut a = node.device(0);
	let answer = a.open(time.secs()).await;
	// "The node's answer is these lines, in this order": the status line, the fields of `upgrade_headers` as the origin spelled and sent them (`Server`, `Date` by default, the first value of a field it sent twice), the three fields of the upgrade, and one cookie of 16 to 96 characters.
	let lines: Vec<&str> = answer.trim_end().split("\r\n").collect();
	assert_eq!((lines.len(), lines[0], lines[1], lines[3], lines[4], lines[5]), (7, "HTTP/1.1 101 Switching Protocols", "server: decoy/1.0", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{answer}");
	let (date, cookie) = (lines[2].strip_prefix("date: ").expect("no date"), lines[6].strip_prefix("Set-Cookie: sid=").expect("no cookie"));
	assert!(date.ends_with(" GMT") && date.len() == 29 && (16..=96).contains(&cookie.len()) && cookie.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'), "{answer}");
	// "The node sends nothing on a pending session." Its first answer comes when the session is established, and is the handshake response.
	assert_eq!((a.chunk(QUIET).await, node.totals().pending, node.totals().sessions), (None, 1, 0));
	let init = a.initiation();
	a.put(&[&init]).await;
	let first = a.chunk(SECOND).await.expect("no first answer");
	assert_eq!((first.len(), first[0].len(), first[0][0]), (1, 92, 2));
	let mut out = vec![0u8; 2048];
	let TunnResult::WriteToNetwork(keepalive) = a.tunn.decapsulate(None, &first[0], &mut out) else {panic!("no handshake response")};
	let keepalive = keepalive.to_vec();
	a.put(&[&keepalive]).await;
	// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay."
	assert_eq!(a.chunk(Duration::from_secs(4)).await, Some(Vec::new()), "a lone keepalive was not echoed");
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	// The control channel at the gateway: the opening exchange under the device's transport secret, inside the tunnel that came over `tls`.
	let (mut syn, mut out, sport, started) = (TcpHeader::new(41000, PORT, 5000, 65535), Vec::new(), 41000, Instant::now());
	syn.syn = true;
	PacketBuilder::ipv4(address(0), GATEWAY, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
	a.send(&out).await;
	let (answer, _) = segment(&a.recv(SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (PORT, sport))).await.expect("the control port did not answer")).unwrap();
	let (mut seq, mut ack, mut up) = (5001u32, answer.sequence_number.wrapping_add(1), Vec::new());
	let mut opening = ClientOpening::start(ControlKey::derive(&secret(0), &public(&NODE), &public(&KEYS[0])), 1, Duration::ZERO, &mut random, &mut up).unwrap();
	let (mut opened, mut rest) = loop {
		let (mut header, mut out) = (TcpHeader::new(sport, PORT, seq, 65535), Vec::new());
		(header.ack, header.psh, header.acknowledgment_number) = (true, true, ack);
		PacketBuilder::ipv4(address(0), GATEWAY, 64).tcp_header(header).write(&mut out, &up).unwrap();
		a.send(&out).await;
		seq = seq.wrapping_add(up.len() as u32);
		up.clear();
		let (tcp, data) = segment(&a.recv(Duration::from_secs(3), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (PORT, sport) && !data.is_empty() && tcp.sequence_number == ack)).await.expect("the control channel went quiet")).unwrap();
		ack = tcp.sequence_number.wrapping_add(data.len() as u32);
		let mut input = &data[..];
		if let Some(opened) = opening.receive(started.elapsed(), &mut input, &mut up).expect("the node broke the opening exchange") {break (opened, input.to_vec())}
	};
	assert_eq!(opened.version, 1);
	// "It applies on `udp` and `udp-obfs`. On a stream transport nothing fragments, the node answers `probe_start` with `error` code 2": no run is started over `tls`, where no probe could ever be lost.
	let (mut header, mut out, mut ask) = (TcpHeader::new(sport, PORT, seq, 65535), Vec::new(), Vec::new());
	ClientMessage::ProbeStart.encode(&mut ask).unwrap();
	(header.ack, header.psh, header.acknowledgment_number) = (true, true, ack);
	PacketBuilder::ipv4(address(0), GATEWAY, 64).tcp_header(header).write(&mut out, &ask).unwrap();
	a.send(&out).await;
	let refusal = loop {
		let mut input = &rest[..];
		match opened.messages.read(&mut input).expect("the node sent what no client reads") {
			Some(NodeMessage::Error {code, answers}) => break (code, answers),
			Some(NodeMessage::ProbeToken {..}) => panic!("a probe run was started over tls"),
			Some(_) => rest = input.to_vec(),
			None => {
				let (tcp, data) = segment(&a.recv(Duration::from_secs(3), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (PORT, sport) && !data.is_empty() && tcp.sequence_number == ack)).await.expect("the probe run was not answered")).unwrap();
				ack = tcp.sequence_number.wrapping_add(data.len() as u32);
				rest = [input, &data[..]].concat();
			}
		}
	};
	assert_eq!((refusal, node.engine.control().probe_runs), ((ErrorCode::NotApplicable, kind::PROBE_START), 0));
	// Usage is counted, the session is a `tls` one, and nothing of the user's connection reached the origin: the node asked it once for its header fields, and the connection it opened for the user was closed unused.
	let (peers, totals, control) = (node.engine.peers(Some("a")), node.totals(), node.engine.control());
	assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(Over::Tls), true));
	assert_eq!((totals.proofs_accepted, totals.established, totals.sessions, totals.pending, totals.relays, totals.undecided, control.authenticated), (1, 1, 1, 0, 0, 0, 1), "{totals:?}");
	assert!(node.engine.user("a").unwrap().up_bytes > 0 && node.engine.user("a").unwrap().down_bytes > 0);
	assert_eq!((node.site.requests.load(Ordering::SeqCst), node.site.connections.load(Ordering::SeqCst)), (1, 2));
	// "Either side ends a session with a WebSocket Close frame with status 1000 and no reason": the device's is answered with the node's, and the connection ends.
	let mut close = Vec::new();
	websocket::frame(CLOSE, &websocket::NORMAL, Some([1, 2, 3, 4]), &mut close);
	a.io.as_mut().unwrap().write_all(&close).await.unwrap();
	assert!(a.ends(SECOND).await);
	eventually("the session did not end", || node.totals().sessions == 0 && node.totals().ended_closed == 1).await;
	node.engine.shutdown().await;
}

// The heart of the transport: "Everything a stranger sends to a stream listener reaches the operator's own decoy origin and nowhere else", and what comes back is the origin's answer and nothing of the node's.
// Every request is sent once to the origin itself and once through the node, and what comes back must be the same bytes with the same end: closed where the origin closes, open where the origin keeps the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whoever_is_not_a_user_gets_from_the_node_exactly_what_the_origin_gives() {
	let time = time!();
	let mut node = launch("differential", time, |_| {}).await;
	// A proof that was valid and is spent, and one of a device the config no longer has.
	let (mut a, f) = (node.device(0), node.device(5));
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let (spent, removed) = (a.token.clone(), f.prover.prove(Name::Tls, time.secs(), &mut random).unwrap().token);
	node.reload(|doc| drop(doc["users"].as_array_mut().unwrap().pop())).await;
	let fresh = node.device(1).prover.prove(Name::Tls, time.secs(), &mut random).unwrap().token;
	let near = format!("{}{}", &fresh[..fresh.len() - 1], if fresh.ends_with('A') {'Q'} else {'A'});
	let send = |text: &str| Step::Send(text.as_bytes().to_vec());
	// The origin closes a connection it keeps for another request two seconds after the last one. A case is watched for less than that where the connection must still be open on both sides, and for more where it must be closed on both.
	let (long, late) = (8 * 1024, Duration::from_millis(3500));
	let cases: Vec<(&str, Vec<Step>, Duration)> = vec![
		("the page, as a browser asks for it", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Language: en\r\n\r\n")], SECOND),
		("the page, and then the connection is to close", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], 2 * SECOND),
		("a miss", vec![send("GET /favicon.ico HTTP/1.1\r\nHost: node.test\r\n\r\n")], late),
		("two requests on one connection", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\n"), Step::Wait(200), send("GET /second HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], 2 * SECOND),
		("two requests in one write", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\nGET /other HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], 2 * SECOND),
		("another method", vec![send("HEAD / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], 2 * SECOND),
		("a body", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")], 2 * SECOND),
		("an older version", vec![send("GET / HTTP/1.0\r\n\r\n")], 2 * SECOND),
		("garbage", vec![Step::Send(vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03])], 4 * SECOND),
		("words that are no request", vec![send("hello there\r\n\r\n")], 4 * SECOND),
		("a request that arrives slowly", vec![send("GET / HT"), Step::Wait(300), send("TP/1.1\r\nHo"), Step::Wait(300), send("st: node.test\r\nConnection: close\r\n\r\n")], 2 * SECOND),
		("a request line with no blank line behind it", vec![send("GET / HTTP/1.1\r\n")], 4 * SECOND),
		// The origin gives these two up after two seconds, and so does the node at that moment: it watches the origin while the line is not complete.
		("a request line that is never finished", vec![send("GET / HT")], 5 * SECOND),
		("nothing at all", vec![], 5 * SECOND),
		("a body the client announces and waits with", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"), Step::Wait(300), send("hello")], 2 * SECOND),
		("a body in chunks", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n")], 2 * SECOND),
		("the preface of HTTP/2", vec![send("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")], 4 * SECOND),
		("a request line of exactly the node's limit", vec![Step::Send(format!("GET /{} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n", "a".repeat(4096 - 16)).into_bytes())], 2 * SECOND),
		("a request line one byte above the node's limit", vec![Step::Send(format!("GET /{} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n", "a".repeat(4097 - 16)).into_bytes())], 2 * SECOND),
		("a proof with one character changed, and a second request in the same write", vec![Step::Send([&upgrade(PATH, &near)[..], b"GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n"].concat())], 2 * SECOND),
		("a request line above the node's limit", vec![Step::Send(format!("GET /{} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n", "a".repeat(6000)).into_bytes())], 2 * SECOND),
		("a head above the node's limit", vec![Step::Send(format!("GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n{}\r\n", (0..40).map(|at| format!("X-Pad-{at}: {}\r\n", "b".repeat(long / 16))).collect::<String>()).into_bytes())], 2 * SECOND),
		("the path of the transport with no proof", vec![Step::Send(format!("GET {PATH} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n").into_bytes())], 2 * SECOND),
		("a proof with one character changed", vec![Step::Send(upgrade(PATH, &near))], late),
		("a proof that was accepted before", vec![Step::Send(upgrade(PATH, &spent))], late),
		("a proof of a device that was removed", vec![Step::Send(upgrade(PATH, &removed))], late),
		("a proof on another path", vec![Step::Send(upgrade("/assets/app-other.js", &fresh))], late),
		("a request, and then the peer closes its side", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\n"), Step::Finish], 2 * SECOND),
	];
	// Every case runs against both at once, so the whole test takes as long as its slowest case.
	let (origin, connector, addr) = (node.site.addr, node.connector.clone(), node.addr);
	let runs: Vec<_> = cases.into_iter().map(|(case, steps, patience)| {
		let connector = connector.clone();
		tokio::spawn(async move {
			let through = async {play(connector.connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(addr).await.unwrap()).await.unwrap(), &steps, patience).await};
			let direct = async {play(TcpStream::connect(origin).await.unwrap(), &steps, patience).await};
			let ((got, closed), (expected, ended)) = tokio::join!(through, direct);
			(case, undated(&got), closed, undated(&expected), ended)
		})
	}).collect();
	let mut answered = 0;
	for run in runs {
		let (case, got, closed, expected, ended) = run.await.unwrap();
		assert_eq!((got.as_str(), closed), (expected.as_str(), ended), "{case}: the node on the left, the origin on the right");
		// Nothing in an answer is the node's own: not the status line of an upgrade, and not its cookie.
		assert!(!got.contains("101") && !got.contains("Set-Cookie") && !got.contains("Sec-WebSocket-Accept"), "{case}: {got}");
		answered += usize::from(!got.is_empty());
	}
	// The cases are not all silence: the origin answered most of them, and the node passed each answer on.
	assert!(answered >= 22, "only {answered} cases were answered at all");
	// The spent proof, the removed device and the changed proof were three kinds of refusal inside the node, and one answer outside it.
	let totals = node.totals();
	assert_eq!((totals.refused_seen, totals.proofs_accepted, totals.decoy_down), (1, 1, 0), "{totals:?}");
	// Seven were no request line a user could send, two never finished theirs and were decided when the origin gave them up, long before the node's own limit, and eighteen were complete lines that proved nothing. All twenty-eight were relayed.
	assert_eq!((totals.stranger_syntax, totals.stranger_origin, totals.stranger_slow, totals.stranger_proof, totals.relays, totals.relayed, totals.undecided), (7, 2, 0, 18, 28, 0, 0), "{totals:?}");
	node.engine.shutdown().await;
}

// "A request that fails any step takes the unauthenticated path, and the node never says which step failed." Each refusal has its own counter inside the node and the same answer outside it: the origin's answer for that path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refusal_takes_the_decoy_path() {
	let time = time!();
	let node = launch("refusals", time, |doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 2})).await;
	let now = time.secs();
	let miss = |answer: String| assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n") && !answer.contains("Set-Cookie"), "{answer}");
	// What steps 1 to 4 refuse: another path, another method, a proof made for another transport, a secret the node does not have, and a transport key that is not the node's.
	let token = |n: usize| node.device(n).prover.prove(Name::Tls, now, &mut random).unwrap().token;
	miss(node.ask(&upgrade("/assets/app-0000.js", &token(0))).await.0);
	miss(node.ask(&upgrade(PATH, &token(0)).strip_prefix(b"GET").map(|rest| [&b"POST"[..], rest].concat()).unwrap()).await.0);
	miss(node.device(0).open_as(PATH, Name::Ws, now).await);
	miss(Device::new(0, [0xee; 32], &TRANSPORT, node.addr, node.connector.clone()).open(now).await);
	miss(Device::new(0, secret(0), &[0x77; 32], node.addr, node.connector.clone()).open(now).await);
	assert_eq!((node.totals().stranger_proof, node.totals().proofs_accepted), (5, 0));
	// A proof under TLS 1.2: "`tls`: WebSocket inside TLS 1.3", and a client ends its attempt unless TLS 1.3 was negotiated.
	let (_, mut roots) = (rustls::crypto::ring::default_provider().install_default(), RootCertStore::empty());
	roots.add(CertificateDer::from_pem_file(node.dir.join("cert.pem")).unwrap()).unwrap();
	let old = TlsConnector::from(Arc::new(ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12]).with_root_certificates(roots).with_no_client_auth()));
	let (answer, _) = play(old.connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(node.addr).await.unwrap()).await.unwrap(), &[Step::Send(upgrade(PATH, &token(0)))], SECOND).await;
	miss(String::from_utf8_lossy(&answer).into_owned());
	assert_eq!(node.totals().stranger_proof, 6);
	// What the replay rule refuses: a timestamp outside the window on either side, and a token that was accepted before.
	let mut a = node.device(0);
	miss(a.open(now - WINDOW - 5).await);
	miss(a.open(now + WINDOW + 5).await);
	assert!(a.open(now).await.starts_with("HTTP/1.1 101 "));
	miss(node.ask(&upgrade(PATH, &a.token)).await.0);
	let totals = node.totals();
	assert_eq!((totals.refused_window, totals.refused_seen, totals.proofs_accepted, totals.pending), (2, 1, 1, 1), "{totals:?}");
	// What the limits refuse. "A device may have 2 pending sessions, and further proofs are refused while it has."
	let mut again = node.device(0);
	assert!(again.open(now).await.starts_with("HTTP/1.1 101 "));
	miss(node.device(0).open(now).await);
	assert_eq!(node.totals().refused_pending, 1);
	// "Session: New proofs are refused and take the unauthenticated path": a pool of two with two sessions in it.
	let (mut b, mut c) = (node.device(1), node.device(2));
	b.connect(time).await;
	c.connect(time).await;
	miss(node.device(3).open(now).await);
	assert_eq!((node.totals().refused_pool, node.totals().sessions), (1, 2));
	// Every one of them was relayed, and none was told apart from a stranger's miss.
	assert_eq!((node.totals().relays, node.totals().decoy_down), (11, 0), "{:?}", node.totals());
	node.engine.shutdown().await;
}

// "Accepted proofs per device: burst 16, then 1 a second", and "accepted proofs per source: burst 256, then 32 a second", which a config may set. Sessions are opened and closed one after another until a proof is the origin's miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_and_a_source_have_an_allowance_of_accepted_proofs() {
	let time = time!();
	let node = launch("device-rate", time, |_| {}).await;
	let (mut a, started, mut taken) = (node.device(0), Instant::now(), 0u64);
	while a.open(time.secs()).await.starts_with("HTTP/1.1 101 ") {
		taken += 1;
		a.io = None;
		eventually("a pending session did not end with its connection", || node.totals().pending == 0).await;
		assert!(taken < 64, "the device's allowance never ended");
	}
	// Sixteen at once, and one more for every second the loop took.
	assert!((16..=17 + started.elapsed().as_secs()).contains(&taken), "{taken} proofs were accepted in {:?}", started.elapsed());
	assert_eq!((node.totals().proofs_accepted, node.totals().refused_device_rate, node.totals().ended_closed), (taken, 1, taken));
	node.engine.shutdown().await;
	// A source with an allowance of two: the third device from the same address is refused for the address and for nothing of its own.
	let node = launch("source-rate", time, |doc| doc["replay"] = json!({"per_source": {"burst": 2, "rate": 1}})).await;
	let (mut b, mut c, mut d, mut e) = (node.device(1), node.device(2), node.device(3), node.device(4));
	assert!(b.open(time.secs()).await.starts_with("HTTP/1.1 101 ") && c.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert!(d.open(time.secs()).await.starts_with("HTTP/1.1 404 "));
	assert_eq!((node.totals().refused_source_rate, node.totals().proofs_accepted), (1, 2));
	// Another source has its own.
	e.from = IpAddr::from([127, 0, 0, 77]);
	assert!(e.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	node.engine.shutdown().await;
}

// "A proof is accepted once, including across restarts": after a clean stop the cache is read back, and after a kill every timestamp the node may have accepted is at or below its floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spent_proof_stays_spent_across_restarts() {
	let time = time!();
	let node = launch("restart", time, |_| {}).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let (spent, mut doc, dir, site, connector) = (a.token.clone(), node.doc.clone(), node.dir.clone(), node.site, node.connector.clone());
	node.engine.shutdown().await;
	// An engine that has stopped still holds its listeners, as a process that is about to go does, so the node that starts again on the same files listens elsewhere.
	let ask = |addr: SocketAddr, token: String| {
		let connector = connector.clone();
		async move {String::from_utf8_lossy(&play(connector.connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(addr).await.unwrap()).await.unwrap(), &[Step::Send(upgrade(PATH, &token))], SECOND).await.0).into_owned()}
	};
	let addr = listen();
	doc["inbounds"][0]["transports"][0]["listen"] = json!(addr.to_string());
	let again = start(&doc, &dir, time).await.unwrap();
	assert!(ask(addr, spent.clone()).await.starts_with("HTTP/1.1 404 "));
	assert_eq!((again.stream().refused_seen, again.replay().unwrap().entries), (1, 1));
	// A fresh proof is taken at once after a clean stop, and then the node is killed: nothing is written, and the engine goes as a process does.
	b.node = addr;
	assert!(b.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let (later, addr) = (b.token.clone(), listen());
	drop(again);
	doc["inbounds"][0]["transports"][0]["listen"] = json!(addr.to_string());
	let killed = start(&doc, &dir, time).await.unwrap();
	assert!(ask(addr, later).await.starts_with("HTTP/1.1 404 ") && ask(addr, spent).await.starts_with("HTTP/1.1 404 "));
	assert_eq!((killed.stream().refused_floor, killed.replay().unwrap().entries), (2, 0));
	killed.shutdown().await;
	drop(site);
}

// "A proof that is valid in every other way and lies above the limit asks for a limit 20 s above its timestamp. On a stream transport the proof waits for that write to end, and is then asked again."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_above_the_limit_waits_for_the_write_and_is_accepted() {
	let time = time!();
	let node = launch("raise", time, |_| {}).await;
	let (mut a, limit) = (node.device(0), node.engine.replay().unwrap().limit);
	// A device whose clock is 40 seconds ahead: above the limit, which is 20 seconds above the clock at the most, and inside the window.
	assert!(time.secs() + 40 > limit);
	assert!(a.open(time.secs() + 40).await.starts_with("HTTP/1.1 101 "));
	let (totals, replay) = (node.totals(), node.engine.replay().unwrap());
	assert_eq!((totals.proofs_waited, totals.proofs_accepted, totals.refused_limit), (1, 1, 0), "{totals:?}");
	assert!(replay.limit >= time.secs() + 40, "the limit is {} and the proof was at {}", replay.limit, time.secs() + 40);
	// The same token again is spent like any other.
	assert!(node.ask(&upgrade(PATH, &a.token)).await.0.starts_with("HTTP/1.1 404 "));
	node.engine.shutdown().await;
}

/// A config for `Bench`: the document of a node whose listener a harness drives without sockets.
fn bench() -> String {document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap()).to_string()}

// "If the deadline passes first it is refused": a node whose replay file is never written keeps the proof for the write deadline and then hands the connection to the origin with every byte it sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proof_whose_limit_is_not_written_in_time_goes_to_the_origin_unchanged() {
	let mut bench = Bench::new(&bench(), Pools {sessions: 4, undecided: 4, per_source: 4, relayed: 4}, OffsetDateTime::now_utc).unwrap();
	let client = proof::Client::new(&proof::public_key(&TRANSPORT), &secret(0), &public(&NODE), &public(&KEYS[0]));
	let request = upgrade(PATH, &client.prove(Name::Tls, OffsetDateTime::now_utc().unix_timestamp() as u64 + 40, &mut random).unwrap().token);
	let ((mut peer, _), started) = (bench.connect("192.0.2.1:4000".parse().unwrap()), Instant::now());
	peer.write_all(&request).await.unwrap();
	let mut origin = loop {
		if let Some(origin) = bench.origin() {break origin}
		tokio::time::sleep(Duration::from_millis(5)).await;
	};
	let mut forwarded = vec![0u8; request.len()];
	origin.read_exact(&mut forwarded).await.unwrap();
	assert!(forwarded == request && started.elapsed() >= Duration::from_millis(1900), "forwarded after {:?}", started.elapsed());
	assert_eq!((bench.totals().refused_limit, bench.totals().proofs_waited, bench.totals().relayed, bench.totals().pending), (1, 1, 1, 0));
	// With the timer running, the same kind of proof is accepted when the write has ended.
	let ((mut peer, _), mut answer) = (bench.connect("192.0.2.1:4001".parse().unwrap()), [0u8; 12]);
	peer.write_all(&upgrade(PATH, &client.prove(Name::Tls, OffsetDateTime::now_utc().unix_timestamp() as u64 + 40, &mut random).unwrap().token)).await.unwrap();
	tokio::time::sleep(Duration::from_millis(200)).await;
	bench.tick();
	peer.read_exact(&mut answer).await.unwrap();
	assert_eq!((&answer[..], bench.totals().proofs_accepted, bench.totals().pending), (&b"HTTP/1.1 101"[..], 1, 1));
}

// Protocol overview, "Rotation": "An inbound may have two transport keys at once. The node tries a proof against both", and "a device may have two secrets in the config at once. When the old one is removed, sessions opened with it are dropped within one second".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_keys_and_device_secrets_are_rotated_without_a_gap() {
	let time = time!();
	let mut node = launch("rotation", time, |_| {}).await;
	let mut old = node.device(0);
	old.connect(time).await;
	// Both keys: a proof sealed to either is accepted.
	node.reload(|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&ROTATED), text(&TRANSPORT)])).await;
	let (mut b, mut c) = (node.device(1), Device::new(2, secret(2), &ROTATED, node.addr, node.connector.clone()));
	b.connect(time).await;
	c.connect(time).await;
	// With both keys in the config no session ends: the one from before the first reload is as it was.
	assert_eq!((old.leaves(40001).await.as_deref(), node.totals().sessions, node.totals().ended_revoked), (Some("main"), 3, 0));
	// The old key is retired: "When a node transport key is removed, sessions opened with it are dropped within one second, by the same path." The keys of a session's chunks come from the key its proof was sealed to, so whoever holds a key that leaked holds those too. The session that was opened under the new key stays, and a token sealed to the old one opens no more.
	let retired = Instant::now();
	node.reload(|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&ROTATED)])).await;
	assert!(old.ends(SECOND).await && b.ends(SECOND).await && retired.elapsed() < SECOND, "the sessions of a removed transport key were still there after {:?}", retired.elapsed());
	assert_eq!((c.leaves(40006).await.as_deref(), c.closed, node.totals().sessions, node.totals().ended_revoked), (Some("main"), false, 1, 2));
	assert!(node.device(3).open(time.secs()).await.starts_with("HTTP/1.1 404 "));
	assert!(Device::new(3, secret(3), &ROTATED, node.addr, node.connector.clone()).open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	// The devices that lost their session come back under the new key.
	let mut old = Device::new(0, secret(0), &ROTATED, node.addr, node.connector.clone());
	old.connect(time).await;
	// A second secret for device c, which opens a session with it next to the one it has. The tunnel of the device is one tunnel, and its newest handshake is on the new session.
	let newer = [0xb2; 32];
	node.reload(|doc| doc["users"][2]["devices"][0]["transport_secrets"] = json!([text(&secret(2)), text(&newer)])).await;
	assert_eq!(c.leaves(40002).await.as_deref(), Some("main"));
	let mut renewed = Device::new(2, newer, &ROTATED, node.addr, node.connector.clone());
	renewed.connect(time).await;
	assert_eq!((c.closed, node.totals().sessions), (false, 3));
	// The old secret is removed: the session it opened ends within a second, with the close every session ends with, and the others stay.
	let removed = Instant::now();
	node.reload(|doc| doc["users"][2]["devices"][0]["transport_secrets"] = json!([text(&newer)])).await;
	assert!(c.ends(SECOND).await && removed.elapsed() < SECOND, "the session of a removed secret was still there after {:?}", removed.elapsed());
	assert_eq!((renewed.leaves(40003).await.as_deref(), old.leaves(40004).await.as_deref()), (Some("main"), Some("main")));
	assert_eq!((node.totals().sessions, node.totals().ended_revoked), (2, 3));
	assert!(Device::new(2, secret(2), &ROTATED, node.addr, node.connector.clone()).open(time.secs()).await.starts_with("HTTP/1.1 404 "));
	node.engine.shutdown().await;
}

// One cut-off path for every transport: whatever takes a device's access away ends its sessions within a second, and nothing of the connection reaches the tunnel after that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_cut_off_ends_the_session_within_a_second() {
	let time = time!();
	let mut node = launch("cut", time, |doc| {
		doc["users"][3]["expires_at"] = json!((time.now)().replace_nanosecond(0).unwrap().checked_add(time::Duration::seconds(30)).unwrap().format(&time::format_description::well_known::Rfc3339).unwrap());
		doc["users"][4]["quota_bytes"] = json!(600);
	}).await;
	let mut devices: Vec<Device> = (0..5).map(|n| node.device(n)).collect();
	for device in &mut devices {device.connect(time).await}
	assert_eq!(node.totals().sessions, 5);
	// A user who is disabled.
	let cut = Instant::now();
	node.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	assert!(devices[0].ends(SECOND).await && cut.elapsed() < SECOND, "disabled: {:?}", cut.elapsed());
	// A device that is removed with its user, and one whose WireGuard preshared key changes: any device the new config does not have as it was.
	let cut = Instant::now();
	node.reload(|doc| {
		doc["users"].as_array_mut().unwrap().remove(1);
		doc["users"][1]["devices"][0]["preshared_key"] = json!(text(&[0x44; 32]));
	}).await;
	assert!(devices[1].ends(SECOND).await && devices[2].ends(SECOND).await && cut.elapsed() < SECOND, "removed and rekeyed: {:?}", cut.elapsed());
	// A user whose time is over: the clock passes `expires_at`.
	let cut = Instant::now();
	time.ahead.fetch_add(31, Ordering::SeqCst);
	assert!(devices[3].ends(2 * SECOND).await && cut.elapsed() < 2 * SECOND, "expired: {:?}", cut.elapsed());
	// A user who runs out of quota: the packet that takes them over it is their last.
	let cut = Instant::now();
	for sport in 42000..42004 {
		if devices[4].closed {break}
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), vec![0u8; 0]);
		syn.syn = true;
		PacketBuilder::ipv4(address(4), PUBLIC, 64).tcp_header(syn).write(&mut out, &[0u8; 200]).unwrap();
		devices[4].send(&out).await;
	}
	assert!(devices[4].ends(2 * SECOND).await && cut.elapsed() < 2 * SECOND, "quota: {:?}", cut.elapsed());
	let totals = node.totals();
	assert_eq!((totals.sessions, totals.ended_revoked), (0, 5), "{totals:?}");
	// None of them is taken again: each proof is the origin's miss from here on.
	for n in [0, 1, 3, 4] {assert!(node.device(n).open(time.secs()).await.starts_with("HTTP/1.1 404 "), "device {n} was taken again")}
	node.engine.shutdown().await;
}

// "Binding. A session belongs to the one device its proof named. Test: device A's proof followed by device B's initiation yields no handshake response, and the session ends at the first tunnel packet deadline."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_carries_only_the_tunnel_of_the_device_its_proof_named() {
	let time = time!();
	let node = launch("binding", time, |_| {}).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let foreign = b.initiation();
	a.put(&[&foreign]).await;
	assert_eq!((a.chunk(QUIET).await, a.closed, node.totals().pending, node.totals().tunnel), (None, false, 1, 1));
	// B's own session is B's: its tunnel comes up there, and A's pending session is not helped by it.
	b.connect(time).await;
	assert_eq!((node.totals().sessions, node.totals().pending, node.engine.peers(Some("a"))[0].handshake.is_some()), (1, 1, false));
	// A data packet of B's tunnel on A's session is nobody's either.
	let stray = b.sealed(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 3, 10, 7, 0, 1]);
	a.put(&[&stray]).await;
	assert_eq!((a.chunk(QUIET).await, node.totals().tunnel, node.totals().pending), (None, 2, 1));
	// "A pending session that is not established within the first tunnel packet deadline is ended."
	time.ahead.fetch_add(11, Ordering::SeqCst);
	assert!(a.ends(2 * SECOND).await);
	assert_eq!((node.totals().ended_deadline, node.totals().pending, node.totals().sessions), (1, 0, 1));
	node.engine.shutdown().await;
}

// "A connection is in one of four states, each with its own pool, so that pressure from strangers lands on strangers first. Strangers may displace strangers. Nothing a stranger does displaces a session."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pressure_from_strangers_lands_on_strangers() {
	let time = time!();
	let node = launch_at("pools", time, patient().await, |doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 2, "undecided": 4, "undecided_per_source": 2, "relayed": 3})).await;
	let from = |last: u8| IpAddr::from([127, 0, 0, last]);
	let mut a = node.device(0);
	a.connect(time).await;
	// "The same happens to a source's oldest undecided connection when that source reaches its share": two silent connections of one source are that source's share, and a third decides the first, which is relayed with the nothing it sent.
	let (mut first, _second) = (node.dial(from(2)).await, node.dial(from(2)).await);
	eventually("the undecided pool did not take two connections", || node.totals().undecided == 2).await;
	let _third = node.dial(from(2)).await;
	eventually("a source above its share displaced nobody", || node.totals().stranger_displaced == 1 && node.totals().relayed == 1 && node.totals().undecided == 2).await;
	// It is the origin's connection now: its request is answered by the origin.
	first.write_all(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	let mut answer = vec![0u8; 15];
	first.read_exact(&mut answer).await.unwrap();
	assert_eq!(answer, b"HTTP/1.1 200 OK");
	// "The oldest undecided connection is decided as not a user at once": the pool of four holds two of source 2, and two more sources fill it. A connection that is still inside its TLS handshake has nothing to relay and is closed.
	let mut stalled = TcpStream::connect(node.addr).await.unwrap();
	let _others = (node.dial(from(3)).await, node.dial(from(4)).await);
	eventually("the pool did not displace its oldest", || node.totals().undecided == 4 && node.totals().stranger_displaced == 2).await;
	let _more = (node.dial(from(5)).await, node.dial(from(6)).await, node.dial(from(7)).await);
	eventually("a handshake was not displaced", || node.totals().handshake_displaced == 1).await;
	assert_eq!(timeout(SECOND, stalled.read(&mut [0u8; 16])).await.unwrap().unwrap(), 0, "a displaced handshake was not closed");
	// "Relayed: the relayed connection that has been idle longest is closed. If none has been idle for the time in the table of numbers, the oldest is closed." The pool of three is full by now, and `first` is its oldest.
	eventually("the relayed pool is not full, or closed nobody for room", || node.totals().relayed == 3 && node.totals().relays_evicted == 1).await;
	let (rest, closed) = play(first, &[], SECOND).await;
	assert!(closed && rest.ends_with(PAGE.as_bytes()), "the oldest relayed connection was not closed for room");
	// Through all of it the user's session was never touched, and a second device still finds its place.
	assert_eq!((a.leaves(40005).await.as_deref(), node.totals().sessions), (Some("main"), 1));
	let mut b = node.device(1);
	b.connect(time).await;
	assert_eq!((node.totals().sessions, node.totals().undecided <= 4, node.totals().relayed <= 3), (2, true, true), "{:?}", node.totals());
	node.engine.shutdown().await;
}

// "When the pool is full, the relayed connection that has been idle longest is closed." With every connection idle for more than a minute, the one that was used last stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relayed_connection_that_was_idle_longest_makes_room() {
	let time = time!();
	// An origin that keeps a quiet connection for as long as this test takes.
	let node = launch_at("idlest", time, patient().await, |doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"relayed": 2})).await;
	let get = b"GET /again HTTP/1.1\r\nHost: node.test\r\n\r\n";
	let (mut one, mut two, mut answer) = (node.dial(Ipv4Addr::LOCALHOST.into()).await, node.dial(Ipv4Addr::LOCALHOST.into()).await, vec![0u8; 4096]);
	for io in [&mut one, &mut two] {
		io.write_all(get).await.unwrap();
		assert!(io.read(&mut answer).await.unwrap() > 0);
	}
	// A minute and a half later the first is used again, so the second is the one that was idle longest.
	time.ahead.fetch_add(90, Ordering::SeqCst);
	one.write_all(get).await.unwrap();
	assert!(one.read(&mut answer).await.unwrap() > 0);
	let mut three = node.dial(Ipv4Addr::LOCALHOST.into()).await;
	three.write_all(get).await.unwrap();
	assert!(three.read(&mut answer).await.unwrap() > 0);
	assert_eq!(timeout(SECOND, two.read(&mut answer)).await.map(|read| read.unwrap_or(0)).unwrap_or(1), 0, "the idlest connection was not the one that was closed");
	one.write_all(get).await.unwrap();
	assert!(one.read(&mut answer).await.unwrap() > 0);
	assert_eq!((node.totals().relays_evicted, node.totals().relayed), (1, 2));
	node.engine.shutdown().await;
}

/// An opening packet of `udp-obfs` for device `n` around `datagram`, sent to `to` from a socket of its own, which comes back with the keys of the session.
async fn obfs(n: usize, datagram: &[u8], to: SocketAddr, at: u64) -> (UdpSocket, udp_obfs::Sender, udp_obfs::Receiver) {
	let (sock, mut packet, padding) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), Vec::new(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap());
	let keys = udp_obfs::Client::new(&secret(n), &public(&NODE)).open(at, datagram, &padding, 1390 + udp_obfs::OVERHEAD, &mut random, &mut packet).unwrap();
	sock.send_to(&packet, to).await.unwrap();
	(sock, udp_obfs::Sender::new(keys.c2s, padding), udp_obfs::Receiver::new(keys.s2c))
}

// "Pending sessions per device: 2" and "Sessions per device: 8" are the node's limits and not a transport's: a device's `udp-obfs` and `tls` sessions are counted together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_limits_of_a_device_hold_across_udp_obfs_and_tls() {
	let (time, datagrams) = (time!(), listen());
	let node = launch("across", time, |doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "udp-obfs", "listen": datagrams.to_string()}))).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	// One pending session over each transport: an opening packet around another device's initiation, and a proof with nothing behind it.
	let foreign = b.initiation();
	let _pending = obfs(0, &foreign, datagrams, time.secs()).await;
	eventually("the opening packet opened no pending session", || node.engine.obfs().pending == 1).await;
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	// The device has its two. A third proof is refused on either transport, for the same reason.
	assert!(node.device(0).open(time.secs()).await.starts_with("HTTP/1.1 404 "));
	let _refused = obfs(0, &foreign, datagrams, time.secs()).await;
	eventually("a third pending session was not refused on both transports", || node.totals().refused_pending == 1 && node.engine.obfs().pending_full == 1).await;
	assert_eq!((node.totals().pending, node.engine.obfs().pending), (1, 1));
	// Both end at their deadline, and the device opens eight sessions: four over each transport, each with a handshake of its own.
	time.ahead.fetch_add(11, Ordering::SeqCst);
	eventually("the pending sessions did not end", || node.totals().pending == 0 && node.engine.obfs().pending == 0).await;
	let (mut held, mut streams) = (Vec::new(), Vec::new());
	for _ in 0..4 {
		let init = a.initiation();
		let (sock, mut tx, mut rx) = obfs(0, &init, datagrams, time.secs()).await;
		let (mut packet, mut scratch, mut out) = (vec![0u8; 2048], Vec::new(), vec![0u8; 2048]);
		let (count, _) = timeout(SECOND, sock.recv_from(&mut packet)).await.expect("no first answer over udp-obfs").unwrap();
		let response = rx.open(&packet[..count], &mut scratch).unwrap().expect("a padding-only first answer").to_vec();
		let TunnResult::WriteToNetwork(keepalive) = a.tunn.decapsulate(None, &response, &mut out) else {panic!("no handshake response")};
		let (keepalive, mut sealed) = (keepalive.to_vec(), Vec::new());
		tx.seal(Some(&keepalive), false, 1390 + udp_obfs::OVERHEAD, &mut random, &mut sealed).unwrap();
		sock.send_to(&sealed, datagrams).await.unwrap();
		held.push(sock);
	}
	for _ in 0..4 {
		let mut device = Device::new(0, secret(0), &TRANSPORT, node.addr, node.connector.clone());
		std::mem::swap(&mut device.tunn, &mut a.tunn);
		device.connect(time).await;
		std::mem::swap(&mut device.tunn, &mut a.tunn);
		streams.push(device);
	}
	eventually("the device does not have its eight sessions", || node.engine.obfs().sessions + node.totals().sessions == 8).await;
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions), (4, 4));
	// "A device at its own session limit replaces its own oldest session, but only once the new session is established": the ninth, over `tls`, takes the place of the oldest, which is one of `udp-obfs`.
	let mut ninth = Device::new(0, secret(0), &TRANSPORT, node.addr, node.connector.clone());
	std::mem::swap(&mut ninth.tunn, &mut a.tunn);
	assert!(ninth.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions, node.totals().pending), (4, 4, 1));
	let init = ninth.initiation();
	ninth.put(&[&init]).await;
	assert!(ninth.chunk(SECOND).await.is_some_and(|answer| answer.len() == 1));
	eventually("the ninth session displaced nothing", || node.engine.obfs().ended_displaced == 1).await;
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions, node.totals().ended_displaced), (3, 5, 0));
	node.engine.shutdown().await;
}

// "On `tls`, `ws` and `fronted` every chunk has a number, so any chunk that opens at the expected number is activity, padding-only chunks included", and "the node ends a session with no activity for 300 s".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_lives_by_its_chunks_and_ends_when_it_is_idle() {
	let time = time!();
	let node = launch("idle", time, |_| {}).await;
	let mut a = node.device(0);
	a.connect(time).await;
	assert_eq!(a.chunk(Duration::from_secs(4)).await, Some(Vec::new()), "the keepalive that ended the handshake was not echoed");
	// Two hundred seconds of silence, a padding-only chunk, two hundred more: the session is still there, because the chunk was activity.
	node.advance(200).await;
	a.put(&[]).await;
	tokio::time::sleep(Duration::from_millis(300)).await;
	node.advance(200).await;
	tokio::time::sleep(Duration::from_millis(1300)).await;
	assert_eq!((node.totals().sessions, a.closed), (1, false));
	// An idle keepalive of the device gets a chunk back: the echo, "unless it sent something else in that time", which the keepalive of the node's own WireGuard may be.
	let keepalive = a.sealed(&[]);
	a.put(&[&keepalive]).await;
	assert!(a.chunk(Duration::from_secs(4)).await.is_some_and(|chunk| chunk.iter().all(|datagram| datagram.len() == 32)));
	// Three hundred seconds with nothing end it, with the one close.
	node.advance(301).await;
	assert!(a.ends(2 * SECOND).await);
	assert_eq!((node.totals().ended_idle, node.totals().sessions), (1, 0));
	node.engine.shutdown().await;
}

// "A chunk that does not decrypt, or that decrypts and is invalid, ends the session on `tls` and `ws`", and "a message longer than 16,016 bytes, a text message or a fragmented message ends the session", each with the close every session ends with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_session_does_not_allow_ends_it_the_same_way() {
	let time = time!();
	let node = launch("invalid", time, |_| {}).await;
	let breaks: Vec<(&str, Vec<u8>)> = vec![
		("a chunk that does not open", {
			let mut out = Vec::new();
			websocket::frame(BINARY, &[7u8; 64], Some([1, 2, 3, 4]), &mut out);
			out
		}),
		("a text message", {
			let mut out = Vec::new();
			websocket::frame(websocket::TEXT, b"hello", Some([1, 2, 3, 4]), &mut out);
			out
		}),
		("a message in pieces", vec![0x02, 0x81, 1, 2, 3, 4, 0]),
		("a message above 16,016 bytes", vec![0x82, 0xfe, 0x3e, 0x91, 1, 2, 3, 4]),
		("a frame without a mask", vec![0x82, 0x01, 0x00]),
		("a reserved bit", vec![0xc2, 0x80, 1, 2, 3, 4]),
	];
	for (round, (case, bytes)) in breaks.iter().enumerate() {
		let mut device = node.device(round % 5);
		device.connect(time).await;
		device.io.as_mut().unwrap().write_all(bytes).await.unwrap();
		assert!(device.ends(SECOND).await, "{case}: the session stayed");
		eventually("an ended session stayed in the table", || node.totals().sessions == 0).await;
		assert_eq!(node.totals().ended_invalid, round as u64 + 1, "{case}");
	}
	// "A received ping is answered with a pong", and a head that is no WebSocket upgrade closes with no HTTP answer: no status line of the node's own is ever sent.
	let (mut a, mut ping) = (node.device(5), Vec::new());
	a.connect(time).await;
	websocket::frame(websocket::PING, b"still there", Some([9, 9, 9, 9]), &mut ping);
	a.io.as_mut().unwrap().write_all(&ping).await.unwrap();
	let (mut read, pong) = (vec![0u8; 4096], [&[0x8a, 11][..], b"still there"].concat());
	while !a.buf.windows(pong.len()).any(|window| window == pong) {
		let count = timeout(Duration::from_secs(4), a.io.as_mut().unwrap().read(&mut read)).await.expect("no pong").unwrap();
		a.buf.extend_from_slice(&read[..count]);
	}
	let token = node.device(0).prover.prove(Name::Tls, time.secs(), &mut random).unwrap().token;
	let (answer, closed) = node.ask(format!("GET {PATH}?{token} HTTP/1.1\r\nHost: node.test\r\n\r\n").as_bytes()).await;
	assert_eq!((answer.as_str(), closed, node.totals().head_refused), ("", true, 1));
	node.engine.shutdown().await;
}

// "If the origin could not be reached, close the peer's connection, count it as `decoy_down`, and log at warn at most once a minute. A broken origin never affects a user."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decoy_that_is_down_closes_strangers_and_never_touches_a_user() {
	let time = time!();
	// An origin nobody listens at: the port of a listener that is gone.
	let gone = site().await;
	let (addr, listen_again) = (gone.addr, gone.addr);
	let node = launch_at("down", time, gone, |_| {}).await;
	node.site.task.abort();
	eventually("the origin did not go away", || std::net::TcpStream::connect(addr).is_err()).await;
	let (answer, closed) = node.ask(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await;
	assert_eq!((answer.as_str(), closed), ("", true));
	assert!(node.totals().decoy_down == 1 && logged("its decoy origin cannot be reached"));
	// A user connects as ever. Its upgrade answer carries only `Date` of the list while the origin's fields are not known: "If that request fails, the node sends only `Date` from the list."
	let mut a = node.device(0);
	a.connect(time).await;
	assert_eq!(a.leaves(40006).await.as_deref(), Some("main"));
	// The origin comes back: strangers are answered again, and that is said once.
	let _back = site_on(TcpListener::bind(listen_again).await.unwrap(), Duration::ZERO, HEAD);
	assert!(node.ask(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.0.starts_with("HTTP/1.1 200 OK"));
	assert!(logged("its decoy origin is reached again") && node.totals().decoy_down == 1);
	node.engine.shutdown().await;
}

// The fields of the upgrade answer while the origin has not answered the node's own request, and once it has: learnt at start, again at a reload, and tried again while it fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_upgrade_answer_takes_its_fields_from_the_origin_and_only_date_without_it() {
	let time = time!();
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (origin, spare) = (listener.local_addr().unwrap(), site().await);
	drop(listener);
	let mut node = launch_at("fields", time, spare, |doc| {
		doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!(format!("http://{origin}"));
		doc["inbounds"][0]["upgrade_headers"] = json!(["X-Site", "Date", "Server", "X-Absent"]);
	}).await;
	eventually("the node did not try to learn the fields", || node.totals().upgrade_learn_failed > 0).await;
	let mut a = node.device(0);
	let lines: Vec<String> = a.open(time.secs()).await.trim_end().split("\r\n").map(str::to_string).collect();
	assert!(lines.len() == 6 && lines[1].starts_with("Date: ") && lines[2] == "Upgrade: websocket" && logged("the decoy origin did not answer the node's own request"), "{lines:?}");
	// The origin is there at the next reload. Its fields are written in the order of the list, each as the origin spelled it, with the first value of one it sent twice, and one it did not send is left out.
	let _site = site_on(TcpListener::bind(origin).await.unwrap(), Duration::ZERO, HEAD);
	node.reload(|doc| doc["notices"] = json!([{"text": "learn again"}])).await;
	eventually("the node did not learn the fields at the reload", || node.totals().upgrade_learned > 0).await;
	let lines: Vec<String> = node.device(1).open(time.secs()).await.trim_end().split("\r\n").map(str::to_string).collect();
	assert!(lines.len() == 8 && lines[1] == "x-site: one" && lines[2].starts_with("date: ") && lines[3] == "server: decoy/1.0" && lines[4] == "Upgrade: websocket", "{lines:?}");
	node.engine.shutdown().await;
}

// An origin that is slow, one that closes what it accepts, and one that sends everything back to the node: a stranger gets what such an origin gives, the node stays inside its pools, and a user never notices.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_origin_that_is_slow_closes_early_or_loops_back_harms_no_user() {
	let time = time!();
	// Slow: every answer takes a second, and arrives.
	let slow = launch_at("slow", time, site_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), SECOND, HEAD), |_| {}).await;
	let (asked, mut a) = (Instant::now(), slow.device(0));
	a.connect(time).await;
	assert!(asked.elapsed() < SECOND, "a user waited for the origin");
	let (answer, _) = play(slow.dial(Ipv4Addr::LOCALHOST.into()).await, &[Step::Send(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n".to_vec())], 3 * SECOND).await;
	assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 OK"));
	slow.engine.shutdown().await;
	// Closing early: an origin that accepts every connection and closes it at once. The stranger is closed the same way, with nothing.
	let closer = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let mut early = site().await;
	early.addr = closer.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((stream, _)) = closer.accept().await {drop(stream)}
	});
	let early = launch_at("early", time, early, |_| {}).await;
	assert_eq!(early.ask(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await, (String::new(), true));
	// "An origin that closes connections before a request arrives can therefore cost a user an attempt": the origin's close and the user's request line race, and the line wins whenever it is there first. The user is in after a few attempts at the most, and such an origin is not a web server.
	let (mut b, mut attempts) = (early.device(1), 1);
	while !b.try_connect(time.secs()).await {
		attempts += 1;
		assert!(attempts <= 8, "a user did not get past an origin that closes at once");
	}
	assert_eq!((b.leaves(40007).await.as_deref(), early.totals().decoy_down), (Some("main"), 0));
	early.engine.shutdown().await;
	// Looping back: an origin that hands every connection to the node's own listener, as a web server with a wrong rule would. What comes back to the stranger is whatever the node's TLS says to plain HTTP, the chain ends there, and the pools empty again.
	let (forwarder, target) = (TcpListener::bind("127.0.0.1:0").await.unwrap(), Arc::new(Mutex::new(None::<SocketAddr>)));
	let mut looped = site().await;
	looped.addr = forwarder.local_addr().unwrap();
	tokio::spawn({
		let target = target.clone();
		async move {
			while let Ok((mut from, _)) = forwarder.accept().await {
				let Some(to) = *target.lock().unwrap() else {continue};
				tokio::spawn(async move {
					let Ok(mut to) = TcpStream::connect(to).await else {return};
					let _ = tokio::io::copy_bidirectional(&mut from, &mut to).await;
				});
			}
		}
	});
	let looped = launch_at("loop", time, looped, |_| {}).await;
	*target.lock().unwrap() = Some(looped.addr);
	let (answer, closed) = looped.ask(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await;
	assert!(closed && !answer.contains("HTTP/1.1"), "{answer:?}");
	let mut c = looped.device(2);
	c.connect(time).await;
	assert_eq!(c.leaves(40008).await.as_deref(), Some("main"));
	eventually("a loop left connections behind", || looped.totals().relayed == 0 && looped.totals().undecided == 0).await;
	// An origin that is the node's own listen address is refused before any of that. With a wildcard listen address that is an origin on this host for certain: loopback, or the wildcard itself. One on another host with the same port is the operator's own web server like any other.
	let errors = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = looped.doc.clone();
		change(&mut doc);
		Config::parse(doc.to_string().as_bytes()).map_or_else(|error| vec![error.path], |config| config.validate(false).errors.iter().map(|error| error.path.clone()).collect())
	};
	let own = looped.addr;
	assert_eq!(errors(&|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!(format!("http://{own}"))), ["inbounds[0].transports[0].decoy.origin"]);
	assert_eq!(errors(&|doc| {
		doc["inbounds"][0]["transports"][0]["listen"] = json!(format!("0.0.0.0:{}", own.port()));
		doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!(format!("http://127.0.0.1:{}", own.port()));
	}), ["inbounds[0].transports[0].decoy.origin"]);
	for (listen, origin, refused) in [("0.0.0.0", "0.0.0.0", true), ("127.0.0.1", "0.0.0.0", true), ("127.0.0.1", "[::ffff:127.0.0.1]", true), ("[::]", "127.0.0.1", true), ("[::]", "[::1]", true), ("0.0.0.0", "[::1]", false), ("0.0.0.0", "10.1.2.3", false), ("[::]", "10.1.2.3", false), ("127.0.0.1", "127.0.0.2", false)] {
		let found = errors(&|doc| {
			doc["inbounds"][0]["transports"][0]["listen"] = json!(format!("{listen}:{}", own.port()));
			doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!(format!("http://{origin}:{}", own.port()));
		});
		assert_eq!(found, if refused {vec!["inbounds[0].transports[0].decoy.origin".to_string()]} else {Vec::new()}, "listening at {listen} with the origin at {origin}");
	}
	looped.engine.shutdown().await;
}

// "`decoy.proxy_protocol` makes the node send the PROXY protocol header, version 2, at the start of every connection it opens to the origin, so that the operator's site sees the stranger's address."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_origin_is_told_the_address_of_the_stranger() {
	let time = time!();
	// An origin that reads the header before anything else, and says in its answer which source it named.
	let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let mut told = site().await;
	told.addr = origin.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = origin.accept().await {
			tokio::spawn(async move {
				let (mut header, mut request) = ([0u8; 28], [0u8; 4096]);
				if stream.read_exact(&mut header).await.is_err() || header[..16] != *b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c" || !stream.read(&mut request).await.is_ok_and(|count| count > 0) {return}
				let body = format!("{}.{}.{}.{}:{}", header[16], header[17], header[18], header[19], u16::from_be_bytes([header[24], header[25]]));
				let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nServer: told\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
			});
		}
	});
	let node = launch_at("proxy-protocol", time, told, |doc| doc["inbounds"][0]["transports"][0]["decoy"]["proxy_protocol"] = json!(true)).await;
	// The node's own request carries the header too, with the node's address, or the origin would not have answered it.
	eventually("the node did not learn the fields through the header", || node.totals().upgrade_learned > 0).await;
	let mut io = node.dial(IpAddr::from([127, 0, 0, 9])).await;
	let from = io.get_ref().0.local_addr().unwrap();
	io.write_all(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	let (answer, closed) = play(io, &[], SECOND).await;
	assert!(closed && String::from_utf8_lossy(&answer).ends_with(&format!("\r\n\r\n{from}")), "{}", String::from_utf8_lossy(&answer));
	node.engine.shutdown().await;
}

// "TLS certificate: by the operator." New files are read at the next reload of the config file, sessions that are established stay, and a file that cannot be used leaves the certificate that runs in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_certificate_is_served_from_the_next_reload_and_no_session_ends_for_it() {
	let time = time!();
	let node = launch("certificate", time, |_| {}).await;
	let config = node.dir.join("config.json");
	std::fs::write(&config, node.doc.to_string()).unwrap();
	#[cfg(unix)]
	std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	// The file holds what runs, so the first reload from it changes nothing but what is read from the host again.
	let mut a = node.device(0);
	a.connect(time).await;
	node.engine.reload(node.doc.to_string().into_bytes(), None).await.unwrap();
	let (before, renewed) = (node.connector.clone(), certify(&node.dir));
	// Until the reload the old certificate is served.
	assert!(renewed.connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(node.addr).await.unwrap()).await.is_err());
	node.engine.reload_from(&config).await.unwrap();
	assert!(before.connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(node.addr).await.unwrap()).await.is_err());
	let mut b = Device::new(1, secret(1), &TRANSPORT, node.addr, renewed.clone());
	b.connect(time).await;
	assert_eq!((a.leaves(40009).await.as_deref(), b.leaves(40010).await.as_deref(), node.totals().sessions), (Some("main"), Some("main"), 2));
	// A key file that is no key: the reload is refused, and the certificate that runs keeps running.
	std::fs::write(node.dir.join("key.pem"), "not a key").unwrap();
	assert!(node.engine.reload_from(&config).await.is_err());
	let mut c = Device::new(2, secret(2), &TRANSPORT, node.addr, renewed);
	c.connect(time).await;
	assert_eq!((a.closed, node.totals().sessions), (false, 3));
	node.engine.shutdown().await;
}

// What a reload does to a listener: a change that leaves a transport as it was keeps its sessions, a new path ends them and is the path from then on, and a transport that is gone takes its listener and everything on it away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_keeps_what_is_as_it_was_and_ends_what_is_not() {
	let time = time!();
	let mut node = launch_at("reload", time, patient().await, |_| {}).await;
	eventually("the node did not learn the header fields of its origin", || node.totals().upgrade_learned > 0).await;
	let mut a = node.device(0);
	a.connect(time).await;
	let mut stranger = node.dial(Ipv4Addr::LOCALHOST.into()).await;
	stranger.write_all(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	let mut answer = vec![0u8; 4096];
	assert!(stranger.read(&mut answer).await.unwrap() > 0);
	// Another user, other pools, another cookie and other header fields: the transport is the same transport.
	node.reload(|doc| {
		doc["users"][5]["enabled"] = json!(false);
		doc["inbounds"][0]["upgrade_cookie"] = json!("visit");
		doc["inbounds"][0]["upgrade_headers"] = json!(["Date"]);
		doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 64, "relayed": 64});
	}).await;
	assert_eq!((a.leaves(40011).await.as_deref(), node.totals().sessions, node.totals().relayed), (Some("main"), 1, 1));
	assert!(node.device(1).open(time.secs()).await.contains("\r\nSet-Cookie: visit="));
	// A new path: the session that came in by the old one ends, the old path is the origin's from here on, and the new one is the transport's.
	node.reload(|doc| doc["inbounds"][0]["transports"][0]["path"] = json!("/assets/app-renamed.js")).await;
	assert!(a.ends(SECOND).await && node.totals().ended_unserved >= 1);
	assert!(node.device(2).open(time.secs()).await.starts_with("HTTP/1.1 404 ") && node.device(2).open_as("/assets/app-renamed.js", Name::Tls, time.secs()).await.starts_with("HTTP/1.1 101 "));
	// The relayed connection was nobody's session and stays the origin's.
	stranger.write_all(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	assert!(stranger.read(&mut answer).await.unwrap() > 0);
	// The transport goes: its listener closes with every connection it holds, and the address is free again.
	let (free, was) = (listen(), node.addr);
	node.reload(|doc| doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": free.to_string()}])).await;
	assert_eq!(timeout(SECOND, stranger.read(&mut answer)).await.map(|read| read.unwrap_or(0)).unwrap_or(1), 0, "a relayed connection outlived its listener");
	eventually("the listener is still there", || std::net::TcpStream::connect(was).is_err()).await;
	assert_eq!((node.totals().sessions, node.totals().pending, node.totals().relayed, node.totals().undecided), (0, 0, 0, 0));
	node.engine.shutdown().await;
}

/// Asks for answers of `sizes` bytes all at once, each through the node and of the origin itself, by peers that read as `fetch` says. The sizes that came short through the node, each with how much was missing.
async fn short(node: &Node, sizes: &[usize], keep: bool, stall: Duration, quiet: Duration, pace: Duration) -> Vec<(usize, usize)> {
	let runs: Vec<_> = sizes.iter().enumerate().map(|(at, body)| {
		let (body, origin, connector, addr) = (*body, node.site.addr, node.connector.clone(), node.addr);
		tokio::spawn(async move {
			// From eight sources, so that none is near its share of the undecided pool.
			let socket = TcpSocket::new_v4().unwrap();
			socket.bind(SocketAddr::from(([127, 0, 0, 2 + (at % 8) as u8], 0))).unwrap();
			let tls = connector.connect(ServerName::try_from("node.test").unwrap(), socket.connect(addr).await.unwrap()).await.unwrap();
			let (through, direct) = tokio::join!(fetch(tls, body, keep, stall, quiet, pace), fetch(TcpStream::connect(origin).await.unwrap(), body, keep, stall, quiet, pace));
			(body, through, direct)
		})
	}).collect();
	let mut short = Vec::new();
	for run in runs {
		let (body, through, direct) = run.await.unwrap();
		assert_eq!(direct, BULK_HEAD + body, "the origin itself did not deliver {body} bytes");
		if through != direct {short.push((body, direct - through))}
	}
	short
}

// "Every byte the origin sent is written out to the peer before the node waits for anything else." The origin keeps every connection here, so nothing else brings the end of an answer: no next answer, and no close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_end_of_an_answer_never_stays_in_the_node() {
	let time = time!();
	let node = launch_at("whole", time, raw().await, |_| {}).await;
	// Large answers one after another, to a peer that reads at once and to one that waits first.
	for (body, stall) in [(256 * 1024, 0), (1024 * 1024, 0), (4 * 1024 * 1024, 0), (8 * 1024 * 1024, 0), (8 * 1024 * 1024, 2)] {
		let cut = short(&node, &[body], true, Duration::from_secs(stall), Duration::from_secs(6), Duration::from_millis(2)).await;
		assert!(cut.is_empty(), "an answer to a peer that waited {stall} s did not arrive whole, as (size, missing): {cut:?}");
	}
	// Many sizes at once, to peers that read three seconds late: whatever the size, some of the answer was still in the node when the origin went quiet.
	let sizes: Vec<usize> = (1..=80).map(|step| step * 48 * 1024).collect();
	let cut = short(&node, &sizes, true, Duration::from_secs(3), Duration::from_secs(6), Duration::ZERO).await;
	assert!(cut.is_empty(), "answers whose end never came, as (size, missing): {cut:?}");
	// The first size that blocks: how much of an answer the origin gets rid of while the peer reads nothing. An answer just below that is the one whose end sits in the node while the origin has nothing more to say.
	let (before, mut hold) = (node.site.written.load(Ordering::SeqCst), node.dial(Ipv4Addr::LOCALHOST.into()).await);
	hold.write_all(b"GET /big/268435456/keep HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	let (mut blocked, mut steady) = (0, Instant::now());
	while steady.elapsed() < Duration::from_millis(700) {
		let written = node.site.written.load(Ordering::SeqCst) - before;
		if written != blocked {(blocked, steady) = (written, Instant::now())}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	drop(hold);
	eprintln!("an answer blocks at {blocked} bytes when the peer reads nothing");
	assert!(blocked > 0 && blocked < 128 << 20, "the origin wrote {blocked} bytes to a peer that reads nothing");
	// Sizes in steps of 8 kB from well below that to above it, to peers that wait and then read slowly.
	let sizes: Vec<usize> = (0..88).map(|step| (blocked.saturating_sub(640 * 1024) / 8192 + step) * 8192).filter(|size| *size > 0).collect();
	let cut = short(&node, &sizes, true, Duration::from_secs(2), Duration::from_secs(6), Duration::from_millis(3)).await;
	assert!(cut.is_empty(), "answers to a slow reader whose end never came, as (size, missing): {cut:?}");
	node.engine.shutdown().await;
}

// "When the origin closes, the peer is closed only after all of it has been handed on": the origin closes behind each answer, and the peers read eight seconds later. Only the pool's own rule ends a relayed connection before its peer has taken everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_the_origin_closed_behind_reaches_a_peer_that_reads_late() {
	let time = time!();
	let node = launch_at("closed-behind", time, raw().await, |_| {}).await;
	let sizes: Vec<usize> = (1..=60).map(|step| step * 96 * 1024).collect();
	let cut = short(&node, &sizes, false, Duration::from_secs(8), Duration::from_secs(3), Duration::ZERO).await;
	assert!(cut.is_empty(), "answers that were cut, as (size, missing): {cut:?}");
	eventually("a relayed connection outlived its end", || node.totals().relayed == 0).await;
	node.engine.shutdown().await;
}

// "If the origin sends anything or closes the connection while the request line is not complete, the connection is decided as not a user at that moment." A peer that never finishes its line, and one that sends nothing, are given up by the node when the origin gives them up, with what the origin said, and not at the node's own ten seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_origin_that_gives_a_connection_up_decides_it_at_that_moment() {
	let time = time!();
	for (kind, site, says) in [("an origin that says 408 and closes", raw().await, true), ("an origin that closes", site().await, false)] {
		let node = launch_at(if says {"gives-up-408"} else {"gives-up"}, time, site, |_| {}).await;
		for (case, steps) in [("a request line that is never finished", vec![Step::Send(b"GET / HT".to_vec())]), ("nothing at all", vec![])] {
			let through = async {
				let started = Instant::now();
				let (got, closed) = play(node.dial(Ipv4Addr::LOCALHOST.into()).await, &steps, 6 * SECOND).await;
				(got, closed, started.elapsed())
			};
			let direct = async {
				let started = Instant::now();
				let (got, closed) = play(TcpStream::connect(node.site.addr).await.unwrap(), &steps, 6 * SECOND).await;
				(got, closed, started.elapsed())
			};
			let ((got, closed, took), (expected, ended, origin_took)) = tokio::join!(through, direct);
			eprintln!("{kind}, {case}: closed after {took:?} through the node and after {origin_took:?} by the origin itself");
			assert_eq!((undated(&got), closed), (undated(&expected), ended), "{kind}, {case}: the node on the left, the origin on the right");
			assert!(ended && expected.starts_with(b"HTTP/1.1 408 ") == says, "{kind}, {case}: the origin itself gave {:?}", String::from_utf8_lossy(&expected));
			assert!(took.abs_diff(origin_took) < Duration::from_millis(300) && took < 4 * SECOND, "{kind}, {case}: closed after {took:?} through the node and after {origin_took:?} by the origin itself");
		}
		assert_eq!((node.totals().stranger_origin, node.totals().stranger_slow, node.totals().relays), (2, 0, 2), "{kind}: {:?}", node.totals());
		node.engine.shutdown().await;
	}
}

/// Sends `request` and reads to the end of the connection. What came, and the error that ended it where that was no close.
async fn until_end<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, request: &[u8]) -> (Vec<u8>, Option<std::io::ErrorKind>) {
	let (_, _, mut got, mut buf) = (io.write_all(request).await, io.flush().await, Vec::new(), vec![0u8; 4096]);
	loop {
		match timeout(3 * SECOND, io.read(&mut buf)).await {
			Ok(Ok(read)) if read > 0 => got.extend_from_slice(&buf[..read]),
			Ok(Ok(_)) => return (got, None),
			Ok(Err(e)) => return (got, Some(e.kind())),
			Err(_) => return (got, Some(std::io::ErrorKind::TimedOut)),
		}
	}
}

// What the origin does to a connection beyond answering a request: an upgrade of its own, a reset, and an answer before the body was read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_an_origin_does_to_a_connection_is_what_the_peer_gets() {
	let time = time!();
	let node = launch_at("origin-does", time, raw().await, |_| {}).await;
	let origin = node.site.addr;
	// A WebSocket endpoint of the site's own. Its upgrade is no proof, so it is the origin's: the `101` is the origin's, and both directions go on for as long as the two sides talk.
	let steps = [Step::Send(format!("GET /echo HTTP/1.1\r\nHost: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n").into_bytes()), Step::Wait(300), Step::Send(b"one".to_vec()), Step::Wait(300), Step::Send(b"two".to_vec()), Step::Wait(300), Step::Finish];
	let ((got, closed), (expected, ended)) = tokio::join!(play(node.dial(Ipv4Addr::LOCALHOST.into()).await, &steps, 2 * SECOND), play(TcpStream::connect(origin).await.unwrap(), &steps, 2 * SECOND));
	assert_eq!((String::from_utf8_lossy(&got), closed), (String::from_utf8_lossy(&expected), ended));
	assert!(closed && got.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n") && got.ends_with(b"\r\n\r\nonetwo") && !got.windows(10).any(|window| window == b"Set-Cookie"), "{}", String::from_utf8_lossy(&got));
	// An origin that resets its connection in the middle of an answer: the peer has what came before, and then a reset, not a close.
	let get = b"GET /reset HTTP/1.1\r\nHost: node.test\r\n\r\n";
	let (through, direct) = tokio::join!(until_end(node.dial(Ipv4Addr::LOCALHOST.into()).await, get), until_end(TcpStream::connect(origin).await.unwrap(), get));
	assert_eq!((String::from_utf8_lossy(&through.0), through.1), (String::from_utf8_lossy(&direct.0), direct.1));
	assert!(direct.0.ends_with(b"half of it") && direct.1 == Some(std::io::ErrorKind::ConnectionReset), "the origin itself: {direct:?}");
	// An answer before the body was read, to a peer that is still sending. The origin takes the rest of the upload, as a web server with a lingering close does. The node closes when the origin has closed its side, so the peer's upload ends in a reset there: the answer arrives whole or not at all, and the test says which.
	let upload = [Step::Send([format!("POST /early HTTP/1.1\r\nHost: node.test\r\nContent-Length: {}\r\n\r\n", 4 << 20).into_bytes(), vec![0x62; 4 << 20]].concat())];
	let ((got, closed), (expected, ended)) = tokio::join!(play(node.dial(Ipv4Addr::LOCALHOST.into()).await, &upload, 2 * SECOND), play(TcpStream::connect(origin).await.unwrap(), &upload, 2 * SECOND));
	eprintln!("an early answer to an upload: {} of {} bytes of it came through the node", got.len(), expected.len());
	assert!(ended && closed && expected.starts_with(b"HTTP/1.1 413 ") && (got == expected || got.is_empty()), "{:?} through the node, {:?} from the origin itself", String::from_utf8_lossy(&got), String::from_utf8_lossy(&expected));
	// A client that speaks only HTTP/2 gets no TLS session at all: the node offers `http/1.1` and nothing else, which is one of the things `tls` does not hide.
	let (_, mut roots) = (rustls::crypto::ring::default_provider().install_default(), RootCertStore::empty());
	roots.add(CertificateDer::from_pem_file(node.dir.join("cert.pem")).unwrap()).unwrap();
	let mut only = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
	only.alpn_protocols = vec![b"h2".to_vec()];
	assert!(TlsConnector::from(Arc::new(only)).connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(node.addr).await.unwrap()).await.is_err(), "a client that offered only h2 was taken");
	eventually("a handshake that failed was not counted", || node.totals().handshake_failed == 1).await;
	assert_eq!((node.totals().relays, node.totals().decoy_down), (3, 0), "{:?}", node.totals());
	node.engine.shutdown().await;
}

// "Stream transports and TCP inside TCP": a device may hold two sessions at once, and the node sends what it has for the device on the one it heard the device on last. It does not spread flows over the sessions by a hash of its own: a session whose connection has died without a close would take its share of the flows with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_two_sessions_is_answered_on_the_one_it_was_heard_on_last() {
	let time = time!();
	let node = launch("two-sessions", time, |_| {}).await;
	let mut a = node.device(0);
	a.connect(time).await;
	let mut first = (a.io.take(), a.tx.take(), a.rx.take(), std::mem::take(&mut a.buf));
	// A second connection of the same device, and one packet of the tunnel it already has: no new handshake, and the session is established by it.
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let keepalive = a.sealed(&[]);
	a.put(&[&keepalive]).await;
	eventually("the second session was not established", || node.totals().sessions == 2).await;
	assert_eq!(a.leaves(40020).await.as_deref(), Some("main"), "no answer on the second session");
	// The device speaks on the first again, and the answers come there. Both sessions are alive through all of it. The pause lets the node read the last packet of the one session before the first of the other arrives: "last" is the order the node heard them in.
	tokio::time::sleep(Duration::from_millis(200)).await;
	(first.0, first.1, first.2, first.3) = (std::mem::replace(&mut a.io, first.0.take()), std::mem::replace(&mut a.tx, first.1.take()), std::mem::replace(&mut a.rx, first.2.take()), std::mem::replace(&mut a.buf, std::mem::take(&mut first.3)));
	assert_eq!(a.leaves(40021).await.as_deref(), Some("main"), "no answer on the first session: {:?}", node.totals());
	assert_eq!((a.closed, node.totals().sessions, node.totals().established, node.engine.peers(Some("a")).len()), (false, 2, 2, 1));
	// And on the second once more.
	tokio::time::sleep(Duration::from_millis(200)).await;
	(a.io, a.tx, a.rx, a.buf) = (first.0.take(), first.1.take(), first.2.take(), std::mem::take(&mut first.3));
	assert_eq!((a.leaves(40022).await.as_deref(), a.closed), (Some("main"), false), "no answer on the second session again");
	node.engine.shutdown().await;
}

#[test]
fn the_new_keys_are_validated_shown_and_compared() {
	let doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap());
	let errors = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		Config::parse(doc.to_string().as_bytes()).map_or_else(|error| vec![error.path], |config| config.validate(false).errors.iter().map(|error| error.path.clone()).collect())
	};
	assert_eq!(errors(&|_| {}), Vec::<String>::new());
	let transport = "inbounds[0].transports[0]";
	for (case, change, path) in [
		("tls on a wireguard inbound", &(|doc: &mut Value| {
			doc["inbounds"][0]["type"] = json!("wireguard");
			for user in doc["users"].as_array_mut().unwrap() {user["devices"][0].as_object_mut().unwrap().remove("transport_secrets");}
		}) as &dyn Fn(&mut Value), format!("{transport}.type")),
		("no transport key", &|doc| drop(doc["inbounds"][0].as_object_mut().unwrap().remove("transport_keys")), "inbounds[0].transport_keys".to_string()),
		("three transport keys", &|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&[1; 32]), text(&[2; 32]), text(&[3; 32])]), "inbounds[0].transport_keys".to_string()),
		("the same transport key twice", &|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&TRANSPORT), text(&TRANSPORT)]), "inbounds[0].transport_keys[1]".to_string()),
		("a transport key that is the inbound's WireGuard key", &|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&NODE)]), "inbounds[0].transport_keys[0]".to_string()),
		("a transport key that is a device's public key", &|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&public(&KEYS[0]))]), "inbounds[0].transport_keys[0]".to_string()),
		("a transport secret that is the transport key", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&TRANSPORT)]), "users[0].devices[0].transport_secrets[0]".to_string()),
		("no cookie name", &|doc| drop(doc["inbounds"][0].as_object_mut().unwrap().remove("upgrade_cookie")), "inbounds[0].upgrade_cookie".to_string()),
		("a cookie name that is no token", &|doc| doc["inbounds"][0]["upgrade_cookie"] = json!("a b"), "inbounds[0].upgrade_cookie".to_string()),
		("a field the node writes itself", &|doc| doc["inbounds"][0]["upgrade_headers"] = json!(["Server", "set-cookie"]), "inbounds[0].upgrade_headers[1]".to_string()),
		("a field that changes how the answer is read", &|doc| doc["inbounds"][0]["upgrade_headers"] = json!(["Content-Length"]), "inbounds[0].upgrade_headers[0]".to_string()),
		("a field twice", &|doc| doc["inbounds"][0]["upgrade_headers"] = json!(["Server", "server"]), "inbounds[0].upgrade_headers[1]".to_string()),
		("a field name that is none", &|doc| doc["inbounds"][0]["upgrade_headers"] = json!(["X Y"]), "inbounds[0].upgrade_headers[0]".to_string()),
		("a path of 11 characters", &|doc| doc["inbounds"][0]["transports"][0]["path"] = json!("/0123456789"), format!("{transport}.path")),
		("a path with a query", &|doc| doc["inbounds"][0]["transports"][0]["path"] = json!("/assets/app?x=1"), format!("{transport}.path")),
		("no path", &|doc| drop(doc["inbounds"][0]["transports"][0].as_object_mut().unwrap().remove("path")), transport.to_string()),
		("no certificate", &|doc| drop(doc["inbounds"][0]["transports"][0].as_object_mut().unwrap().remove("tls")), transport.to_string()),
		("a certificate outside the config's directory", &|doc| doc["inbounds"][0]["transports"][0]["tls"]["key"] = json!("../key.pem"), format!("{transport}.tls.key")),
		// "`self_signed: true` may stand instead of `cert` and `key`", and nothing else does.
		("self_signed beside the files", &|doc| doc["inbounds"][0]["transports"][0]["tls"]["self_signed"] = json!(true), format!("{transport}.tls")),
		("self_signed with a key alone", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": true, "key": "key.pem"}), format!("{transport}.tls")),
		("self_signed false", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": false}), format!("{transport}.tls")),
		("a name beside the files", &|doc| doc["inbounds"][0]["transports"][0]["tls"]["name"] = json!("www.example.org"), format!("{transport}.tls")),
		("a name that is no host name", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": true, "name": "not a name"}), format!("{transport}.tls.name")),
		("a name that is an address", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": true, "name": "192.0.2.1"}), format!("{transport}.tls.name")),
		("a name of 65 characters", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": true, "name": format!("{}.org", "a".repeat(61))}), format!("{transport}.tls.name")),
		("a name that is no string", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": true, "name": 7}), format!("{transport}.tls.name")),
		("self_signed that is no boolean", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"self_signed": "true"}), format!("{transport}.tls.self_signed")),
		("no decoy", &|doc| drop(doc["inbounds"][0]["transports"][0].as_object_mut().unwrap().remove("decoy")), transport.to_string()),
		("a decoy with no origin", &|doc| doc["inbounds"][0]["transports"][0]["decoy"] = json!({}), format!("{transport}.decoy")),
		("an origin over https", &|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("https://127.0.0.1:8443"), format!("{transport}.decoy.origin")),
		("an origin with a path", &|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://127.0.0.1:8080/site"), format!("{transport}.decoy.origin")),
		("an origin that is somebody's name with a user", &|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://user@example.com"), format!("{transport}.decoy.origin")),
		("an origin that is the listener", &|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://127.0.0.1:443"), format!("{transport}.decoy.origin")),
		("a decoy key nobody knows", &|doc| doc["inbounds"][0]["transports"][0]["decoy"]["sni"] = json!("example.com"), format!("{transport}.decoy")),
		("no undecided connection", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"undecided": 0}), format!("{transport}.limits.undecided")),
		("a share above the pool", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"undecided": 8, "undecided_per_source": 9}), format!("{transport}.limits.undecided_per_source")),
		("too many relayed connections", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"relayed": 65537}), format!("{transport}.limits.relayed")),
		("a decoy on udp", &|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "udp", "listen": "127.0.0.1:51820", "decoy": {"origin": "http://127.0.0.1:8080"}})), "inbounds[0].transports[1]".to_string()),
		("the ws of a wireguard inbound, which has no decoy", &|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws", "listen": "127.0.0.1:8081", "path": "/assets/app-ws-path.js"})), "inbounds[0].transports[1].type".to_string()),
		("fronted without its keys", &|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "fronted", "listen": "127.0.0.1:8081"})), "inbounds[0].transports[1]".to_string()),
		("the pools of the proxy path on a listener that has only direct peers", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"proxy_connections": 64}), format!("{transport}.limits.proxy_connections")),
		("the proxies of the proxy path on a listener that ends TLS", &|doc| doc["inbounds"][0]["transports"][0]["trusted_proxies"] = json!(["127.0.0.1"]), transport.to_string()),
		("two tls transports on one address with one path", &|doc| {
			let again = doc["inbounds"][0]["transports"][0].clone();
			doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(again);
		}, "inbounds[0].transports[1].listen".to_string()),
		("two tls transports on one address with two origins", &|doc| {
			let mut other = doc["inbounds"][0]["transports"][0].clone();
			(other["path"], other["decoy"]["origin"]) = (json!("/assets/app-second.js"), json!("http://127.0.0.1:8090"));
			doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(other);
		}, "inbounds[0].transports[1].listen".to_string()),
	] {assert_eq!(errors(change), [path], "{case}")}
	// Two paths on one address with one certificate, one origin and one set of pools are two transports of one listener.
	assert_eq!(errors(&|doc| {
		let mut other = doc["inbounds"][0]["transports"][0].clone();
		other["path"] = json!("/assets/app-second.js");
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(other);
	}), Vec::<String>::new());
	// An origin that is not on the host, or is a name, is a warning: it must be the operator's own.
	let warned = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		parsed(&doc).validate(false).warnings.iter().map(|warning| warning.path.clone()).collect()
	};
	assert_eq!((warned(&|_| {}), warned(&|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://[::1]:8080")), warned(&|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://10.1.2.3"))), (Vec::<String>::new(), Vec::new(), Vec::new()));
	assert_eq!(warned(&|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://198.51.100.7:8080")).len() + warned(&|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://8.8.8.8")).len(), 1);
	assert_eq!(warned(&|doc| doc["inbounds"][0]["transports"][0]["decoy"]["origin"] = json!("http://site.example.com:8080")), [format!("{transport}.decoy.origin")]);
	// A certificate the node makes itself is valid, and on an address others reach a warning: a prober sees it, and ordinary sites rarely have one.
	let own = |listen: &'static str| move |doc: &mut Value| (doc["inbounds"][0]["transports"][0]["tls"], doc["inbounds"][0]["transports"][0]["listen"]) = (json!({"self_signed": true}), json!(listen));
	assert_eq!((errors(&own("127.0.0.1:443")), warned(&own("127.0.0.1:443")), errors(&own("0.0.0.0:443")), warned(&own("0.0.0.0:443"))), (Vec::<String>::new(), Vec::new(), Vec::new(), vec![format!("{transport}.tls.self_signed")]));
	let mut written = doc.clone();
	own("127.0.0.1:443")(&mut written);
	assert_eq!(serde_json::to_value(parsed(&written)).unwrap()["inbounds"][0]["transports"][0]["tls"], json!({"self_signed": true}));
	// The operator's own name is a valid setting and is kept as written.
	written["inbounds"][0]["transports"][0]["tls"]["name"] = json!("www.example.org");
	assert_eq!((errors(&|doc| *doc = written.clone()), serde_json::to_value(parsed(&written)).unwrap()["inbounds"][0]["transports"][0]["tls"].clone()), (Vec::<String>::new(), json!({"self_signed": true, "name": "www.example.org"})));
	// What is set and never used is a warning, and the `mtu` of an inbound with `tls` alone is the plain default: no datagram of it has an envelope to make room for.
	let plain = |doc: &mut Value| doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": "127.0.0.1:51820"}]);
	assert_eq!((warned(&plain), parsed(&doc).inbounds[0].mtu()), (vec!["inbounds[0].transport_keys".to_string(), "inbounds[0].upgrade_cookie".to_string()], 1420));
	// A document the control API shows has a marker in the place of each transport key, which names its key and comes back as it.
	let (config, mut two) = (parsed(&doc), doc.clone());
	two["inbounds"][0]["transport_keys"] = json!([text(&ROTATED), text(&TRANSPORT)]);
	let (running, shown) = (parsed(&two), parsed(&two).redacted());
	let markers: Vec<String> = shown["inbounds"][0]["transport_keys"].as_array().unwrap().iter().map(|marker| marker.as_str().unwrap().to_string()).collect();
	assert!(markers.len() == 2 && markers[0] != markers[1] && markers.iter().all(|marker| marker.starts_with("<redacted:")) && shown["inbounds"][0]["private_key"] == REDACTED && !shown.to_string().contains(&text(&TRANSPORT)), "{markers:?}");
	let mut back = shown.clone();
	back["inbounds"][0]["transport_keys"] = json!([markers[1]]);
	let (kept, _) = Config::parse_keeping(back.to_string().as_bytes(), &running).unwrap();
	assert_eq!(kept.inbounds[0].transport_keys, config.inbounds[0].transport_keys);
	back["inbounds"][0]["transport_keys"] = json!(["<redacted:00000000>"]);
	assert_eq!(Config::parse_keeping(back.to_string().as_bytes(), &running).unwrap_err().errors[0].path, "inbounds[0].transport_keys[0]");
	// A change of the keys, the cookie or the header fields is a change of the inbound that restarts nothing, and the default list written out is no change at all.
	let between = |change: &dyn Fn(&mut Value)| {
		let mut next = doc.clone();
		change(&mut next);
		Diff::between(&config, &parsed(&next), OffsetDateTime::now_utc())
	};
	let rotated = between(&|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&ROTATED), text(&TRANSPORT)]));
	assert_eq!((rotated.inbounds.changed.len(), rotated.inbound_changes[0].restart, rotated.inbound_changes[0].transports_started.len()), (1, false, 0));
	assert_eq!((between(&|doc| doc["inbounds"][0]["upgrade_cookie"] = json!("other")).inbounds.changed.len(), between(&|doc| doc["inbounds"][0]["upgrade_headers"] = json!(["Server", "Date"])).is_empty()), (1, true));
	// A document that is written back holds the keys as they were given.
	let written = serde_json::to_value(parsed(&two)).unwrap();
	assert_eq!((&written["inbounds"][0]["transport_keys"], &written["inbounds"][0]["transports"][0], &written["inbounds"][0]["upgrade_cookie"]), (&two["inbounds"][0]["transport_keys"], &two["inbounds"][0]["transports"][0], &two["inbounds"][0]["upgrade_cookie"]));
}
