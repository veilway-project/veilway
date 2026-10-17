//! The `faketls` transport of a `veilway` inbound, end to end (borrowed-site page): a node that is started the way `veilway run` starts it, a real TLS 1.3 server on this machine as the site it borrows, and the client of `veilway-transport` with a boringtun peer.
//! Whoever is not a user must get from the node what the site itself gives, byte for byte. A hello that opens is never relayed: a replay, a clock that is off and a device the node does not know get a flight the node made, which nobody but the client can read.
//! The node's clock is each test's own. Every node has a replay file in a directory of its own, and the site is a local one: nothing here reaches the internet.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use ring::digest::{digest, SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use veilway_core::config::Config;
use veilway_core::{Engine, FakeTlsTotals, Options, Over};
use veilway_proto::proof;
use veilway_proto::subscription::payload::Padding;
use veilway_proto::subscription::Secret;
use veilway_proto::flight::{Flight, Wire};
use veilway_proto::tls13::{write_server_hello, Suite, HYBRID, KEM_CIPHERTEXT, X25519};
use veilway_transport::probe::{probe, Mode, Patience};
use veilway_transport::{faketls, flow, End, Ended, Env, Front, Kind, Link, Session, Source, State, Target, Unreachable, Want};

const GATEWAY: [u8; 4] = [10, 7, 0, 1];
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
// Keys and secrets of tests are fixed patterns, and no secret of anything real. Device `n` has the private key `KEYS[n]`, the tunnel address 10.7.0.(2 + n) and the transport secret `secret(n)`.
const NODE: [u8; 32] = [0x10; 32];
const KEYS: [[u8; 32]; 3] = [[0x21; 32], [0x22; 32], [0x23; 32]];
/// The transport key of the `faketls` transport, private half, and the one it is rotated to.
const TRANSPORT: [u8; 32] = [0x61; 32];
const ROTATED: [u8; 32] = [0x62; 32];
/// The name of the site, the only one a hello may carry.
const NAME: &str = "www.example.com";
const PAGE: &str = "<html>the borrowed site</html>\n";
const SECOND: Duration = Duration::from_secs(1);
/// What a quiet connection is given to stay quiet in.
const QUIET: Duration = Duration::from_millis(500);
const PLAIN: Kind = Kind::Packet {flow: 0, control: false};
/// How long the probes of a test node wait: the site of a test answers at once and ends a connection that is idle after 250 ms.
const QUICK: Patience = Patience {gap: Duration::from_millis(10), collect: Duration::from_millis(60), idle: Duration::from_millis(600), reaction: Duration::from_millis(600)};
/// How long the site of a test lets a connection that has finished its handshake sit idle before it closes it.
const SITE_IDLE: Duration = Duration::from_millis(250);
/// How long the site of a test waits to answer a `close_notify`.
const NOTIFY_DELAY: Duration = Duration::from_millis(200);
/// Port 0 is no listen port of a config, so every listener of a test node takes the next one from here.
static NEXT_PORT: AtomicU16 = AtomicU16::new(31000);
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

fn provider() -> Arc<rustls::crypto::CryptoProvider> {Arc::new(rustls::crypto::ring::default_provider())}

/// The site the node borrows: a real TLS 1.3 server (rustls) with a certificate for `NAME` that nobody but the site has, and one page. It answers a request and closes, the way a site does that has nothing to keep a connection for.
struct Site {addr: SocketAddr, der: CertificateDer<'static>, connections: Arc<AtomicUsize>, task: JoinHandle<()>}

impl Drop for Site {
	fn drop(&mut self) {self.task.abort()}
}

/// The same site, which waits `delay` before it answers a hello.
async fn site_after(delay: Duration) -> Site {
	let made = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
	let der = CertificateDer::from(made.cert.der().to_vec());
	let config = ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der.clone()], PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap()).unwrap();
	let (listener, connections) = (TcpListener::bind("127.0.0.1:0").await.unwrap(), Arc::new(AtomicUsize::new(0)));
	let (addr, acceptor) = (listener.local_addr().unwrap(), TlsAcceptor::from(Arc::new(config)));
	let task = tokio::spawn({
		let connections = connections.clone();
		async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else {return};
				connections.fetch_add(1, Ordering::SeqCst);
				let acceptor = acceptor.clone();
				tokio::spawn(async move {
					tokio::time::sleep(delay).await;
					let Ok(mut tls) = acceptor.accept(stream).await else {return};
					let (mut head, mut buf) = (Vec::new(), vec![0u8; 4096]);
					while !head.windows(4).any(|window| window == b"\r\n\r\n") {
						match timeout(SITE_IDLE, tls.read(&mut buf)).await {
							Ok(Ok(count)) if count > 0 => head.extend_from_slice(&buf[..count]),
							Err(_) => return drop(tls.shutdown().await),
						Ok(Ok(0)) => {
							tokio::time::sleep(NOTIFY_DELAY).await;
							return drop(tls.shutdown().await);
						}
							_ => return,
						}
					}
					let _ = tls.write_all(format!("HTTP/1.1 200 OK\r\nServer: site/1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAGE}", PAGE.len()).as_bytes()).await;
					let _ = tls.shutdown().await;
				});
			}
		}
	});
	Site {addr, der, connections, task}
}

/// A pipe between two ends that records what the end that dialled said, as it was handed on, and what came back to it. With `flip` set to a position, the next connection's byte at that position is changed on the way. What is recorded as seen is what the other end received.
struct Tap {addr: SocketAddr, seen: Arc<Mutex<Vec<Vec<u8>>>>, heard: Arc<Mutex<Vec<Vec<u8>>>>, flip: Arc<AtomicUsize>, task: JoinHandle<()>}

impl Drop for Tap {
	fn drop(&mut self) {self.task.abort()}
}

async fn tap(upstream: SocketAddr) -> Tap {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, seen, heard, flip) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::<Vec<u8>>::new())), Arc::new(Mutex::new(Vec::<Vec<u8>>::new())), Arc::new(AtomicUsize::new(0)));
	let task = tokio::spawn({
		let (seen, heard, flip) = (seen.clone(), heard.clone(), flip.clone());
		async move {
			loop {
				let Ok((client, _)) = listener.accept().await else {return};
				let (seen, heard, flip) = (seen.clone(), heard.clone(), flip.clone());
				tokio::spawn(async move {
					let Ok(up) = TcpStream::connect(upstream).await else {return};
					let at = {
						let mut seen = seen.lock().unwrap();
						seen.push(Vec::new());
						heard.lock().unwrap().push(Vec::new());
						seen.len() - 1
					};
					let ((mut from_client, mut to_client), (mut from_up, mut to_up)) = (client.into_split(), up.into_split());
					let (mut position, mut buf) = (0, vec![0u8; 65536]);
					let forward = async {
						loop {
							let count = match from_client.read(&mut buf).await {
								Ok(count) if count > 0 => count,
								_ => return drop(to_up.shutdown().await),
							};
							let at_flip = flip.load(Ordering::SeqCst);
							if at_flip > position && at_flip <= position + count {
								buf[at_flip - position - 1] ^= 0x01;
								flip.store(0, Ordering::SeqCst);
							}
							position += count;
							seen.lock().unwrap()[at].extend_from_slice(&buf[..count]);
							if to_up.write_all(&buf[..count]).await.is_err() {return}
						}
					};
					let back = async {
						let mut buf = vec![0u8; 65536];
						loop {
							match from_up.read(&mut buf).await {
								Ok(count) if count > 0 => {
									heard.lock().unwrap()[at].extend_from_slice(&buf[..count]);
									if to_client.write_all(&buf[..count]).await.is_err() {return}
								}
								_ => return drop(to_client.shutdown().await),
							}
						}
					};
					tokio::join!(forward, back);
				});
			}
		}
	});
	Tap {addr, seen, heard, flip, task}
}

/// A new directory for one test.
fn scratch(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-faketls-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// Writes the replay file a node leaves that was killed with this floor and this limit: a head without the clean mark and without entries, and its hash.
fn seed(path: &Path, floor: u64, limit: u64) {
	let body = [&b"VWREPLAY"[..], &1u32.to_be_bytes(), &[0; 4], &floor.to_be_bytes(), &limit.to_be_bytes(), &0u32.to_be_bytes()].concat();
	std::fs::write(path, [&body[..], digest(&SHA256, &body).as_ref()].concat()).unwrap();
}

/// A document with one `veilway` inbound `home` on 10.7.0.1/24 that is reached over `faketls` at `listen` and borrows the site at `site`, one exit through `proxy`, and the users `a` to `c` with one device each.
fn document(proxy: SocketAddr, listen: SocketAddr, site: SocketAddr) -> Value {
	let names = ["a", "b", "c"];
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transports": [{"type": "faketls", "listen": listen.to_string(), "transport_key": text(&TRANSPORT), "site": {"host": NAME, "address": site.to_string(), "acknowledged": true}}]}],
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

/// A node, the site it borrows with a tap between them, and a tap in front of it for the client to dial.
struct Node {engine: Engine, addr: SocketAddr, doc: Value, time: Time, site: Site, to_site: Tap, front: Tap}

/// Starts a node on `document` after `change` had its way with it. Its replay file is one a node left that was killed 100 seconds ago, so it takes proofs from its first moment.
async fn launch(test: &str, time: Time, change: impl FnOnce(&mut Value)) -> Node {launch_after(test, time, Duration::ZERO, change).await}

/// The same, with a site that waits `delay` before it answers a hello.
async fn launch_after(test: &str, time: Time, delay: Duration, change: impl FnOnce(&mut Value)) -> Node {
	LOGGING.call_once(|| tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_writer(|| Sink).init());
	let (dir, addr, site) = (scratch(test), listen(), site_after(delay).await);
	let to_site = tap(site.addr).await;
	let mut doc = document(proxy().await, addr, to_site.addr);
	change(&mut doc);
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let engine = veilway_core::start(&parsed(&doc), Options {now: time.now, replay: Some(dir.join("replay")), probes: QUICK, ..Options::new(&dir)}).await.unwrap();
	let front = tap(addr).await;
	let node = Node {engine, addr, doc, time, site, to_site, front};
	// The eight probes of the start are connections to the site too: the tests count what a connection of theirs does, so they are waited for and forgotten.
	eventually("the probes did not finish", || node.totals().probes + node.totals().probe_failed >= 8).await;
	node.to_site.seen.lock().unwrap().clear();
	node.to_site.heard.lock().unwrap().clear();
	node.site.connections.store(0, Ordering::SeqCst);
	node
}

impl Node {
	fn totals(&self) -> FakeTlsTotals {self.engine.faketls()}

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

	/// What the client library needs to reach the node: the candidate, which is the tap in front of it, and the node's key.
	fn target(&self, link: &Link) -> Target {Target::FakeTls {candidate: Front {address: self.front.addr, sni: Some(NAME.into()), host: String::new(), verify_name: None, pins: Vec::new(), ech: false, self_signed: false, http2: Default::default()}, client: faketls::client(link).unwrap()}}

	fn env(&self, ahead: i64) -> Env {
		let time = self.time;
		Env {device: Arc::new(move || time.secs()), now: Arc::new(move || time.secs().saturating_add_signed(ahead)), roots: Arc::new(RootCertStore::empty()), socket: None}
	}

	fn peer(&self, n: usize, link: &Link, ahead: i64) -> Peer {
		let (tunn, up, source) = wireguard(n);
		Peer {n, tunn, up, session: Session::open(link, self.target(link), self.env(ahead), source).unwrap(), inbox: VecDeque::new()}
	}
}

/// Waits for something the engine does on its own time.
async fn eventually(what: &str, done: impl Fn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(8);
	while !done() {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// What device `n` holds for the inbound, with the transport key of the node it is made for.
fn link(n: usize, transport: &[u8; 32]) -> Link {Link {inbound: public(&NODE), device: public(&KEYS[n]), secret: Secret::new(secret(n)), node: Some(proof::public_key(transport)), mtu: 1390, padding: Padding {wide_max: 1023, normal_max: 255, keepalive: 20_000..=40_000}}}

/// The WireGuard layer of device `n` as the library asks for it: a handshake initiation while the tunnel has no session, a keepalive once it has, which `up` says.
fn wireguard(n: usize) -> (Arc<Mutex<Tunn>>, Arc<std::sync::atomic::AtomicBool>, Source) {
	let (tunn, up) = (Arc::new(Mutex::new(Tunn::new(StaticSecret::from(KEYS[n]), PublicKey::from(public(&NODE)), None, None, 0, None))), Arc::new(std::sync::atomic::AtomicBool::new(false)));
	let source: Source = Arc::new(Mutex::new({
		let (tunn, up) = (tunn.clone(), up.clone());
		move |want| {
			let (mut tunn, mut out) = (tunn.lock().unwrap(), vec![0u8; 2048]);
			let made = match (want, up.load(Ordering::SeqCst)) {
				(Want::First, false) => tunn.format_handshake_initiation(&mut out, true),
				(Want::Keepalive, false) => return None,
				(_, true) => tunn.encapsulate(&[], &mut out),
			};
			if let TunnResult::WriteToNetwork(datagram) = made {Some(datagram.to_vec())} else {None}
		}
	}));
	(tunn, up, source)
}

fn segment(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	Some((tcp, if let PayloadSlice::Tcp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

/// A device: its WireGuard, and the one session of the library its datagrams travel on.
struct Peer {n: usize, tunn: Arc<Mutex<Tunn>>, up: Arc<std::sync::atomic::AtomicBool>, session: Session, inbox: VecDeque<Vec<u8>>}

impl Peer {
	/// Hands one WireGuard datagram of the node to the device's WireGuard, sends what that wants sent, and gives the IP packets that came out.
	fn take(&mut self, datagram: &[u8]) -> Vec<Vec<u8>> {
		let (mut input, mut packets) = (datagram, Vec::new());
		loop {
			let mut out = vec![0u8; 2048];
			let (reply, packet) = match self.tunn.lock().unwrap().decapsulate(None, input, &mut out) {
				TunnResult::WriteToNetwork(reply) => (Some(reply.to_vec()), None),
				TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => (None, Some(packet.to_vec())),
				_ => (None, None),
			};
			packets.extend(packet);
			let Some(reply) = reply else {return packets};
			// The node's handshake response: the tunnel has a session from here on.
			if datagram.first() == Some(&2) {self.up.store(true, Ordering::SeqCst)}
			self.session.send(reply, PLAIN);
			input = &[];
		}
	}

	/// Waits until the session is established and the tunnel has a session, or gives how the session ended.
	async fn connect(&mut self) -> Result<(), Ended> {
		let (deadline, mut watch) = (tokio::time::Instant::now() + Duration::from_secs(20), self.session.watch());
		loop {
			match self.session.state() {
				State::Established if self.up.load(Ordering::SeqCst) => return Ok(()),
				State::Ended(ended) => return Err(ended),
				_ => {}
			}
			tokio::select! {
				_ = watch.changed() => {}
				got = self.session.recv() => match got {
					Ok(datagram) => {
						let packets = self.take(&datagram);
						self.inbox.extend(packets);
					}
					Err(ended) => return Err(ended),
				},
				_ = tokio::time::sleep_until(deadline) => panic!("neither a session nor its end in 20 s"),
			}
		}
	}

	/// How the session ends, for one that is not expected to open.
	async fn ended(&mut self) -> Ended {self.connect().await.expect_err("a session that should not have opened")}

	/// One IP packet into the tunnel, marked with its flow.
	fn send(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn.lock().unwrap().encapsulate(packet, &mut out) else {panic!("the tunnel has no session to send under")};
		self.session.send(datagram.to_vec(), Kind::Packet {flow: flow(packet), control: false});
	}

	/// The next IP packet `wanted` picks, from the inbox or from the tunnel. Every other packet stays in the inbox.
	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let datagram = timeout(deadline.checked_duration_since(Instant::now())?, self.session.recv()).await.ok()?.ok()?;
			let mut found = None;
			for packet in self.take(&datagram) {
				if found.is_none() && wanted(&packet) {found = Some(packet)} else {self.inbox.push_back(packet)}
			}
			if found.is_some() {return found}
		}
	}

	/// Opens a TCP connection to `PUBLIC` from the device's tunnel address and reads what the exit's proxy says first. None when the SYN gets no answer.
	async fn leaves(&mut self, sport: u16) -> Option<String> {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out);
		let (answer, _) = segment(&self.recv(4 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (80, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		let (mut ack, mut out) = (TcpHeader::new(sport, 80, 1001, 65535), Vec::new());
		(ack.ack, ack.acknowledgment_number) = (true, answer.sequence_number.wrapping_add(1));
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(ack).write(&mut out, &[]).unwrap();
		self.send(&out);
		let (_, said) = segment(&self.recv(Duration::from_secs(6), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (80, sport) && !data.is_empty())).await?)?;
		let (mut rst, mut out) = (TcpHeader::new(sport, 80, 1001, 0), Vec::new());
		rst.rst = true;
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(rst).write(&mut out, &[]).unwrap();
		self.send(&out);
		Some(String::from_utf8(said).unwrap())
	}

	/// An echo request of `size` bytes to the gateway as an IP packet, and whether the reply of the same size came back.
	async fn ping(&mut self, size: usize, seq: u16) -> bool {
		let mut out = Vec::new();
		PacketBuilder::ipv4(address(self.n), GATEWAY, 64).icmpv4_echo_request(9, seq).write(&mut out, &vec![0x5a; size - 28]).unwrap();
		assert_eq!(out.len(), size);
		self.send(&out);
		self.recv(3 * SECOND, |packet| packet.len() == size && packet[9] == 1 && packet[20] == 0 && packet[26..28] == seq.to_be_bytes()).await.is_some()
	}
}

/// Sends `bytes` to `to` and reads until the connection ends or nothing came for `patience`. What came, and whether the other end closed.
async fn ask(to: SocketAddr, bytes: &[u8], patience: Duration) -> (Vec<u8>, bool) {
	let (mut io, mut got, mut buf) = (TcpStream::connect(to).await.unwrap(), Vec::new(), vec![0u8; 65536]);
	if !bytes.is_empty() {
		let _ = io.write_all(bytes).await;
		let _ = io.flush().await;
	}
	loop {
		match timeout(patience, io.read(&mut buf)).await {
			Ok(Ok(count)) if count > 0 => got.extend_from_slice(&buf[..count]),
			Ok(_) => return (got, true),
			Err(_) => return (got, false),
		}
	}
}

fn trusting(der: &CertificateDer<'static>) -> TlsConnector {
	let mut roots = RootCertStore::empty();
	roots.add(der.clone()).unwrap();
	TlsConnector::from(Arc::new(ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth()))
}

/// A site that speaks first: it says that it has waited long enough for a request and closes, the way a site with a short timer does, the moment a connection is made.
async fn eager() -> (SocketAddr, JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	(addr, tokio::spawn(async move {
		loop {
			let Ok((mut stream, _)) = listener.accept().await else {return};
			tokio::spawn(async move {
				let _ = stream.write_all(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n").await;
				let _ = stream.shutdown().await;
				let mut sink = [0u8; 256];
				while stream.read(&mut sink).await.is_ok_and(|count| count > 0) {}
			});
		}
	}))
}

/// The first TLS record of what a client sent, which is its hello.
fn record(sent: &[u8]) -> &[u8] {&sent[..5 + usize::from(u16::from_be_bytes([sent[3], sent[4]]))]}

/// Like `ask`, with the offset of every read from the moment the bytes were written.
async fn ask_timed(to: SocketAddr, bytes: &[u8], patience: Duration) -> (Vec<(Duration, Vec<u8>)>, bool) {
	let (mut io, mut got, mut buf) = (TcpStream::connect(to).await.unwrap(), Vec::new(), vec![0u8; 65536]);
	let started = Instant::now();
	let _ = io.write_all(bytes).await;
	loop {
		match timeout(patience, io.read(&mut buf)).await {
			Ok(Ok(count)) if count > 0 => got.push((started.elapsed(), buf[..count].to_vec())),
			Ok(_) => return (got, true),
			Err(_) => return (got, false),
		}
	}
}

/// Sends `first`, reads until nothing comes for `patience`, sends `second` and reads until the connection ends or 1.5 s pass. What came before, what came after, and whether the other end closed.
async fn ask_twice(to: SocketAddr, first: &[u8], second: &[u8], patience: Duration) -> (Vec<u8>, Vec<u8>, bool) {
	let (mut io, mut buf) = (TcpStream::connect(to).await.unwrap(), vec![0u8; 65536]);
	io.write_all(first).await.unwrap();
	let (mut one, mut two) = (Vec::new(), Vec::new());
	while let Ok(Ok(count)) = timeout(patience, io.read(&mut buf)).await {
		if count == 0 {return (one, two, true)}
		one.extend_from_slice(&buf[..count]);
	}
	io.write_all(second).await.unwrap();
	loop {
		match timeout(Duration::from_millis(1500), io.read(&mut buf)).await {
			Ok(Ok(count)) if count > 0 => two.extend_from_slice(&buf[..count]),
			Ok(_) => return (one, two, true),
			Err(_) => return (one, two, false),
		}
	}
}

/// What a site sent for a hello, as the library reads it, with at most `limit` encrypted records.
fn flight_of(sent: &[u8], hello: &[u8], limit: usize) -> Flight {
	Flight::read(&[(Duration::ZERO, sent.to_vec())], &hello[5 + 39..5 + 71], limit).unwrap_or_else(|| panic!("no flight in {} bytes starting {:02x?}", sent.len(), &sent[..sent.len().min(8)]))
}

/// A flight as a comparison between two takes it: the choices of the site and the records in order, not how the reads happened to cut them.
fn sizes(flight: &Flight) -> (Suite, u16, bool, Vec<Wire>) {(flight.suite, flight.group, flight.key_first, flight.bursts.iter().flat_map(|burst| burst.wire.clone()).collect())}

/// A site that is only a flight, for the sizes and the delay to be seen alone: it reads a hello, waits `wait`, writes a ServerHello of `suite` and `group`, the compatibility record and encrypted records of `sizes` in one write, and sits on the connection. What it writes cannot be read by anybody, so no probe of it succeeds.
async fn scripted(suite: Suite, group: u16, wait: Duration, sizes: Vec<usize>) -> (SocketAddr, JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	(addr, tokio::spawn(async move {
		loop {
			let Ok((mut stream, _)) = listener.accept().await else {return};
			let sizes = sizes.clone();
			tokio::spawn(async move {
				let mut hello = vec![0u8; 5];
				if stream.read_exact(&mut hello).await.is_err() {return}
				let mut rest = vec![0u8; usize::from(u16::from_be_bytes([hello[3], hello[4]]))];
				if stream.read_exact(&mut rest).await.is_err() {return}
				hello.extend_from_slice(&rest);
				tokio::time::sleep(wait).await;
				let message = write_server_hello(&hello[5 + 39..5 + 71], suite, group, false, &[7; 32], &vec![9u8; if group == X25519 {32} else {KEM_CIPHERTEXT + 32}]);
				let mut out = [&[22, 3, 3, (message.len() >> 8) as u8, message.len() as u8][..], &message, &[20, 3, 3, 0, 1, 1]].concat();
				for size in &sizes {out.extend_from_slice(&[&[23, 3, 3, (size >> 8) as u8, *size as u8][..], &vec![0x5a; *size]].concat())}
				let _ = stream.write_all(&out).await;
				let mut sink = [0u8; 256];
				while stream.read(&mut sink).await.is_ok_and(|count| count > 0) {}
			});
		}
	}))
}

/// A user's session, opened and closed, and the hello it began with.
async fn recorded(node: &Node) -> Vec<u8> {
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap_or_else(|ended| panic!("the session did not open: {ended:?}"));
	peer.session.close().await;
	record(&node.front.seen.lock().unwrap()[0]).to_vec()
}

/// Connections of strangers at once, enough to spend the burst of the budget for new connections to the site.
async fn exhaust(node: &Node) {
	let mut asks = Vec::new();
	for _ in 0..80 {
		let to = node.addr;
		asks.push(tokio::spawn(async move {ask(to, b"GET / HTTP/1.1\r\n\r\n", Duration::from_millis(300)).await}));
	}
	for ask in asks {ask.await.unwrap();}
}

/// A pipe in front of `upstream` that cuts what the upstream sends for a connection after its first `cut` bytes and waits `gap` before it sends the rest: a site whose flight comes in two bursts.
async fn stagger(upstream: SocketAddr, cut: usize, gap: Duration) -> (SocketAddr, JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	(addr, tokio::spawn(async move {
		loop {
			let Ok((client, _)) = listener.accept().await else {return};
			tokio::spawn(async move {
				let Ok(up) = TcpStream::connect(upstream).await else {return};
				let ((mut from_client, mut to_client), (mut from_up, mut to_up)) = (client.into_split(), up.into_split());
				let forward = async {
					let mut buf = vec![0u8; 65536];
					while let Ok(count) = from_client.read(&mut buf).await {
						if count == 0 || to_up.write_all(&buf[..count]).await.is_err() {break}
					}
					drop(to_up.shutdown().await);
				};
				let back = async {
					let (mut buf, mut sent) = (vec![0u8; 65536], 0);
					while let Ok(count) = from_up.read(&mut buf).await {
						if count == 0 {break}
						let head = cut.saturating_sub(sent).min(count);
						if head > 0 && head < count {
							if to_client.write_all(&buf[..head]).await.is_err() || to_client.flush().await.is_err() {return}
							tokio::time::sleep(gap).await;
						}
						if to_client.write_all(&buf[head..count]).await.is_err() || to_client.flush().await.is_err() {return}
						sent += count;
					}
					drop(to_client.shutdown().await);
				};
				tokio::join!(forward, back);
			});
		}
	}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_with_an_ordinary_hello_completes_the_handshake_of_the_site_and_sees_its_certificate() {
	let time = time!();
	let node = launch("stranger", time, |_| {}).await;
	assert!(logged("faketls listener") && logged("alpha, new and unreviewed"));
	let hello = tap(node.addr).await;
	let mut tls = trusting(&node.site.der).connect(ServerName::try_from(NAME).unwrap(), TcpStream::connect(hello.addr).await.unwrap()).await.unwrap();
	// The certificate it sees is the site's, byte for byte, and the page is the site's.
	assert_eq!(tls.get_ref().1.peer_certificates().unwrap()[0].as_ref(), node.site.der.as_ref());
	tls.write_all(format!("GET / HTTP/1.1\r\nHost: {NAME}\r\n\r\n").as_bytes()).await.unwrap();
	let (mut page, mut buf) = (Vec::new(), vec![0u8; 4096]);
	while let Ok(Ok(count)) = timeout(SECOND, tls.read(&mut buf)).await {
		if count == 0 {break}
		page.extend_from_slice(&buf[..count]);
	}
	assert!(String::from_utf8_lossy(&page).ends_with(PAGE), "{}", String::from_utf8_lossy(&page));
	// What the site was sent is what the stranger sent, every byte of it, over the one connection the node opened for it at accept.
	eventually("the site was not sent what the stranger sent", || node.to_site.seen.lock().unwrap().len() == 1 && node.to_site.seen.lock().unwrap()[0] == hello.seen.lock().unwrap()[0]).await;
	assert_eq!(node.site.connections.load(Ordering::SeqCst), 1);
	let totals = node.totals();
	assert_eq!((totals.stranger_hello, totals.relays, totals.early_connections, totals.refused_hello, totals.proofs_accepted, totals.decoys, totals.site_down, totals.site_budget), (1, 1, 1, 0, 0, 0, 0, 0));
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_that_are_no_hello_get_what_the_site_sends_and_the_way_it_closes() {
	let time = time!();
	let node = launch("plain", time, |_| {}).await;
	let garbage: Vec<u8> = (0..64u8).map(|byte| byte.wrapping_mul(7).wrapping_add(3)).collect();
	// A record header that cannot start a hello, a hello that declares more than the node reads, a message that is none, and what a browser sends to a site that is not one.
	let inputs: Vec<(&str, Vec<u8>)> = vec![
		("an HTTP request", b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".to_vec()),
		("64 bytes of garbage", garbage),
		("a record of another version", vec![22, 3, 2, 0, 5, 1, 0, 0, 1, 0]),
		("application data", vec![23, 3, 3, 0, 4, 1, 2, 3, 4]),
		("a handshake message that is no ClientHello", vec![22, 3, 1, 0, 4, 2, 0, 0, 0]),
		("a record above the limit", [&[22u8, 3, 1, 0xff, 0xff][..], &[1; 40]].concat()),
		("a hello that declares more than 8,192 bytes", vec![22, 3, 1, 0x40, 0x00, 1, 0x00, 0x23, 0x29, 3, 3]),
		("a hello in a record that holds more than the hello", vec![22, 3, 1, 0x00, 0x20, 1, 0x00, 0x00, 0x04, 3, 3, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]),
		("nothing at all", Vec::new()),
	];
	for (what, bytes) in &inputs {
		let (direct, through) = (ask(node.site.addr, bytes, QUIET).await, ask(node.addr, bytes, QUIET).await);
		assert_eq!(direct, through, "{what}: the site gave one answer and the node another");
	}
	// A hello that is cut short is held for 3 s and then handed to the site as it was, and the site's timers run from there.
	let cut = [&[22u8, 3, 1, 0x00, 0xc8][..], &[1, 0, 0, 0xc4, 3, 3], &[9; 40]].concat();
	let (direct, through) = (ask(node.site.addr, &cut, Duration::from_millis(4500)).await, ask(node.addr, &cut, Duration::from_millis(4500)).await);
	assert_eq!(direct, through);
	eventually("the cut hello did not reach the site", || node.to_site.seen.lock().unwrap().iter().any(|seen| *seen == cut)).await;
	let totals = node.totals();
	assert!(totals.stranger_syntax >= 6 && totals.stranger_slow == 1, "{totals:?}");
	assert_eq!((totals.refused_hello, totals.proofs_accepted, totals.established), (0, 0, 0));
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_the_proof_gets_a_session_and_its_tunnel_works() {
	let time = time!();
	let node = launch("session", time, |_| {}).await;
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	assert!(matches!(peer.session.state(), State::Opening | State::Established));
	peer.connect().await.unwrap_or_else(|ended| panic!("the session did not open: {ended:?}"));
	// A real WireGuard handshake went through the session, and traffic passes both ways: a TCP connection through the exit, and an echo the node answers itself.
	assert_eq!(peer.leaves(40000).await.as_deref(), Some("main"));
	assert!(peer.ping(200, 1).await);
	let peers = node.engine.peers(Some("a"));
	assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(Over::FakeTls), true));
	let (totals, numbers) = (node.totals(), peer.session.numbers());
	assert_eq!((totals.proofs_accepted, totals.established, totals.sessions, totals.pending, totals.refused_hello, totals.stranger_hello), (1, 1, 1, 0, 0, 0));
	assert!(numbers.sent >= 5 && numbers.received >= 4 && numbers.dropped == 0 && numbers.heard.is_some(), "{numbers:?}");
	// The user's connection was never relayed: what the node opened at accept was sent the hello, to read the site's flight for it, and nothing else.
	assert_eq!((totals.relays, totals.early_connections), (0, 1));
	let hello = record(&node.front.seen.lock().unwrap()[0]).to_vec();
	eventually("the site was not sent the hello", || node.to_site.seen.lock().unwrap().first() == Some(&hello)).await;
	// Two devices at once, each on its own connection.
	let mut second = node.peer(1, &link(1, &TRANSPORT), 0);
	second.connect().await.unwrap();
	assert_eq!(second.leaves(40001).await.as_deref(), Some("main"));
	assert_eq!(node.totals().sessions, 2);
	assert_eq!(peer.session.close().await, Ended::Closed(End::Asked));
	eventually("the session did not end", || node.totals().sessions == 1 && node.totals().ended_closed == 1).await;
	second.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hello_that_is_sent_again_gets_a_flight_of_the_sizes_the_site_gives_for_those_bytes() {
	let time = time!();
	let node = launch("replay", time, |_| {}).await;
	let hello = recorded(&node).await;
	assert_eq!(hello[..3], [22, 3, 1]);
	// The same bytes from a new connection: the carrier opens and the replay rule says it was seen. It is not relayed: the node answers with a ServerHello and the rest of a flight whose leaf is random, and the site is sent the bytes to read its flight for them.
	let answer = ask(node.addr, &hello, SECOND).await.0;
	assert!(answer.len() > 200 && answer[..3] == [22, 3, 3] && answer[5] == 2, "the answer to a replayed hello is no flight of the node: {} bytes starting {:02x?}", answer.len(), &answer[..answer.len().min(8)]);
	eventually("the replay was not refused as seen", || node.totals().refused_seen == 1).await;
	eventually("the site was not sent the hello twice", || node.to_site.seen.lock().unwrap().len() == 2).await;
	assert!(node.to_site.seen.lock().unwrap().iter().all(|seen| *seen == hello), "the site was sent more than the hello");
	// The paired comparison: the same bytes straight to the site, the flight of the user's own connection, and the copy that was replayed. The site's sizes, its choices and the grouping of its records are in all three.
	let (direct, _) = ask(node.site.addr, &hello, SECOND).await;
	let site = flight_of(&direct, &hello, 64);
	let limit = site.sealed().len();
	let (own, copy) = (flight_of(&node.front.heard.lock().unwrap()[0], &hello, limit), flight_of(&answer, &hello, limit));
	// What the site sent the node for the two copies of the hello is what each of them was answered with, to the byte. The site's own flight varies by a byte or two from one connection to the next (a signature in DER is 70 to 72 bytes), so against the direct one the sizes are held to that.
	let heard = node.to_site.heard.lock().unwrap().clone();
	let (for_user, for_copy) = (flight_of(&heard[0], &hello, limit), flight_of(&heard[1], &hello, limit));
	assert_eq!((sizes(&own), sizes(&copy)), (sizes(&for_user), sizes(&for_copy)));
	for flight in [&own, &copy] {
		assert_eq!((flight.suite, flight.group, flight.key_first, flight.sealed().len()), (site.suite, site.group, site.key_first, limit));
		assert!(flight.sealed().iter().zip(site.sealed()).all(|(made, shown)| made.abs_diff(shown) <= 3), "{:?} against {:?}", flight.sealed(), site.sealed());
	}
	let totals = node.totals();
	assert_eq!((totals.stranger_hello, totals.proofs_accepted, totals.sessions, totals.flights_live, totals.flights_generic, totals.flights_live_miss), (0, 1, 0, 2, 0, 0));
	assert!(totals.probes >= 8 && totals.shapes >= 1, "{totals:?}");
	// The client's next attempt has a hello of its own and is taken.
	let mut again = node.peer(0, &link(0, &TRANSPORT), 0);
	again.connect().await.unwrap();
	again.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_for_another_node_or_with_a_changed_byte_is_a_strangers_and_gets_the_site() {
	let time = time!();
	let node = launch("changed", time, |_| {}).await;
	// A hello sealed to a key the node does not hold does not open, and is relayed: the client is given the site's own flight, whose leaf is not the one it derives.
	let ended = node.peer(0, &link(0, &[0x99; 32]), 0).ended().await;
	assert_eq!(ended, Ended::Unreachable(Unreachable::Certificate));
	eventually("the hello was not relayed", || node.totals().stranger_hello == 1).await;
	// One byte of a good hello changed on its way: the same, but for the client's keys: the site's handshake was made over the hello it received, and the client's over the one it sent, so nothing of the site's flight opens for it.
	node.front.flip.store(60, Ordering::SeqCst);
	let ended = node.peer(1, &link(1, &TRANSPORT), 0).ended().await;
	assert_eq!(ended, Ended::Unreachable(Unreachable::Tls));
	eventually("the changed hello was not relayed", || node.totals().stranger_hello == 2).await;
	// What the site was sent is the hello the node received, changed byte and all.
	let received = record(&node.front.seen.lock().unwrap()[1]).to_vec();
	assert!(node.to_site.seen.lock().unwrap().iter().any(|seen| seen.starts_with(&received)));
	let totals = node.totals();
	assert_eq!((totals.refused_hello, totals.proofs_accepted, totals.decoys, totals.sessions), (0, 0, 0, 0));
	assert_eq!(node.site.connections.load(Ordering::SeqCst), 2);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_with_a_clock_off_gets_a_flight_that_does_not_match_and_no_session() {
	let time = time!();
	let node = launch("clock", time, |_| {}).await;
	// Two hours away: the hour tag is none the node holds, so the carrier opens and no device is named. A flight of the node with a random leaf, which the client reports as a mismatch, and no session.
	let ended = node.peer(0, &link(0, &TRANSPORT), 7200).ended().await;
	assert_eq!(ended, Ended::Unreachable(Unreachable::Certificate));
	eventually("the flight was not counted", || node.totals().decoys == 1).await;
	let totals = node.totals();
	assert_eq!((totals.refused_hello, totals.stranger_hello, totals.proofs_accepted, totals.sessions, totals.pending, totals.relays), (1, 0, 0, 0, 0, 0));
	// An hour away: the hour tag is the next hour's and the node holds it, so the device is named and the replay rule says the timestamp is outside its window.
	let ended = node.peer(0, &link(0, &TRANSPORT), 3600).ended().await;
	assert_eq!(ended, Ended::Unreachable(Unreachable::Certificate));
	eventually("the window was not the reason", || node.totals().refused_window == 1 && node.totals().decoys == 2).await;
	// A device the node does not know: the same flight, and the node does not say which of its checks said no.
	let stranger = Link {secret: Secret::new([0x77; 32]), ..link(0, &TRANSPORT)};
	assert_eq!(node.peer(0, &stranger, 0).ended().await, Ended::Unreachable(Unreachable::Certificate));
	eventually("the unknown device was not refused", || node.totals().refused_hello == 2).await;
	let totals = node.totals();
	assert_eq!((totals.proofs_accepted, totals.sessions, totals.pending, totals.stranger_hello), (0, 0, 0, 0));
	// The site was sent the hello of each and nothing else, to read its flight for it, and none of them was relayed.
	eventually("the site was not sent the hellos", || node.to_site.seen.lock().unwrap().len() >= 3).await;
	assert!(node.to_site.seen.lock().unwrap().iter().all(|seen| seen[..3] == [22, 3, 1] && 5 + usize::from(u16::from_be_bytes([seen[3], seen[4]])) == seen.len()));
	// A client with the right clock is taken after all of that.
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap();
	peer.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spent_budget_for_the_site_closes_a_stranger_and_never_a_user() {
	let time = time!();
	let node = launch("budget", time, |doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"site_rate": 1})).await;
	// 80 connections of strangers at once: the first 64 take a connection to the site each, and the rest are taken without one and closed where they would need one.
	let mut asks = Vec::new();
	for _ in 0..80 {
		let to = node.addr;
		asks.push(tokio::spawn(async move {ask(to, b"GET / HTTP/1.1\r\n\r\n", Duration::from_secs(2)).await}));
	}
	for ask in asks {ask.await.unwrap();}
	let totals = node.totals();
	assert!(totals.early_skipped >= 1 && totals.site_budget >= 1 && totals.early_connections + totals.early_skipped == 80, "{totals:?}");
	// All of them are one source, of which the node relays 8 at once and closes the oldest for the next.
	assert!(totals.relays_evicted >= 1, "{totals:?}");
	// A user needs no connection to the site and is served all the same.
	let before = node.totals().early_skipped;
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap_or_else(|ended| panic!("a user was refused while the budget for the site was spent: {ended:?}"));
	assert_eq!(peer.leaves(40002).await.as_deref(), Some("main"));
	assert!(node.totals().early_skipped > before || node.totals().early_connections > totals.early_connections);
	peer.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_with_another_transport_key_ends_the_sessions_of_the_old_key_and_takes_the_new_one() {
	let time = time!();
	let mut node = launch("rotate", time, |_| {}).await;
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap();
	assert_eq!(peer.leaves(40003).await.as_deref(), Some("main"));
	node.reload(|doc| doc["inbounds"][0]["transports"][0]["transport_key"] = json!(text(&ROTATED))).await;
	eventually("the session of the old key did not end", || node.totals().sessions == 0 && node.totals().ended_unserved == 1).await;
	assert!(peer.session.recv().await.is_err());
	// The old key opens nothing now: its hello is a stranger's, and the site answers it. The new key does.
	assert_eq!(node.peer(0, &link(0, &TRANSPORT), 0).ended().await, Ended::Unreachable(Unreachable::Certificate));
	eventually("the old key was not a stranger's", || node.totals().stranger_hello == 1).await;
	let mut renewed = node.peer(0, &link(0, &ROTATED), 0);
	renewed.connect().await.unwrap();
	assert_eq!(renewed.leaves(40004).await.as_deref(), Some("main"));
	renewed.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tag_table_follows_the_hour() {
	let time = time!();
	let node = launch("hour", time, |_| {}).await;
	let mut before = node.peer(0, &link(0, &TRANSPORT), 0);
	before.connect().await.unwrap();
	before.session.close().await;
	let rebuilds = node.engine.obfs().table_rebuilds;
	// Two hours on, the hour tag of the device is none the table held. It is built anew away from the packet path, within a moment, for the hour the clock is in.
	node.advance(2 * 3600).await;
	eventually("the tag table did not follow the hour", || node.engine.obfs().table_rebuilds > rebuilds).await;
	let mut after = node.peer(0, &link(0, &TRANSPORT), 0);
	after.connect().await.unwrap_or_else(|ended| panic!("the device was not taken in the new hour: {ended:?}"));
	after.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_site_that_speaks_or_closes_first_decides_the_connection_at_that_moment() {
	let time = time!();
	let (site, _task) = eager().await;
	let node = launch("eager", time, |doc| doc["inbounds"][0]["transports"][0]["site"]["address"] = json!(site.to_string())).await;
	let direct = ask(site, &[], SECOND).await;
	assert!(direct.1 && direct.0.starts_with(b"HTTP/1.1 408 "));
	assert_eq!(ask(node.addr, &[], SECOND).await, direct);
	// The start of a hello does not make the node wait for the rest of it: the site has spoken, and the peer is given that at once, not after the hold of 3 s.
	let started = Instant::now();
	assert_eq!(ask(node.addr, &[22, 3, 1, 0, 200, 1, 0], SECOND).await, direct);
	assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
	let totals = node.totals();
	assert_eq!((totals.stranger_origin, totals.stranger_slow, totals.relays), (2, 0, 2));
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_site_that_cannot_be_reached_closes_strangers_with_no_answer_and_serves_users() {
	let time = time!();
	let gone = {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		listener.local_addr().unwrap()
	};
	let node = launch("down", time, |doc| doc["inbounds"][0]["transports"][0]["site"]["address"] = json!(gone.to_string())).await;
	let (answer, closed) = ask(node.addr, b"GET / HTTP/1.1\r\n\r\n", SECOND).await;
	assert!(answer.is_empty() && closed);
	eventually("the site was not counted as down", || node.totals().site_down == 1).await;
	assert!(logged("its site cannot be reached"));
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap_or_else(|ended| panic!("a user was refused while the site was down: {ended:?}"));
	assert_eq!(peer.leaves(40005).await.as_deref(), Some("main"));
	peer.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_flight_of_a_copy_has_the_sizes_the_group_the_suite_and_the_delay_of_the_sites_flight() {
	let time = time!();
	let sizes_of_the_site = vec![1200, 1400, 600];
	let (site, _task) = scripted(Suite::Aes256, HYBRID, Duration::from_millis(150), sizes_of_the_site.clone()).await;
	let node = launch("scripted", time, |doc| doc["inbounds"][0]["transports"][0]["site"]["address"] = json!(site.to_string())).await;
	// The probes of a site that cannot complete a handshake keep nothing, and say so.
	let totals = node.totals();
	assert_eq!((totals.probes, totals.shapes), (0, 0));
	assert!(totals.probe_failed >= 8 && logged("failed:"), "{totals:?}");
	// The client holds the keys of the hybrid share, so the node answers in the group the site chose, and the session works over it.
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap_or_else(|ended| panic!("the session did not open in the hybrid group: {ended:?}"));
	assert_eq!(peer.leaves(40010).await.as_deref(), Some("main"));
	peer.session.close().await;
	let hello = record(&node.front.seen.lock().unwrap()[0]).to_vec();
	let own = flight_of(&node.front.heard.lock().unwrap()[0], &hello, 3);
	assert_eq!((own.suite, own.group, own.sealed()), (Suite::Aes256, HYBRID, sizes_of_the_site));
	// A copy of the hello gets the same, and not before the site would have answered.
	let (reads, closed) = ask_timed(node.addr, &hello, SECOND).await;
	let sent: Vec<u8> = reads.iter().flat_map(|(_, bytes)| bytes.clone()).collect();
	let copy = flight_of(&sent, &hello, 3);
	assert!(!closed && sizes(&copy) == sizes(&own));
	assert!(reads[0].0 >= Duration::from_millis(140), "the first byte of the copy came after {:?}, before the site's 150 ms", reads[0].0);
	assert!(node.totals().flights_live >= 2);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_byte_of_a_copy_comes_when_the_sites_does_and_a_kept_shape_carries_the_time_when_there_is_no_live_answer() {
	let time = time!();
	let node = launch_after("timing", time, Duration::from_millis(200), |doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"site_rate": 1})).await;
	let hello = recorded(&node).await;
	// The live copy: the same bytes to the node and to the site, from one place.
	let ((copy, _), (direct, _)) = (ask_timed(node.addr, &hello, SECOND).await, ask_timed(node.site.addr, &hello, SECOND).await);
	let (at_copy, at_site) = (copy[0].0, direct[0].0);
	assert!(at_site >= Duration::from_millis(190) && at_copy >= Duration::from_millis(190), "{at_copy:?} {at_site:?}");
	assert!(at_copy.abs_diff(at_site) < Duration::from_millis(150), "the copy's first byte came at {at_copy:?} and the site's at {at_site:?}");
	// With the budget for the site spent there is no connection to read its answer on: the flight is one kept shape's, with the time that shape showed.
	exhaust(&node).await;
	let before = node.totals();
	let (reads, closed) = ask_timed(node.addr, &hello, SECOND).await;
	assert!(reads[0].0 >= Duration::from_millis(190), "{:?}, closed: {closed}", reads[0].0);
	let totals = node.totals();
	assert!(totals.flights_kept > before.flights_kept || totals.flights_live > before.flights_live, "{totals:?}");
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hello_that_opened_and_got_no_session_is_relayed_to_the_site_when_the_allowance_of_its_source_is_spent() {
	let time = time!();
	let node = launch("allowance", time, |_| {}).await;
	let hello = recorded(&node).await;
	let mut answers = Vec::new();
	for _ in 0..9 {answers.push(ask(node.addr, &hello, Duration::from_millis(150)).await.0)}
	// A burst of 4 and one a second: the first are answered with a flight of the node's, and the rest with what the site sent for the hello, as it came. None is closed with no answer.
	assert!(answers.iter().all(|answer| answer.len() > 100 && answer[5] == 2), "{:?}", answers.iter().map(Vec::len).collect::<Vec<_>>());
	eventually("the flights over the allowance were not counted", || node.totals().flights_spent >= 1).await;
	assert!(logged("the allowance of its source or of the listener was spent"));
	let totals = node.totals();
	assert_eq!((totals.refused_seen, totals.relays), (9, totals.flights_spent));
	assert!(totals.flights_spent >= 1 && totals.handshake_failed + totals.flights_spent == 9, "{totals:?}");
	// A user is not held to it: it has a proof of its own.
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap();
	peer.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayer_that_goes_silent_after_the_flight_gets_the_reaction_of_a_site_to_an_idle_connection() {
	let time = time!();
	let node = launch("replayer-silent", time, |_| {}).await;
	let hello = recorded(&node).await;
	let shown = probe(node.site.addr, NAME, Mode::Wait, time.secs(), QUICK).await.unwrap().idle.expect("the site ends an idle connection");
	let started = Instant::now();
	let (answer, closed) = ask(node.addr, &hello, Duration::from_millis(1800)).await;
	// Not a bare close at the handshake deadline of 10 s: the alert the site sent when it ended an idle connection, then the end, at about the time it did.
	assert!(closed && started.elapsed() < Duration::from_secs(5), "closed: {closed} after {:?}", started.elapsed());
	let (size, ..) = shown.alert.expect("the site sends an alert");
	assert_eq!(answer[answer.len() - 5 - size..][..3], [23, 3, 3]);
	assert!(started.elapsed() >= shown.after / 2, "{:?} against {:?}", started.elapsed(), shown.after);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_flight_goes_out_as_the_sites_comes_in_with_the_serverhello_at_once_and_each_burst_at_its_offset() {
	let time = time!();
	let direct = site_after(Duration::ZERO).await;
	// The ServerHello (127 bytes) and the compatibility record (6) come first, and the encrypted records 200 ms later.
	let (cut, _task) = stagger(direct.addr, 133, Duration::from_millis(200)).await;
	let node = launch("burst", time, |doc| doc["inbounds"][0]["transports"][0]["site"]["address"] = json!(cut.to_string())).await;
	let hello = recorded(&node).await;
	let (reads, closed) = ask_timed(node.addr, &hello, SECOND).await;
	let sealed_at = reads.iter().find(|(_, bytes)| bytes.iter().any(|byte| *byte == 23) && bytes.len() > 133).map(|(at, _)| *at).or_else(|| reads.last().map(|(at, _)| *at)).unwrap();
	assert!(reads.len() >= 2, "{} reads, closed: {closed}", reads.len());
	assert!(reads[0].0 < Duration::from_millis(120), "the ServerHello came after {:?}", reads[0].0);
	assert!(sealed_at >= Duration::from_millis(180), "the encrypted records came after {sealed_at:?}, not at the site's 200 ms");
	let totals = node.totals();
	assert!(totals.flights_live >= 2 && totals.flights_live_miss == 0, "{totals:?}");
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_takes_no_proof_after_24_hours_without_a_probe_and_takes_them_again_after_one() {
	let time = time!();
	let mut node = launch("stale", time, |_| {}).await;
	recorded(&node).await;
	let rebuilds = node.engine.obfs().table_rebuilds;
	node.advance(25 * 3600).await;
	eventually("the tag table did not follow the hour", || node.engine.obfs().table_rebuilds > rebuilds).await;
	// No probe has succeeded for 24 h by the node's clock: the hello of a user is relayed to the site as a stranger's, which shows it the site's own flight, and it says so.
	assert_eq!(node.peer(0, &link(0, &TRANSPORT), 0).ended().await, Ended::Unreachable(Unreachable::Certificate));
	eventually("the hello was not relayed", || node.totals().stranger_stale == 1).await;
	assert!(logged("no probe of the site has succeeded for 24 h"));
	assert_eq!(node.totals().proofs_accepted, 1);
	// A site that changes is probed again at the reload, and the first probe that succeeds ends it.
	let probes = node.totals().probes;
	let direct = node.site.addr.to_string();
	node.reload(|doc| doc["inbounds"][0]["transports"][0]["site"]["address"] = json!(direct)).await;
	eventually("the site was not probed again", || node.totals().probes > probes).await;
	let mut peer = node.peer(0, &link(0, &TRANSPORT), 0);
	peer.connect().await.unwrap_or_else(|ended| panic!("a user was refused after a probe succeeded: {ended:?}"));
	assert!(logged("a probe of the site succeeded, so proofs are taken again"));
	peer.session.close().await;
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayer_that_sends_garbage_gets_the_reaction_the_site_showed_to_it() {
	let time = time!();
	let node = launch("garbage", time, |_| {}).await;
	let hello = recorded(&node).await;
	// What the site does to a record that fails to decrypt, from a probe of it as the node makes them.
	let shown = probe(node.site.addr, NAME, Mode::Garbage, time.secs(), QUICK).await.unwrap().garbage.expect("the site reacts to garbage");
	let (size, ..) = shown.alert.expect("the site sends an alert");
	let junk = [&[23u8, 3, 3, 0, 40][..], &[0x42; 40]].concat();
	let (flight, after, closed) = ask_twice(node.addr, &hello, &junk, Duration::from_millis(100)).await;
	assert!(flight.len() > 200 && closed, "{} bytes of flight, closed: {closed}", flight.len());
	assert_eq!((after.len(), &after[..3]), (5 + size, &[23u8, 3, 3][..]), "the node's answer to garbage is not the alert the site sent");
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_the_node_refused_is_answered_after_the_time_the_site_takes_to_answer_a_close_notify() {
	let time = time!();
	let node = launch("notify", time, |_| {}).await;
	let shown = probe(node.site.addr, NAME, Mode::Notify, time.secs(), QUICK).await.unwrap().notified.expect("the site reacts to a close_notify");
	assert!(shown.after >= Duration::from_millis(150), "{shown:?}");
	// A client whose clock is two hours off gets a flight it cannot match, finishes the handshake, says goodbye, and waits for the answer.
	let started = Instant::now();
	assert_eq!(node.peer(0, &link(0, &TRANSPORT), 7200).ended().await, Ended::Unreachable(Unreachable::Certificate));
	assert!(started.elapsed() >= Duration::from_millis(150), "the node answered the goodbye after {:?}, before the site's {:?}", started.elapsed(), shown.after);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_sends_nothing_and_has_no_connection_to_the_site_is_closed_as_the_site_closes_an_idle_one() {
	let time = time!();
	let node = launch("silent", time, |doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"site_rate": 1})).await;
	let shown = probe(node.site.addr, NAME, Mode::Wait, time.secs(), QUICK).await.unwrap().idle.expect("the site ends an idle connection");
	exhaust(&node).await;
	let started = Instant::now();
	let (answer, closed) = ask(node.addr, &[], Duration::from_millis(1500)).await;
	assert!(closed, "the node held a silent connection for {:?}", started.elapsed());
	assert!(started.elapsed() >= Duration::from_millis(100) && started.elapsed() < Duration::from_millis(1400), "{:?} against the site's {:?}", started.elapsed(), shown.after);
	assert_eq!(answer.len(), 5 + shown.alert.map_or(0, |(size, ..)| size));
	assert_eq!(node.totals().idled, 1);
	node.engine.shutdown().await;
}
