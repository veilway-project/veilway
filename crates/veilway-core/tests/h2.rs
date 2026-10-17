//! HTTP/2 on the `tls` transport, end to end (http2 page, "The node: `tls`"): an HTTP/2 client with a proof gets the tunnel in both directions, a stranger's streams reach a real HTTP/1.1 origin as the right bytes, every malformed stream is reset before anything goes upstream, and the node's counters trip on a rapid reset and on a flood. The node is started the way `veilway run` starts it, with the clock, the replay file and the certificate of each test its own.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::digest::{digest, SHA256};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use veilway_core::config::Config;
use veilway_core::{Engine, Options, StreamTotals};
use veilway_proto::chunk::{Opener, Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::h2 as frames;
use veilway_proto::proof::{self, Name};
use veilway_proto::websocket::{self, BINARY};
use veilway_proto::NoRandom;

const NODE: [u8; 32] = [0x10; 32];
const KEY: [u8; 32] = [0x21; 32];
const TRANSPORT: [u8; 32] = [0x51; 32];
const PATH: &str = "/assets/app-3f9c2e71.js";
const SECOND: Duration = Duration::from_secs(1);
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
const ADDRESS: [u8; 4] = [10, 7, 0, 2];
const PAGE: &str = "<html>the operator's own site</html>\n";
static NEXT_PORT: AtomicU16 = AtomicU16::new(29000);

fn listen() -> SocketAddr {SocketAddr::from((Ipv4Addr::LOCALHOST, NEXT_PORT.fetch_add(1, Ordering::SeqCst)))}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for part in bytes.chunks_mut(32) {part.copy_from_slice(&veilway_wg::generate_key()[..part.len()])}
	Ok(())
}

/// A SOCKS5 proxy without authentication that answers every CONNECT with `main`.
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

/// What an origin written by hand saw: the bytes of every request head, one for each connection, and how many connections it took.
struct Origin {addr: SocketAddr, heads: Arc<std::sync::Mutex<Vec<Vec<u8>>>>, connections: Arc<AtomicUsize>, task: JoinHandle<()>}

impl Drop for Origin {
	fn drop(&mut self) {self.task.abort()}
}

/// An origin that reads one request head (and the body its `Content-Length` or chunking names) on each connection, records the bytes, and answers by the path: `/chunked` with a chunked body of three chunks and a trailer, `/big/<n>` with `n` bytes and a length, `/close` with no length and a close, `/head` as a `HEAD` is answered, `/hold` with nothing at all, `/two` with a `100 Continue` first, and anything else with a short page and `Connection: close`.
async fn origin() -> Origin {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, heads, connections) = (listener.local_addr().unwrap(), Arc::new(std::sync::Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
	let task = tokio::spawn({
		let (heads, connections) = (heads.clone(), connections.clone());
		async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else {return};
				let heads = heads.clone();
				let connections = connections.clone();
				tokio::spawn(async move {
					let (mut got, mut buf) = (Vec::new(), vec![0u8; 16384]);
					let end = loop {
						if let Some(at) = got.windows(4).position(|window| window == b"\r\n\r\n") {break at + 4}
						match stream.read(&mut buf).await {
							Ok(count) if count > 0 => got.extend_from_slice(&buf[..count]),
							_ => return,
						}
					};
					let head = String::from_utf8_lossy(&got[..end]).into_owned();
					let target = head.split(' ').nth(1).unwrap_or_default().to_string();
					// Wait for the body: a length, or the zero chunk.
					let lower = head.to_ascii_lowercase();
					let length = lower.lines().find_map(|line| line.strip_prefix("content-length: ")).and_then(|value| value.trim().parse::<usize>().ok()).unwrap_or(0);
					let chunked = lower.contains("transfer-encoding: chunked");
					while (!chunked && got.len() < end + length) || (chunked && !got[end..].ends_with(b"0\r\n\r\n")) {
						match stream.read(&mut buf).await {
							Ok(count) if count > 0 => got.extend_from_slice(&buf[..count]),
							_ => break,
						}
					}
					// The node's own probe of the origin at start (its upgrade headers) is answered but not counted.
					if !got.starts_with(format!("GET / HTTP/1.1\r\nHost: {addr}\r\n").as_bytes()) {
						connections.fetch_add(1, Ordering::SeqCst);
						heads.lock().unwrap().push(got.clone());
					}
					let parts: Vec<&str> = target.split('/').collect();
					match parts.get(1).copied() {
						Some("chunked") => drop(stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;x=1\r\nhello\r\n6\r\n world\r\n1\r\n!\r\n0\r\nTrailer: gone\r\n\r\n").await),
						Some("big") => {
							let body = parts.get(2).and_then(|size| size.parse::<usize>().ok()).unwrap_or(0);
							let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: {body}\r\nConnection: close\r\n\r\n").as_bytes()).await;
							let block = vec![0x61u8; 16 * 1024];
							let mut left = body;
							while left > 0 {
								let size = left.min(block.len());
								if stream.write_all(&block[..size]).await.is_err() {return}
								left -= size;
							}
						}
						Some("close") => drop(stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\n\r\nuntil the end").await),
						Some("head") => drop(stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 12345\r\nConnection: close\r\n\r\n").await),
						Some("hold") => tokio::time::sleep(Duration::from_secs(30)).await,
						Some("two") => drop(stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nServer: raw\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await),
						_ => drop(stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 4\r\nConnection: close\r\n\r\nraw!").await),
					}
				});
			}
		}
	});
	Origin {addr, heads, connections, task}
}

/// The operator's own web site, a real HTTP/1.1 server.
async fn site() -> (SocketAddr, JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let task = tokio::spawn(async move {
		loop {
			let Ok((stream, _)) = listener.accept().await else {return};
			tokio::spawn(async move {
				let page = service_fn(move |request: Request<Incoming>| async move {
					let found = request.method() == hyper::Method::GET && request.uri().path() == "/";
					Ok::<_, Infallible>(Response::builder().status(if found {200} else {404}).header("server", "decoy/1.0").body(Full::new(Bytes::from(if found {PAGE} else {"nothing here\n"}))).unwrap())
				});
				let _ = hyper::server::conn::http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(2)).serve_connection(TokioIo::new(stream), page).await;
			});
		}
	});
	(addr, task)
}

fn scratch(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-h2-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

fn seed(path: &Path, floor: u64, limit: u64) {
	let body = [&b"VWREPLAY"[..], &1u32.to_be_bytes(), &[0; 4], &floor.to_be_bytes(), &limit.to_be_bytes(), &0u32.to_be_bytes()].concat();
	std::fs::write(path, [&body[..], digest(&SHA256, &body).as_ref()].concat()).unwrap();
}

/// Writes a certificate for `node.test` into `dir` and gives the clients that trust exactly it: one that offers `h2` and `http/1.1`, one that offers `h2` alone and one that offers `http/1.1` alone.
fn certify(dir: &Path) -> [TlsConnector; 3] {
	let _ = rustls::crypto::ring::default_provider().install_default();
	let made = rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap();
	for (name, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
		std::fs::write(dir.join(name), pem).unwrap();
		#[cfg(unix)]
		std::fs::set_permissions(dir.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
	let mut roots = RootCertStore::empty();
	roots.add(CertificateDer::from(made.cert.der().to_vec())).unwrap();
	let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
	let alpn = |config: &ClientConfig, protocols: &[&[u8]]| {
		let mut config = config.clone();
		config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
		TlsConnector::from(Arc::new(config))
	};
	config.alpn_protocols = Vec::new();
	[alpn(&config, &[b"h2", b"http/1.1"]), alpn(&config, &[b"h2"]), alpn(&config, &[b"http/1.1"])]
}

fn document(proxy: SocketAddr, listen: SocketAddr, origin: SocketAddr, http2: Option<&str>) -> Value {
	let mut transport = json!({"type": "tls", "listen": listen.to_string(), "path": PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": format!("http://{origin}")}});
	if let Some(http2) = http2 {transport["http2"] = json!(http2)}
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": veilway_wg::encode_key(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [veilway_wg::encode_key(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [transport]}],
		"outbounds": [{"tag": "main-proxy", "type": "socks5", "server": proxy.to_string()}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "main-proxy"}}],
		"routing": {"default": "main", "rules": [{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "phone", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&KEY)), "transport_secrets": [veilway_wg::encode_key(&[0xa0; 32])], "addresses": ["10.7.0.2"]}]}]
	})
}

struct Node {engine: Engine, addr: SocketAddr, connectors: [TlsConnector; 3], origin: Option<Origin>, _site: Option<JoinHandle<()>>}

impl Node {
	fn totals(&self) -> StreamTotals {self.engine.stream()}

	/// Starts a node whose decoy is `origin` (or a real web site when there is none), with `http2` set as given.
	async fn launch(test: &str, http2: Option<&str>, origin: Option<Origin>) -> Node {
		let (dir, addr) = (scratch(test), listen());
		let connectors = certify(&dir);
		let (site, task) = if origin.is_some() {(None, None)} else {let (site, task) = site().await; (Some(site), Some(task))};
		let target = origin.as_ref().map_or_else(|| site.unwrap(), |origin| origin.addr);
		let doc = document(proxy().await, addr, target, http2);
		let config = Config::parse(doc.to_string().as_bytes()).unwrap();
		assert!(config.validate(false).errors.is_empty(), "{:?}", config.validate(false).errors);
		let now = OffsetDateTime::now_utc;
		let secs = now().unix_timestamp() as u64;
		seed(&dir.join("replay"), secs - 100, secs - 100);
		let engine = veilway_core::start(&config, Options {now, replay: Some(dir.join("replay")), ..Options::new(&dir)}).await.unwrap();
		Node {engine, addr, connectors, origin, _site: task}
	}

	async fn tls(&self, connector: usize) -> TlsStream<TcpStream> {
		let socket = TcpSocket::new_v4().unwrap();
		self.connectors[connector].connect(ServerName::try_from("node.test").unwrap(), socket.connect(self.addr).await.unwrap()).await.unwrap()
	}

	/// A connection that spoke the preface and was told the node's SETTINGS.
	async fn client(&self) -> Client {
		let io = self.tls(0).await;
		assert_eq!(io.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "the node did not choose h2");
		Client::start(io).await
	}
}

/// A bare HTTP/2 client: it speaks the preface, reads frames as they come and answers nothing on its own but SETTINGS and PING.
struct Client {io: TlsStream<TcpStream>, encoder: frames::Encoder, decoder: frames::Decoder, buf: Vec<u8>, next: u32, settings: Vec<(u16, u32)>, goaway: Option<u32>, later: VecDeque<(frames::Header, Vec<u8>)>}

impl Client {
	async fn start(mut io: TlsStream<TcpStream>) -> Client {
		let mut hello = frames::PREFACE.to_vec();
		frames::settings(&[(frames::ENABLE_PUSH, 0)], &mut hello);
		io.write_all(&hello).await.unwrap();
		let mut client = Client {io, encoder: frames::Encoder::new(), decoder: frames::Decoder::new(4096), buf: Vec::new(), next: 1, settings: Vec::new(), goaway: None, later: VecDeque::new()};
		let (header, payload) = client.frame(Duration::from_secs(3)).await.expect("no SETTINGS from the node");
		assert_eq!((header.kind, header.flags), (frames::SETTINGS, 0));
		client.settings = frames::read_settings(&payload).unwrap().collect();
		client
	}

	async fn send(&mut self, bytes: &[u8]) {let _ = self.io.write_all(bytes).await; let _ = self.io.flush().await;}

	/// The next frame, or None when none came in `budget` or the connection ended. A SETTINGS and a PING of the node's are answered on the way.
	async fn frame(&mut self, budget: Duration) -> Option<(frames::Header, Vec<u8>)> {
		if let Some(frame) = self.later.pop_front() {return Some(frame)}
		let deadline = Instant::now() + budget;
		let mut read = vec![0u8; 65536];
		loop {
			if self.buf.len() >= frames::HEADER {
				let header = frames::Header::parse(self.buf[..frames::HEADER].try_into().unwrap());
				if self.buf.len() >= frames::HEADER + header.len {
					let payload = self.buf[frames::HEADER..frames::HEADER + header.len].to_vec();
					self.buf.drain(..frames::HEADER + header.len);
					match header.kind {
						frames::SETTINGS if header.flags & frames::ACK == 0 => {
							let mut ack = Vec::new();
							frames::frame(frames::SETTINGS, frames::ACK, 0, &[], &mut ack);
							self.send(&ack).await;
						}
						frames::PING if header.flags & frames::ACK == 0 => {
							let mut ack = Vec::new();
							frames::frame(frames::PING, frames::ACK, 0, &payload, &mut ack);
							self.send(&ack).await;
						}
						frames::GOAWAY => self.goaway = Some(u32::from_be_bytes(payload[4..8].try_into().unwrap())),
						_ => {}
					}
					return Some((header, payload));
				}
			}
			match timeout(deadline.checked_duration_since(Instant::now())?, self.io.read(&mut read)).await {
				Ok(Ok(count)) if count > 0 => self.buf.extend_from_slice(&read[..count]),
				_ => return None,
			}
		}
	}

	/// A request on a new stream: its fields in order, and `end` if no body follows. The stream's number.
	async fn open(&mut self, fields: &[(&str, &str)], end: bool) -> u32 {
		let id = self.next;
		self.next += 2;
		let block = self.encoder.encode(&fields.iter().map(|(name, value)| (name.as_bytes(), value.as_bytes())).collect::<Vec<_>>());
		let mut out = Vec::new();
		frames::headers(id, &block, end, &mut out);
		self.send(&out).await;
		id
	}

	async fn data(&mut self, id: u32, data: &[u8], end: bool) {
		let mut out = Vec::new();
		frames::frame(frames::DATA, if end {frames::END_STREAM} else {0}, id, data, &mut out);
		self.send(&out).await;
	}

	/// A GET for `path` with the fields a browser sends.
	async fn get(&mut self, path: &str) -> u32 {self.open(&[(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", path), ("user-agent", "browser"), ("accept", "*/*")], true).await}

	/// What stream `id` came to: its status and fields, and its body, or the code it was reset with. The windows are given back as data arrives, unless `credit` is false.
	async fn answer(&mut self, id: u32, budget: Duration, credit: bool) -> Result<(String, Vec<(String, String)>, Vec<u8>), u32> {
		let mut parked = Vec::new();
		let answer = self.reply(id, budget, credit, &mut parked).await;
		for frame in parked.into_iter().rev() {self.later.push_front(frame)}
		answer
	}

	async fn reply(&mut self, id: u32, budget: Duration, credit: bool, parked: &mut Vec<(frames::Header, Vec<u8>)>) -> Result<(String, Vec<(String, String)>, Vec<u8>), u32> {
		let (mut status, mut fields, mut body, deadline) = (String::new(), Vec::new(), Vec::new(), Instant::now() + budget);
		loop {
			let Some((header, payload)) = self.frame(deadline.saturating_duration_since(Instant::now())).await else {return Err(u32::MAX)};
			if header.stream != id {
				if self.goaway.is_some() {return Err(u32::MAX - 1)}
				parked.push((header, payload));
				continue;
			}
			match header.kind {
				frames::HEADERS => {
					if let Some(list) = self.decoder.decode(frames::unpad(header.flags, &payload, true).unwrap(), 65536).unwrap() {
						for (name, value) in list {
							let (name, value) = (String::from_utf8(name).unwrap(), String::from_utf8(value).unwrap());
							if name == ":status" {status = value} else {fields.push((name, value))}
						}
					}
					if header.flags & frames::END_STREAM != 0 {return Ok((status, fields, body))}
				}
				frames::DATA => {
					body.extend_from_slice(frames::unpad(header.flags, &payload, false).unwrap());
					if credit && !payload.is_empty() {
						let mut out = Vec::new();
						frames::window_update(0, payload.len() as u32, &mut out);
						frames::window_update(id, payload.len() as u32, &mut out);
						self.send(&out).await;
					}
					if header.flags & frames::END_STREAM != 0 {return Ok((status, fields, body))}
				}
				frames::RST_STREAM => return Err(u32::from_be_bytes(payload[..4].try_into().unwrap())),
				_ => {}
			}
		}
	}

	/// The connection's end: the GOAWAY the node sent and its error code, when the node closed within `budget`.
	async fn closed(&mut self, budget: Duration) -> Option<u32> {
		let deadline = Instant::now() + budget;
		let mut code = None;
		loop {
			match self.frame(deadline.saturating_duration_since(Instant::now())).await {
				Some((header, payload)) if header.kind == frames::GOAWAY => code = Some(u32::from_be_bytes(payload[4..8].try_into().unwrap())),
				Some(_) => {}
				None => return code,
			}
		}
	}
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Vec<&'a str> {fields.iter().filter(|(known, _)| known == name).map(|(_, value)| value.as_str()).collect()}

fn head_of(bytes: &[u8]) -> String {String::from_utf8_lossy(bytes).into_owned()}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_gets_the_origins_answer_through_an_http_2_stream_and_the_node_announces_what_it_must() {
	let node = Node::launch("stranger", Some("on"), None).await;
	let mut client = node.client().await;
	// The same SETTINGS for everyone: the three limits and extended CONNECT, and no window, so the defaults hold.
	assert_eq!(client.settings, [(frames::HEADER_TABLE_SIZE, 4096), (frames::MAX_CONCURRENT_STREAMS, 100), (frames::MAX_HEADER_LIST_SIZE, 65536), (frames::ENABLE_CONNECT_PROTOCOL, 1)]);
	let id = client.get("/").await;
	let (status, fields, body) = client.answer(id, Duration::from_secs(3), true).await.unwrap();
	assert_eq!((status.as_str(), String::from_utf8(body).unwrap()), ("200", PAGE.to_string()));
	assert_eq!(field(&fields, "server"), ["decoy/1.0"]);
	for forbidden in ["connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"] {assert!(field(&fields, forbidden).is_empty(), "{forbidden}")}
	assert!(fields.iter().all(|(name, _)| name.bytes().all(|byte| !byte.is_ascii_uppercase())));
	let id = client.get("/missing").await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap().0, "404");
	let totals = node.totals();
	assert_eq!((totals.h2_connections, totals.h2_strangers, totals.h2_users, totals.h2_refused), (1, 2, 0, 0), "{totals:?}");
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_alpn_follows_the_setting_and_a_client_that_offers_http_1_1_alone_is_unchanged() {
	let off = Node::launch("alpn-off", None, None).await;
	let io = off.tls(0).await;
	assert_eq!(io.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
	let socket = TcpSocket::new_v4().unwrap();
	let refused = off.connectors[1].connect(ServerName::try_from("node.test").unwrap(), socket.connect(off.addr).await.unwrap()).await;
	assert!(refused.is_err(), "a client that offers h2 alone must fail where the node offers http/1.1 alone");
	off.engine.shutdown().await;
	let on = Node::launch("alpn-on", Some("on"), None).await;
	assert_eq!(on.tls(0).await.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
	let mut old = on.tls(2).await;
	assert_eq!(old.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
	old.write_all(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	let mut buf = vec![0u8; 4096];
	let read = timeout(Duration::from_secs(2), old.read(&mut buf)).await.unwrap().unwrap();
	assert!(head_of(&buf[..read]).starts_with("HTTP/1.1 200 OK"), "{}", head_of(&buf[..read]));
	on.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_requests_reach_an_http_1_1_origin_as_the_right_bytes() {
	let node = Node::launch("bytes", Some("on"), Some(origin().await)).await;
	let mut client = node.client().await;
	let id = client.open(&[(":method", "GET"), (":authority", "node.test:8443"), (":scheme", "https"), (":path", "/a?b=1"), ("user-agent", "x"), ("cookie", "a=1"), ("cookie", "b=2"), ("te", "trailers"), ("accept", "*/*")], true).await;
	let (status, fields, body) = client.answer(id, Duration::from_secs(3), true).await.unwrap();
	assert_eq!((status.as_str(), body.as_slice(), field(&fields, "server")), ("200", &b"raw!"[..], vec!["raw"]));
	// A body with a length is written with that length, and one without is chunked by the node.
	let id = client.open(&[(":method", "POST"), (":authority", "node.test"), (":scheme", "https"), (":path", "/up"), ("content-length", "10")], false).await;
	client.data(id, b"hello", false).await;
	client.data(id, b"world", true).await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap().0, "200");
	let id = client.open(&[(":method", "POST"), (":authority", "node.test"), (":scheme", "https"), (":path", "/up")], false).await;
	client.data(id, b"abc", false).await;
	client.data(id, b"de", false).await;
	client.data(id, b"", true).await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap().0, "200");
	// A chunked answer arrives as DATA and ends at END_STREAM, with its trailer dropped. An answer with no length ends where the origin's connection does. A HEAD has no body whatever its head says.
	let id = client.get("/chunked").await;
	let (_, fields, body) = client.answer(id, Duration::from_secs(3), true).await.unwrap();
	assert_eq!((body.as_slice(), field(&fields, "trailer")), (&b"hello world!"[..], Vec::<&str>::new()));
	assert!(field(&fields, "transfer-encoding").is_empty());
	let id = client.get("/close").await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap().2, b"until the end");
	let id = client.open(&[(":method", "HEAD"), (":authority", "node.test"), (":scheme", "https"), (":path", "/head")], true).await;
	let (status, fields, body) = client.answer(id, Duration::from_secs(3), true).await.unwrap();
	assert_eq!((status.as_str(), body.len(), field(&fields, "content-length")), ("200", 0, vec!["12345"]));
	// An interim answer is passed over, and the answer is the one behind it, with a field the origin repeated.
	let id = client.get("/two").await;
	let (status, fields, _) = client.answer(id, Duration::from_secs(3), true).await.unwrap();
	assert_eq!((status.as_str(), field(&fields, "set-cookie")), ("201", vec!["a=1", "b=2"]));
	let origin = node.origin.as_ref().unwrap();
	let heads: Vec<String> = origin.heads.lock().unwrap().iter().map(|head| head_of(head)).collect();
	assert_eq!(heads[0], "GET /a?b=1 HTTP/1.1\r\nHost: node.test:8443\r\nuser-agent: x\r\naccept: */*\r\ncookie: a=1; b=2\r\nConnection: close\r\n\r\n");
	assert_eq!(heads[1], "POST /up HTTP/1.1\r\nHost: node.test\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhelloworld");
	assert_eq!(heads[2], "POST /up HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
	assert_eq!(heads.len(), 7);
	// One upstream connection for each stream, used once.
	assert_eq!(origin.connections.load(Ordering::SeqCst), 7);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refused_field_and_pseudo_header_case_resets_the_stream_and_nothing_goes_upstream() {
	let node = Node::launch("refused", Some("on"), Some(origin().await)).await;
	let mut client = node.client().await;
	let base = [(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")];
	let with = |extra: &[(&'static str, &'static str)]| [base.to_vec(), extra.to_vec()].concat();
	let cases: Vec<Vec<(&'static str, &'static str)>> = vec![
		with(&[("connection", "close")]), with(&[("keep-alive", "5")]), with(&[("proxy-connection", "x")]), with(&[("transfer-encoding", "chunked")]), with(&[("upgrade", "websocket")]), with(&[("te", "gzip")]),
		with(&[("host", "other.test")]), with(&[("host", "node.test"), ("host", "node.test")]), with(&[("X-Upper", "1")]), with(&[("a", "x\r\nInjected: 1")]), with(&[("a", "x\ny")]), with(&[("a", "x\0")]), with(&[("a", " x")]),
		with(&[("content-length", "1"), ("content-length", "1")]), with(&[("content-length", "+1")]), with(&[("content-length", "5")]),
		vec![(":method", "GET"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "GET"), (":authority", "node.test"), (":path", "/")],
		vec![(":method", "GET"), (":authority", "node.test"), (":scheme", "https")],
		vec![(":authority", "node.test"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "GET"), (":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/"), (":bogus", "x")],
		vec![(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/"), (":status", "200")],
		vec![("user-agent", "x"), (":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "CONNECT"), (":authority", "node.test:443")],
		vec![(":method", "CONNECT"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "CONNECT"), (":protocol", "other"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "GET"), (":authority", "u@node.test"), (":scheme", "https"), (":path", "/")],
		vec![(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "")],
		vec![(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/a b")],
		vec![(":method", "G ET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")],
	];
	for (at, fields) in cases.iter().enumerate() {
		let id = client.open(fields, true).await;
		assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap_err(), frames::PROTOCOL_ERROR, "case {at}: {fields:?}");
	}
	// A body longer than its length, and one that ends short of it, are reset, and the upstream connection closed.
	let id = client.open(&with(&[]).into_iter().map(|(name, value)| if name == ":method" {(name, "POST")} else {(name, value)}).chain([("content-length", "3")]).collect::<Vec<_>>(), false).await;
	client.data(id, b"abcd", true).await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap_err(), frames::PROTOCOL_ERROR);
	let id = client.open(&with(&[]).into_iter().map(|(name, value)| if name == ":method" {(name, "POST")} else {(name, value)}).chain([("content-length", "9")]).collect::<Vec<_>>(), false).await;
	client.data(id, b"abc", true).await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap_err(), frames::PROTOCOL_ERROR);
	// The connection is as good as it was, and the origin never saw a malformed request.
	let id = client.get("/").await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap().0, "200");
	let origin = node.origin.as_ref().unwrap();
	assert_eq!(origin.heads.lock().unwrap().len(), 1 + 2, "{:?}", origin.heads.lock().unwrap().iter().map(|head| head_of(head)).collect::<Vec<_>>());
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rapid_resets_and_streams_that_end_early_trip_a_limit_whoever_ends_them() {
	let node = Node::launch("rapid", Some("on"), Some(origin().await)).await;
	let mut client = node.client().await;
	// The peer's own resets: a request and a reset of it, again and again.
	for _ in 0..140 {
		let id = client.get("/hold").await;
		let mut out = Vec::new();
		frames::rst_stream(id, frames::CANCEL, &mut out);
		client.send(&out).await;
	}
	assert_eq!(client.closed(Duration::from_secs(3)).await, Some(frames::ENHANCE_YOUR_CALM));
	let totals = node.totals();
	assert_eq!((totals.h2_rapid, totals.h2_flood), (1, 0), "{totals:?}");
	// The resets the node makes itself count the same: a peer that makes the node reset its streams (a malformed request, again and again) is held to the same number.
	let mut client = node.client().await;
	for _ in 0..140 {
		client.open(&[(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/"), ("connection", "close")], true).await;
	}
	assert_eq!(client.closed(Duration::from_secs(3)).await, Some(frames::ENHANCE_YOUR_CALM));
	assert_eq!(node.totals().h2_rapid, 2);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_frames_that_carry_nothing_trips_a_limit() {
	let node = Node::launch("flood", Some("on"), Some(origin().await)).await;
	let mut client = node.client().await;
	let mut out = Vec::new();
	for _ in 0..1100 {frames::frame(frames::PRIORITY, 0, 1, &[0, 0, 0, 0, 16], &mut out)}
	client.send(&out).await;
	assert_eq!(client.closed(Duration::from_secs(3)).await, Some(frames::ENHANCE_YOUR_CALM));
	let mut client = node.client().await;
	let mut out = Vec::new();
	// Unknown frame types and empty DATA frames on an open stream are the same nothing.
	let id = client.open(&[(":method", "POST"), (":authority", "node.test"), (":scheme", "https"), (":path", "/hold")], false).await;
	for _ in 0..600 {frames::frame(0xee, 0, 0, &[], &mut out)}
	for _ in 0..600 {frames::frame(frames::DATA, 0, id, &[], &mut out)}
	client.send(&out).await;
	assert_eq!(client.closed(Duration::from_secs(3)).await, Some(frames::ENHANCE_YOUR_CALM));
	assert_eq!(node.totals().h2_flood, 2);
	// A PING flood the peer never reads the answers of: the unanswered control frames are bounded too.
	let mut client = node.client().await;
	let mut out = Vec::new();
	for _ in 0..400 {frames::frame(frames::PING, 0, 0, &[7; 8], &mut out)}
	client.send(&out).await;
	let code = client.closed(Duration::from_secs(3)).await;
	assert!(code.is_none() || code == Some(frames::ENHANCE_YOUR_CALM), "{code:?}");
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_header_block_the_first_headers_and_the_preface_are_held_to_their_bounds() {
	let node = Node::launch("bounds", Some("on"), Some(origin().await)).await;
	// A header block over 65,536 bytes of CONTINUATION frames ends the connection.
	let mut client = node.client().await;
	let mut out = Vec::new();
	frames::frame(frames::HEADERS, 0, 1, &vec![0x82; 16384], &mut out);
	for _ in 0..5 {frames::frame(frames::CONTINUATION, 0, 1, &vec![0x82; 16384], &mut out)}
	client.send(&out).await;
	assert_eq!(client.closed(Duration::from_secs(3)).await, Some(frames::ENHANCE_YOUR_CALM));
	// A decoded list over the bound resets the stream, and the table stays in step for the next.
	let mut client = node.client().await;
	let long = "v".repeat(4000);
	let many: Vec<(&str, &str)> = [(":method", "GET"), (":authority", "node.test"), (":scheme", "https"), (":path", "/")].into_iter().chain(std::iter::repeat_n(("x-long", long.as_str()), 20)).collect();
	let id = client.open(&many, true).await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap_err(), frames::REFUSED_STREAM);
	let id = client.get("/").await;
	assert_eq!(client.answer(id, Duration::from_secs(3), true).await.unwrap().0, "200");
	// HTTP/1.1 after choosing h2 gets a GOAWAY with PROTOCOL_ERROR.
	let mut io = node.tls(0).await;
	io.write_all(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n").await.unwrap();
	let mut buf = Vec::new();
	let _ = timeout(Duration::from_secs(3), io.read_to_end(&mut buf)).await;
	let goaway = buf.windows(frames::HEADER).position(|window| window[3] == frames::GOAWAY).expect("no GOAWAY");
	assert_eq!(u32::from_be_bytes(buf[goaway + frames::HEADER + 4..goaway + frames::HEADER + 8].try_into().unwrap()), frames::PROTOCOL_ERROR);
	// No HEADERS within 10 s closes the connection with NO_ERROR.
	let mut client = node.client().await;
	assert_eq!(client.closed(Duration::from_secs(12)).await, Some(frames::NO_ERROR));
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_answer_is_read_at_the_pace_of_its_peer_and_the_windows_are_the_defaults() {
	let node = Node::launch("pace", Some("on"), Some(origin().await)).await;
	let mut client = node.client().await;
	let id = client.get("/big/300000").await;
	// Without credit the node sends the default window and no more.
	let mut got = 0;
	let deadline = Instant::now() + SECOND * 2;
	while let Some((header, payload)) = client.frame(deadline.saturating_duration_since(Instant::now())).await {
		if header.kind == frames::DATA && header.stream == id {got += payload.len()}
	}
	assert_eq!(got, 65_535);
	// With credit the rest comes.
	let mut out = Vec::new();
	frames::window_update(0, 300_000, &mut out);
	frames::window_update(id, 300_000, &mut out);
	client.send(&out).await;
	let mut rest = 0;
	let mut ended = false;
	let deadline = Instant::now() + Duration::from_secs(5);
	while !ended {
		let Some((header, payload)) = client.frame(deadline.saturating_duration_since(Instant::now())).await else {break};
		if header.kind == frames::DATA && header.stream == id {
			rest += payload.len();
			ended = header.flags & frames::END_STREAM != 0;
		}
	}
	assert_eq!((rest, ended), (300_000 - 65_535, true));
	// A stranger is never told of a larger window.
	assert_eq!(node.totals().h2_strangers, 1);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_connection_holds_six_upstream_connections_and_the_rest_wait_and_are_refused() {
	let node = Node::launch("six", Some("on"), Some(origin().await)).await;
	let mut client = node.client().await;
	let ids = [client.get("/hold").await, client.get("/hold").await, client.get("/hold").await, client.get("/hold").await, client.get("/hold").await, client.get("/hold").await, client.get("/hold").await, client.get("/hold").await];
	tokio::time::sleep(SECOND).await;
	assert_eq!(node.origin.as_ref().unwrap().connections.load(Ordering::SeqCst), 6);
	let deadline = Instant::now() + Duration::from_secs(8);
	let mut refused = Vec::new();
	while let Some((header, payload)) = client.frame(deadline.saturating_duration_since(Instant::now())).await {
		if header.kind == frames::RST_STREAM && payload[..4] == frames::REFUSED_STREAM.to_be_bytes() {refused.push(header.stream)}
	}
	// Which two wait depends on which tasks reach the semaphore first, so the two refused are any two of the eight.
	assert_eq!((refused.len(), refused.iter().all(|id| ids.contains(id))), (2, true));
	node.engine.shutdown().await;
}

fn address(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	Some((tcp, if let PayloadSlice::Tcp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_gets_the_tunnel_in_both_directions_over_an_extended_connect_and_the_larger_windows() {
	let node = Node::launch("user", Some("on"), None).await;
	let mut client = node.client().await;
	let prover = proof::Client::new(&proof::public_key(&TRANSPORT), &[0xa0; 32], &veilway_wg::public_key(&NODE), &veilway_wg::public_key(&KEY));
	let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
	let proof = prover.prove(Name::Tls, now, &mut random).unwrap();
	let target = format!("{PATH}?{}", proof.token);
	let id = client.open(&[(":method", "CONNECT"), (":protocol", "websocket"), (":authority", "node.test"), (":scheme", "https"), (":path", &target), ("sec-websocket-version", "13"), ("origin", "https://node.test"), ("user-agent", "browser")], false).await;
	// Before the user's proof was accepted the node had offered the defaults. The answer is a 200 with the fields of the upgrade answer, in lowercase, and a cookie.
	let mut windows = (None, None);
	let (header, payload) = loop {
		let frame = client.frame(Duration::from_secs(3)).await.expect("no answer");
		match frame.0.kind {
			frames::SETTINGS if frame.0.flags & frames::ACK == 0 => windows.0 = frames::read_settings(&frame.1).unwrap().find(|(known, _)| *known == frames::INITIAL_WINDOW_SIZE).map(|(_, value)| value).or(windows.0),
			frames::WINDOW_UPDATE if frame.0.stream == 0 => windows.1 = Some(u32::from_be_bytes(frame.1[..4].try_into().unwrap())),
			_ => {}
		}
		if frame.0.kind == frames::HEADERS && frame.0.stream == id {break frame}
	};
	assert_eq!(header.flags & frames::END_STREAM, 0);
	let list = client.decoder.decode(&payload, 65536).unwrap().unwrap();
	let fields: Vec<(String, String)> = list.into_iter().map(|(name, value)| (String::from_utf8(name).unwrap(), String::from_utf8(value).unwrap())).collect();
	assert_eq!(fields[0], (":status".to_string(), "200".to_string()));
	assert!(field(&fields, "set-cookie")[0].starts_with("sid="), "{fields:?}");
	for gone in ["upgrade", "connection", "sec-websocket-accept"] {assert!(field(&fields, gone).is_empty(), "{gone}")}
	let mut tunn = Tunn::new(StaticSecret::from(KEY), PublicKey::from(veilway_wg::public_key(&NODE)), None, None, 0, None);
	let (mut sealer, mut opener) = (Sealer::new(proof.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap()), Opener::new(proof.keys.s2c));
	let mut scratch = vec![0u8; 2048];
	let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut scratch, true) else {panic!("no initiation")};
	let init = init.to_vec();
	let (mut out, mut sealed, mut framed) = (Vec::new(), Vec::new(), Vec::new());
	let mut put = |client_out: &mut Vec<u8>, sealer: &mut Sealer, datagrams: &[&[u8]]| {
		sealed.clear();
		framed.clear();
		sealer.seal(datagrams, false, &mut random, &mut sealed).unwrap();
		websocket::frame(BINARY, &sealed, Some([0x3a, 0x5c, 0x11, 0x7e]), &mut framed);
		frames::frame(frames::DATA, 0, id, &framed, client_out);
	};
	put(&mut out, &mut sealer, &[&init]);
	client.send(&out).await;
	// What the node sends back on the stream is WebSocket frames in DATA frames.
	let mut stream_bytes = Vec::new();
	let mut chunks: Vec<Vec<Vec<u8>>> = Vec::new();
	let deadline = Instant::now() + Duration::from_secs(3);
	while chunks.is_empty() {
		let (header, payload) = client.frame(deadline.saturating_duration_since(Instant::now())).await.expect("no first chunk");
		match header.kind {
			frames::DATA if header.stream == id => stream_bytes.extend_from_slice(&payload),
			frames::SETTINGS if header.flags & frames::ACK == 0 => windows.0 = frames::read_settings(&payload).unwrap().find(|(id, _)| *id == frames::INITIAL_WINDOW_SIZE).map(|(_, value)| value),
			frames::WINDOW_UPDATE if header.stream == 0 => windows.1 = Some(u32::from_be_bytes(payload[..4].try_into().unwrap())),
			_ => {}
		}
		while let Ok(Some(head)) = websocket::header(&stream_bytes) {
			if stream_bytes.len() < head.size + head.payload as usize {break}
			let mut frame: Vec<u8> = stream_bytes.drain(..head.size + head.payload as usize).collect();
			assert!(head.fin && head.mask.is_none());
			if head.opcode == BINARY {chunks.push(opener.open(&mut frame[head.size..]).unwrap().map(<[u8]>::to_vec).collect())}
		}
	}
	assert_eq!(chunks[0][0].len(), 92, "the first answer is the handshake response");
	let mut response_out = vec![0u8; 2048];
	let TunnResult::WriteToNetwork(keepalive) = tunn.decapsulate(None, &chunks[0][0], &mut response_out) else {panic!("no handshake response")};
	let keepalive = keepalive.to_vec();
	let mut out = Vec::new();
	put(&mut out, &mut sealer, &[&keepalive]);
	client.send(&out).await;
	// A SYN to a public address leaves through the exit: the proxy's first word comes back through the tunnel, so packets went up and down.
	let (mut syn, mut packet) = (TcpHeader::new(40000, 80, 1000, 65535), Vec::new());
	syn.syn = true;
	PacketBuilder::ipv4(ADDRESS, PUBLIC, 64).tcp_header(syn).write(&mut packet, &[]).unwrap();
	let mut datagram = vec![0u8; packet.len() + 2048];
	let TunnResult::WriteToNetwork(sealed_packet) = tunn.encapsulate(&packet, &mut datagram) else {panic!("no session")};
	let sealed_packet = sealed_packet.to_vec();
	let mut out = Vec::new();
	put(&mut out, &mut sealer, &[&sealed_packet]);
	client.send(&out).await;
	let mut answered = false;
	let deadline = Instant::now() + Duration::from_secs(4);
	'wait: while let Some((header, payload)) = client.frame(deadline.saturating_duration_since(Instant::now())).await {
		match header.kind {
			frames::DATA if header.stream == id => stream_bytes.extend_from_slice(&payload),
			frames::SETTINGS if header.flags & frames::ACK == 0 => windows.0 = frames::read_settings(&payload).unwrap().find(|(id, _)| *id == frames::INITIAL_WINDOW_SIZE).map(|(_, value)| value).or(windows.0),
			frames::WINDOW_UPDATE if header.stream == 0 => windows.1 = Some(u32::from_be_bytes(payload[..4].try_into().unwrap())),
			_ => {}
		}
		while let Ok(Some(head)) = websocket::header(&stream_bytes) {
			if stream_bytes.len() < head.size + head.payload as usize {break}
			let mut frame: Vec<u8> = stream_bytes.drain(..head.size + head.payload as usize).collect();
			if head.opcode != BINARY {continue}
			let items: Vec<Vec<u8>> = opener.open(&mut frame[head.size..]).unwrap().map(<[u8]>::to_vec).collect();
			for item in items {
				let mut plain = vec![0u8; 2048];
				if let TunnResult::WriteToTunnelV4(inner, _) = tunn.decapsulate(None, &item, &mut plain) {
					if address(inner).is_some_and(|(tcp, _)| tcp.syn && tcp.ack && tcp.source_port == 80) {
						answered = true;
						break 'wait;
					}
				}
			}
		}
	}
	assert!(answered, "the SYN of the tunnel was not answered");
	// Only a user's connection is told of the larger windows, by a second SETTINGS and a WINDOW_UPDATE.
	assert_eq!(windows, (Some(6_291_456), Some(15_728_640 - 65_535)));
	// Another stream of the same connection is served as a stranger's.
	let other = client.get("/").await;
	assert_eq!(client.answer(other, Duration::from_secs(3), true).await.unwrap().0, "200");
	let totals = node.totals();
	assert_eq!((totals.h2_users, totals.h2_strangers, totals.proofs_accepted), (1, 1, 1), "{totals:?}");
	node.engine.shutdown().await;
}
