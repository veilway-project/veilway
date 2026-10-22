//! What the tests of the proxy path share (`tests/ws.rs` and `tests/fronted.rs`): a node that is started the way `veilway run` starts it, with a `ws` and a `fronted` transport on one listener, a real small web server behind it as the decoy origin, and a small reverse proxy in front of it as the operator's web server.
//! The reverse proxy is written here on sockets, because it has to hand on what a careful web server would refuse: it keeps one connection to its upstream for each connection of a client, adds the address it took the request from to every request, and changes nothing else.
//! The node's clock is each test's own, so a test that needs minutes to pass moves the clock and waits for the node's next look at it.
#![allow(dead_code, async_fn_in_trait)]
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use socket2::SockRef;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use veilway_core::config::Config;
use veilway_core::{Engine, Options, StreamTotals};
use veilway_proto::chunk::{Opener, Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::control::PORT;
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::ClientOpening;
use veilway_proto::proof::{self, Name};
use veilway_proto::websocket::{self, BINARY, CLOSE};
use veilway_proto::{fronted, NoRandom};

pub const GATEWAY: [u8; 4] = [10, 7, 0, 1];
pub const PUBLIC: [u8; 4] = [93, 184, 216, 34];
// Keys and secrets of tests are fixed patterns, and no secret of anything real. Device `n` has the private key `KEYS[n]`, the tunnel address 10.7.0.(2 + n) and the transport secret `secret(n)`.
pub const NODE: [u8; 32] = [0x10; 32];
pub const KEYS: [[u8; 32]; 6] = [[0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32], [0x25; 32], [0x26; 32]];
/// The node transport key of the inbound, private half, and the one it is rotated to.
pub const TRANSPORT: [u8; 32] = [0x51; 32];
pub const ROTATED: [u8; 32] = [0x52; 32];
/// The paths of the `ws` and of the `fronted` transport, which the origin serves nothing at.
pub const WS_PATH: &str = "/assets/live-7c1d0a52.js";
pub const POLL_PATH: &str = "/assets/sync-90be44f1.js";
/// The path of the `fronted-shaped` transport of a test that adds one (`with_shape`).
pub const SHAPED_PATH: &str = "/assets/shape-4d1e90b7.js";
pub const SECOND: Duration = Duration::from_secs(1);
/// What a quiet connection is given to stay quiet in.
pub const QUIET: Duration = Duration::from_millis(500);
/// What a connection to a port nobody listens at is given to be refused in: Windows retries the SYN for about two seconds before it reports the refusal, where Linux and macOS refuse at once. The node's own limit is 5 s.
pub const REFUSED: Duration = Duration::from_secs(4);
/// What the test origin gives a peer to send its request head in, and after which it closes a connection it kept for another request.
pub const HEAD: Duration = Duration::from_secs(2);
/// What the reverse proxy gives a client to send a request head in, from the connection's first moment and from the end of the request before. It is above `HEAD`, so a connection the origin gives up is seen to be given up by the origin.
pub const FRONT_HEAD: Duration = Duration::from_secs(4);
pub const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
pub const PAGE: &str = "<html>the operator's own site</html>\n";
pub const MISS: &str = "nothing here\n";
/// Where the reverse proxy is, as the node sees it, and where a client is that nobody said otherwise of.
pub const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1));
/// Port 0 is no listen port of a config, so every listener of a test node takes the next one from here.
static NEXT_PORT: AtomicU16 = AtomicU16::new(28000);
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

pub fn logged(text: &str) -> bool {String::from_utf8_lossy(&LOGS.lock().unwrap()).contains(text)}

/// The lines of the log that hold `text`, newest last.
pub fn lines(text: &str) -> Vec<String> {String::from_utf8_lossy(&LOGS.lock().unwrap()).lines().filter(|line| line.contains(text)).map(str::to_owned).collect()}

pub fn listen() -> SocketAddr {SocketAddr::from((Ipv4Addr::LOCALHOST, NEXT_PORT.fetch_add(1, Ordering::SeqCst)))}

pub fn text(key: &[u8; 32]) -> String {veilway_wg::encode_key(key)}

pub fn public(private: &[u8; 32]) -> [u8; 32] {veilway_wg::public_key(private)}

pub fn secret(device: usize) -> [u8; 32] {[0xa0 + device as u8; 32]}

pub fn address(device: usize) -> [u8; 4] {[10, 7, 0, 2 + device as u8]}

pub fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for part in bytes.chunks_mut(32) {part.copy_from_slice(&veilway_wg::generate_key()[..part.len()])}
	Ok(())
}

/// The clock of one test's node: the real one and however far the test has moved it ahead.
#[derive(Clone, Copy)]
pub struct Time {pub ahead: &'static AtomicI64, pub now: fn() -> OffsetDateTime}

impl Time {
	pub fn secs(&self) -> u64 {(self.now)().unix_timestamp() as u64}
}

/// A clock of its own for the test that calls it: tests run side by side, and one that moves time must not move another's.
macro_rules! time {
	() => {{
		static AHEAD: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
		fn now() -> time::OffsetDateTime {time::OffsetDateTime::now_utc() + time::Duration::seconds(AHEAD.load(std::sync::atomic::Ordering::SeqCst))}
		$crate::proxied::Time {ahead: &AHEAD, now}
	}};
}

/// A SOCKS5 proxy without authentication that answers every CONNECT with `main` and then holds the connection open.
pub async fn socks() -> SocketAddr {
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

/// A SOCKS5 proxy without authentication that dials what each CONNECT asks for, relays it, and says what it was asked for as `host:port`. A CONNECT to `refuse` is answered with a refusal instead. IPv4 targets only.
pub async fn forwarder(refuse: Option<SocketAddr>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let seen = Arc::new(Mutex::new(Vec::new()));
	let asked = seen.clone();
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {return};
			let asked = asked.clone();
			tokio::spawn(async move {
				let (mut hello, mut head, mut target) = ([0u8; 2], [0u8; 4], [0u8; 6]);
				if client.read_exact(&mut hello).await.is_err() {return}
				let mut methods = vec![0u8; usize::from(hello[1])];
				if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut head).await.is_err() || head[3] != 1 || client.read_exact(&mut target).await.is_err() {return}
				let at = SocketAddr::from(([target[0], target[1], target[2], target[3]], u16::from_be_bytes([target[4], target[5]])));
				asked.lock().unwrap().push(at.to_string());
				let connected = if Some(at) == refuse {None} else {TcpStream::connect(at).await.ok()};
				let Some(mut upstream) = connected else {let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await; return};
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {return}
				let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
			});
		}
	});
	(addr, seen)
}

/// The operator's own web site. `seen` holds what the hand-written one read of every connection, the PROXY protocol header included.
pub struct Site {pub addr: SocketAddr, pub connections: Arc<AtomicUsize>, pub requests: Arc<AtomicUsize>, pub written: Arc<AtomicUsize>, pub seen: Arc<Mutex<Vec<Vec<u8>>>>, task: JoinHandle<()>}

impl Drop for Site {
	fn drop(&mut self) {self.task.abort()}
}

/// A real HTTP/1.1 server (hyper) with one page, a miss for every other path, and its own limit on how long a request head may take. It answers `delay` after a request came. Everything it does to a connection is its own doing, which is what the node has to pass on.
pub fn site_on(listener: TcpListener, delay: Duration, head: Duration) -> Site {
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
							Ok::<_, Infallible>(Response::builder().status(if found {200} else {404}).header("server", "decoy/1.0").header("x-site", "one").body(Full::new(Bytes::from(if found {PAGE} else {MISS}))).unwrap())
						}
					});
					let _ = hyper::server::conn::http1::Builder::new().timer(TokioTimer::new()).header_read_timeout(head).half_close(true).serve_connection(TokioIo::new(stream), page).await;
				});
			}
		}
	});
	Site {addr, connections, requests, written: Arc::default(), seen: Arc::default(), task}
}

pub async fn site() -> Site {site_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), Duration::ZERO, HEAD)}

/// A site that keeps a quiet connection for longer than a test takes, and answers `delay` after a request came.
pub async fn patient(delay: Duration) -> Site {site_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), delay, Duration::from_secs(60))}

/// The length of the head the hand-written origin writes before a body of the size it was asked for.
pub const BULK_HEAD: usize = "HTTP/1.1 200 OK\r\nContent-Length: 0000000000\r\n\r\n".len();

/// An origin written by hand, for what a real server does only when it is made to. It reads one request head after another on a connection, with `skip` bytes before the first that are no request: the PROXY protocol header of a node that sends one.
/// `GET /big/<bytes>` is answered with that many bytes, counted in `written` as they are written, and `GET /slow/<millis>` with a short answer after that long. `/echo` is the upgrade of a WebSocket endpoint of the site's own, which sends back whatever comes. `/reset` is half an answer and then a reset.
/// `/body/<bytes>` reads that many bytes behind the head and says how many came. `/continue` says `100 Continue`, reads the five bytes it was promised, and answers. `/close` answers and closes. Everything else gets a short answer, and the connection is kept.
pub async fn raw(skip: usize) -> Site {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, connections, requests, written, seen) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(Vec::new())));
	let task = tokio::spawn({
		let (connections, requests, written, seen) = (connections.clone(), requests.clone(), written.clone(), seen.clone());
		async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else {return};
				let (at, requests, written, seen) = (connections.fetch_add(1, Ordering::SeqCst), requests.clone(), written.clone(), seen.clone());
				seen.lock().unwrap().push(Vec::new());
				tokio::spawn(async move {
					let (mut buf, mut filled, mut skip) = (vec![0u8; 65536], 0, skip);
					loop {
						let end = loop {
							if let Some(end) = buf[skip.min(filled)..filled].windows(4).position(|window| window == b"\r\n\r\n").filter(|_| filled >= skip) {break skip + end + 4}
							match stream.read(&mut buf[filled..]).await {
								Ok(read) if read > 0 => {
									seen.lock().unwrap()[at].extend_from_slice(&buf[filled..filled + read]);
									filled += read;
								}
								_ => return,
							}
						};
						requests.fetch_add(1, Ordering::SeqCst);
						let line = String::from_utf8_lossy(&buf[skip..end]).lines().next().unwrap_or_default().to_string();
						buf.copy_within(end..filled, 0);
						(filled, skip) = (filled - end, 0);
						let mut parts = line.split(' ').nth(1).unwrap_or_default().split('/').skip(1);
						let (what, size) = (parts.next().unwrap_or_default().to_string(), parts.next().and_then(|size| size.parse::<usize>().ok()).unwrap_or(0));
						match what.as_str() {
							"big" => {
								if stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {size:010}\r\n\r\n").as_bytes()).await.is_err() {return}
								let (block, mut left) = (vec![0x61u8; 16 * 1024], size);
								while left > 0 {
									let count = left.min(block.len());
									if stream.write_all(&block[..count]).await.is_err() {return}
									written.fetch_add(count, Ordering::SeqCst);
									left -= count;
								}
							}
							"slow" => {
								tokio::time::sleep(Duration::from_millis(size as u64)).await;
								if stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 4\r\n\r\nslow").await.is_err() {return}
							}
							"echo" => {
								if stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.is_err() || stream.write_all(&buf[..filled]).await.is_err() {return}
								let mut said = [0u8; 4096];
								while let Ok(read) = stream.read(&mut said).await {
									if read == 0 || stream.write_all(&said[..read]).await.is_err() {return}
								}
								return;
							}
							"reset" => {
								let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhalf of it").await;
								tokio::time::sleep(Duration::from_millis(300)).await;
								let _ = SockRef::from(&stream).set_linger(Some(Duration::ZERO));
								return;
							}
							"body" | "continue" => {
								let wanted = if what == "body" {size} else {5};
								if what == "continue" && stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.is_err() {return}
								while filled < wanted {
									match stream.read(&mut buf[filled..]).await {
										Ok(read) if read > 0 => {
											seen.lock().unwrap()[at].extend_from_slice(&buf[filled..filled + read]);
											filled += read;
										}
										_ => return,
									}
								}
								buf.copy_within(wanted..filled, 0);
								filled -= wanted;
								if stream.write_all(format!("HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 10\r\n\r\n{wanted:010}").as_bytes()).await.is_err() {return}
							}
							"close" => return drop(stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await),
							_ => if stream.write_all(b"HTTP/1.1 200 OK\r\nServer: raw\r\nContent-Length: 2\r\n\r\nok").await.is_err() {return},
						}
					}
				});
			}
		}
	});
	Site {addr, connections, requests, written, seen, task}
}

/// What a scripted origin does with a connection once it has written its answer to a request: keep it, close it, or after so many milliseconds write these bytes that nobody asked for, and close it when there are none.
pub enum Then {Keep, Close, Later(u64, &'static [u8])}

/// An origin that does to each request what `act` says: for the number of its connection, the number of the request on that connection and its request line, the bytes to write and what to do then. No bytes and `Close` is a connection closed with no answer.
/// It reads heads only, so a request with a body is not for it. It is here for what no web server does on purpose and some do: speak on a quiet connection, write more than one answer, close a connection it kept.
pub async fn scripted(act: fn(usize, usize, &str) -> (&'static [u8], Then)) -> Site {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, connections, requests, seen) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(Vec::new())));
	let task = tokio::spawn({
		let (connections, requests, seen) = (connections.clone(), requests.clone(), seen.clone());
		async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else {return};
				let (at, requests, seen) = (connections.fetch_add(1, Ordering::SeqCst), requests.clone(), seen.clone());
				seen.lock().unwrap().push(Vec::new());
				tokio::spawn(async move {
					let (mut buf, mut read, mut asked) = (Vec::new(), vec![0u8; 16384], 0);
					loop {
						let end = loop {
							if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {break end + 4}
							match stream.read(&mut read).await {
								Ok(size) if size > 0 => {
									seen.lock().unwrap()[at].extend_from_slice(&read[..size]);
									buf.extend_from_slice(&read[..size]);
								}
								_ => return,
							}
						};
						requests.fetch_add(1, Ordering::SeqCst);
						let head: Vec<u8> = buf.drain(..end).collect();
						let (answer, then) = act(at, asked, String::from_utf8_lossy(&head).lines().next().unwrap_or_default());
						asked += 1;
						if stream.write_all(answer).await.is_err() {return}
						match then {
							Then::Keep => {}
							Then::Close => return,
							Then::Later(millis, said) => {
								tokio::time::sleep(Duration::from_millis(millis)).await;
								if said.is_empty() || stream.write_all(said).await.is_err() {return}
							}
						}
					}
				});
			}
		}
	});
	Site {addr, connections, requests, written: Arc::default(), seen, task}
}

/// Reads one answer from a connection: its head, and its body by the length the head names. None when the connection ended first or nothing more came within `budget`.
pub async fn reply(io: &mut (impl AsyncRead + Unpin), budget: Duration) -> Option<String> {
	let (deadline, mut got, mut buf) = (Instant::now() + budget, Vec::new(), vec![0u8; 65536]);
	loop {
		if let Some(end) = got.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {
			let length = String::from_utf8_lossy(&got[..end]).split("\r\n").find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|length| length.trim().parse::<usize>().ok())).unwrap_or(0);
			if got.len() >= end + length {return Some(String::from_utf8_lossy(&got[..end + length]).into_owned())}
		}
		match timeout(deadline.checked_duration_since(Instant::now())?, io.read(&mut buf)).await {
			Ok(Ok(count)) if count > 0 => got.extend_from_slice(&buf[..count]),
			_ => return None,
		}
	}
}

/// The operator's web server in front of the node, as far as the node can tell: a reverse proxy on sockets. It asks its upstream nothing before it has a whole request head, as a web server does that buffers heads, keeps one upstream connection for each connection of a client, and uses it for every request of that client.
/// It adds one field to the end of every head, `X-Forwarded-For` with the address it took the request from, and hands on every other byte as it came, in both directions, with closes and resets. It reads bodies leniently, as a careless proxy would: `chunked` before a length, the first length of several, and whatever stands in a chunk size line behind its digits.
/// A request with an `Upgrade` field, and one whose body it cannot follow, turns the client's connection into a pipe to the upstream. `upstreams` counts the connections it opened.
pub struct Front {pub addr: SocketAddr, pub upstreams: Arc<AtomicUsize>, task: JoinHandle<()>}

impl Drop for Front {
	fn drop(&mut self) {self.task.abort()}
}

// What a lenient proxy takes the value of a header field to be: the first field of that name, wherever blanks stand.
fn field(head: &[u8], name: &str) -> Option<String> {String::from_utf8_lossy(head).split("\r\n").skip(1).find_map(|line| line.split_once(':').filter(|(found, _)| found.trim().eq_ignore_ascii_case(name)).map(|(_, value)| value.trim().to_string()))}

// Hands the next `count` bytes of the client's connection to the upstream, from what was read already and then from the socket. False when either connection ended first.
async fn pass(from: &mut OwnedReadHalf, to: &mut (impl AsyncWrite + Unpin), buf: &mut Vec<u8>, mut count: usize) -> bool {
	while count > 0 {
		if buf.is_empty() {
			if to.flush().await.is_err() {return false}
			let mut read = vec![0u8; 16384];
			match from.read(&mut read).await {
				Ok(size) if size > 0 => buf.extend_from_slice(&read[..size]),
				_ => return false,
			}
		}
		let take = count.min(buf.len());
		if to.write_all(&buf[..take]).await.is_err() {return false}
		buf.drain(..take);
		count -= take;
	}
	true
}

// Hands one line of the client's connection to the upstream, its line feed included. None when a connection ended first.
async fn line(from: &mut OwnedReadHalf, to: &mut (impl AsyncWrite + Unpin), buf: &mut Vec<u8>) -> Option<Vec<u8>> {
	loop {
		if let Some(end) = buf.iter().position(|byte| *byte == b'\n') {
			let line: Vec<u8> = buf.drain(..=end).collect();
			return to.write_all(&line).await.is_ok().then_some(line);
		}
		if to.flush().await.is_err() {return None}
		let mut read = vec![0u8; 16384];
		match from.read(&mut read).await {
			Ok(size) if size > 0 => buf.extend_from_slice(&read[..size]),
			_ => return None,
		}
	}
}

pub async fn front(upstream: SocketAddr) -> Front {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, upstreams, base) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)), tokio::time::Instant::now());
	let task = tokio::spawn({
		let upstreams = upstreams.clone();
		async move {
			loop {
				let Ok((client, peer)) = listener.accept().await else {return};
				let upstreams = upstreams.clone();
				tokio::spawn(async move {
					let _ = client.set_nodelay(true);
					let (mut from_client, write) = client.into_split();
					let (from_client, mut buf, mut to_client, mut to_upstream, mut relay) = (&mut from_client, Vec::new(), Some(write), None::<OwnedWriteHalf>, None::<JoinHandle<()>>);
					// When the answer last moved, in milliseconds after `base`, and `u64::MAX` while a write to the client is under way: a client that is still being handed an answer is not a client that left the next request unsent.
					let moved = Arc::new(AtomicU64::new(0));
					loop {
						// A whole head, within its time, before anybody is asked. What ends the wait otherwise: the upstream closed, the client closed its side, or the client gave up or took too long.
						let deadline = tokio::time::Instant::now() + FRONT_HEAD;
						let end = loop {
							if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {break Ok(end + 4)}
							let mut read = vec![0u8; 16384];
							let got = tokio::select! {
								_ = async {
									match relay.as_mut() {
										Some(relay) => drop(relay.await),
										None => std::future::pending().await,
									}
								} => break Err(None),
								got = async {
									loop {
										let at = || match moved.load(Ordering::Relaxed) {u64::MAX => tokio::time::Instant::now() + FRONT_HEAD, at => deadline.max(base + Duration::from_millis(at) + SECOND)};
										let got = tokio::time::timeout_at(at(), from_client.read(&mut read)).await;
										if got.is_err() && tokio::time::Instant::now() < at() {continue}
										break got;
									}
								} => got,
							};
							match got {
								Ok(Ok(size)) if size > 0 && buf.len() + size <= 262_144 => buf.extend_from_slice(&read[..size]),
								Ok(Ok(0)) => break Err(Some(true)),
								_ => break Err(Some(false)),
							}
						};
						let end = match end {
							Ok(end) => end,
							Err(None) => return,
							// A client that closed its side behind a whole request is told to the upstream as that, and the upstream's answer is waited for. Anything else ends both connections.
							Err(Some(closed)) => {
								if let (Some(to_upstream), Some(relay)) = (to_upstream.as_mut(), relay.take()) {
									if closed && buf.is_empty() {
										let _ = to_upstream.shutdown().await;
										let _ = relay.await;
									} else {relay.abort()}
								}
								return;
							}
						};
						let head: Vec<u8> = buf.drain(..end).collect();
						if to_upstream.is_none() {
							let socket = TcpSocket::new_v4().unwrap();
							socket.bind(SocketAddr::new(PROXY, 0)).unwrap();
							let Ok(dialed) = socket.connect(upstream).await else {return};
							let _ = dialed.set_nodelay(true);
							upstreams.fetch_add(1, Ordering::SeqCst);
							let ((mut from_upstream, write), Some(mut to_client)) = (dialed.into_split(), to_client.take()) else {return};
							to_upstream = Some(write);
							let moved = moved.clone();
							relay = Some(tokio::spawn(async move {
								let mut answer = vec![0u8; 16384];
								loop {
									match from_upstream.read(&mut answer).await {
										Ok(size) if size > 0 => {
											moved.store(u64::MAX, Ordering::Relaxed);
											if to_client.write_all(&answer[..size]).await.is_err() {return}
											moved.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
										}
										Ok(_) => return drop(to_client.shutdown().await),
										Err(_) => return drop(SockRef::from(to_client.as_ref()).set_linger(Some(Duration::ZERO))),
									}
								}
							}));
						}
						// What the client sent in one piece goes to the upstream in one piece, as a reverse proxy does it: an origin that answers before its request is whole in what it read does not read the rest, and the proxy's two writes would otherwise make that depend on whether it read between them.
						let Some(upstream) = to_upstream.as_mut() else {return};
						let mut to = BufWriter::with_capacity(1 << 20, upstream);
						if to.write_all(&[&head[..head.len() - 2], format!("X-Forwarded-For: {}\r\n\r\n", peer.ip()).as_bytes()].concat()).await.is_err() {break}
						let (chunked, length) = (field(&head, "transfer-encoding").is_some_and(|coding| coding.to_ascii_lowercase().contains("chunked")), field(&head, "content-length").and_then(|length| length.parse::<usize>().ok()));
						let followed = if field(&head, "upgrade").is_some() {false} else if chunked {
							loop {
								let Some(size) = line(from_client, &mut to, &mut buf).await else {break false};
								let digits: String = String::from_utf8_lossy(&size).chars().take_while(char::is_ascii_hexdigit).collect();
								let Ok(size) = usize::from_str_radix(&digits, 16) else {break false};
								if size > 0 {
									if !pass(from_client, &mut to, &mut buf, size).await || line(from_client, &mut to, &mut buf).await.is_none() {break false}
									continue;
								}
								// The trailer, to its empty line.
								break loop {
									match line(from_client, &mut to, &mut buf).await {
										Some(trailer) if trailer.len() <= 2 => break true,
										Some(_) => {}
										None => break false,
									}
								};
							}
						} else {pass(from_client, &mut to, &mut buf, length.unwrap_or(0)).await};
						if followed && to.flush().await.is_err() {break}
						if !followed {
							// A pipe from here on, until either side closes.
							let piped = async {
								if to.write_all(&buf).await.is_err() || to.flush().await.is_err() {return}
								let mut read = vec![0u8; 16384];
								loop {
									match from_client.read(&mut read).await {
										Ok(size) if size > 0 => if to.write_all(&read[..size]).await.is_err() || to.flush().await.is_err() {return},
										Ok(_) => return drop(to.shutdown().await),
										Err(_) => return,
									}
								}
							};
							let Some(relay) = relay.as_mut() else {return};
							tokio::pin!(piped);
							tokio::select! {
								_ = &mut *relay => return,
								_ = &mut piped => {}
							}
							let _ = relay.await;
							return;
						}
					}
					if let Some(relay) = relay {relay.abort()}
				});
			}
		}
	});
	Front {addr, upstreams, task}
}

/// The directory of one test's node.
pub fn folder(test: &str) -> PathBuf {std::env::temp_dir().join(format!("veilway-proxied-{}-{test}", std::process::id()))}

/// A new directory for one test.
pub fn scratch(test: &str) -> PathBuf {
	let dir = folder(test);
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// Writes the replay file a node leaves that was killed with this floor and this limit: a head without the clean mark and without entries, and its hash.
pub fn seed(path: &Path, floor: u64, limit: u64) {
	let body = [&b"VWREPLAY"[..], &1u32.to_be_bytes(), &[0; 4], &floor.to_be_bytes(), &limit.to_be_bytes(), &0u32.to_be_bytes()].concat();
	std::fs::write(path, [&body[..], digest(&SHA256, &body).as_ref()].concat()).unwrap();
}

/// A document with one `veilway` inbound `home` on 10.7.0.1/24 that is reached over `ws` and over `fronted` on one listener at `listen`, behind the reverse proxy at 127.0.0.1 and with the decoy origin `origin`, one exit through `proxy`, and the users `a` to `f` with one device each.
pub fn document(proxy: SocketAddr, listen: SocketAddr, origin: SocketAddr) -> Value {
	let (names, behind) = (["a", "b", "c", "d", "e", "f"], |kind: &str, path: &str| json!({"type": kind, "listen": listen.to_string(), "path": path, "decoy": {"origin": format!("http://{origin}")}, "trusted_proxies": ["127.0.0.1"], "client_address_header": "X-Forwarded-For"}));
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [text(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [behind("ws", WS_PATH), behind("fronted", POLL_PATH)]}],
		"outbounds": [{"tag": "main-proxy", "type": "socks5", "server": proxy.to_string()}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "main-proxy"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": (0..KEYS.len()).map(|device| json!({"name": names[device], "exits": "all", "devices": [{"name": "phone", "public_key": text(&public(&KEYS[device])), "transport_secrets": [text(&secret(device))], "addresses": [Ipv4Addr::from(address(device)).to_string()]}]})).collect::<Vec<_>>()
	})
}

/// Adds a `fronted-shaped` transport with this shape to the one listener of `document`, which it shares with the `ws` and the `fronted` transport: the same decoy, proxies and pools.
pub fn with_shape(doc: &mut Value, shape: &Value) {
	let transports = doc["inbounds"][0]["transports"].as_array_mut().unwrap();
	let mut shaped = transports[1].clone();
	shaped["type"] = json!("fronted-shaped");
	shaped["path"] = json!(SHAPED_PATH);
	shaped["shape"] = shape.clone();
	transports.push(shaped);
}

pub fn parsed(doc: &Value) -> Config {
	let config = Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("the test config does not parse: {e}"));
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	config
}

/// A node with its origin behind it and two reverse proxies: `front` with the node for its upstream, and `bare` with the origin itself, which is what the node is held against.
pub struct Node {pub engine: Engine, pub addr: SocketAddr, pub doc: Value, pub dir: PathBuf, pub time: Time, pub site: Site, pub front: Front, pub bare: Front}

/// Starts the log of the process, once: every line at info goes to `logged`. A test that starts its node by itself calls it first.
pub fn logging() {LOGGING.call_once(|| tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_writer(|| Sink).init());}

/// Starts an engine on `doc` with its files in `dir` and the clock of `time`.
pub async fn start(doc: &Value, dir: &Path, time: Time) -> anyhow::Result<Engine> {
	logging();
	veilway_core::start(&parsed(doc), Options {now: time.now, replay: Some(dir.join("replay")), ..Options::new(dir)}).await
}

/// Starts a node on `document` after `change` had its way with it, with the origin `site` for its decoy. Its replay file is one a node left that was killed 100 seconds ago, so it takes proofs from its first moment.
pub async fn launch_at(test: &str, time: Time, site: Site, change: impl FnOnce(&mut Value)) -> Node {
	let (dir, addr) = (scratch(test), listen());
	let mut doc = document(socks().await, addr, site.addr);
	change(&mut doc);
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let engine = start(&doc, &dir, time).await.unwrap();
	let (front, bare) = (front(addr).await, front(site.addr).await);
	Node {engine, addr, doc, dir, time, site, front, bare}
}

pub async fn launch(test: &str, time: Time, change: impl FnOnce(&mut Value)) -> Node {launch_at(test, time, site().await, change).await}

impl Node {
	pub fn totals(&self) -> StreamTotals {self.engine.stream()}

	pub async fn reload(&mut self, change: impl FnOnce(&mut Value)) {
		change(&mut self.doc);
		parsed(&self.doc);
		self.engine.reload(self.doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
	}

	/// Moves the node's clock ahead and waits until the replay memory has written a limit for the new time, as the node's timer does within a second.
	pub async fn advance(&self, secs: i64) {
		self.time.ahead.fetch_add(secs, Ordering::SeqCst);
		eventually("the replay limit did not follow the clock", || self.engine.replay().is_some_and(|replay| replay.limit >= self.time.secs())).await;
	}

	/// What a visitor at `CLIENT` gets for `request` through the reverse proxy and the node, and whether the connection was closed behind it.
	pub async fn ask(&self, request: &[u8]) -> (String, bool) {
		let (answer, closed, _) = play(dial(self.front.addr, CLIENT).await, &[Step::Send(request.to_vec())], SECOND).await;
		(String::from_utf8_lossy(&answer).into_owned(), closed)
	}

	/// What the node answers its reverse proxy for `request`, with the proxy played by the test: a connection from 127.0.0.1 that names `from` as the visitor.
	pub async fn hand(&self, request: &[u8], from: &str) -> (String, bool) {
		let (answer, closed, _) = play(dial(self.addr, PROXY).await, &[Step::Send(forwarded(request, from))], SECOND).await;
		(String::from_utf8_lossy(&answer).into_owned(), closed)
	}

	/// Device `n` as a client of the `ws` transport, at `CLIENT`, by way of the reverse proxy.
	pub fn device(&self, n: usize) -> Device {Device::new(n, secret(n), &TRANSPORT, self.front.addr)}

	/// Device `n` as a client of the `fronted` transport, the same way.
	pub fn poller(&self, n: usize) -> Poller {Poller::new(n, secret(n), &TRANSPORT, self.front.addr)}
}

/// A connection to `to` from the address `from`.
pub async fn dial(to: SocketAddr, from: IpAddr) -> TcpStream {
	let socket = TcpSocket::new_v4().unwrap();
	socket.bind(SocketAddr::new(from, 0)).unwrap();
	let stream = socket.connect(to).await.unwrap();
	let _ = stream.set_nodelay(true);
	stream
}

/// A request as a reverse proxy hands it on: with the field that names the visitor at the end of its head.
pub fn forwarded(request: &[u8], from: &str) -> Vec<u8> {
	let end = request.windows(4).position(|window| window == b"\r\n\r\n").map_or(request.len(), |end| end + 2);
	if from.is_empty() {request.to_vec()} else {[&request[..end], format!("X-Forwarded-For: {from}\r\n").as_bytes(), &request[end..]].concat()}
}

/// Waits for something the engine does on its own time.
pub async fn eventually(what: &str, done: impl Fn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(30);
	while !done() {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// The upgrade request of a client for `path` with `token`.
pub fn upgrade(path: &str, token: &str) -> Vec<u8> {format!("GET {path}?{token} HTTP/1.1\r\nHost: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n").into_bytes()}

/// A `fronted` request for `target` with `body`.
pub fn post(target: &str, body: &[u8]) -> Vec<u8> {[format!("POST {target} HTTP/1.1\r\nHost: node.test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(), body].concat()}

/// One thing a peer does to a connection.
pub enum Step {Send(Vec<u8>), Wait(u64), Finish}

/// What a connection was like to its peer: when its first byte came and when it was closed from the other side, in milliseconds from its start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Times {pub first: Option<u64>, pub closed: Option<u64>}

/// Does `steps` to a connection and then reads it to its end. What came, whether the connection was closed from the other side before nothing had come for `patience`, and when.
pub async fn play<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, steps: &[Step], patience: Duration) -> (Vec<u8>, bool, Times) {
	let (mut got, mut buf, mut times, started) = (Vec::new(), vec![0u8; 65536], Times::default(), Instant::now());
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
			Ok(Ok(count)) if count > 0 => {
				times.first.get_or_insert(started.elapsed().as_millis() as u64);
				got.extend_from_slice(&buf[..count]);
			}
			Ok(_) => {
				times.closed = Some(started.elapsed().as_millis() as u64);
				return (got, true, times);
			}
			Err(_) => return (got, false, times),
		}
	}
}

/// An answer with the one header field that follows the clock made the same on both sides: `Date` is the origin's own clock at two moments.
pub fn undated(answer: &[u8]) -> String {String::from_utf8_lossy(answer).split("\r\n").map(|line| if line.to_ascii_lowercase().starts_with("date:") {"date: (the origin's clock)"} else {line}).collect::<Vec<_>>().join("\r\n")}

pub fn segment(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	Some((tcp, if let PayloadSlice::Tcp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

/// What a device does with its tunnel, whichever transport carries it: `put` sends one chunk with these WireGuard datagrams, and `chunk` gives the datagrams of the next chunk of the node, none for a padding-only chunk, or None when nothing came in time.
pub trait Link {
	fn n(&self) -> usize;
	fn tunn(&mut self) -> &mut Tunn;
	fn inbox(&mut self) -> &mut VecDeque<Vec<u8>>;
	async fn put(&mut self, datagrams: &[&[u8]]);
	async fn chunk(&mut self, budget: Duration) -> Option<Vec<Vec<u8>>>;

	/// A fresh WireGuard handshake initiation.
	fn initiation(&mut self) -> Vec<u8> {
		let mut scratch = vec![0u8; 2048];
		let TunnResult::WriteToNetwork(init) = self.tunn().format_handshake_initiation(&mut scratch, true) else {panic!("no handshake initiation")};
		init.to_vec()
	}

	/// The WireGuard datagram around one IP packet, or a keepalive for none, under the session the tunnel has.
	fn sealed(&mut self, packet: &[u8]) -> Vec<u8> {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn().encapsulate(packet, &mut out) else {panic!("the tunnel has no session to send under")};
		datagram.to_vec()
	}

	/// Takes the node's handshake response and gives the keepalive that confirms it.
	fn confirm(&mut self, response: &[u8]) -> Vec<u8> {
		let mut out = vec![0u8; 2048];
		let TunnResult::WriteToNetwork(keepalive) = self.tunn().decapsulate(None, response, &mut out) else {panic!("the first answer held no handshake response")};
		keepalive.to_vec()
	}

	/// One IP packet into the tunnel.
	async fn send(&mut self, packet: &[u8]) {
		let datagram = self.sealed(packet);
		self.put(&[&datagram]).await;
	}

	/// The next IP packet `wanted` picks, from the inbox or from the tunnel. Every other packet stays in the inbox.
	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox().iter().position(|packet| wanted(packet)) {return self.inbox().remove(at)}
		let (deadline, mut found) = (Instant::now() + budget, None);
		loop {
			for datagram in self.chunk(deadline.checked_duration_since(Instant::now())?).await? {
				let mut input: &[u8] = &datagram;
				loop {
					let mut out = vec![0u8; 2048];
					match self.tunn().decapsulate(None, input, &mut out) {
						TunnResult::WriteToNetwork(reply) => {
							let reply = reply.to_vec();
							self.put(&[&reply]).await;
							input = &[];
						}
						TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
							let packet = packet.to_vec();
							if wanted(&packet) && found.is_none() {found = Some(packet)} else {self.inbox().push_back(packet)}
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
		let (mut syn, mut out, n) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new(), self.n());
		syn.syn = true;
		PacketBuilder::ipv4(address(n), PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (answer, _) = segment(&self.recv(2 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (80, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		let (mut ack, mut out) = (TcpHeader::new(sport, 80, 1001, 65535), Vec::new());
		(ack.ack, ack.acknowledgment_number) = (true, answer.sequence_number.wrapping_add(1));
		PacketBuilder::ipv4(address(n), PUBLIC, 64).tcp_header(ack).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (_, said) = segment(&self.recv(Duration::from_secs(4), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (80, sport) && !data.is_empty())).await?)?;
		let (mut rst, mut out) = (TcpHeader::new(sport, 80, 1001, 0), Vec::new());
		rst.rst = true;
		PacketBuilder::ipv4(address(n), PUBLIC, 64).tcp_header(rst).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		Some(String::from_utf8(said).unwrap())
	}

	/// The opening exchange of the control channel at the gateway, under the device's transport secret, inside the tunnel.
	async fn control(&mut self, sport: u16) {
		let (mut syn, mut out, n, started) = (TcpHeader::new(sport, PORT, 5000, 65535), Vec::new(), self.n(), Instant::now());
		syn.syn = true;
		PacketBuilder::ipv4(address(n), GATEWAY, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (answer, _) = segment(&self.recv(2 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (PORT, sport))).await.expect("the control port did not answer")).unwrap();
		let (mut seq, mut ack, mut up) = (5001u32, answer.sequence_number.wrapping_add(1), Vec::new());
		let mut opening = ClientOpening::start(ControlKey::derive(&secret(n), &public(&NODE), &public(&KEYS[n])), 1, Duration::ZERO, &mut random, &mut up).unwrap();
		loop {
			let (mut header, mut out) = (TcpHeader::new(sport, PORT, seq, 65535), Vec::new());
			(header.ack, header.psh, header.acknowledgment_number) = (true, true, ack);
			PacketBuilder::ipv4(address(n), GATEWAY, 64).tcp_header(header).write(&mut out, &up).unwrap();
			self.send(&out).await;
			seq = seq.wrapping_add(up.len() as u32);
			up.clear();
			let (tcp, data) = segment(&self.recv(Duration::from_secs(4), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (PORT, sport) && !data.is_empty() && tcp.sequence_number == ack)).await.expect("the control channel went quiet")).unwrap();
			ack = tcp.sequence_number.wrapping_add(data.len() as u32);
			let mut input = &data[..];
			if let Some(opened) = opening.receive(started.elapsed(), &mut input, &mut up).expect("the node broke the opening exchange") {return assert_eq!(opened.version, 1)}
		}
	}
}

/// What a device's WebSocket session runs over: a connection, or TLS on one.
pub trait Wire: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Wire for S {}

/// A device that reaches its tunnel over the native `ws`. It connects to `via` from `from`: to the reverse proxy as any client does, or to the node itself as the reverse proxy would, and then names `named` as the visitor. What it receives and nobody asked for yet waits in `inbox`.
pub struct Device {pub n: usize, pub tunn: Tunn, pub prover: proof::Client, pub via: SocketAddr, pub from: IpAddr, pub named: String, pub io: Option<Box<dyn Wire>>, pub tx: Option<Sealer>, pub rx: Option<Opener>, pub buf: Vec<u8>, pub inbox: VecDeque<Vec<u8>>, pub closed: bool, pub token: String}

impl Device {
	/// Device `n` with the transport secret `secret`, which seals its proofs to the node transport key whose private half is `transport`.
	pub fn new(n: usize, secret: [u8; 32], transport: &[u8; 32], via: SocketAddr) -> Device {
		Device {n, tunn: Tunn::new(StaticSecret::from(KEYS[n]), PublicKey::from(public(&NODE)), None, None, 0, None), prover: proof::Client::new(&proof::public_key(transport), &secret, &public(&NODE), &public(&KEYS[n])), via, from: CLIENT, named: String::new(), io: None, tx: None, rx: None, buf: Vec::new(), inbox: VecDeque::new(), closed: false, token: String::new()}
	}

	/// A new connection with the upgrade request for `path`, its proof made for `name` with the timestamp `at`. What came back up to the end of its head, or all of it when the connection closed first. On a `101` the session's keys are the device's from here on.
	pub async fn open_as(&mut self, path: &str, name: Name, at: u64) -> String {
		let io = dial(self.via, self.from).await;
		self.open_on(Box::new(io), path, name, at).await
	}

	/// The same on a connection that is there already: one with TLS on it, to a `tls` transport.
	pub async fn open_on(&mut self, io: Box<dyn Wire>, path: &str, name: Name, at: u64) -> String {self.open_with(io, name, at, |token| upgrade(path, token)).await}

	/// The same with the whole request made from the token by `request`: a transport that carries it elsewhere than in the query.
	pub async fn open_with(&mut self, mut io: Box<dyn Wire>, name: Name, at: u64, request: impl FnOnce(&str) -> Vec<u8>) -> String {
		let proof = self.prover.prove(name, at, &mut random).unwrap();
		io.write_all(&forwarded(&request(&proof.token), &self.named)).await.unwrap();
		let _ = io.flush().await;
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

	pub async fn open(&mut self, at: u64) -> String {self.open_as(WS_PATH, Name::Ws, at).await}

	/// Whether the node closes the session within `budget`: its Close frame, or the end of the connection.
	pub async fn ends(&mut self, budget: Duration) -> bool {
		let deadline = Instant::now() + budget;
		while !self.closed && Instant::now() < deadline {self.chunk(deadline.saturating_duration_since(Instant::now())).await;}
		self.closed
	}

	/// Opens a session and finishes a WireGuard handshake on it. False when the node did not take the proof or did not answer.
	pub async fn try_connect(&mut self, at: u64) -> bool {
		if !self.open(at).await.starts_with("HTTP/1.1 101 ") {return false}
		let init = self.initiation();
		self.put(&[&init]).await;
		let Some(answer) = self.chunk(Duration::from_secs(30)).await else {return false};
		let Some(response) = answer.first() else {return false};
		let keepalive = self.confirm(response);
		self.put(&[&keepalive]).await;
		true
	}

	pub async fn connect(&mut self, time: Time) {assert!(self.try_connect(time.secs()).await, "the node did not take its device")}
}

impl Link for Device {
	fn n(&self) -> usize {self.n}

	fn tunn(&mut self) -> &mut Tunn {&mut self.tunn}

	fn inbox(&mut self) -> &mut VecDeque<Vec<u8>> {&mut self.inbox}

	/// One chunk with these WireGuard datagrams, in one masked binary frame.
	async fn put(&mut self, datagrams: &[&[u8]]) {
		let (mut sealed, mut out) = (Vec::new(), Vec::new());
		self.tx.as_mut().expect("no session").seal(datagrams, false, &mut random, &mut sealed).unwrap();
		websocket::frame(BINARY, &sealed, Some([0x3a, 0x5c, 0x11, 0x7e]), &mut out);
		let io = self.io.as_mut().unwrap();
		let _ = io.write_all(&out).await;
		let _ = io.flush().await;
	}

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
}

/// A device that reaches its tunnel over `fronted`: one request after another on a connection it keeps, to `via` from `from`, as `Device` does. `got` holds the chunks of answers nobody read yet, and `answer` the head of the last answer that was no `200` the device could open.
pub struct Poller {pub n: usize, pub tunn: Tunn, pub prover: proof::Client, pub via: SocketAddr, pub from: IpAddr, pub named: String, pub io: Option<TcpStream>, pub tx: Option<Sealer>, pub rx: Option<fronted::Opener>, pub sid: [u8; 16], pub number: u32, pub inbox: VecDeque<Vec<u8>>, pub got: VecDeque<Vec<Vec<u8>>>, pub token: String, pub answer: String, pub last: Vec<u8>}

impl Poller {
	pub fn new(n: usize, secret: [u8; 32], transport: &[u8; 32], via: SocketAddr) -> Poller {
		Poller {n, tunn: Tunn::new(StaticSecret::from(KEYS[n]), PublicKey::from(public(&NODE)), None, None, 0, None), prover: proof::Client::new(&proof::public_key(transport), &secret, &public(&NODE), &public(&KEYS[n])), via, from: CLIENT, named: String::new(), io: None, tx: None, rx: None, sid: [0; 16], number: 0, inbox: VecDeque::new(), got: VecDeque::new(), token: String::new(), answer: String::new(), last: Vec::new()}
	}

	/// A body of one chunk for each list of datagrams, sealed at the numbers that follow the device's last.
	pub fn body(&mut self, chunks: &[&[&[u8]]]) -> Vec<u8> {
		let mut body = Vec::new();
		for datagrams in chunks {fronted::append(self.tx.as_mut().expect("no session"), datagrams, false, &mut random, &mut body).unwrap()}
		body
	}

	/// The target of the later request with the number `number`.
	pub fn target(&self, number: u32) -> String {format!("{POLL_PATH}?{}", fronted::later_query(&self.sid, number).unwrap())}

	/// Sends one request as it is on the connection the device keeps, on a new one when it has none, and reads one answer: its head and its body by the length the head names. None when the connection ended first or nothing came in `budget`.
	pub async fn exchange(&mut self, request: &[u8], budget: Duration) -> Option<(String, Vec<u8>)> {
		let (deadline, mut buf) = (Instant::now() + budget, vec![0u8; 65536]);
		self.last = forwarded(request, &self.named);
		// A connection that was kept and has been closed since, as a web server closes one that stays quiet, gives nothing back: the request is sent once more on a new one, as a client of HTTP does.
		for fresh in [self.io.is_none(), true] {
			if fresh {self.io = Some(dial(self.via, self.from).await)}
			let (io, mut got) = (self.io.as_mut()?, Vec::new());
			if io.write_all(&self.last).await.is_ok() {
				loop {
					if let Some(end) = got.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {
						let head = String::from_utf8_lossy(&got[..end]).into_owned();
						let length = head.split("\r\n").find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|length| length.trim().parse::<usize>().ok())).unwrap_or(0);
						if got.len() >= end + length {return Some((head, got[end..end + length].to_vec()))}
					}
					match timeout(deadline.checked_duration_since(Instant::now()).unwrap_or_default(), io.read(&mut buf)).await {
						Ok(Ok(count)) if count > 0 => got.extend_from_slice(&buf[..count]),
						_ => break,
					}
				}
			}
			self.io = None;
			if fresh || !got.is_empty() || Instant::now() >= deadline {return None}
		}
		None
	}

	/// What an answer holds for the device: the datagrams of each of its chunks. An answer that is no `200` with a body the session opens is kept in `answer`.
	pub fn opened(&mut self, answer: Option<(String, Vec<u8>)>) -> Result<Vec<Vec<Vec<u8>>>, String> {
		let Some((head, body)) = answer else {
			self.answer = "no answer".to_string();
			return Err(self.answer.clone());
		};
		let mut scratch = Vec::new();
		self.answer = head;
		match self.rx.as_mut().filter(|_| self.answer.starts_with("HTTP/1.1 200 ")).and_then(|rx| rx.open(&body, &mut scratch).ok()) {
			Some(opened) => Ok(opened.commit().into_iter().map(|items| items.map(<[u8]>::to_vec).collect()).collect()),
			None => Err(self.answer.clone()),
		}
	}

	/// The opening request for `path` with a proof made for `name` at `at`, and one chunk with `datagrams` for its body. The chunks of the node's answer, or the head of an answer that is none of the session's.
	pub async fn open_as(&mut self, path: &str, name: Name, at: u64, datagrams: &[&[u8]], budget: Duration) -> Result<Vec<Vec<Vec<u8>>>, String> {
		let proof = self.prover.prove(name, at, &mut random).unwrap();
		(self.tx, self.rx, self.sid, self.number, self.token) = (Some(Sealer::new(proof.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap())), Some(fronted::Opener::new(proof.keys.s2c)), proof.keys.sid, 0, proof.token);
		let request = post(&format!("{path}?{}", self.token), &self.body(&[datagrams]));
		let answer = self.exchange(&request, budget).await;
		self.opened(answer)
	}

	/// The next later request, with one chunk of `datagrams`.
	pub async fn poll(&mut self, datagrams: &[&[u8]]) -> Result<Vec<Vec<Vec<u8>>>, String> {
		self.number += 1;
		let request = post(&self.target(self.number), &self.body(&[datagrams]));
		let answer = self.exchange(&request, 4 * SECOND).await;
		self.opened(answer)
	}

	/// Opens a session and finishes a WireGuard handshake on it. False when the node did not take the proof or did not answer with a handshake response.
	pub async fn try_connect(&mut self, at: u64) -> bool {
		let init = self.initiation();
		let Ok(answer) = self.open_as(POLL_PATH, Name::Fronted, at, &[&init], 4 * SECOND).await else {return false};
		let Some(response) = answer.first().and_then(|chunk| chunk.first()) else {return false};
		let keepalive = self.confirm(response);
		self.put(&[&keepalive]).await;
		true
	}

	pub async fn connect(&mut self, time: Time) {assert!(self.try_connect(time.secs()).await, "the node did not take its device: {}", self.answer)}
}

impl Link for Poller {
	fn n(&self) -> usize {self.n}

	fn tunn(&mut self) -> &mut Tunn {&mut self.tunn}

	fn inbox(&mut self) -> &mut VecDeque<Vec<u8>> {&mut self.inbox}

	/// One request with these datagrams. What its answer holds waits in `got`.
	async fn put(&mut self, datagrams: &[&[u8]]) {
		if let Ok(chunks) = self.poll(datagrams).await {self.got.extend(chunks)}
	}

	/// The next chunk of an answer that was read, or of the answer to a request with nothing to carry.
	async fn chunk(&mut self, _: Duration) -> Option<Vec<Vec<u8>>> {
		if self.got.is_empty() {
			let chunks = self.poll(&[]).await.ok()?;
			self.got.extend(chunks);
		}
		self.got.pop_front()
	}
}
