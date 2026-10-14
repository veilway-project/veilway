//! The control API against a real engine: every test starts a node on a config with secrets in it, serves the API on a unix socket in a directory of its own, and talks to it with hyper's client over a `UnixStream`.
//! Every answer and every event that comes back through the helpers here is held against the OpenAPI document and searched for the secrets of every node the tests have started.
//! `VEILWAY_WRITE_OPENAPI=1 cargo test -p veilway-api --test api the_committed` writes `openapi.json` again after the API has changed.
#![cfg(unix)]
use axum::body::{to_bytes, Body};
use axum::http::Request;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, TcpHeader, TransportHeader};
use hyper::body::{Body as _, Incoming};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::BTreeSet;
use std::future::poll_fn;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Once};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, UnixStream};
use tokio::time::timeout;
use veilway_api::{Limits, Options as ApiOptions, Server};
use veilway_core::config::REDACTED;
use veilway_core::{Engine, Options};

const PEER_A: [u8; 4] = [10, 7, 0, 2];
const PEER_B: [u8; 4] = [10, 7, 0, 3];
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
const GREETING: &[u8] = b"hello-from-upstream";
const JSON: (&str, &str) = ("content-type", "application/json");
/// Port 0 is not a valid listen port in a config, so every listener of a test node takes the next one from here.
static NEXT_PORT: AtomicU16 = AtomicU16::new(23000);
static NEXT_NODE: AtomicUsize = AtomicUsize::new(0);
/// The secrets of every node the tests have started. None may show up in anything a node says.
static SECRETS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Every log line of the process, at debug.
static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static LOGGING: Once = Once::new();
static OPENAPI: LazyLock<Value> = LazyLock::new(|| serde_json::from_str(&veilway_api::openapi()).expect("the OpenAPI document is not JSON"));

struct Sink;

impl Write for Sink {
	fn write(&mut self, line: &[u8]) -> std::io::Result<usize> {
		LOGS.lock().unwrap().extend_from_slice(line);
		Ok(line.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {Ok(())}
}

/// Fails when `bytes`, which a node said or logged, hold a secret of any node.
fn no_secret_in(bytes: &[u8], what: &str) {
	for secret in SECRETS.lock().unwrap().iter() {
		assert!(!bytes.windows(secret.len()).any(|window| window == secret.as_bytes()), "{what} holds a secret of a node");
	}
}

fn no_secret_logged() {
	let logs = LOGS.lock().unwrap().clone();
	assert!(!logs.is_empty(), "nothing was logged, so the search of the log proves nothing");
	no_secret_in(&logs, "the log");
}

/// Holds `value` against `schema` of the OpenAPI document. A property the schema does not name is an error, so a field that is missing from the document is found by the first answer that has it.
fn valid(schema: &Value, value: &Value, at: &str) -> Result<(), String> {
	let kind = |value: &Value, kind: &str| match kind {
		"null" => value.is_null(),
		"boolean" => value.is_boolean(),
		"integer" => value.is_i64() || value.is_u64(),
		"number" => value.is_number(),
		"string" => value.is_string(),
		"array" => value.is_array(),
		"object" => value.is_object(),
		_ => false,
	};
	let Some(schema) = schema.as_object() else {return if schema == &Value::Bool(true) {Ok(())} else {Err(format!("{at}: the schema takes nothing"))}};
	if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
		let target = OPENAPI.pointer(reference.trim_start_matches('#')).ok_or_else(|| format!("{at}: {reference} is not in the document"))?;
		return valid(target, value, at);
	}
	match schema.get("type") {
		Some(Value::String(one)) if !kind(value, one) => return Err(format!("{at}: expected {one}, found {value}")),
		Some(Value::Array(any)) if !any.iter().filter_map(Value::as_str).any(|one| kind(value, one)) => return Err(format!("{at}: expected one of {any:?}, found {value}")),
		_ => {}
	}
	if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
		if !allowed.contains(value) {return Err(format!("{at}: {value} is not one of {allowed:?}"))}
	}
	if schema.get("const").is_some_and(|only| only != value) {return Err(format!("{at}: {value} is not the one value the schema takes"))}
	if schema.get("minimum").and_then(Value::as_f64).zip(value.as_f64()).is_some_and(|(minimum, value)| value < minimum) {return Err(format!("{at}: {value} is below the minimum"))}
	for key in ["anyOf", "oneOf"] {
		if let Some(options) = schema.get(key).and_then(Value::as_array) {
			if !options.iter().any(|option| valid(option, value, at).is_ok()) {return Err(format!("{at}: {value} fits none of the {} alternatives", options.len()))}
		}
	}
	if let Some(object) = value.as_object() {
		let (properties, extra) = (schema.get("properties").and_then(Value::as_object), schema.get("additionalProperties"));
		for required in schema.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
			if !object.contains_key(required) {return Err(format!("{at}: `{required}` is missing"))}
		}
		for (name, field) in object {
			match (properties.and_then(|properties| properties.get(name)), extra) {
				(Some(property), _) => valid(property, field, &format!("{at}.{name}"))?,
				(None, Some(extra)) => valid(extra, field, &format!("{at}.{name}"))?,
				(None, None) if properties.is_some() => return Err(format!("{at}: `{name}` is in the answer and not in the document")),
				(None, None) => {}
			}
		}
	}
	if let (Some(items), Some(list)) = (schema.get("items"), value.as_array()) {
		for (i, item) in list.iter().enumerate() {valid(items, item, &format!("{at}[{i}]"))?}
	}
	Ok(())
}

/// The operation of the document that `method` and `path` belong to, with the path as the document writes it.
fn operation(method: &str, path: &str) -> Option<(&'static str, &'static Value)> {
	let path = path.split('?').next().unwrap_or(path);
	OPENAPI["paths"].as_object().unwrap().iter().find(|(template, _)| {
		let (wanted, given): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
		wanted.len() == given.len() && wanted.iter().zip(&given).all(|(wanted, given)| wanted == given || (wanted.starts_with('{') && !given.is_empty()))
	}).and_then(|(template, methods)| Some((template.as_str(), methods.get(method.to_lowercase())?)))
}

struct Answer {status: u16, etag: Option<String>, body: Vec<u8>, json: Value}

impl Answer {
	fn code(&self) -> &str {self.json["error"]["code"].as_str().unwrap_or("")}
}

/// One request on a connection of its own. The answer is searched for secrets and held against the OpenAPI document: its status must be one the route documents, and its body must fit the schema of that status.
/// An answer that is not a success must have the one shape of an error whatever route, or none, it came from.
async fn call(socket: &Path, method: &str, path: &str, headers: &[(&str, &str)], body: Option<Body>) -> Answer {
	let stream = UnixStream::connect(socket).await.unwrap_or_else(|e| panic!("the control socket does not take a connection: {e}"));
	let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
	tokio::spawn(connection);
	let request = headers.iter().fold(Request::builder().method(method).uri(path).header("host", "veilway"), |request, (name, value)| request.header(*name, *value));
	let response = sender.send_request(request.body(body.unwrap_or_else(Body::empty)).unwrap()).await.unwrap_or_else(|e| panic!("{method} {path} got no answer: {e}"));
	let (status, etag, kind) = (response.status().as_u16(), response.headers().get("etag").map(|tag| tag.to_str().unwrap().to_string()), response.headers().get("content-type").map(|kind| kind.to_str().unwrap().to_string()));
	no_secret_in(format!("{:?}", response.headers()).as_bytes(), "a header");
	let body = to_bytes(Body::new(response.into_body()), usize::MAX).await.unwrap().to_vec();
	no_secret_in(&body, &format!("the answer of {method} {path}"));
	assert_eq!(kind.as_deref(), Some("application/json"), "{method} {path} answered {status} with something that is not JSON");
	let json: Value = serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{method} {path} answered {status} with a body that is not JSON: {e}"));
	if status >= 400 {
		valid(&json!({"$ref": "#/components/schemas/ErrorBody"}), &json, "error").unwrap_or_else(|e| panic!("{method} {path} answered {status} with an error of another shape: {e}"));
		assert!(json["error"]["code"].as_str().is_some_and(|code| !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')), "{method} {path}: {:?} is no stable code", json["error"]["code"]);
	}
	if let Some((template, operation)) = operation(method, path) {
		let documented = operation["responses"].get(status.to_string()).unwrap_or_else(|| panic!("{method} {template} answered {status}, which the OpenAPI document does not have for it"));
		valid(&documented["content"]["application/json"]["schema"], &json, "body").unwrap_or_else(|e| panic!("{method} {template} answered {status} with a body the OpenAPI document does not describe: {e}"));
	} else {assert!(status == 404 || status == 405, "{method} {path} is not in the OpenAPI document and answered {status}")}
	Answer {status, etag, body, json}
}

async fn get(socket: &Path, path: &str) -> Answer {call(socket, "GET", path, &[], None).await}

/// Sends a config document.
async fn send(socket: &Path, method: &str, path: &str, revision: Option<&str>, doc: &Value) -> Answer {
	let mut headers = vec![JSON];
	if let Some(revision) = revision {headers.push(("if-match", revision))}
	call(socket, method, path, &headers, Some(Body::from(doc.to_string()))).await
}

/// Bytes on a connection of their own, and whatever comes back until the node closes it or `budget` is over.
async fn raw(socket: &Path, request: &[u8], budget: Duration) -> (Vec<u8>, bool) {
	let mut stream = UnixStream::connect(socket).await.unwrap();
	// The node may answer and close before it has taken all of an oversized head, which makes this write fail. What it said is what is looked at.
	let _ = stream.write_all(request).await;
	let (mut got, mut buf, deadline) = (Vec::new(), vec![0u8; 65536], Instant::now() + budget);
	loop {
		match timeout(deadline.saturating_duration_since(Instant::now()), stream.read(&mut buf)).await {
			Ok(Ok(0)) | Ok(Err(_)) => return (got, true),
			Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
			Err(_) => return (got, false),
		}
	}
}

struct Sse {id: Option<u64>, kind: String, data: Value}

/// A reader of the event stream. Every event it reads must fit the schema the document has for its name, hold no secret, and have an id above the one before.
struct Events {body: Incoming, text: String, last: u64, comments: usize}

impl Events {
	async fn open(socket: &Path) -> Events {
		let stream = UnixStream::connect(socket).await.unwrap();
		let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
		tokio::spawn(connection);
		let response = sender.send_request(Request::builder().uri("/v1/events").header("host", "veilway").body(Body::empty()).unwrap()).await.unwrap();
		assert_eq!((response.status().as_u16(), response.headers().get("content-type").map(|kind| kind.to_str().unwrap())), (200, Some("text/event-stream")));
		Events {body: response.into_body(), text: String::new(), last: 0, comments: 0}
	}

	/// The next event within `budget`. Comment lines are counted and passed over.
	async fn next(&mut self, budget: Duration) -> Option<Sse> {
		let deadline = Instant::now() + budget;
		loop {
			if let Some(end) = self.text.find("\n\n") {
				let block: String = self.text.drain(..end + 2).collect();
				let (mut id, mut kind, mut data) = (None, String::new(), String::new());
				for line in block.lines() {
					match line.split_once(':').map(|(field, value)| (field, value.strip_prefix(' ').unwrap_or(value))) {
						Some(("", _)) => self.comments += 1,
						Some(("id", value)) => id = Some(value.parse::<u64>().expect("an id that is no number")),
						Some(("event", value)) => kind = value.to_string(),
						Some(("data", value)) => data.push_str(value),
						_ => {}
					}
				}
				if kind.is_empty() {continue}
				let data: Value = serde_json::from_str(&data).unwrap_or_else(|e| panic!("the data of a {kind} event is not JSON: {e}"));
				let schema = OPENAPI["x-events"].get(&kind).unwrap_or_else(|| panic!("the OpenAPI document has no {kind} event"));
				valid(schema, &data, &kind).unwrap_or_else(|e| panic!("a {kind} event the OpenAPI document does not describe: {e}"));
				match id {
					Some(id) => {
						assert!(id > self.last, "a {kind} event has id {id} after {}", self.last);
						self.last = id;
					}
					None => assert_eq!(kind, "lagged", "a {kind} event has no id"),
				}
				return Some(Sse {id, kind, data});
			}
			let frame = timeout(deadline.checked_duration_since(Instant::now())?, poll_fn(|cx| Pin::new(&mut self.body).poll_frame(cx))).await.ok()??.expect("the event stream broke");
			let Ok(chunk) = frame.into_data() else {continue};
			no_secret_in(&chunk, "an event");
			self.text.push_str(std::str::from_utf8(&chunk).expect("an event that is not UTF-8"));
		}
	}

	/// The next event of `kind` that `fits`, passing over every other.
	async fn until(&mut self, kind: &str, fits: impl Fn(&Value) -> bool) -> Sse {
		let deadline = Instant::now() + Duration::from_secs(8);
		loop {
			let event = self.next(deadline.saturating_duration_since(Instant::now())).await.unwrap_or_else(|| panic!("no {kind} event came"));
			if event.kind == kind && fits(&event.data) {return event}
		}
	}
}

/// A no-auth SOCKS5 proxy that sends every CONNECT to `backend`, records its target, and refuses to relay UDP the way a proxy without UDP does.
async fn socks5_proxy(backend: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, seen) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())));
	let recorder = seen.clone();
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {return};
			let recorder = recorder.clone();
			tokio::spawn(async move {
				let (mut hello, mut head, mut v4, mut port) = ([0u8; 2], [0u8; 4], [0u8; 4], [0u8; 2]);
				if client.read_exact(&mut hello).await.is_err() || hello[0] != 5 {return}
				let mut methods = vec![0u8; hello[1] as usize];
				if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() {return}
				if client.read_exact(&mut head).await.is_err() || head[3] != 1 || client.read_exact(&mut v4).await.is_err() || client.read_exact(&mut port).await.is_err() {return}
				if head[1] == 3 {
					recorder.lock().unwrap().push("associate".to_string());
					let _ = client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
					return;
				}
				recorder.lock().unwrap().push(format!("{}:{}", Ipv4Addr::from(v4), u16::from_be_bytes(port)));
				let Ok(mut upstream) = TcpStream::connect(backend).await else {return};
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {return}
				let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
			});
		}
	});
	(addr, seen)
}

/// Greets whoever connects.
async fn tcp_responder() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let Ok((mut stream, _)) = listener.accept().await else {return};
			tokio::spawn(async move {
				let _ = stream.write_all(GREETING).await;
				let mut sink = [0u8; 256];
				let _ = stream.read(&mut sink).await;
			});
		}
	});
	addr
}

fn listen() -> SocketAddr {SocketAddr::from((Ipv4Addr::LOCALHOST, NEXT_PORT.fetch_add(1, Ordering::SeqCst)))}

fn encoded(private: &[u8; 32]) -> String {veilway_wg::encode_key(&veilway_wg::public_key(private))}

/// A WireGuard client, as a device of a test node.
struct Client {tunn: Tunn, sock: UdpSocket}

impl Client {
	async fn connect(private: [u8; 32], preshared: Option<[u8; 32]>, server_public: [u8; 32], server: SocketAddr) -> Client {
		Client::try_connect(private, preshared, server_public, server, Duration::from_secs(3)).await.expect("handshake timed out")
	}

	/// None when the server does not answer the handshake within `budget`, or answers with what this device cannot read, which is what the wrong preshared key comes to.
	async fn try_connect(private: [u8; 32], preshared: Option<[u8; 32]>, server_public: [u8; 32], server: SocketAddr, budget: Duration) -> Option<Client> {
		let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.connect(server).await.unwrap();
		let mut tunn = Tunn::new(StaticSecret::from(private), PublicKey::from(server_public), preshared, None, 0, None);
		let (mut scratch, mut datagram, mut out) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
		let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut scratch, false) else {panic!("no handshake initiation")};
		sock.send(init).await.unwrap();
		let n = timeout(budget, sock.recv(&mut datagram)).await.ok()?.unwrap();
		match tunn.decapsulate(None, &datagram[..n], &mut out) {
			TunnResult::WriteToNetwork(keepalive) => drop(sock.send(keepalive).await.unwrap()),
			TunnResult::Err(_) => return None,
			_ => {}
		}
		Some(Client {tunn, sock})
	}

	async fn send_ip(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn.encapsulate(packet, &mut out) else {panic!("encapsulate produced nothing")};
		self.sock.send(datagram).await.unwrap();
	}

	/// Next decrypted IP packet, pumping boringtun's own traffic along the way.
	async fn recv_ip(&mut self, budget: Duration) -> Option<Vec<u8>> {
		let deadline = Instant::now() + budget;
		loop {
			let mut datagram = vec![0u8; 2048];
			let n = match timeout(deadline.checked_duration_since(Instant::now())?, self.sock.recv(&mut datagram)).await {
				Ok(Ok(n)) => n,
				_ => return None,
			};
			let mut input: &[u8] = &datagram[..n];
			loop {
				let mut out = vec![0u8; 2048];
				match self.tunn.decapsulate(None, input, &mut out) {
					TunnResult::WriteToNetwork(reply) => {
						let reply = reply.to_vec();
						let _ = self.sock.send(&reply).await;
						input = &[];
					}
					TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => return Some(packet.to_vec()),
					_ => break,
				}
			}
		}
	}

	/// Opens a TCP flow to `PUBLIC` and reads what the upstream says on it.
	async fn greeted(&mut self, src: [u8; 4], sport: u16) -> Vec<u8> {
		let segment = |header: TcpHeader| {
			let builder = PacketBuilder::ipv4(src, PUBLIC, 64).tcp_header(header);
			let mut out = Vec::with_capacity(builder.size(0));
			builder.write(&mut out, &[]).unwrap();
			out
		};
		let mut syn = TcpHeader::new(sport, 80, 1000, 65535);
		syn.syn = true;
		self.send_ip(&segment(syn)).await;
		let (mut got, mut open) = (Vec::new(), false);
		while got.len() < GREETING.len() {
			let Some(packet) = self.recv_ip(Duration::from_secs(5)).await else {break};
			let Ok(PacketHeaders {transport: Some(TransportHeader::Tcp(tcp)), payload, ..}) = PacketHeaders::from_ip_slice(&packet) else {continue};
			if tcp.syn && tcp.ack && !open {
				let mut ack = TcpHeader::new(sport, 80, 1001, 65535);
				(ack.ack, ack.acknowledgment_number, open) = (true, tcp.sequence_number.wrapping_add(1), true);
				self.send_ip(&segment(ack)).await;
			}
			got.extend_from_slice(payload.slice());
		}
		got
	}
}

fn ip_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
	let builder = PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
	let mut out = Vec::with_capacity(builder.size(payload.len()));
	builder.write(&mut out, payload).unwrap();
	out
}

/// Waits for something the node does on its own time.
async fn eventually(what: &str, done: impl AsyncFn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(5);
	while !done().await {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// A valid version 1 document with every kind of secret in it, and what a test needs to be a device of it: inbound `home` on 10.7.0.1/16 over UDP, users `a` (10.7.0.2), `b` (10.7.0.3) and `c` (10.7.0.4, with a preshared key),
/// exit `main` through a SOCKS5 outbound with a user name and a password, and exit `sink`. A test changes `doc` before `launch`.
struct Setup {doc: Value, private: [u8; 32], keys: [[u8; 32]; 3], preshared: [u8; 32], listen: SocketAddr, seen: Arc<Mutex<Vec<String>>>, limits: Limits, mode: u32}

async fn setup() -> Setup {
	let (proxy, seen) = socks5_proxy(tcp_responder().await).await;
	let (private, keys, preshared, listen) = (veilway_wg::generate_key(), [veilway_wg::generate_key(), veilway_wg::generate_key(), veilway_wg::generate_key()], veilway_wg::generate_key(), listen());
	let word = |salt: &[u8; 32]| salt[..12].iter().map(|byte| format!("{byte:02x}")).collect::<String>();
	let user = |name: &str, private: &[u8; 32], address: &str| json!({"name": name, "exits": "all", "devices": [{"name": "device", "public_key": encoded(private), "addresses": [address]}]});
	let mut doc = json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"], "hijack": false},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&private), "address": ["10.7.0.1/16"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [{"tag": "proxy", "type": "socks5", "server": proxy.to_string(), "username": format!("name-{}", word(&veilway_wg::generate_key())), "password": format!("word-{}", word(&veilway_wg::generate_key()))}],
		"exits": [{"tag": "main", "name": "Main", "backend": {"type": "netstack", "outbound": "proxy"}}, {"tag": "sink", "backend": {"type": "block"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [user("a", &keys[0], "10.7.0.2"), user("b", &keys[1], "10.7.0.3"), user("c", &keys[2], "10.7.0.4")]
	});
	doc["users"][2]["devices"][0]["preshared_key"] = json!(veilway_wg::encode_key(&preshared));
	Setup {doc, private, keys, preshared, listen, seen, limits: Limits::default(), mode: 0o600}
}

/// The four secrets of a document `setup` made.
fn secrets(doc: &Value) -> Vec<String> {
	[&doc["inbounds"][0]["private_key"], &doc["outbounds"][0]["username"], &doc["outbounds"][0]["password"], &doc["users"][2]["devices"][0]["preshared_key"]].map(|secret| secret.as_str().expect("a secret is missing from the document").to_string()).to_vec()
}

struct Node {engine: Arc<Engine>, server: Server, dir: PathBuf, socket: PathBuf, file: PathBuf, addr: SocketAddr, public: [u8; 32], keys: [[u8; 32]; 3], preshared: [u8; 32], seen: Arc<Mutex<Vec<String>>>, doc: Value, limits: Limits}

/// Starts the engine on the config file at `file`, the way `veilway run` does, and serves the API next to it.
async fn start(dir: &Path, limits: &Limits) -> (Arc<Engine>, Server) {
	let (config, report) = veilway_core::config::load(&dir.join("config.json"), false);
	let config = config.unwrap_or_else(|| panic!("the config file is not valid: {:#?}", report.errors));
	let engine = Arc::new(veilway_core::start(&config, Options {revision: report.revision, allow_readable: true, state: Some(dir.join("state.json")), replay: Some(dir.join("replay")), ..Options::new(dir)}).await.unwrap());
	let server = veilway_api::serve(engine.clone(), ApiOptions {socket: dir.join("veilway.sock"), config: dir.join("config.json"), limits: limits.clone()}).unwrap();
	(engine, server)
}

async fn launch(setup: Setup) -> Node {
	LOGGING.call_once(|| tracing_subscriber::fmt().with_writer(|| Sink).with_ansi(false).with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init());
	let dir = std::env::temp_dir().join(format!("vwapi-{}-{}", std::process::id(), NEXT_NODE.fetch_add(1, Ordering::SeqCst)));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	SECRETS.lock().unwrap().extend(secrets(&setup.doc));
	let file = dir.join("config.json");
	std::fs::write(&file, format!("{:#}\n", setup.doc)).unwrap();
	std::fs::set_permissions(&file, std::fs::Permissions::from_mode(setup.mode)).unwrap();
	let (engine, server) = start(&dir, &setup.limits).await;
	Node {engine, server, socket: dir.join("veilway.sock"), file, dir, addr: setup.listen, public: veilway_wg::public_key(&setup.private), keys: setup.keys, preshared: setup.preshared, seen: setup.seen, doc: setup.doc, limits: setup.limits}
}

impl Node {
	/// Ends the API and then the engine, which only works when nothing of the API holds the engine any more, and gives back the directory.
	async fn stop(self) -> PathBuf {
		self.server.shutdown().await;
		assert!(!self.socket.exists(), "the socket file is still there after the shutdown");
		Arc::try_unwrap(self.engine).ok().expect("the API still holds the engine after its shutdown").shutdown().await;
		self.dir
	}

	async fn end(self) {std::fs::remove_dir_all(self.stop().await).unwrap()}

	/// The running config as the API shows it, with its revision.
	async fn shown(&self) -> (Value, String) {
		let got = get(&self.socket, "/v1/config").await;
		assert_eq!(got.status, 200);
		(got.json["document"].clone(), got.json["revision"].as_str().unwrap().to_string())
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_route_answers() {
	let node = launch(setup().await).await;
	let mut client = Client::connect(node.keys[0], None, node.public, node.addr).await;
	assert_eq!(client.greeted(PEER_A, 40001).await, GREETING);
	let mut asked = BTreeSet::new();
	let mut ask = |method: &str, path: &str| asked.insert((method.to_lowercase(), operation(method, path).unwrap_or_else(|| panic!("{method} {path} is not in the OpenAPI document")).0.to_string()));
	let status = get(&node.socket, "/v1/status").await;
	ask("GET", "/v1/status");
	assert_eq!((status.status, &status.json["version"], &status.json["generation"], &status.json["inbounds"], &status.json["exits"], &status.json["users"]), (200, &json!(env!("CARGO_PKG_VERSION")), &json!(1), &json!(1), &json!(2), &json!(3)), "{}", status.json);
	assert!(status.json["flows"].as_u64().unwrap() >= 1 && status.json["uptime_secs"].is_u64() && status.json["revision"].as_str().unwrap().len() == 64, "{}", status.json);
	let config = get(&node.socket, "/v1/config").await;
	ask("GET", "/v1/config");
	assert_eq!((config.status, &config.json["revision"], config.etag.as_deref()), (200, &status.json["revision"], Some(format!("\"{}\"", status.json["revision"].as_str().unwrap()).as_str())));
	let (shown, revision) = (config.json["document"].clone(), config.json["revision"].as_str().unwrap().to_string());
	assert_eq!((&shown["inbounds"][0]["private_key"], &shown["outbounds"][0]["username"], &shown["outbounds"][0]["password"], &shown["users"][2]["devices"][0]["preshared_key"]), (&json!(REDACTED), &json!(REDACTED), &json!(REDACTED), &json!(REDACTED)));
	assert_eq!((&shown["users"][0]["devices"][0]["public_key"], &shown["inbounds"][0]["tag"], shown["users"][0]["devices"][0].get("preshared_key")), (&node.doc["users"][0]["devices"][0]["public_key"], &json!("home"), None));
	let validated = send(&node.socket, "POST", "/v1/config/validate", None, &shown).await;
	ask("POST", "/v1/config/validate");
	assert_eq!((validated.status, &validated.json["valid"], validated.json["report"]["errors"].as_array().map(Vec::len)), (200, &json!(true), Some(0)), "{}", validated.json);
	let mut invalid = shown.clone();
	invalid["routing"]["default"] = json!("nowhere");
	let validated = send(&node.socket, "POST", "/v1/config/validate", None, &invalid).await;
	assert_eq!((validated.status, &validated.json["valid"], &validated.json["report"]["errors"][0]["path"]), (200, &json!(false), &json!("routing.default")), "{}", validated.json);
	let mut changed = shown.clone();
	changed["users"][1]["enabled"] = json!(false);
	changed["users"].as_array_mut().unwrap().push(json!({"name": "d", "exits": ["main"], "devices": [{"name": "device", "public_key": encoded(&veilway_wg::generate_key()), "addresses": ["10.7.0.5"]}]}));
	changed["exits"].as_array_mut().unwrap().remove(1);
	let diff = send(&node.socket, "POST", "/v1/config/diff", None, &changed).await;
	ask("POST", "/v1/config/diff");
	assert_eq!((diff.status, &diff.json["valid"], &diff.json["diff"]["users"], &diff.json["diff"]["exits"], &diff.json["diff"]["inbounds"]), (200, &json!(true), &json!({"added": ["d"], "changed": ["b"], "removed": []}), &json!({"added": [], "changed": [], "removed": ["sink"]}), &json!({"added": [], "changed": [], "removed": []})), "{}", diff.json);
	assert_eq!(diff.json["diff"]["user_changes"], json!([{"name": "b", "devices_added": [], "devices_removed": [], "devices_readdressed": [], "devices_rekeyed": [], "devices_secrets_changed": [], "lost_access": true}]));
	let diff = send(&node.socket, "POST", "/v1/config/diff", None, &invalid).await;
	assert_eq!((diff.status, &diff.json["valid"], &diff.json["diff"]), (200, &json!(false), &Value::Null));
	assert_eq!(node.engine.snapshot().generation, 1, "a validate or a diff changed the running config");
	let users = get(&node.socket, "/v1/users").await;
	ask("GET", "/v1/users");
	assert_eq!((users.status, users.json["users"].as_array().map(Vec::len)), (200, Some(3)));
	let a = &users.json["users"][0];
	assert_eq!((&a["name"], &a["enabled"], &a["denied"], &a["quota_bytes"], &a["devices"][0]["name"], &a["devices"][0]["public_key"], &a["devices"][0]["addresses"]), (&json!("a"), &json!(true), &Value::Null, &Value::Null, &json!("device"), &json!(encoded(&node.keys[0])), &json!(["10.7.0.2"])), "{a}");
	assert!(a["devices"][0]["handshake_age_secs"].as_u64().is_some_and(|age| age < 10) && a["traffic"]["up_bytes"].as_u64().unwrap() > 0 && a["traffic"]["down_bytes"].as_u64().unwrap() > 0 && a["used_bytes"].as_u64().unwrap() > 0, "{a}");
	assert_eq!((&users.json["users"][1]["devices"][0]["handshake_age_secs"], &users.json["users"][1]["traffic"]["up_bytes"]), (&Value::Null, &json!(0)));
	let one = get(&node.socket, "/v1/users/a").await;
	ask("GET", "/v1/users/a");
	assert_eq!((one.status, &one.json["name"], &one.json["devices"][0]["public_key"]), (200, &json!("a"), &a["devices"][0]["public_key"]));
	for missing in ["/v1/users/nobody", "/v1/users/%ff", "/v1/users/A%20B"] {
		let none = get(&node.socket, missing).await;
		assert_eq!((none.status, none.code()), (404, "user_not_found"), "{missing}");
	}
	let reset = call(&node.socket, "POST", "/v1/users/a/usage/reset", &[], None).await;
	ask("POST", "/v1/users/a/usage/reset");
	assert_eq!((reset.status, &reset.json["name"], &reset.json["traffic"]["up_bytes"]), (200, &json!("a"), &a["traffic"]["up_bytes"]), "{}", reset.json);
	// A node without an obfuscated transport keeps no replay memory, so there is none to reset and no replay file is made.
	let replay = call(&node.socket, "POST", "/v1/replay/reset", &[], None).await;
	ask("POST", "/v1/replay/reset");
	assert_eq!((replay.status, replay.code(), node.dir.join("replay").exists()), (409, "replay_absent", false), "{}", replay.json);
	let stats = get(&node.socket, "/v1/stats").await;
	ask("GET", "/v1/stats");
	assert_eq!((&stats.json["replay"], &stats.json["udp_obfs"]["sessions"], &stats.json["udp_obfs"]["unknown"]), (&Value::Null, &json!(0), &json!(0)), "{}", stats.json);
	assert_eq!((stats.status, &stats.json["users"][0]["name"], &stats.json["inbounds"][0]["name"], &stats.json["exits"][0]["name"], stats.json["drops"].as_object().map(|drops| drops.len())), (200, &json!("a"), &json!("home"), &json!("main"), Some(15)), "{}", stats.json);
	assert!(stats.json["users"][0]["traffic"]["up_packets"].as_u64().unwrap() >= 2 && stats.json["exits"][0]["traffic"]["down_bytes"].as_u64().unwrap() > 0 && stats.json["drops"]["gate"].is_u64() && stats.json["dns"]["answered"].is_u64(), "{}", stats.json);
	let sessions = get(&node.socket, "/v1/sessions").await;
	ask("GET", "/v1/sessions");
	assert_eq!(sessions.json["sessions"].as_array().map(Vec::len), Some(1), "{}", sessions.json);
	let session = &sessions.json["sessions"][0];
	assert_eq!((&session["user"], &session["device"], &session["inbound"], &session["transport"], &session["public_key"]), (&json!("a"), &json!("device"), &json!("home"), &json!("udp"), &json!(encoded(&node.keys[0]))), "{session}");
	assert!(session["flows"].as_u64().unwrap() >= 1 && session["handshake_age_secs"].as_u64().unwrap() < 10, "{session}");
	// Where a device connects from is nobody's business who only reads the API: no field of a session holds an address.
	assert!(!String::from_utf8_lossy(&sessions.body).contains("127.0.0.1"), "a session shows where its device connects from");
	let exits = get(&node.socket, "/v1/exits").await;
	ask("GET", "/v1/exits");
	// A node without links lists none.
	assert_eq!(get(&node.socket, "/v1/links").await.json, json!({"links": []}));
	ask("GET", "/v1/links");
	assert_eq!(exits.json["exits"].as_array().map(Vec::len), Some(2));
	let (main, sink) = (&exits.json["exits"][0], &exits.json["exits"][1]);
	assert_eq!((&main["tag"], &main["name"], &main["backend"], &main["outbound"], &main["udp"], &main["udp_down_secs"], &main["udp_flips"]), (&json!("main"), &json!("Main"), &json!("netstack"), &json!("proxy"), &json!(true), &Value::Null, &json!(0)), "{main}");
	assert_eq!((&main["interface_up"], &main["interface_down_secs"], &main["interface_flips"]), (&Value::Null, &Value::Null, &json!(0)), "only an l3 exit has an interface: {main}");
	assert_eq!((&sink["tag"], &sink["name"], &sink["backend"], &sink["outbound"], &sink["udp"]), (&json!("sink"), &json!("sink"), &json!("block"), &Value::Null, &Value::Null), "{sink}");
	assert!(main["traffic"]["up_bytes"].as_u64().unwrap() > 0, "{main}");
	let document = get(&node.socket, "/v1/openapi.json").await;
	ask("GET", "/v1/openapi.json");
	assert_eq!((document.status, String::from_utf8(document.body).unwrap()), (200, veilway_api::openapi()));
	let mut events = Events::open(&node.socket).await;
	ask("GET", "/v1/events");
	assert!(events.until("stats", |_| true).await.data["users"][0]["traffic"]["up_bytes"].as_u64().unwrap() > 0);
	changed["exits"] = shown["exits"].clone();
	let applied = send(&node.socket, "PUT", "/v1/config", Some(&revision), &changed).await;
	ask("PUT", "/v1/config");
	assert_eq!((applied.status, &applied.json["generation"], &applied.json["saved"], &applied.json["save_error"], &applied.json["diff"]["users"]["added"]), (200, &json!(2), &json!(true), &Value::Null, &json!(["d"])), "{}", applied.json);
	assert_eq!((applied.etag.as_deref(), node.engine.snapshot().generation), (Some(format!("\"{}\"", applied.json["revision"].as_str().unwrap()).as_str()), 2));
	assert_eq!(get(&node.socket, "/v1/users/b").await.json["denied"], json!("disabled"));
	// Every operation of the document was asked for here, so every route has had a real answer held against it.
	let documented: BTreeSet<(String, String)> = OPENAPI["paths"].as_object().unwrap().iter().flat_map(|(path, methods)| methods.as_object().unwrap().keys().map(move |method| (method.clone(), path.clone()))).collect();
	assert_eq!(asked, documented);
	no_secret_logged();
	drop(events);
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_socket_is_for_the_node_alone_and_only_ever_replaces_a_dead_socket() {
	let node = launch(setup().await).await;
	let meta = std::fs::symlink_metadata(&node.socket).unwrap();
	assert!(meta.file_type().is_socket() && meta.permissions().mode() & 0o777 == 0o600, "the socket has mode {:o}", meta.permissions().mode() & 0o777);
	assert_eq!(std::fs::read_dir(&node.dir).unwrap().filter_map(|entry| entry.ok()).filter(|entry| entry.file_name().to_string_lossy().starts_with(".vw-")).count(), 0, "the directory the socket was made in was left behind");
	let serve = |socket: PathBuf| veilway_api::serve(node.engine.clone(), ApiOptions {socket, config: node.file.clone(), limits: Limits::default()});
	// A socket somebody answers on is another node. It keeps its socket and goes on answering.
	let busy = serve(node.socket.clone()).err().expect("a second server took the socket of a running one");
	assert!(busy.kind() == std::io::ErrorKind::AddrInUse && busy.to_string().contains("another process answers"), "{busy}");
	assert_eq!(get(&node.socket, "/v1/status").await.status, 200, "the running node lost its socket to one that failed to start");
	// A node says what it holds of the host, which is what `doctor` excuses a taken address on. Something else that listens on a socket path says nothing.
	let held = veilway_api::held(&node.socket, Duration::from_secs(5)).await.expect("a running node did not say what it holds");
	assert!(held.listens.contains(&(node.addr, false)) && held.interfaces.is_empty(), "{held:?}");
	let mute = std::os::unix::net::UnixListener::bind(node.dir.join("mute.sock")).unwrap();
	assert_eq!(veilway_api::held(&node.dir.join("mute.sock"), Duration::from_millis(300)).await, None);
	drop(mute);
	// What a node that was killed leaves behind: a socket file nobody listens on. Whatever its mode was, the new one has 600.
	let stale = node.dir.join("stale.sock");
	drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
	std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o666)).unwrap();
	let second = serve(stale.clone()).expect("a socket nobody answers on was not replaced");
	assert_eq!((get(&stale, "/v1/status").await.status, std::fs::symlink_metadata(&stale).unwrap().permissions().mode() & 0o777), (200, 0o600));
	second.shutdown().await;
	assert!(!stale.exists(), "the socket file is still there after the shutdown");
	// Anything else at the path is somebody's file and stays exactly as it is.
	let (file, folder, link) = (node.dir.join("file.sock"), node.dir.join("folder.sock"), node.dir.join("link.sock"));
	std::fs::write(&file, "not a socket").unwrap();
	std::fs::create_dir(&folder).unwrap();
	std::os::unix::fs::symlink(&file, &link).unwrap();
	for path in [&file, &folder, &link] {
		let before = std::fs::symlink_metadata(path).unwrap().file_type();
		let refused = serve(path.clone()).err().expect("something that is not a socket was replaced");
		assert!(refused.to_string().contains("is not a socket"), "{refused}");
		assert_eq!(std::fs::symlink_metadata(path).unwrap().file_type(), before);
	}
	assert_eq!(std::fs::read_to_string(&file).unwrap(), "not a socket");
	// A server that is dropped takes its socket with it, and never the socket another server has put there since.
	let dropped = node.dir.join("dropped.sock");
	let first = serve(dropped.clone()).unwrap();
	std::fs::remove_file(&dropped).unwrap();
	let later = serve(dropped.clone()).unwrap();
	drop(first);
	assert_eq!(get(&dropped, "/v1/status").await.status, 200, "a server that went away removed the socket of the one after it");
	drop(later);
	assert!(!dropped.exists());
	eventually("a server that failed to start, was shut down or was dropped still holds the engine", async || Arc::strong_count(&node.engine) == 2).await;
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_goes_out_redacted_and_comes_back_with_its_secrets() {
	let node = launch(setup().await).await;
	let (mut doc, revision) = node.shown().await;
	assert_eq!(doc.to_string().matches(REDACTED).count(), 4);
	doc["users"][1]["quota_bytes"] = json!(5000000);
	doc["exits"][0]["name"] = json!("Renamed");
	let applied = send(&node.socket, "PUT", "/v1/config", Some(&revision), &doc).await;
	assert_eq!((applied.status, &applied.json["saved"], &applied.json["diff"]["users"]["changed"], &applied.json["diff"]["inbounds"]["changed"], &applied.json["diff"]["outbounds"]["changed"]), (200, &json!(true), &json!(["b"]), &json!([]), &json!([])), "{}", applied.json);
	// The file holds the real secrets, the ones the node was started with, and no marker.
	let saved: Value = serde_json::from_slice(&std::fs::read(&node.file).unwrap()).unwrap();
	assert_eq!((secrets(&saved), &saved["users"][1]["quota_bytes"], saved.to_string().contains(REDACTED)), (secrets(&node.doc), &json!(5000000), false));
	// And the node still serves with them: its own key answers a handshake, the device with a preshared key gets in with it and not without, and a flow still leaves through the proxy.
	let mut a = Client::connect(node.keys[0], None, node.public, node.addr).await;
	assert_eq!(a.greeted(PEER_A, 40002).await, GREETING);
	assert_eq!(node.seen.lock().unwrap().as_slice(), ["93.184.216.34:80"]);
	Client::connect(node.keys[2], Some(node.preshared), node.public, node.addr).await;
	assert!(Client::try_connect(node.keys[2], None, node.public, node.addr, Duration::from_millis(700)).await.is_none(), "a device got in without its preshared key");
	let (shown, revision) = node.shown().await;
	assert_eq!((shown.to_string().matches(REDACTED).count(), &shown["exits"][0]["name"]), (4, &json!("Renamed")));
	// A marker stands for the secret of one object of the running config. Where there is no such object there is nothing to keep, and the answer names the field.
	let mut nothing = shown.clone();
	nothing["inbounds"].as_array_mut().unwrap().push(json!({"tag": "second", "type": "wireguard", "private_key": REDACTED, "address": ["10.8.0.1/24"], "transports": [{"type": "udp", "listen": listen().to_string()}]}));
	nothing["outbounds"].as_array_mut().unwrap().push(json!({"tag": "other", "type": "socks5", "server": "127.0.0.1:1080", "username": REDACTED, "password": REDACTED}));
	nothing["users"][0]["devices"][0]["preshared_key"] = json!(REDACTED);
	let paths = json!([{"path": "inbounds[1].private_key"}, {"path": "outbounds[1].username"}, {"path": "outbounds[1].password"}, {"path": "users[0].devices[0].preshared_key"}]);
	let only_paths = |list: &Value| Value::Array(list.as_array().unwrap().iter().map(|problem| json!({"path": problem["path"]})).collect());
	let refused = send(&node.socket, "PUT", "/v1/config", Some(&revision), &nothing).await;
	assert_eq!((refused.status, refused.code(), only_paths(&refused.json["error"]["details"])), (422, "config_invalid", paths.clone()), "{}", refused.json);
	let validated = send(&node.socket, "POST", "/v1/config/validate", None, &nothing).await;
	assert_eq!((validated.status, &validated.json["valid"], only_paths(&validated.json["report"]["errors"])), (200, &json!(false), paths), "{}", validated.json);
	let diff = send(&node.socket, "POST", "/v1/config/diff", None, &nothing).await;
	assert_eq!((diff.status, &diff.json["valid"], &diff.json["diff"]), (200, &json!(false), &Value::Null));
	// A marker where no secret belongs is a wrong value like any other.
	let mut misplaced = shown.clone();
	misplaced["users"][0]["devices"][0]["public_key"] = json!(REDACTED);
	let refused = send(&node.socket, "PUT", "/v1/config", Some(&revision), &misplaced).await;
	assert_eq!((refused.status, &refused.json["error"]["details"][0]["path"]), (422, &json!("users[0].devices[0].public_key")));
	assert_eq!((node.engine.snapshot().generation, serde_json::from_slice::<Value>(&std::fs::read(&node.file).unwrap()).unwrap()), (2, saved));
	// A secret that is sent in the clear replaces the running one, and is not said back either.
	let (mut rekeyed, fresh) = (shown.clone(), veilway_wg::generate_key());
	rekeyed["users"][2]["devices"][0]["preshared_key"] = json!(veilway_wg::encode_key(&fresh));
	SECRETS.lock().unwrap().push(veilway_wg::encode_key(&fresh));
	let applied = send(&node.socket, "PUT", "/v1/config", Some(&revision), &rekeyed).await;
	assert_eq!((applied.status, &applied.json["diff"]["user_changes"][0]["devices_rekeyed"]), (200, &json!([encoded(&node.keys[2])])), "{}", applied.json);
	Client::connect(node.keys[2], Some(fresh), node.public, node.addr).await;
	assert!(Client::try_connect(node.keys[2], Some(node.preshared), node.public, node.addr, Duration::from_millis(700)).await.is_none(), "a device got in with the preshared key it had before");
	no_secret_logged();
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_apply_needs_the_revision_it_was_made_on() {
	let node = launch(setup().await).await;
	let (mut doc, revision) = node.shown().await;
	let before = std::fs::read(&node.file).unwrap();
	doc["users"][1]["enabled"] = json!(false);
	let missing = send(&node.socket, "PUT", "/v1/config", None, &doc).await;
	assert_eq!((missing.status, missing.code()), (428, "precondition_required"));
	for stale in ["0000000000000000000000000000000000000000000000000000000000000000", "", "*", "\"nonsense\""] {
		let refused = send(&node.socket, "PUT", "/v1/config", Some(stale), &doc).await;
		assert_eq!((refused.status, refused.code(), &refused.json["error"]["details"], refused.etag.as_deref()), (409, "stale_revision", &json!([{"path": "revision", "message": revision}]), Some(format!("\"{revision}\"").as_str())), "{stale:?}");
	}
	assert_eq!((node.engine.snapshot().generation, std::fs::read(&node.file).unwrap()), (1, before), "an apply without the right revision changed something");
	// With or without the quotes of an ETag. The revision it was made on is spent once it is applied.
	let applied = send(&node.socket, "PUT", "/v1/config", Some(&format!("\"{revision}\"")), &doc).await;
	assert_eq!((applied.status, &applied.json["generation"]), (200, &json!(2)));
	doc["users"][1]["enabled"] = json!(true);
	let again = send(&node.socket, "PUT", "/v1/config", Some(&revision), &doc).await;
	assert_eq!((again.status, again.code(), &again.json["error"]["details"][0]["message"]), (409, "stale_revision", &applied.json["revision"]));
	assert_eq!(send(&node.socket, "PUT", "/v1/config", Some(applied.json["revision"].as_str().unwrap()), &doc).await.json["generation"], json!(3));
	node.end().await;
}

/// The tasks of an engine, and with them the ports of its node, live as long as the runtime they run on. So each of the two nodes here has a runtime of its own that goes when the node does, the way a process would.
#[test]
fn an_apply_is_saved_for_the_node_alone_and_a_restart_comes_back_with_it() {
	let runtime = || tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
	let first = runtime();
	let (dir, limits, revision, wanted, keys, public, addr) = first.block_on(async {
		let mut setup = setup().await;
		setup.mode = 0o644;
		let node = launch(setup).await;
		let (mut doc, revision) = node.shown().await;
		doc["users"][1]["enabled"] = json!(false);
		doc["exits"][0]["name"] = json!("Kept");
		// A file next to the config file that the node did not make, under the name a temporary file is most likely to be given.
		let theirs = node.dir.join("config.json.tmp");
		std::fs::write(&theirs, "somebody's").unwrap();
		let applied = send(&node.socket, "PUT", "/v1/config", Some(&revision), &doc).await;
		assert_eq!((applied.status, &applied.json["saved"]), (200, &json!(true)), "{}", applied.json);
		assert_eq!(std::fs::metadata(&node.file).unwrap().permissions().mode() & 0o777, 0o600, "the saved config can be read by others");
		assert_eq!(std::fs::read_to_string(&theirs).ok().as_deref(), Some("somebody's"), "the write of the config file removed a file the node did not make");
		let temporary = || std::fs::read_dir(&node.dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).filter(|name| name.ends_with(".tmp") && name != "config.json.tmp").count();
		assert_eq!(temporary(), 0, "the temporary file of the write was left behind");
		// The same document again is the same config: nothing is put in force a second time and the file is as it was.
		let saved = std::fs::read(&node.file).unwrap();
		let again = send(&node.socket, "PUT", "/v1/config", Some(applied.json["revision"].as_str().unwrap()), &doc).await;
		assert_eq!((again.status, &again.json["generation"], &again.json["revision"], std::fs::read(&node.file).unwrap()), (200, &json!(2), &applied.json["revision"], saved));
		// A file that cannot be written leaves the config in force and says so. Sending the document again once the file can be written saves it.
		// Here a directory with something in it stands in the place of the config file, which no file can be renamed onto.
		doc["exits"][0]["name"] = json!("Unsaved");
		let aside = node.dir.join("config.aside");
		std::fs::rename(&node.file, &aside).unwrap();
		std::fs::create_dir(&node.file).unwrap();
		std::fs::write(node.file.join("in the way"), "").unwrap();
		let unsaved = send(&node.socket, "PUT", "/v1/config", Some(applied.json["revision"].as_str().unwrap()), &doc).await;
		assert_eq!((unsaved.status, &unsaved.json["saved"], &unsaved.json["generation"], unsaved.json["save_error"].is_string()), (200, &json!(false), &json!(3), true), "{}", unsaved.json);
		assert_eq!((get(&node.socket, "/v1/exits").await.json["exits"][0]["name"].clone(), serde_json::from_slice::<Value>(&std::fs::read(&aside).unwrap()).unwrap()["exits"][0]["name"].clone(), temporary()), (json!("Unsaved"), json!("Kept"), 0));
		std::fs::remove_dir_all(&node.file).unwrap();
		std::fs::rename(&aside, &node.file).unwrap();
		let retried = send(&node.socket, "PUT", "/v1/config", Some(unsaved.json["revision"].as_str().unwrap()), &doc).await;
		assert_eq!((retried.status, &retried.json["saved"], &retried.json["generation"]), (200, &json!(true), &json!(3)), "{}", retried.json);
		assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(&node.file).unwrap()).unwrap()["exits"][0]["name"], json!("Unsaved"));
		let (limits, revision, wanted, keys, public, addr) = (node.limits.clone(), retried.json["revision"].clone(), secrets(&node.doc), node.keys, node.public, node.addr);
		(node.stop().await, limits, revision, wanted, keys, public, addr)
	});
	drop(first);
	// A node that starts on the file runs what was applied, under the revision the apply answered with, and with the secrets it had.
	runtime().block_on(async {
		let (engine, server) = start(&dir, &limits).await;
		let shown = get(&dir.join("veilway.sock"), "/v1/config").await;
		assert_eq!((&shown.json["revision"], &shown.json["generation"], &shown.json["document"]["exits"][0]["name"], &shown.json["document"]["users"][1]["enabled"]), (&revision, &json!(1), &json!("Unsaved"), &json!(false)));
		assert_eq!(secrets(&serde_json::from_slice::<Value>(&std::fs::read(dir.join("config.json")).unwrap()).unwrap()), wanted);
		Client::connect(keys[0], None, public, addr).await;
		assert!(Client::try_connect(keys[1], None, public, addr, Duration::from_millis(700)).await.is_none(), "a user the saved config disables got in after the restart");
		server.shutdown().await;
		Arc::try_unwrap(engine).ok().expect("the API still holds the engine after its shutdown").shutdown().await;
	});
	std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_apply_that_is_refused_changes_neither_the_node_nor_the_file() {
	let node = launch(setup().await).await;
	let (doc, revision) = node.shown().await;
	let before = std::fs::read(&node.file).unwrap();
	let mut a = Client::connect(node.keys[0], None, node.public, node.addr).await;
	let mut events = Events::open(&node.socket).await;
	// Validation: a reference to nothing, and a value of the wrong kind next to a secret that was sent in the clear.
	let mut dangling = doc.clone();
	dangling["routing"]["default"] = json!("nowhere");
	let refused = send(&node.socket, "PUT", "/v1/config", Some(&revision), &dangling).await;
	assert_eq!((refused.status, refused.code(), &refused.json["error"]["details"][0]["path"]), (422, "config_invalid", &json!("routing.default")), "{}", refused.json);
	let mut wrong = node.doc.clone();
	wrong["outbounds"][0]["server"] = json!(7);
	let refused = send(&node.socket, "PUT", "/v1/config", Some(&revision), &wrong).await;
	assert_eq!((refused.status, refused.code(), &refused.json["error"]["details"][0]["path"]), (422, "config_invalid", &json!("outbounds[0].server")), "{}", refused.json);
	// Prepare: an inbound on a port somebody else holds.
	let taken = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let mut busy = doc.clone();
	busy["inbounds"].as_array_mut().unwrap().push(json!({"tag": "second", "type": "wireguard", "private_key": veilway_wg::encode_key(&veilway_wg::generate_key()), "address": ["10.8.0.1/24"], "transports": [{"type": "udp", "listen": taken.local_addr().unwrap().to_string()}]}));
	let refused = send(&node.socket, "PUT", "/v1/config", Some(&revision), &busy).await;
	assert_eq!((refused.status, refused.code()), (422, "config_not_prepared"), "{}", refused.json);
	assert!(refused.json["error"]["message"].as_str().unwrap().contains("inbounds[1].transports[0].listen"), "{}", refused.json);
	assert_eq!(events.until("config_refused", |_| true).await.data, json!({"stage": "prepare", "errors": 1}));
	// What a reload on SIGHUP refuses is an event too.
	assert!(node.engine.reload(b"{\"version\":1".to_vec(), None).await.is_err());
	assert_eq!(events.until("config_refused", |_| true).await.data, json!({"stage": "validate", "errors": 1}));
	let status = get(&node.socket, "/v1/status").await;
	assert_eq!((&status.json["generation"], status.json["revision"].as_str(), std::fs::read(&node.file).unwrap(), node.engine.snapshot().generation), (&json!(1), Some(revision.as_str()), before, 1));
	assert_eq!(a.greeted(PEER_A, 40003).await, GREETING, "the session of a device did not survive applies that were refused");
	no_secret_logged();
	drop(events);
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_request_that_goes_wrong_is_answered_in_one_shape() {
	let mut roomy = setup().await;
	roomy.limits.body = 64 << 10;
	let node = launch(roomy).await;
	let (doc, revision) = node.shown().await;
	let padded = |bytes: usize| {
		let mut large = doc.clone();
		large["groups"] = Value::Array((0..bytes / 16).map(|group| json!(format!("group-{group:08}"))).collect());
		large.to_string()
	};
	for (method, path) in [("POST", "/v1/config/validate"), ("POST", "/v1/config/diff"), ("PUT", "/v1/config")] {
		let headers = [JSON, ("if-match", revision.as_str())];
		// Too large, whether the request says so up front or only turns out to be while it is read.
		let large = call(&node.socket, method, path, &headers, Some(Body::from(padded(128 << 10)))).await;
		assert_eq!((large.status, large.code()), (413, "body_too_large"), "{method} {path}");
		let pieces: Vec<Result<String, std::io::Error>> = padded(128 << 10).as_bytes().chunks(8 << 10).map(|piece| Ok(String::from_utf8_lossy(piece).into_owned())).collect();
		let large = call(&node.socket, method, path, &headers, Some(Body::from_stream(futures_util::stream::iter(pieces)))).await;
		assert_eq!((large.status, large.code()), (413, "body_too_large"), "{method} {path}, streamed");
		// A body just under the limit is read and judged as a document.
		assert!(matches!(call(&node.socket, method, path, &headers, Some(Body::from(padded(48 << 10)))).await.status, 200 | 422), "{method} {path} did not take a body under the limit");
		for broken in ["", "{\"version\":1", "{\"version\":1}}", "not json", "\u{feff}{}"] {
			let bad = call(&node.socket, method, path, &headers, Some(Body::from(broken))).await;
			assert_eq!((bad.status, bad.code()), (400, "bad_json"), "{method} {path} {broken:?}");
		}
		// JSON that is no config is a document to report on, with the path of what is wrong and never its value.
		for (strange, at) in [("[]", ""), ("{}", ""), ("{\"version\":1,\"version\":1}", ""), ("{\"version\":2}", "")] {
			let judged = call(&node.socket, method, path, &headers, Some(Body::from(strange))).await;
			if method == "PUT" {assert_eq!((judged.status, judged.code(), &judged.json["error"]["details"][0]["path"]), (422, "config_invalid", &json!(at)), "{strange}")} else {assert_eq!((judged.status, &judged.json["valid"], &judged.json["report"]["errors"][0]["path"]), (200, &json!(false), &json!(at)), "{strange}")}
		}
		for kind in [None, Some("text/plain"), Some("application/x-www-form-urlencoded"), Some("application/jsonx")] {
			let mut headers = vec![("if-match", revision.as_str())];
			headers.extend(kind.map(|kind| ("content-type", kind)));
			let wrong = call(&node.socket, method, path, &headers, Some(Body::from(doc.to_string()))).await;
			assert_eq!((wrong.status, wrong.code()), (415, "unsupported_media_type"), "{method} {path} {kind:?}");
		}
		assert!(matches!(call(&node.socket, method, path, &[("content-type", "Application/JSON; charset=utf-8"), ("if-match", revision.as_str())], Some(Body::from(doc.to_string()))).await.status, 200), "{method} {path} did not take application/json with a charset");
	}
	for path in ["/", "/v1", "/v1/", "/v1/nothing", "/v2/status", "/v1/status/", "/v1/users/a/b", "/v1/users/", "/status", "/v1/config/apply"] {
		let unknown = get(&node.socket, path).await;
		assert_eq!((unknown.status, unknown.code()), (404, "not_found"), "{path}");
	}
	for (method, path) in [("POST", "/v1/status"), ("DELETE", "/v1/config"), ("GET", "/v1/config/validate"), ("PUT", "/v1/users/a"), ("POST", "/v1/events"), ("PATCH", "/v1/config")] {
		let refused = call(&node.socket, method, path, &[JSON], Some(Body::from("{}"))).await;
		assert_eq!((refused.status, refused.code()), (405, "method_not_allowed"), "{method} {path}");
	}
	// A request line or headers beyond what the HTTP layer takes never reach a handler, and the node goes on serving.
	for head in [format!("GET /v1/status?{} HTTP/1.1\r\nhost: veilway\r\n\r\n", "x".repeat(64 << 10)), format!("GET /v1/status HTTP/1.1\r\nhost: veilway\r\nx-large: {}\r\n\r\n", "x".repeat(64 << 10)), format!("GET /v1/status HTTP/1.1\r\nhost: veilway\r\n{}\r\n", "x-many: 1\r\n".repeat(200))] {
		let (answer, closed) = raw(&node.socket, head.as_bytes(), Duration::from_secs(3)).await;
		assert!(closed && (answer.is_empty() || answer.starts_with(b"HTTP/1.1 4")) && !answer.windows(4).any(|window| window == b"\"ver"), "an oversized request head was served: {:?}", String::from_utf8_lossy(&answer[..answer.len().min(80)]));
	}
	assert_eq!(node.engine.snapshot().generation, 2, "one request above was an apply, of the running document with a charset, and no other put anything in force");
	node.end().await;
	// A request that is not finished in time: a body that never comes is answered and dropped, and so is a connection that never says what it wants. Only this node has a request time of one second, so that no other request above can be late for it on a busy machine.
	let mut setup = setup().await;
	setup.limits.request = Duration::from_secs(1);
	let node = launch(setup).await;
	let started = Instant::now();
	let (answer, _) = raw(&node.socket, b"POST /v1/config/validate HTTP/1.1\r\nhost: veilway\r\ncontent-type: application/json\r\ncontent-length: 10\r\n\r\n{", Duration::from_secs(4)).await;
	let answer = String::from_utf8_lossy(&answer);
	assert!(answer.starts_with("HTTP/1.1 408") && answer.contains("\"code\":\"request_timeout\"") && started.elapsed() < Duration::from_secs(3), "{answer:?} after {:?}", started.elapsed());
	for unfinished in [&b""[..], b"GET /v1/status HTTP/1.1\r\nhost: veil"] {
		let started = Instant::now();
		let (_, closed) = raw(&node.socket, unfinished, Duration::from_secs(4)).await;
		assert!(closed && started.elapsed() < Duration::from_secs(3), "a connection that never finished its request was kept for {:?}", started.elapsed());
	}
	// The event stream is no request that has to finish: it outlives the time a request gets.
	let mut events = Events::open(&node.socket).await;
	let started = Instant::now();
	while started.elapsed() < Duration::from_millis(2500) {events.until("stats", |_| true).await;}
	assert_eq!(get(&node.socket, "/v1/status").await.status, 200);
	drop(events);
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_and_streams_are_counted() {
	let mut setup = setup().await;
	(setup.limits.connections, setup.limits.streams) = (4, 2);
	let node = launch(setup).await;
	let (first, second) = (Events::open(&node.socket).await, Events::open(&node.socket).await);
	let third = get(&node.socket, "/v1/events").await;
	assert_eq!((third.status, third.code()), (503, "too_many_streams"));
	tokio::time::sleep(Duration::from_millis(300)).await;
	// Two streams are two connections. Two more that say nothing fill the node, and the one after is told so and closed.
	let mut idle = Vec::new();
	let full = loop {
		let mut stream = UnixStream::connect(&node.socket).await.unwrap();
		let mut answer = vec![0u8; 4096];
		match timeout(Duration::from_millis(300), stream.read(&mut answer)).await {
			Ok(Ok(n)) => break String::from_utf8_lossy(&answer[..n]).into_owned(),
			_ => idle.push(stream),
		}
		assert!(idle.len() <= 4, "the node took more connections than it may");
	};
	assert_eq!(idle.len(), 2, "the node was full at another number of connections than its limit");
	assert!(full.starts_with("HTTP/1.1 503") && full.contains("\"code\":\"too_many_connections\"") && full.contains("connection: close"), "{full:?}");
	let body: Value = serde_json::from_str(full.split("\r\n\r\n").nth(1).unwrap()).unwrap();
	valid(&json!({"$ref": "#/components/schemas/ErrorBody"}), &body, "error").unwrap();
	// A connection that ends gives its place back, and a stream that ends its place among the streams.
	idle.pop();
	eventually("a connection that ended did not give its place back", async || raw(&node.socket, b"GET /v1/status HTTP/1.1\r\nhost: veilway\r\nconnection: close\r\n\r\n", Duration::from_secs(2)).await.0.starts_with(b"HTTP/1.1 200")).await;
	drop(first);
	eventually("a stream that ended did not give its place back", async || {
		let (answer, _) = raw(&node.socket, b"GET /v1/events HTTP/1.1\r\nhost: veilway\r\n\r\n", Duration::from_millis(300)).await;
		answer.starts_with(b"HTTP/1.1 200")
	}).await;
	drop((second, idle));
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_event_stream_says_what_the_node_does() {
	let mut setup = setup().await;
	setup.doc["users"][1]["quota_bytes"] = json!(1200);
	setup.limits.keep_alive = Duration::from_millis(200);
	let node = launch(setup).await;
	let mut events = Events::open(&node.socket).await;
	let mut a = Client::connect(node.keys[0], None, node.public, node.addr).await;
	let mut b = Client::connect(node.keys[1], None, node.public, node.addr).await;
	// One event a second with the snapshot of /v1/stats, and comment lines in between to keep the stream alive.
	let (first, second) = (events.until("stats", |_| true).await, events.until("stats", |_| true).await);
	assert!(second.id > first.id && first.data["users"].as_array().unwrap().len() == 3 && events.comments >= 2, "{} comments", events.comments);
	// A user who runs out of quota, on traffic the node refuses at its own gateway, which counts like any other.
	for _ in 0..2 {b.send_ip(&ip_udp(PEER_B, [10, 7, 0, 1], 44002, 9, &[b'x'; 1000])).await}
	let cut = events.until("user_cut_off", |_| true).await;
	assert_eq!(cut.data, json!({"user": "b", "reason": "quota"}));
	assert_eq!(get(&node.socket, "/v1/users/b").await.json["denied"], json!("quota"));
	// An apply: the config, and every user whose access it turns.
	let (mut doc, revision) = node.shown().await;
	doc["users"][1].as_object_mut().unwrap().remove("quota_bytes");
	doc["users"][0]["enabled"] = json!(false);
	doc["users"].as_array_mut().unwrap().remove(2);
	let applied = send(&node.socket, "PUT", "/v1/config", Some(&revision), &doc).await;
	assert_eq!(applied.status, 200, "{}", applied.json);
	let (mut said, mut config) = (Vec::new(), None);
	while said.len() < 3 || config.is_none() {
		let event = events.next(Duration::from_secs(5)).await.expect("the events of an apply did not come");
		match event.kind.as_str() {
			"config_applied" => config = Some(event),
			"user_cut_off" | "user_restored" => said.push((event.kind, event.data)),
			_ => {}
		}
	}
	said.sort_by_key(|(_, data)| data["user"].as_str().unwrap().to_string());
	assert_eq!(said, [("user_cut_off".to_string(), json!({"user": "a", "reason": "disabled"})), ("user_restored".to_string(), json!({"user": "b"})), ("user_cut_off".to_string(), json!({"user": "c", "reason": "removed"}))]);
	let config = config.unwrap();
	assert_eq!((&config.data["generation"], &config.data["revision"], &config.data["diff"]["users"]), (&json!(2), &applied.json["revision"], &json!({"added": [], "changed": ["a", "b"], "removed": ["c"]})), "{}", config.data);
	// The upstream of an exit that turns out not to relay UDP.
	let mut b = Client::connect(node.keys[1], None, node.public, node.addr).await;
	b.send_ip(&ip_udp(PEER_B, PUBLIC, 44003, 9999, b"datagram")).await;
	assert_eq!(events.until("exit_udp_changed", |_| true).await.data, json!({"exit": "main", "udp": false}));
	let exits = get(&node.socket, "/v1/exits").await;
	assert_eq!((&exits.json["exits"][0]["udp"], &exits.json["exits"][0]["udp_flips"], exits.json["exits"][0]["udp_down_secs"].is_u64()), (&json!(false), &json!(1), true), "{}", exits.json);
	assert!(Client::try_connect(node.keys[0], None, node.public, node.addr, Duration::from_millis(700)).await.is_none() && a.recv_ip(Duration::from_millis(100)).await.is_none());
	no_secret_logged();
	drop(events);
	node.end().await;
}

/// A usage reset through the API. User `b` runs out of quota, and the reset lets them in again at once, says so on the event stream, and is in the state file when it is answered: the second node here starts on the file as it was at that moment, which is what a node that is killed right then leaves.
/// `traffic` stays until the body asks for it, a body that is no reset is refused before anything changes, and a user the config does not have is a 404.
/// The second node also finds a quota period for `b` that begins years after its clock, which it puts back and says so once.
#[test]
fn a_usage_reset_starts_the_count_over_lets_the_user_in_and_survives_a_restart() {
	let runtime = || tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
	let (first, far) = (runtime(), 4102444800i64 + i64::from(std::process::id()));
	let (limits, kept, traffic, dir) = first.block_on(async {
		let mut setup = setup().await;
		setup.doc["users"][1]["quota_bytes"] = json!(1200);
		setup.limits.body = 64 << 10;
		let node = launch(setup).await;
		let (mut events, reset, state) = (Events::open(&node.socket).await, "/v1/users/b/usage/reset", node.dir.join("state.json"));
		let mut b = Client::connect(node.keys[1], None, node.public, node.addr).await;
		for _ in 0..2 {b.send_ip(&ip_udp(PEER_B, [10, 7, 0, 1], 44010, 9, &[b'x'; 1000])).await}
		events.until("user_cut_off", |_| true).await;
		// Whatever was on its way to the device when it was cut off has been counted by now.
		tokio::time::sleep(Duration::from_millis(200)).await;
		let spent = get(&node.socket, "/v1/users/b").await.json;
		assert!(spent["denied"] == "quota" && spent["used_bytes"].as_u64().unwrap() >= 1200 && spent["traffic"]["up_bytes"].as_u64().unwrap() >= 1028, "{spent}");
		for (typed, body, status, code) in [(true, "{\"totals\":\"yes\"}", 422, "body_invalid"), (true, "{\"totals\":true,\"more\":1}", 422, "body_invalid"), (true, "[]", 422, "body_invalid"), (true, "true", 422, "body_invalid"), (true, "{\"totals\":true", 400, "bad_json"), (false, "{\"totals\":true}", 415, "unsupported_media_type")] {
			let refused = call(&node.socket, "POST", reset, if typed {&[JSON][..]} else {&[]}, Some(Body::from(body))).await;
			assert_eq!((refused.status, refused.code()), (status, code), "{body}");
		}
		let large = call(&node.socket, "POST", reset, &[JSON], Some(Body::from(format!("{{\"totals\":true{}}}", " ".repeat(128 << 10))))).await;
		assert_eq!((large.status, large.code()), (413, "body_too_large"));
		for missing in ["/v1/users/nobody/usage/reset", "/v1/users/%ff/usage/reset", "/v1/users/A%20B/usage/reset"] {
			let none = call(&node.socket, "POST", missing, &[JSON], Some(Body::from("{\"totals\":true}"))).await;
			assert_eq!((none.status, none.code()), (404, "user_not_found"), "{missing}");
		}
		let wrong = get(&node.socket, reset).await;
		assert_eq!((wrong.status, wrong.code()), (405, "method_not_allowed"));
		assert_eq!(get(&node.socket, "/v1/users/b").await.json, spent, "a reset that was refused changed something");
		assert!(Client::try_connect(node.keys[1], None, node.public, node.addr, Duration::from_millis(500)).await.is_none(), "a user who ran out of quota completed a handshake");
		// The reset, with no body at all.
		let fresh = call(&node.socket, "POST", reset, &[], None).await;
		assert_eq!((fresh.status, &fresh.json["name"], &fresh.json["used_bytes"], &fresh.json["period_start"], &fresh.json["denied"], &fresh.json["quota_bytes"], &fresh.json["traffic"]), (200, &json!("b"), &json!(0), &json!(0), &Value::Null, &json!(1200), &spent["traffic"]), "{}", fresh.json);
		let kept = std::fs::read(&state).unwrap();
		let saved: Value = serde_json::from_slice(&kept).unwrap();
		assert_eq!((&saved["users"]["b"]["used_bytes"], &saved["users"]["b"]["up_bytes"]), (&json!(0), &spent["traffic"]["up_bytes"]), "the reset was not in the state file when it was answered: {saved}");
		assert_eq!(events.until("usage_reset", |_| true).await.data, json!({"user": "b", "totals": false}));
		assert_eq!(events.until("user_restored", |_| true).await.data, json!({"user": "b"}));
		let mut b = Client::connect(node.keys[1], None, node.public, node.addr).await;
		b.send_ip(&ip_udp(PEER_B, [10, 7, 0, 1], 44011, 9, &[b'x'; 100])).await;
		eventually("a user who was let in again is not counted", async || get(&node.socket, "/v1/users/b").await.json["used_bytes"].as_u64().unwrap() >= 128).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
		// The same request again starts the count over again and that is all: the totals go on from where they were.
		let again = call(&node.socket, "POST", reset, &[JSON], Some(Body::from("{}"))).await;
		assert!(again.status == 200 && again.json["used_bytes"] == 0 && again.json["denied"].is_null() && again.json["traffic"]["up_bytes"].as_u64() > spent["traffic"]["up_bytes"].as_u64(), "{}", again.json);
		let zeroed = call(&node.socket, "POST", reset, &[("content-type", "application/json; charset=utf-8")], Some(Body::from("{\"totals\": true}"))).await;
		assert_eq!((zeroed.status, &zeroed.json["traffic"], &zeroed.json["used_bytes"]), (200, &json!({"up_bytes": 0, "up_packets": 0, "down_bytes": 0, "down_packets": 0}), &json!(0)), "{}", zeroed.json);
		assert_eq!(events.until("usage_reset", |data| data["totals"] == true).await.data, json!({"user": "b", "totals": true}));
		assert_eq!(get(&node.socket, "/v1/users/a").await.json["denied"], Value::Null);
		assert!(String::from_utf8_lossy(&LOGS.lock().unwrap()).contains("user b: usage reset: "), "a usage reset was not logged");
		no_secret_logged();
		drop(events);
		(node.limits.clone(), kept, spent["traffic"].clone(), node.stop().await)
	});
	drop(first);
	let mut left: Value = serde_json::from_slice(&kept).unwrap();
	(left["users"]["b"]["period_start"], left["users"]["a"]["period_start"]) = (json!(far), json!(far));
	std::fs::write(dir.join("state.json"), left.to_string()).unwrap();
	runtime().block_on(async {
		let (engine, server) = start(&dir, &limits).await;
		let b = get(&dir.join("veilway.sock"), "/v1/users/b").await;
		assert_eq!((b.status, &b.json["used_bytes"], &b.json["period_start"], &b.json["denied"], &b.json["traffic"]), (200, &json!(0), &json!(0), &Value::Null, &traffic), "{}", b.json);
		// Several looks at the clock later it has still been said once for each of the two users, and no more.
		tokio::time::sleep(Duration::from_secs(1)).await;
		assert_eq!(String::from_utf8_lossy(&LOGS.lock().unwrap()).matches(&format!("was said to have begun at {far}, ")).count(), 2, "a quota period after the clock was not said once for each user it was found for");
		server.shutdown().await;
		Arc::try_unwrap(engine).ok().expect("the API still holds the engine after its shutdown").shutdown().await;
	});
	std::fs::remove_dir_all(dir).unwrap();
}

/// `count` more users on top of the three, which is what makes a snapshot of the counters too large for the buffers between the node and a reader.
fn crowd(doc: &mut Value, count: usize) {
	let users = doc["users"].as_array_mut().unwrap();
	for user in 0..count {
		let mut public = [1u8; 32];
		public[..8].copy_from_slice(&(user as u64).to_be_bytes());
		users.push(json!({"name": format!("crowd-{user:05}"), "exits": "all", "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&public), "addresses": [format!("10.7.{}.{}", 1 + user / 250, 1 + user % 250)]}]}));
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_is_too_slow_loses_events_and_is_told_how_many() {
	let mut setup = setup().await;
	crowd(&mut setup.doc, 3000);
	setup.limits.events = 8;
	// The slow reader of this test is one that lags, not one that is dropped for taking nothing, however long a starved machine needs for the applies.
	setup.limits.request = Duration::from_secs(600);
	let node = launch(setup).await;
	// A reader that asks for the stream and then takes nothing: the snapshots fill what lies between the node and it, and from then on the node has nowhere to put its events.
	let mut slow = UnixStream::connect(&node.socket).await.unwrap();
	slow.write_all(b"GET /v1/events HTTP/1.1\r\nhost: veilway\r\n\r\n").await.unwrap();
	// 20 applies are 40 events, each config with the user it turned. A reader that keeps up gets every one of them, and that it keeps up is made true here, not hoped for.
	// A snapshot is an event like any other in the node's buffer, one a second, so a reader that needs longer than that for each falls behind on snapshots alone and is rightly told so.
	// Reading every snapshot against its schema is what took `Events::next` that long on a starved machine. This reader passes over a snapshot, and every apply waits for the events of the one before to be read.
	let mut quick = Events::open(&node.socket).await;
	let (taken, mut seen) = tokio::sync::watch::channel((0, 0));
	let kept_up = tokio::spawn(async move {
		let (mut text, mut from, mut last, mut got, mut snapshots) = (Vec::new(), 0, 0u64, 0, 0);
		while got < 40 {
			let frame = timeout(Duration::from_secs(30), poll_fn(|cx| Pin::new(&mut quick.body).poll_frame(cx))).await.expect("a reader that kept up did not get every event").expect("the event stream ended").expect("the event stream broke");
			let Ok(chunk) = frame.into_data() else {continue};
			text.extend_from_slice(&chunk);
			while let Some(end) = text[from..].windows(2).position(|pair| pair == b"\n\n").map(|at| from + at) {
				let block = String::from_utf8(text.drain(..end + 2).collect()).expect("an event that is not UTF-8");
				from = 0;
				let Some(kind) = block.lines().find_map(|line| line.strip_prefix("event: ")) else {continue};
				assert_ne!(kind, "lagged", "a reader that kept up was told it had not: {}", &block[..block.len().min(200)]);
				let id = block.lines().find_map(|line| line.strip_prefix("id: ")).and_then(|id| id.parse::<u64>().ok()).expect("an event without an id");
				assert!(last == 0 || id == last + 1, "nothing was lost and the {kind} event after {last} has id {id}");
				last = id;
				if kind == "stats" {snapshots += 1} else {
					valid(&OPENAPI["x-events"][kind], &serde_json::from_str(block.lines().find_map(|line| line.strip_prefix("data: ")).expect("an event without data")).unwrap(), kind).unwrap();
					got += 1;
				}
				taken.send_replace((got, snapshots));
			}
			from = text.len().saturating_sub(1);
		}
	});
	// Four snapshots are more than a megabyte, which nothing between the node and a reader holds.
	let _ = timeout(Duration::from_secs(60), seen.wait_for(|(_, snapshots)| *snapshots >= 4)).await.expect("no snapshots came").expect("the reader that kept up ended early");
	let mut doc = node.doc.clone();
	for round in 0..20 {
		doc["users"][1]["enabled"] = json!(round % 2 == 1);
		node.engine.reload(doc.to_string().into_bytes(), None).await.unwrap();
		let _ = timeout(Duration::from_secs(30), seen.wait_for(|(got, _)| *got >= 2 * (round + 1))).await.expect("a reader that kept up did not get the events of an apply").expect("the reader that kept up ended early");
	}
	kept_up.await.unwrap();
	// The slow one now reads what was waiting for it. The node kept 8 events for it and no more, so of the 40 it gets a few, and a count of the rest.
	let (mut text, mut buf, deadline) = (String::new(), vec![0u8; 1 << 20], Instant::now() + Duration::from_secs(20));
	let lagged = loop {
		if let Some(data) = text.find("event: lagged\ndata: ").map(|at| &text[at + 20..]) {
			if let Some(end) = data.find("\n\n") {break serde_json::from_str::<Value>(&data[..end]).unwrap()}
		}
		let n = timeout(deadline.saturating_duration_since(Instant::now()), slow.read(&mut buf)).await.expect("no lagged event came").unwrap();
		assert!(n > 0, "the node closed the stream of a slow reader instead of telling it what it lost");
		text.push_str(&String::from_utf8_lossy(&buf[..n]));
		// Only the tail is kept: the snapshots before it are megabytes.
		if text.len() > 4096 && !text.contains("event: lagged") {text = text.split_off(text.len() - 64)}
	};
	valid(&OPENAPI["x-events"]["lagged"], &lagged, "lagged").unwrap();
	assert!(lagged["missed"].as_u64().unwrap() >= 40 - 8 - 4, "the node kept more events for a slow reader than its limit: only {lagged} were dropped");
	// What comes after the gap is the stream as everybody gets it.
	let rest = timeout(Duration::from_secs(5), async {
		loop {
			let n = slow.read(&mut buf).await.unwrap();
			text.push_str(&String::from_utf8_lossy(&buf[..n]));
			if text.matches("\nid: ").count() >= 3 {return}
		}
	}).await;
	assert!(rest.is_ok(), "nothing came after the lagged event");
	let ids: Vec<u64> = text[text.find("event: lagged").unwrap()..].split("\nid: ").skip(1).filter_map(|rest| rest.lines().next()?.trim().parse().ok()).collect();
	assert!(ids.windows(2).all(|pair| pair[0] < pair[1]) && ids.len() >= 3, "{ids:?}");
	drop(slow);
	node.end().await;
}

/// A node whose snapshots take longer to put together than the time between two has the next one due the moment one is done. The readers it wakes with a frame must still be run before the next frame is made:
/// a reader that waits for its first event would otherwise not be looked at again for well over a hundred snapshots, by when the buffer has gone over it, and it would be told it had lagged before it was sent anything.
/// No machine is slow enough to make a snapshot take a second here, so the time between two is brought down to less than one takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_that_takes_longer_than_the_time_between_two_holds_no_reader_up() {
	let mut setup = setup().await;
	crowd(&mut setup.doc, 3000);
	(setup.limits.sample, setup.limits.events, setup.limits.request) = (Duration::from_millis(1), 16, Duration::from_secs(600));
	let node = launch(setup).await;
	// The runtime only learns that the next snapshot is already due when something else makes it look at the clock, which the timers of a node with traffic do all the time.
	let clock = tokio::spawn(async {
		loop {tokio::time::sleep(Duration::from_millis(1)).await}
	});
	for round in 0..10 {
		let (mut reader, mut text, mut buf) = (UnixStream::connect(&node.socket).await.unwrap(), String::new(), vec![0u8; 4096]);
		reader.write_all(b"GET /v1/events HTTP/1.1\r\nhost: veilway\r\n\r\n").await.unwrap();
		let kind = loop {
			if let Some((kind, _)) = text.split_once("event: ").and_then(|(_, rest)| rest.split_once('\n')) {break kind.to_string()}
			let n = timeout(Duration::from_secs(120), reader.read(&mut buf)).await.expect("no event came").unwrap();
			assert!(n > 0, "the node closed an event stream");
			text.push_str(&String::from_utf8_lossy(&buf[..n]));
		};
		assert_eq!(kind, "stats", "reader {round} had asked for the stream and was waiting, and the first thing it was sent was not the next event");
	}
	clock.abort();
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_takes_nothing_of_its_answer_is_dropped() {
	let mut setup = setup().await;
	crowd(&mut setup.doc, 3000);
	setup.limits.request = Duration::from_secs(1);
	let node = launch(setup).await;
	let full = get(&node.socket, "/v1/users").await.body.len();
	assert!(full > 512 << 10, "the answer is only {full} bytes, which a socket may hold without its reader");
	let mut stuck = UnixStream::connect(&node.socket).await.unwrap();
	stuck.write_all(b"GET /v1/users HTTP/1.1\r\nhost: veilway\r\n\r\n").await.unwrap();
	tokio::time::sleep(Duration::from_millis(2500)).await;
	// By now the node has given up on it. What it reads is what was already on its way, and then the end.
	let (mut got, mut buf) = (0, vec![0u8; 1 << 16]);
	let closed = timeout(Duration::from_secs(5), async {
		loop {
			match stuck.read(&mut buf).await {
				Ok(0) | Err(_) => return,
				Ok(n) => got += n,
			}
		}
	}).await;
	assert!(closed.is_ok() && got < full, "a reader that took nothing for longer than a request may take was still sent its whole answer ({got} of {full} bytes)");
	assert_eq!(get(&node.socket, "/v1/status").await.status, 200);
	node.end().await;
}

/// Whoever edits a config through the API is never shown its secrets, and must not get at them another way: not by having the node send them somewhere, and not by asking it whether a guess is right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_marker_keeps_a_secret_only_for_the_proxy_it_was_shown_for_and_no_answer_tells_a_guess_from_the_secret() {
	let mut setup = setup().await;
	let second = [format!("name-{}", veilway_wg::encode_key(&veilway_wg::generate_key()).replace(['+', '/', '='], "")), format!("word-{}", veilway_wg::encode_key(&veilway_wg::generate_key()).replace(['+', '/', '='], ""))];
	setup.doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "second", "type": "socks5", "server": "127.0.0.1:1081", "username": second[0], "password": second[1]}));
	SECRETS.lock().unwrap().extend(second);
	let node = launch(setup).await;
	let (doc, revision) = node.shown().await;
	let before = std::fs::read(&node.file).unwrap();
	let only_paths = |list: &Value| list.as_array().unwrap().iter().map(|problem| problem["path"].as_str().unwrap().to_string()).collect::<Vec<_>>();
	// The markers of one proxy under the server of another, by changing the server or by swapping the tags: the node would log in there with what it was never asked to show.
	let (mut moved, mut swapped) = (doc.clone(), doc.clone());
	moved["outbounds"][0]["server"] = json!("127.0.0.1:9");
	(swapped["outbounds"][0]["tag"], swapped["outbounds"][1]["tag"]) = (json!("second"), json!("proxy"));
	for (sent, paths) in [(&moved, vec!["outbounds[0].username", "outbounds[0].password"]), (&swapped, vec!["outbounds[0].username", "outbounds[0].password", "outbounds[1].username", "outbounds[1].password"])] {
		let refused = send(&node.socket, "PUT", "/v1/config", Some(&revision), sent).await;
		assert_eq!((refused.status, refused.code(), only_paths(&refused.json["error"]["details"])), (422, "config_invalid", paths.iter().map(|path| path.to_string()).collect()), "{}", refused.json);
		let validated = send(&node.socket, "POST", "/v1/config/validate", None, sent).await;
		assert_eq!((validated.status, &validated.json["valid"], only_paths(&validated.json["report"]["errors"])), (200, &json!(false), paths.iter().map(|path| path.to_string()).collect()), "{}", validated.json);
		assert_eq!(send(&node.socket, "POST", "/v1/config/diff", None, sent).await.json["diff"], Value::Null);
	}
	assert_eq!((node.engine.snapshot().generation, std::fs::read(&node.file).unwrap()), (1, before), "a document that moved a marker changed something");
	// A proxy that moves with its secrets sent along is a new proxy like any other.
	let mut fresh = moved.clone();
	(fresh["outbounds"][0]["username"], fresh["outbounds"][0]["password"]) = (json!("fresh-user"), json!("fresh-password"));
	assert_eq!(send(&node.socket, "POST", "/v1/config/validate", None, &fresh).await.json["valid"], json!(true));
	// A user name or a password that is sent in the clear is a changed outbound whatever it holds, so a guess that is right is answered exactly like one that is wrong.
	let unchanged = send(&node.socket, "POST", "/v1/config/diff", None, &doc).await;
	assert_eq!((unchanged.status, &unchanged.json["diff"]["outbounds"]["changed"]), (200, &json!([])), "{}", unchanged.json);
	for key in ["username", "password"] {
		let (mut right, mut wrong) = (doc.clone(), doc.clone());
		(right["outbounds"][0][key], wrong["outbounds"][0][key]) = (node.doc["outbounds"][0][key].clone(), json!("wrong-guess"));
		let (right, wrong) = (send(&node.socket, "POST", "/v1/config/diff", None, &right).await, send(&node.socket, "POST", "/v1/config/diff", None, &wrong).await);
		assert_eq!((right.status, &right.json["diff"]["outbounds"]["changed"], &right.json), (200, &json!(["proxy"]), &wrong.json), "the diff tells a {key} that was guessed right from one that was not");
	}
	no_secret_logged();
	node.end().await;
}

/// A reload that cuts off thousands of users says so thousands of times at once, which is more than the engine keeps for a listener. What is lost there is lost for every reader, and every reader is told how many.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_the_node_itself_could_not_keep_are_counted_for_every_reader() {
	let mut setup = setup().await;
	crowd(&mut setup.doc, 6000);
	// Room for everything on the reader's side, so whatever is lost here is lost between the engine and the API.
	setup.limits.events = 1 << 15;
	let node = launch(setup).await;
	let mut events = Events::open(&node.socket).await;
	events.until("stats", |_| true).await;
	let mut few = node.doc.clone();
	few["users"].as_array_mut().unwrap().truncate(3);
	node.engine.reload(few.to_string().into_bytes(), None).await.unwrap();
	let (mut cut, mut told, mut next) = (0u64, 0u64, events.last + 1);
	loop {
		let event = events.next(Duration::from_secs(20)).await.expect("the events of the reload did not come");
		match event.id {
			Some(id) => {
				assert_eq!(id, next, "{} events are missing before a {} event and no lagged event said so", id.saturating_sub(next), event.kind);
				next = id + 1;
			}
			None => {
				told += event.data["missed"].as_u64().unwrap();
				next += event.data["missed"].as_u64().unwrap();
			}
		}
		if event.kind == "user_cut_off" {cut += 1}
		if event.kind == "config_applied" {break}
	}
	assert!(told > 0, "the node kept all 6000 events, so this run says nothing about the ones it cannot keep");
	assert!(cut <= 6000 && cut + told >= 6000, "{cut} users were said to be cut off and {told} events were said to be lost, of 6000");
	drop(events);
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_apply_that_is_answered_as_too_slow_has_changed_nothing() {
	let mut setup = setup().await;
	crowd(&mut setup.doc, 4000);
	let node = launch(setup).await;
	let (mut doc, revision) = node.shown().await;
	doc["users"].as_array_mut().unwrap().truncate(2000);
	// How long the node takes to read and check the document, which is the first half of what an apply of it does. The first time is not counted: it is slower than any after it.
	assert_eq!(send(&node.socket, "POST", "/v1/config/diff", None, &doc).await.status, 200);
	let started = Instant::now();
	assert_eq!(send(&node.socket, "POST", "/v1/config/diff", None, &doc).await.status, 200);
	// A second API on the same engine that gives a request a little more than that: enough to check the document, and not enough to put it in force as well.
	let hurried = node.dir.join("hurried.sock");
	let server = veilway_api::serve(node.engine.clone(), ApiOptions {socket: hurried.clone(), config: node.file.clone(), limits: Limits {request: started.elapsed().mul_f32(1.4), ..Limits::default()}}).unwrap();
	let answer = send(&hurried, "PUT", "/v1/config", Some(&revision), &doc).await;
	// Whatever the engine was still doing when the answer went out has ended by now.
	tokio::time::sleep(Duration::from_secs(3)).await;
	match (answer.status, node.engine.snapshot().generation) {
		(200, 2) => assert_eq!((&answer.json["generation"], node.engine.snapshot().config.users.len()), (&json!(2), 2000)),
		(408, 1) => assert_eq!(answer.code(), "request_timeout"),
		(408, _) => panic!("the node answered that the apply was not finished in time, and put the config in force all the same"),
		other => panic!("an apply was answered {} with generation {} in force: {}", other.0, other.1, answer.json),
	}
	server.shutdown().await;
	node.end().await;
}

/// The check of a document takes memory many times the size of its text, so only two are ever being checked, however many connections ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn documents_are_checked_two_at_a_time_and_the_next_one_waits_its_turn() {
	let node = launch(setup().await).await;
	let (small, _) = node.shown().await;
	let mut large = small.clone();
	crowd(&mut large, 12000);
	// Eight large documents at once, each written to its socket whole. A document waits for its turn only once the node has it, so the small one is sent when the first is answered and every other has been handed over, however late the machine let them be.
	let (answered, written, mut busy) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), tokio::task::JoinSet::new());
	let body = large.to_string();
	let request = format!("POST /v1/config/validate HTTP/1.1\r\nhost: veilway\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len());
	for _ in 0..8 {
		let (socket, request, answered, written) = (node.socket.clone(), request.clone(), answered.clone(), written.clone());
		busy.spawn(async move {
			let mut stream = UnixStream::connect(&socket).await.unwrap();
			stream.write_all(request.as_bytes()).await.unwrap();
			written.fetch_add(1, Ordering::SeqCst);
			let mut line = [0u8; 12];
			stream.read_exact(&mut line).await.unwrap();
			answered.fetch_add(1, Ordering::SeqCst);
			String::from_utf8_lossy(&line[9..]).parse::<u16>().unwrap()
		});
	}
	assert_eq!(busy.join_next().await.unwrap().unwrap(), 200);
	timeout(Duration::from_secs(60), async {while written.load(Ordering::SeqCst) < 8 {tokio::time::sleep(Duration::from_millis(10)).await}}).await.expect("a large document was never handed to the node");
	assert_eq!(send(&node.socket, "POST", "/v1/config/validate", None, &small).await.json["valid"], json!(true));
	let before = answered.load(Ordering::SeqCst);
	while let Some(status) = busy.join_next().await {assert_eq!(status.unwrap(), 200)}
	assert!(before >= 6, "a document was checked ahead of others that had been waiting for their turn: only {before} of the 8 before it had been answered");
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whatever_is_put_at_the_socket_path_while_the_node_starts_stays() {
	let node = launch(setup().await).await;
	let (path, stop) = (node.dir.join("raced.sock"), Arc::new(AtomicBool::new(false)));
	// Somebody who keeps putting a file at the path, and looks whether it is still theirs before taking it away again.
	let intruder = std::thread::spawn({
		let (path, stop) = (path.clone(), stop.clone());
		move || {
			let mut lost = 0;
			while !stop.load(Ordering::SeqCst) {
				std::thread::sleep(Duration::from_micros(50));
				if std::fs::OpenOptions::new().write(true).create_new(true).open(&path).and_then(|mut file| file.write_all(b"theirs")).is_err() {continue}
				std::thread::sleep(Duration::from_micros(200));
				if std::fs::read(&path).ok().as_deref() == Some(b"theirs") {let _ = std::fs::remove_file(&path);} else {lost += 1}
			}
			lost
		}
	});
	let (started, mut served) = (Instant::now(), 0);
	while started.elapsed() < Duration::from_millis(1500) {
		if let Ok(server) = veilway_api::serve(node.engine.clone(), ApiOptions {socket: path.clone(), config: node.file.clone(), limits: Limits::default()}) {
			served += 1;
			drop(server);
		}
		tokio::task::yield_now().await;
	}
	stop.store(true, Ordering::SeqCst);
	let lost = intruder.join().unwrap();
	assert!(served > 0, "the path was never free for the node, so this run says nothing");
	assert_eq!(lost, 0, "a file that was put at the socket path while the node started was replaced by its socket");
	// A node whose queue of connections is full is a node that answers: its socket is not taken for a dead one, and trying it does not hold the start up.
	#[cfg(target_os = "linux")]
	{
		let (full, listener) = (node.dir.join("full.sock"), Socket::new(Domain::UNIX, Type::STREAM, None).unwrap());
		listener.bind(&SockAddr::unix(&full).unwrap()).unwrap();
		listener.listen(1).unwrap();
		let mut waiting = Vec::new();
		loop {
			let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
			client.set_nonblocking(true).unwrap();
			match client.connect(&SockAddr::unix(&full).unwrap()) {
				Ok(()) => waiting.push(client),
				Err(e) => break assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
			}
			assert!(waiting.len() < 64, "the queue of the listener never filled");
		}
		let tried = tokio::task::spawn_blocking({
			let (engine, socket, config) = (node.engine.clone(), full.clone(), node.file.clone());
			move || veilway_api::serve(engine, ApiOptions {socket, config, limits: Limits::default()}).err().map(|e| e.kind())
		});
		let tried = timeout(Duration::from_secs(2), tried).await;
		let still = std::fs::symlink_metadata(&full).unwrap().file_type().is_socket();
		// A start that was held up by the full queue is let go by the listener going away.
		drop((listener, waiting));
		assert_eq!((tried.ok().map(|tried| tried.unwrap()), still), (Some(Some(std::io::ErrorKind::AddrInUse)), true), "a socket whose listener has a full queue held the start up, or was taken for a dead one");
	}
	eventually("a server that failed to start or was dropped still holds the engine", async || Arc::strong_count(&node.engine) == 2).await;
	node.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rates_follow_the_traffic_and_fall_back_to_zero() {
	let node = launch(setup().await).await;
	let rates = async |socket: &Path| {
		let stats = get(socket, "/v1/stats").await.json;
		(stats["users"][0]["up_bytes_per_sec"].as_u64().unwrap(), stats["users"][0]["down_bytes_per_sec"].as_u64().unwrap(), stats["inbounds"][0]["up_bytes_per_sec"].as_u64().unwrap(), stats["users"][1]["up_bytes_per_sec"].as_u64().unwrap(), stats["window_secs"].as_u64().unwrap())
	};
	assert_eq!(rates(&node.socket).await.0, 0);
	let mut a = Client::connect(node.keys[0], None, node.public, node.addr).await;
	// About 20 kB a second for three seconds, to a port the node refuses, which counts like any traffic and is answered with ICMP errors while the device's share of them lasts.
	let started = Instant::now();
	while started.elapsed() < Duration::from_secs(3) {
		for _ in 0..2 {a.send_ip(&ip_udp(PEER_A, [10, 7, 0, 1], 45000, 9, &[b'x'; 972])).await}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let (up, down, inbound, other, window) = rates(&node.socket).await;
	assert!(up > 4000 && up < 40000 && inbound >= up && down > 0 && other == 0 && (2..=5).contains(&window), "up {up}, down {down}, inbound {inbound}, another user {other}, over {window}s");
	let totals = get(&node.socket, "/v1/users/a").await.json["traffic"]["up_bytes"].as_u64().unwrap();
	assert!(totals >= 50000, "{totals}");
	// With the traffic gone the window empties, and the totals stay.
	tokio::time::sleep(Duration::from_secs(7)).await;
	let (up, down, inbound, _, window) = rates(&node.socket).await;
	assert_eq!((up, down, inbound, window), (0, 0, 0, 5));
	assert!(get(&node.socket, "/v1/users/a").await.json["traffic"]["up_bytes"].as_u64().unwrap() >= totals);
	node.end().await;
}

/// An outbound counts nothing itself. Exits `main` and `second` leave through the proxy, user `a` by the first and user `b` by the second, and `outbounds` of the stats has their sum: totals, rates, and what the two know of the proxy's UDP.
/// The outbound `spare` is one no exit uses, and the exit `sink` has no outbound and is counted under none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outbound_is_the_sum_of_the_exits_that_leave_through_it() {
	let mut setup = setup().await;
	setup.doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "spare", "type": "direct"}));
	setup.doc["exits"].as_array_mut().unwrap().push(json!({"tag": "second", "backend": {"type": "netstack", "outbound": "proxy"}}));
	setup.doc["routing"]["rules"].as_array_mut().unwrap().push(json!({"tag": "b-second", "user": ["b"], "action": {"exit": "second"}}));
	let node = launch(setup).await;
	let (mut a, mut b) = (Client::connect(node.keys[0], None, node.public, node.addr).await, Client::connect(node.keys[1], None, node.public, node.addr).await);
	// The exits are main, sink and second in the order of the config. What comes back is the proxy, the spare outbound, and whether every number of the proxy is the sum of the two exits in the same snapshot.
	let read = async |socket: &Path| {
		let stats = get(socket, "/v1/stats").await.json;
		let (main, second, proxy) = (&stats["exits"][0], &stats["exits"][2], &stats["outbounds"][0]);
		assert_eq!((stats["outbounds"].as_array().map(Vec::len), &stats["exits"][1]["name"], &proxy["name"]), (Some(2), &json!("sink"), &json!("proxy")), "{stats}");
		let sum = ["up_bytes", "up_packets", "down_bytes", "down_packets"].iter().all(|field| proxy["traffic"][field].as_u64().unwrap() == main["traffic"][field].as_u64().unwrap() + second["traffic"][field].as_u64().unwrap()) && ["up_bytes_per_sec", "down_bytes_per_sec"].iter().all(|field| proxy[field].as_u64().unwrap() == main[field].as_u64().unwrap() + second[field].as_u64().unwrap());
		assert!(sum, "{stats}");
		(proxy.clone(), stats["outbounds"][1].clone(), [main.clone(), second.clone()])
	};
	let unused = json!({"name": "spare", "traffic": {"up_bytes": 0, "up_packets": 0, "down_bytes": 0, "down_packets": 0}, "up_bytes_per_sec": 0, "down_bytes_per_sec": 0, "udp": null, "udp_down_secs": null, "udp_flips": 0});
	let (proxy, spare, _) = read(&node.socket).await;
	assert_eq!((&proxy["traffic"]["up_bytes"], &proxy["udp"], &proxy["udp_down_secs"], &proxy["udp_flips"], &spare), (&json!(0), &json!(true), &Value::Null, &json!(0), &unused), "{proxy}");
	// A new TCP flow through each exit every 200 ms for three seconds.
	let (started, mut port) = (Instant::now(), 41000);
	while started.elapsed() < Duration::from_secs(3) {
		assert_eq!((a.greeted(PEER_A, port).await, b.greeted(PEER_B, port).await), (GREETING.to_vec(), GREETING.to_vec()));
		port += 1;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	let (proxy, spare, exits) = read(&node.socket).await;
	assert!(exits.iter().all(|exit| exit["traffic"]["up_bytes"].as_u64().unwrap() > 0 && exit["traffic"]["down_bytes"].as_u64().unwrap() > 0 && exit["up_bytes_per_sec"].as_u64().unwrap() > 0) && proxy["down_bytes_per_sec"].as_u64().unwrap() > 0, "{exits:?}");
	assert_eq!(spare, unused);
	// The proxy relays no UDP, and the node learns that for each exit from the flows of that exit: first for `second` alone, which is enough for the outbound to say so, then for `main` as well.
	b.send_ip(&ip_udp(PEER_B, PUBLIC, 44003, 9999, b"datagram")).await;
	eventually("the outbound never said that its proxy relays no udp", async || read(&node.socket).await.0["udp"] == json!(false)).await;
	let (proxy, spare, listed) = (read(&node.socket).await.0, read(&node.socket).await.1, get(&node.socket, "/v1/exits").await.json);
	assert_eq!((&proxy["udp_flips"], proxy["udp_down_secs"].is_u64(), &listed["exits"][0]["udp"], &listed["exits"][2]["udp"], &spare), (&json!(1), true, &json!(true), &json!(false), &unused), "{proxy} {listed}");
	a.send_ip(&ip_udp(PEER_A, PUBLIC, 44004, 9999, b"datagram")).await;
	eventually("the outbound never counted the change of its other exit", async || read(&node.socket).await.0["udp_flips"] == json!(2)).await;
	// With the traffic gone the window empties, and the totals stay.
	let before = read(&node.socket).await.0["traffic"].clone();
	tokio::time::sleep(Duration::from_secs(7)).await;
	let (proxy, spare, _) = read(&node.socket).await;
	assert_eq!((&proxy["up_bytes_per_sec"], &proxy["down_bytes_per_sec"], &proxy["traffic"], &proxy["udp"], &spare), (&json!(0), &json!(0), &before, &json!(false), &unused), "{proxy}");
	node.end().await;
}

/// A user says which DNS set speaks for them: the one that names them, before the one that names a group of theirs. Null is a user who goes by the inbound a query comes through, and so is every user of a config without sets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_says_the_dns_set_that_names_them_or_their_group() {
	let mut setup = setup().await;
	setup.doc["groups"] = json!(["family"]);
	setup.doc["users"][0]["groups"] = json!(["family"]);
	setup.doc["users"][1]["groups"] = json!(["family"]);
	setup.doc["dns"]["hijack"] = json!(true);
	setup.doc["dns"]["sets"] = json!([{"tag": "family", "servers": ["1.1.1.3:53"], "groups": ["family"]}, {"tag": "own", "servers": ["9.9.9.9:53"], "users": ["a"]}, {"tag": "lab", "servers": ["9.9.9.10:53"], "inbounds": ["home"]}]);
	let node = launch(setup).await;
	let sets = async |socket: &Path| {
		let users = get(socket, "/v1/users").await.json;
		[0, 1, 2].map(|at| users["users"][at]["dns_set"].clone())
	};
	assert_eq!(sets(&node.socket).await, [json!("own"), json!("family"), Value::Null]);
	assert_eq!(get(&node.socket, "/v1/users/b").await.json["dns_set"], json!("family"));
	let (mut doc, revision) = node.shown().await;
	doc["dns"].as_object_mut().unwrap().remove("sets");
	let applied = send(&node.socket, "PUT", "/v1/config", Some(&revision), &doc).await;
	assert_eq!((applied.status, &applied.json["diff"]["dns"]), (200, &json!(true)), "{}", applied.json);
	assert_eq!(sets(&node.socket).await, [Value::Null, Value::Null, Value::Null]);
	node.end().await;
}

// Transports page, "When the floor is ahead of the clock": the reset "asks the running node, through the control socket, to empty its cache and set the floor and the limit to the wall clock plus `W`", and "touches nothing else, usage and quotas included".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replay_reset_is_written_before_it_is_answered_and_touches_no_usage() {
	let mut setup = setup().await;
	let (device, secret) = (veilway_wg::generate_key(), veilway_wg::generate_key());
	setup.doc["inbounds"].as_array_mut().unwrap().push(json!({"tag": "native", "type": "veilway", "private_key": encoded(&veilway_wg::generate_key()), "address": ["10.9.0.1/24"], "transports": [{"type": "udp-obfs", "listen": listen().to_string()}]}));
	setup.doc["users"].as_array_mut().unwrap().push(json!({"name": "n", "exits": "all", "quota_bytes": 1000, "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&device)), "transport_secrets": [veilway_wg::encode_key(&secret)], "addresses": ["10.9.0.2"]}]}));
	SECRETS.lock().unwrap().extend([setup.doc["inbounds"][1]["private_key"].as_str().unwrap().to_string(), veilway_wg::encode_key(&secret)]);
	let node = launch(setup).await;
	let (before, users) = (get(&node.socket, "/v1/stats").await.json["replay"].clone(), get(&node.socket, "/v1/users").await.json);
	// A node that never ran here: the file is made, and the floor is the clock plus the window.
	assert_eq!((&before["ready"], &before["floor_ahead"], before["refusing_secs"].as_u64().is_some_and(|secs| (1..=60).contains(&secs)), &before["entries"], &before["capacity"], &before["resets"]), (&json!(true), &json!(false), true, &json!(0), &json!(262144), &json!(0)), "{before}");
	assert_eq!(before["floor"].as_u64().unwrap(), before["limit"].as_u64().unwrap());
	let reset = call(&node.socket, "POST", "/v1/replay/reset", &[], None).await;
	assert_eq!((reset.status, &reset.json["ready"], &reset.json["resets"], &reset.json["entries"]), (200, &json!(true), &json!(1), &json!(0)), "{}", reset.json);
	assert!(reset.json["floor"].as_u64().unwrap() >= before["floor"].as_u64().unwrap() && reset.json["floor"] == reset.json["limit"] && reset.json["floor"] == reset.json["disk_limit"], "{}", reset.json);
	// What the answer says is what the file holds: a floor and a limit in big-endian behind the 16 bytes of its head.
	let file = std::fs::read(node.dir.join("replay")).unwrap();
	assert_eq!((file.len(), u64::from_be_bytes(file[16..24].try_into().unwrap()), u64::from_be_bytes(file[24..32].try_into().unwrap())), (68, reset.json["floor"].as_u64().unwrap(), reset.json["limit"].as_u64().unwrap()));
	assert_eq!(get(&node.socket, "/v1/users").await.json, users, "a replay reset changed what a user has used");
	no_secret_logged();
	node.end().await;
}

#[test]
fn the_openapi_document_has_every_route_and_nothing_dangling() {
	assert_eq!(OPENAPI["openapi"], json!("3.1.0"));
	let documented: Vec<(String, String)> = OPENAPI["paths"].as_object().unwrap().iter().flat_map(|(path, methods)| methods.as_object().unwrap().keys().map(move |method| (method.to_uppercase(), path.clone()))).collect();
	let mut wanted: Vec<(String, String)> = [("GET", "/v1/status"), ("GET", "/v1/config"), ("POST", "/v1/config/validate"), ("POST", "/v1/config/diff"), ("PUT", "/v1/config"), ("GET", "/v1/users"), ("GET", "/v1/users/{name}"), ("POST", "/v1/users/{name}/usage/reset"), ("POST", "/v1/replay/reset"), ("GET", "/v1/stats"), ("GET", "/v1/sessions"), ("GET", "/v1/exits"), ("GET", "/v1/links"), ("GET", "/v1/events"), ("GET", "/v1/openapi.json")].map(|(method, path)| (method.to_string(), path.to_string())).to_vec();
	wanted.sort_by(|a, b| (&a.1, &a.0).cmp(&(&b.1, &b.0)));
	assert_eq!(documented, wanted);
	let mut operations = BTreeSet::new();
	for (path, methods) in OPENAPI["paths"].as_object().unwrap() {
		for (method, operation) in methods.as_object().unwrap() {
			assert!(operations.insert(operation["operationId"].as_str().unwrap()) && operation["summary"].as_str().is_some_and(|summary| !summary.is_empty()), "{method} {path}");
			// Every route answers a success, a request that took too long and a node that is full, and every answer that is not a success has the one shape.
			for status in ["200", "408", "503"] {assert!(operation["responses"].get(status).is_some(), "{method} {path} has no {status}")}
			for (status, response) in operation["responses"].as_object().unwrap() {
				assert!(response["description"].as_str().is_some_and(|meaning| !meaning.is_empty()), "{method} {path} {status}");
				if status != "200" {assert_eq!(response["content"]["application/json"]["schema"], json!({"$ref": "#/components/schemas/ErrorBody"}), "{method} {path} {status}")}
			}
			let takes = |name: &str, place: &str| operation["parameters"].as_array().unwrap().iter().any(|parameter| parameter["name"] == name && parameter["in"] == place && parameter["required"] == true);
			// A reset of the replay memory is the one request that changes something and has nothing to say: there is one replay memory and one thing a reset does to it.
			assert_eq!((takes("name", "path"), takes("If-Match", "header"), operation.get("requestBody").is_some()), (path.contains("{name}"), method == "put", method != "get" && path != "/v1/replay/reset"), "{method} {path}");
		}
	}
	for status in ["409", "422", "428", "400", "413", "415"] {assert!(OPENAPI["paths"]["/v1/config"]["put"]["responses"].get(status).is_some(), "an apply has no {status}")}
	assert!(OPENAPI["paths"]["/v1/users/{name}"]["get"]["responses"].get("404").is_some());
	let reset = &OPENAPI["paths"]["/v1/users/{name}/usage/reset"]["post"];
	for status in ["404", "422", "400", "413", "415"] {assert!(reset["responses"].get(status).is_some(), "a usage reset has no {status}")}
	assert_eq!((&reset["requestBody"]["required"], &reset["requestBody"]["content"]["application/json"]["schema"], &OPENAPI["components"]["schemas"]["ResetUsage"]["required"]), (&json!(false), &json!({"$ref": "#/components/schemas/ResetUsage"}), &Value::Null));
	assert_eq!(OPENAPI["paths"]["/v1/events"]["get"]["responses"]["200"]["content"].as_object().unwrap().keys().collect::<Vec<_>>(), ["text/event-stream"]);
	assert_eq!(OPENAPI["x-events"].as_object().unwrap().keys().map(String::as_str).collect::<Vec<_>>(), ["config_applied", "config_refused", "exit_udp_changed", "lagged", "stats", "usage_reset", "user_cut_off", "user_restored"]);
	// Every reference leads to a schema, and no schema has a place for a secret.
	let text = OPENAPI.to_string();
	for reference in text.split("\"$ref\":\"").skip(1).map(|rest| &rest[..rest.find('"').unwrap()]) {
		assert!(OPENAPI.pointer(reference.trim_start_matches('#')).is_some(), "{reference} leads nowhere");
	}
	for schema in OPENAPI["components"]["schemas"].as_object().unwrap().values() {
		for secret in ["private_key", "preshared_key", "username", "password"] {assert!(schema["properties"].get(secret).is_none(), "a schema has a field for a {secret}")}
	}
}

#[test]
fn the_committed_openapi_document_is_what_the_code_produces() {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("openapi.json");
	if std::env::var_os("VEILWAY_WRITE_OPENAPI").is_some() {std::fs::write(&path, veilway_api::openapi()).unwrap()}
	let committed = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
	assert!(committed == veilway_api::openapi(), "crates/veilway-api/openapi.json is out of date. Write it again with: VEILWAY_WRITE_OPENAPI=1 cargo test -p veilway-api --test api the_committed");
}
