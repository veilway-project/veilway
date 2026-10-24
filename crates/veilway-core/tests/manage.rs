//! Management through node links end to end (threat model 5.19): two engines in one process, joined by a link over `udp-obfs` and over `tls` in either direction, with the control API of the real crate on one or both. The node that manages calls the other's API through its own socket, `/v1/links/far/api/...`.
//! Where a test needs a hostile node, the test is that node: a WireGuard of its own on the client's side of the transports. Where it needs a control API that misbehaves, the test is that API: it takes the streams of `Engine::managed` and answers them as it likes.
//! The node that dials reaches the other on an address of this host that is not loopback: validation never lets a link dial loopback.
#![cfg(unix)]
#[macro_use]
mod proxied;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, TcpHeader};
use proxied::*;
use rcgen::PublicKeyData;
use ring::digest::{digest, SHA256};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use veilway_api::{Limits, Options as ApiOptions, Server};
use veilway_core::engine::link::Status;
use veilway_core::engine::manage::{self, Error};
use veilway_core::{Engine, Options};
use veilway_proto::subscription::payload::Padding;
use veilway_proto::subscription::Secret;
use veilway_transport::{Env, Kind, Link as Leg, Session, Source, State, Target, Want};

const ENTRY: [u8; 32] = [0x11; 32];
const EXIT: [u8; 32] = [0x12; 32];
/// The inbound of the entry that a reverse link connects to, which carries links alone.
const RECEIVER: [u8; 32] = [0x13; 32];
const USER: [u8; 32] = [0x21; 32];
/// The WireGuard key the dialling node made for the link, and the secret the pairing gave.
const DIALLER: [u8; 32] = [0x31; 32];
const OTHER: [u8; 32] = [0x32; 32];
const SECRET: [u8; 32] = [0x41; 32];
const OTHER_SECRET: [u8; 32] = [0x42; 32];
const NODE_KEY: [u8; 32] = [0x51; 32];
const LINK_ID: &str = "AAECAwQFBgcICQoLDA0ODw";
const OTHER_ID: &str = "AQECAwQFBgcICQoLDA0ODw";
const PATH: &str = "/assets/app-3f9c2e71.js";
const USER_ADDRESS: [u8; 4] = [10, 7, 0, 2];
/// The link's addresses: the dialler's, and the listener's.
const DIALLER_AT: [u8; 4] = [10, 9, 0, 2];
const LISTENER_AT: [u8; 4] = [10, 9, 0, 3];
const MANAGE: u16 = 47874;

fn outward() -> IpAddr {
	let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
	socket.connect("192.0.2.1:9").expect("this host has no address but loopback, and a link never dials loopback");
	socket.local_addr().unwrap().ip()
}

fn port() -> u16 {listen().port()}

fn certify(dir: &Path) -> ([u8; 32], Arc<RootCertStore>) {
	let (made, _) = (rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap(), std::fs::create_dir_all(dir));
	for (name, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
		std::fs::write(dir.join(name), pem).unwrap();
		std::fs::set_permissions(dir.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
	let mut roots = RootCertStore::empty();
	roots.add(CertificateDer::from(made.cert.der().to_vec())).unwrap();
	(digest(&SHA256, &made.signing_key.subject_public_key_info()).as_ref().try_into().unwrap(), Arc::new(roots))
}

#[derive(Clone, Copy, PartialEq)]
enum Over {Obfs, Tls}

/// The two halves of one managed link. `forward`: the entry dials the exit. `node1_entry`: the entry is the node that manages, and the exit is the managed one.
#[derive(Clone)]
struct Pair {forward: bool, over: Over, at: SocketAddr, pin: [u8; 32], origin: SocketAddr, node1_entry: bool}

impl Pair {
	fn transports(&self) -> Value {
		match self.over {
			Over::Obfs => json!([{"type": "udp-obfs", "endpoints": [self.at.to_string()]}]),
			Over::Tls => json!([{"type": "tls", "path": PATH, "candidates": [{"address": self.at.to_string(), "sni": "node.test", "host": "node.test", "pins": [text(&self.pin)]}]}]),
		}
	}

	fn inbound(&self, key: &[u8; 32]) -> Value {
		let transport = match self.over {
			Over::Obfs => json!({"type": "udp-obfs", "listen": self.at.to_string()}),
			Over::Tls => json!({"type": "tls", "listen": self.at.to_string(), "path": PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": format!("http://{}", self.origin)}}),
		};
		let mut inbound = json!({"tag": "links", "type": "veilway", "private_key": text(key), "address": ["10.9.0.1/24"], "transports": [transport]});
		if self.over == Over::Tls {(inbound["transport_keys"], inbound["upgrade_cookie"]) = (json!([text(&NODE_KEY)]), json!("sid"))}
		inbound
	}

	/// The link as one node writes it. A managed link has both addresses, whatever its direction, and `peer` on the node that manages.
	fn link(&self, entry: bool) -> Value {
		let mut link = json!({"tag": "far", "id": LINK_ID, "direction": if self.forward {"forward"} else {"reverse"}, "addresses": {"dialler": ["10.9.0.2"], "listener": ["10.9.0.3"]}, "manage": if entry == self.node1_entry {"peer"} else {"by_peer"}, "transport_secret": text(&SECRET)});
		if entry != self.forward {(link["inbound"], link["public_key"]) = (json!("links"), json!(text(&public(&DIALLER))))} else {
			(link["private_key"], link["peer"]) = (json!(text(&DIALLER)), json!({"inbound_public_key": text(&public(if self.forward {&EXIT} else {&RECEIVER})), "transports": self.transports()}));
			if self.over == Over::Tls {link["peer"]["transport_public_key"] = json!(text(&veilway_proto::proof::public_key(&NODE_KEY)))}
		}
		if !entry {link["exits"] = json!(["main"])}
		link
	}

	fn entry(&self, home: SocketAddr) -> Value {
		let mut inbounds = vec![json!({"tag": "home", "type": "wireguard", "private_key": text(&ENTRY), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": home.to_string()}]})];
		if !self.forward {inbounds.push(self.inbound(&RECEIVER))}
		json!({
			"version": 1, "dns": {"servers": ["1.1.1.1:53"]}, "inbounds": inbounds,
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "far", "backend": {"type": "chain", "links": ["far"]}}, {"tag": "near", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "far", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
			"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": text(&public(&USER)), "addresses": ["10.7.0.2"]}]}],
			"links": [self.link(true)]
		})
	}

	fn exit(&self, proxy: SocketAddr) -> Value {
		json!({
			"version": 1, "dns": {"servers": ["1.1.1.1:53"]}, "inbounds": if self.forward {vec![self.inbound(&EXIT)]} else {Vec::new()},
			"outbounds": [{"tag": "proxy", "type": "socks5", "server": proxy.to_string()}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "proxy"}}],
			"routing": {"default": "main", "rules": [{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
			"users": [],
			"links": [self.link(false)]
		})
	}

	/// The document of the node that manages and of the one that is managed.
	fn docs(&self, home: SocketAddr, proxy: SocketAddr) -> (Value, Value) {if self.node1_entry {(self.entry(home), self.exit(proxy))} else {(self.exit(proxy), self.entry(home))}}
}

async fn run(doc: &Value, dir: &Path, time: Time, roots: &Arc<RootCertStore>) -> Arc<Engine> {
	let _ = (std::fs::create_dir_all(dir), tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_test_writer().try_init());
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	std::fs::write(dir.join("config.json"), format!("{doc:#}\n")).unwrap();
	let config = parsed(doc);
	Arc::new(veilway_core::start(&config, Options {now: time.now, replay: Some(dir.join("replay")), roots: Some(roots.clone()), ..Options::new(dir)}).await.unwrap_or_else(|e| panic!("the node did not start: {e:#}")))
}

fn serve(engine: &Arc<Engine>, dir: &Path, limits: Limits) -> Server {veilway_api::serve(engine.clone(), ApiOptions {socket: dir.join("veilway.sock"), config: dir.join("config.json"), limits}).expect("the control API did not start")}

enum Carrier {Udp(UdpSocket), Session(Session)}

/// A WireGuard of the test and what carries it: the user's device, or a node of the test's own at the other end of a link.
struct Peer {tunn: Arc<Mutex<Tunn>>, up: Arc<AtomicBool>, carrier: Carrier, inbox: VecDeque<Vec<u8>>, from: [u8; 4]}

impl Peer {
	async fn device(key: &[u8; 32], node_key: &[u8; 32], node: SocketAddr, from: [u8; 4]) -> Peer {
		let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		socket.connect(node).await.unwrap();
		let mut peer = Peer {tunn: Arc::new(Mutex::new(Tunn::new(StaticSecret::from(*key), PublicKey::from(public(node_key)), None, None, 0, None))), up: Arc::default(), carrier: Carrier::Udp(socket), inbox: VecDeque::new(), from};
		let mut out = vec![0u8; 2048];
		let TunnResult::WriteToNetwork(init) = peer.tunn.lock().unwrap().format_handshake_initiation(&mut out, false) else {panic!("no initiation")};
		let init = init.to_vec();
		peer.put(init).await;
		peer
	}

	/// A node of the test that holds a link to a real one over `udp-obfs` at `at`, as the link `key`, and sends from `from` in the link.
	fn node(key: &[u8; 32], node_key: &[u8; 32], at: SocketAddr, from: [u8; 4], time: Time) -> Peer {Peer::node_with(key, node_key, &SECRET, at, from, time)}

	fn node_with(key: &[u8; 32], node_key: &[u8; 32], secret: &[u8; 32], at: SocketAddr, from: [u8; 4], time: Time) -> Peer {
		let (tunn, up) = (Arc::new(Mutex::new(Tunn::new(StaticSecret::from(*key), PublicKey::from(public(node_key)), None, None, 0, None))), Arc::new(AtomicBool::new(false)));
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
		let leg = Leg {inbound: public(node_key), device: public(key), secret: Secret::new(*secret), node: None, mtu: 1390, padding: Padding {wide_max: 1023, normal_max: 255, keepalive: 20_000..=40_000}, borrowed: Default::default()};
		let env = Env {device: Arc::new(move || time.secs()), now: Arc::new(move || time.secs()), roots: Arc::new(RootCertStore::empty()), socket: None};
		Peer {tunn, up, carrier: Carrier::Session(Session::open(&leg, Target::UdpObfs(at), env, source).unwrap()), inbox: VecDeque::new(), from}
	}

	async fn put(&mut self, datagram: Vec<u8>) {
		match &self.carrier {
			Carrier::Udp(socket) => drop(socket.send(&datagram).await),
			Carrier::Session(session) => drop(session.send(datagram, Kind::Packet {flow: 0, control: false})),
		}
	}

	async fn get(&mut self) -> Option<Vec<u8>> {
		match &mut self.carrier {
			Carrier::Udp(socket) => {
				let mut buf = vec![0u8; 2048];
				let n = socket.recv(&mut buf).await.ok()?;
				buf.truncate(n);
				Some(buf)
			}
			Carrier::Session(session) => session.recv().await.ok(),
		}
	}

	async fn take(&mut self, datagram: &[u8]) -> Vec<Vec<u8>> {
		let (mut input, mut packets) = (datagram.to_vec(), Vec::new());
		loop {
			let mut out = vec![0u8; 2048];
			let (reply, packet) = match self.tunn.lock().unwrap().decapsulate(None, &input, &mut out) {
				TunnResult::WriteToNetwork(reply) => (Some(reply.to_vec()), None),
				TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => (None, Some(packet.to_vec())),
				_ => (None, None),
			};
			packets.extend(packet);
			let Some(reply) = reply else {return packets};
			if datagram.first() == Some(&2) {self.up.store(true, Ordering::SeqCst)}
			self.put(reply).await;
			input = Vec::new();
		}
	}

	async fn connect(&mut self) {
		let deadline = Instant::now() + Duration::from_secs(20);
		while !self.up.load(Ordering::SeqCst) {
			if matches!(&self.carrier, Carrier::Session(session) if matches!(session.state(), State::Ended(_))) {panic!("the session of the test's node ended")}
			assert!(Instant::now() < deadline, "no handshake in 20 s");
			if let Ok(Some(datagram)) = timeout(Duration::from_millis(200), self.get()).await {
				let packets = self.take(&datagram).await;
				self.inbox.extend(packets);
			}
		}
	}

	async fn send(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let datagram = match self.tunn.lock().unwrap().encapsulate(packet, &mut out) {
			TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
			_ => panic!("the tunnel has no session to send under"),
		};
		self.put(datagram).await;
	}

	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let datagram = timeout(deadline.checked_duration_since(Instant::now())?, self.get()).await.ok()??;
			let mut found = None;
			for packet in self.take(&datagram).await {
				if found.is_none() && wanted(&packet) {found = Some(packet)} else {self.inbox.push_back(packet)}
			}
			if found.is_some() {return found}
		}
	}

	/// A TCP connection to `to`:80 from the tunnel address, and what the far side says first. None when the SYN gets no answer that opens it.
	async fn leaves(&mut self, to: [u8; 4], sport: u16) -> Option<String> {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(self.from, to, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (answer, _) = segment(&self.recv(4 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (80, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		let (mut ack, mut out) = (TcpHeader::new(sport, 80, 1001, 65535), Vec::new());
		(ack.ack, ack.acknowledgment_number) = (true, answer.sequence_number.wrapping_add(1));
		PacketBuilder::ipv4(self.from, to, 64).tcp_header(ack).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		let (_, said) = segment(&self.recv(Duration::from_secs(6), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (80, sport) && !data.is_empty())).await?)?;
		Some(String::from_utf8(said).unwrap())
	}

	/// What answers a SYN from `from`:`sport` to `to`:`dport` within `budget`: a reset, an ICMP error, a SYN-ACK, or nothing.
	async fn syn(&mut self, from: [u8; 4], to: [u8; 4], sport: u16, dport: u16, budget: Duration) -> Option<Vec<u8>> {
		let (mut syn, mut out) = (TcpHeader::new(sport, dport, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(from, to, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		self.recv(budget, |packet| packet[9] == 1 || segment(packet).is_some_and(|(tcp, _)| tcp.destination_port == sport)).await
	}
}

/// Whether `packet` is the SYN-ACK of an opened connection.
fn opened(packet: &[u8]) -> bool {segment(packet).is_some_and(|(tcp, _)| tcp.syn && tcp.ack)}

fn reset(packet: &[u8]) -> bool {segment(packet).is_some_and(|(tcp, _)| tcp.rst)}

/// Two nodes with a managed link between them. Node 1 manages. `user` is alice's device on the entry, when the entry is node 1.
struct Net {node1: Arc<Engine>, remote: Option<Arc<Engine>>, node1_api: Option<Server>, remote_api: Option<Server>, node1_dir: PathBuf, remote_dir: PathBuf, pair: Pair, home: SocketAddr, user: Option<Peer>, remote_doc: Value, roots: Arc<RootCertStore>, time: Time, trial: Duration, renew: Duration, settle: Duration, _site: Site}

/// What `up` is asked for: the link's direction and transport, whether node 1 is the entry, whether the control API runs, the timers of a pushed config on trial on the remote (how long it is on trial, when its session is renewed, and how soon after the push a request may confirm it), how many relays node 1 runs at once, and whether the remote starts at all.
struct Setup {forward: bool, over: Over, node1_entry: bool, api: bool, trial: Duration, renew: Duration, settle: Duration, relays: usize, remote: bool, change: fn(&mut Value)}

impl Setup {
	fn new(forward: bool, over: Over, node1_entry: bool) -> Setup {Setup {forward, over, node1_entry, api: true, trial: Duration::from_secs(120), renew: Duration::from_secs(1), settle: Duration::from_secs(2), relays: 8, remote: true, change: |_| {}}}
}

async fn up(test: &'static str, want: Setup, time: Time) -> Net {
	let (dir, site) = (scratch(test), site().await);
	let (node1_dir, remote_dir) = (dir.join("node1"), dir.join("remote"));
	// The node that is dialled starts first, so the first dial finds it. In a forward link that is the exit, in a reverse one the entry. Its directory holds the certificate of its `tls` transport.
	let node1_dialled = if want.node1_entry {!want.forward} else {want.forward};
	let (pin, roots) = certify(if node1_dialled {&node1_dir} else {&remote_dir});
	let (home, pair) = (listen(), Pair {forward: want.forward, over: want.over, at: SocketAddr::new(outward(), port()), pin, origin: site.addr, node1_entry: want.node1_entry});
	let (node1_doc, mut remote_doc) = pair.docs(home, socks().await);
	(want.change)(&mut remote_doc);
	let (node1, remote) = if node1_dialled {
		let node1 = run(&node1_doc, &node1_dir, time, &roots).await;
		let remote = if want.remote {Some(run(&remote_doc, &remote_dir, time, &roots).await)} else {None};
		(node1, remote)
	} else {
		let remote = if want.remote {Some(run(&remote_doc, &remote_dir, time, &roots).await)} else {None};
		(run(&node1_doc, &node1_dir, time, &roots).await, remote)
	};
	let node1_api = want.api.then(|| serve(&node1, &node1_dir, Limits {request: Duration::from_secs(8), relays: want.relays, ..Limits::default()}));
	let remote_api = remote.as_ref().filter(|_| want.api).map(|remote| serve(remote, &remote_dir, Limits {trial: want.trial, renew: want.renew, settle: want.settle, ..Limits::default()}));
	let mut net = Net {node1, remote, node1_api, remote_api, node1_dir, remote_dir, pair, home, user: None, remote_doc, roots, time, trial: want.trial, renew: want.renew, settle: want.settle, _site: site};
	if want.remote {net.arrive().await}
	net
}

impl Net {
	fn remote(&self) -> &Arc<Engine> {self.remote.as_ref().expect("the remote is not started")}

	fn socket(&self, remote: bool) -> PathBuf {(if remote {&self.remote_dir} else {&self.node1_dir}).join("veilway.sock")}

	/// Waits until both nodes report the link up, and opens alice's device when node 1 is the entry.
	async fn arrive(&mut self) {
		for (node, name) in [(&self.node1, "node 1"), (self.remote(), "the remote")] {
			let deadline = Instant::now() + Duration::from_secs(90);
			while node.links()[0].status != Status::Up {
				assert!(Instant::now() < deadline, "the link is not up at {name} after 90 s: {:?}", node.links());
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}
		if self.pair.node1_entry && self.user.is_none() {
			let mut user = Peer::device(&USER, &ENTRY, self.home, USER_ADDRESS).await;
			user.connect().await;
			self.user = Some(user);
		}
	}

	/// Starts the remote of a net that was started without it, with its control API.
	async fn start_remote(&mut self) {
		let remote = run(&self.remote_doc, &self.remote_dir, self.time, &self.roots).await;
		self.remote_api = Some(serve(&remote, &self.remote_dir, Limits {trial: self.trial, renew: self.renew, settle: self.settle, ..Limits::default()}));
		self.remote = Some(remote);
		self.arrive().await;
	}

	async fn end(mut self) {
		for server in [self.node1_api.take(), self.remote_api.take()].into_iter().flatten() {server.shutdown().await}
		drop(self.user.take());
		if let Some(remote) = self.remote.take() {Arc::try_unwrap(remote).ok().expect("something still holds the remote").shutdown().await}
		Arc::try_unwrap(self.node1).ok().expect("something still holds node 1").shutdown().await;
	}
}

/// One request on the socket at `socket`: the status and the answer as JSON (null when it is not).
async fn call(socket: &Path, method: &str, path: &str, headers: &[(&str, &str)], body: Option<Vec<u8>>) -> (u16, Value) {
	let (status, bytes) = veilway_api::request_with(socket, method, path, headers, body, Duration::from_secs(100)).await.unwrap_or_else(|e| panic!("{method} {path}: {e}"));
	(status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A request through the link `far` of the node whose socket is `socket`, to the other node's `path`.
async fn relay(socket: &Path, method: &str, path: &str, headers: &[(&str, &str)], body: Option<Vec<u8>>) -> (u16, Value) {call(socket, method, &format!("/v1/links/far/api{path}"), headers, body).await}

/// GET through the link until it answers 200, which it does once the link is up again after a push. The answer is the body of the first 200.
async fn settled(socket: &Path, path: &str) -> Value {
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		let (status, answer) = relay(socket, "GET", path, &[], None).await;
		if status == 200 {return answer}
		assert!(Instant::now() < deadline, "GET {path} through the link did not answer 200 in 30 s: {status} {answer}");
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

/// The whole answer to one GET on the socket at `socket`, with its status line and headers as they came.
async fn raw(socket: &Path, path: &str) -> String {
	let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
	stream.write_all(format!("GET {path} HTTP/1.1\r\nhost: veilway\r\nconnection: close\r\n\r\n").as_bytes()).await.unwrap();
	let mut answer = String::new();
	stream.read_to_string(&mut answer).await.unwrap();
	answer
}

/// Starts a node again from the document `doc` on the files of `dir`, as a restart does. The UDP port of a node that was stopped in this process is not let go, so the caller moves the listener of the link to a port that is free.
async fn restarted(doc: &Value, dir: &Path, time: Time, roots: &Arc<RootCertStore>) -> Arc<Engine> {
	let config = parsed(doc);
	Arc::new(veilway_core::start(&config, Options {now: time.now, replay: Some(dir.join("replay")), roots: Some(roots.clone()), ..Options::new(dir)}).await.unwrap_or_else(|e| panic!("the node did not start again: {e:#}")))
}

fn code(answer: &Value) -> &str {answer["error"]["code"].as_str().unwrap_or("")}

fn ask(method: &str, path: &str, body: Vec<u8>) -> manage::Request {manage::Request {method: method.to_string(), path: path.to_string(), query: None, if_match: None, content_type: Some("application/json".to_string()), body, within: Duration::from_secs(100)}}

/// What every direction and transport must do: the other node's own answers come through the link, a config is read and replaced with its revision, and the counters of both sides say so.
async fn works(test: &'static str, forward: bool, over: Over, node1_entry: bool) {
	let net = up(test, Setup {trial: Duration::from_secs(8), ..Setup::new(forward, over, node1_entry)}, time!()).await;
	let (mine, theirs) = (net.socket(false), net.socket(true));
	let (status, through) = relay(&mine, "GET", "/v1/status", &[], None).await;
	let (_, direct) = call(&theirs, "GET", "/v1/status", &[], None).await;
	assert_eq!(status, 200, "{through}");
	assert_eq!((&through["revision"], &through["generation"], &through["version"]), (&direct["revision"], &direct["generation"], &json!(env!("CARGO_PKG_VERSION"))), "the answer is not the remote's own");
	let own = call(&mine, "GET", "/v1/status", &[], None).await.1;
	assert_ne!((&through["inbounds"], &through["users"], &through["exits"]), (&own["inbounds"], &own["users"], &own["exits"]), "the answer is node 1's own: {through} {own}");
	let (status, config) = relay(&mine, "GET", "/v1/config", &[], None).await;
	assert_eq!(status, 200, "{config}");
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	// Secrets come redacted and are put back from the running config, as the panel's sync does.
	assert!(config.to_string().contains("<redacted>"), "{config}");
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"], &applied["saved"]), (200, &json!(2), &json!(true)), "{applied}");
	// The link makes its session again after the push, and a request from the settle time on, over that session, confirms the config: it is still the new one after the trial would have ended.
	tokio::time::sleep(Duration::from_secs(3)).await;
	let after = settled(&mine, "/v1/status").await;
	assert_eq!(after["revision"], applied["revision"]);
	tokio::time::sleep(Duration::from_secs(6)).await;
	assert_eq!((net.remote().snapshot().generation, net.remote().snapshot().config.dns.servers.len()), (2, 1), "a confirmed config was put back");
	// A stale revision is the remote's own refusal, with its code, through the link.
	let (status, stale) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, code(&stale)), (409, "stale_revision"), "{stale}");
	let (sent, taken) = (net.node1.links()[0].management, net.remote().links()[0].management);
	assert!(sent.opened >= 5 && taken.opened >= 5 && sent.up_bytes > 0 && taken.up_bytes > 0 && sent.down_bytes > 0 && taken.down_bytes > 0, "{sent:?} {taken:?}");
	assert_eq!((sent.refused, taken.refused, sent.failed, taken.failed), (0, 0, 0, 0), "{sent:?} {taken:?}");
	// Management is in the link's traffic and nowhere else: the remote has no flow, and node 1 charges no user.
	assert!(net.node1.links()[0].traffic.up_packets > 5 && net.remote().links()[0].traffic.down_packets > 5);
	assert_eq!((net.node1.links()[0].flows, net.remote().links()[0].flows), (0, 0));
	assert!(net.node1.usage("alice").is_none_or(|usage| usage.used_bytes == 0), "management was charged to a user");
	net.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_1_dialling_over_udp_obfs_calls_the_exit_it_manages() {works("manage-fwd-obfs", true, Over::Obfs, true).await}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_1_dialled_over_tls_calls_the_exit_it_manages() {works("manage-rev-tls", false, Over::Tls, true).await}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_1_the_exit_dialling_over_tls_calls_the_entry_it_manages() {works("manage-exit-fwd-tls", true, Over::Tls, false).await}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_1_the_exit_dialled_over_udp_obfs_calls_the_entry_it_manages() {works("manage-exit-rev-obfs", false, Over::Obfs, false).await}

/// What a stand-in for a control API does with a request: answers it with these bytes, answers it with a body of this many bytes, or keeps the connection open and says nothing.
enum Reply {Raw(Vec<u8>), Hold, Length(usize)}

/// A control API that is no control API: it takes the streams the node hands over, `script` is given the path and the length of the body of each request, and `seen` has the request lines. `held` counts the connections it keeps.
struct Standing {seen: Arc<Mutex<Vec<String>>>, held: Arc<AtomicUsize>, task: JoinHandle<()>}

fn stand_in(engine: &Engine, script: fn(&str, usize) -> Reply) -> Standing {
	let (mut streams, seen, held) = (engine.managed(), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicUsize::new(0)));
	let task = tokio::spawn({
		let (seen, held) = (seen.clone(), held.clone());
		async move {
			while let Some(managed) = streams.recv().await {
				let (seen, held) = (seen.clone(), held.clone());
				tokio::spawn(async move {
					let (mut stream, mut buf, mut chunk) = (managed.stream, Vec::new(), vec![0u8; 16384]);
					let end = loop {
						if let Some(at) = buf.windows(4).position(|window| window == b"\r\n\r\n") {break at}
						match stream.read(&mut chunk).await {Ok(0) | Err(_) => return, Ok(n) => buf.extend_from_slice(&chunk[..n])}
					};
					let head = String::from_utf8_lossy(&buf[..end]).to_string();
					let line = head.lines().next().unwrap().to_string();
					let length = head.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|digits| digits.parse::<usize>().ok())).unwrap_or(0);
					let mut have = buf.len() - end - 4;
					while have < length {
						match stream.read(&mut chunk).await {Ok(0) | Err(_) => return, Ok(n) => have += n}
					}
					seen.lock().unwrap().push(line.clone());
					match script(line.split(' ').nth(1).unwrap_or(""), length) {
						Reply::Raw(bytes) => drop(stream.write_all(&bytes).await),
						Reply::Length(n) => {
							let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {n}\r\n\r\n").as_bytes()).await;
							let _ = stream.write_all(&vec![b'x'; n]).await;
						}
						Reply::Hold => {
							held.fetch_add(1, Ordering::SeqCst);
							while stream.read(&mut chunk).await.is_ok_and(|n| n > 0) {}
							held.fetch_sub(1, Ordering::SeqCst);
						}
					}
					let _ = stream.shutdown().await;
				});
			}
		}
	});
	Standing {seen, held, task}
}

// "User traffic on the link is not slowed by management (tested with a 4 MiB transfer)."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_4_mib_transfer_each_way_leaves_a_users_traffic_and_the_flow_table_alone() {
	let mut net = up("manage-4mib", Setup {api: false, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let standing = stand_in(net.remote(), |path, length| if path == "/echo" {Reply::Raw(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{length}", length.to_string().len()).into_bytes())} else {Reply::Length(manage::BODY)});
	assert_eq!(net.user.as_mut().unwrap().leaves(PUBLIC, 40000).await.as_deref(), Some("main"));
	let (flows, far, used) = (net.node1.flows(), net.remote().links()[0].flows, net.node1.usage("alice").unwrap().used_bytes);
	let started = Instant::now();
	let sent = net.node1.manage("far", ask("POST", "/echo", vec![b'a'; manage::BODY])).await.expect("a 4 MiB request was not carried");
	let up_took = started.elapsed();
	assert_eq!((sent.status, String::from_utf8_lossy(&sent.body).to_string()), (200, manage::BODY.to_string()));
	let started = Instant::now();
	let taken = net.node1.manage("far", ask("GET", "/big", Vec::new())).await.expect("a 4 MiB answer was not carried");
	let down_took = started.elapsed();
	assert_eq!((taken.status, taken.body.len(), taken.body.iter().all(|byte| *byte == b'x')), (200, manage::BODY, true));
	println!("4 MiB request through the link: {up_took:?}, 4 MiB answer: {down_took:?}");
	assert_eq!((net.node1.flows(), net.node1.usage("alice").unwrap().used_bytes), (flows, used), "management took a place in the flow table or was charged to the user");
	assert_eq!(net.remote().links()[0].flows, far, "management took a place in the flows of the link");
	// A user's flow while a transfer runs: it opens and answers within its own few seconds.
	let node1 = net.node1.clone();
	let (carried, user_flow) = tokio::join!(node1.manage("far", ask("GET", "/big", Vec::new())), net.user.as_mut().unwrap().leaves(PUBLIC, 40001));
	drop(node1);
	assert!(carried.is_ok(), "{:?}", carried.map(|answer| answer.status));
	assert_eq!(user_flow.as_deref(), Some("main"), "a user's flow did not open while a transfer ran");
	assert_eq!(standing.seen.lock().unwrap().len(), 3);
	standing.task.abort();
	net.end().await;
}

// "Answered at once, no packet sent."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_is_down_answers_link_down_at_once_and_works_when_it_is_up() {
	let mut net = up("manage-down", Setup {remote: false, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let socket = net.socket(false);
	let started = Instant::now();
	let (status, answer) = relay(&socket, "GET", "/v1/status", &[], None).await;
	assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
	assert_eq!((status, code(&answer)), (503, "link_down"), "{answer}");
	assert!(answer["error"]["details"].as_array().unwrap().iter().any(|detail| detail["path"] == "status"), "{answer}");
	let direct = net.node1.manage("far", ask("GET", "/v1/status", Vec::new())).await;
	assert!(matches!(direct, Err(Error::Down {..})), "{direct:?}");
	assert_eq!(net.node1.links()[0].management.opened, 0, "a packet was sent for a link that is down");
	assert_eq!(call(&socket, "GET", "/v1/links/nobody/api/v1/status", &[], None).await.0, 404);
	// The other node comes up, and the link with it, with no action of anyone: the same request works.
	net.start_remote().await;
	assert_eq!(relay(&socket, "GET", "/v1/status", &[], None).await.0, 200);
	assert!(net.node1.links()[0].management.opened >= 1);
	net.end().await;
}

/// One node of a managed pair that is dialled over `udp-obfs`, on its own, for a test whose other node is the test itself: the node that manages (`remote` false) or the one that is managed. `change` edits its document before it starts.
async fn alone(test: &'static str, node1_entry: bool, remote: bool, change: fn(&mut Value), time: Time) -> (Arc<Engine>, Pair, PathBuf, Site) {
	let (dir, site) = (scratch(test), site().await);
	let pair = Pair {forward: true, over: Over::Obfs, at: SocketAddr::new(outward(), port()), pin: [0; 32], origin: site.addr, node1_entry};
	let (node1_doc, remote_doc) = pair.docs(listen(), socks().await);
	let mut doc = if remote {remote_doc} else {node1_doc};
	change(&mut doc);
	(run(&doc, &dir, time, &Arc::new(RootCertStore::empty())).await, pair, dir, site)
}

// "Node 1 opens connections and never accepts one: it has no listener, and a SYN from the remote to node 1's link address is dropped as any other packet to a link address is."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managed_node_cannot_open_a_management_connection_to_node_1() {
	let time = time!();
	let (node1, pair, _, _site) = alone("manage-hostile-remote", false, false, |_| {}, time).await;
	assert_eq!(node1.links()[0].manage, Some(veilway_core::config::LinkManage::Peer));
	let mut remote = Peer::node(&DIALLER, &EXIT, pair.at, DIALLER_AT, time);
	remote.connect().await;
	for (sport, dport) in [(40000, MANAGE), (40001, 80), (40002, MANAGE)] {
		let answer = remote.syn(DIALLER_AT, LISTENER_AT, sport, dport, SECOND).await;
		assert!(!answer.as_deref().is_some_and(opened), "node 1 took a connection to {dport} from the node it manages");
	}
	let counted = node1.links()[0].management;
	assert_eq!((counted.refused, counted.opened, counted.open), (3, 0, 0), "{counted:?}");
	// It does not take one from another address either, and a connection opened by node 1 is not a way back in.
	assert!(!remote.syn([10, 9, 0, 9], LISTENER_AT, 40003, MANAGE, SECOND).await.as_deref().is_some_and(opened));
	assert_eq!(node1.links()[0].management.opened, 0);
	Arc::try_unwrap(node1).ok().unwrap().shutdown().await;
}

// "A remote serves management only while its own config says `by_peer`", "A link of another operator to the same node has another link index and is never served."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_is_not_managed_by_its_peer_is_never_served() {
	fn unmanaged(doc: &mut Value) {
		doc["links"][0].as_object_mut().unwrap().remove("manage");
		doc["links"][0]["addresses"].as_object_mut().unwrap().remove("listener");
	}
	fn managing(doc: &mut Value) {doc["links"][0]["manage"] = json!("peer")}
	fn beside(doc: &mut Value) {
		doc["links"].as_array_mut().unwrap().push(json!({"tag": "other", "id": OTHER_ID, "direction": "forward", "addresses": {"dialler": ["10.9.0.4"]}, "transport_secret": text(&OTHER_SECRET), "inbound": "links", "public_key": text(&public(&OTHER)), "exits": ["main"]}));
	}
	let time = time!();
	for (test, change, key, from, name) in [("manage-hostile-none", unmanaged as fn(&mut Value), &DIALLER, DIALLER_AT, "a link with no manage"), ("manage-hostile-peer", managing, &DIALLER, DIALLER_AT, "a link that manages the other node"), ("manage-hostile-second", beside, &OTHER, [10, 9, 0, 4], "the link of another operator beside the managing one")] {
		let (remote, pair, _, _site) = alone(test, true, true, change, time).await;
		let standing = stand_in(&remote, |_, _| Reply::Hold);
		let mut peer = Peer::node_with(key, &EXIT, if key == &OTHER {&OTHER_SECRET} else {&SECRET}, pair.at, from, time);
		peer.connect().await;
		for sport in [40000, 40001] {
			let answer = peer.syn(from, LISTENER_AT, sport, MANAGE, SECOND).await;
			assert!(!answer.as_deref().is_some_and(opened), "{name} was served");
			// A reset or an error, or nothing: never a connection.
			assert!(answer.as_deref().is_none_or(|packet| reset(packet) || packet[9] == 1), "{name} got something that is not a refusal");
		}
		assert!(standing.seen.lock().unwrap().is_empty() && standing.held.load(Ordering::SeqCst) == 0, "{name}: a stream reached the control API");
		let counted = remote.links().into_iter().find(|link| link.manage == Some(veilway_core::config::LinkManage::ByPeer)).map(|link| link.management);
		assert!(counted.is_none_or(|counted| counted.opened == 0 && counted.open == 0), "{name}: {counted:?}");
		standing.task.abort();
		Arc::try_unwrap(remote).ok().unwrap().shutdown().await;
	}
}

// "Four management connections at once per link ... (a fifth is reset)", and only the link's own address speaks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fifth_connection_to_a_managed_node_is_reset_and_a_wrong_address_is_ignored() {
	let time = time!();
	let (remote, pair, _, _site) = alone("manage-hostile-five", true, true, |_| {}, time).await;
	let standing = stand_in(&remote, |_, _| Reply::Hold);
	let mut peer = Peer::node(&DIALLER, &EXIT, pair.at, DIALLER_AT, time);
	peer.connect().await;
	for sport in 40001..=40004 {
		let answer = peer.syn(DIALLER_AT, LISTENER_AT, sport, MANAGE, 4 * SECOND).await;
		assert!(answer.as_deref().is_some_and(opened), "connection {sport} was not taken");
	}
	let answer = peer.syn(DIALLER_AT, LISTENER_AT, 40005, MANAGE, 4 * SECOND).await;
	assert!(answer.as_deref().is_some_and(reset), "a fifth connection was not reset: {answer:?}");
	assert_eq!((remote.links()[0].management.open, remote.links()[0].management.refused), (4, 1));
	assert!(peer.syn([10, 9, 0, 9], LISTENER_AT, 40006, MANAGE, SECOND).await.is_none(), "a connection from an address that is not the link's was answered");
	// A SYN to another port is the gate's, not management's.
	assert!(!peer.syn(DIALLER_AT, LISTENER_AT, 40007, 8080, SECOND).await.as_deref().is_some_and(opened));
	assert_eq!(remote.links()[0].management.open, 4);
	standing.task.abort();
	Arc::try_unwrap(remote).ok().unwrap().shutdown().await;
}

// "A node without a control API refuses every connection."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_no_control_api_resets_management_and_node_1_says_so() {
	let net = up("manage-no-api", Setup {api: false, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let started = Instant::now();
	let answer = net.node1.manage("far", ask("GET", "/v1/status", Vec::new())).await;
	assert_eq!(answer.map(|answer| answer.status), Err(Error::Refused));
	assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
	let (sent, taken) = (net.node1.links()[0].management, net.remote().links()[0].management);
	assert_eq!((sent.failed, sent.opened, taken.refused, taken.opened), (1, 0, 1, 0), "{sent:?} {taken:?}");
	// The node that is managed does not call: NotManaged, with nothing sent.
	assert_eq!(net.remote().manage("far", ask("GET", "/v1/status", Vec::new())).await.map(|answer| answer.status), Err(Error::NotManaged));
	assert_eq!(net.node1.manage("nobody", ask("GET", "/v1/status", Vec::new())).await.map(|answer| answer.status), Err(Error::NoLink));
	for bad in [("TRACE", "/v1/status"), ("GET", "/v1/../status"), ("GET", "v1/status"), ("GET", "/v1//status"), ("GET", "/v1/status\r\nx: y")] {
		assert_eq!(net.node1.manage("far", ask(bad.0, bad.1, Vec::new())).await.map(|answer| answer.status), Err(Error::BadRequest), "{bad:?}");
	}
	assert_eq!(net.node1.manage("far", ask("POST", "/v1/status", vec![0; manage::BODY + 1])).await.map(|answer| answer.status), Err(Error::BadRequest));
	net.end().await;
}

// "Answers are untrusted: 8 MiB cap, strict HTTP; what is larger or odd ends the connection."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_that_are_too_large_or_not_strict_http_are_cut_and_nothing_stays_open() {
	let net = up("manage-answers", Setup {api: false, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let standing = stand_in(net.remote(), |path, _| match path {
		"/huge" => Reply::Raw(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", manage::ANSWER + 1).into_bytes()),
		"/hugebody" => Reply::Length(manage::ANSWER + 4096),
		"/chunked" => Reply::Raw(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec()),
		"/nolength" => Reply::Raw(b"HTTP/1.1 200 OK\r\n\r\nhello".to_vec()),
		"/short" => Reply::Raw(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nhello".to_vec()),
		"/garbage" => Reply::Raw(vec![0xff; 70000]),
		"/headers" => Reply::Raw([&b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n"[..], &vec![b'x'; 20000], &b"\r\n\r\nok"[..]].concat()),
		_ => Reply::Length(10),
	});
	for (path, wanted) in [("/huge", Error::TooLarge), ("/hugebody", Error::TooLarge), ("/chunked", Error::BadAnswer), ("/nolength", Error::BadAnswer), ("/short", Error::BadAnswer), ("/garbage", Error::BadAnswer), ("/headers", Error::BadAnswer)] {
		let started = Instant::now();
		let answer = net.node1.manage("far", ask("GET", path, Vec::new())).await;
		assert_eq!(answer.map(|answer| answer.status), Err(wanted), "{path}");
		assert!(started.elapsed() < Duration::from_secs(8), "{path} took {:?}", started.elapsed());
	}
	// Nothing was left open, on either node, and the next request goes through.
	let deadline = Instant::now() + Duration::from_secs(10);
	while net.node1.links()[0].management.open + net.remote().links()[0].management.open > 0 {
		assert!(Instant::now() < deadline, "connections stayed open: {:?} {:?}", net.node1.links()[0].management, net.remote().links()[0].management);
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let fine = net.node1.manage("far", ask("GET", "/ok", Vec::new())).await.unwrap();
	assert_eq!((fine.status, fine.body.len()), (200, 10));
	standing.task.abort();
	net.end().await;
}

// "A fifth waits up to 5 s, then 503 busy."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fifth_request_waits_five_seconds_and_is_then_busy() {
	let net = up("manage-busy", Setup {api: false, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let standing = stand_in(net.remote(), |_, _| Reply::Hold);
	let held: Vec<_> = (0..4).map(|_| tokio::spawn({
		let node1 = net.node1.clone();
		async move {node1.manage("far", manage::Request {within: Duration::from_secs(12), ..ask("GET", "/hold", Vec::new())}).await.map(|answer| answer.status)}
	})).collect();
	let deadline = Instant::now() + Duration::from_secs(10);
	while standing.held.load(Ordering::SeqCst) < 4 {
		assert!(Instant::now() < deadline, "the four connections did not open");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let started = Instant::now();
	let fifth = net.node1.manage("far", ask("GET", "/hold", Vec::new())).await.map(|answer| answer.status);
	assert_eq!(fifth, Err(Error::Busy));
	assert!(started.elapsed() >= Duration::from_secs(5) && started.elapsed() < Duration::from_secs(7), "{:?}", started.elapsed());
	for task in held {assert_eq!(task.await.unwrap(), Err(Error::Silent))}
	standing.task.abort();
	net.end().await;
}

// "A fixed allowlist, checked on node 1 and again on the remote ... a managed node cannot be used as a hop."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_off_the_list_is_refused_on_node_1_and_again_on_the_remote() {
	let net = up("manage-list", Setup::new(true, Over::Obfs, true), time!()).await;
	let mine = net.socket(false);
	let off = [("GET", "/v1/events"), ("GET", "/v1/openapi.json"), ("PUT", "/v1/status"), ("DELETE", "/v1/config"), ("POST", "/v1/users/alice"), ("GET", "/v1/users/%2e%2e"), ("GET", "/v1/users/a/b"), ("GET", "/v1/links/far/api/v1/status"), ("GET", "/v1/status/")];
	for (method, path) in off {
		let (status, answer) = relay(&mine, method, path, &[], None).await;
		assert_eq!((status, code(&answer)), (404, "not_allowed_through_link"), "{method} {path}");
	}
	let (sent, taken) = (net.node1.links()[0].management, net.remote().links()[0].management);
	assert_eq!((sent.denied, sent.opened, taken.denied, taken.opened), (off.len() as u64, 0, 0, 0), "{sent:?} {taken:?}");
	// What node 1 would never send is refused by the remote all the same: the request is made by the engine, past node 1's list.
	let past = [("GET", "/v1/events"), ("GET", "/v1/openapi.json"), ("PUT", "/v1/status"), ("DELETE", "/v1/config"), ("POST", "/v1/users/alice"), ("GET", "/v1/users/a/b"), ("GET", "/v1/links/far/api/v1/status")];
	for (method, path) in past {
		let answer = net.node1.manage("far", ask(method, path, Vec::new())).await.unwrap_or_else(|e| panic!("{method} {path}: {e:?}"));
		let body: Value = serde_json::from_slice(&answer.body).unwrap();
		assert_eq!((answer.status, code(&body)), (404, "not_allowed_through_link"), "{method} {path}");
	}
	assert_eq!(net.remote().links()[0].management.denied, past.len() as u64);
	// What is on the list goes through, and the remote's own list of links shows the counters.
	let (status, links) = relay(&mine, "GET", "/v1/links", &[], None).await;
	assert_eq!((status, &links["links"][0]["manage"], &links["links"][0]["management"]["denied"]), (200, &json!("by_peer"), &json!(past.len())), "{links}");
	net.end().await;
}

// "Refused at once (422 managing_link): a document in which that link is missing, disabled, or has a different id, keys, addresses, manage, inbound or peer", and the one exception: the removal of the node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_that_would_cut_the_managing_link_is_refused_and_a_removal_without_users_is_taken() {
	let net = up("manage-guard", Setup {trial: Duration::from_secs(2), ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let mine = net.socket(false);
	let (_, config) = relay(&mine, "GET", "/v1/config", &[], None).await;
	let (revision, document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	let changes: [(&str, fn(&mut Value)); 5] = [
		("disabled", |doc| doc["links"][0]["enabled"] = json!(false)),
		("another address", |doc| doc["links"][0]["addresses"]["dialler"] = json!(["10.9.0.9"])),
		("no manage", |doc| {
			doc["links"][0].as_object_mut().unwrap().remove("manage");
			doc["links"][0]["addresses"].as_object_mut().unwrap().remove("listener");
		}),
		("manage the other way", |doc| doc["links"][0]["manage"] = json!("peer")),
		("another key", |doc| doc["links"][0]["public_key"] = json!(text(&public(&OTHER)))),
	];
	for (what, change) in changes {
		let mut doc = document.clone();
		change(&mut doc);
		let (status, answer) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(doc.to_string().into_bytes())).await;
		assert_eq!((status, code(&answer)), (422, "managing_link"), "{what}: {answer}");
		assert_eq!(net.remote().snapshot().generation, 1, "{what}: something was applied");
	}
	// Changes that leave the link alone are the remote's own to judge, and are taken.
	let mut same = document.clone();
	same["exits"][0]["name"] = json!("Main");
	assert_eq!(relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(same.to_string().into_bytes())).await.0, 200);
	let config = settled(&mine, "/v1/config").await;
	// "Remove node": no users, no link. It is not put on trial, so it is not put back, and the trial of the change before it goes with it.
	let mut gone = config["document"].clone();
	gone["links"] = json!([]);
	let (status, answer) = relay(&mine, "PUT", "/v1/config", &[("if-match", config["revision"].as_str().unwrap())], Some(gone.to_string().into_bytes())).await;
	// The answer is sent before the removal goes into force, since it goes back through the link the document removes.
	assert_eq!(status, 202, "{answer}");
	assert_eq!(net.remote().links().len(), 1, "the removal was applied before its answer left");
	// It is in the config file before it is answered, so a restart meanwhile comes back emptied.
	let saved: Value = serde_json::from_slice(&std::fs::read(net.remote_dir.join("config.json")).unwrap()).unwrap();
	assert!(saved["links"].as_array().is_none_or(Vec::is_empty) && saved["users"].as_array().is_none_or(Vec::is_empty), "the config file does not hold the removal: {saved}");
	tokio::time::sleep(Duration::from_secs(3)).await;
	assert!(net.remote().links().is_empty(), "the removal was not applied");
	tokio::time::sleep(Duration::from_secs(3)).await;
	assert!(net.remote().links().is_empty(), "a removal was put back");
	net.end().await;
	// With users on it, the same document is refused: the removal of a node comes with none.
	let net = up("manage-guard-users", Setup {trial: Duration::from_secs(2), ..Setup::new(true, Over::Obfs, false)}, time!()).await;
	let mine = net.socket(false);
	let (_, config) = relay(&mine, "GET", "/v1/config", &[], None).await;
	let mut gone = config["document"].clone();
	(gone["links"], gone["exits"][0]) = (json!([]), json!({"tag": "far", "backend": {"type": "block"}}));
	let (status, answer) = relay(&mine, "PUT", "/v1/config", &[("if-match", config["revision"].as_str().unwrap())], Some(gone.to_string().into_bytes())).await;
	assert_eq!((status, code(&answer)), (422, "managing_link"), "{answer}");
	assert_eq!((net.remote().snapshot().generation, net.remote().links().len()), (1, 1));
	net.end().await;
}

// "Every relayed PUT is applied on trial and rolled back without a confirming request within 120 s."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_pushed_through_the_link_is_put_back_when_nothing_follows_it() {
	let net = up("manage-trial", Setup {trial: Duration::from_secs(2), ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let mine = net.socket(false);
	let (_, config) = relay(&mine, "GET", "/v1/config", &[], None).await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	let before = net.remote().snapshot().config.dns.servers.clone();
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"]), (200, &json!(2)), "{applied}");
	assert_eq!(net.remote().snapshot().config.dns.servers.len(), 1);
	assert_ne!(net.remote().snapshot().config.dns.servers, before);
	// Nothing is asked of the remote through the link: after the trial the config before is back, in force and in the file.
	let started = Instant::now();
	while net.remote().snapshot().generation < 3 {
		assert!(started.elapsed() < Duration::from_secs(10), "the config was not put back");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert!(started.elapsed() >= Duration::from_secs(1), "the config was put back before the trial ended: {:?}", started.elapsed());
	assert_eq!(net.remote().snapshot().config.dns.servers, before);
	let file: Value = serde_json::from_slice(&std::fs::read(net.remote_dir.join("config.json")).unwrap()).unwrap();
	assert_eq!(file["dns"]["servers"], json!(["1.1.1.1:53"]));
	assert!(!net.remote_dir.join("config.json.trial").exists(), "the trial file stayed after the rollback");
	// The link was never cut: it comes back after the new session, and shows the old config.
	assert_eq!(settled(&mine, "/v1/config").await["document"]["dns"]["servers"], json!(["1.1.1.1:53"]));
	// A config somebody changed at the remote since is not put back over theirs.
	let config = settled(&mine, "/v1/config").await;
	let mut next = config["document"].clone();
	next["dns"]["servers"] = json!(["9.9.9.9:53"]);
	assert_eq!(relay(&mine, "PUT", "/v1/config", &[("if-match", config["revision"].as_str().unwrap())], Some(next.to_string().into_bytes())).await.0, 200);
	let (_, local) = call(&net.socket(true), "GET", "/v1/config", &[], None).await;
	let mut theirs = local["document"].clone();
	theirs["dns"]["servers"] = json!(["8.8.4.4:53"]);
	assert_eq!(call(&net.socket(true), "PUT", "/v1/config", &[("if-match", local["revision"].as_str().unwrap())], Some(theirs.to_string().into_bytes())).await.0, 200);
	tokio::time::sleep(Duration::from_secs(4)).await;
	assert_eq!(serde_json::to_value(&net.remote().snapshot().config.dns.servers).unwrap(), json!(["8.8.4.4:53"]), "the operator's own change was put back over");
	net.end().await;
}

// "Refused at once (422 managing_link)": the listen port and the key of the inbound the link is carried by are held to what the link depends on, with the whole inbound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_that_moves_the_listen_port_or_changes_the_key_of_the_link_is_refused_at_once() {
	let net = up("manage-port", Setup::new(true, Over::Obfs, true), time!()).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	let mut moved = document.clone();
	moved["inbounds"][0]["transports"][0]["listen"] = json!(SocketAddr::new(outward(), port()).to_string());
	let mut rekeyed = document.clone();
	rekeyed["inbounds"][0]["private_key"] = json!(text(&OTHER));
	for (what, doc) in [("the listen port", moved), ("the key", rekeyed)] {
		let (status, answer) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(doc.to_string().into_bytes())).await;
		assert_eq!((status, code(&answer)), (422, "managing_link"), "{what}: {answer}");
	}
	assert_eq!(net.remote().snapshot().generation, 1, "something was applied");
	assert!(!net.remote_dir.join("config.json.trial").exists(), "a refused push left a trial file");
	assert_eq!(settled(&mine, "/v1/status").await["generation"], json!(1));
	net.end().await;
}

// "Every relayed PUT is applied on trial": a push that breaks the next session is put back, however soon requests come after it, since they travel on the session the push began with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_that_breaks_the_next_session_is_put_back_even_when_requests_follow_it() {
	let net = up("manage-break", Setup {trial: Duration::from_secs(6), ..Setup::new(false, Over::Tls, true)}, time!()).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	// The remote dials node 1 through a SOCKS5 outbound that refuses. Guard 1 does not look at the outbound of a link, so the push is applied on trial.
	document["outbounds"].as_array_mut().unwrap().push(json!({"tag": "dead", "type": "socks5", "server": SocketAddr::new(outward(), port()).to_string()}));
	document["links"][0]["via"] = json!("dead");
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	// The remote restarts the session of a link whose outbound changed, so the answer may be cut off: the push is then read from the remote, as the panel does.
	assert!(matches!(status, 200 | 502 | 504), "{status} {applied}");
	assert!(net.remote().snapshot().generation >= 2, "the push was not applied");
	let started = Instant::now();
	while net.remote().snapshot().generation < 3 {
		assert!(started.elapsed() < Duration::from_secs(20), "the config was not put back");
		let _ = relay(&mine, "GET", "/v1/status", &[], None).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	assert!(net.remote().snapshot().config.links[0].via.is_none(), "the outbound of the link was not put back");
	assert!(!net.remote_dir.join("config.json.trial").exists(), "the trial file stayed after the rollback");
	assert_eq!(settled(&mine, "/v1/status").await["generation"], json!(3));
	net.end().await;
}

// "A request confirms a config on trial only from the settle time on": requests that come before it do not, even over a session the push made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_before_the_settle_time_do_not_confirm_a_config_on_trial() {
	// Requests sent up to 6 s after the push reach the remote within 10 s of being sent (a management connection gives up then), so all of them arrive before the settle time of 20 s.
	let net = up("manage-early", Setup {trial: Duration::from_secs(30), settle: Duration::from_secs(20), ..Setup::new(false, Over::Obfs, true)}, time!()).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"]), (200, &json!(2)), "{applied}");
	let started = Instant::now();
	let mut answered = 0;
	while started.elapsed() < Duration::from_secs(6) {
		if let Ok((200, _)) = tokio::time::timeout(Duration::from_millis(500), relay(&mine, "GET", "/v1/status", &[], None)).await {answered += 1}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
	assert!(answered > 0, "no request reached the remote before the settle time, so the test proves nothing");
	let started = Instant::now();
	while net.remote().snapshot().generation < 3 {
		assert!(started.elapsed() < Duration::from_secs(40), "the config was not put back");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert_eq!(serde_json::to_value(&net.remote().snapshot().config.dns.servers).unwrap(), json!(["1.1.1.1:53"]), "an early request confirmed the config");
	assert!(!net.remote_dir.join("config.json.trial").exists(), "the trial file stayed after the rollback");
	net.end().await;
}

// "A request from the settle time on, over a session the push made, confirms the config on trial, which then stays."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_from_the_settle_time_on_confirms_a_config_on_trial() {
	let net = up("manage-settle", Setup {trial: Duration::from_secs(6), settle: Duration::from_secs(2), ..Setup::new(false, Over::Obfs, true)}, time!()).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"]), (200, &json!(2)), "{applied}");
	tokio::time::sleep(Duration::from_secs(3)).await;
	let after = settled(&mine, "/v1/status").await;
	assert_eq!(after["revision"], applied["revision"]);
	tokio::time::sleep(Duration::from_secs(5)).await;
	assert_eq!((net.remote().snapshot().generation, serde_json::to_value(&net.remote().snapshot().config.dns.servers).unwrap()), (2, json!(["9.9.9.9:53"])), "a confirmed config was put back");
	net.end().await;
}

// "The routes with a name are served through a link": the router takes the templates of the list as they are, and a name is answered by the remote's own handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_routes_with_a_name_are_served_through_the_link() {
	let net = up("manage-names", Setup::new(true, Over::Obfs, false), time!()).await;
	let mine = net.socket(false);
	let (status, user) = relay(&mine, "GET", "/v1/users/alice", &[], None).await;
	assert_eq!((status, &user["name"]), (200, &json!("alice")), "{user}");
	let (status, missing) = relay(&mine, "GET", "/v1/users/x", &[], None).await;
	assert_eq!((status, code(&missing)), (404, "user_not_found"), "{missing}");
	let (status, missing) = relay(&mine, "POST", "/v1/users/x/usage/reset", &[], None).await;
	assert_eq!((status, code(&missing)), (404, "user_not_found"), "{missing}");
	let (status, reset) = relay(&mine, "POST", "/v1/users/alice/usage/reset", &[], None).await;
	assert_eq!((status, &reset["name"]), (200, &json!("alice")), "{reset}");
	assert_eq!(net.node1.links()[0].management.denied, 0, "a route with a name was turned away");
	net.end().await;
}

// "A fifth waits up to 5 s, then 503 busy": the places are one count for all links of the node, and a relay past them waits 5 s and is busy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_past_the_places_of_the_node_is_busy() {
	let net = up("manage-places", Setup {relays: 1, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let standing = stand_in(net.remote(), |_, _| Reply::Hold);
	let mine = net.socket(false);
	let held = tokio::spawn({
		let mine = mine.clone();
		async move {relay(&mine, "GET", "/v1/status", &[], None).await}
	});
	tokio::time::sleep(Duration::from_millis(500)).await;
	let started = Instant::now();
	let (status, answer) = relay(&mine, "GET", "/v1/status", &[], None).await;
	assert_eq!((status, code(&answer)), (503, "busy"), "{answer}");
	assert!(started.elapsed() >= Duration::from_secs(4) && started.elapsed() < Duration::from_secs(7), "{:?}", started.elapsed());
	assert_eq!(held.await.unwrap().0, 504);
	standing.task.abort();
	net.end().await;
}

// "Node 1's own answers of the relay route carry `veilway-relay: node1`, which the other node cannot set: its answer crosses the relay with status, ETag and Content-Type only."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_1s_relay_answers_say_so_and_the_other_nodes_do_not() {
	let own = up("manage-header-own", Setup {remote: false, ..Setup::new(true, Over::Obfs, true)}, time!()).await;
	let answer = raw(&own.socket(false), "/v1/links/far/api/v1/status").await;
	assert!(answer.starts_with("HTTP/1.1 503") && answer.contains("link_down") && answer.to_ascii_lowercase().contains("veilway-relay: node1"), "{answer}");
	own.end().await;
	let net = up("manage-header-theirs", Setup::new(true, Over::Obfs, true), time!()).await;
	let standing = stand_in(net.remote(), |_, _| {
		let body = r#"{"error":{"code":"link_down","message":"the other node says so","details":[]}}"#;
		Reply::Raw(format!("HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len()).into_bytes())
	});
	let answer = raw(&net.socket(false), "/v1/links/far/api/v1/status").await;
	assert!(answer.starts_with("HTTP/1.1 503") && answer.contains("the other node says so") && !answer.to_ascii_lowercase().contains("veilway-relay"), "{answer}");
	standing.task.abort();
	net.end().await;
}

// "A config on trial is saved next to the config file until it is confirmed": a restart before that puts the config before back, and the file goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_on_trial_is_put_back_by_a_restart_before_it_is_confirmed() {
	let time = time!();
	let mut net = up("manage-restart", Setup::new(true, Over::Obfs, true), time).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"]), (200, &json!(2)), "{applied}");
	let (config_file, trial_file) = (net.remote_dir.join("config.json"), net.remote_dir.join("config.json.trial"));
	let saved: Value = serde_json::from_slice(&std::fs::read(&trial_file).expect("the trial was not saved next to the config")).unwrap();
	assert_eq!(saved["previous"]["dns"]["servers"], json!(["1.1.1.1:53"]));
	assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&trial_file).unwrap().permissions()) & 0o777, 0o600);
	// The node stops before the push is confirmed, and starts again from the same files.
	net.remote_api.take().unwrap().shutdown().await;
	Arc::try_unwrap(net.remote.take().unwrap()).ok().expect("something still holds the remote").shutdown().await;
	assert_eq!(veilway_api::restore_trial(&config_file).unwrap(), Some(veilway_api::Restore::Put), "there was no trial file to restore");
	assert!(!trial_file.exists(), "the trial file stayed");
	let mut doc: Value = serde_json::from_slice(&std::fs::read(&config_file).unwrap()).unwrap();
	doc["inbounds"][0]["transports"][0]["listen"] = json!(SocketAddr::new(outward(), port()).to_string());
	net.remote = Some(restarted(&doc, &net.remote_dir, time, &net.roots).await);
	net.remote_api = Some(serve(net.remote(), &net.remote_dir, Limits {trial: net.trial, renew: net.renew, settle: net.settle, ..Limits::default()}));
	let (_, config) = call(&net.socket(true), "GET", "/v1/config", &[], None).await;
	assert_eq!((&config["document"]["dns"]["servers"], net.remote().snapshot().generation), (&json!(["1.1.1.1:53"]), 1), "{config}");
	assert!(!trial_file.exists(), "the trial file came back");
	net.end().await;
}

// "A confirmed trial leaves no file behind": the file goes with the confirmation, before the answer to the request that confirmed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmed_trial_leaves_nothing_behind() {
	let net = up("manage-confirm", Setup::new(true, Over::Obfs, true), time!()).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"]), (200, &json!(2)), "{applied}");
	assert!(net.remote_dir.join("config.json.trial").exists(), "the trial was not saved");
	tokio::time::sleep(Duration::from_secs(3)).await;
	let after = settled(&mine, "/v1/status").await;
	assert_eq!(after["revision"], applied["revision"]);
	assert!(!net.remote_dir.join("config.json.trial").exists(), "a confirmed trial left its file");
	net.end().await;
}

// "The config file is kept as it is when it was changed since the push": a restart puts back nothing over a change made by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_changed_since_a_push_on_trial_is_kept_by_a_restart() {
	let time = time!();
	let mut net = up("manage-changed", Setup::new(true, Over::Obfs, true), time).await;
	let mine = net.socket(false);
	let config = settled(&mine, "/v1/config").await;
	let (revision, mut document) = (config["revision"].as_str().unwrap().to_string(), config["document"].clone());
	document["dns"]["servers"] = json!(["9.9.9.9:53"]);
	let (status, applied) = relay(&mine, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes())).await;
	assert_eq!((status, &applied["generation"]), (200, &json!(2)), "{applied}");
	let (config_file, trial_file) = (net.remote_dir.join("config.json"), net.remote_dir.join("config.json.trial"));
	net.remote_api.take().unwrap().shutdown().await;
	Arc::try_unwrap(net.remote.take().unwrap()).ok().expect("something still holds the remote").shutdown().await;
	let mut by_hand: Value = serde_json::from_slice(&std::fs::read(&config_file).unwrap()).unwrap();
	by_hand["dns"]["servers"] = json!(["8.8.8.8:53"]);
	std::fs::write(&config_file, by_hand.to_string()).unwrap();
	assert_eq!(veilway_api::restore_trial(&config_file).unwrap(), Some(veilway_api::Restore::Changed));
	assert!(!trial_file.exists(), "the trial file stayed");
	by_hand["inbounds"][0]["transports"][0]["listen"] = json!(SocketAddr::new(outward(), port()).to_string());
	net.remote = Some(restarted(&by_hand, &net.remote_dir, time, &net.roots).await);
	net.remote_api = Some(serve(net.remote(), &net.remote_dir, Limits {trial: net.trial, renew: net.renew, settle: net.settle, ..Limits::default()}));
	let (_, config) = call(&net.socket(true), "GET", "/v1/config", &[], None).await;
	assert_eq!((&config["document"]["dns"]["servers"], net.remote().snapshot().generation), (&json!(["8.8.8.8:53"]), 1), "{config}");
	net.end().await;
}
