//! The `udp-obfs` transport of a `veilway` inbound, end to end: a boringtun peer whose datagrams travel in the packets of `veilway_proto::udp_obfs`, against a node that is started the way `veilway run` starts it.
//! The node's clock is each test's own, so a test that needs minutes to pass moves the clock and waits for the node's next look at it. Every node has a replay file in a directory of its own.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use veilway_core::config::Config;
use veilway_core::{Engine, ObfsTotals, Options, Over, Reset};
use veilway_proto::chunk::{Padding, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::control::PORT;
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::ClientOpening;
use veilway_proto::replay::{STEP, WINDOW};
use veilway_proto::udp_obfs::{self, Receiver, Sender};
use veilway_proto::NoRandom;

const GATEWAY: [u8; 4] = [10, 7, 0, 1];
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
// Keys and secrets of tests are fixed patterns, and no secret of anything real. Device `n` has the private key `KEYS[n]`, the tunnel address 10.7.0.(2 + n) and the transport secret `secret(n)`.
const NODE: [u8; 32] = [0x10; 32];
const KEYS: [[u8; 32]; 6] = [[0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32], [0x25; 32], [0x26; 32]];
const SECOND: Duration = Duration::from_secs(1);
/// What a quiet socket is given to stay quiet in.
const QUIET: Duration = Duration::from_millis(400);
/// The largest packet of an inbound with an `mtu` of 1390.
const MAX: usize = 1390 + udp_obfs::OVERHEAD;
/// Port 0 is no listen port of a config, so every listener of a test node takes the next one from here.
static NEXT_PORT: AtomicU16 = AtomicU16::new(25000);
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

/// A new directory for one test.
fn scratch(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-udp-obfs-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// Writes the replay file a node leaves that was killed with this floor and this limit: a head without the clean mark and without entries, and its hash.
fn seed(path: &Path, floor: u64, limit: u64) {
	let body = [&b"VWREPLAY"[..], &1u32.to_be_bytes(), &[0; 4], &floor.to_be_bytes(), &limit.to_be_bytes(), &0u32.to_be_bytes()].concat();
	std::fs::write(path, [&body[..], digest(&SHA256, &body).as_ref()].concat()).unwrap();
}

/// A document with one `veilway` inbound `home` on 10.7.0.1/24 that is reached over `udp-obfs` at `listen`, one exit through `proxy`, and the users `a` to `f` with one device each.
fn document(proxy: SocketAddr, listen: SocketAddr) -> Value {
	let names = ["a", "b", "c", "d", "e", "f"];
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transports": [{"type": "udp-obfs", "listen": listen.to_string()}]}],
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

struct Node {engine: Engine, addr: SocketAddr, doc: Value, dir: PathBuf, time: Time}

/// Starts an engine on `doc` with the replay file `replay` and the clock of `time`.
async fn start(doc: &Value, replay: Option<PathBuf>, time: Time) -> anyhow::Result<Engine> {
	LOGGING.call_once(|| tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_writer(|| Sink).init());
	veilway_core::start(&parsed(doc), Options {now: time.now, replay, ..Options::new("")}).await
}

/// Starts a node on `document` after `change` had its way with it. Its replay file is one a node left that was killed 100 seconds ago, so it takes proofs from its first moment.
async fn launch(test: &str, time: Time, change: impl FnOnce(&mut Value)) -> Node {
	let (dir, addr) = (scratch(test), listen());
	let mut doc = document(proxy().await, addr);
	change(&mut doc);
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let engine = start(&doc, Some(dir.join("replay")), time).await.unwrap();
	Node {engine, addr, doc, dir, time}
}

impl Node {
	fn totals(&self) -> ObfsTotals {self.engine.obfs()}

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
}

/// Waits for something the engine does on its own time.
async fn eventually(what: &str, done: impl Fn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(8);
	while !done() {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// A device that reaches its tunnel over `udp-obfs`. What it receives and nobody asked for yet waits in `inbox`.
/// `last` is the size of the last packet of the node that opened, and `largest` that of the largest.
struct Device {tunn: Tunn, sock: UdpSocket, wrap: udp_obfs::Client, node: SocketAddr, tx: Option<Sender>, rx: Option<Receiver>, before: Option<Sender>, inbox: VecDeque<Vec<u8>>, last: usize, largest: usize}

impl Device {
	/// Device `n` with the transport secret `secret`, from a socket of its own.
	async fn new(n: usize, secret: [u8; 32], node: SocketAddr) -> Device {
		Device {tunn: Tunn::new(StaticSecret::from(KEYS[n]), PublicKey::from(public(&NODE)), None, None, 0, None), sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(), wrap: udp_obfs::Client::new(&secret, &public(&NODE)), node, tx: None, rx: None, before: None, inbox: VecDeque::new(), last: 0, largest: 0}
	}

	/// Another source address and port for the same device, as after a rebinding in a network address translator.
	async fn rebind(&mut self) {self.sock = UdpSocket::bind("127.0.0.1:0").await.unwrap()}

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

	/// An opening packet around `datagram` with the timestamp `at`, and the two directions of the session it would open.
	fn opening(&self, at: u64, datagram: &[u8]) -> (Vec<u8>, Sender, Receiver) {
		let (mut packet, padding) = (Vec::new(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap());
		let keys = self.wrap.open(at, datagram, &padding, MAX, &mut random, &mut packet).unwrap();
		(packet, Sender::new(keys.c2s, padding), Receiver::new(keys.s2c))
	}

	/// Sends an opening packet and takes the session it opens for the one in use. The session before stays for `put_before`.
	async fn open(&mut self, at: u64, datagram: &[u8]) -> Vec<u8> {
		let (packet, tx, rx) = self.opening(at, datagram);
		self.sock.send_to(&packet, self.node).await.unwrap();
		(self.before, self.rx) = (self.tx.replace(tx), Some(rx));
		packet
	}

	/// One WireGuard datagram in a data packet of the session in use. What was sent.
	async fn put(&mut self, datagram: &[u8]) -> Vec<u8> {
		let mut packet = Vec::new();
		self.tx.as_mut().expect("no session").seal(Some(datagram), false, MAX, &mut random, &mut packet).unwrap();
		self.sock.send_to(&packet, self.node).await.unwrap();
		packet
	}

	/// The same in a data packet of the session before the one in use.
	async fn put_before(&mut self, datagram: &[u8]) {
		let mut packet = Vec::new();
		self.before.as_mut().expect("no session before this one").seal(Some(datagram), false, MAX, &mut random, &mut packet).unwrap();
		self.sock.send_to(&packet, self.node).await.unwrap();
	}

	/// The next packet from the node that opens under the session in use: the WireGuard datagram in it, or None inside for a padding-only packet. None when nothing came in time.
	async fn chunk(&mut self, budget: Duration) -> Option<Option<Vec<u8>>> {
		let (deadline, mut datagram, mut scratch) = (Instant::now() + budget, vec![0u8; 4096], Vec::new());
		loop {
			let (count, from) = timeout(deadline.checked_duration_since(Instant::now())?, self.sock.recv_from(&mut datagram)).await.ok()?.ok()?;
			assert_eq!(from, self.node, "a packet from somebody else than the node");
			if let Ok(inner) = self.rx.as_mut()?.open(&datagram[..count], &mut scratch) {
				(self.last, self.largest) = (count, self.largest.max(count));
				return Some(inner.map(<[u8]>::to_vec));
			}
		}
	}

	/// Opens a session around a handshake initiation and finishes the handshake on it. False when the node did not answer within `QUIET`.
	async fn try_connect(&mut self, at: u64) -> bool {
		let init = self.initiation();
		let opening = self.open(at, &init).await;
		let Some(Some(response)) = self.chunk(QUIET).await else {return false};
		// "The first answer, which it sends when the session is established, is no larger than the opening packet it answers."
		assert!(self.last <= opening.len(), "a first answer of {} bytes to an opening packet of {}", self.last, opening.len());
		let mut out = vec![0u8; 2048];
		let TunnResult::WriteToNetwork(keepalive) = self.tunn.decapsulate(None, &response, &mut out) else {panic!("the first answer held no handshake response")};
		let keepalive = keepalive.to_vec();
		self.put(&keepalive).await;
		true
	}

	/// `try_connect` the way a client does it: "If no chunk of the new session opens, the client sends a new opening packet, with a fresh salt and a fresh WireGuard datagram of the same kind."
	async fn connect(&mut self, time: Time) {
		for _ in 0..10 {
			if self.try_connect(time.secs()).await {return}
		}
		panic!("the node answered no opening packet");
	}

	/// One IP packet into the tunnel.
	async fn send(&mut self, packet: &[u8]) {
		let datagram = self.sealed(packet);
		self.put(&datagram).await;
	}

	/// The next IP packet `wanted` picks, from the inbox or from the tunnel. Every other packet stays in the inbox.
	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let Some(datagram) = self.chunk(deadline.checked_duration_since(Instant::now())?).await? else {continue};
			let mut input: &[u8] = &datagram;
			loop {
				let mut out = vec![0u8; 2048];
				match self.tunn.decapsulate(None, input, &mut out) {
					TunnResult::WriteToNetwork(reply) => {
						let reply = reply.to_vec();
						self.put(&reply).await;
						input = &[];
					}
					TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
						if wanted(packet) {return Some(packet.to_vec())}
						self.inbox.push_back(packet.to_vec());
						break;
					}
					_ => break,
				}
			}
		}
	}

	/// Whether the node sends the device nothing for `QUIET`, but for the echo of a keepalive it sent earlier on the session in use, which comes up to 3 seconds after it.
	async fn silence(&mut self) -> bool {
		let (deadline, mut datagram, mut scratch) = (Instant::now() + QUIET, vec![0u8; 4096], Vec::new());
		loop {
			let Some(left) = deadline.checked_duration_since(Instant::now()) else {return true};
			let Ok(Ok((count, _))) = timeout(left, self.sock.recv_from(&mut datagram)).await else {return true};
			if !self.rx.as_mut().is_some_and(|rx| rx.open(&datagram[..count], &mut scratch) == Ok(None)) {return false}
		}
	}

	/// Opens a TCP connection to `PUBLIC` from the device's tunnel address and reads what the exit's proxy says first. None when the SYN gets no answer.
	async fn leaves(&mut self, n: usize, sport: u16) -> Option<String> {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new());
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
		self.reset(n, PUBLIC, sport, 80, 1001).await;
		Some(String::from_utf8(said).unwrap())
	}

	/// Ends a TCP connection of the device from its side, so the node's stack sends nothing more on it: a test that listens for silence must not hear a retransmission.
	async fn reset(&mut self, n: usize, to: [u8; 4], sport: u16, dport: u16, seq: u32) {
		let (mut rst, mut out) = (TcpHeader::new(sport, dport, seq, 0), Vec::new());
		rst.rst = true;
		PacketBuilder::ipv4(address(n), to, 64).tcp_header(rst).write(&mut out, &[]).unwrap();
		self.send(&out).await;
	}

	/// Throws away what has arrived and nobody read: answers to what the device sent before, which say nothing about what it sends next.
	async fn drain(&mut self) {
		tokio::time::sleep(Duration::from_millis(100)).await;
		while self.sock.try_recv_from(&mut [0u8; 4096]).is_ok() {}
	}
}

fn segment(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	Some((tcp, if let PayloadSlice::Tcp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

/// A socket of somebody who is no device, with what it sends to the node.
async fn stranger(node: SocketAddr, datagrams: &[Vec<u8>]) -> UdpSocket {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	for datagram in datagrams {sock.send_to(datagram, node).await.unwrap();}
	sock
}

async fn quiet(sock: &UdpSocket) -> bool {timeout(QUIET, sock.recv_from(&mut [0u8; 4096])).await.is_err()}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_its_tunnel_and_everything_of_the_engine_works_over_it() {
	let time = time!();
	let node = launch("happy", time, |_| {}).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	a.connect(time).await;
	// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay": here the keepalive that ends the handshake, on a session that carries nothing else yet.
	assert_eq!(a.chunk(Duration::from_secs(4)).await, Some(None), "a lone keepalive was not echoed");
	assert_eq!(a.leaves(0, 40000).await.as_deref(), Some("main"));
	// The control channel at the gateway: the opening exchange under the device's transport secret, inside the tunnel that came over `udp-obfs`.
	let (mut syn, mut out, sport, started) = (TcpHeader::new(41000, PORT, 5000, 65535), Vec::new(), 41000, Instant::now());
	syn.syn = true;
	PacketBuilder::ipv4(address(0), GATEWAY, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
	a.send(&out).await;
	let (answer, _) = segment(&a.recv(SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (PORT, sport))).await.expect("the control port did not answer")).unwrap();
	let (mut seq, mut ack, mut up) = (5001u32, answer.sequence_number.wrapping_add(1), Vec::new());
	let mut opening = ClientOpening::start(ControlKey::derive(&secret(0), &public(&NODE), &public(&KEYS[0])), 1, Duration::ZERO, &mut random, &mut up).unwrap();
	let opened = loop {
		let (mut header, mut out) = (TcpHeader::new(sport, PORT, seq, 65535), Vec::new());
		(header.ack, header.psh, header.acknowledgment_number) = (true, true, ack);
		PacketBuilder::ipv4(address(0), GATEWAY, 64).tcp_header(header).write(&mut out, &up).unwrap();
		a.send(&out).await;
		seq = seq.wrapping_add(up.len() as u32);
		up.clear();
		let (tcp, data) = segment(&a.recv(Duration::from_secs(3), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (PORT, sport) && !data.is_empty() && tcp.sequence_number == ack)).await.expect("the control channel went quiet")).unwrap();
		ack = tcp.sequence_number.wrapping_add(data.len() as u32);
		let mut input = &data[..];
		if let Some(opened) = opening.receive(started.elapsed(), &mut input, &mut up).expect("the node broke the opening exchange") {break opened}
	};
	assert_eq!(opened.version, 1);
	// Usage is counted, the session is a `udp-obfs` one, and nothing the node sent was larger than `mtu` + 62.
	let (peers, totals, control) = (node.engine.peers(Some("a")), node.totals(), node.engine.control());
	assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(Over::UdpObfs), true));
	assert_eq!((totals.opened, totals.established, totals.sessions, totals.pending, totals.tags, control.authenticated), (1, 1, 1, 0, 3 * KEYS.len(), 1), "{totals:?}");
	assert!(node.engine.user("a").unwrap().up_bytes > 0 && node.engine.user("a").unwrap().down_bytes > 0 && a.largest <= MAX, "{}", a.largest);
	node.engine.shutdown().await;
}

// "There is no decoy and there are no error messages. Every drop is silent and counted by reason. A prober that does not hold a device secret gets no reply, whatever it sends and however often."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whatever_is_no_valid_packet_for_the_node_gets_silence() {
	let time = time!();
	let node = launch("silence", time, |_| {}).await;
	let (mut a, now) = (Device::new(0, secret(0), node.addr).await, time.secs());
	let init = a.initiation();
	let accepted = a.open(now, &init).await;
	let Some(Some(response)) = a.chunk(SECOND).await else {panic!("the node did not answer its device")};
	let mut out = vec![0u8; 2048];
	let TunnResult::WriteToNetwork(keepalive) = a.tunn.decapsulate(None, &response, &mut out) else {panic!("no handshake response")};
	let keepalive = keepalive.to_vec();
	let recorded = a.put(&keepalive).await;
	// The echo of that keepalive is the last thing the node has to send its device, so from here on it must make no packet for any socket at all.
	assert_eq!(a.chunk(Duration::from_secs(4)).await, Some(None));
	let before = node.totals();
	assert_eq!(before.sent, 2);
	// Datagrams of every size around the two limits, with any bytes.
	let noise = |size: usize| (0..size).map(|at| (at * 31 + size) as u8).collect::<Vec<u8>>();
	let short = [0, 1, 27].map(noise).to_vec();
	let mut unknown: Vec<Vec<u8>> = [28, 75, 76, 77, 148, 200, 1452, 1500, 4000].map(noise).to_vec();
	// A WireGuard handshake initiation as it is, which the plain transport would answer.
	let mut plain = Device::new(1, secret(1), node.addr).await;
	unknown.push(plain.initiation());
	// A real opening packet that was changed on the way: in its tag, its salt, its sealed part and its last byte, and one that was cut.
	let mut b = Device::new(1, secret(1), node.addr).await;
	let init = b.initiation();
	let (good, ..) = b.opening(now, &init);
	for at in [0, 15, 16, 47, 48, 60, good.len() - 1] {
		let mut changed = good.clone();
		changed[at] ^= 1;
		unknown.push(changed);
	}
	unknown.extend([good[..75].to_vec(), good[..good.len() - 1].to_vec(), [&good[..], &[0]].concat()]);
	// An opening packet under a secret the node does not have, and one of a real device for another inbound.
	let (other, mut elsewhere) = (Device::new(1, [0xee; 32], node.addr).await, Device::new(1, secret(1), node.addr).await);
	elsewhere.wrap = udp_obfs::Client::new(&secret(1), &public(&[0x77; 32]));
	unknown.extend([other.opening(now, &init).0, elsewhere.opening(now, &init).0]);
	// A data packet of a live session from another source is nobody's.
	unknown.push(recorded.clone());
	let outside = stranger(node.addr, &[&short[..], &unknown[..]].concat()).await;
	assert!(quiet(&outside).await, "a stranger was answered");
	// What the replay rule refuses: an opening packet that was accepted before, from anywhere, and a timestamp outside the window on either side.
	let fresh = b.initiation();
	let replays = stranger(node.addr, &[accepted.clone(), b.opening(now - WINDOW - 5, &fresh).0, b.opening(now + WINDOW + 5, &fresh).0]).await;
	a.sock.send_to(&accepted, node.addr).await.unwrap();
	// The session's own data packet again from its own source opens, and WireGuard refuses what is in it as a replay.
	a.sock.send_to(&recorded, node.addr).await.unwrap();
	assert!(quiet(&replays).await && a.silence().await, "a replay was answered");
	let after = node.totals();
	// Five of them name a device by a tag of this epoch and do not open: the three changed behind the salt, the one that lost its last byte and the one that gained one. Every other is a tag the table does not have.
	assert_eq!((after.short - before.short, after.unknown - before.unknown, after.open_failed - before.open_failed, after.seen - before.seen, after.window - before.window, after.tunnel - before.tunnel), (short.len() as u64, unknown.len() as u64 - 5, 5, 2, 2, 1), "{after:?}");
	// Not only did no socket of the test hear anything: the node made no packet for any socket.
	assert_eq!(after.sent, before.sent);
	assert_eq!((after.opened, after.established, after.sessions, after.pending), (1, 1, 1, 0), "{after:?}");
	// The device itself is still served.
	assert_eq!(a.leaves(0, 40001).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// Protocol overview, "Rotation": "A device may have two secrets in the config at once. The node accepts both. When the old one is removed, sessions opened with it are dropped within one second."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_that_is_removed_opens_nothing_more_and_ends_what_it_opened() {
	let time = time!();
	let old = [0xc0; 32];
	let mut node = launch("rotation", time, |doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&old), text(&secret(0))])).await;
	// One session under each secret, and one of another device that the change must not touch.
	let (mut first, mut second, mut b) = (Device::new(0, old, node.addr).await, Device::new(0, secret(0), node.addr).await, Device::new(1, secret(1), node.addr).await);
	first.connect(time).await;
	assert_eq!(first.leaves(0, 40000).await.as_deref(), Some("main"));
	second.connect(time).await;
	b.connect(time).await;
	assert_eq!((second.leaves(0, 40001).await.as_deref(), node.totals().sessions, node.totals().tags), (Some("main"), 3, 3 * (KEYS.len() + 1)));
	node.reload(|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&secret(0))])).await;
	let totals = node.totals();
	assert_eq!((totals.ended_revoked, totals.tags), (1, 3 * KEYS.len()), "{totals:?}");
	// The session of the old secret is gone: what comes in on it is a stranger's, and a new opening packet under the old secret is one too.
	let (keepalive, unknown) = (first.sealed(&[]), totals.unknown);
	first.drain().await;
	first.put(&keepalive).await;
	let init = first.initiation();
	first.open(time.secs(), &init).await;
	assert!(first.silence().await, "a removed secret was answered");
	assert_eq!((node.totals().unknown - unknown, node.totals().opened), (2, 3));
	// The other secret's session, and the other device, never notice.
	assert_eq!((second.leaves(0, 40002).await.as_deref(), b.leaves(1, 40003).await.as_deref()), (Some("main"), Some("main")));
	eventually("the ended session was not taken out of the table", || node.totals().sessions == 2).await;
	// A user who is disabled: the device's sessions end, and its opening packets are a stranger's from the same moment.
	node.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	assert_eq!(node.totals().ended_revoked, 2);
	let init = second.initiation();
	second.drain().await;
	second.open(time.secs(), &init).await;
	assert!(second.silence().await && node.totals().opened == 3, "a disabled user's device was answered");
	assert_eq!(b.leaves(1, 40004).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// "WireGuard on an obfuscated transport", rule 1: "device A's proof followed by device B's initiation yields no handshake response, and the session ends at the first tunnel packet deadline."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_carries_the_tunnel_of_the_device_that_opened_it_and_of_no_other() {
	let time = time!();
	let node = launch("binding", time, |_| {}).await;
	let (mut a, mut b) = (Device::new(0, secret(0), node.addr).await, Device::new(1, secret(1), node.addr).await);
	// An opening packet under A's secret around B's handshake initiation.
	let foreign = b.initiation();
	a.open(time.secs(), &foreign).await;
	assert!(a.silence().await, "another device's handshake was answered on the session");
	let totals = node.totals();
	assert_eq!((totals.opened, totals.pending, totals.established, totals.tunnel), (1, 1, 0, 1), "{totals:?}");
	// The same in a data packet of the pending session.
	let foreign = b.initiation();
	a.put(&foreign).await;
	assert!(a.silence().await && node.totals().tunnel == 2);
	assert!(node.engine.peers(None).iter().all(|peer| peer.handshake.is_none()), "a handshake went through");
	node.advance(11).await;
	eventually("the pending session did not end at its deadline", || node.totals().ended_deadline == 1 && node.totals().pending == 0).await;
	// An established session of A: B's initiation in one of its data packets is dropped with no reply, and A goes on.
	a.connect(time).await;
	let (foreign, before) = (b.initiation(), node.totals().tunnel);
	a.put(&foreign).await;
	assert!(a.silence().await && node.totals().tunnel == before + 1, "another device's handshake was answered on an established session");
	assert_eq!((a.leaves(0, 40000).await.as_deref(), node.engine.peers(Some("b"))[0].handshake), (Some("main"), None));
	node.engine.shutdown().await;
}

// "A change of the client's address that the client cannot see leaves the node with a session for the old address. The client sends an opening packet with a keepalive. No new WireGuard handshake is needed."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_source_takes_the_tunnel_over_and_the_session_of_the_old_one_idles_out() {
	let time = time!();
	let node = launch("rebinding", time, |_| {}).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	a.connect(time).await;
	assert_eq!(a.leaves(0, 40000).await.as_deref(), Some("main"));
	a.rebind().await;
	let keepalive = a.sealed(&[]);
	let opening = a.open(time.secs(), &keepalive).await;
	// The first answer of a session that a keepalive established is a padding-only chunk, no larger than the opening packet.
	assert_eq!((a.chunk(SECOND).await, a.last <= opening.len()), (Some(None), true));
	// The node answers the device where it is now, under the tunnel it already had.
	assert_eq!((a.leaves(0, 40001).await.as_deref(), node.totals().sessions, node.totals().established), (Some("main"), 2, 2));
	// "The node ends a session with no activity for 180 s": the old source's session, and not the one that is used.
	node.advance(170).await;
	let keepalive = a.sealed(&[]);
	a.put(&keepalive).await;
	tokio::time::sleep(Duration::from_millis(200)).await;
	node.advance(15).await;
	eventually("the session of the old source did not idle out", || node.totals().ended_idle == 1 && node.totals().sessions == 1).await;
	assert_eq!(a.leaves(0, 40002).await.as_deref(), Some("main"));
	// What the device sent last has reached the node before its clock moves, so it is activity of the time before.
	a.drain().await;
	node.advance(181).await;
	eventually("the last session did not idle out", || node.totals().ended_idle == 2 && node.totals().sessions == 0).await;
	assert!(node.engine.peers(Some("a"))[0].over.is_none());
	node.engine.shutdown().await;
}

// "Keep an older established session of the same source and device readable for 10 s before removing it." The client opens such a session when it has sent 2^30 packets under one key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_session_from_the_same_source_takes_over_and_the_old_keys_are_read_for_ten_seconds() {
	let time = time!();
	let node = launch("rekey", time, |_| {}).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	a.connect(time).await;
	let keepalive = a.sealed(&[]);
	a.open(time.secs(), &keepalive).await;
	assert_eq!(a.chunk(SECOND).await, Some(None));
	let totals = node.totals();
	assert_eq!((totals.opened, totals.established, totals.sessions, totals.pending), (2, 2, 2, 0), "{totals:?}");
	// A packet under the old keys still reaches the tunnel, and its answer comes under the new ones.
	let (mut syn, mut out) = (TcpHeader::new(40000, 80, 1000, 65535), Vec::new());
	syn.syn = true;
	PacketBuilder::ipv4(address(0), PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
	let datagram = a.sealed(&out);
	a.put_before(&datagram).await;
	assert!(a.recv(SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| tcp.syn && tcp.ack && tcp.destination_port == 40000)).await.is_some(), "a packet under the keys of the session before was not read");
	a.reset(0, PUBLIC, 40000, 80, 1001).await;
	node.advance(11).await;
	eventually("the session before was not removed", || node.totals().ended_replaced == 1 && node.totals().sessions == 1).await;
	let (keepalive, unknown) = (a.sealed(&[]), node.totals().unknown);
	a.drain().await;
	a.put_before(&keepalive).await;
	assert!(a.silence().await && node.totals().unknown == unknown + 1, "the keys of a removed session were still read");
	assert_eq!(a.leaves(0, 40001).await.as_deref(), Some("main"));
	// The WireGuard rekey travels in data packets like everything else: a new handshake on the session, answered on it.
	let init = a.initiation();
	a.put(&init).await;
	let Some(Some(response)) = a.chunk(SECOND).await else {panic!("a handshake inside the session was not answered")};
	let mut out = vec![0u8; 2048];
	let TunnResult::WriteToNetwork(keepalive) = a.tunn.decapsulate(None, &response, &mut out) else {panic!("no handshake response")};
	let keepalive = keepalive.to_vec();
	a.put(&keepalive).await;
	assert_eq!((a.leaves(0, 40002).await.as_deref(), node.totals().opened), (Some("main"), 2));
	node.engine.shutdown().await;
}

/// An opening packet of device `n` around a datagram that is no WireGuard message of anybody, so its session stays pending.
async fn pending(n: usize, node: SocketAddr, at: u64) -> Device {
	let mut device = Device::new(n, secret(n), node).await;
	device.open(at, &[0xfe; 40]).await;
	device
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_has_two_pending_sessions_and_sixteen_proofs_at_once() {
	let time = time!();
	let node = launch("pending", time, |_| {}).await;
	// "A device may have 2 pending sessions, and further proofs are refused while it has."
	let (mut first, _second, mut third) = (pending(0, node.addr, time.secs()).await, pending(0, node.addr, time.secs()).await, pending(0, node.addr, time.secs()).await);
	eventually("the opening packets were not counted", || node.totals().opened + node.totals().pending_full == 3).await;
	let totals = node.totals();
	assert_eq!((totals.opened, totals.pending, totals.pending_full, totals.tunnel), (2, 2, 1, 2), "{totals:?}");
	assert!(first.silence().await && third.silence().await, "a pending session was answered");
	// Another device is not held up by it, and neither is the device itself once a session ends.
	let mut b = Device::new(1, secret(1), node.addr).await;
	b.connect(time).await;
	// "In place of a pending session of the same source and device if there is one": from one source the device opens again and again, until its allowance of 16 accepted proofs is spent.
	let mut again = first;
	for _ in 0..20 {again.open(time.secs(), &[0xfe; 40]).await;}
	eventually("the opening packets were not counted", || node.totals().opened + node.totals().device_rate == 23).await;
	let totals = node.totals();
	assert!(totals.device_rate >= 5 && totals.pending == 2 && totals.ended_replaced == totals.opened - 3, "{totals:?}");
	// Its real client still gets in when the pending sessions have ended and the allowance has filled up again, which the test's clock brings about.
	node.advance(20).await;
	eventually("the pending sessions did not end", || node.totals().pending == 0).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	a.connect(time).await;
	assert_eq!(a.leaves(0, 40000).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_a_listener_and_a_session_have_their_limits() {
	let time = time!();
	// A pool of three sessions, and two accepted proofs at once from one source, then one a second.
	let mut node = launch("limits", time, |doc| {
		doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 3});
		doc["replay"] = json!({"per_source": {"burst": 2, "rate": 1}});
	}).await;
	let (mut a, mut b, mut c, mut d) = (Device::new(0, secret(0), node.addr).await, Device::new(1, secret(1), node.addr).await, Device::new(2, secret(2), node.addr).await, Device::new(3, secret(3), node.addr).await);
	assert!(a.try_connect(time.secs()).await && b.try_connect(time.secs()).await);
	// "Accepted proofs per source": every test device comes from 127.0.0.1, and the third proof within the second is one too many.
	assert!(!c.try_connect(time.secs()).await);
	assert_eq!((node.totals().source_rate, node.totals().opened), (1, 2));
	node.advance(5).await;
	c.connect(time).await;
	// "A full session table refuses new proofs." The pool is full with three devices, whatever the source's allowance.
	node.advance(5).await;
	assert!(!d.try_connect(time.secs()).await);
	assert_eq!((node.totals().pool, node.totals().opened, node.totals().sessions), (1, 3, 3));
	// A larger pool by reload keeps the sessions there are, and lets the fourth device in.
	node.reload(|doc| {
		doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 100});
		doc["replay"] = json!({"per_source": {"burst": 50, "rate": 50}});
	}).await;
	assert_eq!((node.totals().sessions, a.leaves(0, 40000).await.as_deref()), (3, Some("main")));
	d.connect(time).await;
	// "WireGuard handshake initiations per session: burst 3, then 1 a second." The opening packet's was the first.
	for _ in 0..5 {
		let init = a.initiation();
		a.put(&init).await;
	}
	eventually("the handshakes above the session's allowance were not counted", || node.totals().handshakes >= 2).await;
	// "A source that already has sessions of 4 other devices: drop." One socket speaks for five devices, as behind a translator that hands one port on.
	let shared = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	for n in [1, 2, 3, 4, 5] {shared.send_to(&Device::new(n, secret(n), node.addr).await.opening(time.secs(), &[0xfe; 40]).0, node.addr).await.unwrap();}
	eventually("the opening packets of the shared source were not counted", || node.totals().source_devices == 1).await;
	assert_eq!((node.totals().pending, quiet(&shared).await), (4, true));
	node.engine.shutdown().await;
}

// "Sessions per device: 8. A device at its own session limit replaces its own oldest session, but only once the new session is established."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ninth_session_of_a_device_takes_the_place_of_its_oldest() {
	let time = time!();
	let node = launch("nine", time, |_| {}).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	a.connect(time).await;
	for round in 1..9 {
		a.rebind().await;
		let keepalive = a.sealed(&[]);
		a.open(time.secs(), &keepalive).await;
		assert_eq!(a.chunk(SECOND).await, Some(None), "session {round} was not established");
	}
	eventually("the oldest session was not replaced", || node.totals().ended_displaced == 1 && node.totals().sessions == 8).await;
	assert_eq!((node.totals().established, a.leaves(0, 40000).await.as_deref()), (9, Some("main")));
	node.engine.shutdown().await;
}

// "It is rebuilt on reload and when the epoch changes, away from the packet path, and swapped in whole."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_epoch_that_changes_leaves_live_sessions_alone_and_new_ones_open_under_its_tags() {
	let time = time!();
	let node = launch("epoch", time, |_| {}).await;
	let (mut a, mut b, mut c) = (Device::new(0, secret(0), node.addr).await, Device::new(1, secret(1), node.addr).await, Device::new(2, secret(2), node.addr).await);
	a.connect(time).await;
	node.advance(120).await;
	eventually("the tag table did not follow the epoch", || node.totals().table_rebuilds >= 1).await;
	assert_eq!((a.leaves(0, 40000).await.as_deref(), node.totals().sessions, node.totals().tags), (Some("main"), 1, 3 * KEYS.len()));
	b.connect(time).await;
	// Several epochs at once, as after a clock that was set: the table before knows none of the new tags, and the node says that it refused everybody until it had a new one.
	node.advance(600).await;
	eventually("the tag table did not follow the clock", || node.totals().table_rebuilds >= 2 && node.totals().table_rebuilds_late >= 1).await;
	c.connect(time).await;
	assert!(logged("every opening packet was refused until now"));
	assert_eq!((c.leaves(2, 40001).await.as_deref(), node.totals().tag_collisions), (Some("main"), 0));
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_keeps_the_sessions_of_a_listener_that_stays_and_ends_those_of_one_that_goes() {
	let time = time!();
	let mut node = launch("reload", time, |_| {}).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	a.connect(time).await;
	// A reload that leaves the tunnel and the transport as they are: the session is the one it was.
	node.reload(|doc| doc["notices"] = json!([{"text": "maintenance tonight"}])).await;
	node.reload(|doc| doc["inbounds"][0]["padding"] = json!({"wide": 600, "normal": 100})).await;
	assert_eq!((a.leaves(0, 40000).await.as_deref(), node.totals().sessions, node.totals().opened), (Some("main"), 1, 1));
	// The same address for a plain `udp` transport: the socket is kept, its sessions are not, and a WireGuard peer is answered on it as it is.
	let addr = node.addr.to_string();
	node.reload(|doc| doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": addr}])).await;
	assert_eq!((node.totals().sessions, node.totals().tags), (0, 0));
	let init = a.initiation();
	a.drain().await;
	a.sock.send_to(&init, node.addr).await.unwrap();
	let mut answer = [0u8; 2048];
	let (count, _) = timeout(SECOND, a.sock.recv_from(&mut answer)).await.expect("a plain handshake was not answered").unwrap();
	assert_eq!((count, answer[0]), (92, 2));
	// And back: an opening packet opens a session again, and the plain handshake is a stranger's datagram.
	node.reload(|doc| doc["inbounds"][0]["transports"] = json!([{"type": "udp-obfs", "listen": addr}])).await;
	let (init, unknown) = (a.initiation(), node.totals().unknown);
	a.sock.send_to(&init, node.addr).await.unwrap();
	assert!(a.silence().await && node.totals().unknown == unknown + 1);
	a.connect(time).await;
	assert_eq!(a.leaves(0, 40001).await.as_deref(), Some("main"));
	// A tunnel that restarts, here for another `mtu`, takes its sessions with it.
	node.reload(|doc| doc["inbounds"][0]["mtu"] = json!(1300)).await;
	assert_eq!(node.totals().sessions, 0);
	node.engine.shutdown().await;
}

// "No writable path for the file, or the lock is held: `veilway run` refuses to start a config that has an obfuscated transport."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_obfuscated_transport_runs_without_a_replay_file_the_node_holds_alone() {
	let time = time!();
	let (dir, addr) = (scratch("refused"), listen());
	let doc = document(proxy().await, addr);
	let refused = |result: anyhow::Result<Engine>| format!("{:#}", result.err().expect("the node started"));
	let none = refused(start(&doc, None, time).await);
	assert!(none.contains("needs a replay file") && none.contains("inbound `home`"), "{none}");
	let nowhere = refused(start(&doc, Some(dir.join("missing").join("replay")), time).await);
	assert!(nowhere.contains("lock file cannot be made") && nowhere.contains("--replay"), "{nowhere}");
	// A node that runs holds the file, and a second one on it does not start. Nothing of the first is disturbed.
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let first = start(&doc, Some(dir.join("replay")), time).await.unwrap();
	let mut second = doc.clone();
	second["inbounds"][0]["transports"][0]["listen"] = json!(listen().to_string());
	let held = refused(start(&second, Some(dir.join("replay")), time).await);
	assert!(held.contains("another node holds its lock"), "{held}");
	let mut a = Device::new(0, secret(0), addr).await;
	a.connect(time).await;
	first.shutdown().await;
	// A node without such a transport needs none and makes none, and a reload that brings one in is refused the same way while the running config stays.
	let (mut plain, mut native) = (doc.clone(), doc.clone());
	(plain["inbounds"][0]["transports"], plain["inbounds"][0]["mtu"]) = (json!([{"type": "udp", "listen": listen().to_string()}]), json!(1390));
	(native["inbounds"][0]["transports"][0]["listen"], native["inbounds"][0]["mtu"]) = (json!(listen().to_string()), json!(1390));
	let engine = start(&plain, None, time).await.unwrap();
	let reloaded = engine.reload(native.to_string().into_bytes(), None).await.err().expect("a reload brought in a transport without a replay file").to_string();
	assert!(reloaded.contains("needs a replay file") && engine.replay().is_none() && engine.snapshot().generation == 1, "{reloaded}");
	engine.shutdown().await;
}

// The table of "The replay file": a clean stop, a start after it, and a start after a kill.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_opening_packet_is_accepted_once_across_a_clean_stop_and_across_a_kill() {
	let time = time!();
	let node = launch("restarts", time, |_| {}).await;
	let (mut a, replay) = (Device::new(0, secret(0), node.addr).await, node.dir.join("replay"));
	let init = a.initiation();
	let spent = a.open(time.secs(), &init).await;
	assert!(a.chunk(SECOND).await.is_some_and(|answer| answer.is_some()));
	node.engine.shutdown().await;
	// "Clean stop: written to the file with the clean mark." One entry of 41 bytes, and mode 600.
	let file = std::fs::read(&replay).unwrap();
	assert_eq!((file.len(), file[12], u32::from_be_bytes(file[32..36].try_into().unwrap())), (68 + 41, 1, 1));
	#[cfg(unix)]
	assert_eq!(std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&replay).unwrap()) & 0o777, 0o600);
	// "Start after a clean stop: no refusal because of the restart." The packet from before is known, and a new one opens a session.
	let mut doc = node.doc.clone();
	let addr = listen();
	doc["inbounds"][0]["transports"][0]["listen"] = json!(addr.to_string());
	let second = start(&doc, Some(replay.clone()), time).await.unwrap();
	assert_eq!((std::fs::read(&replay).unwrap()[12], second.replay().unwrap().entries), (0, 1), "the first file after a clean start still has the mark");
	let again = stranger(addr, std::slice::from_ref(&spent)).await;
	assert!(quiet(&again).await && second.obfs().seen == 1, "{:?}", second.obfs());
	let mut b = Device::new(1, secret(1), addr).await;
	let init = b.initiation();
	let later = b.open(time.secs(), &init).await;
	assert!(b.chunk(SECOND).await.is_some_and(|answer| answer.is_some()), "a new opening packet was refused after a clean start");
	// A kill: nothing is written, and the lock goes with the process. "Start after anything else: the cache is empty and the floor is the written limit."
	let limit = second.replay().unwrap().limit;
	drop(second);
	let addr = listen();
	doc["inbounds"][0]["transports"][0]["listen"] = json!(addr.to_string());
	let third = start(&doc, Some(replay.clone()), time).await.unwrap();
	let status = third.replay().unwrap();
	// It is what a start after a kill costs, and no fault of the clock.
	assert!(status.floor >= limit && status.entries == 0 && status.wait > 0 && !status.floor_ahead, "{status:?}");
	let again = stranger(addr, &[spent, later]).await;
	assert!(quiet(&again).await && third.obfs().floor == 2, "{:?}", third.obfs());
	// "Clients with a correct clock are refused until the clock passes the floor: up to 20 s."
	let mut c = Device::new(2, secret(2), addr).await;
	assert!(!c.try_connect(time.secs()).await && third.obfs().floor == 3 && third.replay().unwrap().refused_floor_ahead == 0);
	time.ahead.fetch_add(STEP as i64 + 1, Ordering::SeqCst);
	eventually("the replay limit did not follow the clock", || third.replay().unwrap().limit >= time.secs()).await;
	c.connect(time).await;
	third.shutdown().await;
}

// "Start with no replay file, or with one that cannot be used: every proof is refused for `W`, 60 s." And "an unusable file is renamed with `.bad` added, logged at error, and handled exactly as no replay file".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_without_a_usable_replay_file_refuses_every_proof_for_the_window() {
	for case in ["missing", "damaged"] {
		let time = time!();
		let (dir, addr) = (scratch(case), listen());
		let (doc, replay, garbage) = (document(proxy().await, addr), dir.join("replay"), b"VWREPLAY and then nothing a node ever wrote, for sixty-eight bytes and more".to_vec());
		if case == "damaged" {std::fs::write(&replay, &garbage).unwrap()}
		let engine = start(&doc, Some(replay.clone()), time).await.unwrap();
		let status = engine.replay().unwrap();
		assert_eq!((status.floor.abs_diff(status.clock + WINDOW) <= 2, status.limit, status.entries, status.floor_ahead, status.wait > 0, status.ready), (true, status.floor, 0, false, true, true), "{case}: {status:?}");
		assert_eq!(std::fs::read(dir.join("replay.bad")).ok(), (case == "damaged").then_some(garbage), "{case}");
		assert_eq!(std::fs::read(&replay).unwrap().len(), 68, "{case}");
		let mut a = Device::new(0, secret(0), addr).await;
		assert!(!a.try_connect(time.secs()).await && engine.obfs().floor == 1 && engine.replay().unwrap().refused_floor_ahead == 0, "{case}: {:?}", engine.obfs());
		// A start is no fault of the clock: the node's timer has run by now, and it has not logged this floor as one that a reset is the answer to.
		tokio::time::sleep(Duration::from_millis(1300)).await;
		assert!(!logged(&format!("(floor {}, clock", status.floor)), "{case}: a start was logged as a floor ahead of the clock");
		time.ahead.fetch_add(WINDOW as i64 + 1, Ordering::SeqCst);
		eventually("the replay limit did not follow the clock", || engine.replay().unwrap().limit >= time.secs()).await;
		a.connect(time).await;
		assert_eq!(engine.replay().unwrap().wait, 0);
		engine.shutdown().await;
	}
	assert!(logged("replay.bad") && logged("there was none"));
}

// "The file cannot be written while the node runs: the node accepts no proof once the clock has passed the limit in use, within about 20 s. Logged at error, at most once a minute, and counted."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_cannot_write_its_replay_file_opens_no_new_session_and_says_so() {
	let time = time!();
	let node = launch("unwritten", time, |_| {}).await;
	let (mut a, mut b) = (Device::new(0, secret(0), node.addr).await, Device::new(1, secret(1), node.addr).await);
	a.connect(time).await;
	// A directory where the temporary file goes makes every write fail, also for root.
	std::fs::create_dir(node.dir.join("replay.tmp")).unwrap();
	let limit = node.engine.replay().unwrap().limit;
	time.ahead.fetch_add(30, Ordering::SeqCst);
	eventually("the failed writes were not counted", || node.engine.replay().unwrap().write_failures >= 2).await;
	assert_eq!(node.engine.replay().unwrap().limit, limit);
	// The opening packet waits for a write that never ends well, and is dropped when the write deadline has passed for it.
	assert!(!b.try_connect(time.secs()).await && node.totals().waited == 1 && node.totals().opened == 1, "{:?}", node.totals());
	eventually("the opening packet that waited for the limit was not dropped", || node.totals().limit == 1).await;
	// A session that is open is not a proof: it goes on.
	assert_eq!(a.leaves(0, 40000).await.as_deref(), Some("main"));
	assert!(logged("it could not be written") && logged("so the limit cannot rise"));
	std::fs::remove_dir(node.dir.join("replay.tmp")).unwrap();
	eventually("the replay limit was not written once the disk took writes again", || node.engine.replay().unwrap().limit >= time.secs()).await;
	b.connect(time).await;
	node.engine.shutdown().await;
}

// "When the floor is ahead of the clock": the node logs at error and counts, and only a reset ends it, which touches nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_floor_ahead_of_the_clock_is_said_loudly_and_a_reset_ends_it() {
	let time = time!();
	let (dir, addr) = (scratch("ahead"), listen());
	let (doc, replay) = (document(proxy().await, addr), dir.join("replay"));
	// What a node leaves whose clock ran an hour ahead and that was killed before the clock was put right.
	let limit = time.secs() + 3600;
	seed(&replay, time.secs() - 100, limit);
	let engine = start(&doc, Some(replay.clone()), time).await.unwrap();
	let (status, usage) = (engine.replay().unwrap(), engine.counters().users);
	assert_eq!((status.floor, status.limit, status.floor_ahead), (limit, limit, true), "{status:?}");
	let mut a = Device::new(0, secret(0), addr).await;
	assert!(!a.try_connect(time.secs()).await && engine.replay().unwrap().refused_floor_ahead == 1 && engine.obfs().floor == 1);
	eventually("the floor that is ahead was not logged", || logged("ahead of the node's clock") && logged("veilway replay reset")).await;
	// Waiting does not end it within any time a user has.
	time.ahead.fetch_add(120, Ordering::SeqCst);
	assert!(!a.try_connect(time.secs()).await);
	assert_eq!(engine.reset_replay().await, Some(Reset::Done(engine.replay().unwrap().floor)));
	let status = engine.replay().unwrap();
	assert_eq!((status.floor.abs_diff(status.clock + WINDOW) <= 2, status.limit, status.disk, status.entries, status.resets, status.ready), (true, status.floor, status.floor, 0, 1, true), "{status:?}");
	let file = std::fs::read(&replay).unwrap();
	assert_eq!((u64::from_be_bytes(file[16..24].try_into().unwrap()), u64::from_be_bytes(file[24..32].try_into().unwrap())), (status.floor, status.limit));
	// "It costs one refusal period of `W`", and usage is what it was.
	assert!(!a.try_connect(time.secs()).await);
	time.ahead.fetch_add(WINDOW as i64 + 1, Ordering::SeqCst);
	eventually("the replay limit did not follow the clock", || engine.replay().unwrap().limit >= time.secs()).await;
	a.connect(time).await;
	assert_eq!(engine.counters().users[1..], usage[1..]);
	eventually("the end of the state was not logged", || logged("no longer ahead of the node's clock")).await;
	assert!(logged("reset at the operator's word"));
	engine.shutdown().await;
}

// A reload brings the first obfuscated transport in: the replay memory is taken then, and with no file there it refuses for the window like any first start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_that_brings_the_first_obfuscated_transport_in_takes_the_replay_file_then() {
	let time = time!();
	let (dir, addr, other) = (scratch("late"), listen(), listen());
	let mut doc = document(proxy().await, addr);
	doc["inbounds"][0]["mtu"] = json!(1390);
	doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": other.to_string()}]);
	let engine = start(&doc, Some(dir.join("replay")), time).await.unwrap();
	assert!(engine.replay().is_none() && !dir.join("replay").exists());
	doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": other.to_string()}, {"type": "udp-obfs", "listen": addr.to_string()}]);
	engine.reload(doc.to_string().into_bytes(), None).await.unwrap();
	assert!(engine.replay().is_some_and(|replay| replay.wait > 0 && !replay.floor_ahead) && dir.join("replay").exists());
	let mut a = Device::new(0, secret(0), addr).await;
	assert!(!a.try_connect(time.secs()).await);
	time.ahead.fetch_add(WINDOW as i64 + 1, Ordering::SeqCst);
	eventually("the replay limit did not follow the clock", || engine.replay().unwrap().limit >= time.secs()).await;
	a.connect(time).await;
	assert_eq!((a.leaves(0, 40000).await.as_deref(), engine.peers(Some("a"))[0].over), (Some("main"), Some(Over::UdpObfs)));
	engine.shutdown().await;
}

// An opening packet above the written limit is not dropped: dropped, it would be good a moment later for whoever saw it, from any address, a second before its device tries again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_opening_packet_that_waits_for_the_limit_is_answered_to_its_device_and_to_nobody_who_copies_it() {
	let time = time!();
	let node = launch("raise", time, |_| {}).await;
	let mut a = Device::new(0, secret(0), node.addr).await;
	// The device's clock is 40 seconds ahead: inside the window and above the limit, which is at most 20 seconds ahead of the node's clock.
	let (init, at) = (a.initiation(), time.secs() + 40);
	let packet = a.open(at, &init).await;
	// Somebody who sees the packet sends it at once from another address, before the node has written the limit.
	let observer = stranger(node.addr, std::slice::from_ref(&packet)).await;
	assert!(a.chunk(SECOND).await.is_some_and(|answer| answer.is_some_and(|response| response[0] == 2)), "the device was not answered once the limit was written");
	assert!(node.engine.replay().unwrap().limit >= at);
	// And again when the limit is written, which is when a dropped packet would have been good.
	observer.send_to(&packet, node.addr).await.unwrap();
	let late = stranger(node.addr, std::slice::from_ref(&packet)).await;
	assert!(quiet(&observer).await && quiet(&late).await, "a copy of an opening packet that waited for the limit was answered");
	let totals = node.totals();
	assert_eq!((totals.waited, totals.opened, totals.established, totals.sessions, totals.sent), (1, 1, 1, 1, 1), "{totals:?}");
	assert!(totals.limit + totals.seen == 3 && totals.seen >= 2, "{totals:?}");
	node.engine.shutdown().await;
}

// One cut-off path: whatever makes the node cut a device off or drop its WireGuard sessions ends its `udp-obfs` sessions too. A session that lived on would take a recorded handshake initiation for a new one, because the tunnel has forgotten the handshakes it saw (threat model G18).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_way_a_device_is_cut_off_ends_its_sessions() {
	let time = time!();
	let mut node = launch("cut", time, |_| {}).await;
	let mut devices = Vec::new();
	for n in 0..5 {
		let mut device = Device::new(n, secret(n), node.addr).await;
		device.connect(time).await;
		assert_eq!(device.leaves(n, 40000).await.as_deref(), Some("main"));
		devices.push(device);
	}
	// A rekey of device 0 inside its session, which somebody records.
	let init = devices[0].initiation();
	let recorded = devices[0].put(&init).await;
	assert!(devices[0].chunk(SECOND).await.is_some_and(|answer| answer.is_some_and(|response| response[0] == 2)), "the rekey was not answered");
	// One reload: the first device gets another address, the second a preshared key, the third's user has expired, the fourth's is disabled, and the fifth's is given a quota that is spent.
	node.reload(|doc| {
		doc["users"][0]["devices"][0]["addresses"] = json!(["10.7.0.50"]);
		doc["users"][1]["devices"][0]["preshared_key"] = json!(text(&[0x77; 32]));
		doc["users"][2]["expires_at"] = json!("2020-01-01T00:00:00Z");
		doc["users"][3]["enabled"] = json!(false);
		doc["users"][4]["quota_bytes"] = json!(1);
	}).await;
	let totals = node.totals();
	assert_eq!((totals.ended_revoked, totals.established), (5, 5), "{totals:?}");
	eventually("the ended sessions were not taken out of the table", || node.totals().sessions == 0).await;
	assert!(node.engine.peers(None).iter().all(|peer| peer.over.is_none() && peer.handshake.is_none()));
	// The recorded initiation again from the session's own source: the session is gone, so it is a stranger's datagram and draws nothing.
	let unknown = totals.unknown;
	devices[0].drain().await;
	devices[0].sock.send_to(&recorded, node.addr).await.unwrap();
	assert!(devices[0].silence().await && node.totals().unknown == unknown + 1 && node.totals().sent == totals.sent, "a recorded initiation was answered after its device was cut off");
	// A device that is still one of the config opens a new session. One whose user may not connect is a stranger.
	devices[0].connect(time).await;
	let init = devices[3].initiation();
	devices[3].drain().await;
	devices[3].open(time.secs(), &init).await;
	assert!(devices[3].silence().await && node.totals().opened == 6);
	node.engine.shutdown().await;
}

#[test]
fn the_new_keys_are_validated() {
	let doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:51820".parse().unwrap());
	let errors = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		Config::parse(doc.to_string().as_bytes()).map_or_else(|error| vec![error.path], |config| config.validate(false).errors.iter().map(|error| error.path.clone()).collect())
	};
	assert_eq!(errors(&|_| {}), Vec::<String>::new());
	for (case, change, path) in [
		("udp-obfs on a wireguard inbound", &(|doc: &mut Value| {
			doc["inbounds"][0]["type"] = json!("wireguard");
			for user in doc["users"].as_array_mut().unwrap() {user["devices"][0].as_object_mut().unwrap().remove("transport_secrets");}
		}) as &dyn Fn(&mut Value), "inbounds[0].transports[0].type"),
		("a path on udp-obfs", &|doc| doc["inbounds"][0]["transports"][0]["path"] = json!("/wg"), "inbounds[0].transports[0]"),
		("limits on udp", &|doc| doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": "127.0.0.1:51820", "limits": {"sessions": 5}}]), "inbounds[0].transports[0]"),
		("no session at all", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 0}), "inbounds[0].transports[0].limits.sessions"),
		("too many sessions", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"sessions": 1048577}), "inbounds[0].transports[0].limits.sessions"),
		("a limit of another transport", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"undecided": 5}), "inbounds[0].transports[0].limits.undecided"),
		("a limit nobody knows", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"connections": 5}), "inbounds[0].transports[0].limits"),
		("a pool of the proxy path", &|doc| doc["inbounds"][0]["transports"][0]["limits"] = json!({"proxy_connections": 5}), "inbounds[0].transports[0].limits.proxy_connections"),
		("udp and udp-obfs on one address", &|doc| doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": "127.0.0.1:51820"}, {"type": "udp-obfs", "listen": "127.0.0.1:51820"}]), "inbounds[0].transports[1].listen"),
		("wide padding below its bounds", &|doc| doc["inbounds"][0]["padding"] = json!({"wide": 511}), "inbounds[0].padding.wide"),
		("wide padding above its bounds", &|doc| doc["inbounds"][0]["padding"] = json!({"wide": 1024}), "inbounds[0].padding.wide"),
		("normal padding below its bounds", &|doc| doc["inbounds"][0]["padding"] = json!({"normal": 63}), "inbounds[0].padding.normal"),
		("normal padding above its bounds", &|doc| doc["inbounds"][0]["padding"] = json!({"normal": 256}), "inbounds[0].padding.normal"),
		("a padding key nobody knows", &|doc| doc["inbounds"][0]["padding"] = json!({"base": 5}), "inbounds[0].padding"),
		("a replay cache that is too small", &|doc| doc["replay"] = json!({"cache": 1023}), "replay.cache"),
		("a replay cache that is too large", &|doc| doc["replay"] = json!({"cache": 1048577}), "replay.cache"),
		("no proof a second", &|doc| doc["replay"] = json!({"per_source": {"burst": 5, "rate": 0}}), "replay.per_source.rate"),
		("no proof at once", &|doc| doc["replay"] = json!({"per_source": {"burst": 0, "rate": 5}}), "replay.per_source.burst"),
		("a rate without its burst", &|doc| doc["replay"] = json!({"per_source": {"rate": 5}}), "replay.per_source"),
		("a replay key nobody knows", &|doc| doc["replay"] = json!({"file": "x"}), "replay"),
	] {assert_eq!(errors(change), [path], "{case}")}
	// The `mtu` of a `veilway` inbound with `udp-obfs` is 1390 unless it is written, and one above that is a warning: a full-size packet then does not fit a 1500 byte path over IPv6.
	let warned = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		parsed(&doc).validate(false).warnings.iter().map(|warning| warning.path.clone()).collect()
	};
	assert_eq!((parsed(&doc).inbounds[0].mtu(), warned(&|_| {}), warned(&|doc| doc["inbounds"][0]["mtu"] = json!(1390))), (1390, Vec::<String>::new(), Vec::new()));
	assert_eq!(warned(&|doc| doc["inbounds"][0]["mtu"] = json!(1391)), ["inbounds[0].mtu"]);
	let mut plain = doc.clone();
	plain["inbounds"][0]["transports"][0]["type"] = json!("udp");
	assert_eq!(parsed(&plain).inbounds[0].mtu(), 1420);
	// What is set and never used is a warning.
	assert_eq!(warned(&|doc| {
		doc["inbounds"][0]["transports"][0]["type"] = json!("udp");
		doc["inbounds"][0]["padding"] = json!({"wide": 600});
		doc["replay"] = json!({"cache": 2048});
	}), ["inbounds[0].padding", "replay"]);
	// A document that is written back holds the keys as they were given, and adding the transport is a change of the inbound that restarts its tunnel only for the `mtu` it brings.
	let mut full = doc.clone();
	(full["inbounds"][0]["padding"], full["inbounds"][0]["transports"][0]["limits"], full["replay"]) = (json!({"wide": 600, "normal": 100}), json!({"sessions": 5}), json!({"cache": 2048, "per_source": {"burst": 5, "rate": 2}}));
	let written = serde_json::to_value(parsed(&full)).unwrap();
	assert_eq!((&written["inbounds"][0]["padding"], &written["inbounds"][0]["transports"][0], &written["replay"]), (&full["inbounds"][0]["padding"], &full["inbounds"][0]["transports"][0], &full["replay"]));
	let diff = veilway_core::config::Diff::between(&parsed(&plain), &parsed(&full), OffsetDateTime::now_utc());
	assert_eq!((diff.replay, diff.inbound_changes.len(), diff.inbound_changes[0].restart, &diff.inbound_changes[0].transports_started), (true, 1, true, &vec![0]));
	plain["inbounds"][0]["mtu"] = json!(1390);
	full["inbounds"][0]["mtu"] = json!(1390);
	assert!(!veilway_core::config::Diff::between(&parsed(&plain), &parsed(&full), OffsetDateTime::now_utc()).inbound_changes[0].restart);
}
