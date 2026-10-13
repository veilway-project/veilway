//! The control channel of a `veilway` inbound, end to end: a boringtun peer talks TCP to the gateway address inside its tunnel and runs the client's side of the opening exchange from `veilway-proto`.
//! Exits are local SOCKS5 proxies that answer every connection with their own name, so a test sees which exit a flow left through.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TcpOptionElement, TransportHeader};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use veilway_core::config::{Config, REDACTED};
use veilway_core::engine::usage;
use veilway_core::{CutOff, Engine, Event, Options, Reason};
use veilway_proto::control::{self, kind, Addresses, ByeReason, Catalogue, ClientMessage, ErrorCode, ExitStatus, Load, NodeMessage, NodeMessages, Severity, Token, PORT, PREFACE};
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::ClientOpening;
use veilway_proto::NoRandom;

const GATEWAY: [u8; 4] = [10, 7, 0, 1];
const A: [u8; 4] = [10, 7, 0, 2];
const B: [u8; 4] = [10, 7, 0, 3];
const PUBLIC: [u8; 4] = [93, 184, 216, 34];
const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1);
const A6: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 2);
const PUBLIC6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);
// Keys and secrets of tests are fixed patterns, and no secret of anything real.
const NODE: [u8; 32] = [0x10; 32];
const KEY_A: [u8; 32] = [0x21; 32];
const KEY_B: [u8; 32] = [0x22; 32];
const SECRET_A: [u8; 32] = [0xa1; 32];
const SECRET_B: [u8; 32] = [0xb1; 32];
const SECOND: Duration = Duration::from_secs(1);
/// Port 0 is no listen port of a config, so every listener of a test node takes the next one from here.
static NEXT_PORT: AtomicU16 = AtomicU16::new(24000);

fn listen() -> SocketAddr {SocketAddr::from((Ipv4Addr::LOCALHOST, NEXT_PORT.fetch_add(1, Ordering::SeqCst)))}

fn text(key: &[u8; 32]) -> String {veilway_wg::encode_key(key)}

fn public(private: &[u8; 32]) -> [u8; 32] {veilway_wg::public_key(private)}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	bytes.copy_from_slice(&veilway_wg::generate_key()[..bytes.len()]);
	Ok(())
}

/// A SOCKS5 proxy without authentication. A CONNECT is answered with `name` and then held open, and one to port 7000 gets 6000 more bytes behind the name. A UDP ASSOCIATE echoes every datagram with `echo:` in front, and every target asked for is recorded.
async fn proxy(name: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, seen) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())));
	let recorder = seen.clone();
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {return};
			let recorder = recorder.clone();
			tokio::spawn(async move {
				let (mut hello, mut head, mut target) = ([0u8; 2], [0u8; 4], [0u8; 18]);
				if client.read_exact(&mut hello).await.is_err() {return}
				let mut methods = vec![0u8; usize::from(hello[1])];
				if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut head).await.is_err() {return}
				let size = if head[3] == 4 {18} else {6};
				if (head[3] != 1 && head[3] != 4) || client.read_exact(&mut target[..size]).await.is_err() {return}
				let address = |bytes: &[u8]| if bytes.len() == 18 {SocketAddr::from((<[u8; 16]>::try_from(&bytes[..16]).unwrap(), u16::from_be_bytes([bytes[16], bytes[17]])))} else {SocketAddr::from((<[u8; 4]>::try_from(&bytes[..4]).unwrap(), u16::from_be_bytes([bytes[4], bytes[5]])))};
				let (target, mut sink) = (address(&target[..size]), [0u8; 256]);
				if head[1] == 3 {
					let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
					let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
					reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
					if client.write_all(&reply).await.is_err() {return}
					let mut framed = vec![0u8; 65535];
					loop {
						tokio::select! {
							received = relay.recv_from(&mut framed) => {
								let Ok((count, peer)) = received else {return};
								let header = if framed[3] == 4 {22} else {10};
								if count < header {continue}
								recorder.lock().unwrap().push(format!("udp {}", address(&framed[4..header])));
								let _ = relay.send_to(&[&framed[..header], b"echo:", &framed[header..count]].concat(), peer).await;
							}
							_ = client.read(&mut sink) => return,
						}
					}
				}
				recorder.lock().unwrap().push(target.to_string());
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() || client.write_all(name.as_bytes()).await.is_err() {return}
				if target.port() == 7000 && client.write_all(&[0x55; 6000]).await.is_err() {return}
				while client.read(&mut sink).await.is_ok_and(|count| count > 0) {}
			});
		}
	});
	(addr, seen)
}

/// A document with one `veilway` inbound `home` on 10.7.0.1/24, the exits `main` and `alt` through the two proxies, user `a` (10.7.0.2, every exit) and user `b` (10.7.0.3, `main` only). A test changes it before `launch`.
fn document(main: SocketAddr, alt: SocketAddr, listen: SocketAddr) -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [{"tag": "main-proxy", "type": "socks5", "server": main.to_string()}, {"tag": "alt-proxy", "type": "socks5", "server": alt.to_string()}],
		"exits": [{"tag": "main", "name": "Main exit", "country": "DE", "backend": {"type": "netstack", "outbound": "main-proxy"}}, {"tag": "alt", "backend": {"type": "netstack", "outbound": "alt-proxy"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [
			{"name": "a", "exits": "all", "devices": [{"name": "laptop", "public_key": text(&public(&KEY_A)), "transport_secrets": [text(&SECRET_A)], "addresses": ["10.7.0.2"]}]},
			{"name": "b", "exits": ["main"], "devices": [{"name": "phone", "public_key": text(&public(&KEY_B)), "transport_secrets": [text(&SECRET_B)], "addresses": ["10.7.0.3"]}]}
		]
	})
}

struct Node {engine: Engine, addr: SocketAddr, doc: Value, main: Arc<Mutex<Vec<String>>>, alt: Arc<Mutex<Vec<String>>>}

/// The validation errors of `shown` with `list` as the transport secrets of its first device.
fn parsed_errors(shown: &Value, list: Value) -> Vec<String> {
	let mut doc = shown.clone();
	(doc["users"][0]["devices"][0]["transport_secrets"], doc["users"][1]["devices"][0]["transport_secrets"]) = (list, json!([text(&SECRET_B)]));
	(doc["inbounds"][0]["private_key"], doc["notices"]) = (json!(text(&NODE)), json!([]));
	Config::parse(doc.to_string().as_bytes()).unwrap().validate(false).errors.iter().map(|error| error.path.clone()).collect()
}

fn parsed(doc: &Value) -> Config {
	let config = Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("the test config does not parse: {e}"));
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	config
}

/// Starts a node on `document` after `change` had its way with it. The usage pushes of its control channel come 300 to 600 ms apart, so no test waits a minute for one.
async fn launch(change: impl FnOnce(&mut Value), state: Option<PathBuf>) -> Node {
	let ((main, seen_main), (alt, seen_alt), addr) = (proxy("main").await, proxy("alt").await, listen());
	let mut doc = document(main, alt, addr);
	change(&mut doc);
	let engine = veilway_core::start(&parsed(&doc), Options {state, usage_push: 300..=600, ..Options::new("")}).await.unwrap();
	Node {engine, addr, doc, main: seen_main, alt: seen_alt}
}

async fn reload(node: &mut Node, change: impl FnOnce(&mut Value)) {
	change(&mut node.doc);
	parsed(&node.doc);
	node.engine.reload(node.doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
}

/// Waits for something the engine does on its own time.
async fn eventually(what: &str, done: impl Fn() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(5);
	while !done() {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// A WireGuard peer. What it receives and nobody asked for yet waits in `inbox`.
struct Client {tunn: Tunn, sock: UdpSocket, inbox: VecDeque<Vec<u8>>}

impl Client {
	async fn connect(private: [u8; 32], server: SocketAddr) -> Client {Client::try_connect(private, public(&NODE), server).await.expect("the handshake timed out")}

	async fn try_connect(private: [u8; 32], server_public: [u8; 32], server: SocketAddr) -> Option<Client> {
		let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.connect(server).await.unwrap();
		let (mut tunn, mut scratch, mut datagram, mut out) = (Tunn::new(StaticSecret::from(private), PublicKey::from(server_public), None, None, 0, None), vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
		let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut scratch, false) else {panic!("no handshake initiation")};
		sock.send(init).await.unwrap();
		let count = timeout(SECOND, sock.recv(&mut datagram)).await.ok()?.unwrap();
		if let TunnResult::WriteToNetwork(keepalive) = tunn.decapsulate(None, &datagram[..count], &mut out) {sock.send(keepalive).await.unwrap();}
		Some(Client {tunn, sock, inbox: VecDeque::new()})
	}

	async fn send(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn.encapsulate(packet, &mut out) else {panic!("nothing to send")};
		self.sock.send(datagram).await.unwrap();
	}

	/// The next packet `wanted` picks, from the inbox or from the tunnel. Every other packet stays in the inbox.
	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let (left, mut datagram) = (deadline.checked_duration_since(Instant::now())?, vec![0u8; 2048]);
			let count = timeout(left, self.sock.recv(&mut datagram)).await.ok()?.ok()?;
			let mut input: &[u8] = &datagram[..count];
			loop {
				let mut out = vec![0u8; 2048];
				match self.tunn.decapsulate(None, input, &mut out) {
					TunnResult::WriteToNetwork(reply) => {
						let _ = self.sock.send(reply).await;
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
}

fn udp(src: impl Into<IpAddr>, dst: impl Into<IpAddr>, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	match (src.into(), dst.into()) {
		(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(sport, dport).write(&mut out, payload).unwrap(),
		(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(sport, dport).write(&mut out, payload).unwrap(),
		_ => panic!("two address families in one packet"),
	}
	out
}

fn segment(packet: &[u8]) -> Option<(TcpHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	Some((tcp, if let PayloadSlice::Tcp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

/// What the other end of a TCP connection did next.
#[derive(Debug, PartialEq)]
enum Read {Data(Vec<u8>), Fin, Reset, Nothing}

/// The device's end of one TCP connection inside the tunnel, as far as these tests need one: it sends in order, acknowledges what comes in order and never retransmits. `sizes` holds the size of every IP packet that brought it data.
struct Tcp {src: IpAddr, dst: IpAddr, sport: u16, dport: u16, seq: u32, ack: u32, over: Option<Read>, sizes: Vec<usize>}

impl Tcp {
	fn header(&self) -> TcpHeader {
		let mut header = TcpHeader::new(self.sport, self.dport, self.seq, 65535);
		(header.ack, header.acknowledgment_number) = (true, self.ack);
		header
	}

	async fn put(&self, client: &mut Client, header: TcpHeader, data: &[u8]) {
		let mut out = Vec::new();
		match (self.src, self.dst) {
			(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64).tcp_header(header).write(&mut out, data).unwrap(),
			(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64).tcp_header(header).write(&mut out, data).unwrap(),
			_ => panic!("two address families in one connection"),
		}
		client.send(&out).await;
	}

	/// None when the SYN is refused or gets no answer within a second.
	async fn open(client: &mut Client, src: impl Into<IpAddr>, dst: impl Into<IpAddr>, sport: u16, dport: u16) -> Option<Tcp> {Tcp::open_with(client, src.into(), dst.into(), sport, dport, None).await}

	/// `open` with the largest segment the device says it takes in its SYN.
	async fn open_with(client: &mut Client, src: IpAddr, dst: IpAddr, sport: u16, dport: u16, mss: Option<u16>) -> Option<Tcp> {
		let mut tcp = Tcp {src, dst, sport, dport, seq: 1000, ack: 0, over: None, sizes: Vec::new()};
		let mut syn = TcpHeader::new(sport, dport, tcp.seq, 65535);
		syn.syn = true;
		if let Some(mss) = mss {syn.set_options(&[TcpOptionElement::MaximumSegmentSize(mss)]).unwrap()}
		tcp.put(client, syn, &[]).await;
		let (answer, _) = segment(&client.recv(SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (dport, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		(tcp.seq, tcp.ack) = (1001, answer.sequence_number.wrapping_add(1));
		tcp.put(client, tcp.header(), &[]).await;
		Some(tcp)
	}

	async fn send(&mut self, client: &mut Client, data: &[u8]) {
		let mut header = self.header();
		header.psh = true;
		self.put(client, header, data).await;
		self.seq = self.seq.wrapping_add(data.len() as u32);
	}

	async fn read(&mut self, client: &mut Client, budget: Duration) -> Read {
		let (deadline, ports) = (Instant::now() + budget, (self.dport, self.sport));
		loop {
			if let Some(over) = &self.over {return if *over == Read::Fin {Read::Fin} else {Read::Reset}}
			let Some(left) = deadline.checked_duration_since(Instant::now()) else {return Read::Nothing};
			let Some(packet) = client.recv(left, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == ports)).await else {return Read::Nothing};
			let Some((tcp, data)) = segment(&packet) else {continue};
			if tcp.rst {
				self.over = Some(Read::Reset);
				continue;
			}
			if tcp.sequence_number != self.ack || (data.is_empty() && !tcp.fin) {continue}
			self.ack = self.ack.wrapping_add(data.len() as u32).wrapping_add(u32::from(tcp.fin));
			self.put(client, self.header(), &[]).await;
			if tcp.fin {self.over = Some(Read::Fin)}
			if !data.is_empty() {self.sizes.push(packet.len())}
			if !data.is_empty() {return Read::Data(data)}
		}
	}

	/// Everything that comes in until `want` bytes are there or nothing more comes.
	async fn take(&mut self, client: &mut Client, want: usize) -> Vec<u8> {
		let mut got = Vec::new();
		while got.len() < want {
			let Read::Data(data) = self.read(client, Duration::from_secs(3)).await else {break};
			got.extend_from_slice(&data);
		}
		got
	}
}

/// The exit a new TCP flow of a device to `PUBLIC` leaves through: the name its proxy answers with.
async fn leaves(client: &mut Client, src: [u8; 4], sport: u16, dport: u16) -> (Tcp, String) {
	let mut tcp = Tcp::open(client, src, PUBLIC, sport, dport).await.expect("a flow to a public address was not accepted");
	let name = tcp.take(client, 3).await;
	(tcp, String::from_utf8(name).unwrap())
}

type Snapshot = (control::Session, Vec<control::Exit>, control::Usage, Vec<control::Notice>, Vec<control::Hint>);

/// The client's end of a control connection that has opened. `usage` holds every `usage` that was pushed while an answer was waited for.
struct Channel {tcp: Tcp, messages: NodeMessages, rest: Vec<u8>, usage: Vec<control::Usage>}

impl Channel {
	/// Runs the client's side of the opening exchange from `src` to the control port of `gateway`. Err with what the node did when the channel did not open.
	async fn open(client: &mut Client, src: impl Into<IpAddr>, gateway: impl Into<IpAddr>, sport: u16, key: ControlKey) -> Result<Channel, Read> {
		let (mut tcp, mut up, started) = (Tcp::open(client, src, gateway, sport, PORT).await.ok_or(Read::Reset)?, Vec::new(), Instant::now());
		let mut opening = ClientOpening::start(key, 1, Duration::ZERO, &mut random, &mut up).unwrap();
		loop {
			tcp.send(client, &up).await;
			up.clear();
			let data = match tcp.read(client, Duration::from_secs(3)).await {
				Read::Data(data) => data,
				other => return Err(other),
			};
			let mut input = &data[..];
			if let Some(opened) = opening.receive(started.elapsed(), &mut input, &mut up).expect("the node broke the opening exchange") {return Ok(Channel {tcp, messages: opened.messages, rest: input.to_vec(), usage: Vec::new()})}
		}
	}

	/// The control connection of device `a` with its own secret, which must open.
	async fn of_a(client: &mut Client, sport: u16) -> Channel {Channel::open(client, A, GATEWAY, sport, ControlKey::derive(&SECRET_A, &public(&NODE), &public(&KEY_A))).await.expect("the control channel did not open")}

	async fn ask(&mut self, client: &mut Client, message: ClientMessage) {
		let mut bytes = Vec::new();
		message.encode(&mut bytes).unwrap();
		self.tcp.send(client, &bytes).await;
	}

	/// The next message of the node, None when none comes within `budget` or the connection is over.
	async fn next(&mut self, client: &mut Client, budget: Duration) -> Option<NodeMessage> {
		let deadline = Instant::now() + budget;
		loop {
			let mut input = &self.rest[..];
			let message = self.messages.read(&mut input).expect("the node sent what no client reads");
			self.rest = input.to_vec();
			if message.is_some() {return message}
			let Read::Data(data) = self.tcp.read(client, deadline.checked_duration_since(Instant::now())?).await else {return None};
			self.rest = data;
		}
	}

	/// The next message that is no pushed `usage`.
	async fn answer(&mut self, client: &mut Client) -> Option<NodeMessage> {
		loop {
			match self.next(client, Duration::from_secs(3)).await {
				Some(NodeMessage::Usage(usage)) => self.usage.push(usage),
				other => return other,
			}
		}
	}

	/// One whole snapshot, as it comes after the opening and after a `refresh`.
	async fn snapshot(&mut self, client: &mut Client) -> Snapshot {
		let (mut catalogue, mut session, mut exits, mut usage, mut notices) = (Catalogue::default(), None, None, None, None);
		loop {
			match self.next(client, Duration::from_secs(3)).await.expect("the snapshot stopped halfway") {
				NodeMessage::Session(now) => session = Some(now),
				NodeMessage::Exits {last, entries} => exits = catalogue.add(last, entries).expect("the catalogue broke its rules").or(exits),
				NodeMessage::Usage(now) => usage = Some(now),
				NodeMessage::Notices(now) => notices = Some(now),
				NodeMessage::Hints(hints) => return (session.unwrap(), exits.unwrap(), usage.unwrap(), notices.unwrap(), hints),
				other => panic!("{other:?} is no part of a snapshot"),
			}
		}
	}

	/// Whether the node has ended the connection, and how.
	async fn ended(&mut self, client: &mut Client) -> Read {
		loop {
			match self.tcp.read(client, Duration::from_secs(3)).await {
				Read::Data(_) => {}
				end => return end,
			}
		}
	}
}

fn dir(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-control-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_opens_the_channel_reads_its_snapshot_and_moves_its_traffic_to_another_exit() {
	let node = launch(|doc| {
		doc["notices"] = json!([{"severity": "warning", "text": "maintenance tonight"}, {"text": "\u{62e}\u{648}\u{634} \u{622}\u{645}\u{62f}\u{6cc}\u{62f}"}]);
		doc["routing"]["rules"].as_array_mut().unwrap().push(json!({"tag": "pinned", "protocol": ["tcp"], "port": [8080], "action": {"exit": "main"}}));
	}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	let mut channel = Channel::of_a(&mut a, 50000).await;
	let (session, exits, usage, notices, hints) = channel.snapshot(&mut a).await;
	assert_eq!((session.mtu, session.v4, session.v6), (1420, Some(Addresses {device: A.into(), gateway: GATEWAY.into()}), None));
	assert!(session.node_time.abs_diff(time::OffsetDateTime::now_utc().unix_timestamp() as u64) < 5);
	// Only what a client may know of an exit: its tag, its name and country, and four coarse facts.
	assert_eq!(exits.iter().map(|exit| (exit.tag.as_str(), exit.shown_name(), exit.country, exit.selected, exit.configured, exit.working, exit.all_protocols, exit.load)).collect::<Vec<_>>(), [("main", "Main exit".to_string(), Some(*b"DE"), false, true, true, false, Load::Unknown), ("alt", "alt".to_string(), None, false, false, true, false, Load::Unknown)]);
	assert_eq!((usage.quota_bytes, usage.period, usage.expires_at), (0, control::Period::None, 0));
	assert_eq!(notices.iter().map(|notice| (notice.severity, notice.shown_text())).collect::<Vec<_>>(), [(Severity::Warning, "maintenance tonight".to_string()), (Severity::Information, "\u{62e}\u{648}\u{634} \u{622}\u{645}\u{62f}\u{6cc}\u{62f}".to_string())]);
	assert!(hints.is_empty());
	let (mut web, first) = leaves(&mut a, A, 40001, 80).await;
	let (mut pinned, held) = leaves(&mut a, A, 40002, 8080).await;
	assert_eq!((first.as_str(), held.as_str()), ("main", "main"));
	channel.ask(&mut a, ClientMessage::SetExit {tag: "alt".into()}).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: "alt".into()}));
	// The flow that followed the user's exit is broken on purpose, and the one a rule pinned to a named exit is not touched.
	assert_eq!(web.read(&mut a, SECOND).await, Read::Reset);
	pinned.send(&mut a, b"still here").await;
	assert_eq!(pinned.read(&mut a, Duration::from_millis(400)).await, Read::Nothing);
	assert_eq!((leaves(&mut a, A, 40003, 80).await.1.as_str(), leaves(&mut a, A, 40004, 8080).await.1.as_str()), ("alt", "main"));
	assert_eq!((node.main.lock().unwrap().len(), node.alt.lock().unwrap().as_slice()), (3, &["93.184.216.34:80".to_string()][..]));
	// The other user's device is not moved by it, and what the node says of the session is what the device chose.
	let mut b = Client::connect(KEY_B, node.addr).await;
	assert_eq!(leaves(&mut b, B, 40005, 80).await.1, "main");
	let peers = node.engine.peers(None);
	assert_eq!(peers.iter().map(|peer| (peer.user.as_str(), peer.exit.as_deref(), peer.control, peer.mtu)).collect::<Vec<_>>(), [("a", Some("alt"), 1, None), ("b", None, 0, None)]);
	// The traffic is pushed as a new `usage`, and after that an idle tunnel carries nothing: the push itself is no change that calls for the next.
	tokio::time::sleep(Duration::from_millis(700)).await;
	while let Some(message) = channel.next(&mut a, Duration::from_millis(1500)).await {
		let NodeMessage::Usage(pushed) = message else {panic!("{message:?} was pushed")};
		channel.usage.push(pushed);
	}
	assert!(channel.usage.last().is_some_and(|pushed| pushed.up_bytes > usage.up_bytes && pushed.down_bytes > usage.down_bytes && pushed.used_bytes >= pushed.up_bytes), "the traffic was not pushed: {:?}", channel.usage);
	assert_eq!(channel.next(&mut a, Duration::from_millis(1500)).await, None, "an idle tunnel carried a push");
	// An empty tag clears the selection, and a refresh shows it.
	channel.ask(&mut a, ClientMessage::SetExit {tag: String::new()}).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: String::new()}));
	channel.ask(&mut a, ClientMessage::Refresh).await;
	assert!(channel.snapshot(&mut a).await.1.iter().all(|exit| !exit.selected));
	assert_eq!(leaves(&mut a, A, 40006, 80).await.1, "main");
	let totals = node.engine.control();
	assert_eq!((totals.accepted, totals.authenticated, totals.open, totals.exits_selected, totals.auth_failed + totals.malformed + totals.timed_out + totals.replaced), (1, 1, 1, 2, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whoever_does_not_prove_the_secret_of_the_device_in_the_tunnel_is_closed_on() {
	let mut node = launch(|_| {}, None).await;
	let (mut a, mut b) = (Client::connect(KEY_A, node.addr).await, Client::connect(KEY_B, node.addr).await);
	let (key_a, key_b) = (public(&KEY_A), public(&KEY_B));
	// A secret nobody has, the other device's secret, and this device's secret from the other device's tunnel, with either device's key in it.
	assert_eq!(Channel::open(&mut a, A, GATEWAY, 50001, ControlKey::derive(&[0x77; 32], &public(&NODE), &key_a)).await.err(), Some(Read::Reset));
	assert_eq!(Channel::open(&mut a, A, GATEWAY, 50002, ControlKey::derive(&SECRET_B, &public(&NODE), &key_a)).await.err(), Some(Read::Reset));
	assert_eq!(Channel::open(&mut b, B, GATEWAY, 50003, ControlKey::derive(&SECRET_A, &public(&NODE), &key_b)).await.err(), Some(Read::Reset));
	assert_eq!(Channel::open(&mut b, B, GATEWAY, 50004, ControlKey::derive(&SECRET_A, &public(&NODE), &key_a)).await.err(), Some(Read::Reset));
	eventually("the failed credentials were not counted", || node.engine.control().auth_failed == 4).await;
	// What a browser can send, a request in the place of `hello`, an `auth` first, a length no message of the exchange has: each is closed with no byte in answer.
	let mut hello = PREFACE.to_vec();
	hello.extend_from_slice(&[0, 34, kind::HELLO, 1]);
	hello.extend_from_slice(&[7; 32]);
	for (sport, bytes) in [(50010, &b"GET / HTTP/1.1\r\nHost: 10.7.0.1\r\n\r\n"[..]), (50011, &[&PREFACE[..], &[0, 1, kind::REFRESH]].concat()), (50012, &[&PREFACE[..], &[0, 33, kind::AUTH], &[0; 32]].concat()), (50013, &[&PREFACE[..], &[0x10, 0, kind::HELLO], &[0; 64]].concat()), (50014, &[&hello[..], &hello[8..]].concat())] {
		let mut raw = Tcp::open(&mut a, A, GATEWAY, sport, PORT).await.unwrap();
		raw.send(&mut a, bytes).await;
		// The last one gets `hello_reply` for its first `hello`, and nothing but the close for the second.
		let got = raw.read(&mut a, SECOND).await;
		assert!(got == Read::Reset || (sport == 50014 && matches!(&got, Read::Data(reply) if reply.len() == 36) && raw.read(&mut a, SECOND).await == Read::Reset), "{sport}: {got:?}");
	}
	eventually("the malformed openings were not counted", || node.engine.control().malformed == 5).await;
	// After the opening: a message of the exchange, a length over the limit, a body that is not its layout, a tag that is no tag, an unknown type.
	for (sport, bytes) in [(50020, &hello[8..]), (50021, &[0x10, 0x01, kind::SET_EXIT, 1, b'x'][..]), (50022, &[0, 2, kind::SET_MTU, 5]), (50023, &[0, 4, kind::SET_EXIT, 2, b'D', b'E']), (50024, &[0, 1, 0x15]), (50025, &[0, 0, kind::REFRESH])] {
		let mut channel = Channel::of_a(&mut a, sport).await;
		channel.snapshot(&mut a).await;
		channel.tcp.send(&mut a, bytes).await;
		assert_eq!(channel.ended(&mut a).await, Read::Reset, "{sport}");
	}
	eventually("the malformed requests were not counted", || node.engine.control().malformed == 11).await;
	// A tag that is no exit and an exit the user may not use get the same answer, and the catalogue holds the user's exits and no other.
	let mut theirs = Channel::open(&mut b, B, GATEWAY, 50030, ControlKey::derive(&SECRET_B, &public(&NODE), &key_b)).await.unwrap();
	assert_eq!(theirs.snapshot(&mut b).await.1.iter().map(|exit| exit.tag.clone()).collect::<Vec<_>>(), ["main"]);
	for tag in ["alt", "nowhere"] {
		theirs.ask(&mut b, ClientMessage::SetExit {tag: tag.into()}).await;
		assert_eq!(theirs.answer(&mut b).await, Some(NodeMessage::ExitResult {status: ExitStatus::Refused, tag: String::new()}));
	}
	assert_eq!((leaves(&mut b, B, 40010, 80).await.1.as_str(), node.engine.control().exits_refused), ("main", 2));
	// Rotation: with two secrets both open the channel. When the old one is removed, the connection that proved it ends within a second, it opens no new one, and the tunnel itself stays up.
	let fresh = [0xa2; 32];
	reload(&mut node, |doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&fresh), text(&SECRET_A)])).await;
	let (mut old, mut new) = (Channel::of_a(&mut a, 50040).await, Channel::open(&mut a, A, GATEWAY, 50041, ControlKey::derive(&fresh, &public(&NODE), &key_a)).await.unwrap());
	old.snapshot(&mut a).await;
	new.snapshot(&mut a).await;
	let (mut web, _) = leaves(&mut a, A, 40011, 80).await;
	reload(&mut node, |doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&fresh)])).await;
	assert_eq!(old.tcp.read(&mut a, SECOND).await, Read::Reset);
	assert_eq!(Channel::open(&mut a, A, GATEWAY, 50042, ControlKey::derive(&SECRET_A, &public(&NODE), &key_a)).await.err(), Some(Read::Reset));
	new.ask(&mut a, ClientMessage::Refresh).await;
	new.snapshot(&mut a).await;
	web.send(&mut a, b"the flow outlived the secret").await;
	assert_eq!(web.read(&mut a, Duration::from_millis(400)).await, Read::Nothing);
	assert_eq!(node.engine.peers(Some("a"))[0].control, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pools_and_the_rate_limits_hold_and_leave_the_device_its_channel() {
	let node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	// "Connections per device that have not authenticated: 4. A fifth replaces the oldest."
	let mut waiting = Vec::new();
	for sport in 50100..50105 {
		let mut tcp = Tcp::open(&mut a, A, GATEWAY, sport, PORT).await.unwrap();
		tcp.send(&mut a, &PREFACE).await;
		waiting.push(tcp);
	}
	assert_eq!(waiting[0].read(&mut a, SECOND).await, Read::Reset);
	assert_eq!(waiting[4].read(&mut a, Duration::from_millis(300)).await, Read::Nothing);
	// Connections that fail in a loop do not keep the device out, and "authenticated connections per device: 2. A third replaces the oldest."
	let mut open = Vec::new();
	for sport in 50110..50113 {
		let mut channel = Channel::of_a(&mut a, sport).await;
		channel.snapshot(&mut a).await;
		open.push(channel);
	}
	assert_eq!(open[0].ended(&mut a).await, Read::Reset);
	let totals = node.engine.control();
	assert_eq!((totals.open, totals.authenticated, totals.replaced), (2, 3, 3));
	// "Messages from one device: 10 at once, then 1 a second": 40 requests in one segment get at most a few more snapshots than 10, and a 5 byte error each for the rest.
	let (mut flood, started) = (Vec::new(), Instant::now());
	for _ in 0..40 {ClientMessage::Refresh.encode(&mut flood).unwrap()}
	let channel = &mut open[2];
	channel.tcp.send(&mut a, &flood).await;
	let (mut sessions, mut errors) = (0, 0);
	while sessions + errors < 40 {
		match channel.answer(&mut a).await.expect("a flood ended the connection") {
			NodeMessage::Session(_) => sessions += 1,
			NodeMessage::Error {code: ErrorCode::RateLimited, answers: kind::REFRESH} => errors += 1,
			_ => {}
		}
	}
	assert!((10..=10 + started.elapsed().as_secs() as usize + 1).contains(&sessions), "{sessions} snapshots for 40 requests");
	// "`set_exit` from one device: 3 at once, then 1 every 5 s", on top of the limit for every message, which has to have 6 messages to give again first.
	tokio::time::sleep(Duration::from_millis(6500)).await;
	let (mut burst, mut results) = (Vec::new(), Vec::new());
	for tag in ["alt", "", "alt", "", "alt", ""] {ClientMessage::SetExit {tag: tag.into()}.encode(&mut burst).unwrap()}
	channel.tcp.send(&mut a, &burst).await;
	while results.len() < 6 {
		if let NodeMessage::ExitResult {status, tag} = channel.answer(&mut a).await.expect("a flood ended the connection") {results.push((status, tag))}
	}
	// One more may have been earned while the burst was read.
	assert_eq!(results[..3], [(ExitStatus::Selected, "alt".to_string()), (ExitStatus::Selected, String::new()), (ExitStatus::Selected, "alt".to_string())]);
	assert!(results[4..].iter().all(|(status, tag)| *status == ExitStatus::RateLimited && tag == &results[3].1) && results[3].0 != ExitStatus::Refused, "{results:?}");
	assert!(node.engine.control().rate_limited >= 28);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_opening_that_is_not_done_in_ten_seconds_is_closed() {
	let node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	let (mut slow, started) = (Tcp::open(&mut a, A, GATEWAY, 50200, PORT).await.unwrap(), Instant::now());
	// A byte every second keeps the flow alive, and not the exchange.
	let hello = [&PREFACE[..], &[0, 34, kind::HELLO, 1], &[7; 32]].concat();
	let mut closed = Read::Nothing;
	for byte in hello.iter().take(14) {
		slow.send(&mut a, &[*byte]).await;
		closed = slow.read(&mut a, SECOND).await;
		if closed != Read::Nothing {break}
	}
	assert_eq!(closed, Read::Reset);
	assert!((9..=12).contains(&started.elapsed().as_secs()), "closed after {:?}", started.elapsed());
	assert_eq!((node.engine.control().timed_out, node.engine.control().authenticated), (1, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_is_cut_off_is_told_why_and_is_cut_off_within_a_second_all_the_same() {
	let mut node = launch(|doc| doc["users"][0]["quota_bytes"] = json!(30000), None).await;
	let (mut a, mut b, mut events) = (Client::connect(KEY_A, node.addr).await, Client::connect(KEY_B, node.addr).await, node.engine.events());
	let mut channel = Channel::of_a(&mut a, 50300).await;
	assert_eq!(channel.snapshot(&mut a).await.2.quota_bytes, 30000);
	let mut theirs = Channel::open(&mut b, B, GATEWAY, 50301, ControlKey::derive(&SECRET_B, &public(&NODE), &public(&KEY_B))).await.unwrap();
	theirs.snapshot(&mut b).await;
	// Quota: a last `usage` that shows it spent, then `bye`, and then nothing: the session keys are gone.
	for at in 0..30u16 {a.send(&udp(A, PUBLIC, 41000 + at, 9000, &[7; 1200])).await}
	let spent = Instant::now();
	let (mut last, mut bye) = (None, None);
	while let Some(message) = channel.next(&mut a, Duration::from_secs(2)).await {
		match message {
			NodeMessage::Usage(usage) => last = Some(usage),
			NodeMessage::Bye {reason} => bye = Some((reason, spent.elapsed())),
			other => panic!("{other:?} came before the cut-off"),
		}
	}
	assert!(last.is_some_and(|usage| usage.used_bytes >= usage.quota_bytes && usage.quota_bytes == 30000), "no last usage");
	assert!(bye.as_ref().is_some_and(|(reason, after)| *reason == ByeReason::Quota && *after < SECOND), "{bye:?}");
	assert_eq!(channel.tcp.read(&mut a, Duration::from_millis(100)).await, Read::Fin);
	eventually("the user was not cut off", || node.engine.usage("a").is_some_and(|usage| usage.denied.is_some())).await;
	assert!(matches!(events.recv().await, Ok(Event::UserCutOff {user, reason: CutOff::Quota}) if user == "a"));
	assert!(Client::try_connect(KEY_A, public(&NODE), node.addr).await.is_none(), "a device over its quota got a handshake");
	// Disabled by a reload: `bye` with that reason, and no `usage` in front of it.
	let disabled = Instant::now();
	reload(&mut node, |doc| doc["users"][1]["enabled"] = json!(false)).await;
	assert_eq!(theirs.next(&mut b, SECOND).await, Some(NodeMessage::Bye {reason: ByeReason::Disabled}));
	assert!(disabled.elapsed() < SECOND && theirs.tcp.read(&mut b, Duration::from_millis(100)).await == Read::Fin);
	assert!(Client::try_connect(KEY_B, public(&NODE), node.addr).await.is_none(), "a disabled device got a handshake");
	assert_eq!(node.engine.control().byes, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_stops_says_so() {
	let node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	let mut channel = Channel::of_a(&mut a, 50400).await;
	channel.snapshot(&mut a).await;
	node.engine.shutdown().await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::Bye {reason: ByeReason::Stopping}));
	assert_eq!(channel.tcp.read(&mut a, SECOND).await, Read::Fin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_pushes_what_it_changed_and_drops_a_selection_the_user_may_no_longer_make() {
	let mut node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	let mut channel = Channel::of_a(&mut a, 50500).await;
	channel.snapshot(&mut a).await;
	channel.ask(&mut a, ClientMessage::SetExit {tag: "alt".into()}).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: "alt".into()}));
	let (mut web, name) = leaves(&mut a, A, 40100, 80).await;
	assert_eq!(name, "alt");
	// Only what changed for the device is sent again: here the notices and nothing else.
	reload(&mut node, |doc| doc["notices"] = json!([{"text": "new address next week"}])).await;
	let Some(NodeMessage::Notices(notices)) = channel.answer(&mut a).await else {panic!("the new notices were not pushed")};
	assert_eq!(notices.iter().map(|notice| (notice.severity, notice.shown_text())).collect::<Vec<_>>(), [(Severity::Information, "new address next week".to_string())]);
	// A reload that keeps the entitlement keeps the selection, and nothing is pushed for it.
	reload(&mut node, |doc| doc["users"][0]["exits"] = json!(["main", "alt"])).await;
	assert_eq!((node.engine.peers(Some("a"))[0].exit.as_deref(), leaves(&mut a, A, 40101, 80).await.1.as_str()), (Some("alt"), "alt"));
	// One that takes the exit away drops the selection, ends the flow that left through it and sends the catalogue the user has now.
	reload(&mut node, |doc| doc["users"][0]["exits"] = json!(["main"])).await;
	assert_eq!(web.read(&mut a, SECOND).await, Read::Reset);
	let Some(NodeMessage::Exits {last: true, entries}) = channel.answer(&mut a).await else {panic!("the new catalogue was not pushed")};
	assert_eq!(entries.iter().map(|exit| (exit.tag.as_str(), exit.selected, exit.configured)).collect::<Vec<_>>(), [("main", false, true)]);
	assert_eq!((node.engine.peers(Some("a"))[0].exit.as_deref(), node.engine.control().exits_dropped, leaves(&mut a, A, 40102, 80).await.1.as_str()), (None, 1, "main"));
	// Giving the exit back does not bring the selection back.
	reload(&mut node, |doc| doc["users"][0]["exits"] = json!("all")).await;
	assert!(matches!(channel.answer(&mut a).await, Some(NodeMessage::Exits {entries, ..}) if entries.len() == 2 && entries.iter().all(|exit| !exit.selected)));
	assert_eq!(leaves(&mut a, A, 40103, 80).await.1, "main");
	assert_eq!(channel.next(&mut a, Duration::from_millis(300)).await.filter(|message| !matches!(message, NodeMessage::Usage(_))), None);
	// An inbound that is no `veilway` inbound any more has no control channel: the connection ends and the port is the gateway's closed door again.
	reload(&mut node, |doc| doc["inbounds"][0]["type"] = json!("wireguard")).await;
	assert_eq!(channel.ended(&mut a).await, Read::Reset);
	assert!(Tcp::open(&mut a, A, GATEWAY, 50501, PORT).await.is_none());
	assert_eq!(leaves(&mut a, A, 40104, 80).await.1, "main");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_selection_is_kept_in_the_state_file_and_comes_back_with_the_node() {
	let (dir, key) = (dir("state"), text(&public(&KEY_A)));
	let state = dir.join("state.json");
	let stored = || std::fs::read_to_string(&state).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok()).unwrap_or_default();
	let first = launch(|_| {}, Some(state.clone())).await;
	eventually("the state file was not written", || stored()["version"] == json!(1) && stored().get("devices").is_none()).await;
	let mut a = Client::connect(KEY_A, first.addr).await;
	let mut channel = Channel::of_a(&mut a, 50600).await;
	channel.snapshot(&mut a).await;
	// Any number of selections costs no write of the file: it is written when its time comes, every 10 s, and when the node stops. A choice that is lost with a node that is killed in between costs its device one more `set_exit`.
	let (written, started) = (std::fs::metadata(&state).unwrap().modified().unwrap(), Instant::now());
	for tag in ["alt", "", "alt"] {
		channel.ask(&mut a, ClientMessage::SetExit {tag: tag.into()}).await;
		assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: tag.into()}));
		tokio::time::sleep(Duration::from_millis(400)).await;
	}
	assert!(started.elapsed() < Duration::from_secs(8) && std::fs::metadata(&state).unwrap().modified().unwrap() == written && stored().get("devices").is_none(), "a set_exit had the state file written");
	first.engine.shutdown().await;
	// Keyed by the device's public key, next to the users, in a file of the same version as before: a build from before the control channel reads it and passes the devices over.
	assert_eq!((&stored()["version"], &stored()["devices"]), (&json!(1), &json!({key.clone(): {"exit": "alt"}})));
	// The node that starts on the file has the selection before the device says a word.
	let second = launch(|_| {}, Some(state.clone())).await;
	assert_eq!(second.engine.peers(Some("a"))[0].exit.as_deref(), Some("alt"));
	let mut a = Client::connect(KEY_A, second.addr).await;
	assert_eq!(leaves(&mut a, A, 40200, 80).await.1, "alt");
	let mut channel = Channel::of_a(&mut a, 50601).await;
	assert_eq!(channel.snapshot(&mut a).await.1.iter().map(|exit| (exit.tag.as_str(), exit.selected)).collect::<Vec<_>>(), [("main", false), ("alt", true)]);
	second.engine.shutdown().await;
	// A file that names an exit the user may not use, a tag that is no tag and a key that is no key chooses nothing, and costs the users of the file nothing.
	let entry = json!({"used_bytes": 7, "period_start": 0, "up_bytes": 7, "up_packets": 1, "down_bytes": 0, "down_packets": 0});
	std::fs::write(&state, json!({"version": 1, "users": {"a": entry, "b": entry}, "devices": {key.clone(): {"exit": "alt"}, text(&public(&KEY_B)): {"exit": "alt"}, "no key": {"exit": "main"}, text(&[9; 32]): {"exit": "USER"}}}).to_string()).unwrap();
	assert_eq!(usage::inspect(&state), usage::Found::Good {users: 2, skipped: 2});
	let third = launch(|_| {}, Some(state.clone())).await;
	assert_eq!(third.engine.peers(None).iter().map(|peer| (peer.user.as_str(), peer.exit.as_deref())).collect::<Vec<_>>(), [("a", Some("alt")), ("b", None)]);
	assert_eq!((third.engine.usage("a").unwrap().used_bytes, third.engine.usage("b").unwrap().used_bytes, third.engine.control().exits_dropped), (7, 7, 1));
	third.engine.shutdown().await;
	assert_eq!(stored()["devices"], json!({key.clone(): {"exit": "alt"}}), "the selection that was dropped stayed in the file");
	// A file from before there were selections is read as it always was, and so is one whose devices are no object of devices at all.
	std::fs::write(&state, json!({"version": 1, "users": {"a": entry}}).to_string()).unwrap();
	let fourth = launch(|_| {}, Some(state.clone())).await;
	assert_eq!((fourth.engine.usage("a").unwrap().used_bytes, fourth.engine.peers(Some("a"))[0].exit.as_deref()), (7, None));
	fourth.engine.shutdown().await;
	assert!(stored().get("devices").is_none());
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The UDP datagram a device gets back whole or in fragments: the payload, and the size of every IP packet it came in.
async fn datagram(client: &mut Client, from: [u8; 4], sport: u16) -> (Vec<u8>, Vec<usize>) {
	let (mut parts, mut sizes, mut whole) = (Vec::new(), Vec::new(), None);
	while whole.is_none_or(|whole| parts.iter().map(|(_, part): &(usize, Vec<u8>)| part.len()).sum::<usize>() < whole) {
		let Some(packet) = client.recv(Duration::from_secs(3), |packet| packet[0] == 0x45 && packet[9] == 17 && packet[12..16] == from).await else {break};
		let (flags, body) = (u16::from_be_bytes([packet[6], packet[7]]), packet[20..].to_vec());
		let offset = usize::from(flags & 0x1fff) * 8;
		if offset == 0 && u16::from_be_bytes([body[0], body[1]]) != sport {continue}
		if flags & 0x2000 == 0 {whole = Some(offset + body.len())}
		sizes.push(packet.len());
		parts.push((offset, body));
	}
	parts.sort();
	(parts.into_iter().flat_map(|(_, part)| part).skip(8).collect(), sizes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_probes_its_mtu_sets_it_and_gets_nothing_larger_from_then_on() {
	let node = launch(|doc| doc["routing"]["rules"][0]["enabled"] = json!(false), None).await;
	let (mut a, mut b) = (Client::connect(KEY_A, node.addr).await, Client::connect(KEY_B, node.addr).await);
	let mut channel = Channel::of_a(&mut a, 50700).await;
	channel.snapshot(&mut a).await;
	// A datagram to the probe port without a run confirms nothing, and nothing answers it over UDP.
	a.send(&udp(A, GATEWAY, 45000, PORT, &[0; 1252])).await;
	channel.ask(&mut a, ClientMessage::ProbeStart).await;
	let Some(NodeMessage::ProbeToken {token, max_size: 1420}) = channel.answer(&mut a).await else {panic!("no probe token")};
	// Upstream: a probe of each size is confirmed on the channel with the size that arrived. One with another token, one with a filler that is not zero and one that is smaller than any tunnel carries are not.
	for (seq, size) in [(1u8, 1420u16), (2, 1280)] {
		let mut payload = Vec::new();
		control::probe(&token, seq, size, false, &mut payload).unwrap();
		let packet = udp(A, GATEWAY, 45000, PORT, &payload);
		assert_eq!(packet.len(), usize::from(size));
		a.send(&packet).await;
		assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::ProbeAck {seq, size}));
	}
	let (mut other, mut dirty) = (Vec::new(), Vec::new());
	control::probe(&Token([9; 8]), 3, 1300, false, &mut other).unwrap();
	control::probe(&token, 4, 1300, false, &mut dirty).unwrap();
	dirty[100] = 1;
	for payload in [&other[..], &dirty[..], &[&token.0[..], &[5], &[0; 100]].concat()] {a.send(&udp(A, GATEWAY, 45000, PORT, payload)).await}
	// Another device's datagram with this device's token confirms nothing either: the run belongs to the device it was started for.
	let mut theirs = Vec::new();
	control::probe(&token, 6, 1300, false, &mut theirs).unwrap();
	b.send(&udp(B, GATEWAY, 45000, PORT, &theirs)).await;
	eventually("the datagrams that were no probe were not counted", || node.engine.control().probes_refused == 5).await;
	// Downstream: one probe of the size asked for, whole, from the gateway to the port the device named.
	channel.ask(&mut a, ClientMessage::ProbeDown {seq: 7, size: 1300, port: 45001}).await;
	let probe = a.recv(SECOND, |packet| packet[9] == 17 && packet[12..16] == GATEWAY && packet[22..24] == 45001u16.to_be_bytes()).await.expect("no downstream probe");
	assert_eq!((probe.len(), u16::from_be_bytes([probe[20], probe[21]]), control::read_probe(&probe[28..], 1300, false)), (1300, PORT, Ok((token, 7))));
	// One run a minute, and `probe_down` only on the connection that has the token.
	channel.ask(&mut a, ClientMessage::ProbeStart).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::Error {code: ErrorCode::Busy, answers: kind::PROBE_START}));
	let mut second = Channel::of_a(&mut a, 50701).await;
	second.snapshot(&mut a).await;
	second.ask(&mut a, ClientMessage::ProbeDown {seq: 1, size: 1300, port: 45001}).await;
	assert_eq!(second.answer(&mut a).await, Some(NodeMessage::Error {code: ErrorCode::NotApplicable, answers: kind::PROBE_DOWN}));
	// The probes are the channel's own traffic, and no `usage` is pushed for them.
	assert_eq!((channel.next(&mut a, Duration::from_millis(1500)).await, channel.usage.len()), (None, 0));
	// `set_mtu` inside its bounds is taken, and outside them changes nothing.
	for (asked, in_force) in [(1280, 1280), (9000, 1280), (1279, 1280), (1300, 1300), (1421, 1300), (1280, 1280)] {
		channel.ask(&mut a, ClientMessage::SetMtu {mtu: asked}).await;
		assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::MtuResult {mtu: in_force}), "set_mtu {asked}");
	}
	channel.ask(&mut a, ClientMessage::Refresh).await;
	assert_eq!((channel.snapshot(&mut a).await.0.mtu, node.engine.peers(Some("a"))[0].mtu, node.engine.control().mtus_set), (1280, Some(1280), 3));
	// A datagram the node's stack builds for the device, larger than its MTU: fragmented by the node as its sender, never sent whole and never dropped.
	a.send(&udp(A, PUBLIC, 45002, 9000, &[7; 1380])).await;
	let (payload, sizes) = datagram(&mut a, PUBLIC, 9000).await;
	assert_eq!((payload, sizes.len(), sizes.iter().all(|size| *size <= 1280)), ([&b"echo:"[..], &[7; 1380]].concat(), 2, true), "{sizes:?}");
	// One that fits goes whole, and a device that set no MTU gets the large one whole.
	a.send(&udp(A, PUBLIC, 45003, 9000, &[7; 1000])).await;
	assert_eq!(datagram(&mut a, PUBLIC, 9000).await.1, [1033]);
	b.send(&udp(B, PUBLIC, 45004, 9000, &[7; 1380])).await;
	assert_eq!(datagram(&mut b, PUBLIC, 9000).await.1, [1413]);
	// A packet another device sends it, which the node forwards: IPv4 that allows it is fragmented, and the sender of one that prohibits it is told the MTU that fits.
	let mut forwarded = udp(B, A, 45005, 7777, &[5; 1300]);
	forwarded[6] &= !0x40;
	for _ in 0..20 {
		b.send(&forwarded).await;
		if a.recv(Duration::from_millis(150), |packet| packet[9] == 17 && packet[12..16] == B).await.is_some() {break}
	}
	while a.recv(Duration::from_millis(200), |packet| packet[9] == 17 && packet[12..16] == B).await.is_some() {}
	b.inbox.clear();
	b.send(&forwarded).await;
	let (payload, sizes) = datagram(&mut a, B, 45005).await;
	assert_eq!((payload, sizes.len(), sizes.iter().all(|size| *size <= 1280)), (vec![5; 1300], 2, true), "{sizes:?}");
	forwarded[6] |= 0x40;
	b.send(&forwarded).await;
	let error = b.recv(SECOND, |packet| packet[9] == 1 && packet[20] == 3).await.expect("no icmp error for a packet that may not be fragmented");
	assert_eq!((&error[12..16], error[21], &error[24..28]), (&GATEWAY[..], 4, &[0, 0, 5, 0][..]));
	assert!(a.recv(Duration::from_millis(300), |packet| packet[9] == 17 && packet[12..16] == B).await.is_none(), "a packet over the device's mtu was delivered whole");
	assert_eq!(node.engine.dropped(Reason::TooBig), 1);
	// A size outside what the token allows is no value of the field. The requests above have used up what the device may send at once, so one more has to be earned first.
	tokio::time::sleep(Duration::from_millis(1200)).await;
	channel.ask(&mut a, ClientMessage::ProbeDown {seq: 8, size: 1421, port: 45001}).await;
	assert_eq!(channel.ended(&mut a).await, Read::Reset);
	let totals = node.engine.control();
	assert_eq!((totals.probe_runs, totals.probes_confirmed, totals.probes_sent, totals.malformed), (1, 2, 1, 1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_channel_is_reached_from_the_device_s_own_address_on_its_own_inbound_and_from_nowhere_else() {
	let (office, plain, key_c, key_d, secret_c) = ([0x11; 32], [0x12; 32], [0x23; 32], [0x24; 32], [0xc1; 32]);
	let (office_listen, plain_listen) = (listen(), listen());
	let node = launch(|doc| {
		doc["inbounds"].as_array_mut().unwrap().push(json!({"tag": "office", "type": "veilway", "private_key": text(&office), "address": ["10.8.0.1/24"], "transports": [{"type": "udp", "listen": office_listen.to_string()}]}));
		doc["inbounds"].as_array_mut().unwrap().push(json!({"tag": "plain", "type": "wireguard", "private_key": text(&plain), "address": ["10.9.0.1/24"], "transports": [{"type": "udp", "listen": plain_listen.to_string()}]}));
		doc["users"].as_array_mut().unwrap().push(json!({"name": "c", "exits": "all", "devices": [{"name": "desk", "public_key": text(&public(&key_c)), "transport_secrets": [text(&secret_c)], "addresses": ["10.8.0.2"]}]}));
		doc["users"].as_array_mut().unwrap().push(json!({"name": "d", "exits": "all", "devices": [{"name": "old", "public_key": text(&public(&key_d)), "addresses": ["10.9.0.2"]}]}));
	}, None).await;
	let (mut a, mut c, mut d) = (Client::connect(KEY_A, node.addr).await, Client::try_connect(key_c, public(&office), office_listen).await.unwrap(), Client::try_connect(key_d, public(&plain), plain_listen).await.unwrap());
	// Each device of a `veilway` inbound reaches the channel at its own gateway, with the key of its own inbound in its credential.
	Channel::of_a(&mut a, 50800).await.snapshot(&mut a).await;
	let mut theirs = Channel::open(&mut c, [10, 8, 0, 2], [10, 8, 0, 1], 50801, ControlKey::derive(&secret_c, &public(&office), &public(&key_c))).await.unwrap();
	assert_eq!(theirs.snapshot(&mut c).await.0.v4, Some(Addresses {device: [10, 8, 0, 2].into(), gateway: [10, 8, 0, 1].into()}));
	// The gateway of another inbound is a closed door, whichever kind either inbound is, and so is the port on an inbound that is no `veilway` inbound.
	for (who, src, gateway) in [(1, [10, 8, 0, 2], GATEWAY), (0, A, [10, 8, 0, 1]), (0, A, [10, 9, 0, 1]), (2, [10, 9, 0, 2], [10, 9, 0, 1]), (2, [10, 9, 0, 2], GATEWAY)] {
		let client = [&mut a, &mut c, &mut d].into_iter().nth(who).unwrap();
		assert!(Tcp::open(client, src, gateway, 50810 + who as u16, PORT).await.is_none(), "{src:?} reached the control port of {gateway:?}");
		client.send(&udp(src, gateway, 50811, PORT, &[0; 1252])).await;
	}
	// A device that writes another device's address into its packets is not that device.
	let mut syn = TcpHeader::new(50820, PORT, 1, 65535);
	syn.syn = true;
	let mut spoofed = Vec::new();
	PacketBuilder::ipv4(A, GATEWAY, 64).tcp_header(syn).write(&mut spoofed, &[]).unwrap();
	c.send(&spoofed).await;
	assert!(c.recv(Duration::from_millis(300), |packet| segment(packet).is_some()).await.is_none() && a.recv(Duration::from_millis(100), |packet| segment(packet).is_some_and(|(tcp, _)| tcp.destination_port == 50820)).await.is_none());
	eventually("the spoofed packet was not counted", || node.engine.dropped(Reason::SpoofedSource) == 1).await;
	// Nothing of it went through an exit, and nothing but the two real connections was ever taken for a control connection or a probe.
	let totals = node.engine.control();
	assert_eq!((totals.accepted, totals.authenticated, totals.probes_refused, node.engine.dropped(Reason::Gate)), (2, 2, 0, 10));
	assert!(node.main.lock().unwrap().is_empty() && node.alt.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_from_before_the_control_channel_is_served_as_before() {
	let dir = dir("before");
	let node = launch(|doc| {
		doc["inbounds"][0]["type"] = json!("wireguard");
		for user in doc["users"].as_array_mut().unwrap() {user["devices"][0].as_object_mut().unwrap().remove("transport_secrets");}
	}, Some(dir.join("state.json"))).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	// The gateway answers DNS and nothing else: the control port is refused like any other, over TCP and UDP.
	assert!(Tcp::open(&mut a, A, GATEWAY, 50900, PORT).await.is_none());
	a.send(&udp(A, GATEWAY, 50901, PORT, &[0; 1252])).await;
	let error = a.recv(SECOND, |packet| packet[9] == 1 && packet[20] == 3).await.expect("no icmp error from the gateway");
	assert_eq!((&error[12..16], error[21]), (&GATEWAY[..], 13));
	assert_eq!(leaves(&mut a, A, 40900, 80).await.1, "main");
	// A large answer comes whole, as it always did.
	a.send(&udp(A, PUBLIC, 40901, 9000, &[7; 1380])).await;
	assert_eq!(datagram(&mut a, PUBLIC, 9000).await.1, [1413]);
	assert_eq!((node.engine.control(), node.engine.dropped(Reason::Gate)), (veilway_core::ControlTotals::default(), 2));
	assert_eq!(node.engine.peers(Some("a")).iter().map(|peer| (peer.exit.clone(), peer.control, peer.mtu)).collect::<Vec<_>>(), [(None, 0, None)]);
	node.engine.shutdown().await;
	let stored: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("state.json")).unwrap()).unwrap();
	assert!(stored["version"] == json!(1) && stored.get("devices").is_none() && stored["users"]["a"]["up_packets"].as_u64().is_some_and(|packets| packets > 0));
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The UDP datagram a device gets back over IPv6, whole or in fragments: the payload, the size of every IP packet it came in, and the identification of every fragment.
async fn datagram6(client: &mut Client, from: Ipv6Addr) -> (Vec<u8>, Vec<usize>, Vec<u32>) {
	let (mut parts, mut sizes, mut ids, mut whole) = (Vec::new(), Vec::new(), Vec::new(), None);
	while whole.is_none_or(|whole| parts.iter().map(|(_, part): &(usize, Vec<u8>)| part.len()).sum::<usize>() < whole) {
		let Some(packet) = client.recv(Duration::from_secs(3), |packet| packet[0] >> 4 == 6 && packet[8..24] == from.octets() && (packet[6] == 44 && packet[40] == 17 || packet[6] == 17)).await else {break};
		let (offset, more, body) = if packet[6] == 44 {(usize::from(u16::from_be_bytes([packet[42], packet[43]]) & 0xfff8), packet[43] & 1 == 1, packet[48..].to_vec())} else {(0, false, packet[40..].to_vec())};
		if packet[6] == 44 {ids.push(u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]))}
		if !more {whole = Some(offset + body.len())}
		sizes.push(packet.len());
		parts.push((offset, body));
	}
	parts.sort();
	(parts.into_iter().flat_map(|(_, part)| part).skip(8).collect(), sizes, ids)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_channel_is_the_same_at_the_ipv6_gateway_with_probes_and_fragments_in_ipv6() {
	let node = launch(|doc| {
		doc["inbounds"][0]["address"] = json!(["10.7.0.1/24", "fd7a:115c:a1e0::1/64"]);
		doc["users"][0]["devices"][0]["addresses"] = json!(["10.7.0.2", "fd7a:115c:a1e0::2"]);
	}, None).await;
	let (mut a, mut b) = (Client::connect(KEY_A, node.addr).await, Client::connect(KEY_B, node.addr).await);
	let mut six = Channel::open(&mut a, A6, GATEWAY6, 51000, ControlKey::derive(&SECRET_A, &public(&NODE), &public(&KEY_A))).await.expect("the control channel did not open at the ipv6 gateway");
	// The session names both families of a device that has both, and one for a device that has one.
	let (session, exits, ..) = six.snapshot(&mut a).await;
	assert_eq!((session.mtu, session.v4, session.v6, exits.len()), (1420, Some(Addresses {device: A.into(), gateway: GATEWAY.into()}), Some(Addresses {device: A6, gateway: GATEWAY6}), 2));
	let mut theirs = Channel::open(&mut b, B, GATEWAY, 51001, ControlKey::derive(&SECRET_B, &public(&NODE), &public(&KEY_B))).await.unwrap();
	let (session, ..) = theirs.snapshot(&mut b).await;
	assert_eq!((session.v4.map(|pair| pair.device), session.v6), (Some(B.into()), None));
	// The wrong secret is closed on here as it is over IPv4, and the pools are the device's whichever family a connection came by: a third authenticated one replaces the first.
	assert_eq!(Channel::open(&mut a, A6, GATEWAY6, 51002, ControlKey::derive(&SECRET_B, &public(&NODE), &public(&KEY_A))).await.err(), Some(Read::Reset));
	let mut four = Channel::of_a(&mut a, 51003).await;
	four.snapshot(&mut a).await;
	let mut last = Channel::open(&mut a, A6, GATEWAY6, 51004, ControlKey::derive(&SECRET_A, &public(&NODE), &public(&KEY_A))).await.unwrap();
	last.snapshot(&mut a).await;
	assert_eq!(six.ended(&mut a).await, Read::Reset);
	// Probes: 48 bytes of headers in a packet of the size probed, confirmed at the gateway the run was asked at and at no other.
	last.ask(&mut a, ClientMessage::ProbeStart).await;
	let Some(NodeMessage::ProbeToken {token, max_size: 1420}) = last.answer(&mut a).await else {panic!("no probe token")};
	for (seq, size) in [(1u8, 1420u16), (2, 1280)] {
		let mut payload = Vec::new();
		control::probe(&token, seq, size, true, &mut payload).unwrap();
		let packet = udp(A6, GATEWAY6, 45000, PORT, &payload);
		assert_eq!(packet.len(), usize::from(size));
		a.send(&packet).await;
		assert_eq!(last.answer(&mut a).await, Some(NodeMessage::ProbeAck {seq, size}));
	}
	let (mut other, mut dirty) = (Vec::new(), Vec::new());
	control::probe(&token, 3, 1300, false, &mut other).unwrap();
	control::probe(&token, 4, 1300, true, &mut dirty).unwrap();
	dirty[100] = 1;
	// The run's token at the IPv4 gateway of the same inbound, and an IPv6 probe whose filler is not zero.
	a.send(&udp(A, GATEWAY, 45000, PORT, &other)).await;
	a.send(&udp(A6, GATEWAY6, 45000, PORT, &dirty)).await;
	eventually("the probe at another gateway and the one with a filler that is not zero were not refused", || node.engine.control().probes_refused == 2).await;
	last.ask(&mut a, ClientMessage::ProbeDown {seq: 7, size: 1300, port: 45001}).await;
	let probe = a.recv(SECOND, |packet| packet[0] >> 4 == 6 && packet[6] == 17 && packet[8..24] == GATEWAY6.octets() && packet[24..40] == A6.octets()).await.expect("no downstream probe");
	assert_eq!((probe.len(), &probe[40..44], control::read_probe(&probe[48..], 1300, true)), (1300, &[PORT.to_be_bytes(), 45001u16.to_be_bytes()].concat()[..], Ok((token, 7))));
	// A device that set its MTU gets what the node sends it in IPv6 fragments the node made as its sender: each fits, all carry one identification, and together they are the datagram.
	last.ask(&mut a, ClientMessage::SetMtu {mtu: 1280}).await;
	assert_eq!(last.answer(&mut a).await, Some(NodeMessage::MtuResult {mtu: 1280}));
	a.send(&udp(A6, PUBLIC6, 45002, 9000, &[7; 1350])).await;
	let (payload, sizes, ids) = datagram6(&mut a, PUBLIC6).await;
	assert_eq!((payload, sizes.len(), sizes.iter().all(|size| *size <= 1280), ids.len(), ids.iter().all(|id| *id == ids[0])), ([&b"echo:"[..], &[7; 1350]].concat(), 2, true, 2, true), "{sizes:?} {ids:?}");
	a.send(&udp(A6, PUBLIC6, 45003, 9000, &[7; 1000])).await;
	assert_eq!(datagram6(&mut a, PUBLIC6).await.1, [1053]);
	// The next one has the next identification, whatever was fragmented for anybody else in between.
	a.send(&udp(A6, PUBLIC6, 45004, 9000, &[7; 1350])).await;
	assert_eq!(datagram6(&mut a, PUBLIC6).await.2, [ids[0].wrapping_add(1); 2]);
	assert!(node.main.lock().unwrap().iter().any(|target| target == "udp [2606:4700::1111]:9000"));
	let totals = node.engine.control();
	assert_eq!((totals.authenticated, totals.auth_failed, totals.probes_confirmed, totals.probes_sent, totals.open), (4, 1, 2, 1, 3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_in_two_inbounds_proves_itself_to_each_with_that_inbound_s_key_and_has_one_state() {
	let (office, office_listen, there, gateway) = ([0x11; 32], listen(), [10, 8, 0, 2], [10, 8, 0, 1]);
	let node = launch(|doc| {
		doc["inbounds"].as_array_mut().unwrap().push(json!({"tag": "office", "type": "veilway", "private_key": text(&office), "address": ["10.8.0.1/24"], "mtu": 1400, "transports": [{"type": "udp", "listen": office_listen.to_string()}]}));
		doc["users"][0]["devices"][0]["addresses"] = json!(["10.7.0.2", "10.8.0.2"]);
	}, None).await;
	let (mut home, mut work) = (Client::connect(KEY_A, node.addr).await, Client::try_connect(KEY_A, public(&office), office_listen).await.unwrap());
	let key = |inbound: &[u8; 32]| ControlKey::derive(&SECRET_A, &public(inbound), &public(&KEY_A));
	// The credential is bound to the inbound a connection came through: the key made for one opens nothing at the other.
	assert_eq!(Channel::open(&mut work, there, gateway, 52000, key(&NODE)).await.err(), Some(Read::Reset));
	assert_eq!(Channel::open(&mut home, A, GATEWAY, 52001, key(&office)).await.err(), Some(Read::Reset));
	let mut first = Channel::of_a(&mut home, 52002).await;
	assert_eq!(first.snapshot(&mut home).await.0.mtu, 1420);
	let mut second = Channel::open(&mut work, there, gateway, 52003, key(&office)).await.unwrap();
	let (session, ..) = second.snapshot(&mut work).await;
	assert_eq!((session.mtu, session.v4), (1400, Some(Addresses {device: there.into(), gateway: gateway.into()})));
	// Neither tunnel reaches the other's gateway.
	assert!(Tcp::open(&mut home, A, gateway, 52004, PORT).await.is_none() && Tcp::open(&mut work, there, GATEWAY, 52005, PORT).await.is_none());
	// The pools, the limits, the exit and the MTU are the device's, whichever inbound a connection came through. A third authenticated connection replaces the oldest, which came through the other inbound.
	let mut third = Channel::open(&mut work, there, gateway, 52006, key(&office)).await.unwrap();
	third.snapshot(&mut work).await;
	assert_eq!(first.ended(&mut home).await, Read::Reset);
	second.ask(&mut work, ClientMessage::SetExit {tag: "alt".into()}).await;
	assert_eq!(second.answer(&mut work).await, Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: "alt".into()}));
	assert_eq!((leaves(&mut home, A, 40300, 80).await.1.as_str(), leaves(&mut work, there, 40301, 80).await.1.as_str()), ("alt", "alt"));
	// A probe run belongs to the gateway it was asked at: its token confirms nothing at the device's other gateway.
	second.ask(&mut work, ClientMessage::ProbeStart).await;
	let Some(NodeMessage::ProbeToken {token, max_size: 1400}) = second.answer(&mut work).await else {panic!("no probe token with the mtu of the inbound it was asked at")};
	let mut payload = Vec::new();
	control::probe(&token, 1, 1300, false, &mut payload).unwrap();
	home.send(&udp(A, GATEWAY, 45000, PORT, &payload)).await;
	eventually("the token was taken at the other gateway", || node.engine.control().probes_refused == 1).await;
	work.send(&udp(there, gateway, 45000, PORT, &payload)).await;
	assert_eq!(second.answer(&mut work).await, Some(NodeMessage::ProbeAck {seq: 1, size: 1300}));
	// The MTU is one for the device, held to each inbound's own: set through one tunnel it is what the other says too.
	second.ask(&mut work, ClientMessage::SetMtu {mtu: 1300}).await;
	assert_eq!(second.answer(&mut work).await, Some(NodeMessage::MtuResult {mtu: 1300}));
	second.ask(&mut work, ClientMessage::SetMtu {mtu: 1410}).await;
	assert_eq!(second.answer(&mut work).await, Some(NodeMessage::MtuResult {mtu: 1300}), "an mtu above the inbound's was taken");
	let mut fourth = Channel::of_a(&mut home, 52007).await;
	assert_eq!(fourth.snapshot(&mut home).await.0.mtu, 1300);
	assert_eq!(node.engine.peers(Some("a")).iter().map(|peer| (peer.inbound.as_str(), peer.exit.as_deref(), peer.control, peer.mtu)).collect::<Vec<_>>(), [("home", Some("alt"), 2, Some(1300)), ("office", Some("alt"), 2, Some(1300))]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_goes_to_another_user_takes_nothing_of_the_channel_with_it() {
	let mut node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	let mut channel = Channel::of_a(&mut a, 53000).await;
	channel.snapshot(&mut a).await;
	channel.ask(&mut a, ClientMessage::SetExit {tag: "alt".into()}).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: "alt".into()}));
	channel.ask(&mut a, ClientMessage::SetMtu {mtu: 1280}).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::MtuResult {mtu: 1280}));
	assert_eq!(node.engine.peers(Some("a")).iter().map(|peer| (peer.exit.clone(), peer.mtu)).collect::<Vec<_>>(), [(Some("alt".to_string()), Some(1280))]);
	// The same key, address and secret, under another user: for the node that is another device. The one it was is told it is no device any more.
	reload(&mut node, |doc| {
		let device = doc["users"][0]["devices"][0].clone();
		doc["users"][0]["devices"][0] = json!({"name": "other", "public_key": text(&public(&[0x2a; 32])), "transport_secrets": [text(&[0xa9; 32])], "addresses": ["10.7.0.9"]});
		doc["users"].as_array_mut().unwrap().push(json!({"name": "z", "exits": "all", "devices": [device]}));
	}).await;
	assert_eq!(channel.next(&mut a, SECOND).await, Some(NodeMessage::Bye {reason: ByeReason::Disabled}));
	let mut a = Client::connect(KEY_A, node.addr).await;
	assert_eq!(node.engine.peers(Some("z")).iter().map(|peer| (peer.exit.clone(), peer.mtu, peer.control)).collect::<Vec<_>>(), [(None, None, 0)]);
	// It leaves through its new user's exit and is sent a large packet whole, and the channel opens for it with nothing chosen.
	assert_eq!(leaves(&mut a, A, 40350, 80).await.1, "main");
	a.send(&udp(A, PUBLIC, 45300, 9000, &[7; 1380])).await;
	assert_eq!(datagram(&mut a, PUBLIC, 9000).await.1, [1413]);
	let (session, exits, ..) = Channel::of_a(&mut a, 53001).await.snapshot(&mut a).await;
	assert_eq!((session.mtu, exits.iter().filter(|exit| exit.selected).count()), (1420, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fragments_never_reach_the_channel_and_hijack_has_nothing_to_say_about_its_port() {
	let node = launch(|doc| doc["dns"]["hijack"] = json!(true), None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	// A first fragment of a datagram to the probe port and of a SYN to the control port: both are dropped where every fragment from a device is, before anything looks at where they go.
	let (mut probe, mut syn, mut knock) = (udp(A, GATEWAY, 45000, PORT, &[0; 1252]), TcpHeader::new(54000, PORT, 1, 65535), Vec::new());
	syn.syn = true;
	PacketBuilder::ipv4(A, GATEWAY, 64).tcp_header(syn).write(&mut knock, &[]).unwrap();
	(probe[6], knock[6]) = (probe[6] | 0x20, knock[6] | 0x20);
	a.send(&probe).await;
	a.send(&knock).await;
	eventually("the fragments were not dropped as fragments", || node.engine.dropped(Reason::Fragment) == 2).await;
	assert!(a.recv(Duration::from_millis(300), |_| true).await.is_none());
	assert_eq!((node.engine.control().accepted, node.engine.control().probes_refused, node.engine.flows()), (0, 0, 0));
	// With every port 53 flow hijacked the channel opens as it does without, the port on any other address is a destination like any other, and the gateway's port 53 is still the resolver's.
	Channel::of_a(&mut a, 54001).await.snapshot(&mut a).await;
	assert_eq!(leaves(&mut a, A, 40400, PORT).await.1, "main");
	assert!(Tcp::open(&mut a, A, GATEWAY, 40401, 53).await.is_some() && Tcp::open(&mut a, A, GATEWAY, 40402, 80).await.is_none());
	assert_eq!((node.engine.control().accepted, node.main.lock().unwrap().as_slice()), (1, &[format!("93.184.216.34:{PORT}")][..]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_set_exit_that_meets_a_reload_still_moves_the_flows_of_its_device() {
	let mut node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	let mut channel = Channel::of_a(&mut a, 55000).await;
	channel.snapshot(&mut a).await;
	for (round, tag) in ["alt", "", "alt"].into_iter().enumerate() {
		let (mut web, before) = leaves(&mut a, A, 40500 + round as u16, 80).await;
		assert_eq!(before, if tag == "alt" {"main"} else {"alt"});
		// A reload and a `set_exit` at the same moment. Whichever the node takes first, the device is told "selected", and the flow that followed the exit it had is ended.
		node.doc["notices"] = json!([{"text": format!("round {round}")}]);
		let (reloaded, _) = tokio::join!(node.engine.reload(node.doc.to_string().into_bytes(), None), channel.ask(&mut a, ClientMessage::SetExit {tag: tag.into()}));
		assert!(reloaded.is_ok());
		loop {
			match channel.answer(&mut a).await {
				Some(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: now}) if now == tag => break,
				Some(NodeMessage::Notices(_)) => {}
				other => panic!("round {round}: {other:?}"),
			}
		}
		assert_eq!(web.read(&mut a, Duration::from_secs(2)).await, Read::Reset, "round {round}: a flow stayed on the exit the device left");
		assert_eq!(leaves(&mut a, A, 40510 + round as u16, 80).await.1, if tag == "alt" {"alt"} else {"main"});
	}
}

/// The identification of the fragmented datagram the node sends this device next from `PUBLIC`.
async fn identification(client: &mut Client, src: [u8; 4], sport: u16) -> u16 {
	client.send(&udp(src, PUBLIC, sport, 9000, &[7; 1380])).await;
	let mut id = None;
	loop {
		let packet = client.recv(Duration::from_secs(3), |packet| packet[0] == 0x45 && packet[9] == 17 && packet[12..16] == PUBLIC).await.expect("no fragment");
		let flags = u16::from_be_bytes([packet[6], packet[7]]);
		assert!(flags & 0x3fff != 0, "not fragmented");
		id.get_or_insert(u16::from_be_bytes([packet[4], packet[5]]));
		if flags & 0x2000 == 0 {return id.unwrap()}
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fragments_a_device_gets_say_nothing_of_what_was_fragmented_for_another() {
	let node = launch(|_| {}, None).await;
	let (mut a, mut b) = (Client::connect(KEY_A, node.addr).await, Client::connect(KEY_B, node.addr).await);
	let (mut mine, mut theirs) = (Channel::of_a(&mut a, 56000).await, Channel::open(&mut b, B, GATEWAY, 56001, ControlKey::derive(&SECRET_B, &public(&NODE), &public(&KEY_B))).await.unwrap());
	mine.snapshot(&mut a).await;
	theirs.snapshot(&mut b).await;
	mine.ask(&mut a, ClientMessage::SetMtu {mtu: 1280}).await;
	assert_eq!(mine.answer(&mut a).await, Some(NodeMessage::MtuResult {mtu: 1280}));
	theirs.ask(&mut b, ClientMessage::SetMtu {mtu: 1280}).await;
	assert_eq!(theirs.answer(&mut b).await, Some(NodeMessage::MtuResult {mtu: 1280}));
	// One identification counter for the node would let `a` count the packets fragmented for `b` between two of its own.
	let first = identification(&mut a, A, 45100).await;
	for at in 0..5 {identification(&mut b, B, 45200 + at).await;}
	assert_eq!(identification(&mut a, A, 45101).await.wrapping_sub(first), 1, "the identification of a device's fragments moved with another user's packets");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bye_follows_what_the_device_has_not_acknowledged_yet() {
	let mut node = launch(|_| {}, None).await;
	let mut b = Client::connect(KEY_B, node.addr).await;
	let mut theirs = Channel::open(&mut b, B, GATEWAY, 57000, ControlKey::derive(&SECRET_B, &public(&NODE), &public(&KEY_B))).await.unwrap();
	theirs.snapshot(&mut b).await;
	// The node pushes new notices, and the device's acknowledgement of them is still on its way, or delayed as every TCP delays a lone one, when the cut-off comes.
	reload(&mut node, |doc| doc["notices"] = json!([{"text": "new address next week"}])).await;
	tokio::time::sleep(Duration::from_millis(150)).await;
	reload(&mut node, |doc| doc["users"][1]["enabled"] = json!(false)).await;
	// What a real TCP receiver makes of the segments that came: bytes it has are dropped, and a FIN counts only at the sequence number it is waited for at.
	let (mut next, mut stream, mut fin, mut segments) = (theirs.tcp.ack, theirs.rest.clone(), false, Vec::new());
	while let Some(packet) = b.recv(Duration::from_millis(600), |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (PORT, 57000))).await {
		let (tcp, data) = segment(&packet).unwrap();
		segments.push((tcp.sequence_number.wrapping_sub(theirs.tcp.ack), data.len(), tcp.fin, tcp.rst));
		let behind = next.wrapping_sub(tcp.sequence_number) as usize;
		if behind > data.len() || tcp.rst {continue}
		stream.extend_from_slice(&data[behind..]);
		next = next.wrapping_add((data.len() - behind) as u32);
		fin |= tcp.fin;
	}
	let (mut input, mut read) = (&stream[..], Vec::new());
	while let Ok(Some(message)) = theirs.messages.read(&mut input) {read.push(message)}
	assert!(matches!(&read[..], [NodeMessage::Notices(_), NodeMessage::Bye {reason: ByeReason::Disabled}]) && fin && node.engine.control().byes == 1, "the device read {read:?} with fin {fin} from the segments (offset, length, fin, rst) {segments:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_sends_a_device_no_segment_larger_than_it_announced() {
	let node = launch(|_| {}, None).await;
	let mut a = Client::connect(KEY_A, node.addr).await;
	// Without the option a segment is as large as the inbound's MTU lets it be.
	let mut plain = Tcp::open(&mut a, A, PUBLIC, 40600, 7000).await.unwrap();
	assert_eq!((plain.take(&mut a, 6004).await.len(), plain.sizes.iter().max()), (6004, Some(&1420)));
	// With it no segment carries more than the device said it takes.
	let mut small = Tcp::open_with(&mut a, A.into(), PUBLIC.into(), 40601, 7000, Some(1200)).await.unwrap();
	assert_eq!((small.take(&mut a, 6004).await.len(), small.sizes.iter().max()), (6004, Some(&1240)));
	// So a device that lowered its MTU, and announces the segment size that goes with it as every system does, is sent TCP that fits, whole, and no fragment.
	let mut channel = Channel::of_a(&mut a, 58000).await;
	channel.snapshot(&mut a).await;
	channel.ask(&mut a, ClientMessage::SetMtu {mtu: 1280}).await;
	assert_eq!(channel.answer(&mut a).await, Some(NodeMessage::MtuResult {mtu: 1280}));
	let mut fits = Tcp::open_with(&mut a, A.into(), PUBLIC.into(), 40602, 7000, Some(1240)).await.unwrap();
	assert_eq!((fits.take(&mut a, 6004).await.len(), fits.sizes.iter().max()), (6004, Some(&1280)));
	assert!(a.inbox.iter().all(|packet| packet[0] != 0x45 || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff == 0), "a fragment was sent");
	// An option that asks for a segment smaller than any host must take is not followed below that size.
	let mut tiny = Tcp::open_with(&mut a, A.into(), PUBLIC.into(), 40603, 7000, Some(1)).await.unwrap();
	assert_eq!((tiny.take(&mut a, 6004).await.len(), tiny.sizes.iter().max()), (6004, Some(&576)));
}

#[test]
fn the_new_keys_are_validated_and_their_secrets_are_shown_to_nobody() {
	let doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:1081".parse().unwrap(), "127.0.0.1:51820".parse().unwrap());
	let errors = |change: &dyn Fn(&mut Value)| {
		let mut doc = doc.clone();
		change(&mut doc);
		match Config::parse(doc.to_string().as_bytes()) {
			Ok(config) => config.validate(false).errors.iter().map(|error| error.path.clone()).collect::<Vec<_>>(),
			Err(error) => vec![error.path],
		}
	};
	assert!(errors(&|_| {}).is_empty());
	// A device of a `veilway` inbound has one secret or two, of its own, and none of them is a WireGuard key of the config.
	for (case, change, path) in [
		("no secret", (&|doc: &mut Value| drop(doc["users"][0]["devices"][0].as_object_mut().unwrap().remove("transport_secrets"))) as &dyn Fn(&mut Value), "users[0].devices[0].transport_secrets"),
		("an empty list", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([]), "users[0].devices[0].transport_secrets"),
		("three secrets", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&[1; 32]), text(&[2; 32]), text(&[3; 32])]), "users[0].devices[0].transport_secrets"),
		("the same secret twice", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&SECRET_A), text(&SECRET_A)]), "users[0].devices[0].transport_secrets[1]"),
		("another device's secret", &|doc| doc["users"][1]["devices"][0]["transport_secrets"] = json!([text(&SECRET_A)]), "users[1].devices[0].transport_secrets[0]"),
		("the inbound's private key", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&NODE)]), "users[0].devices[0].transport_secrets[0]"),
		("a device's public key", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&public(&KEY_B))]), "users[0].devices[0].transport_secrets[0]"),
		("a secret that is no key", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!(["short"]), "users[0].devices[0].transport_secrets[0]"),
		("the marker of the control api", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([REDACTED]), "users[0].devices[0].transport_secrets[0]"),
		("an all zero secret", &|doc| doc["users"][0]["devices"][0]["transport_secrets"] = json!([text(&[0; 32])]), "users[0].devices[0].transport_secrets[0]"),
		// The `ws` without a decoy is that of a `wireguard` inbound, and of the protocol's own transports `faketls` and `quic` are not built.
		("the ws of a wireguard inbound on a veilway inbound", &|doc| doc["inbounds"][0]["transports"] = json!([{"type": "ws", "listen": "127.0.0.1:8443", "path": "/wg"}]), "inbounds[0].transports[0].type"),
		("a transport that is not built", &|doc| doc["inbounds"][0]["transports"][0]["type"] = json!("faketls"), "inbounds[0].transports[0].type"),
		("an inbound type nobody knows", &|doc| doc["inbounds"][0]["type"] = json!("native"), "inbounds[0].type"),
		("five notices", &|doc| doc["notices"] = json!([{"text": "1"}, {"text": "2"}, {"text": "3"}, {"text": "4"}, {"text": "5"}]), "notices"),
		("a notice of 281 bytes", &|doc| doc["notices"] = json!([{"text": "x".repeat(281)}]), "notices[0].text"),
		("an empty notice", &|doc| doc["notices"] = json!([{"text": ""}]), "notices[0].text"),
		("a notice that reorders its text", &|doc| doc["notices"] = json!([{"text": "pay \u{202e}here"}]), "notices[0].text"),
		("a notice with a line break", &|doc| doc["notices"] = json!([{"text": "one\ntwo"}]), "notices[0].text"),
		("a severity nobody knows", &|doc| doc["notices"] = json!([{"severity": "fatal", "text": "x"}]), "notices[0].severity"),
		("a key of the profile, which is none of the config", &|doc| doc["min_control_version"] = json!(1), ""),
	] {assert_eq!(errors(change), [path], "{case}")}
	let mut two = doc.clone();
	two["users"][0]["devices"][0]["transport_secrets"] = json!([text(&SECRET_A), text(&[0xa2; 32])]);
	two["notices"] = json!([{"severity": "warning", "text": "x".repeat(280)}]);
	let config = parsed(&two);
	// Wherever other secrets are redacted these are: the document the control API shows, and `Debug`. The document that is saved holds them.
	let (shown, debug, saved) = (config.redacted(), format!("{config:?}"), serde_json::to_string(&config).unwrap());
	let markers: Vec<String> = shown["users"][0]["devices"][0]["transport_secrets"].as_array().unwrap().iter().map(|marker| marker.as_str().unwrap().to_string()).collect();
	// Each entry is shown as a marker that names it: `<redacted:` and eight hex digits, others for another secret and the same every time this process shows it.
	assert!(markers.len() == 2 && markers[0] != markers[1] && markers.iter().all(|marker| marker.len() == 19 && marker.starts_with("<redacted:") && marker.ends_with('>') && marker[10..18].bytes().all(|digit| digit.is_ascii_hexdigit())), "{markers:?}");
	assert_eq!(config.redacted()["users"][0]["devices"][0]["transport_secrets"], json!(markers));
	for secret in [text(&SECRET_A), text(&[0xa2; 32]), text(&SECRET_B)] {assert!(!shown.to_string().contains(&secret) && !debug.contains(&secret) && saved.contains(&secret))}
	assert!(!debug.contains("161, 161") && !debug.contains("a1a1") && !saved.contains("redacted"));
	// What comes back stands for the secret it names, wherever it stands. The end of a rotation takes the old secret out of the list, and the one that stays is the one whose marker stayed, in either order of the two.
	let kept = |list: Value| {
		let mut back = shown.clone();
		back["users"][0]["devices"][0]["transport_secrets"] = list;
		Config::parse_keeping(back.to_string().as_bytes(), &config).map(|(kept, _)| serde_json::to_value(&kept).unwrap()["users"][0]["devices"][0]["transport_secrets"].clone()).map_err(|report| report.errors.iter().map(|error| error.path.clone()).collect::<Vec<_>>())
	};
	let (old, new, third) = (text(&SECRET_A), text(&[0xa2; 32]), text(&[0xa3; 32]));
	assert_eq!(kept(json!([markers[0], markers[1]])), Ok(json!([old, new])));
	assert_eq!(kept(json!([markers[1]])), Ok(json!([new])), "the old secret was taken out and is the one that stayed");
	assert_eq!(kept(json!([markers[0]])), Ok(json!([old])));
	assert_eq!(kept(json!([markers[1], markers[0]])), Ok(json!([new, old])));
	// A rotation begins with a new secret written out next to the marker of the one that stays, on either side of it.
	assert_eq!(kept(json!([third, markers[1]])), Ok(json!([third, new])));
	assert_eq!(kept(json!([markers[0], third])), Ok(json!([old, third])));
	// A marker that names no secret of the device is an error at its place: the plain marker of the other secrets, digits nobody was shown, and the marker of another device's secret.
	let theirs = shown["users"][1]["devices"][0]["transport_secrets"][0].clone();
	for (case, list) in [("the plain marker", json!([REDACTED])), ("digits of no secret", json!(["<redacted:00000000>", markers[1]])), ("another device's marker", json!([theirs])), ("a marker cut short", json!([&markers[0][..12]]))] {assert_eq!(kept(list), Err(vec!["users[0].devices[0].transport_secrets[0]".to_string()]), "{case}")}
	// A marker under the key of a device that does not run is an error too, and the same marker twice is the same secret twice.
	let mut moved = shown.clone();
	moved["users"][0]["devices"][0]["public_key"] = json!(text(&public(&[0x29; 32])));
	assert_eq!(Config::parse_keeping(moved.to_string().as_bytes(), &config).err().unwrap().errors.iter().map(|error| error.path.clone()).collect::<Vec<_>>(), ["users[0].devices[0].transport_secrets[0]", "users[0].devices[0].transport_secrets[1]"]);
	assert_eq!(kept(json!([markers[0], markers[0]])).map(|list| parsed_errors(&shown, list)), Ok(vec!["users[0].devices[0].transport_secrets[1]".to_string()]));
	// A secret on a device that has no `veilway` inbound, and notices nobody is shown, are warnings.
	let mut unused = doc.clone();
	unused["inbounds"][0]["type"] = json!("wireguard");
	unused["notices"] = json!([{"text": "x"}]);
	let warned: Vec<String> = parsed(&unused).validate(false).warnings.iter().map(|warning| warning.path.clone()).filter(|path| path.contains("secrets") || path == "notices").collect();
	assert_eq!(warned, ["users[0].devices[0].transport_secrets", "users[1].devices[0].transport_secrets", "notices"]);
	assert_eq!(veilway_core::config::transport_secret().unwrap().len(), 44);
}
