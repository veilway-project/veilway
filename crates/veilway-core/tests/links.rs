//! Node links end to end: two engines in one process, an entry with a user and an exit with a responder behind it, joined by a link over `udp-obfs` and over `tls`, in either direction. Where a test needs a hostile node, the test is that node itself: a WireGuard of its own on the client's side of the transports, which sends whatever it likes into the link.
//! The node that dials reaches the other on an address of this host that is not loopback: validation never lets a link dial loopback, as a subscription never lets a client.
#[macro_use]
mod proxied;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
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
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use veilway_core::config::Config;
use veilway_core::engine::link::Status;
use veilway_core::{Engine, Options, Reason};
use veilway_proto::subscription::payload::Padding;
use veilway_proto::subscription::Secret;
use veilway_transport::{Env, Kind, Link as Leg, Session, Source, State, Target, Want};

const ENTRY: [u8; 32] = [0x11; 32];
const EXIT: [u8; 32] = [0x12; 32];
/// The inbound of the entry that a reverse link connects to, which carries links alone.
const RECEIVER: [u8; 32] = [0x13; 32];
const USER: [u8; 32] = [0x21; 32];
/// A second user of the entry, on another device.
const BOB: [u8; 32] = [0x22; 32];
/// The WireGuard key the dialling node made for the link, and the secret the pairing gave.
const DIALLER: [u8; 32] = [0x31; 32];
const SECRET: [u8; 32] = [0x41; 32];
const NODE_KEY: [u8; 32] = [0x51; 32];
const LINK_ID: &str = "AAECAwQFBgcICQoLDA0ODw";
const PATH: &str = "/assets/app-3f9c2e71.js";
const USER_ADDRESS: [u8; 4] = [10, 7, 0, 2];

/// An address of this host that is not loopback, which the node that dials can be told to dial.
fn outward() -> IpAddr {
	let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
	socket.connect("192.0.2.1:9").expect("this host has no address but loopback, and a link never dials loopback");
	socket.local_addr().unwrap().ip()
}

fn port() -> u16 {listen().port()}

/// The certificate of the exit's `tls` transport, its pin, and the roots the entry dials it with.
fn certify(dir: &Path) -> ([u8; 32], Arc<RootCertStore>) {
	let (made, _) = (rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap(), std::fs::create_dir_all(dir));
	for (name, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
		std::fs::write(dir.join(name), pem).unwrap();
		#[cfg(unix)]
		std::fs::set_permissions(dir.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
	let mut roots = RootCertStore::empty();
	roots.add(CertificateDer::from(made.cert.der().to_vec())).unwrap();
	(digest(&SHA256, &made.signing_key.subject_public_key_info()).as_ref().try_into().unwrap(), Arc::new(roots))
}

/// The key of a self-signed `tls` transport, put where the node keeps it, so that its pin is known before the node starts. The node makes the certificate of it itself. No root is needed.
fn seeded(dir: &Path) -> ([u8; 32], Arc<RootCertStore>) {
	let (made, _) = (rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap(), std::fs::create_dir_all(dir));
	std::fs::write(dir.join("tls-links.key"), made.signing_key.serialize_pem()).unwrap();
	#[cfg(unix)]
	std::fs::set_permissions(dir.join("tls-links.key"), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	(digest(&SHA256, &made.signing_key.subject_public_key_info()).as_ref().try_into().unwrap(), Arc::new(RootCertStore::empty()))
}

/// How the two nodes reach each other. `Pinned` is `Tls` to a transport whose certificate the node makes itself, trusted through its pin alone.
#[derive(Clone, Copy, PartialEq)]
enum Over {Obfs, Tls, Pinned}

/// The two halves of one link. `forward`: the entry dials the exit. Otherwise the exit dials the entry. The node that is dialled listens on `at`.
struct Pair {forward: bool, over: Over, at: SocketAddr, pin: [u8; 32], origin: SocketAddr}

impl Pair {
	fn transports(&self) -> Value {
		match self.over {
			Over::Obfs => json!([{"type": "udp-obfs", "endpoints": [self.at.to_string()]}]),
			Over::Tls => json!([{"type": "tls", "path": PATH, "candidates": [{"address": self.at.to_string(), "sni": "node.test", "host": "node.test", "pins": [text(&self.pin)]}]}]),
			Over::Pinned => json!([{"type": "tls", "path": PATH, "candidates": [{"address": self.at.to_string(), "sni": "", "host": "node.test", "pins": [text(&self.pin)], "self_signed": true}]}]),
		}
	}

	/// The inbound of the node that is dialled: links alone, on the pool the link's addresses come from.
	fn inbound(&self, key: &[u8; 32]) -> Value {
		let transport = match self.over {
			Over::Obfs => json!({"type": "udp-obfs", "listen": self.at.to_string()}),
			Over::Tls => json!({"type": "tls", "listen": self.at.to_string(), "path": PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": format!("http://{}", self.origin)}}),
			Over::Pinned => json!({"type": "tls", "listen": self.at.to_string(), "path": PATH, "tls": {"self_signed": true}, "decoy": {"origin": format!("http://{}", self.origin)}}),
		};
		let mut inbound = json!({"tag": "links", "type": "veilway", "private_key": text(key), "address": ["10.9.0.1/24"], "transports": [transport]});
		if self.over != Over::Obfs {(inbound["transport_keys"], inbound["upgrade_cookie"]) = (json!([text(&NODE_KEY)]), json!("sid"))}
		inbound
	}

	fn link(&self, entry: bool) -> Value {
		let mut link = json!({"tag": "far", "id": LINK_ID, "direction": if self.forward {"forward"} else {"reverse"}, "addresses": {"dialler": ["10.9.0.2"]}, "transport_secret": text(&SECRET)});
		if !self.forward {link["addresses"]["listener"] = json!(["10.9.0.3"])}
		// The node that is dialled is the exit in a forward link and the entry in a reverse one.
		if entry != self.forward {(link["inbound"], link["public_key"]) = (json!("links"), json!(text(&public(&DIALLER))))} else {
			(link["private_key"], link["peer"]) = (json!(text(&DIALLER)), json!({"inbound_public_key": text(&public(if self.forward {&EXIT} else {&RECEIVER})), "transports": self.transports()}));
			if self.over != Over::Obfs {link["peer"]["transport_public_key"] = json!(text(&veilway_proto::proof::public_key(&NODE_KEY)))}
		}
		if !entry {link["exits"] = json!(["main"])}
		link
	}

	/// The entry: a user on a plain WireGuard inbound at `home`, a `chain` exit for the link, and a direct exit nobody is routed to, which must carry nothing.
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

	/// The exit: the link, and an exit through a SOCKS5 proxy that answers every connection with `main` and whose own pings the node answers itself.
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
}

/// Starts an engine the way `veilway run` does, with the test's clock, a replay file that takes proofs from the first moment, and the roots the test's certificates lead to.
async fn run(doc: &Value, dir: &Path, time: Time, roots: &Arc<RootCertStore>) -> Engine {
	let _ = (std::fs::create_dir_all(dir), tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_ansi(false).with_test_writer().try_init());
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let config = parsed(doc);
	veilway_core::start(&config, Options {now: time.now, replay: Some(dir.join("replay")), roots: Some(roots.clone()), ..Options::new(dir)}).await.unwrap_or_else(|e| panic!("the node did not start: {e:#}"))
}

/// What carries a WireGuard of the test: plain UDP to a `udp` transport, or a session of the client's side of the transports.
enum Carrier {Udp(UdpSocket), Session(Session)}

/// A WireGuard of the test and what carries it: the user's device, or a node of the test's own at the other end of a link.
struct Peer {tunn: Arc<Mutex<Tunn>>, up: Arc<AtomicBool>, carrier: Carrier, inbox: VecDeque<Vec<u8>>, from: [u8; 4]}

impl Peer {
	/// A device with the key `key` that sends from `from` over plain UDP to `node`, whose WireGuard key is `node_key`.
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

	/// A node of the test that holds a link to a real one over `udp-obfs` at `at`, as the link `key` with the link's secret, and sends from `from` in the link.
	fn node(key: &[u8; 32], node_key: &[u8; 32], at: SocketAddr, from: [u8; 4], time: Time) -> Peer {
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
		let leg = Leg {inbound: public(node_key), device: public(key), secret: Secret::new(SECRET), node: None, mtu: 1390, padding: Padding {wide_max: 1023, normal_max: 255, keepalive: 20_000..=40_000}, borrowed: Default::default()};
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

	/// Hands one datagram of the other side to the WireGuard, sends what that wants sent, and gives the IP packets that came out.
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

	/// Waits until the tunnel has a session.
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

	/// The next packet `wanted` picks, within `budget`.
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

	/// What answers a SYN to `to`:80 from `from` in the tunnel, within a second: a reset, an ICMP error, a SYN-ACK, or nothing.
	async fn knock(&mut self, from: [u8; 4], to: [u8; 4], sport: u16) -> Option<Vec<u8>> {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(from, to, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		self.recv(SECOND, |packet| packet[9] == 1 || segment(packet).is_some_and(|(tcp, _)| tcp.destination_port == sport)).await
	}

	/// An echo request of `size` bytes to `to` with the identifier `ident`, and the packet that answered it within two seconds.
	async fn ping(&mut self, to: [u8; 4], ident: u16, size: usize) -> Option<Vec<u8>> {
		let mut out = Vec::new();
		PacketBuilder::ipv4(self.from, to, 64).icmpv4_echo_request(ident, 1).write(&mut out, &vec![0x5a; size - 28]).unwrap();
		self.send(&out).await;
		self.recv(2 * SECOND, |packet| packet[9] == 1).await
	}
}

/// A link up between two engines, and a user on the entry.
struct Linked {entry: Engine, exit: Engine, user: Peer, pair: Pair, home: SocketAddr, _site: Site}

/// `edit` changes the entry's document before it starts, for a test that puts a proxy chain in front of the link.
async fn linked(test: &'static str, forward: bool, over: Over, edit: impl FnOnce(&mut Value), time: Time) -> Linked {
	let (dir, site) = (scratch(test), site().await);
	let (pin, roots) = if over == Over::Pinned {seeded(&dir.join(if forward {"exit"} else {"entry"}))} else {certify(&dir.join(if forward {"exit"} else {"entry"}))};
	let (home, pair) = (listen(), Pair {forward, over, at: SocketAddr::new(outward(), port()), pin, origin: site.addr});
	// The node that is dialled starts first, so the first dial finds it.
	let exit_doc = pair.exit(socks().await);
	let mut entry_doc = pair.entry(home);
	edit(&mut entry_doc);
	let (entry, exit) = if forward {
		let exit = run(&exit_doc, &dir.join("exit"), time, &roots).await;
		(run(&entry_doc, &dir.join("entry"), time, &roots).await, exit)
	} else {
		let entry = run(&entry_doc, &dir.join("entry"), time, &roots).await;
		(entry, run(&exit_doc, &dir.join("exit"), time, &roots).await)
	};
	for (node, name) in [(&entry, "entry"), (&exit, "exit")] {
		let deadline = Instant::now() + Duration::from_secs(20);
		while node.links()[0].status != Status::Up {
			assert!(Instant::now() < deadline, "the link is not up at the {name} after 20 s: {:?}", node.links());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}
	let mut user = Peer::device(&USER, &ENTRY, home, USER_ADDRESS).await;
	user.connect().await;
	Linked {entry, exit, user, pair, home, _site: site}
}

/// What every direction and transport must do: traffic leaves from the exit and is counted for the user at the entry, a ping is answered from the far side under the identifier the user chose, and a packet larger than the link is refused at the entry with the link's MTU.
async fn carries(mut net: Linked, base: u16) {
	assert_eq!(net.user.leaves(PUBLIC, base).await.as_deref(), Some("main"), "a connection did not leave through the link");
	let reply = net.user.ping(PUBLIC, 4242, 200).await.expect("a ping through the link was not answered");
	assert_eq!((reply.len(), reply[20], &reply[12..16], &reply[16..20], &reply[24..26]), (200, 0, &PUBLIC[..], &USER_ADDRESS[..], &4242u16.to_be_bytes()[..]), "the answer is not the user's own echo reply");
	// "Usage is counted per user before translation", and both nodes count what crossed the link.
	let usage = net.entry.usage("alice").unwrap();
	assert!(usage.traffic.up_packets >= 3 && usage.traffic.down_packets >= 3 && usage.used_bytes > 0, "{usage:?}");
	let (sent, taken) = (net.entry.links()[0].traffic, net.exit.links()[0].traffic);
	assert!(sent.up_packets >= 3 && sent.down_packets >= 3 && taken.down_packets >= 3 && taken.up_packets >= 3, "{sent:?} {taken:?}");
	assert_eq!((net.entry.exit("near").unwrap().up_packets, net.entry.counters().users.len(), net.exit.counters().users.len()), (0, 1, 0), "something left through another exit, or a link was listed as a user");
	// "Nothing is fragmented for a link": a packet one byte larger than the link is answered "fragmentation needed" with the link's MTU, from the user's gateway.
	let mtu: u16 = if net.pair.over == Over::Obfs {1390} else {1420};
	let too_big = net.user.ping(PUBLIC, 4243, usize::from(mtu) + 1).await.expect("a packet larger than the link got no answer");
	assert_eq!((too_big[20], too_big[21], u16::from_be_bytes([too_big[26], too_big[27]]), &too_big[12..16]), (3, 4, mtu, &[10, 7, 0, 1][..]));
	assert!(net.entry.dropped(Reason::TooBig) >= 1);
	net.entry.shutdown().await;
	net.exit.shutdown().await;
}

/// "The client starts a new WireGuard handshake when it sends a packet on a tunnel whose last handshake is older than the client rekey point": a link that carries nothing stays up past WireGuard's 180 s, and so its traffic still flows. Real time, since WireGuard keeps its own clock: run with `--ignored`, about three and a half minutes each.
async fn stays_up_while_idle(test: &'static str, forward: bool, over: Over) {
	let mut net = linked(test, forward, over, |_| {}, time!()).await;
	tokio::time::sleep(Duration::from_secs(200)).await;
	for (node, name) in [(&net.entry, "entry"), (&net.exit, "exit")] {
		let link = &node.links()[0];
		assert_eq!(link.status, Status::Up, "the idle link went down at the {name}: {link:?}");
		assert!(link.handshake.is_some_and(|age| age < Duration::from_secs(180)), "the idle link at the {name} has no fresh handshake: {link:?}");
	}
	// The test's user is a bare WireGuard peer that renews nothing, so its own tunnel to the entry has lapsed by now: it connects again, as an app would.
	net.user = Peer::device(&USER, &ENTRY, net.home, USER_ADDRESS).await;
	net.user.connect().await;
	carries(net, 46000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real time, about three and a half minutes"]
async fn an_idle_forward_link_over_tls_stays_up_past_the_reject_time() {stays_up_while_idle("links-idle-tls", true, Over::Tls).await}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real time, about three and a half minutes"]
async fn an_idle_reverse_link_over_udp_obfs_stays_up_past_the_reject_time() {stays_up_while_idle("links-idle-obfs", false, Over::Obfs).await}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_link_over_udp_obfs_carries_a_users_traffic_out_of_the_exit() {
	let time = time!();
	let net = linked("links-forward-obfs", true, Over::Obfs, |_| {}, time).await;
	let (entry, exit) = (&net.entry.links()[0], &net.exit.links()[0]);
	assert_eq!((entry.entry, entry.listener, exit.entry, exit.listener, entry.transport.map(|(name, ..)| name), exit.transport, entry.exit.as_deref()), (true, false, false, true, Some("udp-obfs"), None, Some("far")));
	carries(net, 40000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_link_over_tls_carries_a_users_traffic_out_of_the_exit() {
	let time = time!();
	let net = linked("links-forward-tls", true, Over::Tls, |_| {}, time).await;
	assert_eq!(net.entry.links()[0].transport.map(|(name, ..)| name), Some("tls"));
	carries(net, 41000).await;
}

// Node links page, "Pin-only candidates": a node with no domain is linked to through its own certificate, trusted through the pin alone, and the pin holds across the node's renewals of the certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_to_a_self_signed_tls_transport_comes_up_and_reconnects_after_the_certificate_is_renewed() {
	let time = time!();
	for (forward, test) in [(true, "links-pinned-forward"), (false, "links-pinned-reverse")] {
		let mut net = linked(test, forward, Over::Pinned, |_| {}, time).await;
		assert_eq!(net.user.leaves(PUBLIC, 43000).await.as_deref(), Some("main"));
		let (dialled, dialler) = if forward {(&net.exit, &net.entry)} else {(&net.entry, &net.exit)};
		assert_eq!(dialler.links()[0].transport.map(|(name, ..)| name), Some("tls"));
		let before = dialled.certificates();
		assert_eq!((before.len(), before[0].pin), (1, net.pair.pin));
		time.ahead.fetch_add(85 * 86_400, Ordering::SeqCst);
		eventually("the certificate was not made anew", || dialled.certificates().first().is_some_and(|again| again.not_before > before[0].not_before)).await;
		assert_eq!(dialled.certificates()[0].pin, net.pair.pin);
		eventually("the replay limit did not follow the clock", || [&net.entry, &net.exit].iter().all(|node| node.replay().is_none_or(|replay| replay.limit >= time.secs()))).await;
		let mut doc = if forward {net.pair.entry(net.home)} else {net.pair.exit(socks().await)};
		doc["links"][0]["mtu"] = json!(1380);
		dialler.reload(doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
		eventually("the link did not come back with the same pin", || dialler.links()[0].status == Status::Up && dialler.links()[0].handshake.is_some_and(|age| age < Duration::from_secs(10))).await;
		net.user.connect().await;
		// The first flow after the link came back can race the user's own session: a few tries, each on its own port.
		let mut left = None;
		for port in 43001..43021 {
			left = net.user.leaves(PUBLIC, port).await;
			if left.is_some() {break}
			tokio::time::sleep(Duration::from_millis(500)).await;
		}
		assert_eq!(left.as_deref(), Some("main"));
		net.entry.shutdown().await;
		net.exit.shutdown().await;
	}
}

// "A link whose dial fails because the other node's key matches none of the pins says so, apart from an unreachable node", and it never latches: a link with the right pin comes up at the next dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_whose_pin_does_not_match_says_pin_mismatch_and_comes_up_with_the_right_pin() {
	let time = time!();
	let (dir, site) = (scratch("links-pin-mismatch"), site().await);
	let (pin, roots) = seeded(&dir.join("exit"));
	let (home, pair) = (listen(), Pair {forward: true, over: Over::Pinned, at: SocketAddr::new(outward(), port()), pin, origin: site.addr});
	let exit = run(&pair.exit(socks().await), &dir.join("exit"), time, &roots).await;
	let mut wrong = pair.entry(home);
	wrong["links"][0]["peer"]["transports"][0]["candidates"][0]["pins"] = json!([text(&[7; 32])]);
	let entry = run(&wrong, &dir.join("entry"), time, &roots).await;
	eventually("the link did not say pin mismatch", || entry.links()[0].status == Status::PinMismatch).await;
	assert_eq!(entry.links()[0].status.name(), "pin_mismatch");
	assert_ne!(exit.links()[0].status, Status::Up);
	entry.reload(pair.entry(home).to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
	eventually("the link did not come up with the right pin", || entry.links()[0].status == Status::Up).await;
	entry.shutdown().await;
	exit.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_link_over_tls_through_a_socks5_outbound_comes_up_and_carries_a_users_traffic() {
	let time = time!();
	let (hop, asked) = forwarder(None).await;
	let net = linked("links-via-tls", true, Over::Tls, |doc| {doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "hop", "type": "socks5", "server": hop.to_string()})); doc["links"][0]["via"] = json!("hop")}, time).await;
	assert_eq!(net.entry.links()[0].transport.map(|(name, ..)| name), Some("tls"));
	let exit = net.pair.at.to_string();
	assert!(asked.lock().unwrap().contains(&exit), "the proxy was not asked for the exit at {exit}: {:?}", asked.lock().unwrap());
	carries(net, 42000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_whose_chain_refuses_one_candidate_moves_on_to_the_next() {
	let time = time!();
	let (hop, asked) = forwarder(None).await;
	let refused = SocketAddr::new(outward(), port());
	let net = linked("links-via-refused", true, Over::Tls, |doc| {
		doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "hop", "type": "socks5", "server": hop.to_string()}));
		doc["links"][0]["via"] = json!("hop");
		let real = doc["links"][0]["peer"]["transports"][0]["candidates"][0].clone();
		let mut first = real.clone();
		first["address"] = json!(refused.to_string());
		doc["links"][0]["peer"]["transports"][0]["candidates"] = json!([first, real]);
	}, time).await;
	assert_eq!(net.entry.links()[0].transport.map(|(name, ..)| name), Some("tls"));
	let exit = net.pair.at.to_string();
	assert!(asked.lock().unwrap().contains(&exit), "the chain was never asked for the exit at {exit}: {:?}", asked.lock().unwrap());
	carries(net, 42100).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_that_changes_the_via_of_a_link_dials_through_the_new_chain() {
	let time = time!();
	let (first, first_asked) = forwarder(None).await;
	let (second, second_asked) = forwarder(None).await;
	let net = linked("links-via-reload", true, Over::Tls, |doc| {
		doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "first", "type": "socks5", "server": first.to_string()}));
		doc["links"][0]["via"] = json!("first");
	}, time).await;
	let exit = net.pair.at.to_string();
	assert!(first_asked.lock().unwrap().contains(&exit), "the first chain was not used at all");
	let home = net.entry.snapshot().config.inbounds[0].transports[0].listen();
	let mut doc = net.pair.entry(home);
	doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "first", "type": "socks5", "server": first.to_string()}));
	doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "second", "type": "socks5", "server": second.to_string()}));
	doc["links"][0]["via"] = json!("second");
	net.entry.reload(doc.to_string().into_bytes(), None).await.unwrap();
	let deadline = Instant::now() + Duration::from_secs(20);
	while !second_asked.lock().unwrap().contains(&exit) {
		assert!(Instant::now() < deadline, "the link did not dial through the new chain within 20 s: {:?}", second_asked.lock().unwrap());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	net.entry.shutdown().await;
	net.exit.shutdown().await;
}

/// A link over `udp-obfs` alone cannot go through a proxy chain, and the config check says so instead of letting the link wait for nothing.
#[test]
fn a_udp_only_link_with_via_is_reported_by_the_config_check() {
	let mut entry = Pair {forward: true, over: Over::Obfs, at: SocketAddr::new(outward(), port()), pin: [0; 32], origin: "127.0.0.1:9".parse().unwrap()}.entry(listen());
	entry["outbounds"].as_array_mut().unwrap().push(json!({"tag": "hop", "type": "socks5", "server": "127.0.0.1:1080"}));
	entry["links"][0]["via"] = json!("hop");
	let report = Config::parse(entry.to_string().as_bytes()).unwrap().validate(false);
	assert!(report.errors.iter().any(|error| error.path == "links[0].via" && error.message.contains("tls or ws")), "{:#?}", report.errors);
	assert!(report.warnings.iter().any(|warning| warning.path == "links[0].peer.transports[0]" && warning.message.contains("not usable through via")), "{:#?}", report.warnings);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reverse_link_over_udp_obfs_carries_a_users_traffic_out_of_the_exit() {
	let time = time!();
	let net = linked("links-reverse-obfs", false, Over::Obfs, |_| {}, time).await;
	let (entry, exit) = (&net.entry.links()[0], &net.exit.links()[0]);
	assert_eq!((entry.entry, entry.listener, exit.entry, exit.listener, exit.transport.map(|(name, ..)| name)), (true, true, false, false, Some("udp-obfs")));
	carries(net, 42000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reverse_link_over_tls_carries_a_users_traffic_out_of_the_exit() {
	let time = time!();
	let net = linked("links-reverse-tls", false, Over::Tls, |_| {}, time).await;
	carries(net, 43000).await;
}

/// The exit with its link, and the test in the place of the entry: a node of its own that dials the exit as the link.
async fn hostile_entry(test: &'static str, time: Time, change: impl FnOnce(&mut Value)) -> (Engine, Peer) {
	let (dir, roots) = (scratch(test), Arc::new(RootCertStore::empty()));
	let pair = Pair {forward: true, over: Over::Obfs, at: SocketAddr::new(outward(), port()), pin: [0; 32], origin: listen()};
	let mut doc = pair.exit(socks().await);
	change(&mut doc);
	let exit = run(&doc, &dir, time, &roots).await;
	let mut entry = Peer::node(&DIALLER, &EXIT, pair.at, [10, 9, 0, 2], time);
	entry.connect().await;
	(exit, entry)
}

// "The exit treats the link as one peer and trusts nothing it says."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hostile_entry_reaches_nothing_but_what_the_exits_rules_give_a_link() {
	let time = time!();
	let (exit, mut entry) = hostile_entry("links-hostile-entry", time, |doc| doc["links"][0]["max_flows"] = json!(8)).await;
	// From the entry's link address a flow leaves, as it would for any entry.
	assert_eq!(entry.leaves(PUBLIC, 44000).await.as_deref(), Some("main"));
	// "A hostile entry cannot send from any address but one": from any other address nothing is answered, and it is counted.
	let spoofed = exit.dropped(Reason::SpoofedSource);
	for from in [[10, 9, 0, 3], [10, 7, 0, 2], [93, 184, 216, 1]] {assert!(entry.knock(from, PUBLIC, 44100 + u16::from(from[3])).await.is_none(), "a packet from {from:?} was answered")}
	assert_eq!(exit.dropped(Reason::SpoofedSource), spoofed + 3);
	// "Destinations that are always refused for a link": the exit's own gateway, any address of its pools, its own link addresses, and private networks without `allow_private`. Each is refused with a reset, from the gate, whatever the rules say.
	let gate = exit.dropped(Reason::Gate);
	for (n, to) in [[10, 9, 0, 1], [10, 9, 0, 77], [10, 9, 0, 2], [192, 168, 1, 1], [10, 20, 0, 1], [127, 0, 0, 1], [169, 254, 169, 254]].into_iter().enumerate() {
		let answer = entry.knock([10, 9, 0, 2], to, 44200 + n as u16).await.unwrap_or_else(|| panic!("no answer for {to:?}"));
		assert!(segment(&answer).is_some_and(|(tcp, _)| tcp.rst), "{to:?} was not refused with a reset");
	}
	assert!(exit.dropped(Reason::Gate) >= gate + 7);
	// "Flows of one link at the exit", the link's own: past `max_flows` a new flow is refused and counted, and the flows it has go on.
	let full = exit.dropped(Reason::FlowTableFull);
	for sport in 44300..44320 {entry.knock([10, 9, 0, 2], PUBLIC, sport).await;}
	assert!(exit.dropped(Reason::FlowTableFull) > full, "a link went past its max_flows");
	// The exit counts what the link sent, and lists no user for it.
	let link = &exit.links()[0];
	assert!(link.traffic.down_packets > 20 && link.dropped >= 10 && link.flows <= 8 && exit.counters().users.is_empty(), "{link:?}");
	exit.shutdown().await;
}

// "The engine also refuses, at the moment it decides a flow, to send a packet that arrived from a link into a link", and "dns.hijack does not apply to a link".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_arrives_from_a_link_is_never_served_the_nodes_own_dns() {
	let time = time!();
	let (exit, mut entry) = hostile_entry("links-no-dns", time, |_| {}).await;
	let mut query = Vec::new();
	PacketBuilder::ipv4([10, 9, 0, 2], [10, 9, 0, 1], 64).udp(5353, 53).write(&mut query, &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]).unwrap();
	let answered = exit.dns().answered + exit.dns().refused + exit.dns().failed;
	entry.send(&query).await;
	// The gateway is refused for a link like any address of a pool: the node's resolver never sees the query.
	let refusal = entry.recv(SECOND, |packet| packet[9] == 1).await.expect("the query to the gateway was not refused");
	assert_eq!((refusal[20], refusal[21]), (3, 13));
	assert_eq!(exit.dns().answered + exit.dns().refused + exit.dns().failed, answered);
	exit.shutdown().await;
}

/// The entry with its link and a user, and the test in the place of the exit: a node of its own that dials the entry, which is the listener of a reverse link. `home` is where the entry's users connect.
async fn hostile_exit(test: &'static str, time: Time, change: impl FnOnce(&mut Value)) -> (Engine, Peer, Peer, SocketAddr) {
	let (dir, roots) = (scratch(test), Arc::new(RootCertStore::empty()));
	let (home, pair) = (listen(), Pair {forward: false, over: Over::Obfs, at: SocketAddr::new(outward(), port()), pin: [0; 32], origin: listen()});
	let mut doc = pair.entry(home);
	change(&mut doc);
	let entry = run(&doc, &dir, time, &roots).await;
	let mut exit = Peer::node(&DIALLER, &RECEIVER, pair.at, [10, 9, 0, 2], time);
	exit.connect().await;
	eventually("the link is not up at the entry", || entry.links()[0].status == Status::Up).await;
	let mut user = Peer::device(&USER, &ENTRY, home, USER_ADDRESS).await;
	user.connect().await;
	(entry, exit, user, home)
}

// "The entry delivers only what answers a flow it sent." "A hostile or compromised exit cannot send the entry a packet that reaches a user unless it answers a flow that user opened, and cannot reach the entry's own addresses or other users."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hostile_exit_reaches_no_user_but_with_answers_to_their_flows() {
	let time = time!();
	let (entry, mut exit, mut user, home) = hostile_exit("links-hostile-exit", time, |doc| doc["users"].as_array_mut().unwrap().push(json!({"name": "bob", "exits": "all", "devices": [{"name": "phone", "public_key": text(&public(&BOB)), "addresses": ["10.7.0.3"]}]}))).await;
	// The user opens a flow, which the test's exit sees under the entry's link address and a port drawn at random, with the fields that tell a device rewritten.
	let (mut syn, mut out) = (TcpHeader::new(45000, 80, 1000, 65535), Vec::new());
	syn.syn = true;
	PacketBuilder::ipv4(USER_ADDRESS, PUBLIC, 33).tcp_header(syn).write(&mut out, &[]).unwrap();
	user.send(&out).await;
	let seen = exit.recv(2 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| tcp.syn)).await.expect("the user's flow did not reach the exit");
	let (tcp, _) = segment(&seen).unwrap();
	assert_eq!((&seen[12..16], seen[8], &seen[16..20]), (&[10, 9, 0, 3][..], 64, &PUBLIC[..]), "the exit was given the user's address, or a hop limit that tells the device");
	assert!(tcp.source_port >= 1024 && tcp.source_port != 45000);
	// What answers that flow reaches the user, as the far side's answer to the user's own port.
	let answer = |from: [u8; 4], to: [u8; 4], sport: u16, dport: u16| {
		let (mut syn_ack, mut out) = (TcpHeader::new(sport, dport, 7000, 65535), Vec::new());
		(syn_ack.syn, syn_ack.ack, syn_ack.acknowledgment_number) = (true, true, 1001);
		PacketBuilder::ipv4(from, to, 64).tcp_header(syn_ack).write(&mut out, &[]).unwrap();
		out
	};
	exit.send(&answer(PUBLIC, [10, 9, 0, 3], 80, tcp.source_port)).await;
	let delivered = user.recv(2 * SECOND, |packet| segment(packet).is_some()).await.expect("the answer to the user's flow was not delivered");
	assert_eq!((&delivered[16..20], segment(&delivered).unwrap().0.destination_port), (&USER_ADDRESS[..], 45000));
	// Another user opens a flow to the same remote address and port from the same port of theirs. It is given a port of its own, and what answers one user's flow never reaches the other.
	let mut bob = Peer::device(&BOB, &ENTRY, home, [10, 7, 0, 3]).await;
	bob.connect().await;
	let (mut syn, mut out) = (TcpHeader::new(45000, 80, 1000, 65535), Vec::new());
	syn.syn = true;
	PacketBuilder::ipv4([10, 7, 0, 3], PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
	bob.send(&out).await;
	let theirs = exit.recv(2 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| tcp.syn)).await.expect("the other user's flow did not reach the exit");
	let theirs = segment(&theirs).unwrap().0.source_port;
	assert_ne!(theirs, tcp.source_port);
	exit.send(&answer(PUBLIC, [10, 9, 0, 3], 80, tcp.source_port)).await;
	assert!(user.recv(2 * SECOND, |packet| segment(packet).is_some()).await.is_some() && bob.recv(SECOND, |_| true).await.is_none(), "an answer to one user's flow reached the other");
	exit.send(&answer(PUBLIC, [10, 9, 0, 3], 80, theirs)).await;
	let delivered = bob.recv(2 * SECOND, |packet| segment(packet).is_some()).await.expect("the answer to the other user's flow was not delivered");
	assert_eq!((&delivered[16..20], segment(&delivered).unwrap().0.destination_port), (&[10, 7, 0, 3][..], 45000));
	assert!(user.recv(SECOND, |packet| segment(packet).is_some()).await.is_none(), "an answer to the other user's flow reached the user");
	// A ping goes under an identifier of the entry's drawing, and the reply comes back under the user's own, 0 included. The other user is sent nothing of it.
	let mut out = Vec::new();
	PacketBuilder::ipv4(USER_ADDRESS, PUBLIC, 64).icmpv4_echo_request(0, 1).write(&mut out, b"ping").unwrap();
	user.send(&out).await;
	let request = exit.recv(2 * SECOND, |packet| packet[9] == 1 && packet[20] == 8).await.expect("the ping did not reach the exit");
	let mut reply = Vec::new();
	PacketBuilder::ipv4(PUBLIC, [10, 9, 0, 3], 64).icmpv4_echo_reply(u16::from_be_bytes([request[24], request[25]]), 1).write(&mut reply, b"ping").unwrap();
	exit.send(&reply).await;
	let echoed = user.recv(2 * SECOND, |packet| packet[9] == 1).await.expect("the echo reply was not delivered");
	assert_eq!((echoed[20], &echoed[24..26], &echoed[16..20]), (0, &[0, 0][..], &USER_ADDRESS[..]), "the reply did not come back under the user's own identifier");
	assert!(bob.recv(SECOND, |_| true).await.is_none(), "the other user was sent the reply to a ping of the user");
	// One ping flow holds so many identifiers, and the one past them is refused with an ICMP error rather than dropped unseen.
	for ident in 1..=16u16 {
		let mut out = Vec::new();
		PacketBuilder::ipv4(USER_ADDRESS, PUBLIC, 64).icmpv4_echo_request(ident, 1).write(&mut out, b"ping").unwrap();
		user.send(&out).await;
	}
	let refused = user.recv(2 * SECOND, |packet| packet[9] == 1).await.expect("an echo identifier past what one ping flow holds was not refused");
	assert_eq!((refused[20], &refused[52..54]), (3, &16u16.to_be_bytes()[..]), "the refusal does not quote the identifier past the ones a ping flow holds");
	// Everything else is dropped and counted: an answer to no flow, a packet to the user's own address, one to the entry's gateway, one to another port and one from another remote address.
	let before = (entry.dropped(Reason::NoFlow), entry.links()[0].dropped);
	for packet in [answer(PUBLIC, [10, 9, 0, 3], 80, tcp.source_port ^ 1), answer(PUBLIC, USER_ADDRESS, 80, 45000), answer(PUBLIC, [10, 7, 0, 1], 80, 45000), answer([93, 184, 216, 35], [10, 9, 0, 3], 80, tcp.source_port), answer(PUBLIC, [10, 9, 0, 3], 81, tcp.source_port)] {exit.send(&packet).await}
	assert!(user.recv(SECOND, |packet| segment(packet).is_some()).await.is_none(), "a packet that answers no flow of the user reached them");
	eventually("the packets were not counted as answering no flow", || entry.dropped(Reason::NoFlow) >= before.0 + 5 && entry.links()[0].dropped >= before.1 + 5).await;
	// An ICMP error that quotes the flow is translated back, quote and checksums included. One that quotes nothing the entry sent is dropped.
	let mut quoted = seen[..28].to_vec();
	let mut error = Vec::new();
	PacketBuilder::ipv4([198, 51, 100, 1], [10, 9, 0, 3], 64).icmpv4_raw(3, 1, [0; 4]).write(&mut error, &quoted).unwrap();
	exit.send(&error).await;
	let back = user.recv(2 * SECOND, |packet| packet[9] == 1).await.expect("the ICMP error for the user's flow was not delivered");
	assert_eq!((&back[16..20], &back[40..44], &back[48..50], back[20]), (&USER_ADDRESS[..], &USER_ADDRESS[..], &45000u16.to_be_bytes()[..], 3));
	let sum = |bytes: &[u8]| {
		let mut sum = bytes.chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))).sum::<u32>();
		while sum >> 16 != 0 {sum = (sum & 0xffff) + (sum >> 16)}
		sum
	};
	assert_eq!((sum(&back[..20]), sum(&back[20..]), sum(&back[28..48])), (0xffff, 0xffff, 0xffff), "a checksum of the translated error is wrong");
	quoted[22..24].copy_from_slice(&1u16.to_be_bytes());
	let mut stray = Vec::new();
	PacketBuilder::ipv4([198, 51, 100, 1], [10, 9, 0, 3], 64).icmpv4_raw(3, 1, [0; 4]).write(&mut stray, &quoted).unwrap();
	exit.send(&stray).await;
	assert!(user.recv(SECOND, |packet| packet[9] == 1).await.is_none());
	entry.shutdown().await;
}

// "A link that is down carries nothing, and nothing goes round it": every flow routed to it is answered as unreachable. "It comes back when a link does, with no action by anyone."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_is_down_answers_unreachable_and_comes_back_by_itself() {
	let time = time!();
	for forward in [true, false] {
		let (dir, site) = (scratch(if forward {"links-down-forward"} else {"links-down-reverse"}), site().await);
		let (pin, roots) = certify(&dir.join("exit"));
		let (home, pair) = (listen(), Pair {forward, over: Over::Obfs, at: SocketAddr::new(outward(), port()), pin, origin: site.addr});
		// The entry starts alone: its link has nobody to dial, or nobody dials it.
		let entry = run(&pair.entry(home), &dir.join("entry"), time, &roots).await;
		let mut user = Peer::device(&USER, &ENTRY, home, USER_ADDRESS).await;
		user.connect().await;
		let answer = user.knock(USER_ADDRESS, PUBLIC, 46000).await.expect("a flow to a link that is down got no answer");
		assert!(segment(&answer).is_some_and(|(tcp, _)| tcp.rst), "a flow to a link that is down was not reset");
		let ping = user.ping(PUBLIC, 7, 100).await.expect("a ping to a link that is down got no answer");
		assert_eq!((ping[20], ping[21]), (3, 1), "a ping to a link that is down was not answered host unreachable");
		// A name the user asks the gateway for is looked up through the exit the user is routed to, and fails at once: it is not asked another way.
		let mut query = Vec::new();
		PacketBuilder::ipv4(USER_ADDRESS, [10, 7, 0, 1], 64).udp(5353, 53).write(&mut query, &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]).unwrap();
		user.send(&query).await;
		let failed = user.recv(6 * SECOND, |packet| packet[9] == 17 && packet[20..22] == 53u16.to_be_bytes()).await.expect("a lookup through a link that is down got no answer");
		assert_eq!((&failed[28..30], failed[31] & 0x0f), (&[0x12, 0x34][..], 2), "a lookup through a link that is down did not fail with SERVFAIL");
		assert!(entry.dropped(Reason::Unreachable) >= 2 && entry.exit("near").unwrap().up_packets == 0 && entry.exit("far").unwrap().up_packets == 0, "something left another way");
		assert_ne!(entry.links()[0].status, Status::Up);
		// The exit comes up, and the dialler finds the other node on its own, by the client's waits.
		let exit = run(&pair.exit(socks().await), &dir.join("exit"), time, &roots).await;
		let deadline = Instant::now() + Duration::from_secs(90);
		while entry.links()[0].status != Status::Up {
			assert!(Instant::now() < deadline, "the link did not come back in 90 s: {:?}", entry.links());
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
		assert!(entry.links()[0].flips >= 1);
		assert_eq!(user.leaves(PUBLIC, 46001).await.as_deref(), Some("main"));
		entry.shutdown().await;
		exit.shutdown().await;
	}
}

// "Ending a link. Either operator removes it from their config. The sessions and the tunnel are dropped within one second on the node that removed it."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_that_removes_the_link_cuts_it_within_a_second() {
	let time = time!();
	for (forward, remover, test) in [(true, "exit", "links-removed-1"), (true, "entry", "links-removed-2"), (false, "exit", "links-removed-3"), (false, "entry", "links-removed-4")] {
		let mut net = linked(test, forward, Over::Obfs, |_| {}, time).await;
		assert_eq!(net.user.leaves(PUBLIC, 47000).await.as_deref(), Some("main"));
		let (node, home) = (if remover == "exit" {&net.exit} else {&net.entry}, net.entry.snapshot().config.inbounds[0].transports[0].listen());
		let mut doc = if remover == "exit" {net.pair.exit(socks().await)} else {net.pair.entry(home)};
		doc["links"] = json!([]);
		// The chain exit goes with its link, and what was routed to it is refused from here on: nothing of the test leaves for a real address.
		if remover == "entry" {doc["exits"][0] = json!({"tag": "far", "backend": {"type": "block"}})}
		let started = Instant::now();
		node.reload(doc.to_string().into_bytes(), None).await.unwrap();
		assert!(node.links().is_empty());
		// Within a second the link's session ends on the node that is dialled, and its dialler on the node that dials.
		let deadline = Instant::now() + SECOND;
		while (node.obfs().sessions, node.diallers()) != (0, 0) {
			assert!(Instant::now() < deadline, "{test}: the link the {remover} removed still had {} sessions and {} diallers after a second", node.obfs().sessions, node.diallers());
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
		assert!(started.elapsed() <= Duration::from_millis(1500), "{test}: the link ended after {:?}", started.elapsed());
		net.entry.shutdown().await;
		net.exit.shutdown().await;
	}
}

// A hostile exit answers every flow it was ever given, to keep them all. Answers keep no flow its device has closed or left, so the users of a link cannot be locked out of their share of the table, and so out of every other exit, from the exit's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_from_a_hostile_exit_keep_no_flow_its_user_has_closed() {
	const OTHER: [u8; 4] = [93, 184, 216, 99];
	let (time, proxy) = (time!(), socks().await);
	let (entry, mut exit, mut user, _) = hostile_exit("links-hostile-keep", time, |doc| {
		doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "proxy", "type": "socks5", "server": proxy.to_string()}));
		doc["exits"].as_array_mut().unwrap().push(json!({"tag": "other", "backend": {"type": "netstack", "outbound": "proxy"}}));
		doc["routing"]["rules"].as_array_mut().unwrap().insert(0, json!({"tag": "other", "ip": ["93.184.216.99/32"], "action": {"exit": "other"}}));
	}).await;
	let segment_to = |sport: u16, syn: bool| {
		let (mut tcp, mut out) = (TcpHeader::new(sport, 80, if syn {1000} else {1001}, 65535), Vec::new());
		(tcp.syn, tcp.rst) = (syn, !syn);
		PacketBuilder::ipv4(USER_ADDRESS, PUBLIC, 64).tcp_header(tcp).write(&mut out, &[]).unwrap();
		out
	};
	// The user opens as many flows through the link as one device may hold, and the ones past that are refused.
	let full = entry.dropped(Reason::FlowTableFull);
	let mut ports = Vec::new();
	// A few at a time, read by the exit as they come, so that none is lost on the way.
	for sport in 50000..50520 {
		user.send(&segment_to(sport, true)).await;
		if sport % 8 == 7 {
			while let Some(seen) = exit.recv(Duration::from_millis(30), |packet| segment(packet).is_some_and(|(tcp, _)| tcp.syn)).await {ports.push(segment(&seen).unwrap().0.source_port)}
		}
	}
	while let Some(seen) = exit.recv(2 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| tcp.syn)).await {ports.push(segment(&seen).unwrap().0.source_port)}
	assert!(ports.len() >= 500 && entry.dropped(Reason::FlowTableFull) >= full + 8, "the user's share was not filled: {} flows reached the exit", ports.len());
	// The user closes them all. The exit answers every one of them for longer than a closed flow is kept.
	for sport in 50000..50520 {
		user.send(&segment_to(sport, false)).await;
		if sport % 8 == 7 {tokio::time::sleep(Duration::from_millis(20)).await}
	}
	let until = Instant::now() + Duration::from_secs(45);
	while Instant::now() < until {
		for port in &ports {
			let (mut ack, mut out) = (TcpHeader::new(80, *port, 7000, 65535), Vec::new());
			(ack.ack, ack.acknowledgment_number) = (true, 1001);
			PacketBuilder::ipv4(PUBLIC, [10, 9, 0, 3], 64).tcp_header(ack).write(&mut out, &[]).unwrap();
			exit.send(&out).await;
		}
		tokio::time::sleep(5 * SECOND).await;
	}
	// The user's device reads what the exit sent it meanwhile first, which has no part in what follows.
	let _ = user.recv(3 * SECOND, |_| false).await;
	user.inbox.clear();
	// The flows have gone all the same, and the user opens a new one on another exit.
	assert_eq!(user.leaves(OTHER, 51000).await.as_deref(), Some("main"), "answers from the exit kept flows the user had closed, and the user is locked out");
	entry.shutdown().await;
}

/// Leg `k` of a chain of nodes, over `udp-obfs` and dialled at `at`: the node before it dials and the node after it listens. The entry half is the link `far` and the exit half the link `up`.
fn leg(k: u8, at: SocketAddr, entry: bool) -> Value {
	let dialler = [0x30 + k; 32];
	let mut link = json!({"tag": if entry {"far"} else {"up"}, "id": URL_SAFE_NO_PAD.encode([k; 16]), "direction": "forward", "addresses": {"dialler": [format!("10.9.{k}.2")]}, "transport_secret": text(&[0x40 + k; 32])});
	if entry {(link["private_key"], link["peer"]) = (json!(text(&dialler)), json!({"inbound_public_key": text(&public(&[0x60 + k; 32])), "transports": [{"type": "udp-obfs", "endpoints": [at.to_string()]}]}))} else {(link["inbound"], link["public_key"], link["exits"]) = (json!("links"), json!(text(&public(&dialler))), json!(["far"]))}
	link
}

/// Node `k` of a chain, the one that listens for leg `k` at `ats[k - 1]`. A relay leaves through the next leg, and the last node leaves through `proxy`. A relay's link has `allow_chain`.
fn relay(k: u8, last: bool, ats: &[SocketAddr], proxy: SocketAddr) -> Value {
	let at = ats[usize::from(k) - 1];
	let mut up = leg(k, at, false);
	let mut doc = json!({"version": 1, "dns": {"servers": ["1.1.1.1:53"]}, "users": [], "inbounds": [{"tag": "links", "type": "veilway", "private_key": text(&[0x60 + k; 32]), "address": [format!("10.9.{k}.1/24")], "transports": [{"type": "udp-obfs", "listen": at.to_string()}]}]});
	if last {
		up["exits"] = json!(["main"]);
		(doc["outbounds"], doc["exits"], doc["routing"], doc["links"]) = (json!([{"tag": "proxy", "type": "socks5", "server": proxy.to_string()}]), json!([{"tag": "main", "backend": {"type": "netstack", "outbound": "proxy"}}]), json!({"default": "main", "rules": [{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]}), json!([up]));
	} else {
		up["allow_chain"] = json!(true);
		(doc["outbounds"], doc["exits"], doc["routing"], doc["links"]) = (json!([]), json!([{"tag": "far", "backend": {"type": "chain", "links": ["far"]}}]), json!({"default": "far", "rules": [{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]}), json!([up, leg(k + 1, ats[usize::from(k)], true)]));
	}
	doc
}

/// A user on the entry and `links` links in a row over `udp-obfs`, each node but the first one listening for the link before it and dialling the next. `nodes[0]` is the entry.
struct Chain {nodes: Vec<Engine>, user: Peer, ats: Vec<SocketAddr>, proxy: SocketAddr}

async fn chain(test: &'static str, links: u8, time: Time) -> Chain {
	let (dir, roots, home) = (scratch(test), Arc::new(RootCertStore::empty()), listen());
	let (ats, proxy): (Vec<SocketAddr>, SocketAddr) = ((0..links).map(|_| SocketAddr::new(outward(), port())).collect(), socks().await);
	let mut entry = Pair {forward: true, over: Over::Obfs, at: ats[0], pin: [0; 32], origin: listen()}.entry(home);
	entry["links"] = json!([leg(1, ats[0], true)]);
	let mut nodes = Vec::new();
	// The node that is dialled starts before the one that dials it, so the first dial finds it.
	for k in (1..=links).rev() {nodes.insert(0, run(&relay(k, k == links, &ats, proxy), &dir.join(format!("node{k}")), time, &roots).await)}
	nodes.insert(0, run(&entry, &dir.join("node0"), time, &roots).await);
	for (n, node) in nodes.iter().enumerate() {eventually(&format!("a link of node {n} is not up"), || node.links().iter().all(|link| link.status == Status::Up)).await}
	let mut user = Peer::device(&USER, &ENTRY, home, USER_ADDRESS).await;
	user.connect().await;
	Chain {nodes, user, ats, proxy}
}

// Node links page, "A link leaves through another link only with allow_chain": A to B to C. The last node sees nothing but the middle's link address, and the answers find their way back to A's user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chained_link_carries_tcp_pings_and_udp_through_the_middle_node_and_is_cut_when_allow_chain_goes_off() {
	let time = time!();
	let mut net = chain("links-chained", 2, time).await;
	assert_eq!(net.user.leaves(PUBLIC, 52000).await.as_deref(), Some("main"), "a connection did not leave through two links");
	let reply = net.user.ping(PUBLIC, 4242, 200).await.expect("a ping through two links was not answered");
	assert_eq!((reply.len(), reply[20], &reply[12..16], &reply[16..20], &reply[24..26]), (200, 0, &PUBLIC[..], &USER_ADDRESS[..], &4242u16.to_be_bytes()[..]), "the answer is not the user's own echo reply");
	// A datagram goes the same way, and what the last node does with it is its own business: it only has to arrive from the middle's link address.
	let (before, mut datagram) = (net.nodes[2].links()[0].traffic.down_packets, Vec::new());
	PacketBuilder::ipv4(USER_ADDRESS, PUBLIC, 64).udp(52100, 9999).write(&mut datagram, b"datagram").unwrap();
	net.user.send(&datagram).await;
	eventually("the datagram did not reach the last node", || net.nodes[2].links()[0].traffic.down_packets > before).await;
	let (middle, last) = (&net.nodes[1], &net.nodes[2]);
	assert!(middle.links()[0].chained >= 4, "{:?}", middle.links());
	assert_eq!((last.dropped(Reason::SpoofedSource), last.dropped(Reason::LinkHops), middle.dropped(Reason::LinkHops)), (0, 0, 0), "the last node saw a source that is not the middle's link address, or a packet was dropped for its hops");
	assert_eq!((net.nodes[0].links()[0].chained, last.links()[0].chained), (0, 0));
	// Turning allow_chain off at the middle ends the flows that pass through it within a second, and a new one is refused there.
	let mut doc = relay(1, false, &net.ats, net.proxy);
	doc["exits"].as_array_mut().unwrap().push(json!({"tag": "shut", "backend": {"type": "block"}}));
	(doc["routing"]["default"], doc["links"][0]["exits"]) = (json!("shut"), json!(["shut"]));
	doc["links"][0].as_object_mut().unwrap().remove("allow_chain");
	net.nodes[1].reload(doc.to_string().into_bytes(), None).await.unwrap();
	eventually("the flows of the link were not cut", || net.nodes[1].links()[0].flows == 0).await;
	let (chained, blocked) = (net.nodes[1].links()[0].chained, net.nodes[1].dropped(Reason::BlockExit));
	assert_eq!(net.user.leaves(PUBLIC, 52200).await, None, "a flow went through the middle with allow_chain off");
	assert!(net.nodes[1].dropped(Reason::BlockExit) > blocked && net.nodes[1].links()[0].chained == chained);
	for node in net.nodes {node.shutdown().await}
}

// "outgoing = min(received, 64) - 1" and "MIN_FORWARD_HOPS = 62": four links in a row end at the third middle node, which counts the packets and sends nothing on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_of_four_links_drops_at_the_third_middle_node_and_counts_it() {
	let time = time!();
	let mut net = chain("links-four", 4, time).await;
	assert_eq!(net.user.leaves(PUBLIC, 52400).await, None, "a connection went through four links");
	let (second, third, last) = (&net.nodes[2], &net.nodes[3], &net.nodes[4]);
	assert!(third.dropped(Reason::LinkHops) >= 1 && third.links()[0].dropped >= 1, "{:?}", third.links());
	assert_eq!((second.dropped(Reason::LinkHops), third.links()[0].chained, last.links()[0].traffic.down_packets), (0, 0, 0));
	for node in net.nodes {node.shutdown().await}
}
