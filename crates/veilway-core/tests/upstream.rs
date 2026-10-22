//! Another provider's subscription as an exit, end to end, in one process. Node A has users and an `upstream` exit; the provider is either a real node B (a `veilway` inbound with the control channel, a signed subscription endpoint of the test in front of it) or a node of the test's own that speaks WireGuard by hand and sends whatever it likes into A's tunnel.
//! A profile cannot name a loopback address, so the documents here name addresses of the private range and the node's `redirect` hook says where they really are. Documents are signed with a key of the test and fetched from an endpoint written in the test, with the device A made for the provider.
#[macro_use]
mod proxied;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, TcpHeader, TransportHeader};
use proxied::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use veilway_core::engine::upstream::{Hooks, Phase, PreviewError, PreviewRequest};
use veilway_core::{Engine, Options, Reason};
use veilway_engine::import::Resolve;
use veilway_engine::Redirect;
use veilway_proto::subscription::envelope::{self, SigningKey};
use veilway_proto::subscription::exchange::{Gateway, GatewayKey};
use veilway_proto::subscription::fetch::Op;
use veilway_proto::NoRandom;

/// The inbound key of node A and the keys of its two users.
const ENTRY: [u8; 32] = [0x31; 32];
const ALICE: [u8; 32] = [0x21; 32];
const BOB: [u8; 32] = [0x22; 32];
/// The WireGuard key and the account secret A made for its device with the provider.
const DEVICE: [u8; 32] = [0x61; 32];
const ACCOUNT: [u8; 16] = [0x44; 16];
/// The key of the provider node of the test that is not a real node.
const HAND: [u8; 32] = [0x71; 32];
/// Where the documents say the provider is, and where the provider's gateway is: not in A's pool.
const FAKE_OBFS: &str = "10.99.0.1:5001";
const FAKE_UDP: &str = "10.99.0.2:5002";
const THEIRS: [u8; 4] = [10, 8, 0, 2];
const THEIR_GATEWAY: [u8; 4] = [10, 8, 0, 1];
const ALICE_ADDRESS: [u8; 4] = [10, 7, 0, 2];
const BOB_ADDRESS: [u8; 4] = [10, 7, 0, 3];
const ID: &str = "test-subscription-0001";
/// How long A is given to bring an upstream up, and how long to notice that one went down.
const UP: Duration = Duration::from_secs(60);

fn gateway_private() -> [u8; 32] {std::array::from_fn(|index| 0x40 + index as u8)}

fn gateway_key() -> GatewayKey {GatewayKey::new(1, veilway_proto::proof::public_key(&gateway_private())).unwrap()}

fn entropy(bytes: &mut [u8]) -> Result<(), NoRandom> {ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), bytes).map_err(|_| NoRandom)}

fn b64(bytes: &[u8]) -> String {base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)}

fn b64url(bytes: &[u8]) -> String {base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)}

/// The key a provider signs with: the one the operator confirmed when `which` is 0x11, any other for a provider that is not who the operator thinks.
fn signer(which: u8) -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&[which; 32]).unwrap()}

fn signing(which: u8) -> SigningKey {SigningKey::new(signer(which).public_key().as_ref().try_into().unwrap()).unwrap()}

/// A SOCKS5 proxy that answers every CONNECT with its own name and holds the connection open.
async fn named(name: &'static str) -> SocketAddr {
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
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() || client.write_all(name.as_bytes()).await.is_err() {return}
				while client.read(&mut sink).await.is_ok_and(|count| count > 0) {}
			});
		}
	});
	addr
}

/// A certificate for `sub.example.com`: what a client trusts, and a server's config.
fn certify() -> (Arc<RootCertStore>, Arc<ServerConfig>) {
	let made = rcgen::generate_simple_self_signed(vec!["sub.example.com".to_string()]).unwrap();
	let (mut roots, der, provider) = (RootCertStore::empty(), CertificateDer::from(made.cert.der().to_vec()), Arc::new(rustls::crypto::ring::default_provider()));
	roots.add(der.clone()).unwrap();
	let mut config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap()).unwrap();
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	(Arc::new(roots), Arc::new(config))
}

fn http(status: &str, body: &[u8]) -> Vec<u8> {[format!("HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").as_bytes(), body].concat()}

/// The subscription endpoint of a provider: it answers every request with the signed document the provider has at that moment, and counts the requests that fetched one.
struct Provider {
	addr: SocketAddr, fetches: Arc<Mutex<u32>>, roots: Arc<RootCertStore>, link: String, fingerprint: String, signer: Arc<AtomicU8>,
	/// The serial of the document, the seeds of the keys it lists besides the signer's (none: the signer's alone), whether it answers a fetch with a refusal, members merged into the document, and the profile.
	serial: Arc<AtomicU64>, listed: Arc<Mutex<Vec<u8>>>, refusing: Arc<AtomicBool>, extra: Arc<Mutex<Value>>, profile: Arc<Mutex<Value>>,
	/// The operation of every request that reached it, and every host name the node asked its resolver for.
	ops: Arc<Mutex<Vec<&'static str>>>, asked: Arc<Mutex<Vec<String>>>, task: tokio::task::JoinHandle<()>,
}

impl Drop for Provider {
	fn drop(&mut self) {self.task.abort()}
}

impl Provider {
	async fn start(time: Time, profile: Value) -> Provider {
		let (roots, config) = certify();
		let (gateway, fetches, profile, which) = (Arc::new(Mutex::new(Gateway::new(&[(1, gateway_private())], 0, &mut entropy).unwrap())), Arc::new(Mutex::new(0u32)), Arc::new(Mutex::new(profile)), Arc::new(AtomicU8::new(0x11)));
		let (serial, listed, refusing, extra, ops) = (Arc::new(AtomicU64::new(1)), Arc::new(Mutex::new(Vec::<u8>::new())), Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(json!({}))), Arc::new(Mutex::new(Vec::<&'static str>::new())));
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let (addr, base) = (listener.local_addr().unwrap(), time.secs() - 10);
		let task = tokio::spawn({
			let (fetches, profile, which, serial, listed, refusing, extra, ops) = (fetches.clone(), profile.clone(), which.clone(), serial.clone(), listed.clone(), refusing.clone(), extra.clone(), ops.clone());
			async move {
				loop {
					let Ok((stream, _)) = listener.accept().await else {return};
					let (acceptor, gateway, fetches, profile, which, serial, listed, refusing, extra, ops) = (TlsAcceptor::from(config.clone()), gateway.clone(), fetches.clone(), profile.clone(), which.clone(), serial.clone(), listed.clone(), refusing.clone(), extra.clone(), ops.clone());
					tokio::spawn(async move {
						let Ok(mut tls) = acceptor.accept(stream).await else {return};
						let (mut buffer, mut chunk) = (Vec::new(), [0u8; 4096]);
						let end = loop {
							if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {break end + 4}
							match tls.read(&mut chunk).await {
								Ok(count) if count > 0 => buffer.extend_from_slice(&chunk[..count]),
								_ => return,
							}
						};
						let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
						let length = head.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|value| value.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
						while buffer.len() < end + length {
							match tls.read(&mut chunk).await {
								Ok(count) if count > 0 => buffer.extend_from_slice(&chunk[..count]),
								_ => return,
							}
						}
						let issued = time.secs() - 10;
						let opened = gateway.lock().unwrap().open(&buffer[end..end + length], time.secs(), || true).expect("the node sealed a request the gateway cannot open");
						let (received, reply) = (opened.request.expect("the node wrote a request the gateway cannot read"), opened.reply);
						let key = signing(which.load(Ordering::SeqCst));
						let pair = signer(which.load(Ordering::SeqCst));
						let sign = |payload: &Value| envelope::seal(&key, &serde_json::to_vec(payload).unwrap(), |signed| pair.sign(signed).as_ref().try_into().unwrap());
						ops.lock().unwrap().push(match received.op() {Op::Fetch => "fetch", Op::Confirm(_) => "confirm", Op::Release => "release", Op::Leave => "leave"});
						let envelope = if matches!(received.op(), Op::Release | Op::Leave) {
							sign(&json!({"v": 1, "subscription_id": ID, "issued_at": issued, "refusal": "released"}))
						} else if refusing.load(Ordering::SeqCst) {
							sign(&json!({"v": 1, "subscription_id": ID, "issued_at": issued, "refusal": "disabled"}))
						} else {
							if matches!(received.op(), Op::Fetch) {*fetches.lock().unwrap() += 1}
							let (profile, listed) = (profile.lock().unwrap().clone(), listed.lock().unwrap().clone());
							let keys: Vec<String> = if listed.is_empty() {vec![b64(key.bytes())]} else {listed.iter().map(|seed| b64(signing(*seed).bytes())).collect()};
							// The same serial is the same bytes, and a newer one is issued later: a refresh that finds nothing new is no fork.
							let (serial, issued) = (serial.load(Ordering::SeqCst), base + serial.load(Ordering::SeqCst));
							let mut document = json!({"v": 1, "subscription_id": ID, "serial": serial, "issued_at": issued, "expires_at": issued + 30 * 86_400, "signing_keys": keys, "provider": {"name": "Test provider"}, "profiles": [profile], "gateway_keys": [{"id": 1, "key": b64(gateway_key().public())}]});
							for (member, value) in extra.lock().unwrap().as_object().unwrap() {document[member.as_str()] = value.clone()}
							sign(&document)
						};
						let _ = tls.write_all(&http("200 OK", &reply.seal(envelope.as_bytes(), &mut entropy).unwrap())).await;
						let _ = tls.shutdown().await;
					});
				}
			}
		});
		let link = format!("veilway://sub/sub.example.com/s#v1.{}.{}.{}", b64url(signing(0x11).bytes()), b64url(&gateway_key().link()), b64url(&[0x55; 16]));
		Provider {addr, fetches, roots, link, fingerprint: signing(0x11).fingerprint().to_string(), signer: which, serial, listed, refusing, extra, profile, ops, asked: Arc::default(), task}
	}

	fn fetched(&self) -> u32 {*self.fetches.lock().unwrap()}

	/// How many requests of the operation `op` reached the provider.
	fn requests(&self, op: &str) -> usize {self.ops.lock().unwrap().iter().filter(|seen| **seen == op).count()}

	/// The provider's next document: `serial`, the transports of its one profile, and members to merge into the document.
	fn publish(&self, serial: u64, transports: Vec<Value>, extra: Value) {
		self.profile.lock().unwrap()["transports"] = json!(transports);
		*self.extra.lock().unwrap() = extra;
		self.serial.store(serial, Ordering::SeqCst);
	}

	/// Where `sub.example.com` is, for the fetch of A.
	fn resolver(&self) -> Resolve {
		let (at, asked) = (self.addr, self.asked.clone());
		Arc::new(move |host, _| {
			asked.lock().unwrap().push(host);
			Box::pin(async move {Ok(vec![at])})
		})
	}
}

/// The profile of the device A made, for the provider whose WireGuard key is `node`: the transports are the caller's.
fn profile(node: &[u8; 32], transports: Vec<Value>) -> Value {
	json!({
		"type": "veilway", "id": "home", "name": "Home", "inbound_public_key": text(&public(node)),
		"device": {"public_key": text(&public(&DEVICE)), "transport_secrets": [text(&secret(5))], "addresses": [std::net::Ipv4Addr::from(THEIRS).to_string()]},
		"gateways": [std::net::Ipv4Addr::from(THEIR_GATEWAY).to_string()], "mtu": 1390, "transport_public_key": text(&veilway_proto::proof::public_key(&TRANSPORT)),
		"transports": transports,
		"exits": [{"tag": "main", "name": "Main exit"}, {"tag": "alt", "name": "alt"}],
	})
}

fn redirect(map: &[(&str, SocketAddr)]) -> Redirect {
	let map: HashMap<SocketAddr, SocketAddr> = map.iter().map(|(fake, real)| (fake.parse().unwrap(), *real)).collect();
	Arc::new(move |address| map.get(&address).copied().unwrap_or(address))
}

/// A real node B: one `veilway` inbound on `udp-obfs`, A's device as its only user, and exits that answer with their names.
struct Real {engine: Engine, obfs: SocketAddr, doc: Value}

impl Real {
	async fn start(test: &str, time: Time, change: impl FnOnce(&mut Value)) -> Real {
		let (dir, obfs) = (scratch(&format!("{test}-b")), listen());
		let (main, alt) = (socks().await, named("alt").await);
		let mut doc = document(main, listen(), "127.0.0.1:9".parse().unwrap());
		doc["inbounds"][0]["address"] = json!(["10.8.0.1/24"]);
		doc["inbounds"][0]["transports"] = json!([{"type": "udp-obfs", "listen": obfs.to_string()}]);
		doc["users"] = json!([{"name": "up", "exits": "all", "devices": [{"name": "node", "public_key": text(&public(&DEVICE)), "transport_secrets": [text(&secret(5))], "addresses": [std::net::Ipv4Addr::from(THEIRS).to_string()]}]}]);
		doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "alt-proxy", "type": "socks5", "server": alt.to_string()}));
		doc["exits"].as_array_mut().unwrap().push(json!({"tag": "alt", "backend": {"type": "netstack", "outbound": "alt-proxy"}}));
		change(&mut doc);
		seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
		logging();
		let engine = veilway_core::start(&parsed(&doc), Options {now: time.now, replay: Some(dir.join("replay")), usage_push: 300..=600, ..Options::new(&dir)}).await.unwrap();
		Real {engine, obfs, doc}
	}

	async fn reload(&mut self, change: impl FnOnce(&mut Value)) {
		change(&mut self.doc);
		parsed(&self.doc);
		self.engine.reload(self.doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
	}

	fn redirect(&self) -> Redirect {redirect(&[(FAKE_OBFS, self.obfs)])}
}

/// What a test starts node A with.
struct Setup {time: Time, dir: PathBuf, provider: Provider, redirect: Redirect, allow: Vec<&'static str>, exit: Option<&'static str>, private: bool, refresh: Option<Duration>, preview: Option<Duration>, tag: &'static str}

impl Setup {
	fn new(time: Time, dir: PathBuf, provider: Provider, redirect: Redirect) -> Setup {Setup {time, dir, provider, redirect, allow: vec!["no_cover", "plain"], exit: None, private: true, refresh: None, preview: None, tag: "b"}}

	/// The document of node A: two users on a plain WireGuard inbound, an exit through the upstream `b`, and one that leaves from A itself and which nothing may reach but a rule that names it.
	fn document(&self, home: SocketAddr) -> Value {
		let mut upstream = json!({"tag": self.tag, "link": self.provider.link, "signing_key": self.provider.fingerprint, "private_key": text(&DEVICE), "device_secret": b64url(&ACCOUNT), "allow": self.allow, "allow_private": self.private});
		if let Some(exit) = self.exit {upstream["exit"] = json!(exit)}
		json!({
			"version": 1, "dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": text(&ENTRY), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": home.to_string()}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "up", "backend": {"type": "upstream", "upstream": self.tag}}, {"tag": "near", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "up", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}]},
			"users": [
				{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": text(&public(&ALICE)), "addresses": ["10.7.0.2"]}]},
				{"name": "bob", "exits": "all", "devices": [{"name": "phone", "public_key": text(&public(&BOB)), "addresses": ["10.7.0.3"]}]}
			],
			"upstreams": [upstream]
		})
	}

	async fn start(&self, doc: &Value) -> Engine {
		let hooks = Hooks {resolve: Some(self.provider.resolver()), retry: Some(Duration::from_secs(1)), refresh: self.refresh, preview: self.preview, redirect: Some(self.redirect.clone())};
		seed(&self.dir.join("replay"), self.time.secs() - 100, self.time.secs() - 100);
		logging();
		veilway_core::start(&parsed(doc), Options {now: self.time.now, replay: Some(self.dir.join("replay")), upstreams: Some(self.dir.join("upstreams.state")), upstream: hooks, roots: Some(self.provider.roots.clone()), ..Options::new(&self.dir)}).await.unwrap_or_else(|e| panic!("node A did not start: {e:#}"))
	}
}

fn phase(engine: &Engine) -> (Phase, String) {
	let report = engine.upstreams().remove(0);
	(report.phase, report.reason)
}

async fn until_phase(engine: &Engine, wanted: Phase, budget: Duration) {
	let deadline = Instant::now() + budget;
	while phase(engine).0 != wanted {
		assert!(Instant::now() < deadline, "the upstream is not {wanted:?} after {budget:?}: {:?}\n{}", engine.upstreams(), lines("upstream").join("\n"));
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// Waits until the upstream is anything but up.
async fn until_not_up(engine: &Engine, budget: Duration) {
	let deadline = Instant::now() + budget;
	while phase(engine).0 == Phase::Up {
		assert!(Instant::now() < deadline, "the upstream is still up after {budget:?}: {:?}", engine.upstreams());
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// A user's device of node A, over plain WireGuard.
struct Device {tunn: Arc<Mutex<Tunn>>, up: AtomicBool, socket: UdpSocket, inbox: VecDeque<Vec<u8>>, from: [u8; 4]}

impl Device {
	async fn start(key: &[u8; 32], home: SocketAddr, from: [u8; 4]) -> Device {
		let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		socket.connect(home).await.unwrap();
		let mut device = Device {tunn: Arc::new(Mutex::new(Tunn::new(StaticSecret::from(*key), PublicKey::from(public(&ENTRY)), None, None, 0, None))), up: AtomicBool::new(false), socket, inbox: VecDeque::new(), from};
		let mut out = vec![0u8; 2048];
		let TunnResult::WriteToNetwork(init) = device.tunn.lock().unwrap().format_handshake_initiation(&mut out, false) else {panic!("no initiation")};
		let _ = device.socket.send(init).await;
		let deadline = Instant::now() + Duration::from_secs(20);
		while !device.up.load(Ordering::SeqCst) {
			assert!(Instant::now() < deadline, "no handshake in 20 s");
			let mut buf = vec![0u8; 2048];
			if let Ok(Ok(n)) = timeout(Duration::from_millis(200), device.socket.recv(&mut buf)).await {
				let packets = device.take(&buf[..n]).await;
				device.inbox.extend(packets);
			}
		}
		device
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
			let _ = self.socket.send(&reply).await;
			input = Vec::new();
		}
	}

	async fn send(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let datagram = match self.tunn.lock().unwrap().encapsulate(packet, &mut out) {
			TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
			_ => panic!("the tunnel has no session to send under"),
		};
		let _ = self.socket.send(&datagram).await;
	}

	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let mut buf = vec![0u8; 2048];
			let n = timeout(deadline.checked_duration_since(Instant::now())?, self.socket.recv(&mut buf)).await.ok()?.ok()?;
			let mut found = None;
			for packet in self.take(&buf[..n]).await {
				if found.is_none() && wanted(&packet) {found = Some(packet)} else {self.inbox.push_back(packet)}
			}
			if found.is_some() {return found}
		}
	}

	/// A TCP connection to `to`:80, and what the far side says first. None when the SYN gets no answer that opens it.
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

	/// What answers a SYN to `to`:`dport` within a second: a reset, an ICMP error, a SYN-ACK, or nothing.
	async fn knock(&mut self, to: [u8; 4], dport: u16, sport: u16) -> Option<Vec<u8>> {
		let (mut syn, mut out) = (TcpHeader::new(sport, dport, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(self.from, to, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out).await;
		self.recv(SECOND, |packet| packet[9] == 1 || segment(packet).is_some_and(|(tcp, _)| tcp.destination_port == sport)).await
	}

	async fn datagram(&mut self, to: [u8; 4], sport: u16, dport: u16, payload: &[u8]) {
		let mut out = Vec::new();
		PacketBuilder::ipv4(self.from, to, 64).udp(sport, dport).write(&mut out, payload).unwrap();
		self.send(&out).await;
	}

	/// An echo request of `size` bytes to `to`, and the packet that answered it within three seconds.
	async fn ping(&mut self, to: [u8; 4], ident: u16, size: usize) -> Option<Vec<u8>> {
		let mut out = Vec::new();
		PacketBuilder::ipv4(self.from, to, 64).icmpv4_echo_request(ident, 1).write(&mut out, &vec![0x5a; size - 28]).unwrap();
		self.send(&out).await;
		self.recv(3 * SECOND, |packet| packet[9] == 1).await
	}
}

/// A provider that is a WireGuard of the test: every IP packet A's tunnel carries to it is kept, and what the test hands `inject` goes back into the tunnel.
struct Hand {addr: SocketAddr, seen: Arc<Mutex<Vec<Vec<u8>>>>, inject: tokio::sync::mpsc::UnboundedSender<Vec<u8>>, task: tokio::task::JoinHandle<()>}

impl Drop for Hand {
	fn drop(&mut self) {self.task.abort()}
}

impl Hand {
	async fn start() -> Hand {
		let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let (addr, seen, (inject, mut injected)) = (socket.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())), tokio::sync::mpsc::unbounded_channel::<Vec<u8>>());
		let task = tokio::spawn({
			let seen = seen.clone();
			async move {
				let mut tunn = Tunn::new(StaticSecret::from(HAND), PublicKey::from(public(&DEVICE)), None, None, 0, None);
				let (mut peer, mut buf, mut out, mut tick) = (None::<SocketAddr>, vec![0u8; 4096], vec![0u8; 4096], tokio::time::interval(Duration::from_millis(250)));
				loop {
					tokio::select! {
						received = socket.recv_from(&mut buf) => {
							let Ok((n, from)) = received else {continue};
							peer = Some(from);
							let mut input = buf[..n].to_vec();
							loop {
								let (reply, packet) = match tunn.decapsulate(None, &input, &mut out) {
									TunnResult::WriteToNetwork(reply) => (Some(reply.to_vec()), None),
									TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => (None, Some(packet.to_vec())),
									_ => (None, None),
								};
								if let Some(packet) = packet {seen.lock().unwrap().push(packet)}
								let Some(reply) = reply else {break};
								let _ = socket.send_to(&reply, from).await;
								input = Vec::new();
							}
						}
						Some(packet) = injected.recv() => {
							if let (Some(to), TunnResult::WriteToNetwork(datagram)) = (peer, tunn.encapsulate(&packet, &mut out)) {let _ = socket.send_to(datagram, to).await;}
						}
						_ = tick.tick() => {
							if let (Some(to), TunnResult::WriteToNetwork(datagram)) = (peer, tunn.update_timers(&mut out)) {let _ = socket.send_to(datagram, to).await;}
						}
					}
				}
			}
		});
		Hand {addr, seen, inject, task}
	}

	fn transports(&self) -> Vec<Value> {vec![json!({"type": "udp", "endpoints": [FAKE_UDP]})]}

	fn redirect(&self) -> Redirect {redirect(&[(FAKE_UDP, self.addr)])}

	fn put(&self, packet: Vec<u8>) {self.inject.send(packet).unwrap()}

	/// The packets A has carried to the provider that are not the engine's own: the control channel and the probes of the engine go to the gateway's port 47873 and nothing else does.
	fn carried(&self) -> Vec<Vec<u8>> {self.seen.lock().unwrap().iter().filter(|packet| !(packet[16..20] == THEIR_GATEWAY && packet.get(22..24) == Some(&47873u16.to_be_bytes()) && packet.len() < 100)).cloned().collect()}

	async fn wait(&self, what: &str, found: impl Fn(&[u8]) -> bool) -> Vec<u8> {
		let deadline = Instant::now() + Duration::from_secs(10);
		loop {
			if let Some(packet) = self.carried().into_iter().find(|packet| found(packet)) {return packet}
			assert!(Instant::now() < deadline, "{what}");
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}
}

fn udp_of(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let (Some(etherparse::NetHeaders::Ipv4(ip, _)), Some(TransportHeader::Udp(udp))) = (parsed.net, parsed.transport) else {return None};
	Some((SocketAddr::from((ip.source, udp.source_port)), SocketAddr::from((ip.destination, udp.destination_port)), parsed.payload.slice().to_vec()))
}

// A real provider: a user's TCP flow leaves through it, comes back as an answer to the flow, and the provider holds one device, A's own, and no packet of a user's tunnel address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_users_flow_leaves_through_the_provider_and_the_provider_sees_one_device_and_a_restart_fetches_nothing() {
	let time = time!();
	let b = Real::start("up-carry", time, |_| {}).await;
	let provider = Provider::start(time, profile(&NODE, vec![json!({"type": "udp-obfs", "endpoints": [FAKE_OBFS]})])).await;
	let (dir, home) = (scratch("up-carry-a"), listen());
	let setup = Setup::new(time, dir.clone(), provider, b.redirect());
	let doc = setup.document(home);
	let a = setup.start(&doc).await;
	until_phase(&a, Phase::Up, UP).await;
	assert_eq!(setup.provider.fetched(), 1);
	let mut alice = Device::start(&ALICE, home, ALICE_ADDRESS).await;
	assert_eq!(alice.leaves(PUBLIC, 40000).await.as_deref(), Some("main"), "a flow did not leave through the provider");
	let reply = alice.ping(PUBLIC, 4242, 200).await.expect("a ping through the provider was not answered");
	assert_eq!((reply.len(), reply[20], &reply[12..16], &reply[16..20], &reply[24..26]), (200, 0, &PUBLIC[..], &ALICE_ADDRESS[..], &4242u16.to_be_bytes()[..]), "the answer is not the user's own echo reply");
	// The provider holds A's device and sees its flows from the device's address alone: a packet from any other address would have been a spoofed source there.
	let peers = b.engine.peers(Some("up"));
	assert_eq!((peers.len(), peers[0].flows >= 2), (1, true), "{peers:?}");
	assert_eq!(b.engine.dropped(Reason::SpoofedSource), 0);
	let report = a.upstreams().remove(0);
	assert!(report.traffic.up_packets >= 3 && report.traffic.down_packets >= 3 && report.sent >= 3 && report.mtu == 1390 && report.profile.as_deref() == Some("home") && report.transport == Some("udp-obfs"), "{report:?}");
	assert_eq!((a.exit("near").unwrap().up_packets, a.exit("up").unwrap().up_packets >= 3, a.links().len()), (0, true, 0), "something left through another exit, or an upstream was listed as a node link");
	// The state file holds the document and the id, with no key of the device in it, and only its owner can read it.
	let file = dir.join("upstreams.state");
	let bytes = std::fs::read(&file).unwrap();
	for secret in [b64(&DEVICE), b64url(&ACCOUNT), setup.provider.link.clone()] {assert!(!String::from_utf8_lossy(&bytes).contains(&secret))}
	#[cfg(unix)]
	assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&file).unwrap().permissions()) & 0o777, 0o600);
	// A restart finds the document and the id where they were, and asks the provider for nothing.
	let id = report.id;
	a.shutdown().await;
	let again = setup.start(&setup.document(listen())).await;
	until_phase(&again, Phase::Up, UP).await;
	assert_eq!((setup.provider.fetched(), again.upstreams()[0].id), (1, id));
	again.shutdown().await;
	b.engine.shutdown().await;
}

// A provider of the test's own: UDP leaves from the device's address, a hostile packet it sends is dropped unless it answers a flow, and no flow of a user reaches its gateway on any port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hostile_provider_reaches_no_user_and_a_user_reaches_no_gateway_of_it() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-hand-a"), listen());
	let setup = Setup::new(time, dir, provider, hand.redirect());
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	let (mut alice, mut bob) = (Device::start(&ALICE, home, ALICE_ADDRESS).await, Device::start(&BOB, home, BOB_ADDRESS).await);
	// UDP leaves from the device's address, under a port of the node's choosing, and the answer reaches the user under the port it chose.
	alice.datagram(PUBLIC, 40001, 5300, b"ask").await;
	let seen = hand.wait("the datagram did not reach the provider", |packet| udp_of(packet).is_some_and(|(_, to, _)| to == SocketAddr::from((PUBLIC, 5300)))).await;
	let (from, to, said) = udp_of(&seen).unwrap();
	assert_eq!((from.ip(), to, said.as_slice()), (std::net::IpAddr::from(THEIRS), SocketAddr::from((PUBLIC, 5300)), &b"ask"[..]));
	let mut answer = Vec::new();
	PacketBuilder::ipv4(PUBLIC, THEIRS, 60).udp(5300, from.port()).write(&mut answer, b"echo").unwrap();
	hand.put(answer);
	let heard = alice.recv(4 * SECOND, |packet| udp_of(packet).is_some_and(|(from, _, _)| from.port() == 5300)).await.expect("the answer did not reach the user");
	let (from, to, said) = udp_of(&heard).unwrap();
	assert_eq!((from, to, said.as_slice()), (SocketAddr::from((PUBLIC, 5300)), SocketAddr::from((ALICE_ADDRESS, 40001)), &b"echo"[..]));
	// Whatever the provider saw of the users, it saw from one address: the device's, and never a tunnel address of A.
	for packet in hand.seen.lock().unwrap().iter() {assert!(packet[12..16] == THEIRS, "a packet reached the provider from {:?}", &packet[12..16])}
	// What the provider injects: an answer to nothing, packets for the users' tunnel addresses (the engine of the upstream hands the platform what is for the device alone), a packet from the gateway to a port that looks like the engine's, a SYN-ACK to a port no flow has, and an echo reply nobody asked for.
	let dropped = a.dropped(Reason::NoFlow) + a.dropped(Reason::Unparsable) + a.dropped(Reason::Fragment);
	let inject = |build: &dyn Fn(&mut Vec<u8>)| {
		let mut packet = Vec::new();
		build(&mut packet);
		hand.put(packet);
	};
	let mut synack = TcpHeader::new(80, 33333, 1, 65535);
	(synack.syn, synack.ack, synack.acknowledgment_number) = (true, true, 1001);
	inject(&|out| PacketBuilder::ipv4(PUBLIC, THEIRS, 60).udp(9, 40001).write(out, b"no flow").unwrap());
	inject(&|out| PacketBuilder::ipv4(PUBLIC, BOB_ADDRESS, 60).udp(5300, 40001).write(out, b"for bob").unwrap());
	inject(&|out| PacketBuilder::ipv4(PUBLIC, ALICE_ADDRESS, 60).udp(5300, 40001).write(out, b"for alice").unwrap());
	inject(&|out| PacketBuilder::ipv4(THEIR_GATEWAY, THEIRS, 60).udp(47873, 20000).write(out, b"like the channel").unwrap());
	inject(&|out| PacketBuilder::ipv4(PUBLIC, THEIRS, 60).tcp_header(synack.clone()).write(out, &[]).unwrap());
	inject(&|out| PacketBuilder::ipv4(PUBLIC, THEIRS, 60).icmpv4_echo_reply(1, 1).write(out, b"x").unwrap());
	eventually("the hostile packets were not all taken in", || a.dropped(Reason::NoFlow) + a.dropped(Reason::Unparsable) + a.dropped(Reason::Fragment) >= dropped + 4).await;
	assert!(alice.recv(SECOND, |_| true).await.is_none() && bob.recv(SECOND, |_| true).await.is_none(), "a packet of the provider's own making reached a user");
	// The flow that was real still works after that.
	alice.datagram(PUBLIC, 40001, 5300, b"again").await;
	assert!(hand.wait("the flow did not go on", |packet| udp_of(packet).is_some_and(|(_, _, said)| said == b"again")).await.len() > 0);
	// No flow of a user reaches the gateway of the provider's profile, on any port: the engine's own port among them (port 53 is not one to try: A's own resolver answers every flow to it and sends nothing on). A neighbour address of the same range passes, so the gate is what refuses.
	let (gate, before) = (a.dropped(Reason::Gate), a.exit("up").unwrap().up_packets);
	for (n, dport) in [47873u16, 80, 22, 8080].into_iter().enumerate() {
		let refused = alice.knock(THEIR_GATEWAY, dport, 41000 + n as u16).await.expect("a flow to the gateway got no refusal");
		assert!(segment(&refused).is_none_or(|(tcp, _)| tcp.rst), "a flow to the gateway at port {dport} was answered with more than a refusal");
	}
	alice.datagram(THEIR_GATEWAY, 41500, 47873, b"MARKER-THAT-THE-ENGINE-NEVER-SENDS").await;
	alice.datagram(THEIR_GATEWAY, 41501, 8080, b"MARKER-THAT-THE-ENGINE-NEVER-SENDS").await;
	eventually("the gate did not refuse the datagrams", || a.dropped(Reason::Gate) >= gate + 6).await;
	assert_eq!(a.exit("up").unwrap().up_packets, before, "something of a flow to the gateway entered the exit");
	assert!(!hand.seen.lock().unwrap().iter().any(|packet| packet.windows(34).any(|window| window == b"MARKER-THAT-THE-ENGINE-NEVER-SENDS")), "a datagram of a user reached the gateway of the provider");
	let _ = alice.knock([10, 8, 0, 9], 80, 42000).await;
	hand.wait("the neighbour of the gateway was refused too", |packet| segment(packet).is_some_and(|(tcp, _)| tcp.syn && tcp.destination_port == 80 && packet[16..20] == [10, 8, 0, 9])).await;
	a.shutdown().await;
}

// A provider that stops carrying the device: the exit is down and what is routed to it is refused, it falls back to nothing unless `routing.fallback` says where, and it comes back when the provider takes the device again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_that_removes_the_device_takes_the_exit_down_with_no_fallback_and_it_comes_back() {
	let time = time!();
	let mut b = Real::start("up-bye", time, |_| {}).await;
	let provider = Provider::start(time, profile(&NODE, vec![json!({"type": "udp-obfs", "endpoints": [FAKE_OBFS]})])).await;
	let (dir, home) = (scratch("up-bye-a"), listen());
	let setup = Setup::new(time, dir, provider, b.redirect());
	let mut doc = setup.document(home);
	let a = setup.start(&doc).await;
	until_phase(&a, Phase::Up, UP).await;
	let mut alice = Device::start(&ALICE, home, ALICE_ADDRESS).await;
	assert_eq!(alice.leaves(PUBLIC, 40000).await.as_deref(), Some("main"));
	let users = b.doc["users"].clone();
	b.reload(|doc| doc["users"] = json!([])).await;
	until_not_up(&a, UP).await;
	let reason = phase(&a).1;
	assert!(!reason.is_empty() && !reason.contains(&setup.provider.link), "{reason}");
	// What is routed to the exit is refused as unreachable, and nothing of it leaves through the exit that leaves from A itself.
	let unreachable = a.dropped(Reason::Unreachable);
	alice.inbox.clear();
	let refused = alice.knock(PUBLIC, 80, 43000).await.expect("a flow to a down exit got no refusal");
	assert!(segment(&refused).is_none_or(|(tcp, _)| !(tcp.syn && tcp.ack)), "a flow was carried while the exit was down");
	assert!(a.dropped(Reason::Unreachable) > unreachable && a.exit("near").unwrap().up_packets == 0 && a.upstreams()[0].refused >= 1);
	// Without a fallback the user stays on the exit that is down. With one that the config names, the exit it names is the user's meanwhile: that is the operator's word, and the only one.
	let plan = a.plan();
	assert_eq!(plan.exits[plan.automatic(0)].tag, "up");
	doc["routing"]["fallback"] = json!(["near"]);
	a.reload(doc.to_string().into_bytes(), None).await.unwrap();
	let plan = a.plan();
	assert_eq!((plan.exits[plan.automatic(0)].tag.as_str(), phase(&a).0 == Phase::Up), ("near", false));
	// The provider takes the device again, the operator asks, and the exit is back with the same state: no new fetch.
	b.reload(|doc| doc["users"] = users).await;
	assert!(a.upstream_again("b") && !a.upstream_again("nobody"));
	until_phase(&a, Phase::Up, UP).await;
	assert_eq!(setup.provider.fetched(), 1);
	doc["routing"].as_object_mut().unwrap().remove("fallback");
	a.reload(doc.to_string().into_bytes(), None).await.unwrap();
	assert_eq!(alice.leaves(PUBLIC, 40001).await.as_deref(), Some("main"), "the exit did not carry again");
	a.shutdown().await;
	b.engine.shutdown().await;
}

// The provider's tunnel carries less than the profile says: the link is lowered to it and never raised, and a packet above it is answered with the size, from the user's own gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lower_mtu_of_the_provider_is_taken_and_a_larger_packet_gets_the_size_back() {
	let time = time!();
	let b = Real::start("up-mtu", time, |doc| doc["inbounds"][0]["mtu"] = json!(1300)).await;
	let provider = Provider::start(time, profile(&NODE, vec![json!({"type": "udp-obfs", "endpoints": [FAKE_OBFS]})])).await;
	let (dir, home) = (scratch("up-mtu-a"), listen());
	let setup = Setup::new(time, dir, provider, b.redirect());
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	let deadline = Instant::now() + UP;
	while a.upstreams()[0].mtu != 1300 {
		assert!(Instant::now() < deadline, "the link was not lowered: {:?}", a.upstreams());
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let mut alice = Device::start(&ALICE, home, ALICE_ADDRESS).await;
	let big = alice.ping(PUBLIC, 4243, 1301).await.expect("a packet above the link got no answer");
	assert_eq!((big[20], big[21], u16::from_be_bytes([big[26], big[27]]), &big[12..16]), (3, 4, 1300, &[10, 7, 0, 1][..]), "{big:?}");
	let fits = alice.ping(PUBLIC, 4244, 1300).await.expect("a packet that fits got no answer");
	assert_eq!((fits.len(), fits[20]), (1300, 0));
	assert!(a.dropped(Reason::TooBig) >= 1 && a.upstreams()[0].mtu == 1300);
	a.shutdown().await;
	b.engine.shutdown().await;
}

// The exit the config names is the exit in use, or the upstream is down: the provider's own default is never an answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_exit_the_config_names_is_used_and_an_exit_the_provider_does_not_offer_leaves_nothing_through_its_default() {
	let time = time!();
	let b = Real::start("up-exit", time, |_| {}).await;
	let provider = Provider::start(time, profile(&NODE, vec![json!({"type": "udp-obfs", "endpoints": [FAKE_OBFS]})])).await;
	let (dir, home) = (scratch("up-exit-a"), listen());
	let mut setup = Setup::new(time, dir, provider, b.redirect());
	setup.exit = Some("alt");
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	let report = a.upstreams().remove(0);
	assert_eq!((report.exit.as_deref(), report.offered.clone()), (Some("alt"), vec!["main".to_owned(), "alt".to_owned()]), "{report:?}");
	let mut alice = Device::start(&ALICE, home, ALICE_ADDRESS).await;
	assert_eq!(alice.leaves(PUBLIC, 40000).await.as_deref(), Some("alt"), "the flow did not leave through the exit the config names");
	a.shutdown().await;
	setup.exit = Some("nope");
	setup.dir = scratch("up-exit-a2");
	let home = listen();
	let a = setup.start(&setup.document(home)).await;
	let deadline = Instant::now() + UP;
	while !a.upstreams()[0].reason.contains("does not offer the exit nope") {
		assert!(Instant::now() < deadline, "{:?}\n{}", a.upstreams(), lines("upstream").join("\n"));
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let mut alice = Device::start(&ALICE, home, ALICE_ADDRESS).await;
	assert_eq!((a.upstreams()[0].phase, alice.leaves(PUBLIC, 40001).await), (Phase::Down, None), "a flow left through the provider's default exit");
	a.shutdown().await;
	b.engine.shutdown().await;
}

// What a profile may make the node dial, and what the operator allowed: all of it is held at the profile, before the engine sees it, and a profile with one address that is refused is not used at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_profile_that_points_the_node_at_a_forbidden_address_or_a_way_the_operator_did_not_allow_is_not_used() {
	let time = time!();
	let loopback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let udp = |at: &str| json!({"type": "udp", "endpoints": [at]});
	let cases: Vec<(&str, Vec<Value>, bool, Vec<&'static str>, &str)> = vec![
		("loopback", vec![udp(&loopback.local_addr().unwrap().to_string())], true, vec!["plain"], "could not be fetched"),
		("pool", vec![udp("10.7.0.50:5003")], true, vec!["plain"], "inbound pool"),
		("mixed", vec![udp(FAKE_UDP), udp("10.7.0.50:5003")], true, vec!["plain"], "inbound pool"),
		("private", vec![udp(FAKE_UDP)], false, vec!["plain"], "private address"),
		("class", vec![udp(FAKE_UDP)], true, vec![], "did not allow"),
	];
	for (name, transports, private, allow, reason) in cases {
		let (dir, home) = (scratch(&format!("up-gate-{name}")), listen());
		let mut setup = Setup::new(time, dir, Provider::start(time, profile(&NODE, transports)).await, redirect(&[]));
		(setup.private, setup.allow) = (private, allow);
		let a = setup.start(&setup.document(home)).await;
		let deadline = Instant::now() + UP;
		while phase(&a).0 != Phase::Down || !phase(&a).1.contains(reason) {
			assert!(Instant::now() < deadline, "{name}: {:?}", a.upstreams());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
		assert!(timeout(Duration::from_millis(500), loopback.recv_from(&mut [0u8; 64])).await.is_err(), "{name}: the node dialled the loopback address of a profile");
		assert_eq!((a.upstreams()[0].transport, a.upstreams()[0].sent), (None, 0), "{name}");
		a.shutdown().await;
	}
}

// A document the confirmed key did not sign is not taken, and neither the link nor its token is in the reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_signed_by_another_key_is_not_taken() {
	let time = time!();
	let provider = Provider::start(time, profile(&NODE, vec![json!({"type": "udp-obfs", "endpoints": [FAKE_OBFS]})])).await;
	provider.signer.store(0x22, Ordering::SeqCst);
	let (dir, home) = (scratch("up-signer-a"), listen());
	let setup = Setup::new(time, dir.clone(), provider, redirect(&[]));
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Down, UP).await;
	let reason = phase(&a).1;
	assert!(reason.contains("could not be fetched") && !reason.contains(&setup.provider.link) && !reason.contains(&b64url(&[0x55; 16])), "{reason}");
	assert_eq!(a.upstreams()[0].profile, None);
	assert!(!dir.join("upstreams.state").exists(), "a document the key did not sign was kept");
	// The provider signs with the key again, and the next try takes it: nothing stayed down on the word of one answer.
	setup.provider.signer.store(0x11, Ordering::SeqCst);
	let deadline = Instant::now() + UP;
	while a.upstreams()[0].profile.is_none() {
		assert!(Instant::now() < deadline, "{:?}", a.upstreams());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	a.shutdown().await;
}

/// A SOCKS5 proxy that connects every CONNECT to `target`, whatever it asks for, and writes down what it was asked for: `host:port` for a name and for an address alike.
async fn lookup_proxy(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, seen) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())));
	let asked = seen.clone();
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {return};
			let asked = asked.clone();
			tokio::spawn(async move {
				let (mut hello, mut head) = ([0u8; 2], [0u8; 4]);
				if client.read_exact(&mut hello).await.is_err() {return}
				let mut methods = vec![0u8; usize::from(hello[1])];
				if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut head).await.is_err() {return}
				let host = match head[3] {
					1 => {
						let mut ip = [0u8; 4];
						if client.read_exact(&mut ip).await.is_err() {return}
						std::net::Ipv4Addr::from(ip).to_string()
					}
					3 => {
						let mut length = [0u8; 1];
						if client.read_exact(&mut length).await.is_err() {return}
						let mut name = vec![0u8; usize::from(length[0])];
						if client.read_exact(&mut name).await.is_err() {return}
						String::from_utf8_lossy(&name).into_owned()
					}
					_ => return,
				};
				let mut port = [0u8; 2];
				if client.read_exact(&mut port).await.is_err() {return}
				asked.lock().unwrap().push(format!("{host}:{}", u16::from_be_bytes(port)));
				let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {return};
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {return}
				let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
			});
		}
	});
	(addr, seen)
}

// A `via` that is a proxy: the provider's name is looked up by the proxy and never by the node's own resolver, the fetch goes through it, and a profile of datagram transports alone, which cannot, is not used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_via_that_is_a_proxy_looks_the_provider_up_itself_and_the_datagram_transports_are_not_used_through_it() {
	let time = time!();
	let provider = Provider::start(time, profile(&NODE, vec![json!({"type": "udp-obfs", "endpoints": [FAKE_OBFS]})])).await;
	let (hop, asked) = lookup_proxy(provider.addr).await;
	let (dir, home) = (scratch("up-via-a"), listen());
	let setup = Setup::new(time, dir, provider, redirect(&[]));
	let mut doc = setup.document(home);
	doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "hop", "type": "socks5", "server": hop.to_string()}));
	doc["upstreams"][0]["via"] = json!("hop");
	let a = setup.start(&doc).await;
	let deadline = Instant::now() + UP;
	while !phase(&a).1.contains("datagram transports") {
		assert!(Instant::now() < deadline, "{:?}\n{}", a.upstreams(), lines("upstream").join("\n"));
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert!(!asked.lock().unwrap().is_empty() && asked.lock().unwrap().iter().all(|at| at == "sub.example.com:443"), "the proxy was not asked for the name of the provider, and for nothing else: {:?}", asked.lock().unwrap());
	assert!(setup.provider.asked.lock().unwrap().is_empty(), "the node's own resolver was asked for {:?}", setup.provider.asked.lock().unwrap());
	assert_eq!(a.upstreams()[0].sent, 0);
	a.shutdown().await;
}

/// Waits until `done` holds, for as long as an upstream is given to move, and says what the upstream was doing when it did not.
async fn until(engine: &Engine, what: &str, done: impl Fn() -> bool) {
	let deadline = Instant::now() + UP;
	while !done() {
		assert!(Instant::now() < deadline, "{what}: {:?}\n{}", engine.upstreams(), lines("upstream").join("\n"));
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// What is read of the keys the state file holds for the upstream `tag`, as base64.
fn kept_keys(dir: &std::path::Path, tag: &str) -> Vec<String> {
	let value: Value = serde_json::from_slice(&std::fs::read(dir.join("upstreams.state")).unwrap()).unwrap();
	value["upstreams"][tag]["held"][0]["keys"].as_array().map(|keys| keys.iter().map(|key| key.as_str().unwrap().to_owned()).collect()).unwrap_or_default()
}

/// Nothing the operator or the provider gave the node in secret may be in a line the node logs or a word it says: the link, its token, the device's key and secret, and the transport secret of the device.
fn assert_clean(what: &str, said: &str, provider: &Provider) {
	for secret in [provider.link.clone(), b64url(&[0x55; 16]), text(&DEVICE), b64url(&ACCOUNT), text(&secret(5))] {assert!(!said.contains(&secret), "{what} holds a secret: {secret}")}
}

// A refresh that changes nothing the tunnel was made from leaves it alone. One that changes the candidates makes the tunnel again, and the addresses are checked again: a loopback candidate takes the exit down and nothing is dialled, and a later document without it brings the exit back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_that_changes_the_candidates_makes_the_tunnel_again_and_checks_the_addresses_again() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let loopback = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let (dir, home) = (scratch("up-refresh-a"), listen());
	let mut setup = Setup::new(time, dir, provider, hand.redirect());
	setup.refresh = Some(Duration::from_secs(1));
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	let first = a.upstreams().remove(0);
	// A new document that renames the profile and leaves its keys, addresses and candidates alone: the tunnel is not touched.
	setup.provider.profile.lock().unwrap()["name"] = json!("Renamed");
	setup.provider.publish(2, hand.transports(), json!({}));
	until(&a, "the renamed document was not taken", || a.upstreams()[0].refreshes >= first.refreshes + 2).await;
	let renamed = a.upstreams().remove(0);
	assert_eq!((renamed.starts, renamed.flips, renamed.phase), (first.starts, first.flips, Phase::Up), "a document that changes nothing the tunnel was made from restarted it");
	// A second candidate for the tunnel: it is made again from the new document.
	setup.provider.publish(3, vec![json!({"type": "udp", "endpoints": [FAKE_UDP, "10.99.0.3:5003"]})], json!({}));
	until(&a, "the tunnel was not made again", || a.upstreams()[0].starts > first.starts).await;
	until_phase(&a, Phase::Up, UP).await;
	// A candidate on the node's own loopback is a document the reader refuses: the refresh fails, the tunnel goes on, and no datagram goes there.
	let failures = a.upstreams()[0].refresh_failures;
	setup.provider.publish(4, vec![json!({"type": "udp", "endpoints": [FAKE_UDP, loopback.local_addr().unwrap().to_string()]})], json!({}));
	until(&a, "the document with a loopback candidate was not refused", || a.upstreams()[0].refresh_failures > failures).await;
	assert!(timeout(Duration::from_millis(1500), loopback.recv_from(&mut [0u8; 64])).await.is_err(), "the node dialled the loopback address of a refreshed profile");
	assert_eq!(phase(&a).0, Phase::Up);
	// A candidate inside the node's own pool reads, and is the node's to refuse: the profile is not used, the exit is down, and nothing is dialled there.
	setup.provider.publish(5, vec![json!({"type": "udp", "endpoints": [FAKE_UDP, "10.7.0.50:5003"]})], json!({}));
	until(&a, "the exit was not taken down", || phase(&a).0 == Phase::Down && phase(&a).1.contains("inbound pool")).await;
	assert_eq!(phase(&a).0, Phase::Down);
	// The provider takes it out again, and the next refresh brings the exit back: nothing latched.
	setup.provider.publish(6, hand.transports(), json!({}));
	until_phase(&a, Phase::Up, UP).await;
	a.shutdown().await;
}

// A signing key rotates only under a key that is held, and the node keeps the rotation: a restart finds the new keys and fetches nothing. A document signed by a key that was never held is refused, and the exit goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rotation_under_a_held_key_is_taken_and_kept_and_a_key_that_was_never_held_is_refused() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-rotate-a"), listen());
	let mut setup = Setup::new(time, dir.clone(), provider, hand.redirect());
	setup.refresh = Some(Duration::from_secs(1));
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	let (old, new, stranger) = (b64(signing(0x11).bytes()), b64(signing(0x33).bytes()), b64(signing(0x22).bytes()));
	assert_eq!(kept_keys(&dir, "b"), [old.clone()]);
	// The held key lists a second one.
	*setup.provider.listed.lock().unwrap() = vec![0x11, 0x33];
	setup.provider.publish(2, hand.transports(), json!({}));
	until(&a, "the rotation was not kept", || kept_keys(&dir, "b") == [old.clone(), new.clone()]).await;
	// The new key signs, and lists itself alone.
	setup.provider.signer.store(0x33, Ordering::SeqCst);
	*setup.provider.listed.lock().unwrap() = vec![0x33];
	setup.provider.publish(3, hand.transports(), json!({}));
	until(&a, "the key that was listed was not taken", || kept_keys(&dir, "b") == [new.clone()]).await;
	assert_eq!(phase(&a).0, Phase::Up);
	// A key nobody held signs the next document, and lists itself: refused, nothing changes.
	let failures = a.upstreams()[0].refresh_failures;
	setup.provider.signer.store(0x22, Ordering::SeqCst);
	*setup.provider.listed.lock().unwrap() = vec![0x22];
	setup.provider.publish(4, hand.transports(), json!({}));
	until(&a, "the stranger's document was not refused", || a.upstreams()[0].refresh_failures > failures).await;
	let report = a.upstreams().remove(0);
	assert!(report.refresh_error.as_deref().is_some_and(|reason| reason.contains("signed")), "{report:?}");
	assert_eq!((kept_keys(&dir, "b"), report.phase), (vec![new.clone()], Phase::Up), "a key that was never held changed what is kept, or took the exit down");
	assert!(!kept_keys(&dir, "b").contains(&stranger));
	// A restart finds the rotated keys and asks the provider for nothing.
	setup.provider.signer.store(0x33, Ordering::SeqCst);
	*setup.provider.listed.lock().unwrap() = vec![0x33];
	setup.provider.publish(3, hand.transports(), json!({}));
	let fetched = setup.provider.fetched();
	a.shutdown().await;
	setup.refresh = None;
	let again = setup.start(&setup.document(listen())).await;
	until_phase(&again, Phase::Up, UP).await;
	assert_eq!((setup.provider.fetched(), kept_keys(&dir, "b")), (fetched, vec![new]));
	again.shutdown().await;
}

// A move of the endpoint and refresh hosts the provider announces are held until the operator says yes: the old endpoint is used meanwhile, the status shows what waits, and a yes makes a refresh try the new endpoint first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_and_new_hosts_wait_for_the_operator_and_the_old_endpoint_is_used_meanwhile() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-move-a"), listen());
	let mut setup = Setup::new(time, dir, provider, hand.redirect());
	setup.refresh = Some(Duration::from_secs(1));
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	setup.provider.publish(2, hand.transports(), json!({"main_endpoint": {"url": "https://moved.example.com/s", "gateway_keys": [{"id": 1, "key": b64(gateway_key().public())}]}, "refresh_urls": ["https://mirror.example.net/s"]}));
	until(&a, "the move and the hosts were not reported", || a.upstreams()[0].pending_move.is_some() && !a.upstreams()[0].pending_hosts.is_empty()).await;
	let waiting = a.upstreams().remove(0);
	assert_eq!((waiting.phase, waiting.pending_move.as_deref().is_some_and(|moving| moving.contains("moved.example.com")), waiting.pending_hosts.iter().all(|host| host.contains("mirror.example.net"))), (Phase::Up, true, true), "{waiting:?}");
	// Several refreshes later: only the old endpoint was ever asked for.
	let refreshes = waiting.refreshes;
	until(&a, "no refresh went by", || a.upstreams()[0].refreshes >= refreshes + 3).await;
	let asked = setup.provider.asked.lock().unwrap().clone();
	assert!(!asked.is_empty() && asked.iter().all(|host| host == "sub.example.com"), "an endpoint nobody confirmed was asked for: {asked:?}");
	// The operator says yes to both, once, and then nothing waits.
	assert_eq!(a.upstream_confirm("b", true, true).await.unwrap().unwrap(), (true, true));
	let confirmed = a.upstreams().remove(0);
	assert_eq!((confirmed.pending_move, confirmed.pending_hosts.len()), (None, 0));
	until(&a, "the confirmed move was not tried", || setup.provider.asked.lock().unwrap().iter().any(|host| host == "moved.example.com")).await;
	assert_eq!(a.upstream_confirm("b", true, true).await.unwrap().unwrap(), (false, false));
	assert!(a.upstream_confirm("nobody", true, true).await.is_none());
	assert_eq!(phase(&a).0, Phase::Up);
	a.shutdown().await;
}

// A refusal takes the exit down with a reason and a count, is tried again at the pace of a refusal, and the exit comes back the moment a refresh goes through. The state changes are in the log once each, with no secret in them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_takes_the_exit_down_and_the_refresh_that_lifts_it_brings_it_back() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-refused-a"), listen());
	let mut setup = Setup::new(time, dir, provider, hand.redirect());
	(setup.refresh, setup.tag) = (Some(Duration::from_secs(1)), "refused");
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	assert_eq!(a.upstreams()[0].flips, 1);
	let fetches = setup.provider.requests("fetch");
	setup.provider.refusing.store(true, Ordering::SeqCst);
	until(&a, "the refusal did not take the exit down", || phase(&a).0 == Phase::Down && phase(&a).1.contains("could not be refreshed")).await;
	let down = a.upstreams().remove(0);
	assert_eq!((down.flips, down.refresh_failures >= 1, down.refresh_error.is_some()), (2, true, true), "{down:?}");
	// It is asked again, over and over, and stays down meanwhile.
	until(&a, "the refusal was not tried again", || setup.provider.requests("fetch") >= fetches + 4).await;
	assert_eq!(phase(&a).0, Phase::Down);
	let said = lines("upstream refused:");
	assert_eq!(said.iter().filter(|line| line.contains("could not be refreshed")).count(), 2, "each change of state is logged once, here as the refresh's word and as the state's: {said:?}");
	setup.provider.refusing.store(false, Ordering::SeqCst);
	until_phase(&a, Phase::Up, UP).await;
	let back = a.upstreams().remove(0);
	assert_eq!((back.flips, back.refresh_error.clone()), (3, None), "{back:?}");
	assert!(lines("upstream refused:").iter().any(|line| line.contains("refreshed again")));
	for line in lines("upstream") {assert_clean("a log line", &line, &setup.provider)}
	assert_clean("the report", &format!("{back:?}"), &setup.provider);
	a.shutdown().await;
}

/// A request to look at the provider's subscription with the device of node A, under the token `token` in the link: 0x55 is the one the config names, and another is another place at the provider.
fn asking(setup: &Setup, token: u8) -> PreviewRequest {PreviewRequest {link: setup.provider.link.replace(&b64url(&[0x55; 16]), &b64url(&[token; 16])), private_key: text(&DEVICE), device_secret: b64url(&ACCOUNT), via: None, allow_private: true}}

/// The config of node A without the upstream, for the preview tests: the operator looks at a provider before any config names it.
fn bare(setup: &Setup, home: SocketAddr) -> Value {
	let mut doc = setup.document(home);
	doc["exits"].as_array_mut().unwrap().remove(0);
	doc["routing"]["default"] = json!("near");
	doc["upstreams"] = json!([]);
	doc
}

// The operator looks at a provider before a config names it: the node fetches with the device the panel made, shows what the document holds without a secret in it, and the config that follows takes the document it fetched, confirms the place, and fetches nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_preview_fetches_for_the_operator_and_the_config_that_follows_takes_its_document_without_asking_again() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-preview-a"), listen());
	let setup = Setup::new(time, dir.clone(), provider, hand.redirect());
	let a = setup.start(&bare(&setup, home)).await;
	assert!(a.upstreams().is_empty());
	let reviewing = a.upstream_preview(asking(&setup, 0x55)).await.unwrap();
	assert_eq!((reviewing.provider.as_str(), reviewing.fingerprint.as_str(), reviewing.profiles.len(), reviewing.serial), ("Test provider", setup.provider.fingerprint.as_str(), 1, 1));
	let profile = &reviewing.profiles[0];
	assert_eq!((profile.id.as_str(), profile.transports.as_slice(), profile.mtu, profile.refused.as_deref()), ("home", &["udp"][..], 1390, None));
	assert_eq!((profile.classes.as_slice(), profile.exits.len(), profile.private.len()), (&[veilway_core::config::UpstreamClass::Plain][..], 2, 1), "{profile:?}");
	assert_eq!((setup.provider.requests("fetch"), setup.provider.requests("confirm")), (1, 0));
	assert_clean("the review", &format!("{reviewing:?}"), &setup.provider);
	// Nothing was written: no state file, no config change.
	assert!(!dir.join("upstreams.state").exists());
	// The config that names the same link and device takes the document, and the place becomes permanent.
	a.reload(setup.document(home).to_string().into_bytes(), None).await.unwrap();
	until_phase(&a, Phase::Up, UP).await;
	assert_eq!((setup.provider.requests("fetch"), setup.provider.requests("confirm")), (1, 1), "the provider was asked for the document again, or never told it was taken");
	assert!(!a.upstream_decline(&reviewing.id).await, "a preview a config took is still waiting");
	assert_eq!(setup.provider.requests("release"), 0);
	a.shutdown().await;
}

// A preview the operator declines frees its place at the provider, and so does one nobody answers, after its time. At most four wait at once, and a fifth is refused with nothing fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declined_preview_and_one_nobody_answers_give_their_place_back_and_no_more_than_four_wait() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-decline-a"), listen());
	let mut setup = Setup::new(time, dir, provider, hand.redirect());
	setup.preview = Some(Duration::from_secs(3));
	let a = setup.start(&bare(&setup, home)).await;
	let first = a.upstream_preview(asking(&setup, 0x55)).await.unwrap();
	assert!(a.upstream_decline(&first.id).await && !a.upstream_decline(&first.id).await);
	assert_eq!(setup.provider.requests("release"), 1);
	let mut ids = Vec::new();
	for key in 0x62..0x66 {ids.push(a.upstream_preview(asking(&setup, key)).await.unwrap().id)}
	assert_eq!(a.upstream_preview(asking(&setup, 0x66)).await.unwrap_err(), PreviewError::Full);
	assert_eq!(setup.provider.requests("fetch"), 5, "a fifth preview asked the provider");
	until(&a, "the previews nobody answered were not released", || setup.provider.requests("release") == 5).await;
	for id in ids {assert!(!a.upstream_decline(&id).await)}
	for bad in [PreviewRequest {link: "https://example.org/s".into(), ..asking(&setup, 0x55)}, PreviewRequest {private_key: "not a key".into(), ..asking(&setup, 0x55)}, PreviewRequest {device_secret: "short".into(), ..asking(&setup, 0x55)}, PreviewRequest {via: Some("nowhere".into()), ..asking(&setup, 0x55)}] {
		assert!(matches!(a.upstream_preview(bad).await, Err(PreviewError::Invalid(_))));
	}
	assert_eq!(setup.provider.requests("fetch"), 5);
	a.shutdown().await;
}

// The operator removes an upstream through the API: the provider is told the device left, the state file loses the document, and a config that still names it does not enrol it again. A reload that merely drops an upstream tells the provider nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_an_upstream_tells_the_provider_and_a_reload_that_drops_one_does_not() {
	let time = time!();
	let hand = Hand::start().await;
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let (dir, home) = (scratch("up-leave-a"), listen());
	let setup = Setup::new(time, dir.clone(), provider, hand.redirect());
	let doc = setup.document(home);
	let a = setup.start(&doc).await;
	until_phase(&a, Phase::Up, UP).await;
	assert!(a.upstream_leave("nobody").await.is_none());
	assert_eq!(a.upstream_leave("b").await, Some(true));
	assert_eq!(setup.provider.requests("leave"), 1);
	assert!(!String::from_utf8_lossy(&std::fs::read(dir.join("upstreams.state")).unwrap()).contains("document"), "the document of a removed device is still in the state file");
	assert!(phase(&a).0 == Phase::Down && phase(&a).1.contains("removed this device"), "{:?}", phase(&a));
	a.reload(doc.to_string().into_bytes(), None).await.unwrap();
	tokio::time::sleep(Duration::from_secs(3)).await;
	assert_eq!((phase(&a).0, setup.provider.fetched(), setup.provider.requests("confirm")), (Phase::Down, 1, 1), "a removed device enrolled itself anew");
	a.shutdown().await;
	let (dir, home) = (scratch("up-leave-b"), listen());
	let provider = Provider::start(time, profile(&HAND, hand.transports())).await;
	let setup = Setup::new(time, dir.clone(), provider, hand.redirect());
	let a = setup.start(&setup.document(home)).await;
	until_phase(&a, Phase::Up, UP).await;
	a.reload(bare(&setup, home).to_string().into_bytes(), None).await.unwrap();
	tokio::time::sleep(Duration::from_secs(2)).await;
	assert_eq!(setup.provider.requests("leave"), 0, "a reload told the provider the device left");
	assert!(!String::from_utf8_lossy(&std::fs::read(dir.join("upstreams.state")).unwrap()).contains("document"), "the document of an upstream that is gone is still in the state file");
	a.shutdown().await;
}
