//! The client engine (`veilway-engine`) against the node, end to end, in one process: a node started the way `veilway run` starts it, with `udp`, `udp-obfs` and `tls` on one `veilway` inbound, and the engine's tunnel as the only client. The engine's WireGuard, transports, control channel and TCP are the engine's own; nothing of a client is written here but the packets a platform layer would hand it.
//! A profile cannot name a loopback address, so the documents here name addresses of the private range and the engine's `redirect` hook says where they really are. Documents are signed with a key of the test, and reach the engine as a file, as a whole document does, or through an endpoint written in the test that answers over TLS and enrolls the device it is asked about at the node.
#[macro_use]
mod proxied;
use etherparse::{PacketBuilder, TcpHeader};
use proxied::*;
use rcgen::PublicKeyData;
use ring::digest::{digest, SHA256};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use veilway_core::{Engine, Options};
use veilway_engine::import::{self, Fetcher, FileVault, Library};
use veilway_transport::udp::DONT_FRAGMENT;
use veilway_engine::{Agree, Class, Event, Pause, Redirect, Retry, Say, Settings, StartError, State, Status, Stop, Store, Tunnel};
use veilway_proto::control::ExitStatus;
use veilway_proto::subscription::client::Offer;
use veilway_proto::subscription::envelope::{self, SigningKey};
use veilway_proto::subscription::exchange::{Gateway, GatewayKey};
use veilway_proto::subscription::fetch::{Op, Received};
use veilway_proto::NoRandom;

const TLS_PATH: &str = "/assets/app-3f9c2e71.js";
const OBFS: &str = "10.99.0.1:5001";
const TLS: &str = "10.99.0.2:5002";
const DEAD_TLS: &str = "10.99.0.3:5003";
const SLOW_TLS: &str = "10.99.0.5:5005";
const FAKETLS: &str = "10.99.0.6:5006";
/// How long a stop the node decided may take to reach the engine: the `bye` is a datagram that a loaded runner can lose, and then only the idle keepalive and the liveness limit show the cut-off (G57).
const STOP: Duration = Duration::from_secs(60);
const PLAIN: &str = "10.99.0.4:5004";
const ID: &str = "test-subscription-0001";

/// The gateway key of the provider of every document of the tests: the id 1 and the private key 40..5f.
fn gateway_private() -> [u8; 32] {std::array::from_fn(|index| 0x40 + index as u8)}

fn gateway_key() -> GatewayKey {GatewayKey::new(1, veilway_proto::proof::public_key(&gateway_private())).unwrap()}

/// The gateway the endpoints of the tests open requests with.
fn gateway() -> Arc<Mutex<Gateway>> {Arc::new(Mutex::new(Gateway::new(&[(1, gateway_private())], 0, &mut entropy).unwrap()))}

fn entropy(bytes: &mut [u8]) -> Result<(), NoRandom> {ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), bytes).map_err(|_| NoRandom)}

fn b64(bytes: &[u8]) -> String {base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)}

fn b64url(bytes: &[u8]) -> String {base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)}

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

/// A certificate for `name` made for one test: what a client trusts, the pin of its key, and a server's config.
fn certify(name: &str, files: Option<&Path>) -> (Arc<RootCertStore>, [u8; 32], Arc<ServerConfig>) {
	let made = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
	if let Some(dir) = files {
		for (file, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
			std::fs::write(dir.join(file), pem).unwrap();
			#[cfg(unix)]
			std::fs::set_permissions(dir.join(file), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
		}
	}
	let (mut roots, der, provider) = (RootCertStore::empty(), CertificateDer::from(made.cert.der().to_vec()), Arc::new(rustls::crypto::ring::default_provider()));
	roots.add(der.clone()).unwrap();
	let mut config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap()).unwrap();
	// The fronts of these tests speak HTTP/1.1, and pick it from the client's list.
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	(Arc::new(roots), digest(&SHA256, &made.signing_key.subject_public_key_info()).as_ref().try_into().unwrap(), Arc::new(config))
}

/// A port nothing listens on: a connection to it is refused at once.
fn dead_port() -> SocketAddr {
	let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	socket.local_addr().unwrap()
}

/// A TCP port that takes a connection and never answers, like a front that holds a connection and does nothing. `held` counts the connections it took and `dropped` the ones the other end closed.
async fn hole() -> (SocketAddr, Arc<AtomicU64>, Arc<AtomicU64>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, held, dropped) = (listener.local_addr().unwrap(), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
	tokio::spawn({
		let (held, dropped) = (held.clone(), dropped.clone());
		async move {
			loop {
				let Ok((mut stream, _)) = listener.accept().await else {return};
				held.fetch_add(1, Ordering::SeqCst);
				let dropped = dropped.clone();
				tokio::spawn(async move {
					let mut sink = [0u8; 4096];
					while stream.read(&mut sink).await.is_ok_and(|count| count > 0) {}
					dropped.fetch_add(1, Ordering::SeqCst);
				});
			}
		}
	});
	(addr, held, dropped)
}

/// A node with `udp`, `udp-obfs` and `tls` on one inbound, and what a client of it needs.
struct Net {slow: (SocketAddr, Arc<AtomicU64>, Arc<AtomicU64>), engine: Arc<Engine>, doc: Arc<Mutex<Value>>, time: Time, dir: PathBuf, obfs: SocketAddr, tls: SocketAddr, plain: SocketAddr, roots: Arc<RootCertStore>, pin: [u8; 32], _site: Site}

async fn net(test: &'static str, time: Time, change: impl FnOnce(&mut Value)) -> Net {
	let (dir, site) = (scratch(test), site().await);
	let (obfs, tls, plain, main, alt) = (listen(), listen(), listen(), named("main").await, named("alt").await);
	let (roots, pin, _) = certify("node.test", Some(&dir));
	let mut doc = document(main, listen(), site.addr);
	doc["inbounds"][0]["transports"] = json!([
		{"type": "udp", "listen": plain.to_string()},
		{"type": "udp-obfs", "listen": obfs.to_string()},
		{"type": "tls", "listen": tls.to_string(), "path": TLS_PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": format!("http://{}", site.addr)}},
	]);
	doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "alt-proxy", "type": "socks5", "server": alt.to_string()}));
	doc["exits"][0]["name"] = json!("Main exit");
	doc["exits"].as_array_mut().unwrap().push(json!({"tag": "alt", "backend": {"type": "netstack", "outbound": "alt-proxy"}}));
	doc["notices"] = json!([{"severity": "warning", "text": "maintenance tonight"}]);
	change(&mut doc);
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	logging();
	let engine = veilway_core::start(&parsed(&doc), Options {now: time.now, replay: Some(dir.join("replay")), usage_push: 300..=600, ..Options::new(&dir)}).await.unwrap();
	Net {slow: hole().await, engine: Arc::new(engine), doc: Arc::new(Mutex::new(doc)), time, dir, obfs, tls, plain, roots, pin, _site: site}
}

impl Net {
	async fn reload(&self, change: impl FnOnce(&mut Value)) {reload(&self.engine, &self.doc, change).await}

	/// Where the addresses of the documents really are.
	fn redirect(&self) -> Redirect {
		let map: HashMap<SocketAddr, SocketAddr> = [(OBFS, self.obfs), (TLS, self.tls), (DEAD_TLS, dead_port()), (SLOW_TLS, self.slow.0), (PLAIN, self.plain)].into_iter().map(|(fake, real)| (fake.parse().unwrap(), real)).collect();
		Arc::new(move |address| map.get(&address).copied().unwrap_or(address))
	}

	fn settings(&self, name: &str) -> Settings {
		let time = self.time;
		Settings::new(Arc::new(Store::open(self.dir.join(format!("{name}.json")))), Arc::new(move || time.secs()), self.roots.clone(), "test network".into()).with_redirect(self.redirect())
	}

	fn pin(&self) -> String {b64(&self.pin)}
}

async fn reload(engine: &Engine, doc: &Mutex<Value>, change: impl FnOnce(&mut Value)) {
	let text = {
		let mut doc = doc.lock().unwrap();
		change(&mut doc);
		parsed(&doc);
		doc.to_string()
	};
	engine.reload(text.into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
}

/// The key of the provider of every document of the tests.
fn provider() -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&[0x11; 32]).unwrap()}

fn provider_key() -> SigningKey {SigningKey::new(provider().public_key().as_ref().try_into().unwrap()).unwrap()}

fn sign(payload: &Value) -> String {envelope::seal(&provider_key(), &serde_json::to_vec(payload).unwrap(), |signed| provider().sign(signed).as_ref().try_into().unwrap())}

fn transport(kind: &str, net: &Net) -> Value {
	match kind {
		"udp" => json!({"type": "udp", "endpoints": [PLAIN]}),
		"udp-obfs" => json!({"type": "udp-obfs", "endpoints": [OBFS]}),
		"tls" => json!({"type": "tls", "path": TLS_PATH, "candidates": [{"address": TLS, "sni": "node.test", "host": "node.test", "pins": [net.pin()]}]}),
		"tls-blocked-first" => json!({"type": "tls", "path": TLS_PATH, "candidates": [{"address": DEAD_TLS, "sni": "node.test", "host": "node.test", "pins": [net.pin()]}, {"address": TLS, "sni": "node.test", "host": "node.test", "pins": [net.pin()]}]}),
		"tls-slow-first" => json!({"type": "tls", "path": TLS_PATH, "candidates": [{"address": SLOW_TLS, "sni": "node.test", "host": "node.test", "pins": [net.pin()]}, {"address": TLS, "sni": "node.test", "host": "node.test", "pins": [net.pin()]}]}),
		"tls-blocked" => json!({"type": "tls", "path": TLS_PATH, "candidates": [{"address": DEAD_TLS, "sni": "node.test", "host": "node.test", "pins": [net.pin()]}]}),
		"faketls-blocked" => json!({"type": "faketls", "transport_public_key": text(&veilway_proto::proof::public_key(&[0x45; 32])), "candidates": [{"address": DEAD_TLS, "sni": "www.example.com"}]}),
		"faketls" => json!({"type": "faketls", "transport_public_key": text(&veilway_proto::proof::public_key(&[0x65; 32])), "candidates": [{"address": FAKETLS, "sni": "www.example.com"}]}),
		other => panic!("{other}"),
	}
}

/// The profile of device `n`, with a key the provider made, so that a document that carries it needs no endpoint.
fn profile(net: &Net, n: usize, kinds: &[&str]) -> Value {
	json!({
		"type": "veilway", "id": "home", "name": "Home", "inbound_public_key": text(&public(&NODE)),
		"device": {"public_key": text(&public(&KEYS[n])), "private_key": text(&KEYS[n]), "transport_secrets": [text(&secret(n))], "addresses": [format!("10.7.0.{}", 2 + n)]},
		"gateways": ["10.7.0.1"], "mtu": 1390, "transport_public_key": text(&veilway_proto::proof::public_key(&TRANSPORT)),
		"transports": kinds.iter().map(|kind| transport(kind, net)).collect::<Vec<_>>(),
		"exits": [{"tag": "main", "name": {"default": "Main exit", "fa": "\u{62e}\u{631}\u{648}\u{62c}\u{6cc} \u{627}\u{635}\u{644}\u{6cc}"}, "country": "DE"}, {"tag": "alt", "name": "alt"}],
		"notices": [{"severity": "warning", "text": {"default": "maintenance tonight", "fa": "\u{62a}\u{639}\u{645}\u{6cc}\u{631}\u{627}\u{62a} \u{627}\u{645}\u{634}\u{628}"}}],
	})
}

fn payload(time: Time, profiles: Vec<Value>) -> Value {
	json!({
		"v": 1, "subscription_id": ID, "serial": 1, "issued_at": time.secs() - 10, "expires_at": time.secs() + 30 * 86_400,
		"signing_keys": [b64(provider_key().bytes())], "provider": {"name": "Test provider"}, "profiles": profiles,
		"gateway_keys": [{"id": 1, "key": b64(gateway_key().public())}],
	})
}

/// A library that holds the subscription of `payload`, imported the way a file is: through the first yes, the review and the second.
async fn library(net: &Net, name: &str, payload: &Value) -> Library {
	let content = format!("v1.{}.{}", b64url(provider_key().bytes()), sign(payload));
	let (mut library, damaged) = Library::open(Box::new(FileVault(net.dir.join(format!("{name}.vault"))))).unwrap();
	assert!(damaged.is_empty());
	let Offer::Carried(offer) = import::open_file(content.as_bytes()).unwrap() else {panic!("a file is a whole document")};
	let reviewed = import::proceed_carried(offer, net.time.secs(), &library).unwrap();
	assert_eq!(reviewed.review.subscription().profiles.len(), payload["profiles"].as_array().unwrap().len());
	Fetcher::new(net.roots.clone(), None).accept(reviewed, None, &mut library).await.unwrap();
	library
}

/// A running tunnel and what a test needs to drive it as a platform would.
struct Run {tunnel: Tunnel, n: usize, inbox: VecDeque<Vec<u8>>}

fn start(net: &Net, settings: Settings, library: &Library, agree: Agree) -> Result<Tunnel, StartError> {start_as(net, settings, library, "home", agree)}

fn start_as(net: &Net, settings: Settings, library: &Library, profile: &str, agree: Agree) -> Result<Tunnel, StartError> {
	let held = &library.held()[0];
	let permit = held.connect(net.time.secs()).unwrap_or_else(|_| panic!("the test document is stale"));
	Tunnel::start(settings, held, profile, &permit, agree)
}

const PRIVATE: Agree = Agree {private: true, unsafe_profile: false};

impl Run {
	fn new(tunnel: Tunnel, n: usize) -> Self {Self {tunnel, n, inbox: VecDeque::new()}}

	/// Waits for a status `done` is happy with.
	async fn until(&self, what: &str, budget: Duration, done: impl Fn(&Status) -> bool) -> Status {
		let (mut watch, deadline) = (self.tunnel.watch(), tokio::time::Instant::now() + budget);
		loop {
			let status = watch.borrow_and_update().clone();
			if done(&status) {return status}
			if timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), watch.changed()).await.is_err() {panic!("{what}: {:?}\n{}", self.tunnel.status(), lines("veilway_engine").join("\n"))}
		}
	}

	async fn connected(&self) -> Status {self.until("the tunnel did not connect", Duration::from_secs(40), |status| matches!(status.state, State::Connected {..})).await}

	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let packet = timeout(deadline.checked_duration_since(Instant::now())?, self.tunnel.recv()).await.ok()??;
			if wanted(&packet) {return Some(packet)}
			self.inbox.push_back(packet);
		}
	}

	/// An echo request of `size` bytes, and whether the reply of the same size came back.
	async fn ping(&mut self, size: usize, seq: u16) -> bool {
		let mut out = Vec::new();
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).icmpv4_echo_request(9, seq).write(&mut out, &vec![0x5a; size - 28]).unwrap();
		assert!(self.tunnel.send(out));
		self.recv(3 * SECOND, |packet| packet.len() == size && packet[9] == 1 && packet[20] == 0 && packet[26..28] == seq.to_be_bytes()).await.is_some()
	}

	/// A TCP connection to `PUBLIC` from the device's address, and what the exit's proxy says first.
	async fn leaves(&mut self, sport: u16) -> Option<String> {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.tunnel.send(out);
		let (answer, _) = segment(&self.recv(4 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (80, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		let (mut ack, mut out) = (TcpHeader::new(sport, 80, 1001, 65535), Vec::new());
		(ack.ack, ack.acknowledgment_number) = (true, answer.sequence_number.wrapping_add(1));
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(ack).write(&mut out, &[]).unwrap();
		self.tunnel.send(out);
		let (_, said) = segment(&self.recv(Duration::from_secs(6), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (80, sport) && !data.is_empty())).await?)?;
		let (mut rst, mut out) = (TcpHeader::new(sport, 80, 1001, 0), Vec::new());
		rst.rst = true;
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(rst).write(&mut out, &[]).unwrap();
		self.tunnel.send(out);
		Some(String::from_utf8(said).unwrap())
	}
}

// No word of a rating or a class is in anything an app is given.
fn plain_words(status: &Status) {
	// The connection details name the transport on purpose, so transport words are looked for everywhere else and rating words everywhere.
	let shown = format!("{:?} {}", Status {connection: None, ..status.clone()}, status.say.map_or("", |say| say.text())).to_lowercase();
	for word in ["protected", "detectable", "unsafe", "rating", "nocover", "cover", "obfs", "tls", "fronted"] {assert!(!shown.contains(word), "{word} in {shown}")}
	let details = format!("{:?}", status.connection).to_lowercase();
	for word in ["protected", "detectable", "unsafe", "rating", "nocover", "cover"] {assert!(!details.contains(word), "{word} in {details}")}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tunnel_connects_over_each_transport_carries_packets_and_runs_the_control_channel() {
	let time = time!();
	let net = net("engine-connect", time, |_| {}).await;
	for (n, kind) in ["udp-obfs", "tls", "udp"].into_iter().enumerate() {
		let library = library(&net, kind, &payload(time, vec![profile(&net, n, &[kind])])).await;
		let mut run = Run::new(start(&net, net.settings(kind), &library, PRIVATE).unwrap(), n);
		let status = run.connected().await;
		assert_eq!(status.name, "Home");
		// A WireGuard handshake went through the session and traffic passes both ways: an echo the node answers, and a TCP connection through the exit.
		assert!(run.ping(200, 1).await, "{kind}");
		assert_eq!(run.leaves(40000 + n as u16).await.as_deref(), Some("main"), "{kind}");
		// The control channel opens inside the tunnel, and what the node says of the account arrives after the display filter, with the profile's translation where the node's text is the profile's.
		let status = run.until("the control channel did not open", Duration::from_secs(20), |status| status.control && !status.exits.is_empty() && status.usage.is_some() && !status.notices.is_empty()).await;
		assert_eq!(status.exits.iter().map(|exit| (exit.tag.as_str(), exit.name.as_str(), exit.configured, exit.selected)).collect::<Vec<_>>(), [("main", "Main exit", true, false), ("alt", "alt", false, false)]);
		assert_eq!((status.state.clone(), status.notices[0].text.as_str(), status.notices[0].subscription, status.out_of_date), (State::Connected {exit: Some("main".into())}, "maintenance tonight", None, false), "{kind}");
		assert_eq!(status.usage.map(|usage| (usage.quota_bytes, usage.period)), Some((0, veilway_proto::control::Period::None)));
		plain_words(&status);
		let counters = status.counters;
		assert!(counters.opened == 1 && counters.attempts >= 1 && counters.packets_sent >= 4 && counters.packets_received >= 3 && counters.control_opened == 1 && counters.dropped_offline == 0, "{kind}: {counters:?}");
		// The probe settles at the profile's size where the path carries it, on the transports that are probed: the datagram ones where the system can prohibit fragmentation, since a probe that is fragmented is not lost and says nothing.
		let probed = kind != "tls" && DONT_FRAGMENT;
		let mtu = if probed {run.until("the MTU was not probed", Duration::from_secs(20), |status| status.counters.probes >= 1).await.mtu} else {status.mtu};
		assert_eq!((mtu, run.tunnel.status().counters.probes > 0), (1390, probed), "{kind}");
		let last = run.tunnel.stop().await;
		assert_eq!(last.state, State::Off);
	}
	assert!(logged("tunnel state") && logged("a session is established"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_user_moves_the_exit_through_the_channel_and_the_flows_follow() {
	let time = time!();
	let net = net("engine-exit", time, |_| {}).await;
	let library = library(&net, "exit", &payload(time, vec![profile(&net, 0, &["tls"])])).await;
	let mut run = Run::new(start(&net, net.settings("exit"), &library, PRIVATE).unwrap(), 0);
	run.connected().await;
	run.until("no catalogue", Duration::from_secs(20), |status| status.control && !status.exits.is_empty()).await;
	let mut events = run.tunnel.events();
	assert_eq!(run.leaves(40100).await.as_deref(), Some("main"));
	run.tunnel.select_exit(Some("alt".into()));
	let status = run.until("the exit did not move", Duration::from_secs(20), |status| status.exits.iter().any(|exit| exit.tag == "alt" && exit.selected)).await;
	assert_eq!(status.state, State::Connected {exit: Some("alt".into())});
	assert_eq!(run.leaves(40101).await.as_deref(), Some("alt"));
	let mut seen = None;
	while let Ok(event) = timeout(SECOND, events.recv()).await {
		if let Ok(Event::Exit {status, selected}) = event {seen = Some((status, selected))}
	}
	assert_eq!(seen, Some((ExitStatus::Selected, "alt".to_string())));
	// An exit the user is not entitled to is refused and nothing changes; clearing the selection brings the configured exit back.
	run.tunnel.select_exit(Some("nope".into()));
	let mut refused = None;
	while let Ok(event) = timeout(2 * SECOND, events.recv()).await {
		if let Ok(Event::Exit {status, selected}) = event {refused = Some((status, selected))}
	}
	assert_eq!(refused, Some((ExitStatus::Refused, "alt".to_string())));
	run.tunnel.select_exit(None);
	run.until("the selection was not cleared", Duration::from_secs(20), |status| status.exits.iter().all(|exit| !exit.selected) && status.state == State::Connected {exit: Some("main".into())}).await;
	assert_eq!(run.leaves(40102).await.as_deref(), Some("main"));
	run.tunnel.stop().await;
}

/// A clock for the engine's waits, which are seconds and minutes long: they are not slept, they are written down, with the status of the tunnel at that moment, and `advance` adds them to the device's clock. The node's clock is the real one, so the engine's proofs are made on its offset, as a client with a wrong clock's are.
struct Waits {time: Time, extra: Arc<AtomicU64>, seen: Arc<Mutex<Vec<(Duration, Option<Status>)>>>, status: Arc<Mutex<Option<tokio::sync::watch::Receiver<Status>>>>}

impl Waits {
	fn new(time: Time) -> Self {Self {time, extra: Arc::new(AtomicU64::new(0)), seen: Arc::default(), status: Arc::default()}}

	fn settings(&self, base: &Settings, advance: bool) -> Settings {
		let (time, extra, seen, status) = (self.time, self.extra.clone(), self.seen.clone(), self.status.clone());
		let pause: Pause = Arc::new({
			let extra = extra.clone();
			move |wait| {
				let shown = status.lock().unwrap().as_ref().map(|watch| watch.borrow().clone());
				seen.lock().unwrap().push((wait, shown));
				if advance {extra.fetch_add(wait.as_secs(), Ordering::SeqCst);}
				Box::pin(tokio::time::sleep(Duration::from_millis(5)))
			}
		});
		let mut settings = base.clone();
		settings.clock = Arc::new(move || time.secs() + extra.load(Ordering::SeqCst));
		settings.with_pause(pause)
	}

	fn watch(&self, tunnel: &Tunnel) {*self.status.lock().unwrap() = Some(tunnel.watch())}

	async fn count(&self, at_least: usize) -> Vec<(Duration, Option<Status>)> {
		let deadline = Instant::now() + Duration::from_secs(30);
		loop {
			{
				let seen = self.seen.lock().unwrap();
				if seen.len() >= at_least {return seen.clone()}
			}
			assert!(Instant::now() < deadline, "only {} waits in 30 s", self.seen.lock().unwrap().len());
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}
}

fn seconds(wait: Duration, low: u64, high: u64) -> bool {(low..=high).contains(&wait.as_secs())}

// "Refusal wait: uniform 60 to 120 s, doubled after every refusal up to 3600 s", "a candidate is tried at most 3 times in a row ... and then the client continues in the profile's order without setting it aside", and "3 per round, then 30 s doubling to 900 s".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_marks_nothing_and_waits_longer_each_time_while_the_user_can_always_ask_again() {
	let time = time!();
	let net = net("engine-refused", time, |_| {}).await;
	let waits = Waits::new(time);
	// A device whose secret the node does not know: over validated TLS the stream proof is refused every time, with the decoy's own miss.
	let mut stranger = profile(&net, 0, &["tls"]);
	stranger["device"]["transport_secrets"] = json!([text(&[0x77; 32])]);
	let library = library(&net, "refused", &payload(time, vec![stranger])).await;
	let tunnel = start(&net, waits.settings(&net.settings("refused"), true), &library, PRIVATE).unwrap();
	waits.watch(&tunnel);
	let run = Run::new(tunnel, 0);
	let seen = waits.count(8).await;
	let ranges = [(60, 120), (120, 240), (240, 480), (15, 45), (480, 960), (960, 1920), (1920, 3600), (30, 90)];
	for (at, (low, high)) in ranges.into_iter().enumerate() {
		assert!(seconds(seen[at].0, low, high), "wait {at} was {:?}", seen[at].0);
		let status = seen[at].1.as_ref().expect("a wait with no status");
		assert!(matches!(status.state, State::Connecting {attempt: None, wait: Some(_)}), "{:?}", status.state);
		assert!(matches!(status.say, Some(Say::Refused | Say::ClockWrong)), "{:?}", status.say);
		plain_words(status);
	}
	let status = run.tunnel.status();
	assert!(status.counters.refused >= 6 && status.counters.set_aside == 0 && status.counters.unreachable == 0, "{:?}", status.counters);
	// Nothing was set aside for a refusal, and what the client remembers says so; asking again starts every count and wait over.
	run.tunnel.stop().await;
	let kept = Store::open(net.dir.join("refused.json")).kept(&format!("{ID}/home"));
	assert!(kept.standing.refusals >= 6 && kept.networks.iter().all(|(_, network)| network.aside.is_empty()), "{kept:?}");
	let again = Waits::new(time);
	let tunnel = start(&net, again.settings(&net.settings("refused"), true), &library, PRIVATE).unwrap();
	again.watch(&tunnel);
	let seen = again.count(1).await;
	assert!(seconds(seen[0].0, 1920, 3600), "the count of refusals does not survive a restart: {:?}", seen[0].0);
	tunnel.connect_again();
	// A wait of the first refusal, 60 to 120 s, and then of the second, 120 to 240 s, after waits of more than half an hour.
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		let seen = again.seen.lock().unwrap().clone();
		if seen.windows(3).any(|three| three[0].0.as_secs() >= 1920 && seconds(three[1].0, 60, 120) && seconds(three[2].0, 120, 240)) {break}
		assert!(Instant::now() < deadline, "asking again did not start the waits over: {:?}", seen.iter().map(|(wait, _)| wait.as_secs()).collect::<Vec<_>>());
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	tunnel.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_candidate_is_set_aside_for_an_hour_and_the_last_transport_is_still_tried_with_a_wait() {
	let time = time!();
	let net = net("engine-unreachable", time, |_| {}).await;
	let waits = Waits::new(time);
	let library = library(&net, "unreachable", &payload(time, vec![profile(&net, 0, &["tls-blocked"])])).await;
	let tunnel = start(&net, waits.settings(&net.settings("unreachable"), false), &library, PRIVATE).unwrap();
	waits.watch(&tunnel);
	let seen = waits.count(3).await;
	// A connection that is refused at once is no reason to dial again at once: the wait between transports, 2 to 10 s, and the user is told the server cannot be reached.
	for (wait, status) in &seen[..3] {
		assert!(seconds(*wait, 2, 10), "{wait:?}");
		let status = status.as_ref().unwrap();
		assert_eq!(status.say, Some(Say::Unreachable));
		assert!(matches!(status.state, State::Connecting {attempt: None, wait: Some(_)}));
	}
	let counters = tunnel.status().counters;
	assert!(counters.unreachable >= 3 && counters.opened == 0 && counters.refused == 0, "{counters:?}");
	tunnel.stop().await;
	let kept = Store::open(net.dir.join("unreachable.json")).kept(&format!("{ID}/home"));
	let (_, network) = &kept.networks[0];
	// "The mark and its expiry are logged at info, so that no failure is remembered forever": an hour from now at most.
	assert!(network.aside.len() == 1 && network.aside[0].0 == 0 && network.aside[0].1 == Some(0) && (time.secs() + 3_500..=time.secs() + 3_700).contains(&network.aside[0].2), "{network:?}");
	assert!(logged("a candidate is unreachable and set aside"));
}

// Windows reports a refused connection to a closed port after about 2 s, so the dead candidate cannot end inside the 250 ms stagger, which is what this test is about.
#[cfg_attr(windows, ignore = "a closed port is refused after about 2 s on Windows")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_candidate_costs_a_mark_and_the_one_that_worked_is_tried_first_and_alone_next_time() {
	let time = time!();
	let net = net("engine-blocked", time, |_| {}).await;
	let library = library(&net, "blocked", &payload(time, vec![profile(&net, 0, &["tls-blocked-first"])])).await;
	// Two candidates are raced, 250 ms apart, with the same datagram. The order they are walked in is random per installation: when the live one is first it wins before the dead one is opened, and when the dead one is first it ends at once and the live one wins. A fresh installation is made until the second order has been seen.
	let (mut name, mut seen_dead) = (String::new(), None);
	for round in 0..24 {
		name = format!("blocked{round}");
		let mut run = Run::new(start(&net, net.settings(&name), &library, PRIVATE).unwrap(), 0);
		let status = run.connected().await;
		assert!(run.ping(300, 1).await);
		// Only a candidate that was opened is an attempt, and only that takes a place of the hour's budget: the live one that wins inside the stagger leaves the dead one unopened.
		assert_eq!((status.counters.attempts, status.counters.opened), (1 + status.counters.unreachable, 1), "{:?}", status.counters);
		run.tunnel.stop().await;
		let tried = Store::open(net.dir.join(format!("{name}.json"))).kept(&format!("{ID}/home")).networks[0].1.tried.len() as u64;
		assert_eq!(tried, status.counters.attempts, "a candidate that was never opened took a place of the budget");
		if status.counters.unreachable == 1 {
			seen_dead = Some(status);
			break;
		}
	}
	let status = seen_dead.expect("the dead candidate was never walked first in 24 installations");
	assert_eq!(status.counters.set_aside, 1);
	let kept = Store::open(net.dir.join(format!("{name}.json"))).kept(&format!("{ID}/home"));
	assert!(!kept.networks.is_empty(), "{}", std::fs::read_to_string(net.dir.join(format!("{name}.json"))).unwrap_or_default());
	let (_, network) = &kept.networks[0];
	assert!(network.worked.is_some_and(|(transport, candidate, _)| (transport, candidate) == (0, 1)) && network.aside.iter().any(|(transport, candidate, _)| (*transport, *candidate) == (0, Some(0))), "{network:?}");
	// The next run on this network tries the one that worked and no other.
	let mut run = Run::new(start(&net, net.settings(&name), &library, PRIVATE).unwrap(), 0);
	let status = run.connected().await;
	assert_eq!((status.counters.attempts, status.counters.unreachable), (1, 0), "{:?}", status.counters);
	assert!(run.ping(300, 2).await);
	// On another network the memory of this one does not apply, and the state file keeps both without a name of either.
	run.tunnel.moved("another network".into(), Vec::new());
	run.tunnel.stop().await;
	let text = std::fs::read_to_string(net.dir.join(format!("{name}.json"))).unwrap();
	assert!(!text.contains("test network") && !text.contains("another network") && !text.contains("node.test") && !text.contains("10.99"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn when_the_cover_transport_is_unreachable_the_next_one_is_tried_after_the_user_said_yes_to_its_class() {
	let time = time!();
	let net = net("engine-fallback", time, |_| {}).await;
	let library = library(&net, "fallback", &payload(time, vec![profile(&net, 0, &["tls-blocked", "udp-obfs"])])).await;
	// A profile that lists a lower class asks once before its first connection, and the question names no class.
	let key = format!("{ID}/home");
	let settings = net.settings("fallback");
	let Err(StartError::Ask(classes)) = start(&net, settings.clone(), &library, PRIVATE) else {panic!("no question was asked")};
	assert_eq!(classes, [Class::NoCover]);
	assert!(!veilway_engine::ask_text(Class::NoCover).to_lowercase().contains("cover"));
	settings.store.decline(&key, Class::NoCover);
	// Said no, the client uses the best class alone and never asks again, and it keeps trying it.
	let waits = Waits::new(time);
	let tunnel = start(&net, waits.settings(&settings, false), &library, PRIVATE).unwrap();
	waits.watch(&tunnel);
	let seen = waits.count(2).await;
	assert!(tunnel.status().counters.opened == 0 && seen.iter().all(|(wait, _)| seconds(*wait, 2, 10)));
	tunnel.stop().await;
	// Said yes, it falls back after the wait between transports and sets the unreachable one aside for an hour.
	settings.store.agree(&key, Class::NoCover);
	let waits = Waits::new(time);
	let mut run = Run::new(start(&net, waits.settings(&settings, false), &library, PRIVATE).unwrap(), 0);
	waits.watch(&run.tunnel);
	run.connected().await;
	assert!(run.ping(300, 1).await);
	let seen = waits.seen.lock().unwrap().clone();
	assert!(seen.iter().any(|(wait, _)| seconds(*wait, 2, 10)), "{seen:?}");
	run.tunnel.stop().await;
	settings.store.flush().unwrap();
	let kept = Store::open(net.dir.join("fallback.json")).kept(&key);
	let (_, network) = &kept.networks[0];
	assert!(network.aside.iter().any(|(transport, candidate, until)| (*transport, *candidate) == (0, None) && *until <= time.secs() + 3_700) && network.worked.is_some_and(|(transport, _, _)| transport == 1), "{network:?} {}", std::fs::read_to_string(net.dir.join("fallback.json")).unwrap());
	assert!(logged("a transport is unreachable and set aside"));
}

// "No `faketls` candidate is dialed until `alpha_transports` is on": off, a profile is used as if it had no `faketls` transport, and one with nothing else does not start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_faketls_transport_is_never_dialed_while_alpha_transports_is_off() {
	let time = time!();
	let net = net("engine-alpha", time, |_| {}).await;
	let both = library(&net, "alpha", &payload(time, vec![profile(&net, 0, &["faketls-blocked", "udp-obfs"])])).await;
	let settings = net.settings("alpha");
	assert!(!settings.store.alpha_transports());
	// Off, `udp-obfs` is the best class the profile has, so there is no question, and it is the only transport tried.
	let mut run = Run::new(start(&net, settings.clone(), &both, PRIVATE).unwrap(), 0);
	let status = run.connected().await;
	assert!(run.ping(200, 1).await);
	assert_eq!((status.connection.as_ref().map(|connection| (connection.transport, connection.alpha)), status.counters.attempts), (Some(("udp-obfs", false)), 1));
	run.tunnel.stop().await;
	settings.store.flush().unwrap();
	assert!(Store::open(net.dir.join("alpha.json")).kept(&format!("{ID}/home")).networks.iter().all(|(_, network)| network.aside.is_empty()));
	// On, `faketls` is the cover transport of the profile, and `udp-obfs` now needs the user's yes.
	settings.store.set_alpha_transports(true);
	assert_eq!(start(&net, settings.clone(), &both, PRIVATE).err(), Some(StartError::Ask(vec![Class::NoCover])));
	// A profile whose only transport is `faketls` does not start while the setting is off, and does once it is on.
	let only = library(&net, "alpha-only", &payload(time, vec![profile(&net, 1, &["faketls-blocked"])])).await;
	let settings = net.settings("alpha-only");
	// Its address is a private one, which is asked about only when the transport may be dialled.
	assert_eq!(start(&net, settings.clone(), &only, Agree::default()).err(), Some(StartError::Alpha));
	assert_eq!(start(&net, settings.clone(), &only, PRIVATE).err(), Some(StartError::Alpha));
	assert!(!veilway_engine::ALPHA_WARNING.is_empty());
	settings.store.set_alpha_transports(true);
	assert_eq!(start(&net, settings.clone(), &only, Agree::default()).err(), Some(StartError::Private));
	start(&net, settings, &only, PRIVATE).unwrap().stop().await;
}

// A session over `faketls` that is running ends when `alpha_transports` is turned off, and the profile is used as if it had no `faketls` transport from then on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_alpha_transports_off_ends_a_running_faketls_session() {
	let (time, borrowed) = (time!(), listen());
	let made = rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()]).unwrap();
	let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![CertificateDer::from(made.cert.der().to_vec())], PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap()).unwrap();
	let (site, acceptor) = (TcpListener::bind("127.0.0.1:0").await.unwrap(), TlsAcceptor::from(Arc::new(config)));
	let site_addr = site.local_addr().unwrap();
	// The site answers each request with one page and closes, as a site does that has nothing to keep a connection for.
	let site_task = tokio::spawn(async move {
		while let Ok((stream, _)) = site.accept().await {
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(mut tls) = acceptor.accept(stream).await else {return};
				let (mut head, mut buf) = (Vec::new(), vec![0u8; 4096]);
				while !head.windows(4).any(|window| window == b"\r\n\r\n") {
					match timeout(Duration::from_millis(250), tls.read(&mut buf)).await {
						Ok(Ok(count)) if count > 0 => head.extend_from_slice(&buf[..count]),
						_ => return drop(tls.shutdown().await),
					}
				}
				let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").await;
				let _ = tls.shutdown().await;
			});
		}
	});
	let net = net("engine-alpha-live", time, |doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "faketls", "listen": borrowed.to_string(), "transport_key": text(&[0x65; 32]), "site": {"host": "www.example.com", "address": site_addr.to_string(), "acknowledged": true}}))).await;
	let (base, fake) = (net.redirect(), FAKETLS.parse::<SocketAddr>().unwrap());
	let settings = net.settings("alpha-live").with_redirect(Arc::new(move |address| if address == fake {borrowed} else {base(address)}));
	let only = library(&net, "alpha-live", &payload(time, vec![profile(&net, 0, &["faketls"])])).await;
	settings.store.set_alpha_transports(true);
	let mut run = Run::new(start(&net, settings.clone(), &only, PRIVATE).unwrap(), 0);
	let status = run.connected().await;
	assert_eq!(status.connection.as_ref().map(|connection| (connection.transport, connection.alpha)), Some(("faketls", true)));
	assert!(run.ping(200, 1).await);
	settings.store.set_alpha_transports(false);
	let status = run.until("the faketls session was not ended", Duration::from_secs(30), |status| matches!(status.state, State::Failed)).await;
	assert_eq!(status.say, Some(Say::AlphaOff));
	// Nothing dials it again while the setting is off.
	let attempts = status.counters.attempts;
	tokio::time::sleep(Duration::from_secs(3)).await;
	let status = run.tunnel.status();
	assert!(matches!(status.state, State::Failed) && status.counters.attempts == attempts, "{:?}", status);
	// And on again, it connects without a new start.
	settings.store.set_alpha_transports(true);
	run.tunnel.connect_again();
	run.until("it did not connect again", Duration::from_secs(40), |status| matches!(status.state, State::Connected {..})).await;
	run.tunnel.stop().await;
	site_task.abort();
}

// "A client that received `bye` knows the tunnel was ended on purpose. It shows the reason, does not treat any transport or candidate as failed, and does not run transport fallback."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bye_stops_the_tunnel_until_its_reason_is_gone_and_counts_against_no_candidate() {
	let time = time!();
	let net = net("engine-bye", time, |_| {}).await;
	let library = library(&net, "bye", &payload(time, vec![profile(&net, 0, &["udp-obfs"])])).await;
	let mut run = Run::new(start(&net, net.settings("bye"), &library, PRIVATE).unwrap(), 0);
	run.connected().await;
	run.until("the channel did not open", Duration::from_secs(20), |status| status.control && !status.exits.is_empty()).await;
	let mut events = run.tunnel.events();
	// Disabled: the node says so before it cuts the device off.
	net.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	let status = run.until("the tunnel did not stop", STOP, |status| matches!(status.state, State::Stopped {..})).await;
	let State::Stopped {reason, retry: Retry::At(at)} = status.state else {panic!("{:?}", status.state)};
	assert_eq!((reason, status.say), (Stop::Disabled, Some(Say::Disabled)));
	assert!((time.secs() + 55..=time.secs() + 125).contains(&at), "tries again in {} s", at.saturating_sub(time.secs()));
	let mut told = Vec::new();
	while let Ok(Ok(event)) = timeout(Duration::from_millis(300), events.recv()).await {told.push(event)}
	assert!(told.contains(&Event::Stopped(Stop::Disabled)) && !told.contains(&Event::Lost), "a bye is no lost session: {told:?}");
	// It does not walk through the transports and the fronts: no attempt, nothing set aside, nothing refused.
	let counters = status.counters;
	tokio::time::sleep(Duration::from_secs(3)).await;
	let after = run.tunnel.status().counters;
	assert_eq!((after.attempts, after.unreachable, after.refused, after.set_aside, counters.byes), (counters.attempts, 0, 0, 0, 1), "{after:?}");
	plain_words(&run.tunnel.status());
	// The user asks again: one attempt, which the node refuses as it refuses a stranger.
	run.tunnel.connect_again();
	let status = run.until("no attempt", Duration::from_secs(10), |status| status.counters.attempts > counters.attempts).await;
	assert!(matches!(status.state, State::Reconnecting {attempt: Some(_), ..}), "{:?}", status.state);
	// The account is back, and asking again connects.
	net.reload(|doc| doc["users"][0]["enabled"] = json!(true)).await;
	run.tunnel.connect_again();
	run.connected().await;
	assert!(run.ping(300, 1).await);
	run.tunnel.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quota_that_is_used_up_waits_for_the_next_period_and_an_expired_account_waits_for_the_user() {
	let time = time!();
	let net = net("engine-quota", time, |doc| {
		doc["users"][0]["quota_bytes"] = json!(30_000);
		doc["users"][0]["quota_period"] = json!("daily");
	}).await;
	let library = library(&net, "quota", &payload(time, vec![profile(&net, 0, &["udp-obfs"])])).await;
	let mut run = Run::new(start(&net, net.settings("quota"), &library, PRIVATE).unwrap(), 0);
	run.connected().await;
	run.until("the channel did not open", Duration::from_secs(20), |status| status.control && status.usage.is_some_and(|usage| usage.quota_bytes == 30_000)).await;
	for seq in 0..30 {
		let mut out = Vec::new();
		PacketBuilder::ipv4(address(0), PUBLIC, 64).icmpv4_echo_request(9, seq).write(&mut out, &[0x5a; 1200]).unwrap();
		run.tunnel.send(out);
	}
	let status = run.until("the tunnel did not stop for its quota", STOP, |status| matches!(status.state, State::Stopped {..})).await;
	// "When the next period starts, worked out from `period` and `period_start` of the last `usage`."
	let usage = status.usage.expect("a last usage");
	assert!(usage.used_bytes >= usage.quota_bytes && usage.period == veilway_proto::control::Period::Daily, "{usage:?}");
	assert_eq!(status.state, State::Stopped {reason: Stop::Quota, retry: Retry::At(usage.period_start + 86_400)});
	assert_eq!(status.say, Some(Say::QuotaUsed));
	// A reload that raises the quota, and a refreshed subscription that shows it, end the stop.
	net.reload(|doc| doc["users"][0]["quota_bytes"] = json!(10_000_000)).await;
	run.tunnel.refreshed(Some(veilway_proto::subscription::payload::Usage {used_bytes: 0, quota_bytes: 10_000_000, period: veilway_proto::control::Period::Daily, period_start: usage.period_start, expires_at: 0, device_limit: 0}));
	run.connected().await;
	assert!(run.ping(300, 1).await);
	run.until("the channel did not open again", Duration::from_secs(20), |status| status.control).await;
	// An account that expired: nothing but the user, or a refreshed subscription with a later expiry, brings the tunnel back.
	net.reload(|doc| doc["users"][0]["expires_at"] = json!("2020-01-01T00:00:00Z")).await;
	let status = run.until("the tunnel did not stop for its expiry", STOP, |status| matches!(status.state, State::Stopped {..})).await;
	assert_eq!(status.state, State::Stopped {reason: Stop::Expired, retry: Retry::Asked});
	let attempts = status.counters.attempts;
	tokio::time::sleep(Duration::from_secs(2)).await;
	assert_eq!(run.tunnel.status().counters.attempts, attempts);
	net.reload(|doc| doc["users"][0]["expires_at"] = json!("2090-01-01T00:00:00Z")).await;
	run.tunnel.refreshed(Some(veilway_proto::subscription::payload::Usage {used_bytes: 0, quota_bytes: 0, period: veilway_proto::control::Period::None, period_start: 0, expires_at: time.secs() + 86_400, device_limit: 0}));
	run.connected().await;
	run.tunnel.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_drops_the_device_on_a_reload_ends_the_session_and_the_engine_says_so_and_a_node_that_stops_says_so_too() {
	let time = time!();
	let net = net("engine-removed", time, |_| {}).await;
	let (mut away, mut third) = (profile(&net, 1, &["tls"]), profile(&net, 2, &["udp-obfs"]));
	(away["id"], third["id"]) = (json!("away"), json!("third"));
	let library = library(&net, "removed", &payload(time, vec![profile(&net, 0, &["tls"]), away, third])).await;
	let gone = Run::new(start(&net, net.settings("removed"), &library, PRIVATE).unwrap(), 0);
	gone.connected().await;
	gone.until("the channel did not open", Duration::from_secs(20), |status| status.control).await;
	let mut events = gone.tunnel.events();
	// The user is removed with its device. The node closes the session of a stream transport, and the engine sees a session that ended and is refused as a stranger from then on.
	let began = Instant::now();
	net.reload(|doc| drop(doc["users"].as_array_mut().unwrap().remove(0))).await;
	let status = gone.until("the session did not end", Duration::from_secs(10), |status| !matches!(status.state, State::Connected {..})).await;
	assert!(began.elapsed() < Duration::from_secs(5), "{:?}", began.elapsed());
	assert!(!status.control && status.counters.lost + status.counters.byes == 1, "{:?}", status.counters);
	let mut told = Vec::new();
	while let Ok(Ok(event)) = timeout(Duration::from_millis(300), events.recv()).await {told.push(event)}
	assert!(told.contains(&Event::Lost) || told.contains(&Event::Stopped(Stop::Disabled)), "{told:?}");
	if !matches!(status.state, State::Stopped {..}) {
		let status = gone.until("no refusal", Duration::from_secs(20), |status| status.counters.refused >= 1 && matches!(status.state, State::Reconnecting {wait: Some(_), ..})).await;
		assert_eq!(status.say, Some(Say::Refused));
	}
	gone.tunnel.stop().await;
	// A device whose key is replaced is a device removed, and no reason is among the four: a session that ended, and a stranger from then on.
	let replaced = Run::new(start_as(&net, net.settings("removed"), &library, "away", PRIVATE).unwrap(), 1);
	replaced.connected().await;
	replaced.until("the channel did not open", Duration::from_secs(20), |status| status.control).await;
	net.reload(|doc| doc["users"][0]["devices"][0]["public_key"] = json!(text(&public(&[0x77; 32])))).await;
	let status = replaced.until("the session did not end", Duration::from_secs(10), |status| !matches!(status.state, State::Connected {..})).await;
	assert!(!status.control && status.counters.lost + status.counters.byes == 1, "{:?}", status.counters);
	// The node says "removed" before it closes the session when it gets the bye out first, and closes it with no word when it does not: both are a session that ended, and the second is a stranger from then on.
	if !matches!(status.state, State::Stopped {reason: Stop::Disabled, ..}) {
		let status = replaced.until("no refusal", Duration::from_secs(20), |status| status.counters.refused >= 1 && matches!(status.state, State::Reconnecting {wait: Some(_), ..})).await;
		assert_eq!(status.say, Some(Say::Refused));
	}
	replaced.tunnel.stop().await;
	// The node stops: `bye` with that reason, and the engine tries again after the ordinary reconnect wait, which finds nobody home.
	let stopped = Run::new(start_as(&net, net.settings("removed"), &library, "third", PRIVATE).unwrap(), 2);
	let mut events = stopped.tunnel.events();
	stopped.connected().await;
	stopped.until("the channel did not open", Duration::from_secs(20), |status| status.control).await;
	// Watched while the node shuts down: the stop is a state of a second or two, and a shutdown that takes long (it does on Windows) is over after the engine has gone on.
	let (_, status) = tokio::join!(async {Arc::try_unwrap(net.engine).ok().expect("the engine is held by nobody else").shutdown().await}, stopped.until("no stop", Duration::from_secs(10), |status| matches!(status.state, State::Stopped {..})));
	let State::Stopped {reason, retry: Retry::At(at)} = status.state else {panic!("{:?}", status.state)};
	assert_eq!(reason, Stop::NodeStopping);
	assert!(at <= time.secs() + 3, "the ordinary reconnect wait is a second or two: {} s", at.saturating_sub(time.secs()));
	let mut told = Vec::new();
	while let Ok(Ok(event)) = timeout(Duration::from_millis(300), events.recv()).await {told.push(event)}
	assert!(told.contains(&Event::Stopped(Stop::NodeStopping)), "{told:?}");
	let status = stopped.until("no new try", Duration::from_secs(15), |status| matches!(status.state, State::Reconnecting {..})).await;
	assert!(matches!(status.say, Some(Say::NodeStopping | Say::Unreachable | Say::Silence | Say::Lost)), "{:?}", status.say);
	stopped.tunnel.stop().await;
}

// "The client takes its MTU from the signed profile. Path MTU discovery can lower it, never raise it, and never below 1280, or 1080 on a tunnel whose addresses are all IPv4." What the node says is bounded by the profile's, and the probing settles at a size the node takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mtu_is_lowered_to_what_the_node_and_the_probes_allow_and_never_raised() {
	let time = time!();
	let net = net("engine-mtu", time, |doc| doc["inbounds"][0]["mtu"] = json!(1300)).await;
	let library = library(&net, "mtu", &payload(time, vec![profile(&net, 0, &["udp-obfs"])])).await;
	let mut run = Run::new(start(&net, net.settings("mtu"), &library, PRIVATE).unwrap(), 0);
	let mut events = run.tunnel.events();
	run.connected().await;
	let status = run.until("the MTU was not lowered", Duration::from_secs(20), |status| status.control && status.mtu == 1300 && (status.counters.probes >= 1 || !DONT_FRAGMENT)).await;
	assert_eq!(status.mtu, 1300);
	let mut told = Vec::new();
	while let Ok(Ok(event)) = timeout(Duration::from_millis(300), events.recv()).await {told.push(event)}
	assert!(told.contains(&Event::Mtu(1300)) && !told.iter().any(|event| matches!(event, Event::Mtu(mtu) if *mtu > 1300)), "{told:?}");
	// The node took the size the device set, and a packet that fits it passes. Where fragmentation cannot be prohibited the device walks nothing and sets nothing, and the node's size is the inbound's, which is the same.
	if DONT_FRAGMENT {eventually("the node did not take the device's MTU", || net.engine.peers(Some("a")).first().is_some_and(|peer| peer.mtu == Some(1300))).await}
	assert!(run.ping(1300, 1).await);
	run.tunnel.stop().await;
}

// A path that carries less than 1280 and the overhead of `udp-obfs`, made by hand: run as root with `VEILWAY_TEST_PATH=1350` after `nft add table inet path; nft add chain inet path o "{ type filter hook output priority -300; }"; nft add rule inet path o oifname lo meta l4proto udp ip length gt 1350 drop`. On a tunnel of IPv4 alone the walk goes below 1280 to the largest size of the table that fits, and padding never makes a packet the path drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tunnel_of_ipv4_alone_works_on_a_path_below_1280_and_its_overhead() {
	let Some(limit) = std::env::var("VEILWAY_TEST_PATH").ok().and_then(|limit| limit.parse::<u16>().ok()) else {return};
	let time = time!();
	let net = net("engine-small-path", time, |doc| doc["inbounds"][0]["mtu"] = json!(1390)).await;
	let library = library(&net, "small-path", &payload(time, vec![profile(&net, 0, &["udp-obfs"])])).await;
	let mut run = Run::new(start(&net, net.settings("small-path"), &library, PRIVATE).unwrap(), 0);
	run.connected().await;
	let fits = veilway_proto::control::PROBE_SIZES.into_iter().filter(|size| size + 62 + 28 <= limit).max().unwrap();
	let status = run.until("the size that fits was not found", Duration::from_secs(40), |status| status.control && status.mtu == fits).await;
	assert!(status.mtu < 1280);
	eventually("the node did not take the device's MTU", || net.engine.peers(Some("a")).first().is_some_and(|peer| peer.mtu == Some(fits))).await;
	for seq in 1..=20 {assert!(run.ping(usize::from(fits), seq).await)}
	run.tunnel.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_app_must_ask_first_stops_the_start_and_a_document_long_out_of_date_asks_once_more() {
	let time = time!();
	let net = net("engine-start", time, |_| {}).await;
	let mut unsafe_profile = profile(&net, 0, &["tls"]);
	unsafe_profile["rating_cap"] = json!("unsafe");
	let library = library(&net, "start", &payload(time, vec![unsafe_profile])).await;
	let held = &library.held()[0];
	let permit = held.connect(time.secs()).unwrap_or_else(|_| panic!("stale"));
	let settings = net.settings("start");
	// Nothing is sent before the plain warning of an Unsafe profile was shown and tapped, nor before a private address was agreed to, and a profile or permit that is not the subscription's is refused.
	assert_eq!(Tunnel::start(settings.clone(), held, "home", &permit, Agree {private: true, unsafe_profile: false}).err(), Some(StartError::Unsafe));
	assert_eq!(Tunnel::start(settings.clone(), held, "home", &permit, Agree {private: false, unsafe_profile: true}).err(), Some(StartError::Private));
	assert_eq!(Tunnel::start(settings.clone(), held, "nope", &permit, PRIVATE).err(), Some(StartError::NoProfile));
	let other = library_other(&net).await;
	assert_eq!(Tunnel::start(settings.clone(), &other.held()[0], "home", &permit, Agree {private: true, unsafe_profile: true}).err(), Some(StartError::Permit));
	// The document is past its expiry by more than 30 days: "every connect needs one explicit confirmation", which is the permit's own method.
	let Err(stale) = held.connect(time.secs() + 90 * 86_400) else {panic!("a document 60 days past its expiry was not stale")};
	let permit = stale.confirmed();
	let mut run = Run::new(Tunnel::start(settings, held, "home", &permit, Agree {private: true, unsafe_profile: true}).unwrap(), 0);
	run.connected().await;
	assert!(run.ping(300, 1).await);
	run.tunnel.stop().await;
}

// A second subscription, of another id, for the permit of the first to be refused with.
async fn library_other(net: &Net) -> Library {
	let mut other = payload(net.time, vec![profile(net, 1, &["tls"])]);
	other["subscription_id"] = json!("test-subscription-0002");
	library(net, "other", &other).await
}

/// What an endpoint written in the test answers with.
#[derive(Clone, Copy, PartialEq)]
enum Mode {Normal, Chunked, Redirect, Missing, Encoded, Foreign}

type Answer = Arc<dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> + Send + Sync>;

/// A subscription endpoint over TLS: it records the head and the body of every request, and answers what `answer` makes of the body.
struct Endpoint {addr: SocketAddr, seen: Arc<Mutex<Vec<(String, Vec<u8>)>>>, task: tokio::task::JoinHandle<()>}

impl Drop for Endpoint {
	fn drop(&mut self) {self.task.abort()}
}

async fn endpoint(config: Arc<ServerConfig>, answer: Answer) -> Endpoint {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, seen) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())));
	let task = tokio::spawn({
		let seen = seen.clone();
		async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else {return};
				let (acceptor, seen, answer) = (TlsAcceptor::from(config.clone()), seen.clone(), answer.clone());
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
					let body = buffer[end..end + length].to_vec();
					seen.lock().unwrap().push((head, body.clone()));
					let _ = tls.write_all(&answer(body).await).await;
					let _ = tls.shutdown().await;
				});
			}
		}
	});
	Endpoint {addr, seen, task}
}

fn http(status: &str, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
	let fields: String = fields.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
	[format!("HTTP/1.1 {status}\r\n{fields}Connection: close\r\n\r\n").as_bytes(), body].concat()
}

fn chunked(body: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for part in body.chunks(100) {out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes()); out.extend_from_slice(part); out.extend_from_slice(b"\r\n")}
	out.extend_from_slice(b"0\r\n\r\n");
	out
}

// The three steps of an import against an endpoint of the test that enrolls the device it is asked about at the node, then a tunnel over what was imported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_is_imported_in_three_steps_after_two_yeses_and_the_device_it_made_connects() {
	let time = time!();
	let net = net("engine-import", time, |_| {}).await;
	let (roots, _, config) = certify("sub.example.com", None);
	let (mode, enrolled, numbers, issued) = (Arc::new(Mutex::new(Mode::Normal)), Arc::new(AtomicU64::new(0)), Arc::new(Mutex::new(Vec::<([u8; 32], u64)>::new())), time.secs() - 10);
	let (gateway, requests) = (gateway(), Arc::new(Mutex::new(Vec::<Received>::new())));
	let transports = vec![transport("udp-obfs", &net), transport("tls", &net)];
	let (engine, doc) = (net.engine.clone(), net.doc.clone());
	let endpoint = endpoint(config, Arc::new({
		let (mode, enrolled, numbers, gateway, requests) = (mode.clone(), enrolled.clone(), numbers.clone(), gateway.clone(), requests.clone());
		move |body| {
			let (mode, enrolled, numbers, transports, engine, doc, gateway, requests) = (mode.clone(), enrolled.clone(), numbers.clone(), transports.clone(), engine.clone(), doc.clone(), gateway.clone(), requests.clone());
			Box::pin(async move {
				let opened = gateway.lock().unwrap().open(&body, issued + 10, || true).expect("the client sealed a request the gateway cannot open");
				let (received, reply) = (opened.request.expect("the client wrote a request the gateway cannot read"), opened.reply);
				requests.lock().unwrap().push(received.clone());
				let seal = |envelope: &str| reply.seal(envelope.as_bytes(), &mut entropy).unwrap();
				let key = provider_key();
				let released = || http("200 OK", &[("Content-Type", "application/octet-stream")], &seal(&sign(&json!({"v": 1, "subscription_id": ID, "issued_at": issued, "refusal": "released"}))));
				if matches!(received.op(), Op::Release) {return released()}
				// The device is enrolled at the node on its first request, with a place of its own in the node's config.
				let known = numbers.lock().unwrap().iter().find(|(public, _)| public == received.device_public_key()).map(|(_, number)| *number);
				let number = match known {
					Some(number) => number,
					None => {
						let number = 20 + enrolled.fetch_add(1, Ordering::SeqCst);
						numbers.lock().unwrap().push((*received.device_public_key(), number));
						reload(&engine, &doc, |doc| doc["users"].as_array_mut().unwrap().push(json!({"name": format!("imp{number}"), "exits": "all", "devices": [{"name": "phone", "public_key": text(received.device_public_key()), "transport_secrets": [text(&[0x80 + number as u8; 32])], "addresses": [format!("10.7.0.{number}")]}]}))).await;
						number
					}
				};
				let imported = json!({
					"type": "veilway", "id": "home", "name": "Home", "inbound_public_key": text(&public(&NODE)),
					"device": {"public_key": text(received.device_public_key()), "transport_secrets": [text(&[0x80 + number as u8; 32])], "addresses": [format!("10.7.0.{number}")]},
					"gateways": ["10.7.0.1"], "mtu": 1390, "transport_public_key": text(&veilway_proto::proof::public_key(&TRANSPORT)), "transports": transports,
					"exits": [{"tag": "main", "name": "Main exit"}],
				});
				let document = json!({"v": 1, "subscription_id": ID, "serial": 1, "issued_at": issued, "expires_at": issued + 30 * 86_400, "signing_keys": [b64(key.bytes())], "provider": {"name": "Test provider"}, "profiles": [imported], "gateway_keys": [{"id": 1, "key": b64(gateway_key().public())}]});
				let current = *mode.lock().unwrap();
				match current {
					Mode::Normal => http("200 OK", &[("Content-Type", "application/octet-stream"), ("Cache-Control", "no-store")], &seal(&sign(&document))),
					Mode::Chunked => http("200 OK", &[("Transfer-Encoding", "chunked")], &chunked(&seal(&sign(&document)))),
					Mode::Redirect => http("302 Found", &[("Location", "https://elsewhere.example.com/")], b""),
					Mode::Missing => http("404 Not Found", &[], b"nothing here\n"),
					Mode::Encoded => http("200 OK", &[("Content-Encoding", "gzip")], &seal(&sign(&document))),
					Mode::Foreign => {
						let other = Ed25519KeyPair::from_seed_unchecked(&[0x22; 32]).unwrap();
						let signer = SigningKey::new(other.public_key().as_ref().try_into().unwrap()).unwrap();
						http("200 OK", &[], &seal(&envelope::seal(&signer, &serde_json::to_vec(&document).unwrap(), |signed| other.sign(signed).as_ref().try_into().unwrap())))
					}
				}
			})
		}
	})).await;
	let at = endpoint.addr;
	let mut fetcher = Fetcher::new(roots.clone(), None);
	fetcher.resolve = Arc::new(move |host, port| Box::pin(async move {
		assert_eq!((host.as_str(), port), ("sub.example.com", 443));
		Ok(vec![at])
	}));
	let link = format!("  veilway://sub/sub.example.com/s#v1.{}.{}.{}\n", b64url(provider_key().bytes()), b64url(&gateway_key().link()), b64url(&[0x55; 16]));
	let (mut library, _) = Library::open(Box::new(FileVault(net.dir.join("import.vault")))).unwrap();
	// Step 1 shows what the link alone says and nothing is sent: not by opening it, and not by the user's yes to it either until the request is made.
	let Offer::Native(offer) = import::open(&link).unwrap() else {panic!("a native link")};
	assert_eq!((offer.endpoint().host(), offer.fingerprint().to_string()), ("sub.example.com", provider_key().fingerprint().to_string()));
	assert!(endpoint.seen.lock().unwrap().is_empty());
	for bad in ["veilway://sub/sub.example.com/s", "veilway://sub/sub.example.com/s#v1.short.short.short", "http://sub.example.com/s#v1.x.y.z", "veilway://sub/localhost/s#v1.x.y"] {assert!(matches!(import::open(bad), Err(import::ImportError::Link(_) | import::ImportError::NotALink)), "{bad}")}
	// A link of another kind cannot be verified, and this engine does not connect to it by itself: nothing is sent for it either.
	assert!(matches!(import::open("https://example.com/legacy-list"), Err(import::ImportError::Legacy)));
	let fetching = import::proceed(offer, None).unwrap();
	assert!(endpoint.seen.lock().unwrap().is_empty());
	// Every answer that is no signed document under the link's key is a failed fetch, and each leaves the step as it was: to try again.
	for (answer, wanted) in [(Mode::Redirect, "redirect"), (Mode::Missing, "status"), (Mode::Encoded, "encoding"), (Mode::Foreign, "signature")] {
		*mode.lock().unwrap() = answer;
		let error = fetcher.fetch(&fetching, &library, time.secs(), &[]).await.unwrap_err();
		let matched = match (&error, wanted) {
			(import::ImportError::Fetch(import::FetchError::Redirect), "redirect") | (import::ImportError::Fetch(import::FetchError::Status(404)), "status") | (import::ImportError::Fetch(import::FetchError::Encoding), "encoding") | (import::ImportError::Subscription(veilway_proto::subscription::client::Failure::Envelope(_)), "signature") => true,
			_ => false,
		};
		assert!(matched, "{wanted}: {error:?}");
		assert!(!error.text().is_empty() && library.held().is_empty());
	}
	// A certificate that does not lead to a root held is no answer, and a pin is a check this build does not have: nothing is sent to a pinned endpoint by the chain rules.
	let (other, _, _) = certify("other.example.com", None);
	assert!(matches!(Fetcher {roots: other, ..fetcher.clone()}.fetch(&fetching, &library, time.secs(), &[]).await, Err(import::ImportError::Fetch(import::FetchError::Certificate))));
	let before = endpoint.seen.lock().unwrap().len();
	assert_eq!(fetcher.post(fetching.endpoint(), &import::Trust::Pinned(vec![[1; 32]]), &[0; 1_073], &[], time.secs()).await, Err(import::FetchError::Pin));
	assert_eq!(endpoint.seen.lock().unwrap().len(), before);
	// The answer that passes, once with a body that comes in chunks. Nothing is stored before the second yes.
	*mode.lock().unwrap() = Mode::Chunked;
	let again = fetcher.fetch(&fetching, &library, time.secs(), &[]).await.unwrap();
	*mode.lock().unwrap() = Mode::Normal;
	let reviewed = fetcher.fetch(&fetching, &library, time.secs(), &[]).await.unwrap();
	assert_eq!(again.review.subscription(), reviewed.review.subscription());
	assert!(library.held().is_empty() && !net.dir.join("import.vault").exists());
	let review = &reviewed.review;
	assert_eq!((review.subscription().profiles[0].id.as_str(), review.origin(), review.replaces(), review.refreshes(), review.fingerprint().to_string()), ("home", veilway_proto::subscription::payload::KeyOrigin::Device, false, true, provider_key().fingerprint().to_string()));
	// The request: exactly the fields of the page, a body of exactly 1,073 sealed bytes, and the token inside the seal and nowhere else.
	let (head, body) = endpoint.seen.lock().unwrap().last().cloned().unwrap();
	let lower = head.to_ascii_lowercase();
	assert_eq!(head, "POST /s HTTP/1.1\r\nHost: sub.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 1073\r\nAccept-Encoding: identity\r\n\r\n");
	assert!(!lower.contains("accept-language") && !lower.contains("cookie") && !lower.contains("authorization") && !lower.contains("user-agent") && !head.contains("VVVVVVVV") && body.len() == 1_073 && !body.windows(22).any(|part| part == b"VVVVVVVVVVVVVVVVVVVVVQ"), "{head}");
	let request = requests.lock().unwrap().last().cloned().unwrap();
	assert_eq!((request.op(), request.token().expose(), request.t().abs_diff(time.secs()) <= 1), (&Op::Fetch, &[0x55; 16], true));
	// The second yes, with a name: stored, and the place made permanent.
	let name = veilway_proto::subscription::fetch::DeviceName::typed("my phone");
	fetcher.accept(reviewed, name, &mut library).await.unwrap();
	assert_eq!(library.held().len(), 1);
	assert_eq!(requests.lock().unwrap().last().unwrap().op(), &Op::Confirm(veilway_proto::subscription::fetch::DeviceName::typed("my phone")));
	#[cfg(unix)]
	assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(net.dir.join("import.vault")).unwrap().permissions()) & 0o777, 0o600);
	let (restored, damaged) = Library::open(Box::new(FileVault(net.dir.join("import.vault")))).unwrap();
	assert!(damaged.is_empty() && restored.held().len() == 1 && restored.held()[0].document() == library.held()[0].document());
	// A yes to a private address is kept with the subscription in the vault, only for an address that may be asked about at all.
	assert!(library.held()[0].private_addresses().is_empty());
	library.allow_private(0, &["192.168.1.20".parse().unwrap(), "127.0.0.1".parse().unwrap()]).unwrap();
	let (kept, _) = Library::open(Box::new(FileVault(net.dir.join("import.vault")))).unwrap();
	assert_eq!(kept.held()[0].private_addresses(), ["192.168.1.20".parse::<std::net::IpAddr>().unwrap()]);
	// A refresh of what is stored: the same document again changes nothing.
	assert!(matches!(fetcher.refresh(&mut library, 0, time.secs()).await, Ok(veilway_proto::subscription::client::Refreshed::Unchanged)));
	// The device the import made connects, over each of the profile's transports in turn, with a key no one but this client holds.
	let settings = net.settings("import");
	settings.store.agree(&format!("{ID}/home"), Class::NoCover);
	let mut run = Run::new(start(&net, settings, &library, PRIVATE).unwrap(), 18);
	run.connected().await;
	assert!(run.ping(300, 1).await);
	run.until("the channel did not open", Duration::from_secs(20), |status| status.control).await;
	run.tunnel.stop().await;
	// The user says no at the second step: the place is released and nothing is kept.
	let (other_library, _) = Library::open(Box::new(FileVault(net.dir.join("declined.vault")))).unwrap();
	let Offer::Native(offer) = import::open(&link).unwrap() else {panic!("a native link")};
	let fetching = import::proceed(offer, None).unwrap();
	let reviewed = fetcher.fetch(&fetching, &other_library, time.secs(), &[]).await.unwrap();
	fetcher.decline(reviewed).await;
	assert_eq!(requests.lock().unwrap().last().unwrap().op(), &Op::Release);
	assert!(other_library.held().is_empty());
	assert!(logged("tunnel state"));
}

// "What a client has stored for these decisions is untrusted input to itself": a file that is damaged is no file, and one that says the worst it can is no reason not to connect, nor to hold a candidate back for longer than a mark lasts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_state_file_that_is_damaged_or_hostile_is_no_reason_not_to_connect_and_is_written_again_sound() {
	let time = time!();
	let net = net("engine-hostile", time, |_| {}).await;
	let library = library(&net, "hostile", &payload(time, vec![profile(&net, 0, &["tls"])])).await;
	let key = format!("{ID}/home");
	let network = veilway_engine::store::network_key(5, "test network");
	std::fs::write(net.dir.join("garbage.json"), b"\xff\x00 {not json").unwrap();
	let hostile = format!(r#"{{"version":1,"seed":5,"profiles":{{"{key}":{{"standing":{{"profile":0,"refusals":4294967295,"losses":4294967295,"short":4294967295,"opened":18446744073709551615,"offset":[-9223372036854775808,18446744073709551615],"consent":["plain","cover","bogus"]}},"networks":[["{network}",{{"profile":0,"worked":[0,0,18446744073709551615],"aside":[[0,null,18446744073709551615],[0,0,18446744073709551615],[999,5,1]],"tried":[[0,0,18446744073709551615]],"silent":[0,18446744073709551615]}}]]}}}}}}"#);
	std::fs::write(net.dir.join("hostile.json"), hostile).unwrap();
	for name in ["garbage", "hostile"] {
		let mut run = Run::new(start(&net, net.settings(name), &library, PRIVATE).unwrap(), 0);
		let status = run.connected().await;
		assert!(run.ping(300, 1).await && status.counters.attempts == 1, "{name}: {:?}", status.counters);
		run.tunnel.stop().await;
		let saved = veilway_engine::store::parse(&std::fs::read(net.dir.join(format!("{name}.json"))).unwrap()).unwrap();
		let kept = &saved.profiles[&key];
		assert!(kept.standing.refusals == 0 && kept.standing.losses == 0 && kept.standing.offset.is_none(), "{name}: {:?}", kept.standing);
		assert!(kept.networks[0].1.aside.is_empty() && kept.networks[0].1.worked.is_some_and(|(_, _, when)| when <= time.secs() + 5), "{name}: {:?}", kept.networks[0].1);
	}
}

// "The answer is stored per profile and class and can be withdrawn." What the user answers while a tunnel runs is what the tunnel works under from then on, and what it writes to the file is its own state and never the answers it read when it started.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_the_user_changes_while_the_tunnel_runs_takes_effect_at_once_and_is_not_written_back() {
	let time = time!();
	let net = net("engine-answers", time, |_| {}).await;
	let library = library(&net, "answers", &payload(time, vec![profile(&net, 0, &["tls-blocked", "udp-obfs"])])).await;
	let (settings, key) = (net.settings("answers"), format!("{ID}/home"));
	settings.store.agree(&key, Class::NoCover);
	let mut run = Run::new(start(&net, settings.clone(), &library, PRIVATE).unwrap(), 0);
	run.connected().await;
	assert!(run.ping(300, 1).await);
	// The user withdraws the class this session uses, and turns `stream_first` on, in the settings of the app.
	settings.store.withdraw(&key, Class::NoCover);
	settings.store.set_stream_first(&key, Some(true));
	run.until("the session of a withdrawn class went on", Duration::from_secs(5), |status| !matches!(status.state, State::Connected {..})).await;
	// Saves follow (every attempt writes), and the tunnel does not come back over the class.
	tokio::time::sleep(Duration::from_secs(3)).await;
	let counters = run.tunnel.status().counters;
	assert_eq!((counters.opened, run.tunnel.status().state.clone() == State::Off), (1, false), "{counters:?}");
	assert!(!matches!(run.tunnel.status().state, State::Connected {..}));
	run.tunnel.stop().await;
	settings.store.flush().unwrap();
	let kept = Store::open(net.dir.join("answers.json")).kept(&key);
	assert!(!kept.standing.consent.contains(&Class::NoCover) && kept.declined.contains(&Class::NoCover) && kept.stream_first == Some(true), "{kept:?}");
	// A start after it asks nothing and uses the best class alone.
	let again = Run::new(start(&net, net.settings("answers"), &library, PRIVATE).unwrap(), 0);
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert!(!matches!(again.tunnel.status().state, State::Connected {..}));
	again.tunnel.stop().await;
}

// "Skipped at each connect: an address inside one of the device's own networks", except a private one after the user's yes to a private address. The public one that stays skipped is a unit test of the engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_address_in_the_devices_own_network_is_dialled_after_the_yes_at_the_start_and_after_a_move() {
	let time = time!();
	let net = net("engine-own", time, |_| {}).await;
	let library = library(&net, "own", &payload(time, vec![profile(&net, 0, &["tls"])])).await;
	let own = veilway_proto::subscription::payload::Network::new([10, 99, 0, 0].into(), 24).unwrap();
	let mut base = net.settings("own");
	base.networks = vec![own];
	let mut run = Run::new(start(&net, base, &library, PRIVATE).unwrap(), 0);
	run.connected().await;
	assert!(run.ping(300, 1).await);
	run.tunnel.moved("a cafe".into(), vec![own]);
	tokio::time::sleep(Duration::from_secs(2)).await;
	assert!(matches!(run.tunnel.status().state, State::Connected {..}));
	assert!(run.ping(300, 2).await);
	assert_eq!((run.tunnel.status().counters.attempts, run.tunnel.status().counters.opened), (1, 1));
	run.tunnel.stop().await;
}

// "At most 2 candidates are in flight, the second starting 250 ms after the first ... That candidate wins and the other is closed."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_two_candidates_in_flight_the_one_that_answers_wins_and_the_connection_of_the_other_is_closed() {
	let time = time!();
	let net = net("engine-race", time, |_| {}).await;
	let library = library(&net, "race", &payload(time, vec![profile(&net, 0, &["tls-slow-first"])])).await;
	// The order of the candidates is random per installation: when the one that does not answer is walked first both are in flight together, and when it is walked second the live one wins before it is opened. Fresh installations are made until the first order has been seen.
	let (mut seen, mut unopened) = (false, 0);
	for round in 0..24 {
		let name = format!("race{round}");
		let held = net.slow.1.load(Ordering::SeqCst);
		let mut run = Run::new(start(&net, net.settings(&name), &library, PRIVATE).unwrap(), 0);
		let status = run.connected().await;
		assert!(run.ping(300, 1).await);
		let taken = net.slow.1.load(Ordering::SeqCst) - held;
		// A candidate that took a connection is an attempt, and one that was never opened is neither an attempt nor a place of the budget.
		assert_eq!((status.counters.attempts, status.counters.opened), (1 + taken, 1), "{:?}", status.counters);
		if taken == 1 {
			// The one that did not answer saw its connection closed by the client when the other won, and the node holds one session of the device.
			eventually("the loser's connection was not closed", || net.slow.2.load(Ordering::SeqCst) >= net.slow.1.load(Ordering::SeqCst)).await;
			eventually("the node holds more than one session", || net.engine.stream().sessions == 1).await;
			seen = true;
		} else {unopened += 1}
		run.tunnel.stop().await;
		let tried = Store::open(net.dir.join(format!("{name}.json"))).kept(&format!("{ID}/home")).networks[0].1.tried.len() as u64;
		assert_eq!(tried, status.counters.attempts, "{name}");
		if seen && unopened > 0 {break}
	}
	assert!(seen, "the candidate that does not answer was never walked first in 24 installations");
}

// "A pinned endpoint": the link names the certificate, and no chain, name or date is looked at. Nothing is sent before the pin matched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_endpoint_is_trusted_by_its_pin_alone_and_nothing_is_sent_to_one_that_does_not_match() {
	let time = time!();
	let net = net("engine-pinned", time, |_| {}).await;
	let (_, pin, config) = certify("some-other-name.example.org", None);
	let (document, gateway, now) = (sign(&payload(time, vec![profile(&net, 0, &["tls"])])), gateway(), time.secs());
	let endpoint = endpoint(config, Arc::new(move |body| {
		let (document, gateway) = (document.clone(), gateway.clone());
		Box::pin(async move {
			let reply = gateway.lock().unwrap().open(&body, now, || true).expect("the client sealed a request the gateway cannot open").reply;
			http("200 OK", &[("Content-Type", "application/octet-stream")], &reply.seal(document.as_bytes(), &mut entropy).unwrap())
		})
	})).await;
	let at = endpoint.addr;
	// No root is held at all, and the name on the certificate is not the link's: only the pin can pass it.
	let mut fetcher = Fetcher::new(Arc::new(RootCertStore::empty()), None);
	fetcher.resolve = Arc::new(move |_, _| Box::pin(async move { Ok(vec![at]) }));
	let link = |pin: &[u8; 32]| format!("veilway://sub/sub.example.com/s#v1.{}.{}.{}.{}", b64url(provider_key().bytes()), b64url(&gateway_key().link()), b64url(&[0x55; 16]), b64url(pin));
	let (mut library, _) = Library::open(Box::new(FileVault(net.dir.join("pinned.vault")))).unwrap();
	let Offer::Native(offer) = import::open(&link(&pin)).unwrap() else {panic!("a native link")};
	assert_eq!(offer.pin(), Some(&pin));
	let fetching = import::proceed(offer, None).unwrap();
	assert_eq!(fetching.pins(), [pin]);
	// A pin that is not the certificate's: the handshake fails before a byte of the request is written, and the server's answer is never read.
	let Offer::Native(other) = import::open(&link(&[7; 32])).unwrap() else {panic!("a native link")};
	let wrong = import::proceed(other, None).unwrap();
	assert!(matches!(fetcher.fetch(&wrong, &library, time.secs(), &[]).await, Err(import::ImportError::Fetch(import::FetchError::Pin))));
	assert!(endpoint.seen.lock().unwrap().is_empty());
	// The right one passes, and the accepted subscription holds the pin its endpoint is checked by, in the vault too.
	let reviewed = fetcher.fetch(&fetching, &library, time.secs(), &[]).await.unwrap();
	assert_eq!(reviewed.pins, [pin]);
	fetcher.accept(reviewed, None, &mut library).await.unwrap();
	assert_eq!(library.held()[0].targets().first().map(|target| target.pins.to_vec()), Some(vec![pin]));
	assert_eq!(endpoint.seen.lock().unwrap().len(), 2, "the fetch and the confirmation");
	let (restored, _) = Library::open(Box::new(FileVault(net.dir.join("pinned.vault")))).unwrap();
	assert_eq!(restored.held()[0].targets().first().map(|target| target.pins.to_vec()), Some(vec![pin]));
	// A refresh goes to the endpoint by the same pin, and an endpoint whose certificate changed is refused, not trusted by its chain.
	assert!(matches!(fetcher.refresh(&mut library, 0, time.secs()).await, Ok(veilway_proto::subscription::client::Refreshed::Unchanged)));
	let (_, _, moved) = certify("sub.example.com", None);
	let new = self::endpoint(moved, Arc::new(|_| Box::pin(async { http("200 OK", &[], b"x") }))).await;
	let at = new.addr;
	fetcher.resolve = Arc::new(move |_, _| Box::pin(async move { Ok(vec![at]) }));
	assert!(matches!(fetcher.refresh(&mut library, 0, time.secs()).await, Err(import::ImportError::Fetch(import::FetchError::Pin))));
	assert!(new.seen.lock().unwrap().is_empty());
}

// The same node-side numbers as `hole`, for many addresses: each fake address of a candidate goes to a port of its own that takes the connection and closes it, and the test counts which were dialled.
async fn many(count: u8) -> (HashMap<SocketAddr, SocketAddr>, Arc<Mutex<HashMap<SocketAddr, u64>>>) {
	let dialled = Arc::new(Mutex::new(HashMap::<SocketAddr, u64>::new()));
	let mut redirect = HashMap::new();
	for at in 1..=count {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let (real, fake): (SocketAddr, SocketAddr) = (listener.local_addr().unwrap(), format!("10.99.1.{at}:6000").parse().unwrap());
		redirect.insert(fake, real);
		let dialled = dialled.clone();
		tokio::spawn(async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else {return};
				*dialled.lock().unwrap().entry(real).or_default() += 1;
				drop(stream);
			}
		});
	}
	(redirect, dialled)
}

// "At most 6 distinct candidates are tried per hour per network."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seventh_distinct_candidate_is_not_dialled_within_the_hour() {
	let time = time!();
	let net = net("engine-budget", time, |_| {}).await;
	let (redirect, dialled) = many(8).await;
	let candidates: Vec<Value> = (1..=8).map(|at| json!({"address": format!("10.99.1.{at}:6000"), "sni": "node.test", "host": "node.test", "pins": [net.pin()]})).collect();
	let mut eight = profile(&net, 0, &["tls"]);
	eight["transports"] = json!([{"type": "tls", "path": TLS_PATH, "candidates": candidates}]);
	let library = library(&net, "budget", &payload(time, vec![eight])).await;
	let waits = Waits::new(time);
	let base = net.settings("budget").with_redirect(Arc::new(move |address| redirect.get(&address).copied().unwrap_or(address)));
	let tunnel = start(&net, waits.settings(&base, false), &library, PRIVATE).unwrap();
	waits.watch(&tunnel);
	// Many rounds of the loop, every wait skipped, on a clock that does not move: six candidates are dialled, again and again, and no seventh.
	let seen = waits.count(60).await;
	tunnel.stop().await;
	let dials = dialled.lock().unwrap().clone();
	assert_eq!(dials.len(), 6, "{} distinct candidates were dialled in an hour: {dials:?}", dials.len());
	assert!(seen.iter().all(|(_, status)| status.as_ref().is_some_and(|status| matches!(status.say, Some(Say::BudgetSpent | Say::Unreachable)))));
	let kept = Store::open(net.dir.join("budget.json")).kept(&format!("{ID}/home"));
	assert!(kept.networks[0].1.tried.len() <= 6, "{:?}", kept.networks[0].1.tried);
}

// A withdrawal during an attempt is noticed: nothing waits the ten seconds out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_class_withdrawn_during_an_attempt_ends_the_attempt() {
	let time = time!();
	let net = net("engine-withdrawn-attempt", time, |_| {}).await;
	// A device whose secret the node does not know, on `udp-obfs`: the node says nothing, and the attempt would last ten seconds.
	let mut stranger = profile(&net, 0, &["tls-blocked", "udp-obfs"]);
	stranger["device"]["transport_secrets"] = json!([text(&[0x77; 32])]);
	let library = library(&net, "withdrawn-attempt", &payload(time, vec![stranger])).await;
	let (settings, key) = (net.settings("withdrawn-attempt"), format!("{ID}/home"));
	settings.store.agree(&key, Class::NoCover);
	let waits = Waits::new(time);
	let run = Run::new(start(&net, waits.settings(&settings, false), &library, PRIVATE).unwrap(), 0);
	run.until("the class was never tried", Duration::from_secs(20), |status| matches!(&status.state, State::Connecting {attempt: Some(attempt), ..} if attempt.transport == 1)).await;
	let began = Instant::now();
	settings.store.withdraw(&key, Class::NoCover);
	run.until("the attempt went on", Duration::from_secs(5), |status| !matches!(&status.state, State::Connecting {attempt: Some(attempt), ..} if attempt.transport == 1)).await;
	assert!(began.elapsed() < Duration::from_secs(4), "{:?}", began.elapsed());
	run.tunnel.stop().await;
}

// A size found for a transport on a network is the size a session starts at on that network, and a reconnect does not raise it, not even for a moment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_starts_at_the_size_found_for_the_network_and_does_not_raise_it_even_for_a_moment() {
	let time = time!();
	let net = net("engine-remembered", time, |doc| doc["inbounds"][0]["mtu"] = json!(1300)).await;
	let library = library(&net, "remembered", &payload(time, vec![profile(&net, 0, &["udp-obfs"])])).await;
	let run = Run::new(start(&net, net.settings("remembered"), &library, PRIVATE).unwrap(), 0);
	let mut events = run.tunnel.events();
	run.connected().await;
	run.until("the size was not found", Duration::from_secs(20), |status| status.mtu == 1300 && (status.counters.probes >= 1 || !DONT_FRAGMENT)).await;
	// The node ends the tunnel for a moment, and the engine starts a new session after the asking.
	net.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	run.until("no stop", Duration::from_secs(10), |status| matches!(status.state, State::Stopped {..})).await;
	net.reload(|doc| doc["users"][0]["enabled"] = json!(true)).await;
	run.tunnel.connect_again();
	let status = run.until("no second session", Duration::from_secs(20), |status| status.counters.opened == 2 && matches!(status.state, State::Connected {..})).await;
	// Where fragmentation cannot be prohibited nothing was found, so the session starts at the profile's size and the node's comes with its first word.
	let status = if DONT_FRAGMENT {status} else {run.until("the node's size was not taken", Duration::from_secs(10), |status| status.mtu == 1300).await};
	assert_eq!(status.mtu, 1300, "the new session started above the size found");
	let mut told = Vec::new();
	while let Ok(Ok(event)) = timeout(Duration::from_millis(300), events.recv()).await {told.push(event)}
	assert!(told.contains(&Event::Mtu(1300)) && (!DONT_FRAGMENT || !told.iter().any(|event| matches!(event, Event::Mtu(mtu) if *mtu > 1300))), "{told:?}");
	run.tunnel.stop().await;
}

// What a node says out of its turn: through the engine's own path for the node's messages, a size above the one in force is nothing, and a lower one is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_says_a_higher_mtu_than_the_one_in_force_does_not_raise_the_tunnel() {
	use veilway_proto::control::{Addresses, NodeMessage, Session};
	let time = time!();
	let net = net("engine-hostile-mtu", time, |doc| doc["inbounds"][0]["mtu"] = json!(1300)).await;
	let library = library(&net, "hostile-mtu", &payload(time, vec![profile(&net, 0, &["udp-obfs"])])).await;
	let run = Run::new(start(&net, net.settings("hostile-mtu"), &library, PRIVATE).unwrap(), 0);
	let mut events = run.tunnel.events();
	run.connected().await;
	run.until("the size was not found", Duration::from_secs(20), |status| status.mtu == 1300 && (status.counters.probes >= 1 || !DONT_FRAGMENT)).await;
	let session = |mtu| NodeMessage::Session(Session {node_time: time.secs(), mtu, v4: Some(Addresses {device: [10, 7, 0, 2].into(), gateway: [10, 7, 0, 1].into()}), v6: None});
	for message in [NodeMessage::MtuResult {mtu: 1390}, NodeMessage::MtuResult {mtu: 1300}, session(1390), session(1500), NodeMessage::MtuResult {mtu: 1079}, NodeMessage::MtuResult {mtu: 0}] {run.tunnel.inject(message)}
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert_eq!(run.tunnel.status().mtu, 1300);
	// A lower size, in the same two ways, is taken, so the path was live.
	run.tunnel.inject(NodeMessage::MtuResult {mtu: 1290});
	run.until("a lower size was not taken", Duration::from_secs(5), |status| status.mtu == 1290).await;
	run.tunnel.inject(session(1285));
	run.until("a lower size in a session was not taken", Duration::from_secs(5), |status| status.mtu == 1285).await;
	run.tunnel.inject(NodeMessage::MtuResult {mtu: 1300});
	tokio::time::sleep(Duration::from_secs(1)).await;
	let mut told = Vec::new();
	while let Ok(Ok(event)) = timeout(Duration::from_millis(300), events.recv()).await {told.push(event)}
	assert!(run.tunnel.status().mtu == 1285 && !told.iter().any(|event| matches!(event, Event::Mtu(1390 | 1500 | 1420))) && told.iter().filter(|event| matches!(event, Event::Mtu(1300))).count() <= 1, "{told:?}");
	run.tunnel.stop().await;
}
