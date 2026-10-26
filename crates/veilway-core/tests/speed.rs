//! Per-user speed limits (`speed_up`, `speed_down`) against a node that runs in this process, driven by the client engine: TCP through a `netstack` exit is slowed down to the rate and never dropped, UDP over the rate is dropped and counted, DNS and the control channel are never dropped, a quota counts what a limit dropped on the way in and not on the way out, and a `socks5` inbound is paced like the tunnel. The destinations are servers on an address of this host that is not loopback, since the destination gate refuses loopback.
//! Rates are measured over a window after a warm-up that is longer than the burst (one second of the rate), so what is measured is the rate and not the burst.
#[macro_use]
mod proxied;
use etherparse::{PacketBuilder, PacketHeaders, PayloadSlice, TransportHeader};
use proxied::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::RootCertStore;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};
use veilway_core::{Engine, Options, Reason};
use veilway_engine::import::{self, Fetcher, FileVault, Library};
use veilway_engine::local::{Kind, Local, LocalProxy};
use veilway_engine::{Agree, Redirect, Settings, State, Store, Tunnel};
use veilway_proto::subscription::client::Offer;
use veilway_proto::subscription::envelope::{self, SigningKey};
use veilway_proto::subscription::exchange::GatewayKey;

const PLAIN: &str = "10.99.0.4:5004";
const ID: &str = "test-subscription-0001";
const RATE: u64 = 2_000_000;
const PRIVATE: Agree = Agree {private: true, unsafe_profile: false};
const ALICE: &str = "alice-secret-pass-01";

fn b64(bytes: &[u8]) -> String {base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)}

fn b64url(bytes: &[u8]) -> String {base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)}

fn provider() -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&[0x11; 32]).unwrap()}

fn provider_key() -> SigningKey {SigningKey::new(provider().public_key().as_ref().try_into().unwrap()).unwrap()}

fn gateway_key() -> GatewayKey {GatewayKey::new(1, veilway_proto::proof::public_key(&std::array::from_fn(|index| 0x40 + index as u8))).unwrap()}

/// An address of this host that is not loopback, which the gate lets a destination be.
fn own() -> Option<IpAddr> {
	let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
	probe.connect("192.0.2.1:9").ok()?;
	Some(probe.local_addr().ok()?.ip()).filter(|ip| ip.is_ipv4() && !ip.is_loopback())
}

/// A TCP server that sends every connection zeros for as long as it is read.
async fn source(at: IpAddr) -> SocketAddr {
	let listener = TcpListener::bind((at, 0)).await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut client, _)) = listener.accept().await {
			tokio::spawn(async move {
				let chunk = vec![0u8; 65536];
				while client.write_all(&chunk).await.is_ok() {}
			});
		}
	});
	addr
}

/// A TCP server that reads every connection and counts the bytes.
async fn sink(at: IpAddr) -> (SocketAddr, Arc<AtomicU64>) {
	let (listener, count) = (TcpListener::bind((at, 0)).await.unwrap(), Arc::new(AtomicU64::new(0)));
	let addr = listener.local_addr().unwrap();
	tokio::spawn({
		let count = count.clone();
		async move {
			while let Ok((mut client, _)) = listener.accept().await {
				let count = count.clone();
				tokio::spawn(async move {
					let mut buffer = vec![0u8; 65536];
					while let Ok(n) = client.read(&mut buffer).await {
						if n == 0 {return}
						count.fetch_add(n as u64, Ordering::Relaxed);
					}
				});
			}
		}
	});
	(addr, count)
}

/// A UDP server that sends back every datagram and counts them.
async fn udp_echo(at: IpAddr) -> (SocketAddr, Arc<AtomicU64>) {
	let (socket, count) = (UdpSocket::bind((at, 0)).await.unwrap(), Arc::new(AtomicU64::new(0)));
	let addr = socket.local_addr().unwrap();
	tokio::spawn({
		let count = count.clone();
		async move {
			let mut buffer = vec![0u8; 2048];
			while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
				count.fetch_add(1, Ordering::Relaxed);
				let _ = socket.send_to(&buffer[..n], from).await;
			}
		}
	});
	(addr, count)
}

/// A DNS server that answers every A query with `answer`.
async fn dns(at: IpAddr, answer: Ipv4Addr) -> SocketAddr {
	let socket = UdpSocket::bind((at, 0)).await.unwrap();
	let addr = socket.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buffer = vec![0u8; 2048];
		while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
			let address = buffer[n - 4..n - 2] == [0, 1];
			let mut reply = [&buffer[..2], &[0x81, 0x80, 0, 1, 0, u8::from(address), 0, 0, 0, 0][..], &buffer[12..n]].concat();
			if address {reply.extend_from_slice(&[&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4][..], &answer.octets()].concat());}
			let _ = socket.send_to(&reply, from).await;
		}
	});
	addr
}

fn device(n: usize) -> Value {json!({"name": format!("d{n}"), "public_key": text(&public(&KEYS[n])), "transport_secrets": [text(&secret(n))], "addresses": [Ipv4Addr::from(address(n)).to_string()]})}

/// A node with a `veilway` inbound reached over plain `udp`, two exits through a direct outbound, and the user `a` with two devices. `change` has its way with the document before the node starts.
struct Net {engine: Arc<Engine>, dir: PathBuf, plain: SocketAddr, time: Time, own: IpAddr}

async fn net(test: &'static str, change: impl FnOnce(&mut Value)) -> Option<Net> {
	let (own, time, dir, plain) = (own()?, time!(), scratch(test), listen());
	let mut doc = document(plain, listen(), plain);
	doc["inbounds"][0]["transports"] = json!([{"type": "udp", "listen": plain.to_string()}]);
	doc["outbounds"] = json!([{"tag": "plain", "type": "direct"}]);
	doc["exits"] = json!([{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "alt", "backend": {"type": "netstack", "outbound": "plain"}}]);
	doc["routing"]["rules"] = json!([]);
	doc["users"] = json!([{"name": "a", "exits": "all", "devices": [device(0), device(1)]}]);
	change(&mut doc);
	logging();
	let engine = veilway_core::start(&parsed(&doc), Options {now: time.now, is_local: |_| false, ..Options::new(&dir)}).await.unwrap_or_else(|e| panic!("the node did not start: {e:#}"));
	Some(Net {engine: Arc::new(engine), dir, plain, time, own})
}

impl Net {
	fn redirect(&self) -> Redirect {
		let (fake, real): (SocketAddr, SocketAddr) = (PLAIN.parse().unwrap(), self.plain);
		Arc::new(move |address| if address == fake {real} else {address})
	}

	fn settings(&self, name: &str) -> Settings {
		let time = self.time;
		Settings::new(Arc::new(Store::open(self.dir.join(format!("{name}.json")))), Arc::new(move || time.secs()), Arc::new(RootCertStore::empty()), "test network".into()).with_redirect(self.redirect())
	}

	/// Device `n` of user `a` as a tunnel to the node, and the library that holds its profile.
	async fn tunnel(&self, n: usize) -> Tunnel {
		let name = format!("device{n}");
		let profile = json!({
			"type": "veilway", "id": "home", "name": "Home", "inbound_public_key": text(&public(&NODE)),
			"device": {"public_key": text(&public(&KEYS[n])), "private_key": text(&KEYS[n]), "transport_secrets": [text(&secret(n))], "addresses": [Ipv4Addr::from(address(n)).to_string()]},
			"gateways": ["10.7.0.1"], "mtu": 1390, "transport_public_key": text(&veilway_proto::proof::public_key(&TRANSPORT)),
			"transports": [{"type": "udp", "endpoints": [PLAIN]}],
			"exits": [{"tag": "main", "name": "main"}, {"tag": "alt", "name": "alt"}],
		});
		let payload = json!({"v": 1, "subscription_id": ID, "serial": 1, "issued_at": self.time.secs() - 10, "expires_at": self.time.secs() + 30 * 86_400, "signing_keys": [b64(provider_key().bytes())], "provider": {"name": "Test provider"}, "profiles": [profile], "gateway_keys": [{"id": 1, "key": b64(gateway_key().public())}]});
		let signed = envelope::seal(&provider_key(), &serde_json::to_vec(&payload).unwrap(), |signed| provider().sign(signed).as_ref().try_into().unwrap());
		let content = format!("v1.{}.{}", b64url(provider_key().bytes()), signed);
		let (mut library, damaged) = Library::open(Box::new(FileVault(self.dir.join(format!("{name}.vault"))))).unwrap();
		assert!(damaged.is_empty());
		let Offer::Carried(offer) = import::open_file(content.as_bytes()).unwrap() else {panic!("a file is a whole document")};
		let reviewed = import::proceed_carried(offer, self.time.secs(), &library).unwrap();
		Fetcher::new(Arc::new(RootCertStore::empty()), None).accept(reviewed, None, &mut library).await.unwrap();
		let held = &library.held()[0];
		let permit = held.connect(self.time.secs()).unwrap_or_else(|_| panic!("the test document is stale"));
		Tunnel::start(self.settings(&name), held, "home", &permit, PRIVATE).unwrap_or_else(|_| panic!("the tunnel did not start"))
	}

	/// Device `n` as a SOCKS5 proxy on loopback inside its tunnel, once the tunnel is connected.
	async fn local(&self, n: usize) -> Local {
		let local = Local::in_tunnel(self.tunnel(n).await, LocalProxy::new("127.0.0.1:0".parse().unwrap(), Kind::Mixed)).await.unwrap_or_else(|_| panic!("the proxy did not start"));
		let (mut watch, deadline) = (local.watch().unwrap(), tokio::time::Instant::now() + Duration::from_secs(40));
		while !matches!(watch.borrow_and_update().state, State::Connected {..}) {timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), watch.changed()).await.expect("the tunnel did not connect").unwrap()}
		local
	}

	fn usage(&self) -> veilway_core::Usage {self.engine.usage("a").unwrap()}
}

/// A connection to `to` through a SOCKS5 proxy that asks for no login.
async fn through(at: SocketAddr, to: SocketAddr) -> TcpStream {
	let (mut stream, mut said) = (TcpStream::connect(at).await.unwrap(), [0u8; 2]);
	stream.write_all(&[5, 1, 0]).await.unwrap();
	stream.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [5, 0]);
	let SocketAddr::V4(to) = to else {panic!("an IPv4 destination")};
	stream.write_all(&[&[5, 1, 0, 1][..], &to.ip().octets(), &to.port().to_be_bytes()].concat()).await.unwrap();
	let mut reply = [0u8; 10];
	timeout(Duration::from_secs(15), stream.read_exact(&mut reply)).await.expect("no answer").unwrap();
	assert_eq!(reply[1], 0, "the connect was refused: {reply:?}");
	stream
}

/// Reads a stream to its end and counts the bytes.
fn drain(mut stream: TcpStream, count: Arc<AtomicU64>) {
	tokio::spawn(async move {
		let mut buffer = vec![0u8; 65536];
		while let Ok(n) = stream.read(&mut buffer).await {
			if n == 0 {return}
			count.fetch_add(n as u64, Ordering::Relaxed);
		}
	});
}

/// Writes zeros to a stream until it is closed.
fn flood(mut stream: TcpStream) {
	tokio::spawn(async move {
		let chunk = vec![0u8; 65536];
		while stream.write_all(&chunk).await.is_ok() {}
	});
}

/// The bytes a counter gains per second over the next `window` bytes, once it has passed `warm`.
async fn rate(count: &AtomicU64, warm: u64, window: u64) -> f64 {
	timeout(Duration::from_secs(60), async {
		while count.load(Ordering::Relaxed) < warm {sleep(Duration::from_millis(10)).await}
		let (from, begun) = (count.load(Ordering::Relaxed), Instant::now());
		while count.load(Ordering::Relaxed) < from + window {sleep(Duration::from_millis(10)).await}
		(count.load(Ordering::Relaxed) - from) as f64 / begun.elapsed().as_secs_f64()
	}).await.expect("the bytes did not come")
}

fn near(measured: f64, wanted: u64) {assert!((measured - wanted as f64).abs() <= wanted as f64 * 0.15, "measured {measured:.0} bytes per second against a limit of {wanted}")}

fn udp(n: usize, to: SocketAddr, sport: u16, payload: &[u8]) -> Vec<u8> {
	let (IpAddr::V4(ip), mut out) = (to.ip(), Vec::new()) else {panic!("an IPv4 destination")};
	PacketBuilder::ipv4(address(n), ip.octets(), 64).udp(sport, to.port()).write(&mut out, payload).unwrap();
	out
}

fn datagram(packet: &[u8]) -> Option<(u16, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Udp(header) = parsed.transport? else {return None};
	Some((header.source_port, if let PayloadSlice::Udp(payload) = parsed.payload {payload.to_vec()} else {Vec::new()}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_download_through_a_netstack_exit_is_paced_to_the_rate() {
	let Some(net) = net("speed-down", |doc| doc["users"][0]["speed_down"] = json!(RATE)).await else {return};
	let source = source(net.own).await;
	let local = net.local(0).await;
	let count = Arc::new(AtomicU64::new(0));
	drain(through(local.addr(), source).await, count.clone());
	let measured = rate(&count, 3_000_000, 5_000_000).await;
	eprintln!("speed: download limited to {RATE}, measured {measured:.0} bytes per second");
	near(measured, RATE);
	let usage = net.usage();
	assert!(usage.paced_ms > 0 && usage.limited == [0, 0], "TCP is slowed down and never dropped: {usage:?}");
	assert_eq!(net.engine.dropped(Reason::RateLimited), 0);
	local.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_upload_through_a_netstack_exit_is_paced_to_the_rate() {
	let Some(net) = net("speed-up", |doc| doc["users"][0]["speed_up"] = json!(RATE)).await else {return};
	let (sink, count) = sink(net.own).await;
	let local = net.local(0).await;
	flood(through(local.addr(), sink).await);
	let measured = rate(&count, 3_000_000, 5_000_000).await;
	eprintln!("speed: upload limited to {RATE}, measured {measured:.0} bytes per second");
	near(measured, RATE);
	let usage = net.usage();
	eprintln!("speed: upload: the server got {} bytes, the node counted {} bytes up and {} packets", count.load(Ordering::Relaxed), usage.traffic.up_bytes, usage.traffic.up_packets);
	assert!(usage.paced_ms > 0 && usage.limited == [0, 0], "TCP is slowed down and never dropped: {usage:?}");
	// The stack's receive window closes on a reader that is slow, so the device does not send what the node has to hold: a stack that took everything counted five times what the server got.
	assert!(usage.traffic.up_bytes <= count.load(Ordering::Relaxed) * 3 / 2 + 1_000_000, "the device sent far more than the node passed on: {usage:?}");
	local.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_of_a_user_share_one_limit() {
	let Some(net) = net("speed-share", |doc| doc["users"][0]["speed_down"] = json!(RATE)).await else {return};
	let source = source(net.own).await;
	let (first, second) = (net.local(0).await, net.local(1).await);
	let count = Arc::new(AtomicU64::new(0));
	for local in [&first, &second] {drain(through(local.addr(), source).await, count.clone())}
	let measured = rate(&count, 3_500_000, 5_000_000).await;
	eprintln!("speed: two devices share a download limit of {RATE}, measured {measured:.0} bytes per second together");
	near(measured, RATE);
	first.stop().await;
	second.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_socks5_proxy_inbound_is_paced_like_the_tunnel() {
	let proxy = listen();
	let Some(net) = net("speed-proxy", |doc| {
		doc["users"][0]["speed_down"] = json!(RATE);
		doc["users"][0]["proxy_password"] = json!(ALICE);
		doc["inbounds"].as_array_mut().unwrap().push(json!({"tag": "s", "type": "socks5", "listen": proxy.to_string()}));
	}).await else {return};
	let source = source(net.own).await;
	let mut stream = TcpStream::connect(proxy).await.unwrap();
	let mut said = [0u8; 2];
	stream.write_all(&[5, 2, 0, 2]).await.unwrap();
	stream.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [5, 2]);
	stream.write_all(&[&[1, 1][..], b"a", &[ALICE.len() as u8], ALICE.as_bytes()].concat()).await.unwrap();
	stream.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [1, 0]);
	let SocketAddr::V4(to) = source else {panic!("an IPv4 destination")};
	stream.write_all(&[&[5, 1, 0, 1][..], &to.ip().octets(), &to.port().to_be_bytes()].concat()).await.unwrap();
	let mut reply = [0u8; 10];
	stream.read_exact(&mut reply).await.unwrap();
	assert_eq!(reply[1], 0, "{reply:?}");
	let count = Arc::new(AtomicU64::new(0));
	drain(stream, count.clone());
	let measured = rate(&count, 3_000_000, 5_000_000).await;
	eprintln!("speed: socks5 inbound download limited to {RATE}, measured {measured:.0} bytes per second");
	near(measured, RATE);
	assert!(net.usage().paced_ms > 0);
}

/// Packets of 1000 bytes of payload, sent in small bursts so that the loopback socket does not lose them before the node counts them.
async fn send_udp(tunnel: &Tunnel, to: SocketAddr, packets: usize) {
	for sent in 0..packets {
		assert!(tunnel.send(udp(0, to, 40000, &[7u8; 1000])));
		if sent % 25 == 24 {sleep(Duration::from_millis(5)).await}
	}
}

const WHOLE: u64 = 1028;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_udp_flood_up_is_dropped_and_counted_and_still_counts_against_the_quota() {
	let Some(net) = net("speed-udp-up", |doc| {
		doc["users"][0]["speed_up"] = json!(200_000);
		doc["users"][0]["quota_bytes"] = json!(100_000_000);
	}).await else {return};
	let (echo, served) = udp_echo(net.own).await;
	let mut tunnel = net.tunnel(0).await;
	timeout(Duration::from_secs(40), async {while !matches!(tunnel.status().state, State::Connected {..}) {sleep(Duration::from_millis(20)).await}}).await.expect("the tunnel did not connect");
	send_udp(&tunnel, echo, 2000).await;
	sleep(Duration::from_secs(1)).await;
	let (mut received, usage) = (0u64, net.usage());
	while let Ok(Some(packet)) = timeout(Duration::from_millis(200), tunnel.recv()).await {if datagram(&packet).is_some_and(|(port, _)| port == echo.port()) {received += 1}}
	let passed = served.load(Ordering::Relaxed);
	eprintln!("speed: udp flood up limited to 200000, {passed} of 2000 packets passed, {} dropped, {received} echoes came back", usage.limited[0]);
	assert!(usage.limited[0] > 1000 && net.engine.dropped(Reason::RateLimited) >= usage.limited[0], "{usage:?}");
	assert!(passed > 100 && passed < 600, "a burst and a trickle go through: {passed}");
	assert!(usage.limited[0] + passed >= 1500, "every packet either passed or was counted as dropped: {} + {passed}", usage.limited[0]);
	assert!(usage.traffic.up_bytes >= WHOLE * (usage.limited[0] + passed) && usage.used_bytes >= WHOLE * (usage.limited[0] + passed), "what was dropped on the way in still counts: {usage:?}");
	assert_eq!(usage.limited[1], 0);
	let _ = tunnel.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_download_over_the_rate_is_dropped_before_it_is_counted() {
	let Some(net) = net("speed-udp-down", |doc| doc["users"][0]["speed_down"] = json!(200_000)).await else {return};
	let (echo, served) = udp_echo(net.own).await;
	let mut tunnel = net.tunnel(0).await;
	timeout(Duration::from_secs(40), async {while !matches!(tunnel.status().state, State::Connected {..}) {sleep(Duration::from_millis(20)).await}}).await.expect("the tunnel did not connect");
	let before = net.usage().traffic.down_bytes;
	send_udp(&tunnel, echo, 1000).await;
	sleep(Duration::from_secs(1)).await;
	let mut received = 0u64;
	while let Ok(Some(packet)) = timeout(Duration::from_millis(200), tunnel.recv()).await {if datagram(&packet).is_some_and(|(port, _)| port == echo.port()) {received += 1}}
	let usage = net.usage();
	eprintln!("speed: udp down limited to 200000, the server answered {} packets, {received} reached the device, {} dropped", served.load(Ordering::Relaxed), usage.limited[1]);
	assert!(usage.limited[1] > 300 && usage.limited[0] == 0, "{usage:?}");
	assert!(received > 100 && received < 600, "{received}");
	// The control channel's own packets come down as well, and are a few kilobytes at most.
	assert!(usage.traffic.down_bytes - before <= WHOLE * received + 30_000, "a packet dropped for the rate was counted: {} bytes for {received} packets", usage.traffic.down_bytes - before);
	let _ = tunnel.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_and_the_control_channel_are_never_dropped_while_the_user_is_at_the_limit() {
	let Some(own) = own() else {return};
	let resolver = dns(own, Ipv4Addr::new(93, 184, 216, 34)).await;
	let Some(net) = net("speed-control", |doc| {
		doc["dns"] = json!({"servers": [resolver.to_string()]});
		doc["users"][0]["speed_up"] = json!(100_000);
		doc["users"][0]["speed_down"] = json!(100_000);
	}).await else {return};
	let (echo, _) = udp_echo(net.own).await;
	let mut tunnel = net.tunnel(0).await;
	timeout(Duration::from_secs(40), async {while !matches!(tunnel.status().state, State::Connected {..}) {sleep(Duration::from_millis(20)).await}}).await.expect("the tunnel did not connect");
	let mut watch = tunnel.watch();
	timeout(Duration::from_secs(20), async {while !watch.borrow_and_update().exits.iter().any(|exit| exit.tag == "alt") {watch.changed().await.unwrap()}}).await.expect("no catalogue from the control channel");
	let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
	for label in ["example", "test"] {
		query.push(label.len() as u8);
		query.extend_from_slice(label.as_bytes());
	}
	query.extend_from_slice(&[0, 0, 1, 0, 1]);
	let (mut answered, mut asked, mut moved) = (0, 0, false);
	let deadline = Instant::now() + Duration::from_secs(20);
	tunnel.select_exit(Some("alt".into()));
	// Keeps the user over the rate in both directions with UDP, which is policed, and asks for names meanwhile.
	while Instant::now() < deadline && !(answered >= 5 && moved) {
		send_udp(&tunnel, echo, 150).await;
		let mut out = Vec::new();
		PacketBuilder::ipv4(address(0), [10, 7, 0, 1], 64).udp(41000, 53).write(&mut out, &query).unwrap();
		tunnel.send(out);
		asked += 1;
		let until = Instant::now() + Duration::from_millis(200);
		while let Some(left) = until.checked_duration_since(Instant::now()) {
			match timeout(left, tunnel.recv()).await {
				Ok(Some(packet)) => if datagram(&packet).is_some_and(|(port, payload)| port == 53 && payload.starts_with(&[0x12, 0x34, 0x81, 0x80])) {answered += 1},
				_ => break,
			}
		}
		moved = tunnel.status().exits.iter().any(|exit| exit.tag == "alt" && exit.selected);
	}
	let usage = net.usage();
	eprintln!("speed: at the limit, {answered} of {asked} DNS queries were answered, the exit moved: {moved}, {} up and {} down packets were dropped", usage.limited[0], usage.limited[1]);
	assert!(usage.limited[0] > 500, "the user was not at the limit: {usage:?}");
	assert!(answered >= 5 && answered as u64 >= asked as u64 * 9 / 10, "{answered} of {asked} queries were answered");
	assert!(moved, "the control channel could not move the exit");
	let _ = tunnel.stop().await;
}
