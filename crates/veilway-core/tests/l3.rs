//! The `l3` exit against a real kernel: a WireGuard client talks to the engine, which writes its packets to a TUN device, and the kernel forwards them with source NAT to a responder on the network.
//! It needs Linux, `CAP_NET_ADMIN`, `/dev/net/tun`, `ip` and `nft`, so it only runs when `VEILWAY_TEST_L3=1` is set, with `VEILWAY_TEST_L3_PEER` naming an IPv4 host next to this one that answers ping,
//! sends `GREETING` to whoever connects on TCP port 7000, echoes UDP datagrams on port 7001 with `echo:` in front, and has nothing on UDP port 7002. `tests/l3-responder.py` is that host.
//! Run it in two containers on one Docker network, from the repo root:
//!
//! ```text
//! docker network create veilway-l3
//! docker run -d --rm --name veilway-l3-peer --network veilway-l3 -v "$PWD/crates/veilway-core/tests/l3-responder.py":/responder.py:ro python:3-alpine python /responder.py
//! docker run --rm --network veilway-l3 --cap-add NET_ADMIN --device /dev/net/tun -e VEILWAY_TEST_L3=1 -v "$PWD":/w -v veilway-target:/w/target -v veilway-cargo:/usr/local/cargo -w /w rust:1 sh -c \
//!   "apt-get update -qq && apt-get install -y -qq iproute2 nftables && VEILWAY_TEST_L3_PEER=\$(getent hosts veilway-l3-peer | cut -d' ' -f1) cargo test -p veilway-core --test l3 --locked -- --nocapture"
//! docker rm -f veilway-l3-peer && docker network rm veilway-l3
//! ```
#![cfg(target_os = "linux")]
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{IpNumber, PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use veilway_core::config::Config;
use veilway_core::{Options, Reason};

const INTERFACE: &str = "vwtest0";
const DEVICE: [u8; 4] = [10, 7, 0, 2];
const GATEWAY: [u8; 4] = [10, 7, 0, 1];
const GREETING: &[u8] = b"hello-from-responder";
/// The tests share one interface name and one set of pool routes, so they take turns.
static HOST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A WireGuard peer that sends and receives whole IP packets.
struct Client {tunn: Tunn, sock: UdpSocket}

impl Client {
	async fn connect(private: [u8; 32], server_public: [u8; 32], server: SocketAddr) -> Client {
		let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.connect(server).await.unwrap();
		let mut tunn = Tunn::new(StaticSecret::from(private), PublicKey::from(server_public), None, None, 0, None);
		let (mut scratch, mut datagram, mut out) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
		let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut scratch, false) else {panic!("no handshake initiation")};
		sock.send(init).await.unwrap();
		let n = timeout(Duration::from_secs(3), sock.recv(&mut datagram)).await.expect("handshake timed out").unwrap();
		if let TunnResult::WriteToNetwork(keepalive) = tunn.decapsulate(None, &datagram[..n], &mut out) {sock.send(keepalive).await.unwrap();}
		Client {tunn, sock}
	}

	async fn send_ip(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn.encapsulate(packet, &mut out) else {panic!("encapsulate produced nothing")};
		self.sock.send(datagram).await.unwrap();
	}

	/// The next decrypted IP packet within `budget`.
	async fn recv_ip(&mut self, budget: Duration) -> Option<Vec<u8>> {
		let deadline = Instant::now() + budget;
		loop {
			let (mut datagram, mut out) = (vec![0u8; 2048], vec![0u8; 2048]);
			let n = timeout(deadline.checked_duration_since(Instant::now())?, self.sock.recv(&mut datagram)).await.ok()?.ok()?;
			match self.tunn.decapsulate(None, &datagram[..n], &mut out) {
				TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => return Some(packet.to_vec()),
				TunnResult::WriteToNetwork(reply) => drop(self.sock.send(reply).await),
				_ => {}
			}
		}
	}

	/// The next packet within `budget` that `wanted` picks out. Others are passed over.
	async fn expect<T>(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
		let deadline = Instant::now() + budget;
		loop {
			let packet = self.recv_ip(deadline.checked_duration_since(Instant::now())?).await?;
			if let Some(found) = wanted(&packet) {return Some(found)}
		}
	}
}

fn udp(dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	PacketBuilder::ipv4(DEVICE, dst, 64).udp(sport, dport).write(&mut out, payload).unwrap();
	out
}

fn tcp(dst: [u8; 4], header: TcpHeader) -> Vec<u8> {
	let mut out = Vec::new();
	PacketBuilder::ipv4(DEVICE, dst, 64).tcp_header(header).write(&mut out, &[]).unwrap();
	out
}

/// A counter of the interface as the kernel keeps it. What the node writes to a TUN device is what the interface received.
fn interface_counter(name: &str) -> u64 {std::fs::read_to_string(format!("/sys/class/net/{INTERFACE}/statistics/{name}")).unwrap().trim().parse().unwrap()}

fn output(program: &str, args: &[&str]) -> (bool, String) {
	let out = Command::new(program).args(args).output().unwrap();
	(out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_l3_exit_carries_every_protocol_through_the_kernel_and_cleans_up() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("skipped: the l3 tests need a TUN device and CAP_NET_ADMIN, set VEILWAY_TEST_L3=1 and VEILWAY_TEST_L3_PEER to run them")}
	let _turn = HOST.lock().await;
	let peer: Ipv4Addr = std::env::var("VEILWAY_TEST_L3_PEER").expect("VEILWAY_TEST_L3_PEER names the responder").parse().expect("VEILWAY_TEST_L3_PEER is an IPv4 address");
	let (private, key, listen, peer) = (veilway_wg::generate_key(), veilway_wg::generate_key(), SocketAddr::from((Ipv4Addr::LOCALHOST, 21900)), peer.octets());
	let encode = |key: &[u8; 32]| veilway_wg::encode_key(key);
	// The second tunnel has no user. Its smaller MTU is the one the interface must take.
	let doc = json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"], "hijack": false},
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": encode(&private), "address": ["10.7.0.1/24"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]},
			{"tag": "small", "type": "wireguard", "private_key": encode(&veilway_wg::generate_key()), "address": ["10.8.0.1/24"], "mtu": 1280, "transports": [{"type": "udp", "listen": "127.0.0.1:21901"}]}
		],
		"outbounds": [],
		"exits": [{"tag": "node", "backend": {"type": "l3", "interface": INTERFACE, "masquerade": true}}],
		"routing": {"default": "node", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "device", "public_key": encode(&veilway_wg::public_key(&key)), "addresses": ["10.7.0.2"]}]}]
	});
	let config = Config::parse(doc.to_string().as_bytes()).unwrap();
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	let engine = veilway_core::start(&config, Options::new("")).await.expect("the l3 exit did not start");
	assert_eq!(std::fs::read_to_string(format!("/sys/class/net/{INTERFACE}/mtu")).unwrap().trim(), "1280", "the interface did not take the smallest mtu of the inbounds");
	let (routes, table) = (output("ip", &["route", "show", "dev", INTERFACE]).1, format!("veilway_{INTERFACE}"));
	assert!(routes.contains("10.7.0.0/24") && routes.contains("10.8.0.0/24"), "the pools are not routed to the interface: {routes}");
	assert!(output("nft", &["list", "table", "inet", &table]).1.contains("masquerade"), "no source nat was set up");
	let mut a = Client::connect(key, veilway_wg::public_key(&private), listen).await;
	// Ping: the kernel forwards it, the responder's host answers, and the answer comes back under the identifier the device chose.
	let mut ping = Vec::new();
	PacketBuilder::ipv4(DEVICE, peer, 64).icmpv4_echo_request(77, 3).write(&mut ping, b"abcdefgh").unwrap();
	a.send_ip(&ping).await;
	let reply = a.expect(Duration::from_secs(5), |packet| (packet[9] == 1 && packet[20] == 0).then(|| packet.to_vec())).await.expect("no echo reply through the l3 exit");
	assert_eq!((&reply[12..16], &reply[16..20], &reply[24..]), (&peer[..], &DEVICE[..], &ping[24..]), "the echo reply is not the answer to the ping");
	// TCP: a handshake with the responder's own stack, then its greeting.
	let mut syn = TcpHeader::new(41000, 7000, 1000, 65535);
	syn.syn = true;
	a.send_ip(&tcp(peer, syn)).await;
	let transport = |packet: &[u8]| PacketHeaders::from_ip_slice(packet).ok().and_then(|parsed| parsed.transport.zip(Some(match parsed.payload {PayloadSlice::Tcp(payload) | PayloadSlice::Udp(payload) => payload.to_vec(), _ => Vec::new()})));
	let server = a.expect(Duration::from_secs(5), |packet| match transport(packet) {Some((TransportHeader::Tcp(tcp), _)) if tcp.syn && tcp.ack && tcp.destination_port == 41000 => Some(tcp.sequence_number), _ => None}).await.expect("no SYN/ACK through the l3 exit");
	let mut ack = TcpHeader::new(41000, 7000, 1001, 65535);
	(ack.ack, ack.acknowledgment_number) = (true, server.wrapping_add(1));
	a.send_ip(&tcp(peer, ack)).await;
	let greeting = a.expect(Duration::from_secs(5), |packet| match transport(packet) {Some((TransportHeader::Tcp(_), payload)) if !payload.is_empty() => Some(payload), _ => None}).await.expect("no data on the tcp flow");
	assert_eq!(greeting, GREETING);
	let mut reset = TcpHeader::new(41000, 7000, 1001, 0);
	reset.rst = true;
	a.send_ip(&tcp(peer, reset)).await;
	// UDP both ways.
	a.send_ip(&udp(peer, 41001, 7001, b"ping")).await;
	let echoed = a.expect(Duration::from_secs(5), |packet| match transport(packet) {Some((TransportHeader::Udp(udp), payload)) if udp.source_port == 7001 => Some(payload), _ => None}).await.expect("no udp reply through the l3 exit");
	assert_eq!(echoed, b"echo:ping");
	// An ICMP error from the network that quotes a packet of a live flow is let through to the device: nothing listens on this port of the responder.
	let closed = udp(peer, 41002, 7002, b"ping");
	a.send_ip(&closed).await;
	let quoted = a.expect(Duration::from_secs(5), |packet| (packet[9] == 1 && packet[20] == 3 && packet[21] == 3).then(|| packet[28..].to_vec())).await.expect("the port unreachable of the responder did not come back");
	assert_eq!((&quoted[12..20], &quoted[20..24]), (&closed[12..20], &closed[20..24]), "the error does not quote the packet the device sent");
	// Another IP protocol leaves through the interface like everything else.
	let (before, mut gre) = (interface_counter("rx_packets"), Vec::new());
	PacketBuilder::ipv4(DEVICE, peer, 64).write(&mut gre, IpNumber(47), &[0, 0, 0x08, 0, 0, 0, 0, 0]).unwrap();
	a.send_ip(&gre).await;
	let deadline = Instant::now() + Duration::from_secs(3);
	while interface_counter("rx_packets") == before {
		assert!(Instant::now() < deadline, "a gre packet did not leave through the interface");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert_eq!(engine.dropped(Reason::Unsupported), 0);
	// A packet that is too big for the interface is answered to the device with the MTU that fits.
	a.send_ip(&udp(peer, 41003, 7001, &[7; 1300])).await;
	let (from, mtu) = a.expect(Duration::from_secs(3), |packet| (packet[9] == 1 && packet[20] == 3 && packet[21] == 4).then(|| (packet[12..16].to_vec(), packet[24..28].to_vec()))).await.expect("no fragmentation needed for a packet over the mtu of the interface");
	assert_eq!((&from[..], &mtu[..], engine.dropped(Reason::TooBig)), (&GATEWAY[..], &[0, 0, 5, 0][..], 1));
	// What reaches the interface without belonging to a flow is not delivered: here a datagram from this host itself, aimed at the port the device used for its UDP flow and sent from the responder's port.
	let (stray, drops) = (UdpSocket::bind("0.0.0.0:7001").await.unwrap(), engine.dropped(Reason::NoFlow));
	stray.send_to(b"not for you", (Ipv4Addr::from(DEVICE), 41001)).await.unwrap();
	assert!(a.recv_ip(Duration::from_millis(700)).await.is_none(), "a packet that belongs to no flow was delivered");
	assert!(engine.dropped(Reason::NoFlow) > drops, "the stray packet was not counted");
	let exit = engine.exit("node").unwrap();
	assert!(exit.up_packets >= 7 && exit.down_packets >= 5, "the exit did not count what it carried: {exit:?}");
	// Shutdown takes the interface, its routes and the firewall table with it.
	engine.shutdown().await;
	let deadline = Instant::now() + Duration::from_secs(3);
	while Path::new(&format!("/sys/class/net/{INTERFACE}")).exists() {
		assert!(Instant::now() < deadline, "the interface outlived the shutdown");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert!(!output("nft", &["list", "table", "inet", &table]).0, "the firewall table outlived the shutdown");
	assert!(!output("ip", &["route", "show"]).1.contains("10.7.0.0/24"), "a pool route outlived the shutdown");
}

/// A reload brings the l3 exit up and takes it away again, and the interface, its routes and its firewall table come and go with it. A reload that cannot set the interface up leaves the host and the running config as they were,
/// and one that changes what the interface needs (here a second pool and a smaller MTU) sets it up anew without losing the flows that leave through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_adds_changes_and_removes_the_l3_exit_with_everything_it_sets_up() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("skipped: the l3 tests need a TUN device and CAP_NET_ADMIN, set VEILWAY_TEST_L3=1 and VEILWAY_TEST_L3_PEER to run them")}
	let _turn = HOST.lock().await;
	let peer: Ipv4Addr = std::env::var("VEILWAY_TEST_L3_PEER").expect("VEILWAY_TEST_L3_PEER names the responder").parse().expect("VEILWAY_TEST_L3_PEER is an IPv4 address");
	let (private, key, listen, peer, table) = (veilway_wg::generate_key(), veilway_wg::generate_key(), SocketAddr::from((Ipv4Addr::LOCALHOST, 21910)), peer.octets(), format!("veilway_{INTERFACE}"));
	let without = json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"], "hijack": false},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&private), "address": ["10.7.0.1/24"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [],
		"exits": [{"tag": "sink", "backend": {"type": "block"}}],
		"routing": {"default": "sink", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&key)), "addresses": ["10.7.0.2"]}]}]
	});
	let wired = |interface: &str| {
		let mut doc = without.clone();
		doc["exits"].as_array_mut().unwrap().push(json!({"tag": "node", "backend": {"type": "l3", "interface": interface, "masquerade": true}}));
		doc["routing"]["default"] = json!("node");
		doc
	};
	let config = Config::parse(without.to_string().as_bytes()).unwrap();
	assert!(config.validate(false).errors.is_empty());
	let engine = veilway_core::start(&config, Options::new("")).await.unwrap();
	let present = || (Path::new(&format!("/sys/class/net/{INTERFACE}")).exists(), output("nft", &["list", "table", "inet", &table]).0, output("ip", &["route", "show"]).1.contains("10.7.0.0/24"));
	assert_eq!(present(), (false, false, false));
	let mut a = Client::connect(key, veilway_wg::public_key(&private), listen).await;
	let ping = |seq: u16| {
		let mut ping = Vec::new();
		PacketBuilder::ipv4(DEVICE, peer, 64).icmpv4_echo_request(77, seq).write(&mut ping, b"abcdefgh").unwrap();
		ping
	};
	let echoed = |packet: &[u8]| (packet[9] == 1 && packet[20] == 0).then_some(());
	a.send_ip(&ping(1)).await;
	assert!(a.expect(Duration::from_millis(700), echoed).await.is_none(), "a ping got out without an l3 exit");
	// An interface that cannot be made: the name is the loopback interface's. Nothing of the reload stays, on the host or in the node.
	let failed = engine.reload(wired("lo").to_string().into_bytes(), None).await.err().expect("an l3 exit on an interface that exists came up").to_string();
	assert!(failed.contains("`node`"), "{failed}");
	assert_eq!((present(), output("nft", &["list", "table", "inet", "veilway_lo"]).0, engine.snapshot().generation), ((false, false, false), false, 1));
	engine.reload(wired(INTERFACE).to_string().into_bytes(), None).await.expect("the reload that adds the l3 exit failed");
	assert_eq!(present(), (true, true, true), "the reload did not set up the interface, its table and its routes");
	a.send_ip(&ping(2)).await;
	a.expect(Duration::from_secs(5), echoed).await.expect("no echo reply through an l3 exit that a reload added");
	// A second pool and a smaller MTU: the interface is made anew for them, and the ping that was going on goes on.
	let mut wider = wired(INTERFACE);
	wider["inbounds"].as_array_mut().unwrap().push(json!({"tag": "small", "type": "wireguard", "private_key": veilway_wg::encode_key(&veilway_wg::generate_key()), "address": ["10.8.0.1/24"], "mtu": 1280, "transports": [{"type": "udp", "listen": "127.0.0.1:21911"}]}));
	engine.reload(wider.to_string().into_bytes(), None).await.expect("the reload that adds a pool failed");
	let routes = output("ip", &["route", "show", "dev", INTERFACE]).1;
	assert!(routes.contains("10.7.0.0/24") && routes.contains("10.8.0.0/24"), "the pools are not routed to the interface: {routes}");
	assert_eq!(std::fs::read_to_string(format!("/sys/class/net/{INTERFACE}/mtu")).unwrap().trim(), "1280");
	a.send_ip(&ping(3)).await;
	a.expect(Duration::from_secs(5), echoed).await.expect("no echo reply after the interface was set up anew");
	assert_eq!(engine.flows(), 1, "the ping is one flow, before and after");
	// And away again: the exit is gone from the config, and so is everything it set up.
	engine.reload(without.to_string().into_bytes(), None).await.expect("the reload that removes the l3 exit failed");
	let deadline = Instant::now() + Duration::from_secs(3);
	while present() != (false, false, false) {
		assert!(Instant::now() < deadline, "the interface, its table or its routes outlived the exit: {:?}", present());
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert_eq!((engine.exit("node"), engine.flows()), (None, 0), "the flow through the exit outlived it");
	a.send_ip(&ping(4)).await;
	assert!(a.expect(Duration::from_millis(700), echoed).await.is_none(), "a ping got out after its exit was removed");
	engine.shutdown().await;
}

/// Without `masquerade` the node leaves forwarding and NAT to the operator, and a device still reaches nothing on the host itself. The kernel takes more addresses for its own than the engine's gate knows:
/// here the broadcast address of the network this host is on. And an engine that is dropped without `shutdown` takes its firewall table and its interface with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_masquerade_a_device_still_reaches_nothing_on_the_host_and_a_dropped_engine_cleans_up() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("skipped: the l3 tests need a TUN device and CAP_NET_ADMIN, set VEILWAY_TEST_L3=1 to run them")}
	let _turn = HOST.lock().await;
	let (private, key, listen) = (veilway_wg::generate_key(), veilway_wg::generate_key(), SocketAddr::from((Ipv4Addr::LOCALHOST, 21902)));
	let broadcast: Ipv4Addr = output("ip", &["-4", "-o", "addr", "show", "scope", "global"]).1.split_whitespace().skip_while(|word| *word != "brd").nth(1).expect("this host has no network with a broadcast address").parse().unwrap();
	let doc = json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"], "hijack": false},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&private), "address": ["10.7.0.1/24"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [],
		"exits": [{"tag": "node", "backend": {"type": "l3", "interface": INTERFACE, "masquerade": false}}],
		"routing": {"default": "node", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&key)), "addresses": ["10.7.0.2"]}]}]
	});
	let config = Config::parse(doc.to_string().as_bytes()).unwrap();
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	let engine = veilway_core::start(&config, Options::new("")).await.expect("the l3 exit did not start");
	let mut a = Client::connect(key, veilway_wg::public_key(&private), listen).await;
	// A service of the host that listens on every address, as most do.
	let (service, before, mut heard) = (UdpSocket::bind("0.0.0.0:7155").await.unwrap(), interface_counter("rx_packets"), [0u8; 64]);
	for _ in 0..3 {a.send_ip(&udp(broadcast.octets(), 41500, 7155, b"knock")).await}
	let deadline = Instant::now() + Duration::from_secs(3);
	while interface_counter("rx_packets") < before + 3 {
		assert!(Instant::now() < deadline, "the datagrams did not reach the kernel, so this test shows nothing");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert!(timeout(Duration::from_millis(700), service.recv_from(&mut heard)).await.is_err(), "a device reached a service of the host through the interface");
	let (listed, rules) = output("nft", &["list", "table", "inet", &format!("veilway_{INTERFACE}")]);
	assert!(listed && rules.contains("drop") && !rules.contains("masquerade"), "without masquerade the table holds the two drops and no source nat: {rules}");
	drop(engine);
	assert!(!output("nft", &["list", "table", "inet", &format!("veilway_{INTERFACE}")]).0, "the firewall table outlived the engine");
	let deadline = Instant::now() + Duration::from_secs(3);
	while Path::new(&format!("/sys/class/net/{INTERFACE}")).exists() {
		assert!(Instant::now() < deadline, "the interface outlived the engine");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}
