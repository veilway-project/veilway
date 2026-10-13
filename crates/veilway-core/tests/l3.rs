//! The `l3` exit against a real kernel: a WireGuard client talks to the engine, which writes its packets to a TUN device, and the kernel forwards them to a responder on the network, with source NAT or without.
//! It needs Linux, `CAP_NET_ADMIN`, `/dev/net/tun`, `ip` and `nft`, so it only runs when `VEILWAY_TEST_L3=1` is set, with `VEILWAY_TEST_L3_PEER` and `VEILWAY_TEST_L3_PEER6` naming the IPv4 and the IPv6 address of a host next to this one
//! that answers ping, sends `GREETING` to whoever connects on TCP port 7000, echoes UDP datagrams on port 7001 with `echo:` in front, answers on UDP port 7003 with the address a datagram came from, and has nothing on UDP port 7002.
//! `tests/l3-responder.py` is that host. For the test without `masquerade` it needs a route to the tunnel's pools by way of this host, which is why both have fixed addresses here, and this host has to forward IPv6, which a container cannot turn on for itself.
//! Run it in two containers on one Docker network with IPv6, from the repo root:
//!
//! ```text
//! docker network create --ipv6 --subnet 172.30.72.0/24 --subnet fd00:72::/64 veilway-l3
//! docker run -d --rm --name veilway-l3-peer --network veilway-l3 --ip 172.30.72.3 --ip6 fd00:72::3 --cap-add NET_ADMIN -v "$PWD/crates/veilway-core/tests/l3-responder.py":/responder.py:ro python:3-alpine sh -c \
//!   "ip route add 10.7.0.0/24 via 172.30.72.2 && ip -6 route add fd07::/64 via fd00:72::2 && python /responder.py"
//! docker run --rm --network veilway-l3 --ip 172.30.72.2 --ip6 fd00:72::2 --sysctl net.ipv6.conf.all.forwarding=1 --cap-add NET_ADMIN --device /dev/net/tun \
//!   -e VEILWAY_TEST_L3=1 -e VEILWAY_TEST_L3_PEER=172.30.72.3 -e VEILWAY_TEST_L3_PEER6=fd00:72::3 -v "$PWD":/w -v veilway-target:/w/target -v veilway-cargo:/usr/local/cargo -w /w rust:1 sh -c \
//!   "apt-get update -qq && apt-get install -y -qq iproute2 nftables && cargo test -p veilway-core --test l3 --locked -- --nocapture"
//! docker rm -f veilway-l3-peer && docker network rm veilway-l3
//! ```
#![cfg(target_os = "linux")]
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{Icmpv4Type, Icmpv6Type, IpNumber, NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
const DEVICE6: [u8; 16] = Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 2).octets();
const GATEWAY6: [u8; 16] = Ipv6Addr::new(0xfd07, 0, 0, 0, 0, 0, 0, 1).octets();
const SKIPPED: &str = "skipped: the l3 tests need a TUN device and CAP_NET_ADMIN, set VEILWAY_TEST_L3=1, VEILWAY_TEST_L3_PEER and VEILWAY_TEST_L3_PEER6 to run them";
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

/// The packets a device sends come from its address of the family of `dst`.
fn udp(dst: impl Into<IpAddr>, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	match dst.into() {
		IpAddr::V4(dst) => PacketBuilder::ipv4(DEVICE, dst.octets(), 64).udp(sport, dport).write(&mut out, payload),
		IpAddr::V6(dst) => PacketBuilder::ipv6(DEVICE6, dst.octets(), 64).udp(sport, dport).write(&mut out, payload),
	}.unwrap();
	out
}

fn tcp(dst: impl Into<IpAddr>, header: TcpHeader) -> Vec<u8> {
	let mut out = Vec::new();
	match dst.into() {
		IpAddr::V4(dst) => PacketBuilder::ipv4(DEVICE, dst.octets(), 64).tcp_header(header).write(&mut out, &[]),
		IpAddr::V6(dst) => PacketBuilder::ipv6(DEVICE6, dst.octets(), 64).tcp_header(header).write(&mut out, &[]),
	}.unwrap();
	out
}

fn ping(dst: impl Into<IpAddr>, seq: u16) -> Vec<u8> {
	let mut out = Vec::new();
	match dst.into() {
		IpAddr::V4(dst) => PacketBuilder::ipv4(DEVICE, dst.octets(), 64).icmpv4_echo_request(77, seq).write(&mut out, b"abcdefgh"),
		IpAddr::V6(dst) => PacketBuilder::ipv6(DEVICE6, dst.octets(), 64).icmpv6_echo_request(77, seq).write(&mut out, b"abcdefgh"),
	}.unwrap();
	out
}

/// The source of a packet and what it carries: the TCP or UDP header with its payload, or the ICMP header.
fn transport(packet: &[u8]) -> Option<(IpAddr, TransportHeader, Vec<u8>)> {
	let parsed = PacketHeaders::from_ip_slice(packet).ok()?;
	let from = match parsed.net? {
		NetHeaders::Ipv4(ip, _) => IpAddr::from(ip.source),
		NetHeaders::Ipv6(ip, _) => IpAddr::from(ip.source),
		_ => return None,
	};
	Some((from, parsed.transport?, match parsed.payload {PayloadSlice::Tcp(payload) | PayloadSlice::Udp(payload) => payload.to_vec(), _ => Vec::new()}))
}

/// The echo reply to the ping with `seq`, by where it came from.
fn echoed(packet: &[u8], seq: u16) -> Option<IpAddr> {
	match transport(packet)? {
		(from, TransportHeader::Icmpv4(icmp), _) if matches!(icmp.icmp_type, Icmpv4Type::EchoReply(echo) if echo.id == 77 && echo.seq == seq) => Some(from),
		(from, TransportHeader::Icmpv6(icmp), _) if matches!(icmp.icmp_type, Icmpv6Type::EchoReply(echo) if echo.id == 77 && echo.seq == seq) => Some(from),
		_ => None,
	}
}

/// A TCP handshake from `sport` with the responder's own stack, and the first data the responder sends on it.
async fn greeted(a: &mut Client, dst: IpAddr, sport: u16) -> Vec<u8> {
	let mut syn = TcpHeader::new(sport, 7000, 1000, 65535);
	syn.syn = true;
	a.send_ip(&tcp(dst, syn)).await;
	let server = a.expect(Duration::from_secs(5), |packet| match transport(packet) {Some((_, TransportHeader::Tcp(tcp), _)) if tcp.syn && tcp.ack && tcp.destination_port == sport => Some(tcp.sequence_number), _ => None}).await.expect("no SYN/ACK through the l3 exit");
	let mut ack = TcpHeader::new(sport, 7000, 1001, 65535);
	(ack.ack, ack.acknowledgment_number) = (true, server.wrapping_add(1));
	a.send_ip(&tcp(dst, ack)).await;
	let greeting = a.expect(Duration::from_secs(5), |packet| match transport(packet) {Some((_, TransportHeader::Tcp(tcp), payload)) if tcp.destination_port == sport && !payload.is_empty() => Some(payload), _ => None}).await.expect("no data on the tcp flow");
	let mut reset = TcpHeader::new(sport, 7000, 1001, 0);
	reset.rst = true;
	a.send_ip(&tcp(dst, reset)).await;
	greeting
}

/// What the responder answers to one datagram from `sport` to its port `dport`.
async fn asked(a: &mut Client, dst: IpAddr, sport: u16, dport: u16) -> Vec<u8> {
	a.send_ip(&udp(dst, sport, dport, b"ping")).await;
	a.expect(Duration::from_secs(5), |packet| match transport(packet) {Some((_, TransportHeader::Udp(udp), payload)) if udp.source_port == dport && udp.destination_port == sport => Some(payload), _ => None}).await.expect("no udp reply through the l3 exit")
}

/// The responder's two addresses.
fn peers() -> (Ipv4Addr, Ipv6Addr) {
	(std::env::var("VEILWAY_TEST_L3_PEER").expect("VEILWAY_TEST_L3_PEER names the responder").parse().expect("VEILWAY_TEST_L3_PEER is an IPv4 address"), std::env::var("VEILWAY_TEST_L3_PEER6").expect("VEILWAY_TEST_L3_PEER6 names the responder").parse().expect("VEILWAY_TEST_L3_PEER6 is an IPv6 address"))
}

/// One inbound with an IPv4 and an IPv6 pool, one device with an address in each, and the l3 exit as the default.
fn dual(private: &[u8; 32], key: &[u8; 32], listen: SocketAddr, masquerade: bool) -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"], "hijack": false},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(private), "address": ["10.7.0.1/24", "fd07::1/64"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [],
		"exits": [{"tag": "node", "backend": {"type": "l3", "interface": INTERFACE, "masquerade": masquerade}}],
		"routing": {"default": "node", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(key)), "addresses": ["10.7.0.2", "fd07::2"]}]}]
	})
}

/// A counter of the interface as the kernel keeps it. What the node writes to a TUN device is what the interface received.
fn interface_counter(name: &str) -> u64 {std::fs::read_to_string(format!("/sys/class/net/{INTERFACE}/statistics/{name}")).unwrap().trim().parse().unwrap()}

fn output(program: &str, args: &[&str]) -> (bool, String) {
	let out = Command::new(program).args(args).output().unwrap();
	(out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_l3_exit_carries_every_protocol_through_the_kernel_and_cleans_up() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
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
	// TCP: a handshake with the responder's own stack, then its greeting. And UDP both ways.
	assert_eq!(greeted(&mut a, peer.into(), 41000).await, GREETING);
	assert_eq!(asked(&mut a, peer.into(), 41001, 7001).await, b"echo:ping");
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
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
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
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
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

/// IPv6 through the interface, with source NAT: ping, TCP and UDP reach the responder and come back, the errors of the network and of the node come back, and what reaches the interface without belonging to a flow is not delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_goes_through_the_l3_exit_and_only_the_answers_to_live_flows_come_back() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
	let _turn = HOST.lock().await;
	let (private, key, listen, peer) = (veilway_wg::generate_key(), veilway_wg::generate_key(), SocketAddr::from((Ipv4Addr::LOCALHOST, 21920)), IpAddr::from(peers().1));
	let config = Config::parse(dual(&private, &key, listen, true).to_string().as_bytes()).unwrap();
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	let engine = veilway_core::start(&config, Options::new("")).await.expect("the l3 exit did not start");
	assert!(output("ip", &["-6", "route", "show", "dev", INTERFACE]).1.contains("fd07::/64"), "the ipv6 pool is not routed to the interface");
	let mut a = Client::connect(key, veilway_wg::public_key(&private), listen).await;
	a.send_ip(&ping(peer, 1)).await;
	assert_eq!(a.expect(Duration::from_secs(5), |packet| echoed(packet, 1)).await.expect("no ipv6 echo reply through the l3 exit"), peer);
	assert_eq!(greeted(&mut a, peer, 41600).await, GREETING);
	assert_eq!(asked(&mut a, peer, 41601, 7001).await, b"echo:ping");
	// The responder saw the node's address on the network, not the device's.
	let seen = String::from_utf8(asked(&mut a, peer, 41602, 7003).await).unwrap();
	assert!(seen.starts_with("from:") && seen != format!("from:{}", Ipv6Addr::from(DEVICE6)), "the responder saw {seen}, which is not a source the node's NAT wrote");
	// An ICMPv6 error from the network that quotes a packet of a live flow is let through: nothing listens on this port of the responder. Type 1 code 4 is port unreachable, and the quoted packet starts 8 bytes into the message.
	let closed = udp(peer, 41603, 7002, b"ping");
	a.send_ip(&closed).await;
	let quoted = a.expect(Duration::from_secs(5), |packet| (packet[6] == 58 && packet[40] == 1 && packet[41] == 4).then(|| packet[48..].to_vec())).await.expect("the port unreachable of the responder did not come back");
	assert_eq!((&quoted[8..40], &quoted[40..44]), (&closed[8..40], &closed[40..44]), "the error does not quote the packet the device sent");
	// A packet that is too big for the interface is answered by the node with packet too big, type 2, and the MTU that fits.
	a.send_ip(&udp(peer, 41604, 7001, &[7; 1400])).await;
	let (from, mtu) = a.expect(Duration::from_secs(3), |packet| (packet[6] == 58 && packet[40] == 2).then(|| (packet[8..24].to_vec(), packet[44..48].to_vec()))).await.expect("no packet too big for a packet over the mtu of the interface");
	assert_eq!((&from[..], &mtu[..], engine.dropped(Reason::TooBig)), (&GATEWAY6[..], &1420u32.to_be_bytes()[..], 1));
	// A datagram from this host itself, aimed at the port the device used for its UDP flow and sent from the responder's port, belongs to no flow: that flow is with the responder's address.
	let (stray, drops) = (UdpSocket::bind("[::]:7001").await.unwrap(), engine.dropped(Reason::NoFlow));
	stray.send_to(b"not for you", (Ipv6Addr::from(DEVICE6), 41601)).await.unwrap();
	assert!(a.recv_ip(Duration::from_millis(700)).await.is_none(), "an ipv6 packet that belongs to no flow was delivered");
	assert!(engine.dropped(Reason::NoFlow) > drops, "the stray packet was not counted");
	// The flow is still there for its own answers.
	assert_eq!(asked(&mut a, peer, 41601, 7001).await, b"echo:ping");
	let exit = engine.exit("node").unwrap();
	assert!(exit.up_packets >= 7 && exit.down_packets >= 7, "the exit did not count what it carried: {exit:?}");
	engine.shutdown().await;
	let deadline = Instant::now() + Duration::from_secs(3);
	while Path::new(&format!("/sys/class/net/{INTERFACE}")).exists() {
		assert!(Instant::now() < deadline, "the interface outlived the shutdown");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert!(!output("ip", &["-6", "route", "show"]).1.contains("fd07::/64"), "an ipv6 pool route outlived the shutdown");
}

/// Without `masquerade` the kernel forwards a device's packets under the device's own address, IPv4 and IPv6. The responder has a route to both pools by way of this host, so its answers come back, and only into live flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_masquerade_traffic_leaves_under_the_address_of_its_device_and_comes_back() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
	let _turn = HOST.lock().await;
	let (private, key, listen, (peer, peer6)) = (veilway_wg::generate_key(), veilway_wg::generate_key(), SocketAddr::from((Ipv4Addr::LOCALHOST, 21930)), peers());
	let config = Config::parse(dual(&private, &key, listen, false).to_string().as_bytes()).unwrap();
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	let engine = veilway_core::start(&config, Options::new("")).await.expect("the l3 exit did not start");
	assert!(!output("nft", &["list", "ruleset"]).1.contains("masquerade"), "source nat was set up without masquerade");
	let mut a = Client::connect(key, veilway_wg::public_key(&private), listen).await;
	for (peer, device, sport) in [(IpAddr::from(peer), IpAddr::from(DEVICE), 41700), (IpAddr::from(peer6), IpAddr::from(DEVICE6), 41710)] {
		a.send_ip(&ping(peer, 1)).await;
		assert_eq!(a.expect(Duration::from_secs(5), |packet| echoed(packet, 1)).await.expect("no echo reply without masquerade: has the responder its route to the pools?"), peer);
		assert_eq!(greeted(&mut a, peer, sport).await, GREETING);
		assert_eq!(asked(&mut a, peer, sport + 1, 7001).await, b"echo:ping");
		assert_eq!(String::from_utf8(asked(&mut a, peer, sport + 2, 7003).await).unwrap(), format!("from:{device}"), "the responder did not see the device's own address");
	}
	// The responder can reach the pools, and still nothing of it comes in that no flow asked for: here a datagram from this host, as in the tests with source NAT.
	let (stray, drops) = (UdpSocket::bind("0.0.0.0:7001").await.unwrap(), engine.dropped(Reason::NoFlow));
	stray.send_to(b"not for you", (Ipv4Addr::from(DEVICE), 41701)).await.unwrap();
	assert!(a.recv_ip(Duration::from_millis(700)).await.is_none(), "a packet that belongs to no flow was delivered");
	assert!(engine.dropped(Reason::NoFlow) > drops, "the stray packet was not counted");
	engine.shutdown().await;
}

/// An exit whose interface is gone is down, says so, answers what is routed to it as unreachable, and comes back by itself: after an interface that was removed under the node, and after a reload that closed the interface and could bring up neither the new one nor the old.
/// A reload does not wait for an exit that is down and has it try at once, and a shutdown in the middle of the tries leaves nothing behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_l3_exit_that_goes_down_is_brought_up_again() {
	if std::env::var("VEILWAY_TEST_L3").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
	let _turn = HOST.lock().await;
	let (private, key, listen, (peer, peer6), table) = (veilway_wg::generate_key(), veilway_wg::generate_key(), SocketAddr::from((Ipv4Addr::LOCALHOST, 21940)), peers(), format!("veilway_{INTERFACE}"));
	let doc = dual(&private, &key, listen, true);
	let config = Config::parse(doc.to_string().as_bytes()).unwrap();
	assert!(config.validate(false).errors.is_empty());
	let engine = veilway_core::start(&config, Options::new("")).await.expect("the l3 exit did not start");
	let health = || engine.exit_health().into_iter().find(|health| health.exit == "node").map(|health| (health.interface_down.map(|down| down.is_some()), health.interface_flips)).unwrap();
	let present = || (Path::new(&format!("/sys/class/net/{INTERFACE}")).exists(), output("nft", &["list", "table", "inet", &table]).0, output("ip", &["route", "show"]).1.contains("10.7.0.0/24"));
	// Waits for the exit to say `down`, for `budget` at most.
	let turns = async |down: bool, budget: Duration| {
		let deadline = Instant::now() + budget;
		while health().0 != Some(down) {
			if Instant::now() > deadline {return false}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
		true
	};
	let mut a = Client::connect(key, veilway_wg::public_key(&private), listen).await;
	a.send_ip(&ping(peer, 1)).await;
	a.expect(Duration::from_secs(5), |packet| echoed(packet, 1)).await.expect("no echo reply through the l3 exit");
	assert_eq!(health(), (Some(false), 0));
	// The interface is removed under the node, and its name is taken by another before the node's first try.
	let blocked = || assert!(output("ip", &["link", "del", INTERFACE]).0 && output("ip", &["tuntap", "add", "dev", INTERFACE, "mode", "tun"]).0, "the interface could not be replaced by one that is not the node's");
	blocked();
	assert!(turns(true, Duration::from_secs(2)).await, "the node did not notice that its interface was removed");
	assert_eq!((health().1, output("nft", &["list", "table", "inet", &table]).0), (1, false), "an exit that is down keeps nothing on the host");
	// What is routed to the exit is answered: host unreachable for a ping, address unreachable over IPv6, a reset for TCP. Nothing leaves another way.
	let drops = engine.dropped(Reason::Unreachable);
	a.send_ip(&ping(peer, 2)).await;
	assert_eq!(a.expect(Duration::from_secs(2), |packet| (packet[0] >> 4 == 4 && packet[9] == 1 && packet[20] == 3 && packet[21] == 1).then(|| packet[12..16].to_vec())).await.expect("no host unreachable while the exit is down"), GATEWAY);
	a.send_ip(&ping(peer6, 2)).await;
	assert_eq!(a.expect(Duration::from_secs(2), |packet| (packet[0] >> 4 == 6 && packet[6] == 58 && packet[40] == 1 && packet[41] == 3).then(|| packet[8..24].to_vec())).await.expect("no address unreachable while the exit is down"), GATEWAY6);
	let mut syn = TcpHeader::new(41800, 7000, 1000, 65535);
	syn.syn = true;
	a.send_ip(&tcp(peer, syn)).await;
	a.expect(Duration::from_secs(2), |packet| matches!(transport(packet), Some((_, TransportHeader::Tcp(tcp), _)) if tcp.rst && tcp.destination_port == 41800).then_some(())).await.expect("no reset while the exit is down");
	assert_eq!(engine.dropped(Reason::Unreachable), drops + 3);
	// A reload that wants another interface and cannot have it stops the tries, fails, and starts them again for the exit of the config that still runs.
	let mut other = doc.clone();
	other["exits"][0]["backend"]["interface"] = json!("lo");
	engine.reload(other.to_string().into_bytes(), None).await.err().expect("an l3 exit on an interface that exists came up");
	assert_eq!((health(), engine.snapshot().generation), ((Some(true), 1), 1));
	// A reload that leaves the exit as it is goes through while the exit is down, and has it try at once: the name is free again, and the first try by the clock is two seconds away.
	assert!(output("ip", &["link", "del", INTERFACE]).0);
	let mut more = doc.clone();
	more["users"].as_array_mut().unwrap().push(json!({"name": "b", "exits": "all", "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&veilway_wg::generate_key())), "addresses": ["10.7.0.3"]}]}));
	engine.reload(more.to_string().into_bytes(), None).await.expect("a reload was refused because an exit it does not change is down");
	assert!(turns(false, Duration::from_secs(1)).await, "the reload did not have the exit try at once");
	assert_eq!((health().1, present(), engine.snapshot().generation), (2, (true, true, true), 2));
	a.send_ip(&ping(peer, 3)).await;
	a.expect(Duration::from_secs(5), |packet| echoed(packet, 3)).await.expect("no echo reply after the exit came back");
	// A reload that changes the interface while neither `ip` nor `nft` can be run: the old interface is closed, the new one cannot be set up, and the old one cannot be brought back. The exit of the running config is down, not gone.
	let path = std::env::var_os("PATH").unwrap();
	std::env::set_var("PATH", "/nonexistent");
	other["exits"][0]["backend"]["interface"] = json!("vwtest1");
	let failed = engine.reload(other.to_string().into_bytes(), None).await.err().expect("an interface came up without ip and nft").to_string();
	assert!(failed.contains("`node`"), "{failed}");
	assert_eq!((health(), engine.snapshot().generation, Path::new(&format!("/sys/class/net/{INTERFACE}")).exists(), Path::new("/sys/class/net/vwtest1").exists()), ((Some(true), 3), 2, false, false));
	std::env::set_var("PATH", path);
	// Nobody asks for it this time: the node's own first try, two seconds after the exit went down.
	assert!(turns(false, Duration::from_secs(4)).await, "the exit did not come back by itself");
	assert_eq!((health().1, present()), (4, (true, true, true)));
	a.send_ip(&ping(peer, 4)).await;
	a.expect(Duration::from_secs(5), |packet| echoed(packet, 4)).await.expect("no echo reply after the exit came back by itself");
	// A shutdown while the tries go on ends them: once the name is free again nothing comes up on it.
	blocked();
	assert!(turns(true, Duration::from_secs(2)).await, "the node did not notice that its interface was removed");
	engine.shutdown().await;
	assert!(output("ip", &["link", "del", INTERFACE]).0);
	tokio::time::sleep(Duration::from_millis(2500)).await;
	assert_eq!(present(), (false, false, false), "a try to bring the exit up outlived the shutdown");
}
