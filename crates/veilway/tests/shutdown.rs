//! `veilway run` under SIGTERM while hundreds of TCP flows are open in every state a flow can be stopped in. The binary is run the way a service manager runs it,
//! a WireGuard peer in this process opens the flows through its tunnel, and a fake SOCKS5 proxy on the loopback decides by the destination port what becomes of each.
#![cfg(unix)]
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, PacketHeaders, TcpHeader, TransportHeader};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

const DST: [u8; 4] = [93, 184, 216, 34];
/// The proxy never answers the CONNECT, so the node's dial is still out when it is stopped. The port after it, 7002, is connected and nobody says anything.
const STALLED: u16 = 7001;
/// Connected, and the proxy sends without end to a peer that acknowledges nothing, so the stack holds unacknowledged data.
const POURING: u16 = 7003;
/// Connected, the peer has sent its FIN and the proxy keeps its side open.
const HALF: u16 = 7004;
/// The peer never answers the stack's SYN/ACK.
const OPENING: u16 = 7005;
const STATES: usize = 5;
/// Flows of one peer, which is below the share one device has of the flow table.
const PER_PEER: usize = 400;
/// How long a node may take from SIGTERM to the end of its process.
const STOP: Duration = Duration::from_secs(5);

struct Peer {tunn: Tunn, sock: UdpSocket, address: [u8; 4]}

impl Peer {
	/// Tries until the node answers a handshake, because the node is another process that is still starting.
	async fn connect(private: [u8; 32], node: [u8; 32], listen: SocketAddr, address: [u8; 4]) -> Peer {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			assert!(Instant::now() < deadline, "the node never answered a handshake");
			let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
			sock.connect(listen).await.unwrap();
			let mut tunn = Tunn::new(StaticSecret::from(private), PublicKey::from(node), None, None, 0, None);
			let (mut scratch, mut datagram, mut out) = (vec![0u8; 2048], vec![0u8; 2048], vec![0u8; 2048]);
			let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut scratch, false) else {panic!("no handshake initiation")};
			let _ = sock.send(init).await;
			let Ok(Ok(n)) = timeout(Duration::from_millis(300), sock.recv(&mut datagram)).await else {continue};
			if let TunnResult::WriteToNetwork(keepalive) = tunn.decapsulate(None, &datagram[..n], &mut out) {
				let keepalive = keepalive.to_vec();
				sock.send(&keepalive).await.unwrap();
			}
			return Peer {tunn, sock, address};
		}
	}

	async fn send(&mut self, tcp: TcpHeader) {
		let builder = PacketBuilder::ipv4(self.address, DST, 64).tcp_header(tcp);
		let (mut packet, mut out) = (Vec::with_capacity(builder.size(0)), vec![0u8; 2048]);
		builder.write(&mut packet, &[]).unwrap();
		let TunnResult::WriteToNetwork(datagram) = self.tunn.encapsulate(&packet, &mut out) else {panic!("encapsulate produced nothing")};
		let datagram = datagram.to_vec();
		self.sock.send(&datagram).await.unwrap();
	}

	/// Reads what the node sends until nothing has come for `quiet`, and takes every flow that got its SYN/ACK to the state its port stands for.
	async fn answer(&mut self, quiet: Duration) {
		let mut datagram = vec![0u8; 2048];
		while let Ok(Ok(n)) = timeout(quiet, self.sock.recv(&mut datagram)).await {
			let mut input: &[u8] = &datagram[..n];
			loop {
				let mut out = vec![0u8; 2048];
				match self.tunn.decapsulate(None, input, &mut out) {
					TunnResult::WriteToNetwork(reply) => {
						let reply = reply.to_vec();
						let _ = self.sock.send(&reply).await;
						input = &[];
					}
					TunnResult::WriteToTunnelV4(packet, _) => {
						let Some(TransportHeader::Tcp(tcp)) = PacketHeaders::from_ip_slice(packet).ok().and_then(|parsed| parsed.transport) else {break};
						if !(tcp.syn && tcp.ack) || tcp.source_port == OPENING {break}
						let mut ack = TcpHeader::new(tcp.destination_port, tcp.source_port, 1001, 8192);
						(ack.ack, ack.acknowledgment_number) = (true, tcp.sequence_number.wrapping_add(1));
						self.send(ack.clone()).await;
						if tcp.source_port == HALF {
							ack.fin = true;
							self.send(ack).await;
						}
						break;
					}
					_ => break,
				}
			}
		}
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_hundreds_of_open_tcp_flows_stops_within_five_seconds() {
	let dir = std::env::temp_dir().join(format!("veilway-shutdown-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (proxy_addr, reached) = (proxy.local_addr().unwrap(), Arc::new([const {AtomicUsize::new(0)}; STATES]));
	tokio::spawn({
		let reached = reached.clone();
		async move {
			loop {
				let Ok((mut client, _)) = proxy.accept().await else {return};
				let reached = reached.clone();
				tokio::spawn(async move {
					let (mut hello, mut request, mut sink) = ([0u8; 2], [0u8; 10], [0u8; 1024]);
					if client.read_exact(&mut hello).await.is_err() || client.read_exact(&mut sink[..usize::from(hello[1])]).await.is_err() || client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut request).await.is_err() {return}
					let port = u16::from_be_bytes([request[8], request[9]]);
					let count = || reached[usize::from(port - STALLED)].fetch_add(1, Ordering::SeqCst);
					if port == STALLED {
						count();
						return std::future::pending().await;
					}
					if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {return}
					if port != HALF {count();}
					if port == POURING {while client.write_all(&sink).await.is_ok() {}}
					// The end of what the peer sends is its FIN, which the node passes on. The proxy keeps its own side open after it.
					while client.read(&mut sink).await.is_ok_and(|n| n > 0) {}
					if port == HALF {count();}
					std::future::pending().await
				});
			}
		}
	});
	let (private, keys) = (veilway_wg::generate_key(), [veilway_wg::generate_key(), veilway_wg::generate_key()]);
	let listen = SocketAddr::from(([127, 0, 0, 1], 23900 + (std::process::id() % 1000) as u16));
	let encoded = |key: &[u8; 32]| veilway_wg::encode_key(&veilway_wg::public_key(key));
	let (config, state, log) = (dir.join("config.json"), dir.join("state.json"), dir.join("node.log"));
	std::fs::write(&config, json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"], "hijack": false},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&private), "address": ["10.7.0.1/24"], "mtu": 1420, "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [{"tag": "proxy", "type": "socks5", "server": proxy_addr.to_string()}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "proxy"}}],
		"routing": {"default": "main", "rules": []},
		"users": [
			{"name": "a", "exits": "all", "devices": [{"name": "device", "public_key": encoded(&keys[0]), "addresses": ["10.7.0.2"]}]},
			{"name": "b", "exits": "all", "devices": [{"name": "device", "public_key": encoded(&keys[1]), "addresses": ["10.7.0.3"]}]}
		]
	}).to_string()).unwrap();
	std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
	let mut node = Command::new(env!("CARGO_BIN_EXE_veilway")).arg("run").arg("--config").arg(&config).arg("--state").arg(&state).arg("--no-api").stdin(Stdio::null()).stdout(std::fs::File::create(&log).unwrap()).stderr(std::fs::File::create(dir.join("node.err")).unwrap()).spawn().unwrap();
	let said = || format!("{}{}", std::fs::read_to_string(&log).unwrap_or_default(), std::fs::read_to_string(dir.join("node.err")).unwrap_or_default());
	for (key, address) in keys.iter().zip([[10, 7, 0, 2], [10, 7, 0, 3]]) {
		let mut peer = Peer::connect(*key, veilway_wg::public_key(&private), listen, address).await;
		for flow in 0..PER_PEER {
			let mut syn = TcpHeader::new(20000 + flow as u16, STALLED + (flow % STATES) as u16, 1000, 8192);
			syn.syn = true;
			peer.send(syn).await;
			if flow % 8 == 7 {peer.answer(Duration::from_millis(2)).await}
		}
		peer.answer(Duration::from_millis(500)).await;
	}
	// Nine in ten: a datagram the loopback drops under load costs one flow its state and the test nothing.
	let (want, deadline) = (2 * PER_PEER / STATES * 9 / 10, Instant::now() + Duration::from_secs(10));
	while reached.iter().any(|count| count.load(Ordering::SeqCst) < want) {
		assert!(Instant::now() < deadline, "the flows never got to their states, by state {reached:?}:\n{}", said());
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert!(node.try_wait().unwrap().is_none(), "the node ended before it was stopped:\n{}", said());
	assert!(Command::new("kill").arg("-TERM").arg(node.id().to_string()).status().unwrap().success());
	let stopping = Instant::now();
	let status = loop {
		if let Some(status) = node.try_wait().unwrap() {break status}
		if stopping.elapsed() > 4 * STOP {
			let _ = node.kill();
			let _ = node.wait();
			panic!("the node was still running {:?} after SIGTERM with {} flows open:\n{}", stopping.elapsed(), 2 * PER_PEER, said());
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	};
	let took = stopping.elapsed();
	println!("the node stopped {took:?} after SIGTERM with {} flows open, by state {reached:?}", 2 * PER_PEER);
	assert!(took < STOP, "the node took {took:?} to stop:\n{}", said());
	assert!(status.success(), "the node ended with {status}:\n{}", said());
	// The first write of the state file comes at start, before a packet was counted, so these counts are those of a later write.
	let written: Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
	for user in ["a", "b"] {assert!(written["users"][user]["up_packets"].as_u64().is_some_and(|packets| packets >= PER_PEER as u64), "the state file does not have what `{user}` sent: {written}")}
	std::fs::remove_dir_all(&dir).unwrap();
}
