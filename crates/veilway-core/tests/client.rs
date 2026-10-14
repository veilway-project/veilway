//! The client library (`veilway-transport`) against the node, end to end: a node that is started the way `veilway run` starts it, with one inbound that is reached over `udp-obfs`, `tls`, `ws` and `fronted`, and devices whose WireGuard is boringtun and whose transport is the library and nothing written here.
//! `ws` and `fronted` go the way a client's would: TLS to a front (an end of TLS written here, with the node's certificate), from there to the reverse proxy of `proxied` that stands for the operator's web server, and from there to the node.
//! These tests live in this crate because it is the one that will depend on both: the node gets the library for its links to other nodes, and the library does not depend on the node.
#[macro_use]
mod proxied;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{PacketBuilder, TcpHeader};
use proxied::*;
use rcgen::PublicKeyData;
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use veilway_core::Over;
use veilway_proto::proof;
use veilway_proto::subscription::payload::Padding;
use veilway_proto::subscription::Secret;
use veilway_transport::choice::{self, Network, Next, Standing};
use veilway_transport::{flow, Answer, End, Ended, Env, Front, Kind, Link, Refusal, Session, Source, State, Target, Unreachable, Want};

/// The path of the `tls` transport.
const TLS_PATH: &str = "/assets/app-3f9c2e71.js";
const PLAIN: Kind = Kind::Packet {flow: 0, control: false};

/// Writes a new self-signed certificate for `node.test` with its key into `dir`, for the node's `tls` transport, and gives what a client of it holds and what a front needs to end TLS with the same certificate: the roots, the pin (the SHA-256 of the SubjectPublicKeyInfo) and a server's config.
fn certify(dir: &Path) -> (Arc<RootCertStore>, [u8; 32], Arc<ServerConfig>) {
	let made = rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap();
	for (name, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
		std::fs::write(dir.join(name), pem).unwrap();
		#[cfg(unix)]
		std::fs::set_permissions(dir.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
	let (mut roots, der, provider) = (RootCertStore::empty(), CertificateDer::from(made.cert.der().to_vec()), Arc::new(rustls::crypto::ring::default_provider()));
	roots.add(der.clone()).unwrap();
	let config = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der], PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap()).unwrap();
	(Arc::new(roots), digest(&SHA256, &made.signing_key.subject_public_key_info()).as_ref().try_into().unwrap(), Arc::new(config))
}

/// What ends TLS in front of the operator's web server: every connection is handed on to `upstream` byte for byte. `seen` holds what each connection's client sent.
/// With `lose` set, the next bytes that come back from upstream are thrown away and the connection is closed: an answer that is lost on its way. With `twice` set, the next bytes of a client are sent upstream on a connection of the front's own first, as someone would who holds a request back and sends it first.
struct Edge {addr: SocketAddr, seen: Arc<Mutex<Vec<Vec<u8>>>>, lose: Arc<AtomicBool>, twice: Arc<AtomicBool>, task: JoinHandle<()>}

impl Drop for Edge {
	fn drop(&mut self) {self.task.abort()}
}

async fn edge(upstream: SocketAddr, config: Arc<ServerConfig>) -> Edge {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, seen, lose, twice) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
	let task = tokio::spawn({
		let (seen, lose, twice) = (seen.clone(), lose.clone(), twice.clone());
		async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else {return};
				let (acceptor, seen, lose, twice) = (TlsAcceptor::from(config.clone()), seen.clone(), lose.clone(), twice.clone());
				tokio::spawn(async move {
					let Ok(mut client) = acceptor.accept(stream).await else {return};
					let (mut up, mut sent, mut answered) = (dial(upstream, CLIENT).await, vec![0u8; 65536], vec![0u8; 65536]);
					let at = {
						let mut seen = seen.lock().unwrap();
						seen.push(Vec::new());
						seen.len() - 1
					};
					loop {
						tokio::select! {
							got = client.read(&mut sent) => match got {
								Ok(count) if count > 0 => {
									seen.lock().unwrap()[at].extend_from_slice(&sent[..count]);
									if twice.swap(false, Ordering::SeqCst) {
										let mut first = dial(upstream, CLIENT).await;
										first.write_all(&sent[..count]).await.unwrap();
										let _ = timeout(SECOND, first.read(&mut answered)).await;
									}
									if up.write_all(&sent[..count]).await.is_err() {return}
								}
								_ => return drop(up.shutdown().await),
							},
							got = up.read(&mut answered) => match got {
								Ok(count) if count > 0 => {
									if lose.swap(false, Ordering::SeqCst) || client.write_all(&answered[..count]).await.is_err() || client.flush().await.is_err() {return}
								}
								_ => return drop(client.shutdown().await),
							},
						}
					}
				});
			}
		}
	});
	Edge {addr, seen, lose, twice, task}
}

/// A node with all four transports and what a client needs to reach each: the addresses of `udp-obfs` and `tls`, the front of `ws` and `fronted`, the roots and the pin.
struct Net {node: Node, obfs: SocketAddr, tls: SocketAddr, edge: Edge, roots: Arc<RootCertStore>, pin: [u8; 32], time: Time}

async fn net(test: &'static str, time: Time, change: impl FnOnce(&mut Value)) -> Net {
	let (obfs, tls, made) = (listen(), listen(), Mutex::new(None));
	let node = launch(test, time, |doc| {
		*made.lock().unwrap() = Some(certify(&folder(test)));
		let transports = doc["inbounds"][0]["transports"].as_array_mut().unwrap();
		let origin = transports[0]["decoy"].clone();
		transports.push(json!({"type": "udp-obfs", "listen": obfs.to_string()}));
		transports.push(json!({"type": "tls", "listen": tls.to_string(), "path": TLS_PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": origin}));
		change(doc);
	}).await;
	let (roots, pin, config) = made.into_inner().unwrap().unwrap();
	let edge = edge(node.front.addr, config).await;
	Net {node, obfs, tls, edge, roots, pin, time}
}

/// What device `n` holds for the inbound.
fn link(n: usize) -> Link {Link {inbound: public(&NODE), device: public(&KEYS[n]), secret: Secret::new(secret(n)), node: Some(proof::public_key(&TRANSPORT)), mtu: 1390, padding: Padding {wide_max: 1023, normal_max: 255, keepalive: 20_000..=40_000}}}

impl Net {
	fn front(&self, address: SocketAddr, pinned: bool) -> Front {Front {address, sni: Some("node.test".into()), host: "node.test".into(), verify_name: None, pins: if pinned {vec![self.pin]} else {Vec::new()}, ech: false, self_signed: false}}

	/// The target of a transport by its name. `ws` is pinned here, as a client's is that reaches the operator's own web server.
	fn target(&self, kind: &str) -> Target {
		match kind {
			"udp-obfs" => Target::UdpObfs(self.obfs),
			"tls" => Target::Tls {path: TLS_PATH.into(), candidate: self.front(self.tls, true)},
			"ws" => Target::Ws {path: WS_PATH.into(), candidate: self.front(self.edge.addr, true)},
			_ => Target::Fronted {path: POLL_PATH.into(), candidate: self.front(self.edge.addr, false)},
		}
	}

	fn env(&self) -> Env {
		let time = self.time;
		Env {device: Arc::new(move || time.secs()), now: Arc::new(move || time.secs()), roots: self.roots.clone(), socket: None}
	}

	/// Device `n` with a WireGuard of its own, on a session to `target` that has just been asked for.
	fn peer(&self, n: usize, link: &Link, target: Target) -> Peer {peer(n, link, target, 1, self.env(), wireguard(n))}
}

/// Device `n` on a session to `target` over so many connections, with the clock and the WireGuard it is given.
fn peer(n: usize, link: &Link, target: Target, connections: u8, env: Env, (tunn, up, source): (Arc<Mutex<Tunn>>, Arc<AtomicBool>, Source)) -> Peer {Peer {n, tunn, up, session: Session::parallel(link, target, connections, env, source).unwrap(), inbox: VecDeque::new()}}

/// The WireGuard layer of device `n` as the library asks for it: a handshake initiation while the tunnel has no session, a keepalive once it has, which `up` says.
fn wireguard(n: usize) -> (Arc<Mutex<Tunn>>, Arc<AtomicBool>, Source) {
	let (tunn, up) = (Arc::new(Mutex::new(Tunn::new(StaticSecret::from(KEYS[n]), PublicKey::from(public(&NODE)), None, None, 0, None))), Arc::new(AtomicBool::new(false)));
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
	(tunn, up, source)
}

/// A device: its WireGuard, and the one session of the library its datagrams travel on.
struct Peer {n: usize, tunn: Arc<Mutex<Tunn>>, up: Arc<AtomicBool>, session: Session, inbox: VecDeque<Vec<u8>>}

impl Peer {
	/// Hands one WireGuard datagram of the node to the device's WireGuard, sends what that wants sent, and gives the IP packets that came out.
	fn take(&mut self, datagram: &[u8]) -> Vec<Vec<u8>> {
		let (mut input, mut packets) = (datagram, Vec::new());
		loop {
			let mut out = vec![0u8; 2048];
			let (reply, packet) = match self.tunn.lock().unwrap().decapsulate(None, input, &mut out) {
				TunnResult::WriteToNetwork(reply) => (Some(reply.to_vec()), None),
				TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => (None, Some(packet.to_vec())),
				_ => (None, None),
			};
			packets.extend(packet);
			let Some(reply) = reply else {return packets};
			// The node's handshake response: the tunnel has a session from here on.
			if datagram.first() == Some(&2) {self.up.store(true, Ordering::SeqCst)}
			self.session.send(reply, PLAIN);
			input = &[];
		}
	}

	/// Waits until the session is established and the tunnel has a session, or gives how the session ended.
	async fn connect(&mut self) -> Result<(), Ended> {
		let (deadline, mut watch) = (tokio::time::Instant::now() + Duration::from_secs(20), self.session.watch());
		loop {
			match self.session.state() {
				State::Established if self.up.load(Ordering::SeqCst) => return Ok(()),
				State::Ended(ended) => return Err(ended),
				_ => {}
			}
			tokio::select! {
				_ = watch.changed() => {}
				got = self.session.recv() => match got {
					Ok(datagram) => {
						let packets = self.take(&datagram);
						self.inbox.extend(packets);
					}
					Err(ended) => return Err(ended),
				},
				_ = tokio::time::sleep_until(deadline) => panic!("neither a session nor its end in 20 s"),
			}
		}
	}

	/// How the session ends, for one that is not expected to open.
	async fn ended(&mut self) -> Ended {self.connect().await.expect_err("a session that should not have opened")}

	/// How a session that was open ends within `budget`, whatever it still carries until then. None when it does not end.
	async fn over(&mut self, budget: Duration) -> Option<Ended> {
		timeout(budget, async {
			loop {
				if let Err(ended) = self.session.recv().await {return ended}
			}
		}).await.ok()
	}

	/// One IP packet into the tunnel, marked with its flow.
	fn send(&mut self, packet: &[u8]) {
		let mut out = vec![0u8; packet.len() + 2048];
		let TunnResult::WriteToNetwork(datagram) = self.tunn.lock().unwrap().encapsulate(packet, &mut out) else {panic!("the tunnel has no session to send under")};
		self.session.send(datagram.to_vec(), Kind::Packet {flow: flow(packet), control: false});
	}

	/// The next IP packet `wanted` picks, from the inbox or from the tunnel. Every other packet stays in the inbox.
	async fn recv(&mut self, budget: Duration, wanted: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
		if let Some(at) = self.inbox.iter().position(|packet| wanted(packet)) {return self.inbox.remove(at)}
		let deadline = Instant::now() + budget;
		loop {
			let datagram = timeout(deadline.checked_duration_since(Instant::now())?, self.session.recv()).await.ok()?.ok()?;
			let mut found = None;
			for packet in self.take(&datagram) {
				if found.is_none() && wanted(&packet) {found = Some(packet)} else {self.inbox.push_back(packet)}
			}
			if found.is_some() {return found}
		}
	}

	/// Opens a TCP connection to `PUBLIC` from the device's tunnel address and reads what the exit's proxy says first. None when the SYN gets no answer.
	async fn leaves(&mut self, sport: u16) -> Option<String> {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), Vec::new());
		syn.syn = true;
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
		self.send(&out);
		let (answer, _) = segment(&self.recv(4 * SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| (tcp.source_port, tcp.destination_port) == (80, sport))).await?)?;
		if !(answer.syn && answer.ack) {return None}
		let (mut ack, mut out) = (TcpHeader::new(sport, 80, 1001, 65535), Vec::new());
		(ack.ack, ack.acknowledgment_number) = (true, answer.sequence_number.wrapping_add(1));
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(ack).write(&mut out, &[]).unwrap();
		self.send(&out);
		let (_, said) = segment(&self.recv(Duration::from_secs(6), |packet| segment(packet).is_some_and(|(tcp, data)| (tcp.source_port, tcp.destination_port) == (80, sport) && !data.is_empty())).await?)?;
		let (mut rst, mut out) = (TcpHeader::new(sport, 80, 1001, 0), Vec::new());
		rst.rst = true;
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).tcp_header(rst).write(&mut out, &[]).unwrap();
		self.send(&out);
		Some(String::from_utf8(said).unwrap())
	}

	/// An echo request of `size` bytes as an IP packet, and whether the reply of the same size came back.
	async fn ping(&mut self, size: usize, seq: u16) -> bool {
		let mut out = Vec::new();
		PacketBuilder::ipv4(address(self.n), PUBLIC, 64).icmpv4_echo_request(9, seq).write(&mut out, &vec![0x5a; size - 28]).unwrap();
		assert_eq!(out.len(), size);
		self.send(&out);
		self.recv(3 * SECOND, |packet| packet.len() == size && packet[9] == 1 && packet[20] == 0 && packet[26..28] == seq.to_be_bytes()).await.is_some()
	}
}

const REFUSED: Answer = Answer::Status(404);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_its_tunnel_over_each_of_the_four_transports() {
	let time = time!();
	let net = net("client-four", time, |_| {}).await;
	for (n, (kind, over, user)) in [("udp-obfs", Over::UdpObfs, "a"), ("tls", Over::Tls, "b"), ("ws", Over::WsNative, "c"), ("fronted", Over::Fronted, "d")].into_iter().enumerate() {
		let mut peer = net.peer(n, &link(n), net.target(kind));
		assert_eq!((peer.session.state(), peer.session.numbers().datagram), (State::Opening, 1422));
		peer.connect().await.unwrap_or_else(|ended| panic!("{kind}: {ended:?}"));
		// A real WireGuard handshake went through the session, and traffic passes both ways: a TCP connection through the exit, and an echo the node answers.
		assert_eq!(peer.leaves(40000 + n as u16).await.as_deref(), Some("main"), "{kind}");
		assert!(peer.ping(200, 1).await, "{kind}");
		let (peers, numbers) = (net.node.engine.peers(Some(user)), peer.session.numbers());
		assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(over), true), "{kind}");
		assert!(numbers.sent >= 5 && numbers.received >= 4 && numbers.dropped == 0 && numbers.heard.is_some(), "{kind}: {numbers:?}");
		assert_eq!(peer.session.close().await, Ended::Closed(End::Asked), "{kind}");
	}
	// The two WebSocket sessions were closed with a Close frame the node answered. The `fronted` one has nothing to say at its end and goes by its idle time.
	eventually("the sessions did not end", || net.node.totals().sessions == 1 && net.node.totals().ended_closed == 2).await;
	assert_eq!((net.node.totals().proofs_accepted, net.node.totals().established, net.node.engine.obfs().established), (3, 3, 1));
	net.node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_node_refuses_is_a_refusal_on_a_stream_and_silence_on_udp_obfs() {
	let time = time!();
	let mut net = net("client-refused", time, |_| {}).await;
	// A secret no device has, on every transport at once. A stream answers with the origin's own miss, over TLS that validated, and that is a refusal whose `Date` is read where the candidate is pinned and nowhere else. `udp-obfs` answers nothing, and four opening packets and ten seconds later that is silence.
	let stranger = Link {secret: Secret::new([0x77; 32]), ..link(0)};
	let mut tried: Vec<Peer> = ["udp-obfs", "tls", "ws", "fronted"].into_iter().map(|kind| net.peer(0, &stranger, net.target(kind))).collect();
	tried.push(net.peer(0, &stranger, Target::Ws {path: WS_PATH.into(), candidate: net.front(net.edge.addr, false)}));
	let started = Instant::now();
	for (at, pinned) in [(1, true), (2, true), (3, false), (4, false)] {
		let Ended::Refused(Refusal {answer, offset}) = tried[at].ended().await else {panic!("transport {at} was not refused")};
		assert_eq!((answer, offset.is_some()), (REFUSED, pinned), "transport {at}");
		assert!(offset.is_none_or(|offset| offset.abs() <= 2), "an offset of {offset:?} between two clocks that are one");
	}
	assert_eq!(tried[0].ended().await, Ended::Unreachable(Unreachable::Silence));
	assert!((9..=12).contains(&started.elapsed().as_secs()), "silence after {:?}", started.elapsed());
	// The right secret on a path the node does not serve, and the proof of one transport on another.
	assert!(matches!(net.peer(0, &link(0), Target::Tls {path: "/assets/app-00000000.js".into(), candidate: net.front(net.tls, true)}).ended().await, Ended::Refused(Refusal {answer: REFUSED, offset: Some(_)})));
	assert!(matches!(net.peer(0, &link(0), Target::Ws {path: TLS_PATH.into(), candidate: net.front(net.tls, true)}).ended().await, Ended::Refused(Refusal {answer: REFUSED, ..})));
	// Another device's secret under this device's WireGuard key: the binder does not hold.
	assert!(matches!(net.peer(0, &Link {secret: Secret::new(secret(1)), ..link(0)}, net.target("ws")).ended().await, Ended::Refused(Refusal {answer: REFUSED, ..})));
	assert_eq!((net.node.totals().proofs_accepted, net.node.totals().sessions, net.node.totals().pending, net.node.engine.obfs().pending), (0, 0, 0, 0));
	// A device that is removed loses the session it has, closed by the node as every session is closed, and gets no new one on any transport.
	let (mut on_tls, mut on_fronted) = (net.peer(2, &link(2), net.target("tls")), net.peer(3, &link(3), net.target("fronted")));
	on_tls.connect().await.unwrap();
	on_fronted.connect().await.unwrap();
	net.node.reload(|doc| {
		doc["users"].as_array_mut().unwrap().remove(3);
		doc["users"].as_array_mut().unwrap().remove(2);
	}).await;
	assert_eq!(on_tls.over(3 * SECOND).await, Some(Ended::Closed(End::Peer)));
	// On `fronted` the next request is the origin's: the node no longer knows the session.
	assert_eq!(on_fronted.over(8 * SECOND).await, Some(Ended::Closed(End::Lost)));
	for kind in ["tls", "ws", "fronted"] {assert!(matches!(net.peer(2, &link(2), net.target(kind)).ended().await, Ended::Refused(Refusal {answer: REFUSED, ..})), "{kind}")}
	net.node.engine.shutdown().await;
}

// "On `tls` or `ws`, and only after the certificate matched a pin from the profile, the client may read the `Date` header of the decoy's answer and use the difference as an offset for proof timestamps and for the epoch number of `udp-obfs`."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_clock_is_refused_and_the_offset_of_a_pinned_refusal_sets_it_right() {
	let time = time!();
	let net = net("client-clock", time, |_| {}).await;
	// The device's clock is a quarter of an hour behind. What the caller keeps of the profile is the `Standing`, and the clock it gives the library is `choice::clock` over it.
	let (standing, mut network) = (Arc::new(Mutex::new(Standing::default())), Network::default());
	let env = Env {device: Arc::new(move || time.secs() - 900), now: Arc::new({
		let standing = standing.clone();
		move || choice::clock(time.secs() - 900, &standing.lock().unwrap())
	}), roots: net.roots.clone(), socket: None};
	// Through a front without a pin the refusal carries no offset, and the clock stays wrong.
	let ended = peer(0, &link(0), net.target("fronted"), 1, env.clone(), wireguard(0)).ended().await;
	assert_eq!(ended, Ended::Refused(Refusal {answer: REFUSED, offset: None}));
	assert!(matches!(choice::outcome(&mut network, &mut standing.lock().unwrap(), 0, 2, 0, Some(ended), time.secs() - 900, &mut random), Ok(Next::Again(wait)) if (60..=120).contains(&wait.as_secs())));
	assert_eq!(standing.lock().unwrap().offset, None);
	// On the pinned `tls` candidate it does: the difference between the answer's `Date` and the device's clock at the moment the answer was read, which becomes the offset.
	let ended = peer(0, &link(0), net.target("tls"), 1, env.clone(), wireguard(0)).ended().await;
	assert!(matches!(ended, Ended::Refused(Refusal {answer: REFUSED, offset: Some(offset)}) if (898..=902).contains(&offset)), "{ended:?}");
	choice::outcome(&mut network, &mut standing.lock().unwrap(), 0, 0, 0, Some(ended), time.secs() - 900, &mut random).unwrap();
	let offset = standing.lock().unwrap().offset.expect("no offset from a pinned refusal").0;
	assert!((898..=902).contains(&offset), "an offset of {offset}");
	assert_eq!((net.node.totals().refused_window, net.node.totals().proofs_accepted), (2, 0));
	// "It then uses that offset for every transport of the profile": the stream proof and the epoch tag of `udp-obfs` are both right now.
	for (n, kind) in ["tls", "fronted", "udp-obfs"].into_iter().enumerate() {
		let mut device = peer(n, &link(n), net.target(kind), 1, env.clone(), wireguard(n));
		device.connect().await.unwrap_or_else(|ended| panic!("{kind} with the offset: {ended:?}"));
		assert_eq!(device.leaves(42000 + n as u16).await.as_deref(), Some("main"), "{kind}");
		device.session.close().await;
	}
	assert_eq!(choice::outcome(&mut network, &mut standing.lock().unwrap(), 0, 0, 0, None, time.secs() - 900, &mut random), Ok(Next::Rest));
	assert_eq!((standing.lock().unwrap().refusals, network.worked.map(|worked| (worked.0, worked.1))), (0, Some((0, 0))));
	net.node.engine.shutdown().await;
}

// "Held back, or copied, and sent first: the node answers 101 and holds a pending session for the sender. The client's own request then arrives as a replay and gets the decoy's answer."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_that_reached_the_node_before_its_client_is_a_refusal_for_the_client() {
	let time = time!();
	let net = net("client-replayed", time, |_| {}).await;
	for kind in ["ws", "fronted"] {
		net.edge.twice.store(true, Ordering::SeqCst);
		assert!(matches!(net.peer(0, &link(0), net.target(kind)).ended().await, Ended::Refused(Refusal {answer: REFUSED, ..})), "{kind}");
	}
	eventually("the replays were not refused as seen", || net.node.totals().refused_seen == 2).await;
	// The next attempt has a proof of its own and is taken.
	let mut peer = net.peer(0, &link(0), net.target("ws"));
	peer.connect().await.unwrap();
	peer.session.close().await;
	net.node.engine.shutdown().await;
}

// "Accepted proofs per device: burst 16, then 1 a second."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_spent_its_proofs_is_refused_until_they_come_back() {
	let time = time!();
	let net = net("client-rate", time, |_| {}).await;
	let (wireguard, started, mut open, mut refused) = (wireguard(0), Instant::now(), Vec::new(), None);
	// One tunnel, and session after session for it: the first carries the handshake and every later one a keepalive of the tunnel that is up. The device's ninth session takes the place of its oldest, so sessions are no limit here, and proofs are.
	for at in 0..24 {
		let mut device = peer(0, &link(0), net.target("ws"), 1, net.env(), wireguard.clone());
		match device.connect().await {
			Ok(()) => open.push(device),
			Err(ended) => {
				refused = Some((at, ended));
				break;
			}
		}
	}
	let (at, ended) = refused.expect("24 proofs of one device were accepted in a row");
	assert!(matches!(ended, Ended::Refused(Refusal {answer: REFUSED, ..})), "{ended:?}");
	assert!((16..=16 + started.elapsed().as_secs() as usize + 1).contains(&at), "refused at the proof {at} after {:?}", started.elapsed());
	assert!(net.node.totals().refused_device_rate >= 1);
	// A refusal marks nothing: a second and a half later the same candidate takes the device again.
	tokio::time::sleep(Duration::from_millis(1500)).await;
	peer(0, &link(0), net.target("ws"), 1, net.env(), wireguard.clone()).connect().await.unwrap();
	net.node.engine.shutdown().await;
}

// "Start after anything else (a crash, a kill): clients with a correct clock are refused until the clock passes the floor."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_was_killed_refuses_until_its_clock_passes_its_floor() {
	let time = time!();
	let net = net("client-restart", time, |_| {}).await;
	let (mut doc, dir, obfs, tls) = (net.node.doc.clone(), net.node.dir.clone(), listen(), listen());
	let mut before = net.peer(0, &link(0), net.target("tls"));
	before.connect().await.unwrap();
	// The node is killed, and the one that starts on its files finds a limit that a client with a fast clock left 25 s ahead. An engine that has stopped still holds its listeners, so the new one listens elsewhere.
	drop(before);
	let Net {node, roots, pin, ..} = net;
	node.engine.shutdown().await;
	seed(&dir.join("replay"), time.secs() + 25, time.secs() + 25);
	let behind = listen();
	for (transport, addr) in doc["inbounds"][0]["transports"].as_array_mut().unwrap().iter_mut().zip([behind, behind, obfs, tls]) {transport["listen"] = json!(addr.to_string())}
	let again = start(&doc, &dir, time).await.unwrap();
	let (env, on_tls) = (Env {device: Arc::new(move || time.secs()), now: Arc::new(move || time.secs()), roots, socket: None}, Target::Tls {path: TLS_PATH.into(), candidate: Front {address: tls, sni: Some("node.test".into()), host: "node.test".into(), verify_name: None, pins: vec![pin], ech: false, self_signed: false}});
	// A refusal on the stream, with the date of a clock that is right, and silence on `udp-obfs`: neither marks anything.
	let (mut refused, mut silent) = (peer(0, &link(0), on_tls.clone(), 1, env.clone(), wireguard(0)), peer(1, &link(1), Target::UdpObfs(obfs), 1, env.clone(), wireguard(1)));
	let ended = refused.ended().await;
	assert!(matches!(ended, Ended::Refused(Refusal {answer: REFUSED, offset: Some(offset)}) if offset.abs() <= 2), "{ended:?}");
	assert_eq!(silent.ended().await, Ended::Unreachable(Unreachable::Silence));
	assert!(again.stream().refused_floor >= 1 && again.stream().proofs_accepted == 0);
	// Half a minute on the same candidates work, with nothing changed on the client.
	time.ahead.fetch_add(30, Ordering::SeqCst);
	eventually("the replay limit did not follow the clock", || again.replay().is_some_and(|replay| replay.limit >= time.secs())).await;
	for (n, target) in [(0, on_tls), (1, Target::UdpObfs(obfs))] {
		let mut device = peer(n, &link(n), target, 1, env.clone(), wireguard(n));
		device.connect().await.unwrap();
		assert_eq!(device.leaves(43000 + n as u16).await.as_deref(), Some("main"));
	}
	again.shutdown().await;
	drop(node.site);
}

// "A proof that was accepted and is followed by silence for 10 s, on a session the client opened with a keepalive, is neither: the client tries the same candidate once more, at once, with a handshake initiation." A node that restarted is where that comes from: every client's tunnel is up on the client's side, and the node knows none of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_that_restarted_takes_the_proof_and_not_the_keepalive_and_nothing_is_marked() {
	let time = time!();
	let net = net("client-forgot", time, |_| {}).await;
	let (mut doc, dir, tls, (tunn, up, source)) = (net.node.doc.clone(), net.node.dir.clone(), listen(), wireguard(0));
	let mut before = peer(0, &link(0), net.target("tls"), 1, net.env(), (tunn.clone(), up.clone(), source.clone()));
	before.connect().await.unwrap();
	assert_eq!(before.leaves(48000).await.as_deref(), Some("main"));
	drop(before);
	// A clean stop and a start on the same files: the replay memory is as it was, and the tunnels are gone. The engine that stopped still holds its listeners, so the new one listens elsewhere.
	let Net {node, roots, pin, ..} = net;
	node.engine.shutdown().await;
	let behind = listen();
	for (transport, addr) in doc["inbounds"][0]["transports"].as_array_mut().unwrap().iter_mut().zip([behind, behind, listen(), tls]) {transport["listen"] = json!(addr.to_string())}
	let again = start(&doc, &dir, time).await.unwrap();
	let (env, on_tls) = (Env {device: Arc::new(move || time.secs()), now: Arc::new(move || time.secs()), roots, socket: None}, Target::Tls {path: TLS_PATH.into(), candidate: Front {address: tls, sni: Some("node.test".into()), host: "node.test".into(), verify_name: None, pins: vec![pin], ech: false, self_signed: false}});
	// The device's tunnel is up as far as the device knows, so its session opens with a keepalive. The node takes the proof, cannot place the keepalive, and says nothing until its own 10 s are over.
	let (started, mut forgotten) = (Instant::now(), peer(0, &link(0), on_tls.clone(), 1, env.clone(), (tunn.clone(), up.clone(), source.clone())));
	let ended = forgotten.ended().await;
	assert_eq!(ended, Ended::Closed(End::Unanswered), "after {:?}", started.elapsed());
	assert!((9..=12).contains(&started.elapsed().as_secs()) && again.stream().proofs_accepted == 1, "{:?}, {:?}", started.elapsed(), again.stream());
	// Nothing is marked and no budget is spent: the same candidate is tried again at once, and the WireGuard layer opens with a handshake initiation this time.
	let (mut network, mut standing) = (Network::default(), Standing::default());
	assert_eq!(choice::outcome(&mut network, &mut standing, 0, 0, 0, Some(ended), time.secs(), &mut random), Ok(Next::Again(Duration::ZERO)));
	assert!(network.aside.is_empty() && network.tried.is_empty());
	up.store(false, Ordering::SeqCst);
	let mut after = peer(0, &link(0), on_tls, 1, env, (tunn, up, source));
	after.connect().await.unwrap();
	assert_eq!(after.leaves(48001).await.as_deref(), Some("main"));
	assert_eq!(choice::outcome(&mut network, &mut standing, 0, 0, 0, None, time.secs(), &mut random), Ok(Next::Rest));
	again.shutdown().await;
	drop(node.site);
}

// "When it has sent nothing for the idle keepalive time, it asks the WireGuard layer for one keepalive datagram and sends it in a chunk. The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_session_sends_its_keepalive_and_hears_the_echo() {
	let time = time!();
	let net = net("client-idle", time, |_| {}).await;
	// The shortest range a profile may set: 10 s.
	let quick = |n: usize| Link {padding: Padding {wide_max: 1023, normal_max: 255, keepalive: 10_000..=10_000}, ..link(n)};
	let mut peers: Vec<Peer> = ["udp-obfs", "tls", "ws"].into_iter().enumerate().map(|(n, kind)| net.peer(n, &quick(n), net.target(kind))).collect();
	for peer in &mut peers {peer.connect().await.unwrap()}
	// The keepalive that confirmed the handshake has gone out by now, with its echo. From here the device sends nothing of its own.
	tokio::time::sleep(4 * SECOND).await;
	let before: Vec<_> = peers.iter().map(|peer| peer.session.numbers()).collect();
	tokio::time::sleep(17 * SECOND).await;
	for (peer, before) in peers.iter_mut().zip(before) {
		// Whatever the tunnel itself sent in that time goes to its WireGuard.
		while let Ok(Ok(datagram)) = timeout(Duration::from_millis(50), peer.session.recv()).await {peer.take(&datagram);}
		let now = peer.session.numbers();
		assert!(peer.session.state() == State::Established && now.heard.zip(before.heard).is_some_and(|(now, before)| now >= before + Duration::from_secs(6)), "{} heard nothing of an echo: {before:?} {now:?}", peer.n);
		assert_eq!(peer.leaves(44000 + peer.n as u16).await.as_deref(), Some("main"));
	}
	net.node.engine.shutdown().await;
}

// "Keeps one request in flight per session at a time", in order, and when an answer is lost "the identical bytes" are sent again and the node "answers a repeat from the stored response".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fronted_requests_come_in_order_and_a_lost_answer_is_asked_for_again_with_the_same_bytes() {
	let time = time!();
	let net = net("client-polled", time, |_| {}).await;
	let mut peer = net.peer(0, &link(0), net.target("fronted"));
	peer.connect().await.unwrap();
	assert_eq!(peer.leaves(45000).await.as_deref(), Some("main"));
	// The answer to the next request is lost on its way, with its connection.
	net.edge.lose.store(true, Ordering::SeqCst);
	eventually("no answer was lost", || !net.edge.lose.load(Ordering::SeqCst)).await;
	assert_eq!(peer.leaves(45001).await.as_deref(), Some("main"));
	assert_eq!(peer.session.state(), State::Established);
	tokio::time::sleep(SECOND).await;
	// What the front saw: the opening request with the proof, then the requests of the session numbered from 1 with none left out, and one of them twice, byte for byte, on two connections.
	let seen = net.edge.seen.lock().unwrap().clone();
	let (mut numbers, mut requests) = (Vec::new(), Vec::new());
	for sent in &seen {
		let mut rest = &sent[..];
		while let Some(end) = rest.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {
			let head = String::from_utf8_lossy(&rest[..end]).into_owned();
			let length = head.split("\r\n").find_map(|line| line.strip_prefix("Content-Length: ").and_then(|length| length.parse::<usize>().ok())).expect("a request without a length");
			assert_eq!((head.matches("Content-Length").count(), head.contains("Transfer-Encoding"), head.starts_with(&format!("POST {POLL_PATH}?"))), (1, false, true), "{head}");
			let query = head.split(' ').nth(1).unwrap().split_once('?').unwrap().1.to_string();
			if let Some((_, number)) = query.split_once('.') {numbers.push(number.parse::<u32>().unwrap())}
			requests.push(rest[..end + length].to_vec());
			rest = &rest[end + length..];
		}
		assert!(rest.is_empty(), "a request that was not whole");
	}
	let repeated: Vec<u32> = numbers.windows(2).filter(|pair| pair[0] == pair[1]).map(|pair| pair[0]).collect();
	assert_eq!(repeated.len(), 1, "{numbers:?}");
	numbers.dedup();
	assert_eq!(numbers, (1..=numbers.len() as u32).collect::<Vec<_>>());
	assert!(requests.len() == numbers.len() + 2 && requests[repeated[0] as usize] == requests[repeated[0] as usize + 1]);
	assert_eq!((net.node.totals().fronted, net.node.totals().proofs_accepted), (1, 1));
	// "At least one poll a minute", and far more often: an idle session polls at most every 6.25 s.
	let polled = numbers.len();
	tokio::time::sleep(7 * SECOND).await;
	assert!(net.edge.seen.lock().unwrap().iter().map(|sent| sent.windows(5).filter(|window| window == b"POST ").count()).sum::<usize>() > polled + 2);
	peer.session.close().await;
	net.node.engine.shutdown().await;
}

// "A profile may allow up to 4. Each connection is its own session with its own proof and keys, for the same device", opened "one at a time, each after a delay drawn uniformly from 1 to 5 s".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_connections_carry_one_tunnel() {
	let time = time!();
	let net = net("client-parallel", time, |_| {}).await;
	let (started, mut peer) = (Instant::now(), peer(0, &link(0), net.target("tls"), 3, net.env(), wireguard(0)));
	peer.connect().await.unwrap();
	assert_eq!((net.node.totals().sessions, peer.leaves(46000).await.as_deref()), (1, Some("main")));
	// The tunnel's own packets while the others open: each of them opens with a keepalive of the tunnel that is up.
	while net.node.totals().sessions < 3 {
		assert!(started.elapsed() < Duration::from_secs(14), "{} connections after 14 s", net.node.totals().sessions);
		peer.recv(Duration::from_millis(100), |_| false).await;
	}
	assert!(started.elapsed() >= 2 * SECOND && net.node.totals().proofs_accepted == 3 && net.node.engine.peers(Some("a")).len() == 1);
	// Many flows, each on the connection its hash picks, and the answers from whichever connection the node last heard the device on.
	for sport in 46100..46112 {assert_eq!(peer.leaves(sport).await.as_deref(), Some("main"), "the flow from port {sport}")}
	assert_eq!(peer.session.numbers().dropped, 0);
	// Closing closes every connection, each with its Close frame.
	assert_eq!(peer.session.close().await, Ended::Closed(End::Asked));
	eventually("the connections were not closed", || net.node.totals().sessions == 0 && net.node.totals().ended_closed == 3).await;
	net.node.engine.shutdown().await;
}

// "The client takes its MTU from the signed profile", and "on `udp-obfs` no packet is larger than `mtu` + 62 bytes".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_packet_of_the_mtu_passes_and_a_larger_one_is_dropped_and_counted() {
	let time = time!();
	let net = net("client-sizes", time, |_| {}).await;
	for (n, kind) in ["udp-obfs", "tls", "fronted"].into_iter().enumerate() {
		let mut peer = net.peer(n, &link(n), net.target(kind));
		peer.connect().await.unwrap();
		for (seq, size) in [28, 29, 100, 1389, 1390].into_iter().enumerate() {assert!(peer.ping(size, seq as u16).await, "{kind}: a packet of {size} bytes")}
		let dropped = peer.session.numbers().dropped;
		// One byte above the `mtu`: the datagram is over what the session carries, and it is not cut and not sent.
		let mut out = Vec::new();
		PacketBuilder::ipv4(address(n), PUBLIC, 64).icmpv4_echo_request(9, 99).write(&mut out, &vec![0x5a; 1391 - 28]).unwrap();
		peer.send(&out);
		assert!(peer.recv(SECOND, |packet| packet.len() == 1391).await.is_none(), "{kind}");
		assert_eq!((peer.session.numbers().dropped, peer.session.state()), (dropped + 1, State::Established), "{kind}");
		peer.session.close().await;
	}
	net.node.engine.shutdown().await;
}

// "When its network interface or address changes" the client sends an opening packet, "with a keepalive. No new WireGuard handshake is needed."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_obfs_moves_to_a_new_socket_without_a_new_handshake() {
	let time = time!();
	let net = net("client-moved", time, |_| {}).await;
	let mut peer = net.peer(0, &link(0), net.target("udp-obfs"));
	peer.connect().await.unwrap();
	assert_eq!(peer.leaves(47000).await.as_deref(), Some("main"));
	let (handshakes, opened) = (net.node.engine.peers(Some("a"))[0].handshake, net.node.engine.obfs().established);
	peer.session.moved();
	eventually("the session of the new socket was not established", || net.node.engine.obfs().established == opened + 1).await;
	assert_eq!(peer.leaves(47001).await.as_deref(), Some("main"));
	// The tunnel's session is the one it had: its age went on, where a new handshake would have set it back.
	assert!(net.node.engine.peers(Some("a"))[0].handshake >= handshakes && peer.session.state() == State::Established);
	peer.session.close().await;
	net.node.engine.shutdown().await;
}

// A client that takes any certificate and keeps it: what the tests look at a listener's certificate with. No client of the library is ever this.
#[derive(Debug)]
struct Seen(Mutex<Vec<u8>>);

impl ServerCertVerifier for Seen {
	fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
		*self.0.lock().unwrap() = end_entity.to_vec();
		Ok(ServerCertVerified::assertion())
	}
	fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {Ok(HandshakeSignatureValid::assertion())}
	fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {Ok(HandshakeSignatureValid::assertion())}
	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()}
}

/// The certificate a TLS listener answers a new connection with.
async fn shown(addr: SocketAddr) -> Vec<u8> {
	let seen = Arc::new(Seen(Mutex::new(Vec::new())));
	let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().dangerous().with_custom_certificate_verifier(seen.clone()).with_no_client_auth();
	let _ = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(ServerName::try_from("node.test").unwrap(), tokio::net::TcpStream::connect(addr).await.unwrap()).await;
	let shown = seen.0.lock().unwrap().clone();
	shown
}

// Transports page, "`tls`": "For a self-signed one the node makes the key and the certificate itself when its config asks for it, keeps the key on the node with mode 600, and never sends it anywhere. The node reports the SHA-256 of the certificate's SubjectPublicKeyInfo", and a client whose profile marks the candidate `self_signed` trusts it by that pin alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_makes_its_own_certificate_and_a_profile_that_pins_it_reaches_the_node_through_it() {
	let (time, tls) = (time!(), listen());
	let mut node = launch("client-self-signed", time, |doc| {
		let transports = doc["inbounds"][0]["transports"].as_array_mut().unwrap();
		let origin = transports[0]["decoy"].clone();
		transports.push(json!({"type": "tls", "listen": tls.to_string(), "path": TLS_PATH, "tls": {"self_signed": true}, "decoy": origin}));
	}).await;
	let made = node.engine.certificates();
	assert_eq!(made.iter().map(|made| made.listen).collect::<Vec<_>>(), [tls]);
	let made = made[0].clone();
	// What the files hold: the pin is the key's, and nothing in the certificate is a fixed placeholder or names the program.
	let read = |path: &Path| {
		let der = CertificateDer::from_pem_file(path).unwrap();
		let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
		let names: Vec<String> = cert.subject_alternative_name().unwrap().unwrap().value.general_names.iter().map(|name| name.to_string()).collect();
		(digest(&SHA256, cert.public_key().raw).as_ref().to_vec(), cert.subject().to_string(), cert.issuer().to_string(), names, cert.raw_serial().to_vec(), cert.validity().not_before.timestamp(), cert.validity().not_after.timestamp(), cert.public_key().algorithm.parameters.as_ref().and_then(|curve| curve.as_oid().ok()).map(|oid| oid.to_id_string()), cert.basic_constraints().unwrap().map(|constraints| constraints.value.ca), cert.key_usage().unwrap().map(|usage| (usage.value.digital_signature(), usage.value.key_cert_sign())), cert.extended_key_usage().unwrap().map(|usage| (usage.value.server_auth, usage.value.client_auth)), der.to_vec())
	};
	let (pin, subject, issuer, names, serial, not_before, not_after, curve, ca, usage, extended, der) = read(&made.files.cert);
	let name = subject.strip_prefix("CN=").unwrap().to_owned();
	assert_eq!((pin.as_slice(), issuer, names, not_after - not_before, (made.not_before, made.not_after)), (&made.pin[..], subject.clone(), vec![format!("DNSName({name})")], not_after - not_before, (not_before, not_after)));
	assert!((80 * 86_400..101 * 86_400).contains(&(not_after - not_before)) && not_before <= time.secs() as i64 && not_before > time.secs() as i64 - 7 * 86_400 - 5);
	assert!(name.contains('.') && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.') && (8..=16).contains(&serial.len()), "{name} {serial:?}");
	assert_eq!((curve.as_deref(), ca, usage, extended), (Some("1.2.840.10045.3.1.7"), Some(false), Some((true, false)), Some((true, false))));
	assert!(!der.windows(5).any(|window| window.eq_ignore_ascii_case(b"rcgen") || window.eq_ignore_ascii_case(b"veilw")));
	assert_eq!(shown(tls).await, der);
	#[cfg(unix)]
	for path in [&made.files.key, &made.files.cert] {assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions()) & 0o777, 0o600, "{path:?}")}
	// A device whose profile pins that key alone reaches its tunnel, with no server name and with one, and no root of any kind is asked for.
	let candidate = |pins: Vec<[u8; 32]>, sni: Option<&str>, self_signed: bool| Target::Tls {path: TLS_PATH.into(), candidate: Front {address: tls, sni: sni.map(str::to_owned), host: "node.test".into(), verify_name: None, pins, ech: false, self_signed}};
	let env = |roots: RootCertStore| Env {device: Arc::new(move || time.secs()), now: Arc::new(move || time.secs()), roots: Arc::new(roots), socket: None};
	for (n, sni) in [(0, None), (1, Some("node.test"))] {
		let mut device = peer(n, &link(n), candidate(vec![made.pin], sni, true), 1, env(RootCertStore::empty()), wireguard(n));
		device.connect().await.unwrap_or_else(|ended| panic!("{sni:?}: {ended:?}"));
		assert_eq!(device.leaves(41000 + n as u16).await.as_deref(), Some("main"), "{sni:?}");
		device.session.close().await;
	}
	// A pin that does not match ends the candidate at once, and so does the right pin on a candidate from an authority: the chain is checked there whatever the server sends, and the node's certificate has none.
	let (other, mut roots) = (rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap(), RootCertStore::empty());
	roots.add(CertificateDer::from(other.cert.der().to_vec())).unwrap();
	let other_pin: [u8; 32] = digest(&SHA256, &other.signing_key.subject_public_key_info()).as_ref().try_into().unwrap();
	for (target, roots) in [(candidate(vec![other_pin], None, true), RootCertStore::empty()), (candidate(vec![made.pin], Some("node.test"), false), roots)] {
		let started = Instant::now();
		assert_eq!(peer(2, &link(2), target, 1, env(roots), wireguard(2)).ended().await, Ended::Unreachable(Unreachable::Certificate));
		assert!(started.elapsed() < 2 * SECOND, "{:?}", started.elapsed());
	}
	// A reload keeps the key, and the certificate with it.
	node.reload(|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().last_mut().unwrap()["limits"] = json!({"sessions": 100})).await;
	assert_eq!(node.engine.certificates().iter().map(|again| (again.pin, again.not_before)).collect::<Vec<_>>(), [(made.pin, made.not_before)]);
	assert_eq!(read(&made.files.cert).11, der);
	// After 85 days the certificate is made anew with the same key and the same name, and the listener answers with it: the pin in every profile stays good.
	time.ahead.fetch_add(85 * 86_400, Ordering::SeqCst);
	eventually("the certificate was not made anew", || node.engine.certificates().first().is_some_and(|again| again.not_before > made.not_before)).await;
	let (again_pin, again_subject, _, _, again_serial, again_before, .., again) = read(&made.files.cert);
	assert!(again_pin == pin && again_subject == subject && again_serial != serial && again_before >= time.secs() as i64 - 7 * 86_400 - 5 && node.engine.certificates()[0].pin == made.pin);
	assert_eq!(shown(tls).await, again);
	eventually("the replay limit did not follow the clock", || node.engine.replay().is_none_or(|replay| replay.limit >= time.secs())).await;
	let mut device = peer(3, &link(3), candidate(vec![made.pin], None, true), 1, env(RootCertStore::empty()), wireguard(3));
	device.connect().await.unwrap();
	assert!(device.session.numbers().heard.is_some());
	device.session.close().await;
	node.engine.shutdown().await;
}
