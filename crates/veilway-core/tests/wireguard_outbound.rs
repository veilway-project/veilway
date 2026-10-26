//! The `wireguard` outbound against a real node: node A leaves through a WireGuard server, which is node B, a plain `wireguard` inbound that has A's key as a device. TCP, UDP and DNS go through A to B, a proxy inbound of A uses the outbound, B stopped makes A's exit down and B back makes it work again, `max_flows` and an address family the outbound lacks are refused, and what a hostile server sends unasked is dropped without an answer.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::PacketBuilder;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use veilway_core::config::Config;
use veilway_core::engine::wg_out::Report;
use veilway_core::{Engine, Event, Options, Reason};

const ALICE: &str = "alice-secret-pass-01";

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn public(byte: u8) -> String {veilway_wg::encode_key(&veilway_wg::public_key(&[byte; 32]))}

/// An address of this host that is not loopback, which the gate lets a destination be and an endpoint of an outbound may be.
fn own() -> Option<IpAddr> {
	let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
	probe.connect("192.0.2.1:9").ok()?;
	Some(probe.local_addr().ok()?.ip()).filter(|ip| ip.is_ipv4() && !ip.is_loopback())
}

/// A port no one holds, on `at`, for both TCP and UDP.
fn free(at: IpAddr) -> SocketAddr {
	static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
	loop {
		let found = std::net::TcpListener::bind((at, 0)).unwrap().local_addr().unwrap();
		let mut given = GIVEN.lock().unwrap();
		if !given.contains(&found.port()) && std::net::UdpSocket::bind(found).is_ok() {given.push(found.port()); return found}
	}
}

async fn echo(at: IpAddr) -> SocketAddr {
	let listener = TcpListener::bind((at, 0)).await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut client, _)) = listener.accept().await {
			tokio::spawn(async move {
				let (mut read, mut write) = client.split();
				let _ = tokio::io::copy(&mut read, &mut write).await;
				let _ = write.shutdown().await;
			});
		}
	});
	addr
}

async fn udp_echo(at: IpAddr) -> SocketAddr {
	let socket = UdpSocket::bind((at, 0)).await.unwrap();
	let addr = socket.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buffer = vec![0u8; 2048];
		while let Ok((n, from)) = socket.recv_from(&mut buffer).await {let _ = socket.send_to(&buffer[..n], from).await;}
	});
	addr
}

/// A DNS server that answers every A query with `answer`, over UDP and, when `tcp` is set, over TCP as well.
async fn dns(at: IpAddr, answer: IpAddr) -> SocketAddr {
	let socket = UdpSocket::bind((at, 0)).await.unwrap();
	let addr = socket.local_addr().unwrap();
	let IpAddr::V4(answer) = answer else {panic!("an IPv4 address")};
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

/// Node B, the server: a `wireguard` inbound on `listen` that has the device of node A, and a direct exit.
fn far_doc(listen: SocketAddr) -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["192.0.2.53:53"]},
		"inbounds": [{"tag": "far", "type": "wireguard", "private_key": key(0x51), "address": ["10.9.0.1/24"], "transports": [{"type": "udp", "listen": listen.to_string()}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "a", "public_key": public(0x61), "addresses": ["10.9.0.2"]}]}]
	})
}

/// Node A: a proxy inbound for alice, and the exit `far` through a WireGuard outbound to `server`. `outbound` edits the outbound's keys.
fn near_doc(server: &str, dns: SocketAddr, socks: SocketAddr, outbound: impl FnOnce(&mut Value)) -> Value {
	let mut up = json!({"tag": "up", "type": "wireguard", "server": server, "public_key": public(0x51), "private_key": key(0x61), "addresses": ["10.9.0.2"], "keepalive_secs": 1});
	outbound(&mut up);
	json!({
		"version": 1,
		"dns": {"servers": [dns.to_string()]},
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": free("127.0.0.1".parse().unwrap()).to_string()}]},
			{"tag": "s", "type": "socks5", "listen": socks.to_string()}
		],
		"outbounds": [{"tag": "plain", "type": "direct"}, up],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "far", "backend": {"type": "netstack", "outbound": "up"}}],
		"routing": {"default": "far", "rules": []},
		"users": [{"name": "alice", "exits": "all", "proxy_password": ALICE, "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}]
	})
}

async fn start(doc: &Value) -> Engine {
	let config = Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("the test config does not parse: {e}"));
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	veilway_core::start(&config, Options {is_local: |_| false, ..Options::new("")}).await.unwrap_or_else(|e| panic!("the node did not start: {e:#}"))
}

fn report(engine: &Engine) -> Report {engine.exit_health().into_iter().find(|health| health.exit == "far").and_then(|health| health.wireguard).expect("the exit far has no WireGuard outbound")}

/// Waits for `ready` to hold of the outbound's report, up to `wait` seconds.
async fn until(engine: &Engine, wait: u64, what: &str, ready: impl Fn(&Report) -> bool) -> Report {
	let began = Instant::now();
	loop {
		let now = report(engine);
		if ready(&now) {return now}
		assert!(began.elapsed() < Duration::from_secs(wait), "{what}: still {now:?} after {wait} s");
		sleep(Duration::from_millis(100)).await;
	}
}

/// Node B on a runtime of its own, so that stopping it closes its sockets as a process that ends does: `Engine::shutdown` leaves the listeners to the process.
struct Far {engine: Option<Engine>, stop: std::sync::mpsc::Sender<()>, thread: Option<std::thread::JoinHandle<()>>}

impl Far {
	fn start(doc: &Value) -> Far {
		let ((stop, stopped), (sent, received), doc) = (std::sync::mpsc::channel::<()>(), std::sync::mpsc::channel::<Engine>(), doc.clone());
		let thread = std::thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
			sent.send(runtime.block_on(start(&doc))).unwrap();
			let _ = stopped.recv();
			runtime.shutdown_timeout(Duration::from_secs(5));
		});
		Far {engine: Some(received.recv().unwrap()), stop, thread: Some(thread)}
	}

	fn user(&self, name: &str) -> Option<veilway_core::Totals> {self.engine.as_ref().and_then(|engine| engine.user(name))}

	/// Ends the node: its tasks are dropped, and the sockets with them.
	fn stop(&mut self) {
		drop(self.engine.take());
		let _ = self.stop.send(());
		if let Some(thread) = self.thread.take() {thread.join().unwrap()}
	}
}

struct Net {far: Far, near: Engine, far_doc: Value, socks: SocketAddr, echo: SocketAddr, udp: SocketAddr, own: IpAddr, dns: SocketAddr}

/// Both nodes, with the servers of the tests on an address of this host. None where the host has no address but loopback.
async fn net(outbound: impl FnOnce(&mut Value)) -> Option<Net> {
	let own = own()?;
	let (listen, socks) = (free(own), free("127.0.0.1".parse().unwrap()));
	let (echoed, dns) = (echo(own).await, dns(own, own).await);
	let far_doc = far_doc(listen);
	let far = Far::start(&far_doc);
	let near = start(&near_doc(&listen.to_string(), dns, socks, outbound)).await;
	until(&near, 10, "the first handshake", |now| now.handshake_secs.is_some()).await;
	Some(Net {far, near, far_doc, socks, echo: echoed, udp: udp_echo(own).await, own, dns})
}

fn encode(dest: &SocketAddr) -> Vec<u8> {
	match dest {
		SocketAddr::V4(addr) => [&[1][..], &addr.ip().octets(), &addr.port().to_be_bytes()].concat(),
		SocketAddr::V6(addr) => [&[4][..], &addr.ip().octets(), &addr.port().to_be_bytes()].concat(),
	}
}

async fn login(at: SocketAddr) -> TcpStream {
	let mut stream = TcpStream::connect(at).await.unwrap();
	stream.write_all(&[5, 2, 0, 2]).await.unwrap();
	let mut said = [0u8; 2];
	stream.read_exact(&mut said).await.unwrap();
	stream.write_all(&[&[1, 5][..], b"alice", &[ALICE.len() as u8], ALICE.as_bytes()].concat()).await.unwrap();
	stream.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [1, 0], "the login was refused");
	stream
}

/// The reply code of one request on a logged in stream, and the address it carries.
async fn ask(stream: &mut TcpStream, command: u8, dest: &[u8]) -> (u8, SocketAddr) {
	stream.write_all(&[&[5, command, 0][..], dest].concat()).await.unwrap();
	let mut head = [0u8; 4];
	stream.read_exact(&mut head).await.unwrap();
	let ip: IpAddr = if head[3] == 1 {
		let mut raw = [0u8; 4];
		stream.read_exact(&mut raw).await.unwrap();
		raw.into()
	} else {
		let mut raw = [0u8; 16];
		stream.read_exact(&mut raw).await.unwrap();
		raw.into()
	};
	let mut port = [0u8; 2];
	stream.read_exact(&mut port).await.unwrap();
	(head[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
}

/// A connection through the proxy inbound of node A to `dest`.
async fn connect(at: SocketAddr, dest: &[u8]) -> Result<TcpStream, u8> {
	let mut stream = login(at).await;
	match ask(&mut stream, 1, dest).await {
		(0, _) => Ok(stream),
		(code, _) => Err(code),
	}
}

async fn through(stream: &mut TcpStream, text: &[u8]) {
	stream.write_all(text).await.unwrap();
	let mut back = vec![0u8; text.len()];
	timeout(Duration::from_secs(10), stream.read_exact(&mut back)).await.expect("no answer through the outbound").unwrap();
	assert_eq!(back, text);
}

#[tokio::test]
async fn tcp_udp_and_dns_go_through_the_server() {
	let Some(net) = net(|_| {}).await else {return};
	let mut stream = connect(net.socks, &encode(&net.echo)).await.expect("the connection was refused");
	through(&mut stream, b"hello through a wireguard outbound").await;
	let mut named = connect(net.socks, &[&[3, 14][..], b"anything.local", &net.echo.port().to_be_bytes()].concat()).await.expect("a name was not resolved through the outbound");
	through(&mut named, b"by name").await;
	let (mut control, client) = (login(net.socks).await, UdpSocket::bind("127.0.0.1:0").await.unwrap());
	let hint = if cfg!(target_os = "linux") {"0.0.0.0:0".parse().unwrap()} else {client.local_addr().unwrap()};
	let (code, relay) = ask(&mut control, 3, &encode(&hint)).await;
	assert_eq!(code, 0);
	let datagram = [&[0, 0, 0][..], &encode(&net.udp), b"datagram"].concat();
	client.send_to(&datagram, relay).await.unwrap();
	let mut buffer = vec![0u8; 2048];
	let (n, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buffer)).await.expect("no UDP answer through the outbound").unwrap();
	assert!(buffer[..n].ends_with(b"datagram"));
	let (exit, user) = (net.near.exit("far").unwrap(), net.far.user("alice").unwrap());
	assert!(exit.up_bytes > 0 && exit.down_bytes > 0, "{exit:?}: node A did not count the exit's bytes");
	assert!(user.up_bytes > 0 && user.down_bytes > 0, "{user:?}: node B did not see the flows of node A's device");
	let now = report(&net.near);
	assert!(now.up && now.endpoint.is_some() && now.handshake_secs.is_some() && now.flips == 0, "{now:?}");
	assert!(now.flows >= 2, "{now:?}: the two open connections are flows of the stack");
	assert_eq!(net.near.exit("main").unwrap().up_bytes, 0, "something left around the outbound");
	drop((stream, named, control));
}

#[tokio::test]
async fn a_lookup_through_the_outbound_asks_over_udp_and_then_over_tcp() {
	let Some(net) = net(|_| {}).await else {return};
	let query = {
		let mut message = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
		message.extend_from_slice(&[3, b'f', b'o', b'o', 0, 0, 1, 0, 1]);
		message
	};
	let plan = net.near.plan();
	let veilway_core::engine::plan::Backend::Netstack {outbound, ..} = &plan.exits.iter().find(|exit| exit.tag == "far").unwrap().backend else {panic!("not a netstack exit")};
	let answer = veilway_core::engine::probe::lookup(outbound, net.dns, &query).await.expect("no answer through the outbound over UDP");
	assert_eq!(&answer[..2], &query[..2], "the id of the client's query was not put back");
	assert!(answer[2] & 0x80 != 0 && answer.ends_with(&match net.own {IpAddr::V4(own) => own.octets(), _ => unreachable!()}));
	// A server that answers over TCP alone: the UDP wait ends and the same query is asked again as a stream.
	let tcp = TcpListener::bind((net.own, 0)).await.unwrap();
	let at = tcp.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut client, _)) = tcp.accept().await {
			tokio::spawn(async move {
				let mut length = [0u8; 2];
				client.read_exact(&mut length).await.unwrap();
				let mut asked = vec![0u8; usize::from(u16::from_be_bytes(length))];
				client.read_exact(&mut asked).await.unwrap();
				let reply = [&asked[..2], &[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0][..], &asked[12..], &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 77][..]].concat();
				let _ = client.write_all(&[&(reply.len() as u16).to_be_bytes()[..], &reply].concat()).await;
			});
		}
	});
	let began = Instant::now();
	let answer = veilway_core::engine::probe::lookup(outbound, at, &query).await.expect("no answer through the outbound over TCP");
	assert!(answer.ends_with(&[192, 0, 2, 77]), "{answer:?}");
	assert!(began.elapsed() >= Duration::from_secs(2), "the UDP wait was not given: {:?}", began.elapsed());
}

#[tokio::test]
async fn throughput_through_the_outbound() {
	let Some(net) = net(|_| {}).await else {return};
	let (mut stream, size) = (connect(net.socks, &encode(&net.echo)).await.expect("the connection was refused"), 16usize << 20);
	let (mut read, mut write) = stream.split();
	let began = Instant::now();
	let (sent, got) = tokio::join!(async {
		let chunk = vec![0x5au8; 64 << 10];
		for _ in 0..size / chunk.len() {write.write_all(&chunk).await.unwrap()}
	}, async {
		let (mut buffer, mut total) = (vec![0u8; 64 << 10], 0usize);
		while total < size {
			let n = timeout(Duration::from_secs(30), read.read(&mut buffer)).await.expect("the echo stalled").unwrap();
			assert!(n > 0, "the stream ended after {total} bytes");
			total += n;
		}
		total
	});
	let _ = sent;
	let took = began.elapsed().as_secs_f64();
	eprintln!("throughput through the wireguard outbound: {size} bytes up and {got} down in {took:.2} s, {:.1} MB/s each way (one connection, both nodes in this process pair, an address of this host)", size as f64 / took / 1e6);
	assert_eq!(got, size);
}

#[tokio::test]
async fn a_server_that_stops_makes_the_exit_down_and_one_that_returns_makes_it_work_again() {
	let Some(mut net) = net(|_| {}).await else {return};
	let mut events = net.near.events();
	assert!(net.near.plan().working(net.near.plan().exits.iter().position(|exit| exit.tag == "far").unwrap()));
	net.far.stop();
	let down = until(&net.near, 30, "the exit going down", |now| !now.up).await;
	assert!(down.why.as_deref().is_some_and(|why| !why.is_empty()) && down.flips >= 1, "{down:?}");
	let far = net.near.plan().exits.iter().position(|exit| exit.tag == "far").unwrap();
	assert!(!net.near.plan().working(far), "an exit through a down outbound counted as working");
	// A flow of a down outbound fails at once and goes nowhere else.
	let before = net.near.exit("main").unwrap().up_bytes;
	let began = Instant::now();
	assert!(connect(net.socks, &encode(&net.echo)).await.is_err(), "a flow was carried while the outbound was down");
	assert!(began.elapsed() < Duration::from_secs(2), "the flow waited {:?} instead of failing at once", began.elapsed());
	assert_eq!(net.near.exit("main").unwrap().up_bytes, before, "a flow went around the outbound");
	assert!(net.near.wireguard_down("up").is_some_and(|why| !why.is_empty()));
	let mut told = Vec::new();
	while let Ok(event) = events.try_recv() {if let Event::ExitWorkingChanged {exit, working} = event {told.push((exit, working))}}
	assert_eq!(told, vec![("far".to_string(), false)], "the exit going down was not published once");
	// Never latched: the server comes back on its address and the node finds it again by itself.
	net.far = Far::start(&net.far_doc);
	let up = until(&net.near, 60, "the exit coming back", |now| now.up && now.down_secs.is_none()).await;
	assert!(up.flips >= 2, "{up:?}");
	assert!(net.near.plan().working(far));
	let mut stream = connect(net.socks, &encode(&net.echo)).await.expect("the outbound did not carry again");
	through(&mut stream, b"back").await;
	let mut again = Vec::new();
	while let Ok(event) = events.try_recv() {if let Event::ExitWorkingChanged {exit, working} = event {again.push((exit, working))}}
	assert_eq!(again, vec![("far".to_string(), true)]);
}

#[tokio::test]
async fn max_flows_refuses_the_next_flow_and_a_closed_one_frees_a_place() {
	let Some(net) = net(|o| o["max_flows"] = json!(16)).await else {return};
	let mut held = Vec::new();
	for at in 0..16 {held.push(connect(net.socks, &encode(&net.echo)).await.unwrap_or_else(|code| panic!("flow {at} was refused with {code}")))}
	assert_eq!(report(&net.near).flows, 16);
	assert!(connect(net.socks, &encode(&net.echo)).await.is_err(), "a flow past max_flows was carried");
	assert_eq!(report(&net.near).refused, 1);
	drop(held.pop());
	sleep(Duration::from_millis(500)).await;
	let mut stream = connect(net.socks, &encode(&net.echo)).await.expect("a place freed by a closed flow was not given again");
	through(&mut stream, b"room again").await;
	assert_eq!(report(&net.near).refused, 1);
}

#[tokio::test]
async fn a_destination_of_a_family_the_outbound_has_no_address_for_is_refused() {
	let Some(net) = net(|_| {}).await else {return};
	let unreachable = net.near.dropped(Reason::Unreachable);
	let began = Instant::now();
	let refused = connect(net.socks, &encode(&"[2001:db8::1]:80".parse().unwrap())).await;
	assert!(refused.is_err() && began.elapsed() < Duration::from_secs(2), "{refused:?} after {:?}", began.elapsed());
	assert_eq!(report(&net.near).flows, 0, "the stack opened a flow for a family it has no address of");
	assert_eq!(net.near.dropped(Reason::Unreachable), unreachable + 1);
	let mut stream = connect(net.socks, &encode(&net.echo)).await.expect("the family it has was refused too");
	through(&mut stream, b"v4").await;
}

#[tokio::test]
async fn a_server_that_resolves_to_an_address_the_node_never_dials_is_refused_and_down() {
	let Some(own) = own() else {return};
	let (dns, socks) = (dns(own, own).await, free("127.0.0.1".parse().unwrap()));
	let near = start(&near_doc(&format!("localhost:{}", free(own).port()), dns, socks, |_| {})).await;
	let down = until(&near, 15, "the exit going down", |now| !now.up).await;
	assert!(down.why.as_deref().is_some_and(|why| why.contains("loopback")), "{down:?}");
	assert!(down.endpoint.is_none() && down.handshake_secs.is_none());
	assert!(connect(socks, &encode(&SocketAddr::new(own, 9))).await.is_err());
}

/// A server that is a test's own end of the tunnel: it answers the handshake, counts the IP packets the node sends it, and sends what the test hands it.
async fn hostile(listen: SocketAddr, private: u8, client: u8) -> (mpsc::Sender<Vec<u8>>, Arc<AtomicUsize>) {
	let socket = UdpSocket::bind(listen).await.unwrap();
	let (inject, mut injected) = mpsc::channel::<Vec<u8>>(64);
	let received = Arc::new(AtomicUsize::new(0));
	let counted = received.clone();
	tokio::spawn(async move {
		let mut tunn = Tunn::new(StaticSecret::from([private; 32]), PublicKey::from(veilway_wg::public_key(&[client; 32])), None, None, 7, None);
		let (mut peer, mut buffer, mut out) = (None::<SocketAddr>, vec![0u8; 65535], vec![0u8; 65535 + 64]);
		loop {
			tokio::select! {
				Ok((n, from)) = socket.recv_from(&mut buffer) => {
					peer = Some(from);
					let mut input = &buffer[..n];
					loop {
						match tunn.decapsulate(None, input, &mut out) {
							TunnResult::WriteToNetwork(reply) => {
								let _ = socket.send_to(reply, from).await;
								input = &[];
							}
							TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
								counted.fetch_add(1, Ordering::Relaxed);
								break;
							}
							_ => break,
						}
					}
				}
				Some(packet) = injected.recv() => {
					if let (Some(to), TunnResult::WriteToNetwork(datagram)) = (peer, tunn.encapsulate(&packet, &mut out)) {let _ = socket.send_to(datagram, to).await;}
				}
				_ = sleep(Duration::from_millis(250)) => {
					if let (Some(to), TunnResult::WriteToNetwork(datagram)) = (peer, tunn.update_timers(&mut out)) {let _ = socket.send_to(datagram, to).await;}
				}
			}
		}
	});
	(inject, received)
}

#[tokio::test]
async fn what_the_server_sends_unasked_is_dropped_and_never_answered() {
	let Some(own) = own() else {return};
	let (listen, socks, dns) = (free(own), free("127.0.0.1".parse().unwrap()), dns(own, own).await);
	let (inject, received) = hostile(listen, 0x51, 0x61).await;
	let near = start(&near_doc(&listen.to_string(), dns, socks, |_| {})).await;
	until(&near, 10, "the handshake with the hostile server", |now| now.handshake_secs.is_some()).await;
	let (mine, theirs) = ([10, 9, 0, 2], [198, 51, 100, 1]);
	let mut packets: Vec<Vec<u8>> = Vec::new();
	macro_rules! build {($builder:expr, $payload:expr) => {{
		let mut packet = Vec::new();
		$builder.write(&mut packet, $payload).unwrap();
		packet
	}}}
	// A SYN to a port nothing listens on, a segment of no connection, a datagram to a port nobody opened, an echo request, a packet for another address, a fragment and a packet of another protocol. A truncated packet never gets here: the tunnel refuses to encrypt it, and `admit` has a test of its own.
	packets.push(build!(PacketBuilder::ipv4(theirs, mine, 64).tcp(80, 33000, 1, 1000).syn(), &[]));
	packets.push(build!(PacketBuilder::ipv4(theirs, mine, 64).tcp(80, 34000, 1, 1000).ack(1), b"data"));
	packets.push(build!(PacketBuilder::ipv4(theirs, mine, 64).udp(53, 40000), b"unsolicited"));
	packets.push(build!(PacketBuilder::ipv4(theirs, mine, 64).icmpv4_echo_request(1, 1), b"ping"));
	packets.push(build!(PacketBuilder::ipv4(theirs, [10, 9, 0, 9], 64).udp(53, 40000), b"elsewhere"));
	let mut fragment = build!(PacketBuilder::ipv4(theirs, mine, 64).udp(53, 40000), &[1u8; 64]);
	fragment[6] |= 0x20;
	packets.push(fragment);
	packets.push(vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 47, 0, 0, 198, 51, 100, 1, 10, 9, 0, 2]);
	let sent = packets.len();
	for packet in packets {inject.send(packet).await.unwrap()}
	let counted = until(&near, 5, "the packets being counted as unsolicited", |now| now.unsolicited >= sent as u64).await;
	sleep(Duration::from_millis(1500)).await;
	assert_eq!(received.load(Ordering::Relaxed), 0, "the node answered a packet it never asked for: an RST, an unreachable or an echo reply went back");
	assert_eq!(counted.flows, 0);
	let again = report(&near);
	assert!(again.up && again.unsolicited >= sent as u64, "{again:?}: a hostile server made the outbound go down");
}
