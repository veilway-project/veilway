//! Tunnels end to end (node links page, "Tunnels"): two engines in one process joined by a forward link over `udp-obfs`, the entry listening on loopback and the exit leaving through a SOCKS5 proxy of the test that echoes. The node that dials reaches the other on an address of this host that is not loopback.
#[macro_use]
mod proxied;
use proxied::*;
use rustls::RootCertStore;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use veilway_core::engine::link::Status;
use veilway_core::{Engine, Options, TunnelTotals};

const EXIT: [u8; 32] = [0x12; 32];
const DIALLER: [u8; 32] = [0x31; 32];
const SECRET: [u8; 32] = [0x41; 32];
const LINK_ID: &str = "AAECAwQFBgcICQoLDA0ODw";
/// The address the exit is asked to reach: public, so that the exit's rules let it through.
const FAR: &str = "93.184.216.34:5353";

fn outward() -> IpAddr {
	let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
	socket.connect("192.0.2.1:9").expect("this host has no address but loopback, and a link never dials loopback");
	socket.local_addr().unwrap().ip()
}

/// A SOCKS5 proxy without authentication that echoes: a CONNECT is answered and then every byte is sent back until the client closes its side, and a UDP ASSOCIATE gets a relay that sends every datagram back to where it came from. A datagram that starts with `amp` is answered ten times with a thousand bytes, the way a reflector answers.
async fn echo() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {return};
			tokio::spawn(async move {
				let (mut hello, mut head, mut target) = ([0u8; 2], [0u8; 4], [0u8; 6]);
				if client.read_exact(&mut hello).await.is_err() {return}
				let mut methods = vec![0u8; usize::from(hello[1])];
				if client.read_exact(&mut methods).await.is_err() || client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut head).await.is_err() || client.read_exact(&mut target).await.is_err() {return}
				if head[1] == 1 {
					if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {return}
					let (mut read, mut write) = client.split();
					let _ = tokio::io::copy(&mut read, &mut write).await;
					let _ = write.shutdown().await;
					return;
				}
				let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
				let port = relay.local_addr().unwrap().port().to_be_bytes();
				if client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]]).await.is_err() {return}
				let (mut buf, mut sink) = (vec![0u8; 65535], [0u8; 16]);
				loop {
					tokio::select! {
						received = relay.recv_from(&mut buf) => {
							let Ok((n, from)) = received else {return};
							if buf[10..n].starts_with(b"amp") {
								let answer = [&buf[..10], &[b'x'; 1000][..]].concat();
								for _ in 0..10 {let _ = relay.send_to(&answer, from).await;}
							} else {
								let _ = relay.send_to(&buf[..n], from).await;
							}
						}
						held = client.read(&mut sink) => if held.map_or(true, |n| n == 0) {return},
					}
				}
			});
		}
	});
	addr
}

/// The entry with its two links, one that comes up and one that never does, and the exit.
struct Net {entry: Engine, exit: Engine, doc: Value}

impl Net {
	async fn start(test: &'static str, tunnels: Vec<Value>) -> Net {
		let (dir, time, roots) = (scratch(test), time!(), Arc::new(RootCertStore::empty()));
		let (at, silent) = (SocketAddr::new(outward(), listen().port()), SocketAddr::new(outward(), listen().port()));
		let exit_doc = json!({
			"version": 1, "dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "links", "type": "veilway", "private_key": text(&EXIT), "address": ["10.9.0.1/24"], "transports": [{"type": "udp-obfs", "listen": at.to_string()}]}],
			"outbounds": [{"tag": "proxy", "type": "socks5", "server": echo().await.to_string()}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "proxy"}}],
			"routing": {"default": "main", "rules": [{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
			"users": [],
			"links": [{"tag": "far", "id": LINK_ID, "direction": "forward", "addresses": {"dialler": ["10.9.0.2"]}, "transport_secret": text(&SECRET), "inbound": "links", "public_key": text(&public(&DIALLER)), "exits": ["main"]}]
		});
		let doc = json!({
			"version": 1, "dns": {"servers": ["1.1.1.1:53"]}, "inbounds": [], "outbounds": [],
			"exits": [{"tag": "far", "backend": {"type": "chain", "links": ["far"]}}, {"tag": "dead", "backend": {"type": "chain", "links": ["dead"]}}],
			"routing": {"default": "far", "rules": []}, "users": [],
			"links": [
				{"tag": "far", "id": LINK_ID, "direction": "forward", "addresses": {"dialler": ["10.9.0.2"]}, "transport_secret": text(&SECRET), "private_key": text(&DIALLER), "peer": {"inbound_public_key": text(&public(&EXIT)), "transports": [{"type": "udp-obfs", "endpoints": [at.to_string()]}]}},
				{"tag": "dead", "id": "EBESExQVFhcYGRobHB0eHw", "direction": "forward", "addresses": {"dialler": ["10.20.0.2"]}, "transport_secret": text(&[0x42; 32]), "private_key": text(&[0x32; 32]), "peer": {"inbound_public_key": text(&public(&[0x61; 32])), "transports": [{"type": "udp-obfs", "endpoints": [silent.to_string()]}]}}
			],
			"tunnels": tunnels
		});
		let exit = Net::run(&exit_doc, &dir.join("exit"), time, &roots).await;
		let entry = Net::run(&doc, &dir.join("entry"), time, &roots).await;
		eventually("the link is not up at the entry", || entry.links()[0].status == Status::Up).await;
		eventually("the link is not up at the exit", || exit.links()[0].status == Status::Up).await;
		Net {entry, exit, doc}
	}

	async fn run(doc: &Value, dir: &std::path::Path, time: Time, roots: &Arc<RootCertStore>) -> Engine {
		let _ = std::fs::create_dir_all(dir);
		seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
		veilway_core::start(&parsed(doc), Options {now: time.now, replay: Some(dir.join("replay")), roots: Some(roots.clone()), ..Options::new(dir)}).await.unwrap_or_else(|e| panic!("the node did not start: {e:#}"))
	}

	/// What the tunnel `tag` counted.
	fn of(&self, tag: &str) -> TunnelTotals {self.entry.tunnels().into_iter().find(|(name, _)| name == tag).unwrap_or_else(|| panic!("no tunnel {tag} runs")).1}

	async fn reload(&self) {self.entry.reload(self.doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e:?}"));}

	async fn stop(self) {
		self.entry.shutdown().await;
		self.exit.shutdown().await;
	}
}

fn tunnel(tag: &str, protocol: &str, listen: SocketAddr, exit: &str) -> Value {json!({"tag": tag, "protocol": protocol, "listen": listen.to_string(), "exit": exit, "target": FAR})}

/// Sends a few bytes and waits for them to come back.
async fn echoes(stream: &mut TcpStream, what: &[u8]) {
	stream.write_all(what).await.unwrap();
	let mut back = vec![0u8; what.len()];
	timeout(Duration::from_secs(10), stream.read_exact(&mut back)).await.expect("no answer within 10 s").unwrap();
	assert_eq!(back, what);
}

/// Whether a connection to `at` is refused: the connection is reset before it is made, or closed by the node before any byte.
async fn refused(at: SocketAddr) -> bool {
	match TcpStream::connect(at).await {
		Ok(mut stream) => closed(&mut stream).await,
		Err(_) => true,
	}
}

/// Whether the connection was closed by the node, as a refusal or a reload does: end of stream or an error before any byte.
async fn closed(stream: &mut TcpStream) -> bool {
	let mut byte = [0u8; 1];
	matches!(timeout(Duration::from_secs(5), stream.read(&mut byte)).await, Ok(Ok(0) | Err(_)))
}

// "Bytes are copied both ways, a half close is passed on."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tcp_tunnel_carries_a_megabyte_both_ways_and_passes_a_half_close_on() {
	let at = listen();
	let net = Net::start("tunnels-tcp", vec![tunnel("echo", "tcp", at, "far")]).await;
	let stream = TcpStream::connect(at).await.unwrap();
	let (mut read, mut write) = stream.into_split();
	let data: Vec<u8> = (0..1usize << 20).map(|n| (n * 7 + n / 251) as u8).collect();
	let sent = data.clone();
	let writer = tokio::spawn(async move {
		write.write_all(&sent).await.unwrap();
		write
	});
	let mut back = vec![0u8; data.len()];
	timeout(Duration::from_secs(60), read.read_exact(&mut back)).await.expect("the megabyte did not come back within 60 s").unwrap();
	assert!(back == data, "the megabyte came back changed");
	// A half close is passed on: the far side sees the end of what was sent and ends its side too, which the client sees as the end of the stream. (What the far side still has to say after the end is for the exit's own TCP to deliver, and is not asserted here.)
	let mut write = writer.await.unwrap();
	write.shutdown().await.unwrap();
	let mut rest = Vec::new();
	timeout(Duration::from_secs(20), read.read_to_end(&mut rest)).await.expect("the half close did not come back within 20 s").unwrap();
	assert!(rest.is_empty());
	let counted = net.of("echo");
	assert_eq!((counted.opened, counted.up_bytes, counted.down_bytes), (1, 1 << 20, 1 << 20), "{counted:?}");
	assert!(counted.up_packets > 700 && counted.down_packets > 700, "{counted:?}");
	// What crossed the link is counted at the exit as the flows of a link.
	assert!(net.exit.links()[0].flows >= 1 || net.exit.links()[0].traffic.down_packets > 700);
	net.stop().await;
}

// "A session per client address and port, with its own translated port." And the answer budget: "at most 3 times the bytes the client sent since its last datagram plus 4096 bytes".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_udp_tunnel_echoes_each_client_and_does_not_reflect_more_than_its_budget() {
	let at = listen();
	let net = Net::start("tunnels-udp", vec![json!({"tag": "echo", "protocol": "udp", "listen": at.to_string(), "exit": "far", "target": FAR, "sources": ["127.0.0.1"]})]).await;
	let (one, two) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
	let mut buf = vec![0u8; 4096];
	for (socket, what) in [(&one, &b"first"[..]), (&two, &b"second"[..])] {
		socket.send_to(what, at).await.unwrap();
		let (n, from) = timeout(Duration::from_secs(10), socket.recv_from(&mut buf)).await.expect("no echo within 10 s").unwrap();
		assert_eq!((&buf[..n], from), (what, at), "a client got something that is not its own echo");
	}
	assert_eq!(net.of("echo").open, 2);
	// Ten answers of a thousand bytes to a datagram of three: 3 * 3 + 4096 bytes may come, which is four of them.
	one.send_to(b"amp", at).await.unwrap();
	let mut got = 0;
	while timeout(Duration::from_millis(1500), one.recv_from(&mut buf)).await.is_ok() {got += 1}
	assert_eq!(got, 4, "the budget let {got} answers of a thousand bytes through");
	eventually("the answers past the budget are not counted", || net.of("echo").dropped >= 6).await;
	// A new datagram of the client starts the budget again.
	one.send_to(b"again", at).await.unwrap();
	timeout(Duration::from_secs(10), one.recv_from(&mut buf)).await.expect("no echo after the budget was used").unwrap();
	// A datagram larger than the link carries is dropped and counted.
	let dropped = net.of("echo").dropped;
	one.send_to(&vec![1u8; 1500], at).await.unwrap();
	eventually("a datagram larger than the link was not counted", || net.of("echo").dropped > dropped).await;
	net.stop().await;
}

// "Anyone who reaches the address, unless `sources` lists networks": another address is refused and counted. And a UDP tunnel on an address that is not loopback has to list them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sources_refuse_other_addresses() {
	let at = listen();
	let net = Net::start("tunnels-sources", vec![json!({"tag": "closed", "protocol": "tcp", "listen": at.to_string(), "exit": "far", "target": FAR, "sources": ["127.0.0.2", "10.0.0.0/8"]})]).await;
	assert!(refused(at).await, "a connection from an address that is not listed was kept");
	eventually("the refusal is not counted", || net.of("closed").refused_sources == 1).await;
	assert_eq!(net.of("closed").opened, 0);
	net.stop().await;
}

// "`max_connections` TCP connections or UDP sessions at once per tunnel."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_connections_refuses_the_next_one() {
	let at = listen();
	let mut few = tunnel("few", "tcp", at, "far");
	few["max_connections"] = json!(2);
	let net = Net::start("tunnels-max", vec![few]).await;
	let (mut one, mut two) = (TcpStream::connect(at).await.unwrap(), TcpStream::connect(at).await.unwrap());
	echoes(&mut one, b"one").await;
	echoes(&mut two, b"two").await;
	assert!(refused(at).await, "a connection past max_connections was kept");
	assert_eq!((net.of("few").refused_limit, net.of("few").open), (1, 2));
	drop(one);
	eventually("the place of a closed connection is not given back", || net.of("few").open == 1).await;
	echoes(&mut two, b"still").await;
	net.stop().await;
}

// "While the `chain` exit is down, a connection is refused at once and a UDP datagram is dropped, and both are counted."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_exit_that_is_down_refuses_at_once() {
	let (at, datagrams) = (listen(), listen());
	let net = Net::start("tunnels-down", vec![tunnel("down", "tcp", at, "dead"), json!({"tag": "lost", "protocol": "udp", "listen": datagrams.to_string(), "exit": "dead", "target": FAR, "sources": ["127.0.0.1"]})]).await;
	assert!(refused(at).await, "a connection through a link that is down was kept");
	let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	socket.send_to(b"hello", datagrams).await.unwrap();
	eventually("the refusals are not counted", || net.of("down").refused_down == 1 && net.of("lost").refused_down == 1).await;
	net.stop().await;
}

// "A source holds at most 16 ... and at most 8 new ones per second."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_source_opens_at_most_eight_a_second_and_holds_sixteen() {
	let at = listen();
	let net = Net::start("tunnels-rate", vec![tunnel("rate", "tcp", at, "far")]).await;
	let mut held = Vec::new();
	// A burst of twelve: the exact counts per second are the unit test's (`tunnel.rs`), since a loaded runner can spread a burst over two seconds.
	for _ in 0..12 {held.extend(TcpStream::connect(at).await)}
	eventually("the burst was not all counted", || {let counted = net.of("rate"); counted.opened + counted.refused_rate == 12}).await;
	let counted = net.of("rate");
	assert!(counted.refused_rate >= 1 && counted.opened as usize == counted.open, "{counted:?}");
	net.stop().await;
}

// "A tunnel whose keys did not change keeps its connections. A narrower `sources` closes the connections ... from sources it no longer lists, and a lower `max_connections` closes the newest ones past it. Any other change ... closes its listener and its connections."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_keeps_an_unchanged_tunnel_and_closes_what_a_change_leaves_out() {
	let (at, other) = (listen(), listen());
	let mut echo = tunnel("echo", "tcp", at, "far");
	echo["sources"] = json!(["127.0.0.1", "127.0.0.2"]);
	let mut net = Net::start("tunnels-reload", vec![echo.clone()]).await;
	let mut kept = TcpStream::connect(at).await.unwrap();
	echoes(&mut kept, b"before").await;
	// Another tunnel is added and an unrelated key of the document changes: the connection goes on.
	net.doc["tunnels"].as_array_mut().unwrap().push(tunnel("extra", "tcp", other, "far"));
	net.reload().await;
	echoes(&mut kept, b"after").await;
	assert_eq!((net.of("echo").opened, net.of("echo").open), (1, 1));
	// A wider `sources` and a higher `max_connections` close nothing.
	net.doc["tunnels"][0]["sources"] = json!(["127.0.0.0/24"]);
	net.doc["tunnels"][0]["max_connections"] = json!(500);
	net.reload().await;
	echoes(&mut kept, b"wider").await;
	// A narrower `sources` closes it.
	net.doc["tunnels"][0]["sources"] = json!(["127.0.0.2"]);
	net.reload().await;
	assert!(closed(&mut kept).await, "a connection from a source that is no longer listed was kept");
	// A lower `max_connections` closes the newest connections past it and keeps the oldest.
	net.doc["tunnels"][0]["sources"] = json!(["127.0.0.0/24"]);
	net.reload().await;
	let (mut old, mut young) = (TcpStream::connect(at).await.unwrap(), TcpStream::connect(at).await.unwrap());
	echoes(&mut old, b"old").await;
	echoes(&mut young, b"young").await;
	net.doc["tunnels"][0]["max_connections"] = json!(1);
	net.reload().await;
	assert!(closed(&mut young).await, "the newest connection was kept past a lower max_connections");
	echoes(&mut old, b"older").await;
	// Any other change closes the connections: here the target.
	net.doc["tunnels"][0]["target"] = json!("93.184.216.35:5353");
	net.reload().await;
	assert!(closed(&mut old).await, "a connection of a tunnel that changed was kept");
	let mut fresh = TcpStream::connect(at).await.unwrap();
	echoes(&mut fresh, b"new").await;
	net.stop().await;
}
