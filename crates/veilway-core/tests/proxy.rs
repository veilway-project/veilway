//! The `socks5`, `http` and `mixed` inbounds against a node that runs in this process: logins, what is carried and what is refused, UDP ASSOCIATE, the counters, and the cut-off of a connection by a quota, a disable and a reload. The destinations are servers on an address of this host that is not loopback, since the destination gate refuses loopback.
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use veilway_core::config::Config;
use veilway_core::{Engine, Options, Reason};

const ALICE: &str = "alice-secret-pass-01";
const CAROL: &str = "carol-secret-pass-01";

/// An address of this host that is not loopback, which the gate lets a destination be.
fn own() -> Option<IpAddr> {
	let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
	probe.connect("192.0.2.1:9").ok()?;
	Some(probe.local_addr().ok()?.ip()).filter(|ip| ip.is_ipv4() && !ip.is_loopback())
}

/// A loopback address with a port nothing holds.
fn free() -> SocketAddr {std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()}

/// A server that sends back every byte until the client closes.
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

/// An HTTP server that answers with the head it was sent as the body, and closes.
async fn origin(at: IpAddr) -> SocketAddr {
	let listener = TcpListener::bind((at, 0)).await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut client, _)) = listener.accept().await {
			tokio::spawn(async move {
				let mut head = Vec::new();
				let mut chunk = [0u8; 1024];
				while !head.windows(4).any(|window| window == b"\r\n\r\n") {
					match client.read(&mut chunk).await {
						Ok(n) if n > 0 => head.extend_from_slice(&chunk[..n]),
						_ => return,
					}
				}
				let _ = client.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", head.len()).as_bytes()).await;
				let _ = client.write_all(&head).await;
			});
		}
	});
	addr
}

/// A UDP server that sends back every datagram.
async fn udp_echo(at: IpAddr) -> SocketAddr {
	let socket = UdpSocket::bind((at, 0)).await.unwrap();
	let addr = socket.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buffer = vec![0u8; 2048];
		while let Ok((n, from)) = socket.recv_from(&mut buffer).await {let _ = socket.send_to(&buffer[..n], from).await;}
	});
	addr
}

/// A DNS server that answers every A query with `answer`.
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

fn user(name: &str, password: Option<&str>, byte: u8) -> Value {
	let mut user = json!({"name": name, "exits": "all", "devices": [{"name": "laptop", "public_key": veilway_wg::encode_key(&[byte; 32]), "addresses": [format!("10.7.0.{}", byte - 0x20 + 1)]}]});
	if let Some(password) = password {user["proxy_password"] = json!(password)}
	user
}

/// A node with a tunnel inbound, the users alice and carol (with a proxy password) and bob (without), and `proxies`.
fn document(dns: SocketAddr, proxies: Vec<Value>) -> Value {
	let mut inbounds = vec![json!({"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&[0x11; 32]), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": free().to_string()}]})];
	inbounds.extend(proxies);
	json!({
		"version": 1,
		"dns": {"servers": [dns.to_string()]},
		"inbounds": inbounds,
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": []},
		"users": [user("alice", Some(ALICE), 0x21), user("bob", None, 0x22), user("carol", Some(CAROL), 0x23)]
	})
}

struct Node {engine: Engine, doc: Value}

impl Node {
	async fn start(doc: Value) -> Node {
		let config = Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("the test config does not parse: {e}"));
		let report = config.validate(false);
		assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
		let engine = veilway_core::start(&config, Options {is_local: |_| false, ..Options::new("")}).await.unwrap_or_else(|e| panic!("the node did not start: {e:#}"));
		Node {engine, doc}
	}

	async fn reload(&mut self, change: impl FnOnce(&mut Value)) {
		change(&mut self.doc);
		self.engine.reload(self.doc.to_string().into_bytes(), None).await.unwrap_or_else(|e| panic!("the reload was refused: {e}"));
	}

	fn dropped(&self, reason: Reason) -> u64 {self.engine.dropped(reason)}

	fn totals(&self, tag: &str) -> veilway_core::ProxyTotals {self.engine.proxies().into_iter().find(|(name, _)| name == tag).unwrap().1}
}

/// A node with one proxy inbound of each type, on loopback, and the servers of the tests on an address of this host.
struct Net {node: Node, socks: SocketAddr, http: SocketAddr, mixed: SocketAddr, echo: SocketAddr, origin: SocketAddr, own: IpAddr}

async fn net(extra: impl FnOnce(&mut Value)) -> Option<Net> {
	let own = own()?;
	let (socks, http, mixed) = (free(), free(), free());
	let resolved = echo(own).await;
	let mut doc = document(dns(own, own).await, vec![
		json!({"tag": "s", "type": "socks5", "listen": socks.to_string()}),
		json!({"tag": "h", "type": "http", "listen": http.to_string()}),
		json!({"tag": "m", "type": "mixed", "listen": mixed.to_string()}),
	]);
	extra(&mut doc);
	Some(Net {node: Node::start(doc).await, socks, http, mixed, echo: resolved, origin: origin(own).await, own})
}

enum Dest {Addr(SocketAddr), Name(&'static str, u16)}

fn encode(dest: &Dest) -> Vec<u8> {
	match dest {
		Dest::Addr(SocketAddr::V4(addr)) => [&[1][..], &addr.ip().octets(), &addr.port().to_be_bytes()].concat(),
		Dest::Addr(SocketAddr::V6(addr)) => [&[4][..], &addr.ip().octets(), &addr.port().to_be_bytes()].concat(),
		Dest::Name(name, port) => [&[3, name.len() as u8][..], name.as_bytes(), &port.to_be_bytes()].concat(),
	}
}

/// The greeting and the login of SOCKS5. The stream when the node accepted the login, and what it said when it did not.
async fn socks_login(at: SocketAddr, user: &str, pass: &str) -> Result<TcpStream, [u8; 2]> {socks_login_from(at, None, user, pass).await}

/// A connection to `at` from the address `from`, or from wherever the system picks.
async fn dial(at: SocketAddr, from: Option<IpAddr>) -> TcpStream {
	match from {
		Some(ip) => {
			let socket = tokio::net::TcpSocket::new_v4().unwrap();
			socket.bind(SocketAddr::new(ip, 0)).unwrap();
			socket.connect(at).await.unwrap()
		}
		None => TcpStream::connect(at).await.unwrap(),
	}
}

async fn socks_login_from(at: SocketAddr, from: Option<IpAddr>, user: &str, pass: &str) -> Result<TcpStream, [u8; 2]> {
	let mut stream = dial(at, from).await;
	stream.write_all(&[5, 2, 0, 2]).await.unwrap();
	let mut said = [0u8; 2];
	stream.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [5, 2], "the node did not choose username and password");
	stream.write_all(&[&[1, user.len() as u8][..], user.as_bytes(), &[pass.len() as u8], pass.as_bytes()].concat()).await.unwrap();
	stream.read_exact(&mut said).await.unwrap();
	if said == [1, 0] {Ok(stream)} else {Err(said)}
}

/// A request on a logged in SOCKS5 stream: the reply code, and the address it carries.
async fn socks_ask(stream: &mut TcpStream, command: u8, dest: &Dest) -> (u8, SocketAddr) {
	stream.write_all(&[&[5, command, 0][..], &encode(dest)].concat()).await.unwrap();
	let mut head = [0u8; 4];
	stream.read_exact(&mut head).await.unwrap();
	let ip: IpAddr = match head[3] {
		1 => {
			let mut raw = [0u8; 4];
			stream.read_exact(&mut raw).await.unwrap();
			raw.into()
		}
		_ => {
			let mut raw = [0u8; 16];
			stream.read_exact(&mut raw).await.unwrap();
			raw.into()
		}
	};
	let mut port = [0u8; 2];
	stream.read_exact(&mut port).await.unwrap();
	(head[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
}

/// A connection through the SOCKS5 inbound at `at` as `user`, to `dest`.
async fn socks_connect(at: SocketAddr, user: &str, pass: &str, dest: &Dest) -> Result<TcpStream, u8> {
	let mut stream = socks_login(at, user, pass).await.map_err(|_| 0xff_u8)?;
	match socks_ask(&mut stream, 1, dest).await {
		(0, _) => Ok(stream),
		(code, _) => Err(code),
	}
}

fn basic(user: &str, pass: &str) -> String {
	let mut text = String::new();
	let raw = format!("{user}:{pass}");
	for chunk in raw.as_bytes().chunks(3) {
		let n = u32::from_be_bytes([0, chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)]);
		for i in 0..4 {
			text.push(if i <= chunk.len() {b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(n >> (18 - 6 * i) & 63) as usize] as char} else {'='});
		}
	}
	text
}

/// Everything the stream sends until it closes, within `wait` seconds.
async fn all(stream: &mut TcpStream, wait: u64) -> Vec<u8> {
	let mut out = Vec::new();
	let _ = timeout(Duration::from_secs(wait), stream.read_to_end(&mut out)).await;
	out
}

/// An HTTP request through the inbound at `at`, and everything that comes back.
async fn http(at: SocketAddr, request: &str) -> String {
	let mut stream = TcpStream::connect(at).await.unwrap();
	stream.write_all(request.as_bytes()).await.unwrap();
	String::from_utf8_lossy(&all(&mut stream, 5).await).to_string()
}

/// The status line and the connection after it: a stream that is read to its end.
fn status(answer: &str) -> &str {answer.lines().next().unwrap_or("")}

#[tokio::test]
async fn socks5_connect_logs_in_and_carries_bytes() {
	let Some(net) = net(|_| {}).await else {return};
	let mut stream = socks_connect(net.socks, "alice", ALICE, &Dest::Addr(net.echo)).await.expect("the connection was refused");
	stream.write_all(b"hello through socks5").await.unwrap();
	let mut back = [0u8; 20];
	timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await.unwrap().unwrap();
	assert_eq!(&back, b"hello through socks5");
	let (user, exit) = (net.node.engine.user("alice").unwrap(), net.node.engine.exit("main").unwrap());
	assert!(user.up_bytes >= 20 && user.down_bytes >= 20 && exit.up_bytes >= 20 && exit.down_bytes >= 20, "{user:?} {exit:?}: the bytes were not counted for the user and the exit");
	let totals = net.node.totals("s");
	assert!(totals.opened == 1 && totals.open == 1 && totals.up_bytes == 20 && totals.down_bytes == 20, "{totals:?}");
	assert_eq!(net.node.engine.counters().inbounds.iter().find(|(tag, _)| tag == "s").map(|(_, totals)| (totals.up_bytes, totals.down_bytes)), Some((20, 20)), "the inbound has no bytes in the node's counters");
	drop(stream);
}

#[tokio::test]
async fn socks5_refuses_what_is_not_a_login() {
	let Some(net) = net(|_| {}).await else {return};
	for (user, pass) in [("alice", "not-her-password-123"), ("alice", "x"), ("nobody", ALICE), ("bob", ALICE), ("alice", CAROL)] {
		let refused = socks_login(net.socks, user, pass).await;
		assert!(matches!(refused, Err([1, 1])), "{user}: a login that is not one was taken");
	}
	assert_eq!(net.node.totals("s").refused_logins, 5);
	let mut bare = TcpStream::connect(net.socks).await.unwrap();
	bare.write_all(&[5, 1, 0]).await.unwrap();
	let mut said = [0u8; 2];
	bare.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [5, 0xff], "a client that offers no login was let in");
	assert!(all(&mut bare, 3).await.is_empty(), "the connection was kept");
	let mut wrong = TcpStream::connect(net.socks).await.unwrap();
	wrong.write_all(&[4, 1, 0]).await.unwrap();
	assert!(all(&mut wrong, 3).await.is_empty(), "SOCKS4 was answered");
}

#[tokio::test]
async fn socks5_refuses_bind_and_what_the_gate_refuses() {
	let Some(net) = net(|_| {}).await else {return};
	let mut stream = socks_login(net.socks, "alice", ALICE).await.unwrap();
	assert_eq!(socks_ask(&mut stream, 2, &Dest::Addr(net.echo)).await.0, 7, "BIND was not refused with 7");
	for dest in ["127.0.0.1:9", "[::1]:9", "169.254.169.254:80", "0.0.0.0:80", "[::ffff:127.0.0.1]:80"] {
		let gate = net.node.dropped(Reason::Gate);
		let refused = socks_connect(net.socks, "alice", ALICE, &Dest::Addr(dest.parse().unwrap())).await;
		assert!(matches!(refused, Err(2)), "{dest}: {refused:?}");
		assert_eq!(net.node.dropped(Reason::Gate), gate + 1, "{dest} was not counted for the gate");
	}
	assert!(matches!(socks_connect(net.socks, "alice", ALICE, &Dest::Addr(SocketAddr::new(net.own, 0))).await, Err(2)), "port 0 was carried");
}

#[tokio::test]
async fn socks5_resolves_a_name_through_the_nodes_dns() {
	let Some(net) = net(|_| {}).await else {return};
	let mut stream = socks_connect(net.socks, "alice", ALICE, &Dest::Name("Anything.Example", net.echo.port())).await.expect("a name was not resolved");
	stream.write_all(b"by name").await.unwrap();
	let mut back = [0u8; 7];
	timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await.unwrap().unwrap();
	assert_eq!(&back, b"by name");
}

#[tokio::test]
async fn socks5_carries_udp_for_the_address_that_asked_and_for_no_other() {
	let Some(net) = net(|_| {}).await else {return};
	let echoed = udp_echo(net.own).await;
	let mut control = socks_login(net.socks, "alice", ALICE).await.unwrap();
	let (code, relay) = socks_ask(&mut control, 3, &Dest::Addr("0.0.0.0:0".parse().unwrap())).await;
	assert_eq!((code, relay.ip()), (0, net.socks.ip()), "the relay is not on the address the client connected to");
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let datagram = [&[0, 0, 0][..], &encode(&Dest::Addr(echoed)), b"hello"].concat();
	let ask = async |socket: &UdpSocket, datagram: &[u8], wait: u64| {
		let mut buffer = vec![0u8; 2048];
		socket.send_to(datagram, relay).await.unwrap();
		timeout(Duration::from_millis(wait), socket.recv_from(&mut buffer)).await.ok().map(|received| buffer[..received.unwrap().0].to_vec())
	};
	assert!(ask(&client, &datagram, 3000).await.expect("no answer through the relay").ends_with(b"hello"));
	let spoofed = net.node.dropped(Reason::SpoofedSource);
	let stranger = UdpSocket::bind("127.0.0.2:0").await.unwrap();
	assert!(ask(&stranger, &datagram, 300).await.is_none(), "a datagram from another address was carried");
	assert_eq!(net.node.dropped(Reason::SpoofedSource), spoofed + 1);
	let (fragments, mut fragment) = (net.node.dropped(Reason::Fragment), datagram.clone());
	fragment[2] = 1;
	assert!(ask(&client, &fragment, 300).await.is_none(), "a fragment was carried");
	assert_eq!(net.node.dropped(Reason::Fragment), fragments + 1);
	let gate = net.node.dropped(Reason::Gate);
	assert!(ask(&client, &[&[0, 0, 0][..], &encode(&Dest::Addr("127.0.0.1:9".parse().unwrap())), b"x"].concat(), 300).await.is_none());
	assert_eq!(net.node.dropped(Reason::Gate), gate + 1, "a datagram to loopback was not refused by the gate");
	assert!(ask(&client, &datagram, 3000).await.is_some(), "the association stopped answering its own address");
	drop(control);
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert!(ask(&client, &datagram, 300).await.is_none(), "the association outlived its control connection");
}

#[tokio::test]
async fn socks5_udp_is_refused_where_it_is_off() {
	let Some(net) = net(|doc| doc["inbounds"][1]["udp"] = json!(false)).await else {return};
	let mut control = socks_login(net.socks, "alice", ALICE).await.unwrap();
	assert_eq!(socks_ask(&mut control, 3, &Dest::Addr("0.0.0.0:0".parse().unwrap())).await.0, 7);
}

#[tokio::test]
async fn http_connect_and_a_plain_request_are_carried() {
	let Some(net) = net(|_| {}).await else {return};
	let auth = basic("alice", ALICE);
	let mut stream = TcpStream::connect(net.http).await.unwrap();
	stream.write_all(format!("CONNECT {} HTTP/1.1\r\nHost: {0}\r\nProxy-Authorization: Basic {auth}\r\n\r\nearly", net.echo).as_bytes()).await.unwrap();
	let mut said = vec![0u8; "HTTP/1.1 200 Connection Established\r\n\r\n".len()];
	timeout(Duration::from_secs(5), stream.read_exact(&mut said)).await.unwrap().unwrap();
	assert!(said.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&said));
	stream.write_all(b" late").await.unwrap();
	let mut back = [0u8; 10];
	timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await.unwrap().unwrap();
	assert_eq!(&back, b"early late", "what came with the request, and after it, was not carried");
	let answer = http(net.http, &format!("GET http://{}/a/b?c=d HTTP/1.1\r\nHost: wrong.example\r\nProxy-Authorization: Basic {auth}\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nX-Custom: kept\r\n\r\n", net.origin)).await;
	assert_eq!(status(&answer), "HTTP/1.1 200 OK", "{answer}");
	let sent = answer.split_once("\r\n\r\n").unwrap().1;
	assert!(sent.starts_with("GET /a/b?c=d HTTP/1.1\r\n") && sent.contains(&format!("Host: {}\r\n", net.origin)) && sent.contains("X-Custom: kept\r\n") && sent.ends_with("Connection: close\r\n\r\n"), "{sent}");
	assert!(!sent.to_ascii_lowercase().contains("proxy-") && !sent.contains("wrong.example") && !sent.contains("keep-alive"), "{sent}");
	let totals = net.node.totals("h");
	assert!(totals.opened == 2 && totals.up_bytes > 0 && totals.down_bytes > 0, "{totals:?}");
}

#[tokio::test]
async fn http_asks_for_a_login_and_refuses_what_it_does_not_take() {
	let Some(net) = net(|_| {}).await else {return};
	let target = net.origin;
	for request in [format!("GET http://{target}/ HTTP/1.1\r\n\r\n"), format!("CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", basic("alice", "wrong-password-0001")), format!("GET http://{target}/ HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", basic("bob", ALICE)), format!("GET http://{target}/ HTTP/1.1\r\nProxy-Authorization: Bearer abc\r\n\r\n")] {
		let answer = http(net.http, &request).await;
		assert_eq!(status(&answer), "HTTP/1.1 407 Proxy Authentication Required", "{request:?}: {answer}");
		assert!(answer.contains("Proxy-Authenticate: Basic realm=\"proxy\"\r\n") && answer.contains("Connection: close\r\n"), "{answer}");
	}
	assert_eq!(net.node.totals("h").refused_logins, 3, "a request without a login is no failed login, and one with a wrong login is");
	let auth = basic("alice", ALICE);
	let big = http(net.http, &format!("GET http://{target}/ HTTP/1.1\r\nX-Big: {}\r\nProxy-Authorization: Basic {auth}\r\n\r\n", "a".repeat(9000))).await;
	assert_eq!(status(&big), "HTTP/1.1 431 Request Header Fields Too Large", "{big}");
	for (what, request) in [
		("both framings", format!("POST http://{target}/ HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nProxy-Authorization: Basic {auth}\r\n\r\n")),
		("https", format!("GET https://{target}/ HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")),
		("origin form", format!("GET / HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n")),
		("folded", format!("GET http://{target}/ HTTP/1.1\r\nX: a\r\n b\r\nProxy-Authorization: Basic {auth}\r\n\r\n")),
	] {
		let answer = http(net.http, &request).await;
		assert_eq!(status(&answer), "HTTP/1.1 400 Bad Request", "{what}: {answer}");
	}
	let blocked = http(net.http, &format!("CONNECT 127.0.0.1:9 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")).await;
	assert_eq!(status(&blocked), "HTTP/1.1 403 Forbidden", "{blocked}");
	let dead = http(net.http, &format!("CONNECT {}:1 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n", net.own)).await;
	assert_eq!(status(&dead), "HTTP/1.1 502 Bad Gateway", "{dead}");
}

#[tokio::test]
async fn a_request_written_behind_another_never_reaches_the_origin() {
	let Some(net) = net(|_| {}).await else {return};
	let (got, listener) = (std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new())), TcpListener::bind((net.own, 0)).await.unwrap());
	let target = listener.local_addr().unwrap();
	let seen = got.clone();
	tokio::spawn(async move {
		let (mut client, _) = listener.accept().await.unwrap();
		let mut chunk = [0u8; 1024];
		let _ = client.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
		let _ = timeout(Duration::from_millis(800), async {
			while let Ok(n) = client.read(&mut chunk).await {
				if n == 0 {break}
				seen.lock().unwrap().extend_from_slice(&chunk[..n]);
			}
		}).await;
	});
	let auth = basic("alice", ALICE);
	let (first, second) = (format!("POST http://{target}/one HTTP/1.1\r\nContent-Length: 4\r\nProxy-Authorization: Basic {auth}\r\n\r\nabcd"), format!("GET http://{target}/two HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n"));
	let mut stream = TcpStream::connect(net.http).await.unwrap();
	stream.write_all(format!("{first}{second}").as_bytes()).await.unwrap();
	let mut answer = vec![0u8; 20];
	timeout(Duration::from_secs(5), stream.read_exact(&mut answer)).await.unwrap().unwrap();
	assert!(answer.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&answer));
	stream.write_all(second.as_bytes()).await.unwrap();
	tokio::time::sleep(Duration::from_millis(1000)).await;
	let received = String::from_utf8_lossy(&got.lock().unwrap()).to_string();
	assert!(received.starts_with("POST /one HTTP/1.1\r\n") && received.ends_with("Connection: close\r\n\r\nabcd"), "{received}");
	assert!(!received.contains("/two") && !received.to_ascii_lowercase().contains("proxy-authorization"), "the origin was sent what was written behind the request: {received}");
}

#[tokio::test]
async fn mixed_serves_socks5_and_http_on_one_port() {
	let Some(net) = net(|_| {}).await else {return};
	let mut socks = socks_connect(net.mixed, "alice", ALICE, &Dest::Addr(net.echo)).await.expect("the mixed port did not serve SOCKS5");
	socks.write_all(b"one").await.unwrap();
	let mut back = [0u8; 3];
	timeout(Duration::from_secs(5), socks.read_exact(&mut back)).await.unwrap().unwrap();
	assert_eq!(&back, b"one");
	let answer = http(net.mixed, &format!("GET http://{}/ HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", net.origin, basic("alice", ALICE))).await;
	assert_eq!(status(&answer), "HTTP/1.1 200 OK", "the mixed port did not serve HTTP: {answer}");
	assert!(http(net.mixed, "GET http://example.com/ HTTP/1.1\r\n\r\n").await.starts_with("HTTP/1.1 407"));
	let mut control = socks_login(net.mixed, "alice", ALICE).await.unwrap();
	assert_eq!(socks_ask(&mut control, 3, &Dest::Addr("0.0.0.0:0".parse().unwrap())).await.0, 0, "the mixed port did not take UDP ASSOCIATE");
}

#[tokio::test]
async fn a_socks5_inbound_does_not_answer_http_and_an_http_inbound_answers_garbage_with_a_bad_request() {
	let Some(net) = net(|_| {}).await else {return};
	assert!(http(net.socks, "GET http://example.com/ HTTP/1.1\r\n\r\n").await.is_empty(), "a socks5 inbound answered HTTP");
	let mut garbage = TcpStream::connect(net.http).await.unwrap();
	garbage.write_all(&[5, 1, 2, b'\r', b'\n', b'\r', b'\n']).await.unwrap();
	assert!(String::from_utf8_lossy(&all(&mut garbage, 5).await).starts_with("HTTP/1.1 400"));
}

#[tokio::test]
async fn a_connection_that_never_logs_in_is_closed_and_one_source_cannot_hold_more_than_its_share() {
	let Some(net) = net(|doc| doc["inbounds"][1]["limits"] = json!({"per_source": 2})).await else {return};
	let from = Some(net.own);
	let (first, second) = (dial(net.socks, from).await, dial(net.socks, from).await);
	let mut third = dial(net.socks, from).await;
	assert!(timeout(Duration::from_secs(3), third.read(&mut [0u8; 1])).await.unwrap().map_or(true, |n| n == 0), "a third connection of one source was held");
	assert_eq!(net.node.totals("s").refused_source, 1);
	let mut other = dial(net.socks, Some("127.0.0.2".parse().unwrap())).await;
	assert!(timeout(Duration::from_millis(300), other.read(&mut [0u8; 1])).await.is_err(), "another source was refused for what the first held");
	drop((first, second));
}

#[tokio::test]
async fn a_loopback_peer_is_a_front_with_many_users_behind_it_and_is_held_to_neither_a_share_nor_a_block() {
	let Some(net) = net(|doc| doc["inbounds"][1]["limits"] = json!({"per_source": 2})).await else {return};
	let mut held = Vec::new();
	for _ in 0..5 {held.push(TcpStream::connect(net.socks).await.unwrap())}
	assert!(socks_login(net.socks, "alice", ALICE).await.is_ok(), "a loopback peer was held to a share of a source");
	assert_eq!(net.node.totals("s").refused_source, 0);
	for _ in 0..11 {assert!(socks_login(net.socks, "carol", "not-her-password-123").await.is_err())}
	assert!(socks_login(net.socks, "carol", CAROL).await.is_ok(), "a loopback peer was blocked for failures behind it");
	assert_eq!(net.node.totals("s").refused_blocked, 0);
	drop(held);
}

#[tokio::test]
async fn a_source_that_fails_too_many_logins_is_turned_away() {
	let Some(net) = net(|_| {}).await else {return};
	let from = Some(net.own);
	for _ in 0..10 {assert!(socks_login_from(net.socks, from, "alice", "not-her-password-123").await.is_err())}
	assert!(matches!(socks_login_from(net.socks, from, "alice", ALICE).await, Err([1, 1])), "a source with ten failed logins to a name was heard for it");
	assert_eq!(net.node.totals("s").refused_blocked, 1);
	assert!(socks_login_from(net.socks, from, "carol", CAROL).await.is_ok(), "the block of a name reached another name from the same source");
	let auth = basic("alice", ALICE);
	assert_eq!(status(&http(net.http, &format!("GET http://{}/ HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n", net.origin)).await), "HTTP/1.1 200 OK", "the block of one inbound reached another");
}

/// Whether the stream was closed by the node within `wait` seconds.
async fn closed(stream: &mut TcpStream, wait: u64) -> bool {
	let mut sink = [0u8; 4096];
	timeout(Duration::from_secs(wait), async {while stream.read(&mut sink).await.is_ok_and(|n| n > 0) {}}).await.is_ok()
}

#[tokio::test]
async fn a_user_who_runs_out_of_quota_is_cut_off_within_the_watch_period() {
	let Some(net) = net(|doc| doc["users"][2]["quota_bytes"] = json!(3000)).await else {return};
	let mut stream = socks_connect(net.socks, "carol", CAROL, &Dest::Addr(net.echo)).await.unwrap();
	let (mut read, mut write) = stream.split();
	let sent = async {
		for _ in 0..10 {
			if write.write_all(&[7u8; 1000]).await.is_err() {return}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	};
	let drained = async {
		let mut sink = [0u8; 4096];
		while read.read(&mut sink).await.is_ok_and(|n| n > 0) {}
	};
	let cut = tokio::time::Instant::now();
	assert!(timeout(Duration::from_secs(5), async {tokio::join!(sent, drained)}).await.is_ok(), "the connection of a user over quota was kept");
	assert!(cut.elapsed() < Duration::from_secs(4), "the cut-off took {:?}", cut.elapsed());
	let mut again = socks_login(net.socks, "carol", CAROL).await.unwrap();
	assert_eq!(socks_ask(&mut again, 1, &Dest::Addr(net.echo)).await.0, 2, "a user over quota was let in again");
}

#[tokio::test]
async fn a_reload_ends_the_connections_it_leaves_without_a_login() {
	let Some(mut net) = net(|_| {}).await else {return};
	let mut by_socks = socks_connect(net.socks, "alice", ALICE, &Dest::Addr(net.echo)).await.unwrap();
	let mut by_carol = socks_connect(net.socks, "carol", CAROL, &Dest::Addr(net.echo)).await.unwrap();
	let mut by_http = TcpStream::connect(net.http).await.unwrap();
	by_http.write_all(format!("CONNECT {} HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", net.echo, basic("alice", ALICE)).as_bytes()).await.unwrap();
	let mut said = vec![0u8; "HTTP/1.1 200 Connection Established\r\n\r\n".len()];
	by_http.read_exact(&mut said).await.unwrap();
	net.node.reload(|doc| doc["users"][0]["proxy_password"] = json!("a-new-password-0001")).await;
	assert!(closed(&mut by_socks, 5).await && closed(&mut by_http, 5).await, "a connection kept its login after the password changed");
	assert!(by_carol.write_all(b"still here").await.is_ok());
	let mut back = [0u8; 10];
	timeout(Duration::from_secs(5), by_carol.read_exact(&mut back)).await.unwrap().unwrap();
	assert_eq!(&back, b"still here", "a reload that changed alice's password ended carol's connection");
	assert!(socks_login(net.socks, "alice", ALICE).await.is_err(), "the old password still works");
	let mut again = socks_connect(net.socks, "alice", "a-new-password-0001", &Dest::Addr(net.echo)).await.expect("the new password does not work");
	net.node.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	assert!(closed(&mut again, 5).await, "a disabled user kept a connection");
	let mut denied = socks_login(net.socks, "alice", "a-new-password-0001").await.unwrap();
	assert_eq!(socks_ask(&mut denied, 1, &Dest::Addr(net.echo)).await.0, 2, "a disabled user was carried");
	net.node.reload(|doc| doc["users"].as_array_mut().unwrap().retain(|user| user["name"] != "carol")).await;
	assert!(closed(&mut by_carol, 5).await, "a removed user kept a connection");
}

#[tokio::test]
async fn a_reload_that_removes_an_inbound_closes_its_connections_and_its_port() {
	let Some(mut net) = net(|_| {}).await else {return};
	let mut held = socks_connect(net.socks, "alice", ALICE, &Dest::Addr(net.echo)).await.unwrap();
	let mut other = socks_connect(net.mixed, "alice", ALICE, &Dest::Addr(net.echo)).await.unwrap();
	net.node.reload(|doc| doc["inbounds"].as_array_mut().unwrap().retain(|inbound| inbound["tag"] != "s")).await;
	assert!(closed(&mut held, 5).await, "an inbound that was removed kept a connection");
	let mut tries = 0;
	while TcpStream::connect(net.socks).await.is_ok() && tries < 100 {
		tries += 1;
		tokio::time::sleep(Duration::from_millis(30)).await;
	}
	assert!(TcpStream::connect(net.socks).await.is_err(), "the port of a removed inbound still answers");
	assert!(other.write_all(b"x").await.is_ok() && net.node.engine.proxies().len() == 2, "another inbound was touched");
	net.node.reload(|doc| doc["inbounds"][2]["users"] = json!(["carol"])).await;
	assert!(closed(&mut other, 5).await, "a user the inbound no longer admits kept a connection");
	assert!(matches!(socks_login(net.mixed, "alice", ALICE).await, Err([1, 1])), "a user the inbound does not admit logged in");
}

/// The seeds of the `proxy_front` fuzz target read as what their names say, so that a change to a reader that breaks one is noticed.
#[test]
fn the_seeds_of_the_fuzz_target_read() {
	use veilway_core::engine::{proxy_http, proxy_socks};
	let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/proxy_front");
	let mut seen = 0;
	for entry in std::fs::read_dir(dir).unwrap() {
		let entry = entry.unwrap();
		let (name, bytes) = (entry.file_name().to_string_lossy().to_string(), std::fs::read(entry.path()).unwrap());
		let input = &bytes[1..];
		let read = match name.as_str() {
			"socks_greeting" => proxy_socks::greeting(input).map(|read| read.is_some()).unwrap_or(false),
			"socks_login" => proxy_socks::credentials(input).map(|read| read.is_some()).unwrap_or(false),
			"http_both_framings" | "http_folded" => proxy_http::read(input).is_err(),
			name if name.starts_with("socks_") => proxy_socks::request(input).map(|read| read.is_some()).unwrap_or(false),
			_ => proxy_http::read(input).map(|read| read.is_some()).unwrap_or(false),
		};
		assert!(read, "{name} no longer reads as what its name says");
		seen += 1;
	}
	assert_eq!(seen, 11);
}

/// A user who only logs in to proxy inbounds: no devices.
fn proxy_only(name: &str, password: &str) -> Value {json!({"name": name, "exits": "all", "proxy_password": password, "devices": []})}

const DAVE: &str = "dave-secret-pass-001";

#[tokio::test]
async fn a_user_with_no_device_logs_in_and_is_counted_and_held_to_a_quota() {
	let Some(net) = net(|doc| {
		doc["users"].as_array_mut().unwrap().push(proxy_only("dave", DAVE));
		doc["users"][3]["quota_bytes"] = json!(3000);
	}).await else {return};
	let mut stream = socks_connect(net.socks, "dave", DAVE, &Dest::Addr(net.echo)).await.expect("a user with no device was refused");
	stream.write_all(b"proxy only").await.unwrap();
	let mut back = [0u8; 10];
	timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await.unwrap().unwrap();
	let counters = net.node.engine.counters();
	let dave = counters.users.iter().find(|usage| usage.name == "dave").expect("the user is not in the counters");
	assert!(dave.traffic.up_bytes >= 10 && dave.traffic.down_bytes >= 10 && dave.used_bytes >= 20 && dave.quota_bytes == Some(3000), "{dave:?}");
	let (mut read, mut write) = stream.split();
	let sent = async {
		for _ in 0..10 {
			if write.write_all(&[7u8; 1000]).await.is_err() {return}
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	};
	let drained = async {
		let mut sink = [0u8; 4096];
		while read.read(&mut sink).await.is_ok_and(|n| n > 0) {}
	};
	assert!(timeout(Duration::from_secs(5), async {tokio::join!(sent, drained)}).await.is_ok(), "the connection of a user over quota was kept");
	let mut again = socks_login(net.socks, "dave", DAVE).await.unwrap();
	assert_eq!(socks_ask(&mut again, 1, &Dest::Addr(net.echo)).await.0, 2, "a user with no device was let in over quota");
	assert!(matches!(socks_login(net.socks, "dave", ALICE).await, Err([1, 1])));
}

#[tokio::test]
async fn a_rule_scoped_by_inbound_applies_to_that_inbound_alone() {
	let Some(own) = own() else {return};
	let Some(net) = net(|doc| doc["routing"]["rules"] = json!([{"tag": "no-echo-on-s", "inbound": ["s"], "ip": [format!("{own}/32")], "action": "block"}])).await else {return};
	let rule = net.node.dropped(Reason::Rule);
	assert!(matches!(socks_connect(net.socks, "alice", ALICE, &Dest::Addr(net.echo)).await, Err(2)), "a rule scoped to the socks5 inbound did not apply to it");
	assert_eq!(net.node.dropped(Reason::Rule), rule + 1);
	assert!(socks_connect(net.mixed, "alice", ALICE, &Dest::Addr(net.echo)).await.is_ok(), "the rule reached another inbound");
	let blocked = http(net.http, &format!("CONNECT {} HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n", net.echo, basic("alice", ALICE))).await;
	assert!(blocked.starts_with("HTTP/1.1 200"), "the rule reached the http inbound: {blocked}");
}

#[tokio::test]
async fn a_user_holds_no_more_connections_than_their_share_across_every_proxy_inbound() {
	let Some(net) = net(|doc| for at in [1, 2] {doc["inbounds"][at]["limits"] = json!({"connections": 5000})}).await else {return};
	let mut held = Vec::new();
	for _ in 0..600 {held.push(socks_connect(net.socks, "alice", ALICE, &Dest::Addr(net.echo)).await.expect("a connection within the share was refused"))}
	let (mut taken, mut refused) = (0, 0);
	let auth = basic("alice", ALICE);
	for _ in 0..600 {
		let mut stream = TcpStream::connect(net.http).await.unwrap();
		stream.write_all(format!("CONNECT {} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n", net.echo).as_bytes()).await.unwrap();
		let mut head = [0u8; 12];
		timeout(Duration::from_secs(5), stream.read_exact(&mut head)).await.unwrap().unwrap();
		if head.starts_with(b"HTTP/1.1 200") {taken += 1; held.push(stream)} else {refused += 1}
	}
	assert!(refused > 0 && 600 + taken <= 1024, "{taken} taken and {refused} refused through the second inbound after 600 through the first: the share is not the user's");
	let mut another = socks_login(net.mixed, "carol", CAROL).await.unwrap();
	assert_eq!(socks_ask(&mut another, 1, &Dest::Addr(net.echo)).await.0, 0, "another user was held to what alice holds");
	drop(held);
}

#[tokio::test]
async fn udp_on_an_address_that_strangers_may_reach_needs_the_port_the_client_sends_from() {
	let Some(mut net) = net(|_| {}).await else {return};
	let addr = SocketAddr::new(net.own, std::net::TcpListener::bind((net.own, 0)).unwrap().local_addr().unwrap().port());
	net.node.reload(|doc| {
		doc["inbounds"][1]["listen"] = json!(addr.to_string());
		doc["inbounds"][1]["public"] = json!(true);
	}).await;
	let echoed = udp_echo(net.own).await;
	let mut control = socks_login(addr, "alice", ALICE).await.unwrap();
	assert_eq!(socks_ask(&mut control, 3, &Dest::Addr("0.0.0.0:0".parse().unwrap())).await.0, 2, "an association with no port was granted where no owner can be looked up");
	let client = UdpSocket::bind((net.own, 0)).await.unwrap();
	let mut control = socks_login(addr, "alice", ALICE).await.unwrap();
	let (code, relay) = socks_ask(&mut control, 3, &Dest::Addr(client.local_addr().unwrap())).await;
	assert_eq!((code, relay.ip()), (0, net.own));
	let datagram = [&[0, 0, 0][..], &encode(&Dest::Addr(echoed)), b"hello"].concat();
	let ask = async |socket: &UdpSocket| {
		let mut buffer = vec![0u8; 2048];
		socket.send_to(&datagram, relay).await.unwrap();
		timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await.is_ok()
	};
	let neighbour = UdpSocket::bind((net.own, 0)).await.unwrap();
	let spoofed = net.node.dropped(Reason::SpoofedSource);
	assert!(!ask(&neighbour).await, "a sender on the client's address but not its port took the association");
	assert_eq!(net.node.dropped(Reason::SpoofedSource), spoofed + 1);
	assert!(ask(&client).await, "the client got no answer");
}

#[tokio::test]
async fn a_rule_by_transport_tells_a_socks5_connection_from_an_http_one_even_on_a_mixed_inbound() {
	let Some(own) = own() else {return};
	let Some(net) = net(|doc| doc["routing"]["rules"] = json!([{"tag": "no-http", "transport": ["http"], "ip": [format!("{own}/32")], "action": "block"}])).await else {return};
	assert!(socks_connect(net.socks, "alice", ALICE, &Dest::Addr(net.echo)).await.is_ok());
	assert!(socks_connect(net.mixed, "alice", ALICE, &Dest::Addr(net.echo)).await.is_ok(), "a SOCKS5 connection on a mixed inbound was taken for http");
	let auth = basic("alice", ALICE);
	for at in [net.http, net.mixed] {
		let answer = http(at, &format!("CONNECT {} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n", net.echo)).await;
		assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
	}
}
