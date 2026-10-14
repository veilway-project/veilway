//! `veilway doctor` against fakes on the loopback: DNS servers that answer over UDP only or over both, SOCKS5 proxies with and without UDP ASSOCIATE, one that wants a password and one that names a relay on another host,
//! ports that are taken, and certificates that are good, about to end, expired and of another key. The binary is run the way a user runs it, so what is held against the fakes is its lines, its JSON document and its exit status.
#![cfg(unix)]
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

const USER: &str = "doctor-user-7f3a";
const PASSWORD: &str = "doctor-pass-91c2";
const WRONG: &str = "doctor-wrong-55d0";
/// Listen addresses come from below the range the system hands out by itself, so nothing a fake opens while doctor runs can take one first.
static NEXT_PORT: AtomicU16 = AtomicU16::new(23100);

/// A loopback address whose port nothing holds, over UDP or over TCP.
fn free() -> SocketAddr {
	loop {
		let addr = SocketAddr::from(([127, 0, 0, 1], NEXT_PORT.fetch_add(1, Ordering::Relaxed)));
		if std::net::UdpSocket::bind(addr).is_ok() && std::net::TcpListener::bind(addr).is_ok() {return addr}
	}
}

/// The first address of this machine that is not loopback, which is where a DNS server of a config may be.
fn host() -> IpAddr {
	let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
	match probe.connect("192.0.2.1:9").and_then(|_| probe.local_addr()).map(|local| local.ip()) {
		Ok(ip) if !ip.is_loopback() && !ip.is_unspecified() => ip,
		other => panic!("this test needs a non-loopback IPv4 address on the machine, found {other:?}"),
	}
}

/// The query as a response with no records.
fn answer(query: &[u8]) -> Vec<u8> {
	let mut answer = query.to_vec();
	if let Some(flags) = answer.get_mut(2..4) {(flags[0], flags[1]) = (flags[0] | 0x80, 0x80)}
	answer
}

/// A DNS server that answers every query over UDP, and over TCP as well when `tcp` is set. Without it the TCP port is held and refuses every connection.
async fn dns(tcp: bool) -> SocketAddr {
	let (socket, udp) = loop {
		let socket = TcpSocket::new_v4().unwrap();
		socket.bind(SocketAddr::new(host(), 0)).unwrap();
		if let Ok(udp) = UdpSocket::bind(socket.local_addr().unwrap()).await {break (socket, udp)}
	};
	let addr = udp.local_addr().unwrap();
	let listener = if tcp {Ok(socket.listen(64).unwrap())} else {Err(socket)};
	tokio::spawn(async move {
		let mut query = [0u8; 512];
		loop {
			let accepted = async {
				match &listener {
					Ok(listener) => listener.accept().await,
					Err(_) => std::future::pending().await,
				}
			};
			tokio::select! {
				received = udp.recv_from(&mut query) => if let Ok((n, from)) = received {let _ = udp.send_to(&answer(&query[..n]), from).await;},
				accepted = accepted => {
					let Ok((mut stream, _)) = accepted else {continue};
					tokio::spawn(async move {
						let mut len = [0u8; 2];
						if stream.read_exact(&mut len).await.is_err() {return}
						let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
						if stream.read_exact(&mut query).await.is_err() {return}
						let answer = answer(&query);
						let _ = stream.write_all(&[&(answer.len() as u16).to_be_bytes()[..], &answer].concat()).await;
					});
				}
			}
		}
	});
	addr
}

/// What a fake proxy does: whether it gives a UDP ASSOCIATE, the user name and password it wants, and whether it names a relay on another host than itself.
#[derive(Clone, Copy, Default)]
struct Proxy {udp: bool, password: Option<(&'static str, &'static str)>, elsewhere: bool}

/// One connection to a fake proxy, for IPv4 destinations only.
async fn proxied(mut client: TcpStream, proxy: Proxy) -> std::io::Result<()> {
	let (mut head, mut request, mut dst, mut sink) = ([0u8; 2], [0u8; 4], [0u8; 6], [0u8; 1]);
	client.read_exact(&mut head).await?;
	let mut methods = vec![0u8; usize::from(head[1])];
	client.read_exact(&mut methods).await?;
	match proxy.password {
		Some(_) if !methods.contains(&2) => return client.write_all(&[5, 0xff]).await,
		Some((user, password)) => {
			client.write_all(&[5, 2]).await?;
			client.read_exact(&mut head).await?;
			let mut name = vec![0u8; usize::from(head[1])];
			client.read_exact(&mut name).await?;
			client.read_exact(&mut head[..1]).await?;
			let mut word = vec![0u8; usize::from(head[0])];
			client.read_exact(&mut word).await?;
			let known = name == user.as_bytes() && word == password.as_bytes();
			client.write_all(&[1, u8::from(!known)]).await?;
			if !known {return Ok(())}
		}
		None => client.write_all(&[5, 0]).await?,
	}
	client.read_exact(&mut request).await?;
	client.read_exact(&mut dst).await?;
	match request[1] {
		1 => match TcpStream::connect(SocketAddr::from(([dst[0], dst[1], dst[2], dst[3]], u16::from_be_bytes([dst[4], dst[5]])))).await {
			Ok(mut remote) => {
				client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
				tokio::io::copy_bidirectional(&mut client, &mut remote).await.map(drop)
			}
			Err(_) => client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await,
		},
		3 if proxy.udp => {
			let (relay, out) = (UdpSocket::bind("127.0.0.1:0").await?, UdpSocket::bind("0.0.0.0:0").await?);
			let (port, host) = (relay.local_addr()?.port().to_be_bytes(), if proxy.elsewhere {[192, 0, 2, 1]} else {[0, 0, 0, 0]});
			client.write_all(&[5, 0, 0, 1, host[0], host[1], host[2], host[3], port[0], port[1]]).await?;
			let (mut wrapped, mut reply, mut asker) = ([0u8; 2048], [0u8; 2048], None);
			loop {
				tokio::select! {
					received = relay.recv_from(&mut wrapped) => {
						let (n, from) = received?;
						if n < 10 || wrapped[3] != 1 {continue}
						asker = Some(from);
						out.send_to(&wrapped[10..n], SocketAddr::from(([wrapped[4], wrapped[5], wrapped[6], wrapped[7]], u16::from_be_bytes([wrapped[8], wrapped[9]])))).await?;
					}
					received = out.recv_from(&mut reply) => {
						let (n, _) = received?;
						if let Some(asker) = asker {relay.send_to(&[&[0, 0, 0, 1, 127, 0, 0, 1, 0, 53][..], &reply[..n]].concat(), asker).await?;}
					}
					_ = client.read(&mut sink) => return Ok(()),
				}
			}
		}
		_ => client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await,
	}
}

async fn socks5(proxy: Proxy) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let Ok((client, _)) = listener.accept().await else {continue};
			tokio::spawn(async move {let _ = proxied(client, proxy).await;});
		}
	});
	addr
}

/// A new directory for one test.
fn scratch(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-doctor-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// Writes `text` to `name` in `dir` for its owner alone.
fn private(dir: &Path, name: &str, text: &str) {
	std::fs::write(dir.join(name), text).unwrap();
	std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A self-signed certificate and its key as `<name>.crt` and `<name>.key` in `dir`, valid from `from` days to `until` days from now.
fn certificate(dir: &Path, name: &str, from: i64, until: i64) {
	let (mut params, key, now) = (rcgen::CertificateParams::new(vec!["doctor.test".to_string(), "*.doctor.test".to_string()]).unwrap(), rcgen::KeyPair::generate().unwrap(), time::OffsetDateTime::now_utc());
	(params.not_before, params.not_after) = (now + time::Duration::days(from), now + time::Duration::days(until));
	private(dir, &format!("{name}.crt"), &params.self_signed(&key).unwrap().pem());
	private(dir, &format!("{name}.key"), &key.serialize_pem());
}

/// A config with one inbound of the given transports and one exit for each outbound, and the secrets in it.
fn config(dir: &Path, servers: &[SocketAddr], transports: Value, outbounds: Value) -> Vec<String> {
	let (node, device, shared) = (veilway_wg::generate_key(), veilway_wg::generate_key(), veilway_wg::generate_key());
	let exits: Vec<Value> = outbounds.as_array().unwrap().iter().map(|outbound| json!({"tag": format!("via-{}", outbound["tag"].as_str().unwrap()), "backend": {"type": "netstack", "outbound": outbound["tag"]}})).collect();
	private(dir, "config.json", &json!({
		"version": 1,
		"dns": {"servers": servers.iter().map(|server| server.to_string()).collect::<Vec<_>>()},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&node), "address": ["10.7.0.1/24"], "transports": transports}],
		"outbounds": outbounds,
		"routing": {"default": exits[0]["tag"], "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"exits": exits,
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "phone", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&device)), "preshared_key": veilway_wg::encode_key(&shared), "addresses": ["10.7.0.2"]}]}],
	}).to_string());
	vec![veilway_wg::encode_key(&node), veilway_wg::encode_key(&shared), USER.to_string(), PASSWORD.to_string(), WRONG.to_string()]
}

/// Runs `veilway doctor` on the config in `dir`: its exit status, what it printed, and what it wrote to standard error.
async fn doctor(dir: &Path, args: &[&str]) -> (i32, String, String) {
	let done = tokio::process::Command::new(env!("CARGO_BIN_EXE_veilway")).arg("doctor").arg("--config").arg(dir.join("config.json")).args(["--timeout", "2"]).args(args).output().await.unwrap();
	(done.status.code().expect("doctor was killed"), String::from_utf8(done.stdout).unwrap(), String::from_utf8(done.stderr).unwrap())
}

/// The status of the one check of the JSON document whose subject begins with `subject`.
fn status<'a>(document: &'a Value, check: &str, subject: &str) -> &'a str {
	let found: Vec<&Value> = document["checks"].as_array().unwrap().iter().filter(|line| line["check"] == check && line["subject"].as_str().unwrap().starts_with(subject)).collect();
	assert_eq!(found.len(), 1, "{check} {subject} in {document:#}");
	found[0]["status"].as_str().unwrap()
}

fn listing(dir: &Path) -> BTreeSet<String> {std::fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect()}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_fault_has_its_own_line_and_no_secret_is_printed() {
	let dir = scratch("faults");
	let (both, udp_only) = (dns(true).await, dns(false).await);
	let (full, tcp_only, locked, elsewhere) = (socks5(Proxy {udp: true, ..Proxy::default()}).await, socks5(Proxy::default()).await, socks5(Proxy {udp: true, password: Some((USER, PASSWORD)), ..Proxy::default()}).await, socks5(Proxy {udp: true, elsewhere: true, ..Proxy::default()}).await);
	// Held for the whole test: a port that is taken over UDP, one that is taken over TCP, and one nothing listens on.
	let (taken_udp, taken_tcp, dead) = (std::net::UdpSocket::bind(free()).unwrap(), std::net::TcpListener::bind(free()).unwrap(), TcpSocket::new_v4().unwrap());
	dead.bind("127.0.0.1:0".parse().unwrap()).unwrap();
	for (name, from, until) in [("good", -1, 90), ("soon", -80, 5), ("expired", -400, -30), ("early", 30, 90)] {certificate(&dir, name, from, until)}
	let listens: Vec<String> = [free(), free(), taken_udp.local_addr().unwrap(), taken_tcp.local_addr().unwrap(), free(), free(), free(), free()].iter().map(|addr| addr.to_string()).collect();
	let secrets = config(&dir, &[both, udp_only], json!([
		{"type": "udp", "listen": listens[0]},
		{"type": "ws", "listen": listens[1], "path": "/wg", "tls": {"cert": "good.crt", "key": "good.key"}},
		{"type": "udp", "listen": listens[2]},
		{"type": "ws", "listen": listens[3], "path": "/wg", "tls": {"cert": "expired.crt", "key": "expired.key"}},
		{"type": "ws", "listen": listens[4], "path": "/wg", "tls": {"cert": "good.crt", "key": "expired.key"}},
		{"type": "ws", "listen": listens[5], "path": "/wg", "tls": {"cert": "soon.crt", "key": "soon.key"}},
		{"type": "ws", "listen": listens[6], "path": "/wg", "tls": {"cert": "early.crt", "key": "early.key"}},
		{"type": "ws", "listen": listens[7], "path": "/wg", "tls": {"cert": "missing.crt", "key": "good.key"}},
	]), json!([
		{"tag": "plain", "type": "direct"},
		{"tag": "full", "type": "socks5", "server": full.to_string()},
		{"tag": "tcp-only", "type": "socks5", "server": tcp_only.to_string()},
		{"tag": "locked", "type": "socks5", "server": locked.to_string(), "username": USER, "password": PASSWORD},
		{"tag": "wrong", "type": "socks5", "server": locked.to_string(), "username": USER, "password": WRONG},
		{"tag": "open", "type": "socks5", "server": locked.to_string()},
		{"tag": "elsewhere", "type": "socks5", "server": elsewhere.to_string()},
		{"tag": "dead", "type": "socks5", "server": dead.local_addr().unwrap().to_string()},
	]));
	let before = listing(&dir);
	let ((code, plain, plain_errors), (json_code, document, json_errors)) = (doctor(&dir, &[]).await, doctor(&dir, &["--json"]).await);
	assert_eq!((code, json_code, plain_errors.as_str(), json_errors.as_str()), (1, 1, "", ""), "{plain}");
	assert_eq!(listing(&dir), before, "doctor left something behind or took something away");
	let document: Value = serde_json::from_str(&document).expect("--json printed something that is no JSON document");
	for (check, subject, expected) in [
		("config", dir.join("config.json").to_str().unwrap(), "ok"),
		("node", "", "ok"),
		("listen", "inbound home, transports[0], udp", "ok"),
		("listen", "inbound home, transports[1], tcp", "ok"),
		("listen", "inbound home, transports[2], udp", "fail"),
		("listen", "inbound home, transports[3], tcp", "fail"),
		("certificate", "inbound home, transports[1].tls", "ok"),
		("certificate", "inbound home, transports[3].tls", "fail"),
		("certificate", "inbound home, transports[4].tls", "fail"),
		("certificate", "inbound home, transports[5].tls", "warn"),
		("certificate", "inbound home, transports[6].tls", "fail"),
		("certificate", "inbound home, transports[7].tls", "fail"),
		("dns", "servers[0], udp", "ok"),
		("dns", "servers[0], tcp", "ok"),
		("dns", "servers[1], udp", "ok"),
		("dns", "servers[1], tcp", "warn"),
		("outbound", "plain, tcp", "ok"),
		("outbound", "plain, udp", "ok"),
		("outbound", "full, tcp connect", "ok"),
		("outbound", "full, handshake", "ok"),
		("outbound", "full, connect", "ok"),
		("outbound", "full, udp associate", "ok"),
		("outbound", "tcp-only, tcp connect", "ok"),
		("outbound", "tcp-only, handshake", "ok"),
		("outbound", "tcp-only, connect", "ok"),
		("outbound", "tcp-only, udp associate", "warn"),
		("outbound", "locked, tcp connect", "ok"),
		("outbound", "locked, handshake", "ok"),
		("outbound", "locked, connect", "ok"),
		("outbound", "locked, udp associate", "ok"),
		("outbound", "wrong, tcp connect", "ok"),
		("outbound", "wrong, handshake", "fail"),
		("outbound", "wrong, connect", "skipped"),
		("outbound", "wrong, udp associate", "skipped"),
		("outbound", "open, handshake", "fail"),
		("outbound", "open, udp associate", "skipped"),
		("outbound", "elsewhere, connect", "ok"),
		("outbound", "elsewhere, udp associate", "warn"),
		("outbound", "dead, tcp connect", "fail"),
		("outbound", "dead, handshake", "skipped"),
		("outbound", "dead, connect", "skipped"),
		("outbound", "dead, udp associate", "skipped"),
		("state", "", "ok"),
		("socket", "", "ok"),
	] {assert_eq!(status(&document, check, subject), expected, "{check} {subject}\n{plain}")}
	let message = |check: &str, subject: &str| document["checks"].as_array().unwrap().iter().find(|line| line["check"] == check && line["subject"].as_str().unwrap().starts_with(subject)).unwrap()["message"].as_str().unwrap().to_string();
	assert!(message("outbound", "tcp-only, udp associate").contains("this upstream has no UDP"), "{plain}");
	assert!(message("outbound", "elsewhere, udp associate").contains("another host"), "the rule for the address of the relay was not held against the proxy\n{plain}");
	assert!(message("certificate", "inbound home, transports[1].tls").contains("doctor.test, *.doctor.test"), "{plain}");
	assert!(message("certificate", "inbound home, transports[3].tls").contains("expired") && message("certificate", "inbound home, transports[6].tls").contains("not valid for another"), "{plain}");
	// The lines say what the document says, in its order, and the last line counts them.
	let (checks, lines) = (document["checks"].as_array().unwrap(), plain.lines().collect::<Vec<_>>());
	assert_eq!(lines.len(), checks.len() + 1, "{plain}");
	for (line, check) in lines.iter().zip(checks) {
		let begins = format!("{:<8}{} {}: ", check["status"].as_str().unwrap(), check["check"].as_str().unwrap(), check["subject"].as_str().unwrap());
		assert!(line.starts_with(&begins), "`{line}` does not begin with `{begins}`");
	}
	let count = |word: &str| checks.iter().filter(|check| check["status"] == word).count();
	assert_eq!(*lines.last().unwrap(), format!("{} checks: {} ok, {} warn, {} fail, {} skipped", checks.len(), count("ok"), count("warn"), count("fail"), count("skipped")));
	assert_eq!((&document["ok"], &document["warn"], &document["fail"], &document["skipped"]), (&json!(count("ok")), &json!(count("warn")), &json!(count("fail")), &json!(count("skipped"))));
	// No key and no password, and no address of a proxy or a DNS server either: only tags, field paths and listen addresses.
	for hidden in secrets.iter().cloned().chain([both, udp_only, full, tcp_only, locked, elsewhere, dead.local_addr().unwrap()].iter().map(|addr| addr.to_string())) {
		assert!(!plain.contains(&hidden) && !document.to_string().contains(&hidden), "`{hidden}` is in what doctor printed\n{plain}");
	}
	// A socket nobody answers on is what a node that was killed leaves behind, and without the control API a taken address is a failure as well.
	drop(std::os::unix::net::UnixListener::bind(dir.join("veilway.sock")).unwrap());
	let (_, dead_socket, _) = doctor(&dir, &["--json"]).await;
	let dead_socket: Value = serde_json::from_str(&dead_socket).unwrap();
	assert_eq!((status(&dead_socket, "socket", ""), status(&dead_socket, "listen", "inbound home, transports[2], udp")), ("ok", "fail"), "{dead_socket:#}");
	assert!(dir.join("veilway.sock").exists(), "doctor removed a socket file");
	let (_, no_api, _) = doctor(&dir, &["--json", "--no-api"]).await;
	let no_api: Value = serde_json::from_str(&no_api).unwrap();
	assert_eq!((status(&no_api, "node", "control socket"), status(&no_api, "socket", "control socket"), status(&no_api, "listen", "inbound home, transports[3], tcp")), ("skipped", "skipped", "fail"), "{no_api:#}");
	drop((taken_udp, taken_tcp));
	std::fs::remove_dir_all(&dir).unwrap();
}

/// Stands on a control socket in the place of a node: every request is answered 200 with `body`.
fn answering(path: &Path, body: String) -> tokio::task::JoinHandle<()> {
	let listener = tokio::net::UnixListener::bind(path).unwrap();
	tokio::spawn(async move {
		loop {
			let Ok((mut stream, _)) = listener.accept().await else {continue};
			let body = body.clone();
			tokio::spawn(async move {
				let mut request = [0u8; 1024];
				let _ = stream.read(&mut request).await;
				let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes()).await;
			});
		}
	})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_taken_address_is_excused_only_for_a_node_that_says_it_holds_it() {
	let dir = scratch("node");
	let (both, taken_udp, taken_tcp, socket) = (dns(true).await, std::net::UdpSocket::bind(free()).unwrap(), std::net::TcpListener::bind(free()).unwrap(), dir.join("veilway.sock"));
	let (udp, tcp) = (taken_udp.local_addr().unwrap().to_string(), taken_tcp.local_addr().unwrap().to_string());
	config(&dir, &[both], json!([{"type": "udp", "listen": udp}, {"type": "ws", "listen": tcp, "path": "/wg"}]), json!([{"tag": "plain", "type": "direct"}]));
	let running = |transports: Value| json!({"revision": "0".repeat(64), "generation": 1, "document": {"version": 1, "inbounds": [{"tag": "home", "transports": transports}], "exits": [{"tag": "via-plain", "backend": {"type": "netstack", "outbound": "plain"}}]}}).to_string();
	let seen = |document: &str| {
		let document: Value = serde_json::from_str(document).unwrap();
		[("node", ""), ("listen", "inbound home, transports[0], udp"), ("listen", "inbound home, transports[1], tcp"), ("socket", "")].map(|(check, subject)| status(&document, check, subject).to_string())
	};
	// Another program on the socket path is no node: one that takes connections and says nothing, and one that answers something else.
	let silent = std::os::unix::net::UnixListener::bind(&socket).unwrap();
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	assert_eq!((code, seen(&document)), (1, ["warn", "fail", "fail", "fail"].map(str::to_string)), "{document}");
	drop(silent);
	std::fs::remove_file(&socket).unwrap();
	let other = answering(&socket, json!({"hello": "world"}).to_string());
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	assert_eq!((code, seen(&document)), (1, ["warn", "fail", "fail", "fail"].map(str::to_string)), "{document}");
	other.abort();
	let _ = other.await;
	std::fs::remove_file(&socket).unwrap();
	// A node excuses the addresses it holds and no other: here it has the first one, and the second only over UDP, where the config asks for TCP.
	let partly = answering(&socket, running(json!([{"type": "udp", "listen": udp}, {"type": "udp", "listen": tcp}])));
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	assert_eq!((code, seen(&document)), (1, ["ok", "ok", "fail", "ok"].map(str::to_string)), "{document}");
	partly.abort();
	let _ = partly.await;
	std::fs::remove_file(&socket).unwrap();
	let node = answering(&socket, running(json!([{"type": "udp", "listen": udp}, {"type": "ws", "listen": tcp, "path": "/wg"}])));
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	assert_eq!((code, seen(&document)), (0, ["ok", "ok", "ok", "ok"].map(str::to_string)), "{document}");
	node.abort();
	drop((taken_udp, taken_tcp));
	std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_is_read_the_way_the_node_serves_it() {
	let dir = scratch("chains");
	let both = dns(true).await;
	for (name, from, until) in [("good", -1, 90), ("expired", -400, -30)] {certificate(&dir, name, from, until)}
	let text = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
	// The node serves the first CERTIFICATE block of a file, whatever stands before it, and a client checks every certificate it is sent.
	private(&dir, "keyfirst.crt", &(text("expired.key") + &text("expired.crt")));
	private(&dir, "chain.crt", &(text("good.crt") + &text("expired.crt")));
	private(&dir, "badhead.key", &text("good.key").replacen("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY SECRETTEXT", 1));
	private(&dir, "badbody.crt", &text("good.crt").replacen('\n', "\n!!!!", 1));
	assert!(text("badhead.key").contains("SECRETTEXT") && text("badbody.crt").contains("!!!!"));
	let secrets = config(&dir, &[both], json!([
		{"type": "ws", "listen": free().to_string(), "path": "/wg", "tls": {"cert": "keyfirst.crt", "key": "expired.key"}},
		{"type": "ws", "listen": free().to_string(), "path": "/wg", "tls": {"cert": "chain.crt", "key": "good.key"}},
		{"type": "ws", "listen": free().to_string(), "path": "/wg", "tls": {"cert": "good.crt", "key": "badhead.key"}},
		{"type": "ws", "listen": free().to_string(), "path": "/wg", "tls": {"cert": "badbody.crt", "key": "good.key"}},
		{"type": "ws", "listen": free().to_string(), "path": "/wg", "tls": {"cert": "good.crt", "key": "good.key"}},
	]), json!([{"tag": "plain", "type": "direct"}]));
	let (code, plain, errors) = doctor(&dir, &["--json"]).await;
	let document: Value = serde_json::from_str(&plain).unwrap();
	let message = |at: usize| document["checks"].as_array().unwrap().iter().find(|line| line["check"] == "certificate" && line["subject"].as_str().unwrap().starts_with(&format!("inbound home, transports[{at}].tls"))).unwrap()["message"].as_str().unwrap().to_string();
	for (at, expected) in ["fail", "fail", "fail", "fail", "ok"].into_iter().enumerate() {assert_eq!(status(&document, "certificate", &format!("inbound home, transports[{at}].tls")), expected, "transports[{at}]\n{document:#}")}
	assert!(message(0).contains("expired 30 days ago") && message(1).contains("certificate 2 of the chain expired 30 days ago"), "{document:#}");
	assert!(message(2).contains("the key file") && message(3).contains("the certificate file"), "{document:#}");
	// Nothing of a file is printed, in the words of doctor or in those of the library that read it.
	for leaked in ["illegal", "base64", "Invalid", "83, 69, 67", "[45", "SECRETTEXT"].into_iter().map(str::to_string).chain(secrets) {assert!(!plain.contains(&leaked) && !errors.contains(&leaked), "`{leaked}` is in what doctor printed\n{plain}")}
	assert_eq!(code, 1);
	std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_others_can_read_fails_as_it_does_for_run_and_a_full_standard_output_changes_no_status() {
	let dir = scratch("readable");
	let both = dns(true).await;
	config(&dir, &[both], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let (code, document, _) = doctor(&dir, &["--json", "--no-api"]).await;
	assert_eq!((code, status(&serde_json::from_str(&document).unwrap(), "config", dir.join("config.json").to_str().unwrap())), (0, "ok"), "{document}");
	std::fs::set_permissions(dir.join("config.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
	let (code, document, _) = doctor(&dir, &["--json", "--no-api"]).await;
	let parsed: Value = serde_json::from_str(&document).unwrap();
	assert_eq!((code, &parsed["fail"]), (1, &json!(1)), "{document}");
	assert!(parsed["checks"].as_array().unwrap().iter().any(|line| line["check"] == "config" && line["status"] == "fail" && line["message"].as_str().unwrap().contains("`veilway run` would not start")), "{document}");
	let (code, document, errors) = doctor(&dir, &["--json", "--no-api", "--allow-readable-config"]).await;
	assert_eq!((code, errors.as_str(), &serde_json::from_str::<Value>(&document).unwrap()["fail"]), (0, "", &json!(0)), "{document}");
	// Standard output that takes nothing: the status is still the one the checks stand for, and nothing is said of a panic.
	#[cfg(target_os = "linux")]
	for (args, expected) in [(&["--no-api"][..], 1), (&["--no-api", "--allow-readable-config"][..], 0), (&["--no-api", "--allow-readable-config", "--json"][..], 0)] {
		let done = tokio::process::Command::new(env!("CARGO_BIN_EXE_veilway")).arg("doctor").arg("--config").arg(dir.join("config.json")).args(args).stdout(std::fs::File::options().write(true).open("/dev/full").unwrap()).output().await.unwrap();
		assert_eq!((done.status.code(), String::from_utf8_lossy(&done.stderr).as_ref()), (Some(expected), ""), "{args:?}");
	}
	std::fs::remove_dir_all(&dir).unwrap();
}

/// Takes the whole time doctor gives its network checks, and a little more than a minute before it had one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_proxies_in_numbers_are_cut_off_well_under_a_minute() {
	let dir = scratch("slow");
	// A proxy that uses up most of every wait: it greets after 6 s, gives a UDP relay after 2 more, and then nothing answers on the relay or on a CONNECT. With --timeout 10 that is 24 s for one outbound.
	let (both, listener, relay) = (dns(true).await, TcpListener::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
	let (proxy, port) = (listener.local_addr().unwrap(), relay.local_addr().unwrap().port().to_be_bytes());
	tokio::spawn(async move {
		loop {
			let Ok((mut client, _)) = listener.accept().await else {continue};
			tokio::spawn(async move {
				let (mut head, mut request, mut sink) = ([0u8; 2], [0u8; 10], [0u8; 64]);
				if client.read_exact(&mut head).await.is_err() || client.read_exact(&mut sink[..usize::from(head[1]).min(64)]).await.is_err() {return}
				tokio::time::sleep(std::time::Duration::from_secs(6)).await;
				if client.write_all(&[5, 0]).await.is_err() || client.read_exact(&mut request).await.is_err() {return}
				if request[1] == 3 {
					tokio::time::sleep(std::time::Duration::from_secs(2)).await;
					let _ = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]]).await;
				}
				while client.read(&mut sink).await.is_ok_and(|n| n > 0) {}
			});
		}
	});
	config(&dir, &[both], json!([{"type": "udp", "listen": free().to_string()}]), Value::Array((0..200).map(|at| json!({"tag": format!("slow-{at:03}"), "type": "socks5", "server": proxy.to_string()})).collect()));
	let started = std::time::Instant::now();
	let done = tokio::process::Command::new(env!("CARGO_BIN_EXE_veilway")).arg("doctor").arg("--config").arg(dir.join("config.json")).args(["--timeout", "10", "--json"]).output().await.unwrap();
	let (took, document): (_, Value) = (started.elapsed(), serde_json::from_slice(&done.stdout).expect("--json printed something that is no JSON document"));
	assert!(took < std::time::Duration::from_secs(55), "doctor took {took:?}");
	let cut = document["checks"].as_array().unwrap().iter().filter(|line| line["check"] == "outbound" && line["status"] == "skipped" && line["message"].as_str().unwrap().contains("out of time")).count();
	assert!(cut > 0 && cut < 200, "{cut} outbounds were cut off\n{document:#}");
	assert_eq!((done.status.code(), status(&document, "outbound", "slow-000, handshake"), status(&document, "outbound", "slow-000, udp associate"), status(&document, "dns", "servers[0], udp")), (Some(1), "ok", "fail", "ok"), "{document:#}");
	drop(relay);
	std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_has_everything_ends_with_status_zero() {
	let dir = scratch("healthy");
	let (both, proxy) = (dns(true).await, socks5(Proxy {udp: true, password: Some((USER, PASSWORD)), ..Proxy::default()}).await);
	certificate(&dir, "good", -1, 90);
	let secrets = config(&dir, &[both], json!([{"type": "udp", "listen": free().to_string()}, {"type": "ws", "listen": free().to_string(), "path": "/wg", "tls": {"cert": "good.crt", "key": "good.key"}}]), json!([
		{"tag": "proxy", "type": "socks5", "server": proxy.to_string(), "username": USER, "password": PASSWORD},
		{"tag": "plain", "type": "direct", "bind": host().to_string()},
	]));
	private(&dir, "veilway-state.json", r#"{"version":1,"users":{"a":{"used_bytes":7,"period_start":0,"up_bytes":4,"up_packets":1,"down_bytes":3,"down_packets":1}}}"#);
	let before = listing(&dir);
	let ((code, plain, errors), (json_code, document, _)) = (doctor(&dir, &[]).await, doctor(&dir, &["--json"]).await);
	let document: Value = serde_json::from_str(&document).unwrap();
	// One warning comes from the config itself and has nothing to do with the host: a test can only put its DNS server on a private address, which the rule against private networks refuses.
	assert_eq!((code, json_code, errors.as_str(), &document["fail"], &document["warn"], &document["skipped"]), (0, 0, "", &json!(0), &json!(1), &json!(0)), "{plain}");
	assert!(plain.lines().all(|line| line.starts_with("ok      ") || line.starts_with("warn    config routing.rules[1]: ") || line.ends_with("1 warn, 0 fail, 0 skipped")), "{plain}");
	assert!(plain.contains("it is a state file of 1 users"), "{plain}");
	assert_eq!(listing(&dir), before, "doctor left something behind or took something away");
	for secret in &secrets {assert!(!plain.contains(secret) && !document.to_string().contains(secret), "`{secret}` is in what doctor printed")}
	// A state file the node would move aside is a failure, and doctor leaves it where it is.
	std::fs::write(dir.join("veilway-state.json"), "no state file").unwrap();
	let (code, broken, _) = doctor(&dir, &["--json"]).await;
	assert_eq!((code, status(&serde_json::from_str(&broken).unwrap(), "state", ""), std::fs::read_to_string(dir.join("veilway-state.json")).unwrap().as_str(), listing(&dir)), (1, "fail", "no state file", before));
	std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dns_server_that_is_gone_fails_what_asks_it_within_the_timeout() {
	let dir = scratch("silent");
	// A UDP port that takes every query and answers none, with a TCP port that takes every connection and says nothing.
	let quiet = TcpListener::bind(SocketAddr::new(host(), 0)).await.unwrap();
	let (silent, hush) = (quiet.local_addr().unwrap(), UdpSocket::bind(quiet.local_addr().unwrap()).await.unwrap());
	let proxy = socks5(Proxy {udp: true, ..Proxy::default()}).await;
	config(&dir, &[silent], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}, {"tag": "proxy", "type": "socks5", "server": proxy.to_string()}]));
	let started = std::time::Instant::now();
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	let document: Value = serde_json::from_str(&document).unwrap();
	assert!(started.elapsed() < std::time::Duration::from_secs(8), "doctor took {:?} with a timeout of 2 s", started.elapsed());
	for (check, subject, expected) in [("dns", "servers[0], udp", "fail"), ("dns", "servers[0], tcp", "warn"), ("outbound", "plain, tcp", "ok"), ("outbound", "plain, udp", "fail"), ("outbound", "proxy, handshake", "ok"), ("outbound", "proxy, connect", "fail"), ("outbound", "proxy, udp associate", "fail")] {
		assert_eq!(status(&document, check, subject), expected, "{check} {subject}\n{document:#}");
	}
	assert_eq!(code, 1);
	drop((quiet, hush));
	std::fs::remove_dir_all(&dir).unwrap();
}

/// The servers of every DNS set are asked like those of `dns.servers`, each on a line that names its set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_servers_of_every_dns_set_have_their_own_lines() {
	let dir = scratch("sets");
	let (both, udp_only, quiet) = (dns(true).await, dns(false).await, TcpListener::bind(SocketAddr::new(host(), 0)).await.unwrap());
	let (silent, hush) = (quiet.local_addr().unwrap(), UdpSocket::bind(quiet.local_addr().unwrap()).await.unwrap());
	config(&dir, &[both], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let mut document: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
	document["dns"]["sets"] = json!([{"tag": "family", "servers": [udp_only.to_string(), both.to_string()], "users": ["a"]}, {"tag": "lab", "servers": [silent.to_string()], "inbounds": ["home"]}]);
	private(&dir, "config.json", &document.to_string());
	let (code, document, errors) = doctor(&dir, &["--json"]).await;
	let document: Value = serde_json::from_str(&document).unwrap_or_else(|e| panic!("{e}: {document} {errors}"));
	for (subject, expected) in [("servers[0], udp", "ok"), ("servers[0], tcp", "ok"), ("set family, servers[0], udp", "ok"), ("set family, servers[0], tcp", "warn"), ("set family, servers[1], udp", "ok"), ("set family, servers[1], tcp", "ok"), ("set lab, servers[0], udp", "fail"), ("set lab, servers[0], tcp", "warn")] {
		assert_eq!(status(&document, "dns", subject), expected, "{subject}\n{document:#}");
	}
	// They stand in the order of the config, before the outbounds, and after them doctor says that it tried no outbound towards the servers of a set.
	let checks: Vec<&str> = document["checks"].as_array().unwrap().iter().filter(|line| line["check"] == "dns" || line["check"] == "outbound").map(|line| line["subject"].as_str().unwrap()).collect();
	assert_eq!(checks[..10], ["servers[0], udp", "servers[0], tcp", "set family, servers[0], udp", "set family, servers[0], tcp", "set family, servers[1], udp", "set family, servers[1], tcp", "set lab, servers[0], udp", "set lab, servers[0], tcp", "sets, through the outbounds", "plain, tcp"], "{document:#}");
	assert_eq!(status(&document, "dns", "sets, through the outbounds"), "skipped");
	assert_eq!(code, 1);
	drop((quiet, hush));
	std::fs::remove_dir_all(&dir).unwrap();
}

/// Writes the replay file a node leaves that was killed with this floor and this limit.
/// A web server that answers a request for its page with the status line `page`, and one for any other path with `other`, or never when that is None.
async fn web(page: &'static str, other: Option<&'static str>) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			tokio::spawn(async move {
				let (mut head, mut read) = (Vec::new(), [0u8; 1024]);
				while !head.windows(4).any(|window| window == b"\r\n\r\n") {
					match stream.read(&mut read).await {
						Ok(count) if count > 0 => head.extend_from_slice(&read[..count]),
						_ => return,
					}
				}
				let Some(status) = (if head.starts_with(b"GET / ") {Some(page)} else {other}) else {return tokio::time::sleep(std::time::Duration::from_secs(60)).await};
				let _ = stream.write_all(format!("HTTP/1.1 {status}\r\nServer: fake/1.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await;
			});
		}
	});
	addr
}

/// Transports page, "What the decoy origin must be": "The origin must also not send the transport path back to the node by a rule of its own. `veilway doctor` checks this by a request", and "the origin must not serve anything at a transport path".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_decoy_origin_of_a_tls_transport_is_asked_for_its_page_and_for_the_path() {
	let (dir, server, listen, path) = (scratch("decoy"), dns(true).await, free(), "/assets/doctor-9c41b7.js");
	certificate(&dir, "node", -1, 90);
	config(&dir, &[server], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let written: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
	// What doctor says of the two decoy lines for a config whose origin is `origin`, after `change` had its way with the document.
	let asked = |origin: SocketAddr, change: &dyn Fn(&mut Value)| {
		let mut document = written.clone();
		(document["inbounds"][0]["type"], document["inbounds"][0]["transport_keys"], document["inbounds"][0]["upgrade_cookie"], document["users"][0]["devices"][0]["transport_secrets"]) = (json!("veilway"), json!([veilway_wg::encode_key(&[0x51; 32])]), json!("sid"), json!([veilway_wg::encode_key(&[0xa1; 32])]));
		document["inbounds"][0]["transports"] = json!([{"type": "tls", "listen": listen.to_string(), "path": path, "tls": {"cert": "node.crt", "key": "node.key"}, "decoy": {"origin": format!("http://{origin}")}}]);
		change(&mut document);
		private(&dir, "config.json", &document.to_string());
		let dir = dir.clone();
		async move {
			let (_, printed, _) = doctor(&dir, &["--json"]).await;
			let document: Value = serde_json::from_str(&printed).unwrap_or_else(|e| panic!("{e}: {printed}"));
			// The path is a secret of the subscription: doctor sends it to the origin and prints it nowhere.
			assert!(!printed.contains(path), "{printed}");
			let message = |part: &str| document["checks"].as_array().unwrap().iter().find(|line| line["check"] == "decoy" && line["subject"].as_str().unwrap().ends_with(part)).map(|line| line["message"].as_str().unwrap().to_string()).unwrap_or_default();
			((status(&document, "decoy", "inbound home, transports[0].decoy, origin").to_string(), message("origin")), (status(&document, "decoy", "inbound home, transports[0].decoy, path").to_string(), message("path")), (status(&document, "certificate", "inbound home, transports[0].tls").to_string(), status(&document, "listen", &format!("inbound home, transports[0], tcp {listen}")).to_string()))
		}
	};
	// A site that has its page and misses the path, which is what a decoy origin is.
	let ((origin, _), (missed, _), files) = asked(web("200 OK", Some("404 Not Found")).await, &|_| {}).await;
	assert_eq!((origin.as_str(), missed.as_str(), files), ("ok", "ok", ("ok".to_string(), "ok".to_string())));
	// One that serves something at the path, one that hands the path on and gets an error from where it handed it, and one that never answers for it.
	let ((_, _), (served, message), _) = asked(web("200 OK", Some("200 OK")).await, &|_| {}).await;
	assert!(served == "warn" && message.contains("must serve nothing there"), "{served}: {message}");
	let ((_, _), (handed, message), _) = asked(web("200 OK", Some("502 Bad Gateway")).await, &|_| {}).await;
	assert!(handed == "fail" && message.contains("goes round between the two"), "{handed}: {message}");
	let ((origin, _), (silent, message), _) = asked(web("200 OK", None).await, &|_| {}).await;
	assert!(origin == "ok" && silent == "fail" && message.contains("gave no answer for the path"), "{origin} {silent}: {message}");
	// A field of `upgrade_headers` the origin does not send is named, and one it sends is not.
	let ((named, message), (missed, _), _) = asked(web("200 OK", Some("404 Not Found")).await, &|document| document["inbounds"][0]["upgrade_headers"] = json!(["X-Absent", "Server", "Date"])).await;
	assert!(named == "warn" && missed == "ok" && message.contains("did not send X-Absent,") && !message.contains("Server"), "{named}: {message}");
	// The line of the page says which `Host` the request carried, and the line of the path that the origin's log has it now.
	let ((_, page), (_, logged), _) = asked(web("200 OK", Some("404 Not Found")).await, &|_| {}).await;
	assert!(page.contains("`Host: 127.0.0.1:") && logged.contains("in the origin's access log"), "{page} / {logged}");
	// A plain listener that sends everyone to `https://` is a redirect for ever behind the node's TLS. One that redirects within plain HTTP is not.
	let ((secure, message), _, _) = asked(web("301 Moved Permanently\r\nLocation: HTTPS://site.example/", Some("404 Not Found")).await, &|_| {}).await;
	assert!(secure == "warn" && message.contains("without the redirect"), "{secure}: {message}");
	let ((plain, _), _, _) = asked(web("302 Found\r\nLocation: http://site.example/home", Some("404 Not Found")).await, &|_| {}).await;
	assert_eq!(plain, "ok");
	// Nobody there: strangers would be closed with no answer, and the line says that users are not.
	let ((down, message), (skipped, _), _) = asked(free(), &|_| {}).await;
	assert!(down == "fail" && skipped == "skipped" && message.contains("Users are not affected"), "{down} {skipped}: {message}");
	std::fs::remove_dir_all(&dir).unwrap();
}

/// Config reference, the `tls` row: with `self_signed: true` the node "reports the pin (the SHA-256 of the SubjectPublicKeyInfo) in `veilway doctor`". Doctor makes and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pin_of_a_certificate_the_node_makes_itself_is_said_and_nothing_is_made() {
	let (dir, server, listen) = (scratch("self-signed"), dns(true).await, free());
	config(&dir, &[server], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let mut document: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
	(document["inbounds"][0]["type"], document["inbounds"][0]["transport_keys"], document["inbounds"][0]["upgrade_cookie"], document["users"][0]["devices"][0]["transport_secrets"]) = (json!("veilway"), json!([veilway_wg::encode_key(&[0x51; 32])]), json!("sid"), json!([veilway_wg::encode_key(&[0xa1; 32])]));
	document["inbounds"][0]["transports"] = json!([{"type": "tls", "listen": listen.to_string(), "path": "/assets/doctor-5e1f.js", "tls": {"self_signed": true}, "decoy": {"origin": format!("http://{}", free())}}]);
	private(&dir, "config.json", &document.to_string());
	let said = || async {
		let (_, printed, _) = doctor(&dir, &["--json"]).await;
		let document: Value = serde_json::from_str(&printed).unwrap();
		let line = document["checks"].as_array().unwrap().iter().find(|line| line["check"] == "certificate").unwrap().clone();
		(line["status"].as_str().unwrap().to_string(), line["message"].as_str().unwrap().to_string())
	};
	// Before the first start there is no key, and doctor makes none.
	let before = listing(&dir);
	let (status, message) = said().await;
	assert!(status == "ok" && message.contains("at its next start") && listing(&dir) == before, "{status}: {message}");
	// Once the node made them, the pin is the one the node says.
	let (made, _) = veilway_core::engine::certificate::ensure(veilway_core::engine::certificate::files(&dir, "home"), listen, None, time::OffsetDateTime::now_utc()).unwrap();
	let (status, message) = said().await;
	assert!(status == "ok" && message.contains(&format!("pin {}", made.pin_text())) && message.contains("more days"), "{status}: {message}");
	// A key file the node would not use is a failure of the start, and is left as it is.
	std::fs::write(&made.files.key, "no key").unwrap();
	let (status, message) = said().await;
	assert!(status == "fail" && message.contains("not a key of ECDSA on P-256") && std::fs::read_to_string(&made.files.key).unwrap() == "no key", "{status}: {message}");
	std::fs::remove_dir_all(&dir).unwrap();
}

/// Transports page, "Who ends TLS": "A native `ws` or `fronted` listener never ends TLS itself", so doctor says whether anybody but this host reaches such a listener, asks its decoy origin as it asks that of `tls`, and tells from the counts of a node that runs whether the web server in front names its visitors in the header the config says.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proxy_path_of_a_listener_is_held_to_loopback_and_to_the_header_its_proxy_sends() {
	let (dir, server, origin) = (scratch("front"), dns(true).await, web("200 OK", Some("404 Not Found")).await);
	config(&dir, &[server], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let (written, socket): (Value, _) = (serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap(), dir.join("veilway.sock"));
	// What doctor says of a `ws` and a `fronted` transport on `listen` behind `trusted`, with a node on the control socket that has counted `node` when there is one: the lines of the proxy path, and how many lines of the decoy origin are good.
	let asked = |listen: SocketAddr, trusted: Value, node: Option<(u64, u64, u64)>| {
		let (mut document, behind) = (written.clone(), |kind: &str, path: &str| json!({"type": kind, "listen": listen.to_string(), "path": path, "decoy": {"origin": format!("http://{origin}")}, "trusted_proxies": trusted, "client_address_header": "X-Forwarded-For"}));
		(document["inbounds"][0]["type"], document["inbounds"][0]["transport_keys"], document["inbounds"][0]["upgrade_cookie"], document["users"][0]["devices"][0]["transport_secrets"]) = (json!("veilway"), json!([veilway_wg::encode_key(&[0x51; 32])]), json!("sid"), json!([veilway_wg::encode_key(&[0xa1; 32])]));
		document["inbounds"][0]["transports"] = json!([behind("ws", "/assets/doctor-live-1.js"), behind("fronted", "/assets/doctor-sync-1.js")]);
		private(&dir, "config.json", &document.to_string());
		let running = node.map(|(requests, unnamed, old)| answering(&socket, json!({"revision": "0".repeat(64), "generation": 1, "document": {"version": 1, "inbounds": [{"tag": "home", "transports": [{"type": "ws", "listen": listen.to_string()}]}], "exits": []}, "stream": {"proxy_requests": requests, "proxy_unnamed": unnamed, "proxy_http10": old}}).to_string()));
		let (dir, socket) = (dir.clone(), socket.clone());
		async move {
			let (_, printed, _) = doctor(&dir, &["--json"]).await;
			if let Some(running) = running {
				running.abort();
				let _ = running.await;
				std::fs::remove_file(&socket).unwrap();
			}
			let document: Value = serde_json::from_str(&printed).unwrap_or_else(|e| panic!("{e}: {printed}"));
			// The paths are secrets of the subscription: doctor sends them to the origin and prints them nowhere.
			assert!(!printed.contains("doctor-live") && !printed.contains("doctor-sync"), "{printed}");
			let checks = document["checks"].as_array().unwrap();
			(checks.iter().filter(|line| line["check"] == "proxy").map(|line| (line["subject"].as_str().unwrap().rsplit('.').next().unwrap().to_string(), line["status"].as_str().unwrap().to_string())).collect::<Vec<_>>(), checks.iter().filter(|line| line["check"] == "decoy" && line["status"] == "ok").count())
		}
	};
	let line = |part: &str, status: &str| (part.to_string(), status.to_string());
	// A listener on loopback behind proxies on loopback, with no node to ask: one line for the two transports of the listener, the header left open, and the origin asked for its page and for the path of each transport.
	assert_eq!(asked(free(), json!(["127.0.0.1", "::1"]), None).await, (vec![line("listen", "ok"), line("client_address_header", "skipped")], 4));
	// A listener anybody may reach, and proxies that cannot reach a listener on loopback, are warnings.
	assert_eq!(asked(SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), free().port()), json!(["127.0.0.1"]), None).await.0, [line("listen", "warn"), line("client_address_header", "skipped")]);
	assert_eq!(asked(free(), json!(["127.0.0.1", "10.0.0.0/8"]), None).await.0, [line("trusted_proxies", "warn"), line("client_address_header", "skipped")]);
	// A node that runs has counted: no request yet, every request with its visitor named, some without, and none with, which is a web server that does not send the header at all.
	for (node, expected) in [((0, 0, 0), "skipped"), ((40, 0, 0), "ok"), ((40, 3, 0), "warn"), ((40, 40, 0), "fail")] {
		let taken = std::net::TcpListener::bind(free()).unwrap();
		assert_eq!(asked(taken.local_addr().unwrap(), json!(["127.0.0.1"]), Some(node)).await.0, [line("listen", "ok"), line("client_address_header", expected)], "{node:?}");
	}
	// A web server that speaks HTTP/1.0 to the node hands on no request a user could have sent: some such requests are a warning, and nothing else is a failure.
	for (node, expected) in [((40, 0, 2), "warn"), ((40, 0, 40), "fail")] {
		let taken = std::net::TcpListener::bind(free()).unwrap();
		assert_eq!(asked(taken.local_addr().unwrap(), json!(["127.0.0.1"]), Some(node)).await.0, [line("listen", "ok"), line("http_version", expected), line("client_address_header", "ok")], "{node:?}");
	}
	std::fs::remove_dir_all(&dir).unwrap();
}

fn replay(dir: &Path, floor: u64, limit: u64) {
	let body = [&b"VWREPLAY"[..], &1u32.to_be_bytes(), &[0; 4], &floor.to_be_bytes(), &limit.to_be_bytes(), &0u32.to_be_bytes()].concat();
	std::fs::write(dir.join("veilway-replay"), [&body[..], ring::digest::digest(&ring::digest::SHA256, &body).as_ref()].concat()).unwrap();
	std::fs::set_permissions(dir.join("veilway-replay"), std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Transports page, "When the floor is ahead of the clock": "`veilway doctor` reports the floor, the limit and the clock, fails the check when the floor is ahead, and warns when the limit is more than `W` plus 20 s ahead."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_replay_file_of_a_config_with_an_obfuscated_transport_is_held_against_the_clock() {
	let (dir, server) = (scratch("replay"), dns(true).await);
	// A config without such a transport has no replay file, and doctor has no line for one.
	config(&dir, &[server], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let (_, document, _) = doctor(&dir, &["--json"]).await;
	assert!(serde_json::from_str::<Value>(&document).unwrap()["checks"].as_array().unwrap().iter().all(|line| line["check"] != "replay"), "{document}");
	let mut document: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
	(document["inbounds"][0]["type"], document["inbounds"][0]["transports"], document["users"][0]["devices"][0]["transport_secrets"]) = (json!("veilway"), json!([{"type": "udp-obfs", "listen": free().to_string()}]), json!([veilway_wg::encode_key(&[0xa1; 32])]));
	private(&dir, "config.json", &document.to_string());
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
	let subject = dir.join("veilway-replay").display().to_string();
	let checked = |document: &str| -> (String, String) {
		let document: Value = serde_json::from_str(document).unwrap_or_else(|e| panic!("{e}: {document}"));
		let line = document["checks"].as_array().unwrap().iter().find(|line| line["check"] == "replay" && line["subject"] == subject.as_str()).unwrap_or_else(|| panic!("no replay line in {document:#}")).clone();
		(line["status"].as_str().unwrap().to_string(), line["message"].as_str().unwrap().to_string())
	};
	// Nothing there yet: the node makes it, and says what its first minute is like.
	let (_, document, _) = doctor(&dir, &["--json"]).await;
	let (status, message) = checked(&document);
	assert!(status == "ok" && message.contains("refuses every proof for the first 60s"), "{status}: {message}");
	// A file as a node writes it while it runs, and one whose limit a clock that ran ahead left behind.
	replay(&dir, now - 100, now + 10);
	let (_, document, _) = doctor(&dir, &["--json"]).await;
	let (status, message) = checked(&document);
	assert!(status == "ok" && message.contains(&format!("floor {}, limit {}, clock ", now - 100, now + 10)), "{status}: {message}");
	// What a start or a reset leaves: a floor up to 80 seconds ahead. It ends by itself, and the line does not send anybody to the reset.
	replay(&dir, now + 50, now + 50);
	let (_, document, _) = doctor(&dir, &["--json"]).await;
	let (status, message) = checked(&document);
	assert!(status == "ok" && message.contains("what a start or a reset costs") && message.contains("Do not reset"), "{status}: {message}");
	replay(&dir, now - 100, now + 3600);
	let (_, document, _) = doctor(&dir, &["--json"]).await;
	let (status, message) = checked(&document);
	assert!(status == "warn" && message.contains("the limit is") && message.contains("takes this limit as its floor"), "{status}: {message}");
	// The floor ahead of the clock is an outage, and the line says what ends it.
	replay(&dir, now + 3600, now + 3620);
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	let (status, message) = checked(&document);
	assert!(code == 1 && status == "fail" && message.contains(&format!("floor {}, limit {}", now + 3600, now + 3620)) && message.contains("ahead of the clock") && message.contains("veilway replay reset"), "{code} {status}: {message}");
	let (code, plain, _) = doctor(&dir, &[]).await;
	assert!(code == 1 && plain.lines().any(|line| line.starts_with("fail    replay ") && line.contains("veilway replay reset")), "{code}: {plain}");
	// A file no node wrote. Doctor moves nothing and makes nothing, whatever it finds.
	private(&dir, "veilway-replay", "VWREPLAY and nothing else of a replay file, though long enough to be one as far as its length goes");
	let before = listing(&dir);
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	let (status, message) = checked(&document);
	assert!(code == 1 && status == "fail" && message.contains(".bad") && message.contains("Never put a replay file back from a backup"), "{code} {status}: {message}");
	assert_eq!(listing(&dir), before);
	std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_config_that_cannot_be_read_ends_with_status_two_and_one_that_is_wrong_with_one() {
	let dir = scratch("unreadable");
	let (code, plain, _) = doctor(&dir, &[]).await;
	assert!(code == 2 && plain.starts_with("fail    config ") && plain.contains("cannot read the config file"), "{code}: {plain}");
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	let document: Value = serde_json::from_str(&document).expect("--json printed something that is no JSON document");
	assert_eq!((code, &document["fail"], &document["skipped"]), (2, &json!(1), &json!(1)), "{document:#}");
	// A document that parses and names an exit it does not define: every error is a line, and nothing it names is tried.
	let secrets = config(&dir, &["192.0.2.53:53".parse().unwrap()], json!([{"type": "udp", "listen": free().to_string()}]), json!([{"tag": "plain", "type": "direct"}]));
	let wrong = std::fs::read_to_string(dir.join("config.json")).unwrap().replace(r#""default":"via-plain""#, r#""default":"nowhere""#);
	assert!(wrong.contains("nowhere"));
	private(&dir, "config.json", &wrong);
	let (code, document, _) = doctor(&dir, &["--json"]).await;
	let parsed: Value = serde_json::from_str(&document).unwrap();
	assert_eq!((code, status(&parsed, "config", "routing.default"), status(&parsed, "checks", "")), (1, "fail", "skipped"), "{parsed:#}");
	assert!(parsed["checks"].as_array().unwrap().iter().all(|line| line["check"] == "config" || line["check"] == "checks"), "{parsed:#}");
	for secret in &secrets {assert!(!document.contains(secret), "`{secret}` is in what doctor printed")}
	std::fs::remove_dir_all(&dir).unwrap();
}

// "`veilway doctor` checks, without dialling anything: that the clock is set, that the link's `mtu` is not below the `mtu` of an inbound whose users are routed to it, and, from a running node, each link's state." What validation holds a link to stands in the config lines.
#[tokio::test]
async fn a_link_is_looked_at_without_dialling_it() {
	let (dir, server) = (scratch("link"), dns(false).await);
	let key = |byte: u8| veilway_wg::encode_key(&[byte; 32]);
	let document = |mtu: u16, chained: bool| json!({
		"version": 1, "dns": {"servers": [server.to_string()]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": free().to_string()}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": if chained {json!([{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "far", "backend": {"type": "chain", "links": ["far"]}}])} else {json!([{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}])},
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "phone", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}],
		"links": [{"tag": "far", "id": "AAECAwQFBgcICQoLDA0ODw", "direction": "forward", "mtu": mtu, "addresses": {"dialler": ["10.9.0.2"]}, "transport_secret": key(0x41), "private_key": key(0x31), "peer": {"inbound_public_key": key(0x61), "transports": [{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821"]}]}}]
	}).to_string();
	for (mtu, chained, check) in [(1300, true, "warn"), (1420, true, "ok"), (1420, false, "warn")] {
		private(&dir, "config.json", &document(mtu, chained));
		let (_, printed, _) = doctor(&dir, &["--json", "--no-api"]).await;
		let parsed: Value = serde_json::from_str(&printed).unwrap();
		assert_eq!((status(&parsed, "link", "clock"), status(&parsed, "link", "links[0]"), status(&parsed, "link", "state")), ("ok", check, "skipped"), "{parsed:#}");
		// The secret and the private key of the link are in no line.
		assert!(!printed.contains(&key(0x41)) && !printed.contains(&key(0x31)));
	}
	std::fs::remove_dir_all(&dir).unwrap();
}
