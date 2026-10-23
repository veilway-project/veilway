//! An `xray` outbound against a node that runs in this process, with a stand-in for the add-on's host: what the node asks of it, what the outbound reports while the add-on is missing and once it runs, and that nothing leaves around the outbound meanwhile. The real Xray is run by `an_xray_outbound_carries_tcp_and_udp_through_the_real_xray_and_a_down_hop_dials_nothing` in the crate itself, with VEILWAY_TEST_XRAY.
#![cfg(unix)]
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use veilway_core::config::Config;
use veilway_core::{Engine, Options};

const ALICE: &str = "alice-secret-pass-01";

fn own() -> Option<IpAddr> {
	let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
	probe.connect("192.0.2.1:9").ok()?;
	Some(probe.local_addr().ok()?.ip()).filter(|ip| ip.is_ipv4() && !ip.is_loopback())
}

fn free() -> SocketAddr {std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()}

/// What the stand-in for the host does with the next lease: refuse it as a host without the add-on does, or take it and hold it.
const MISSING: u8 = 0;
const RUNS: u8 = 1;

#[derive(Default)]
struct Host {mode: AtomicU8, documents: Mutex<Vec<Value>>, held: AtomicUsize}

async fn host(path: PathBuf) -> Arc<Host> {
	let (state, listener) = (Arc::new(Host::default()), UnixListener::bind(&path).unwrap());
	let seen = state.clone();
	tokio::spawn(async move {
		while let Ok((mut node, _)) = listener.accept().await {
			let state = seen.clone();
			tokio::spawn(async move {
				let mut length = [0u8; 4];
				node.read_exact(&mut length).await.unwrap();
				let mut document = vec![0u8; u32::from_be_bytes(length) as usize];
				node.read_exact(&mut document).await.unwrap();
				let document: Value = serde_json::from_slice(&document).unwrap();
				state.documents.lock().unwrap().push(document.clone());
				if state.mode.load(Ordering::SeqCst) == MISSING {return drop(node.write_all(b"error the add-on is not installed (test): run `scripts/veilway.sh addon xray install`\n").await)}
				// What Xray does with each inbound that listens on a socket: makes it.
				let sockets: Vec<UnixListener> = document["inbounds"].as_array().unwrap().iter().filter_map(|inbound| inbound["listen"].as_str()?.split(',').next().map(|path| {
					let listener = UnixListener::bind(path).unwrap();
					std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o660)).unwrap();
					listener
				})).collect();
				node.write_all(format!("ok 4242 {}\n", unsafe {libc::geteuid()}).as_bytes()).await.unwrap();
				state.held.fetch_add(1, Ordering::SeqCst);
				let mut sink = [0u8; 16];
				while node.read(&mut sink).await.is_ok_and(|n| n > 0) {}
				drop(sockets);
				state.held.fetch_sub(1, Ordering::SeqCst);
			});
		}
	});
	state
}

async fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
	let until = Instant::now() + Duration::from_secs(15);
	while !holds() {
		assert!(Instant::now() < until, "{what}");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn document(dns: SocketAddr, socks: SocketAddr) -> Value {
	json!({
		"version": 1,
		"dns": {"servers": [dns.to_string()]},
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&[0x11; 32]), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": free().to_string()}]},
			{"tag": "s", "type": "socks5", "listen": socks.to_string()}
		],
		"outbounds": [{"tag": "plain", "type": "direct"}, {"tag": "up", "type": "xray", "protocol": "vless", "server": "93.184.216.34:443", "id": "3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c", "security": {"type": "tls", "server_name": "front.example"}}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "far", "backend": {"type": "netstack", "outbound": "up"}}],
		"routing": {"default": "far", "rules": []},
		"users": [{"name": "alice", "exits": "all", "proxy_password": ALICE, "devices": [{"name": "laptop", "public_key": veilway_wg::encode_key(&[0x21; 32]), "addresses": ["10.7.0.2"]}]}]
	})
}

/// A CONNECT to `target` through the node's SOCKS5 inbound as alice: the reply code.
async fn connect(socks: SocketAddr, target: SocketAddr) -> u8 {
	let mut stream = TcpStream::connect(socks).await.unwrap();
	stream.write_all(&[5, 2, 0, 2]).await.unwrap();
	let mut said = [0u8; 2];
	stream.read_exact(&mut said).await.unwrap();
	stream.write_all(&[&[1, 5][..], b"alice", &[ALICE.len() as u8], ALICE.as_bytes()].concat()).await.unwrap();
	stream.read_exact(&mut said).await.unwrap();
	assert_eq!(said, [1, 0]);
	let IpAddr::V4(ip) = target.ip() else {panic!("an IPv4 target")};
	stream.write_all(&[&[5, 1, 0, 1][..], &ip.octets(), &target.port().to_be_bytes()].concat()).await.unwrap();
	let mut head = [0u8; 4];
	tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut head)).await.unwrap().unwrap();
	head[1]
}

#[tokio::test]
async fn the_add_on_missing_takes_the_outbound_down_with_a_reason_and_nothing_goes_around_it() {
	let Some(own) = own() else {return};
	let echo = TcpListener::bind((own, 0)).await.unwrap();
	let (target, reached) = (echo.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)));
	let counted = reached.clone();
	tokio::spawn(async move {while echo.accept().await.is_ok() {counted.fetch_add(1, Ordering::SeqCst);}});
	let dir = std::env::temp_dir().join(format!("veilway-xray-out-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let (socket, socks) = (dir.join("host.sock"), free());
	let out = dir.join("out");
	std::fs::create_dir_all(&out).unwrap();
	let host = host(socket.clone()).await;
	let doc = document(SocketAddr::new(own, 53), socks);
	let config = Config::parse(doc.to_string().as_bytes()).unwrap();
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	let engine: Engine = veilway_core::start(&config, Options {is_local: |_| false, xray_socket: Some(socket), xray_dir: Some(out.clone()), xray_same_user: true, ..Options::new("")}).await.unwrap();
	eventually("the outbound was not told that the add-on is missing", || engine.xray_outbound_down("up").is_some_and(|why| why.contains("not installed"))).await;
	assert_ne!(connect(socks, target).await, 0, "a flow of an exit whose Xray outbound is down was carried");
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert_eq!(reached.load(Ordering::SeqCst), 0, "a flow of an exit whose Xray outbound is down left around it");
	host.mode.store(RUNS, Ordering::SeqCst);
	eventually("the outbound did not come up once the add-on started", || engine.xray_outbound_down("up").is_none()).await;
	let documents = host.documents.lock().unwrap().clone();
	let document = documents.last().unwrap();
	for inbound in document["inbounds"].as_array().unwrap() {
		assert!(inbound["listen"].as_str().unwrap().starts_with(out.to_str().unwrap()) && inbound["listen"].as_str().unwrap().ends_with(",0660"), "an Xray listener that is not a socket of the shared folder");
		assert!(inbound.get("port").is_none());
	}
	assert_eq!(document["inbounds"].as_array().unwrap().len(), 1);
	assert_eq!(document["inbounds"][0]["protocol"], "trojan");
	assert_eq!(document["inbounds"][0]["settings"]["clients"][0]["password"].as_str().unwrap().len(), 64);
	assert_eq!(document["routing"]["rules"][0]["inboundTag"][0], "out-up");
	assert_eq!(document["outbounds"][1]["settings"]["vnext"][0]["address"], "93.184.216.34");
	assert!(document["log"]["maskAddress"] == "full" && document["log"]["access"] == "none");
	let mut without = doc.clone();
	without["outbounds"] = json!([{"tag": "plain", "type": "direct"}]);
	without["exits"] = json!([{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}]);
	without["routing"]["default"] = json!("main");
	engine.reload(without.to_string().into_bytes(), None).await.unwrap();
	eventually("a removed outbound was still told to carry", || engine.xray_outbound_down("up").is_some()).await;
	eventually("Xray was not stopped once the config had no outbound of it", || host.held.load(Ordering::SeqCst) == 0).await;
	let _ = std::fs::remove_dir_all(dir);
}
