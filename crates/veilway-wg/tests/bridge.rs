//! Loopback end-to-end: test socket -> run_client -> serve -> UDP echo, and back.
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use veilway_wg::ws::{Stats, TlsFiles, MAX_CONNS, MAX_PENDING_PER_SOURCE, UPGRADE_TIMEOUT};

/// Bind a UDP echo server that bounces every datagram back to its sender.
async fn echo_server()->SocketAddr{
	let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr=sock.local_addr().unwrap();
	tokio::spawn(async move{
		let mut buf=[0u8; 65535];
		while let Ok((n, src))=sock.recv_from(&mut buf).await{let _=sock.send_to(&buf[..n], src).await;}
	});
	addr
}

/// Bring up echo + relay + bridge and return the bridge's local UDP address.
async fn stack(tls:Option<TlsFiles>, scheme:&str)->SocketAddr{
	let target=echo_server().await;
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let relay=listener.local_addr().unwrap();
	tokio::spawn(async move{veilway_wg::ws::serve(listener, tls, "/wg".to_string(), target).await.unwrap()});
	let client=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr=client.local_addr().unwrap();
	let url=format!("{scheme}://127.0.0.1:{}/wg", relay.port());
	tokio::spawn(async move{veilway_wg::ws::run_client_on(client, url, true).await.unwrap()});
	addr
}

/// Send every payload from a fresh socket and assert the echoes come back in the same order.
async fn roundtrip(bridge:SocketAddr, payloads:&[Vec<u8>]){
	let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(bridge).await.unwrap();
	for p in payloads{sock.send(p).await.unwrap();}
	let mut buf=[0u8; 65535];
	for p in payloads{
		let n=tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf)).await.expect("timed out waiting for echo").unwrap();
		assert_eq!(&buf[..n], &p[..], "echo mismatch for a {} byte datagram", p.len());
	}
}

fn payloads()->Vec<Vec<u8>>{
	vec![b"hello wireguard".to_vec(), (0..1400u32).map(|i| (i%251) as u8).collect(), vec![0x7f]]
}

#[tokio::test]
async fn plain_ws_roundtrip(){
	let bridge=stack(None, "ws").await;
	let p=payloads();
	tokio::join!(roundtrip(bridge, &p), roundtrip(bridge, &p));
}

#[tokio::test]
async fn tls_roundtrip_with_self_signed_cert(){
	let ck=rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
	let dir=std::env::temp_dir().join(format!("veilway-ws-test-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let (cert, key)=(dir.join("cert.pem"), dir.join("key.pem"));
	std::fs::write(&cert, ck.cert.pem()).unwrap();
	std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
	let bridge=stack(Some(TlsFiles{cert, key}), "wss").await;
	roundtrip(bridge, &payloads()).await;
	let _=std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pre_resolved_address_skips_dns(){
	let target=echo_server().await;
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let relay=listener.local_addr().unwrap();
	tokio::spawn(async move{veilway_wg::ws::serve(listener, None, "/wg".to_string(), target).await.unwrap()});
	let client=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridge=client.local_addr().unwrap();
	// The host in the url never resolves, so an echo only comes back if the bridge dialled `relay` itself.
	let url=format!("ws://does-not-resolve.invalid:{}/wg", relay.port());
	tokio::spawn(async move{veilway_wg::ws::run_client_to(client, url, false, Some(relay)).await.unwrap()});
	roundtrip(bridge, &payloads()).await;
}

/// Connections that never send the upgrade give their place back after UPGRADE_TIMEOUT, so they cannot keep everyone else out.
#[tokio::test]
async fn silent_connections_do_not_hold_the_relay_forever(){
	let target=echo_server().await;
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let relay=listener.local_addr().unwrap();
	let stats=Arc::new(Stats::default());
	tokio::spawn(veilway_wg::ws::relay(listener, None, vec![("/wg".to_string(), target)], 4, stats.clone()).unwrap());
	let mut silent=Vec::new();
	for _ in 0..5{silent.push(TcpStream::connect(relay).await.unwrap())}
	tokio::time::sleep(UPGRADE_TIMEOUT+Duration::from_secs(1)).await;
	assert_eq!((stats.stalled.load(Ordering::Relaxed), stats.refused.load(Ordering::Relaxed)), (4, 1), "four held a place until the timeout and the fifth found the relay full");
	let client=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridge=client.local_addr().unwrap();
	tokio::spawn(async move{veilway_wg::ws::run_client_on(client, format!("ws://{relay}/wg"), false).await.unwrap()});
	roundtrip(bridge, &payloads()).await;
	drop(silent);
}

/// One source cannot take every place with connections that have not upgraded yet, and gets its share back when they end.
#[tokio::test]
async fn unfinished_upgrades_are_bounded_per_source(){
	let target=echo_server().await;
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let relay=listener.local_addr().unwrap();
	let stats=Arc::new(Stats::default());
	tokio::spawn(veilway_wg::ws::relay(listener, None, vec![("/wg".to_string(), target)], MAX_CONNS, stats.clone()).unwrap());
	let mut silent=Vec::new();
	for _ in 0..MAX_PENDING_PER_SOURCE+8{silent.push(TcpStream::connect(relay).await.unwrap())}
	let deadline=Instant::now()+Duration::from_secs(3);
	while stats.refused.load(Ordering::Relaxed)<8{
		assert!(Instant::now()<deadline, "connections past the limit of one source were not refused");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	tokio::time::sleep(Duration::from_millis(200)).await;
	assert_eq!((stats.refused.load(Ordering::Relaxed), stats.stalled.load(Ordering::Relaxed)), (8, 0));
	drop(silent);
	let client=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridge=client.local_addr().unwrap();
	tokio::spawn(async move{veilway_wg::ws::run_client_on(client, format!("ws://{relay}/wg"), false).await.unwrap()});
	roundtrip(bridge, &payloads()).await;
}
