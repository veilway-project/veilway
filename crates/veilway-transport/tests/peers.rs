//! The stream transports against peers written here: TLS servers with every kind of certificate a client must refuse, servers that answer what no node answers, and a node that is only its keys, for what a session does once it is open.
//! The tests against the real node are in `veilway-core` (`tests/client.rs`), which is the crate that can depend on both.
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
use socket2::SockRef;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use veilway_proto::chunk::{Opener, Padding, Sealer};
use veilway_proto::keys::{Device, Table, TagKey};
use veilway_proto::proof::{self, Name, SessionKeys};
use veilway_proto::replay::{Decision, Replay, Started};
use veilway_proto::subscription::payload::Padding as Bounds;
use veilway_proto::subscription::Secret;
use veilway_proto::websocket::{self, BINARY, CLOSE, PING, PONG, TEXT};
use veilway_proto::{fronted, NoRandom};
use veilway_transport::{Answer, End, Ended, Env, Fault, Front, Kind, Link, Refusal, Refuse, Session, Source, State, Target, Unreachable, Want};

// Keys of tests: fixed patterns, and no secret of anything real.
const INBOUND: [u8; 32] = [0x11; 32];
const DEVICE: [u8; 32] = [0x22; 32];
const SECRET: [u8; 32] = [0x33; 32];
const TRANSPORT: [u8; 32] = [0x51; 32];
const NOW: u64 = 1_700_000_000;
const PATH: &str = "/assets/app-3f9c2e71.js";
const SECOND: Duration = Duration::from_secs(1);
const MISS: &[u8] = b"HTTP/1.1 404 Not Found\r\nDate: Tue, 14 Nov 2023 22:13:20 GMT\r\nContent-Length: 13\r\n\r\nnothing here\n";
const PLAIN: Kind = Kind::Packet {flow: 0, control: false};

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| NoRandom)}

/// A root of the tests' own, and what signs with it.
struct Root {roots: Arc<RootCertStore>, issuer: Issuer<'static, KeyPair>}

fn root() -> Root {
	let (key, mut params, mut roots) = (KeyPair::generate().unwrap(), CertificateParams::new(Vec::new()).unwrap(), RootCertStore::empty());
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.distinguished_name.push(DnType::CommonName, "a root of the tests");
	roots.add(params.self_signed(&key).unwrap().der().clone()).unwrap();
	Root {roots: Arc::new(roots), issuer: Issuer::new(params, key)}
}

/// A certificate for `name` with a key of its own, signed by `issuer` or by itself, valid now or in 2020 alone, in the config of a server that speaks `versions`. With it the pin of its key: the SHA-256 of the SubjectPublicKeyInfo.
fn served(issuer: Option<&Issuer<'static, KeyPair>>, name: &str, expired: bool, versions: &[&'static SupportedProtocolVersion]) -> (Arc<ServerConfig>, [u8; 32]) {
	let (config, pin, _) = certified(issuer, name, expired.then(|| (date_time_ymd(2020, 1, 1), date_time_ymd(2020, 12, 31))), &[], versions);
	(config, pin)
}

/// The same with the time the certificate is valid in, when it is not "now and long after", and with the certificates the server sends behind its own: the authority between it and the root. The certificate itself comes back too.
fn certified(issuer: Option<&Issuer<'static, KeyPair>>, name: &str, valid: Option<(OffsetDateTime, OffsetDateTime)>, above: &[CertificateDer<'static>], versions: &[&'static SupportedProtocolVersion]) -> (Arc<ServerConfig>, [u8; 32], CertificateDer<'static>) {
	let (key, mut params) = (KeyPair::generate().unwrap(), CertificateParams::new(vec![name.to_string()]).unwrap());
	if let Some(valid) = valid {(params.not_before, params.not_after) = valid}
	let cert = match issuer {
		Some(issuer) => params.signed_by(&key, issuer),
		None => params.self_signed(&key),
	}.unwrap();
	let (own, chain) = (CertificateDer::from(cert.der().to_vec()), [&[CertificateDer::from(cert.der().to_vec())][..], above].concat());
	let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_protocol_versions(versions).unwrap().with_no_client_auth().with_single_cert(chain, PrivateKeyDer::try_from(key.serialize_der()).unwrap()).unwrap();
	// A front that speaks HTTP/1.1 only picks it from the client's list, as the stream transports need.
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	(Arc::new(config), digest(&SHA256, &key.subject_public_key_info()).as_ref().try_into().unwrap(), own)
}

/// A TLS server that hands every connection whose handshake ends to `serve`, with its number and the server name the client sent. `met` counts the TCP connections.
async fn server<F: Fn(usize, Option<String>, TlsStream<TcpStream>) -> R + Send + Sync + 'static, R: Future<Output = ()> + Send + 'static>(config: Arc<ServerConfig>, serve: F) -> (SocketAddr, Arc<AtomicUsize>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (addr, met, serve) = (listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)), Arc::new(serve));
	tokio::spawn({
		let met = met.clone();
		async move {
			loop {
				let Ok((stream, _)) = listener.accept().await else {return};
				let (at, acceptor, serve) = (met.fetch_add(1, Ordering::SeqCst), TlsAcceptor::from(config.clone()), serve.clone());
				tokio::spawn(async move {
					if let Ok(io) = acceptor.accept(stream).await {
						let name = io.get_ref().1.server_name().map(str::to_owned);
						serve(at, name, io).await;
					}
				});
			}
		}
	});
	(addr, met)
}

/// Reads one request head. What came behind it stays in the second place.
async fn head(io: &mut TlsStream<TcpStream>) -> Option<(String, Vec<u8>)> {
	let (mut got, mut buf) = (Vec::new(), vec![0u8; 65536]);
	loop {
		if let Some(end) = got.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {return Some((String::from_utf8_lossy(&got[..end]).into_owned(), got[end..].to_vec()))}
		match io.read(&mut buf).await {
			Ok(count) if count > 0 => got.extend_from_slice(&buf[..count]),
			_ => return None,
		}
	}
}

/// The answer that opens a WebSocket for the request with this head.
fn upgraded(head: &str) -> Vec<u8> {format!("HTTP/1.1 101 Switching Protocols\r\nServer: decoy/1.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSet-Cookie: sid=q0w9e8r7t6y5u4i3\r\n\r\n", websocket::accept(head.split("\r\n").find_map(|line| line.strip_prefix("Sec-WebSocket-Key: ")).expect("no key").as_bytes())).into_bytes()}

/// A server that reads a request head, answers it with `answer` and does what `hold` says: keeps the connection or closes it.
async fn answering(config: Arc<ServerConfig>, answer: &'static [u8], hold: bool) -> (SocketAddr, Arc<AtomicUsize>) {
	server(config, move |_, _, mut io| async move {
		if head(&mut io).await.is_none() {return}
		let _ = io.write_all(answer).await;
		let _ = io.flush().await;
		if hold {sleep(Duration::from_secs(30)).await} else {let _ = io.shutdown().await;}
	}).await
}

/// A server that opens a WebSocket for whatever asks, writes `frames` and keeps the connection. What the client sent after its request is in `said` once it closed.
async fn framing(config: Arc<ServerConfig>, frames: Vec<u8>, said: Arc<Mutex<Vec<u8>>>) -> SocketAddr {
	server(config, move |_, _, mut io| {
		let (frames, said) = (frames.clone(), said.clone());
		async move {
			let Some((head, rest)) = head(&mut io).await else {return};
			said.lock().unwrap().extend_from_slice(&rest);
			let _ = io.write_all(&[&upgraded(&head)[..], &frames].concat()).await;
			let _ = io.flush().await;
			let mut buf = vec![0u8; 65536];
			while let Ok(count) = io.read(&mut buf).await {
				if count == 0 {break}
				said.lock().unwrap().extend_from_slice(&buf[..count]);
			}
		}
	}).await.0
}

fn link(keepalive: u32) -> Link {Link {inbound: INBOUND, device: DEVICE, secret: Secret::new(SECRET), node: Some(proof::public_key(&TRANSPORT)), mtu: 1390, padding: Bounds {wide_max: 1023, normal_max: 255, keepalive: keepalive..=keepalive}}}

fn env(roots: &Arc<RootCertStore>) -> Env {Env {device: Arc::new(|| NOW), now: Arc::new(|| NOW), roots: roots.clone(), socket: None}}

/// A WireGuard layer in shape: a handshake initiation of 148 bytes to open with, and a keepalive of 32.
fn source() -> Source {
	Arc::new(Mutex::new(|want: Want| Some(match want {
		Want::First => [&[1, 0, 0, 0][..], &[0xee; 144]].concat(),
		Want::Keepalive => [&[4, 0, 0, 0][..], &[0; 28]].concat(),
	})))
}

fn front(address: SocketAddr, sni: &str, pins: &[[u8; 32]]) -> Front {Front {address, sni: Some(sni.into()), host: "node.test".into(), verify_name: None, pins: pins.to_vec(), ech: false, self_signed: false, http2: Default::default()}}

fn ws(candidate: Front) -> Target {Target::Ws {path: PATH.into(), candidate}}

/// How a session ends, with whatever it carried until then thrown away. It must end inside `budget`.
async fn end(session: &mut Session, budget: Duration) -> Ended {
	timeout(budget, async {
		loop {
			if let Err(ended) = session.recv().await {return ended}
		}
	}).await.expect("the session did not end in time")
}

async fn tried(roots: &Arc<RootCertStore>, target: Target) -> Ended {end(&mut Session::open(&link(20_000), target, env(roots), source()).unwrap(), 15 * SECOND).await}

const REFUSED: Ended = Ended::Refused(Refusal {answer: Answer::Status(404), offset: None});
// The servers of these tests write the `Date` the device's clock shows, so the offset of a pinned refusal is nothing.
const DATED: Ended = Ended::Refused(Refusal {answer: Answer::Status(404), offset: Some(0)});
const NO_CERTIFICATE: Ended = Ended::Unreachable(Unreachable::Certificate);
const WRONG_TIME: Ended = Ended::Unreachable(Unreachable::CertificateTime);

// Fail-closed rule 4: "A certificate that does not validate, or does not match a pin where the profile has one, ends the attempt. There is no continue anyway and no retry without the check."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_certificate_is_held_against_the_roots_the_name_the_clock_and_the_pins() {
	let (root, stranger) = (root(), root());
	let both = &[&TLS13, &TLS12][..];
	let ((good, pin), (other_name, other_pin), (expired, old_pin), (alone, alone_pin), (unknown, unknown_pin), (older, older_pin)) = (served(Some(&root.issuer), "node.test", false, both), served(Some(&root.issuer), "other.test", false, both), served(Some(&root.issuer), "node.test", true, both), served(None, "node.test", false, both), served(Some(&stranger.issuer), "node.test", false, both), served(Some(&root.issuer), "node.test", false, &[&TLS12]));
	let mut servers = Vec::new();
	for config in [good, other_name, expired, alone, unknown, older] {servers.push(answering(config, MISS, false).await)}
	let at = |server: usize| servers[server].0;
	// A chain to a root the client holds, for the name it asked for, valid now: TLS is done, and the server's 404 is a refusal. Its `Date` is read with a pin that matched and not without.
	assert_eq!(tried(&root.roots, ws(front(at(0), "node.test", &[]))).await, REFUSED);
	assert_eq!(tried(&root.roots, ws(front(at(0), "node.test", &[pin]))).await, DATED);
	assert_eq!(tried(&root.roots, Target::Tls {path: PATH.into(), candidate: front(at(0), "node.test", &[other_pin, pin])}).await, DATED);
	// A pin that does not match ends it, though the chain validates.
	assert_eq!(tried(&root.roots, ws(front(at(0), "node.test", &[other_pin]))).await, NO_CERTIFICATE);
	assert_eq!(tried(&root.roots, Target::Tls {path: PATH.into(), candidate: front(at(0), "node.test", &[other_pin, old_pin, alone_pin, unknown_pin])}).await, NO_CERTIFICATE);
	// Another name, a certificate that ran out, one that signed itself and one from a root the client does not hold: each ends it, without a pin and with the pin of that very key. A pin is a second condition and never replaces the first.
	// The one that ran out is told apart, because the device's clock is the first thing to look at then. It is refused all the same.
	for (server, pin, wanted) in [(1, other_pin, NO_CERTIFICATE), (2, old_pin, WRONG_TIME), (3, alone_pin, NO_CERTIFICATE), (4, unknown_pin, NO_CERTIFICATE)] {
		assert_eq!(tried(&root.roots, ws(front(at(server), "node.test", &[]))).await, wanted, "server {server} without a pin");
		assert_eq!(tried(&root.roots, ws(front(at(server), "node.test", &[pin]))).await, wanted, "server {server} with its pin");
		assert_eq!(tried(&root.roots, Target::Tls {path: PATH.into(), candidate: front(at(server), "node.test", &[pin])}).await, wanted, "server {server} over tls");
	}
	// No root at all is a fault of the device and no verdict on a candidate: the session is not opened, and nothing is dialled.
	assert_eq!(Session::open(&link(20_000), ws(front(at(0), "node.test", &[pin])), env(&Arc::new(RootCertStore::empty())), source()).map(|_| ()).unwrap_err(), Refuse::Roots);
	// "The client requires TLS 1.3 on a pinned candidate and accepts what the CDN negotiates otherwise."
	assert_eq!(tried(&root.roots, ws(front(at(5), "node.test", &[]))).await, REFUSED);
	assert_eq!(tried(&root.roots, ws(front(at(5), "node.test", &[older_pin]))).await, Ended::Unreachable(Unreachable::Tls));
	// Every server was met once for each attempt and no more: nothing was tried again with fewer checks.
	assert_eq!(servers.iter().map(|(_, met)| met.load(Ordering::SeqCst)).collect::<Vec<_>>(), [5, 3, 3, 3, 3, 2]);
}

// What a server answers with whatever it is asked: a certificate, and a key that may not be its own.
#[derive(Debug)]
struct Shown(Arc<CertifiedKey>);

impl ResolvesServerCert for Shown {
	fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {Some(self.0.clone())}
}

// The `tls` client step 1, second path: "only on a candidate whose `self_signed` member is `true`: the chain, the name and the validity dates are not checked. The leaf's public key must match a pin of that candidate. The TLS 1.3 handshake's signature is always verified against that pinned key."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_self_signed_candidate_is_held_to_its_pins_and_to_the_key_that_signs_the_handshake() {
	let (root, provider) = (root(), Arc::new(rustls::crypto::ring::default_provider()));
	let ((alone, pin, own), (renamed, renamed_pin, _), (expired, expired_pin, _)) = (certified(None, "node.test", None, &[], &[&TLS13]), certified(None, "other.test", None, &[], &[&TLS13]), certified(None, "node.test", Some((date_time_ymd(2020, 1, 1), date_time_ymd(2020, 12, 31))), &[], &[&TLS13]));
	let (older, older_pin) = served(None, "node.test", false, &[&TLS12]);
	// The pinned certificate, shown by a server that signs with another key.
	let forged = ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&TLS13]).unwrap().with_no_client_auth().with_cert_resolver(Arc::new(Shown(Arc::new(CertifiedKey::new(vec![own], provider.key_provider.load_private_key(PrivateKeyDer::try_from(KeyPair::generate().unwrap().serialize_der()).unwrap()).unwrap())))));
	let mut servers = Vec::new();
	for config in [alone, renamed, expired, Arc::new(forged), older] {servers.push(answering(config, MISS, false).await)}
	let at = |server: usize| servers[server].0;
	let alone = |server: usize, sni: Option<&str>, pins: &[[u8; 32]]| Target::Tls {path: PATH.into(), candidate: Front {sni: sni.map(str::to_owned), self_signed: true, ..front(at(server), "", pins)}};
	// The pin is the whole check: with a server name or none, for a name the certificate does not have, and long after it ran out. The root store plays no part, an empty one included. The pin matched, so the `Date` of the refusal is read.
	for (server, sni, pins) in [(0, Some("node.test"), vec![pin]), (0, None, vec![older_pin, pin]), (1, Some("node.test"), vec![renamed_pin]), (2, None, vec![expired_pin])] {
		assert_eq!(tried(&root.roots, alone(server, sni, &pins)).await, DATED, "server {server}");
		assert_eq!(tried(&Arc::new(RootCertStore::empty()), alone(server, sni, &pins)).await, DATED, "server {server} with no roots");
	}
	// A pin that does not match ends it at once, and so does the pinned certificate from a server that does not hold its key: a certificate is public, the key is what is proven.
	for (server, pins) in [(0, vec![renamed_pin, expired_pin]), (3, vec![pin])] {
		let started = Instant::now();
		assert_eq!(tried(&root.roots, alone(server, None, &pins)).await, NO_CERTIFICATE, "server {server}");
		assert!(started.elapsed() < 2 * SECOND, "server {server} took {:?}", started.elapsed());
	}
	// TLS 1.3 or nothing.
	assert_eq!(tried(&root.roots, alone(4, None, &[older_pin])).await, Ended::Unreachable(Unreachable::Tls));
	// The server cannot put a candidate on this path: one from an authority is refused the self-signed certificate it pinned, and the forged one.
	for server in [0, 3] {assert_eq!(tried(&root.roots, Target::Tls {path: PATH.into(), candidate: front(at(server), "node.test", &[pin])}).await, NO_CERTIFICATE, "server {server}")}
	// What a profile can never hold is not dialled: `self_signed` on another transport, with a `verify_name`, or without a pin.
	let open = |target: Target| Session::open(&link(20_000), target, env(&root.roots), source()).map(|_| ()).unwrap_err();
	assert_eq!(open(ws(Front {self_signed: true, ..front(at(0), "node.test", &[pin])})), Refuse::SelfSigned);
	assert_eq!(open(Target::Fronted {path: PATH.into(), candidate: Front {self_signed: true, ..front(at(0), "node.test", &[])}}), Refuse::SelfSigned);
	assert_eq!(open(Target::Tls {path: PATH.into(), candidate: Front {sni: None, verify_name: Some("node.test".into()), self_signed: true, ..front(at(0), "", &[pin])}}), Refuse::SelfSigned);
	assert_eq!(open(alone(0, None, &[])), Refuse::Pins);
	assert_eq!(servers.iter().map(|(_, met)| met.load(Ordering::SeqCst)).collect::<Vec<_>>(), [6, 2, 2, 2, 1]);
}

// "A candidate says where to connect and which names to show": the address, the server name and the `Host` are three fields.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn the_names_of_a_candidate_are_used_as_they_are_written() {
	let (root, seen) = (root(), Arc::new(Mutex::new(Vec::new())));
	let (config, _) = served(Some(&root.issuer), "front.test", false, &[&TLS13]);
	let (addr, _) = server(config, {
		let seen = seen.clone();
		move |_, name, mut io| {
			let seen = seen.clone();
			async move {
				let Some((head, _)) = head(&mut io).await else {return};
				seen.lock().unwrap().push((name, head));
				let _ = io.write_all(MISS).await;
				let _ = io.shutdown().await;
			}
		}
	}).await;
	// The server name of one host and the `Host` of another, on an address neither was looked up for.
	assert_eq!(tried(&root.roots, ws(front(addr, "front.test", &[]))).await, REFUSED);
	// No server name: nothing is sent, and the certificate is held against `verify_name`.
	let unnamed = |verify: &str| Front {sni: None, verify_name: Some(verify.into()), ..front(addr, "", &[])};
	assert_eq!(tried(&root.roots, ws(unnamed("front.test"))).await, REFUSED);
	assert_eq!(tried(&root.roots, ws(unnamed("node.test"))).await, NO_CERTIFICATE);
	assert_eq!(tried(&root.roots, Target::Fronted {path: PATH.into(), candidate: front(addr, "front.test", &[])}).await, REFUSED);
	let seen = seen.lock().unwrap().clone();
	assert_eq!(seen.iter().map(|(name, _)| name.as_deref()).collect::<Vec<_>>(), [Some("front.test"), None, Some("front.test")]);
	let host = format!("Host: node.test:{}\r\n", addr.port());
	assert!(seen.iter().all(|(_, head)| head.matches(&host).count() == 1 && head.matches("Host:").count() == 1), "{seen:?}");
	// The upgrade request: the path with a token of 144 to 272 characters for its query, and the three fields a node requires.
	let line = seen[0].1.split("\r\n").next().unwrap();
	let token = line.strip_prefix(&format!("GET {PATH}?")).and_then(|rest| rest.strip_suffix(" HTTP/1.1")).expect("no request line of an upgrade");
	assert!((144..=272).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'), "{line}");
	assert!(["Upgrade: websocket\r\n", "Connection: Upgrade\r\n", "Sec-WebSocket-Version: 13\r\n", "Sec-WebSocket-Key: "].iter().all(|field| seen[0].1.contains(field)) && !seen[0].1.to_ascii_lowercase().contains("cookie"));
	// The opening request of `fronted`: a POST with one length and a body.
	assert!(seen[2].1.starts_with(&format!("POST {PATH}?")) && seen[2].1.matches("Content-Length: ").count() == 1 && seen[2].1.contains("Content-Type: application/octet-stream\r\n") && !seen[2].1.contains("Transfer-Encoding"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn what_cannot_be_checked_is_not_dialled() {
	let root = root();
	let (config, pin) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, met) = answering(config, MISS, false).await;
	let open = |link: &Link, target: Target| Session::open(link, target, env(&root.roots), source()).map(|_| ()).unwrap_err();
	// Encrypted Client Hello is not built: the candidate is refused and not dialled without it.
	assert_eq!(open(&link(20_000), ws(Front {ech: true, ..front(addr, "node.test", &[pin])})), Refuse::Ech);
	// `tls` is the node's own certificate: a pin is asked on top of the chain, and a candidate without one is not dialled.
	assert_eq!(open(&link(20_000), Target::Tls {path: PATH.into(), candidate: front(addr, "node.test", &[])}), Refuse::Pins);
	assert_eq!(open(&Link {node: None, ..link(20_000)}, ws(front(addr, "node.test", &[]))), Refuse::NodeKey);
	assert_eq!(open(&link(20_000), ws(Front {sni: None, ..front(addr, "", &[])})), Refuse::Name);
	assert_eq!(open(&link(20_000), ws(front(addr, "192.0.2.7", &[]))), Refuse::Name);
	// A profile's own bounds: padding and the keepalive range are inside the page's or the session is not opened.
	assert_eq!(open(&link(9_999), ws(front(addr, "node.test", &[]))), Refuse::Padding);
	assert_eq!(open(&Link {padding: Bounds {wide_max: 1024, normal_max: 255, keepalive: 20_000..=40_000}, ..link(20_000)}, Target::UdpObfs(addr)), Refuse::Padding);
	sleep(Duration::from_millis(200)).await;
	assert_eq!(met.load(Ordering::SeqCst), 0);
	// Nobody listens: unreachable, and at once.
	let nobody = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	assert_eq!(tried(&root.roots, ws(front(nobody, "node.test", &[]))).await, Ended::Unreachable(Unreachable::Connect));
}

// "Gives each transport 10 s to carry a chunk from the node." Whatever a peer does not finish, the attempt is over then.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_peer_that_never_finishes_costs_ten_seconds_and_no_more() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	// A listener that takes the connection and says nothing, a server that reads the request and says nothing, one whose head never ends, and one that opens the WebSocket and never sends a chunk.
	let mute = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (quiet, _) = server(config.clone(), |_, _, mut io| async move {
		let _ = head(&mut io).await;
		sleep(Duration::from_secs(30)).await;
	}).await;
	let (endless, _) = server(config.clone(), |_, _, mut io| async move {
		let _ = head(&mut io).await;
		let _ = io.write_all(b"HTTP/1.1 200 OK\r\n").await;
		while io.write_all(b"X-Pad: aaaaaaaaaaaaaaaa\r\n").await.is_ok() && io.flush().await.is_ok() {sleep(Duration::from_millis(250)).await}
	}).await;
	let (opened, _) = server(config, |_, _, mut io| async move {
		let Some((head, _)) = head(&mut io).await else {return};
		let _ = io.write_all(&upgraded(&head)).await;
		let _ = io.flush().await;
		sleep(Duration::from_secs(30)).await;
	}).await;
	let (started, mut sessions) = (Instant::now(), Vec::new());
	for target in [ws(front(mute.local_addr().unwrap(), "node.test", &[])), ws(front(quiet, "node.test", &[])), ws(front(endless, "node.test", &[])), ws(front(opened, "node.test", &[])), Target::Fronted {path: PATH.into(), candidate: front(quiet, "node.test", &[])}, Target::Fronted {path: PATH.into(), candidate: front(endless, "node.test", &[])}] {sessions.push(Session::open(&link(20_000), target, env(&root.roots), source()).unwrap())}
	for session in &mut sessions {
		assert_eq!(end(session, 13 * SECOND).await, Ended::Unreachable(Unreachable::Timeout));
		assert!((9_800..=12_500).contains(&started.elapsed().as_millis()), "{:?}", started.elapsed());
	}
}

// "An HTTP answer that arrived over validated TLS means the node or its front was reached and said no", and so does "a close with no answer".
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn every_answer_that_is_no_session_is_a_refusal_and_is_read_inside_its_bound() {
	let root = root();
	let (config, pin) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let refusal = |answer| Ended::Refused(Refusal {answer, offset: None});
	for (answer, hold, wanted) in [
		(MISS, true, Answer::Status(404)),
		(&b"HTTP/1.0 503 Service Unavailable\r\n\r\n"[..], true, Answer::Status(503)),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true, Answer::Status(200)),
		(b"", false, Answer::Closed),
		(b"HTTP/1.1 101 Switching Proto", false, Answer::NotHttp),
		(b"\x15\x03\x03\x00\x02\x02\x28 no http at all\r\n\r\n", true, Answer::NotHttp),
		(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", true, Answer::Accept),
		(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", true, Answer::Accept),
	] {
		let (addr, _) = answering(config.clone(), answer, hold).await;
		let started = Instant::now();
		assert_eq!(tried(&root.roots, ws(front(addr, "node.test", &[]))).await, refusal(wanted), "{:?}", String::from_utf8_lossy(answer));
		assert!(started.elapsed() < 2 * SECOND, "{:?} after {:?}", String::from_utf8_lossy(answer), started.elapsed());
	}
	// A head without an end: the client reads 16,384 bytes of it and not the megabytes behind them.
	let written = Arc::new(AtomicUsize::new(0));
	let (flood, _) = server(config.clone(), {
		let written = written.clone();
		move |_, _, mut io| {
			let written = written.clone();
			async move {
				let _ = head(&mut io).await;
				let _ = io.write_all(b"HTTP/1.1 101 Switching Protocols\r\n").await;
				while io.write_all(&[b'a'; 4096]).await.is_ok() && io.flush().await.is_ok() {
					if written.fetch_add(4096, Ordering::SeqCst) > 64 << 20 {return}
				}
			}
		}
	}).await;
	let started = Instant::now();
	assert_eq!(tried(&root.roots, ws(front(flood, "node.test", &[pin]))).await, refusal(Answer::NotHttp));
	assert_eq!(tried(&root.roots, Target::Fronted {path: PATH.into(), candidate: front(flood, "node.test", &[])}).await, refusal(Answer::NotHttp));
	assert!(started.elapsed() < 4 * SECOND && written.load(Ordering::SeqCst) < 16 << 20, "{:?}, {} bytes", started.elapsed(), written.load(Ordering::SeqCst));
	// The WebSocket was opened and the connection closed before a chunk of the node: still no session, and a refusal.
	let (addr, _) = server(config, |_, _, mut io| async move {
		let Some((head, _)) = head(&mut io).await else {return};
		let _ = io.write_all(&upgraded(&head)).await;
		let _ = io.shutdown().await;
		// What the client sent is read before the drop: on Windows a close with unread data is a reset, which the client rightly calls a cut.
		let _ = tokio::time::timeout(SECOND, async {let mut buf = [0u8; 4096]; while matches!(io.read(&mut buf).await, Ok(read) if read > 0) {}}).await;
	}).await;
	assert_eq!(tried(&root.roots, ws(front(addr, "node.test", &[]))).await, refusal(Answer::Unopened));
}

// "A message longer than 16,016 bytes, a text message or a fragmented message ends the session", and so does a chunk that does not open.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn frames_no_node_sends_end_the_session_with_the_one_close() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let framed = |opcode: u8, payload: &[u8], key: Option<[u8; 4]>| {
		let mut out = Vec::new();
		websocket::frame(opcode, payload, key, &mut out);
		out
	};
	let mut cases = Vec::new();
	for (frames, fault) in [
		// A frame with a mask, which no server sends.
		(framed(BINARY, &[7; 64], Some([1, 2, 3, 4])), Fault::Frame),
		// The header of a frame of 16,017 bytes and of one of 2^62, with nothing behind either: the verdict falls at the header.
		(vec![0x82, 126, 0x3e, 0x91], Fault::Frame),
		(vec![0x82, 127, 0x40, 0, 0, 0, 0, 0, 0, 0], Fault::Frame),
		(framed(TEXT, &[b'a'; 64], None), Fault::Frame),
		(vec![0x02, 64], Fault::Frame),
		(vec![0x80, 64], Fault::Frame),
		(vec![0xc2, 64], Fault::Frame),
		(vec![0x83, 0], Fault::Frame),
		(framed(BINARY, &[7; 15], None), Fault::Frame),
		(vec![0x89, 126, 0, 126], Fault::Frame),
		// Bytes nobody sealed, in a frame that is one.
		(framed(BINARY, &[7; 64], None), Fault::Chunk),
		(framed(BINARY, &[0; 16_016], None), Fault::Chunk),
	] {
		let said = Arc::new(Mutex::new(Vec::new()));
		let addr = framing(config.clone(), frames.clone(), said.clone()).await;
		let (started, mut session) = (Instant::now(), Session::open(&link(20_000), ws(front(addr, "node.test", &[])), env(&root.roots), source()).unwrap());
		// The caller is told at once, and the session is over for it.
		assert_eq!(end(&mut session, 3 * SECOND).await, Ended::Closed(End::Fault(fault)), "{:?}", &frames[..frames.len().min(12)]);
		assert_eq!((session.state(), session.send(vec![4; 64], PLAIN)), (State::Ended(Ended::Closed(End::Fault(fault))), false));
		assert!(started.elapsed() < 2 * SECOND, "{:?}", started.elapsed());
		cases.push((session, said));
	}
	// "Waits up to 5 s for the peer's Close frame, then closes TLS and TCP in the normal order whether or not it came." This peer sends none.
	sleep(6 * SECOND).await;
	for (_session, said) in cases {
		// What the client sent: its first chunk, in one masked binary frame, and then one Close frame with status 1000 and no reason. Nothing else, and nothing after.
		let said = said.lock().unwrap().clone();
		let first = websocket::header(&said).unwrap().unwrap();
		let close = websocket::header(&said[first.size + first.payload as usize..]).unwrap().unwrap();
		let mut status = said[said.len() - 2..].to_vec();
		websocket::mask(close.mask.unwrap(), &mut status);
		assert_eq!((first.opcode, first.fin, first.mask.is_some(), close.opcode, close.payload, status, said.len()), (BINARY, true, true, CLOSE, 2, vec![0x03, 0xe8], first.size + first.payload as usize + close.size + 2));
	}
}

/// Enough of a node to open a session with: the keys of a session for the token of a request, by the node's side of `veilway-proto`.
fn keys(name: Name, token: &str) -> SessionKeys {
	let (node, mut table) = (proof::Node::new(&[TRANSPORT], &INBOUND, &mut random).unwrap(), Table::new());
	assert!(table.device(TagKey::derive(&SECRET, &INBOUND).device_tag(), Device::derive((), &SECRET, &INBOUND, &DEVICE)));
	let Started::NoFile(pending) = Replay::start(None, NOW - 100, 9) else {panic!("a start without a file")};
	let mut replay = pending.written();
	assert!(replay.raise(NOW + 20).is_some());
	replay.written();
	let Decision::Accepted(accepted) = node.open(Some(name), token.as_bytes(), &table).expect("the token is no proof of the device").accept(&mut replay, NOW, |_| true) else {panic!("the replay rule refused a fresh proof")};
	accepted.keys
}

/// The node's end of one WebSocket session.
struct Fake {io: TlsStream<TcpStream>, tx: Sealer, rx: Opener, buf: Vec<u8>, pongs: Vec<Vec<u8>>, closed: Option<Vec<u8>>}

impl Fake {
	/// Reads the upgrade request, takes its proof and answers it.
	async fn accept(mut io: TlsStream<TcpStream>) -> Option<Fake> {
		let (head, buf) = head(&mut io).await?;
		let keys = keys(Name::Ws, head.split(' ').nth(1)?.split_once('?')?.1);
		io.write_all(&upgraded(&head)).await.ok()?;
		io.flush().await.ok()?;
		Some(Fake {io, tx: Sealer::new(keys.s2c, Padding::new(1023, 255, &mut random).unwrap()), rx: Opener::new(keys.c2s), buf, pongs: Vec::new(), closed: None})
	}

	/// The datagrams of the client's next chunk. None when the connection ended or the client closed the session, and `closed` then holds the payload of its Close frame. Every frame of a client must be masked.
	async fn chunk(&mut self) -> Option<Vec<Vec<u8>>> {
		let mut read = vec![0u8; 65536];
		loop {
			if let Some(header) = websocket::header(&self.buf).expect("the client sent what is no frame").filter(|header| self.buf.len() >= header.size + header.payload as usize) {
				let mut frame: Vec<u8> = self.buf.drain(..header.size + header.payload as usize).collect();
				websocket::mask(header.mask.expect("a frame of the client without a mask"), &mut frame[header.size..]);
				assert!(header.fin);
				match header.opcode {
					BINARY => return Some(self.rx.open(&mut frame[header.size..]).expect("the client sent a chunk that does not open").map(<[u8]>::to_vec).collect()),
					PONG => self.pongs.push(frame[header.size..].to_vec()),
					CLOSE => {
						self.closed = Some(frame[header.size..].to_vec());
						return None;
					}
					opcode => panic!("a frame of the client with the opcode {opcode}"),
				}
				continue;
			}
			match self.io.read(&mut read).await {
				Ok(count) if count > 0 => self.buf.extend_from_slice(&read[..count]),
				_ => return None,
			}
		}
	}

	/// One chunk with these datagrams, in one frame.
	async fn put(&mut self, datagrams: &[&[u8]]) {
		let mut sealed = Vec::new();
		self.tx.seal(datagrams, false, &mut random, &mut sealed).unwrap();
		self.frame(BINARY, &sealed).await;
	}

	async fn frame(&mut self, opcode: u8, payload: &[u8]) {
		let mut out = Vec::new();
		websocket::frame(opcode, payload, None, &mut out);
		let _ = self.io.write_all(&out).await;
		let _ = self.io.flush().await;
	}
}

async fn established(session: &Session) {
	let mut watch = session.watch();
	timeout(5 * SECOND, watch.wait_for(|state| *state == State::Established)).await.expect("no session in 5 s").unwrap();
}

// "The first thing a client sends on a new session is always a WireGuard packet", "a chunk from the node therefore always means that WireGuard has authenticated on that session", pings, and the close from either side.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_session_carries_datagrams_answers_pings_and_closes_in_order() {
	let (root, log) = (root(), Arc::new(Mutex::new(Vec::new())));
	let (config, pin) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, _) = server(config, {
		let log = log.clone();
		move |at, _, io| {
			let log = log.clone();
			async move {
				let mut fake = Fake::accept(io).await.unwrap();
				let first = fake.chunk().await.unwrap();
				// The node's first answer, a ping, and one datagram.
				fake.put(&[]).await;
				fake.frame(PING, b"are you there").await;
				fake.put(&[&[4; 100], &[4; 200]]).await;
				let second = fake.chunk().await.unwrap();
				if at == 0 {
					// The client closes: its Close frame is answered with one.
					let last = fake.chunk().await;
					fake.frame(CLOSE, &websocket::NORMAL).await;
					log.lock().unwrap().push((first, second, last, fake.pongs.clone(), fake.closed.clone()));
				} else {
					// The node closes, and the client answers with its own Close frame.
					fake.frame(CLOSE, &websocket::NORMAL).await;
					let last = fake.chunk().await;
					log.lock().unwrap().push((first, second, last, fake.pongs.clone(), fake.closed.clone()));
				}
			}
		}
	}).await;
	for closes in [true, false] {
		let mut session = Session::open(&link(20_000), ws(front(addr, "node.test", &[pin])), env(&root.roots), source()).unwrap();
		established(&session).await;
		assert_eq!((session.recv().await, session.recv().await), (Ok(vec![4; 100]), Ok(vec![4; 200])));
		assert!(session.send(vec![4; 300], PLAIN));
		let (started, numbers) = (Instant::now(), session.numbers());
		assert_eq!((numbers.received, numbers.dropped, numbers.heard.is_some()), (2, 0, true));
		let ended = if closes {session.close().await} else {end(&mut session, 3 * SECOND).await};
		assert_eq!(ended, Ended::Closed(if closes {End::Asked} else {End::Peer}));
		// The peer's Close frame came, so nobody waited 5 s for it.
		assert!(started.elapsed() < 2 * SECOND, "{:?}", started.elapsed());
	}
	sleep(Duration::from_millis(300)).await;
	let log = log.lock().unwrap().clone();
	assert_eq!(log.len(), 2);
	for (first, second, last, pongs, closed) in log {
		// The first chunk held the one datagram the WireGuard layer gave to open with, and nothing was sent before it.
		assert_eq!((first.len(), first[0].len(), first[0][0], second, last), (1, 148, 1, vec![vec![4; 300]], None));
		assert_eq!((pongs, closed), (vec![b"are you there".to_vec()], Some(vec![0x03, 0xe8])));
	}
}

// A node that is gone, one that sends a chunk again, and one that sends what it never sealed, each after the session was open.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_session_that_is_open_ends_for_good_when_its_node_breaks_it() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, _) = server(config, |at, _, io| async move {
		let mut fake = Fake::accept(io).await.unwrap();
		fake.chunk().await.unwrap();
		let mut sealed = Vec::new();
		fake.tx.seal(&[&[4; 64]], false, &mut random, &mut sealed).unwrap();
		fake.frame(BINARY, &sealed).await;
		match at {
			// The connection ends with no word.
			0 => {}
			// The same chunk a second time: its number has passed.
			1 => fake.frame(BINARY, &sealed).await,
			// A chunk that opens under no key of the session.
			_ => fake.frame(BINARY, &[9; 80]).await,
		}
		if at > 0 {while fake.chunk().await.is_some() {}}
	}).await;
	for wanted in [End::Lost, End::Fault(Fault::Chunk), End::Fault(Fault::Chunk)] {
		let mut session = Session::open(&link(20_000), ws(front(addr, "node.test", &[])), env(&root.roots), source()).unwrap();
		assert_eq!(session.recv().await, Ok(vec![4; 64]));
		assert_eq!(end(&mut session, 3 * SECOND).await, Ended::Closed(wanted));
		// Over is over: every later call gives the same end, and nothing more is taken.
		assert_eq!((session.recv().await, session.send(vec![4; 64], PLAIN), session.state()), (Err(Ended::Closed(wanted)), false, State::Ended(Ended::Closed(wanted))));
	}
}

// "An idle keepalive got no chunk back within 10 s": the session is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn an_idle_keepalive_that_gets_no_chunk_back_ends_the_session() {
	let (root, got) = (root(), Arc::new(Mutex::new(Vec::new())));
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, _) = server(config, {
		let got = got.clone();
		move |_, _, io| {
			let got = got.clone();
			async move {
				let mut fake = Fake::accept(io).await.unwrap();
				fake.chunk().await.unwrap();
				fake.put(&[]).await;
				// A node that reads and never answers again.
				while let Some(chunk) = fake.chunk().await {got.lock().unwrap().push((Instant::now(), chunk))}
			}
		}
	}).await;
	// The shortest idle keepalive a profile may set: 10 s.
	let (started, mut session) = (Instant::now(), Session::open(&link(10_000), ws(front(addr, "node.test", &[])), env(&root.roots), source()).unwrap());
	assert_eq!(end(&mut session, 30 * SECOND).await, Ended::Closed(End::Lost));
	// The keepalive after 10 s of silence and its own delay of up to 3 s, alone in its chunk, and the end 10 s after it.
	let got = got.lock().unwrap().clone();
	assert_eq!(got.iter().map(|(_, chunk)| chunk.iter().map(Vec::len).collect::<Vec<_>>()).collect::<Vec<_>>(), [vec![32]]);
	let (sent, ended) = (got[0].0.duration_since(started), started.elapsed());
	assert!((9_800..=13_600).contains(&sent.as_millis()) && (9_800..=10_800).contains(&(ended - sent).as_millis()), "the keepalive after {sent:?}, the end after {ended:?}");
}

// "A sender picks the connection for a datagram by a hash of the inner packet's addresses, protocol and ports, so one inner flow stays on one connection and in order. WireGuard handshake messages go on the connection that has been open longest."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn several_connections_keep_a_flow_on_one_and_are_read_from_all() {
	let (root, got) = (root(), Arc::new(Mutex::new(Vec::<(usize, Instant, Vec<u8>)>::new())));
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, met) = server(config, {
		let got = got.clone();
		move |at, _, io| {
			let got = got.clone();
			async move {
				let mut fake = Fake::accept(io).await.unwrap();
				// Each connection opens with a datagram of its own, and the node answers on each.
				for datagram in fake.chunk().await.unwrap() {got.lock().unwrap().push((at, Instant::now(), datagram))}
				fake.put(&[&[&[4, 0, 0, 0, 0xaa, at as u8][..], &[0; 34]].concat()]).await;
				while let Some(chunk) = fake.chunk().await {
					for datagram in chunk {got.lock().unwrap().push((at, Instant::now(), datagram))}
				}
			}
		}
	}).await;
	let mut session = Session::parallel(&link(20_000), ws(front(addr, "node.test", &[])), 3, env(&root.roots), source()).unwrap();
	// "The client opens the second and later connections one at a time, each after a delay drawn uniformly from 1 to 5 s", and every one of them gives the caller what its node sends.
	let mut answered = Vec::new();
	for _ in 0..3 {answered.push(timeout(8 * SECOND, session.recv()).await.expect("a connection was not opened in time").unwrap()[5])}
	assert_eq!((answered, met.load(Ordering::SeqCst)), (vec![0, 1, 2], 3));
	let opened: Vec<Instant> = got.lock().unwrap().iter().map(|(_, at, _)| *at).collect();
	assert!(opened.windows(2).all(|pair| (900..=5_500).contains(&(pair[1] - pair[0]).as_millis())), "{opened:?}");
	sleep(Duration::from_millis(300)).await;
	// Eight flows of forty datagrams each, numbered, and between them handshake messages.
	for number in 0..40u8 {
		for flow in 0..8u32 {assert!(session.send([&[4, 0, 0, 0, 0xbb, flow as u8, number][..], &[0; 57]].concat(), Kind::Packet {flow: flow * 7 + 1, control: false}))}
		if number % 10 == 0 {assert!(session.send([&[1, 0, 0, 0, 0xcc, 0, number][..], &[0; 141]].concat(), Kind::Handshake))}
		sleep(Duration::from_millis(5)).await;
	}
	sleep(SECOND).await;
	let got = got.lock().unwrap().clone();
	let mut used = std::collections::HashSet::new();
	for flow in 0..8u32 {
		let on: Vec<(usize, u8)> = got.iter().filter(|(_, _, datagram)| datagram[4] == 0xbb && datagram[5] == flow as u8).map(|(at, _, datagram)| (*at, datagram[6])).collect();
		// One connection for the whole flow, and its datagrams in the order they were sent.
		assert_eq!(on, (0..40).map(|number| (on[0].0, number)).collect::<Vec<_>>(), "the flow {flow}");
		used.insert(on[0].0);
	}
	assert!(used.len() >= 2, "eight flows on one connection of three");
	assert_eq!(got.iter().filter(|(_, _, datagram)| datagram[4] == 0xcc).map(|(at, _, datagram)| (*at, datagram[6])).collect::<Vec<_>>(), [(0, 0), (0, 10), (0, 20), (0, 30)]);
	assert_eq!((session.numbers().dropped, session.close().await), (0, Ended::Closed(End::Asked)));
}

/// A server of `fronted` that is a node for the opening request and answers the first later request with `later`, whatever it asks. What every request was is kept in `asked`: its target and its body.
async fn polled(config: Arc<ServerConfig>, opening: Option<&'static [u8]>, later: &'static [u8], asked: Arc<Mutex<Vec<(String, Vec<u8>)>>>) -> SocketAddr {
	server(config, move |_, _, mut io| {
		let asked = asked.clone();
		async move {
			loop {
				// One request: its head, and its body by the one length it has. One request is in flight, so nothing stands behind it.
				let Some((head, mut body)) = head(&mut io).await else {return};
				let length: usize = head.split("\r\n").find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
				let mut buf = vec![0u8; 65536];
				while body.len() < length {
					match io.read(&mut buf).await {
						Ok(count) if count > 0 => body.extend_from_slice(&buf[..count]),
						_ => return,
					}
				}
				assert_eq!(body.len(), length, "bytes behind a request");
				let target = head.split(' ').nth(1).unwrap().to_string();
				let first = asked.lock().unwrap().is_empty();
				asked.lock().unwrap().push((target.clone(), body.clone()));
				let answer = match (first, opening) {
					(true, Some(answer)) => answer.to_vec(),
					(true, None) => {
						// The node's first answer: the body opens under the keys of the proof, and one chunk comes back.
						let (keys, mut scratch, mut answer) = (keys(Name::Fronted, target.split_once('?').unwrap().1), Vec::new(), Vec::new());
						assert_eq!(fronted::Opener::new(keys.c2s).open(&body, &mut scratch).expect("the body of the opening request does not open").commit().len(), 1);
						fronted::append(&mut Sealer::new(keys.s2c, Padding::new(1023, 255, &mut random).unwrap()), &[&[2; 92]], false, &mut random, &mut answer).unwrap();
						[format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", answer.len()).as_bytes(), &answer].concat()
					}
					_ => later.to_vec(),
				};
				if io.write_all(&answer).await.is_err() || io.flush().await.is_err() {return}
			}
		}
	}).await.0
}

// "Drops the session when a request gets anything but a 200 with a body it can open. If that happens to the opening request, it is a refusal."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_front_that_answers_fronted_with_what_no_node_wrote_ends_the_session() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let target = |addr| Target::Fronted {path: PATH.into(), candidate: front(addr, "node.test", &[])};
	// The opening request: a 200 whose body is nobody's, of a wrong length, cut short, or followed by a byte.
	for (opening, wanted) in [
		(&b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..], Answer::Body),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\naaaaaaaaaaaaaaaaa", Answer::Body),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\naaaaaaaaaaaaaaaaaaa", Answer::Body),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nContent-Length: 18\r\n\r\naaaaaaaaaaaaaaaaaa", Answer::Body),
		(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\naaaaaaaaaaaaaaaaaa\r\n0\r\n\r\n", Answer::Body),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", Answer::Body),
		(b"HTTP/1.1 204 No Content\r\n\r\n", Answer::Status(204)),
		(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", Answer::Status(502)),
		(b"HTTP/1.1 100 Continue\r\n\r\n", Answer::Status(100)),
		(b"<html>an error page of no protocol</html>\r\n\r\n", Answer::NotHttp),
	] {
		let addr = polled(config.clone(), Some(opening), b"", Arc::default()).await;
		let started = Instant::now();
		assert_eq!(tried(&root.roots, target(addr)).await, Ended::Refused(Refusal {answer: wanted, offset: None}), "{:?}", String::from_utf8_lossy(opening));
		assert!(started.elapsed() < 2 * SECOND);
	}
	// A later request, on a session that is open.
	for (later, wanted) in [
		(&b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..], End::Fault(Fault::Chunk)),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\naaaaaaaaaaaaaaaaaaa", End::Fault(Fault::Response)),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nContent-Length: 18\r\n\r\naaaaaaaaaaaaaaaaaa", End::Fault(Fault::Response)),
		(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12\r\naaaaaaaaaaaaaaaaaa\r\n0\r\n\r\n", End::Fault(Fault::Response)),
		(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n", End::Fault(Fault::Response)),
		(b"garbage of no protocol\r\n\r\n", End::Fault(Fault::Response)),
		// The node no longer knows the session, and the origin answers: the session is lost, and that is no fault of anyone's.
		(b"HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\nnothing here\n", End::Lost),
	] {
		let asked = Arc::new(Mutex::new(Vec::new()));
		let addr = polled(config.clone(), None, later, asked.clone()).await;
		let (started, mut session) = (Instant::now(), Session::open(&link(20_000), target(addr), env(&root.roots), source()).unwrap());
		assert_eq!(session.recv().await, Ok(vec![2; 92]), "{:?}", String::from_utf8_lossy(later));
		assert_eq!(session.state(), State::Established);
		assert_eq!(end(&mut session, 3 * SECOND).await, Ended::Closed(wanted), "{:?}", String::from_utf8_lossy(later));
		assert!(started.elapsed() < 2 * SECOND);
		// The opening request and the first later one, numbered 1, and nothing after the session ended.
		sleep(Duration::from_millis(400)).await;
		let asked = asked.lock().unwrap().clone();
		assert!(asked.len() == 2 && asked[1].0.ends_with(".1") && asked[1].0.len() == PATH.len() + 1 + 22 + 2, "{:?}", asked.iter().map(|(target, _)| target).collect::<Vec<_>>());
	}
}

// "Drops the session when a request gets no response within 10 s."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_fronted_request_without_an_answer_costs_ten_seconds() {
	let (root, asked) = (root(), Arc::new(Mutex::new(Vec::new())));
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	// An answer that is promised whole and never is.
	let addr = polled(config, None, b"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\nhalf of it", asked.clone()).await;
	let mut session = Session::open(&link(20_000), Target::Fronted {path: PATH.into(), candidate: front(addr, "node.test", &[])}, env(&root.roots), source()).unwrap();
	assert_eq!(session.recv().await, Ok(vec![2; 92]));
	let started = Instant::now();
	assert_eq!(end(&mut session, 14 * SECOND).await, Ended::Closed(End::Lost));
	assert!((9_800..=11_500).contains(&started.elapsed().as_millis()), "{:?}", started.elapsed());
	assert_eq!(asked.lock().unwrap().len(), 2);
}

/// A WireGuard layer whose tunnel is up: it opens with a keepalive.
fn settled() -> Source {Arc::new(Mutex::new(|_: Want| Some([&[4, 0, 0, 0][..], &[0; 28]].concat())))}

/// How a server of these tests ends a connection: in order, with the `close_notify` of its TLS session, by dropping it with nothing said, or with a reset.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Finish {Notify, Drop, Reset}

async fn finish(mut io: TlsStream<TcpStream>, how: Finish) {
	match how {
		Finish::Notify => drop(io.shutdown().await),
		Finish::Drop => {}
		Finish::Reset => drop(SockRef::from(io.get_ref().0).set_linger(Some(Duration::ZERO))),
	}
}

// "A close counts only when it is authenticated: a TLS `close_notify`, or a WebSocket Close frame. A connection that is reset or ends without one, at any point after the handshake, is unreachable. Anyone on the path can cause it."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_connection_that_is_cut_is_unreachable_and_one_that_is_closed_in_order_is_a_refusal() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (refusal, cut) = (|answer| Ended::Refused(Refusal {answer, offset: None}), Ended::Unreachable(Unreachable::Cut));
	for how in [Finish::Notify, Finish::Drop, Finish::Reset] {
		// The request was read, and the connection ends with no answer.
		let (unanswered, _) = server(config.clone(), move |_, _, mut io| async move {
			let _ = head(&mut io).await;
			finish(io, how).await;
		}).await;
		// The WebSocket was opened, and the connection ends before a chunk.
		let (opened, _) = server(config.clone(), move |_, _, mut io| async move {
			let Some((head, _)) = head(&mut io).await else {return};
			let _ = io.write_all(&upgraded(&head)).await;
			let _ = io.flush().await;
			sleep(Duration::from_millis(100)).await;
			finish(io, how).await;
		}).await;
		// Half an answer, and then the end.
		let (halved, _) = server(config.clone(), move |_, _, mut io| async move {
			let _ = head(&mut io).await;
			let _ = io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\nhalf of it").await;
			let _ = io.flush().await;
			sleep(Duration::from_millis(100)).await;
			finish(io, how).await;
		}).await;
		let fronted = |addr| Target::Fronted {path: PATH.into(), candidate: front(addr, "node.test", &[])};
		let in_order = how == Finish::Notify;
		let started = Instant::now();
		assert_eq!(tried(&root.roots, ws(front(unanswered, "node.test", &[]))).await, if in_order {refusal(Answer::Closed)} else {cut}, "{how:?} with no answer to the upgrade");
		assert_eq!(tried(&root.roots, fronted(unanswered)).await, if in_order {refusal(Answer::Closed)} else {cut}, "{how:?} with no answer to the opening request");
		assert_eq!(tried(&root.roots, ws(front(opened, "node.test", &[]))).await, if in_order {refusal(Answer::Unopened)} else {cut}, "{how:?} behind the upgrade answer");
		assert_eq!(tried(&root.roots, fronted(halved)).await, if in_order {refusal(Answer::Closed)} else {cut}, "{how:?} inside the answer to the opening request");
		// A session that opened with a keepalive and is closed in order behind the upgrade answer met a node that does not know its tunnel. Cut, it met the path.
		assert_eq!(end(&mut Session::open(&link(20_000), ws(front(opened, "node.test", &[])), env(&root.roots), settled()).unwrap(), 5 * SECOND).await, if in_order {Ended::Closed(End::Unanswered)} else {cut}, "{how:?} behind the upgrade answer to a keepalive");
		assert!(started.elapsed() < 4 * SECOND, "{how:?}: {:?}", started.elapsed());
	}
}

// "A proof that was accepted and is followed by silence for 10 s, on a session the client opened with a keepalive, is neither."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_proof_that_is_taken_and_followed_by_silence_is_told_apart_by_what_the_session_opened_with() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (opened, _) = server(config.clone(), |_, _, mut io| async move {
		let Some((head, _)) = head(&mut io).await else {return};
		let _ = io.write_all(&upgraded(&head)).await;
		let _ = io.flush().await;
		sleep(Duration::from_secs(30)).await;
	}).await;
	let (quiet, _) = server(config, |_, _, mut io| async move {
		let _ = head(&mut io).await;
		sleep(Duration::from_secs(30)).await;
	}).await;
	let (started, polled) = (Instant::now(), Target::Fronted {path: PATH.into(), candidate: front(quiet, "node.test", &[])});
	let mut sessions = [(settled(), ws(front(opened, "node.test", &[])), Ended::Closed(End::Unanswered)), (settled(), polled.clone(), Ended::Closed(End::Unanswered)), (source(), ws(front(opened, "node.test", &[])), Ended::Unreachable(Unreachable::Timeout)), (source(), polled, Ended::Unreachable(Unreachable::Timeout)), (settled(), ws(front(quiet, "node.test", &[])), Ended::Unreachable(Unreachable::Timeout))].map(|(source, target, wanted)| (Session::open(&link(20_000), target, env(&root.roots), source).unwrap(), wanted));
	for (session, wanted) in &mut sessions {
		assert_eq!(end(session, 13 * SECOND).await, *wanted);
		assert!((9_800..=12_500).contains(&started.elapsed().as_millis()), "{:?}", started.elapsed());
	}
}

// "Or 10 s pass without a chunk after a handshake that WireGuard started because the node stopped answering": a connection that goes dark with no reset, under a caller that keeps sending.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_session_that_goes_dark_while_the_caller_sends_is_lost_ten_seconds_after_wireguard_says_so() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, _) = server(config, |_, _, io| async move {
		let mut fake = Fake::accept(io).await.unwrap();
		fake.chunk().await.unwrap();
		fake.put(&[]).await;
		// From here the node neither reads nor writes, and the connection stays as it is.
		sleep(Duration::from_secs(60)).await;
	}).await;
	let mut session = Session::open(&link(20_000), ws(front(addr, "node.test", &[])), env(&root.roots), source()).unwrap();
	established(&session).await;
	let (started, mut stalled, mut ended) = (Instant::now(), None, None);
	for second in 1..=25u64 {
		tokio::select! {
			got = session.recv() => {
				ended = got.err();
				break;
			}
			_ = sleep(SECOND) => {}
		}
		session.send(vec![4; 100], Kind::Packet {flow: 3, control: false});
		if second % 5 == 0 {
			session.send([&[1, 0, 0, 0][..], &[0; 144]].concat(), Kind::Stalled);
			stalled.get_or_insert(Instant::now());
		}
	}
	let waited = stalled.expect("the session ended before WireGuard said anything").elapsed();
	assert_eq!(ended, Some(Ended::Closed(End::Lost)), "after {:?}", started.elapsed());
	assert!((9_500..=11_500).contains(&waited.as_millis()), "{waited:?} after the first handshake of a stalled tunnel");
}

// A session that is closed or dropped while it opens: nothing more leaves the device for it, and the WireGuard layer is asked once, before anything is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn closing_or_dropping_a_session_that_is_opening_stops_it_at_once() {
	let (root, asked, requests) = (root(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	// A server that takes three seconds over its TLS handshake, and one that reads the request and says nothing.
	let (slow, acceptor) = (TcpListener::bind("127.0.0.1:0").await.unwrap(), TlsAcceptor::from(config.clone()));
	let stalled = slow.local_addr().unwrap();
	tokio::spawn({
		let requests = requests.clone();
		async move {
			loop {
				let Ok((stream, _)) = slow.accept().await else {return};
				let (acceptor, requests) = (acceptor.clone(), requests.clone());
				tokio::spawn(async move {
					sleep(3 * SECOND).await;
					let Ok(mut io) = acceptor.accept(stream).await else {return};
					if head(&mut io).await.is_some() {requests.fetch_add(1, Ordering::SeqCst);}
				});
			}
		}
	});
	let (quiet, _) = server(config, |_, _, mut io| async move {
		let _ = head(&mut io).await;
		sleep(Duration::from_secs(30)).await;
	}).await;
	let counted = || -> Source {
		let asked = asked.clone();
		Arc::new(Mutex::new(move |_: Want| {
			asked.fetch_add(1, Ordering::SeqCst);
			Some([&[1, 0, 0, 0][..], &[0xee; 144]].concat())
		}))
	};
	for target in [ws(front(stalled, "node.test", &[])), Target::Fronted {path: PATH.into(), candidate: front(stalled, "node.test", &[])}, ws(front(quiet, "node.test", &[])), Target::Fronted {path: PATH.into(), candidate: front(quiet, "node.test", &[])}] {
		// Closed, which is what the loser of two candidates in flight gets, and dropped.
		let (closed, dropped) = (Session::open(&link(20_000), target.clone(), env(&root.roots), counted()).unwrap(), Session::open(&link(20_000), target, env(&root.roots), counted()).unwrap());
		sleep(Duration::from_millis(150)).await;
		let started = Instant::now();
		drop(dropped);
		assert_eq!(closed.close().await, Ended::Closed(End::Asked));
		assert!(started.elapsed() < Duration::from_millis(500), "a close that took {:?}", started.elapsed());
	}
	sleep(4 * SECOND).await;
	// No request reached the server that was slow, and the WireGuard layer was asked once for each session, before its dial.
	assert_eq!((requests.load(Ordering::SeqCst), asked.load(Ordering::SeqCst)), (0, 8));
}

// "Once any connection was established, the end of the last one is a lost session", and "a parallel connection that is unreachable is not tried again for 1 hour. One that is refused waits the refusal wait."
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn several_connections_end_as_a_lost_session_whatever_the_last_one_said() {
	let root = root();
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	// The first connection is a session for seven seconds and is then cut. Every later one is refused.
	let (addr, met) = server(config, |at, _, mut io| async move {
		if at > 0 {
			let _ = head(&mut io).await;
			let _ = io.write_all(MISS).await;
			return drop(io.shutdown().await);
		}
		let mut fake = Fake::accept(io).await.unwrap();
		fake.chunk().await.unwrap();
		fake.put(&[]).await;
		sleep(7 * SECOND).await;
	}).await;
	let (started, mut session) = (Instant::now(), Session::parallel(&link(20_000), ws(front(addr, "node.test", &[])), 3, env(&root.roots), source()).unwrap());
	established(&session).await;
	// The whole carried the tunnel: its end is a session that was lost, and neither the refusal of its second connection nor anything else that would mark a candidate that worked.
	assert_eq!(end(&mut session, 12 * SECOND).await, Ended::Closed(End::Lost));
	// The second connection was opened once, 1 to 5 s after the first, and refused: its next try is a refusal wait away, a minute at the least.
	assert!((6_800..=8_500).contains(&started.elapsed().as_millis()) && met.load(Ordering::SeqCst) == 2, "{:?}, {} connections", started.elapsed(), met.load(Ordering::SeqCst));
	// With a first connection that is refused, the whole is refused.
	let (refusing, _) = answering(served(Some(&root.issuer), "node.test", false, &[&TLS13]).0, MISS, false).await;
	assert_eq!(end(&mut Session::parallel(&link(20_000), ws(front(refusing, "node.test", &[])), 3, env(&root.roots), source()).unwrap(), 5 * SECOND).await, REFUSED);
}

// What the library is given about the device and cannot check on the network: a socket hook, a device without a route, and a request that a hand-built target would spoil.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn the_devices_own_faults_are_no_verdict_on_a_candidate() {
	let (root, hooked) = (root(), Arc::new(AtomicUsize::new(0)));
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, met) = answering(config, MISS, false).await;
	// The hook has every socket before it is connected, for TCP and for UDP.
	let counting = Env {socket: Some(Arc::new({
		let hooked = hooked.clone();
		move |socket: SockRef<'_>| {
			assert!(socket.peer_addr().is_err(), "the hook got a socket that is connected already");
			hooked.fetch_add(1, Ordering::SeqCst);
			Ok(())
		}
	})), ..env(&root.roots)};
	assert_eq!(end(&mut Session::open(&link(20_000), ws(front(addr, "node.test", &[])), counting.clone(), source()).unwrap(), 5 * SECOND).await, REFUSED);
	let datagrams = Session::open(&link(20_000), Target::UdpObfs(addr), counting, source()).unwrap();
	sleep(Duration::from_millis(300)).await;
	assert_eq!((hooked.load(Ordering::SeqCst), met.load(Ordering::SeqCst), datagrams.state()), (2, 1, State::Opening));
	assert_eq!(datagrams.close().await, Ended::Closed(End::Asked));
	// A hook that fails ends the attempt before anything is dialled.
	let failing = Env {socket: Some(Arc::new(|_: SockRef<'_>| Err(std::io::ErrorKind::PermissionDenied.into()))), ..env(&root.roots)};
	for target in [ws(front(addr, "node.test", &[])), Target::Fronted {path: PATH.into(), candidate: front(addr, "node.test", &[])}, Target::UdpObfs(addr)] {assert_eq!(end(&mut Session::open(&link(20_000), target, failing.clone(), source()).unwrap(), 5 * SECOND).await, Ended::Closed(End::Offline))}
	assert_eq!(met.load(Ordering::SeqCst), 1);
	// A device with no route to the address, which is what a router that reboots leaves for a minute: where this host has no route for IPv6, an address of that family is one.
	let unrouted: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
	if std::net::UdpSocket::bind("[::]:0").and_then(|socket| socket.connect(unrouted)).is_err() {
		for target in [ws(front(unrouted, "node.test", &[])), Target::Fronted {path: PATH.into(), candidate: front(unrouted, "node.test", &[])}, Target::UdpObfs(unrouted)] {assert_eq!(end(&mut Session::open(&link(20_000), target, env(&root.roots), source()).unwrap(), 5 * SECOND).await, Ended::Closed(End::Offline))}
	}
	// A `host` or a `path` that would write another request than the one meant is refused before anything is dialled.
	let open = |target: Target| Session::open(&link(20_000), target, env(&root.roots), source()).map(|_| ()).unwrap_err();
	for host in ["node.test\r\nX-Other: 1", "node.test other", "node.test?", ""] {assert_eq!(open(ws(Front {host: host.into(), ..front(addr, "node.test", &[])})), Refuse::Request, "{host:?}")}
	for path in ["/assets/app.js?debug", "/assets/app.js HTTP/1.1\r\nHost: other", "/assets/ app.js", "assets/app.js", ""] {assert_eq!(open(Target::Fronted {path: path.into(), candidate: front(addr, "node.test", &[])}), Refuse::Request, "{path:?}")}
	assert_eq!(met.load(Ordering::SeqCst), 1);
}

// The certificate checks the first test leaves out: a chain with an authority in between, a certificate that is not valid yet, one for the `Host` and not for the server name, the second a certificate runs out in, and a certificate that signed itself with its pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_chain_is_followed_to_its_root_and_held_to_the_devices_clock() {
	let (root, both) = (root(), &[&TLS13, &TLS12][..]);
	// An authority the root signed, and a certificate that authority signed, sent with it.
	let (key, mut params) = (KeyPair::generate().unwrap(), CertificateParams::new(Vec::new()).unwrap());
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.distinguished_name.push(DnType::CommonName, "an authority of the tests");
	let between = CertificateDer::from(params.signed_by(&key, &root.issuer).unwrap().der().to_vec());
	let authority = Issuer::new(params, key);
	let (chained, chained_pin, _) = certified(Some(&authority), "node.test", None, &[between], both);
	// The same certificate without the authority's: the chain does not reach the root.
	let (broken, broken_pin, _) = certified(Some(&authority), "node.test", None, &[], both);
	let (early, early_pin, _) = certified(Some(&root.issuer), "node.test", Some((date_time_ymd(2090, 1, 1), date_time_ymd(2091, 1, 1))), &[], both);
	let (hosted, hosted_pin) = served(Some(&root.issuer), "node.test", false, both);
	let (alone, alone_pin, own) = certified(None, "node.test", None, &[], both);
	let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
	let (ending, ending_pin, _) = certified(Some(&root.issuer), "node.test", Some((now - time::Duration::days(1), now + time::Duration::seconds(4))), &[], both);
	let mut servers = Vec::new();
	for config in [chained, broken, early, hosted, alone, ending] {servers.push(answering(config, MISS, false).await.0)}
	// The second a certificate runs out in: accepted before it, refused after it, and told as the clock's matter.
	assert_eq!(tried(&root.roots, ws(front(servers[5], "node.test", &[ending_pin]))).await, DATED);
	assert_eq!(tried(&root.roots, ws(front(servers[0], "node.test", &[]))).await, REFUSED);
	assert_eq!(tried(&root.roots, Target::Tls {path: PATH.into(), candidate: front(servers[0], "node.test", &[chained_pin])}).await, DATED);
	// The pin is the leaf's: the authority's key is no pin of it.
	assert_eq!(tried(&root.roots, ws(front(servers[1], "node.test", &[]))).await, NO_CERTIFICATE);
	assert_eq!(tried(&root.roots, ws(front(servers[1], "node.test", &[broken_pin]))).await, NO_CERTIFICATE);
	for pins in [&[][..], &[early_pin]] {assert_eq!(tried(&root.roots, ws(front(servers[2], "node.test", pins))).await, WRONG_TIME)}
	// The certificate is held against the server name that was sent, and never against the `Host` of the request.
	for pins in [&[][..], &[hosted_pin]] {assert_eq!(tried(&root.roots, ws(Front {host: "node.test".into(), ..front(servers[3], "front.test", pins)})).await, NO_CERTIFICATE)}
	// "A self-signed certificate with a matching pin is refused. A private authority is used by giving the client its root."
	assert_eq!(tried(&root.roots, Target::Tls {path: PATH.into(), candidate: front(servers[4], "node.test", &[alone_pin])}).await, NO_CERTIFICATE);
	// What a root store holds is a trust anchor whatever it says of itself, so a caller that puts that very certificate there has made it one. No pin does that.
	let mut anchored = RootCertStore::empty();
	anchored.add(own).unwrap();
	assert_eq!(tried(&Arc::new(anchored), Target::Tls {path: PATH.into(), candidate: front(servers[4], "node.test", &[alone_pin])}).await, DATED);
	sleep(Duration::from_millis(5_200).saturating_sub(Duration::try_from(OffsetDateTime::now_utc() - now).unwrap_or_default())).await;
	assert_eq!(tried(&root.roots, ws(front(servers[5], "node.test", &[ending_pin]))).await, WRONG_TIME);
}

/// A node of `fronted` that goes on: it takes the proof of the opening request, opens every body and answers every request with one datagram, a repeat from the answer it stored. `odd` says what else it does behind the answer to a request, by its number: write this field into the head, write these bytes a moment after the answer, and close the connection. `asked` holds the number of every request with the connection it came on.
async fn polling(config: Arc<ServerConfig>, odd: fn(u32) -> (&'static str, &'static [u8], bool), asked: Arc<Mutex<Vec<(usize, u32)>>>) -> (SocketAddr, Arc<AtomicUsize>) {
	let node = Arc::new(Mutex::new(None::<(fronted::Opener, Sealer, u32, Vec<u8>)>));
	server(config, move |at, _, mut io| {
		let (node, asked) = (node.clone(), asked.clone());
		async move {
			loop {
				let Some((head, mut body)) = head(&mut io).await else {return};
				let (length, mut buf): (usize, _) = (head.split("\r\n").find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().parse().unwrap(), vec![0u8; 65536]);
				while body.len() < length {
					match io.read(&mut buf).await {
						Ok(count) if count > 0 => body.extend_from_slice(&buf[..count]),
						_ => return,
					}
				}
				let query = head.split(' ').nth(1).unwrap().split_once('?').unwrap().1.to_string();
				let number = fronted::later(query.as_bytes()).map_or(0, |(_, number)| number);
				asked.lock().unwrap().push((at, number));
				let answer = {
					let mut node = node.lock().unwrap();
					if number == 0 {
						let keys = keys(Name::Fronted, &query);
						*node = Some((fronted::Opener::new(keys.c2s), Sealer::new(keys.s2c, Padding::new(1023, 255, &mut random).unwrap()), u32::MAX, Vec::new()));
					}
					let (rx, tx, last, stored) = node.as_mut().expect("a later request before the opening one");
					if *last != number {
						let (mut scratch, mut answer) = (Vec::new(), Vec::new());
						rx.open(&body, &mut scratch).expect("the body of a request does not open").commit();
						fronted::append(tx, &[&[&[4, 0, 0, 0][..], &number.to_be_bytes(), &[0; 32]].concat()], false, &mut random, &mut answer).unwrap();
						(*last, *stored) = (number, answer);
					}
					stored.clone()
				};
				let (field, behind, close) = odd(number);
				if io.write_all(&[format!("HTTP/1.1 200 OK\r\n{field}Content-Length: {}\r\n\r\n", answer.len()).as_bytes(), &answer].concat()).await.is_err() || io.flush().await.is_err() {return}
				if !behind.is_empty() {
					sleep(Duration::from_millis(30)).await;
					let _ = io.write_all(behind).await;
					let _ = io.flush().await;
				}
				if close {return drop(io.shutdown().await)}
			}
		}
	}).await
}

// One request is in flight, so nothing stands between two answers: a connection the front wrote on unasked is given up before the next request, and so is one whose answer said it was the last.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_fronted_connection_is_kept_only_while_the_front_keeps_to_one_answer_for_one_request() {
	let (root, asked) = (root(), Arc::new(Mutex::new(Vec::new())));
	let (config, _) = served(Some(&root.issuer), "node.test", false, &[&TLS13]);
	let (addr, met) = polling(config, |number| match number {
		// The answer says its connection ends with it, and it does.
		2 => ("Connection: keep-alive, Close\r\n", b"", true),
		// A whole answer nobody asked for, a moment behind the one that was.
		4 => ("", b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\naaaaaaaaaaaaaaaaaa", false),
		// The connection ends with no word of it in the answer. The next request finds it ended and goes on a new one, or was written into it already and goes out again with the same bytes.
		6 => ("", b"", true),
		_ => ("", b"", false),
	}, asked.clone()).await;
	let mut session = Session::open(&link(20_000), Target::Fronted {path: PATH.into(), candidate: front(addr, "node.test", &[])}, env(&root.roots), source()).unwrap();
	// The datagram of every answer, in the order of the requests, with none left out and none twice.
	for number in 0..=9u32 {assert_eq!(timeout(5 * SECOND, session.recv()).await.expect("the session stalled").map(|datagram| datagram[4..8].to_vec()), Ok(number.to_be_bytes().to_vec()), "the answer to the request {number}")}
	assert_eq!(session.state(), State::Established);
	let (asked, connections) = (asked.lock().unwrap().clone(), met.load(Ordering::SeqCst));
	// After `Connection: close` and after the unasked bytes the next request went out once, on a new connection.
	let on = |number: u32| asked.iter().filter(|(_, asked)| *asked == number).map(|(at, _)| *at).collect::<Vec<_>>();
	assert_eq!((on(2), on(3), on(4), on(5), on(6), connections >= 4), (vec![0], vec![1], vec![1], vec![2], vec![2], true), "{asked:?}");
	assert!(on(7).len() <= 2 && on(7).last() == Some(&3), "{asked:?}");
	session.close().await;
}
