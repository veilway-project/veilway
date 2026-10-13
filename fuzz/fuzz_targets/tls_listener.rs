#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use veilway_core::engine::stream::{Bench, Pools};
use veilway_proto::chunk::{Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::proof::{self, Name};
use veilway_proto::websocket::{self, BINARY};
use veilway_proto::NoRandom;
use veilway_wg::Wg;

const NODE: [u8; 32] = [0x10; 32];
const KEYS: [[u8; 32]; 3] = [[0x21; 32], [0x22; 32], [0x23; 32]];
const TRANSPORT: [u8; 32] = [0x51; 32];
const PATH: &str = "/assets/app-3f9c2e71.js";
const POOLS: Pools = Pools {sessions: 4, undecided: 8, per_source: 4, relayed: 8};
// What the stub origin says to a connection, once it has read all of it or before it reads anything.
const MARKER: &[u8] = b"the origin's own answer";
const HEAD: &str = "Host: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
// An IPv4 header with nothing behind it, which a tunnel carries once a handshake is done.
const PACKET: [u8; 20] = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1];
// The node's clock in Unix seconds, which every input moves ahead.
static CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000);

fn now() -> OffsetDateTime {OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::Relaxed)).expect("a time of this century")}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for part in bytes.chunks_mut(32) {part.copy_from_slice(&veilway_wg::generate_key()[..part.len()])}
	Ok(())
}

// One node for the whole run: a runtime, a listener that reads plain HTTP from pipes in memory with a stub origin behind it, and the three devices of its config with their WireGuard. A fourth client has a secret the node does not have.
struct Harness {runtime: Runtime, bench: Bench, clients: Vec<proof::Client>, devices: Vec<Wg>, runs: u16}

thread_local! {
	static HARNESS: RefCell<Option<Harness>> = const {RefCell::new(None)};
}

impl Harness {
	fn new() -> Harness {
		let (text, public) = (|key: &[u8; 32]| veilway_wg::encode_key(key), veilway_wg::public_key(&NODE));
		let users: Vec<serde_json::Value> = KEYS.iter().enumerate().map(|(n, key)| serde_json::json!({"name": format!("user{n}"), "exits": "all", "devices": [{"name": "phone", "public_key": text(&veilway_wg::public_key(key)), "transport_secrets": [text(&[0xa0 + n as u8; 32])], "addresses": [format!("10.7.0.{}", 2 + n)]}]})).collect();
		let document = serde_json::json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [text(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [{"type": "tls", "listen": "127.0.0.1:443", "path": PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": "http://127.0.0.1:8080"}}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "main"},
			"users": users,
		});
		let devices = KEYS.iter().map(|key| {
			let mut device = Wg::new(*key);
			device.add_peer(public, None, None).expect("one peer");
			device
		}).collect();
		let clients = (0..4usize).map(|n| proof::Client::new(&proof::public_key(&TRANSPORT), &if n < 3 {[0xa0 + n as u8; 32]} else {[0xee; 32]}, &public, &veilway_wg::public_key(&KEYS[n.min(2)]))).collect();
		Harness {runtime: tokio::runtime::Builder::new_current_thread().enable_time().build().expect("a runtime"), bench: Bench::new(&document.to_string(), POOLS, now).expect("a node"), clients, devices, runs: 0}
	}
}

// The unauthenticated path of a stream listener as a whole (`engine::stream`): one connection of a direct peer for each input, over a pipe in memory, against a node with three devices, the replay rule, the limits and a stub origin. The first three bytes of an input are settings and the rest is payload:
//   0  the two low bits are the kind of stream. 0: the payload as it is, from a stranger. 1: the request line of a real, fresh proof of a device, and the payload as whatever follows it. 2: such a request with the upgrade head a client sends, and one thing about it that makes it no proof,
//      which bits 2 to 4 pick: a changed character of the token, another path, another method, a proof made for another transport, a timestamp outside the window on either side, a method in lower case, another HTTP version. Then the payload.
//      3: a good request with its head, then, with bit 2, one chunk with a real handshake initiation of the device, and then the payload as the bytes of the WebSocket session.
//      Bits 5 and 6 are what the stub origin does. 1: it speaks first, with its answer at once, and then reads the connection to its end. 2: it closes at once. Anything else: it reads the connection to its end, answers once, and closes.
//   1  the two low bits are the device, where 3 is a secret the node does not have and makes every kind a stranger's
//   2  the size of the pieces the stream is written in, 0 for one piece
// What must hold whatever the input is: a stream that is no accepted proof reaches the origin whole and unchanged, and the peer gets the origin's answer and not one byte besides. A stream that begins with a real proof of a device of the config is accepted: nothing of it reaches the origin,
// and what the peer gets is the upgrade answer, or nothing when the head behind the proof is no upgrade. When the connection is over, the node holds nothing of it: no undecided connection, no relayed one, no pending session and no session.
// An origin that speaks or closes first may decide a connection before its request line is complete, so a real proof may end as a stranger's stream there, and never the other way round. A stranger of an origin that closed at once gets nothing, as that origin gives nothing.
// What stays out: two connections at once. The harness serves one connection to its end before the next, so displacement, a full pool, the proofs that wait for a limit and the rate limits are not reached here, and the suite's tests have them.
fuzz_target!(|data: &[u8]| {
	let Some((&[kind, pick, size], payload)) = data.split_first_chunk::<3>() else {return};
	HARNESS.with_borrow_mut(|harness| {
		let Harness {runtime, bench, clients, devices, runs} = harness.get_or_insert_with(Harness::new);
		let (clock, device, known, public) = (CLOCK.fetch_add(3, Ordering::Relaxed) as u64 + 3, usize::from(pick & 3).min(2), pick & 3 != 3, veilway_wg::public_key(&NODE));
		*runs = runs.wrapping_add(1);
		let (flaw, client, origin_does) = (kind >> 2 & 7, &clients[usize::from(pick & 3)], kind >> 5 & 3);
		let prove = |name: Name, at: u64| client.prove(name, at, &mut random).expect("a client proves");
		let line = |method: &str, path: &str, token: &str, version: &str| format!("{method} {path}?{token} HTTP/{version}\r\n").into_bytes();
		let (stream, accepted): (Vec<u8>, bool) = match kind & 3 {
			0 => (payload.to_vec(), false),
			1 => ([&line("GET", PATH, &prove(Name::Tls, clock).token, "1.1")[..], payload].concat(), known),
			2 => {
				let token = prove(if flaw == 3 {Name::Ws} else {Name::Tls}, match flaw {
					4 => clock - 200,
					5 => clock + 200,
					_ => clock,
				}).token;
				let at = usize::from(payload.first().copied().unwrap_or(0)) % token.len();
				let changed = if flaw == 0 {format!("{}{}{}", &token[..at], if token.as_bytes()[at] == b'A' {'B'} else {'A'}, &token[at + 1..])} else {token};
				([&line(if flaw == 2 {"POST"} else if flaw == 6 {"get"} else {"GET"}, if flaw == 1 {"/assets/app-00000000.js"} else {PATH}, &changed, if flaw == 7 {"1.0"} else {"1.1"})[..], HEAD.as_bytes(), payload].concat(), false)
			}
			_ => {
				let (proof, mut frames) = (prove(Name::Tls, clock), Vec::new());
				if kind & 4 != 0 {
					let (mut net, mut sealed) = (Vec::new(), Vec::new());
					devices[device].drop_sessions(&public);
					devices[device].encapsulate(0, &PACKET, &mut net);
					let items: Vec<&[u8]> = net.iter().map(Vec::as_slice).collect();
					Sealer::new(proof.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).expect("the default bounds")).seal(&items, true, &mut random, &mut sealed).expect("a session seals");
					websocket::frame(BINARY, &sealed, Some([pick, size, kind, 7]), &mut frames);
				}
				([&line("GET", PATH, &proof.token, "1.1")[..], HEAD.as_bytes(), &frames, payload].concat(), known)
			}
		};
		let (origin_got, peer_got, totals) = runtime.block_on(async {
			bench.tick();
			let (peer, task) = bench.connect(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1 + (*runs % 200) as u8), 4000)));
			// The node opens its connection to the origin before it reads anything, so the pipe is there once the connection's task has run.
			let mut origin = None;
			for _ in 0..1000 {
				origin = bench.origin();
				if origin.is_some() {break}
				tokio::task::yield_now().await;
			}
			let (mut origin, (mut from_node, mut to_node)) = (origin.expect("the node opened no connection to the origin"), tokio::io::split(peer));
			let writing = async {
				for piece in stream.chunks(if size == 0 {stream.len().max(1)} else {usize::from(size)}) {
					if to_node.write_all(piece).await.is_err() {break}
					tokio::task::yield_now().await;
				}
				let _ = to_node.shutdown().await;
			};
			// The stub origin, which closes when it is done.
			let serving = async {
				let mut got = Vec::new();
				match origin_does {
					1 => {
						let _ = origin.write_all(MARKER).await;
						let _ = origin.read_to_end(&mut got).await;
					}
					2 => {}
					_ => {
						let _ = origin.read_to_end(&mut got).await;
						let _ = origin.write_all(MARKER).await;
					}
				}
				drop(origin);
				got
			};
			let reading = async {
				let mut got = Vec::new();
				let _ = from_node.read_to_end(&mut got).await;
				got
			};
			let (_, origin_got, peer_got) = tokio::time::timeout(Duration::from_secs(20), async {tokio::join!(writing, serving, reading)}).await.expect("a connection that was closed from both ends did not end");
			tokio::time::timeout(Duration::from_secs(20), task).await.expect("the task of a connection outlived the connection").expect("the task of a connection panicked");
			(origin_got, peer_got, bench.totals())
		});
		let upgraded = peer_got.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n");
		let (user, stranger) = (origin_got.is_empty() && (upgraded || kind & 3 != 3 && peer_got.is_empty()), if origin_does == 2 {origin_got.is_empty() && peer_got.is_empty()} else {origin_got == stream && peer_got == MARKER});
		assert!(if accepted {user || matches!(origin_does, 1 | 2) && stranger} else {stranger}, "{}: the origin got {} bytes of the {} that were sent, and the peer got {} bytes{}", if accepted {"a user"} else {"a stranger"}, origin_got.len(), stream.len(), peer_got.len(), if upgraded {", an upgrade answer"} else {""});
		assert_eq!((totals.undecided, totals.relayed, totals.pending, totals.sessions), (0, 0, 0, 0), "the node kept something of a connection that is over");
	});
});
