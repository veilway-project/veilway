#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;
use veilway_core::engine::stream::{Bench, Pools};
use veilway_proto::chunk::{Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::proof::{self, Name};
use veilway_proto::{fronted, NoRandom};
use veilway_wg::Wg;

const NODE: [u8; 32] = [0x10; 32];
const KEY: [u8; 32] = [0x21; 32];
const TRANSPORT: [u8; 32] = [0x51; 32];
const WS: &str = "/assets/live-7c1d0a52.js";
const PATH: &str = "/assets/sync-90be44f1.js";
const POOLS: Pools = Pools {sessions: 8, undecided: 8, per_source: 4, relayed: 8};
// What the stub origin answers every request it is handed.
const MISS: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found";
// An IPv4 header with nothing behind it, which a tunnel carries once a handshake is done.
const PACKET: [u8; 20] = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1];
// The node's clock in Unix seconds, which every input moves ahead by more than the idle time of a `fronted` session, so the session of the input before is gone.
static CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000);

fn now() -> OffsetDateTime {OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::Relaxed)).expect("a time of this century")}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for part in bytes.chunks_mut(32) {part.copy_from_slice(&veilway_wg::generate_key()[..part.len()])}
	Ok(())
}

// One node for the whole run: a runtime whose clock is paused and jumps to the next timer when nothing else can run, a listener of the proxy path that reads plain HTTP from pipes in memory with a stub origin behind it, and the one device of its config with its WireGuard.
struct Harness {runtime: Runtime, bench: Bench, client: proof::Client, device: Wg}

thread_local! {
	static HARNESS: RefCell<Option<Harness>> = const {RefCell::new(None)};
}

impl Harness {
	fn new() -> Harness {
		let (text, public) = (|key: &[u8; 32]| veilway_wg::encode_key(key), veilway_wg::public_key(&NODE));
		let behind = |kind: &str, path: &str| serde_json::json!({"type": kind, "listen": "127.0.0.1:443", "path": path, "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "client_address_header": "X-Forwarded-For"});
		let document = serde_json::json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [text(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [behind("ws", WS), behind("fronted", PATH)]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "main"},
			"users": [{"name": "user", "exits": "all", "devices": [{"name": "phone", "public_key": text(&veilway_wg::public_key(&KEY)), "transport_secrets": [text(&[0xa0; 32])], "addresses": ["10.7.0.2"]}]}],
		});
		let mut device = Wg::new(KEY);
		device.add_peer(public, None, None).expect("one peer");
		Harness {runtime: tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().expect("a runtime"), bench: Bench::new(&document.to_string(), POOLS, now).expect("a node"), client: proof::Client::new(&proof::public_key(&TRANSPORT), &[0xa0; 32], &public, &veilway_wg::public_key(&KEY)), device}
	}
}

// A `fronted` request as the reverse proxy hands it to the node, with the visitor it names.
fn request(method: &str, target: &str, body: &[u8]) -> Vec<u8> {[format!("{method} {target} HTTP/1.1\r\nHost: node.test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Forwarded-For: 198.51.100.7\r\n\r\n", body.len()).as_bytes(), body].concat()}

// Sends one request on the proxy's connection and reads one answer whose head names its length: the whole answer as it came, and where its body begins.
async fn ask(proxy: &mut DuplexStream, request: &[u8]) -> (Vec<u8>, usize) {
	proxy.write_all(request).await.expect("the node closed its proxy's connection");
	let (mut got, mut buf) = (Vec::new(), [0u8; 4096]);
	loop {
		if let Some(end) = got.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {
			let length = String::from_utf8_lossy(&got[..end]).split("\r\n").find_map(|line| line.strip_prefix("Content-Length: ").and_then(|length| length.parse::<usize>().ok())).expect("an answer without a length");
			if got.len() >= end + length {
				assert_eq!(got.len(), end + length, "bytes behind an answer");
				return (got, end);
			}
		}
		match proxy.read(&mut buf).await.expect("the proxy's connection broke") {
			0 => panic!("the node closed its proxy's connection in the middle of an answer"),
			read => got.extend_from_slice(&buf[..read]),
		}
	}
}

// A request that must be the origin's: it is sent, the stub origin must receive it byte for byte, on the connection the node kept there or on a new one, and what the stub answers must come back and nothing else.
async fn missed(bench: &mut Bench, proxy: &mut DuplexStream, origin: &mut Option<DuplexStream>, request: &[u8]) {
	proxy.write_all(request).await.expect("the node closed its proxy's connection");
	tokio::time::sleep(Duration::from_millis(1)).await;
	if let Some(fresh) = bench.origin() {*origin = Some(fresh)}
	let (stub, mut handed, mut answer) = (origin.as_mut().expect("the node opened no connection to the origin for a request that is no user's"), vec![0u8; request.len()], vec![0u8; MISS.len()]);
	stub.read_exact(&mut handed).await.expect("the origin did not get the whole request");
	assert!(handed == request, "the origin got other bytes than the proxy sent");
	stub.write_all(MISS).await.expect("the node closed the origin's connection before the answer");
	proxy.read_exact(&mut answer).await.expect("the origin's answer did not come back");
	assert!(answer == MISS, "the proxy got other bytes than the origin answered");
}

// A `fronted` session under a sequence of requests (`engine::stream`, the proxy path): each input opens one session with a real proof and a real WireGuard handshake, through a connection of the trusted proxy, and then sends what the input says, two bytes for each request: what kind it is, and one number that shapes it.
//   0, 1  the client's next request, with a padding-only chunk, a WireGuard keepalive of the device, or a datagram that is no WireGuard packet
//   2     the last accepted request again, byte for byte
//   3     the last accepted number with another body
//   4     a number that is neither the last one nor the next one
//   5     the next number with a body nobody sealed
//   6     the next number with the body of the last accepted request, whose chunks were sealed for numbers that are used
//   7     the next request with something wrong in its head: another method, the path of the other transport, a session id that is one character too long, a number with a leading zero
// What must hold whatever the sequence is: every request of the first two kinds is accepted, in order, with an answer the client can open at the numbers that follow its last, however many requests of the other kinds stand between them. A repeat gets the stored answer, byte for byte. Every other request reaches the origin whole and unchanged, and its answer is the origin's.
// So nothing a request without a valid chunk does changes the session: if it did, the client's next request would not open, or the node's next answer would not. At the end the node has counted exactly the accepted requests and the repeats, and holds one session.
// What stays out: two requests at once, which the suite's tests have (`tests/fronted.rs`), and a chunk that opens and is invalid, which no key of a real proof can be made to seal from outside the crate.
fuzz_target!(|data: &[u8]| {
	HARNESS.with_borrow_mut(|harness| {
		let Harness {runtime, bench, client, device} = harness.get_or_insert_with(Harness::new);
		let (clock, public, from) = (CLOCK.fetch_add(70, Ordering::Relaxed) as u64 + 70, veilway_wg::public_key(&NODE), SocketAddr::from((Ipv4Addr::LOCALHOST, 4000)));
		runtime.block_on(async {
			bench.tick();
			let ((mut proxy, task), before, made) = (bench.proxy(from).expect("a place in the proxy pool"), bench.totals(), client.prove(Name::Fronted, clock, &mut random).expect("a client proves"));
			let (mut tx, mut rx, sid, mut origin, mut net, mut ip, mut scratch) = (Sealer::new(made.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).expect("the default bounds")), fronted::Opener::new(made.keys.s2c), made.keys.sid, None, Vec::new(), Vec::new(), Vec::new());
			// The opening request, with a fresh handshake initiation of the device. Its answer is the handshake response. The device's WireGuard is made anew for it: one that is kept counts every handshake message it was ever sent towards its load limit, since nothing here runs its timers.
			*device = Wg::new(KEY);
			device.add_peer(public, None, None).expect("one peer");
			device.encapsulate(0, &PACKET, &mut net);
			let mut body = Vec::new();
			fronted::append(&mut tx, &net.iter().map(Vec::as_slice).collect::<Vec<_>>(), true, &mut random, &mut body).expect("a body of one chunk");
			let (answer, at) = ask(&mut proxy, &request("POST", &format!("{PATH}?{}", made.token), &body)).await;
			assert!(answer.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "), "the opening request of a device was not answered by the node");
			let first: Vec<Vec<u8>> = rx.open(&answer[at..], &mut scratch).expect("the first answer does not open").commit().into_iter().flatten().map(<[u8]>::to_vec).collect();
			net.clear();
			assert!(first.len() == 1 && device.recv_authenticated(from, &first[0], &mut net, &mut ip).is_some_and(|(_, proven)| proven), "the first answer held no handshake response");
			let (mut number, mut last, mut accepted, mut repeats, target) = (0u32, None::<(Vec<u8>, Vec<u8>, Vec<u8>)>, 1u64, 0u64, |number: u32| format!("{PATH}?{}", fronted::later_query(&sid, number).expect("a number above 0")));
			// The steps of the input, and one request of the client behind them all.
			for step in data.chunks(2).take(24).map(|step| (step[0] % 8, step.get(1).copied().unwrap_or(0))).chain([(0, 0)]) {
				match step {
					(0 | 1, shape) => {
						let datagram = match shape % 3 {
							0 => None,
							1 => {
								net.clear();
								device.encapsulate(0, &[], &mut net);
								net.first().cloned()
							}
							_ => Some(vec![shape; 40]),
						};
						let (mut body, mut scratch) = (Vec::new(), Vec::new());
						fronted::append(&mut tx, &datagram.iter().map(Vec::as_slice).collect::<Vec<_>>(), false, &mut random, &mut body).expect("a body of one chunk");
						let asked = request("POST", &target(number + 1), &body);
						let (answer, at) = ask(&mut proxy, &asked).await;
						assert!(answer.starts_with(b"HTTP/1.1 200 OK\r\n") && rx.open(&answer[at..], &mut scratch).is_ok_and(|opened| !opened.commit().is_empty()), "request {} of the session's client was not accepted, or its answer does not open", number + 1);
						(number, accepted, last) = (number + 1, accepted + 1, Some((asked, body, answer)));
					}
					(2, _) => if let Some((asked, _, stored)) = &last {
						assert!(ask(&mut proxy, asked).await.0 == *stored, "a repeat was not answered with the stored answer");
						repeats += 1;
					},
					(3, shape) => if number > 0 {missed(bench, &mut proxy, &mut origin, &request("POST", &target(number), &vec![shape; 18 + usize::from(shape)])).await},
					(4, shape) => missed(bench, &mut proxy, &mut origin, &request("POST", &target(if shape & 1 == 0 || number < 2 {number + 2 + u32::from(shape)} else {number - 1}), &vec![shape; 18 + usize::from(shape)])).await,
					(5, shape) => missed(bench, &mut proxy, &mut origin, &request("POST", &target(number + 1), &vec![shape; 18 + usize::from(shape)])).await,
					(6, _) => if let Some((_, body, _)) = &last {missed(bench, &mut proxy, &mut origin, &request("POST", &target(number + 1), body)).await},
					(_, shape) => {
						let (next, body) = (target(number + 1), vec![shape; 18 + usize::from(shape)]);
						let (start, digits) = next.rsplit_once('.').expect("a number behind the session id");
						let wrong = match shape % 4 {
							0 => request("GET", &next, &body),
							1 => request("POST", &next.replace(PATH, WS), &body),
							2 => request("POST", &next.replacen('?', "?A", 1), &body),
							_ => request("POST", &format!("{start}.0{digits}"), &body),
						};
						missed(bench, &mut proxy, &mut origin, &wrong).await;
					}
				}
			}
			let after = bench.totals();
			assert_eq!((after.polls - before.polls, after.poll_repeats - before.poll_repeats, after.sessions, after.fronted, after.pending, after.decoys, after.ended_invalid - before.ended_invalid), (accepted, repeats, 1, 1, 0, 0, 0), "the node counted other requests than the client's, or the session is not what it was");
			drop((proxy, origin));
			tokio::time::timeout(Duration::from_secs(600), task).await.expect("the task of a connection outlived the connection").expect("the task of a connection panicked");
		});
	});
});
