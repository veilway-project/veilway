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
use veilway_proto::request::HEAD_MAX;
use veilway_proto::{fronted, NoRandom};
use veilway_wg::Wg;

const NODE: [u8; 32] = [0x10; 32];
const KEY: [u8; 32] = [0x21; 32];
const TRANSPORT: [u8; 32] = [0x51; 32];
const WS: &str = "/assets/live-7c1d0a52.js";
const POLLED: &str = "/assets/sync-90be44f1.js";
const POOLS: Pools = Pools {sessions: 8, undecided: 8, per_source: 4, relayed: 8};
// What the stub origin answers a request it could read, and one it could not.
const TAKEN: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const REFUSED: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const UPGRADE: &str = "Host: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
// An IPv4 header with nothing behind it, which a tunnel carries once a handshake is done.
const PACKET: [u8; 20] = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1];
// The node's clock in Unix seconds, which every input moves ahead by more than the idle time of a `fronted` session.
static CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000);

fn now() -> OffsetDateTime {OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::Relaxed)).expect("a time of this century")}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for part in bytes.chunks_mut(32) {part.copy_from_slice(&veilway_wg::generate_key()[..part.len()])}
	Ok(())
}

// One node for the whole run: a runtime whose clock is paused and jumps to the next timer when nothing else can run, a listener of the proxy path that reads plain HTTP from pipes in memory, and the one device of its config with its WireGuard.
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
			"inbounds": [{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [text(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [behind("ws", WS), behind("fronted", POLLED)]}],
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

// What the first bytes of a connection are to a web server that reads HTTP/1.1 and takes nothing two readers could take two ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read {
	// No whole request yet.
	Incomplete,
	// Not a request such a server answers with anything but an error.
	Invalid,
	// One whole request of this many bytes, whose head has that many.
	Request(usize, usize),
}

// The lines of `bytes` up to its first empty line, and where the bytes behind that line begin. None while there is no empty line.
fn lines(bytes: &[u8]) -> Option<(Vec<&[u8]>, usize)> {
	let end = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
	let (mut lines, mut rest) = (Vec::new(), &bytes[..end - 2]);
	while let Some(at) = rest.windows(2).position(|window| window == b"\r\n") {
		lines.push(&rest[..at]);
		rest = &rest[at + 2..];
	}
	Some((lines, end))
}

// Where the first request of `bytes` ends: a second writing of the rule the node reads its proxy's requests by (`veilway_proto::http`), by another hand and in another shape, which the node is held against.
// A request line of a method, a target and `HTTP/1.1` with one blank between them. Field lines of a name that is a token, a colon and a value, each ended by CR LF and with no other CR, LF or NUL. At most one length, in digits and no more than 2^63 - 1, or the one coding `chunked`, and never both, nor either under a name that has `_` for `-`.
// Chunks of a size in hexadecimal digits alone, and a trailer of such lines. `CONNECT` is not answered as a request.
fn reference(bytes: &[u8]) -> Read {
	let Some((lines, end)) = lines(bytes) else {return Read::Incomplete};
	let (token, clean) = (|name: &[u8]| !name.is_empty() && name.iter().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)), |line: &[u8]| !line.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)));
	let line: Vec<&[u8]> = lines[0].split(|byte| *byte == b' ').collect();
	if line.len() != 3 || !token(line[0]) || line[0] == b"CONNECT" || line[1].is_empty() || !line[1].iter().all(|byte| (0x21..=0x7e).contains(byte)) || line[2] != b"HTTP/1.1" {return Read::Invalid}
	let (mut length, mut chunked) = (None, false);
	for field in &lines[1..] {
		let Some(colon) = field.iter().position(|byte| *byte == b':') else {return Read::Invalid};
		let (name, value) = (&field[..colon], String::from_utf8_lossy(&field[colon + 1..]).trim_matches([' ', '\t']).to_string());
		if !token(name) || !clean(field) {return Read::Invalid}
		match name.to_ascii_lowercase().iter().map(|byte| if *byte == b'_' {b'-'} else {*byte}).collect::<Vec<u8>>().as_slice() {
			b"content-length" if name.contains(&b'_') || length.is_some() || value.is_empty() || value.len() > 19 || !value.bytes().all(|byte| byte.is_ascii_digit()) || value.parse::<i64>().is_err() => return Read::Invalid,
			b"content-length" => length = value.parse::<usize>().ok(),
			b"transfer-encoding" if name.contains(&b'_') || chunked || !value.eq_ignore_ascii_case("chunked") => return Read::Invalid,
			b"transfer-encoding" => chunked = true,
			_ => {}
		}
	}
	match (length, chunked) {
		(Some(_), true) => Read::Invalid,
		(None, false) => Read::Request(end, end),
		(Some(length), false) => if bytes.len() - end >= length {Read::Request(end + length, end)} else {Read::Incomplete},
		(None, true) => {
			let mut at = end;
			loop {
				let Some(stop) = bytes[at..].windows(2).position(|window| window == b"\r\n") else {return if bytes[at..].iter().all(|byte| byte.is_ascii_hexdigit() || *byte == b'\r') && bytes.len() - at <= 17 {Read::Incomplete} else {Read::Invalid}};
				let digits = &bytes[at..at + stop];
				if digits.is_empty() || digits.len() > 16 || !digits.iter().all(u8::is_ascii_hexdigit) {return Read::Invalid}
				let (size, data) = (usize::from_str_radix(&String::from_utf8_lossy(digits), 16).unwrap_or(usize::MAX), at + stop + 2);
				if size == 0 {
					// The trailer: lines to the empty one.
					let mut at = data;
					loop {
						let Some(stop) = bytes[at..].windows(2).position(|window| window == b"\r\n") else {return if clean(&bytes[at..bytes.len() - usize::from(bytes.ends_with(b"\r"))]) && !matches!(bytes.get(at), Some(b' ' | b'\t')) {Read::Incomplete} else {Read::Invalid}};
						if stop == 0 {return Read::Request(at + 2, end)}
						if !clean(&bytes[at..at + stop]) || matches!(bytes[at], b' ' | b'\t') {return Read::Invalid}
						at += stop + 2;
					}
				}
				let Some(behind) = data.checked_add(size) else {return Read::Invalid};
				if bytes.len() < behind.saturating_add(2) {return if bytes.len() <= behind || bytes[behind] == b'\r' {Read::Incomplete} else {Read::Invalid}}
				if &bytes[behind..behind + 2] != b"\r\n" {return Read::Invalid}
				at = behind + 2;
			}
		}
	}
}

// What the stub origin answers the request that `bytes` begin with: a short page with its length, and for a `HEAD` the head of that alone, as a web server does.
fn taken(bytes: &[u8]) -> &'static [u8] {if bytes.starts_with(b"HEAD ") {&TAKEN[..TAKEN.len() - 2]} else {TAKEN}}

// The requests of strangers as the reverse proxy hands them on, when `bytes` are whole requests and nothing else, each with a head the node reads whole: how many bytes the stub origin answers them with in all. None for anything else.
fn whole(mut bytes: &[u8]) -> Option<usize> {
	let mut answers = 0;
	while !bytes.is_empty() {
		let Read::Request(size, head) = reference(bytes) else {return None};
		if head > HEAD_MAX {return None}
		(answers, bytes) = (answers + taken(bytes).len(), &bytes[size..]);
	}
	Some(answers)
}

// The proxy path of a stream listener as a whole (`engine::stream`): one connection of a trusted proxy for each input, over a pipe in memory, against a node with a `ws` and a `fronted` transport and a stub origin that answers every request it can read and keeps the connection, as a web server does. The first two bytes of an input are settings and the rest is payload:
//   0  the two low bits are what the connection carries. 0, 3: the payload as it is, which is requests of strangers or anything else. 1: the payload, and behind it the WebSocket open of a real, fresh proof of the device. 2: the payload, and behind it the opening request of a `fronted` session, with a real proof and a real handshake initiation.
//   1  the size of the pieces the stream is written in, 0 for one piece
// The stub origin reads requests by a rule of its own (`reference`), written apart from the node's. It answers a request the moment it has all of it, and from the first thing that is no request it answers once with an error and then only reads. What must hold whatever the input is:
//   - What the origin receives is the bytes the proxy sent, from the first one on and in their order, with nothing added, left out or changed: "the head byte for byte, the body by its framing". What the proxy gets back is what the origin wrote, from its first byte on, and not one byte besides.
//   - While everything so far was a whole request, the origin never holds a byte beyond the request it is about to answer: the node hands it one request, waits for the answer, and hands it the next. A node that took a request to end somewhere else than the origin does would hand on too much, or wait for ever with the rest in its hands, and both are caught here.
//   - When the payload is whole requests and nothing else, the origin gets all of them, the proxy gets an answer for each, and a user behind them is a user: nothing of the proof reaches the origin, and the proxy gets the node's answer to it behind the origin's answers.
//   - Nothing waits for ever, and when the connection is over the node holds nothing of it: no proxy connection, no request waiting for the origin, and at most the one session a user opened.
// What stays out: two connections at once, so the pool of proxy connections and the shares of sources are not reached here and the suite's tests have them, an origin that closes, resets or answers in pieces, which the differential tests have, and a head that takes more than its ten seconds.
fuzz_target!(|data: &[u8]| {
	let Some((&[kind, size], payload)) = data.split_first_chunk::<2>() else {return};
	HARNESS.with_borrow_mut(|harness| {
		let Harness {runtime, bench, client, device} = harness.get_or_insert_with(Harness::new);
		let (clock, public) = (CLOCK.fetch_add(70, Ordering::Relaxed) as u64 + 70, veilway_wg::public_key(&NODE));
		// The user's request behind the payload, when the input has one, and how the node's answer to it begins.
		let (user, answered): (Vec<u8>, &[u8]) = match kind & 3 {
			1 => (format!("GET {WS}?{} HTTP/1.1\r\n{UPGRADE}", client.prove(Name::Ws, clock, &mut random).expect("a client proves").token).into_bytes(), b"HTTP/1.1 101 Switching Protocols\r\n"),
			2 => {
				let (made, mut net, mut body) = (client.prove(Name::Fronted, clock, &mut random).expect("a client proves"), Vec::new(), Vec::new());
				device.drop_sessions(&public);
				device.encapsulate(0, &PACKET, &mut net);
				fronted::append(&mut Sealer::new(made.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).expect("the default bounds")), &net.iter().map(Vec::as_slice).collect::<Vec<_>>(), true, &mut random, &mut body).expect("a body of one chunk");
				([format!("POST {POLLED}?{} HTTP/1.1\r\nHost: node.test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", made.token, body.len()).as_bytes(), &body].concat(), b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: ")
			}
			_ => (Vec::new(), b""),
		};
		let (stream, requests) = ([payload, &user].concat(), whole(payload));
		let (received, wrote, early, peer_got, before, after) = runtime.block_on(async {
			bench.tick();
			let (before, (peer, task)) = (bench.totals(), bench.proxy(SocketAddr::from((Ipv4Addr::LOCALHOST, 4000))).expect("a place in the proxy pool"));
			let (mut from_node, mut to_node) = tokio::io::split(peer);
			let writing = async {
				for piece in stream.chunks(if size == 0 {stream.len().max(1)} else {usize::from(size)}) {
					if to_node.write_all(piece).await.is_err() {break}
					tokio::task::yield_now().await;
				}
				// A user's connection is the session's from its answer on, and stays until the answer was read. A stranger's is closed behind what it sent.
				if user.is_empty() || requests.is_none() {let _ = to_node.shutdown().await;}
				to_node
			};
			// The stub origin. The node opens its connection there for the first request that is no user's, which may be never.
			let serving = async {
				let mut waited = 0u32;
				let mut origin = loop {
					if let Some(origin) = bench.origin() {break origin}
					if task.is_finished() || waited > 4096 || requests == Some(0) {return (Vec::new(), Vec::new(), false)}
					waited += 1;
					if waited % 64 == 0 {tokio::time::sleep(Duration::from_secs(1)).await} else {tokio::task::yield_now().await}
				};
				let (mut held, mut received, mut wrote, mut strict, mut early, mut sink, mut read) = (Vec::new(), Vec::new(), Vec::new(), true, false, false, [0u8; 4096]);
				loop {
					while !sink {
						match reference(&held) {
							Read::Request(size, head) => {
								strict &= head <= HEAD_MAX;
								early |= strict && held.len() > size;
								let answer = taken(&held);
								if origin.write_all(answer).await.is_err() {break}
								wrote.extend_from_slice(answer);
								held.drain(..size);
							}
							Read::Invalid => {
								(sink, strict) = (true, false);
								if origin.write_all(REFUSED).await.is_ok() {wrote.extend_from_slice(REFUSED)}
							}
							Read::Incomplete => {
								strict &= held.len() < HEAD_MAX || lines(&held[..HEAD_MAX]).is_some();
								break;
							}
						}
					}
					match origin.read(&mut read).await {
						Ok(count) if count > 0 => {
							received.extend_from_slice(&read[..count]);
							if !sink {held.extend_from_slice(&read[..count])}
						}
						_ => break,
					}
				}
				// What never became a whole request is answered when the node says there is no more.
				if !sink && !held.is_empty() && origin.write_all(REFUSED).await.is_ok() {wrote.extend_from_slice(REFUSED)}
				drop(origin);
				(received, wrote, early)
			};
			let reading = async {
				let (mut got, mut buf, wanted) = (Vec::new(), [0u8; 4096], requests.filter(|_| !user.is_empty()).map(|answers| answers + answered.len()));
				// With a user behind whole requests, the answer is read as far as its beginning says what it is, and then the connection is closed, as a client that is done closes it.
				while wanted.is_none_or(|wanted| got.len() < wanted) {
					match from_node.read(&mut buf).await {
						Ok(count) if count > 0 => got.extend_from_slice(&buf[..count]),
						_ => break,
					}
				}
				got
			};
			let (to_node, (received, wrote, early), peer_got) = tokio::time::timeout(Duration::from_secs(7200), async {tokio::join!(writing, serving, reading)}).await.expect("a connection whose proxy had sent everything did not end");
			drop((to_node, from_node));
			tokio::time::timeout(Duration::from_secs(7200), task).await.expect("the task of a connection outlived the connection").expect("the task of a connection panicked");
			(received, wrote, early, peer_got, before, bench.totals())
		});
		assert!(stream.starts_with(&received), "the origin got {} bytes that are not the first {} the proxy sent", received.len(), received.len());
		assert!(!early, "the origin held bytes beyond the request it was about to answer, while every request so far was whole");
		match requests {
			// Whole requests of strangers, and a user behind them when the input has one: the origin gets the strangers' requests and nothing of the user's, and the proxy gets the origin's answers and then the node's own.
			Some(answers) => {
				assert!(received == payload && wrote.len() == answers, "the origin got {} bytes of the {} that strangers sent, and answered with {} bytes where every request has {} in all", received.len(), payload.len(), wrote.len(), answers);
				assert!(peer_got.starts_with(&wrote) && peer_got[wrote.len()..].starts_with(answered) && (!user.is_empty() || peer_got.len() == wrote.len()), "the proxy got {} bytes where the origin wrote {}, and a user behind them was {}", peer_got.len(), wrote.len(), if user.is_empty() {"not there"} else {"not answered as one"});
				assert_eq!(after.proofs_accepted - before.proofs_accepted, u64::from(!user.is_empty()), "a proof behind whole requests was not taken, or one was taken that nobody made");
			}
			// Anything else: the node may stop telling requests apart and close behind an answer, so the proxy has the origin's bytes from the first on, and never one that the origin did not write.
			None => assert!(wrote.starts_with(&peer_got), "the proxy got {} bytes that are not the first {} the origin wrote", peer_got.len(), peer_got.len()),
		}
		assert_eq!((after.proxies, after.decoys, after.undecided, after.relayed, after.pending), (0, 0, 0, 0, 0), "the node kept something of a connection that is over");
		assert!(after.sessions <= 1 && after.fronted <= 1, "the node holds {} sessions after one connection", after.sessions);
	});
});
