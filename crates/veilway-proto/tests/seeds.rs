//! The seed corpus of the fuzz targets in `fuzz/corpus` stays what its file names say: seeds that no longer read would leave the fuzzers starting from nothing. The seeds of `fuzz_control_server` and `fuzz_control_client` are settings for exchanges those targets run themselves, and each run of a target checks them.
use std::{fs, time::Duration};
use veilway_proto::{chunk::{parse, ChunkError, Opener}, control::{ClientMessages, NodeMessages}, fronted::later, keys::{ChunkKey, ControlKey}, opening::{ClientOpening, NodeOpening}, replay::{File, MARKER}, request::{Line, Method, Scan, Scanner}, NoRandom};

fn seed(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

// The two readers of a connection, from an exchange that opened.
fn readers() -> (ClientMessages, NodeMessages) {
	let key = || ControlKey::derive(&[1; 32], &[2; 32], &[3; 32]);
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		bytes.fill(0x4e);
		Ok(())
	};
	let (mut up, mut down) = (Vec::new(), Vec::new());
	let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut random, &mut up).unwrap();
	let mut node = NodeOpening::new(Duration::ZERO);
	assert!(node.receive(Duration::ZERO, &[key()], &mut &up[..], &mut random, &mut down).unwrap().is_none());
	assert!(client.receive(Duration::ZERO, &mut &down[..], &mut up).unwrap().is_none());
	let requests = node.receive(Duration::ZERO, &[key()], &mut &up[44..], &mut random, &mut down).unwrap().unwrap().messages;
	(requests, client.receive(Duration::ZERO, &mut &down[36..], &mut up).unwrap().unwrap().messages)
}

#[test]
fn chunk_seeds() {
	let key = || ChunkKey::new(&std::array::from_fn(|i| i as u8));
	assert_eq!(Opener::new(key()).open(&mut seed("chunk/sealed-two-items")[1..]).unwrap().map(<[u8]>::len).collect::<Vec<_>>(), [32, 48]);
	for name in ["plain-two-items", "written-two-items", "items-to-seal"] {assert_eq!(parse(&seed(&format!("chunk/{name}"))[1..]).unwrap().count(), 2, "{name}")}
	assert_eq!(parse(&seed("chunk/plain-padding-only")[1..]).unwrap().count(), 0);
	for name in ["plain-item-too-short", "plain-length-past-end", "plain-length-over-limit", "items-one-too-short"] {assert_eq!(parse(&seed(&format!("chunk/{name}"))[1..]).unwrap_err(), ChunkError::Item, "{name}")}
}

#[test]
fn control_stream_seeds() {
	for (name, count) in [("client-requests", 6), ("node-snapshot", 5), ("node-answers", 6)] {
		let (bytes, (mut requests, mut pushes), mut seen) = (seed(&format!("control_stream/{name}")), readers(), 0);
		let mut input = &bytes[1..];
		while if bytes[0] & 1 == 1 {pushes.read(&mut input).unwrap().is_some()} else {requests.read(&mut input).unwrap().is_some()} {seen += 1}
		assert_eq!((seen, input.len()), (count, 0), "{name}");
	}
}

// The seeds of the transports' targets that spell out more than settings: the bytes after the settings are what their names say.
#[test]
fn transport_seeds() {
	for (name, clean, entries) in [("clean", true, 2), ("running", false, 0)] {assert_eq!(File::decode(&seed(&format!("replay_file/{name}"))[1..], 64).map(|file| (file.clean(), file.len())), Ok((clean, entries)), "{name}")}
	for (name, rule) in [("body-clean", 2), ("body-running", 0), ("body-version-2", 0), ("body-entries-without-mark", 2), ("body-count-too-high", 3)] {
		let body = seed(&format!("replay_file/{name}"));
		assert_eq!((&body[1..9], body[36], body.len()), (&MARKER[..], rule, if rule == 3 {119} else {37 + 41 * usize::from(rule)}), "{name}");
	}
	for (name, method, query) in [("get-token", Method::Get, 151), ("post-opening", Method::Post, 151), ("post-later", Method::Post, 24)] {
		let bytes = seed(&format!("request_line/{name}"));
		let Scan::Line(size) = Scanner::new().feed(&bytes[1..]) else {panic!("{name} is no line")};
		let line = Line::parse(&bytes[1..1 + size]).unwrap();
		assert_eq!((line.method, line.path, line.query.map(<[u8]>::len)), (method, &b"/a-path-of-a-transport"[..], Some(query)), "{name}");
		assert_eq!(later(line.query.unwrap()).map(|(_, number)| number), (query == 24).then_some(7), "{name}");
	}
	assert_eq!(Scanner::new().feed(&seed("request_line/no-query")[1..]), Scan::Line(16));
	for name in ["http-1-0", "head", "bare-newline", "space-in-target", "tls-hello"] {assert_eq!(Scanner::new().feed(&seed(&format!("request_line/{name}"))[1..]), Scan::Forward, "{name}")}
	for (name, count) in [("forged-good", 1), ("forged-no-datagram", 0), ("forged-two-datagrams", 2), ("data-one", 1), ("data-padding-only", 0), ("data-two", 2)] {assert_eq!(parse(&seed(&format!("udp_obfs/{name}"))[20..]).unwrap().count(), count, "{name}")}
	for (name, valid) in [("two-chunks", [true, true]), ("invalid-item", [true, false])] {
		let (bytes, mut at, mut read) = (seed(&format!("fronted_body/{name}")), 4, Vec::new());
		while at < bytes.len() {
			let end = at + 2 + usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
			read.push(parse(&bytes[at + 2..end]).is_ok());
			at = end;
		}
		assert_eq!(read, valid, "{name}");
	}
	for (name, size) in [("forged-good", 8 + 28 + 9), ("forged-binder", 8 + 28 + 32 + 4), ("raw-token", 8 + 151)] {assert_eq!(seed(&format!("stream_proof/{name}")).len(), size, "{name}")}
}

// The requests and the messages that follow the settings in the seeds of the two exchange targets.
#[test]
fn control_exchange_seeds() {
	for (name, node, count) in [("fuzz_control_server/opens-then-requests", false, 6), ("fuzz_control_server/second-key-in-pieces", false, 6), ("fuzz_control_client/opens-then-snapshot", true, 5), ("fuzz_control_client/opens-then-answers", true, 6)] {
		let (bytes, (mut requests, mut pushes), mut seen) = (seed(name), readers(), 0);
		let mut input = &bytes[8..];
		while if node {pushes.read(&mut input).unwrap().is_some()} else {requests.read(&mut input).unwrap().is_some()} {seen += 1}
		assert_eq!((seen, input.len()), (count, 0), "{name}");
	}
}
