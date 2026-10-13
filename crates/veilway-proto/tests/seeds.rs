//! The seed corpus of the fuzz targets in `fuzz/corpus` stays what its file names say: seeds that no longer read would leave the fuzzers starting from nothing. The seeds of `fuzz_control_server` and `fuzz_control_client` are settings for exchanges those targets run themselves, and each run of a target checks them.
use std::{fs, time::Duration};
use veilway_proto::{chunk::{parse, ChunkError, Opener}, control::{ClientMessages, NodeMessages}, keys::{ChunkKey, ControlKey}, opening::{ClientOpening, NodeOpening}, NoRandom};

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
