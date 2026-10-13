//! The seed corpus of the `state` fuzz target in `fuzz/corpus/state` stays what its file names say: seeds that no longer read would leave the fuzzer starting from nothing, and it then never gets past the parser to the fragmenter. `tests/seeds.py` writes them.
use std::fs;
use veilway_core::engine::netstack::{forward, fragments, parse, Fit};
use veilway_core::engine::usage;

fn seed(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/state/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

#[test]
fn packet_seeds() {
	// What the target makes of each: the MTU and whether the node is the sender come from the first byte.
	let cut = |name: &str| {
		let bytes = seed(name);
		let (mtu, packet) = (1280 + u16::from(bytes[0] >> 1), &bytes[1..]);
		assert!(bytes[0] & 1 == 1 && parse(packet).is_some_and(|parsed| parsed.len == packet.len()), "{name} is no whole packet");
		(fragments(packet, mtu, (bytes[0] & 2 != 0).then_some(7)).len(), forward(packet, mtu))
	};
	assert!(matches!(cut("v4-forwarded"), (2, Fit::Pieces(pieces)) if pieces.len() == 2));
	assert_eq!(cut("v4-forwarded-df"), (2, Fit::TooBig));
	assert_eq!(cut("v4-sent").0, 4);
	assert_eq!(cut("v4-sent-options").0, 2);
	assert_eq!(cut("v4-sent-fragment"), (0, Fit::TooBig));
	assert_eq!(cut("v4-sent-fits"), (0, Fit::Whole));
	assert_eq!(cut("v4-sent-largest-mtu").0, 2);
	assert_eq!(cut("v6-forwarded"), (0, Fit::TooBig));
	assert_eq!(cut("v6-sent").0, 4);
	assert_eq!(cut("v6-sent-hop-by-hop"), (0, Fit::TooBig));
	assert_eq!(cut("v6-sent-largest-mtu").0, 2);
}

#[test]
fn state_seeds() {
	for (name, users, devices, skipped) in [("state-devices", 1, 1, 0), ("state-untrusted", 1, 0, 3)] {
		let bytes = seed(name);
		assert_eq!(bytes[0] & 1, 0, "{name}");
		let file = usage::parse(&bytes[1..]).unwrap_or_else(|e| panic!("{name}: {e}"));
		assert_eq!((file.users.len(), file.devices.len(), file.skipped), (users, devices, skipped), "{name}");
	}
}
