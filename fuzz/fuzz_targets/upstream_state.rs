#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::engine::upstream_state::{encode, parse, FILE_MAX, UPSTREAMS_MAX};
use veilway_proto::subscription::client::Held;

// The state file of the upstreams (`veilway-core`, `upstream_state`), read as hostile input: any bytes, and the bytes of a file that was written, changed in one place.
// A file that reads is within its bounds (documents and tombstones of removed upstreams) and holds no origin, reads the same after it is written again, and every subscription in it goes through `Held::restore` without a panic (the check that decides whether a changed document is held).
fuzz_target!(|data: &[u8]| {
	let Ok(content) = parse(data) else {return};
	assert!(data.len() <= FILE_MAX && content.held.len() <= UPSTREAMS_MAX && content.left.len() <= UPSTREAMS_MAX && content.held.values().all(|(.., stored)| stored.origin.is_none()));
	assert!(parse(&encode(&content)).is_ok_and(|again| again == content));
	for (.., stored) in content.held.into_values() {let _ = Held::restore(stored);}
});
