#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::engine::upstream_state::{encode, parse, FILE_MAX, UPSTREAMS_MAX};
use veilway_proto::subscription::client::Held;

// The state file of the upstreams (`veilway-core`, `upstream_state`), read as hostile input: any bytes, and the bytes of a file that was written, changed in one place.
// A file that reads is within its bounds and holds no origin, reads the same after it is written again, and every subscription in it goes through `Held::restore` without a panic (the check that decides whether a changed document is held).
fuzz_target!(|data: &[u8]| {
	let Ok(state) = parse(data) else {return};
	assert!(data.len() <= FILE_MAX && state.len() <= UPSTREAMS_MAX && state.values().all(|(_, stored)| stored.origin.is_none()));
	assert!(parse(&encode(&state)).is_ok_and(|again| again == state));
	for (_, (_, stored)) in state {let _ = Held::restore(stored);}
});
