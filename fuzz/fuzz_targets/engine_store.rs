#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_engine::store::{encode, parse, Saved, FILE_MAX, LIST, NETWORKS_MAX, PROFILES_MAX};

// The file a client keeps its choice state in (`veilway-engine`, `store`), read back as hostile input: any bytes, and the bytes of a file that was written, changed in one place.
// A file that reads must be within the bounds the reader promises, and must read the same after it is written again.
fn bounded(saved: &Saved) -> bool {
	saved.profiles.len() <= PROFILES_MAX && saved.profiles.values().all(|kept| kept.networks.len() <= NETWORKS_MAX && kept.mtus.len() <= LIST && kept.standing.rows.len() <= LIST && kept.standing.consent.len() <= 4 && kept.declined.len() <= 4 && kept.networks.iter().all(|(_, network)| network.aside.len() <= LIST && network.tried.len() <= LIST))
}

fuzz_target!(|data: &[u8]| {
	let Ok(saved) = parse(data) else {return};
	assert!(data.len() <= FILE_MAX && bounded(&saved));
	assert_eq!(parse(&encode(&saved)), Ok(saved));
});
