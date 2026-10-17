#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::h2::{Decoder, HEADER_LIST};

// The input is decoded as two header blocks by one decoder, so that the second block reads the dynamic table the first one left. The first byte picks the table size, from nothing to the default.
fuzz_target!(|data: &[u8]| {
	let Some((table, block)) = data.split_first() else {return};
	let mut decoder = Decoder::new(usize::from(*table) * 16);
	let _ = decoder.decode(block, HEADER_LIST);
	let _ = decoder.decode(block, HEADER_LIST / 4);
});
