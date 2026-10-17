#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::sse::{chunked, event, Fault, Reader, END, EVENTS};

// How many events the harness writes at the most, so that an input costs little: the reader's own limit of 4,095 is what the tests of the crate have.
const WRITTEN: usize = 48;

// The reader the client puts a stream answer through. Two bytes of settings, then what the mode says:
//   0  the size of the pieces the bytes arrive in
//   1  bit 0: the rest is bytes as they are. Clear: the rest is sealed chunks of the sizes it names, written by the node's writer inside the chunked coding, and with bit 1 set one byte of the wire is changed.
// A stream must read the same in pieces as whole, event by event and fault by fault. Whatever came out is a sealed chunk of 16 to 16,016 bytes, there are at most 4,095 of them, a fault is final, and a stream the writer wrote reads back as the chunks it was given.
fuzz_target!(|data: &[u8]| {
	let Some((&[step, flags], rest)) = data.split_first_chunk::<2>() else {return};
	let wire = if flags & 1 == 1 {rest.to_vec()} else {
		let (mut wire, mut at) = (Vec::new(), 0);
		while let Some(size) = rest.get(at).filter(|_| at < WRITTEN) {
			let size = 16 + (usize::from(*size) * 63) % 16_001;
			let sealed: Vec<u8> = (0..size).map(|index| rest.get(at + 1 + index % 7).copied().unwrap_or(index as u8)).collect();
			chunked(&event(&sealed), &mut wire);
			at += 1;
		}
		wire.extend_from_slice(END);
		if flags & 2 != 0 && !wire.is_empty() {
			let place = (usize::from(step) * 251 + rest.len()) % wire.len();
			wire[place] ^= 1 << (usize::from(step) % 8);
		}
		wire
	};
	let (mut whole, mut out_whole) = (Reader::new(), Vec::new());
	let result_whole = whole.feed(&wire, &mut out_whole);
	let (mut pieces, mut out_pieces, mut result_pieces) = (Reader::new(), Vec::new(), Ok(false));
	for piece in wire.chunks(usize::from(step).max(1)) {
		result_pieces = pieces.feed(piece, &mut out_pieces);
		if result_pieces.is_err() {break}
	}
	assert_eq!(result_whole, result_pieces, "a stream read in pieces ended another way");
	assert_eq!(out_whole, out_pieces, "a stream read in pieces gave other events");
	assert!(out_whole.len() <= EVENTS && out_whole.iter().all(|sealed| (16..=16_016).contains(&sealed.len())), "an event outside its bounds");
	assert_eq!(whole.events(), out_whole.len());
	if let Err(fault) = result_whole {
		assert_eq!(whole.feed(&[0], &mut out_whole), Err(fault), "a fault was not final");
		assert!(matches!(fault, Fault::Chunked | Fault::Line | Fault::Event | Fault::Count));
	}
	if flags & 3 == 0 {
		assert_eq!((result_whole, out_whole.len()), (Ok(true), rest.len().min(WRITTEN)), "a stream the writer wrote was not read back");
	}
});
