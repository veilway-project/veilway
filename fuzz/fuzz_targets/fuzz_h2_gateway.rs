#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::h2::gateway::{self, Chunked};
use veilway_proto::h2::Fields;

// The input is a settings byte and the rest. Bit 0 picks the side: a header list (bit 1 is END_STREAM) turned into the request for the origin, or an origin's answer head turned back. Bit 2 feeds the answer's body through the chunked reader in pieces of the size the next bits give.
// The header list is read as a run of fields, each a length byte, the name, a length byte and the value. A request that is made has one Host line, its head ends at the empty line, every line ends in CRLF with no NUL, CR or LF inside it, and a chunked body has no content-length.
fuzz_target!(|data: &[u8]| {
	let Some((settings, rest)) = data.split_first() else {return};
	if settings & 1 == 0 {
		let (mut fields, mut at): (Fields, usize) = (Vec::new(), 0);
		while let Some(&name) = rest.get(at) {
			let Some(&value) = rest.get(at + 1 + usize::from(name)) else {break};
			let Some(bytes) = rest.get(at + 2 + usize::from(name)..at + 2 + usize::from(name) + usize::from(value)) else {break};
			fields.push((rest[at + 1..at + 1 + usize::from(name)].to_vec(), bytes.to_vec()));
			at += 2 + usize::from(name) + usize::from(value);
		}
		let Ok(request) = gateway::request(&fields, settings & 2 != 0, "c2VjcmV0c2VjcmV0c2VjcmV0") else {return};
		let head = &request.head;
		assert!(head.ends_with(b"\r\n\r\n"));
		let lines: Vec<&[u8]> = head[..head.len() - 2].split(|byte| *byte == b'\n').collect();
		assert!(lines[..lines.len() - 1].iter().all(|line| line.last() == Some(&b'\r') && !line[..line.len() - 1].iter().any(|byte| matches!(byte, 0 | b'\r'))));
		assert_eq!(lines[1..lines.len() - 1].iter().filter(|line| line.to_ascii_lowercase().starts_with(b"host:")).count(), 1);
		assert!(!(request.chunked && head.windows(15).any(|window| window.eq_ignore_ascii_case(b"content-length:"))));
	} else {
		let Some(answer) = gateway::response(rest, settings & 2 != 0, settings & 4 != 0) else {return};
		assert!((100..=599).contains(&answer.status));
		if settings & 4 == 0 {return}
		let (mut chunked, mut out) = (Chunked::new(), Vec::new());
		let step = usize::from(settings >> 3) + 1;
		for piece in rest.chunks(step) {
			if chunked.feed(piece, &mut out).is_err() {break}
		}
	}
});
