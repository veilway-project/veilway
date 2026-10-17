#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::{request::Line, shape::{Given, Shape}, shaped::{decode, decoded_len, encode, Parts, Target, Who, DATA_MAX}, NoRandom};

const PATH: &str = "/assets/sync-90be44f1.js";
const SID: &str = "AAECAwQFBgcICQoLDA0ODw";

// The text of a request's data, the canonical decoder and the strict reader of a target. Two bytes of settings, then what the mode says:
//   0  bit 0: the rest is a text for `decode` alone. Clear: the rest is bytes that are encoded, put in a request of the shape the other settings pick, and read back.
//   1  the placement: 0 `body`, 1 `query`, 2 `path`, 3 `header`, and bit 2 for a custom method.
// The decoder must take a text exactly when it is base64url without padding in its one form (every character in the alphabet, a length base64 has, the unused bits of the last character zero, at most 65,536 bytes), and the bytes it gives must encode back to the text. A request the builder writes must read back as its own data, whatever the cut of a path, and a target read must be in the one form the page allows, so that a second spelling of the same bytes is never read.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, place], rest)) = data.split_first_chunk::<2>() else {return};
	if flags & 1 == 1 {
		let alphabet = rest.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_');
		let unused = match rest.len() % 4 {
			0 => true,
			1 => false,
			2 => rest.last().is_some_and(|last| bits(*last) & 0x0f == 0),
			_ => rest.last().is_some_and(|last| bits(*last) & 0x03 == 0),
		};
		let expected = alphabet && unused && decoded_len(rest.len()).is_some_and(|size| size <= DATA_MAX);
		let decoded = decode(rest);
		assert_eq!(decoded.is_some(), expected, "a text was taken or refused against the rule");
		if let Some(bytes) = decoded {
			assert!(bytes.len() <= DATA_MAX && encode(&bytes).as_bytes() == rest, "a decoded text did not encode back to itself");
			assert_eq!(Some(bytes.len()), decoded_len(rest.len()));
		}
		return;
	}
	let (method, place, name) = match place & 3 {
		0 => (if place & 4 != 0 {"DELETE"} else {"POST"}, "body", None),
		1 => (if place & 4 != 0 {"DELETE"} else {"GET"}, "query", None),
		2 => (if place & 4 != 0 {"DELETE"} else {"GET"}, "path", None),
		_ => (if place & 4 != 0 {"DELETE"} else {"GET"}, "header", Some("X-Hint")),
	};
	let shape = Shape::resolve(&Given {method, place, name, limit: None, inflight: None, gather: None, mode: "poll", down_gather: None, life: None, fallback: None}).expect("a shape of the table");
	let mut state = 0x9e3779b97f4a7c15u64 ^ rest.iter().fold(0u64, |sum, byte| sum.rotate_left(5) ^ u64::from(*byte));
	let mut random = |bytes: &mut [u8]| {
		for byte in bytes {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			*byte = state as u8;
		}
		Ok::<(), NoRandom>(())
	};
	for who in [format!("{SID}.5"), "T".repeat(150)] {
		let Ok(Some(parts)) = Parts::build(&shape, PATH, &who, rest, &mut random) else {continue};
		assert!(parts.header.is_some() == (place == "header") && parts.body.is_empty() != (place == "body"));
		let bytes = format!("{method} {} HTTP/1.1\r\n", parts.target).into_bytes();
		let line = Line::parse_any(&bytes).expect("a target the builder wrote is a request line");
		let read = Target::read(&shape, PATH.as_bytes(), &line, parts.header.as_deref().map(str::as_bytes));
		// Data the builder wrote is data only if it is 18 to 65,536 bytes: the node reads no shorter request.
		let Some(read) = read else {
			assert!(rest.len() < 18 || rest.len() > DATA_MAX, "a request the builder wrote was not read back");
			continue;
		};
		assert_eq!(read.who, if who.len() == 150 {Who::Opening(who.as_bytes())} else {Who::Later(std::array::from_fn(|i| i as u8), 5)});
		let found = if read.bodied() {parts.body.clone()} else {read.data().expect("data in a target decodes")};
		assert_eq!(found, rest, "a request did not read back as its own data");
	}
});

// The value of a base64url character.
fn bits(byte: u8) -> u8 {
	match byte {
		b'A'..=b'Z' => byte - b'A',
		b'a'..=b'z' => byte - b'a' + 26,
		b'0'..=b'9' => byte - b'0' + 52,
		b'-' => 62,
		_ => 63,
	}
}
