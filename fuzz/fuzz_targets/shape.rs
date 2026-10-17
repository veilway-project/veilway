#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::shape::{Given, In, Mode, Shape};

// The shape of a `fronted-shaped` transport as a profile writes it. The input is JSON text, read as strictly as a payload is.
// A text that reads must be a shape every rule of the page holds for, written a second time here, and must read back from the members it has: the shape a config writes and the shape a profile writes are one object, so the node and the client never disagree about it.
fuzz_target!(|data: &[u8]| {
	let Ok(shape) = Shape::parse(data) else {return};
	let (up, down) = (&shape.up, &shape.down);
	let custom = !["GET", "POST", "PUT", "PATCH"].contains(&up.method.as_str());
	assert!(!["CONNECT", "TRACE", "HEAD", "OPTIONS"].contains(&up.method.as_str()), "a method the page refuses");
	assert!(!custom || ((3..=16).contains(&up.method.len()) && up.method.bytes().all(|byte| byte.is_ascii_uppercase())), "a custom method outside 3 to 16 capitals");
	match (up.method.as_str(), up.place) {
		("GET", In::Body) | ("POST" | "PUT" | "PATCH", In::Query | In::Path | In::Header) => panic!("a combination the table refuses"),
		_ => {}
	}
	assert_eq!(up.name.is_some(), up.place == In::Header, "a header name is there exactly with a header");
	if let Some(name) = &up.name {
		let lower = name.to_ascii_lowercase();
		assert!((1..=32).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'), "a header name outside its alphabet");
		assert!(!["host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "accept", "range", "expect", "te", "trailer"].contains(&lower.as_str()) && !lower.starts_with("sec-") && !lower.starts_with("proxy-"), "a header name the page refuses");
	}
	let bounds = match up.place {
		In::Body => 1_024..=65_536,
		In::Header => 1_024..=4_096,
		In::Query | In::Path => 1_024..=8_000,
	};
	assert!(bounds.contains(&up.limit) && (1..=4).contains(&up.inflight) && (down.mode == Mode::Sse || up.inflight == 1), "a limit or a count outside its bounds");
	assert!(up.gather.start() <= up.gather.end() && *up.gather.end() <= 250 && down.gather.start() <= down.gather.end() && *down.gather.end() <= 250, "a gather range out of order or over 250 ms");
	assert!(down.life.start() <= down.life.end() && *down.life.start() >= 30 && *down.life.end() <= 3_600, "a life range out of order or outside 30 to 3,600 s");
	// What the shape holds, handed to the rules again, gives the same shape.
	let (gather, down_gather, life) = ([u64::from(*up.gather.start()), u64::from(*up.gather.end())], [u64::from(*down.gather.start()), u64::from(*down.gather.end())], [u64::from(*down.life.start()), u64::from(*down.life.end())]);
	let sse = down.mode == Mode::Sse;
	let again = Shape::resolve(&Given {method: &up.method, place: up.place.word(), name: up.name.as_deref(), limit: Some(up.limit as u64), inflight: Some(u64::from(up.inflight)), gather: Some(gather), mode: if sse {"sse"} else {"poll"}, down_gather: sse.then_some(down_gather), life: sse.then_some(life), fallback: sse.then_some(down.fallback)});
	assert_eq!(again.as_ref(), Ok(&shape), "a shape did not read back from its own members");
	assert_eq!(shape.line_max() == 8_192, up.limit > 4_000);
});
