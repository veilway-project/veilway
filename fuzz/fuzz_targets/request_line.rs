#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use veilway_proto::{fronted::{later, later_query}, keys::{Device, Table}, proof::{Name, Node}, request::{Line, Method, Scan, Scanner, LINE_MAX}, NoRandom, Refused};

// The request line rule written a second time, over a whole prefix: what a scanner must say once it has read exactly these bytes and had said `More` before.
fn rule(bytes: &[u8]) -> Scan {
	let target = |byte: &u8| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?%".contains(byte);
	let fits = b"GET /".starts_with(bytes) || b"POST /".starts_with(bytes) || bytes.strip_prefix(b"GET /").or(bytes.strip_prefix(b"POST /")).is_some_and(|rest| {
		let end = rest.iter().position(|byte| *byte == b' ').unwrap_or(rest.len());
		rest[..end].iter().all(target) && b" HTTP/1.1\r\n".starts_with(&rest[end..])
	});
	if !fits {Scan::Forward} else if bytes.ends_with(b" HTTP/1.1\r\n") {Scan::Line(bytes.len())} else if bytes.len() >= LINE_MAX {Scan::Forward} else {Scan::More}
}

// What a stream listener reads before it knows who is there. The first byte is the size of the pieces the rest arrives in, and the rest is the bytes of a connection.
// The scanner must decide at the byte the rule decides at, the same in pieces as byte by byte. A line it calls complete must split into its parts and back, its query is read as the query of a later `fronted` request, which has one text, and as a token, which no node may open.
fuzz_target!(|data: &[u8]| {
	let Some((step, bytes)) = data.split_first() else {return};
	let (mut single, mut pieces, mut expected, mut scan) = (Scanner::new(), Scanner::new(), Scan::More, Scan::More);
	for size in 1..=bytes.len().min(LINE_MAX + 8) {
		if expected == Scan::More {expected = rule(&bytes[..size])}
		assert_eq!(single.feed(&bytes[size - 1..size]), expected, "after {size} bytes");
	}
	for piece in bytes.chunks(usize::from(*step).max(1)) {scan = pieces.feed(piece)}
	assert_eq!(scan, expected, "a line read in pieces was decided another way");
	let Scan::Line(size) = expected else {
		assert!(Line::parse(bytes).is_none(), "bytes that are no complete line were read as one");
		return;
	};
	let line = Line::parse(&bytes[..size]).expect("a complete line has parts");
	let (method, skip) = if bytes[0] == b'G' {(Method::Get, 4)} else {(Method::Post, 5)};
	assert!(size <= LINE_MAX && line.method == method && line.path.starts_with(b"/") && !line.path.contains(&b'?') && line.path_is(line.path) && !line.path_is(&line.path[1..]));
	assert_eq!(line.query.map_or(line.path.to_vec(), |query| [line.path, query].join(&b"?"[..])), &bytes[skip..size - 11], "the parts of a line do not add up to its target");
	let Some(query) = line.query else {return};
	if let Some((sid, number)) = later(query) {assert_eq!(later_query(&sid, number).map(String::into_bytes).as_deref(), Some(query), "a later request has a second text")}
	static NODE: OnceLock<Node> = OnceLock::new();
	let node = NODE.get_or_init(|| Node::new(&[[0x61; 32]], &[0x20; 32], &mut |bytes: &mut [u8]| -> Result<(), NoRandom> {
		bytes.fill(0xd0);
		Ok(())
	}).expect("one key"));
	assert_eq!(node.open(Some(Name::Tls), query, &Table::<Device<()>>::new()).map(|opened| opened.key), Err(Refused), "a node opened a token for a device it does not have");
	// A listener with several paths is told which one it is, and only for a path that is equal.
	assert_eq!((line.path_among(&[b"/", line.path, line.path]), line.path_among(&[&line.path[1..]])), (Some(usize::from(line.path != b"/")), None));
});
