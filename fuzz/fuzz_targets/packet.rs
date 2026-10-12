#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::engine::netstack::{echo_reply, parse, tcp_rst};

fuzz_target!(|data: &[u8]| {
	let _ = tcp_rst(data);
	let Some(packet) = parse(data) else {return};
	assert!(packet.upper <= packet.len && packet.len <= data.len(), "the parser placed a header outside the packet");
	if let Some(reply) = echo_reply(data, &packet) {
		let back = parse(&reply).expect("an echo reply the node wrote itself parses");
		assert_eq!((back.src, back.dst), (packet.dst, packet.src), "the echo reply does not go back to the sender");
	}
});
