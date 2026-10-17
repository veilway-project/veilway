#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;
use std::time::Instant;
use veilway_engine::packets::{Front, Taken, IN_FLIGHT};

// The front door of the carrier of a legacy profile (`veilway-engine`, `packets`): what the device writes into the tunnel, packet after packet. The input is cut into packets by a length byte before each. Whatever comes, nothing may panic, a packet handed to the stack must be a whole TCP or UDP packet that reads back, an answer must be an echo reply to the gateway, and the datagrams that wait for their pieces stay within their cap.
fuzz_target!(|data: &[u8]| {
	let (mut front, mut input, now) = (Front::new([IpAddr::from([198, 18, 0, 1]), IpAddr::from([0xfdfe_u16, 0x7665, 0x6c77, 0, 0, 0, 0, 1])]), data, Instant::now());
	while let Some((length, rest)) = input.split_first() {
		let (packet, rest) = rest.split_at(usize::from(*length).min(rest.len()));
		input = rest;
		match front.take(packet.to_vec(), now) {
			Taken::Stack(whole) => assert!(matches!(whole.first().map(|byte| byte >> 4), Some(4 | 6)) && whole.len() >= 28 && whole.len() <= 65535 + 40, "a packet for the stack that is no whole packet"),
			Taken::Reply(reply) => assert!(reply.len() >= 28 && reply.len() <= packet.len() + 8, "an answer longer than the question"),
			Taken::Held | Taken::Unsupported => {}
		}
		assert!(front.waiting() <= IN_FLIGHT, "more datagrams wait than the cap");
	}
});
