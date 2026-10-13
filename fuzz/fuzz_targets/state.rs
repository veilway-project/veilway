#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::config::MAX_USERS;
use veilway_core::engine::netstack::{forward, fragments, parse, Fit};
use veilway_core::engine::usage::{parse as state, MAX_COUNT, MAX_SELECTIONS};
use veilway_proto::control::is_tag;

// The first byte picks what the rest is read as. Bit 0 clear: a usage state file. Bit 0 set: a packet the node cuts to fit a device's MTU, which is 1280 plus the upper seven bits of that byte, as its sender when bit 1 is set and as a router when it is not.
fuzz_target!(|data: &[u8]| {
	let Some((pick, data)) = data.split_first() else {return};
	if pick & 1 == 0 {
		let Ok(file) = state(data) else {return};
		for (_, user) in &file.users {
			let totals = user.traffic.totals();
			assert!([user.used(), totals.up_bytes, totals.up_packets, totals.down_bytes, totals.down_packets].iter().all(|count| *count <= MAX_COUNT), "a count above the largest a file holds was read");
		}
		assert!(file.users.len() <= MAX_USERS && file.devices.len() <= MAX_SELECTIONS && file.devices.iter().all(|(_, exit)| is_tag(exit)), "more entries than a node writes were kept, or an exit that is no tag");
		return;
	}
	let (mtu, id) = (1280 + u16::from(pick >> 1), (pick & 2 != 0).then_some(u32::from(*pick)));
	if parse(data).is_none_or(|packet| packet.len != data.len()) {return}
	// The header of an IPv4 packet with its options, and the header of an IPv6 packet with the fragment header its fragments get.
	let header = |packet: &[u8]| if packet[0] >> 4 == 4 {usize::from(packet[0] & 0x0f) * 4} else {40};
	let pieces = fragments(data, mtu, id);
	assert!(pieces.is_empty() || data.len() > usize::from(mtu), "a packet that fits was cut");
	assert!(pieces.iter().all(|piece| piece.len() <= usize::from(mtu) && parse(piece).is_some_and(|packet| packet.len == piece.len() && packet.fragment)), "a fragment does not fit or is no fragment");
	if !pieces.is_empty() {
		assert!(pieces.len() >= 2 && (data[0] >> 4 == 4 || id.is_some()), "one piece, or an ipv6 packet cut by a router");
		assert_eq!(pieces.iter().map(|piece| piece.len() - header(piece) - if data[0] >> 4 == 4 {0} else {8}).sum::<usize>(), data.len() - header(data), "the fragments do not carry what the packet carried");
	}
	match forward(data, mtu) {
		Fit::Whole => assert!(data.len() <= usize::from(mtu)),
		Fit::Pieces(pieces) => assert!(data.len() > usize::from(mtu) && data[0] >> 4 == 4 && data[6] & 0x40 == 0 && pieces.iter().all(|piece| piece.len() <= usize::from(mtu))),
		Fit::TooBig => assert!(data.len() > usize::from(mtu)),
	}
});
