#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;
use veilway_core::engine::icmp::{error, Kind, QUOTE_V4, QUOTE_V6};
use veilway_core::engine::netstack::{echo_reply, parse, quoted, tcp_rst};

fuzz_target!(|data: &[u8]| {
	let _ = tcp_rst(data);
	// An ICMP error from the network quotes the start of a packet, and that quote is read whatever it holds.
	if let Some(quote) = quoted(data) {assert!(quote.upper <= quote.len && quote.len <= data.len(), "the parser placed a header outside the quote")}
	let Some(packet) = parse(data) else {return};
	assert!(packet.upper <= packet.len && packet.len <= data.len(), "the parser placed a header outside the packet");
	if let Some(reply) = echo_reply(data, &packet) {
		let back = parse(&reply).expect("an echo reply the node wrote itself parses");
		assert_eq!((back.src, back.dst), (packet.dst, packet.src), "the echo reply does not go back to the sender");
	}
	let pools = ["10.7.0.1/24".parse().unwrap(), "fd7a:115c:a1e0::1/64".parse().unwrap()].map(|pool| (pool, 0));
	let from: IpAddr = if packet.src.is_ipv4() {[10, 7, 0, 1].into()} else {"fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap()};
	for kind in [Kind::Host, Kind::Protocol, Kind::Port, Kind::Prohibited, Kind::TooBig(1280)] {
		let Some(answer) = error(data, &packet, kind, from, &pools) else {continue};
		let back = parse(&answer).expect("an icmp error the node wrote itself parses");
		assert_eq!((back.src, back.dst), (from, packet.src), "the icmp error does not go from the gateway to the sender");
		assert!(!packet.dst.is_multicast() && !packet.src.is_multicast() && !packet.src.is_unspecified(), "an icmp error answers a packet that names no single host");
		let (header, quote) = if from.is_ipv4() {(28, QUOTE_V4)} else {(48, QUOTE_V6)};
		assert_eq!(answer.len(), header + packet.len.min(quote), "the icmp error quotes more or less than it may");
		assert_eq!(answer[header..], data[..packet.len.min(quote)], "the icmp error does not quote the packet it answers");
		assert!(error(&answer, &back, kind, packet.src, &pools).is_none(), "the node would answer its own icmp error");
	}
});
