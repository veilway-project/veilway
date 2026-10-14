#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};
use tokio::time::Instant;
use veilway_engine::{ip, tcp};

const A: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), 40000);
const B: (IpAddr, u16) = (IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)), 47873);

// The client end of the control channel's TCP connection (`veilway-engine`, `tcp`) against a node that is hostile: the input is the segments it sends, one after another, each as a flags byte, a sequence number, an acknowledgment number, a window, and as many bytes of data as a length byte says. The SYN is answered correctly first when the first byte is odd, so that both the handshake and an open connection see the rest.
// Whatever comes, the connection must not panic, must hold no more than it promises (what the caller wrote and what the node sent that was not read), write only packets that read back as segments of its own two ports, and once over stay over.
fuzz_target!(|data: &[u8]| {
	let (now, mut out) = (Instant::now(), Vec::new());
	let mut conn = tcp::Conn::open(A, B, 100, 1300, now, &mut out);
	let mut input = data;
	if input.first().is_some_and(|first| first % 2 == 1) {
		let packet = ip::tcp(B, A, 5000, 101, ip::SYN | ip::ACK, 65535, Some(1200), &[]).expect("a SYN-ACK of one family");
		let found = ip::header(&packet).expect("a SYN-ACK that does not read");
		conn.receive(&ip::segment(&packet[found.payload]).expect("a SYN-ACK segment that does not read"), now, &mut out);
	}
	let mut over = false;
	while input.len() >= 12 {
		let (head, rest) = input.split_at(12);
		let (flags, sequence, acknowledgment, window, length) = (head[0], u32::from_be_bytes(head[1..5].try_into().unwrap()), u32::from_be_bytes(head[5..9].try_into().unwrap()), u16::from_be_bytes([head[9], head[10]]), usize::from(head[11]));
		let (data, rest) = rest.split_at(length.min(rest.len()));
		input = rest;
		if let Some(packet) = ip::tcp(B, A, sequence, acknowledgment, flags, window, None, data) {
			if let Some(found) = ip::header(&packet) {
				if let Some(segment) = ip::segment(&packet[found.payload]) {conn.receive(&segment, now, &mut out)}
			}
		}
		conn.write(b"x", now, &mut out);
		conn.poll(now + std::time::Duration::from_secs(60), &mut out);
		for packet in out.drain(..) {
			let found = ip::header(&packet).expect("a packet the connection wrote does not read");
			let segment = ip::segment(&packet[found.payload]).expect("a segment the connection wrote does not read");
			assert!((found.source, segment.source, found.destination, segment.destination) == (A.0, A.1, B.0, B.1));
		}
		assert!(conn.read().len() <= 65_535 * 2);
		if over {assert!(conn.closed().is_some(), "a connection that was over is open again")} else if conn.closed().is_some() {over = true}
	}
});
