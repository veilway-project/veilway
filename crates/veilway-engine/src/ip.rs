//! The few IP packets the engine writes and reads for itself: the TCP segments of the control channel and the UDP datagrams of an MTU probe, both between the device's tunnel address and the gateway.
//!
//! Anything else that comes out of the tunnel is handed to the platform whole and unread, so these readers see only what the demultiplexer has already matched by address and port. They still check every length against the packet, because the packet came from a node. They do not check checksums: WireGuard authenticated the packet, and the one who could have damaged it is the node that is already trusted with the tunnel's content.
//! Only whole datagrams are read. A fragment, an IPv6 packet with an extension header and an IPv4 header with options that do not fit are not seen here and go on to the platform.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Where a packet comes from and goes to, and where its transport part lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {pub source: IpAddr, pub destination: IpAddr, pub protocol: u8, pub payload: Range<usize>}

/// Reads the header of a whole TCP or UDP packet. None for everything else.
pub fn header(packet: &[u8]) -> Option<Header> {
	match packet.first()? >> 4 {
		4 => {
			let length = usize::from(packet[0] & 0x0f) * 4;
			let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
			if length < 20 || total < length || total > packet.len() || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 || !matches!(packet[9], TCP | UDP) {return None}
			Some(Header {source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).into(), destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).into(), protocol: packet[9], payload: length..total})
		}
		6 => {
			let length = usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
			if packet.len() < 40 + length || !matches!(packet[6], TCP | UDP) {return None}
			Some(Header {source: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).into(), destination: Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).into(), protocol: packet[6], payload: 40..40 + length})
		}
		_ => None,
	}
}

/// The destination address of an IP packet, of either family and any protocol.
pub fn destination(packet: &[u8]) -> Option<IpAddr> {
	match packet.first()? >> 4 {
		4 if packet.len() >= 20 => Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).into()),
		6 if packet.len() >= 40 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).into()),
		_ => None,
	}
}

/// A TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {pub source: u16, pub destination: u16, pub sequence: u32, pub acknowledgment: u32, pub flags: u8, pub window: u16, pub mss: Option<u16>, pub data: &'a [u8]}

/// Reads the transport part of a TCP packet. The options are walked inside the header and only the segment size is taken from them.
pub fn segment(payload: &[u8]) -> Option<Segment<'_>> {
	let length = usize::from(*payload.get(12)? >> 4) * 4;
	if length < 20 || payload.len() < length {return None}
	let (mut options, mut mss) = (&payload[20..length], None);
	while let Some((&kind, rest)) = options.split_first() {
		match kind {
			0 => break,
			1 => options = rest,
			_ => {
				let size = usize::from(*rest.first()?);
				if size < 2 || size - 1 > rest.len() {return None}
				if kind == 2 && size == 4 {mss = Some(u16::from_be_bytes([rest[1], rest[2]]))}
				options = &rest[size - 1..];
			}
		}
	}
	Some(Segment {source: u16::from_be_bytes([payload[0], payload[1]]), destination: u16::from_be_bytes([payload[2], payload[3]]), sequence: u32::from_be_bytes(payload[4..8].try_into().ok()?), acknowledgment: u32::from_be_bytes(payload[8..12].try_into().ok()?), flags: payload[13], window: u16::from_be_bytes([payload[14], payload[15]]), mss, data: &payload[length..]})
}

/// A UDP datagram: the ports and what it carries, for a datagram whose length field is the length of its payload.
pub fn datagram(payload: &[u8]) -> Option<(u16, u16, &[u8])> {
	let length = usize::from(u16::from_be_bytes([*payload.get(4)?, *payload.get(5)?]));
	if length < 8 || length != payload.len() {return None}
	Some((u16::from_be_bytes([payload[0], payload[1]]), u16::from_be_bytes([payload[2], payload[3]]), &payload[8..]))
}

// The ones' complement sum of 16-bit words, folded.
fn sum(parts: &[&[u8]]) -> u16 {
	let (mut total, mut high) = (0u32, None::<u8>);
	for byte in parts.iter().flat_map(|part| part.iter()) {
		match high.take() {
			Some(first) => total += u32::from(u16::from_be_bytes([first, *byte])),
			None => high = Some(*byte),
		}
	}
	if let Some(first) = high {total += u32::from(first) << 8}
	while total > 0xffff {total = (total & 0xffff) + (total >> 16)}
	!(total as u16)
}

// The packet around a transport part: the IP header, with the checksum of the transport part (at `check`) filled in over the pseudo header. None when the two addresses are of two families.
fn wrap(source: IpAddr, destination: IpAddr, protocol: u8, mut part: Vec<u8>, check: usize) -> Option<Vec<u8>> {
	let mut packet = Vec::with_capacity(60 + part.len());
	let length = part.len() as u16;
	match (source, destination) {
		(IpAddr::V4(source), IpAddr::V4(destination)) => {
			let pseudo = [&source.octets()[..], &destination.octets(), &[0, protocol], &length.to_be_bytes()].concat();
			let checksum = sum(&[&pseudo, &part]);
			part[check..check + 2].copy_from_slice(&(if checksum == 0 && protocol == UDP {0xffff} else {checksum}).to_be_bytes());
			packet.extend_from_slice(&[0x45, 0]);
			packet.extend_from_slice(&(20 + length).to_be_bytes());
			// No identification and "don't fragment": nothing the engine writes is ever fragmented.
			packet.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
			packet.extend_from_slice(&source.octets());
			packet.extend_from_slice(&destination.octets());
			let header = sum(&[&packet]);
			packet[10..12].copy_from_slice(&header.to_be_bytes());
		}
		(IpAddr::V6(source), IpAddr::V6(destination)) => {
			let pseudo = [&source.octets()[..], &destination.octets(), &u32::from(length).to_be_bytes(), &[0, 0, 0, protocol]].concat();
			let checksum = sum(&[&pseudo, &part]);
			part[check..check + 2].copy_from_slice(&(if checksum == 0 && protocol == UDP {0xffff} else {checksum}).to_be_bytes());
			packet.extend_from_slice(&[0x60, 0, 0, 0]);
			packet.extend_from_slice(&length.to_be_bytes());
			packet.extend_from_slice(&[protocol, 64]);
			packet.extend_from_slice(&source.octets());
			packet.extend_from_slice(&destination.octets());
		}
		_ => return None,
	}
	packet.append(&mut part);
	Some(packet)
}

/// A TCP packet from `source` to `destination`. `mss` is the segment size option of a SYN.
#[allow(clippy::too_many_arguments)]
pub fn tcp(source: (IpAddr, u16), destination: (IpAddr, u16), sequence: u32, acknowledgment: u32, flags: u8, window: u16, mss: Option<u16>, data: &[u8]) -> Option<Vec<u8>> {
	let length = if mss.is_some() {24} else {20};
	let mut part = Vec::with_capacity(length + data.len());
	part.extend_from_slice(&source.1.to_be_bytes());
	part.extend_from_slice(&destination.1.to_be_bytes());
	part.extend_from_slice(&sequence.to_be_bytes());
	part.extend_from_slice(&acknowledgment.to_be_bytes());
	part.extend_from_slice(&[(length as u8 / 4) << 4, flags]);
	part.extend_from_slice(&window.to_be_bytes());
	part.extend_from_slice(&[0, 0, 0, 0]);
	if let Some(mss) = mss {part.extend_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8])}
	part.extend_from_slice(data);
	wrap(source.0, destination.0, TCP, part, 16)
}

/// A UDP packet from `source` to `destination`.
pub fn udp(source: (IpAddr, u16), destination: (IpAddr, u16), data: &[u8]) -> Option<Vec<u8>> {
	let mut part = Vec::with_capacity(8 + data.len());
	part.extend_from_slice(&source.1.to_be_bytes());
	part.extend_from_slice(&destination.1.to_be_bytes());
	part.extend_from_slice(&(8 + data.len() as u16).to_be_bytes());
	part.extend_from_slice(&[0, 0]);
	part.extend_from_slice(data);
	wrap(source.0, destination.0, UDP, part, 6)
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2));
	const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1));
	const A6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 2));
	const B6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1));

	#[test]
	fn what_is_written_is_read_back_and_its_checksums_hold() {
		for (a, b) in [(A, B), (A6, B6)] {
			let packet = tcp((a, 40000), (b, 47873), 7, 9, SYN | ACK, 65535, Some(1350), b"hi").unwrap();
			let found = header(&packet).unwrap();
			assert_eq!((found.source, found.destination, found.protocol, found.payload.end), (a, b, TCP, packet.len()));
			let read = segment(&packet[found.payload.clone()]).unwrap();
			assert_eq!((read.source, read.destination, read.sequence, read.acknowledgment, read.flags, read.window, read.mss, read.data), (40000, 47873, 7, 9, SYN | ACK, 65535, Some(1350), &b"hi"[..]));
			// The sum over the pseudo header and the segment, checksum included, is zero.
			let length = (packet.len() - found.payload.start) as u16;
			let pseudo = match (a, b) {
				(IpAddr::V4(a), IpAddr::V4(b)) => [&a.octets()[..], &b.octets(), &[0, TCP], &length.to_be_bytes()].concat(),
				(IpAddr::V6(a), IpAddr::V6(b)) => [&a.octets()[..], &b.octets(), &u32::from(length).to_be_bytes(), &[0, 0, 0, TCP]].concat(),
				_ => unreachable!(),
			};
			assert_eq!(sum(&[&pseudo, &packet[found.payload.clone()]]), 0);
			if a.is_ipv4() {assert_eq!(sum(&[&packet[..20]]), 0)}
			let probe = udp((a, 50000), (b, 47873), &[1, 2, 3]).unwrap();
			let found = header(&probe).unwrap();
			assert_eq!((found.protocol, datagram(&probe[found.payload]).unwrap()), (UDP, (50000, 47873, &[1u8, 2, 3][..])));
		}
		assert_eq!(tcp((A, 1), (B6, 2), 0, 0, SYN, 0, None, &[]), None);
	}

	#[test]
	fn the_destination_is_read_from_a_packet_of_either_family_and_from_none_that_is_cut() {
		assert_eq!(destination(&udp((A, 1), (B, 2), b"").unwrap()), Some(B));
		assert_eq!(destination(&udp((A6, 1), (B6, 2), b"").unwrap()), Some(B6));
		let packet = udp((A, 1), (B, 2), b"").unwrap();
		for cut in 0..20 {assert_eq!(destination(&packet[..cut]), None)}
		assert_eq!((destination(&[0x30; 40]), destination(&[])), (None, None));
	}

	#[test]
	fn what_is_not_a_whole_tcp_or_udp_packet_is_not_read() {
		let packet = udp((A, 1), (B, 2), b"abcd").unwrap();
		for cut in 0..packet.len() {assert_eq!(header(&packet[..cut]), None, "{cut}")}
		// A fragment, options that run past the packet and a protocol that is neither.
		let mut fragment = packet.clone();
		fragment[6] = 0x20;
		assert_eq!(header(&fragment), None);
		let mut other = packet.clone();
		other[9] = 1;
		assert_eq!(header(&other), None);
		let mut long = packet.clone();
		long[0] = 0x4f;
		assert_eq!(header(&long), None);
		let mut extended = udp((A6, 1), (B6, 2), b"abcd").unwrap();
		extended[6] = 0;
		assert_eq!(header(&extended), None);
		// A header length of a segment that lies, and an option that does.
		let mut segment_bytes = tcp((A, 1), (B, 2), 0, 0, SYN, 0, Some(1200), &[]).unwrap()[20..].to_vec();
		assert!(segment(&segment_bytes).is_some());
		segment_bytes[12] = 0xf0;
		assert_eq!(segment(&segment_bytes), None);
		segment_bytes[12] = 0x60;
		segment_bytes[21] = 9;
		assert_eq!(segment(&segment_bytes), None);
		segment_bytes[21] = 0;
		assert_eq!(segment(&segment_bytes), None);
		assert_eq!(datagram(&[0; 7]), None);
		assert_eq!(datagram(&[0, 1, 0, 2, 0, 9, 0, 0, 0]), Some((1, 2, &[0u8][..])));
		assert_eq!(datagram(&[0, 1, 0, 2, 0, 9, 0, 0, 0, 0]), None);
	}

	proptest! {
		#[test]
		fn no_bytes_make_a_reader_panic_or_read_past_its_input(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
			if let Some(found) = header(&bytes) {
				prop_assert!(found.payload.start <= found.payload.end && found.payload.end <= bytes.len());
				let part = &bytes[found.payload];
				if let Some(read) = segment(part) {prop_assert!(read.data.len() <= part.len())}
				if let Some((_, _, data)) = datagram(part) {prop_assert!(data.len() + 8 == part.len())}
			}
			let _ = segment(&bytes);
			let _ = datagram(&bytes);
		}
	}
}
