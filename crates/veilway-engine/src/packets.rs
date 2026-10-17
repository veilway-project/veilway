//! The packets the Xray carrier reads and writes for itself, around the userspace stack ("How traffic reaches Xray"). Everything that comes out of the device is looked at here before the stack sees it: a TCP or UDP packet goes on, an echo request to the gateway is answered, the pieces of a fragmented datagram are put together under a cap, and everything else is dropped and counted. Nothing of it goes anywhere: the routes still point into the device, so a dropped packet cannot find another way.
//!
//! It also builds the few packets the carrier writes without the stack: the reset that ends a TCP flow, and the ICMP error that tells the device a destination cannot be reached. A packet from the device is the user's own machine, but a fragment's offsets and lengths are still read as hostile: nothing is indexed before it is checked against the packet.
use etherparse::{icmpv4, icmpv6, Icmpv4Type, Icmpv6Type, PacketBuilder, TcpHeader};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const TCP: u8 = 6;
const UDP: u8 = 17;
const FRAGMENT: u8 = 44;
/// The most a reassembled datagram may hold.
pub const DATAGRAM_MAX: usize = 64 << 10;
/// The most datagrams that wait for their pieces at once.
pub const IN_FLIGHT: usize = 64;
/// A datagram whose pieces do not all come within this long is forgotten.
const AGE: Duration = Duration::from_secs(30);
const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REQUEST_V6: u8 = 128;

/// What the carrier does with one packet from the device.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken {
	/// A whole TCP or UDP packet, for the stack. A datagram put together from pieces comes out here, whole.
	Stack(Vec<u8>),
	/// Answered here, and nothing goes on: the reply to a ping of the gateway.
	Reply(Vec<u8>),
	/// A piece of a datagram that is not complete yet.
	Held,
	/// ICMP anywhere else, another protocol, a packet that does not read, or a piece over the caps. Dropped, and counted as `unsupported_packets`.
	Unsupported,
}

struct Ip {src: IpAddr, dst: IpAddr, protocol: u8, upper: usize, len: usize, piece: Option<Piece>}

/// Where a packet lies in the datagram it was cut from.
struct Piece {id: u32, offset: usize, more: bool}

fn read(raw: &[u8]) -> Option<Ip> {
	match raw.first()? >> 4 {
		4 => {
			let (header, len) = (usize::from(raw[0] & 0x0f) * 4, usize::from(u16::from_be_bytes([*raw.get(2)?, *raw.get(3)?])));
			if header < 20 || len < header || raw.len() < len {return None}
			let place = u16::from_be_bytes([raw[6], raw[7]]);
			let piece = (place & 0x3fff != 0).then(|| Piece {id: u32::from(u16::from_be_bytes([raw[4], raw[5]])), offset: usize::from(place & 0x1fff) * 8, more: place & 0x2000 != 0});
			Some(Ip {src: IpAddr::from(<[u8; 4]>::try_from(&raw[12..16]).ok()?), dst: IpAddr::from(<[u8; 4]>::try_from(&raw[16..20]).ok()?), protocol: raw[9], upper: header, len, piece})
		}
		6 => {
			let len = 40 + usize::from(u16::from_be_bytes([*raw.get(4)?, *raw.get(5)?]));
			if raw.len() < len {return None}
			let (src, dst) = (IpAddr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?), IpAddr::from(<[u8; 16]>::try_from(&raw[24..40]).ok()?));
			if raw[6] != FRAGMENT {return Some(Ip {src, dst, protocol: raw[6], upper: 40, len, piece: None})}
			if len < 48 {return None}
			let place = u16::from_be_bytes([raw[42], raw[43]]);
			Some(Ip {src, dst, protocol: raw[40], upper: 48, len, piece: Some(Piece {id: u32::from_be_bytes([raw[44], raw[45], raw[46], raw[47]]), offset: usize::from(place & 0xfff8), more: place & 1 == 1})})
		}
		_ => None,
	}
}

// The ones' complement sum of the words of an IPv4 header.
fn checksum(header: &[u8]) -> u16 {
	let mut total = header.chunks(2).fold(0u32, |total, word| total + u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)])));
	while total > 0xffff {total = (total & 0xffff) + (total >> 16)}
	!(total as u16)
}

/// The pieces of one datagram: the header of the first, and the data of each by its offset.
struct Pending {header: Option<Vec<u8>>, pieces: BTreeMap<usize, Vec<u8>>, end: Option<usize>, started: Instant}

/// The carrier's front door: what it does with each packet of the device, and the datagrams waiting for their pieces.
pub struct Front {
	gateways: [IpAddr; 2],
	waiting: HashMap<(IpAddr, IpAddr, u32, u8), Pending>,
}

impl Front {
	/// `gateways` are the tunnel's own addresses of the two families: the ones a ping is answered at.
	pub fn new(gateways: [IpAddr; 2]) -> Self {Self {gateways, waiting: HashMap::new()}}
	/// How many datagrams wait for their pieces.
	#[cfg_attr(not(feature = "fuzz"), allow(dead_code))]
	pub fn waiting(&self) -> usize {self.waiting.len()}
	/// Looks at one packet from the device. A piece is kept until the rest has come, and the datagram it completes is judged whole, as if it had come in one packet.
	pub fn take(&mut self, mut raw: Vec<u8>, now: Instant) -> Taken {
		let Some(ip) = read(&raw) else {return Taken::Unsupported};
		raw.truncate(ip.len);
		let Some(piece) = &ip.piece else {return self.whole(raw, &ip)};
		self.waiting.retain(|_, pending| now.duration_since(pending.started) < AGE);
		let key = (ip.src, ip.dst, piece.id, ip.protocol);
		if !self.waiting.contains_key(&key) && self.waiting.len() >= IN_FLIGHT {return Taken::Unsupported}
		let pending = self.waiting.entry(key).or_insert_with(|| Pending {header: None, pieces: BTreeMap::new(), end: None, started: now});
		let data = &raw[ip.upper..];
		let end = piece.offset + data.len();
		let sound = !data.is_empty() && (!piece.more || data.len() % 8 == 0) && end <= DATAGRAM_MAX && pending.end.is_none_or(|known| end <= known && (piece.more || end == known));
		let overlap = pending.pieces.iter().any(|(offset, held)| *offset < end && piece.offset < offset + held.len());
		if !sound || (overlap && pending.pieces.get(&piece.offset).is_none_or(|held| held.len() != data.len())) {
			self.waiting.remove(&key);
			return Taken::Unsupported;
		}
		if overlap {return Taken::Held}
		if piece.offset == 0 {pending.header = Some(raw[..ip.upper].to_vec())}
		if !piece.more {pending.end = Some(end)}
		pending.pieces.insert(piece.offset, data.to_vec());
		let (Some(header), Some(total)) = (&pending.header, pending.end) else {return Taken::Held};
		let mut next = 0;
		for (offset, held) in &pending.pieces {
			if *offset != next {return Taken::Held}
			next += held.len();
		}
		if next != total {return Taken::Held}
		let mut whole = header.clone();
		for held in pending.pieces.values() {whole.extend_from_slice(held)}
		if ip.src.is_ipv4() {
			let length = (whole.len() as u16).to_be_bytes();
			whole[2..4].copy_from_slice(&length);
			whole[6..8].copy_from_slice(&[0, 0]);
			whole[10..12].copy_from_slice(&[0, 0]);
			let sum = checksum(&whole[..usize::from(whole[0] & 0x0f) * 4]).to_be_bytes();
			whole[10..12].copy_from_slice(&sum);
		} else {
			// The header kept is the first piece's, with the fragment header cut out of it: the protocol the fragment header named is the packet's.
			let next = whole[40];
			whole.drain(40..48);
			let length = ((whole.len() - 40) as u16).to_be_bytes();
			whole[4..6].copy_from_slice(&length);
			whole[6] = next;
		}
		self.waiting.remove(&key);
		match read(&whole) {
			Some(found) if found.piece.is_none() => self.whole(whole, &found),
			_ => Taken::Unsupported,
		}
	}
	fn whole(&self, raw: Vec<u8>, ip: &Ip) -> Taken {
		let body = &raw[ip.upper..ip.len];
		match ip.protocol {
			TCP if body.len() >= 20 => Taken::Stack(raw),
			UDP if body.len() >= 8 => Taken::Stack(raw),
			ICMP | ICMPV6 if body.len() >= 8 && body[1] == 0 && body[0] == if ip.protocol == ICMP {ECHO_REQUEST_V4} else {ECHO_REQUEST_V6} && self.gateways.contains(&ip.dst) && ip.dst.is_ipv4() == (ip.protocol == ICMP) => {
				let (ident, seq, payload) = (u16::from_be_bytes([body[4], body[5]]), u16::from_be_bytes([body[6], body[7]]), &body[8..]);
				let mut out = Vec::with_capacity(raw.len());
				let built = match (ip.dst, ip.src) {
					(IpAddr::V4(from), IpAddr::V4(to)) => PacketBuilder::ipv4(from.octets(), to.octets(), 64).icmpv4_echo_reply(ident, seq).write(&mut out, payload),
					(IpAddr::V6(from), IpAddr::V6(to)) => PacketBuilder::ipv6(from.octets(), to.octets(), 64).icmpv6_echo_reply(ident, seq).write(&mut out, payload),
					_ => return Taken::Unsupported,
				};
				if built.is_ok() {Taken::Reply(out)} else {Taken::Unsupported}
			}
			_ => Taken::Unsupported,
		}
	}
}

/// The reset that tells the device a TCP flow is over, as the remote end would send it: from `remote` to `local`, at the sequence number the stack has reached and acknowledging what it has taken.
pub fn reset(local: SocketAddr, remote: SocketAddr, seq: u32, ack: u32) -> Option<Vec<u8>> {
	let mut header = TcpHeader::new(remote.port(), local.port(), seq, 0);
	header.rst = true;
	header.ack = true;
	header.acknowledgment_number = ack;
	let builder = match (remote.ip(), local.ip()) {
		(IpAddr::V4(from), IpAddr::V4(to)) => PacketBuilder::ipv4(from.octets(), to.octets(), 64),
		(IpAddr::V6(from), IpAddr::V6(to)) => PacketBuilder::ipv6(from.octets(), to.octets(), 64),
		_ => return None,
	}.tcp_header(header);
	let mut out = Vec::with_capacity(builder.size(0));
	builder.write(&mut out, &[]).ok()?;
	Some(out)
}

/// The ICMP error "host unreachable" for a flow of the device, from `from` (the gateway), quoting the flow's first packet as the device sent it: the headers rebuilt from the flow's addresses and ports, and for TCP the sequence number `seq` the first packet carried.
pub fn unreachable(from: IpAddr, local: SocketAddr, remote: SocketAddr, seq: Option<u32>) -> Option<Vec<u8>> {
	let mut quote = Vec::new();
	let builder = match (local.ip(), remote.ip()) {
		(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64),
		(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64),
		_ => return None,
	};
	match seq {
		Some(seq) => builder.tcp(local.port(), remote.port(), seq, 65535).write(&mut quote, &[]).ok()?,
		None => builder.udp(local.port(), remote.port()).write(&mut quote, &[]).ok()?,
	}
	quote.truncate(if local.is_ipv4() {28} else {48});
	let mut out = Vec::new();
	match (from, local.ip()) {
		(IpAddr::V4(from), IpAddr::V4(to)) => PacketBuilder::ipv4(from.octets(), to.octets(), 64).icmpv4(Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::Host)).write(&mut out, &quote).ok()?,
		(IpAddr::V6(from), IpAddr::V6(to)) => PacketBuilder::ipv6(from.octets(), to.octets(), 64).icmpv6(Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Address)).write(&mut out, &quote).ok()?,
		_ => return None,
	}
	Some(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	const DEVICE: [u8; 4] = [198, 18, 0, 2];
	const GATEWAY: [u8; 4] = [198, 18, 0, 1];
	const DEVICE_V6: [u8; 16] = [0xfd, 0xfe, 0x76, 0x65, 0x6c, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
	const GATEWAY_V6: [u8; 16] = [0xfd, 0xfe, 0x76, 0x65, 0x6c, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

	fn front() -> Front {Front::new([IpAddr::from(GATEWAY), IpAddr::from(GATEWAY_V6)])}

	fn udp(payload: &[u8]) -> Vec<u8> {
		let mut raw = Vec::new();
		PacketBuilder::ipv4(DEVICE, [93, 184, 216, 34], 64).udp(40000, 9000).write(&mut raw, payload).unwrap();
		raw
	}

	// Cuts a whole IPv4 packet into pieces of `size` bytes of data (a multiple of 8), each with its own header.
	fn cut_v4(raw: &[u8], size: usize, id: u16) -> Vec<Vec<u8>> {
		let (header, data) = (&raw[..20], &raw[20..]);
		let count = data.len().div_ceil(size);
		data.chunks(size).enumerate().map(|(at, part)| {
			let mut piece = [header, part].concat();
			piece[2..4].copy_from_slice(&((20 + part.len()) as u16).to_be_bytes());
			piece[4..6].copy_from_slice(&id.to_be_bytes());
			let place = (at * size / 8) as u16 | if at + 1 < count {0x2000} else {0};
			piece[6..8].copy_from_slice(&place.to_be_bytes());
			piece
		}).collect()
	}

	fn cut_v6(raw: &[u8], size: usize, id: u32) -> Vec<Vec<u8>> {
		let (header, data) = (&raw[..40], &raw[40..]);
		let count = data.len().div_ceil(size);
		data.chunks(size).enumerate().map(|(at, part)| {
			let place = ((at * size) as u16 & 0xfff8) | u16::from(at + 1 < count);
			let mut piece = [header, &[raw[6], 0][..], &place.to_be_bytes(), &id.to_be_bytes(), part].concat();
			piece[4..6].copy_from_slice(&((8 + part.len()) as u16).to_be_bytes());
			piece[6] = FRAGMENT;
			piece
		}).collect()
	}

	#[test]
	fn tcp_and_udp_go_to_the_stack_and_padding_is_cut() {
		let mut raw = udp(b"hello");
		let whole = raw.clone();
		raw.extend_from_slice(&[0; 9]);
		assert_eq!(front().take(raw, Instant::now()), Taken::Stack(whole));
		let mut tcp = Vec::new();
		PacketBuilder::ipv4(DEVICE, [93, 184, 216, 34], 64).tcp(40000, 443, 1, 1000).syn().write(&mut tcp, &[]).unwrap();
		assert!(matches!(front().take(tcp, Instant::now()), Taken::Stack(_)));
		let mut six = Vec::new();
		PacketBuilder::ipv6(DEVICE_V6, [0x20; 16], 64).udp(1, 2).write(&mut six, b"x").unwrap();
		assert!(matches!(front().take(six, Instant::now()), Taken::Stack(_)));
	}

	#[test]
	fn a_ping_of_the_gateway_is_answered_and_nothing_else_of_icmp_is() {
		let ping = |to: [u8; 4]| {
			let mut raw = Vec::new();
			PacketBuilder::ipv4(DEVICE, to, 64).icmpv4_echo_request(7, 9).write(&mut raw, b"abcd").unwrap();
			raw
		};
		let Taken::Reply(reply) = front().take(ping(GATEWAY), Instant::now()) else {panic!("the gateway did not answer")};
		let found = read(&reply).unwrap();
		assert_eq!((found.src, found.dst, found.protocol, reply[20], &reply[24..28], &reply[28..]), (IpAddr::from(GATEWAY), IpAddr::from(DEVICE), 1, 0, &[0, 7, 0, 9][..], &b"abcd"[..]));
		assert_eq!(front().take(ping([93, 184, 216, 34]), Instant::now()), Taken::Unsupported);
		let mut six = Vec::new();
		PacketBuilder::ipv6(DEVICE_V6, GATEWAY_V6, 64).icmpv6_echo_request(1, 2).write(&mut six, b"zz").unwrap();
		let Taken::Reply(reply) = front().take(six, Instant::now()) else {panic!("the v6 gateway did not answer")};
		assert_eq!((read(&reply).unwrap().protocol, reply[40]), (58, 129));
		let mut timestamp = Vec::new();
		PacketBuilder::ipv4(DEVICE, GATEWAY, 64).icmpv4_raw(13, 0, [0; 4]).write(&mut timestamp, &[0; 12]).unwrap();
		assert_eq!(front().take(timestamp, Instant::now()), Taken::Unsupported);
		let mut to_v4_gateway_over_v6 = Vec::new();
		PacketBuilder::ipv6(DEVICE_V6, [0x20; 16], 64).icmpv6_echo_request(1, 2).write(&mut to_v4_gateway_over_v6, b"zz").unwrap();
		assert_eq!(front().take(to_v4_gateway_over_v6, Instant::now()), Taken::Unsupported);
	}

	#[test]
	fn other_protocols_and_unreadable_packets_are_unsupported() {
		for protocol in [50u8, 47, 132, 41] {
			let mut raw = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, protocol, 0, 0, 198, 18, 0, 2, 1, 1, 1, 1];
			raw.extend_from_slice(&[0; 8]);
			assert_eq!(front().take(raw, Instant::now()), Taken::Unsupported, "protocol {protocol}");
		}
		for raw in [vec![], vec![0x45], vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2], vec![0x60; 20], vec![0x15; 40]] {assert_eq!(front().take(raw, Instant::now()), Taken::Unsupported)}
		let mut short = udp(b"x");
		short.truncate(short.len() - 1);
		assert_eq!(front().take(short, Instant::now()), Taken::Unsupported);
	}

	#[test]
	fn the_pieces_of_a_datagram_are_put_together_in_any_order() {
		let payload: Vec<u8> = (0..3000).map(|at| (at % 251) as u8).collect();
		let whole = udp(&payload);
		for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0]] {
			let pieces = cut_v4(&whole, 1480, 77);
			let mut front = front();
			let mut got = Vec::new();
			for at in order {got.push(front.take(pieces[at].clone(), Instant::now()))}
			assert_eq!(&got[..2], [Taken::Held, Taken::Held]);
			let Taken::Stack(rebuilt) = &got[2] else {panic!("not put together: {got:?}")};
			assert_eq!(rebuilt[20..], whole[20..]);
			assert_eq!(checksum(&rebuilt[..20]), 0, "the header checksum of the datagram put together");
			assert_eq!(u16::from_be_bytes([rebuilt[2], rebuilt[3]]) as usize, rebuilt.len());
			assert!(front.waiting.is_empty());
		}
	}

	#[test]
	fn ipv6_pieces_are_put_together() {
		let payload: Vec<u8> = (0..3000).map(|at| (at % 251) as u8).collect();
		let mut whole = Vec::new();
		PacketBuilder::ipv6(DEVICE_V6, [0x20; 16], 64).udp(40000, 9000).write(&mut whole, &payload).unwrap();
		let mut front = front();
		let pieces = cut_v6(&whole, 1448, 5);
		assert_eq!(front.take(pieces[1].clone(), Instant::now()), Taken::Held);
		assert_eq!(front.take(pieces[2].clone(), Instant::now()), Taken::Held);
		assert_eq!(front.take(pieces[0].clone(), Instant::now()), Taken::Stack(whole));
	}

	#[test]
	fn a_datagram_over_the_cap_a_piece_that_overlaps_and_a_flood_are_dropped() {
		let payload = vec![7u8; 70000];
		let mut big = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 198, 18, 0, 2, 1, 1, 1, 1];
		big.extend_from_slice(&payload[..2000]);
		let pieces = cut_v4(&big, 1000, 1);
		let mut front = front();
		assert_eq!(front.take(pieces[0].clone(), Instant::now()), Taken::Held);
		let mut far = pieces[1].clone();
		far[6..8].copy_from_slice(&(0x2000u16 | 0x1fff).to_be_bytes());
		assert_eq!(front.take(far, Instant::now()), Taken::Unsupported, "a piece past 64 KiB");
		assert!(front.waiting.is_empty(), "the datagram that went over the cap is forgotten");
		let whole = udp(&vec![1u8; 2000]);
		let pieces = cut_v4(&whole, 1000, 2);
		assert_eq!(front.take(pieces[0].clone(), Instant::now()), Taken::Held);
		assert_eq!(front.take(pieces[0].clone(), Instant::now()), Taken::Held, "an exact repeat is ignored");
		let mut overlapping = pieces[0].clone();
		overlapping[6..8].copy_from_slice(&(0x2000u16 | 62).to_be_bytes());
		assert_eq!(front.take(overlapping, Instant::now()), Taken::Unsupported);
		for id in 0..IN_FLIGHT as u16 + 10 {front.take(cut_v4(&whole, 1000, 100 + id).remove(0), Instant::now());}
		assert_eq!(front.waiting.len(), IN_FLIGHT);
		assert_eq!(front.take(cut_v4(&whole, 1000, 9999).remove(0), Instant::now()), Taken::Unsupported);
	}

	#[test]
	fn a_datagram_that_never_completes_is_forgotten() {
		let whole = udp(&vec![1u8; 2000]);
		let mut front = front();
		let start = Instant::now();
		front.take(cut_v4(&whole, 1000, 3).remove(0), start);
		assert_eq!(front.waiting.len(), 1);
		front.take(cut_v4(&whole, 1000, 4).remove(0), start + AGE + Duration::from_secs(1));
		assert_eq!(front.waiting.len(), 1);
		assert!(front.waiting.keys().all(|key| key.2 == 4));
	}

	#[test]
	fn a_reset_and_an_unreachable_error_read_back_as_what_they_are() {
		let (local, remote): (SocketAddr, SocketAddr) = ("198.18.0.2:40000".parse().unwrap(), "93.184.216.34:443".parse().unwrap());
		let raw = reset(local, remote, 1000, 2000).unwrap();
		let found = read(&raw).unwrap();
		assert_eq!((found.src, found.dst, found.protocol), (remote.ip(), local.ip(), 6));
		assert_eq!((u16::from_be_bytes([raw[20], raw[21]]), u16::from_be_bytes([raw[22], raw[23]]), raw[33] & 0x14), (443, 40000, 0x14));
		assert_eq!((u32::from_be_bytes(raw[24..28].try_into().unwrap()), u32::from_be_bytes(raw[28..32].try_into().unwrap())), (1000, 2000));
		let error = unreachable(IpAddr::from(GATEWAY), local, remote, Some(55)).unwrap();
		assert_eq!((error[20], error[21], error.len()), (3, 1, 20 + 8 + 28));
		assert_eq!((&error[40..44], &error[44..48], &error[52..56]), (&DEVICE[..], &[93, 184, 216, 34][..], &[0, 0, 0, 55][..]));
		let udp_error = unreachable(IpAddr::from(GATEWAY), local, remote, None).unwrap();
		assert_eq!((udp_error[20], udp_error[21]), (3, 1));
		assert!(unreachable(IpAddr::from(GATEWAY), local, "[2001:db8::1]:1".parse().unwrap(), None).is_none());
		let v6 = unreachable(IpAddr::from(GATEWAY_V6), SocketAddr::new(IpAddr::from(DEVICE_V6), 4000), "[2001:db8::1]:53".parse().unwrap(), None).unwrap();
		assert_eq!((v6[6], v6[40], v6[41], v6.len()), (58, 1, 3, 40 + 8 + 48));
	}
}
