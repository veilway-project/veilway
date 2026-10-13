//! Packets at the edge of the userspace stack: the header parser every decrypted packet goes through, the answers the node writes itself (TCP reset, echo reply) and the device ipstack reads from.
use crate::config::Protocol;
use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{Receiver, Sender};

/// Extension headers walked before an IPv6 packet counts as unparsable.
const MAX_EXTENSION_HEADERS: usize = 8;
pub const ECHO_REQUEST_V4: u8 = 8;
pub const ECHO_REPLY_V4: u8 = 0;
pub const ECHO_REQUEST_V6: u8 = 128;
pub const ECHO_REPLY_V6: u8 = 129;

/// What routing needs from one IP packet. Ports are zero for anything but TCP, UDP and SCTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
	pub src: IpAddr,
	pub dst: IpAddr,
	/// The upper-layer protocol, after any IPv6 extension headers.
	pub protocol: u8,
	pub sport: u16,
	pub dport: u16,
	/// Type and code of an ICMP or ICMPv6 message.
	pub icmp: Option<(u8, u8)>,
	/// A fragment carries no usable upper-layer header, so the fields above stop at the protocol.
	pub fragment: bool,
	/// Where the upper-layer header starts and where the packet ends. Bytes past the end are padding.
	pub upper: usize,
	pub len: usize,
}

impl Packet {
	pub fn echo_request(&self) -> bool {
		matches!((self.protocol, self.icmp), (Protocol::ICMP, Some((ECHO_REQUEST_V4, 0))) | (Protocol::ICMPV6, Some((ECHO_REQUEST_V6, 0))))
	}
}

/// Reads the IP header and the start of the upper-layer header. None for anything that is not a complete, well formed packet.
pub fn parse(raw: &[u8]) -> Option<Packet> {read(raw, false)}

/// The same for the start of a packet as an ICMP error quotes it. The quote may end anywhere past the ports or the ICMP type and code, and `len` is then where it ends.
pub fn quoted(raw: &[u8]) -> Option<Packet> {read(raw, true)}

fn read(raw: &[u8], cut: bool) -> Option<Packet> {
	let (src, dst, mut protocol, mut upper, len, mut fragment) = match raw.first()? >> 4 {
		4 => {
			let (header, len) = (usize::from(raw[0] & 0x0f) * 4, usize::from(u16::from_be_bytes([*raw.get(2)?, *raw.get(3)?])));
			let len = if cut {len.min(raw.len())} else {len};
			if header < 20 || len < header || raw.len() < len {return None}
			let fragment = u16::from_be_bytes([raw[6], raw[7]]) & 0x3fff != 0;
			(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[12..16]).ok()?)), IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[16..20]).ok()?)), raw[9], header, len, fragment)
		}
		6 => {
			let len = 40 + usize::from(u16::from_be_bytes([*raw.get(4)?, *raw.get(5)?]));
			let len = if cut {len.min(raw.len())} else {len};
			if len < 40 || raw.len() < len {return None}
			(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?)), IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).ok()?)), raw[6], 40, len, false)
		}
		_ => return None,
	};
	if src.is_ipv6() {
		// Hop-by-hop, routing, fragment, authentication, destination options, mobility, host identity and shim6. Anything else is the upper layer.
		for walked in 0.. {
			let size = match protocol {
				44 => {
					fragment = true;
					break;
				}
				0 | 43 | 60 | 135 | 139 | 140 => (usize::from(*raw.get(upper + 1).filter(|_| upper + 2 <= len)?) + 1) * 8,
				51 => (usize::from(*raw.get(upper + 1).filter(|_| upper + 2 <= len)?) + 2) * 4,
				_ => break,
			};
			if walked == MAX_EXTENSION_HEADERS || upper + size > len {return None}
			(protocol, upper) = (raw[upper], upper + size);
		}
	}
	let body = &raw[upper..len];
	let (mut sport, mut dport, mut icmp) = (0, 0, None);
	if !fragment {
		match protocol {
			Protocol::TCP | Protocol::UDP | Protocol::SCTP => {
				if body.len() < if cut {4} else if protocol == Protocol::TCP {20} else if protocol == Protocol::UDP {8} else {12} {return None}
				(sport, dport) = (u16::from_be_bytes([body[0], body[1]]), u16::from_be_bytes([body[2], body[3]]));
			}
			Protocol::ICMP | Protocol::ICMPV6 => {
				if body.len() < if cut {2} else {8} {return None}
				icmp = Some((body[0], body[1]));
			}
			_ => {}
		}
	}
	Some(Packet {src, dst, protocol, sport, dport, icmp, fragment, upper, len})
}

/// The reset that refuses a TCP segment, as the destination would have sent it. None for a reset, so two nodes never answer each other forever.
pub fn tcp_rst(raw: &[u8]) -> Option<Vec<u8>> {
	let parsed = PacketHeaders::from_ip_slice(raw).ok()?;
	let TransportHeader::Tcp(tcp) = parsed.transport? else {return None};
	if tcp.rst {return None}
	let payload = match parsed.payload {
		PayloadSlice::Tcp(payload) => payload.len() as u32,
		_ => 0,
	};
	let mut h = TcpHeader::new(tcp.destination_port, tcp.source_port, 0, 0);
	h.rst = true;
	// RFC 9293 3.10.7.1: a segment with ACK is reset from the sequence number it acknowledges, any other is acknowledged in full.
	if tcp.ack {h.sequence_number = tcp.acknowledgment_number} else {
		h.ack = true;
		h.acknowledgment_number = tcp.sequence_number.wrapping_add(payload).wrapping_add(u32::from(tcp.syn)).wrapping_add(u32::from(tcp.fin));
	}
	let builder = match parsed.net? {
		NetHeaders::Ipv4(ip, _) => PacketBuilder::ipv4(ip.destination, ip.source, 64),
		NetHeaders::Ipv6(ip, _) => PacketBuilder::ipv6(ip.destination, ip.source, 64),
		_ => return None,
	}.tcp_header(h);
	let mut out = Vec::with_capacity(builder.size(0));
	builder.write(&mut out, &[]).ok()?;
	Some(out)
}

/// The answer to a ping, written by the node itself with the addresses swapped.
pub fn echo_reply(raw: &[u8], packet: &Packet) -> Option<Vec<u8>> {
	let body = raw.get(packet.upper..packet.len).filter(|body| body.len() >= 8 && packet.echo_request())?;
	let (id, seq, data) = (u16::from_be_bytes([body[4], body[5]]), u16::from_be_bytes([body[6], body[7]]), &body[8..]);
	let mut out = Vec::with_capacity(packet.len);
	match (packet.src, packet.dst) {
		(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(dst.octets(), src.octets(), 64).icmpv4_echo_reply(id, seq).write(&mut out, data).ok()?,
		(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(dst.octets(), src.octets(), 64).icmpv6_echo_reply(id, seq).write(&mut out, data).ok()?,
		_ => return None,
	}
	Some(out)
}

/// What becomes of a packet somebody else sent when it meets a link of a given MTU.
#[derive(Debug, PartialEq, Eq)]
pub enum Fit {
	Whole,
	/// IPv4 that allows it, cut into fragments that fit.
	Pieces(Vec<Vec<u8>>),
	/// IPv4 that prohibits fragmentation, and every IPv6 packet: it is dropped and its sender is told ("fragmentation needed", "packet too big").
	TooBig,
}

/// What a router does with `raw`, a whole packet, on its way over a link of `mtu` (control channel page, "What the node does with a device's MTU").
pub fn forward(raw: &[u8], mtu: u16) -> Fit {
	if raw.len() <= usize::from(mtu) {return Fit::Whole}
	// Bit 6 of the flags byte is "do not fragment".
	let pieces = if raw[0] >> 4 == 4 && raw.get(6).is_some_and(|flags| flags & 0x40 == 0) {fragments(raw, mtu, None)} else {Vec::new()};
	if pieces.is_empty() {Fit::TooBig} else {Fit::Pieces(pieces)}
}

/// `raw`, a whole packet larger than `mtu`, cut into fragments of at most `mtu` bytes. With `id` the node is the host that sends the packet: the fragments carry that identification, and an IPv6 packet gets fragment headers, which only its source may add.
/// Without it the node forwards an IPv4 packet, whose identification stays as its sender wrote it. The first IPv4 fragment keeps every option, and the others those that say they go into every fragment (RFC 791, 3.1).
/// Empty for what is not cut: a packet that fits, a packet that is a fragment already, an IPv6 packet that is forwarded or that starts with a header that belongs before a fragment header or may, and an `mtu` that leaves no room.
pub fn fragments(raw: &[u8], mtu: u16, id: Option<u32>) -> Vec<Vec<u8>> {
	let (mtu, mut out) = (usize::from(mtu), Vec::new());
	if raw.len() <= mtu {return out}
	match raw[0] >> 4 {
		4 => {
			let header = usize::from(raw[0] & 0x0f) * 4;
			let room = mtu.saturating_sub(header) / 8 * 8;
			if header < 20 || raw.len() <= header || raw.len() > 65535 || room == 0 || u16::from_be_bytes([raw[6], raw[7]]) & 0x3fff != 0 {return out}
			// The header of every fragment but the first: an option is kept when the top bit of its type says "copied", and the rest is padded to whole words.
			let (mut later, mut at) = (raw[..20].to_vec(), 20);
			while at < header && raw[at] != 0 {
				let size = if raw[at] == 1 {1} else {usize::from(raw.get(at + 1).copied().unwrap_or(0))};
				if size == 0 || (raw[at] != 1 && size < 2) || at + size > header {break}
				if raw[at] & 0x80 != 0 {later.extend_from_slice(&raw[at..at + size])}
				at += size;
			}
			later.resize(later.len().div_ceil(4) * 4, 0);
			later[0] = 0x40 | (later.len() / 4) as u8;
			let count = (raw.len() - header).div_ceil(room);
			for (at, part) in raw[header..].chunks(room).enumerate() {
				let head = if at == 0 {&raw[..header]} else {&later[..]};
				let mut piece = [head, part].concat();
				piece[2..4].copy_from_slice(&((head.len() + part.len()) as u16).to_be_bytes());
				if let Some(id) = id {piece[4..6].copy_from_slice(&(id as u16).to_be_bytes())}
				// The offset counts in units of 8 bytes, and bit 13 says more fragments follow.
				piece[6..8].copy_from_slice(&(((at * room / 8) as u16) | if at + 1 < count {0x2000} else {0}).to_be_bytes());
				piece[10..12].copy_from_slice(&[0, 0]);
				let mut sum = piece[..head.len()].chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]]))).sum::<u32>();
				while sum >> 16 != 0 {sum = (sum & 0xffff) + (sum >> 16)}
				piece[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
				out.push(piece);
			}
		}
		6 => {
			let (Some(id), room) = (id, mtu.saturating_sub(48) / 8 * 8) else {return out};
			// Hop-by-hop options and a routing header belong before the fragment header, and destination options may stand before a routing header. The node writes none of the three, so a packet that starts with one is left alone.
			if raw.len() <= 40 || room == 0 || matches!(raw[6], 0 | 43 | 44 | 60) {return out}
			let count = (raw.len() - 40).div_ceil(room);
			for (at, part) in raw[40..].chunks(room).enumerate() {
				let mut piece = [&raw[..40], &[raw[6], 0][..], &(((at * room) as u16) | u16::from(at + 1 < count)).to_be_bytes(), &id.to_be_bytes(), part].concat();
				piece[4..6].copy_from_slice(&((8 + part.len()) as u16).to_be_bytes());
				piece[6] = 44;
				out.push(piece);
			}
		}
		_ => {}
	}
	out
}

/// Packet-boundary preserving device for ipstack: one read yields exactly one IP packet and one write consumes exactly one. `tokio::io::duplex` cannot do this, it coalesces writes into a stream.
pub struct PacketDev {rx: Receiver<Vec<u8>>, tx: Sender<Vec<u8>>}

impl PacketDev {
	pub fn new(rx: Receiver<Vec<u8>>, tx: Sender<Vec<u8>>) -> PacketDev {PacketDev {rx, tx}}
}

impl AsyncRead for PacketDev {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		loop {
			match self.rx.poll_recv(cx) {
				Poll::Ready(Some(p)) => {
					if p.len() <= buf.remaining() {
						buf.put_slice(&p);
						return Poll::Ready(Ok(()));
					}
					tracing::debug!("dropping {} byte packet, over mtu", p.len());
				}
				// Closed channel parks the stack instead of spinning on a zero-length read.
				_ => return Poll::Pending,
			}
		}
	}
}

impl AsyncWrite for PacketDev {
	fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		if self.tx.try_send(buf.to_vec()).is_err() {tracing::debug!("tunnel queue full, dropping {} byte packet", buf.len())}
		Poll::Ready(Ok(buf.len()))
	}
	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {Poll::Ready(Ok(()))}
	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {Poll::Ready(Ok(()))}
}

#[cfg(test)]
mod tests {
	use super::*;
	use etherparse::{IpNumber, Ipv6Header};

	fn v4(protocol: IpNumber, flags: [u8; 2], body: &[u8]) -> Vec<u8> {
		let mut raw = vec![0x45, 0, 0, 0, 0, 0, flags[0], flags[1], 64, protocol.0, 0, 0, 10, 7, 0, 2, 1, 1, 1, 1];
		raw.extend_from_slice(body);
		let len = (raw.len() as u16).to_be_bytes();
		raw[2..4].copy_from_slice(&len);
		raw
	}

	fn v6(next: u8, body: &[u8]) -> Vec<u8> {
		let header = Ipv6Header {payload_length: body.len() as u16, next_header: IpNumber(next), hop_limit: 64, source: [0xfd; 16], destination: [0x20; 16], ..Default::default()};
		let mut raw = Vec::new();
		header.write(&mut raw).unwrap();
		raw.extend_from_slice(body);
		raw
	}

	#[test]
	fn ports_and_protocol_are_read() {
		let mut raw = Vec::new();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).udp(40000, 53).write(&mut raw, b"query").unwrap();
		let p = parse(&raw).unwrap();
		assert_eq!((p.src, p.dst, p.protocol, p.sport, p.dport, p.fragment, p.len), ("10.7.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap(), 17, 40000, 53, false, raw.len()));
		raw.extend_from_slice(&[0; 7]);
		assert_eq!(parse(&raw).unwrap().len, raw.len() - 7, "padding after the packet was counted as part of it");
		let mut six = Vec::new();
		PacketBuilder::ipv6([0xfd; 16], [0x20; 16], 64).tcp(40000, 443, 1, 65535).write(&mut six, &[]).unwrap();
		let p = parse(&six).unwrap();
		assert_eq!((p.protocol, p.sport, p.dport, p.upper), (6, 40000, 443, 40));
	}

	#[test]
	fn extension_headers_are_walked() {
		let udp = [0x9c, 0x40, 0, 53, 0, 8, 0, 0];
		let mut body = vec![60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0];
		body.extend_from_slice(&udp);
		let p = parse(&v6(0, &body)).unwrap();
		assert_eq!((p.protocol, p.dport, p.upper), (17, 53, 56));
		// An authentication header counts its length in 4 byte words past the first two.
		let mut auth = vec![17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		auth.extend_from_slice(&udp);
		assert_eq!(parse(&v6(51, &auth)).unwrap().dport, 53);
		assert!(parse(&v6(0, &[60, 9, 0, 0, 0, 0, 0, 0])).is_none(), "an extension header longer than the packet was accepted");
		let chain: Vec<u8> = (0..MAX_EXTENSION_HEADERS + 1).flat_map(|_| [60, 0, 0, 0, 0, 0, 0, 0]).collect();
		assert!(parse(&v6(60, &chain)).is_none(), "an endless chain of extension headers was walked");
		assert_eq!(parse(&v6(59, &[])).unwrap().protocol, 59);
	}

	#[test]
	fn fragments_are_flagged() {
		let udp = [0x9c, 0x40, 0, 53, 0, 8, 0, 0];
		assert!(parse(&v4(IpNumber::UDP, [0x20, 0], &udp)).unwrap().fragment, "more fragments");
		assert!(parse(&v4(IpNumber::UDP, [0, 9], &[1, 2, 3])).unwrap().fragment, "a later fragment");
		assert!(!parse(&v4(IpNumber::UDP, [0x40, 0], &udp)).unwrap().fragment, "don't fragment is not a fragment");
		assert!(parse(&v6(44, &[17, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3])).unwrap().fragment);
	}

	#[test]
	fn broken_packets_are_refused() {
		let udp = [0x9c, 0x40, 0, 53, 0, 8, 0, 0];
		let whole = v4(IpNumber::UDP, [0, 0], &udp);
		for cut in 0..whole.len() {assert!(parse(&whole[..cut]).is_none(), "a packet cut to {cut} bytes was accepted")}
		let mut short_header = whole.clone();
		short_header[0] = 0x44;
		assert!(parse(&short_header).is_none());
		let mut long_header = whole.clone();
		long_header[0] = 0x4f;
		assert!(parse(&long_header).is_none());
		assert!(parse(&v4(IpNumber::TCP, [0, 0], &udp)).is_none(), "a tcp header of 8 bytes was accepted");
		assert!(parse(&v4(IpNumber::ICMP, [0, 0], &[8, 0, 0])).is_none());
		assert!(parse(&v6(17, &udp[..7])).is_none());
		assert!(parse(&[0x70; 60]).is_none());
		assert!(parse(&[]).is_none());
	}

	#[test]
	fn a_quoted_packet_is_read_as_far_as_it_goes() {
		let mut whole = Vec::new();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).tcp(40000, 443, 1, 65535).write(&mut whole, &[0; 100]).unwrap();
		// The least an ICMP error quotes is the IP header and 8 bytes, which is less than a TCP header.
		assert!(parse(&whole[..28]).is_none());
		let p = quoted(&whole[..28]).unwrap();
		assert_eq!((p.src, p.dst, p.protocol, p.sport, p.dport, p.upper, p.len), ("10.7.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap(), 6, 40000, 443, 20, 28));
		assert_eq!(quoted(&whole).unwrap().len, whole.len());
		for cut in 0..24 {assert!(quoted(&whole[..cut]).is_none(), "a quote cut to {cut} bytes was accepted")}
		let mut six = Vec::new();
		PacketBuilder::ipv6([0xfd; 16], [0x20; 16], 64).icmpv6_echo_request(7, 9).write(&mut six, b"payload").unwrap();
		assert_eq!(quoted(&six[..42]).unwrap().icmp, Some((ECHO_REQUEST_V6, 0)));
		assert!(quoted(&six[..41]).is_none() && quoted(&six[..39]).is_none());
		assert!(quoted(&[0x70; 60]).is_none() && quoted(&[]).is_none());
	}

	// What a receiver makes of fragments: the payload put together by offset, with the header of the first.
	fn reassembled(pieces: &[Vec<u8>]) -> Vec<u8> {
		let v6 = pieces[0][0] >> 4 == 6;
		let (header, mut parts): (usize, Vec<(usize, &[u8])>) = if v6 {(40, pieces.iter().map(|piece| (usize::from(u16::from_be_bytes([piece[42], piece[43]]) & 0xfff8), &piece[48..])).collect())} else {(20, pieces.iter().map(|piece| (usize::from(u16::from_be_bytes([piece[6], piece[7]]) & 0x1fff) * 8, &piece[20..])).collect())};
		parts.sort();
		assert!(parts.iter().scan(0, |end, (offset, part)| Some(std::mem::replace(end, offset + part.len()) == *offset)).all(|joined| joined), "the fragments leave a gap or overlap");
		[&pieces[0][..header], &parts.iter().flat_map(|(_, part)| part.iter().copied()).collect::<Vec<u8>>()].concat()
	}

	#[test]
	fn a_packet_the_node_sends_is_fragmented_to_fit_and_reads_back_whole() {
		for (size, mtu) in [(1385, 1280), (1400, 1300), (4000, 1280), (1281, 1280), (65000, 1500)] {
			let (mut four, mut six, payload) = (Vec::new(), Vec::new(), (0..size).map(|at| at as u8).collect::<Vec<u8>>());
			PacketBuilder::ipv4([93, 184, 216, 34], [10, 7, 0, 2], 64).udp(9000, 40000).write(&mut four, &payload).unwrap();
			PacketBuilder::ipv6([0x20; 16], [0xfd; 16], 64).udp(9000, 40000).write(&mut six, &payload).unwrap();
			let pieces = fragments(&four, mtu, Some(0x1234_5678));
			assert!(pieces.len() == (four.len() - 20).div_ceil(usize::from((mtu - 20) / 8 * 8)) && pieces.iter().all(|piece| piece.len() <= usize::from(mtu)), "{size} over {mtu}");
			for (at, piece) in pieces.iter().enumerate() {
				// Every fragment is a packet of its own length under the same identification, with a header that sums to zero, and all but the last say that more follow.
				let sum = piece[..20].chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]]))).sum::<u32>();
				assert_eq!((usize::from(u16::from_be_bytes([piece[2], piece[3]])), &piece[4..6], piece[6] & 0x20 != 0, piece[6] & 0x40, (sum & 0xffff) + (sum >> 16)), (piece.len(), &[0x56, 0x78][..], at + 1 < pieces.len(), 0, 0xffff));
				assert!(parse(piece).is_some_and(|parsed| parsed.fragment));
			}
			let mut whole = reassembled(&pieces);
			// But for what fragmenting writes into the header, it is the packet that was cut.
			for at in [4, 5, 6, 7, 10, 11] {(whole[at], four[at]) = (0, 0)}
			whole[2..4].copy_from_slice(&(four.len() as u16).to_be_bytes());
			assert_eq!(whole, four);
			let pieces = fragments(&six, mtu, Some(0x1234_5678));
			assert!(pieces.len() == (six.len() - 40).div_ceil(usize::from((mtu - 48) / 8 * 8)) && pieces.iter().all(|piece| piece.len() <= usize::from(mtu)));
			for (at, piece) in pieces.iter().enumerate() {
				assert_eq!((usize::from(u16::from_be_bytes([piece[4], piece[5]])) + 40, piece[6], piece[40], piece[43] & 1 != 0, &piece[44..48]), (piece.len(), 44, 17, at + 1 < pieces.len(), &[0x12, 0x34, 0x56, 0x78][..]));
				assert!(parse(piece).is_some_and(|parsed| parsed.fragment));
			}
			let mut whole = reassembled(&pieces);
			whole[4..6].copy_from_slice(&((six.len() - 40) as u16).to_be_bytes());
			whole[6] = 17;
			assert_eq!(whole, six);
		}
	}

	#[test]
	fn a_packet_the_node_forwards_is_fragmented_only_where_its_sender_allowed_it() {
		let (mut four, mut six) = (Vec::new(), Vec::new());
		PacketBuilder::ipv4([93, 184, 216, 34], [10, 7, 0, 2], 64).udp(9000, 40000).write(&mut four, &[7; 1400]).unwrap();
		PacketBuilder::ipv6([0x20; 16], [0xfd; 16], 64).udp(9000, 40000).write(&mut six, &[7; 1400]).unwrap();
		four[4..6].copy_from_slice(&[0xab, 0xcd]);
		assert_eq!((forward(&four, 1428), forward(&six, 1448)), (Fit::Whole, Fit::Whole));
		// IPv4 that prohibits fragmentation, and every IPv6 packet: the sender hears of it.
		four[6] |= 0x40;
		assert_eq!((forward(&four, 1280), forward(&six, 1280)), (Fit::TooBig, Fit::TooBig));
		// IPv4 that allows it keeps the identification its sender gave it.
		four[6] &= !0x40;
		let Fit::Pieces(pieces) = forward(&four, 1280) else {panic!("not fragmented")};
		assert!(pieces.len() == 2 && pieces.iter().all(|piece| piece.len() <= 1280 && piece[4..6] == [0xab, 0xcd]) && reassembled(&pieces)[20..] == four[20..]);
		// A fragment is never cut again by the node, an IPv6 packet is never cut by anyone but its sender, and neither is one that starts with a header every hop reads.
		four[6] |= 0x20;
		assert_eq!(forward(&four, 1280), Fit::TooBig);
		assert!(fragments(&six, 1280, None).is_empty() && fragments(&six, 40, Some(1)).is_empty() && fragments(&four[..20], 1280, Some(1)).is_empty() && fragments(&[], 1280, Some(1)).is_empty());
		for first in [0, 43, 44, 60] {
			six[6] = first;
			assert!(fragments(&six, 1280, Some(1)).is_empty(), "an ipv6 packet that starts with header {first} was cut");
		}
		// A packet that fits is not cut, whoever asks: one piece that is no fragment would be a packet with another identification and nothing else.
		four[6] = 0;
		assert!(fragments(&four, 1428, Some(1)).is_empty() && fragments(&four, 1500, None).is_empty());
		// Options: the first fragment keeps all of them, the others only those marked as copied. Here a record route (7, not copied), a no-operation and a strict source route (137, copied).
		let mut with = vec![0x49, 0, 0, 0, 0xab, 0xcd, 0, 0, 64, 17, 0, 0, 93, 184, 216, 34, 10, 7, 0, 2, 7, 7, 4, 0, 0, 0, 0, 1, 137, 7, 4, 1, 2, 3, 4, 0];
		with.extend((0..2000).map(|at| at as u8));
		let total = with.len() as u16;
		with[2..4].copy_from_slice(&total.to_be_bytes());
		let pieces = fragments(&with, 1280, None);
		assert_eq!(pieces.iter().map(|piece| (piece[0], piece.len())).collect::<Vec<_>>(), [(0x49, 1276), (0x47, 28 + 2000 - 1240)]);
		assert_eq!((&pieces[1][20..28], [&pieces[0][36..], &pieces[1][28..]].concat() == with[36..]), (&[137, 7, 4, 1, 2, 3, 4, 0][..], true));
		assert!(pieces.iter().all(|piece| parse(piece).is_some_and(|parsed| parsed.fragment && parsed.len == piece.len())));
	}

	#[test]
	fn rst_mirrors_the_syn() {
		let mut syn = TcpHeader::new(40000, 80, 12345, 65535);
		syn.syn = true;
		let builder = PacketBuilder::ipv4([10, 7, 0, 2], [10, 7, 0, 3], 64).tcp_header(syn.clone());
		let mut packet = Vec::new();
		builder.write(&mut packet, &[]).unwrap();
		let rst = tcp_rst(&packet).unwrap();
		let parsed = PacketHeaders::from_ip_slice(&rst).unwrap();
		let NetHeaders::Ipv4(ip, _) = parsed.net.unwrap() else {panic!("not ipv4")};
		let TransportHeader::Tcp(tcp) = parsed.transport.unwrap() else {panic!("not tcp")};
		assert_eq!((ip.source, ip.destination), ([10, 7, 0, 3], [10, 7, 0, 2]));
		assert_eq!((tcp.source_port, tcp.destination_port), (80, 40000));
		assert!(tcp.rst && tcp.ack && !tcp.syn);
		assert_eq!(tcp.acknowledgment_number, 12346);
		assert!(tcp_rst(&rst).is_none(), "never answer an RST with an RST");
		let mut six = Vec::new();
		PacketBuilder::ipv6([0xfd; 16], [0x20; 16], 64).tcp_header(syn).write(&mut six, &[]).unwrap();
		let rst = tcp_rst(&six).unwrap();
		let NetHeaders::Ipv6(ip, _) = PacketHeaders::from_ip_slice(&rst).unwrap().net.unwrap() else {panic!("not ipv6")};
		assert_eq!((ip.source, ip.destination), ([0x20; 16], [0xfd; 16]));
	}

	#[test]
	fn rst_for_an_established_segment_uses_its_ack() {
		let mut data = TcpHeader::new(40000, 80, 500, 65535);
		data.ack = true;
		data.acknowledgment_number = 9000;
		let mut packet = Vec::new();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).tcp_header(data).write(&mut packet, b"abc").unwrap();
		let TransportHeader::Tcp(tcp) = PacketHeaders::from_ip_slice(&tcp_rst(&packet).unwrap()).unwrap().transport.unwrap() else {panic!("not tcp")};
		assert!(tcp.rst && !tcp.ack);
		assert_eq!(tcp.sequence_number, 9000);
	}

	#[test]
	fn echo_is_answered_from_the_destination() {
		let mut ping = Vec::new();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).icmpv4_echo_request(7, 9).write(&mut ping, b"payload").unwrap();
		let parsed = parse(&ping).unwrap();
		assert!(parsed.echo_request());
		let reply = echo_reply(&ping, &parsed).unwrap();
		let back = parse(&reply).unwrap();
		assert_eq!((back.src, back.dst, back.icmp), (parsed.dst, parsed.src, Some((0, 0))));
		assert_eq!(&reply[back.upper + 4..], &ping[parsed.upper + 4..], "identifier, sequence or payload changed");
		assert!(echo_reply(&reply, &back).is_none(), "a reply was answered");
		let mut six = Vec::new();
		PacketBuilder::ipv6([0xfd; 16], [0x20; 16], 64).icmpv6_echo_request(7, 9).write(&mut six, b"payload").unwrap();
		let parsed = parse(&six).unwrap();
		let back = parse(&echo_reply(&six, &parsed).unwrap()).unwrap();
		assert_eq!((back.src, back.dst, back.icmp), (parsed.dst, parsed.src, Some((129, 0))));
	}
}
