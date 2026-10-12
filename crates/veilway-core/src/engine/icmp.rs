//! ICMP the node writes or sends itself: the errors that answer traffic it turns away, how many of them one device is sent, and pings that leave from the node's own address.
use super::netstack::{Packet, ECHO_REPLY_V4, ECHO_REPLY_V6};
use super::plan::{Holder, Plan};
use super::Shared;
use crate::config::Protocol;
use etherparse::{icmpv4, icmpv6, Icmpv4Type, Icmpv6Type, PacketBuilder};
use ipnet::IpNet;
use socket2::{Domain, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Receiver;

/// How much of the offending packet an error quotes. RFC 1812 4.3.2.3 keeps an ICMP error within 576 bytes and RFC 4443 2.4 keeps an ICMPv6 error within the minimum IPv6 MTU, headers included.
pub const QUOTE_V4: usize = 576 - 20 - 8;
pub const QUOTE_V6: usize = 1280 - 40 - 8;
/// ICMP errors one device is sent at once, and how many more it earns each second.
pub const BURST: u32 = 20;
pub const PER_SECOND: u32 = 10;
/// ICMP messages that ask something: echo and its reply, router advertisement and solicitation, timestamp, information and address mask. Every other type is treated as an error.
const QUERIES_V4: [u8; 10] = [0, 8, 9, 10, 13, 14, 15, 16, 17, 18];
const REDIRECT_V6: u8 = 137;
/// Pings in flight from the node's own address: in total, for one user across all their devices, and for one device. As in the flow table, the device share alone would let one user with many devices take them all.
pub const MAX_PINGS: usize = 1024;
pub const MAX_PINGS_PER_USER: usize = 32;
pub const MAX_PINGS_PER_DEVICE: usize = 16;
/// Echo requests of one ping that wait for its socket.
pub const PING_QUEUE: usize = 16;
const PING_IDLE: Duration = Duration::from_secs(10);

/// What an error tells the sender of the packet it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
	/// A tunnel address no connected device holds.
	Host,
	/// An IP protocol the exit does not carry. ICMPv6 has no code for that and says "prohibited".
	Protocol,
	/// UDP the exit cannot relay.
	Port,
	/// A rule, the destination gate, the user's `exits` or a `reject` policy turned it away.
	Prohibited,
	/// Larger than what comes next takes: "fragmentation needed" with that MTU, or "packet too big".
	TooBig(u16),
}

/// The ICMP or ICMPv6 error that answers `raw`, sent from `from` to the packet's source.
/// None where RFC 1122 3.2.2 and RFC 4443 2.4 say never to answer: an ICMP error or redirect, a fragment other than the first, a packet to a multicast or broadcast address, and a source that does not name one host.
pub fn error(raw: &[u8], packet: &Packet, kind: Kind, from: IpAddr, pools: &[(IpNet, usize)]) -> Option<Vec<u8>> {
	let raw = raw.get(..packet.len)?;
	// The header of an IPv6 fragment sits where the upper layer would start, with the protocol it carries in its first byte.
	let (protocol, at, offset) = match packet.src {
		IpAddr::V4(_) => (packet.protocol, packet.upper, u16::from_be_bytes([*raw.get(6)?, *raw.get(7)?]) & 0x1fff),
		IpAddr::V6(_) if packet.fragment => (*raw.get(packet.upper)?, packet.upper + 8, u16::from_be_bytes([*raw.get(packet.upper + 2)?, *raw.get(packet.upper + 3)?]) >> 3),
		IpAddr::V6(_) => (packet.protocol, packet.upper, 0),
	};
	if offset != 0 {return None}
	// Only what is known to ask something is answered: an ICMP message whose type cannot be read counts as an error.
	match protocol {
		Protocol::ICMP if !raw.get(at).is_some_and(|kind| QUERIES_V4.contains(kind)) => return None,
		Protocol::ICMPV6 if !raw.get(at).is_some_and(|kind| *kind >= 128 && *kind != REDIRECT_V6) => return None,
		_ => {}
	}
	let many = |ip: IpAddr| ip.is_multicast() || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast() || pools.iter().any(|(pool, _)| pool.prefix_len() < 31 && pool.broadcast() == ip));
	if many(packet.dst) || many(packet.src) || packet.src.is_unspecified() || packet.src.is_loopback() {return None}
	let mut out = Vec::with_capacity(raw.len().min(QUOTE_V6) + 48);
	match (from, packet.src) {
		(IpAddr::V4(from), IpAddr::V4(to)) => {
			let header = match kind {
				Kind::Host => icmpv4::DestUnreachableHeader::Host,
				Kind::Protocol => icmpv4::DestUnreachableHeader::Protocol,
				Kind::Port => icmpv4::DestUnreachableHeader::Port,
				Kind::Prohibited => icmpv4::DestUnreachableHeader::FilterProhibited,
				Kind::TooBig(mtu) => icmpv4::DestUnreachableHeader::FragmentationNeeded {next_hop_mtu: mtu},
			};
			PacketBuilder::ipv4(from.octets(), to.octets(), 64).icmpv4(Icmpv4Type::DestinationUnreachable(header)).write(&mut out, &raw[..raw.len().min(QUOTE_V4)]).ok()?
		}
		(IpAddr::V6(from), IpAddr::V6(to)) => {
			let message = match kind {
				Kind::Host => Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Address),
				Kind::Port => Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Port),
				Kind::Protocol | Kind::Prohibited => Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Prohibited),
				Kind::TooBig(mtu) => Icmpv6Type::PacketTooBig {mtu: u32::from(mtu)},
			};
			PacketBuilder::ipv6(from.octets(), to.octets(), 64).icmpv6(message).write(&mut out, &raw[..raw.len().min(QUOTE_V6)]).ok()?
		}
		_ => return None,
	}
	Some(out)
}

/// The share of ICMP errors one device is sent: `BURST` at once, then `PER_SECOND` a second. Without it a device could make the node write an error for every packet it throws at a closed door.
pub struct Limit {left: u32, since: Instant}

impl Limit {
	pub fn new(now: Instant) -> Limit {Limit {left: BURST, since: now}}

	/// Whether one more error may be sent at `now`.
	pub fn take(&mut self, now: Instant) -> bool {
		let earned = (now.saturating_duration_since(self.since).as_millis().saturating_mul(u128::from(PER_SECOND)) / 1000).min(u128::from(BURST)) as u32;
		if earned > 0 {(self.left, self.since) = ((self.left + earned).min(BURST), now)}
		if self.left == 0 {return false}
		self.left -= 1;
		true
	}
}

/// A ping socket: the kernel writes the echo request under an identifier of its own and hands back only the replies to it. It takes no privilege and is never a raw socket.
pub fn ping_socket(v4: bool) -> io::Result<Socket> {
	if v4 {Socket::new(Domain::IPV4, Type::DGRAM, Some(socket2::Protocol::ICMPV4))} else {Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::ICMPV6))}
}

/// One ping of a device to `dst` under the identifier `ident`, sent from the node's own address: every echo request that comes in on `requests` goes out through a ping socket, and each reply goes back to the device as an echo reply from `dst` under the identifier the device chose. Ends when the ping has been quiet for `PING_IDLE`.
pub async fn ping(shared: Arc<Shared>, plan: Arc<Plan>, exit: usize, to: Holder, id: (IpAddr, IpAddr, u16), mut requests: Receiver<Vec<u8>>) {
	let (src, dst, ident) = id;
	let relay = async {
		let socket = ping_socket(dst.is_ipv4()).and_then(|socket| {
			socket.set_nonblocking(true)?;
			socket.connect(&SocketAddr::new(dst, 0).into())?;
			UdpSocket::from_std(socket.into())
		});
		let socket = match socket {
			Ok(socket) => socket,
			Err(e) => return tracing::debug!("exit {}: ping to {}: no ping socket: {}", plan.exits[exit].tag, plan.show(dst), e.kind()),
		};
		let mut reply = vec![0u8; 65535];
		loop {
			tokio::select! {
				request = requests.recv() => {
					let Some(request) = request else {return};
					if let Err(e) = socket.send(&request).await {tracing::debug!("exit {}: ping to {}: send: {}", plan.exits[exit].tag, plan.show(dst), e.kind())}
				}
				received = socket.recv(&mut reply) => {
					// An error here is an ICMP error for an earlier request. The ping outlives it.
					let Ok(n) = received else {continue};
					// Some systems hand back the IPv4 header in front of the message.
					let message = if dst.is_ipv4() && reply[0] >> 4 == 4 {reply[..n].get(usize::from(reply[0] & 0x0f) * 4..)} else {Some(&reply[..n])};
					let Some(message) = message.filter(|message| message.len() >= 8 && message[0] == if dst.is_ipv4() {ECHO_REPLY_V4} else {ECHO_REPLY_V6}) else {continue};
					let (seq, mut out) = (u16::from_be_bytes([message[6], message[7]]), Vec::with_capacity(message.len() + 40));
					let built = match (dst, src) {
						(IpAddr::V4(dst), IpAddr::V4(src)) => PacketBuilder::ipv4(dst.octets(), src.octets(), 64).icmpv4_echo_reply(ident, seq).write(&mut out, &message[8..]),
						(IpAddr::V6(dst), IpAddr::V6(src)) => PacketBuilder::ipv6(dst.octets(), src.octets(), 64).icmpv6_echo_reply(ident, seq).write(&mut out, &message[8..]),
						_ => return,
					};
					if built.is_err() || out.len() > usize::from(plan.inbounds[to.inbound].mtu) {continue}
					shared.counters.exits[exit].down(out.len());
					shared.send(&plan, to, &out).await;
				}
				_ = tokio::time::sleep(PING_IDLE) => return,
			}
		}
	};
	relay.await;
	shared.pings.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::netstack::parse;
	use etherparse::{IpNumber, Ipv6Header, TcpHeader};

	const GATEWAY_V4: [u8; 4] = [10, 7, 0, 1];
	const GATEWAY_V6: [u8; 16] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
	const DEVICE_V6: [u8; 16] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

	fn pools() -> Vec<(IpNet, usize)> {vec![("10.7.0.1/24".parse().unwrap(), 0), ("fd7a:115c:a1e0::1/64".parse().unwrap(), 0)]}

	fn answer(raw: &[u8], kind: Kind) -> Option<Vec<u8>> {
		let packet = parse(raw)?;
		error(raw, &packet, kind, if packet.src.is_ipv4() {GATEWAY_V4.into()} else {GATEWAY_V6.into()}, &pools())
	}

	fn udp_v4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
		let mut raw = Vec::new();
		PacketBuilder::ipv4(src, dst, 64).udp(40000, 9999).write(&mut raw, payload).unwrap();
		raw
	}

	fn udp_v6(dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
		let mut raw = Vec::new();
		PacketBuilder::ipv6(DEVICE_V6, dst, 64).udp(40000, 9999).write(&mut raw, payload).unwrap();
		raw
	}

	/// The internet checksum of RFC 1071 over `parts`. It is zero over a message that carries its own correct checksum.
	fn checksum(parts: &[&[u8]]) -> u16 {
		let mut sum = 0u32;
		for part in parts {
			for pair in part.chunks(2) {sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))}
		}
		while sum >> 16 != 0 {sum = (sum & 0xffff) + (sum >> 16)}
		!(sum as u16)
	}

	#[test]
	fn an_ipv4_error_quotes_the_packet_and_carries_good_checksums() {
		let raw = udp_v4([10, 7, 0, 2], [1, 1, 1, 1], b"ping");
		for (kind, code, rest) in [(Kind::Host, 1, [0u8; 4]), (Kind::Protocol, 2, [0; 4]), (Kind::Port, 3, [0; 4]), (Kind::Prohibited, 13, [0; 4]), (Kind::TooBig(1280), 4, [0, 0, 5, 0])] {
			let out = answer(&raw, kind).unwrap();
			let back = parse(&out).unwrap();
			assert_eq!((back.src, back.dst, back.protocol, back.icmp), (IpAddr::from(GATEWAY_V4), IpAddr::from([10, 7, 0, 2]), Protocol::ICMP, Some((3, code))), "{kind:?}");
			assert_eq!(out[24..28], rest, "{kind:?}");
			assert_eq!(&out[28..], &raw[..], "{kind:?}: the offending packet is not quoted whole");
			assert_eq!((checksum(&[&out[..20]]), checksum(&[&out[20..]])), (0, 0), "{kind:?}");
		}
	}

	#[test]
	fn an_ipv6_error_quotes_the_packet_and_carries_a_good_checksum() {
		let raw = udp_v6([0x20; 16], b"ping");
		for (kind, message, rest) in [(Kind::Host, (1, 3), [0u8; 4]), (Kind::Protocol, (1, 1), [0; 4]), (Kind::Port, (1, 4), [0; 4]), (Kind::Prohibited, (1, 1), [0; 4]), (Kind::TooBig(1280), (2, 0), [0, 0, 5, 0])] {
			let out = answer(&raw, kind).unwrap();
			let back = parse(&out).unwrap();
			assert_eq!((back.src, back.dst, back.protocol, back.icmp), (IpAddr::from(GATEWAY_V6), IpAddr::from(DEVICE_V6), Protocol::ICMPV6, Some(message)), "{kind:?}");
			assert_eq!(out[44..48], rest, "{kind:?}");
			assert_eq!(&out[48..], &raw[..], "{kind:?}: the offending packet is not quoted whole");
			// The pseudo header: both addresses, the length of the message and the next header.
			let length = ((out.len() - 40) as u32).to_be_bytes();
			assert_eq!(checksum(&[&out[8..40], &length, &[0, 0, 0, 58], &out[40..]]), 0, "{kind:?}");
		}
	}

	#[test]
	fn the_quote_stops_where_the_rfcs_say() {
		let out = answer(&udp_v4([10, 7, 0, 2], [1, 1, 1, 1], &[7; 1300]), Kind::Port).unwrap();
		assert_eq!(out.len(), 576);
		assert_eq!(checksum(&[&out[20..]]), 0);
		let raw = udp_v6([0x20; 16], &[7; 1300]);
		let out = answer(&raw, Kind::Port).unwrap();
		assert_eq!(out.len(), 1280);
		assert_eq!(&out[48..], &raw[..QUOTE_V6]);
		// Padding after the packet is not part of it.
		let mut padded = udp_v4([10, 7, 0, 2], [1, 1, 1, 1], b"ping");
		let len = padded.len();
		padded.extend_from_slice(&[0; 9]);
		assert_eq!(answer(&padded, Kind::Port).unwrap().len(), 28 + len);
	}

	#[test]
	fn an_icmp_error_is_never_answered() {
		let icmp = |kind: u8, code: u8| {
			let mut raw = Vec::new();
			PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).icmpv4_raw(kind, code, [0; 4]).write(&mut raw, &[0; 28]).unwrap();
			raw
		};
		for kind in [3, 4, 5, 11, 12, 40, 255] {assert!(answer(&icmp(kind, 0), Kind::Prohibited).is_none(), "icmp type {kind} was answered")}
		for kind in [0, 8, 13, 17] {assert!(answer(&icmp(kind, 0), Kind::Prohibited).is_some(), "icmp type {kind} was not answered")}
		let six = |kind: u8| {
			let mut raw = Vec::new();
			PacketBuilder::ipv6(DEVICE_V6, [0x20; 16], 64).icmpv6_raw(kind, 0, [0; 4]).write(&mut raw, &[0; 48]).unwrap();
			raw
		};
		for kind in [1, 2, 3, 4, 100, 127, 137] {assert!(answer(&six(kind), Kind::Prohibited).is_none(), "icmpv6 type {kind} was answered")}
		for kind in [128, 129, 135] {assert!(answer(&six(kind), Kind::Prohibited).is_some(), "icmpv6 type {kind} was not answered")}
		// What the node writes is itself an error, so two nodes never answer each other forever.
		let out = answer(&udp_v4([10, 7, 0, 2], [1, 1, 1, 1], b"ping"), Kind::Port).unwrap();
		assert!(error(&out, &parse(&out).unwrap(), Kind::Port, [1, 1, 1, 1].into(), &pools()).is_none());
		let out = answer(&udp_v6([0x20; 16], b"ping"), Kind::TooBig(1280)).unwrap();
		assert!(error(&out, &parse(&out).unwrap(), Kind::Port, [0x20; 16].into(), &pools()).is_none());
	}

	#[test]
	fn only_the_first_fragment_is_answered() {
		let fragment = |flags: [u8; 2], protocol: IpNumber, body: &[u8]| {
			let mut raw = vec![0x45, 0, 0, 0, 0, 0, flags[0], flags[1], 64, protocol.0, 0, 0, 10, 7, 0, 2, 1, 1, 1, 1];
			raw.extend_from_slice(body);
			let len = (raw.len() as u16).to_be_bytes();
			raw[2..4].copy_from_slice(&len);
			raw
		};
		let udp = [0x9c, 0x40, 0x27, 0x0f, 0, 16, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
		assert!(answer(&fragment([0x20, 0], IpNumber::UDP, &udp), Kind::Port).is_some(), "a first fragment was not answered");
		assert!(answer(&fragment([0x20, 1], IpNumber::UDP, &udp), Kind::Port).is_none(), "a middle fragment was answered");
		assert!(answer(&fragment([0, 9], IpNumber::UDP, &udp), Kind::Port).is_none(), "a last fragment was answered");
		// A first fragment that carries an ICMP error is an ICMP error.
		assert!(answer(&fragment([0x20, 0], IpNumber::ICMP, &[3, 1, 0, 0, 0, 0, 0, 0]), Kind::Port).is_none());
		let six = |offset: u16, next: u8, body: &[u8]| {
			let mut payload = vec![next, 0];
			payload.extend_from_slice(&(offset << 3 | 1).to_be_bytes());
			payload.extend_from_slice(&[0, 0, 0, 1]);
			payload.extend_from_slice(body);
			let header = Ipv6Header {payload_length: payload.len() as u16, next_header: IpNumber(44), hop_limit: 64, source: DEVICE_V6, destination: [0x20; 16], ..Default::default()};
			let mut raw = Vec::new();
			header.write(&mut raw).unwrap();
			raw.extend_from_slice(&payload);
			raw
		};
		assert!(answer(&six(0, 17, &udp), Kind::Port).is_some(), "a first ipv6 fragment was not answered");
		assert!(answer(&six(1, 17, &udp), Kind::Port).is_none(), "a later ipv6 fragment was answered");
		assert!(answer(&six(0, 58, &[1, 0, 0, 0, 0, 0, 0, 0]), Kind::Port).is_none(), "an ipv6 fragment with an icmpv6 error in it was answered");
		assert!(answer(&six(0, 58, &[]), Kind::Port).is_none(), "an ipv6 fragment whose icmpv6 type is cut off was answered");
	}

	#[test]
	fn multicast_broadcast_and_sources_that_name_nobody_are_never_answered() {
		for dst in [[224, 0, 0, 1], [239, 1, 2, 3], [255, 255, 255, 255], [10, 7, 0, 255]] {assert!(answer(&udp_v4([10, 7, 0, 2], dst, b"x"), Kind::Port).is_none(), "{dst:?} was answered")}
		for src in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255, 255, 255, 255], [10, 7, 0, 255]] {assert!(answer(&udp_v4(src, [1, 1, 1, 1], b"x"), Kind::Port).is_none(), "{src:?} was answered")}
		let mut multicast = [0u8; 16];
		(multicast[0], multicast[1], multicast[15]) = (0xff, 0x02, 1);
		assert!(answer(&udp_v6(multicast, b"x"), Kind::Port).is_none());
		for src in [[0u8; 16], multicast] {
			let mut raw = Vec::new();
			PacketBuilder::ipv6(src, [0x20; 16], 64).udp(40000, 9999).write(&mut raw, b"x").unwrap();
			assert!(answer(&raw, Kind::Port).is_none(), "{src:?} was answered");
		}
		// Unicast that only looks like a broadcast in another network is answered, and so is TCP when a caller asks for it.
		assert!(answer(&udp_v4([10, 7, 0, 2], [10, 8, 0, 255], b"x"), Kind::Port).is_some());
		let mut tcp = Vec::new();
		PacketBuilder::ipv4([10, 7, 0, 2], [1, 1, 1, 1], 64).tcp_header(TcpHeader::new(40000, 80, 1, 65535)).write(&mut tcp, &[]).unwrap();
		assert!(answer(&tcp, Kind::TooBig(1280)).is_some());
		// An error is written in the family of the packet it answers or not at all.
		let raw = udp_v4([10, 7, 0, 2], [1, 1, 1, 1], b"x");
		assert!(error(&raw, &parse(&raw).unwrap(), Kind::Port, GATEWAY_V6.into(), &pools()).is_none());
	}

	#[test]
	fn a_device_is_sent_a_burst_and_then_a_steady_few() {
		let start = Instant::now();
		let mut limit = Limit::new(start);
		assert_eq!((0..BURST * 3).filter(|_| limit.take(start)).count(), BURST as usize);
		assert!(!limit.take(start + Duration::from_millis(50)), "less than one error was earned");
		assert!(limit.take(start + Duration::from_millis(150)) && !limit.take(start + Duration::from_millis(150)));
		// One second earns `PER_SECOND`, and a long quiet time never more than the burst.
		let later = start + Duration::from_millis(1150);
		assert_eq!((0..BURST * 3).filter(|_| limit.take(later)).count(), PER_SECOND as usize);
		let much_later = later + Duration::from_secs(3600);
		assert_eq!((0..BURST * 3).filter(|_| limit.take(much_later)).count(), BURST as usize);
		assert!(!limit.take(start), "a clock that steps back earned something");
	}
}
