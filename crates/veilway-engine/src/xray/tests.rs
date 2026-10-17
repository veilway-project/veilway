//! The carrier against a SOCKS5 server of the test's own, standing in for Xray. No real Xray runs here.
use super::*;
use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TransportHeader};
use tokio::net::{TcpListener, UdpSocket};

const LOGIN: &str = "run-login";
const DEVICE: [u8; 4] = [198, 18, 0, 2];
const GATEWAY: [u8; 4] = [198, 18, 0, 1];
const FAR: [u8; 4] = [93, 184, 216, 34];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {Normal, RefuseConnect, NoUdp}

/// What the server saw: the kind of request and the address it was for.
type Seen = Arc<Mutex<Vec<(&'static str, SocketAddr)>>>;

async fn greet(stream: &mut tokio::net::TcpStream) -> bool {
	let mut head = [0u8; 2];
	stream.read_exact(&mut head).await.unwrap();
	stream.read_exact(&mut vec![0u8; usize::from(head[1])]).await.unwrap();
	stream.write_all(&[5, 2]).await.unwrap();
	let mut user = [0u8; 2];
	stream.read_exact(&mut user).await.unwrap();
	let mut name = vec![0u8; usize::from(user[1])];
	stream.read_exact(&mut name).await.unwrap();
	let mut length = [0u8; 1];
	stream.read_exact(&mut length).await.unwrap();
	let mut password = vec![0u8; usize::from(length[0])];
	stream.read_exact(&mut password).await.unwrap();
	let good = name == b"veilway" && password == LOGIN.as_bytes();
	stream.write_all(&[1, if good {0} else {1}]).await.unwrap();
	good
}

async fn target(stream: &mut tokio::net::TcpStream) -> (u8, SocketAddr) {
	let mut head = [0u8; 4];
	stream.read_exact(&mut head).await.unwrap();
	let ip = if head[3] == 1 {
		let mut octets = [0u8; 4];
		stream.read_exact(&mut octets).await.unwrap();
		IpAddr::from(octets)
	} else {
		let mut octets = [0u8; 16];
		stream.read_exact(&mut octets).await.unwrap();
		IpAddr::from(octets)
	};
	let mut port = [0u8; 2];
	stream.read_exact(&mut port).await.unwrap();
	(head[1], SocketAddr::new(ip, u16::from_be_bytes(port)))
}

async fn hop(mode: Mode) -> (SocketAddr, Seen) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (address, seen): (SocketAddr, Seen) = (listener.local_addr().unwrap(), Arc::default());
	let record = seen.clone();
	tokio::spawn(async move {
		loop {
			let (mut stream, _) = listener.accept().await.unwrap();
			let seen = record.clone();
			tokio::spawn(async move {
				if !greet(&mut stream).await {return}
				let (command, destination) = target(&mut stream).await;
				if command == 1 {
					if mode == Mode::RefuseConnect {return stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap()}
					seen.lock().unwrap().push(("connect", destination));
					stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
					let mut buffer = [0u8; 4096];
					while let Ok(read) = stream.read(&mut buffer).await {
						if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {break}
					}
					return;
				}
				if mode == Mode::NoUdp {return stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap()}
				let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
				let port = relay.local_addr().unwrap().port().to_be_bytes();
				seen.lock().unwrap().push(("associate", destination));
				stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]]).await.unwrap();
				let echo = tokio::spawn(async move {
					let mut buffer = vec![0u8; 65535];
					while let Ok((read, from)) = relay.recv_from(&mut buffer).await {
						let Some((to, data)) = socks::unwrap(&buffer[..read]) else {continue};
						seen.lock().unwrap().push(("datagram", to));
						relay.send_to(&socks::wrap(to, data), from).await.unwrap();
					}
				});
				let _ = stream.read(&mut [0u8; 1]).await;
				echo.abort();
			});
		}
	});
	(address, seen)
}

struct Rig {tunnel: XrayTunnel, live: Arc<Live>, seen: Seen}

async fn rig(mode: Mode, up: bool) -> Rig {
	let (socks, seen) = hop(mode).await;
	let live = Live::new();
	live.set_up(up);
	let tunnel = XrayTunnel::start(Params {name: "Home".into(), socks, login: LOGIN.into(), addresses: addresses(&[]).unwrap(), resolvers: [IpAddr::from([1, 1, 1, 1]), IpAddr::from([9, 9, 9, 9])], live: live.clone(), relay_ok: Arc::new(|_| true)});
	Rig {tunnel, live, seen}
}

impl Rig {
	async fn next(&mut self) -> Vec<u8> {tokio::time::timeout(Duration::from_secs(5), self.tunnel.recv()).await.expect("no packet in time").expect("the carrier stopped")}
	async fn quiet(&mut self) {assert!(tokio::time::timeout(Duration::from_millis(300), self.tunnel.recv()).await.is_err(), "a packet came that should not have")}
	fn seen(&self) -> Vec<(&'static str, SocketAddr)> {self.seen.lock().unwrap().clone()}
	async fn counters(&self, until: impl Fn(&XrayCounters) -> bool) -> XrayCounters {
		let mut watch = self.tunnel.watch();
		tokio::time::timeout(Duration::from_secs(5), async {
			loop {
				let counters = watch.borrow_and_update().xray.unwrap().counters;
				if until(&counters) {return counters}
				watch.changed().await.unwrap();
			}
		}).await.expect("the counters did not get there")
	}
	// The device's side of a TCP flow: the handshake, then the sequence numbers to go on from.
	async fn open(&mut self, sport: u16, to: [u8; 4], dport: u16) -> (u32, u32) {
		self.tunnel.send(tcp(sport, to, dport, 1000, 0, 0x02, b""));
		let reply = self.next().await;
		let (flags, seq, _) = parse_tcp(&reply);
		assert_eq!(flags & 0x12, 0x12, "no SYN-ACK");
		self.tunnel.send(tcp(sport, to, dport, 1001, seq + 1, 0x10, b""));
		(1001, seq + 1)
	}
}

fn tcp(sport: u16, to: [u8; 4], dport: u16, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Vec<u8> {
	let mut builder = PacketBuilder::ipv4(DEVICE, to, 64).tcp(sport, dport, seq, 65535);
	if flags & 0x02 != 0 {builder = builder.syn()}
	if flags & 0x10 != 0 {builder = builder.ack(ack)}
	if flags & 0x08 != 0 {builder = builder.psh()}
	let mut raw = Vec::new();
	builder.write(&mut raw, data).unwrap();
	raw
}

fn parse_tcp(raw: &[u8]) -> (u8, u32, Vec<u8>) {
	let found = PacketHeaders::from_ip_slice(raw).unwrap();
	let Some(TransportHeader::Tcp(header)) = found.transport else {panic!("not tcp")};
	let flags = u8::from(header.fin) | u8::from(header.syn) << 1 | u8::from(header.rst) << 2 | u8::from(header.psh) << 3 | u8::from(header.ack) << 4;
	let PayloadSlice::Tcp(payload) = found.payload else {panic!("no payload")};
	(flags, header.sequence_number, payload.to_vec())
}

fn udp(sport: u16, to: [u8; 4], dport: u16, data: &[u8]) -> Vec<u8> {
	let mut raw = Vec::new();
	PacketBuilder::ipv4(DEVICE, to, 64).udp(sport, dport).write(&mut raw, data).unwrap();
	raw
}

fn parse_udp(raw: &[u8]) -> (IpAddr, u16, u16, Vec<u8>) {
	let found = PacketHeaders::from_ip_slice(raw).unwrap();
	let (Some(NetHeaders::Ipv4(ip, _)), Some(TransportHeader::Udp(header))) = (found.net, found.transport) else {panic!("not udp")};
	let PayloadSlice::Udp(payload) = found.payload else {panic!("no payload")};
	(IpAddr::from(ip.source), header.source_port, header.destination_port, payload.to_vec())
}

#[test]
fn the_tunnel_takes_the_first_range_that_no_network_of_the_device_overlaps() {
	let own = |address: &str, prefix| Network::new(address.parse().unwrap(), prefix).unwrap();
	let free = addresses(&[own("192.168.1.7", 24), own("fe80::1", 64)]).unwrap();
	assert_eq!((free.device[0], free.gateway[0], free.device[1], free.gateway[1]), (IpAddr::from(DEVICE), IpAddr::from(GATEWAY), "fdfe:7665:6c77::2".parse().unwrap(), "fdfe:7665:6c77::1".parse().unwrap()));
	for overlapping in [own("198.18.0.0", 16), own("198.18.0.3", 32), own("198.18.0.1", 30)] {
		let moved = addresses(&[overlapping]).unwrap();
		assert_eq!((moved.device[0], moved.gateway[0]), (IpAddr::from([198, 19, 0, 2]), IpAddr::from([198, 19, 0, 1])));
	}
	assert_eq!(addresses(&[own("198.18.0.0", 15), own("198.19.0.2", 32)]), None);
	assert!(addresses(&[own("198.18.0.4", 30), own("198.20.0.0", 16)]).is_some(), "a neighbouring /30 does not overlap");
	assert!(addresses(&[own("fdfe:7665:6c77::", 48)]).is_none(), "the same range of the second family cannot be moved away from");
}

#[test]
fn the_server_is_not_answering_after_eight_failures_over_thirty_seconds_and_a_carried_flow_clears_it() {
	let (mut streak, start) = (Streak::default(), Instant::now());
	for _ in 0..7 {streak.failed(start)}
	assert!(!streak.silent(start + Duration::from_secs(60)), "seven failures are not eight");
	streak.failed(start + Duration::from_secs(1));
	assert!(!streak.silent(start + Duration::from_secs(29)), "not over thirty seconds yet");
	assert!(streak.silent(start + Duration::from_secs(31)));
	streak.carried();
	assert!(!streak.silent(start + Duration::from_secs(90)));
}

#[tokio::test]
async fn a_tcp_flow_goes_to_the_address_the_stack_saw_with_the_login_and_back() {
	let mut rig = rig(Mode::Normal, true).await;
	let (seq, ack) = rig.open(40000, FAR, 80).await;
	rig.tunnel.send(tcp(40000, FAR, 80, seq, ack, 0x18, b"hello through xray"));
	let mut got = Vec::new();
	while got.len() < 18 {
		let (flags, _, data) = parse_tcp(&rig.next().await);
		assert_eq!(flags & 0x04, 0, "a reset");
		got.extend_from_slice(&data);
	}
	assert_eq!(got, b"hello through xray");
	assert_eq!(rig.seen(), [("connect", SocketAddr::new(IpAddr::from(FAR), 80))]);
	let counters = rig.counters(|counters| counters.carried_flows == 1 && counters.bytes_received >= 18).await;
	assert_eq!((counters.open_tcp, counters.failed_flows, counters.bytes_sent), (1, 0, 18));
	let status = rig.tunnel.status();
	assert!(matches!(status.state, State::Connected {exit: None}) && status.xray.unwrap().say.is_none() && status.mtu == MTU);
	assert!(status.counters.packets_sent >= 3 && status.counters.packets_received >= 2);
}

#[tokio::test]
async fn while_xray_is_down_a_flow_is_reset_at_once_and_not_counted_as_failed() {
	let mut rig = rig(Mode::Normal, false).await;
	assert!(matches!(rig.tunnel.status().state, State::Connecting {..}));
	rig.tunnel.send(tcp(40001, FAR, 80, 1000, 0, 0x02, b""));
	loop {
		let (flags, _, _) = parse_tcp(&rig.next().await);
		if flags & 0x04 != 0 {break}
	}
	rig.tunnel.send(udp(40002, FAR, 9000, b"dropped"));
	rig.quiet().await;
	let counters = rig.counters(|counters| counters.dropped_udp_flows == 1).await;
	assert_eq!(counters.failed_flows, 0);
	assert!(rig.seen().is_empty(), "nothing reached the hop");
}

#[tokio::test]
async fn an_open_flow_is_reset_when_xray_goes_down_and_the_state_says_it_restarts() {
	let mut rig = rig(Mode::Normal, true).await;
	let (seq, ack) = rig.open(40003, FAR, 80).await;
	rig.tunnel.send(tcp(40003, FAR, 80, seq, ack, 0x18, b"x"));
	rig.next().await;
	rig.live.restarted(1234);
	rig.live.set_up(false);
	loop {
		let (flags, _, _) = parse_tcp(&rig.next().await);
		if flags & 0x04 != 0 {break}
	}
	let mut watch = rig.tunnel.watch();
	let status = tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			let status = watch.borrow_and_update().clone();
			if matches!(status.state, State::Reconnecting {..}) {return status}
			watch.changed().await.unwrap();
		}
	}).await.unwrap();
	let view = status.xray.unwrap();
	assert_eq!((view.say, view.counters.restarts, view.counters.last_restart), (Some(XraySay::Restarting), 1, Some(1234)));
	rig.live.set_up(true);
	assert!(rig.tunnel.status().xray.unwrap().say.is_none() || matches!(rig.tunnel.status().state, State::Reconnecting {..}));
}

#[tokio::test]
async fn a_refused_connect_ends_the_flow_with_a_reset_and_counts_a_failure() {
	let mut rig = rig(Mode::RefuseConnect, true).await;
	rig.tunnel.send(tcp(40004, FAR, 443, 1000, 0, 0x02, b""));
	loop {
		let (flags, _, _) = parse_tcp(&rig.next().await);
		if flags & 0x04 != 0 {break}
	}
	assert_eq!(rig.counters(|counters| counters.failed_flows == 1).await.carried_flows, 0);
}

#[tokio::test]
async fn a_udp_flow_gets_its_own_association_and_answers_come_back_from_the_address_it_was_sent_to() {
	let mut rig = rig(Mode::Normal, true).await;
	rig.tunnel.send(udp(41000, FAR, 9000, b"ping"));
	let (from, sport, dport, data) = parse_udp(&rig.next().await);
	assert_eq!((from, sport, dport, data), (IpAddr::from(FAR), 9000, 41000, b"ping".to_vec()));
	rig.tunnel.send(udp(41001, [8, 8, 8, 8], 3478, b"other"));
	rig.next().await;
	let seen = rig.seen();
	assert_eq!(seen.iter().filter(|(kind, _)| *kind == "associate").count(), 2, "one association for each flow");
	assert!(seen.contains(&("datagram", SocketAddr::new(IpAddr::from(FAR), 9000))) && seen.contains(&("datagram", "8.8.8.8:3478".parse().unwrap())));
	let counters = rig.counters(|counters| counters.carried_flows == 2).await;
	assert_eq!((counters.open_udp, counters.bytes_sent), (2, 9));
}

#[tokio::test]
async fn a_relay_the_platform_does_not_vouch_for_gets_no_datagram() {
	let (socks, seen) = hop(Mode::Normal).await;
	let live = Live::new();
	live.set_up(true);
	let asked: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
	let record = asked.clone();
	let mut tunnel = XrayTunnel::start(Params {name: "Home".into(), socks, login: LOGIN.into(), addresses: addresses(&[]).unwrap(), resolvers: [IpAddr::from([1, 1, 1, 1]), IpAddr::from([9, 9, 9, 9])], live, relay_ok: Arc::new(move |relay| {record.lock().unwrap().push(relay); false})});
	tunnel.send(udp(41100, FAR, 9000, b"ping"));
	assert!(tokio::time::timeout(Duration::from_millis(500), tunnel.recv()).await.is_err(), "an answer came through a relay that was refused");
	assert!(seen.lock().unwrap().iter().all(|(kind, _)| *kind != "datagram"));
	let asked = asked.lock().unwrap().clone();
	assert!(asked.len() == 1 && asked[0].ip() == socks.ip());
	let mut watch = tunnel.watch();
	tokio::time::timeout(Duration::from_secs(5), async {while watch.borrow_and_update().xray.unwrap().counters.failed_flows == 0 {watch.changed().await.unwrap()}}).await.unwrap();
}

#[tokio::test]
async fn a_udp_flow_over_the_cap_is_dropped_and_counted() {
	let rig = rig(Mode::Normal, true).await;
	for port in 0..=UDP_MAX as u16 {rig.tunnel.send(udp(42000 + port, FAR, 9000, b"x"));}
	let counters = rig.counters(|counters| counters.dropped_udp_flows == 1).await;
	assert_eq!(counters.open_udp as usize, UDP_MAX);
}

#[tokio::test]
async fn a_dns_query_to_the_gateway_goes_through_the_association_to_the_public_resolver() {
	let mut rig = rig(Mode::Normal, true).await;
	rig.tunnel.send(udp(43000, GATEWAY, 53, b"\x12\x34query"));
	let (from, sport, dport, data) = parse_udp(&rig.next().await);
	assert_eq!((from, sport, dport, data), (IpAddr::from(GATEWAY), 53, 43000, b"\x12\x34query".to_vec()));
	assert!(rig.seen().contains(&("datagram", "1.1.1.1:53".parse().unwrap())), "{:?}", rig.seen());
}

#[tokio::test]
async fn a_dns_query_falls_back_to_tcp_through_connect_when_the_association_fails() {
	let mut rig = rig(Mode::NoUdp, true).await;
	rig.tunnel.send(udp(43001, GATEWAY, 53, b"\x56\x78query"));
	let (from, _, _, data) = parse_udp(&rig.next().await);
	assert_eq!((from, data), (IpAddr::from(GATEWAY), b"\x56\x78query".to_vec()));
	assert_eq!(rig.seen(), [("connect", "1.1.1.1:53".parse().unwrap())]);
}

#[tokio::test]
async fn a_tcp_connection_to_the_gateway_is_a_dns_query_for_the_resolver_and_other_ports_get_a_reset() {
	let mut rig = rig(Mode::Normal, true).await;
	let (seq, ack) = rig.open(43002, GATEWAY, 53).await;
	rig.tunnel.send(tcp(43002, GATEWAY, 53, seq, ack, 0x18, b"\x00\x03abc"));
	let mut data = Vec::new();
	while data.len() < 5 {data.extend_from_slice(&parse_tcp(&rig.next().await).2)}
	assert_eq!(data, b"\x00\x03abc");
	assert_eq!(rig.seen(), [("connect", "1.1.1.1:53".parse().unwrap())]);
	rig.tunnel.send(tcp(43003, GATEWAY, 22, 1000, 0, 0x02, b""));
	loop {
		let (flags, _, _) = parse_tcp(&rig.next().await);
		if flags & 0x04 != 0 {break}
	}
	rig.tunnel.send(udp(43004, GATEWAY, 5353, b"x"));
	rig.counters(|counters| counters.dropped_udp_flows == 1).await;
}

#[tokio::test]
async fn a_ping_of_the_gateway_is_answered_and_other_icmp_and_protocols_are_dropped_and_counted() {
	let mut rig = rig(Mode::Normal, true).await;
	let mut ping = Vec::new();
	PacketBuilder::ipv4(DEVICE, GATEWAY, 64).icmpv4_echo_request(1, 1).write(&mut ping, b"up").unwrap();
	rig.tunnel.send(ping);
	let reply = rig.next().await;
	assert_eq!((reply[9], reply[20], &reply[28..]), (1, 0, &b"up"[..]));
	let mut elsewhere = Vec::new();
	PacketBuilder::ipv4(DEVICE, FAR, 64).icmpv4_echo_request(1, 2).write(&mut elsewhere, b"up").unwrap();
	let mut esp = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 50, 0, 0, 198, 18, 0, 2, 93, 184, 216, 34];
	esp.extend_from_slice(&[0; 8]);
	let mut redirect = Vec::new();
	PacketBuilder::ipv4(DEVICE, FAR, 64).icmpv4_raw(5, 0, [0; 4]).write(&mut redirect, &[0; 28]).unwrap();
	for packet in [elsewhere, esp, redirect] {rig.tunnel.send(packet);}
	rig.quiet().await;
	assert_eq!(rig.counters(|counters| counters.unsupported_packets == 3).await.carried_flows, 0);
	assert!(rig.seen().is_empty());
}

#[tokio::test]
async fn the_pieces_of_a_fragmented_udp_datagram_are_put_together_before_the_flow_sees_it() {
	let mut rig = rig(Mode::Normal, true).await;
	let payload: Vec<u8> = (0..1200).map(|at| (at % 200) as u8).collect();
	let whole = udp(44000, FAR, 9000, &payload);
	let size = 512;
	let pieces: Vec<Vec<u8>> = whole[20..].chunks(size).enumerate().map(|(at, part)| {
		let mut piece = [&whole[..20], part].concat();
		piece[2..4].copy_from_slice(&((20 + part.len()) as u16).to_be_bytes());
		piece[4..6].copy_from_slice(&9u16.to_be_bytes());
		let place = (at * size / 8) as u16 | if (at + 1) * size < whole.len() - 20 {0x2000} else {0};
		piece[6..8].copy_from_slice(&place.to_be_bytes());
		piece
	}).collect();
	for piece in pieces.iter().rev() {rig.tunnel.send(piece.clone());}
	let mut got = Vec::new();
	while got.len() < payload.len() {
		let (from, _, _, data) = parse_udp(&rig.next().await);
		assert_eq!(from, IpAddr::from(FAR));
		got.extend_from_slice(&data);
	}
	assert_eq!(rig.seen().iter().filter(|(kind, _)| *kind == "datagram").count(), 1, "the flow saw one datagram");
}

#[tokio::test]
async fn stopping_closes_the_flows_and_the_state_is_off() {
	let mut rig = rig(Mode::Normal, true).await;
	let (seq, ack) = rig.open(45000, FAR, 80).await;
	rig.tunnel.send(tcp(45000, FAR, 80, seq, ack, 0x18, b"x"));
	rig.next().await;
	let last = rig.tunnel.stop().await;
	assert_eq!(last.state, State::Off);
}

#[test]
fn an_answer_over_the_packet_size_becomes_a_header_with_the_truncated_bit_and_no_records() {
	let mut answer = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 40, 0, 0, 0, 0];
	answer.extend_from_slice(&[7; 2000]);
	assert_eq!(truncated(&answer), Some(vec![0x12, 0x34, 0x83, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]));
	assert_eq!(truncated(&answer[..12]).unwrap().len(), 12);
	assert_eq!(truncated(&answer[..11]), None, "less than a header is no answer");
}
