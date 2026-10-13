#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::{Ipv4Addr, SocketAddr};
use veilway_core::engine::obfs::{Bench, DEVICE_SESSIONS};
use veilway_proto::chunk::{Padding, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::session::PENDING;
use veilway_proto::udp_obfs::{Client, Receiver, Sender, OVERHEAD};
use veilway_proto::NoRandom;
use veilway_wg::Wg;

const NODE: [u8; 32] = [0x10; 32];
const KEYS: [[u8; 32]; 3] = [[0x21; 32], [0x22; 32], [0x23; 32]];
const TIME: i64 = 1_700_000_000_000;
const POOL: usize = 12;
const MAX: usize = 1390 + OVERHEAD;
// How many sessions the harness opens and how many packets it remembers in one run.
const KEPT: usize = 64;
// An IPv4 header with nothing behind it, which the tunnel carries once a handshake is done.
const PACKET: [u8; 20] = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1];

// One session as the harness knows it: who opened it, from where, and the keys its opening packet gave. Whether the node accepted that packet the harness does not ask.
struct Session {device: usize, source: SocketAddr, tx: Sender, rx: Receiver, opening: usize, answered: bool}

// One packet the harness sent: where from, on which session, whether it holds a WireGuard packet the node has to take as its device's and had not seen when it was made, whether the node has answered it or taken a packet out of the tunnel for it,
// and whether the node keeps it for the write of a higher limit, in which case nobody but its own source may ever be answered for it.
struct Sent {from: SocketAddr, packet: Vec<u8>, on: Option<usize>, authentic: bool, answered: bool, held: bool}

// The datagram path of a `udp-obfs` listener as a whole: a node with three devices, one of them with two transport secrets, and whatever arrives from four sources. The input is a list of steps, each three bytes of settings and up to 255 bytes of payload:
//   0  the low three bits are the step. 0: the payload from a stranger. 1: an opening packet of a device around the payload as its datagram. 2: an opening packet around a fresh WireGuard handshake initiation of the device.
//      3: a data packet of a session the harness opened, around the payload. 4: the same around what the device's WireGuard sends next, a keepalive or a handshake. 5: a packet the harness sent before, again, whatever the node did with it then.
//      6 and 7: the node's clock moves, by quarter seconds or by tens of seconds, and its timers run: the limit a proof asked for is written, and the opening packets that waited for it go to the replay rule again.
//   1  the two low bits are the source, the next two the device (3 is a secret the node does not have), bit 4 the second secret of a device that has two and, for a packet that is sent again, another source than its own, bits 5 to 7 which session or which earlier packet
//   2  the length of the payload. Its first byte is how many seconds the timestamp of an opening packet is off the node's clock, as a signed number.
// What must hold whatever the input is: nothing is sent, and nothing comes out of the tunnel, unless the packet holds an authentic WireGuard packet of the session's own device and the node has not answered that packet before. A first answer is no larger than the opening packet of its session.
// A packet that was answered once is never answered again, from any source. A packet the node keeps for a higher limit is answered at its own source or nowhere. And the node holds no more pending sessions than two for each device and no more established ones than its pool has places.
fuzz_target!(|data: &[u8]| {
	let (public, secrets, mut seed) = (veilway_wg::public_key(&NODE), [[0xa0; 32], [0xa1; 32], [0xa2; 32], [0xc2; 32], [0xee; 32]], 0u64);
	let mut random = move |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for byte in bytes {
			seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			*byte = (seed >> 33) as u8;
		}
		Ok(())
	};
	let mut bench = Bench::new(NODE, &[(veilway_wg::public_key(&KEYS[0]), vec![secrets[0]]), (veilway_wg::public_key(&KEYS[1]), vec![secrets[1]]), (veilway_wg::public_key(&KEYS[2]), vec![secrets[2], secrets[3]])], POOL, TIME as u64 / 1000);
	let mut devices: Vec<Wg> = KEYS.iter().map(|key| {
		let mut device = Wg::new(*key);
		device.add_peer(public, None, None).expect("one peer");
		device
	}).collect();
	let (mut sessions, mut sent, mut now, mut rest, node) = (Vec::<Session>::new(), Vec::<Sent>::new(), TIME, data, SocketAddr::from((Ipv4Addr::new(192, 0, 2, 200), 443)));
	// What the node did with packet `at` of `sent` when it came from `from`, held against what it may do.
	let judge = |sent: &mut Vec<Sent>, sessions: &mut Vec<Session>, devices: &mut Vec<Wg>, at: usize, from: SocketAddr, replies: &[Vec<u8>], carried: usize| {
		let record = &mut sent[at];
		assert!((record.authentic && !record.answered && (!record.held || from == record.from)) || (replies.is_empty() && carried == 0), "{} packets sent and {carried} taken from the tunnel for a packet that proved nothing new: authentic {}, answered before {}, kept for its own source {}", replies.len(), record.authentic, record.answered, record.held && from != record.from);
		record.answered |= !replies.is_empty() || carried > 0;
		let (Some(session), mut scratch) = (record.on.map(|on| &mut sessions[on]), Vec::new()) else {return};
		for reply in replies {
			// "The first answer is no larger than the opening packet it answers", and every answer is a data packet of the session the packet belongs to.
			assert!(session.answered || reply.len() <= session.opening, "a first answer of {} bytes to an opening packet of {}", reply.len(), session.opening);
			session.answered = true;
			let inner = session.rx.open(reply, &mut scratch).expect("the node sent something that is no packet of the session").map(<[u8]>::to_vec);
			// What the node's WireGuard says goes to the device's, and what that answers is for a later step to send.
			if let Some(inner) = inner {devices[session.device].recv_from_network(node, &inner, &mut Vec::new(), &mut Vec::new());}
		}
	};
	while let Some((&[step, pick, size], tail)) = rest.split_first_chunk::<3>() {
		let (payload, after) = tail.split_at(usize::from(size).min(tail.len()));
		rest = after;
		let (source, device, slot) = (SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1 + (pick & 3)), 4000)), usize::from(pick >> 2 & 3), usize::from(pick >> 5));
		// The secret the device speaks with: its own, the second one of the device that has two, or one the node does not have.
		let secret = if device == 3 {secrets[4]} else if device == 2 && pick & 16 != 0 {secrets[3]} else {secrets[device]};
		let at = (now / 1000).saturating_add(i64::from(payload.first().copied().unwrap_or(0) as i8)).max(0) as u64;
		let junk = if (32..=255).contains(&payload.len()) {payload.to_vec()} else {vec![step; 40]};
		// What the step sends: the packet of `sent` it is, and the source it comes from.
		let (which, from) = match step & 7 {
			0 if sent.len() < KEPT => {
				sent.push(Sent {from: source, packet: payload.to_vec(), on: None, authentic: false, answered: false, held: false});
				(sent.len() - 1, source)
			}
			kind @ (1 | 2) if sent.len() < KEPT && sessions.len() < KEPT => {
				let (owner, mut net) = (device.min(2), Vec::new());
				if kind == 2 {
					devices[owner].drop_sessions(&public);
					devices[owner].encapsulate(0, &PACKET, &mut net);
				}
				let (datagram, padding, mut packet) = (net.pop().unwrap_or(junk), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).expect("the default bounds"), Vec::new());
				let keys = Client::new(&secret, &public).open(at, &datagram, &padding, MAX, &mut random, &mut packet).expect("a client seals");
				sessions.push(Session {device: owner, source, tx: Sender::new(keys.c2s, padding), rx: Receiver::new(keys.s2c), opening: packet.len(), answered: false});
				// An initiation is authentic for the session when the opening packet names the device it is of, under a secret the node has for it.
				sent.push(Sent {from: source, packet, on: Some(sessions.len() - 1), authentic: kind == 2 && device < 3, answered: false, held: false});
				(sent.len() - 1, source)
			}
			kind @ (3 | 4) if sent.len() < KEPT && !sessions.is_empty() => {
				let (on, owner, mut net, mut packet) = (slot % sessions.len(), device.min(2), Vec::new(), Vec::new());
				if kind == 4 {devices[owner].encapsulate(0, &[], &mut net)}
				let authentic = !net.is_empty() && sessions[on].device == owner;
				sessions[on].tx.seal(Some(&net.pop().unwrap_or(junk)), false, MAX, &mut random, &mut packet).expect("a session seals");
				sent.push(Sent {from: sessions[on].source, packet, on: Some(on), authentic, answered: false, held: false});
				(sent.len() - 1, sessions[on].source)
			}
			5 if !sent.is_empty() => (slot % sent.len(), if pick & 16 != 0 {source} else {sent[slot % sent.len()].from}),
			kind @ (6 | 7) => {
				now += if kind == 6 {250 * (i64::from(pick) + 1)} else {10_000 * i64::from(pick)};
				let before = bench.totals();
				let again = bench.tick(now);
				let after = bench.totals();
				// A packet that waited and was refused by a limit without being recorded, for which a device has a small allowance, is anybody's again, and so is one the node gave up on. Only one that went to the rule and was recorded stays its source's alone.
				let unrecorded = (after.pool + after.pending_full + after.device_rate + after.source_rate + after.source_devices) - (before.pool + before.pending_full + before.device_rate + before.source_rate + before.source_devices) > after.spent - before.spent;
				for record in sent.iter_mut().filter(|record| record.held && (unrecorded || !again.iter().any(|(_, packet, ..)| *packet == record.packet))) {record.held = false}
				for (from, packet, replies, carried) in &again {
					let at = sent.iter().position(|record| record.packet == *packet).expect("the node took a packet to the rule again that it was never sent");
					judge(&mut sent, &mut sessions, &mut devices, at, *from, replies, *carried);
				}
				continue;
			}
			_ => continue,
		};
		let waited = bench.totals().waited;
		let (replies, carried) = bench.datagram(from, &sent[which].packet, now);
		let replies = replies.to_vec();
		// A packet the node keeps is its own source's from here on.
		if bench.totals().waited > waited {
			assert!(from == sent[which].from || !sent[which].held, "the node kept a copy of a packet it already keeps");
			sent[which].held |= from == sent[which].from;
		}
		judge(&mut sent, &mut sessions, &mut devices, which, from, &replies, carried);
		let totals = bench.totals();
		assert!(totals.pending <= PENDING * KEYS.len() && totals.sessions <= POOL.min(DEVICE_SESSIONS * KEYS.len()), "{} pending sessions and {} established", totals.pending, totals.sessions);
	}
});
