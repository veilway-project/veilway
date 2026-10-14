#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use tokio::time::Instant;
use veilway_proto::chunk::Padding;
use veilway_proto::keys::{Device, Table, TagKey};
use veilway_proto::replay::{Decision, Replay, Started};
use veilway_proto::subscription::payload::Padding as Bounds;
use veilway_proto::subscription::Secret;
use veilway_proto::udp_obfs::{self, Receiver, Sender};
use veilway_proto::NoRandom;
use veilway_transport::udp::{Io, Machine};
use veilway_transport::{Kind, Link, Want};

const TIME: u64 = 1_700_000_000;
const SECRET: [u8; 32] = [0x33; 32];
const INBOUND: [u8; 32] = [0x11; 32];
const DEVICE: [u8; 32] = [0x22; 32];
// The largest packet of a link with an `mtu` of 1390.
const MAX: usize = 1390 + udp_obfs::OVERHEAD;

// The client of `udp-obfs` (`udp::Machine`) between a caller, a clock and whatever arrives from the node's address. The input is steps of three bytes, `what`, `a` and `b`:
//   what % 6 = 0  a datagram arrives that nobody sealed: the next `a` bytes of the input, and none of the step when fewer are left
//              1  the node answers under the keys of one of the client's opening packets, `a` picks which and the newest for 0: a data packet around a datagram of 32 + `b` / 2 bytes, or around nothing when `b` is odd
//              2  the same answer with one bit changed on its way
//              3  the clock moves `a` * 50 ms and the timers run
//              4  the caller sends a datagram of 32 + 6 * `a` bytes, as traffic, as a handshake message or as one WireGuard's own timer made, by `b` % 3
//              5  the network changed
// The node here is `veilway-proto`'s own: it opens every opening packet the client sends and keeps the keys. Whatever the input is, every packet the client sends must be an opening packet of the device, never smaller than a first answer, or a data packet under the keys of one of its opening packets: nothing leaves outside a session. No packet is above the `mtu` and 62 bytes. The client takes a datagram only from a packet the node sealed, under the keys of whichever opening packet the node answers, gives exactly the datagram that was sealed, always reads the answer to its newest opening packet, and is established by nothing else. One attempt has four opening packets at the most, and once the timers have run nothing is due before the clock moves.
fuzz_target!(|data: &[u8]| {
	let (link, start, mut out, mut count) = (Link {inbound: INBOUND, device: DEVICE, secret: Secret::new(SECRET), node: None, mtu: 1390, padding: Bounds {wide_max: 1023, normal_max: 255, keepalive: 20_000..=40_000}}, Instant::now(), Vec::new(), 0u8);
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for byte in bytes {
			count = count.wrapping_mul(13).wrapping_add(7);
			*byte = count;
		}
		Ok(())
	};
	let mut asked = 0u8;
	let mut source = |want: Want| {
		asked = asked.wrapping_add(1);
		Some(match want {
			Want::First => [&[1, 0, 0, 0, asked][..], &[0xee; 143]].concat(),
			Want::Keepalive => [&[4, 0, 0, 0][..], &[0; 28]].concat(),
		})
	};
	let (node, mut table, tags) = (udp_obfs::Node::new(&INBOUND), Table::new(), TagKey::derive(&SECRET, &INBOUND));
	for epoch in udp_obfs::epochs(TIME) {assert!(table.epoch(tags.epoch_tag(epoch), Device::derive((), &SECRET, &INBOUND, &DEVICE)))}
	let Started::NoFile(pending) = Replay::start(None, TIME - 100, 4096) else {panic!("a start without a file")};
	let mut replay = pending.written();
	assert!(replay.raise(TIME + 20).is_some());
	replay.written();
	// The node's side of every opening packet the client sent, in order, and how many opening packets came since an answer last opened or the network last changed.
	let (mut sessions, mut machine, mut now, mut left, mut openings, mut established, mut newest) = (Vec::<(Sender, Receiver)>::new(), Machine::new(&link, start), start, data, 0usize, false, start);
	machine.moved(&mut Io {time: TIME, now, source: &mut source, out: &mut out}).expect("the first opening packet was not made");
	loop {
		for packet in out.drain(..) {
			assert!(packet.len() <= MAX, "a packet of {} bytes on a link whose largest is {MAX}", packet.len());
			let (mut opened, mut scratch) = (Vec::new(), Vec::new());
			let keys = node.open(&packet, &table, &mut opened).ok().map(|opening| {
				let Decision::Accepted(accepted) = opening.accept(&mut replay, TIME, |_| true) else {panic!("an opening packet of the client was refused by the replay rule")};
				assert!((32..=1422).contains(&accepted.datagram.len()), "an opening packet around what is no datagram");
				accepted.keys
			});
			match keys {
				Some(keys) => {
					assert!(packet.len() >= udp_obfs::FIRST_ANSWER, "an opening packet of {} bytes has no room for a first answer", packet.len());
					sessions.push((Sender::new(keys.s2c, Padding::new(1023, 255, &mut random).expect("the default bounds")), Receiver::new(keys.c2s)));
					(openings, newest) = (openings + 1, now);
					assert!(openings <= 4, "{openings} opening packets without an answer or a change of network between them");
				}
				None => assert!(sessions.iter_mut().any(|(_, rx)| rx.open(&packet, &mut scratch).is_ok()), "a packet was sent outside every session"),
			}
		}
		let Some((&[what, a, b], rest)) = left.split_first_chunk::<3>() else {return};
		left = rest;
		let mut io = Io {time: TIME, now, source: &mut source, out: &mut out};
		match what % 6 {
			0 => {
				let Some((stray, rest)) = left.split_at_checked(usize::from(a)) else {return};
				left = rest;
				assert_eq!(machine.received(stray, now), None, "a datagram nobody sealed was taken");
			}
			1 | 2 => {
				let (at, datagram, mut packet) = (sessions.len() - 1 - usize::from(a) % sessions.len(), (b % 2 == 0).then(|| [&[4, 0, 0, 0, a, b][..], &vec![0; 26 + usize::from(b) / 2]].concat()), Vec::new());
				sessions[at].0.seal(datagram.as_deref(), false, MAX, &mut random, &mut packet).expect("a datagram of this size seals");
				if what % 6 == 2 {
					let at = usize::from(a) * 131 % packet.len();
					packet[at] ^= 1 << (b % 8);
					assert_eq!(machine.received(&packet, now), None, "a packet that was changed on its way was taken");
				} else {
					let got = machine.received(&packet, now);
					assert!(got.is_none() || got == Some(datagram.clone()), "the client gave another datagram than the node sealed");
					// An opening packet is waited for as long as an attempt lasts, also when an older one of the same attempt was answered first.
					if at == sessions.len() - 1 && now < newest + Duration::from_secs(10) {assert_eq!(got, Some(datagram), "the answer to the newest opening packet did not open")}
					if got.is_some() {(established, openings) = (true, 0)}
				}
			}
			3 => {
				now += Duration::from_millis(u64::from(a) * 50);
				io.now = now;
				// A machine that says it is over is over: silence, or a session that was lost.
				// A clock that jumped has several things due at once, and each call does one of each kind: an attempt has four opening packets, so five calls have done them all.
				for _ in 0..5 {
					if machine.tick(&mut io).is_err() {return}
				}
				// With everything done that was due, the next thing to do lies ahead: a deadline that stays behind the clock is a loop that never waits.
				assert!(machine.deadline() > now, "nothing is due at this moment and the machine does not wait");
			}
			4 => {
				let (kind, first) = [(Kind::Packet {flow: u32::from(b), control: b & 4 != 0}, 4), (Kind::Handshake, 1), (Kind::Stalled, 1)][usize::from(b % 3)];
				if machine.send(&[&[first, 0, 0, 0][..], &vec![0x5a; 28 + 6 * usize::from(a)]].concat(), kind, &mut io).is_err() {return}
			}
			_ => {
				openings = 0;
				if machine.moved(&mut io).is_err() {return}
			}
		}
		assert_eq!(machine.established(), established, "the client is established by something else than a packet of the node");
	}
});
