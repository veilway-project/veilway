#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use veilway_proto::{chunk::{parse, Padding, MAX_ITEM, MIN_ITEM, NORMAL_DEFAULT, WIDE_DEFAULT}, keys::{ChunkKey, Device, Table, TagKey}, replay::{Decision, Refusal, Replay, Started}, udp_obfs::{epoch, epochs, Client, Node, Receiver, Sender, DATA_MIN, OPENING_MIN, OVERHEAD}, NoRandom, Refused};

// The packets of `udp-obfs`. Eight bytes of settings, then what the mode says:
//   0  the two low bits are the mode. 0: a real client makes an opening packet around the rest as its datagram, and the packet is changed on the way. 1: the rest is a datagram from a stranger, for a node and for a session. 2: a client seals the rest as the 12 bytes and the chunk plaintext of an opening packet. 3: the rest is a nonce and a chunk plaintext, sealed here as a data packet with the library the crate opens it with.
//   1  the client: the first secret of a device in the table, its second secret, or a secret the node does not have (by the value modulo 3)
//   2  how far the client's epoch is from the node's: two behind to two ahead (modulo 5). The table holds one either side.
//   3  which byte of the packet is changed
//   4  what is XORed onto it, 0 for no change
//   5  the inbound's `mtu` above 1280, in steps of 2
//   7  the seed of the client's random bytes
// The outcome is known in advance in every mode but 1, and the node must agree.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, who, shift, at, change, mtu, _, seed], rest)) = data.split_first_chunk::<8>() else {return};
	let (inbound, device, secrets, time, mut scratch) = ([0x20; 32], [0x40; 32], [[1; 32], [7; 32], [9; 32]], 1_700_000_000u64, Vec::new());
	// One table for both kinds of tag, as a node with a stream transport and `udp-obfs` holds it.
	let mut table = Table::new();
	for slot in 0..2 {
		let tags = TagKey::derive(&secrets[slot], &inbound);
		assert!(table.device(tags.device_tag(), Device::derive(slot, &secrets[slot], &inbound, &device)));
		for epoch in epochs(time) {assert!(table.epoch(tags.epoch_tag(epoch), Device::derive(slot, &secrets[slot], &inbound, &device)))}
	}
	let (node, slot, shift, max) = (Node::new(&inbound), usize::from(who % 3), i64::from(shift % 5) - 2, 1280 + 2 * usize::from(mtu) + OVERHEAD);
	let mut random = move |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for (index, byte) in bytes.iter_mut().enumerate() {*byte = seed ^ (index as u8).wrapping_mul(31)}
		Ok(())
	};
	let padding = |random: &mut dyn FnMut(&mut [u8]) -> Result<(), NoRandom>| Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, random).expect("the default bounds are legal");
	match flags & 3 {
		1 => {
			assert_eq!(node.open(rest, &table, &mut scratch).map(|opening| opening.device.id), Err(Refused), "a node opened a packet no client made");
			assert_eq!(Receiver::new(ChunkKey::new(&[0x33; 32])).open(rest, &mut scratch), Err(Refused), "a session opened a packet no peer made");
		}
		3 => {
			let Some((nonce, plaintext)) = rest.split_first_chunk::<12>() else {return};
			let mut packet = [&nonce[..], plaintext].concat();
			let tag = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &[0x33; 32]).expect("a key of 32 bytes")).seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::empty(), &mut packet[12..]).expect("a plaintext of this size seals");
			packet.extend_from_slice(tag.as_ref());
			// "A chunk holds one WireGuard datagram or none": what a stream chunk may hold beyond that is refused here.
			let expected = parse(plaintext).ok().map(Iterator::collect::<Vec<_>>).filter(|items| items.len() <= 1).map(|items| items.first().copied()).ok_or(Refused);
			let mut receiver = Receiver::new(ChunkKey::new(&[0x33; 32]));
			assert_eq!(receiver.open(&packet, &mut scratch), expected, "a data packet opened to something else than its plaintext reads as");
			assert_eq!(receiver.received(), u64::from(expected.is_ok()));
			if let Ok(Some(datagram)) = expected {assert!((MIN_ITEM..=MAX_ITEM).contains(&datagram.len()))}
		}
		mode => {
			let (client, stamp, mut packet) = (Client::new(&secrets[slot], &inbound), time.wrapping_add_signed(shift * 120), Vec::new());
			let fallback = [seed; 32];
			let datagram = if (MIN_ITEM..=1200).contains(&rest.len()) {rest} else {&fallback};
			// What the packet holds, and whether the specification allows it: version 1, zero bytes, and a chunk of exactly one datagram.
			let (keys, timestamp, allowed) = if mode == 0 {(client.open(stamp, datagram, &padding(&mut random), max, &mut random, &mut packet), stamp, true)} else {
				let (mut header, mut plaintext) = ([0; 12], rest);
				if let Some((first, tail)) = rest.split_first_chunk::<12>() {(header, plaintext) = (*first, tail)}
				let one = parse(plaintext).is_ok_and(|items| items.count() == 1);
				(client.forge(epoch(stamp), &header, plaintext, &mut random, &mut packet), u64::from_be_bytes(std::array::from_fn(|index| header[4 + index])), header[..4] == [1, 0, 0, 0] && one)
			};
			let keys = keys.expect("a client seals");
			assert!(packet.len() >= OPENING_MIN && (mode != 0 || packet.len() <= max), "an opening packet of {} bytes on a path of {max}", packet.len());
			let at = usize::from(at) % packet.len();
			packet[at] ^= change;
			let honest = allowed && slot < 2 && shift.abs() <= 1 && change == 0;
			let Ok(opening) = node.open(&packet, &table, &mut scratch) else {
				assert!(!honest, "a node refused an opening packet: secret {slot}, {shift} epochs away");
				return;
			};
			assert!(honest, "a node opened a packet it must refuse: secret {slot}, {shift} epochs away, change {change:#04x} at {at}");
			assert_eq!((opening.device.id, opening.timestamp), (slot, timestamp));
			// The rest of step 6, and step 7: a replay memory whose clock is the packet's own time accepts it once, after the write its limit needs, and only then are the datagram and the keys given out. The same packet again opens and is refused.
			let Started::NoFile(pending) = Replay::start(None, timestamp.saturating_sub(1000), 4) else {panic!("a start without a file")};
			let (mut replay, mut again) = (pending.written(), Vec::new());
			let accepted = match opening.accept(&mut replay, timestamp, |device| device.id == slot) {
				Decision::Raise(limit, waiting) => {
					assert!(replay.raise(limit).is_some(), "no file for a limit the rule asked for");
					replay.written();
					waiting.accept(&mut replay, timestamp, |device| device.id == slot)
				}
				decision => decision,
			};
			// A packet may say any time. One in the first minute of time is at the floor of every memory or below it, and every other is accepted.
			let Decision::Accepted(opening) = accepted else {
				assert!(timestamp < 1060, "the replay rule refused an opening packet it had never seen");
				return;
			};
			assert!(matches!(node.open(&packet, &table, &mut again).expect("the same packet opens again").accept(&mut replay, timestamp, |_| panic!("a replay was charged")), Decision::Refused(Refusal::Seen)), "an opening packet was accepted twice");
			assert!((MIN_ITEM..=MAX_ITEM).contains(&opening.datagram.len()) && (mode != 0 || opening.datagram == datagram));
			// Both sides hold the same keys: a data packet each way, the node's no larger than the opening packet it answers.
			let (mut up, mut down, mut sent, mut answer, mut opened) = (Sender::new(keys.c2s, padding(&mut random)), Sender::new(opening.keys.s2c, padding(&mut random)), Vec::new(), Vec::new(), Vec::new());
			up.seal(Some(datagram), flags & 4 != 0, max, &mut random, &mut sent).expect("a data packet seals");
			down.seal(None, flags & 4 != 0, packet.len(), &mut random, &mut answer).expect("a first answer seals");
			assert!(sent.len() <= max && (DATA_MIN..=packet.len()).contains(&answer.len()));
			assert_eq!(Receiver::new(opening.keys.c2s).open(&sent, &mut opened), Ok(Some(datagram)));
			assert_eq!(Receiver::new(keys.s2c).open(&answer, &mut opened), Ok(None));
		}
	}
});
