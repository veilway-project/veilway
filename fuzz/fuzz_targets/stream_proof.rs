#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use veilway_proto::{chunk::{Opener, Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT}, keys::{Device, Table, TagKey}, proof::{public_key, Client, Name, Node, TEXT}, replay::{Decision, Refusal, Replay, Started}, udp_obfs::epochs, NoRandom, Refused};

const INBOUND: [u8; 32] = [0x20; 32];
const DEVICE: [u8; 32] = [0x40; 32];
// The two secrets of the device in the table, and one the node does not have.
const SECRETS: [[u8; 32]; 3] = [[1; 32], [7; 32], [9; 32]];
// The node's transport keys, and one it does not have.
const KEYS: [[u8; 32]; 3] = [[0x61; 32], [0x62; 32], [0x63; 32]];
const TIME: u64 = 1_700_000_000;

// What every input shares, made once: the node with one transport key and with two, the public halves of the keys, the table, with the device tags of both secrets and their epoch tags as a node with a `udp-obfs` transport holds them, and one real token for `tls`.
struct Fixed {nodes: [Node; 2], public: [[u8; 32]; 3], table: Table<Device<usize>>, token: Vec<u8>}

fn fixed() -> &'static Fixed {
	static FIXED: OnceLock<Fixed> = OnceLock::new();
	FIXED.get_or_init(|| {
		let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
			for (index, byte) in bytes.iter_mut().enumerate() {*byte = 0xd0 ^ (index as u8).wrapping_mul(29)}
			Ok(())
		};
		let (public, mut table) = (KEYS.map(|key| public_key(&key)), Table::new());
		for slot in 0..2 {
			let tags = TagKey::derive(&SECRETS[slot], &INBOUND);
			assert!(table.device(tags.device_tag(), Device::derive(slot, &SECRETS[slot], &INBOUND, &DEVICE)));
			for epoch in epochs(TIME) {assert!(table.epoch(tags.epoch_tag(epoch), Device::derive(slot, &SECRETS[slot], &INBOUND, &DEVICE)))}
		}
		let token = Client::new(&public[0], &SECRETS[0], &INBOUND, &DEVICE).prove(Name::Tls, TIME, &mut random).expect("a client seals").token.into_bytes();
		Fixed {nodes: [Node::new(&KEYS[..1], &INBOUND, &mut random).expect("one key"), Node::new(&KEYS[..2], &INBOUND, &mut random).expect("two keys")], public, table, token}
	})
}

// The node's side of the stream proof. Eight bytes of settings, then what the mode says:
//   0  the two low bits are the mode. 0: a real client makes a token, which is changed on the way. 1: the rest is the text of a token, as from a stranger. 2: a client seals the rest as a hello (28 bytes, then padding) with the binder it would compute. 3: the same with the 32 bytes after the first 28 as the binder.
//      bit 2, in modes 2 and 3: the tag in the hello is replaced by the client's own device tag. Bit 4: by its epoch tag, which the table holds as well.
//      bit 3, in mode 1: the rest is not a text but changes to one real token that is made once, three bytes each: where (two bytes), and what is XORed there. This mode costs the node's work alone and no client's, so it runs several times as fast as the others.
//   1  the client: the first secret of a device in the table, its second secret, or a secret the node does not have (by the value modulo 3)
//   2  the transport keys: the node has one, two with the client's first, two with the client's second, or the client's is not among them (modulo 4)
//   3  the transport the client proves for (modulo 3)
//   4  the transport the node opens for (modulo 4, where 3 is a line that cannot be a user's)
//   5  which character of the token is changed
//   6  what is XORed onto it, 0 for no change
//   7  the seed of the client's random bytes, and of its clock
// The outcome is known in advance in every mode but the plain mode 1, and the node must agree: a token opens when the node has the secret and the key, the transports are equal, nothing was changed and the hello is one the specification allows, and in no other case. A token that opens is taken to the replay rule, which must accept it once and give the keys the client has.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, who, keys, proved, opened, at, change, seed], rest)) = data.split_first_chunk::<8>() else {return};
	let (fixed, name) = (fixed(), [Some(Name::Tls), Some(Name::Ws), Some(Name::Fronted), None][usize::from(opened % 4)]);
	let (held, node) = [(0, &fixed.nodes[0]), (0, &fixed.nodes[1]), (1, &fixed.nodes[1]), (2, &fixed.nodes[1])][usize::from(keys % 4)];
	if flags & 3 == 1 {
		let mut text = if flags & 8 == 0 {rest.to_vec()} else {fixed.token.clone()};
		if flags & 8 != 0 {
			for change in rest.chunks_exact(3) {
				let at = usize::from(u16::from_be_bytes([change[0], change[1]])) % text.len();
				text[at] ^= change[2];
			}
		}
		// The one real token is for `tls` under the node's first key, which both nodes have. Every other text is no proof.
		let real = flags & 8 != 0 && text == fixed.token && name == Some(Name::Tls);
		assert_eq!(node.open(name, &text, &fixed.table).map(|opened| (opened.device.id, opened.timestamp, opened.key)), if real {Ok((0, TIME, 0))} else {Err(Refused)}, "a node opened a token no client made, or refused the one a client made");
		return;
	}
	let (slot, proved) = (usize::from(who % 3), Name::ALL[usize::from(proved % 3)]);
	let (client, tags) = (Client::new(&fixed.public[held], &SECRETS[slot], &INBOUND, &DEVICE), TagKey::derive(&SECRETS[slot], &INBOUND));
	let mut random = move |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for (index, byte) in bytes.iter_mut().enumerate() {*byte = seed ^ (index as u8).wrapping_mul(31)}
		Ok(())
	};
	// What the hello holds, and whether the specification allows it: version 1, zero bytes, the client's own device tag, the client's own binder, zero padding.
	let (made, timestamp, allowed) = if flags & 3 == 0 {(client.prove(proved, TIME + u64::from(seed), &mut random), TIME + u64::from(seed), true)} else {
		let (mut head, mut rest) = ([0; 28], rest);
		if let Some((first, tail)) = rest.split_first_chunk::<28>() {(head, rest) = (*first, tail)}
		if flags & 4 != 0 {head[12..].copy_from_slice(&tags.device_tag())}
		if flags & 16 != 0 {head[12..].copy_from_slice(&tags.epoch_tag(epochs(TIME)[1]))}
		let binder = (flags & 3 == 3).then(|| std::array::from_fn(|index| rest.get(index).copied().unwrap_or(0)));
		let padding = &rest[rest.len().min(if binder.is_some() {32} else {0})..];
		let padding = &padding[..padding.len().min(96)];
		(client.forge(proved, &head, binder.as_ref(), padding, &mut random), u64::from_be_bytes(std::array::from_fn(|index| head[4 + index])), binder.is_none() && head[..4] == [1, 0, 0, 0] && head[12..] == tags.device_tag() && padding.iter().all(|byte| *byte == 0))
	};
	let made = made.expect("a client seals");
	assert!(TEXT.contains(&made.token.len()), "a token of {} characters", made.token.len());
	let (mut text, at) = (made.token.clone().into_bytes(), usize::from(at) % made.token.len());
	text[at] ^= change;
	let honest = allowed && slot < 2 && held < 2 && name == Some(proved) && change == 0;
	let Ok(opened) = node.open(name, &text, &fixed.table) else {
		assert!(!honest, "a node refused a proof: secret {slot}, key {held}, {proved:?}");
		return;
	};
	assert!(honest, "a node opened a token it must refuse: secret {slot}, key {held}, {proved:?} opened as {name:?}, change {change:#04x} at {at}");
	assert_eq!((opened.device.id, opened.timestamp, opened.key), (slot, timestamp, held));
	// Steps 5 to 7: a replay memory whose clock is the token's own time accepts it once, after the write its limit needs, and gives the keys the client has. The same token again opens and is refused.
	let Started::NoFile(pending) = Replay::start(None, timestamp.saturating_sub(1000), 4) else {panic!("a start without a file")};
	let mut replay = pending.written();
	let accepted = match opened.accept(&mut replay, timestamp, |device| device.id == slot) {
		Decision::Raise(limit, waiting) => {
			assert!(replay.raise(limit).is_some(), "no file for a limit the rule asked for");
			replay.written();
			waiting.accept(&mut replay, timestamp, |device| device.id == slot)
		}
		decision => decision,
	};
	// A hello may say any time. One in the first minute of time is at the floor of every memory or below it, and every other is accepted.
	let Decision::Accepted(accepted) = accepted else {
		assert!(timestamp < 1060, "the replay rule refused a proof it had never seen");
		return;
	};
	assert_eq!((accepted.device.id, accepted.timestamp, accepted.key, accepted.keys.sid), (slot, timestamp, held, made.keys.sid));
	for (sealing, opening) in [(made.keys.c2s, accepted.keys.c2s), (accepted.keys.s2c, made.keys.s2c)] {
		let (mut sealed, item) = (Vec::new(), [seed; 32]);
		Sealer::new(sealing, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).expect("the default bounds are legal")).seal(&[&item], false, &mut random, &mut sealed).expect("a chunk seals");
		assert!(Opener::new(opening).open(&mut sealed).is_ok_and(|items| items.eq([&item[..]])), "the two sides have different session keys");
	}
	assert!(matches!(node.open(name, &text, &fixed.table).expect("the same token opens again").accept(&mut replay, timestamp, |_| panic!("a replay was charged")), Decision::Refused(Refusal::Seen)), "a proof was accepted twice");
});
