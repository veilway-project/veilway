//! Property tests of the transports' wire formats: what one side makes the other side opens, any changed bit is refused with the one error, a proof belongs to one device, one inbound and one node key and gives its keys only through the replay rule, the replay rule keeps its promises in both directions across every kind of start, and no reader panics on bytes it did not write.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use proptest::{collection::vec, prelude::*, sample::{select, Index}};
use ring::digest::{digest, SHA256};
use std::{collections::HashSet, sync::{Arc, Mutex}};
use veilway_proto::{chunk::{self, Opener as ChunkOpener, Padding, Sealer}, fronted::{self, BodyError}, keys::{ChunkKey, Device, Table, TagKey}, proof::{self, Name}, replay::{self, Decision, Failed, File, FileError, Kind, Pending, Refusal, Replay, Started, Verdict}, request::{Line, Method, Scan, Scanner, LINE_MAX}, udp_obfs, NoRandom, Refused};

const INBOUND: [u8; 32] = [0x10; 32];
const TIME: u64 = 1_700_000_000;
// The largest `udp-obfs` packet of an inbound with an `mtu` of 1390.
const MAX: usize = 1390 + udp_obfs::OVERHEAD;

fn seeded(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> {
	let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
	move |bytes: &mut [u8]| {
		for byte in bytes {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			*byte = (state >> 32) as u8;
		}
		Ok(())
	}
}

// A device is its number: its WireGuard key is that byte 32 times, and its secrets start with the number and with which of the two it is.
fn device_pub(device: u8) -> [u8; 32] {[device; 32]}

fn secret(device: u8, slot: u8) -> [u8; 32] {std::array::from_fn(|index| [device, slot].get(index).copied().unwrap_or(index as u8))}

// The node's one table for these devices, each with two secrets: the device tag of every secret, and its epoch tags around `time`. The id is the device and which of its secrets.
fn table(devices: &[u8], time: u64) -> Table<Arc<Device<(u8, u8)>>> {
	let mut table = Table::new();
	for (device, slot) in devices.iter().flat_map(|device| [(*device, 0), (*device, 1)]) {
		let (tags, entry) = (TagKey::derive(&secret(device, slot), &INBOUND), Arc::new(Device::derive((device, slot), &secret(device, slot), &INBOUND, &device_pub(device))));
		assert!(table.device(tags.device_tag(), entry.clone()), "two tags of one inbound are equal");
		for epoch in udp_obfs::epochs(time) {assert!(table.epoch(tags.epoch_tag(epoch), entry.clone()), "two tags of one inbound are equal")}
	}
	table
}

// A node with the transport keys and the inbound it was made for.
type Made = (Vec<[u8; 32]>, [u8; 32], Arc<proof::Node>);

// A node makes some thousands of dummy keys when it starts, so every node of these tests is made once and kept.
fn node(keys: &[[u8; 32]], inbound: &[u8; 32]) -> Arc<proof::Node> {
	static NODES: Mutex<Vec<Made>> = Mutex::new(Vec::new());
	let mut nodes = NODES.lock().unwrap();
	if let Some((.., node)) = nodes.iter().find(|(made, on, _)| made == keys && on == inbound) {return node.clone()}
	nodes.push((keys.to_vec(), *inbound, Arc::new(proof::Node::new(keys, inbound, &mut seeded(0xd0)).unwrap())));
	nodes[nodes.len() - 1].2.clone()
}

fn padding(seed: u64) -> Padding {Padding::new(chunk::WIDE_DEFAULT, chunk::NORMAL_DEFAULT, &mut seeded(seed)).unwrap()}

// Whether two keys are the same key: what one seals the other opens.
fn same(first: ChunkKey, second: ChunkKey) -> bool {
	let (mut sealed, item) = (Vec::new(), [0x5a; 32]);
	Sealer::new(first, padding(1)).seal(&[&item], false, &mut seeded(2), &mut sealed).unwrap();
	ChunkOpener::new(second).open(&mut sealed).is_ok_and(|items| items.eq([&item[..]]))
}

fn encoded(file: &File) -> Vec<u8> {
	let mut bytes = Vec::new();
	file.encode(&mut bytes).unwrap();
	bytes
}

// A replay file written out by hand, with the hash it should have: the layout of "The replay file", with an entry as its kind, its key and its timestamp.
fn file_bytes(floor: u64, limit: u64, entries: Option<&[(u8, [u8; 32], u64)]>) -> Vec<u8> {
	let mut body = [&b"VWREPLAY"[..], &[0, 0, 0, 1, u8::from(entries.is_some()), 0, 0, 0], &floor.to_be_bytes(), &limit.to_be_bytes(), &(entries.map_or(0, <[_]>::len) as u32).to_be_bytes()].concat();
	for (kind, key, timestamp) in entries.unwrap_or_default() {body.extend([&[*kind][..], key, &timestamp.to_be_bytes()].concat())}
	[&body[..], digest(&SHA256, &body).as_ref()].concat()
}

// A replay memory in use at `now`: started without a file a long time before, with its file written and the limit written as rule 6 keeps it.
fn memory(now: u64, capacity: usize) -> Replay {
	let Started::NoFile(pending) = Replay::start(None, now - 1000, capacity) else {panic!("a start without a file")};
	let mut replay = pending.written();
	assert!(replay.raise(now + replay::STEP).is_some());
	replay.written();
	replay
}

// How a write ends: on disk and reported so, not on disk and reported failed, or reported failed and on disk all the same (the rename was done and the sync of the directory failed, or the write finished after its deadline).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Write {Synced, Lost, FailedButLanded}

// Does to the disk what the outcome says, and says whether the node is told the file is written.
fn put(disk: &mut Vec<u8>, file: &File, write: Write) -> bool {
	if write != Write::Lost {*disk = encoded(file)}
	write == Write::Synced
}

// Writes the file a pending memory asks for, with this outcome. After a reset that is not known to be on disk, the file that puts the old state back fails once more, the other way round, and is then written.
fn settle(disk: &mut Vec<u8>, pending: Pending, write: Write) -> Replay {
	if put(disk, &pending.file(), write) {return pending.written()}
	match pending.failed() {
		Failed::Usable(replay) => replay,
		Failed::Restore(pending) => {
			assert!(!put(disk, &pending.file(), if write == Write::Lost {Write::FailedButLanded} else {Write::Lost}));
			let Failed::Restore(pending) = pending.failed() else {panic!("a reset that is not undone gave a memory")};
			assert!(put(disk, &pending.file(), Write::Synced));
			pending.written()
		}
	}
}

// A start from what is on disk, with this outcome for the file it must write first, if it must.
fn restart(disk: &mut Vec<u8>, now: u64, capacity: usize, write: Write) -> Replay {
	match Replay::start(File::decode(disk, capacity).ok(), now, capacity) {
		Started::Unclean(replay) => replay,
		Started::Clean(pending) | Started::NoFile(pending) => settle(disk, pending, write),
	}
}

// The request line rule written a second time, over a whole prefix: what the scanner must say once it has read exactly these bytes and had said `More` before.
fn line_rule(bytes: &[u8]) -> Scan {
	let target = |byte: &u8| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?%".contains(byte);
	let fits = b"GET /".starts_with(bytes) || b"POST /".starts_with(bytes) || bytes.strip_prefix(b"GET /").or(bytes.strip_prefix(b"POST /")).is_some_and(|rest| {
		let end = rest.iter().position(|byte| *byte == b' ').unwrap_or(rest.len());
		rest[..end].iter().all(target) && b" HTTP/1.1\r\n".starts_with(&rest[end..])
	});
	if !fits {Scan::Forward} else if bytes.ends_with(b" HTTP/1.1\r\n") {Scan::Line(bytes.len())} else if bytes.len() >= LINE_MAX {Scan::Forward} else {Scan::More}
}

// Bytes that are a request line, nearly one, or nothing like one.
fn line_bytes() -> impl Strategy<Value = Vec<u8>> {
	let line = (select(vec!["GET ", "POST ", "GET", "PUT ", "get "]), "/[A-Za-z0-9._~!$&'()*+,;=:@/?%-]{0,60}", select(vec![" HTTP/1.1\r\n", " HTTP/1.1\n", " HTTP/1.0\r\n", "\r\n", " HTTP/1.1\r\nHost: example.com\r\n\r\n"])).prop_map(|(method, target, ending)| [method, &target, ending].concat().into_bytes());
	prop_oneof![4 => line.clone(), 3 => (line, any::<Index>(), any::<u8>()).prop_map(|(mut line, at, value)| {
		let at = at.index(line.len());
		line[at] = value;
		line
	}), 1 => vec(any::<u8>(), 0..80)]
}

// What happens to a node between proofs. Every event that makes the node write a file says how that write ends.
#[derive(Debug, Clone)]
enum Event {
	// A proof: one of a few keys or a key nobody used before, of either kind, at an offset from the node's clock, whether the node's limits have room for it, and how the write ends that it may need.
	Proof {key: Option<u8>, opening: bool, offset: i64, room: bool, write: Write},
	// The wall clock steps, forward or back.
	Clock(i64),
	// The node's timer runs.
	Tick(Write),
	// A clean stop and a start.
	Stop(Write),
	// A clean stop, a start that is killed before it has written the file again, and another start.
	StopKilled(Write),
	// A crash and a start.
	Crash(Write),
	// A start with no usable replay file, at a moment the clock is not behind where it has been.
	Lose(Write),
	// `veilway replay reset`.
	Reset(Write),
}

fn events() -> impl Strategy<Value = Vec<Event>> {
	let write = || prop_oneof![6 => Just(Write::Synced), 1 => Just(Write::Lost), 1 => Just(Write::FailedButLanded)];
	let proof = (prop_oneof![3 => (0u8..6).prop_map(Some), 1 => Just(None)], any::<bool>(), prop_oneof![3 => -5i64..=10, 2 => -70i64..=70], prop_oneof![9 => Just(true), 1 => Just(false)], write()).prop_map(|(key, opening, offset, room, write)| Event::Proof {key, opening, offset, room, write});
	vec(prop_oneof![14 => proof, 4 => prop_oneof![4 => 0i64..50, 1 => -200i64..400, 1 => 80_000i64..90_000, 1 => -90_000i64..-80_000].prop_map(Event::Clock), 3 => write().prop_map(Event::Tick), 2 => write().prop_map(Event::Stop), 1 => write().prop_map(Event::StopKilled), 2 => write().prop_map(Event::Crash), 1 => write().prop_map(Event::Lose), 2 => write().prop_map(Event::Reset)], 0..150)
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(256))]

	// Rotation: an inbound with one or two transport keys and devices with two secrets each. Whatever key and secret a client holds, the node opens its token and says which they were, and the session keys come out of the replay rule.
	#[test]
	fn a_token_opens_for_its_device_under_any_key_and_secret(node_keys in select(vec![vec![[0x61; 32]], vec![[0x61; 32], [0x62; 32]], vec![[0x62; 32], [0x61; 32]], vec![[0x00; 32], [0xff; 32]]]), held in any::<Index>(), devices in vec(1u8..=250, 1..4), who in any::<Index>(), slot in 0u8..2, name in select(Name::ALL.to_vec()), seed in any::<u64>()) {
		let devices: Vec<u8> = devices.into_iter().collect::<HashSet<_>>().into_iter().collect();
		let (held, device, table, mut replay) = (held.index(node_keys.len()), devices[who.index(devices.len())], table(&devices, TIME), memory(TIME, 16));
		let node = node(&node_keys, &INBOUND);
		let made = proof::Client::new(&proof::public_key(&node_keys[held]), &secret(device, slot), &INBOUND, &device_pub(device)).prove(name, TIME, &mut seeded(seed)).unwrap();
		prop_assert!(proof::TEXT.contains(&made.token.len()) && made.token.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
		let bytes = URL_SAFE_NO_PAD.decode(&made.token).unwrap();
		prop_assert!(proof::TOKEN.contains(&bytes.len()) && URL_SAFE_NO_PAD.encode(&bytes) == made.token);
		let opened = node.open(Some(name), made.token.as_bytes(), &table).unwrap();
		prop_assert_eq!((opened.device.id, opened.device.public, opened.timestamp, opened.key), ((device, slot), device_pub(device), TIME, held));
		let Decision::Accepted(accepted) = opened.accept(&mut replay, TIME, |charged| charged.id == (device, slot)) else {panic!("a proof was not accepted")};
		prop_assert_eq!((accepted.device.id, accepted.timestamp, accepted.key, accepted.keys.sid), ((device, slot), TIME, held, made.keys.sid));
		prop_assert!(same(made.keys.c2s, accepted.keys.c2s) && same(accepted.keys.s2c, made.keys.s2c));
		// The same token again opens and is refused by the replay rule, before the limits are asked.
		prop_assert!(matches!(node.open(Some(name), made.token.as_bytes(), &table).unwrap().accept(&mut replay, TIME + 1, |_| panic!("a replay was charged")), Decision::Refused(Refusal::Seen)));
		// "A proof made for one transport is not valid on another", and a line that cannot be a user's is refused whatever its token.
		for other in Name::ALL.into_iter().filter(|other| *other != name).map(Some).chain([None]) {prop_assert_eq!(node.open(other, made.token.as_bytes(), &table).map(|opened| opened.device.id), Err(Refused))}
	}

	#[test]
	fn any_changed_bit_of_a_token_is_refused(seed in any::<u64>(), slot in 0u8..2, at in any::<Index>(), bit in 0u8..8, text_at in any::<Index>(), text_bit in 0u8..7) {
		let (node, table) = (node(&[[0x61; 32], [0x62; 32]], &INBOUND), table(&[1, 2], TIME));
		let token = proof::Client::new(&proof::public_key(&[0x62; 32]), &secret(1, slot), &INBOUND, &device_pub(1)).prove(Name::Ws, TIME, &mut seeded(seed)).unwrap().token;
		let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
		let at = at.index(bytes.len());
		bytes[at] ^= 1 << bit;
		prop_assert_eq!(node.open(Some(Name::Ws), URL_SAFE_NO_PAD.encode(&bytes).as_bytes(), &table).map(|opened| opened.device.id), Err(Refused));
		// `enc` has one encoding: X25519 does not read its top bit, and the token with that bit changed is no proof all the same, since HPKE hashes the bytes of `enc` as they were sent.
		bytes[at] ^= 1 << bit;
		bytes[31] ^= 0x80;
		prop_assert_eq!(node.open(Some(Name::Ws), URL_SAFE_NO_PAD.encode(&bytes).as_bytes(), &table).map(|opened| opened.device.id), Err(Refused));
		// A changed bit of the text, whether or not what it gives is still base64url.
		let mut text = token.clone().into_bytes();
		let at = text_at.index(text.len());
		text[at] ^= 1 << text_bit;
		prop_assert_eq!(node.open(Some(Name::Ws), &text, &table).map(|opened| opened.device.id), Err(Refused));
		// Cut short, or with more at its end.
		prop_assert_eq!(node.open(Some(Name::Ws), &token.as_bytes()[..at], &table).map(|opened| opened.device.id), Err(Refused));
		prop_assert_eq!(node.open(Some(Name::Ws), &[token.as_bytes(), &text[..at.max(1)]].concat(), &table).map(|opened| opened.device.id), Err(Refused));
		prop_assert_eq!(node.open(Some(Name::Ws), token.as_bytes(), &table).map(|opened| opened.device.id), Ok((1, slot)));
	}

	// The token is base64url "in its one canonical form": a last character with bits that belong to no byte is refused, so one token has one text.
	#[test]
	fn a_token_has_one_text(seed in any::<u64>(), extra in 1u8..16) {
		let (node, table) = (node(&[[0x61; 32]], &INBOUND), table(&[1], TIME));
		let client = proof::Client::new(&proof::public_key(&[0x61; 32]), &secret(1, 0), &INBOUND, &device_pub(1));
		// A token whose length leaves unused bits in its last character: 2 bits or 4.
		let token = (0..).map(|round| client.prove(Name::Tls, TIME, &mut seeded(seed.wrapping_add(round))).unwrap().token).find(|token| token.len() % 4 != 0).unwrap();
		prop_assert!(node.open(Some(Name::Tls), token.as_bytes(), &table).is_ok());
		let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		let (mut other, unused) = (token.clone().into_bytes(), if token.len() % 4 == 2 {4} else {2});
		let last = alphabet.iter().position(|letter| *letter == other[other.len() - 1]).unwrap();
		prop_assert_eq!(last & ((1 << unused) - 1), 0);
		*other.last_mut().unwrap() = alphabet[last | usize::from(extra) & ((1 << unused) - 1) | usize::from(extra & ((1 << unused) - 1) == 0)];
		prop_assert_eq!(node.open(Some(Name::Tls), &other, &table).map(|opened| opened.device.id), Err(Refused));
		// With padding characters it is no token either.
		prop_assert_eq!(node.open(Some(Name::Tls), format!("{token}=").as_bytes(), &table).map(|opened| opened.device.id), Err(Refused));
	}

	// "Knowing a device's tag, or a node's transport private key, is not enough to make a proof."
	#[test]
	fn a_proof_of_one_device_is_none_for_another_device_inbound_or_node(seed in any::<u64>(), slot in 0u8..2, name in select(Name::ALL.to_vec())) {
		let (node_key, other_key) = ([0x61; 32], [0x62; 32]);
		let token = proof::Client::new(&proof::public_key(&node_key), &secret(1, slot), &INBOUND, &device_pub(1)).prove(name, TIME, &mut seeded(seed)).unwrap().token;
		let open = |keys: &[[u8; 32]], inbound: &[u8; 32], tags: &Table<Arc<Device<(u8, u8)>>>| node(keys, inbound).open(Some(name), token.as_bytes(), tags).map(|opened| opened.device.id);
		prop_assert_eq!(open(&[node_key], &INBOUND, &table(&[1, 2], TIME)), Ok((1, slot)));
		// A node that does not have the device, one with another transport key, and the same keys on another inbound.
		prop_assert_eq!(open(&[node_key], &INBOUND, &table(&[2, 3], TIME)), Err(Refused));
		prop_assert_eq!(open(&[other_key], &INBOUND, &table(&[1, 2], TIME)), Err(Refused));
		prop_assert_eq!(open(&[node_key], &[0x11; 32], &table(&[1, 2], TIME)), Err(Refused));
		// The table says the tag is device 2's: device 1's secret under device 2's WireGuard key. The binder key depends on that key, so the proof is no proof of device 2.
		let (tag, mut moved, mut stolen, mut epochs) = (TagKey::derive(&secret(1, slot), &INBOUND).device_tag(), Table::new(), Table::new(), Table::new());
		prop_assert!(moved.device(tag, Arc::new(Device::derive((2, slot), &secret(1, slot), &INBOUND, &device_pub(2)))));
		prop_assert_eq!(open(&[node_key], &INBOUND, &moved), Err(Refused));
		// The same tag with device 2's own secret behind it: a tag alone proves nothing.
		prop_assert!(stolen.device(tag, Arc::new(Device::derive((2, slot), &secret(2, slot), &INBOUND, &device_pub(1)))));
		prop_assert_eq!(open(&[node_key], &INBOUND, &stolen), Err(Refused));
		// The device's own entry, filed as an epoch tag: "A device tag is valid only in a stream proof and an epoch tag only on an opening packet. The other kind in either place is a miss."
		prop_assert!(epochs.epoch(tag, Arc::new(Device::derive((1, slot), &secret(1, slot), &INBOUND, &device_pub(1)))));
		prop_assert_eq!(open(&[node_key], &INBOUND, &epochs), Err(Refused));
		// A client that holds a secret and a key of zero bytes, from which the node's dummy key was once made.
		let zero = proof::Client::new(&proof::public_key(&node_key), &[0; 32], &INBOUND, &[0; 32]).prove(name, TIME, &mut seeded(seed)).unwrap().token;
		prop_assert_eq!(node(&[node_key], &INBOUND).open(Some(name), zero.as_bytes(), &table(&[1, 2], TIME)).map(|opened| opened.device.id), Err(Refused));
	}

	#[test]
	fn random_text_is_never_a_proof(bytes in prop_oneof![vec(any::<u8>(), 0..300), "[A-Za-z0-9_-]{140,275}".prop_map(String::into_bytes), vec(any::<u8>(), 108..=204).prop_map(|bytes| URL_SAFE_NO_PAD.encode(bytes).into_bytes())], name in select(Name::ALL.to_vec())) {
		let (node, table) = (node(&[[0x61; 32], [0x62; 32]], &INBOUND), table(&[1, 2], TIME));
		prop_assert_eq!(node.open(Some(name), &bytes, &table).map(|opened| opened.device.id), Err(Refused));
	}

	#[test]
	fn an_opening_packet_starts_a_session_for_its_device(devices in vec(1u8..=250, 1..4), who in any::<Index>(), slot in 0u8..2, shift in -120i64..=120, datagram in vec(any::<u8>(), 32..=1300), reply in proptest::option::of(vec(any::<u8>(), 32..=92)), seed in any::<u64>()) {
		let devices: Vec<u8> = devices.into_iter().collect::<HashSet<_>>().into_iter().collect();
		let (device, mut packet, mut scratch, mut again) = (devices[who.index(devices.len())], vec![0xee], Vec::new(), Vec::new());
		// The node's clock is up to one epoch away from the client's, and its table holds the epochs around its own. The timestamp is then outside the window, so this node's replay memory is set at the client's time.
		let (table, mut random, mut replay) = (table(&devices, TIME.wrapping_add_signed(shift)), seeded(seed), memory(TIME, 16));
		let keys = udp_obfs::Client::new(&secret(device, slot), &INBOUND).open(TIME, &datagram, &padding(seed), MAX, &mut random, &mut packet).unwrap();
		prop_assert!(packet[0] == 0xee && packet.len() > udp_obfs::OPENING_MIN + 2 + datagram.len() && packet.len() - 1 <= MAX);
		let opening = udp_obfs::Node::new(&INBOUND).open(&packet[1..], &table, &mut scratch).unwrap();
		prop_assert_eq!((opening.device.id, opening.timestamp), ((device, slot), TIME));
		let Decision::Accepted(opening) = opening.accept(&mut replay, TIME, |charged| charged.id == (device, slot)) else {panic!("an opening packet was not accepted")};
		prop_assert_eq!((opening.device.id, opening.timestamp, opening.datagram), ((device, slot), TIME, &datagram[..]));
		// The packet again, as from another address: it opens, and the replay rule refuses it before the limits are asked.
		prop_assert!(matches!(udp_obfs::Node::new(&INBOUND).open(&packet[1..], &table, &mut again).unwrap().accept(&mut replay, TIME + 1, |_| panic!("a replay was charged")), Decision::Refused(Refusal::Seen)));
		// Data packets in both directions under the session's keys. The node's first answer is no larger than the opening packet.
		let (mut up, mut down, mut sent, mut answer, mut opened) = (udp_obfs::Sender::new(keys.c2s, padding(seed)), udp_obfs::Receiver::new(keys.s2c), Vec::new(), Vec::new(), Vec::new());
		let (mut node_up, mut node_down) = (udp_obfs::Receiver::new(opening.keys.c2s), udp_obfs::Sender::new(opening.keys.s2c, padding(!seed)));
		node_down.seal(reply.as_deref(), reply.is_some(), packet.len() - 1, &mut random, &mut answer).unwrap();
		prop_assert!(answer.len() < packet.len() && answer.len() >= udp_obfs::DATA_MIN + reply.as_ref().map_or(0, |reply| 2 + reply.len()));
		prop_assert_eq!(down.open(&answer, &mut opened), Ok(reply.as_deref()));
		up.seal(Some(&datagram), false, MAX, &mut random, &mut sent).unwrap();
		prop_assert!(sent.len() <= MAX);
		prop_assert_eq!(node_up.open(&sent, &mut opened), Ok(Some(&datagram[..])));
		// Each direction has its own key, and an opening packet is no data packet.
		prop_assert_eq!(down.open(&sent, &mut opened), Err(Refused));
		prop_assert_eq!(node_up.open(&answer, &mut opened), Err(Refused));
		prop_assert_eq!(node_up.open(&packet[1..], &mut opened), Err(Refused));
		prop_assert_eq!((up.sent(), node_down.sent(), down.received(), node_up.received()), (1, 1, 1, 1));
	}

	#[test]
	fn any_changed_bit_of_a_udp_obfs_packet_is_refused(seed in any::<u64>(), slot in 0u8..2, datagram in vec(any::<u8>(), 32..=200), at in any::<Index>(), bit in 0u8..8, cut in any::<Index>()) {
		let (table, mut packet, mut data, mut scratch, mut random, mut replay) = (table(&[1, 2], TIME), Vec::new(), Vec::new(), Vec::new(), seeded(seed), memory(TIME, 16));
		let keys = udp_obfs::Client::new(&secret(1, slot), &INBOUND).open(TIME, &datagram, &padding(seed), MAX, &mut random, &mut packet).unwrap();
		let node = udp_obfs::Node::new(&INBOUND);
		let mut changed = packet.clone();
		changed[at.index(packet.len())] ^= 1 << bit;
		prop_assert_eq!(node.open(&changed, &table, &mut scratch).map(|opening| opening.device.id), Err(Refused));
		prop_assert_eq!(node.open(&packet[..cut.index(packet.len())], &table, &mut scratch).map(|opening| opening.device.id), Err(Refused));
		prop_assert_eq!(node.open(&[&packet[..], &[0]].concat(), &table, &mut scratch).map(|opening| opening.device.id), Err(Refused));
		// A device that is not in the table, another inbound, and an epoch the table does not hold.
		prop_assert_eq!(node.open(&packet, &self::table(&[2, 3], TIME), &mut scratch).map(|opening| opening.device.id), Err(Refused));
		prop_assert_eq!(udp_obfs::Node::new(&[0x11; 32]).open(&packet, &table, &mut scratch).map(|opening| opening.device.id), Err(Refused));
		prop_assert_eq!(node.open(&packet, &self::table(&[1, 2], TIME + 2 * udp_obfs::EPOCH), &mut scratch).map(|opening| opening.device.id), Err(Refused));
		// The table holds this device's epoch tags filed as device tags, and nothing else: an opening packet finds no device there.
		let (tags, mut streams) = (TagKey::derive(&secret(1, slot), &INBOUND), Table::new());
		for epoch in udp_obfs::epochs(TIME) {prop_assert!(streams.device(tags.epoch_tag(epoch), Arc::new(Device::derive((1, slot), &secret(1, slot), &INBOUND, &device_pub(1)))))}
		prop_assert_eq!(node.open(&packet, &streams, &mut scratch).map(|opening| opening.device.id), Err(Refused));
		let Decision::Accepted(opening) = node.open(&packet, &table, &mut scratch).unwrap().accept(&mut replay, TIME, |_| true) else {panic!("an opening packet was not accepted")};
		prop_assert_eq!(opening.device.id, (1, slot));
		let mut receiver = udp_obfs::Receiver::new(opening.keys.c2s);
		udp_obfs::Sender::new(keys.c2s, padding(seed)).seal(Some(&datagram), true, MAX, &mut random, &mut data).unwrap();
		let (mut changed, mut opened) = (data.clone(), Vec::new());
		changed[at.index(data.len())] ^= 1 << bit;
		prop_assert_eq!(receiver.open(&changed, &mut opened), Err(Refused));
		prop_assert_eq!(receiver.open(&data[..cut.index(data.len())], &mut opened), Err(Refused));
		prop_assert_eq!(receiver.open(&[&data[..], &[0]].concat(), &mut opened), Err(Refused));
		prop_assert_eq!(receiver.open(&data, &mut opened), Ok(Some(&datagram[..])));
	}

	#[test]
	fn random_bytes_are_never_a_udp_obfs_packet(bytes in vec(any::<u8>(), 0..400)) {
		let (table, mut scratch) = (table(&[1, 2], TIME), Vec::new());
		prop_assert_eq!(udp_obfs::Node::new(&INBOUND).open(&bytes, &table, &mut scratch).map(|opening| opening.device.id), Err(Refused));
		prop_assert_eq!(udp_obfs::Receiver::new(ChunkKey::new(&[7; 32])).open(&bytes, &mut scratch), Err(Refused));
	}

	// The replay rule through clock steps in both directions, clock faults of a day, writes that fail and every kind of start. Nothing here repeats the rule: each assertion is a promise of the specification, checked from outside.
	// Safety: no proof is ever accepted twice, none outside the window or at or below the floor, and none above a limit that is not on disk.
	// Liveness: since the last reset or lost file, the floor is never more than `W` plus the step above the highest clock value seen unless a proof with such a timestamp was accepted, a proof nobody has used and nothing forbids is not refused, on a node whose timer keeps the limit written an honest proof never waits for a write, and after the timer has run the limit on disk is no further ahead than the window, the floor or an accepted proof put it.
	// Every write the node is asked for ends in one of three ways, and the promises hold for each: written, failed, and reported failed with the file on disk all the same.
	#[test]
	fn the_replay_rule_keeps_its_promises_in_both_directions(events in events(), capacity in 1usize..5, attentive in any::<bool>()) {
		let (mut now, mut latest, mut spent, mut highest, mut fresh, mut disk) = (TIME, TIME, HashSet::new(), 0u64, 0u64, Vec::new());
		// What is on disk is `disk`: the last file whose write landed, whatever the node was told about it.
		let mut replay = restart(&mut disk, now, capacity, Write::Synced);
		for event in events {
			match event {
				Event::Proof {key, opening, offset, room, write} => {
					let (kind, timestamp, unused) = (if opening {Kind::Opening} else {Kind::Stream}, now.wrapping_add_signed(offset), key.is_none());
					let key: [u8; 32] = key.map_or_else(|| {
						fresh += 1;
						std::array::from_fn(|index| if index < 8 {fresh.to_be_bytes()[index]} else {0xf5})
					}, |fill| [fill; 32]);
					let (floor, limit, len, mut charged) = (replay.floor(), replay.limit(), replay.len(), 0);
					let mut verdict = replay.accept(kind, &key, timestamp, now, || {
						charged += 1;
						room
					});
					let honest = timestamp.abs_diff(now) <= replay::WINDOW && timestamp > replay.floor();
					if let Verdict::Raise(wanted) = verdict {
						prop_assert!(charged == 0 && timestamp > limit && wanted == timestamp + replay::STEP && honest && !spent.contains(&(kind, key, timestamp)), "a write was asked for a proof that needs none");
						// An honest proof "never waits for a write" where the node's timer keeps the limit written.
						prop_assert!(!attentive || offset > replay::AHEAD as i64, "a proof {} s from the clock met Raise", offset);
						let file = replay.raise(wanted).expect("no file is out, and the limit is below what was asked for");
						prop_assert!(file.limit() == wanted && replay.raise(wanted).is_none() && replay.timer(now).is_none(), "a second file was handed out while one was out");
						if put(&mut disk, &file, write) {replay.written()} else {replay.failed()}
						verdict = replay.accept(kind, &key, timestamp, now, || {
							charged += 1;
							room
						});
						// The proof is accepted once its limit is on disk, and waits on while the node only knows that the write failed.
						prop_assert!(if write == Write::Synced {matches!(verdict, Verdict::Accept | Verdict::Refuse(Refusal::Limited))} else {verdict == Verdict::Raise(wanted)}, "a proof whose limit write ended as {:?} met {:?}", write, verdict);
					}
					// The limits are asked exactly when the rule itself has nothing against the proof.
					prop_assert_eq!(charged, usize::from(matches!(verdict, Verdict::Accept | Verdict::Refuse(Refusal::Limited))));
					match verdict {
						Verdict::Accept => {
							prop_assert!(room && honest && timestamp > floor, "a proof outside the rule was accepted");
							prop_assert!(spent.insert((kind, key, timestamp)), "a proof was accepted twice");
							// "The limit is a number the node has written to its replay file and synced, before it relies on it."
							prop_assert!(File::decode(&disk, capacity).is_ok_and(|file| file.limit() >= timestamp), "a proof above the limit on disk was accepted");
							highest = highest.max(timestamp);
						}
						Verdict::Refuse(Refusal::Limited) => prop_assert!(!room && replay.len() <= len, "limits without room recorded a proof"),
						// A proof nobody has used, inside the window, above the floor, with room in the cache: nothing forbids it.
						Verdict::Refuse(refusal) => prop_assert!(!(unused && honest && len < capacity), "an unused proof that nothing forbids met {:?}", refusal),
						Verdict::Raise(_) => prop_assert!(write != Write::Synced),
					}
				}
				Event::Clock(step) => {
					now = now.wrapping_add_signed(step);
					latest = latest.max(now);
				}
				Event::Tick(_) => {}
				// The start writes the file again without its mark. If that fails the cache is forgotten, and the clean file may still be the one on disk.
				Event::Stop(write) => {
					disk = encoded(&replay.stop());
					replay = restart(&mut disk, now, capacity, write);
				}
				Event::StopKilled(write) => {
					disk = encoded(&replay.stop());
					prop_assert!(matches!(Replay::start(File::decode(&disk, capacity).ok(), now, capacity), Started::Clean(_)));
					replay = restart(&mut disk, now, capacity, write);
				}
				// Without a file nothing is known but the clock, so that start protects only when the clock is not behind where it has been. A crash finds no file when the first write of such a start was lost.
				Event::Crash(write) => {
					if File::decode(&disk, capacity).is_err() {(now, highest) = (latest, 0)}
					replay = restart(&mut disk, now, capacity, write);
				}
				Event::Lose(write) => {
					(now, highest) = (latest, 0);
					disk.clear();
					replay = restart(&mut disk, now, capacity, write);
					prop_assert_eq!((replay.floor(), replay.limit(), replay.len()), (now + replay::WINDOW, now + replay::WINDOW, 0));
				}
				// What was accepted above the new floor is forgotten, which is the stated cost of the command. A reset whose write is not known to be on disk has not happened: the old floor and limit are written back before anything else, and nothing is forgotten.
				Event::Reset(write) => {
					let before = (replay.floor(), replay.limit(), replay.len());
					replay = settle(&mut disk, replay.reset(now), write);
					if write == Write::Synced {
						spent.retain(|(_, _, timestamp)| *timestamp <= now + replay::WINDOW);
						// From here the clock and the proofs of before the reset excuse nothing: a floor above this moment's window has to be earned again.
						(latest, highest) = (now, 0);
					}
					prop_assert_eq!((replay.floor(), replay.limit(), replay.len()), if write == Write::Synced {(now + replay::WINDOW, now + replay::WINDOW, 0)} else {before});
					prop_assert!(File::decode(&disk, capacity).is_ok_and(|file| file.limit() == replay.limit() && file.floor() == replay.floor()), "after a reset the disk does not hold what the memory holds");
				}
			}
			// The node's timer, with a disk that works where the node is said to keep its limit written.
			if let Some(write) = match event {Event::Tick(write) => Some(write), _ => attentive.then_some(Write::Synced)} {
				let synced = replay.timer(now).is_none_or(|file| {
					let synced = put(&mut disk, &file, write);
					if synced {replay.written()} else {replay.failed()}
					synced
				});
				if synced {
					// Rule 6: the limit is at least 10 s above the clock.
					prop_assert!(replay.limit() >= now + replay::AHEAD, "the limit is {} s above the clock after the timer ran", replay.limit().saturating_sub(now));
					// And the limit that may be on disk is no further ahead than the window, the floor or an accepted proof put it: what a wrong clock alone raised has come down.
					let top = spent.iter().map(|(_, _, timestamp)| *timestamp).max().unwrap_or(0);
					prop_assert!(replay.disk() <= (now + replay::WINDOW).max(replay.floor()).max(top) + replay::STEP, "the limit on disk is {} s ahead of the clock, and nothing accepted holds it there", replay.disk() - now);
				}
			}
			// The limit in use is never above the limit on disk, whatever the node was told about its writes, and the cache never holds more than it may.
			prop_assert!(File::decode(&disk, capacity).map_or(disk.is_empty(), |file| file.limit() >= replay.limit()) && replay.limit() <= replay.disk() && replay.len() <= capacity, "the limit in use is above the limit on disk");
			// "A node that crashes and restarts in a loop" does not raise its floor, and neither does anything else that is no accepted proof and no clock value since the last reset.
			prop_assert!(replay.floor() <= (latest + replay::WINDOW).max(highest) + replay::STEP, "the floor is {} s above the highest clock value seen since the last reset, and no proof that high was accepted", replay.floor() - latest);
		}
		// Every proof that was ever accepted, shown again at any moment near its timestamp and now: refused.
		for (kind, key, timestamp) in spent {
			for shown in [timestamp.saturating_sub(replay::WINDOW), timestamp, timestamp + replay::WINDOW, now] {prop_assert!(matches!(replay.accept(kind, &key, timestamp, shown, || true), Verdict::Refuse(_)), "a proof was accepted again")}
		}
	}

	#[test]
	fn a_replay_file_reads_back_and_nothing_else_reads(floor in any::<u64>(), limit in any::<u64>(), entries in proptest::option::of(vec((1u8..=2, any::<[u8; 32]>(), any::<u64>()), 0..12)), cut in any::<Index>(), at in any::<Index>(), bit in 0u8..8, junk in vec(any::<u8>(), 1..200), bad in any::<Index>()) {
		// Entries as a node writes them: of a known kind, with timestamps at or below the limit.
		let entries: Option<Vec<(u8, [u8; 32], u64)>> = entries.map(|entries| entries.into_iter().map(|(kind, key, back)| (kind, key, limit.saturating_sub(back % 100))).collect());
		let (bytes, count) = (file_bytes(floor, limit, entries.as_deref()), entries.as_ref().map_or(0, Vec::len));
		prop_assert_eq!(bytes.len(), 68 + 41 * count);
		let file = File::decode(&bytes, count).unwrap();
		prop_assert_eq!((file.floor(), file.limit(), file.clean(), file.len()), (floor, limit, entries.is_some(), count));
		prop_assert_eq!(encoded(&file), bytes.clone());
		if let Some(entries) = entries.as_ref().filter(|entries| !entries.is_empty()) {
			prop_assert_eq!(File::decode(&bytes, count - 1), Err(FileError::Count));
			// One entry of a kind that is not defined, or with a timestamp above the limit: no node writes it, so the file is not one.
			let (mut unknown, mut above, bad) = (entries.clone(), entries.clone(), bad.index(count));
			unknown[bad].0 = 3;
			prop_assert_eq!(File::decode(&file_bytes(floor, limit, Some(&unknown)), count), Err(FileError::Entry));
			above[bad].2 = limit.saturating_add(1);
			prop_assert_eq!(File::decode(&file_bytes(floor, limit, Some(&above)), count).err(), (limit < u64::MAX).then_some(FileError::Entry));
		}
		// Cut at any length, one bit changed, bytes added, or random bytes: a typed error, never a file.
		prop_assert!(File::decode(&bytes[..cut.index(bytes.len())], 64).is_err());
		for size in 0..bytes.len().min(140) {prop_assert!(File::decode(&bytes[..size], 64).is_err())}
		let mut changed = bytes.clone();
		changed[at.index(bytes.len())] ^= 1 << bit;
		prop_assert!(File::decode(&changed, 64).is_err());
		prop_assert!(File::decode(&[&bytes[..], &junk[..]].concat(), 64).is_err());
		prop_assert!(File::decode(&junk, 64).is_err());
		prop_assert!(File::decode(&[&replay::MARKER[..], &[0, 0, 0, 1], &junk].concat(), 64).is_err());
		// A start from the file: the cache comes back only from a clean one, the floor never below the file's, the limit as it is on disk, or as the clock asks for it in the file a clean start writes first.
		match Replay::start(Some(file), TIME, 64) {
			Started::Clean(pending) => {
				prop_assert!(entries.is_some() && pending.file().limit() == limit.max(TIME + replay::STEP) && pending.file().floor() == floor && !pending.file().clean());
				let replay = pending.written();
				prop_assert!(replay.floor() == floor && replay.limit() == limit.max(TIME + replay::STEP) && replay.len() <= count);
			}
			Started::Unclean(replay) => prop_assert!(entries.is_none() && replay.floor() == floor.max(limit) && replay.limit() == limit && replay.is_empty()),
			Started::NoFile(_) => prop_assert!(false, "a file that decoded was taken for no file"),
		}
	}

	#[test]
	fn the_scanner_follows_the_request_line_rule_however_the_bytes_arrive(bytes in line_bytes(), cuts in vec(any::<Index>(), 0..6)) {
		let (mut scanner, mut expected) = (Scanner::new(), Scan::More);
		for size in 1..=bytes.len() {
			if expected == Scan::More {expected = line_rule(&bytes[..size])}
			prop_assert_eq!(scanner.feed(&bytes[size - 1..size]), expected, "after {} bytes", size);
		}
		let mut ends: Vec<usize> = cuts.iter().map(|cut| cut.index(bytes.len() + 1)).chain([bytes.len()]).collect();
		ends.sort_unstable();
		let (mut pieces, mut start, mut scan) = (Scanner::new(), 0, Scan::More);
		for end in ends {
			scan = pieces.feed(&bytes[start..end]);
			start = end;
		}
		prop_assert_eq!(scan, expected);
		match expected {
			Scan::Line(size) => {
				let line = Line::parse(&bytes[..size]).unwrap();
				let (method, target) = if bytes[0] == b'G' {(Method::Get, &bytes[4..size - 11])} else {(Method::Post, &bytes[5..size - 11])};
				prop_assert_eq!(line.method, method);
				prop_assert_eq!(line.query.map_or(line.path.to_vec(), |query| [line.path, query].join(&b"?"[..])), target);
				prop_assert!(line.path.starts_with(b"/") && !line.path.contains(&b'?') && line.path_is(line.path) && !line.path_is(&line.path[1..]));
				// Among several paths the answer is the place of the first that is equal, whatever stands before and after it.
				prop_assert_eq!((line.path_among(&[&line.path[1..], line.path, b"/", line.path]), line.path_among(&[&line.path[1..], &[line.path, b"/"].concat()])), (Some(1), None));
				prop_assert!(size == bytes.len() || Line::parse(&bytes).is_none());
			}
			_ => prop_assert!(Line::parse(&bytes).is_none()),
		}
	}

	#[test]
	fn a_long_line_is_forwarded_at_the_limit(size in LINE_MAX - 40..LINE_MAX + 40, fill in select(b"aZ9/?%._~-".to_vec())) {
		let bytes = [&b"POST /"[..], &vec![fill; size - 17], b" HTTP/1.1\r\n"].concat();
		prop_assert_eq!(Scanner::new().feed(&bytes), if size <= LINE_MAX {Scan::Line(size)} else {Scan::Forward});
		prop_assert_eq!(Scanner::new().feed(&bytes[..size - 1]), if size <= LINE_MAX {Scan::More} else {Scan::Forward});
	}

	#[test]
	fn the_query_of_a_later_request_has_one_text(sid in any::<[u8; 16]>(), number in prop_oneof![1u32..20, any::<u32>()], bytes in prop_oneof![vec(any::<u8>(), 0..40), "[A-Za-z0-9_-]{20,23}\\.[0-9]{0,12}".prop_map(String::into_bytes)]) {
		match fronted::later_query(&sid, number) {
			Some(query) => prop_assert_eq!(fronted::later(query.as_bytes()), Some((sid, number))),
			None => prop_assert_eq!(number, 0),
		}
		if let Some((sid, number)) = fronted::later(&bytes) {prop_assert_eq!(fronted::later_query(&sid, number).map(String::into_bytes), Some(bytes))}
	}

	#[test]
	fn a_fronted_body_opens_whole_and_a_changed_one_changes_nothing(chunks in vec(vec(vec(any::<u8>(), 32..=120), 0..4), 1..6), before in 0u64..20, key in any::<[u8; 32]>(), seed in any::<u64>(), at in any::<Index>(), bit in 0u8..8, cut in any::<Index>()) {
		let (mut sealer, mut opener, mut random, mut scratch) = (Sealer::new(ChunkKey::new(&key), padding(seed)), fronted::Opener::new(ChunkKey::new(&key)), seeded(!seed), Vec::new());
		// Some requests before this one, so that the numbers do not start at 0.
		for _ in 0..before {
			let mut body = Vec::new();
			fronted::append(&mut sealer, &[], false, &mut random, &mut body).unwrap();
			prop_assert_eq!(opener.open(&body, &mut scratch).unwrap().commit().len(), 1);
		}
		let mut body = Vec::new();
		for items in &chunks {fronted::append(&mut sealer, &items.iter().map(Vec::as_slice).collect::<Vec<_>>(), false, &mut random, &mut body).unwrap()}
		prop_assert!((fronted::BODY_MIN..=fronted::BODY_MAX).contains(&body.len()));
		let mut changed = body.clone();
		changed[at.index(body.len())] ^= 1 << bit;
		// A cut that ends on a chunk is a body of fewer chunks, which only the content length of the request can tell from the whole.
		let cut = cut.index(body.len());
		let whole = {
			let (mut at, mut ends) = (0, HashSet::new());
			while at < body.len() {
				at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
				ends.insert(at);
			}
			ends.contains(&cut)
		};
		for bad in [&changed[..], &[&body[..], &[0]].concat(), &[&body[..], &body[..]].concat()].into_iter().chain((!whole).then_some(&body[..cut])) {
			prop_assert_eq!(opener.open(bad, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused));
			prop_assert_eq!(opener.number(), before);
		}
		let opened = opener.open(&body, &mut scratch).unwrap();
		prop_assert_eq!(opened.chunks().iter().map(|items| items.clone().map(<[u8]>::to_vec).collect::<Vec<_>>()).collect::<Vec<_>>(), chunks.clone());
		drop(opened);
		prop_assert_eq!(opener.number(), before);
		prop_assert_eq!(opener.open(&body, &mut scratch).unwrap().commit().len(), chunks.len());
		prop_assert_eq!(opener.number(), before + chunks.len() as u64);
		prop_assert_eq!(opener.open(&body, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused));
		// The stream opener reads the same chunks at the same numbers: one format on `tls`, `ws` and `fronted`.
		let (mut stream, mut at) = (ChunkOpener::new(ChunkKey::new(&key)), 0);
		if before == 0 {
			for items in &chunks {
				let size = usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
				prop_assert_eq!(stream.open(&mut body[at + 2..at + 2 + size]).unwrap().map(<[u8]>::to_vec).collect::<Vec<_>>(), items.clone());
				at += 2 + size;
			}
		}
	}
}
