//! The opening exchange of the control channel, end to end between the two state machines.
use std::time::Duration;
use veilway_proto::{control::{ClientMessage, DecodeError, NodeMessage, CLIENT_LIMIT, PREFACE}, keys::ControlKey, opening::{ClientOpened, ClientOpening, NodeOpened, NodeOpening, OpenError, DEADLINE}, NoRandom};

const INBOUND: [u8; 32] = [0x10; 32];
const DEVICE_A: [u8; 32] = [0xa0; 32];
const DEVICE_B: [u8; 32] = [0xb0; 32];
const SECRET_A: [u8; 32] = [0xa1; 32];
const SECRET_B: [u8; 32] = [0xb1; 32];
const SOON: Duration = Duration::from_secs(1);

fn key_a() -> ControlKey {ControlKey::derive(&SECRET_A, &INBOUND, &DEVICE_A)}

fn join(parts: &[&[u8]]) -> Vec<u8> {parts.concat()}

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

// What a test compares of a client's and a node's result: the version, and for the node which key matched.
fn client_seen(result: Result<Option<ClientOpened>, OpenError>) -> Result<Option<u8>, OpenError> {result.map(|opened| opened.map(|opened| opened.version))}

fn node_seen(result: Result<Option<NodeOpened>, OpenError>) -> Result<Option<(u8, usize)>, OpenError> {result.map(|opened| opened.map(|opened| (opened.version, opened.key)))}

fn client() -> ClientOpening {ClientOpening::start(key_a(), 1, Duration::ZERO, &mut seeded(1), &mut Vec::new()).unwrap()}

fn node(now: Duration, bytes: &[u8]) -> Result<Option<(u8, usize)>, OpenError> {node_seen(NodeOpening::new(Duration::ZERO).receive(now, &[key_a()], &mut &bytes[..], &mut seeded(2), &mut Vec::new()))}

type Outcome = (Result<Option<u8>, OpenError>, Result<Option<(u8, usize)>, OpenError>);

// Runs one exchange. `tamper` sees each flight before it is delivered: 0 is the preface and `hello`, 1 `hello_reply`, 2 `auth`, 3 `auth_ok`.
fn run(client_key: ControlKey, node_keys: &[ControlKey], min_version: u8, mut tamper: impl FnMut(usize, &mut Vec<u8>)) -> Outcome {
	let (mut up, mut down) = (Vec::new(), Vec::new());
	let mut client = ClientOpening::start(client_key, min_version, Duration::ZERO, &mut seeded(1), &mut up).unwrap();
	let mut node = NodeOpening::new(Duration::ZERO);
	tamper(0, &mut up);
	let mut node_result = node_seen(node.receive(SOON, node_keys, &mut &up[..], &mut seeded(2), &mut down));
	tamper(1, &mut down);
	up.clear();
	let mut client_result = client_seen(client.receive(SOON, &mut &down[..], &mut up));
	tamper(2, &mut up);
	down.clear();
	if node_result == Ok(None) {node_result = node_seen(node.receive(SOON, node_keys, &mut &up[..], &mut seeded(2), &mut down))}
	tamper(3, &mut down);
	if client_result == Ok(None) {client_result = client_seen(client.receive(SOON, &mut &down[..], &mut up))}
	(client_result, node_result)
}

// The four flights of an exchange that opens, with the same random bytes `run` uses.
fn flights() -> [Vec<u8>; 4] {
	let mut flights = [const {Vec::new()}; 4];
	assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| flights[flight] = bytes.clone()), (Ok(Some(1)), Ok(Some((1, 0)))));
	flights
}

#[test]
fn the_exchange_opens_with_the_sizes_the_page_states() {
	assert_eq!(flights().map(|flight| flight.len()), [44, 36, 35, 35]);
}

#[test]
fn a_wrong_secret_fails_auth_and_the_client_never_opens() {
	assert_eq!(run(ControlKey::derive(&SECRET_B, &INBOUND, &DEVICE_A), &[key_a()], 1, |_, _| {}), (Ok(None), Err(OpenError::Auth)));
	assert_eq!(run(key_a(), &[], 1, |_, _| {}), (Ok(None), Err(OpenError::Auth)));
}

// "Device A's secret presented from device B's tunnel fails `auth`, also when both belong to one user." The node computes the key for the device the connection came from, so it holds B's public key, whatever secret it is tried with.
#[test]
fn one_devices_secret_does_not_authenticate_from_another_devices_tunnel() {
	for node_key in [ControlKey::derive(&SECRET_B, &INBOUND, &DEVICE_B), ControlKey::derive(&SECRET_A, &INBOUND, &DEVICE_B), ControlKey::derive(&SECRET_A, &DEVICE_A, &INBOUND), ControlKey::derive(&SECRET_A, &[0x11; 32], &DEVICE_A)] {
		assert_eq!(run(key_a(), &[node_key], 1, |_, _| {}), (Ok(None), Err(OpenError::Auth)));
	}
}

#[test]
fn during_a_rotation_the_node_answers_with_the_secret_that_matched() {
	let keys = || [ControlKey::derive(&SECRET_B, &INBOUND, &DEVICE_A), key_a()];
	assert_eq!(run(key_a(), &keys(), 1, |_, _| {}), (Ok(Some(1)), Ok(Some((1, 1)))));
	assert_eq!(run(ControlKey::derive(&SECRET_B, &INBOUND, &DEVICE_A), &keys(), 1, |_, _| {}), (Ok(Some(1)), Ok(Some((1, 0)))));
	assert_eq!(run(key_a(), &[key_a(), key_a()], 1, |_, _| {}).1, Ok(Some((1, 0))));
}

// A device has at most two secrets, so a third key is a mistake of the caller, refused before a byte is read and whatever the keys are.
#[test]
fn a_node_checks_at_most_two_keys() {
	let [hello, _, auth, _] = flights();
	let (mut node, up, mut out) = (NodeOpening::new(Duration::ZERO), join(&[&hello, &auth]), Vec::new());
	let mut input = &up[..];
	assert_eq!(node_seen(node.receive(SOON, &[key_a(), key_a(), key_a()], &mut input, &mut seeded(2), &mut out)), Err(OpenError::Keys));
	assert_eq!((input.len(), out.len()), (up.len(), 0));
	assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut input, &mut seeded(2), &mut out)), Err(OpenError::Keys));
}

#[test]
fn a_changed_version_byte_opens_nothing() {
	// `max_version` raised on the way: the node still answers 1, and its transcript no longer is the client's.
	assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 0 {bytes[PREFACE.len() + 3] = 2}), (Ok(None), Err(OpenError::Auth)));
	assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 0 {bytes[PREFACE.len() + 3] = 0}), (Ok(None), Err(OpenError::Version)));
	// `version` changed on the way to one above the offer, or to 0: the protocol is broken, and that is not an old node.
	for version in [0, 2, 255] {
		let mut sent = 0;
		assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| match flight {
			1 => bytes[3] = version,
			2 => sent = bytes.len(),
			_ => {}
		}), (Err(OpenError::Version), Ok(None)));
		assert_eq!(sent, 0, "a client answered a version no node may give");
	}
}

// "Versions", rule 0: a profile that demands more than the client speaks ends before anything is sent, and the fault is the app's.
#[test]
fn a_client_that_is_too_old_for_its_profile_sends_nothing() {
	for min_version in [2, 3, 255] {
		let mut out = vec![0xee];
		assert_eq!(ClientOpening::start(key_a(), min_version, Duration::ZERO, &mut |_: &mut [u8]| panic!("a number was drawn for a hello that is not sent"), &mut out).map(|_| ()), Err(OpenError::ClientTooOld));
		assert_eq!(out, [0xee]);
	}
	// A profile that demands nothing, or exactly what both sides speak, opens.
	for min_version in [0, 1] {assert_eq!(run(key_a(), &[key_a()], min_version, |_, _| {}), (Ok(Some(1)), Ok(Some((1, 0)))))}
}

#[test]
fn a_node_that_cannot_make_its_credential_is_refused() {
	assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 3 {bytes[10] ^= 1}), (Err(OpenError::Auth), Ok(Some((1, 0)))));
	// The client's own MAC sent back as the node's: the direction byte keeps it from passing.
	let mut client_mac = Vec::new();
	let reflect = |flight: usize, bytes: &mut Vec<u8>| match flight {
		2 => client_mac = bytes[3..].to_vec(),
		3 => bytes[3..].copy_from_slice(&client_mac),
		_ => {}
	};
	assert_eq!(run(key_a(), &[key_a()], 1, reflect).0, Err(OpenError::Auth));
}

#[test]
fn any_flipped_bit_in_either_mac_is_refused() {
	for bit in 0..256 {
		assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 2 {bytes[3 + bit / 8] ^= 1 << (bit % 8)}), (Ok(None), Err(OpenError::Auth)), "client_mac bit {bit}");
		assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 3 {bytes[3 + bit / 8] ^= 1 << (bit % 8)}).0, Err(OpenError::Auth), "node_mac bit {bit}");
	}
}

#[test]
fn any_flipped_bit_in_a_nonce_is_refused() {
	for bit in 0..256 {
		assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 0 {bytes[PREFACE.len() + 4 + bit / 8] ^= 1 << (bit % 8)}), (Ok(None), Err(OpenError::Auth)), "client_nonce bit {bit}");
		assert_eq!(run(key_a(), &[key_a()], 1, |flight, bytes| if flight == 1 {bytes[4 + bit / 8] ^= 1 << (bit % 8)}), (Ok(None), Err(OpenError::Auth)), "node_nonce bit {bit}");
	}
}

#[test]
fn a_replayed_exchange_meets_a_fresh_number() {
	let [hello, reply, auth, auth_ok] = flights();
	// Everything a client sent, played again to a node. The node's number is new, so the recorded MAC is for another transcript.
	let (mut node, mut out) = (NodeOpening::new(Duration::ZERO), Vec::new());
	assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &join(&[&hello, &auth])[..], &mut seeded(8), &mut out)), Err(OpenError::Auth));
	assert_eq!(out.len(), 36);
	// Everything a node sent, played again to a client.
	let mut out = Vec::new();
	let mut client = ClientOpening::start(key_a(), 1, Duration::ZERO, &mut seeded(4), &mut out).unwrap();
	assert_eq!(client_seen(client.receive(SOON, &mut &join(&[&reply, &auth_ok])[..], &mut out)), Err(OpenError::Auth));
}

#[test]
fn a_message_out_of_order_closes() {
	let [hello, reply, auth, auth_ok] = flights();
	assert_eq!(node(SOON, &join(&[&PREFACE, &auth])), Err(OpenError::Unexpected));
	assert_eq!(node(SOON, &join(&[&hello, &hello[PREFACE.len()..]])), Err(OpenError::Unexpected));
	// A message of the other side, and a request before the exchange is over, are no messages of the exchange at this end.
	assert_eq!(node(SOON, &join(&[&PREFACE, &reply])), Err(OpenError::Unexpected));
	assert_eq!(node(SOON, &join(&[&hello, &[0x00, 0x01, 0x10]])), Err(OpenError::Decode(DecodeError::Type)));
	assert_eq!(node(SOON, &join(&[&PREFACE, &[0x00, 0x01, 0x10]])), Err(OpenError::Decode(DecodeError::Type)));
	assert_eq!(node(SOON, &join(&[&PREFACE, &[0x00, 0x00]])), Err(OpenError::Decode(DecodeError::Length)));
	assert_eq!(node(SOON, &hello[PREFACE.len()..]), Err(OpenError::Decode(DecodeError::Preface)));
	assert_eq!(node(SOON, b"GET / HTTP/1.1\r\n\r\n"), Err(OpenError::Decode(DecodeError::Preface)));
	assert_eq!(node(SOON, &join(&[&hello, &auth])), Ok(Some((1, 0))));
	let receive = |bytes: &[u8]| client_seen(client().receive(SOON, &mut &bytes[..], &mut Vec::new()));
	assert_eq!(receive(&auth_ok), Err(OpenError::Unexpected));
	assert_eq!(receive(&join(&[&reply, &reply])), Err(OpenError::Unexpected));
	assert_eq!(receive(&hello[PREFACE.len()..]), Err(OpenError::Unexpected));
	assert_eq!(receive(&[0x00, 0x02, 0x99, 0x04]), Err(OpenError::Decode(DecodeError::Type)));
	assert_eq!(receive(&join(&[&reply, &auth_ok])), Ok(Some(1)));
}

#[test]
fn input_cut_at_any_byte_waits_and_then_meets_the_deadline() {
	let [hello, reply, auth, auth_ok] = flights();
	let (up, down) = (join(&[&hello, &auth]), join(&[&reply, &auth_ok]));
	for cut in 0..up.len() {
		let (mut node, mut out) = (NodeOpening::new(Duration::ZERO), Vec::new());
		assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &up[..cut], &mut seeded(2), &mut out)), Ok(None), "cut at {cut}");
		assert_eq!(out.len(), if cut < 44 {0} else {36}, "cut at {cut}");
		// The rest in a second piece opens the same exchange.
		assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &up[cut..], &mut seeded(2), &mut out)), Ok(Some((1, 0))), "cut at {cut}");
		assert_eq!(out, down, "cut at {cut}");
		// Without the rest, the deadline ends it, and for good.
		let mut node = NodeOpening::new(Duration::ZERO);
		assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &up[..cut], &mut seeded(2), &mut out)), Ok(None));
		assert_eq!(node_seen(node.receive(DEADLINE, &[key_a()], &mut &up[cut..], &mut seeded(2), &mut out)), Err(OpenError::Deadline));
		assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &up[cut..], &mut seeded(2), &mut out)), Err(OpenError::Deadline));
	}
	for cut in 0..down.len() {
		let mut out = Vec::new();
		let mut client = ClientOpening::start(key_a(), 1, Duration::ZERO, &mut seeded(1), &mut out).unwrap();
		assert_eq!(client_seen(client.receive(SOON, &mut &down[..cut], &mut out)), Ok(None), "cut at {cut}");
		assert_eq!(out.len(), if cut < 36 {44} else {44 + 35}, "cut at {cut}");
		assert_eq!(client_seen(client.receive(SOON, &mut &down[cut..], &mut out)), Ok(Some(1)), "cut at {cut}");
		assert_eq!(out, up, "cut at {cut}");
		// A node that stops answering cannot hold the exchange open: the client has the same limit.
		let mut stalled = self::client();
		assert_eq!(client_seen(stalled.receive(SOON, &mut &down[..cut], &mut out)), Ok(None));
		assert_eq!(client_seen(stalled.receive(DEADLINE, &mut &down[cut..], &mut out)), Err(OpenError::Deadline));
		assert_eq!(client_seen(stalled.receive(SOON, &mut &down[cut..], &mut out)), Err(OpenError::Deadline));
	}
}

#[test]
fn the_deadline_is_ten_seconds_for_both_sides() {
	let [hello, reply, auth, auth_ok] = flights();
	let (up, down, at) = (join(&[&hello, &auth]), join(&[&reply, &auth_ok]), Duration::from_secs(1000));
	let last = at + DEADLINE - Duration::from_nanos(1);
	assert_eq!(NodeOpening::new(at).deadline(), at + DEADLINE);
	assert_eq!(node_seen(NodeOpening::new(at).receive(last, &[key_a()], &mut &up[..], &mut seeded(2), &mut Vec::new())), Ok(Some((1, 0))));
	assert_eq!(node_seen(NodeOpening::new(at).receive(at + DEADLINE, &[key_a()], &mut &up[..], &mut seeded(2), &mut Vec::new())), Err(OpenError::Deadline));
	assert_eq!(node_seen(NodeOpening::new(Duration::MAX).receive(Duration::MAX, &[key_a()], &mut &up[..], &mut seeded(2), &mut Vec::new())), Err(OpenError::Deadline));
	let start = || ClientOpening::start(key_a(), 1, at, &mut seeded(1), &mut Vec::new()).unwrap();
	assert_eq!(start().deadline(), at + DEADLINE);
	assert_eq!(client_seen(start().receive(last, &mut &down[..], &mut Vec::new())), Ok(Some(1)));
	assert_eq!(client_seen(start().receive(at + DEADLINE, &mut &down[..], &mut Vec::new())), Err(OpenError::Deadline));
	// The limit runs to the moment `auth_ok` is verified: a reply in time and a credential too late is too late.
	let mut client = start();
	assert_eq!(client_seen(client.receive(last, &mut &reply[..], &mut Vec::new())), Ok(None));
	assert_eq!(client_seen(client.receive(at + DEADLINE, &mut &auth_ok[..], &mut Vec::new())), Err(OpenError::Deadline));
}

#[test]
fn a_failure_is_final_and_a_failed_random_source_opens_nothing() {
	let [hello, reply, auth, auth_ok] = flights();
	let mut none = |_: &mut [u8]| Err(NoRandom);
	assert_eq!(ClientOpening::start(key_a(), 1, Duration::ZERO, &mut none, &mut Vec::new()).map(|_| ()), Err(OpenError::Random));
	let (mut node, mut out) = (NodeOpening::new(Duration::ZERO), Vec::new());
	assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &hello[..], &mut none, &mut out)), Err(OpenError::Random));
	assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &join(&[&hello, &auth])[..], &mut seeded(2), &mut out)), Err(OpenError::Random));
	assert!(out.is_empty());
	let mut node = NodeOpening::new(Duration::ZERO);
	assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &join(&[&hello, &[0x00, 0x21, 0x02], &[0; 32]])[..], &mut seeded(2), &mut out)), Err(OpenError::Auth));
	assert_eq!(node_seen(node.receive(SOON, &[key_a()], &mut &auth[..], &mut seeded(2), &mut out)), Err(OpenError::Auth));
	let mut client = client();
	assert_eq!(client_seen(client.receive(SOON, &mut &join(&[&reply, &[0x00, 0x21, 0x82], &[0; 32]])[..], &mut Vec::new())), Err(OpenError::Auth));
	assert_eq!(client_seen(client.receive(SOON, &mut &auth_ok[..], &mut Vec::new())), Err(OpenError::Auth));
}

// The readers an exchange gives are for the other side's messages after the opening, with the limits of their direction: a request is at most 68 bytes, a node's message at most 65,535 of `length`, and a message of the opening is an unknown type from here on.
#[test]
fn the_readers_of_an_opened_exchange_keep_their_direction_and_its_limits() {
	let [hello, reply, auth, auth_ok] = flights();
	let opened = || {
		let node = NodeOpening::new(Duration::ZERO).receive(SOON, &[key_a()], &mut &join(&[&hello, &auth])[..], &mut seeded(2), &mut Vec::new()).unwrap().unwrap();
		(node.messages, client().receive(SOON, &mut &join(&[&reply, &auth_ok])[..], &mut Vec::new()).unwrap().unwrap().messages)
	};
	let (mut requests, mut pushes) = opened();
	let mut largest = Vec::new();
	ClientMessage::SetExit {tag: "a".repeat(64)}.encode(&mut largest).unwrap();
	assert_eq!(requests.read(&mut &join(&[&[0x00, 0x01, 0x10], &largest])[..]), Ok(Some(ClientMessage::Refresh)));
	assert_eq!(requests.read(&mut &largest[..]), Ok(Some(ClientMessage::SetExit {tag: "a".repeat(64)})));
	let notice = join(&[&[0xff, 0xff, 0x94, 0x01, 0x00, 0xff, 0xfa], &[0x61; 65_530]]);
	assert!(matches!(pushes.read(&mut &notice[..]), Ok(Some(NodeMessage::Notices(notices))) if notices[0].text.as_sent().len() == 65_530 && notices[0].shown_text().len() == 280));
	// A `length` of 4,096, the client's limit, with a type that could never be that long: refused at the third byte.
	let mut input = &join(&[&(CLIENT_LIMIT as u16).to_be_bytes(), &[0x11], &[0x61; 4_095]])[..];
	assert_eq!((requests.read(&mut input), input.len()), (Err(DecodeError::Length), 4_095));
	for (first, error) in [(&hello[PREFACE.len()..], DecodeError::Type), (&auth[..], DecodeError::Type), (&reply[..], DecodeError::Type), (&[0x00, 0x02, 0x99, 0x04][..], DecodeError::Type), (&[0x00, 0x04, 0x11, 0x02, 0x44, 0x45][..], DecodeError::Value)] {
		let (mut requests, _) = opened();
		assert_eq!(requests.read(&mut &first[..]), Err(error));
		assert_eq!(requests.read(&mut &[0x00, 0x01, 0x10][..]), Err(error));
	}
	for first in [&reply[..], &auth_ok[..], &hello[PREFACE.len()..], &[0x00, 0x01, 0x10][..]] {
		let (_, mut pushes) = opened();
		assert_eq!(pushes.read(&mut &first[..]), Err(DecodeError::Type));
		assert_eq!(pushes.read(&mut &[0x00, 0x02, 0x99, 0x04][..]), Err(DecodeError::Type));
	}
}

#[test]
fn the_flights_are_the_messages_of_the_page() {
	let [hello, reply, auth, auth_ok] = flights();
	assert_eq!(hello[..12], *join(&[&PREFACE, &[0x00, 0x22, 0x01, 0x01]]));
	assert_eq!((&reply[..4], &auth[..3], &auth_ok[..3]), (&[0x00, 0x22, 0x81, 0x01][..], &[0x00, 0x21, 0x02][..], &[0x00, 0x21, 0x82][..]));
	assert_ne!(hello[12..], reply[4..]);
}
