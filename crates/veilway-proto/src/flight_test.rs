use super::*;
use crate::tls13::{Cursor, Secrets};
use ring::rand::SystemRandom;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

const SITE: &str = "site.example";
const SEED: [u8; 40] = [0x9c; 40];

fn ext(kind: u16, body: &[u8]) -> Vec<u8> {[&kind.to_be_bytes()[..], &(body.len() as u16).to_be_bytes(), body].concat()}

// A ClientHello with the fields the node reads: a standalone X25519 share, and a hybrid share when `kem` is given, whose X25519 part is `part`.
fn hello(x: &[u8; 32], kem: Option<(&[u8], [u8; 32])>) -> Vec<u8> {
	let mut keys = [&[0x00, 0x1d, 0x00, 0x20][..], &x25519(*x, X25519_BASEPOINT_BYTES)].concat();
	if let Some((key, part)) = kem {keys.extend_from_slice(&[&[0x11, 0xec, 0x04, 0xc0][..], key, &part].concat())}
	let name = [&[0u8][..], &(SITE.len() as u16).to_be_bytes(), SITE.as_bytes()].concat();
	let extensions = [ext(0, &[&(name.len() as u16).to_be_bytes()[..], &name].concat()), ext(43, &[2, 3, 4]), ext(51, &[&(keys.len() as u16).to_be_bytes()[..], &keys].concat())].concat();
	let mut body = vec![3, 3];
	body.extend_from_slice(&[0x05; 32]);
	body.push(32);
	body.extend_from_slice(&[0x07; 32]);
	body.extend_from_slice(&[0, 6, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 1, 0]);
	body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
	body.extend_from_slice(&extensions);
	message(1, &body)
}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	bytes.iter_mut().enumerate().for_each(|(index, byte)| *byte = (index as u8).wrapping_mul(31) ^ 0x5a);
	Ok(())
}

fn shape() -> Shape {
	let mut shape = Shape::generic(7, &mut random);
	shape.extensions = message(8, &[0, 8, 0, 16, 0, 5, 0, 3, 2, 104, 50]);
	shape.chain = [&[0, 0, 40][..], &[0xaa; 40], &[0, 0]].concat();
	shape
}

fn flight(suite: Suite, group: u16, sizes: &[usize]) -> Flight {
	let hello = write_server_hello(&[0x07; 32], suite, group, true, &[0; 32], &vec![0; if group == X25519 {32} else {KEM_CIPHERTEXT + 32}]).len();
	let (first, rest) = sizes.split_first().unwrap();
	Flight {suite, group, key_first: true, bursts: vec![Burst {at: Duration::from_millis(20), wire: vec![Wire::Hello(hello), Wire::Ccs, Wire::Sealed(*first)]}, Burst {at: Duration::from_millis(21), wire: rest.iter().map(|size| Wire::Sealed(*size)).collect()}]}
}

// What a client does with the node's flight: reads the ServerHello, opens every record with the handshake keys, and returns the messages of the stream with the keys of the handshake and the transcript hash through the server's Finished.
fn client(hello: &[u8], made: &Made, private: &[u8; 32], kem: Option<[u8; 32]>) -> (Vec<Vec<u8>>, Vec<u8>, Secrets, Transcript) {
	let wire: Vec<u8> = made.bursts.iter().flat_map(|(_, bytes)| bytes.clone()).collect();
	let (size, mut at) = (usize::from(u16::from_be_bytes([wire[3], wire[4]])), 5);
	let server = wire[5..5 + size].to_vec();
	let read = server_hello(&server, &hello[39..71]).unwrap();
	let suite = read.suite;
	let (part, agreed) = (&read.key[read.key.len() - 32..], x25519(*private, read.key[read.key.len() - 32..].try_into().unwrap()));
	let shared = if let Some(secret) = kem {[&secret[..], &agreed].concat()} else {assert_eq!(part.len(), 32); agreed.to_vec()};
	let mut transcript = Transcript::new(suite);
	transcript.update(hello);
	transcript.update(&server);
	let secrets = handshake_secrets(suite, &shared, &transcript.hash());
	let (mut keys, mut stream) = (Keys::new(suite, &secrets.server), Vec::new());
	at += size;
	while at < wire.len() {
		let (kind, size) = (wire[at], usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]])));
		if kind == 23 {
			let header: [u8; 5] = std::array::from_fn(|index| wire[at + index]);
			let mut body = wire[at + 5..at + 5 + size].to_vec();
			let (inner, content) = keys.open(&header, &mut body).expect("a record of the flight opens");
			assert_eq!(inner, 22);
			stream.extend_from_slice(content);
		} else {
			assert_eq!((kind, size), (20, 1));
		}
		at += 5 + size;
	}
	let mut messages = Vec::new();
	let mut rest = Cursor(&stream);
	while !rest.0.is_empty() {
		let (kind, body) = (rest.uint(1).unwrap(), rest.var(3).unwrap());
		messages.push([&[kind as u8, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8][..], body].concat());
	}
	(messages, server, secrets, transcript)
}

fn made(hello: &[u8], flight: &Flight, kem: bool) -> Made {
	answer(hello, flight, &shape(), &SEED, SITE, &SystemRandom::new(), &mut random, &mut |_| kem.then_some(([0xc7; KEM_CIPHERTEXT], [0x3b; 32]))).expect("the flight is written")
}

#[test]
fn the_flight_has_the_sizes_of_the_one_it_copies_and_a_client_can_finish_it() {
	let x = [0x31; 32];
	let hello = hello(&x, None);
	for suite in [Suite::Aes128, Suite::Aes256, Suite::Chacha] {
		let flight = flight(suite, X25519, &[1400, 1450, 600]);
		let made = made(&hello, &flight, false);
		assert_eq!(made.bursts.iter().map(|(at, _)| *at).collect::<Vec<_>>(), flight.bursts.iter().map(|burst| burst.at).collect::<Vec<_>>());
		let wire: Vec<(Duration, Vec<u8>)> = made.bursts.iter().map(|(at, bytes)| (*at, bytes.clone())).collect();
		assert_eq!(Flight::read(&wire, &hello[39..71], MOST_RECORDS).as_ref(), Some(&flight));
		let (messages, _, secrets, mut transcript) = client(&hello, &made, &x, None);
		assert_eq!(messages.iter().map(|message| message[0]).collect::<Vec<_>>(), [8, 11, 15, 20]);
		assert_eq!(messages[0], shape().extensions);
		let point = leaf_key(&SEED).unwrap().1;
		assert!(messages[1].windows(65).any(|window| window == &point[..]));
		assert!(messages[1].ends_with(&shape().chain));
		transcript.update(&messages[0]);
		transcript.update(&messages[1]);
		let signature = &messages[2][8..];
		let content = [&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", &transcript.hash()].concat();
		UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point).verify(&content, signature).expect("the CertificateVerify verifies under the leaf's key");
		transcript.update(&messages[2]);
		assert_eq!(messages[3][4..], finished(suite, &secrets.server, &transcript.hash())[..]);
		transcript.update(&messages[3]);
		let client_finished = message(20, &finished(suite, &secrets.client, &transcript.hash()));
		let established = made.pending.finish(&client_finished).expect("the client's Finished is the one expected");
		let mut keys = established.send;
		let mut out = Vec::new();
		assert!(keys.seal(23, b"x", 0, &mut out));
		let (client_ap, server_ap) = application_secrets(suite, &secrets.next, &transcript.hash());
		let (mut opened, header) = (Keys::new(suite, &server_ap), <[u8; 5]>::try_from(&out[..5]).unwrap());
		assert_eq!(opened.open(&header, &mut out[5..].to_vec()), Some((23, &b"x"[..])));
		assert_ne!(client_ap, server_ap);
	}
}

#[test]
fn a_finished_that_is_not_the_clients_is_refused() {
	let x = [0x31; 32];
	let hello = hello(&x, None);
	let made = made(&hello, &flight(Suite::Aes128, X25519, &[3000]), false);
	assert!(made.pending.finish(&message(20, &[0; 32])).is_none());
}

#[test]
fn the_hybrid_group_answers_with_the_kem_ciphertext_and_the_secret_of_the_hybrid_x25519_key() {
	let (x, own, kem) = ([0x31; 32], [0x32; 32], [0x44u8; KEM_KEY]);
	let hello = hello(&x, Some((&kem, x25519(own, X25519_BASEPOINT_BYTES))));
	assert!(answers(&hello, HYBRID) && answers(&hello, X25519));
	let made = made(&hello, &flight(Suite::Aes256, HYBRID, &[3000]), true);
	let (messages, server, ..) = client(&hello, &made, &own, Some([0x3b; 32]));
	assert_eq!(messages.len(), 4);
	assert_eq!(server_hello(&server, &hello[39..71]).unwrap().key[..KEM_CIPHERTEXT], [0xc7; KEM_CIPHERTEXT]);
}

#[test]
fn the_hybrid_group_is_not_answered_when_the_hello_has_no_hybrid_share() {
	let hello = hello(&[0x31; 32], None);
	assert!(answers(&hello, X25519) && !answers(&hello, HYBRID));
	assert!(answer(&hello, &flight(Suite::Aes128, HYBRID, &[3000]), &shape(), &SEED, SITE, &SystemRandom::new(), &mut random, &mut |_| Some(([0; KEM_CIPHERTEXT], [0; 32]))).is_none());
}

#[test]
fn a_flight_too_small_for_the_messages_or_of_the_wrong_hello_size_is_not_written() {
	let x = [0x31; 32];
	let hello = hello(&x, None);
	assert!(answer(&hello, &flight(Suite::Aes128, X25519, &[200]), &shape(), &SEED, SITE, &SystemRandom::new(), &mut random, &mut |_| None).is_none());
	let mut odd = flight(Suite::Aes128, X25519, &[3000]);
	odd.bursts[0].wire[0] = Wire::Hello(99);
	assert!(answer(&hello, &odd, &shape(), &SEED, SITE, &SystemRandom::new(), &mut random, &mut |_| None).is_none());
}

#[test]
fn the_leaf_fills_what_the_records_leave() {
	let point = leaf_key(&SEED).unwrap().1;
	for target in [400, 401, 1000, 1500, 4096, 9000] {
		let made = leaf(SITE, &point, &mut random, target).unwrap();
		assert!(made.len() <= target && target - made.len() <= 4, "{target}: {}", made.len());
	}
	assert!(leaf(SITE, &point, &mut random, 100).is_none());
}

#[test]
fn the_tickets_and_the_data_are_sealed_in_the_order_of_their_times() {
	let mut shape = shape();
	shape.tickets = vec![(Duration::from_millis(5), 250), (Duration::from_millis(1), 300)];
	shape.data = vec![(Duration::from_millis(3), 60)];
	let made = afterwards(&shape, &mut random).unwrap();
	assert_eq!(made.iter().map(|(at, kind, plain)| (at.as_millis(), *kind, plain.len() + TAG + 1)).collect::<Vec<_>>(), [(1, 22, 300), (3, 23, 60), (5, 22, 250)]);
	assert_eq!(made[1].2[..2], 41u16.to_be_bytes());
}

#[test]
fn a_flight_that_is_no_server_hello_is_not_read() {
	let session = [0x07; 32];
	assert!(Flight::read(&[(Duration::ZERO, vec![21, 3, 3, 0, 2, 2, 40])], &session, MOST_RECORDS).is_none());
	assert!(Flight::read(&[(Duration::ZERO, b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec())], &session, MOST_RECORDS).is_none());
	let ok = flight(Suite::Aes128, X25519, &[3000]);
	let hello = hello(&[0x31; 32], None);
	let made = made(&hello, &ok, false);
	let mut bytes: Vec<u8> = made.bursts.iter().flat_map(|(_, bytes)| bytes.clone()).collect();
	bytes.truncate(bytes.len() - 10);
	assert!(Flight::read(&[(Duration::ZERO, bytes)], &session, MOST_RECORDS).is_none());
}

#[test]
fn a_flight_is_read_as_it_arrives_each_byte_once_and_one_above_the_limit_is_not_read() {
	let hello = hello(&[0x31; 32], None);
	let sizes = [1400, 1450, 600];
	let flight = flight(Suite::Aes128, X25519, &sizes);
	let made = made(&hello, &flight, false);
	let bytes: Vec<u8> = made.bursts.iter().flat_map(|(_, bytes)| bytes.clone()).collect();
	let mut parser = Parser::new(&hello[39..71], MOST_RECORDS);
	let mut wires = Vec::new();
	for piece in bytes.chunks(7) {wires.extend(parser.feed(piece).unwrap())}
	assert_eq!(wires, flight.bursts.iter().flat_map(|burst| burst.wire.clone()).collect::<Vec<_>>());
	assert_eq!((parser.sealed(), parser.total(), parser.hello()), (3, 3450, Some((Suite::Aes128, X25519, true))));
	let big = made_big(&hello);
	assert!(Flight::read(&[(Duration::ZERO, big)], &hello[39..71], MOST_RECORDS).is_none());
}

fn made_big(hello: &[u8]) -> Vec<u8> {
	let flight = flight(Suite::Aes128, X25519, &[16_000; 9]);
	made(hello, &flight, false).bursts.iter().flat_map(|(_, bytes)| bytes.clone()).collect()
}

#[test]
fn the_messages_are_sealed_record_by_record_as_the_sizes_become_known_and_a_few_bytes_of_difference_are_padding() {
	let (x, sizes) = ([0x31; 32], [1400usize, 1450, 600]);
	let hello = hello(&x, None);
	let opening = open(&hello, Suite::Aes256, X25519, false, &mut random, &mut |_| None).unwrap();
	assert_eq!(opening.record()[5..], opening.record()[5..opening.size() + 5]);
	let capacity: usize = sizes.iter().map(|size| size - TAG - 1).sum();
	let mut stream = opening.messages(&shape(), &SEED, SITE, capacity - 8, &SystemRandom::new(), &mut random).unwrap();
	// The last record is two bytes smaller than the shape's: the slack takes it.
	for size in [1400, 1450, 598] {assert_eq!(stream.seal(size).unwrap().len(), HEADER + size)}
	assert_eq!(stream.left(), 0);
	assert!(stream.seal(600).is_none());
}
