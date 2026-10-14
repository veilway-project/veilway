//! Property tests of node link pairing: an offer that is issued reads back as its terms, two panels that pair agree on one secret and one fingerprint, a code has one writing, and no reader panics on text or bytes nobody wrote.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use proptest::{collection::vec, option, prelude::*, sample::select};
use ring::digest::{digest, SHA256};
use std::net::IpAddr;
use veilway_proto::pairing::{pairing_hash, transports, transports_json, Answer, CodeError, Direction, Fingerprint, Offer, Offers, Pastes, Terms, Unconfirmed, ANSWER_CHARS, LIFETIME_MAX, OFFER_MAX};
use veilway_proto::proof::public_key;
use veilway_proto::subscription::payload::{Candidate, Dial, Stream, Transport};
use veilway_proto::NoRandom;

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

// A code around any bytes, with a checksum that holds.
fn coded(prefix: &str, bytes: &[u8]) -> String {format!("{prefix}{}.{}", URL_SAFE_NO_PAD.encode(bytes), URL_SAFE_NO_PAD.encode(&digest(&SHA256, bytes).as_ref()[..4]))}

fn dial() -> impl Strategy<Value = Dial> {(select(vec!["203.0.113.9", "198.51.100.7", "10.1.2.3", "192.168.7.9", "[2001:db8::9]", "[2a00:1450::7]"]), 1u16..=65535).prop_map(|(host, port)| Dial::parse(&format!("{host}:{port}")).unwrap())}

fn host() -> impl Strategy<Value = String> {"[a-z0-9]{1,12}(\\.[a-z0-9]{1,8}){0,2}\\.[a-z]{2,6}"}

fn candidate(pinned: bool) -> impl Strategy<Value = Candidate> {
	(dial(), option::of(host()), host(), host(), vec(any::<[u8; 32]>(), 1..=2)).prop_map(move |(address, sni, host, verify, pins)| Candidate {address, verify_name: if sni.is_none() {Some(verify)} else {None}, sni, host, ech: None, pins: if pinned {pins} else {Vec::new()}, self_signed: false})
}

fn stream(pinned: bool) -> impl Strategy<Value = Stream> {("/[A-Za-z0-9._~-]{11,40}", vec(candidate(pinned), 1..=2)).prop_filter("a path with a .. component is no path", |(path, _)| !path.split('/').any(|part| part == "..")).prop_map(|(path, candidates)| Stream {path, candidates})}

fn transport() -> impl Strategy<Value = Transport> {prop_oneof![vec(dial(), 1..=3).prop_map(Transport::Udp), vec(dial(), 1..=3).prop_map(Transport::UdpObfs), stream(true).prop_map(Transport::Tls), (any::<bool>(), any::<bool>()).prop_flat_map(|(pinned, _)| stream(pinned)).prop_map(Transport::Ws)]}

// A private key whose public half is a key a code may carry.
fn key() -> impl Strategy<Value = [u8; 32]> {any::<[u8; 32]>().prop_map(|private| public_key(&private))}

fn terms() -> impl Strategy<Value = Terms> {
	(any::<bool>(), "[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,40}", key(), key(), any::<bool>(), 1280u16..=1500, vec(transport(), 1..=3)).prop_map(|(reverse, name, inbound, transport, two, mtu, transports)| {
		let addresses = |last: u8| -> Vec<IpAddr> {[format!("10.9.0.{last}"), format!("fd00:9::{last}")][..if two {2} else {1}].iter().map(|address| address.parse().unwrap()).collect()};
		Terms {direction: if reverse {Direction::Reverse} else {Direction::Forward}, name, inbound_public_key: inbound, transport_public_key: Some(transport), dialler: addresses(2), listener: if reverse {addresses(3)} else {Vec::new()}, mtu, transports}
	})
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(64))]

	#[test]
	fn an_offer_reads_back_as_its_terms_and_two_panels_agree(terms in terms(), now in 0u64..=4_000_000_000, lifetime in 1u64..=LIFETIME_MAX, seeds in any::<(u64, u64)>()) {
		let (mut offers, mut pastes) = (Offers::default(), Pastes::default());
		let code = match offers.issue(&terms, now, lifetime, &mut seeded(seeds.0)) {
			Ok(code) => code,
			// Terms that make a code of more than 2,048 characters are refused when the offer is issued, and for nothing else.
			Err(error) => return Ok(prop_assert_eq!(error, CodeError::Length)),
		};
		prop_assert!(code.len() <= OFFER_MAX);
		let offer = Offer::parse(&code).unwrap();
		prop_assert_eq!((offer.direction, &offer.name, offer.inbound_public_key, offer.transport_public_key, &offer.dialler, &offer.listener, offer.mtu, &offer.transports, offer.expires_at, offer.code()), (terms.direction, &terms.name, terms.inbound_public_key, terms.transport_public_key, &terms.dialler, &terms.listener, terms.mtu, &terms.transports, now + lifetime, code));
		prop_assert_eq!(offer.dials().len(), offer.transports.iter().map(|transport| match transport {
			Transport::Udp(list) | Transport::UdpObfs(list) => list.len(),
			Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => stream.candidates.len(),
		}).sum::<usize>());
		let (answer, dialler) = pastes.answer(&offer, now + lifetime, &mut seeded(seeds.1)).unwrap();
		prop_assert_eq!(answer.len(), ANSWER_CHARS);
		let read = Answer::parse(&answer).unwrap();
		prop_assert_eq!((read.id, read.code()), (offer.id, answer.clone()));
		let listener = offers.answer(&answer, now + lifetime).unwrap();
		let (hash, ours, theirs) = (pairing_hash(offer.object(), &read.bytes()), listener.shown(), dialler.shown());
		prop_assert_eq!((&ours, &theirs), (&Fingerprint::of(&hash, true).groups().join(" "), &Fingerprint::of(&hash, false).groups().join(" ")));
		// Each panel refuses its own value and half of the other's, and takes the other's whole. Both then hold one secret and one key.
		let mut listener = listener;
		for typed in [&ours[..], &theirs[..19]] {
			listener = match listener.confirm(typed, now) {
				Err(Unconfirmed::Mismatch(kept)) => *kept,
				taken => panic!("the listener took {typed:?}: {taken:?}"),
			};
		}
		let mut dialler = dialler;
		for typed in [&theirs[..], &ours[20..]] {
			dialler = match dialler.confirm(typed, now) {
				Err(Unconfirmed::Mismatch(kept)) => *kept,
				taken => panic!("the dialler took {typed:?}: {taken:?}"),
			};
		}
		let (listener, dialler) = (listener.confirm(&theirs, now + lifetime).unwrap(), dialler.confirm(&ours, now + lifetime).unwrap());
		prop_assert!(listener.secret == dialler.secret && listener.public_key == read.public_key && dialler.private_key.is_some_and(|private| public_key(private.expose()) == read.public_key));
		// The offer is spent on both sides.
		prop_assert_eq!((offers.answer(&answer, now).err(), pastes.answer(&offer, now, &mut seeded(seeds.0)).err()), (Some(CodeError::Spent), Some(CodeError::Spent)));
	}

	#[test]
	fn no_text_and_no_object_makes_a_reader_panic(text in "\\PC{0,200}", bytes in vec(any::<u8>(), 0..300), tail in "[A-Za-z0-9_.-]{0,140}") {
		let _ = (Offer::parse(&text), Answer::parse(&text));
		for code in [format!("vwlink1.{tail}"), format!("vwlinka1.{tail}"), coded("vwlink1.", &bytes), coded("vwlinka1.", &bytes), coded("vwlink1.", text.as_bytes())] {
			// Whatever reads is written back as the text it was read from.
			if let Ok(offer) = Offer::parse(&code) {prop_assert_eq!(offer.code(), code.clone())}
			if let Ok(answer) = Answer::parse(&code) {prop_assert_eq!(answer.code(), code)}
		}
	}

	#[test]
	fn an_answer_is_its_eighty_bytes(id in any::<[u8; 16]>(), keys in (key(), key())) {
		let answer = Answer {id, public_key: keys.0, pairing_public_key: keys.1};
		prop_assert_eq!(Answer::parse(&coded("vwlinka1.", &answer.bytes())), Ok(answer));
		prop_assert_eq!(answer.code(), coded("vwlinka1.", &answer.bytes()));
		// Any other count of bytes under a checksum that holds is no answer.
		for size in [0, 79, 81] {prop_assert!(Answer::parse(&coded("vwlinka1.", &[&answer.bytes()[..], &[0]].concat()[..size])).is_err())}
	}
}

#[test]
fn a_self_signed_candidate_is_no_candidate_of_a_link() {
	let candidate = |self_signed| Candidate {address: Dial::parse("203.0.113.9:443").unwrap(), verify_name: None, sni: Some("example.org".to_owned()), host: "example.org".to_owned(), ech: None, pins: vec![[7; 32]], self_signed};
	let stream = |self_signed| vec![Transport::Tls(Stream {path: "/abcdefghijk".to_owned(), candidates: vec![candidate(self_signed)]})];
	assert!(transports(transports_json(&stream(false)).as_bytes()).is_ok());
	assert_eq!(transports(transports_json(&stream(true)).as_bytes()).err(), Some(CodeError::Member("transports")));
}
