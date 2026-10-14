#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::digest::{digest, SHA256};
use veilway_proto::pairing::{pairing_hash, Answer, CodeError, Direction, Fingerprint, Offer, Offers, Pastes, Terms, Unconfirmed, ANSWER_BYTES, ANSWER_CHARS, LIFETIME, NAME_MAX, OFFER_MAX, TRANSPORTS_MAX};
use veilway_proto::subscription::payload::Transport;
use veilway_proto::NoRandom;

// The two codes of node link pairing, which a person pastes into a panel. The first byte picks what the rest is:
// 0, the text of an offer code. 1, the text of an answer code. 2, the object of an offer, which the harness puts into a code with a checksum that holds, so that every byte of it reaches the reader behind the checksum. 3, the bytes of an answer, the same.
// An offer that reads must be within every limit of the page and be written back as the text it was read from. It must then pair: the dialler answers it, a listener that issued the same terms takes that answer, each side refuses its own value and half of the other's and takes the other's whole, and both hold one secret. An answer that reads must be written back as the text it was read from, with keys that are keys.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn sealed(bytes: &[u8]) -> String {
	let mut out = String::new();
	for chunk in bytes.chunks(3) {
		let word = chunk.iter().enumerate().fold(0u32, |word, (at, byte)| word | u32::from(*byte) << (16 - 8 * at));
		for at in 0..=chunk.len() {out.push(ALPHABET[(word >> (18 - 6 * at) & 63) as usize] as char)}
	}
	out
}

fn coded(prefix: &str, bytes: &[u8]) -> String {format!("{prefix}{}.{}", sealed(bytes), sealed(&digest(&SHA256, bytes).as_ref()[..4]))}

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

fn offered(code: &str) {
	let Ok(offer) = Offer::parse(code) else {return};
	assert!(code.len() <= OFFER_MAX && offer.code() == code, "an offer was read as another text than it is");
	assert!((1..=NAME_MAX).contains(&offer.name.chars().count()) && (1280..=1500).contains(&offer.mtu) && (1..=TRANSPORTS_MAX).contains(&offer.transports.len()) && (1..=2).contains(&offer.dialler.len()));
	assert!(offer.listener.is_empty() == (offer.direction == Direction::Forward) && (offer.listener.is_empty() || offer.listener.len() == offer.dialler.len()));
	assert!(offer.dialler.iter().chain(&offer.listener).enumerate().all(|(at, address)| !offer.dialler.iter().chain(&offer.listener).skip(at + 1).any(|other| other == address)), "one address twice in a link");
	let mut stream = false;
	for transport in &offer.transports {
		match transport {
			Transport::Fronted(_) => panic!("an offer lists fronted"),
			Transport::Tls(listed) | Transport::Ws(listed) => {
				stream = true;
				assert!(listed.candidates.iter().all(|candidate| candidate.ech.is_none() && (!matches!(transport, Transport::Tls(_)) || !candidate.pins.is_empty())));
			}
			Transport::Udp(_) | Transport::UdpObfs(_) => {}
		}
	}
	assert!(!stream || offer.transport_public_key.is_some(), "a stream transport without the key its proofs are sealed to");
	assert!(!offer.dials().is_empty() && offer.dials().iter().all(|(address, _)| !address.ip().is_loopback() && !address.ip().is_unspecified() && !address.ip().is_multicast() && address.port() != 0));
	// The dialler answers what it read. An offer that has expired is refused, and nothing else is.
	let now = offer.expires_at;
	let mut pastes = Pastes::default();
	assert_eq!(pastes.answer(&offer, now.saturating_add(1), &mut seeded(1)).err(), Some(CodeError::Expired));
	let (answer, dialler) = pastes.answer(&offer, now, &mut seeded(1)).expect("an offer that read was not answered");
	let read = Answer::parse(&answer).expect("the dialler wrote an answer that does not read");
	assert!(answer.len() == ANSWER_CHARS && read.id == offer.id && read.code() == answer);
	assert_eq!(pastes.answer(&offer, now, &mut seeded(2)).err(), Some(CodeError::Spent));
	assert_eq!(dialler.shown(), Fingerprint::of(&pairing_hash(offer.object(), &read.bytes()), false).shown());
	// A listener that issues the same terms pairs with a dialler of its own offer, and the two hold one secret.
	let (terms, mut offers) = (Terms {direction: offer.direction, name: offer.name.clone(), inbound_public_key: offer.inbound_public_key, transport_public_key: offer.transport_public_key, dialler: offer.dialler.clone(), listener: offer.listener.clone(), mtu: offer.mtu, transports: offer.transports.clone()}, Offers::default());
	let issued = match offers.issue(&terms, 1_700_000_000, LIFETIME, &mut seeded(3)) {
		Ok(issued) => issued,
		// The same terms written out again may be a longer text than the one that was read, which had its own expiry and its own spelling.
		Err(error) => return assert_eq!(error, CodeError::Length),
	};
	let again = Offer::parse(&issued).expect("an offer that was issued does not read");
	assert!((again.direction, &again.name, &again.dialler, &again.listener, again.mtu, &again.transports) == (offer.direction, &offer.name, &offer.dialler, &offer.listener, offer.mtu, &offer.transports), "terms that were read and written out again are other terms");
	let (answer, dialler) = Pastes::default().answer(&again, 1_700_000_000, &mut seeded(4)).unwrap();
	let listener = offers.answer(&answer, 1_700_000_000).expect("the listener did not take the answer to its own offer");
	let (ours, theirs) = (listener.shown(), dialler.shown());
	assert_ne!(ours, theirs, "the two panels of one pairing show one value, which each would then accept from its own screen");
	let Err(Unconfirmed::Mismatch(listener)) = listener.confirm(&ours, 1_700_000_000) else {panic!("the listener took its own value")};
	let Err(Unconfirmed::Mismatch(dialler)) = dialler.confirm(&theirs, 1_700_000_000) else {panic!("the dialler took its own value")};
	let Err(Unconfirmed::Mismatch(listener)) = listener.confirm(&theirs[..19], 1_700_000_000) else {panic!("the listener took half of the dialler's value")};
	let (listener, dialler) = (listener.confirm(&theirs, 1_700_000_000).expect("the listener refused the dialler's value"), dialler.confirm(&ours, 1_700_000_000).expect("the dialler refused the listener's value"));
	assert!(listener.secret == dialler.secret && listener.public_key == dialler.public_key && listener.private_key.is_none() && dialler.private_key.is_some());
	assert_eq!(offers.answer(&answer, 1_700_000_000).err(), Some(CodeError::Spent));
}

fn answered(code: &str) {
	let Ok(answer) = Answer::parse(code) else {return};
	assert!(code.len() == ANSWER_CHARS && answer.code() == code, "an answer was read as another text than it is");
	assert!(answer.public_key != [0; 32] && answer.pairing_public_key != [0; 32] && answer.bytes().len() == ANSWER_BYTES && answer.bytes()[..16] == answer.id);
	// An answer nobody asked for is taken by no listener.
	assert_eq!(Offers::default().answer(code, 0).err(), Some(CodeError::Spent));
}

fuzz_target!(|data: &[u8]| {
	let Some((mode, rest)) = data.split_first() else {return};
	match mode & 3 {
		0 | 1 => {
			let Ok(text) = std::str::from_utf8(rest) else {return};
			offered(text);
			answered(text);
		}
		2 => offered(&coded("vwlink1.", rest)),
		_ => answered(&coded("vwlinka1.", rest)),
	}
});
