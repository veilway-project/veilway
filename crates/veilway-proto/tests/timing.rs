//! What a clock sees of `proof::Node::open`: the time of an accepted token against every kind of refusal, in a release build. The hooks of the unit tests count operations. This measures them.
//!
//! It is ignored in an ordinary run, because a debug build and a busy machine say nothing about it. Run it before a release and after any change to `proof.rs` or to the `hpke` dependency:
//!   cargo test -p veilway-proto --release --locked --test timing -- --ignored --nocapture
//! It prints the medians and fails when a class is outside the range it is expected in, measured from an accepted token. Each range is about 0.4 microseconds either side of what that class measured when this was written, which was the same within 0.1 microseconds over several runs on a machine that was also compiling.
//!
//! What it is narrow enough to see: the three exports and two key setups of the session keys cost about 0.55 microseconds together. With that step skipped on refusals, which the unit tests' hooks also catch, the two classes that are closest to an accepted token leave their ranges, and this test fails. A single HMAC, at about 0.1 microseconds, is below what it can see.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{hint::black_box, ops::RangeInclusive, time::Instant};
use veilway_proto::{keys::{Device, Table, TagKey}, proof::{self, Name}, NoRandom};

const INBOUND: [u8; 32] = [0x10; 32];
const DEVICES: u32 = 100_000;
// Tokens per class, and how often each is opened.
const TOKENS: usize = 512;
const ROUNDS: usize = 40;

// What is measured together: a name, the transport the node opens for, the texts, whether they are accepted, and where the median is expected, in nanoseconds from the median of an accepted token.
type Class = (&'static str, Option<Name>, Vec<Vec<u8>>, bool, RangeInclusive<i64>);

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

fn secret(index: u32) -> [u8; 32] {std::array::from_fn(|at| index.to_be_bytes()[at % 4] ^ at as u8)}

// A token of exactly 156 bytes, 208 characters, so that every class has one length.
fn token(key: &[u8; 32], secret: &[u8; 32], device: &[u8; 32], seed: u64) -> Vec<u8> {
	let client = proof::Client::new(&proof::public_key(key), secret, &INBOUND, device);
	(0..).map(|round| client.prove(Name::Tls, 1_700_000_000, &mut seeded(seed * 1000 + round)).unwrap().token).find(|token| token.len() == 208).unwrap().into_bytes()
}

#[test]
#[ignore = "a release build on a quiet machine: see the head of this file"]
fn a_refusal_takes_the_time_of_an_accepted_token_within_the_stated_differences() {
	let (key, mut table, mut random) = ([0x61; 32], Table::new(), seeded(99));
	for index in 0..DEVICES {assert!(table.device(TagKey::derive(&secret(index), &INBOUND).device_tag(), Device::derive(index, &secret(index), &INBOUND, &[7; 32])))}
	let node = proof::Node::new(&[key], &INBOUND, &mut seeded(98)).unwrap();
	// Devices spread over the table, so that an entry that is found is as cold as it would be on a node.
	let spread = |offset: u32| move |index: usize| secret(index as u32 * 190 + offset);
	// The ranges follow the four differences `Node::open` states: a tag that is not in the table is about 0.1 microseconds early, an open that fails about 0.5, and a text that is no token a little more.
	let classes: Vec<Class> = vec![
		("accepted", Some(Name::Tls), (0..TOKENS).map(|index| token(&key, &spread(0)(index), &[7; 32], index as u64)).collect(), true, 0..=0),
		("opens, tag in the table, the binder fails", Some(Name::Tls), (0..TOKENS).map(|index| token(&key, &spread(1)(index), &[8; 32], index as u64)).collect(), false, -350..=250),
		("opens, tag not in the table", Some(Name::Tls), (0..TOKENS).map(|index| token(&key, &secret(DEVICES + index as u32), &[7; 32], index as u64)).collect(), false, -450..=200),
		("a proof on a line that cannot be a user's", None, (0..TOKENS).map(|index| token(&key, &spread(2)(index), &[7; 32], index as u64)).collect(), false, -900..=-50),
		("a proof for another transport", Some(Name::Ws), (0..TOKENS).map(|index| token(&key, &spread(3)(index), &[7; 32], index as u64)).collect(), false, -1050..=-200),
		("random bytes of a token's size", Some(Name::Tls), (0..TOKENS).map(|_| {
			let mut bytes = [0; 156];
			random(&mut bytes).unwrap();
			URL_SAFE_NO_PAD.encode(bytes).into_bytes()
		}).collect(), false, -1050..=-200),
		("no base64: a wrong first character", Some(Name::Tls), (0..TOKENS).map(|index| [&b"="[..], &token(&key, &secret(1), &[7; 32], index as u64)[1..]].concat()).collect(), false, -1100..=-250),
		("no base64: a wrong last character", Some(Name::Tls), (0..TOKENS).map(|index| [&token(&key, &secret(1), &[7; 32], index as u64)[..207], &b"="[..]].concat()).collect(), false, -1100..=-250),
		("a text of no token's size", Some(Name::Tls), (0..TOKENS).map(|_| b"AAAAAAAAAA".to_vec()).collect(), false, -1150..=-300),
	];
	// The classes take turns token by token, so that whatever else the machine does falls on all of them alike. The first round warms up and is not kept.
	let mut samples = vec![Vec::new(); classes.len()];
	for round in 0..=ROUNDS {
		for index in 0..TOKENS {
			for (class, (what, name, texts, accepted, _)) in classes.iter().enumerate() {
				let started = Instant::now();
				let opened = black_box(node.open(*name, black_box(&texts[index]), &table)).is_ok();
				let taken = started.elapsed().as_nanos() as i64;
				assert_eq!(opened, *accepted, "{what}");
				if round > 0 {samples[class].push(taken)}
			}
		}
	}
	let medians: Vec<i64> = samples.into_iter().map(|mut taken| {
		taken.sort_unstable();
		taken[taken.len() / 2]
	}).collect();
	for ((what, ..), median) in classes.iter().zip(&medians) {println!("{median:>8} ns median, {:+6} ns against accepted: {what}", median - medians[0])}
	for ((what, .., expected), median) in classes.iter().zip(&medians) {assert!(expected.contains(&(median - medians[0])), "{what}: {} ns from an accepted token, expected {expected:?}", median - medians[0])}
}
