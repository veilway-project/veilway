#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::OnceLock;
use veilway_proto::subscription::{envelope::{self, SigningKey}, payload, BODY_MAX};

// A document of tests/vectors.py, signed by the first of the two keys below. Its first byte is the settings byte of the seed.
const DOCUMENT: &[u8] = include_bytes!("../corpus/fuzz_sub_envelope/document");

// The two provider keys a client holds here: the seeds 11..11 and 22..22.
fn pairs() -> &'static [(Ed25519KeyPair, SigningKey); 2] {
	static PAIRS: OnceLock<[(Ed25519KeyPair, SigningKey); 2]> = OnceLock::new();
	PAIRS.get_or_init(|| [0x11, 0x22].map(|fill| {
		let pair = Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).expect("a seed is 32 bytes");
		let key = SigningKey::new(pair.public_key().as_ref().try_into().expect("a public key is 32 bytes")).expect("a key from a seed is of full order");
		(pair, key)
	}))
}

// The verifier of the envelope on bytes nobody signed. The first byte picks what the rest is, by its lowest bit:
//   0  a document as it arrives. It must be refused, unless it is one a holder of a private key made: sealing its payload again under the key it verified under must give the same bytes, so nothing but the one encoding of a part, the exact header of a held key and a signature of RFC 8032 gets through. What verifies is then read as a payload. Under no held key at all, nothing verifies.
//   1  changes to a good document, three bytes each: a position, as two bytes, and a byte that is added to the byte there. The document must verify exactly when nothing is left changed.
fuzz_target!(|data: &[u8]| {
	let Some((mode, rest)) = data.split_first() else {return};
	let held = [pairs()[0].1, pairs()[1].1];
	if mode & 1 == 0 {
		if let Ok(verified) = envelope::verify(rest, &held, BODY_MAX) {
			let pair = &pairs()[usize::from(verified.signer() != held[0])].0;
			assert_eq!(envelope::seal(&verified.signer(), verified.payload(), |signed| pair.sign(signed).as_ref().try_into().expect("a signature is 64 bytes")).as_bytes(), rest, "a document verified that the holder of the key did not write this way");
			let _ = payload::parse(&verified);
		}
		assert!(envelope::verify(rest, &[], BODY_MAX).is_err() && envelope::verify(rest, &held, rest.len().saturating_sub(1)).is_err(), "a document verified under no key, or over its size limit");
	} else {
		let mut document = DOCUMENT[1..].to_vec();
		for change in rest.chunks_exact(3) {
			let at = usize::from(u16::from_be_bytes([change[0], change[1]])) % document.len();
			document[at] = document[at].wrapping_add(change[2]);
		}
		assert_eq!(envelope::verify(&document, &held, BODY_MAX).is_ok(), document == DOCUMENT[1..], "a changed document verified, or an unchanged one did not");
	}
});
