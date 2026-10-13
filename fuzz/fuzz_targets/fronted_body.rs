#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use veilway_proto::{chunk::{nonce, parse, MAX_PLAINTEXT}, fronted::{BodyError, Opener, BODY_MAX, BODY_MIN}, keys::ChunkKey};

// The body of a `fronted` request. Four bytes of settings, then what the mode says:
//   0  bit 0 set: the rest is a body as from a stranger who knows a session id. Clear: the rest is chunk plaintexts, each behind a 2 byte size, which are sealed here with the library the crate opens them with and put behind their lengths.
//   1  how many bodies the session accepted before this one, so that its chunk numbers do not start at 0
//   2  which chunk of the body is sealed at a number that is not its own, when bit 1 of byte 0 is set
//   3  how many bytes are cut from the end of the body, when bit 2 of byte 0 is set
// The opener must open a body exactly when every chunk in it opens at its own number and is a valid chunk, end the session exactly when every chunk opens and one is invalid, and in every other case leave the session as it was, so that the body it would have accepted next still opens.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, before, wrong, cut], rest)) = data.split_first_chunk::<4>() else {return};
	let (bytes, before): ([u8; 32], _) = (std::array::from_fn(|i| i as u8), u64::from(before % 8));
	let sealing = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &bytes).expect("a key of 32 bytes"));
	let sealed = |number: u64, plaintext: &[u8]| {
		let mut chunk = plaintext.to_vec();
		let tag = sealing.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(number)), Aad::empty(), &mut chunk).expect("a plaintext of this size seals");
		[&((chunk.len() + 16) as u16).to_be_bytes()[..], &chunk, tag.as_ref()].concat()
	};
	let (mut opener, mut scratch) = (Opener::new(ChunkKey::new(&bytes)), Vec::new());
	for number in 0..before {assert_eq!(opener.open(&sealed(number, &[]), &mut scratch).expect("a body the session's client sealed opens").commit().len(), 1)}
	let next = sealed(before, &[0, 32, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]);
	if flags & 1 == 1 {
		// A stranger cannot make a chunk that opens, so nothing it sends is accepted and nothing ends the session.
		assert_eq!(opener.open(rest, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused), "a body no client sealed was not refused");
	} else {
		let (mut plaintexts, mut left) = (Vec::new(), rest);
		while let [high, low, tail @ ..] = left {
			let (plaintext, tail) = tail.split_at(tail.len().min(usize::from(u16::from_be_bytes([*high, *low])) % (MAX_PLAINTEXT + 1)));
			plaintexts.push(plaintext);
			left = tail;
		}
		let misplaced = (flags & 2 != 0 && !plaintexts.is_empty()).then(|| usize::from(wrong) % plaintexts.len());
		let mut body: Vec<u8> = plaintexts.iter().enumerate().flat_map(|(index, plaintext)| sealed(before + index as u64 + u64::from(misplaced == Some(index)), plaintext)).collect();
		let cut = if flags & 4 != 0 {usize::from(cut).min(body.len())} else {0};
		body.truncate(body.len() - cut);
		// A cut that ends on a chunk leaves a body of fewer chunks.
		let (mut whole, mut end) = (0, 0);
		for plaintext in &plaintexts {
			if end + plaintext.len() + 18 > body.len() {break}
			(whole, end) = (whole + 1, end + plaintext.len() + 18);
		}
		let opens = end == body.len() && (BODY_MIN..=BODY_MAX).contains(&body.len()) && misplaced.is_none_or(|index| index >= whole);
		let expected = if !opens {Err(BodyError::Refused)} else {plaintexts[..whole].iter().map(|plaintext| parse(plaintext).map(Iterator::collect::<Vec<_>>)).collect::<Result<Vec<_>, _>>().map_err(BodyError::Ended)};
		let result = opener.open(&body, &mut scratch).map(|opened| opened.commit().into_iter().map(Iterator::collect::<Vec<_>>).collect::<Vec<_>>());
		assert_eq!(result, expected, "a body was not opened as its chunks read");
		match expected {
			Ok(chunks) => {
				assert_eq!(opener.number(), before + chunks.len() as u64);
				assert_eq!(opener.open(&body, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Refused), "an accepted body opened a second time");
				return;
			}
			Err(BodyError::Ended(error)) => {
				assert_eq!(opener.open(&next, &mut scratch).map(|opened| opened.chunks().len()), Err(BodyError::Ended(error)), "a session went on after it ended");
				return;
			}
			Err(BodyError::Refused) => {}
		}
	}
	assert_eq!(opener.number(), before, "a refused body moved the chunk numbers");
	assert_eq!(opener.open(&next, &mut scratch).map(|opened| opened.commit().len()), Ok(1), "a refused body disturbed the session");
});
