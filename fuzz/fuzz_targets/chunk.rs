#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use veilway_proto::{chunk::{nonce, parse, write, ChunkError, Opener, Padding, Sealer, MAX_ITEM, MAX_ITEMS, MAX_PLAINTEXT, MAX_SEALED, MIN_ITEM, NORMAL_DEFAULT, TAG, WIDE_DEFAULT}, keys::ChunkKey, NoRandom};

// The first byte picks what the rest is, by its two low bits.
fuzz_target!(|data: &[u8]| {
	let Some((mode, data)) = data.split_first() else {return};
	let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
	let key = || ChunkKey::new(&bytes);
	match mode % 4 {
		// A plaintext. It is sealed here with the library the crate uses and not through the crate's writer, so the opener gets past the tag with any plaintext, and must then decide exactly as the reading rules do.
		0 => {
			let mut sealed = data.to_vec();
			let tag = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &bytes).expect("a key of 32 bytes")).seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(0)), Aad::empty(), &mut sealed).expect("a plaintext of this size seals");
			sealed.extend_from_slice(tag.as_ref());
			let (mut opener, expected) = (Opener::new(key()), parse(data).map(Iterator::collect::<Vec<_>>));
			assert_eq!(opener.open(&mut sealed).map(Iterator::collect::<Vec<_>>), expected, "a chunk opened to something else than its plaintext reads as");
			assert_eq!(opener.number(), u64::from(expected.is_ok()));
			if let Ok(items) = &expected {assert!(items.len() <= MAX_ITEMS && items.iter().all(|item| (MIN_ITEM..=MAX_ITEM).contains(&item.len())), "an item outside the limits was opened")}
			// After a refusal the direction is over, whatever comes next.
			if let Err(error) = expected {assert_eq!(opener.open(&mut [0; 40]).map(Iterator::count), Err(error), "an opener went on after an error")}
		}
		// A sealed chunk from the wire, at number 0 under the key of the seeds.
		1 => {
			let mut sealed = data.to_vec();
			if let Ok(items) = Opener::new(key()).open(&mut sealed) {assert!(items.count() <= MAX_ITEMS && data.len() <= MAX_SEALED)}
		}
		// Items to seal, each a 2 byte size and that many of the bytes that follow. A size may be too small or over the limit, and the sealer must refuse exactly those.
		2 => {
			let (mut items, mut rest) = (Vec::new(), data);
			while let [high, low, tail @ ..] = rest {
				let (item, tail) = tail.split_at(tail.len().min(usize::from(u16::from_be_bytes([*high, *low])) % (MAX_ITEM + 200)));
				items.push(item);
				rest = tail;
			}
			// A draw of four equal bytes below 0x80 is never one a uniform draw has to refuse.
			let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
				bytes.fill(data.len() as u8 & 0x7f);
				Ok(())
			};
			let mut sealer = Sealer::new(key(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).expect("the default bounds are legal"));
			let (used, mut sealed) = (items.iter().map(|item| 2 + item.len()).sum::<usize>(), Vec::new());
			match sealer.seal(&items, mode & 4 != 0, &mut random, &mut sealed) {
				Ok(()) => {
					assert!(sealed.len() >= used + TAG && sealed.len() <= MAX_SEALED, "a sealed chunk of {} bytes for {used} bytes of items", sealed.len());
					assert_eq!(Opener::new(key()).open(&mut sealed).expect("a chunk that was just sealed opens").collect::<Vec<_>>(), items);
				}
				Err(ChunkError::Item) => assert!(items.iter().any(|item| !(MIN_ITEM..=MAX_ITEM).contains(&item.len()))),
				Err(ChunkError::Size) => assert!(used > MAX_PLAINTEXT),
				Err(error) => panic!("sealing failed with {error:?}"),
			}
		}
		// A plaintext for the reader and the writer alone. What reads must read the same when it is written again.
		_ => {
			let Ok(items) = parse(data) else {return};
			let items: Vec<&[u8]> = items.collect();
			let used: usize = items.iter().map(|item| 2 + item.len()).sum();
			let mut again = Vec::new();
			write(&items, data.len() - used, &mut again).expect("what was read can be written");
			assert_eq!((&again[..used], again.len()), (&data[..used], data.len()), "the items were not written as they were read");
			assert_eq!(parse(&again).expect("what was written reads").collect::<Vec<_>>(), items);
		}
	}
});
