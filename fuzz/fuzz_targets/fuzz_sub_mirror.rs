#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::{keys::MirrorKeys, subscription::mirror::{self, OpenError}, NoRandom};

// The body of an answer from a static mirror, from anyone. The whole input is the body, opened with the keys, base URL and period of the static mirror vector in `tests/vectors.py`.
// A body of another size is told apart from one that does not open. A body that opens has one of the five sizes, an envelope within what the size holds, and is the one file a panel writes for that envelope under that salt.
fuzz_target!(|data: &[u8]| {
	let keys = MirrorKeys::derive(&std::array::from_fn(|index| 1 + index as u8), &std::array::from_fn(|index| 0x21 + index as u8), &std::array::from_fn(|index| 0x41 + index as u8));
	let base = "https://files.example.net/vw/";
	match mirror::open(&keys, base, 2000, data) {
		Ok(envelope) => {
			assert!(mirror::SIZES.contains(&data.len()) && (1..=mirror::capacity(data.len()).unwrap()).contains(&envelope.len()), "an envelope outside what its file holds");
			let salt = &data[..32];
			let mut same = |bytes: &mut [u8]| -> Result<(), NoRandom> {bytes.copy_from_slice(salt); Ok(())};
			assert_eq!(mirror::seal(&keys, base, 2000, data.len(), &envelope, &mut same).as_deref(), Ok(data), "a file that opened is not the one a panel writes for its envelope");
		}
		Err(OpenError::Size) => assert!(!mirror::SIZES.contains(&data.len()), "a body of one of the five sizes was refused for its size"),
		Err(_) => assert!(mirror::SIZES.contains(&data.len()), "a body of another size was read past its size"),
	}
});
