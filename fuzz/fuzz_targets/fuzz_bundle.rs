#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::OnceLock;
use veilway_proto::subscription::{bundle::{self, Index, Input}, envelope::SigningKey};

// The signer of every bundle here: a key made from the seed 0x33 repeated.
fn signer() -> &'static (Ed25519KeyPair, SigningKey) {
	static SIGNER: OnceLock<(Ed25519KeyPair, SigningKey)> = OnceLock::new();
	SIGNER.get_or_init(|| {
		let pair = Ed25519KeyPair::from_seed_unchecked(&[0x33; 32]).expect("a seed is 32 bytes");
		let key = SigningKey::new(pair.public_key().as_ref().try_into().expect("a public key is 32 bytes")).expect("a key from a seed is of full order");
		(pair, key)
	})
}

// A bundle with an app part, a pack of decoys and a notice, which the first byte's mode changes. The head ends at `bundle::head` plus 85 bytes.
fn document() -> &'static Vec<u8> {
	static DOCUMENT: OnceLock<Vec<u8>> = OnceLock::new();
	DOCUMENT.get_or_init(|| {
		let (pair, key) = signer();
		let mut state = 0x9e37_79b9_7f4a_7c15u64;
		let mut random = |bytes: &mut [u8]| {
			for byte in bytes {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = state as u8;
			}
			Ok(())
		};
		let pack = bundle::assemble(vec![([1; 16], vec![2; 9_413])], 9_413, &mut random).expect("a pack of one file");
		let (app, notice) = (vec![1; 16], vec![3; 20]);
		let inputs = [
			Input::App {platform: "linux-x86_64", version: "1.0.0", name: "veilway.AppImage", signature: "s", bytes: &app},
			Input::Pack {periods: &[4], bytes: &pack},
			Input::Notice {bytes: &notice},
		];
		let head = bundle::make(*key, [9; 16], 1_000, &inputs, |bytes| pair.sign(bytes).as_ref().try_into().expect("a signature is 64 bytes")).expect("a bundle the reader reads");
		[head, app, pack, notice].concat()
	})
}

// The first byte picks what the rest is, by its lowest two bits:
//   0  a file as it arrives. The head and the manifest are read as far as they go, and a manifest that verifies is read through each part's hash.
//   1  the good bundle with three bytes changed each: a position, as two bytes, and a byte that is added to the byte there. The manifest verifies exactly when the change is outside the head and manifest, and no part passes its hash when its bytes changed.
//   2  arbitrary bytes as a notice, under the key held and at a clock of 1,000.
//   3  arbitrary bytes as the index of a pack of the rest's length, and as the text of a version.
fuzz_target!(|data: &[u8]| {
	let Some((mode, rest)) = data.split_first() else {return};
	let held = [signer().1];
	match mode & 3 {
		0 => {
			let _ = bundle::head(rest).and_then(|m| bundle::manifest(&rest[..rest.len().min(bundle::HEAD + m + 64)], &held, rest.len() as u64));
		}
		1 => {
			let good = document();
			let mut changed = good.clone();
			for change in rest.chunks_exact(3) {
				let at = usize::from(u16::from_be_bytes([change[0], change[1]])) % changed.len();
				changed[at] = changed[at].wrapping_add(change[2]);
			}
			let head_end = bundle::HEAD + bundle::head(good).expect("the good bundle has a head") + 64;
			let verified = bundle::head(&changed).and_then(|m| bundle::manifest(&changed[..changed.len().min(bundle::HEAD + m + 64)], &held, changed.len() as u64));
			assert_eq!(verified.is_err(), changed[..head_end] != good[..head_end], "a changed head verified, or an unchanged one did not");
		}
		2 => {
			let _ = bundle::notice(rest, &held, 1_000, &[]);
		}
		_ => {
			let _ = bundle::Version::read(&String::from_utf8_lossy(rest));
			if let Ok(len) = bundle::index_len(rest.get(..8).unwrap_or(&[]), rest.len() as u64) {
				if let Ok(index) = Index::read(&rest[..len.min(rest.len())], rest.len() as u64) {
					let _ = index.find(&[0; 16]);
				}
			}
		}
	}
});
