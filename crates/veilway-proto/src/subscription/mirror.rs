//! Static mirrors (subscription format page, "Static mirrors"): the periods, the names, and the file that a panel seals for one device and a client opens, with no IO.
//!
//! A file is `salt (32) || ChaCha20-Poly1305(n (4) || envelope (n) || zeros) || tag (16)`, one of five sizes, with no magic, no version and no length in the clear. `seal` is the panel's side and `open` the client's. Opening proves only that the file was made by someone who knows `k_mirror`: its envelope still goes through every check of an answer from the endpoint (`Held::refresh_static`), by the same code.
use super::{Url, BODY_MAX};
use crate::{keys::{MirrorKeys, MIRROR_FILE}, NoRandom, Random};
use ring::aead;
use std::{fmt, time::Duration};

/// "Mirror period `P`: 604,800 s, fixed."
pub const PERIOD: u64 = 604_800;
/// "Overlap of mirror periods `W`: 86,400 s, fixed. No static file lives longer than `P + 2W`."
pub const OVERLAP: u64 = 86_400;
/// "Size of a static file: 9,413, 36,979, 140,867, 538,201 or 1,089,437 bytes."
pub const SIZES: [usize; 5] = [9_413, 36_979, 140_867, 538_201, 1_089_437];
/// "Static mirrors: at most 4."
pub const MIRRORS_MAX: usize = 4;
/// "Static mirror base URL: at most 216 characters, ending in `/`."
pub const BASE_MAX: usize = 216;
// The salt, the length and the tag: what a file holds besides the envelope and the zeros.
const OVERHEAD: usize = 52;

/// Why a file is not opened. Each is a failure of that static mirror and nothing more: "A failure is never a revocation."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
	/// The body is not exactly one of the five sizes.
	Size,
	/// The tag does not verify: another key, another name or period, or a changed byte.
	Seal,
	/// `n` is 0 or more than the file holds.
	Length,
	/// A byte after the envelope is not zero.
	Padding,
}

impl fmt::Display for OpenError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "static mirror file: {self:?}")}
}

impl std::error::Error for OpenError {}

/// Why a file was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
	/// `size` is none of the five sizes.
	Size,
	/// The envelope is empty or larger than the size holds.
	Envelope,
	/// The salt could not be drawn.
	Random,
}

impl fmt::Display for SealError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "static mirror file: {self:?}")}
}

impl std::error::Error for SealError {}

/// The period number, `floor(unix_time / P)`.
pub fn epoch(now: u64) -> u64 {now / PERIOD}

/// `start(e)` = `e × P`.
pub fn start(epoch: u64) -> u64 {epoch.saturating_mul(PERIOD)}

/// The periods whose files a publishing round at `now` writes ("Periods and clocks"): the period of `now`, the next one from `W` before it begins, and the one before until `W` after it ended. A file of any other period is deleted.
pub fn live(now: u64) -> Vec<u64> {
	let current = epoch(now);
	let mut periods = Vec::new();
	if current > 0 && now <= start(current).saturating_add(OVERLAP) {periods.push(current - 1)}
	periods.push(current);
	if now.saturating_add(OVERLAP) >= start(current + 1) {periods.push(current + 1)}
	periods
}

/// What a confirmed static host is kept as, apart from the refresh hosts: `host:port#static`.
pub fn host_key(base: &Url) -> String {format!("{}#static", base.authority())}

/// The file name for `epoch`: `mirror_id` in lowercase hexadecimal, then `.bin`. The file URL is `base_url` followed by it, with nothing between.
pub fn file_name(keys: &MirrorKeys, base_url: impl AsRef<[u8]>, epoch: u64) -> String {
	let mut name: String = keys.id(epoch, base_url).iter().map(|byte| format!("{byte:02x}")).collect();
	name.push_str(".bin");
	name
}

/// The largest envelope a file of `size` holds: the size minus 52, and never above the response body limit. `None` for a size that is none of the five.
pub fn capacity(size: usize) -> Option<usize> {SIZES.contains(&size).then(|| (size - OVERHEAD).min(BODY_MAX))}

/// The smallest size that holds an envelope of `length` bytes, or `None` for one that is empty or over the limit. A folder uses the smallest size that holds its largest envelope.
pub fn size_for(length: usize) -> Option<usize> {SIZES.into_iter().find(|size| capacity(*size).is_some_and(|capacity| (1..=capacity).contains(&length)))}

/// "The time limit is the one of the size the answer's `Content-Length` names, and of the largest size when it names none or names another number."
pub fn time_limit(length: Option<usize>) -> Duration {
	Duration::from_secs(match length.and_then(|length| SIZES.iter().position(|size| *size == length)) {
		Some(0 | 1) => 30,
		Some(2) => 60,
		Some(3) => 120,
		_ => 240,
	})
}

fn key_and_aad(keys: &MirrorKeys, base_url: impl AsRef<[u8]>, epoch: u64, salt: &[u8; 32]) -> (crate::keys::ChunkKey, Vec<u8>) {
	(keys.file(salt), [MIRROR_FILE, &keys.id(epoch, base_url)].concat())
}

/// The file of one device for one period on the static mirror of `base_url`, of `size` bytes (one of `SIZES`): the panel's side. `envelope` is the signed document as the endpoint would answer, without `usage`, or a signed refusal. The salt is drawn here from `random` and is never reused, so each write has a key of its own and the zero nonce is used once per key.
pub fn seal(keys: &MirrorKeys, base_url: impl AsRef<[u8]>, epoch: u64, size: usize, envelope: &[u8], random: &mut Random) -> Result<Vec<u8>, SealError> {
	let capacity = capacity(size).ok_or(SealError::Size)?;
	if envelope.is_empty() || envelope.len() > capacity {return Err(SealError::Envelope)}
	let mut salt = [0; 32];
	random(&mut salt).map_err(|NoRandom| SealError::Random)?;
	let (key, aad) = key_and_aad(keys, base_url, epoch, &salt);
	let mut sealed = Vec::with_capacity(size);
	sealed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
	sealed.extend_from_slice(envelope);
	sealed.resize(size - 48, 0);
	let tag = key.0.seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key([0; 12]), aead::Aad::from(aad), &mut sealed).expect("a file is far below the limit of ChaCha20-Poly1305");
	Ok([&salt[..], &sealed, tag.as_ref()].concat())
}

/// "How the client opens a file", steps 1 to 3, in order: the size first, then the seal, then the length and the zeros. The envelope it gives back goes to `Held::refresh_static`, which runs the rest.
pub fn open(keys: &MirrorKeys, base_url: impl AsRef<[u8]>, epoch: u64, body: &[u8]) -> Result<Vec<u8>, OpenError> {
	let capacity = capacity(body.len()).ok_or(OpenError::Size)?;
	let salt: [u8; 32] = body[..32].try_into().expect("a file holds its salt");
	let (key, aad) = key_and_aad(keys, base_url, epoch, &salt);
	let mut opened = body[32..].to_vec();
	let plain = key.0.open_in_place(aead::Nonce::assume_unique_for_key([0; 12]), aead::Aad::from(aad), &mut opened).map_err(|_| OpenError::Seal)?;
	let length = u32::from_be_bytes(plain[..4].try_into().expect("a file holds its length")) as usize;
	if length == 0 || length > capacity {return Err(OpenError::Length)}
	if plain[4 + length..].iter().any(|byte| *byte != 0) {return Err(OpenError::Padding)}
	Ok(plain[4..4 + length].to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;
	use ring::digest::{digest, SHA256};

	const BASE: &str = "https://files.example.net/vw/";

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	// The inputs of tests/vectors.py: token 01..10, device secret 21..30, device_pub 41..60, and a salt of 80..9f.
	fn keys() -> MirrorKeys {MirrorKeys::derive(&std::array::from_fn(|i| 1 + i as u8), &std::array::from_fn(|i| 0x21 + i as u8), &std::array::from_fn(|i| 0x41 + i as u8))}

	fn fixed(bytes: &mut [u8]) -> Result<(), NoRandom> {
		for (index, byte) in bytes.iter_mut().enumerate() {*byte = 0x80 + index as u8}
		Ok(())
	}

	fn broken(_: &mut [u8]) -> Result<(), NoRandom> {Err(NoRandom)}

	// A file with any plaintext at all, sealed the way `seal` does, for the cases a panel never writes.
	fn forged(plain: Vec<u8>, size: usize) -> Vec<u8> {
		let (salt, mut plain) = ([0x80; 32], plain);
		plain.resize(size - 48, 0);
		let key = keys().file(&salt);
		let tag = key.0.seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key([0; 12]), aead::Aad::from([MIRROR_FILE, &keys().id(2000, BASE)].concat()), &mut plain).unwrap();
		[&salt[..], &plain, tag.as_ref()].concat()
	}

	// Expected values come from tests/vectors.py, which uses only Python's hmac and hashlib and a ChaCha20-Poly1305 written out from RFC 8439.
	#[test]
	fn the_keys_and_the_name_are_the_ones_the_specification_derives() {
		let keys = keys();
		let (name, key) = keys.expose();
		assert_eq!(hex(name), "e51da8f1ac5e86f8e82d38263a9be4d9e5475244df049ccc8d883f76fdb485c4");
		assert_eq!(hex(key), "b8ff922d98c7e74b613574b516f1b36aa7ed924c2ad698ddfb9661e52ab62278");
		assert_eq!(hex(&keys.id(2000, BASE)), "41061aa1ae12d729f9dd2f2d5f715408");
		assert_eq!(file_name(&keys, BASE, 2000), "41061aa1ae12d729f9dd2f2d5f715408.bin");
		assert_eq!(hex(&keys.id(2001, BASE)), "4e83a838a81e0da8089cde74f331fac2");
		assert_eq!(hex(&keys.id(2000, "https://files.example.net/vx/")), "95641ef2aeed852ee6b08ce9e5799da6");
		assert_eq!(MirrorKeys::restore(*name, *key).id(2000, BASE), keys.id(2000, BASE));
		assert_eq!(format!("{keys:?}"), "MirrorKeys(..)");
	}

	#[test]
	fn a_key_changes_with_every_input_and_a_name_with_every_period_and_base() {
		let (token, secret, public, keys) = ([1; 16], [2; 16], [3; 32], keys());
		let base = MirrorKeys::derive(&token, &secret, &public);
		for other in [MirrorKeys::derive(&[9; 16], &secret, &public), MirrorKeys::derive(&token, &[9; 16], &public), MirrorKeys::derive(&token, &secret, &[9; 32])] {assert!(other.expose().0 != base.expose().0 && other.expose().1 != base.expose().1)}
		assert_ne!(base.expose().0, base.expose().1);
		assert_ne!(keys.id(1, BASE), keys.id(2, BASE));
		assert_ne!(keys.id(1, BASE), keys.id(1, "https://files.example.net/vw"));
		assert_eq!(hex(&keys.id(1, BASE)).len(), 32);
	}

	#[test]
	fn the_sealed_file_is_the_one_the_specification_writes_byte_for_byte() {
		let file = seal(&keys(), BASE, 2000, 9_413, b"veilway static mirror test vector", &mut fixed).unwrap();
		assert_eq!(file.len(), 9_413);
		assert_eq!(hex(&file[..48]), "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f6698f3e5d7ee42a2fc67ad5a1154bbfb");
		assert_eq!(hex(&file[9_397..]), "f297f77add1830549d7d8d6715fe435e");
		assert_eq!(hex(digest(&SHA256, &file).as_ref()), "863389c734cb351fa2456037c58716e7d40cc6cfd6be326f242a56f6fdb829a1");
		assert_eq!(open(&keys(), BASE, 2000, &file).unwrap(), b"veilway static mirror test vector");
	}

	#[test]
	fn every_size_holds_its_largest_envelope_and_one_byte() {
		for size in SIZES {
			let largest = capacity(size).unwrap();
			for length in [1, largest / 2, largest] {
				let envelope: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
				let file = seal(&keys(), BASE, 2000, size, &envelope, &mut fixed).unwrap();
				assert_eq!((file.len(), open(&keys(), BASE, 2000, &file)), (size, Ok(envelope)), "{size} {length}");
			}
			assert_eq!(seal(&keys(), BASE, 2000, size, &vec![1; largest + 1], &mut fixed), Err(SealError::Envelope), "{size}");
		}
		assert_eq!(SIZES.map(|size| capacity(size).unwrap()), [9_361, 36_927, 140_815, 538_149, 1_048_576]);
		assert_eq!((capacity(0), capacity(9_412), capacity(9_414), capacity(BODY_MAX)), (None, None, None, None));
	}

	#[test]
	fn the_smallest_size_that_holds_an_envelope_is_chosen() {
		for (length, size) in [(1, 9_413), (9_361, 9_413), (9_362, 36_979), (36_927, 36_979), (36_928, 140_867), (140_815, 140_867), (140_816, 538_201), (538_149, 538_201), (538_150, 1_089_437), (BODY_MAX, 1_089_437)] {assert_eq!(size_for(length), Some(size), "{length}")}
		assert_eq!((size_for(0), size_for(BODY_MAX + 1)), (None, None));
	}

	#[test]
	fn the_time_limit_follows_the_size_the_length_names() {
		let seconds: Vec<u64> = SIZES.iter().map(|size| time_limit(Some(*size)).as_secs()).collect();
		assert_eq!(seconds, [30, 30, 60, 120, 240]);
		for other in [None, Some(0), Some(9_412), Some(1_000_000_000)] {assert_eq!(time_limit(other).as_secs(), 240, "{other:?}")}
	}

	#[test]
	fn a_body_of_another_size_is_refused_before_anything_else() {
		let file = seal(&keys(), BASE, 2000, 9_413, b"x", &mut fixed).unwrap();
		for body in [&file[..0], &file[..9_412], &[&file[..], &[0]].concat()[..], &file[..32], &[0; 9_414][..]] {assert_eq!(open(&keys(), BASE, 2000, body), Err(OpenError::Size), "{}", body.len())}
		assert_eq!(seal(&keys(), BASE, 2000, 9_412, b"x", &mut fixed), Err(SealError::Size));
		assert_eq!(seal(&keys(), BASE, 2000, 9_413, b"", &mut fixed), Err(SealError::Envelope));
		assert_eq!(seal(&keys(), BASE, 2000, 9_413, b"x", &mut broken), Err(SealError::Random));
	}

	#[test]
	fn a_changed_byte_anywhere_is_a_failed_seal() {
		let file = seal(&keys(), BASE, 2000, 9_413, b"an envelope", &mut fixed).unwrap();
		for at in [0, 31, 32, 33, 40, 4_000, 9_396, 9_397, 9_412] {
			let mut changed = file.clone();
			changed[at] ^= 1;
			assert_eq!(open(&keys(), BASE, 2000, &changed), Err(OpenError::Seal), "{at}");
		}
	}

	#[test]
	fn the_name_the_period_the_base_and_the_device_are_bound_into_the_seal() {
		let file = seal(&keys(), BASE, 2000, 9_413, b"an envelope", &mut fixed).unwrap();
		assert!(open(&keys(), BASE, 2000, &file).is_ok());
		for (keys, base, epoch) in [(keys(), BASE, 1999), (keys(), BASE, 2001), (keys(), "https://files.example.net/vx/", 2000), (keys(), "https://files.example.net/vw", 2000), (MirrorKeys::derive(&[1; 16], &[2; 16], &[3; 32]), BASE, 2000)] {assert_eq!(open(&keys, base, epoch, &file), Err(OpenError::Seal), "{base} {epoch}")}
		// Another device's key moved over this file: the same token and secret with another device_pub.
		let other = MirrorKeys::derive(&std::array::from_fn(|i| 1 + i as u8), &std::array::from_fn(|i| 0x21 + i as u8), &[7; 32]);
		assert_eq!(open(&other, BASE, 2000, &file), Err(OpenError::Seal));
		// One salt is one key: the same envelope under another salt is another file.
		let mut counted = 0u8;
		let mut other_salt = |bytes: &mut [u8]| -> Result<(), NoRandom> {counted += 1; bytes.fill(counted); Ok(())};
		let again = seal(&keys(), BASE, 2000, 9_413, b"an envelope", &mut other_salt).unwrap();
		assert!(again[..32] != file[..32] && again[32..9_397] != file[32..9_397] && open(&keys(), BASE, 2000, &again).is_ok());
	}

	#[test]
	fn a_file_has_exactly_one_valid_form() {
		let size = 9_413;
		let plain = |length: u32, envelope: &[u8], tail: &[u8]| forged([&length.to_be_bytes()[..], envelope, tail].concat(), size);
		assert_eq!(open(&keys(), BASE, 2000, &plain(3, b"abc", b"")), Ok(b"abc".to_vec()));
		assert_eq!(open(&keys(), BASE, 2000, &plain(0, b"", b"")), Err(OpenError::Length));
		assert_eq!(open(&keys(), BASE, 2000, &plain(9_361, &[7; 9_361], b"")), Ok(vec![7; 9_361]));
		for length in [9_362, 9_365, 1 << 20, u32::MAX] {assert_eq!(open(&keys(), BASE, 2000, &plain(length, b"abc", b"")), Err(OpenError::Length), "{length}")}
		for (place, tail) in [(0, vec![1]), (100, vec![0; 100]), (9_000, vec![0xff])] {
			let mut padded = vec![0; place];
			padded.extend(tail);
			assert_eq!(open(&keys(), BASE, 2000, &plain(3, b"abc", &padded)), if padded.iter().any(|byte| *byte != 0) {Err(OpenError::Padding)} else {Ok(b"abc".to_vec())}, "{place}");
		}
		// A length that stops short leaves bytes of the envelope in the padding, and they are not zero.
		assert_eq!(open(&keys(), BASE, 2000, &plain(2, b"abc", b"")), Err(OpenError::Padding));
	}

	#[test]
	fn the_period_changes_on_its_boundary_and_the_publisher_covers_a_day_either_way() {
		assert_eq!((epoch(0), epoch(PERIOD - 1), epoch(PERIOD), epoch(2000 * PERIOD + 5), start(2000)), (0, 0, 1, 2000, 2000 * PERIOD));
		let (e, begin) = (5, start(5));
		assert_eq!(live(begin), vec![4, 5]);
		assert_eq!(live(begin + OVERLAP), vec![4, 5]);
		assert_eq!(live(begin + OVERLAP + 1), vec![5]);
		assert_eq!(live(begin + PERIOD - OVERLAP - 1), vec![5]);
		assert_eq!(live(begin + PERIOD - OVERLAP), vec![5, 6]);
		assert_eq!(live(begin + PERIOD - 1), vec![5, 6]);
		assert_eq!((live(start(e + 1)), live(0), live(OVERLAP), live(OVERLAP + 1), live(PERIOD - OVERLAP)), (vec![5, 6], vec![0], vec![0], vec![0], vec![0, 1]));
		// No file lives longer than `P + 2W`: the first moment a period is written and the last.
		let period = 9;
		let times: Vec<u64> = (start(period - 1)..start(period + 2)).step_by(3_600).filter(|now| live(*now).contains(&period)).collect();
		assert!(times.last().unwrap() - times[0] <= PERIOD + 2 * OVERLAP && times[0] == start(period) - OVERLAP && *times.last().unwrap() == start(period + 1) + OVERLAP);
	}

	#[test]
	fn a_static_host_is_kept_as_its_own_kind() {
		let base = Url::parse(BASE, BASE_MAX, false, false).unwrap();
		assert_eq!(host_key(&base), "files.example.net:443#static");
		assert_eq!(host_key(&Url::parse("https://files.example.net:8443/a/", BASE_MAX, false, false).unwrap()), "files.example.net:8443#static");
	}
}
