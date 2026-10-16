//! The sealed subscription file: the vector the spec prints, the refusals, and the round trip from a link through a file back to the same link.
use std::fs;
use veilway_proto::subscription::{link::Link, sealed_file::{self, OpenError, SealError, COST, FILE_MAX, HEADER}};

const PASSWORD: &str = "correct horse battery";
const SALT: [u8; 16] = [7; 16];
const NONCE: [u8; 12] = [9; 12];

fn seed(name: &str) -> String {String::from_utf8(fs::read(format!("{}/../../fuzz/corpus/fuzz_deeplink/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

#[test]
fn the_file_of_the_vector_is_these_bytes() {
	let file = sealed_file::seal(PASSWORD, &seed("native-veilway"), SALT, NONCE).unwrap();
	assert_eq!(hex(&file), VECTOR);
	assert_eq!(sealed_file::open(PASSWORD, &file).unwrap(), seed("native-veilway"));
}

#[test]
fn the_seed_of_the_fuzz_target_still_opens() {
	let file = fs::read(format!("{}/../../fuzz/corpus/fuzz_sub_sealed/file", env!("CARGO_MANIFEST_DIR"))).unwrap();
	assert_eq!(sealed_file::open(PASSWORD, &file).unwrap(), seed("native-veilway"));
}

#[test]
fn a_link_goes_into_a_file_and_comes_out_the_same_link() {
	for name in ["native-veilway", "native-pinned", "native-pinned-address", "native-pinned-ipv6"] {
		let text = seed(name);
		let file = sealed_file::seal(PASSWORD, &text, SALT, NONCE).unwrap();
		assert!(sealed_file::is_sealed(&file) && file.len() == HEADER + text.len() + 16, "{name}");
		let opened = sealed_file::open(PASSWORD, &file).unwrap();
		assert_eq!(Link::parse(&opened).unwrap(), Link::parse(&text).unwrap(), "{name}");
	}
	let carried = seed("document");
	assert!(matches!(Link::parse(&carried), Ok(Link::Carried(_))), "the seed is a document in a link");
	assert_eq!(sealed_file::open(PASSWORD, &sealed_file::seal(PASSWORD, &carried, SALT, NONCE).unwrap()).unwrap(), carried);
}

#[test]
fn a_wrong_password_and_every_changed_byte_are_one_error() {
	let file = sealed_file::seal(PASSWORD, &seed("native-veilway"), SALT, NONCE).unwrap();
	assert_eq!(sealed_file::open("correct horse batterz", &file), Err(OpenError::Wrong));
	assert_eq!(sealed_file::open("", &file), Err(OpenError::Wrong));
	// The salt, the nonce, a byte of the body and one of the tag. A byte of the cost or the version has its own refusal, below.
	for at in [21, 36, 37, 48, HEADER, HEADER + 5, file.len() - 1] {
		let mut changed = file.clone();
		changed[at] ^= 1;
		assert_eq!(sealed_file::open(PASSWORD, &changed), Err(OpenError::Wrong), "byte {at}");
	}
	let mut cut = file.clone();
	cut.pop();
	assert_eq!(sealed_file::open(PASSWORD, &cut), Err(OpenError::Wrong));
}

#[test]
fn the_header_is_read_before_any_hashing() {
	let file = sealed_file::seal(PASSWORD, &seed("native-veilway"), SALT, NONCE).unwrap();
	let with = |at: usize, bytes: &[u8]| {
		let mut changed = file.clone();
		changed[at..at + bytes.len()].copy_from_slice(bytes);
		changed
	};
	assert_eq!(sealed_file::open(PASSWORD, &with(0, b"VWSUBSEB")), Err(OpenError::NotSealed));
	assert_eq!(sealed_file::open(PASSWORD, &file[..HEADER + 15]), Err(OpenError::NotSealed));
	assert_eq!(sealed_file::open(PASSWORD, &[0u8; FILE_MAX + 1]), Err(OpenError::Size));
	assert_eq!(sealed_file::open(PASSWORD, &with(8, &[2])), Err(OpenError::Version(2)));
	// Too much to ask of a device: a gigabyte, a hundred passes, a hundred lanes. Each is refused with no memory allocated, and so is too little.
	for (at, bytes) in [(9, 1_048_576u32), (9, COST.0 - 1), (9, u32::MAX), (13, 100), (13, COST.1 - 1), (13, u32::MAX), (17, 100), (17, 0)] {assert_eq!(sealed_file::open(PASSWORD, &with(at, &bytes.to_be_bytes())), Err(OpenError::Cost), "{at} {bytes}")}
}

#[test]
fn a_file_asking_for_the_most_a_client_opens_is_opened() {
	let file = sealed_file::seal_at((131_072, 6, 4), PASSWORD, &seed("native-veilway"), SALT, NONCE).unwrap();
	assert_eq!(sealed_file::open(PASSWORD, &file).unwrap(), seed("native-veilway"));
}

#[test]
fn only_a_long_enough_password_and_a_subscription_link_are_sealed() {
	assert_eq!(sealed_file::seal("short one", &seed("native-veilway"), SALT, NONCE), Err(SealError::Password));
	assert_eq!(sealed_file::seal(&"a".repeat(1025), &seed("native-veilway"), SALT, NONCE), Err(SealError::Password));
	assert!(sealed_file::seal("ten chars!", &seed("native-veilway"), SALT, NONCE).is_ok());
	// Ten characters are ten, not ten bytes.
	assert!(sealed_file::seal("دوازده‌حرف۱۲", &seed("native-veilway"), SALT, NONCE).is_ok());
	assert_eq!(sealed_file::seal_at((1, 1, 1), PASSWORD, &seed("native-veilway"), SALT, NONCE), Err(SealError::Cost));
	assert_eq!(sealed_file::seal(PASSWORD, &seed("legacy"), SALT, NONCE), Err(SealError::Link));
	assert_eq!(sealed_file::seal(PASSWORD, "not a link", SALT, NONCE), Err(SealError::Link));
	assert_eq!(sealed_file::seal(PASSWORD, &format!("{}\n", seed("native-veilway")), SALT, NONCE), Err(SealError::Link));
}

// Made again with argon2-cffi and cryptography from the values of the spec: password "correct horse battery", salt of sixteen 0x07, nonce of twelve 0x09, the link of the seed "native-veilway".
const VECTOR: &str = "5657535542534541010001000000000003000000010707070707070707070707070707070709090909090909090909090966802ab495a740c98ea383a9ccf97fc7ba1d350bf66efd7fe9855a54bba3f8b67fb1cf40753399b129afd10474cf22f319edd5132b8643d19ea37624d118f17c22517776e674d0d826e99bd7005a5c62fabed6a3bea14c440e54f6f0399e3b7dce3113dd6e796a8f3fd5d201e51425413cea3aeceb";
