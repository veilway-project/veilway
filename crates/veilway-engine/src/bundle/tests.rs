use super::*;
use crate::import::FileVault;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{fs, io::Cursor};
use veilway_proto::subscription::bundle::{make, Input};

const NOW: u64 = 1_000;

fn pair(fill: u8) -> (Ed25519KeyPair, SigningKey) {
	let pair = Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).expect("32 bytes");
	let key = SigningKey::new(pair.public_key().as_ref().try_into().expect("32 bytes")).expect("a key of full order");
	(pair, key)
}

fn scratch(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-bundle-{name}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).expect("a temporary folder");
	dir
}

// A minisign signature file whose global signature is made by `key` over the signature bytes and `comment`, as the release job writes it.
fn signature(key: &(Ed25519KeyPair, SigningKey), comment: &str) -> String {
	let sig = [7u8; 64];
	let global = key.0.sign(&[&sig[..], comment.as_bytes()].concat());
	let line = STANDARD.encode([b"Ed".as_slice(), &[1; 8], &sig].concat());
	format!("untrusted comment: test\n{line}\ntrusted comment: {comment}\n{}\n", STANDARD.encode(global.as_ref()))
}

// A bundle of one linux app part, whose manifest says `version` and whose signature text is `signature`, and of a notice that is no notice at all.
fn bundle(signer: &(Ed25519KeyPair, SigningKey), version: &str, signature: &str, app: &[u8]) -> Vec<u8> {
	let notice = b"not a notice";
	let inputs = [Input::App {platform: "linux-x86_64", version, name: "veilway.AppImage", signature, bytes: app}, Input::Notice {bytes: notice}];
	let mut file = make(signer.1, [5; 16], NOW, &inputs, |bytes| signer.0.sign(bytes).as_ref().try_into().expect("64 bytes")).expect("a bundle");
	file.extend(app);
	file.extend(notice);
	file
}

fn run(source: &[u8], families: &[SigningKey], platform: &str, dir: &Path) -> Result<Review, Error> {
	let library = Library::open(Box::new(FileVault(dir.join("vault")))).expect("an empty library").0;
	let check = Check {families, platform, running: "0.2.0", now: NOW, last: &[]};
	review(&mut Cursor::new(source), &dir.join("copy.vwbundle"), &library, &check)
}

fn good(_dir: &Path, version: &str, comment: &str) -> (Vec<u8>, (Ed25519KeyPair, SigningKey)) {
	let key = pair(4);
	(bundle(&key, version, &signature(&key, comment), b"app bytes"), key)
}

#[test]
fn a_newer_app_part_is_listed_installable_and_the_copy_is_the_bundle() {
	let dir = scratch("newer");
	let (source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	let review = run(&source, &[key.1, key.1], "linux-x86_64", &dir).expect("a good bundle");
	assert_eq!(review.apps, vec![App {platform: "linux-x86_64", version: "0.3.0".to_owned(), size: 9, newer: true, installable: true}]);
	assert_eq!(review.dropped, vec!["part 1 is a notice that does not verify: the bundle member \"notice\" is not valid".to_owned()]);
	assert!(review.found.is_empty() && review.notices.is_empty() && review.notice_marks.is_empty());
	assert_eq!(fs::read(&review.copy).expect("the copy"), source);
	assert!(!review.old && !review.future);
}

#[test]
fn an_equal_or_lower_version_or_another_platform_is_not_installable() {
	let dir = scratch("older");
	let (source, key) = good(&dir, "0.2.0", "timestamp:1 file:veilway.AppImage version:0.2.0");
	let equal = run(&source, &[key.1, key.1], "linux-x86_64", &dir).expect("a good bundle");
	assert_eq!((equal.apps[0].newer, equal.apps[0].installable), (false, false));
	let elsewhere = scratch("elsewhere");
	let (source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	let other = run(&source, &[key.1, key.1], "macos-aarch64", &elsewhere).expect("a good bundle");
	assert_eq!((other.apps[0].newer, other.apps[0].installable), (true, false));
}

#[test]
fn a_manifest_version_that_differs_from_the_signed_one_drops_the_app_part() {
	let dir = scratch("mismatch");
	let key = pair(4);
	let source = bundle(&key, "0.4.0", &signature(&key, "timestamp:1 file:veilway.AppImage version:0.3.0"), b"app bytes");
	let review = run(&source, &[key.1, key.1], "linux-x86_64", &dir).expect("the manifest verifies");
	assert!(review.apps.is_empty());
	assert_eq!(review.dropped[0], "part 0 is an app part whose release signature does not check");
}

#[test]
fn an_app_part_is_checked_with_the_key_of_its_own_family_only() {
	let dir = scratch("family");
	let (source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	let other = pair(5);
	let review = run(&source, &[key.1, other.1], "linux-x86_64", &dir).expect("the manifest verifies");
	assert!(review.apps.is_empty());
	assert_eq!(review.dropped[0], "part 0 is an app part whose release signature does not check");
}

#[test]
fn a_damaged_part_is_dropped_alone_and_named() {
	let dir = scratch("damaged");
	let (mut source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	let at = source.len() - 12 - 9;
	source[at] ^= 1;
	let review = run(&source, &[key.1, key.1], "linux-x86_64", &dir).expect("the manifest still verifies");
	assert!(review.apps.is_empty());
	assert_eq!(review.dropped[0], "part 0 is damaged");
}

#[test]
fn a_file_that_fails_its_manifest_writes_no_copy() {
	let dir = scratch("refused");
	let (mut source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	source[bundle::HEAD + 3] ^= 1;
	assert!(matches!(run(&source, &[key.1, key.1], "linux-x86_64", &dir), Err(Error::Refused(Refusal::Signature))));
	assert!(!dir.join("copy.vwbundle").exists());
}

#[test]
fn a_stream_that_ends_early_removes_the_partial_copy() {
	let dir = scratch("partial");
	let (source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	let cut = &source[..source.len() - 5];
	assert!(matches!(run(cut, &[key.1, key.1], "linux-x86_64", &dir), Err(Error::Refused(Refusal::Length))));
	assert!(!dir.join("copy.vwbundle").exists());
}

#[test]
fn a_file_one_byte_long_is_refused_before_a_copy() {
	let dir = scratch("long");
	let (mut source, key) = good(&dir, "0.3.0", "timestamp:1 file:veilway.AppImage version:0.3.0");
	source.push(0);
	assert!(matches!(run(&source, &[key.1, key.1], "linux-x86_64", &dir), Err(Error::Refused(Refusal::Length))));
	assert!(!dir.join("copy.vwbundle").exists());
}
