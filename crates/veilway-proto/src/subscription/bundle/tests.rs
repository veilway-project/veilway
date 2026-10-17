use super::*;
use crate::keys::MirrorKeys;
use crate::subscription::mirror;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn pair(fill: u8) -> (Ed25519KeyPair, SigningKey) {
	let pair = Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).expect("32 bytes");
	let key = SigningKey::new(pair.public_key().as_ref().try_into().expect("32 bytes")).expect("a key of full order");
	(pair, key)
}

fn sign(pair: &Ed25519KeyPair, bytes: &[u8]) -> [u8; 64] {pair.sign(bytes).as_ref().try_into().expect("64 bytes")}

fn counter(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> {
	let mut state = seed;
	move |bytes: &mut [u8]| {
		for byte in bytes {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			*byte = state as u8;
		}
		Ok(())
	}
}

const ID: [u8; 16] = [7; 16];
const SHELL: &[u8] = b"app bytes";

fn pack() -> Vec<u8> {
	let file = |id: u8| ([id; 16], vec![id; 9_413]);
	assemble(vec![file(1), file(2)], 9_413, &mut counter(9)).unwrap()
}

fn good_notice(signer: &(Ed25519KeyPair, SigningKey), issued_at: u64, expires_at: u64) -> Vec<u8> {
	let payload = format!("{{\"v\":1,\"critical\":[],\"issued_at\":{issued_at},\"expires_at\":{expires_at},\"notices\":[{{\"severity\":\"warning\",\"text\":\"Renew soon\"}}]}}");
	let signed = format!("{}.{}", sealed(signer.1.notice_header().as_bytes()), sealed(payload.as_bytes()));
	let signature = sealed(&sign(&signer.0, signed.as_bytes()));
	format!("{signed}.{signature}").into_bytes()
}

fn sample(signer: &(Ed25519KeyPair, SigningKey), pack: &[u8], notice: &[u8]) -> Vec<u8> {
	let inputs = [
		Input::App {platform: "linux-x86_64", version: "0.2.0", name: "veilway.AppImage", signature: "sig", bytes: SHELL},
		Input::Pack {periods: &[5, 6], bytes: pack},
		Input::Notice {bytes: notice},
	];
	let mut file = make(signer.1, ID, 1_000, &inputs, |bytes| sign(&signer.0, bytes)).unwrap();
	file.extend(SHELL);
	file.extend(pack);
	file.extend(notice);
	file
}

// A manifest with the given body, signed by `signer`, with `parts` parts of one byte each.
fn manifest_of(signer: &(Ed25519KeyPair, SigningKey), body: &str, parts: usize) -> Result<Manifest, Refusal> {
	let mut head = [MAGIC.as_slice(), &[FORMAT], &signer.1.kid().bytes()[..], &(body.len() as u32).to_be_bytes()[..]].concat();
	head.extend_from_slice(body.as_bytes());
	let signed = [LABEL, &[FORMAT], &signer.1.kid().bytes()[..], &(body.len() as u32).to_be_bytes()[..], body.as_bytes()].concat();
	head.extend_from_slice(&sign(&signer.0, &signed));
	let length = (head.len() + parts) as u64;
	manifest(&head, &[signer.1], length)
}

#[test]
fn a_good_bundle_reads_and_every_part_holds() {
	let signer = pair(1);
	let (pack, notice_part) = (pack(), good_notice(&signer, 900, 2_000));
	let file = sample(&signer, &pack, &notice_part);
	let m = head(&file).unwrap();
	let read = manifest(&file[..HEAD + m + 64], &[signer.1], file.len() as u64).unwrap();
	assert_eq!((read.bundle_id, read.created_at, read.signer), (ID, 1_000, signer.1));
	assert_eq!(read.parts.len(), 3);
	assert!(matches!(read.parts[1].kind, Kind::Pack {ref periods} if periods == &[5, 6]));
	let mut at = HEAD + m + 64;
	for part in &read.parts {
		let end = at + part.size as usize;
		assert!(part.holds(&file[at..end]));
		at = end;
	}
	assert_eq!(at, file.len());
	assert_eq!(super::notice(&notice_part, &[signer.1], 1_000, &[]).map(|message| message.notices.len()), Ok(1));
}

#[test]
fn the_head_refuses_what_is_not_a_bundle_before_anything_else() {
	let signer = pair(1);
	let file = sample(&signer, &pack(), &good_notice(&signer, 900, 2_000));
	let mut magic = file.clone();
	magic[0] ^= 1;
	let mut version = file.clone();
	version[8] = 2;
	assert_eq!(head(&magic), Err(Refusal::Magic));
	assert_eq!(head(&version), Err(Refusal::Version(2)));
	assert_eq!(head(&file[..20]), Err(Refusal::Magic));
	let mut short = file.clone();
	short[17..21].copy_from_slice(&1u32.to_be_bytes());
	assert_eq!(head(&short), Err(Refusal::Length));
	short[17..21].copy_from_slice(&(MANIFEST_MAX as u32 + 1).to_be_bytes());
	assert_eq!(head(&short), Err(Refusal::Length));
}

#[test]
fn one_changed_byte_of_the_head_manifest_or_signature_refuses_the_file() {
	let signer = pair(1);
	let file = sample(&signer, &pack(), &good_notice(&signer, 900, 2_000));
	let m = head(&file).unwrap();
	for at in 0..HEAD + m + 64 {
		let mut changed = file.clone();
		changed[at] ^= 0x01;
		let read = head(&changed).and_then(|m| manifest(&changed[..HEAD + m + 64], &[signer.1], changed.len() as u64));
		assert!(read.is_err(), "a changed byte at {at} verified");
	}
}

#[test]
fn a_changed_byte_of_a_part_fails_only_that_part() {
	let signer = pair(1);
	let pack = pack();
	let file = sample(&signer, &pack, &good_notice(&signer, 900, 2_000));
	let m = head(&file).unwrap();
	let read = manifest(&file[..HEAD + m + 64], &[signer.1], file.len() as u64).unwrap();
	let mut changed = file.clone();
	changed[HEAD + m + 64] ^= 0x80;
	assert!(!read.parts[0].holds(&changed[HEAD + m + 64..HEAD + m + 64 + SHELL.len()]));
	assert!(read.parts[1].holds(&file[HEAD + m + 64 + SHELL.len()..HEAD + m + 64 + SHELL.len() + pack.len()]));
}

#[test]
fn a_file_one_byte_short_or_long_is_refused() {
	let signer = pair(1);
	let file = sample(&signer, &pack(), &good_notice(&signer, 900, 2_000));
	let m = head(&file).unwrap();
	let head_bytes = &file[..HEAD + m + 64];
	assert_eq!(manifest(head_bytes, &[signer.1], file.len() as u64 - 1), Err(Refusal::Member("parts")));
	assert_eq!(manifest(head_bytes, &[signer.1], file.len() as u64 + 1), Err(Refusal::Member("parts")));
	assert_eq!(manifest(&file[..HEAD + m + 63], &[signer.1], file.len() as u64), Err(Refusal::Length));
	assert_eq!(manifest(head_bytes, &[signer.1], FILE_MAX + 1), Err(Refusal::Length));
}

#[test]
fn an_unknown_key_id_refuses_with_its_own_message() {
	let signer = pair(1);
	let other = pair(2);
	let file = sample(&signer, &pack(), &good_notice(&signer, 900, 2_000));
	let m = head(&file).unwrap();
	assert_eq!(manifest(&file[..HEAD + m + 64], &[other.1], file.len() as u64), Err(Refusal::Signer));
	assert_eq!(manifest(&file[..HEAD + m + 64], &[], file.len() as u64), Err(Refusal::Signer));
}

#[test]
fn a_wrong_signature_is_damage_and_another_held_key_does_not_stop_the_right_one() {
	let signer = pair(1);
	let file = sample(&signer, &pack(), &good_notice(&signer, 900, 2_000));
	let m = head(&file).unwrap();
	let mut bad = file.clone();
	bad[HEAD + m] ^= 1;
	assert_eq!(manifest(&bad[..HEAD + m + 64], &[signer.1], bad.len() as u64), Err(Refusal::Signature));
	let other = pair(3);
	assert_eq!(manifest(&file[..HEAD + m + 64], &[other.1, signer.1], file.len() as u64).map(|read| read.signer), Ok(signer.1));
}

#[test]
fn the_manifest_is_strict_json_and_its_members_are_judged() {
	let signer = pair(1);
	let id = "00112233445566778899aabbccddeeff";
	let part = format!("{{\"kind\":\"notice\",\"size\":1,\"sha256\":\"{}\"}}", sealed(&sha256(b"x")));
	let ok = format!("{{\"v\":1,\"critical\":[],\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert!(manifest_of(&signer, &ok, 1).is_ok());
	let duplicate = format!("{{\"v\":1,\"v\":1,\"critical\":[],\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert_eq!(manifest_of(&signer, &duplicate, 1), Err(Refusal::Json(JsonError::Duplicate)));
	let critical = format!("{{\"v\":1,\"critical\":[\"new\"],\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert_eq!(manifest_of(&signer, &critical, 1), Err(Refusal::Member("critical")));
	let newer = format!("{{\"v\":2,\"critical\":[],\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert_eq!(manifest_of(&signer, &newer, 1), Err(Refusal::Member("v")));
	let extra = format!("{{\"v\":1,\"critical\":[],\"future\":{{\"a\":[1]}},\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert!(manifest_of(&signer, &extra, 1).is_ok());
	let upper = format!("{{\"v\":1,\"critical\":[],\"bundle_id\":\"{}\",\"created_at\":5,\"parts\":[{part}]}}", id.to_uppercase());
	assert_eq!(manifest_of(&signer, &upper, 1), Err(Refusal::Member("bundle_id")));
	let deep = format!("{{\"v\":1,\"critical\":[],\"x\":[[[[[[[[1]]]]]]]],\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert_eq!(manifest_of(&signer, &deep, 1), Err(Refusal::Json(JsonError::Depth)));
}

#[test]
fn the_parts_of_a_manifest_are_bounded_and_unique() {
	let signer = pair(1);
	let part = |kind: &str, extra: &str| format!("{{\"kind\":\"{kind}\",\"size\":1,\"sha256\":\"{}\"{extra}}}", sealed(&sha256(b"x")));
	let build = |parts: Vec<String>| {
		let body = format!("{{\"v\":1,\"critical\":[],\"bundle_id\":\"{}\",\"created_at\":5,\"parts\":[{}]}}", "00".repeat(16), parts.join(","));
		manifest_of(&signer, &body, parts.len())
	};
	let app = |platform: &str, name: &str| part("app", &format!(",\"platform\":\"{platform}\",\"version\":\"1.0.0\",\"name\":\"{name}\",\"signature\":\"s\""));
	assert!(build(vec![app("linux-x86_64", "veilway.AppImage")]).is_ok());
	assert_eq!(build(vec![app("linux-x86_64", "veilway.AppImage"), app("linux-x86_64", "other.deb")]), Err(Refusal::Member("app")));
	assert_eq!(build(vec![app("linux-x86_64", "veilway.exe")]), Err(Refusal::Member("app")));
	assert_eq!(build(vec![app("plan9", "veilway.exe")]), Err(Refusal::Member("platform")));
	assert_eq!(build(vec![part("pack", ",\"periods\":[3,5]")]), Err(Refusal::Member("pack")));
	assert_eq!(build(vec![part("pack", ",\"periods\":[3,4]")]).map(|read| read.parts[0].kind.clone()), Ok(Kind::Pack {periods: vec![3, 4]}));
	assert_eq!(build(vec![part("notice", ""); 9]), Err(Refusal::Member("notice")));
	assert!(build(vec![part("future", ""); 32]).is_ok());
	assert_eq!(build(vec![part("future", ""); 33]), Err(Refusal::Member("parts")));
	assert_eq!(build(vec![]), Err(Refusal::Member("parts")));
}

#[test]
fn a_version_is_strict_and_orders_by_semver() {
	let read = Version::read;
	assert!(read("1.2.3").is_some() && read("1.2.3-rc.1+build.5").is_some());
	assert!(read("01.2.3").is_none() && read("1.2").is_none() && read("1.2.3-01").is_none() && read("v1.2.3").is_none() && read("1.2.3-").is_none());
	assert!(read("1.2.3-rc.1") < read("1.2.3") && read("1.2.3") < read("1.10.0") && read("1.9.0") < read("1.10.0"));
	assert!(read("1.0.0-alpha") < read("1.0.0-alpha.1") && read("1.0.0-alpha.beta") < read("1.0.0-beta") && read("1.0.0-2") < read("1.0.0-10"));
	assert_eq!(read("1.2.3+a"), read("1.2.3+b"));
}

#[test]
fn a_pack_file_opens_only_under_its_own_bundle_and_is_found_by_its_id() {
	let keys = MirrorKeys::derive(&[1; 16], &[2; 16], &[3; 32]);
	let envelope = b"document".to_vec();
	let sealed_file = mirror::seal(&keys, base(&ID), 5, 9_413, &envelope, &mut counter(5)).unwrap();
	let pack = assemble(vec![(keys.id(5, base(&ID)), sealed_file.clone())], 9_413, &mut counter(6)).unwrap();
	let len = index_len(&pack[..8], pack.len() as u64).unwrap();
	let index = Index::read(&pack[..len], pack.len() as u64).unwrap();
	assert_eq!(index.size(), 9_413);
	assert!((33..=65).contains(&index.count()));
	let at = index.find(&keys.id(5, base(&ID))).unwrap() as usize;
	assert_eq!(&pack[at..at + 9_413], &sealed_file[..]);
	assert_eq!(mirror::open(&keys, base(&ID), 5, &pack[at..at + 9_413]).unwrap(), envelope);
	assert!(mirror::open(&keys, base(&[8; 16]), 5, &sealed_file).is_err());
	assert!(mirror::open(&keys, base(&ID), 6, &sealed_file).is_err());
	assert!(index.find(&keys.id(6, base(&ID))).is_none());
}

// A minisign signature file of an app part whose global signature is made by `key` over the signature bytes and `comment`.
fn minisign(key: &(Ed25519KeyPair, SigningKey), comment: &str) -> String {
	let signature = [7u8; 64];
	let global = sign(&key.0, &[&signature[..], comment.as_bytes()].concat());
	let line = STANDARD.encode([b"Ed".as_slice(), &[1; 8], &signature].concat());
	format!("untrusted comment: test\n{line}\ntrusted comment: {comment}\n{}\n", STANDARD.encode(global))
}

#[test]
fn an_app_signature_gives_its_version_and_name_only_under_its_family_key() {
	let key = pair(4);
	let other = pair(5);
	let android = minisign(&key, "veilway v0.3.0 veilway-android-arm64.apk");
	assert_eq!(signed("android-arm64", &android, &[key.1, other.1]), Some(Signed {version: "0.3.0".to_owned(), name: "veilway-android-arm64.apk".to_owned()}));
	assert_eq!(signed("android-arm64", &android, &[other.1, key.1]), None);
	assert_eq!(signed("android-arm64", &android.replace("0.3.0", "0.9.0"), &[key.1, other.1]), None);
	let desktop = minisign(&key, "timestamp:1 file:veilway.AppImage version:0.3.0");
	assert_eq!(signed("linux-x86_64", &desktop, &[other.1, key.1]), Some(Signed {version: "0.3.0".to_owned(), name: "veilway.AppImage".to_owned()}));
	assert_eq!(signed("linux-x86_64", &desktop, &[key.1, other.1]), None);
	assert_eq!(signed("linux-x86_64", &desktop, &[]), None);
}

#[test]
fn a_notice_not_above_the_last_one_of_its_key_is_refused() {
	let signer = pair(1);
	let now = 10_000;
	let good = good_notice(&signer, now - 10, now + 100);
	assert_eq!(super::notice(&good, &[signer.1], now, &[(signer.1, now - 10)]), Err(Refusal::Member("issued_at")));
	assert!(super::notice(&good, &[signer.1], now, &[(signer.1, now - 11)]).is_ok());
	assert!(super::notice(&good, &[signer.1], now, &[(pair(2).1, now)]).is_ok());
}

#[test]
fn a_manifest_with_more_than_2000_values_is_refused() {
	let signer = pair(1);
	let id = "00112233445566778899aabbccddeeff";
	let part = format!("{{\"kind\":\"notice\",\"size\":1,\"sha256\":\"{}\"}}", sealed(&sha256(b"x")));
	let many = vec!["0"; 2_000].join(",");
	let body = format!("{{\"v\":1,\"critical\":[],\"x\":[{many}],\"bundle_id\":\"{id}\",\"created_at\":5,\"parts\":[{part}]}}");
	assert_eq!(manifest_of(&signer, &body, 1), Err(Refusal::Member("manifest")));
}

#[test]
fn the_release_keys_are_the_two_families_keys() {
	let keys = release_keys();
	assert_eq!(keys.len(), 2);
	assert_eq!(keys[0].kid().text().len(), 11);
	assert_ne!(keys[0], keys[1]);
}

#[test]
fn the_decoys_are_drawn_in_the_range_of_the_page() {
	for real in [1usize, 4, 33, 100, 1000] {
		for seed in 0..4 {
			let files: Vec<([u8; 16], Vec<u8>)> = (0..real).map(|index| {
				let mut id = [0; 16];
				id[12..].copy_from_slice(&(index as u32).to_be_bytes());
				(id, vec![1; 9_413])
			}).collect();
			let pack = assemble(files, 9_413, &mut counter(seed + 1)).unwrap();
			let n = u32::from_be_bytes(pack[..4].try_into().unwrap()) as usize;
			let (low, high) = (real.div_ceil(4).max(32), real.div_ceil(2).max(64));
			assert!((real + low..=real + high).contains(&n), "{real} real files gave {n} files");
			assert_eq!(pack.len(), 8 + n * (16 + 9_413));
		}
	}
}

#[test]
fn a_pack_index_refuses_bad_counts_lengths_and_orders() {
	let mut pack = assemble(vec![([1; 16], vec![0; 9_413]), ([2; 16], vec![0; 9_413])], 9_413, &mut counter(3)).unwrap();
	let part = pack.len() as u64;
	assert!(index_len(&pack[..8], part).is_ok());
	assert_eq!(index_len(&pack[..8], part + 1), Err(Refusal::Length));
	assert_eq!(index_len(&[0, 0, 0, 0, 0, 0, 0x24, 0x7d], part), Err(Refusal::Length));
	assert_eq!(index_len(&[0, 0, 0, 0, 0, 0, 0x24, 0x7e], part), Err(Refusal::Length));
	assert_eq!(index_len(&pack[..7], part), Err(Refusal::Length));
	let swap: Vec<u8> = pack[8..24].to_vec();
	pack.copy_within(24..40, 8);
	pack[24..40].copy_from_slice(&swap);
	let len = index_len(&pack[..8], part).unwrap();
	assert_eq!(Index::read(&pack[..len], part), Err(Refusal::Member("ids")));
}

#[test]
fn a_notice_is_judged_by_its_key_its_clock_and_its_lifetime() {
	let signer = pair(1);
	let other = pair(2);
	let now = 10_000;
	let good = good_notice(&signer, now - 10, now + 100);
	assert_eq!(super::notice(&good, &[signer.1], now, &[]).map(|message| (message.issued_at, message.notices.len())), Ok((now - 10, 1)));
	assert_eq!(super::notice(&good, &[other.1], now, &[]), Err(Refusal::Signer));
	assert_eq!(super::notice(&good_notice(&signer, now + CLOCK_TOLERANCE + 1, now + 1_000), &[signer.1], now, &[]), Err(Refusal::Member("issued_at")));
	assert!(super::notice(&good_notice(&signer, now + CLOCK_TOLERANCE, now + 1_000), &[signer.1], now, &[]).is_ok());
	assert_eq!(super::notice(&good_notice(&signer, now - 100, now), &[signer.1], now, &[]), Err(Refusal::Member("expires_at")));
	assert_eq!(super::notice(&good_notice(&signer, now, now + LIFETIME_MAX + 1), &[signer.1], now, &[]), Err(Refusal::Member("expires_at")));
	let mut damaged = good.clone();
	damaged[good.len() - 3] ^= 1;
	assert!(super::notice(&damaged, &[signer.1], now, &[]).is_err());
}

#[test]
fn the_writer_refuses_what_the_reader_would_refuse() {
	let signer = pair(1);
	let notice_part = good_notice(&signer, 900, 2_000);
	let inputs = [Input::App {platform: "android-arm64", version: "0.2.0", name: "veilway-android-arm64.apk", signature: "s", bytes: SHELL}, Input::Notice {bytes: &notice_part}];
	assert!(make(signer.1, ID, 1_000, &inputs, |bytes| sign(&signer.0, bytes)).is_ok());
	let bad = [Input::App {platform: "android-arm64", version: "not-a-version", name: "x.apk", signature: "s", bytes: SHELL}];
	assert_eq!(make(signer.1, ID, 1_000, &bad, |bytes| sign(&signer.0, bytes)), Err(Refusal::Member("version")));
	let packs = [Input::Pack {periods: &[1, 2, 3], bytes: &[0; 9_413]}];
	assert_eq!(make(signer.1, ID, 1_000, &packs, |bytes| sign(&signer.0, bytes)), Err(Refusal::Member("periods")));
}
