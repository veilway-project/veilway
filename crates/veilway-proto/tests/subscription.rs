//! The subscription format against vectors that tests/vectors.py computed without this crate (they are the seeds of the fuzz targets, so a seed that no longer reads fails here), against the public edge cases of Ed25519 verification, and against one hostile document for every limit and strict rule.
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::{json, Value};
use std::fs;
use veilway_proto::{control::{self, Period, Severity}, subscription::{client::{wait, Accepted, Damaged, Failure, Held, Offer, Refreshed, Replaced, Review, Standing, GRACE}, direction, envelope::{self, EnvelopeError, Kid, SigningKey}, fetch::{DeviceName, Op, Received, RequestError}, legacy::{self, Cap, LegacyError, Scheme, Server, Tls}, link::{Carried, Link, LinkError}, payload::{self, dialable, own, Card, Dial, Fault, JsonError, KeyOrigin, LogoKind, Network, Payload, PayloadError, RatingCap, Reason, Subscription, Transport}, Direction, Secret, Tag, Text, Translation, BODY_MAX, CARRIED_MAX}, NoRandom};

// The clock of every test: 100 s after the documents of vectors.py were issued.
const ISSUED: u64 = 1_700_000_000;
const NOW: u64 = ISSUED + 100;

fn seed(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

fn text(name: &str) -> String {String::from_utf8(seed(name)).unwrap()}

fn unhex(text: &str) -> Vec<u8> {(0..text.len() / 2).map(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap()).collect()}

// The provider keys of vectors.py: the seeds 11..11, 22..22 and, for a key no client holds, 99..99.
fn pair(fill: u8) -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).unwrap()}

fn key(fill: u8) -> SigningKey {SigningKey::new(pair(fill).public_key().as_ref().try_into().unwrap()).unwrap()}

fn sign_with(fill: u8, header_of: u8, payload: &[u8]) -> String {envelope::seal(&key(header_of), payload, |signed| pair(fill).sign(signed).as_ref().try_into().unwrap())}

fn sign(fill: u8, payload: &Value) -> String {sign_with(fill, fill, &serde_json::to_vec(payload).unwrap())}

// The payload of a seed of `fuzz_subscription`, which starts with one byte of settings.
fn payload(name: &str) -> Value {serde_json::from_slice(&seed(&format!("fuzz_subscription/{name}"))[1..]).unwrap()}

// Sets or removes the member a JSON pointer names.
fn put(document: &mut Value, pointer: &str, value: Option<Value>) {
	let (parent, name) = pointer.rsplit_once('/').unwrap();
	match (document.pointer_mut(parent).unwrap_or_else(|| panic!("{pointer}")), value) {
		(Value::Object(members), Some(value)) => drop(members.insert(name.to_owned(), value)),
		(Value::Object(members), None) => drop(members.remove(name)),
		(Value::Array(items), Some(value)) if name.parse() == Ok(items.len()) => items.push(value),
		(Value::Array(items), Some(value)) => items[name.parse::<usize>().unwrap()] = value,
		(Value::Array(items), None) => drop(items.remove(name.parse().unwrap())),
		_ => panic!("{pointer}"),
	}
}

fn with(mut document: Value, changes: &[(&str, Value)]) -> Value {
	for (pointer, value) in changes {put(&mut document, pointer, Some(value.clone()))}
	document
}

fn read_raw(payload: &[u8]) -> Result<Payload, PayloadError> {payload::parse(&envelope::verify(sign_with(0x11, 0x11, payload).as_bytes(), &[key(0x11)], BODY_MAX).unwrap())}

fn read(payload: &Value) -> Result<Payload, PayloadError> {read_raw(&serde_json::to_vec(payload).unwrap())}

fn subscription(payload: &Value) -> Subscription {
	match read(payload) {
		Ok(Payload::Subscription(subscription)) => *subscription,
		other => panic!("{other:?}"),
	}
}

// The random source of a client whose device key is 33..33 and whose device secret is 44..44, as in vectors.py.
fn fixed(bytes: &mut [u8]) -> Result<(), NoRandom> {
	bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
	Ok(())
}

// A document of the device-keyed subscription of vectors.py, with members changed.
fn issue(fill: u8, changes: &[(&str, Value)]) -> String {sign(fill, &with(serde_json::from_slice(envelope::verify(&seed("fuzz_sub_envelope/document")[1..], &[key(0x11)], BODY_MAX).unwrap().payload()).unwrap(), changes))}

fn review(document: &[u8], stored: &[&Held]) -> Result<Review, Failure> {
	let Offer::Native(offer) = Offer::open(Link::parse(&text("fuzz_deeplink/native-veilway")).unwrap()) else {panic!("a native link")};
	offer.proceed(None, &mut fixed).unwrap().answer(document, NOW, stored)
}

// The subscription of vectors.py, imported and accepted.
fn held() -> Held {review(&seed("fuzz_sub_envelope/document")[1..], &[]).unwrap().accept(None, &[]).unwrap().held}

// A whole document in a file, under the first key, through its first step.
fn carried(document: &str, stored: &[&Held]) -> Result<Review, Failure> {
	let Offer::Carried(offer) = Offer::open(Link::Carried(Carried::file(format!("v1.{}.{document}", base64(key(0x11).bytes())).as_bytes()).unwrap())) else {panic!("a document in a file")};
	offer.proceed(NOW, stored)
}

// The payload of the device-keyed document of vectors.py.
fn first() -> Value {serde_json::from_slice(envelope::verify(&seed("fuzz_sub_envelope/document")[1..], &[key(0x11)], BODY_MAX).unwrap().payload()).unwrap()}

#[test]
fn the_key_its_id_its_fingerprint_and_its_header() {
	let key = key(0x11);
	assert_eq!(key.bytes()[..], unhex("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")[..]);
	assert_eq!((key.kid().text(), key.fingerprint().to_string()), ("ELpoLIrRNRM".to_owned(), "10ba 682c 8ad1 3513 971e 8b56 881a ab8b".to_owned()));
	assert_eq!(key.header(), "{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"ELpoLIrRNRM\"}");
	assert_eq!((Kid::read("ELpoLIrRNRM"), Kid::read("ELpoLIrRNRN"), Kid::read("ELpoLIrRNR")), (Some(key.kid()), None, None));
	assert_eq!(format!("{key:?}"), "SigningKey(10ba 682c 8ad1 3513 971e 8b56 881a ab8b)");
}

// Each document of vectors.py verifies, and sealing its payload here gives the same bytes: the header, the encoding and the signature are the ones a plain-Python Ed25519 wrote.
#[test]
fn a_signed_document_and_a_signed_refusal_byte_for_byte() {
	for (name, signer) in [("document", 0x11), ("carried", 0x11), ("refusal", 0x11), ("two-keys", 0x11), ("second-key", 0x22)] {
		let document = seed(&format!("fuzz_sub_envelope/{name}"));
		let verified = envelope::verify(&document[1..], &[key(0x11), key(0x22)], BODY_MAX).unwrap();
		assert_eq!((verified.signer(), sign_with(signer, signer, verified.payload()).as_bytes()), (key(signer), &document[1..]), "{name}");
		assert!(!format!("{verified:?}").contains("example"), "{name}");
	}
	let Ok(Payload::Refusal(refusal)) = payload::parse(&envelope::verify(&seed("fuzz_sub_envelope/refusal")[1..], &[key(0x11)], BODY_MAX).unwrap()) else {panic!("a refusal")};
	assert_eq!((refusal.subscription_id.as_str(), refusal.issued_at, refusal.reason), ("example-account-0001", ISSUED, Reason::DeviceLimit));
	assert_eq!(seed("fuzz_sub_envelope/document").len() - 1, 1570);
}

#[test]
fn every_link_form_byte_for_byte() {
	let (veilway, https) = (text("fuzz_deeplink/native-veilway"), text("fuzz_deeplink/native-https"));
	assert_eq!(veilway, "veilway://sub/sub.example.com/s#v1.0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc.VVVVVVVVVVVVVVVVVVVVVQ");
	let (Link::Native(native), Link::Native(other)) = (Link::parse(&veilway).unwrap(), Link::parse(&https).unwrap()) else {panic!("native links")};
	assert_eq!((native.veilway(), native.https(), native == other), (veilway.clone(), https, true));
	assert_eq!((native.endpoint().as_str(), native.endpoint().host(), native.key(), native.token().expose()), ("https://sub.example.com/s", "sub.example.com", key(0x11), &[0x55; 16]));
	// "The fragment is 70 characters with its `#`", and neither the token nor the link is printed.
	assert_eq!((veilway.len() - veilway.find('#').unwrap(), format!("{native:?}").contains("VVVV")), (70, false));
	let (Link::Carried(carried), in_file) = (Link::parse(&text("fuzz_deeplink/document")).unwrap(), Carried::file(&seed("fuzz_deeplink/file")).unwrap()) else {panic!("a document in a link")};
	assert_eq!((carried.veilway(), in_file.file_content().into_bytes(), carried.document(), carried.in_file(), in_file.in_file()), (Some(text("fuzz_deeplink/document")), seed("fuzz_deeplink/file"), &seed("fuzz_sub_envelope/carried")[1..], false, true));
	assert!(envelope::verify(carried.document(), &[carried.key()], CARRIED_MAX).is_ok() && !format!("{carried:?}").contains("eyJ"));
	let Link::Legacy(legacy) = Link::parse(&text("fuzz_deeplink/legacy")).unwrap() else {panic!("a legacy link")};
	assert_eq!(legacy.url().as_str(), "https://sub.example.com/list?token=abc");
}

#[test]
fn what_is_no_link() {
	let (key, token) = ("0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc", "VVVVVVVVVVVVVVVVVVVVVQ");
	let native = |front: &str, back: &str| Link::parse(&format!("{front}#{back}"));
	let good = format!("v1.{key}.{token}");
	assert!(matches!(native("veilway://sub/sub.example.com:8443/a/b", &good), Ok(Link::Native(_))) && matches!(native("https://sub.example.com/", &good), Ok(Link::Native(_))));
	for front in ["veilway://sub/sub.example.com", "veilway://sub/sub.example.com/s?x=1", "veilway://sub//s", "veilway://sub/Sub.example.com/s", "veilway://sub/192.0.2.1/s", "veilway://sub/[2001:db8::1]/s", "veilway://sub/user@sub.example.com/s", "veilway://sub/sub.example.com:0/s", "veilway://sub/sub.example.com:99999/s", "veilway://sub/sub.example.com/a/../s", "veilway://sub/sub.example.com/s s", "veilway://Sub/sub.example.com/s", "veilway://sub.example.com/s", "veilway://subs/sub.example.com/s", "veilway:/sub/sub.example.com/s", "VEILWAY://sub/sub.example.com/s", "https://sub.example.com", "https://sub.example.com/s?x=1", "http://sub.example.com/s", "veilway://sub/https://sub.example.com/s", " veilway://sub/sub.example.com/s"] {assert_eq!(native(front, &good), Err(LinkError::Form), "{front}")}
	// The token ends in a character whose unused bits are set, the key is one character short, has padding, is in the other alphabet, and so on.
	for back in [format!("v1.{key}.VVVVVVVVVVVVVVVVVVVVVR"), format!("v1.{key}.{}", &token[..21]), format!("v1.{key}.{token}A"), format!("v1.{}.{token}", &key[..42]), format!("v1.{key}={token}"), format!("v1.{key}.{token}="), format!("v1.{key}.{token}#x"), format!("v1.{key}.{token}\n"), format!("v1.{}.{token}", key.replace('0', "+")), format!("v1.{key}d.{token}"), format!("v2.{key}.{token}"), format!("V1.{key}.{token}"), format!("v1{key}.{token}"), format!("v1.{key}.{token}.x"), format!("v01.{key}.{token}"), "v1".to_owned(), "v1.".to_owned(), "v12.x".to_owned(), String::new()] {
		assert_eq!(native("veilway://sub/sub.example.com/s", &back), Err(LinkError::Form), "{back}");
		// On an `https` URL a fragment that is not of the form `v`, digits, dot is no native fragment, and the link is a legacy one. Every other is refused.
		let legacy = back.is_empty() || back.starts_with('V') || back.starts_with("v10E");
		assert_eq!(native("https://sub.example.com/s", &back).map(|link| matches!(link, Link::Legacy(_))), if legacy {Ok(true)} else {Err(LinkError::Form)}, "{back}");
	}
	// A native link whose `#` was lost or changed on the way is no legacy link: a `GET` to it would carry the key and the token.
	for damaged in [format!("https://sub.example.com/s{good}"), format!("https://sub.example.com/s?{good}"), format!("https://sub.example.com/s/{good}"), format!("https://sub.example.com/s/{good}#name"), format!("https://sub.example.com/s:{}", good.replace('0', "A")), format!("https://sub.example.com/s%23{good}"), format!("https://sub.example.com/s%23{good}."), format!("https://sub.example.com/s%23{good}/"), format!("https://sub.example.com/s%23{good}?utm_source=x"), format!("https://sub.example.com/s?k={good}&utm=1"), format!("https://sub.example.com/s/{good}/x"), format!("https://sub.example.com/s{good})"), format!("https://sub.example.com/s#!{good}"), format!("https://sub.example.com/s#x{good}x"), format!("https://sub.example.com/s?a=1#name={good}"), format!("veilway://sub/sub.example.com/s%23{good}"), format!("veilway://sub/sub.example.com/s#{good}.")] {assert_eq!(Link::parse(&damaged), Err(LinkError::Form), "{damaged}")}
	// What is left of a fragment that is no native one is not requested, so a legacy link never holds a token that was behind a `#`.
	assert!(matches!(Link::parse(&format!("https://sub.example.com/s#V1{}", &good[2..])), Ok(Link::Legacy(legacy)) if legacy.url().as_str() == "https://sub.example.com/s"));
	// "A key of small order is also refused in a link": the neutral element, and the same in the encoding that is not canonical.
	for small in [base64(&std::array::from_fn::<u8, 32, _>(|index| u8::from(index == 0))), base64(&std::array::from_fn::<u8, 32, _>(|index| if index == 0 {0xee} else if index == 31 {0x7f} else {0xff})), base64(&[0; 32])] {
		assert_eq!(native("veilway://sub/sub.example.com/s", &format!("v1.{small}.{token}")), Err(LinkError::Key), "{small}");
		assert_eq!(Link::parse(&format!("veilway://doc#v1.{small}.a.b.c")), Err(LinkError::Key));
	}
	// "Subscription URL without its fragment: at most 256 characters", counted on the URL that is requested.
	let path = "a".repeat(256 - "https://sub.example.com/".len());
	assert!(native(&format!("veilway://sub/sub.example.com/{path}"), &good).is_ok() && native(&format!("https://sub.example.com/{path}"), &good).is_ok());
	assert_eq!((native(&format!("veilway://sub/sub.example.com/{path}a"), &good), native(&format!("https://sub.example.com/{path}a"), &good), Link::parse(&format!("https://sub.example.com/{path}a"))), (Err(LinkError::Size), Err(LinkError::Size), Err(LinkError::Size)));
	// A whole document: at most 2,048 bytes in a link and 1,048,576 in a file, only the characters a document has, and nothing around it.
	let document = |size: usize| format!("v1.{key}.{}", "a".repeat(size));
	assert!(Link::parse(&format!("veilway://doc#{}", document(CARRIED_MAX))).is_ok() && Carried::file(document(BODY_MAX).as_bytes()).is_ok_and(|carried| carried.veilway().is_none()));
	assert_eq!((Link::parse(&format!("veilway://doc#{}", document(CARRIED_MAX + 1))), Carried::file(document(BODY_MAX + 1).as_bytes())), (Err(LinkError::Size), Err(LinkError::Size)));
	for content in [document(0), format!("{}\n\n", document(8)), format!("{}\r", document(8)), format!("{} ", document(8)), format!("{}=", document(8)), format!("{}/", document(8)), format!("v1.{key}"), format!("v1.{key}a.a.b.c"), format!("v2.{key}.a.b.c"), format!("veilway://doc#{}", document(8))] {
		assert_eq!((Link::parse(&format!("veilway://doc#{content}")), Carried::file(content.as_bytes())), (Err(LinkError::Form), Err(LinkError::Form)), "{content}");
	}
	// A file may end with the one line end an editor adds. A link may not.
	assert!(Carried::file(format!("{}\n", document(8)).as_bytes()).is_ok() && Carried::file(format!("{}\r\n", document(8)).as_bytes()).is_ok() && Link::parse(&format!("veilway://doc#{}\n", document(8))).is_err());
	assert_eq!((Link::parse(&format!("veilway://doc/#{}", document(8))), Link::parse(&format!("veilway://doc?#{}", document(8))), Carried::file(b"v1.\xff")), (Err(LinkError::Form), Err(LinkError::Form), Err(LinkError::Form)));
	// A legacy link "must be `https`".
	for other in ["http://example.com/list", "ftp://example.com/list", "example.com/list", "https://user:pass@example.com/list", "https://192.0.2.1/list", "vless://example.com", ""] {assert_eq!(Link::parse(other), Err(LinkError::Form), "{other}")}
}

// The public edge cases of Ed25519 verification (Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs", the 12 vectors of ed25519-speccheck), as message, public key and signature. For each: whether this crate holds the key at all, and what `ring` says of the signature by itself.
#[test]
fn the_edge_cases_of_ed25519_verification() {
	let cases = [
		("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"),
		("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
		("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"),
		("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"),
		("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"),
		("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"),
		("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"),
		("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"),
		("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"),
		("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"),
		("e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
		("39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"),
	];
	let held: Vec<bool> = cases.iter().map(|(_, key, _)| SigningKey::new(unhex(key).try_into().unwrap()).is_some()).collect();
	let library: Vec<bool> = cases.iter().map(|(message, key, signature)| UnparsedPublicKey::new(&ED25519, unhex(key)).verify(&unhex(message), &unhex(signature)).is_ok()).collect();
	// Cases 0, 1, 10 and 11 have a key of small order, 10 and 11 in an encoding that is not canonical: never held.
	assert_eq!(held, [false, false, true, true, true, true, true, true, true, true, false, false]);
	// What `ring` verifies by itself. It refuses an S that is not below the order (6, 7), an R that is not canonical (8, 9) and what only a cofactored check takes (4, 5).
	assert_eq!(library, [true, true, true, true, false, false, false, false, false, false, false, true]);
	// Together: only 2 and 3 pass, which are valid under the strict rule. Their R is of small order or of mixed order, which the rule does not refuse.
	assert_eq!(held.iter().zip(&library).map(|(held, library)| *held && *library).collect::<Vec<_>>(), [false, false, true, true, false, false, false, false, false, false, false, false]);
}

// The vectors of tests/vectors.py that its lax verifier accepts, over the message "veilway" and, for two of them, as whole documents.
#[test]
fn a_signature_only_a_lax_verifier_accepts_is_refused() {
	let (message, verifies) = (b"veilway", |key: &[u8], signature: &str| UnparsedPublicKey::new(&ED25519, key).verify(b"veilway", &unhex(signature)).is_ok());
	let signature = "6213f3c75f5cddc49d1d46d89bf12dd00b8c25a3c0f69458a8983cfa0dba4d6e83367a8da33f970a871b2e827996ecb9d70d4be3430225144bc23ce9c352b609";
	assert_eq!(pair(0x11).sign(message).as_ref(), &unhex(signature)[..]);
	assert!(verifies(key(0x11).bytes(), signature));
	// S with the group order added, and the neutral element as R in an encoding of p + 1: `ring` refuses both.
	assert!(!verifies(key(0x11).bytes(), "6213f3c75f5cddc49d1d46d89bf12dd00b8c25a3c0f69458a8983cfa0dba4d6e700a70eabda2a9625db825255890cbced70d4be3430225144bc23ce9c352b619"));
	assert!(!verifies(key(0x11).bytes(), "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f646e675258ce81cf41f087f8b57d822c0217e1a730d0456dc52107d45525bc0c"));
	// The neutral element as the key, under which one signature verifies for every message: `ring` takes it in all three encodings, and this crate holds none of them.
	let neutral = "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b10700000000000000000000000000000000000000000000000000000000000000";
	for small in ["0100000000000000000000000000000000000000000000000000000000000000", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000080"] {
		assert!(verifies(&unhex(small), neutral) && UnparsedPublicKey::new(&ED25519, unhex(small)).verify(b"anything else", &unhex(neutral)).is_ok(), "{small}");
		assert!(SigningKey::new(unhex(small).try_into().unwrap()).is_none(), "{small}");
	}
	// Every encoding of a point of small order, and every y that is not below p, with either sign bit.
	let order_eight = ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "0000000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"];
	for sign in [0, 0x80] {
		for small in order_eight {assert!(SigningKey::new(std::array::from_fn(|index| unhex(small)[index] | if index == 31 {sign} else {0})).is_none(), "{small}")}
		for low in 0xed..=0xff {assert!(SigningKey::new(std::array::from_fn(|index| if index == 0 {low} else if index == 31 {0x7f | sign} else {0xff})).is_none(), "{low:02x}")}
		// The largest y below p that is no point of small order passes the check of the encoding.
		assert!(SigningKey::new(std::array::from_fn(|index| if index == 0 {0xeb} else if index == 31 {0x7f | sign} else {0xff})).is_some());
	}
	for name in ["high-s", "neutral-r"] {assert_eq!(envelope::verify(&seed(&format!("fuzz_sub_envelope/{name}"))[1..], &[key(0x11)], BODY_MAX).map(|_| ()), Err(EnvelopeError::Signature), "{name}")}
}

#[test]
fn the_header_is_compared_as_bytes() {
	let payload = envelope::verify(&seed("fuzz_sub_envelope/document")[1..], &[key(0x11)], BODY_MAX).unwrap().payload().to_vec();
	let kid = key(0x11).kid().text();
	// Signs under the first key with any bytes as the header.
	let headed = |header: String| {
		let signed = format!("{}.{}", base64(header.as_bytes()), base64(&payload));
		format!("{signed}.{}", base64(pair(0x11).sign(signed.as_bytes()).as_ref()))
	};
	let verify = |document: &str, held: &[SigningKey]| envelope::verify(document.as_bytes(), held, BODY_MAX).map(|verified| verified.signer());
	assert_eq!(verify(&headed(key(0x11).header()), &[key(0x11)]), Ok(key(0x11)));
	// Another algorithm, no algorithm, another type, an extra member, another order, white space, another spelling of the same JSON, a key in the header, and no JSON at all: each is a valid signature of the held key over its own bytes, and none is its header.
	for header in [format!("{{\"alg\":\"none\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"HS256\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"Ed25519\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"EdDSA\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\",\"crit\":[]}}"), format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\",\"jku\":\"https://example.com/keys\"}}"), format!("{{\"typ\":\"veilway-sub+jws\",\"alg\":\"EdDSA\",\"kid\":\"{kid}\"}}"), format!("{{\"kid\":\"{kid}\",\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\"}}"), format!("{{\"alg\": \"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}} "), format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}}\n"), format!("{{\"alg\":\"\\u0045dDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\"}}"), format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{kid}\",\"alg\":\"EdDSA\"}}"), format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{}\"}}", &kid[..10]), String::new(), "{}".to_owned()] {assert_eq!(verify(&headed(header.clone()), &[key(0x11), key(0x22)]), Err(EnvelopeError::UnknownKey), "{header}")}
	// A header that names another held key than the one that signed, and one that names a key that is not held.
	assert_eq!(verify(&sign_with(0x11, 0x22, &payload), &[key(0x11), key(0x22)]), Err(EnvelopeError::Signature));
	assert_eq!(verify(&sign_with(0x11, 0x22, &payload), &[key(0x11)]), Err(EnvelopeError::UnknownKey));
	assert_eq!(verify(&text("fuzz_sub_envelope/other-algorithm")[1..], &[key(0x11)]), Err(EnvelopeError::UnknownKey));
	// "A document that verifies under no key held": signed by a key the client never had, and by one it no longer holds.
	assert_eq!(verify(&text("fuzz_sub_envelope/key-not-held")[1..], &[key(0x11), key(0x22)]), Err(EnvelopeError::UnknownKey));
	assert_eq!(verify(&text("fuzz_sub_envelope/document")[1..], &[key(0x22)]), Err(EnvelopeError::UnknownKey));
	assert_eq!(verify(&text("fuzz_sub_envelope/document")[1..], &[]), Err(EnvelopeError::UnknownKey));
	// Rotation with two keys: each of them signs, and the order they are held in does not matter.
	for held in [[key(0x11), key(0x22)], [key(0x22), key(0x11)]] {assert_eq!((verify(&text("fuzz_sub_envelope/two-keys")[1..], &held), verify(&text("fuzz_sub_envelope/second-key")[1..], &held)), (Ok(key(0x11)), Ok(key(0x22))))}
}

fn base64(bytes: &[u8]) -> String {
	let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	bytes.chunks(3).flat_map(|chunk| {
		let bits = chunk.iter().enumerate().fold(0u32, |bits, (index, byte)| bits | u32::from(*byte) << (16 - 8 * index));
		(0..=chunk.len()).map(move |index| alphabet[(bits >> (18 - 6 * index) & 63) as usize] as char)
	}).collect()
}

#[test]
fn a_badly_encoded_part_refuses_the_document() {
	let document = text("fuzz_sub_envelope/document")[1..].to_owned();
	let parts: Vec<&str> = document.split('.').collect();
	let verify = |document: String, limit: usize| envelope::verify(document.as_bytes(), &[key(0x11)], limit).map(|_| ());
	assert_eq!((verify(document.clone(), document.len()), verify(document.clone(), document.len() - 1), verify(format!("{document} "), document.len())), (Ok(()), Err(EnvelopeError::Size), Err(EnvelopeError::Size)));
	for broken in [String::new(), parts[0].to_owned(), format!("{}.{}", parts[0], parts[1]), format!("{document}."), format!("{document}.{}", parts[2]), format!(".{document}")] {assert_eq!(verify(broken, BODY_MAX), Err(EnvelopeError::Parts))}
	// Padding, white space, the other alphabet, a length no encoding has, and bits set that no byte takes, in each part. The signed bytes of the first two are as delivered, so each of these would also fail the signature: the encoding is what is reported, since it is checked first.
	for (index, changed) in [(0, format!("{}=", parts[0])), (0, format!("{} ", parts[0])), (0, format!("{}AA", parts[0])), (0, format!("{}B", &parts[0][..parts[0].len() - 1])), (1, format!("{}=", parts[1])), (1, format!("{}\n", parts[1])), (1, format!(" {}", parts[1])), (1, parts[1].replacen('a', "+", 1)), (1, parts[1].replacen('a', "/", 1)), (1, format!("{}A", &parts[1][..parts[1].len() - parts[1].len() % 4])), (2, format!("{}=", parts[2])), (2, format!("{}==", parts[2])), (2, parts[2][..85].to_owned()), (2, format!("{}A", parts[2])), (2, format!("{}B", &parts[2][..85])), (2, format!("{} ", &parts[2][..85])), (2, String::new())] {
		let mut broken = parts.clone();
		broken[index] = &changed;
		assert_eq!(verify(broken.join("."), BODY_MAX), Err(EnvelopeError::Encoding), "part {index}: {changed}");
	}
	// A payload part whose last character has an unused bit set decodes to the same bytes under a lax decoder. Here it is refused before the signature is looked at.
	let (lax, strict) = ("e31", base64(b"{}"));
	assert_eq!((strict.as_str(), verify(format!("{}.{lax}.{}", parts[0], parts[2]), BODY_MAX), verify(format!("{}.{strict}.{}", parts[0], parts[2]), BODY_MAX)), ("e30", Err(EnvelopeError::Encoding), Err(EnvelopeError::Signature)));
}

#[test]
fn the_document_of_the_vectors_reads_as_what_it_says() {
	let document = subscription(&payload("content"));
	assert_eq!((document.id.as_str(), document.serial, document.issued_at, document.expires_at, document.signing_keys.clone(), document.provider.as_str(), document.update_interval), ("example-account-0001", 5, ISSUED, ISSUED + 30 * 86_400, vec![key(0x11)], "Example Provider", 7_200));
	assert_eq!((document.refresh_urls[0].as_str(), document.refresh_urls[0].host(), document.origin(), document.left_out, document.refused.len()), ("https://mirror.example.net/s", "mirror.example.net", KeyOrigin::Provider, 0, 0));
	let profile = &document.profiles[0];
	assert_eq!((profile.id.as_str(), profile.name.as_str(), profile.inbound_public_key, profile.mtu, profile.parallel, profile.stream_first, profile.min_control_version, profile.rating_cap), ("main", "Example", std::array::from_fn(|index| 32 + index as u8), 1420, 1, false, 1, None));
	assert_eq!((profile.padding.wide_max, profile.padding.normal_max, profile.padding.keepalive.clone()), (1023, 255, 20_000..=40_000));
	assert_eq!((profile.device.addresses.clone(), profile.gateways.clone()), (vec!["10.7.0.2".parse().unwrap(), "fd00::2".parse().unwrap()], vec!["10.7.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]));
	assert_eq!((profile.device.private_key.clone(), profile.device.transport_secrets.clone(), profile.device.preshared_key.clone()), (Some(Secret::new([0x33; 32])), vec![Secret::new(std::array::from_fn(|index| index as u8))], None));
	let (Transport::UdpObfs(endpoints), Transport::Tls(stream)) = (&profile.transports[0], &profile.transports[1]) else {panic!("the two transports")};
	assert_eq!(endpoints.iter().map(|dial| dial.address().to_string()).collect::<Vec<_>>(), ["192.0.2.10:51820", "[2001:db8::10]:51820"]);
	assert_eq!((stream.path.as_str(), stream.candidates[0].address.address().to_string(), stream.candidates[0].sni.as_deref(), stream.candidates[0].host.as_str(), stream.candidates[0].verify_name.as_deref(), stream.candidates[0].pins.len()), ("/a-path-of-a-transport", "192.0.2.10:443".to_owned(), Some("node.example.com"), "node.example.com", None, 1));
	assert_eq!((profile.exits[0].tag.as_str(), profile.exits[0].name.as_str(), profile.exits[0].country, profile.exits[0].full_ip), ("de", "Berlin", Some(*b"DE"), true));
	// "A cover transport whose address is also the address of a `udp` or `udp-obfs` endpoint is capped": the set the core compares with.
	assert!(document.datagram_addresses().contains(&stream.candidates[0].address.address().ip()) && document.datagram_addresses().len() == 2);
	assert_eq!((document.devices[0].name.as_str(), document.devices[0].enrolled_at, document.devices[0].this, document.devices[0].pending), ("phone", ISSUED, true, false));
	let usage = document.usage.clone().unwrap();
	assert_eq!((usage.used_bytes, usage.quota_bytes, usage.period, usage.period_start, usage.expires_at, usage.device_limit), (1, 2, Period::Monthly, ISSUED, 0, 3));
	assert_eq!((document.support[0].label.as_str(), document.support[0].url.as_str(), document.accent, document.logo.clone().map(|logo| (logo.kind, logo.data))), ("Help", "https://example.com/help", Some([0x33, 0x66, 0xcc]), Some((LogoKind::Png, b"\x89PNG".to_vec()))));
	assert_eq!((document.notices[0].severity, document.notices[0].text.as_str(), document.cards.len()), (Severity::Warning, "Maintenance", 4));
	assert!(matches!(&document.cards[..], [Card::Stat {unit: Some(unit), ..}, Card::Progress {used: 1, total: 2, ..}, Card::Notice(notice), Card::Link {url, ..}] if unit.as_str() == "GB" && notice.severity == Severity::Information && url.host() == "example.com"));
	// No secret of a document is in what it prints.
	let printed = format!("{document:?}");
	assert_eq!(printed, "Subscription(example-account-0001, serial 5, 1 profiles, 0 refused)");
}

// What a hostile document must come to.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Want {
	// The document is refused with this error.
	Refused(PayloadError),
	// The first profile is refused with this fault, and the second is kept.
	Profile(Fault),
	// The document is kept, with this many things left out of it.
	LeftOut(usize),
	// The document reads whole: the value is at a limit, not over it.
	Fine,
}

// A document of two profiles and every kind of provider content, in which the first profile has a stream transport of each kind.
fn rich() -> Value {
	let mut document = payload("content");
	let candidate = json!({"address": "192.0.2.20:443", "sni": "cdn.example.net", "host": "node.example.com"});
	document["profiles"][0]["transports"].as_array_mut().unwrap().extend([json!({"type": "ws", "path": "/a-path-of-a-transport", "candidates": [candidate.clone()]}), json!({"type": "fronted", "path": "/a-path-of-a-transport", "candidates": [candidate]}), json!({"type": "udp", "endpoints": ["192.0.2.30:51820"]})]);
	let mut other = document["profiles"][0].clone();
	other["id"] = json!("other");
	document["profiles"].as_array_mut().unwrap().push(other);
	document["devices"].as_array_mut().unwrap().push(json!({"name": "", "enrolled_at": 1, "this": false, "pending": true}));
	document
}

fn judge(name: &str, document: &Value, want: Want) {
	match (read(document), want) {
		(Err(error), Want::Refused(wanted)) => assert_eq!(error, wanted, "{name}"),
		(Ok(Payload::Subscription(read)), Want::Profile(fault)) => assert_eq!((read.refused.iter().map(|refused| (refused.position, refused.fault)).collect::<Vec<_>>(), read.profiles.iter().map(|profile| profile.id.as_str()).collect::<Vec<_>>()), (vec![(0, fault)], vec!["other"]), "{name}"),
		(Ok(Payload::Subscription(read)), Want::LeftOut(count)) => assert_eq!((read.left_out, read.profiles.len(), read.refused.len()), (count, 2, 0), "{name}"),
		(Ok(Payload::Subscription(read)), Want::Fine) => assert_eq!((read.left_out, read.profiles.len(), read.refused.len()), (0, 2, 0), "{name}"),
		(other, want) => panic!("{name}: wanted {want:?}, got {other:?}"),
	}
}

#[test]
fn a_hostile_document_for_every_limit_and_rule() {
	use {Fault::Unsupported, PayloadError as E, Want::{Fine, LeftOut, Profile, Refused}};
	let (member, fault) = (|name: &'static str| Refused(E::Member(name)), |name: &'static str| Profile(Fault::Member(name)));
	let (zero, one, small) = ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=");
	let (key1, key2, key3) = (json!(std_base64(key(0x11).bytes())), json!(std_base64(key(0x22).bytes())), json!(small));
	let list = |item: Value, count: usize| Value::Array(vec![item; count]);
	let long = |count: usize| "a".repeat(count);
	let pin = rich()["profiles"][0]["transports"][1]["candidates"][0]["pins"][0].clone();
	let exits = |count: usize| Value::Array((0..count).map(|index| json!({"tag": format!("e{index}"), "name": "Exit"})).collect());
	let profiles = |count: usize| Value::Array((0..count).map(|index| with(rich()["profiles"][0].clone(), &[("/id", json!(format!("p{index}")))])).collect());
	let table: Vec<(&str, Option<Value>, Want)> = vec![
		// Versioning.
		("/v", None, member("v")), ("/v", Some(json!(0)), member("v")), ("/v", Some(json!("1")), member("v")), ("/v", Some(json!(2)), Refused(E::Version)), ("/v", Some(json!(9_007_199_254_740_991u64)), Refused(E::Version)), ("/v", Some(json!(9_007_199_254_740_992u64)), member("v")),
		("/critical", Some(json!([])), Fine), ("/critical", Some(json!(["routes"])), Refused(E::Critical)), ("/critical", Some(json!("routes")), member("critical")), ("/critical", Some(json!([1])), member("critical")),
		// Identity, rollback and expiry.
		("/subscription_id", None, member("subscription_id")), ("/subscription_id", Some(json!(long(15))), member("subscription_id")), ("/subscription_id", Some(json!(long(16))), Fine), ("/subscription_id", Some(json!(long(64))), Fine), ("/subscription_id", Some(json!(long(65))), member("subscription_id")), ("/subscription_id", Some(json!("example account 0001")), member("subscription_id")), ("/subscription_id", Some(json!(1)), member("subscription_id")),
		("/serial", None, member("serial")), ("/serial", Some(json!(0)), member("serial")), ("/serial", Some(json!(9_007_199_254_740_991u64)), Fine), ("/serial", Some(json!(9_007_199_254_740_992u64)), member("serial")), ("/serial", Some(json!(-1)), member("serial")), ("/serial", Some(json!("5")), member("serial")),
		("/issued_at", None, member("issued_at")), ("/issued_at", Some(json!(9_007_199_254_740_992u64)), member("issued_at")), ("/expires_at", None, member("expires_at")), ("/expires_at", Some(json!(ISSUED)), member("expires_at")), ("/expires_at", Some(json!(ISSUED - 1)), member("expires_at")), ("/expires_at", Some(json!(ISSUED + 1)), Fine), ("/expires_at", Some(json!(ISSUED + 90 * 86_400)), Fine), ("/expires_at", Some(json!(ISSUED + 90 * 86_400 + 1)), member("expires_at")),
		// Keys held.
		("/signing_keys", None, member("signing_keys")), ("/signing_keys", Some(json!([])), member("signing_keys")), ("/signing_keys", Some(json!([key1, key2])), Fine), ("/signing_keys", Some(json!([key2, key1])), Fine), ("/signing_keys", Some(json!([key1, key2, key3])), member("signing_keys")), ("/signing_keys", Some(json!([key1, key1])), member("signing_keys")), ("/signing_keys", Some(json!([key2])), Refused(E::Signer)), ("/signing_keys", Some(json!([key2, key3])), Refused(E::Signer)), ("/signing_keys", Some(json!([key1, zero])), member("signing_keys")), ("/signing_keys", Some(json!([key1, one])), member("signing_keys")), ("/signing_keys", Some(json!([key1, &small[..43]])), member("signing_keys")), ("/signing_keys", Some(json!([key1, 7])), member("signing_keys")), ("/signing_keys", Some(key1.clone()), member("signing_keys")),
		// The provider's name: display text of 1 to 64 characters, cut and never refused for its length.
		("/provider", None, member("provider")), ("/provider", Some(json!("Example")), member("provider")), ("/provider/name", None, member("name")), ("/provider/name", Some(json!("")), member("name")), ("/provider/name", Some(json!("\u{200b}\u{202e}\u{7}")), member("name")), ("/provider/name", Some(json!(7)), member("name")), ("/provider/name", Some(json!(long(5_000))), Fine), ("/provider/logo", Some(json!("ignored")), Fine),
		("/update_interval", Some(json!(899)), member("update_interval")), ("/update_interval", Some(json!(900)), Fine), ("/update_interval", Some(json!(604_800)), Fine), ("/update_interval", Some(json!(604_801)), member("update_interval")), ("/update_interval", Some(json!("3600")), member("update_interval")),
		("/refresh_urls", Some(list(json!("https://mirror.example.net/s"), 4)), Fine), ("/refresh_urls", Some(list(json!("https://mirror.example.net/s"), 5)), member("refresh_urls")), ("/refresh_urls/0", Some(json!("http://mirror.example.net/s")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/s#v1")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://192.0.2.1/s")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://user@mirror.example.net/s")), member("refresh_urls")), ("/refresh_urls/0", Some(json!(format!("https://mirror.example.net/{}", long(229)))), Fine), ("/refresh_urls/0", Some(json!(format!("https://mirror.example.net/{}", long(230)))), member("refresh_urls")), ("/refresh_urls/0", Some(json!(1)), member("refresh_urls")), ("/refresh_urls", Some(json!("https://mirror.example.net/s")), member("refresh_urls")),
		// Profiles as a list.
		("/profiles", None, member("profiles")), ("/profiles", Some(json!([])), member("profiles")), ("/profiles", Some(json!({})), member("profiles")), ("/profiles", Some(profiles(65)), member("profiles")), ("/profiles", Some(list(json!({"type": "later"}), 3)), Refused(E::Profiles)), ("/profiles", Some(list(json!(7), 2)), Refused(E::Profiles)), ("/profiles", Some(list(rich()["profiles"][0].clone(), 2)), Refused(E::Profiles)),
		// The three unknown values of a profile, and each of its members.
		("/profiles/0", Some(json!("profile")), fault("profiles")), ("/profiles/0/type", Some(json!("wireguard")), Profile(Unsupported)), ("/profiles/0/type", Some(json!("Veilway")), Profile(Unsupported)), ("/profiles/0/type", None, fault("type")), ("/profiles/0/type", Some(json!(1)), fault("type")), ("/profiles/0/transports/0/type", Some(json!("quic")), Profile(Unsupported)), ("/profiles/0/transports/4/type", Some(json!("quic")), Profile(Unsupported)), ("/profiles/0/transports/0/type", None, fault("type")), ("/profiles/0/future", Some(json!({"anything": [1, 2, {"deep": null}]})), Fine),
		("/profiles/0/id", None, fault("id")), ("/profiles/0/id", Some(json!("")), fault("id")), ("/profiles/0/id", Some(json!("Main")), fault("id")), ("/profiles/0/id", Some(json!("_main")), fault("id")), ("/profiles/0/id", Some(json!("ma in")), fault("id")), ("/profiles/0/id", Some(json!(long(64))), Fine), ("/profiles/0/id", Some(json!(long(65))), fault("id")), ("/profiles/0/id", Some(json!("direct")), Fine),
		("/profiles/0/name", None, fault("name")), ("/profiles/0/name", Some(json!("")), fault("name")), ("/profiles/0/name", Some(json!("\u{feff}")), fault("name")), ("/profiles/0/name", Some(json!(long(9_000))), Fine),
		("/profiles/0/inbound_public_key", None, fault("inbound_public_key")), ("/profiles/0/inbound_public_key", Some(json!(zero)), fault("inbound_public_key")), ("/profiles/0/inbound_public_key", Some(json!(&small[..43])), fault("inbound_public_key")), ("/profiles/0/inbound_public_key", Some(json!(small.replace('=', "A"))), fault("inbound_public_key")), ("/profiles/0/inbound_public_key", Some(json!(format!("{small}="))), fault("inbound_public_key")),
		("/profiles/0/device", None, fault("device")), ("/profiles/0/device", Some(json!([])), fault("device")), ("/profiles/0/device/public_key", None, fault("public_key")), ("/profiles/0/device/public_key", Some(json!(small)), fault("private_key")), ("/profiles/0/device/private_key", Some(json!(small)), fault("private_key")), ("/profiles/0/device/private_key", Some(json!(zero)), fault("private_key")), ("/profiles/0/device/private_key", None, Fine), ("/profiles/0/device/preshared_key", Some(json!(small)), Fine), ("/profiles/0/device/preshared_key", Some(json!(zero)), fault("preshared_key")),
		("/profiles/0/device/addresses", None, fault("addresses")), ("/profiles/0/device/addresses", Some(json!([])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["10.7.0.2", "fd00::2", "fd00::3"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["10.7.0.2", "10.7.0.3"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["fd00::2", "10.7.0.2"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["192.0.2.2", "fd00::2"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["10.7.0.2", "2001:db8::2"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["10.7.0.2/24", "fd00::2"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["10.7.0.2", "fd00::2%1"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["010.7.0.2", "fd00::2"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!("10.7.0.2")), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["100.64.0.2", "fdff::2"])), Fine), ("/profiles/0/device/addresses", Some(json!(["172.32.0.2", "fd00::2"])), fault("addresses")), ("/profiles/0/device/addresses", Some(json!(["10.7.0.2"])), fault("gateways")),
		("/profiles/0/device/transport_secrets", None, fault("transport_secrets")), ("/profiles/0/device/transport_secrets", Some(json!([])), fault("transport_secrets")), ("/profiles/0/device/transport_secrets", Some(list(json!(small), 2)), Fine), ("/profiles/0/device/transport_secrets", Some(list(json!(small), 3)), fault("transport_secrets")), ("/profiles/0/device/transport_secrets", Some(json!([zero])), fault("transport_secrets")), ("/profiles/0/device/transport_secrets", Some(json!([1])), fault("transport_secrets")),
		("/profiles/0/gateways", None, fault("gateways")), ("/profiles/0/gateways", Some(json!(["10.7.0.1"])), fault("gateways")), ("/profiles/0/gateways", Some(json!(["fd00::1", "10.7.0.1"])), fault("gateways")), ("/profiles/0/gateways", Some(json!(["10.7.0.2", "fd00::1"])), fault("gateways")), ("/profiles/0/gateways", Some(json!(["192.0.2.1", "fd00::1"])), fault("gateways")), ("/profiles/0/gateways", Some(json!(["10.7.0.1", "fd00::1", "fd00::3"])), fault("gateways")),
		("/profiles/0/mtu", None, fault("mtu")), ("/profiles/0/mtu", Some(json!(1279)), fault("mtu")), ("/profiles/0/mtu", Some(json!(1280)), Fine), ("/profiles/0/mtu", Some(json!(1500)), Fine), ("/profiles/0/mtu", Some(json!(1501)), fault("mtu")), ("/profiles/0/mtu", Some(json!("1420")), fault("mtu")),
		("/profiles/0/transport_public_key", None, fault("transport_public_key")), ("/profiles/0/transport_public_key", Some(json!(zero)), fault("transport_public_key")),
		("/profiles/0/transports", None, fault("transports")), ("/profiles/0/transports", Some(json!([])), fault("transports")), ("/profiles/0/transports", Some(list(json!({"type": "udp", "endpoints": ["192.0.2.30:51820"]}), 8)), Fine), ("/profiles/0/transports", Some(list(json!({"type": "udp", "endpoints": ["192.0.2.30:51820"]}), 9)), fault("transports")), ("/profiles/0/transports/0", Some(json!("udp")), fault("transports")),
		// "Where a client may be told to connect."
		("/profiles/0/transports/0/endpoints", None, fault("endpoints")), ("/profiles/0/transports/0/endpoints", Some(json!([])), fault("endpoints")), ("/profiles/0/transports/0/endpoints", Some(list(json!("192.0.2.10:51820"), 16)), Fine), ("/profiles/0/transports/0/endpoints", Some(list(json!("192.0.2.10:51820"), 17)), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!(51820)), fault("endpoints")),
		("/profiles/0/transports/0/endpoints/0", Some(json!("127.0.0.1:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("127.255.255.254:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[::1]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("169.254.1.1:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[fe80::1]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[febf::1]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("0.0.0.0:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("0.1.2.3:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[::]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("224.0.0.1:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("239.255.255.255:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[ff02::1]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("255.255.255.255:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[::ffff:192.0.2.10]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[::ffff:c000:20a]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("192.0.2.10:0")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("192.0.2.10:051820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("192.0.2.10:65536")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("192.0.2.10")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("node.example.com:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[fe80::1%1]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("[2001:db8::10%1]:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("2001:db8::10:51820")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("192.0.2.10:51820 ")), fault("endpoints")), ("/profiles/0/transports/0/endpoints/0", Some(json!("10.1.2.3:51820")), Fine), ("/profiles/0/transports/0/endpoints/0", Some(json!("[fe7f::1]:65535")), Fine),
		("/profiles/0/transports/1/candidates/0/address", Some(json!("127.0.0.1:443")), fault("address")), ("/profiles/0/transports/1/candidates/0/address", Some(json!("192.0.2.10:0")), fault("address")), ("/profiles/0/transports/1/candidates/0/address", None, fault("address")), ("/profiles/0/transports/1/candidates/0/address", Some(json!("node.example.com:443")), fault("address")),
		// The path, the candidates and the names.
		("/profiles/0/transports/1/path", None, fault("path")), ("/profiles/0/transports/1/path", Some(json!("/a-path-of-a")), Fine), ("/profiles/0/transports/1/path", Some(json!("/a-path-of-")), fault("path")), ("/profiles/0/transports/1/path", Some(json!("a-path-of-a-transport")), fault("path")), ("/profiles/0/transports/1/path", Some(json!("/a-path-of-a/../transport")), fault("path")), ("/profiles/0/transports/1/path", Some(json!("/a-path-of-a-transport?x")), fault("path")), ("/profiles/0/transports/1/path", Some(json!("/a-path-of-a-transp%6frt")), fault("path")), ("/profiles/0/transports/1/path", Some(json!(format!("/{}", long(255)))), Fine), ("/profiles/0/transports/1/path", Some(json!(format!("/{}", long(256)))), fault("path")),
		("/profiles/0/transports/1/candidates", None, fault("candidates")), ("/profiles/0/transports/1/candidates", Some(json!([])), fault("candidates")), ("/profiles/0/transports/1/candidates", Some(list(rich()["profiles"][0]["transports"][1]["candidates"][0].clone(), 16)), Fine), ("/profiles/0/transports/1/candidates", Some(list(rich()["profiles"][0]["transports"][1]["candidates"][0].clone(), 17)), fault("candidates")), ("/profiles/0/transports/1/candidates/0", Some(json!("192.0.2.10:443")), fault("candidates")),
		("/profiles/0/transports/1/candidates/0/sni", None, fault("sni")), ("/profiles/0/transports/1/candidates/0/sni", Some(json!("Node.example.com")), fault("sni")), ("/profiles/0/transports/1/candidates/0/sni", Some(json!("*.example.com")), fault("sni")), ("/profiles/0/transports/1/candidates/0/sni", Some(json!("192.0.2.10")), fault("sni")), ("/profiles/0/transports/1/candidates/0/sni", Some(json!("")), fault("verify_name")), ("/profiles/0/transports/1/candidates/0/verify_name", Some(json!("node.example.com")), fault("verify_name")), ("/profiles/0/transports/1/candidates/0/host", None, fault("host")), ("/profiles/0/transports/1/candidates/0/host", Some(json!("")), fault("host")), ("/profiles/0/transports/1/candidates/0/host", Some(json!("node.example.com:443")), fault("host")), ("/profiles/0/transports/1/candidates/0/host", Some(json!(format!("{}.example.com", long(64)))), fault("host")),
		("/profiles/0/transports/1/candidates/0/ech", Some(json!(std_base64(&[7; 1_024]))), Fine), ("/profiles/0/transports/1/candidates/0/ech", Some(json!(std_base64(&[7; 1_025]))), fault("ech")), ("/profiles/0/transports/1/candidates/0/ech", Some(json!("")), fault("ech")), ("/profiles/0/transports/1/candidates/0/ech", Some(json!("AAA")), fault("ech")), ("/profiles/0/transports/1/candidates/0/ech", Some(json!([0])), fault("ech")),
		// Pins per candidate, with the rule of each transport: `tls` at index 1, `ws` at 2, `fronted` at 3.
		("/profiles/0/transports/1/candidates/0/pins", None, fault("pins")), ("/profiles/0/transports/1/candidates/0/pins", Some(json!([])), fault("pins")), ("/profiles/0/transports/1/candidates/0/pins", Some(list(pin.clone(), 4)), Fine), ("/profiles/0/transports/1/candidates/0/pins", Some(list(pin.clone(), 5)), fault("pins")), ("/profiles/0/transports/1/candidates/0/pins", Some(json!([&small[..43]])), fault("pins")), ("/profiles/0/transports/1/candidates/0/pins", Some(json!([1])), fault("pins")), ("/profiles/0/transports/1/candidates/0/pins", Some(pin.clone()), fault("pins")), ("/profiles/0/transports/2/candidates/0/pins", Some(json!([pin])), Fine), ("/profiles/0/transports/2/candidates/0/pins", Some(json!([])), fault("pins")), ("/profiles/0/transports/3/candidates/0/pins", Some(json!([pin])), fault("pins")), ("/profiles/0/transports/3/candidates/0/pins", Some(json!([])), fault("pins")),
		// `self_signed`: a boolean, and on a `tls` candidate alone.
		("/profiles/0/transports/1/candidates/0/self_signed", Some(json!(true)), Fine), ("/profiles/0/transports/1/candidates/0/self_signed", Some(json!(false)), Fine), ("/profiles/0/transports/1/candidates/0/self_signed", Some(json!("true")), fault("self_signed")), ("/profiles/0/transports/1/candidates/0/self_signed", Some(json!(1)), fault("self_signed")), ("/profiles/0/transports/1/candidates/0/self_signed", Some(Value::Null), fault("self_signed")), ("/profiles/0/transports/2/candidates/0/self_signed", Some(json!(true)), fault("self_signed")), ("/profiles/0/transports/2/candidates/0/self_signed", Some(json!(false)), fault("self_signed")), ("/profiles/0/transports/3/candidates/0/self_signed", Some(json!(true)), fault("self_signed")), ("/profiles/0/transports/3/candidates/0/self_signed", Some(json!(false)), fault("self_signed")),
		// The optional members of a profile.
		("/profiles/0/stream_first", Some(json!(true)), Fine), ("/profiles/0/stream_first", Some(json!("true")), fault("stream_first")), ("/profiles/0/stream_first", Some(json!(1)), fault("stream_first")), ("/profiles/0/stream_first", Some(Value::Null), fault("stream_first")), ("/profiles/0/parallel", Some(json!(0)), fault("parallel")), ("/profiles/0/parallel", Some(json!(4)), Fine), ("/profiles/0/parallel", Some(json!(5)), fault("parallel")), ("/profiles/0/min_control_version", Some(json!(0)), fault("min_control_version")), ("/profiles/0/min_control_version", Some(json!(255)), Fine), ("/profiles/0/min_control_version", Some(json!(256)), fault("min_control_version")),
		("/profiles/0/padding", Some(json!({})), Fine), ("/profiles/0/padding", Some(json!([])), fault("padding")), ("/profiles/0/padding", Some(json!({"wide_max": 511})), fault("wide_max")), ("/profiles/0/padding", Some(json!({"wide_max": 512, "normal_max": 64})), Fine), ("/profiles/0/padding", Some(json!({"wide_max": 1024})), fault("wide_max")), ("/profiles/0/padding", Some(json!({"normal_max": 63})), fault("normal_max")), ("/profiles/0/padding", Some(json!({"normal_max": 256})), fault("normal_max")),
		// "The upper at least 10 above the lower."
		("/profiles/0/padding", Some(json!({"keepalive": [10, 20]})), Fine), ("/profiles/0/padding", Some(json!({"keepalive": [50, 60]})), Fine), ("/profiles/0/padding", Some(json!({"keepalive": [20, 29]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": [40, 20]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": [9, 30]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": [30, 61]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": [20]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": [20, 40, 60]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": [20.0, 40]})), fault("keepalive")), ("/profiles/0/padding", Some(json!({"keepalive": 30})), fault("keepalive")),
		("/profiles/0/rating_cap", Some(json!("detectable")), Fine), ("/profiles/0/rating_cap", Some(json!("unsafe")), Fine), ("/profiles/0/rating_cap", Some(json!("protected")), fault("rating_cap")), ("/profiles/0/rating_cap", Some(json!("Unsafe")), fault("rating_cap")), ("/profiles/0/rating_cap", Some(json!(1)), fault("rating_cap")),
		("/profiles/0/exits", Some(exits(256)), Fine), ("/profiles/0/exits", Some(exits(257)), fault("exits")), ("/profiles/0/exits", Some(json!({})), fault("exits")),
		// Devices, usage and provider content.
		("/devices", Some(list(json!({"name": "", "enrolled_at": 0, "this": false}), 64)), Fine), ("/devices", Some(list(json!({"name": "", "enrolled_at": 0, "this": false}), 65)), member("devices")), ("/devices", Some(list(json!({"name": "", "enrolled_at": 0, "this": true}), 2)), LeftOut(2)), ("/devices", Some(json!([{"name": "a", "enrolled_at": 0, "this": true}, {"name": "b", "enrolled_at": 0, "this": false}, {"name": "c", "enrolled_at": 0, "this": true}, {"name": "d", "enrolled_at": 0, "this": true}])), LeftOut(3)), ("/devices", Some(json!("phone")), member("devices")), ("/devices/0/this", None, LeftOut(1)), ("/devices/0/name", None, LeftOut(1)), ("/devices/0/enrolled_at", Some(json!(-1)), LeftOut(1)), ("/devices/0/pending", Some(json!("no")), LeftOut(1)), ("/devices/0", Some(json!("phone")), LeftOut(1)), ("/devices/0/name", Some(json!(long(900))), Fine),
		// `usage` decides nothing, so whatever is wrong with it leaves it out and keeps the document.
		("/usage", Some(json!([])), LeftOut(1)), ("/usage", Some(json!("none")), LeftOut(1)), ("/usage/used_bytes", None, LeftOut(1)), ("/usage/used_bytes", Some(json!(9_007_199_254_740_992u64)), LeftOut(1)), ("/usage/quota_bytes", Some(json!(-1)), LeftOut(1)), ("/usage/period", None, LeftOut(1)), ("/usage/period", Some(json!("yearly")), LeftOut(1)), ("/usage/period", Some(json!(3)), LeftOut(1)), ("/usage/period_start", Some(json!(1.5)), LeftOut(1)), ("/usage/expires_at", Some(json!("0")), LeftOut(1)), ("/usage/device_limit", Some(json!(65_535)), Fine), ("/usage/device_limit", Some(json!(65_536)), LeftOut(1)), ("/usage/later", Some(json!(1)), Fine),
		// A name must show something: white space, a lone combining mark and characters that render as nothing are no name. Elsewhere such text is only cut.
		("/provider/name", Some(json!(" ")), member("name")), ("/provider/name", Some(json!("\u{a0}\u{3000}\u{2003}")), member("name")), ("/provider/name", Some(json!("\u{2800}")), member("name")), ("/provider/name", Some(json!("\u{fffc}\u{1bca0}\u{13430}\u{e000}\u{ffff}")), member("name")), ("/provider/name", Some(json!("\u{301}")), member("name")), ("/provider/name", Some(json!("\u{1160}\u{2062}\u{e0001}")), member("name")), ("/provider/name", Some(json!(" a\u{301} ")), Fine), ("/profiles/0/name", Some(json!("\u{2000}\u{2001}")), fault("name")), ("/profiles/0/name", Some(json!("\u{2800}\u{fffc}")), fault("name")), ("/devices/0/name", Some(json!(" ")), Fine),
		// A public key of small order is no key, in a document as in a request: here 1, and p - 1 with the highest bit set.
		("/profiles/0/inbound_public_key", Some(json!(one)), fault("inbound_public_key")), ("/profiles/0/transport_public_key", Some(json!(one)), fault("transport_public_key")), ("/profiles/0/device/public_key", Some(json!(one)), fault("public_key")), ("/profiles/0/inbound_public_key", Some(json!(std_base64(&unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))), fault("inbound_public_key")), ("/profiles/0/inbound_public_key", Some(json!(std_base64(&unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")))), fault("inbound_public_key")), ("/profiles/0/device/transport_secrets", Some(json!([one])), Fine),
		// A URL the token is sent to holds no encoded control character, slash or backslash, and no `.` or `..` segment in any dress.
		("/refresh_urls/0", Some(json!("https://mirror.example.net/%00")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/%0d%0a")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a%1Fb")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a%7fb")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a%2f..%2fb")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a%2Fb")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a%5cb")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a/..;/b")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a/.;x=1/b")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a/%2e%2e%2fb")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/s?x=%00")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/\\\\b")), member("refresh_urls")), ("/refresh_urls/0", Some(json!("https://mirror.example.net/a%20b;c/..d?y=../..")), Fine), ("/refresh_urls/0", Some(json!("https://mirror.example.net:443/@b.example")), Fine), ("/support/0/url", Some(json!("https://example.com/a%2Fb%0a")), Fine),
		("/support", Some(list(json!({"label": "Help", "url": "https://example.com/"}), 4)), Fine), ("/support", Some(list(json!({"label": "Help", "url": "https://example.com/"}), 5)), member("support")), ("/support", Some(json!({})), member("support")), ("/support/0/url", Some(json!("http://example.com/help")), LeftOut(1)), ("/support/0/url", Some(json!("javascript:alert(1)")), LeftOut(1)), ("/support/0/url", Some(json!("https://user:pass@example.com/")), LeftOut(1)), ("/support/0/url", Some(json!(format!("https://example.com/{}", long(492)))), Fine), ("/support/0/url", Some(json!(format!("https://example.com/{}", long(493)))), LeftOut(1)), ("/support/0/url", None, LeftOut(1)), ("/support/0/label", None, LeftOut(1)), ("/support/0/label", Some(json!(["Help"])), LeftOut(1)),
		("/cards", Some(list(json!({"type": "stat", "label": "", "value": ""}), 6)), Fine), ("/cards", Some(list(json!({"type": "stat", "label": "", "value": ""}), 7)), member("cards")), ("/cards", Some(json!("card")), member("cards")), ("/cards/0/type", Some(json!("html")), LeftOut(1)), ("/cards/0/type", None, LeftOut(1)), ("/cards/0/value", None, LeftOut(1)), ("/cards/0/unit", None, Fine), ("/cards/0/unit", Some(json!(8)), LeftOut(1)), ("/cards/1/used", Some(json!(3)), LeftOut(1)), ("/cards/1/total", Some(json!(0)), LeftOut(1)), ("/cards/1/used", Some(json!(0)), Fine), ("/cards/1/used", Some(json!(1.0)), LeftOut(1)), ("/cards/1/total", Some(json!(9_007_199_254_740_992u64)), LeftOut(1)), ("/cards/2/severity", Some(json!("error")), LeftOut(1)), ("/cards/2/text", None, LeftOut(1)), ("/cards/3/url", Some(json!("veilway://sub/example.com/s")), LeftOut(1)), ("/cards/3/url", Some(json!("https://example.com/a b")), LeftOut(1)), ("/cards/3", Some(json!(["link"])), LeftOut(1)),
		("/logo", Some(json!({"type": "png", "data": std_base64(&vec![7; 65_536])})), Fine), ("/logo", Some(json!({"type": "png", "data": std_base64(&vec![7; 65_537])})), LeftOut(1)), ("/logo/type", Some(json!("gif")), LeftOut(1)), ("/logo/type", Some(json!("svg")), LeftOut(1)), ("/logo/data", Some(json!("")), LeftOut(1)), ("/logo/data", Some(json!("iVBORw0K Ggo=")), LeftOut(1)), ("/logo/data", Some(json!("https://example.com/logo.png")), LeftOut(1)), ("/logo", Some(json!("iVBORw0KGgo=")), LeftOut(1)),
		("/accent", Some(json!("#AbCdEf")), Fine), ("/accent", Some(json!("#12345")), member("accent")), ("/accent", Some(json!("#1234567")), member("accent")), ("/accent", Some(json!("#gggggg")), member("accent")), ("/accent", Some(json!("336699")), member("accent")), ("/accent", Some(json!("red")), member("accent")), ("/accent", Some(json!(3_368_601)), member("accent")),
		("/notices", Some(list(json!({"severity": "info", "text": ""}), 4)), Fine), ("/notices", Some(list(json!({"severity": "info", "text": ""}), 5)), member("notices")), ("/notices/0/severity", Some(json!("critical")), LeftOut(1)), ("/notices/0/severity", None, LeftOut(1)), ("/notices/0/text", Some(json!(280)), LeftOut(1)),
		// A refusal is a closed set too, and "the other members are not read".
		("/refusal", Some(json!("banned")), Refused(E::Refusal)), ("/refusal", Some(json!(1)), member("refusal")), ("/unknown", Some(json!({"anything": [1, 2, 3]})), Fine),
	];
	judge("the document as it is", &rich(), Fine);
	for (pointer, value, want) in table {
		let mut document = rich();
		put(&mut document, pointer, value.clone());
		judge(&format!("{pointer} = {}", value.map_or("absent".to_owned(), |value| value.to_string().chars().take(60).collect())), &document, want);
	}
	// Two profiles with one `id` are both refused, and the third is kept.
	let twice = subscription(&with(rich(), &[("/profiles/1/id", json!("main")), ("/profiles/2", rich()["profiles"][1].clone())]));
	assert_eq!((twice.refused.iter().map(|refused| (refused.position, refused.id.as_deref(), refused.fault)).collect::<Vec<_>>(), twice.profiles.len(), twice.profiles[0].id.as_str()), (vec![(0, Some("main"), Fault::Duplicate), (1, Some("main"), Fault::Duplicate)], 1, "other"));
	// An exit that does not read is left out, and so is one whose tag is taken.
	let exits = subscription(&with(rich(), &[("/profiles/0/exits", json!([{"tag": "de", "name": "Berlin"}, {"tag": "direct", "name": "Reserved"}, {"tag": "DE", "name": "Upper"}, {"tag": "nl", "name": ""}, {"tag": "fr", "name": "Paris", "country": "fr"}, {"tag": "se", "name": "Stockholm", "country": "SWE"}, {"tag": "de", "name": "Again"}, {"tag": "us", "name": "Dallas", "full_ip": 1}, "it", {"tag": "ch", "name": "Zurich", "country": "CH", "later": true}]))]));
	assert_eq!(exits.profiles[0].exits.iter().map(|exit| (exit.tag.as_str(), exit.name.as_str(), exit.full_ip)).collect::<Vec<_>>(), [("de", "Berlin", false), ("ch", "Zurich", false)]);
	// A signed refusal needs its four members and reads no other.
	for (reason, word) in Reason::ALL.iter().map(|reason| (*reason, reason.word())) {assert_eq!(read(&json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": 5, "refusal": word, "serial": "not read", "profiles": 7})).map(|payload| matches!(payload, Payload::Refusal(refusal) if refusal.reason == reason && refusal.issued_at == 5)), Ok(true), "{word}")}
	assert_eq!((Reason::ALL.len(), RatingCap::ALL.len(), LogoKind::ALL.len()), (8, 2, 2));
	for (document, error) in [(json!({"v": 1, "issued_at": 5, "refusal": "disabled"}), E::Member("subscription_id")), (json!({"v": 1, "subscription_id": "example-account-0001", "refusal": "disabled"}), E::Member("issued_at")), (json!({"subscription_id": "example-account-0001", "issued_at": 5, "refusal": "disabled"}), E::Member("v")), (json!({"v": 2, "subscription_id": "example-account-0001", "issued_at": 5, "refusal": "disabled"}), E::Version), (json!({"v": 1, "critical": ["x"], "subscription_id": "example-account-0001", "issued_at": 5, "refusal": "disabled"}), E::Critical), (json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": 5, "refusal": "Disabled"}), E::Refusal)] {assert_eq!(read(&document).err(), Some(error), "{document}")}
}

// "A candidate with `self_signed` set still needs 1 to 4 `pins`. Its `sni` may be a host name, which is sent, or empty. It has no `verify_name`, since no name is checked, and a `verify_name` on it refuses the candidate."
#[test]
fn a_self_signed_candidate_is_a_tls_candidate_with_pins_and_no_name_to_check() {
	let document = subscription(&payload("self-signed"));
	let Transport::Tls(stream) = &document.profiles[0].transports[0] else {panic!("a tls transport")};
	assert_eq!(stream.candidates.iter().map(|candidate| (candidate.self_signed, candidate.sni.as_deref(), candidate.verify_name.as_deref(), candidate.pins.len())).collect::<Vec<_>>(), [(true, None, None, 1), (true, Some("node.example.com"), None, 2)]);
	assert_eq!(format!("{:?}", stream.candidates), "[Candidate(1 pins, self-signed), Candidate(2 pins, self-signed)]");
	// Every other candidate of the vectors is checked as it always was.
	assert!(subscription(&payload("content")).profiles.iter().flat_map(|profile| &profile.transports).all(|transport| !matches!(transport, Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) if stream.candidates.iter().any(|candidate| candidate.self_signed))));
	let at = "/profiles/0/transports/1/candidates/0";
	let changed = |changes: &[(&str, Option<Value>)]| {
		let mut document = rich();
		for (member, value) in changes {put(&mut document, &format!("{at}/{member}"), value.clone())}
		document
	};
	use Want::{Fine, Profile};
	for (name, changes, want) in [
		("an empty sni and no verify_name", vec![("self_signed", Some(json!(true))), ("sni", Some(json!("")))], Fine),
		("an empty sni and a verify_name", vec![("self_signed", Some(json!(true))), ("sni", Some(json!(""))), ("verify_name", Some(json!("node.example.com")))], Profile(Fault::Member("verify_name"))),
		("a sni and a verify_name", vec![("self_signed", Some(json!(true))), ("verify_name", Some(json!("node.example.com")))], Profile(Fault::Member("verify_name"))),
		("no pins", vec![("self_signed", Some(json!(true))), ("pins", None)], Profile(Fault::Member("pins"))),
		("five pins", vec![("self_signed", Some(json!(true))), ("pins", Some(Value::Array(vec![rich()["profiles"][0]["transports"][1]["candidates"][0]["pins"][0].clone(); 5])))], Profile(Fault::Member("pins"))),
		("false with an empty sni and no verify_name", vec![("self_signed", Some(json!(false))), ("sni", Some(json!("")))], Profile(Fault::Member("verify_name"))),
	] {judge(name, &changed(&changes), want)}
	// What is read is what the page means: `true` alone makes a candidate self-signed.
	let read = subscription(&changed(&[("self_signed", Some(json!(true))), ("sni", Some(json!("")))]));
	let Transport::Tls(stream) = &read.profiles[0].transports[1] else {panic!("a tls transport")};
	assert!(stream.candidates[0].self_signed && stream.candidates[0].sni.is_none() && stream.candidates[0].verify_name.is_none());
	assert!(matches!(&subscription(&rich()).profiles[0].transports[1], Transport::Tls(stream) if !stream.candidates[0].self_signed));
}

fn std_base64(bytes: &[u8]) -> String {
	let text = base64(bytes).replace('-', "+").replace('_', "/");
	format!("{text}{}", "=".repeat((4 - text.len() % 4) % 4))
}

// The strict rules of JSON and its parsing limits, each in a payload under a good signature.
#[test]
fn a_payload_that_is_not_strict_json_refuses_the_document() {
	let good = serde_json::to_string(&rich()).unwrap();
	assert!(read_raw(good.as_bytes()).is_ok() && read_raw(format!(" {good}\n").as_bytes()).is_ok());
	// A member the reader does not know, nested `depth` lists deep inside the payload object.
	let nested = |depth: usize| format!("{},\"x\":{}1{}}}", &good[..good.len() - 1], "[".repeat(depth), "]".repeat(depth));
	let json = |error: JsonError| Some(PayloadError::Json(error));
	for (payload, error) in [
		(format!("{{\"v\":2,{}", &good[1..]), json(JsonError::Duplicate)),
		(good.replacen("\"mtu\":1420", "\"mtu\":1420,\"mtu\":1420", 1), json(JsonError::Duplicate)),
		// The same name, written once with an escape.
		(good.replacen("\"mtu\"", "\"mtu\":1280,\"\\u006dtu\"", 1), json(JsonError::Duplicate)),
		(format!("\u{feff}{good}"), json(JsonError::Syntax)),
		(format!("{good}{good}"), json(JsonError::Syntax)),
		(format!("{good}x"), json(JsonError::Syntax)),
		(good.replacen("Example Provider", "Example\\u0000Provider", 1), json(JsonError::Nul)),
		(good.replacen("\"provider\"", "\"\\u0000\":1,\"provider\"", 1), json(JsonError::Nul)),
		(good.replacen("Example Provider", "Example\u{0}Provider", 1), json(JsonError::Syntax)),
		(good.replacen("Example Provider", "Example\\ud800Provider", 1), json(JsonError::Syntax)),
		// The payload object is the first level, so seven more are within the limit and eight are not.
		(nested(7), None),
		(nested(8), json(JsonError::Depth)),
		(format!("{},\"x\":[{}1]}}", &good[..good.len() - 1], "1,".repeat(20_000)), json(JsonError::Values)),
		(format!("{},\"{}\":1}}", &good[..good.len() - 1], "x".repeat(1_024)), None),
		(format!("{},\"{}\":1}}", &good[..good.len() - 1], "x".repeat(1_025)), json(JsonError::Name)),
		("[]".to_owned(), Some(PayloadError::Object)),
		("\"v\"".to_owned(), Some(PayloadError::Object)),
		("null".to_owned(), Some(PayloadError::Object)),
		(String::new(), json(JsonError::Syntax)),
	] {assert_eq!(read_raw(payload.as_bytes()).err(), error, "{}", &payload[..payload.len().min(60)])}
	// Invalid UTF-8 inside a string.
	assert_eq!(read_raw(&[&good.as_bytes()[..good.len() - 1], b",\"x\":\"\xff\"}"].concat()).err(), json(JsonError::Syntax));
	// "Where an integer is expected only an integer token is accepted": the profile whose `mtu` is written with a fraction is refused.
	let Ok(Payload::Subscription(read)) = read_raw(good.replacen("\"mtu\":1420", "\"mtu\":1420.0", 1).as_bytes()) else {panic!("a document")};
	assert_eq!(read.refused.iter().map(|refused| refused.fault).collect::<Vec<_>>(), [Fault::Member("mtu")]);
}

#[test]
fn display_text_is_filtered_then_cut_and_never_markup() {
	let document = subscription(&with(rich(), &[("/provider/name", json!(format!("\u{202e}Exa\u{200b}mple\u{7}\n{}", "\u{e9}".repeat(100)))), ("/profiles/0/name", json!("<b>Name</b> https://example.com")), ("/notices/0/text", json!("\u{e9}".repeat(200))), ("/cards/0/value", json!("12345678901234567")), ("/cards/0/unit", json!("123456789")), ("/devices/0/name", json!("a".repeat(33))), ("/support/0/label", json!("\u{2066}Help"))]));
	assert_eq!((document.provider.as_str().chars().count(), document.provider.as_str().starts_with("Example\u{e9}")), (64, true));
	// Markup and a URL are characters like any other: the text is shown as plain text, and nothing in it is a link.
	assert_eq!(document.profiles[0].name.as_str(), "<b>Name</b> https://example.com");
	assert_eq!((document.notices[0].text.as_str().len(), document.devices[0].name.as_str().len(), document.support[0].label.as_str()), (280, 32, "Help"));
	assert!(matches!(&document.cards[0], Card::Stat {value, unit: Some(unit), ..} if value.as_str() == "1234567890123456" && unit.as_str() == "12345678"));
}

// The languages of an app: its display language and then the user's fallbacks, each as the app fills it in.
fn tags(list: &[&str]) -> Vec<Tag> {list.iter().map(|tag| Tag::read(tag).unwrap_or_else(|| panic!("{tag}"))).collect()}

// A text as a document writes it, in the place of the provider's name of the document of the vectors. It is put in as written, member by member, because the order of the members is part of the rule.
fn said(written: &str) -> Result<Text, PayloadError> {
	match read_raw(serde_json::to_string(&with(rich(), &[("/provider/name", json!("@@text@@"))])).unwrap().replace("\"@@text@@\"", written).as_bytes()) {
		Ok(Payload::Subscription(read)) => Ok(read.provider),
		Ok(Payload::Refusal(_)) => panic!("{written}"),
		Err(error) => Err(error),
	}
}

fn kept(text: &Text) -> Vec<(&str, &str)> {text.translations().map(|translation| (translation.tag.as_str(), translation.text)).collect()}

#[test]
fn a_language_tag_has_one_spelling() {
	for (tag, parts) in [("fa", ("fa", None, None)), ("en", ("en", None, None)), ("ckb", ("ckb", None, None)), ("fa-Arab", ("fa", Some("Arab"), None)), ("fa-IR", ("fa", None, Some("IR"))), ("fa-Arab-IR", ("fa", Some("Arab"), Some("IR"))), ("zh-Hant-TW", ("zh", Some("Hant"), Some("TW"))), ("ckb-Arab-IQ", ("ckb", Some("Arab"), Some("IQ"))), ("und", ("und", None, None)), ("fas", ("fas", None, None)), ("xx-Xxxx-XX", ("xx", Some("Xxxx"), Some("XX")))] {
		let read = Tag::read(tag).unwrap_or_else(|| panic!("{tag}"));
		assert_eq!((read.as_str(), read.parts()), (tag, parts));
	}
	// Another case, an underscore, a part too long or too short, the parts in another order, other subtags of BCP 47, and anything that is not ASCII.
	for tag in ["", "f", "fars", "FA", "Fa", "fA", "fa-ir", "fa-Ir", "fa-arab", "fa-ARAB", "fa-aRab", "fa-Arab-ir", "fa-Arab-IRN", "fa-Arab-I", "fa-IR-Arab", "fa-Arab-Arab", "fa-IR-IR", "fa-Arab-IR-x", "ckb-Arab-IQQ", "zh-Hant-TWN", "fa_IR", "fa-", "-fa", "fa--IR", "fa-Arab-", "fa -IR", " fa", "fa ", "fa\n", "default", "Default", "x-private", "en-US-POSIX", "es-419", "de-1996", "en-a-bbb", "sr-Latn-RS-x-y", "i-klingon", "f\u{e0}", "\u{6f}\u{301}", "fa-\u{410}rab", "f1", "12", "fa-Ar1b", "fa-I1"] {assert_eq!(Tag::read(tag), None, "{tag:?}")}
}

// The document of the vectors that is written in several languages: what each text holds, and what readers of several languages are shown.
#[test]
fn the_document_in_several_languages_reads_as_what_it_says() {
	// The seed is read as it is written, so that the translations come in the order of the document.
	let Ok(Payload::Subscription(document)) = read_raw(&seed("fuzz_subscription/languages")[1..]) else {panic!("a document")};
	let (profile, persian, german, none) =(&document.profiles[0], tags(&["fa-Arab-IR"]), tags(&["de-Latn-DE"]), tags(&[]));
	assert_eq!((document.provider.as_str(), kept(&document.provider)), ("Example Provider", vec![("fa", "ارائه\u{200c}دهنده نمونه"), ("de", "Beispielanbieter")]));
	assert_eq!((profile.name.as_str(), kept(&profile.name), profile.exits.len(), profile.notices.len(), document.notices.len(), document.left_out), ("Example", vec![("fa", "نمونه")], 2, 1, 1, 0));
	assert_eq!((profile.exits[0].name.as_str(), kept(&profile.exits[0].name), profile.exits[1].name.as_str(), kept(&profile.exits[1].name)), ("Frankfurt", vec![("fa", "فرانکفورت"), ("de", "Frankfurt am Main"), ("zh-Hant-TW", "法蘭克福")], "Amsterdam", vec![]));
	// The joiner of Persian spelling is still in what is shown, in each place where the words need it.
	assert_eq!((profile.notices[0].severity, profile.notices[0].text.as_str(), kept(&profile.notices[0].text)), (Severity::Information, "Maintenance tonight", vec![("fa", "امشب سرور به\u{200c}روزرسانی می\u{200c}شود")]));
	assert_eq!((document.notices[0].severity, document.notices[0].text.as_str(), kept(&document.notices[0].text)), (Severity::Warning, "Welcome", vec![("fa-Arab-IR", "خوش آمدید"), ("fa", "خوش آمدید"), ("en-GB", "Welcome back")]));
	assert_eq!((document.support[0].label.as_str(), kept(&document.support[0].label)), ("Help", vec![("fa", "راهنما")]));
	assert!(matches!(&document.cards[..], [Card::Stat {label, value, unit: Some(unit)}, Card::Notice(notice), Card::Link {label: site, ..}] if kept(label) == [("fa", "طرح")] && kept(value) == [("fa", "پایه")] && kept(unit) == [("fa", "گیگابایت")] && kept(&notice.text) == [("fa", "سلام")] && kept(site) == [("fa", "وب\u{200c}سایت")] && (label.as_str(), value.as_str(), unit.as_str(), notice.text.as_str(), site.as_str()) == ("Plan", "Basic", "GB", "Hello", "Site")));
	// What a reader of Persian, one of German and one of neither is shown, with the tag that marks a translation.
	assert_eq!((document.provider.pick(&persian), document.provider.pick(&german), document.provider.pick(&none), document.provider.pick(&tags(&["ja-Jpan-JP"]))), (("ارائه\u{200c}دهنده نمونه", Some(&persian_tag())), ("Beispielanbieter", Some(&Tag::read("de").unwrap())), ("Example Provider", None), ("Example Provider", None)));
	assert_eq!((profile.name.pick(&german), profile.name.pick(&tags(&["de-Latn-DE", "fa-Arab-IR"])), profile.exits[1].name.pick(&persian)), (("Example", None), ("نمونه", Some(&persian_tag())), ("Amsterdam", None)));
	// Where the user decides, `default` is always there, and the translation stands beside it.
	assert_eq!((document.provider.decided(&persian), document.provider.decided(&none), profile.name.decided(&german)), (("Example Provider", Some(Translation {tag: &persian_tag(), text: "ارائه\u{200c}دهنده نمونه"})), ("Example Provider", None), ("Example", None)));
	// The direction is that of the text that is shown, whatever its tag.
	assert_eq!((direction(document.provider.pick(&persian).0), direction(document.provider.pick(&german).0), direction(profile.exits[0].name.pick(&tags(&["zh-Hant-TW"])).0)), (Direction::RightToLeft, Direction::LeftToRight, Direction::LeftToRight));
	assert_eq!(format!("{document:?}"), "Subscription(example-account-0001, serial 6, 1 profiles, 0 refused)");
}

fn persian_tag() -> Tag {Tag::read("fa").unwrap()}

// "Display text as a string or an object of translations is part of version 1": a document written with strings reads as it did, its texts have no translation, and the same document with every text as an object of `default` alone is the same document.
#[test]
fn a_text_as_a_string_is_the_same_text_as_an_object_with_default_alone() {
	for name in ["content", "import", "import-content", "refresh", "rotation", "refresh-with-link", "rotation-with-link"] {
		let (written, mut objects) = (payload(name), payload(name));
		let mut places = vec!["/provider/name".to_owned()];
		for (index, profile) in written["profiles"].as_array().unwrap().iter().enumerate() {
			places.push(format!("/profiles/{index}/name"));
			places.extend((0..profile["exits"].as_array().map_or(0, Vec::len)).map(|exit| format!("/profiles/{index}/exits/{exit}/name")));
		}
		for (list, members) in [("support", &["label"][..]), ("notices", &["text"]), ("cards", &["label", "value", "unit", "text"])] {
			for (index, item) in written[list].as_array().into_iter().flatten().enumerate() {places.extend(members.iter().filter(|member| item.get(**member).is_some()).map(|member| format!("/{list}/{index}/{member}")))}
		}
		for place in &places {
			let default = objects.pointer(place).unwrap().clone();
			put(&mut objects, place, Some(json!({"default": default})));
		}
		let (strings, same) = (subscription(&written), subscription(&objects));
		assert!(strings == same && format!("{strings:?}") == format!("{same:?}") && strings.left_out == 0 && same.left_out == 0, "{name}");
		let texts: Vec<&Text> = [&strings.provider].into_iter().chain(strings.profiles.iter().flat_map(|profile| [&profile.name].into_iter().chain(profile.exits.iter().map(|exit| &exit.name)))).chain(strings.support.iter().map(|link| &link.label)).chain(strings.notices.iter().map(|notice| &notice.text)).collect();
		assert!(texts.len() >= 3 && texts.iter().all(|text| text.translations().count() == 0 && text.pick(&tags(&["fa-Arab-IR", "en-Latn-US"])) == (text.as_str(), None) && text.decided(&tags(&["fa-Arab-IR"])) == (text.as_str(), None)), "{name}");
	}
	// The seed that is a whole document in several languages is one a client imports.
	assert_eq!(carried(&sign(0x11, &payload("import-languages")), &[]).unwrap().accept(None, &[]).unwrap().held.subscription().profiles[0].notices.len(), 1);
}

// "How the client picks": for the display language and then each fallback, the four tags in turn, then `default`. Nothing is guessed.
#[test]
fn a_translation_is_picked_in_four_steps_per_language_and_never_guessed() {
	let all = said(r#"{"default":"D","sr":"4","sr-RS":"3","sr-Cyrl":"2","sr-Cyrl-RS":"1","sr-Latn":"L","sr-ME":"M","en":"E"}"#).unwrap();
	let pick = |text: &Text, languages: &[&str]| text.pick(&tags(languages)).0.to_owned();
	assert_eq!((pick(&all, &["sr-Cyrl-RS"]), pick(&all, &["sr-Cyrl-BA"]), pick(&all, &["sr-Latn-RS"]), pick(&all, &["sr-Latn-ME"]), pick(&all, &["sr-Glag-RS"]), pick(&all, &["sr-Glag-BA"])), ("1".to_owned(), "2".to_owned(), "L".to_owned(), "L".to_owned(), "3".to_owned(), "4".to_owned()));
	// An app's tag without a script or without a region leaves out the steps that need it.
	assert_eq!((pick(&all, &["sr-RS"]), pick(&all, &["sr-Cyrl"]), pick(&all, &["sr"]), pick(&all, &["sr-ME"]), pick(&all, &["sr-BA"])), ("3".to_owned(), "2".to_owned(), "4".to_owned(), "M".to_owned(), "4".to_owned()));
	// Each step in turn as the text loses the one before.
	for (written, shown) in [(r#"{"default":"D","sr":"4","sr-RS":"3","sr-Cyrl":"2"}"#, "2"), (r#"{"default":"D","sr":"4","sr-RS":"3"}"#, "3"), (r#"{"default":"D","sr":"4"}"#, "4"), (r#"{"default":"D","sr-Latn":"L","sr-ME":"M","sr-Latn-RS":"x","sr-Cyrl-ME":"y"}"#, "D"), (r#"{"default":"D"}"#, "D"), (r#""D""#, "D")] {assert_eq!(pick(&said(written).unwrap(), &["sr-Cyrl-RS"]), shown, "{written}")}
	// The display language is asked through all four steps before the first fallback is asked at all, and the fallbacks in their order.
	assert_eq!((pick(&all, &["sr-Glag-BA", "en-Latn-US"]), pick(&all, &["de-Latn-DE", "en-Latn-US", "sr-Cyrl-RS"]), pick(&all, &["de-Latn-DE", "sr-Cyrl-RS", "en-Latn-US"]), pick(&all, &["de-Latn-DE", "fr-Latn-FR"]), pick(&all, &[])), ("4".to_owned(), "E".to_owned(), "1".to_owned(), "D".to_owned(), "D".to_owned()));
	// No similar language: not a three-letter code for a two-letter one or the other way round, not another language of the same script or region, and `und` matches nothing, also when it is what the app asks for.
	let near = said(r#"{"default":"D","fas":"three","und":"U","ar-Arab-IR":"arabic","prs":"dari","en-GB":"british"}"#).unwrap();
	assert_eq!(kept(&near).len(), 5);
	for languages in [&["fa-Arab-IR"][..], &["fa"], &["und"], &["und-Arab-IR"], &["en-Latn-US"], &["en"], &["ar-Arab-EG"], &["ar"], &["pes"]] {assert_eq!((near.pick(&tags(languages)), near.translation(&tags(languages))), (("D", None), None), "{languages:?}")}
	assert_eq!((pick(&near, &["fas"]), pick(&near, &["ar-Arab-IR"]), pick(&near, &["en-Latn-GB"]), pick(&near, &["und", "prs-Arab-AF"])), ("three".to_owned(), "arabic".to_owned(), "british".to_owned(), "dari".to_owned()));
}

// What a text comes to: `default` and the translations that were kept, or the error of a document whose provider has no name.
type Said<'a> = Result<(&'a str, Vec<(&'a str, &'a str)>), PayloadError>;

// "Text in several languages", rule by rule: what a text is left with, or the refusal where `default` made it wrong.
#[test]
fn a_bad_translation_is_dropped_and_only_default_can_make_a_text_wrong() {
	let (wrong, long): (Said, String) = (Err(PayloadError::Member("name")), "\u{e9}".repeat(100));
	let nine = |names: &[&str]| format!("{{{}}}", names.iter().enumerate().map(|(index, name)| if *name == "default" {"\"default\":\"D\"".to_owned()} else {format!("\"{name}\":\"{index}\"")}).collect::<Vec<_>>().join(","));
	let table: Vec<(String, Said)> = vec![
		// The two forms.
		(r#""Name""#.into(), Ok(("Name", vec![]))), (r#"{"default":"Name"}"#.into(), Ok(("Name", vec![]))), (r#"{"default":"Name","fa":"نام","de":"Name"}"#.into(), Ok(("Name", vec![("fa", "نام"), ("de", "Name")]))),
		// "Only `default` can make a text wrong": missing, of another type, or a name that shows nothing.
		(r#"{}"#.into(), wrong.clone()), (r#"{"fa":"نام"}"#.into(), wrong.clone()), (r#"{"default":5,"fa":"نام"}"#.into(), wrong.clone()), (r#"{"default":null}"#.into(), wrong.clone()), (r#"{"default":["Name"]}"#.into(), wrong.clone()), (r#"{"default":{"default":"Name"}}"#.into(), wrong.clone()), (r#"{"Default":"Name"}"#.into(), wrong.clone()),
		(r#"{"default":"","fa":"نام"}"#.into(), wrong.clone()), ("{\"default\":\"\u{200b} \u{301}\",\"fa\":\"نام\"}".into(), wrong.clone()), (r#"["Name"]"#.into(), wrong.clone()), (r#"5"#.into(), wrong.clone()), (r#"null"#.into(), wrong.clone()), (r#"true"#.into(), wrong.clone()),
		// A member whose name is no legal tag is dropped, and the rest stays.
		(r#"{"default":"Name","FA":"a","fa-ir":"b","fa_IR":"c","fars":"d","f":"e","fa-Arab-IR-x":"f","zh-Hant-TWN":"g","en-US-POSIX":"h","es-419":"i","x-private":"j","":"k","defaults":"l","fa":"نام"}"#.into(), Ok(("Name", vec![("fa", "نام")]))),
		// A value that is no string is dropped, and the rest stays.
		(r#"{"default":"Name","fa":5,"de":null,"en":["x"],"fr":{"default":"x"},"it":true,"es":"Nombre"}"#.into(), Ok(("Name", vec![("es", "Nombre")]))),
		// The same filter, the same limit and the same need to show something as `default`. What is empty after the filter is dropped.
		("{\"default\":\"Name\",\"fa\":\"\u{202e}نا\u{200b}م\u{85}\",\"de\":\"<b>Name</b>\"}".into(), Ok(("Name", vec![("fa", "نام"), ("de", "<b>Name</b>")]))),
		(format!(r#"{{"default":"Name","fr":"{long}"}}"#), Ok(("Name", vec![("fr", &long[..128])]))),
		("{\"default\":\"Name\",\"fa\":\"\",\"de\":\"\u{200b}\u{200c}\",\"en\":\"   \",\"fr\":\"\u{301}\",\"it\":\"\u{200c}\",\"es\":\"x\"}".into(), Ok(("Name", vec![("es", "x")]))),
		// The joiner of a translation is judged as in any text.
		("{\"default\":\"Name\",\"fa\":\"می\u{200c}خواهم\",\"de\":\"Na\u{200c}me\"}".into(), Ok(("Name", vec![("fa", "می\u{200c}خواهم"), ("de", "Name")]))),
		// Eight translations are kept. Of nine the first eight as the document wrote them, wherever `default` stands and whatever the order of their names.
		(nine(&["default", "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh"]), Ok(("D", vec![("aa", "1"), ("bb", "2"), ("cc", "3"), ("dd", "4"), ("ee", "5"), ("ff", "6"), ("gg", "7"), ("hh", "8")]))),
		(nine(&["zz", "yy", "xx", "ww", "default", "vv", "uu", "tt", "ss", "aa"]), Ok(("D", vec![("zz", "0"), ("yy", "1"), ("xx", "2"), ("ww", "3"), ("vv", "5"), ("uu", "6"), ("tt", "7"), ("ss", "8")]))),
		(nine(&["zz", "yy", "xx", "ww", "vv", "uu", "tt", "ss", "aa", "bb", "cc", "default"]), Ok(("D", vec![("zz", "0"), ("yy", "1"), ("xx", "2"), ("ww", "3"), ("vv", "4"), ("uu", "5"), ("tt", "6"), ("ss", "7")]))),
		// A name that is no tag takes none of the eight places.
		(nine(&["default", "AA", "aa", "b", "bb", "cc_DD", "cc", "dd", "ee", "ff", "gg", "hh", "ii"]), Ok(("D", vec![("aa", "2"), ("bb", "4"), ("cc", "6"), ("dd", "7"), ("ee", "8"), ("ff", "9"), ("gg", "10"), ("hh", "11")]))),
		// A legal tag takes its place whatever its value comes to: one of the first eight that is dropped is not made up for by the ninth.
		(r#"{"default":"D","aa":5,"bb":"","cc":"3","dd":"4","ee":"5","ff":"6","gg":"7","hh":"8","ii":"9"}"#.into(), Ok(("D", vec![("cc", "3"), ("dd", "4"), ("ee", "5"), ("ff", "6"), ("gg", "7"), ("hh", "8")]))),
		// `und` and a three-letter code are tags like any other: they are kept, and match no language of an app.
		(r#"{"default":"Name","und":"x","fas":"y"}"#.into(), Ok(("Name", vec![("und", "x"), ("fas", "y")]))),
		// "The same tag twice is a duplicate key", also when one of the two is written with an escape, and so is a second `default`.
		(r#"{"default":"Name","fa":"a","fa":"b"}"#.into(), Err(PayloadError::Json(JsonError::Duplicate))), ("{\"default\":\"Name\",\"fa\":\"a\",\"\\u0066a\":\"b\"}".into(), Err(PayloadError::Json(JsonError::Duplicate))), (r#"{"default":"Name","default":"Name"}"#.into(), Err(PayloadError::Json(JsonError::Duplicate))),
	];
	for (written, want) in table {assert_eq!(said(&written).as_ref().map(|text| (text.as_str(), kept(text))), want.as_ref().map(|(default, translations)| (*default, translations.clone())), "{}", &written[..written.len().min(120)])}
	// "Every translation is a JSON value and counts toward the document's limits on values and on size": a text of 20,000 members is over the limit on values whatever they are named, and one under it keeps eight.
	let many = |count: usize| format!("{{\"default\":\"D\"{}}}", (0..count).map(|index| format!(",\"{}{}{}\":\"x\"", (b'a' + (index / 676) as u8) as char, (b'a' + (index / 26 % 26) as u8) as char, (b'a' + (index % 26) as u8) as char)).collect::<String>());
	assert_eq!((said(&many(17_000)).map(|text| kept(&text).len()), said(&many(20_000)).err()), (Ok(8), Some(PayloadError::Json(JsonError::Values))));
	// Where a text is wrong, the result is the one its place has: the profile is refused, and the exit, the link, the notice, the card and the listed device are left out. A device's name is one string, and an object in its place is another type.
	let (missing, fault) = (json!({"fa": "x"}), Want::Profile(Fault::Member("name")));
	for (pointer, value, want) in [("/profiles/0/name", missing.clone(), fault), ("/profiles/0/name", json!({"default": " ", "fa": "x"}), fault), ("/profiles/0/name", json!({"default": "Name", "FA": "x", "fa": 5, "de": ""}), Want::Fine), ("/support/0/label", missing.clone(), Want::LeftOut(1)), ("/support/0/label", json!({"default": "", "fa": "x"}), Want::Fine), ("/notices/0/text", missing.clone(), Want::LeftOut(1)), ("/notices/0/text", json!({"default": 1}), Want::LeftOut(1)), ("/cards/0/label", missing.clone(), Want::LeftOut(1)), ("/cards/0/value", missing.clone(), Want::LeftOut(1)), ("/cards/0/unit", missing.clone(), Want::LeftOut(1)), ("/cards/1/label", missing.clone(), Want::LeftOut(1)), ("/cards/2/text", missing.clone(), Want::LeftOut(1)), ("/cards/3/label", missing.clone(), Want::LeftOut(1)), ("/cards/0/unit", json!({"default": "GB", "fa": 1}), Want::Fine), ("/devices/0/name", json!({"default": "phone"}), Want::LeftOut(1)), ("/devices/0/name", json!({"default": "phone", "fa": "x"}), Want::LeftOut(1))] {judge(&format!("{pointer} = {value}"), &with(rich(), &[(pointer, value.clone())]), want)}
	let exits = subscription(&with(rich(), &[("/profiles/0/exits", json!([{"tag": "de", "name": {"fa": "x"}}, {"tag": "nl", "name": {"default": "\u{200b}", "fa": "x"}}, {"tag": "fr", "name": {"default": "Paris", "fa": "\u{200b}", "FR": "x", "de": 1}}, {"tag": "se", "name": {"default": "Stockholm", "fa": "استکهلم"}}]))]));
	assert_eq!(exits.profiles[0].exits.iter().map(|exit| (exit.tag.as_str(), exit.name.as_str(), kept(&exit.name))).collect::<Vec<_>>(), [("fr", "Paris", vec![]), ("se", "Stockholm", vec![("fa", "استکهلم")])]);
	// The notices of a profile: at most 4, a list of another type or a longer one is a member of the profile out of its range, and a notice in it that does not read is left out by itself.
	let notice = json!({"severity": "info", "text": {"default": "Maintenance", "fa": "تعمیرات"}});
	for (value, want) in [(json!([]), Want::Fine), (Value::Array(vec![notice.clone(); 4]), Want::Fine), (Value::Array(vec![notice.clone(); 5]), Want::Profile(Fault::Member("notices"))), (json!("Maintenance"), Want::Profile(Fault::Member("notices"))), (json!({"0": notice.clone()}), Want::Profile(Fault::Member("notices"))), (Value::Null, Want::Profile(Fault::Member("notices")))] {judge(&format!("/profiles/0/notices = {value}"), &with(rich(), &[("/profiles/0/notices", value.clone())]), want)}
	let notices = subscription(&with(rich(), &[("/profiles/0/notices", json!([notice, {"severity": "fatal", "text": "x"}, {"severity": "warning", "text": {"fa": "x"}}, {"severity": "warning", "text": "\u{e9}".repeat(200)}]))]));
	assert_eq!((notices.profiles[0].notices.iter().map(|notice| (notice.severity, notice.text.as_str().len(), kept(&notice.text))).collect::<Vec<_>>(), notices.profiles[1].notices.len(), notices.left_out), (vec![(Severity::Information, 11, vec![("fa", "تعمیرات")]), (Severity::Warning, 280, vec![])], 0, 0));
}

fn sent_exit(tag: &str, name: &str) -> control::Exit {control::Exit {tag: tag.into(), name: name.into(), country: None, all_protocols: false, selected: false, configured: false, working: true, load: control::Load::Low}}

// "Languages" on the control channel page: a translation stands for what a node sent only when `default`, as the document wrote it, is byte for byte what the node sent.
#[test]
fn a_translation_stands_for_a_nodes_text_only_when_default_is_the_same_bytes() {
	let document = subscription(&payload("languages"));
	let (profile, persian) = (&document.profiles[0], tags(&["fa-Arab-IR"]));
	assert_eq!(profile.exit_name(&sent_exit("de", "Frankfurt")).map(|name| name.pick(&persian).0), Some("فرانکفورت"));
	// Another name under the tag, the name under another tag, a tag the catalogue does not have, and every way two names can look alike without being the same bytes.
	for (tag, name) in [("de", "Frankfurt am Main"), ("de", "frankfurt"), ("de", "Frankfurt "), ("de", " Frankfurt"), ("de", "Frankfurt\u{200b}"), ("de", "Fran\u{200c}kfurt"), ("de", "Frankfurt\0"), ("de", ""), ("de", "فرانکفورت"), ("de", "Amsterdam"), ("nl", "Frankfurt"), ("fr", "Frankfurt"), ("d", "Frankfurt")] {assert_eq!(profile.exit_name(&sent_exit(tag, name)), None, "{tag} {name:?}")}
	assert_eq!(profile.exit_name(&sent_exit("nl", "Amsterdam")).map(|name| name.pick(&persian)), Some(("Amsterdam", None)));
	// The raw `default` is what is compared, before the filter and the cut: a name the filter changes matches only what was written, and so does a text longer than its limit.
	let (composed, apart, long) = ("Caf\u{e9}", "Cafe\u{301}", "a".repeat(300));
	let raw = subscription(&with(payload("languages"), &[("/profiles/0/exits", json!([{"tag": "a", "name": {"default": "Frank\u{200b}furt", "fa": "x"}}, {"tag": "b", "name": {"default": composed, "fa": "y"}}, {"tag": "c", "name": {"default": "\u{202e}Berlin ", "fa": "z"}}])), ("/profiles/0/notices", json!([{"severity": "info", "text": {"default": long, "fa": "طولانی"}}, {"severity": "info", "text": {"default": "Both", "fa": "از نمایه"}}])), ("/notices", json!([{"severity": "warning", "text": {"default": "Both", "fa": "از اشتراک"}}, {"severity": "warning", "text": {"default": "Welcome", "fa": "خوش آمدید"}}]))]));
	let node = &raw.profiles[0];
	assert_eq!((node.exits[0].name.as_str(), node.exits[2].name.as_str(), node.notices[0].text.as_str().len()), ("Frankfurt", "Berlin ", 280));
	assert_eq!((node.exit_name(&sent_exit("a", "Frankfurt")), node.exit_name(&sent_exit("a", "Frank\u{200b}furt")).map(|name| name.pick(&persian).0), node.exit_name(&sent_exit("b", apart)), node.exit_name(&sent_exit("b", composed)).map(|name| name.pick(&persian).0), node.exit_name(&sent_exit("c", "Berlin ")), node.exit_name(&sent_exit("c", "\u{202e}Berlin ")).map(|name| name.pick(&persian).0)), (None, Some("x"), None, Some("y"), None, Some("z")));
	// A notice: the profile's own first, then the subscription's, whose place says that the two are one notice on the screen. The severity is the node's and is not looked at.
	let notice = |text: &str, severity: Severity| control::Notice {severity, text: text.into()};
	let found = |text: &str, severity: Severity| raw.notice_text(node, &notice(text, severity)).map(|(text, place)| (text.pick(&persian).0.to_owned(), place));
	assert_eq!((found(&long, Severity::Warning), found(&long[..280], Severity::Information), found("Both", Severity::Information), found("Both", Severity::Warning), found("Welcome", Severity::Information), found("Welcome ", Severity::Warning), found("welcome", Severity::Warning), found("", Severity::Warning), found("از نمایه", Severity::Information)), (Some(("طولانی".to_owned(), None)), None, Some(("از نمایه".to_owned(), None)), Some(("از نمایه".to_owned(), None)), Some(("خوش آمدید".to_owned(), Some(1))), None, None, None, None));
	// A reader with no language of the text sees `default`, which is then what the node sent, filtered.
	assert_eq!(raw.notice_text(node, &notice("Welcome", Severity::Warning)).map(|(text, _)| text.pick(&tags(&["de-Latn-DE"]))), Some(("Welcome", None)));
	// Through another profile of the document the profile's own notices are not found, and the subscription's are.
	let two = subscription(&with(rich(), &[("/profiles/0/notices", json!([{"severity": "info", "text": "Only here"}]))]));
	assert_eq!((two.notice_text(&two.profiles[0], &notice("Only here", Severity::Information)).map(|(_, place)| place), two.notice_text(&two.profiles[1], &notice("Only here", Severity::Information)), two.notice_text(&two.profiles[1], &notice("Maintenance", Severity::Information)).map(|(_, place)| place)), (Some(None), None, Some(Some(0))));
}

// "The direction of a provider text is taken from the first character in it that has a strong direction. A text with none, such as one of digits only, is left to right."
#[test]
fn the_direction_of_a_text_is_that_of_its_first_strong_character() {
	use Direction::{LeftToRight, RightToLeft};
	for (text, want) in [
		("Frankfurt", LeftToRight), ("فرانکفورت", RightToLeft), ("שלום", RightToLeft), ("ܫܠܡܐ", RightToLeft), ("ދިވެހި", RightToLeft), ("\u{7ca}\u{7cb}", RightToLeft), ("\u{1e900}\u{1e901}", RightToLeft), ("法蘭克福", LeftToRight), ("हिन्दी", LeftToRight), ("ශ්\u{200d}රී ලංකා", LeftToRight),
		// No strong character: digits of either kind, spaces, punctuation, symbols and marks alone.
		("", LeftToRight), ("12345", LeftToRight), ("۱۲۳", LeftToRight), ("١٢٣", LeftToRight), (" .,:;!?()[]-+*/%", LeftToRight), ("\u{1f600} \u{2192}", LeftToRight), ("\u{301}\u{64e}", LeftToRight),
		// The first strong character decides, whatever stands before it and whatever follows.
		("123 فارسی", RightToLeft), ("(۱) فارسی English", RightToLeft), ("\u{1f600} فارسی", RightToLeft), ("VPN فارسی", LeftToRight), ("فارسی VPN", RightToLeft), ("100% English فارسی", LeftToRight), ("\u{64e}a", LeftToRight), ("-\u{5d0}a", RightToLeft),
	] {assert_eq!(direction(text), want, "{text:?}")}
	// The tag of a text says nothing about its direction: Persian written in Latin letters under `fa` is left to right, and Persian letters under `en` are right to left.
	let text = said(r#"{"default":"Tehran","fa":"Tehran","en":"تهران"}"#).unwrap();
	assert_eq!((direction(text.pick(&tags(&["fa-Arab-IR"])).0), direction(text.pick(&tags(&["en-Latn-US"])).0), direction(text.as_str())), (LeftToRight, RightToLeft, LeftToRight));
}

#[test]
fn an_address_inside_the_devices_own_networks_is_not_dialled() {
	let network = |address: &str, prefix: u8| Network::new(address.parse().unwrap(), prefix).unwrap();
	let networks = [network("192.168.1.23", 24), network("192.168.1.1", 32), network("2001:db8:1::5", 64), network("10.7.0.200", 16)];
	for (address, inside) in [("192.168.1.1:443", true), ("192.168.1.255:443", true), ("192.168.2.1:443", false), ("192.0.2.10:443", false), ("[2001:db8:1::99]:443", true), ("[2001:db8:1:0:ffff::1]:443", true), ("[2001:db8:2::99]:443", false), ("10.7.255.255:1", true), ("10.8.0.0:1", false)] {assert_eq!(Dial::parse(address).unwrap().own(&networks), inside, "{address}")}
	assert!(!Dial::parse("192.168.1.1:443").unwrap().own(&[]) && Dial::parse("192.0.2.1:1").unwrap().own(&[network("0.0.0.0", 0)]) && !Dial::parse("192.0.2.1:1").unwrap().own(&[network("::", 0)]) && own("2001:db8::1".parse().unwrap(), &[network("::", 0)]));
	assert_eq!((Network::new("192.0.2.1".parse().unwrap(), 33), Network::new("2001:db8::1".parse().unwrap(), 129).is_none(), network("192.0.2.1", 32).contains("192.0.2.1".parse().unwrap()), network("192.0.2.1", 32).contains("192.0.2.0".parse().unwrap())), (None, true, true, false));
	// "Asked about once per profile: any other private or shared address", by the list of `geoip:private` in the config reference.
	for (address, private) in [("10.0.0.1:1", true), ("172.16.0.1:1", true), ("172.31.255.255:1", true), ("172.32.0.1:1", false), ("192.168.0.1:1", true), ("100.64.0.1:1", true), ("100.127.255.255:1", true), ("100.128.0.1:1", false), ("192.0.0.1:1", true), ("192.0.1.1:1", false), ("192.0.2.1:1", true), ("192.88.99.1:1", true), ("198.18.0.1:1", true), ("198.19.255.255:1", true), ("198.20.0.1:1", false), ("198.51.100.1:1", true), ("203.0.113.1:1", true), ("240.0.0.1:1", true), ("255.255.255.254:1", true), ("239.255.255.255:1", false), ("1.1.1.1:53", false), ("[fc00::1]:1", true), ("[fdff::1]:1", true), ("[fe00::1]:1", false), ("[2001:db8::1]:1", true), ("[2001:db9::1]:1", false), ("[2606:4700:4700::1111]:53", false)] {assert_eq!(Dial::parse(address).map(|dial| dial.private()), (address != "239.255.255.255:1").then_some(private), "{address}")}
	// An IPv6 address that carries an IPv4 address is refused whole, whatever the address inside: IPv4-compatible, IPv4-mapped and IPv4-translated, NAT64 in both of its ranges, 6to4 and Teredo. So is the site-local range, and a zone or an address in another spelling is no address.
	for address in ["[::127.0.0.1]:443", "[::7f00:1]:443", "[::2]:443", "[::1.1.1.1]:443", "[::ffff:1.1.1.1]:53", "[0:0:0:0:0:ffff:7f00:1]:1", "[::ffff:0:7f00:1]:443", "[64:ff9b::7f00:1]:443", "[64:ff9b::c0a8:101]:443", "[64:ff9b::101:101]:443", "[64:ff9b:1::c0a8:101]:443", "[2002:7f00:1::1]:443", "[2002:c0a8:101::1]:443", "[2002:101:101::1]:443", "[2001:0:7f00:1::1]:443", "[2001:0:101:101::fefe:fefe]:443", "[fec0::1]:443", "[feff::1]:443", "127.1:80", "0x7f.0.0.1:80", "2130706433:80", "[::1%lo]:80", "\u{ff11}.1.1.1:80"] {
		assert!(Dial::parse(address).is_none(), "{address}");
	}
	// The same check for an address a legacy name resolved to.
	assert!(dialable("192.0.2.1".parse().unwrap()) && dialable("2001:db8::1".parse().unwrap()) && !dialable("127.0.0.1".parse().unwrap()) && !dialable("64:ff9b::a00:1".parse().unwrap()) && !dialable("::1".parse().unwrap()) && !dialable("169.254.169.254".parse().unwrap()));
	for address in ["[64:ff9c::1]:443", "[2001:1::1]:443", "[2003::1]:443", "[100::1]:443", "[fe7f::1]:443"] {assert!(Dial::parse(address).is_some(), "{address}")}
	// A `Dial` says its family and nothing else.
	assert_eq!((format!("{:?}", Dial::parse("192.0.2.10:443").unwrap()), format!("{:?}", Dial::parse("[2001:db8::10]:443").unwrap())), ("Dial(IPv4)".to_owned(), "Dial(IPv6)".to_owned()));
	// The tunnel side: the profile of the vectors has the device at 10.7.0.2 and the gateway at 10.7.0.1.
	let document = subscription(&rich());
	assert!(document.profiles[0].clashes(&networks) && !document.profiles[0].clashes(&networks[..3]) && document.profiles[0].clashes(&[network("fd00::", 8)]));
}

#[test]
fn the_request_byte_for_byte_and_what_an_endpoint_refuses() {
	let Offer::Native(offer) = Offer::open(Link::parse(&text("fuzz_deeplink/native-https")).unwrap()) else {panic!("a native link")};
	assert_eq!((offer.endpoint().host(), offer.fingerprint().to_string()), ("sub.example.com", "10ba 682c 8ad1 3513 971e 8b56 881a ab8b".to_owned()));
	let fetching = offer.proceed(None, &mut fixed).unwrap();
	assert_eq!((fetching.request().body(), fetching.endpoint().as_str()), (seed("fuzz_sub_request/fetch"), "https://sub.example.com/s"));
	let review = fetching.answer(&seed("fuzz_sub_envelope/document")[1..], NOW, &[]).unwrap();
	assert_eq!((review.fingerprint(), review.replaces(), review.origin(), review.refreshes(), review.subscription().provider.as_str()), (key(0x11).fingerprint(), false, KeyOrigin::Device, true, "Example Provider"));
	let Accepted {held, replaces, confirm} = review.accept(DeviceName::typed("phone\u{200b}"), &[]).unwrap();
	assert_eq!((confirm.unwrap().body(), replaces, held.fetch().unwrap().body(), held.rename(None).unwrap().op().clone()), (seed("fuzz_sub_request/confirm"), None, seed("fuzz_sub_request/fetch"), Op::Confirm(None)));
	// Declining, and giving up before an answer: the same `release`.
	assert_eq!((self::review(&seed("fuzz_sub_envelope/document")[1..], &[]).unwrap().decline().unwrap().body(), fetching.abandon().body()), (seed("fuzz_sub_request/release"), seed("fuzz_sub_request/release")));
	// The endpoint's side reads what a client writes, as another type than the one a client sends, and knows the one body it has.
	for name in ["fetch", "confirm", "release"] {
		let request = Received::read(&seed(&format!("fuzz_sub_request/{name}"))).unwrap();
		assert_eq!((request.canonical(), request.token().expose(), request.kids(), request.device_secret().expose(), request.device_public_key()), (seed(&format!("fuzz_sub_request/{name}")), &[0x55; 16], &[key(0x11).kid()][..], &[0x44; 16], &veilway_proto::proof::public_key(&[0x33; 32])), "{name}");
		assert!(!format!("{request:?}").contains("VVVV") && !format!("{request:?}").contains("RERE"));
	}
	// A body in another spelling reads, and is not the body a client writes.
	let spaced = text("fuzz_sub_request/fetch").replace(",", " ,\n");
	assert!(Received::read(spaced.as_bytes()).is_ok_and(|request| request.canonical() == seed("fuzz_sub_request/fetch") && request.canonical() != spaced.as_bytes()));
	assert_eq!((Received::read(&seed("fuzz_sub_request/confirm")).unwrap().op().clone(),DeviceName::typed("\u{200b}\u{7}"), DeviceName::typed(&"n".repeat(40)).map(|name| name.as_str().len())), (Op::Confirm(DeviceName::typed("phone")), None, Some(32)));
	let fetch: Value = serde_json::from_slice(&seed("fuzz_sub_request/fetch")).unwrap();
	let read = |request: &Value| Received::read(request.to_string().as_bytes()).map(|request| request.op().clone());
	let malformed = Err(RequestError::Malformed(Secret::new([0x55; 16])));
	// A member that is missing, of another type or not in its one form, an unknown member, a name without `confirm` or one of which nothing is left, and a device key that is zero or of small order.
	for (pointer, value) in [("/v", None), ("/v", Some(json!(2))), ("/v", Some(json!("1"))), ("/kids", None), ("/kids", Some(json!([]))), ("/kids", Some(json!(["ELpoLIrRNRM", "ELpoLIrRNRM"]))), ("/kids", Some(json!(["ELpoLIrRNRM", "AAAAAAAAAAA", "AAAAAAAAAAB"]))), ("/kids", Some(json!(["ELpoLIrRNRN"]))), ("/kids", Some(json!("ELpoLIrRNRM"))), ("/device_public_key", None), ("/device_public_key", Some(json!(std_base64(&[0; 32])))), ("/device_public_key", Some(json!(std_base64(&unhex("0100000000000000000000000000000000000000000000000000000000000000"))))), ("/device_public_key", Some(json!(std_base64(&unhex("0100000000000000000000000000000000000000000000000000000000000080"))))), ("/device_public_key", Some(json!(std_base64(&unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))))), ("/device_public_key", Some(json!(std_base64(&unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"))))), ("/device_public_key", Some(json!(std_base64(&[7; 31])))), ("/device_secret", None), ("/device_secret", Some(json!("RERERERERERERERERERERB"))), ("/device_secret", Some(json!("RERERERERERERERERERERA=="))), ("/op", None), ("/op", Some(json!("remove"))), ("/op", Some(json!("Fetch"))), ("/device_name", Some(json!("phone"))), ("/later", Some(json!(1)))] {
		let mut request = fetch.clone();
		put(&mut request, pointer, value.clone());
		assert_eq!(read(&request), malformed, "{pointer} = {value:?}");
	}
	assert_eq!((read(&with(fetch.clone(), &[("/op", json!("confirm")), ("/device_name", json!("\u{200b}"))])), read(&with(fetch.clone(), &[("/op", json!("confirm")), ("/device_name", json!(5))])), read(&with(fetch.clone(), &[("/op", json!("release")), ("/device_name", json!("x"))]))), (malformed.clone(), malformed.clone(), malformed.clone()));
	assert_eq!((read(&with(fetch.clone(), &[("/kids", json!(["ELpoLIrRNRM", "AAAAAAAAAAA"]))])), read(&with(fetch.clone(), &[("/op", json!("confirm")), ("/device_name", json!("a\u{202e}b"))]))), (Ok(Op::Fetch), Ok(Op::Confirm(DeviceName::typed("ab")))));
	// Without a token that reads there is nothing to answer to.
	for (pointer, value) in [("/token", None), ("/token", Some(json!("VVVVVVVVVVVVVVVVVVVVVR"))), ("/token", Some(json!("VVVVVVVVVVVVVVVVVVVVV"))), ("/token", Some(json!(5)))] {
		let mut request = fetch.clone();
		put(&mut request, pointer, value);
		assert_eq!(read(&request), Err(RequestError::Unreadable), "{pointer}");
	}
	for body in [&b""[..], b"[]", b"null", b"{\"token\":\"VVVVVVVVVVVVVVVVVVVVVQ\",\"token\":\"VVVVVVVVVVVVVVVVVVVVVQ\"}", &[b' '; 2_000], format!("{{\"v\":1,\"token\":\"VVVVVVVVVVVVVVVVVVVVVQ\",\"x\":\"{}\"}}", "a".repeat(990)).as_bytes(), b"{\"Token\":\"VVVVVVVVVVVVVVVVVVVVVQ\"}"] {assert_eq!(Received::read(body).err(), Some(RequestError::Unreadable))}
	assert_eq!(Received::read(b"{\"v\":1,\"token\":\"VVVVVVVVVVVVVVVVVVVVVQ\"}").err(), Some(RequestError::Malformed(Secret::new([0x55; 16]))));
	assert!(!format!("{malformed:?}").contains("85"));
}

#[test]
fn a_refresh_is_taken_only_when_every_check_passes() {
	let mut held = held();
	let before = held.clone();
	assert_eq!((held.id().as_str(), held.keys(), held.subscription().serial, held.device().unwrap().public(), held.endpoints().iter().map(|url| url.as_str()).collect::<Vec<_>>()), ("example-account-0001", &[key(0x11)][..], 1, &veilway_proto::proof::public_key(&[0x33; 32]), vec!["https://sub.example.com/s"]));
	let failures = [
		// "An equal serial is accepted only when the body is byte for byte the same", "a lower one is refused".
		(issue(0x11, &[("/provider/name", json!("Another Name"))]), Failure::Fork),
		(issue(0x11, &[("/serial", json!(1)), ("/issued_at", json!(ISSUED + 50))]), Failure::Fork),
		(issue(0x11, &[("/serial", json!(2)), ("/subscription_id", json!("example-account-0002"))]), Failure::OtherSubscription),
		(issue(0x99, &[("/serial", json!(2))]), Failure::Envelope(EnvelopeError::UnknownKey)),
		(issue(0x22, &[("/serial", json!(2))]), Failure::Envelope(EnvelopeError::UnknownKey)),
		(issue(0x11, &[("/serial", json!(2)), ("/signing_keys", json!([std_base64(key(0x22).bytes())]))]), Failure::Payload(PayloadError::Signer)),
		(issue(0x11, &[("/serial", json!(2)), ("/v", json!(2))]), Failure::Payload(PayloadError::Version)),
		(issue(0x11, &[("/serial", json!(2)), ("/critical", json!(["later"]))]), Failure::Payload(PayloadError::Critical)),
		// The clock: "more than the clock tolerance ahead", and "already expired".
		(issue(0x11, &[("/serial", json!(2)), ("/issued_at", json!(NOW + 301)), ("/expires_at", json!(NOW + 1_000))]), Failure::Future),
		(issue(0x11, &[("/serial", json!(2)), ("/issued_at", json!(NOW - 50)), ("/expires_at", json!(NOW))]), Failure::Expired),
		// "No silent change": another device key, a private key where there was none, and a new profile that brings one.
		(issue(0x11, &[("/serial", json!(2)), ("/profiles/0/device/public_key", json!(std_base64(&veilway_proto::proof::public_key(&[0x34; 32]))))]), Failure::DeviceKey),
		(issue(0x11, &[("/serial", json!(2)), ("/profiles/0/device/public_key", json!(std_base64(&veilway_proto::proof::public_key(&[0x34; 32])))), ("/profiles/0/device/private_key", json!(std_base64(&[0x34; 32])))]), Failure::DeviceKey),
		(issue(0x11, &[("/serial", json!(2)), ("/profiles/0/device/private_key", json!(std_base64(&[0x33; 32])))]), Failure::PrivateKey),
		(issue(0x11, &[("/serial", json!(2)), ("/profiles/1", with(payload("import")["profiles"][0].clone(), &[("/id", json!("second")), ("/device/public_key", json!(std_base64(&veilway_proto::proof::public_key(&[0x34; 32])))), ("/device/private_key", json!(std_base64(&[0x34; 32])))]))]), Failure::PrivateKey),
		// A refusal: recent and this subscription's, too old, from the future, and another account's.
		(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW - 86_400, "refusal": "rate_limited"})), Failure::Refused(Reason::RateLimited)),
		(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW + 300, "refusal": "key_retired"})), Failure::Refused(Reason::KeyRetired)),
		(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW - 86_401, "refusal": "disabled"})), Failure::StaleRefusal),
		(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW + 301, "refusal": "disabled"})), Failure::StaleRefusal),
		(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0002", "issued_at": NOW, "refusal": "disabled"})), Failure::OtherSubscription),
		(sign(0x99, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW, "refusal": "disabled"})), Failure::Envelope(EnvelopeError::UnknownKey)),
		(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW, "refusal": "later"})), Failure::Payload(PayloadError::Refusal)),
		// "When the answer is not a subscription at all", a legacy list among it.
		(String::from_utf8(seed("fuzz_links/plain")[1..].to_vec()).unwrap(), Failure::Envelope(EnvelopeError::Parts)),
		("<html>not found</html>".to_owned(), Failure::Envelope(EnvelopeError::Parts)),
		(String::new(), Failure::Envelope(EnvelopeError::Parts)),
		("a.b.c".to_owned(), Failure::Envelope(EnvelopeError::Encoding)),
		(text("fuzz_sub_envelope/high-s")[1..].to_owned(), Failure::Envelope(EnvelopeError::Signature)),
	];
	for (document, failure) in &failures {
		assert_eq!(held.refresh(document.as_bytes(), NOW), Err(*failure), "{failure:?}");
		assert_eq!(held, before, "{failure:?} changed what is held");
	}
	// The same document again changes nothing, and neither does it once it has expired.
	assert_eq!((held.refresh(&seed("fuzz_sub_envelope/document")[1..], NOW), held.refresh(&seed("fuzz_sub_envelope/document")[1..], ISSUED + 30 * 86_400)), (Ok(Refreshed::Unchanged), Err(Failure::Expired)));
	assert_eq!(held, before);
	// A higher serial is taken: with a profile left out, one refused, a longer device list and a host the user has not seen.
	let newer = issue(0x11, &[("/serial", json!(7)), ("/profiles/0/id", json!("renamed")), ("/profiles/1", with(payload("import")["profiles"][0].clone(), &[("/device", before_device()), ("/type", json!("later"))])), ("/devices/1", json!({"name": "tablet", "enrolled_at": NOW, "this": false, "pending": true})), ("/refresh_urls", json!(["https://mirror.example.net/s", "https://sub.example.com/other", "https://mirror.example.net/t"]))]);
	let Ok(Refreshed::Updated(changes)) = held.refresh(newer.as_bytes(), NOW) else {panic!("a newer document")};
	assert_eq!((changes.rotated, changes.hosts.clone(), changes.dropped.clone(), changes.devices_grew, held.subscription().serial, held.document()), (false, vec!["mirror.example.net:443".to_owned()], vec![("main".to_owned(), Some(Fault::Unsupported))], true, 7, newer.as_str()));
	// "A host that a later document adds is not contacted until the user has confirmed it." A URL on the host and port of the link needs no question.
	assert_eq!((held.endpoints().iter().map(|url| url.as_str()).collect::<Vec<_>>(), held.unconfirmed()), (vec!["https://sub.example.com/s", "https://sub.example.com/other"], vec!["mirror.example.net:443".to_owned()]));
	held.confirm_hosts(&["elsewhere.example.org:443", "mirror.example.net", "mirror.example.net:8443"]);
	assert_eq!(held.unconfirmed(), ["mirror.example.net:443"]);
	held.confirm_hosts(&["mirror.example.net:443"]);
	assert_eq!((held.endpoints().len(), held.unconfirmed().len()), (4, 0));
	// What is confirmed is a host with its port, and only while documents list it: the same name on another port waits for the user, the link's own host on another port does, and a host a document dropped is asked about again when a later one lists it.
	let Ok(Refreshed::Updated(changes)) = held.refresh(issue(0x11, &[("/serial", json!(8)), ("/refresh_urls", json!(["https://mirror.example.net:8443/s", "https://sub.example.com:8443/s", "https://mirror.example.net/s"]))]).as_bytes(), NOW) else {panic!("a newer document")};
	assert_eq!((changes.hosts, held.endpoints().iter().map(|url| url.as_str()).collect::<Vec<_>>()), (vec!["mirror.example.net:8443".to_owned(), "sub.example.com:8443".to_owned()], vec!["https://sub.example.com/s", "https://mirror.example.net/s"]));
	assert!(matches!(held.refresh(issue(0x11, &[("/serial", json!(9)), ("/refresh_urls", json!([]))]).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if changes.hosts.is_empty()));
	let Ok(Refreshed::Updated(changes)) = held.refresh(issue(0x11, &[("/serial", json!(10)), ("/refresh_urls", json!(["https://mirror.example.net/elsewhere?x=1"]))]).as_bytes(), NOW) else {panic!("a newer document")};
	assert_eq!((changes.hosts, held.endpoints().len(), held.stored().hosts.len()), (vec!["mirror.example.net:443".to_owned()], 1, 0));
	// The device list: the same devices are no growth, and another device in the place of one is, though the list is no longer.
	let devices = |serial: u64, list: Value| issue(0x11, &[("/serial", json!(serial)), ("/devices", list)]);
	assert!(matches!(held.refresh(devices(11, json!([{"name": "phone", "enrolled_at": ISSUED, "this": true, "pending": true}])).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if !changes.devices_grew));
	assert!(matches!(held.refresh(devices(12, json!([{"name": "someone else", "enrolled_at": ISSUED + 50, "this": false}])).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if changes.devices_grew));
	assert!(matches!(held.refresh(devices(13, json!([])).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if !changes.devices_grew));
	// "On a refresh `issued_at` must not be lower than the stored document's": a higher serial that went back in time is refused, so no older document gets in behind it through a fresh import.
	let stored = held.clone();
	assert_eq!((held.refresh(issue(0x11, &[("/serial", json!(20)), ("/issued_at", json!(ISSUED - 1_000)), ("/expires_at", json!(ISSUED + 86_400))]).as_bytes(), NOW), held == stored), (Err(Failure::Backdated), true));
	assert_eq!(review(issue(0x11, &[("/serial", json!(2)), ("/issued_at", json!(ISSUED - 500)), ("/expires_at", json!(ISSUED + 86_400))]).as_bytes(), &[&held]).err(), Some(Failure::NotNewer));
	// What was the last good document is a rollback now.
	assert_eq!((held.refresh(&seed("fuzz_sub_envelope/document")[1..], NOW), held.refresh(issue(0x11, &[("/serial", json!(6))]).as_bytes(), NOW)), (Err(Failure::Rollback), Err(Failure::Rollback)));
	fn before_device() -> Value {first()["profiles"][0]["device"].clone()}
}

#[test]
fn a_key_is_rotated_by_a_document_the_old_key_signed() {
	let mut held = held();
	// "A provider that wants a new key first lists both, signed with the old one, and later signs with the new one and lists only that."
	assert_eq!(held.refresh(issue(0x22, &[("/serial", json!(2)), ("/signing_keys", json!([std_base64(key(0x22).bytes())]))]).as_bytes(), NOW), Err(Failure::Envelope(EnvelopeError::UnknownKey)));
	assert!(matches!(held.refresh(&seed("fuzz_sub_envelope/two-keys")[1..], NOW), Ok(Refreshed::Updated(changes)) if changes.rotated));
	assert_eq!((held.keys(), held.fetch().unwrap().kids()), (&[key(0x11), key(0x22)][..], &[key(0x11).kid(), key(0x22).kid()][..]));
	// Both keys are held, and a document under either is taken. One that lists the same keys is no rotation.
	assert!(matches!(held.refresh(issue(0x22, &[("/serial", json!(3)), ("/signing_keys", json!([std_base64(key(0x11).bytes()), std_base64(key(0x22).bytes())]))]).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if !changes.rotated));
	assert!(matches!(held.refresh(issue(0x22, &[("/serial", json!(4)), ("/signing_keys", json!([std_base64(key(0x22).bytes())]))]).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if changes.rotated));
	assert_eq!(held.keys(), [key(0x22)]);
	// The old key is not held any more: what it signs is "a failed refresh and nothing more", also when it lists itself again.
	let before = held.clone();
	for document in [issue(0x11, &[("/serial", json!(9))]), issue(0x11, &[("/serial", json!(9)), ("/signing_keys", json!([std_base64(key(0x11).bytes()), std_base64(key(0x22).bytes())]))])] {assert_eq!((held.refresh(document.as_bytes(), NOW), &held), (Err(Failure::Envelope(EnvelopeError::UnknownKey)), &before))}
	// A client that was offline through the whole rotation holds only the old key, and gets the refusal the retired key signed.
	let mut late = self::held();
	assert_eq!(late.refresh(sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW, "refusal": "key_retired"})).as_bytes(), NOW), Err(Failure::Refused(Reason::KeyRetired)));
	assert_eq!(late.refresh(issue(0x22, &[("/serial", json!(4)), ("/signing_keys", json!([std_base64(key(0x22).bytes())]))]).as_bytes(), NOW), Err(Failure::Envelope(EnvelopeError::UnknownKey)));
}

#[test]
fn an_import_goes_through_its_three_steps() {
	// A first import is judged by the clock and by the device's key, with nothing stored to compare with.
	for (document, failure) in [
		(issue(0x11, &[("/issued_at", json!(NOW + 301)), ("/expires_at", json!(NOW + 1_000))]), Failure::Future),
		(issue(0x11, &[("/issued_at", json!(NOW - 50)), ("/expires_at", json!(NOW - 1))]), Failure::Expired),
		(issue(0x11, &[("/profiles/0/device/public_key", json!(std_base64(&veilway_proto::proof::public_key(&[0x34; 32]))))]), Failure::DeviceKey),
		(issue(0x22, &[("/signing_keys", json!([std_base64(key(0x22).bytes())]))]), Failure::Envelope(EnvelopeError::UnknownKey)),
		(text("fuzz_sub_envelope/refusal")[1..].to_owned(), Failure::Refused(Reason::DeviceLimit)),
		(sign(0x11, &json!({"v": 1, "subscription_id": "any-other-account-01", "issued_at": NOW - 90_000, "refusal": "disabled"})), Failure::StaleRefusal),
		(text("fuzz_links/plain")[1..].to_owned(), Failure::Envelope(EnvelopeError::Parts)),
	] {assert_eq!(review(document.as_bytes(), &[]).err(), Some(failure), "{failure:?}")}
	// A document that lists a second key is signed by the key of the link, so a first import takes it.
	assert!(review(&seed("fuzz_sub_envelope/two-keys")[1..], &[]).is_ok());
	// A provider-issued key is taken on a first import, and said: "key issued by the provider".
	let issued = review(issue(0x11, &[("/profiles/0/device/public_key", json!(std_base64(&veilway_proto::proof::public_key(&[0x34; 32])))), ("/profiles/0/device/private_key", json!(std_base64(&[0x34; 32])))]).as_bytes(), &[]).unwrap();
	assert_eq!(issued.origin(), KeyOrigin::Provider);
	// "A fresh import by the user of a link for a subscription that is already stored": later issued and any serial replaces it, the same document replaces it, anything else does not. Under another key or id it is a second subscription.
	let (stored, other) = (held(), review(issue(0x11, &[("/subscription_id", json!("example-account-0002"))]).as_bytes(), &[]).unwrap().accept(None, &[]).unwrap().held);
	let (mut rotated, both) = (held(), [&other, &stored]);
	rotated.refresh(&seed("fuzz_sub_envelope/two-keys")[1..], NOW).unwrap();
	rotated.refresh(issue(0x22, &[("/serial", json!(4)), ("/signing_keys", json!([std_base64(key(0x22).bytes())]))]).as_bytes(), NOW).unwrap();
	assert_eq!(review(issue(0x11, &[("/serial", json!(1)), ("/issued_at", json!(ISSUED + 1))]).as_bytes(), &both).map(|review| review.replaces()), Ok(true));
	assert_eq!(review(issue(0x11, &[("/serial", json!(9))]).as_bytes(), &both).err(), Some(Failure::NotNewer));
	assert_eq!(review(issue(0x11, &[("/serial", json!(9)), ("/issued_at", json!(ISSUED - 1))]).as_bytes(), &both).err(), Some(Failure::NotNewer));
	assert_eq!(review(&seed("fuzz_sub_envelope/document")[1..], &both).map(|review| review.replaces()), Ok(true));
	assert_eq!(review(issue(0x11, &[("/subscription_id", json!("example-account-0003"))]).as_bytes(), &both).map(|review| review.replaces()), Ok(false));
	// The stored subscription has moved to another key: the link's key is not one it holds, so this is another subscription beside it.
	assert_eq!(review(&seed("fuzz_sub_envelope/document")[1..], &[&rotated]).map(|review| review.replaces()), Ok(false));
	let replaced = review(issue(0x11, &[("/serial", json!(1)), ("/issued_at", json!(ISSUED + 1)), ("/refresh_urls", json!(["https://mirror.example.net/s"]))]).as_bytes(), &both).unwrap().accept(None, &both).unwrap();
	// What is replaced is named by its id and key, which only the one stored subscription answers to, wherever it is in the list. The hosts that were on the confirmation are confirmed with it.
	let Some(Replaced {id, key: under}) = &replaced.replaces else {panic!("an import over a stored subscription")};
	assert_eq!(([&other, &stored, &rotated].map(|held| held.is(id, under)), replaced.held.subscription().issued_at, replaced.held.endpoints().len(), replaced.held.unconfirmed().len()), ([false, true, false], ISSUED + 1, 2, 0));
	// The confirmation was on the screen while a refresh ran: the rule is asked again when the user accepts, against what is stored then. The import is declined with the request that frees its place, and nothing is rolled back.
	let (mut current, stale) = (held(), review(issue(0x11, &[("/serial", json!(2)), ("/issued_at", json!(ISSUED + 10))]).as_bytes(), &[&stored]).unwrap());
	current.refresh(issue(0x11, &[("/serial", json!(9)), ("/issued_at", json!(ISSUED + 50))]).as_bytes(), NOW).unwrap();
	let declined = stale.accept(None, &[&other, &current]).unwrap_err();
	assert_eq!((declined.failure, declined.release.map(|request| request.body())), (Failure::NotNewer, Some(seed("fuzz_sub_request/release"))));
	// With the stored subscription gone in the meantime, the same review adds a new one.
	assert!(review(issue(0x11, &[("/serial", json!(2)), ("/issued_at", json!(ISSUED + 10))]).as_bytes(), &[&stored]).unwrap().accept(None, &[&other]).is_ok_and(|accepted| accepted.replaces.is_none()));
	// A whole document: verified under the key it came with, no request at any step, and no refresh.
	let Offer::Carried(offer) = Offer::open(Link::parse(&text("fuzz_deeplink/document")).unwrap()) else {panic!("a document in a link")};
	assert_eq!((offer.fingerprint(), offer.in_file()), (key(0x11).fingerprint(), false));
	let review = offer.proceed(NOW, &[]).unwrap();
	assert_eq!((review.origin(), review.refreshes()), (KeyOrigin::Provider, false));
	let Accepted {held: whole, confirm, ..} = review.accept(None, &[]).unwrap();
	assert!(confirm.is_none() && whole.fetch().is_none() && whole.rename(None).is_none() && whole.device().is_none() && whole.endpoints().is_empty());
	// A whole document that lists refresh URLs has nowhere to send a token all the same: it names no endpoint, confirms no host and waits for none.
	let listing = carried(&sign(0x11, &payload("content")), &[]).unwrap().accept(None, &[]).unwrap().held;
	assert!(listing.subscription().refresh_urls.len() == 1 && listing.endpoints().is_empty() && listing.unconfirmed().is_empty() && listing.stored().hosts.is_empty() && listing.fetch().is_none());
	// A whole document may replace a whole document. It may not replace a subscription that has a link, which would lose its endpoint and leave its device place behind: at the review, and at the accept when the stored one came in between.
	let newer = sign(0x11, &with(payload("content"), &[("/issued_at", json!(ISSUED + 50)), ("/expires_at", json!(ISSUED + 86_400))]));
	assert_eq!(carried(&newer, &[&listing]).map(|review| review.replaces()), Ok(true));
	let linked = self::review(sign(0x11, &with(first(), &[("/subscription_id", json!(payload("content")["subscription_id"]))])).as_bytes(), &[]).unwrap().accept(None, &[]).unwrap().held;
	assert_eq!((linked.id() == listing.id(), carried(&newer, &[&linked]).err(), carried(&newer, &[]).unwrap().accept(None, &[&linked]).map_err(|declined| (declined.failure, declined.release.is_none())).err()), (true, Some(Failure::HasLink), Some((Failure::HasLink, true))));
	// A link may replace a whole document, and the subscription can refresh from then on.
	assert!(self::review(issue(0x11, &[("/issued_at", json!(ISSUED + 60))]).as_bytes(), &[&listing]).unwrap().accept(None, &[&listing]).is_ok_and(|accepted| accepted.replaces.is_some() && accepted.held.fetch().is_some()));
	let carry = |document: &str| {
		let Offer::Carried(offer) = Offer::open(Link::Carried(Carried::file(format!("v1.{}.{document}", &text("fuzz_deeplink/file")[3..46]).as_bytes()).unwrap())) else {panic!("a document in a file")};
		offer.proceed(NOW, &[]).map(|review| review.decline().is_none())
	};
	assert_eq!((carry(&text("fuzz_sub_envelope/carried")[1..]), carry(&text("fuzz_sub_envelope/document")[1..]), carry(&text("fuzz_sub_envelope/second-key")[1..]), carry("a.b.c")), (Ok(true), Err(Failure::DeviceKey), Err(Failure::Envelope(EnvelopeError::UnknownKey)), Err(Failure::Envelope(EnvelopeError::Encoding))));
	// In a link a document is held to the limit of a link, in a file to that of a body.
	let padded = sign(0x11, &with(payload("import"), &[("/later", json!("x".repeat(2_000)))]));
	assert!(padded.len() > CARRIED_MAX && carry(&padded) == Ok(true) && Link::parse(&format!("veilway://doc#v1.{}.{padded}", &text("fuzz_deeplink/file")[3..46])) == Err(LinkError::Size));
}

#[test]
fn a_legacy_link_stays_a_legacy_link() {
	let Offer::Legacy(offer) = Offer::open(Link::parse(&text("fuzz_deeplink/legacy")).unwrap()) else {panic!("a legacy link")};
	assert_eq!(offer.url().as_str(), "https://sub.example.com/list?token=abc");
	let fetching = offer.proceed();
	// "If it is answered with a signed document, the app says ... and imports nothing from that answer."
	for name in ["document", "refusal", "carried", "key-not-held"] {assert_eq!(fetching.answer(&seed(&format!("fuzz_sub_envelope/{name}"))[1..], &[]).err(), Some(LegacyError::Native), "{name}")}
	assert_eq!(legacy::list(&seed("fuzz_links/native")[1..]).err(), Some(LegacyError::Native));
	let (list, headers) = fetching.answer(&seed("fuzz_links/plain")[1..], &[("Profile-Title", b"Example"), ("PROFILE-UPDATE-INTERVAL", b"12")]).unwrap();
	assert_eq!((list.entries.len(), list.skipped, list.cut, headers.title.unwrap().as_str().to_owned(), headers.update_interval, fetching.url().host()), (4, 1, false, "Example".to_owned(), Some(43_200), "sub.example.com"));
	let entry = &list.entries[0];
	assert_eq!((entry.scheme, entry.name.as_str(), &entry.server, entry.port, entry.tls, entry.insecure, entry.sni.as_deref(), entry.network.as_deref(), entry.path.as_deref(), entry.cap()), (Scheme::Vless, "One", &Server::Name("node.example.com".to_owned()), 443, Tls::Tls, false, Some("node.example.com"), Some("ws"), Some("/ws"), Cap::Detectable));
	assert_eq!(list.entries.iter().map(|entry| (entry.scheme, entry.cap(), entry.cipher.as_deref())).collect::<Vec<_>>(), [(Scheme::Vless, Cap::Detectable, None), (Scheme::Trojan, Cap::Detectable, None), (Scheme::Shadowsocks, Cap::Detectable, Some("aes-256-gcm")), (Scheme::Vmess, Cap::Detectable, Some("auto"))]);
	assert_eq!((&list.entries[1].server, format!("{:?}", list.entries[1].credential), list.entries[1].credential.expose()), (&Server::Address("192.0.2.10".parse().unwrap()), "Credential(..)".to_owned(), "password"));
	// The same list in base64, where each entry is capped at Unsafe: certificate checking switched off, and a weak cipher.
	let packed = legacy::list(&seed("fuzz_links/packed")[1..]).unwrap();
	assert_eq!(packed.entries.iter().map(|entry| (entry.scheme, entry.insecure, entry.cipher.as_deref(), entry.cap())).collect::<Vec<_>>(), [(Scheme::Trojan, true, None, Cap::Unsafe), (Scheme::Shadowsocks, false, Some("rc4-md5"), Cap::Unsafe)]);
}

#[test]
fn what_a_legacy_list_is_held_to() {
	let caps = |body: &str| legacy::list(body.as_bytes()).map(|list| (list.entries.iter().map(|entry| entry.cap()).collect::<Vec<_>>(), list.skipped));
	let vmess = |fields: Value| format!("vmess://{}", std_base64(fields.to_string().as_bytes()));
	// "Unsafe when there is no encryption, when certificate checking is switched off, or when the cipher is one the core lists as weak."
	for (link, cap) in [
		("vless://id@node.example.com:443".to_owned(), Cap::Unsafe),
		("vless://id@node.example.com:443?security=none".to_owned(), Cap::Unsafe),
		("vless://id@node.example.com:443?security=tls".to_owned(), Cap::Detectable),
		("vless://id@node.example.com:443?security=reality".to_owned(), Cap::Detectable),
		("vless://id@node.example.com:443?security=tls&allowInsecure=1".to_owned(), Cap::Unsafe),
		("vless://id@node.example.com:443?security=tls&insecure=true".to_owned(), Cap::Unsafe),
		("vless://id@[2001:db8::1]:443?security=tls#name".to_owned(), Cap::Detectable),
		("trojan://pass@node.example.com:443".to_owned(), Cap::Detectable),
		("trojan://pass@node.example.com:443?security=none".to_owned(), Cap::Unsafe),
		("trojan://pass@node.example.com:443?allowInsecure=true".to_owned(), Cap::Unsafe),
		("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@node.example.com:8388".to_owned(), Cap::Detectable),
		("ss://2022-blake3-aes-256-gcm:pass%40word@node.example.com:8388/?plugin=x#n".to_owned(), Cap::Detectable),
		(format!("ss://{}@node.example.com:8388", std_base64(b"aes-256-cfb:pass")), Cap::Unsafe),
		(format!("ss://{}", std_base64(b"none:pass@node.example.com:8388")), Cap::Unsafe),
		(format!("ss://{}", std_base64(b"new-cipher:pass@node.example.com:8388")), Cap::Unsafe),
		(vmess(json!({"add": "node.example.com", "port": 443, "id": "id"})), Cap::Detectable),
		(vmess(json!({"add": "192.0.2.10", "port": "443", "id": "id", "scy": "none", "tls": "tls"})), Cap::Unsafe),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "scy": "zero"})), Cap::Unsafe),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "scy": "aes-128-cfb"})), Cap::Unsafe),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "tls": "tls", "allowInsecure": true})), Cap::Unsafe),
	] {assert_eq!(caps(&link), Ok((vec![cap], 0)), "{link}")}
	// "A link that does not parse is skipped", and so is a line of another scheme. A body with no link at all is no list.
	for link in ["vless://node.example.com:443", "vless://id@node.example.com", "vless://id@node.example.com:0", "vless://id@node.example.com:70000", "vless://id@:443", "vless://id@node_example.com:443", "vless://id@node.example.com:443?security=later", "vless://@node.example.com:443", "vless://id@node.example.com:443#%ff", "trojan://pa%ss@node.example.com:443", "ss://node.example.com:8388", "ss://!!!@node.example.com:8388", "ss://bm9jb2xvbg@node.example.com:8388", "vmess://!!!", "vmess://e30", &vmess(json!({"add": "node.example.com", "port": "443"})), &vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "tls": "later"})), &vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "scy": "A B"})), &vmess(json!([1])), "hysteria2://pass@node.example.com:443", "wireguard://key@node.example.com:51820", "https://example.com/", "veilway://sub/sub.example.com/s#v1.x.y", "://", &format!("trojan://pass@node.example.com:443#{}", "n".repeat(4_096))] {assert_eq!(caps(link), Ok((vec![], 1)), "{link}")}
	for body in ["", "   \n", "just text", "!!!!", "bm8gbGlua3MgaGVyZQ==", "\u{feff}"] {assert_eq!(legacy::list(body.as_bytes()).err(), Some(LegacyError::Unreadable), "{body}")}
	assert_eq!((legacy::list(&[0xff, 0xfe]).err(), legacy::list(&vec![b'a'; BODY_MAX + 1]).err()), (Some(LegacyError::Unreadable), Some(LegacyError::Size)));
	// A field that is not on the list is dropped, and one that is on it is kept only in its checked form. The name is display text.
	let list = legacy::list("vless://id@Node.Example.com:443?security=tls&type=WS&sni=bad_name&host=a.example.com&path=no-slash&flow=xtls&fp=chrome&extra=%3Cscript%3E#%E2%80%AEname%07\r\n".as_bytes()).unwrap();
	let entry = &list.entries[0];
	assert_eq!((&entry.server, entry.network.as_deref(), entry.sni.as_deref(), entry.host.as_deref(), entry.path.as_deref(), entry.name.as_str()), (&Server::Name("node.example.com".to_owned()), Some("ws"), None, Some("a.example.com"), None, "name"));
	assert!(!format!("{entry:?}").contains("script") && !format!("{entry:?}").contains("xtls"));
	// An unsigned list is held to no less than a signed profile: an entry may not dial what a profile may not, in any spelling, nor a name that can only be the device itself. A private address is taken, and the caller asks about it as for a profile.
	for server in ["127.0.0.1:8080", "[::1]:443", "[::ffff:127.0.0.1]:443", "[fe80::1]:443", "[fec0::1]:443", "0.0.0.0:443", "169.254.169.254:80", "224.0.0.1:443", "255.255.255.255:443", "[64:ff9b::c0a8:101]:443", "[2002:c0a8:101::1]:443", "[::192.168.1.1]:443", "localhost:443", "app.localhost:443", "2001:db8::1:443", "[node.example.com]:443", "[192.0.2.1]:443"] {
		assert_eq!((caps(&format!("trojan://pw@{server}")), caps(&format!("vless://id@{server}?security=tls"))), (Ok((vec![], 1)), Ok((vec![], 1))), "{server}");
	}
	for address in ["127.0.0.1", "::1", "64:ff9b::a00:1", "localhost", "[2001:db8::1]"] {assert_eq!(caps(&vmess(json!({"add": address, "port": 443, "id": "id"}))), Ok((vec![], 1)), "{address}")}
	let private = legacy::list(format!("trojan://pw@192.168.1.1:80\ntrojan://pw@[fd00::1]:80\ntrojan://pw@192.0.2.10:443\n{}\n", vmess(json!({"add": "2001:db8::1", "port": 443, "id": "id"}))).as_bytes()).unwrap();
	assert_eq!(private.entries.iter().map(|entry| matches!(entry.server, Server::Address(address) if payload::private(address) && dialable(address))).collect::<Vec<_>>(), [true; 4]);
	// A path is only the characters of a URL path: a quote, a backslash or a brace is no part of one, so no path writes itself into a config. An escape is two hexadecimal digits and nothing else.
	let paths = |path: &str| legacy::list(format!("vless://id@node.example.com:443?security=tls&path={path}").as_bytes()).unwrap().entries[0].path.clone();
	assert_eq!((paths("%2Fa%22%2C%22x%22%3A%7B%5C"), paths("%2Fa%5Cb"), paths("%2Fa%20b"), paths("%2Fa%7Bb%7D"), paths("%2Fa%27b"), paths("%2Fws%3Fed%3D2048"), paths("%2Fa%2Fb.c-d_e~f%25"), paths("%+f")), (None, None, None, None, None, Some("/ws?ed=2048".to_owned()), Some("/a/b.c-d_e~f%".to_owned()), None));
	assert_eq!((caps("trojan://pw@node.example.com:443#%+f"), caps("trojan://p%-1w@node.example.com:443"), caps("trojan://pw@node.example.com:443#%2B%2b")), (Ok((vec![], 1)), Ok((vec![], 1)), Ok((vec![Cap::Detectable], 0))));
	// An entry prints its kind and nothing of where it goes or what it holds.
	assert_eq!((format!("{entry:?}"), format!("{:?}", entry.server), format!("{:?}", private.entries[0].server)), ("Entry(Vless, Tls, ..)".to_owned(), "Name(..)".to_owned(), "Address(..)".to_owned()));
	// "A list over the count limit is cut at the limit and the app says so." Lines that are skipped count as links.
	let lines = |count: usize| (0..count).map(|index| if index % 2 == 0 {"trojan://pass@node.example.com:443\n"} else {"other://x\n"}).collect::<String>();
	assert_eq!((legacy::list(lines(256).as_bytes()).map(|list| (list.entries.len(), list.skipped, list.cut)), legacy::list(lines(257).as_bytes()).map(|list| (list.entries.len(), list.skipped, list.cut)), legacy::list(std_base64(lines(300).as_bytes()).as_bytes()).map(|list| (list.entries.len(), list.skipped, list.cut))), (Ok((128, 128, false)), Ok((128, 128, true)), Ok((128, 128, true))));
	// A link of exactly 4,096 bytes is read, and base64 is taken with line breaks, without padding and in either alphabet.
	let long = format!("trojan://pass@node.example.com:443#{}", "n".repeat(4_096 - 35));
	assert_eq!((long.len(), caps(&long)), (4_096, Ok((vec![Cap::Detectable], 0))));
	let packed = std_base64(b"trojan://pass@node.example.com:443#x>>?>>>\n");
	assert!(packed.contains('+') && packed.contains('/'));
	for body in [packed.clone(), packed.trim_end_matches('=').to_owned(), packed.replace('+', "-").replace('/', "_"), format!("{}\r\n{}\n", &packed[..20], &packed[20..])] {assert_eq!(caps(&body), Ok((vec![Cap::Detectable], 0)), "{body}")}
}

#[test]
fn the_legacy_headers_within_their_bounds() {
	let read = |name: &str, value: &[u8]| legacy::headers(&[(name, value)]);
	let usage = |value: &str| read("Subscription-Userinfo", value.as_bytes()).usage.map(|usage| (usage.upload, usage.download, usage.total, usage.expire));
	assert_eq!(usage("upload=1; download=2; total=3; expire=1700000000"), Some((1, 2, 3, Some(1_700_000_000))));
	assert_eq!((usage("upload=1;download=2;total=3"), usage("total=3; download=2; upload=1; expire=0; later=x"), usage(" upload = 1 ; download=2;total=9007199254740991;")), (Some((1, 2, 3, None)), Some((1, 2, 3, None)), Some((1, 2, 9_007_199_254_740_991, None))));
	for value in ["", "upload=1; download=2", "upload=1; download=2; total=x", "upload=1; download=2; total=-3", "upload=1; download=2; total=3.0", "upload=1; download=2; total=", "upload=1; download=2; total=9007199254740992", "upload=1; download=2; total=99999999999999999999", "upload=1; upload=1; download=2; total=3", "upload=1; download=2; total=+3", "upload=1, download=2, total=3"] {assert_eq!(usage(value), None, "{value}")}
	let interval = |value: &str| read("profile-update-interval", value.as_bytes()).update_interval;
	// Hours, "within the bounds of `update_interval`": 1 to 168.
	assert_eq!((interval("1"), interval("24"), interval("168"), interval(" 12 ")), (Some(3_600), Some(86_400), Some(604_800), Some(43_200)));
	for value in ["0", "169", "1.5", "-1", "", "12h", "0x10", "99999999999", "+1"] {assert_eq!(interval(value), None, "{value}")}
	let title = |value: &[u8]| read("PROFILE-TITLE", value).title.map(|title| title.as_str().to_owned());
	assert_eq!((title(b"Example"), title("\u{202e}Exa\u{200b}mple".as_bytes()), title(&[b'a'; 100]).map(|title| title.len()), title(b""), title(b"\x07"), title(b"\xff\xfe"), title(&[b'a'; 1_025])), (Some("Example".to_owned()), Some("Example".to_owned()), Some(64), None, None, None, None));
	let support = |value: &str| read("support-url", value.as_bytes()).support_url.map(|url| url.host().to_owned());
	assert_eq!((support("https://example.com/help?x=1#top"), support("http://example.com/help"), support("https://user@example.com/"), support("tg://resolve?domain=example"), support(&format!("https://example.com/{}", "a".repeat(500)))), (Some("example.com".to_owned()), None, None, None, None));
	// A header that is there twice is ignored, and the others are read.
	let twice = legacy::headers(&[("profile-title", b"One"), ("Profile-Title", b"Two"), ("profile-update-interval", b"2"), ("x-other", b"ignored")]);
	assert_eq!((twice.title, twice.update_interval, twice.usage, twice.support_url), (None, Some(7_200), None, None));
}

// No `Debug` of any public type of the module holds a document, a secret, a dial address, a name a client shows the network, a path, or a legacy URL, which is a bearer secret. A log line, a panic message or an `unwrap` on any of them gives away an id, a serial, a fingerprint, a host and counts.
#[test]
fn nothing_prints_a_document_a_secret_an_address_or_a_path() {
	let document = sign(0x11, &with(rich(), &[("/refresh_urls", json!(["https://mirror.example.net/refresh-path?k=1"]))]));
	let (verified, whole) = (envelope::verify(document.as_bytes(), &[key(0x11)], BODY_MAX).unwrap(), carried(&document, &[]).unwrap());
	let Ok(Payload::Subscription(read)) = payload::parse(&verified) else {panic!("a document")};
	let (profile, held, legacy) = (&read.profiles[0], held(), "https://sub.example.com/list-path?token=SECRETLEGACYTOKEN");
	let Offer::Native(offer) = Offer::open(Link::parse(&text("fuzz_deeplink/native-veilway")).unwrap()) else {panic!("a native link")};
	let (fetching, list) = (offer.proceed(None, &mut fixed).unwrap(), legacy::list(&seed("fuzz_links/plain")[1..]).unwrap());
	let (review, mut refreshed) = (fetching.answer(issue(0x11, &[("/refresh_urls", json!(["https://mirror.example.net/refresh-path"]))]).as_bytes(), NOW, &[]).unwrap(), held.clone());
	let changes = refreshed.refresh(issue(0x11, &[("/serial", json!(2)), ("/refresh_urls", json!(["https://mirror.example.net/refresh-path"]))]).as_bytes(), NOW).unwrap();
	let printed = [
		format!("{verified:?}"), format!("{read:?}"), format!("{:?}", Payload::Subscription(read.clone())), format!("{profile:?}"), format!("{:?}", profile.device), format!("{:?}", profile.transports), format!("{:?}", profile.padding), format!("{:?}", profile.exits),
		format!("{:?}", profile.transports.iter().filter_map(|transport| if let Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) = transport {Some((stream, &stream.candidates, stream.candidates[0].address))} else {None}).collect::<Vec<_>>()),
		format!("{:?}", (&read.refresh_urls, &read.support, &read.cards, &read.logo, &read.devices, &read.usage, &read.notices, &read.refused)),
		format!("{whole:?}"), format!("{:?}", whole.accept(None, &[]).unwrap()), format!("{held:?}"), format!("{refreshed:?}"), format!("{changes:?}"), format!("{:?}", held.stored()), format!("{:?}", held.device()), format!("{:?}", held.fetch()), format!("{:?}", held.connect(NOW)),
		format!("{fetching:?}"), format!("{:?}", fetching.request()), format!("{review:?}"), format!("{:?}", review.accept(DeviceName::typed("phone"), &[&held]).unwrap_err()),
		format!("{:?}", Held::restore(veilway_proto::subscription::client::Stored {keys: Vec::new(), ..held.stored()})), format!("{:?}", Held::restore(veilway_proto::subscription::client::Stored {document: issue(0x11, &[("/v", json!(2))]), ..held.stored()})),
		format!("{:?}", Link::parse(&text("fuzz_deeplink/native-https"))), format!("{:?}", Link::parse(&text("fuzz_deeplink/document"))), format!("{:?}", Offer::open(Link::parse(&text("fuzz_deeplink/document")).unwrap())), format!("{:?}", Link::parse(legacy)), format!("{:?}", Offer::open(Link::parse(legacy).unwrap())),
		format!("{:?}", Received::read(&seed("fuzz_sub_request/confirm"))), format!("{:?}", Received::read(b"{\"token\":\"VVVVVVVVVVVVVVVVVVVVVQ\"}")), format!("{list:?}"), format!("{:?}", legacy::headers(&[("support-url", b"https://example.com/help-path?ticket=SECRETLEGACYTOKEN")])),
	];
	let secrets = [document.clone(), document.split('.').nth(1).unwrap()[..40].to_owned(), held.document().to_owned(), "VVVVVVVV".to_owned(), "RERERERE".to_owned(), "51, 51".to_owned(), "68, 68".to_owned(), "85, 85".to_owned(), "[0, 1, 2".to_owned(), "SECRETLEGACYTOKEN".to_owned(), "password".to_owned(), "00000000-0000".to_owned()];
	let places = ["192.0.2", "2001:db8", "10.7.0", "fd00:", "node.example.com", "cdn.example.net", "a-path-of-a-transport", "refresh-path", "list-path", "help-path", "com/s", "k=1", "/ws", "51820"];
	for (index, text) in printed.iter().enumerate() {
		for hidden in secrets.iter().map(String::as_str).chain(places) {assert!(!text.contains(hidden), "{index} prints {hidden}: {}", &text[..text.len().min(300)])}
	}
	// No text a provider wrote for a reader is printed either, in `default` or in any translation: not by a text, by what holds one, or by a translation that was picked, which prints its tag.
	let spoken = subscription(&with(payload("languages"), &[("/devices/0/name", json!("Telefon"))]));
	let (node, persian) = (&spoken.profiles[0], tags(&["fa-Arab-IR"]));
	let said = [
		format!("{spoken:?}"), format!("{:?}", (&spoken.provider, &spoken.profiles, &spoken.support, &spoken.cards, &spoken.notices, &spoken.devices)), format!("{:?}", (&node.name, &node.exits, &node.notices)),
		format!("{:?}", (spoken.provider.translation(&persian), spoken.provider.translations().collect::<Vec<_>>(), spoken.provider.decided(&persian).1, node.exits[0].name.pick(&persian).1)),
		format!("{:?}", (node.exit_name(&sent_exit("de", "Frankfurt")), spoken.notice_text(node, &control::Notice {severity: Severity::Warning, text: "Maintenance tonight".into()}))),
		format!("{:?}", carried(&sign(0x11, &payload("languages")), &[]).unwrap().accept(None, &[]).unwrap()),
	];
	for (index, text) in said.iter().enumerate() {
		for hidden in ["Example", "Provider", "Beispiel", "Frankfurt", "Amsterdam", "Maintenance", "Welcome", "Help", "Plan", "Basic", "GB", "Hello", "Site", "Telefon", "نمونه", "ارائه", "فرانکفورت", "امشب", "خوش", "راهنما", "طرح", "پایه", "گیگابایت", "سلام", "سایت", "法蘭克福", "\u{200c}"] {assert!(!text.contains(hidden), "{index} prints {hidden}: {}", text.chars().take(300).collect::<String>())}
	}
	assert_eq!((format!("{:?}", spoken.provider), said[3].as_str()), ("Text(16 bytes, 2 translations)".to_owned(), "(Some(Translation(fa)), [Translation(de), Translation(fa)], Some(Translation(fa)), Some(Tag(\"fa\")))"));
	// What they do print, for a few of them.
	assert_eq!((printed[1].as_str(), printed[3].as_str(), printed[4].as_str(), printed[5].as_str()), ("Subscription(example-account-0001, serial 5, 2 profiles, 0 refused)", "Profile(main, 5 transports, 1 exits)", "DeviceKeys(2 addresses, 1 transport secrets, ..)", "[UdpObfs(2 endpoints), Tls(1 candidates), Ws(1 candidates), Fronted(1 candidates), Udp(1 endpoints)]"));
	assert_eq!((printed[12].as_str(), format!("{:?}", Link::parse(legacy).unwrap())), (format!("Held(Subscription(example-account-0001, serial 1, 1 profiles, 0 refused), [{:?}], {} bytes, 0 confirmed hosts)", key(0x11), held.document().len()).as_str(), "Legacy(Legacy { url: Url(sub.example.com, ..) })".to_owned()));
}

// "An endpoint signs one serial once": during an overlap the same payload under the other held key is another body, and a fork.
#[test]
fn the_same_payload_under_the_other_held_key_is_another_body() {
	let (mut held, both) = (held(), with(first(), &[("/serial", json!(2)), ("/signing_keys", json!([std_base64(key(0x11).bytes()), std_base64(key(0x22).bytes())]))]));
	assert_eq!((held.refresh(sign(0x11, &both).as_bytes(), NOW).is_ok(), held.refresh(sign(0x22, &both).as_bytes(), NOW), held.refresh(sign(0x11, &both).as_bytes(), NOW)), (true, Err(Failure::Fork), Ok(Refreshed::Unchanged)));
}

// With provider-issued keys there is no key of the client's own to hold a refresh to, so every device key of a refresh is one the stored document had, under whatever profile id.
#[test]
fn a_refresh_brings_no_device_key_the_stored_document_did_not_have() {
	let other = |id: &str, fill: u8| with(payload("content")["profiles"][0].clone(), &[("/id", json!(id)), ("/device/private_key", json!(std_base64(&[fill; 32]))), ("/device/public_key", json!(std_base64(&veilway_proto::proof::public_key(&[fill; 32]))))]);
	let mut held = carried(&sign(0x11, &payload("content")), &[]).unwrap().accept(None, &[]).unwrap().held;
	let before = held.clone();
	// The profile under a new id with a new key, the same beside the old profile, and the old id with a new key.
	for (serial, profiles) in [(6, json!([other("main2", 0x35)])), (6, json!([payload("content")["profiles"][0], other("second", 0x35)])), (6, json!([other("main", 0x35)]))] {
		assert_eq!((held.refresh(sign(0x11, &with(payload("content"), &[("/serial", json!(serial)), ("/profiles", profiles)])).as_bytes(), NOW), held == before), (Err(Failure::DeviceKey), true));
	}
	// A new profile id with the key the stored document had is taken, and so is a profile that drops out.
	assert!(held.refresh(sign(0x11, &with(payload("content"), &[("/serial", json!(6)), ("/profiles", json!([payload("content")["profiles"][0], other("second", 0x33)]))])).as_bytes(), NOW).is_ok());
	assert!(matches!(held.refresh(sign(0x11, &with(payload("content"), &[("/serial", json!(7)), ("/profiles", json!([other("third", 0x33)]))])).as_bytes(), NOW), Ok(Refreshed::Updated(changes)) if changes.dropped.len() == 2));
	// A fresh import by the user is how another key comes in.
	assert!(carried(&sign(0x11, &with(payload("content"), &[("/issued_at", json!(ISSUED + 50)), ("/expires_at", json!(ISSUED + 86_400)), ("/profiles", json!([other("main", 0x35)]))])), &[&held]).is_ok_and(|review| review.replaces()));
	// A subscription whose device made its key: a new profile that brings a private key is refused as before.
	let mut device_made = self::held();
	assert_eq!(device_made.refresh(issue(0x11, &[("/serial", json!(2)), ("/profiles/1", other("issued", 0x33))]).as_bytes(), NOW), Err(Failure::PrivateKey));
}

#[test]
fn expiry_warns_and_then_asks_at_every_connect() {
	let held = held();
	let expires = ISSUED + 30 * 86_400;
	assert_eq!((held.standing(NOW), held.standing(expires - 1), held.standing(expires), held.standing(expires + GRACE), held.standing(expires + GRACE + 1), held.standing(u64::MAX)), (Standing::Current, Standing::Current, Standing::OutOfDate, Standing::OutOfDate, Standing::Stale, Standing::Stale));
	// "Keeps working" while it is out of date, and "every connect needs one explicit confirmation" after the grace: the question comes back at each connect.
	assert!(held.connect(expires + GRACE).is_ok());
	for _ in 0..2 {
		let Err(question) = held.connect(expires + GRACE + 1) else {panic!("a connect that asks")};
		let permit = question.confirmed();
		// The leave is for this subscription at this time, and no other.
		assert_eq!((permit.id(), permit.at()), (held.id(), expires + GRACE + 1));
	}
	// A refresh that works ends it.
	let mut refreshed = held.clone();
	refreshed.refresh(issue(0x11, &[("/serial", json!(2)), ("/issued_at", json!(expires + GRACE)), ("/expires_at", json!(expires + GRACE + 1_000))]).as_bytes(), expires + GRACE + 1).unwrap();
	assert_eq!(refreshed.standing(expires + GRACE + 1), Standing::Current);
}

#[test]
fn what_is_held_goes_to_storage_and_back() {
	let mut held = held();
	held.refresh(issue(0x11, &[("/serial", json!(2)), ("/refresh_urls", json!(["https://mirror.example.net/s", "https://other.example.org/s"]))]).as_bytes(), NOW).unwrap();
	held.confirm_hosts(&["mirror.example.net:443"]);
	let stored = held.stored();
	assert_eq!((format!("{stored:?}"), stored.keys.clone(), stored.hosts.clone(), stored.origin.clone().map(|(link, private, secret)| (link, *private.expose(), *secret.expose()))), ("Stored(..)".to_owned(), vec![*key(0x11).bytes()], vec!["mirror.example.net:443".to_owned()], Some((text("fuzz_deeplink/native-veilway"), [0x33; 32], [0x44; 16]))));
	assert!(Held::restore(stored.clone()).is_ok_and(|restored| restored == held));
	// A whole document has no link and no device.
	let whole = carried(&text("fuzz_sub_envelope/carried")[1..], &[]).unwrap().accept(None, &[]).unwrap().held;
	assert!(whole.stored().origin.is_none() && Held::restore(whole.stored()).is_ok_and(|restored| restored == whole));
	// A confirmed host that is no `host:port`, or that the document does not list, is not kept: the user is asked again.
	let mut hosts = stored.clone();
	hosts.hosts.extend(["Not A Host".to_owned(), "mirror.example.net".to_owned(), "gone.example.org:443".to_owned(), "other.example.org:99999".to_owned()]);
	assert!(Held::restore(hosts).is_ok_and(|restored| restored == held));
	// What does not hold together: another document, keys that did not sign it, a key no client may hold, no key or three, a link that is no native link. The link, the token and the device's key come back as they were stored, so the device keeps its place.
	let mut broken = vec![stored.clone(); 7];
	broken[0].document.push('A');
	broken[1].keys = vec![*key(0x22).bytes()];
	broken[2].keys = vec![[0; 32]];
	broken[3].keys = Vec::new();
	broken[4].keys = vec![*key(0x11).bytes(), *key(0x22).bytes(), *key(0x99).bytes()];
	broken[5].origin.as_mut().unwrap().0 = text("fuzz_deeplink/legacy");
	broken[6].origin.as_mut().unwrap().0 = text("fuzz_deeplink/document");
	for (index, stored) in broken.into_iter().enumerate() {
		let origin = stored.origin.clone();
		assert!(matches!(Held::restore(stored), Err(Damaged::Broken(back)) if back.as_deref() == origin.as_ref() && back.is_some()), "{index}");
	}
	// A document that verifies and that today's reader does not read, as after an update of the app that tightened a rule: here one of a later version, a refusal, and one whose list of keys is not the keys stored. The link, the device and the keys are kept, and a fetch under them puts the subscription back without a new device place.
	let mut unread = vec![stored.clone(); 3];
	unread[0].document = issue(0x11, &[("/v", json!(2))]);
	unread[1].document = text("fuzz_sub_envelope/refusal")[1..].to_owned();
	unread[2].keys.push(*key(0x22).bytes());
	for (index, stored) in unread.into_iter().enumerate() {
		let Err(Damaged::Unread(Some(fetching))) = Held::restore(stored) else {panic!("{index}")};
		assert_eq!((fetching.request().body() == seed("fuzz_sub_request/fetch"), fetching.endpoint().as_str()), (index < 2, "https://sub.example.com/s"), "{index}");
		assert!(fetching.answer(issue(0x11, &[("/serial", json!(3))]).as_bytes(), NOW, &[]).unwrap().accept(None, &[]).is_ok_and(|accepted| accepted.held.device() == held.device() && accepted.held.subscription().serial == 3), "{index}");
	}
	assert!(matches!(Held::restore(veilway_proto::subscription::client::Stored {document: sign(0x11, &with(payload("import"), &[("/v", json!(2))])), ..whole.stored()}), Err(Damaged::Unread(None))));
	assert_eq!((format!("{:?}", Held::restore(veilway_proto::subscription::client::Stored {keys: Vec::new(), ..stored.clone()}).unwrap_err()), format!("{:?}", Held::restore(veilway_proto::subscription::client::Stored {document: issue(0x11, &[("/v", json!(2))]), ..stored}).unwrap_err())), ("Damaged::Broken(..)".to_owned(), "Damaged::Unread(..)".to_owned()));
	// What is stored is trusted as the link is: a stored value whose keys and document are another provider's restores, with the user's token and device. Nothing in this crate can tell, which is why the value belongs in secret storage.
	let theirs = veilway_proto::subscription::client::Stored {keys: vec![*key(0x99).bytes()], document: sign(0x99, &with(first(), &[("/signing_keys", json!([std_base64(key(0x99).bytes())])), ("/subscription_id", json!("another-account-0002"))])), ..held.stored()};
	assert!(Held::restore(theirs).is_ok_and(|restored| restored.keys() == [key(0x99)] && restored.device() == held.device()));
}

#[test]
fn the_wait_between_refreshes() {
	let at = |fill: u8| move |bytes: &mut [u8]| -> Result<(), NoRandom> {
		bytes.fill(fill);
		Ok(())
	};
	// A draw of all zero bytes is the low end of the range, 0.8.
	assert_eq!((wait(3_600, 0, &mut at(0)).unwrap().as_secs(), wait(900, 0, &mut at(0)).unwrap().as_millis(), wait(604_800, 0, &mut at(0)).unwrap().as_secs()), (2_880, 720_000, 483_840));
	// "The interval, doubled per failure up to 86,400 s."
	assert_eq!([1, 2, 3, 4, 5, 6, 40, u32::MAX].map(|failures| wait(3_600, failures, &mut at(0)).unwrap().as_secs() * 10 / 8), [7_200, 14_400, 28_800, 57_600, 86_400, 86_400, 86_400, 86_400]);
	// "Never shorter than the interval": above a day a failure changes nothing.
	assert_eq!([0, 1, 5, 40].map(|failures| wait(604_800, failures, &mut at(0)).unwrap().as_secs() * 10 / 8), [604_800; 4]);
	assert_eq!([0, 1, 2].map(|failures| wait(50_000, failures, &mut at(0)).unwrap().as_secs() * 10 / 8), [50_000, 86_400, 86_400]);
	let mut state = 7u64;
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for byte in bytes {
			state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
			*byte = (state >> 56) as u8;
		}
		Ok(())
	};
	let waits: Vec<u128> = (0..500).map(|_| wait(1_000, 0, &mut random).unwrap().as_millis()).collect();
	assert!(waits.iter().all(|wait| (800_000..=1_200_000).contains(wait)) && waits.iter().any(|wait| *wait < 850_000) && waits.iter().any(|wait| *wait > 1_150_000));
	assert_eq!(wait(1_000, 0, &mut |_: &mut [u8]| Err(NoRandom)), Err(NoRandom));
}
