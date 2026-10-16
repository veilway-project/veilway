//! Static mirrors (subscription format page, "Static mirrors") in the client's hands: the member of the document, what a user confirms, the one file a refresh asks for and what each kind of answer does to what is held. The seal itself is tested next to its code in `subscription/mirror.rs`, against vectors from tests/vectors.py.
use ring::signature::{Ed25519KeyPair, KeyPair};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use serde_json::{json, Value};
use std::fs;
use veilway_proto::{keys::MirrorKeys, subscription::{client::{Failure, Held, Offer, Refreshed, StaticTarget}, envelope::{self, EnvelopeError, SigningKey}, link::Link, mirror::{self, OpenError}, payload::{self, PayloadError, Payload, Reason}, BODY_MAX}, NoRandom};

// The clock of every test: 100 s after the documents of vectors.py were issued.
const ISSUED: u64 = 1_700_000_000;
const NOW: u64 = ISSUED + 100;
const BASE: &str = "https://files.example.net/vw/";
const OTHER: &str = "https://cdn.example.org:8443/a/b/";
const HOST: &str = "files.example.net:443#static";

fn seed(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

fn pair(fill: u8) -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).unwrap()}

fn key(fill: u8) -> SigningKey {SigningKey::new(pair(fill).public_key().as_ref().try_into().unwrap()).unwrap()}

fn sign(fill: u8, payload: &Value) -> String {envelope::seal(&key(fill), &serde_json::to_vec(payload).unwrap(), |signed| pair(fill).sign(signed).as_ref().try_into().unwrap())}

fn first() -> Value {serde_json::from_slice(envelope::verify(&seed("fuzz_sub_envelope/document")[1..], &[key(0x11)], BODY_MAX).unwrap().payload()).unwrap()}

fn with(mut document: Value, changes: &[(&str, Value)]) -> Value {
	for (pointer, value) in changes {
		let (parent, name) = pointer.rsplit_once('/').unwrap();
		document.pointer_mut(parent).unwrap().as_object_mut().unwrap().insert(name.to_owned(), value.clone());
	}
	document
}

// The first document of vectors.py with members changed, signed by the first key.
fn issue(changes: &[(&str, Value)]) -> String {sign(0x11, &with(first(), changes))}

// The random source of a client whose device key is 33..33 and whose device secret is 44..44, as in vectors.py.
fn fixed(bytes: &mut [u8]) -> Result<(), NoRandom> {
	bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
	Ok(())
}

fn salt(bytes: &mut [u8]) -> Result<(), NoRandom> {
	bytes.fill(0x5a);
	Ok(())
}

fn link() -> Link {Link::parse(&String::from_utf8(seed("fuzz_deeplink/native-veilway")).unwrap()).unwrap()}

// The imported subscription of vectors.py with the changes, accepted with every host on its screen confirmed.
fn held(changes: &[(&str, Value)]) -> Held {
	let Offer::Native(offer) = Offer::open(link()) else {panic!("a native link")};
	offer.proceed(None, &mut fixed).unwrap().answer(issue(changes).as_bytes(), NOW, &[]).unwrap().accept(None, &[]).unwrap().held
}

fn mirrors(list: &[&str]) -> Vec<(&'static str, Value)> {vec![("/refresh_urls", json!([])), ("/static_mirrors", json!(list))]}

// The keys the client derives for itself, from the link's token and the device of `fixed`.
fn keys() -> MirrorKeys {
	let Link::Native(link) = link() else {panic!("a native link")};
	MirrorKeys::derive(link.token().expose(), &[0x44; 16], &veilway_proto::proof::public_key(&[0x33; 32]))
}

// The file a panel would write for `document` in the period of `at`.
fn file(base: &str, at: u64, document: &str) -> Vec<u8> {mirror::seal(&keys(), base, mirror::epoch(at), mirror::size_for(document.len()).unwrap(), document.as_bytes(), &mut salt).unwrap()}

fn target(held: &Held, at: u64, place: usize) -> StaticTarget {held.static_targets(at)[place].clone()}

fn parse(document: &Value) -> Result<Payload, PayloadError> {payload::parse(&envelope::verify(sign(0x11, document).as_bytes(), &[key(0x11)], BODY_MAX).unwrap())}

fn refused(list: Value) -> bool {parse(&with(first(), &[("/refresh_urls", json!(["https://mirror.example.net/s"])), ("/static_mirrors", list)])) == Err(PayloadError::Member("static_mirrors"))}

fn read_list(list: Value) -> Vec<String> {
	match parse(&with(first(), &[("/refresh_urls", json!(["https://mirror.example.net/s"])), ("/static_mirrors", list)])) {
		Ok(Payload::Subscription(subscription)) => subscription.static_mirrors.iter().map(|url| url.as_str().to_owned()).collect(),
		other => panic!("{other:?}"),
	}
}

#[test]
fn the_list_of_static_mirrors_is_read_and_held_to_its_rules() {
	assert_eq!(read_list(json!([BASE, OTHER])), [BASE, OTHER]);
	assert_eq!(read_list(json!([])), Vec::<String>::new());
	assert_eq!(read_list(json!(["https://files.example.net/vw/", "https://files.example.net/vx/", "https://files.example.net:8443/", "https://a.example.net/"])).len(), 4);
	// A list that is not there is an empty one, and a document without the member is a document of before.
	let Ok(Payload::Subscription(plain)) = parse(&first()) else {panic!("the document of the vectors")};
	assert!(plain.static_mirrors.is_empty());
	let long = |length: usize| format!("https://files.example.net/{}/", "a".repeat(length - "https://files.example.net//".len()));
	assert_eq!((long(216).len(), read_list(json!([long(216)])).len()), (216, 1));
	for bad in [
		json!([long(217)]), json!([BASE, BASE]), json!([BASE, OTHER, "https://c.example.net/", "https://d.example.net/", "https://e.example.net/"]),
		json!("https://files.example.net/vw/"), json!({"https://files.example.net/vw/": 1}), json!([1]), json!([null]), json!([["https://files.example.net/vw/"]]),
		json!([{"url": BASE, "pins": ["AAAA"]}]), json!([{"url": BASE}]),
		json!(["http://files.example.net/vw/"]), json!(["files.example.net/vw/"]), json!(["HTTPS://files.example.net/vw/"]), json!(["https://files.example.net"]), json!(["https://files.example.net/vw"]),
		json!(["https://files.example.net/vw/?a=b"]), json!(["https://files.example.net/vw/#a"]), json!(["https://files.example.net/vw/?"]), json!(["https://u@files.example.net/vw/"]), json!(["https://u:p@files.example.net/vw/"]),
		json!(["https://203.0.113.7/vw/"]), json!(["https://[2001:db8::1]/vw/"]), json!(["https://127.0.0.1/"]), json!(["https://files.example.net:0/vw/"]), json!(["https://Files.example.net/vw/"]),
		json!(["https://files.example.net/vw/%00/"]), json!(["https://files.example.net/vw%2f/"]), json!(["https://files.example.net/a%5cb/"]), json!(["https://files.example.net/a/../"]), json!(["https://files.example.net/a/%2e%2E/"]),
		json!(["https://files.example.net/a/./"]), json!(["https://files.example.net/a/..;/"]), json!(["https://files.example.net/a b/"]), json!(["https://files.example.net/\u{e4}/"]),
		// One host has one role: an entry of `refresh_urls` has this host and port.
		json!(["https://mirror.example.net/static/"]), json!(["https://mirror.example.net:443/"]),
	] {assert!(refused(bad.clone()), "{bad}")}
	// A host and port of its own, even with the same name on another port.
	assert_eq!(read_list(json!(["https://mirror.example.net:8443/static/"])).len(), 1);
	// Two folders on one shared host are two base URLs of one host, and are confirmed together as one.
	assert_eq!(read_list(json!(["https://files.example.net/a/", "https://files.example.net/b/"])).len(), 2);
	// A pinned entry of `refresh_urls` on the same host and port is the same role clash.
	let pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
	assert_eq!(parse(&with(first(), &[("/refresh_urls", json!([{"url": "https://203.0.113.7/s", "pins": [pin]}])), ("/static_mirrors", json!(["https://files.example.net/"]))])).map(|payload| matches!(payload, Payload::Subscription(_))), Ok(true));
}

#[test]
fn a_static_mirror_is_confirmed_as_a_kind_of_its_own_and_stays_confirmed_while_listed() {
	let held = held(&mirrors(&[BASE, OTHER]));
	assert_eq!(held.stored().hosts, ["files.example.net:443#static", "cdn.example.org:8443#static"]);
	assert!(held.unconfirmed().is_empty() && held.endpoints().len() == 1 && held.targets().len() == 1);
	// Restoring from storage keeps them: `Held::restore` once dropped a host that its document did not list in `refresh_urls`.
	let restored = Held::restore(held.stored()).unwrap();
	assert_eq!((restored.stored().hosts, restored.static_targets(NOW).len()), (held.stored().hosts, 2));
	// A host that was confirmed as a refresh host is no yes to the same host as a static mirror, and the reverse.
	let mut stored = held.stored();
	stored.hosts = vec!["files.example.net:443".into(), "cdn.example.org:8443#pinned".into()];
	let restored = Held::restore(stored).unwrap();
	assert!(restored.stored().hosts.is_empty() && restored.static_targets(NOW).is_empty() && restored.unconfirmed() == [HOST, "cdn.example.org:8443#static"]);
	// A later document that adds one waits for the user, and nothing is asked of it before.
	let mut held = self::held(&mirrors(&[BASE]));
	let Ok(Refreshed::Updated(changes)) = held.refresh(issue(&[("/serial", json!(2)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))]).as_bytes(), NOW) else {panic!("a newer document")};
	assert_eq!((changes.hosts.clone(), held.unconfirmed(), held.static_targets(NOW).len()), (vec!["cdn.example.org:8443#static".to_owned()], vec!["cdn.example.org:8443#static".to_owned()], 1));
	// A yes to what the screen showed is a yes to those and no others.
	held.confirm_hosts(&["files.example.net:443", HOST, "other.example.net:443#static"]);
	assert_eq!((held.unconfirmed(), held.static_targets(NOW).len()), (vec!["cdn.example.org:8443#static".to_owned()], 1));
	held.confirm_hosts(&["cdn.example.org:8443#static"]);
	assert_eq!((held.unconfirmed(), held.static_targets(NOW).len()), (Vec::<String>::new(), 2));
	// Confirmed only while documents list it: dropped by one, listed again by the next, it waits again.
	held.refresh(issue(&[("/serial", json!(3)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE]))]).as_bytes(), NOW).unwrap();
	assert_eq!((held.stored().hosts, held.static_targets(NOW).len()), (vec![HOST.to_owned()], 1));
	held.refresh(issue(&[("/serial", json!(4)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))]).as_bytes(), NOW).unwrap();
	assert_eq!((held.unconfirmed(), held.static_targets(NOW).len()), (vec!["cdn.example.org:8443#static".to_owned()], 1));
	// A different port is a different host, and the same host with another path is the same one.
	held.refresh(issue(&[("/serial", json!(5)), ("/refresh_urls", json!([])), ("/static_mirrors", json!(["https://files.example.net/other/", "https://files.example.net:8443/vw/"]))]).as_bytes(), NOW).unwrap();
	assert_eq!((held.unconfirmed(), held.static_targets(NOW).len()), (vec!["files.example.net:8443#static".to_owned()], 1));
}

#[test]
fn a_no_is_kept_while_documents_list_the_host_and_a_yes_can_be_taken_back() {
	let mut held = held(&mirrors(&[BASE]));
	let Ok(Refreshed::Updated(changes)) = held.refresh(issue(&[("/serial", json!(2)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))]).as_bytes(), NOW) else {panic!("a newer document")};
	assert_eq!((changes.hosts, held.waiting()), (vec!["cdn.example.org:8443#static".to_owned()], vec!["cdn.example.org:8443#static".to_owned()]));
	// A no to what the screen showed and to a host it did not: only the waiting one is taken, and it is not asked about again.
	held.decline_hosts(&["cdn.example.org:8443#static", "other.example.net:443#static"]);
	assert_eq!((held.waiting(), held.unconfirmed(), held.declined().to_vec(), held.static_targets(NOW).len()), (Vec::<String>::new(), vec!["cdn.example.org:8443#static".to_owned()], vec!["cdn.example.org:8443#static".to_owned()], 1));
	// Kept through storage and through a document that still lists it, so the next refresh notes nothing.
	let mut held = Held::restore(held.stored()).unwrap();
	let Ok(Refreshed::Updated(changes)) = held.refresh(issue(&[("/serial", json!(3)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))]).as_bytes(), NOW) else {panic!("a newer document")};
	assert!(changes.hosts.is_empty() && held.declined() == ["cdn.example.org:8443#static"]);
	// A yes taken back: the host is no longer contacted, and is not asked about either.
	held.decline_hosts(&[HOST]);
	assert_eq!((held.confirmed().len(), held.static_targets(NOW).len(), held.waiting().len(), held.declined().len()), (0, 0, 0, 2));
	// A later yes to a declined host is taken.
	held.confirm_hosts(&[HOST]);
	assert_eq!((held.confirmed().to_vec(), held.declined().to_vec(), held.static_targets(NOW).len()), (vec![HOST.to_owned()], vec!["cdn.example.org:8443#static".to_owned()], 1));
	// Dropped by a document and listed again by the next, a declined host is asked about again.
	held.refresh(issue(&[("/serial", json!(4)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE]))]).as_bytes(), NOW).unwrap();
	let Ok(Refreshed::Updated(changes)) = held.refresh(issue(&[("/serial", json!(5)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))]).as_bytes(), NOW) else {panic!("a newer document")};
	assert_eq!((changes.hosts, held.declined().len()), (vec!["cdn.example.org:8443#static".to_owned()], 0));
	// What storage says was declined is read as untrusted: a host the document does not list, or one also confirmed, is not kept.
	let mut stored = held.stored();
	stored.declined = vec!["gone.example.org:443".into(), HOST.into(), "cdn.example.org:8443#static".into(), "cdn.example.org:8443#static".into()];
	assert_eq!(Held::restore(stored).unwrap().declined(), ["cdn.example.org:8443#static"]);
}

#[test]
fn a_static_mirror_may_not_be_the_host_of_the_endpoint_or_a_refresh_host() {
	let endpoint = held(&[]).endpoints()[0].authority();
	assert_eq!(endpoint, "sub.example.com:443");
	let Offer::Native(offer) = Offer::open(link()) else {panic!("a native link")};
	let fetching = offer.proceed(None, &mut fixed).unwrap();
	let sharing = issue(&[("/refresh_urls", json!([])), ("/static_mirrors", json!(["https://sub.example.com/files/"]))]);
	assert_eq!(fetching.answer(sharing.as_bytes(), NOW, &[]).err(), Some(Failure::MirrorHost));
	assert!(fetching.answer(issue(&[("/refresh_urls", json!([])), ("/static_mirrors", json!(["https://sub.example.com:8443/files/"]))]).as_bytes(), NOW, &[]).is_ok());
	let mut held = held(&[]);
	assert_eq!(held.refresh(issue(&[("/serial", json!(2)), ("/refresh_urls", json!([])), ("/static_mirrors", json!(["https://sub.example.com/files/"]))]).as_bytes(), NOW), Err(Failure::MirrorHost));
	assert_eq!(held.refresh(issue(&[("/serial", json!(2)), ("/refresh_urls", json!(["https://files.example.net/s"])), ("/static_mirrors", json!([BASE]))]).as_bytes(), NOW), Err(Failure::Payload(PayloadError::Member("static_mirrors"))));
	assert_eq!(held.subscription().serial, 1);
}

#[test]
fn the_file_a_refresh_asks_for_is_one_name_and_carries_nothing_of_the_device() {
	let held = held(&mirrors(&[BASE, OTHER]));
	let ([one, two], epoch) = ([target(&held, NOW, 0), target(&held, NOW, 1)], mirror::epoch(NOW));
	assert_eq!(one.url().as_str(), format!("{BASE}{}", mirror::file_name(&keys(), BASE, epoch)));
	assert_eq!(two.url().as_str(), format!("{OTHER}{}", mirror::file_name(&keys(), OTHER, epoch)));
	assert!(one.url().as_str().ends_with(".bin") && one.url().as_str().len() == BASE.len() + 36 && (one.base().as_str(), two.base().as_str()) == (BASE, OTHER));
	// Names differ per base URL, so two hosts cannot match their files, and per period, so one host cannot follow a device.
	assert_ne!(one.url().as_str()[BASE.len()..], two.url().as_str()[OTHER.len()..]);
	assert_ne!(target(&held, NOW + mirror::PERIOD, 0).url().as_str(), one.url().as_str());
	// The name changes on the boundary of the period by the client's own clock, and in no other second. It never asks for the next or the last period's name.
	let begin = mirror::start(epoch + 1);
	assert_eq!(target(&held, begin - 1, 0).url(), one.url());
	assert_ne!(target(&held, begin, 0).url(), one.url());
	assert_eq!(target(&held, begin, 0).url(), target(&held, begin + 5, 0).url());
	// Nothing secret is in the URL: not the token, the device secret or the device key, in any spelling a log could hold.
	let url = one.url().as_str();
	let Link::Native(native) = link() else {panic!("a native link")};
	for secret in [&native.token().expose()[..], &[0x44; 16][..], &veilway_proto::proof::public_key(&[0x33; 32])[..]] {
		let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
		assert!(!url.contains(&hex) && !url.contains(&STANDARD.encode(secret)) && !url.contains(&URL_SAFE_NO_PAD.encode(secret)));
	}
}

#[test]
fn a_static_answer_is_a_refresh_only_when_it_is_a_newer_document_that_passes_every_check() {
	let mut held = held(&mirrors(&[BASE, OTHER]));
	let (one, two) = (target(&held, NOW, 0), target(&held, NOW, 1));
	let before = held.clone();
	// A newer document is taken, by the path of an answer from the endpoint.
	let newer = issue(&[("/serial", json!(2)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER])), ("/provider/name", json!("Newer Name"))]);
	assert!(matches!(held.refresh_static(&one, &file(BASE, NOW, &newer), NOW), Ok(Refreshed::Updated(_))));
	assert_eq!((held.subscription().serial, held.document()), (2, newer.as_str()));
	// The document the client already holds means only that this mirror has nothing newer.
	let after = held.clone();
	assert_eq!(held.refresh_static(&one, &file(BASE, NOW, &newer), NOW), Ok(Refreshed::Unchanged));
	assert_eq!(held, after);
	// An older one, which a stale cache gives, is refused by its serial, and so is the same serial with other bytes.
	assert_eq!(held.refresh_static(&one, &file(BASE, NOW, &issue(&[("/serial", json!(1)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))])), NOW), Err(Failure::Rollback));
	assert_eq!(held.refresh_static(&one, &file(BASE, NOW, &issue(&[("/serial", json!(2)), ("/provider/name", json!("Other Name"))])), NOW), Err(Failure::Fork));
	// A file of the wrong size, one that was changed, one for another period, name or base URL, and one made with other keys do not open.
	let third = issue(&[("/serial", json!(3)), ("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE, OTHER]))]);
	let good = file(BASE, NOW, &third);
	assert_eq!(held.refresh_static(&one, &good[..good.len() - 1], NOW), Err(Failure::Mirror(OpenError::Size)));
	assert_eq!(held.refresh_static(&one, &[], NOW), Err(Failure::Mirror(OpenError::Size)));
	let mut changed = good.clone();
	changed[100] ^= 1;
	assert_eq!(held.refresh_static(&one, &changed, NOW), Err(Failure::Mirror(OpenError::Seal)));
	assert_eq!(held.refresh_static(&two, &good, NOW), Err(Failure::Mirror(OpenError::Seal)));
	assert_eq!(held.refresh_static(&one, &file(BASE, NOW + mirror::PERIOD, &third), NOW), Err(Failure::Mirror(OpenError::Seal)));
	assert_eq!(held.refresh_static(&one, &file(OTHER, NOW, &third), NOW), Err(Failure::Mirror(OpenError::Seal)));
	let elsewhere = mirror::seal(&MirrorKeys::derive(&[1; 16], &[2; 16], &[3; 32]), BASE, mirror::epoch(NOW), 9_413, b"x", &mut salt).unwrap();
	assert_eq!(held.refresh_static(&one, &elsewhere, NOW), Err(Failure::Mirror(OpenError::Seal)));
	// What opens is then judged like any answer: another key, another subscription and an expired document are each a failure of that mirror.
	let signed = |fill: u8, changes: &[(&str, Value)]| sign(fill, &with(first(), changes));
	for (document, failure) in [
		(signed(0x99, &[("/serial", json!(9))]), Failure::Envelope(EnvelopeError::UnknownKey)),
		(signed(0x11, &[("/serial", json!(9)), ("/subscription_id", json!("example-account-0002"))]), Failure::OtherSubscription),
		(signed(0x11, &[("/serial", json!(9)), ("/issued_at", json!(NOW - 50)), ("/expires_at", json!(NOW - 1))]), Failure::Expired),
		(signed(0x11, &[("/serial", json!(9)), ("/issued_at", json!(NOW + 301)), ("/expires_at", json!(NOW + 1_000))]), Failure::Future),
		(signed(0x11, &[("/serial", json!(9)), ("/profiles/0/device/public_key", json!(STANDARD.encode(veilway_proto::proof::public_key(&[0x34; 32]))))]), Failure::DeviceKey),
	] {assert_eq!(held.refresh_static(&one, &file(BASE, NOW, &document), NOW), Err(failure), "{failure:?}")}
	assert_eq!((held.document(), held.subscription().serial), (newer.as_str(), 2));
	// A signed refusal that verifies is the one answer that says an account is off.
	let disabled = sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW - 10, "refusal": "disabled"}));
	assert_eq!(held.refresh_static(&one, &file(BASE, NOW, &disabled), NOW), Err(Failure::Refused(Reason::Disabled)));
	let old = sign(0x11, &json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW - 90_000, "refusal": "disabled"}));
	assert_eq!(held.refresh_static(&one, &file(BASE, NOW, &old), NOW), Err(Failure::StaleRefusal));
	assert_eq!(held.document(), newer.as_str());
	assert_eq!(before.document(), issue(&mirrors(&[BASE, OTHER])));
}

#[test]
fn a_whole_document_has_no_static_mirrors_and_no_way_to_open_one() {
	let content: Value = serde_json::from_slice(&seed("fuzz_subscription/content")[1..]).unwrap();
	let document = sign(0x11, &with(content, &[("/refresh_urls", json!([])), ("/static_mirrors", json!([BASE]))]));
	let key = String::from_utf8(seed("fuzz_deeplink/file")).unwrap()[3..46].to_owned();
	let Offer::Carried(offer) = Offer::open(Link::Carried(veilway_proto::subscription::link::Carried::file(format!("v1.{key}.{document}").as_bytes()).unwrap())) else {panic!("a document in a file")};
	let mut whole = offer.proceed(NOW, &[]).unwrap().accept(None, &[]).unwrap().held;
	assert_eq!(whole.subscription().static_mirrors.len(), 1);
	assert!(whole.static_targets(NOW).is_empty() && whole.stored().hosts.is_empty() && whole.unconfirmed().is_empty());
	let fake = target(&held(&mirrors(&[BASE])), NOW, 0);
	assert_eq!(whole.refresh_static(&fake, &[0; 9_413], NOW), Err(Failure::Mirror(OpenError::Seal)));
}

// The seeds of `fuzz_sub_mirror` come from vectors.py, which wrote them without this crate: each opens, or fails, as its name says.
#[test]
fn the_seeds_of_the_fuzz_target_open_or_fail_as_they_are_named() {
	let keys = MirrorKeys::derive(&std::array::from_fn(|index| 1 + index as u8), &std::array::from_fn(|index| 0x21 + index as u8), &std::array::from_fn(|index| 0x41 + index as u8));
	let (base, open) = ("https://files.example.net/vw/", |name: &str| mirror::open(&keys, "https://files.example.net/vw/", 2000, &seed(&format!("fuzz_sub_mirror/{name}"))));
	assert_eq!(open("file"), Ok(b"veilway static mirror test vector".to_vec()));
	assert_eq!(open("biggest-envelope"), Ok(vec![b'e'; 9_361]));
	assert_eq!(open("second-size"), Ok(b"veilway static mirror test vector".to_vec()));
	assert_eq!([open("file-other-period"), open("tag-changed")], [Err(OpenError::Seal), Err(OpenError::Seal)]);
	assert_eq!([open("nonzero-padding"), open("empty-envelope"), open("one-byte-short")], [Err(OpenError::Padding), Err(OpenError::Length), Err(OpenError::Size)]);
	assert_eq!(mirror::file_name(&keys, base, 2000), "41061aa1ae12d729f9dd2f2d5f715408.bin");
}
