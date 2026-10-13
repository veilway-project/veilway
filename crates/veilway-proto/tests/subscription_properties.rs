//! Property tests of the subscription format: a link reads back and no single changed character passes for it, a request reads back, a signed document with one bit flipped is refused, no reader panics on bytes it did not write or on a good document with one member changed, and what a client holds follows a second, simpler writing of the rules.
use proptest::{collection::vec, option, prelude::*, sample::{select, Index}};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs};
use veilway_proto::{proof::public_key, subscription::{client::{Failure, Held, Offer, Refreshed}, envelope::{self, EnvelopeError, SigningKey}, fetch::{DeviceName, Received}, legacy, link::{Carried, Link}, payload::{self, Card, Payload, PayloadError, Reason, Subscription, Transport, CANDIDATES_MAX, CARDS_MAX, DEVICES_MAX, PINS_MAX, PROFILES_MAX, REFRESH_URLS_MAX, SUPPORT_MAX, TRANSPORTS_MAX}, BODY_MAX}, NoRandom};

const ISSUED: u64 = 1_700_000_000;

fn seed(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

fn pair(fill: u8) -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).unwrap()}

fn key(fill: u8) -> SigningKey {SigningKey::new(pair(fill).public_key().as_ref().try_into().unwrap()).unwrap()}

fn sign(fill: u8, payload: &[u8]) -> String {envelope::seal(&key(fill), payload, |signed| pair(fill).sign(signed).as_ref().try_into().unwrap())}

fn read(payload: &[u8]) -> Result<Payload, PayloadError> {payload::parse(&envelope::verify(sign(0x11, payload).as_bytes(), &[key(0x11)], BODY_MAX).unwrap())}

fn base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
	bytes.chunks(3).flat_map(|chunk| {
		let bits = chunk.iter().enumerate().fold(0u32, |bits, (index, byte)| bits | u32::from(*byte) << (16 - 8 * index));
		(0..=chunk.len()).map(move |index| alphabet[(bits >> (18 - 6 * index) & 63) as usize] as char)
	}).collect()
}

fn url_base64(bytes: &[u8]) -> String {base64(bytes, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}

fn std_base64(bytes: &[u8]) -> String {
	let text = base64(bytes, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
	format!("{text}{}", "=".repeat((4 - text.len() % 4) % 4))
}

// Sets or removes the member a JSON pointer names.
fn put(document: &mut Value, pointer: &str, value: Option<Value>) {
	let (parent, name) = pointer.rsplit_once('/').unwrap();
	match (document.pointer_mut(parent).unwrap(), value) {
		(Value::Object(members), Some(value)) => drop(members.insert(name.to_owned(), value)),
		(Value::Object(members), None) => drop(members.remove(name)),
		(Value::Array(items), Some(value)) if name.parse() == Ok(items.len()) => items.push(value),
		(Value::Array(items), Some(value)) => items[name.parse::<usize>().unwrap()] = value,
		(Value::Array(items), None) => drop(items.remove(name.parse().unwrap())),
		_ => panic!("{pointer}"),
	}
}

// Every pointer into a document, the containers included.
fn pointers(value: &Value, at: String, out: &mut Vec<String>) {
	match value {
		Value::Object(members) => members.iter().for_each(|(name, member)| pointers(member, format!("{at}/{name}"), out)),
		Value::Array(items) => items.iter().enumerate().for_each(|(index, item)| pointers(item, format!("{at}/{index}"), out)),
		_ => {}
	}
	if !at.is_empty() {out.push(at)}
}

// The characters a link is made of, and a few it must not hold.
const CHANGES: [char; 22] = ['a', 'Z', '0', '9', '.', '/', '#', ':', '-', '_', '%', '?', '@', '=', '+', ' ', '\n', '\0', 'v', '1', '\u{e9}', '\u{202e}'];

// Every text that differs from `text` in exactly one character, by a change, a removal or an addition.
fn neighbours(text: &str) -> Vec<String> {
	let chars: Vec<char> = text.chars().collect();
	(0..=chars.len()).flat_map(|at| {
		let (chars, part) = (chars.clone(), |range: std::ops::Range<usize>| chars[range].iter().collect::<String>());
		let removed = (at < chars.len()).then(|| format!("{}{}", part(0..at), part(at + 1..chars.len())));
		CHANGES.into_iter().flat_map(move |c| [(at < chars.len() && chars[at] != c).then(|| chars.iter().enumerate().map(|(index, old)| if index == at {c} else {*old}).collect::<String>()), Some(chars[..at].iter().chain([&c]).chain(&chars[at..]).collect())]).flatten().chain(removed)
	}).collect()
}

fn signing_key() -> impl Strategy<Value = [u8; 32]> {any::<[u8; 32]>().prop_filter("a key a client may hold", |key| SigningKey::new(*key).is_some())}

fn endpoint() -> impl Strategy<Value = String> {("[a-z][a-z0-9]{0,8}(\\.[a-z][a-z0-9-]{0,6}[a-z0-9]){0,3}", option::of(1..=65_535u16), "(/[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,8}){0,3}/?").prop_map(|(host, port, path)| format!("{host}{}{}", port.map_or(String::new(), |port| format!(":{port}")), if path.is_empty() {"/".to_owned()} else {path}))}

// A subscription as a client is left with it: every count within its limit, every text within its length and free of what the filter removes, every dial address one a document may name.
fn sound(read: &Subscription) {
	let shown = |text: &str, chars: usize| assert!(text.chars().count() <= chars && !text.chars().any(|c| c.is_control() || ('\u{200b}'..='\u{200f}').contains(&c) || ('\u{202a}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c)), "{text:?}");
	assert!((1..=PROFILES_MAX).contains(&read.profiles.len()) && read.profiles.len() + read.refused.len() <= PROFILES_MAX && (1..=2).contains(&read.signing_keys.len()) && read.serial >= 1 && read.expires_at > read.issued_at && read.expires_at - read.issued_at <= 90 * 86_400 && (900..=604_800).contains(&read.update_interval));
	assert!(read.refresh_urls.len() <= REFRESH_URLS_MAX && read.devices.len() <= DEVICES_MAX && read.support.len() <= SUPPORT_MAX && read.cards.len() <= CARDS_MAX && read.notices.len() <= 4 && read.devices.iter().filter(|device| device.this).count() <= 1 && read.logo.as_ref().is_none_or(|logo| (1..=65_536).contains(&logo.data.len())));
	shown(read.provider.as_str(), 64);
	assert!(!read.provider.is_empty() && read.refresh_urls.iter().all(|url| url.as_str().starts_with("https://") && url.as_str().len() <= 256 && !url.as_str().contains('#') && !url.host().contains('@')));
	read.devices.iter().for_each(|device| shown(device.name.as_str(), 32));
	read.support.iter().for_each(|link| shown(link.label.as_str(), 32));
	read.notices.iter().for_each(|notice| assert!(notice.text.as_str().len() <= 280));
	for card in &read.cards {
		match card {
			Card::Stat {label, value, unit} => [(label, 32), (value, 16)].into_iter().chain(unit.as_ref().map(|unit| (unit, 8))).for_each(|(text, chars)| shown(text.as_str(), chars)),
			Card::Progress {label, used, total} => assert!(used <= total && *total > 0 && label.as_str().chars().count() <= 32),
			Card::Notice(notice) => assert!(notice.text.as_str().len() <= 280),
			Card::Link {label, url} => assert!(label.as_str().chars().count() <= 32 && url.as_str().starts_with("https://") && url.as_str().len() <= 512),
		}
	}
	let mut ids = BTreeSet::new();
	for profile in &read.profiles {
		shown(profile.name.as_str(), 64);
		assert!(ids.insert(&profile.id) && !profile.name.is_empty() && (1280..=1500).contains(&profile.mtu) && (1..=4).contains(&profile.parallel) && profile.min_control_version >= 1 && (1..=TRANSPORTS_MAX).contains(&profile.transports.len()) && profile.exits.len() <= 256);
		assert!((1..=2).contains(&profile.device.addresses.len()) && profile.gateways.len() == profile.device.addresses.len() && (1..=2).contains(&profile.device.transport_secrets.len()) && profile.device.private_key.as_ref().is_none_or(|private| public_key(private.expose()) == profile.device.public_key));
		assert!(profile.padding.keepalive.start() + 10_000 <= *profile.padding.keepalive.end() && *profile.padding.keepalive.start() >= 10_000 && *profile.padding.keepalive.end() <= 60_000 && (512..=1023).contains(&profile.padding.wide_max) && (64..=255).contains(&profile.padding.normal_max));
		for transport in &profile.transports {
			let dials: Vec<_> = match transport {
				Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) => endpoints.clone(),
				Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => {
					assert!(stream.path.len() >= 12 && profile.transport_public_key.is_some());
					stream.candidates.iter().for_each(|candidate| assert!(candidate.pins.len() <= PINS_MAX && candidate.sni.is_some() != candidate.verify_name.is_some() && (candidate.pins.is_empty() != matches!(transport, Transport::Tls(_)) || matches!(transport, Transport::Ws(_))) && candidate.ech.as_ref().is_none_or(|ech| (1..=1_024).contains(&ech.len()))));
					stream.candidates.iter().map(|candidate| candidate.address).collect()
				}
			};
			assert!((1..=CANDIDATES_MAX).contains(&dials.len()));
			for address in dials.iter().map(|dial| dial.address()) {assert!(address.port() != 0 && !address.ip().is_loopback() && !address.ip().is_unspecified() && !address.ip().is_multicast() && !address.ip().to_canonical().is_loopback() && address.ip().to_canonical() == address.ip(), "{address}")}
		}
	}
}

// One value to put in the place of a member: of every JSON type, at and around the limits, and of the kinds of text a document holds.
fn replacement() -> impl Strategy<Value = Value> {
	let leaf = prop_oneof![
		Just(Value::Null), any::<bool>().prop_map(Value::from), any::<u64>().prop_map(Value::from), any::<i64>().prop_map(Value::from), any::<f64>().prop_map(|number| json!(number)),
		select(vec![0u64, 1, 2, 4, 5, 9, 10, 16, 17, 60, 61, 64, 65, 255, 256, 257, 899, 900, 1279, 1280, 1500, 1501, 65_535, 65_536, 604_800, 604_801, ISSUED, 9_007_199_254_740_991, 9_007_199_254_740_992]).prop_map(Value::from),
		any::<String>().prop_map(Value::from), "[ -~]{0,40}".prop_map(Value::from), vec(any::<char>(), 0..300).prop_map(|chars| Value::from(chars.into_iter().collect::<String>())),
		select(vec!["", "veilway", "later", "tls", "ws", "fronted", "udp", "udp-obfs", "info", "warning", "none", "unsafe", "main", "direct", "127.0.0.1:443", "[::1]:443", "192.0.2.1:0", "[::ffff:192.0.2.1]:443", "10.0.0.1:1", "192.0.2.1:443", "10.7.0.1", "fd00::1", "node.example.com", "https://example.com/", "http://example.com/", "https://user@example.com/", "/a-path-of-a-transport", "#000000", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="]).prop_map(Value::from),
		any::<[u8; 32]>().prop_map(|bytes| Value::from(std_base64(&bytes))),
	];
	leaf.prop_recursive(3, 24, 6, |inner| prop_oneof![vec(inner.clone(), 0..6).prop_map(Value::from), vec(("[a-z_]{1,8}", inner), 0..4).prop_map(|members| Value::Object(members.into_iter().collect()))])
}

proptest! {
	#[test]
	fn a_native_link_reads_back_and_no_changed_character_passes_for_it(endpoint in endpoint(), key in signing_key(), token in any::<[u8; 16]>()) {
		let fragment = format!("#v1.{}.{}", url_base64(&key), url_base64(&token));
		let (veilway, https) = (format!("veilway://sub/{endpoint}{fragment}"), format!("https://{endpoint}{fragment}"));
		let (Ok(Link::Native(native)), Ok(Link::Native(other))) = (Link::parse(&veilway), Link::parse(&https)) else {panic!("{veilway}")};
		prop_assert_eq!((native.veilway(), native.https(), *native.key().bytes(), *native.token().expose(), &other), (veilway.clone(), https.clone(), key, token, &native));
		let printed = format!("{native:?}");
		prop_assert!(!printed.contains(&url_base64(&token)));
		for (text, form) in [(&veilway, true), (&https, false)] {
			for changed in neighbours(text) {
				match Link::parse(&changed) {
					Err(_) => {}
					// Another link, and well formed: it writes back as the changed text, so the change is in a part the grammar leaves free.
					Ok(Link::Native(read)) => prop_assert!(read != native && changed == if form {read.veilway()} else {read.https()}, "{changed}"),
					// Only the `https` form can lose its `v1` fragment and still be a link: a legacy one, to a URL that holds neither the key nor the token.
					Ok(Link::Legacy(read)) => prop_assert!(!form && changed.starts_with(read.url().as_str()) && !read.url().as_str().contains(&url_base64(&token)), "{changed}"),
					Ok(Link::Carried(_)) => prop_assert!(false, "{changed}"),
				}
			}
		}
	}

	#[test]
	fn a_document_in_a_link_reads_back_and_no_changed_character_passes_for_it(key in signing_key(), document in "[A-Za-z0-9_-]{1,40}\\.[A-Za-z0-9_-]{0,60}\\.[A-Za-z0-9_-]{86}") {
		let content = format!("v1.{}.{document}", url_base64(&key));
		let link = format!("veilway://doc#{content}");
		let (Ok(Link::Carried(carried)), Ok(in_file)) = (Link::parse(&link), Carried::file(content.as_bytes())) else {panic!("{link}")};
		prop_assert_eq!((carried.veilway(), carried.document(), *carried.key().bytes(), in_file.file_content(), in_file.document(), in_file.veilway()), (Some(link.clone()), document.as_bytes(), key, content.clone(), document.as_bytes(), Some(link.clone())));
		for changed in neighbours(&link) {
			match Link::parse(&changed) {
				Err(_) => {}
				Ok(Link::Carried(read)) => prop_assert!(read != carried && read.veilway() == Some(changed.clone()), "{changed}"),
				Ok(_) => prop_assert!(false, "{changed}"),
			}
		}
		for changed in neighbours(&content) {
			// The one change a file may carry and still be this document is the line end an editor adds.
			if let Ok(read) = Carried::file(changed.as_bytes()) {prop_assert!(if changed == format!("{content}\n") {read == in_file} else {read != in_file && read.file_content() == changed.strip_suffix('\n').unwrap_or(&changed)}, "{changed}")}
		}
	}

	#[test]
	fn a_link_reader_takes_any_text(text in prop_oneof![any::<String>(), "(veilway://|https://|veilway://sub/|veilway://doc#)[ -~]{0,200}", "https://[a-z.]{1,20}/[ -~]{0,40}#v1\\.[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{22}"], bytes in vec(any::<u8>(), 0..200)) {
		match Link::parse(&text) {
			Err(_) => {}
			Ok(Link::Native(native)) => prop_assert!(Link::parse(&native.veilway()) == Ok(Link::Native(native.clone())) && (text == native.veilway() || text == native.https())),
			Ok(Link::Carried(carried)) => prop_assert_eq!(carried.veilway(), Some(text.clone())),
			// A legacy link never comes out of the project's own scheme.
			Ok(Link::Legacy(legacy)) => prop_assert!(text.starts_with(legacy.url().as_str()) && !text.starts_with("veilway")),
		}
		if let Ok(carried) = Carried::file(&bytes) {prop_assert_eq!(carried.file_content().into_bytes(), bytes)}
	}

	#[test]
	fn a_request_reads_back_as_it_was_written(token in any::<[u8; 16]>(), kids in vec(any::<[u8; 8]>(), 1..=2), device in any::<[u8; 32]>(), secret in any::<[u8; 16]>(), op in 0..3usize, name in option::of(any::<String>()), at in any::<Index>(), byte in any::<u8>()) {
		prop_assume!(kids.len() == 1 || kids[0] != kids[1]);
		let (device, name) = (public_key(&device), name.and_then(|name| DeviceName::typed(&name)).filter(|_| op == 1));
		let body = format!("{{\"v\":1,\"token\":\"{}\",\"kids\":[{}],\"device_public_key\":\"{}\",\"device_secret\":\"{}\",\"op\":\"{}\"{}}}", url_base64(&token), kids.iter().map(|kid| format!("\"{}\"", url_base64(kid))).collect::<Vec<_>>().join(","), std_base64(&device), url_base64(&secret), ["fetch", "confirm", "release"][op], name.as_ref().map_or(String::new(), |name| format!(",\"device_name\":{}", serde_json::to_string(name.as_str()).unwrap())));
		let request = Received::read(body.as_bytes()).unwrap();
		prop_assert_eq!((String::from_utf8(request.canonical()).unwrap(), request.token().expose(), request.device_public_key(), request.device_secret().expose(), request.kids().iter().map(|kid| kid.bytes()).collect::<Vec<_>>()), (body.clone(), &token, &device, &secret, kids));
		// One byte changed: refused, or another request that is written back as it reads.
		let mut changed = body.into_bytes();
		let at = at.index(changed.len());
		changed[at] = byte;
		if let Ok(read) = Received::read(&changed) {prop_assert_eq!(Received::read(&read.canonical()), Ok(read))}
	}

	#[test]
	fn a_request_reader_takes_any_bytes(bytes in vec(any::<u8>(), 0..400)) {
		if let Ok(read) = Received::read(&bytes) {prop_assert_eq!(Received::read(&read.canonical()), Ok(read))}
	}

	#[test]
	fn a_flipped_bit_in_a_signed_document_is_refused(name in select(vec!["document", "carried", "refusal", "two-keys", "second-key"]), at in any::<Index>(), bit in 0..8u8) {
		let mut document = seed(&format!("fuzz_sub_envelope/{name}"))[1..].to_vec();
		prop_assert!(envelope::verify(&document, &[key(0x11), key(0x22)], BODY_MAX).is_ok());
		let at = at.index(document.len());
		document[at] ^= 1 << bit;
		prop_assert!(envelope::verify(&document, &[key(0x11), key(0x22)], BODY_MAX).is_err());
	}

	#[test]
	fn the_envelope_takes_any_bytes(bytes in vec(any::<u8>(), 0..600), text in "[A-Za-z0-9_.=-]{0,300}") {
		prop_assert!(envelope::verify(&bytes, &[key(0x11), key(0x22)], BODY_MAX).is_err() && envelope::verify(text.as_bytes(), &[key(0x11)], BODY_MAX).is_err());
		// The canonical form of a part is what the decoder of the rest of the crate takes, no more and no less: a payload part that is in it reaches the signature check, and one that is not does not.
		let header = url_base64(key(0x11).header().as_bytes());
		let part: String = text.chars().filter(|c| *c != '.').collect();
		let strict = part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') && part.len() % 4 != 1 && url_base64(&decode(&part)) == part;
		prop_assert_eq!(envelope::verify(format!("{header}.{part}.{}", "A".repeat(86)).as_bytes(), &[key(0x11)], BODY_MAX).err(), Some(if strict {EnvelopeError::Signature} else {EnvelopeError::Encoding}));
	}

	#[test]
	fn a_payload_reader_takes_any_bytes_behind_a_signature(bytes in vec(any::<u8>(), 0..300), text in "[ -~]{0,200}", at in any::<Index>(), byte in any::<u8>()) {
		let (object, _) = (bytes.first() == Some(&0x7b), read(text.as_bytes()));
		prop_assert!(read(&bytes).is_err() || object);
		// A good payload with one byte changed.
		let mut changed = seed("fuzz_subscription/content")[1..].to_vec();
		let at = at.index(changed.len());
		changed[at] = byte;
		if let Ok(Payload::Subscription(read)) = read(&changed) {sound(&read)}
	}

	#[test]
	fn a_good_document_with_one_member_changed_reads_soundly_or_not_at_all(at in any::<Index>(), value in option::of(replacement()), extra in "[a-z_]{1,12}") {
		let mut document: Value = serde_json::from_slice(&seed("fuzz_subscription/content")[1..]).unwrap();
		let mut all = Vec::new();
		pointers(&document, String::new(), &mut all);
		let pointer = at.get(&all).clone();
		// The member is replaced or removed, and the same value is added under a name of its own beside it.
		if let (Some(value), Some(Value::Object(members))) = (&value, document.pointer_mut(pointer.rsplit_once('/').unwrap().0)) {members.entry(extra).or_insert(value.clone());}
		put(&mut document, &pointer, value);
		match read(&serde_json::to_vec(&document).unwrap()) {
			Ok(Payload::Subscription(read)) => sound(&read),
			Ok(Payload::Refusal(refusal)) => prop_assert!(Reason::ALL.contains(&refusal.reason)),
			Err(_) => {}
		}
	}

	#[test]
	fn the_legacy_reader_takes_any_bytes(bytes in vec(any::<u8>(), 0..400), lines in vec(prop_oneof!["(vless|trojan|ss|vmess|other)://[ -~]{0,80}", "(vless|trojan)://[a-z0-9-]{1,36}@[a-z0-9.-]{1,30}:[0-9]{1,5}(\\?[a-zA-Z=&%0-9]{0,40})?(#[ -~]{0,20})?"], 0..300), name in "[a-zA-Z-]{0,30}") {
		let _ = legacy::list(&bytes);
		let _ = legacy::headers(&[(&name, &bytes), ("subscription-userinfo", &bytes), ("profile-title", &bytes), ("profile-update-interval", &bytes), ("support-url", &bytes)]);
		for body in [lines.join("\n"), std_base64(lines.join("\r\n").as_bytes())] {
			if let Ok(list) = legacy::list(body.as_bytes()) {
				prop_assert!(list.entries.len() + list.skipped <= 256 && list.cut == (lines.iter().filter(|line| !line.trim().is_empty()).count() > 256));
				let hidden = list.entries.iter().all(|entry| format!("{:?}", entry.credential) == "Credential(..)" && format!("{entry:?}").len() < 40 && !matches!(&entry.server, legacy::Server::Address(address) if !payload::dialable(*address)));
				prop_assert!(hidden && list.entries.iter().all(|entry| entry.port != 0 && entry.name.as_str().chars().count() <= 64 && !entry.name.as_str().chars().any(char::is_control) && !entry.credential.expose().is_empty()));
			}
		}
	}
}

fn decode(part: &str) -> Vec<u8> {
	let value = |c: u8| b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".iter().position(|letter| *letter == c).unwrap() as u32;
	part.as_bytes().chunks(4).flat_map(|chunk| {
		let bits = chunk.iter().enumerate().fold(0, |bits, (index, c)| bits | value(*c) << (18 - 6 * index));
		(0..chunk.len().saturating_sub(1)).map(move |index| (bits >> (16 - 8 * index)) as u8)
	}).collect()
}

// Every bit of a signed refusal, which is short enough to try them all.
#[test]
fn every_flipped_bit_of_a_signed_refusal_is_refused() {
	let document = seed("fuzz_sub_envelope/refusal")[1..].to_vec();
	for (at, bit) in (0..document.len()).flat_map(|at| (0..8).map(move |bit| (at, bit))) {
		let mut flipped = document.clone();
		flipped[at] ^= 1 << bit;
		assert!(envelope::verify(&flipped, &[key(0x11)], BODY_MAX).is_err(), "byte {at}, bit {bit}");
	}
}

// What a provider, or whoever answers in its place, may send to a client that holds a subscription.
#[derive(Debug, Clone)]
enum Event {
	// A document: who signed it (0 and 1 are the provider's two keys, 2 is a key no client holds), which of the three keys it lists as a mask, whether it is another account's, its serial, when it was issued relative to the clock, how long it lives, a member that changes nothing but the bytes, what it does to the device's key (1 names another, 2 adds a private key), and which refresh hosts it lists.
	Document {signer: usize, listed: usize, other: bool, serial: u64, issued: i64, life: u64, note: u8, device: u8, hosts: usize},
	Refusal {signer: usize, other: bool, age: i64},
	// The last good document once more.
	Again,
	Garbage(Vec<u8>),
	// The user confirms the hosts of this mask.
	Confirm(usize),
	// Time passes.
	Tick(u64),
}

const FILLS: [u8; 3] = [0x11, 0x22, 0x99];
// Refresh hosts with their ports. The last is the endpoint of the link, which needs no confirmation.
const HOSTS: [&str; 3] = ["mirror.example.net:443", "other.example.org:8443", "sub.example.com:443"];

fn event() -> impl Strategy<Value = Event> {
	prop_oneof![
		8 => (prop_oneof![4 => Just(0usize), 3 => Just(1usize), 1 => Just(2usize)], select(vec![1usize, 1, 2, 3, 3, 3, 5, 6]), prop::bool::weighted(0.08), 1..7u64, select(vec![-10i64, 0, 0, 0, 50, 300, 301]), select(vec![10u64, 86_400, 30 * 86_400]), 0..2u8, prop_oneof![10 => Just(0u8), 1 => Just(1u8), 1 => Just(2u8)], 0..8usize).prop_map(|(signer, listed, other, serial, issued, life, note, device, hosts)| Event::Document {signer, listed, other, serial, issued, life, note, device, hosts}),
		1 => (0..3usize, prop::bool::weighted(0.2), select(vec![0i64, 86_400, 86_401, -300, -301])).prop_map(|(signer, other, age)| Event::Refusal {signer, other, age}),
		1 => Just(Event::Again),
		1 => vec(any::<u8>(), 0..64).prop_map(Event::Garbage),
		1 => (0..8usize).prop_map(Event::Confirm),
		1 => select(vec![1u64, 60, 86_400, 20 * 86_400, 40 * 86_400]).prop_map(Event::Tick),
	]
}

// The rules of "Keys held", "Identity", "Rollback and expiry" and "Device keys" a second time, over what the test itself knows about each document.
struct Model {keys: Vec<usize>, serial: u64, issued: u64, expires: u64, document: String, listed: Vec<&'static str>, confirmed: BTreeSet<&'static str>}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(96))]
	#[test]
	fn what_is_held_follows_the_model(events in vec(event(), 1..24)) {
		let Offer::Native(offer) = Offer::open(Link::parse(std::str::from_utf8(&seed("fuzz_deeplink/native-veilway")).unwrap()).unwrap()) else {panic!("a native link")};
		let first = seed("fuzz_sub_envelope/document")[1..].to_vec();
		let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
			bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
			Ok(())
		};
		let mut held: Held = offer.proceed(None, &mut random).unwrap().answer(&first, ISSUED + 100, &[]).unwrap().accept(None, &[]).unwrap().held;
		let base: Value = serde_json::from_slice(envelope::verify(&first, &[key(0x11)], BODY_MAX).unwrap().payload()).unwrap();
		let (mut model, mut now) = (Model {keys: vec![0], serial: 1, issued: ISSUED, expires: ISSUED + 30 * 86_400, document: String::from_utf8(first).unwrap(), listed: Vec::new(), confirmed: BTreeSet::from([HOSTS[2]])}, ISSUED + 100);
		for event in events {
			let before = held.clone();
			let (answer, expected): (Vec<u8>, Option<Result<bool, Failure>>) = match &event {
				Event::Document {signer, listed, other, serial, issued, life, note, device, hosts} => {
					let (mut document, issued_at, keys, urls) = (base.clone(), now.saturating_add_signed(*issued), (0..3).filter(|index| listed >> index & 1 == 1).collect::<Vec<_>>(), (0..3).filter(|index| hosts >> index & 1 == 1).map(|index| HOSTS[index]).collect::<Vec<_>>());
					for (pointer, value) in [("/serial", json!(serial)), ("/issued_at", json!(issued_at)), ("/expires_at", json!(issued_at + life)), ("/signing_keys", json!(keys.iter().map(|index| std_base64(key(FILLS[*index]).bytes())).collect::<Vec<_>>())), ("/note", json!(note)), ("/refresh_urls", json!(urls.iter().map(|host| format!("https://{host}/s")).collect::<Vec<_>>()))] {put(&mut document, pointer, Some(value))}
					if *other {put(&mut document, "/subscription_id", Some(json!("another-account-0002")))}
					if *device == 1 {put(&mut document, "/profiles/0/device/public_key", Some(json!(std_base64(&public_key(&[0x34; 32])))))}
					if *device == 2 {put(&mut document, "/profiles/0/device/private_key", Some(json!(std_base64(&[0x33; 32]))))}
					let answer = sign(FILLS[*signer], &serde_json::to_vec(&document).unwrap());
					let verdict = if !model.keys.contains(signer) {Err(Failure::Envelope(EnvelopeError::UnknownKey))} else if !keys.contains(signer) {Err(Failure::Payload(PayloadError::Signer))} else if *other {Err(Failure::OtherSubscription)} else if issued_at > now + 300 {Err(Failure::Future)} else if issued_at + life <= now {Err(Failure::Expired)} else if *serial < model.serial {Err(Failure::Rollback)} else if *serial == model.serial {if answer == model.document {Ok(false)} else {Err(Failure::Fork)}} else if issued_at < model.issued {Err(Failure::Backdated)} else if *device == 1 {Err(Failure::DeviceKey)} else if *device == 2 {Err(Failure::PrivateKey)} else {Ok(true)};
					if verdict == Ok(true) {
						// A host stays confirmed only while documents list it.
						model.confirmed.retain(|host| urls.contains(host) || *host == HOSTS[2]);
						(model.keys, model.serial, model.issued, model.expires, model.document, model.listed) = (keys, *serial, issued_at, issued_at + life, answer.clone(), urls);
					}
					(answer.into_bytes(), Some(verdict))
				}
				Event::Refusal {signer, other, age} => {
					let issued_at = now.saturating_add_signed(-age);
					let verdict = if !model.keys.contains(signer) {Failure::Envelope(EnvelopeError::UnknownKey)} else if *other {Failure::OtherSubscription} else if *age > 86_400 || *age < -300 {Failure::StaleRefusal} else {Failure::Refused(Reason::Disabled)};
					(sign(FILLS[*signer], &serde_json::to_vec(&json!({"v": 1, "subscription_id": if *other {"another-account-0002"} else {"example-account-0001"}, "issued_at": issued_at, "refusal": "disabled"})).unwrap()).into_bytes(), Some(Err(verdict)))
				}
				Event::Again => (model.document.clone().into_bytes(), Some(if model.expires <= now {Err(Failure::Expired)} else {Ok(false)})),
				Event::Garbage(bytes) => (bytes.clone(), None),
				Event::Confirm(mask) => {
					let seen: Vec<&str> = (0..3).filter(|index| mask >> index & 1 == 1).map(|index| HOSTS[index]).collect();
					held.confirm_hosts(&seen);
					// Only a host the last good document lists can be confirmed.
					model.confirmed.extend(seen.iter().filter(|host| model.listed.contains(host)));
					continue;
				}
				Event::Tick(seconds) => {
					now += seconds;
					continue;
				}
			};
			let verdict = held.refresh(&answer, now);
			match (&verdict, expected) {
				(Ok(Refreshed::Updated(changes)), Some(Ok(true))) => prop_assert_eq!(changes.rotated, before.keys() != held.keys(), "{:?}", event),
				(Ok(Refreshed::Unchanged), Some(Ok(false))) => {}
				(Err(failure), Some(Err(expected))) => prop_assert_eq!(*failure, expected, "{:?}", event),
				(Err(_), None) => {}
				(verdict, expected) => prop_assert!(false, "{:?}: {:?}, expected {:?}", event, verdict, expected),
			}
			// Nothing but a document that was taken changes what is held.
			if !matches!(verdict, Ok(Refreshed::Updated(_))) {prop_assert_eq!(&held, &before, "{:?}", event)}
			// What is held is what the model holds: the keys, the serial and the bytes of the last good document.
			prop_assert_eq!((held.keys().to_vec(), held.subscription().serial, held.document(), held.subscription().expires_at), (model.keys.iter().map(|index| key(FILLS[*index])).collect::<Vec<_>>(), model.serial, model.document.as_str(), model.expires));
			// A request goes only to the endpoint of the link and to refresh hosts the user has confirmed, and to every one of those the document lists.
			let hosts: BTreeSet<String> = held.endpoints().iter().map(|url| url.authority()).collect();
			prop_assert_eq!(&hosts, &model.listed.iter().copied().filter(|host| model.confirmed.contains(host)).chain([HOSTS[2]]).map(str::to_owned).collect::<BTreeSet<_>>(), "{:?}", event);
			prop_assert_eq!(held.unconfirmed().into_iter().collect::<BTreeSet<_>>(), model.listed.iter().copied().filter(|host| !model.confirmed.contains(host)).map(str::to_owned).collect::<BTreeSet<_>>());
			prop_assert!(Held::restore(held.stored()).is_ok_and(|restored| restored == held));
		}
	}
}
