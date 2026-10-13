#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{collections::HashSet, sync::OnceLock};
use veilway_proto::{control, proof::public_key, subscription::{client::{Held, Offer, Refreshed}, envelope::{self, SigningKey}, is_host, link::{Carried, Link}, payload::{self, Card, Payload, Subscription, Transport, CANDIDATES_MAX, CARDS_MAX, DEVICES_MAX, INTEGER_MAX, LIFETIME_MAX, LOGO_MAX, PINS_MAX, PROFILES_MAX, REFRESH_URLS_MAX, SUPPORT_MAX, TRANSPORTS_MAX, UPDATE_INTERVAL}, BODY_MAX, LINK_URL_MAX, URL_MAX}};

// The payload of a whole document of tests/vectors.py, with a provider-issued device key, after one byte of settings. The file that carries it starts with the key it is signed under.
const IMPORT: &[u8] = include_bytes!("../corpus/fuzz_subscription/import");
const FILE: &str = include_str!("../corpus/fuzz_deeplink/file");
// The native link of the seeds, and the first document its endpoint answers with: one profile whose device made its own key. Its first byte is the settings byte of the seed.
const LINK: &str = include_str!("../corpus/fuzz_deeplink/native-veilway");
const DOCUMENT: &[u8] = include_bytes!("../corpus/fuzz_sub_envelope/document");
// The clock: 100 s after the documents of the seeds were issued.
const NOW: u64 = 1_700_000_100;

fn pairs() -> &'static [(Ed25519KeyPair, SigningKey); 2] {
	static PAIRS: OnceLock<[(Ed25519KeyPair, SigningKey); 2]> = OnceLock::new();
	PAIRS.get_or_init(|| [0x11, 0x22].map(|fill| {
		let pair = Ed25519KeyPair::from_seed_unchecked(&[fill; 32]).expect("a seed is 32 bytes");
		let key = SigningKey::new(pair.public_key().as_ref().try_into().expect("a public key is 32 bytes")).expect("a key from a seed is of full order");
		(pair, key)
	}))
}

fn sealed(signer: usize, payload: &[u8]) -> String {envelope::seal(&pairs()[signer].1, payload, |signed| pairs()[signer].0.sign(signed).as_ref().try_into().expect("a signature is 64 bytes"))}

// A whole document through the three steps of an import, as a file.
fn import(document: &str) -> Option<Held> {
	let Offer::Carried(offer) = Offer::open(Link::Carried(Carried::file(format!("{}{document}", &FILE[..47]).as_bytes()).ok()?)) else {return None};
	let review = offer.proceed(NOW, &[]).ok()?;
	let accepted = review.accept(None, &[]).expect("nothing is stored that an import could run into");
	assert!(accepted.confirm.is_none() && accepted.replaces.is_none(), "a whole document gave a request");
	Some(accepted.held)
}

// The subscription of the seeds as a client holds it after an import by its link: a device that made its own key (33..33, with the secret 44..44), and an endpoint to refresh by.
fn linked() -> Held {
	let Ok(Link::Native(link)) = Link::parse(LINK) else {panic!("the seed is a native link")};
	let Offer::Native(offer) = Offer::open(Link::Native(link)) else {panic!("a native link is offered as one")};
	let fetching = offer.proceed(None, &mut |bytes: &mut [u8]| {
		bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
		Ok(())
	}).expect("the random source works");
	fetching.answer(&DOCUMENT[1..], NOW, &[]).expect("the seed is the document of the link").accept(None, &[]).expect("nothing is stored").held
}

// What every document a client is left with keeps, whatever the provider wrote: each count within its limit, each text within its length and free of what the filter removes, each address one a document may name.
fn sound(read: &Subscription) {
	let shown = |text: &str, chars: usize| assert!(text.chars().count() <= chars && control::display(text, usize::MAX, usize::MAX) == text, "display text that was not filtered and cut");
	assert!((1..=PROFILES_MAX).contains(&read.profiles.len()) && read.profiles.len() + read.refused.len() <= PROFILES_MAX && (1..=2).contains(&read.signing_keys.len()) && (1..=INTEGER_MAX).contains(&read.serial) && read.expires_at > read.issued_at && read.expires_at - read.issued_at <= LIFETIME_MAX && UPDATE_INTERVAL.contains(&u64::from(read.update_interval)), "a top-level value outside its range");
	assert!(read.refresh_urls.len() <= REFRESH_URLS_MAX && read.devices.len() <= DEVICES_MAX && read.support.len() <= SUPPORT_MAX && read.cards.len() <= CARDS_MAX && read.notices.len() <= control::NOTICES_MAX && read.devices.iter().filter(|device| device.this).count() <= 1 && read.logo.as_ref().is_none_or(|logo| (1..=LOGO_MAX).contains(&logo.data.len())), "a list over its limit");
	shown(read.provider.as_str(), 64);
	assert!(!read.provider.is_empty() && read.refresh_urls.iter().all(|url| url.as_str().starts_with("https://") && url.as_str().len() <= LINK_URL_MAX && !url.as_str().contains('#') && url.as_str()[8..].starts_with(url.host()) && is_host(url.host())), "a refresh URL that is none");
	read.devices.iter().for_each(|device| shown(device.name.as_str(), 32));
	read.support.iter().for_each(|link| {
		shown(link.label.as_str(), 32);
		assert!(link.url.as_str().starts_with("https://") && link.url.as_str().len() <= URL_MAX);
	});
	read.notices.iter().for_each(|notice| assert!(notice.text.as_str().len() <= control::NOTICE_MAX));
	for card in &read.cards {
		match card {
			Card::Stat {label, value, unit} => [(label, 32), (value, 16)].into_iter().chain(unit.as_ref().map(|unit| (unit, 8))).for_each(|(text, chars)| shown(text.as_str(), chars)),
			Card::Progress {label, used, total} => assert!(used <= total && *total > 0 && *total <= INTEGER_MAX && label.as_str().chars().count() <= 32),
			Card::Notice(notice) => assert!(notice.text.as_str().len() <= control::NOTICE_MAX),
			Card::Link {label, url} => assert!(label.as_str().chars().count() <= 32 && url.as_str().starts_with("https://") && url.as_str().len() <= URL_MAX),
		}
	}
	let mut ids = HashSet::new();
	for profile in &read.profiles {
		shown(profile.name.as_str(), 64);
		assert!(ids.insert(&profile.id) && !profile.name.is_empty() && (1280..=1500).contains(&profile.mtu) && (1..=4).contains(&profile.parallel) && profile.min_control_version >= 1 && (1..=TRANSPORTS_MAX).contains(&profile.transports.len()) && profile.exits.len() <= control::EXITS_MAX && profile.exits.iter().all(|exit| control::is_tag(&exit.tag) && !exit.name.is_empty()), "a profile outside its ranges");
		assert!((1..=2).contains(&profile.device.addresses.len()) && profile.gateways.len() == profile.device.addresses.len() && (1..=2).contains(&profile.device.transport_secrets.len()) && profile.device.private_key.as_ref().is_none_or(|private| public_key(private.expose()) == profile.device.public_key), "device keys that do not hold together");
		assert!(profile.padding.keepalive.start() + 10_000 <= *profile.padding.keepalive.end() && *profile.padding.keepalive.start() >= 10_000 && *profile.padding.keepalive.end() <= 60_000 && (512..=1023).contains(&profile.padding.wide_max) && (64..=255).contains(&profile.padding.normal_max), "padding outside its ranges");
		for transport in &profile.transports {
			let dials: Vec<_> = match transport {
				Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) => endpoints.clone(),
				Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => {
					assert!(stream.path.len() >= 12 && stream.path.starts_with('/') && profile.transport_public_key.is_some(), "a stream transport without its path or key");
					stream.candidates.iter().for_each(|candidate| assert!(candidate.pins.len() <= PINS_MAX && candidate.sni.is_some() != candidate.verify_name.is_some() && (matches!(transport, Transport::Ws(_)) || candidate.pins.is_empty() != matches!(transport, Transport::Tls(_))) && candidate.ech.as_ref().is_none_or(|ech| (1..=1_024).contains(&ech.len())), "a candidate that breaks the rule of its transport"));
					stream.candidates.iter().map(|candidate| candidate.address).collect()
				}
			};
			assert!((1..=CANDIDATES_MAX).contains(&dials.len()));
			for address in dials.iter().map(|dial| dial.address()) {assert!(address.port() != 0 && !address.ip().is_loopback() && !address.ip().is_unspecified() && !address.ip().is_multicast() && address.ip().to_canonical() == address.ip(), "a dial address a document may not name")}
		}
	}
}

// The payload reader behind a good signature, and what a client then decides. The first byte is settings and the rest is the payload, which is sealed here under a key the client holds, so every byte of it reaches the reader.
//   bit 0  clear: the document is the answer to a refresh. Set: it is a whole document in a file, imported.
//   bit 1  the document is signed by the second key, which the client does not hold.
//   bit 2  who refreshes. Clear: a client that holds the whole document of the seeds, with a key the provider issued and no link. Set: a client that imported the link of the seeds, with a key its device made and an endpoint.
// A payload that reads must be sound. A refresh that fails must leave what is held exactly as it was. One that is taken must be signed by a held key, of the same subscription, of a higher serial and not issued earlier, and must bring no device key the client did not have. A request may go only to the endpoint of the link and to hosts the user confirmed, and nowhere at all for a whole document. What is held must go to storage and come back the same.
fuzz_target!(|data: &[u8]| {
	let Some((mode, payload)) = data.split_first() else {return};
	let (signer, held) = (usize::from(mode & 2 != 0), [pairs()[0].1, pairs()[1].1]);
	let document = sealed(signer, payload);
	let read = payload::parse(&envelope::verify(document.as_bytes(), &held, BODY_MAX).expect("a document sealed here verifies"));
	if let Ok(Payload::Subscription(read)) = &read {sound(read)}
	if mode & 1 == 1 {
		let Some(imported) = import(&document) else {return};
		assert!(signer == 0 && matches!(&read, Ok(Payload::Subscription(read)) if **read == *imported.subscription()), "an import took what does not read, or what the key of the link did not sign");
		assert!(imported.fetch().is_none() && imported.endpoints().is_empty() && imported.unconfirmed().is_empty() && imported.stored().hosts.is_empty() && imported.subscription().expires_at > NOW && imported.subscription().profiles.iter().all(|profile| profile.device.private_key.is_some()), "a whole document that is not one");
		assert!(Held::restore(imported.stored()).is_ok_and(|restored| restored == imported), "what is held did not come back from storage");
		assert!(!format!("{imported:?}").contains(&document), "what is held printed its document");
		return;
	}
	static BASES: OnceLock<[Held; 2]> = OnceLock::new();
	let (with_link, bases) = (mode & 4 != 0, BASES.get_or_init(|| [import(&sealed(0, &IMPORT[1..])).expect("the seed is a whole document"), linked()]));
	let mut client = bases[usize::from(with_link)].clone();
	let before = client.clone();
	match client.refresh(document.as_bytes(), NOW) {
		Ok(Refreshed::Updated(changes)) => {
			assert!(signer == 0 && client.subscription().serial > before.subscription().serial && client.subscription().issued_at >= before.subscription().issued_at && client.id() == before.id() && client.document() == document && client.subscription().expires_at > NOW && client.keys().contains(&held[0]), "a refresh was taken that the rules refuse");
			assert!(client.subscription().profiles.iter().all(|profile| profile.device.private_key.is_some() != with_link && before.subscription().profiles.iter().any(|old| old.device.public_key == profile.device.public_key) && client.device().is_none_or(|device| *device.public() == profile.device.public_key)), "a refresh changed a device key");
			// Nothing was confirmed, so the token goes to the host and port of the link and nowhere else, and every other host the document lists waits for the user.
			assert!(client.endpoints().iter().all(|url| url.authority() == "sub.example.com:443") && (with_link || client.endpoints().is_empty()) && client.unconfirmed() == changes.hosts && (with_link || changes.hosts.is_empty()), "a request may go somewhere the user has not confirmed");
			assert!(client.subscription().refresh_urls.iter().all(|url| url.authority() == "sub.example.com:443" || changes.hosts.contains(&url.authority()) || !with_link), "a refresh host is neither the link's nor waiting");
			// The user confirms what waits: from then on those URLs are endpoints, and no other.
			let waiting: Vec<&str> = changes.hosts.iter().map(String::as_str).collect();
			client.confirm_hosts(&waiting);
			assert!(client.unconfirmed().is_empty() && client.endpoints().len() == usize::from(with_link) * (1 + client.subscription().refresh_urls.len()), "a confirmed host is not an endpoint");
			assert!(Held::restore(client.stored()).is_ok_and(|restored| restored == client), "what is held did not come back from storage");
			assert!(!format!("{client:?}").contains(&document), "what is held printed its document");
		}
		Ok(Refreshed::Unchanged) => assert!(client == before && document == before.document(), "other bytes were taken as the same document"),
		Err(_) => assert!(client == before, "a refresh that failed changed what is held"),
	}
});
