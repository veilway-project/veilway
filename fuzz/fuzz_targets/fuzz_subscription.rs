#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{collections::HashSet, sync::OnceLock};
use veilway_proto::{control, proof::public_key, subscription::{client::{Held, Offer, Refreshed, Role}, envelope::{self, SigningKey}, is_host, link::{Carried, Link}, payload::{self, Card, Cause, Payload, Subscription, Transport, CANDIDATES_MAX, CARDS_MAX, DEVICES_MAX, INTEGER_MAX, LIFETIME_MAX, LOGO_MAX, PINS_MAX, PROFILES_MAX, REFRESH_URLS_MAX, SUPPORT_MAX, TRANSPORTS_MAX, UPDATE_INTERVAL}, Tag, Text, BODY_MAX, LINK_URL_MAX, TAG_MAX, TRANSLATIONS_MAX, URL_MAX}};

// The payload of a whole document of tests/vectors.py, with a provider-issued device key, after one byte of settings. The file that carries it starts with the key it is signed under.
const IMPORT: &[u8] = include_bytes!("../corpus/fuzz_subscription/import");
const FILE: &str = include_str!("../corpus/fuzz_deeplink/file");
// The native link of the seeds, and the first document its endpoint answers with: one profile whose device made its own key. Its first byte is the settings byte of the seed.
const LINK: &str = include_str!("../corpus/fuzz_deeplink/native-veilway");
// The same endpoint with the pin of its own certificate in the link, held for the document as for the one above.
const PINNED_LINK: &str = include_str!("../corpus/fuzz_deeplink/native-pinned");
// A first document for the pinned link that already lists pinned refresh entries, so the client holds them confirmed, one of them on the link's own host and port.
const PINNED_DOCUMENT: &[u8] = include_bytes!("../corpus/fuzz_subscription/refresh-with-pinned-link");
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
fn linked(link: &str, document: &[u8]) -> Held {
	let Ok(Link::Native(link)) = Link::parse(link) else {panic!("the seed is a native link")};
	let Offer::Native(offer) = Offer::open(Link::Native(link)) else {panic!("a native link is offered as one")};
	let fetching = offer.proceed(None, &mut |bytes: &mut [u8]| {
		bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
		Ok(())
	}).expect("the random source works");
	fetching.answer(document, NOW, &[]).expect("the seed is the document of the link").accept(None, &[]).expect("nothing is stored").held
}

// What every document a client is left with keeps, whatever the provider wrote: each count within its limit, each text within its length and free of what the filter removes, each address one a document may name.
fn sound(read: &Subscription) {
	let plain = |text: &str, chars: usize, bytes: usize| assert!(text.chars().count() <= chars && text.len() <= bytes && control::display(text, usize::MAX, usize::MAX) == text, "display text that was not filtered and cut");
	// A text in every language it has: at most 8 translations, each under a tag that is one and no tag twice, none empty, each held to what `default` is held to.
	let shown = |text: &Text, chars: usize, bytes: usize| {
		plain(text.as_str(), chars, bytes);
		assert!(text.translations().count() <= TRANSLATIONS_MAX && text.translations().all(|translation| Tag::read(translation.tag.as_str()).as_ref() == Some(translation.tag) && translation.tag.as_str().len() <= TAG_MAX && !translation.text.is_empty()) && text.translations().map(|translation| translation.tag).collect::<HashSet<_>>().len() == text.translations().count(), "a translation that is none");
		text.translations().for_each(|translation| plain(translation.text, chars, bytes));
		// Picking never panics and gives a text the document holds, whatever the app asks for.
		let asked: Vec<Tag> = text.translations().map(|translation| translation.tag.clone()).chain(["und", "fa-Arab-IR", "en"].into_iter().filter_map(Tag::read)).collect();
		assert!(asked.iter().all(|tag| text.translation(std::slice::from_ref(tag)).is_none_or(|picked| picked.tag.parts().0 == tag.parts().0 && tag.parts().0 != "und")) && text.decided(&asked).0 == text.as_str() && text.pick(&[]) == (text.as_str(), None), "a translation was picked that was not asked for");
	};
	assert!((1..=PROFILES_MAX).contains(&read.profiles.len()) && read.profiles.len() + read.refused.len() <= PROFILES_MAX && (1..=2).contains(&read.signing_keys.len()) && (1..=INTEGER_MAX).contains(&read.serial) && read.expires_at > read.issued_at && read.expires_at - read.issued_at <= LIFETIME_MAX && UPDATE_INTERVAL.contains(&u64::from(read.update_interval)), "a top-level value outside its range");
	assert!(read.refresh_urls.len() <= REFRESH_URLS_MAX && read.devices.len() <= DEVICES_MAX && read.support.len() <= SUPPORT_MAX && read.cards.len() <= CARDS_MAX && read.notices.len() <= control::NOTICES_MAX && read.devices.iter().filter(|device| device.this).count() <= 1 && read.logo.as_ref().is_none_or(|logo| (1..=LOGO_MAX).contains(&logo.data.len())), "a list over its limit");
	shown(&read.provider, 64, 256);
	assert!(read.provider.visible() &&read.refresh_urls.iter().all(|url| url.as_str().starts_with(if url.is_plain() {"http://"} else {"https://"}) && url.as_str().len() <= LINK_URL_MAX && !url.as_str().contains('#') && url.as_str()[if url.is_plain() {7} else {8}..].starts_with(url.host()) && if let Some(address) = url.literal() {(url.pinned() || url.is_plain()) && !(url.pinned() && url.is_plain()) && payload::dialable(address) && !is_host(url.host()) && url.host() == match address {std::net::IpAddr::V4(ip) => ip.to_string(), std::net::IpAddr::V6(ip) => format!("[{ip}]")}} else {is_host(url.host())}), "a refresh URL that is none");
	assert!(read.refresh_urls.iter().all(|entry| entry.pins().len() <= 2 && entry.pins().windows(2).all(|pair| pair[0] != pair[1])) && read.refresh_urls.iter().enumerate().all(|(place, entry)| read.refresh_urls[..place].iter().all(|earlier| earlier.authority() != entry.authority() || earlier.kind() == entry.kind())) && read.endpoint_pins.len() <= 2 && read.endpoint_pins.windows(2).all(|pair| pair[0] != pair[1]), "pins that are none, or entries of one host and port of two kinds");
	read.devices.iter().for_each(|device| {
		plain(device.name.as_str(), 32, 128);
		assert!(device.name.translations().count() == 0, "a device's name in several languages");
	});
	read.support.iter().for_each(|link| {
		shown(&link.label, 32, 128);
		assert!(link.url.as_str().starts_with("https://") && link.url.as_str().len() <= URL_MAX);
	});
	read.notices.iter().for_each(|notice| shown(&notice.text, usize::MAX, control::NOTICE_MAX));
	for card in &read.cards {
		match card {
			Card::Stat {label, value, unit} => [(label, 32), (value, 16)].into_iter().chain(unit.as_ref().map(|unit| (unit, 8))).for_each(|(text, chars)| shown(text, chars, 4 * chars)),
			Card::Progress {label, used, total} => {
				shown(label, 32, 128);
				assert!(used <= total && *total > 0 && *total <= INTEGER_MAX);
			}
			Card::Notice(notice) => shown(&notice.text, usize::MAX, control::NOTICE_MAX),
			Card::Link {label, url} => {
				shown(label, 32, 128);
				assert!(url.as_str().starts_with("https://") && url.as_str().len() <= URL_MAX);
			}
		}
	}
	let mut ids = HashSet::new();
	for profile in &read.profiles {
		shown(&profile.name, 64, 256);
		profile.exits.iter().for_each(|exit| shown(&exit.name, 64, 256));
		profile.notices.iter().for_each(|notice| shown(&notice.text, usize::MAX, control::NOTICE_MAX));
		// What a node sends stands for a text of the document only when it is the bytes of its `default`: the name of another exit and a notice no list holds find nothing.
		assert!(profile.exit_name(&control::Exit {tag: "none".into(), name: "".into(), country: None, all_protocols: false, selected: false, configured: false, working: false, load: control::Load::Low}).is_none() && read.notice_text(profile, &control::Notice {severity: control::Severity::Warning, text: "\u{0}".into()}).is_none(), "a text of the document stood for one no node sent");
		assert!(ids.insert(&profile.id) && profile.name.visible() && (1280..=1500).contains(&profile.mtu) && (1..=4).contains(&profile.parallel) && profile.min_control_version >= 1 && (1..=TRANSPORTS_MAX).contains(&profile.transports.len()) && profile.exits.len() <= control::EXITS_MAX && profile.notices.len() <= control::NOTICES_MAX && profile.exits.iter().all(|exit| control::is_tag(&exit.tag) && exit.name.visible()), "a profile outside its ranges");
		assert!((1..=2).contains(&profile.device.addresses.len()) && profile.gateways.len() == profile.device.addresses.len() && (1..=2).contains(&profile.device.transport_secrets.len()) && profile.device.private_key.as_ref().is_none_or(|private| public_key(private.expose()) == profile.device.public_key), "device keys that do not hold together");
		assert!(profile.padding.keepalive.start() + 10_000 <= *profile.padding.keepalive.end() && *profile.padding.keepalive.start() >= 10_000 && *profile.padding.keepalive.end() <= 60_000 && (512..=1023).contains(&profile.padding.wide_max) && (64..=255).contains(&profile.padding.normal_max), "padding outside its ranges");
		let keys: Vec<_> = profile.transports.iter().filter_map(|transport| if let Transport::FakeTls {key, ..} = transport {Some(key)} else {None}).collect();
		assert!(keys.iter().enumerate().all(|(at, key)| !keys[..at].contains(key)), "two faketls transports with one key");
		// The places the document wrote: one for each transport kept, rising, with the candidates kept in rising places too, and every drop within the document.
		assert!(profile.places.len() == profile.transports.len() && profile.places.windows(2).all(|pair| pair[0].transport < pair[1].transport) && profile.places.iter().all(|place| place.transport < TRANSPORTS_MAX && place.candidates.windows(2).all(|pair| pair[0] < pair[1]) && place.candidates.iter().all(|at| *at < CANDIDATES_MAX)), "places that do not hold together");
		assert!(profile.dropped.windows(2).all(|pair| pair[0].transport <= pair[1].transport) && profile.dropped.iter().all(|drop| drop.transport < TRANSPORTS_MAX && (1..=CANDIDATES_MAX).contains(&drop.count) && profile.places.iter().any(|place| place.transport == drop.transport) == (drop.cause == Cause::Candidate)), "a drop that does not hold together");
		for (transport, place) in profile.transports.iter().zip(&profile.places) {
			let dials: Vec<_> = match transport {
				Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) => endpoints.clone(),
				Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _) => {
					assert!(stream.path.len() >= 12 && stream.path.starts_with('/') && profile.transport_public_key.is_some(), "a stream transport without its path or key");
					stream.candidates.iter().for_each(|candidate| assert!(candidate.pins.len() <= PINS_MAX && (if candidate.self_signed {candidate.verify_name.is_none() && matches!(transport, Transport::Tls(_))} else {candidate.sni.is_some() != candidate.verify_name.is_some()}) && (matches!(transport, Transport::Ws(_)) || candidate.pins.is_empty() != matches!(transport, Transport::Tls(_))) && candidate.ech.as_ref().is_none_or(|ech| (1..=1_024).contains(&ech.len())), "a candidate that breaks the rule of its transport"));
					stream.candidates.iter().map(|candidate| candidate.address).collect()
				}
				Transport::FakeTls {key, candidates} => {
					assert!(profile.transport_public_key != Some(*key) && candidates.iter().all(|candidate| !candidate.sni.is_empty() && is_host(&candidate.sni)), "a faketls transport with the profile's key or no site");
					candidates.iter().map(|candidate| candidate.address).collect()
				}
			};
			assert!((1..=CANDIDATES_MAX).contains(&dials.len()) && place.candidates.len() == dials.len());
			for address in dials.iter().map(|dial| dial.address()) {assert!(address.port() != 0 && !address.ip().is_loopback() && !address.ip().is_unspecified() && !address.ip().is_multicast() && address.ip().to_canonical() == address.ip(), "a dial address a document may not name")}
		}
	}
}

// The payload reader behind a good signature, and what a client then decides. The first byte is settings and the rest is the payload, which is sealed here under a key the client holds, so every byte of it reaches the reader.
//   bit 0  clear: the document is the answer to a refresh. Set: it is a whole document in a file, imported.
//   bit 1  the document is signed by the second key, which the client does not hold.
//   bit 3  the client imported the pinned link of the seeds, which is the link above with the pin of its endpoint's own certificate. It implies bit 2.
//   bit 4  the same, from a first document that lists pinned refresh entries, which the import confirmed. It implies bits 2 and 3.
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
	static BASES: OnceLock<[Held; 4]> = OnceLock::new();
	let (pinned, bases) = (mode & 24 != 0, BASES.get_or_init(|| [import(&sealed(0, &IMPORT[1..])).expect("the seed is a whole document"), linked(LINK, &DOCUMENT[1..]), linked(PINNED_LINK, &DOCUMENT[1..]), linked(PINNED_LINK, sealed(0, &PINNED_DOCUMENT[1..]).as_bytes())]));
	let with_link = pinned || mode & 4 != 0;
	let mut client = bases[if mode & 16 != 0 {3} else if pinned {2} else {usize::from(with_link)}].clone();
	let before = client.clone();
	match client.refresh(document.as_bytes(), NOW) {
		Ok(Refreshed::Updated(changes)) => {
			assert!(signer == 0 && client.subscription().serial > before.subscription().serial && client.subscription().issued_at >= before.subscription().issued_at && client.id() == before.id() && client.document() == document && client.subscription().expires_at > NOW && client.keys().contains(&held[0]), "a refresh was taken that the rules refuse");
			assert!(client.subscription().profiles.iter().all(|profile| profile.device.private_key.is_some() != with_link && before.subscription().profiles.iter().any(|old| old.device.public_key == profile.device.public_key) && client.device().is_none_or(|device| *device.public() == profile.device.public_key)), "a refresh changed a device key");
			// Only a base with bit 4 has confirmed hosts, and only the ones the document before also listed stay confirmed. Otherwise nothing was confirmed, so the token goes to the host and port of the link and nowhere else, and every other host the document lists waits for the user.
			assert!(client.endpoints().iter().all(|url| url.authority() == "sub.example.com:443" || client.subscription().refresh_urls.iter().any(|entry| entry.url() == *url && !changes.hosts.contains(&entry.key()) && before.subscription().refresh_urls.iter().any(|old| old.key() == entry.key()))) && (with_link || client.endpoints().is_empty()) && client.unconfirmed() == changes.hosts && (with_link || changes.hosts.is_empty()), "a request may go somewhere the user has not confirmed");
			assert!(client.subscription().refresh_urls.iter().all(|url| url.authority() == "sub.example.com:443" || changes.hosts.contains(&url.key()) || !with_link || before.subscription().refresh_urls.iter().any(|old| old.key() == url.key())), "a refresh host is neither the link's nor waiting");
			// The pins of an entry follow the pins held: a pinned entry on the link's host and port holds a pin held for the endpoint, and a pinned entry that was confirmed and is listed again holds one of the pins it had. Without this rule a document could hand a host to a key the client has no tie to.
			assert!(client.subscription().refresh_urls.iter().all(|entry| !with_link || !entry.pinned() || if entry.authority() == "sub.example.com:443" {entry.pins().iter().any(|pin| before.stored().pins.contains(pin))} else {!before.subscription().refresh_urls.iter().any(|old| old.key() == entry.key()) || entry.pins().iter().any(|pin| before.subscription().refresh_urls.iter().any(|old| old.key() == entry.key() && old.pins().contains(pin)))}), "a pinned entry that holds no pin that was held");
			// The link alone decides whether the endpoint is pinned. Every entry of the link's host and port is of its kind, a list of pins is for a pinned endpoint only and holds a pin that was held, and the client holds exactly the list. Nothing is pinned for a whole document.
			let (list, held_before) = (&client.subscription().endpoint_pins, before.stored().pins);
			assert!(client.stored().pins.len() <= 2 && client.stored().pins.is_empty() != pinned && client.targets().iter().take(1).all(|target| target.pins == &client.stored().pins[..]) && client.targets().iter().all(|target| target.role != Role::Move && !target.keys.is_empty()), "a pin set that is not the link's kind");
			assert!(client.targets().iter().all(|target| target.pins.len() <= 2) && client.subscription().refresh_urls.iter().all(|url| !with_link || url.authority() != "sub.example.com:443" || url.pinned() == pinned && !url.is_plain()), "an entry of the link's host and port moved to the other kind");
			assert!(list.is_empty() || !with_link || (pinned && client.stored().pins == *list && list.iter().any(|pin| held_before.contains(pin))), "a list of pins that does not hold a pin that was held");
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
