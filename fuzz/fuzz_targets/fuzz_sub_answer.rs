#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use veilway_proto::{subscription::{client::{Fetching, Held, Offer, Refreshed}, link::Link, mirror}, NoRandom};

// The native link of the seeds, and the first document its endpoint answers with.
const LINK: &str = include_str!("../corpus/fuzz_deeplink/native-veilway");
const DOCUMENT: &[u8] = include_bytes!("../corpus/fuzz_sub_envelope/document");
// The clock: 100 s after the documents of the seeds were issued.
const NOW: u64 = 1_700_000_100;

// The step 2 of the import of the link of the seeds, for a device whose key is 33..33 and whose secret is 44..44.
fn fetching() -> Fetching {
	let Ok(Link::Native(link)) = Link::parse(LINK) else {panic!("the seed is a native link")};
	let Offer::Native(offer) = Offer::open(Link::Native(link)) else {panic!("a native link is offered as one")};
	offer.proceed(None, &mut |bytes: &mut [u8]| -> Result<(), NoRandom> {
		bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
		Ok(())
	}).expect("the random source works")
}

// The body of the answer of a gateway, opened as a client does once the status was 200. The first byte is settings, and the rest is the body.
//   bit 0  clear: the client refreshes a subscription it holds. Set: it imports the link, and the answer is the first one.
// The request is sealed to the gateway key 1 of the vectors with the input a0..bf for its ephemeral key and a clear top bit, so the answers of `tests/vectors.py` open. A body that does not open changes nothing. One that opens holds an envelope within what its size holds, and goes through the same checks as every other answer: what is held changes only for a newer document that passed every one of them, of the subscription held, signed by a key held.
fuzz_target!(|data: &[u8]| {
	let Some((settings, body)) = data.split_first() else {return};
	static HELD: OnceLock<Held> = OnceLock::new();
	let held = HELD.get_or_init(|| fetching().answer(&DOCUMENT[1..], NOW, &[]).expect("the seed is the document of the link").accept(None, &[]).expect("nothing is stored").held);
	let fetching = fetching();
	let mut asked = 0;
	let sealed = held.fetch().expect("a link has a request").seal(&fetching.gateway()[0], NOW, &mut |bytes: &mut [u8]| -> Result<(), NoRandom> {
		bytes.iter_mut().enumerate().for_each(|(place, byte)| *byte = if asked == 0 {0xa0 + place as u8} else {0});
		asked += 1;
		Ok(())
	}).expect("the request of the seeds is sealed");
	let Ok(envelope) = sealed.open(body) else {return};
	assert!(mirror::SIZES.contains(&body.len()) && (1..=mirror::capacity(body.len()).expect("a size")).contains(&envelope.len()), "an envelope outside what its answer holds");
	if settings & 1 == 1 {
		if let Ok(review) = fetching.answer(&envelope, NOW, &[]) {assert!(!review.subscription().gateway_keys.is_empty() && review.subscription().expires_at > NOW, "a first document that is none")}
		return;
	}
	let (mut client, before) = (held.clone(), held.clone());
	match client.refresh(&envelope, NOW) {
		Ok(Refreshed::Updated(_)) => assert!(client.subscription().serial > before.subscription().serial && client.document().as_bytes() == envelope && client.subscription().expires_at > NOW && client.id() == before.id() && !client.subscription().gateway_keys.is_empty() && client.keys().iter().any(|key| before.keys().contains(key)), "an answer was taken that the rules refuse"),
		Ok(Refreshed::Unchanged) => assert!(client == before && envelope == before.document().as_bytes(), "other bytes were taken as the same document"),
		Err(_) => assert!(client == before, "an answer that failed changed what is held"),
	}
});
