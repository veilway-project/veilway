#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::subscription::{client::Offer, is_host, link::{Carried, Link}, BODY_MAX, CARRIED_MAX, LINK_URL_MAX};

// A link as it is typed, pasted, scanned or opened by another app, and the content of a file. The whole input is the text.
// A link that reads must be exactly one of the forms: it is written back as the bytes it was read from, a native link reads the same in both of its forms and never prints its token, a legacy link comes only out of an `https` URL and keeps no fragment, and every size is within its limit. What a link becomes is the first screen of an import and nothing else: an offer, which holds no request.
fuzz_target!(|data: &[u8]| {
	if let Ok(carried) = Carried::file(data) {
		assert_eq!(carried.file_content().as_bytes(), data, "a file was read as other bytes than it holds");
		assert!(carried.in_file() && carried.document().len() <= BODY_MAX && carried.veilway().is_some() == (carried.document().len() <= CARRIED_MAX));
	}
	let Ok(text) = std::str::from_utf8(data) else {return};
	let Ok(link) = Link::parse(text) else {return};
	match &link {
		Link::Native(native) => {
			assert!(text == native.veilway() || text == native.https(), "a native link was read as another text than it is");
			assert!(Link::parse(&native.veilway()).as_ref() == Ok(&link) && Link::parse(&native.https()).as_ref() == Ok(&link), "the two forms of a native link read as two links");
			assert!(native.endpoint().as_str().len() <= LINK_URL_MAX && !native.endpoint().as_str().contains(['#', '?']) && is_host(native.endpoint().host()));
			// The endpoint is no secret and is printed. A path may hold the same characters as the token, so it is taken out first.
			assert!(!format!("{native:?}").replace(native.endpoint().as_str(), "").contains(&text[text.len() - 22..]), "a native link printed its token");
		}
		Link::Carried(carried) => {
			assert_eq!(carried.veilway().as_deref(), Some(text), "a document in a link was read as another text than it is");
			assert!(!carried.in_file() && carried.document().len() <= CARRIED_MAX);
		}
		Link::Legacy(legacy) => {
			assert!(text.starts_with("https://") && text.starts_with(legacy.url().as_str()) && legacy.url().as_str().len() <= LINK_URL_MAX && !legacy.url().as_str().contains('#') && is_host(legacy.url().host()), "a legacy link out of something that is no plain https URL");
			assert!(matches!(text.as_bytes().get(legacy.url().as_str().len()), None | Some(b'#')));
		}
	}
	let _ = Offer::open(link);
});
