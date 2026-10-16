#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::subscription::{client::Offer, is_host, link::{Carried, Link}, payload::dialable, BODY_MAX, CARRIED_MAX, LINK_URL_MAX};

// A link as it is typed, pasted, scanned or opened by another app, and the content of a file. The whole input is the text.
// A link that reads must be exactly one of the forms: it is written back as the bytes it was read from, a native link reads the same in both of its forms and never prints its token, a legacy link comes only out of an `https` URL and keeps no fragment, and every size is within its limit. What a link becomes is the first screen of an import and nothing else: an offer, which holds no request.
fuzz_target!(|data: &[u8]| {
	if let Ok(carried) = Carried::file(data) {
		// "One line end, LF or CRLF, which editors add when a file is saved and which is ignored."
		assert_eq!(carried.file_content().as_bytes(), data.strip_suffix(b"\n").map_or(data, |rest| rest.strip_suffix(b"\r").unwrap_or(rest)), "a file was read as other bytes than it holds");
		assert!(carried.in_file() && carried.document().len() <= BODY_MAX && carried.veilway().is_some() == (carried.document().len() <= CARRIED_MAX));
	}
	let Ok(text) = std::str::from_utf8(data) else {return};
	let Ok(link) = Link::parse(text) else {return};
	match &link {
		Link::Native(native) => {
			assert!(text == native.veilway() || text == native.https(), "a native link was read as another text than it is");
			assert!(Link::parse(&native.veilway()).as_ref() == Ok(&link) && Link::parse(&native.https()).as_ref() == Ok(&link), "the two forms of a native link read as two links");
			// The link alone decides whether the endpoint is pinned: 158 characters of fragment with a pin and 114 without, a plain link never has a pin, and only a pinned or a plain link has an address for a host, one that is dialable and in its one spelling.
			let fragment = text.split_once('#').map_or("", |(_, fragment)| fragment);
			assert!(native.pin().is_some() == (fragment.len() == 158) && (native.pin().is_some() || fragment.len() == 114) && (native.pin().is_none() || !native.endpoint().is_plain()), "a pin and the length of the fragment disagree");
			assert!(native.endpoint().as_str().len() <= LINK_URL_MAX && !native.endpoint().as_str().contains(['#', '?']) && if let Some(address) = native.endpoint().literal() {(native.pin().is_some() || native.endpoint().is_plain()) && dialable(address) && !is_host(native.endpoint().host()) && native.endpoint().host() == match address {std::net::IpAddr::V4(ip) => ip.to_string(), std::net::IpAddr::V6(ip) => format!("[{ip}]")}} else {is_host(native.endpoint().host())});
			// The endpoint is no secret and is printed. A path may hold the same characters as the token, so it is taken out first.
			let printed = format!("{native:?}").replace(native.endpoint().as_str(), "");
			assert!(!printed.contains(&fragment[92..114]), "a native link printed its token");
			assert!(native.pin().is_none() || !printed.contains(&fragment[115..]), "a native link printed its pin");
		}
		Link::Carried(carried) => {
			assert_eq!(carried.veilway().as_deref(), Some(text), "a document in a link was read as another text than it is");
			assert!(!carried.in_file() && carried.document().len() <= CARRIED_MAX);
		}
		Link::Legacy(legacy) => {
			assert!(text.starts_with("https://") && text.starts_with(legacy.url().as_str()) && legacy.url().as_str().len() <= LINK_URL_MAX && !legacy.url().as_str().contains('#') && is_host(legacy.url().host()) && legacy.url().literal().is_none(), "a legacy link out of something that is no plain https URL");
			assert!(matches!(text.as_bytes().get(legacy.url().as_str().len()), None | Some(b'#')));
		}
	}
	let _ = Offer::open(link);
});
