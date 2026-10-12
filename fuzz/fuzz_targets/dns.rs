#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::engine::dns::{clip, query, response, MAX_RECORDS, REFUSED, SERVFAIL};

fuzz_target!(|data: &[u8]| {
	if let Some(query) = query(data) {
		if let Some(name) = &query.question.name {assert!(!name.is_empty() && name.len() <= 253 && !name.bytes().any(|byte| byte.is_ascii_uppercase()), "a name that is no config domain was read from a query")}
		for rcode in [REFUSED, SERVFAIL] {
			let reply = query.reply(rcode);
			let back = response(&reply).expect("an answer the node wrote itself parses");
			assert_eq!((back.id, back.rcode, back.question.as_ref(), back.addresses.len()), (query.id, rcode, Some(&query.question), 0), "the node's own answer does not belong to the query");
		}
	}
	if let Some(response) = response(data) {assert!(response.addresses.len() <= MAX_RECORDS, "more addresses than records were read")}
	let mut answer = data.to_vec();
	clip(&mut answer, 512);
	assert!(answer.len() <= 512);
});
