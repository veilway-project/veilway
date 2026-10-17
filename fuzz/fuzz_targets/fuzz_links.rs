#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::subscription::{is_host, legacy::{self, LegacyError, Server, LINKS_MAX}, payload::{dialable, INTEGER_MAX}, URL_MAX};
use veilway_proto::xray::{document::{self, Run}, profile};

// The answer to a legacy `GET`: nothing in it is signed, and anyone on the way may have written it. The first byte picks what the rest is, by its lowest bit:
//   0  the body: a list of links, plain or in base64. What is read must stay inside its limits, every field of an entry must be of the kind its type says, and a body with the shape of a signed document is never read as a list.
//   1  the response headers, one per line as `name: value`. Each value that is read must be within its bounds.
fuzz_target!(|data: &[u8]| {
	let Some((mode, rest)) = data.split_first() else {return};
	if mode & 1 == 0 {
		let list = match legacy::list(rest) {
			Ok(list) => list,
			Err(LegacyError::Native) => return assert!(rest.iter().filter(|byte| **byte == b'.').count() == 2, "a body was called a signed document that has not its shape"),
			Err(_) => return,
		};
		assert!(list.entries.len() + list.skipped <= LINKS_MAX, "more links than the limit were read");
		let word = |word: &Option<String>| word.as_ref().is_none_or(|word| (1..=32).contains(&word.len()) && word.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
		for entry in &list.entries {
			assert!(entry.port != 0 && entry.name.as_str().chars().count() <= 64 && !entry.name.as_str().chars().any(char::is_control) && (1..=256).contains(&entry.credential.expose().len()), "an entry outside its limits");
			assert!(word(&entry.cipher) && word(&entry.network) && [&entry.sni, &entry.host].iter().all(|name| name.as_ref().is_none_or(|name| is_host(name))) && entry.path.as_ref().is_none_or(|path| path.starts_with('/') && path.len() <= 256 && path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&()*+,;=:@/?%".contains(&byte))) && !matches!(&entry.server, Server::Name(name) if !is_host(name)), "a field of an entry that is not of its kind");
			let token = |text: &Option<String>, limit: usize, extra: &[u8]| text.as_ref().is_none_or(|text| (1..=limit).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte)));
			assert!(word(&entry.flow) && word(&entry.fp) && word(&entry.encryption) && word(&entry.header) && word(&entry.mode), "a word field of an entry that is not a word");
			assert!(entry.alpn.as_ref().is_none_or(|list| list.len() <= 64 && list.split(',').all(|item| (1..=32).contains(&item.len()) && item.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-/.".contains(&byte)))), "an alpn list outside its grammar");
			assert!(token(&entry.pbk, 64, b"-_") && token(&entry.service, 128, b"-._/") && entry.sid.as_ref().is_none_or(|sid| sid.len() <= 16 && sid.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())) && entry.aid.as_ref().is_none_or(|aid| (1..=4).contains(&aid.len()) && aid.bytes().all(|byte| byte.is_ascii_digit())), "a key, a service name, a short id or an alter id outside its grammar");
			// What passes the table of what can connect is the only thing the document is built from: it must come out as one JSON object, and nothing of the entry may break out of its slot.
			if let Ok(profile) = profile::check(entry) {
				let built = document::document(&profile, &Run {port: 10808, login: "login", address: "192.0.2.10".parse().unwrap(), interface: Some("eth0")});
				let value: serde_json::Value = serde_json::from_str(&built).expect("the document is not JSON");
				assert!(value.as_object().is_some_and(|map| map.len() == 4) && value["inbounds"].as_array().is_some_and(|list| list.len() == 1) && value["outbounds"].as_array().is_some_and(|list| list.len() == 2), "the document is not the template");
				assert!(!built.contains("\"allowInsecure\":true"), "a document that switches the certificate check off");
			}
			assert!(!matches!(&entry.server, Server::Address(address) if !dialable(*address)) && !matches!(&entry.server, Server::Name(name) if name == "localhost"), "an entry that dials what a signed profile may not");
			assert!(format!("{entry:?}").len() < 40 && format!("{:?}", entry.credential) == "Credential(..)", "an entry printed what it holds");
			let _ = entry.cap();
		}
	} else {
		let fields: Vec<(&str, &[u8])> = rest.split(|byte| *byte == b'\n').filter_map(|line| {
			let at = line.iter().position(|byte| *byte == b':')?;
			Some((std::str::from_utf8(&line[..at]).ok()?, &line[at + 1..]))
		}).collect();
		let read = legacy::headers(&fields);
		assert!(read.usage.is_none_or(|usage| usage.upload <= INTEGER_MAX && usage.download <= INTEGER_MAX && usage.total <= INTEGER_MAX && usage.expire.is_none_or(|expire| (1..=INTEGER_MAX).contains(&expire))), "usage outside its range");
		assert!(read.title.as_ref().is_none_or(|title| (1..=64).contains(&title.as_str().chars().count()) && !title.as_str().chars().any(char::is_control)) && read.update_interval.is_none_or(|seconds| (3_600..=604_800).contains(&seconds) && seconds % 3_600 == 0) && read.support_url.as_ref().is_none_or(|url| url.as_str().starts_with("https://") && url.as_str().len() <= URL_MAX && is_host(url.host())), "a header outside its bounds");
	}
});
