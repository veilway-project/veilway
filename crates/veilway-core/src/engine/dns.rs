//! DNS messages as far as the node's resolver needs them: the question of a query, the addresses in the answer section of a response, and the answers the node writes itself.
//! Every byte comes from a tunnel or from an upstream resolver, so every length is checked and every loop is bounded.
use crate::config::domain;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const HEADER: usize = 12;
pub const MAX_MESSAGE: usize = 65535;
/// A name on the wire: every label with its length byte, and the root label. As text that is at most 253 bytes.
const MAX_WIRE_NAME: usize = 255;
/// Compression pointers followed while the owner name of one record is read. A question may hold none: nothing comes before it to point at.
const MAX_POINTERS: usize = 16;
/// Records in the answer section of a response. One that claims more is not read at all.
pub const MAX_RECORDS: usize = 128;
pub const SERVFAIL: u8 = 2;
pub const REFUSED: u8 = 5;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// `name` is lowercase and only present when it is a domain as a config may write one in a rule. Any other name (the root, a label with an underscore, bytes that are not text) is still a question, one that no `domain` condition can match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {pub name: Option<String>, pub qtype: u16, pub qclass: u16}

/// A standard query with one question. `wire` is that question as it was sent.
#[derive(Debug)]
pub struct Query<'a> {pub id: u16, pub rd: bool, pub question: Question, wire: &'a [u8]}

/// `addresses` are the A and AAAA records of the answer section with their TTLs, whatever name each belongs to: after a CNAME they belong to the name it points at.
#[derive(Debug)]
pub struct Response {pub id: u16, pub rcode: u8, pub truncated: bool, pub question: Option<Question>, pub addresses: Vec<(IpAddr, u32)>}

fn word(message: &[u8], at: usize) -> Option<u16> {Some(u16::from_be_bytes([*message.get(at)?, *message.get(at + 1)?]))}

/// Reads the name that starts at `start`, following at most `allowed` compression pointers: its text when every byte is printable ASCII, and where the bytes after it begin.
/// A pointer must point back into the message body, but labels walk forward again and may reach the same pointer, so it is the length of the name and the number of pointers that end a loop.
fn name(message: &[u8], start: usize, allowed: usize) -> Option<(Option<String>, usize)> {
	let (mut text, mut plain, mut at, mut end, mut pointers, mut wire) = (String::new(), true, start, None, 0, 1);
	loop {
		let len = usize::from(*message.get(at)?);
		match len >> 6 {
			0 if len == 0 => return Some((plain.then_some(text), end.unwrap_or(at + 1))),
			0 => {
				let label = message.get(at + 1..at + 1 + len)?;
				wire += len + 1;
				if wire > MAX_WIRE_NAME {return None}
				plain &= label.iter().all(|byte| byte.is_ascii_graphic() && *byte != b'.');
				if plain {
					if !text.is_empty() {text.push('.')}
					text.extend(label.iter().map(|byte| char::from(byte.to_ascii_lowercase())));
				}
				at += len + 1;
			}
			3 => {
				let target = usize::from(word(message, at)? & 0x3fff);
				pointers += 1;
				if pointers > allowed || target < HEADER || target >= at {return None}
				end.get_or_insert(at + 2);
				at = target;
			}
			_ => return None,
		}
	}
}

/// The first question of a message and where the bytes after it begin. Its name is read without pointers: one that points back into itself could walk on past the question, and the name would then depend on bytes that are no part of it.
fn question(message: &[u8]) -> Option<(Question, usize)> {
	let (name, at) = name(message, HEADER, 0)?;
	Some((Question {name: name.filter(|name| domain(name, false)), qtype: word(message, at)?, qclass: word(message, at + 2)?}, at + 4))
}

/// Reads a standard query: QR clear, opcode 0, exactly one question and nothing in the answer and authority sections. Additional records, which is where EDNS lives, are not read.
pub fn query(message: &[u8]) -> Option<Query<'_>> {
	if message.len() < HEADER || message.len() > MAX_MESSAGE || message[2] & 0xf8 != 0 || word(message, 4)? != 1 || word(message, 6)? != 0 || word(message, 8)? != 0 {return None}
	let (question, end) = question(message)?;
	Some(Query {id: word(message, 0)?, rd: message[2] & 1 != 0, question, wire: message.get(HEADER..end)?})
}

impl Query<'_> {
	/// The answer the node writes itself: the id and the question of the query, its RD bit, the code, and no records.
	pub fn reply(&self, rcode: u8) -> Vec<u8> {
		let mut out = Vec::with_capacity(HEADER + self.wire.len());
		out.extend_from_slice(&self.id.to_be_bytes());
		out.extend_from_slice(&[0x80 | u8::from(self.rd), 0x80 | (rcode & 0x0f), 0, 1, 0, 0, 0, 0, 0, 0]);
		out.extend_from_slice(self.wire);
		out
	}
}

/// Reads a response to a standard query as far as its answer section. None for a message that is cut short, claims more answer records than `MAX_RECORDS` or more than one question, or holds a name or an address record that is not well formed.
pub fn response(message: &[u8]) -> Option<Response> {
	if message.len() < HEADER || message.len() > MAX_MESSAGE || message[2] & 0xf8 != 0x80 {return None}
	let (questions, records) = (word(message, 4)?, usize::from(word(message, 6)?));
	if questions > 1 || records > MAX_RECORDS {return None}
	let (question, mut at) = if questions == 1 {question(message).map(|(question, end)| (Some(question), end))?} else {(None, HEADER)};
	let mut addresses = Vec::new();
	for _ in 0..records {
		let (_, fixed) = name(message, at, MAX_POINTERS)?;
		let (kind, class, ttl, len) = (word(message, fixed)?, word(message, fixed + 2)?, u32::from(word(message, fixed + 4)?) << 16 | u32::from(word(message, fixed + 6)?), usize::from(word(message, fixed + 8)?));
		let data = message.get(fixed + 10..fixed + 10 + len)?;
		// RFC 2181 section 8: a TTL with the top bit set counts as zero.
		let ttl = if ttl > i32::MAX as u32 {0} else {ttl};
		match (class, kind, <[u8; 4]>::try_from(data), <[u8; 16]>::try_from(data)) {
			(CLASS_IN, TYPE_A, Ok(v4), _) => addresses.push((IpAddr::V4(Ipv4Addr::from(v4)), ttl)),
			(CLASS_IN, TYPE_AAAA, _, Ok(v6)) => addresses.push((IpAddr::V6(Ipv6Addr::from(v6)), ttl)),
			(CLASS_IN, TYPE_A | TYPE_AAAA, ..) => return None,
			_ => {}
		}
		at = fixed + 10 + len;
	}
	Some(Response {id: word(message, 0)?, rcode: message[3] & 0x0f, truncated: message[2] & 0x02 != 0, question, addresses})
}

/// Cuts an answer down to what one datagram may carry and sets its TC bit, so the client asks again over TCP.
pub fn clip(answer: &mut Vec<u8>, cap: usize) {
	if answer.len() <= cap {return}
	if let Some(flags) = answer.get_mut(2) {*flags |= 0x02}
	answer.truncate(cap);
}

#[cfg(test)]
mod tests {
	use super::*;

	fn labels(name: &str) -> Vec<u8> {
		let mut out: Vec<u8> = name.split('.').filter(|label| !label.is_empty()).flat_map(|label| [&[label.len() as u8][..], label.as_bytes()].concat()).collect();
		out.push(0);
		out
	}

	fn message(flags: [u8; 2], counts: [u16; 4], body: &[&[u8]]) -> Vec<u8> {
		let mut out = vec![0xab, 0xcd, flags[0], flags[1]];
		for count in counts {out.extend_from_slice(&count.to_be_bytes())}
		for part in body {out.extend_from_slice(part)}
		out
	}

	fn asking(name: &str, qtype: u16) -> Vec<u8> {[&labels(name)[..], &qtype.to_be_bytes(), &[0, 1]].concat()}

	fn record(owner: &[u8], kind: u16, class: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
		[owner, &kind.to_be_bytes(), &class.to_be_bytes(), &ttl.to_be_bytes(), &(data.len() as u16).to_be_bytes(), data].concat()
	}

	const POINTER: [u8; 2] = [0xc0, 0x0c];

	#[test]
	fn a_query_gives_its_id_and_its_question() {
		let raw = message([1, 0], [1, 0, 0, 1], &[&asking("WwW.Example.COM", 28), &[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]]);
		let query = query(&raw).unwrap();
		assert_eq!((query.id, query.rd), (0xabcd, true));
		assert_eq!(query.question, Question {name: Some("www.example.com".to_string()), qtype: 28, qclass: 1});
		assert!(!super::query(&message([0, 0], [1, 0, 0, 0], &[&asking("example.com", 1)])).unwrap().rd);
		// The longest name there is: 253 bytes as text, 255 on the wire.
		let long = [&"a".repeat(63)[..], &"b".repeat(63), &"c".repeat(63), &"d".repeat(61)].join(".");
		assert_eq!(super::query(&message([1, 0], [1, 0, 0, 0], &[&asking(&long, 1)])).unwrap().question.name, Some(long));
	}

	#[test]
	fn a_name_no_rule_could_write_is_still_a_question() {
		for odd in ["", "_sip._tcp.example.com", "example.123", "example.0x1f", "-a.example.com", "ex ample.com"] {
			let raw = message([1, 0], [1, 0, 0, 0], &[&asking(odd, 33)]);
			let query = query(&raw).unwrap_or_else(|| panic!("`{odd}` was not read"));
			assert_eq!((query.question.name.as_deref(), query.question.qtype), (None, 33), "{odd}");
		}
		// A dot inside a label is not a label boundary, and a byte that is not text never becomes one.
		for label in [&b"a.b"[..], &[0xc3, 0xa9], &[0]] {
			let raw = message([1, 0], [1, 0, 0, 0], &[&[label.len() as u8], label, &labels("example.com"), &[0, 1, 0, 1]]);
			assert_eq!(query(&raw).unwrap().question.name, None, "{label:?}");
		}
	}

	#[test]
	fn what_is_not_a_standard_query_is_refused() {
		let good = message([1, 0], [1, 0, 0, 0], &[&asking("example.com", 1)]);
		assert!(query(&good).is_some());
		for cut in 0..good.len() {assert!(query(&good[..cut]).is_none(), "a query cut to {cut} bytes was read")}
		for (what, flags, counts) in [("a response", [0x81, 0], [1, 0, 0, 0]), ("an update", [0x28, 0], [1, 0, 0, 0]), ("no question", [1, 0], [0, 0, 0, 0]), ("two questions", [1, 0], [2, 0, 0, 0]), ("an answer record", [1, 0], [1, 1, 0, 0]), ("an authority record", [1, 0], [1, 0, 1, 0])] {
			assert!(query(&message(flags, counts, &[&asking("example.com", 1), &asking("example.com", 1)])).is_none(), "{what} passed for a query");
		}
		let mut huge = good.clone();
		huge.resize(MAX_MESSAGE + 1, 0);
		assert!(query(&huge).is_none() && response(&huge).is_none(), "a message over the size limit was read");
		assert!(query(&[]).is_none() && response(&[]).is_none());
	}

	#[test]
	fn oversized_names_are_refused() {
		let over = [&"a".repeat(63)[..], &"b".repeat(63), &"c".repeat(63), &"d".repeat(62)].join(".");
		assert!(query(&message([1, 0], [1, 0, 0, 0], &[&asking(&over, 1)])).is_none(), "a name of 254 bytes was read");
		// A label length of 64 or more is no label: 0x40 and 0x80 are reserved, and 0xc0 starts a pointer.
		for len in [0x40u8, 0x7f, 0x80, 0xbf] {
			assert!(query(&message([1, 0], [1, 0, 0, 0], &[&[len], &[b'a'; 200], &[0, 0, 1, 0, 1]])).is_none(), "a label of length byte {len:#x} was read");
		}
		assert!(query(&message([1, 0], [1, 0, 0, 0], &[&[5, b'a', b'b']])).is_none(), "a label longer than the message was read");
		assert!(query(&message([1, 0], [1, 0, 0, 0], &[&labels("example.com")[..12]])).is_none(), "a name without its root label was read");
		// A pointer in a question can only point back into the question. Here it lands inside the first label, and the labels read from there walk past the pointer into the bytes after the question.
		let (looped, strided) = ([&[1, b'a', 0xc0, 12][..], &[0, 1, 0, 1]].concat(), [&[4, 2, b'a', b'b', 2, 0xc0, 13][..], &[0, 1, 0, 1, 0, 0]].concat());
		for (what, body) in [("a pointer back to its own start", looped), ("a pointer into its own label", strided)] {
			assert!(query(&message([1, 0], [1, 0, 0, 0], &[&body])).is_none() && response(&message([0x81, 0x80], [1, 0, 0, 0], &[&body])).is_none(), "a question with {what} was read");
		}
	}

	#[test]
	fn compression_pointers_are_followed_within_bounds() {
		let question = asking("example.com", 1);
		let answered = |records: &[&[u8]], count: u16| response(&message([0x81, 0x80], [1, count, 0, 0], &[&[&question[..]], records].concat()));
		assert_eq!(answered(&[&record(&POINTER, 1, 1, 300, &[1, 2, 3, 4])], 1).unwrap().addresses, [("1.2.3.4".parse().unwrap(), 300)]);
		// The owner of the record starts at 29, right after the question.
		for (what, owner) in [("a pointer to itself", &[0xc0, 29][..]), ("a pointer forward", &[0xc0, 40]), ("a pointer into the header", &[0xc0, 4]), ("a pointer past the end", &[0xff, 0xff]), ("a pointer cut in half", &[0xc0])] {
			assert!(answered(&[&record(owner, 1, 1, 300, &[1, 2, 3, 4])], 1).is_none(), "{what} was followed");
		}
		// A label and then a pointer back to that label: walking forward from the target reaches the pointer again.
		assert!(answered(&[&record(&[1, b'a', 0xc0, 29], 1, 1, 300, &[1, 2, 3, 4])], 1).is_none(), "a loop of a label and a pointer was followed");
		// A chain of pointers, each to the one before it, kept in the data of a record nobody reads. The first of them is at 41.
		let chain = |links: u8| {
			let data: Vec<u8> = (0..links).flat_map(|link| if link == 0 {POINTER} else {[0xc0, 41 + 2 * (link - 1)]}).collect();
			answered(&[&record(&POINTER, 16, 1, 300, &data), &record(&[0xc0, 41 + 2 * (links - 1)], 1, 1, 300, &[1, 2, 3, 4])], 2)
		};
		assert_eq!(chain(MAX_POINTERS as u8 - 1).unwrap().addresses.len(), 1);
		assert!(chain(MAX_POINTERS as u8).is_none(), "a chain of more than {MAX_POINTERS} pointers was followed");
	}

	#[test]
	fn a_response_gives_its_addresses_with_their_ttls() {
		let v6: Ipv6Addr = "2606:4700::1111".parse().unwrap();
		let raw = message([0x83, 0x83], [1, 6, 1, 0], &[
			&asking("Example.com", 255), &record(&POINTER, 5, 1, 60, &labels("cdn.example.net")), &record(&labels("cdn.example.net"), 1, 1, 30, &[93, 184, 216, 34]),
			&record(&POINTER, 28, 1, 86400, &v6.octets()), &record(&POINTER, 1, 3, 300, &[9, 9, 9, 9]), &record(&POINTER, 16, 1, 300, b"\x04text"), &record(&POINTER, 1, 1, 0x8000_0000, &[1, 1, 1, 1]),
			&record(&POINTER, 2, 1, 300, &labels("ns.example.com")),
		]);
		let response = response(&raw).unwrap();
		assert_eq!((response.id, response.rcode, response.truncated), (0xabcd, 3, true));
		assert_eq!(response.question, Some(Question {name: Some("example.com".to_string()), qtype: 255, qclass: 1}));
		assert_eq!(response.addresses, [("93.184.216.34".parse().unwrap(), 30), (IpAddr::V6(v6), 86400), ("1.1.1.1".parse().unwrap(), 0)], "only IN A and AAAA of the answer section count");
		let bare = super::response(&message([0x81, 0x80], [0, 1, 0, 0], &[&record(&labels("example.com"), 1, 1, 5, &[1, 2, 3, 4])])).unwrap();
		assert_eq!((bare.question, bare.addresses.len()), (None, 1));
		assert!(super::response(&message([1, 0], [1, 0, 0, 0], &[&asking("example.com", 1)])).is_none(), "a query passed for a response");
		for (kind, data) in [(1, &[1, 2, 3][..]), (1, &[1, 2, 3, 4, 5]), (28, &[0; 4]), (28, &[0; 17])] {
			assert!(super::response(&message([0x81, 0x80], [1, 1, 0, 0], &[&asking("example.com", 1), &record(&POINTER, kind, 1, 300, data)])).is_none(), "an address record of type {kind} with {} bytes was read", data.len());
		}
	}

	#[test]
	fn a_record_count_that_lies_is_refused() {
		let (question, one) = (asking("example.com", 1), record(&POINTER, 1, 1, 300, &[1, 2, 3, 4]));
		let with = |claimed: u16, present: usize| response(&message([0x81, 0x80], [1, claimed, 0, 0], &[&question, &one.repeat(present)]));
		assert_eq!(with(2, 2).unwrap().addresses.len(), 2);
		assert!(with(3, 2).is_none() && with(65535, 1).is_none(), "a response with fewer records than it claims was read");
		assert_eq!(with(1, 5).unwrap().addresses.len(), 1, "records past the answer section were read as answers");
		assert_eq!(with(0, 5).unwrap().addresses.len(), 0);
		assert_eq!(with(MAX_RECORDS as u16, MAX_RECORDS).unwrap().addresses.len(), MAX_RECORDS);
		assert!(with(MAX_RECORDS as u16 + 1, MAX_RECORDS + 1).is_none(), "more records than the limit were read");
		let whole = message([0x81, 0x80], [1, 1, 0, 0], &[&question, &one]);
		for cut in HEADER..whole.len() {assert!(response(&whole[..cut]).is_none(), "a response cut to {cut} bytes was read")}
		assert!(response(&message([0x81, 0x80], [2, 0, 0, 0], &[&question, &question])).is_none(), "two questions were read");
		assert!(response(&message([0x81, 0x80], [1, 1, 0, 0], &[&question, &record(&POINTER, 16, 1, 300, &[0; 40])[..20]])).is_none(), "a record longer than the message was read");
	}

	#[test]
	fn the_node_answers_with_the_id_and_the_question_of_the_query() {
		for (flags, rd) in [([1, 0x20], true), ([0, 0], false)] {
			let raw = message(flags, [1, 0, 0, 1], &[&asking("Blocked.Example.com", 28), &[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]]);
			let query = query(&raw).unwrap();
			for rcode in [REFUSED, SERVFAIL] {
				let reply = query.reply(rcode);
				assert_eq!(reply[..4], [0xab, 0xcd, 0x80 | u8::from(rd), 0x80 | rcode]);
				assert_eq!(reply[4..HEADER], [0, 1, 0, 0, 0, 0, 0, 0], "the answer claims records it does not have");
				assert_eq!(reply[HEADER..], raw[HEADER..raw.len() - 11], "the question was not echoed as it was asked");
				let back = response(&reply).unwrap();
				assert_eq!((back.id, back.rcode, back.question.as_ref(), back.addresses.len()), (query.id, rcode, Some(&query.question), 0));
			}
		}
	}

	#[test]
	fn an_answer_over_the_limit_is_cut_and_marked_truncated() {
		let whole = message([0x81, 0x80], [1, 1, 0, 0], &[&asking("example.com", 1), &record(&POINTER, 16, 1, 300, &[7; 600])]);
		let mut fits = whole.clone();
		clip(&mut fits, whole.len());
		assert_eq!(fits, whole);
		let mut cut = whole.clone();
		clip(&mut cut, 512);
		assert_eq!((cut.len(), cut[2], &cut[3..]), (512, 0x83, &whole[3..512]));
		let mut tiny = vec![1, 2];
		clip(&mut tiny, 1);
		assert_eq!(tiny, [1]);
	}
}
