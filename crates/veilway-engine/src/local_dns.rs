//! The two DNS messages the local proxy needs, as pure code: a query for the A or AAAA records of one name, and the reading of the answer. What comes back is read as hostile: the answer must be for the question that was asked, every length is checked before it is used, and the records and the addresses kept are bounded.
//! No compression pointer is followed. The name of a record is only skipped, so there is nothing to loop on. A truncated answer is used for the records it has and not retried over TCP.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const A: u16 = 1;
pub const AAAA: u16 = 28;
const HEADER: usize = 12;
/// The most records read from an answer, and the most addresses kept.
const MAX_RECORDS: usize = 64;
const MAX_ADDRESSES: usize = 16;

/// Why an answer gives nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
	/// Not an answer to this question, or not well formed. Dropped and waited past.
	Unrelated,
	/// The name does not exist (NXDOMAIN) or has no record of the kind.
	NotFound,
	/// The resolver answered with an error.
	Failed,
}

fn word(message: &[u8], at: usize) -> Option<u16> {Some(u16::from_be_bytes([*message.get(at)?, *message.get(at + 1)?]))}

/// The question's name as labels on the wire. None for a name that is empty, longer than 253 bytes, or has an empty label, a label over 63 bytes or a byte that is not a letter, digit, hyphen or underscore.
fn labels(name: &str) -> Option<Vec<u8>> {
	if name.is_empty() || name.len() > 253 {return None}
	let mut wire = Vec::with_capacity(name.len() + 2);
	for label in name.split('.') {
		if label.is_empty() || label.len() > 63 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {return None}
		wire.push(label.len() as u8);
		wire.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
	}
	wire.push(0);
	Some(wire)
}

/// A standard recursive query with one question of `qtype`, class IN. None when `name` cannot be one.
pub fn query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
	let wire = labels(name)?;
	let mut message = Vec::with_capacity(HEADER + wire.len() + 4);
	message.extend_from_slice(&id.to_be_bytes());
	message.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
	message.extend_from_slice(&wire);
	message.extend_from_slice(&qtype.to_be_bytes());
	message.extend_from_slice(&1u16.to_be_bytes());
	Some(message)
}

/// The end of a name that starts at `at`: after its zero label, or after a pointer.
fn skip(message: &[u8], mut at: usize) -> Option<usize> {
	for _ in 0..128 {
		let len = usize::from(*message.get(at)?);
		match len >> 6 {
			0 if len == 0 => return Some(at + 1),
			0 => at += len + 1,
			3 => return Some(at + 2),
			_ => return None,
		}
	}
	None
}

/// The addresses and their TTLs in the answer to the query `query(id, name, qtype)`, A or AAAA records only, in the order they came.
pub fn answer(message: &[u8], id: u16, name: &str, qtype: u16) -> Result<Vec<(IpAddr, u32)>, Bad> {
	let wire = labels(name).ok_or(Bad::Unrelated)?;
	let flags = word(message, 2).ok_or(Bad::Unrelated)?;
	if word(message, 0) != Some(id) || flags & 0x8000 == 0 || flags >> 11 & 0xf != 0 || word(message, 4) != Some(1) {return Err(Bad::Unrelated)}
	let asked = message.get(HEADER..HEADER + wire.len() + 4).ok_or(Bad::Unrelated)?;
	if !asked[..wire.len()].eq_ignore_ascii_case(&wire) || word(asked, wire.len()) != Some(qtype) || word(asked, wire.len() + 2) != Some(1) {return Err(Bad::Unrelated)}
	match flags & 0xf {
		0 => {}
		3 => return Err(Bad::NotFound),
		_ => return Err(Bad::Failed),
	}
	let count = usize::from(word(message, 6).ok_or(Bad::Unrelated)?);
	if count > MAX_RECORDS {return Err(Bad::Unrelated)}
	let (mut at, mut found) = (HEADER + wire.len() + 4, Vec::new());
	for _ in 0..count {
		at = skip(message, at).ok_or(Bad::Unrelated)?;
		let (kind, class, length) = (word(message, at).ok_or(Bad::Unrelated)?, word(message, at + 2).ok_or(Bad::Unrelated)?, usize::from(word(message, at + 8).ok_or(Bad::Unrelated)?));
		let ttl = u32::from(word(message, at + 4).ok_or(Bad::Unrelated)?) << 16 | u32::from(word(message, at + 6).ok_or(Bad::Unrelated)?);
		let data = message.get(at + 10..at + 10 + length).ok_or(Bad::Unrelated)?;
		at += 10 + length;
		if class != 1 || kind != qtype || found.len() >= MAX_ADDRESSES {continue}
		match (kind, <[u8; 4]>::try_from(data), <[u8; 16]>::try_from(data)) {
			(A, Ok(octets), _) => found.push((IpAddr::V4(Ipv4Addr::from(octets)), ttl)),
			(AAAA, _, Ok(octets)) => found.push((IpAddr::V6(Ipv6Addr::from(octets)), ttl)),
			_ => {}
		}
	}
	if found.is_empty() {Err(Bad::NotFound)} else {Ok(found)}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn reply(id: u16, name: &str, qtype: u16, rcode: u8, records: &[(u16, u16, &[u8])]) -> Vec<u8> {
		let mut message = query(id, name, qtype).unwrap();
		message[2] = 0x81;
		message[3] = 0x80 | rcode;
		message[7] = records.len() as u8;
		for (kind, class, data) in records {
			message.extend_from_slice(&[0xc0, 12]);
			message.extend_from_slice(&kind.to_be_bytes());
			message.extend_from_slice(&class.to_be_bytes());
			message.extend_from_slice(&[0, 0, 1, 44]);
			message.extend_from_slice(&(data.len() as u16).to_be_bytes());
			message.extend_from_slice(data);
		}
		message
	}

	#[test]
	fn a_query_names_one_question() {
		let message = query(0x1234, "Example.COM", A).unwrap();
		assert_eq!(message, [&[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0][..], b"\x07example\x03com\x00", &[0, 1, 0, 1]].concat());
		for bad in ["", ".", "a..b", "a b", "é.com", &"a".repeat(64), &["a"; 130].join(".")] {assert_eq!(query(1, bad, A), None, "{bad:?}");}
	}

	#[test]
	fn the_records_of_the_kind_asked_are_read() {
		let both = reply(7, "a.test", A, 0, &[(5, 1, &[1, b'x', 0]), (A, 1, &[192, 0, 2, 1]), (28, 1, &[0; 16]), (A, 3, &[1, 1, 1, 1]), (A, 1, &[192, 0, 2, 2]), (A, 1, &[1, 2, 3])]);
		assert_eq!(answer(&both, 7, "A.test", A), Ok(vec![("192.0.2.1".parse().unwrap(), 300), ("192.0.2.2".parse().unwrap(), 300)]));
		let six = reply(7, "a.test", AAAA, 0, &[(AAAA, 1, &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets())]);
		assert_eq!(answer(&six, 7, "a.test", AAAA), Ok(vec![("2001:db8::1".parse().unwrap(), 300)]));
		assert_eq!(answer(&reply(7, "a.test", A, 0, &[]), 7, "a.test", A), Err(Bad::NotFound));
	}

	#[test]
	fn what_is_not_the_answer_is_refused() {
		let good = reply(7, "a.test", A, 0, &[(A, 1, &[192, 0, 2, 1])]);
		assert!(answer(&good, 7, "a.test", A).is_ok());
		assert_eq!(answer(&good, 8, "a.test", A), Err(Bad::Unrelated), "another id");
		assert_eq!(answer(&good, 7, "b.test", A), Err(Bad::Unrelated), "another name");
		assert_eq!(answer(&good, 7, "a.test", AAAA), Err(Bad::Unrelated), "another type");
		let mut query_only = good.clone();
		query_only[2] = 0x01;
		assert_eq!(answer(&query_only, 7, "a.test", A), Err(Bad::Unrelated), "not a response");
		let mut other_opcode = good.clone();
		other_opcode[2] = 0x89;
		assert_eq!(answer(&other_opcode, 7, "a.test", A), Err(Bad::Unrelated));
		assert_eq!(answer(&reply(7, "a.test", A, 3, &[]), 7, "a.test", A), Err(Bad::NotFound));
		assert_eq!(answer(&reply(7, "a.test", A, 2, &[]), 7, "a.test", A), Err(Bad::Failed));
		let mut many = good.clone();
		many[7] = 65;
		assert_eq!(answer(&many, 7, "a.test", A), Err(Bad::Unrelated), "more records than the limit");
		many[7] = 3;
		assert_eq!(answer(&many, 7, "a.test", A), Err(Bad::Unrelated), "records that are not there");
	}

	#[test]
	fn no_cut_of_an_answer_reads_out_of_bounds() {
		let good = reply(7, "a.test", A, 0, &[(A, 1, &[192, 0, 2, 1]), (A, 1, &[192, 0, 2, 2])]);
		for cut in 0..good.len() {assert!(answer(&good[..cut], 7, "a.test", A).is_err(), "{cut}");}
		let mut odd = good.clone();
		odd[HEADER + 11] = 0x80;
		assert!(answer(&odd, 7, "a.test", A).is_err(), "a label length that is neither a length nor a pointer");
	}
}
