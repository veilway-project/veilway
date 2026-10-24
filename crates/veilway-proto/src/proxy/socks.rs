//! The SOCKS5 of a proxy inbound (RFC 1928 and RFC 1929) without any IO: each reader takes the bytes received so far and says that it needs more (`None`), that it has a whole message and how many bytes it used, or why the message is refused. Everything a client sends is attacker input, so nothing is trusted to be whole, and nothing allocates by a length before the bytes of it are there.
//! Datagrams of UDP ASSOCIATE are read by `xray_udp::parse`, the same code the Xray hop runs.
//! The only method the node offers is username and password. A client that does not offer it is answered `0xff` and closed, so there is no anonymous way in.
use super::{destination, Target};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// RFC 1928 reply codes.
pub const GENERAL: u8 = 1;
pub const NOT_ALLOWED: u8 = 2;
pub const UNSUPPORTED_COMMAND: u8 = 7;
pub const UNSUPPORTED_ADDRESS: u8 = 8;

pub const CONNECT: u8 = 1;
pub const ASSOCIATE: u8 = 3;

/// A request of the client: CONNECT or UDP ASSOCIATE (for the second, the address and port the client says it will send from, which are zeros when it does not know).
#[derive(Debug, PartialEq, Eq)]
pub struct Request {pub command: u8, pub target: Target}

/// Reads the client's greeting: the version, and the methods it offers. The answer is whether username and password is among them, and the length of the greeting. A greeting that offers no method at all is refused.
pub fn greeting(buf: &[u8]) -> Result<Option<(bool, usize)>, ()> {
	let [version, count, rest @ ..] = buf else {return Ok(None)};
	if *version != 5 || *count == 0 {return Err(())}
	let count = usize::from(*count);
	if rest.len() < count {return Ok(None)}
	Ok(Some((rest[..count].contains(&2), 2 + count)))
}

/// Reads the username and password of RFC 1929: version 1, then each with a length byte. Neither may be empty. The answer is the pair and the length used.
pub fn credentials(buf: &[u8]) -> Result<Option<((Vec<u8>, Vec<u8>), usize)>, ()> {
	let [version, rest @ ..] = buf else {return Ok(None)};
	if *version != 1 {return Err(())}
	let Some((&user, rest)) = rest.split_first() else {return Ok(None)};
	let user = usize::from(user);
	if user == 0 {return Err(())}
	if rest.len() <= user {return Ok(None)}
	let (name, rest) = rest.split_at(user);
	let pass = usize::from(rest[0]);
	if pass == 0 {return Err(())}
	if rest.len() <= pass {return Ok(None)}
	Ok(Some(((name.to_vec(), rest[1..=pass].to_vec()), 3 + user + pass)))
}

/// Reads the request. The version must be 5 and the reserved byte 0, the command CONNECT or UDP ASSOCIATE (BIND and anything else is answered 7 at once, before the rest is waited for), and the address IPv4, IPv6 or a name. A refusal is the reply code to give.
pub fn request(buf: &[u8]) -> Result<Option<(Request, usize)>, u8> {
	let [version, command, reserved, kind, rest @ ..] = buf else {
		return if buf.first().is_some_and(|version| *version != 5) || buf.get(2).is_some_and(|reserved| *reserved != 0) {Err(GENERAL)} else if buf.get(1).is_some_and(|command| !matches!(*command, CONNECT | ASSOCIATE)) {Err(UNSUPPORTED_COMMAND)} else {Ok(None)};
	};
	if *version != 5 || *reserved != 0 {return Err(GENERAL)}
	if !matches!(*command, CONNECT | ASSOCIATE) {return Err(UNSUPPORTED_COMMAND)}
	let (target, used) = match kind {
		1 if rest.len() >= 6 => (Target::Address(SocketAddr::new(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]).into(), u16::from_be_bytes([rest[4], rest[5]]))), 6),
		4 if rest.len() >= 18 => (Target::Address(SocketAddr::new(Ipv6Addr::from(<[u8; 16]>::try_from(&rest[..16]).map_err(|_| GENERAL)?).into(), u16::from_be_bytes([rest[16], rest[17]]))), 18),
		3 => {
			let Some((&length, tail)) = rest.split_first() else {return Ok(None)};
			let length = usize::from(length);
			if length == 0 {return Err(UNSUPPORTED_ADDRESS)}
			if tail.len() < length + 2 {return Ok(None)}
			let name = std::str::from_utf8(&tail[..length]).map_err(|_| UNSUPPORTED_ADDRESS)?;
			(destination(name, u16::from_be_bytes([tail[length], tail[length + 1]])).ok_or(UNSUPPORTED_ADDRESS)?, 1 + length + 2)
		}
		1 | 4 => return Ok(None),
		_ => return Err(UNSUPPORTED_ADDRESS),
	};
	Ok(Some((Request {command: *command, target}, 4 + used)))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_greeting_is_read_whole_or_waited_for() {
		assert_eq!(greeting(&[]), Ok(None));
		assert_eq!(greeting(&[5]), Ok(None));
		assert_eq!(greeting(&[5, 2, 0]), Ok(None));
		assert_eq!(greeting(&[5, 2, 0, 2]), Ok(Some((true, 4))));
		assert_eq!(greeting(&[5, 1, 0, 9, 9]), Ok(Some((false, 3))), "bytes after the greeting are not part of it");
		assert_eq!(greeting(&[4, 1, 0]), Err(()));
		assert_eq!(greeting(&[5, 0]), Err(()));
	}

	#[test]
	fn credentials_need_both_parts() {
		assert_eq!(credentials(&[1]), Ok(None));
		assert_eq!(credentials(&[1, 2, b'a']), Ok(None));
		assert_eq!(credentials(&[1, 1, b'a']), Ok(None));
		assert_eq!(credentials(&[1, 1, b'a', 2, b'p']), Ok(None));
		assert_eq!(credentials(&[1, 1, b'a', 2, b'p', b'q', 7]), Ok(Some(((b"a".to_vec(), b"pq".to_vec()), 6))));
		assert_eq!(credentials(&[2, 1, b'a', 1, b'p']), Err(()));
		assert_eq!(credentials(&[1, 0, 1, b'p']), Err(()));
		assert_eq!(credentials(&[1, 1, b'a', 0]), Err(()));
	}

	#[test]
	fn a_request_is_read_for_each_kind_of_address() {
		assert_eq!(request(&[5, 1, 0, 1, 93, 184, 216, 34, 1, 187]), Ok(Some((Request {command: CONNECT, target: Target::Address("93.184.216.34:443".parse().unwrap())}, 10))));
		assert_eq!(request(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]), Ok(Some((Request {command: ASSOCIATE, target: Target::Address("0.0.0.0:0".parse().unwrap())}, 10))));
		let mut six = vec![5, 1, 0, 4];
		six.extend_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
		six.extend_from_slice(&[0, 80]);
		assert_eq!(request(&six), Ok(Some((Request {command: CONNECT, target: Target::Address("[2606:4700::1111]:80".parse().unwrap())}, 22))));
		let mut named = vec![5, 1, 0, 3, 11];
		named.extend_from_slice(b"Example.COM");
		named.extend_from_slice(&[1, 187]);
		assert_eq!(request(&named), Ok(Some((Request {command: CONNECT, target: Target::Name("example.com".to_string(), 443)}, 18))));
		for cut in 0..named.len() {assert_eq!(request(&named[..cut]), Ok(None), "{cut} bytes");}
		for cut in 0..10 {assert_eq!(request(&[5, 1, 0, 1, 93, 184, 216, 34, 1, 187][..cut]), Ok(None), "{cut} bytes");}
	}

	#[test]
	fn what_the_node_does_not_carry_is_refused_with_the_code_of_the_rfc() {
		assert_eq!(request(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80]), Err(UNSUPPORTED_COMMAND), "BIND");
		assert_eq!(request(&[5, 2]), Err(UNSUPPORTED_COMMAND), "BIND is refused before the rest of it is waited for");
		assert_eq!(request(&[5, 9, 0, 1]), Err(UNSUPPORTED_COMMAND));
		assert_eq!(request(&[5, 1, 0, 7, 0, 0]), Err(UNSUPPORTED_ADDRESS));
		assert_eq!(request(&[5, 1, 0, 3, 0, 0, 80]), Err(UNSUPPORTED_ADDRESS), "an empty name");
		assert_eq!(request(&[5, 1, 0, 3, 3, 0xff, 0xfe, 0xfd, 0, 80]), Err(UNSUPPORTED_ADDRESS), "a name that is no text");
		assert_eq!(request(&[5, 1, 0, 3, 3, b'a', b' ', b'b', 0, 80]), Err(UNSUPPORTED_ADDRESS), "a name with a space");
		assert_eq!(request(&[4, 1, 0, 1, 1, 2, 3, 4, 0, 80]), Err(GENERAL));
		assert_eq!(request(&[5, 1, 1, 1, 1, 2, 3, 4, 0, 80]), Err(GENERAL), "a reserved byte that is not zero");
	}
}
