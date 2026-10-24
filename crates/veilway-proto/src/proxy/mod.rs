//! What a proxy front end reads from a client, as pure code: the SOCKS5 greeting, login and request (`socks`) and the head of an HTTP proxy request (`http`). The node's proxy inbounds and the client engine's local proxy read their clients with this one code, so the two cannot drift apart. Everything here is attacker input and nothing does IO.
use std::net::{IpAddr, SocketAddr};

pub mod http;
pub mod socks;

/// The destination of a request: an address, or a name that is resolved by whoever carries the connection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {Address(SocketAddr), Name(String, u16)}

/// The destination a client names with a host and a port: an address, or a name in lower case. A name may hold letters, digits, hyphens, underscores and dots, up to 253 bytes, with no empty label. A trailing dot is dropped.
pub fn destination(host: &str, port: u16) -> Option<Target> {
	let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
	if let Ok(ip) = host.parse::<IpAddr>() {return Some(Target::Address(SocketAddr::new(ip, port)))}
	(!host.is_empty() && host.len() <= 253 && !host.starts_with('.') && !host.contains("..") && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))).then_some(Target::Name(host, port))
}
