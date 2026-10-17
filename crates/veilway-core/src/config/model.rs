//! The typed document. Deserializing checks that each value is well formed on its own; `Config::validate` checks everything that relates one value to another.
use super::{DEFAULT_TUNNEL_CONNECTIONS, DEFAULT_MTU, DEFAULT_MTU_OBFS, DEFAULT_PROOFS_PER_SOURCE, DEFAULT_REPLAY_CACHE, DEFAULT_UPGRADE_HEADERS, KEY_CHARS, MAX_CHAIN_LINKS, MAX_CREDENTIAL_BYTES, MAX_DEVICES, MAX_DEVICE_ADDRESSES, MAX_DNS_SETS, MAX_DOMAIN_BYTES, MAX_EXITS, MAX_GROUPS, MAX_INBOUNDS, MAX_LABEL_BYTES, MAX_LINKS, MAX_LINK_CANDIDATES, MAX_LINK_PINS, MAX_NAME_BYTES, MAX_NOTICES, MAX_NOTICE_BYTES, MAX_OUTBOUNDS, MAX_PUBLIC_ADDRESSES, MAX_RULES, MAX_RULE_ENTRIES, MAX_TRANSPORTS, MAX_TRANSPORT_KEYS, MAX_TRANSPORT_SECRETS, MAX_TRUSTED_PROXIES, MAX_TUNNELS, MAX_TUNNEL_CONNECTIONS, MAX_TUNNEL_SOURCES, MAX_UPGRADE_HEADERS, MAX_USERS, MAX_XRAY_INBOUNDS, NAME_PATTERN, TAG_PATTERN};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ipnet::IpNet;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::value::SeqAccessDeserializer;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A value written as one JSON string. A failure reports only what was expected, never the text. The pattern is for the schema: it holds for every text that parses and carries the canonical spelling, not the whole rule.
macro_rules! text_value {
	($name:ident, $expect:literal, $pattern:literal, $parse:expr, $show:expr) => {
		impl<'de> Deserialize<'de> for $name {
			fn deserialize<D: Deserializer<'de>>(d: D) -> Result<$name, D::Error> {
				struct V;
				impl Visitor<'_> for V {
					type Value = $name;
					fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str($expect)}
					fn visit_str<E: de::Error>(self, s: &str) -> Result<$name, E> {
						let parse: fn(&str) -> Result<$name, &'static str> = $parse;
						parse(s).map_err(|expected| E::invalid_value(Unexpected::Other("text"), &expected))
					}
				}
				d.deserialize_str(V)
			}
		}
		impl Serialize for $name {
			fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
				let show: fn(&$name) -> String = $show;
				s.serialize_str(&show(self))
			}
		}
		impl JsonSchema for $name {
			fn schema_name() -> Cow<'static, str> {stringify!($name).into()}
			fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "string", "description": $expect, "pattern": $pattern})}
		}
	};
}

/// A value that is either one of a few words or an object with a single key naming a tag.
macro_rules! word_or_object {
	($name:ident, $expect:literal, [$($word:literal => $unit:ident),+], $key:literal => $object:ident) => {
		impl<'de> Deserialize<'de> for $name {
			fn deserialize<D: Deserializer<'de>>(d: D) -> Result<$name, D::Error> {
				struct V;
				impl<'de> Visitor<'de> for V {
					type Value = $name;
					fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str($expect)}
					fn visit_str<E: de::Error>(self, s: &str) -> Result<$name, E> {
						match s {
							$($word => Ok($name::$unit),)+
							_ => Err(E::unknown_variant(s, &[$($word),+])),
						}
					}
					fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<$name, A::Error> {
						let mut tag = None;
						while let Some(key) = map.next_key::<String>()? {
							if key != $key {return Err(de::Error::unknown_field(&key, &[$key]))}
							if tag.is_some() {return Err(de::Error::duplicate_field($key))}
							tag = Some(map.next_value::<String>()?);
						}
						tag.map($name::$object).ok_or_else(|| de::Error::missing_field($key))
					}
				}
				d.deserialize_any(V)
			}
		}
		impl Serialize for $name {
			fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
				match self {
					$($name::$unit => s.serialize_str($word),)+
					$name::$object(tag) => {
						let mut map = s.serialize_map(Some(1))?;
						map.serialize_entry($key, tag)?;
						map.end()
					}
				}
			}
		}
	};
}

/// The schema of a `word_or_object` value, or of the words one key takes from it.
macro_rules! word_or_object_schema {
	($name:ident, $expect:literal, [$($word:literal),+], $key:literal) => {
		impl JsonSchema for $name {
			fn schema_name() -> Cow<'static, str> {stringify!($name).into()}
			fn json_schema(_: &mut SchemaGenerator) -> Schema {
				json_schema!({"description": $expect, "oneOf": [{"enum": [$($word),+]}, {"type": "object", "properties": {$key: {"type": "string", "pattern": TAG_PATTERN}}, "required": [$key], "additionalProperties": false}]})
			}
		}
	};
}

/// Lowercase ASCII labels of letters, digits and inner hyphens, the last one neither all digits nor `0x` and hex digits, so the name cannot be read as an address in any spelling. With `wildcard`, `*.` may lead and needs two labels after it.
pub(crate) fn domain(s: &str, wildcard: bool) -> bool {
	let name = match s.strip_prefix("*.") {
		Some(rest) if wildcard => rest,
		_ => s,
	};
	s.len() <= MAX_DOMAIN_BYTES && name.split('.').count() >= if name.len() < s.len() {2} else {1}
		&& name.split('.').all(|l| (1..=MAX_LABEL_BYTES).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !l.starts_with('-') && !l.ends_with('-'))
		&& !name.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()) || l.strip_prefix("0x").is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// `[a-z0-9][a-z0-9_-]{0,63}`, with `.` as well when `dot` is set.
pub(crate) fn ident(s: &str, dot: bool) -> bool {
	(1..=MAX_NAME_BYTES).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || (dot && b == b'.')) && s.as_bytes()[0].is_ascii_alphanumeric()
}

fn ip(s: &str) -> Result<IpAddr, &'static str> {
	if s.contains('%') {return Err("an address without a zone")}
	match s.parse() {
		Ok(IpAddr::V6(a)) if a.to_ipv4_mapped().is_some() => Err("an address that is not IPv4-mapped IPv6"),
		Ok(ip) => Ok(ip),
		Err(_) => Err("an IPv4 or IPv6 address"),
	}
}

fn net(s: &str, host_bits: bool) -> Result<IpNet, &'static str> {
	let (addr, prefix) = s.split_once('/').ok_or("a network with a prefix length such as 10.7.0.0/24")?;
	if prefix.is_empty() || prefix.len() > 3 || (prefix.len() > 1 && prefix.starts_with('0')) || !prefix.bytes().all(|b| b.is_ascii_digit()) {return Err("a prefix length written as a plain number with no leading zeros")}
	let net = IpNet::new(ip(addr)?, prefix.parse().map_err(|_| "a prefix length that fits the address family")?).map_err(|_| "a prefix length that fits the address family")?;
	if !host_bits && net.trunc() != net {return Err("a network with no host bits set")}
	Ok(net)
}

fn port(s: &str) -> Result<u16, &'static str> {
	if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {return Err("a port from 1 to 65535")}
	s.parse().map_err(|_| "a port from 1 to 65535")
}

/// What stands in the place of every secret in a document the control API shows. In a document it is sent, it stands for the value the same object has in the running config, see `Config::parse_keeping`.
pub const REDACTED: &str = "<redacted>";

thread_local! {
	/// Set while `Config::redacted` serializes on this thread.
	static REDACTING: Cell<bool> = const {Cell::new(false)};
}

/// A secret. No diagnostic, log line or `Debug` output shows it.
// `Serialize` writes the real value, because that is how the document is saved. `Config::redacted` is the one way to a document without them, and it covers every `Secret` there is or will be, because the marker is written here.
#[derive(Deserialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(transparent)]
#[schemars(inline)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
	pub fn expose(&self) -> &T {&self.0}
}

impl<T: Serialize> Serialize for Secret<T> {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {if REDACTING.get() {s.serialize_str(REDACTED)} else {self.0.serialize(s)}}
}

impl Config {
	/// The document with `REDACTED` in the place of every secret, for whoever may see the config and not its keys and passwords.
	pub fn redacted(&self) -> serde_json::Value {
		// Switched off again however this ends: a flag left on would write the marker into the next config file that is saved.
		struct Off;
		impl Drop for Off {
			fn drop(&mut self) {REDACTING.set(false)}
		}
		let _off = Off;
		REDACTING.set(true);
		serde_json::to_value(self).unwrap_or_default()
	}
}

impl<T> fmt::Debug for Secret<T> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("<secret>")}
}

impl<T> fmt::Display for Secret<T> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("<secret>")}
}

/// A WireGuard key as its 32 decoded bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(pub [u8; 32]);

impl fmt::Debug for Key {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {write!(f, "Key({})", STANDARD.encode(self.0))}
}

text_value!(Key, "a WireGuard key: 44 characters of standard base64 with padding", "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", |s| {
	match STANDARD.decode(s).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
		Some(key) if s.len() == KEY_CHARS && key != [0; 32] => Ok(Key(key)),
		Some(_) if s.len() == KEY_CHARS => Err("a key that is not all zero"),
		_ => Err("a WireGuard key: 44 characters of standard base64 with padding"),
	}
}, |key| STANDARD.encode(key.0));

/// A device transport secret as its 32 decoded bytes: uniformly random, and written like a WireGuard key. It is a secret like those inside a `Secret`: `Debug` shows nothing of it, and `Config::redacted` writes a marker in its place.
/// That marker is not the one of the other secrets. A device may have two of these, and a marker that comes back has to say which of them it stands for, so it names its secret, see `reload::marker`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportSecret(pub [u8; 32]);

impl fmt::Debug for TransportSecret {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("TransportSecret(..)")}
}

text_value!(TransportSecret, "a transport secret: 44 characters of standard base64 with padding", "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", |s| {
	match STANDARD.decode(s).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
		Some(secret) if s.len() == KEY_CHARS && secret != [0; 32] => Ok(TransportSecret(secret)),
		Some(_) if s.len() == KEY_CHARS => Err("a secret that is not all zero"),
		_ => Err("a transport secret: 44 characters of standard base64 with padding"),
	}
}, |secret| if REDACTING.get() {super::reload::marker(&secret.0)} else {STANDARD.encode(secret.0)});

/// The private half of a node transport key as its 32 decoded bytes: an X25519 key that the tokens of the stream proof are sealed to, written like a WireGuard key and never one of them. It is a secret, and an inbound may have two, so it is shown like a transport secret: by a marker that names it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportKey(pub [u8; 32]);

impl fmt::Debug for TransportKey {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("TransportKey(..)")}
}

text_value!(TransportKey, "a transport key: 44 characters of standard base64 with padding", "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", |s| {
	match STANDARD.decode(s).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
		Some(key) if s.len() == KEY_CHARS && key != [0; 32] => Ok(TransportKey(key)),
		Some(_) if s.len() == KEY_CHARS => Err("a key that is not all zero"),
		_ => Err("a transport key: 44 characters of standard base64 with padding"),
	}
}, |key| if REDACTING.get() {super::reload::marker(&key.0)} else {STANDARD.encode(key.0)});

/// Where the decoy origin is: the host and port of an `http://` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin(pub HostPort);

impl Origin {
	/// What the node's own requests to the origin carry as `Host`: "the host of the `decoy.origin` URL", with the port where that is not 80.
	pub fn host(&self) -> String {
		let host = match &self.0.host {
			Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
			Host::Ip(IpAddr::V4(v4)) => v4.to_string(),
			Host::Name(name) => name.clone(),
		};
		if self.0.port == 80 {host} else {format!("{host}:{}", self.0.port)}
	}
}

const ORIGIN: &str = "an http:// URL of the operator's own web server with nothing behind the host and port, such as http://127.0.0.1:8080. This build has no https:// origin";

// Transports page, "What the decoy origin must be": "`decoy.origin` is an `http://` or `https://` URL with an address or a name." This build reaches the origin over plain HTTP only: the page does not say which roots and which name an `https://` origin is verified against, so such a URL is refused until it does.
text_value!(Origin, "an http:// URL of the operator's own web server with nothing behind the host and port, such as http://127.0.0.1:8080. This build has no https:// origin", "^http://([a-z0-9.-]{1,253}|\\[[0-9A-Fa-f:.]+\\])(:[1-9][0-9]{0,4})?/?$", |s| {
	let rest = s.strip_prefix("http://").ok_or(ORIGIN)?;
	let rest = rest.strip_suffix('/').unwrap_or(rest);
	let (host, port) = match rest.rfind(':').filter(|at| !rest[*at..].contains(']')) {
		Some(at) => (&rest[..at], port(&rest[at + 1..])?),
		None => (rest, 80),
	};
	let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
		Some(v6) => Host::Ip(ip(v6).ok().filter(IpAddr::is_ipv6).ok_or("an IPv6 address between the brackets, with no zone and not IPv4-mapped")?),
		None => match host.parse::<std::net::Ipv4Addr>() {
			Ok(v4) => Host::Ip(IpAddr::V4(v4)),
			Err(_) if domain(host, false) => Host::Name(host.to_string()),
			Err(_) => return Err(ORIGIN),
		},
	};
	Ok(Origin(HostPort {host, port}))
}, |origin| format!("http://{}", origin.host()));

/// An address and port: a DNS server or a listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Addr(pub SocketAddr);

text_value!(Addr, "an address and port such as 192.0.2.1:443 or [2001:db8::1]:443", "^[0-9A-Fa-f:.\\[\\]]+:[1-9][0-9]{0,4}$", |s| {
	if s.contains('%') {return Err("an address without a zone")}
	match s.parse::<SocketAddr>() {
		// The standard parser reads a port with leading zeros, so the text is compared with the port it read.
		Ok(addr) if addr.port() == 0 || !s.ends_with(&format!(":{}", addr.port())) => Err("a port from 1 to 65535 with no leading zeros"),
		Ok(SocketAddr::V6(addr)) if addr.ip().to_ipv4_mapped().is_some() => Err("an address that is not IPv4-mapped IPv6"),
		Ok(addr) => Ok(Addr(addr)),
		Err(_) => Err("an address and port such as 192.0.2.1:443 or [2001:db8::1]:443"),
	}
}, |addr| addr.0.to_string());

/// One address, written without a prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ip(pub IpAddr);

text_value!(Ip, "an IPv4 or IPv6 address without a prefix", "^[0-9A-Fa-f:.]+$", |s| ip(s).map(Ip), |ip| ip.0.to_string());

/// One reverse proxy of a `ws` or `fronted` transport, or a network of them. An address alone is the network of that one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Proxy(pub IpNet);

text_value!(Proxy, "an address such as 127.0.0.1 or a network such as 10.0.0.0/8 with no host bits set", "^[0-9A-Fa-f:.]+(/(0|[1-9][0-9]{0,2}))?$", |s| if s.contains('/') {net(s, false).map(Proxy)} else {ip(s).map(|ip| Proxy(IpNet::from(ip)))}, |proxy| if proxy.0.prefix_len() == proxy.0.max_prefix_len() {proxy.0.addr().to_string()} else {proxy.0.to_string()});

/// One entry of a rule's `ip` condition: a network, the name `geoip:private` for the ranges in `GEOIP_PRIVATE` outside every inbound pool, the name `tunnel:users` for every address in every inbound pool except the gateways, or `tunnel:<inbound tag>` for those of one inbound.
/// `Tunnel` holds the tag as written. Whether an inbound has it is for `validate` to say.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IpEntry {Net(IpNet), Private, Users, Tunnel(String)}

text_value!(IpEntry, "a network such as 10.7.0.0/24 with no host bits set, geoip:private, tunnel:users or tunnel:<inbound tag>", "^([0-9A-Fa-f:.]+/(0|[1-9][0-9]{0,2})|geoip:private|tunnel:[a-z0-9][a-z0-9_-]{0,63})$", |s| {
	match (net(s, false), s.strip_prefix("tunnel:")) {
		_ if s == "geoip:private" => Ok(IpEntry::Private),
		_ if s == "tunnel:users" => Ok(IpEntry::Users),
		(_, Some(tag)) if ident(tag, false) => Ok(IpEntry::Tunnel(tag.to_string())),
		(Ok(net), _) => Ok(IpEntry::Net(net)),
		(Err(_), _) if s.contains(':') => Err("an IPv6 network with no host bits set, geoip:private, tunnel:users or tunnel:<inbound tag>: no other geoip name is supported in this version"),
		(Err(expected), _) => Err(expected),
	}
}, |entry| match entry {
	IpEntry::Net(net) => net.to_string(),
	IpEntry::Private => "geoip:private".to_string(),
	IpEntry::Users => "tunnel:users".to_string(),
	IpEntry::Tunnel(tag) => format!("tunnel:{tag}"),
});

/// One network that may connect to a tunnel. An address alone is the network of that one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Source(pub IpNet);

text_value!(Source, "an address such as 192.0.2.1 or a network such as 192.0.2.0/24 with no host bits set", "^[0-9A-Fa-f:.]+(/(0|[1-9][0-9]{0,2}))?$", |s| if s.contains('/') {net(s, false).map(Source)} else {ip(s).map(|ip| Source(IpNet::from(ip)))}, |source| if source.0.prefix_len() == source.0.max_prefix_len() {source.0.addr().to_string()} else {source.0.to_string()});

/// An inbound's gateway address with the prefix of its pool. The host part is the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GatewayNet(pub IpNet);

text_value!(GatewayNet, "a gateway address with its prefix such as 10.7.0.1/24", "^[0-9A-Fa-f:.]+/[1-9][0-9]{0,2}$", |s| net(s, true).map(GatewayNet), |net| net.0.to_string());

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {Ip(IpAddr), Name(String)}

text_value!(Host, "an IP address or a lowercase host name, with no port", "^[0-9A-Za-z.:-]{1,253}$", |s| {
	if let Ok(addr) = ip(s) {return Ok(Host::Ip(addr))}
	if domain(s, false) {Ok(Host::Name(s.to_string()))} else {Err("an IP address or a lowercase host name, with no port")}
}, |host| match host {
	Host::Ip(addr) => addr.to_string(),
	Host::Name(name) => name.clone(),
});

/// A SOCKS5 server: an address or a host name, and a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPort {pub host: Host, pub port: u16}

text_value!(HostPort, "a host and port such as proxy.example.com:1080, with an IPv6 address in brackets", "^([a-z0-9.-]{1,253}|\\[[0-9A-Fa-f:.]+\\]):[1-9][0-9]{0,4}$", |s| {
	let (host, tail) = s.rsplit_once(':').ok_or("a host and port such as proxy.example.com:1080, with an IPv6 address in brackets")?;
	let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
		Some(v6) => Host::Ip(ip(v6).ok().filter(IpAddr::is_ipv6).ok_or("an IPv6 address between the brackets, with no zone and not IPv4-mapped")?),
		None => match host.parse::<std::net::Ipv4Addr>() {
			Ok(v4) => Host::Ip(IpAddr::V4(v4)),
			Err(_) if domain(host, false) => Host::Name(host.to_string()),
			Err(_) => return Err("an IPv4 address, an IPv6 address in brackets or a lowercase host name before the port"),
		},
	};
	Ok(HostPort {host, port: port(tail)?})
}, |server| match &server.host {
	Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]:{}", server.port),
	Host::Ip(IpAddr::V4(v4)) => format!("{v4}:{}", server.port),
	Host::Name(name) => format!("{name}:{}", server.port),
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp(pub OffsetDateTime);

text_value!(Timestamp, "an RFC 3339 timestamp with an offset such as 2027-01-31T00:00:00Z", "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}", |s| {
	if s.as_bytes().get(10) != Some(&b'T') {return Err("an RFC 3339 timestamp with T between date and time such as 2027-01-31T00:00:00Z")}
	OffsetDateTime::parse(s, &Rfc3339).map(Timestamp).map_err(|_| "an RFC 3339 timestamp with an offset such as 2027-01-31T00:00:00Z")
}, |at| at.0.format(&Rfc3339).unwrap_or_default());

/// An IP protocol number. A name and its number are the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Protocol(pub u8);

impl Protocol {
	pub const NAMES: [(&'static str, u8); 7] = [("tcp", 6), ("udp", 17), ("icmp", 1), ("icmpv6", 58), ("gre", 47), ("esp", 50), ("sctp", 132)];
	pub const TCP: u8 = 6;
	pub const UDP: u8 = 17;
	pub const ICMP: u8 = 1;
	pub const ICMPV6: u8 = 58;
	pub const SCTP: u8 = 132;
}

impl<'de> Deserialize<'de> for Protocol {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Protocol, D::Error> {
		struct V;
		impl Visitor<'_> for V {
			type Value = Protocol;
			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("a protocol name or an integer from 0 to 255")}
			fn visit_str<E: de::Error>(self, s: &str) -> Result<Protocol, E> {
				Protocol::NAMES.iter().find(|(name, _)| *name == s).map(|(_, n)| Protocol(*n)).ok_or_else(|| E::unknown_variant(s, &["tcp", "udp", "icmp", "icmpv6", "gre", "esp", "sctp"]))
			}
			fn visit_u64<E: de::Error>(self, n: u64) -> Result<Protocol, E> {u8::try_from(n).map(Protocol).map_err(|_| E::invalid_value(Unexpected::Other("integer"), &self))}
		}
		d.deserialize_any(V)
	}
}

impl Serialize for Protocol {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		match Protocol::NAMES.iter().find(|(_, n)| *n == self.0) {
			Some((name, _)) => s.serialize_str(name),
			None => s.serialize_u8(self.0),
		}
	}
}

impl JsonSchema for Protocol {
	fn schema_name() -> Cow<'static, str> {"Protocol".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {
		json_schema!({"oneOf": [{"enum": ["tcp", "udp", "icmp", "icmpv6", "gre", "esp", "sctp"]}, {"type": "integer", "minimum": 0, "maximum": 255}]})
	}
}

/// Destination ports `lo` to `hi`, both included. One port is a range with `lo == hi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortRange {pub lo: u16, pub hi: u16}

impl<'de> Deserialize<'de> for PortRange {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<PortRange, D::Error> {
		struct V;
		impl Visitor<'_> for V {
			type Value = PortRange;
			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("a port from 1 to 65535 or a string \"lo-hi\" with lo <= hi")}
			fn visit_u64<E: de::Error>(self, n: u64) -> Result<PortRange, E> {
				match u16::try_from(n) {
					Ok(port) if port > 0 => Ok(PortRange {lo: port, hi: port}),
					_ => Err(E::invalid_value(Unexpected::Other("integer"), &self)),
				}
			}
			fn visit_str<E: de::Error>(self, s: &str) -> Result<PortRange, E> {
				match s.split_once('-').map(|(lo, hi)| (port(lo), port(hi))) {
					Some((Ok(lo), Ok(hi))) if lo <= hi => Ok(PortRange {lo, hi}),
					_ => Err(E::invalid_value(Unexpected::Other("text"), &self)),
				}
			}
		}
		d.deserialize_any(V)
	}
}

impl Serialize for PortRange {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		if self.lo == self.hi {s.serialize_u16(self.lo)} else {s.serialize_str(&format!("{}-{}", self.lo, self.hi))}
	}
}

impl JsonSchema for PortRange {
	fn schema_name() -> Cow<'static, str> {"PortRange".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {
		json_schema!({"oneOf": [{"type": "integer", "minimum": 1, "maximum": 65535}, {"type": "string", "pattern": "^[1-9][0-9]{0,4}-[1-9][0-9]{0,4}$"}]})
	}
}

/// The exits a user may leave through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exits {All, List(Vec<String>)}

impl<'de> Deserialize<'de> for Exits {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Exits, D::Error> {
		struct V;
		impl<'de> Visitor<'de> for V {
			type Value = Exits;
			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("\"all\" or a list of exit tags")}
			fn visit_str<E: de::Error>(self, s: &str) -> Result<Exits, E> {if s == "all" {Ok(Exits::All)} else {Err(E::unknown_variant(s, &["all"]))}}
			fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Exits, A::Error> {Vec::deserialize(SeqAccessDeserializer::new(seq)).map(Exits::List)}
		}
		d.deserialize_any(V)
	}
}

impl Serialize for Exits {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		match self {
			Exits::All => s.serialize_str("all"),
			Exits::List(list) => list.serialize(s),
		}
	}
}

impl JsonSchema for Exits {
	fn schema_name() -> Cow<'static, str> {"Exits".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"oneOf": [{"const": "all"}, {"type": "array", "items": {"type": "string", "pattern": TAG_PATTERN}, "maxItems": MAX_EXITS}]})}
}

/// What a netstack exit does with traffic its outbound cannot carry. Which words a key takes is checked by `validate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {Local, Reject, Drop, Direct, Via(String)}

word_or_object!(Policy, "\"local\", \"reject\", \"drop\", \"direct\" or {\"via\": \"<exit tag>\"}", ["local" => Local, "reject" => Reject, "drop" => Drop, "direct" => Direct], "via" => Via);

// The document reads all three keys of `unsupported` as `Policy`, so a word a key does not take is reported by `validate` with its path. These only give each key its own words in the schema.
enum IcmpEchoPolicy {}
enum UdpPolicy {}
enum OtherPolicy {}

word_or_object_schema!(IcmpEchoPolicy, "\"local\", \"reject\", \"drop\", \"direct\" or {\"via\": \"<exit tag>\"}", ["local", "reject", "drop", "direct"], "via");
word_or_object_schema!(UdpPolicy, "\"reject\", \"drop\", \"direct\" or {\"via\": \"<exit tag>\"}", ["reject", "drop", "direct"], "via");
word_or_object_schema!(OtherPolicy, "\"reject\", \"drop\" or {\"via\": \"<exit tag>\"}", ["reject", "drop"], "via");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {Exit(String), User, Block, Reject}

word_or_object!(Action, "{\"exit\": \"<exit tag>\"}, \"user\", \"block\" or \"reject\"", ["user" => User, "block" => Block, "reject" => Reject], "exit" => Exit);
word_or_object_schema!(Action, "{\"exit\": \"<exit tag>\"}, \"user\", \"block\" or \"reject\"", ["user", "block", "reject"], "exit");

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
	#[schemars(range(min = 1, max = 1))]
	pub version: u64,
	#[serde(default)]
	pub log: Log,
	pub dns: Dns,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_GROUPS), inner(pattern(NAME_PATTERN)))]
	pub groups: Vec<String>,
	#[schemars(length(max = MAX_INBOUNDS))]
	pub inbounds: Vec<Inbound>,
	#[schemars(length(max = MAX_OUTBOUNDS))]
	pub outbounds: Vec<Outbound>,
	#[schemars(length(max = MAX_EXITS))]
	pub exits: Vec<Exit>,
	pub routing: Routing,
	#[schemars(length(max = MAX_USERS))]
	pub users: Vec<User>,
	/// What the operator tells every device on the control channel of a `veilway` inbound, as plain text.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_NOTICES))]
	pub notices: Vec<Notice>,
	/// The addresses a profile of this node is given, as host names or IP addresses with no port: each transport keeps the port of its own listener.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_PUBLIC_ADDRESSES))]
	pub public_addresses: Vec<Host>,
	/// The replay memory of the obfuscated transports. Only a node with such a transport keeps one.
	#[serde(default, skip_serializing_if = "Replay::is_default")]
	pub replay: Replay,
	/// The node links of this node: each joins it to one other node, so that users connect to one of the two and their traffic leaves from the other.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_LINKS))]
	pub links: Vec<Link>,
	/// The ports of this node that are forwarded through a `chain` exit to an address on the far side of a node link, with no client.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_TUNNELS))]
	pub tunnels: Vec<Tunnel>,
	/// The Xray add-on: inbounds of Xray that carry the users listed in their `clients`. Off when the key is absent.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub xray: Option<Xray>,
}

/// Accepted proofs one source may bring: `burst` at once, then `rate` a second. A source is an IPv4 address or an IPv6 /64.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofRate {
	#[schemars(range(min = 1, max = 65536))]
	pub burst: u32,
	#[schemars(range(min = 1, max = 65536))]
	pub rate: u32,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Replay {
	/// How many accepted proofs the node remembers at once. Defaults to 262144. It is read at start: a reload that changes it changes nothing until the node starts again.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1024, max = 1048576))]
	pub cache: Option<u32>,
	/// Defaults to a burst of 256 and 32 a second.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub per_source: Option<ProofRate>,
}

impl Replay {
	fn is_default(&self) -> bool {*self == Replay::default()}

	pub fn cache(&self) -> usize {self.cache.unwrap_or(DEFAULT_REPLAY_CACHE) as usize}

	pub fn per_source(&self) -> ProofRate {self.per_source.unwrap_or(DEFAULT_PROOFS_PER_SOURCE)}
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NoticeSeverity {#[default] Information, Warning}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Notice {
	/// Defaults to "information".
	#[serde(default, skip_serializing_if = "NoticeSeverity::is_information")]
	pub severity: NoticeSeverity,
	#[schemars(length(min = 1, max = MAX_NOTICE_BYTES))]
	pub text: String,
}

impl NoticeSeverity {
	fn is_information(&self) -> bool {*self == NoticeSeverity::Information}
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {Error, Warn, #[default] Info, Debug, Trace}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Log {
	#[serde(default)]
	pub level: LogLevel,
	/// Whether log lines may contain the destinations and DNS names users reach.
	#[serde(default)]
	pub destinations: bool,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
	#[schemars(length(min = 1, max = 4))]
	pub servers: Vec<Addr>,
	/// Defaults to true.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub hijack: Option<bool>,
	/// Other lists of servers, each for the inbounds, groups and users it names. Whoever no set names asks `servers`.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_DNS_SETS))]
	pub sets: Vec<DnsSet>,
}

impl Dns {
	/// The set that names each user, each group and each inbound, as indexes into `sets`. In a document that validates nothing is named by two sets.
	pub fn named(&self) -> [HashMap<&str, usize>; 3] {
		let of = |list: fn(&DnsSet) -> &Vec<String>| self.sets.iter().enumerate().flat_map(|(at, set)| list(set).iter().map(move |name| (name.as_str(), at))).collect();
		[of(|set| &set.users), of(|set| &set.groups), of(|set| &set.inbounds)]
	}
}

/// A set that names a user decides for that user, before one that names a group of theirs, before one that names the inbound a query came through.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsSet {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	#[schemars(length(min = 1, max = 4))]
	pub servers: Vec<Addr>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_INBOUNDS), inner(pattern(TAG_PATTERN)))]
	pub inbounds: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_GROUPS), inner(pattern(NAME_PATTERN)))]
	pub groups: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_USERS), inner(pattern(NAME_PATTERN)))]
	pub users: Vec<String>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InboundType {
	/// Plain WireGuard. Its gateway answers DNS and ping, and nothing else.
	Wireguard,
	/// The same tunnel with the control channel at its gateway address. Every device with an address in it has a transport secret.
	Veilway,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	#[serde(rename = "type")]
	pub kind: InboundType,
	pub private_key: Secret<Key>,
	#[schemars(length(min = 1, max = 2))]
	pub address: Vec<GatewayNet>,
	/// Defaults to 1420, and to 1390 for a `veilway` inbound with a `udp-obfs` transport.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1280, max = 1500))]
	pub mtu: Option<u16>,
	/// The upper bounds of the padding the node puts on what it sends over the obfuscated transports of a `veilway` inbound.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub padding: Option<Padding>,
	/// The node transport keys, private halves: one, or two while the key is rotated. Needed by an inbound with a `tls`, native `ws` or `fronted` transport. Profiles carry the public half of the first.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_TRANSPORT_KEYS))]
	pub transport_keys: Option<Vec<TransportKey>>,
	/// The name of the cookie on the upgrade answer of a `tls` or native `ws` transport. It has no default and carries no meaning: its value is random text of a random length.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern("^[A-Za-z0-9_-]{1,32}$"))]
	pub upgrade_cookie: Option<String>,
	/// The header fields the upgrade answer takes from the decoy origin, in this order. Defaults to `Server`, `Date` for a `tls` transport and to none for a native `ws` transport, where the web server in front adds its own.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(max = MAX_UPGRADE_HEADERS), inner(pattern("^[A-Za-z0-9-]{1,64}$")))]
	pub upgrade_headers: Option<Vec<String>>,
	#[schemars(length(min = 1, max = 8))]
	pub transports: Vec<Transport>,
}

impl Inbound {
	/// Whether the inbound has a transport that wraps its datagrams in `udp-obfs`.
	pub fn enveloped(&self) -> bool {self.transports.iter().any(|transport| matches!(transport, Transport::UdpObfs {..}))}

	/// Whether the inbound has a transport that takes the stream proof.
	pub fn proved(&self) -> bool {self.transports.iter().any(|transport| transport.decoy().is_some())}

	/// Whether the inbound has a transport whose proof is answered with a WebSocket upgrade, which carries the inbound's cookie: `tls` or the native `ws`.
	pub fn upgraded(&self) -> bool {self.transports.iter().any(|transport| matches!(transport, Transport::Tls {..} | Transport::WsNative {..}))}

	/// Whether the inbound has an obfuscated transport of this build: one that takes a proof, and so needs the replay memory.
	pub fn obfuscated(&self) -> bool {self.enveloped() || self.proved()}

	/// The `mtu` in force (transports page, "MTU": "The proposed default `mtu` of such an inbound is 1390, and 1420 otherwise").
	pub fn mtu(&self) -> u16 {self.mtu.unwrap_or(if self.kind == InboundType::Veilway && self.enveloped() {DEFAULT_MTU_OBFS} else {DEFAULT_MTU})}

	/// The fields the upgrade answer takes from the decoy origin: "The default list is `Server`, `Date` on a `tls` listener and empty on a `ws` listener, where the front web server adds its own." `tls` says which of the two the answer is for.
	pub fn upgrade_headers(&self, tls: bool) -> Vec<String> {self.upgrade_headers.clone().unwrap_or_else(|| DEFAULT_UPGRADE_HEADERS.iter().filter(|_| tls).map(|name| name.to_string()).collect())}

	/// The WireGuard public key of the inbound.
	pub fn public_key(&self) -> Key {Key(veilway_wg::public_key(&self.private_key.expose().0))}

	/// The public half of the first node transport key, which a profile carries.
	pub fn transport_public_key(&self) -> Option<Key> {self.transport_keys.as_ref()?.first().map(|key| Key(veilway_proto::proof::public_key(&key.0)))}
}

/// Transports page, "Padding", rule 4: the bounds "may be set per profile for the client and per inbound for the node, inside the bounds in the table of numbers".
#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Padding {
	/// The most bytes of wide padding. Defaults to 1023.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 512, max = 1023))]
	pub wide: Option<u16>,
	/// The most bytes of normal padding. Defaults to 255.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 64, max = 255))]
	pub normal: Option<u16>,
}

/// Node capacity numbers of one listener (transports page, "Numbers that are judgement calls").
#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportLimits {
	/// Established sessions the listener holds at once. Defaults to 16384.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 1048576))]
	pub sessions: Option<u32>,
	/// Connections of a stream listener that have not sent their request line yet. Defaults to 512.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub undecided: Option<u32>,
	/// How many of those one source may have. A source is an IPv4 address or an IPv6 /64. Defaults to 64.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub undecided_per_source: Option<u32>,
	/// Connections of a stream listener that are relayed to the decoy origin. Defaults to 1024.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub relayed: Option<u32>,
	/// Connections from `trusted_proxies` a `ws` or `fronted` listener holds at once. Defaults to twice its `fronted_sessions`. Requests of strangers that wait for the decoy origin hold at most half of them.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 2, max = 65536))]
	pub proxy_connections: Option<u32>,
	/// Requests one source may have waiting for the decoy origin at once on a `ws` or `fronted` listener. Defaults to 16.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub decoy_requests_per_source: Option<u32>,
	/// Established `fronted` sessions the listener holds at once, each of which keeps its last response, up to 65536 bytes. Defaults to 1024, which is 64 MiB when full.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub fronted_sessions: Option<u32>,
	/// Established `fronted-shaped` sessions the listener holds at once, counted among its `fronted_sessions`. Each can hold up to 603136 bytes. Defaults to 256, which is about 147 MiB when full.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub shaped_sessions: Option<u32>,
}

/// The decoy origin of a stream listener: the operator's own web server, which answers everyone who is not a user.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Decoy {
	pub origin: Origin,
	/// Whether the node sends the PROXY protocol header, version 2, at the start of every connection to the origin. Defaults to false.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub proxy_protocol: Option<bool>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tls {
	#[schemars(length(min = 1))]
	pub cert: String,
	#[schemars(length(min = 1))]
	pub key: String,
}

/// The certificate of a native `tls` transport: files the operator obtains with their own tooling, or one the node makes itself.
#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Certificate {
	Files(Tls),
	SelfSigned(SelfSigned),
}

/// `{"self_signed": true}`: the node makes an ECDSA P-256 key and a self-signed certificate on its first start, keeps them next to the config file with mode 600, makes the certificate anew with the same key before it runs out, and reports the pin, the SHA-256 of the SubjectPublicKeyInfo, that profiles carry with `self_signed`.
#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfSigned {
	#[schemars(extend("const" = true))]
	pub self_signed: bool,
	/// The operator's own host name, which the certificate carries as its subject and its alternative name. Without it the node draws a name per node and keeps it.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(max = 64), pattern("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"))]
	pub name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateKeys {cert: Option<String>, key: Option<String>, self_signed: Option<bool>, name: Option<String>}

impl<'de> Deserialize<'de> for Certificate {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Certificate, D::Error> {
		match CertificateKeys::deserialize(d)? {
			CertificateKeys {self_signed: Some(true), cert: None, key: None, name} => Ok(Certificate::SelfSigned(SelfSigned {self_signed: true, name})),
			CertificateKeys {self_signed: Some(true), ..} => Err(de::Error::custom("no `cert` or `key` with `self_signed`: the node makes the key and the certificate itself")),
			CertificateKeys {self_signed: Some(false), ..} => Err(de::Error::invalid_value(Unexpected::Bool(false), &"true, or no `self_signed` and a `cert` and a `key`")),
			CertificateKeys {name: Some(_), ..} => Err(de::Error::custom("`name` only with `self_signed`: a certificate from files has the name it was issued for")),
			CertificateKeys {cert, key, self_signed: None, name: None} => Ok(Certificate::Files(Tls {cert: cert.ok_or_else(|| de::Error::missing_field("cert"))?, key: key.ok_or_else(|| de::Error::missing_field("key"))?})),
		}
	}
}

/// What a censor can see of a profile's connection, computed here so that the panel and the clients agree. See PLAN.md, "three ratings".
#[derive(Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Rating {Protected, Detectable, Unsafe}

#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transport {
	Udp {listen: Addr},
	Ws {
		listen: Addr,
		#[schemars(pattern("^/[A-Za-z0-9._~/-]{0,255}$"))]
		path: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		tls: Option<Tls>,
	},
	/// WireGuard datagrams inside the `udp-obfs` envelope, for a `veilway` inbound.
	#[serde(rename = "udp-obfs")]
	UdpObfs {
		listen: Addr,
		#[serde(skip_serializing_if = "Option::is_none")]
		limits: Option<TransportLimits>,
	},
	/// The native WebSocket session inside TLS that the node ends itself, for a `veilway` inbound. Whoever is not a user is relayed to `decoy.origin`.
	Tls {
		listen: Addr,
		/// The path a proof arrives on, which the origin must serve nothing at.
		#[schemars(pattern("^/[A-Za-z0-9._~/-]{11,255}$"))]
		path: String,
		tls: Certificate,
		decoy: Decoy,
		#[serde(skip_serializing_if = "Option::is_none")]
		limits: Option<TransportLimits>,
	},
	/// The native WebSocket session behind the operator's own web server, for a `veilway` inbound: `ws` with a `decoy`. The node never ends TLS here. It reads plain HTTP from `trusted_proxies`, and whoever is not a user is answered by `decoy.origin`.
	#[serde(rename = "ws")]
	WsNative {
		listen: Addr,
		/// The path a proof arrives on, as the web server in front hands it on, which the origin must serve nothing at.
		#[schemars(pattern("^/[A-Za-z0-9._~/-]{11,255}$"))]
		path: String,
		decoy: Decoy,
		/// The operator's own reverse proxies, as addresses and networks. Only a connection from one of them can carry a user, and only from them is `client_address_header` believed.
		#[schemars(length(min = 1, max = MAX_TRUSTED_PROXIES))]
		trusted_proxies: Vec<Proxy>,
		/// The header field in which the proxies name the address a request came from, such as `X-Forwarded-For`. Without it every visitor counts as the proxy itself.
		#[serde(skip_serializing_if = "Option::is_none")]
		#[schemars(pattern("^[A-Za-z0-9-]{1,64}$"))]
		client_address_header: Option<String>,
		#[serde(skip_serializing_if = "Option::is_none")]
		limits: Option<TransportLimits>,
	},
	/// Polling with HTTP requests through a CDN that allows nothing better, behind the operator's own web server, for a `veilway` inbound. Its keys are those of the native `ws`.
	Fronted {
		listen: Addr,
		#[schemars(pattern("^/[A-Za-z0-9._~/-]{11,255}$"))]
		path: String,
		decoy: Decoy,
		#[schemars(length(min = 1, max = MAX_TRUSTED_PROXIES))]
		trusted_proxies: Vec<Proxy>,
		#[serde(skip_serializing_if = "Option::is_none")]
		#[schemars(pattern("^[A-Za-z0-9-]{1,64}$"))]
		client_address_header: Option<String>,
		#[serde(skip_serializing_if = "Option::is_none")]
		limits: Option<TransportLimits>,
	},
	/// `fronted` whose requests and answers are in the shape this transport names (protocol, "Shapes of fronted"): which method carries the data, where in the request it goes, and whether the node answers each request or writes to one event stream. Its keys are those of `fronted`, and its proofs are valid on no other transport.
	#[serde(rename = "fronted-shaped")]
	FrontedShaped {
		listen: Addr,
		#[schemars(pattern("^/[A-Za-z0-9._~/-]{11,255}$"))]
		path: String,
		decoy: Decoy,
		#[schemars(length(min = 1, max = MAX_TRUSTED_PROXIES))]
		trusted_proxies: Vec<Proxy>,
		#[serde(skip_serializing_if = "Option::is_none")]
		#[schemars(pattern("^[A-Za-z0-9-]{1,64}$"))]
		client_address_header: Option<String>,
		#[serde(skip_serializing_if = "Option::is_none")]
		limits: Option<TransportLimits>,
		shape: Shape,
	},
}

/// The shape of a `fronted-shaped` transport, as the profile of its subscription carries it. The members are those of the shapes page, and the panel writes one object to the config and to the profile.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Shape {
	pub up: ShapeUp,
	pub down: ShapeDown,
}

/// The upstream half of a shape. Which methods go with which `in`, and the bounds of every number, are validation's.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShapeUp {
	/// `GET`, `POST`, `PUT`, `PATCH`, or a custom method of 3 to 16 capital letters. `CONNECT`, `TRACE`, `HEAD` and `OPTIONS` are refused.
	#[schemars(pattern("^[A-Z]{3,16}$"))]
	pub method: String,
	/// Where the data of a request goes. `GET` takes `query`, `path` or `header`; `POST`, `PUT` and `PATCH` take `body`; a custom method takes any.
	#[serde(rename = "in")]
	pub place: ShapePlace,
	/// The name of the one header field that carries the data. Required with `header` and refused otherwise.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern("^[A-Za-z0-9-]{1,32}$"))]
	pub name: Option<String>,
	/// The most one request carries, as bytes of body, of request target or of header value. 1024 to 8000 for `query` and `path` (default 4000), 1024 to 4096 for `header` (default 3000), 1024 to 65536 for `body` (default 65536).
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1024, max = 65536))]
	pub limit: Option<u32>,
	/// Requests that may be in flight at once, not counting the stream. 1 to 4. Defaults to 1 with `poll` and 2 with `sse`, and is 1 with `poll`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 4))]
	pub inflight: Option<u32>,
	/// Milliseconds the client waits to collect datagrams into one request, drawn from `[low, high]`, 0 to 250 each. Defaults to `[10, 60]`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 2, max = 2))]
	pub gather: Option<Vec<u32>>,
}

/// The downstream half of a shape.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShapeDown {
	/// `poll`: answers carry the downstream data. `sse`: one Server-Sent Events stream does.
	pub mode: ShapeMode,
	/// Milliseconds the node waits to collect datagrams into one event, `[low, high]`, 0 to 250 each. Only with `sse`. Defaults to `[0, 20]`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 2, max = 2))]
	pub gather: Option<Vec<u32>>,
	/// The range in seconds a stream's length is drawn from, `[low, high]`, 30 to 3600 each. Only with `sse`. Defaults to `[120, 900]`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 2, max = 2))]
	pub life: Option<Vec<u32>>,
	/// Whether the client may fall back to polling when streams do not work. Only with `sse`. Defaults to true.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fallback: Option<bool>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShapePlace {Body, Query, Path, Header}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShapeMode {Poll, Sse}

impl Shape {
	/// The shape with its defaults and every rule of the shapes page applied, or the dotted name of the member that breaks one. A range that is not two numbers breaks `up.gather`, `down.gather` or `down.life`.
	pub fn resolve(&self) -> Result<veilway_proto::shape::Shape, &'static str> {
		let pair = |range: &Option<Vec<u32>>| -> Result<Option<[u64; 2]>, ()> {range.as_ref().map(|range| if let [low, high] = range[..] {Ok([u64::from(low), u64::from(high)])} else {Err(())}).transpose()};
		let place = match self.up.place {
			ShapePlace::Body => "body",
			ShapePlace::Query => "query",
			ShapePlace::Path => "path",
			ShapePlace::Header => "header",
		};
		veilway_proto::shape::Shape::resolve(&veilway_proto::shape::Given {
			method: &self.up.method, place, name: self.up.name.as_deref(), limit: self.up.limit.map(u64::from), inflight: self.up.inflight.map(u64::from), gather: pair(&self.up.gather).map_err(|()| "up.gather")?,
			mode: if self.down.mode == ShapeMode::Sse {"sse"} else {"poll"}, down_gather: pair(&self.down.gather).map_err(|()| "down.gather")?, life: pair(&self.down.life).map_err(|()| "down.life")?, fallback: self.down.fallback,
		})
	}
}

/// What the three transports of the proxy path have besides their listen address: the native `ws`, `fronted` and `fronted-shaped`.
pub struct Proxied<'a> {pub fronted: bool, pub path: &'a str, pub decoy: &'a Decoy, pub trusted: &'a [Proxy], pub header: Option<&'a str>, pub limits: Option<TransportLimits>, pub shape: Option<&'a Shape>}

impl Transport {
	pub fn listen(&self) -> SocketAddr {
		match self {
			Transport::Udp {listen} | Transport::Ws {listen, ..} | Transport::UdpObfs {listen, ..} | Transport::Tls {listen, ..} | Transport::WsNative {listen, ..} | Transport::Fronted {listen, ..} | Transport::FrontedShaped {listen, ..} => listen.0,
		}
	}

	/// Whether the transport has a UDP socket of its own.
	pub fn datagram(&self) -> bool {matches!(self, Transport::Udp {..} | Transport::UdpObfs {..})}

	/// Version 1: no transport has passed the tests Protected needs, and none is weaker than Detectable, so every transport is Detectable.
	pub fn rating(&self) -> Rating {Rating::Detectable}

	/// The decoy origin of a transport that takes the stream proof.
	pub fn decoy(&self) -> Option<&Decoy> {
		match self {
			Transport::Tls {decoy, ..} | Transport::WsNative {decoy, ..} | Transport::Fronted {decoy, ..} | Transport::FrontedShaped {decoy, ..} => Some(decoy),
			_ => None,
		}
	}

	/// The transport as one of the proxy path, when it is one.
	pub fn proxied(&self) -> Option<Proxied<'_>> {
		match self {
			Transport::WsNative {path, decoy, trusted_proxies, client_address_header, limits, ..} | Transport::Fronted {path, decoy, trusted_proxies, client_address_header, limits, ..} | Transport::FrontedShaped {path, decoy, trusted_proxies, client_address_header, limits, ..} => Some(Proxied {fronted: matches!(self, Transport::Fronted {..} | Transport::FrontedShaped {..}), path, decoy, trusted: trusted_proxies, header: client_address_header.as_deref(), limits: *limits, shape: if let Transport::FrontedShaped {shape, ..} = self {Some(shape)} else {None}}),
			_ => None,
		}
	}
}

/// A key that belongs to another `type` of the same object is refused like an unknown key.
fn only<E: de::Error>(kind: &str, others: &[(&str, bool)]) -> Result<(), E> {
	match others.iter().find(|(_, present)| *present) {
		Some((key, _)) => Err(E::invalid_value(Unexpected::Other("key"), &format!("no key `{key}` when type is `{kind}`").as_str())),
		None => Ok(()),
	}
}

// The objects that pick their keys by `type` are read through a flat struct of every key, so a wrong value keeps its exact path. serde's own tagged enums buffer the object and lose it.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransportType {Udp, Ws, #[serde(rename = "udp-obfs")] UdpObfs, Tls, Fronted, #[serde(rename = "fronted-shaped")] FrontedShaped}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportKeys {#[serde(rename = "type")] kind: TransportType, listen: Addr, path: Option<String>, tls: Option<Certificate>, decoy: Option<Decoy>, trusted_proxies: Option<Vec<Proxy>>, client_address_header: Option<String>, limits: Option<TransportLimits>, shape: Option<Shape>}

impl<'de> Deserialize<'de> for Transport {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Transport, D::Error> {
		let keys = TransportKeys::deserialize(d)?;
		let proxy = [("trusted_proxies", keys.trusted_proxies.is_some()), ("client_address_header", keys.client_address_header.is_some())];
		let shaped = [("shape", keys.shape.is_some())];
		match keys.kind {
			TransportType::Udp => only("udp", &[&[("path", keys.path.is_some()), ("tls", keys.tls.is_some()), ("decoy", keys.decoy.is_some()), ("limits", keys.limits.is_some())][..], &proxy, &shaped].concat()).map(|_| Transport::Udp {listen: keys.listen}),
			// `ws` is two formats under one name. With none of the keys of the proxy path it is the one of a `wireguard` inbound, and with any of them the native one of a `veilway` inbound, which never ends TLS itself. `validate` holds each to its kind of inbound.
			TransportType::Ws if keys.decoy.is_none() && keys.limits.is_none() && keys.shape.is_none() && proxy.iter().all(|(_, present)| !present) => Ok(Transport::Ws {listen: keys.listen, path: keys.path.ok_or_else(|| de::Error::missing_field("path"))?, tls: match keys.tls {Some(Certificate::SelfSigned(_)) => return Err(de::Error::custom("no `self_signed` on a ws transport of a wireguard inbound: the node makes its own certificate for a native tls transport alone")), Some(Certificate::Files(tls)) => Some(tls), None => None}}),
			TransportType::Ws => only("ws` with a decoy, which reads plain HTTP from the web server in front of it and never ends TLS: that is `tls", &[("tls", keys.tls.is_some()), ("shape", keys.shape.is_some())]).and_then(|_| Ok(Transport::WsNative {listen: keys.listen, path: keys.path.ok_or_else(|| de::Error::missing_field("path"))?, decoy: keys.decoy.ok_or_else(|| de::Error::missing_field("decoy"))?, trusted_proxies: keys.trusted_proxies.ok_or_else(|| de::Error::missing_field("trusted_proxies"))?, client_address_header: keys.client_address_header, limits: keys.limits})),
			TransportType::UdpObfs => only("udp-obfs", &[&[("path", keys.path.is_some()), ("tls", keys.tls.is_some()), ("decoy", keys.decoy.is_some())][..], &proxy, &shaped].concat()).map(|_| Transport::UdpObfs {listen: keys.listen, limits: keys.limits}),
			TransportType::Tls => only("tls", &[&proxy[..], &shaped].concat()).and_then(|_| Ok(Transport::Tls {listen: keys.listen, path: keys.path.ok_or_else(|| de::Error::missing_field("path"))?, tls: keys.tls.ok_or_else(|| de::Error::missing_field("tls"))?, decoy: keys.decoy.ok_or_else(|| de::Error::missing_field("decoy"))?, limits: keys.limits})),
			TransportType::Fronted => only("fronted", &[("tls", keys.tls.is_some()), ("shape", keys.shape.is_some())]).and_then(|_| Ok(Transport::Fronted {listen: keys.listen, path: keys.path.ok_or_else(|| de::Error::missing_field("path"))?, decoy: keys.decoy.ok_or_else(|| de::Error::missing_field("decoy"))?, trusted_proxies: keys.trusted_proxies.ok_or_else(|| de::Error::missing_field("trusted_proxies"))?, client_address_header: keys.client_address_header, limits: keys.limits})),
			TransportType::FrontedShaped => only("fronted-shaped", &[("tls", keys.tls.is_some())]).and_then(|_| Ok(Transport::FrontedShaped {listen: keys.listen, path: keys.path.ok_or_else(|| de::Error::missing_field("path"))?, decoy: keys.decoy.ok_or_else(|| de::Error::missing_field("decoy"))?, trusted_proxies: keys.trusted_proxies.ok_or_else(|| de::Error::missing_field("trusted_proxies"))?, client_address_header: keys.client_address_header, limits: keys.limits, shape: keys.shape.ok_or_else(|| de::Error::missing_field("shape"))?})),
		}
	}
}

#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outbound {
	Direct {
		#[schemars(pattern(TAG_PATTERN))]
		tag: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		bind: Option<Ip>,
	},
	#[schemars(extend("dependentRequired" = {"username": ["password"], "password": ["username"]}))]
	Socks5 {
		#[schemars(pattern(TAG_PATTERN))]
		tag: String,
		server: HostPort,
		#[serde(skip_serializing_if = "Option::is_none")]
		#[schemars(length(min = 1, max = MAX_CREDENTIAL_BYTES))]
		username: Option<Secret<String>>,
		#[serde(skip_serializing_if = "Option::is_none")]
		#[schemars(length(min = 1, max = MAX_CREDENTIAL_BYTES))]
		password: Option<Secret<String>>,
	},
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutboundType {Direct, Socks5}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundKeys {#[serde(rename = "type")] kind: OutboundType, tag: String, bind: Option<Ip>, server: Option<HostPort>, username: Option<Secret<String>>, password: Option<Secret<String>>}

impl<'de> Deserialize<'de> for Outbound {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Outbound, D::Error> {
		let keys = OutboundKeys::deserialize(d)?;
		match keys.kind {
			OutboundType::Direct => only("direct", &[("server", keys.server.is_some()), ("username", keys.username.is_some()), ("password", keys.password.is_some())]).map(|_| Outbound::Direct {tag: keys.tag, bind: keys.bind}),
			OutboundType::Socks5 => {
				only("socks5", &[("bind", keys.bind.is_some())])?;
				Ok(Outbound::Socks5 {tag: keys.tag, server: keys.server.ok_or_else(|| de::Error::missing_field("server"))?, username: keys.username, password: keys.password})
			}
		}
	}
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exit {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	/// Display name. Defaults to the tag.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = 64))]
	pub name: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern("^[A-Z]{2}$"))]
	pub country: Option<String>,
	pub backend: Backend,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Unsupported {
	/// Defaults to "local".
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(with = "Option<IcmpEchoPolicy>")]
	pub icmp_echo: Option<Policy>,
	/// Defaults to "reject". "local" is not allowed.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(with = "Option<UdpPolicy>")]
	pub udp: Option<Policy>,
	/// Defaults to "reject". "local" and "direct" are not allowed.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(with = "Option<OtherPolicy>")]
	pub other: Option<Policy>,
}

#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Netstack {
	#[schemars(pattern(TAG_PATTERN))]
	pub outbound: String,
	/// Defaults to true on a socks5 outbound. Must be absent or false on a direct one.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub proxy_only: Option<bool>,
	/// Defaults to 7200.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 10, max = 86400))]
	pub tcp_idle_secs: Option<u32>,
	/// Defaults to 60.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 5, max = 3600))]
	pub udp_idle_secs: Option<u32>,
	#[serde(default, skip_serializing_if = "Unsupported::is_default")]
	pub unsupported: Unsupported,
}

impl Unsupported {
	fn is_default(&self) -> bool {*self == Unsupported::default()}
}

#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L3 {
	/// Defaults to "veilway0".
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern("^[a-z][a-z0-9_-]{0,14}$"))]
	pub interface: Option<String>,
	/// Defaults to true.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub masquerade: Option<bool>,
}

/// The entry half of node links: what is routed to the exit leaves from another node, through one of these links.
#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chain {
	/// The tags of 1 to 4 links that lead to the same exit node. Each is a link whose entry half this node is.
	#[schemars(length(min = 1, max = MAX_CHAIN_LINKS), inner(pattern(TAG_PATTERN)))]
	pub links: Vec<String>,
}

#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Backend {Netstack(Netstack), L3(L3), Block {}, Chain(Chain)}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackendType {Netstack, L3, Block, Chain}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendKeys {
	#[serde(rename = "type")]
	kind: BackendType,
	outbound: Option<String>,
	proxy_only: Option<bool>,
	tcp_idle_secs: Option<u32>,
	udp_idle_secs: Option<u32>,
	unsupported: Option<Unsupported>,
	interface: Option<String>,
	masquerade: Option<bool>,
	links: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for Backend {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Backend, D::Error> {
		let keys = BackendKeys::deserialize(d)?;
		let netstack = [("outbound", keys.outbound.is_some()), ("proxy_only", keys.proxy_only.is_some()), ("tcp_idle_secs", keys.tcp_idle_secs.is_some()), ("udp_idle_secs", keys.udp_idle_secs.is_some()), ("unsupported", keys.unsupported.is_some())];
		let l3 = [("interface", keys.interface.is_some()), ("masquerade", keys.masquerade.is_some())];
		// "A `chain` exit carries whole packets of every IP protocol, so the per-exit `unsupported` policies of the config reference do not exist for it."
		if let BackendType::Chain = keys.kind {return only("chain", &netstack).and_then(|_| only("chain", &l3)).and_then(|_| Ok(Backend::Chain(Chain {links: keys.links.ok_or_else(|| de::Error::missing_field("links"))?})))}
		only(match keys.kind {
			BackendType::Netstack => "netstack",
			BackendType::L3 => "l3",
			_ => "block",
		}, &[("links", keys.links.is_some())])?;
		match keys.kind {
			BackendType::Netstack => {
				only("netstack", &l3)?;
				Ok(Backend::Netstack(Netstack {
					outbound: keys.outbound.ok_or_else(|| de::Error::missing_field("outbound"))?,
					proxy_only: keys.proxy_only,
					tcp_idle_secs: keys.tcp_idle_secs,
					udp_idle_secs: keys.udp_idle_secs,
					unsupported: keys.unsupported.unwrap_or_default(),
				}))
			}
			BackendType::L3 => only("l3", &netstack).map(|_| Backend::L3(L3 {interface: keys.interface, masquerade: keys.masquerade})),
			_ => only("block", &netstack).and_then(|_| only("block", &l3)).map(|_| Backend::Block {}),
		}
	}
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Routing {
	#[schemars(pattern(TAG_PATTERN))]
	pub default: String,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_RULES))]
	pub rules: Vec<Rule>,
}

/// Every condition that is present must hold. A condition that is present is never an empty list.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schemars(extend(
	"anyOf" = [{"required": ["inbound"]}, {"required": ["user"]}, {"required": ["group"]}, {"required": ["link"]}, {"required": ["ip"]}, {"required": ["domain"]}, {"required": ["protocol"]}, {"required": ["port"]}, {"required": ["icmp_type"]}, {"required": ["icmp_code"]}],
	"dependentRequired" = {"port": ["protocol"], "icmp_type": ["protocol"], "icmp_code": ["icmp_type"]},
))]
pub struct Rule {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	/// Defaults to true. Not a condition: a disabled rule is validated like any other and skipped when flows are matched.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub enabled: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES), inner(pattern(TAG_PATTERN)))]
	pub inbound: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES), inner(pattern(NAME_PATTERN)))]
	pub user: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES), inner(pattern(NAME_PATTERN)))]
	pub group: Option<Vec<String>>,
	/// The tags of node links whose exit half this node is: the rule matches what arrives from one of them. A link has no user and no group.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_LINKS), inner(pattern(TAG_PATTERN)))]
	pub link: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES))]
	pub ip: Option<Vec<IpEntry>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES), inner(length(min = 1, max = MAX_DOMAIN_BYTES)))]
	pub domain: Option<Vec<String>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES))]
	pub protocol: Option<Vec<Protocol>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES))]
	pub port: Option<Vec<PortRange>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES))]
	pub icmp_type: Option<Vec<u8>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_RULE_ENTRIES))]
	pub icmp_code: Option<Vec<u8>>,
	pub action: Action,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPeriod {Daily, Weekly, Monthly}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schemars(extend("dependentRequired" = {"quota_period": ["quota_bytes"]}))]
pub struct User {
	#[schemars(pattern(NAME_PATTERN))]
	pub name: String,
	/// Defaults to true.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub enabled: Option<bool>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[schemars(length(max = MAX_GROUPS), inner(pattern(NAME_PATTERN)))]
	pub groups: Vec<String>,
	#[schemars(length(min = 1, max = MAX_DEVICES))]
	pub devices: Vec<Device>,
	pub exits: Exits,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern(TAG_PATTERN))]
	pub exit: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 9007199254740991_u64))]
	pub quota_bytes: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub quota_period: Option<QuotaPeriod>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<Timestamp>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Device {
	#[schemars(pattern(NAME_PATTERN))]
	pub name: String,
	pub public_key: Key,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub preshared_key: Option<Secret<Key>>,
	/// One, or two while the secret is rotated. Needed by a device with an address in a `veilway` inbound.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_TRANSPORT_SECRETS))]
	pub transport_secrets: Option<Vec<TransportSecret>>,
	#[schemars(length(min = 1, max = MAX_DEVICE_ADDRESSES))]
	pub addresses: Vec<Ip>,
}

/// The id of a node link as its pairing made it: 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkId(pub [u8; 16]);

text_value!(LinkId, "the id of a link: 22 characters of base64url without padding", "^[A-Za-z0-9_-]{21}[AQgw]$", |s| {
	let mut bytes = [0u8; 18];
	if s.len() == 22 && URL_SAFE_NO_PAD.decode_slice(s, &mut bytes) == Ok(16) {Ok(LinkId(std::array::from_fn(|at| bytes[at])))} else {Err("the id of a link: 22 characters of base64url without padding")}
}, |id| URL_SAFE_NO_PAD.encode(id.0));

/// The SHA-256 of a certificate's SubjectPublicKeyInfo, written like a key. It is no key and no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pin(pub [u8; 32]);

text_value!(Pin, "a certificate pin: 44 characters of standard base64 with padding", "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", |s| {
	match STANDARD.decode(s).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
		Some(pin) if s.len() == KEY_CHARS => Ok(Pin(pin)),
		_ => Err("a certificate pin: 44 characters of standard base64 with padding"),
	}
}, |pin| STANDARD.encode(pin.0));

/// Who dials. In a forward link the entry dials the exit, in a reverse link the exit dials the entry.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkDirection {Forward, Reverse}

/// The addresses pairing fixed for a link, all from the inbound pool of the node the link connects to.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkAddresses {
	/// The address of the node that dials: at most one IPv4 and one IPv6.
	#[schemars(length(min = 1, max = 2))]
	pub dialler: Vec<Ip>,
	/// The link address of the node that is dialled, in a reverse link and in no other: one for each family of `dialler`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = 2))]
	pub listener: Option<Vec<Ip>>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkTransportType {
	#[serde(rename = "udp")] Udp,
	#[serde(rename = "udp-obfs")] UdpObfs,
	#[serde(rename = "tls")] Tls,
	#[serde(rename = "ws")] Ws,
	/// Read so that validation can say why a link has none.
	#[serde(rename = "fronted")] Fronted,
}

/// One way to reach the other node of a link through its web server or directly, as a profile of a subscription writes a candidate.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkCandidate {
	pub address: Addr,
	/// The server name that is shown, or empty for none.
	#[schemars(length(max = 253))]
	pub sni: String,
	/// The `Host` of the request.
	#[schemars(length(min = 1, max = 253))]
	pub host: String,
	/// The name the certificate is held against when `sni` is empty, and only then.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = 253))]
	pub verify_name: Option<String>,
	/// Needed by a `tls` candidate. The certificate chain is always validated, and a pin is a second condition.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_LINK_PINS))]
	pub pins: Option<Vec<Pin>>,
}

/// One transport of the node a link dials, in the shape a profile of a subscription has: `endpoints` for `udp` and `udp-obfs`, `path` and `candidates` for `tls` and `ws`.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkTransport {
	#[serde(rename = "type")]
	pub kind: LinkTransportType,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_LINK_CANDIDATES))]
	pub endpoints: Option<Vec<Addr>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern("^/[A-Za-z0-9._~/-]{11,255}$"))]
	pub path: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_LINK_CANDIDATES))]
	pub candidates: Option<Vec<LinkCandidate>>,
}

/// What the node that dials a link holds of the node it dials, "as the offer gave them".
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinkPeer {
	/// The WireGuard public key of the inbound the link connects to.
	pub inbound_public_key: Key,
	/// The node transport public key of that inbound. Needed when a `tls` or `ws` transport is listed.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transport_public_key: Option<Key>,
	/// In the other node's order of preference.
	#[schemars(length(min = 1, max = MAX_TRANSPORTS))]
	pub transports: Vec<LinkTransport>,
}

/// One node link, as its pairing left it on this node. A link with `inbound` and `public_key` is one this node is dialled for, and a link with `peer` and `private_key` one it dials.
/// With `direction`, that says which half the node is: the exit half when it is dialled in a forward link or dials a reverse one, and the entry half otherwise. The entry half is used through an exit with a `chain` backend.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schemars(extend("dependentRequired" = {"inbound": ["public_key"], "public_key": ["inbound"], "peer": ["private_key"], "private_key": ["peer"], "quota_period": ["quota_bytes"]}))]
pub struct Link {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	pub id: LinkId,
	pub direction: LinkDirection,
	/// Defaults to true. A link that is not enabled is validated like any other and neither dialled nor answered.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub enabled: Option<bool>,
	pub addresses: LinkAddresses,
	/// Defaults to 1390 when the link lists `udp-obfs`, and to 1420 otherwise.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1280, max = 1500))]
	pub mtu: Option<u16>,
	/// The secret the two nodes agreed on when they were paired. It never travels.
	pub transport_secret: TransportSecret,
	/// On the node that is dialled: the tag of the `veilway` inbound the link connects to. That inbound carries no users' devices.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern(TAG_PATTERN))]
	pub inbound: Option<String>,
	/// On the node that is dialled: the WireGuard public key the other node made for this link.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub public_key: Option<Key>,
	/// On the node that dials: the WireGuard private key it made for this link.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub private_key: Option<Secret<Key>>,
	/// On the node that dials: the other node's keys and transports.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub peer: Option<LinkPeer>,
	/// On the exit half: the exit the link leaves through when no rule names one. Without it that is `routing.default`.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(pattern(TAG_PATTERN))]
	pub exit: Option<String>,
	/// On the exit half, where it is needed: the exits the link may leave through. None of them is a `chain` exit.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(max = MAX_EXITS), inner(pattern(TAG_PATTERN)))]
	pub exits: Option<Vec<String>>,
	/// On the exit half: whether private networks are decided by the rules for this link. Defaults to false, which refuses them whatever the rules say.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub allow_private: Option<bool>,
	/// On the exit half: the flows the link may have at once. Defaults to 16384.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 65536))]
	pub max_flows: Option<u32>,
	/// On the exit half. The quota and its period mean what they mean for a user.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = 9007199254740991_u64))]
	pub quota_bytes: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub quota_period: Option<QuotaPeriod>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub expires_at: Option<Timestamp>,
}

impl Link {
	/// Whether this node is the one the link connects to. A link that validates is that or is one this node dials.
	pub fn listener(&self) -> bool {self.inbound.is_some()}

	/// Whether this node is the entry half: it has the users, and sends their packets into the link.
	pub fn entry(&self) -> bool {self.listener() != (self.direction == LinkDirection::Forward)}

	/// The entry's link address: "the dialler's address in a forward link and the listener's link address in a reverse link".
	pub fn entry_addresses(&self) -> &[Ip] {if self.direction == LinkDirection::Forward {&self.addresses.dialler} else {self.addresses.listener.as_deref().unwrap_or(&[])}}

	/// The WireGuard public key the dialling node has for the link, which is what names a link on both nodes.
	pub fn identity(&self) -> Option<[u8; 32]> {self.public_key.map(|key| key.0).or_else(|| self.private_key.as_ref().map(|key| veilway_wg::public_key(&key.expose().0)))}

	/// The `mtu` in force. `inbounds` are those of the config the link is in: a link that is dialled lists the transports of its inbound.
	pub fn mtu(&self, inbounds: &[Inbound]) -> u16 {
		let obfs = self.peer.as_ref().is_some_and(|peer| peer.transports.iter().any(|transport| transport.kind == LinkTransportType::UdpObfs)) || self.inbound.as_ref().is_some_and(|tag| inbounds.iter().any(|inbound| inbound.tag == *tag && inbound.enveloped()));
		self.mtu.unwrap_or(if obfs {DEFAULT_MTU_OBFS} else {DEFAULT_MTU})
	}
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {Tcp, Udp}

/// A tunnel (node links page, "Tunnels"): one TCP or UDP port of this node forwarded to one address on the far side of a node link, through a `chain` exit, with no client.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	/// Defaults to true. A tunnel that is not enabled is validated and does not listen.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub enabled: Option<bool>,
	pub protocol: TunnelProtocol,
	/// The address this node listens on. No other tunnel, inbound transport or listener of this node uses the same address, port and protocol.
	pub listen: Addr,
	/// The tag of a `chain` exit.
	#[schemars(pattern(TAG_PATTERN))]
	pub exit: String,
	/// The address the far node is asked to reach. Not a link address, not inside an inbound pool of this node, and nothing the destination gate refuses. A private address works only when the far node set `allow_private` for the link.
	pub target: Addr,
	/// The networks that may connect. Without it, a tunnel that listens on an address that is not loopback is a warning.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(length(min = 1, max = MAX_TUNNEL_SOURCES))]
	pub sources: Option<Vec<Source>>,
	/// TCP connections or UDP sessions at once. Defaults to 256. One client address holds at most 16.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1, max = MAX_TUNNEL_CONNECTIONS))]
	pub max_connections: Option<u32>,
}

impl Tunnel {
	/// Whether this tunnel listens: `enabled` is left out or true.
	pub fn on(&self) -> bool {self.enabled != Some(false)}

	/// `max_connections` in force.
	pub fn limit(&self) -> u32 {self.max_connections.unwrap_or(DEFAULT_TUNNEL_CONNECTIONS)}

	/// What a reload cannot change in a running tunnel without closing its connections: everything but `sources` and `max_connections`.
	pub fn core(&self) -> Tunnel {Tunnel {enabled: Some(true), sources: None, max_connections: None, ..self.clone()}}

	/// The tunnel with its defaults written out, so that two spellings of one tunnel are equal.
	pub fn effective(&self) -> Tunnel {Tunnel {enabled: Some(self.on()), max_connections: Some(self.limit()), ..self.clone()}}
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XrayProtocol {
	/// Needs `tls` and a `decoy`. The client secret is a UUID.
	Vless,
	/// Needs `tls` and a `decoy`. The client secret is a password.
	Trojan,
	/// The cipher is 2022-blake3-aes-256-gcm with a key for the server and one per client. Every key is 32 bytes as standard base64.
	Shadowsocks,
}

/// The Xray add-on's part of the config. Xray runs as a child of the node and only ever reaches the network through the node: its traffic is attributed to the user of the client, and the node's gate, rules, exits and quotas apply to it.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Xray {
	#[schemars(length(max = MAX_XRAY_INBOUNDS))]
	pub inbounds: Vec<XrayInbound>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XrayInbound {
	#[schemars(pattern(TAG_PATTERN))]
	pub tag: String,
	pub protocol: XrayProtocol,
	/// The public listener of Xray.
	pub listen: Addr,
	/// The certificate files of the listener. Required for `vless` and `trojan`, and not allowed for `shadowsocks`, which encrypts itself.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tls: Option<Tls>,
	/// Where a connection that is not a user's goes after the TLS handshake: the operator's own web server, the same one the `decoy.origin` of a `tls` transport names. Required for `vless` and `trojan`, not allowed for `shadowsocks`.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub decoy: Option<Origin>,
	/// The server's key for `shadowsocks`: 32 bytes as standard base64. Required for `shadowsocks`, not allowed for the others.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub server_key: Option<Secret<String>>,
	/// The users that may use this inbound, each with the credential they present to it.
	#[schemars(length(max = MAX_USERS))]
	pub clients: Vec<XrayClient>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XrayClient {
	#[schemars(pattern(NAME_PATTERN))]
	pub user: String,
	/// A UUID for `vless`. For `trojan` a password of 22 to 128 characters from A-Z a-z 0-9 and _ - . + / =. For `shadowsocks` a key of 32 bytes as standard base64. No two clients of an inbound share a secret.
	#[schemars(length(min = 22, max = 128))]
	pub secret: Secret<String>,
}
