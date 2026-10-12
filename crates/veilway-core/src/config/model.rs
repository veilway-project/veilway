//! The typed document. Deserializing checks that each value is well formed on its own; `Config::validate` checks everything that relates one value to another.
use super::{KEY_CHARS, MAX_CREDENTIAL_BYTES, MAX_DEVICES, MAX_DEVICE_ADDRESSES, MAX_DOMAIN_BYTES, MAX_EXITS, MAX_GROUPS, MAX_INBOUNDS, MAX_LABEL_BYTES, MAX_NAME_BYTES, MAX_OUTBOUNDS, MAX_RULES, MAX_RULE_ENTRIES, MAX_USERS, NAME_PATTERN, TAG_PATTERN};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ipnet::IpNet;
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::de::value::SeqAccessDeserializer;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
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

/// A secret. No diagnostic, log line or `Debug` output shows it.
// `Serialize` writes the real value, because that is how the document is saved: an API response must redact it first.
#[derive(Deserialize, Serialize, JsonSchema, Clone, PartialEq, Eq)]
#[serde(transparent)]
#[schemars(inline)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
	pub fn expose(&self) -> &T {&self.0}
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

/// An inbound's gateway address with the prefix of its pool. The host part is the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GatewayNet(pub IpNet);

text_value!(GatewayNet, "a gateway address with its prefix such as 10.7.0.1/24", "^[0-9A-Fa-f:.]+/[1-9][0-9]{0,2}$", |s| net(s, true).map(GatewayNet), |net| net.0.to_string());

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {Ip(IpAddr), Name(String)}

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
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InboundType {Wireguard}

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
	/// Defaults to 1420.
	#[serde(skip_serializing_if = "Option::is_none")]
	#[schemars(range(min = 1280, max = 1500))]
	pub mtu: Option<u16>,
	#[schemars(length(min = 1, max = 8))]
	pub transports: Vec<Transport>,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tls {
	#[schemars(length(min = 1))]
	pub cert: String,
	#[schemars(length(min = 1))]
	pub key: String,
}

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
}

impl Transport {
	pub fn listen(&self) -> SocketAddr {
		match self {
			Transport::Udp {listen} | Transport::Ws {listen, ..} => listen.0,
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
enum TransportType {Udp, Ws}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportKeys {#[serde(rename = "type")] kind: TransportType, listen: Addr, path: Option<String>, tls: Option<Tls>}

impl<'de> Deserialize<'de> for Transport {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Transport, D::Error> {
		let keys = TransportKeys::deserialize(d)?;
		match keys.kind {
			TransportType::Udp => only("udp", &[("path", keys.path.is_some()), ("tls", keys.tls.is_some())]).map(|_| Transport::Udp {listen: keys.listen}),
			TransportType::Ws => Ok(Transport::Ws {listen: keys.listen, path: keys.path.ok_or_else(|| de::Error::missing_field("path"))?, tls: keys.tls}),
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

#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Backend {Netstack(Netstack), L3(L3), Block {}}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackendType {Netstack, L3, Block}

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
}

impl<'de> Deserialize<'de> for Backend {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Backend, D::Error> {
		let keys = BackendKeys::deserialize(d)?;
		let netstack = [("outbound", keys.outbound.is_some()), ("proxy_only", keys.proxy_only.is_some()), ("tcp_idle_secs", keys.tcp_idle_secs.is_some()), ("udp_idle_secs", keys.udp_idle_secs.is_some()), ("unsupported", keys.unsupported.is_some())];
		let l3 = [("interface", keys.interface.is_some()), ("masquerade", keys.masquerade.is_some())];
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
			BackendType::Block => only("block", &netstack).and_then(|_| only("block", &l3)).map(|_| Backend::Block {}),
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
	"anyOf" = [{"required": ["inbound"]}, {"required": ["user"]}, {"required": ["group"]}, {"required": ["ip"]}, {"required": ["domain"]}, {"required": ["protocol"]}, {"required": ["port"]}, {"required": ["icmp_type"]}, {"required": ["icmp_code"]}],
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
	#[schemars(length(min = 1, max = MAX_DEVICE_ADDRESSES))]
	pub addresses: Vec<Ip>,
}
