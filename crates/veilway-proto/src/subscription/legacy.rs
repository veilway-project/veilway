//! The unsigned formats of other apps (subscription format page, "Native and legacy"), only as far as the page goes: what is accepted from the answer to a legacy link, within which limits, and the most each entry can be rated.
//!
//! Nothing here is verified and nothing can be: "it can be changed on the way at every fetch". So everything read here is an `Entry` or a `Headers`, which are other types than a profile of a signed document, and no function turns one into the other. The protocols the links name are not here. An entry holds the fields this reader knows, each checked as a host name, an address, a port or a short word, and "a field that is not on the parser's list of known fields is dropped". Nothing of a link is kept as raw text.
use super::{is_host, json::{self, Json, Members}, payload::{dialable, INTEGER_MAX}, sealed, Text, Url, BODY_MAX, STRING_MAX, URL_MAX};
use base64::{alphabet::URL_SAFE, engine::{general_purpose::{GeneralPurpose, NO_PAD}, Engine}};
use std::{fmt, net::IpAddr};

/// "Legacy list: at most 256 links, each at most 4,096 bytes."
pub const LINKS_MAX: usize = 256;
pub const LINK_MAX: usize = 4_096;
// What other apps write is read with or without padding, in either alphabet, and with bits set that no byte takes.
const LENIENT: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, NO_PAD.with_decode_allow_trailing_bits(true));
// The ciphers under which an entry that has its own encryption is not capped at Unsafe. "The cipher is one the core lists as weak": the core's list decides, and it can only lower what `Entry::cap` gives. A cipher this reader does not know counts as weak.
const STRONG: [&str; 11] = ["auto", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];

/// Why the body of an answer gave no list at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyError {
	/// Longer than `BODY_MAX`.
	Size,
	/// The answer is a signed document: "this provider offers a native subscription, ask it for the full link". Nothing is imported from it.
	Native,
	/// Neither a list of links nor base64 of one.
	Unreadable,
}

impl fmt::Display for LegacyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "legacy subscription: {self:?}")}
}

impl std::error::Error for LegacyError {}

/// The scheme of a link that is read. "Every other line is skipped and counted."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {Vless, Vmess, Trojan, Shadowsocks}

/// The most a legacy profile can be rated: "Otherwise it is Detectable. A legacy profile is never rated higher." There is no higher value to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {Detectable, Unsafe}

/// Whether a link asks for TLS around its protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {None, Tls, Reality}

/// Where an entry connects. Unlike a native profile, a legacy one may name a host that has to be looked up: the caller asks `payload::dialable` about every address the name resolves to, and `payload::own` about the device's own networks, before it dials. An address in a link has passed `dialable` already.
#[derive(Clone, PartialEq, Eq)]
pub enum Server {Name(String), Address(IpAddr)}

// Where a list sends its users is not for a log.
impl fmt::Debug for Server {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str(if matches!(self, Self::Name(_)) {"Name(..)"} else {"Address(..)"})}
}

/// The password or user id of a link. It prints nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
	pub fn expose(&self) -> &str {&self.0}
}

impl fmt::Debug for Credential {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Credential(..)")}
}

/// One link of a legacy list, read into its known fields: an unsigned profile. The app marks it "unsigned" and "TCP and UDP only", and connecting to it "needs the optional compatibility add-on".
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
	pub scheme: Scheme,
	/// At most 64 characters, and empty when the link has no name.
	pub name: Text,
	pub server: Server,
	pub port: u16,
	pub credential: Credential,
	/// The cipher of a link that has its own encryption: a lowercase word.
	pub cipher: Option<String>,
	pub tls: Tls,
	/// The link switches certificate checking off.
	pub insecure: bool,
	pub sni: Option<String>,
	/// The kind of stream the link names, as a lowercase word: `tcp`, `ws`, `grpc` and so on.
	pub network: Option<String>,
	pub host: Option<String>,
	/// Starts with `/`, at most 256 bytes of visible ASCII.
	pub path: Option<String>,
}

impl fmt::Debug for Entry {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Entry({:?}, {:?}, ..)", self.scheme, self.tls)}
}

impl Entry {
	/// "It is Unsafe when there is no encryption, when certificate checking is switched off, or when the cipher is one the core lists as weak. Otherwise it is Detectable."
	pub fn cap(&self) -> Cap {
		let (own, strong) = (matches!(self.scheme, Scheme::Vmess | Scheme::Shadowsocks), self.cipher.as_deref().is_some_and(|cipher| STRONG.contains(&cipher)));
		if self.insecure || (own && !strong) || (!own && self.tls == Tls::None) {Cap::Unsafe} else {Cap::Detectable}
	}
}

/// What was read from the body of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
	pub entries: Vec<Entry>,
	/// Lines that are no link of a scheme that is read, or that did not parse, or that are longer than `LINK_MAX`.
	pub skipped: usize,
	/// "A list over the count limit is cut at the limit and the app says so."
	pub cut: bool,
}

/// `subscription-userinfo`: bytes, and Unix seconds for `expire`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInfo {pub upload: u64, pub download: u64, pub total: u64, pub expire: Option<u64>}

/// The response headers that are read. "A header that does not parse is ignored", and so is one that is sent twice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Headers {
	pub usage: Option<UserInfo>,
	/// `profile-title`: "display text, at most 64 characters".
	pub title: Option<Text>,
	/// `profile-update-interval`, in seconds: a whole number of hours "within the bounds of `update_interval`".
	pub update_interval: Option<u32>,
	/// `support-url`, under the rules of every URL a provider gives.
	pub support_url: Option<Url>,
}

// Percent-decoding of one field. A field that does not decode to UTF-8 is no field.
fn decoded(text: &str) -> Option<String> {
	let (bytes, mut out, mut index) = (text.as_bytes(), Vec::with_capacity(text.len()), 0);
	while let Some(byte) = bytes.get(index) {
		// Two hexadecimal digits and nothing else: the number reader alone would take a sign.
		let escaped = (*byte == b'%').then(|| text.get(index + 1..index + 3).filter(|digits| digits.bytes().all(|digit| digit.is_ascii_hexdigit())).and_then(|digits| u8::from_str_radix(digits, 16).ok()));
		out.push(match escaped {
			None => *byte,
			Some(value) => value?,
		});
		index += if escaped.is_some() {3} else {1};
	}
	String::from_utf8(out).ok()
}

// A short lowercase word: the name of a cipher, a kind of stream, a security setting.
fn word(text: &str) -> Option<String> {Some(text.to_ascii_lowercase()).filter(|word| (1..=32).contains(&word.len()) && word.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))}

fn name(text: &str) -> Option<String> {Some(text.to_ascii_lowercase()).filter(|name| is_host(name))}

// Only the characters RFC 3986 allows in a path and a query, since links in the wild carry a query in this field: no double quote, no backslash, no bracket or brace and no space, so that the path is no way into whatever a config is written in.
fn path(text: &str) -> Option<String> {Some(text).filter(|path| path.starts_with('/') && path.len() <= 256 && path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&()*+,;=:@/?%".contains(&byte))).map(str::to_owned)}

fn credential(text: &str) -> Option<Credential> {Some(text).filter(|text| (1..=256).contains(&text.len()) && !text.chars().any(char::is_control)).map(|text| Credential(text.to_owned()))}

fn port(text: &str) -> Option<u16> {text.parse().ok().filter(|port| *port != 0 && text.len() <= 5 && text.bytes().all(|byte| byte.is_ascii_digit()))}

// `host:port` or `[address]:port`.
fn server(text: &str) -> Option<(Server, u16)> {
	let (host, number) = text.rsplit_once(':')?;
	// An IPv6 address is in brackets, and nothing else is.
	let host = match host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
		Some(address) if address.contains(':') => address,
		None if !host.contains(':') => host,
		_ => return None,
	};
	Some((reached(host)?, port(number)?))
}

// Where an entry connects: an address a signed profile could name as well, or a host name. A list is unsigned, and whoever is on the way can rewrite it at every fetch, so it is held to no less than a profile: `payload::dialable` decides about an address. A name is not looked up here. It is refused when it can only mean the device itself.
fn reached(host: &str) -> Option<Server> {
	match host.parse::<IpAddr>() {
		Ok(address) => dialable(address).then_some(Server::Address(address)),
		Err(_) => name(host).filter(|name| name != "localhost" && !name.ends_with(".localhost")).map(Server::Name),
	}
}

fn shown(text: &str) -> Text {Text::shown(text, 64, 256)}

// `credential@host:port?fields#name`, the shape of a `vless` and a `trojan` link.
fn plain(scheme: Scheme, rest: &str) -> Option<Entry> {
	let (rest, label) = rest.split_once('#').unwrap_or((rest, ""));
	let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
	let (user, at) = rest.rsplit_once('@')?;
	let field = |key: &str| query.split('&').filter_map(|pair| pair.split_once('=')).find(|(name, _)| *name == key).and_then(|(_, value)| decoded(value));
	let tls = match field("security").as_deref() {
		None if scheme == Scheme::Trojan => Tls::Tls,
		None | Some("none" | "") => Tls::None,
		Some("tls") => Tls::Tls,
		Some("reality") => Tls::Reality,
		Some(_) => return None,
	};
	let (server, port) = server(at.trim_end_matches('/'))?;
	Some(Entry {scheme, name: shown(&decoded(label)?), server, port, credential: credential(&decoded(user)?)?, cipher: None, tls, insecure: ["allowInsecure", "insecure"].iter().any(|key| matches!(field(key).as_deref(), Some("1" | "true"))), sni: field("sni").and_then(|sni| name(&sni)), network: field("type").and_then(|kind| word(&kind)), host: field("host").and_then(|host| name(&host)), path: field("path").and_then(|text| path(&text))})
}

// `base64(cipher:password)@host:port#name`, the same with the first part written out, or `base64(cipher:password@host:port)#name`.
fn shadowsocks(rest: &str) -> Option<Entry> {
	let (rest, label) = rest.split_once('#').unwrap_or((rest, ""));
	let rest = rest.split_once('?').map_or(rest, |(rest, _)| rest).trim_end_matches('/');
	let unpacked = |text: &str| LENIENT.decode(text.trim_end_matches('=').replace('+', "-").replace('/', "_")).ok().and_then(|bytes| String::from_utf8(bytes).ok());
	let (user, at) = match rest.rsplit_once('@') {
		Some((user, at)) => (unpacked(user).filter(|user| user.contains(':')).or_else(|| decoded(user))?, at.to_owned()),
		None => unpacked(rest)?.rsplit_once('@').map(|(user, at)| (user.to_owned(), at.to_owned()))?,
	};
	let ((cipher, password), (server, port)) = (user.split_once(':')?, server(&at)?);
	Some(Entry {scheme: Scheme::Shadowsocks, name: shown(&decoded(label)?), server, port, credential: credential(password)?, cipher: Some(word(cipher)?), tls: Tls::None, insecure: false, sni: None, network: None, host: None, path: None})
}

// `base64(JSON)`, with every value a string, or a number where one is common.
fn vmess(rest: &str) -> Option<Entry> {
	let root = json::parse(&LENIENT.decode(rest.trim_end_matches('=').replace('+', "-").replace('/', "_")).ok()?).ok()?;
	let members = Members::of(&root)?;
	let field = |key: &str| match members.0.get(key) {
		Some(Json::Str(text)) if text.len() <= STRING_MAX => Some(text.clone()),
		Some(Json::Uint(number)) => Some(number.to_string()),
		Some(Json::Bool(true)) => Some("true".to_owned()),
		_ => None,
	};
	let tls = match field("tls").as_deref() {
		None | Some("none" | "") => Tls::None,
		Some("tls") => Tls::Tls,
		Some("reality") => Tls::Reality,
		Some(_) => return None,
	};
	let (address, number) = (field("add")?, port(&field("port")?)?);
	let server = reached(&address)?;
	Some(Entry {scheme: Scheme::Vmess, name: shown(&field("ps").unwrap_or_default()), server, port: number, credential: credential(&field("id")?)?, cipher: Some(field("scy").filter(|cipher| !cipher.is_empty()).map_or(Some("auto".to_owned()), |cipher| word(&cipher))?), tls, insecure: matches!(field("allowInsecure").as_deref(), Some("1" | "true")), sni: field("sni").and_then(|sni| name(&sni)), network: field("net").and_then(|kind| word(&kind)), host: field("host").and_then(|host| name(&host)), path: field("path").and_then(|text| path(&text))})
}

/// Reads the body of the answer to a legacy `GET`: "a list of links, one per line, plain or in base64".
/// A body that has the shape of a signed document is refused as `Native` and nothing of it is read: "a legacy link is fetched with a `GET`, never with a device key. If it is answered with a signed document", the user needs the full link.
pub fn list(body: &[u8]) -> Result<List, LegacyError> {
	if body.len() > BODY_MAX {return Err(LegacyError::Size)}
	let text = std::str::from_utf8(body).map_err(|_| LegacyError::Unreadable)?.trim();
	// The start of the header of any key: what comes before the key id, as far as it fills whole characters of base64url.
	if text.starts_with(&sealed(&b"{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\""[..45])) && text.bytes().filter(|byte| *byte == b'.').count() == 2 {return Err(LegacyError::Native)}
	let unpacked;
	let lines = if text.contains("://") {text} else {
		unpacked = LENIENT.decode(text.bytes().filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=').map(|byte| if byte == b'+' {b'-'} else if byte == b'/' {b'_'} else {byte}).collect::<Vec<_>>()).ok().and_then(|bytes| String::from_utf8(bytes).ok()).filter(|text| text.contains("://")).ok_or(LegacyError::Unreadable)?;
		&unpacked[..]
	};
	let mut list = List {entries: Vec::new(), skipped: 0, cut: false};
	for line in lines.lines().map(str::trim).filter(|line| !line.is_empty()) {
		if list.entries.len() + list.skipped == LINKS_MAX {
			list.cut = true;
			break;
		}
		let entry = Some(line).filter(|line| line.len() <= LINK_MAX).and_then(|line| line.split_once("://")).and_then(|(scheme, rest)| match scheme {
			"vless" => plain(Scheme::Vless, rest),
			"trojan" => plain(Scheme::Trojan, rest),
			"ss" => shadowsocks(rest),
			"vmess" => vmess(rest),
			_ => None,
		});
		match entry {
			Some(entry) => list.entries.push(entry),
			None => list.skipped += 1,
		}
	}
	Ok(list)
}

/// Reads the response headers of the answer to a legacy `GET`, given as names and values. Names are compared without regard to case. A value over `STRING_MAX` bytes, one that is not UTF-8 and a header that is there twice are ignored like one that does not parse.
pub fn headers(fields: &[(&str, &[u8])]) -> Headers {
	let field = |name: &str| {
		let mut found = fields.iter().filter(|(field, _)| field.eq_ignore_ascii_case(name));
		found.next().filter(|_| found.next().is_none()).filter(|(_, value)| value.len() <= STRING_MAX).and_then(|(_, value)| std::str::from_utf8(value).ok()).map(str::trim)
	};
	let usage = field("subscription-userinfo").and_then(|value| {
		let mut read = [None; 4];
		for (key, number) in value.split(';').filter_map(|pair| pair.trim().split_once('=')) {
			let (Some(slot), number) = (["upload", "download", "total", "expire"].iter().position(|known| *known == key.trim()), number.trim()) else {continue};
			// A known field that is there twice, or is no integer in range, spoils the header.
			if read[slot].is_some() || number.is_empty() || number.len() > 16 || !number.bytes().all(|byte| byte.is_ascii_digit()) {return None}
			read[slot] = Some(number.parse::<u64>().ok().filter(|number| *number <= INTEGER_MAX)?);
		}
		Some(UserInfo {upload: read[0]?, download: read[1]?, total: read[2]?, expire: read[3].filter(|expire| *expire != 0)})
	});
	Headers {usage, title: field("profile-title").map(shown).filter(|title| !title.is_empty()), update_interval: field("profile-update-interval").filter(|hours| hours.len() <= 3 && hours.bytes().all(|byte| byte.is_ascii_digit())).and_then(|hours| hours.parse::<u32>().ok()).filter(|hours| (1..=168).contains(hours)).map(|hours| hours * 3_600), support_url: field("support-url").and_then(|value| Url::parse(value, URL_MAX, true, true))}
}
