//! The subscription format (subscription format page): the link (`link`), the signed envelope (`envelope`), the payload (`payload`), the request and its body (`fetch`), what a client holds and decides (`client`) and the unsigned formats of other apps (`legacy`).
//!
//! Everything here reads what a provider or whoever answers in its place wrote, so every reader checks a limit before it uses a byte, and no error carries any of the input. There is no socket, no clock and no storage: the body of an answer, the time and the random bytes are parameters, and what a client holds is a value the caller keeps.
//!
//! Two properties are carried by the types and not by the caller's care. A payload is read only from an `envelope::Verified`, which nothing but `envelope::verify` makes, so no byte of a payload is parsed before its signature was checked under a key that was held. And a `fetch::Request` of a client comes only out of the steps of `client`, the first of which is the user's yes to what the link alone shows.
use crate::{control::{display, Untrusted}, unicode::strong};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use payload::dialable;
use std::{fmt, net::IpAddr};
use subtle::ConstantTimeEq;

pub mod client;
pub mod envelope;
pub mod exchange;
pub mod fetch;
pub(crate) mod json;
pub mod legacy;
pub mod link;
pub mod mirror;
pub mod payload;

/// "Response body, and a document in a file: at most 1,048,576 bytes."
pub const BODY_MAX: usize = 1_048_576;
/// "Document in a link or a QR code: at most 2,048 bytes."
pub const CARRIED_MAX: usize = 2_048;
/// "Subscription URL without its fragment: at most 256 characters."
pub const LINK_URL_MAX: usize = 256;
/// Every other `url`: "at most 512 characters".
pub const URL_MAX: usize = 512;
/// "Any string without its own limit: at most 1,024 bytes."
pub const STRING_MAX: usize = 1_024;

/// A secret of `N` bytes: the token of a link, a device secret, a private key, a preshared key, a transport secret. It prints nothing, and two of them are compared in constant time.
#[derive(Clone)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
	pub fn new(bytes: [u8; N]) -> Self {Self(bytes)}
	/// The bytes, for the one place that needs them: a request body, the secret storage, the tunnel. Never a log line, a URL or a header.
	pub fn expose(&self) -> &[u8; N] {&self.0}
}

impl<const N: usize> PartialEq for Secret<N> {
	fn eq(&self, other: &Self) -> bool {self.0.ct_eq(&other.0).into()}
}

impl<const N: usize> Eq for Secret<N> {}

impl<const N: usize> fmt::Debug for Secret<N> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Secret(..)")}
}

/// How an endpoint is reached ("The link decides how the endpoint is reached"): by the chain of its certificate, by the pins it was given alone, or over plain HTTP. No answer and no setting moves an endpoint from one to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {Chain, Pinned, Plain}

/// "Link token: 16 bytes, 22 base64url characters." Whoever has it is that user to the provider.
pub type Token = Secret<16>;
/// "Device secret: 16 bytes, 22 base64url characters."
pub type DeviceSecret = Secret<16>;

/// "Languages of one text: the default and at most 8 more."
pub const TRANSLATIONS_MAX: usize = 8;
/// "A language tag: at most 11 characters."
pub const TAG_MAX: usize = 11;

/// A language tag of "Text in several languages": 2 or 3 lowercase letters, then optionally `-` and a script of one uppercase and three lowercase letters, then optionally `-` and a region of two uppercase letters. One spelling only, and no registry behind it: a tag nobody has heard of is a tag that matches no language of the app.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag(String);

impl Tag {
	pub fn read(text: &str) -> Option<Self> {
		let (language, rest) = text.split_once('-').map_or((text, None), |(language, rest)| (language, Some(rest)));
		let (script, region) = match rest.map(|rest| rest.split_once('-').ok_or(rest)) {
			None => (None, None),
			Some(Ok((script, region))) => (Some(script), Some(region)),
			Some(Err(one)) => if one.len() == 4 {(Some(one), None)} else {(None, Some(one))},
		};
		(text.len() <= TAG_MAX && (2..=3).contains(&language.len()) && language.bytes().all(|byte| byte.is_ascii_lowercase()) && script.is_none_or(|script| script.len() == 4 && script.bytes().enumerate().all(|(index, byte)| if index == 0 {byte.is_ascii_uppercase()} else {byte.is_ascii_lowercase()})) && region.is_none_or(|region| region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase()))).then(|| Self(text.to_owned()))
	}
	/// The tag as it is written, which is what a renderer takes as the language of a text, "for shaping and the choice of font only".
	pub fn as_str(&self) -> &str {&self.0}
	/// The language, the script and the region.
	pub fn parts(&self) -> (&str, Option<&str>, Option<&str>) {
		let mut parts = self.0.split('-');
		let (language, second, third) = (parts.next().unwrap_or_default(), parts.next(), parts.next());
		(language, second.filter(|part| part.len() == 4), third.or(second.filter(|part| part.len() == 2)))
	}
}

/// A translation of a text that was picked for the reader: the tag it was written under, for the "small mark of its language" and for the renderer, and the text itself.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Translation<'a> {pub tag: &'a Tag, pub text: &'a str}

impl fmt::Debug for Translation<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Translation({})", self.tag.as_str())}
}

/// Which way a text is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {LeftToRight, RightToLeft}

/// "The direction of a provider text is taken from the first character in it that has a strong direction. A text with none, such as one of digits only, is left to right." For a translation as for `default`, and for what a node sent once it went through `control::display`. The language tag of a text says nothing about this.
pub fn direction(text: &str) -> Direction {if text.chars().find_map(strong) == Some(true) {Direction::RightToLeft} else {Direction::LeftToRight}}

// Whether a text shows anything: it holds a character that is neither white space nor a combining mark with nothing to sit on.
pub(crate) fn visible(text: &str) -> bool {text.chars().any(|c| !c.is_whitespace() && !matches!(c, '\u{300}'..='\u{36f}' | '\u{1ab0}'..='\u{1aff}' | '\u{1dc0}'..='\u{1dff}' | '\u{20d0}'..='\u{20ff}' | '\u{fe20}'..='\u{fe2f}'))}

/// Display text of a provider after the filter and the cut of the control channel page: fit to show as plain text. Only this module makes one, and only through `control::display`.
/// It is `default` and at most `TRANSLATIONS_MAX` translations, each filtered and cut as `default` is. A legacy text and a device's name have `default` alone.
/// It prints no text of any language. What it also holds and never gives out is `default` as the document wrote it, unfiltered and uncut, which `is` compares with what a node sent.
#[derive(Clone, Default)]
pub struct Text {shown: String, sent: String, translations: Vec<(Tag, String)>}

// Two texts are the same text when they show the same in every language. What the filter took out of one of them makes no difference a reader could see.
impl PartialEq for Text {
	fn eq(&self, other: &Self) -> bool {self.shown == other.shown && self.translations == other.translations}
}

impl Eq for Text {}

impl fmt::Debug for Text {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Text({} bytes, {} translations)", self.shown.len(), self.translations.len())}
}

impl Text {
	/// Filters `sent`, then cuts it to `chars` characters and `bytes` bytes. The text has no translation.
	pub fn shown(sent: &str, chars: usize, bytes: usize) -> Self {Self {shown: display(sent, chars, bytes), sent: sent.to_owned(), translations: Vec::new()}}
	// A text of a document: `default` as it was written, as it is shown, and the translations that were kept, each already filtered and cut.
	pub(crate) fn translated(sent: &str, shown: String, translations: Vec<(Tag, String)>) -> Self {Self {shown, sent: sent.to_owned(), translations}}
	/// `default`: what the provider wrote for a reader of any language.
	pub fn as_str(&self) -> &str {&self.shown}
	pub fn is_empty(&self) -> bool {self.shown.is_empty()}
	/// Whether `default` shows anything. What the filter removed is gone already. A name must be visible, so that no provider and no profile is shown as a blank next to a fingerprint.
	pub fn visible(&self) -> bool {visible(&self.shown)}
	/// The translations that were kept, in the order of the document.
	pub fn translations(&self) -> impl Iterator<Item = Translation<'_>> {self.translations.iter().map(|(tag, text)| Translation {tag, text})}
	/// "How the client picks." `languages` is the app's display language and then the user's fallback languages, each with the script and the region the app fills in from its own table, such as `fa-Arab-IR`. For each in turn the text is asked for language, script and region, then language and script, then language and region, then the language alone. A step that needs a part the app's tag does not have is left out.
	/// `None` when the text has none of them: the reader then sees `default`. Nothing is guessed, no "similar" language is taken, and `und` matches nothing, also when it is asked for.
	pub fn translation(&self, languages: &[Tag]) -> Option<Translation<'_>> {
		languages.iter().map(Tag::parts).filter(|(language, ..)| *language != "und").find_map(|(language, script, region)| [script.zip(region).map(|(script, region)| (Some(script), Some(region))), script.map(|script| (Some(script), None)), region.map(|region| (None, Some(region))), Some((None, None))].into_iter().flatten().find_map(|(script, region)| self.translations().find(|translation| translation.tag.parts() == (language, script, region))))
	}
	/// What a reader of `languages` is shown where nothing is decided: the text, and the tag it was written under when it is a translation, which is then marked as one "with a way to see `default` from there".
	pub fn pick(&self, languages: &[Tag]) -> (&str, Option<&Tag>) {self.translation(languages).map_or((&self.shown, None), |translation| (translation.text, Some(translation.tag)))}
	/// What a screen shows "where the user decides something (an import, a replacement, the consent to a lower class, the question about a private address)": `default` always, "with the picked translation beside it when there is one".
	pub fn decided(&self, languages: &[Tag]) -> (&str, Option<Translation<'_>>) {(&self.shown, self.translation(languages))}
	/// Whether `default`, exactly as the document wrote it, is byte for byte what a node sent ("Languages" on the control channel page): "before any filter or cut, with no normalisation". Only then may a translation of this text stand for the node's text.
	pub fn is(&self, sent: &Untrusted) -> bool {self.sent == sent.as_sent()}
}

// The u coordinates of the points of small order on Curve25519, lowest byte first, with the highest bit clear as X25519 reads them: 0, 1, the two of order 8, p - 1, p and p + 1. tests/vectors.py shows that X25519 gives all zero bytes for each. `proof` holds the same list for the `enc` of a token.
const SMALL_ORDER: [[u8; 32]; 7] = [
	[0; 32],
	[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
	[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
	[0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
	[0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
	[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
	[0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
];

// Whether a public key of X25519 is all zero or a point of small order, under which every private key gives the same shared secret.
pub(crate) fn weak(key: &[u8; 32]) -> bool {*key == [0; 32] || SMALL_ORDER.iter().any(|point| key[..31] == point[..31] && key[31] & 0x7f == point[31])}

// A public key of X25519 as a document or a request writes it: 44 characters, not all zero and no point of small order.
pub(crate) fn public(text: &str) -> Option<[u8; 32]> {key(text).filter(|key| !weak(key))}

/// Whether `name` is a host name: "lowercase ASCII, at most 253 bytes, by the domain rule of the config reference, without the wildcard". Labels of 1 to 63 letters, digits and inner hyphens, and a last label that is neither all digits nor `0x` and hex digits, so that the name is no address in any spelling.
pub fn is_host(name: &str) -> bool {
	name.len() <= 253 && name.split('.').all(|label| (1..=63).contains(&label.len()) && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') && !label.starts_with('-') && !label.ends_with('-')) && !name.rsplit('.').next().is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()) || last.strip_prefix("0x").is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit())))
}

/// An `https` URL, or an `http` URL for a plain endpoint ("The link"), "with a host name, no user or password part", kept exactly as it was written: nothing is normalised, so what is shown is what is opened or fetched.
/// The page gives no grammar beyond that. This one is the narrow reading: after the host an optional port of 1 to 65535 without a leading zero, then only the characters RFC 3986 allows in a path, a query and a fragment, every `%` followed by two hexadecimal digits, and no path segment that is `.` or `..` in any spelling, because whatever fetches or opens the URL would rewrite such a path.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Url {text: String, host: usize}

// A legacy subscription URL is a bearer secret, and the path of an endpoint is known to subscribers only: the host is all that is printed.
impl fmt::Debug for Url {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Url({}, ..)", self.host())}
}

impl Url {
	/// `limit` is the longest text, `query` and `fragment` say whether the URL may have those parts.
	pub fn parse(text: &str, limit: usize, query: bool, fragment: bool) -> Option<Self> {Self::read(text, limit, query, fragment, false, false)}
	/// `pinned` for an `http` URL, the endpoint of a plain link: it has no certificate to name, so its host may be an IP literal in the one spelling as well. Held to the same refusals of `dialable`.
	pub fn plain(text: &str, limit: usize, query: bool, fragment: bool) -> Option<Self> {Self::read(text, limit, query, fragment, true, true)}
	/// `parse` for an `https` URL and `plain` for an `http` one: the URL of a refresh entry given as a string or of a move, which a plain endpoint may be.
	pub fn either(text: &str, limit: usize, query: bool, fragment: bool) -> Option<Self> {if text.starts_with("http://") {Self::plain(text, limit, query, fragment)} else {Self::parse(text, limit, query, fragment)}}
	/// `parse` for the URL of a pinned endpoint ("A pinned endpoint"), whose host may also be an IP literal: a dotted IPv4 address or an IPv6 address in brackets, in the one spelling Rust prints (so lowercase, no zone, no leading zeros), that is `dialable`. A pinned endpoint has no certificate that names it, so an address is all a provider with no domain has to put here.
	pub fn pinned(text: &str, limit: usize, query: bool, fragment: bool) -> Option<Self> {Self::read(text, limit, query, fragment, true, false)}
	fn read(text: &str, limit: usize, query: bool, fragment: bool, literal: bool, plain: bool) -> Option<Self> {
		let rest = text.strip_prefix(if plain {"http://"} else {"https://"}).filter(|_| text.len() <= limit)?;
		let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
		let (host, port) = if authority.starts_with('[') {
			let (host, rest) = authority.split_at(authority.find(']')? + 1);
			(host, if rest.is_empty() {None} else {Some(rest.strip_prefix(':')?)})
		} else {authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)))};
		if !(is_host(host) || (literal && address(host).is_some_and(dialable))) || port.is_some_and(|port| port.len() > 5 || port.starts_with('0') || !port.bytes().all(|byte| byte.is_ascii_digit()) || port.parse::<u16>().is_err()) {return None}
		let (tail, part) = tail.split_once('#').map_or((tail, None), |(tail, part)| (tail, Some(part)));
		let (path, asked) = tail.split_once('?').map_or((tail, None), |(path, asked)| (path, Some(asked)));
		if (part.is_some() && !fragment) || (asked.is_some() && !query) || part.is_some_and(|part| part.contains('#')) {return None}
		let after = &rest.as_bytes()[authority.len()..];
		if !after.iter().enumerate().all(|(index, byte)| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?#".contains(byte) || (*byte == b'%' && after.get(index + 1..index + 3).is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit)))) {return None}
		if path.split('/').any(|segment| matches!(segment.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | "..")) {return None}
		// A URL that may hold no fragment is one the app requests itself, with the token in the body: an endpoint, a refresh URL, a legacy link. What a server or a proxy on the way may read as another path is refused in it: an encoded control character, slash or backslash anywhere, and a `.` or `..` segment that carries a parameter.
		if !fragment && (after.windows(3).any(|escape| escape[0] == b'%' && std::str::from_utf8(&escape[1..]).ok().and_then(|digits| u8::from_str_radix(digits, 16).ok()).is_some_and(|byte| byte < 0x20 || matches!(byte, 0x7f | 0x2f | 0x5c))) || path.split('/').any(|segment| matches!(segment.split(';').next().unwrap_or_default().to_ascii_lowercase().replace("%2e", ".").as_str(), "." | ".."))) {return None}
		Some(Self {text: text.to_owned(), host: host.len()})
	}
	/// The host and the port, as `host:port`, with 443 (80 for `http`) when the URL names none: what a user confirms when a document adds a refresh host.
	pub fn authority(&self) -> String {format!("{}:{}", self.host(), self.port())}
	/// Whether this is an `http` URL: a plain endpoint, which nothing hides from the network.
	pub fn is_plain(&self) -> bool {self.text.starts_with("http://")}
	// The length of the scheme and `://`.
	fn start(&self) -> usize {if self.is_plain() {7} else {8}}
	/// The whole URL as it was written.
	pub fn as_str(&self) -> &str {&self.text}
	/// The host name, which is ASCII by the rule of `is_host`, or an IP literal as written (with its brackets when it is IPv6) in a URL that was read with `pinned`. It is what a screen shows before the URL is opened or fetched.
	pub fn host(&self) -> &str {&self.text[self.start()..self.start() + self.host]}
	/// The address when the host is an IP literal, which only a pinned or a plain endpoint's can be: it is dialled with no lookup and sent no server name.
	pub fn literal(&self) -> Option<IpAddr> {address(self.host())}
	/// The port, 443 when an `https` URL names none and 80 when an `http` one does not.
	pub fn port(&self) -> u16 {self.text[self.start() + self.host..].strip_prefix(':').and_then(|rest| rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())].parse().ok()).unwrap_or(if self.is_plain() {80} else {443})}
}

// An IP literal in its one spelling, as a URL host: `1.2.3.4` or `[::1]`. One spelling, so that two spellings of an address cannot be two hosts to the rules that compare `authority`.
fn address(host: &str) -> Option<IpAddr> {
	let ip = match host.strip_prefix('[') {Some(inner) => IpAddr::V6(inner.strip_suffix(']')?.parse().ok()?), None => IpAddr::V4(host.parse().ok()?)};
	(match ip {IpAddr::V4(ip) => ip.to_string(), IpAddr::V6(ip) => format!("[{ip}]")} == host).then_some(ip)
}

// "Every base64url part has no padding and no white space, and its unused trailing bits are zero." The decoder refuses all three as it is set up here, which a test of `envelope` shows.
pub(crate) fn unsealed<const N: usize>(text: &str) -> Option<[u8; N]> {
	let mut bytes = [0; 68];
	(N <= 64 && text.len() == (N * 4).div_ceil(3) && URL_SAFE_NO_PAD.decode_slice(text, &mut bytes) == Ok(N)).then(|| std::array::from_fn(|index| bytes[index]))
}

pub(crate) fn sealed(bytes: &[u8]) -> String {URL_SAFE_NO_PAD.encode(bytes)}

// "A WireGuard key, a transport key and a transport secret are written as in the config reference: standard base64 with padding, 44 characters, 32 bytes. An all-zero key is an error."
pub(crate) fn key(text: &str) -> Option<[u8; 32]> {hash(text).filter(|key| *key != [0; 32])}

// 32 bytes in the same writing that are no key: a certificate pin.
pub(crate) fn hash(text: &str) -> Option<[u8; 32]> {
	let mut bytes = [0; 36];
	(text.len() == 44 && STANDARD.decode_slice(text, &mut bytes) == Ok(32)).then(|| std::array::from_fn(|index| bytes[index]))
}

pub(crate) fn key_text(key: &[u8; 32]) -> String {STANDARD.encode(key)}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_secret_prints_nothing_and_compares_whole() {
		assert_eq!(format!("{:?}", Token::new([7; 16])), "Secret(..)");
		assert!(Token::new([7; 16]) == Token::new([7; 16]) && Token::new([7; 16]) != Token::new([8; 16]));
	}

	#[test]
	fn a_host_name_follows_the_domain_rule() {
		for name in ["example.com", "sub.example.com", "a", "xn--80ak6aa92e.example", "a-b.example", &format!("{}.example", "a".repeat(63))] {assert!(is_host(name), "{name}")}
		for name in ["", ".", "example.com.", ".example.com", "Example.com", "exa_mple.com", "-a.example", "a-.example", "*.example.com", "192.0.2.1", "example.1", "example.0x1f", "exa mple.com", "example.com:443", "[2001:db8::1]", "ex\u{e4}mple.com", &format!("{}.example", "a".repeat(64)), &["a"; 128].join(".")] {assert!(!is_host(name), "{name}")}
		assert!(is_host(&["a"; 127].join(".")) && ["a"; 127].join(".").len() == 253);
	}

	#[test]
	fn a_url_is_https_with_a_host_name_and_is_kept_as_written() {
		for text in ["https://example.com", "https://example.com/", "https://example.com:8443/a/b?c=d&e=%20#top", "https://example.com/a.b/..c/%2fd", "https://example.com?x", "https://example.com#x"] {
			let url = Url::parse(text, URL_MAX, true, true).unwrap();
			assert_eq!((url.as_str(), url.host()), (text, "example.com"), "{text}");
		}
		assert_eq!((Url::parse("https://example.com:8443/a", URL_MAX, true, true).unwrap().port(), Url::parse("https://example.com/a:1", URL_MAX, true, true).unwrap().port()), (8443, 443));
		for text in ["http://example.com/", "HTTPS://example.com/", "https:/example.com/", "https://", "https:///a", "https://user@example.com/", "https://user:pass@example.com/", "https://example.com:0/", "https://example.com:/", "https://example.com:65536/", "https://example.com:0443/", "https://example.com:44 3/", "https://192.0.2.1/", "https://[2001:db8::1]/", "https://Example.com/", "https://example.com/a b", "https://example.com/a\\b", "https://example.com/%", "https://example.com/%2", "https://example.com/%zz", "https://example.com/a/../b", "https://example.com/./b", "https://example.com/a/%2E%2e", "https://example.com/a/.%2e/b", "https://example.com/\u{e4}", "https://example.com/a\n", "https://example.com/a#b#c", "https://example.com/<a>", " https://example.com/"] {assert!(Url::parse(text, URL_MAX, true, true).is_none(), "{text}")}
		assert!(Url::parse("https://example.com/a?b", URL_MAX, false, true).is_none() && Url::parse("https://example.com/a#b", URL_MAX, true, false).is_none());
		let long = format!("https://example.com/{}", "a".repeat(URL_MAX - 20));
		assert!(Url::parse(&long, URL_MAX, true, true).is_some() && Url::parse(&format!("{long}a"), URL_MAX, true, true).is_none());
	}

	#[test]
	fn only_a_pinned_url_has_an_address_for_a_host_and_in_one_spelling() {
		for (text, host, port) in [("https://203.0.113.7/s", "203.0.113.7", 443), ("https://203.0.113.7:8443/s?a=b", "203.0.113.7", 8443), ("https://[2001:db8::1]/s", "[2001:db8::1]", 443), ("https://[2001:db8::1]:444/s", "[2001:db8::1]", 444), ("https://example.com:8443/s", "example.com", 8443)] {
			let url = Url::pinned(text, URL_MAX, true, false).unwrap();
			assert_eq!((url.host(), url.port(), url.literal().is_some(), Url::parse(text, URL_MAX, true, false).is_some()), (host, port, host != "example.com", host == "example.com"), "{text}");
		}
		for text in ["https://127.0.0.1/", "https://[::1]/", "https://0.0.0.0/", "https://169.254.1.1/", "https://224.0.0.1/", "https://255.255.255.255/", "https://[fe80::1]/", "https://[::ffff:203.0.113.7]/", "https://[2001:DB8::1]/", "https://[2001:db8:0:0:0:0:0:1]/", "https://[2001:db8::1%25eth0]/", "https://203.000.113.007/", "https://203.0.113/", "https://3405803783/", "https://0xcb007107/", "https://[2001:db8::1/", "https://[2001:db8::1]x/", "https://[2001:db8::1]:/", "https://[2001:db8::1]:0/", "https://[]/", "https://2001:db8::1/", "https://u@203.0.113.7/", "https://203.0.113.7:99999/"] {assert!(Url::pinned(text, URL_MAX, true, false).is_none(), "{text}")}
		assert_eq!(Url::pinned("https://example.com/", URL_MAX, true, false).unwrap().literal(), None);
	}

	#[test]
	fn a_key_is_44_characters_of_standard_base64_and_not_zero() {
		assert_eq!(key(&key_text(&[7; 32])), Some([7; 32]));
		// Another length, the URL alphabet, a missing pad, bits set in what the pad covers, and the all-zero key.
		for text in [key_text(&[0; 32]), key_text(&[7; 32])[..43].to_owned(), STANDARD.encode([7; 33]), key_text(&[0xfb; 32]).replace('+', "-"), format!("{}9=", &key_text(&[7; 32])[..42]), String::new()] {assert_eq!(key(&text), None, "{text}")}
	}
}
