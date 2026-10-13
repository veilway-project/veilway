//! The subscription format (subscription format page): the link (`link`), the signed envelope (`envelope`), the payload (`payload`), the request and its body (`fetch`), what a client holds and decides (`client`) and the unsigned formats of other apps (`legacy`).
//!
//! Everything here reads what a provider or whoever answers in its place wrote, so every reader checks a limit before it uses a byte, and no error carries any of the input. There is no socket, no clock and no storage: the body of an answer, the time and the random bytes are parameters, and what a client holds is a value the caller keeps.
//!
//! Two properties are carried by the types and not by the caller's care. A payload is read only from an `envelope::Verified`, which nothing but `envelope::verify` makes, so no byte of a payload is parsed before its signature was checked under a key that was held. And a `fetch::Request` of a client comes only out of the steps of `client`, the first of which is the user's yes to what the link alone shows.
use crate::control::display;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use std::fmt;
use subtle::ConstantTimeEq;

pub mod client;
pub mod envelope;
pub mod fetch;
mod json;
pub mod legacy;
pub mod link;
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

/// "Link token: 16 bytes, 22 base64url characters." Whoever has it is that user to the provider.
pub type Token = Secret<16>;
/// "Device secret: 16 bytes, 22 base64url characters."
pub type DeviceSecret = Secret<16>;

/// Display text of a provider after the filter and the cut of the control channel page: fit to show as plain text. Only this module makes one, and only through `control::display`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Text(String);

impl Text {
	/// Filters `sent`, then cuts it to `chars` characters and `bytes` bytes.
	pub fn shown(sent: &str, chars: usize, bytes: usize) -> Self {Self(display(sent, chars, bytes))}
	pub fn as_str(&self) -> &str {&self.0}
	pub fn is_empty(&self) -> bool {self.0.is_empty()}
	/// Whether the text shows anything: it holds a character that is neither white space nor a combining mark with nothing to sit on. What the filter removed is gone already. A name must be visible, so that no provider and no profile is shown as a blank next to a fingerprint.
	pub fn visible(&self) -> bool {self.0.chars().any(|c| !c.is_whitespace() && !matches!(c, '\u{300}'..='\u{36f}' | '\u{1ab0}'..='\u{1aff}' | '\u{1dc0}'..='\u{1dff}' | '\u{20d0}'..='\u{20ff}' | '\u{fe20}'..='\u{fe2f}'))}
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

// A public key of X25519 as a document or a request writes it: 44 characters, not all zero and no point of small order, under which every private key gives the same shared secret.
pub(crate) fn public(text: &str) -> Option<[u8; 32]> {key(text).filter(|key| !SMALL_ORDER.iter().any(|point| key[..31] == point[..31] && key[31] & 0x7f == point[31]))}

/// Whether `name` is a host name: "lowercase ASCII, at most 253 bytes, by the domain rule of the config reference, without the wildcard". Labels of 1 to 63 letters, digits and inner hyphens, and a last label that is neither all digits nor `0x` and hex digits, so that the name is no address in any spelling.
pub fn is_host(name: &str) -> bool {
	name.len() <= 253 && name.split('.').all(|label| (1..=63).contains(&label.len()) && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') && !label.starts_with('-') && !label.ends_with('-')) && !name.rsplit('.').next().is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()) || last.strip_prefix("0x").is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit())))
}

/// An `https` URL "with a host name, no user or password part", kept exactly as it was written: nothing is normalised, so what is shown is what is opened or fetched.
/// The page gives no grammar beyond that. This one is the narrow reading: after the host an optional port of 1 to 65535 without a leading zero, then only the characters RFC 3986 allows in a path, a query and a fragment, every `%` followed by two hexadecimal digits, and no path segment that is `.` or `..` in any spelling, because whatever fetches or opens the URL would rewrite such a path.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Url {text: String, host: usize}

// A legacy subscription URL is a bearer secret, and the path of an endpoint is known to subscribers only: the host is all that is printed.
impl fmt::Debug for Url {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Url({}, ..)", self.host())}
}

impl Url {
	/// `limit` is the longest text, `query` and `fragment` say whether the URL may have those parts.
	pub fn parse(text: &str, limit: usize, query: bool, fragment: bool) -> Option<Self> {
		let rest = text.strip_prefix("https://").filter(|_| text.len() <= limit)?;
		let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
		let (host, port) = authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)));
		if !is_host(host) || port.is_some_and(|port| port.len() > 5 || port.starts_with('0') || !port.bytes().all(|byte| byte.is_ascii_digit()) || port.parse::<u16>().is_err()) {return None}
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
	/// The host and the port, as `host:port`, with 443 when the URL names none: what a user confirms when a document adds a refresh host.
	pub fn authority(&self) -> String {format!("{}:{}", self.host(), self.port())}
	/// The whole URL as it was written.
	pub fn as_str(&self) -> &str {&self.text}
	/// The host name, which is ASCII by the rule of `is_host`. It is what a screen shows before the URL is opened or fetched.
	pub fn host(&self) -> &str {&self.text[8..8 + self.host]}
	/// The port, 443 when the URL names none.
	pub fn port(&self) -> u16 {self.text[8 + self.host..].strip_prefix(':').and_then(|rest| rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())].parse().ok()).unwrap_or(443)}
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
	fn a_key_is_44_characters_of_standard_base64_and_not_zero() {
		assert_eq!(key(&key_text(&[7; 32])), Some([7; 32]));
		// Another length, the URL alphabet, a missing pad, bits set in what the pad covers, and the all-zero key.
		for text in [key_text(&[0; 32]), key_text(&[7; 32])[..43].to_owned(), STANDARD.encode([7; 33]), key_text(&[0xfb; 32]).replace('+', "-"), format!("{}9=", &key_text(&[7; 32])[..42]), String::new()] {assert_eq!(key(&text), None, "{text}")}
	}
}
