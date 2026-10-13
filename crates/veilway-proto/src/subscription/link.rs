//! The link (subscription format page, "The link" and "Import"): the two forms of a native link, a whole document in a link or a file, and a legacy link.
//!
//! "The form of the link decides what it is." The three kinds are three types, and nothing turns one into another: there is no function from a `Legacy` to a `Native` or back, and no answer of a server is an argument of anything here. A text is read exactly as it is. Cutting white space off a pasted text is the caller's, before it calls.
use super::{envelope::SigningKey, sealed, unsealed, Token, Url, BODY_MAX, CARRIED_MAX, LINK_URL_MAX};
use std::fmt;

// "The fragment is 70 characters with its `#`": `v1.`, 43 characters of key, a dot and 22 characters of token.
const FRAGMENT: usize = 69;
const KEY: usize = 43;

/// Why a text is no link. A link that is refused shows nothing and causes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
	/// "A link over a size limit": the URL without its fragment, or the document it carries.
	Size,
	/// "One that is not exactly one of the forms above": another scheme, another shape after `veilway://`, a host that is no host name, a query on a native link, a fragment of another length or alphabet, a key or token that is not in its one encoding, a version of the form this page does not define.
	Form,
	/// The key is the encoding of a point of small order, or no canonical encoding.
	Key,
}

impl fmt::Display for LinkError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "subscription link: {self:?}")}
}

impl std::error::Error for LinkError {}

/// What a user typed, pasted, scanned or opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
	Native(Native),
	Carried(Carried),
	Legacy(Legacy),
}

/// A native subscription link: the provider's endpoint, the provider's key and the user's token.
#[derive(Clone, PartialEq, Eq)]
pub struct Native {endpoint: Url, key: SigningKey, token: Token}

/// "A whole document in a link, a code or a file": the provider's key and a document that has yet to be verified under it. "It has no endpoint, so it cannot refresh."
#[derive(Clone, PartialEq, Eq)]
pub struct Carried {key: SigningKey, document: String, file: bool}

/// A legacy link: an `https` URL with no key part. What it leads to "cannot be verified".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Legacy {url: Url}

// `v1.<key>.<rest>`, where the key is 43 characters and the rest is what the caller reads.
fn keyed(content: &str) -> Result<(SigningKey, &str), LinkError> {
	let rest = content.strip_prefix("v1.").filter(|rest| rest.is_char_boundary(KEY) && rest.as_bytes().get(KEY) == Some(&b'.')).ok_or(LinkError::Form)?;
	Ok((SigningKey::new(unsealed(&rest[..KEY]).ok_or(LinkError::Form)?).ok_or(LinkError::Key)?, &rest[KEY + 1..]))
}

impl Link {
	/// Reads a link by "the exact grammar, which the client checks before it does anything else".
	///
	/// - `veilway://sub/`, a host name with an optional port, `/` and a path, `#v1.`, the key, a dot and the token: native.
	/// - The same with `https://`: native.
	/// - `veilway://doc#v1.`, the key, a dot and a document of at most `CARRIED_MAX` bytes: a whole document.
	/// - "Anything that begins with `veilway://` and matches none of these is refused at once."
	/// - Any other `https` URL: legacy. Its fragment, if it has one, is not kept, as no request carries one.
	///
	/// An `https` text that holds `v1.`, 43 characters of base64url, a dot and 22 more anywhere is refused and is never a legacy link.
	/// An `https` URL whose fragment is `v`, digits and then a dot or the end is held to the native grammar and refused when it does not fit. The page says only that a link with a `v1` fragment is native and every other is legacy. Read to the letter, a native link whose key lost a character on the way would become a legacy link to the provider's endpoint, and a later form `v2` would be fetched as a legacy list by a client that does not know it.
	pub fn parse(text: &str) -> Result<Self, LinkError> {
		if let Some(rest) = text.strip_prefix("veilway://") {
			return match (rest.strip_prefix("doc#"), rest.strip_prefix("sub/")) {
				(Some(content), _) => Carried::read(content, CARRIED_MAX, false).map(Self::Carried),
				(_, Some(rest)) => Native::read(rest).map(Self::Native),
				_ => Err(LinkError::Form),
			};
		}
		let rest = text.strip_prefix("https://").ok_or(LinkError::Form)?;
		let fragment = rest.split_once('#').map(|(_, fragment)| fragment);
		if fragment.is_some_and(|fragment| fragment.strip_prefix('v').is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()) && rest.trim_start_matches(|c: char| c.is_ascii_digit()).chars().next().is_none_or(|c| c == '.'))) {return Native::read(rest).map(Self::Native)}
		let fetched = &text[..text.len() - fragment.map_or(0, |fragment| fragment.len() + 1)];
		// A native link that lost its `#`, or had it changed or something put behind it on the way, would be a legacy URL with the key and the token in its path or query, and a `GET` would send both in the request line. A text that holds what a native fragment holds, anywhere, is refused.
		let letter = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_';
		if text.as_bytes().windows(FRAGMENT).any(|part| part.starts_with(b"v1.") && part[3..3 + KEY].iter().all(letter) && part[3 + KEY] == b'.' && part[4 + KEY..].iter().all(letter)) {return Err(LinkError::Form)}
		if fetched.len() > LINK_URL_MAX {return Err(LinkError::Size)}
		Url::parse(fetched, LINK_URL_MAX, true, false).map(|url| Self::Legacy(Legacy {url})).ok_or(LinkError::Form)
	}
}

impl Native {
	// What follows `veilway://sub/` or `https://`.
	fn read(rest: &str) -> Result<Self, LinkError> {
		let (endpoint, fragment) = rest.split_once('#').ok_or(LinkError::Form)?;
		// The limit is counted on the `https` form, which is the URL the client requests.
		if endpoint.len() + 8 > LINK_URL_MAX {return Err(LinkError::Size)}
		if fragment.len() != FRAGMENT {return Err(LinkError::Form)}
		let (key, token) = keyed(fragment)?;
		let endpoint = Url::parse(&format!("https://{endpoint}"), LINK_URL_MAX, false, false).filter(|_| endpoint.contains('/')).ok_or(LinkError::Form)?;
		Ok(Self {endpoint, key, token: Token::new(unsealed(token).ok_or(LinkError::Form)?)})
	}
	/// The provider's subscription endpoint as the URL a fetch goes to: `https`, a host, an optional port and a path. "It is the same for all of a provider's users and holds no secret."
	pub fn endpoint(&self) -> &Url {&self.endpoint}
	/// The key every document of this subscription is verified against until a document names others.
	pub fn key(&self) -> SigningKey {self.key}
	pub fn token(&self) -> &Token {&self.token}
	fn fragment(&self) -> String {format!("#v1.{}.{}", sealed(self.key.bytes()), sealed(self.token.expose()))}
	/// The link in the form providers hand out. It holds the token: it goes to the secret storage and to the screen the user asked for it on, and nowhere else.
	pub fn veilway(&self) -> String {format!("veilway://sub/{}{}", &self.endpoint.as_str()[8..], self.fragment())}
	/// The link in its `https` form, under the same care.
	pub fn https(&self) -> String {format!("{}{}", self.endpoint.as_str(), self.fragment())}
}

// The token is the account.
impl fmt::Debug for Native {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Native({}, {:?}, ..)", self.endpoint.host(), self.key)}
}

impl Carried {
	// `v1.<key>.<document>`. "The content is split at the first two dots, because the document has two dots of its own."
	fn read(content: &str, limit: usize, file: bool) -> Result<Self, LinkError> {
		let (key, document) = keyed(content)?;
		if document.len() > limit {return Err(LinkError::Size)}
		// Only the characters a document can have, so that the link reads back as it was written. Whether it is a document is for `envelope::verify`, after the user's first yes.
		if document.is_empty() || !document.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)) {return Err(LinkError::Form)}
		Ok(Self {key, document: document.to_owned(), file})
	}
	/// Reads the content of a file: "`v1.<key>.<document>`", with a document of at most `BODY_MAX` bytes and nothing before or after it, a line end included.
	pub fn file(content: &[u8]) -> Result<Self, LinkError> {
		if content.len() > BODY_MAX + KEY + 4 {return Err(LinkError::Size)}
		Self::read(std::str::from_utf8(content).map_err(|_| LinkError::Form)?, BODY_MAX, true)
	}
	pub fn key(&self) -> SigningKey {self.key}
	/// The document as it was carried: bytes for `envelope::verify`, and nothing else until it has verified.
	pub fn document(&self) -> &[u8] {self.document.as_bytes()}
	/// Whether it came in a file, which the first screen says.
	pub fn in_file(&self) -> bool {self.file}
	/// The content of a file that carries the document.
	pub fn file_content(&self) -> String {format!("v1.{}.{}", sealed(self.key.bytes()), self.document)}
	/// The link that carries the document, or `None` when the document is longer than a link may carry.
	pub fn veilway(&self) -> Option<String> {(self.document.len() <= CARRIED_MAX).then(|| format!("veilway://doc#{}", self.file_content()))}
}

// "Such a link holds a private key and transport secrets."
impl fmt::Debug for Carried {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Carried({:?}, {} bytes)", self.key, self.document.len())}
}

impl Legacy {
	/// The URL a `GET` goes to, without a fragment.
	pub fn url(&self) -> &Url {&self.url}
}
