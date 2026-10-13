//! The envelope of a subscription document (subscription format page, "Envelope" and steps 1 to 3 of "What is checked, in order"): one JWS in compact serialisation with EdDSA over Ed25519, verified against the keys a client holds.
//!
//! There is no JOSE here and no header parser. The header of a key is one exact byte string, and the first part of a document is compared with it as bytes. The signature is checked by `ring`, with the checks in front of it that the strict rule of RFC 8032 needs and `ring` does not make: see `SigningKey::new`.
//!
//! `Verified` is the only way to a payload. Nothing outside this module makes one, and `payload::parse` takes nothing else.
use super::{sealed, unsealed};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{digest::{digest, SHA256}, signature::{UnparsedPublicKey, ED25519}};
use std::fmt;

/// "The signature part is 86 characters."
pub const SIGNATURE: usize = 86;
// The order of the group of Ed25519, 2^252 + 27742317777372353535851937790883648493, with its lowest byte first as a signature carries a number.
const ORDER: [u8; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];
// The y coordinates of the eight points of small order, lowest byte first: 0 (order 4), 1 (the neutral element), p - 1 (order 2) and the two of order 8. Each is the encoding of a point with the sign bit clear, and the other point with that y has it set. tests/vectors.py shows that eight times each point is the neutral element.
const SMALL: [[u8; 32]; 5] = [
	[0; 32],
	[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
	[0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
	[0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
	[0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
];

/// Why bytes are no document under a key that is held. Whatever it is, the document changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
	/// Longer than the limit of where it came from.
	Size,
	/// Not exactly three parts.
	Parts,
	/// A part that is not base64url in its one form: another character, padding, white space, a length no encoding has, unused bits that are set, or a signature part that is not 86 characters.
	Encoding,
	/// The first part is the header of no key held for this subscription. This is every other algorithm, type, member, order and spelling of a header as much as a key that is not held: "The answer was not signed by this provider's key."
	UnknownKey,
	/// The header names a key that is held and the signature does not verify under it.
	Signature,
}

impl fmt::Display for EnvelopeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "subscription envelope: {self:?}")}
}

impl std::error::Error for EnvelopeError {}

/// A provider's signing key: an Ed25519 public key that may be held for a subscription. One exists only for bytes that passed `new`, so a key from a link, from `signing_keys` and from storage are all checked the same way.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningKey([u8; 32]);

/// "The first 8 bytes of the SHA-256 of the public key, in base64url, 11 characters."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kid([u8; 8]);

impl Kid {
	pub fn new(bytes: [u8; 8]) -> Self {Self(bytes)}
	pub fn bytes(&self) -> [u8; 8] {self.0}
	/// The 11 characters.
	pub fn text(&self) -> String {sealed(&self.0)}
	/// Reads the 11 characters, in their one form.
	pub fn read(text: &str) -> Option<Self> {unsealed(text).map(Self)}
}

/// "The fingerprint of a key is the first 16 bytes of its SHA-256, shown as 8 groups of 4 hexadecimal digits." `Display` writes the groups with a space between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 16]);

impl fmt::Display for Fingerprint {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {self.0.chunks(2).enumerate().try_for_each(|(index, pair)| write!(f, "{}{:02x}{:02x}", if index == 0 {""} else {" "}, pair[0], pair[1]))}
}

impl SigningKey {
	/// "Encodings of points must be canonical, and a public key of small order is refused. A key of small order is also refused in a link and in `signing_keys`."
	/// `ring` checks neither: it reads a y coordinate of `p` or more as that number less `p`, takes a set sign bit with an x coordinate of 0, and verifies under the neutral element. So both are refused here, before `ring` sees the key: a y coordinate that is not below `p`, and each of the five y coordinates a point of small order has, with either sign bit, which covers the two encodings of an x of 0 with the sign bit set.
	/// Bytes that are the encoding of no point at all pass. Telling them apart takes a square root in the field, which would be arithmetic of this crate's own, and nothing verifies under such a key.
	pub fn new(bytes: [u8; 32]) -> Option<Self> {
		let mut y = bytes;
		y[31] &= 0x7f;
		// p is 2^255 - 19: the lowest byte is 0xed, the highest 0x7f and every byte between 0xff.
		let reduced = y[31] != 0x7f || y[1..31].iter().any(|byte| *byte != 0xff) || y[0] < 0xed;
		(reduced && !SMALL.contains(&y)).then_some(Self(bytes))
	}
	pub fn bytes(&self) -> &[u8; 32] {&self.0}
	pub fn kid(&self) -> Kid {Kid(std::array::from_fn(|index| digest(&SHA256, &self.0).as_ref()[index]))}
	pub fn fingerprint(&self) -> Fingerprint {Fingerprint(std::array::from_fn(|index| digest(&SHA256, &self.0).as_ref()[index]))}
	/// "The header is one exact byte string per key", "with the members in this order and no white space".
	pub fn header(&self) -> String {format!("{{\"alg\":\"EdDSA\",\"typ\":\"veilway-sub+jws\",\"kid\":\"{}\"}}", self.kid().text())}
}

// A public key is no secret, but 32 raw bytes in a log line help nobody: the fingerprint is what a user and a provider compare.
impl fmt::Debug for SigningKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "SigningKey({})", self.fingerprint())}
}

/// A document whose signature was checked under a key that was held. `payload::parse` reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct Verified {payload: Vec<u8>, signer: SigningKey}

impl Verified {
	/// The bytes that were signed, decoded: the JSON text of the payload.
	pub fn payload(&self) -> &[u8] {&self.payload}
	/// The held key the document verified under.
	pub fn signer(&self) -> SigningKey {self.signer}
}

// A payload holds transport secrets, and with a provider-issued key a private key.
impl fmt::Debug for Verified {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Verified({} bytes under {:?})", self.payload.len(), self.signer)}
}

// Whether `part` is base64url without padding in its one form, without decoding it: only the alphabet, a length an encoding can have, and no bit set that no byte takes.
pub(crate) fn canonical(part: &[u8]) -> bool {
	let value = |byte: u8| match byte {
		b'A'..=b'Z' => Some(byte - b'A'),
		b'a'..=b'z' => Some(byte - b'a' + 26),
		b'0'..=b'9' => Some(byte - b'0' + 52),
		b'-' => Some(62),
		b'_' => Some(63),
		_ => None,
	};
	part.iter().all(|byte| value(*byte).is_some()) && match (part.len() % 4, part.last().and_then(|byte| value(*byte))) {
		(1, _) => false,
		(2, Some(last)) => last & 0x0f == 0,
		(3, Some(last)) => last & 0x03 == 0,
		_ => true,
	}
}

/// Steps 1 to 3 of "What is checked, in order": `document` is within `limit` (`BODY_MAX` for an answer and a file, `CARRIED_MAX` for a link) and has exactly three well encoded parts, the first part is the header of a key in `held`, and the signature verifies under that key over the first two parts and the dot between them, "exactly as they were delivered".
/// Until the signature has verified, the payload part is looked at only as far as its characters go. It is decoded after that, and it is parsed by whoever takes the `Verified`.
pub fn verify(document: &[u8], held: &[SigningKey], limit: usize) -> Result<Verified, EnvelopeError> {
	if document.len() > limit {return Err(EnvelopeError::Size)}
	let mut parts = document.split(|byte| *byte == b'.');
	let (Some(header), Some(payload), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {return Err(EnvelopeError::Parts)};
	if !canonical(header) || !canonical(payload) {return Err(EnvelopeError::Encoding)}
	let signature: [u8; 64] = std::str::from_utf8(signature).ok().and_then(unsealed).ok_or(EnvelopeError::Encoding)?;
	// Two held keys can share a key id only if the provider made them so. Each key the header names is tried.
	let mut named = held.iter().filter(|key| sealed(key.header().as_bytes()).as_bytes() == header).peekable();
	if named.peek().is_none() {return Err(EnvelopeError::UnknownKey)}
	// "The second half of the signature must be below the group order." `ring` refuses it as well, which a test shows. It is checked here too, so that the rule does not rest on one library's reading of it.
	let below = signature[32..].iter().rev().zip(ORDER.iter().rev()).find(|(byte, order)| byte != order).is_some_and(|(byte, order)| byte < order);
	let signed = &document[..header.len() + 1 + payload.len()];
	let signer = named.find(|key| below && UnparsedPublicKey::new(&ED25519, key.0).verify(signed, &signature).is_ok()).ok_or(EnvelopeError::Signature)?;
	Ok(Verified {payload: URL_SAFE_NO_PAD.decode(payload).map_err(|_| EnvelopeError::Encoding)?, signer: *signer})
}

/// Writes a document: the header of `key`, `payload` and what `sign` gives for the bytes a signature covers. This is the provider's side, and the side of every test. The private key stays with the caller, whose `sign` is Ed25519 as RFC 8032 defines it.
pub fn seal(key: &SigningKey, payload: &[u8], sign: impl FnOnce(&[u8]) -> [u8; 64]) -> String {
	let signed = format!("{}.{}", sealed(key.header().as_bytes()), sealed(payload));
	let signature = sealed(&sign(signed.as_bytes()));
	format!("{signed}.{signature}")
}
