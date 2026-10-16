//! A sealed subscription file (subscription format page, "Sealed subscription file"): the text of a link, encrypted under a key made from a password.
//!
//! Layout, all numbers big-endian: `"VWSUBSEA"` (8), the format version (1), Argon2id memory in KiB (4), passes (4), lanes (4), salt (16), nonce (12), and then ChaCha20-Poly1305 of the link text with its 16 byte tag. The first 49 bytes are the header, and are the associated data.
//!
//! The password adds secrecy while the file is in transit and never trust: whatever opens is the text of a link, and the caller reads it through the ordinary import. A wrong password and a changed byte are one error. The salt and the nonce are arguments, because this crate draws nothing.
use super::{link::Link, CARRIED_MAX};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::fmt;

pub const MAGIC: &[u8; 8] = b"VWSUBSEA";
pub const FORMAT: u8 = 1;
pub const HEADER: usize = 49;
/// Memory in KiB, passes and lanes of a file this crate makes. A file with less is refused, since a client that opens it should not take part in a file whose password is cheap to guess.
pub const COST: (u32, u32, u32) = (65_536, 3, 1);
/// The most a file may ask a client for: 128 MiB, 6 passes and 4 lanes. A hostile file cannot make the device allocate more.
pub const COST_MAX: (u32, u32, u32) = (131_072, 6, 4);
pub const PASSWORD_MIN: usize = 10;
pub const PASSWORD_MAX: usize = 1_024;
/// The longest link text a file holds: a whole document in a link (`veilway://doc#v1.`, the key, a dot and 2,048 bytes) is the longest link there is.
pub const LINK_MAX: usize = 14 + 3 + 43 + 1 + CARRIED_MAX;
pub const FILE_MAX: usize = HEADER + LINK_MAX + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
	/// Fewer than `PASSWORD_MIN` characters, or more than `PASSWORD_MAX` bytes.
	Password,
	/// The text is not a native link or a whole document in a link, or is longer than `LINK_MAX`.
	Link,
	Cost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
	/// No magic, or too short to hold a header and a tag.
	NotSealed,
	Size,
	/// A format version other than this one. Only a newer one is worth a different word.
	Version(u8),
	/// Memory, passes or lanes outside what a client opens.
	Cost,
	/// "Wrong password, or the file is damaged": the two cannot be told apart.
	Wrong,
}

impl fmt::Display for SealError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "sealed subscription file: {self:?}")}
}

impl fmt::Display for OpenError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "sealed subscription file: {self:?}")}
}

impl std::error::Error for SealError {}

impl std::error::Error for OpenError {}

/// Whether a file begins with the magic. This is how an importer tells a sealed file from a plain one, before it asks for a password.
pub fn is_sealed(content: &[u8]) -> bool {content.starts_with(MAGIC)}

fn within(cost: (u32, u32, u32)) -> bool {cost.0 >= COST.0 && cost.1 >= COST.1 && cost.2 >= COST.2 && cost.0 <= COST_MAX.0 && cost.1 <= COST_MAX.1 && cost.2 <= COST_MAX.2}

fn derive(password: &str, salt: &[u8], (memory, passes, lanes): (u32, u32, u32)) -> Option<[u8; 32]> {
	let mut key = [0u8; 32];
	Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(memory, passes, lanes, Some(32)).ok()?).hash_password_into(password.as_bytes(), salt, &mut key).ok()?;
	Some(key)
}

/// Seals the text of a link with the cost of `COST`. Only a native link or a whole document in a link is sealed: nothing else is a subscription.
pub fn seal(password: &str, link: &str, salt: [u8; 16], nonce: [u8; 12]) -> Result<Vec<u8>, SealError> {seal_at(COST, password, link, salt, nonce)}

/// `seal` at another cost, between `COST` and `COST_MAX`: for a maker that wants to ask more, and for the tests of the caps.
pub fn seal_at(cost: (u32, u32, u32), password: &str, link: &str, salt: [u8; 16], nonce: [u8; 12]) -> Result<Vec<u8>, SealError> {
	if !within(cost) {return Err(SealError::Cost)}
	if password.chars().count() < PASSWORD_MIN || password.len() > PASSWORD_MAX {return Err(SealError::Password)}
	if link.len() > LINK_MAX || !matches!(Link::parse(link), Ok(Link::Native(_) | Link::Carried(_))) {return Err(SealError::Link)}
	let mut file = [MAGIC.as_slice(), &[FORMAT], &cost.0.to_be_bytes(), &cost.1.to_be_bytes(), &cost.2.to_be_bytes(), &salt, &nonce].concat();
	let key = derive(password, &salt, cost).ok_or(SealError::Cost)?;
	let mut body = link.as_bytes().to_vec();
	LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("32 byte key")).seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(file.as_slice()), &mut body).map_err(|_| SealError::Link)?;
	file.extend(body);
	Ok(file)
}

/// Opens a sealed file to the text of the link in it. The header is checked first, and its cost against `COST` and `COST_MAX` before any hashing, so a file cannot make the device work more than the caps allow. Nothing of the body is read before the tag has passed.
pub fn open(password: &str, file: &[u8]) -> Result<String, OpenError> {
	if file.len() > FILE_MAX {return Err(OpenError::Size)}
	if file.len() < HEADER + 16 || !is_sealed(file) {return Err(OpenError::NotSealed)}
	if file[8] != FORMAT {return Err(OpenError::Version(file[8]))}
	let number = |at: usize| u32::from_be_bytes(file[at..at + 4].try_into().expect("4 bytes"));
	let cost = (number(9), number(13), number(17));
	if !within(cost) {return Err(OpenError::Cost)}
	if password.len() > PASSWORD_MAX {return Err(OpenError::Wrong)}
	let key = derive(password, &file[21..37], cost).ok_or(OpenError::Cost)?;
	let mut body = file[HEADER..].to_vec();
	let length = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("32 byte key")).open_in_place(Nonce::try_assume_unique_for_key(&file[37..HEADER]).expect("12 bytes"), Aad::from(&file[..HEADER]), &mut body).map_err(|_| OpenError::Wrong)?.len();
	body.truncate(length);
	String::from_utf8(body).ok().filter(|text| text.len() <= LINK_MAX).ok_or(OpenError::Wrong)
}
