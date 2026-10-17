//! The pieces of TLS 1.3 (RFC 8446) that the client and the node of `faketls` both write themselves, because no TLS library lets them set the sizes of records or the bytes of a hello: the three suites, the key schedule of section 7.1, the record protection of section 5 with record padding (section 5.4), and the ServerHello (section 4.1.3) with the two groups the mode answers with.
//! All cryptography is `ring`'s. Nothing here reads a socket or a clock.
use crate::{NoRandom, Random};
use ring::{aead, digest, hkdf, hmac};
use zeroize::Zeroize;

/// The record header's length, and the tag every protected record ends with.
pub const HEADER: usize = 5;
pub const TAG: usize = 16;
/// What RFC 8446 section 5.2 allows a protected record to hold: 2^14 bytes of inner plaintext, the content type, and 255 bytes of expansion.
pub const RECORD: usize = 16_384 + 256;
/// The two key exchange groups: X25519, and X25519MLKEM768 whose ML-KEM part comes first in both the share and the secret.
pub const X25519: u16 = 0x001d;
pub const HYBRID: u16 = 0x11ec;
/// The sizes of a hybrid share: the ML-KEM-768 encapsulation key and ciphertext, and the X25519 part that follows each.
pub const KEM_KEY: usize = 1184;
pub const KEM_CIPHERTEXT: usize = 1088;
/// RFC 8446 section 4.1.3: the `random` that makes a ServerHello a HelloRetryRequest, SHA-256 of "HelloRetryRequest".
const HELLO_RETRY: [u8; 32] = [0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c];

/// The three TLS 1.3 suites of RFC 8446 section 9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {Aes128, Aes256, Chacha}

impl Suite {
	pub fn from_id(id: u16) -> Option<Suite> {
		match id {
			0x1301 => Some(Suite::Aes128),
			0x1302 => Some(Suite::Aes256),
			0x1303 => Some(Suite::Chacha),
			_ => None,
		}
	}

	pub fn id(self) -> u16 {
		match self {
			Suite::Aes128 => 0x1301,
			Suite::Aes256 => 0x1302,
			Suite::Chacha => 0x1303,
		}
	}

	/// The length of the suite's hash, which is the length of every secret of its key schedule.
	pub fn hash_len(self) -> usize {if self == Suite::Aes256 {48} else {32}}

	fn algorithm(self) -> &'static aead::Algorithm {
		match self {
			Suite::Aes128 => &aead::AES_128_GCM,
			Suite::Aes256 => &aead::AES_256_GCM,
			Suite::Chacha => &aead::CHACHA20_POLY1305,
		}
	}

	fn hkdf(self) -> hkdf::Algorithm {if self == Suite::Aes256 {hkdf::HKDF_SHA384} else {hkdf::HKDF_SHA256}}

	fn hmac(self) -> hmac::Algorithm {if self == Suite::Aes256 {hmac::HMAC_SHA384} else {hmac::HMAC_SHA256}}

	fn digest(self) -> &'static digest::Algorithm {if self == Suite::Aes256 {&digest::SHA384} else {&digest::SHA256}}

	/// RFC 8446 section 5.5: AES-GCM is used for at most 2^24.5 records under a key, and nothing here sends a KeyUpdate, so a session ends well before that and a new one is made.
	fn records(self) -> u64 {if self == Suite::Chacha {1 << 60} else {1 << 24}}
}

/// The hash of the handshake messages so far.
#[derive(Clone)]
pub struct Transcript(digest::Context);

impl Transcript {
	pub fn new(suite: Suite) -> Transcript {Transcript(digest::Context::new(suite.digest()))}

	pub fn update(&mut self, message: &[u8]) {self.0.update(message)}

	pub fn hash(&self) -> Vec<u8> {self.0.clone().finish().as_ref().to_vec()}
}

struct Length(usize);

impl hkdf::KeyType for Length {
	fn len(&self) -> usize {self.0}
}

// HKDF-Expand-Label of RFC 8446 section 7.1. Every length here is a few dozen bytes, which HKDF can always give.
fn label(prk: &hkdf::Prk, label: &str, context: &[u8], size: usize) -> Vec<u8> {
	let mut out = vec![0; size];
	prk.expand(&[&(size as u16).to_be_bytes(), &[6 + label.len() as u8], b"tls13 ", label.as_bytes(), &[context.len() as u8], context], Length(size)).and_then(|okm| okm.fill(&mut out)).expect("an output of a few dozen bytes is within the limit of HKDF");
	out
}

/// HKDF-Expand-Label over a secret.
pub fn expand(suite: Suite, secret: &[u8], name: &str, context: &[u8], size: usize) -> Vec<u8> {label(&hkdf::Prk::new_less_safe(suite.hkdf(), secret), name, context, size)}

fn empty(suite: Suite) -> Vec<u8> {digest::digest(suite.digest(), &[]).as_ref().to_vec()}

/// The two traffic secrets of one extract of the key schedule, and the salt of the next extract.
pub struct Secrets {pub client: Vec<u8>, pub server: Vec<u8>, pub next: Vec<u8>}

impl Drop for Secrets {
	fn drop(&mut self) {
		self.client.zeroize();
		self.server.zeroize();
		self.next.zeroize();
	}
}

fn secrets(suite: Suite, salt: &[u8], input: &[u8], names: [&str; 2], hash: &[u8]) -> Secrets {
	let prk = hkdf::Salt::new(suite.hkdf(), salt).extract(input);
	Secrets {client: label(&prk, names[0], hash, suite.hash_len()), server: label(&prk, names[1], hash, suite.hash_len()), next: label(&prk, "derived", &empty(suite), suite.hash_len())}
}

/// The handshake traffic secrets from the key agreement `shared` and the hash of the transcript through the ServerHello. `next` is the salt of the master extract.
pub fn handshake_secrets(suite: Suite, shared: &[u8], hello_hash: &[u8]) -> Secrets {
	let zeros = vec![0; suite.hash_len()];
	let early = hkdf::Salt::new(suite.hkdf(), &zeros).extract(&zeros);
	secrets(suite, &label(&early, "derived", &empty(suite), suite.hash_len()), shared, ["c hs traffic", "s hs traffic"], hello_hash)
}

/// The application traffic secrets of the client and the server, from the salt `handshake_secrets` gave and the hash of the transcript through the server's Finished.
pub fn application_secrets(suite: Suite, salt: &[u8], hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
	let mut secrets = secrets(suite, salt, &vec![0; suite.hash_len()], ["c ap traffic", "s ap traffic"], hash);
	(std::mem::take(&mut secrets.client), std::mem::take(&mut secrets.server))
}

/// The verify data of a Finished message (RFC 8446 section 4.4.4) for a side's handshake traffic secret and the hash of the transcript before it.
pub fn finished(suite: Suite, secret: &[u8], hash: &[u8]) -> Vec<u8> {hmac::sign(&hmac::Key::new(suite.hmac(), &expand(suite, secret, "finished", &[], suite.hash_len())), hash).as_ref().to_vec()}

/// One direction of the record layer: the key and iv of a traffic secret, and the record number, which starts at 0 with every key.
pub struct Keys {key: aead::LessSafeKey, iv: [u8; 12], number: u64, limit: u64}

impl Drop for Keys {
	fn drop(&mut self) {self.iv.zeroize()}
}

impl Keys {
	pub fn new(suite: Suite, secret: &[u8]) -> Keys {
		let (mut key, mut iv) = (expand(suite, secret, "key", &[], suite.algorithm().key_len()), expand(suite, secret, "iv", &[], 12));
		let keys = Keys {key: aead::LessSafeKey::new(aead::UnboundKey::new(suite.algorithm(), &key).expect("the key has the length of its algorithm")), iv: std::array::from_fn(|at| iv[at]), number: 0, limit: suite.records()};
		key.zeroize();
		iv.zeroize();
		keys
	}

	/// The number of records sealed or opened under this key so far.
	pub fn number(&self) -> u64 {self.number}

	// RFC 8446 section 5.3: the iv xor the record number, as 64 bits big-endian padded on the left.
	fn nonce(&self) -> aead::Nonce {
		let mut nonce = self.iv;
		for (byte, counter) in nonce[4..].iter_mut().zip(self.number.to_be_bytes()) {*byte ^= counter}
		aead::Nonce::assume_unique_for_key(nonce)
	}

	/// Appends one record of content type `kind` holding `plaintext` and `pad` zero bytes of record padding after it (RFC 8446 section 5.4). False when the keys have sealed all they may or the record would not fit, and then nothing is appended.
	pub fn seal(&mut self, kind: u8, plaintext: &[u8], pad: usize, out: &mut Vec<u8>) -> bool {
		if self.number >= self.limit || plaintext.len() + pad > 16_384 {return false}
		let (start, length) = (out.len(), plaintext.len() + 1 + pad + TAG);
		out.extend_from_slice(&[23, 3, 3, (length >> 8) as u8, length as u8]);
		out.extend_from_slice(plaintext);
		out.push(kind);
		out.resize(out.len() + pad, 0);
		let (header, body) = out[start..].split_at_mut(HEADER);
		let Ok(tag) = self.key.seal_in_place_separate_tag(self.nonce(), aead::Aad::from(&*header), body) else {
			out.truncate(start);
			return false;
		};
		out.extend_from_slice(tag.as_ref());
		self.number += 1;
		true
	}

	/// Opens the body of a record whose header was `header`: the content type and the content, or None for a record that does not open or holds no content type.
	pub fn open<'a>(&mut self, header: &[u8; HEADER], body: &'a mut [u8]) -> Option<(u8, &'a [u8])> {
		if self.number >= self.limit {return None}
		let plain = &*self.key.open_in_place(self.nonce(), aead::Aad::from(&header[..]), body).ok()?;
		self.number += 1;
		let end = plain.iter().rposition(|byte| *byte != 0)?;
		Some((plain[end], &plain[..end]))
	}
}

/// Bytes of a message, read from the front. Every read is checked, and a read past the end is `None`.
pub struct Cursor<'a>(pub &'a [u8]);

impl<'a> Cursor<'a> {
	pub fn take(&mut self, count: usize) -> Option<&'a [u8]> {
		let (head, tail) = self.0.split_at_checked(count)?;
		self.0 = tail;
		Some(head)
	}

	/// A big-endian integer of `width` bytes.
	pub fn uint(&mut self, width: usize) -> Option<usize> {self.take(width).map(|bytes| bytes.iter().fold(0, |sum, byte| sum << 8 | usize::from(*byte)))}

	/// The bytes behind a length of `width` bytes.
	pub fn var(&mut self, width: usize) -> Option<&'a [u8]> {
		let count = self.uint(width)?;
		self.take(count)
	}
}

/// What a ServerHello says: the suite, the group with its key exchange bytes, and whether `key_share` comes before `supported_versions`, which is the order the site chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello<'a> {pub suite: Suite, pub group: u16, pub key: &'a [u8], pub key_first: bool, pub random: &'a [u8]}

/// Reads a ServerHello message with its 4 byte header. It must echo `session`, hold nothing but `supported_versions` (TLS 1.3) and one `key_share` of X25519 or the hybrid group with the right length, name one of the three suites, and not be a HelloRetryRequest.
pub fn server_hello<'a>(message: &'a [u8], session: &[u8]) -> Option<ServerHello<'a>> {
	let mut outer = Cursor(message);
	let (kind, body) = (outer.uint(1)?, outer.var(3)?);
	if kind != 2 || !outer.0.is_empty() {return None}
	let mut hello = Cursor(body);
	let (version, random, echoed, id, compression) = (hello.uint(2)?, hello.take(32)?, hello.var(1)?, hello.uint(2)?, hello.uint(1)?);
	let mut extensions = Cursor(hello.var(2)?);
	if version != 0x0303 || random == HELLO_RETRY || echoed != session || compression != 0 || !hello.0.is_empty() {return None}
	let suite = Suite::from_id(id as u16)?;
	let (mut versions, mut share, mut key_first) = (false, None, false);
	while !extensions.0.is_empty() {
		let (kind, data) = (extensions.uint(2)?, extensions.var(2)?);
		match kind {
			43 if !versions && data == [3, 4] => versions = true,
			51 if share.is_none() => {
				key_first = !versions;
				let mut entry = Cursor(data);
				let (group, key) = (entry.uint(2)? as u16, entry.var(2)?);
				if !entry.0.is_empty() || key.len() != if group == X25519 {32} else if group == HYBRID {KEM_CIPHERTEXT + 32} else {return None} {return None}
				share = Some((group, key));
			}
			_ => return None,
		}
	}
	share.filter(|_| versions).map(|(group, key)| ServerHello {suite, group, key, key_first, random})
}

/// Writes a ServerHello message with its 4 byte header, in the extension order `key_first` says.
pub fn write_server_hello(session: &[u8], suite: Suite, group: u16, key_first: bool, random: &[u8; 32], key: &[u8]) -> Vec<u8> {
	let versions = [&[0, 43, 0, 2][..], &[3, 4]].concat();
	let share = [&[0, 51][..], &(key.len() as u16 + 4).to_be_bytes(), &group.to_be_bytes(), &(key.len() as u16).to_be_bytes(), key].concat();
	let extensions = if key_first {[share, versions].concat()} else {[versions, share].concat()};
	let body = [&[3, 3][..], random, &[session.len() as u8], session, &suite.id().to_be_bytes(), &[0], &(extensions.len() as u16).to_be_bytes(), &extensions].concat();
	[&[2, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8][..], &body].concat()
}

/// A fresh `random` for a ServerHello.
pub fn server_random(random: &mut Random) -> Result<[u8; 32], NoRandom> {
	let mut bytes = [0; 32];
	random(&mut bytes)?;
	Ok(bytes)
}

#[cfg(test)]
mod tests {
	use super::*;

	// RFC 8448 section 3, "Simple 1-RTT Handshake": the hashes and secrets of the trace for TLS_AES_128_GCM_SHA256 with X25519.
	fn hex(text: &str) -> Vec<u8> {text.split_whitespace().collect::<String>().as_bytes().chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()}

	#[test]
	fn the_key_schedule_follows_rfc_8448() {
		let shared = hex("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");
		let hello_hash = hex("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
		let secrets = handshake_secrets(Suite::Aes128, &shared, &hello_hash);
		assert_eq!(secrets.client, hex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"));
		assert_eq!(secrets.server, hex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"));
		let keys = expand(Suite::Aes128, &secrets.server, "key", &[], 16);
		assert_eq!(keys, hex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"));
		assert_eq!(expand(Suite::Aes128, &secrets.server, "iv", &[], 12), hex("5d 31 3e b2 67 12 76 ee 13 00 0b 30"));
		// The client's keys, the salt of the master extract, the finished key, and the Finished of both sides over the hashes of the trace; then the application secrets.
		assert_eq!(expand(Suite::Aes128, &secrets.client, "key", &[], 16), hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01"));
		assert_eq!(expand(Suite::Aes128, &secrets.client, "iv", &[], 12), hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f"));
		assert_eq!(secrets.next, hex("43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4"));
		assert_eq!(expand(Suite::Aes128, &secrets.server, "finished", &[], 32), hex("00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8"));
		let through_verify = hex("ed b7 72 5f a7 a3 47 3b 03 1e c8 ef 65 a2 48 54 93 90 01 38 a2 b9 12 91 40 7d 79 51 a0 61 10 ed");
		assert_eq!(finished(Suite::Aes128, &secrets.server, &through_verify), hex("9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18"));
		let through_finished = hex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
		assert_eq!(finished(Suite::Aes128, &secrets.client, &through_finished), hex("a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61"));
		let (client, server) = application_secrets(Suite::Aes128, &secrets.next, &through_finished);
		assert_eq!(client, hex("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5"));
		assert_eq!(server, hex("a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43"));
	}

	#[test]
	fn a_record_opens_under_the_other_sides_keys_with_its_padding_and_nothing_else_does() {
		for suite in [Suite::Aes128, Suite::Aes256, Suite::Chacha] {
			let secret = vec![7; suite.hash_len()];
			let (mut seal, mut open) = (Keys::new(suite, &secret), Keys::new(suite, &secret));
			let mut out = Vec::new();
			assert!(seal.seal(22, b"hello", 9, &mut out));
			assert_eq!(out.len(), HEADER + 5 + 1 + 9 + TAG);
			assert_eq!(out[3..5], ((5 + 1 + 9 + TAG) as u16).to_be_bytes());
			let header: [u8; HEADER] = std::array::from_fn(|at| out[at]);
			let mut body = out[HEADER..].to_vec();
			assert_eq!(open.open(&header, &mut body), Some((22, &b"hello"[..])));
			let mut again = out[HEADER..].to_vec();
			assert_eq!(open.open(&header, &mut again), None);
			assert!(!seal.seal(23, &[0; 16_384], 1, &mut out));
		}
	}

	#[test]
	fn a_server_hello_is_read_in_both_orders_and_the_odd_ones_are_refused() {
		let (session, random) = ([5u8; 32], [9u8; 32]);
		for (group, key) in [(X25519, vec![1u8; 32]), (HYBRID, vec![2u8; KEM_CIPHERTEXT + 32])] {
			for key_first in [false, true] {
				let message = write_server_hello(&session, Suite::Aes256, group, key_first, &random, &key);
				let read = server_hello(&message, &session).unwrap();
				assert_eq!((read.suite, read.group, read.key, read.key_first, read.random), (Suite::Aes256, group, &key[..], key_first, &random[..]));
				assert!(server_hello(&message, &[6; 32]).is_none());
				assert!(server_hello(&message[..message.len() - 1], &session).is_none());
			}
		}
		assert!(server_hello(&write_server_hello(&session, Suite::Aes128, 0x0017, false, &random, &[1; 65]), &session).is_none());
		assert!(server_hello(&write_server_hello(&session, Suite::Aes128, X25519, false, &HELLO_RETRY, &[1; 32]), &session).is_none());
	}
}
