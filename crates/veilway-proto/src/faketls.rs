//! The borrowed-site mode, `faketls` (borrowed-site page, "The proof" and "Verifying"): the proof a client carries in the random and the legacy session id of its ClientHello, how a node opens it, and the P-256 key of the node's leaf.
//!
//! ```text
//! carrier = AEAD-Seal(k_seal, plaintext, nonce 0, aad = "veilway v1 faketls aad" || hello with the carrier zeroed)
//! plaintext = 0x01 || 0 0 0 || timestamp (8) || hour tag (16) || binder (16) || 0 0 0 0
//! binder = HMAC-SHA-256(k_bind, b || plaintext[0..28])[0..16], with b = HKDF-Expand(prk_f, "veilway v1 faketls binder" || X)
//! ```
//!
//! `Node::open` is steps 1 to 6 of "Verifying". A hello that is not a proof gets `Outcome::Stranger`, and one whose carrier opens but fails a later check gets `Outcome::Refused`: both are answered alike on the wire, and nothing here tells the caller which step failed. `Opened::accept` is steps 7 to 9. `Client::carry` seals the carrier of a hello the caller has built with the X25519 share `X` of a fresh key `x`.
use crate::{keys::{Borrowed, BinderKey, Device, TagKey, Tags, FAKETLS_AAD}, replay::{Decision, Kind, Replay, Verdict}, NoRandom, Random};
use p256::elliptic_curve::{bigint::{Encoding, NonZero, U384}, sec1::ToEncodedPoint, PrimeField};
use ring::aead;
use std::collections::VecDeque;
use subtle::ConstantTimeEq;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

pub const VERSION: u8 = 1;
/// The length of one hour, in seconds: the tags of a hello change with it.
pub const HOUR: u64 = 3600;
/// How many seals a client remembers, so that it never seals with the same `X` twice.
pub const SEALS: usize = 4096;
// The offsets of the two fields of the carrier in a ClientHello handshake message: the header (4) and `legacy_version` (2) come before `random`, and `legacy_session_id` has its length at 38 and its 32 bytes from 39.
const RANDOM: usize = 6;
const SESSION: usize = 39;
const CARRIER: usize = 64;
const PLAIN: usize = 48;
// What the key agreement is run on when a hello has no share, so that a hello that is no proof costs the node the same work.
const DUMMY_SHARE: [u8; 32] = [9; 32];
// The order of the P-256 group.
const ORDER: [u8; 32] = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51];

/// What the node reads of a ClientHello: the server name it asks for, whether it offers TLS 1.3, and the offset of `X` in the message (the standalone X25519 share when there is one, else the X25519 part of the hybrid share).
#[derive(Debug, PartialEq, Eq)]
pub struct Parsed<'a> {
	pub name: &'a [u8],
	pub tls13: bool,
	pub share: usize,
	/// The offset of the X25519 part of the hybrid share, when the hello has one.
	pub hybrid: Option<usize>,
}

fn be16(bytes: &[u8], at: usize) -> Option<usize> {Some(usize::from(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?])))}

// The first `host_name` of a server_name extension, which is the only one a hello may carry.
fn host_name(body: &[u8]) -> Option<&[u8]> {
	let list = body.get(2..)?;
	if be16(body, 0)? != list.len() {return None}
	let (mut at, mut found) = (0, None);
	while at < list.len() {
		let (kind, size) = (*list.get(at)?, be16(list, at + 1)?);
		let name = list.get(at + 3..at + 3 + size)?;
		if kind == 0 {found = found.or(Some(name))}
		at += 3 + size;
	}
	found
}

fn offers_tls13(body: &[u8]) -> Option<bool> {
	let (count, list) = body.split_first()?;
	(usize::from(*count) == list.len() && list.len() % 2 == 0).then(|| list.chunks(2).any(|pair| pair == [3, 4]))
}

// The offsets in a key_share extension whose body starts at `start` in the message: of the standalone X25519 value, and of the X25519 part after the 1,184 bytes of the ML-KEM-768 key of the hybrid group.
fn key_share(body: &[u8], start: usize) -> Option<(Option<usize>, Option<usize>)> {
	let list = body.get(2..)?;
	if be16(body, 0)? != list.len() {return None}
	let (mut at, mut standalone, mut hybrid) = (0, None, None);
	while at < list.len() {
		let (group, size) = (be16(list, at)?, be16(list, at + 2)?);
		let value = at + 4;
		if value + size > list.len() {return None}
		match (group, size) {
			(0x001d, 32) => standalone = standalone.or(Some(start + 2 + value)),
			(0x11ec, 1216) => hybrid = hybrid.or(Some(start + 2 + value + 1184)),
			_ => {}
		}
		at = value + size;
	}
	Some((standalone, hybrid))
}

/// Reads a ClientHello handshake message, with its 4 byte header. Nothing is read past the end of the message, and a message that is not exactly one ClientHello, or that lacks a server name, a TLS 1.3 offer or a share `X`, is `None`.
pub fn parse(message: &[u8]) -> Option<Parsed<'_>> {
	let length = message.get(1..4).map(|size| usize::from(size[0]) << 16 | usize::from(size[1]) << 8 | usize::from(size[2]))?;
	if message.first() != Some(&1) || message.len() != 4 + length || message.get(38) != Some(&32) {return None}
	let mut at = 71 + 2 + be16(message, 71)?;
	at += 1 + usize::from(*message.get(at)?);
	let end = at + 2 + be16(message, at)?;
	if end != message.len() {return None}
	at += 2;
	let (mut name, mut tls13, mut share) = (None, false, None::<(Option<usize>, Option<usize>)>);
	while at < end {
		let (kind, size, start) = (be16(message, at)?, be16(message, at + 2)?, at + 4);
		let body = message.get(start..start + size)?;
		match kind {
			0 => name = name.or(Some(host_name(body)?)),
			43 => tls13 |= offers_tls13(body)?,
			51 => share = share.or(Some(key_share(body, start)?)),
			_ => {}
		}
		at = start + size;
	}
	let (standalone, hybrid) = share?;
	Some(Parsed {name: name?, tls13, share: standalone.or(hybrid)?, hybrid})
}

// The 64 bytes of the carrier: `random`, then the legacy session id. Only called on a message that `parse` has read.
fn carrier(message: &[u8]) -> [u8; CARRIER] {std::array::from_fn(|index| if index < 32 {message[RANDOM + index]} else {message[SESSION + index - 32]})}

// The associated data of the carrier: the hello with its carrier zeroed, behind the label.
fn scrubbed(message: &[u8]) -> Vec<u8> {
	let mut hello = [FAKETLS_AAD, message].concat();
	let at = FAKETLS_AAD.len();
	hello[at + RANDOM..at + RANDOM + 32].fill(0);
	hello[at + SESSION..at + SESSION + 32].fill(0);
	hello
}

/// The hour of a Unix time: "the number of the hour (Unix time divided by 3,600, rounded down)".
pub fn hour(now: u64) -> u64 {now / HOUR}

/// The DER of a P-256 private key with its public point, in the PKCS#8 form `ring` reads (the outer length, the version, the algorithm, the SEC1 key with its public point in `[1]`).
fn pkcs8(scalar: &[u8], public: &[u8]) -> Vec<u8> {[&[0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20][..], scalar, &[0xa1, 0x44, 0x03, 0x42, 0x00][..], public].concat()}

/// The node's leaf key for `seed` (borrowed-site page, "The throwaway leaf"): `d = (c mod (n - 1)) + 1`, with `c` the seed as a big-endian integer and `n` the group order. Returns the key as PKCS#8 and its public point in the uncompressed form. A seed drawn at random gives a key that matches nothing the client computes.
pub fn leaf_key(seed: &[u8; 40]) -> Option<(Vec<u8>, Vec<u8>)> {
	let (mut wide, mut order) = ([0u8; 48], [0u8; 48]);
	wide[8..].copy_from_slice(seed);
	order[16..].copy_from_slice(&ORDER);
	let modulus = NonZero::new(U384::from_be_slice(&order).wrapping_sub(&U384::ONE)).into_option()?;
	let scalar: [u8; 32] = U384::from_be_slice(&wide).rem(&modulus).wrapping_add(&U384::ONE).to_be_bytes()[16..].try_into().ok()?;
	let secret = p256::Scalar::from_repr(scalar.into()).into_option()?;
	let public = (p256::ProjectivePoint::GENERATOR * secret).to_affine().to_encoded_point(false).as_bytes().to_vec();
	Some((pkcs8(&scalar, &public), public))
}

/// What the node makes of a complete ClientHello.
#[derive(Debug)]
pub enum Outcome<'a, T> {
	/// Not a proof: the connection is relayed to the site, byte for byte.
	Stranger,
	/// The carrier opened, and a check of steps 4 to 6 refused it. The node answers with a flight whose leaf is random and opens no session.
	Refused,
	/// Steps 1 to 6 hold. `accept` takes it on to the replay rule and the limits.
	Proved(Opened<'a, T>),
}

/// A proof that passed steps 1 to 6: a device's hello, not yet recorded. Its `share` is the key of the proof in the replay cache, and `seed` makes the leaf the node answers with.
#[derive(Debug)]
pub struct Opened<'a, T> {
	pub device: &'a Device<T>,
	pub timestamp: u64,
	pub share: [u8; 32],
	pub seed: [u8; 40],
}

impl<'a, T> Opened<'a, T> {
	/// Steps 7 to 9 of "Verifying" at the wall clock `now`: the replay rule, then `charge`, the device's and the source's rate limits and its pending sessions, which is called only when the rule would accept. The proof is recorded when the rule says so.
	pub fn accept(self, replay: &mut Replay, now: u64, charge: impl FnOnce(&'a Device<T>) -> bool) -> Decision<Self, Self> {
		match replay.accept(Kind::Stream, &self.share, self.timestamp, now, || charge(self.device)) {
			Verdict::Accept => Decision::Accepted(self),
			Verdict::Raise(limit) => Decision::Raise(limit, self),
			Verdict::Refuse(refusal) => Decision::Refused(refusal),
		}
	}
}

/// What a node holds for `faketls`: the private key `T` of the transport, the inbound's public key, and a dummy binder key that a tag the table does not hold is checked with.
pub struct Node {secret: [u8; 32], public: [u8; 32], inbound: [u8; 32], dummy: BinderKey}

impl Node {
	/// `secret` is `T_priv`, the transport's private key, and `inbound` the inbound's WireGuard public key. The dummy key is drawn from `random`, and nobody else holds it.
	pub fn new(secret: [u8; 32], inbound: [u8; 32], random: &mut Random) -> Result<Self, NoRandom> {
		let (mut dummy, mut device) = ([0; 32], [0; 32]);
		random(&mut dummy).and_then(|()| random(&mut device))?;
		Ok(Self {secret, public: x25519(secret, X25519_BASEPOINT_BYTES), inbound, dummy: BinderKey::derive(&dummy, &inbound, &device)})
	}
	/// Steps 1 to 6 of "Verifying" for a complete ClientHello `message`. `names` are the site's names a hello may ask for. The tags are looked up as hour tags only.
	/// "Steps 1 to 6 are done for every complete hello with dummy inputs where a field is missing, and their results are combined at the end": a hello that is no proof costs the same X25519, the same AEAD open, and the same lookup and binder as one that is.
	pub fn open<'a, T>(&self, message: &[u8], names: &[&[u8]], tags: &'a impl Tags<T>) -> Outcome<'a, T> {
		let parsed = parse(message);
		let named = parsed.as_ref().is_some_and(|parsed| parsed.tls13 && names.contains(&parsed.name));
		let share: [u8; 32] = parsed.as_ref().and_then(|parsed| message.get(parsed.share..parsed.share + 32)).and_then(|bytes| bytes.try_into().ok()).unwrap_or(DUMMY_SHARE);
		// A share of low order gives the all-zero result, which no sealer can have made a key of.
		let (dh, sealed) = (x25519(self.secret, share), if parsed.is_some() {carrier(message)} else {[0; CARRIER]});
		let (borrowed, mut buf) = (Borrowed::new(&dh), sealed);
		let aad = if parsed.is_some() {scrubbed(message)} else {FAKETLS_AAD.to_vec()};
		let opened = borrowed.seal(&share, &self.public, &self.inbound).0.open_in_place(aead::Nonce::assume_unique_for_key([0; 12]), aead::Aad::from(&aad[..]), &mut buf).is_ok();
		let plain: [u8; PLAIN] = if opened {std::array::from_fn(|index| buf[index])} else {[0; PLAIN]};
		let version = plain[0] ^ VERSION;
		let zeros = plain[1..4].iter().chain(&plain[44..PLAIN]).fold(version, |all, byte| all | byte);
		let timestamp = u64::from_be_bytes(std::array::from_fn(|index| plain[4 + index]));
		let device = tags.find_hour(&std::array::from_fn(|index| plain[12 + index]));
		let binder = device.map_or(&self.dummy, |device| &device.binder);
		let mac = binder.short(&[&borrowed.binder(&share), &plain[..28]]);
		let bound: bool = mac[..].ct_eq(&plain[28..44]).into();
		if !(named && opened && dh != [0; 32]) {return Outcome::Stranger}
		match device.filter(|_| zeros == 0 && bound) {
			Some(device) => Outcome::Proved(Opened {device, timestamp, share, seed: borrowed.node_seed(&share, &sealed)}),
			None => Outcome::Refused,
		}
	}
}

/// Why `Client::carry` refused a hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarryError {
	/// The hello's share is not `X25519(x)`, or the node's key gives an all-zero result.
	Hello,
	/// `X` is one of the last `SEALS` seals: a fresh `x` is drawn for every hello.
	Reused,
}

/// The client's side: the node's transport public key, the inbound's key, and the device's `k_tag` and `k_bind`.
pub struct Client {node: [u8; 32], inbound: [u8; 32], tag: TagKey, binder: BinderKey, seals: VecDeque<[u8; 32]>}

impl Client {
	pub fn new(node: &[u8; 32], secret: &[u8; 32], inbound: &[u8; 32], device: &[u8; 32]) -> Self {Self {node: *node, inbound: *inbound, tag: TagKey::derive(secret, inbound), binder: BinderKey::derive(secret, inbound, device), seals: VecDeque::new()}}
	/// Seals the carrier of `message`, a ClientHello whose standalone X25519 share is `X25519(x)`, and writes it into `random` and the legacy session id. `timestamp` is the client's clock in Unix seconds.
	pub fn carry(&mut self, message: &mut [u8], x: &[u8; 32], timestamp: u64) -> Result<(), CarryError> {self.carry_with(message, x, timestamp, |_| {})}
	// The plaintext before its binder is made, so that a test can put a field the node must refuse into it.
	fn carry_with(&mut self, message: &mut [u8], x: &[u8; 32], timestamp: u64, tamper: impl FnOnce(&mut [u8; PLAIN])) -> Result<(), CarryError> {
		let parsed = parse(message).ok_or(CarryError::Hello)?;
		let share = x25519(*x, X25519_BASEPOINT_BYTES);
		if message.get(parsed.share..parsed.share + 32) != Some(&share[..]) {return Err(CarryError::Hello)}
		if self.seals.contains(&share) {return Err(CarryError::Reused)}
		let dh = x25519(*x, self.node);
		if dh == [0; 32] {return Err(CarryError::Hello)}
		let borrowed = Borrowed::new(&dh);
		let mut plain = [0; PLAIN];
		plain[0] = VERSION;
		plain[4..12].copy_from_slice(&timestamp.to_be_bytes());
		plain[12..28].copy_from_slice(&self.tag.hour_tag(hour(timestamp)));
		tamper(&mut plain);
		let mac = self.binder.short(&[&borrowed.binder(&share), &plain[..28]]);
		plain[28..44].copy_from_slice(&mac);
		let mut sealed = [0; CARRIER];
		sealed[..PLAIN].copy_from_slice(&plain);
		let tag = borrowed.seal(&share, &self.node, &self.inbound).0.seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key([0; 12]), aead::Aad::from(&scrubbed(message)[..]), &mut sealed[..PLAIN]).map_err(|_| CarryError::Hello)?;
		sealed[PLAIN..].copy_from_slice(tag.as_ref());
		message[RANDOM..RANDOM + 32].copy_from_slice(&sealed[..32]);
		message[SESSION..SESSION + 32].copy_from_slice(&sealed[32..]);
		self.seals.push_front(share);
		self.seals.truncate(SEALS);
		Ok(())
	}
	/// The public point of the node's leaf for a hello that `carry` sealed with `x`, in the uncompressed form. The client checks the leaf's key against it, and against nothing else.
	pub fn leaf(&self, x: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
		parse(message)?;
		let dh = x25519(*x, self.node);
		leaf_key(&Borrowed::new(&dh).node_seed(&x25519(*x, X25519_BASEPOINT_BYTES), &carrier(message))).map(|(_, public)| public)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::keys::Table;
	use crate::replay::{Refusal, Started};
	use ring::rand::SystemRandom;
	use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

	const SITE: &[u8] = b"site.example";
	const INBOUND: [u8; 32] = [0x21; 32];
	const DEVICE: [u8; 32] = [0x41; 32];
	const SECRET: [u8; 32] = [0x11; 32];
	const NODE: [u8; 32] = [0x61; 32];
	const NOW: u64 = 1_700_000_000;

	fn ext(kind: u16, body: &[u8]) -> Vec<u8> {[&kind.to_be_bytes()[..], &(body.len() as u16).to_be_bytes(), body].concat()}

	// A ClientHello with the fields the node reads: `versions` are the bytes of the supported_versions list, and `share` and `hybrid` the key shares. The random and the session id are zeros until a client seals them.
	fn hello_with(name: &[u8], versions: &[u8], share: Option<&[u8; 32]>, hybrid: Option<&[u8; 32]>) -> Vec<u8> {
		let mut name_list = vec![0];
		name_list.extend_from_slice(&(name.len() as u16).to_be_bytes());
		name_list.extend_from_slice(name);
		let mut keys = Vec::new();
		if let Some(share) = share {keys.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]); keys.extend_from_slice(share)}
		if let Some(hybrid) = hybrid {keys.extend_from_slice(&[0x11, 0xec, 0x04, 0xc0]); keys.extend_from_slice(&[0x77; 1184]); keys.extend_from_slice(hybrid)}
		let extensions = [ext(0, &[&(name_list.len() as u16).to_be_bytes()[..], &name_list].concat()), ext(43, &[&[versions.len() as u8][..], versions].concat()), ext(51, &[&(keys.len() as u16).to_be_bytes()[..], &keys].concat()), ext(10, &[0, 2, 0, 0x1d])].concat();
		let mut body = vec![3, 3];
		body.extend_from_slice(&[0x05; 32]);
		body.push(32);
		body.extend_from_slice(&[0x00; 32]);
		body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
		body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
		body.extend_from_slice(&extensions);
		[&[1, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8][..], &body].concat()
	}

	fn hello(x: &[u8; 32]) -> Vec<u8> {hello_with(SITE, &[3, 4], Some(&x25519(*x, X25519_BASEPOINT_BYTES)), None)}

	fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
		bytes.iter_mut().enumerate().for_each(|(index, byte)| *byte = index as u8 ^ 0x5a);
		Ok(())
	}

	fn node() -> Node {Node::new(NODE, INBOUND, &mut random).unwrap()}

	fn client(secret: &[u8; 32], device: &[u8; 32]) -> Client {Client::new(&x25519(NODE, X25519_BASEPOINT_BYTES), secret, &INBOUND, device)}

	// The node's table of one device: its hour tags for the hour before, the hour of `now` and the hour after.
	fn table(now: u64) -> Table<Device<u32>> {
		let mut table = Table::new();
		let tags = TagKey::derive(&SECRET, &INBOUND);
		for at in [hour(now) - 1, hour(now), hour(now) + 1] {assert!(table.hour(tags.hour_tag(at), Device::derive(7, &SECRET, &INBOUND, &DEVICE)))}
		table
	}

	// A memory that started at `now - 100` with no file, and whose limit is raised to `now + 20`, so that a proof at `now` is inside it.
	fn memory(now: u64) -> Replay {
		let Started::NoFile(pending) = Replay::start(None, now - 100, 16) else {panic!("a start without a file")};
		let mut replay = pending.written();
		assert!(replay.raise(now + 20).is_some());
		replay.written();
		replay
	}

	fn sealed(x: [u8; 32], now: u64) -> Vec<u8> {
		let mut message = hello(&x);
		client(&SECRET, &DEVICE).carry(&mut message, &x, now).unwrap();
		message
	}

	#[test]
	fn a_proof_opens_and_its_leaf_is_the_clients_own() {
		let (x, table, mut replay) = ([0x31; 32], table(NOW), memory(NOW));
		let message = sealed(x, NOW);
		let Outcome::Proved(opened) = node().open(&message, &[SITE], &table) else {panic!("a proof of a device did not open")};
		assert_eq!((opened.timestamp, opened.share, opened.device.id), (NOW, x25519(x, X25519_BASEPOINT_BYTES), 7));
		assert_eq!(client(&SECRET, &DEVICE).leaf(&x, &message), leaf_key(&opened.seed).map(|(_, public)| public));
		assert!(matches!(opened.accept(&mut replay, NOW, |_| true), Decision::Accepted(_)));
	}

	#[test]
	fn the_leaf_key_is_one_ring_reads_with_the_point_it_was_made_with() {
		let (key, public) = leaf_key(&[0x9c; 40]).unwrap();
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key, &SystemRandom::new()).unwrap();
		assert_eq!(pair.public_key().as_ref(), &public[..]);
		assert_eq!(public.len(), 65);
	}

	#[test]
	fn a_hello_that_is_not_a_proof_is_a_stranger() {
		let (x, table, node) = ([0x31; 32], table(NOW), node());
		let message = sealed(x, NOW);
		let mut flipped = message.clone();
		flipped[73] ^= 1;
		let mut carrier_bit = message.clone();
		carrier_bit[RANDOM + 3] ^= 0x80;
		let mut session_bit = message.clone();
		session_bit[SESSION + 31] ^= 0x01;
		let other = sealed([0x32; 32], NOW);
		let mut pasted = message.clone();
		pasted[RANDOM..RANDOM + 32].copy_from_slice(&other[RANDOM..RANDOM + 32]);
		pasted[SESSION..SESSION + 32].copy_from_slice(&other[SESSION..SESSION + 32]);
		let other_node = Node::new([0x62; 32], INBOUND, &mut random).unwrap();
		for bad in [&flipped, &carrier_bit, &session_bit, &pasted] {assert!(matches!(node.open(bad, &[SITE], &table), Outcome::Stranger))}
		assert!(matches!(other_node.open(&message, &[SITE], &table), Outcome::Stranger));
		assert!(matches!(node.open(&message, &[b"other.example"], &table), Outcome::Stranger));
		assert!(matches!(node.open(&hello_with(SITE, &[3, 3], Some(&x25519(x, X25519_BASEPOINT_BYTES)), None), &[SITE], &table), Outcome::Stranger));
		assert!(matches!(node.open(&message[..message.len() - 1], &[SITE], &table), Outcome::Stranger));
		assert!(matches!(node.open(&hello_with(SITE, &[3, 4], Some(&[0; 32]), None), &[SITE], &table), Outcome::Stranger));
	}

	#[test]
	fn a_carrier_that_opens_but_fails_a_later_check_is_refused_not_relayed() {
		let (x, node, table) = ([0x31; 32], node(), table(NOW));
		let mut late = hello(&x);
		client(&SECRET, &DEVICE).carry(&mut late, &x, NOW + 2 * HOUR).unwrap();
		assert!(matches!(node.open(&late, &[SITE], &table), Outcome::Refused));
		let mut device_tag = hello(&[0x33; 32]);
		client(&SECRET, &DEVICE).carry(&mut device_tag, &[0x33; 32], NOW).unwrap();
		let mut device_only = Table::new();
		assert!(device_only.device(TagKey::derive(&SECRET, &INBOUND).device_tag(), Device::derive(7, &SECRET, &INBOUND, &DEVICE)));
		assert!(matches!(node.open(&device_tag, &[SITE], &device_only), Outcome::Refused));
		let mut other_secret = hello(&x);
		client(&[0x12; 32], &DEVICE).carry(&mut other_secret, &x, NOW).unwrap();
		assert!(matches!(node.open(&other_secret, &[SITE], &table), Outcome::Refused));
		let mut other_device = hello(&x);
		client(&SECRET, &[0x42; 32]).carry(&mut other_device, &x, NOW).unwrap();
		assert!(matches!(node.open(&other_device, &[SITE], &table), Outcome::Refused));
	}

	#[test]
	fn a_wrong_version_or_reserved_byte_is_refused() {
		let (x, node, table) = ([0x31; 32], node(), table(NOW));
		let mut version = hello(&x);
		client(&SECRET, &DEVICE).carry_with(&mut version, &x, NOW, |plain| plain[0] = 2).unwrap();
		assert!(matches!(node.open(&version, &[SITE], &table), Outcome::Refused));
		let mut reserved = hello(&x);
		client(&SECRET, &DEVICE).carry_with(&mut reserved, &x, NOW, |plain| plain[2] = 1).unwrap();
		assert!(matches!(node.open(&reserved, &[SITE], &table), Outcome::Refused));
		let mut padding = hello(&x);
		client(&SECRET, &DEVICE).carry_with(&mut padding, &x, NOW, |plain| plain[47] = 1).unwrap();
		assert!(matches!(node.open(&padding, &[SITE], &table), Outcome::Refused));
	}

	#[test]
	fn a_proof_is_recorded_once_and_a_refused_one_is_not_recorded() {
		let (x, table, mut replay) = ([0x31; 32], table(NOW), memory(NOW));
		let message = sealed(x, NOW);
		let Outcome::Proved(first) = node().open(&message, &[SITE], &table) else {panic!("no proof")};
		assert!(matches!(first.accept(&mut replay, NOW, |_| true), Decision::Accepted(_)));
		let Outcome::Proved(again) = node().open(&message, &[SITE], &table) else {panic!("no proof")};
		assert!(matches!(again.accept(&mut replay, NOW, |_| true), Decision::Refused(Refusal::Seen)));
		let other = sealed([0x32; 32], NOW);
		let Outcome::Proved(limited) = node().open(&other, &[SITE], &table) else {panic!("no proof")};
		assert!(matches!(limited.accept(&mut replay, NOW, |_| false), Decision::Refused(Refusal::Limited)));
		let Outcome::Proved(retried) = node().open(&other, &[SITE], &table) else {panic!("no proof")};
		assert!(matches!(retried.accept(&mut replay, NOW, |_| true), Decision::Accepted(_)));
	}

	#[test]
	fn a_proof_outside_the_window_is_refused_by_the_rule() {
		let (x, mut replay) = ([0x31; 32], memory(NOW));
		let message = sealed(x, NOW - 3 * HOUR);
		let past = table(NOW - 3 * HOUR);
		let Outcome::Proved(opened) = node().open(&message, &[SITE], &past) else {panic!("no proof")};
		assert!(matches!(opened.accept(&mut replay, NOW, |_| true), Decision::Refused(Refusal::Window)));
	}

	#[test]
	fn a_client_never_seals_the_same_share_twice() {
		let x = [0x31; 32];
		let mut sealer = client(&SECRET, &DEVICE);
		let mut first = hello(&x);
		let mut second = hello(&x);
		sealer.carry(&mut first, &x, NOW).unwrap();
		assert_eq!(sealer.carry(&mut second, &x, NOW), Err(CarryError::Reused));
		assert_eq!(sealer.carry(&mut hello(&[0x44; 32]), &x, NOW), Err(CarryError::Hello));
	}

	#[test]
	fn the_hybrid_share_is_read_at_its_x25519_part_when_no_standalone_share_is_there() {
		let hybrid = [0x55; 32];
		let message = hello_with(SITE, &[3, 4], None, Some(&hybrid));
		let parsed = parse(&message).unwrap();
		assert_eq!(&message[parsed.share..parsed.share + 32], &hybrid[..]);
		assert!(parse(&hello_with(SITE, &[3, 4], None, None)).is_none());
	}

	#[test]
	fn the_standalone_share_wins_over_the_hybrid_one() {
		let (share, hybrid) = ([0x66; 32], [0x77; 32]);
		let message = hello_with(SITE, &[3, 4], Some(&share), Some(&hybrid));
		let parsed = parse(&message).unwrap();
		assert_eq!(&message[parsed.share..parsed.share + 32], &share[..]);
	}
	#[test]
	fn a_message_with_nothing_to_read_is_a_stranger_after_the_same_work_as_any_other() {
		let (table, node) = (table(NOW), node());
		for message in [vec![], vec![1, 0, 0, 0], vec![1; 70], vec![1; 71], vec![0xff; 4000]] {assert!(matches!(node.open(&message, &[SITE], &table), Outcome::Stranger))}
		// A hello whose carrier does not open takes the same path to the same answer as one with a name that is none.
		let message = sealed([0x31; 32], NOW);
		let mut flipped = message.clone();
		flipped[RANDOM + 1] ^= 1;
		assert!(matches!(node.open(&flipped, &[SITE], &table), Outcome::Stranger) && matches!(node.open(&message, &[b"other.example"], &table), Outcome::Stranger));
	}
}
