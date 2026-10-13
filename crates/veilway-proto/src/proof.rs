//! The stream proof of `tls`, `ws` and `fronted` (transports page, "The stream proof"): how a client makes the token of a request, and how a node opens one.
//!
//! ```text
//! token = base64url(enc || HPKE-Seal(hello)), in the request target as <path>?<token>
//! hello = 0x01 || 0 0 0 || timestamp (8) || device tag (16) || binder (32) || zero padding (0 to 96)
//! binder = HMAC-SHA-256(k_bind, export("veilway v1 binder", 32) || hello[0..28])
//! ```
//!
//! HPKE is RFC 9180 in base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20Poly1305, from the `hpke` crate and used as it is. Nothing of it is written here.
//!
//! `Node::open` is steps 1 to 4 of "Verifying": whether a token is a proof of a device. What it gives has no keys in it. `Opened::accept` is steps 5 to 7: it takes the proof through the replay rule and then through the listener's own limits, and only then gives the session keys out.
use crate::{keys::{BinderKey, ChunkKey, Device, TagKey, Tags, BINDER, C2S, FRONTED, PROOF, S2C, SID, TLS, WS}, replay::{Decision, Kind, Replay, Verdict}, uniform, Random, Refused};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hpke::{aead::{AeadTag, ChaCha20Poly1305}, inout::InOutBuf, kdf::HkdfSha256, kem::X25519HkdfSha256, rand_core::{TryCryptoRng, TryRng}, Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable};
use std::{convert::Infallible, fmt, ops::RangeInclusive};

type Private = <X25519HkdfSha256 as Kem>::PrivateKey;
type Public = <X25519HkdfSha256 as Kem>::PublicKey;
type Encapped = <X25519HkdfSha256 as Kem>::EncappedKey;

/// The one proof version this crate speaks. "A node treats any other version exactly as an invalid proof."
pub const VERSION: u8 = 1;
/// `enc`, the client's fresh public value.
pub const ENC: usize = 32;
/// The hello without its padding.
pub const HELLO: usize = 60;
/// "Hello padding: uniform 0 to 96 bytes."
pub const PADDING: RangeInclusive<u32> = 0..=96;
/// A token is `enc`, the hello and a 16 byte tag: "108 to 204 bytes".
pub const TOKEN: RangeInclusive<usize> = 108..=204;
/// The token as text: "base64url without padding, 144 to 272 characters".
pub const TEXT: RangeInclusive<usize> = 144..=272;
/// An inbound has at most this many node transport keys at once (overview, "Rotation"). A node tries a token against every one of them, always.
pub const KEYS: usize = 2;
// How many dummy keys a node holds, about 2 MiB of them, which cost about 20 ms to make at start. With one dummy, always in the processor's cache, a tag that is in the table took about 0.3 microseconds longer than one that is not, because the keys of a device come from a table of any size. With 1,024 dummies the difference measured about 0.2 microseconds, and with this many about 0.1.
const DUMMIES: u16 = 8192;
// The part of the hello the binder covers: "the version, the zero bytes, the timestamp and the device tag".
const HEAD: usize = 28;
const TAG: usize = 16;
// The u-coordinates for which X25519 gives zero for every private key: the points of small order, in each encoding of 255 bits. RFC 9180 makes HPKE stop at such an `enc`, before its key schedule, which would be less work than for any other token. A node therefore swaps such an `enc` for the base point, and refuses the token at the end.
const SMALL_ORDER: [[u8; 32]; 7] = [
	[0; 32],
	[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
	[0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
	[0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
	[0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
	[0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
	[0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
];
// The base point of X25519, which is not of small order.
const BASE: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// The transport a proof is made for. Its name is part of the HPKE `info`, "so a proof made for one transport is not valid on another".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {Tls = 0, Ws = 1, Fronted = 2}

impl Name {
	pub const ALL: [Self; 3] = [Self::Tls, Self::Ws, Self::Fronted];
	// `info` = `"veilway v1 proof" || name || inbound_pub` ("Inputs").
	fn info(self, inbound_pub: &[u8; 32]) -> Vec<u8> {[PROOF, [TLS, WS, FRONTED][self as usize], inbound_pub].concat()}
}

/// Why a proof was not made, or a node's keys were not taken. None of these is an answer to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
	/// The random source failed.
	Random,
	/// The node transport public key of the profile is one that no private key can answer. The profile is wrong.
	NodeKey,
	/// A node was given no transport key, or more than an inbound can have.
	Keys,
	/// The HPKE library refused a step that has no way to fail here.
	Crypto,
}

impl fmt::Display for ProofError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "stream proof: {self:?}")}
}

impl std::error::Error for ProofError {}

/// The keys both sides take from the HPKE exporter of one proof ("Session keys").
pub struct SessionKeys {
	/// `k_c2s`: chunks from client to node.
	pub c2s: ChunkKey,
	/// `k_s2c`: chunks from node to client.
	pub s2c: ChunkKey,
	/// `sid`: the session id on `fronted`.
	pub sid: [u8; 16],
}

impl fmt::Debug for SessionKeys {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("SessionKeys(..)")}
}

// `device_pub` is in every exporter context, so "both sides must agree on which WireGuard identity the session belongs to, or the first chunk does not decrypt".
fn session(export: impl Fn(&[u8], &mut [u8]) -> Result<(), HpkeError>, device_pub: &[u8; 32]) -> Result<SessionKeys, HpkeError> {
	#[cfg(test)]
	crate::trace::op("export session");
	let (mut c2s, mut s2c, mut sid) = ([0; 32], [0; 32], [0; 16]);
	export(&[C2S, device_pub].concat(), &mut c2s)?;
	export(&[S2C, device_pub].concat(), &mut s2c)?;
	export(&[SID, device_pub].concat(), &mut sid)?;
	Ok(SessionKeys {c2s: ChunkKey::new(&c2s), s2c: ChunkKey::new(&s2c), sid})
}

/// The public half of a node transport key, as a profile carries it.
pub fn public_key(transport_key: &[u8; 32]) -> [u8; 32] {
	let mut public = [0; 32];
	X25519HkdfSha256::sk_to_pk(&Private::from_bytes(transport_key).expect("an X25519 private key is 32 bytes")).write_exact(&mut public);
	public
}

// The caller's random source as the generator HPKE draws its ephemeral key from. That generator has no way to fail, so a failure is remembered here and the context it led to is thrown away.
struct Source<'a, 'b> {random: &'a mut Random<'b>, failed: bool}

impl TryRng for Source<'_, '_> {
	type Error = Infallible;
	fn try_next_u32(&mut self) -> Result<u32, Infallible> {
		let mut bytes = [0; 4];
		self.try_fill_bytes(&mut bytes)?;
		Ok(u32::from_le_bytes(bytes))
	}
	fn try_next_u64(&mut self) -> Result<u64, Infallible> {
		let mut bytes = [0; 8];
		self.try_fill_bytes(&mut bytes)?;
		Ok(u64::from_le_bytes(bytes))
	}
	fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
		if (self.random)(bytes).is_err() {
			bytes.fill(0);
			self.failed = true;
		}
		Ok(())
	}
}

impl TryCryptoRng for Source<'_, '_> {}

/// A token for one request, and the keys of the session it opens if the node accepts it.
#[derive(Debug)]
pub struct Proof {
	/// The query part of the request target: `<path>?<token>`.
	pub token: String,
	pub keys: SessionKeys,
}

/// What a device holds to make proofs for one inbound.
pub struct Client {node: Public, inbound_pub: [u8; 32], device_pub: [u8; 32], tag: [u8; 16], binder: BinderKey}

impl Client {
	/// `node_key` is the node transport public key of the profile, `secret` the device transport secret, the other two are WireGuard public keys.
	pub fn new(node_key: &[u8; 32], secret: &[u8; 32], inbound_pub: &[u8; 32], device_pub: &[u8; 32]) -> Self {Self {node: Public::from_bytes(node_key).expect("an X25519 public key is 32 bytes"), inbound_pub: *inbound_pub, device_pub: *device_pub, tag: TagKey::derive(secret, inbound_pub).device_tag(), binder: BinderKey::derive(secret, inbound_pub, device_pub)}}
	/// Makes the token of one request. `timestamp` is Unix time in seconds on the client's clock, with the offset from "Refusals and clocks" when one is held. Every call makes a new HPKE context: "The client creates a new HPKE context for every proof and never reuses one."
	pub fn prove(&self, name: Name, timestamp: u64, random: &mut Random) -> Result<Proof, ProofError> {
		let padding = uniform(*PADDING.start(), *PADDING.end(), random).map_err(|_| ProofError::Random)? as usize;
		let mut head = [0; HEAD];
		head[0] = VERSION;
		head[4..12].copy_from_slice(&timestamp.to_be_bytes());
		head[12..].copy_from_slice(&self.tag);
		self.seal(name, &head, None, &[0; *PADDING.end() as usize][..padding], random)
	}
	/// A token whose hello is whatever the caller says, with the binder a client would compute or with another, for fuzzing what a node does behind the HPKE check. Padding beyond 96 bytes is cut.
	#[cfg(fuzzing)]
	pub fn forge(&self, name: Name, head: &[u8; 28], binder: Option<&[u8; 32]>, padding: &[u8], random: &mut Random) -> Result<Proof, ProofError> {self.seal(name, head, binder, padding, random)}
	// Seals a hello of these 28 bytes, the binder over them unless another is given, and this padding.
	fn seal(&self, name: Name, head: &[u8; HEAD], binder: Option<&[u8; 32]>, padding: &[u8], random: &mut Random) -> Result<Proof, ProofError> {
		let (padding, mut source) = (&padding[..padding.len().min(*PADDING.end() as usize)], Source {random, failed: false});
		let sent = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeS::Base, &self.node, &name.info(&self.inbound_pub), &mut source);
		if source.failed {return Err(ProofError::Random)}
		let (enc, mut context) = sent.map_err(|_| ProofError::NodeKey)?;
		let (mut token, size, mut message) = ([0; *TOKEN.end()], *TOKEN.start() + padding.len(), [0; 32 + HEAD]);
		enc.write_exact(&mut token[..ENC]);
		context.export(BINDER, &mut message[..32]).map_err(|_| ProofError::Crypto)?;
		message[32..].copy_from_slice(head);
		token[ENC..ENC + HEAD].copy_from_slice(head);
		token[ENC + HEAD..ENC + HELLO].copy_from_slice(&binder.copied().unwrap_or_else(|| self.binder.mac(&message)));
		token[ENC + HELLO..size - TAG].copy_from_slice(padding);
		// "`aad`: Empty. The request path is not bound, because a front may rewrite it."
		let tag = context.seal_inout_detached(InOutBuf::from(&mut token[ENC..size - TAG]), &[]).map_err(|_| ProofError::Crypto)?;
		tag.write_exact(&mut token[size - TAG..size]);
		let keys = session(|label, out| context.export(label, out), &self.device_pub).map_err(|_| ProofError::Crypto)?;
		Ok(Proof {token: URL_SAFE_NO_PAD.encode(&token[..size]), keys})
	}
}

impl fmt::Debug for Client {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Client(..)")}
}

/// A token that passed steps 1 to 4 of "Verifying": it is a proof of a device in the table. It is not accepted, and it gives no session keys: those come from `accept`, which takes it through the replay rule and the caller's limits (steps 5 to 7).
#[derive(Debug)]
pub struct Opened<'a, T> {
	/// The device the tag named, with the secret the tag came from.
	pub device: &'a Device<T>,
	/// The timestamp of the hello, Unix seconds.
	pub timestamp: u64,
	/// Which of the node's transport keys opened the token, by its position in the list the node was made with.
	pub key: usize,
	// `enc` as it was sent: the key of this proof in the replay cache.
	enc: [u8; 32],
	keys: SessionKeys,
}

impl<'a, T> Opened<'a, T> {
	/// Steps 5 to 7 of "Verifying", in that order: the replay rule at the wall clock `now`, then `charge`, which is the caller's rate limits for the device and the source and its count of pending sessions. `charge` is called only when the replay rule would accept, spends what it spends, and says whether there was room: "A proof that fails the replay rule spends no rate limit."
	/// When all hold, `enc` is in the replay cache and the session keys are given out. On `Raise` nothing was charged or recorded, and the proof comes back to be asked again once the limit is written.
	/// A proof that waits for that write still points into the tag table it was found in. A reload inside those 2 s that removes the device does not take the proof back: the session it opens is cut off by the engine's path for a removed device, as every other session of that device is.
	pub fn accept(self, replay: &mut Replay, now: u64, charge: impl FnOnce(&'a Device<T>) -> bool) -> Decision<Accepted<'a, T>, Self> {
		match replay.accept(Kind::Stream, &self.enc, self.timestamp, now, || charge(self.device)) {
			Verdict::Accept => Decision::Accepted(Accepted {device: self.device, timestamp: self.timestamp, key: self.key, keys: self.keys}),
			Verdict::Raise(limit) => Decision::Raise(limit, self),
			Verdict::Refuse(refusal) => Decision::Refused(refusal),
		}
	}
}

/// An accepted proof: a pending session of this device, with its keys.
#[derive(Debug)]
pub struct Accepted<'a, T> {
	pub device: &'a Device<T>,
	pub timestamp: u64,
	/// Which of the node's transport keys opened the token.
	pub key: usize,
	pub keys: SessionKeys,
}

/// What a node holds to open tokens on one inbound: its transport keys.
pub struct Node {keys: Vec<Private>, infos: [Vec<u8>; 3], dummies: Vec<Device<()>>}

impl Node {
	/// `transport_keys` are the private halves of the inbound's node transport keys, one or two, and not the same key twice.
	/// `random` gives the dummy keys: "On a tag that is not in the table the node computes with a dummy key that it draws from the random source at start and that nobody else holds." There are 8,192 of them, from one secret that is drawn here, and the tag picks which. What is computed with a dummy key never counts, and nobody can seal a hello that one would accept.
	pub fn new(transport_keys: &[[u8; 32]], inbound_pub: &[u8; 32], random: &mut Random) -> Result<Self, ProofError> {
		if transport_keys.is_empty() || transport_keys.len() > KEYS || transport_keys.first() == transport_keys.get(1) {return Err(ProofError::Keys)}
		let (mut secret, mut public) = ([0; 32], [0; 32]);
		random(&mut secret).and_then(|()| random(&mut public)).map_err(|_| ProofError::Random)?;
		Ok(Self {keys: transport_keys.iter().map(|key| Private::from_bytes(key).expect("an X25519 private key is 32 bytes")).collect(), infos: Name::ALL.map(|name| name.info(inbound_pub)), dummies: (0..DUMMIES).map(|index| {
			secret[..2].copy_from_slice(&index.to_be_bytes());
			Device::derive((), &secret, inbound_pub, &public)
		}).collect()})
	}
	/// Steps 1 to 4 of "Verifying": opens the query part of a request target as a token for the transport `name`, and finds its device in `tags` with one lookup, as a device tag.
	///
	/// "Steps 1 to 4 are done for every request the node evaluates, with dummy inputs where a field is missing or malformed, and their results are combined at the end without leaving early." For every transport key, in order and always for all of them: one HPKE receiver setup, one open, one table lookup, one export and one HMAC for the binder, and the exports of the session keys. A text that is no token is replaced by a fixed token that never opens, a hello that did not open by zero bytes, and a tag that is not in the table by the dummy key. The answer to everything that is not a proof is the one `Refused`.
	///
	/// The same operations are not the same time. Four differences remain, measured in a release build with one transport key and a table of 100,000 devices, against an accepted token of about 47 microseconds (`tests/timing.rs` measures them again):
	///
	/// 1. A tag that is in the table against one that is not, about 0.1 microseconds: the keys of a device come from wherever the table keeps them, and a dummy key from a pool of 8,192 that the tag picks from. With a single dummy, which is always in the processor's cache, it was 0.3 to 0.45 microseconds. It answers "is this tag in the table now" to whoever can seal a hello with a chosen tag, which takes the node transport public key and, for a tag that means something, a tag from an opened token.
	/// 2. An open that fails against one that succeeds, about 0.5 microseconds: the AEAD checks its tag first and decrypts only then, which is about 0.3, and the hello of zero bytes that takes the place of one that did not open always names the same dummy.
	/// 3. A text that is no token against one that is, 0.1 to 0.2 microseconds: a text of another length is not decoded, a wrong character ends the decoding, and the fixed token that takes its place is of the smallest size. This depends on nothing but the peer's own bytes.
	/// 4. What follows: only a token that passed here goes on to the replay rule and the limits. "Steps 5 to 7 are done only for a token that passed steps 1 to 4. They are not repeated with dummy values for the others."
	///
	/// `name` is `None` for a request line that cannot be a user's whatever its token says (a `POST` on a `tls` path, a path no transport of the listener has): the same steps are done and the answer is `Refused`.
	pub fn open<'a, T>(&self, name: Option<Name>, text: &[u8], tags: &'a impl Tags<T>) -> Result<Opened<'a, T>, Refused> {
		let mut token = [0; *TOKEN.end()];
		// "A legal token is base64url without padding in its one canonical form, which means the unused bits of the last character are zero, and decodes to 108 to 204 bytes." The decoder refuses padding and such bits as it is set up here.
		let decoded = if TEXT.contains(&text.len()) {URL_SAFE_NO_PAD.decode_slice(text, &mut token).ok().filter(|size| TOKEN.contains(size))} else {None};
		let size = decoded.unwrap_or_else(|| {
			token.fill(0);
			*TOKEN.start()
		});
		let enc: [u8; 32] = std::array::from_fn(|index| token[index]);
		// `enc` is the peer's own bytes and no secret, so the comparison need not be in constant time. X25519 ignores the top bit.
		let small = SMALL_ORDER.iter().fold(false, |small, point| small | (enc[..31] == point[..31] && enc[31] & 0x7f == point[31]));
		let legal = decoded.is_some() & !small & name.is_some();
		let (encapped, tag, info) = (Encapped::from_bytes(if small {&BASE} else {&enc}).map_err(|_| Refused)?, AeadTag::<ChaCha20Poly1305>::from_bytes(&token[size - TAG..size]).map_err(|_| Refused)?, &self.infos[name.unwrap_or(Name::Tls) as usize]);
		let mut found = None;
		for (index, key) in self.keys.iter().enumerate() {
			let mut hello = [0; HELLO + *PADDING.end() as usize];
			let hello = &mut hello[..size - ENC - TAG];
			hello.copy_from_slice(&token[ENC..size - TAG]);
			#[cfg(test)]
			crate::trace::op("hpke setup");
			// The setup fails for an `enc` of small order and for nothing else, and none reaches it.
			let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, key, &encapped, info).map_err(|_| Refused)?;
			#[cfg(test)]
			crate::trace::op("hpke open");
			let opened = context.open_inout_detached(InOutBuf::from(&mut *hello), &[], &tag).is_ok() & legal;
			// What a failed open leaves behind is undefined, so every later step then works on a hello of zero bytes.
			let keep = u8::from(opened).wrapping_neg();
			hello.iter_mut().for_each(|byte| *byte &= keep);
			// "The version is 1, the three zero bytes are zero, and every padding byte is zero."
			let fields = (hello[0] ^ VERSION) | hello[1] | hello[2] | hello[3] | hello[HELLO..].iter().fold(0, |all, byte| all | byte);
			let device = tags.find_device(&std::array::from_fn(|index| hello[12 + index]));
			// The dummy is picked by the tag, so that the keys of a tag that is not in the table are as far from the processor's cache as the keys of one that is.
			let dummy = &self.dummies[usize::from(u16::from_be_bytes([hello[12], hello[13]]) % DUMMIES)];
			let (binder, public) = device.map_or((&dummy.binder, &dummy.public), |device| (&device.binder, &device.public));
			let mut message = [0; 32 + HEAD];
			#[cfg(test)]
			crate::trace::op("export binder");
			context.export(BINDER, &mut message[..32]).map_err(|_| Refused)?;
			message[32..].copy_from_slice(&hello[..HEAD]);
			let bound = binder.verify(&message, &std::array::from_fn(|index| hello[HEAD + index]));
			let keys = session(|label, out| context.export(label, out), public).map_err(|_| Refused)?;
			if let (true, Some(device), None) = (opened & (fields == 0) & bound, device, &found) {found = Some(Opened {device, timestamp: u64::from_be_bytes(std::array::from_fn(|index| hello[4 + index])), key: index, enc, keys})}
		}
		found.ok_or(Refused)
	}
}

impl fmt::Debug for Node {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Node({} keys)", self.keys.len())}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{replay::{Refusal, Started}, trace, NoRandom};
	use ring::aead::{Aad, Nonce};

	const NODE: [u8; 32] = [0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f];
	const TIME: u64 = 1_700_000_000;

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn unhex(text: &str) -> Vec<u8> {(0..text.len() / 2).map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap()).collect()}

	fn inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {(std::array::from_fn(|i| i as u8), std::array::from_fn(|i| 32 + i as u8), std::array::from_fn(|i| 64 + i as u8))}

	// Gives out the listed draws in order, each of exactly the size that is asked for, then fails.
	fn script<'a>(draws: &'a [&'a [u8]]) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> + 'a {
		let mut draws = draws.iter();
		move |bytes: &mut [u8]| {
			bytes.copy_from_slice(draws.next().filter(|draw| draw.len() == bytes.len()).ok_or(NoRandom)?);
			Ok(())
		}
	}

	fn seeded(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> {
		let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
		move |bytes: &mut [u8]| {
			for byte in bytes {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = (state >> 32) as u8;
			}
			Ok(())
		}
	}

	// A table that writes its lookups into the trace.
	struct Table(crate::keys::Table<Device<u32>>);

	impl Tags<u32> for Table {
		fn find_device(&self, tag: &[u8; 16]) -> Option<&Device<u32>> {
			trace::op("lookup");
			self.0.find_device(tag)
		}
		fn find_epoch(&self, tag: &[u8; 16]) -> Option<&Device<u32>> {self.0.find_epoch(tag)}
	}

	// The device of the vectors as number 7, and a second device with a secret of 0xb1 bytes and a key of 0xb0 bytes as number 8. Device 7 also has its epoch tag of epoch 5 in the table, as a node with a `udp-obfs` transport would.
	fn table() -> Table {
		let ((secret, inbound, device), mut table) = (inputs(), crate::keys::Table::new());
		assert!(table.device(TagKey::derive(&secret, &inbound).device_tag(), Device::derive(7, &secret, &inbound, &device)) && table.device(TagKey::derive(&[0xb1; 32], &inbound).device_tag(), Device::derive(8, &[0xb1; 32], &inbound, &[0xb0; 32])));
		assert!(table.epoch(TagKey::derive(&secret, &inbound).epoch_tag(5), Device::derive(7, &secret, &inbound, &device)));
		Table(table)
	}

	fn client() -> Client {
		let (secret, inbound, device) = inputs();
		Client::new(&public_key(&NODE), &secret, &inbound, &device)
	}

	fn node() -> Node {Node::new(&[NODE], &inputs().1, &mut seeded(9)).unwrap()}

	// A replay memory whose floor is `TIME - 40` and whose written limit is `TIME + 20`.
	fn replay() -> Replay {
		let Started::NoFile(pending) = Replay::start(None, TIME - 100, 9) else {panic!("a start without a file")};
		let mut replay = pending.written();
		assert!(replay.raise(TIME + 20).is_some());
		replay.written();
		replay
	}

	// The head of a hello of the device of the vectors.
	fn head(version: u8, timestamp: u64) -> [u8; HEAD] {
		let mut head = [0; HEAD];
		head[0] = version;
		head[4..12].copy_from_slice(&timestamp.to_be_bytes());
		head[12..].copy_from_slice(&TagKey::derive(&inputs().0, &inputs().1).device_tag());
		head
	}

	// A key is shown by what it seals.
	fn shown(key: &ChunkKey) -> String {
		let mut sealed = b"abc".to_vec();
		let tag = key.0.seal_in_place_separate_tag(Nonce::assume_unique_for_key([0; 12]), Aad::empty(), &mut sealed).unwrap();
		hex(&[&sealed[..], tag.as_ref()].concat())
	}

	// RFC 9180, appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base mode. The values are typed in from the RFC, and tests/vectors.py checks the same ones against an HPKE written out in plain Python. The ephemeral key comes from `ikmE` through the same random source a proof uses.
	#[test]
	fn the_hpke_library_gives_the_vectors_of_rfc_9180() {
		let (ikm_e, sk_r, info) = (unhex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"), unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"), b"Ode on a Grecian Urn");
		let pk_r = public_key(&sk_r.clone().try_into().unwrap());
		assert_eq!(hex(&pk_r), "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
		let draws = [&ikm_e[..]];
		let mut random = script(&draws);
		let mut source = Source {random: &mut random, failed: false};
		let (enc, mut sender) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeS::Base, &Public::from_bytes(&pk_r).unwrap(), info, &mut source).unwrap();
		assert!(!source.failed);
		let (mut encapped, mut sealed, mut tag_bytes) = ([0; 32], b"Beauty is truth, truth beauty".to_vec(), [0; TAG]);
		enc.write_exact(&mut encapped);
		assert_eq!(hex(&encapped), "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
		let tag = sender.seal_inout_detached(InOutBuf::from(&mut sealed[..]), b"Count-0").unwrap();
		tag.write_exact(&mut tag_bytes);
		assert_eq!(hex(&[&sealed[..], &tag_bytes].concat()), "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28");
		let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &Private::from_bytes(&sk_r).unwrap(), &enc, info).unwrap();
		receiver.open_inout_detached(InOutBuf::from(&mut sealed[..]), b"Count-0", &tag).unwrap();
		assert_eq!(sealed, b"Beauty is truth, truth beauty");
		for (context, expected) in [(&b""[..], "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"), (&[0], "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69"), (b"TestContext", "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53")] {
			let (mut sent, mut received) = ([0; 32], [0; 32]);
			sender.export(context, &mut sent).unwrap();
			receiver.export(context, &mut received).unwrap();
			assert_eq!((hex(&sent), hex(&received)), (expected.to_owned(), expected.to_owned()));
		}
	}

	// The list is right when the library refuses each of its points, with the top bit clear and set, and takes the base point. tests/vectors.py checks the same list against an X25519 written out in plain Python.
	#[test]
	fn the_library_stops_at_exactly_the_points_the_node_swaps() {
		let setup = |enc: &[u8; 32]| hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &Private::from_bytes(&NODE).unwrap(), &Encapped::from_bytes(enc).unwrap(), b"").is_ok();
		for mut point in SMALL_ORDER {
			assert!(!setup(&point), "{}", hex(&point));
			point[31] |= 0x80;
			assert!(!setup(&point), "{}", hex(&point));
		}
		assert!(setup(&BASE) && setup(&[2; 32]) && setup(&[0xff; 32]));
	}

	// Expected values come from tests/vectors.py: S = 00..1f, inbound_pub = 20..3f, device_pub = 40..5f, a node transport key of 60..7f, 5 bytes of padding, an ephemeral key from the 32 bytes 80..9f, for `tls` at 1,700,000,000.
	#[test]
	fn a_token_byte_for_byte() {
		assert_eq!(hex(&public_key(&NODE)), "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f");
		let ikm: [u8; 32] = std::array::from_fn(|i| 0x80 + i as u8);
		let proof = client().prove(Name::Tls, TIME, &mut script(&[&[0, 0, 0, 5], &ikm])).unwrap();
		assert_eq!(proof.token, "evA98Vni11dRwaiOtanoeYjxONznWW69o61_C7BKhzTvTTu3V3wYeDX_f5lexUHA7sUtYW3JBP0vfUiFteIF_UjEc44ur9sgymYuYWpZYiLXVyUH6wxSAMqt-6721QR_aZ5P_oQ4gj6uVozwCovzDjs");
		assert_eq!((shown(&proof.keys.c2s), shown(&proof.keys.s2c), hex(&proof.keys.sid)), ("e4fcc93f8528ae3f38419b8895ccad9324543a".to_owned(), "eda5142263bfb5e61d2f72b97880ba0694b39e".to_owned(), "24720866fae9b6e3802d9174128585b3".to_owned()));
		let table = table();
		let opened = node().open(Some(Name::Tls), proof.token.as_bytes(), &table).unwrap();
		assert_eq!((opened.device.id, opened.device.public, opened.timestamp, opened.key), (7, inputs().2, TIME, 0));
		assert_eq!(opened.enc[..], URL_SAFE_NO_PAD.decode(&proof.token).unwrap()[..ENC]);
		assert_eq!((shown(&opened.keys.c2s), shown(&opened.keys.s2c), opened.keys.sid), (shown(&proof.keys.c2s), shown(&proof.keys.s2c), proof.keys.sid));
	}

	#[test]
	fn the_padding_is_drawn_from_0_to_96_and_sets_the_length() {
		for (draw, size) in [(0u32, 144), (96, 272), (97, 144), (5, 151)] {
			let proof = client().prove(Name::Ws, TIME, &mut script(&[&draw.to_be_bytes(), &[7; 32]])).unwrap();
			assert_eq!(proof.token.len(), size);
			assert!(TEXT.contains(&proof.token.len()) && node().open(Some(Name::Ws), proof.token.as_bytes(), &table()).is_ok());
		}
		assert_eq!(client().prove(Name::Ws, TIME, &mut script(&[])).unwrap_err(), ProofError::Random);
		assert_eq!(client().prove(Name::Ws, TIME, &mut script(&[&[0; 4]])).unwrap_err(), ProofError::Random);
		// A profile whose node key is a point of small order: no private key answers it.
		let (secret, inbound, device) = inputs();
		assert_eq!(Client::new(&[0; 32], &secret, &inbound, &device).prove(Name::Ws, TIME, &mut seeded(1)).unwrap_err(), ProofError::NodeKey);
		// No key, three keys, and one key twice, which would be twice the work for nothing.
		for keys in [&[][..], &[NODE, [1; 32], [2; 32]], &[NODE, NODE]] {assert_eq!(Node::new(keys, &inbound, &mut seeded(1)).unwrap_err(), ProofError::Keys)}
		assert_eq!(Node::new(&[NODE], &inbound, &mut script(&[&[0; 32]])).unwrap_err(), ProofError::Random);
		assert!(Node::new(&[NODE, [1; 32]], &inbound, &mut script(&[&[0; 32], &[0; 32]])).is_ok());
	}

	// Steps 5 to 7 of "Verifying": the session keys come out of the replay rule and the limits, and of nothing else.
	#[test]
	fn a_proof_gives_its_keys_once_and_only_through_the_replay_rule() {
		let (table, mut replay, mut charged) = (table(), replay(), Vec::new());
		let token = |timestamp: u64, seed: u64| client().prove(Name::Tls, timestamp, &mut seeded(seed)).unwrap();
		let made = token(TIME, 1);
		let open = |text: &str| node().open(Some(Name::Tls), text.as_bytes(), &table).unwrap();
		// The limits have no room: nothing is recorded, and the same token is good when they have.
		assert!(matches!(open(&made.token).accept(&mut replay, TIME, |_| false), Decision::Refused(Refusal::Limited)));
		let Decision::Accepted(accepted) = open(&made.token).accept(&mut replay, TIME, |device| {
			charged.push(device.id);
			true
		}) else {panic!("a proof was not accepted")};
		assert_eq!((accepted.device.id, accepted.timestamp, accepted.key, accepted.keys.sid, shown(&accepted.keys.c2s)), (7, TIME, 0, made.keys.sid, shown(&made.keys.c2s)));
		// The same token again, and one from an old log: refused before the limits are asked.
		assert!(matches!(open(&made.token).accept(&mut replay, TIME + 1, |_| panic!("a replay was charged")), Decision::Refused(Refusal::Seen)));
		assert!(matches!(open(&token(TIME - 86_400, 2).token).accept(&mut replay, TIME, |_| panic!("an old token was charged")), Decision::Refused(Refusal::Window)));
		// A client whose clock runs ahead: the proof comes back with the limit to write, and is accepted once that is on disk.
		let Decision::Raise(limit, waiting) = open(&token(TIME + 30, 3).token).accept(&mut replay, TIME, |_| panic!("a proof above the limit was charged")) else {panic!("no write was asked for")};
		assert_eq!((limit, replay.len()), (TIME + 50, 1));
		assert!(replay.raise(limit).is_some());
		replay.written();
		assert!(matches!(waiting.accept(&mut replay, TIME, |_| true), Decision::Accepted(_)));
		assert_eq!((charged, replay.len()), (vec![7], 2));
	}

	// The structural stand-in for a timing test: an accepted token and every kind of refusal leave the same sequence of cryptographic operations behind, once per transport key, through hooks in the functions that do them. What the hooks cannot see is inside the libraries: an open that fails does not decrypt, and that difference stays.
	#[test]
	fn every_refusal_does_the_work_of_an_accepted_token() {
		let (table, (secret, inbound, device)) = (table(), inputs());
		let per_key = ["hpke setup", "hpke open", "lookup", "export binder", "hmac verify", "export session"];
		let good = client().prove(Name::Tls, TIME, &mut seeded(1)).unwrap().token;
		let forged = |head: &[u8; HEAD], binder: Option<&[u8; 32]>, padding: &[u8]| client().seal(Name::Tls, head, binder, padding, &mut seeded(2)).unwrap().token.into_bytes();
		let mut flipped = good.clone().into_bytes();
		flipped[50] ^= 1;
		let mut refused: Vec<(&str, Option<Name>, Vec<u8>)> = vec![
			("no text", Some(Name::Tls), Vec::new()),
			("a short text", Some(Name::Tls), good.as_bytes()[..143].to_vec()),
			("a long text", Some(Name::Tls), [good.as_bytes(), &[b'A'; 200]].concat()),
			("a character outside the alphabet", Some(Name::Tls), [&good.as_bytes()[..80], b"=", &good.as_bytes()[81..]].concat()),
			("one character more", Some(Name::Tls), [good.as_bytes(), b"A"].concat()),
			("a changed character", Some(Name::Tls), flipped),
			("another transport", Some(Name::Ws), good.clone().into_bytes()),
			("a line that cannot be a user's", None, good.clone().into_bytes()),
			("a token for another node key", Some(Name::Tls), Client::new(&public_key(&[0x34; 32]), &secret, &inbound, &device).prove(Name::Tls, TIME, &mut seeded(3)).unwrap().token.into_bytes()),
			("a device that is not in the table", Some(Name::Tls), Client::new(&public_key(&NODE), &[0x99; 32], &inbound, &device).prove(Name::Tls, TIME, &mut seeded(4)).unwrap().token.into_bytes()),
			("a device with another WireGuard key", Some(Name::Tls), Client::new(&public_key(&NODE), &secret, &inbound, &[0xb0; 32]).prove(Name::Tls, TIME, &mut seeded(5)).unwrap().token.into_bytes()),
			("another inbound", Some(Name::Tls), Client::new(&public_key(&NODE), &secret, &[0x99; 32], &device).prove(Name::Tls, TIME, &mut seeded(6)).unwrap().token.into_bytes()),
			("version 2 under a right binder", Some(Name::Tls), forged(&head(2, TIME), None, &[])),
			("version 0 under a right binder", Some(Name::Tls), forged(&head(0, TIME), None, &[0; 9])),
			("a padding byte that is set", Some(Name::Tls), forged(&head(1, TIME), None, &[0, 0, 1, 0])),
			("a last padding byte that is set", Some(Name::Tls), forged(&head(1, TIME), None, &[&[0; 95][..], &[0x80]].concat())),
			("a binder of zero bytes", Some(Name::Tls), forged(&head(1, TIME), Some(&[0; 32]), &[])),
		];
		for zero in 1..4 {
			let mut head = head(1, TIME);
			head[zero] = 1;
			refused.push(("a zero byte that is set", Some(Name::Tls), forged(&head, None, &[])));
		}
		// The other device's tag in a hello that this device bound: the table finds the other device, whose key gives another binder.
		let mut other = head(1, TIME);
		other[12..].copy_from_slice(&TagKey::derive(&[0xb1; 32], &inbound).device_tag());
		refused.push(("another device's tag", Some(Name::Tls), forged(&other, None, &[])));
		// The device's own epoch tag, which the table holds for `udp-obfs`: "A device tag is valid only in a stream proof and an epoch tag only on an opening packet. The other kind in either place is a miss."
		let mut epoch = head(1, TIME);
		epoch[12..].copy_from_slice(&TagKey::derive(&secret, &inbound).epoch_tag(5));
		assert!(table.find_epoch(&TagKey::derive(&secret, &inbound).epoch_tag(5)).is_some());
		refused.push(("an epoch tag in a hello", Some(Name::Tls), forged(&epoch, None, &[])));
		// A client that holds the secret and the key the dummy once came from. The dummy is drawn at start now, and nobody holds it.
		refused.push(("a secret of zero bytes", Some(Name::Tls), Client::new(&public_key(&NODE), &[0; 32], &inbound, &[0; 32]).prove(Name::Tls, TIME, &mut seeded(7)).unwrap().token.into_bytes()));
		for mut point in SMALL_ORDER {
			for top in [0, 0x80] {
				point[31] |= top;
				refused.push(("an enc of small order", Some(Name::Tls), URL_SAFE_NO_PAD.encode([&point[..], &[0x5a; 100]].concat()).into_bytes()));
			}
		}
		for (keys, repeats) in [(&[NODE][..], 1), (&[[0x33; 32], NODE], 2), (&[NODE, [0x33; 32]], 2)] {
			let (node, expected) = (Node::new(keys, &inbound, &mut seeded(8)).unwrap(), per_key.repeat(repeats));
			trace::take();
			assert_eq!(node.open(Some(Name::Tls), good.as_bytes(), &table).map(|opened| (opened.device.id, opened.timestamp)), Ok((7, TIME)));
			assert_eq!(trace::take(), expected);
			// The controls: what the forged hellos change is all that makes them fail.
			assert!(node.open(Some(Name::Tls), &forged(&head(1, TIME + 9), None, &[0; 96]), &table).is_ok_and(|opened| opened.timestamp == TIME + 9));
			trace::take();
			for (what, name, text) in &refused {
				assert_eq!(node.open(*name, text, &table).map(|opened| opened.device.id), Err(Refused), "{what}");
				assert_eq!(trace::take(), expected, "{what}");
			}
		}
	}

	// "Without the hello fields under the binder, such a holder could keep a logged `enc` and binder and seal a new hello with a fresh timestamp. With them, a new timestamp needs `k_bind`." The same ephemeral key gives the same `enc` and the same HPKE context, which is what the holder of the node's key can rebuild.
	#[test]
	fn a_new_timestamp_under_a_kept_enc_and_binder_is_refused() {
		let (table, ikm, info) = (table(), [0x44; 32], Name::Tls.info(&inputs().1));
		let logged = client().seal(Name::Tls, &head(1, TIME), None, &[], &mut script(&[&ikm])).unwrap().token;
		assert!(node().open(Some(Name::Tls), logged.as_bytes(), &table).is_ok_and(|opened| opened.timestamp == TIME));
		// The holder of the node's key opens the logged token and reads the binder.
		let mut bytes = URL_SAFE_NO_PAD.decode(&logged).unwrap();
		let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &Private::from_bytes(&NODE).unwrap(), &Encapped::from_bytes(&bytes[..ENC]).unwrap(), &info).unwrap();
		let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&bytes[ENC + HELLO..]).unwrap();
		context.open_inout_detached(InOutBuf::from(&mut bytes[ENC..ENC + HELLO]), &[], &tag).unwrap();
		let binder: [u8; 32] = bytes[ENC + HEAD..ENC + HELLO].try_into().unwrap();
		let retimed = client().seal(Name::Tls, &head(1, TIME + 30), Some(&binder), &[], &mut script(&[&ikm])).unwrap().token;
		assert_eq!((&retimed[..42], retimed.len()), (&logged[..42], logged.len()));
		assert_eq!(node().open(Some(Name::Tls), retimed.as_bytes(), &table).map(|opened| opened.timestamp), Err(Refused));
		// The controls: the same hello with the binder only the device can compute is a proof, and the kept binder is one for its own hello.
		assert!(node().open(Some(Name::Tls), client().seal(Name::Tls, &head(1, TIME + 30), None, &[], &mut script(&[&ikm])).unwrap().token.as_bytes(), &table).is_ok_and(|opened| opened.timestamp == TIME + 30));
		assert!(node().open(Some(Name::Tls), client().seal(Name::Tls, &head(1, TIME), Some(&binder), &[], &mut script(&[&ikm])).unwrap().token.as_bytes(), &table).is_ok());
	}

	#[test]
	fn nothing_secret_is_printed() {
		let proof = client().prove(Name::Fronted, TIME, &mut seeded(1)).unwrap();
		assert_eq!((format!("{:?}", client()), format!("{:?}", node()), format!("{:?}", proof.keys)), ("Client(..)".to_owned(), "Node(1 keys)".to_owned(), "SessionKeys(..)".to_owned()));
		let table = table();
		let opened = format!("{:?}", node().open(Some(Name::Fronted), proof.token.as_bytes(), &table).unwrap());
		assert!(opened.starts_with("Opened { device: Device(7, ..), timestamp: 1700000000, key: 0, enc: [") && opened.ends_with("keys: SessionKeys(..) }"), "{opened}");
	}
}
