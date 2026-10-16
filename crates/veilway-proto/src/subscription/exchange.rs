//! The encrypted exchange of a native fetch (subscription format page, "The encrypted exchange", "Replays and clocks" and "Gateway keys"): Oblivious HTTP (RFC 9458) over HPKE (RFC 9180) in base mode with the suite of the stream proof, with the page's own content, header and strings. No part of HPKE is written here, and there is no socket, clock or storage: the time and the random bytes are parameters.
//!
//! ```text
//! request = key_id (1) || enc (32, top bit of the last byte random) || ct (1,024 + 16)
//! plaintext = n (2) || request JSON (n, 1 to 1,022) || zero bytes
//! answer = response_nonce (32) || ct (size - 48 + 16), size one of the five of `mirror::SIZES`
//! plaintext = m (4) || envelope (m) || zero bytes
//! ```
//!
//! The two sides are two sets of types. A client makes a `Sealed` with `Request::seal` and opens the answer to that request with it, and to no other. A gateway holds a `Gateway`, which opens a body into an `Opened` (the request that was read and the `Reply` that seals its answer) or into a `Refusal`, which only a counter is told. Whatever the refusal, the gateway's answer is the one answer of a path it does not serve.
use super::{mirror, weak, fetch::{Received, RequestError}};
use crate::{keys, proof::{Encapped, Private, Public, Source, BASE, SMALL_ORDER}, NoRandom, Random};
use hpke::{aead::{AeadTag, ChaCha20Poly1305}, inout::InOutBuf, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR, OpModeS, Serializable};
use ring::aead;
use std::{collections::HashMap, fmt, sync::Arc};

/// "Encapsulated request: exactly 1,073 bytes: a 1-byte key id, a 32-byte `enc`, and 1,040 bytes of ciphertext with its tag."
pub const REQUEST: usize = 1_073;
/// "Request plaintext: exactly 1,024 bytes: a 2-byte length, the request JSON of at most 1,022 bytes, and zero bytes."
pub const PLAINTEXT: usize = 1_024;
/// The largest request JSON.
pub const JSON_MAX: usize = PLAINTEXT - 2;
/// "Request time window: `t` within 300 s of the gateway's clock, either way." The memory keeps a request until the clock passes its `t` plus this.
pub const WINDOW: u64 = 300;
/// "Gateway key in a link: 33 bytes: a 1-byte key id and a 32-byte X25519 public key."
pub const KEY: usize = 33;
/// "Gateway keys in a document: 1 or 2."
pub const KEYS_MAX: usize = 2;
const TAG: usize = 16;
// The exporter context of the answer's secret, and the strings of `info`: "ASCII bytes of that string with no zero byte" for the first, a zero byte before the header for the second.
const RESPONSE: &[u8] = b"veilway v1 sub response";
const REQUEST_INFO: &[u8] = b"veilway v1 sub request\0";
// The request that takes the place of one that did not open.
const DUMMY: &[u8] = br#"{"v":1,"t":0,"token":"AAAAAAAAAAAAAAAAAAAAAA","kids":["AAAAAAAAAAA"],"device_public_key":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=","device_secret":"AAAAAAAAAAAAAAAAAAAAAA","op":"fetch"}"#;
// The suite's identifiers after the key id: DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20Poly1305 `0x0003`.
const SUITE: [u8; 6] = [0, 0x20, 0, 1, 0, 3];

/// A gateway key: "`key_id` (1 byte) followed by `pkR` (32 bytes, the X25519 public key as HPKE serializes it)". One that is all zero or a point of small order is none.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayKey {id: u8, public: [u8; 32]}

impl GatewayKey {
	pub fn new(id: u8, public: [u8; 32]) -> Option<Self> {(!weak(&public)).then_some(Self {id, public})}
	/// Reads the 33 bytes of a link: the id and then the key.
	pub fn from_link(bytes: &[u8; KEY]) -> Option<Self> {Self::new(bytes[0], std::array::from_fn(|index| bytes[1 + index]))}
	/// The 33 bytes a link carries, 44 base64url characters.
	pub fn link(&self) -> [u8; KEY] {std::array::from_fn(|index| if index == 0 {self.id} else {self.public[index - 1]})}
	pub fn id(&self) -> u8 {self.id}
	pub fn public(&self) -> &[u8; 32] {&self.public}
}

// A key is public, but a log line with one in it ties a line to a provider's gateway.
impl fmt::Debug for GatewayKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "GatewayKey({})", self.id)}
}

// `info` = `"veilway v1 sub request" || hdr`, where `hdr` = `key_id || 00 20 || 00 01 || 00 03`, 7 bytes.
fn info(id: u8) -> Vec<u8> {[REQUEST_INFO, &[id], &SUITE].concat()}

/// Why a request was not sealed, or an answer not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
	/// The JSON is empty or over 1,022 bytes, or the envelope is empty or larger than the biggest of the five sizes holds.
	Size,
	/// The random source failed.
	Random,
	/// The HPKE library refused the key, which a `GatewayKey` is made not to be.
	Key,
}

impl fmt::Display for SealError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "subscription exchange: {self:?}")}
}

impl std::error::Error for SealError {}

/// Why an answer does not open ("How the client opens an answer", steps 1 to 3). Each is a failed fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
	/// The body is not exactly one of the five sizes.
	Size,
	/// The tag does not verify: another request's answer, or a changed byte.
	Seal,
	/// `m` is 0 or more than the answer holds.
	Length,
	/// A byte after the envelope is not zero.
	Padding,
}

impl fmt::Display for AnswerError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "subscription answer: {self:?}")}
}

impl std::error::Error for AnswerError {}

/// A request that is sealed, and what opens the one answer to it. It holds the secret of the answer, so it prints nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {bytes: Vec<u8>, enc: [u8; 32], secret: [u8; 32]}

impl fmt::Debug for Sealed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Sealed(..)")}
}

/// "Sealing a request", for `json`: the plaintext is padded to 1,024 bytes, sealed to `key` with a new ephemeral key, and the top bit of the last byte of `enc` is set to a random bit for the wire. The random source is asked for the 32 bytes of the ephemeral key's input and then for one byte, whose lowest bit is that bit.
pub fn seal(key: &GatewayKey, json: &[u8], random: &mut Random) -> Result<Sealed, SealError> {
	if json.is_empty() || json.len() > JSON_MAX {return Err(SealError::Size)}
	let mut plain = [0; PLAINTEXT];
	plain[..2].copy_from_slice(&(json.len() as u16).to_be_bytes());
	plain[2..2 + json.len()].copy_from_slice(json);
	seal_plaintext(key, plain, random)
}

/// A request whose plaintext is whatever the caller says, for the tests of what a gateway does with a seal that opens and holds no request. No build of a client turns it on.
#[cfg(any(feature = "bench", fuzzing))]
pub fn seal_plain(key: &GatewayKey, plain: &[u8; PLAINTEXT], random: &mut Random) -> Result<Sealed, SealError> {seal_plaintext(key, *plain, random)}

fn seal_plaintext(key: &GatewayKey, mut plain: [u8; PLAINTEXT], random: &mut Random) -> Result<Sealed, SealError> {
	let mut source = Source {random, failed: false};
	let sent = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeS::Base, &Public::from_bytes(&key.public).map_err(|_| SealError::Key)?, &info(key.id), &mut source);
	if source.failed {return Err(SealError::Random)}
	let (encapped, mut context) = sent.map_err(|_| SealError::Key)?;
	let (mut enc, mut tag, mut secret) = ([0; 32], [0; TAG], [0; 32]);
	encapped.write_exact(&mut enc);
	context.seal_inout_detached(InOutBuf::from(&mut plain[..]), &[]).map_err(|_| SealError::Key)?.write_exact(&mut tag);
	context.export(RESPONSE, &mut secret).map_err(|_| SealError::Key)?;
	let mut bit = [0];
	random(&mut bit).map_err(|NoRandom| SealError::Random)?;
	let mut bytes = [&[key.id][..], &enc, &plain, &tag].concat();
	bytes[32] |= (bit[0] & 1) << 7;
	Ok(Sealed {bytes, enc, secret})
}

impl Sealed {
	/// The 1,073 bytes of the `POST`, `Content-Type: application/octet-stream`.
	pub fn bytes(&self) -> &[u8] {&self.bytes}
	/// "How the client opens an answer", steps 2 and 3: the size, the seal, the length and the zeros. The envelope goes on to the checks of "What is checked, in order" by the same path as every other answer. Whether the status was 200 is the caller's, who reads at most 1,089,437 bytes.
	pub fn open(&self, answer: &[u8]) -> Result<Vec<u8>, AnswerError> {
		let capacity = mirror::capacity(answer.len()).ok_or(AnswerError::Size)?;
		let nonce: [u8; 32] = std::array::from_fn(|index| answer[index]);
		let (key, nonce) = keys::answer(&self.enc, &nonce, &self.secret);
		let mut opened = answer[32..].to_vec();
		let plain = key.0.open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::empty(), &mut opened).map_err(|_| AnswerError::Seal)?;
		let length = u32::from_be_bytes(std::array::from_fn(|index| plain[index])) as usize;
		if length == 0 || length > capacity {return Err(AnswerError::Length)}
		if plain[4 + length..].iter().any(|byte| *byte != 0) {return Err(AnswerError::Padding)}
		Ok(plain[4..4 + length].to_vec())
	}
}

/// What seals the answer to one request: the `enc` the client's HPKE made and the secret both sides export. It holds a secret, so it prints nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Reply {enc: [u8; 32], secret: [u8; 32]}

impl fmt::Debug for Reply {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Reply(..)")}
}

impl Reply {
	/// "Sealing an answer": `envelope` is the signed document or refusal exactly as signed. The answer has the smallest of the five sizes whose plaintext holds it, and a `response_nonce` drawn here.
	pub fn seal(&self, envelope: &[u8], random: &mut Random) -> Result<Vec<u8>, SealError> {
		let size = mirror::size_for(envelope.len()).ok_or(SealError::Size)?;
		let mut sealed = Vec::with_capacity(size);
		sealed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
		sealed.extend_from_slice(envelope);
		sealed.resize(size - 48, 0);
		self.encrypt(sealed, random)
	}
	/// An answer of the smallest size whose plaintext `change` has made, for the tests of what a client does with a gateway that is wrong. No build of a gateway turns it on.
	#[cfg(any(feature = "bench", fuzzing))]
	pub fn seal_changed(&self, envelope: &[u8], random: &mut Random, change: impl FnOnce(&mut Vec<u8>)) -> Result<Vec<u8>, SealError> {
		let size = mirror::size_for(envelope.len()).ok_or(SealError::Size)?;
		let mut sealed = Vec::with_capacity(size);
		sealed.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
		sealed.extend_from_slice(envelope);
		sealed.resize(size - 48, 0);
		change(&mut sealed);
		self.encrypt(sealed, random)
	}
	// `response_nonce` from `random`, then the key and nonce of the page, and the plaintext sealed.
	fn encrypt(&self, mut sealed: Vec<u8>, random: &mut Random) -> Result<Vec<u8>, SealError> {
		let mut nonce = [0; 32];
		random(&mut nonce).map_err(|NoRandom| SealError::Random)?;
		let (key, number) = keys::answer(&self.enc, &nonce, &self.secret);
		let tag = key.0.seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key(number), aead::Aad::empty(), &mut sealed).map_err(|_| SealError::Key)?;
		Ok([&nonce[..], &sealed, tag.as_ref()].concat())
	}
}

/// Why the gateway refused a body. Only a counter is told: the answer is the same for every one, "exactly what the host answers on any path it does not serve".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// A body of another length.
	Size,
	/// An unknown key id.
	Key,
	/// A request that did not open, an `enc` of small order, or one that opened with a plaintext that is no length and zero bytes.
	Open,
	/// A plaintext that is not the request JSON.
	Request,
	/// A `t` outside the window, or earlier than the gateway's start.
	Window,
	/// An `enc` seen before.
	Replay,
	/// The caller's limit for the source of the request is used up.
	Source,
	/// The memory of acted requests is at `SEEN_MAX`. Nothing new is taken until some of it expires, so that a flood can fill the memory but never grow it.
	Full,
}

/// A request that opened, was in the window and was not seen before, and the means to answer it. The token is not looked at yet: that is the panel's, with one HMAC and one lookup.
pub struct Opened {
	/// The request, or for one that read as far as its token and `t` and no further, those two: "the gateway answers `"bad_request"`, sealed, when the token in it is valid".
	pub request: Result<Received, RequestError>,
	pub reply: Reply,
}

impl fmt::Debug for Opened {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Opened({})", if self.request.is_ok() {"request"} else {"malformed"})}
}

/// Most requests the memory of a gateway holds. A request is recorded once it has opened and is in the window, before its token is looked at, so anyone who knows a gateway key can add entries: past this many the gateway refuses new requests (`Refusal::Full`) and the memory stops growing. A request lives 600 s in it at most, so the cap is a sustained rate of about 333 requests a second.
pub const SEEN_MAX: usize = 200_000;

/// The keys of a gateway and its dummy key, which need no state: a body is opened with them by `unseal` on any thread and without a lock, and only `Gateway::admit` needs the gateway's memory.
pub struct Keyring {keys: Vec<(u8, Private)>, dummy: Private}

/// A body that was opened (or was not) with the keys but is not yet judged by the clock and the memory. It is admitted only by the gateway whose keys opened it.
pub struct Unsealed {keyring: Arc<Keyring>, sized: bool, slot: bool, opened: bool, shaped: bool, enc: [u8; 32], request: Result<Received, RequestError>, secret: [u8; 32]}

impl fmt::Debug for Unsealed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Unsealed({})", if self.opened && self.shaped {"opened"} else {"closed"})}
}

/// What a gateway holds to open requests: its keys, a dummy key, the time it started, the highest value its clock has shown and the memory of the requests it has acted on. The memory is in memory only.
pub struct Gateway {keyring: Arc<Keyring>, started: u64, clock: u64, purged: u64, steps: u64, seen: HashMap<[u8; 32], u64>, cap: usize}

impl fmt::Debug for Gateway {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Gateway({} keys, {} remembered)", self.keyring.keys.len(), self.seen.len())}
}

/// A gateway was given no key, or one id twice ("The panel never holds or lists two keys with one id"), or a private key HPKE cannot use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayKeys;

impl fmt::Display for GatewayKeys {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("subscription gateway: the keys are none, or share an id")}
}

impl std::error::Error for GatewayKeys {}

impl Keyring {
	/// "What the gateway does", steps 1 to 3, for a body read up to 1,073 bytes and no further. The work does not depend on what the body holds: a body of another length is replaced by a fixed request that never opens, an unknown key id by a fixed dummy key, an `enc` of small order by the base point, and a request that did not open by zeros, and the results are combined at the end. It reads and writes no state, so a caller opens bodies at the same time and takes the gateway's lock only for `Gateway::admit`.
	pub fn unseal(self: &Arc<Self>, body: &[u8]) -> Result<Unsealed, Refusal> {
		let sized = body.len() == REQUEST;
		let mut request = [0; REQUEST];
		request[1..33].copy_from_slice(&BASE);
		if sized {request.copy_from_slice(body)}
		let slot = self.keys.iter().position(|(id, _)| *id == request[0]);
		let private = slot.map_or(&self.dummy, |at| &self.keys[at].1);
		let mut enc: [u8; 32] = std::array::from_fn(|index| request[1 + index]);
		enc[31] &= 0x7f;
		// `enc` is the peer's own bytes and no secret, so the comparison need not be in constant time. X25519 ignores the top bit, and HPKE stops at such an `enc` before its key schedule.
		let small = SMALL_ORDER.iter().fold(false, |small, point| small | (enc[..31] == point[..31] && enc[31] == point[31]));
		let encapped = Encapped::from_bytes(if small {&BASE} else {&enc}).map_err(|_| Refusal::Open)?;
		let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&request[REQUEST - TAG..]).map_err(|_| Refusal::Open)?;
		let mut plain = [0; PLAINTEXT];
		plain.copy_from_slice(&request[33..33 + PLAINTEXT]);
		let mut context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, private, &encapped, &info(request[0])).map_err(|_| Refusal::Open)?;
		let opened = context.open_inout_detached(InOutBuf::from(&mut plain[..]), &[], &tag).is_ok() & sized & !small & slot.is_some();
		// What a failed open leaves behind is undefined, so every later step then works on a plaintext of zero bytes.
		let keep = u8::from(opened).wrapping_neg();
		plain.iter_mut().for_each(|byte| *byte &= keep);
		let mut secret = [0; 32];
		context.export(RESPONSE, &mut secret).map_err(|_| Refusal::Open)?;
		let length = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
		let shaped = (1..=JSON_MAX).contains(&length) & plain[2..].iter().enumerate().fold(true, |zeros, (place, byte)| zeros & (place < length || *byte == 0));
		// "The JSON is read": a request that did not open is replaced by a fixed one, so that the work is the same, and its result is thrown away.
		let read = Received::read(if opened & shaped {&plain[2..2 + length]} else {DUMMY});
		let request = if opened & shaped {read} else {Err(RequestError::Unreadable)};
		Ok(Unsealed {keyring: self.clone(), sized, slot: slot.is_some(), opened, shaped, enc, request, secret})
	}
}

impl Gateway {
	/// `keys` are the private halves of the active key, the next one and the retired keys still kept, each with its id. `started` is the clock at the start, in Unix seconds: "After a start, any `t` earlier than the start is refused". `random` gives the dummy key that a request with an unknown key id is opened with.
	pub fn new(keys: &[(u8, [u8; 32])], started: u64, random: &mut Random) -> Result<Self, GatewayKeys> {
		if keys.is_empty() || keys.iter().enumerate().any(|(place, (id, _))| keys[..place].iter().any(|(earlier, _)| earlier == id)) {return Err(GatewayKeys)}
		let mut dummy = [0; 32];
		random(&mut dummy).map_err(|NoRandom| GatewayKeys)?;
		let keyring = Keyring {keys: keys.iter().map(|(id, key)| Private::from_bytes(key).map(|key| (*id, key)).map_err(|_| GatewayKeys)).collect::<Result<_, _>>()?, dummy: Private::from_bytes(&dummy).map_err(|_| GatewayKeys)?};
		Ok(Self {keyring: Arc::new(keyring), started, clock: started, purged: started, steps: 0, seen: HashMap::new(), cap: SEEN_MAX})
	}
	/// A gateway whose memory holds at most `cap` requests instead of `SEEN_MAX`, for a test of what happens at the cap.
	pub fn capped(mut self, cap: usize) -> Self {
		self.cap = cap;
		self
	}
	/// How many times the clock stepped back since the start: "a step back is logged at warning level". The window never moves back with it.
	pub fn steps_back(&self) -> u64 {self.steps}
	/// How many requests the memory holds.
	pub fn remembered(&self) -> usize {self.seen.len()}
	/// The keys, to open bodies with outside the lock that guards this gateway. A body they open is admitted by this gateway only.
	pub fn keyring(&self) -> Arc<Keyring> {self.keyring.clone()}
	/// `Keyring::unseal` and `admit` in one step, for a caller that holds the gateway for both.
	pub fn open(&mut self, body: &[u8], now: u64, charge: impl FnOnce() -> bool) -> Result<Opened, Refusal> {
		let unsealed = self.keyring.unseal(body)?;
		self.admit(unsealed, now, charge)
	}
	/// "What the gateway does", steps 4 to 6, at the wall clock `now`: the window, the memory and the cap on it. A body that another set of keys opened is an unknown key.
	/// `charge` is the caller's limit for the source of the request. It is called only for a request that opened, is in the window and is new, which is the one that is recorded, and says whether the source still has room.
	pub fn admit(&mut self, unsealed: Unsealed, now: u64, charge: impl FnOnce() -> bool) -> Result<Opened, Refusal> {
		let Unsealed {keyring, sized, slot, opened, shaped, enc, request, secret} = unsealed;
		if !Arc::ptr_eq(&keyring, &self.keyring) {return Err(Refusal::Key)}
		let t = match &request {Ok(request) => Some(request.t()), Err(RequestError::Malformed(_, t)) => Some(*t), Err(RequestError::Unreadable) => None};
		// "The clock it judges by is the highest value its clock has shown since it started."
		self.steps += u64::from(now < self.clock);
		self.clock = self.clock.max(now);
		if self.clock > self.purged {
			self.seen.retain(|_, until| *until >= self.clock);
			self.purged = self.clock;
		}
		let in_window = t.is_some_and(|t| t.abs_diff(self.clock) <= WINDOW && t >= self.started);
		let fresh = !self.seen.contains_key(&enc);
		let refusal = if !sized {Some(Refusal::Size)} else if !slot {Some(Refusal::Key)} else if !(opened && shaped) {Some(Refusal::Open)} else if t.is_none() {Some(Refusal::Request)} else if !in_window {Some(Refusal::Window)} else if !fresh {Some(Refusal::Replay)} else if self.seen.len() >= self.cap {Some(Refusal::Full)} else {None};
		if let Some(refusal) = refusal {return Err(refusal)}
		// "A request that opened and is inside the window is recorded now, before the token is looked at."
		if !charge() {return Err(Refusal::Source)}
		self.seen.insert(enc, t.unwrap_or(0).saturating_add(WINDOW));
		Ok(Opened {request, reply: Reply {enc, secret}})
	}
}

/// "How a client uses them": it seals to the first key. "When an HTTP answer arrived and it was not a sealed answer that opens, it tries the second key once, in the same refresh, with a new request. A timeout, a failed TLS handshake or pin, or a failed lookup is no reason to try the second key: it says nothing about the key. Never more than one retry." `tried` is the key the request that got the answer was sealed to, and `answered` says whether an HTTP answer arrived that was not a sealed answer that opens. Gives the key for the one retry, or `None`.
pub fn next_key(keys: &[GatewayKey], tried: &GatewayKey, answered: bool) -> Option<GatewayKey> {
	if !answered || keys.len() != KEYS_MAX || keys[0] != *tried {return None}
	Some(keys[1])
}
