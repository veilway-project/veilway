//! Node links (node links page, "Pairing"): the offer code and the answer code, the pairing hash with its fingerprint, the link's transport secret, and what each of the two panels holds between a paste and its confirmation.
//!
//! ```text
//! offer  = "vwlink1." || base64url(object) || "." || base64url(SHA-256(object)[0..4])
//! answer = "vwlinka1." || base64url(id (16) || dialler WireGuard public key (32) || dialler pairing public key (32)) || "." || checksum as above
//! hash   = SHA-256("veilway v1 link pairing" || length of object (4) || object || the 80 bytes of the answer)
//! S      = HKDF(salt "veilway v1 link secret", ikm X25519(own pairing private key, the other pairing public key), info hash, 32)
//! ```
//!
//! Both codes are pasted by a person and are hostile input. Nothing of a code is used before its length, its shape and its checksum hold, a code that fails any check changes nothing, and no error carries a byte of the input. The checksum catches a text that was cut or mistyped and protects nothing: what protects a pairing is the fingerprint, which two people compare.
//! There is no clock, no random source and no storage here. `Offers` is what a listener keeps of the offers it issued and `Pastes` what a dialler keeps of the offers it answered, both in memory only: "A restart of the panel cancels every pending pairing."
//! The key agreement is the one new construction of the page and has had no review. `x25519-dalek` computes it and `ring` the HKDF, and nothing of either is written here.
use crate::control::display;
use crate::keys::{link_fingerprint, link_secret, LINK_PAIRING};
use crate::subscription::json::{self, JsonError, Members};
use crate::subscription::payload::{self, Dial, Transport, INTEGER_MAX};
use crate::subscription::{key_text, public, sealed, unsealed, visible, Secret};
use crate::Random;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::digest::{digest, SHA256};
use std::fmt;
use subtle::ConstantTimeEq;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// "Offer code: at most 2,048 characters."
pub const OFFER_MAX: usize = 2_048;
/// "Answer code: 123 characters."
pub const ANSWER_CHARS: usize = 123;
/// The bytes an answer carries: the link's id, the dialler's WireGuard public key and its pairing public key.
pub const ANSWER_BYTES: usize = 80;
/// "Lifetime of an offer code: 600 s by default, at most 3,600 s."
pub const LIFETIME: u64 = 600;
pub const LIFETIME_MAX: u64 = 3_600;
/// "Links on one node: at most 64", which is also how many offers a node holds open at once.
pub const LINKS_MAX: usize = 64;
/// How far the clocks of the two panels may disagree when an offer's `expires_at` is held to its longest lifetime.
pub const SKEW: u64 = 300;
/// How many answered offers a dialler remembers at once, each until it has expired.
pub const SPENT_MAX: usize = 256;
/// "Link `mtu`: 1280 to 1500."
pub const MTU: RangeInclusive<u64> = 1_280..=1_500;
/// A link's transports: "list of 1 to 8".
pub const TRANSPORTS_MAX: usize = 8;
/// `name`: "display text, 1 to 64 characters".
pub const NAME_MAX: usize = 64;
/// The one version of both codes this crate reads.
pub const VERSION: u64 = 1;
const OFFER: &str = "vwlink1.";
const ANSWER: &str = "vwlinka1.";
// The characters of the checksum and of the 80 bytes of an answer in base64url.
const SUM_CHARS: usize = 6;
const ANSWER_BODY: usize = 107;
// Every member an offer may have: "a member this page does not define refuses the code".
const MEMBERS: [&str; 11] = ["v", "id", "direction", "expires_at", "name", "inbound_public_key", "transport_public_key", "pairing_public_key", "addresses", "mtu", "transports"];

/// Why a code is no code, or is not taken. It names a member by the word the page has for it and never holds text of the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
	/// Longer than a code may be, or not the one length an answer has.
	Length,
	/// Not the prefix, the two parts and the base64url characters of a code.
	Shape,
	/// The checksum is not that of the bytes before it: the text was cut or mistyped.
	Checksum,
	/// The object of an offer is not strict JSON within the parsing limits.
	Json(JsonError),
	/// The object of an offer is another JSON value than one object.
	Object,
	/// A `v` this build does not read.
	Version,
	/// A member the page does not define.
	Unknown,
	/// A member, by its name, that is missing, of another type or outside its range. For an answer it is the key that is no key.
	Member(&'static str),
	/// The offer's `expires_at` has passed.
	Expired,
	/// An answer for an `id` this node has no open offer for, or an offer this node answered already and that has not expired yet.
	Spent,
	/// This node holds as many open offers, or answered ones, as it may.
	Full,
	/// The caller's random source failed.
	Random,
	/// The two pairing keys agree on nothing: X25519 gave all zero bytes.
	Agreement,
}

impl From<&'static str> for CodeError {
	fn from(name: &'static str) -> Self {Self::Member(name)}
}

impl fmt::Display for CodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "pairing code: {self:?}")}
}

impl std::error::Error for CodeError {}

/// Who dials. "The creator is always the listener, so this also says which half the creator is": in a forward link the listener is the exit, in a reverse link the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {Forward, Reverse}

impl Direction {
	/// The value as a code and a config write it.
	pub fn word(self) -> &'static str {if self == Self::Forward {"forward"} else {"reverse"}}
}

// The two parts of a code after its prefix, once the checksum of the first holds. `body` is how many characters the first part has, where a code has one length.
fn checked(code: &str, prefix: &str, body: Option<usize>) -> Result<Vec<u8>, CodeError> {
	let (encoded, sum) = code.strip_prefix(prefix).and_then(|rest| rest.split_once('.')).ok_or(CodeError::Shape)?;
	if sum.len() != SUM_CHARS || body.is_some_and(|body| encoded.len() != body) {return Err(CodeError::Shape)}
	let (sum, bytes) = (unsealed::<4>(sum).ok_or(CodeError::Shape)?, URL_SAFE_NO_PAD.decode(encoded).map_err(|_| CodeError::Shape)?);
	if digest(&SHA256, &bytes).as_ref()[..4] != sum {return Err(CodeError::Checksum)}
	Ok(bytes)
}

fn coded(prefix: &str, bytes: &[u8]) -> String {format!("{prefix}{}.{}", sealed(bytes), sealed(&digest(&SHA256, bytes).as_ref()[..4]))}

fn member<T>(name: &'static str, value: Result<Option<T>, &'static str>) -> Result<T, CodeError> {value?.ok_or(CodeError::Member(name))}

/// What the creator of a link decides, which an offer then carries: everything but the id, the expiry and the pairing key, which are made when the offer is issued.
#[derive(Clone, PartialEq, Eq)]
pub struct Terms {
	pub direction: Direction,
	/// "The creator's label for the link, shown as the other operator's word."
	pub name: String,
	/// The WireGuard public key of the listener's inbound.
	pub inbound_public_key: [u8; 32],
	/// The listener's node transport public key. "Required when a `tls` or `ws` transport is listed."
	pub transport_public_key: Option<[u8; 32]>,
	/// The dialler's address: one or two, IPv4 first, from the listener's inbound pool.
	pub dialler: Vec<IpAddr>,
	/// The listener's link address, in a reverse link and in no other.
	pub listener: Vec<IpAddr>,
	pub mtu: u16,
	/// The listener's transports in its order of preference.
	pub transports: Vec<Transport>,
}

// No address, name, path, pin or key of a link is printed, as for a profile of a subscription.
impl fmt::Debug for Terms {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Terms({}, {} transports)", self.direction.word(), self.transports.len())}
}

/// The transports of a link as a code and a config write them: the list in "the shape of Transports of a profile in the subscription format", as JSON.
pub fn transports_json(transports: &[Transport]) -> String {
	let text = |text: &str| serde_json::to_string(text).unwrap_or_default();
	let endpoints = |kind: &str, list: &[Dial]| format!("{{\"type\":\"{kind}\",\"endpoints\":[{}]}}", list.iter().map(|dial| text(&dial.address().to_string())).collect::<Vec<_>>().join(","));
	let stream = |kind: &str, stream: &payload::Stream| format!("{{\"type\":\"{kind}\",\"path\":{},\"candidates\":[{}]}}", text(&stream.path), stream.candidates.iter().map(|candidate| {
		let mut members = vec![format!("\"address\":{}", text(&candidate.address.address().to_string())), format!("\"sni\":{}", text(candidate.sni.as_deref().unwrap_or_default())), format!("\"host\":{}", text(&candidate.host))];
		members.extend(candidate.verify_name.as_ref().map(|name| format!("\"verify_name\":{}", text(name))));
		members.extend(candidate.ech.as_ref().map(|ech| format!("\"ech\":{}", text(&STANDARD.encode(ech)))));
		if !candidate.pins.is_empty() {members.push(format!("\"pins\":[{}]", candidate.pins.iter().map(|pin| text(&key_text(pin))).collect::<Vec<_>>().join(",")))}
		if candidate.self_signed {members.push("\"self_signed\":true".to_owned())}
		format!("{{{}}}", members.join(","))
	}).collect::<Vec<_>>().join(","));
	format!("[{}]", transports.iter().map(|transport| match transport {
		Transport::Udp(list) => endpoints("udp", list),
		Transport::UdpObfs(list) => endpoints("udp-obfs", list),
		Transport::Tls(tls) => stream("tls", tls),
		Transport::Ws(ws) => stream("ws", ws),
		Transport::Fronted(fronted) => stream("fronted", fronted),
	}).collect::<Vec<_>>().join(","))
}

/// Reads the transports of a link from the JSON `transports_json` writes, which is how an operator hands them to whatever issues an offer: strict JSON, a list of 1 to 8, each of a type a link may list.
pub fn transports(text: &[u8]) -> Result<Vec<Transport>, CodeError> {
	let root = json::parse(text).map_err(CodeError::Json)?;
	let json::Json::Arr(items) = &root else {return Err(CodeError::Member("transports"))};
	if !(1..=TRANSPORTS_MAX).contains(&items.len()) {return Err(CodeError::Member("transports"))}
	items.iter().map(listed).collect()
}

// "`udp`, `udp-obfs`, `tls` and `ws`. Not `ws-plain`. Not `fronted` in version 1." A type this build does not know is refused like any other, and so is a candidate that asks for Encrypted Client Hello, which no dialler of this build can use. A `self_signed` candidate is refused too: a link's `peer.transports` has no such member, so the pairing would end in a link the other node cannot hold.
fn listed(item: &json::Json) -> Result<Transport, CodeError> {
	payload::transport(item).ok().filter(|transport| match transport {
		Transport::Fronted(_) => false,
		Transport::Tls(stream) | Transport::Ws(stream) => stream.candidates.iter().all(|candidate| candidate.ech.is_none() && !candidate.self_signed),
		_ => true,
	}).ok_or(CodeError::Member("transports"))
}

/// An offer that read: what the listener's operator proposes. Its fields can be read by anyone and one is made only by `Offer::parse`, so every one of them passed the checks of the page.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Offer {
	/// "The link's id, 16 random bytes."
	pub id: [u8; 16],
	pub direction: Direction,
	/// Unix seconds. "The offer is refused after this time."
	pub expires_at: u64,
	/// 1 to 64 characters that the display filter leaves as they are.
	pub name: String,
	pub inbound_public_key: [u8; 32],
	/// Present whenever a `tls` or `ws` transport is listed.
	pub transport_public_key: Option<[u8; 32]>,
	pub pairing_public_key: [u8; 32],
	/// One or two, IPv4 first, inside the ranges a pool may lie in.
	pub dialler: Vec<IpAddr>,
	/// Empty in a forward link. In a reverse link one for each family of `dialler`, in the same order.
	pub listener: Vec<IpAddr>,
	pub mtu: u16,
	/// 1 to 8 of `udp`, `udp-obfs`, `tls` and `ws`, none with an Encrypted Client Hello configuration.
	pub transports: Vec<Transport>,
	// "The exact bytes of the offer's object as they stand between the two dots of the code after decoding", which the fingerprint covers. "Nothing is parsed and written out again."
	object: Vec<u8>,
}

impl fmt::Debug for Offer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Offer({}, {} transports)", self.direction.word(), self.transports.len())}
}

impl Offer {
	/// Reads an offer code. The length is checked first, then the shape, then the checksum, and only then is the object read: as strict JSON under the limits of the subscription format, with every member held to its type and range and a member the page does not define refused.
	/// Whether the offer has expired is `expired`, which needs the clock. Whether an address of it lies inside a pool of the node that pastes it, and whether its operator agrees to the addresses it dials, is the caller's to check before it answers.
	pub fn parse(code: &str) -> Result<Offer, CodeError> {
		if code.len() > OFFER_MAX {return Err(CodeError::Length)}
		let object = checked(code, OFFER, None)?;
		let root = json::parse(&object).map_err(CodeError::Json)?;
		let members = Members::of(&root).ok_or(CodeError::Object)?;
		if members.0.keys().any(|name| !MEMBERS.contains(&name.as_str())) {return Err(CodeError::Unknown)}
		if member("v", members.uint("v", 1..=INTEGER_MAX))? != VERSION {return Err(CodeError::Version)}
		let id = unsealed::<16>(member("id", members.string("id", 22))?).ok_or("id")?;
		let direction = match member("direction", members.string("direction", 7))? {
			"forward" => Direction::Forward,
			"reverse" => Direction::Reverse,
			_ => return Err(CodeError::Member("direction")),
		};
		let expires_at = member("expires_at", members.uint("expires_at", 0..=INTEGER_MAX))?;
		// A name the filter would change, or cut, is refused: what the other operator is shown is then what the creator wrote.
		let name = member("name", members.string("name", 4 * NAME_MAX))?;
		if !(1..=NAME_MAX).contains(&name.chars().count()) || !visible(name) || display(name, NAME_MAX, usize::MAX) != name {return Err(CodeError::Member("name"))}
		let key = |name: &'static str| members.string(name, 44).and_then(|text| text.map(|text| public(text).ok_or(name)).transpose());
		let (inbound_public_key, transport_public_key, pairing_public_key) = (member("inbound_public_key", key("inbound_public_key"))?, key("transport_public_key")?, member("pairing_public_key", key("pairing_public_key"))?);
		let addresses = member("addresses", members.object("addresses"))?;
		if addresses.0.keys().any(|name| name != "dialler" && name != "listener") {return Err(CodeError::Unknown)}
		let dialler = payload::addresses(addresses, "dialler")?;
		// "A reverse link fixes one more, the listener's link address. A forward link has no use for a second address and has none."
		let listener = if addresses.get("listener").is_some() {payload::addresses(addresses, "listener")?} else {Vec::new()};
		if (direction == Direction::Reverse) == listener.is_empty() || (!listener.is_empty() && (listener.len() != dialler.len() || listener.iter().zip(&dialler).any(|(listener, dialler)| listener.is_ipv4() != dialler.is_ipv4() || listener == dialler))) {return Err(CodeError::Member("addresses"))}
		let mtu = member("mtu", members.uint("mtu", MTU))? as u16;
		let transports = member("transports", members.list("transports", 1..=TRANSPORTS_MAX))?.iter().map(listed).collect::<Result<Vec<_>, _>>()?;
		if transport_public_key.is_none() && transports.iter().any(|transport| matches!(transport, Transport::Tls(_) | Transport::Ws(_))) {return Err(CodeError::Member("transport_public_key"))}
		Ok(Offer {id, direction, expires_at, name: name.to_owned(), inbound_public_key, transport_public_key, pairing_public_key, dialler, listener, mtu, transports, object})
	}
	/// "The offer is refused after this time."
	pub fn expired(&self, now: u64) -> bool {now > self.expires_at}
	/// Every address the link would dial, in the order of the offer, each with whether it is "a private address", which "is shown plainly on the dialler's panel at step 2 and is accepted there by the operator or the offer is declined".
	/// An address of the dialling node's own networks is the caller's to find: only it knows them.
	pub fn dials(&self) -> Vec<(SocketAddr, bool)> {
		self.transports.iter().flat_map(|transport| match transport {
			Transport::Udp(list) | Transport::UdpObfs(list) => list.clone(),
			Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => stream.candidates.iter().map(|candidate| candidate.address).collect(),
		}).map(|dial| (dial.address(), dial.private())).collect()
	}
	/// The object of the offer as the code carried it.
	pub fn object(&self) -> &[u8] {&self.object}
	/// The code the offer was read from: a code has one writing.
	pub fn code(&self) -> String {coded(OFFER, &self.object)}
}

/// An answer that read: the id of the offer it answers and the dialler's two public keys.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Answer {
	pub id: [u8; 16],
	/// The dialler's WireGuard public key for the link.
	pub public_key: [u8; 32],
	pub pairing_public_key: [u8; 32],
}

impl fmt::Debug for Answer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Answer(..)")}
}

impl Answer {
	/// Reads an answer code: 123 characters, the prefix, 80 bytes and their checksum. "A public key of small order" refuses it, and so does one that is all zero.
	pub fn parse(code: &str) -> Result<Answer, CodeError> {
		if code.len() != ANSWER_CHARS {return Err(CodeError::Length)}
		let bytes = <[u8; ANSWER_BYTES]>::try_from(checked(code, ANSWER, Some(ANSWER_BODY))?).map_err(|_| CodeError::Shape)?;
		let key = |at: usize, name: &'static str| public(&key_text(&std::array::from_fn(|index| bytes[at + index]))).ok_or(CodeError::Member(name));
		Ok(Answer {id: std::array::from_fn(|index| bytes[index]), public_key: key(16, "public_key")?, pairing_public_key: key(48, "pairing_public_key")?})
	}
	/// The 80 bytes of the answer, which the fingerprint covers.
	pub fn bytes(&self) -> [u8; ANSWER_BYTES] {std::array::from_fn(|index| if index < 16 {self.id[index]} else if index < 48 {self.public_key[index - 16]} else {self.pairing_public_key[index - 48]})}
	pub fn code(&self) -> String {coded(ANSWER, &self.bytes())}
}

/// "The pairing hash is the SHA-256 of these bytes in this order: the label, the length of the offer's object as 4 bytes, the exact bytes of the offer's object as they stand between the two dots of the code after decoding, and the 80 bytes of the answer."
pub fn pairing_hash(object: &[u8], answer: &[u8; ANSWER_BYTES]) -> [u8; 32] {
	let mut hash = [0; 32];
	hash.copy_from_slice(digest(&SHA256, &[LINK_PAIRING, &(object.len() as u32).to_be_bytes(), object, answer].concat()).as_ref());
	hash
}

/// One of the two values of a pairing's fingerprint, shown as 8 groups of 4 hexadecimal digits: the listener's or the dialler's, each made from the pairing hash with a label of its own (`keys::link_fingerprint`). It is no secret: whoever holds both codes can compute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; 16]);

impl Fingerprint {
	pub fn of(hash: &[u8; 32], listener: bool) -> Self {Self(link_fingerprint(hash, listener))}
	/// The eight groups, in order.
	pub fn groups(&self) -> [String; 8] {std::array::from_fn(|group| format!("{:02x}{:02x}", self.0[2 * group], self.0[2 * group + 1]))}
	/// What a panel shows: all eight groups of its own value. Each operator reads them to the other, who types what they heard.
	pub fn shown(&self) -> String {self.groups().join(" ")}
	/// Whether `typed` is this value whole: a panel accepts the link only when all eight typed groups equal the other side's value, which it never shows. A check of half of it would be 64 bits against whoever sits in the middle and picks its own code after it has seen the other side's, which is work done offline within the offer's lifetime. Blanks and hyphens between the digits and the case of the letters do not count, nothing else is forgiven, and the digits are compared in constant time.
	pub fn confirms(&self, typed: &str) -> bool {
		let digits: Vec<u8> = typed.bytes().filter(|byte| !matches!(byte, b' ' | b'-' | b'\t')).map(|byte| byte.to_ascii_lowercase()).collect();
		bool::from(digits.ct_eq(self.groups().concat().as_bytes()))
	}
}

/// What a confirmed pairing gives a node for its config: "The listener: the link's id, the dialler's public key, the transport secret, the addresses and the direction. The dialler: the same, the listener's keys and transports, and its own private key."
/// It is made only by `Agreed::confirm`, so a link reaches a config only after its operator typed the fingerprint the other side read out. It is not `Clone`: the secret and the private key are held once.
pub struct Paired {
	pub offer: Offer,
	/// The dialler's WireGuard public key for the link.
	pub public_key: [u8; 32],
	/// The dialler's WireGuard private key for the link, on the dialler and nowhere else.
	pub private_key: Option<Secret<32>>,
	/// The link's transport secret.
	pub secret: Secret<32>,
}

impl fmt::Debug for Paired {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Paired(..)")}
}

/// A pairing between the paste of the answer and the confirmation: both codes, the secret they agreed on and the fingerprint. "Both panels now hold the same fingerprint", and neither has the link in its config yet.
/// The pairing private key that made it is gone: "Both pairing private keys are destroyed as soon as `S` is computed." Nothing here zeroes memory, as nothing in this crate does, and it is not `Clone`, so the secret and the private key are never copied.
/// `own` is the value this panel shows and `theirs` the one it accepts.
pub struct Agreed {paired: Paired, own: Fingerprint, theirs: Fingerprint, listener: bool}

impl fmt::Debug for Agreed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Agreed({})", if self.listener {"listener"} else {"dialler"})}
}

/// Why a pairing was not confirmed.
#[derive(Debug)]
pub enum Unconfirmed {
	/// What was typed is not the fingerprint this panel has. The pairing stays as it was, to be typed again or dropped.
	Mismatch(Box<Agreed>),
	/// "A pasted answer must be confirmed before the offer's `expires_at`. After that the pairing is discarded with everything made for it."
	Expired,
}

impl Agreed {
	// `private` is this side's pairing private key and `theirs` the other side's pairing public key. "A `shared` of all zero bytes refuses the pairing."
	fn new(offer: Offer, answer: &Answer, private: &[u8; 32], theirs: &[u8; 32], key: Option<Secret<32>>, listener: bool) -> Result<Agreed, CodeError> {
		let (shared, hash) = (x25519(*private, *theirs), pairing_hash(&offer.object, &answer.bytes()));
		if shared == [0; 32] {return Err(CodeError::Agreement)}
		Ok(Agreed {paired: Paired {offer, public_key: answer.public_key, private_key: key, secret: Secret::new(link_secret(&shared, &hash))}, own: Fingerprint::of(&hash, listener), theirs: Fingerprint::of(&hash, !listener), listener})
	}
	pub fn offer(&self) -> &Offer {&self.paired.offer}
	/// The value this panel shows, for its operator to read to the other. This panel never accepts it.
	pub fn shown(&self) -> String {self.own.shown()}
	/// Step 4: the operator typed the fingerprint they were told. "There is no button that confirms without it."
	pub fn confirm(self, typed: &str, now: u64) -> Result<Paired, Unconfirmed> {
		if self.paired.offer.expired(now) {return Err(Unconfirmed::Expired)}
		if self.theirs.confirms(typed) {Ok(self.paired)} else {Err(Unconfirmed::Mismatch(Box::new(self)))}
	}
}

// A private key of X25519 in the shape `wg genkey` gives one.
fn private(random: &mut Random) -> Result<[u8; 32], CodeError> {
	let mut key = [0; 32];
	random(&mut key).map_err(|_| CodeError::Random)?;
	(key[0], key[31]) = (key[0] & 248, key[31] & 127 | 64);
	Ok(key)
}

/// The offers a listener has issued and that are still open, each with its pairing private key: "The listener keeps a list of its open offers."
#[derive(Default)]
pub struct Offers {open: Vec<(Offer, Secret<32>)>}

impl fmt::Debug for Offers {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Offers({})", self.open.len())}
}

impl Offers {
	/// Step 1: makes an offer for `terms` that is good for `lifetime` seconds from `now`, and keeps it open. The id and the pairing key are drawn from `random`.
	/// What comes back is the code. It was read back by `Offer::parse` before it was kept, so terms that break a rule of the page, or make a code of more than 2,048 characters, are refused here with the error a reader of the code would give.
	pub fn issue(&mut self, terms: &Terms, now: u64, lifetime: u64, random: &mut Random) -> Result<String, CodeError> {
		self.open.retain(|(offer, _)| !offer.expired(now));
		if self.open.len() >= LINKS_MAX {return Err(CodeError::Full)}
		if !(1..=LIFETIME_MAX).contains(&lifetime) {return Err(CodeError::Member("expires_at"))}
		let (mut id, pairing, text) = ([0; 16], private(random)?, |text: &str| serde_json::to_string(text).unwrap_or_default());
		random(&mut id).map_err(|_| CodeError::Random)?;
		let list = |addresses: &[IpAddr]| addresses.iter().map(|address| text(&address.to_string())).collect::<Vec<_>>().join(",");
		let object = format!("{{\"v\":{VERSION},\"id\":{},\"direction\":\"{}\",\"expires_at\":{},\"name\":{},\"inbound_public_key\":{},{}\"pairing_public_key\":{},\"addresses\":{{\"dialler\":[{}]{}}},\"mtu\":{},\"transports\":{}}}", text(&sealed(&id)), terms.direction.word(), now.saturating_add(lifetime), text(&terms.name), text(&key_text(&terms.inbound_public_key)), terms.transport_public_key.map(|key| format!("\"transport_public_key\":{},", text(&key_text(&key)))).unwrap_or_default(), text(&key_text(&x25519(pairing, X25519_BASEPOINT_BYTES))), list(&terms.dialler), if terms.listener.is_empty() {String::new()} else {format!(",\"listener\":[{}]", list(&terms.listener))}, terms.mtu, transports_json(&terms.transports));
		let code = coded(OFFER, object.as_bytes());
		self.open.push((Offer::parse(&code)?, Secret::new(pairing)));
		Ok(code)
	}
	/// The offers that are open at `now`.
	pub fn open(&mut self, now: u64) -> impl Iterator<Item = &Offer> {
		self.open.retain(|(offer, _)| !offer.expired(now));
		self.open.iter().map(|(offer, _)| offer)
	}
	/// Step 3: takes the answer to an open offer. "An `id` the panel has no open offer for" refuses it, which is also what an expired offer and a second answer for the same `id` meet: "When an answer for an offer has been accepted, or its time has passed, it is spent."
	/// The fingerprint is computed "from the offer it issued and kept, never from anything that was sent back to it". A code that does not read leaves every offer open.
	pub fn answer(&mut self, code: &str, now: u64) -> Result<Agreed, CodeError> {
		let answer = Answer::parse(code)?;
		self.open.retain(|(offer, _)| !offer.expired(now));
		let (offer, pairing) = self.open.remove(self.open.iter().position(|(offer, _)| offer.id == answer.id).ok_or(CodeError::Spent)?);
		Agreed::new(offer, &answer, pairing.expose(), &answer.pairing_public_key, None, true)
	}
}

/// The offers a dialler has answered, each until it expires: "An offer that was answered once is spent on the dialler too: pasting it again is refused until it has expired."
#[derive(Debug, Default)]
pub struct Pastes {spent: Vec<([u8; 16], u64)>}

impl Pastes {
	/// Step 2, once the operator has seen where the offer dials and agreed: makes "a new WireGuard key pair and a new pairing key pair for this paste" from `random`, and gives the answer code and the pairing it makes with the offer.
	/// "A panel never shows one answer for two offers, and never shows an answer again once it has left the screen": every call draws new keys, and the same offer is answered once.
	pub fn answer(&mut self, offer: &Offer, now: u64, random: &mut Random) -> Result<(String, Agreed), CodeError> {
		if offer.expired(now) {return Err(CodeError::Expired)}
		// "Lifetime of an offer code: at most 3,600 s." An offer that expires later than that from now, with room for two clocks that disagree, would keep its pending pairing and a place of this list for as long as it says.
		if offer.expires_at > now.saturating_add(LIFETIME_MAX + SKEW) {return Err(CodeError::Member("expires_at"))}
		self.spent.retain(|(_, until)| now <= *until);
		if self.spent.iter().any(|(id, _)| *id == offer.id) {return Err(CodeError::Spent)}
		if self.spent.len() >= SPENT_MAX {return Err(CodeError::Full)}
		let (key, pairing) = (private(random)?, private(random)?);
		let answer = Answer {id: offer.id, public_key: x25519(key, X25519_BASEPOINT_BYTES), pairing_public_key: x25519(pairing, X25519_BASEPOINT_BYTES)};
		let agreed = Agreed::new(offer.clone(), &answer, &pairing, &offer.pairing_public_key, Some(Secret::new(key)), false)?;
		self.spent.push((offer.id, offer.expires_at));
		Ok((answer.code(), agreed))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::subscription::payload::{Candidate, Stream};
	use crate::NoRandom;

	const NOW: u64 = 1_700_000_000;

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

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn candidate(pinned: bool) -> Candidate {Candidate {address: Dial::parse("203.0.113.9:443").unwrap(), sni: Some("node.example".into()), host: "node.example".into(), verify_name: None, ech: None, pins: if pinned {vec![[7; 32]]} else {Vec::new()}, self_signed: false}}

	fn terms(direction: Direction) -> Terms {
		Terms {direction, name: "exit in the north".into(), inbound_public_key: x25519([1; 32], X25519_BASEPOINT_BYTES), transport_public_key: Some(x25519([2; 32], X25519_BASEPOINT_BYTES)), dialler: vec!["10.9.0.2".parse().unwrap(), "fd00:9::2".parse().unwrap()], listener: if direction == Direction::Reverse {vec!["10.9.0.3".parse().unwrap(), "fd00:9::3".parse().unwrap()]} else {Vec::new()}, mtu: 1390, transports: vec![Transport::UdpObfs(vec![Dial::parse("203.0.113.9:51821").unwrap(), Dial::parse("[2001:db8::9]:51821").unwrap()]), Transport::Tls(Stream {path: "/assets/app-3f9c2e71.js".into(), candidates: vec![candidate(true)]}), Transport::Ws(Stream {path: "/assets/live-7c1d0a52.js".into(), candidates: vec![candidate(false)]}), Transport::Udp(vec![Dial::parse("10.1.2.3:51820").unwrap()])]}
	}

	// An offer with the object `object`, whatever that is.
	fn offer(object: &str) -> Result<Offer, CodeError> {Offer::parse(&coded(OFFER, object.as_bytes()))}

	// The object of a good forward offer with `change` applied to its JSON.
	fn changed(change: impl FnOnce(&mut serde_json::Value)) -> Result<Offer, CodeError> {
		let code = Offers::default().issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(1)).unwrap();
		let mut object: serde_json::Value = serde_json::from_slice(Offer::parse(&code).unwrap().object()).unwrap();
		change(&mut object);
		offer(&object.to_string())
	}

	// RFC 7748, section 6.1, and tests/vectors.py for the rest: the pairing hash and the secret of two fixed codes, computed with Python's hashlib and hmac alone.
	#[test]
	fn the_key_agreement_and_the_secret_are_the_ones_the_page_derives() {
		let unhex = |text: &str| -> [u8; 32] {std::array::from_fn(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap())};
		let (alice, bob) = (unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
		assert_eq!(hex(&x25519(alice, X25519_BASEPOINT_BYTES)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
		assert_eq!(hex(&x25519(alice, x25519(bob, X25519_BASEPOINT_BYTES))), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
		// The two codes vectors.py writes as seeds of the fuzz target, with the pairing private keys it names: 0x03 bytes on the listener and 0x05 bytes on the dialler.
		let seed = |name: &str| String::from_utf8(std::fs::read(format!("{}/../../fuzz/corpus/fuzz_pairing/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()[1..].to_vec()).unwrap();
		let (offer, answer) = (Offer::parse(&seed("offer")).unwrap(), Answer::parse(&seed("answer")).unwrap());
		assert_eq!((offer.id, answer.id, offer.expires_at, offer.transports.len(), answer.code()), (std::array::from_fn(|index| index as u8), offer.id, 1_700_000_600, 2, seed("answer")));
		assert_eq!((offer.pairing_public_key, answer.pairing_public_key), (x25519([3; 32], X25519_BASEPOINT_BYTES), x25519([5; 32], X25519_BASEPOINT_BYTES)));
		assert_eq!(hex(&pairing_hash(offer.object(), &answer.bytes())), "a1a7063d3543a17b38f02d7cc1fb14eef712f3ddfb49af7f9f271bf5bd53385c");
		let (listener, dialler) = (Agreed::new(offer.clone(), &answer, &[3; 32], &answer.pairing_public_key, None, true).unwrap(), Agreed::new(offer.clone(), &answer, &[5; 32], &offer.pairing_public_key, None, false).unwrap());
		for agreed in [&listener, &dialler] {assert_eq!(hex(agreed.paired.secret.expose()), "90c11986cd5e68916c33277d624746c06fa9970b6fbf82ea771c3bab5cccfd6b")}
		// The two values of the fingerprint, from SHA-256 over each label and the pairing hash, as Python's hashlib gives them.
		assert_eq!((listener.shown(), dialler.shown()), ("4aa1 3baf ae4a 800c b147 2457 386e 3da3".to_string(), "5566 cf11 74f3 c7ae 9f30 9d6d b18e 7f11".to_string()));
		assert!(Offer::parse(&seed("offer-reverse")).is_ok_and(|offer| offer.direction == Direction::Reverse && offer.listener.len() == 2));
		// "A `shared` of all zero bytes refuses the pairing": no code that reads carries such a key, and a key that got here some other way is refused all the same.
		assert_eq!(Agreed::new(offer, &answer, &[5; 32], &[0; 32], None, false).err(), Some(CodeError::Agreement));
	}

	#[test]
	fn two_panels_pair_a_link_and_hold_the_same_secret() {
		for direction in [Direction::Forward, Direction::Reverse] {
			let (mut offers, mut pastes) = (Offers::default(), Pastes::default());
			let code = offers.issue(&terms(direction), NOW, LIFETIME, &mut seeded(1)).unwrap();
			assert!(code.len() <= OFFER_MAX && code.starts_with("vwlink1.") && code.is_ascii());
			let offer = Offer::parse(&code).unwrap();
			assert_eq!((offer.direction, offer.expires_at, offer.name.as_str(), offer.mtu, offer.transports.len(), offer.dialler.len(), offer.listener.len()), (direction, NOW + LIFETIME, "exit in the north", 1390, 4, 2, if direction == Direction::Reverse {2} else {0}));
			assert_eq!(offer.dials().iter().map(|(_, private)| *private).collect::<Vec<_>>(), [true, true, true, true, true]);
			let (answer, dialler) = pastes.answer(&offer, NOW + 5, &mut seeded(2)).unwrap();
			assert_eq!((answer.len(), answer.starts_with("vwlinka1.")), (ANSWER_CHARS, true));
			let listener = offers.answer(&answer, NOW + 9).unwrap();
			// Each shows its own value, which is what the other accepts.
			assert!(listener.shown().len() == 39 && listener.shown() != dialler.shown() && (listener.own, listener.theirs) == (dialler.theirs, dialler.own));
			let (theirs, ours) = (dialler.shown(), listener.shown());
			// A panel never takes what its own screen says, so its operator cannot confirm without the other side.
			let listener = match listener.confirm(&ours, NOW + 20) {
				Err(Unconfirmed::Mismatch(kept)) => *kept,
				taken => panic!("the listener took its own value: {taken:?}"),
			};
			let dialler = match dialler.confirm(&theirs, NOW + 20) {
				Err(Unconfirmed::Mismatch(kept)) => *kept,
				taken => panic!("the dialler took its own value: {taken:?}"),
			};
			let (listener, dialler) = (listener.confirm(&theirs.to_uppercase().replace(' ', "-"), NOW + 20).unwrap(), dialler.confirm(&ours, NOW + 20).unwrap());
			assert!(listener.secret == dialler.secret && listener.public_key == dialler.public_key && listener.private_key.is_none());
			assert_eq!(x25519(*dialler.private_key.unwrap().expose(), X25519_BASEPOINT_BYTES), listener.public_key);
			assert_eq!(format!("{listener:?} {offer:?} {:?}", terms(direction)), format!("Paired(..) Offer({0}, 4 transports) Terms({0}, 4 transports)", direction.word()));
		}
	}

	#[test]
	fn a_panel_takes_a_link_only_with_the_whole_fingerprint() {
		let (mut offers, mut pastes) = (Offers::default(), Pastes::default());
		let offer = Offer::parse(&offers.issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(1)).unwrap()).unwrap();
		let (answer, dialler) = pastes.answer(&offer, NOW, &mut seeded(2)).unwrap();
		let mut listener = offers.answer(&answer, NOW).unwrap();
		let (whole, mine) = (dialler.shown(), listener.shown());
		let groups: Vec<&str> = whole.split(' ').collect();
		// Either half alone, a value that agrees with one half and not the other, one digit changed, too much, too little, and a letter that only looks like one: none confirms.
		let flipped = |group: &str| group.chars().map(|c| if c == '0' {'1'} else {'0'}).collect::<String>();
		let (mut near, mixed) = (whole.clone().into_bytes(), |first: bool| groups.iter().enumerate().map(|(at, group)| if (at < 4) == first {group.to_string()} else {flipped(group)}).collect::<Vec<_>>().join(" "));
		near[38] = if near[38] == b'0' {b'1'} else {b'0'};
		for typed in [mine.clone(), mixed(true), mixed(false), groups[..4].join(" "), groups[4..].join(" "), String::new(), String::from_utf8(near).unwrap(), format!("{whole} 0000"), whole[..38].to_string(), whole.replace('a', "\u{e1}").replace('0', "\u{660}")] {
			listener = match listener.confirm(&typed, NOW) {
				Err(Unconfirmed::Mismatch(kept)) => *kept,
				taken => panic!("{typed:?} confirmed a link: {taken:?}"),
			};
		}
		// "A pasted answer must be confirmed before the offer's `expires_at`."
		assert!(matches!(listener.confirm(&whole, NOW + LIFETIME + 1), Err(Unconfirmed::Expired)));
		assert!(dialler.confirm(&mine.to_uppercase().replace(' ', "-"), NOW + LIFETIME).is_ok());
	}

	// An offer that says it lives longer than an offer may is refused by the panel that pastes it: it would keep the pairing and a place of the list of answered offers for as long as it says.
	#[test]
	fn an_offer_that_lives_longer_than_an_offer_may_is_not_answered() {
		let code = Offers::default().issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(1)).unwrap();
		let mut object: serde_json::Value = serde_json::from_slice(Offer::parse(&code).unwrap().object()).unwrap();
		for (expires, answered) in [(NOW + LIFETIME_MAX + SKEW, true), (NOW + LIFETIME_MAX + SKEW + 1, false), (INTEGER_MAX, false)] {
			object["expires_at"] = serde_json::json!(expires);
			let offer = offer(&object.to_string()).unwrap();
			assert_eq!(Pastes::default().answer(&offer, NOW, &mut seeded(2)).map(|_| ()).err(), if answered {None} else {Some(CodeError::Member("expires_at"))}, "{expires}");
		}
	}

	// "If the reader sends an answer of its own to the creating operator in the real peer's place, the fingerprints on the two honest panels differ."
	#[test]
	fn someone_in_the_middle_shows_as_two_fingerprints() {
		let (mut offers, mut pastes, mut forger, mut forged) = (Offers::default(), Pastes::default(), Offers::default(), Pastes::default());
		let offer = Offer::parse(&offers.issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(1)).unwrap()).unwrap();
		// The forger hands the dialler an offer of its own with the same terms, and the listener an answer of its own.
		let altered = Offer::parse(&forger.issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(3)).unwrap()).unwrap();
		let (_, dialler) = pastes.answer(&altered, NOW, &mut seeded(2)).unwrap();
		let (answer, _) = forged.answer(&offer, NOW, &mut seeded(4)).unwrap();
		let listener = offers.answer(&answer, NOW).unwrap();
		assert_ne!(listener.theirs, dialler.own);
		// Whoever forged the answer could grind it until the last half of the listener's fingerprint was the dialler's, in 2^64 work: with the whole fingerprint checked on each side, that ground answer is still refused.
		let ground = Fingerprint(std::array::from_fn(|at| if at < 8 {listener.theirs.0[at]} else {dialler.own.0[at]}));
		assert!(!ground.confirms(&dialler.shown()) && ground.confirms(&ground.shown()));
		assert!(matches!(listener.confirm(&dialler.shown(), NOW), Err(Unconfirmed::Mismatch(_))));
		// A change of one byte of either code is another fingerprint.
		let (object, bytes) = (offer.object().to_vec(), Answer::parse(&answer).unwrap().bytes());
		let base = pairing_hash(&object, &bytes);
		for at in 0..object.len() {
			let mut other = object.clone();
			other[at] ^= 1;
			assert_ne!(pairing_hash(&other, &bytes), base);
		}
		for at in 0..ANSWER_BYTES {
			let mut other = bytes;
			other[at] ^= 1;
			assert_ne!(pairing_hash(&object, &other), base);
		}
		// The length stands in front of the object, so no byte can move from one of the two to the other.
		assert_ne!(pairing_hash(&object[..object.len() - 1], &bytes), pairing_hash(&object, &bytes));
	}

	#[test]
	fn an_offer_is_used_once_on_both_sides() {
		let (mut offers, mut pastes) = (Offers::default(), Pastes::default());
		let offer = Offer::parse(&offers.issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(1)).unwrap()).unwrap();
		let (first, _) = pastes.answer(&offer, NOW, &mut seeded(2)).unwrap();
		// "Pasting it again is refused until it has expired", and then it is refused as expired.
		assert_eq!(pastes.answer(&offer, NOW + 1, &mut seeded(5)).err(), Some(CodeError::Spent));
		assert_eq!(pastes.answer(&offer, NOW + LIFETIME + 1, &mut seeded(5)).err(), Some(CodeError::Expired));
		// An answer that does not read leaves the offer open. One that reads is taken once.
		assert_eq!(offers.answer(&first[..ANSWER_CHARS - 1], NOW).err(), Some(CodeError::Length));
		assert_eq!(offers.answer(&first.replace("vwlinka1.", "vwlinkb1."), NOW).err(), Some(CodeError::Shape));
		assert!(offers.answer(&first, NOW).is_ok());
		assert_eq!(offers.answer(&first, NOW).err(), Some(CodeError::Spent));
		// An offer whose time has passed is no open offer, and an answer for an id nobody issued is refused.
		let late = Offer::parse(&offers.issue(&terms(Direction::Forward), NOW, 60, &mut seeded(6)).unwrap()).unwrap();
		let (answer, _) = Pastes::default().answer(&late, NOW + 60, &mut seeded(7)).unwrap();
		assert_eq!((offers.open(NOW + 60).count(), offers.answer(&answer, NOW + 61).err(), offers.open(NOW + 61).count()), (1, Some(CodeError::Spent), 0));
		// A node holds only so many open offers, and the ones that expired make room.
		let mut many = Offers::default();
		for seed in 0..LINKS_MAX as u64 {many.issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(100 + seed)).unwrap();}
		assert_eq!(many.issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(9)).err(), Some(CodeError::Full));
		assert!(many.issue(&terms(Direction::Forward), NOW + LIFETIME + 1, LIFETIME, &mut seeded(9)).is_ok());
		assert_eq!(many.issue(&terms(Direction::Forward), NOW, LIFETIME_MAX + 1, &mut seeded(9)).err(), Some(CodeError::Member("expires_at")));
		assert_eq!(Offers::default().issue(&terms(Direction::Forward), NOW, LIFETIME, &mut |_: &mut [u8]| Err(NoRandom)).err(), Some(CodeError::Random));
	}

	#[test]
	fn a_code_is_checked_for_length_shape_and_checksum_before_anything_is_read() {
		let code = Offers::default().issue(&terms(Direction::Forward), NOW, LIFETIME, &mut seeded(1)).unwrap();
		assert!(Offer::parse(&code).is_ok());
		// Cut anywhere, it is no code.
		for cut in 0..code.len() {assert!(Offer::parse(&code[..cut]).is_err(), "an offer cut to {cut} characters read")}
		// One character changed anywhere, it is no code.
		for at in 0..code.len() {
			let mut other = code.clone().into_bytes();
			other[at] = if other[at] == b'A' {b'B'} else {b'A'};
			assert!(Offer::parse(&String::from_utf8(other).unwrap()).is_err(), "an offer with character {at} changed read");
		}
		for (text, error) in [(String::new(), CodeError::Shape), ("vwlink1.".into(), CodeError::Shape), ("vwlink1..".into(), CodeError::Shape), ("vwlink2.e30.RBNvow".into(), CodeError::Shape), ("vwlink1.e30.AAAAAA".into(), CodeError::Checksum), ("vwlink1.e30=.RBNvow".into(), CodeError::Shape), ("vwlink1.e30.RBNvow ".into(), CodeError::Shape), (" vwlink1.e30.RBNvow".into(), CodeError::Shape), ("vwlink1.e30.RBNvox".into(), CodeError::Shape), (format!("vwlink1.{}.AAAAAA", "A".repeat(OFFER_MAX)), CodeError::Length), (code.replace("vwlink1.", "vwlinka1."), CodeError::Shape)] {assert_eq!(Offer::parse(&text).err(), Some(error), "{}", &text[..text.len().min(40)])}
		// The empty object has a checksum that holds and is read, and is no offer.
		assert_eq!((coded(OFFER, b"{}"), Offer::parse("vwlink1.e30.RBNvow").err()), ("vwlink1.e30.RBNvow".to_string(), Some(CodeError::Member("v"))));
		for (object, error) in [("[]", CodeError::Object), ("{\"v\":1,\"v\":1}", CodeError::Json(JsonError::Duplicate)), ("\u{feff}{}", CodeError::Json(JsonError::Syntax)), ("{} ", CodeError::Member("v")), ("{}{}", CodeError::Json(JsonError::Syntax)), ("{\"v\":2}", CodeError::Version), ("{\"v\":1.0}", CodeError::Member("v")), ("{\"v\":1,\"more\":1}", CodeError::Unknown)] {assert_eq!(offer(object).err(), Some(error), "{object}")}
		// A code of more than 2,048 characters is not issued either.
		let long = Terms {transports: (0..8).map(|at| Transport::Ws(Stream {path: format!("/assets/{}", "a".repeat(200 + at)), candidates: vec![candidate(true); 4]})).collect(), ..terms(Direction::Forward)};
		assert_eq!(Offers::default().issue(&long, NOW, LIFETIME, &mut seeded(1)).err(), Some(CodeError::Length));
	}

	#[test]
	fn every_member_of_an_offer_is_held_to_its_rule() {
		use serde_json::json;
		assert!(changed(|_| {}).is_ok());
		let cases: Vec<(&str, Box<dyn FnOnce(&mut serde_json::Value)>)> = vec![
			("id", Box::new(|doc| doc["id"] = json!("AAAAAAAAAAAAAAAAAAAAA"))),
			("id", Box::new(|doc| doc["id"] = json!("AAAAAAAAAAAAAAAAAAAAAB"))),
			("id", Box::new(|doc| drop(doc.as_object_mut().unwrap().remove("id")))),
			("direction", Box::new(|doc| doc["direction"] = json!("sideways"))),
			("expires_at", Box::new(|doc| doc["expires_at"] = json!(-1))),
			("expires_at", Box::new(|doc| doc["expires_at"] = json!("1700000000"))),
			("name", Box::new(|doc| doc["name"] = json!(""))),
			("name", Box::new(|doc| doc["name"] = json!(" "))),
			("name", Box::new(|doc| doc["name"] = json!("a".repeat(65)))),
			("name", Box::new(|doc| doc["name"] = json!("exit\u{202e}tixe"))),
			("name", Box::new(|doc| doc["name"] = json!({"default": "exit"}))),
			("inbound_public_key", Box::new(|doc| doc["inbound_public_key"] = json!(key_text(&[0; 32])))),
			("inbound_public_key", Box::new(|doc| doc["inbound_public_key"] = json!("short"))),
			("pairing_public_key", Box::new(|doc| doc["pairing_public_key"] = json!(key_text(&[0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f])))),
			("pairing_public_key", Box::new(|doc| drop(doc.as_object_mut().unwrap().remove("pairing_public_key")))),
			("transport_public_key", Box::new(|doc| drop(doc.as_object_mut().unwrap().remove("transport_public_key")))),
			("transport_public_key", Box::new(|doc| doc["transport_public_key"] = json!(key_text(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])))),
			("dialler", Box::new(|doc| doc["addresses"]["dialler"] = json!([]))),
			("dialler", Box::new(|doc| doc["addresses"]["dialler"] = json!(["fd00:9::2", "10.9.0.2"]))),
			("dialler", Box::new(|doc| doc["addresses"]["dialler"] = json!(["10.9.0.2", "10.9.0.3"]))),
			("dialler", Box::new(|doc| doc["addresses"]["dialler"] = json!(["203.0.113.9"]))),
			("dialler", Box::new(|doc| doc["addresses"]["dialler"] = json!(["10.9.0.2/24"]))),
			("addresses", Box::new(|doc| doc["addresses"]["listener"] = json!(["10.9.0.3", "fd00:9::3"]))),
			("addresses", Box::new(|doc| doc["addresses"] = json!(["10.9.0.2"]))),
			("mtu", Box::new(|doc| doc["mtu"] = json!(1279))),
			("mtu", Box::new(|doc| doc["mtu"] = json!(1501))),
			("transports", Box::new(|doc| doc["transports"] = json!([]))),
			("transports", Box::new(|doc| doc["transports"] = json!([{"type": "udp", "endpoints": ["127.0.0.1:51820"]}]))),
			("transports", Box::new(|doc| doc["transports"] = json!([{"type": "udp", "endpoints": ["[::ffff:203.0.113.9]:51820"]}]))),
			("transports", Box::new(|doc| doc["transports"] = json!([{"type": "ws-plain", "endpoints": ["203.0.113.9:80"]}]))),
			("transports", Box::new(|doc| doc["transports"][0]["type"] = json!("fronted"))),
			("transports", Box::new(|doc| doc["transports"][2]["type"] = json!("fronted"))),
			("transports", Box::new(|doc| doc["transports"][1]["candidates"][0].as_object_mut().unwrap().remove("pins").map_or((), drop))),
			("transports", Box::new(|doc| doc["transports"][1]["candidates"][0]["ech"] = json!("AAAA"))),
			("transports", Box::new(|doc| doc["transports"][1]["path"] = json!("/short"))),
			("transports", Box::new(|doc| doc["transports"] = json!(vec![json!({"type": "udp", "endpoints": ["203.0.113.9:51820"]}); 9]))),
		];
		for (name, change) in cases {assert_eq!(changed(change).err(), Some(CodeError::Member(name)))}
		assert_eq!(changed(|doc| doc["addresses"]["gateway"] = json!(["10.9.0.1"])).err(), Some(CodeError::Unknown));
		// A reverse offer needs the listener's address, one for each family of the dialler's and none of them the dialler's own.
		let reverse = |change: fn(&mut serde_json::Value)| {
			let code = Offers::default().issue(&terms(Direction::Reverse), NOW, LIFETIME, &mut seeded(1)).unwrap();
			let mut object: serde_json::Value = serde_json::from_slice(Offer::parse(&code).unwrap().object()).unwrap();
			change(&mut object);
			offer(&object.to_string()).err()
		};
		assert_eq!(reverse(|_| {}), None);
		for change in [(|doc| drop(doc["addresses"].as_object_mut().unwrap().remove("listener"))) as fn(&mut serde_json::Value), |doc| doc["addresses"]["listener"] = json!(["10.9.0.3"]), |doc| doc["addresses"]["listener"] = json!(["10.9.0.2", "fd00:9::3"]), |doc| doc["direction"] = json!("forward")] {assert_eq!(reverse(change), Some(CodeError::Member("addresses")))}
		// Without a stream transport an offer needs no transport key.
		assert!(changed(|doc| {
			doc.as_object_mut().unwrap().remove("transport_public_key");
			doc["transports"] = json!([{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821"]}]);
		}).is_ok());
	}

	#[test]
	fn an_answer_is_123_characters_with_keys_that_are_keys() {
		let (id, key, pairing) = ([9; 16], x25519([3; 32], X25519_BASEPOINT_BYTES), x25519([4; 32], X25519_BASEPOINT_BYTES));
		let answer = Answer {id, public_key: key, pairing_public_key: pairing};
		let code = answer.code();
		assert_eq!((code.len(), Answer::parse(&code)), (ANSWER_CHARS, Ok(answer)));
		assert_eq!(format!("{answer:?}"), "Answer(..)");
		for cut in 0..code.len() {assert!(Answer::parse(&code[..cut]).is_err())}
		for at in 0..code.len() {
			let mut other = code.clone().into_bytes();
			other[at] = if other[at] == b'A' {b'B'} else {b'A'};
			assert!(Answer::parse(&String::from_utf8(other).unwrap()).is_err(), "an answer with character {at} changed read");
		}
		assert_eq!(Answer::parse(&format!("{code}A")).err(), Some(CodeError::Length));
		// "A public key of small order" in either place, with a checksum that holds.
		for (at, name) in [(16, "public_key"), (48, "pairing_public_key")] {
			for point in [[0u8; 32], std::array::from_fn(|index| u8::from(index == 0))] {
				let mut bytes = answer.bytes();
				bytes[at..at + 32].copy_from_slice(&point);
				assert_eq!(Answer::parse(&coded(ANSWER, &bytes)).err(), Some(CodeError::Member(name)));
			}
		}
		// 80 bytes in another split of the two parts, and another count of bytes under the right count of characters.
		assert_eq!(Answer::parse(&format!("vwlinka1.{}.{}", "A".repeat(106), "A".repeat(7))).err(), Some(CodeError::Shape));
	}

	#[test]
	fn a_fingerprint_is_eight_groups_and_each_panel_checks_all_of_them() {
		let print = Fingerprint(std::array::from_fn(|index| 0x11u8.wrapping_mul(index as u8 + 1)));
		assert_eq!((print.shown(), print.groups().join(" ")), ("1122 3344 5566 7788 99aa bbcc ddee ff10".to_string(), print.shown()));
		assert!(print.confirms("1122 3344 5566 7788 99aa bbcc ddee ff10") && print.confirms("1122-3344-5566-7788-99AA-BBCC-DDEE-FF10") && print.confirms("112233445566778899aabbccddeeff10"));
		for typed in ["1122 3344 5566 7788", "99aa bbcc ddee ff10", "1122 3344 5566 7788 99aa bbcc ddee ff1", "1122 3344 5566 7788 99aa bbcc ddee ff10 0", "1122 3344 5566 7788 99aa bbcc ddee ff1g", "0000 0000 0000 0000 99aa bbcc ddee ff10", ""] {assert!(!print.confirms(typed), "{typed}")}
	}

	#[test]
	fn the_transports_of_an_offer_are_written_as_a_profile_writes_them() {
		let written = transports_json(&terms(Direction::Forward).transports);
		assert_eq!(written, "[{\"type\":\"udp-obfs\",\"endpoints\":[\"203.0.113.9:51821\",\"[2001:db8::9]:51821\"]},{\"type\":\"tls\",\"path\":\"/assets/app-3f9c2e71.js\",\"candidates\":[{\"address\":\"203.0.113.9:443\",\"sni\":\"node.example\",\"host\":\"node.example\",\"pins\":[\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\"]}]},{\"type\":\"ws\",\"path\":\"/assets/live-7c1d0a52.js\",\"candidates\":[{\"address\":\"203.0.113.9:443\",\"sni\":\"node.example\",\"host\":\"node.example\"}]},{\"type\":\"udp\",\"endpoints\":[\"10.1.2.3:51820\"]}]");
		// What is written reads back as what it was.
		let root = json::parse(written.as_bytes()).unwrap();
		let json::Json::Arr(items) = &root else {panic!("no list")};
		assert_eq!(items.iter().map(|item| payload::transport(item).unwrap()).collect::<Vec<_>>(), terms(Direction::Forward).transports);
	}
}
