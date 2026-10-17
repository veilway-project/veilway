//! Keys, and every label of the protocol (transports page, "Keys derived from the device transport secret", "The stream proof" and the keys of `udp-obfs`).
//!
//! A key lives inside the opaque key type of `ring` from the moment it is made, so the types here cannot print a key, cannot be copied and cannot be compared. The one exception is `ObfsKey`: `k_obfs` is the input keying material of an HKDF, which `ring` takes as bytes, so that type keeps the 32 bytes itself. Nothing is zeroed on drop: `ring` does not zero its key types, and doing it from outside would need `unsafe` or a dependency.
use ring::digest::{digest, SHA256};
use ring::{aead, hkdf, hmac};
use std::{borrow::Borrow, collections::HashMap, fmt};

// A label in double quotes is its ASCII bytes followed by one zero byte (transports page, "Building blocks"). Labels are written here and nowhere else.
const DEVICE_SECRET: &[u8] = b"veilway v1 device secret\0";
const TAG: &[u8] = b"veilway v1 tag\0";
const PROOF_BINDER: &[u8] = b"veilway v1 proof binder\0";
const OBFS: &[u8] = b"veilway v1 udp-obfs\0";
const CONTROL: &[u8] = b"veilway v1 control\0";
const DEVICE_TAG: &[u8] = b"veilway v1 device tag\0";
const EPOCH_TAG: &[u8] = b"veilway v1 epoch tag\0";
const OBFS_MASK: &[u8] = b"veilway v1 udp-obfs mask\0";
const OBFS_OPEN: &[u8] = b"veilway v1 udp-obfs open\0";
const OBFS_C2S: &[u8] = b"veilway v1 udp-obfs c2s\0";
const OBFS_S2C: &[u8] = b"veilway v1 udp-obfs s2c\0";
pub(crate) const CONTROL_AUTH: &[u8] = b"veilway v1 control auth\0";
// The stream proof: the start of the HPKE `info`, the three names that follow it, and the exporter contexts.
pub(crate) const PROOF: &[u8] = b"veilway v1 proof\0";
pub(crate) const TLS: &[u8] = b"tls\0";
pub(crate) const WS: &[u8] = b"ws\0";
pub(crate) const FRONTED: &[u8] = b"fronted\0";
pub(crate) const FRONTED_SHAPED: &[u8] = b"fronted-shaped\0";
pub(crate) const BINDER: &[u8] = b"veilway v1 binder\0";
pub(crate) const C2S: &[u8] = b"veilway v1 c2s\0";
pub(crate) const S2C: &[u8] = b"veilway v1 s2c\0";
pub(crate) const SID: &[u8] = b"veilway v1 sid\0";
// The borrowed-site mode (`faketls`, its protocol page, "Keys"): the salt of `prk_f`, the three labels of its keys, the label of the hour tag and the one of the associated data.
const FAKETLS: &[u8] = b"veilway v1 faketls\0";
const FAKETLS_SEAL: &[u8] = b"veilway v1 faketls seal\0";
const FAKETLS_BINDER: &[u8] = b"veilway v1 faketls binder\0";
const FAKETLS_NODE: &[u8] = b"veilway v1 faketls node key\0";
const FAKETLS_HOUR: &[u8] = b"veilway v1 faketls hour tag\0";
pub(crate) const FAKETLS_AAD: &[u8] = b"veilway v1 faketls aad\0";
// Node links: the label the pairing hash begins with, and the salt of the link's transport secret.
pub(crate) const LINK_PAIRING: &[u8] = b"veilway v1 link pairing\0";
const LINK_SECRET: &[u8] = b"veilway v1 link secret\0";
// The two values of a pairing's fingerprint: the one the listener's panel shows and the dialler's accepts, and the other way round.
const LINK_LISTENER: &[u8] = b"veilway v1 link listener\0";
const LINK_DIALLER: &[u8] = b"veilway v1 link dialler\0";
// A static mirror (subscription format page, "Keys of a static mirror"): the salt of `prk_m`, the four info labels and the label of the file's associated data. Used nowhere else.
const MIRROR: &[u8] = b"veilway v1 sub mirror\0";
const MIRROR_NAME: &[u8] = b"veilway v1 sub mirror name\0";
const MIRROR_KEY: &[u8] = b"veilway v1 sub mirror key\0";
const MIRROR_ID: &[u8] = b"veilway v1 sub mirror id\0";
const MIRROR_SEAL: &[u8] = b"veilway v1 sub mirror seal\0";
pub(crate) const MIRROR_FILE: &[u8] = b"veilway v1 sub mirror file\0";

// `prk` = HKDF-Extract(salt `"veilway v1 device secret"`, ikm `S`): "Deriving the four keys below, nothing else".
fn prk(secret: &[u8; 32]) -> hkdf::Prk {hkdf::Salt::new(hkdf::HKDF_SHA256, DEVICE_SECRET).extract(secret)}

// The first 16 bytes of an HMAC-SHA-256: both tags and the tag mask.
fn truncated(key: &hmac::Key, parts: &[&[u8]]) -> [u8; 16] {
	let mut context = hmac::Context::with_key(key);
	for part in parts {context.update(part)}
	let mut tag = [0; 16];
	tag.copy_from_slice(&context.sign().as_ref()[..16]);
	tag
}

/// The transport secret of a node link (node links page, "The link's transport secret"): `S` = HKDF(salt `"veilway v1 link secret"`, ikm `shared`, info the pairing hash, 32). `shared` is what X25519 gave for the two pairing keys, and the caller has refused one that is all zero.
/// From here on it is a device transport secret, and goes through `prk` like any other. Its label is its own, so nothing else of the protocol can be made to derive it.
pub fn link_secret(shared: &[u8; 32], pairing_hash: &[u8; 32]) -> [u8; 32] {
	let mut secret = [0; 32];
	hkdf::Salt::new(hkdf::HKDF_SHA256, LINK_SECRET).extract(shared).expand(&[pairing_hash], hkdf::HKDF_SHA256).and_then(|okm| okm.fill(&mut secret)).expect("32 bytes are within the output limit of HKDF-SHA-256");
	secret
}

/// The value of a pairing's fingerprint that the panel of the listener (`listener`) or of the dialler shows: the first 16 bytes of SHA-256(label, pairing hash). Each panel accepts only the other's, so no operator can confirm by typing what their own screen says.
pub fn link_fingerprint(pairing_hash: &[u8; 32], listener: bool) -> [u8; 16] {
	let mut value = [0; 16];
	value.copy_from_slice(&digest(&SHA256, &[if listener {LINK_LISTENER} else {LINK_DIALLER}, &pairing_hash[..]].concat()).as_ref()[..16]);
	value
}

/// `k_ctl`, the key of the control channel credential, for one device transport secret on one inbound.
pub struct ControlKey(hmac::Key);

impl ControlKey {
	/// `k_ctl` = HKDF-Expand(`prk`, `"veilway v1 control" || inbound_pub || device_pub`, 32), as in "Keys derived from the device transport secret".
	/// `secret` is the device transport secret `S`, the other two are WireGuard public keys. The key depends on both, so one device's secret gives another key from another device's tunnel.
	pub fn derive(secret: &[u8; 32], inbound_pub: &[u8; 32], device_pub: &[u8; 32]) -> Self {Self(hmac::Key::from(prk(secret).expand(&[CONTROL, inbound_pub, device_pub], hmac::HMAC_SHA256).expect("32 bytes are within the output limit of HKDF-SHA-256")))}
	pub(crate) fn mac(&self, message: &[u8]) -> [u8; 32] {
		let mut mac = [0; 32];
		mac.copy_from_slice(hmac::sign(&self.0, message).as_ref());
		mac
	}
	/// Compares in constant time.
	pub(crate) fn verify(&self, message: &[u8], mac: &[u8; 32]) -> bool {hmac::verify(&self.0, message, mac).is_ok()}
}

impl fmt::Debug for ControlKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("ControlKey(..)")}
}

/// `k_tag`: "Computing tags, nothing else." A device on two inbounds has different tags on each.
pub struct TagKey(hmac::Key);

impl TagKey {
	/// `k_tag` = HKDF-Expand(`prk`, `"veilway v1 tag" || inbound_pub`, 32).
	pub fn derive(secret: &[u8; 32], inbound_pub: &[u8; 32]) -> Self {Self(hmac::Key::from(prk(secret).expand(&[TAG, inbound_pub], hmac::HMAC_SHA256).expect("32 bytes are within the output limit of HKDF-SHA-256")))}
	/// The device tag, which names the device inside a stream proof: the first 16 bytes of HMAC-SHA-256(`k_tag`, `"veilway v1 device tag"`). "It has no time step and never changes for a given secret."
	pub fn device_tag(&self) -> [u8; 16] {truncated(&self.0, &[DEVICE_TAG])}
	/// The epoch tag, which names the device on a `udp-obfs` opening packet: the first 16 bytes of HMAC-SHA-256(`k_tag`, `"veilway v1 epoch tag" || e`), with the epoch number as 8 bytes, big-endian as every integer on the wire.
	pub fn epoch_tag(&self, epoch: u64) -> [u8; 16] {truncated(&self.0, &[EPOCH_TAG, &epoch.to_be_bytes()])}
	/// The hour tag of `faketls`: the first 16 bytes of HMAC-SHA-256(`k_tag`, `"veilway v1 faketls hour tag" || e`), with `e` the hour (Unix time divided by 3,600) as 8 bytes.
	pub fn hour_tag(&self, hour: u64) -> [u8; 16] {truncated(&self.0, &[FAKETLS_HOUR, &hour.to_be_bytes()])}
}

impl fmt::Debug for TagKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("TagKey(..)")}
}

/// `k_bind`, the key of the binder of the stream proof.
pub struct BinderKey(hmac::Key);

impl BinderKey {
	/// `k_bind` = HKDF-Expand(`prk`, `"veilway v1 proof binder" || inbound_pub || device_pub`, 32).
	pub fn derive(secret: &[u8; 32], inbound_pub: &[u8; 32], device_pub: &[u8; 32]) -> Self {Self(hmac::Key::from(prk(secret).expand(&[PROOF_BINDER, inbound_pub, device_pub], hmac::HMAC_SHA256).expect("32 bytes are within the output limit of HKDF-SHA-256")))}
	/// The first 16 bytes of HMAC-SHA-256 over the parts, which is the binder of `faketls`.
	pub(crate) fn short(&self, parts: &[&[u8]]) -> [u8; 16] {truncated(&self.0, parts)}
	pub(crate) fn mac(&self, message: &[u8]) -> [u8; 32] {
		let mut mac = [0; 32];
		mac.copy_from_slice(hmac::sign(&self.0, message).as_ref());
		mac
	}
	/// Compares in constant time.
	pub(crate) fn verify(&self, message: &[u8], mac: &[u8; 32]) -> bool {
		#[cfg(test)]
		crate::trace::op("hmac verify");
		hmac::verify(&self.0, message, mac).is_ok()
	}
}

impl fmt::Debug for BinderKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("BinderKey(..)")}
}

/// The keys of one `faketls` hello, all from `prk_f` = HKDF-Extract(salt `"veilway v1 faketls"`, ikm `dh`), where `dh` is the X25519 result of the hello's key share `X` and the node's transport key.
pub(crate) struct Borrowed(hkdf::Prk);

impl Borrowed {
	pub(crate) fn new(dh: &[u8; 32]) -> Self {Self(hkdf::Salt::new(hkdf::HKDF_SHA256, FAKETLS).extract(dh))}
	/// `k_seal` = HKDF-Expand(`prk_f`, `"veilway v1 faketls seal" || X || T_pub || inbound_pub`, 32), new for every `X`.
	pub(crate) fn seal(&self, share: &[u8; 32], node: &[u8; 32], inbound: &[u8; 32]) -> ChunkKey {ChunkKey::new(&expand(&self.0, &[FAKETLS_SEAL, share, node, inbound]))}
	/// `b` = HKDF-Expand(`prk_f`, `"veilway v1 faketls binder" || X`, 32), the key the binder is computed from.
	pub(crate) fn binder(&self, share: &[u8; 32]) -> [u8; 32] {expand(&self.0, &[FAKETLS_BINDER, share])}
	/// `node_seed` = HKDF-Expand(`prk_f`, `"veilway v1 faketls node key" || X || carrier`, 40), which makes the node's leaf key.
	pub(crate) fn node_seed(&self, share: &[u8; 32], carrier: &[u8; 64]) -> [u8; 40] {expand(&self.0, &[FAKETLS_NODE, share, carrier])}
}

impl fmt::Debug for Borrowed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Borrowed(..)")}
}

/// `k_obfs`, from which every `udp-obfs` session of a device takes its keys.
pub struct ObfsKey([u8; 32]);

impl ObfsKey {
	/// `k_obfs` = HKDF-Expand(`prk`, `"veilway v1 udp-obfs" || inbound_pub`, 32).
	pub fn derive(secret: &[u8; 32], inbound_pub: &[u8; 32]) -> Self {
		let mut key = [0; 32];
		prk(secret).expand(&[OBFS, inbound_pub], hkdf::HKDF_SHA256).and_then(|okm| okm.fill(&mut key)).expect("32 bytes are within the output limit of HKDF-SHA-256");
		Self(key)
	}
	/// The keys of the session one opening packet starts, and first of them `k_open`: HKDF(`salt`, `k_obfs`, `"veilway v1 udp-obfs open"`, 32). The two keys of the data packets are derived from what this gives, and a node derives them only for a packet that opened.
	pub(crate) fn opening(&self, salt: &[u8; 32]) -> (ChunkKey, Salted) {
		#[cfg(test)]
		crate::trace::op("hkdf open");
		let salted = Salted(hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&self.0));
		(salted.key(OBFS_OPEN), salted)
	}
}

/// HKDF-Extract(`salt`, `k_obfs`): what the keys of one `udp-obfs` session are expanded from.
pub(crate) struct Salted(hkdf::Prk);

impl Salted {
	fn key(&self, label: &[u8]) -> ChunkKey {ChunkKey(aead::LessSafeKey::new(self.0.expand(&[label], &aead::CHACHA20_POLY1305).expect("32 bytes are within the output limit of HKDF-SHA-256").into()))}
	/// `k_c2s` and `k_s2c`: "The same with `"veilway v1 udp-obfs c2s"` and `"veilway v1 udp-obfs s2c"`."
	pub(crate) fn data(&self) -> [ChunkKey; 2] {
		#[cfg(test)]
		crate::trace::op("hkdf data");
		[self.key(OBFS_C2S), self.key(OBFS_S2C)]
	}
}

impl fmt::Debug for Salted {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Salted(..)")}
}

impl fmt::Debug for ObfsKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("ObfsKey(..)")}
}

/// `k_mask`, which hides the epoch tag of a `udp-obfs` opening packet on the wire. It comes from the inbound's public key and from no secret, so every device of the inbound has it, and so has everyone who holds a subscription of the inbound.
pub struct MaskKey(hmac::Key);

impl MaskKey {
	/// `k_mask` = HKDF(salt `"veilway v1 udp-obfs mask"`, ikm `inbound_pub`, info empty, 32).
	pub fn derive(inbound_pub: &[u8; 32]) -> Self {Self(hmac::Key::from(hkdf::Salt::new(hkdf::HKDF_SHA256, OBFS_MASK).extract(inbound_pub).expand(&[], hmac::HMAC_SHA256).expect("32 bytes are within the output limit of HKDF-SHA-256")))}
	/// The mask of one opening packet: the first 16 bytes of HMAC-SHA-256(`k_mask`, `salt`).
	pub(crate) fn mask(&self, salt: &[u8; 32]) -> [u8; 16] {
		#[cfg(test)]
		crate::trace::op("hmac mask");
		truncated(&self.0, &[salt])
	}
}

impl fmt::Debug for MaskKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("MaskKey(..)")}
}

/// The key of one direction of a session, for sealing or opening its chunks ("The chunk"). A stream proof and a `udp-obfs` opening packet give two of them each. `new` is for a caller that has key bytes from elsewhere.
pub struct ChunkKey(pub(crate) aead::LessSafeKey);

impl ChunkKey {
	pub fn new(key: &[u8; 32]) -> Self {Self(aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).expect("a ChaCha20-Poly1305 key is 32 bytes")))}
}

impl fmt::Debug for ChunkKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("ChunkKey(..)")}
}

/// What a node's tag table holds for one tag: the device the tag names, and the keys of the one transport secret the tag came from ("How the node finds the device"). A device with two secrets has two of these.
pub struct Device<T> {
	/// Whatever the caller needs to find its own record of the device and of the secret.
	pub id: T,
	/// `device_pub`, the WireGuard public key of the device.
	pub public: [u8; 32],
	pub(crate) binder: BinderKey,
	pub(crate) obfs: ObfsKey,
}

impl<T> Device<T> {
	pub fn derive(id: T, secret: &[u8; 32], inbound_pub: &[u8; 32], device_pub: &[u8; 32]) -> Self {Self {id, public: *device_pub, binder: BinderKey::derive(secret, inbound_pub, device_pub), obfs: ObfsKey::derive(secret, inbound_pub)}}
}

impl<T: fmt::Debug> fmt::Debug for Device<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Device({:?}, ..)", self.id)}
}

/// The node's table from tag to device: "one device tag per device secret, and one epoch tag per device secret for each of the previous, current and next epoch", built by the caller from `TagKey` and swapped in whole.
/// The two kinds of tag are kept apart: a device tag is valid only in a stream proof and an epoch tag only on an opening packet, so a tag of one kind is unknown where the other is asked for.
/// Each method must be one lookup whatever the number of devices, never a scan: the work per proof must not grow with the number of users or depend on which user it is.
pub trait Tags<T> {
	/// The device a stream proof names by its device tag.
	fn find_device(&self, tag: &[u8; 16]) -> Option<&Device<T>>;
	/// The device a `udp-obfs` opening packet names by an epoch tag of an epoch the node accepts now.
	fn find_epoch(&self, tag: &[u8; 16]) -> Option<&Device<T>>;
	/// The device a `faketls` hello names by an hour tag of an hour the node accepts now.
	fn find_hour(&self, tag: &[u8; 16]) -> Option<&Device<T>>;
}

/// A tag table over two hash maps, for a caller that needs no other. `V` is a `Device` or anything that lends one, such as an `Arc` of a device that several tags name.
/// A lookup that hits compares the 16 bytes of the tag with an ordinary comparison. A tag is no secret from whoever can put one in front of this table: it is inside a proof sealed to the node, or masked with a key every subscriber of the inbound has.
pub struct Table<V> {devices: HashMap<[u8; 16], V>, epochs: HashMap<[u8; 16], V>, hours: HashMap<[u8; 16], V>}

impl<V> Table<V> {
	pub fn new() -> Self {Self {devices: HashMap::new(), epochs: HashMap::new(), hours: HashMap::new()}}
	/// Adds the device tag of one device secret. `false`, and nothing added, when the tag is in the table already as any kind: "Validation refuses a config in which two tags of one inbound are equal."
	#[must_use = "a tag that was not added is a config that validation must refuse"]
	pub fn device(&mut self, tag: [u8; 16], entry: V) -> bool {!self.epochs.contains_key(&tag) && !self.hours.contains_key(&tag) && !self.devices.contains_key(&tag) && self.devices.insert(tag, entry).is_none()}
	/// Adds the epoch tag of one device secret for one epoch, under the same rule.
	#[must_use = "a tag that was not added is a config that validation must refuse"]
	pub fn epoch(&mut self, tag: [u8; 16], entry: V) -> bool {!self.devices.contains_key(&tag) && !self.epochs.contains_key(&tag) && !self.hours.contains_key(&tag) && self.epochs.insert(tag, entry).is_none()}
	/// Adds the hour tag of one device secret for one hour of `faketls`, under the same rule.
	#[must_use = "a tag that was not added is a config that validation must refuse"]
	pub fn hour(&mut self, tag: [u8; 16], entry: V) -> bool {!self.devices.contains_key(&tag) && !self.epochs.contains_key(&tag) && !self.hours.contains_key(&tag) && self.hours.insert(tag, entry).is_none()}
	/// The number of tags, of all kinds.
	pub fn len(&self) -> usize {self.devices.len() + self.epochs.len() + self.hours.len()}
	pub fn is_empty(&self) -> bool {self.devices.is_empty() && self.epochs.is_empty() && self.hours.is_empty()}
}

impl<V> Default for Table<V> {
	fn default() -> Self {Self::new()}
}

impl<V> fmt::Debug for Table<V> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Table({} device tags, {} epoch tags, {} hour tags)", self.devices.len(), self.epochs.len(), self.hours.len())}
}

impl<T, V: Borrow<Device<T>>> Tags<T> for Table<V> {
	fn find_device(&self, tag: &[u8; 16]) -> Option<&Device<T>> {self.devices.get(tag).map(Borrow::borrow)}
	fn find_epoch(&self, tag: &[u8; 16]) -> Option<&Device<T>> {self.epochs.get(tag).map(Borrow::borrow)}
	fn find_hour(&self, tag: &[u8; 16]) -> Option<&Device<T>> {self.hours.get(tag).map(Borrow::borrow)}
}

// An HKDF-Expand output of `N` bytes, for the one derivation that is not 32 long.
struct Output<const N: usize>;

impl<const N: usize> hkdf::KeyType for Output<N> {
	fn len(&self) -> usize {N}
}

fn expand<const N: usize>(prk: &hkdf::Prk, info: &[&[u8]]) -> [u8; N] {
	let mut out = [0; N];
	prk.expand(info, Output::<N>).and_then(|okm| okm.fill(&mut out)).expect("up to 32 bytes are within the output limit of HKDF-SHA-256");
	out
}

/// The key and the nonce of an answer of the subscription endpoint (subscription format page, "Sealing an answer"): `prk = Extract(enc || response_nonce, secret)`, `key = Expand(prk, "key", 32)` and `nonce = Expand(prk, "nonce", 12)`, with the labels of RFC 9458 as ASCII with no zero byte. `enc` is the one HPKE made, with its top bit clear.
pub(crate) fn answer(enc: &[u8; 32], response_nonce: &[u8; 32], secret: &[u8; 32]) -> (ChunkKey, [u8; 12]) {
	let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[&enc[..], &response_nonce[..]].concat()).extract(secret);
	(ChunkKey::new(&expand(&prk, &[b"key"])), expand(&prk, &[b"nonce"]))
}

/// `k_name` and `k_mirror` of one device on a static mirror (subscription format page, "Keys of a static mirror"). The panel keeps both, sealed, after a request that carried the token and the device secret, and a client derives them from its own link, key and secret. Neither gives a way back to the token or the secret. `prk_m` is not kept.
/// The bytes can be read for the one place that stores them sealed (`expose`) and for nothing else: the type prints nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct MirrorKeys {name: [u8; 32], key: [u8; 32]}

impl MirrorKeys {
	/// `prk_m` = HKDF-Extract(salt `"veilway v1 sub mirror"`, ikm `token_bytes || secret_bytes`), then `k_name` and `k_mirror` = HKDF-Expand(`prk_m`, label `|| device_pub`, 32). `device_pub` is the `device_public_key` of the device's requests.
	pub fn derive(token: &[u8; 16], secret: &[u8; 16], device_pub: &[u8; 32]) -> Self {
		let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, MIRROR).extract(&[&token[..], &secret[..]].concat());
		Self {name: expand(&prk, &[MIRROR_NAME, device_pub]), key: expand(&prk, &[MIRROR_KEY, device_pub])}
	}
	/// The two keys out of the panel's sealed storage.
	pub fn restore(name: [u8; 32], key: [u8; 32]) -> Self {Self {name, key}}
	/// `k_name` and `k_mirror`, in that order, for the storage that seals them.
	pub fn expose(&self) -> (&[u8; 32], &[u8; 32]) {(&self.name, &self.key)}
	/// `mirror_id` = HKDF-Expand(`k_name`, `"veilway v1 sub mirror id" || be64(epoch) || base_url`, 16): the name of the device's file for that period on the static mirror of `base_url`, exactly as the document's string holds it.
	pub fn id(&self, epoch: u64, base_url: impl AsRef<[u8]>) -> [u8; 16] {expand(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &self.name), &[MIRROR_ID, &epoch.to_be_bytes(), base_url.as_ref()])}
	/// `k_file` = HKDF-Expand(`k_mirror`, `"veilway v1 sub mirror seal" || salt`, 32): the key of one write of a file, used once.
	pub(crate) fn file(&self, salt: &[u8; 32]) -> ChunkKey {ChunkKey::new(&expand(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &self.key), &[MIRROR_SEAL, salt]))}
}

impl fmt::Debug for MirrorKeys {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("MirrorKeys(..)")}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	fn inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {(std::array::from_fn(|i| i as u8), std::array::from_fn(|i| 32 + i as u8), std::array::from_fn(|i| 64 + i as u8))}

	// Expected values come from a script that uses only Python's hmac and hashlib: S = 00..1f, inbound_pub = 20..3f, device_pub = 40..5f, k_ctl = 1e0517b5...2aeb6b02.
	#[test]
	fn the_control_key_is_the_one_the_specification_derives() {
		let (secret, inbound, device) = inputs();
		let key = ControlKey::derive(&secret, &inbound, &device);
		assert_eq!(hex(&key.mac(b"abc")), "9b048343d8a5dd4aebee37c5596697f6f10b2a92f70d6112963a23548d2aab88");
		assert!(key.verify(b"abc", &key.mac(b"abc")));
		assert!(!key.verify(b"abd", &key.mac(b"abc")));
	}

	// Expected values come from tests/vectors.py, with the same three inputs, the epoch number 0x0102030405060708 and a salt of 0xa5 bytes. A key cannot be read back, so each is shown by what it computes.
	#[test]
	fn the_other_keys_are_the_ones_the_specification_derives() {
		let (secret, inbound, device) = inputs();
		let tags = TagKey::derive(&secret, &inbound);
		assert_eq!(hex(&tags.device_tag()), "e54629ca7b9c437e8bfbf420d0af199a");
		assert_eq!(hex(&tags.epoch_tag(0x0102030405060708)), "1b1236bd8d22f2a3ed7b784ed51e108d");
		assert_eq!(hex(&BinderKey::derive(&secret, &inbound, &device).mac(b"abc")), "f6e680b0738b4c46849eaf7bbd1bf58bd0cc4fa414b3b1473cecf8f7e2ffa4fb");
		assert_eq!(hex(&MaskKey::derive(&inbound).mask(&[0xa5; 32])), "5019ba71df2674837a3bc752d51cfd01");
		let (open, salted) = ObfsKey::derive(&secret, &inbound).opening(&[0xa5; 32]);
		let [c2s, s2c] = salted.data();
		let sealed = [open, c2s, s2c].map(|key| {
			let mut sealed = b"abc".to_vec();
			let tag = key.0.seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key([0; 12]), aead::Aad::empty(), &mut sealed).unwrap();
			hex(&[&sealed[..], tag.as_ref()].concat())
		});
		assert_eq!(sealed, ["052bf2d58442db33ce31af96472389b1f7f3d8", "50bc03e6aaf2a4e43c61c36d660d827d136679", "93a7f28d1181f27cee9e54fa2bfb8754d868c3"]);
	}

	#[test]
	fn a_key_changes_with_every_input() {
		let (secret, inbound, device) = ([1; 32], [2; 32], [3; 32]);
		let mac = ControlKey::derive(&secret, &inbound, &device).mac(b"");
		for other in [ControlKey::derive(&[9; 32], &inbound, &device), ControlKey::derive(&secret, &[9; 32], &device), ControlKey::derive(&secret, &inbound, &[9; 32]), ControlKey::derive(&secret, &device, &inbound)] {assert_ne!(other.mac(b""), mac)}
		let mac = BinderKey::derive(&secret, &inbound, &device).mac(b"");
		for other in [BinderKey::derive(&[9; 32], &inbound, &device), BinderKey::derive(&secret, &[9; 32], &device), BinderKey::derive(&secret, &inbound, &[9; 32]), BinderKey::derive(&secret, &device, &inbound)] {assert_ne!(other.mac(b""), mac)}
		let tag = TagKey::derive(&secret, &inbound).device_tag();
		for other in [TagKey::derive(&[9; 32], &inbound), TagKey::derive(&secret, &[9; 32])] {assert_ne!(other.device_tag(), tag)}
		assert_ne!(MaskKey::derive(&inbound).mask(&[0; 32]), MaskKey::derive(&[9; 32]).mask(&[0; 32]));
		assert_ne!(MaskKey::derive(&inbound).mask(&[0; 32]), MaskKey::derive(&inbound).mask(&[1; 32]));
	}

	// One purpose per key: no two keys of a device are equal, and the two tags of one key differ from each other and between epochs.
	#[test]
	fn the_keys_of_one_secret_are_all_different() {
		let (secret, inbound, device) = inputs();
		let macs = [ControlKey::derive(&secret, &inbound, &device).mac(b""), BinderKey::derive(&secret, &inbound, &device).mac(b""), hmac::sign(&TagKey::derive(&secret, &inbound).0, b"").as_ref().try_into().unwrap(), hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &ObfsKey::derive(&secret, &inbound).0), b"").as_ref().try_into().unwrap()];
		for (index, mac) in macs.iter().enumerate() {assert!(!macs[..index].contains(mac))}
		let tags = TagKey::derive(&secret, &inbound);
		assert_ne!(tags.device_tag(), tags.epoch_tag(0));
		assert_ne!(tags.epoch_tag(0), tags.epoch_tag(1));
	}

	#[test]
	fn a_key_does_not_print_itself() {
		let (secret, inbound, device) = inputs();
		assert_eq!(format!("{:?}", ControlKey::derive(&secret, &inbound, &device)), "ControlKey(..)");
		assert_eq!(format!("{:?}", TagKey::derive(&secret, &inbound)), "TagKey(..)");
		assert_eq!(format!("{:?}", BinderKey::derive(&secret, &inbound, &device)), "BinderKey(..)");
		assert_eq!(format!("{:?}", ObfsKey::derive(&secret, &inbound)), "ObfsKey(..)");
		assert_eq!(format!("{:?}", MaskKey::derive(&inbound)), "MaskKey(..)");
		assert_eq!(format!("{:?}", ChunkKey::new(&secret)), "ChunkKey(..)");
		assert_eq!(format!("{:?}", Device::derive(7, &secret, &inbound, &device)), "Device(7, ..)");
	}

	#[test]
	fn a_table_keeps_the_two_kinds_of_tag_apart() {
		let (secret, inbound, device) = inputs();
		let (tags, entry, mut table) = (TagKey::derive(&secret, &inbound), std::sync::Arc::new(Device::derive(7, &secret, &inbound, &device)), Table::new());
		assert!(table.is_empty() && table.device(tags.device_tag(), entry.clone()) && table.epoch(tags.epoch_tag(5), entry.clone()));
		assert_eq!(table.find_device(&tags.device_tag()).map(|device| (device.id, device.public)), Some((7, device)));
		assert_eq!(table.find_epoch(&tags.epoch_tag(5)).map(|device| device.id), Some(7));
		// A tag of one kind is unknown where the other is asked for.
		assert!(table.find_epoch(&tags.device_tag()).is_none() && table.find_device(&tags.epoch_tag(5)).is_none() && table.find_epoch(&tags.epoch_tag(6)).is_none());
		// "Validation refuses a config in which two tags of one inbound are equal": a tag is taken once, as either kind.
		for tag in [tags.device_tag(), tags.epoch_tag(5)] {assert!(!table.device(tag, entry.clone()) && !table.epoch(tag, entry.clone()))}
		assert_eq!((table.len(), format!("{table:?}")), (2, "Table(1 device tags, 1 epoch tags, 0 hour tags)".to_owned()));
	}
}
