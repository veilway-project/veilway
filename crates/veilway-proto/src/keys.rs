//! Keys, and every label of the protocol (transports page, "Keys derived from the device transport secret").
//!
//! A key lives inside the opaque key type of `ring` from the moment it is made. This crate keeps no key bytes of its own, so the types here cannot print a key, cannot be copied and cannot be compared. They are not zeroed on drop: `ring` does not zero its key types, and doing it from outside would need `unsafe` or a dependency.
use ring::{aead, hkdf, hmac};
use std::fmt;

// A label in double quotes is its ASCII bytes followed by one zero byte (transports page, "Building blocks"). Labels are written here and nowhere else.
const DEVICE_SECRET: &[u8] = b"veilway v1 device secret\0";
const CONTROL: &[u8] = b"veilway v1 control\0";
pub(crate) const CONTROL_AUTH: &[u8] = b"veilway v1 control auth\0";

/// `k_ctl`, the key of the control channel credential, for one device transport secret on one inbound.
pub struct ControlKey(hmac::Key);

impl ControlKey {
	/// `prk` = HKDF-Extract(salt `"veilway v1 device secret"`, ikm `S`), then `k_ctl` = HKDF-Expand(`prk`, `"veilway v1 control" || inbound_pub || device_pub`, 32), as in "Keys derived from the device transport secret".
	/// `secret` is the device transport secret `S`, the other two are WireGuard public keys. The key depends on both, so one device's secret gives another key from another device's tunnel.
	pub fn derive(secret: &[u8; 32], inbound_pub: &[u8; 32], device_pub: &[u8; 32]) -> Self {
		let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, DEVICE_SECRET).extract(secret);
		Self(hmac::Key::from(prk.expand(&[CONTROL, inbound_pub, device_pub], hmac::HMAC_SHA256).expect("32 bytes are within the output limit of HKDF-SHA-256")))
	}
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

/// The key of one direction of a session, for sealing or opening its chunks ("The chunk"). Where it comes from belongs to the transport: this crate derives none.
pub struct ChunkKey(pub(crate) aead::LessSafeKey);

impl ChunkKey {
	pub fn new(key: &[u8; 32]) -> Self {Self(aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).expect("a ChaCha20-Poly1305 key is 32 bytes")))}
}

impl fmt::Debug for ChunkKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("ChunkKey(..)")}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	// Expected values come from a script that uses only Python's hmac and hashlib: S = 00..1f, inbound_pub = 20..3f, device_pub = 40..5f, k_ctl = 1e0517b5...2aeb6b02.
	#[test]
	fn the_control_key_is_the_one_the_specification_derives() {
		let (secret, inbound, device): ([u8; 32], [u8; 32], [u8; 32]) = (std::array::from_fn(|i| i as u8), std::array::from_fn(|i| 32 + i as u8), std::array::from_fn(|i| 64 + i as u8));
		let key = ControlKey::derive(&secret, &inbound, &device);
		assert_eq!(hex(&key.mac(b"abc")), "9b048343d8a5dd4aebee37c5596697f6f10b2a92f70d6112963a23548d2aab88");
		assert!(key.verify(b"abc", &key.mac(b"abc")));
		assert!(!key.verify(b"abd", &key.mac(b"abc")));
	}

	#[test]
	fn the_key_changes_with_every_input() {
		let (secret, inbound, device) = ([1; 32], [2; 32], [3; 32]);
		let mac = ControlKey::derive(&secret, &inbound, &device).mac(b"");
		for other in [ControlKey::derive(&[9; 32], &inbound, &device), ControlKey::derive(&secret, &[9; 32], &device), ControlKey::derive(&secret, &inbound, &[9; 32]), ControlKey::derive(&secret, &device, &inbound)] {assert_ne!(other.mac(b""), mac)}
	}

	#[test]
	fn a_key_does_not_print_itself() {
		assert_eq!(format!("{:?}", ControlKey::derive(&[7; 32], &[8; 32], &[9; 32])), "ControlKey(..)");
		assert_eq!(format!("{:?}", ChunkKey::new(&[7; 32])), "ChunkKey(..)");
	}
}
