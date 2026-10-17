//! ML-KEM-768 (FIPS 203) for the hybrid group X25519MLKEM768 of `faketls`, from BoringSSL, the library this crate already builds for the hello. No cryptography is written here: these are the library's own functions, called with buffers of the sizes it documents.
//! The client makes a key and keeps its seed, and takes the shared secret out of the node's ciphertext. The node, which is the other caller (`veilway-core`), encapsulates to the key in the client's hello.
#![allow(unsafe_code)]
use boring_sys::{MLKEM768_decap, MLKEM768_encap, MLKEM768_generate_key, MLKEM768_parse_public_key, MLKEM768_private_key, MLKEM768_private_key_from_seed, MLKEM768_public_key, CBS};
use std::mem::MaybeUninit;
use zeroize::Zeroize;
use veilway_proto::tls13::{KEM_CIPHERTEXT, KEM_KEY};

/// The length of the seed a private key is made from again.
pub const SEED: usize = 64;

/// A new key: its encapsulation key, as a hello carries it, and the seed its private key is made from.
pub fn generate() -> ([u8; KEM_KEY], [u8; SEED]) {
	let (mut key, mut seed, mut private) = ([0; KEM_KEY], [0; SEED], MaybeUninit::<MLKEM768_private_key>::uninit());
	// SAFETY: the buffers have the lengths the function writes, and it writes the whole private key, which is not read here.
	unsafe {MLKEM768_generate_key(key.as_mut_ptr(), seed.as_mut_ptr(), private.as_mut_ptr())};
	// SAFETY: the private key is plain bytes, written above, and is wiped before it goes out of scope.
	unsafe {std::ptr::write_bytes(private.as_mut_ptr(), 0, 1)};
	(key, seed)
}

/// The shared secret in a ciphertext, for the key `seed` made. None for a ciphertext of another length. A ciphertext that is wrong gives a secret nobody else has, as the library documents, and the handshake's own checks fail on it.
pub fn decap(seed: &[u8; SEED], ciphertext: &[u8]) -> Option<[u8; 32]> {
	let (mut private, mut secret) = (MaybeUninit::<MLKEM768_private_key>::uninit(), [0u8; 32]);
	// SAFETY: the seed has the length it is given with, and the private key is read only after the library wrote it and said so.
	if unsafe {MLKEM768_private_key_from_seed(private.as_mut_ptr(), seed.as_ptr(), SEED)} != 1 {return None}
	// SAFETY: the secret has the length the function writes, the ciphertext is given with its own length, and the private key was written above.
	let done = unsafe {MLKEM768_decap(secret.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len(), private.as_ptr())} == 1;
	// SAFETY: as in `generate`.
	unsafe {std::ptr::write_bytes(private.as_mut_ptr(), 0, 1)};
	if !done {secret.zeroize()}
	done.then_some(secret)
}

/// A ciphertext for the encapsulation key `key` and the shared secret it holds. None for a key that is not one.
pub fn encap(key: &[u8]) -> Option<([u8; KEM_CIPHERTEXT], [u8; 32])> {
	if key.len() != KEM_KEY {return None}
	let (mut cbs, mut public, mut ciphertext, mut secret) = (CBS {data: key.as_ptr(), len: key.len()}, MaybeUninit::<MLKEM768_public_key>::uninit(), [0; KEM_CIPHERTEXT], [0; 32]);
	// SAFETY: the byte string points at `key`, which outlives it, and the library writes the public key only when it says it parsed one.
	if unsafe {MLKEM768_parse_public_key(public.as_mut_ptr(), &mut cbs)} != 1 {return None}
	// SAFETY: the buffers have the lengths the function writes, and the public key was written above.
	unsafe {MLKEM768_encap(ciphertext.as_mut_ptr(), secret.as_mut_ptr(), public.as_ptr())};
	Some((ciphertext, secret))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn what_one_side_encapsulates_the_other_decapsulates_and_nothing_else_does() {
		let ((key, seed), (other, other_seed)) = (generate(), generate());
		let (ciphertext, secret) = encap(&key).unwrap();
		assert_eq!(decap(&seed, &ciphertext), Some(secret));
		assert_ne!(decap(&other_seed, &ciphertext), Some(secret));
		assert_ne!(key, other);
		assert!(decap(&seed, &ciphertext[1..]).is_none() && encap(&key[1..]).is_none());
	}
}
