//! The vault: the subscriptions' secrets (the link's token, the device's private key, the transport secrets) in one file that is encrypted, with its key kept in the system keychain (`/Library/Keychains/System.keychain`), where a copy of the file or of its folder does not reach. There is no plain text mode: a system where the keychain cannot hold the key gets no vault, and says so.
//!
//! A client that runs as root has no login session, so the key is a generic password item of the system keychain, which root can use without a prompt (the user interaction is switched off for the calls, so that a keychain that would ask fails instead of waiting for a window nobody sees). The item is made by this program and is readable by it without a prompt; another program, or this one replaced by a build with another signature, is asked by the system, and here that is a failure that says so. The key is 32 random bytes. The vault is then useless to anyone who has only the file, and not to root, which can read the keychain.
//!
//! The file is `VWM1`, one byte for where the key is (only the system keychain, 1, so far), a fresh random nonce of 12 bytes and the ChaCha20-Poly1305 ciphertext of the vault bytes, whose header is authenticated. A key that is not in the keychain for a vault that exists is an error: a new key is never made for it, since that would orphan what is in the file. The vault is the same bytes as on every other system (`veilway_engine::import::write_vault`).
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
use std::io;
use std::path::PathBuf;
use veilway_engine::import::{read_vault, write_vault, Vault};
use veilway_engine::store::{read_limited, write_atomic};
use veilway_proto::subscription::client::Stored;
use veilway_proto::subscription::BODY_MAX;

const MAGIC: &[u8; 4] = b"VWM1";
const HEADER: usize = 5;
const NONCE: usize = 12;
const TAG: usize = 16;
const FILE_MAX: usize = 64 * BODY_MAX + 64;
/// The keychain item: its service and account.
const SERVICE: &str = "com.veilway.client";
const ACCOUNT: &str = "vault-key";
#[cfg(target_os = "macos")]
const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
/// The only place a key is kept so far.
const KEYCHAIN: u8 = 1;
/// errSecItemNotFound.
#[cfg(target_os = "macos")]
const NOT_FOUND: i32 = -25300;

/// Where the key can be put and found. Real behind `Keychain`; a test puts its own.
pub trait Keys: Send + Sync {
	fn fetch(&self) -> io::Result<Option<[u8; 32]>>;
	fn create(&self, key: &[u8; 32]) -> io::Result<()>;
}

fn seal(key: &[u8; 32], plain: &[u8]) -> io::Result<Vec<u8>> {
	let mut nonce = [0u8; NONCE];
	SystemRandom::new().fill(&mut nonce).map_err(|_| io::Error::other("the system gave no random bytes"))?;
	let mut out = [&MAGIC[..], &[KEYCHAIN]].concat();
	let mut buffer = plain.to_vec();
	LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| io::Error::other("no cipher"))?).seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&out[..HEADER]), &mut buffer).map_err(|_| io::Error::other("the vault could not be encrypted"))?;
	out.extend_from_slice(&nonce);
	out.extend_from_slice(&buffer);
	Ok(out)
}

fn open(key: &[u8; 32], file: &[u8]) -> io::Result<Vec<u8>> {
	let bad = || io::Error::new(io::ErrorKind::InvalidData, "the vault file does not decrypt: it is damaged, or its key is not the one it was made with");
	if file.len() < HEADER + NONCE + TAG {return Err(bad())}
	let (nonce, mut buffer) = (Nonce::try_assume_unique_for_key(&file[HEADER..HEADER + NONCE]).map_err(|_| bad())?, file[HEADER + NONCE..].to_vec());
	let plain = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| bad())?).open_in_place(nonce, Aad::from(&file[..HEADER]), &mut buffer).map_err(|_| bad())?.len();
	buffer.truncate(plain);
	Ok(buffer)
}

fn check_header(file: &[u8]) -> io::Result<()> {
	if file.len() < HEADER || &file[..4] != MAGIC {return Err(io::Error::new(io::ErrorKind::InvalidData, "this is not an encrypted Veilway vault"))}
	if file[4] != KEYCHAIN {return Err(io::Error::new(io::ErrorKind::InvalidData, "the vault names a place for its key that this version does not know"))}
	Ok(())
}

pub struct SecretVault {path: PathBuf, keys: Box<dyn Keys>}

impl SecretVault {
	#[cfg(target_os = "macos")]
	pub fn new(path: impl Into<PathBuf>) -> Self {Self::with(path, Box::new(Keychain))}
	pub fn with(path: impl Into<PathBuf>, keys: Box<dyn Keys>) -> Self {Self {path: path.into(), keys}}
	fn missing(error: Option<io::Error>) -> io::Error {io::Error::new(io::ErrorKind::NotFound, format!("the vault's key is not in the system keychain{}. The vault cannot be read; the subscriptions in it must be imported again", error.map_or_else(String::new, |error| format!(" ({error})"))))}
	// The key of the vault: the one in the keychain, or, when there is no vault yet, a new one made and kept there first.
	fn key_for_write(&self, existing: bool) -> io::Result<[u8; 32]> {
		if let Some(key) = self.keys.fetch().map_err(|error| Self::missing(Some(error)))? {return Ok(key)}
		if existing {return Err(Self::missing(None))}
		let mut key = [0u8; 32];
		SystemRandom::new().fill(&mut key).map_err(|_| io::Error::other("the system gave no random bytes"))?;
		self.keys.create(&key).map_err(|error| io::Error::new(error.kind(), format!("there is no safe place for the vault's key: the system keychain refused it ({error}). No vault is written")))?;
		Ok(key)
	}
	fn read_file(&self) -> io::Result<Option<Vec<u8>>> {
		match read_limited(&self.path, FILE_MAX) {
			Ok(bytes) if bytes.len() > FILE_MAX => Err(io::Error::new(io::ErrorKind::InvalidData, "the vault file is larger than any vault")),
			Ok(bytes) => Ok(Some(bytes)),
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(error),
		}
	}
}

impl Vault for SecretVault {
	fn load(&self) -> io::Result<Vec<Stored>> {
		let Some(file) = self.read_file()? else {return Ok(Vec::new())};
		check_header(&file)?;
		let key = self.keys.fetch().map_err(|error| Self::missing(Some(error)))?.ok_or_else(|| Self::missing(None))?;
		read_vault(&open(&key, &file)?)
	}
	fn save(&self, held: &[Stored]) -> io::Result<()> {
		let existing = self.read_file()?;
		if let Some(file) = &existing {check_header(file)?}
		let key = self.key_for_write(existing.is_some())?;
		write_atomic(&self.path, &seal(&key, &write_vault(held))?)
	}
}

/// The system keychain's item for the key.
#[cfg(target_os = "macos")]
pub struct Keychain;

#[cfg(target_os = "macos")]
impl Keychain {
	// The system keychain, with the system's windows switched off for the calls: as root there is nobody to answer one.
	fn chain() -> io::Result<(SecKeychain, KeychainUserInteractionLock)> {
		let lock = SecKeychain::disable_user_interaction().map_err(io::Error::other)?;
		Ok((SecKeychain::open(SYSTEM_KEYCHAIN).map_err(io::Error::other)?, lock))
	}
}

#[cfg(target_os = "macos")]
impl Keys for Keychain {
	fn fetch(&self) -> io::Result<Option<[u8; 32]>> {
		let (chain, _quiet) = Self::chain()?;
		match chain.find_generic_password(SERVICE, ACCOUNT) {
			Ok((password, _item)) => <[u8; 32]>::try_from(&*password).map(Some).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the keychain's item for the vault key is not 32 bytes")),
			Err(error) if error.code() == NOT_FOUND => Ok(None),
			Err(error) => Err(io::Error::other(error)),
		}
	}
	fn create(&self, key: &[u8; 32]) -> io::Result<()> {
		let (chain, _quiet) = Self::chain()?;
		chain.set_generic_password(SERVICE, ACCOUNT, key).map_err(io::Error::other)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Arc, Mutex};

	// A keychain in memory that takes or refuses a key.
	struct Fake {has: Mutex<Option<[u8; 32]>>, takes: bool}

	impl Keys for Arc<Fake> {
		fn fetch(&self) -> io::Result<Option<[u8; 32]>> {Ok(*self.has.lock().unwrap())}
		fn create(&self, key: &[u8; 32]) -> io::Result<()> {
			if !self.takes {return Err(io::Error::other("no"))}
			*self.has.lock().unwrap() = Some(*key);
			Ok(())
		}
	}

	fn path(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-mac-vault-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir.join("vault")
	}

	#[test]
	fn what_is_sealed_opens_with_the_key_and_with_nothing_else() {
		let (key, other) = ([7u8; 32], [8u8; 32]);
		let file = seal(&key, b"secrets").unwrap();
		assert_eq!(&file[..5], b"VWM1\x01");
		assert_eq!(open(&key, &file).unwrap(), b"secrets");
		assert!(open(&other, &file).is_err());
		assert!(!file.windows(7).any(|window| window == b"secrets"));
		let mut flipped = file.clone();
		*flipped.last_mut().unwrap() ^= 1;
		assert!(open(&key, &flipped).is_err());
		let mut renamed = file.clone();
		renamed[4] = 2;
		assert!(open(&key, &renamed).is_err(), "the header is authenticated");
		assert_ne!(seal(&key, b"secrets").unwrap(), file, "a fresh nonce at every write");
	}

	#[test]
	fn the_header_is_checked_before_anything_is_decrypted() {
		assert!(check_header(&seal(&[1u8; 32], b"").unwrap()).is_ok());
		assert!(check_header(b"[]").is_err() && check_header(b"VWM1\x09").is_err() && check_header(b"").is_err());
		assert!(check_header(b"VWV1\x01").is_err(), "the Linux vault is another format");
		assert!(open(&[1u8; 32], b"VWM1\x01short").is_err());
	}

	#[test]
	fn a_first_save_makes_the_key_in_the_keychain_and_the_next_load_asks_it() {
		let keychain = Arc::new(Fake {has: Mutex::default(), takes: true});
		let vault = SecretVault::with(path("first"), Box::new(keychain.clone()));
		assert!(vault.load().unwrap().is_empty());
		assert!(keychain.has.lock().unwrap().is_none(), "reading a missing vault makes no key");
		vault.save(&[]).unwrap();
		assert!(keychain.has.lock().unwrap().is_some());
		assert_eq!(&std::fs::read(&vault.path).unwrap()[..4], b"VWM1");
		assert!(vault.load().unwrap().is_empty());
		vault.save(&[]).unwrap();
	}

	#[test]
	fn a_keychain_that_refuses_the_key_gets_no_vault_and_no_file() {
		let vault = SecretVault::with(path("refused"), Box::new(Arc::new(Fake {has: Mutex::default(), takes: false})));
		let error = vault.save(&[]).unwrap_err();
		assert!(error.to_string().contains("no safe place") && error.to_string().contains("system keychain"), "{error}");
		assert!(!vault.path.exists());
	}

	#[test]
	fn a_vault_whose_key_is_gone_is_not_read_or_written_over_with_a_new_key() {
		let keychain = Arc::new(Fake {has: Mutex::default(), takes: true});
		let vault = SecretVault::with(path("gone"), Box::new(keychain.clone()));
		vault.save(&[]).unwrap();
		let before = std::fs::read(&vault.path).unwrap();
		*keychain.has.lock().unwrap() = None;
		assert!(vault.load().unwrap_err().to_string().contains("imported again"));
		assert!(vault.save(&[]).is_err());
		assert!(keychain.has.lock().unwrap().is_none(), "no new key for a vault that exists");
		assert_eq!(std::fs::read(&vault.path).unwrap(), before);
	}

	#[test]
	fn a_file_that_is_not_a_vault_is_not_written_over() {
		let vault = SecretVault::with(path("foreign"), Box::new(Arc::new(Fake {has: Mutex::default(), takes: true})));
		std::fs::write(&vault.path, b"[{\"plain\":true}]").unwrap();
		assert!(vault.load().is_err() && vault.save(&[]).is_err());
		assert_eq!(std::fs::read(&vault.path).unwrap(), b"[{\"plain\":true}]");
	}
}
