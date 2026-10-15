//! The vault on Android: the subscriptions' secrets in one file, ChaCha20-Poly1305 under a random 32 byte key, and that key kept only in wrapped form, encrypted with an AES-GCM key that lives in the Android Keystore (hardware backed where the phone has it) and never leaves it. There is no plain mode: without the Keystore nothing is stored.
//!
//! The file is `VWA1`, a 12 byte nonce, then the sealed bytes; the header is authenticated. The wrapped key is `vault.key` next to it. A copy of the app's files without the phone's Keystore reads as noise.
use crate::bridge;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use veilway_engine::import::{read_vault, write_vault, Vault};
use veilway_engine::store::{read_limited, write_atomic};
use veilway_proto::subscription::client::Stored;
use veilway_proto::subscription::BODY_MAX;

const MAGIC: &[u8; 4] = b"VWA1";
const HEADER: usize = 4;
const NONCE: usize = 12;
const TAG: usize = 16;
const FILE_MAX: usize = 64 * BODY_MAX + 64;

/// Set when the vault's key is gone (a restore, a reset of the lock screen): the vault opens empty and host.rs says so once the log is up.
pub static KEY_LOST: AtomicBool = AtomicBool::new(false);

pub struct AndroidVault {path: PathBuf, key_path: PathBuf}

impl AndroidVault {
	pub fn new(dir: &std::path::Path) -> Self {Self {path: dir.join("vault"), key_path: dir.join("vault.key")}}

	fn missing(what: &str) -> io::Error {io::Error::new(io::ErrorKind::PermissionDenied, format!("the Android Keystore {what}, so the secrets of your subscriptions cannot be kept or read. Nothing was stored in plain text"))}

	fn read(&self, path: &PathBuf, max: usize) -> io::Result<Option<Vec<u8>>> {
		match read_limited(path, max) {
			Ok(bytes) if bytes.len() > max => Err(io::Error::new(io::ErrorKind::InvalidData, "the vault file is larger than any vault")),
			Ok(bytes) => Ok(Some(bytes)),
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(error),
		}
	}

	fn key(&self, create: bool) -> io::Result<Option<[u8; 32]>> {
		if let Some(wrapped) = self.read(&self.key_path, 256)? {
			// An empty answer means the key is gone; a missing answer means the Keystore did not respond, and that is an error the service retries.
			let plain = bridge::unwrap(&wrapped).ok_or_else(|| io::Error::other("the Android Keystore did not answer, the vault is opened again later"))?;
			if let Ok(key) = <[u8; 32]>::try_from(plain.as_slice()) {return Ok(Some(key))}
		}
		if !create {return Ok(None)}
		let mut key = [0u8; 32];
		SystemRandom::new().fill(&mut key).map_err(|_| io::Error::other("the system gave no random bytes"))?;
		let wrapped = bridge::wrap(&key).ok_or_else(|| Self::missing("is not available"))?;
		write_atomic(&self.key_path, &wrapped)?;
		tracing::info!("the vault key is kept in the Android Keystore");
		Ok(Some(key))
	}
}

fn cipher(key: &[u8; 32]) -> io::Result<LessSafeKey> {Ok(LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| io::Error::other("no cipher"))?))}

impl Vault for AndroidVault {
	fn load(&self) -> io::Result<Vec<Stored>> {
		let Some(file) = self.read(&self.path, FILE_MAX)? else {return Ok(Vec::new())};
		let bad = || io::Error::new(io::ErrorKind::InvalidData, "the vault file does not decrypt: it is damaged, or its key is not the one it was made with");
		if file.len() < HEADER + NONCE + TAG || &file[..HEADER] != MAGIC {return Err(bad())}
		let Some(key) = self.key(false)? else {KEY_LOST.store(true, Ordering::Relaxed); return Ok(Vec::new())};
		let nonce = Nonce::try_assume_unique_for_key(&file[HEADER..HEADER + NONCE]).map_err(|_| bad())?;
		let mut buffer = file[HEADER + NONCE..].to_vec();
		let plain = cipher(&key)?.open_in_place(nonce, Aad::from(&file[..HEADER]), &mut buffer).map_err(|_| bad())?.len();
		buffer.truncate(plain);
		read_vault(&buffer)
	}

	fn save(&self, held: &[Stored]) -> io::Result<()> {
		let key = self.key(true)?.ok_or_else(|| Self::missing("is not available"))?;
		let mut nonce = [0u8; NONCE];
		SystemRandom::new().fill(&mut nonce).map_err(|_| io::Error::other("the system gave no random bytes"))?;
		let mut out = MAGIC.to_vec();
		let mut buffer = write_vault(held);
		cipher(&key)?.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(&out[..HEADER]), &mut buffer).map_err(|_| io::Error::other("the vault could not be encrypted"))?;
		out.extend_from_slice(&nonce);
		out.extend_from_slice(&buffer);
		write_atomic(&self.path, &out)
	}
}
