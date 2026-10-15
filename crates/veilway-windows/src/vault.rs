//! The vault: the subscriptions' secrets (the link's token, the device's private key, the transport secrets) in one file that is encrypted by DPAPI, the data protection API of Windows, whose key lives with the account and not in any file. There is no plain text mode: a system where DPAPI fails gets no vault, and says so.
//!
//! The scope is the user's by default: only the account that wrote the vault reads it, on this machine, and a copy of the file taken to another machine or another account is noise. `Scope::Machine` is there for a service that runs as an account nobody logs in with; any process of any account on the machine can then unprotect the file, so the file's own folder (admin only, `state::secure_dir`) is what keeps it, and it is a choice that is made on purpose and never a fallback.
//!
//! The file is `VWD1`, one byte for the scope, and the DPAPI blob. The header is the blob's entropy (with a fixed label), so a header that was changed, or a blob moved from another kind of file, does not unprotect. The blob is the same vault bytes as on every other system (`veilway_engine::import::write_vault`).
use std::io;
use std::path::PathBuf;
use veilway_engine::import::{read_vault, write_vault, Vault};
use veilway_engine::store::{read_limited, write_atomic};
use veilway_proto::subscription::client::Stored;
use veilway_proto::subscription::BODY_MAX;

const MAGIC: &[u8; 4] = b"VWD1";
const HEADER: usize = 5;
const LABEL: &[u8] = b"veilway:vault:";
const FILE_MAX: usize = 64 * BODY_MAX + 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {User = 1, Machine = 2}

impl Scope {
	fn of(tag: u8) -> Option<Self> {match tag {1 => Some(Self::User), 2 => Some(Self::Machine), _ => None}}
}

/// What turns bytes into a blob only this account (or machine) can turn back. Real behind `Dpapi`; a test puts its own.
pub trait Protector: Send + Sync {
	fn protect(&self, scope: Scope, entropy: &[u8], data: &[u8]) -> io::Result<Vec<u8>>;
	fn unprotect(&self, entropy: &[u8], blob: &[u8]) -> io::Result<Vec<u8>>;
}

fn entropy(header: &[u8]) -> Vec<u8> {[LABEL, header].concat()}

fn seal(protector: &dyn Protector, scope: Scope, plain: &[u8]) -> io::Result<Vec<u8>> {
	let header = [&MAGIC[..], &[scope as u8]].concat();
	Ok([header.clone(), protector.protect(scope, &entropy(&header), plain)?].concat())
}

fn open(protector: &dyn Protector, file: &[u8]) -> io::Result<Vec<u8>> {
	if file.len() <= HEADER || &file[..4] != MAGIC {return Err(io::Error::new(io::ErrorKind::InvalidData, "this is not an encrypted Veilway vault"))}
	Scope::of(file[4]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the vault names a scope that this version does not know"))?;
	protector.unprotect(&entropy(&file[..HEADER]), &file[HEADER..]).map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, format!("the vault cannot be unprotected by this account on this machine ({error}). The subscriptions in it must be imported again")))
}

pub struct SecretVault {path: PathBuf, scope: Scope, protector: Box<dyn Protector>}

impl SecretVault {
	#[cfg(windows)]
	pub fn new(path: impl Into<PathBuf>) -> Self {Self::with(path, Scope::User, Box::new(Dpapi))}
	pub fn with(path: impl Into<PathBuf>, scope: Scope, protector: Box<dyn Protector>) -> Self {Self {path: path.into(), scope, protector}}
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
		read_vault(&open(&*self.protector, &file)?)
	}
	fn save(&self, held: &[Stored]) -> io::Result<()> {
		// A vault that is there and cannot be read is not written over: the user would lose what is in it without being told.
		if let Some(file) = self.read_file()? {open(&*self.protector, &file)?;}
		write_atomic(&self.path, &seal(&*self.protector, self.scope, &write_vault(held))?)
	}
}

#[cfg(windows)]
pub struct Dpapi;

#[cfg(windows)]
impl Protector for Dpapi {
	fn protect(&self, scope: Scope, entropy: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
		use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN};
		call(entropy, data, |input, salt, output| {
			let flags = CRYPTPROTECT_UI_FORBIDDEN | if scope == Scope::Machine {CRYPTPROTECT_LOCAL_MACHINE} else {0};
			// SAFETY: `input` and `salt` point at live buffers for the length they say, the description, the reserved value and the prompt are null as the call allows, and `output` is a live struct the call fills in.
			unsafe {CryptProtectData(input, std::ptr::null(), salt, std::ptr::null(), std::ptr::null(), flags, output)}
		})
	}
	fn unprotect(&self, entropy: &[u8], blob: &[u8]) -> io::Result<Vec<u8>> {
		use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
		call(entropy, blob, |input, salt, output| {
			// SAFETY: as in `protect`.
			unsafe {CryptUnprotectData(input, std::ptr::null_mut(), salt, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, output)}
		})
	}
}

// Runs one DPAPI call over `data` and `entropy` and copies the answer out of the memory the system allocated for it, which is wiped and freed.
#[cfg(windows)]
fn call(entropy: &[u8], data: &[u8], run: impl FnOnce(*const Blob, *const Blob, *mut Blob) -> i32) -> io::Result<Vec<u8>> {
	use windows_sys::Win32::Foundation::LocalFree;
	let blob = |bytes: &[u8]| Blob {cbData: bytes.len() as u32, pbData: bytes.as_ptr() as *mut u8};
	let (input, salt, mut output) = (blob(data), blob(entropy), Blob {cbData: 0, pbData: std::ptr::null_mut()});
	if run(&input, &salt, &mut output) == 0 {return Err(io::Error::last_os_error())}
	// SAFETY: on success the call set `output` to a buffer of `cbData` bytes that it allocated; it is read once and freed once.
	let answer = unsafe {std::slice::from_raw_parts(output.pbData, output.cbData as usize)}.to_vec();
	// SAFETY: as above; the buffer may hold the plain vault, so it is overwritten before it is given back.
	unsafe {
		std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
		LocalFree(output.pbData.cast());
	}
	Ok(answer)
}

#[cfg(windows)]
type Blob = windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;

#[cfg(test)]
mod tests {
	use super::*;

	// Stands in for DPAPI: the blob remembers the entropy it was made with and refuses any other, as DPAPI does.
	struct Fake;

	impl Protector for Fake {
		fn protect(&self, _scope: Scope, entropy: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {Ok([&[entropy.len() as u8][..], entropy, &data.iter().rev().copied().collect::<Vec<u8>>()].concat())}
		fn unprotect(&self, entropy: &[u8], blob: &[u8]) -> io::Result<Vec<u8>> {
			let length = *blob.first().ok_or_else(|| io::Error::other("empty"))? as usize;
			if blob.len() < 1 + length || &blob[1..1 + length] != entropy {return Err(io::Error::other("wrong entropy"))}
			Ok(blob[1 + length..].iter().rev().copied().collect())
		}
	}

	fn path(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-win-vault-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir.join("vault")
	}

	#[test]
	fn a_vault_is_sealed_with_its_header_as_entropy_and_opens_again() {
		let file = seal(&Fake, Scope::User, b"secret bytes").unwrap();
		assert_eq!(&file[..5], b"VWD1\x01");
		assert!(!file.windows(12).any(|window| window == b"secret bytes"));
		assert_eq!(open(&Fake, &file).unwrap(), b"secret bytes");
	}

	#[test]
	fn a_changed_header_or_a_foreign_file_does_not_open() {
		let mut file = seal(&Fake, Scope::User, b"x").unwrap();
		file[4] = Scope::Machine as u8;
		assert!(open(&Fake, &file).is_err());
		file[4] = 9;
		assert!(open(&Fake, &file).is_err());
		assert!(open(&Fake, b"[{\"plain\":true}]").is_err());
		assert!(open(&Fake, b"VWD1\x01").is_err());
	}

	#[test]
	fn a_vault_file_is_never_plain_and_a_missing_one_is_empty() {
		let path = path("round");
		let vault = SecretVault::with(&path, Scope::User, Box::new(Fake));
		assert!(vault.load().unwrap().is_empty());
		vault.save(&[]).unwrap();
		let on_disk = std::fs::read(&path).unwrap();
		assert_eq!(&on_disk[..4], b"VWD1");
		assert!(vault.load().unwrap().is_empty());
	}

	#[test]
	fn a_vault_that_cannot_be_opened_is_not_written_over() {
		let path = path("kept");
		std::fs::write(&path, b"VWD1\x01not a blob").unwrap();
		let vault = SecretVault::with(&path, Scope::User, Box::new(Fake));
		assert!(vault.load().is_err());
		assert!(vault.save(&[]).is_err());
		assert_eq!(std::fs::read(&path).unwrap(), b"VWD1\x01not a blob");
	}
}
