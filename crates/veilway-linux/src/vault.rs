//! The vault: the subscriptions' secrets (the link's token, the device's private key, the transport secrets) in one file that is encrypted, with its key kept somewhere a copy of the file does not reach. There is no plain text mode: a system with no safe place for the key gets no vault, and says so.
//!
//! A client that runs as root, which is how `connect` runs, has no desktop session: the Secret Service is not on its bus, and a credential is only there in a systemd unit. It keeps the key in `/var/lib/veilway/vault.key`, a file of root that nobody else can read, which survives a reboot. That protects the vault from a copy of the vault file or of its data folder (`/var/lib/veilway/client`), and not from root, which can read both, and not from a copy of the whole of `/var/lib/veilway`, which holds the key file beside the folder; a key sealed to the machine's TPM is what a credential of `systemd-creds encrypt` is, and it comes before the file.
//!
//! The key is 32 random bytes, and it lives in the first of these that works (the key file only for root). (1) The Secret Service, which is the desktop's own keyring (GNOME Keyring, KeePassXC, KWallet), reached over D-Bus by the `secret-tool` program of libsecret. The whole vault is not stored in it: a service is for small values, and the file can be large. (2) A systemd credential named `veilway-vault-key` (`LoadCredential` or `LoadCredentialEncrypted`, which can bind it to the machine's TPM), for a service on a system with no desktop. (3) The kernel's keyring of the user, for a system with neither. A key in the kernel keyring is gone at the next boot, and the vault is then unreadable and says why; it is a safe place and not a lasting one. The file names which of the three holds its key, and a key that is not there is an error: another place is never tried for a vault that exists, since a new key would orphan what is in the file.
//!
//! The file is ChaCha20-Poly1305 with a fresh random nonce at every write, and its header is authenticated.
use crate::state::program;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use veilway_engine::import::{read_vault, write_vault, Vault};
use veilway_engine::store::{read_limited, write_atomic};
use veilway_proto::subscription::client::Stored;
use veilway_proto::subscription::BODY_MAX;

const MAGIC: &[u8; 4] = b"VWV1";
const HEADER: usize = 5;
const NONCE: usize = 12;
const TAG: usize = 16;
const FILE_MAX: usize = 64 * BODY_MAX + 64;
const CREDENTIAL: &str = "veilway-vault-key";
/// Where the key of a vault is kept for a client that runs as root, in the directory that holds nothing else of the client.
pub const KEY_FILE: &str = "/var/lib/veilway/vault.key";
const KEY_SPEC_USER_KEYRING: libc::c_long = -4;
const KEYCTL_SEARCH: libc::c_long = 10;
const KEYCTL_READ: libc::c_long = 11;
const KEYCTL_SETPERM: libc::c_long = 5;
const KEYCTL_LINK: libc::c_long = 8;
const KEY_SPEC_PROCESS_KEYRING: libc::c_long = -2;
/// `KEY_POS_ALL | KEY_USR_ALL`.
const KEY_PERM_POSSESSOR_AND_USER: libc::c_long = 0x3f3f0000;
const DESCRIPTION: &[u8] = b"veilway:vault\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {SecretService = 1, Credential = 2, Keyring = 3, File = 4}

impl Source {
	/// Where a key is looked for and made, first place first. Root has no desktop session, and `secret-tool` run as root can start a D-Bus session of its own and put the key in a keyring nobody expects, so for root the sealed credential and the key file come first.
	fn order() -> [Source; 4] {if rustix::process::geteuid().is_root() {[Self::Credential, Self::File, Self::SecretService, Self::Keyring]} else {[Self::SecretService, Self::Credential, Self::File, Self::Keyring]}}
	fn of(tag: u8) -> Option<Self> {Self::order().into_iter().find(|source| *source as u8 == tag)}
	pub fn describe(self) -> &'static str {
		match self {
			Self::SecretService => "the Secret Service",
			Self::Credential => "the systemd credential veilway-vault-key",
			Self::Keyring => "the kernel keyring",
			Self::File => "the key file of root",
		}
	}
}

/// Where the key can be put and found. Real behind `System`; a test puts its own.
pub trait Keys: Send + Sync {
	fn fetch(&self, source: Source) -> io::Result<Option<[u8; 32]>>;
	fn create(&self, source: Source, key: &[u8; 32]) -> io::Result<()>;
}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

fn unhex(text: &str) -> Option<[u8; 32]> {
	let text = text.trim();
	if text.len() != 64 || !text.is_ascii() {return None}
	let mut key = [0u8; 32];
	for (index, byte) in key.iter_mut().enumerate() {*byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?}
	Some(key)
}

// `secret-tool` with an optional standard input: whether it succeeded, what it printed and what it complained of.
fn secret_tool(args: &[&str], input: Option<&[u8]>) -> io::Result<(bool, Vec<u8>, String)> {
	let mut child = Command::new(program("secret-tool").map_err(|error| io::Error::new(io::ErrorKind::Unsupported, format!("{error} (libsecret-tools)")))?).args(args).stdin(if input.is_some() {Stdio::piped()} else {Stdio::null()}).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|error| if error.kind() == io::ErrorKind::NotFound {io::Error::new(io::ErrorKind::Unsupported, "the secret-tool program (libsecret-tools) is not installed")} else {error})?;
	if let Some(input) = input {child.stdin.take().ok_or_else(|| io::Error::other("no standard input for secret-tool"))?.write_all(input)?}
	let output = child.wait_with_output()?;
	Ok((output.status.success(), output.stdout, String::from_utf8_lossy(&output.stderr).trim().to_owned()))
}

/// The real places. `key_file` is the key of a client that runs as root, which has no desktop session to hold one.
pub struct System {pub key_file: PathBuf}

impl Default for System {
	fn default() -> Self {Self {key_file: PathBuf::from(KEY_FILE)}}
}

// The key file is root's alone: a regular file of this user that no one else can read, in a directory that no one else can write in.
fn root_only() -> io::Result<()> {if rustix::process::geteuid().is_root() {Ok(())} else {Err(io::Error::new(io::ErrorKind::Unsupported, "a key file is kept for root only"))}}

impl Keys for System {
	fn fetch(&self, source: Source) -> io::Result<Option<[u8; 32]>> {
		match source {
			Source::File => {
				root_only()?;
				let meta = match std::fs::symlink_metadata(&self.key_file) {
					Ok(meta) => meta,
					Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
					Err(error) => return Err(error),
				};
				if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a file of root that only root can read", self.key_file.display())))}
				unhex(&std::fs::read_to_string(&self.key_file)?).map(Some).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the key file does not hold a key"))
			}
			Source::SecretService => {
				let (found, out, complaint) = secret_tool(&["lookup", "application", "veilway", "kind", "vault-key"], None)?;
				if found {return unhex(&String::from_utf8_lossy(&out)).map(Some).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the Secret Service holds a vault key that is not a key"))}
				// An item that is not there is an exit status of 1 and nothing said; a service that cannot be reached says why.
				if complaint.is_empty() {Ok(None)} else {Err(io::Error::other(complaint))}
			}
			Source::Credential => {
				let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") else {return Ok(None)};
				match std::fs::read(PathBuf::from(dir).join(CREDENTIAL)) {
					Ok(bytes) => <[u8; 32]>::try_from(bytes.as_slice()).ok().or_else(|| unhex(&String::from_utf8_lossy(&bytes))).map(Some).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the credential is not 32 bytes or 64 hexadecimal digits")),
					Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
					Err(error) => Err(error),
				}
			}
			Source::Keyring => {
				// SAFETY: `keyctl(KEYCTL_SEARCH, ...)` reads two NUL-terminated strings, both live for the call (a literal and a constant), and passes back a key number. Nothing of ours is written.
				let id = unsafe {libc::syscall(libc::SYS_keyctl, KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, c"user".as_ptr(), DESCRIPTION.as_ptr(), 0 as libc::c_long)};
				if id < 0 {
					let error = io::Error::last_os_error();
					return if error.raw_os_error() == Some(libc::ENOKEY) {Ok(None)} else {Err(error)};
				}
				let mut key = [0u8; 32];
				// SAFETY: `KEYCTL_READ` writes at most the length given to the buffer given, which is this array and its size.
				let read = unsafe {libc::syscall(libc::SYS_keyctl, KEYCTL_READ, id, key.as_mut_ptr(), key.len())};
				if read == 32 {Ok(Some(key))} else if read < 0 {Err(io::Error::last_os_error())} else {Err(io::Error::new(io::ErrorKind::InvalidData, "the key in the kernel keyring has the wrong length"))}
			}
		}
	}
	fn create(&self, source: Source, key: &[u8; 32]) -> io::Result<()> {
		match source {
			Source::File => {
				root_only()?;
				crate::state::secure_dir(self.key_file.parent().unwrap_or(Path::new("/")), 0o700)?;
				write_atomic(&self.key_file, hex(key).as_bytes())
			}
			Source::SecretService => {
				let (stored, _, complaint) = secret_tool(&["store", "--label=Veilway vault key", "application", "veilway", "kind", "vault-key"], Some(hex(key).as_bytes()))?;
				if stored {Ok(())} else {Err(io::Error::other(if complaint.is_empty() {"the Secret Service did not store the key".to_owned()} else {complaint}))}
			}
			Source::Credential => Err(io::Error::new(io::ErrorKind::Unsupported, "a credential is given to the program and is not made by it")),
			Source::Keyring => {
				// SAFETY: `add_key` reads two NUL-terminated strings and a payload of the length given, which is this key; all of them live for the call. It makes a key and writes nothing of ours.
				let made = unsafe {libc::syscall(libc::SYS_add_key, c"user".as_ptr(), DESCRIPTION.as_ptr(), key.as_ptr(), key.len(), KEY_SPEC_PROCESS_KEYRING)};
				if made < 0 {return Err(io::Error::last_os_error())}
				// A key is readable and changeable by its possessor alone, and a later run of this program does not possess it (the user keyring is not in its session keyring). So it is made in the process keyring, where this process does possess it, given to the same user as well, and only then linked into the user keyring, which outlives the process. Other users cannot read it either way.
				// SAFETY: `KEYCTL_SETPERM` takes the number of the key just made and the permission mask, and touches nothing of ours.
				if unsafe {libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, made, KEY_PERM_POSSESSOR_AND_USER)} < 0 {return Err(io::Error::last_os_error())}
				// SAFETY: `KEYCTL_LINK` takes the numbers of the key and of the keyring, and touches nothing of ours.
				if unsafe {libc::syscall(libc::SYS_keyctl, KEYCTL_LINK, made, KEY_SPEC_USER_KEYRING)} < 0 {return Err(io::Error::last_os_error())}
				Ok(())
			}
		}
	}
}

fn seal(key: &[u8; 32], source: Source, plain: &[u8]) -> io::Result<Vec<u8>> {
	let (mut nonce, mut out) = ([0u8; NONCE], MAGIC.to_vec());
	SystemRandom::new().fill(&mut nonce).map_err(|_| io::Error::other("the system gave no random bytes"))?;
	out.push(source as u8);
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

fn header_of(file: &[u8]) -> io::Result<Source> {
	if file.len() < HEADER || &file[..4] != MAGIC {return Err(io::Error::new(io::ErrorKind::InvalidData, "this is not an encrypted Veilway vault"))}
	Source::of(file[4]).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the vault names a place for its key that this version does not know"))
}

pub struct SecretVault {path: PathBuf, keys: Box<dyn Keys>}

impl SecretVault {
	pub fn new(path: impl Into<PathBuf>) -> Self {Self::with(path, Box::new(System::default()))}
	pub fn with(path: impl Into<PathBuf>, keys: Box<dyn Keys>) -> Self {Self {path: path.into(), keys}}
	fn missing(source: Source, error: Option<io::Error>) -> io::Error {io::Error::new(io::ErrorKind::NotFound, format!("the vault's key is not in {}{}. The vault cannot be read; the subscriptions in it must be imported again{}", source.describe(), error.map_or_else(String::new, |error| format!(" ({error})")), if source == Source::Keyring {" (a key in the kernel keyring does not survive a restart; use the Secret Service or a systemd credential for a vault that should)"} else {""}))}
	// The key for a write: the one the file names, and for a first write the first place that takes a key.
	fn key_for_write(&self, existing: Option<Source>) -> io::Result<(Source, [u8; 32])> {
		if let Some(source) = existing {return self.keys.fetch(source).map_err(|error| Self::missing(source, Some(error)))?.map(|key| (source, key)).ok_or_else(|| Self::missing(source, None))}
		let mut reasons = Vec::new();
		for source in Source::order() {
			match self.keys.fetch(source) {
				Ok(Some(key)) => return Ok((source, key)),
				Ok(None) => {}
				Err(error) => {
					reasons.push(format!("{}: {error}", source.describe()));
					continue;
				}
			}
			let mut key = [0u8; 32];
			SystemRandom::new().fill(&mut key).map_err(|_| io::Error::other("the system gave no random bytes"))?;
			match self.keys.create(source, &key) {
				Ok(()) => {
					tracing::info!("the vault key is kept in {}", source.describe());
					return Ok((source, key));
				}
				Err(error) => reasons.push(format!("{}: {error}", source.describe())),
			}
		}
		Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("there is no safe place on this system to keep the secrets of your subscriptions, so nothing was stored. Tried: {}. Install and start a Secret Service (GNOME Keyring or KeePassXC, with the secret-tool program), or give the program a systemd credential named {CREDENTIAL}", reasons.join("; "))))
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
		let source = header_of(&file)?;
		let key = self.keys.fetch(source).map_err(|error| Self::missing(source, Some(error)))?.ok_or_else(|| Self::missing(source, None))?;
		read_vault(&open(&key, &file)?)
	}
	fn save(&self, held: &[Stored]) -> io::Result<()> {
		let existing = self.read_file()?.map(|file| header_of(&file)).transpose()?;
		let (source, key) = self.key_for_write(existing)?;
		write_atomic(&self.path, &seal(&key, source, &write_vault(held))?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use std::sync::Mutex;

	// Places that take or refuse a key, in memory.
	struct Fake {has: Mutex<HashMap<u8, [u8; 32]>>, takes: Vec<Source>}

	impl Fake {
		fn new(takes: &[Source]) -> Self {Self {has: Mutex::default(), takes: takes.to_vec()}}
	}

	impl Keys for std::sync::Arc<Fake> {
		fn fetch(&self, source: Source) -> io::Result<Option<[u8; 32]>> {Ok(self.has.lock().unwrap().get(&(source as u8)).copied())}
		fn create(&self, source: Source, key: &[u8; 32]) -> io::Result<()> {
			if !self.takes.contains(&source) {return Err(io::Error::other("no"))}
			self.has.lock().unwrap().insert(source as u8, *key);
			Ok(())
		}
	}

	fn path(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-vault-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir.join("vault")
	}

	#[test]
	fn the_key_file_of_root_survives_and_is_refused_when_others_can_read_it() {
		if !rustix::process::geteuid().is_root() {return}
		let dir = path("keyfile").parent().unwrap().to_owned();
		let system = System {key_file: dir.join("keys").join("vault.key")};
		let key = [9u8; 32];
		assert_eq!(system.fetch(Source::File).unwrap(), None);
		system.create(Source::File, &key).unwrap();
		assert_eq!(system.fetch(Source::File).unwrap(), Some(key));
		assert_eq!(std::fs::metadata(&system.key_file).unwrap().mode() & 0o777, 0o600);
		std::fs::set_permissions(&system.key_file, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
		assert!(system.fetch(Source::File).is_err());
	}

	#[test]
	fn what_is_sealed_opens_with_the_key_and_with_nothing_else() {
		let (key, other) = ([7u8; 32], [8u8; 32]);
		let file = seal(&key, Source::Keyring, b"secrets").unwrap();
		assert_eq!(open(&key, &file).unwrap(), b"secrets");
		assert!(open(&other, &file).is_err());
		assert!(!file.windows(7).any(|window| window == b"secrets"));
		let mut flipped = file.clone();
		*flipped.last_mut().unwrap() ^= 1;
		assert!(open(&key, &flipped).is_err());
		let mut renamed = file.clone();
		renamed[4] = Source::Credential as u8;
		assert!(open(&key, &renamed).is_err(), "the header is authenticated");
		assert_ne!(seal(&key, Source::Keyring, b"secrets").unwrap(), file, "a fresh nonce at every write");
	}

	#[test]
	fn the_header_says_which_place_holds_the_key() {
		let file = seal(&[1u8; 32], Source::Credential, b"").unwrap();
		assert_eq!(header_of(&file).unwrap(), Source::Credential);
		assert!(header_of(b"[]").is_err() && header_of(b"VWV1\x09").is_err() && header_of(b"").is_err());
	}

	#[test]
	fn hex_is_read_back_and_nothing_else_is() {
		let key: [u8; 32] = std::array::from_fn(|index| index as u8 * 7);
		assert_eq!(unhex(&hex(&key)), Some(key));
		assert_eq!(unhex(&format!("{}\n", hex(&key))), Some(key));
		assert!(unhex("zz").is_none() && unhex(&"é".repeat(32)).is_none() && unhex(&"0".repeat(63)).is_none());
	}

	#[test]
	fn a_first_save_takes_the_first_place_that_takes_a_key_and_the_next_load_asks_that_place() {
		let places = std::sync::Arc::new(Fake::new(&[Source::Keyring]));
		let vault = SecretVault::with(path("first"), Box::new(places.clone()));
		assert!(vault.load().unwrap().is_empty());
		vault.save(&[]).unwrap();
		assert_eq!(header_of(&std::fs::read(&vault.path).unwrap()).unwrap(), Source::Keyring);
		assert!(vault.load().unwrap().is_empty());
		assert_eq!(places.has.lock().unwrap().len(), 1);
	}

	#[test]
	fn a_system_with_no_place_for_a_key_gets_no_vault_and_a_file_is_not_written() {
		let vault = SecretVault::with(path("none"), Box::new(std::sync::Arc::new(Fake::new(&[]))));
		let error = vault.save(&[]).unwrap_err();
		assert!(error.to_string().contains("no safe place") && error.to_string().contains("the kernel keyring"), "{error}");
		assert!(!vault.path.exists());
	}

	#[test]
	fn a_vault_whose_key_is_gone_is_an_error_and_is_not_written_over_with_a_new_key() {
		let places = std::sync::Arc::new(Fake::new(&[Source::Keyring]));
		let vault = SecretVault::with(path("gone"), Box::new(places.clone()));
		vault.save(&[]).unwrap();
		let before = std::fs::read(&vault.path).unwrap();
		places.has.lock().unwrap().clear();
		let error = vault.load().unwrap_err();
		assert!(error.to_string().contains("does not survive a restart"), "{error}");
		assert!(vault.save(&[]).is_err());
		assert_eq!(std::fs::read(&vault.path).unwrap(), before);
	}

	#[test]
	fn a_file_that_is_not_a_vault_is_never_read_as_one() {
		let file = path("plain");
		std::fs::write(&file, b"[]").unwrap();
		let vault = SecretVault::with(file, Box::new(std::sync::Arc::new(Fake::new(&[Source::Keyring]))));
		assert!(vault.load().is_err() && vault.save(&[]).is_err());
	}
}
