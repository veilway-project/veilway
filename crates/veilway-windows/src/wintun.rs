//! The Wintun library that the TUN device loads.
//!
//! The `wintun.dll` next to `veilway.exe` is used when there is one, which is how the desktop app ships it. Without one, the official 0.14.1 library compiled into the binary (`embedded-wintun`, from the file that `build.rs` checked against the pin) is written to `%ProgramData%\Veilway\wintun`, a folder that only SYSTEM and the administrators can write, and its SHA-256 is checked before every load, so a copy that differs is written again. `tun` loads the file by its full path with the system folder as the only place its imports are searched.
use ring::digest::{digest, SHA256};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::io;

/// The copy's file name. The version is in it, so an older copy is never taken for this one.
pub const FILE: &str = "wintun-0.14.1.dll";

/// The library compiled into this binary: empty when the feature is off or the target is not Windows.
#[cfg(all(windows, feature = "embedded-wintun"))]
pub const EMBEDDED: &[u8] = include_bytes!(env!("VEILWAY_WINTUN_DLL"));
#[cfg(not(all(windows, feature = "embedded-wintun")))]
pub const EMBEDDED: &[u8] = &[];

/// Whether the SHA-256 of `bytes` is `sha256`, in lower-case hex.
pub fn has_sha256(bytes: &[u8], sha256: &str) -> bool {digest(&SHA256, bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>() == sha256}

/// Where the copy is in `folder`.
pub fn dll_in(folder: &Path) -> PathBuf {folder.join(FILE)}

/// Whether `folder` holds the pinned library under its name.
pub fn holds_pinned(folder: &Path) -> bool {fs::read(dll_in(folder)).is_ok_and(|bytes| has_sha256(&bytes, env!("VEILWAY_WINTUN_SHA256")))}

/// The library to load: the one next to `veilway.exe` when there is one, else the pinned copy, written to ProgramData when it is missing or differs.
#[cfg(windows)]
pub fn locate() -> io::Result<PathBuf> {
	let beside = std::env::current_exe()?.with_file_name("wintun.dll");
	if beside.is_file() {return Ok(beside)}
	if EMBEDDED.is_empty() {return Err(io::Error::new(io::ErrorKind::NotFound, format!("{} is missing: wintun.dll has to be next to veilway.exe", beside.display())))}
	let folder = crate::state::default_wintun_dir();
	crate::state::secure_dir(&folder, crate::acl::Access::Private)?;
	if !holds_pinned(&folder) {fs::write(dll_in(&folder), EMBEDDED)?}
	if !holds_pinned(&folder) {return Err(io::Error::other(format!("{} does not hold the pinned wintun.dll after it was written", folder.display())))}
	Ok(dll_in(&folder))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_hash_is_compared_in_lower_case_hex() {
		let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
		assert!(has_sha256(b"abc", abc) && !has_sha256(b"abd", abc));
		assert!(!has_sha256(b"abc", &abc.to_uppercase()));
	}

	#[test]
	fn the_copy_has_its_own_name_in_the_folder_and_a_missing_one_is_not_held() {
		assert!(dll_in(Path::new("folder")).ends_with("wintun-0.14.1.dll"));
		assert!(!holds_pinned(Path::new("folder-that-does-not-exist")));
	}
}
