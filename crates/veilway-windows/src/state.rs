//! The run directory and the one lock every command takes, and the status a running client writes for `veilway status`.
//!
//! The lock is a named mutex in the global namespace, `Global\VeilwayClientLock`: there is one of what a client changes (the filters of the kill switch, the policy table, the adapter), so there is one lock, and neither a flag nor an environment variable moves it. Creating objects in the global namespace takes the privilege that services and administrators have, so an ordinary user cannot take the name first. The mutex is never owned by a thread (that would tie it to one of the runtime's); it exists as long as some process holds a handle to it, which is as long as that process lives, however it ends. A second `CreateMutexW` that finds it there is told so, and that is the whole test.
//!
//! A client that runs also holds a named event, `Global\VeilwayClientStop`, that `terminate` sets and the client polls: that is the clean stop. Windows has no signal to send to a process that has a console of its own or none, and a kill would leave the client no chance to lift anything.
//!
//! The directories are under `%ProgramData%\Veilway`, found through the shell's known folder and not the environment. Each, `Veilway` and below, is owned by the Administrators group with a protected ACL for SYSTEM and administrators (`acl`), and a folder that is there already with another owner is refused. The run folder is also readable by users, and the lock's objects can be waited on by them, so that `veilway status` works from an ordinary console.
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::Duration;
use tokio::time::{sleep, Instant};
use crate::acl::{self, Access};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{GetAce, GetAclInformation, GetTokenInformation, SetFileSecurityW, TokenElevation, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{OpenProcessToken, GetCurrentProcess, CreateEventW, CreateMutexW, OpenEventW, OpenMutexW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE};

const LOCK: &str = "Global\\VeilwayClientLock";
const STOP: &str = "Global\\VeilwayClientStop";
const STATUS: &str = "status.txt";

fn wide(text: &str) -> Vec<u16> {text.encode_utf16().chain(std::iter::once(0)).collect()}

/// A handle that is closed when it is dropped.
#[derive(Debug)]
struct Owned(HANDLE);

// SAFETY: a kernel handle is a number the system looks up, valid from any thread, and nothing else is done with this one but closing it and waiting on it.
unsafe impl Send for Owned {}
unsafe impl Sync for Owned {}

impl Drop for Owned {
	// SAFETY: the handle came from a successful call and is closed once, here.
	fn drop(&mut self) {unsafe {CloseHandle(self.0)};}
}

/// A folder of the shell, by its id.
fn known_folder() -> io::Result<PathBuf> {
	use windows_sys::Win32::System::Com::CoTaskMemFree;
	use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};
	let mut path: *mut u16 = null_mut();
	// SAFETY: the id is a constant, the token is null (the current user), and `path` is a live local that the call writes a pointer to.
	let status = unsafe {SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &mut path)};
	if status < 0 {return Err(io::Error::other("the system would not say where ProgramData is"))}
	// SAFETY: on success `path` is a null-terminated wide string that the shell allocated; it is copied and freed once.
	let found = unsafe {
		let length = (0..).take_while(|offset| *path.add(*offset) != 0).count();
		let found = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(path, length)));
		CoTaskMemFree(path.cast());
		found
	};
	Ok(found)
}

/// Where the lock's status file is, and what a client keeps while it runs.
pub fn default_dir() -> PathBuf {known_folder().unwrap_or_else(|_| PathBuf::from("C:\\ProgramData")).join("Veilway").join("run")}

/// Where a client that has no `--data-dir` keeps its vault and what it remembers.
pub fn default_data_dir() -> PathBuf {known_folder().unwrap_or_else(|_| PathBuf::from("C:\\ProgramData")).join("Veilway").join("client")}

/// The path of a program in the system's own folder, and nowhere else: not `PATH` and not the working directory, which an ordinary user could have planted a program in.
pub fn program(name: &str) -> io::Result<PathBuf> {
	use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
	let mut buffer = [0u16; 260];
	// SAFETY: the buffer is live and its length is passed.
	let length = unsafe {GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32)} as usize;
	if length == 0 || length >= buffer.len() {return Err(io::Error::other("the system would not say where its folder is"))}
	let path = PathBuf::from(OsString::from_wide(&buffer[..length])).join(name);
	if path.is_file() {Ok(path)} else {Err(io::Error::new(io::ErrorKind::NotFound, format!("{} is not installed", path.display())))}
}

/// The owner and the allowing entries of a file or folder: the SID of each in text, the rights it is given and whether the entry is only for what is inside.
fn security(path: &Path) -> io::Result<(String, Vec<(String, u32, bool)>)> {
	let name = wide(&path.to_string_lossy());
	let (mut owner, mut dacl, mut descriptor): (PSID, *mut ACL, *mut core::ffi::c_void) = (null_mut(), null_mut(), null_mut());
	// SAFETY: the name is null-terminated and the three out pointers are live locals; the descriptor they point into is freed once below.
	let code = unsafe {GetNamedSecurityInfoW(name.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut owner, null_mut(), &mut dacl, null_mut(), &mut descriptor)};
	if code != 0 {return Err(io::Error::from_raw_os_error(code as i32))}
	let sid_text = |sid: PSID| -> io::Result<String> {
		let mut text: *mut u16 = null_mut();
		// SAFETY: the SID points into the descriptor, which is alive, and `text` is a live local the call writes a pointer to.
		if unsafe {ConvertSidToStringSidW(sid, &mut text)} == 0 {return Err(io::Error::last_os_error())}
		// SAFETY: a null-terminated wide string that the call allocated, copied and freed once.
		let found = unsafe {String::from_utf16_lossy(std::slice::from_raw_parts(text, (0..).take_while(|at| *text.add(*at) != 0).count()))};
		unsafe {LocalFree(text.cast())};
		Ok(found)
	};
	let found = (|| {
		let mut aces = Vec::new();
		if !dacl.is_null() {
			let mut size = ACL_SIZE_INFORMATION {AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0};
			// SAFETY: the ACL is part of the live descriptor, and `size` is a live struct of the size the class names.
			if unsafe {GetAclInformation(dacl, (&mut size as *mut ACL_SIZE_INFORMATION).cast(), std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation)} == 0 {return Err(io::Error::last_os_error())}
			for index in 0..size.AceCount {
				let mut ace: *mut core::ffi::c_void = null_mut();
				// SAFETY: the index is below the count the ACL gave.
				if unsafe {GetAce(dacl, index, &mut ace)} == 0 {return Err(io::Error::last_os_error())}
				// SAFETY: every ACE starts with a header that says its kind; an allowing one is laid out as `ACCESS_ALLOWED_ACE`, with the SID from `SidStart` on.
				unsafe {
					let header = *ace.cast::<ACE_HEADER>();
					if header.AceType == 0 {
						let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
						aces.push((sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?, allowed.Mask, header.AceFlags & INHERIT_ONLY_ACE as u8 != 0));
					}
				}
			}
		}
		Ok((sid_text(owner)?, aces))
	})();
	// SAFETY: the descriptor came from `GetNamedSecurityInfoW` and is freed once, after the last use of what points into it.
	unsafe {LocalFree(descriptor)};
	found
}

/// A directory that only SYSTEM and the administrators can use, made if it is not there, owned by the Administrators group, and never a link. One that is there already must be owned by SYSTEM or the Administrators: an ordinary user can make a folder first and keep the right to change its ACL for ever. Everything between ProgramData and the folder gets the same, so that the folder cannot be moved from above.
pub fn secure_dir(path: &Path, access: Access) -> io::Result<()> {
	let base = known_folder().unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
	let Ok(below) = path.strip_prefix(&base) else {
		if let Some(parent) = path.parent() {fs::create_dir_all(parent)?}
		return secure_one(path, access);
	};
	let mut at = base.clone();
	let count = below.components().count();
	for (position, part) in below.components().enumerate() {
		at.push(part);
		secure_one(&at, if position + 1 == count {access} else {Access::Traverse})?;
	}
	Ok(())
}

fn secure_one(path: &Path, access: Access) -> io::Result<()> {
	match fs::symlink_metadata(path) {
		Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is a link or not a directory", path.display()))),
		Ok(_) => {
			let (owner, _) = security(path)?;
			if !acl::trusted_owner(&owner) {return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is owned by {owner}, which is neither SYSTEM nor the administrators. Delete it as an administrator and run again", path.display())))}
		}
		Err(error) if error.kind() == io::ErrorKind::NotFound => {}
		Err(error) => return Err(error),
	}
	with_descriptor(&acl::folder_sddl(access), |attributes| {
		let name = wide(&path.to_string_lossy());
		// SAFETY: the name is null-terminated and the attributes are live through the calls.
		unsafe {
			let made = CreateDirectoryW(name.as_ptr(), attributes) != 0;
			if !made && GetLastError() != ERROR_ALREADY_EXISTS {return Err(io::Error::last_os_error())}
			if SetFileSecurityW(name.as_ptr(), OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, attributes.lpSecurityDescriptor) == 0 {return Err(io::Error::last_os_error())}
		}
		Ok(())
	})
}

/// Runs `then` with the attributes of a descriptor made from `sddl`, and frees the descriptor after.
fn with_descriptor<T>(sddl: &str, then: impl FnOnce(&SECURITY_ATTRIBUTES) -> io::Result<T>) -> io::Result<T> {
	let mut descriptor: *mut core::ffi::c_void = null_mut();
	// SAFETY: the SDDL is a null-terminated string and `descriptor` is a live local the call writes a pointer to.
	if unsafe {ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut descriptor, null_mut())} == 0 {return Err(io::Error::last_os_error())}
	let attributes = SECURITY_ATTRIBUTES {nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor, bInheritHandle: 0};
	let outcome = then(&attributes);
	// SAFETY: the descriptor came from the call above and is freed once, after its last use.
	unsafe {LocalFree(descriptor)};
	outcome
}

/// Refuses to go on as an administrator from a folder that someone else can write in: whoever can replace `wintun.dll` or the program itself would be running as an administrator. A client that is not elevated has nothing to protect and is let through.
pub fn check_install_dir() -> io::Result<()> {
	let mut token: HANDLE = null_mut();
	// SAFETY: the process handle is a pseudo handle and `token` is a live local the call writes to.
	if unsafe {OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)} == 0 {return Err(io::Error::last_os_error())}
	let token = Owned(token);
	let mut elevation = TOKEN_ELEVATION {TokenIsElevated: 0};
	let mut returned = 0u32;
	// SAFETY: the token is open and the buffer is a live struct of the size passed.
	if unsafe {GetTokenInformation(token.0, TokenElevation, (&mut elevation as *mut TOKEN_ELEVATION).cast(), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut returned)} == 0 {return Err(io::Error::last_os_error())}
	if elevation.TokenIsElevated == 0 {return Ok(())}
	let exe = std::env::current_exe()?;
	let dir = exe.parent().ok_or_else(|| io::Error::other("the program has no folder"))?;
	let (owner, aces) = security(dir)?;
	let unsafe_dir = |why: String| io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not safe to run as an administrator from: {why}. Install the program where only administrators can write, such as Program Files", dir.display()));
	if !acl::trusted_install_owner(&owner) {return Err(unsafe_dir(format!("it is owned by {owner}")))}
	if let Some((sid, ..)) = aces.iter().find(|(sid, mask, inherit_only)| acl::grants_write(sid, *mask, *inherit_only)) {return Err(unsafe_dir(format!("{sid} can write in it")))}
	Ok(())
}

/// The lock, held until it is dropped, which is when the process ends however it ends. It holds the stop event too.
#[derive(Debug)]
pub struct Lock {_mutex: Owned, stop: Owned}

impl Lock {
	/// Completes when `veilway disconnect` asks this client to stop.
	pub async fn stop_asked(&self) {
		loop {
			// SAFETY: the handle is open for as long as `self` is.
			if unsafe {WaitForSingleObject(self.stop.0, 0)} == WAIT_OBJECT_0 {return}
			sleep(Duration::from_millis(200)).await;
		}
	}
}

fn create_mutex() -> io::Result<Option<Owned>> {
	with_descriptor(acl::OBJECT_SDDL, |attributes| {
		// SAFETY: the attributes hold a descriptor that lives through the call, the mutex is not owned at the start, and the name is null-terminated.
		let handle = unsafe {CreateMutexW(attributes, 0, wide(LOCK).as_ptr())};
		if handle.is_null() {return Err(io::Error::last_os_error())}
		// SAFETY: read at once after the call, on the same thread.
		let existed = unsafe {GetLastError()} == ERROR_ALREADY_EXISTS;
		let owned = Owned(handle);
		Ok(if existed {None} else {Some(owned)})
	})
}

/// Takes the lock for this process. A holder that is still taking it, or an observer that looks for a moment, is waited for a second: only a lock that stays held is a client that runs.
pub async fn lock(dir: &Path) -> io::Result<Lock> {
	secure_dir(dir, Access::Read)?;
	for attempt in 0..20 {
		if let Some(mutex) = create_mutex()? {
			// SAFETY: manual reset, not set at the start, a descriptor that lives through the call, and a null-terminated name.
			let stop = with_descriptor(acl::OBJECT_SDDL, |attributes| Ok(unsafe {CreateEventW(attributes, 1, 0, wide(STOP).as_ptr())}))?;
			if stop.is_null() {return Err(io::Error::last_os_error())}
			return Ok(Lock {_mutex: mutex, stop: Owned(stop)});
		}
		if attempt < 19 {sleep(Duration::from_millis(50)).await}
	}
	Err(io::Error::new(io::ErrorKind::AddrInUse, "a connection runs already, or another veilway command is working on it. Stop it with `veilway disconnect`"))
}

/// Who holds the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {Free, Held}

pub fn holder(_dir: &Path) -> Holder {
	// SAFETY: a null-terminated name that lives through the call; the handle it gives is closed by `Owned`.
	let handle = unsafe {OpenMutexW(SYNCHRONIZE, 0, wide(LOCK).as_ptr())};
	if handle.is_null() {Holder::Free} else {drop(Owned(handle)); Holder::Held}
}

/// What `terminate` had to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
	/// Nothing was running.
	NotRunning,
	/// The client stopped by itself after the request to, and removed what it made.
	Stopped,
}

/// Asks the running client to stop, which it does the clean way, and waits for it to. A client that does not stop in `wait` is an error and is not killed: a kill leaves the kill switch in force, which is what it is for, and `cleanup` lifts it once the process is gone.
pub async fn terminate(dir: &Path, wait: Duration) -> io::Result<Ended> {
	let deadline = Instant::now() + wait;
	if holder(dir) == Holder::Free {return Ok(Ended::NotRunning)}
	while Instant::now() < deadline {
		// SAFETY: a null-terminated name that lives through the call; the handle is closed by `Owned`.
		let event = unsafe {OpenEventW(EVENT_MODIFY_STATE, 0, wide(STOP).as_ptr())};
		if !event.is_null() {
			let event = Owned(event);
			// SAFETY: the handle is open and was opened with the right to set it.
			if unsafe {SetEvent(event.0)} == 0 {return Err(io::Error::last_os_error())}
			break;
		}
		// A client that took the lock and has not made its event yet.
		sleep(Duration::from_millis(50)).await;
	}
	while Instant::now() < deadline {
		sleep(Duration::from_millis(100)).await;
		if holder(dir) == Holder::Free {return Ok(Ended::Stopped)}
	}
	Err(io::Error::new(io::ErrorKind::TimedOut, "the connection did not stop in time. End the veilway process in the Task Manager, then run `veilway disconnect` again"))
}

/// Writes the status text where `veilway status` reads it. Anyone may read it: it holds the connection's name and its state and no secret.
pub fn write_status(dir: &Path, text: &str) -> io::Result<()> {veilway_engine::store::write_atomic(&dir.join(STATUS), text.as_bytes())}

pub fn read_status(dir: &Path) -> io::Result<String> {fs::read_to_string(dir.join(STATUS))}

pub fn remove_status(dir: &Path) {let _ = fs::remove_file(dir.join(STATUS));}
