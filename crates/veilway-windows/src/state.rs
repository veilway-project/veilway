//! The run directory and the one lock every command takes, and the status a running client writes for `veilway status`.
//!
//! The lock is a named mutex in the global namespace, `Global\VeilwayClientLock`: there is one of what a client changes (the filters of the kill switch, the policy table, the adapter), so there is one lock, and neither a flag nor an environment variable moves it. Creating objects in the global namespace takes the privilege that services and administrators have, so an ordinary user cannot take the name first. The mutex is never owned by a thread (that would tie it to one of the runtime's); it exists as long as some process holds a handle to it, which is as long as that process lives, however it ends. A second `CreateMutexW` that finds it there is told so, and that is the whole test.
//!
//! A client that runs also holds a named event, `Global\VeilwayClientStop`, that `terminate` sets and the client polls: that is the clean stop. Windows has no signal to send to a process that has a console of its own or none, and a kill would leave the client no chance to lift anything.
//!
//! The directories are under `%ProgramData%\Veilway`, found through the shell's known folder and not the environment, and are made readable by SYSTEM and administrators only (a protected ACL, so a parent's does not leak in), and never a link.
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;
use tokio::time::{sleep, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW, OpenEventW, OpenMutexW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE};

const LOCK: &str = "Global\\VeilwayClientLock";
const STOP: &str = "Global\\VeilwayClientStop";
const STATUS: &str = "status.txt";
/// SYSTEM and the administrators, full control, inherited by what is made inside, and no other entry.
const SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

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

/// A directory that only SYSTEM and the administrators can use, made if it is not there, and never a link. An existing one gets the ACL again: a client that runs as an administrator must not keep its vault where an ordinary user can write.
pub fn secure_dir(path: &Path) -> io::Result<()> {
	if let Some(parent) = path.parent() {fs::create_dir_all(parent)?}
	if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink() || !meta.is_dir()) {return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is a link or not a directory", path.display())))}
	let mut descriptor: *mut core::ffi::c_void = null_mut();
	// SAFETY: the SDDL is a constant null-terminated string and `descriptor` is a live local the call writes a pointer to.
	if unsafe {ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(SDDL).as_ptr(), SDDL_REVISION_1, &mut descriptor, null_mut())} == 0 {return Err(io::Error::last_os_error())}
	let name = wide(&path.to_string_lossy());
	let attributes = SECURITY_ATTRIBUTES {nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor, bInheritHandle: 0};
	// SAFETY: the name is null-terminated and the attributes point at the descriptor made above, all live through the calls. The descriptor is freed once, after them.
	let outcome = unsafe {
		let made = CreateDirectoryW(name.as_ptr(), &attributes) != 0;
		let outcome = if made || GetLastError() == ERROR_ALREADY_EXISTS {
			if SetFileSecurityW(name.as_ptr(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor) != 0 {Ok(())} else {Err(io::Error::last_os_error())}
		} else {Err(io::Error::last_os_error())};
		LocalFree(descriptor);
		outcome
	};
	outcome
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
	// SAFETY: default security, not owned at the start, and a null-terminated name that lives through the call.
	let handle = unsafe {CreateMutexW(null(), 0, wide(LOCK).as_ptr())};
	if handle.is_null() {return Err(io::Error::last_os_error())}
	// SAFETY: read at once after the call, on the same thread.
	let existed = unsafe {GetLastError()} == ERROR_ALREADY_EXISTS;
	let owned = Owned(handle);
	Ok(if existed {None} else {Some(owned)})
}

/// Takes the lock for this process. A holder that is still taking it, or an observer that looks for a moment, is waited for a second: only a lock that stays held is a client that runs.
pub async fn lock(dir: &Path) -> io::Result<Lock> {
	secure_dir(dir)?;
	for attempt in 0..20 {
		if let Some(mutex) = create_mutex()? {
			// SAFETY: manual reset, not set at the start, default security, and a name that lives through the call.
			let stop = unsafe {CreateEventW(null(), 1, 0, wide(STOP).as_ptr())};
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

/// Writes the status text where `veilway status` reads it. The folder is for administrators, and so is `veilway status`.
pub fn write_status(dir: &Path, text: &str) -> io::Result<()> {veilway_engine::store::write_atomic(&dir.join(STATUS), text.as_bytes())}

pub fn read_status(dir: &Path) -> io::Result<String> {fs::read_to_string(dir.join(STATUS))}

pub fn remove_status(dir: &Path) {let _ = fs::remove_file(dir.join(STATUS));}
