//! Where the window and the helper meet, and the few files the helper reads from the user's side.
//!
//! Unix: a socket in a folder that only root can write (`/run/veilway-desktop` on Linux, `/var/run/veilway-desktop` on macOS), so no other user can bind the name before the helper, owned by the user who raised the helper and mode 600, and every connection is checked for that user's uid (`peer_cred`) as well. Windows: a named pipe whose access list names the SID of that user, SYSTEM and the administrators only, refusing remote clients and a second creator of the name. Whatever could still listen where the helper should is kept from learning the token by the challenge in `proto.rs`: the token itself is never sent.
//!
//! The helper writes nothing in the user's folders. The one thing root reads from there is the token file, and it is opened as `openat` from a folder that was itself opened once with `O_DIRECTORY|O_NOFOLLOW`, checked to be owned by the user who raised the helper, and the file has to be a regular file of that user's, of the length of a token.
use std::io;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}

pub type Conn = Box<dyn Duplex>;

#[cfg(target_os = "linux")]
pub const RUN_DIR: &str = "/run/veilway-desktop";
#[cfg(target_os = "macos")]
pub const RUN_DIR: &str = "/var/run/veilway-desktop";
#[cfg(windows)]
pub const PIPE: &str = r"\\.\pipe\veilway-desktop-helper";

#[cfg(unix)]
pub fn socket_path() -> PathBuf {Path::new(RUN_DIR).join("helper.sock")}

/// The folder of the socket, made by the helper (root) and checked every time: a real folder, ours, closed to everyone else.
#[cfg(unix)]
pub fn ensure_run_dir() -> io::Result<()> {
	let dir = Path::new(RUN_DIR);
	match std::fs::DirBuilder::new().mode(0o755).create(dir) {
		Ok(()) => {}
		Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
		Err(error) => return Err(error),
	}
	check_dir(dir)
}

#[cfg(unix)]
fn check_dir(dir: &Path) -> io::Result<()> {
	let meta = std::fs::symlink_metadata(dir)?;
	if !meta.is_dir() || std::os::unix::fs::MetadataExt::uid(&meta) != unsafe {libc::geteuid()} || std::os::unix::fs::MetadataExt::mode(&meta) & 0o022 != 0 {return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a folder of this user that others cannot write in", dir.display())))}
	Ok(())
}

#[cfg(unix)]
pub struct Server {listener: UnixListener, uid: u32}

#[cfg(unix)]
impl Server {
	/// Binds `path`, in a folder `ensure_run_dir` (or the caller) made, for the user `uid`.
	pub fn bind(path: &Path, uid: u32) -> io::Result<Self> {
		check_dir(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
		match std::fs::remove_file(path) {
			Ok(()) => {}
			Err(error) if error.kind() == io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
		let listener = UnixListener::bind(path)?;
		std::os::unix::fs::chown(path, Some(uid), None)?;
		std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
		Ok(Self {listener, uid})
	}
	/// The next connection from the user the helper was raised for; any other is closed at once.
	pub async fn accept(&mut self) -> io::Result<Conn> {
		loop {
			let (stream, _) = self.listener.accept().await?;
			if stream.peer_cred().is_ok_and(|peer| peer.uid() == self.uid) {return Ok(Box::new(stream))}
		}
	}
}

#[cfg(unix)]
pub async fn connect() -> io::Result<Conn> {connect_to(&socket_path()).await}

#[cfg(unix)]
pub async fn connect_to(path: &Path) -> io::Result<Conn> {Ok(Box::new(UnixStream::connect(path).await?))}

#[cfg(windows)]
pub struct Server {next: NamedPipeServer, descriptor: usize}

#[cfg(windows)]
impl Server {
	/// `sid` is the string form of the SID of the user the helper was raised for, as the window found it.
	pub fn bind(sid: &str) -> io::Result<Self> {
		use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
		if !sid_ok(sid) {return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a SID"))}
		let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)").encode_utf16().chain(Some(0)).collect();
		let mut descriptor = std::ptr::null_mut();
		if unsafe {ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut())} == 0 {return Err(io::Error::last_os_error())}
		Ok(Self {next: unsafe {Self::make(descriptor as usize, true)?}, descriptor: descriptor as usize})
	}
	unsafe fn make(descriptor: usize, first: bool) -> io::Result<NamedPipeServer> {
		use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
		let mut attributes = SECURITY_ATTRIBUTES {nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: descriptor as *mut std::ffi::c_void, bInheritHandle: 0};
		ServerOptions::new().first_pipe_instance(first).reject_remote_clients(true).create_with_security_attributes_raw(PIPE, &mut attributes as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void)
	}
	pub async fn accept(&mut self) -> io::Result<Conn> {
		self.next.connect().await?;
		let ready = std::mem::replace(&mut self.next, unsafe {Self::make(self.descriptor, false)?});
		Ok(Box::new(ready))
	}
}

/// `S-1-` and digits and dashes: the only shape that goes into the access list and into a command line.
#[cfg(windows)]
pub fn sid_ok(sid: &str) -> bool {sid.starts_with("S-1-") && sid.len() < 128 && sid.bytes().all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')}

#[cfg(windows)]
pub async fn connect() -> io::Result<Conn> {
	for _ in 0..20 {
		match ClientOptions::new().open(PIPE) {
			Ok(client) => return Ok(Box::new(client)),
			// ERROR_PIPE_BUSY: every instance is taken for a moment.
			Err(error) if error.raw_os_error() == Some(231) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
			Err(error) => return Err(error),
		}
	}
	Err(io::ErrorKind::TimedOut.into())
}

/// Reads `name` in `dir`, a folder of the user `uid`, for a process that has more rights than that user. The folder is opened once without following a link as its last part and has to be that user's; the file is opened relative to it, also without following, and has to be a regular file of that user's of at most `max` bytes.
#[cfg(unix)]
pub fn read_user_file(dir: &Path, name: &str, uid: u32, max: usize) -> io::Result<String> {
	use rustix::fs::{fstat, open, openat, FileType, Mode, OFlags};
	use std::io::Read;
	let folder = open(dir, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty())?;
	if fstat(&folder)?.st_uid != uid {return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the folder is not the user's"))}
	// Not blocking, so that a pipe planted under the name is refused by the type check below instead of waited on.
	let fd = openat(&folder, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK, Mode::empty())?;
	let found = fstat(&fd)?;
	if FileType::from_raw_mode(found.st_mode) != FileType::RegularFile || found.st_uid != uid || found.st_size as u64 > max as u64 {return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the file is not a plain file of the user's"))}
	let mut text = String::new();
	std::fs::File::from(fd).take(max as u64).read_to_string(&mut text)?;
	Ok(text)
}

/// Windows has no `O_NOFOLLOW`; what is read is only ever compared with a nonce's proof and never echoed, written or executed.
#[cfg(windows)]
pub fn read_user_file(dir: &Path, name: &str, _owner: u32, max: usize) -> io::Result<String> {
	use std::io::Read;
	let mut text = String::new();
	std::fs::File::open(dir.join(name))?.take(max as u64).read_to_string(&mut text)?;
	Ok(text)
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;
	use std::os::unix::fs::symlink;

	fn euid() -> u32 {unsafe {libc::geteuid()}}

	fn scratch(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-ipc-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn a_plain_file_of_the_user_in_a_folder_of_the_user_is_read() {
		let dir = scratch("plain");
		std::fs::write(dir.join("token"), "abc").unwrap();
		assert_eq!(read_user_file(&dir, "token", euid(), 64).unwrap(), "abc");
		assert!(read_user_file(&dir, "token", euid() + 1, 64).is_err(), "a folder of another user");
		assert!(read_user_file(&dir, "token", euid(), 2).is_err(), "longer than allowed");
		assert!(read_user_file(&dir, "missing", euid(), 64).is_err());
	}

	#[test]
	fn a_link_in_place_of_the_folder_or_the_file_is_never_followed() {
		let dir = scratch("links");
		let (real, secret) = (dir.join("real"), dir.join("secret"));
		std::fs::create_dir_all(&real).unwrap();
		std::fs::write(&secret, "abc").unwrap();
		symlink(&secret, real.join("token")).unwrap();
		assert!(read_user_file(&real, "token", euid(), 64).is_err(), "a link as the file");
		symlink(&real, dir.join("alias")).unwrap();
		std::fs::write(real.join("plain"), "abc").unwrap();
		assert!(read_user_file(&dir.join("alias"), "plain", euid(), 64).is_err(), "a link as the folder");
	}

	#[test]
	fn a_pipe_or_a_folder_in_place_of_the_file_is_refused_without_waiting() {
		let dir = scratch("kinds");
		let fifo = std::ffi::CString::new(dir.join("token").to_str().unwrap()).unwrap();
		assert_eq!(unsafe {libc::mkfifo(fifo.as_ptr(), 0o600)}, 0);
		assert!(read_user_file(&dir, "token", euid(), 64).is_err());
		std::fs::create_dir(dir.join("folder")).unwrap();
		assert!(read_user_file(&dir, "folder", euid(), 64).is_err());
	}

	#[test]
	fn a_run_folder_that_others_can_write_in_is_refused() {
		let dir = scratch("run");
		std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
		assert!(check_dir(&dir).is_err());
		std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
		assert!(check_dir(&dir).is_ok());
		symlink(&dir, dir.join("self")).unwrap();
		assert!(check_dir(&dir.join("self")).is_err());
	}
}
