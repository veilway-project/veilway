//! The run directory: the one lock every command takes, the process number under it, and the status a running client writes for `veilway status`. Also the checks on the folders the client keeps its files in.
//!
//! The lock is at a fixed path, `/var/run/veilway/client.lock`, and neither an environment variable nor a flag moves it: the things a client changes (the pf anchor, the routing table, the resolver entry) are the system's and there is one of each, so there is one lock. Whoever takes it is the only one that may change them. A client holds it for as long as it runs, `disconnect` and a clean-up hold it while they remove what a client left, and a command that finds it held does not touch what is in force.
//!
//! The folders (`DEFAULT` for the lock and the status, `DATA` for the pf token and the client's files) are root's. A folder that is a link, is not owned by root, or can be written by others is an error and is never changed to fit: a client that runs as root must not be walked into a folder a user planted.
use rustix::fs::{flock, FlockOperation};
use rustix::io::Errno;
use rustix::process::{kill_process, Pid, Signal};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::{sleep, Instant};

pub const DEFAULT: &str = "/var/run/veilway";
/// What has to survive a reboot or a crash: the pf token, and in `client` the vault and the engine's memory. Root only.
pub const DATA: &str = "/Library/Application Support/Veilway";
const LOCK: &str = "client.lock";
const STATUS: &str = "status.txt";
/// The directories the programs the client runs as root are looked for in, and nowhere else: not `PATH`, which a user who started the program with `sudo -E` may have set.
const PROGRAMS: [&str; 4] = ["/sbin", "/usr/sbin", "/usr/bin", "/bin"];

/// The path of a program of the system, from the fixed list of directories.
pub fn program(name: &str) -> io::Result<PathBuf> {PROGRAMS.iter().map(|dir| Path::new(dir).join(name)).find(|path| path.is_file()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("the {name} program is not installed")))}

/// Whether a folder with these facts can be used: a directory (not a link) of `owner` that no one else can write in.
pub fn folder_problem(is_dir: bool, uid: u32, mode: u32, owner: u32) -> Option<&'static str> {
	if !is_dir {Some("is not a directory, or is a link")} else if uid != owner {Some("is not owned by the account that must own it")} else if mode & 0o022 != 0 {Some("can be written by others")} else {None}
}

/// Checks a folder, and makes it with `mode` if it is not there. The owner is root for every folder of the client; `secure_dir_as` names another for tests.
pub fn secure_dir(path: &Path, mode: u32) -> io::Result<()> {secure_dir_as(path, mode, 0)}

pub fn secure_dir_as(path: &Path, mode: u32, owner: u32) -> io::Result<()> {
	if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {fs::create_dir_all(parent)?}
	match fs::symlink_metadata(path) {
		Ok(meta) => match folder_problem(meta.is_dir(), meta.uid(), meta.mode(), owner) {
			None => Ok(()),
			Some(problem) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} {problem}", path.display()))),
		},
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			fs::DirBuilder::new().mode(mode).create(path)?;
			// The process's umask may have taken bits off the mode, never put any on; a folder that is not as asked is not used.
			match folder_problem(true, fs::symlink_metadata(path)?.uid(), mode, owner) {None => Ok(()), Some(problem) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} {problem}", path.display())))}
		}
		Err(error) => Err(error),
	}
}

/// The first folder of a chain (root down to the folder itself, each with its owner and mode) that someone other than `owner` could change the contents of, with what is wrong with it. A folder that others can write in lets them swap the next one for a link.
pub fn chain_problem(chain: &[(PathBuf, u32, u32)], owner: u32) -> Option<String> {chain.iter().find_map(|(path, uid, mode)| folder_problem(true, *uid, *mode, owner).map(|problem| format!("{} {problem}", path.display())))}

/// `secure_dir` for a folder a user may have named (`--data-dir`): after it is made or checked, the path is resolved, and every folder from `/` down to it must be `owner`'s and closed to others. The resolved path is returned and is the one to use: the links of the system itself (`/var` is `/private/var`) are followed, and a link in a folder that is not root's would have to be in a folder that fails the check.
pub fn secure_tree_as(path: &Path, mode: u32, owner: u32) -> io::Result<PathBuf> {
	secure_dir_as(path, mode, owner)?;
	let real = fs::canonicalize(path)?;
	let chain = real.ancestors().map(|folder| fs::metadata(folder).map(|meta| (folder.to_owned(), meta.uid(), meta.mode()))).collect::<io::Result<Vec<_>>>()?;
	match chain_problem(&chain, owner) {None => Ok(real), Some(problem) => Err(io::Error::new(io::ErrorKind::PermissionDenied, problem))}
}

pub fn secure_tree(path: &Path, mode: u32) -> io::Result<PathBuf> {secure_tree_as(path, mode, 0)}

fn open(dir: &Path, write: bool) -> io::Result<File> {OpenOptions::new().read(true).write(write).create(write).truncate(false).mode(0o644).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(dir.join(LOCK))}

fn pid_in(file: &mut File) -> Option<u32> {
	let mut text = String::new();
	file.read_to_string(&mut text).ok()?;
	text.trim().parse().ok()
}

/// The lock, held until it is dropped, which is when the process ends however it ends.
#[derive(Debug)]
pub struct Lock {_file: File}

/// Takes the lock for this process and writes its process number under it. A holder that is still taking it, or an observer that looks for a moment, is waited for a second: only a lock that stays held is a client that runs.
pub async fn lock(dir: &Path) -> io::Result<Lock> {
	secure_dir(dir, 0o755)?;
	let mut file = open(dir, true)?;
	for attempt in 0..20 {
		match flock(&file, FlockOperation::NonBlockingLockExclusive) {
			Ok(()) => {
				file.set_len(0)?;
				write!(file, "{}", std::process::id())?;
				return Ok(Lock {_file: file});
			}
			Err(Errno::WOULDBLOCK) if attempt < 19 => sleep(Duration::from_millis(50)).await,
			Err(Errno::WOULDBLOCK) => return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("a connection runs already (process {}), or another veilway command is working on it. Stop it with `veilway disconnect`", pid_in(&mut file).map_or_else(|| "unknown".to_owned(), |pid| pid.to_string())))),
			Err(error) => return Err(error.into()),
		}
	}
	unreachable!("the loop returns on its last attempt")
}

/// Who holds the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
	Free,
	/// Held, and the process number is not under it yet: the holder is still starting.
	Starting,
	Pid(u32),
}

pub fn holder(dir: &Path) -> Holder {
	let Ok(mut file) = open(dir, false) else {return Holder::Free};
	match flock(&file, FlockOperation::NonBlockingLockShared) {
		Err(Errno::WOULDBLOCK) => pid_in(&mut file).map_or(Holder::Starting, Holder::Pid),
		_ => Holder::Free,
	}
}

/// What `terminate` had to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
	/// Nothing was running.
	NotRunning,
	/// The client stopped by itself after the request to, and removed what it made.
	Stopped(u32),
	/// It did not, and was killed. What a kill leaves is for `cleanup`.
	Killed(u32),
}

/// Asks the running client to stop, which it does the clean way, and waits for it to, and kills it if it does not in `wait`.
pub async fn terminate(dir: &Path, wait: Duration) -> io::Result<Ended> {
	let deadline = Instant::now() + wait;
	let pid = loop {
		match holder(dir) {
			Holder::Free => return Ok(Ended::NotRunning),
			Holder::Pid(pid) => break pid,
			Holder::Starting if Instant::now() < deadline => sleep(Duration::from_millis(50)).await,
			Holder::Starting => return Err(io::Error::new(io::ErrorKind::TimedOut, "a client is starting and has not said who it is")),
		}
	};
	let target = i32::try_from(pid).ok().and_then(Pid::from_raw).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the lock file names no process"))?;
	kill_process(target, Signal::TERM)?;
	while Instant::now() < deadline {
		sleep(Duration::from_millis(100)).await;
		if holder(dir) == Holder::Free {return Ok(Ended::Stopped(pid))}
	}
	kill_process(target, Signal::KILL)?;
	sleep(Duration::from_millis(500)).await;
	Ok(Ended::Killed(pid))
}

/// Writes the status text where `veilway status` reads it. Anyone may read it: it holds the connection's name and its state and no secret.
pub fn write_status(dir: &Path, text: &str) -> io::Result<()> {
	let path = dir.join(STATUS);
	veilway_engine::store::write_atomic(&path, text.as_bytes())?;
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
}

pub fn read_status(dir: &Path) -> io::Result<String> {fs::read_to_string(dir.join(STATUS))}

pub fn remove_status(dir: &Path) {let _ = fs::remove_file(dir.join(STATUS));}

#[cfg(test)]
mod tests {
	use super::*;

	fn scratch(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-mac-run-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	#[test]
	fn a_folder_must_be_a_directory_of_its_owner_that_others_cannot_write() {
		assert_eq!(folder_problem(true, 0, 0o755, 0), None);
		assert_eq!(folder_problem(true, 0, 0o700, 0), None);
		assert!(folder_problem(false, 0, 0o755, 0).is_some(), "a link or a file");
		assert!(folder_problem(true, 501, 0o755, 0).is_some(), "a folder a user made");
		assert!(folder_problem(true, 0, 0o775, 0).is_some(), "group can write");
		assert!(folder_problem(true, 0, 0o757, 0).is_some(), "anyone can write");
	}

	#[test]
	fn a_folder_is_made_checked_and_a_link_or_a_loose_folder_is_refused() {
		let (dir, uid) = (scratch("dirs"), rustix::process::geteuid().as_raw());
		let good = dir.join("good");
		secure_dir_as(&good, 0o700, uid).unwrap();
		secure_dir_as(&good, 0o700, uid).unwrap();
		assert!(secure_dir_as(&good, 0o700, uid + 1).is_err(), "another owner is wanted");
		let link = dir.join("link");
		std::os::unix::fs::symlink(&good, &link).unwrap();
		assert!(secure_dir_as(&link, 0o700, uid).is_err());
		let loose = dir.join("loose");
		fs::create_dir(&loose).unwrap();
		fs::set_permissions(&loose, fs::Permissions::from_mode(0o777)).unwrap();
		assert!(secure_dir_as(&loose, 0o700, uid).is_err());
	}

	#[test]
	fn a_chain_is_as_good_as_its_worst_folder() {
		let folder = |path: &str, uid: u32, mode: u32| (PathBuf::from(path), uid, mode);
		assert_eq!(chain_problem(&[folder("/Library/Application Support/Veilway/client", 0, 0o40700), folder("/Library/Application Support", 0, 0o40755), folder("/", 0, 0o40755)], 0), None);
		let tmp = chain_problem(&[folder("/tmp/x", 0, 0o40700), folder("/tmp", 0, 0o41777), folder("/", 0, 0o40755)], 0).unwrap();
		assert!(tmp.starts_with("/tmp ") && tmp.contains("written by others"), "{tmp}");
		assert!(chain_problem(&[folder("/Users/me/data", 501, 0o40700), folder("/Users/me", 501, 0o40755)], 0).unwrap().contains("/Users/me/data"));
		assert!(chain_problem(&[folder("/a", 0, 0o40775)], 0).is_some(), "group can write");
	}

	#[test]
	fn a_tree_under_a_folder_others_can_write_in_is_refused() {
		let (dir, uid) = (scratch("tree"), rustix::process::geteuid().as_raw());
		let error = secure_tree_as(&dir.join("a").join("b"), 0o700, uid).unwrap_err();
		assert!(error.kind() == io::ErrorKind::PermissionDenied, "the system's temporary folder is closed to nobody: {error}");
	}

	#[tokio::test]
	async fn a_lock_is_held_by_one_and_seen_by_the_others() {
		if !rustix::process::geteuid().is_root() {return}
		let dir = scratch("lock").join("run");
		assert_eq!(holder(&dir), Holder::Free);
		let held = lock(&dir).await.unwrap();
		assert_eq!(holder(&dir), Holder::Pid(std::process::id()));
		drop(held);
		assert_eq!(holder(&dir), Holder::Free);
	}

	#[test]
	fn the_status_is_written_read_and_removed() {
		let dir = scratch("status");
		fs::create_dir_all(&dir).unwrap();
		write_status(&dir, "Connected.\n").unwrap();
		assert_eq!(read_status(&dir).unwrap(), "Connected.\n");
		remove_status(&dir);
		assert!(read_status(&dir).is_err());
	}
}
