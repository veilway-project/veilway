//! The run directory: the one lock every command takes, the process number under it, and the status a running client writes for `veilway status`.
//!
//! The lock is at a fixed path, `/run/veilway/client.lock`, and neither an environment variable nor a flag moves it: the things a client changes (the nftables table, the routing table, the rule priorities) are the system's and there is one of each, so there is one lock. Whoever takes it is the only one that may change them. A client holds it for as long as it runs, `disconnect` and a clean-up hold it while they remove what a client left, and a command that finds it held does not touch what is in force.
use rustix::fs::{flock, FlockOperation};
use rustix::io::Errno;
use rustix::process::{geteuid, kill_process, Pid, Signal};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::{sleep, Instant};

pub const DEFAULT: &str = "/run/veilway";
/// Where the client keeps what has to survive a reboot: the copy of `/etc/resolv.conf` that a connection replaced, and the vault key of root. Root only.
pub const STATE: &str = "/var/lib/veilway";
const LOCK: &str = "client.lock";
const STATUS: &str = "status.txt";
/// The directories the programs the client runs as root are looked for in, and nowhere else: not `PATH`, which a user who started the program with `sudo -E` may have set.
const PROGRAMS: [&str; 6] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"];

/// The path of a program of the system, from the fixed list of directories.
pub fn program(name: &str) -> io::Result<PathBuf> {PROGRAMS.iter().map(|dir| Path::new(dir).join(name)).find(|path| path.is_file()).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("the {name} program is not installed")))}

/// A directory this user owns, that nobody else can write in, and that is not a link. Made with `mode` if it is not there. A client that runs as root must not be walked into `/etc` by a path a user planted, so a directory that fails this is an error and is never changed to fit.
pub fn secure_dir(path: &Path, mode: u32) -> io::Result<()> {
	if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {fs::create_dir_all(parent)?}
	match fs::symlink_metadata(path) {
		Ok(meta) if meta.is_dir() && meta.uid() == geteuid().as_raw() && meta.mode() & 0o022 == 0 => Ok(()),
		Ok(_) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a directory of this user that only this user can write in", path.display()))),
		Err(error) if error.kind() == io::ErrorKind::NotFound => fs::DirBuilder::new().mode(mode).create(path),
		Err(error) => Err(error),
	}
}

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
		let dir = std::env::temp_dir().join(format!("veilway-run-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	#[tokio::test]
	async fn one_client_holds_the_lock_and_the_second_is_told_who() {
		let dir = scratch("lock");
		assert_eq!(holder(&dir), Holder::Free);
		let held = lock(&dir).await.unwrap();
		assert_eq!(holder(&dir), Holder::Pid(std::process::id()));
		let error = lock(&dir).await.unwrap_err();
		assert!(error.to_string().contains(&std::process::id().to_string()), "{error}");
		drop(held);
		assert_eq!(holder(&dir), Holder::Free);
		assert!(lock(&dir).await.is_ok());
	}

	#[test]
	fn a_lock_with_no_number_under_it_yet_is_a_client_that_is_starting_and_not_a_free_lock() {
		let dir = scratch("starting");
		secure_dir(&dir, 0o755).unwrap();
		let file = open(&dir, true).unwrap();
		flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
		assert_eq!(holder(&dir), Holder::Starting);
		drop(file);
		assert_eq!(holder(&dir), Holder::Free);
	}

	#[tokio::test]
	async fn a_lock_that_an_observer_holds_for_a_moment_does_not_fail_a_connect() {
		let dir = scratch("observer");
		secure_dir(&dir, 0o755).unwrap();
		drop(open(&dir, true).unwrap());
		let observer = open(&dir, false).unwrap();
		flock(&observer, FlockOperation::NonBlockingLockShared).unwrap();
		let release = std::thread::spawn(move || {
			std::thread::sleep(Duration::from_millis(200));
			drop(observer);
		});
		assert!(lock(&dir).await.is_ok());
		release.join().unwrap();
	}

	#[test]
	fn a_directory_that_is_a_link_or_that_others_can_write_in_is_refused_and_not_changed() {
		let dir = scratch("secure");
		fs::create_dir_all(&dir).unwrap();
		let (target, link, open_dir) = (dir.join("target"), dir.join("link"), dir.join("open"));
		fs::create_dir(&target).unwrap();
		std::os::unix::fs::symlink(&target, &link).unwrap();
		assert!(secure_dir(&link, 0o700).is_err());
		fs::create_dir(&open_dir).unwrap();
		fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).unwrap();
		assert!(secure_dir(&open_dir, 0o700).is_err());
		assert_eq!(fs::metadata(&open_dir).unwrap().permissions().mode() & 0o777, 0o777);
		assert!(secure_dir(&dir.join("new"), 0o700).is_ok());
		assert_eq!(fs::metadata(dir.join("new")).unwrap().permissions().mode() & 0o777, 0o700);
	}

	#[tokio::test]
	async fn a_lock_file_that_is_a_link_is_not_followed() {
		let dir = scratch("nofollow");
		secure_dir(&dir, 0o755).unwrap();
		let target = dir.join("elsewhere");
		fs::write(&target, "keep").unwrap();
		std::os::unix::fs::symlink(&target, dir.join(LOCK)).unwrap();
		assert!(lock(&dir).await.is_err());
		assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
	}

	#[test]
	fn programs_are_found_in_the_fixed_directories_only() {
		assert!(program("sh").is_ok());
		assert!(program("no-such-program-anywhere").is_err());
	}

	#[test]
	fn a_status_is_written_whole_and_read_back() {
		let dir = scratch("status");
		fs::create_dir_all(&dir).unwrap();
		write_status(&dir, "Home\nConnected\n").unwrap();
		assert_eq!(read_status(&dir).unwrap(), "Home\nConnected\n");
		remove_status(&dir);
		assert!(read_status(&dir).is_err());
	}
}
