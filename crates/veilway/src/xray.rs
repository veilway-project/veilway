//! The Xray-core add-on of the desktop client. An archive is checked against the pin before it is opened, one entry is taken out of it under a cap, and the executable is checked again from the open file before every start, so the file that is hashed is the file that runs.
use anyhow::{bail, Context};
use ring::digest::{Context as Hasher, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use veilway_engine::xray::{Live, XraySay};
use veilway_proto::xray::{self, Pin};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use tokio::process::{Child, Command};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use veilway_windows::xray::Child;

/// `FILE_SHARE_READ`: the file is opened so that nobody can write to it or delete it while it is held.
#[cfg(windows)]
const SHARE_READ: u32 = 1;
#[cfg(windows)]
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const REPARSE_POINT: u32 = 0x400;

/// The archive as the release publishes it, at most this many bytes.
pub const ARCHIVE_MAX: u64 = 64 << 20;
/// The executable inside the archive, inflated, at most this many bytes.
pub const EXECUTABLE_MAX: u64 = 128 << 20;

/// The pin target of this build, or `None` where the app ships no Xray.
pub fn target() -> Option<&'static str> {
	Some(match (std::env::consts::OS, std::env::consts::ARCH) {
		("linux", "x86_64") => "linux-64",
		("linux", "aarch64") => "linux-arm64-v8a",
		("macos", "x86_64") => "macos-64",
		("macos", "aarch64") => "macos-arm64-v8a",
		("windows", "x86_64") => "windows-64",
		("windows", "aarch64") => "windows-arm64-v8a",
		_ => return None,
	})
}

fn digest(file: &mut impl Read) -> io::Result<String> {
	let mut hasher = Hasher::new(&SHA256);
	let mut buffer = vec![0; 1 << 16];
	loop {
		let read = file.read(&mut buffer)?;
		if read == 0 {break}
		hasher.update(&buffer[..read]);
	}
	Ok(hasher.finish().as_ref().iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The add-on is not what this app pins: it is another file, or someone else can write to it. The app shows "the Xray add-on does not match this app" and logs both values.
#[derive(Debug)]
pub struct Mismatch(pub String);

impl std::fmt::Display for Mismatch {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "the Xray add-on does not match this app: {}", self.0)}
}

impl std::error::Error for Mismatch {}

/// Opens the installed executable without following a link, and holds it to the pin: the owner is root (the Administrators or SYSTEM on Windows, for it and the folders above it) and nobody else can write to it. The open file is rewound and returned, so the caller runs what was hashed on Linux. On Windows it is opened so that nobody can write to it or delete it, and the caller keeps it open until the child has exited. A file that fails the pin is a `Mismatch`.
pub fn open_checked(path: &Path, pin: &Pin) -> anyhow::Result<File> {
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_NOFOLLOW);
	#[cfg(windows)]
	options.share_mode(SHARE_READ).custom_flags(OPEN_REPARSE_POINT);
	let mut file = options.open(path).with_context(|| format!("the Xray executable cannot be opened: {}", path.display()))?;
	#[cfg(unix)]
	let meta = file.metadata()?;
	#[cfg(unix)]
	if meta.uid() != 0 || meta.mode() & 0o022 != 0 {return Err(Mismatch("the executable is not root's or can be written by someone else".to_owned()).into())}
	#[cfg(windows)]
	if file.metadata()?.file_attributes() & REPARSE_POINT != 0 {return Err(Mismatch("the executable is a link".to_owned()).into())}
	#[cfg(windows)]
	if let Some(problem) = veilway_windows::state::addon_problem(path)? {return Err(Mismatch(problem).into())}
	let got = digest(&mut file)?;
	if got != pin.executable {return Err(Mismatch(format!("want {}, got {got}", pin.executable)).into())}
	file.seek(SeekFrom::Start(0))?;
	Ok(file)
}

/// Installs the add-on from an archive on disk. The archive is checked before it is opened. The one entry named `xray` (`xray.exe` on Windows) is inflated under a cap into a staged file, which is checked against the executable pin before it is renamed into place. A failure leaves nothing staged, and the folders of other releases go only after the new one is in place.
pub fn install(addons: &Path, archive: &Path, pin: &Pin) -> anyhow::Result<PathBuf> {
	let size = fs::metadata(archive)?.len();
	if size > ARCHIVE_MAX {bail!("the Xray archive is {size} bytes, over the {ARCHIVE_MAX} the app takes")}
	let got = digest(&mut File::open(archive)?)?;
	if got != pin.archive {bail!("the Xray archive does not match its pin: want {}, got {got}", pin.archive)}
	let name = if cfg!(windows) {"xray.exe"} else {"xray"};
	let mut zip = zip::ZipArchive::new(File::open(archive)?).context("the Xray archive is not a zip")?;
	let mut found = None;
	for index in 0..zip.len() {
		let entry = zip.by_index_raw(index)?;
		let (entry_name, link) = (entry.name().context("an entry of the Xray archive has a name that does not read")?.into_owned(), entry.is_symlink());
		if entry_name.rsplit(['/', '\\']).next() != Some(name) {continue}
		if entry_name != name || link || found.replace(index).is_some() {bail!("the Xray archive has a second {name}, or one that is not at the top, or a link")}
	}
	let Some(index) = found else {bail!("the Xray archive has no {name}")};
	let folder = addons.join("xray").join(xray::RELEASE);
	fs::create_dir_all(&folder)?;
	let staged = folder.join(format!("{name}.new"));
	let inflated = (|| -> anyhow::Result<()> {
		let mut entry = zip.by_index(index)?;
		let copied = io::copy(&mut (&mut entry).take(EXECUTABLE_MAX + 1), &mut File::create(&staged)?)?;
		if copied > EXECUTABLE_MAX {bail!("the Xray executable is over the {EXECUTABLE_MAX} bytes the app takes")}
		Ok(())
	})();
	let verified = inflated.and_then(|_| -> anyhow::Result<()> {
		let got = digest(&mut File::open(&staged)?)?;
		if got != pin.executable {bail!("the Xray executable does not match its pin: want {}, got {got}", pin.executable)}
		Ok(())
	});
	if let Err(error) = verified {
		let _ = fs::remove_file(&staged);
		return Err(error);
	}
	#[cfg(unix)]
	fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
	// Windows flushes a file only through a handle that can write.
	OpenOptions::new().write(true).open(&staged)?.sync_all()?;
	let installed = folder.join(name);
	#[cfg(target_os = "macos")]
	immutable(&installed, false)?;
	fs::rename(&staged, &installed)?;
	#[cfg(target_os = "macos")]
	immutable(&installed, true)?;
	for old in fs::read_dir(addons.join("xray"))? {
		let old = old?.path();
		if old != folder && old.is_dir() {
			#[cfg(target_os = "macos")]
			immutable(&old.join(name), false)?;
			fs::remove_dir_all(&old)?
		}
	}
	Ok(installed)
}

/// Sets the immutable flag of a file (`chflags uchg`), or clears it, so that the add-on cannot be swapped by a root process that does not mean to. macOS runs a file by its path, so this is what keeps the path to what was hashed. A file that is not there is fine.
#[cfg(target_os = "macos")]
fn immutable(path: &Path, on: bool) -> io::Result<()> {
	let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
	// SAFETY: the path is a NUL-terminated string that lives through the call.
	if unsafe {libc::chflags(name.as_ptr(), if on {libc::UF_IMMUTABLE} else {0})} == 0 {Ok(())} else {Err(io::Error::last_os_error()).or_else(|error| if error.kind() == io::ErrorKind::NotFound {Ok(())} else {Err(error)})}
}

const MIN: Duration = Duration::from_secs(1);
const MAX: Duration = Duration::from_secs(60);
const HEALTH: Duration = Duration::from_secs(10);
const STOP: Duration = Duration::from_secs(8);
const HANDSHAKE: Duration = Duration::from_secs(10);
const LINE_MAX: usize = 512;

/// The wait before the next start, and the wait that follows it: 1 s, doubling to 60 s, and 1 s again after a run of 60 s or more. Nothing counts failures, so nothing latches.
pub fn backoff(wait: Duration, ran: Duration) -> (Duration, Duration) {
	if ran >= MAX {return (MIN, MIN * 2)}
	(wait, (wait * 2).min(MAX))
}

/// A SOCKS5 handshake with the local hop, with the login: the check the supervisor makes every 10 s.
pub async fn socks_ok(port: u16, login: &str) -> bool {
	let check = async {
		let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
		stream.write_all(&[5, 1, 2]).await?;
		let mut greeting = [0u8; 2];
		stream.read_exact(&mut greeting).await?;
		let mut auth = vec![1, 7];
		auth.extend_from_slice(b"veilway");
		auth.push(login.len() as u8);
		auth.extend_from_slice(login.as_bytes());
		stream.write_all(&auth).await?;
		let mut reply = [0u8; 2];
		stream.read_exact(&mut reply).await?;
		Ok::<bool, io::Error>(greeting == [5, 2] && reply == [1, 0])
	};
	matches!(tokio::time::timeout(HANDSHAKE, check).await, Ok(Ok(true)))
}

/// A new login for a run: 24 random bytes in hex, given to the child in its document and to the local check only.
pub fn new_login() -> anyhow::Result<String> {
	let mut bytes = [0u8; 24];
	SystemRandom::new().fill(&mut bytes).map_err(|_| anyhow::anyhow!("no random source"))?;
	Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

// Standard output and error of the child, as lines: each cut to 512 bytes and with every secret of the run replaced before it is logged.
async fn drain(output: impl AsyncRead + Unpin, secrets: Vec<String>) {
	let mut lines = BufReader::new(output).lines();
	while let Ok(Some(line)) = lines.next_line().await {
		let mut line = secrets.iter().fold(line, |line, secret| line.replace(secret.as_str(), "[redacted]"));
		line.truncate((0..=LINE_MAX.min(line.len())).rev().find(|at| line.is_char_boundary(*at)).unwrap_or(0));
		tracing::info!("xray: {line}");
	}
}

fn unix_now() -> u64 {SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())}

/// Starts the add-on from the descriptor of the file that was checked, as `ids` (the user and group made for it, which the caller got from the Linux layer). The path is `/proc/self/fd/N`, so the file that was hashed is the file that runs and there is no window between the check and the exec. Between the fork and the exec, and in the child only: the supplementary groups are dropped and the ids are changed, `no_new_privs` is set, a kill signal is asked for when this process ends, every capability is dropped, and the process is made dumpable again, which a change of ids undid and without which it cannot open its own `/proc/self/fd`. Environment empty, working directory the root of the filesystem, no console.
#[cfg(target_os = "linux")]
fn spawn_checked(file: &File, _path: &Path, args: &[&str], ids: (u32, u32)) -> io::Result<Child> {
	let (fd, parent) = (file.as_raw_fd(), std::process::id() as libc::pid_t);
	let mut command = Command::new(format!("/proc/self/fd/{fd}"));
	command.arg0("xray").args(args).env_clear().current_dir("/").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
	// Safety: only async-signal-safe calls run between the fork and the exec, and none allocates.
	unsafe {
		command.pre_exec(move || {
			if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(ids.1) != 0 || libc::setuid(ids.0) != 0 {return Err(io::Error::last_os_error())}
			if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {return Err(io::Error::last_os_error())}
			// The signal is only sent for a parent that dies after the call above, so a parent that died before it is looked for here.
			if libc::getppid() != parent {libc::_exit(1)}
			if libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 || libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) != 0 {return Err(io::Error::last_os_error())}
			// The descriptor is closed on exec in this process. In the child it stays open for the exec of `/proc/self/fd/N`.
			if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {return Err(io::Error::last_os_error())}
			Ok(())
		});
	}
	command.spawn()
}

/// macOS has no way to run a descriptor, so the path is run: it was hashed an instant ago, it lies in folders only root can write in, and the file has the immutable flag (`install`), which is the residual risk the spec names. Between the fork and the exec, and in the child only: a monitor process is forked that watches this process and Xray with a kqueue and kills Xray when this process ends however it ends (the child waits until the monitor has said it watches both), then the supplementary groups are dropped and the ids are changed to those of the account made for Xray. Environment empty, working directory the root of the filesystem.
#[cfg(target_os = "macos")]
fn spawn_checked(_file: &File, path: &Path, args: &[&str], ids: (u32, u32)) -> io::Result<Child> {
	let parent = std::process::id() as libc::pid_t;
	let mut command = Command::new(path);
	command.arg0("xray").args(args).env_clear().current_dir("/").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
	// Safety: only async-signal-safe calls run between the fork and the exec, and none allocates.
	unsafe {
		command.pre_exec(move || {
			let (me, mut ready) = (libc::getpid(), [0 as libc::c_int; 2]);
			if libc::pipe(ready.as_mut_ptr()) != 0 {return Err(io::Error::last_os_error())}
			match libc::fork() {
				-1 => return Err(io::Error::last_os_error()),
				0 => {
					// The monitor. It watches both with a kqueue, says one byte on the pipe (1 once the watch is in, 0 if it could not be), and then waits for the first of the two to end; if that is this process it kills Xray, and if that is Xray it has nothing left to do. An end that came before the watch began is reported at once as an error event, and means the same.
					libc::close(ready[0]);
					let queue = libc::kqueue();
					let mut changes: [libc::kevent; 2] = std::mem::zeroed();
					for (change, pid) in changes.iter_mut().zip([parent, me]) {
						change.ident = pid as libc::uintptr_t;
						change.filter = libc::EVFILT_PROC;
						change.flags = libc::EV_ADD | libc::EV_ONESHOT;
						change.fflags = libc::NOTE_EXIT;
					}
					let (mut event, now): (libc::kevent, libc::timespec) = (std::mem::zeroed(), std::mem::zeroed());
					let mut got = if queue >= 0 {libc::kevent(queue, changes.as_ptr(), 2, &mut event, 1, &now)} else {-1};
					let registered: u8 = u8::from(got >= 0);
					libc::write(ready[1], (&registered as *const u8).cast(), 1);
					libc::close(ready[1]);
					if registered == 0 {libc::_exit(1)}
					if got == 0 {got = libc::kevent(queue, std::ptr::null(), 0, &mut event, 1, std::ptr::null())}
					if got > 0 && event.ident as libc::pid_t != me {libc::kill(me, libc::SIGKILL);}
					libc::_exit(0);
				}
				_ => {}
			}
			libc::close(ready[1]);
			let mut said = 0u8;
			let read = libc::read(ready[0], (&mut said as *mut u8).cast(), 1);
			libc::close(ready[0]);
			if read != 1 || said != 1 {return Err(io::Error::other("the monitor of the child did not start"))}
			if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(ids.1) != 0 || libc::setuid(ids.0) != 0 {return Err(io::Error::last_os_error())}
			Ok(())
		});
	}
	command.spawn()
}

/// Windows: the child gets a restricted token and a job object that kills it (`veilway_windows::xray::Child`), and runs from the path, which the caller holds open with sharing that denies writes and deletes until the child has exited. The ids are not used: there is no account.
#[cfg(windows)]
fn spawn_checked(_file: &File, path: &Path, args: &[&str], _ids: (u32, u32)) -> io::Result<Child> {
	let root = veilway_windows::state::program("cmd.exe")?.ancestors().last().map(Path::to_path_buf).ok_or_else(|| io::Error::other("the system drive has no root"))?;
	Child::spawn(path, args, &root)
}

/// Whether every socket that listens on the loopback address at `port` belongs to Xray, and at least one does. On Linux Xray is told from the rest by its user, whose sockets are read from `/proc/net`; on macOS and Windows by the process, whose number the supervisor holds. A process that took the port first (or shares it) is seen whatever it answers.
#[cfg(target_os = "linux")]
fn listener_owned(port: u16, ids: (u32, u32), _pid: Option<u32>) -> bool {veilway_linux::xray::listening_as(std::net::SocketAddr::from(([127, 0, 0, 1], port)), ids.0, false).unwrap_or(false)}

#[cfg(target_os = "macos")]
fn listener_owned(port: u16, _ids: (u32, u32), pid: Option<u32>) -> bool {pid.is_some_and(|pid| veilway_macos::xray::listening_as(std::net::SocketAddr::from(([127, 0, 0, 1], port)), pid, false).unwrap_or(false))}

#[cfg(windows)]
fn listener_owned(port: u16, _ids: (u32, u32), pid: Option<u32>) -> bool {pid.is_some_and(|pid| veilway_windows::xray::listening_as(std::net::SocketAddr::from(([127, 0, 0, 1], port)), pid, false).unwrap_or(false))}

/// Runs the add-on until `stop` is set: the executable is checked before each start and run from the open file (kept open until the child has ended, which on Windows is what keeps it from being swapped), the document is built for the physical interface that `live` holds at the time (`document` takes its name, or none) and given on standard input, a change of that interface restarts the child at once, and `live` says the add-on is up after the first SOCKS handshake with the login has worked and down the moment it ends or its local check fails twice. The local check runs every 10 s. A stop closes the input, waits 8 s and kills the child. A failure at any point waits and starts again, and every start after the first is a restart for the counter.
#[allow(clippy::too_many_arguments)]
pub async fn supervise(binary: PathBuf, pin: &'static Pin, document: impl Fn(Option<&str>) -> String, port: u16, login: String, secrets: Vec<String>, ids: (u32, u32), live: Arc<Live>, mut stop: watch::Receiver<bool>) {
	let (mut wait, mut starts, mut interface) = (MIN, 0u32, live.watch_interface());
	loop {
		let started = Instant::now();
		if starts > 0 {live.restarted(unix_now())}
		starts += 1;
		let text = document(interface.borrow_and_update().as_deref());
		// The open file stays here until the child is gone.
		let mut held = Vec::new();
		let spawned = open_checked(&binary, pin).and_then(|file| {
			let child = spawn_checked(&file, &binary, &["run", "-config", "stdin:"], ids)?;
			held.push(file);
			Ok(child)
		});
		let ran = match spawned {
			Err(error) => {
				live.explain(if error.is::<Mismatch>() {XraySay::Mismatch} else {XraySay::StartFailed});
				tracing::warn!("xray: the add-on did not start: {error:#}");
				Duration::ZERO
			}
			Ok(mut child) => {
				// Xray reads `stdin:` to its end, so the input is closed as soon as the document is in, and a document that did not go in is a failed start.
				let wrote = match child.stdin.take() {
					Some(mut input) => match input.write_all(text.as_bytes()).await {
						// A file of the runtime writes in the background, and closes only when its writes are done.
						Ok(()) => input.flush().await,
						Err(error) => Err(error),
					},
					None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "no standard input")),
				};
				if let Err(error) = wrote {
					live.explain(XraySay::StartFailed);
					tracing::warn!("xray: the document did not go in: {error}");
					let _ = child.start_kill();
					let _ = child.wait().await;
					let (pause, next) = backoff(wait, Duration::ZERO);
					wait = next;
					tokio::select! {
						_ = tokio::time::sleep(pause) => {}
						_ = stop.changed() => return,
					}
					continue;
				}
				if let Some(output) = child.stdout.take() {tokio::spawn(drain(output, secrets.clone()));}
				if let Some(output) = child.stderr.take() {tokio::spawn(drain(output, secrets.clone()));}
				live.set_pid(child.id());
				tracing::info!("xray: started");
				let (mut moved, mut tick, mut probe, mut up, mut missed) = (false, tokio::time::interval(HEALTH), tokio::time::interval(Duration::from_millis(250)), false, 0);
				tick.tick().await;
				let ended = loop {
					tokio::select! {
						status = child.wait() => {
							tracing::warn!("xray: exited with {status:?}");
							// An end the supervisor asked for because the interface changed is not a failure, and does not lengthen the wait.
							break if moved {MAX} else {started.elapsed()};
						}
						_ = interface.changed() => {
							tracing::info!("xray: the physical interface changed, restarting");
							moved = true;
							live.set_up(false);
							let _ = child.start_kill();
						}
						// Nothing is carried before the first handshake with the login has worked.
						_ = probe.tick(), if !up => {
							if socks_ok(port, &login).await {
								// The port was picked and released before Xray bound it, so whoever answers must be Xray's user.
								if !listener_owned(port, ids, child.id()) {
									live.explain(XraySay::PortTaken);
									tracing::warn!("xray: the SOCKS port is held by another user, nothing is carried");
									let _ = child.start_kill();
								} else {
									up = true;
									live.set_up(true);
									tracing::info!("xray: answers the local check, flows are carried");
								}
							} else if started.elapsed() > HANDSHAKE {
								tracing::warn!("xray: no answer to the local check in {HANDSHAKE:?}, restarting");
								let _ = child.start_kill();
							}
						}
						_ = tick.tick(), if up => {
							if socks_ok(port, &login).await && listener_owned(port, ids, child.id()) {missed = 0} else {
								missed += 1;
								if missed == 2 {
									tracing::warn!("xray: the local check failed twice, restarting");
									live.set_up(false);
									let _ = child.start_kill();
								}
							}
						}
						_ = stop.changed() => {
							live.set_up(false);
							let _ = tokio::time::timeout(STOP, child.wait()).await;
							let _ = child.start_kill();
							live.set_pid(None);
							return;
						}
					}
				};
				live.set_up(false);
				live.set_pid(None);
				ended
			}
		};
		let (pause, next) = backoff(wait, ran);
		wait = next;
		tracing::info!("xray: starting again in {pause:?}");
		tokio::select! {
			_ = tokio::time::sleep(pause) => {}
			_ = stop.changed() => return,
		}
	}
}

const HOSTS: [&str; 3] = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
const CONNECT: Duration = Duration::from_secs(10);
const TOTAL: Duration = Duration::from_secs(300);
const HEAD_MAX: usize = 16 << 10;

/// The places the archive is asked for, in order: GitHub, then each mirror (`https://host/prefix`, the layout of GitHub under it, as `veilway.sh --mirror` has it). For each, the host and the path, and the hosts a redirect may go to: GitHub's own, or for a mirror its own host. Which one answered does not matter, since the archive is checked against the pin before it is opened.
fn sources(target: &str, mirrors: &[String]) -> Vec<(String, String, Vec<String>)> {
	let tail = format!("/XTLS/Xray-core/releases/download/{}/Xray-{target}.zip", xray::RELEASE);
	let mut found = vec![("github.com".to_owned(), tail.clone(), HOSTS.iter().map(|host| (*host).to_owned()).collect())];
	for mirror in mirrors {
		let Some(rest) = mirror.strip_prefix("https://") else {continue};
		let (host, prefix) = rest.split_once('/').map_or((rest, ""), |(host, prefix)| (host, prefix.trim_end_matches('/')));
		if host.is_empty() || !host.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-') || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte)) || prefix.contains("..") {continue}
		found.push((host.to_owned(), format!("{}{tail}", if prefix.is_empty() {String::new()} else {format!("/{prefix}")}), vec![host.to_owned()]));
	}
	found
}

/// Downloads the release archive of this target to `part` (mode 600) over TLS with the chain validated, from GitHub and then from each mirror if that fails. Redirects follow only to the hosts of the source, and the file is removed on any failure.
pub async fn download(target: &str, part: &Path, mirrors: &[String]) -> anyhow::Result<()> {
	let mut last = anyhow::anyhow!("no source for the Xray archive");
	let started = Instant::now();
	for (host, path, allowed) in sources(target, mirrors) {
		let left = TOTAL.saturating_sub(started.elapsed());
		let outcome = tokio::time::timeout(left, fetch(host, path, part, &allowed)).await;
		if matches!(outcome, Ok(Ok(()))) {return Ok(())}
		let _ = fs::remove_file(part);
		last = match outcome {Ok(Err(error)) => error, _ => anyhow::anyhow!("the Xray download took longer than 300 seconds")};
		tracing::warn!("xray: a source of the archive failed: {last:#}");
	}
	Err(last)
}

async fn fetch(mut host: String, mut path: String, part: &Path, allowed: &[String]) -> anyhow::Result<()> {
	let roots = RootCertStore {roots: webpki_roots::TLS_SERVER_ROOTS.to_vec()};
	let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions()?.with_root_certificates(roots).with_no_client_auth();
	let tls = TlsConnector::from(Arc::new(config));
	let mut redirects = 0;
	loop {
		let tcp = tokio::time::timeout(CONNECT, TcpStream::connect((host.as_str(), 443))).await.context("the connection to the Xray host timed out")??;
		let mut stream = tls.connect(ServerName::try_from(host.clone())?, tcp).await?;
		stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: veilway\r\nAccept: */*\r\nConnection: close\r\n\r\n").as_bytes()).await?;
		let mut head = Vec::new();
		let split = loop {
			let mut chunk = [0u8; 4096];
			let read = stream.read(&mut chunk).await?;
			if read == 0 {bail!("the Xray host closed the connection in its headers")}
			head.extend_from_slice(&chunk[..read]);
			if let Some(at) = head.windows(4).position(|window| window == b"\r\n\r\n") {break at}
			if head.len() > HEAD_MAX {bail!("the headers of the Xray download are too long")}
		};
		let body = head.split_off(split + 4);
		head.truncate(split);
		let text = String::from_utf8_lossy(&head).into_owned();
		let mut lines = text.lines();
		let status = lines.next().and_then(|line| line.split_whitespace().nth(1)).and_then(|code| code.parse::<u16>().ok()).unwrap_or(0);
		let fields: Vec<(String, String)> = lines.filter_map(|line| line.split_once(':')).map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned())).collect();
		let field = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone());
		if matches!(status, 301 | 302 | 303 | 307 | 308) {
			redirects += 1;
			if redirects > 3 {bail!("the Xray download redirected more than three times")}
			let location = field("location").context("the Xray redirect has no location")?;
			let rest = location.strip_prefix("https://").context("the Xray redirect is not https")?;
			let (next_host, next_path) = rest.split_once('/').map_or((rest, "/".to_owned()), |(next_host, next_path)| (next_host, format!("/{next_path}")));
			if !allowed.iter().any(|allowed| allowed == next_host) {bail!("the Xray redirect leaves the release hosts")}
			host = next_host.to_owned();
			path = next_path;
			continue;
		}
		if status != 200 {bail!("the Xray download answered {status}")}
		if field("transfer-encoding").is_some() {bail!("the Xray download is chunked, which the app does not take")}
		let expected = field("content-length").and_then(|length| length.parse::<u64>().ok());
		let mut options = OpenOptions::new();
		options.write(true).create(true).truncate(true);
		#[cfg(unix)]
		options.mode(0o600);
		let mut file = options.open(part)?;
		let mut written = body.len() as u64;
		file.write_all(&body)?;
		let mut chunk = vec![0u8; 1 << 16];
		loop {
			let read = stream.read(&mut chunk).await?;
			if read == 0 {break}
			written += read as u64;
			if written > ARCHIVE_MAX {bail!("the Xray download is over the {ARCHIVE_MAX} bytes the app takes")}
			file.write_all(&chunk[..read])?;
		}
		if expected.is_some_and(|expected| expected != written) {bail!("the Xray download stopped at {written} bytes")}
		file.sync_all()?;
		return Ok(());
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use zip::{write::SimpleFileOptions, CompressionMethod};

	fn scratch(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-xray-{}-{name}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	fn archive(dir: &Path, entries: &[(&str, &[u8], bool)]) -> PathBuf {
		let path = dir.join("Xray.zip");
		let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
		for (name, data, link) in entries {
			let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
			if *link {zip.add_symlink(*name, "/etc/passwd", options).unwrap()} else {
				zip.start_file(*name, options).unwrap();
				zip.write_all(data).unwrap();
			}
		}
		zip.finish().unwrap();
		path
	}

	fn pin(archive: &Path, executable: &[u8]) -> Pin {
		let archive = digest(&mut File::open(archive).unwrap()).unwrap();
		let executable = digest(&mut &executable[..]).unwrap();
		Pin {target: "test", archive: Box::leak(archive.into_boxed_str()), executable: Box::leak(executable.into_boxed_str())}
	}

	#[test]
	fn backoff_doubles_to_a_minute_and_a_stable_run_starts_over() {
		let mut wait = MIN;
		let mut seen = Vec::new();
		for _ in 0..8 {
			let (pause, next) = backoff(wait, Duration::ZERO);
			seen.push(pause.as_secs());
			wait = next;
		}
		assert_eq!(seen, [1, 2, 4, 8, 16, 32, 60, 60]);
		assert_eq!(backoff(Duration::from_secs(32), Duration::from_secs(60)), (MIN, MIN * 2));
	}

	#[tokio::test]
	async fn the_local_check_sends_the_login_and_takes_only_its_answer() {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();
		tokio::spawn(async move {
			for _ in 0..2 {
				let (mut stream, _) = listener.accept().await.unwrap();
				let mut head = [0u8; 2];
				stream.read_exact(&mut head).await.unwrap();
				stream.read_exact(&mut vec![0u8; head[1] as usize]).await.unwrap();
				stream.write_all(&[5, 2]).await.unwrap();
				let mut user = [0u8; 2];
				stream.read_exact(&mut user).await.unwrap();
				let mut name = vec![0u8; user[1] as usize];
				stream.read_exact(&mut name).await.unwrap();
				let mut len = [0u8; 1];
				stream.read_exact(&mut len).await.unwrap();
				let mut pass = vec![0u8; len[0] as usize];
				stream.read_exact(&mut pass).await.unwrap();
				stream.write_all(&[1, if name == b"veilway" && pass == b"good" {0} else {1}]).await.unwrap();
			}
		});
		assert!(socks_ok(port, "good").await);
		assert!(!socks_ok(port, "bad").await);
	}

	#[test]
	fn a_matching_archive_installs_its_one_entry_and_checks_again_before_a_start() {
		let dir = scratch("install");
		let exe = b"not really xray".to_vec();
		let archive = archive(&dir, &[("README.md", b"hi", false), (if cfg!(windows) {"xray.exe"} else {"xray"}, &exe, false)]);
		let pin = pin(&archive, &exe);
		let installed = install(&dir.join("addons"), &archive, &pin).unwrap();
		assert_eq!(fs::read(&installed).unwrap(), exe);
		assert!(installed.ends_with(format!("xray/{}/{}", xray::RELEASE, if cfg!(windows) {"xray.exe"} else {"xray"})));
		// The installed file is trusted only when the test runs as root (an administrator on Windows, in a folder only they can write in); anywhere else the check must refuse it.
		#[cfg(unix)]
		let root = std::os::unix::fs::MetadataExt::uid(&fs::metadata(&installed).unwrap()) == 0;
		#[cfg(not(unix))]
		let root = veilway_windows::state::addon_problem(&installed).ok().flatten().is_none();
		if !root {return assert!(open_checked(&installed, &pin).is_err())}
		let mut opened = open_checked(&installed, &pin).unwrap();
		let mut again = Vec::new();
		opened.read_to_end(&mut again).unwrap();
		assert_eq!(again, exe);
		fs::write(&installed, b"changed").unwrap();
		assert!(open_checked(&installed, &pin).is_err());
	}

	// Runs as root in a container (`useradd` is not needed: `nobody` is there). Anywhere else it has nothing to try.
	#[cfg(target_os = "linux")]
	#[tokio::test]
	async fn the_checked_file_runs_from_its_descriptor_as_another_user_with_nothing_kept() {
		if !rustix::process::geteuid().is_root() {return}
		let Some(ids) = fs::read_to_string("/etc/passwd").unwrap().lines().find_map(|line| {
			let parts: Vec<&str> = line.split(':').collect();
			(parts[0] == "nobody").then(|| (parts[2].parse::<u32>().unwrap(), parts[3].parse::<u32>().unwrap()))
		}) else {return};
		let dir = scratch("spawn");
		let installed = dir.join("xray");
		fs::copy("/bin/sleep", &installed).unwrap();
		fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
		let pin = pin(&installed, &fs::read(&installed).unwrap());
		let file = open_checked(&installed, &pin).unwrap();
		let mut child = spawn_checked(&file, &installed, &["30"], ids).unwrap();
		let status = fs::read_to_string(format!("/proc/{}/status", child.id().unwrap())).unwrap();
		let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name)).map(|rest| rest.trim().to_owned()).unwrap();
		assert_eq!(field("Uid:"), format!("{0}\t{0}\t{0}\t{0}", ids.0));
		assert_eq!(field("Gid:"), format!("{0}\t{0}\t{0}\t{0}", ids.1));
		assert_eq!((field("NoNewPrivs:").as_str(), field("Groups:").as_str(), field("CapEff:").as_str(), field("CapPrm:").as_str()), ("1", "", "0000000000000000", "0000000000000000"));
		child.kill().await.unwrap();
		let mut other = pin;
		other.executable = "0".repeat(64).leak();
		assert!(open_checked(&installed, &other).unwrap_err().is::<Mismatch>());
	}

	// Xray reads `stdin:` to its end. This one is a script that does the same and then says what it read, so a document whose input stayed open would never be seen.
	#[cfg(target_os = "linux")]
	#[tokio::test]
	async fn the_document_goes_in_and_the_input_is_closed_so_the_child_sees_its_end() {
		if !rustix::process::geteuid().is_root() {return}
		let Some(ids) = fs::read_to_string("/etc/passwd").unwrap().lines().find_map(|line| {
			let parts: Vec<&str> = line.split(':').collect();
			(parts[0] == "nobody").then(|| (parts[2].parse::<u32>().unwrap(), parts[3].parse::<u32>().unwrap()))
		}) else {return};
		let dir = scratch("stdin");
		let out = dir.join("out");
		fs::create_dir(&out).unwrap();
		fs::set_permissions(&out, fs::Permissions::from_mode(0o777)).unwrap();
		let script = format!("#!/bin/sh\n/bin/cat > {0}/doc.part\n/bin/mv {0}/doc.part {0}/doc\nexit 0\n", out.display());
		let installed = dir.join("xray");
		fs::write(&installed, &script).unwrap();
		fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
		let pin: &'static Pin = Box::leak(Box::new(pin(&installed, script.as_bytes())));
		let (stop, stopped) = watch::channel(false);
		let document = "d".repeat(100_000);
		let sent = document.clone();
		let task = tokio::spawn(supervise(installed, pin, move |_| sent.clone(), 1, "login".into(), Vec::new(), ids, Live::new(), stopped));
		let seen = tokio::time::timeout(Duration::from_secs(10), async {
			loop {
				if let Ok(text) = fs::read_to_string(out.join("doc")) {return text}
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}).await.expect("the child never saw the end of its input");
		assert_eq!(seen, document);
		stop.send(true).unwrap();
		tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
	}

	#[test]
	fn the_mirrors_are_asked_after_github_and_only_over_https_with_a_plain_layout() {
		let found = sources("linux-64", &["https://mirror.example/releases".to_owned(), "http://plain.example".to_owned(), "https://evil.example/../x".to_owned(), "https://user@bad.example".to_owned(), "https://ok.example".to_owned()]);
		let hosts: Vec<&str> = found.iter().map(|source| source.0.as_str()).collect();
		assert_eq!(hosts, ["github.com", "mirror.example", "ok.example"]);
		assert_eq!(found[1].1, format!("/releases/XTLS/Xray-core/releases/download/{}/Xray-linux-64.zip", xray::RELEASE));
		assert_eq!(found[2].1, format!("/XTLS/Xray-core/releases/download/{}/Xray-linux-64.zip", xray::RELEASE));
		assert!(found[0].2.contains(&"release-assets.githubusercontent.com".to_owned()) && found[1].2 == ["mirror.example"], "a redirect may leave GitHub for its own hosts only, and a mirror for none");
	}

	#[test]
	fn an_archive_that_does_not_match_its_pin_is_refused_and_nothing_is_staged() {
		let dir = scratch("wrong-archive");
		let exe = b"x".to_vec();
		let archive = archive(&dir, &[("xray", &exe, false)]);
		let mut pin = pin(&archive, &exe);
		pin.archive = "0".repeat(64).leak();
		assert!(install(&dir.join("addons"), &archive, &pin).is_err());
		assert!(!dir.join("addons").exists());
	}

	#[test]
	fn an_executable_that_does_not_match_its_pin_leaves_no_staged_file() {
		let dir = scratch("wrong-exe");
		let exe = b"x".to_vec();
		let archive = archive(&dir, &[("xray", &exe, false)]);
		let mut pin = pin(&archive, &exe);
		pin.executable = "0".repeat(64).leak();
		assert!(install(&dir.join("addons"), &archive, &pin).is_err());
		assert!(!dir.join("addons").join("xray").join(xray::RELEASE).join("xray.new").exists());
	}

	#[test]
	fn an_entry_with_a_path_a_second_name_or_a_link_refuses_the_archive() {
		let dir = scratch("entries");
		let cases: [Vec<(&str, &[u8], bool)>; 3] = [vec![("bin/xray", b"x", false)], vec![("xrax", b"x", false), ("xray", b"y", false)], vec![("xray", b"x", true)]];
		for entries in cases {
			let archive = archive(&dir, &entries);
			let mut bytes = fs::read(&archive).unwrap();
			for at in 0..bytes.len().saturating_sub(3) {if &bytes[at..at + 4] == b"xrax" {bytes[at + 3] = b'y'}}
			fs::write(&archive, bytes).unwrap();
			let pin = pin(&archive, b"x");
			assert!(install(&dir.join("addons"), &archive, &pin).is_err(), "{:?}", entries.iter().map(|entry| entry.0).collect::<Vec<_>>());
		}
	}

	#[test]
	fn a_zip_bomb_stops_at_the_cap() {
		let dir = scratch("bomb");
		let exe = vec![0u8; EXECUTABLE_MAX as usize + 1];
		let archive = archive(&dir, &[("xray", &exe, false)]);
		assert!(fs::metadata(&archive).unwrap().len() < ARCHIVE_MAX);
		let pin = pin(&archive, &exe);
		assert!(install(&dir.join("addons"), &archive, &pin).is_err());
		assert!(!dir.join("addons").join("xray").join(xray::RELEASE).join("xray.new").exists());
	}
}
