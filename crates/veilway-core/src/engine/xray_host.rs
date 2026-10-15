//! The host of the Xray add-on: a small process that runs as a user of its own, which the node asks over a unix socket to start Xray. It is what lets Xray run without anything of the node's: its user, its files, its capabilities and its control socket.
//! The node connects and sends one document (a 4 byte length and the bytes). The host opens the executable in the add-on folder, which must belong to root and be writable by nobody else, takes its SHA-256 from the very file it then executes, and refuses anything but the pinned release. It starts Xray with the document on its standard input, no environment, no capability but the one to bind a port below 1024 when the document has one, and a kill signal for when this process ends.
//! It answers `ok <pid>` or `error <reason>` on one line. The connection is Xray's lease: when the node closes it, or ends, Xray is killed and awaited. When Xray ends first the host says `ended <status>` and closes.
use super::xray::{PIN, RELEASE};
use ring::digest::{Context, SHA256};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};

/// The largest document the node may send.
const MAX_DOCUMENT: usize = 4 << 20;
const READ_WAIT: Duration = Duration::from_secs(10);
/// The longest piece of Xray's output that is logged as one line. A line that is longer is cut into pieces of this size, so a process that never ends a line costs no memory.
const MAX_LINE: u64 = 512;
/// systemd hands a socket it made to the service as this descriptor.
const LISTEN_FD: i32 = 3;

/// Fails unless the path is a folder of root's that nobody else can write into.
fn sealed(path: &Path) -> anyhow::Result<()> {
	let meta = std::fs::symlink_metadata(path).map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e.kind()))?;
	anyhow::ensure!(meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0, "{} is not a folder of root's that only root can write to", path.display());
	Ok(())
}

/// The executable, opened once: not through a link, owned by root, writable by nobody else, and the pinned release. The descriptor is what is executed, so the file that was hashed is the file that runs.
fn open_pinned(addons: &Path) -> anyhow::Result<File> {
	let (folder, path) = (addons.join("xray"), super::xray::binary(addons));
	sealed(addons)?;
	sealed(&folder)?;
	let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(|e| anyhow::anyhow!("the add-on is not installed ({}): run `scripts/veilway.sh addon xray install`", e.kind()))?;
	let meta = file.metadata()?;
	anyhow::ensure!(meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0, "the xray executable is not a file of root's that only root can write to");
	let (mut hash, mut buffer) = (Context::new(&SHA256), vec![0u8; 1 << 16]);
	loop {
		let n = file.read(&mut buffer)?;
		if n == 0 {break}
		hash.update(&buffer[..n]);
	}
	let found: String = hash.finish().as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
	anyhow::ensure!(!PIN.is_empty() && found == PIN, "the xray executable is not the pinned release {RELEASE}");
	Ok(file)
}

/// Whether the document has a listener on a port below 1024, which is the one thing Xray keeps a capability for.
fn low_port(document: &str) -> bool {
	serde_json::from_str::<Value>(document).ok().and_then(|document| document["inbounds"].as_array().map(|inbounds| inbounds.iter().any(|inbound| inbound["port"].as_u64().is_none_or(|port| port < 1024)))).unwrap_or(true)
}

/// Starts Xray from the descriptor of the checked executable. Between the fork and the exec, and in the child only, it sets `no_new_privs`, asks for a kill signal when this process ends, and drops every ambient capability unless a low port needs the one to bind it, so what Xray holds is nothing (`CapEff` 0 in its `/proc/<pid>/status`).
fn spawn(file: &File, document: &str) -> std::io::Result<Child> {
	let (fd, parent, keep_bind) = (file.as_raw_fd(), std::process::id() as libc::pid_t, low_port(document));
	let mut command = Command::new(format!("/proc/self/fd/{fd}"));
	command.arg0("xray").args(["run", "-config", "stdin:"]).env_clear().current_dir("/").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
	// Safety: only async-signal-safe calls (prctl, fcntl, getppid, _exit) run between the fork and the exec, and none allocates.
	unsafe {
		command.pre_exec(move || {
			if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {return Err(std::io::Error::last_os_error())}
			if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {return Err(std::io::Error::last_os_error())}
			// The signal is only sent for a parent that dies after this call, so a parent that died before it is looked for here.
			if libc::getppid() != parent {libc::_exit(1)}
			if !keep_bind && libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 {return Err(std::io::Error::last_os_error())}
			// The descriptor is closed on exec in this process. In the child it stays open for the exec of `/proc/self/fd/N`, and Xray holds it read only.
			if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {return Err(std::io::Error::last_os_error())}
			Ok(())
		});
	}
	command.spawn()
}

/// Copies what Xray writes to this process's log, a bounded piece at a time.
async fn relay(output: impl AsyncRead + Unpin) {
	let (mut reader, mut line) = (BufReader::new(output), Vec::new());
	loop {
		line.clear();
		match (&mut reader).take(MAX_LINE).read_until(b'\n', &mut line).await {
			Ok(0) | Err(_) => return,
			Ok(_) => tracing::info!("xray: {}", String::from_utf8_lossy(&line).trim_end()),
		}
	}
}

/// One lease: the node's document in, Xray started, and Xray killed when the lease ends.
async fn lease(mut node: UnixStream, addons: PathBuf) -> anyhow::Result<()> {
	let document = tokio::time::timeout(READ_WAIT, async {
		let mut length = [0u8; 4];
		node.read_exact(&mut length).await?;
		let length = u32::from_be_bytes(length) as usize;
		anyhow::ensure!(length <= MAX_DOCUMENT, "the document is larger than {MAX_DOCUMENT} bytes");
		let mut document = vec![0u8; length];
		node.read_exact(&mut document).await?;
		Ok(String::from_utf8(document)?)
	}).await.map_err(|_| anyhow::anyhow!("no document within {}s", READ_WAIT.as_secs()))??;
	// The child is started from here and not from the blocking thread: the kill signal Xray asks for when its parent ends is tied to the thread that started it, and a blocking thread is let go when it has been idle.
	let started = match tokio::task::spawn_blocking(move || open_pinned(&addons)).await? {
		Ok(file) => spawn(&file, &document).map(|child| (child, document)).map_err(anyhow::Error::from),
		Err(e) => Err(e),
	};
	let (mut child, document) = match started {
		Ok(started) => started,
		Err(e) => {
			tracing::error!("xray: not started: {e:#}");
			node.write_all(format!("error {}\n", format!("{e:#}").replace('\n', " ")).as_bytes()).await?;
			return Ok(());
		}
	};
	let mut stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("no standard input"))?;
	stdin.write_all(document.as_bytes()).await?;
	drop(stdin);
	drop(document);
	if let Some(out) = child.stdout.take() {tokio::spawn(relay(out));}
	if let Some(out) = child.stderr.take() {tokio::spawn(relay(out));}
	let pid = child.id().unwrap_or(0);
	tracing::info!("xray {RELEASE}: started (pid {pid})");
	node.write_all(format!("ok {pid}\n").as_bytes()).await?;
	let mut sink = [0u8; 256];
	loop {
		tokio::select! {
			status = child.wait() => {
				let said = format!("ended {}\n", status.map_or_else(|e| e.kind().to_string(), |status| status.to_string()));
				tracing::warn!("xray: {}", said.trim_end());
				let _ = node.write_all(said.as_bytes()).await;
				return Ok(());
			}
			read = node.read(&mut sink) => if read.map_or(true, |n| n == 0) {
				let _ = child.kill().await;
				tracing::info!("xray: ended, the node closed the connection");
				return Ok(());
			}
		}
	}
}

/// Serves the node's socket, one lease at a time. The socket is the one systemd made and handed over when `socket` is None, which is how the unit runs it, and one made at `socket` otherwise.
pub async fn run(addons: PathBuf, socket: Option<PathBuf>) -> anyhow::Result<()> {
	anyhow::ensure!(unsafe {libc::geteuid()} != 0, "the xray host does not run as root: give it a user of its own");
	let listener = match socket {
		Some(path) => {
			let _ = std::fs::remove_file(&path);
			let listener = UnixListener::bind(&path)?;
			std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
			listener
		}
		None => {
			anyhow::ensure!(std::env::var("LISTEN_PID").ok().and_then(|pid| pid.parse::<u32>().ok()) == Some(std::process::id()) && std::env::var("LISTEN_FDS").is_ok_and(|count| count == "1"), "no socket from systemd: start this from veilway-xray.socket, or give --socket");
			// Safety: systemd says in LISTEN_FDS that descriptor 3 is the one socket it passed, and nothing else in this process owns it.
			let socket = unsafe {std::os::unix::net::UnixListener::from_raw_fd(LISTEN_FD)};
			socket.set_nonblocking(true)?;
			UnixListener::from_std(socket)?
		}
	};
	loop {
		let (node, _) = listener.accept().await?;
		if let Err(e) = lease(node, addons.clone()).await {tracing::warn!("xray host: {e:#}")}
	}
}
