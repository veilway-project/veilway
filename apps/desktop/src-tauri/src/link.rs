//! The window's side of the channel to the helper (see `helper.rs` for the design): the token file, starting the helper through the system's own elevation prompt, and a client that proves the helper holds the token before it believes it, matches each answer to its ask and passes the helper's pushes on.
use crate::ipc::{self, Conn};
use crate::proto::{nonce_ok, proof, random_hex, read_line, verify, write_line, Call, Frame, Out, NONCE_LEN, REPLY_MAX, TOKEN_LEN};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{BufReader, WriteHalf};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

const CALL_WAIT: Duration = Duration::from_secs(120);
/// The time the user has to type an administrator password.
const PROMPT_WAIT: Duration = Duration::from_secs(120);

type Waiting = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct Link {writer: AsyncMutex<WriteHalf<Conn>>, waiting: Waiting, next: AtomicU64, closed: Arc<AtomicBool>}

impl Link {
	/// Proves the token both ways over `conn` (nothing secret is sent), then serves. `push` gets everything the helper says that is not an answer.
	pub async fn over(conn: Conn, token: &str, push: Arc<dyn Fn(Out) + Send + Sync>) -> std::io::Result<Arc<Self>> {
		let denied = |text: &'static str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, text);
		let (read, mut write) = tokio::io::split(conn);
		let mut read = BufReader::new(read);
		let ours = random_hex(NONCE_LEN / 2)?;
		write_line(&mut write, &Frame {id: 0, call: Call::Hello {nonce: ours.clone()}}).await?;
		let first = tokio::time::timeout(Duration::from_secs(10), read_line(&mut read, 1024)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
		let Some(Out::Challenge {nonce: theirs, proof: given}) = first.and_then(|line| serde_json::from_str::<Out>(&line).ok()) else {return Err(denied("the listener is not the helper"))};
		if !nonce_ok(&theirs) || !verify(token, "server", &ours, &theirs, &given) {return Err(denied("the listener does not hold the token, so it is not the helper"))}
		write_line(&mut write, &Frame {id: 0, call: Call::Auth {proof: proof(token, "client", &theirs, &ours)}}).await?;
		let second = tokio::time::timeout(Duration::from_secs(10), read_line(&mut read, REPLY_MAX)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
		if !matches!(second.and_then(|line| serde_json::from_str::<Out>(&line).ok()), Some(Out::Reply {id: 0, error: None, ..})) {return Err(denied("the helper did not accept the proof"))}
		let (waiting, closed): (Waiting, _) = (Arc::default(), Arc::new(AtomicBool::new(false)));
		let (reader_waiting, reader_closed) = (waiting.clone(), closed.clone());
		tokio::spawn(async move {
			while let Ok(Some(line)) = read_line(&mut read, REPLY_MAX).await {
				match serde_json::from_str::<Out>(&line) {
					Ok(Out::Reply {id, ok, error}) => if let Some(sender) = reader_waiting.lock().unwrap().remove(&id) {let _ = sender.send(match error {Some(error) => Err(error), None => Ok(ok.unwrap_or(Value::Null))});},
					Ok(other) => push(other),
					Err(_) => break,
				}
			}
			reader_closed.store(true, Ordering::SeqCst);
			for (_, sender) in reader_waiting.lock().unwrap().drain() {let _ = sender.send(Err("The helper stopped.".into()));}
		});
		Ok(Arc::new(Self {writer: AsyncMutex::new(write), waiting, next: AtomicU64::new(1), closed}))
	}

	pub fn closed(&self) -> bool {self.closed.load(Ordering::SeqCst)}

	pub async fn call(&self, call: Call) -> Result<Value, String> {
		let id = self.next.fetch_add(1, Ordering::SeqCst);
		let (sender, receiver) = oneshot::channel();
		self.waiting.lock().unwrap().insert(id, sender);
		if let Err(error) = write_line(&mut *self.writer.lock().await, &Frame {id, call}).await {
			self.waiting.lock().unwrap().remove(&id);
			return Err(format!("The helper could not be reached: {error}"));
		}
		match tokio::time::timeout(CALL_WAIT, receiver).await {
			Ok(Ok(result)) => result,
			Ok(Err(_)) => Err("The helper stopped.".into()),
			Err(_) => {
				self.waiting.lock().unwrap().remove(&id);
				Err("The helper did not answer in time.".into())
			}
		}
	}
}

fn valid(token: &str) -> bool {token.len() == TOKEN_LEN && token.bytes().all(|byte| byte.is_ascii_hexdigit())}

/// The token of the helper that may still be running, if the file holds one.
pub fn read_token(dir: &Path) -> Option<String> {std::fs::read_to_string(dir.join("token")).ok().filter(|text| valid(text))}

/// A new token for a new helper, in the app's own folder, readable by the user only. Never reused for a helper that is started again.
pub fn fresh_token(dir: &Path) -> std::io::Result<String> {
	let token = random_hex(TOKEN_LEN / 2)?;
	let path = dir.join("token");
	let _ = std::fs::remove_file(&path);
	let mut open = std::fs::OpenOptions::new();
	open.write(true).create_new(true);
	#[cfg(unix)]
	open.mode(0o600);
	std::io::Write::write_all(&mut open.open(&path)?, token.as_bytes())?;
	Ok(token)
}

pub fn private_dir(dir: &Path) -> std::io::Result<()> {
	let mut builder = std::fs::DirBuilder::new();
	builder.recursive(true);
	#[cfg(unix)]
	builder.mode(0o700);
	builder.create(dir)
}

/// The path goes into a command for the system's prompt, so nothing the shells or the script treat as syntax is allowed in it.
fn plain_path(path: &Path) -> std::io::Result<&str> {
	path.to_str().filter(|text| !text.chars().any(|c| c.is_control() || "'\"`$;&|<>%".contains(c) || (!cfg!(windows) && c == '\\'))).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "the path of the app has a character the administrator prompt cannot carry"))
}

/// The SID of the user the app runs as, for the pipe's access list, from the system's own `whoami`.
#[cfg(windows)]
fn user_sid() -> std::io::Result<String> {
	let root = std::env::var_os("SystemRoot").ok_or(std::io::ErrorKind::NotFound)?;
	let output = Command::new(Path::new(&root).join("System32").join("whoami.exe")).args(["/user", "/fo", "csv", "/nh"]).stdin(Stdio::null()).stderr(Stdio::null()).output()?;
	let text = String::from_utf8_lossy(&output.stdout);
	let sid = text.trim().rsplit(',').next().map(|field| field.trim().trim_matches('"').to_owned()).unwrap_or_default();
	if ipc::sid_ok(&sid) {Ok(sid)} else {Err(std::io::Error::other("the user's SID could not be read"))}
}

/// `ShellExecuteExW` with the verb `runas`, which is the system's elevation prompt, with no shell and no script in between.
#[cfg(windows)]
fn run_as(exe: &str, arguments: &str) -> std::io::Result<()> {
	use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
	let wide = |text: &str| text.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
	let (verb, file, parameters) = (wide("runas"), wide(exe), wide(arguments));
	let mut info: SHELLEXECUTEINFOW = unsafe {std::mem::zeroed()};
	info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
	info.lpVerb = verb.as_ptr();
	info.lpFile = file.as_ptr();
	info.lpParameters = parameters.as_ptr();
	// SW_HIDE
	info.nShow = 0;
	if unsafe {ShellExecuteExW(&mut info)} == 0 {return Err(std::io::Error::last_os_error())}
	Ok(())
}

/// Asks the system for administrator rights once and starts `exe --helper --dir <dir>` with them. The child, when there is one, is the prompt (macOS) or the parent of the helper (Linux); on Windows the prompt returns at once.
pub fn elevate(exe: &Path, dir: &Path) -> std::io::Result<Option<Child>> {
	let (exe, dir) = (plain_path(exe)?, plain_path(dir)?);
	#[cfg(target_os = "linux")]
	return Command::new("pkexec").args([exe, "--helper", "--dir", dir]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(Some);
	#[cfg(target_os = "macos")]
	return Command::new("osascript").args(["-e", &format!("do shell script \"'{exe}' --helper --dir '{dir}' --uid {} >/dev/null 2>&1 &\" with administrator privileges", unsafe {libc::getuid()})]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(Some);
	#[cfg(windows)]
	{
		run_as(exe, &format!("--helper --dir \"{dir}\" --sid {}", user_sid()?))?;
		Ok(None)
	}
}

pub struct Backend {
	dir: PathBuf,
	link: AsyncMutex<Option<Arc<Link>>>,
	push: Arc<dyn Fn(Out) + Send + Sync>,
}

impl Backend {
	pub fn new(dir: PathBuf, push: Arc<dyn Fn(Out) + Send + Sync>) -> Self {Self {dir, link: AsyncMutex::new(None), push}}

	async fn attach(&self, token: &str) -> std::io::Result<Arc<Link>> {Link::over(ipc::connect().await?, token, self.push.clone()).await}

	/// The open channel, or a new one: a helper that still runs (one the token file still belongs to) is joined, and otherwise a new token is made and the user is asked for administrator rights once.
	async fn link(&self) -> Result<Arc<Link>, String> {
		let mut guard = self.link.lock().await;
		if let Some(link) = guard.as_ref().filter(|link| !link.closed()) {return Ok(link.clone())}
		*guard = None;
		let text = |error: std::io::Error| format!("The helper could not be started: {error}");
		private_dir(&self.dir).map_err(text)?;
		if let Some(token) = read_token(&self.dir) {
			if let Ok(link) = self.attach(&token).await {
				*guard = Some(link.clone());
				return Ok(link);
			}
		}
		let token = fresh_token(&self.dir).map_err(text)?;
		let mut child = elevate(&std::env::current_exe().map_err(text)?, &self.dir).map_err(text)?;
		let started = Instant::now();
		while started.elapsed() < PROMPT_WAIT {
			tokio::time::sleep(Duration::from_millis(300)).await;
			if let Ok(link) = self.attach(&token).await {
				*guard = Some(link.clone());
				if let Some(mut child) = child {std::thread::spawn(move || {let _ = child.wait();});}
				return Ok(link);
			}
			// pkexec stays the parent of the helper, the other two prompts end once the helper runs: only a failure, or any end of pkexec, means the helper is not coming.
			if let Some(Ok(Some(status))) = child.as_mut().map(Child::try_wait) {
				if !status.success() || cfg!(target_os = "linux") {return Err("Administrator permission was not given, so the tunnel cannot be set up.".into())}
				child = None;
			}
		}
		Err("The helper did not start in time.".into())
	}

	pub async fn call(&self, call: Call) -> Result<Value, String> {
		let link = self.link().await?;
		link.call(call).await
	}

	/// For the tray's Quit and an update: stops a helper that is there, the one this window has open or one a token file still belongs to, and never raises the prompt. Without one there is nothing to stop.
	pub async fn quit(&self) {
		let mut guard = self.link.lock().await;
		let open = guard.as_ref().filter(|link| !link.closed()).cloned();
		let link = match open {
			Some(link) => Some(link),
			None => match read_token(&self.dir) {
				Some(token) => self.attach(&token).await.ok(),
				None => None,
			},
		};
		*guard = None;
		if let Some(link) = link {let _ = link.call(Call::Quit).await;}
	}
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;

	#[test]
	fn a_token_is_made_fresh_each_time_as_hex_and_kept_private() {
		let dir = std::env::temp_dir().join(format!("veilway-token-{}", std::process::id()));
		private_dir(&dir).unwrap();
		assert!(read_token(&dir).is_none());
		let first = fresh_token(&dir).unwrap();
		assert!(valid(&first));
		assert_eq!(read_token(&dir).as_deref(), Some(first.as_str()));
		assert_eq!(std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(dir.join("token")).unwrap()) & 0o777, 0o600);
		assert_ne!(fresh_token(&dir).unwrap(), first);
		std::fs::write(dir.join("token"), "short").unwrap();
		assert!(read_token(&dir).is_none());
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn paths_with_shell_syntax_are_refused_before_a_prompt_is_raised() {
		assert!(plain_path(Path::new("/opt/veilway/app")).is_ok());
		for bad in ["/tmp/a'b", "/tmp/a\"b", "/tmp/a$b", "/tmp/a`b", "/tmp/a;b", "/tmp/a\nb"] {assert!(plain_path(Path::new(bad)).is_err(), "{bad}")}
	}
}
