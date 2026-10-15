//! The window's side of the channel to the helper (see `helper.rs` for the design): the token file, starting the helper through the system's own elevation prompt, and a client that matches each answer to its ask and passes the helper's pushes on.
use crate::proto::{read_line, write_line, Call, Frame, Out, REPLY_MAX, TOKEN_LEN};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::BufReader;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::process::CommandExt;

const CALL_WAIT: Duration = Duration::from_secs(120);
/// The time the user has to type an administrator password.
const PROMPT_WAIT: Duration = Duration::from_secs(120);

type Waiting = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct Link {writer: AsyncMutex<OwnedWriteHalf>, waiting: Waiting, next: AtomicU64, closed: Arc<AtomicBool>}

impl Link {
	/// Connects and proves the token. `push` gets everything the helper says that is not an answer.
	pub async fn open(port: u16, token: &str, push: Arc<dyn Fn(Out) + Send + Sync>) -> std::io::Result<Arc<Self>> {
		let (read, mut write) = TcpStream::connect(("127.0.0.1", port)).await?.into_split();
		let mut read = BufReader::new(read);
		write_line(&mut write, &Frame {id: 0, call: Call::Hello {token: token.into()}}).await?;
		let first = tokio::time::timeout(Duration::from_secs(10), read_line(&mut read, REPLY_MAX)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
		match first.and_then(|line| serde_json::from_str::<Out>(&line).ok()) {
			Some(Out::Reply {id: 0, error: None, ..}) => {}
			_ => return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "the helper did not accept the token")),
		}
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

/// The token, made once and kept in the app's own folder (readable by the user only), so that a window opened later finds a helper that still runs.
pub fn ensure_token(dir: &Path) -> std::io::Result<String> {
	let path = dir.join("token");
	if let Ok(text) = std::fs::read_to_string(&path) {
		if text.len() == TOKEN_LEN && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {return Ok(text)}
	}
	let mut bytes = [0u8; TOKEN_LEN / 2];
	ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| std::io::Error::other("no random source"))?;
	let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
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
	path.to_str().filter(|text| !text.chars().any(|c| c.is_control() || "'\"`$\\;&|<>%".contains(c) && !(cfg!(windows) && c == '\\'))).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "the path of the app has a character the administrator prompt cannot carry"))
}

/// Asks the system for administrator rights once and starts `exe --helper --dir <dir>` with them.
pub fn elevate(exe: &Path, dir: &Path) -> std::io::Result<Child> {
	let (exe, dir) = (plain_path(exe)?, plain_path(dir)?);
	#[cfg(target_os = "linux")]
	return Command::new("pkexec").args([exe, "--helper", "--dir", dir]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
	#[cfg(target_os = "macos")]
	return Command::new("osascript").args(["-e", &format!("do shell script \"'{exe}' --helper --dir '{dir}' >/dev/null 2>&1 &\" with administrator privileges")]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
	#[cfg(windows)]
	return Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &format!("Start-Process -FilePath '{exe}' -ArgumentList '--helper','--dir','\"{dir}\"' -Verb RunAs -WindowStyle Hidden")]).creation_flags(0x0800_0000).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
}

pub struct Backend {
	dir: PathBuf,
	link: AsyncMutex<Option<Arc<Link>>>,
	push: Arc<dyn Fn(Out) + Send + Sync>,
}

impl Backend {
	pub fn new(dir: PathBuf, push: Arc<dyn Fn(Out) + Send + Sync>) -> Self {Self {dir, link: AsyncMutex::new(None), push}}

	async fn attach(&self, token: &str) -> std::io::Result<Arc<Link>> {
		let port: u16 = std::fs::read_to_string(self.dir.join("port"))?.trim().parse().map_err(|_| std::io::ErrorKind::InvalidData)?;
		Link::open(port, token, self.push.clone()).await
	}

	/// The open channel, or a new one: a helper that still runs is joined, and otherwise the user is asked for administrator rights once.
	async fn link(&self) -> Result<Arc<Link>, String> {
		let mut guard = self.link.lock().await;
		if let Some(link) = guard.as_ref().filter(|link| !link.closed()) {return Ok(link.clone())}
		*guard = None;
		let text = |error: std::io::Error| format!("The helper could not be started: {error}");
		private_dir(&self.dir).map_err(text)?;
		let token = ensure_token(&self.dir).map_err(text)?;
		if let Ok(link) = self.attach(&token).await {
			*guard = Some(link.clone());
			return Ok(link);
		}
		let _ = std::fs::remove_file(self.dir.join("port"));
		let mut child = elevate(&std::env::current_exe().map_err(text)?, &self.dir).map_err(text)?;
		let started = Instant::now();
		while started.elapsed() < PROMPT_WAIT {
			tokio::time::sleep(Duration::from_millis(300)).await;
			if let Ok(link) = self.attach(&token).await {
				*guard = Some(link.clone());
				std::thread::spawn(move || {let _ = child.wait();});
				return Ok(link);
			}
			// pkexec stays the parent of the helper, the other two prompts end once the helper runs: only a failure, or any end of pkexec, means the helper is not coming.
			if let Ok(Some(status)) = child.try_wait() {
				if !status.success() || cfg!(target_os = "linux") {return Err("Administrator permission was not given, so the tunnel cannot be set up.".into())}
			}
		}
		Err("The helper did not start in time.".into())
	}

	pub async fn call(&self, call: Call) -> Result<Value, String> {
		let link = self.link().await?;
		link.call(call).await
	}

	/// For the tray's Quit: only talks to a helper that is already there, and never raises the prompt.
	pub async fn quit(&self) {
		let Some(link) = self.link.lock().await.clone().filter(|link| !link.closed()) else {return};
		let _ = link.call(Call::Quit).await;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::helper::{serve, Core};
	use tokio::net::TcpListener;
	use veilway_engine::import::{FileVault, Library};
	use veilway_engine::Store;

	#[test]
	fn the_token_is_made_once_as_hex_and_kept_private() {
		let dir = std::env::temp_dir().join(format!("veilway-token-{}", std::process::id()));
		private_dir(&dir).unwrap();
		let first = ensure_token(&dir).unwrap();
		assert_eq!(first.len(), TOKEN_LEN);
		assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
		assert_eq!(ensure_token(&dir).unwrap(), first);
		#[cfg(unix)]
		assert_eq!(std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(dir.join("token")).unwrap()) & 0o777, 0o600);
		std::fs::write(dir.join("token"), "short").unwrap();
		assert_ne!(ensure_token(&dir).unwrap(), "short");
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn paths_with_shell_syntax_are_refused_before_a_prompt_is_raised() {
		assert!(plain_path(Path::new("/opt/veilway/app")).is_ok());
		for bad in ["/tmp/a'b", "/tmp/a\"b", "/tmp/a$b", "/tmp/a`b", "/tmp/a;b", "/tmp/a\nb"] {assert!(plain_path(Path::new(bad)).is_err(), "{bad}")}
	}

	#[tokio::test]
	async fn a_window_talks_to_a_helper_over_the_channel_and_a_wrong_token_is_refused() {
		let dir = std::env::temp_dir().join(format!("veilway-link-{}", std::process::id()));
		private_dir(&dir).unwrap();
		let (library, _) = Library::open(Box::new(FileVault(dir.join("vault")))).unwrap();
		let core = Core::new(library, Arc::new(Store::open(dir.join("client.json"))), dir.join("run"));
		let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
		let port = listener.local_addr().unwrap().port();
		let token = "c".repeat(TOKEN_LEN);
		tokio::spawn(serve(core, listener, token.clone()));
		let pushed: Arc<Mutex<Vec<Out>>> = Arc::default();
		let sink = pushed.clone();
		assert!(Link::open(port, &"d".repeat(TOKEN_LEN), Arc::new(|_| {})).await.is_err());
		let link = Link::open(port, &token, Arc::new(move |out| sink.lock().unwrap().push(out))).await.unwrap();
		assert_eq!(link.call(Call::Library {languages: vec![]}).await.unwrap(), serde_json::json!([]));
		let error = link.call(Call::Refresh {subscription: "none".into()}).await.unwrap_err();
		assert!(error.contains("not held"), "{error}");
		link.call(Call::Quit).await.unwrap();
		let _ = std::fs::remove_dir_all(&dir);
	}
}
