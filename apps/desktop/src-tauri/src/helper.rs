//! The privileged half of the desktop client: the engine and the platform layer (`veilway-linux`, `veilway-macos` or `veilway-windows`, all `platform` here, driven exactly as `veilway connect` drives them), in a process of its own that has the rights the tunnel needs.
//!
//! **Design.** The window is an ordinary unprivileged process. The helper is this same executable started with `--helper --dir <folder>` and raised once per session, by the system's own prompt: `pkexec` on Linux, `osascript ... with administrator privileges` on macOS, `Start-Process -Verb RunAs` on Windows (`link.rs`). Everything that touches a secret or a system setting lives here: the vault (the root-only data folder of the platform layer, so the window never holds a key or a token), the routes, the kill switch and the resolver, the stored subscriptions and every fetch. The window sends ids and answers, never paths or commands, and receives plain views (`view.rs`).
//!
//! **The channel.** A loopback TCP socket on a port the helper picks, one JSON object per line (`proto.rs`). The first line has to carry the token, 32 random bytes in hex that the window wrote to its own folder (mode 600, inside the user's profile) before it started the helper; the helper reads that file without following a link, compares in constant time, drops a connection that does not say it within five seconds, and reads nothing longer than the limits. The token never goes on a command line. The port is written to `<folder>/port` with an exclusive create, so a planted link is never followed by a root process. Any process of the same user can read the token and so drive the helper; it cannot make it do more than the protocol allows (connect a held subscription, disconnect, import with the user's answers). That is the same trust as the user's own `sudo veilway connect`, and it is written down as a limit, not hidden.
//!
//! **Lifetime and the kill switch.** Closing the window or killing the app leaves the helper and a running tunnel as they are (the tray keeps the tunnel up, and a crashed window must not drop the kill switch). The helper exits on `Quit`, or when no window has been connected for two minutes and no tunnel runs. A connection that ends on its own keeps the kill switch in force exactly like the platform layer says (`Ended { kept: true }`), and only `Disconnect` (the platform's `cleanup`) lifts it. The helper adds no teardown of its own to any other path.
//!
//! **Per OS.** Linux: root through polkit; the executable and every folder above it have to be root's and closed to others in a release build, or the helper refuses (whoever could replace the file would be root). macOS: root through the administrator prompt; the program is the one in the app bundle, which a drag install leaves writable by the installing user, so a signed LaunchDaemon (`SMAppService`) that checks the signature of its client is the proper form and is open. Windows: an elevated process; `check_install_dir` of the platform layer refuses a folder others can write, and `wintun.dll` has to sit next to the executable (`tauri.windows.conf.json`). A tunnel that is up while the window is away is why Windows NCSI (lesson 3) and the name rules (lesson 6) stay the platform layer's business: nothing here changes them.
use crate::logs::{LogLayer, START};
use crate::proto::{read_line, write_line, Call, Frame, Options, Out, Source, REQUEST_MAX, TOKEN_LEN};
use crate::view::{library_view, status_view, subscription_view, tags, AppliedOut, SubscriptionOut};
use anyhow::{anyhow, bail, Context};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch, Mutex as AsyncMutex, Notify};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use veilway_engine::import::{self, Fetcher, Library, Reviewed};
use veilway_engine::{ask_text, default_roots, Agree, Settings, StartError, Status, Store};
use veilway_proto::subscription::client::{Fetching, Standing, Offer, NativeOffer, CarriedOffer};
use veilway_proto::subscription::payload::Id;
#[cfg(target_os = "linux")]
use veilway_linux as platform;
#[cfg(target_os = "macos")]
use veilway_macos as platform;
#[cfg(windows)]
use veilway_windows as platform;
use platform::state;
use platform::vault::SecretVault;
use platform::{Applied, Routes, Stop};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const IDLE_EXIT: Duration = Duration::from_secs(120);
const HELLO_WAIT: Duration = Duration::from_secs(5);
const STOP_WAIT: Duration = Duration::from_secs(30);

pub fn now() -> u64 {SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())}

/// The step an import is at. Only one import is open at a time, and nothing is kept until the second answer.
enum Pending {
	Native(NativeOffer),
	Carried(CarriedOffer),
	Fetching(Fetching),
	Reviewed(Reviewed),
}

struct Running {subscription: String, stop: Arc<Notify>, answers: mpsc::UnboundedSender<bool>, done: watch::Receiver<bool>}

pub struct Core {
	library: AsyncMutex<Library>,
	store: Arc<Store>,
	run: PathBuf,
	languages: Mutex<Vec<String>>,
	pending: AsyncMutex<Option<Pending>>,
	running: Mutex<Option<Running>>,
	push: broadcast::Sender<Out>,
	last: Mutex<Option<crate::view::StatusView>>,
	quit: Notify,
	clients: AtomicUsize,
}

#[derive(Serialize)]
struct OfferOut {kind: &'static str, host: Option<String>, fingerprint: String, pinned: bool, in_file: bool}

#[derive(Serialize)]
struct ReviewOut {fingerprint: String, replaces: bool, endpoint_changed: bool, left_out: Vec<String>, preview: SubscriptionOut}

fn to_value<T: Serialize>(value: T) -> Result<Value, String> {serde_json::to_value(value).map_err(|error| error.to_string())}

fn kept_message(failure: &platform::Failure) -> String {
	if failure.kept {format!("{failure}. The connection ended on its own, and the kill switch is still in force, so nothing leaves this device outside the tunnel. Disconnect to restore your normal connection.")} else {format!("{failure}")}
}

impl Core {
	pub fn new(library: Library, store: Arc<Store>, run: PathBuf) -> Arc<Self> {
		Arc::new(Self {library: AsyncMutex::new(library), store, run, languages: Mutex::new(Vec::new()), pending: AsyncMutex::new(None), running: Mutex::new(None), push: broadcast::channel(256).0, last: Mutex::new(None), quit: Notify::new(), clients: AtomicUsize::new(0)})
	}

	fn send(&self, out: Out) {let _ = self.push.send(out);}

	fn tags(&self) -> Vec<veilway_proto::subscription::Tag> {tags(&self.languages.lock().unwrap())}

	async fn library_value(&self) -> Result<Value, String> {to_value(library_view(&*self.library.lock().await, &self.tags(), now()))}

	/// One request. The error is the text the window shows.
	pub async fn call(self: &Arc<Self>, call: Call) -> Result<Value, String> {
		let fetcher = || Fetcher::new(default_roots(), None);
		match call {
			Call::Hello {..} => Ok(Value::Null),
			Call::Library {languages} => {
				*self.languages.lock().unwrap() = languages.into_iter().take(8).collect();
				self.library_value().await
			}
			Call::ImportOpen {source} => {
				let offer = match source {
					Source::Link {text} => import::open(&text),
					Source::File {data} => import::open_file(&base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| "The file could not be read.".to_owned())?),
				}.map_err(|error| error.text().to_owned())?;
				let (out, pending) = match offer {
					Offer::Native(offer) => (OfferOut {kind: "native", host: Some(offer.endpoint().host().to_owned()), fingerprint: offer.fingerprint().to_string(), pinned: offer.pin().is_some(), in_file: false}, Pending::Native(offer)),
					Offer::Carried(offer) => (OfferOut {kind: "carried", host: None, fingerprint: offer.fingerprint().to_string(), pinned: false, in_file: offer.in_file()}, Pending::Carried(offer)),
					Offer::Legacy(_) => return Err(import::ImportError::Legacy.text().to_owned()),
				};
				*self.pending.lock().await = Some(pending);
				to_value(out)
			}
			Call::ImportProceed => {
				let mut pending = self.pending.lock().await;
				let library = self.library.lock().await;
				let reviewed = match pending.take() {
					Some(Pending::Native(offer)) => {
						let fetching = import::proceed(offer, None).map_err(|error| error.text().to_owned())?;
						Self::fetch(&fetcher(), fetching, &library, &mut pending).await?
					}
					Some(Pending::Fetching(fetching)) => Self::fetch(&fetcher(), fetching, &library, &mut pending).await?,
					Some(Pending::Carried(offer)) => import::proceed_carried(offer, now(), &library).map_err(|error| error.text().to_owned())?,
					other => {
						*pending = other;
						return Err("There is no import waiting for a yes.".into());
					}
				};
				let subscription = reviewed.review.subscription();
				let out = ReviewOut {fingerprint: reviewed.review.fingerprint().to_string(), replaces: reviewed.review.replaces(), endpoint_changed: reviewed.review.endpoint_changed(), left_out: subscription.refused.iter().map(|refused| format!("{refused:?}")).collect(), preview: subscription_view(subscription, Standing::Current, reviewed.review.refreshes(), &self.tags())};
				*pending = Some(Pending::Reviewed(reviewed));
				to_value(out)
			}
			Call::ImportKeep {keep} => {
				let Some(Pending::Reviewed(reviewed)) = self.pending.lock().await.take() else {return Err("There is no subscription waiting to be kept.".into())};
				if keep {
					let mut library = self.library.lock().await;
					// A vault that could not be written says why: the user has to know that no safe place for the key was found.
					fetcher().accept(reviewed, None, &mut library).await.map_err(|error| match &error {import::ImportError::Store(cause) => format!("{} {cause}", error.text()), _ => error.text().to_owned()})?;
				} else {fetcher().decline(reviewed).await}
				self.library_value().await
			}
			Call::ImportCancel => {
				match self.pending.lock().await.take() {
					Some(Pending::Fetching(fetching)) => fetcher().abandon(fetching).await,
					Some(Pending::Reviewed(reviewed)) => fetcher().decline(reviewed).await,
					_ => {}
				}
				Ok(Value::Null)
			}
			Call::Refresh {subscription: id} => {
				let mut library = self.library.lock().await;
				let at = library.held().iter().position(|held| held.id().as_str() == id).ok_or("That subscription is not held.")?;
				fetcher().refresh(&mut library, at, now()).await.map_err(|error| error.text().to_owned())?;
				drop(library);
				self.library_value().await
			}
			Call::Remove {subscription: id} => {
				if self.running.lock().unwrap().as_ref().is_some_and(|running| running.subscription == id) {return Err("Disconnect before removing the subscription that is in use.".into())}
				let mut library = self.library.lock().await;
				let found: Option<Id> = library.held().iter().find(|held| held.id().as_str() == id).map(|held| held.id().clone());
				if let Some(found) = found {library.remove(&found).map_err(|error| format!("The subscription could not be removed: {error}"))?;}
				drop(library);
				self.library_value().await
			}
			Call::Connect {subscription, profile, options} => self.connect(subscription, profile, options).await,
			Call::Answer {yes} => {
				let sent = self.running.lock().unwrap().as_ref().is_some_and(|running| running.answers.send(yes).is_ok());
				if sent {Ok(Value::Null)} else {Err("There is no question waiting.".into())}
			}
			Call::Disconnect => {
				self.disconnect().await.map_err(|error| format!("{error:#}"))?;
				Ok(Value::Null)
			}
			Call::SelectExit {..} => Err("Choosing an exit is not available yet: the platform layer does not hand the running tunnel to the app.".into()),
			Call::Status => {
				let running = self.running.lock().unwrap().is_some();
				to_value(json!({"connected": running, "status": self.last.lock().unwrap().clone(), "kill_switch_kept": !running && platform::firewall::present() == Some(true)}))
			}
			Call::Quit => {
				if self.running.lock().unwrap().is_some() {let _ = self.disconnect().await;}
				self.quit.notify_one();
				Ok(Value::Null)
			}
		}
	}

	/// A failed fetch keeps the step, so that the user can try again or cancel.
	async fn fetch(fetcher: &Fetcher, fetching: Fetching, library: &Library, pending: &mut Option<Pending>) -> Result<Reviewed, String> {
		match fetcher.fetch(&fetching, library, now()).await {
			Ok(reviewed) => Ok(reviewed),
			Err(error) => {
				*pending = Some(Pending::Fetching(fetching));
				Err(error.text().to_owned())
			}
		}
	}

	async fn connect(self: &Arc<Self>, subscription: String, profile: String, options: Options) -> Result<Value, String> {
		let held = self.library.lock().await.held().iter().find(|held| held.id().as_str() == subscription).cloned().ok_or("That subscription is not held.")?;
		if !held.subscription().profiles.iter().any(|candidate| candidate.id == profile) {return Err("That connection is not in the subscription.".into())}
		let (stop, (answers, replies), (done_tx, done)) = (Arc::new(Notify::new()), mpsc::unbounded_channel(), watch::channel(false));
		let mut running = self.running.lock().unwrap();
		if running.is_some() {return Err("Already connected.".into())}
		let (core, notify) = (self.clone(), stop.clone());
		// The engine and the platform layer are driven on a runtime of their own, on a thread of their own: their futures need not be Send, and nothing the window does can block them.
		std::thread::Builder::new().name("tunnel".into()).spawn(move || {
			let ended = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
				Ok(runtime) => runtime.block_on(core.session(held, profile, options, notify, replies)),
				Err(error) => Err((error.to_string(), false)),
			};
			core.running.lock().unwrap().take();
			*core.last.lock().unwrap() = None;
			core.send(match ended {Ok(()) => Out::Ended {error: None, kept: false}, Err((error, kept)) => Out::Ended {error: Some(error), kept}});
			let _ = done_tx.send(true);
		}).map_err(|error| error.to_string())?;
		*running = Some(Running {subscription, stop, answers, done});
		Ok(Value::Null)
	}

	async fn ask(&self, text: &str, stop: &Notify, answers: &mut mpsc::UnboundedReceiver<bool>) -> bool {
		self.send(Out::Question {text: text.to_owned()});
		tokio::select! {yes = answers.recv() => yes.unwrap_or(false), () = stop.notified() => false}
	}

	/// `veilway connect` without the terminal: the same loop of running the platform layer and asking what the engine asks. Ok is a stop the user asked for or a no they gave, with everything restored; an error is a connection that ended on its own and says whether the kill switch is still in force.
	async fn session(&self, held: veilway_proto::subscription::client::Held, profile: String, options: Options, stop: Arc<Notify>, mut answers: mpsc::UnboundedReceiver<bool>) -> Result<(), (String, bool)> {
		let plain = |error: anyhow::Error| (format!("{error:#}"), false);
		if held.standing(now()) != Standing::Current {tracing::info!("the subscription is out of date and keeps working")}
		let permit = match held.connect(now()) {
			Ok(permit) => permit,
			Err(stale) => if self.ask("This subscription expired more than 30 days ago, and the addresses and keys in it may no longer belong to the provider. Connect anyway?", &stop, &mut answers).await {stale.confirmed()} else {return Ok(())},
		};
		let mut settings = Settings::new(self.store.clone(), Arc::new(now), default_roots(), String::new());
		settings.languages = self.tags();
		let platform_options = platform::Options {kill_switch: options.kill_switch, allow_lan: options.allow_lan, local_names: options.local_names, routes: if options.routes.is_empty() {Routes::Full} else {Routes::Split(options.routes.clone())}, run_dir: self.run.clone(), ..platform::Options::default()};
		// The one lock every command takes, held to the end, also while the user is asked something: nothing else changes what is in force meanwhile.
		let lock = state::lock(&self.run).await.map_err(|error| plain(error.into()))?;
		let (key, mut agree) = (veilway_engine::store::profile_key(held.id().as_str(), &profile), Agree::default());
		loop {
			let on_status = |status: &Status, applied: &Applied| {
				let view = status_view(status, Some(AppliedOut {interface: applied.interface.clone(), kill_switch: applied.kill_switch, dns: applied.dns.into(), split: applied.split.clone(), allow_lan: applied.allow_lan}));
				*self.last.lock().unwrap() = Some(view.clone());
				self.send(Out::Status(view));
			};
			#[cfg(unix)]
			let stopped = async {
				stop.notified().await;
				Stop::Asked
			};
			#[cfg(windows)]
			let stopped = async {tokio::select! {() = stop.notified() => Stop::Asked, () = lock.stop_asked() => Stop::Asked}};
			let outcome = platform::run(&platform_options, &lock, settings.clone(), &held, &profile, &permit, agree, on_status, stopped).await;
			let _ = self.store.flush();
			let Err(failure) = outcome else {return Ok(())};
			// The tunnel did not start because the user has still to say something. The kill switch is in force while the question waits. A no, or a stop, is the user's own end of it, and lifts what is in force; any other end is not.
			let yes = match failure.error.downcast_ref::<StartError>() {
				Some(StartError::Private) => {
					let yes = self.ask("This connection goes to a private address, which is not on the internet. That is normal for a server on your own network and unusual otherwise. Connect?", &stop, &mut answers).await;
					agree.private |= yes;
					yes
				}
				Some(StartError::Unsafe) => {
					let yes = self.ask("This connection does not check who it is talking to. Anyone on the network can read and change what you send. Connect anyway?", &stop, &mut answers).await;
					agree.unsafe_profile |= yes;
					yes
				}
				Some(StartError::Ask(classes)) => {
					for class in classes {
						if self.ask(ask_text(*class), &stop, &mut answers).await {self.store.agree(&key, *class)} else {self.store.decline(&key, *class)}
					}
					true
				}
				Some(_) | None => return Err((kept_message(&failure), failure.kept)),
			};
			if !yes {
				let cleaned = platform::cleanup(&platform_options, &lock);
				let _ = self.store.flush();
				cleaned.map_err(plain)?;
				return Ok(());
			}
		}
	}

	/// A running connection is asked to stop, which it does the clean way. With none running, whatever an earlier one left in force is removed.
	async fn disconnect(&self) -> anyhow::Result<()> {
		let running = self.running.lock().unwrap().as_ref().map(|running| (running.stop.clone(), running.done.clone()));
		if let Some((stop, mut done)) = running {
			stop.notify_one();
			tokio::time::timeout(STOP_WAIT, done.wait_for(|finished| *finished)).await.context("The connection did not stop in time.")??;
			return Ok(());
		}
		let options = platform::Options::default();
		let _ = state::terminate(&options.run_dir, Duration::from_secs(20)).await;
		let lock = state::lock(&options.run_dir).await?;
		platform::cleanup(&options, &lock)?;
		*self.last.lock().unwrap() = None;
		self.send(Out::Ended {error: None, kept: false});
		Ok(())
	}
}

/// The folder for the vault and the memory of the client, root's (or the administrators') and checked the way the command line client checks it.
#[cfg(target_os = "linux")]
fn data_dir() -> anyhow::Result<PathBuf> {
	if !rustix::process::geteuid().is_root() {bail!("the helper has to run as root")}
	let dir = PathBuf::from("/var/lib/veilway/client");
	state::secure_dir(&dir, 0o700).with_context(|| format!("cannot use {} for the client's files", dir.display()))?;
	Ok(dir)
}

#[cfg(target_os = "macos")]
fn data_dir() -> anyhow::Result<PathBuf> {
	if !rustix::process::geteuid().is_root() {bail!("the helper has to run as root")}
	state::secure_tree(&Path::new(state::DATA).join("client"), 0o700).context("cannot use the client's folder")
}

#[cfg(windows)]
fn data_dir() -> anyhow::Result<PathBuf> {
	let dir = state::default_data_dir();
	state::secure_dir(&dir, platform::acl::Access::Private).with_context(|| format!("cannot use {} for the client's files", dir.display()))?;
	Ok(dir)
}

/// Whoever can replace the executable is root once it runs, so a release build runs elevated only from a place that only root can write. (macOS: see the head of this file.)
fn trusted_exe() -> anyhow::Result<()> {
	#[cfg(windows)]
	state::check_install_dir()?;
	#[cfg(target_os = "linux")]
	if !cfg!(debug_assertions) {
		let exe = std::fs::canonicalize(std::env::current_exe()?)?;
		for path in exe.ancestors() {
			let meta = std::fs::symlink_metadata(path)?;
			if meta.uid() != 0 || meta.mode() & 0o022 != 0 {bail!("{} can be changed by someone other than root, so the client will not run as root from there; install the package", path.display())}
		}
	}
	Ok(())
}

fn open_token(path: &Path) -> std::io::Result<std::fs::File> {
	let mut open = std::fs::OpenOptions::new();
	open.read(true);
	#[cfg(unix)]
	open.custom_flags(libc::O_NOFOLLOW);
	open.open(path)
}

fn same(left: &str, right: &str) -> bool {left.len() == right.len() && left.bytes().zip(right.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0}

async fn client(core: Arc<Core>, stream: TcpStream, token: Arc<String>) {
	let (read, mut write) = stream.into_split();
	let mut read = BufReader::new(read);
	let hello = tokio::time::timeout(HELLO_WAIT, read_line(&mut read, 1024)).await;
	let ok = matches!(hello, Ok(Ok(Some(ref line))) if matches!(serde_json::from_str::<Frame>(line), Ok(Frame {call: Call::Hello {token: ref given}, ..}) if same(given, &token)));
	if !ok {return}
	let id = match hello {Ok(Ok(Some(line))) => serde_json::from_str::<Frame>(&line).map_or(0, |frame| frame.id), _ => 0};
	core.clients.fetch_add(1, Ordering::SeqCst);
	let (out, mut lines) = mpsc::unbounded_channel::<Out>();
	let writer = tokio::spawn(async move {
		while let Some(line) = lines.recv().await {if write_line(&mut write, &line).await.is_err() {break}}
	});
	let _ = out.send(Out::Reply {id, ok: Some(Value::Null), error: None});
	if let Some(status) = core.last.lock().unwrap().clone() {let _ = out.send(Out::Status(status));}
	let (mut pushes, forward) = (core.push.subscribe(), out.clone());
	let pusher = tokio::spawn(async move {
		loop {
			match pushes.recv().await {
				Ok(push) => if forward.send(push).is_err() {break},
				Err(broadcast::error::RecvError::Lagged(_)) => {}
				Err(broadcast::error::RecvError::Closed) => break,
			}
		}
	});
	while let Ok(Some(line)) = read_line(&mut read, REQUEST_MAX).await {
		let Ok(frame) = serde_json::from_str::<Frame>(&line) else {break};
		let (core, out) = (core.clone(), out.clone());
		tokio::spawn(async move {
			let reply = match core.call(frame.call).await {Ok(value) => Out::Reply {id: frame.id, ok: Some(value), error: None}, Err(error) => Out::Reply {id: frame.id, ok: None, error: Some(error)}};
			let _ = out.send(reply);
		});
	}
	pusher.abort();
	writer.abort();
	core.clients.fetch_sub(1, Ordering::SeqCst);
}

/// Serves until `Quit`, or until no window has been here for `IDLE_EXIT` while no tunnel runs.
pub async fn serve(core: Arc<Core>, listener: TcpListener, token: String) {
	let (token, mut idle_since, mut tick) = (Arc::new(token), Instant::now(), tokio::time::interval(Duration::from_secs(5)));
	loop {
		tokio::select! {
			accepted = listener.accept() => if let Ok((stream, _)) = accepted {tokio::spawn(client(core.clone(), stream, token.clone()));},
			() = core.quit.notified() => break,
			_ = tick.tick() => {
				if core.clients.load(Ordering::SeqCst) > 0 || core.running.lock().unwrap().is_some() {idle_since = Instant::now()} else if idle_since.elapsed() > IDLE_EXIT {break}
			}
		}
	}
}

/// The entry of `--helper --dir <folder>`: returns the process's exit code.
pub fn main(dir: &Path) -> i32 {
	let _ = START.set(Instant::now());
	match run(dir) {
		Ok(()) => 0,
		Err(error) => {
			eprintln!("{error:#}");
			2
		}
	}
}

fn run(dir: &Path) -> anyhow::Result<()> {
	trusted_exe()?;
	let meta = std::fs::symlink_metadata(dir).context("the helper's folder is missing")?;
	if !meta.is_dir() {bail!("the helper's folder is a link or not a folder")}
	let mut token = String::new();
	std::io::Read::read_to_string(&mut std::io::Read::take(open_token(&dir.join("token")).context("cannot read the token")?, TOKEN_LEN as u64 + 1), &mut token)?;
	if token.len() != TOKEN_LEN || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {bail!("the token is not what the app writes")}
	let data = data_dir()?;
	let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
	let (library, damaged) = Library::open(Box::new(SecretVault::new(data.join("vault")))).map_err(|error| anyhow!("{error}"))?;
	let core = Core::new(library, Arc::new(Store::open(data.join("client.json"))), platform::Options::default().run_dir);
	let sink = core.push.clone();
	tracing_subscriber::registry().with(LogLayer(move |line| {let _ = sink.send(Out::Log {line});})).init();
	for _ in damaged {tracing::warn!("a stored subscription does not read any more and is left out")}
	runtime.block_on(async {
		let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
		let port_file = dir.join("port");
		let _ = std::fs::remove_file(&port_file);
		// An exclusive create: a link planted at this name is an error and is never followed by a process with these rights.
		std::io::Write::write_all(&mut std::fs::OpenOptions::new().write(true).create_new(true).open(&port_file)?, listener.local_addr()?.port().to_string().as_bytes())?;
		tracing::info!("the helper is ready");
		serve(core, listener, token).await;
		let _ = std::fs::remove_file(&port_file);
		anyhow::Ok(())
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::proto::{read_line, write_line};
	use tokio::io::AsyncWriteExt;
	use veilway_engine::import::FileVault;

	async fn start(dir: &Path) -> (Arc<Core>, std::net::SocketAddr, tokio::task::JoinHandle<()>) {
		let (library, _) = Library::open(Box::new(FileVault(dir.join("vault")))).unwrap();
		let core = Core::new(library, Arc::new(Store::open(dir.join("client.json"))), dir.join("run"));
		let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
		let addr = listener.local_addr().unwrap();
		let task = tokio::spawn(serve(core.clone(), listener, "a".repeat(TOKEN_LEN)));
		(core, addr, task)
	}

	async fn connect(addr: std::net::SocketAddr, token: &str) -> Option<(BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf)> {
		let (read, mut write) = TcpStream::connect(addr).await.unwrap().into_split();
		let mut read = BufReader::new(read);
		write_line(&mut write, &Frame {id: 1, call: Call::Hello {token: token.into()}}).await.unwrap();
		match read_line(&mut read, 1 << 20).await {Ok(Some(_)) => Some((read, write)), _ => None}
	}

	async fn ask(read: &mut BufReader<tokio::net::tcp::OwnedReadHalf>, write: &mut tokio::net::tcp::OwnedWriteHalf, id: u64, call: Call) -> (Option<Value>, Option<String>) {
		write_line(write, &Frame {id, call}).await.unwrap();
		loop {
			let line = read_line(read, 1 << 24).await.unwrap().unwrap();
			if let Out::Reply {id: got, ok, error} = serde_json::from_str(&line).unwrap() {if got == id {return (ok, error)}}
		}
	}

	#[tokio::test]
	async fn only_the_token_opens_the_channel_and_requests_are_answered() {
		let dir = std::env::temp_dir().join(format!("veilway-helper-{}", now()));
		std::fs::create_dir_all(&dir).unwrap();
		let (_core, addr, _task) = start(&dir).await;
		assert!(connect(addr, &"b".repeat(TOKEN_LEN)).await.is_none());
		let (mut read, mut write) = connect(addr, &"a".repeat(TOKEN_LEN)).await.unwrap();
		let (ok, _) = ask(&mut read, &mut write, 2, Call::Library {languages: vec!["en".into()]}).await;
		assert_eq!(ok, Some(json!([])));
		let (ok, error) = ask(&mut read, &mut write, 3, Call::ImportOpen {source: Source::Link {text: "not a link".into()}}).await;
		assert!(ok.is_none() && error.is_some());
		let (_, error) = ask(&mut read, &mut write, 4, Call::ImportProceed).await;
		assert_eq!(error.as_deref(), Some("There is no import waiting for a yes."));
		let (_, error) = ask(&mut read, &mut write, 5, Call::Connect {subscription: "x".into(), profile: "y".into(), options: Options::default()}).await;
		assert_eq!(error.as_deref(), Some("That subscription is not held."));
		let (_, error) = ask(&mut read, &mut write, 6, Call::Answer {yes: true}).await;
		assert_eq!(error.as_deref(), Some("There is no question waiting."));
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn a_line_that_is_no_request_ends_the_connection_and_quit_ends_the_server() {
		let dir = std::env::temp_dir().join(format!("veilway-helper-quit-{}", now()));
		std::fs::create_dir_all(&dir).unwrap();
		let (_core, addr, task) = start(&dir).await;
		let (mut read, mut write) = connect(addr, &"a".repeat(TOKEN_LEN)).await.unwrap();
		write.write_all(b"{\"id\":2,\"call\":\"run_this\"}\n").await.unwrap();
		assert!(matches!(read_line(&mut read, 1 << 20).await, Ok(None) | Err(_)));
		let (mut read, mut write) = connect(addr, &"a".repeat(TOKEN_LEN)).await.unwrap();
		write_line(&mut write, &Frame {id: 9, call: Call::Quit}).await.unwrap();
		let _ = read_line(&mut read, 1 << 20).await;
		tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
		let _ = std::fs::remove_dir_all(&dir);
	}
}
