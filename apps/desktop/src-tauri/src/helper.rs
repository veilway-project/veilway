//! The privileged half of the desktop client: the engine and the platform layer (`veilway-linux`, `veilway-macos` or `veilway-windows`, all `platform` here, driven exactly as `veilway connect` drives them), in a process of its own that has the rights the tunnel needs.
//!
//! **Design.** The window is an ordinary unprivileged process. The helper is this same executable started with `--helper --dir <folder>` and raised once per session, by the system's own prompt: `pkexec` on Linux, `osascript ... with administrator privileges` on macOS, `Start-Process -Verb RunAs` on Windows (`link.rs`). Everything that touches a secret or a system setting lives here: the vault (the root-only data folder of the platform layer, so the window never holds a key or a token), the routes, the kill switch and the resolver, the stored subscriptions and every fetch. The window sends ids and answers, never paths or commands, and receives plain views (`view.rs`).
//!
//! **The channel.** A unix socket in a folder only root can write (`/run/veilway-desktop`, `/var/run/veilway-desktop` on macOS), or a named pipe with an access list for the user's SID on Windows (`ipc.rs`); one JSON object per line (`proto.rs`). The socket belongs to the user who raised the helper (polkit's `PKEXEC_UID`, the uid the window names on macOS), is mode 600, and every peer is checked for that uid. Behind that, a mutual proof: the window writes a fresh token (32 random bytes in hex) to its own folder before each helper start, and the two sides prove they hold it with HMAC-SHA256 over each other's nonces, so the token is never sent and a process that only listens where the helper should learns nothing and is not believed. The one thing root reads from the user's side is that token file, through `openat` from a folder opened once with `O_DIRECTORY|O_NOFOLLOW` and owned by that user, as a regular file of theirs; the helper writes nothing there. Requests are read one at a time per connection, longer than the limits is an error, and a window that stops reading (256 lines queued) is dropped. Any process of the same user can still read the token and so drive the helper; it cannot make it do more than the protocol allows (connect a held subscription, disconnect, import with the user's answers). That is the same trust as the user's own `sudo veilway connect`, and it is written down as a limit, not hidden. What the helper logs to the window is only what the veilway crates log at INFO and above, without path, file, key or secret fields. The helper never decodes a picture: a logo goes to the window as raw bytes within a size cap, and the window checks it.
//!
//! **Lifetime and the kill switch.** Closing the window or killing the app leaves the helper and a running tunnel as they are (the tray keeps the tunnel up, and a crashed window must not drop the kill switch). The helper exits on `Quit`, or when no window has been connected for two minutes and no tunnel runs. A connection that ends on its own keeps the kill switch in force exactly like the platform layer says (`Ended { kept: true }`), and only `Disconnect` (the platform's `cleanup`) lifts it. The helper adds no teardown of its own to any other path.
//!
//! **Per OS.** Linux: root through polkit; the executable and every folder above it have to be root's and closed to others in a release build, or the helper refuses (whoever could replace the file would be root). macOS: root through the administrator prompt; the program is the one in the app bundle, which a drag install leaves writable by the installing user, so a signed LaunchDaemon (`SMAppService`) that checks the signature of its client is the proper form and is open. Windows: an elevated process; `check_install_dir` of the platform layer refuses a folder others can write, and `wintun.dll` has to sit next to the executable (`tauri.windows.conf.json`). A tunnel that is up while the window is away is why Windows NCSI (lesson 3) and the name rules (lesson 6) stay the platform layer's business: nothing here changes them.
use crate::bundle;
use crate::legacy;
use crate::logs::{LogLayer, START};
use crate::ipc::{self, Conn, Server};
use crate::proto::{nonce_ok, proof, random_hex, read_line, verify, write_line, Call, Frame, Options, Out, Phase, Source, NONCE_LEN, REQUEST_MAX, TOKEN_LEN};
use crate::view::{library_view, move_view, status_view, subscription_view, tags, AppliedOut, MoveOut, SubscriptionOut};
use anyhow::{anyhow, bail, Context};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::BufReader;
use tokio::sync::{broadcast, mpsc, watch, Mutex as AsyncMutex, Notify};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use veilway_engine::import::{self, Fetcher, Library, Reviewed};
use veilway_engine::{ask_text, default_roots, Agree, Handle, Settings, StartError, Status, Store};
use veilway_proto::subscription::client::{Fetching, Standing, Offer, NativeOffer, CarriedOffer};
use veilway_proto::subscription::Kind;
use veilway_proto::subscription::payload::{private, Id};
use veilway_proto::xray::{self, profile::Profile, Pin};
#[cfg(target_os = "linux")]
use veilway_linux as platform;
#[cfg(target_os = "macos")]
use veilway_macos as platform;
#[cfg(windows)]
use veilway_windows as platform;
use platform::state;
use platform::vault::SecretVault;
use platform::{Applied, Routes, Stop};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

const IDLE_EXIT: Duration = Duration::from_secs(120);
const HELLO_WAIT: Duration = Duration::from_secs(5);
/// What a window may have waiting to be written before it is dropped as one that does not read.
const CLIENT_QUEUE: usize = 256;
const STOP_WAIT: Duration = Duration::from_secs(30);
const PRIVATE: &str = "This connection goes to a private address, which is not on the internet. That is normal for a server on your own network and unusual otherwise. Connect?";

pub fn now() -> u64 {SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())}

/// The step an import is at. Only one import is open at a time, and nothing is kept until the second answer.
enum Pending {
	Native(NativeOffer),
	Carried(CarriedOffer),
	Fetching(Fetching),
	Reviewed(Reviewed),
	/// Pasted links of another app, read and checked. Nothing is fetched for them; `ImportKeep` keeps what passed.
	Legacy(legacy::Read),
}

/// What a connect runs: a profile of a signed subscription, or one of pasted links through the Xray add-on at `binary`.
enum Job {
	Native {held: veilway_proto::subscription::client::Held, profile: String},
	Xray {profile: Profile, name: String, binary: PathBuf, pin: &'static Pin, allow_lan: bool},
}

struct Running {subscription: String, stop: Arc<Notify>, answers: mpsc::UnboundedSender<bool>, done: watch::Receiver<bool>}

pub struct Core {
	pub(crate) library: AsyncMutex<Library>,
	/// The pasted links of other apps, in a vault of their own.
	legacy: AsyncMutex<legacy::Store>,
	/// Held while the add-on is installed or removed, and while a connection of pasted links is set up, so that no two of them overlap.
	installing: Arc<AsyncMutex<()>>,
	/// Whether a connect has answered with the offer to install the add-on and nothing has installed it since. Only then is `XrayInstall` taken.
	offered: AtomicBool,
	store: Arc<Store>,
	run: PathBuf,
	/// The window's folder, where a bundle is staged for review and an app part is handed back.
	pub(crate) dir: PathBuf,
	/// The helper's own folder: the copy of the reviewed bundle and the notice marks.
	pub(crate) data: PathBuf,
	/// The uid that owns the window's folder, which the helper checks before it opens anything there.
	pub(crate) owner: u32,
	pub(crate) bundle: AsyncMutex<Option<veilway_engine::bundle::Review>>,
	pub(crate) languages: Mutex<Vec<String>>,
	pending: AsyncMutex<Option<Pending>>,
	running: Mutex<Option<Running>>,
	push: broadcast::Sender<Out>,
	last: Mutex<Option<crate::view::StatusView>>,
	quit: Notify,
	clients: AtomicUsize,
	handle: Mutex<Option<Handle>>,
}

#[derive(Serialize)]
struct OfferOut {kind: &'static str, host: Option<String>, fingerprint: String, pinned: bool, plain: bool, in_file: bool}

#[derive(Serialize)]
struct ReviewOut {fingerprint: String, replaces: bool, endpoint_changed: bool, moving: Option<MoveOut>, left_out: Vec<String>, preview: SubscriptionOut}

fn to_value<T: Serialize>(value: T) -> Result<Value, String> {serde_json::to_value(value).map_err(|error| error.to_string())}

fn kept_message(failure: &platform::Failure) -> String {
	if failure.kept {format!("{failure}. The connection ended on its own, and the kill switch is still in force, so nothing leaves this device outside the tunnel. Disconnect to restore your normal connection.")} else {format!("{failure}")}
}

impl Core {
	pub fn new(library: Library, pasted: legacy::Store, store: Arc<Store>, run: PathBuf, dir: PathBuf, data: PathBuf, owner: u32) -> Arc<Self> {
		Arc::new(Self {library: AsyncMutex::new(library), legacy: AsyncMutex::new(pasted), installing: Arc::new(AsyncMutex::new(())), offered: AtomicBool::new(false), store, run, dir, data, owner, bundle: AsyncMutex::new(None), languages: Mutex::new(Vec::new()), pending: AsyncMutex::new(None), running: Mutex::new(None), push: broadcast::channel(256).0, last: Mutex::new(None), quit: Notify::new(), clients: AtomicUsize::new(0), handle: Mutex::new(None)})
	}

	fn send(&self, out: Out) {let _ = self.push.send(out);}

	fn tags(&self) -> Vec<veilway_proto::subscription::Tag> {tags(&self.languages.lock().unwrap())}

	pub(crate) async fn library_value(&self) -> Result<Value, String> {
		let mut views = library_view(&*self.library.lock().await, &self.store, &self.tags(), now());
		views.extend(self.legacy.lock().await.held().iter().map(|pasted| legacy::view(pasted, self.store.lan_local(&pasted.id))));
		let mut value = to_value(views)?;
		self.add_notices(&mut value)?;
		Ok(value)
	}

	/// One request. The error is the text the window shows.
	pub async fn call(self: &Arc<Self>, call: Call) -> Result<Value, String> {
		let fetcher = || Fetcher::new(default_roots(), None);
		match call {
			Call::Hello {..} | Call::Auth {..} => Ok(Value::Null),
			Call::Library {languages} => {
				*self.languages.lock().unwrap() = languages.into_iter().take(8).collect();
				self.library_value().await
			}
			Call::ImportOpen {source} => {
				// Only one import is open at a time: whatever was open ends here, also when this one is refused, so that links read earlier do not stay in memory.
				self.drop_import().await;
				if let Some(lines) = match &source {Source::Link {text} => legacy::lines(text), _ => None} {
					let read = legacy::read(&lines).map_err(str::to_owned)?;
					let out = json!({"kind": "legacy", "connections": read.items.iter().enumerate().filter(|(_, item)| item.checked.is_ok()).map(|(at, item)| json!({"name": item.name(at), "protocol": item.protocol(), "unsafe_cap": item.unsafe_cap()})).collect::<Vec<_>>(), "refused": read.items.iter().enumerate().filter_map(|(at, item)| item.checked.as_ref().err().map(|code| json!({"name": item.name(at), "code": code}))).collect::<Vec<_>>(), "skipped": read.skipped, "cut": read.cut});
					*self.pending.lock().await = Some(Pending::Legacy(read));
					return Ok(out);
				}
				let offer = match source {
					Source::Link {text} => import::open(&text),
					Source::File {data} => import::open_file(&base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| import::Code::FileUnreadable.as_str().to_owned())?),
					Source::Sealed {data, password} => {
						let bytes = base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| import::Code::FileUnreadable.as_str().to_owned())?;
						tokio::task::spawn_blocking(move || import::open_sealed(&bytes, &password)).await.map_err(|error| error.to_string())?
					}
				}.map_err(|error| error.code().as_str().to_owned())?;
				let (out, pending) = match offer {
					Offer::Native(offer) => (OfferOut {kind: "native", host: Some(offer.endpoint().host().to_owned()), fingerprint: offer.fingerprint().to_string(), pinned: offer.pin().is_some(), plain: offer.kind() == Kind::Plain, in_file: false}, Pending::Native(offer)),
					Offer::Carried(offer) => (OfferOut {kind: "carried", host: None, fingerprint: offer.fingerprint().to_string(), pinned: false, plain: false, in_file: offer.in_file()}, Pending::Carried(offer)),
					Offer::Legacy(_) => return Err(import::ImportError::Legacy.code().as_str().to_owned()),
				};
				*self.pending.lock().await = Some(pending);
				to_value(out)
			}
			Call::ImportProceed {private} => {
				let allowed: Vec<IpAddr> = private.iter().filter_map(|address| address.parse().ok()).collect();
				let mut pending = self.pending.lock().await;
				if matches!(pending.as_ref(), Some(Pending::Native(_) | Pending::Fetching(_))) {self.fetch_gate()?}
				let library = self.library.lock().await;
				let reviewed = match pending.take() {
					Some(Pending::Native(offer)) => {
						let fetching = import::proceed(offer, None).map_err(|error| error.code().as_str().to_owned())?;
						Self::fetch(&fetcher(), fetching, &library, &mut pending, &allowed).await?
					}
					Some(Pending::Fetching(fetching)) => Self::fetch(&fetcher(), fetching, &library, &mut pending, &allowed).await?,
					Some(Pending::Carried(offer)) => Ok(import::proceed_carried(offer, now(), &library).map_err(|error| error.code().as_str().to_owned())?),
					other => {
						*pending = other;
						return Err(import::Code::NoImport.as_str().into());
					}
				};
				// A private address the user has not said yes to: the step stays where it was and the window asks.
				let reviewed = match reviewed {
					Ok(reviewed) => reviewed,
					Err(question) => return Ok(question),
				};
				let subscription = reviewed.review.subscription();
				let out = ReviewOut {fingerprint: reviewed.review.fingerprint().to_string(), replaces: reviewed.review.replaces(), endpoint_changed: reviewed.review.endpoint_changed(), moving: reviewed.review.moving().map(|main| move_view(main, reviewed.review.endpoint())), left_out: subscription.refused.iter().map(|refused| format!("{refused:?}")).collect(), preview: subscription_view(subscription, Standing::Current, reviewed.review.refreshes(), false, &self.tags())};
				*pending = Some(Pending::Reviewed(reviewed));
				to_value(out)
			}
			Call::ImportKeep {keep} => {
				let mut pending = self.pending.lock().await;
				if matches!(pending.as_ref(), Some(Pending::Legacy(_))) {
					if let (true, Some(Pending::Legacy(read))) = (keep, pending.take()) {self.legacy.lock().await.add(read, format!("{}{}", legacy::PREFIX, random_hex(16).map_err(|_| import::Code::Random.as_str().to_owned())?), now()).map_err(|error| if error.kind() == std::io::ErrorKind::StorageFull {import::Code::Full.as_str().to_owned()} else {import::Code::Store.as_str().to_owned()})?;}
					*pending = None;
					drop(pending);
					return self.library_value().await;
				}
				if keep && matches!(pending.as_ref(), Some(Pending::Reviewed(reviewed)) if reviewed.endpoint.is_some()) {self.fetch_gate()?}
				let Some(Pending::Reviewed(reviewed)) = pending.take() else {return Err("There is no subscription waiting to be kept.".into())};
				drop(pending);
				if keep {
					let mut library = self.library.lock().await;
					// A vault that could not be written says why: the user has to know that no safe place for the key was found.
					fetcher().accept(reviewed, None, &mut library).await.map_err(|error| error.code().as_str().to_owned())?;
				} else {fetcher().decline(reviewed).await}
				self.library_value().await
			}
			Call::ShareLink {subscription: id} => {
				let library = self.library.lock().await;
				let held = library.held().iter().find(|held| held.id().as_str() == id).ok_or("That subscription is not held.")?;
				Ok(json!({"link": import::share_link(held).map_err(|error| error.code().as_str().to_owned())?}))
			}
			Call::ShareFile {subscription: id, password} => {
				let link = import::share_link(self.library.lock().await.held().iter().find(|held| held.id().as_str() == id).ok_or("That subscription is not held.")?).map_err(|error| error.code().as_str().to_owned())?;
				let file = tokio::task::spawn_blocking(move || import::seal_link(&link, &password)).await.map_err(|error| error.to_string())?.map_err(|error| error.code().as_str().to_owned())?;
				Ok(json!({"data": base64::engine::general_purpose::STANDARD.encode(file)}))
			}
			Call::ImportCancel => {
				self.drop_import().await;
				Ok(Value::Null)
			}
			Call::Refresh {subscription: id, private} => {
				self.fetch_gate()?;
				let mut library = self.library.lock().await;
				let at = library.held().iter().position(|held| held.id().as_str() == id).ok_or("That subscription is not held.")?;
				let allowed: Vec<IpAddr> = private.iter().filter_map(|address| address.parse().ok()).collect();
				if !allowed.is_empty() {library.allow_private(at, &allowed).map_err(|error| format!("The choice could not be saved: {error}"))?}
				match fetcher().refresh(&mut library, at, now()).await {
					Err(import::ImportError::PrivateEndpoint {host, addresses}) => return Ok(json!({"ask_private": {"host": host, "addresses": addresses}})),
					other => other.map_err(|error| error.wire())?,
				};
				drop(library);
				self.library_value().await
			}
			Call::Remove {subscription: id} => {
				if self.running.lock().unwrap().as_ref().is_some_and(|running| running.subscription == id) {return Err("Disconnect before removing the subscription that is in use.".into())}
				if id.starts_with(legacy::PREFIX) {self.legacy.lock().await.remove(&id).map_err(|error| format!("The subscription could not be removed: {error}"))?;}
				let mut library = self.library.lock().await;
				let found: Option<Id> = library.held().iter().find(|held| held.id().as_str() == id).map(|held| held.id().clone());
				if let Some(found) = found {fetcher().leave(&mut library, &found).await.map_err(|error| format!("The subscription could not be removed: {error}"))?;}
				drop(library);
				self.store.set_lan_local(&id, false);
				let _ = self.store.flush();
				self.library_value().await
			}
			Call::AnswerHosts {subscription: id, allow, decline} => {
				let mut library = self.library.lock().await;
				let at = library.held().iter().position(|held| held.id().as_str() == id).ok_or("That subscription is not held.")?;
				let (allow, decline): (Vec<&str>, Vec<&str>) = (allow.iter().take(16).map(String::as_str).collect(), decline.iter().take(16).map(String::as_str).collect());
				// The endpoint of a move is answered apart from the hosts: its yes puts it first in the next refresh, and a no keeps the main endpoint.
				let moving = library.held()[at].moving().map(|moving| moving.key());
				for (yes, answered) in [(true, &allow), (false, &decline)] {
					if let Some(key) = moving.as_deref().filter(|key| answered.contains(key)) {library.answer_move(at, key, yes).map_err(|error| format!("The choice could not be saved: {error}"))?}
				}
				library.answer_hosts(at, &allow, &decline).map_err(|error| format!("The choice could not be saved: {error}"))?;
				drop(library);
				self.library_value().await
			}
			Call::SetLan {subscription: id, on} => {
				if !self.library.lock().await.held().iter().any(|held| held.id().as_str() == id) && !self.legacy.lock().await.held().iter().any(|pasted| pasted.id == id) {return Err("That subscription is not held.".into())}
				self.store.set_lan_local(&id, on);
				self.store.flush().map_err(|error| format!("The choice could not be saved: {error}"))?;
				self.library_value().await
			}
			Call::Alpha => Ok(json!({"alpha": self.store.alpha_transports()})),
			Call::SetAlpha {on} => {
				self.store.set_alpha_transports(on);
				self.store.flush().map_err(|error| format!("The choice could not be saved: {error}"))?;
				Ok(json!({"alpha": on}))
			}
			Call::Connect {subscription, profile, options} => self.connect(subscription, profile, options).await,
			Call::Xray => Ok(self.xray_state()),
			Call::XrayInstall => {
				self.fetch_gate()?;
				if !self.offered.load(Ordering::SeqCst) {return Err("xray_no_offer".into())}
				let installing = self.installing.clone().try_lock_owned().map_err(|_| "xray_installing")?;
				let pin = veilway_xray::target().and_then(xray::pin).ok_or("xray_unsupported")?;
				// The lock `veilway connect` holds for its whole run: with it held by anyone, a connection of the command line or of this helper may be running the add-on that would be replaced.
				let lock = state::lock(&self.run).await.map_err(|error| {
					tracing::warn!("xray: the add-on was not installed, the connection lock is held: {error}");
					"xray_busy"
				})?;
				let core = self.clone();
				// The install runs in a task of its own, and the window is told how it goes by pushes, so that this window's Disconnect and Answer are not held up for the five minutes it can take.
				tokio::spawn(async move {
					let addons = veilway_xray::addons_dir(&core.data);
					let (progress, mirrors) = (AtomicU64::new(0), if cfg!(debug_assertions) {veilway_xray::mirrors_from_env()} else {Vec::new()});
					let outcome = if veilway_xray::installed(&addons) {Ok(())} else {
						let install = veilway_xray::fetch_install(&addons, pin.target, pin, &mirrors, &progress);
						tokio::pin!(install);
						let mut tick = tokio::time::interval(Duration::from_millis(500));
						loop {
							tokio::select! {
								outcome = &mut install => break outcome,
								_ = tick.tick() => core.send(Out::XrayInstall {phase: Phase::Downloading, downloaded: progress.load(Ordering::Relaxed), state: None, error: None}),
							}
						}
					};
					// Released before the window is told, since it connects as soon as it hears.
					drop((lock, installing));
					let downloaded = progress.load(Ordering::Relaxed);
					core.send(match outcome {
						Ok(()) => {
							tracing::info!("xray: the add-on {} is installed", xray::RELEASE);
							core.offered.store(false, Ordering::SeqCst);
							Out::XrayInstall {phase: Phase::Done, downloaded, state: Some(core.xray_state()), error: None}
						}
						Err((step, error)) => {
							tracing::warn!("xray: the add-on was not installed: {error:#}");
							Out::XrayInstall {phase: Phase::Failed, downloaded, state: None, error: Some(step.code().to_owned())}
						}
					});
				});
				Ok(Value::Null)
			}
			Call::XrayRemove => {
				// First, before anything is stopped: an install or a connection being set up decides whether this goes on at all.
				let _installing = self.installing.try_lock().map_err(|_| "xray_installing")?;
				let uses = self.running.lock().unwrap().as_ref().is_some_and(|running| running.subscription.starts_with(legacy::PREFIX));
				if uses {self.disconnect().await.map_err(|error| format!("{error:#}"))?}
				let _lock = state::lock(&self.run).await.map_err(|error| {
					tracing::warn!("xray: the add-on was not removed, the connection lock is held: {error}");
					"xray_busy"
				})?;
				veilway_xray::remove(&veilway_xray::addons_dir(&self.data)).map_err(|error| {
					tracing::warn!("xray: the add-on was not removed: {error:#}");
					"xray_remove_failed".to_owned()
				})?;
				tracing::info!("xray: the add-on is removed");
				Ok(self.xray_state())
			}
			Call::Answer {yes} => {
				let sent = self.running.lock().unwrap().as_ref().is_some_and(|running| running.answers.send(yes).is_ok());
				if sent {Ok(Value::Null)} else {Err("There is no question waiting.".into())}
			}
			Call::Disconnect => {
				self.disconnect().await.map_err(|error| format!("{error:#}"))?;
				Ok(Value::Null)
			}
			Call::SelectExit {tag} => {
				let sent = self.handle.lock().unwrap().as_ref().is_some_and(|handle| handle.select_exit(tag));
				if sent {Ok(Value::Null)} else {Err("There is no running tunnel to change the exit of.".into())}
			}
			Call::BundleReview => self.bundle_review().await,
			Call::BundleDocument {subscription} => self.bundle_document(&subscription).await,
			Call::BundleApp => self.bundle_app().await,
			Call::BundleChunk {offset, len} => self.bundle_chunk(offset, len).await,
			Call::BundleNotices => self.bundle_notices().await,
			Call::BundleClose => self.bundle_close().await,
			Call::Status => {
				let running = self.running.lock().unwrap().is_some();
				to_value(json!({"connected": running, "status": self.last.lock().unwrap().clone(), "kill_switch_kept": !running && platform::firewall::present() == Some(true)}))
			}
			Call::Quit => {
				// A kill switch left by a connection that ended on its own is lifted too: quitting the app is the user saying they are done.
				if self.running.lock().unwrap().is_some() || platform::firewall::present() == Some(true) {let _ = self.disconnect().await;}
				self.quit.notify_one();
				Ok(Value::Null)
			}
		}
	}

	/// Fetches go out as the system's own traffic, so while a tunnel runs they go through it. With none running and the kill switch left in force by an earlier connection they could only fail, or be the very leak the switch is there to stop, so they are refused with what to do.
	fn fetch_gate(&self) -> Result<(), String> {
		if self.running.lock().unwrap().is_none() && platform::firewall::present() == Some(true) {return Err(import::Code::KillSwitch.as_str().into())}
		Ok(())
	}

	/// A failed fetch keeps the step, so that the user can try again or cancel.
	/// An endpoint on a private address that the user has not said yes to is not a failure: the answer is the question for the window, `{"ask_private": {"host", "addresses"}}`, and the step stays.
	async fn fetch(fetcher: &Fetcher, fetching: Fetching, library: &Library, pending: &mut Option<Pending>, allowed: &[IpAddr]) -> Result<Result<Reviewed, Value>, String> {
		match fetcher.fetch(&fetching, library, now(), allowed).await {
			Ok(reviewed) => Ok(Ok(reviewed)),
			Err(error) => {
				*pending = Some(Pending::Fetching(fetching));
				match error {
					import::ImportError::PrivateEndpoint {host, addresses} => Ok(Err(json!({"ask_private": {"host": host, "addresses": addresses}}))),
					error => Err(error.wire()),
				}
			}
		}
	}

	/// Ends the import that is open, whatever step it is at: a fetch is abandoned, a review is declined, and pasted links that were read are dropped with their credentials.
	async fn drop_import(&self) {
		match self.pending.lock().await.take() {
			Some(Pending::Fetching(fetching)) => Fetcher::new(default_roots(), None).abandon(fetching, &[]).await,
			Some(Pending::Reviewed(reviewed)) => Fetcher::new(default_roots(), None).decline(reviewed).await,
			_ => {}
		}
	}

	/// What the window is told about the add-on, also as the offer: whether this system has one, whether this app's release is installed, the release and the most its download can be, and whether an install is running.
	fn xray_state(&self) -> Value {json!({"supported": veilway_xray::target().and_then(xray::pin).is_some(), "installed": veilway_xray::installed(&veilway_xray::addons_dir(&self.data)), "release": xray::RELEASE, "size": veilway_xray::ARCHIVE_MAX, "installing": self.installing.try_lock().is_err()})}

	/// A profile of pasted links that the table refuses does not start, and without the add-on of this app's release the answer is the offer, before anything is changed.
	async fn connect(self: &Arc<Self>, subscription: String, profile: String, options: Options) -> Result<Value, String> {
		// Held to the end of this call, which is after the connection is registered as running: a removal that comes later sees it, and one that is under way refuses this.
		let pasted = subscription.starts_with(legacy::PREFIX);
		let mut installing = if pasted {Some(self.installing.try_lock().map_err(|_| "xray_installing")?)} else {None};
		let job = if pasted {
			let (checked, name) = self.legacy.lock().await.find(&subscription, &profile).map(|(item, name)| (item.checked.clone(), name)).ok_or("That connection is not in the subscription.")?;
			let profile = checked.map_err(str::to_owned)?;
			if self.running.lock().unwrap().is_some() {return Err("Already connected.".into())}
			let pin = veilway_xray::target().and_then(xray::pin).ok_or("xray_unsupported")?;
			let addons = veilway_xray::addons_dir(&self.data);
			if !veilway_xray::installed(&addons) {
				installing.take();
				self.offered.store(true, Ordering::SeqCst);
				return Ok(json!({"xray_offer": self.xray_state()}));
			}
			Job::Xray {profile, name, binary: veilway_xray::executable(&addons), pin, allow_lan: self.store.lan_local(&subscription)}
		} else {
			let held = self.library.lock().await.held().iter().find(|held| held.id().as_str() == subscription).cloned().ok_or("That subscription is not held.")?;
			if !held.subscription().profiles.iter().any(|candidate| candidate.id == profile) {return Err("That connection is not in the subscription.".into())}
			Job::Native {held, profile}
		};
		let (stop, (answers, replies), (done_tx, done)) = (Arc::new(Notify::new()), mpsc::unbounded_channel(), watch::channel(false));
		let mut running = self.running.lock().unwrap();
		if running.is_some() {return Err("Already connected.".into())}
		let (core, notify) = (self.clone(), stop.clone());
		// The engine and the platform layer are driven on a runtime of their own, on a thread of their own: their futures need not be Send, and nothing the window does can block them.
		std::thread::Builder::new().name("tunnel".into()).spawn(move || {
			let ended = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
				Ok(runtime) => match job {
					Job::Native {held, profile} => runtime.block_on(core.session(held, profile, options, notify, replies)),
					Job::Xray {profile, name, binary, pin, allow_lan} => runtime.block_on(core.session_xray(profile, name, binary, pin, allow_lan, options, notify, replies)),
				},
				Err(error) => Err((error.to_string(), false)),
			};
			core.running.lock().unwrap().take();
			*core.handle.lock().unwrap() = None;
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
		*self.handle.lock().unwrap() = Some(settings.handle.clone());
		let platform_options = platform::Options {kill_switch: options.kill_switch, allow_lan: self.store.lan_local(held.id().as_str()), local_names: options.local_names && self.store.lan_local(held.id().as_str()), routes: if options.routes.is_empty() {Routes::Full} else {Routes::Split(options.routes.clone())}, run_dir: self.run.clone(), ..platform::Options::default()};
		// The one lock every command takes, held to the end, also while the user is asked something: nothing else changes what is in force meanwhile.
		let lock = state::lock(&self.run).await.map_err(|error| plain(error.into()))?;
		let (key, mut agree) = (veilway_engine::store::profile_key(held.id().as_str(), &profile), Agree::default());
		loop {
			let on_status = |status: &Status, applied: &Applied| self.shown(status, applied);
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
					let yes = self.ask(PRIVATE, &stop, &mut answers).await;
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
				Some(StartError::Alpha) => {
					let cleaned = platform::cleanup(&platform_options, &lock);
					let _ = self.store.flush();
					cleaned.map_err(plain)?;
					return Err(("alpha_off".into(), false));
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

	/// What the platform layer reports goes to every window, and is kept for the next one that comes.
	fn shown(&self, status: &Status, applied: &Applied) {
		let view = status_view(status, Some(AppliedOut {interface: applied.interface.clone(), kill_switch: applied.kill_switch, dns: applied.dns.into(), split: applied.split.clone(), allow_lan: applied.allow_lan}));
		*self.last.lock().unwrap() = Some(view.clone());
		self.send(Out::Status(view));
	}

	/// `veilway connect` with pasted links, without the terminal: the add-on is held to its pin and the server is looked up before anything is in force, a private address is asked about, and `veilway_xray::run` does the rest under the one lock. Ok and an error mean what they mean for `session`.
	#[allow(clippy::too_many_arguments)]
	async fn session_xray(&self, profile: Profile, name: String, binary: PathBuf, pin: &'static Pin, allow_lan: bool, options: Options, stop: Arc<Notify>, mut answers: mpsc::UnboundedReceiver<bool>) -> Result<(), (String, bool)> {
		let plain = |error: anyhow::Error| (format!("{error:#}"), false);
		let lock = state::lock(&self.run).await.map_err(|error| plain(error.into()))?;
		veilway_xray::check_addon(&binary, pin).map_err(plain)?;
		let server = veilway_xray::server(&profile).await.map_err(plain)?;
		if private(server) && !self.ask(PRIVATE, &stop, &mut answers).await {return Ok(())}
		let platform_options = platform::Options {kill_switch: options.kill_switch, allow_lan, local_names: options.local_names && allow_lan, routes: if options.routes.is_empty() {Routes::Full} else {Routes::Split(options.routes.clone())}, run_dir: self.run.clone(), ..platform::Options::default()};
		#[cfg(unix)]
		let stopped = async {
			stop.notified().await;
			Stop::Asked
		};
		#[cfg(windows)]
		let stopped = async {tokio::select! {() = stop.notified() => Stop::Asked, () = lock.stop_asked() => Stop::Asked}};
		veilway_xray::run(&platform_options, &lock, profile, server, name, binary, pin, |status: &Status, applied: &Applied| self.shown(status, applied), stopped).await.map_err(|failure| (kept_message(&failure), failure.kept))
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

/// Whoever can replace the executable is root once it runs, so a release build runs elevated only from a place that only root can write. (macOS: see the head of this file.) That is also why there is no AppImage: it runs from wherever the user keeps it, so the Linux bundles are deb and rpm only.
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

/// The user who raised the helper: polkit says so on Linux; on macOS the window names its own uid, and the folder it names has to be that user's (`read_user_file`).
#[cfg(unix)]
fn elevating_uid(given: Option<&str>) -> anyhow::Result<u32> {
	#[cfg(target_os = "linux")]
	let named = {
		let _ = given;
		["PKEXEC_UID", "SUDO_UID"].iter().find_map(|name| std::env::var(name).ok())
	};
	#[cfg(target_os = "macos")]
	let named = given.map(str::to_owned).or_else(|| std::env::var("SUDO_UID").ok());
	let uid: u32 = named.and_then(|text| text.parse().ok()).ok_or_else(|| anyhow!("the helper does not know which user raised it"))?;
	if uid == 0 {bail!("the app has to run as your own user, not as root")}
	Ok(uid)
}

/// The mutual proof of the token (see `proto.rs`), within five seconds per step. The token never crosses; the id is the one the window used.
async fn handshake(read: &mut BufReader<tokio::io::ReadHalf<Conn>>, write: &mut tokio::io::WriteHalf<Conn>, token: &str) -> Option<u64> {
	let first = tokio::time::timeout(HELLO_WAIT, read_line(read, 1024)).await.ok()?.ok()??;
	let Frame {call: Call::Hello {nonce: theirs}, ..} = serde_json::from_str(&first).ok()? else {return None};
	if !nonce_ok(&theirs) {return None}
	let ours = random_hex(NONCE_LEN / 2).ok()?;
	write_line(write, &Out::Challenge {proof: proof(token, "server", &theirs, &ours), nonce: ours.clone()}).await.ok()?;
	let second = tokio::time::timeout(HELLO_WAIT, read_line(read, 1024)).await.ok()?.ok()??;
	let Frame {id, call: Call::Auth {proof: given}} = serde_json::from_str(&second).ok()? else {return None};
	verify(token, "client", &ours, &theirs, &given).then_some(id)
}

async fn client(core: Arc<Core>, conn: Conn, token: Arc<String>) {
	let (read, mut write) = tokio::io::split(conn);
	let mut read = BufReader::new(read);
	let Some(id) = handshake(&mut read, &mut write, &token).await else {return};
	core.clients.fetch_add(1, Ordering::SeqCst);
	// Bounded: a window that stops reading is dropped and does not make the helper hold what it was told.
	let (out, mut lines) = mpsc::channel::<Out>(CLIENT_QUEUE);
	let kick = Arc::new(Notify::new());
	let writer = tokio::spawn(async move {
		while let Some(line) = lines.recv().await {if write_line(&mut write, &line).await.is_err() {break}}
	});
	let _ = out.try_send(Out::Reply {id, ok: Some(Value::Null), error: None});
	if let Some(status) = core.last.lock().unwrap().clone() {let _ = out.try_send(Out::Status(status));}
	let (mut pushes, forward, full) = (core.push.subscribe(), out.clone(), kick.clone());
	let pusher = tokio::spawn(async move {
		loop {
			match pushes.recv().await {
				Ok(push) => if forward.try_send(push).is_err() {
					full.notify_one();
					break;
				},
				Err(broadcast::error::RecvError::Lagged(_)) => {}
				Err(broadcast::error::RecvError::Closed) => break,
			}
		}
	});
	// One request at a time per connection: the next line is not read before the answer to this one is queued.
	loop {
		let line = tokio::select! {line = read_line(&mut read, REQUEST_MAX) => line, () = kick.notified() => break};
		let Ok(Some(line)) = line else {break};
		let Ok(frame) = serde_json::from_str::<Frame>(&line) else {break};
		let reply = match core.call(frame.call).await {Ok(value) => Out::Reply {id: frame.id, ok: Some(value), error: None}, Err(error) => Out::Reply {id: frame.id, ok: None, error: Some(error)}};
		if out.try_send(reply).is_err() {break}
	}
	pusher.abort();
	drop(out);
	// What is queued is still written, so that the answer to a Quit reaches the window.
	let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
	core.clients.fetch_sub(1, Ordering::SeqCst);
}

/// Serves until `Quit`, or until no window has been here for `IDLE_EXIT` while no tunnel runs.
pub async fn serve(core: Arc<Core>, mut server: Server, token: String) {
	let (token, mut idle_since, mut tick) = (Arc::new(token), Instant::now(), tokio::time::interval(Duration::from_secs(5)));
	loop {
		tokio::select! {
			accepted = server.accept() => match accepted {
				Ok(conn) => {tokio::spawn(client(core.clone(), conn, token.clone()));}
				Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
			},
			() = core.quit.notified() => break,
			_ = tick.tick() => {
				if core.clients.load(Ordering::SeqCst) > 0 || core.running.lock().unwrap().is_some() {idle_since = Instant::now()} else if idle_since.elapsed() > IDLE_EXIT {break}
			}
		}
	}
}

/// The entry of `--helper --dir <folder> [--uid <n> | --sid <sid>]`: returns the process's exit code. `owner` is the user's uid on macOS and the user's SID on Windows.
pub fn main(dir: &Path, owner: Option<&str>) -> i32 {
	let _ = START.set(Instant::now());
	match run(dir, owner) {
		Ok(()) => 0,
		Err(error) => {
			eprintln!("{error:#}");
			2
		}
	}
}

fn run(dir: &Path, owner: Option<&str>) -> anyhow::Result<()> {
	trusted_exe()?;
	#[cfg(unix)]
	let uid = elevating_uid(owner)?;
	#[cfg(unix)]
	let text = ipc::read_user_file(dir, "token", uid, TOKEN_LEN + 1).context("cannot read the token")?;
	#[cfg(windows)]
	let text = ipc::read_user_file(dir, "token", 0, TOKEN_LEN + 1).context("cannot read the token")?;
	if text.len() != TOKEN_LEN || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {bail!("the token is not what the app writes")}
	let data = data_dir()?;
	#[cfg(unix)]
	let account = uid;
	#[cfg(windows)]
	let account = 0;
	bundle::wipe(dir, &data, account);
	let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
	let (library, damaged) = Library::open(Box::new(SecretVault::new(data.join("vault")))).map_err(|error| anyhow!("{error}"))?;
	let (pasted, dropped, unopened) = legacy::Store::open(Box::new(SecretVault::new(data.join("legacy-vault"))));
	let core = Core::new(library, pasted, Arc::new(Store::open(data.join("client.json"))), platform::Options::default().run_dir, dir.to_path_buf(), data.clone(), account);
	let sink = core.push.clone();
	tracing_subscriber::registry().with(LogLayer {sink: move |line| {let _ = sink.send(Out::Log {line});}, helper: true}).init();
	for _ in damaged {tracing::warn!("a stored subscription does not read any more and is left out")}
	if dropped > 0 {tracing::warn!("{dropped} stored pastes of links do not read any more and are left out")}
	if let Some(error) = unopened {tracing::warn!("the pasted links cannot be read, and none is written over them: {error}")}
	runtime.block_on(async {
		#[cfg(unix)]
		let server = {
			ipc::ensure_run_dir()?;
			Server::bind(&ipc::socket_path(), uid)?
		};
		#[cfg(windows)]
		let server = Server::bind(owner.ok_or_else(|| anyhow!("the helper does not know which user raised it"))?)?;
		tracing::info!("the helper is ready");
		serve(core, server, text).await;
		#[cfg(unix)]
		let _ = std::fs::remove_file(ipc::socket_path());
		anyhow::Ok(())
	})
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;
	use crate::link::Link;
	use std::os::unix::fs::DirBuilderExt;
	use tokio::io::AsyncWriteExt;
	use veilway_engine::import::FileVault;

	fn token() -> String {"a".repeat(TOKEN_LEN)}

	fn euid() -> u32 {unsafe {libc::geteuid()}}

	async fn start(name: &str, uid: u32) -> Option<(Arc<Core>, PathBuf, tokio::task::JoinHandle<()>)> {
		let dir = std::env::temp_dir().join(format!("veilway-helper-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
		let (library, _) = Library::open(Box::new(FileVault(dir.join("vault")))).unwrap();
		let (pasted, _, _) = legacy::Store::open(Box::new(FileVault(dir.join("legacy-vault"))));
		let core = Core::new(library, pasted, Arc::new(Store::open(dir.join("client.json"))), dir.join("run"), dir.join("window"), dir.join("data"), 0);
		let socket = dir.join("helper.sock");
		let server = Server::bind(&socket, uid).ok()?;
		let task = tokio::spawn(serve(core.clone(), server, token()));
		Some((core, socket, task))
	}

	async fn link(socket: &Path, token: &str) -> std::io::Result<Arc<Link>> {Link::over(ipc::connect_to(socket).await?, token, Arc::new(|_| {})).await}

	#[tokio::test]
	async fn only_the_token_opens_the_channel_and_requests_are_answered() {
		let (_core, socket, _task) = start("auth", euid()).await.unwrap();
		assert!(link(&socket, &"b".repeat(TOKEN_LEN)).await.is_err());
		let link = link(&socket, &token()).await.unwrap();
		assert_eq!(link.call(Call::Library {languages: vec!["en".into()]}).await.unwrap(), json!([]));
		assert!(link.call(Call::ImportOpen {source: Source::Link {text: "not a link".into()}}).await.is_err());
		assert_eq!(link.call(Call::ImportProceed {private: Vec::new()}).await.unwrap_err(), "no_import");
		assert_eq!(link.call(Call::Connect {subscription: "x".into(), profile: "y".into(), options: Options::default()}).await.unwrap_err(), "That subscription is not held.");
		assert_eq!(link.call(Call::Answer {yes: true}).await.unwrap_err(), "There is no question waiting.");
		assert_eq!(link.call(Call::SelectExit {tag: None}).await.unwrap_err(), "There is no running tunnel to change the exit of.");
	}

	const GOOD: &str = "vless://5f2c8e1a-0b3d-4c6e-9a7f-1d2e3f4a5b6c@203.0.113.5:443?security=tls&sni=edge.example&type=ws&path=%2Fws#Edge";

	#[tokio::test]
	async fn a_pasted_link_the_table_refuses_gives_its_code_and_nothing_is_kept() {
		let (core, socket, _task) = start("refused", euid()).await.unwrap();
		let link = link(&socket, &token()).await.unwrap();
		let refused = "vless://5f2c8e1a-0b3d-4c6e-9a7f-1d2e3f4a5b6c@203.0.113.5:443?security=tls&type=kcp#Kcp";
		assert_eq!(link.call(Call::ImportOpen {source: Source::Link {text: refused.into()}}).await.unwrap_err(), "profile_refused.stream");
		assert_eq!(link.call(Call::ImportOpen {source: Source::Link {text: "trojan://secret@203.0.113.5:443?allowInsecure=1".into()}}).await.unwrap_err(), "profile_refused.certificate");
		assert_eq!(link.call(Call::ImportKeep {keep: true}).await.unwrap_err(), "There is no subscription waiting to be kept.");
		assert_eq!(link.call(Call::Library {languages: vec!["en".into()]}).await.unwrap(), json!([]));
		assert!(socket.parent().unwrap().join("legacy-vault").metadata().is_err(), "nothing was written");
		assert!(core.pending.lock().await.is_none());
	}

	#[tokio::test]
	async fn a_refused_paste_ends_the_import_that_was_open_and_the_links_read_before_are_not_kept_by_a_later_yes() {
		let (core, socket, _task) = start("ends", euid()).await.unwrap();
		let link = link(&socket, &token()).await.unwrap();
		link.call(Call::ImportOpen {source: Source::Link {text: GOOD.into()}}).await.unwrap();
		assert!(matches!(core.pending.lock().await.as_ref(), Some(Pending::Legacy(read)) if read.items.len() == 1));
		let refused = "vless://5f2c8e1a-0b3d-4c6e-9a7f-1d2e3f4a5b6c@203.0.113.5:443?security=tls&type=kcp#Kcp";
		assert_eq!(link.call(Call::ImportOpen {source: Source::Link {text: refused.into()}}).await.unwrap_err(), "profile_refused.stream");
		assert!(core.pending.lock().await.is_none(), "the links read before do not stay in memory");
		assert_eq!(link.call(Call::ImportKeep {keep: true}).await.unwrap_err(), "There is no subscription waiting to be kept.");
		assert!(socket.parent().unwrap().join("legacy-vault").metadata().is_err(), "nothing was written");
		link.call(Call::ImportOpen {source: Source::Link {text: GOOD.into()}}).await.unwrap();
		assert!(link.call(Call::ImportOpen {source: Source::Link {text: "not a link".into()}}).await.is_err());
		assert!(core.pending.lock().await.is_none(), "a paste that is no link ends it too");
		link.call(Call::ImportOpen {source: Source::Link {text: GOOD.into()}}).await.unwrap();
		link.call(Call::ImportCancel).await.unwrap();
		assert!(core.pending.lock().await.is_none());
	}

	#[tokio::test]
	async fn a_pasted_list_is_kept_in_its_vault_with_what_passed_and_shown_as_unsigned() {
		let (_core, socket, _task) = start("kept", euid()).await.unwrap();
		let link = link(&socket, &token()).await.unwrap();
		let text = format!("{GOOD}\nss://bm9uZTpwYXNz@203.0.113.6:8388#Weak\nnot a link\n");
		let offer = link.call(Call::ImportOpen {source: Source::Link {text}}).await.unwrap();
		assert_eq!((offer["kind"].as_str(), offer["connections"][0]["name"].as_str(), offer["connections"][0]["protocol"].as_str(), offer["skipped"].as_u64()), (Some("legacy"), Some("Edge"), Some("vless"), Some(1)));
		assert_eq!((offer["connections"].as_array().unwrap().len(), offer["refused"][0]["name"].as_str(), offer["refused"][0]["code"].as_str()), (1, Some("Weak"), Some("profile_refused.cipher")));
		let library = link.call(Call::ImportKeep {keep: true}).await.unwrap();
		let pasted = &library[0];
		assert!(pasted["legacy"] == true && pasted["id"].as_str().unwrap().starts_with(legacy::PREFIX) && pasted["can_refresh"] == false);
		let profiles = pasted["profiles"].as_array().unwrap();
		assert_eq!((profiles.len(), profiles[0]["legacy"]["protocol"].as_str(), profiles[0]["legacy"]["refused"].clone()), (2, Some("vless"), Value::Null));
		assert_eq!((profiles[1]["id"].as_str(), profiles[1]["name"].as_str(), profiles[1]["legacy"]["protocol"].as_str(), profiles[1]["legacy"]["refused"].as_str()), (Some("2"), Some("Weak"), Some("shadowsocks"), Some("profile_refused.cipher")));
		let vault = std::fs::read_to_string(socket.parent().unwrap().join("legacy-vault")).unwrap();
		assert!(vault.contains("edge.example") && vault.contains("8388") && !vault.contains("not a link"), "both links are kept, and the line that is no link is not");
		let id = pasted["id"].as_str().unwrap().to_owned();
		assert_eq!(link.call(Call::Connect {subscription: id.clone(), profile: "2".into(), options: Options::default()}).await.unwrap_err(), "profile_refused.cipher", "a refused link never connects, with the add-on or without it");
		assert_eq!(link.call(Call::Remove {subscription: id}).await.unwrap(), json!([]));
	}

	#[tokio::test]
	async fn connecting_pasted_links_without_the_add_on_gives_the_offer_and_starts_nothing() {
		let (core, socket, _task) = start("offer", euid()).await.unwrap();
		let link = link(&socket, &token()).await.unwrap();
		link.call(Call::ImportOpen {source: Source::Link {text: GOOD.into()}}).await.unwrap();
		let id = link.call(Call::ImportKeep {keep: true}).await.unwrap()[0]["id"].as_str().unwrap().to_owned();
		let state = link.call(Call::Xray).await.unwrap();
		assert_eq!((state["installed"].as_bool(), state["release"].as_str()), (Some(false), Some(xray::RELEASE)));
		let answer = link.call(Call::Connect {subscription: id.clone(), profile: "1".into(), options: Options::default()}).await.unwrap();
		if veilway_xray::target().is_none() {return}
		assert!(core.offered.load(Ordering::SeqCst));
		let offer = &answer["xray_offer"];
		assert_eq!((offer["installed"].as_bool(), offer["release"].as_str(), offer["size"].as_u64()), (Some(false), Some(xray::RELEASE), Some(veilway_xray::ARCHIVE_MAX)));
		assert!(core.running.lock().unwrap().is_none(), "nothing was started");
		assert_eq!(link.call(Call::Connect {subscription: id, profile: "2".into(), options: Options::default()}).await.unwrap_err(), "That connection is not in the subscription.");
	}

	#[tokio::test]
	async fn the_add_on_is_not_installed_without_an_offer_or_changed_while_the_lock_of_a_connection_is_held() {
		if veilway_xray::target().and_then(xray::pin).is_none() {return}
		let (core, socket, _task) = start("lock", euid()).await.unwrap();
		let link = link(&socket, &token()).await.unwrap();
		assert_eq!(link.call(Call::XrayInstall).await.unwrap_err(), "xray_no_offer");
		core.offered.store(true, Ordering::SeqCst);
		let held = state::lock(&core.run).await.unwrap();
		assert_eq!(link.call(Call::XrayInstall).await.unwrap_err(), "xray_busy");
		assert_eq!(link.call(Call::XrayRemove).await.unwrap_err(), "xray_busy");
		assert_eq!(link.call(Call::Xray).await.unwrap()["installing"], false, "a refused install leaves nothing running");
		drop(held);
	}

	#[tokio::test]
	async fn a_removal_takes_the_install_before_it_stops_anything_and_a_connect_of_pasted_links_waits_for_neither() {
		let (core, socket, _task) = start("order", euid()).await.unwrap();
		let link = link(&socket, &token()).await.unwrap();
		link.call(Call::ImportOpen {source: Source::Link {text: GOOD.into()}}).await.unwrap();
		let id = link.call(Call::ImportKeep {keep: true}).await.unwrap()[0]["id"].as_str().unwrap().to_owned();
		let installing = core.installing.clone().try_lock_owned().unwrap();
		assert_eq!(link.call(Call::Xray).await.unwrap()["installing"], true);
		assert_eq!(link.call(Call::Connect {subscription: id.clone(), profile: "1".into(), options: Options::default()}).await.unwrap_err(), "xray_installing");
		let stop = Arc::new(Notify::new());
		*core.running.lock().unwrap() = Some(Running {subscription: id, stop: stop.clone(), answers: mpsc::unbounded_channel().0, done: watch::channel(false).1});
		assert_eq!(link.call(Call::XrayRemove).await.unwrap_err(), "xray_installing");
		assert!(tokio::time::timeout(Duration::from_millis(100), stop.notified()).await.is_err(), "the connection that uses the add-on was not told to stop");
		assert!(core.running.lock().unwrap().is_some());
		drop(installing);
	}

	#[tokio::test]
	async fn a_user_other_than_the_one_who_raised_the_helper_is_not_let_in() {
		// Needs the right to give the socket away; without it there is nothing to show.
		let Some((_core, socket, _task)) = start("peer", euid() + 1).await else {return};
		assert!(link(&socket, &token()).await.is_err());
	}

	#[tokio::test]
	async fn a_listener_that_does_not_hold_the_token_is_not_trusted_and_learns_nothing() {
		let dir = std::env::temp_dir().join(format!("veilway-helper-fake-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let socket = dir.join("fake.sock");
		let listener = tokio::net::UnixListener::bind(&socket).unwrap();
		let fake = tokio::spawn(async move {
			let (stream, _) = listener.accept().await.unwrap();
			let (read, mut write) = tokio::io::split(stream);
			let mut read = BufReader::new(read);
			let hello = read_line(&mut read, 1024).await.unwrap().unwrap();
			write_line(&mut write, &Out::Challenge {nonce: "c".repeat(NONCE_LEN), proof: proof(&"x".repeat(TOKEN_LEN), "server", "n", "c")}).await.unwrap();
			let more = tokio::time::timeout(Duration::from_millis(500), read_line(&mut read, 1024)).await;
			(hello, more.map_or(false, |line| matches!(line, Ok(Some(_)))))
		});
		assert!(link(&socket, &token()).await.is_err());
		let (hello, got_proof) = fake.await.unwrap();
		assert!(!hello.contains(&token()) && !got_proof);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn a_line_that_is_no_request_ends_the_connection_and_quit_ends_the_server() {
		let (_core, socket, task) = start("quit", euid()).await.unwrap();
		let link_ok = link(&socket, &token()).await.unwrap();
		let mut raw = ipc::connect_to(&socket).await.unwrap();
		raw.write_all(b"{\"id\":2,\"call\":\"run_this\"}\n").await.unwrap();
		let mut buffer = [0u8; 16];
		assert_eq!(tokio::io::AsyncReadExt::read(&mut raw, &mut buffer).await.unwrap_or(0), 0);
		assert_eq!(link_ok.call(Call::Quit).await.unwrap(), Value::Null);
		tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
	}
}
