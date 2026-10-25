//! The part of the desktop helper's `Core` that does not touch the platform layer: the library, the import steps and the connect loop's questions, run inside the app process. Android needs no helper: the app that holds the VPN permission may run the tunnel itself, and the one lock, the kill switch and the routes of the desktop have no counterpart here (the system's always-on VPN with "Block connections without VPN" is the kill switch, see `vpn.rs`).
//!
//! The code of `Core::call` is the desktop's, line for line, minus `fetch_gate` (there is no kill switch of ours to wait out) and the platform calls; `session` runs `vpn::run` where the helper runs `platform::run`.
use crate::logs::{LogLayer, START};
use crate::proto::{Call, Options, Out, Source};
use crate::proxy::ProxySettings;
use crate::view::{library_view, move_view, status_view, subscription_view, tags, AppliedOut, MoveOut, ProxyOut, SubscriptionOut};
use crate::vault::{AndroidVault, KEY_LOST};
use crate::vpn;
use anyhow::Context;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tokio::sync::{broadcast, mpsc, watch, Mutex as AsyncMutex, Notify};
use veilway_engine::import::{self, Fetcher, Library, Reviewed};
use veilway_engine::local::Local;
use veilway_engine::{ask_text, default_roots, Agree, Handle, Settings, StartError, Status, Store, Tunnel};
use veilway_proto::subscription::client::{Fetching, Standing, Offer, NativeOffer, CarriedOffer};
use veilway_proto::subscription::Kind;
use veilway_proto::subscription::payload::Id;

const STOP_WAIT: Duration = Duration::from_secs(30);

pub fn now() -> u64 {SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())}

/// The step an import is at. Only one import is open at a time, and nothing is kept until the second answer.
enum Pending {
	Native(NativeOffer),
	Carried(CarriedOffer),
	Fetching(Fetching),
	Reviewed(Reviewed),
}

struct Running {subscription: String, profile: String, stop: Arc<Notify>, answers: mpsc::UnboundedSender<bool>, done: watch::Receiver<bool>}

pub struct Core {
	pub(crate) library: AsyncMutex<Library>,
	store: Arc<Store>,
	/// The app's folder: the bundle's folder lives in it.
	pub(crate) dir: PathBuf,
	pub(crate) bundle: AsyncMutex<Option<veilway_engine::bundle::Review>>,
	pub(crate) languages: Mutex<Vec<String>>,
	pending: AsyncMutex<Option<Pending>>,
	running: Mutex<Option<Running>>,
	push: broadcast::Sender<Out>,
	last: Mutex<Option<crate::view::StatusView>>,
	/// Where the local proxy listens now, or why it did not start, put in every status the window gets.
	proxy: Mutex<Option<ProxyOut>>,
	handle: Mutex<Option<Handle>>,
}

#[derive(Serialize)]
struct OfferOut {kind: &'static str, host: Option<String>, fingerprint: String, pinned: bool, plain: bool, in_file: bool}

#[derive(Serialize)]
struct ReviewOut {fingerprint: String, replaces: bool, endpoint_changed: bool, moving: Option<MoveOut>, left_out: Vec<String>, preview: SubscriptionOut}

fn to_value<T: Serialize>(value: T) -> Result<Value, String> {serde_json::to_value(value).map_err(|error| error.to_string())}

impl Core {
	pub fn new(library: Library, store: Arc<Store>, dir: PathBuf) -> Arc<Self> {
		Arc::new(Self {library: AsyncMutex::new(library), store, dir, bundle: AsyncMutex::new(None), languages: Mutex::new(Vec::new()), pending: AsyncMutex::new(None), running: Mutex::new(None), push: broadcast::channel(256).0, last: Mutex::new(None), proxy: Mutex::new(None), handle: Mutex::new(None)})
	}

	pub fn subscribe(&self) -> broadcast::Receiver<Out> {self.push.subscribe()}

	pub fn send(&self, out: Out) {let _ = self.push.send(out);}

	fn tags(&self) -> Vec<veilway_proto::subscription::Tag> {tags(&self.languages.lock().unwrap())}

	pub(crate) async fn library_value(&self) -> Result<Value, String> {
		let mut value = to_value(library_view(&*self.library.lock().await, &self.store, &self.tags(), now()))?;
		self.add_notices(&mut value)?;
		Ok(value)
	}

	/// One request. The error is the text the window shows.
	pub async fn call(self: &Arc<Self>, call: Call) -> Result<Value, String> {
		let fetcher = || Fetcher::new(default_roots(), None);
		if matches!(call, Call::ImportOpen {..} | Call::ImportProceed {..} | Call::Refresh {..}) && LOCKDOWN.load(Ordering::Relaxed) && self.running.lock().unwrap().is_none() {return Err("Connect first. With Always-on VPN and lockdown, subscriptions are fetched only through the tunnel.".into())}
		match call {
			Call::Hello {..} | Call::Auth {..} => Ok(Value::Null),
			Call::Library {languages} => {
				*self.languages.lock().unwrap() = languages.into_iter().take(8).collect();
				self.library_value().await
			}
			Call::ImportOpen {source} => {
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
					Offer::Legacy(_) => return Err(import::ImportError::Legacy.text().to_owned()),
				};
				*self.pending.lock().await = Some(pending);
				to_value(out)
			}
			Call::ImportProceed {private} => {
				let allowed: Vec<IpAddr> = private.iter().filter_map(|address| address.parse().ok()).collect();
				let mut pending = self.pending.lock().await;
				let library = self.library.lock().await;
				let reviewed = match pending.take() {
					Some(Pending::Native(offer)) => {
						let fetching = import::proceed(offer, None).map_err(|error| error.text().to_owned())?;
						Self::fetch(&fetcher(), fetching, &library, &mut pending, &allowed).await?
					}
					Some(Pending::Fetching(fetching)) => Self::fetch(&fetcher(), fetching, &library, &mut pending, &allowed).await?,
					Some(Pending::Carried(offer)) => Ok(import::proceed_carried(offer, now(), &library).map_err(|error| error.text().to_owned())?),
					other => {
						*pending = other;
						return Err("There is no import waiting for a yes.".into());
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
				let Some(Pending::Reviewed(reviewed)) = pending.take() else {return Err("There is no subscription waiting to be kept.".into())};
				drop(pending);
				if keep {
					let mut library = self.library.lock().await;
					// A vault that could not be written says why: the user has to know that no safe place for the key was found.
					fetcher().accept(reviewed, None, &mut library).await.map_err(|error| match &error {import::ImportError::Store(cause) => format!("{} {cause}", error.text()), _ => error.text().to_owned()})?;
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
				match self.pending.lock().await.take() {
					Some(Pending::Fetching(fetching)) => fetcher().abandon(fetching, &[]).await,
					Some(Pending::Reviewed(reviewed)) => fetcher().decline(reviewed).await,
					_ => {}
				}
				Ok(Value::Null)
			}
			Call::Refresh {subscription: id, private} => {
				let mut library = self.library.lock().await;
				let at = library.held().iter().position(|held| held.id().as_str() == id).ok_or("That subscription is not held.")?;
				let allowed: Vec<IpAddr> = private.iter().filter_map(|address| address.parse().ok()).collect();
				if !allowed.is_empty() {library.allow_private(at, &allowed).map_err(|error| format!("The choice could not be saved: {error}"))?}
				match fetcher().refresh(&mut library, at, now()).await {
					Err(import::ImportError::PrivateEndpoint {host, addresses}) => return Ok(json!({"ask_private": {"host": host, "addresses": addresses}})),
					other => other.map_err(|error| error.text().to_owned())?,
				};
				drop(library);
				self.library_value().await
			}
			Call::Remove {subscription: id} => {
				if self.running.lock().unwrap().as_ref().is_some_and(|running| running.subscription == id) {return Err("Disconnect before removing the subscription that is in use.".into())}
				let mut library = self.library.lock().await;
				let found: Option<Id> = library.held().iter().find(|held| held.id().as_str() == id).map(|held| held.id().clone());
				let told = match found {Some(found) => fetcher().leave(&mut library, &found).await.map_err(|error| format!("The subscription could not be removed: {error}"))?, None => true};
				drop(library);
				self.store.set_lan_local(&id, false);
				self.store.set_exit_choice(&id, None);
				let _ = self.store.flush();
				// Whether the provider was told: the app warns when the device keeps its place there.
				Ok(json!({"library": self.library_value().await?, "told": told}))
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
				if !self.library.lock().await.held().iter().any(|held| held.id().as_str() == id) {return Err("That subscription is not held.".into())}
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
			// Android cannot run a downloaded program, so pasted links of other apps never reach the add-on here.
			Call::Xray | Call::XrayInstall | Call::XrayRemove => Err("xray_unsupported".into()),
			Call::Answer {yes} => {
				let sent = self.running.lock().unwrap().as_ref().is_some_and(|running| running.answers.send(yes).is_ok());
				if sent {Ok(Value::Null)} else {Err("There is no question waiting.".into())}
			}
			Call::Disconnect => {
				self.disconnect().await.map_err(|error| format!("{error:#}"))?;
				Ok(Value::Null)
			}
			Call::SelectExit {subscription: id, tag} => {
				if !self.library.lock().await.held().iter().any(|held| held.id().as_str() == id) {return Err("That subscription is not held.".into())}
				self.store.set_exit_choice(&id, tag.clone());
				self.store.flush().map_err(|error| format!("The choice could not be saved: {error}"))?;
				// With no tunnel the choice waits: the engine sends it when a tunnel of this subscription starts.
				if self.running.lock().unwrap().as_ref().is_some_and(|running| running.subscription == id) {
					if let Some(handle) = self.handle.lock().unwrap().as_ref() {handle.select_exit(tag);}
				}
				self.library_value().await
			}
			Call::BundleReview => self.bundle_review().await,
			Call::BundleDocument {subscription} => self.bundle_document(&subscription).await,
			Call::BundleApp => self.bundle_app().await,
			Call::BundleChunk {offset, len} => self.bundle_chunk(offset, len).await,
			Call::BundleNotices => self.bundle_notices().await,
			Call::BundleClose => self.bundle_close().await,
			Call::Status => {
				let running = self.running.lock().unwrap().is_some();
				to_value(json!({"connected": running, "status": self.last.lock().unwrap().clone(), "kill_switch_kept": false}))
			}
			Call::Quit => {
				if self.running.lock().unwrap().is_some() {let _ = self.disconnect().await;}
				Ok(Value::Null)
			}
		}
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
					error => Err(error.text().to_owned()),
				}
			}
		}
	}

	async fn connect(self: &Arc<Self>, subscription: String, profile: String, options: Options) -> Result<Value, String> {
		let held = self.library.lock().await.held().iter().find(|held| held.id().as_str() == subscription).cloned().ok_or("That subscription is not held.")?;
		if !held.subscription().profiles.iter().any(|candidate| candidate.id == profile) {return Err("That connection is not in the subscription.".into())}
		let (stop, (answers, replies), (done_tx, done)) = (Arc::new(Notify::new()), mpsc::unbounded_channel(), watch::channel(false));
		let mut running = self.running.lock().unwrap();
		if let Some(current) = running.as_ref() {return if current.subscription == subscription && current.profile == profile {Ok(Value::Null)} else {Err("Already connected.".into())}}
		let (core, notify, kept) = (self.clone(), stop.clone(), profile.clone());
		// The engine and the platform layer are driven on a runtime of their own, on a thread of their own: their futures need not be Send, and nothing the window does can block them.
		std::thread::Builder::new().name("tunnel".into()).spawn(move || {
			let ended = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
				Ok(runtime) => runtime.block_on(core.session(held, profile, options, notify, replies)),
				Err(error) => Err((error.to_string(), false)),
			};
			core.running.lock().unwrap().take();
			*core.handle.lock().unwrap() = None;
			*core.last.lock().unwrap() = None;
			*core.proxy.lock().unwrap() = None;
			let error = ended.err().map(|(error, _)| error);
			core.send(Out::Ended {error: error.clone(), kept: false});
			crate::bridge::ended(error.as_deref());
			let _ = done_tx.send(true);
		}).map_err(|error| error.to_string())?;
		*running = Some(Running {subscription, profile: kept, stop, answers, done});
		Ok(Value::Null)
	}

	async fn ask(&self, text: &str, stop: &Notify, answers: &mut mpsc::UnboundedReceiver<bool>) -> bool {
		self.send(Out::Question {text: text.to_owned()});
		tokio::select! {yes = answers.recv() => yes.unwrap_or(false), () = stop.notified() => false}
	}

	/// `veilway connect` without the terminal: the same loop of running the platform layer and asking what the engine asks. Ok is a stop the user asked for or a no they gave, with everything restored; an error is a connection that ended on its own and says whether the kill switch is still in force.
	async fn session(&self, held: veilway_proto::subscription::client::Held, profile: String, options: Options, stop: Arc<Notify>, mut answers: mpsc::UnboundedReceiver<bool>) -> Result<(), (String, bool)> {
		if held.standing(now()) != Standing::Current {tracing::info!("the subscription is out of date and keeps working")}
		let permit = match held.connect(now()) {
			Ok(permit) => permit,
			Err(stale) => if self.ask("This subscription expired more than 30 days ago, and the addresses and keys in it may no longer belong to the provider. Connect anyway?", &stop, &mut answers).await {stale.confirmed()} else {return Ok(())},
		};
		let mut settings = Settings::new(self.store.clone(), Arc::new(now), default_roots(), String::new());
		settings.languages = self.tags();
		settings.only = options.transport.clone().filter(|name| ["udp", "udp-obfs", "tls", "ws", "ws-plain", "fronted", "fronted-shaped", "faketls"].contains(&name.as_str()));
		*self.handle.lock().unwrap() = Some(settings.handle.clone());
		let (key, mut agree, lan_local) = (veilway_engine::store::profile_key(held.id().as_str(), &profile), Agree::default(), self.store.lan_local(held.id().as_str()));
		// The local proxy is the app's setting, read when the connection starts: a start at boot has no window to send it.
		let proxy = crate::load_settings().map(|settings| settings.proxy).unwrap_or_default();
		let proxy_only = proxy.on && proxy.only;
		crate::bridge::proxy_only(proxy_only);
		loop {
			let (statuses, seen) = watch::channel(None::<Status>);
			let on_status = |status: &Status| {
				statuses.send_replace(Some(status.clone()));
				let mut view = status_view(status, Some(AppliedOut {interface: "tun".into(), kill_switch: false, dns: "tunnel".into(), split: (!options.routes.is_empty()).then(|| options.routes.iter().map(ToString::to_string).collect()), allow_lan: lan_local}));
				view.proxy = self.proxy.lock().unwrap().clone();
				crate::bridge::state(&view.state);
				*self.last.lock().unwrap() = Some(view.clone());
				self.send(Out::Status(view));
			};
			// Proxy only asks Android for no VPN interface at all, so there is nothing to set up or take down.
			let outcome = if proxy_only {self.proxy_run(&proxy, settings.clone(), &held, &profile, &permit, agree, on_status, &stop).await} else {
				let run = vpn::run(&options, lan_local, settings.clone(), &held, &profile, &permit, agree, on_status, stop.notified());
				if proxy.on {tokio::select! {outcome = run => outcome, _ = proxy.alongside(seen, |out| self.show_proxy(Some(out))) => Ok(())}} else {run.await}
			};
			let _ = self.store.flush();
			let Err(error) = outcome else {return Ok(())};
			// The tunnel did not start because the user has still to say something. A no, or a stop, is the user's own end of it.
			let yes = match error.downcast_ref::<StartError>() {
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
				Some(StartError::Alpha) => return Err(("alpha_off".into(), false)),
				Some(_) | None => return Err((format!("{error:#}"), false)),
			};
			if !yes {
				let _ = self.store.flush();
				return Ok(());
			}
		}
	}

	/// The proxy came up (or could not) after the last status went out: the window is given that status again with it.
	fn show_proxy(&self, proxy: Option<ProxyOut>) {
		*self.proxy.lock().unwrap() = proxy.clone();
		if let Some(view) = self.last.lock().unwrap().as_mut() {
			view.proxy = proxy;
			self.send(Out::Status(view.clone()));
		}
	}

	/// Proxy only: the engine's tunnel with no VPN interface, so the app's own sockets need no `protect`. `Local` is the one reader of the tunnel's packets and opens the proxy's connections inside it. The networks the phone is on are still told to the engine. Ok is a stop the user asked for.
	#[allow(clippy::too_many_arguments)]
	async fn proxy_run(&self, proxy: &ProxySettings, mut settings: Settings, held: &veilway_proto::subscription::client::Held, profile: &str, permit: &veilway_proto::subscription::client::Permit, agree: Agree, mut on_status: impl FnMut(&Status), stop: &Notify) -> anyhow::Result<()> {
		let config = proxy.config().map_err(anyhow::Error::msg)?;
		let mut own = crate::bridge::own();
		let at_start = own.borrow_and_update().clone();
		settings.networks = at_start.networks;
		settings.network = at_start.description;
		let tunnel = Tunnel::start(settings, held, profile, permit, agree)?;
		let local = match Local::in_tunnel(tunnel, config).await {
			Ok(local) => local,
			Err((error, tunnel)) => {
				tunnel.stop().await;
				return Err(error.into());
			}
		};
		let mut watch = local.watch().context("the proxy has no tunnel under it")?;
		let mut power = crate::bridge::low_power();
		local.low_power(*power.borrow_and_update());
		self.show_proxy(Some(proxy.out(local.addr(), None)));
		on_status(&watch.borrow_and_update().clone());
		loop {
			tokio::select! {
				changed = watch.changed() => {
					if changed.is_err() {anyhow::bail!("the engine stopped on its own")}
					on_status(&watch.borrow_and_update().clone());
				}
				changed = own.changed() => {
					changed?;
					let found = own.borrow_and_update().clone();
					tracing::info!(networks = found.networks.len(), "the device's networks changed");
					local.moved(found.description, found.networks);
				}
				changed = power.changed() => {
					changed?;
					local.low_power(*power.borrow_and_update());
				}
				() = stop.notified() => break,
			}
		}
		let last = local.stop().await;
		tracing::info!(state = ?last.map(|status| status.state), "the tunnel stopped");
		Ok(())
	}

	/// A running connection is asked to stop, which it does the clean way. With none running, whatever an earlier one left in force is removed.
	async fn disconnect(&self) -> anyhow::Result<()> {
		let running = self.running.lock().unwrap().as_ref().map(|running| (running.stop.clone(), running.done.clone()));
		if let Some((stop, mut done)) = running {
			stop.notify_one();
			tokio::time::timeout(STOP_WAIT, done.wait_for(|finished| *finished)).await.context("The connection did not stop in time.")??;
			return Ok(());
		}
		*self.last.lock().unwrap() = None;
		self.send(Out::Ended {error: None, kept: false});
		Ok(())
	}
}

/// What the process holds once Kotlin has said where its files are: the core, the runtime that runs its calls, and the folder. Made by whoever comes first, the app's plugin or the VpnService that the system started on its own (boot, always-on), and never twice.
pub struct Host {
	pub core: Arc<Core>,
	pub runtime: tokio::runtime::Runtime,
	pub dir: PathBuf,
}

static HOST: OnceLock<Host> = OnceLock::new();
static SINK: OnceLock<Box<dyn Fn(Out) + Send + Sync>> = OnceLock::new();
static LOGS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
const LOG_KEEP: usize = 200;
/// Set by Kotlin while the system's always-on VPN blocks the internet without the tunnel (`Native.lockdown`).
pub static LOCKDOWN: AtomicBool = AtomicBool::new(false);

#[link(name = "log")]
extern "C" {
	fn __android_log_write(priority: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
}

pub fn get() -> Option<&'static Host> {HOST.get()}

/// The app's window gets everything the core says that is not an answer, as events. Set once, when the window exists; until then (a start at boot) the core runs without one.
pub fn set_sink(sink: impl Fn(Out) + Send + Sync + 'static) {let _ = SINK.set(Box::new(sink));}

pub fn logs() -> Vec<String> {LOGS.lock().unwrap().iter().cloned().collect()}

/// One request from the window, run on the core's own runtime.
pub async fn call(call: Call) -> Result<Value, String> {
	let host = get().ok_or("Veilway is still starting.")?;
	let core = host.core.clone();
	host.runtime.spawn(async move {core.call(call).await}).await.map_err(|error| error.to_string())?
}

pub fn init(dir: &str) -> Result<&'static Host, String> {
	static GUARD: Mutex<()> = Mutex::new(());
	let _guard = GUARD.lock().unwrap();
	if let Some(host) = HOST.get() {return Ok(host)}
	let dir = PathBuf::from(dir);
	let _ = START.set(Instant::now());
	let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|error| error.to_string())?;
	let (library, damaged) = Library::open(Box::new(AndroidVault::new(&dir))).map_err(|error| error.to_string())?;
	let core = Core::new(library, Arc::new(Store::open(dir.join("client.json"))), dir.clone());
	let log = core.clone();
	let _ = tracing_subscriber::registry().with(LogLayer {sink: move |line| log.send(Out::Log {line}), helper: true}).try_init();
	for _ in damaged {tracing::warn!("a stored subscription does not read any more and is left out")}
	if KEY_LOST.load(Ordering::Relaxed) {tracing::warn!("the vault key is gone from the Android Keystore, so the stored subscriptions are not available and must be added again")}
	let mut events = core.subscribe();
	runtime.spawn(async move {
		loop {
			let out = match events.recv().await {
				Ok(out) => out,
				Err(broadcast::error::RecvError::Lagged(_)) => continue,
				Err(broadcast::error::RecvError::Closed) => break,
			};
			if let Out::Log {line} = &out {
				let mut logs = LOGS.lock().unwrap();
				while logs.len() >= LOG_KEEP {logs.pop_front();}
				logs.push_back(line.clone());
				// The line's second word is its level. A release build sends warnings and errors to logcat; a debug build sends everything.
				let level = line.split_whitespace().nth(1).unwrap_or_default();
				if let Some(text) = std::ffi::CString::new(line.as_str()).ok().filter(|_| cfg!(debug_assertions) || matches!(level, "WARN" | "ERROR")) {
					// SAFETY: both strings are NUL terminated and live for the call.
					unsafe {__android_log_write(4, c"veilway".as_ptr(), text.as_ptr())};
				}
			}
			if let Some(sink) = SINK.get() {sink(out)}
		}
	});
	tracing::info!("client ready");
	Ok(HOST.get_or_init(|| Host {core, runtime, dir}))
}
