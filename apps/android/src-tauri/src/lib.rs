//! Tauri shell for Android around `veilway-engine`. Same screens, same commands as the desktop app (`apps/desktop`), whose UI in `../desktop/ui` is loaded unchanged, with two differences: no helper (the app process holds the VPN permission, so the engine runs in it, see `host.rs`) and the tunnel belongs to a Kotlin `VpnService`, not to the window.
//!
//! **Why `apps/android` and not a second target of `apps/desktop`.** Tauri 2 mobile needs the app as a library with a mobile entry point and its own generated Gradle project, and the desktop crate is a binary that starts a privileged helper. A separate crate keeps the finished desktop app untouched and shares what is shared by path (`proto.rs`, `view.rs`, `qr.rs`, `logs.rs`).
//!
//! **Who owns what.** The VpnService owns the interface and the foreground notification and calls the engine through `bridge.rs` (JNI). The window only sends commands: `connect` asks Kotlin for the VPN consent (`prepare`) and then starts the service, which calls `Native.connect`; everything else goes to the core directly. Nothing about the tunnel lives in JavaScript, so a killed webview or a start at boot (no window at all) changes nothing. The Kotlin side is in `../kotlin`.
#[path = "../../../desktop/src-tauri/src/logs.rs"]
mod logs;
#[path = "../../../desktop/src-tauri/src/proto.rs"]
#[allow(dead_code)]
mod proto;
#[path = "../../../desktop/src-tauri/src/qr.rs"]
mod qr;
#[path = "../../../desktop/src-tauri/src/view.rs"]
mod view;
mod bridge;
mod host;
mod update;
mod vault;
mod vpn;
use base64::Engine;
use proto::{Call, Options, Out, Source};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::plugin::{Builder, TauriPlugin};
use tauri::{AppHandle, Emitter, Manager, State, Wry};
use tauri_plugin_opener::OpenerExt;

static LINKS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn linkset() -> &'static Mutex<HashSet<String>> {LINKS.get_or_init(|| Mutex::new(HashSet::new()))}

/// The Kotlin plugin: consent, the service, the settings screen.
struct Vpn(tauri::plugin::PluginHandle<Wry>);

#[derive(Serialize)]
struct UpdateInfo {available: bool, version: String, notes: String, current: String}

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {auto_update: bool, theme: String, locale: String, kill_switch: bool}

impl Default for Settings {
	fn default() -> Self {Settings {auto_update: true, theme: "dark".into(), locale: "en".into(), kill_switch: false}}
}

#[derive(Deserialize)]
struct Granted {granted: bool}

/// What the core says by itself becomes events for the window: `status`, `question` (a yes or no the engine needs, answered with `answer`), `ended` and `log`.
fn forward(app: &AppHandle, out: Out) {
	match out {
		Out::Status(view) => {let _ = app.emit("status", view);}
		Out::Question {text} => {let _ = app.emit("question", text);}
		Out::Ended {error, kept} => {let _ = app.emit("ended", json!({"error": error, "kept": kept}));}
		Out::Log {line} => {let _ = app.emit("log", line);}
		Out::Reply {..} | Out::Challenge {..} => {}
	}
}

/// Like `host::call` for answers that carry logos: the pictures are checked here and become `data:` URLs or nothing.
async fn call_branded(call: Call) -> Result<Value, String> {
	let mut value = host::call(call).await?;
	let value = tokio::task::spawn_blocking(move || {view::brand(&mut value); value}).await.map_err(|error| error.to_string())?;
	remember_links(&value);
	Ok(value)
}

/// The provider links the library shows are the only ones `open_link` opens. Each whole list the core sends replaces the last one.
fn remember_links(value: &Value) {
	let Some(list) = value.as_array() else {return};
	let links: HashSet<String> = list.iter().flat_map(|subscription| {
		let support = subscription["support"].as_array().into_iter().flatten().filter_map(|pair| pair.get(1)?.as_str());
		let cards = subscription["cards"].as_array().into_iter().flatten().filter(|card| card["kind"] == "link").filter_map(|card| card["url"].as_str());
		support.chain(cards).map(String::from).collect::<Vec<_>>()
	}).collect();
	*linkset().lock().unwrap() = links;
}

/// Runs a command of the Kotlin plugin off the async threads, since the call waits for the answer.
async fn plugin<T: serde::de::DeserializeOwned + Send + 'static>(vpn: &State<'_, Arc<Vpn>>, command: &'static str, payload: Value) -> Result<T, String> {
	let vpn = vpn.inner().clone();
	tauri::async_runtime::spawn_blocking(move || vpn.0.run_mobile_plugin::<T>(command, payload).map_err(|error| error.to_string())).await.map_err(|error| error.to_string())?
}

#[tauri::command]
async fn import_open(source: Source) -> Result<Value, String> {host::call(Call::ImportOpen {source}).await}

#[tauri::command]
async fn import_qr(data: String) -> Result<Value, String> {
	let bytes = base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| "The picture could not be read.".to_string())?;
	let text = tokio::task::spawn_blocking(move || qr::decode(&bytes)).await.map_err(|error| error.to_string())??;
	host::call(Call::ImportOpen {source: Source::Link {text}}).await
}

#[tauri::command]
async fn import_proceed(private: Option<Vec<String>>) -> Result<Value, String> {call_branded(Call::ImportProceed {private: private.unwrap_or_default()}).await}

#[tauri::command]
async fn import_keep(keep: bool) -> Result<Value, String> {call_branded(Call::ImportKeep {keep}).await}

#[tauri::command]
async fn import_cancel() -> Result<Value, String> {host::call(Call::ImportCancel).await}

#[tauri::command]
async fn library(languages: Vec<String>) -> Result<Value, String> {call_branded(Call::Library {languages}).await}

#[tauri::command]
async fn refresh(id: String, private: Option<Vec<String>>) -> Result<Value, String> {call_branded(Call::Refresh {subscription: id, private: private.unwrap_or_default()}).await}

#[tauri::command]
async fn remove(id: String) -> Result<Value, String> {call_branded(Call::Remove {subscription: id}).await}

/// Saves "Let apps reach devices on this network" for a subscription and gives the library back. It applies from the next connect.
#[tauri::command]
async fn set_lan(id: String, on: bool) -> Result<Value, String> {call_branded(Call::SetLan {subscription: id, on}).await}

/// Asks for the VPN consent (the system's own dialog, once), then starts the service. The service starts the connection, and what happens after that comes back as events. The first call blocks the window's request until the user has answered the dialog.
#[tauri::command]
async fn connect(vpn: State<'_, Arc<Vpn>>, subscription: String, profile: String, options: Options) -> Result<Value, String> {
	tracing::info!("connect requested");
	let Granted {granted} = plugin(&vpn, "prepare", json!({})).await?;
	if !granted {return Err("Veilway needs your permission to set up a VPN connection. Tap Connect again and allow it.".into())}
	let options = serde_json::to_string(&Options {kill_switch: false, ..options}).map_err(|error| error.to_string())?;
	plugin::<Value>(&vpn, "start", json!({"subscription": subscription, "profile": profile, "options": options})).await?;
	Ok(Value::Null)
}

#[tauri::command]
async fn answer(yes: bool) -> Result<Value, String> {host::call(Call::Answer {yes}).await}

/// Through the service, which stops the connection and itself and forgets that the connection is wanted, so the next boot does not bring it back.
#[tauri::command]
async fn disconnect(vpn: State<'_, Arc<Vpn>>) -> Result<Value, String> {
	plugin::<Value>(&vpn, "stop", json!({})).await?;
	Ok(Value::Null)
}

#[tauri::command]
async fn select_exit(tag: Option<String>) -> Result<Value, String> {host::call(Call::SelectExit {tag}).await}

#[tauri::command]
async fn status() -> Result<Value, String> {host::call(Call::Status).await}

#[tauri::command]
fn log_history() -> Vec<String> {host::logs()}

/// Opens a provider link in the browser or mail app. Only http, https and mailto links the library has shown get through.
#[tauri::command]
fn open_link(app: AppHandle, url: String) -> Result<(), String> {
	let scheme = tauri::Url::parse(&url).map_err(|_| "The link is not valid.".to_string())?.scheme().to_string();
	if !matches!(scheme.as_str(), "http" | "https" | "mailto") || !linkset().lock().unwrap().contains(&url) {return Err("This is not one of the provider's links.".into())}
	app.opener().open_url(url, None::<&str>).map_err(|error| error.to_string())
}

/// The system's VPN settings, where Always-on VPN and "Block connections without VPN" are turned on for Veilway.
#[tauri::command]
async fn open_vpn_settings(vpn: State<'_, Arc<Vpn>>) -> Result<(), String> {plugin::<Value>(&vpn, "openVpnSettings", json!({})).await.map(|_| ())}

#[tauri::command]
fn get_autostart() -> bool {false}

#[tauri::command]
fn set_autostart(_enabled: bool) -> Result<(), String> {Err("Start at login is not a setting on Android. Turn on Always-on VPN in the system's VPN settings.".into())}

/// Looks for a newer signed release on GitHub. See `update.rs` for what is trusted and what is checked.
#[tauri::command]
async fn check_update(app: AppHandle) -> Result<UpdateInfo, String> {
	let current = app.package_info().version.to_string();
	match update::latest(&current).await? {
		Some(found) => {
			tracing::info!("update {} available", found.tag);
			Ok(UpdateInfo {available: true, version: found.version, notes: found.notes, current})
		}
		None => Ok(UpdateInfo {available: false, version: current.clone(), notes: String::new(), current}),
	}
}

static UPDATING: AtomicBool = AtomicBool::new(false);

/// Downloads the newest release, checks its signature, and only then hands it to the system's installer, which asks the user. The Kotlin side stops the connection right before, and it comes back after the update if it was on.
#[tauri::command]
async fn install_update(app: AppHandle, vpn: State<'_, Arc<Vpn>>) -> Result<(), String> {
	if UPDATING.swap(true, Ordering::SeqCst) {return Err("An update is already in progress.".into())}
	let result = download_update(&app, &vpn).await;
	UPDATING.store(false, Ordering::SeqCst);
	result
}

async fn download_update(app: &AppHandle, vpn: &State<'_, Arc<Vpn>>) -> Result<(), String> {
	let Granted {granted} = plugin(vpn, "canInstall", json!({})).await?;
	if !granted {
		plugin::<Value>(vpn, "allowInstalls", json!({})).await?;
		return Err("Android has not allowed Veilway to install apps yet. Allow it in the screen that just opened, come back, and tap Update again.".into());
	}
	let found = update::latest(&app.package_info().version.to_string()).await?.ok_or("Already up to date.")?;
	let signature = update::signature(&found).await?;
	let folder = host::get().ok_or("Veilway is still starting.")?.dir.join("update");
	let _ = std::fs::remove_dir_all(&folder);
	std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
	let path = folder.join(update::APK);
	tracing::info!("downloading update {}", found.tag);
	let verified = async {
		update::download(&found, &path, |downloaded, total| {let _ = app.emit("update-progress", json!({"downloaded": downloaded, "total": total}));}).await?;
		let file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
		let tag = found.tag.clone();
		tokio::task::spawn_blocking(move || update::verify(update::PUBKEY, &signature, &tag, file)).await.map_err(|error| error.to_string())?
	}.await;
	if let Err(error) = verified {
		let _ = std::fs::remove_dir_all(&folder);
		tracing::warn!("update {} refused: {error}", found.tag);
		return Err(error);
	}
	tracing::info!("update {} verified, handing it to the installer", found.tag);
	let handed = plugin::<Value>(vpn, "install", json!({"path": path.to_string_lossy()})).await;
	if handed.is_err() {let _ = std::fs::remove_dir_all(&folder);}
	handed.map(|_| ())
}

fn settings_path() -> Result<std::path::PathBuf, String> {Ok(host::get().ok_or("Veilway is still starting.")?.dir.join("settings.json"))}

#[tauri::command]
async fn get_settings() -> Result<Settings, String> {Ok(std::fs::read_to_string(settings_path()?).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default())}

#[tauri::command]
async fn set_settings(settings: Settings) -> Result<(), String> {
	let body = serde_json::to_string_pretty(&settings).map_err(|error| error.to_string())?;
	std::fs::write(settings_path()?, body).map_err(|error| error.to_string())
}

fn vpn_plugin() -> TauriPlugin<Wry> {
	Builder::new("vpn").setup(|app, api| {
		let handle = api.register_android_plugin("io.github.veilwayproject.app", "VpnPlugin")?;
		app.manage(Arc::new(Vpn(handle)));
		Ok(())
	}).build()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
	tauri::Builder::default()
		.plugin(tauri_plugin_opener::init())
		.plugin(vpn_plugin())
		.invoke_handler(tauri::generate_handler![import_open, import_qr, import_proceed, import_keep, import_cancel, library, refresh, remove, set_lan, connect, answer, disconnect, select_exit, status, log_history, check_update, install_update, get_settings, set_settings, open_link, get_autostart, set_autostart, open_vpn_settings])
		.setup(|app| {
			let handle = app.handle().clone();
			host::set_sink(move |out| forward(&handle, out));
			Ok(())
		})
		.run(tauri::generate_context!())
		.expect("failed to start the tauri application");
}
