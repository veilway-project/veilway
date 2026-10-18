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
#[path = "../../../desktop/src-tauri/src/bundle_store.rs"]
mod bundle_store;
mod bridge;
mod bundle;
mod host;
mod update;
mod vault;
mod vpn;
use base64::Engine;
use ring::digest::{Context, SHA256};
use proto::{Call, Options, Out, Source};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom, Write};
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

#[derive(Deserialize)]
struct Picked {picked: bool}

#[derive(Deserialize)]
struct Saved {saved: bool}

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

/// The provider links the library shows are the only ones `open_link` opens. Each whole list the core sends replaces the last one; an import's preview adds its own, so its terms open before the user keeps it.
fn remember_links(value: &Value) {
	if let Some(preview) = value.get("preview") {linkset().lock().unwrap().extend(view::provider_links(preview)); return}
	let Some(list) = value.as_array() else {return};
	*linkset().lock().unwrap() = list.iter().flat_map(view::provider_links).collect();
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
	let bytes = base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| veilway_engine::import::Code::PictureUnreadable.as_str().to_string())?;
	let text = tokio::task::spawn_blocking(move || qr::decode(&bytes)).await.map_err(|error| error.to_string())?.map_err(|code| code.as_str().to_string())?;
	host::call(Call::ImportOpen {source: Source::Link {text}}).await
}

/// The link of a held subscription with its code, for the share dialog. Only the link: the device's keys and secrets stay in the core.
#[tauri::command]
async fn share_link(id: String) -> Result<Value, String> {
	let mut value = host::call(Call::ShareLink {subscription: id}).await?;
	let qr = value["link"].as_str().map(qr::render).ok_or("The link could not be read.")?.map_err(|code| code.as_str().to_string())?;
	value["qr"] = json!(qr);
	Ok(value)
}

/// Opens the system's share sheet with the link as text.
#[tauri::command]
async fn share_text(vpn: State<'_, Arc<Vpn>>, text: String) -> Result<Value, String> {plugin(&vpn, "shareText", json!({"text": text})).await}

/// Seals the link under the password, then lets the user pick where the file goes (the system's save screen, from which it can be shared). Saved is false when the user backed out.
#[tauri::command]
async fn share_file(vpn: State<'_, Arc<Vpn>>, id: String, password: String) -> Result<bool, String> {
	let value = host::call(Call::ShareFile {subscription: id, password}).await?;
	let Saved {saved} = plugin(&vpn, "saveFile", json!({"name": "veilway-subscription.vwsealed", "data": value["data"]})).await?;
	Ok(saved)
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

/// Confirms or declines a subscription's backup update hosts and gives the library back. Nothing is fetched from a host before its yes.
#[tauri::command]
async fn answer_hosts(id: String, allow: Vec<String>, decline: Vec<String>) -> Result<Value, String> {call_branded(Call::AnswerHosts {subscription: id, allow, decline}).await}

/// Saves "Let apps reach devices on this network" for a subscription and gives the library back. It applies from the next connect.
#[tauri::command]
async fn set_lan(id: String, on: bool) -> Result<Value, String> {call_branded(Call::SetLan {subscription: id, on}).await}

/// Whether the transports in alpha are on, and turning them on or off. The window shows the warning and has the user confirm before it asks for on.
#[tauri::command]
async fn get_alpha() -> Result<Value, String> {host::call(Call::Alpha).await}

#[tauri::command]
async fn set_alpha(on: bool) -> Result<Value, String> {host::call(Call::SetAlpha {on}).await}

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
	if !matches!(scheme.as_str(), "http" | "https" | "mailto") || (!view::PRIVACY_URLS.contains(&url.as_str()) && !linkset().lock().unwrap().contains(&url)) {return Err("This is not one of the provider's links.".into())}
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

/// Copies the bundle the system's picker gave into the app's folder and reviews it. None is a picker the user closed.
#[tauri::command]
async fn bundle_pick(vpn: State<'_, Arc<Vpn>>) -> Result<Option<Value>, String> {
	if !plugin::<Picked>(&vpn, "pickBundle", json!({})).await?.picked {return Ok(None)}
	host::call(Call::BundleReview).await.map(Some)
}

#[tauri::command]
async fn bundle_document(id: String) -> Result<Value, String> {call_branded(Call::BundleDocument {subscription: id}).await}

#[tauri::command]
async fn bundle_notices() -> Result<Value, String> {host::call(Call::BundleNotices).await}

#[tauri::command]
async fn bundle_close() -> Result<Value, String> {host::call(Call::BundleClose).await}

/// Hands the app part of the open bundle to the system's installer. Its bytes are copied out of the bundle, checked against the hash the review made, and checked by the same minisign check as an online update, under the release tag. Refused while a connection is being set up. The installer asks the user.
#[tauri::command]
async fn bundle_install(vpn: State<'_, Arc<Vpn>>) -> Result<(), String> {
	let status = host::call(Call::Status).await?;
	if status["status"]["state"].as_str() == Some("connecting") {return Err("tunnel_starting".into())}
	let staged = host::call(Call::BundleApp).await?;
	let dir = host::get().ok_or("Veilway is still starting.")?.dir.clone();
	let copy = dir.join(bundle::FOLDER).join(bundle_store::COPY);
	let update = dir.join("update");
	let _ = std::fs::remove_dir_all(&update);
	std::fs::create_dir_all(&update).map_err(|error| error.to_string())?;
	let apk = update.join(update::APK);
	let (version, signature) = (staged["version"].as_str().unwrap_or_default().to_owned(), staged["signature"].as_str().unwrap_or_default().to_owned());
	let (offset, size, expected) = (staged["offset"].as_u64().unwrap_or_default(), staged["size"].as_u64().unwrap_or_default(), staged["sha256"].as_str().unwrap_or_default().to_owned());
	let (target, tag) = (apk.clone(), format!("v{version}"));
	let checked = tokio::task::spawn_blocking(move || -> Result<(), String> {
		let mut source = std::fs::File::open(&copy).map_err(|error| error.to_string())?;
		source.seek(SeekFrom::Start(offset)).map_err(|error| error.to_string())?;
		let mut out = std::fs::File::create(&target).map_err(|error| error.to_string())?;
		let mut hash = Context::new(&SHA256);
		let mut buffer = vec![0; 1 << 16];
		let mut left = size;
		while left > 0 {
			let want = left.min(buffer.len() as u64) as usize;
			let read = source.read(&mut buffer[..want]).map_err(|error| error.to_string())?;
			if read == 0 {return Err("app_short".into())}
			hash.update(&buffer[..read]);
			out.write_all(&buffer[..read]).map_err(|error| error.to_string())?;
			left -= read as u64;
		}
		out.sync_all().map_err(|error| error.to_string())?;
		if proto::hex(hash.finish().as_ref()) != expected {return Err("app_mismatch".into())}
		update::verify(update::PUBKEY, &signature, &tag, std::fs::File::open(&target).map_err(|error| error.to_string())?)
	}).await.map_err(|error| error.to_string())?;
	if let Err(error) = checked {
		let _ = std::fs::remove_dir_all(&update);
		return Err(error);
	}
	tracing::info!("app part {} from a bundle verified, handing it to the installer", version);
	let handed = plugin::<Value>(&vpn, "install", json!({"path": apk.to_string_lossy()})).await;
	if handed.is_err() {let _ = std::fs::remove_dir_all(&update);}
	handed?;
	let _ = host::call(Call::BundleClose).await;
	Ok(())
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
		.invoke_handler(tauri::generate_handler![import_open, import_qr, import_proceed, import_keep, import_cancel, share_link, share_text, share_file, library, refresh, remove, answer_hosts, set_lan, get_alpha, set_alpha, connect, answer, disconnect, select_exit, status, log_history, check_update, install_update, bundle_pick, bundle_document, bundle_notices, bundle_close, bundle_install, get_settings, set_settings, open_link, get_autostart, set_autostart, open_vpn_settings])
		.setup(|app| {
			let handle = app.handle().clone();
			host::set_sink(move |out| forward(&handle, out));
			Ok(())
		})
		.run(tauri::generate_context!())
		.expect("failed to start the tauri application");
}
