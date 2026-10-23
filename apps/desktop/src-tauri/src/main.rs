#![cfg_attr(not(debug_assertions), windows_subsystem="windows")]
//! Tauri shell around `veilway-engine` and the platform layer. The window is unprivileged and never holds a key: the engine, the vault and the system changes live in a helper (`helper.rs`, this same executable started with `--helper` and raised once through the system's prompt), and the commands below pass the UI's asks to it over `link.rs`. The UI is static HTML in ../ui.
mod bundle;
mod bundle_store;
mod helper;
mod ipc;
mod legacy;
mod link;
mod logs;
mod proto;
mod qr;
mod view;
use base64::Engine;
use link::Backend;
use logs::{LogLayer, START};
use proto::{Call, Options, Out, Source};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::UpdaterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use veilway_engine::import::Code;

static HANDLE:OnceLock<AppHandle>=OnceLock::new();
static LOGS:OnceLock<Mutex<VecDeque<String>>>=OnceLock::new();
static LINKS:OnceLock<Mutex<HashSet<String>>>=OnceLock::new();
static FRAME_AT:Mutex<Option<Instant>>=Mutex::new(None);
const LOG_KEEP:usize=200;
/// The camera preview sends a frame every 300 ms; frames closer than this are refused unread.
const FRAME_GAP:Duration=Duration::from_millis(200);
/// The largest bundle the window stages: the file cap of the offline bundle format.
const BUNDLE_MAX:u64=1<<30;

fn logbuf()->&'static Mutex<VecDeque<String>>{LOGS.get_or_init(|| Mutex::new(VecDeque::new()))}

fn linkset()->&'static Mutex<HashSet<String>>{LINKS.get_or_init(|| Mutex::new(HashSet::new()))}

/// Appends to the ring buffer and pushes the same line to the webview as a `log` event.
fn push_log(line:String){
	let mut buf=logbuf().lock().unwrap();
	while buf.len()>=LOG_KEEP{buf.pop_front();}
	buf.push_back(line.clone());
	drop(buf);
	if let Some(h)=HANDLE.get(){let _=h.emit("log", line);}
}

#[derive(Serialize)]
struct UpdateInfo{available:bool, version:String, notes:String, current:String}

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings{auto_update:bool, theme:String, locale:String, kill_switch:bool}

impl Default for Settings{fn default()->Self{Settings{auto_update:true, theme:dark(), locale:"en".into(), kill_switch:true}}}

fn dark()->String{"dark".to_string()}

/// What the helper says by itself becomes events for the UI: `status`, `question` (a yes or no the engine needs, answered with `answer`), `ended`, `log` and `xray-install` (how the install of the add-on goes).
fn forward(app:&AppHandle, out:Out){
	match out{
		Out::Status(view)=>{let _=app.emit("status", view);}
		Out::Question{text}=>{let _=app.emit("question", text);}
		Out::Ended{error, kept}=>{let _=app.emit("ended", serde_json::json!({"error":error, "kept":kept}));}
		Out::Log{line}=>push_log(line),
		Out::XrayInstall{phase, downloaded, state, error}=>{let _=app.emit("xray-install", serde_json::json!({"phase":phase, "downloaded":downloaded, "state":state, "error":error}));}
		Out::Reply{..}|Out::Challenge{..}=>{}
	}
}

async fn ask(backend:&State<'_, Arc<Backend>>, call:Call)->Result<Value, String>{backend.call(call).await}

/// Like `ask` for answers that carry logos: the pictures are checked here, in the process without rights, and become `data:` URLs or nothing.
async fn ask_branded(backend:&State<'_, Arc<Backend>>, call:Call)->Result<Value, String>{
	let mut value=backend.call(call).await?;
	let value=tokio::task::spawn_blocking(move || {view::brand(&mut value); value}).await.map_err(|e| e.to_string())?;
	remember_links(&value);
	Ok(value)
}

/// The provider links the library shows are the only ones `open_link` opens. Each whole list the helper sends replaces the last one; an import's preview adds its own, so its terms open before the user keeps it.
fn remember_links(value:&Value){
	if let Some(preview)=value.get("preview"){linkset().lock().unwrap().extend(view::provider_links(preview)); return}
	let Some(list)=value.as_array() else {return};
	*linkset().lock().unwrap()=list.iter().flat_map(view::provider_links).collect();
}

/// Step 1 of an import, from a link or a subscription file. Returns what the user is asked about first; nothing is sent anywhere until `import_proceed`.
#[tauri::command]
async fn import_open(backend:State<'_, Arc<Backend>>, source:Source)->Result<Value, String>{ask(&backend, Call::ImportOpen{source}).await}

/// The same from a picture with a QR code in it (base64 of the file, as pasted or picked). The picture is read here, in the unprivileged process.
#[tauri::command]
async fn import_qr(backend:State<'_, Arc<Backend>>, data:String)->Result<Value, String>{
	let bytes=base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| Code::PictureUnreadable.as_str().to_string())?;
	let text=tokio::task::spawn_blocking(move || qr::decode(&bytes)).await.map_err(|e| e.to_string())?.map_err(|code| code.as_str().to_string())?;
	ask(&backend, Call::ImportOpen{source:Source::Link{text}}).await
}

/// One frame of the camera preview in the scan dialog (base64 of a JPEG). None is a frame with no code in it, so the window keeps looking; a code opens the import exactly like a pasted link. Nothing of the frame is kept.
#[tauri::command]
async fn scan_frame(backend:State<'_, Arc<Backend>>, data:String)->Result<Option<Value>, String>{
	{
		let mut last=FRAME_AT.lock().unwrap();
		if last.is_some_and(|at| at.elapsed()<FRAME_GAP){return Err("scan_busy".into())}
		*last=Some(Instant::now());
	}
	let Some(text)=tokio::task::spawn_blocking(move || qr::frame(&data)).await.map_err(|e| e.to_string())?.map_err(|code| code.as_str().to_string())? else {return Ok(None)};
	ask(&backend, Call::ImportOpen{source:Source::Link{text}}).await.map(Some)
}

/// The link of a held subscription with its code, for the share dialog. Only the link: the device's keys and secrets stay in the helper.
#[tauri::command]
async fn share_link(backend:State<'_, Arc<Backend>>, id:String)->Result<Value, String>{
	let mut value=ask(&backend, Call::ShareLink{subscription:id}).await?;
	let qr=value["link"].as_str().map(qr::render).ok_or("The link could not be read.")?.map_err(|code| code.as_str().to_string())?;
	value["qr"]=json!(qr);
	Ok(value)
}

/// Seals the link under the password in the helper, then asks where to save the file. False is a dialog the user closed.
#[tauri::command]
async fn share_file(app:AppHandle, backend:State<'_, Arc<Backend>>, id:String, password:String)->Result<bool, String>{
	let value=ask(&backend, Call::ShareFile{subscription:id, password}).await?;
	let bytes=base64::engine::general_purpose::STANDARD.decode(value["data"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
	tokio::task::spawn_blocking(move || {
		let Some(path)=app.dialog().file().set_file_name("veilway-subscription.vwsealed").add_filter("Veilway sealed subscription", &["vwsealed"]).blocking_save_file() else {return Ok(false)};
		std::fs::write(path.into_path().map_err(|e| e.to_string())?, bytes).map(|_| true).map_err(|e| e.to_string())
	}).await.map_err(|e| e.to_string())?
}

/// Copies the bundle the user picked into the window's folder, where the helper reviews it. The picker runs here, so the window never names a path. None is a dialog the user closed.
#[tauri::command]
async fn bundle_pick(app:AppHandle, backend:State<'_, Arc<Backend>>)->Result<Option<Value>, String>{
	let folder=app.path().app_config_dir().map_err(|e| e.to_string())?.join("helper");
	let staged=tokio::task::spawn_blocking(move || -> Result<bool, String> {
		let Some(path)=app.dialog().file().add_filter("Veilway bundle", &["vwbundle"]).blocking_pick_file() else {return Ok(false)};
		let mut source=std::fs::File::open(path.into_path().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
		std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
		let staging=folder.join(bundle::INCOMING);
		let mut target=std::fs::File::create(&staging).map_err(|e| e.to_string())?;
		let copied=std::io::copy(&mut std::io::Read::take(&mut source, BUNDLE_MAX + 1), &mut target);
		let fits=matches!(copied, Ok(n) if n <= BUNDLE_MAX);
		if !fits {
			let _ = std::fs::remove_file(&staging);
			return Err(if copied.is_err() {"bundle_copy"} else {"bundle_larger"}.into());
		}
		Ok(true)
	}).await.map_err(|e| e.to_string())??;
	if !staged {return Ok(None)}
	ask(&backend, Call::BundleReview).await.map(Some)
}

#[tauri::command]
async fn bundle_document(backend:State<'_, Arc<Backend>>, id:String)->Result<Value, String>{ask_branded(&backend, Call::BundleDocument{subscription:id}).await}

#[tauri::command]
async fn bundle_notices(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::BundleNotices).await}

#[tauri::command]
async fn bundle_close(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::BundleClose).await}

/// Installs the app part of the open bundle. The bytes come from the helper in pieces and are checked against its hash, then the updater checks them against their signature. A connection being set up blocks it. The helper goes only right before the installer runs, since that step cannot be undone, and the app restarts into the new version.
#[tauri::command]
async fn bundle_install(app:AppHandle, backend:State<'_, Arc<Backend>>)->Result<(), String>{
	let status=ask(&backend, Call::Status).await?;
	if status["status"]["state"].as_str()==Some("connecting") {return Err("tunnel_starting".into())}
	let staged=ask(&backend, Call::BundleApp).await?;
	let size=staged["size"].as_u64().unwrap_or_default();
	let mut bytes=Vec::with_capacity(size as usize);
	let mut hash=ring::digest::Context::new(&ring::digest::SHA256);
	while (bytes.len() as u64) < size {
		let at=bytes.len() as u64;
		let piece=ask(&backend, Call::BundleChunk{offset:at, len:bundle::CHUNK}).await?;
		let piece=base64::engine::general_purpose::STANDARD.decode(piece["data"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
		if piece.is_empty() {return Err("app_short".into())}
		hash.update(&piece);
		bytes.extend_from_slice(&piece);
	}
	let digest=hash.finish();
	if proto::hex(digest.as_ref()) != staged["sha256"].as_str().unwrap_or_default() {return Err("app_mismatch".into())}
	let target=format!("{}-{}", if cfg!(target_os="macos") {"darwin"} else {std::env::consts::OS}, std::env::consts::ARCH);
	let manifest=json!({"version": staged["version"], "platforms": {target: {"url": "https://invalid/", "signature": base64::engine::general_purpose::STANDARD.encode(staged["signature"].as_str().unwrap_or_default())}}});
	let update=app.updater().map_err(|e| format!("updater unavailable: {e}"))?.restore_update(manifest).map_err(|e| e.to_string())?.ok_or_else(|| "app_not_newer".to_string())?;
	backend.quit().await;
	tracing::info!("installing app part {} from a bundle", update.version);
	tokio::task::spawn_blocking(move || update.install(&bytes)).await.map_err(|e| e.to_string())?.map_err(|e| format!("update failed: {e}"))?;
	app.restart()
}

#[tauri::command]
async fn import_proceed(backend:State<'_, Arc<Backend>>, private:Option<Vec<String>>)->Result<Value, String>{ask_branded(&backend, Call::ImportProceed{private:private.unwrap_or_default()}).await}

#[tauri::command]
async fn import_keep(backend:State<'_, Arc<Backend>>, keep:bool)->Result<Value, String>{ask_branded(&backend, Call::ImportKeep{keep}).await}

#[tauri::command]
async fn import_cancel(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::ImportCancel).await}

/// The subscriptions and their connections, provider cards and branding included. `languages` are the UI's, best first.
#[tauri::command]
async fn library(backend:State<'_, Arc<Backend>>, languages:Vec<String>)->Result<Value, String>{ask_branded(&backend, Call::Library{languages}).await}

#[tauri::command]
async fn refresh(backend:State<'_, Arc<Backend>>, id:String, private:Option<Vec<String>>)->Result<Value, String>{ask_branded(&backend, Call::Refresh{subscription:id, private:private.unwrap_or_default()}).await}

#[tauri::command]
async fn remove(backend:State<'_, Arc<Backend>>, id:String)->Result<Value, String>{ask_branded(&backend, Call::Remove{subscription:id}).await}

/// Confirms or declines a subscription's backup update hosts and gives the library back. Nothing is fetched from a host before its yes.
#[tauri::command]
async fn answer_hosts(backend:State<'_, Arc<Backend>>, id:String, allow:Vec<String>, decline:Vec<String>)->Result<Value, String>{ask_branded(&backend, Call::AnswerHosts{subscription:id, allow, decline}).await}

/// Saves "Let apps reach devices on this network" for a subscription and gives the library back. It applies from the next connect.
#[tauri::command]
async fn set_lan(backend:State<'_, Arc<Backend>>, id:String, on:bool)->Result<Value, String>{ask_branded(&backend, Call::SetLan{subscription:id, on}).await}

/// Whether the transports in alpha are on, and turning them on or off. The window shows the warning and has the user confirm before it asks for on.
#[tauri::command]
async fn get_alpha(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::Alpha).await}

#[tauri::command]
async fn set_alpha(backend:State<'_, Arc<Backend>>, on:bool)->Result<Value, String>{ask(&backend, Call::SetAlpha{on}).await}

#[tauri::command]
async fn connect(app:AppHandle, backend:State<'_, Arc<Backend>>, subscription:String, profile:String, mut options:Options)->Result<Value, String>{
	tracing::info!("connect requested");
	// The kill switch is the app's setting: the window does not send it.
	options.kill_switch=load_settings(&app)?.kill_switch;
	ask(&backend, Call::Connect{subscription, profile, options}).await
}

/// Whether the Xray add-on can be had here and is installed, its release and the most its download can be.
#[tauri::command]
async fn xray_state(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::Xray).await}

/// Installs the add-on after the user's yes to the offer that `connect` gave. The window connects again when it is in.
#[tauri::command]
async fn xray_install(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::XrayInstall).await}

#[tauri::command]
async fn xray_remove(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::XrayRemove).await}

#[tauri::command]
async fn answer(backend:State<'_, Arc<Backend>>, yes:bool)->Result<Value, String>{ask(&backend, Call::Answer{yes}).await}

#[tauri::command]
async fn disconnect(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::Disconnect).await}

#[tauri::command]
async fn select_exit(backend:State<'_, Arc<Backend>>, tag:Option<String>)->Result<Value, String>{ask(&backend, Call::SelectExit{tag}).await}

#[tauri::command]
async fn status(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::Status).await}

#[tauri::command]
fn log_history()->Vec<String>{logbuf().lock().unwrap().iter().cloned().collect()}

/// Opens a provider link in the browser or mail app. Only http, https and mailto links the library has shown get through.
#[tauri::command]
fn open_link(app:AppHandle, url:String)->Result<(), String>{
	let scheme=tauri::Url::parse(&url).map_err(|_| "The link is not valid.".to_string())?.scheme().to_string();
	if !matches!(scheme.as_str(), "http"|"https"|"mailto") || (!view::PRIVACY_URLS.contains(&url.as_str()) && !linkset().lock().unwrap().contains(&url)){return Err("This is not one of the provider's links.".into())}
	app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_autostart(app:AppHandle)->Result<bool, String>{app.autolaunch().is_enabled().map_err(|e| e.to_string())}

#[tauri::command]
fn set_autostart(app:AppHandle, enabled:bool)->Result<(), String>{
	let manager=app.autolaunch();
	let done=if enabled{manager.enable()}else{manager.disable()};
	done.map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_update(app:AppHandle)->Result<UpdateInfo, String>{
	let current=app.package_info().version.to_string();
	let found=app.updater().map_err(|e| format!("updater unavailable: {e}"))?.check().await.map_err(|e| format!("update check failed: {e}"))?;
	match found{
		Some(u)=>{tracing::info!("update {} available", u.version); Ok(UpdateInfo{available:true, version:u.version.clone(), notes:u.body.clone().unwrap_or_default(), current})}
		None=>Ok(UpdateInfo{available:false, version:current.clone(), notes:String::new(), current}),
	}
}

#[tauri::command]
async fn install_update(app:AppHandle, backend:State<'_, Arc<Backend>>)->Result<(), String>{
	let update=app.updater().map_err(|e| format!("updater unavailable: {e}"))?.check().await.map_err(|e| format!("update check failed: {e}"))?.ok_or_else(|| "Already up to date".to_string())?;
	backend.quit().await; // the installer restarts the app and replaces the executable the helper runs from, so the helper goes first and restores routes and dns
	tracing::info!("installing update {}", update.version);
	let handle=app.clone();
	let mut downloaded=0usize;
	update.download_and_install(move |chunk, total|{
		downloaded+=chunk;
		let _=handle.emit("update-progress", serde_json::json!({"downloaded":downloaded, "total":total}));
	}, ||{}).await.map_err(|e| format!("update failed: {e}"))?;
	tracing::info!("update installed, restarting");
	app.restart()
}

fn settings_path(app:&AppHandle)->Result<PathBuf, String>{
	let dir=app.path().app_config_dir().map_err(|e| e.to_string())?;
	std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
	Ok(dir.join("settings.json"))
}

fn load_settings(app:&AppHandle)->Result<Settings, String>{
	let path=settings_path(app)?;
	Ok(std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default())
}

/// Title bar and the native fill behind the webview follow the UI theme, so resizing never shows the other theme's colour. The fills match --ground in app.css.
fn apply_theme(app:&AppHandle, theme:&str){
	let light=theme=="light";
	if let Some(w)=app.get_webview_window("main"){
		let _=w.set_theme(Some(if light{tauri::Theme::Light}else{tauri::Theme::Dark}));
		let _=w.set_background_color(Some(if light{tauri::window::Color(236, 239, 237, 255)}else{tauri::window::Color(17, 28, 33, 255)}));
	}
}

#[tauri::command]
async fn get_settings(app:AppHandle)->Result<Settings, String>{load_settings(&app)}

#[tauri::command]
async fn set_settings(app:AppHandle, settings:Settings)->Result<(), String>{
	let body=serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
	std::fs::write(settings_path(&app)?, body).map_err(|e| e.to_string())?;
	apply_theme(&app, &settings.theme);
	Ok(())
}

/// Brings the window back from the tray.
fn show(app:&AppHandle){
	if let Some(w)=app.get_webview_window("main"){let _=w.show(); let _=w.unminimize(); let _=w.set_focus();}
}

fn main(){
	let args:Vec<String>=std::env::args().collect();
	if args.get(1).map(String::as_str)==Some("--helper"){
		let after=|name:&str| args.iter().position(|a| a==name).and_then(|i| args.get(i+1));
		let owner=after("--uid").or_else(|| after("--sid")).map(String::as_str);
		std::process::exit(after("--dir").map_or(2, |d| helper::main(&PathBuf::from(d), owner)));
	}
	let _=START.set(Instant::now());
	tracing_subscriber::registry().with(LogLayer{sink:push_log, helper:false}).init();
	tauri::Builder::default()
		// Has to be the first plugin: a second launch only raises the window of the one hiding in the tray.
		.plugin(tauri_plugin_single_instance::init(|app, _, _| show(app)))
		.plugin(tauri_plugin_process::init())
		.plugin(tauri_plugin_autostart::Builder::new().build())
		.plugin(tauri_plugin_opener::init())
		.plugin(tauri_plugin_dialog::init())
		// Closing the window keeps the tunnel up and leaves the app in the tray; Quit in the tray menu is the real exit.
		.on_window_event(|w, e| if let tauri::WindowEvent::CloseRequested{api, ..}=e{api.prevent_close(); let _=w.hide();})
		.invoke_handler(tauri::generate_handler![import_open, import_qr, scan_frame, import_proceed, import_keep, import_cancel, share_link, share_file, bundle_pick, bundle_document, bundle_notices, bundle_close, bundle_install, library, refresh, remove, answer_hosts, set_lan, xray_state, xray_install, xray_remove, get_alpha, set_alpha, connect, answer, disconnect, select_exit, status, log_history, check_update, install_update, get_settings, set_settings, open_link, get_autostart, set_autostart])
		.setup(|app|{
			let _=HANDLE.set(app.handle().clone());
			let (handle, dir)=(app.handle().clone(), app.path().app_config_dir()?.join("helper"));
			app.manage(Arc::new(Backend::new(dir, Arc::new(move |out| forward(&handle, out)))));
			// tauri.conf.json starts the window dark; only a saved light theme needs correcting here.
			if let Ok(s)=load_settings(app.handle()){if s.theme=="light"{apply_theme(app.handle(), "light")}}
			// Shrinks the default 760px height onto short laptop screens; the work area already excludes the taskbar. Any failure keeps the default.
			if let Some(w)=app.get_webview_window("main"){
				if let (Ok(Some(m)), Ok(outer), Ok(inner))=(w.current_monitor(), w.outer_size(), w.inner_size()){
					let fit=m.work_area().size.height.saturating_sub(outer.height-inner.height).max((420.0*m.scale_factor()) as u32);
					if outer.height>m.work_area().size.height&&fit<inner.height{let _=w.set_size(tauri::PhysicalSize::new(inner.width, fit)); let _=w.center();}
				}
			}
			let menu=Menu::with_items(app, &[&MenuItem::with_id(app, "open", "Open Veilway", true, None::<&str>)?, &MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?])?;
			let mut tray=TrayIconBuilder::with_id("main").tooltip("Veilway").menu(&menu).show_menu_on_left_click(false)
				.on_menu_event(|app, e| match e.id.as_ref(){
					"open"=>show(app),
					"quit"=>{
						let app=app.clone();
						// Tear the tunnel down first so routes and dns are restored before the process goes away.
						tauri::async_runtime::spawn(async move{app.state::<Arc<Backend>>().quit().await; app.exit(0);});
					}
					_=>{}
				})
				.on_tray_icon_event(|tray, e| if let TrayIconEvent::Click{button:MouseButton::Left, button_state:MouseButtonState::Up, ..}=e{show(tray.app_handle())});
			if let Some(icon)=app.default_window_icon(){tray=tray.icon(icon.clone());}
			tray.build(app)?;
			#[cfg(desktop)]
			app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
			tracing::info!("client ready");
			Ok(())
		})
		.run(tauri::generate_context!())
		.expect("failed to start the tauri application");
}
