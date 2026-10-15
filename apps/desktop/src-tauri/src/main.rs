#![cfg_attr(not(debug_assertions), windows_subsystem="windows")]
//! Tauri shell around `veilway-engine` and the platform layer. The window is unprivileged and never holds a key: the engine, the vault and the system changes live in a helper (`helper.rs`, this same executable started with `--helper` and raised once through the system's prompt), and the commands below pass the UI's asks to it over `link.rs`. The UI is static HTML in ../ui.
mod helper;
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
use serde_json::Value;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::UpdaterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static HANDLE:OnceLock<AppHandle>=OnceLock::new();
static LOGS:OnceLock<Mutex<VecDeque<String>>>=OnceLock::new();
const LOG_KEEP:usize=200;

fn logbuf()->&'static Mutex<VecDeque<String>>{LOGS.get_or_init(|| Mutex::new(VecDeque::new()))}

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
struct Settings{auto_update:bool, #[serde(default="dark")] theme:String}

impl Default for Settings{fn default()->Self{Settings{auto_update:true, theme:dark()}}}

fn dark()->String{"dark".to_string()}

/// What the helper says by itself becomes events for the UI: `status`, `question` (a yes or no the engine needs, answered with `answer`), `ended` and `log`.
fn forward(app:&AppHandle, out:Out){
	match out{
		Out::Status(view)=>{let _=app.emit("status", view);}
		Out::Question{text}=>{let _=app.emit("question", text);}
		Out::Ended{error, kept}=>{let _=app.emit("ended", serde_json::json!({"error":error, "kept":kept}));}
		Out::Log{line}=>push_log(line),
		Out::Reply{..}=>{}
	}
}

async fn ask(backend:&State<'_, Arc<Backend>>, call:Call)->Result<Value, String>{backend.call(call).await}

/// Step 1 of an import, from a link or a subscription file. Returns what the user is asked about first; nothing is sent anywhere until `import_proceed`.
#[tauri::command]
async fn import_open(backend:State<'_, Arc<Backend>>, source:Source)->Result<Value, String>{ask(&backend, Call::ImportOpen{source}).await}

/// The same from a picture with a QR code in it (base64 of the file, as pasted or picked). The picture is read here, in the unprivileged process.
#[tauri::command]
async fn import_qr(backend:State<'_, Arc<Backend>>, data:String)->Result<Value, String>{
	let bytes=base64::engine::general_purpose::STANDARD.decode(data.trim()).map_err(|_| "The picture could not be read.".to_string())?;
	let text=tokio::task::spawn_blocking(move || qr::decode(&bytes)).await.map_err(|e| e.to_string())??;
	ask(&backend, Call::ImportOpen{source:Source::Link{text}}).await
}

#[tauri::command]
async fn import_proceed(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::ImportProceed).await}

#[tauri::command]
async fn import_keep(backend:State<'_, Arc<Backend>>, keep:bool)->Result<Value, String>{ask(&backend, Call::ImportKeep{keep}).await}

#[tauri::command]
async fn import_cancel(backend:State<'_, Arc<Backend>>)->Result<Value, String>{ask(&backend, Call::ImportCancel).await}

/// The subscriptions and their connections, provider cards and branding included. `languages` are the UI's, best first.
#[tauri::command]
async fn library(backend:State<'_, Arc<Backend>>, languages:Vec<String>)->Result<Value, String>{ask(&backend, Call::Library{languages}).await}

#[tauri::command]
async fn refresh(backend:State<'_, Arc<Backend>>, id:String)->Result<Value, String>{ask(&backend, Call::Refresh{subscription:id}).await}

#[tauri::command]
async fn remove(backend:State<'_, Arc<Backend>>, id:String)->Result<Value, String>{ask(&backend, Call::Remove{subscription:id}).await}

#[tauri::command]
async fn connect(backend:State<'_, Arc<Backend>>, subscription:String, profile:String, options:Options)->Result<Value, String>{
	tracing::info!("connect requested");
	ask(&backend, Call::Connect{subscription, profile, options}).await
}

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
		let dir=args.iter().position(|a| a=="--dir").and_then(|i| args.get(i+1)).map(PathBuf::from);
		std::process::exit(dir.map_or(2, |d| helper::main(&d)));
	}
	let _=START.set(Instant::now());
	tracing_subscriber::registry().with(LogLayer(push_log)).init();
	tauri::Builder::default()
		// Has to be the first plugin: a second launch only raises the window of the one hiding in the tray.
		.plugin(tauri_plugin_single_instance::init(|app, _, _| show(app)))
		.plugin(tauri_plugin_process::init())
		// Closing the window keeps the tunnel up and leaves the app in the tray; Quit in the tray menu is the real exit.
		.on_window_event(|w, e| if let tauri::WindowEvent::CloseRequested{api, ..}=e{api.prevent_close(); let _=w.hide();})
		.invoke_handler(tauri::generate_handler![import_open, import_qr, import_proceed, import_keep, import_cancel, library, refresh, remove, connect, answer, disconnect, select_exit, status, log_history, check_update, install_update, get_settings, set_settings])
		.setup(|app|{
			let _=HANDLE.set(app.handle().clone());
			let (handle, dir)=(app.handle().clone(), app.path().app_config_dir()?.join("helper"));
			app.manage(Arc::new(Backend::new(dir, Arc::new(move |out| forward(&handle, out)))));
			// tauri.conf.json starts the window dark; only a saved light theme needs correcting here.
			if let Ok(s)=load_settings(app.handle()){if s.theme=="light"{apply_theme(app.handle(), "light")}}
			// Shrinks the default 640px height onto short laptop screens; the work area already excludes the taskbar. Any failure keeps the default.
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
