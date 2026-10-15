//! The two-way bridge to the Kotlin side. Kotlin calls the `Native` functions below (the VpnService starts and stops the connection and tells which networks the device is on); Rust calls the static functions of the Kotlin `Bridge` object (`establish` builds the VPN interface and returns its descriptor, `protect` keeps a socket out of the tunnel, `wrap` and `unwrap` are the Keystore). The VpnService owns the interface; this process only reads and writes the descriptor it is handed.
//!
//! The class is looked up in `Native.init`, which Kotlin always calls first on a Java thread, because a thread Rust starts cannot find an app class by name. A call from Rust to Kotlin that fails or leaves an exception behind is an error here and never a crash.
use crate::host;
use crate::proto::{Call, Options};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JObjectArray, JString, JValue};
use jni::sys::{jboolean, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use socket2::SockRef;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, OnceLock};
use tokio::sync::watch;
use veilway_proto::subscription::payload::Network;
use veilway_transport::Hook;

const BRIDGE: &str = "io/github/veilwayproject/app/Bridge";
static VM: OnceLock<JavaVM> = OnceLock::new();
static CLASS: OnceLock<GlobalRef> = OnceLock::new();

/// The device's own networks as the system last told, and a description of them that the engine hashes into its memory of what worked where. `cellular` is whether the network the phone's packets leave by is mobile data (or the system could not tell).
#[derive(Debug, Clone, PartialEq)]
pub struct Own {
	pub networks: Vec<Network>,
	pub description: String,
	pub cellular: bool,
}

static OWN: LazyLock<watch::Sender<Own>> = LazyLock::new(|| watch::channel(Own {networks: Vec::new(), description: "android:none".into(), cellular: false}).0);

pub fn own() -> watch::Receiver<Own> {OWN.subscribe()}

fn with_bridge<T>(call: impl FnOnce(&mut JNIEnv, &JClass) -> jni::errors::Result<T>) -> Option<T> {
	let (vm, class) = (VM.get()?, CLASS.get()?);
	let mut env = vm.attach_current_thread().ok()?;
	// SAFETY: the reference is a global one held for the life of the process, and `JClass` does not free what it wraps.
	let class = unsafe {JClass::from_raw(class.as_obj().as_raw())};
	let result = call(&mut env, &class);
	if env.exception_check().unwrap_or(true) {
		let _ = env.exception_clear();
		return None;
	}
	result.ok()
}

fn strings<'a>(env: &mut JNIEnv<'a>, list: &[String]) -> jni::errors::Result<JObjectArray<'a>> {
	let array = env.new_object_array(list.len() as i32, "java/lang/String", JObject::null())?;
	for (index, item) in list.iter().enumerate() {
		let text = env.new_string(item)?;
		env.set_object_array_element(&array, index as i32, text)?;
	}
	Ok(array)
}

fn text(env: &mut JNIEnv, value: &JString) -> String {env.get_string(value).map(String::from).unwrap_or_default()}

/// Builds the VPN interface and returns its descriptor, which this process now owns. `None` when the system refused: the permission was withdrawn, or another VPN took over.
pub fn establish(addresses: &[String], dns: &[String], routes: &[String], mtu: u16) -> Option<RawFd> {
	let fd = with_bridge(|env, class| {
		let (addresses, dns, routes) = (strings(env, addresses)?, strings(env, dns)?, strings(env, routes)?);
		env.call_static_method(class, "establish", "([Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;I)I", &[JValue::Object(&addresses), JValue::Object(&dns), JValue::Object(&routes), JValue::Int(i32::from(mtu))])?.i()
	})?;
	(fd >= 0).then_some(fd)
}

/// Keeps a socket out of the VPN, so that the engine's own connection to the node does not loop back into the tunnel (invariant 24).
pub fn protect(fd: RawFd) -> bool {with_bridge(|env, class| env.call_static_method(class, "protect", "(I)Z", &[JValue::Int(fd)])?.z()).unwrap_or(false)}

/// The hook the engine runs on every socket it makes, before it connects. A socket the system will not protect is never connected.
pub fn protect_hook() -> Hook {
	Arc::new(|socket: SockRef<'_>| if protect(socket.as_raw_fd()) {Ok(())} else {Err(std::io::Error::other("the system would not keep this socket out of the VPN"))})
}

fn through_keystore(name: &str, bytes: &[u8]) -> Option<Vec<u8>> {
	with_bridge(|env, class| {
		let input = env.byte_array_from_slice(bytes)?;
		let output = env.call_static_method(class, name, "([B)[B", &[JValue::Object(&input)])?.l()?;
		if output.is_null() {return Ok(None)}
		env.convert_byte_array(JByteArray::from(output)).map(Some)
	}).flatten()
}

/// Encrypts with the AES-GCM key that never leaves the Android Keystore.
pub fn wrap(plain: &[u8]) -> Option<Vec<u8>> {through_keystore("wrap", plain)}

pub fn unwrap(sealed: &[u8]) -> Option<Vec<u8>> {through_keystore("unwrap", sealed)}

/// Tells the notification what the tunnel is doing.
pub fn state(state: &str) {
	let _ = with_bridge(|env, class| {
		let state = env.new_string(state)?;
		env.call_static_method(class, "state", "(Ljava/lang/String;)V", &[JValue::Object(&state)]).map(|_| ())
	});
}

/// The connection ended, for the user or on its own: the service stops, and says why when it was not the user.
pub fn ended(error: Option<&str>) {
	let _ = with_bridge(|env, class| {
		let error = match error {Some(error) => JObject::from(env.new_string(error)?), None => JObject::null()};
		env.call_static_method(class, "ended", "(Ljava/lang/String;)V", &[JValue::Object(&error)]).map(|_| ())
	});
}

fn answer<'a>(env: &mut JNIEnv<'a>, value: Result<serde_json::Value, String>) -> JString<'a> {
	match value {
		Ok(_) => JString::from(JObject::null()),
		Err(error) => env.new_string(error).unwrap_or_else(|_| JString::from(JObject::null())),
	}
}

#[no_mangle]
pub extern "system" fn Java_io_github_veilwayproject_app_Native_init<'a>(mut env: JNIEnv<'a>, _: JClass<'a>, dir: JString<'a>) -> jboolean {
	if VM.get().is_none() {
		let (Ok(vm), Ok(class)) = (env.get_java_vm(), env.find_class(BRIDGE)) else {return JNI_FALSE};
		let Ok(class) = env.new_global_ref(class) else {return JNI_FALSE};
		let _ = (VM.set(vm), CLASS.set(class));
	}
	let dir = text(&mut env, &dir);
	match host::init(&dir) {
		Ok(_) => JNI_TRUE,
		Err(error) => {
			tracing::error!("the client could not start: {error}");
			JNI_FALSE
		}
	}
}

/// Starts a connection. Null when it was started, else the words for the user.
#[no_mangle]
pub extern "system" fn Java_io_github_veilwayproject_app_Native_connect<'a>(mut env: JNIEnv<'a>, _: JClass<'a>, subscription: JString<'a>, profile: JString<'a>, options: JString<'a>) -> JString<'a> {
	let (subscription, profile, options) = (text(&mut env, &subscription), text(&mut env, &profile), text(&mut env, &options));
	let options: Options = serde_json::from_str(&options).unwrap_or_default();
	let result = match host::get() {
		Some(host) => host.runtime.block_on(host.core.call(Call::Connect {subscription, profile, options})),
		None => Err("The client is not running.".into()),
	};
	answer(&mut env, result)
}

/// Stops the connection the clean way. Blocks until it ended, so Kotlin calls it off the main thread.
#[no_mangle]
pub extern "system" fn Java_io_github_veilwayproject_app_Native_disconnect<'a>(mut env: JNIEnv<'a>, _: JClass<'a>) -> JString<'a> {
	let result = match host::get() {
		Some(host) => host.runtime.block_on(host.core.call(Call::Disconnect)),
		None => Ok(serde_json::Value::Null),
	};
	answer(&mut env, result)
}

/// Whether the system's always-on VPN blocks the internet without the tunnel. Kotlin says it when the service starts.
#[no_mangle]
pub extern "system" fn Java_io_github_veilwayproject_app_Native_lockdown(_: JNIEnv, _: JClass, on: jboolean) {
	host::LOCKDOWN.store(on == JNI_TRUE, Ordering::Relaxed);
}

/// The networks the device is on, as `address/prefix` strings: its addresses on networks that are not the VPN, and the gateway, and whether they are mobile data. The engine skips an address of the profile that lies inside one of them, and reconnects when the networks change.
#[no_mangle]
pub extern "system" fn Java_io_github_veilwayproject_app_Native_networkChanged<'a>(mut env: JNIEnv<'a>, _: JClass<'a>, description: JString<'a>, networks: JObjectArray<'a>, cellular: jboolean) {
	let description = text(&mut env, &description);
	let count = env.get_array_length(&networks).unwrap_or(0);
	let mut found = Vec::new();
	for index in 0..count {
		let Ok(item) = env.get_object_array_element(&networks, index) else {continue};
		let item = text(&mut env, &JString::from(item));
		let Some((ip, prefix)) = item.split_once("/") else {continue};
		if let Some(network) = ip.parse().ok().zip(prefix.parse().ok()).and_then(|(ip, prefix)| Network::new(ip, prefix)).filter(|network| !found.contains(network)) {found.push(network)}
	}
	OWN.send_if_modified(|own| {
		let next = Own {networks: found, description, cellular: cellular == JNI_TRUE};
		let changed = *own != next;
		*own = next;
		changed
	});
}
