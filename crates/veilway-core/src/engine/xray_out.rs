//! Xray outbounds (`outbounds[]` of type `xray`): another provider's VLESS, VMess, Trojan or Shadowsocks server as the carrier of a `netstack` exit.
//! They run in the add-on's one Xray process, next to its inbounds (`xray`), and not in one of their own: the host serves one lease at a time and keeps one set of capabilities, and a second process would be a second thing to start, pin, restart and cap. The price is that a change of an outbound restarts Xray, and with it the connections of the Xray inbounds, which come back with the next connect.
//! For each outbound the node writes a `trojan` inbound that listens on a Unix socket in the folder the node and Xray share through a group (`xray_dir`), with a path and a 256 bit password made new for each start, routed to that outbound alone. The node connects to the socket, checks that whoever holds it is Xray's user (`SO_PEERCRED`) before it sends a byte, and speaks Trojan: CONNECT for TCP and one UDP stream for each UDP flow (`xray_trojan`, `flows::dial_conn`). So the exit, the gate, the rules, the quotas and the counters are the ones every flow already meets, nothing is listening on a network address, and UDP has the same login as TCP.
//! A socket and a password live in a `Hop` that the supervisor in `xray` fills in once Xray is up and the socket is there and is Xray's, and empties before it stops Xray. A flow that finds no endpoint fails there, with the reason, and the exit is not working; nothing falls back to a direct connection.
//! Where there is no add-on host (every system but Linux) there is no Xray outbound: the hop says so.
use super::wg_out::WgOuts;
use super::{dns, flows, upstream, Shared};
use crate::config::{self, Host, Store, XhttpMode, XrayFlow, XrayOutboundProtocol, XraySecurity, XrayTransport};
use ipnet::IpNet;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// How long one server of `dns.servers` is given to answer a lookup of a provider's name.
const ASK: Duration = Duration::from_secs(3);
/// How often the names are looked up again, and how soon after one that did not resolve.
const RECHECK: Duration = Duration::from_secs(900);
const RETRY: Duration = Duration::from_secs(30);

/// Where one Xray outbound is dialed: the socket, the user that must hold it, and the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Reach {pub path: PathBuf, pub uid: u32, pub password: String}

enum State {Down(String), Up(Reach)}

/// Where one Xray outbound is reached right now, or why it cannot be. The password is a secret, so this has no `Debug`.
pub struct Hop(Mutex<State>);

impl Hop {
	pub fn reach(&self) -> Result<Reach, String> {
		match &*self.0.lock().unwrap_or_else(|e| e.into_inner()) {
			State::Up(reach) => Ok(reach.clone()),
			State::Down(why) => Err(why.clone()),
		}
	}

	pub fn reason(&self) -> Option<String> {self.reach().err()}

	pub(super) fn up(&self, reach: Reach) {*self.0.lock().unwrap_or_else(|e| e.into_inner()) = State::Up(reach)}

	pub(super) fn down(&self, why: &str) {*self.0.lock().unwrap_or_else(|e| e.into_inner()) = State::Down(why.to_string())}
}

/// The hops by the tag of their outbound, and the WireGuard outbounds, which are carriers that the engine holds the same way. One registry lives as long as the engine, so a reload keeps the hop of an outbound that stays.
#[derive(Default)]
pub struct Hops {hops: Mutex<HashMap<String, Arc<Hop>>>, pub wireguard: WgOuts}

impl Hops {
	pub fn get(&self, tag: &str) -> Arc<Hop> {self.hops.lock().unwrap_or_else(|e| e.into_inner()).entry(tag.to_string()).or_insert_with(|| Arc::new(Hop(Mutex::new(State::Down("the xray add-on has not started yet".to_string()))))).clone()}

	/// A registry whose WireGuard outbounds ask `is_local` which addresses are the node's own.
	pub fn new(is_local: fn(IpAddr) -> bool) -> Hops {Hops {hops: Mutex::default(), wireguard: WgOuts::new(is_local)}}

	/// Every hop down at once, for the moment before Xray is stopped or started again.
	pub(super) fn all_down(&self, why: &str) {for hop in self.hops.lock().unwrap_or_else(|e| e.into_inner()).values() {hop.down(why)}}
}

/// One outbound as the add-on's document has it: the socket and password of its inbound, and the address the provider's server is dialed at, which is one the node looked up and checked.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Wire {pub tag: String, pub path: PathBuf, pub password: String, pub address: IpAddr}

/// A socket path and a password for outbound number `at` of one start of Xray: the path holds a name made for the start, and the password is 32 bytes from the system generator as hex.
pub(super) fn credentials(dir: &Path, start: &str, at: usize) -> std::io::Result<(PathBuf, String)> {
	let mut raw = [0u8; 32];
	SystemRandom::new().fill(&mut raw).map_err(|_| std::io::Error::other("the system has no random source"))?;
	Ok((dir.join(format!("o{start}-{at}.sock")), raw.iter().map(|byte| format!("{byte:02x}")).collect()))
}

/// A name for one start of Xray: 8 bytes from the system generator as hex.
pub(super) fn start_name() -> std::io::Result<String> {
	let mut raw = [0u8; 8];
	SystemRandom::new().fill(&mut raw).map_err(|_| std::io::Error::other("the system has no random source"))?;
	Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// What the lookups have found, by the tag of the outbound with its server: an address to dial, or why there is none, and since when. An address stays until the lookup stops giving it, so a resolver that flaps costs no restart of Xray.
#[derive(Default)]
pub(super) struct Names {found: Mutex<HashMap<String, (config::HostPort, Result<IpAddr, String>, Instant)>>, pub changed: Notify}

impl Names {
	pub(super) fn get(&self, tag: &str, server: &config::HostPort) -> Option<Result<IpAddr, String>> {self.held(tag, server).map(|(found, _)| found)}

	fn held(&self, tag: &str, server: &config::HostPort) -> Option<(Result<IpAddr, String>, Instant)> {self.found.lock().unwrap_or_else(|e| e.into_inner()).get(tag).filter(|(was, ..)| was == server).map(|(_, found, since)| (found.clone(), *since))}
}

/// Whether `path` is a socket that `uid` owns and that has the mode Xray gives it once it is ready (660, which it sets after it binds), which is how an outbound's socket shows that Xray made it. The error is why the folder could not be looked at: a permission one says the node is not in Xray's group.
#[cfg(unix)]
pub(super) fn held(path: &Path, uid: u32) -> Result<bool, std::io::ErrorKind> {
	match std::fs::symlink_metadata(path) {
		Ok(meta) => Ok(meta.file_type().is_socket() && meta.uid() == uid && meta.mode() & 0o777 == 0o660),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
		Err(e) => Err(e.kind()),
	}
}

#[cfg(not(unix))]
pub(super) fn held(_: &Path, _: u32) -> Result<bool, std::io::ErrorKind> {Ok(false)}

/// A DNS question of `qtype` for `name`, the way the node asks its own servers.
fn question(name: &str, qtype: u16, id: u16) -> Vec<u8> {
	let mut message = [&id.to_be_bytes()[..], &[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]].concat();
	for label in name.split('.') {
		message.push(label.len() as u8);
		message.extend_from_slice(label.as_bytes());
	}
	message.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
	message
}

/// The addresses of `name`, from the first server of `dns.servers` that answers it with some, which the node asks itself over UDP and not through the host's resolver. Each query has an id of its own from the system generator, and an answer counts only for the question that was asked (the name and the type) and only with addresses of the type asked for. None when no server did.
async fn lookup(name: &str, servers: &[std::net::SocketAddr]) -> Option<Vec<IpAddr>> {
	for server in servers {
		let mut ids = [0u8; 4];
		SystemRandom::new().fill(&mut ids).ok()?;
		let asked = [(1u16, question(name, 1, u16::from_be_bytes([ids[0], ids[1]]))), (28, question(name, 28, u16::from_be_bytes([ids[2], ids[3]])))];
		let (a, aaaa) = tokio::join!(tokio::time::timeout(ASK, flows::ask_udp(None, None, *server, &asked[0].1)), tokio::time::timeout(ASK, flows::ask_udp(None, None, *server, &asked[1].1)));
		let mut found = Vec::new();
		for ((qtype, _), answer) in asked.iter().zip([a, aaaa]) {
			let Some(response) = answer.ok().and_then(|answer| answer.ok()).and_then(|answer| dns::response(&answer)) else {continue};
			if response.rcode != 0 || response.truncated || !response.question.as_ref().is_some_and(|question| question.qtype == *qtype && question.name.as_deref().is_some_and(|asked| asked.eq_ignore_ascii_case(name))) {continue}
			found.extend(response.addresses.iter().map(|(address, _)| *address).filter(|address| address.is_ipv4() == (*qtype == 1)));
		}
		if !found.is_empty() {return Some(found)}
	}
	None
}

/// Keeps `names` up to date for the Xray outbounds of the config in force: a lookup at once and then every `RECHECK`, every `RETRY` while one has no address, and again when the config changes. The supervisor does none of this itself, so it keeps watching Xray while a resolver is slow.
/// A server that is an address is checked and kept as it is. For a name, the address stays while the lookup still gives it, and changes only when it is no longer among the answers. A lookup that fails changes nothing.
pub(super) async fn watch(shared: Arc<Shared>, store: Arc<Store>, names: Arc<Names>) {
	let mut changes = store.subscribe();
	loop {
		let config = changes.borrow_and_update().config.clone();
		let pools: Vec<(IpNet, usize)> = config.inbounds.iter().enumerate().flat_map(|(at, inbound)| inbound.address.iter().map(move |net| (net.0, at))).collect();
		let servers: Vec<std::net::SocketAddr> = config.dns.servers.iter().map(|server| server.0).collect();
		let (mut next, mut moved, mut deferred) = (HashMap::new(), false, false);
		for outbound in &config.outbounds {
			let config::Outbound::Xray {tag, server, allow_private, ..} = outbound else {continue};
			let (allow, was) = (*allow_private == Some(true), names.held(tag, server));
			let found: Option<Vec<IpAddr>> = match &server.host {
				Host::Ip(ip) => Some(vec![*ip]),
				Host::Name(name) => lookup(name, &servers).await,
			};
			let (current, since) = (was.as_ref().and_then(|(was, _)| was.as_ref().ok().copied()), was.as_ref().map(|(_, since)| *since));
			let current = current.filter(|ip| upstream::forbidden(*ip, &pools, shared.is_local, allow).is_none());
			// An address in use is given up only for another that is allowed, and not more often than every `RETRY`; an answer with nothing allowed in it, like one that did not come, changes nothing.
			let now = match (found, current) {
				(Some(found), current) => {
					let allowed: Vec<IpAddr> = found.into_iter().filter(|ip| upstream::forbidden(*ip, &pools, shared.is_local, allow).is_none()).collect();
					match (allowed.first().copied(), current) {
						(None, Some(current)) => Ok(current),
						(Some(_), Some(current)) if allowed.contains(&current) => Ok(current),
						(Some(_), Some(current)) if since.is_some_and(|since| since.elapsed() < RETRY) => {
							deferred = true;
							Ok(current)
						}
						(Some(first), _) => Ok(first),
						(None, None) => Err("the server gives no address the node may dial: loopback, link-local, one of the node's own or an inbound's, or private while `allow_private` is off".to_string()),
					}
				}
				(None, Some(current)) => Ok(current),
				(None, None) => Err("the name of the server does not resolve".to_string()),
			};
			let kept = was.filter(|(was, _)| *was == now).map(|(_, since)| since);
			if kept.is_none() {moved = true}
			next.insert(tag.clone(), (server.clone(), now, kept.unwrap_or_else(Instant::now)));
		}
		{
			let mut held = names.found.lock().unwrap_or_else(|e| e.into_inner());
			moved |= held.len() != next.len();
			*held = next.clone();
		}
		if moved {names.changed.notify_one()}
		let wait = if deferred || next.values().any(|(_, found, _)| found.is_err()) {RETRY} else {RECHECK};
		tokio::select! {
			_ = tokio::time::sleep(wait) => {}
			r = changes.changed() => if r.is_err() {return},
		}
	}
}

/// The Trojan inbound on the socket of `wire`, and the outbound it is routed to. The document is built with the JSON writer, from fields that validation has checked, and has no key the code does not name.
/// A server that is a name has its address in the document, so Xray resolves nothing, and the name stands for the SNI, the `Host` of a WebSocket, HTTP upgrade or XHTTP request and the authority of a gRPC one wherever the config gives none.
pub(super) fn parts(outbound: &config::Outbound, wire: &Wire) -> Option<(Value, Value)> {
	let config::Outbound::Xray {server, protocol, id, password, flow, cipher, transport, security, ..} = outbound else {return None};
	let named = match &server.host {Host::Name(name) => Some(name.clone()), Host::Ip(_) => None};
	let (address, port) = (wire.address.to_string(), server.port);
	let secret = |secret: &Option<config::Secret<String>>| secret.as_ref().map(|secret| secret.expose().clone()).unwrap_or_default();
	let settings = match protocol {
		XrayOutboundProtocol::Vless => json!({"vnext": [{"address": address, "port": port, "users": [{"id": secret(id), "encryption": "none", "flow": if flow == &Some(XrayFlow::Vision) {"xtls-rprx-vision"} else {""}}]}]}),
		XrayOutboundProtocol::Vmess => json!({"vnext": [{"address": address, "port": port, "users": [{"id": secret(id), "alterId": 0, "security": cipher.as_deref().unwrap_or("auto")}]}]}),
		XrayOutboundProtocol::Trojan => json!({"servers": [{"address": address, "port": port, "password": secret(password)}]}),
		XrayOutboundProtocol::Shadowsocks => json!({"servers": [{"address": address, "port": port, "method": cipher.as_deref().unwrap_or_default(), "password": secret(password)}]}),
	};
	let host = |given: &Option<String>| given.clone().or_else(|| named.clone());
	let mut stream = match transport {
		None | Some(XrayTransport::Tcp {}) => json!({"network": "tcp", "tcpSettings": {"header": {"type": "none"}}}),
		Some(XrayTransport::Ws {path, host: given}) => {
			let mut ws = json!({"path": path.as_deref().unwrap_or("/")});
			if let Some(host) = host(given) {ws["headers"] = json!({"Host": host})}
			json!({"network": "ws", "wsSettings": ws})
		}
		Some(XrayTransport::Grpc {service, authority}) => {
			let mut grpc = json!({"serviceName": service.as_deref().unwrap_or_default(), "multiMode": false});
			if let Some(authority) = host(authority) {grpc["authority"] = json!(authority)}
			json!({"network": "grpc", "grpcSettings": grpc})
		}
		Some(XrayTransport::Httpupgrade {path, host: given}) => {
			let mut upgrade = json!({"path": path.as_deref().unwrap_or("/")});
			if let Some(host) = host(given) {upgrade["host"] = json!(host)}
			json!({"network": "httpupgrade", "httpupgradeSettings": upgrade})
		}
		Some(XrayTransport::Xhttp {path, host: given, mode}) => {
			let mut xhttp = json!({"path": path.as_deref().unwrap_or("/"), "mode": match mode {None | Some(XhttpMode::Auto) => "auto", Some(XhttpMode::PacketUp) => "packet-up", Some(XhttpMode::StreamUp) => "stream-up", Some(XhttpMode::StreamOne) => "stream-one"}});
			if let Some(host) = host(given) {xhttp["host"] = json!(host)}
			json!({"network": "xhttp", "xhttpSettings": xhttp})
		}
	};
	match security {
		None | Some(XraySecurity::Off {}) => stream["security"] = json!("none"),
		Some(XraySecurity::Tls {server_name, alpn, fingerprint}) => {
			let mut tls = json!({"fingerprint": fingerprint.as_deref().unwrap_or("chrome")});
			if let Some(name) = host(server_name) {tls["serverName"] = json!(name)}
			if let Some(alpn) = alpn {tls["alpn"] = json!(alpn)}
			stream["security"] = json!("tls");
			stream["tlsSettings"] = tls;
		}
		Some(XraySecurity::Reality {server_name, public_key, short_id, fingerprint}) => {
			stream["security"] = json!("reality");
			stream["realitySettings"] = json!({"serverName": server_name, "fingerprint": fingerprint.as_deref().unwrap_or("chrome"), "publicKey": public_key, "shortId": short_id.as_deref().unwrap_or_default()});
		}
	}
	let protocol = match protocol {XrayOutboundProtocol::Vless => "vless", XrayOutboundProtocol::Vmess => "vmess", XrayOutboundProtocol::Trojan => "trojan", XrayOutboundProtocol::Shadowsocks => "shadowsocks"};
	Some((
		json!({"tag": format!("out-{}", wire.tag), "listen": format!("{},0660", wire.path.display()), "protocol": "trojan", "settings": {"clients": [{"password": wire.password}]}, "streamSettings": {"network": "tcp"}, "sniffing": {"enabled": false}}),
		json!({"tag": format!("via-{}", wire.tag), "protocol": protocol, "settings": settings, "streamSettings": stream}),
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn outbound(extra: Value) -> config::Outbound {
		let mut document = json!({"type": "xray", "tag": "up", "protocol": "vless", "server": "provider.example:443", "id": "3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c", "security": {"type": "tls"}});
		document.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		serde_json::from_value(document).unwrap()
	}

	fn wire() -> Wire {Wire {tag: "up".to_string(), path: PathBuf::from("/run/veilway-xray-out/oabc-0.sock"), password: "p".repeat(64), address: "93.184.216.34".parse().unwrap()}}

	#[test]
	fn a_trojan_inbound_on_a_socket_is_routed_to_the_outbound_and_the_server_is_dialed_by_address() {
		let (inbound, out) = parts(&outbound(json!({})), &wire()).unwrap();
		assert_eq!((inbound["listen"].as_str(), inbound["protocol"].as_str(), inbound.get("port")), (Some("/run/veilway-xray-out/oabc-0.sock,0660"), Some("trojan"), None));
		assert_eq!(inbound["settings"]["clients"][0]["password"], "p".repeat(64));
		assert_eq!(out["settings"]["vnext"][0]["address"], "93.184.216.34");
		assert_eq!(out["streamSettings"]["tlsSettings"]["serverName"], "provider.example");
		assert!(out["streamSettings"]["tlsSettings"].get("allowInsecure").is_none());
	}

	#[test]
	fn every_protocol_and_stream_has_the_shape_xray_reads() {
		let key = "A".repeat(43);
		let cases = [
			(json!({"flow": "xtls-rprx-vision"}), "/settings/vnext/0/users/0/flow", json!("xtls-rprx-vision")),
			(json!({"protocol": "vmess", "cipher": "aes-128-gcm", "security": {"type": "none"}}), "/settings/vnext/0/users/0/security", json!("aes-128-gcm")),
			(json!({"protocol": "trojan", "password": "a-long-password", "id": null}), "/settings/servers/0/password", json!("a-long-password")),
			(json!({"protocol": "shadowsocks", "password": "a-password-of-sixteen", "cipher": "aes-256-gcm", "security": {"type": "none"}}), "/settings/servers/0/method", json!("aes-256-gcm")),
			(json!({"transport": {"type": "ws", "path": "/w"}}), "/streamSettings/wsSettings/headers/Host", json!("provider.example")),
			(json!({"transport": {"type": "grpc", "service": "svc"}}), "/streamSettings/grpcSettings/authority", json!("provider.example")),
			(json!({"transport": {"type": "httpupgrade", "path": "/h", "host": "front.example"}}), "/streamSettings/httpupgradeSettings/host", json!("front.example")),
			(json!({"transport": {"type": "xhttp", "mode": "stream-up"}}), "/streamSettings/xhttpSettings/mode", json!("stream-up")),
			(json!({"security": {"type": "reality", "server_name": "site.example", "public_key": key, "short_id": "ab"}}), "/streamSettings/realitySettings/shortId", json!("ab")),
		];
		for (extra, pointer, expected) in cases {
			let mut extra = extra;
			extra.as_object_mut().unwrap().retain(|_, value| !value.is_null());
			let (_, out) = parts(&outbound(extra.clone()), &wire()).unwrap();
			assert_eq!(out.pointer(pointer), Some(&expected), "{extra}");
		}
	}

	#[test]
	fn a_provider_without_a_name_gets_no_host_of_its_own_in_the_stream() {
		let (_, out) = parts(&outbound(json!({"server": "93.184.216.34:443", "security": {"type": "tls", "server_name": "front.example"}, "transport": {"type": "ws"}})), &wire()).unwrap();
		assert_eq!(out["streamSettings"]["tlsSettings"]["serverName"], "front.example");
		assert!(out["streamSettings"]["wsSettings"].get("headers").is_none());
	}

	#[test]
	fn a_hop_is_down_until_it_is_given_a_socket_and_down_again_when_all_are_taken_away() {
		let hops = Hops::default();
		let hop = hops.get("up");
		assert!(hop.reason().is_some() && Arc::ptr_eq(&hop, &hops.get("up")));
		let reach = Reach {path: PathBuf::from("/x.sock"), uid: 7, password: "p".to_string()};
		hop.up(reach.clone());
		assert!(hop.reach() == Ok(reach));
		hops.all_down("xray is stopping");
		assert_eq!(hop.reason().as_deref(), Some("xray is stopping"));
	}

	#[test]
	fn a_start_makes_new_paths_and_passwords() {
		let (first, second) = (credentials(Path::new("/d"), &start_name().unwrap(), 0).unwrap(), credentials(Path::new("/d"), &start_name().unwrap(), 0).unwrap());
		assert!(first.1.len() == 64 && first.1 != second.1 && first.0 != second.0 && first.0.starts_with("/d"));
	}

	#[test]
	fn a_question_is_a_whole_dns_message_for_the_name() {
		let message = question("a.example", 28, 7);
		assert_eq!(&message[..4], &[0, 7, 1, 0]);
		assert!(dns::query(&message).is_some_and(|query| query.question.name.as_deref() == Some("a.example") && query.question.qtype == 28));
	}
}
