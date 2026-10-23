//! Xray outbounds (`outbounds[]` of type `xray`): another provider's VLESS, VMess, Trojan or Shadowsocks server as the carrier of a `netstack` exit.
//! They run in the add-on's one Xray process, next to its inbounds (`xray`), and not in one of their own: the host serves one lease at a time and keeps one set of capabilities, and a second process would be a second thing to start, pin, restart and cap. The price is that a change of an outbound restarts Xray, and with it the connections of the Xray inbounds, which come back with the next connect.
//! For each outbound the node writes a SOCKS5 inbound on 127.0.0.1 with a port and a login made new for the run, routed to that outbound alone, and dials it as it dials any `socks5` outbound (`Upstream::endpoint`). So the exit, the gate, the rules, the quotas and the counters are the ones every flow already meets, and nothing here sees a user.
//! The port and the login live in a `Hop` that the supervisor in `xray` fills in when Xray is up and empties when it is not. A flow that finds no endpoint fails there, with the reason, and the exit goes down the way an exit whose proxy refuses the node does. Nothing falls back to a direct connection.
use super::gate;
use crate::config::{self, Host, XhttpMode, XrayFlow, XrayOutboundProtocol, XraySecurity, XrayTransport};
use ipnet::IpNet;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::lookup_host;

/// How long the name of a provider's server is given to resolve.
const RESOLVE: Duration = Duration::from_secs(5);
/// The ports are asked of the system and then given to Xray, so another process may take one in between. Xray then does not start, and the next start asks again.
const PORT_TRIES: usize = 16;

enum State {Down(String), Up(u16, String, String)}

/// Where one Xray outbound is dialed: the loopback inbound of the add-on's current run, or why there is none. Its login is a secret, so this has no `Debug`.
pub struct Hop(Mutex<State>);

impl Hop {
	/// The port and the login of the inbound, or the reason the outbound cannot carry a flow now.
	pub fn endpoint(&self) -> Result<(u16, String, String), String> {
		match &*self.0.lock().unwrap_or_else(|e| e.into_inner()) {
			State::Up(port, user, pass) => Ok((*port, user.clone(), pass.clone())),
			State::Down(why) => Err(why.clone()),
		}
	}

	pub fn reason(&self) -> Option<String> {self.endpoint().err()}

	pub(super) fn up(&self, wire: &Wire) {*self.0.lock().unwrap_or_else(|e| e.into_inner()) = State::Up(wire.port, wire.user.clone(), wire.pass.clone())}

	pub(super) fn down(&self, why: &str) {*self.0.lock().unwrap_or_else(|e| e.into_inner()) = State::Down(why.to_string())}
}

/// The hops by the tag of their outbound. One registry lives as long as the engine, so a reload keeps the endpoint of an outbound that stays.
#[derive(Default)]
pub struct Hops(Mutex<HashMap<String, Arc<Hop>>>);

impl Hops {
	pub fn get(&self, tag: &str) -> Arc<Hop> {self.0.lock().unwrap_or_else(|e| e.into_inner()).entry(tag.to_string()).or_insert_with(|| Arc::new(Hop(Mutex::new(State::Down("the xray add-on has not started yet".to_string()))))).clone()}
}

/// One outbound as the add-on's document has it: the loopback inbound, its login, and the address the provider's server is dialed at, which is one the node looked up and checked.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Wire {pub tag: String, pub port: u16, pub user: String, pub pass: String, pub address: IpAddr}

/// A free port for the inbound, free for TCP and for UDP both (Xray's SOCKS5 inbound carries UDP on its port), above 1023 so that the host keeps no capability for it, and a login made for this run.
pub(super) fn endpoint() -> std::io::Result<(u16, String, String)> {
	let random = SystemRandom::new();
	let mut raw = [0u8; 40];
	random.fill(&mut raw).map_err(|_| std::io::Error::other("the system has no random source"))?;
	let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
	for _ in 0..PORT_TRIES {
		let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
		let port = tcp.local_addr()?.port();
		if port >= 1024 && UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {return Ok((port, hex(&raw[..8]), hex(&raw[8..])))}
	}
	Err(std::io::Error::other("no port that is free for TCP and UDP"))
}

/// The address the server of `outbound` is dialed at: the one it names, or the first one its name gives that the dial rules allow. The reason is for the status of the outbound.
pub(super) async fn resolve(outbound: &config::Outbound, pools: &[(IpNet, usize)]) -> Result<IpAddr, String> {
	let config::Outbound::Xray {server, ..} = outbound else {return Err("not an xray outbound".to_string())};
	let found: Vec<IpAddr> = match &server.host {
		Host::Ip(ip) => vec![*ip],
		Host::Name(name) => match tokio::time::timeout(RESOLVE, lookup_host((name.as_str(), server.port))).await {
			Ok(Ok(found)) => found.map(|addr| addr.ip()).collect(),
			Ok(Err(_)) | Err(_) => return Err("the name of the server does not resolve".to_string()),
		},
	};
	found.iter().copied().find(|ip| !gate::refused(*ip, pools)).ok_or_else(|| "the server gives no address the node may dial".to_string())
}

/// The loopback inbound of `wire`, and the outbound it is routed to. The document is built with the JSON writer, from fields that validation has checked, and has no key the code does not name.
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
			let mut tls = json!({"fingerprint": fingerprint.as_deref().unwrap_or("chrome"), "allowInsecure": false});
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
		json!({"tag": format!("out-{}", wire.tag), "listen": "127.0.0.1", "port": wire.port, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": wire.user, "pass": wire.pass}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}),
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

	fn wire() -> Wire {Wire {tag: "up".to_string(), port: 41000, user: "u".to_string(), pass: "p".to_string(), address: "203.0.113.9".parse().unwrap()}}

	#[test]
	fn a_loopback_inbound_is_routed_to_the_outbound_and_the_server_is_dialed_by_address() {
		let (inbound, out) = parts(&outbound(json!({})), &wire()).unwrap();
		assert_eq!((inbound["listen"].as_str(), inbound["port"].as_u64(), inbound["settings"]["udp"].as_bool()), (Some("127.0.0.1"), Some(41000), Some(true)));
		assert_eq!(inbound["settings"]["accounts"][0]["pass"], "p");
		assert_eq!(out["settings"]["vnext"][0]["address"], "203.0.113.9");
		assert_eq!(out["streamSettings"]["tlsSettings"]["serverName"], "provider.example");
		assert_eq!(out["streamSettings"]["tlsSettings"]["allowInsecure"], false);
	}

	#[test]
	fn every_protocol_and_stream_has_the_shape_xray_reads() {
		let key = "A".repeat(43);
		let cases = [
			(json!({"flow": "xtls-rprx-vision"}), "/settings/vnext/0/users/0/flow", json!("xtls-rprx-vision")),
			(json!({"protocol": "vmess", "cipher": "aes-128-gcm", "security": {"type": "none"}}), "/settings/vnext/0/users/0/security", json!("aes-128-gcm")),
			(json!({"protocol": "trojan", "password": "a-long-password", "id": null}), "/settings/servers/0/password", json!("a-long-password")),
			(json!({"protocol": "shadowsocks", "password": "pw", "cipher": "aes-256-gcm", "security": {"type": "none"}}), "/settings/servers/0/method", json!("aes-256-gcm")),
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
		let (_, out) = parts(&outbound(json!({"server": "203.0.113.9:443", "security": {"type": "tls", "server_name": "front.example"}, "transport": {"type": "ws"}})), &wire()).unwrap();
		assert_eq!(out["streamSettings"]["tlsSettings"]["serverName"], "front.example");
		assert!(out["streamSettings"]["wsSettings"].get("headers").is_none());
	}

	#[tokio::test]
	async fn a_server_the_node_may_not_dial_gets_no_address() {
		let refused = outbound(json!({"server": "127.0.0.1:443", "security": {"type": "tls", "server_name": "front.example"}}));
		assert!(resolve(&refused, &[]).await.is_err());
		let pooled = outbound(json!({"server": "10.7.0.5:443", "security": {"type": "tls", "server_name": "front.example"}}));
		assert!(resolve(&pooled, &[("10.7.0.1/24".parse().unwrap(), 0)]).await.is_err());
		assert_eq!(resolve(&pooled, &[]).await, Ok("10.7.0.5".parse().unwrap()));
	}

	#[test]
	fn a_hop_is_down_until_it_is_given_an_endpoint_and_down_again_when_it_is_taken_away() {
		let hops = Hops::default();
		let hop = hops.get("up");
		assert!(hop.reason().is_some() && Arc::ptr_eq(&hop, &hops.get("up")));
		hop.up(&wire());
		assert_eq!(hop.endpoint(), Ok((41000, "u".to_string(), "p".to_string())));
		hop.down("xray ended");
		assert_eq!(hop.reason().as_deref(), Some("xray ended"));
	}

	#[test]
	fn an_endpoint_is_a_free_port_with_a_login_that_differs_each_time() {
		let (first, second) = (endpoint().unwrap(), endpoint().unwrap());
		assert!(first.0 >= 1024 && first.1.len() == 16 && first.2.len() == 64 && first.1 != second.1 && first.2 != second.2);
	}
}
