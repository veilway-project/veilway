//! The document a run gives Xray on standard input: a fixed template whose slots take the typed fields of a `Profile`. It is built with the JSON writer and never by joining text, and it has no key the template does not name.
use super::profile::{Profile, Security, Stream};
use crate::subscription::legacy::{Scheme, Server};
use serde_json::json;
use std::net::IpAddr;

/// The values of one run: the loopback port of the SOCKS5 inbound and its login, the address the server is dialed at, and the physical interface's name where the platform keeps Xray's own socket out of the tunnel with it.
pub struct Run<'a> {
	pub port: u16,
	pub login: &'a str,
	pub address: IpAddr,
	pub interface: Option<&'a str>,
}

pub fn document(profile: &Profile, run: &Run) -> String {
	let (protocol, settings) = match profile.scheme {
		Scheme::Vless => ("vless", json!({"vnext": [{"address": run.address.to_string(), "port": profile.port, "users": [{"id": profile.credential.expose(), "encryption": "none", "flow": if profile.flow {"xtls-rprx-vision"} else {""}}]}]})),
		Scheme::Vmess => ("vmess", json!({"vnext": [{"address": run.address.to_string(), "port": profile.port, "users": [{"id": profile.credential.expose(), "alterId": 0, "security": profile.cipher.as_deref().unwrap_or("auto")}]}]})),
		Scheme::Trojan => ("trojan", json!({"servers": [{"address": run.address.to_string(), "port": profile.port, "password": profile.credential.expose()}]})),
		Scheme::Shadowsocks => ("shadowsocks", json!({"servers": [{"address": run.address.to_string(), "port": profile.port, "method": profile.cipher.as_deref().unwrap_or_default(), "password": profile.credential.expose()}]})),
	};
	let server_name = match &profile.security {
		Security::Tls {sni, ..} => sni.clone(),
		Security::Reality {sni, ..} => Some(sni.clone()),
		Security::None => None,
	}.or_else(|| match &profile.server {
		Server::Name(name) => Some(name.clone()),
		Server::Address(_) => None,
	});
	let named = match &profile.server {
		Server::Name(name) => Some(name.clone()),
		Server::Address(_) => None,
	};
	let mut stream = match &profile.stream {
		Stream::Tcp => json!({"network": "tcp", "tcpSettings": {"header": {"type": "none"}}}),
		// The address in the document is an IP literal, so a server that is a name gives its name as the Host of a WebSocket request and the authority of a gRPC one when the link names none.
		Stream::Ws {path, host} => {
			let mut ws = json!({"path": path});
			if let Some(host) = host.as_ref().or(named.as_ref()) {ws["headers"] = json!({"Host": host})}
			json!({"network": "ws", "wsSettings": ws})
		}
		Stream::Grpc {service} => {
			let mut grpc = json!({"serviceName": service, "multiMode": false});
			if let Some(name) = &named {grpc["authority"] = json!(name)}
			json!({"network": "grpc", "grpcSettings": grpc})
		}
	};
	match &profile.security {
		Security::None => stream["security"] = json!("none"),
		Security::Tls {alpn, fingerprint, ..} => {
			let mut tls = json!({"fingerprint": fingerprint, "allowInsecure": false, "alpn": alpn});
			if let Some(name) = &server_name {tls["serverName"] = json!(name)}
			stream["security"] = json!("tls");
			stream["tlsSettings"] = tls;
		}
		Security::Reality {fingerprint, public_key, short_id, ..} => {
			let mut reality = json!({"fingerprint": fingerprint, "publicKey": public_key, "shortId": short_id});
			if let Some(name) = &server_name {reality["serverName"] = json!(name)}
			stream["security"] = json!("reality");
			stream["realitySettings"] = reality;
		}
	}
	if let Some(interface) = run.interface {stream["sockopt"] = json!({"interface": interface})}
	json!({
		"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"},
		"inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": run.port, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "veilway", "pass": run.login}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}],
		"outbounds": [{"tag": "proxy", "protocol": protocol, "settings": settings, "streamSettings": stream}, {"tag": "refused", "protocol": "blackhole"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
	}).to_string()
}
