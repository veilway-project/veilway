use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use veilway_proto::{subscription::legacy, xray::{document::{self, Run}, profile::{self, Refusal}}};

// Every key the document may hold, at any depth. A key outside it fails the walk.
const KEYS: &[&str] = &["log", "access", "loglevel", "maskAddress", "inbounds", "tag", "listen", "port", "protocol", "settings", "auth", "accounts", "user", "pass", "udp", "ip", "sniffing", "enabled", "outbounds", "vnext", "address", "users", "id", "encryption", "flow", "alterId", "security", "servers", "password", "method", "streamSettings", "network", "tcpSettings", "header", "type", "wsSettings", "path", "headers", "Host", "grpcSettings", "authority", "serviceName", "multiMode", "tlsSettings", "fingerprint", "allowInsecure", "alpn", "serverName", "realitySettings", "publicKey", "shortId", "sockopt", "interface", "routing", "domainStrategy", "rules", "inboundTag", "outboundTag"];

fn read(link: &str) -> legacy::Entry {legacy::list(link.as_bytes()).unwrap().entries.swap_remove(0)}

fn vmess(value: Value) -> String {format!("vmess://{}", STANDARD.encode(value.to_string()))}

fn walk(value: &Value) {
	match value {
		Value::Object(map) => for (key, child) in map {
			assert!(KEYS.contains(&key.as_str()), "key outside the document: {key}");
			walk(child);
		},
		Value::Array(items) => items.iter().for_each(walk),
		_ => {}
	}
}

fn document(link: &str, interface: Option<&str>) -> Value {
	let profile = profile::check(&read(link)).unwrap();
	let run = Run {port: 10808, login: "L", address: "192.0.2.10".parse().unwrap(), interface};
	let document: Value = serde_json::from_str(&document::document(&profile, &run)).unwrap();
	walk(&document);
	document
}

#[test]
fn which_profiles_connect() {
	let pbk = "A".repeat(43);
	let key16 = STANDARD.encode([7u8; 16]);
	let key8 = STANDARD.encode([7u8; 8]);
	let base = json!({"add": "node.example.com", "port": "443", "id": "id", "net": "ws", "path": "/ws", "tls": "tls", "scy": "auto"});
	let rows: Vec<(String, Result<(), Refusal>)> = vec![
		("vless://id@node.example.com:443?security=tls&sni=sni.example.com#A".to_owned(), Ok(())),
		(format!("vless://id@node.example.com:443?security=reality&sni=sni.example.com&pbk={pbk}&sid=0a&fp=firefox&flow=xtls-rprx-vision#A"), Ok(())),
		("vless://id@node.example.com:443?security=none#A".to_owned(), Err(Refusal::Security)),
		("vless://id@node.example.com:443?security=tls&allowInsecure=1#A".to_owned(), Err(Refusal::Certificate)),
		("vless://id@node.example.com:443?security=tls&pcs=abcd#A".to_owned(), Err(Refusal::Certificate)),
		("vless://id@node.example.com:443?security=tls&encryption=mlkem768x25519plus-a#A".to_owned(), Err(Refusal::Encryption)),
		("vless://id@node.example.com:443?security=tls&encryption=none#A".to_owned(), Ok(())),
		("vless://id@node.example.com:443?security=tls&flow=xtls-rprx-direct#A".to_owned(), Err(Refusal::Flow)),
		("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws&flow=xtls-rprx-vision#A".to_owned(), Err(Refusal::Flow)),
		("vless://id@node.example.com:443?security=tls&headerType=http#A".to_owned(), Err(Refusal::Header)),
		("vless://id@node.example.com:443?security=tls&type=tcp&headerType=none#A".to_owned(), Ok(())),
		("vless://id@node.example.com:443?security=tls&type=kcp#A".to_owned(), Err(Refusal::Stream)),
		("vless://id@node.example.com:443?security=tls&type=xhttp#A".to_owned(), Err(Refusal::Stream)),
		("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws&ed=2048#A".to_owned(), Err(Refusal::Transport)),
		("vless://id@node.example.com:443?security=tls&type=grpc&serviceName=svc&mode=multi#A".to_owned(), Err(Refusal::Transport)),
		("vless://id@node.example.com:443?security=tls&type=grpc&serviceName=svc&mode=gun#A".to_owned(), Ok(())),
		("vless://id@node.example.com:443?security=tls&alpn=quic#A".to_owned(), Err(Refusal::Security)),
		("vless://id@node.example.com:443?security=tls&alpn=h2,http/1.1#A".to_owned(), Ok(())),
		("vless://id@node.example.com:443?security=tls&fp=opera#A".to_owned(), Err(Refusal::Security)),
		("vless://id@node.example.com:443?security=reality&sni=sni.example.com&sid=0a#A".to_owned(), Err(Refusal::Reality)),
		(format!("vless://id@node.example.com:443?security=reality&pbk={pbk}&sid=0a#A"), Err(Refusal::Reality)),
		(format!("vless://id@node.example.com:443?security=reality&sni=sni.example.com&pbk={pbk}&sid=0a0#A"), Err(Refusal::Reality)),
		(format!("vless://id@node.example.com:443?security=reality&sni=sni.example.com&pbk={}#A", "A".repeat(42)), Err(Refusal::Reality)),
		("trojan://pw@node.example.com:443#T".to_owned(), Ok(())),
		("trojan://pw@node.example.com:443?security=none#T".to_owned(), Err(Refusal::Security)),
		("trojan://pw@node.example.com:443?flow=xtls-rprx-vision#T".to_owned(), Err(Refusal::Flow)),
		("trojan://pw@node.example.com:443?type=ws&path=%2Fws&host=cdn.example.com#T".to_owned(), Ok(())),
		(vmess(base.clone()), Ok(())),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "aid": "1"})), Err(Refusal::Aid)),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "aid": "0", "scy": "auto"})), Ok(())),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "scy": "none"})), Err(Refusal::Cipher)),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "scy": "zero"})), Err(Refusal::Cipher)),
		(vmess(json!({"add": "node.example.com", "port": "443", "id": "id", "net": "ws", "type": "http"})), Err(Refusal::Header)),
		(format!("ss://{}@node.example.com:8388#S", STANDARD.encode("aes-128-gcm:pw")), Ok(())),
		(format!("ss://{}@node.example.com:8388#S", STANDARD.encode("rc4-md5:pw")), Err(Refusal::Cipher)),
		(format!("ss://{}@node.example.com:8388?plugin=v2ray-plugin#S", STANDARD.encode("aes-128-gcm:pw")), Err(Refusal::Plugin)),
		(format!("ss://{}@node.example.com:8388#S", STANDARD.encode(format!("2022-blake3-aes-128-gcm:{key16}"))), Ok(())),
		(format!("ss://{}@node.example.com:8388#S", STANDARD.encode(format!("2022-blake3-aes-128-gcm:{key8}"))), Err(Refusal::Key)),
		(format!("ss://{}@node.example.com:8388#S", STANDARD.encode(format!("2022-blake3-aes-256-gcm:{key16}"))), Err(Refusal::Key)),
	];
	for (link, want) in rows {assert_eq!(profile::check(&read(&link)).map(|_| ()), want, "{link}")}
}

#[test]
fn every_refusal_has_its_own_code() {
	let all = [Refusal::Stream, Refusal::Header, Refusal::Security, Refusal::Certificate, Refusal::Encryption, Refusal::Flow, Refusal::Aid, Refusal::Cipher, Refusal::Key, Refusal::Plugin, Refusal::Reality, Refusal::Transport];
	let mut codes: Vec<&str> = all.iter().map(|refusal| refusal.code()).collect();
	codes.sort_unstable();
	codes.dedup();
	assert_eq!((codes.len(), codes.iter().all(|code| code.starts_with("profile_refused."))), (12, true));
}

#[test]
fn vless_tls_tcp_document() {
	let want = json!({
		"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"},
		"inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "veilway", "pass": "L"}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}],
		"outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "192.0.2.10", "port": 443, "users": [{"id": "id", "encryption": "none", "flow": "xtls-rprx-vision"}]}]}, "streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "none"}}, "security": "tls", "tlsSettings": {"fingerprint": "firefox", "allowInsecure": false, "alpn": ["h2", "http/1.1"], "serverName": "sni.example.com"}}}, {"tag": "refused", "protocol": "blackhole"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
	});
	assert_eq!(document("vless://id@node.example.com:443?security=tls&sni=sni.example.com&fp=firefox&alpn=h2,http/1.1&flow=xtls-rprx-vision#A", None), want);
}

#[test]
fn vless_reality_grpc_document() {
	let pbk = "A".repeat(43);
	let want = json!({
		"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"},
		"inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "veilway", "pass": "L"}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}],
		"outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "192.0.2.10", "port": 443, "users": [{"id": "id", "encryption": "none", "flow": ""}]}]}, "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "svc", "multiMode": false, "authority": "node.example.com"}, "security": "reality", "realitySettings": {"fingerprint": "chrome", "publicKey": pbk, "shortId": "0a", "serverName": "www.example.com"}}}, {"tag": "refused", "protocol": "blackhole"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
	});
	assert_eq!(document(&format!("vless://id@node.example.com:443?security=reality&sni=www.example.com&pbk={pbk}&sid=0a&type=grpc&serviceName=svc&mode=gun#B"), None), want);
}

#[test]
fn vmess_ws_document_with_interface() {
	let link = vmess(json!({"add": "node.example.com", "port": "443", "id": "uuid", "net": "ws", "path": "/ws", "host": "cdn.example.com", "tls": "", "scy": "auto"}));
	let want = json!({
		"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"},
		"inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "veilway", "pass": "L"}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}],
		"outbounds": [{"tag": "proxy", "protocol": "vmess", "settings": {"vnext": [{"address": "192.0.2.10", "port": 443, "users": [{"id": "uuid", "alterId": 0, "security": "auto"}]}]}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws", "headers": {"Host": "cdn.example.com"}}, "security": "none", "sockopt": {"interface": "en0"}}}, {"tag": "refused", "protocol": "blackhole"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
	});
	assert_eq!(document(&link, Some("en0")), want);
}

#[test]
fn trojan_tls_ws_document_names_the_server_when_no_sni_is_given() {
	let want = json!({
		"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"},
		"inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "veilway", "pass": "L"}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}],
		"outbounds": [{"tag": "proxy", "protocol": "trojan", "settings": {"servers": [{"address": "192.0.2.10", "port": 443, "password": "pw"}]}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws", "headers": {"Host": "cdn.example.com"}}, "security": "tls", "tlsSettings": {"fingerprint": "chrome", "allowInsecure": false, "alpn": [], "serverName": "node.example.com"}}}, {"tag": "refused", "protocol": "blackhole"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
	});
	assert_eq!(document("trojan://pw@node.example.com:443?type=ws&path=%2Fws&host=cdn.example.com#T", None), want);
}

#[test]
fn shadowsocks_document() {
	let link = format!("ss://{}@node.example.com:8388#S", STANDARD.encode("chacha20-ietf-poly1305:pw"));
	let want = json!({
		"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"},
		"inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "veilway", "pass": "L"}], "udp": true, "ip": "127.0.0.1"}, "sniffing": {"enabled": false}}],
		"outbounds": [{"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [{"address": "192.0.2.10", "port": 8388, "method": "chacha20-ietf-poly1305", "password": "pw"}]}, "streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "none"}}, "security": "none"}}, {"tag": "refused", "protocol": "blackhole"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
	});
	assert_eq!(document(&link, None), want);
}

#[test]
fn a_credential_with_quotes_stays_a_value() {
	let document = document("vless://a%22b%5Cc@node.example.com:443?security=tls#A", None);
	assert_eq!(document["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], json!("a\"b\\c"));
}

fn refused(link: &str) -> Result<(), Refusal> {profile::check(&read(link)).map(drop)}

#[test]
fn a_server_that_is_a_name_gives_its_name_as_the_host_when_the_link_names_none() {
	let ws = document("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws#A", None);
	assert_eq!(ws["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"], "node.example.com");
	let named = document("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com#A", None);
	assert_eq!(named["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"], "cdn.example.com", "a host the link names wins");
	let grpc = document("vless://id@node.example.com:443?security=tls&type=grpc&serviceName=svc#A", None);
	assert_eq!(grpc["outbounds"][0]["streamSettings"]["grpcSettings"]["authority"], "node.example.com");
	let literal = document("vless://id@192.0.2.10:443?security=tls&type=ws&path=%2Fws#A", None);
	assert!(literal["outbounds"][0]["streamSettings"]["wsSettings"].get("headers").is_none(), "an address is no host name");
	assert!(document("vless://id@192.0.2.10:443?security=tls&type=grpc&serviceName=svc#A", None)["outbounds"][0]["streamSettings"]["grpcSettings"].get("authority").is_none());
}

#[test]
fn early_data_in_the_query_of_a_ws_path_refuses_the_profile() {
	assert_eq!(refused("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048#A"), Err(Refusal::Transport));
	assert_eq!(refused("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws%3Fa%3D1%26ed%3D0#A"), Err(Refusal::Transport));
	assert_eq!(refused("vless://id@node.example.com:443?security=tls&type=ws&path=%2Fws%3Fmed%3D1#A"), Ok(()), "a key that only ends in ed is not early data");
	let early = vmess(json!({"add": "node.example.com", "port": "443", "id": "uuid", "net": "ws", "path": "/ws?ed=2048", "tls": "tls", "scy": "auto"}));
	assert_eq!(refused(&early), Err(Refusal::Transport));
}

#[test]
fn a_field_that_is_there_and_does_not_read_refuses_the_link() {
	let bad = [
		"vless://id@node.example.com:443?security=tls&sni=not_a_host!#A",
		"vless://id@node.example.com:443?security=tls&host=bad%20host&type=ws#A",
		"vless://id@node.example.com:443?security=tls&type=ws&path=no-slash#A",
		"vless://id@node.example.com:443?security=tls&type=ws&path=%2Fa%22b#A",
		"vless://id@node.example.com:443?security=tls&sni=%zz#A",
		"vless://id@node.example.com:443?security=tls&path=%ff#A",
		"vless://id@node.example.com:443?security=%zz#A",
		"vless://id@node.example.com:443?security=tls&allowInsecure=%zz#A",
	];
	for link in bad {assert!(legacy::list(link.as_bytes()).unwrap().entries.is_empty(), "{link}")}
	assert_eq!(legacy::list(b"vless://id@node.example.com:443?security=tls&sni=&host=&path=#A").unwrap().entries.len(), 1, "an empty field is an absent one");
	for field in [("sni", "bad host"), ("host", "bad host"), ("path", "no-slash")] {
		let mut value = json!({"add": "node.example.com", "port": "443", "id": "uuid", "net": "ws", "path": "/ws", "tls": "tls", "scy": "auto"});
		value[field.0] = json!(field.1);
		assert!(legacy::list(vmess(value).as_bytes()).unwrap().entries.is_empty(), "{field:?}");
	}
}

#[test]
fn the_type_of_a_vmess_grpc_link_is_its_mode() {
	let grpc = |kind: &str| vmess(json!({"add": "node.example.com", "port": "443", "id": "uuid", "net": "grpc", "path": "svc", "type": kind, "tls": "tls", "scy": "auto"}));
	assert_eq!(refused(&grpc("gun")), Ok(()));
	assert_eq!(refused(&grpc("multi")), Err(Refusal::Transport));
	assert_eq!(refused(&grpc("")), Ok(()));
	let ws = vmess(json!({"add": "node.example.com", "port": "443", "id": "uuid", "net": "ws", "path": "/ws", "type": "http", "tls": "tls", "scy": "auto"}));
	assert_eq!(refused(&ws), Err(Refusal::Header), "for any other stream it stays the header");
}
