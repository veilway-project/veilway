//! Outbounds of type `xray`: what makes them valid, how a share link is read into them, and how their secrets are shown and kept.
use serde_json::{json, Value};
use veilway_core::config::{Config, Outbound, Report, REDACTED};

const ID: &str = "3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c";
const PUBLIC: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE";

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn node(outbound: Value) -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}, {"tag": "chain", "type": "socks5", "server": "192.0.2.50:1080", "via": "up"}, outbound],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "far", "backend": {"type": "netstack", "outbound": "up"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}]
	})
}

fn vless() -> Value {json!({"type": "xray", "tag": "up", "protocol": "vless", "server": "provider.example:443", "id": ID, "security": {"type": "tls"}})}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn refused(path: &str, edit: impl FnOnce(&mut Value)) {
	let mut outbound = vless();
	edit(&mut outbound);
	let report = check(&node(outbound));
	assert!(report.errors.iter().any(|error| error.path == path), "expected an error at {path}, got {:#?}", report.errors);
}

#[track_caller]
fn clean(outbound: Value) {
	let report = check(&node(outbound.clone()));
	assert!(report.errors.is_empty(), "{outbound}: {:#?}", report.errors);
}

#[test]
fn every_protocol_with_its_streams_is_valid() {
	clean(vless());
	clean(json!({"type": "xray", "tag": "up", "protocol": "vless", "server": "203.0.113.9:443", "id": ID, "flow": "xtls-rprx-vision", "security": {"type": "reality", "server_name": "site.example", "public_key": PUBLIC, "short_id": "ab12", "fingerprint": "firefox"}}));
	clean(json!({"type": "xray", "tag": "up", "protocol": "vless", "server": "provider.example:443", "id": ID, "transport": {"type": "xhttp", "path": "/x", "mode": "stream-up"}, "security": {"type": "tls", "alpn": ["h2", "http/1.1"]}}));
	clean(json!({"type": "xray", "tag": "up", "protocol": "vmess", "server": "provider.example:80", "id": ID, "cipher": "chacha20-poly1305", "transport": {"type": "ws", "path": "/ws", "host": "front.example"}}));
	clean(json!({"type": "xray", "tag": "up", "protocol": "trojan", "server": "provider.example:443", "password": "a-long-password", "transport": {"type": "grpc", "service": "svc"}, "security": {"type": "tls"}}));
	clean(json!({"type": "xray", "tag": "up", "protocol": "shadowsocks", "server": "203.0.113.9:8388", "password": key(0x41), "cipher": "2022-blake3-aes-256-gcm"}));
	clean(json!({"type": "xray", "tag": "up", "protocol": "vless", "server": "provider.example:443", "id": ID, "transport": {"type": "httpupgrade"}, "security": {"type": "tls"}}));
}

#[test]
fn what_xray_cannot_do_or_the_node_may_not_dial_is_refused() {
	refused("outbounds[2].server", |o| o["server"] = json!("127.0.0.1:443"));
	refused("outbounds[2].server", |o| o["server"] = json!("169.254.169.254:443"));
	refused("outbounds[2].server", |o| o["server"] = json!("10.7.0.9:443"));
	refused("outbounds[2].server", |o| o["server"] = json!("[::1]:443"));
	refused("outbounds[2].security.server_name", |o| o["server"] = json!("203.0.113.9:443"));
	refused("outbounds[2].security", |o| o.as_object_mut().unwrap().remove("security").map(drop).unwrap());
	refused("outbounds[2].security", |o| o["security"] = json!({"type": "none"}));
	refused("outbounds[2].id", |o| o.as_object_mut().unwrap().remove("id").map(drop).unwrap());
	refused("outbounds[2].id", |o| o["id"] = json!("not-a-uuid"));
	refused("outbounds[2].password", |o| o["password"] = json!("x"));
	refused("outbounds[2].id", |o| o["id"] = json!(REDACTED));
	refused("outbounds[2].cipher", |o| o["cipher"] = json!("aes-128-gcm"));
	refused("outbounds[2].flow", |o| *o = json!({"type": "xray", "tag": "up", "protocol": "trojan", "server": "provider.example:443", "password": "a-long-password", "flow": "xtls-rprx-vision", "security": {"type": "tls"}}));
	refused("outbounds[2].flow", |o| {o["flow"] = json!("xtls-rprx-vision"); o["transport"] = json!({"type": "ws"})});
	refused("outbounds[2].transport.path", |o| o["transport"] = json!({"type": "ws", "path": "no-slash"}));
	refused("outbounds[2].transport.path", |o| o["transport"] = json!({"type": "ws", "path": "/a b"}));
	refused("outbounds[2].transport.host", |o| o["transport"] = json!({"type": "ws", "host": "Not A Host"}));
	refused("outbounds[2].transport.service", |o| o["transport"] = json!({"type": "grpc", "service": "a\"b"}));
	refused("outbounds[2].transport", |o| {o["transport"] = json!({"type": "ws"}); o["security"] = json!({"type": "reality", "server_name": "site.example", "public_key": PUBLIC})});
	refused("outbounds[2].security.public_key", |o| o["security"] = json!({"type": "reality", "server_name": "site.example", "public_key": "short"}));
	refused("outbounds[2].security.short_id", |o| o["security"] = json!({"type": "reality", "server_name": "site.example", "public_key": PUBLIC, "short_id": "abc"}));
	refused("outbounds[2].security.fingerprint", |o| o["security"] = json!({"type": "tls", "fingerprint": "curl"}));
	refused("outbounds[2].security.alpn", |o| o["security"] = json!({"type": "tls", "alpn": ["h3"]}));
	refused("outbounds[2].cipher", |o| {*o = json!({"type": "xray", "tag": "up", "protocol": "shadowsocks", "server": "203.0.113.9:8388", "password": "pw"})});
	refused("outbounds[2].password", |o| *o = json!({"type": "xray", "tag": "up", "protocol": "shadowsocks", "server": "203.0.113.9:8388", "password": "not-a-key", "cipher": "2022-blake3-aes-256-gcm"}));
	let mut many = node(vless());
	for i in 0..16 {many["outbounds"].as_array_mut().unwrap().push(json!({"type": "xray", "tag": format!("extra{i}"), "protocol": "trojan", "server": "provider.example:443", "password": "a-long-password", "security": {"type": "tls"}}))}
	assert!(check(&many).errors.iter().any(|error| error.path == "outbounds"));
}

#[test]
fn keys_that_belong_to_other_types_and_the_certificate_switch_do_not_parse() {
	for extra in [json!({"allow_insecure": true}), json!({"security": {"type": "tls", "allow_insecure": true}}), json!({"via": "plain"}), json!({"username": "x"}), json!({"bind": "192.0.2.1"})] {
		let mut outbound = vless();
		outbound.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		assert!(Config::parse(node(outbound).to_string().as_bytes()).is_err(), "{extra}");
	}
	let mut socks = json!({"type": "socks5", "tag": "s", "server": "192.0.2.1:1080", "id": ID});
	assert!(serde_json::from_value::<Outbound>(socks.clone()).is_err());
	socks.as_object_mut().unwrap().remove("id");
	assert!(serde_json::from_value::<Outbound>(socks).is_ok());
}

#[test]
fn a_chain_may_end_at_an_xray_outbound_and_an_xray_outbound_starts_no_chain() {
	let report = check(&node(vless()));
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	let mut doc = node(vless());
	doc["outbounds"][1]["via"] = json!("plain");
	assert!(check(&doc).errors.iter().any(|error| error.path == "outbounds[1].via"));
	assert!(report.warnings.iter().any(|warning| warning.path == "outbounds[2].server"), "a name that is looked up says so");
}

#[test]
fn a_share_link_is_read_into_the_typed_outbound_and_is_not_kept() {
	let links = [
		(format!("vless://{ID}@provider.example:443?type=tcp&security=reality&sni=site.example&fp=chrome&pbk={PUBLIC}&sid=ab&flow=xtls-rprx-vision#name"), "vless"),
		(format!("vless://{ID}@provider.example:443?type=ws&security=tls&sni=provider.example&path=%2Fws&host=front.example#name"), "vless"),
		(format!("trojan://a-long-password@provider.example:443?type=grpc&security=tls&serviceName=svc#name"), "trojan"),
		("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@203.0.113.9:8388#name".to_string(), "shadowsocks"),
	];
	for (link, protocol) in links {
		let doc = node(json!({"type": "xray", "tag": "up", "link": link}));
		let config = Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("{link}: {e}"));
		assert!(config.validate(false).errors.is_empty(), "{link}");
		let shown = serde_json::to_value(&config).unwrap();
		assert_eq!(shown["outbounds"][2]["protocol"], protocol);
		assert!(shown["outbounds"][2].get("link").is_none(), "the link is input only");
		assert!(Config::parse(shown.to_string().as_bytes()).unwrap() == config, "the typed form is what is stored and it reads back the same");
	}
	let Outbound::Xray {transport, security, flow, server, ..} = &Config::parse(node(json!({"type": "xray", "tag": "up", "link": format!("vless://{ID}@provider.example:443?type=tcp&security=reality&sni=site.example&pbk={PUBLIC}&sid=ab&flow=xtls-rprx-vision")})).to_string().as_bytes()).unwrap().outbounds[2] else {panic!("not xray")};
	assert!(transport.is_none() && flow.is_some() && format!("{security:?}").contains("Reality"));
	assert_eq!(server.port, 443);
}

#[test]
fn a_link_the_client_refuses_is_refused_with_the_clients_code_and_never_echoed() {
	let cases = [
		(format!("vless://{ID}@provider.example:443?type=kcp&security=tls"), "profile_refused.stream"),
		(format!("vless://{ID}@provider.example:443?type=tcp&security=tls&allowInsecure=1"), "profile_refused.certificate"),
		(format!("vless://{ID}@provider.example:443?type=tcp"), "profile_refused.security"),
		(format!("vless://{ID}@provider.example:443?type=ws&security=tls&flow=xtls-rprx-vision"), "profile_refused.flow"),
		("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@203.0.113.9:8388?plugin=obfs-local".to_string(), "profile_refused.plugin"),
	];
	for (link, code) in cases {
		let message = Config::parse(node(json!({"type": "xray", "tag": "up", "link": link})).to_string().as_bytes()).err().unwrap_or_else(|| panic!("{link} was accepted")).message;
		assert!(message.contains(code), "{link}: {message}");
		assert!(!message.contains(ID) && !message.contains("provider.example"), "{message}");
	}
	for link in ["", "not a link", "vless://", "http://provider.example/", "dmxlc3M6Ly8=", &format!("vless://{ID}@provider.example:443?type=tcp&security=tls\nvless://{ID}@other.example:443?type=tcp&security=tls"), &"a".repeat(5000)] {
		let message = Config::parse(node(json!({"type": "xray", "tag": "up", "link": link})).to_string().as_bytes()).err().unwrap_or_else(|| panic!("{link:?} was accepted")).message;
		assert!(!message.contains(ID), "{message}");
	}
	let both = json!({"type": "xray", "tag": "up", "link": format!("vless://{ID}@provider.example:443?type=tcp&security=tls"), "protocol": "vless"});
	assert!(Config::parse(node(both).to_string().as_bytes()).is_err());
}

#[test]
fn secrets_are_shown_as_markers_and_kept_for_the_same_outbound_and_server() {
	let config = Config::parse(node(vless()).to_string().as_bytes()).unwrap();
	let shown = config.redacted();
	assert_eq!(shown.to_string().matches(REDACTED).count(), 2, "the inbound's key and the user id");
	assert!(!shown.to_string().contains(ID));
	assert!(Config::parse_keeping(shown.to_string().as_bytes(), &config).ok().map(|(kept, _)| kept) == Some(config.clone()));
	let mut moved = shown.clone();
	moved["outbounds"][2]["server"] = json!("elsewhere.example:443");
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("a marker was kept for another server");
	assert_eq!(report.errors[0].path, "outbounds[2].id");
	let mut spelled = node(vless());
	spelled["outbounds"][2]["id"] = json!(REDACTED);
	assert!(!check(&spelled).errors.is_empty(), "a marker passed validation as a secret");
	let (_, changed) = Config::parse_keeping(node(vless()).to_string().as_bytes(), &config).unwrap();
	assert_eq!(changed, vec!["up".to_string()], "a secret that is spelled out counts as changed");
	let mut link = shown.clone();
	link["outbounds"][2] = json!({"type": "xray", "tag": "up", "link": format!("vless://{ID}@provider.example:443?type=tcp&security=tls")});
	assert_eq!(Config::parse_keeping(link.to_string().as_bytes(), &config).unwrap().1, vec!["up".to_string()]);
}

#[test]
fn a_change_of_an_xray_outbound_is_a_change_of_that_outbound() {
	let (old, new) = (Config::parse(node(vless()).to_string().as_bytes()).unwrap(), {
		let mut outbound = vless();
		outbound["security"] = json!({"type": "tls", "fingerprint": "firefox"});
		Config::parse(node(outbound).to_string().as_bytes()).unwrap()
	});
	let diff = veilway_core::config::Diff::between(&old, &new, time::OffsetDateTime::now_utc());
	assert_eq!(diff.outbounds.changed, vec!["up".to_string()]);
}

#[test]
fn the_schema_has_the_outbound_and_takes_either_form() {
	let schema: Value = serde_json::from_str(&veilway_core::config::schema()).unwrap();
	let text = schema.to_string();
	for word in ["xhttp", "httpupgrade", "xtls-rprx-vision", "reality", "\"link\""] {assert!(text.contains(word), "{word}")}
	assert!(!text.contains("allow_insecure") && !text.contains("allowInsecure"));
}
