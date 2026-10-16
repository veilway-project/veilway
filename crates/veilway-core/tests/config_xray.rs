//! The `xray` section of config version 1: what makes it valid, and how its secrets are shown and kept.
use serde_json::{json, Value};
use veilway_core::config::{Config, Report, REDACTED};

const UUID: &str = "5783a3e7-e373-51cd-8642-c83782b807c5";

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}],
		"xray": {"inbounds": [
			{"tag": "v1", "protocol": "vless", "listen": "0.0.0.0:8444", "tls": {"cert": "node.crt", "key": "node.key"}, "decoy": "http://127.0.0.1:8080", "clients": [{"user": "alice", "secret": UUID}]},
			{"tag": "t1", "protocol": "trojan", "listen": "0.0.0.0:8445", "tls": {"cert": "node.crt", "key": "node.key"}, "decoy": "http://127.0.0.1:8080", "clients": [{"user": "alice", "secret": "a-long-password-of-enough-length"}]},
			{"tag": "s1", "protocol": "shadowsocks", "listen": "0.0.0.0:8446", "server_key": key(0x31), "clients": [{"user": "alice", "secret": key(0x32)}]}
		]}
	})
}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn refused(path: &str, edit: impl FnOnce(&mut Value)) {
	let mut doc = node();
	edit(&mut doc);
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == path), "expected an error at {path}, got {:#?}", report.errors);
}

#[test]
fn a_good_section_is_clean() {
	let report = check(&node());
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
}

#[test]
fn each_rule_of_the_section_holds() {
	refused("xray.inbounds[0].tls", |doc| {doc["xray"]["inbounds"][0].as_object_mut().unwrap().remove("tls");});
	refused("xray.inbounds[2].tls", |doc| doc["xray"]["inbounds"][2]["tls"] = json!({"cert": "a", "key": "b"}));
	refused("xray.inbounds[0].clients[0].user", |doc| doc["xray"]["inbounds"][0]["clients"][0]["user"] = json!("nobody"));
	refused("xray.inbounds[0].clients[0].secret", |doc| doc["xray"]["inbounds"][0]["clients"][0]["secret"] = json!("not-a-uuid-at-all"));
	refused("xray.inbounds[1].clients[0].secret", |doc| doc["xray"]["inbounds"][1]["clients"][0]["secret"] = json!("short"));
	refused("xray.inbounds[1].clients[0].secret", |doc| doc["xray"]["inbounds"][1]["clients"][0]["secret"] = json!("just-under-22-chars"));
	refused("xray.inbounds[2].clients[0].secret", |doc| doc["xray"]["inbounds"][2]["clients"][0]["secret"] = json!("a-password-not-a-key-at-all-here"));
	refused("xray.inbounds[2].listen", |doc| doc["inbounds"][0]["transports"][0]["listen"] = json!("0.0.0.0:8446"));
	refused("xray.inbounds[2].listen", |doc| {
		doc["xray"]["inbounds"][2]["listen"] = json!("[::]:443");
		doc["inbounds"][0]["transports"][0]["listen"] = json!("0.0.0.0:443");
	});
	refused("xray.inbounds[2].server_key", |doc| doc["xray"]["inbounds"][2]["server_key"] = json!("c2hvcnQ="));
	refused("xray.inbounds[2].server_key", |doc| {doc["xray"]["inbounds"][2].as_object_mut().unwrap().remove("server_key");});
	refused("xray.inbounds[0].server_key", |doc| doc["xray"]["inbounds"][0]["server_key"] = json!(key(0x31)));
	refused("xray.inbounds[0].decoy", |doc| {doc["xray"]["inbounds"][0].as_object_mut().unwrap().remove("decoy");});
	refused("xray.inbounds[1].decoy", |doc| {doc["xray"]["inbounds"][1].as_object_mut().unwrap().remove("decoy");});
	refused("xray.inbounds[2].decoy", |doc| doc["xray"]["inbounds"][2]["decoy"] = json!("http://127.0.0.1:8080"));
	refused("xray.inbounds[0].clients[1].secret", |doc| {
		doc["users"].as_array_mut().unwrap().push(json!({"name": "bob", "exits": "all", "devices": [{"name": "phone", "public_key": key(0x22), "addresses": ["10.7.0.3"]}]}));
		doc["xray"]["inbounds"][0]["clients"].as_array_mut().unwrap().push(json!({"user": "bob", "secret": UUID.to_uppercase()}));
	});
	refused("xray.inbounds[1].clients[0].secret", |doc| doc["xray"]["inbounds"][1]["clients"][0]["secret"] = json!("has a space in it"));
	refused("xray.inbounds[1].tag", |doc| doc["xray"]["inbounds"][1]["tag"] = json!("v1"));
	refused("xray.inbounds[1].listen", |doc| doc["xray"]["inbounds"][1]["listen"] = json!("0.0.0.0:8444"));
	refused("xray.inbounds[0].clients[1].user", |doc| doc["xray"]["inbounds"][0]["clients"].as_array_mut().unwrap().push(json!({"user": "alice", "secret": UUID})));
}

#[test]
fn secrets_are_shown_as_markers_and_kept_for_the_same_user_of_the_same_inbound() {
	let config = Config::parse(node().to_string().as_bytes()).unwrap();
	let shown = config.redacted();
	assert_eq!(shown.to_string().matches(REDACTED).count(), 5);
	assert!(!shown.to_string().contains(UUID) && !shown.to_string().contains("a-long-password-of-enough-length"));
	assert!(check_marker(&shown), "a marker was taken for a secret without a running config to take it from");
	assert!(Config::parse_keeping(shown.to_string().as_bytes(), &config).ok().map(|(kept, _)| kept) == Some(config.clone()));
	let mut moved = shown.clone();
	moved["xray"]["inbounds"][0]["tag"] = json!("elsewhere");
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("a marker with nothing to keep was taken");
	assert_eq!(report.errors[0].path, "xray.inbounds[0].clients[0].secret");
	assert!(!report.errors[0].message.contains(UUID));
	let mut spelled = node();
	spelled["xray"]["inbounds"][0]["clients"][0]["secret"] = json!(REDACTED);
	assert!(check_marker(&spelled), "a marker passed validation as a secret");
}

fn check_marker(doc: &Value) -> bool {
	let Ok(config) = Config::parse(doc.to_string().as_bytes()) else {return true};
	!config.validate(false).errors.is_empty()
}

#[test]
fn a_change_of_the_section_is_a_change() {
	let (old, new) = (Config::parse(node().to_string().as_bytes()).unwrap(), {
		let mut doc = node();
		doc["xray"]["inbounds"][0]["clients"][0]["secret"] = json!("00000000-0000-0000-0000-000000000000");
		Config::parse(doc.to_string().as_bytes()).unwrap()
	});
	assert!(veilway_core::config::Diff::between(&old, &new, time::OffsetDateTime::now_utc()).xray);
	assert!(!veilway_core::config::Diff::between(&old, &old, time::OffsetDateTime::now_utc()).xray);
}
