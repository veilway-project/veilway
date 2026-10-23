//! `enabled` on inbounds and on the transports of an inbound, in config version 1: off is validated like on, and the address stays reserved.
use serde_json::{json, Value};
use veilway_core::config::{Config, Diff, Report, Transport};

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

/// A `veilway` inbound with a `udp` and a `udp-obfs` transport, a `wireguard` inbound with a `ws` one, a proxy inbound and a user with an address in the first.
fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [
			{"tag": "home", "type": "veilway", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "udp-obfs", "listen": "0.0.0.0:51821"}]},
			{"tag": "plain", "type": "wireguard", "private_key": key(0x12), "address": ["10.8.0.1/24"], "transports": [{"type": "ws", "listen": "127.0.0.1:8080", "path": "/ws"}]},
			{"tag": "lan", "type": "socks5", "listen": "127.0.0.1:1080"}
		],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "alice", "exits": "all", "proxy_password": "correct horse battery staple", "devices": [{"name": "laptop", "public_key": key(0x21), "transport_secrets": [key(0x31)], "addresses": ["10.7.0.2"]}]}]
	})
}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[test]
fn enabled_defaults_to_true_and_the_default_written_out_is_the_same_config() {
	let config = Config::parse(node().to_string().as_bytes()).unwrap();
	assert!(config.inbounds.iter().all(|inbound| inbound.on() && inbound.transports.iter().all(Transport::on)) && config.proxies[0].on());
	let mut spelled = node();
	spelled["inbounds"][0]["enabled"] = json!(true);
	spelled["inbounds"][0]["transports"][0]["enabled"] = json!(true);
	spelled["inbounds"][2]["enabled"] = json!(true);
	let spelled = Config::parse(spelled.to_string().as_bytes()).unwrap();
	assert!(spelled.inbounds == config.inbounds && spelled.proxies == config.proxies);
	let now = time::OffsetDateTime::now_utc();
	assert!(Diff::between(&config, &spelled, now).inbound_changes.is_empty());
}

#[test]
fn a_switched_off_inbound_or_transport_validates_and_reads_back() {
	let mut doc = node();
	doc["inbounds"][0]["enabled"] = json!(false);
	doc["inbounds"][1]["transports"][0]["enabled"] = json!(false);
	doc["inbounds"][2]["enabled"] = json!(false);
	let report = check(&doc);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	assert!(!report.warnings.iter().any(|warning| warning.path == "inbounds[0].address"), "{:#?}", report.warnings);
	let config = Config::parse(doc.to_string().as_bytes()).unwrap();
	assert_eq!((config.inbounds[0].on(), config.inbounds[1].on(), config.inbounds[1].transports[0].on(), config.inbounds[0].transports[0].on(), config.proxies[0].on()), (false, true, false, true, false));
	let written: Value = serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
	assert_eq!((&written["inbounds"][0]["enabled"], &written["inbounds"][1]["transports"][0]["enabled"], &written["inbounds"][2]["enabled"], written["inbounds"][1].get("enabled")), (&json!(false), &json!(false), &json!(false), None));
}

#[test]
fn a_switched_off_listener_is_held_to_every_rule_and_keeps_its_address() {
	let mut doc = node();
	doc["inbounds"][0]["transports"][1]["enabled"] = json!(false);
	doc["inbounds"][1]["transports"][0]["enabled"] = json!(false);
	doc["inbounds"][2]["enabled"] = json!(false);
	let mut clash = doc.clone();
	clash["inbounds"][2]["listen"] = json!("127.0.0.1:8080");
	assert!(check(&clash).errors.iter().any(|error| error.path == "inbounds[2].listen"), "a proxy inbound took the address of a transport that is off");
	let mut clash = doc.clone();
	clash["inbounds"][1]["transports"][0]["listen"] = json!("0.0.0.0:51821");
	clash["inbounds"][1]["transports"][0]["type"] = json!("udp");
	clash["inbounds"][1]["transports"][0].as_object_mut().unwrap().remove("path");
	assert!(check(&clash).errors.iter().any(|error| error.path.starts_with("inbounds[1].transports[0]")), "a transport took the address of one that is off");
	let mut off = doc.clone();
	off["inbounds"][1]["enabled"] = json!(false);
	off["inbounds"][1]["address"] = json!(["10.7.0.1/24"]);
	assert!(check(&off).errors.iter().any(|error| error.path.starts_with("inbounds[1]")), "an inbound that is off may overlap another one's pool");
}

#[test]
fn flipping_enabled_is_a_listener_change() {
	let (on, mut off) = (Config::parse(node().to_string().as_bytes()).unwrap(), node());
	off["inbounds"][0]["transports"][1]["enabled"] = json!(false);
	off["inbounds"][1]["enabled"] = json!(false);
	off["inbounds"][2]["enabled"] = json!(false);
	let off = Config::parse(off.to_string().as_bytes()).unwrap();
	let now = time::OffsetDateTime::now_utc();
	let down = Diff::between(&on, &off, now);
	assert_eq!(down.inbounds.changed, ["home", "plain", "lan"]);
	let home = down.inbound_changes.iter().find(|change| change.tag == "home").unwrap();
	assert_eq!((home.restart, home.transports_stopped.clone(), home.transports_started.clone()), (false, vec![1], vec![]));
	let up = Diff::between(&off, &on, now);
	assert_eq!(up.inbounds.changed, ["home", "plain", "lan"]);
}
