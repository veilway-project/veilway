//! Config v1, `upstreams` and the `upstream` exit backend: the document is checked, and nothing runs.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use veilway_core::config::{Backend, Config, Report, REDACTED};
use veilway_proto::subscription::link::Link;

/// An obviously fake key: one byte repeated.
fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn sealed(bytes: &[u8]) -> String {URL_SAFE_NO_PAD.encode(bytes)}

/// A native link to a documentation host with made-up keys, and the fingerprint of its signing key.
fn link(signing: u8, token: u8) -> (String, String) {
	let text = format!("veilway://sub/provider.example.org/sub#v1.{}.{}.{}", sealed(&[signing; 32]), sealed(&[&[1u8][..], &[9u8; 32][..]].concat()), sealed(&[token; 16]));
	let Ok(Link::Native(native)) = Link::parse(&text) else {panic!("the test link does not read")};
	(text, native.key().fingerprint().to_string())
}

fn secret(byte: u8) -> String {sealed(&[byte; 16])}

fn upstream(tag: &str, signing: u8, token: u8, device: u8) -> Value {
	let (text, fingerprint) = link(signing, token);
	json!({"tag": tag, "link": text, "signing_key": fingerprint, "private_key": key(device), "device_secret": secret(device)})
}

fn good() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
		"outbounds": [
			{"tag": "plain", "type": "direct"},
			{"tag": "proxy", "type": "socks5", "server": "127.0.0.1:1080"}
		],
		"exits": [
			{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}},
			{"tag": "abroad", "backend": {"type": "upstream", "upstream": "other"}}
		],
		"routing": {"default": "main", "rules": [
			{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"},
			{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"},
			{"tag": "streaming", "domain": ["*.media.example.org"], "action": {"exit": "abroad"}}
		]},
		"upstreams": [upstream("other", 7, 3, 0x41)],
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}]
	})
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
	let mut doc = good();
	edit(&mut doc);
	doc
}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn error_at(path: &str, edit: impl FnOnce(&mut Value)) {
	let report = check(&with(edit));
	assert!(report.errors.iter().any(|e| e.path == path), "expected an error at {path}, got {report:#?}");
}

#[track_caller]
fn warning_at(path: &str, edit: impl FnOnce(&mut Value)) {
	let report = check(&with(edit));
	assert!(report.errors.is_empty() && report.warnings.iter().any(|w| w.path == path), "expected only a warning at {path}, got {report:#?}");
}

#[test]
fn a_valid_upstream_and_its_exit_are_clean() {
	let report = check(&good());
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	let config = Config::parse(good().to_string().as_bytes()).unwrap();
	assert_eq!(config.upstreams.len(), 1);
	assert!(matches!(&config.exits[1].backend, Backend::Upstream(exit) if exit.upstream == "other"));
	assert!(config.upstreams[0].on() && config.upstreams[0].allow.is_empty());
}

#[test]
fn the_fully_written_upstream_is_clean_and_the_key_may_be_spelled_either_way() {
	let report = check(&with(|d| {
		d["upstreams"][0]["profile"] = json!("main-profile");
		d["upstreams"][0]["exit"] = json!("de");
		d["upstreams"][0]["via"] = json!("proxy");
		d["upstreams"][0]["allow"] = json!(["no_cover", "exposed"]);
		d["upstreams"][0]["allow_private"] = json!(true);
		d["upstreams"][0]["enabled"] = json!(true);
		d["upstreams"][0]["signing_key"] = json!(sealed(&[7; 32]));
	}));
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	let via_direct = check(&with(|d| d["upstreams"][0]["via"] = json!("plain")));
	assert!(via_direct.errors.is_empty(), "{via_direct:#?}");
}

#[test]
fn the_link_must_be_a_native_veilway_sub_link() {
	let (text, _) = link(7, 3);
	error_at("upstreams[0].link", |d| d["upstreams"][0]["link"] = json!(text.replace("veilway://sub/", "veilway://sub-plain/")));
	error_at("upstreams[0].link", |d| d["upstreams"][0]["link"] = json!(format!("https://{}", text.trim_start_matches("veilway://sub/"))));
	error_at("upstreams[0].link", |d| d["upstreams"][0]["link"] = json!("https://provider.example.org/list"));
	error_at("upstreams[0].link", |d| d["upstreams"][0]["link"] = json!(format!("veilway://doc#v1.{}.e30", sealed(&[7; 32]))));
	error_at("upstreams[0].link", |d| d["upstreams"][0]["link"] = json!("veilway://sub/provider.example.org/sub#v1.short"));
	error_at("upstreams[0].link", |d| d["upstreams"][0]["link"] = json!(REDACTED));
}

#[test]
fn the_link_key_must_be_the_confirmed_one() {
	let (_, other) = link(8, 3);
	error_at("upstreams[0].signing_key", |d| d["upstreams"][0]["signing_key"] = json!(other));
	error_at("upstreams[0].signing_key", |d| d["upstreams"][0]["signing_key"] = json!(sealed(&[8; 32])));
	error_at("upstreams[0].signing_key", |d| d["upstreams"][0]["signing_key"] = json!("not a fingerprint"));
}

#[test]
fn the_keys_are_32_bytes_and_the_device_secret_16() {
	error_at("upstreams[0].device_secret", |d| d["upstreams"][0]["device_secret"] = json!(sealed(&[1; 15])));
	error_at("upstreams[0].device_secret", |d| d["upstreams"][0]["device_secret"] = json!(sealed(&[1; 32])));
	error_at("upstreams[0].device_secret", |d| d["upstreams"][0]["device_secret"] = json!(REDACTED));
	assert!(Config::parse(with(|d| d["upstreams"][0]["private_key"] = json!(sealed(&[1; 31]))).to_string().as_bytes()).is_err());
	assert!(Config::parse(with(|d| d["upstreams"][0]["private_key"] = json!(veilway_wg::encode_key(&[0; 32]))).to_string().as_bytes()).is_err());
}

#[test]
fn no_two_upstreams_share_a_token_a_device_or_a_tag() {
	error_at("upstreams[1].link", |d| {
		d["upstreams"].as_array_mut().unwrap().push(upstream("second", 7, 3, 0x42));
	});
	error_at("upstreams[1].private_key", |d| {
		d["upstreams"].as_array_mut().unwrap().push(upstream("second", 8, 4, 0x41));
	});
	error_at("upstreams[1].tag", |d| {
		d["upstreams"].as_array_mut().unwrap().push(upstream("other", 8, 4, 0x42));
	});
	let report = check(&with(|d| d["upstreams"].as_array_mut().unwrap().push(upstream("second", 8, 4, 0x42))));
	assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn at_most_eight_upstreams() {
	error_at("upstreams", |d| {
		for i in 0..8u8 {d["upstreams"].as_array_mut().unwrap().push(upstream(&format!("more-{i}"), 20 + i, 20 + i, 0x50 + i))}
	});
}

#[test]
fn tags_are_checked_like_other_tags() {
	error_at("upstreams[0].tag", |d| d["upstreams"][0]["tag"] = json!("Bad Tag"));
	error_at("upstreams[0].tag", |d| d["upstreams"][0]["tag"] = json!("direct"));
	error_at("upstreams[0].profile", |d| d["upstreams"][0]["profile"] = json!("Not A Profile"));
	error_at("upstreams[0].exit", |d| d["upstreams"][0]["exit"] = json!("x".repeat(65)));
}

#[test]
fn via_names_an_outbound_and_the_classes_are_listed_once() {
	error_at("upstreams[0].via", |d| d["upstreams"][0]["via"] = json!("nothing"));
	error_at("upstreams[0].allow[1]", |d| d["upstreams"][0]["allow"] = json!(["exposed", "exposed"]));
	assert!(Config::parse(with(|d| d["upstreams"][0]["allow"] = json!(["loud"])).to_string().as_bytes()).is_err());
}

#[test]
fn an_exit_names_one_upstream_that_exists_and_no_other_exit_shares_it() {
	error_at("exits[1].backend.upstream", |d| d["exits"][1]["backend"]["upstream"] = json!("missing"));
	error_at("exits[2].backend.upstream", |d| d["exits"].as_array_mut().unwrap().push(json!({"tag": "twin", "backend": {"type": "upstream", "upstream": "other"}})));
	assert!(Config::parse(with(|d| d["exits"][1]["backend"] = json!({"type": "upstream"})).to_string().as_bytes()).is_err());
	assert!(Config::parse(with(|d| d["exits"][1]["backend"]["links"] = json!(["a"])).to_string().as_bytes()).is_err());
	assert!(Config::parse(with(|d| d["exits"][0]["backend"]["upstream"] = json!("other")).to_string().as_bytes()).is_err());
	assert!(Config::parse(with(|d| d["exits"][1]["backend"]["outbound"] = json!("plain")).to_string().as_bytes()).is_err());
}

#[test]
fn an_upstream_without_an_exit_and_an_exit_without_a_rule_are_warnings() {
	warning_at("upstreams[0]", |d| {
		d["exits"].as_array_mut().unwrap().pop();
		d["routing"]["rules"].as_array_mut().unwrap().pop();
	});
	warning_at("exits[1]", |d| {
		d["routing"]["rules"].as_array_mut().unwrap().pop();
	});
	let report = check(&with(|d| d["routing"]["default"] = json!("abroad")));
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
}

#[test]
fn a_node_without_an_isolation_rule_gets_the_warning_it_always_got() {
	warning_at("routing.rules", |d| {
		d["routing"]["rules"].as_array_mut().unwrap().remove(0);
	});
}

#[test]
fn a_link_may_not_leave_through_an_upstream() {
	let report = check(&with(|d| {
		d["inbounds"].as_array_mut().unwrap().push(json!({"tag": "peers", "type": "veilway", "private_key": key(0x13), "address": ["10.9.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51821"}]}));
		d["links"] = json!([{"tag": "in", "id": "AAECAwQFBgcICQoLDA0ODw", "direction": "forward", "addresses": {"dialler": ["10.9.0.2"]}, "transport_secret": key(0x61), "inbound": "peers", "public_key": key(0x62), "exits": ["abroad"]}]);
	}));
	assert!(report.errors.iter().any(|e| e.path == "links[0].exits[0]"), "{report:#?}");
}

#[test]
fn a_disabled_upstream_is_validated_all_the_same() {
	let report = check(&with(|d| {
		d["upstreams"][0]["enabled"] = json!(false);
		d["upstreams"][0]["signing_key"] = json!(link(8, 3).1);
	}));
	assert!(report.errors.iter().any(|e| e.path == "upstreams[0].signing_key"), "{report:#?}");
}

#[test]
fn the_secrets_are_markers_in_what_the_api_shows_and_never_in_debug_output() {
	let config = Config::parse(good().to_string().as_bytes()).unwrap();
	let (text, _) = link(7, 3);
	let (shown, saved) = (config.redacted().to_string(), serde_json::to_string(&config).unwrap());
	for secret in [text.as_str(), key(0x41).as_str(), secret(0x41).as_str(), sealed(&[3; 16]).as_str()] {
		assert!(saved.contains(secret) && !shown.contains(secret), "{secret} is in the redacted document, or missing from the saved one");
	}
	assert_eq!(config.redacted()["upstreams"][0]["link"], REDACTED);
	assert_eq!(config.redacted()["upstreams"][0]["private_key"], REDACTED);
	assert_eq!(config.redacted()["upstreams"][0]["device_secret"], REDACTED);
	assert_eq!(config.redacted()["upstreams"][0]["signing_key"], good()["upstreams"][0]["signing_key"]);
	let debug = format!("{config:?} {config:#?}");
	for secret in [text.as_str(), key(0x41).as_str(), secret(0x41).as_str(), sealed(&[3; 16]).as_str(), "sub#v1."] {
		assert!(!debug.contains(secret), "Debug output shows {secret}");
	}
	assert!(debug.contains("<secret>"));
	assert!(Config::parse(shown.as_bytes()).is_err(), "a marker was taken for a secret without a running config to take it from");
}

#[test]
fn markers_come_back_from_the_running_upstream_with_the_same_tag_and_link() {
	let config = Config::parse(good().to_string().as_bytes()).unwrap();
	let shown = config.redacted().to_string();
	let (kept, spelled) = Config::parse_keeping(shown.as_bytes(), &config).expect("the markers did not come back");
	assert_eq!((kept, spelled), (config.clone(), Vec::new()));
	let mut renamed: Value = serde_json::from_str(&shown).unwrap();
	renamed["upstreams"][0]["tag"] = json!("elsewhere");
	renamed["exits"][1]["backend"]["upstream"] = json!("elsewhere");
	let report = Config::parse_keeping(renamed.to_string().as_bytes(), &config).err().expect("markers with nothing to keep were taken");
	assert_eq!(report.errors.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["upstreams[0].link", "upstreams[0].private_key", "upstreams[0].device_secret"]);
	assert!(report.errors.iter().all(|e| !e.message.contains(&key(0x41)) && !e.message.contains(&secret(0x41))), "{report:?}");
	// Another link is another provider: the device made for the first one is not sent to it.
	let mut moved: Value = serde_json::from_str(&shown).unwrap();
	moved["upstreams"][0]["link"] = json!(link(8, 4).0);
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("the device of one provider was kept for another");
	assert_eq!(report.errors.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["upstreams[0].private_key", "upstreams[0].device_secret"]);
	// A new link with its own keys written out needs no marker at all.
	moved["upstreams"][0]["private_key"] = json!(key(0x42));
	moved["upstreams"][0]["device_secret"] = json!(secret(0x42));
	moved["upstreams"][0]["signing_key"] = json!(link(8, 4).1);
	assert!(Config::parse_keeping(moved.to_string().as_bytes(), &config).is_ok());
}

#[test]
fn a_config_with_upstreams_survives_a_round_trip_and_the_diff_sees_them() {
	let config = Config::parse(good().to_string().as_bytes()).unwrap();
	assert_eq!(Config::parse(serde_json::to_string(&config).unwrap().as_bytes()).unwrap(), config);
	let written = Config::parse(with(|d| {
		d["upstreams"][0]["enabled"] = json!(true);
		d["upstreams"][0]["allow_private"] = json!(false);
	}).to_string().as_bytes()).unwrap();
	let now = time::OffsetDateTime::now_utc();
	assert!(veilway_core::config::Diff::between(&config, &written, now).is_empty());
	let changed = Config::parse(with(|d| d["upstreams"][0]["allow"] = json!(["plain"])).to_string().as_bytes()).unwrap();
	let diff = veilway_core::config::Diff::between(&config, &changed, now);
	assert_eq!(diff.upstreams.changed, ["other"]);
	let gone = Config::parse(with(|d| {
		d["upstreams"] = json!([]);
		d["exits"].as_array_mut().unwrap().pop();
		d["routing"]["rules"].as_array_mut().unwrap().pop();
	}).to_string().as_bytes()).unwrap();
	assert_eq!(veilway_core::config::Diff::between(&config, &gone, now).upstreams.removed, ["other"]);
}
