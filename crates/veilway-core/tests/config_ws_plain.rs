//! The `ws-plain` transport in config version 1 (transports page, "`ws-plain`: WebSocket without TLS"): each rule of the page, by changing one thing in a document that is good.
use serde_json::{json, Value};
use veilway_core::config::{Config, Diff, Report, Transport};

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

const AT: &str = "inbounds[0].transports[0]";

/// A `veilway` inbound `home` whose one transport is a `ws-plain` one behind a reverse proxy on loopback, with its own two keys and no `transport_keys` of the inbound, and one user with one device.
fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": key(0x11), "address": ["10.7.0.1/24"], "upgrade_cookie": "sid", "transports": [
			{"type": "ws-plain", "listen": "127.0.0.1:8081", "path": "/assets/plain-3b9e41aa.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "client_address_header": "X-Forwarded-For", "transport_keys": [key(0x71), key(0x72)]}
		]}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "phone", "public_key": key(0x21), "transport_secrets": [key(0x31)], "addresses": ["10.7.0.2"]}]}]
	})
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
	let mut doc = node();
	edit(&mut doc);
	doc
}

fn parse(doc: &Value) -> Result<Config, veilway_core::config::Diagnostic> {Config::parse(doc.to_string().as_bytes())}

fn check(doc: &Value) -> Report {parse(doc).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn error_at(path: &str, edit: impl FnOnce(&mut Value)) {
	let report = check(&with(edit));
	assert!(report.errors.iter().any(|e| e.path == path), "expected an error at {path}, got {report:#?}");
}

#[track_caller]
fn refused(path: &str, edit: impl FnOnce(&mut Value)) -> String {
	match parse(&with(edit)) {
		Err(e) if e.path == path => e.message,
		other => panic!("expected a parse error at {path}, got {other:?}"),
	}
}

fn transport(doc: &mut Value) -> &mut Value {&mut doc["inbounds"][0]["transports"][0]}

#[test]
fn a_ws_plain_transport_validates_and_reads_back() {
	let report = check(&node());
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	let config = parse(&node()).unwrap();
	let Transport::WsPlain {path, transport_keys, ..} = &config.inbounds[0].transports[0] else {panic!("not a ws-plain transport")};
	assert_eq!((path.as_str(), transport_keys.iter().map(|key| key.0).collect::<Vec<_>>()), ("/assets/plain-3b9e41aa.js", vec![[0x71; 32], [0x72; 32]]));
	// It is a transport of the proxy path that takes a proof and needs the replay memory, but not under the inbound's keys, and it reads the inbound's cookie name.
	let inbound = &config.inbounds[0];
	assert!(inbound.plain() && inbound.obfuscated() && inbound.upgraded() && !inbound.proved() && !inbound.enveloped() && inbound.transports[0].proxied().is_some() && inbound.transport_public_key().is_none());
	assert_eq!(Config::parse(serde_json::to_string(&config).unwrap().as_bytes()).unwrap(), config);
}

#[test]
fn it_needs_its_own_keys_and_the_cookie_name_and_none_of_the_inbounds_keys() {
	error_at("inbounds[0].upgrade_cookie", |doc| {doc["inbounds"][0].as_object_mut().unwrap().remove("upgrade_cookie");});
	let report = check(&with(|doc| doc["inbounds"][0]["transport_keys"] = json!([key(0x73)])));
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == "inbounds[0].transport_keys"), "{report:#?}");
	error_at(&format!("{AT}.transport_keys"), |doc| transport(doc)["transport_keys"] = json!([]));
	error_at(&format!("{AT}.transport_keys"), |doc| transport(doc)["transport_keys"] = json!([key(0x71), key(0x72), key(0x73)]));
	error_at(&format!("{AT}.transport_keys[1]"), |doc| transport(doc)["transport_keys"] = json!([key(0x71), key(0x71)]));
	// Keys of the node belong to one use: not a WireGuard key, not the inbound's transport key, not another transport's.
	error_at(&format!("{AT}.transport_keys[0]"), |doc| transport(doc)["transport_keys"] = json!([key(0x11)]));
	error_at(&format!("{AT}.transport_keys[0]"), |doc| {
		doc["inbounds"][0]["transport_keys"] = json!([key(0x71)]);
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws", "listen": "127.0.0.1:8082", "path": "/assets/live-7c1d0a52.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"]}));
	});
	error_at("inbounds[0].transports[1].transport_keys[1]", |doc| {
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws-plain", "listen": "127.0.0.1:8082", "path": "/assets/plain-4c8f52bb.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "transport_keys": [key(0x74), key(0x72)]}));
	});
	let report = check(&with(|doc| {
		doc["inbounds"][0]["transport_keys"] = json!([key(0x75)]);
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws", "listen": "127.0.0.1:8082", "path": "/assets/live-7c1d0a52.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"]}));
	}));
	assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn its_keys_and_the_others_keys_belong_to_their_own_types() {
	for (name, value) in [("transport_key", json!(key(0x73))), ("site", json!({"host": "www.example.com", "acknowledged": true})), ("tls", json!({"self_signed": true})), ("shape", json!({"up": {"method": "GET", "in": "query"}, "down": {"mode": "poll"}})), ("http2", json!("on"))] {
		let message = refused(AT, |doc| transport(doc)[name] = value);
		assert!(message.contains(&format!("no key `{name}` when type is `ws-plain`")), "{name}: {message}");
	}
	let message = refused(AT, |doc| {transport(doc).as_object_mut().unwrap().remove("transport_keys");});
	assert!(message.contains("missing required key `transport_keys`"), "{message}");
	for kind in ["udp", "udp-obfs"] {
		let message = refused(AT, |doc| *transport(doc) = json!({"type": kind, "listen": "0.0.0.0:51820", "transport_keys": [key(0x73)]}));
		assert!(message.contains("no key `transport_keys`"), "{kind}: {message}");
	}
	for kind in ["ws", "fronted", "fronted-shaped"] {
		let message = refused(AT, |doc| {
			*transport(doc) = json!({"type": kind, "listen": "127.0.0.1:8082", "path": "/assets/live-7c1d0a52.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "transport_keys": [key(0x73)]});
		});
		assert!(message.contains("no key `transport_keys`"), "{kind}: {message}");
	}
}

#[test]
fn it_is_held_to_the_rules_of_the_proxy_path() {
	error_at(&format!("{AT}.trusted_proxies"), |doc| transport(doc)["trusted_proxies"] = json!([]));
	error_at(&format!("{AT}.path"), |doc| transport(doc)["path"] = json!("/short"));
	error_at(&format!("{AT}.path"), |doc| transport(doc)["path"] = json!("/assets/../plain-3b9e41aa.js"));
	let report = check(&with(|doc| {transport(doc).as_object_mut().unwrap().remove("client_address_header");}));
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == format!("{AT}.client_address_header")), "{report:#?}");
	// A wireguard inbound has no devices with transport secrets to seal a proof with.
	error_at(&format!("{AT}.type"), |doc| doc["inbounds"][0]["type"] = json!("wireguard"));
}

#[test]
fn its_path_is_not_the_path_of_a_covered_transport_of_the_inbound() {
	let covered = |kind: &str, path: &str| json!({"type": kind, "listen": "127.0.0.1:8082", "path": path, "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"]});
	for kind in ["ws", "fronted"] {
		error_at(&format!("{AT}.path"), |doc| {
			doc["inbounds"][0]["transport_keys"] = json!([key(0x75)]);
			doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(covered(kind, "/assets/plain-3b9e41aa.js"));
		});
	}
	let report = check(&with(|doc| {
		doc["inbounds"][0]["transport_keys"] = json!([key(0x75)]);
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(covered("ws", "/assets/live-7c1d0a52.js"));
	}));
	assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn its_path_is_not_the_path_of_a_covered_transport_of_another_inbound_either() {
	let other = |path: &str| json!({"tag": "other", "type": "veilway", "private_key": key(0x12), "address": ["10.8.0.1/24"], "upgrade_cookie": "sid", "transport_keys": [key(0x76)], "transports": [{"type": "ws", "listen": "127.0.0.1:8082", "path": path, "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"]}]});
	error_at(&format!("{AT}.path"), |doc| doc["inbounds"].as_array_mut().unwrap().push(other("/assets/plain-3b9e41aa.js")));
	let report = check(&with(|doc| doc["inbounds"].as_array_mut().unwrap().push(other("/assets/live-7c1d0a52.js"))));
	assert!(!report.errors.iter().any(|e| e.path == format!("{AT}.path")), "{report:#?}");
}

#[test]
fn it_never_shares_a_listener_with_a_transport_that_is_not_ws_plain() {
	let on_same = |kind: &str| json!({"type": kind, "listen": "127.0.0.1:8081", "path": "/assets/live-7c1d0a52.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "client_address_header": "X-Forwarded-For"});
	for kind in ["ws", "fronted"] {
		let report = check(&with(|doc| {
			doc["inbounds"][0]["transport_keys"] = json!([key(0x75)]);
			doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(on_same(kind));
		}));
		assert!(report.errors.iter().any(|e| e.path == "inbounds[0].transports[1].listen" && e.message.contains("ws-plain")), "{kind}: {report:#?}");
	}
	let report = check(&with(|doc| {
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws-plain", "listen": "127.0.0.1:8081", "path": "/assets/plain-4c8f52bb.js", "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "client_address_header": "X-Forwarded-For", "transport_keys": [key(0x74)]}));
	}));
	assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn a_change_of_its_keys_is_a_change_of_that_transport_and_nothing_else() {
	let (old, new) = (parse(&node()).unwrap(), parse(&with(|doc| transport(doc)["transport_keys"] = json!([key(0x73), key(0x71)]))).unwrap());
	let diff = Diff::between(&old, &new, time::OffsetDateTime::now_utc());
	let [change] = &diff.inbound_changes[..] else {panic!("{diff:?}")};
	assert_eq!((change.restart, change.transports_stopped.clone(), change.transports_started.clone()), (false, vec![0], vec![0]));
}

#[test]
fn its_keys_are_secrets_that_markers_stand_for() {
	let config = parse(&node()).unwrap();
	let shown = config.redacted();
	let markers = shown["inbounds"][0]["transports"][0]["transport_keys"].as_array().unwrap();
	assert!(markers.iter().all(|marker| marker.as_str().unwrap().starts_with("<redacted:")) && !shown.to_string().contains(&key(0x71)) && !shown.to_string().contains(&key(0x72)));
	assert!(Config::parse(shown.to_string().as_bytes()).is_err());
	let (kept, _) = Config::parse_keeping(shown.to_string().as_bytes(), &config).unwrap();
	assert_eq!(kept, config);
	let mut reordered = shown.clone();
	reordered["inbounds"][0]["transports"][0]["transport_keys"] = json!([markers[1], markers[0]]);
	let (kept, _) = Config::parse_keeping(reordered.to_string().as_bytes(), &config).unwrap();
	assert_eq!(kept, parse(&with(|doc| transport(doc)["transport_keys"] = json!([key(0x72), key(0x71)]))).unwrap());
	let mut moved = shown.clone();
	moved["inbounds"][0]["tag"] = json!("elsewhere");
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("a marker with nothing to keep was taken");
	assert!(report.errors.iter().any(|e| e.path == format!("{AT}.transport_keys[0]")), "{report:?}");
}
