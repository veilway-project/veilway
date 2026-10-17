//! The `faketls` transport in config version 1 (borrowed-site page, "Config and profile fields"): each rule of the page, by changing one thing in a document that is good.
use serde_json::{json, Value};
use veilway_core::config::{Config, Diff, Report, Transport, REDACTED};

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

const AT: &str = "inbounds[0].transports[0]";

/// A `veilway` inbound `home` whose one transport is a `faketls` one for `www.example.com`, with the site's address given, and one user with one device.
fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [
			{"type": "faketls", "listen": "203.0.113.5:443", "transport_key": key(0x71), "site": {"host": "www.example.com", "address": "198.51.100.9:443", "acknowledged": true}}
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
fn a_faketls_transport_validates_and_reads_back() {
	let report = check(&node());
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	let config = parse(&node()).unwrap();
	let Transport::FakeTls {listen, site, transport_key, limits} = &config.inbounds[0].transports[0] else {panic!("not a faketls transport")};
	assert_eq!((listen.0.to_string(), site.host.as_str(), site.names.as_ref(), site.port, site.address.map(|address| address.0.to_string()), site.acknowledged, transport_key.0, limits.is_none()), ("203.0.113.5:443".to_string(), "www.example.com", None, None, Some("198.51.100.9:443".to_string()), true, [0x71; 32], true));
	assert!(config.inbounds[0].borrowed() && config.inbounds[0].obfuscated() && !config.inbounds[0].proved() && !config.inbounds[0].enveloped());
	assert_eq!(Config::parse(serde_json::to_string(&config).unwrap().as_bytes()).unwrap(), config);
	let full = with(|doc| {
		doc["inbounds"][0]["transports"][0]["site"] = json!({"host": "www.example.com", "names": ["example.com", "cdn.example.com"], "port": 8443, "address": "198.51.100.9:8443", "acknowledged": true});
		doc["inbounds"][0]["transports"][0]["limits"] = json!({"relayed": 64, "site_rate": 4});
	});
	let report = check(&full);
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	assert_eq!(Config::parse(serde_json::to_string(&parse(&full).unwrap()).unwrap().as_bytes()).unwrap(), parse(&full).unwrap());
}

#[test]
fn a_site_without_an_address_is_resolved_at_start_and_said_so() {
	let report = check(&with(|doc| {transport(doc)["site"].as_object_mut().unwrap().remove("address");}));
	assert!(report.errors.is_empty() && report.warnings.iter().map(|warning| warning.path.as_str()).collect::<Vec<_>>() == [format!("{AT}.site.address")], "{report:#?}");
}

#[test]
fn the_keys_of_the_other_transports_are_refused_on_it_and_its_own_on_the_others() {
	for (key, value) in [("path", json!("/proof-path-xx")), ("tls", json!({"self_signed": true})), ("decoy", json!({"origin": "http://127.0.0.1:8080"})), ("trusted_proxies", json!(["127.0.0.1"])), ("client_address_header", json!("X-Forwarded-For")), ("shape", json!({"up": {"method": "GET", "in": "query"}, "down": {"mode": "poll"}})), ("http2", json!("on"))] {
		let message = refused(AT, |doc| transport(doc)[key] = value);
		assert!(message.contains(&format!("no key `{key}` when type is `faketls`")), "{key}: {message}");
	}
	for key in ["site", "transport_key"] {
		let message = refused(AT, |doc| {transport(doc).as_object_mut().unwrap().remove(key);});
		assert!(message.contains(&format!("missing required key `{key}`")), "{key}: {message}");
	}
	for kind in ["udp", "udp-obfs"] {
		let message = refused(AT, |doc| *transport(doc) = json!({"type": kind, "listen": "0.0.0.0:51820", "site": {"host": "www.example.com", "acknowledged": true}}));
		assert!(message.contains("no key `site`"), "{kind}: {message}");
		let message = refused(AT, |doc| *transport(doc) = json!({"type": kind, "listen": "0.0.0.0:51820", "transport_key": key(0x71)}));
		assert!(message.contains("no key `transport_key`"), "{kind}: {message}");
	}
	let message = refused(AT, |doc| *transport(doc) = json!({"type": "ws", "listen": "127.0.0.1:8080", "path": "/wg", "site": {"host": "www.example.com", "acknowledged": true}}));
	assert!(message.contains("no key `site`"), "{message}");
	let message = refused(AT, |doc| *transport(doc) = json!({"type": "tls", "listen": "0.0.0.0:443", "path": "/proof-path-xx", "tls": {"self_signed": true}, "decoy": {"origin": "http://127.0.0.1:8080"}, "transport_key": key(0x71)}));
	assert!(message.contains("no key `transport_key`"), "{message}");
	assert!(refused(&format!("{AT}.site"), |doc| transport(doc)["site"]["future"] = json!(1)).contains("unknown key"));
	assert!(refused(&format!("{AT}.limits"), |doc| transport(doc)["limits"] = json!({"relayed": 8, "burst": 1})).contains("unknown key"));
}

#[test]
fn the_site_is_acknowledged_and_named_well() {
	error_at(&format!("{AT}.site.acknowledged"), |doc| transport(doc)["site"]["acknowledged"] = json!(false));
	assert!(refused(&format!("{AT}.site"), |doc| {transport(doc)["site"].as_object_mut().unwrap().remove("acknowledged");}).contains("missing required key `acknowledged`"));
	for host in ["", "WWW.example.com", "www.example.com.", "203.0.113.5", "www_example.com", "-bad.example.com", "a..b", "https://www.example.com"] {
		error_at(&format!("{AT}.site.host"), |doc| transport(doc)["site"]["host"] = json!(host));
	}
	error_at(&format!("{AT}.site.host"), |doc| transport(doc)["site"]["host"] = json!(format!("{}.example.com", "a".repeat(64))));
	error_at(&format!("{AT}.site.names"), |doc| transport(doc)["site"]["names"] = json!(["a.example", "b.example", "c.example", "d.example", "e.example"]));
	let four = check(&with(|doc| transport(doc)["site"]["names"] = json!(["a.example", "b.example", "c.example", "d.example"])));
	assert!(four.errors.is_empty(), "{four:#?}");
	error_at(&format!("{AT}.site.names[1]"), |doc| transport(doc)["site"]["names"] = json!(["a.example", "Not A Name"]));
	error_at(&format!("{AT}.site.names[1]"), |doc| transport(doc)["site"]["names"] = json!(["a.example", "a.example"]));
	error_at(&format!("{AT}.site.names[0]"), |doc| transport(doc)["site"]["names"] = json!(["www.example.com"]));
	error_at(&format!("{AT}.site.port"), |doc| transport(doc)["site"]["port"] = json!(0));
	assert!(refused(&format!("{AT}.site.port"), |doc| transport(doc)["site"]["port"] = json!(70000)).contains("integer"));
	assert!(refused(&format!("{AT}.site.address"), |doc| transport(doc)["site"]["address"] = json!("www.example.com:443")).contains("address"));
}

#[test]
fn a_site_that_is_the_node_itself_is_a_loop() {
	error_at(&format!("{AT}.site.address"), |doc| transport(doc)["site"]["address"] = json!("203.0.113.5:443"));
	error_at(&format!("{AT}.site.address"), |doc| {
		transport(doc)["listen"] = json!("0.0.0.0:443");
		transport(doc)["site"]["address"] = json!("127.0.0.1:443");
	});
	// The same host on another port is another service.
	let report = check(&with(|doc| transport(doc)["site"]["address"] = json!("203.0.113.5:8443")));
	assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn the_key_of_a_faketls_transport_is_its_own() {
	error_at(&format!("{AT}.transport_key"), |doc| {
		doc["inbounds"][0]["transport_keys"] = json!([key(0x71)]);
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "tls", "listen": "203.0.113.5:8443", "path": "/proof-path-xx", "tls": {"self_signed": true}, "decoy": {"origin": "http://127.0.0.1:8080"}}));
		doc["inbounds"][0]["upgrade_cookie"] = json!("sid");
	});
	error_at("inbounds[0].transports[1].transport_key", |doc| {
		let second = json!({"type": "faketls", "listen": "203.0.113.5:8443", "transport_key": key(0x71), "site": {"host": "www.example.org", "address": "198.51.100.10:443", "acknowledged": true}});
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(second);
	});
	error_at(&format!("{AT}.transport_key"), |doc| transport(doc)["transport_key"] = json!(key(0x11)));
	error_at(&format!("{AT}.transport_key"), |doc| transport(doc)["transport_key"] = json!(key(0x21)));
	error_at("inbounds[1].transports[0].transport_key", |doc| {
		let mut other = doc["inbounds"][0].clone();
		other["tag"] = json!("office");
		other["private_key"] = json!(key(0x12));
		other["address"] = json!(["10.8.0.1/24"]);
		other["transports"][0]["listen"] = json!("203.0.113.6:443");
		doc["inbounds"].as_array_mut().unwrap().push(other);
		doc["inbounds"][1]["transports"][0]["transport_key"] = json!(key(0x72));
		doc["inbounds"][0]["transport_keys"] = json!([key(0x72)]);
	});
	let report = check(&with(|doc| {
		let second = json!({"type": "faketls", "listen": "203.0.113.5:8443", "transport_key": key(0x72), "site": {"host": "www.example.org", "address": "198.51.100.10:443", "acknowledged": true}});
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(second);
	}));
	assert!(report.errors.is_empty(), "{report:#?}");
}

#[test]
fn a_faketls_listener_shares_its_address_with_no_other_transport() {
	let conflicts = |edit: &dyn Fn(&mut Value)| {
		let report = check(&with(|doc| {
			doc["inbounds"][0]["upgrade_cookie"] = json!("sid");
			doc["inbounds"][0]["transport_keys"] = json!([key(0x72)]);
			edit(doc);
		}));
		report.errors.iter().any(|error| error.path == "inbounds[0].transports[1].listen" && error.message.contains("faketls"))
	};
	let tls = json!({"type": "tls", "listen": "203.0.113.5:443", "path": "/proof-path-xx", "tls": {"self_signed": true}, "decoy": {"origin": "http://127.0.0.1:8080"}});
	assert!(conflicts(&|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(tls.clone())));
	let wildcard = json!({"type": "tls", "listen": "0.0.0.0:443", "path": "/proof-path-xx", "tls": {"self_signed": true}, "decoy": {"origin": "http://127.0.0.1:8080"}});
	assert!(conflicts(&|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(wildcard.clone())));
	let again = json!({"type": "faketls", "listen": "203.0.113.5:443", "transport_key": key(0x73), "site": {"host": "www.example.org", "address": "198.51.100.10:443", "acknowledged": true}});
	assert!(conflicts(&|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(again.clone())));
	// A UDP socket on the same port is another socket.
	let obfs = json!({"type": "udp-obfs", "listen": "203.0.113.5:443"});
	assert!(!conflicts(&|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(obfs.clone())));
}

#[test]
fn faketls_is_a_transport_of_a_veilway_inbound() {
	error_at(&format!("{AT}.type"), |doc| doc["inbounds"][0]["type"] = json!("wireguard"));
}

#[test]
fn the_limits_are_the_two_it_takes() {
	for key in ["sessions", "undecided", "undecided_per_source", "proxy_connections", "decoy_requests_per_source", "fronted_sessions", "shaped_sessions"] {
		error_at(&format!("{AT}.limits.{key}"), |doc| transport(doc)["limits"] = json!({key: 8}));
	}
	for (key, value) in [("relayed", 0), ("relayed", 65537), ("site_rate", 0), ("site_rate", 1025)] {
		error_at(&format!("{AT}.limits.{key}"), |doc| transport(doc)["limits"] = json!({key: value}));
	}
	for (key, value) in [("relayed", 1), ("relayed", 65536), ("site_rate", 1), ("site_rate", 1024)] {
		let report = check(&with(|doc| transport(doc)["limits"] = json!({key: value})));
		assert!(report.errors.is_empty(), "{key}: {report:#?}");
	}
	assert!(refused(&format!("{AT}.limits.site_rate"), |doc| transport(doc)["limits"] = json!({"site_rate": -1})).contains("integer"));
	// `site_rate` is a limit of the connections to the site, and no other transport has one.
	error_at("inbounds[0].transports[1].limits.site_rate", |doc| {
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "udp-obfs", "listen": "203.0.113.5:51820", "limits": {"site_rate": 4}}));
	});
	error_at("inbounds[0].transports[1].limits.site_rate", |doc| {
		doc["inbounds"][0]["upgrade_cookie"] = json!("sid");
		doc["inbounds"][0]["transport_keys"] = json!([key(0x72)]);
		doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "tls", "listen": "203.0.113.5:8443", "path": "/proof-path-xx", "tls": {"self_signed": true}, "decoy": {"origin": "http://127.0.0.1:8080"}, "limits": {"site_rate": 4}}));
	});
}

#[test]
fn the_key_is_a_secret_that_a_marker_stands_for() {
	let config = parse(&node()).unwrap();
	let shown = config.redacted();
	let marker = shown["inbounds"][0]["transports"][0]["transport_key"].as_str().unwrap().to_string();
	assert!(marker.starts_with("<redacted:") && !shown.to_string().contains(&key(0x71)), "{marker}");
	assert!(Config::parse(shown.to_string().as_bytes()).is_err(), "a marker was taken for a key without a running config to take it from");
	let (kept, _) = Config::parse_keeping(shown.to_string().as_bytes(), &config).unwrap();
	assert_eq!(kept, config);
	let mut moved = shown.clone();
	moved["inbounds"][0]["tag"] = json!("elsewhere");
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("a marker with nothing to keep was taken");
	assert_eq!(report.errors.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), [format!("{AT}.transport_key"), "inbounds[0].private_key".to_string()]);
	assert!(report.errors.iter().all(|e| !e.message.contains(&key(0x71))), "{report:?}");
	let mut wrong = shown.clone();
	wrong["inbounds"][0]["transports"][0]["transport_key"] = json!(REDACTED);
	assert!(Config::parse_keeping(wrong.to_string().as_bytes(), &config).is_err());
	// A new key replaces the old one, and the change is a stopped transport and a started one.
	let other = parse(&with(|doc| transport(doc)["transport_key"] = json!(key(0x72)))).unwrap();
	let diff = Diff::between(&config, &other, time::OffsetDateTime::UNIX_EPOCH);
	assert_eq!((diff.inbound_changes[0].transports_stopped.clone(), diff.inbound_changes[0].transports_started.clone()), (vec![0], vec![0]));
}
