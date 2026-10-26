//! Outbounds of type `wireguard`: what makes them valid, which keys and addresses are refused, how their secrets are shown and kept, and what an exit through one may not do.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use veilway_core::config::{Config, Outbound, Report, REDACTED};
use veilway_proto::subscription::link::Link;

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn node(outbound: Value) -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}, {"tag": "chain", "type": "socks5", "server": "192.0.2.50:1080"}, outbound],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "far", "backend": {"type": "netstack", "outbound": "up"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}]
	})
}

fn wireguard() -> Value {json!({"type": "wireguard", "tag": "up", "server": "198.51.100.7:51820", "public_key": key(0x31), "private_key": key(0x32), "addresses": ["10.64.0.2"]})}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn refused(path: &str, edit: impl FnOnce(&mut Value)) {
	let mut outbound = wireguard();
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
fn the_minimal_form_and_every_setting_are_valid() {
	clean(wireguard());
	clean(json!({"type": "wireguard", "tag": "up", "server": "198.51.100.7:51820", "public_key": key(0x31), "private_key": key(0x32), "preshared_key": key(0x33), "addresses": ["10.64.0.2/32", "fd00:64::2/128"], "mtu": 1280, "keepalive_secs": 0, "max_flows": 16, "bind": "192.0.2.9", "interface": "eth1"}));
	clean(json!({"type": "wireguard", "tag": "up", "server": "vpn.example:51820", "public_key": key(0x31), "private_key": key(0x32), "addresses": ["fd00:64::2"], "mtu": 1500, "keepalive_secs": 3600, "max_flows": 16384}));
	clean(json!({"type": "wireguard", "tag": "up", "server": "192.168.1.5:51820", "public_key": key(0x31), "private_key": key(0x32), "addresses": ["10.64.0.2"]}));
	clean(json!({"type": "wireguard", "tag": "up", "server": "[2001:db8::7]:51820", "public_key": key(0x31), "private_key": key(0x32), "addresses": ["10.64.0.2"]}));
}

#[test]
fn a_suffix_that_wg_quick_writes_is_dropped_and_any_other_is_not_taken() {
	let config = Config::parse(node(json!({"type": "wireguard", "tag": "up", "server": "198.51.100.7:51820", "public_key": key(0x31), "private_key": key(0x32), "addresses": ["10.64.0.2/32", "fd00:64::2/128"]})).to_string().as_bytes()).unwrap();
	let shown = serde_json::to_value(&config).unwrap();
	assert_eq!(shown["outbounds"][2]["addresses"], json!(["10.64.0.2", "fd00:64::2"]));
	for address in ["10.64.0.2/24", "10.64.0.2/31", "fd00:64::2/64", "10.64.0.2/", "10.64.0.2/032", "::ffff:10.64.0.2", "fe80::1%eth0", "not-an-address"] {
		let mut outbound = wireguard();
		outbound["addresses"] = json!([address]);
		assert!(Config::parse(node(outbound).to_string().as_bytes()).is_err(), "{address} was taken");
	}
}

#[test]
fn what_the_node_may_not_dial_or_hold_is_refused() {
	refused("outbounds[2].server", |o| o["server"] = json!("127.0.0.1:51820"));
	refused("outbounds[2].server", |o| o["server"] = json!("[::1]:51820"));
	refused("outbounds[2].server", |o| o["server"] = json!("169.254.169.254:51820"));
	refused("outbounds[2].server", |o| o["server"] = json!("10.7.0.9:51820"));
	refused("outbounds[2].addresses[0]", |o| o["addresses"] = json!(["10.7.0.9"]));
	refused("outbounds[2].addresses[0]", |o| o["addresses"] = json!(["127.0.0.2"]));
	refused("outbounds[2].addresses[0]", |o| o["addresses"] = json!(["224.0.0.1"]));
	refused("outbounds[2].addresses[0]", |o| o["addresses"] = json!(["0.0.0.0"]));
	refused("outbounds[2].addresses[0]", |o| o["addresses"] = json!(["::"]));
	refused("outbounds[2].addresses", |o| o["addresses"] = json!([]));
	refused("outbounds[2].addresses", |o| o["addresses"] = json!(["10.64.0.2", "10.64.0.3"]));
	refused("outbounds[2].addresses", |o| o["addresses"] = json!(["10.64.0.2", "fd00:64::2", "fd00:64::3"]));
	refused("outbounds[2].mtu", |o| o["mtu"] = json!(1279));
	refused("outbounds[2].mtu", |o| o["mtu"] = json!(1501));
	refused("outbounds[2].keepalive_secs", |o| o["keepalive_secs"] = json!(3601));
	refused("outbounds[2].max_flows", |o| o["max_flows"] = json!(15));
	refused("outbounds[2].max_flows", |o| o["max_flows"] = json!(16385));
	refused("outbounds[2].bind", |o| o["bind"] = json!("0.0.0.0"));
	refused("outbounds[2].interface", |o| o["interface"] = json!("a b"));
	refused("outbounds[2].interface", |o| o["interface"] = json!("x".repeat(16)));
}

#[test]
fn the_nodes_own_keys_and_a_shared_key_are_refused() {
	refused("outbounds[2].private_key", |o| o["private_key"] = json!(key(0x11)));
	refused("outbounds[2].private_key", |o| {
		let public = veilway_wg::encode_key(&veilway_wg::public_key(&[0x32; 32]));
		o["public_key"] = json!(public);
	});
	// The private half of a device's public key is not known, so the device case is the other direction: the outbound's public key may not be a device's, and its private key not the inbound's public key.
	refused("outbounds[2].private_key", |o| o["private_key"] = json!(veilway_wg::encode_key(&veilway_wg::public_key(&[0x11; 32]))));
	let mut doc = node(wireguard());
	doc["outbounds"].as_array_mut().unwrap().push(json!({"type": "wireguard", "tag": "second", "server": "198.51.100.8:51820", "public_key": key(0x34), "private_key": key(0x32), "addresses": ["10.64.0.3"]}));
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == "outbounds[3].private_key"), "{:#?}", report.errors);
	let mut other = node(wireguard());
	other["outbounds"].as_array_mut().unwrap().push(json!({"type": "wireguard", "tag": "second", "server": "198.51.100.8:51820", "public_key": key(0x34), "private_key": key(0x35), "addresses": ["10.64.0.3"]}));
	assert!(check(&other).errors.is_empty(), "two outbounds with keys of their own are valid");
}

#[test]
fn keys_that_belong_to_other_types_do_not_parse_and_the_zero_key_is_no_key() {
	for extra in [json!({"via": "plain"}), json!({"username": "x"}), json!({"password": "x"}), json!({"link": "x"}), json!({"protocol": "vless"}), json!({"allow_private": true})] {
		let mut outbound = wireguard();
		outbound.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		assert!(Config::parse(node(outbound).to_string().as_bytes()).is_err(), "{extra}");
	}
	for extra in [json!({"public_key": key(0x31)}), json!({"private_key": key(0x32)}), json!({"addresses": ["10.64.0.2"]}), json!({"mtu": 1400}), json!({"keepalive_secs": 25}), json!({"max_flows": 100})] {
		for kind in [json!({"type": "direct", "tag": "d"}), json!({"type": "socks5", "tag": "d", "server": "192.0.2.1:1080"}), json!({"type": "xray", "tag": "d", "protocol": "trojan", "server": "p.example:443", "password": "a-long-password"})] {
			let mut outbound = kind.clone();
			outbound.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
			assert!(serde_json::from_value::<Outbound>(outbound).is_err(), "{extra} on {kind}");
		}
	}
	for missing in ["server", "public_key", "private_key", "addresses"] {
		let mut outbound = wireguard();
		outbound.as_object_mut().unwrap().remove(missing);
		assert!(serde_json::from_value::<Outbound>(outbound).is_err(), "no {missing}");
	}
	let mut zero = wireguard();
	zero["private_key"] = json!(veilway_wg::encode_key(&[0; 32]));
	assert!(serde_json::from_value::<Outbound>(zero).is_err());
	let mut marked = wireguard();
	marked["private_key"] = json!(REDACTED);
	assert!(serde_json::from_value::<Outbound>(marked).is_err(), "a marker is no key");
}

#[test]
fn it_is_no_via_of_a_chain_a_link_or_an_upstream() {
	let mut doc = node(wireguard());
	doc["outbounds"][1]["via"] = json!("up");
	assert!(check(&doc).errors.iter().any(|error| error.path == "outbounds[1].via"), "a chain through a WireGuard outbound");
	let (signing, token) = ([7u8; 32], [3u8; 16]);
	let text = format!("veilway://sub/provider.example.org/sub#v1.{}.{}.{}", URL_SAFE_NO_PAD.encode(signing), URL_SAFE_NO_PAD.encode([&[1u8][..], &[9u8; 32][..]].concat()), URL_SAFE_NO_PAD.encode(token));
	let Ok(Link::Native(native)) = Link::parse(&text) else {panic!("the test link does not read")};
	let mut doc = node(wireguard());
	doc["exits"].as_array_mut().unwrap().push(json!({"tag": "abroad", "backend": {"type": "upstream", "upstream": "other"}}));
	doc["upstreams"] = json!([{"tag": "other", "link": text, "signing_key": native.key().fingerprint().to_string(), "private_key": key(0x41), "device_secret": URL_SAFE_NO_PAD.encode([0x41u8; 16]), "exit": "main", "via": "plain"}]);
	assert!(check(&doc).errors.is_empty(), "{:#?}", check(&doc).errors);
	doc["upstreams"][0]["via"] = json!("up");
	assert!(check(&doc).errors.iter().any(|error| error.path == "upstreams[0].via"), "an upstream through a WireGuard outbound");
}

#[test]
fn an_exit_through_one_has_no_way_around_it_and_a_name_and_a_fallback_are_said() {
	for policy in [json!("direct"), json!({"via": "main"})] {
		let mut doc = node(wireguard());
		doc["exits"][1]["backend"]["unsupported"] = json!({"udp": policy});
		doc["exits"][1]["backend"]["proxy_only"] = json!(false);
		assert!(check(&doc).errors.iter().any(|error| error.path == "exits[1].backend.unsupported.udp"));
	}
	for policy in [json!("reject"), json!("drop")] {
		let mut doc = node(wireguard());
		doc["exits"][1]["backend"]["unsupported"] = json!({"udp": policy});
		assert!(check(&doc).errors.is_empty());
	}
	let mut doc = node(wireguard());
	doc["routing"]["fallback"] = json!(["main"]);
	assert!(check(&doc).warnings.iter().any(|warning| warning.path == "exits[1]"));
	let mut named = wireguard();
	named["server"] = json!("vpn.example:51820");
	assert!(check(&node(named)).warnings.iter().any(|warning| warning.path == "outbounds[2].server"), "a name that the system's resolver looks up says so");
	assert!(!check(&node(wireguard())).warnings.iter().any(|warning| warning.path == "outbounds[2].server"));
	let mut doc = node(wireguard());
	doc["exits"][1]["backend"]["proxy_only"] = json!(true);
	assert!(check(&doc).errors.is_empty(), "the exit through it is a proxied one, so proxy_only is its default");
}

#[test]
fn secrets_are_shown_as_markers_and_kept_for_the_same_outbound_server_and_key() {
	let mut full = wireguard();
	full["preshared_key"] = json!(key(0x33));
	let config = Config::parse(node(full.clone()).to_string().as_bytes()).unwrap();
	let shown = config.redacted();
	assert_eq!(shown.to_string().matches(REDACTED).count(), 3, "the inbound's key and the outbound's two");
	assert!(!shown.to_string().contains(&key(0x32)) && !shown.to_string().contains(&key(0x33)));
	assert!(Config::parse_keeping(shown.to_string().as_bytes(), &config).ok().map(|(kept, _)| kept) == Some(config.clone()));
	let mut moved = shown.clone();
	moved["outbounds"][2]["server"] = json!("198.51.100.99:51820");
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("a marker was kept for another server");
	assert_eq!(report.errors[0].path, "outbounds[2].private_key");
	let mut other = shown.clone();
	other["outbounds"][2]["public_key"] = json!(key(0x39));
	let report = Config::parse_keeping(other.to_string().as_bytes(), &config).err().expect("a marker was kept for another public key");
	assert_eq!(report.errors[0].path, "outbounds[2].private_key");
	let mut removed = shown.clone();
	removed["outbounds"][2].as_object_mut().unwrap().remove("preshared_key");
	assert!(Config::parse_keeping(removed.to_string().as_bytes(), &config).is_ok(), "a key may be taken away");
	let mut only_private = shown.clone();
	only_private["outbounds"][2]["preshared_key"] = json!(key(0x3a));
	let (kept, changed) = Config::parse_keeping(only_private.to_string().as_bytes(), &config).unwrap();
	assert_eq!(changed, vec!["up".to_string()], "a key that is spelled out counts as changed");
	assert!(kept != config);
	let (_, changed) = Config::parse_keeping(node(full).to_string().as_bytes(), &config).unwrap();
	assert_eq!(changed, vec!["up".to_string()]);
	let mut spelled = node(wireguard());
	spelled["outbounds"][2]["private_key"] = json!(REDACTED);
	assert!(Config::parse(spelled.to_string().as_bytes()).is_err(), "a marker passed as a key");
}

#[test]
fn a_change_of_the_outbound_is_a_change_of_that_outbound_and_the_schema_has_it() {
	let (old, new) = (Config::parse(node(wireguard()).to_string().as_bytes()).unwrap(), {
		let mut outbound = wireguard();
		outbound["mtu"] = json!(1400);
		Config::parse(node(outbound).to_string().as_bytes()).unwrap()
	});
	let diff = veilway_core::config::Diff::between(&old, &new, time::OffsetDateTime::now_utc());
	assert_eq!(diff.outbounds.changed, vec!["up".to_string()]);
	let schema: Value = serde_json::from_str(&veilway_core::config::schema()).unwrap();
	let text = schema.to_string();
	for word in ["wireguard", "keepalive_secs", "max_flows", "preshared_key"] {assert!(text.contains(word), "{word}")}
}

#[test]
fn the_seeds_of_the_config_fuzz_target_are_one_valid_and_one_invalid_document() {
	let seed = |name: &str| std::fs::read(format!("{}/../../fuzz/corpus/config/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
	let valid = Config::parse(&seed("outbound-wireguard.json")).expect("the valid seed does not parse");
	assert!(valid.validate(true).errors.is_empty(), "{:#?}", valid.validate(true).errors);
	let invalid = Config::parse(&seed("outbound-wireguard-invalid.json")).expect("the invalid seed does not parse");
	let paths: Vec<String> = invalid.validate(true).errors.into_iter().map(|error| error.path).collect();
	for expected in ["outbounds[1].server", "outbounds[1].addresses[0]", "outbounds[1].mtu", "outbounds[1].private_key"] {assert!(paths.iter().any(|path| path == expected), "{expected}: {paths:?}")}
}
