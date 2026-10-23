//! The `socks5`, `http` and `mixed` inbounds of config version 1: what makes them valid, how they are told apart from tunnel inbounds in `inbounds`, and how the proxy password is shown and kept.
use serde_json::{json, Value};
use veilway_core::config::{Config, Report, REDACTED};

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]},
			{"tag": "s5", "type": "socks5", "listen": "127.0.0.1:1080"},
			{"tag": "web", "type": "http", "listen": "127.0.0.1:3128", "users": ["alice"]},
			{"tag": "both", "type": "mixed", "listen": "[::1]:1081", "groups": ["family"], "udp": false, "limits": {"connections": 100, "per_source": 8, "handshakes": 16}}
		],
		"groups": ["family"],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "alice", "exits": "all", "groups": ["family"], "proxy_password": "alice-secret-pass-01", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}]
	})
}

fn parse(doc: &Value) -> Config {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}"))}

fn check(doc: &Value) -> Report {
	let mut report = parse(doc).validate(true);
	// The routing of this node has no isolation rules, which is not what these tests are about.
	report.warnings.retain(|warning| warning.path != "routing.rules");
	report
}

#[track_caller]
fn refused(path: &str, edit: impl FnOnce(&mut Value)) {
	let mut doc = node();
	edit(&mut doc);
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == path), "expected an error at {path}, got {:#?}", report.errors);
}

#[test]
fn a_good_config_with_the_three_types_is_clean() {
	let report = check(&node());
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	let config = parse(&node());
	assert_eq!((config.inbounds.len(), config.proxies.len()), (1, 3), "the proxy inbounds are not told apart from the tunnel inbounds");
	assert!(config.proxies[0].udp() && !config.proxies[2].udp() && !config.proxies[1].udp(), "udp is true for socks5, and not for http and for a mixed inbound that turned it off");
}

#[test]
fn a_config_reads_back_as_itself_in_the_order_of_its_document() {
	let mut doc = node();
	doc["inbounds"].as_array_mut().unwrap().rotate_left(1);
	let config = parse(&doc);
	let written = serde_json::to_value(&config).unwrap();
	let tags: Vec<&str> = written["inbounds"].as_array().unwrap().iter().map(|inbound| inbound["tag"].as_str().unwrap()).collect();
	assert_eq!(tags, ["s5", "web", "both", "home"], "a document was not written back in the order it came in");
	assert_eq!(parse(&written), config, "the config is not what it reads back as");
	assert_eq!(serde_json::to_value(&parse(&node())).unwrap()["inbounds"][0]["tag"], "home");
	assert!(written.get("proxy_inbounds").is_none(), "the internal key reached the document");
}

#[test]
fn a_document_may_not_spell_the_internal_key() {
	let mut doc = node();
	doc["proxy_inbounds"] = json!([]);
	let e = Config::parse(doc.to_string().as_bytes()).unwrap_err();
	assert_eq!(e.path, "proxy_inbounds");
}

#[test]
fn a_mistake_is_told_in_the_numbers_of_the_document() {
	let mut doc = node();
	doc["inbounds"].as_array_mut().unwrap().rotate_left(1);
	doc["inbounds"][0]["private_key"] = json!("x");
	let e = Config::parse(doc.to_string().as_bytes()).unwrap_err();
	assert_eq!((e.path.as_str(), e.message.contains("unknown key")), ("inbounds[0]", true), "{e:?}");
	let mut doc = node();
	doc["inbounds"].as_array_mut().unwrap().rotate_left(1);
	doc["inbounds"][2]["transports"] = json!([]);
	assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().path, "inbounds[2]", "a tunnel inbound's fields on a proxy inbound");
	let mut doc = node();
	doc["inbounds"][2]["listen"] = json!("not an address");
	assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().path, "inbounds[2].listen");
	let mut doc = node();
	doc["inbounds"][2]["type"] = json!("socks4");
	assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().path, "inbounds[2]", "an unknown type is a tunnel inbound's mistake, in the right place");
}

#[test]
fn the_listen_address_rule_holds() {
	for listen in ["127.0.0.1:1080", "[::1]:1080", "127.5.5.5:1080"] {
		let mut doc = node();
		doc["inbounds"][1]["listen"] = json!(listen);
		let report = check(&doc);
		assert!(report.errors.is_empty() && report.warnings.is_empty(), "{listen}: {report:#?}");
	}
	for listen in ["10.1.2.3:1080", "172.16.0.9:1080", "192.168.1.1:1080", "100.64.0.1:1080", "[fd12::1]:1080"] {
		let mut doc = node();
		doc["inbounds"][1]["listen"] = json!(listen);
		let report = check(&doc);
		assert!(report.errors.is_empty(), "{listen}: {:#?}", report.errors);
		let warning = report.warnings.iter().find(|warning| warning.path == "inbounds[1].listen").unwrap_or_else(|| panic!("{listen}: a private address passed in silence"));
		assert!(warning.message.contains("NATed") && warning.message.contains("not encrypted"), "{}", warning.message);
	}
	for listen in ["0.0.0.0:1080", "[::]:1080", "203.0.113.5:1080", "[2001:db8::1]:1080", "169.254.1.1:1080", "[fe80::1]:1080", "172.32.0.1:1080", "100.128.0.1:1080"] {
		refused("inbounds[1].listen", |doc| doc["inbounds"][1]["listen"] = json!(listen));
		let mut doc = node();
		doc["inbounds"][1]["listen"] = json!(listen);
		doc["inbounds"][1]["public"] = json!(true);
		let report = check(&doc);
		assert!(report.errors.is_empty(), "{listen}: {:#?}", report.errors);
		let warning = report.warnings.iter().find(|warning| warning.path == "inbounds[1].listen").unwrap_or_else(|| panic!("{listen}: no warning in {:#?}", report.warnings));
		assert!(warning.message.contains("unencrypted") && warning.message.contains("read them") && warning.message.contains("find and block"), "{}", warning.message);
	}
	let mut doc = node();
	doc["inbounds"][1]["public"] = json!(true);
	assert!(check(&doc).warnings.iter().any(|warning| warning.path == "inbounds[1].public"), "public on a private address is not said to be needless");
}

#[test]
fn each_other_rule_of_the_inbound_holds() {
	refused("inbounds[2].udp", |doc| doc["inbounds"][2]["udp"] = json!(true));
	refused("inbounds[2].udp", |doc| doc["inbounds"][2]["udp"] = json!(false));
	refused("inbounds[1].limits.connections", |doc| doc["inbounds"][1]["limits"] = json!({"connections": 0}));
	refused("inbounds[1].limits.per_source", |doc| doc["inbounds"][1]["limits"] = json!({"per_source": 70000}));
	refused("inbounds[1].limits.handshakes", |doc| doc["inbounds"][1]["limits"] = json!({"handshakes": 0}));
	refused("inbounds[2].users[0]", |doc| doc["inbounds"][2]["users"] = json!(["nobody"]));
	refused("inbounds[2].users[1]", |doc| doc["inbounds"][2]["users"] = json!(["alice", "alice"]));
	refused("inbounds[3].groups[0]", |doc| doc["inbounds"][3]["groups"] = json!(["strangers"]));
	refused("inbounds[3].tag", |doc| doc["inbounds"][3]["tag"] = json!("home"));
	refused("inbounds[3].tag", |doc| doc["inbounds"][3]["tag"] = json!("s5"));
	refused("inbounds[1].tag", |doc| doc["inbounds"][1]["tag"] = json!("users"));
	refused("inbounds[2].listen", |doc| doc["inbounds"][2]["listen"] = json!("127.0.0.1:1080"));
	refused("inbounds[1].listen", |doc| {
		doc["inbounds"][0]["transports"] = json!([{"type": "tls", "listen": "127.0.0.1:1080", "path": "/assets/app-3f9c2e71.js", "tls": {"cert": "a", "key": "b"}, "decoy": {"origin": "http://127.0.0.1:8080"}}]);
		doc["inbounds"][0]["type"] = json!("veilway");
	});
}

#[test]
fn a_datagram_transport_may_share_the_port_and_a_tcp_listener_of_the_node_may_not() {
	let mut doc = node();
	doc["inbounds"][1]["listen"] = json!("0.0.0.0:51820");
	doc["inbounds"][1]["public"] = json!(true);
	assert!(!check(&doc).errors.iter().any(|error| error.path == "inbounds[1].listen"), "a proxy inbound is TCP and a udp transport is not");
	refused("inbounds[1].listen", |doc| {
		doc["tunnels"] = json!([{"tag": "t", "protocol": "tcp", "listen": "127.0.0.1:1080", "exit": "main", "target": "93.184.216.34:80", "sources": ["127.0.0.1"]}]);
	});
	refused("inbounds[1].listen", |doc| {
		doc["xray"] = json!({"inbounds": [{"tag": "ss", "protocol": "shadowsocks", "listen": "127.0.0.1:1080", "server_key": key(0x31), "clients": []}]});
	});
}

#[test]
fn a_proxy_password_follows_its_rules() {
	for bad in ["short", "fifteen-chars-x", "has:a-colon-in-it-1234", "ünicode-password-0001", "tab\tin-the-password-1", &"a".repeat(129)] {
		refused("users[0].proxy_password", |doc| doc["users"][0]["proxy_password"] = json!(bad));
	}
	for good in ["sixteen-chars-xxx", "with spaces inside it 1", &"a".repeat(128), "~!@#$%^&*()_+-=[]{}|;',./<>?"] {
		let mut doc = node();
		doc["users"][0]["proxy_password"] = json!(good);
		assert!(check(&doc).errors.is_empty(), "{good}: {:#?}", check(&doc).errors);
	}
	refused("users[0].proxy_password", |doc| doc["users"][0]["proxy_password"] = json!(REDACTED));
}

#[test]
fn a_user_nobody_can_log_in_as_is_said() {
	let mut doc = node();
	doc["users"][0].as_object_mut().unwrap().remove("proxy_password");
	let report = check(&doc);
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == "inbounds[1]" && warning.message.contains("nobody can log in")), "{report:#?}");
	let mut doc = node();
	doc["inbounds"].as_array_mut().unwrap().truncate(1);
	let report = check(&doc);
	assert!(report.warnings.iter().any(|warning| warning.path == "users[0].proxy_password"), "{report:#?}");
}

#[test]
fn the_password_is_a_secret_the_control_api_hides_and_takes_back() {
	let config = parse(&node());
	let shown = config.redacted();
	assert_eq!(shown["users"][0]["proxy_password"], REDACTED);
	assert!(!shown.to_string().contains("alice-secret-pass-01"));
	let (back, _) = Config::parse_keeping(shown.to_string().as_bytes(), &config).unwrap_or_else(|r| panic!("{r:#?}"));
	assert_eq!(back, config, "the marker did not stand for the password of the running user");
	let mut stranger = shown.clone();
	stranger["users"][0]["name"] = json!("bob");
	let refused = Config::parse_keeping(stranger.to_string().as_bytes(), &config).unwrap_err();
	assert!(refused.errors.iter().any(|error| error.path == "users[0].proxy_password"), "{refused:#?}");
	assert!(format!("{config:?}").contains("<secret>") && !format!("{config:?}").contains("alice-secret-pass-01"), "the password is in the Debug output");
}

#[test]
fn a_change_to_a_proxy_inbound_is_in_the_diff() {
	let (old, mut doc) = (parse(&node()), node());
	doc["inbounds"][1]["limits"] = json!({"connections": 5});
	doc["inbounds"].as_array_mut().unwrap().push(json!({"tag": "extra", "type": "http", "listen": "127.0.0.1:3129"}));
	doc["inbounds"].as_array_mut().unwrap().retain(|inbound| inbound["tag"] != "both");
	let diff = veilway_core::config::Diff::between(&old, &parse(&doc), time::OffsetDateTime::now_utc());
	assert_eq!((diff.inbounds.added, diff.inbounds.changed, diff.inbounds.removed), (vec!["extra".to_string()], vec!["s5".to_string()], vec!["both".to_string()]));
	let (mut same, plain) = (node(), parse(&node()));
	same["inbounds"][1]["udp"] = json!(true);
	same["inbounds"][1]["public"] = json!(false);
	assert!(veilway_core::config::Diff::between(&plain, &parse(&same), time::OffsetDateTime::now_utc()).inbounds.changed.is_empty(), "a default written out is a change");
}

#[test]
fn a_message_names_the_inbound_as_the_document_numbers_it() {
	let mut doc = node();
	doc["inbounds"].as_array_mut().unwrap().rotate_left(1);
	doc["inbounds"][2]["listen"] = json!("127.0.0.1:1080");
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == "inbounds[2].listen" && error.message.contains("inbounds[0].listen")), "{:#?}", report.errors);
	let mut doc = node();
	doc["inbounds"].as_array_mut().unwrap().rotate_left(1);
	doc["inbounds"][0]["listen"] = json!("0.0.0.0:1080");
	assert!(check(&doc).errors.iter().any(|error| error.path == "inbounds[0].listen"), "an error is told at the place of the proxy inbound in the document");
}

#[test]
fn a_rule_may_name_a_proxy_inbound_and_a_warning_says_xray_skips_it() {
	let mut doc = node();
	doc["routing"]["rules"] = json!([{"tag": "scoped", "inbound": ["s5"], "ip": ["203.0.113.0/24"], "action": "block"}]);
	assert!(check(&doc).errors.is_empty());
	doc["routing"]["rules"][0]["inbound"] = json!(["nobody"]);
	assert!(check(&doc).errors.iter().any(|error| error.path == "routing.rules[0].inbound[0]"));
	let mut doc = node();
	doc["routing"]["rules"] = json!([{"tag": "scoped", "inbound": ["home"], "ip": ["203.0.113.0/24"], "action": "block"}]);
	doc["xray"] = json!({"inbounds": [{"tag": "ss", "protocol": "shadowsocks", "listen": "0.0.0.0:8446", "server_key": key(0x31), "clients": []}]});
	assert!(check(&doc).warnings.iter().any(|warning| warning.path == "routing.rules[0].inbound" && warning.message.contains("Xray")));
}

#[test]
fn only_a_user_with_a_proxy_password_may_have_no_device() {
	let mut doc = node();
	doc["users"][0]["devices"] = json!([]);
	assert!(check(&doc).errors.is_empty(), "{:#?}", check(&doc).errors);
	doc["users"][0].as_object_mut().unwrap().remove("proxy_password");
	assert!(check(&doc).errors.iter().any(|error| error.path == "users[0].devices"));
}

#[test]
fn a_rule_by_transport_names_only_transports_that_exist_and_warns_for_those_the_node_lacks() {
	let rule = |names: Value| json!([{"tag": "by-transport", "transport": names, "ip": ["203.0.113.0/24"], "action": "block"}]);
	let mut doc = node();
	doc["routing"]["rules"] = rule(json!(["udp", "http", "socks5"]));
	let report = check(&doc);
	assert!(report.errors.is_empty() && !report.warnings.iter().any(|warning| warning.path.contains("transport")), "{report:#?}");
	for unknown in ["tcp", "UDP", "wireguard", "xray", ""] {
		doc["routing"]["rules"] = rule(json!([unknown]));
		assert!(Config::parse(doc.to_string().as_bytes()).is_err(), "{unknown:?} was taken for a transport");
	}
	doc["routing"]["rules"] = rule(json!([]));
	assert!(check(&doc).errors.iter().any(|error| error.path == "routing.rules[0].transport"), "an empty list is a condition");
	doc["routing"]["rules"] = rule(json!(["tls", "udp-obfs", "faketls", "ws", "ws-plain", "fronted", "fronted-shaped", "udp"]));
	let warned: Vec<String> = check(&doc).warnings.into_iter().filter(|warning| warning.path.contains("transport")).map(|warning| warning.path).collect();
	assert_eq!(warned, ["routing.rules[0].transport[0]", "routing.rules[0].transport[1]", "routing.rules[0].transport[2]", "routing.rules[0].transport[3]", "routing.rules[0].transport[4]", "routing.rules[0].transport[5]", "routing.rules[0].transport[6]"], "a transport no inbound has was not said");
	doc["inbounds"].as_array_mut().unwrap().truncate(1);
	doc["routing"]["rules"] = rule(json!(["socks5"]));
	assert!(check(&doc).warnings.iter().any(|warning| warning.path == "routing.rules[0].transport[0]"), "socks5 without a proxy inbound");
	doc["routing"]["rules"] = json!([{"tag": "a", "transport": ["udp"], "action": "block"}, {"tag": "b", "transport": ["udp"], "ip": ["203.0.113.0/24"], "action": "block"}]);
	assert!(check(&doc).warnings.iter().any(|warning| warning.path == "routing.rules[1]" && warning.message.contains("never matches")), "a rule by transport is covered by an earlier one on the same transport");
	doc["routing"]["rules"] = json!([{"tag": "a", "transport": ["udp"], "action": "block"}, {"tag": "b", "ip": ["203.0.113.0/24"], "action": "block"}]);
	assert!(!check(&doc).warnings.iter().any(|warning| warning.message.contains("never matches")), "a rule by transport covered one that has no transport");
}

#[test]
fn udp_any_port_belongs_to_socks5_and_mixed_and_is_warned_about_and_a_nat_is_said() {
	refused("inbounds[2].udp_any_port", |doc| doc["inbounds"][2]["udp_any_port"] = json!(true));
	let mut doc = node();
	doc["inbounds"][1]["listen"] = json!("10.1.2.3:1080");
	let said = |doc: &Value, path: &str, word: &str| check(doc).warnings.iter().any(|warning| warning.path == path && warning.message.contains(word));
	assert!(said(&doc, "inbounds[1].udp", "NAT") && said(&doc, "inbounds[1].udp", "udp_any_port"), "a client behind a NAT is not told it gets no UDP");
	doc["inbounds"][1]["udp_any_port"] = json!(true);
	assert!(said(&doc, "inbounds[1].udp_any_port", "shares the client's address") && !check(&doc).warnings.iter().any(|warning| warning.path == "inbounds[1].udp"));
	let mut doc = node();
	doc["inbounds"][1]["udp_any_port"] = json!(true);
	assert!(said(&doc, "inbounds[1].udp_any_port", "never used"), "the setting on loopback does nothing");
}

#[test]
fn a_rule_by_inbound_that_names_a_proxy_inbound_is_held_to_the_users_it_admits() {
	let mut doc = node();
	doc["exits"] = json!([{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "other", "backend": {"type": "netstack", "outbound": "plain"}}]);
	doc["users"][0]["exits"] = json!(["main"]);
	doc["users"][0]["devices"] = json!([]);
	doc["routing"]["rules"] = json!([{"tag": "to-other", "inbound": ["s5"], "ip": ["203.0.113.0/24"], "action": {"exit": "other"}}]);
	assert!(check(&doc).warnings.iter().any(|warning| warning.path == "routing.rules[0].action" && warning.message.contains("not entitled")), "{:#?}", check(&doc).warnings);
}
