//! Config version 1: every rule of the reference, by changing one thing in a known-good document.
use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;
use veilway_core::config::{load, save, schema, Config, Diagnostic, Report, MAX_DIAGNOSTICS, MAX_FILE_BYTES, MAX_JSON_NODES, MAX_RULES, MAX_USERS, REDACTED};

/// An obviously fake key: one byte repeated.
fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn good() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"groups": ["staff", "guest"],
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24", "fd7a:115c:a1e0::1/64"], "transports": [
				{"type": "udp", "listen": "0.0.0.0:51820"},
				{"type": "ws", "listen": "127.0.0.1:8080", "path": "/wg"}
			]},
			{"tag": "office", "type": "wireguard", "private_key": key(0x12), "address": ["10.8.0.1/24"], "transports": [{"type": "udp", "listen": "[::]:51821"}]}
		],
		"outbounds": [
			{"tag": "proxy", "type": "socks5", "server": "127.0.0.1:1080", "username": "example-user", "password": "example-password"},
			{"tag": "plain", "type": "direct"}
		],
		"exits": [
			{"tag": "main", "backend": {"type": "netstack", "outbound": "proxy"}},
			{"tag": "open", "backend": {"type": "netstack", "outbound": "plain"}},
			{"tag": "node", "backend": {"type": "l3"}},
			{"tag": "sink", "backend": {"type": "block"}}
		],
		"routing": {"default": "main", "rules": [
			{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"},
			{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"},
			{"tag": "no-smtp", "protocol": ["tcp"], "port": [25], "action": "reject"},
			{"tag": "intranet", "group": ["staff"], "domain": ["*.corp.example.com"], "action": {"exit": "node"}}
		]},
		"users": [
			{"name": "alice", "groups": ["staff"], "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "preshared_key": key(0x31), "addresses": ["10.7.0.2", "fd7a:115c:a1e0::2", "10.8.0.2"]}]},
			{"name": "bob", "groups": ["guest"], "exits": ["main", "node"], "devices": [{"name": "phone", "public_key": key(0x22), "addresses": ["10.7.0.3"]}]}
		]
	})
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
	let mut doc = good();
	edit(&mut doc);
	doc
}

fn parse(doc: &Value) -> Result<Config, Diagnostic> {Config::parse(doc.to_string().as_bytes())}

fn check(doc: &Value) -> Report {parse(doc).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn clean(edit: impl FnOnce(&mut Value)) {
	let report = check(&with(edit));
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "expected a clean report, got {report:#?}");
}

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

#[track_caller]
fn refused(path: &str, edit: impl FnOnce(&mut Value)) -> String {
	match parse(&with(edit)) {
		Err(e) if e.path == path => e.message,
		other => panic!("expected a parse error at {path}, got {other:?}"),
	}
}

macro_rules! cases {
	($check:ident: $($path:literal: |$doc:ident| $edit:expr;)+) => {$($check($path, |$doc| {$edit;});)+};
}

macro_rules! all_clean {
	($(|$doc:ident| $edit:expr;)+) => {$(clean(|$doc| {$edit;});)+};
}

fn remove(doc: &mut Value, pointer: &str, key: &str) {doc.pointer_mut(pointer).unwrap().as_object_mut().unwrap().remove(key);}

fn push(doc: &mut Value, pointer: &str, value: Value) {doc.pointer_mut(pointer).unwrap().as_array_mut().unwrap().push(value)}

fn rule(doc: &mut Value, rule: Value) {push(doc, "/routing/rules", rule)}

#[test]
fn the_known_good_document_is_clean() {
	clean(|_| {});
}

#[test]
fn shipped_example_is_clean_and_survives_a_round_trip() {
	let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.json")).unwrap();
	let config = Config::parse(&bytes).unwrap();
	assert_eq!(config.validate(true), Report::default());
	assert_eq!(Config::parse(serde_json::to_string(&config).unwrap().as_bytes()).unwrap(), config);
}

#[test]
fn a_redacted_document_shows_no_secret_and_comes_back_with_every_one_of_them() {
	let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.json")).unwrap();
	let config = Config::parse(&bytes).unwrap();
	let (shown, saved) = (config.redacted().to_string(), serde_json::to_string(&config).unwrap());
	for secret in ["ERERERERERERERERERERERERERERERERERERERERERE=", "EhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhI=", "ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExM=", "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=", "example-user", "example-password"] {
		assert!(!shown.contains(secret) && saved.contains(secret), "a secret is in the redacted document, or missing from the one that is saved");
	}
	assert_eq!(shown.matches(REDACTED).count(), 6);
	// Showing a document must not change how the next one is saved on the same thread.
	assert_eq!(serde_json::to_string(&config).unwrap(), saved);
	assert!(Config::parse(shown.as_bytes()).is_err(), "a marker was taken for a secret without a running config to take it from");
	assert!(Config::parse_keeping(shown.as_bytes(), &config).ok() == Some((config.clone(), Vec::new())), "the secrets of the running config did not come back for their markers");
	// A user name or a password that is written out is said to be, whatever it holds: the control API lists such an outbound as changed without saying whether it is.
	assert_eq!(Config::parse_keeping(saved.as_bytes(), &config).ok().map(|(_, spelled)| spelled), Some(vec!["proxy".to_string()]));
	// Each marker belongs to an object of the running config. Under another tag or key there is nothing to keep, and the error names the field and no value.
	let mut moved: Value = serde_json::from_str(&shown).unwrap();
	(moved["inbounds"][0]["tag"], moved["outbounds"][0]["tag"], moved["users"][0]["devices"][1]["public_key"]) = (json!("elsewhere"), json!("other"), json!(key(99)));
	let report = Config::parse_keeping(moved.to_string().as_bytes(), &config).err().expect("markers with nothing to keep were taken");
	assert_eq!(report.errors.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["inbounds[0].private_key", "outbounds[0].username", "outbounds[0].password", "users[0].devices[1].preshared_key"]);
	assert!(report.errors.iter().all(|e| !e.message.contains('=') && !e.message.contains("example-")), "{report:?}");
	// A marker where no secret belongs is a wrong value like any other.
	let mut misplaced: Value = serde_json::from_str(&saved).unwrap();
	misplaced["users"][0]["devices"][0]["public_key"] = json!(REDACTED);
	assert_eq!(Config::parse_keeping(misplaced.to_string().as_bytes(), &config).err().map(|report| report.errors[0].path.clone()).as_deref(), Some("users[0].devices[0].public_key"));
}

/// A document the control API showed, saved as the config file with real keys pasted in, must not start a node that logs in to its proxy as the marker.
#[test]
fn the_marker_is_no_user_name_and_no_password_of_a_config_that_runs() {
	cases!(error_at:
		"outbounds[0].username": |doc| doc["outbounds"][0]["username"] = json!(REDACTED);
		"outbounds[0].password": |doc| doc["outbounds"][0]["password"] = json!(REDACTED);
	);
	let report = check(&with(|doc| (doc["outbounds"][0]["username"], doc["outbounds"][0]["password"]) = (json!(REDACTED), json!(REDACTED))));
	assert_eq!(report.errors.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["outbounds[0].username", "outbounds[0].password"]);
}

/// A marker keeps a user name and a password for the proxy they were shown for and no other: kept under another server, the node would hand them to whoever the document names.
#[test]
fn a_marker_keeps_the_secrets_of_an_outbound_only_while_it_is_the_same_proxy() {
	let config = parse(&with(|doc| push(doc, "/outbounds", json!({"tag": "second", "type": "socks5", "server": "proxy.example.com:1080", "username": "second-user", "password": "second-password"})))).unwrap();
	let shown = config.redacted();
	let kept = |edit: &dyn Fn(&mut Value)| {
		let mut doc = shown.clone();
		edit(&mut doc);
		Config::parse_keeping(doc.to_string().as_bytes(), &config).map_err(|report| report.errors.iter().map(|e| e.path.clone()).collect::<Vec<_>>())
	};
	assert!(kept(&|_| {}).is_ok());
	assert_eq!(kept(&|doc| doc["outbounds"][0]["server"] = json!("127.0.0.1:9")).err(), Some(vec!["outbounds[0].username".to_string(), "outbounds[0].password".to_string()]));
	assert_eq!(kept(&|doc| doc["outbounds"][2]["server"] = json!("other.example.com:1080")).err(), Some(vec!["outbounds[2].username".to_string(), "outbounds[2].password".to_string()]));
	assert_eq!(kept(&|doc| (doc["outbounds"][0]["tag"], doc["outbounds"][2]["tag"]) = (json!("second"), json!("proxy"))).err().map(|paths| paths.len()), Some(4));
	// A server that changes with its secrets sent along is a new proxy like any other.
	assert!(kept(&|doc| doc["outbounds"][0] = json!({"tag": "proxy", "type": "socks5", "server": "127.0.0.1:9", "username": "fresh-user", "password": "fresh-password"})).is_ok());
}

/// Two writes at once, each of its own megabyte, next to a file the node never made that has the name a temporary file used to have.
#[test]
fn writes_of_the_config_file_share_no_temporary_file_and_remove_nobody_elses() {
	let dir = std::env::temp_dir().join(format!("veilway-config-save-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let (path, theirs) = (&dir.join("config.json"), dir.join("config.json.tmp"));
	std::fs::write(&theirs, "somebody's").unwrap();
	let contents: Vec<Vec<u8>> = (0..4u8).map(|i| vec![b'a' + i; 1 << 20]).collect();
	std::thread::scope(|scope| {
		for content in &contents {
			scope.spawn(move || {
				// Windows refuses a file for as long as a scanner or another write holds it, and a write that gave up says so; what must hold is checked below: the file is one whole write, nobody else's file was touched, nothing was left behind.
				for _ in 0..25 {if let Err(e) = save(path, content) {assert!(cfg!(windows) && e.kind() == std::io::ErrorKind::PermissionDenied, "a write of the config file failed next to another one: {e:?}")}}
			});
		}
	});
	assert!(contents.contains(&std::fs::read(path).unwrap()), "the config file holds what no single write put there");
	assert_eq!(std::fs::read_to_string(&theirs).unwrap(), "somebody's", "a file the node did not make was touched");
	let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect();
	left.sort();
	assert_eq!(left, ["config.json", "config.json.tmp"], "a temporary file was left behind");
	#[cfg(unix)]
	assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions()) & 0o777, 0o600);
	std::fs::remove_dir_all(&dir).unwrap();
}

/// A list of short values costs many times its text once it is a tree, so a root that is no object is refused for what it is, however many values it holds.
#[test]
fn a_document_that_is_no_object_is_refused_before_it_is_held_in_memory() {
	let refused = Config::parse(format!("[{}0]", "0,".repeat(MAX_JSON_NODES)).as_bytes()).unwrap_err();
	assert_eq!((refused.path.as_str(), refused.message.as_str()), ("", "expected an object, found a list"));
	for (text, found) in [("[]", "a list"), (" \r\n\t\"text\"", "a string"), ("7", "a number"), ("-1.5", "a number"), ("true", "true or false"), ("null", "null")] {
		assert_eq!(Config::parse(text.as_bytes()).unwrap_err().message, format!("expected an object, found {found}"), "{text}");
	}
	for broken in ["[1,", "nothing", "", "[] []"] {
		let refused = Config::parse(broken.as_bytes()).unwrap_err();
		assert!(refused.path.is_empty() && refused.message.starts_with("expected one JSON document"), "{broken:?}: {}", refused.message);
	}
}

#[test]
fn committed_schema_matches_the_generated_one() {
	let committed = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/config.v1.json")).unwrap().replace("\r\n", "\n");
	assert!(committed == schema(), "schema/config.v1.json is out of date. Regenerate it with: cargo run -p veilway -- schema > schema/config.v1.json");
}

#[test]
fn strict_json() {
	let text = good().to_string();
	let message = |bytes: &[u8]| {
		let e = Config::parse(bytes).unwrap_err();
		assert_eq!(e.path, "");
		e.message
	};
	Config::parse(format!("  {text}\n\t ").as_bytes()).unwrap();
	assert!(message(format!("\u{feff}{text}").as_bytes()).contains("byte order mark"));
	assert!(message(format!("{text} {{}}").as_bytes()).contains("data after"));
	assert!(message(format!("{text}x").as_bytes()).contains("data after"));
	assert!(message(&[text.as_bytes(), b"\xff"].concat()).contains("UTF-8"));
	assert!(message(text.replace("alice", "al\\ud800ice").as_bytes()).contains("syntax error"));
	assert!(message(text.replace("alice", "al\\u0000ice").as_bytes()).contains("NUL"));
	assert!(message(text.replacen('{', "{\"a\\u0000b\":1,", 1).as_bytes()).contains("NUL"));
	assert!(message(text.replacen('{', "{\"version\":1,", 1).as_bytes()).contains("duplicate key"));
	assert!(message(text.replace("\"listen\":\"0.0.0.0:51820\"", "\"listen\":\"0.0.0.0:51820\",\"listen\":\"0.0.0.0:51820\"").as_bytes()).contains("duplicate key"));
	assert!(message(&text.as_bytes()[..text.len() - 1]).contains("syntax error"));
	assert!(message(&vec![b' '; MAX_FILE_BYTES as usize + 1]).contains("64 MiB"));
	for token in ["1.0", "1e0", "-1", "\"1\"", "true", "null", "[1]", "18446744073709551616"] {
		let e = Config::parse(text.replacen("\"version\":1", &format!("\"version\":{token}"), 1).as_bytes()).unwrap_err();
		assert!(e.path == "version" && e.message.contains("integer"), "{token}: {e}");
	}
	assert!(refused("inbounds[0].mtu", |d| d["inbounds"][0]["mtu"] = json!(1420.0)).contains("integer"));
	assert!(refused("inbounds[0].mtu", |d| d["inbounds"][0]["mtu"] = json!(70000)).contains("integer"));
	assert!(refused("inbounds[0].mtu", |d| d["inbounds"][0]["mtu"] = Value::Null).contains("null"));
	assert!(refused("dns.hijack", |d| d["dns"]["hijack"] = json!("yes")).contains("true or false"));
	assert!(refused("users", |d| d["users"] = json!({})).contains("a list"));
	assert!(refused("dns", |d| d["dns"] = json!([])).contains("an object"));
}

#[test]
fn required_and_optional_keys() {
	for key in ["version", "dns", "inbounds", "outbounds", "exits", "routing", "users"] {
		assert!(refused("", |d| remove(d, "", key)).contains(&format!("missing required key `{key}`")));
	}
	clean(|d| {
		remove(d, "", "groups");
		remove(d, "/users/0", "groups");
		remove(d, "/users/1", "groups");
		d["routing"]["rules"].as_array_mut().unwrap().truncate(2);
	});
	clean(|d| d["log"] = json!({"level": "debug", "destinations": true}));
	clean(|d| d["log"] = json!({}));
	warning_at("routing.rules", |d| remove(d, "/routing", "rules"));
	cases! {refused:
		"inbounds[0]": |d| remove(d, "/inbounds/0", "tag");
		"inbounds[0]": |d| remove(d, "/inbounds/0", "private_key");
		"inbounds[0].transports[1]": |d| remove(d, "/inbounds/0/transports/1", "path");
		"inbounds[0].transports[0]": |d| remove(d, "/inbounds/0/transports/0", "listen");
		"inbounds[0].transports[0]": |d| remove(d, "/inbounds/0/transports/0", "type");
		"inbounds[0].transports[1].tls": |d| d["inbounds"][0]["transports"][1]["tls"] = json!({"cert": "a.pem"});
		"inbounds[0].transports[1]": |d| d["inbounds"][0]["transports"][1]["tls"] = json!({"self_signed": true});
		"outbounds[0]": |d| remove(d, "/outbounds/0", "server");
		"exits[0].backend": |d| remove(d, "/exits/0/backend", "outbound");
		"exits[0]": |d| remove(d, "/exits/0", "backend");
		"routing": |d| remove(d, "/routing", "default");
		"routing.rules[2]": |d| remove(d, "/routing/rules/2", "action");
		"routing.rules[2]": |d| remove(d, "/routing/rules/2", "tag");
		"users[0]": |d| remove(d, "/users/0", "exits");
		"users[0]": |d| remove(d, "/users/0", "devices");
		"users[0].devices[0]": |d| remove(d, "/users/0/devices/0", "public_key");
		"users[0].devices[0]": |d| remove(d, "/users/0/devices/0", "addresses");
		"dns": |d| remove(d, "/dns", "servers");
	};
}

#[test]
fn unknown_keys_and_values_are_refused_as_possibly_newer() {
	for (pointer, path) in [
		("", ""), ("/dns", "dns"), ("/inbounds/0", "inbounds[0]"), ("/inbounds/0/transports/0", "inbounds[0].transports[0]"), ("/outbounds/0", "outbounds[0]"), ("/outbounds/1", "outbounds[1]"),
		("/exits/0", "exits[0]"), ("/exits/0/backend", "exits[0].backend"), ("/exits/3/backend", "exits[3].backend"), ("/routing", "routing"), ("/routing/rules/2", "routing.rules[2]"),
		("/routing/rules/3/action", "routing.rules[3].action"), ("/users/0", "users[0]"), ("/users/0/devices/0", "users[0].devices[0]"),
	] {
		let message = refused(path, |d| d.pointer_mut(pointer).unwrap()["future_key"] = json!(1));
		assert!(message.contains("unknown key \"future_key\"") && message.contains("newer than this build"), "{path}: {message}");
	}
	for (path, message) in [
		(refused("log", |d| d["log"] = json!({"colour": true})), "log"),
		(refused("inbounds[0].transports[1].tls", |d| d["inbounds"][0]["transports"][1]["tls"] = json!({"cert": "a", "key": "b", "ca": "c"})), "tls"),
		(refused("exits[0].backend.unsupported", |d| d["exits"][0]["backend"]["unsupported"] = json!({"tcp": "drop"})), "unsupported"),
	] {
		assert!(path.contains("unknown key"), "{message}: {path}");
	}
	let long = format!("{}\u{202e}\n\"tail", "k".repeat(70));
	let message = refused("", |d| d[long.as_str()] = json!(1));
	assert!(message.contains(&format!("\"{}...\"", "k".repeat(64))) && !message.contains("tail") && !message.contains(&"k".repeat(65)), "{message}");
	assert!(refused("", |d| d["a\u{202e}b\n"] = json!(1)).contains("unknown key \"a\\u{202e}b\\n\""));
	for message in [
		refused("log.level", |d| d["log"] = json!({"level": "loud"})),
		refused("inbounds[0].type", |d| d["inbounds"][0]["type"] = json!("openvpn")),
		refused("inbounds[0].transports[0].type", |d| d["inbounds"][0]["transports"][0]["type"] = json!("quic")),
		refused("outbounds[1].type", |d| d["outbounds"][1]["type"] = json!("http")),
		refused("exits[0].backend.type", |d| d["exits"][0]["backend"]["type"] = json!("tun")),
		refused("users[0].quota_period", |d| d["users"][0]["quota_period"] = json!("yearly")),
		refused("users[0].exits", |d| d["users"][0]["exits"] = json!("none")),
		refused("routing.rules[2].protocol[0]", |d| d["routing"]["rules"][2]["protocol"] = json!(["ospf"])),
		refused("routing.rules[2].action", |d| d["routing"]["rules"][2]["action"] = json!("allow")),
		refused("exits[0].backend.unsupported.udp", |d| d["exits"][0]["backend"]["unsupported"] = json!({"udp": "pass"})),
	] {
		assert!(message.contains("unknown value") && message.contains("newer than this build"), "{message}");
	}
	error_at("version", |d| d["version"] = json!(2));
}

#[test]
fn keys_belong_to_their_type() {
	cases! {refused:
		"inbounds[0].transports[0]": |d| d["inbounds"][0]["transports"][0]["path"] = json!("/wg");
		"inbounds[0].transports[0]": |d| d["inbounds"][0]["transports"][0]["tls"] = json!({"cert": "a.pem", "key": "b.pem"});
		"outbounds[1]": |d| d["outbounds"][1]["server"] = json!("127.0.0.1:1080");
		"outbounds[1]": |d| d["outbounds"][1]["password"] = json!("example-password");
		"outbounds[0]": |d| d["outbounds"][0]["bind"] = json!("192.0.2.7");
		"exits[0].backend": |d| d["exits"][0]["backend"]["interface"] = json!("veilway1");
		"exits[0].backend": |d| d["exits"][0]["backend"]["masquerade"] = json!(false);
		"exits[2].backend": |d| d["exits"][2]["backend"]["outbound"] = json!("proxy");
		"exits[2].backend": |d| d["exits"][2]["backend"]["unsupported"] = json!({});
		"exits[0].backend": |d| d["exits"][0]["backend"]["allow_ranges"] = json!([]);
		"exits[2].backend": |d| d["exits"][2]["backend"]["allow_ranges"] = json!(["192.168.50.0/24"]);
		"routing.rules[2]": |d| d["routing"]["rules"][2]["allow_private"] = json!(true);
		"exits[3].backend": |d| d["exits"][3]["backend"]["interface"] = json!("veilway1");
	};
	all_clean! {
		|d| d["outbounds"][1]["bind"] = json!("192.0.2.7");
		|d| d["exits"][2]["backend"] = json!({"type": "l3", "interface": "wan-1", "masquerade": false});
		|d| d["exits"][0]["backend"] = json!({"type": "netstack", "outbound": "proxy", "proxy_only": true, "tcp_idle_secs": 10, "udp_idle_secs": 3600, "unsupported": {"icmp_echo": "drop", "udp": "drop", "other": "drop"}});
	};
}

#[test]
fn tags_names_and_references() {
	cases! {error_at:
		"inbounds[0].tag": |d| d["inbounds"][0]["tag"] = json!("Home");
		"inbounds[0].tag": |d| d["inbounds"][0]["tag"] = json!("");
		"inbounds[0].tag": |d| d["inbounds"][0]["tag"] = json!("-home");
		"inbounds[0].tag": |d| d["inbounds"][0]["tag"] = json!("ho.me");
		"inbounds[0].tag": |d| d["inbounds"][0]["tag"] = json!("a".repeat(65));
		"inbounds[0].tag": |d| d["inbounds"][0]["tag"] = json!("all");
		"inbounds[1].tag": |d| d["inbounds"][1]["tag"] = json!("home");
		"outbounds[1].tag": |d| d["outbounds"][1]["tag"] = json!("direct");
		"outbounds[1].tag": |d| d["outbounds"][1]["tag"] = json!("proxy");
		"exits[3].tag": |d| d["exits"][3]["tag"] = json!("block");
		"exits[3].tag": |d| d["exits"][3]["tag"] = json!("node");
		"routing.rules[3].tag": |d| d["routing"]["rules"][3]["tag"] = json!("no-smtp");
		"routing.rules[3].tag": |d| d["routing"]["rules"][3]["tag"] = json!("user");
		"groups[0]": |d| d["groups"][0] = json!("Staff");
		"groups[1]": |d| d["groups"][1] = json!("staff");
		"users[0].name": |d| d["users"][0]["name"] = json!("Alice");
		"users[1].name": |d| d["users"][1]["name"] = json!("alice");
		"users[0].devices[0].name": |d| d["users"][0]["devices"][0]["name"] = json!("my laptop");
		"exits[0].backend.outbound": |d| d["exits"][0]["backend"]["outbound"] = json!("missing");
		"routing.default": |d| d["routing"]["default"] = json!("missing");
		"routing.rules[3].action.exit": |d| d["routing"]["rules"][3]["action"] = json!({"exit": "missing"});
		"routing.rules[3].group[0]": |d| d["routing"]["rules"][3]["group"] = json!(["missing"]);
		"routing.rules[2].inbound[0]": |d| d["routing"]["rules"][2]["inbound"] = json!(["missing"]);
		"routing.rules[2].user[1]": |d| d["routing"]["rules"][2]["user"] = json!(["alice", "missing"]);
		"users[0].groups[0]": |d| d["users"][0]["groups"] = json!(["missing"]);
		"users[1].exits[1]": |d| d["users"][1]["exits"] = json!(["main", "missing"]);
		"users[0].exit": |d| d["users"][0]["exit"] = json!("missing");
	};
	all_clean! {
		|d| d["inbounds"][0]["tag"] = json!("0_a-b");
		|d| d["inbounds"][0]["tag"] = json!("a".repeat(64));
		|d| d["exits"][3]["tag"] = json!("home");
		|d| d["users"][0]["name"] = json!("a.b_c-d");
		|d| d["routing"]["rules"][2]["inbound"] = json!(["home", "office"]);
		|d| d["routing"]["rules"][2]["user"] = json!(["alice", "bob"]);
	};
}

#[test]
fn limits() {
	error_at("groups", |d| d["groups"] = (0..257).map(|i| format!("g{i}")).collect());
	clean(|d| d["groups"] = ["staff".to_string(), "guest".to_string()].into_iter().chain((0..254).map(|i| format!("g{i}"))).collect());
	error_at("inbounds", |d| d["inbounds"] = (0..65).map(|i| json!({"tag": format!("in{i}"), "type": "wireguard", "private_key": key(0x11), "address": ["10.9.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:1"}]})).collect());
	error_at("inbounds[0].transports", |d| d["inbounds"][0]["transports"] = (0..9).map(|i| json!({"type": "udp", "listen": format!("0.0.0.0:{}", 2000 + i)})).collect());
	clean(|d| d["inbounds"][0]["transports"] = (0..8).map(|i| json!({"type": "udp", "listen": format!("0.0.0.0:{}", 2000 + i)})).collect());
	error_at("inbounds[0].transports", |d| d["inbounds"][0]["transports"] = json!([]));
	error_at("outbounds", |d| d["outbounds"] = (0..257).map(|i| json!({"tag": format!("o{i}"), "type": "direct"})).collect());
	error_at("exits", |d| d["exits"] = (0..257).map(|i| json!({"tag": format!("e{i}"), "backend": {"type": "block"}})).collect());
	error_at("routing.rules", |d| d["routing"]["rules"] = (0..MAX_RULES + 1).map(|i| json!({"tag": format!("r{i}"), "port": [i + 1], "protocol": ["tcp"], "action": "block"})).collect());
	error_at("routing.rules[2].port", |d| d["routing"]["rules"][2]["port"] = (1..=1025).collect());
	clean(|d| d["routing"]["rules"][2]["port"] = (1001..=2024).collect());
	error_at("users[0].devices", |d| d["users"][0]["devices"] = (0..17).map(|i| json!({"name": format!("d{i}"), "public_key": key(0x40 + i), "addresses": [format!("10.7.0.{}", 10 + i)]})).collect());
	clean(|d| d["users"][0]["devices"] = (0..16).map(|i| json!({"name": format!("d{i}"), "public_key": key(0x40 + i), "addresses": [format!("10.7.0.{}", 10 + i)]})).collect());
	error_at("users[0].devices", |d| d["users"][0]["devices"] = json!([]));
	error_at("users[0].devices[0].addresses", |d| d["users"][0]["devices"][0]["addresses"] = (0..17).map(|i| format!("10.7.0.{}", 10 + i)).collect());
	error_at("users[0].devices[0].addresses", |d| d["users"][0]["devices"][0]["addresses"] = json!([]));
	let user = good()["users"][1].clone();
	error_at("users", |d| d["users"] = vec![user; MAX_USERS + 1].into());
}

#[test]
fn at_most_one_hundred_of_each_are_kept() {
	let report = check(&with(|d| {
		for i in 0..250 {push(d, "/groups", json!(format!("G{i}")))}
		for i in 0..150 {push(d, "/exits", json!({"tag": format!("e{i}"), "backend": {"type": "netstack", "outbound": "plain", "unsupported": {"udp": "drop"}}}))}
	}));
	assert_eq!((report.errors.len(), report.more_errors), (MAX_DIAGNOSTICS, 150));
	assert_eq!((report.warnings.len(), report.more_warnings), (MAX_DIAGNOSTICS, 50));
}

#[test]
fn addresses() {
	for bad in ["1.1.1.1", "1.1.1.1:0", "1.1.1.1:65536", "[::ffff:1.2.3.4]:53", "[fe80::1%eth0]:53", "[fe80::1%1]:53", "resolver.example.com:53", "2606:4700::1111:53", " 1.1.1.1:53", "1.1.1.1:053", "1.1.1.1:00053", "1.1.1.1:+53", "1.1.1.1:-53", "[2606:4700:4700::1111]:053"] {
		refused("dns.servers[0]", |d| d["dns"]["servers"][0] = json!(bad));
	}
	refused("inbounds[0].transports[0].listen", |d| d["inbounds"][0]["transports"][0]["listen"] = json!("0.0.0.0:051820"));
	for bad in ["10.7.0.1", "10.7.0.1/33", "10.7.0.1/+24", "10.7.0.1/024x", "10.7.0.1/024", "::ffff:10.7.0.1/120", "fd00::1%eth0/64", "10.7.0.1/"] {
		refused("inbounds[0].address[0]", |d| d["inbounds"][0]["address"][0] = json!(bad));
	}
	refused("inbounds[0].address[1]", |d| d["inbounds"][0]["address"][1] = json!("fd7a:115c:a1e0::1/064"));
	for bad in ["192.168.50.5/24", "192.168.50.0", "::ffff:192.168.50.0/120", "192.168.50.0/024", "192.168.0.0/016", "0.0.0.0/00"] {
		refused("routing.rules[2].ip[0]", |d| d["routing"]["rules"][2]["ip"] = json!([bad]));
	}
	for bad in ["10.7.0.2/32", "fe80::2%eth0", "::ffff:10.7.0.2", "10.7.0.02"] {
		refused("users[0].devices[0].addresses[0]", |d| d["users"][0]["devices"][0]["addresses"][0] = json!(bad));
	}
	for bad in ["fe80::1%eth0", "::ffff:192.0.2.7", "192.0.2.7:0"] {
		refused("outbounds[1].bind", |d| d["outbounds"][1]["bind"] = json!(bad));
	}
	error_at("outbounds[1].bind", |d| d["outbounds"][1]["bind"] = json!("0.0.0.0"));
	error_at("outbounds[1].bind", |d| d["outbounds"][1]["bind"] = json!("::"));
	for bad in ["proxy.example.com", "[::1]", "::1:1080", "Proxy.example.com:1080", "proxy.example.com:0", "proxy.example.com:080", "proxy.example.com:65536", "[::ffff:1.2.3.4]:1080", "[fe80::1%eth0]:1080", "[1.2.3.4]:1080", "1.2.3:1080", "-a.example.com:1080", ":1080", "proxy.example.com:+1080", "proxy.example.com:-1080", "192.0.2.1:01080", "[2001:db8::1]:01080", "[2001:db8::1]:+1080", "0x7f000001:1080", "proxy.0x7f:1080", "proxy.0x:1080"] {
		refused("outbounds[0].server", |d| d["outbounds"][0]["server"] = json!(bad));
	}
	for fine in ["proxy.example.com:1080", "[2001:db8::1]:1080", "192.0.2.1:65535", "localhost:1", "0x7f.example.com:1080", "proxy.0xg:1080"] {
		clean(|d| d["outbounds"][0]["server"] = json!(fine));
	}
	all_clean! {
		|d| d["dns"]["servers"] = json!(["9.9.9.9:53", "[2620:fe::fe]:5353"]);
		|d| d["routing"]["rules"][2]["ip"] = json!(["8.8.8.0/24", "2001:4860::/32", "0.0.0.0/0", "::/0", "9.9.9.10/32"]);
	};
}

#[test]
fn wireguard_keys() {
	let zero = key(0);
	for bad in [zero.as_str(), &key(0x11)[..43], &format!("{} ", &key(0x11)[..43]), &key(0x11).replace('=', ""), &key(0x11).replace("ER", "-_"), "ERERERERERERERERERERERERERERERERERERERERERF=", &"ER".repeat(24), ""] {
		refused("inbounds[0].private_key", |d| d["inbounds"][0]["private_key"] = json!(bad));
		refused("users[0].devices[0].public_key", |d| d["users"][0]["devices"][0]["public_key"] = json!(bad));
		refused("users[0].devices[0].preshared_key", |d| d["users"][0]["devices"][0]["preshared_key"] = json!(bad));
	}
	refused("inbounds[0].private_key", |d| d["inbounds"][0]["private_key"] = json!(7));
	// 0x11 and 0x10 repeated clamp to different scalars, while a key and its clamped form are the same key written twice.
	let mut clamped = [0x11u8; 32];
	clamped[0] &= 248;
	clamped[31] = clamped[31] & 127 | 64;
	error_at("inbounds[1].private_key", |d| d["inbounds"][1]["private_key"] = json!(veilway_wg::encode_key(&clamped)));
	error_at("inbounds[1].private_key", |d| d["inbounds"][1]["private_key"] = json!(key(0x11)));
	error_at("users[1].devices[0].public_key", |d| d["users"][1]["devices"][0]["public_key"] = json!(key(0x21)));
	error_at("users[0].devices[0].public_key", |d| d["users"][0]["devices"][0]["public_key"] = json!(veilway_wg::encode_key(&veilway_wg::public_key(&[0x12; 32]))));
	clean(|d| d["users"][1]["devices"][0]["preshared_key"] = json!(key(0x31)));
}

#[test]
fn dns() {
	cases! {error_at:
		"dns.servers": |d| d["dns"]["servers"] = json!([]);
		"dns.servers": |d| d["dns"]["servers"] = json!(["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53", "9.9.9.9:53"]);
		"dns.servers[1]": |d| d["dns"]["servers"] = json!(["1.1.1.1:53", "1.1.1.1:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["127.0.0.1:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["[::1]:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["169.254.1.1:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["[fe80::1]:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["0.0.0.0:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["224.0.0.251:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["[ff02::fb]:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["10.7.0.9:53"]);
		"dns.servers[0]": |d| d["dns"]["servers"] = json!(["[fd7a:115c:a1e0::53]:53"]);
	};
	all_clean! {
		|d| d["dns"] = json!({"servers": ["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "[2606:4700:4700::1111]:53"], "hijack": false});
	};
}

/// Three sets on the known-good document: one for user `bob`, one for group `staff`, one for inbound `office`. User `carol` is added on `office`, in no group, so each set has somebody whose queries go to it.
fn sets(d: &mut Value) {
	push(d, "/users", json!({"name": "carol", "exits": "all", "devices": [{"name": "tablet", "public_key": key(0x23), "addresses": ["10.8.0.3"]}]}));
	d["dns"]["sets"] = json!([
		{"tag": "adblock", "servers": ["9.9.9.11:53"], "users": ["bob"]},
		{"tag": "family", "servers": ["1.1.1.3:53", "[2606:4700:4700::1113]:53"], "groups": ["staff"]},
		{"tag": "lab", "servers": ["9.9.9.9:53"], "inbounds": ["office"]}
	]);
}

#[test]
fn dns_sets() {
	let set = |d: &mut Value, key: &str, value: Value| {
		sets(d);
		d["dns"]["sets"][0][key] = value;
	};
	all_clean! {
		|d| sets(d);
		|d| d["dns"]["sets"] = json!([]);
		|d| set(d, "servers", json!(["1.1.1.1:53", "1.1.1.3:53", "9.9.9.9:53", "8.8.8.8:53"]));
		|d| set(d, "groups", json!(["guest"]));
		|d| d["dns"] = json!({"servers": ["1.1.1.1:53"], "hijack": false, "sets": []});
		|d| {sets(d); d["dns"]["hijack"] = json!(true)};
	};
	// Thirty-two sets are within the limit. Thirty of them name a group nobody is in, which is a warning for each and no error.
	let full = check(&with(|d| {
		let groups: Vec<String> = ["staff".to_string(), "guest".to_string()].into_iter().chain((0..30).map(|i| format!("g{i}"))).collect();
		d["dns"]["sets"] = groups.iter().enumerate().map(|(i, group)| json!({"tag": format!("s{i}"), "servers": [format!("9.9.9.{}:53", i + 1)], "groups": [group]})).collect();
		d["groups"] = groups.into();
	}));
	assert!(full.errors.is_empty() && full.warnings.iter().map(|w| w.path.clone()).eq((2..32).map(|i| format!("dns.sets[{i}]"))), "{full:#?}");
	// A set that can be stepped around decides nothing, so sets need `hijack`.
	assert!(check(&with(|d| {sets(d); d["dns"]["hijack"] = json!(false)})).errors.iter().any(|e| e.path == "dns.hijack" && e.message.contains("dns.sets")));
	// A set that names somebody and still gets no query: its group has no user left, or every user of its inbound goes by a more specific set.
	cases! {warning_at:
		"dns.sets[1]": |d| {sets(d); d["dns"]["sets"][1]["groups"] = json!(["guest"])};
		"dns.sets[2]": |d| {sets(d); d["dns"]["sets"][0]["users"] = json!(["bob", "carol"])};
		"dns.sets[2]": |d| {sets(d); d["users"][2]["groups"] = json!(["staff"])};
	};
	// An address the destination gate refuses is no server, in `dns.servers` and in a set, and neither is an IPv6 address that carries one.
	for (path, list) in [("dns.servers[0]", "/dns/servers"), ("dns.sets[1].servers[0]", "/dns/sets/1/servers")] {
		for refused in ["[64:ff9b::7f00:1]:53", "[2002:a07:9::]:53", "[64:ff9b::a07:9]:53", "[::127.0.0.1]:53", "[2001:0:a9fe:101::1]:53", "255.255.255.255:53", "0.1.2.3:53"] {
			let report = check(&with(|d| {
				sets(d);
				*d.pointer_mut(list).unwrap() = json!([refused]);
			}));
			assert!(report.errors.len() == 1 && report.errors[0].path == path, "{refused} at {path}: {report:#?}");
		}
	}
	all_clean! {
		|d| {sets(d); d["dns"]["sets"][1]["servers"] = json!(["[64:ff9b::101:103]:53", "[2002:101:103::]:53"])};
	};
	cases! {error_at:
		"dns.sets": |d| d["dns"]["sets"] = (0..33).map(|i| json!({"tag": format!("s{i}"), "servers": ["9.9.9.9:53"]})).collect();
		"dns.sets[1].tag": |d| {sets(d); d["dns"]["sets"][1]["tag"] = json!("adblock")};
		"dns.sets[0].tag": |d| set(d, "tag", json!("direct"));
		"dns.sets[0].tag": |d| set(d, "tag", json!("Family"));
		"dns.sets[0].tag": |d| set(d, "tag", json!(""));
		"dns.sets[0].servers": |d| set(d, "servers", json!([]));
		"dns.sets[0].servers": |d| set(d, "servers", json!(["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53", "9.9.9.9:53"]));
		"dns.sets[0].servers[1]": |d| set(d, "servers", json!(["9.9.9.9:53", "9.9.9.9:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["127.0.0.1:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["[::1]:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["169.254.1.1:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["[fe80::1]:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["0.0.0.0:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["224.0.0.251:53"]));
		"dns.sets[0].servers[1]": |d| set(d, "servers", json!(["9.9.9.9:53", "10.8.0.9:53"]));
		"dns.sets[0].servers[0]": |d| set(d, "servers", json!(["[fd7a:115c:a1e0::53]:53"]));
		"dns.sets[0].inbounds[0]": |d| set(d, "inbounds", json!(["nowhere"]));
		"dns.sets[0].groups[0]": |d| set(d, "groups", json!(["nobody"]));
		"dns.sets[0].users[1]": |d| set(d, "users", json!(["bob", "dave"]));
		"dns.sets[0].users[1]": |d| set(d, "users", json!(["bob", "bob"]));
		"dns.sets[1].users[0]": |d| {sets(d); d["dns"]["sets"][1]["users"] = json!(["bob"])};
		"dns.sets[2].groups[1]": |d| {sets(d); d["dns"]["sets"][2]["groups"] = json!(["guest", "staff"])};
		"dns.sets[2].inbounds[0]": |d| set(d, "inbounds", json!(["office"]));
		"dns.sets[0].inbounds": |d| set(d, "inbounds", (0..65).map(|i| format!("in{i}")).collect());
		"dns.sets[0].groups": |d| set(d, "groups", (0..257).map(|i| format!("g{i}")).collect());
		"users[0].groups": |d| {sets(d); d["dns"]["sets"][2]["groups"] = json!(["guest"]); d["users"][0]["groups"] = json!(["guest", "staff"])};
	};
	// The user whose groups lead to two sets is named with both of them, and a set that names the user settles it.
	let torn = |d: &mut Value| {
		sets(d);
		d["dns"]["sets"][2]["groups"] = json!(["guest"]);
		d["users"][0]["groups"] = json!(["staff", "guest"]);
	};
	let report = check(&with(torn));
	assert_eq!(report.errors.len(), 1, "{report:#?}");
	assert!(report.errors[0].path == "users[0].groups" && report.errors[0].message.contains("dns.sets[1].groups[0]") && report.errors[0].message.contains("dns.sets[2].groups[0]"), "{report:#?}");
	assert!(check(&with(|d| {torn(d); d["dns"]["sets"][0]["users"] = json!(["bob", "alice"])})).errors.is_empty());
	all_clean! {
		|d| {sets(d); d["dns"]["sets"][1]["groups"] = json!(["staff", "guest"]); d["users"][0]["groups"] = json!(["staff", "guest"])};
	};
	// A name that is named twice says where it was named first.
	let twice = check(&with(|d| {sets(d); d["dns"]["sets"][2]["users"] = json!(["bob"])}));
	assert!(twice.errors.len() == 1 && twice.errors[0].message.contains("dns.sets[0].users[0]"), "{twice:#?}");
	warning_at("dns.sets[0]", |d| {sets(d); remove(d, "/dns/sets/0", "users")});
	cases! {refused:
		"dns.sets[0]": |d| {sets(d); remove(d, "/dns/sets/0", "tag")};
		"dns.sets[0]": |d| {sets(d); remove(d, "/dns/sets/0", "servers")};
		"dns.sets[1]": |d| {sets(d); d["dns"]["sets"][1]["future_key"] = json!(1)};
		"dns.sets[2].servers[0]": |d| {sets(d); d["dns"]["sets"][2]["servers"] = json!(["9.9.9.9"])};
		"dns.sets[2].inbounds": |d| {sets(d); d["dns"]["sets"][2]["inbounds"] = json!("office")};
		"dns.sets": |d| d["dns"]["sets"] = json!({});
	};
	// The servers of a set are the node's resolver like `dns.servers`: a rule that refuses one of them is warned about by its path.
	let report = check(&with(|d| {sets(d); d["dns"]["sets"][1]["servers"] = json!(["1.1.1.3:53", "192.168.1.1:53"])}));
	assert_eq!(report.warnings.iter().map(|w| (w.path.as_str(), w.message.contains("dns.sets[1].servers[1]"))).collect::<Vec<_>>(), [("routing.rules[1]", true)], "{report:#?}");
	// A document with sets comes back from its own text as it was, and one without them is written without the key.
	let (with_sets, without) = (parse(&with(sets)).unwrap(), parse(&good()).unwrap());
	assert_eq!(parse(&serde_json::to_value(&with_sets).unwrap()).unwrap(), with_sets);
	assert!(without.dns.sets.is_empty() && serde_json::to_value(&without).unwrap()["dns"].get("sets").is_none());
}

#[test]
fn inbound_pools_and_mtu() {
	cases! {error_at:
		"inbounds[0].address": |d| d["inbounds"][0]["address"] = json!([]);
		"inbounds[0].address": |d| d["inbounds"][0]["address"] = json!(["10.7.0.1/24", "fd7a:115c:a1e0::1/64", "10.9.0.1/24"]);
		"inbounds[0].address": |d| d["inbounds"][0]["address"] = json!(["10.7.0.1/24", "10.9.0.1/24"]);
		"inbounds[0].address[0]": |d| d["inbounds"][0]["address"][0] = json!("10.7.0.1/15");
		"inbounds[0].address[0]": |d| d["inbounds"][0]["address"][0] = json!("10.7.0.1/31");
		"inbounds[0].address[0]": |d| d["inbounds"][0]["address"][0] = json!("192.0.2.1/24");
		"inbounds[0].address[0]": |d| d["inbounds"][0]["address"][0] = json!("172.32.0.1/24");
		"inbounds[0].address[1]": |d| d["inbounds"][0]["address"][1] = json!("2001:db8::1/64");
		"inbounds[0].address[1]": |d| d["inbounds"][0]["address"][1] = json!("fd7a:115c:a1e0::1/47");
		"inbounds[0].address[1]": |d| d["inbounds"][0]["address"][1] = json!("fd7a:115c:a1e0::1/127");
		"inbounds[0].address[0]": |d| d["inbounds"][0]["address"][0] = json!("10.7.0.0/24");
		"inbounds[0].address[0]": |d| d["inbounds"][0]["address"][0] = json!("10.7.0.255/24");
		"inbounds[0].address[1]": |d| d["inbounds"][0]["address"][1] = json!("fd7a:115c:a1e0::/64");
		"inbounds[1].address[0]": |d| d["inbounds"][1]["address"][0] = json!("10.7.0.129/25");
		"inbounds[1].address[0]": |d| d["inbounds"][1]["address"][0] = json!("10.7.9.1/16");
		"inbounds[0].mtu": |d| d["inbounds"][0]["mtu"] = json!(1279);
		"inbounds[0].mtu": |d| d["inbounds"][0]["mtu"] = json!(1501);
	};
	warning_at("inbounds[0].mtu", |d| d["inbounds"][0]["mtu"] = json!(1421));
	warning_at("inbounds[0].mtu", |d| d["inbounds"][0]["mtu"] = json!(1500));
	all_clean! {
		|d| d["inbounds"][0]["mtu"] = json!(1280);
		|d| d["inbounds"][0]["mtu"] = json!(1420);
		|d| {
			d["inbounds"][1]["address"] = json!(["100.64.0.1/30"]);
			d["users"][0]["devices"][0]["addresses"][2] = json!("100.64.0.2");
		};
		|d| {
			d["inbounds"][1]["address"] = json!(["172.16.0.1/16", "fc00::1/126"]);
			d["users"][0]["devices"][0]["addresses"][2] = json!("172.16.255.254");
		};
		|d| {
			d["inbounds"][1]["address"] = json!(["fd00::ffff/48"]);
			d["users"][0]["devices"][0]["addresses"][2] = json!("fd00::1");
		};
	};
}

#[test]
fn transports_and_listen_conflicts() {
	let tls = json!({"cert": "tls/cert.pem", "key": "tls/key.pem"});
	for bad in ["wg", "", "/a b", "/a?b", "/a/../b", "/..", "/é", &format!("/{}", "a".repeat(256))] {
		error_at("inbounds[0].transports[1].path", |d| d["inbounds"][0]["transports"][1]["path"] = json!(bad));
	}
	for fine in ["/", "/A-z_0.9~/x", "/a..b", &format!("/{}", "a".repeat(255))] {
		clean(|d| d["inbounds"][0]["transports"][1]["path"] = json!(fine));
	}
	for bad in ["/etc/tls/cert.pem", "../cert.pem", "tls/../../cert.pem", "C:\\tls\\cert.pem", "\\\\host\\cert.pem", "tls\\..\\cert.pem", ""] {
		error_at("inbounds[0].transports[1].tls.cert", |d| d["inbounds"][0]["transports"][1]["tls"] = json!({"cert": bad, "key": "key.pem"}));
		error_at("inbounds[0].transports[1].tls.key", |d| d["inbounds"][0]["transports"][1]["tls"] = json!({"cert": "cert.pem", "key": bad}));
	}
	warning_at("inbounds[0].transports[1].listen", |d| d["inbounds"][0]["transports"][1]["listen"] = json!("0.0.0.0:443"));
	clean(|d| d["inbounds"][0]["transports"][1] = json!({"type": "ws", "listen": "0.0.0.0:443", "path": "/wg", "tls": tls}));
	clean(|d| d["inbounds"][0]["transports"][1]["listen"] = json!("[::1]:8080"));
	cases! {error_at:
		"inbounds[1].transports[0].listen": |d| d["inbounds"][1]["transports"][0]["listen"] = json!("0.0.0.0:51820");
		"inbounds[1].transports[0].listen": |d| d["inbounds"][1]["transports"][0]["listen"] = json!("192.0.2.1:51820");
		"inbounds[0].transports[2].listen": |d| push(d, "/inbounds/0/transports", json!({"type": "ws", "listen": "127.0.0.1:8080", "path": "/wg"}));
		"inbounds[0].transports[2].listen": |d| push(d, "/inbounds/0/transports", json!({"type": "ws", "listen": "127.0.0.1:8080", "path": "/other", "tls": tls}));
		"inbounds[1].transports[1].listen": |d| {
			d["inbounds"][0]["transports"][1] = json!({"type": "ws", "listen": "0.0.0.0:443", "path": "/wg", "tls": tls});
			push(d, "/inbounds/1/transports", json!({"type": "ws", "listen": "192.0.2.1:443", "path": "/other", "tls": tls}));
		};
		"inbounds[1].transports[1].listen": |d| {
			d["inbounds"][0]["transports"][1] = json!({"type": "ws", "listen": "0.0.0.0:443", "path": "/wg", "tls": tls});
			push(d, "/inbounds/1/transports", json!({"type": "ws", "listen": "0.0.0.0:443", "path": "/other", "tls": {"cert": "tls/other.pem", "key": "tls/key.pem"}}));
		};
	};
	all_clean! {
		|d| d["inbounds"][1]["transports"][0]["listen"] = json!("[::]:51820");
		|d| d["inbounds"][1]["transports"][0]["listen"] = json!("127.0.0.1:8080");
		|d| d["inbounds"][1]["transports"][0]["listen"] = json!("0.0.0.0:51821");
		|d| push(d, "/inbounds/1/transports", json!({"type": "ws", "listen": "127.0.0.1:8080", "path": "/office"}));
		|d| {
			d["inbounds"][0]["transports"][1] = json!({"type": "ws", "listen": "0.0.0.0:443", "path": "/wg", "tls": tls});
			push(d, "/inbounds/1/transports", json!({"type": "ws", "listen": "0.0.0.0:443", "path": "/office", "tls": tls}));
			push(d, "/inbounds/1/transports", json!({"type": "ws", "listen": "[::]:443", "path": "/wg", "tls": tls}));
		};
	};
}

#[test]
fn a_veilway_inbound_no_device_can_use_is_warned_about() {
	let veilway = |d: &mut Value| {
		d["inbounds"][1]["type"] = json!("veilway");
		d["inbounds"][1]["transports"] = json!([{"type": "udp-obfs", "listen": "[::]:51821"}]);
		d["users"][0]["devices"][0]["addresses"].as_array_mut().unwrap().pop();
	};
	warning_at("inbounds[1].address", veilway);
	clean(|d| {
		veilway(d);
		d["users"] = json!([]);
	});
	let report = check(&with(|d| {
		veilway(d);
		d["users"][1]["devices"][0]["addresses"] = json!(["10.8.0.3"]);
		d["users"][1]["devices"][0]["transport_secrets"] = json!([key(0x41)]);
	}));
	assert!(report.errors.is_empty() && report.warnings.iter().all(|w| w.path != "inbounds[1].address"), "{report:#?}");
}

#[test]
fn outbounds() {
	cases! {error_at:
		"outbounds[0]": |d| remove(d, "/outbounds/0", "password");
		"outbounds[0]": |d| remove(d, "/outbounds/0", "username");
		"outbounds[0].password": |d| d["outbounds"][0]["password"] = json!("");
		"outbounds[0].username": |d| d["outbounds"][0]["username"] = json!("u".repeat(256));
	};
	all_clean! {
		|d| d["outbounds"][0] = json!({"tag": "proxy", "type": "socks5", "server": "127.0.0.1:1080"});
		|d| d["outbounds"][0]["password"] = json!("p".repeat(255));
	};
}

#[test]
fn the_load_of_an_exit() {
	cases! {error_at:
		"exits[0].load.busy": |d| d["exits"][0]["load"] = json!({"by": "flows", "busy": 0, "very_busy": 10});
		"exits[0].load.busy": |d| d["exits"][0]["load"] = json!({"by": "mbps", "busy": 1000001, "very_busy": 1000002});
		"exits[0].load.very_busy": |d| d["exits"][0]["load"] = json!({"by": "flows", "busy": 10, "very_busy": 10});
		"exits[0].load.very_busy": |d| d["exits"][0]["load"] = json!({"by": "flows", "busy": 10, "very_busy": 5});
		"exits[0].load.very_busy": |d| d["exits"][0]["load"] = json!({"by": "mbps", "busy": 10, "very_busy": 1000001});
		"exits[3].load": |d| d["exits"][3]["load"] = json!({"by": "flows", "busy": 10, "very_busy": 20});
	};
	all_clean! {
		|d| d["exits"][0]["load"] = json!({"by": "flows", "busy": 1, "very_busy": 2});
		|d| d["exits"][0]["load"] = json!({"by": "mbps", "busy": 999999, "very_busy": 1000000});
		|d| d["exits"][2]["load"] = json!({"by": "mbps", "busy": 100, "very_busy": 400});
	};
	for bad in [json!({"by": "bytes", "busy": 1, "very_busy": 2}), json!({"by": "flows", "busy": 1}), json!({"by": "flows", "busy": 1.5, "very_busy": 2}), json!({"by": "flows", "busy": -1, "very_busy": 2}), json!({"by": "flows", "busy": 1, "very_busy": 2, "extra": 1})] {
		let mut doc = good();
		doc["exits"][0]["load"] = bad.clone();
		assert!(Config::parse(doc.to_string().as_bytes()).is_err(), "{bad} was parsed");
	}
}

#[test]
fn exits_and_backends() {
	cases! {error_at:
		"exits[0].name": |d| d["exits"][0]["name"] = json!("");
		"exits[0].name": |d| d["exits"][0]["name"] = json!("n".repeat(65));
		"exits[0].name": |d| d["exits"][0]["name"] = json!("a\u{202e}b");
		"exits[0].name": |d| d["exits"][0]["name"] = json!("a\u{2066}b");
		"exits[0].name": |d| d["exits"][0]["name"] = json!("a\nb");
		"exits[0].name": |d| d["exits"][0]["name"] = json!("\u{feff}");
		"exits[0].country": |d| d["exits"][0]["country"] = json!("nl");
		"exits[0].country": |d| d["exits"][0]["country"] = json!("NLD");
		"exits[0].country": |d| d["exits"][0]["country"] = json!("N1");
		"exits[1].backend.proxy_only": |d| d["exits"][1]["backend"]["proxy_only"] = json!(true);
		"exits[0].backend.tcp_idle_secs": |d| d["exits"][0]["backend"]["tcp_idle_secs"] = json!(9);
		"exits[0].backend.tcp_idle_secs": |d| d["exits"][0]["backend"]["tcp_idle_secs"] = json!(86401);
		"exits[0].backend.udp_idle_secs": |d| d["exits"][0]["backend"]["udp_idle_secs"] = json!(4);
		"exits[0].backend.udp_idle_secs": |d| d["exits"][0]["backend"]["udp_idle_secs"] = json!(3601);
		"exits[2].backend.interface": |d| d["exits"][2]["backend"]["interface"] = json!("Eth0");
		"exits[2].backend.interface": |d| d["exits"][2]["backend"]["interface"] = json!("0eth");
		"exits[2].backend.interface": |d| d["exits"][2]["backend"]["interface"] = json!("a".repeat(16));
		"exits[3].backend.interface": |d| d["exits"][3]["backend"] = json!({"type": "l3"});
		"exits[3].backend.interface": |d| d["exits"][3]["backend"] = json!({"type": "l3", "interface": "veilway0"});
	};
	// A joiner between Latin letters is refused like any invisible character. The same character inside a Persian word is spelling, see below.
	for invisible in ['\u{ad}', '\u{61c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}', '\u{2060}', '\u{2062}', '\u{2064}', '\u{2065}', '\u{2069}', '\u{feff}', '\u{e0000}', '\u{e0041}', '\u{e007f}', '\u{e0080}'] {
		error_at("exits[0].name", |d| d["exits"][0]["name"] = json!(format!("Main{invisible}exit")));
	}
	for visible in ['\u{ac}', '\u{ae}', '\u{200a}', '\u{2027}', '\u{202f}', '\u{205f}'] {
		clean(|d| d["exits"][0]["name"] = json!(format!("Main{visible}exit")));
	}
	all_clean! {
		|d| d["exits"][0]["name"] = json!("Amsterdam \u{1f1f3}\u{1f1f1} \u{0627}\u{0635}\u{0644}\u{06cc}");
		|d| d["exits"][0]["name"] = json!("\u{062e}\u{0627}\u{0646}\u{0647}\u{200c}\u{0647}\u{0627}");
		|d| d["exits"][0]["name"] = json!("n".repeat(64));
		|d| d["exits"][0]["country"] = json!("ZZ");
		|d| d["exits"][1]["backend"]["proxy_only"] = json!(false);
		|d| d["exits"][0]["backend"]["tcp_idle_secs"] = json!(86400);
		|d| d["exits"][0]["backend"]["udp_idle_secs"] = json!(5);
		|d| d["exits"][2]["backend"]["interface"] = json!("a".repeat(15));
		|d| d["exits"][3]["backend"] = json!({"type": "l3", "interface": "veilway1"});
	};
}

#[test]
fn unsupported_policies() {
	let around = |d: &mut Value, key: &str, policy: Value| {
		d["exits"][0]["backend"]["proxy_only"] = json!(false);
		d["exits"][0]["backend"]["unsupported"] = json!({key: policy});
	};
	cases! {error_at:
		"exits[0].backend.unsupported.udp": |d| d["exits"][0]["backend"]["unsupported"] = json!({"udp": "local"});
		"exits[0].backend.unsupported.other": |d| d["exits"][0]["backend"]["unsupported"] = json!({"other": "local"});
		"exits[0].backend.unsupported.other": |d| around(d, "other", json!("direct"));
		"exits[0].backend.unsupported.icmp_echo": |d| d["exits"][0]["backend"]["unsupported"] = json!({"icmp_echo": "direct"});
		"exits[0].backend.unsupported.udp": |d| d["exits"][0]["backend"]["unsupported"] = json!({"udp": {"via": "node"}});
		"exits[1].backend.unsupported.icmp_echo": |d| d["exits"][1]["backend"]["unsupported"] = json!({"icmp_echo": "direct"});
		"exits[0].backend.unsupported.udp.via": |d| around(d, "udp", json!({"via": "missing"}));
		"exits[0].backend.unsupported.udp.via": |d| around(d, "udp", json!({"via": "main"}));
		"exits[0].backend.unsupported.udp.via": |d| around(d, "udp", json!({"via": "sink"}));
		"exits[0].backend.unsupported.icmp_echo.via": |d| around(d, "icmp_echo", json!({"via": "open"}));
		"exits[0].backend.unsupported.other.via": |d| around(d, "other", json!({"via": "open"}));
		"exits[0].backend.unsupported.other.via": |d| around(d, "other", json!({"via": "sink"}));
	};
	refused("exits[0].backend.unsupported.udp.via", |d| around(d, "udp", json!({"via": 5})));
	refused("exits[0].backend.unsupported.udp", |d| around(d, "udp", json!({"via": "node", "then": "open"})));
	refused("exits[0].backend.unsupported.udp", |d| around(d, "udp", json!({})));
	cases! {warning_at:
		"exits[0].backend.unsupported.icmp_echo": |d| around(d, "icmp_echo", json!("direct"));
		"exits[0].backend.unsupported.udp": |d| around(d, "udp", json!("direct"));
		"exits[0].backend.unsupported.udp": |d| around(d, "udp", json!({"via": "open"}));
		"exits[0].backend.unsupported.udp": |d| around(d, "udp", json!({"via": "node"}));
		"exits[0].backend.unsupported.icmp_echo": |d| around(d, "icmp_echo", json!({"via": "node"}));
		"exits[0].backend.unsupported.other": |d| around(d, "other", json!({"via": "node"}));
		"exits[1].backend.unsupported.udp": |d| d["exits"][1]["backend"]["unsupported"] = json!({"udp": "drop"});
	};
	all_clean! {
		|d| d["exits"][0]["backend"]["unsupported"] = json!({"icmp_echo": "reject", "udp": "drop", "other": "drop"});
		|d| d["exits"][0]["backend"]["unsupported"] = json!({});
		|d| d["exits"][1]["backend"]["unsupported"] = json!({"icmp_echo": "local", "other": "reject"});
	};
}

#[test]
fn rule_conditions() {
	cases! {error_at:
		"routing.rules[2]": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "action": "block"});
		"routing.rules[2].protocol": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": [], "action": "block"});
		"routing.rules[2].ip": |d| d["routing"]["rules"][2]["ip"] = json!([]);
		"routing.rules[2].user": |d| d["routing"]["rules"][2]["user"] = json!([]);
		"routing.rules[2].port[1]": |d| d["routing"]["rules"][2]["port"] = json!([25, "25-25"]);
		"routing.rules[2].protocol[1]": |d| d["routing"]["rules"][2]["protocol"] = json!(["tcp", 6]);
		"routing.rules[2].ip[1]": |d| d["routing"]["rules"][2]["ip"] = json!(["9.9.9.0/24", "9.9.9.0/24"]);
		"routing.rules[3].domain[1]": |d| d["routing"]["rules"][3]["domain"] = json!(["example.com", "example.com"]);
		"routing.rules[3].group[1]": |d| d["routing"]["rules"][3]["group"] = json!(["staff", "staff"]);
		"routing.rules[2].inbound[1]": |d| d["routing"]["rules"][2]["inbound"] = json!(["home", "home"]);
		"routing.rules[2].port": |d| remove(d, "/routing/rules/2", "protocol");
		"routing.rules[2].port": |d| d["routing"]["rules"][2]["protocol"] = json!(["tcp", "icmp"]);
		"routing.rules[2].port": |d| d["routing"]["rules"][2]["protocol"] = json!([47]);
		"routing.rules[2].icmp_type": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "icmp_type": [8], "action": "block"});
		"routing.rules[2].icmp_type": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["tcp"], "icmp_type": [8], "action": "block"});
		"routing.rules[2].icmp_type": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["icmp", "icmpv6"], "icmp_type": [8], "action": "block"});
		"routing.rules[2].icmp_code": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["icmp"], "icmp_code": [0], "action": "block"});
		"routing.rules[2].icmp_type[1]": |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["icmp"], "icmp_type": [3, 3], "action": "block"});
	};
	for bad in [json!(0), json!(65536), json!("80"), json!("80-70"), json!("0-5"), json!("a-b"), json!("80-"), json!("+80-90"), json!("080-90"), json!("80 - 90"), json!("80-90-100"), json!(-1), json!(80.0), json!([80])] {
		refused("routing.rules[2].port[0]", |d| d["routing"]["rules"][2]["port"] = json!([bad]));
	}
	for bad in [json!(256), json!(-1), json!("TCP"), json!("6"), json!(6.0), json!(true)] {
		refused("routing.rules[2].protocol[0]", |d| d["routing"]["rules"][2]["protocol"] = json!([bad]));
	}
	refused("routing.rules[2].icmp_type[0]", |d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["icmp"], "icmp_type": [256], "action": "block"}));
	for bad in ["Example.com", "example.com.", ".example.com", "*.com", "*", "a.*.example.com", "*a.example.com", "**.example.com", "1.2.3.4", "example.123", "2001:db8::1", "0x7f000001", "example.0x7f", "example.0xff", "example.0x", "*.a.0x1f", "exa_mple.com", "-a.example.com", "a-.example.com", "a..example.com", "", "ex\u{e4}mple.com", &format!("{}.com", "a".repeat(64)), &format!("{}.com", ["a".repeat(63).as_str(); 4].join("."))] {
		error_at("routing.rules[3].domain[0]", |d| d["routing"]["rules"][3]["domain"] = json!([bad]));
	}
	for fine in ["example.com", "*.example.com", "*.a.example.com", "localhost", "xn--mgbh0fb.example", "a-b.1x.example.com", "0x7f.example.com", "example.0xg", "example.x0", "example.00x1", &format!("{}.com", "a".repeat(63)), &format!("{}.com", ["a".repeat(61).as_str(); 4].join("."))] {
		clean(|d| d["routing"]["rules"][3]["domain"] = json!([fine]));
	}
	for bad in [json!({"exit": "main", "also": "node"}), json!({}), json!({"exit": 5}), json!(["block"]), json!(1), json!({"via": "main"})] {
		refused(if bad == json!({"exit": 5}) {"routing.rules[2].action.exit"} else {"routing.rules[2].action"}, |d| d["routing"]["rules"][2]["action"] = bad.clone());
	}
	all_clean! {
		|d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["tcp", "udp", "sctp"], "port": [5353, "1000-2000", "65535-65535"], "action": "block"});
		|d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["icmp"], "icmp_type": [3, 11], "icmp_code": [0, 1], "action": "reject"});
		|d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": ["icmpv6"], "icmp_type": [128], "action": "block"});
		|d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "protocol": [47, "esp", 0, 255], "action": "block"});
		|d| d["routing"]["rules"][2] = json!({"tag": "no-smtp", "inbound": ["office"], "user": ["alice"], "ip": ["9.9.9.0/24"], "action": "user"});
	};
}

#[test]
fn entitlement() {
	cases! {error_at:
		"routing.rules[4].user[1]": |d| rule(d, json!({"tag": "to-open", "user": ["alice", "bob"], "action": {"exit": "open"}}));
		"users[1].exits": |d| d["users"][1]["exits"] = json!(["node"]);
		"users[1].exit": |d| d["users"][1]["exit"] = json!("open");
		"routing.rules[4].action": |d| rule(d, json!({"tag": "gre-out", "protocol": ["gre"], "action": {"exit": "main"}}));
		"routing.rules[4].action": |d| rule(d, json!({"tag": "odd-out", "protocol": ["icmp", 47], "action": {"exit": "main"}}));
		"routing.rules[4].action": |d| rule(d, json!({"tag": "unreachable-out", "protocol": ["icmp"], "icmp_type": [3], "action": {"exit": "main"}}));
		"routing.rules[4].action": |d| {
			d["exits"][0]["backend"]["unsupported"] = json!({"icmp_echo": "drop"});
			rule(d, json!({"tag": "ping-out", "protocol": ["icmpv6"], "action": {"exit": "main"}}));
		};
	};
	cases! {warning_at:
		"users[1].exits": |d| d["users"][1]["exits"] = json!([]);
		"routing.rules[4].action": |d| rule(d, json!({"tag": "all-open", "ip": ["93.184.216.0/24"], "action": {"exit": "open"}}));
		"routing.rules[4].action": |d| rule(d, json!({"tag": "home-open", "inbound": ["home"], "action": {"exit": "open"}}));
		"routing.rules[4].action": |d| rule(d, json!({"tag": "guest-open", "group": ["guest"], "action": {"exit": "open"}}));
		"routing.rules[4].action": |d| {
			d["exits"][0]["backend"]["proxy_only"] = json!(false);
			d["exits"][0]["backend"]["unsupported"] = json!({"udp": {"via": "open"}});
			rule(d, json!({"tag": "guest-main", "group": ["guest"], "action": {"exit": "main"}}));
		};
	};
	let report = check(&with(|d| rule(d, json!({"tag": "all-open", "ip": ["93.184.216.0/24"], "action": {"exit": "open"}}))));
	assert!(report.warnings[0].message.starts_with("1 users"), "{report:#?}");
	error_at("users[1].exit", |d| {
		d["users"][1]["exits"] = json!([]);
		d["users"][1]["exit"] = json!("main");
	});
	let none = check(&with(|d| d["users"][1]["exits"] = json!([])));
	assert!(none.errors.is_empty() && none.warnings.len() == 1, "{none:#?}");
	all_clean! {
		|d| rule(d, json!({"tag": "to-open", "user": ["alice"], "action": {"exit": "open"}}));
		|d| rule(d, json!({"tag": "to-node", "user": ["alice", "bob"], "action": {"exit": "node"}}));
		|d| rule(d, json!({"tag": "staff-open", "group": ["staff"], "action": {"exit": "open"}}));
		|d| rule(d, json!({"tag": "office-open", "inbound": ["office"], "action": {"exit": "open"}}));
		|d| rule(d, json!({"tag": "guest-office-open", "group": ["guest"], "inbound": ["office"], "action": {"exit": "open"}}));
		|d| rule(d, json!({"tag": "all-main", "ip": ["93.184.216.0/24"], "action": {"exit": "main"}}));
		|d| rule(d, json!({"tag": "all-own", "ip": ["93.184.216.0/24"], "action": "user"}));
		|d| d["users"][1]["exit"] = json!("node");
		|d| {
			d["users"][1]["exits"] = json!(["node"]);
			d["users"][1]["exit"] = json!("node");
		};
		|d| rule(d, json!({"tag": "gre-out", "protocol": ["gre"], "action": {"exit": "node"}}));
		|d| rule(d, json!({"tag": "mixed-out", "protocol": ["tcp", "gre"], "action": {"exit": "main"}}));
		|d| rule(d, json!({"tag": "ping-out", "protocol": ["icmp"], "action": {"exit": "main"}}));
		|d| rule(d, json!({"tag": "echo-out", "protocol": ["icmpv6"], "icmp_type": [128], "action": {"exit": "main"}}));
		|d| rule(d, json!({"tag": "udp-out", "protocol": ["udp"], "action": {"exit": "main"}}));
		|d| rule(d, json!({"tag": "gre-own", "protocol": ["gre"], "action": "user"}));
	};
}

#[test]
fn disabled_rules() {
	refused("routing.rules[2].enabled", |d| d["routing"]["rules"][2]["enabled"] = json!("no"));
	// A disabled rule is validated like any other.
	cases! {error_at:
		"routing.rules[4]": |d| rule(d, json!({"tag": "bare", "enabled": false, "action": "user"}));
		"routing.rules[4].action.exit": |d| rule(d, json!({"tag": "nowhere", "enabled": false, "ip": ["9.9.9.0/24"], "action": {"exit": "missing"}}));
		"routing.rules[4].port": |d| rule(d, json!({"tag": "no-protocol", "enabled": false, "port": [80], "action": "block"}));
		"routing.rules[4].tag": |d| rule(d, json!({"tag": "no-smtp", "enabled": false, "ip": ["9.9.9.0/24"], "action": "block"}));
		"routing.rules[4].user[1]": |d| rule(d, json!({"tag": "to-open", "enabled": false, "user": ["alice", "bob"], "action": {"exit": "open"}}));
	};
	// It is left out of everything that reasons about what the rules do: entitlement counts, protocols a netstack exit cannot carry, a refusal after a domain rule, shadowing.
	all_clean! {
		|d| d["routing"]["rules"][2]["enabled"] = json!(true);
		|d| d["routing"]["rules"][2]["enabled"] = json!(false);
		|d| rule(d, json!({"tag": "all-open", "enabled": false, "ip": ["93.184.216.0/24"], "action": {"exit": "open"}}));
		|d| rule(d, json!({"tag": "gre-out", "enabled": false, "protocol": ["gre"], "action": {"exit": "main"}}));
		|d| rule(d, json!({"tag": "late-block", "enabled": false, "ip": ["93.184.216.0/24"], "action": "block"}));
		|d| rule(d, json!({"tag": "smtp-again", "enabled": false, "protocol": ["tcp"], "port": [25], "action": "block"}));
		|d| {
			d["routing"]["rules"][2]["enabled"] = json!(false);
			rule(d, json!({"tag": "smtp-again", "protocol": ["tcp"], "port": [25], "action": "user"}));
		};
		|d| {
			d["routing"]["rules"][3]["enabled"] = json!(false);
			rule(d, json!({"tag": "late-block", "ip": ["93.184.216.0/24"], "action": "block"}));
		};
	};
	let config = parse(&with(|d| d["routing"]["rules"][2]["enabled"] = json!(false))).unwrap();
	assert_eq!((config.routing.rules[1].enabled, config.routing.rules[2].enabled), (None, Some(false)));
	assert_eq!(Config::parse(serde_json::to_string(&config).unwrap().as_bytes()).unwrap(), config);
}

#[test]
fn private_networks_and_geoip() {
	for bad in ["geoip:ir", "geoip:", "geoip:Private", "geoip:private ", "GEOIP:private", "geosite:private", "private", "geoip:private/8", "tunnel:", "tunnel:Users", "tunnel:users/24", "tunnel:ho.me", "tunnel:-home", "tunnel:home ", "users", "2001:db8::1/32", "fe80::%eth0/64", "::ffff:10.0.0.0/104"] {
		let message = refused("routing.rules[1].ip[0]", |d| d["routing"]["rules"][1]["ip"] = json!([bad]));
		assert!(!bad.contains(':') || message.contains("geoip:private") && message.contains("tunnel:users") && message.contains("this version"), "{bad}: {message}");
	}
	error_at("routing.rules[1].ip[1]", |d| d["routing"]["rules"][1]["ip"] = json!(["geoip:private", "geoip:private"]));
	// Nothing refuses private destinations for everyone: no such rule, one that is disabled, one with another condition, one that sends them on.
	cases! {warning_at:
		"routing.rules": |d| d["routing"]["rules"][1]["ip"] = json!(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
		"routing.rules": |d| d["routing"]["rules"][1]["enabled"] = json!(false);
		"routing.rules": |d| d["routing"]["rules"][1]["group"] = json!(["guest"]);
		"routing.rules": |d| d["routing"]["rules"][1]["inbound"] = json!(["home"]);
		"routing.rules": |d| d["routing"]["rules"][1]["protocol"] = json!(["tcp"]);
		"routing.rules": |d| d["routing"]["rules"][1]["action"] = json!("user");
		"routing.rules": |d| d["routing"]["rules"] = json!([]);
	};
	all_clean! {
		|d| d["routing"]["rules"][1]["action"] = json!("block");
		|d| d["routing"]["rules"][1]["enabled"] = json!(true);
		|d| d["routing"]["rules"][1]["ip"] = json!(["9.9.9.0/24", "geoip:private"]);
		|d| d["routing"]["rules"].as_array_mut().unwrap().swap(1, 2);
		|d| d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "staff-lan", "group": ["staff"], "ip": ["192.168.50.0/24"], "action": {"exit": "node"}}));
	};
	// A network inside the set is covered by the name, and the name only by itself.
	cases! {warning_at:
		"routing.rules[4]": |d| rule(d, json!({"tag": "lan", "group": ["staff"], "ip": ["192.168.50.0/24", "fd00::/16", "240.0.0.0/4"], "action": {"exit": "node"}}));
		"routing.rules[4]": |d| rule(d, json!({"tag": "again", "ip": ["geoip:private"], "action": "block"}));
	};
	all_clean! {
		|d| rule(d, json!({"tag": "mixed", "ip": ["192.168.50.0/24", "9.9.9.0/24"], "action": "user"}));
		|d| rule(d, json!({"tag": "wide", "ip": ["192.0.0.0/8"], "action": "user"}));
		|d| d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "all-v4", "ip": ["0.0.0.0/0"], "action": "user"}));
	};
}

#[test]
fn traffic_between_users() {
	let isolation = |doc: &Value| check(doc).warnings.into_iter().filter(|w| w.path == "routing.rules" && w.message.contains("tunnel:users")).map(|w| w.message).collect::<Vec<_>>();
	let open = |edit: &dyn Fn(&mut Value)| {
		let found = isolation(&with(|d| edit(d)));
		assert!(found.len() == 1 && found[0].contains("no other condition") && !found[0].contains("inbounds["), "{found:?}");
	};
	error_at("routing.rules[0].ip[1]", |d| d["routing"]["rules"][0]["ip"] = json!(["tunnel:users", "tunnel:users"]));
	open(&|d| d["routing"]["rules"][0]["enabled"] = json!(false));
	open(&|d| d["routing"]["rules"][0]["action"] = json!("user"));
	open(&|d| d["routing"]["rules"][0]["ip"] = json!(["10.7.0.0/24", "10.8.0.0/24", "fd7a:115c:a1e0::/64"]));
	open(&|d| d["routing"]["rules"][0]["group"] = json!(["guest"]));
	open(&|d| d["routing"]["rules"][0]["protocol"] = json!(["tcp"]));
	open(&|d| {
		d["routing"]["rules"][0]["inbound"] = json!(["home"]);
		d["routing"]["rules"][0]["user"] = json!(["bob"]);
	});
	open(&|d| d["routing"]["rules"].as_array_mut().unwrap().truncate(0));
	// A rule limited to some inbounds leaves the others open, and the warning points at them.
	let one = isolation(&with(|d| d["routing"]["rules"][0]["inbound"] = json!(["home"])));
	assert!(one.len() == 1 && one[0].contains("inbounds[1]") && !one[0].contains("inbounds[0]"), "{one:?}");
	let other = isolation(&with(|d| {
		d["routing"]["rules"][0]["inbound"] = json!(["office"]);
		rule(d, json!({"tag": "isolate-home", "enabled": false, "inbound": ["home"], "ip": ["tunnel:users"], "action": "block"}));
	}));
	assert!(other.len() == 1 && other[0].contains("inbounds[0]") && !other[0].contains("inbounds[1]"), "{other:?}");
	all_clean! {
		|d| d["routing"]["rules"][0]["action"] = json!("block");
		|d| d["routing"]["rules"][0]["ip"] = json!(["tunnel:users", "9.9.9.0/24"]);
		|d| d["routing"]["rules"][0]["inbound"] = json!(["home", "office"]);
		|d| {
			d["routing"]["rules"][0]["inbound"] = json!(["home"]);
			d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "isolate-office", "inbound": ["office"], "ip": ["tunnel:users"], "action": "block"}));
		};
		|d| d["routing"]["rules"].as_array_mut().unwrap().insert(0, json!({"tag": "staff-lan-party", "group": ["staff"], "inbound": ["office"], "ip": ["tunnel:users"], "action": "user"}));
	};
	// The name covers a network inside a pool that leaves out the gateway, and geoip:private covers nothing inside a pool.
	cases! {warning_at:
		"routing.rules[4]": |d| rule(d, json!({"tag": "one-device", "ip": ["10.7.0.128/25", "fd7a:115c:a1e0::2/128"], "action": "user"}));
		"routing.rules[4]": |d| rule(d, json!({"tag": "lan", "ip": ["192.168.0.0/16"], "action": "user"}));
	};
	all_clean! {
		|d| rule(d, json!({"tag": "with-gateway", "ip": ["10.7.0.0/25"], "action": "user"}));
		|d| rule(d, json!({"tag": "whole-pool", "ip": ["10.8.0.0/24"], "action": "user"}));
		|d| rule(d, json!({"tag": "around-pool", "ip": ["10.0.0.0/8"], "action": "user"}));
		|d| {
			d["routing"]["rules"][0]["enabled"] = json!(false);
			d["routing"]["rules"][0]["inbound"] = json!(["home", "office"]);
			d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "isolate", "ip": ["tunnel:users"], "action": "reject"}));
		};
	};
}

#[test]
fn one_tunnel_by_its_inbound_tag() {
	let first = |d: &mut Value, rule: Value| d["routing"]["rules"].as_array_mut().unwrap().insert(0, rule);
	let lan = json!({"tag": "office-lan", "inbound": ["office"], "ip": ["tunnel:office"], "action": "user"});
	// The shared network of the reference: one rule before the isolating one, and users are still isolated everywhere else.
	all_clean! {
		|d| first(d, lan.clone());
		|d| first(d, json!({"tag": "to-any", "group": ["staff"], "ip": ["tunnel:home", "tunnel:office", "10.9.0.0/24"], "action": "user"}));
		|d| first(d, json!({"tag": "no-office", "ip": ["tunnel:office"], "action": "block"}));
		|d| d["exits"][3]["tag"] = json!("users");
	};
	let config = parse(&with(|d| first(d, lan.clone()))).unwrap();
	assert_eq!(serde_json::to_value(&config).unwrap()["routing"]["rules"][0], lan);
	cases! {error_at:
		"routing.rules[0].ip[0]": |d| first(d, json!({"tag": "lan", "ip": ["tunnel:missing"], "action": "user"}));
		"routing.rules[0].ip[1]": |d| first(d, json!({"tag": "lan", "ip": ["tunnel:home", "tunnel:gateways"], "action": "user"}));
		"routing.rules[0].ip[0]": |d| first(d, json!({"tag": "lan", "enabled": false, "ip": ["tunnel:main"], "action": "user"}));
		"routing.rules[0].ip[1]": |d| first(d, json!({"tag": "lan", "ip": ["tunnel:office", "tunnel:office"], "action": "user"}));
		"inbounds[1].tag": |d| d["inbounds"][1]["tag"] = json!("users");
	};
	// Refusing every tunnel by its tag is not the rule the isolation warning asks for.
	let report = check(&with(|d| d["routing"]["rules"][0]["ip"] = json!(["tunnel:home", "tunnel:office"])));
	assert!(report.errors.is_empty() && report.warnings.len() == 1 && report.warnings[0].path == "routing.rules" && report.warnings[0].message.contains("tunnel:users"), "{report:#?}");
	// A tag covers what lies in the pools of its own inbound, gateways left out, and tunnel:users covers every tag.
	let report = check(&with(|d| {
		first(d, json!({"tag": "office-devices", "ip": ["tunnel:office"], "action": "user"}));
		rule(d, json!({"tag": "office-half", "ip": ["10.8.0.128/25"], "action": "user"}));
		rule(d, json!({"tag": "home-half", "ip": ["10.7.0.128/25"], "action": "user"}));
		rule(d, json!({"tag": "home-devices", "group": ["staff"], "ip": ["tunnel:home"], "action": "user"}));
		rule(d, json!({"tag": "office-gateway", "ip": ["10.8.0.0/25"], "action": "user"}));
	}));
	assert_eq!(report.warnings.iter().map(|w| (w.path.as_str(), w.message.contains("routing.rules[0] "), w.message.contains("routing.rules[1] "))).collect::<Vec<_>>(), [("routing.rules[5]", true, false), ("routing.rules[6]", false, true), ("routing.rules[7]", false, true)], "{report:#?}");
}

#[test]
fn a_rule_that_refuses_the_resolver() {
	let lan = |d: &mut Value| d["dns"]["servers"] = json!(["192.168.1.1:53"]);
	let second = |d: &mut Value, rule: Value| d["routing"]["rules"].as_array_mut().unwrap().insert(2, rule);
	cases! {warning_at:
		"routing.rules[1]": |d| lan(d);
		"routing.rules[1]": |d| d["dns"]["servers"] = json!(["1.1.1.1:53", "[fd00::53]:5353"]);
		"routing.rules[2]": |d| second(d, json!({"tag": "no-dns", "protocol": ["udp"], "port": [53], "action": "block"}));
		"routing.rules[2]": |d| second(d, json!({"tag": "no-low", "protocol": ["tcp", "sctp"], "port": ["1-1023"], "ip": ["1.0.0.0/8"], "action": "reject"}));
		"routing.rules[2]": |d| second(d, json!({"tag": "no-resolver", "ip": ["1.1.1.1/32"], "action": "reject"}));
		"routing.rules[2]": |d| {
			lan(d);
			d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "off", "enabled": false, "ip": ["192.168.1.1/32"], "action": "user"}));
		};
	};
	let report = check(&with(|d| d["dns"]["servers"] = json!(["192.168.1.1:53", "1.1.1.1:53", "10.0.0.53:53"])));
	assert_eq!(report.warnings.iter().map(|w| (w.path.as_str(), w.message.contains("dns.servers[0]"), w.message.contains("dns.servers[2]"))).collect::<Vec<_>>(), [("routing.rules[1]", true, false), ("routing.rules[1]", false, true)]);
	all_clean! {
		|d| {
			lan(d);
			d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "resolver", "ip": ["192.168.1.1/32"], "protocol": ["udp", "tcp"], "port": [53], "action": "user"}));
		};
		|d| {
			lan(d);
			d["routing"]["rules"].as_array_mut().unwrap().insert(1, json!({"tag": "staff-lan", "group": ["staff"], "ip": ["192.168.1.0/24"], "action": {"exit": "node"}}));
		};
		|d| second(d, json!({"tag": "no-dns", "enabled": false, "protocol": ["udp"], "port": [53], "action": "block"}));
		|d| second(d, json!({"tag": "no-dot", "protocol": ["tcp"], "port": [853], "action": "block"}));
		|d| second(d, json!({"tag": "no-gre", "protocol": ["gre"], "ip": ["1.1.1.1/32"], "action": "block"}));
		|d| second(d, json!({"tag": "guest-no-dns", "group": ["guest"], "protocol": ["udp"], "port": [53], "action": "block"}));
		|d| second(d, json!({"tag": "no-other-resolver", "ip": ["8.8.8.8/32"], "action": "block"}));
		|d| {
			second(d, json!({"tag": "no-dns", "protocol": ["udp"], "port": [53], "action": "block"}));
			second(d, json!({"tag": "resolver", "ip": ["1.1.1.1/32"], "action": "user"}));
		};
	};
}

#[test]
fn domain_rules_and_shadowed_rules() {
	warning_at("routing.rules[3].domain", |d| rule(d, json!({"tag": "late-block", "ip": ["93.184.216.0/24"], "action": "block"})));
	warning_at("routing.rules[3].domain", |d| rule(d, json!({"tag": "late-reject", "ip": ["93.184.216.0/24"], "action": "reject"})));
	all_clean! {
		|d| rule(d, json!({"tag": "late-own", "ip": ["93.184.216.0/24"], "action": "user"}));
		|d| {
			d["routing"]["rules"][3]["action"] = json!("block");
			rule(d, json!({"tag": "late-block", "ip": ["93.184.216.0/24"], "action": "block"}));
		};
	};
	cases! {warning_at:
		"routing.rules[4]": |d| rule(d, json!({"tag": "smtp-again", "protocol": ["tcp"], "port": [25], "action": "block"}));
		"routing.rules[5]": |d| {
			rule(d, json!({"tag": "low-ports", "protocol": ["tcp", "udp"], "port": ["1-1023"], "action": "block"}));
			rule(d, json!({"tag": "web", "protocol": ["udp"], "port": [443, "80-81"], "inbound": ["home"], "action": "user"}));
		};
		"routing.rules[5]": |d| {
			rule(d, json!({"tag": "test-nets", "ip": ["93.184.216.0/24", "2606:4700::/32"], "action": "block"}));
			rule(d, json!({"tag": "one-host", "ip": ["93.184.216.7/32", "2606:4700:1::/48"], "action": "user"}));
		};
		"routing.rules[4]": |d| rule(d, json!({"tag": "deeper", "group": ["staff"], "domain": ["a.corp.example.com", "*.b.corp.example.com", "*.corp.example.com"], "action": {"exit": "node"}}));
	};
	all_clean! {
		|d| rule(d, json!({"tag": "smtps", "protocol": ["tcp"], "port": [465], "action": "user"}));
		|d| rule(d, json!({"tag": "smtp-wide", "protocol": ["tcp"], "port": ["25-26"], "action": "user"}));
		|d| rule(d, json!({"tag": "smtp-any", "port": [25], "protocol": ["tcp", "udp"], "action": "user"}));
		|d| d["routing"]["rules"][3]["domain"] = json!(["*.corp.example.com", "corp.example.com", "xcorp.example.com"]);
		|d| {
			d["routing"]["rules"][2] = json!({"tag": "guest-names", "group": ["guest"], "domain": ["*.example.com"], "action": "user"});
			d["routing"]["rules"][3]["domain"] = json!(["a.example.com"]);
		};
	};
	let covered = with(|d| rule(d, json!({"tag": "smtp-again", "protocol": ["tcp"], "port": [25], "action": "user"})));
	assert!(parse(&covered).unwrap().validate(false).warnings.is_empty() && check(&covered).warnings.len() == 1);
	// The shadow check only runs on a document with no errors.
	let broken = check(&with(|d| {
		rule(d, json!({"tag": "smtp-again", "protocol": ["tcp"], "port": [25], "action": "user"}));
		d["users"][0]["quota_period"] = json!("daily");
	}));
	assert!(broken.errors.len() == 1 && broken.warnings.is_empty() && !broken.shadow_cut_short, "{broken:#?}");
	let first = good()["routing"]["rules"].clone();
	let many = with(|d| d["routing"]["rules"] = (0..MAX_RULES).map(|i| if i < 2 {first[i].clone()} else {json!({"tag": format!("r{i}"), "protocol": ["tcp"], "port": (0..8).map(|p| 1 + i * 8 + p).collect::<Vec<_>>(), "action": "user"})}).collect());
	let report = check(&many);
	assert!(report.shadow_cut_short && report.errors.is_empty() && report.warnings.is_empty(), "{:?} {:?}", report.errors, report.warnings);
	assert!(!check(&good()).shadow_cut_short);
}

#[test]
fn users_and_devices() {
	cases! {error_at:
		"users[1].groups[1]": |d| d["users"][1]["groups"] = json!(["guest", "guest"]);
		"users[1].exits[1]": |d| d["users"][1]["exits"] = json!(["main", "main"]);
		"users[0].quota_bytes": |d| d["users"][0]["quota_bytes"] = json!(0);
		"users[0].quota_bytes": |d| d["users"][0]["quota_bytes"] = json!(9007199254740992_u64);
		"users[0].quota_period": |d| d["users"][0]["quota_period"] = json!("daily");
		"users[0].devices[1].name": |d| push(d, "/users/0/devices", json!({"name": "laptop", "public_key": key(0x23), "addresses": ["10.7.0.9"]}));
		"users[0].devices[0].addresses[0]": |d| d["users"][0]["devices"][0]["addresses"][0] = json!("10.9.0.2");
		"users[0].devices[0].addresses[0]": |d| d["users"][0]["devices"][0]["addresses"][0] = json!("192.0.2.2");
		"users[0].devices[0].addresses[1]": |d| d["users"][0]["devices"][0]["addresses"][1] = json!("fd7a:115c:a1e1::2");
		"users[0].devices[0].addresses[0]": |d| d["users"][0]["devices"][0]["addresses"][0] = json!("10.7.0.1");
		"users[0].devices[0].addresses[0]": |d| d["users"][0]["devices"][0]["addresses"][0] = json!("10.7.0.0");
		"users[0].devices[0].addresses[0]": |d| d["users"][0]["devices"][0]["addresses"][0] = json!("10.7.0.255");
		"users[0].devices[0].addresses[1]": |d| d["users"][0]["devices"][0]["addresses"][1] = json!("fd7a:115c:a1e0::1");
		"users[0].devices[0].addresses[1]": |d| d["users"][0]["devices"][0]["addresses"][1] = json!("fd7a:115c:a1e0::");
		"users[0].devices[0].addresses[3]": |d| push(d, "/users/0/devices/0/addresses", json!("10.7.0.9"));
		"users[0].devices[0].addresses[3]": |d| push(d, "/users/0/devices/0/addresses", json!("fd7a:115c:a1e0::9"));
		"users[0].devices[0].addresses[3]": |d| push(d, "/users/0/devices/0/addresses", json!("10.7.0.2"));
		"users[1].devices[0].addresses[0]": |d| d["users"][1]["devices"][0]["addresses"][0] = json!("10.7.0.2");
	};
	for bad in ["2030-01-01T00:00:00", "2030-01-01", "2030-13-01T00:00:00Z", "2030-02-30T00:00:00Z", "tomorrow", "1893456000", "2030-01-01t00:00:00Z", "2030-01-01 00:00:00Z", "2030-01-01_00:00:00Z", "2030-01-0100:00:00Z"] {
		refused("users[0].expires_at", |d| d["users"][0]["expires_at"] = json!(bad));
	}
	refused("users[0].expires_at", |d| d["users"][0]["expires_at"] = json!(1893456000));
	refused("users[0].quota_bytes", |d| d["users"][0]["quota_bytes"] = json!(1.5));
	refused("users[0].enabled", |d| d["users"][0]["enabled"] = json!(1));
	all_clean! {
		|d| d["users"][0]["expires_at"] = json!("2030-01-01T00:00:00Z");
		|d| d["users"][0]["expires_at"] = json!("2030-01-01T03:30:00.25+03:30");
		|d| d["users"][0]["quota_bytes"] = json!(1);
		|d| {
			d["users"][0]["quota_bytes"] = json!(9007199254740991_u64);
			d["users"][0]["quota_period"] = json!("weekly");
		};
		|d| d["users"][0]["enabled"] = json!(false);
		|d| d["users"][0]["devices"][0]["addresses"][1] = json!("fd7a:115c:a1e0:0:ffff:ffff:ffff:ffff");
		|d| d["users"][0]["devices"][0]["addresses"] = json!(["10.7.0.254"]);
		|d| push(d, "/users/1/devices", json!({"name": "laptop", "public_key": key(0x23), "addresses": ["10.8.0.9", "fd7a:115c:a1e0::9"]}));
	};
}

#[test]
fn secrets_never_reach_a_diagnostic_or_debug_output() {
	let marker = "c2VjcmV0LW1hcmtlci1kby1ub3QtcHJpbnQtdGhpcyE";
	let secret = format!("{marker}=");
	let leaks = |what: &str, text: String| assert!(!text.contains(marker), "{what} shows a secret: {text}");
	let edits: Vec<Box<dyn Fn(&mut Value)>> = vec![
		Box::new(|d| d["inbounds"][0]["mtu"] = json!(secret)),
		Box::new(|d| d["inbounds"][0]["private_key"] = json!([secret])),
		Box::new(|d| d["inbounds"][0]["private_key"] = json!(format!("{secret}{secret}"))),
		Box::new(|d| d["inbounds"][0]["privatekey"] = json!(secret)),
		Box::new(|d| d["outbounds"][0]["pass"] = json!(secret)),
		Box::new(|d| d["outbounds"][0]["password"] = json!({"value": secret})),
		Box::new(|d| d["outbounds"][0]["type"] = json!(secret)),
		Box::new(|d| d["outbounds"][0]["server"] = json!(secret)),
		Box::new(|d| d["users"][0]["devices"][0]["preshared_key"] = json!(format!("x{secret}"))),
		Box::new(|d| d["users"][0]["devices"][0]["addresses"][0] = json!(secret)),
		Box::new(|d| d["users"][0]["expires_at"] = json!(secret)),
		Box::new(|d| d["users"][0]["exits"] = json!(secret)),
		Box::new(|d| d["routing"]["rules"][2]["action"] = json!(secret)),
		Box::new(|d| d["routing"]["rules"][2]["protocol"] = json!([secret])),
		Box::new(|d| d["routing"]["rules"][2]["port"] = json!([secret])),
		Box::new(|d| d["routing"]["rules"][1]["ip"] = json!([secret])),
		Box::new(|d| d["routing"]["rules"][1]["ip"] = json!([format!("geoip:{secret}")])),
		Box::new(|d| d["log"] = json!({"level": secret})),
		Box::new(|d| d["version"] = json!(secret)),
	];
	for (i, edit) in edits.iter().enumerate() {
		let e = parse(&with(edit)).expect_err("a misplaced secret must not parse");
		leaks(&format!("parse error {i}"), format!("{e} {e:?}"));
	}
	// Values that parse but break a rule: the report names their place and never repeats them.
	let report = check(&with(|d| {
		for pointer in ["/inbounds/0/tag", "/outbounds/1/tag", "/exits/3/tag", "/groups/0", "/users/0/name", "/users/0/devices/0/name", "/routing/default", "/exits/0/backend/outbound", "/inbounds/0/transports/1/path", "/outbounds/0/username"] {
			*d.pointer_mut(pointer).unwrap() = json!(secret.repeat(if pointer.ends_with("username") {8} else {1}));
		}
		d["exits"][2]["backend"]["interface"] = json!(secret);
		d["exits"][0]["name"] = json!(secret.repeat(2));
		d["exits"][0]["country"] = json!(secret);
		d["routing"]["rules"][3]["domain"] = json!([secret]);
		d["routing"]["rules"][2]["user"] = json!([secret]);
		d["users"][1]["exits"] = json!([secret]);
	}));
	assert!(report.errors.len() > 12, "{report:#?}");
	leaks("the report", format!("{report:?} {}", report.errors.iter().map(|e| e.to_string()).collect::<String>()));
	let config = parse(&good()).unwrap();
	let debug = format!("{config:?} {config:#?}");
	for value in [key(0x11), key(0x12), key(0x31), "example-user".to_string(), "example-password".to_string()] {
		assert!(!debug.contains(&value), "Debug output shows a secret");
	}
	assert!(debug.contains("<secret>") && debug.contains(&key(0x21)));
	assert_eq!(format!("{}", config.inbounds[0].private_key), "<secret>");
}

#[test]
fn load_reads_a_file() {
	let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
	let (path, broken) = (dir.join("config_v1_load.json"), dir.join("config_v1_broken.json"));
	std::fs::write(&path, good().to_string()).unwrap();
	std::fs::write(&broken, with(|d| d["version"] = json!(2)).to_string()).unwrap();
	#[cfg(unix)]
	for (mode, warned) in [(0o600, false), (0o400, false), (0o640, true), (0o604, true), (0o644, true), (0o600, false)] {
		std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode)).unwrap();
		let (config, report) = load(&path, true);
		assert!(config.is_some() && report.errors.is_empty());
		assert_eq!(report.warnings.iter().any(|w| w.path.is_empty() && w.message.contains("group or others")), warned, "mode {mode:o}");
	}
	let (config, report) = load(&path, true);
	assert_eq!(config, Some(parse(&good()).unwrap()));
	assert!(report.errors.is_empty());
	let (config, report) = load(&broken, true);
	assert!(config.is_none() && report.errors.iter().any(|e| e.path == "version"));
	let (config, report) = load(&dir.join("config_v1_missing.json"), true);
	assert!(config.is_none() && report.errors.len() == 1 && report.errors[0].message.contains("cannot read"));
}

/// The object and the list in it are one value each, so `MAX_JSON_NODES` - 1 zeros are one too many.
#[test]
fn a_document_of_too_many_values_is_refused_before_it_is_held_in_memory() {
	let zeros = |n: usize| format!("[{}0]", "0,".repeat(n - 1));
	// The object around the list is one more value, and so is the list.
	let over = Config::parse(format!("{{\"version\":{}}}", zeros(MAX_JSON_NODES - 1)).as_bytes()).unwrap_err();
	assert!(over.path.is_empty() && over.message.contains(&format!("more than {MAX_JSON_NODES} values")), "{}", over.message);
	assert!(!Config::parse(format!("{{\"version\":{}}}", zeros(MAX_JSON_NODES - 2)).as_bytes()).unwrap_err().message.contains("values"));
	// Values inside objects count the same. That many keys of one object would not fit the file size limit, so each key holds a list.
	let lists: String = (0..1000).map(|i| format!("\"{i}\":{},", zeros(MAX_JSON_NODES / 1000))).collect();
	assert!(Config::parse(format!("{{{lists}\"z\":0}}").as_bytes()).unwrap_err().message.contains("values"));
}

/// A document at the user and rule limits, with several entries in every rule and users spread over many classes.
#[test]
fn the_user_and_rule_limits_validate_quickly() {
	let users: Vec<Value> = (0..MAX_USERS).map(|i| {
		let mut public = [0x55u8; 32];
		public[..4].copy_from_slice(&(i as u32).to_be_bytes());
		json!({"name": format!("user{i}"), "groups": [format!("g{}", i % 16)], "exits": if i % 3 == 0 {json!("all")} else {json!(["main", "node"])}, "quota_bytes": 1 << 30, "quota_period": "monthly",
			"devices": [{"name": "phone", "public_key": veilway_wg::encode_key(&public), "addresses": [format!("fd7a:115c:a1e0::{:x}:{:x}", 1 + i / 65536, i % 65536)]}]})
	}).collect();
	let rules: Vec<Value> = (0..MAX_RULES).map(|i| json!({"tag": format!("rule{i}"), "group": [format!("g{}", i % 16)], "ip": [format!("198.51.{}.{}/32", i / 256, i % 256), format!("2001:db8:{i:x}::/48")], "protocol": ["tcp", "udp"], "port": [1 + i, format!("{}-{}", 10000 + i, 20000 + i)], "action": {"exit": if i % 2 == 0 {"main"} else {"node"}}})).collect();
	let doc = with(|d| {
		d["groups"] = (0..16).map(|g| format!("g{g}")).collect();
		d["users"] = users.into();
		d["routing"]["rules"] = rules.into();
	}).to_string();
	let started = Instant::now();
	let config = Config::parse(doc.as_bytes()).unwrap();
	let parsed = started.elapsed();
	let report = config.validate(true);
	let validated = started.elapsed() - parsed;
	println!("limits: {} bytes, {} users, {} rules, parse {parsed:?}, validate with the shadow check {validated:?}, shadow cut short: {}", doc.len(), config.users.len(), config.routing.rules.len(), report.shadow_cut_short);
	assert!(report.errors.is_empty() && report.more_errors == 0, "{:?}", &report.errors[..report.errors.len().min(5)]);
	// Only a release build is held to the bound: an unoptimized build is several times slower by nature.
	if !cfg!(debug_assertions) {assert!(validated.as_millis() < 500, "validation took {validated:?}")}
}

#[test]
fn routing_fallback_names_exits_once_and_no_block_exit() {
	clean(|doc| doc["routing"]["fallback"] = json!(["open", "node"]));
	error_at("routing.fallback[0]", |doc| doc["routing"]["fallback"] = json!(["nowhere"]));
	error_at("routing.fallback[1]", |doc| doc["routing"]["fallback"] = json!(["open", "open"]));
	error_at("routing.fallback[0]", |doc| doc["routing"]["fallback"] = json!(["sink"]));
}
