//! Config reloading: the diff between two documents, and the store that applies one in two phases.
use serde_json::{json, Value};
use std::fmt;
use std::fs;
use std::future::ready as now;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::field::Field;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};
use tokio::sync::oneshot;
use veilway_core::config::{ApplyError, Changes, Config, Diff, InboundChange, Key, Report, Revision, Snapshot, Store, UserChange};

/// The time every diff here is taken at.
const NOW: &str = "2027-01-15T08:00:00Z";

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
			{"name": "alice", "groups": ["staff"], "exits": "all", "devices": [
				{"name": "laptop", "public_key": key(0x21), "preshared_key": key(0x31), "addresses": ["10.7.0.2", "fd7a:115c:a1e0::2", "10.8.0.2"]},
				{"name": "phone", "public_key": key(0x24), "addresses": ["10.7.0.4"]}
			]},
			{"name": "bob", "groups": ["guest"], "exits": ["main", "node"], "devices": [{"name": "phone", "public_key": key(0x22), "addresses": ["10.7.0.3"]}]}
		]
	})
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
	let mut doc = good();
	edit(&mut doc);
	doc
}

fn bytes(doc: &Value) -> Vec<u8> {doc.to_string().into_bytes()}

/// Every document a diff is taken of here is one the store would accept.
#[track_caller]
fn config(doc: &Value) -> Config {
	let config = Config::parse(&bytes(doc)).unwrap_or_else(|e| panic!("does not parse: {e}"));
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "expected a valid document, got {:#?}", report.errors);
	config
}

#[track_caller]
fn between(old: &Value, new: &Value) -> Diff {Diff::between(&config(old), &config(new), OffsetDateTime::parse(NOW, &Rfc3339).unwrap())}

#[track_caller]
fn diff(edit: impl FnOnce(&mut Value)) -> Diff {between(&good(), &with(edit))}

fn names(list: &[&str]) -> Vec<String> {list.iter().map(|name| name.to_string()).collect()}

fn changed(tag: &str) -> Changes {Changes {changed: names(&[tag]), ..Changes::default()}}

fn inbound(tag: &str, restart: bool, stopped: &[usize], started: &[usize]) -> Vec<InboundChange> {
	vec![InboundChange {tag: tag.to_string(), restart, transports_stopped: stopped.to_vec(), transports_started: started.to_vec()}]
}

fn alice() -> UserChange {UserChange {name: "alice".to_string(), devices_added: vec![], devices_removed: vec![], devices_readdressed: vec![], devices_rekeyed: vec![], lost_access: false}}

fn store() -> Store {Store::new(config(&good()), Revision::of(&bytes(&good())), Report::default())}

/// A file of its own for one test.
fn file(test: &str) -> PathBuf {std::env::temp_dir().join(format!("veilway-config-reload-{test}-{}.json", std::process::id()))}

async fn ready(_: &Snapshot, _: &Diff) -> Result<(), String> {Ok(())}

async fn never(_: &Snapshot, _: &Diff) -> Result<(), String> {panic!("prepare ran")}

/// Keeps every event of the thread it is set on as its level and its fields.
struct Capture(Arc<Mutex<Vec<(Level, String)>>>);

impl Subscriber for Capture {
	fn enabled(&self, _: &Metadata) -> bool {true}
	fn new_span(&self, _: &Attributes) -> Id {Id::from_u64(1)}
	fn record(&self, _: &Id, _: &Record) {}
	fn record_follows_from(&self, _: &Id, _: &Id) {}
	fn event(&self, event: &Event) {
		let mut line = String::new();
		event.record(&mut |field: &Field, value: &dyn fmt::Debug| line.push_str(&format!("{}={value:?} ", field.name())));
		self.0.lock().unwrap().push((*event.metadata().level(), line));
	}
	fn enter(&self, _: &Id) {}
	fn exit(&self, _: &Id) {}
}

#[test]
fn every_category_is_reported() {
	let d = diff(|doc| {
		doc["dns"]["servers"] = json!(["9.9.9.9:53"]);
		doc["log"] = json!({"level": "debug"});
		doc["routing"]["default"] = json!("open");
		doc["inbounds"][0]["mtu"] = json!(1380);
		doc["inbounds"][1] = json!({"tag": "lab", "type": "wireguard", "private_key": key(0x13), "address": ["10.9.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51830"}]});
		doc["outbounds"] = json!([{"tag": "proxy", "type": "socks5", "server": "127.0.0.1:1081"}, {"tag": "spare", "type": "direct"}]);
		doc["exits"][1]["backend"]["outbound"] = json!("spare");
		doc["exits"][3] = json!({"tag": "extra", "backend": {"type": "block"}});
		doc["routing"]["rules"][2]["port"] = json!([25, 587]);
		doc["routing"]["rules"][3] = json!({"tag": "no-quic", "protocol": ["udp"], "port": [443], "action": "reject"});
		doc["users"][0]["devices"][0]["addresses"] = json!(["10.7.0.2", "fd7a:115c:a1e0::2"]);
		doc["users"][1] = json!({"name": "carol", "exits": "all", "devices": [{"name": "tablet", "public_key": key(0x23), "addresses": ["10.9.0.2"]}]});
	});
	assert_eq!(d, Diff {
		inbounds: Changes {added: names(&["lab"]), changed: names(&["home"]), removed: names(&["office"])},
		outbounds: Changes {added: names(&["spare"]), changed: names(&["proxy"]), removed: names(&["plain"])},
		exits: Changes {added: names(&["extra"]), changed: names(&["open"]), removed: names(&["sink"])},
		rules: Changes {added: names(&["no-quic"]), changed: names(&["no-smtp"]), removed: names(&["intranet"])},
		users: Changes {added: names(&["carol"]), changed: names(&["alice"]), removed: names(&["bob"])},
		dns: true,
		log: true,
		routing_default: true,
		rules_reordered: false,
		inbound_changes: inbound("home", true, &[], &[]),
		user_changes: vec![UserChange {devices_readdressed: vec![Key([0x21; 32])], ..alice()}],
	});
	assert!(!d.is_empty());
}

#[test]
fn each_flag_stands_alone() {
	assert!(between(&good(), &good()).is_empty());
	assert_eq!(diff(|doc| doc["dns"]["hijack"] = json!(false)), Diff {dns: true, ..Diff::default()});
	assert_eq!(diff(|doc| doc["log"] = json!({"destinations": true})), Diff {log: true, ..Diff::default()});
	assert_eq!(diff(|doc| doc["routing"]["default"] = json!("node")), Diff {routing_default: true, ..Diff::default()});
	assert_eq!(diff(|doc| doc["routing"]["rules"].as_array_mut().unwrap().swap(0, 2)), Diff {rules_reordered: true, ..Diff::default()});
	let removed = diff(|doc| {doc["routing"]["rules"].as_array_mut().unwrap().remove(1);});
	assert_eq!(removed, Diff {rules: Changes {removed: names(&["no-private"]), ..Changes::default()}, ..Diff::default()});
}

#[test]
fn tunnel_restart_or_transports_only() {
	let restarts: [fn(&mut Value); 3] = [|doc| doc["inbounds"][1]["private_key"] = json!(key(0x14)), |doc| doc["inbounds"][1]["address"] = json!(["10.8.0.1/23"]), |doc| doc["inbounds"][1]["mtu"] = json!(1300)];
	for edit in restarts {assert_eq!(diff(edit), Diff {inbounds: changed("office"), inbound_changes: inbound("office", true, &[], &[]), ..Diff::default()})}
	assert!(diff(|doc| doc["inbounds"][1]["mtu"] = json!(1420)).is_empty(), "the default mtu written out is the same tunnel");
	assert!(diff(|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().reverse()).is_empty(), "transports in another order are the same transports");
	let moved = diff(|doc| doc["inbounds"][0]["transports"][1]["path"] = json!("/tunnel"));
	assert_eq!(moved, Diff {inbounds: changed("home"), inbound_changes: inbound("home", false, &[1], &[1]), ..Diff::default()});
	let more = diff(|doc| doc["inbounds"][1]["transports"].as_array_mut().unwrap().insert(0, json!({"type": "udp", "listen": "0.0.0.0:51822"})));
	assert_eq!(more, Diff {inbounds: changed("office"), inbound_changes: inbound("office", false, &[], &[0]), ..Diff::default()});
	let fewer = diff(|doc| {doc["inbounds"][0]["transports"].as_array_mut().unwrap().remove(0);});
	assert_eq!(fewer, Diff {inbounds: changed("home"), inbound_changes: inbound("home", false, &[0], &[]), ..Diff::default()});
	let both = diff(|doc| {
		doc["inbounds"][0]["private_key"] = json!(key(0x14));
		doc["inbounds"][0]["transports"][0]["listen"] = json!("0.0.0.0:51900");
	});
	assert_eq!(both, Diff {inbounds: changed("home"), inbound_changes: inbound("home", true, &[0], &[0]), ..Diff::default()});
}

#[test]
fn a_default_written_out_is_not_a_change() {
	let same: [fn(&mut Value); 12] = [
		|doc| doc["inbounds"][0]["address"].as_array_mut().unwrap().reverse(),
		|doc| doc["users"][0]["enabled"] = json!(true),
		|doc| doc["routing"]["rules"][2]["enabled"] = json!(true),
		|doc| doc["dns"]["hijack"] = json!(true),
		|doc| doc["log"] = json!({"level": "info", "destinations": false}),
		|doc| doc["log"] = json!({}),
		|doc| doc["exits"][0]["name"] = json!("main"),
		|doc| doc["exits"][0]["backend"] = json!({"type": "netstack", "outbound": "proxy", "proxy_only": true, "tcp_idle_secs": 7200, "udp_idle_secs": 60, "unsupported": {"icmp_echo": "local", "udp": "reject", "other": "reject"}}),
		|doc| doc["exits"][0]["backend"]["unsupported"] = json!({"other": "reject"}),
		|doc| doc["exits"][1]["backend"]["proxy_only"] = json!(false),
		|doc| doc["exits"][1]["backend"]["unsupported"] = json!({}),
		|doc| doc["exits"][2]["backend"] = json!({"type": "l3", "interface": "veilway0", "masquerade": true}),
	];
	for (i, edit) in same.into_iter().enumerate() {
		let written = with(edit);
		assert!(between(&good(), &written).is_empty() && between(&written, &good()).is_empty(), "edit {i} writes out what was already so and is reported as a change");
	}
	// Another value in the same keys is a change.
	assert_eq!(diff(|doc| doc["inbounds"][0]["address"] = json!(["fd7a:115c:a1e0::1/64", "10.7.0.1/23"])), Diff {inbounds: changed("home"), inbound_changes: inbound("home", true, &[], &[]), ..Diff::default()});
	assert_eq!(diff(|doc| doc["routing"]["rules"][2]["enabled"] = json!(false)), Diff {rules: changed("no-smtp"), ..Diff::default()});
	assert_eq!(diff(|doc| doc["users"][0]["enabled"] = json!(false)), Diff {users: changed("alice"), user_changes: vec![UserChange {lost_access: true, ..alice()}], ..Diff::default()});
	let exits: [(&str, fn(&mut Value)); 6] = [
		("main", |doc| doc["exits"][0]["name"] = json!("Main")),
		("main", |doc| doc["exits"][0]["backend"]["proxy_only"] = json!(false)),
		("main", |doc| doc["exits"][0]["backend"]["udp_idle_secs"] = json!(61)),
		("main", |doc| doc["exits"][0]["backend"]["unsupported"] = json!({"icmp_echo": "drop"})),
		("node", |doc| doc["exits"][2]["backend"]["interface"] = json!("veilway1")),
		("node", |doc| doc["exits"][2]["backend"]["masquerade"] = json!(false)),
	];
	for (tag, edit) in exits {assert_eq!(diff(edit), Diff {exits: changed(tag), ..Diff::default()})}
}

#[test]
fn a_device_is_its_public_key() {
	let (laptop, phone) = (Key([0x21; 32]), Key([0x24; 32]));
	let only_alice = |d: Diff, expected: UserChange| assert_eq!(d, Diff {users: changed("alice"), user_changes: vec![expected], ..Diff::default()});
	only_alice(diff(|doc| {
		doc["users"][0]["devices"].as_array_mut().unwrap().reverse();
		doc["users"][0]["devices"][0]["name"] = json!("pocket");
		doc["users"][0]["devices"][1]["name"] = json!("desk");
	}), alice());
	only_alice(diff(|doc| doc["users"][0]["devices"][0]["addresses"].as_array_mut().unwrap().reverse()), alice());
	only_alice(diff(|doc| doc["users"][0]["devices"][1]["addresses"] = json!(["10.7.0.9"])), UserChange {devices_readdressed: vec![phone], ..alice()});
	only_alice(diff(|doc| doc["users"][0]["devices"][1]["addresses"] = json!(["10.7.0.4", "10.8.0.4"])), UserChange {devices_readdressed: vec![phone], ..alice()});
	only_alice(diff(|doc| doc["users"][0]["devices"][1]["public_key"] = json!(key(0x25))), UserChange {devices_added: vec![Key([0x25; 32])], devices_removed: vec![phone], ..alice()});
	only_alice(diff(|doc| doc["users"][0]["devices"][0]["preshared_key"] = json!(key(0x32))), UserChange {devices_rekeyed: vec![laptop], ..alice()});
	only_alice(diff(|doc| doc["users"][0]["devices"][1]["preshared_key"] = json!(key(0x32))), UserChange {devices_rekeyed: vec![phone], ..alice()});
	let handed_over = diff(|doc| {
		let device = doc["users"][0]["devices"].as_array_mut().unwrap().remove(1);
		doc["users"][1]["devices"].as_array_mut().unwrap().push(json!({"name": "second", "public_key": device["public_key"], "addresses": device["addresses"]}));
	});
	assert_eq!(handed_over.user_changes, vec![UserChange {devices_removed: vec![phone], ..alice()}, UserChange {name: "bob".to_string(), devices_added: vec![phone], ..alice()}]);
}

#[test]
fn losing_access() {
	let lost = |old: &Value, new: &Value| between(old, new).user_changes.first().is_some_and(|change| change.lost_access);
	let at = |when: &str| with(|doc| doc["users"][0]["expires_at"] = json!(when));
	let off = with(|doc| doc["users"][0]["enabled"] = json!(false));
	assert!(lost(&good(), &off));
	assert!(lost(&good(), &at("2027-01-15T07:59:59Z")));
	assert!(lost(&good(), &at(NOW)));
	assert!(lost(&at("2027-01-15T11:00:00+02:00"), &off), "an offset is part of the time");
	assert!(!lost(&good(), &at("2027-01-15T08:00:01Z")));
	assert!(!lost(&good(), &with(|doc| doc["users"][0]["enabled"] = json!(true))));
	assert!(!lost(&off, &good()));
	assert!(!lost(&off, &at("2020-01-01T00:00:00Z")), "a user who could not connect before did not lose anything");
	assert!(!lost(&at("2020-01-01T00:00:00Z"), &off));
	assert!(!lost(&good(), &with(|doc| doc["users"][0]["exits"] = json!(["main"]))));
}

#[tokio::test]
async fn a_commit_swaps_the_snapshot_and_wakes_watchers() {
	let store = store();
	let mut watcher = store.subscribe();
	let first = store.current();
	let doc = with(|doc| {
		doc["inbounds"][0]["private_key"] = json!(key(0x14));
		doc["outbounds"][0]["password"] = json!("another-password");
		doc["users"][0]["devices"][0]["preshared_key"] = json!(key(0x32));
	});
	let applied = store.apply(bytes(&doc), Some(first.revision), async |snapshot: &Snapshot, diff: &Diff| {
		assert_eq!((snapshot.generation, store.current().generation, diff.inbound_changes.len()), (2, 1, 1), "prepare runs before the commit, against the new snapshot");
		Ok::<(), String>(())
	}).await.unwrap();
	assert_eq!((first.generation, applied.snapshot.generation, applied.snapshot.revision), (1, 2, Revision::of(&bytes(&doc))));
	assert_eq!(applied.diff, Diff {inbounds: changed("home"), outbounds: changed("proxy"), users: changed("alice"), inbound_changes: inbound("home", true, &[], &[]), user_changes: vec![UserChange {devices_rekeyed: vec![Key([0x21; 32])], ..alice()}], ..Diff::default()});
	watcher.changed().await.unwrap();
	let seen = watcher.borrow_and_update().clone();
	assert_eq!((seen.generation, seen.revision, &*seen.config), (2, store.current().revision, &config(&doc)));
	let shown = format!("{applied:?} {:?}", store.current());
	for secret in [key(0x11), key(0x12), key(0x14), key(0x31), key(0x32), "example-user".to_string(), "example-password".to_string(), "another-password".to_string()] {
		assert!(!shown.contains(&secret), "a secret is in the Debug output of an apply");
	}
}

#[tokio::test]
async fn an_invalid_document_changes_nothing() {
	let store = store();
	let watcher = store.subscribe();
	let first = store.current();
	for bad in [b"{".to_vec(), bytes(&with(|doc| doc["version"] = json!(2))), bytes(&with(|doc| doc["routing"]["default"] = json!("missing"))), bytes(&with(|doc| doc["users"][0]["devices"][0]["public_key"] = json!("leaked-value")))] {
		match store.apply(bad, None, never).await {
			Err(ApplyError::Invalid(report)) => assert!(!report.errors.is_empty() && !format!("{report:?}").contains("leaked-value")),
			other => panic!("expected an invalid document, got {:?}", other.map(|applied| applied.snapshot.generation)),
		}
	}
	let last = store.current();
	assert_eq!((last.generation, last.revision), (1, first.revision));
	assert!(Arc::ptr_eq(&last.config, &first.config) && !watcher.has_changed().unwrap());
}

#[tokio::test]
async fn a_failing_prepare_changes_nothing() {
	let store = store();
	let watcher = store.subscribe();
	let first = store.current();
	let doc = bytes(&with(|doc| doc["inbounds"][1]["transports"][0]["listen"] = json!("0.0.0.0:51900")));
	let failed = store.apply(doc.clone(), None, async |_: &Snapshot, diff: &Diff| if diff.inbound_changes[0].transports_started == [0] {Err("cannot bind")} else {Ok(())}).await;
	assert!(matches!(failed, Err(ApplyError::Prepare("cannot bind"))));
	let last = store.current();
	assert_eq!((last.generation, last.revision), (1, first.revision));
	assert!(Arc::ptr_eq(&last.config, &first.config) && !watcher.has_changed().unwrap());
	assert_eq!(store.apply(doc, None, ready).await.unwrap().snapshot.generation, 2, "a failed prepare does not use up a generation");
}

#[tokio::test]
async fn a_stale_base_revision_is_refused_unparsed() {
	let store = store();
	let first = store.current().revision;
	let (one, two) = (bytes(&with(|doc| doc["log"] = json!({"level": "debug"}))), bytes(&with(|doc| doc["log"] = json!({"level": "warn"}))));
	assert!(matches!(store.apply(b"not a document".to_vec(), Some(Revision::of(b"something else")), never).await, Err(ApplyError::Stale {current}) if current == first));
	assert_eq!(store.apply(one.clone(), Some(first), ready).await.unwrap().snapshot.generation, 2);
	assert!(matches!(store.apply(two.clone(), Some(first), never).await, Err(ApplyError::Stale {current}) if current == Revision::of(&one)));
	assert_eq!(store.current().revision, Revision::of(&one));
	assert_eq!(store.apply(two, Some(Revision::of(&one)), ready).await.unwrap().snapshot.generation, 3);
}

#[tokio::test]
async fn the_same_bytes_are_a_no_op() {
	let store = store();
	let watcher = store.subscribe();
	let same = store.apply(bytes(&good()), None, never).await.unwrap();
	assert!(same.diff.is_empty() && same.snapshot.generation == 1 && !watcher.has_changed().unwrap());
	let doc = bytes(&with(|doc| doc["log"] = json!({"level": "debug"})));
	assert_eq!(store.apply(doc.clone(), None, ready).await.unwrap().snapshot.generation, 2);
	let again = store.apply(doc.clone(), Some(Revision::of(&doc)), never).await.unwrap();
	assert!(again.diff.is_empty() && again.snapshot.generation == 2 && store.current().generation == 2);
	let spaced = store.apply([doc.as_slice(), b"\n"].concat(), None, ready).await.unwrap();
	assert!(spaced.diff.is_empty() && spaced.snapshot.generation == 3, "other bytes are another revision even when nothing in them differs");
}

#[tokio::test]
async fn a_no_op_returns_the_warnings_of_the_running_config() {
	let warned = with(|doc| doc["inbounds"][0]["mtu"] = json!(1500));
	let report = config(&warned).validate(false);
	assert!(!report.warnings.is_empty());
	let store = Store::new(config(&warned), Revision::of(&bytes(&warned)), report.clone());
	assert_eq!(store.apply(bytes(&warned), None, never).await.unwrap().report, report);
	let store = self::store();
	assert_eq!(store.apply(bytes(&good()), None, never).await.unwrap().report, Report::default());
	assert_eq!(store.apply(bytes(&warned), None, ready).await.unwrap().report, report);
	let again = store.apply(bytes(&warned), None, never).await.unwrap();
	assert_eq!((again.snapshot.generation, &again.report, &*store.current().report), (2, &report, &report));
}

#[tokio::test]
async fn a_reload_of_the_bytes_that_run_prepares_again() {
	let path = file("prepares-again");
	fs::write(&path, bytes(&good())).unwrap();
	let store = store();
	let watcher = store.subscribe();
	let prepared = AtomicBool::new(false);
	let same = store.reload_from(&path, async |snapshot: &Snapshot, diff: &Diff| {
		assert!(diff.is_empty() && snapshot.generation == 1 && Arc::ptr_eq(&snapshot.config, &store.current().config), "prepare gets the running snapshot and an empty diff");
		prepared.store(true, Ordering::SeqCst);
		Ok::<(), String>(())
	}).await.unwrap();
	assert!(prepared.load(Ordering::SeqCst), "certificates and proxy names are only looked at again in prepare");
	assert!(same.diff.is_empty() && same.snapshot.generation == 1);
	assert!(matches!(store.reload_from(&path, async |_: &Snapshot, _: &Diff| Err("cannot read the certificate")).await, Err(ApplyError::Prepare("cannot read the certificate"))));
	assert!(store.current().generation == 1 && !watcher.has_changed().unwrap());
	fs::remove_file(&path).unwrap();
}

#[tokio::test]
async fn a_reload_reads_the_file_once_it_holds_the_lock() {
	let path = file("reads-under-lock");
	let store = store();
	let level = |level: &str| bytes(&with(|doc| doc["log"] = json!({"level": level})));
	fs::write(&path, level("debug")).unwrap();
	let (release, held) = oneshot::channel::<()>();
	let ahead = store.apply(level("trace"), None, async |_: &Snapshot, _: &Diff| held.await.map_err(|_| "never released"));
	let reload = store.reload_from(&path, ready);
	// Long enough for a reload that reads before it has the lock to have read.
	let rewrite = async {
		tokio::time::sleep(Duration::from_millis(300)).await;
		fs::write(&path, level("warn")).unwrap();
		release.send(()).unwrap();
	};
	let (ahead, reload, _) = tokio::join!(ahead, reload, rewrite);
	assert_eq!((ahead.unwrap().snapshot.generation, reload.unwrap().snapshot.generation), (2, 3));
	assert!(store.current().revision == Revision::of(&level("warn")), "the reload committed what the file held before the apply ahead of it finished");
	fs::remove_file(&path).unwrap();
}

#[test]
fn a_dropped_apply_keeps_the_lock_until_its_check_has_ended() {
	// One blocking thread, kept busy, so the check of the dropped apply cannot start until the test lets it.
	let runtime = tokio::runtime::Builder::new_current_thread().max_blocking_threads(1).enable_all().build().unwrap();
	runtime.block_on(async {
		let store = store();
		let (release, wait) = channel::<()>();
		let busy = tokio::task::spawn_blocking(move || wait.recv().is_ok());
		{
			let mut dropped = pin!(store.apply(bytes(&with(|doc| doc["log"] = json!({"level": "debug"}))), None, never));
			tokio::select! {
				biased;
				_ = &mut dropped => panic!("the apply finished without its check"),
				_ = now(()) => {}
			}
		}
		let mut next = pin!(store.apply(bytes(&good()), None, never));
		let free = tokio::select! {
			biased;
			_ = &mut next => true,
			_ = now(()) => false,
		};
		assert!(!free, "the lock was free while the check of a dropped apply had still to run");
		release.send(()).unwrap();
		assert!(busy.await.unwrap());
		assert_eq!((next.await.unwrap().snapshot.generation, store.current().generation), (1, 1), "a dropped apply commits nothing");
	});
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_applies_never_interleave() {
	const APPLIES: u64 = 32;
	let store = Arc::new(store());
	let mut watcher = store.subscribe();
	let watching = tokio::spawn(async move {
		let mut seen = Vec::new();
		while seen.last() != Some(&(APPLIES + 1)) && watcher.changed().await.is_ok() {seen.push(watcher.borrow_and_update().generation)}
		seen
	});
	let preparing = Arc::new(AtomicBool::new(false));
	let docs: Vec<Vec<u8>> = (0..APPLIES + 8).map(|i| bytes(&with(|doc| doc["dns"]["servers"] = json!([format!("1.1.1.1:{}", 1000 + i)])))).collect();
	let apply = |doc: &Vec<u8>, base: Option<Revision>| {
		let (store, preparing, doc) = (store.clone(), preparing.clone(), doc.clone());
		tokio::spawn(async move {
			store.apply(doc, base, async |snapshot: &Snapshot, diff: &Diff| {
				assert!(!preparing.swap(true, Ordering::SeqCst), "two applies are in prepare at once");
				tokio::task::yield_now().await;
				assert!(snapshot.generation == store.current().generation + 1 && diff.dns);
				preparing.store(false, Ordering::SeqCst);
				Ok::<(), String>(())
			}).await.map(|applied| applied.snapshot.generation)
		})
	};
	let tasks: Vec<_> = docs[..APPLIES as usize].iter().map(|doc| apply(doc, None)).collect();
	let mut generations = Vec::new();
	for task in tasks {generations.push(task.await.unwrap().unwrap())}
	generations.sort();
	assert_eq!(generations, (2..=APPLIES + 1).collect::<Vec<_>>());
	let last = store.current();
	let winner = docs.iter().find(|doc| Revision::of(doc) == last.revision).expect("the final revision is one of the applied documents");
	assert_eq!((last.generation, &*last.config), (APPLIES + 1, &Config::parse(winner).unwrap()));
	let seen = watching.await.unwrap();
	assert!(seen.windows(2).all(|pair| pair[0] < pair[1]) && seen.last() == Some(&(APPLIES + 1)), "a watcher saw generations out of order: {seen:?}");
	let racing: Vec<_> = docs[APPLIES as usize..].iter().map(|doc| apply(doc, Some(last.revision))).collect();
	let mut won = 0;
	for task in racing {
		match task.await.unwrap() {
			Ok(generation) => (won, generations) = (won + 1, vec![generation]),
			Err(e) => assert!(matches!(e, ApplyError::Stale {..})),
		}
	}
	assert_eq!((won, generations, store.current().generation), (1, vec![APPLIES + 2], APPLIES + 2), "exactly one apply on the same base wins");
}

#[tokio::test]
async fn a_reload_logs_a_bad_file_once() {
	let lines = Arc::new(Mutex::new(Vec::new()));
	let _capture = tracing::subscriber::set_default(Capture(lines.clone()));
	// With one subscriber alive, tracing decides whether a log line is on from the thread that reaches it first, and another test's thread has none. A second one makes it ask every subscriber.
	let _second = tracing::Dispatch::new(Capture(Arc::default()));
	let logged = |level: Level| lines.lock().unwrap().iter().filter(|(l, _)| *l == level).map(|(_, line)| line.clone()).collect::<Vec<_>>();
	let path = file("logged-once");
	let store = store();
	let bad = bytes(&with(|doc| doc["users"][0]["devices"][0]["public_key"] = json!("leaked-value")));
	let next = with(|doc| {
		doc["users"][0]["enabled"] = json!(false);
		doc["users"][1]["name"] = json!("carol");
		doc["exits"][3]["tag"] = json!("extra");
	});
	fs::write(&path, &bad).unwrap();
	for _ in 0..3 {assert!(matches!(store.reload_from(&path, never).await, Err(ApplyError::Invalid(_))))}
	assert_eq!(logged(Level::WARN).len(), 1, "the same bad content is logged once");
	assert!(logged(Level::WARN)[0].contains("users[0].devices[0].public_key"));
	fs::write(&path, b"{").unwrap();
	for _ in 0..2 {assert!(matches!(store.reload_from(&path, never).await, Err(ApplyError::Invalid(_))))}
	assert_eq!(logged(Level::WARN).len(), 2, "other bad content is logged again");
	fs::write(&path, &bad).unwrap();
	assert!(store.reload_from(&path, never).await.is_err());
	assert_eq!(logged(Level::WARN).len(), 3);
	fs::write(&path, bytes(&next)).unwrap();
	assert!(matches!(store.reload_from(&path, async |_: &Snapshot, _: &Diff| Err("cannot bind")).await, Err(ApplyError::Prepare("cannot bind"))));
	assert_eq!((logged(Level::WARN).len(), logged(Level::INFO).len(), store.current().generation), (4, 0, 1));
	for _ in 0..2 {assert_eq!(store.reload_from(&path, ready).await.unwrap().snapshot.generation, 2)}
	let info = logged(Level::INFO);
	assert_eq!(info.len(), 1, "a reload of the bytes that already run logs nothing");
	for part in ["generation=2 ", "users=added carol; changed alice; removed bob ", "exits=added extra; removed sink ", "inbounds=none ", "dns=false "] {assert!(info[0].contains(part), "the commit line lacks one of its parts")}
	fs::write(&path, &bad).unwrap();
	assert!(store.reload_from(&path, never).await.is_err());
	assert_eq!(logged(Level::WARN).len(), 5, "bad content that comes back after a good reload is logged again");
	fs::remove_file(&path).unwrap();
	for _ in 0..2 {assert!(matches!(store.reload_from(&path, never).await, Err(ApplyError::Invalid(_))))}
	assert_eq!((logged(Level::WARN).len(), logged(Level::INFO).len(), store.current().generation), (6, 1, 2), "a missing file is logged once");
	let all = lines.lock().unwrap().iter().map(|(_, line)| line.as_str()).collect::<Vec<_>>().join("\n");
	for value in [key(0x11), key(0x21), key(0x31), "leaked-value".to_string(), "example-password".to_string(), "example-user".to_string(), "1.1.1.1".to_string(), "10.7.0".to_string()] {
		assert!(!all.contains(&value), "a value from a config is in a log line");
	}
}
