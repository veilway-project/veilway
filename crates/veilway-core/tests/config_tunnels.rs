//! Tunnels in config version 1: `tunnels[]`, each rule of the config reference and of the node links page ("Tunnels") by changing one thing in a document that is good.
use serde_json::{json, Value};
use veilway_core::config::{Config, Diff, Report, MAX_TUNNELS};

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

/// An entry with a `chain` exit for one link it dials, an exit that is no chain, a transport on 51820, and two tunnels: a TCP one on loopback and a UDP one that lists its sources.
fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "ws", "listen": "127.0.0.1:8080", "path": "/ws"}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "far", "backend": {"type": "chain", "links": ["out"]}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}],
		"links": [{"tag": "out", "id": "EBESExQVFhcYGRobHB0eHw", "direction": "forward", "addresses": {"dialler": ["10.20.0.2"]}, "transport_secret": key(0x42), "private_key": key(0x52), "peer": {"inbound_public_key": key(0x61), "transports": [{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821"]}]}}],
		"tunnels": [
			{"tag": "web", "protocol": "tcp", "listen": "127.0.0.1:9443", "exit": "far", "target": "192.168.1.10:443"},
			{"tag": "game", "protocol": "udp", "listen": "203.0.113.5:27015", "exit": "far", "target": "192.168.1.10:27015", "sources": ["198.51.100.0/24", "192.0.2.7"], "max_connections": 64}
		]
	})
}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

#[track_caller]
fn refused(path: &str, says: &str, edit: impl FnOnce(&mut Value)) {
	let mut doc = node();
	edit(&mut doc);
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == path && error.message.contains(says)), "expected an error at {path} that says \"{says}\", got {:#?}", report.errors);
}

#[test]
fn a_node_with_tunnels_validates_and_reads_them_back() {
	let report = check(&node());
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	let config = Config::parse(node().to_string().as_bytes()).unwrap();
	assert_eq!((config.tunnels.len(), config.tunnels[0].on(), config.tunnels[0].limit(), config.tunnels[1].limit()), (2, true, 256, 64));
	assert_eq!(config.tunnels[1].sources.as_ref().unwrap().iter().map(|source| source.0.to_string()).collect::<Vec<_>>(), ["198.51.100.0/24", "192.0.2.7/32"]);
	let written: Value = serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
	assert_eq!(written["tunnels"][1]["sources"], json!(["198.51.100.0/24", "192.0.2.7"]));
}

#[test]
fn a_tunnel_has_a_tag_an_exit_that_chains_and_a_listen_address_of_its_own() {
	refused("tunnels[1].tag", "each entry once", |doc| doc["tunnels"][1]["tag"] = json!("web"));
	refused("tunnels[0].tag", "reserved", |doc| doc["tunnels"][0]["tag"] = json!("direct"));
	refused("tunnels[0].exit", "no exit has", |doc| doc["tunnels"][0]["exit"] = json!("nothing"));
	refused("tunnels[0].exit", "chain backend", |doc| doc["tunnels"][0]["exit"] = json!("main"));
	refused("tunnels[1].listen", "two tunnels never share", |doc| {
		doc["tunnels"][1]["protocol"] = json!("tcp");
		doc["tunnels"][1]["listen"] = json!("0.0.0.0:9443");
	});
	refused("tunnels[0].listen", "never shares an address, port and protocol with a transport", |doc| doc["tunnels"][0]["listen"] = json!("127.0.0.1:8080"));
	refused("tunnels[1].listen", "never shares an address, port and protocol with a transport", |doc| doc["tunnels"][1]["listen"] = json!("0.0.0.0:51820"));
	// The same port over the other protocol is another socket.
	let mut other = node();
	other["tunnels"][0]["listen"] = json!("127.0.0.1:51820");
	assert!(check(&other).errors.is_empty());
	// A tunnel that is not enabled is held to everything.
	refused("tunnels[0].exit", "no exit has", |doc| {
		doc["tunnels"][0]["enabled"] = json!(false);
		doc["tunnels"][0]["exit"] = json!("nothing");
	});
	let mut many = node();
	many["tunnels"] = json!((0..=MAX_TUNNELS).map(|n| json!({"tag": format!("t{n}"), "protocol": "tcp", "listen": format!("127.0.0.1:{}", 20000 + n), "exit": "far", "target": "192.168.1.10:443", "max_connections": 1})).collect::<Vec<_>>());
	assert!(check(&many).errors.iter().any(|error| error.path == "tunnels" && error.message.contains("at most 64")));
}

#[test]
fn the_target_is_nothing_the_node_must_not_reach() {
	// Not a link address, not inside an inbound pool, nothing the destination gate refuses, and not a listen address of this node.
	refused("tunnels[0].target", "link address", |doc| doc["tunnels"][0]["target"] = json!("10.20.0.2:80"));
	refused("tunnels[0].target", "destination gate", |doc| doc["tunnels"][0]["target"] = json!("10.7.0.9:80"));
	refused("tunnels[0].target", "destination gate", |doc| doc["tunnels"][0]["target"] = json!("127.0.0.1:80"));
	refused("tunnels[0].target", "destination gate", |doc| doc["tunnels"][0]["target"] = json!("169.254.169.254:80"));
	refused("tunnels[0].target", "listen address", |doc| doc["tunnels"][0]["target"] = json!("127.0.0.1:8080"));
	refused("tunnels[0].target", "listen address", |doc| doc["tunnels"][0]["target"] = json!("192.168.1.10:51820"));
	refused("tunnels[0].target", "listen address", |doc| doc["tunnels"][0]["target"] = json!("203.0.113.5:27015"));
	// A private address is for the far node to allow, and a port of the node that no listener uses is a target like any other.
	let mut fine = node();
	fine["tunnels"][0]["target"] = json!("192.168.1.10:8080");
	assert!(check(&fine).errors.is_empty());
}

#[test]
fn sources_are_listed_once_and_a_udp_tunnel_off_loopback_needs_them() {
	refused("tunnels[1].sources", "1 to 64", |doc| doc["tunnels"][1]["sources"] = json!([]));
	refused("tunnels[1].sources", "1 to 64", |doc| doc["tunnels"][1]["sources"] = json!((0..65).map(|n| format!("10.{n}.0.0/16")).collect::<Vec<_>>()));
	refused("tunnels[1].sources[1]", "each entry once", |doc| doc["tunnels"][1]["sources"] = json!(["192.0.2.7", "192.0.2.7"]));
	refused("tunnels[1].sources", "UDP tunnel", |doc| drop(doc["tunnels"][1].as_object_mut().unwrap().remove("sources")));
	for bad in [json!("192.0.2.7/24"), json!("not an address"), json!(5)] {
		let mut doc = node();
		doc["tunnels"][1]["sources"] = json!([bad]);
		assert!(Config::parse(doc.to_string().as_bytes()).is_err());
	}
	// On loopback a UDP tunnel needs none, and a TCP tunnel off loopback without them is a warning.
	let mut loopback = node();
	loopback["tunnels"][1]["listen"] = json!("127.0.0.1:27015");
	loopback["tunnels"][1].as_object_mut().unwrap().remove("sources");
	assert!(check(&loopback).errors.is_empty());
	let mut open = node();
	(open["tunnels"][0]["listen"], open["tunnels"][0]["protocol"]) = (json!("203.0.113.5:9443"), json!("tcp"));
	let report = check(&open);
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == "tunnels[0].sources" && warning.message.contains("anyone")), "{report:#?}");
}

#[test]
fn max_connections_is_bounded_alone_and_all_together() {
	refused("tunnels[0].max_connections", "1 to 4096", |doc| doc["tunnels"][0]["max_connections"] = json!(0));
	refused("tunnels[0].max_connections", "1 to 4096", |doc| doc["tunnels"][0]["max_connections"] = json!(4097));
	// Five tunnels of 4,096 come to more than 16,384, and four come to exactly that.
	let mut doc = node();
	doc["tunnels"] = json!((0..4).map(|n| json!({"tag": format!("t{n}"), "protocol": "tcp", "listen": format!("127.0.0.1:{}", 20000 + n), "exit": "far", "target": "192.168.1.10:443", "max_connections": 4096})).collect::<Vec<_>>());
	assert!(check(&doc).errors.is_empty());
	doc["tunnels"].as_array_mut().unwrap().push(json!({"tag": "t4", "protocol": "tcp", "listen": "127.0.0.1:20004", "exit": "far", "target": "192.168.1.10:443", "max_connections": 1}));
	assert!(check(&doc).errors.iter().any(|error| error.path == "tunnels" && error.message.contains("16384")), "{:#?}", check(&doc).errors);
}

#[test]
fn a_diff_sees_a_tunnel_by_its_tag_and_not_by_the_spelling_of_its_defaults() {
	let (old, now) = (Config::parse(node().to_string().as_bytes()).unwrap(), time::OffsetDateTime::now_utc());
	let mut spelled = node();
	(spelled["tunnels"][0]["enabled"], spelled["tunnels"][0]["max_connections"]) = (json!(true), json!(256));
	assert!(Diff::between(&old, &Config::parse(spelled.to_string().as_bytes()).unwrap(), now).tunnels.changed.is_empty());
	let mut changed = node();
	changed["tunnels"][0]["target"] = json!("192.168.1.11:443");
	changed["tunnels"][1]["tag"] = json!("other");
	let diff = Diff::between(&old, &Config::parse(changed.to_string().as_bytes()).unwrap(), now);
	assert_eq!((diff.tunnels.changed, diff.tunnels.added, diff.tunnels.removed), (vec!["web".to_string()], vec!["other".to_string()], vec!["game".to_string()]));
}
