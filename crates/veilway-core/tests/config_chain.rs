//! Outbound chaining and `via` on a node link in config version 1: a `socks5` outbound may name another one, a chain holds at most 8, and a link that dials may go through an outbound's chain. Each rule is refused by changing one thing in a document that is good.
use serde_json::{json, Value};
use veilway_core::config::{Config, Outbound, Report, MAX_CHAIN};

/// An obviously fake key: one byte repeated.
fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

const ID: &str = "AAECAwQFBgcICQoLDA0ODw";
const PATH: &str = "/assets/app-3f9c2e71.js";

/// Two `socks5` outbounds, `second` through `first`, and a link `out` that this node dials. `in` is the link this node is dialled for.
fn base() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]},
			{"tag": "links", "type": "veilway", "private_key": key(0x12), "address": ["10.9.0.1/24"], "transports": [{"type": "udp-obfs", "listen": "0.0.0.0:51821"}]}
		],
		"outbounds": [
			{"tag": "plain", "type": "direct"},
			{"tag": "first", "type": "socks5", "server": "192.0.2.1:1080"},
			{"tag": "second", "type": "socks5", "server": "192.0.2.2:1080", "via": "first"}
		],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "second"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}],
		"links": [
			{"tag": "in", "id": ID, "direction": "forward", "addresses": {"dialler": ["10.9.0.2"]}, "transport_secret": key(0x41), "inbound": "links", "public_key": key(0x51), "exits": ["main"]},
			{"tag": "out", "id": "EBESExQVFhcYGRobHB0eHw", "direction": "forward", "addresses": {"dialler": ["10.20.0.2"]}, "transport_secret": key(0x42), "private_key": key(0x52), "peer": {"inbound_public_key": key(0x61), "transport_public_key": key(0x62), "transports": [
				{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821"]},
				{"type": "tls", "path": PATH, "candidates": [{"address": "203.0.113.9:443", "sni": "node.example", "host": "node.example", "pins": [key(0x07)]}]},
				{"type": "ws", "path": "/assets/live-7c1d0a52.js", "candidates": [{"address": "203.0.113.9:443", "sni": "", "host": "node.example", "verify_name": "node.example"}]}
			]}}
		]
	})
}

/// A chain of `length` socks5 outbounds, `h0` first, and the exit through `h0`.
fn chain(length: usize) -> Value {
	let mut doc = base();
	let mut outbounds = vec![json!({"tag": "plain", "type": "direct"})];
	for at in 0..length {
		let mut outbound = json!({"tag": format!("h{at}"), "type": "socks5", "server": "192.0.2.1:1080"});
		if at + 1 < length {outbound["via"] = json!(format!("h{}", at + 1))}
		outbounds.push(outbound);
	}
	doc["outbounds"] = json!(outbounds);
	doc["exits"][0]["backend"]["outbound"] = json!("h0");
	doc
}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

/// The one error a change of a good document gives at `path`, whose message holds `says`.
#[track_caller]
fn refused(base: fn() -> Value, path: &str, says: &str, edit: impl FnOnce(&mut Value)) {
	let mut doc = base();
	edit(&mut doc);
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == path && error.message.contains(says)), "expected an error at {path} that says \"{says}\", got {:#?}", report.errors);
}

#[test]
fn a_chain_of_socks5_outbounds_validates_and_parses_with_its_vias() {
	let report = check(&base());
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	let config = Config::parse(base().to_string().as_bytes()).unwrap();
	assert!(matches!(&config.outbounds[2], Outbound::Socks5 {via: Some(via), ..} if via == "first"));
	assert!(matches!(&config.outbounds[1], Outbound::Socks5 {via: None, ..}));
}

#[test]
fn a_chain_may_be_as_long_as_the_limit_and_no_longer() {
	assert!(check(&chain(MAX_CHAIN)).errors.is_empty(), "{:#?}", check(&chain(MAX_CHAIN)).errors);
	let report = check(&chain(MAX_CHAIN + 1));
	assert!(report.errors.iter().any(|error| error.path == "outbounds[1].via" && error.message.contains("at most 8")), "{:#?}", report.errors);
	assert_eq!(report.errors.len(), 1, "{:#?}", report.errors);
}

#[test]
fn a_via_names_a_socks5_outbound_that_exists() {
	refused(base, "outbounds[2].via", "found a tag no outbound has", |doc| doc["outbounds"][2]["via"] = json!("nowhere"));
	refused(base, "outbounds[2].via", "expected a socks5 outbound", |doc| doc["outbounds"][2]["via"] = json!("plain"));
	// A direct outbound cannot have a via at all: that is a key the type does not have.
	let mut doc = base();
	doc["outbounds"][0]["via"] = json!("first");
	let error = Config::parse(doc.to_string().as_bytes()).unwrap_err();
	assert!(error.path.starts_with("outbounds[0]") && error.message.contains("via"), "{error}");
}

#[test]
fn a_via_may_not_loop_back_to_its_own_chain() {
	refused(base, "outbounds[1].via", "expected no loop", |doc| doc["outbounds"][1]["via"] = json!("first"));
	refused(base, "outbounds[1].via", "expected no loop", |doc| doc["outbounds"][1]["via"] = json!("second"));
	let report = check(&{let mut doc = base(); doc["outbounds"][1]["via"] = json!("second"); doc});
	assert!(report.errors.iter().any(|error| error.path == "outbounds[2].via" && error.message.contains("expected no loop")), "{:#?}", report.errors);
}

#[test]
fn a_node_link_names_a_socks5_outbound_and_only_one_it_dials() {
	refused(base, "links[1].via", "found a tag no outbound has", |doc| doc["links"][1]["via"] = json!("nowhere"));
	refused(base, "links[1].via", "expected a socks5 outbound", |doc| doc["links"][1]["via"] = json!("plain"));
	refused(base, "links[0].via", "dialled for", |doc| doc["links"][0]["via"] = json!("first"));
	let mut doc = base();
	doc["links"][1]["via"] = json!("second");
	assert!(check(&doc).errors.is_empty(), "{:#?}", check(&doc).errors);
}

#[test]
fn a_chain_may_not_send_udp_from_the_node_around_itself() {
	refused(base, "exits[0].backend.unsupported.udp", "a chain of proxies", |doc| doc["exits"][0]["backend"]["unsupported"] = json!({"udp": "direct"}));
	let mut doc = base();
	doc["exits"][0]["backend"]["unsupported"] = json!({"udp": "reject"});
	assert!(check(&doc).errors.is_empty(), "{:#?}", check(&doc).errors);
	let mut doc = base();
	doc["exits"][0] = json!({"tag": "main", "backend": {"type": "netstack", "outbound": "plain", "proxy_only": false, "unsupported": {"udp": "direct"}}});
	assert!(check(&doc).errors.is_empty(), "{:#?}", check(&doc).errors);
}

#[test]
fn a_link_through_a_chain_needs_a_stream_transport_to_be_usable() {
	refused(base, "links[1].via", "tls or ws", |doc| {
		doc["links"][1]["via"] = json!("first");
		doc["links"][1]["peer"]["transports"] = json!([{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821"]}]);
	});
	let mut doc = base();
	doc["links"][1]["via"] = json!("first");
	doc["links"][1]["peer"]["transports"] = json!([{"type": "udp", "endpoints": ["203.0.113.9:51820"]}, {"type": "ws", "path": PATH, "candidates": [{"address": "203.0.113.9:443", "sni": "", "host": "node.example", "verify_name": "node.example"}]}]);
	let report = check(&doc);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	assert!(report.warnings.iter().any(|warning| warning.path == "links[1].peer.transports[0]" && warning.message.contains("not usable through via")), "{:#?}", report.warnings);
}
