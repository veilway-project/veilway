//! Node links in config version 1: `links[]` on both nodes, the `chain` backend and the `link` condition of a rule, each rule of the node links page by changing one thing in a document that is good.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use veilway_core::config::{Config, Diff, LinkDirection, LinkManage, Report, DEFAULT_MTU, DEFAULT_MTU_OBFS, MAX_LINKS, REDACTED};
use veilway_proto::subscription::link::Link;

/// An obviously fake key: one byte repeated.
fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn public(byte: u8) -> String {veilway_wg::encode_key(&veilway_wg::public_key(&[byte; 32]))}

const ID: &str = "AAECAwQFBgcICQoLDA0ODw";
const PATH: &str = "/assets/app-3f9c2e71.js";

/// What every document here has besides its links: an inbound with a user, an inbound for links, and three exits.
fn node() -> Value {
	json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [
			{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]},
			{"tag": "links", "type": "veilway", "private_key": key(0x12), "address": ["10.9.0.1/24", "fd00:9::1/64"], "transports": [{"type": "udp-obfs", "listen": "0.0.0.0:51821"}]}
		],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "node", "backend": {"type": "l3"}}, {"tag": "far", "backend": {"type": "chain", "links": ["out"]}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}],
		"links": [
			// The exit half of a forward link: this node is dialled.
			{"tag": "in", "id": ID, "direction": "forward", "addresses": {"dialler": ["10.9.0.2", "fd00:9::2"]}, "transport_secret": key(0x41), "inbound": "links", "public_key": key(0x51), "exits": ["main"]},
			// The entry half of another forward link: this node dials.
			{"tag": "out", "id": "EBESExQVFhcYGRobHB0eHw", "direction": "forward", "addresses": {"dialler": ["10.20.0.2"]}, "transport_secret": key(0x42), "private_key": key(0x52), "peer": {"inbound_public_key": key(0x61), "transport_public_key": key(0x62), "transports": [
				{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821", "[2001:db8::9]:51821"]},
				{"type": "tls", "path": PATH, "candidates": [{"address": "203.0.113.9:443", "sni": "node.example", "host": "node.example", "pins": [key(0x07)]}]},
				{"type": "ws", "path": "/assets/live-7c1d0a52.js", "candidates": [{"address": "203.0.113.9:443", "sni": "", "host": "node.example", "verify_name": "node.example"}]}
			]}}
		]
	})
}

/// The other two halves: the entry half of a reverse link, which is dialled, and the exit half of one, which dials.
fn reversed() -> Value {
	let mut doc = node();
	doc["links"][0] = json!({"tag": "in", "id": ID, "direction": "reverse", "addresses": {"dialler": ["10.9.0.2"], "listener": ["10.9.0.3"]}, "transport_secret": key(0x41), "inbound": "links", "public_key": key(0x51)});
	doc["exits"][2]["backend"]["links"] = json!(["in"]);
	let peer = doc["links"][1]["peer"].clone();
	doc["links"][1] = json!({"tag": "out", "id": "EBESExQVFhcYGRobHB0eHw", "direction": "reverse", "addresses": {"dialler": ["10.20.0.2"], "listener": ["10.20.0.3"]}, "transport_secret": key(0x42), "private_key": key(0x52), "peer": peer, "exits": ["main"], "exit": "main", "max_flows": 100, "quota_bytes": 1000, "quota_period": "monthly", "expires_at": "2030-01-01T00:00:00Z", "allow_private": true});
	doc
}

/// A native link to a documentation host with made-up keys, and the fingerprint of its signing key.
fn upstream_link() -> (String, String) {
	let text = format!("veilway://sub/provider.example.org/sub#v1.{}.{}.{}", URL_SAFE_NO_PAD.encode([7u8; 32]), URL_SAFE_NO_PAD.encode([&[1u8][..], &[9u8; 32][..]].concat()), URL_SAFE_NO_PAD.encode([3u8; 16]));
	let Ok(Link::Native(native)) = Link::parse(&text) else {panic!("the test link does not read")};
	(text, native.key().fingerprint().to_string())
}

fn check(doc: &Value) -> Report {Config::parse(doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("does not parse: {e}")).validate(true)}

/// The one error a change of a good document gives, as its path and whether its message holds `says`.
#[track_caller]
fn refused(base: fn() -> Value, path: &str, says: &str, edit: impl FnOnce(&mut Value)) {
	let mut doc = base();
	edit(&mut doc);
	let report = check(&doc);
	assert!(report.errors.iter().any(|error| error.path == path && error.message.contains(says)), "expected an error at {path} that says \"{says}\", got {:#?}", report.errors);
}

#[test]
fn a_node_with_both_halves_of_both_directions_validates() {
	for base in [node, reversed] {
		let report = check(&base());
		assert!(report.errors.is_empty(), "{:#?}", report.errors);
		// The private addresses the tests dial are none: the one warning here is about the pool the link's inbound has no isolation rule for, and there is none of that either.
		assert!(report.warnings.is_empty(), "{:#?}", report.warnings);
	}
	let config = Config::parse(node().to_string().as_bytes()).unwrap();
	assert_eq!((config.links[0].listener(), config.links[0].entry(), config.links[1].listener(), config.links[1].entry()), (true, false, false, true));
	assert_eq!((config.links[0].mtu(&config.inbounds), config.links[1].mtu(&config.inbounds), config.links[0].direction), (DEFAULT_MTU_OBFS, DEFAULT_MTU_OBFS, LinkDirection::Forward));
	assert_eq!((config.links[0].identity(), config.links[1].identity()), (Some([0x51; 32]), Some(veilway_wg::public_key(&[0x52; 32]))));
	assert_eq!(config.links[0].entry_addresses().len(), 2);
	let config = Config::parse(reversed().to_string().as_bytes()).unwrap();
	assert_eq!((config.links[0].entry(), config.links[1].entry(), config.links[0].entry_addresses()[0].0.to_string(), config.links[1].entry_addresses()[0].0.to_string()), (true, false, "10.9.0.3".to_string(), "10.20.0.3".to_string()));
	// A link that lists no udp-obfs has the mtu of a tunnel without the envelope.
	let mut plain = node();
	plain["links"][1]["peer"]["transports"].as_array_mut().unwrap().remove(0);
	let config = Config::parse(plain.to_string().as_bytes()).unwrap();
	assert_eq!(config.links[1].mtu(&config.inbounds), DEFAULT_MTU);
}

#[test]
fn a_link_is_enough_for_an_inbound_without_devices() {
	let report = check(&node());
	assert!(report.warnings.iter().all(|w| w.path != "inbounds[1].address"), "{:#?}", report.warnings);
	let mut none = node();
	none["links"].as_array_mut().unwrap().remove(0);
	let report = check(&none);
	assert!(report.warnings.iter().any(|w| w.path == "inbounds[1].address"), "{report:#?}");
}

#[test]
fn a_link_is_one_of_two_shapes_with_keys_and_an_id_of_its_own() {
	refused(node, "links[0]", "either `inbound` with `public_key`", |doc| doc["links"][0]["peer"] = doc["links"][1]["peer"].clone());
	refused(node, "links[0]", "either `inbound` with `public_key`", |doc| drop(doc["links"][0].as_object_mut().unwrap().remove("inbound")));
	refused(node, "links[0].public_key", "together", |doc| drop(doc["links"][0].as_object_mut().unwrap().remove("public_key")));
	refused(node, "links[1].private_key", "together", |doc| drop(doc["links"][1].as_object_mut().unwrap().remove("private_key")));
	refused(node, "links[1].id", "no other link", |doc| doc["links"][1]["id"] = json!(ID));
	refused(node, "links[1].tag", "each entry once", |doc| doc["links"][1]["tag"] = json!("in"));
	// "Validation refuses a link whose key is also a device's", an inbound's or another link's, on whichever node.
	refused(node, "links[0].public_key", "an inbound or of a device", |doc| doc["links"][0]["public_key"] = json!(key(0x21)));
	refused(node, "links[0].public_key", "an inbound or of a device", |doc| doc["links"][0]["public_key"] = json!(public(0x11)));
	refused(node, "links[1].private_key", "an inbound or of a device", |doc| doc["links"][1]["private_key"] = json!(key(0x12)));
	refused(node, "links[1].private_key", "no other link uses", |doc| doc["links"][0]["public_key"] = json!(public(0x52)));
	refused(node, "links[1].transport_secret", "no device and no other link", |doc| doc["links"][1]["transport_secret"] = json!(key(0x41)));
	refused(node, "links[0].transport_secret", "not a WireGuard key", |doc| doc["links"][0]["transport_secret"] = json!(key(0x21)));
	refused(node, "links[1].transport_secret", "not a WireGuard key", |doc| doc["links"][1]["transport_secret"] = json!(key(0x52)));
	refused(node, "links[1].peer.inbound_public_key", "an inbound of this node", |doc| doc["links"][1]["peer"]["inbound_public_key"] = json!(public(0x12)));
	// What is no link is refused where it is read.
	for (path, edit) in [("links[0].id", json!("AAECAwQFBgcICQoLDA0ODx")), ("links[0].id", json!("short")), ("links[0].direction", json!("sideways")), ("links[0].public_key", json!(key(0))), ("links[0]", json!(1))] {
		let mut doc = node();
		doc["links"][0][path.rsplit_once('.').map_or("more", |(_, key)| key)] = edit;
		assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().path, path);
	}
	let mut many = node();
	many["links"] = json!((0..=MAX_LINKS).map(|_| many["links"][0].clone()).collect::<Vec<_>>());
	assert!(check(&many).errors.iter().any(|error| error.path == "links" && error.message.contains("at most 64")));
}

#[test]
fn a_link_that_is_dialled_is_a_peer_of_a_veilway_inbound_that_carries_no_users() {
	refused(node, "links[0].inbound", "no inbound has", |doc| doc["links"][0]["inbound"] = json!("nowhere"));
	refused(node, "links[0].inbound", "a veilway inbound", |doc| doc["links"][0]["inbound"] = json!("home"));
	refused(node, "links[0].inbound", "carries no users' devices", |doc| {
		doc["users"][0]["devices"][0]["addresses"] = json!(["10.7.0.2", "10.9.0.9"]);
		doc["users"][0]["devices"][0]["transport_secrets"] = json!([key(0x43)]);
	});
	refused(node, "links[0].inbound", "without a fronted transport", |doc| {
		doc["inbounds"][1]["transport_keys"] = json!([key(0x71)]);
		doc["inbounds"][1]["transports"].as_array_mut().unwrap().push(json!({"type": "fronted", "listen": "127.0.0.1:8443", "path": PATH, "decoy": {"origin": "http://127.0.0.1:8080"}, "trusted_proxies": ["127.0.0.1"], "client_address_header": "X-Forwarded-For"}));
	});
	// Its addresses come from that inbound's pool, and are nobody else's.
	refused(node, "links[0].addresses.dialler[0]", "inside the pool of the link's inbound", |doc| doc["links"][0]["addresses"]["dialler"][0] = json!("10.7.0.9"));
	refused(node, "links[0].addresses.dialler[0]", "inside the pool of the link's inbound", |doc| doc["links"][0]["addresses"]["dialler"][0] = json!("10.33.0.2"));
	refused(node, "links[0].addresses.dialler[0]", "not the gateway", |doc| doc["links"][0]["addresses"]["dialler"][0] = json!("10.9.0.1"));
	refused(node, "links[0].addresses.dialler", "at most one IPv4 and one IPv6", |doc| doc["links"][0]["addresses"]["dialler"] = json!(["10.9.0.2", "10.9.0.3"]));
	refused(node, "links[0].addresses.listener", "only a reverse link", |doc| doc["links"][0]["addresses"]["listener"] = json!(["10.9.0.3", "fd00:9::3"]));
	refused(reversed, "links[0].addresses.listener", "a reverse link has one", |doc| drop(doc["links"][0]["addresses"].as_object_mut().unwrap().remove("listener")));
	refused(reversed, "links[0].addresses.listener", "none of them the dialler's own", |doc| doc["links"][0]["addresses"]["listener"] = json!(["10.9.0.2"]));
	refused(reversed, "links[0].addresses.listener", "each family", |doc| doc["links"][0]["addresses"]["listener"] = json!(["fd00:9::3"]));
	refused(node, "links[2].addresses.dialler[0]", "no device and no other link", |doc| {
		let mut second = doc["links"][0].clone();
		(second["tag"], second["id"], second["public_key"], second["transport_secret"]) = (json!("in-2"), json!("ICEiIyQlJicoKSorLC0uLw"), json!(key(0x53)), json!(key(0x44)));
		second["addresses"]["dialler"] = json!(["10.9.0.2"]);
		doc["links"].as_array_mut().unwrap().push(second);
	});
}

#[test]
fn a_link_that_dials_holds_addresses_of_the_other_node_and_dials_only_what_a_node_may() {
	refused(node, "links[1].addresses.dialler[0]", "outside every inbound pool of this node", |doc| doc["links"][1]["addresses"]["dialler"][0] = json!("10.9.0.7"));
	refused(node, "links[1].addresses.dialler[0]", "where the pool it comes from lies", |doc| doc["links"][1]["addresses"]["dialler"][0] = json!("203.0.113.5"));
	// Two links this node dials as the exit half cannot have one address for the node they dial. As the entry half they can: each is looked up for its own link.
	let twin = |doc: &mut Value| {
		let mut second = doc["links"][1].clone();
		(second["tag"], second["id"], second["private_key"], second["transport_secret"]) = (json!("out-2"), json!("ICEiIyQlJicoKSorLC0uLw"), json!(key(0x53)), json!(key(0x44)));
		doc["links"].as_array_mut().unwrap().push(second);
	};
	refused(reversed, "links[2].addresses.listener[0]", "no other link of this node", twin);
	let mut doc = node();
	twin(&mut doc);
	doc["exits"][2]["backend"]["links"] = json!(["out", "out-2"]);
	assert!(check(&doc).errors.is_empty(), "{:#?}", check(&doc).errors);
	// "`udp`, `udp-obfs`, `tls` and `ws`. Not `ws-plain`. Not `fronted` in version 1."
	refused(node, "links[1].peer.transports[2].type", "fronted is not a transport of a link", |doc| doc["links"][1]["peer"]["transports"][2]["type"] = json!("fronted"));
	let mut plain = node();
	plain["links"][1]["peer"]["transports"][2]["type"] = json!("ws-plain");
	assert_eq!(Config::parse(plain.to_string().as_bytes()).unwrap_err().path, "links[1].peer.transports[2].type");
	refused(node, "links[1].peer.transports[0]", "`endpoints` and neither", |doc| doc["links"][1]["peer"]["transports"][0]["path"] = json!(PATH));
	refused(node, "links[1].peer.transports[1]", "`path` and `candidates`", |doc| drop(doc["links"][1]["peer"]["transports"][1].as_object_mut().unwrap().remove("candidates")));
	refused(node, "links[1].peer.transports[1].path", "a path that starts with /", |doc| doc["links"][1]["peer"]["transports"][1]["path"] = json!("/short"));
	refused(node, "links[1].peer.transports[1].candidates[0].pins", "every candidate of a tls transport", |doc| drop(doc["links"][1]["peer"]["transports"][1]["candidates"][0].as_object_mut().unwrap().remove("pins")));
	refused(node, "links[1].peer.transports[1].candidates[0].sni", "a lowercase host name", |doc| doc["links"][1]["peer"]["transports"][1]["candidates"][0]["sni"] = json!("Node.Example"));
	refused(node, "links[1].peer.transports[1].candidates[0].verify_name", "when sni is empty", |doc| doc["links"][1]["peer"]["transports"][1]["candidates"][0]["verify_name"] = json!("node.example"));
	refused(node, "links[1].peer.transports[2].candidates[0].verify_name", "when sni is empty", |doc| drop(doc["links"][1]["peer"]["transports"][2]["candidates"][0].as_object_mut().unwrap().remove("verify_name")));
	// A tls candidate trusted through its pins alone: pins needed, no verify_name, no ws, and an empty sni is fine.
	let pinned = |doc: &mut Value| {let candidate = &mut doc["links"][1]["peer"]["transports"][1]["candidates"][0]; (candidate["sni"], candidate["self_signed"]) = (json!(""), json!(true))};
	let mut alone = node();
	pinned(&mut alone);
	assert!(check(&alone).errors.is_empty(), "{:#?}", check(&alone).errors);
	refused(node, "links[1].peer.transports[1].candidates[0].pins", "every candidate of a tls transport", |doc| {pinned(doc); drop(doc["links"][1]["peer"]["transports"][1]["candidates"][0].as_object_mut().unwrap().remove("pins"))});
	refused(node, "links[1].peer.transports[1].candidates[0].verify_name", "only check", |doc| {pinned(doc); doc["links"][1]["peer"]["transports"][1]["candidates"][0]["verify_name"] = json!("node.example")});
	refused(node, "links[1].peer.transports[2].candidates[0].self_signed", "on a ws transport", |doc| doc["links"][1]["peer"]["transports"][2]["candidates"][0]["self_signed"] = json!(true));
	refused(node, "links[1].peer.transport_public_key", "sealed to it", |doc| drop(doc["links"][1]["peer"].as_object_mut().unwrap().remove("transport_public_key")));
	refused(node, "links[1].peer.transports", "1 to 8 transports", |doc| doc["links"][1]["peer"]["transports"] = json!([]));
	// "No loopback, link-local, unspecified or multicast address, and none of the forms that carry an IPv4 address inside an IPv6 one."
	for address in ["127.0.0.1:51821", "169.254.1.1:51821", "224.0.0.1:51821", "[::1]:51821", "[fe80::1]:51821", "[64:ff9b::7f00:1]:51821", "[2002:a07:2::]:51821"] {refused(node, "links[1].peer.transports[0].endpoints[0]", "a node may be told to dial", |doc| doc["links"][1]["peer"]["transports"][0]["endpoints"][0] = json!(address))}
	refused(node, "links[1].peer.transports[1].candidates[0].address", "a node may be told to dial", |doc| doc["links"][1]["peer"]["transports"][1]["candidates"][0]["address"] = json!("127.0.0.1:443"));
	refused(node, "links[1].peer.transports[0].endpoints[0]", "outside every inbound pool", |doc| doc["links"][1]["peer"]["transports"][0]["endpoints"][0] = json!("10.7.0.9:51821"));
	// A private address is what two nodes in one data centre dial, and it is said.
	let mut near = node();
	near["links"][1]["peer"]["transports"][0]["endpoints"][0] = json!("10.200.0.9:51821");
	let report = check(&near);
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == "links[1].peer.transports[0].endpoints[0]" && warning.message.contains("a private address")), "{report:#?}");
}

#[test]
fn the_exit_half_says_what_a_link_may_reach_and_the_entry_half_says_nothing_of_it() {
	refused(node, "links[0].exits", "the exit half of the link", |doc| drop(doc["links"][0].as_object_mut().unwrap().remove("exits")));
	refused(node, "links[0].exits[1]", "no exit has", |doc| doc["links"][0]["exits"] = json!(["main", "nowhere"]));
	// "A link leaves through another link only with `allow_chain`, and never through an upstream."
	refused(node, "links[0].exits[1]", "only with allow_chain on", |doc| doc["links"][0]["exits"] = json!(["main", "far"]));
	refused(node, "links[0].exits[1]", "only with allow_chain on", |doc| (doc["links"][0]["allow_chain"], doc["links"][0]["exits"]) = (json!(false), json!(["main", "far"])));
	let mut chaining = node();
	(chaining["links"][0]["allow_chain"], chaining["links"][0]["exits"]) = (json!(true), json!(["main", "far"]));
	let report = check(&chaining);
	assert!(report.errors.is_empty() && report.warnings.is_empty(), "{report:#?}");
	assert_eq!(Config::parse(chaining.to_string().as_bytes()).unwrap().links[0].allow_chain, Some(true));
	let mut idle = node();
	(idle["links"][0]["allow_chain"], idle["links"][0]["exits"]) = (json!(true), json!(["main"]));
	let report = check(&idle);
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == "links[0].allow_chain" && warning.message.contains("names no exit with a chain backend")), "{report:#?}");
	for allowed in [false, true] {
		refused(node, "links[0].exits[1]", "not an upstream", |doc| {
			let (text, fingerprint) = upstream_link();
			doc["upstreams"] = json!([{"tag": "other", "link": text, "signing_key": fingerprint, "private_key": key(0x71), "device_secret": URL_SAFE_NO_PAD.encode([0x71; 16]), "exit": "main"}]);
			doc["exits"].as_array_mut().unwrap().push(json!({"tag": "abroad", "backend": {"type": "upstream", "upstream": "other"}}));
			(doc["links"][0]["allow_chain"], doc["links"][0]["exits"]) = (json!(allowed), json!(["main", "abroad"]));
		});
	}
	refused(node, "links[0].exit", "in this link's exits", |doc| doc["links"][0]["exit"] = json!("node"));
	refused(node, "links[0].exit", "no exit has", |doc| doc["links"][0]["exit"] = json!("nowhere"));
	refused(node, "links[0].exits", "routing.default must be in this list", |doc| doc["links"][0]["exits"] = json!(["node"]));
	refused(node, "links[0].max_flows", "from 1 to 65536", |doc| doc["links"][0]["max_flows"] = json!(0));
	refused(node, "links[0].max_flows", "from 1 to 65536", |doc| doc["links"][0]["max_flows"] = json!(65537));
	refused(node, "links[0].quota_period", "needs quota_bytes", |doc| doc["links"][0]["quota_period"] = json!("daily"));
	refused(node, "links[0].quota_bytes", "from 1 to", |doc| doc["links"][0]["quota_bytes"] = json!(0));
	refused(node, "links[0].mtu", "from 1280 to 1500", |doc| doc["links"][0]["mtu"] = json!(1279));
	for key in ["exit", "exits", "allow_chain", "allow_private", "max_flows", "quota_bytes", "expires_at"] {
		refused(node, &format!("links[1].{key}"), "on the entry half of a link", |doc| doc["links"][1][key] = match key {
			"exit" => json!("main"),
			"exits" => json!(["main"]),
			"allow_chain" | "allow_private" => json!(true),
			"expires_at" => json!("2030-01-01T00:00:00Z"),
			_ => json!(100),
		});
	}
	// "Validation warns when an `l3` exit that a link may use has a larger MTU than the link."
	let mut low = node();
	(low["links"][0]["exits"], low["links"][0]["mtu"]) = (json!(["main", "node"]), json!(1300));
	let report = check(&low);
	assert!(report.errors.is_empty() && report.warnings.iter().any(|warning| warning.path == "links[0].mtu" && warning.message.contains("lowers it for that exit's own users")), "{report:#?}");
	let mut high = node();
	high["links"][0]["mtu"] = json!(1400);
	assert!(check(&high).warnings.iter().any(|warning| warning.path == "links[0].mtu" && warning.message.contains("nothing is fragmented for a link")));
	// The shares of the links this node is the exit of are held against the flow table: above half of it, the node's own users may be left with less.
	let shared = |flows: u32| {
		let mut doc = node();
		doc["links"][0]["max_flows"] = json!(flows);
		check(&doc).warnings.iter().any(|warning| warning.path == "links" && warning.message.contains("more than half"))
	};
	assert_eq!((shared(16384), shared(32768), shared(32769)), (false, false, true));
}

#[test]
fn a_chain_exit_names_one_to_four_links_of_which_this_node_is_the_entry_half() {
	refused(node, "exits[2].backend.links[0]", "no link has", |doc| doc["exits"][2]["backend"]["links"] = json!(["nowhere"]));
	refused(node, "exits[2].backend.links[0]", "whose entry half this node is", |doc| doc["exits"][2]["backend"]["links"] = json!(["in"]));
	refused(node, "exits[2].backend.links", "1 to 4 link tags", |doc| doc["exits"][2]["backend"]["links"] = json!([]));
	refused(node, "exits[2].backend.links", "1 to 4 link tags", |doc| doc["exits"][2]["backend"]["links"] = json!(["out", "a", "b", "c", "d"]));
	refused(node, "exits[2].backend.links[1]", "each entry once", |doc| doc["exits"][2]["backend"]["links"] = json!(["out", "out"]));
	refused(node, "exits[3].backend.links[0]", "no other exit names", |doc| doc["exits"].as_array_mut().unwrap().push(json!({"tag": "far-2", "backend": {"type": "chain", "links": ["out"]}})));
	// The policies of an exit that cannot carry something do not exist for a chain exit, and no policy hands traffic to one.
	for (key, value) in [("outbound", json!("plain")), ("unsupported", json!({"udp": "drop"})), ("interface", json!("veilway1")), ("proxy_only", json!(false))] {
		let mut doc = node();
		doc["exits"][2]["backend"][key] = value;
		assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().path, "exits[2].backend");
	}
	let mut doc = node();
	doc["exits"][0]["backend"]["links"] = json!(["out"]);
	assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().path, "exits[0].backend");
	let mut doc = node();
	doc["exits"][2]["backend"].as_object_mut().unwrap().remove("links");
	assert_eq!(Config::parse(doc.to_string().as_bytes()).unwrap_err().message, "missing required key `links`");
	refused(node, "exits[3].backend.unsupported.other.via", "an l3 exit", |doc| {
		doc["outbounds"].as_array_mut().unwrap().push(json!({"tag": "proxy", "type": "socks5", "server": "192.0.2.1:1080"}));
		doc["exits"].as_array_mut().unwrap().push(json!({"tag": "odd", "backend": {"type": "netstack", "outbound": "proxy", "proxy_only": false, "unsupported": {"other": {"via": "far"}}}}));
	});
	// A link nobody routes to is said.
	let mut idle = node();
	idle["exits"].as_array_mut().unwrap().remove(2);
	assert!(check(&idle).warnings.iter().any(|warning| warning.path == "links[1]" && warning.message.contains("never used")));
}

#[test]
fn a_rule_matches_on_a_link_of_which_this_node_is_the_exit_half() {
	let rule = |doc: &mut Value, rule: Value| doc["routing"]["rules"].as_array_mut().unwrap().push(rule);
	let mut doc = node();
	doc["links"][0]["exits"] = json!(["main", "node"]);
	rule(&mut doc, json!({"tag": "link-out", "link": ["in"], "action": {"exit": "node"}}));
	rule(&mut doc, json!({"tag": "link-out-again", "link": ["in"], "protocol": ["tcp"], "action": {"exit": "node"}}));
	let report = check(&doc);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	// The second rule has every condition of the first and more, so the first covers it.
	assert!(report.warnings.iter().any(|warning| warning.path == "routing.rules[3]" && warning.message.contains("never matches")), "{:#?}", report.warnings);
	refused(node, "routing.rules[2].link[0]", "no link has", |doc| rule(doc, json!({"tag": "x", "link": ["nowhere"], "action": "reject"})));
	refused(node, "routing.rules[2].link[0]", "whose exit half this node is", |doc| rule(doc, json!({"tag": "x", "link": ["out"], "action": "reject"})));
	refused(node, "routing.rules[2].link[0]", "not in the link's exits", |doc| rule(doc, json!({"tag": "x", "link": ["in"], "action": {"exit": "node"}})));
	refused(node, "routing.rules[2]", "a link has neither", |doc| rule(doc, json!({"tag": "x", "link": ["in"], "user": ["alice"], "action": "reject"})));
	refused(node, "routing.rules[2].link", "1 to", |doc| rule(doc, json!({"tag": "x", "link": [], "action": "reject"})));
	// "Validation warns when a rule with a `domain` condition could apply to a link": one with no user and no group, on every inbound or on the link's.
	for (applies, extra) in [(true, json!({})), (true, json!({"link": ["in"]})), (true, json!({"inbound": ["links"]})), (false, json!({"inbound": ["home"]})), (false, json!({"user": ["alice"]}))] {
		let mut doc = node();
		let mut named = json!({"tag": "by-name", "domain": ["ads.example.com"], "action": "reject"});
		for (key, value) in extra.as_object().unwrap() {named[key] = value.clone()}
		rule(&mut doc, named);
		let report = check(&doc);
		assert_eq!((report.errors.len(), report.warnings.iter().any(|warning| warning.path == "routing.rules[2].domain" && warning.message.contains("never matches what arrives from a link"))), (0, applies), "{extra}");
	}
}

#[test]
fn the_secrets_of_a_link_are_not_shown_and_come_back_by_the_tag_of_the_link() {
	let config = Config::parse(node().to_string().as_bytes()).unwrap();
	let (shown, saved) = (config.redacted(), serde_json::to_string(&config).unwrap());
	for secret in [key(0x41), key(0x42), key(0x52)] {assert!(!shown.to_string().contains(&secret) && saved.contains(&secret), "a secret of a link is shown, or missing from what is saved")}
	assert_eq!(shown["links"][1]["private_key"], json!(REDACTED));
	assert!(shown["links"][0]["transport_secret"].as_str().is_some_and(|marker| marker.starts_with("<redacted:")) && shown["links"][0]["transport_secret"] != shown["links"][1]["transport_secret"]);
	// What is not secret is shown as it is written: the id, the addresses, the public keys and where the link dials.
	assert_eq!((&shown["links"][0]["public_key"], &shown["links"][1]["peer"], &shown["links"][0]["id"]), (&json!(key(0x51)), &node()["links"][1]["peer"], &json!(ID)));
	// The document that was shown comes back with every secret, in whatever order its links stand.
	let mut back = shown.clone();
	back["links"].as_array_mut().unwrap().reverse();
	back["inbounds"][0]["private_key"] = json!(key(0x11));
	back["inbounds"][1]["private_key"] = json!(key(0x12));
	let (kept, _) = Config::parse_keeping(back.to_string().as_bytes(), &config).unwrap_or_else(|report| panic!("{:#?}", report.errors));
	assert_eq!((&kept.links[0], &kept.links[1]), (&config.links[1], &config.links[0]));
	// A marker under another tag names nothing, and neither does the marker of another link's secret.
	let mut renamed = shown.clone();
	renamed["links"][1]["tag"] = json!("elsewhere");
	let errors = Config::parse_keeping(renamed.to_string().as_bytes(), &config).unwrap_err().errors;
	assert_eq!(errors.iter().filter(|error| error.path.starts_with("links[1].")).map(|error| error.path.as_str()).collect::<Vec<_>>(), ["links[1].transport_secret", "links[1].private_key"]);
	let mut swapped = shown.clone();
	swapped["links"][0]["transport_secret"] = shown["links"][1]["transport_secret"].clone();
	assert!(Config::parse_keeping(swapped.to_string().as_bytes(), &config).unwrap_err().errors.iter().any(|error| error.path == "links[0].transport_secret"));
}

#[test]
fn a_reload_says_which_links_changed() {
	let (old, mut new) = (Config::parse(node().to_string().as_bytes()).unwrap(), node());
	(new["links"][0]["enabled"], new["links"][1]["mtu"]) = (json!(true), json!(1300));
	new["links"].as_array_mut().unwrap().push(json!({"tag": "third", "id": "ICEiIyQlJicoKSorLC0uLw", "direction": "forward", "addresses": {"dialler": ["10.9.0.5"]}, "transport_secret": key(0x45), "inbound": "links", "public_key": key(0x55), "exits": ["main"]}));
	let diff = Diff::between(&old, &Config::parse(new.to_string().as_bytes()).unwrap(), time::OffsetDateTime::UNIX_EPOCH);
	assert_eq!((diff.links.added, diff.links.changed, diff.links.removed.len()), (vec!["third".to_string()], vec!["out".to_string()], 0));
}

/// `node()` with the link it is dialled for managed by its peer, and the link it dials left alone.
fn managed() -> Value {
	let mut doc = node();
	(doc["links"][0]["manage"], doc["links"][0]["addresses"]["listener"]) = (json!("by_peer"), json!(["10.9.0.3", "fd00:9::3"]));
	doc
}

/// `node()` with the link it dials managing the other node.
fn manager() -> Value {
	let mut doc = node();
	(doc["links"][1]["manage"], doc["links"][1]["addresses"]["listener"]) = (json!("peer"), json!(["10.20.0.3"]));
	doc
}

#[test]
fn a_managed_link_has_both_addresses_in_either_direction() {
	// A forward link, dialled for: managed by its peer. The other half of the same pairing dials, and manages.
	let report = check(&managed());
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	let report = check(&manager());
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	let config = Config::parse(manager().to_string().as_bytes()).unwrap();
	assert_eq!((config.links[0].manage, config.links[1].manage), (None, Some(LinkManage::Peer)));
	// A reverse link as well, on either side.
	let mut reverse = reversed();
	reverse["links"][0]["manage"] = json!("by_peer");
	let report = check(&reverse);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	reverse["links"][0].as_object_mut().unwrap().remove("manage");
	reverse["links"][1]["manage"] = json!("peer");
	let report = check(&reverse);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	// Without the listener's address a managed link is refused, whichever direction it has.
	refused(managed, "links[0].addresses.listener", "a managed link has one", |doc| drop(doc["links"][0]["addresses"].as_object_mut().unwrap().remove("listener")));
	refused(managed, "links[0].addresses.listener", "none of them the dialler's own", |doc| doc["links"][0]["addresses"]["listener"] = json!(["10.9.0.2", "fd00:9::3"]));
	refused(managed, "links[0].addresses.listener", "each family", |doc| doc["links"][0]["addresses"]["listener"] = json!(["10.9.0.3"]));
	refused(managed, "links[0].addresses.listener[0]", "inside the pool", |doc| doc["links"][0]["addresses"]["listener"] = json!(["10.20.0.9", "fd00:9::3"]));
	refused(node, "links[1].addresses.listener", "a managed link has one", |doc| doc["links"][1]["manage"] = json!("peer"));
	refused(reversed, "links[0].addresses.listener", "a reverse link has one", |doc| {
		doc["links"][0]["manage"] = json!("by_peer");
		doc["links"][0]["addresses"].as_object_mut().unwrap().remove("listener");
	});
	// A link that is not managed still has no second address in a forward link.
	refused(node, "links[0].addresses.listener", "only a reverse link", |doc| doc["links"][0]["addresses"]["listener"] = json!(["10.9.0.3", "fd00:9::3"]));
	// The values are the two words.
	for value in [json!("listener"), json!("manager"), json!(true), json!(null)] {
		let mut doc = managed();
		doc["links"][0]["manage"] = value.clone();
		assert!(value.is_null() || Config::parse(doc.to_string().as_bytes()).is_err(), "{value}");
	}
}

#[test]
fn a_node_is_managed_by_one_link_and_a_managed_node_manages_none() {
	let second = |peer: Value| json!({"tag": "second", "id": "ICEiIyQlJicoKSorLC0uLw", "direction": "forward", "addresses": {"dialler": ["10.21.0.2"], "listener": ["10.21.0.3"]}, "manage": "peer", "transport_secret": key(0x45), "private_key": key(0x55), "peer": peer});
	// Two links that this node is managed by: one panel per node.
	refused(managed, "links[2].manage", "at most one", |doc| doc["links"].as_array_mut().unwrap().push(json!({"tag": "second", "id": "ICEiIyQlJicoKSorLC0uLw", "direction": "forward", "addresses": {"dialler": ["10.9.0.5"], "listener": ["10.9.0.6"]}, "manage": "by_peer", "transport_secret": key(0x45), "inbound": "links", "public_key": key(0x55), "exits": ["main"]})));
	// A node that is managed is no managing node: no chain of management.
	refused(managed, "links[1].manage", "no peer link", |doc| (doc["links"][1]["manage"], doc["links"][1]["addresses"]["listener"]) = (json!("peer"), json!(["10.20.0.3"])));
	// A node may manage several others, and be managed by none.
	let mut doc = manager();
	let peer = doc["links"][1]["peer"].clone();
	doc["links"].as_array_mut().unwrap().push(second(peer));
	let report = check(&doc);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
}
