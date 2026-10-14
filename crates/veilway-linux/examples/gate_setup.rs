//! The setup of `scripts/gate-client.sh`: what a panel would make for one user. Writes a node config (a `veilway` inbound with `udp-obfs` and `tls`, a self-signed certificate) and a subscription file for one device, signed with a key made here and carrying the device's own keys, so that it needs no endpoint. Keys are made at run time and written to the two files only; nothing is printed.
//!
//! `gate_setup <out-dir> <node-ip> <dns-ip> [--v6]`. The node's files go in `<out-dir>/node`, the subscription in `<out-dir>/client/subscription.vw`. The node address is the one the client dials, and the DNS address is the server the node's resolver asks.
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rcgen::PublicKeyData;
use ring::digest::{digest, SHA256};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use veilway_proto::subscription::envelope::{self, SigningKey};
use veilway_wg::{encode_key, generate_key, public_key};

fn write(path: &Path, text: &str) {
	fs::write(path, text).unwrap();
	fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn main() {
	let args: Vec<String> = std::env::args().skip(1).collect();
	let (out, node_ip, dns_ip, v6) = (Path::new(&args[0]), &args[1], &args[2], args.iter().any(|arg| arg == "--v6"));
	let (node_dir, client_dir) = (out.join("node"), out.join("client"));
	fs::create_dir_all(&node_dir).unwrap();
	fs::create_dir_all(&client_dir).unwrap();
	let (inbound, device, transport, secret, seed) = (generate_key(), generate_key(), generate_key(), generate_key(), generate_key());
	let made = rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap();
	write(&node_dir.join("cert.pem"), &made.cert.pem());
	write(&node_dir.join("key.pem"), &made.signing_key.serialize_pem());
	let pin = STANDARD.encode(digest(&SHA256, &made.signing_key.subject_public_key_info()).as_ref());
	let (path, tunnel, gateways) = ("/assets/app-3f9c2e71.js", if v6 {vec!["10.7.0.2", "fd07:7::2"]} else {vec!["10.7.0.2"]}, if v6 {vec!["10.7.0.1", "fd07:7::1"]} else {vec!["10.7.0.1"]});
	let node = json!({
		"version": 1,
		"log": {"level": "info", "destinations": false},
		"dns": {"servers": [format!("{dns_ip}:53")]},
		"inbounds": [{
			"tag": "home", "type": "veilway", "private_key": encode_key(&inbound),
			"address": if v6 {json!(["10.7.0.1/24", "fd07:7::1/64"])} else {json!(["10.7.0.1/24"])},
			"transport_keys": [encode_key(&transport)], "upgrade_cookie": "sid",
			"transports": [
				{"type": "udp-obfs", "listen": "0.0.0.0:5001"},
				{"type": "tls", "listen": "0.0.0.0:443", "path": path, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": "http://127.0.0.1:8080"}}
			]
		}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "name": "Main exit", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": encode_key(&public_key(&device)), "transport_secrets": [encode_key(&secret)], "addresses": tunnel}]}]
	});
	write(&node_dir.join("config.json"), &serde_json::to_string_pretty(&node).unwrap());
	let provider = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
	let key = SigningKey::new(provider.public_key().as_ref().try_into().unwrap()).unwrap();
	let profile = |id: &str, name: &str, transports: serde_json::Value, only_v4: bool| json!({
		"type": "veilway", "id": id, "name": name, "inbound_public_key": encode_key(&public_key(&inbound)),
		"device": {"public_key": encode_key(&public_key(&device)), "private_key": encode_key(&device), "transport_secrets": [encode_key(&secret)], "addresses": &tunnel[..if only_v4 {1} else {tunnel.len()}]},
		"gateways": &gateways[..if only_v4 {1} else {gateways.len()}], "mtu": 1390, "transport_public_key": encode_key(&veilway_proto::proof::public_key(&transport)),
		"transports": transports, "exits": [{"tag": "main", "name": "Main exit"}]
	});
	let obfs = json!([{"type": "udp-obfs", "endpoints": [format!("{node_ip}:5001")]}]);
	let tls = json!([{"type": "tls", "path": path, "candidates": [{"address": format!("{node_ip}:443"), "sni": "node.test", "host": "node.test", "pins": [pin], "self_signed": true}]}]);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	// The second file is the same device with no IPv6 address in its profile: the tunnel then refuses IPv6 and carries IPv4 only.
	for (file, id, only_v4) in [("subscription.vw", "gate-client-subscription", false), ("subscription-v4.vw", "gate-client-subscription-v4", true)] {
		let payload = json!({
			"v": 1, "subscription_id": id, "serial": 1, "issued_at": now - 10, "expires_at": now + 30 * 86_400,
			"signing_keys": [STANDARD.encode(key.bytes())], "provider": {"name": "Gate provider"},
			"profiles": [profile("obfs", "Gate, obfuscated", obfs.clone(), only_v4), profile("tls", "Gate, looks like a website", tls.clone(), only_v4)]
		});
		let signed = envelope::seal(&key, &serde_json::to_vec(&payload).unwrap(), |signed| provider.sign(signed).as_ref().try_into().unwrap());
		write(&client_dir.join(file), &format!("v1.{}.{signed}", URL_SAFE_NO_PAD.encode(key.bytes())));
	}
}
