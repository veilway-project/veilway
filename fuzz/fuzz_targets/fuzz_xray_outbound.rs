#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use veilway_core::config::{Config, Outbound};

// The `link` of an `xray` outbound is a share link that an operator pasted, which anyone may have written: it is read with the client's legacy reader and its table. It must never panic, and a refusal must never quote the link, which holds the credential of a server.
// A link that is accepted is kept as the typed fields and never as a link, validates without a panic, and writes and reads back as the same config.
fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else {return};
	let document = json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&[0x11; 32]), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
		"outbounds": [{"type": "xray", "tag": "up", "link": text}],
		"exits": [{"tag": "far", "backend": {"type": "netstack", "outbound": "up"}}],
		"routing": {"default": "far", "rules": []},
		"users": []
	});
	let config = match Config::parse(document.to_string().as_bytes()) {
		Ok(config) => config,
		Err(error) => return assert!(!(text.contains('@') && error.message.contains(text)), "a refusal quoted the link"),
	};
	let Some(Outbound::Xray {link, ..}) = config.outbounds.first() else {panic!("an xray outbound was read as something else")};
	assert!(link.is_none(), "the link was kept");
	let _ = config.validate(false);
	let written = serde_json::to_vec(&config).expect("a parsed config serializes");
	assert!(!String::from_utf8_lossy(&written).contains("\"link\""), "the link was written back");
	assert!(Config::parse(&written).expect("the written config parses again") == config, "the round trip changed the config");
});
