//! Writes a signed subscription file with a fresh provider key, for the Windows smoke test in `.github/workflows/ci.yml`. Its one connection goes to a TEST-NET address that nothing answers, so the client waits and the kill switch stays up.
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use veilway_proto::subscription::envelope::{self, SigningKey};

fn main() -> anyhow::Result<()> {
	let path = std::env::args().nth(1).expect("usage: smoke_subscription <file>");
	let mut seed = [0u8; 32];
	SystemRandom::new().fill(&mut seed).map_err(|_| anyhow::anyhow!("no random bytes"))?;
	let provider = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|error| anyhow::anyhow!("the provider key: {error}"))?;
	let public: [u8; 32] = provider.public_key().as_ref().try_into()?;
	let key = SigningKey::new(public).ok_or_else(|| anyhow::anyhow!("the provider key is not usable"))?;
	let (device, node) = (veilway_wg::generate_key(), veilway_wg::generate_key());
	let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
	let payload = json!({
		"v": 1, "subscription_id": "smoke-test-subscription", "serial": 1, "issued_at": now - 10, "expires_at": now + 30 * 86_400,
		"signing_keys": [veilway_wg::encode_key(&public)], "provider": {"name": "Smoke test"},
		"profiles": [{
			"type": "veilway", "id": "smoke", "name": "Smoke",
			"inbound_public_key": veilway_wg::encode_key(&veilway_wg::public_key(&node)),
			"device": {"public_key": veilway_wg::encode_key(&veilway_wg::public_key(&device)), "private_key": veilway_wg::encode_key(&device), "transport_secrets": [veilway_core::config::transport_secret()?], "addresses": ["10.7.0.2"]},
			"gateways": ["10.7.0.1"], "mtu": 1390,
			"transports": [{"type": "udp", "endpoints": ["192.0.2.1:51820"]}],
			"exits": [{"tag": "main", "name": "Main exit"}]
		}]
	});
	let signed = envelope::seal(&key, &serde_json::to_vec(&payload)?, |bytes| provider.sign(bytes).as_ref().try_into().expect("an Ed25519 signature is 64 bytes"));
	// The file form is `v1.<key>.<document>` with the key in URL-safe base64 without padding.
	let file_key = veilway_wg::encode_key(&public).replace('+', "-").replace('/', "_").trim_end_matches('=').to_owned();
	std::fs::write(&path, format!("v1.{file_key}.{signed}\n"))?;
	Ok(())
}
