//! `veilway replay reset` against nodes that the test starts from the same binary: what the command says before it acts, its exit status, and what the replay file holds afterwards.
#![cfg(unix)]
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::{Child, Command};

/// Listen addresses come from below the range the system hands out by itself, and from above what the other tests of this crate take.
static NEXT_PORT: AtomicU16 = AtomicU16::new(23800);

/// Runs `veilway replay reset` with `args`: its exit status, what it printed, and what it wrote to standard error.
async fn reset(args: &[&str]) -> (i32, String, String) {
	let done = Command::new(env!("CARGO_BIN_EXE_veilway")).args(["replay", "reset"]).args(args).output().await.unwrap();
	(done.status.code().expect("the command was killed"), String::from_utf8(done.stdout).unwrap(), String::from_utf8(done.stderr).unwrap())
}

/// The floor and the limit of the replay file in `dir`, and whether it has the clean mark.
fn saved(dir: &Path) -> (u64, u64, bool) {
	let file = std::fs::read(dir.join("veilway-replay")).unwrap();
	(u64::from_be_bytes(file[16..24].try_into().unwrap()), u64::from_be_bytes(file[24..32].try_into().unwrap()), file[12] == 1)
}

/// A directory with the config of a node whose one inbound has a transport of `kind`, and that node, started and answering on its control socket.
async fn node(test: &str, kind: &str) -> (PathBuf, Child) {
	let dir = std::env::temp_dir().join(format!("veilway-replay-cli-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let listen = loop {
		let addr = SocketAddr::from(([127, 0, 0, 1], NEXT_PORT.fetch_add(1, Ordering::Relaxed)));
		if std::net::UdpSocket::bind(addr).is_ok() {break addr}
	};
	std::fs::write(dir.join("config.json"), json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "veilway", "private_key": veilway_wg::encode_key(&veilway_wg::generate_key()), "address": ["10.7.0.1/24"], "transports": [{"type": kind, "listen": listen.to_string()}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": []},
		"users": [{"name": "a", "exits": "all", "quota_bytes": 1000, "devices": [{"name": "phone", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&veilway_wg::generate_key())), "transport_secrets": [veilway_wg::encode_key(&veilway_wg::generate_key())], "addresses": ["10.7.0.2"]}]}],
	}).to_string()).unwrap();
	std::fs::set_permissions(dir.join("config.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
	let node = Command::new(env!("CARGO_BIN_EXE_veilway")).args(["run", "--config", dir.join("config.json").to_str().unwrap()]).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
	let deadline = Instant::now() + Duration::from_secs(20);
	while !dir.join("veilway.sock").exists() {
		assert!(Instant::now() < deadline, "the node did not come up");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	(dir, node)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_says_what_it_costs_acts_only_when_told_to_and_never_touches_the_file_itself() {
	let (dir, mut node) = node("reset", "udp-obfs").await;
	let (config, socket, state) = (dir.join("config.json"), dir.join("veilway.sock"), dir.join("veilway-state.json"));
	let (config, socket) = (config.to_str().unwrap(), socket.to_str().unwrap());
	// The replay file is next to the state file, and a node that never ran here made it with the clock plus the window for its floor and its limit.
	let (floor, limit, clean) = saved(&dir);
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	assert!(floor == limit && floor.abs_diff(now + 60) <= 5 && !clean, "{floor} {limit} at {now}");
	// Two seconds on, so that the reset below has a later clock to set the floor by, and the node has written its state file.
	tokio::time::sleep(Duration::from_millis(2100)).await;
	let usage = || serde_json::from_slice::<Value>(&std::fs::read(&state).unwrap()).unwrap();
	let before = usage();
	// "The command says so before it acts": the price is said every time, and without --yes nothing happens.
	let (status, out, err) = reset(&["--config", config]).await;
	assert!(status == 2 && out.is_empty() && err.contains("Every client is refused for 60 seconds") && err.contains("can use it once more") && err.contains("Usage and quotas are not touched") && err.contains("Nothing was changed"), "{status} {out:?} {err:?}");
	assert_eq!(saved(&dir), (floor, limit, false));
	let (status, out, err) = reset(&["--config", config, "--yes"]).await;
	let (now_floor, now_limit, _) = saved(&dir);
	assert!(status == 0 && err.contains("Every client is refused for 60 seconds") && out.starts_with(&format!("replay memory reset: floor {now_floor}, limit {now_limit}, clock ")) && out.ends_with("Proofs are accepted again once the node's clock has passed the floor\n"), "{status} {out:?} {err:?}");
	assert!(now_floor > floor && now_floor == now_limit && usage() == before, "{now_floor} after {floor}");
	// With the socket named and no config file anywhere near.
	assert_eq!(reset(&["--api", socket, "--yes"]).await.0, 0);
	// A node that was killed leaves its socket behind, and the command does not go to the file in its place.
	node.kill().await.unwrap();
	let left = saved(&dir);
	let (status, out, err) = reset(&["--api", socket, "--yes"]).await;
	assert!(status == 4 && out.is_empty() && err.contains("no node answers on the control socket") && err.contains("never touches the replay file itself") && saved(&dir) == left, "{status} {out:?} {err:?}");
	std::fs::remove_dir_all(&dir).unwrap();
	// A node without an obfuscated transport keeps no replay memory, and makes no replay file.
	let (dir, _node) = self::node("absent", "udp").await;
	let (status, out, err) = reset(&["--config", dir.join("config.json").to_str().unwrap(), "--yes"]).await;
	assert!(status == 3 && out.is_empty() && err.contains("keeps no replay memory") && !dir.join("veilway-replay").exists(), "{status} {out:?} {err:?}");
	std::fs::remove_dir_all(&dir).unwrap();
}
