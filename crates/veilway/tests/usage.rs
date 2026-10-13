//! `veilway usage reset` against a node that the test starts from the same binary, the way a user runs both: what the command prints, its exit status, and what the node holds and has written afterwards.
#![cfg(unix)]
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::process::Command;

/// Listen addresses come from below the range the system hands out by itself, and from above what the other tests of this crate take.
static NEXT_PORT: AtomicU16 = AtomicU16::new(23600);

/// Runs `veilway usage reset` with `args`: its exit status, what it printed, and what it wrote to standard error.
async fn reset(args: &[&str]) -> (i32, String, String) {
	let done = Command::new(env!("CARGO_BIN_EXE_veilway")).args(["usage", "reset"]).args(args).output().await.unwrap();
	(done.status.code().expect("the command was killed"), String::from_utf8(done.stdout).unwrap(), String::from_utf8(done.stderr).unwrap())
}

/// What the state file in `dir` holds for user `a`.
fn saved(dir: &Path) -> Value {serde_json::from_slice::<Value>(&std::fs::read(dir.join("veilway-state.json")).unwrap()).unwrap()["users"]["a"].clone()}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_from_the_command_line_reaches_the_node_that_runs_and_every_failure_has_its_own_status() {
	let dir = std::env::temp_dir().join(format!("veilway-usage-cli-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let (config, socket, listen) = (dir.join("config.json"), dir.join("veilway.sock"), loop {
		let addr = SocketAddr::from(([127, 0, 0, 1], NEXT_PORT.fetch_add(1, Ordering::Relaxed)));
		if std::net::UdpSocket::bind(addr).is_ok() {break addr}
	});
	// User `a` may use 1000 bytes and the state file has them at 5000, so the node starts with the user out of quota.
	for (name, text) in [
		("config.json", json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&veilway_wg::generate_key()), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": listen.to_string()}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "main", "rules": []},
			"users": [{"name": "a", "exits": "all", "quota_bytes": 1000, "devices": [{"name": "phone", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&veilway_wg::generate_key())), "addresses": ["10.7.0.2"]}]}],
		})),
		("veilway-state.json", json!({"version": 1, "users": {"a": {"used_bytes": 5000, "period_start": 0, "up_bytes": 4000, "up_packets": 3, "down_bytes": 1000, "down_packets": 2}}})),
	] {
		std::fs::write(dir.join(name), text.to_string()).unwrap();
		std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	let (config, socket) = (config.to_str().unwrap(), socket.to_str().unwrap());
	// No node runs yet, so nothing is at the path of its socket.
	let (status, out, err) = reset(&["--config", config, "--user", "a"]).await;
	assert!(status == 4 && out.is_empty() && err.contains("no node answers on the control socket") && err.contains(socket), "{status} {out:?} {err:?}");
	let mut node = Command::new(env!("CARGO_BIN_EXE_veilway")).args(["run", "--config", config]).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
	let deadline = Instant::now() + Duration::from_secs(20);
	while !Path::new(socket).exists() {
		assert!(Instant::now() < deadline && node.try_wait().unwrap().is_none(), "the node did not come up");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	// A user the config does not have, and names no config can have: none of them is taken for another route, and nothing changes.
	for name in ["nobody", "a/../a", "a?x=1", "a b", "%61"] {
		let (status, out, err) = reset(&["--config", config, "--user", name]).await;
		assert!(status == 3 && out.is_empty() && err.contains("has no user named") && saved(&dir)["used_bytes"] == 5000, "{name:?}: {status} {out:?} {err:?}");
	}
	// The reset: the socket is found next to the config file, the count is 0 and the totals are what they were, and the state file has it when the command returns.
	let (status, out, err) = reset(&["--config", config, "--user", "a"]).await;
	assert_eq!((status, out.as_str(), err.as_str()), (0, "user a: usage reset. used_bytes 0, period_start 0, traffic kept\n", ""));
	assert_eq!(saved(&dir), json!({"used_bytes": 0, "period_start": 0, "up_bytes": 4000, "up_packets": 3, "down_bytes": 1000, "down_packets": 2}));
	// With the socket named and no config file anywhere near, and the totals asked for.
	let (status, out, err) = reset(&["--api", socket, "--totals", "--user", "a"]).await;
	assert_eq!((status, out.as_str(), err.as_str()), (0, "user a: usage reset. used_bytes 0, period_start 0, traffic zeroed\n", ""));
	assert_eq!(saved(&dir), json!({"used_bytes": 0, "period_start": 0, "up_bytes": 0, "up_packets": 0, "down_bytes": 0, "down_packets": 0}));
	// A socket this user may not open. Root may open every socket, so there is nothing to see as root.
	if unsafe {libc::geteuid()} != 0 {
		std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o000)).unwrap();
		let (status, out, err) = reset(&["--api", socket, "--user", "a"]).await;
		assert!(status == 5 && out.is_empty() && err.contains("may not be opened by this user"), "{status} {out:?} {err:?}");
		std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	// A node that was killed leaves its socket behind, and nobody answers on it.
	node.kill().await.unwrap();
	let (status, out, err) = reset(&["--api", socket, "--user", "a"]).await;
	assert!(status == 4 && out.is_empty() && err.contains("no node answers on the control socket"), "{status} {out:?} {err:?}");
	// Without a user there is nothing to ask the node, which is the status clap gives every wrong command line.
	assert_eq!(reset(&["--api", socket]).await.0, 2);
	std::fs::remove_dir_all(&dir).unwrap();
}
