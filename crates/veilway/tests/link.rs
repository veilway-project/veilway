//! `veilway link offer` and `veilway link answer`, as two operators run them: two processes of the binary as it is shipped, which are handed each other's codes and the halves of the fingerprint, and print the entries of the two configs.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;
use veilway_core::config::Config;

fn key(byte: u8) -> String {veilway_wg::encode_key(&[byte; 32])}

fn folder(test: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("veilway-link-{}-{test}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// The node that is dialled, with an inbound for links, and the node that dials, with a user.
fn configs(dir: &Path) -> (Value, Value) {
	let (listener, dialler) = (json!({
		"version": 1, "dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "links", "type": "veilway", "private_key": key(0x12), "address": ["10.9.0.1/24", "fd00:9::1/64"], "transports": [{"type": "udp-obfs", "listen": "0.0.0.0:51821"}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}], "exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}], "routing": {"default": "main"}, "users": []
	}), json!({
		"version": 1, "dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key(0x11), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
		"outbounds": [{"tag": "plain", "type": "direct"}], "exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}], "routing": {"default": "main"},
		"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": key(0x21), "addresses": ["10.7.0.2"]}]}]
	}));
	for (name, doc) in [("listener.json", &listener), ("dialler.json", &dialler)] {std::fs::write(dir.join(name), doc.to_string()).unwrap()}
	std::fs::write(dir.join("transports.json"), json!([{"type": "udp-obfs", "endpoints": ["203.0.113.9:51821"]}, {"type": "udp", "endpoints": ["203.0.113.9:51820"]}]).to_string()).unwrap();
	(listener, dialler)
}

/// One side of a pairing: the process, what it is typed, what it prints, and what it says.
struct Side {child: Child, typed: ChildStdin, printed: BufReader<ChildStdout>, said: Receiver<String>}

impl Side {
	fn start(args: &[&str]) -> Side {
		let mut child = Command::new(env!("CARGO_BIN_EXE_veilway")).arg("link").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
		let (typed, printed, (tell, said)) = (child.stdin.take().unwrap(), BufReader::new(child.stdout.take().unwrap()), channel());
		let errors = BufReader::new(child.stderr.take().unwrap());
		std::thread::spawn(move || errors.lines().map_while(Result::ok).for_each(|line| drop(tell.send(line))));
		Side {child, typed, printed, said}
	}

	fn types(&mut self, line: &str) {writeln!(self.typed, "{line}").unwrap()}

	/// The next line on standard output.
	fn prints(&mut self) -> String {
		let mut line = String::new();
		self.printed.read_line(&mut line).unwrap();
		line.trim().to_string()
	}

	/// What follows `marker` on the first line of standard error that holds it.
	fn says(&self, marker: &str) -> String {
		loop {
			let line = self.said.recv_timeout(Duration::from_secs(20)).unwrap_or_else(|_| panic!("the command never said \"{marker}\""));
			if let Some((_, rest)) = line.split_once(marker) {return rest.trim().to_string()}
		}
	}

	/// The exit status, and everything that was still to be printed.
	fn ends(self) -> (i32, String) {
		let (Side {mut child, typed, mut printed, ..}, mut rest) = (self, String::new());
		drop(typed);
		printed.read_to_string(&mut rest).unwrap();
		(child.wait().unwrap().code().unwrap(), rest)
	}
}

fn with(mut doc: Value, entry: &str, chain: bool) -> Config {
	doc["links"] = json!([serde_json::from_str::<Value>(entry).unwrap()]);
	let tag = doc["links"][0]["tag"].clone();
	if chain {doc["exits"].as_array_mut().unwrap().push(json!({"tag": "far", "backend": {"type": "chain", "links": [tag]}}))}
	let config = Config::parse(doc.to_string().as_bytes()).unwrap();
	let report = config.validate(false);
	assert!(report.errors.is_empty(), "{:#?}", report.errors);
	config
}

#[test]
fn two_operators_pair_a_link_in_either_direction_and_each_gets_the_entry_of_their_node() {
	for reverse in [false, true] {
		let dir = folder(if reverse {"reverse"} else {"forward"});
		let ((listener, dialler), at) = (configs(&dir), |name: &str| dir.join(name).to_str().unwrap().to_string());
		let (config, transports, other) = (at("listener.json"), at("transports.json"), at("dialler.json"));
		let mut args = vec!["offer", "--config", &config, "--tag", "to-dialler", "--inbound", "links", "--name", "the north node", "--address", "10.9.0.2", "--address", "fd00:9::2", "--transports", &transports];
		if reverse {args.extend(["--reverse", "--listener-address", "10.9.0.3", "--listener-address", "fd00:9::3"])}
		let (mut offering, mut answering) = (Side::start(&args), Side::start(&["answer", "--config", &other, "--tag", "to-listener"]));
		let offer = offering.prints();
		assert!(offer.starts_with("vwlink1.") && offer.len() <= 2048, "{offer}");
		answering.types(&offer);
		// The dialler's operator is shown the other operator's label and every address before anything is answered.
		assert_eq!(answering.says("The other operator calls this link:"), "the north node");
		assert!(answering.says("udp-obfs ").starts_with("203.0.113.9:51821"));
		answering.types("yes");
		let answer = answering.prints();
		assert_eq!((answer.len(), answer.starts_with("vwlinka1.")), (123, true));
		offering.types(&answer);
		let (shown, heard) = (offering.says("over a channel you trust:"), answering.says("over a channel you trust:"));
		assert!(shown != heard && shown.len() == 39 && heard.len() == 39, "{shown} / {heard}");
		// A panel's own groups are not taken.
		offering.types(&shown);
		assert!(offering.says("These are not the groups").contains("pair again"));
		// Half of the fingerprint is not taken, and the whole of it is, typed in whatever case.
		offering.types(&heard[..19]);
		assert!(offering.says("These are not the groups").contains("pair again"));
		offering.types(&heard.to_uppercase());
		answering.types(&shown);
		let ((done, entry), (answered, other)) = (offering.ends(), answering.ends());
		assert_eq!((done, answered), (0, 0), "{entry} {other}");
		// Each entry validates in its node's config: the exit half as it is, the entry half behind a chain exit.
		let (listener, dialler) = (with(listener, &entry, reverse), with(dialler, &other, !reverse));
		let (here, there) = (&listener.links[0], &dialler.links[0]);
		assert_eq!((here.id, here.transport_secret, here.identity(), &here.addresses, here.mtu, here.entry(), there.entry()), (there.id, there.transport_secret, there.identity(), &there.addresses, there.mtu, reverse, !reverse));
		assert_eq!((here.public_key.map(|key| key.0), here.inbound.as_deref(), there.peer.as_ref().map(|peer| (peer.inbound_public_key.0, peer.transports.len())), here.mtu), (there.private_key.as_ref().map(|key| veilway_wg::public_key(&key.expose().0)), Some("links"), Some((veilway_wg::public_key(&[0x12; 32]), 2)), Some(1390)));
		let _ = std::fs::remove_dir_all(&dir);
	}
}

#[test]
fn a_pairing_that_is_not_confirmed_prints_no_entry() {
	let dir = folder("declined");
	let (_, at) = (configs(&dir), |name: &str| dir.join(name).to_str().unwrap().to_string());
	let (config, transports, other) = (at("listener.json"), at("transports.json"), at("dialler.json"));
	let offer = |extra: &[&str]| Side::start(&[&["offer", "--config", &config, "--tag", "x", "--inbound", "links", "--name", "north", "--transports", &transports][..], extra].concat());
	// An operator who does not agree to the addresses, and one who types their own groups three times, which are not the other side's.
	let (mut waiting, mut answering) = (offer(&["--address", "10.9.0.2"]), Side::start(&["answer", "--config", &other, "--tag", "y"]));
	answering.types(&waiting.prints());
	answering.types("no");
	assert_eq!(answering.ends(), (2, String::new()));
	// The listener's side is typed nothing more, and gives up without an entry.
	assert_eq!(waiting.ends(), (2, String::new()));
	let (mut offering, mut answering) = (offer(&["--address", "10.9.0.2"]), Side::start(&["answer", "--config", &other, "--tag", "y"]));
	answering.types("not a code");
	assert!(answering.says("This is no offer code").contains("vwlink1."));
	answering.types(&offering.prints());
	answering.types("yes");
	offering.types(&answering.prints());
	let shown = answering.says("over a channel you trust:");
	for _ in 0..3 {answering.types(&shown)}
	assert_eq!((answering.ends(), offering.ends()), ((2, String::new()), (2, String::new())));
	// An offer whose address lies in a pool of the node that pastes it is refused, and terms that make no offer are refused before one is printed.
	let mut clash = offer(&["--address", "10.9.0.2"]);
	std::fs::write(dir.join("clash.json"), std::fs::read_to_string(&other).unwrap().replace("10.7.0", "10.9.0")).unwrap();
	let mut pasting = Side::start(&["answer", "--config", &at("clash.json"), "--tag", "y"]);
	pasting.types(&clash.prints());
	assert!(pasting.says("error:").contains("inside an inbound pool of this node"));
	assert_eq!(pasting.ends(), (2, String::new()));
	for extra in [&["--address", "203.0.113.5"][..], &["--address", "10.9.0.2", "--listener-address", "10.9.0.3"], &["--address", "10.9.0.2", "--reverse"]] {
		let refused = offer(extra);
		assert!(refused.says("error:").contains("these terms make no offer"));
		assert_eq!(refused.ends(), (1, String::new()));
	}
	let _ = std::fs::remove_dir_all(&dir);
}
