//! The kill switch: the rules of one pf anchor of our own, `com.apple/000.veilway`, loaded by `pfctl -a com.apple/000.veilway -f -` with the rules on its standard input.
//!
//! The anchor sits under `com.apple`, which the stock `/etc/pf.conf` evaluates as `anchor "com.apple/*"`, so nothing of the system's main ruleset is changed or reloaded. The sub-anchors are evaluated in alphabetical order, and the `000.` puts ours before the system's own (`200.AirDrop`, `250.ApplicationFirewall`, ...), whose `quick` passes would otherwise decide first. `install` checks that the running main ruleset reaches the anchor with no `pass quick` before it (`reach`), and refuses (and takes its rules back) if not, since a kill switch that nothing evaluates is worse than none. Every rule is `quick`, so the first that matches decides, in the order of `Rules::ruleset`: loopback and the tunnel's interface, the nodes the profile lists, DHCP by its ports, neighbor discovery, the ports of names (blocked off the tunnel), the protected networks, the LAN if allowed, and then everything else of the protected families, in and out. States are `if-bound`, so a state made on the tunnel's interface never lets a packet through on the physical one, also after a crash.
//!
//! pf is enabled with `pfctl -E`, which hands back a token, kept in the run directory (`/var/run/veilway`, which a reboot empties, as it does pf's enabled state: a token file that outlived a reboot would make `install` skip the enabling). pf is released with that token and never disabled outright, so another program's use of pf is left as it is. After every install `pfctl -s info` must say `Status: Enabled`, and `verify` (the connection runs it on a timer and on every change of the networks) puts the rules and pf back if something else disabled pf or flushed the anchor. The rules are in the kernel, not in the process: they stay when the process dies, and go only when `remove` is called, by a clean stop or by `veilway disconnect`. A reboot ends them; `persist` puts them back at boot.
//!
//! The first install flushes pf's states, since a connection that was opened before the kill switch is let through by its state and not by the rules. Later installs do not: a flushed state would cut the transport's own stream in the middle.
use crate::state::program;
use ipnet::IpNet;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub const ANCHOR: &str = "com.apple/000.veilway";
/// The name an earlier version used. Its rules are taken away with ours.
const LEGACY_ANCHOR: &str = "com.apple/veilway";
const TOKEN: &str = "pf.token";
const STATE: &str = "keep state (if-bound)";
/// The groups and the broadcast that names are asked on the local network, with the port each is asked on. Only these are let out and in with `local_names`, never a port of the LAN as a whole. The directed broadcast of a subnet is not known here, so NetBIOS reaches only the limited broadcast.
const LOCAL_NAMES: [(&str, u16); 6] = [("224.0.0.251", 5353), ("224.0.0.252", 5355), ("255.255.255.255", 137), ("255.255.255.255", 138), ("ff02::fb", 5353), ("ff02::1:3", 5355)];

/// An address and port the engine's transport may reach, with the protocol of the transport that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {pub ip: IpAddr, pub port: u16, pub tcp: bool}

#[derive(Debug, Clone)]
pub struct Rules {
	/// The tunnel's interface, once there is one. It reaches the ruleset as it is, so it is a valid name (`tun::valid_name`) before it gets here.
	pub tun: Option<String>,
	/// The addresses, ports and protocols the profile lists for the node and its fronts.
	pub nodes: Vec<Endpoint>,
	/// The destinations that go through the tunnel or nowhere. A default route of a family is a prefix of length 0.
	pub protected: Vec<IpNet>,
	/// The subnets the user let apps reach outside the tunnel (`veilway_engine::lan::local`), empty when it is off.
	pub lan: Vec<IpNet>,
	/// The user asked for names on the local network: mDNS, LLMNR and NetBIOS are let through with the LAN, on their groups and ports only.
	pub local_names: bool,
	/// The user id Xray runs as, for a legacy profile: the connections to the nodes are then that user's only, and the client's own (root's) are not let out to them. pf knows the owner of a TCP or UDP socket of this device, which the client's own transport cannot be told by.
	pub xray: Option<u32>,
}

impl Rules {
	/// The ruleset as `pfctl` reads it.
	pub fn ruleset(&self) -> String {
		let lan_of = |v6: bool| self.lan.iter().filter(|net| matches!(net, IpNet::V6(_)) == v6).map(ToString::to_string).collect::<Vec<_>>().join(", ");
		let mut lines = vec!["pass quick on lo0 all".to_owned()];
		// Outbound only: what comes back is the state of what went out. A pass in from the tunnel would let whoever is on the other side of it reach every service of this device that listens, which nothing here asks for.
		if let Some(tun) = &self.tun {lines.push(format!("pass out quick on {tun} all {STATE}"))}
		for node in &self.nodes {lines.push(format!("pass out quick {} proto {} from any to {} port {} {}{STATE}", if node.ip.is_ipv4() {"inet"} else {"inet6"}, if node.tcp {"tcp"} else {"udp"}, node.ip, node.port, self.xray.map_or_else(String::new, |uid| format!("user {uid} "))))}
		// DHCP by its ports and nothing else of those hosts. The server's address is not known for a renewal, which is unicast, so any address is allowed on these ports only. The answers to a broadcast come to an address the question was not sent to, so they cannot be part of a state.
		lines.push(format!("pass out quick inet proto udp from any port 68 to any port 67 {STATE}"));
		lines.push("pass in quick inet proto udp from any port 67 to any port 68 no state".into());
		lines.push(format!("pass out quick inet6 proto udp from fe80::/10 port 546 to {{ ff02::1:2, fe80::/10 }} port 547 {STATE}"));
		lines.push("pass in quick inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546 no state".into());
		// Router and neighbor discovery, and multicast listener reports: without them the link has no IPv6.
		lines.push("pass quick inet6 proto icmp6 all icmp6-type { 133, 134, 135, 136, 130, 131, 132, 143 } no state".into());
		// Names go through the tunnel and only there, with the kill switch on or off. Local names are the LAN's own and only when asked for.
		let ports = if self.local_names {"{ 53, 853 }"} else {"{ 53, 853, 5353, 5355, 137, 138 }"};
		lines.push(format!("block drop quick proto {{ tcp, udp }} from any to any port {ports}"));
		lines.push(format!("block drop quick proto {{ tcp, udp }} from any port {ports} to any"));
		// What is tunnelled by network comes before the LAN: a split network inside the LAN's ranges is never let out in clear.
		for net in self.protected.iter().filter(|net| net.prefix_len() > 0) {
			lines.push(format!("block drop quick from any to {net}"));
			lines.push(format!("block drop quick from {net} to any"));
		}
		if !self.lan.is_empty() {
			for v6 in [false, true].into_iter().filter(|v6| !lan_of(*v6).is_empty()) {lines.push(format!("pass out quick {} from any to {{ {} }} {STATE}", if v6 {"inet6"} else {"inet"}, lan_of(v6)))}
			// A question goes to its group, and the answers that come back to the group come from the LAN. A unicast answer is a packet of the state of the question, or it is dropped.
			if self.local_names {
				for (group, port) in LOCAL_NAMES {
					let v6 = group.contains(':');
					let family = if v6 {"inet6"} else {"inet"};
					lines.push(format!("pass out quick {family} proto udp from any to {group} port {port} {STATE}"));
					if !lan_of(v6).is_empty() {lines.push(format!("pass in quick {family} proto udp from {{ {} }} to {group} port {port} {STATE}", lan_of(v6)))}
				}
			}
		}
		for (v6, family) in [(false, "inet"), (true, "inet6")] {
			if self.protected.iter().any(|net| net.prefix_len() == 0 && net.addr().is_ipv6() == v6) {lines.push(format!("block drop quick {family} all"))}
		}
		lines.join("\n") + "\n"
	}
}

// The token a `pfctl -E` printed: a line with `Token` and a number after the colon. pfctl prints it on its error stream.
pub fn parse_token(output: &str) -> Option<u64> {output.lines().find_map(|line| line.trim().strip_prefix("Token")?.trim_start().strip_prefix(':')?.trim().parse().ok())}

/// Whether `pfctl -s info` says pf is enabled.
pub fn pf_enabled(info: &str) -> bool {info.lines().any(|line| line.trim().strip_prefix("Status:").is_some_and(|status| status.trim_start().starts_with("Enabled")))}

/// Whether the main ruleset (`pfctl -s rules`) evaluates the anchor, by the wildcard of the stock file or by its name, with no `pass quick` before it that would decide first.
pub fn reach(main: &str) -> Result<(), String> {
	for line in main.lines().map(str::trim) {
		if line.starts_with("anchor \"com.apple/*\"") || line.starts_with(&format!("anchor \"{ANCHOR}\"")) {return Ok(())}
		if line.starts_with("pass") && line.contains(" quick") {return Err(format!("the main pf ruleset passes traffic with a quick rule ({line}) before it evaluates the anchor com.apple/*, so the kill switch would not decide. Restore /etc/pf.conf to the system's"))}
	}
	Err("the main pf ruleset does not evaluate the anchor com.apple/*, so the kill switch would not be in force. Restore /etc/pf.conf to the system's".into())
}

// Runs `pfctl` with an optional script on its standard input. Whether it succeeded and what it printed, both streams, since pfctl says some of what matters on the error one.
fn pfctl(arguments: &[&str], input: Option<&str>) -> io::Result<(bool, String)> {
	let mut child = Command::new(program("pfctl")?).args(arguments).stdin(if input.is_some() {Stdio::piped()} else {Stdio::null()}).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
	if let Some(input) = input {child.stdin.take().ok_or_else(|| io::Error::other("no standard input for pfctl"))?.write_all(input.as_bytes())?}
	let output = child.wait_with_output()?;
	Ok((output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))))
}

fn refused(what: &str, output: &str) -> io::Error {io::Error::other(format!("pfctl {what}: {}", output.lines().filter(|line| !line.trim().is_empty()).collect::<Vec<_>>().join("; ")))}

// Whether pf is enabled now.
fn enabled() -> io::Result<bool> {
	let (listed, info) = pfctl(&["-s", "info"], None)?;
	if listed {Ok(pf_enabled(&info))} else {Err(refused("could not read pf's state", &info))}
}

// The token pf was enabled with by an earlier install, if its file is there. The file is root's: one that is a link, or is someone else's, is not believed.
fn saved_token(run_dir: &Path) -> io::Result<Option<u64>> {
	match fs::symlink_metadata(run_dir.join(TOKEN)) {
		Ok(meta) if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 => Ok(fs::read_to_string(run_dir.join(TOKEN))?.trim().parse().ok()),
		Ok(_) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a file of root that only root can read", run_dir.join(TOKEN).display()))),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(error),
	}
}

/// Puts the kill switch in force, replacing the rules that are there. `flush` also drops pf's states, for the first install of a connection.
pub fn install(rules: &Rules, run_dir: &Path, flush: bool) -> io::Result<()> {install_text(&rules.ruleset(), run_dir, flush)}

/// The same for a ruleset that is already text, which is what `persist` restores at boot.
pub fn install_text(ruleset: &str, run_dir: &Path, flush: bool) -> io::Result<()> {
	// A token is believed only while pf is enabled: after a reboot, or after another program's `pfctl -d`, it holds nothing, and a new one is taken.
	let held = enabled()?;
	let saved = saved_token(run_dir)?;
	let took = !(held && saved.is_some());
	if took {
		if let Some(old) = saved {
			let _ = pfctl(&["-X", &old.to_string()], None);
			fs::remove_file(run_dir.join(TOKEN))?;
		}
		let (enabled, output) = pfctl(&["-E"], None)?;
		let token = parse_token(&output).filter(|_| enabled).ok_or_else(|| refused("could not enable pf", &output))?;
		// The file is made closed to others from the start, and an old one that was refused above is never written over.
		fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(run_dir.join(TOKEN)).and_then(|mut file| file.write_all(token.to_string().as_bytes())).inspect_err(|_| {let _ = pfctl(&["-X", &token.to_string()], None);})?;
	}
	let loaded = pfctl(&["-a", ANCHOR, "-f", "-"], Some(ruleset)).and_then(|(loaded, output)| if loaded {Ok(())} else {Err(refused("refused the rules", &output))}).and_then(|()| {
		let (listed, main) = pfctl(&["-s", "rules"], None)?;
		if !listed {return Err(refused("could not list the main ruleset", &main))}
		reach(&main).map_err(io::Error::other)?;
		if enabled()? {Ok(())} else {Err(io::Error::other("pf is not enabled after the rules were loaded, so the kill switch would not be in force"))}
	});
	if let Err(error) = loaded {
		if took {let _ = remove(run_dir);}
		return Err(error);
	}
	if flush {
		let (flushed, output) = pfctl(&["-F", "states"], None)?;
		if !flushed {return Err(refused("could not flush the states", &output))}
	}
	Ok(())
}

/// Checks that the kill switch is in force and puts it back if something took it away (`pfctl -d`, a flushed anchor). True when it had to.
pub fn verify(rules: &Rules, run_dir: &Path) -> io::Result<bool> {
	if present() == Some(true) {return Ok(false)}
	install(rules, run_dir, false)?;
	Ok(true)
}

/// Takes it away: the rules of the anchor (and of the name an earlier version used), and the hold on pf. Nothing is wrong if they are not there.
pub fn remove(run_dir: &Path) -> io::Result<()> {
	let _ = pfctl(&["-a", LEGACY_ANCHOR, "-F", "rules"], None);
	let (flushed, output) = pfctl(&["-a", ANCHOR, "-F", "rules"], None)?;
	if !flushed {return Err(refused("could not remove the rules", &output))}
	let Some(token) = saved_token(run_dir)? else {return Ok(())};
	let (released, output) = pfctl(&["-X", &token.to_string()], None)?;
	// A token pf does not know (after a reboot) is gone already, and its file with it.
	if !released && !output.contains("token") && !output.contains("Token") {return Err(refused("could not release pf", &output))}
	fs::remove_file(run_dir.join(TOKEN))
}

/// Whether the anchor holds rules, whether or not pf is on: None when this user cannot tell, or the system has no `pfctl`.
pub fn loaded() -> Option<bool> {
	let (listed, output) = pfctl(&["-a", ANCHOR, "-s", "rules"], None).ok()?;
	if listed {Some(output.lines().any(|line| line.trim_start().starts_with("block") || line.trim_start().starts_with("pass")))} else {None}
}

/// Whether it is in force: the rules are there and pf is on. None when this user cannot tell.
pub fn present() -> Option<bool> {
	match loaded()? {
		true => enabled().ok(),
		false => Some(false),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn node(ip: &str, port: u16, tcp: bool) -> Endpoint {Endpoint {ip: ip.parse().unwrap(), port, tcp}}

	fn nets(list: &[&str]) -> Vec<IpNet> {list.iter().map(|net| net.parse().unwrap()).collect()}

	fn home() -> Vec<IpNet> {nets(&["192.168.1.0/24", "169.254.0.0/16", "224.0.0.0/24", "fe80::/10", "ff02::/16"])}

	fn full() -> Rules {Rules {tun: None, nodes: vec![node("192.0.2.10", 5001, false), node("2001:db8::10", 5001, false), node("198.51.100.7", 443, true)], protected: nets(&["0.0.0.0/0", "::/0"]), lan: Vec::new(), local_names: false, xray: None}}

	fn position(text: &str, line: &str) -> usize {text.lines().position(|found| found == line).unwrap_or_else(|| panic!("no rule {line:?} in\n{text}"))}

	#[test]
	fn a_full_tunnel_ends_in_a_block_of_both_families_in_and_out() {
		let text = full().ruleset();
		assert!(text.ends_with("block drop quick inet all\nblock drop quick inet6 all\n"), "{text}");
	}

	#[test]
	fn every_state_is_bound_to_the_interface_it_was_made_on() {
		let text = Rules {tun: Some("utun5".into()), lan: home(), local_names: true, ..full()}.ruleset();
		assert!(text.lines().filter(|line| line.contains("keep state")).all(|line| line.ends_with("keep state (if-bound)")), "{text}");
		assert!(!text.contains("floating"));
	}

	#[test]
	fn the_nodes_are_let_out_by_address_port_and_protocol_before_anything_is_blocked() {
		let text = full().ruleset();
		let (udp4, udp6, tcp4) = (position(&text, "pass out quick inet proto udp from any to 192.0.2.10 port 5001 keep state (if-bound)"), position(&text, "pass out quick inet6 proto udp from any to 2001:db8::10 port 5001 keep state (if-bound)"), position(&text, "pass out quick inet proto tcp from any to 198.51.100.7 port 443 keep state (if-bound)"));
		let first_block = text.lines().position(|line| line.starts_with("block")).unwrap();
		assert!(udp4 < first_block && udp6 < first_block && tcp4 < first_block);
	}

	#[test]
	fn with_xray_the_nodes_are_let_out_to_its_user_only_and_the_other_rules_are_the_same() {
		let plain = full().ruleset();
		assert!(!plain.contains(" user "), "a native profile's rules name no user");
		let text = Rules {xray: Some(317), ..full()}.ruleset();
		position(&text, "pass out quick inet proto udp from any to 192.0.2.10 port 5001 user 317 keep state (if-bound)");
		position(&text, "pass out quick inet6 proto udp from any to 2001:db8::10 port 5001 user 317 keep state (if-bound)");
		position(&text, "pass out quick inet proto tcp from any to 198.51.100.7 port 443 user 317 keep state (if-bound)");
		assert_eq!(text.replace(" user 317", ""), plain, "only the rules for the nodes change");
	}

	#[test]
	fn the_tunnel_interface_is_passed_outbound_only_once_it_is_known() {
		assert!(!full().ruleset().contains("utun"));
		let text = Rules {tun: Some("utun5".into()), ..full()}.ruleset();
		assert_eq!(position(&text, "pass quick on lo0 all"), 0);
		assert_eq!(position(&text, "pass out quick on utun5 all keep state (if-bound)"), 1);
		assert!(!text.lines().any(|line| line.contains("utun5") && !line.starts_with("pass out")), "nothing is passed in from the tunnel");
	}

	#[test]
	fn dhcp_is_allowed_by_its_exact_ports_and_neighbor_discovery_by_type() {
		let text = full().ruleset();
		position(&text, "pass out quick inet proto udp from any port 68 to any port 67 keep state (if-bound)");
		position(&text, "pass in quick inet proto udp from any port 67 to any port 68 no state");
		position(&text, "pass out quick inet6 proto udp from fe80::/10 port 546 to { ff02::1:2, fe80::/10 } port 547 keep state (if-bound)");
		position(&text, "pass in quick inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546 no state");
		assert!(text.contains("icmp6-type { 133, 134, 135, 136"));
		assert!(!text.contains("proto icmp ") && !text.contains("igmp"), "no echo or IGMP is let out");
	}

	#[test]
	fn names_are_blocked_off_the_tunnel_in_both_directions_and_local_names_only_when_asked() {
		let text = full().ruleset();
		position(&text, "block drop quick proto { tcp, udp } from any to any port { 53, 853, 5353, 5355, 137, 138 }");
		position(&text, "block drop quick proto { tcp, udp } from any port { 53, 853, 5353, 5355, 137, 138 } to any");
		let lan = Rules {lan: home(), local_names: true, ..full()}.ruleset();
		position(&lan, "block drop quick proto { tcp, udp } from any to any port { 53, 853 }");
		assert!(!Rules {lan: home(), ..full()}.ruleset().contains("5353 keep"), "no local names, no groups");
	}

	#[test]
	fn local_names_reach_their_groups_and_ports_and_not_every_service_of_the_lan() {
		let text = Rules {lan: home(), local_names: true, ..full()}.ruleset();
		position(&text, "pass out quick inet proto udp from any to 224.0.0.251 port 5353 keep state (if-bound)");
		position(&text, "pass in quick inet proto udp from { 192.168.1.0/24, 169.254.0.0/16, 224.0.0.0/24 } to 224.0.0.251 port 5353 keep state (if-bound)");
		position(&text, "pass out quick inet6 proto udp from any to ff02::fb port 5353 keep state (if-bound)");
		position(&text, "pass out quick inet proto udp from any to 255.255.255.255 port 137 keep state (if-bound)");
		position(&text, "pass out quick inet6 proto udp from any to ff02::1:3 port 5355 keep state (if-bound)");
		assert!(text.lines().filter(|line| line.starts_with("pass in") && line.contains("from {")).all(|line| LOCAL_NAMES.iter().any(|(group, port)| line.contains(&format!("to {group} port {port} ")))), "{text}");
		assert!(!text.contains("port 5353 to any") && !text.contains("port 137 to any"), "no answer is let in by its source port");
	}

	#[test]
	fn names_are_blocked_with_the_kill_switch_off_too() {
		let text = Rules {protected: Vec::new(), ..full()}.ruleset();
		position(&text, "block drop quick proto { tcp, udp } from any to any port { 53, 853, 5353, 5355, 137, 138 }");
		assert!(!text.lines().any(|line| line.ends_with(" all") && line.starts_with("block")), "{text}");
	}

	#[test]
	fn the_lan_is_let_out_after_the_names_and_the_protected_networks_and_before_the_final_block() {
		let text = Rules {lan: home(), protected: nets(&["192.168.5.0/24", "0.0.0.0/0", "::/0"]), ..full()}.ruleset();
		let (names, split, lan4, lan6, last) = (position(&text, "block drop quick proto { tcp, udp } from any to any port { 53, 853, 5353, 5355, 137, 138 }"), position(&text, "block drop quick from any to 192.168.5.0/24"), position(&text, "pass out quick inet from any to { 192.168.1.0/24, 169.254.0.0/16, 224.0.0.0/24 } keep state (if-bound)"), position(&text, "pass out quick inet6 from any to { fe80::/10, ff02::/16 } keep state (if-bound)"), position(&text, "block drop quick inet all"));
		assert!(names < split && split < lan4 && lan4 < lan6 && lan6 < last);
	}

	#[test]
	fn the_tunnels_own_addresses_are_blocked_off_it_even_inside_the_lan() {
		let text = Rules {lan: nets(&["10.200.0.0/24"]), protected: nets(&["0.0.0.0/0", "::/0", "10.200.0.1/32", "10.200.0.2/32"]), ..full()}.ruleset();
		let (gateway, lan4) = (position(&text, "block drop quick from any to 10.200.0.1/32"), position(&text, "pass out quick inet from any to { 10.200.0.0/24 } keep state (if-bound)"));
		assert!(gateway < lan4);
	}

	#[test]
	fn no_unsolicited_inbound_is_passed_but_dhcp_and_neighbors() {
		for rules in [full(), Rules {lan: home(), ..full()}, Rules {tun: Some("utun3".into()), ..full()}] {
			let text = rules.ruleset();
			let inbound: Vec<&str> = text.lines().filter(|line| line.starts_with("pass in")).collect();
			assert_eq!(inbound.len(), 2, "{inbound:?}");
			assert!(inbound.iter().all(|line| line.contains("port 67 to") || line.contains("port 547 to")));
		}
	}

	#[test]
	fn a_split_blocks_its_networks_in_and_out_and_no_whole_family() {
		let text = Rules {protected: nets(&["203.0.113.0/24", "10.200.0.1/32"]), ..full()}.ruleset();
		position(&text, "block drop quick from any to 203.0.113.0/24");
		position(&text, "block drop quick from 203.0.113.0/24 to any");
		position(&text, "block drop quick from any to 10.200.0.1/32");
		assert!(!text.contains("inet all"));
	}

	#[test]
	fn the_token_is_found_in_what_pfctl_prints() {
		assert_eq!(parse_token("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\n\nToken : 8472615398\n"), Some(8472615398));
		assert_eq!(parse_token("Token:12"), Some(12));
		assert_eq!(parse_token("pf enabled\n"), None);
		assert_eq!(parse_token("Token : none"), None);
	}

	#[test]
	fn pf_is_enabled_only_when_it_says_so() {
		assert!(pf_enabled("Status: Enabled for 0 days 00:10:02           Debug: Urgent\n"));
		assert!(!pf_enabled("Status: Disabled                               Debug: Urgent\n"));
		assert!(!pf_enabled("pfctl: /dev/pf: Permission denied\n") && !pf_enabled(""));
	}

	#[test]
	fn the_main_ruleset_must_reach_the_anchor_with_no_quick_pass_before_it() {
		assert!(reach("scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n").is_ok());
		assert!(reach("block all\nanchor \"com.apple/000.veilway\" all\n").is_ok());
		assert!(reach("scrub-anchor \"com.apple/*\" all fragment reassemble\npass all\n").is_err());
		assert!(reach("anchor \"other/*\" all\n").is_err());
		assert!(reach("").is_err());
		let early = reach("pass quick on lo0 all\npass in quick proto tcp to port 22\nanchor \"com.apple/*\" all\n").unwrap_err();
		assert!(early.contains("quick rule"), "{early}");
		assert!(reach("pass all\nanchor \"com.apple/*\" all\n").is_ok(), "a pass that is not quick is decided by the quick rules after it");
	}

	#[test]
	fn the_anchor_sorts_before_the_systems_own() {
		assert!(ANCHOR < "com.apple/200.AirDrop" && ANCHOR < "com.apple/250.ApplicationFirewall" && ANCHOR.starts_with("com.apple/"));
		assert_ne!(ANCHOR, LEGACY_ANCHOR);
	}

	#[test]
	fn a_ruleset_has_no_blank_lines_and_ends_with_a_newline() {
		for rules in [full(), Rules {tun: Some("utun2".into()), lan: home(), local_names: true, ..full()}] {
			let text = rules.ruleset();
			assert!(text.ends_with('\n') && !text.contains("\n\n"));
		}
	}
}
