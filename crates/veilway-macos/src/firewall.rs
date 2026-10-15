//! The kill switch: the rules of one pf anchor of our own, `com.apple/veilway`, loaded by `pfctl -a com.apple/veilway -f -` with the rules on its standard input.
//!
//! The anchor sits under `com.apple`, which the stock `/etc/pf.conf` evaluates as `anchor "com.apple/*"`, so nothing of the system's main ruleset is changed or reloaded. `install` checks that the running main ruleset does reach the anchor, and refuses (and takes its rules back) if it does not, since a kill switch that nothing evaluates is worse than none. Every rule is `quick`, so the first that matches decides, in the order of `Rules::ruleset`: loopback and the tunnel's interface, the nodes the profile lists, DHCP by its ports, neighbor discovery, the ports of names (blocked off the tunnel), the protected networks, the LAN if allowed, and then everything else of the protected families, in and out.
//!
//! pf is enabled with `pfctl -E`, which hands back a token, and the token is kept in a file of root (`TOKEN`). pf is released with that token and never disabled outright, so another program's use of pf is left as it is. The rules are in the kernel, not in the process: they stay when the process dies, and go only when `remove` is called, by a clean stop or by `veilway disconnect`. They do not survive a reboot (see `lib.rs`).
//!
//! The first install flushes pf's states, since a connection that was opened before the kill switch is let through by its state and not by the rules. Later installs do not: a flushed state would cut the transport's own stream in the middle.
use crate::routes::LAN;
use crate::state::program;
use ipnet::IpNet;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

pub const ANCHOR: &str = "com.apple/veilway";
const TOKEN: &str = "pf.token";

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
	pub lan: bool,
	/// The user asked for names on the local network: mDNS, LLMNR and NetBIOS are let through with the LAN.
	pub local_names: bool,
}

impl Rules {
	/// The ruleset as `pfctl` reads it.
	pub fn ruleset(&self) -> String {
		let mut lines = vec!["pass quick on lo0 all".to_owned()];
		if let Some(tun) = &self.tun {lines.push(format!("pass quick on {tun} all"))}
		for node in &self.nodes {lines.push(format!("pass out quick {} proto {} from any to {} port {} keep state", if node.ip.is_ipv4() {"inet"} else {"inet6"}, if node.tcp {"tcp"} else {"udp"}, node.ip, node.port))}
		// DHCP by its ports and nothing else of those hosts. The server's address is not known for a renewal, which is unicast, so any address is allowed on these ports only.
		lines.push("pass out quick inet proto udp from any port 68 to any port 67 keep state".into());
		lines.push("pass in quick inet proto udp from any port 67 to any port 68 no state".into());
		lines.push("pass out quick inet6 proto udp from fe80::/10 port 546 to { ff02::1:2, fe80::/10 } port 547 keep state".into());
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
		if self.lan {
			for v6 in [false, true] {
				let nets: Vec<&str> = LAN.iter().copied().filter(|net| net.contains(':') == v6).collect();
				lines.push(format!("pass out quick {} from any to {{ {} }} keep state", if v6 {"inet6"} else {"inet"}, nets.join(", ")));
			}
			// The answers to a question to the LAN's names come from the LAN to the port asked from, and are not part of a state.
			if self.local_names {
				let nets: Vec<&str> = LAN.iter().copied().collect();
				lines.push(format!("pass in quick proto udp from {{ {} }} port {{ 5353, 5355, 137, 138 }} to any no state", nets.join(", ")));
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

/// Whether the main ruleset (`pfctl -s rules`) evaluates the anchor, by the wildcard of the stock file or by its name.
pub fn reaches(main: &str) -> bool {main.lines().any(|line| {
	let line = line.trim();
	line.starts_with("anchor \"com.apple/*\"") || line.starts_with(&format!("anchor \"{ANCHOR}\""))
})}

// Runs `pfctl` with an optional script on its standard input. Whether it succeeded and what it printed, both streams, since pfctl says some of what matters on the error one.
fn pfctl(arguments: &[&str], input: Option<&str>) -> io::Result<(bool, String)> {
	let mut child = Command::new(program("pfctl")?).args(arguments).stdin(if input.is_some() {Stdio::piped()} else {Stdio::null()}).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
	if let Some(input) = input {child.stdin.take().ok_or_else(|| io::Error::other("no standard input for pfctl"))?.write_all(input.as_bytes())?}
	let output = child.wait_with_output()?;
	Ok((output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))))
}

fn refused(what: &str, output: &str) -> io::Error {io::Error::other(format!("pfctl {what}: {}", output.lines().filter(|line| !line.trim().is_empty()).collect::<Vec<_>>().join("; ")))}

// The token pf was enabled with by an earlier install, if its file is there. The file is root's: one that is a link, or is someone else's, is not believed.
fn saved_token(state_dir: &Path) -> io::Result<Option<u64>> {
	match fs::symlink_metadata(state_dir.join(TOKEN)) {
		Ok(meta) if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 => Ok(fs::read_to_string(state_dir.join(TOKEN))?.trim().parse().ok()),
		Ok(_) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a file of root that only root can read", state_dir.join(TOKEN).display()))),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(error),
	}
}

/// Puts the kill switch in force, replacing the rules that are there. `flush` also drops pf's states, for the first install of a connection.
pub fn install(rules: &Rules, state_dir: &Path, flush: bool) -> io::Result<()> {
	let took = match saved_token(state_dir)? {
		Some(_) => false,
		None => {
			let (enabled, output) = pfctl(&["-E"], None)?;
			let token = parse_token(&output).filter(|_| enabled).ok_or_else(|| refused("could not enable pf", &output))?;
			// The file is made closed to others from the start, and an old one that was refused above is never written over.
			fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(state_dir.join(TOKEN)).and_then(|mut file| file.write_all(token.to_string().as_bytes())).inspect_err(|_| {let _ = pfctl(&["-X", &token.to_string()], None);})?;
			true
		}
	};
	let loaded = pfctl(&["-a", ANCHOR, "-f", "-"], Some(&rules.ruleset())).and_then(|(loaded, output)| if loaded {Ok(())} else {Err(refused("refused the rules", &output))}).and_then(|()| {
		let (listed, main) = pfctl(&["-s", "rules"], None)?;
		if listed && reaches(&main) {Ok(())} else {Err(io::Error::other("the main pf ruleset does not evaluate the anchor com.apple/*, so the kill switch would not be in force. Restore /etc/pf.conf to the system's"))}
	});
	if let Err(error) = loaded {
		if took {let _ = remove(state_dir);}
		return Err(error);
	}
	if flush {
		let (flushed, output) = pfctl(&["-F", "states"], None)?;
		if !flushed {return Err(refused("could not flush the states", &output))}
	}
	Ok(())
}

/// Takes it away: the anchor's rules, and the hold on pf. Nothing is wrong if they are not there.
pub fn remove(state_dir: &Path) -> io::Result<()> {
	let (flushed, output) = pfctl(&["-a", ANCHOR, "-F", "rules"], None)?;
	if !flushed {return Err(refused("could not remove the rules", &output))}
	let Some(token) = saved_token(state_dir)? else {return Ok(())};
	let (released, output) = pfctl(&["-X", &token.to_string()], None)?;
	// A token pf does not know (after a reboot) is gone already, and its file with it.
	if !released && !output.contains("token") && !output.contains("Token") {return Err(refused("could not release pf", &output))}
	fs::remove_file(state_dir.join(TOKEN))
}

/// Whether it is in force: None when this user cannot tell, or the system has no `pfctl`.
pub fn present() -> Option<bool> {
	let (listed, output) = pfctl(&["-a", ANCHOR, "-s", "rules"], None).ok()?;
	if listed {Some(output.lines().any(|line| line.trim_start().starts_with("block") || line.trim_start().starts_with("pass")))} else {None}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn node(ip: &str, port: u16, tcp: bool) -> Endpoint {Endpoint {ip: ip.parse().unwrap(), port, tcp}}

	fn nets(list: &[&str]) -> Vec<IpNet> {list.iter().map(|net| net.parse().unwrap()).collect()}

	fn full() -> Rules {Rules {tun: None, nodes: vec![node("192.0.2.10", 5001, false), node("2001:db8::10", 5001, false), node("198.51.100.7", 443, true)], protected: nets(&["0.0.0.0/0", "::/0"]), lan: false, local_names: false}}

	fn position(text: &str, line: &str) -> usize {text.lines().position(|found| found == line).unwrap_or_else(|| panic!("no rule {line:?} in\n{text}"))}

	#[test]
	fn a_full_tunnel_ends_in_a_block_of_both_families_in_and_out() {
		let text = full().ruleset();
		assert!(text.ends_with("block drop quick inet all\nblock drop quick inet6 all\n"), "{text}");
	}

	#[test]
	fn the_nodes_are_let_out_by_address_port_and_protocol_before_anything_is_blocked() {
		let text = full().ruleset();
		let (udp4, udp6, tcp4) = (position(&text, "pass out quick inet proto udp from any to 192.0.2.10 port 5001 keep state"), position(&text, "pass out quick inet6 proto udp from any to 2001:db8::10 port 5001 keep state"), position(&text, "pass out quick inet proto tcp from any to 198.51.100.7 port 443 keep state"));
		let first_block = text.lines().position(|line| line.starts_with("block")).unwrap();
		assert!(udp4 < first_block && udp6 < first_block && tcp4 < first_block);
	}

	#[test]
	fn the_tunnel_interface_is_passed_once_it_is_known() {
		assert!(!full().ruleset().contains("utun"));
		let text = Rules {tun: Some("utun5".into()), ..full()}.ruleset();
		assert_eq!(position(&text, "pass quick on lo0 all"), 0);
		assert_eq!(position(&text, "pass quick on utun5 all"), 1);
	}

	#[test]
	fn dhcp_is_allowed_by_its_exact_ports_and_neighbor_discovery_by_type() {
		let text = full().ruleset();
		position(&text, "pass out quick inet proto udp from any port 68 to any port 67 keep state");
		position(&text, "pass in quick inet proto udp from any port 67 to any port 68 no state");
		position(&text, "pass out quick inet6 proto udp from fe80::/10 port 546 to { ff02::1:2, fe80::/10 } port 547 keep state");
		position(&text, "pass in quick inet6 proto udp from fe80::/10 port 547 to fe80::/10 port 546 no state");
		assert!(text.contains("icmp6-type { 133, 134, 135, 136"));
		assert!(!text.contains("proto icmp ") && !text.contains("igmp"), "no echo or IGMP is let out");
	}

	#[test]
	fn names_are_blocked_off_the_tunnel_in_both_directions_and_local_names_only_when_asked() {
		let text = full().ruleset();
		position(&text, "block drop quick proto { tcp, udp } from any to any port { 53, 853, 5353, 5355, 137, 138 }");
		position(&text, "block drop quick proto { tcp, udp } from any port { 53, 853, 5353, 5355, 137, 138 } to any");
		let lan = Rules {lan: true, local_names: true, ..full()}.ruleset();
		position(&lan, "block drop quick proto { tcp, udp } from any to any port { 53, 853 }");
		assert!(lan.contains("port { 5353, 5355, 137, 138 } to any no state"));
		assert!(!Rules {lan: true, ..full()}.ruleset().contains("pass in quick proto udp from { 10"), "no local names, no replies from the LAN");
	}

	#[test]
	fn names_are_blocked_with_the_kill_switch_off_too() {
		let text = Rules {protected: Vec::new(), ..full()}.ruleset();
		position(&text, "block drop quick proto { tcp, udp } from any to any port { 53, 853, 5353, 5355, 137, 138 }");
		assert!(!text.lines().any(|line| line.ends_with(" all") && line.starts_with("block")), "{text}");
	}

	#[test]
	fn the_lan_is_let_out_after_the_names_and_the_protected_networks_and_before_the_final_block() {
		let text = Rules {lan: true, protected: nets(&["192.168.5.0/24", "0.0.0.0/0", "::/0"]), ..full()}.ruleset();
		let (names, split, lan4, lan6, last) = (position(&text, "block drop quick proto { tcp, udp } from any to any port { 53, 853, 5353, 5355, 137, 138 }"), position(&text, "block drop quick from any to 192.168.5.0/24"), position(&text, "pass out quick inet from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/24 } keep state"), position(&text, "pass out quick inet6 from any to { fc00::/7, fe80::/10, ff02::/16 } keep state"), position(&text, "block drop quick inet all"));
		assert!(names < split && split < lan4 && lan4 < lan6 && lan6 < last);
	}

	#[test]
	fn no_unsolicited_inbound_is_passed_but_dhcp_neighbors_and_asked_for_local_names() {
		for rules in [full(), Rules {lan: true, ..full()}] {
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
	fn the_main_ruleset_must_reach_the_anchor() {
		assert!(reaches("scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"));
		assert!(reaches("block all\nanchor \"com.apple/veilway\" all\n"));
		assert!(!reaches("scrub-anchor \"com.apple/*\" all fragment reassemble\npass all\n"));
		assert!(!reaches("anchor \"other/*\" all\n"));
		assert!(!reaches(""));
	}

	#[test]
	fn a_ruleset_has_no_blank_lines_and_ends_with_a_newline() {
		for rules in [full(), Rules {tun: Some("utun2".into()), lan: true, local_names: true, ..full()}] {
			let text = rules.ruleset();
			assert!(text.ends_with('\n') && !text.contains("\n\n"));
		}
	}
}
