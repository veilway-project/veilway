//! The kill switch: one nftables table with one output chain, installed in a single transaction by `nft -f -`.
//!
//! While it is in force, a packet that is headed for what the tunnel is for leaves the device only through the tunnel's device, or from a socket the engine marked and to an address, protocol and port the signed profile lists for its node. Loopback is let through, and so are the exchanges the link layer needs to keep the network up (DHCP, neighbor discovery and the multicast listener reports that go with it), which the invariant names as the only things the gateway is reached for. The LAN is let through only when the user asked. Whatever is let through, names are not asked outside the tunnel: DNS, DNS over TLS, mDNS and LLMNR (unless the user asked for local names) to anything but the tunnel's resolver are dropped, so that a resolver setting a DHCP server or a router advertisement changes cannot send a query to the LAN.
//!
//! The table is in the kernel, not in the process: it stays when the process dies and goes only when `remove` is called, by a clean stop or by `veilway disconnect`.
//!
//! `nft` is a program of the system, run with a ruleset on its standard input. That is a choice of this part: the rules are text a person can read with `nft list ruleset`, applied atomically, and the program is on every system that has nftables, which is what the kill switch needs anyway.
use crate::routes::LAN;
use crate::state::program;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

pub const TABLE: &str = "veilway_killswitch";

/// An address and port a marked socket may reach, with the protocol of the transport that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {pub ip: IpAddr, pub port: u16, pub tcp: bool}

/// What the chain lets through, and what it drops.
pub struct Rules {
	/// The socket mark of the engine.
	pub mark: u32,
	/// The name of the tunnel's device. It reaches the ruleset between quotes, so it is a valid device name (`tun::valid_name`) before it gets here.
	pub tun: String,
	/// The addresses, ports and protocols the profile lists for the node and its fronts, which marked sockets may reach.
	pub nodes: Vec<Endpoint>,
	/// The destinations that go through the tunnel or nowhere. A default route of a family is a prefix of length 0.
	pub protected: Vec<(IpAddr, u8)>,
	pub lan: bool,
	/// The user asked for names on the local network: mDNS and LLMNR are let through with the LAN.
	pub local_names: bool,
}

impl Rules {
	/// The ruleset as `nft -f` reads it. The first two lines make the script safe to run when the table is there already (a client that crashed), and replace it in one transaction.
	pub fn ruleset(&self) -> String {
		let mut lines = vec![format!("add table inet {TABLE}"), format!("delete table inet {TABLE}"), format!("table inet {TABLE} {{"), "\tchain output {".into(), "\t\ttype filter hook output priority -10; policy accept;".into(), "\t\toifname \"lo\" accept".into(), format!("\t\toifname \"{}\" accept", self.tun)];
		for (v6, family) in [(false, "ip"), (true, "ip6")] {
			for (tcp, protocol) in [(false, "udp"), (true, "tcp")] {
				let found: Vec<String> = self.nodes.iter().filter(|node| node.ip.is_ipv6() == v6 && node.tcp == tcp).map(|node| format!("{} . {}", node.ip, node.port)).collect();
				if !found.is_empty() {lines.push(format!("\t\tmeta mark 0x{:08x} {family} daddr . {protocol} dport {{ {} }} accept", self.mark, found.join(", ")))}
			}
		}
		lines.push("\t\tudp sport 68 udp dport 67 accept".into());
		lines.push("\t\tip6 daddr { ff02::1:2, fe80::/10 } udp sport 546 udp dport 547 accept".into());
		lines.push("\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-report, mld2-listener-report, mld-listener-done } accept".into());
		let ports = if self.local_names {"{ 53, 853 }"} else {"{ 53, 853, 5353, 5355 }"};
		lines.push(format!("\t\tudp dport {ports} counter drop"));
		lines.push(format!("\t\ttcp dport {ports} counter drop"));
		if !self.local_names {lines.push("\t\tudp sport { 5353, 5355 } counter drop".into())}
		// What is tunnelled by network comes before the LAN: a split network inside the LAN's ranges is never let out in clear.
		for (ip, prefix) in self.protected.iter().filter(|(_, prefix)| *prefix > 0) {lines.push(format!("\t\t{} daddr {ip}/{prefix} counter drop", if ip.is_ipv4() {"ip"} else {"ip6"}))}
		if self.lan {
			let (v4, v6): (Vec<_>, Vec<_>) = LAN.iter().partition(|(text, _)| !text.contains(':'));
			lines.push(format!("\t\tip daddr {{ {} }} accept", v4.iter().map(|(text, prefix)| format!("{text}/{prefix}")).collect::<Vec<_>>().join(", ")));
			lines.push(format!("\t\tip6 daddr {{ {} }} accept", v6.iter().map(|(text, prefix)| format!("{text}/{prefix}")).collect::<Vec<_>>().join(", ")));
		}
		for (ip, _) in self.protected.iter().filter(|(_, prefix)| *prefix == 0) {lines.push(format!("\t\tmeta nfproto {} counter drop", if ip.is_ipv4() {"ipv4"} else {"ipv6"}))}
		lines.extend(["\t}".into(), "}".into()]);
		lines.join("\n") + "\n"
	}
}

// Runs `nft` with a script on its standard input, and turns its complaint into the error.
fn nft_with(arguments: &[&str], script: &str) -> io::Result<()> {
	let mut child = Command::new(program("nft")?).args(arguments).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
	child.stdin.take().ok_or_else(|| io::Error::other("no standard input for nft"))?.write_all(script.as_bytes())?;
	let output = child.wait_with_output()?;
	if output.status.success() {Ok(())} else {Err(io::Error::other(format!("nft refused the rules: {}", String::from_utf8_lossy(&output.stderr).trim())))}
}

/// Puts the kill switch in force, replacing one that is there.
pub fn install(rules: &Rules) -> io::Result<()> {nft_with(&["-f", "-"], &rules.ruleset())}

/// Takes it away. Nothing is wrong if it is not there.
pub fn remove() -> io::Result<()> {nft_with(&["-f", "-"], &format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"))}

/// Whether it is in force: None when this user cannot tell, or the system has no `nft`.
pub fn present() -> Option<bool> {
	let output = Command::new(program("nft").ok()?).args(["list", "table", "inet", TABLE]).stdout(Stdio::null()).stderr(Stdio::piped()).output().ok()?;
	if output.status.success() {Some(true)} else if String::from_utf8_lossy(&output.stderr).contains("No such file") {Some(false)} else {None}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn node(ip: &str, port: u16, tcp: bool) -> Endpoint {Endpoint {ip: ip.parse().unwrap(), port, tcp}}

	fn rules() -> Rules {Rules {mark: 0x5657, tun: "vw0".into(), nodes: vec![node("192.0.2.10", 5001, false), node("2001:db8::10", 5001, false), node("198.51.100.7", 443, true)], protected: vec![("0.0.0.0".parse().unwrap(), 0), ("::".parse().unwrap(), 0)], lan: false, local_names: false}}

	// The ruleset is read by the real `nft` when there is one: a rule it refuses fails the run of the gate, and here too where it is installed and may be asked.
	fn accepted_by_nft(rules: &Rules) {
		let Ok(path) = program("nft") else {return};
		let mut child = Command::new(path).args(["-c", "-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
		child.stdin.take().unwrap().write_all(rules.ruleset().as_bytes()).unwrap();
		let output = child.wait_with_output().unwrap();
		let complaint = String::from_utf8_lossy(&output.stderr);
		// A container without CAP_NET_ADMIN cannot ask the kernel, and says so; every other complaint is about the rules.
		assert!(output.status.success() || complaint.contains("Operation not permitted"), "{complaint}\n{}", rules.ruleset());
	}

	#[test]
	fn the_ruleset_replaces_the_table_in_one_transaction() {
		let text = rules().ruleset();
		let lines: Vec<&str> = text.lines().collect();
		assert_eq!(&lines[..3], ["add table inet veilway_killswitch", "delete table inet veilway_killswitch", "table inet veilway_killswitch {"]);
		assert_eq!(lines.last(), Some(&"}"));
		assert!(text.contains("type filter hook output priority -10; policy accept;"));
	}

	#[test]
	fn only_loopback_the_device_and_marked_sockets_to_the_listed_endpoints_get_out() {
		let text = rules().ruleset();
		assert!(text.contains("oifname \"lo\" accept") && text.contains("oifname \"vw0\" accept"));
		assert!(text.contains("meta mark 0x00005657 ip daddr . udp dport { 192.0.2.10 . 5001 } accept"));
		assert!(text.contains("meta mark 0x00005657 ip6 daddr . udp dport { 2001:db8::10 . 5001 } accept"));
		assert!(text.contains("meta mark 0x00005657 ip daddr . tcp dport { 198.51.100.7 . 443 } accept"));
		assert!(!text.contains("ip daddr { 192.0.2.10"), "a marked socket may not reach the node on any port");
		let drops: Vec<usize> = ["meta nfproto ipv4 counter drop", "meta nfproto ipv6 counter drop"].iter().map(|drop| text.find(drop).unwrap()).collect();
		let accepts = [text.find("oifname \"vw0\" accept").unwrap(), text.find("meta mark").unwrap(), text.find("nd-neighbor-solicit").unwrap()];
		assert!(accepts.iter().all(|accept| drops.iter().all(|drop| accept < drop)), "an accept after a drop never matches");
		accepted_by_nft(&rules());
	}

	#[test]
	fn the_link_layer_exchanges_are_let_through_and_nothing_wider() {
		let text = rules().ruleset();
		assert!(text.contains("udp sport 68 udp dport 67 accept"));
		assert!(text.contains("ip6 daddr { ff02::1:2, fe80::/10 } udp sport 546 udp dport 547 accept"));
		assert!(text.contains("nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-report, mld2-listener-report, mld-listener-done"));
		assert!(!text.contains("ct state"));
	}

	#[test]
	fn names_are_not_asked_outside_the_tunnel() {
		let text = rules().ruleset();
		for rule in ["udp dport { 53, 853, 5353, 5355 } counter drop", "tcp dport { 53, 853, 5353, 5355 } counter drop", "udp sport { 5353, 5355 } counter drop"] {assert!(text.contains(rule), "{rule}")}
		let lan = Rules {lan: true, ..rules()}.ruleset();
		assert!(lan.find("udp dport { 53,").unwrap() < lan.find("192.168.0.0/16").unwrap(), "the LAN is let through after the names are dropped");
		let local = Rules {lan: true, local_names: true, ..rules()}.ruleset();
		assert!(local.contains("udp dport { 53, 853 } counter drop") && !local.contains("5353") && !local.contains("5355"));
		accepted_by_nft(&Rules {lan: true, ..rules()});
		accepted_by_nft(&Rules {lan: true, local_names: true, ..rules()});
	}

	#[test]
	fn the_lan_is_let_through_only_when_asked() {
		assert!(!rules().ruleset().contains("192.168.0.0/16"));
		let text = Rules {lan: true, ..rules()}.ruleset();
		assert!(text.contains("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/24 } accept"));
		assert!(text.contains("ip6 daddr { fc00::/7, fe80::/10, ff02::/16 } accept"));
		assert!(text.find("192.168.0.0/16").unwrap() < text.find("meta nfproto ipv4 counter drop").unwrap());
	}

	#[test]
	fn a_split_tunnel_drops_only_what_the_tunnel_is_for_and_before_the_lan_is_let_through() {
		let split = Rules {protected: vec![("10.20.0.0".parse().unwrap(), 16), ("10.7.0.1".parse().unwrap(), 32), ("fd07::1".parse().unwrap(), 128)], lan: true, ..rules()};
		let text = split.ruleset();
		assert!(text.contains("ip daddr 10.20.0.0/16 counter drop") && text.contains("ip daddr 10.7.0.1/32 counter drop") && text.contains("ip6 daddr fd07::1/128 counter drop"));
		assert!(!text.contains("meta nfproto"));
		assert!(text.find("ip daddr 10.20.0.0/16 counter drop").unwrap() < text.find("ip daddr { 10.0.0.0/8").unwrap(), "a split network inside the LAN's ranges would go out in clear");
		accepted_by_nft(&split);
	}

	#[test]
	fn a_profile_with_no_address_of_a_family_leaves_that_family_out_of_the_accepts() {
		let text = Rules {nodes: vec![node("192.0.2.10", 5001, false)], ..rules()}.ruleset();
		assert!(!text.contains("meta mark 0x00005657 ip6"));
		assert!(!text.contains("tcp dport {  }"));
	}
}
