//! Names go to the tunnel's resolver and nowhere else. The pin is one entry of the dynamic store of SystemConfiguration, `State:/Network/Service/Veilway/DNS`, set with `scutil` and its commands on the standard input (no shell, nothing built into a command line). `mDNSResponder` reads the store and builds its resolvers from it.
//!
//! The entry names the tunnel's gateways as `ServerAddresses` and one match domain, the empty string, with order 0: a resolver that matches every name and comes before the others, which is how the resolvers of a VPN profile (`NEDNSSettings` with `matchDomains` of `[""]`) are made. After the pin `scutil --dns` is read, and a first resolver that is not ours is told in the log: that is a name that would go elsewhere, and pf blocks port 53 off the tunnel (`firewall`), so it fails and does not leak.
//!
//! The entry has a fixed key, so setting it again replaces it in one step: a resolver of an earlier connection that did not stop is overwritten, and a pin that something else replaced is set again without the entry ever being absent. It is removed on one path only: a stop the user asked for (`Pinned::restore`) or `cleanup`. It lives in memory and is gone after a reboot.
use crate::state::program;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

pub const KEY: &str = "State:/Network/Service/Veilway/DNS";
const SERVERS_MAX: usize = 3;

fn list(servers: &[IpAddr]) -> String {servers.iter().take(SERVERS_MAX).map(ToString::to_string).collect::<Vec<_>>().join(" ")}

/// The `scutil` commands that set the entry, replacing it if it is there.
pub fn set_script(servers: &[IpAddr]) -> String {format!("d.init\nd.add ServerAddresses * {}\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchOrders # 0\nset {KEY}\n", list(servers))}

pub fn remove_script() -> String {format!("remove {KEY}\n")}

pub fn show_script() -> String {format!("show {KEY}\n")}

/// The server addresses a dump of the entry (`show`) lists, in order.
pub fn dumped_servers(output: &str) -> Vec<IpAddr> {
	let (mut inside, mut found) = (false, Vec::new());
	for line in output.lines().map(str::trim) {
		if line.starts_with("ServerAddresses") {inside = true} else if inside && line == "}" {break} else if inside {
			if let Some(address) = line.split_once(" : ").and_then(|(_, value)| value.trim().parse().ok()) {found.push(address)}
		}
	}
	found
}

/// The match domains a dump of the entry lists. scutil takes `""` as an empty string and the dump shows `0 : ` with nothing after the colon; if it had stored the two quote characters the dump would show them, and `rule_holds` refuses that.
pub fn dumped_domains(output: &str) -> Vec<String> {
	let (mut inside, mut found) = (false, Vec::new());
	for line in output.lines().map(str::trim) {
		if line.starts_with("SupplementalMatchDomains") {inside = true} else if inside && line == "}" {break} else if inside {
			if let Some((_, value)) = line.split_once(':') {found.push(value.trim().to_owned())}
		}
	}
	found
}

/// Whether the entry is there with exactly these servers and the one empty match domain.
pub fn rule_holds(output: &str, servers: &[IpAddr]) -> bool {dumped_servers(output) == servers.iter().take(SERVERS_MAX).copied().collect::<Vec<_>>() && dumped_domains(output) == [""]}

// Tells `mDNSResponder` to read its configuration and drop its cache, so that a name asked before the pin (or after its removal) is not answered from the old resolver. Not being able to is told and not an error.
fn flush_cache() {
	match program("killall").and_then(|path| Command::new(path).args(["-HUP", "mDNSResponder"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status()) {
		Ok(status) if status.success() => {}
		Ok(status) => tracing::warn!(%status, "mDNSResponder was not told to flush its cache"),
		Err(error) => tracing::warn!(%error, "mDNSResponder was not told to flush its cache"),
	}
}

/// The name servers of the first resolver of the default configuration in the output of `scutil --dns`, which is the one a name that matches no domain of another goes to.
pub fn first_resolver(output: &str) -> Vec<IpAddr> {
	let (mut inside, mut found) = (false, Vec::new());
	for line in output.lines().map(str::trim) {
		if line.starts_with("DNS configuration (for scoped") {break}
		if line.starts_with("resolver #") {
			if inside {break}
			inside = true;
		} else if inside && line.starts_with("nameserver[") {
			if let Some(address) = line.split_once(" : ").and_then(|(_, value)| value.trim().parse().ok()) {found.push(address)}
		}
	}
	found
}

// Runs `scutil` with commands on its standard input. Whether it succeeded and what it printed.
fn scutil(arguments: &[&str], input: &str) -> io::Result<(bool, String)> {
	let mut child = Command::new(program("scutil")?).args(arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
	child.stdin.take().ok_or_else(|| io::Error::other("no standard input for scutil"))?.write_all(input.as_bytes())?;
	let output = child.wait_with_output()?;
	Ok((output.status.success(), format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))))
}

fn run(script: &str) -> io::Result<String> {
	let (done, output) = scutil(&[], script)?;
	// scutil exits 0 on a command it did not understand and says so in its output.
	if done && !output.contains("Unknown") && !output.contains("Failed") {Ok(output)} else {Err(io::Error::other(format!("scutil: {}", output.trim())))}
}

// What the store holds under our key. A key that is not there is not an error: scutil says "No such key" and nothing in the dump parses.
fn dump() -> io::Result<String> {Ok(scutil(&[], &show_script())?.1)}

/// Removes the entry. Nothing is wrong if it is not there.
pub fn clear() -> io::Result<()> {
	if !present()? {return Ok(())}
	run(&remove_script())?;
	flush_cache();
	Ok(())
}

/// Whether an entry of ours is in the store, from an earlier connection or this one.
pub fn present() -> io::Result<bool> {Ok(!dumped_servers(&dump()?).is_empty())}

/// The pin, held for the connection.
pub struct Pinned {servers: Vec<IpAddr>}

impl Pinned {
	pub fn pin(servers: &[IpAddr]) -> io::Result<Self> {
		if servers.is_empty() {return Err(io::Error::new(io::ErrorKind::InvalidInput, "the profile names no resolver"))}
		run(&set_script(servers))?;
		let pinned = Self {servers: servers.to_vec()};
		if !pinned.holds()? {return Err(io::Error::other("the resolver entry was set and is not in the store as it was meant to be (the servers, and one empty match domain)"))}
		flush_cache();
		match scutil(&["--dns"], "") {
			Ok((true, dump)) if first_resolver(&dump) != pinned.servers.iter().take(SERVERS_MAX).copied().collect::<Vec<_>>() => tracing::warn!(first = ?first_resolver(&dump), "the first resolver of the system is not the tunnel's, so some names may not resolve while pf blocks the port"),
			Ok(_) => {}
			Err(error) => tracing::warn!(%error, "the system's resolvers could not be listed"),
		}
		Ok(pinned)
	}
	pub fn describe(&self) -> &'static str {"the system's resolver configuration (SystemConfiguration)"}
	fn holds(&self) -> io::Result<bool> {Ok(rule_holds(&dump()?, &self.servers))}
	/// Checks the entry and sets it again if it is gone or changed. True when it had to.
	pub fn verify(&self) -> io::Result<bool> {
		if self.holds()? {return Ok(false)}
		run(&set_script(&self.servers))?;
		flush_cache();
		Ok(true)
	}
	pub fn restore(self) -> io::Result<()> {clear()}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn servers() -> Vec<IpAddr> {vec!["10.200.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]}

	#[test]
	fn the_entry_is_set_in_one_script_with_its_key_and_the_match_all_domain() {
		let script = set_script(&servers());
		assert_eq!(script, "d.init\nd.add ServerAddresses * 10.200.0.1 fd00::1\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchOrders # 0\nset State:/Network/Service/Veilway/DNS\n");
		assert_eq!(remove_script(), "remove State:/Network/Service/Veilway/DNS\n");
		assert!(show_script().starts_with("show State:/Network/Service/Veilway/DNS"));
	}

	#[test]
	fn no_more_than_three_servers_are_pinned() {
		let many: Vec<IpAddr> = (1..=5).map(|last| format!("10.200.0.{last}").parse().unwrap()).collect();
		assert!(set_script(&many).contains("10.200.0.1 10.200.0.2 10.200.0.3\n"));
		assert!(!set_script(&many).contains("10.200.0.4"));
	}

	const DUMP: &str = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 10.200.0.1\n    1 : fd00::1\n  }\n  SupplementalMatchDomains : <array> {\n    0 : \n  }\n  SupplementalMatchOrders : <array> {\n    0 : 0\n  }\n}\n";

	#[test]
	fn the_dump_of_the_entry_is_read_back() {
		assert_eq!(dumped_servers(DUMP), servers());
		assert!(rule_holds(DUMP, &servers()));
		assert!(!rule_holds(DUMP, &servers()[..1]));
		assert!(!rule_holds("  No such key\n", &servers()));
		assert!(!rule_holds(&DUMP.replace("10.200.0.1", "9.9.9.9"), &servers()));
		assert!(dumped_servers("").is_empty());
		assert_eq!(dumped_domains(DUMP), [""]);
		assert!(!rule_holds(&DUMP.replace("0 : \n  }\n  SupplementalMatchOrders", "0 : \"\"\n  }\n  SupplementalMatchOrders"), &servers()), "two literal quote characters are not an empty string");
	}

	#[test]
	fn the_first_resolver_of_the_default_configuration_is_read() {
		let ours = "DNS configuration\n\nresolver #1\n  nameserver[0] : 10.200.0.1\n  nameserver[1] : fd00::1\n  flags    : Supplemental, Request A records\n  order    : 0\n\nresolver #2\n  search domain[0] : lan\n  nameserver[0] : 192.168.1.1\n  order    : 200000\n\nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n  if_index : 4 (en0)\n";
		assert_eq!(first_resolver(ours), servers());
		let other = ours.replace("resolver #1\n  nameserver[0] : 10.200.0.1\n  nameserver[1] : fd00::1", "resolver #1\n  nameserver[0] : 192.168.1.1");
		assert_eq!(first_resolver(&other), vec!["192.168.1.1".parse::<IpAddr>().unwrap()]);
		assert!(first_resolver("DNS configuration (for scoped queries)\nresolver #1\n  nameserver[0] : 1.1.1.1\n").is_empty());
		assert!(first_resolver("").is_empty());
	}

	#[test]
	fn nothing_is_pinned_without_a_resolver() {
		assert!(Pinned::pin(&[]).is_err());
	}
}
