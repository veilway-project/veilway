//! Names are asked through the tunnel and nowhere else. Three things hold that: a catch-all rule of the name resolution policy table (NRPT) that sends every name to the tunnel's resolvers, the same resolvers as the DNS servers of the tunnel's adapter, and the kill switch, which drops every query on port 53 that does not leave through the tunnel (`firewall`).
//!
//! Windows asks every adapter's resolver at once (smart multi-homed name resolution) unless a policy says where a name goes, so the interface setting alone is not enough: the catch-all `.` rule is what wins, and the one thing that is certain to hold even when something undoes it is the filter on port 53.
//!
//! The rule is one in the system's policy table, marked with a comment that is ours, and it is persistent: it stays after a crash, pointing at resolvers that are not there, so names fail and do not leak. `clear` removes it, on a clean stop and in `veilway disconnect`, and only the rules with our comment. The scripts are plain text built here from addresses, never from a name a node chose (invariant 23), and run through the programs of the system's own folder.
use std::net::IpAddr;

/// What marks the rule as this client's.
pub const COMMENT: &str = "Veilway";

fn list(servers: &[IpAddr]) -> String {servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")}

/// The script that makes the catch-all rule. `servers` are addresses and nothing else, so they go in as they are.
pub fn add_script(servers: &[IpAddr]) -> String {format!("Add-DnsClientNrptRule -Namespace '.' -NameServers {} -Comment '{COMMENT}'", list(servers))}

/// The script that makes the rule and only then removes the ones that were there, so that there is no moment without one. It stops at the first error.
pub fn replace_script(servers: &[IpAddr]) -> String {format!("$ErrorActionPreference = 'Stop'; $old = @(Get-DnsClientNrptRule | Where-Object Comment -eq '{COMMENT}'); {}; $old | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}", add_script(servers))}

/// The script that removes every rule that is ours, a stale one of a client that crashed too.
pub fn clear_script() -> String {format!("Get-DnsClientNrptRule | Where-Object Comment -eq '{COMMENT}' | Remove-DnsClientNrptRule -Force")}

/// The script that prints the name servers of each of our rules, one rule to a line.
pub fn list_script() -> String {format!("Get-DnsClientNrptRule | Where-Object Comment -eq '{COMMENT}' | ForEach-Object {{ $_.NameServers -join ',' }}")}

/// Whether what `list_script` printed is exactly one rule, with exactly these servers.
pub fn rule_holds(output: &str, servers: &[IpAddr]) -> bool {
	let lines: Vec<&str> = output.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
	lines.len() == 1 && lines[0] == list(servers)
}

/// The `netsh` calls that set the DNS servers of the adapter, one family at a time. The adapter is named by its index, which is a number, so nothing the user typed reaches the command.
pub fn netsh_calls(index: u32, servers: &[IpAddr]) -> Vec<Vec<String>> {
	let mut calls = Vec::new();
	for (family, v6) in [("ipv4", false), ("ipv6", true)] {
		for (position, server) in servers.iter().filter(|server| server.is_ipv6() == v6).enumerate() {
			let verb = if position == 0 {"set"} else {"add"};
			let mut call: Vec<String> = ["interface", family, verb, "dnsservers", &format!("name={index}")].iter().map(ToString::to_string).collect();
			if position == 0 {call.extend(["static".to_owned(), server.to_string(), "primary".to_owned()])} else {call.extend([server.to_string(), format!("index={}", position + 1)])}
			call.push("validate=no".to_owned());
			calls.push(call);
		}
	}
	calls
}

#[cfg(windows)]
pub use pin::{clear, group_policy, present, Pinned};

#[cfg(windows)]
mod pin {
	use super::*;
	use crate::state::program;
	use std::io;
	use std::os::windows::process::CommandExt;
	use std::process::Command;

	const CREATE_NO_WINDOW: u32 = 0x0800_0000;

	fn run(program: &std::path::Path, args: &[String]) -> io::Result<String> {
		// Held while the process is started, so that Xray's pipes are not inherited by it.
		let _guard = crate::xray::SPAWN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let out = Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW).output().map_err(|error| io::Error::new(error.kind(), format!("{} did not run: {error}", program.display())))?;
		if !out.status.success() {return Err(io::Error::other(format!("{} {} failed: {}{}", program.display(), args.join(" "), String::from_utf8_lossy(&out.stdout).trim(), String::from_utf8_lossy(&out.stderr).trim())))}
		Ok(String::from_utf8_lossy(&out.stdout).into_owned())
	}

	fn powershell(script: &str) -> io::Result<String> {run(&program(r"WindowsPowerShell\v1.0\powershell.exe")?, &["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), script.to_owned()])}

	/// Removes the rules that are ours.
	pub fn clear() -> io::Result<()> {powershell(&clear_script()).map(drop)}

	/// Empties the system's name cache. Lookups made while the kill switch still blocked them are kept there as failures, and without this the names they asked for stay unresolved after the connection is gone, until the user turns the network off and on again.
	pub fn flush() -> io::Result<()> {powershell("Clear-DnsClientCache").map(drop)}

	/// Whether Group Policy sets name resolution rules. Those win over a rule made with the cmdlets, so names would not go through the tunnel, and the connection is refused and not left to leak.
	pub fn group_policy() -> io::Result<bool> {
		use windows_sys::Win32::Foundation::ERROR_SUCCESS;
		use windows_sys::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
		let path: Vec<u16> = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig".encode_utf16().chain(std::iter::once(0)).collect();
		let mut key: HKEY = std::ptr::null_mut();
		// SAFETY: the path is null-terminated and `key` is a live local the call writes to.
		match unsafe {RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key)} {
			ERROR_SUCCESS => {}
			2 => return Ok(false),
			code => return Err(io::Error::from_raw_os_error(code as i32)),
		}
		let mut subkeys = 0u32;
		// SAFETY: the key is open; only the count of subkeys is asked for and every other out parameter is null.
		let code = unsafe {RegQueryInfoKeyW(key, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), &mut subkeys, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())};
		// SAFETY: the key was opened above and is closed once.
		unsafe {RegCloseKey(key)};
		if code != ERROR_SUCCESS {return Err(io::Error::from_raw_os_error(code as i32))}
		Ok(subkeys > 0)
	}

	/// Whether a rule of ours is in force.
	pub fn present() -> io::Result<bool> {powershell(&list_script()).map(|output| output.lines().any(|line| !line.trim().is_empty()))}

	/// The resolver settings this connection put in force.
	pub struct Pinned {servers: Vec<IpAddr>}

	impl Pinned {
		pub fn pin(index: u32, servers: &[IpAddr]) -> io::Result<Self> {
			if servers.is_empty() {return Err(io::Error::other("the profile names no resolver, so names have nowhere to go through the tunnel"))}
			let netsh = program("netsh.exe")?;
			for call in netsh_calls(index, servers) {run(&netsh, &call)?;}
			powershell(&replace_script(servers))?;
			Ok(Self {servers: servers.to_vec()})
		}
		pub fn describe(&self) -> &'static str {"the name resolution policy (NRPT) and the tunnel's adapter"}
		/// Whether the rule is still there and still ours, made again if it is not. True when it had to be.
		pub fn verify(&self) -> io::Result<bool> {
			if rule_holds(&powershell(&list_script())?, &self.servers) {return Ok(false)}
			powershell(&replace_script(&self.servers))?;
			Ok(true)
		}
		/// Takes the rule out. The adapter's own servers go with the adapter.
		pub fn restore(self) -> io::Result<()> {clear()}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn servers() -> Vec<IpAddr> {vec!["10.200.0.1".parse().unwrap(), "fd00::1".parse().unwrap(), "10.200.0.2".parse().unwrap()]}

	#[test]
	fn the_catch_all_rule_names_every_server_and_our_comment() {
		assert_eq!(add_script(&servers()), "Add-DnsClientNrptRule -Namespace '.' -NameServers 10.200.0.1,fd00::1,10.200.0.2 -Comment 'Veilway'");
		assert!(clear_script().contains("Comment -eq 'Veilway'") && !clear_script().contains("Add-"));
	}

	#[test]
	fn the_new_rule_is_made_before_the_old_ones_are_removed_and_errors_stop_it() {
		let script = replace_script(&servers());
		assert!(script.starts_with("$ErrorActionPreference = 'Stop';"));
		let (old, add, remove) = (script.find("$old = @(").unwrap(), script.find("Add-DnsClientNrptRule").unwrap(), script.find("Remove-DnsClientNrptRule").unwrap());
		assert!(old < add && add < remove);
	}

	#[test]
	fn a_rule_holds_only_when_it_is_one_with_the_same_servers() {
		let line = "10.200.0.1,fd00::1,10.200.0.2\r\n";
		assert!(rule_holds(line, &servers()));
		assert!(!rule_holds("", &servers()));
		assert!(!rule_holds("10.200.0.1\r\n", &servers()));
		assert!(!rule_holds(&format!("{line}{line}"), &servers()));
	}

	#[test]
	fn the_adapter_gets_its_servers_per_family_in_order() {
		let calls = netsh_calls(12, &servers());
		assert_eq!(calls.len(), 3);
		assert_eq!(calls[0].join(" "), "interface ipv4 set dnsservers name=12 static 10.200.0.1 primary validate=no");
		assert_eq!(calls[1].join(" "), "interface ipv4 add dnsservers name=12 10.200.0.2 index=2 validate=no");
		assert_eq!(calls[2].join(" "), "interface ipv6 set dnsservers name=12 static fd00::1 primary validate=no");
	}
}
