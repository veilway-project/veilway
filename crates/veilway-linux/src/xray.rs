//! What Xray needs of Linux ("The binary", "How traffic reaches Xray"): the system user it runs as, and the choice of the server's address among the ones its name resolved to.
//!
//! The user has no login and no home. Its packets are marked by the kill switch's tables (`firewall::xray_marks`), which is how its one connection to the server leaves the machine outside the tunnel without a capability or a socket option.
use crate::firewall::XRAY_USER;
use crate::netlink::Rt;
use crate::networks;
use crate::state::program;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::{Command, Stdio};
use veilway_proto::subscription::payload::{dialable, own};

/// The user id and the group id of a line of `/etc/passwd` for `name`. Lines that do not read are skipped.
fn find(passwd: &str, name: &str) -> Option<(u32, u32)> {
	passwd.lines().filter_map(|line| {
		let mut parts = line.split(':');
		let (user, _, uid, gid) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
		(user == name).then(|| Some((uid.parse().ok()?, gid.parse().ok()?)))?
	}).next()
}

/// The ids of the user Xray runs as, if it exists.
pub fn ids() -> io::Result<Option<(u32, u32)>> {Ok(find(&fs::read_to_string("/etc/passwd")?, XRAY_USER))}

/// The user Xray runs as: made if it is not there (`useradd --system`, no home, no login shell). Root only, and it is the helper that does it, before the kill switch goes in.
pub fn ensure_user() -> io::Result<(u32, u32)> {
	if let Some(found) = ids()? {return Ok(found)}
	let shell = ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"].iter().find(|path| fs::metadata(path).is_ok_and(|meta| meta.is_file())).copied().unwrap_or("/bin/false");
	let output = Command::new(program("useradd")?).args(["--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", shell, XRAY_USER]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
	if !output.status.success() {return Err(io::Error::other(format!("the user {XRAY_USER} could not be made: {}", String::from_utf8_lossy(&output.stderr).trim())))}
	ids()?.ok_or_else(|| io::Error::other(format!("the user {XRAY_USER} is not there after it was made")))
}

/// Takes the user away, with the add-on's removal. Nothing is wrong if it is not there.
pub fn remove_user() -> io::Result<()> {
	if ids()?.is_none() {return Ok(())}
	let output = Command::new(program("userdel")?).arg(XRAY_USER).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
	if output.status.success() {Ok(())} else {Err(io::Error::other(format!("the user {XRAY_USER} could not be removed: {}", String::from_utf8_lossy(&output.stderr).trim())))}
}

/// The addresses of `candidates` that may be dialled: not a form `dialable` refuses, and not inside a network the device is on now. The caller uses the first one.
pub fn usable(candidates: &[IpAddr]) -> io::Result<Vec<IpAddr>> {
	let held = networks::read(&mut Rt::open()?, None)?;
	Ok(candidates.iter().copied().filter(|address| dialable(*address) && !own(*address, &held.networks)).collect())
}

// An address as `/proc/net` writes it: the words of the address in the byte order of the host, in hex.
fn proc_address(hex: &str) -> Option<IpAddr> {
	let word = |at: usize| u32::from_str_radix(hex.get(at..at + 8)?, 16).ok();
	match hex.len() {
		8 => Some(Ipv4Addr::from(word(0)?.to_ne_bytes()).into()),
		32 => {
			let mut octets = [0u8; 16];
			for at in 0..4 {octets[at * 4..at * 4 + 4].copy_from_slice(&word(at * 8)?.to_ne_bytes())}
			Some(Ipv6Addr::from(octets).into())
		}
		_ => None,
	}
}

/// The user ids of the sockets in one table of `/proc/net` (`tcp`, `tcp6`, `udp`, `udp6`) that would be handed a packet for `address`: the port is the same, and the local address is the same, or any address (`0.0.0.0`, `::`), or the IPv4 address written as IPv6. A TCP socket counts only while it listens. Lines that do not read are skipped.
fn holders(table: &str, address: SocketAddr, tcp: bool) -> Vec<u32> {
	table.lines().skip(1).filter_map(|line| {
		let fields: Vec<&str> = line.split_whitespace().collect();
		let (local, state, uid) = (fields.get(1)?, fields.get(3)?, fields.get(7)?);
		let (ip, port) = local.split_once(':')?;
		let ip = match proc_address(ip)? {IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4), other => other};
		let matches = u16::from_str_radix(port, 16).ok()? == address.port() && (ip == address.ip() || ip.is_unspecified());
		(matches && (!tcp || *state == "0A")).then(|| uid.parse().ok())?
	}).collect()
}

/// Whether every socket on `address` is `uid`'s and there is at least one: the TCP listeners of the SOCKS port (`udp` false), or the UDP sockets of a relay (`udp` true). A process of another user that took the port first, or shares it, makes this false whatever it answers. The files are read now: a failure to read the tables is an error, which the caller treats as no.
pub fn listening_as(address: SocketAddr, uid: u32, udp: bool) -> io::Result<bool> {
	let mut found = Vec::new();
	for name in if udp {["udp", "udp6"]} else {["tcp", "tcp6"]} {
		match fs::read_to_string(format!("/proc/net/{name}")) {
			Ok(table) => found.extend(holders(&table, address, !udp)),
			// A system without IPv6 has no second table.
			Err(error) if error.kind() == io::ErrorKind::NotFound && name.ends_with('6') => {}
			Err(error) => return Err(error),
		}
	}
	Ok(!found.is_empty() && found.iter().all(|holder| *holder == uid))
}

#[cfg(test)]
mod tests {
	use super::*;

	const HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

	fn line(local: &str, state: &str, uid: u32) -> String {format!("   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 {uid:5}        0 12345 1 0000000000000000 100 0 0 10 0\n")}

	#[test]
	fn proc_addresses_are_read_in_the_byte_order_of_the_host() {
		assert_eq!(proc_address("0100007F"), Some("127.0.0.1".parse().unwrap()));
		assert_eq!(proc_address("00000000"), Some("0.0.0.0".parse().unwrap()));
		assert_eq!(proc_address("00000000000000000000000001000000"), Some("::1".parse().unwrap()));
		assert_eq!(proc_address("0000000000000000FFFF00000100007F"), Some("::ffff:127.0.0.1".parse().unwrap()));
		assert_eq!(proc_address("B80D0120000000000000000001000000"), Some("2001:db8::1".parse().unwrap()));
		for bad in ["", "0100007", "ZZZZZZZZ", "0100007F00"] {assert_eq!(proc_address(bad), None, "{bad}")}
	}

	#[test]
	fn the_holders_of_a_loopback_port_are_every_socket_that_would_get_its_packets() {
		let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		let table = HEAD.to_owned() + &line("0100007F:1F90", "0A", 998) + &line("0100007F:1F91", "0A", 1000) + &line("00000000:1F90", "0A", 1001) + &line("0100007F:1F90", "01", 1002) + &line("0200007F:1F90", "0A", 1003) + "garbage\n";
		assert_eq!(holders(&table, address, true), [998, 1001], "a listener on the same address and one on any address; not an established connection, not another address, not another port");
		let udp = HEAD.to_owned() + &line("0100007F:1F90", "07", 998) + &line("0100007F:1F90", "01", 1002);
		assert_eq!(holders(&udp, address, false), [998, 1002], "a UDP socket counts in any state");
		let six = HEAD.to_owned() + &line("0000000000000000FFFF00000100007F:1F90", "0A", 1004) + &line("00000000000000000000000001000000:1F90", "0A", 1005) + &line("00000000000000000000000000000000:1F90", "0A", 1006);
		assert_eq!(holders(&six, address, true), [1004, 1006], "an IPv4 address written as IPv6, and any address; ::1 is not 127.0.0.1");
		assert!(holders(HEAD, address, true).is_empty() && holders("", address, true).is_empty());
	}

	#[test]
	fn the_port_is_xrays_only_when_nobody_else_listens_on_it() {
		let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		let ours = holders(&(HEAD.to_owned() + &line("0100007F:1F90", "0A", 998)), address, true);
		assert!(!ours.is_empty() && ours.iter().all(|holder| *holder == 998));
		let shared = holders(&(HEAD.to_owned() + &line("0100007F:1F90", "0A", 998) + &line("00000000:1F90", "0A", 1000)), address, true);
		assert!(!shared.iter().all(|holder| *holder == 998), "a second listener of another user is not Xray's port");
		assert_eq!(listening_as("127.0.0.1:1".parse().unwrap(), 0, false).ok(), Some(false), "nothing listens on port 1");
	}

	#[test]
	fn the_user_is_found_by_its_whole_name_and_a_line_that_does_not_read_is_skipped() {
		let passwd = "root:x:0:0:root:/root:/bin/bash\nbroken\nveilway-xray-old:x:300:300::/:/bin/false\n:x:\nveilway-xray:x:998:997:xray:/nonexistent:/usr/sbin/nologin\nx:x:notanumber:1:::\n";
		assert_eq!(find(passwd, "veilway-xray"), Some((998, 997)));
		assert_eq!(find(passwd, "veilway"), None);
		assert_eq!(find("veilway-xray:x:abc:1:::\n", "veilway-xray"), None);
		assert_eq!(find("", "veilway-xray"), None);
	}
}
