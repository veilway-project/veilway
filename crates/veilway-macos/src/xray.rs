//! What Xray needs of macOS ("The binary", "How traffic reaches Xray"): the account it runs as, the choice of the server's address among the ones its name resolved to, the name of the physical interface its own socket is kept on, and the look-up of who holds a loopback port.
//!
//! The spec leaves open whether macOS makes an account for Xray or uses `nobody`. This layer makes one, `_veilwayxray`: `nobody` is shared with other daemons, and a flaw in Xray would reach their files. The account has no login, no home and a hidden record, in the range of ids that the system leaves to services (300 to 399), and is made by `dscl` the way the system's own service accounts are. Its id is free in both lists, users and groups, and the same number is the id of its group.
//!
//! Xray's socket stays out of the tunnel with `sockopt.interface` in the document (`IP_BOUND_IF` inside Xray), set to the interface the engine's own sockets are bound to. The kill switch lets the account's connection to the server out by address, port and protocol, and only that account's (`firewall::Rules::xray`).
use crate::state::program;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use veilway_proto::subscription::payload::{dialable, own};

/// The account Xray runs as. It reaches `dscl` as an argument and never a script.
pub const XRAY_USER: &str = "_veilwayxray";
/// The ids the system leaves to the accounts of services that are not its own.
const IDS: std::ops::Range<u32> = 300..400;

/// The user id and the group id from the answer of `dscl . -read /Users/<name> UniqueID PrimaryGroupID`. Lines that do not read are skipped, and both must be there.
pub fn ids_from(output: &str) -> Option<(u32, u32)> {
	let field = |name: &str| output.lines().find_map(|line| line.trim().strip_prefix(name)?.strip_prefix(':')?.trim().parse::<u32>().ok());
	Some((field("UniqueID")?, field("PrimaryGroupID")?))
}

/// The lowest id of the range that neither listing names. Each listing is the answer of `dscl . -list /Users UniqueID` or `/Groups PrimaryGroupID`: a name and a number on a line, and the number is the last word.
pub fn free_id(users: &str, groups: &str) -> Option<u32> {
	let taken: Vec<u32> = users.lines().chain(groups.lines()).filter_map(|line| line.split_whitespace().last()?.parse().ok()).collect();
	IDS.into_iter().find(|id| !taken.contains(id))
}

/// The calls of `dscl` (after the `.` datasource) that make the group and then the user. The shell is `/usr/bin/false` and the home `/var/empty`, which is how the system's accounts for daemons are, the password is `*` (no password can match) and the record is hidden from the login window.
pub fn account_steps(id: u32) -> Vec<Vec<String>> {
	let (group, user, id) = (format!("/Groups/{XRAY_USER}"), format!("/Users/{XRAY_USER}"), id.to_string());
	let (group, user, id) = (group.as_str(), user.as_str(), id.as_str());
	[[group, "RealName", "Veilway Xray"], [group, "PrimaryGroupID", id], [group, "Password", "*"], [user, "RealName", "Veilway Xray"], [user, "UniqueID", id], [user, "PrimaryGroupID", id], [user, "UserShell", "/usr/bin/false"], [user, "NFSHomeDirectory", "/var/empty"], [user, "Password", "*"], [user, "IsHidden", "1"]]
		.iter().map(|step| ["-create", step[0], step[1], step[2]].iter().map(|word| (*word).to_owned()).collect()).collect()
}

// Runs `dscl` on the local datasource and gives what it printed. A failure carries what it said.
fn dscl(arguments: &[String]) -> io::Result<String> {
	let output = Command::new(program("dscl")?).arg(".").args(arguments).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;
	if output.status.success() {Ok(String::from_utf8_lossy(&output.stdout).into_owned())} else {Err(io::Error::other(String::from_utf8_lossy(&output.stderr).trim().to_owned()))}
}

fn words(arguments: &[&str]) -> Vec<String> {arguments.iter().map(|word| (*word).to_owned()).collect()}

/// The ids of the account Xray runs as, if it exists. A record that is not there is a failure of `dscl`, and is read as none. One that is there with ids outside 300 to 399, or a group id other than the user id, is an error.
pub fn ids() -> io::Result<Option<(u32, u32)>> {
	let Some(found) = dscl(&words(&["-read", &format!("/Users/{XRAY_USER}"), "UniqueID", "PrimaryGroupID"])).ok().as_deref().and_then(ids_from) else {return Ok(None)};
	// A record that is there already is believed only if it is the kind this layer makes: a service id, and the same number for the group. Anything else could be root or a real user.
	if found.0 != found.1 || !IDS.contains(&found.0) {return Err(io::Error::other(format!("the account {XRAY_USER} exists with ids {} and {}, which are not the service ids this layer makes it with. Remove it as an administrator or do not connect", found.0, found.1)))}
	Ok(Some(found))
}

/// The account Xray runs as: made if it is not there. Root only, and it is the helper that does it, before the kill switch goes in.
pub fn ensure_user() -> io::Result<(u32, u32)> {
	if let Some(found) = ids()? {return Ok(found)}
	let id = free_id(&dscl(&words(&["-list", "/Users", "UniqueID"]))?, &dscl(&words(&["-list", "/Groups", "PrimaryGroupID"]))?).ok_or_else(|| io::Error::other(format!("no id from {} to {} is free for the account {XRAY_USER}", IDS.start, IDS.end - 1)))?;
	for step in account_steps(id) {dscl(&step).map_err(|error| io::Error::other(format!("the account {XRAY_USER} could not be made: {error}")))?;}
	ids()?.ok_or_else(|| io::Error::other(format!("the account {XRAY_USER} is not there after it was made")))
}

/// Takes the account and its group away, with the add-on's removal. Nothing is wrong if they are not there.
pub fn remove_user() -> io::Result<()> {
	for record in [format!("/Users/{XRAY_USER}"), format!("/Groups/{XRAY_USER}")] {
		if dscl(&words(&["-read", &record, "RecordName"])).is_ok() {dscl(&["-delete".to_owned(), record]).map_err(|error| io::Error::other(format!("the account {XRAY_USER} could not be removed: {error}")))?;}
	}
	Ok(())
}

#[cfg(target_os = "macos")]
/// The addresses of `candidates` that may be dialled: not a form `dialable` refuses, and not inside a network the device is on now. The caller uses the first one.
pub fn usable(candidates: &[IpAddr]) -> io::Result<Vec<IpAddr>> {
	let held = crate::networks::read(None)?;
	Ok(candidates.iter().copied().filter(|address| dialable(*address) && !own(*address, &held.networks)).collect())
}

#[cfg(target_os = "macos")]
/// The physical interface the engine's sockets are bound to now, by its name: what Xray's document names, and what the supervisor restarts it for when it changes. None when the device has no network outside the tunnel.
pub fn physical() -> io::Result<Option<String>> {crate::networks::read(None)?.interface.map(name).transpose()}

#[cfg(target_os = "macos")]
/// The name of the interface with this index (`en0`).
pub fn name(index: u32) -> io::Result<String> {
	let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
	// SAFETY: the buffer is live and `IF_NAMESIZE` bytes long, which is what the call writes at most, with a terminating NUL.
	if unsafe {libc::if_indextoname(index, buffer.as_mut_ptr())}.is_null() {return Err(io::Error::last_os_error())}
	// SAFETY: on success the buffer holds a NUL-terminated string.
	Ok(unsafe {std::ffi::CStr::from_ptr(buffer.as_ptr())}.to_string_lossy().into_owned())
}

/// A socket of a process, as the system lists it: `tcp` for a TCP socket that listens, else a UDP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {pub pid: u32, pub ip: IpAddr, pub port: u16, pub tcp: bool}

// Offsets in the answer of `proc_pidfdinfo` for a socket (`struct socket_fdinfo` of `<sys/proc_info.h>`): the 24 bytes of `proc_fileinfo`, then `socket_info`, whose protocol is at 156, whose kind is at 232 and whose union starts at 240. `in_sockinfo` is the start of that union (`tcp_sockinfo` begins with it): the local port at 4, the IP version flags at 24, the foreign address at 32 and the local one at 48 as a union of 16 bytes whose IPv4 address is the last four. The state of a TCP socket is at 80.
const FILE: usize = 24;
const PROTOCOL: usize = FILE + 156;
const KIND: usize = FILE + 232;
const INFO: usize = FILE + 240;
const LOCAL_PORT: usize = INFO + 4;
const VERSIONS: usize = INFO + 24;
const LOCAL_ADDRESS: usize = INFO + 48;
const TCP_STATE: usize = INFO + 80;
const SOCKET_INFO_LEN: usize = INFO + 120;
const KIND_IN: i32 = 1;
const KIND_TCP: i32 = 2;
const STATE_LISTEN: i32 = 1;
const IPPROTO_UDP: i32 = 17;

/// The socket from one answer of `proc_pidfdinfo`, or None for a socket that is not a TCP socket that listens or a UDP one, or an answer too short to read.
pub fn socket_from(info: &[u8], pid: u32) -> Option<Bound> {
	if info.len() < SOCKET_INFO_LEN {return None}
	let int = |at: usize| i32::from_ne_bytes(info[at..at + 4].try_into().unwrap());
	let tcp = match int(KIND) {
		KIND_TCP if int(TCP_STATE) == STATE_LISTEN => true,
		KIND_IN if int(PROTOCOL) == IPPROTO_UDP => false,
		_ => return None,
	};
	// The port is kept in network order in the low half of an int.
	let port = u16::from_be(int(LOCAL_PORT) as u16);
	let (versions, address) = (info[VERSIONS], &info[LOCAL_ADDRESS..LOCAL_ADDRESS + 16]);
	let v4 = IpAddr::from(<[u8; 4]>::try_from(&address[12..16]).unwrap());
	// A socket for both families carries both flags and an address of zeros, which is the unspecified one either way.
	let ip = if versions & 2 != 0 && address.iter().any(|byte| *byte != 0) && versions & 1 == 0 {IpAddr::from(<[u8; 16]>::try_from(address).unwrap())} else {v4};
	Some(Bound {pid, ip: match ip {IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4), other => other}, port, tcp})
}

/// The processes of the sockets in `found` that would be handed a packet for `address`: the port is the same, and the local address is the same or any address (`0.0.0.0`, `::`), for TCP (`udp` false) or UDP.
pub fn holders(found: &[Bound], address: SocketAddr, udp: bool) -> Vec<u32> {
	found.iter().filter(|socket| socket.tcp != udp && socket.port == address.port() && (socket.ip == address.ip() || socket.ip.is_unspecified())).map(|socket| socket.pid).collect()
}

/// Every TCP socket that listens and every UDP socket of every process, as `libproc` lists them. A process that ended or whose descriptors cannot be read since the list was made is left out; the caller is root, so no live process is.
#[cfg(target_os = "macos")]
fn sockets() -> io::Result<Vec<Bound>> {
	// SAFETY: a null buffer of size 0 asks how many processes there are.
	let wanted = unsafe {libc::proc_listallpids(std::ptr::null_mut(), 0)};
	if wanted <= 0 {return Err(io::Error::last_os_error())}
	// Room for the processes that start between the two calls. Both calls count processes, and not bytes.
	let mut pids = vec![0 as libc::pid_t; wanted as usize + 64];
	// SAFETY: the buffer is live and its size in bytes is passed.
	let got = unsafe {libc::proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int)};
	if got <= 0 {return Err(io::Error::last_os_error())}
	pids.truncate(got as usize);
	let mut found = Vec::new();
	for pid in pids.into_iter().filter(|pid| *pid > 0) {
		// SAFETY: as above, a null buffer asks for the size of the list of descriptors.
		let wanted = unsafe {libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)};
		if wanted <= 0 {continue}
		let mut fds = vec![libc::proc_fdinfo {proc_fd: 0, proc_fdtype: 0}; wanted as usize / std::mem::size_of::<libc::proc_fdinfo>() + 16];
		// SAFETY: the buffer is live and its size in bytes is passed.
		let got = unsafe {libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), (fds.len() * std::mem::size_of::<libc::proc_fdinfo>()) as libc::c_int)};
		if got <= 0 {continue}
		fds.truncate(got as usize / std::mem::size_of::<libc::proc_fdinfo>());
		for fd in fds.iter().filter(|fd| fd.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32) {
			let mut info = [0u8; 1024];
			// SAFETY: the buffer is live and its size is passed; 3 is `PROC_PIDFDSOCKETINFO`, which writes a `socket_fdinfo` of 792 bytes.
			let got = unsafe {libc::proc_pidfdinfo(pid, fd.proc_fd, 3, info.as_mut_ptr().cast(), info.len() as libc::c_int)};
			if got > 0 {found.extend(socket_from(&info[..got as usize], pid as u32))}
		}
	}
	Ok(found)
}

/// Whether every socket on `address` is process `pid`'s and there is at least one: the TCP listeners of the SOCKS port (`udp` false), or the UDP sockets of a relay (`udp` true). A process that took the port first, or shares it, makes this false whatever it answers. A failure to list is an error, which the caller treats as no.
#[cfg(target_os = "macos")]
pub fn listening_as(address: SocketAddr, pid: u32, udp: bool) -> io::Result<bool> {
	let found = holders(&sockets()?, address, udp);
	Ok(!found.is_empty() && found.iter().all(|holder| *holder == pid))
}

#[cfg(test)]
mod tests {
	use super::*;

	// A socket as `proc_pidfdinfo` would answer, built with the offsets above.
	fn info(kind: i32, protocol: i32, state: i32, port: u16, versions: u8, address: [u8; 16]) -> Vec<u8> {
		let mut bytes = vec![0u8; 792];
		bytes[KIND..KIND + 4].copy_from_slice(&kind.to_ne_bytes());
		bytes[PROTOCOL..PROTOCOL + 4].copy_from_slice(&protocol.to_ne_bytes());
		bytes[TCP_STATE..TCP_STATE + 4].copy_from_slice(&state.to_ne_bytes());
		bytes[LOCAL_PORT..LOCAL_PORT + 4].copy_from_slice(&i32::from(port.to_be()).to_ne_bytes());
		bytes[VERSIONS] = versions;
		bytes[LOCAL_ADDRESS..LOCAL_ADDRESS + 16].copy_from_slice(&address);
		bytes
	}

	fn v4(octets: [u8; 4]) -> [u8; 16] {
		let mut address = [0u8; 16];
		address[12..].copy_from_slice(&octets);
		address
	}

	#[test]
	fn the_offsets_are_those_of_socket_fdinfo() {
		assert_eq!((PROTOCOL, KIND, INFO), (180, 256, 264));
		assert_eq!(SOCKET_INFO_LEN, 384);
	}

	#[test]
	fn the_ids_are_read_from_the_answer_of_dscl_and_both_must_be_there() {
		assert_eq!(ids_from("PrimaryGroupID: 301\nUniqueID: 300\n"), Some((300, 301)));
		assert_eq!(ids_from("UniqueID: 300\n"), None);
		assert_eq!(ids_from("UniqueID: x\nPrimaryGroupID: 1\n"), None);
		assert_eq!(ids_from(""), None);
	}

	#[test]
	fn the_id_is_the_lowest_free_one_in_both_listings_and_none_when_the_range_is_full() {
		let users = "root                    0\n_veilwayxray            300\nalice                   501\n_x                      301\n";
		let groups = "wheel                   0\n_y                      302\nbroken\n";
		assert_eq!(free_id(users, groups), Some(303));
		let full: String = IDS.map(|id| format!("u{id} {id}\n")).collect();
		assert_eq!(free_id(&full, ""), None);
		assert_eq!(free_id("", ""), Some(300));
	}

	#[test]
	fn the_account_is_a_group_and_a_user_with_one_id_no_login_no_home_and_no_password() {
		let steps = account_steps(317);
		assert!(steps.iter().all(|step| step[0] == "-create" && step.len() == 4));
		let at = |record: &str, key: &str| steps.iter().find(|step| step[1] == record && step[2] == key).map(|step| step[3].as_str());
		assert_eq!(at("/Users/_veilwayxray", "UniqueID"), Some("317"));
		assert_eq!(at("/Users/_veilwayxray", "PrimaryGroupID"), Some("317"));
		assert_eq!(at("/Groups/_veilwayxray", "PrimaryGroupID"), Some("317"));
		assert_eq!(at("/Users/_veilwayxray", "UserShell"), Some("/usr/bin/false"));
		assert_eq!(at("/Users/_veilwayxray", "NFSHomeDirectory"), Some("/var/empty"));
		assert_eq!((at("/Users/_veilwayxray", "Password"), at("/Users/_veilwayxray", "IsHidden")), (Some("*"), Some("1")));
		let group = steps.iter().position(|step| step[1].starts_with("/Groups")).unwrap();
		let user = steps.iter().position(|step| step[1].starts_with("/Users")).unwrap();
		assert!(group < user, "the group is there before the user names it");
	}

	#[test]
	fn a_tcp_listener_and_a_udp_socket_are_read_and_nothing_else_is() {
		let listener = socket_from(&info(KIND_TCP, 6, STATE_LISTEN, 8080, 1, v4([127, 0, 0, 1])), 40).unwrap();
		assert_eq!(listener, Bound {pid: 40, ip: "127.0.0.1".parse().unwrap(), port: 8080, tcp: true});
		let udp = socket_from(&info(KIND_IN, IPPROTO_UDP, 0, 53, 1, v4([0, 0, 0, 0])), 41).unwrap();
		assert_eq!((udp.port, udp.tcp, udp.ip.is_unspecified()), (53, false, true));
		assert_eq!(socket_from(&info(KIND_TCP, 6, 4, 8080, 1, v4([127, 0, 0, 1])), 40), None, "a TCP socket that is not listening");
		assert_eq!(socket_from(&info(KIND_IN, 1, 0, 8080, 1, v4([127, 0, 0, 1])), 40), None, "a raw socket");
		assert_eq!(socket_from(&info(3, 0, 0, 8080, 1, v4([127, 0, 0, 1])), 40), None, "a socket of another kind");
		assert_eq!(socket_from(&[0u8; 100], 40), None, "an answer too short");
	}

	#[test]
	fn the_address_is_the_ipv6_one_only_when_the_socket_is_only_ipv6() {
		let mut six = [0u8; 16];
		six[15] = 1;
		let only6 = socket_from(&info(KIND_TCP, 6, STATE_LISTEN, 80, 2, six), 1).unwrap();
		assert_eq!(only6.ip, "::1".parse::<IpAddr>().unwrap());
		let both = socket_from(&info(KIND_TCP, 6, STATE_LISTEN, 80, 3, [0u8; 16]), 1).unwrap();
		assert!(both.ip.is_unspecified());
	}

	#[test]
	fn the_holders_of_a_loopback_port_are_every_socket_that_would_get_its_packets() {
		let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		let socket = |pid: u32, ip: &str, port: u16, tcp: bool| Bound {pid, ip: ip.parse().unwrap(), port, tcp};
		let found = [socket(40, "127.0.0.1", 8080, true), socket(41, "0.0.0.0", 8080, true), socket(42, "127.0.0.2", 8080, true), socket(43, "127.0.0.1", 8081, true), socket(44, "127.0.0.1", 8080, false)];
		assert_eq!(holders(&found, address, false), [40, 41], "a listener on the same address and one on any address; not another address, not another port, not a UDP socket");
		assert_eq!(holders(&found, address, true), [44]);
		assert!(holders(&[], address, false).is_empty());
	}
}
