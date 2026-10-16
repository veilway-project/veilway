//! Who owns a socket on this machine, for the UDP relay of the Xray add-on. Xray asks for an association with the address 0.0.0.0:0, so the relay cannot know which source port is Xray's, and any local process could send to the relay's port first and take the association. So the relay asks the kernel: a datagram is carried only from a UDP socket owned by the same user as the TCP connection that asked for the association, read from `/proc/net/{tcp,tcp6,udp,udp6}`. Those files are local, but are read as untrusted: a size cap, strict lines, and any doubt (a line that does not parse, two owners for one socket, no socket) is no owner. Where there is no `/proc/net`, nothing has an owner and no association is granted.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_os = "linux")]
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Looks up the user id that owns the socket at `local` (and `remote` for a TCP socket) of UDP when the flag is set, of TCP when not.
pub(super) type Lookup = Arc<dyn Fn(bool, SocketAddr, Option<SocketAddr>) -> Option<u32> + Send + Sync>;

/// The most of one table that is read. A line is about 150 bytes, so this holds some fifty thousand sockets.
#[cfg(target_os = "linux")]
const MAX_TABLE: u64 = 8 << 20;

/// One address column of a table: hex digits, an IP as the kernel prints the words of its memory (so in the machine's own byte order), a colon and a port in plain hex. An IPv4-mapped IPv6 address is the IPv4 address it maps.
fn address(text: &str) -> Option<SocketAddr> {
	let (ip, port) = text.split_once(':')?;
	if port.len() != 4 || !ip.bytes().chain(port.bytes()).all(|byte| byte.is_ascii_hexdigit()) {return None}
	let word = |at: usize| u32::from_str_radix(&ip[at..at + 8], 16).ok().map(u32::to_ne_bytes);
	let ip = match ip.len() {
		8 => IpAddr::from(Ipv4Addr::from(word(0)?)),
		32 => IpAddr::from(Ipv6Addr::from(<[u8; 16]>::try_from([word(0)?, word(8)?, word(16)?, word(24)?].concat()).ok()?)).to_canonical(),
		_ => return None,
	};
	Some(SocketAddr::new(ip, u16::from_str_radix(port, 16).ok()?))
}

/// The user id that owns the one socket of `table` whose local address is `local` and, when given, whose remote address is `remote`. A socket bound to the wildcard address owns the port on every address, which is how a datagram from it to 127.0.0.1 looks to the one that receives it: Xray's sockets are of that kind, dual-stack on `::`. None when no socket matches, when matching sockets have different owners, and when any line of the table is not well formed: a table that cannot be read in full says nothing.
pub(super) fn owner(table: &str, local: SocketAddr, remote: Option<SocketAddr>) -> Option<u32> {
	let mut lines = table.lines();
	if !lines.next()?.trim_start().starts_with("sl") {return None}
	let canonical = |addr: SocketAddr| SocketAddr::new(addr.ip().to_canonical(), addr.port());
	let (local, remote, mut found) = (canonical(local), remote.map(canonical), None);
	for line in lines.filter(|line| !line.trim().is_empty()) {
		let fields: Vec<&str> = line.split_whitespace().collect();
		if fields.len() < 8 || !fields[0].ends_with(':') {return None}
		let (here, there, uid) = (address(fields[1])?, address(fields[2])?, fields[7].parse::<u32>().ok()?);
		if here.port() != local.port() || !(here.ip() == local.ip() || here.ip().is_unspecified() && (here.is_ipv6() || local.is_ipv4())) || remote.is_some_and(|remote| there != remote) {continue}
		if found.is_some_and(|other| other != uid) {return None}
		found = Some(uid);
	}
	found
}

/// The lookup the relay runs with, on `/proc/net`. Blocking: the caller runs it where that is fine.
#[cfg(target_os = "linux")]
pub(super) fn lookup(udp: bool, local: SocketAddr, remote: Option<SocketAddr>) -> Option<u32> {
	let name = if udp {"udp"} else {"tcp"};
	[name.to_string(), format!("{name}6")].iter().find_map(|name| {
		let mut text = String::new();
		let read = std::fs::File::open(format!("/proc/net/{name}")).ok()?.take(MAX_TABLE + 1).read_to_string(&mut text).ok()?;
		owner(&text, local, remote).filter(|_| read as u64 <= MAX_TABLE)
	})
}

#[cfg(not(target_os = "linux"))]
pub(super) fn lookup(_udp: bool, _local: SocketAddr, _remote: Option<SocketAddr>) -> Option<u32> {None}

#[cfg(test)]
mod tests {
	use super::*;

	const HEAD: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";

	/// The words of an address as the kernel prints them: the bytes of each, in the machine's order.
	fn words(ip: IpAddr) -> String {
		match ip {
			IpAddr::V4(ip) => format!("{:08X}", u32::from_ne_bytes(ip.octets())),
			IpAddr::V6(ip) => ip.octets().chunks(4).map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().unwrap()))).collect(),
		}
	}

	fn row(n: u32, local: &str, remote: &str, uid: u32) -> String {
		let ends = |addr: &str| addr.parse::<SocketAddr>().map_or_else(|_| addr.to_string(), |addr| format!("{}:{:04X}", words(addr.ip()), addr.port()));
		format!("{n:4}: {}  {} 07 00000000:00000000 00:00000000 00000000 {uid:5}        0 {} 2 0000000000000000 0\n", ends(local), ends(remote), 30000 + n)
	}

	fn sock(text: &str) -> SocketAddr {text.parse().unwrap()}

	#[test]
	fn an_address_is_read_as_the_kernel_writes_it() {
		if cfg!(target_endian = "little") {
			assert_eq!(address("0100007F:1F90"), Some(sock("127.0.0.1:8080")));
			assert_eq!(address("0F02000A:0035"), Some(sock("10.0.2.15:53")));
			assert_eq!(address("00000000000000000000000001000000:01BB"), Some(sock("[::1]:443")));
			assert_eq!(address("0000000000000000FFFF00000100007F:C000"), Some(sock("127.0.0.1:49152")), "a mapped address is the IPv4 address");
			assert_eq!(address("B80D0120000000000000000001000000:0050"), Some(sock("[2001:db8::1]:80")));
		}
		for (ip, port) in [("127.0.0.1", 1u16), ("10.1.2.3", 65535), ("::1", 443), ("2001:db8::abcd", 9)] {
			let ip: IpAddr = ip.parse().unwrap();
			assert_eq!(address(&format!("{}:{port:04X}", words(ip))), Some(SocketAddr::new(ip.to_canonical(), port)));
		}
	}

	#[test]
	fn what_is_not_an_address_is_not_read() {
		for bad in ["", ":", "0100007F", "0100007F:", "0100007F:1F9", "0100007F:1F900", "0100007:1F90", "0100007FF:1F90", "0100007G:1F90", "+100007F:1F90", "0100007F:+F90", "-100007F:1F90", "0100007F:1F90:1", "0100007F 1F90", "00000000000000000000000001000000:01B", "0000000000000000000000000100000:01BB", "é100007F:1F90", "éé00007F:1F90", "00000000000000000000000001000é0:01BB"] {
			assert_eq!(address(bad), None, "{bad:?} was read");
		}
	}

	#[test]
	fn the_owner_of_a_socket_is_found_by_its_address() {
		let table = [HEAD.to_string(), row(0, "127.0.0.1:5353", "0.0.0.0:0", 100), row(1, "127.0.0.1:40000", "0.0.0.0:0", 1001), row(2, "10.0.2.15:40000", "0.0.0.0:0", 1002)].concat();
		assert_eq!(owner(&table, sock("127.0.0.1:40000"), None), Some(1001));
		assert_eq!(owner(&table, sock("10.0.2.15:40000"), None), Some(1002));
		assert_eq!(owner(&table, sock("127.0.0.1:5353"), Some(sock("0.0.0.0:0"))), Some(100));
		let wild = [HEAD.to_string(), row(0, "0.0.0.0:6000", "0.0.0.0:0", 11), row(1, "[::]:6001", "[::]:0", 12), row(2, "127.0.0.1:6002", "0.0.0.0:0", 13), row(3, "[::]:6002", "[::]:0", 14)].concat();
		assert_eq!(owner(&wild, sock("127.0.0.1:6000"), None), Some(11), "a socket bound to 0.0.0.0 was not found by the address it sent from");
		assert_eq!(owner(&wild, sock("[::1]:6000"), None), None, "an IPv4 wildcard socket was taken for an IPv6 sender");
		assert_eq!(owner(&wild, sock("127.0.0.1:6001"), None), Some(12), "a dual-stack socket was not found by an IPv4 address");
		assert_eq!(owner(&wild, sock("[::1]:6001"), None), Some(12));
		assert_eq!(owner(&wild, sock("127.0.0.1:6002"), None), None, "a wildcard and a specific socket of different users on one port were told apart");
		assert_eq!(owner(&wild, sock("127.0.0.1:6003"), None), None);
		for absent in ["127.0.0.1:40001", "127.0.0.2:40000", "10.0.2.15:5353"] {assert_eq!(owner(&table, sock(absent), None), None, "{absent} was found")}
		assert_eq!(owner(&table, sock("127.0.0.1:40000"), Some(sock("1.2.3.4:5"))), None, "a remote that is not the socket's was accepted");
		assert_eq!(owner(HEAD, sock("127.0.0.1:1"), None), None);
	}

	#[test]
	fn a_tcp_socket_is_told_from_the_other_end_of_its_connection() {
		let (xray, hop) = ("127.0.0.1:41234", "127.0.0.1:1080");
		let table = [HEAD.to_string(), row(0, hop, "0.0.0.0:0", 0), row(1, xray, hop, 995), row(2, hop, xray, 0)].concat();
		assert_eq!(owner(&table, sock(xray), Some(sock(hop))), Some(995));
		assert_eq!(owner(&table, sock(hop), Some(sock(xray))), Some(0));
		assert_eq!(owner(&table, sock(xray), None), Some(995));
	}

	#[test]
	fn an_ipv6_table_and_a_mapped_address_are_read() {
		let table = [HEAD.to_string(), row(0, "[::1]:7000", "[::]:0", 5), row(1, "[::ffff:127.0.0.1]:7001", "[::]:0", 6), row(2, "[2001:db8::2]:7002", "[::]:0", 7)].concat();
		assert_eq!(owner(&table, sock("[::1]:7000"), None), Some(5));
		assert_eq!(owner(&table, sock("127.0.0.1:7001"), None), Some(6), "a dual-stack socket was not found by its IPv4 address");
		assert_eq!(owner(&table, sock("[::ffff:127.0.0.1]:7001"), None), Some(6));
		assert_eq!(owner(&table, sock("[2001:db8::2]:7002"), None), Some(7));
		assert_eq!(owner(&table, sock("127.0.0.1:7000"), None), None);
	}

	#[test]
	fn two_owners_of_one_address_are_no_owner() {
		let table = [HEAD.to_string(), row(0, "127.0.0.1:9000", "0.0.0.0:0", 1), row(1, "127.0.0.1:9000", "0.0.0.0:0", 1)].concat();
		assert_eq!(owner(&table, sock("127.0.0.1:9000"), None), Some(1), "one owner twice is still one");
		let table = [table, row(2, "127.0.0.1:9000", "0.0.0.0:0", 2)].concat();
		assert_eq!(owner(&table, sock("127.0.0.1:9000"), None), None);
	}

	#[test]
	fn a_table_with_a_line_that_is_not_whole_says_nothing() {
		let good = row(0, "127.0.0.1:9000", "0.0.0.0:0", 1);
		assert_eq!(owner(&[HEAD, &good].concat(), sock("127.0.0.1:9000"), None), Some(1));
		let after = |bad: &str| format!("{HEAD}{good}{bad}\n");
		let before = |bad: &str| format!("{HEAD}{bad}\n{good}");
		for bad in ["garbage", "   1: 0100007F:2328", "   1: 0100007F:2328 00000000:0000 07 00000000:00000000 00:00000000 00000000", "   1 0100007F:2328 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 1", "   1: 0100007F:2328 00000000:0000 07 00000000:00000000 00:00000000 00000000 -1 0 1", "   1: 0100007F:2328 00000000:0000 07 00000000:00000000 00:00000000 00000000 1e3 0 1", "   1: 0100007F:2328 00000000:0000 07 00000000:00000000 00:00000000 00000000 4294967296 0 1", "   1: 0100007F:2328 0000000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 1", "   1: ZZZZZZZZ:2328 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 1"] {
			assert_eq!(owner(&after(bad), sock("127.0.0.1:9000"), None), None, "{bad:?} after a good line was let by");
			assert_eq!(owner(&before(bad), sock("127.0.0.1:9000"), None), None, "{bad:?} before a good line was let by");
		}
		assert_eq!(owner(&format!("{good}{good}"), sock("127.0.0.1:9000"), None), None, "a table without its header was read");
		assert_eq!(owner("", sock("127.0.0.1:9000"), None), None);
		assert_eq!(owner(&format!("{HEAD}{good}\n\n  \n"), sock("127.0.0.1:9000"), None), Some(1), "empty lines at the end broke a good table");
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn the_sockets_of_this_process_are_found_with_its_own_user() {
		let (udp, tcp) = (std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
		let me = unsafe {libc::geteuid()};
		assert_eq!(lookup(true, udp.local_addr().unwrap(), None), Some(me));
		assert_eq!(lookup(false, tcp.local_addr().unwrap(), None), Some(me));
		let (udp6, tcp6) = (std::net::UdpSocket::bind("[::1]:0"), std::net::TcpListener::bind("[::1]:0"));
		if let (Ok(udp6), Ok(tcp6)) = (udp6, tcp6) {
			assert_eq!(lookup(true, udp6.local_addr().unwrap(), None), Some(me));
			assert_eq!(lookup(false, tcp6.local_addr().unwrap(), None), Some(me));
		}
		let wild = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
		assert_eq!(lookup(true, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), wild.local_addr().unwrap().port()), None), Some(me), "a socket bound to the wildcard was not found");
		assert_eq!(lookup(true, "127.0.0.1:1".parse().unwrap(), None), None);
	}
}
