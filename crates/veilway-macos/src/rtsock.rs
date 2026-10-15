//! The routing socket (`PF_ROUTE`): the messages that add a route and ask for the default one, and the reading of the messages the kernel sends when the networks change.
//!
//! The messages are built and read by hand over bytes, on the layout of `<net/route.h>` on macOS (`rt_msghdr` is 92 bytes, socket addresses are rounded up to four), so that they are tested on every system. The socket itself is behind `cfg(target_os = "macos")`. Nothing here shells out to `route`.
//!
//! A route into the tunnel is an interface route, as `route add -net N -interface utunX` makes it and as `wg-quick` does on macOS: the destination, a gateway that is a link-level address naming the interface by its index, the mask, and the flags `UP | STATIC` (`UP | STATIC | HOST` and no mask for a host).
use crate::routes::Step;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const RTM_VERSION: u8 = 5;
pub const RTM_ADD: u8 = 1;
pub const RTM_DELETE: u8 = 2;
pub const RTM_CHANGE: u8 = 3;
pub const RTM_GET: u8 = 4;
pub const RTM_NEWADDR: u8 = 0xc;
pub const RTM_DELADDR: u8 = 0xd;
pub const RTM_IFINFO: u8 = 0xe;
pub const RTM_IFINFO2: u8 = 0x12;
pub const RTF_UP: i32 = 0x1;
pub const RTF_HOST: i32 = 0x4;
pub const RTF_LLINFO: i32 = 0x400;
pub const RTF_STATIC: i32 = 0x800;
pub const RTF_WASCLONED: i32 = 0x20000;
pub const RTA_DST: i32 = 0x1;
pub const RTA_GATEWAY: i32 = 0x2;
pub const RTA_NETMASK: i32 = 0x4;
const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
/// The value on macOS, which is not Linux's.
const AF_INET6: u8 = 30;
const HEADER: usize = 92;

fn round(length: usize) -> usize {if length == 0 {4} else {(length + 3) & !3}}

/// A `sockaddr_in` or `sockaddr_in6` with this address.
pub fn sockaddr(ip: IpAddr) -> Vec<u8> {
	match ip {
		IpAddr::V4(v4) => [&[16, AF_INET, 0, 0][..], &v4.octets(), &[0; 8]].concat(),
		IpAddr::V6(v6) => [&[28, AF_INET6, 0, 0, 0, 0, 0, 0][..], &v6.octets(), &[0; 4]].concat(),
	}
}

/// A `sockaddr_dl` that names an interface by its index and carries no name or address.
pub fn sockaddr_link(index: u16) -> Vec<u8> {
	let index = index.to_ne_bytes();
	[&[20, AF_LINK, index[0], index[1], 0, 0, 0, 0][..], &[0; 12]].concat()
}

/// The mask of a prefix, as a socket address of the family.
pub fn mask(net: &IpNet) -> Vec<u8> {
	match net {
		IpNet::V4(v4) => sockaddr(IpAddr::V4(v4.netmask())),
		IpNet::V6(v6) => sockaddr(IpAddr::V6(v6.netmask())),
	}
}

/// A message of the routing socket: the header, then the socket addresses in the order of their bits.
pub fn build(kind: u8, flags: i32, seq: i32, pid: i32, index: u16, addrs: &[(i32, Vec<u8>)]) -> Vec<u8> {
	let mut body: Vec<u8> = Vec::new();
	let mut bits = 0;
	for (bit, address) in addrs {
		bits |= bit;
		body.extend_from_slice(address);
		body.resize(body.len().next_multiple_of(4), 0);
	}
	let mut message = vec![0u8; HEADER];
	message[..2].copy_from_slice(&((HEADER + body.len()) as u16).to_ne_bytes());
	message[2] = RTM_VERSION;
	message[3] = kind;
	message[4..6].copy_from_slice(&index.to_ne_bytes());
	message[8..12].copy_from_slice(&flags.to_ne_bytes());
	message[12..16].copy_from_slice(&bits.to_ne_bytes());
	message[16..20].copy_from_slice(&pid.to_ne_bytes());
	message[20..24].copy_from_slice(&seq.to_ne_bytes());
	message.extend_from_slice(&body);
	message
}

/// The message that adds the interface route of a step on the interface with this index.
pub fn add(step: &Step, index: u16, seq: i32, pid: i32) -> Vec<u8> {
	let host = step.net.prefix_len() == step.net.max_prefix_len();
	let mut addrs = vec![(RTA_DST, sockaddr(step.net.network())), (RTA_GATEWAY, sockaddr_link(index))];
	if !host {addrs.push((RTA_NETMASK, mask(&step.net)))}
	build(RTM_ADD, RTF_UP | RTF_STATIC | if host {RTF_HOST} else {0}, seq, pid, index, &addrs)
}

/// The message that asks for the system's own default route of a family: the exact entry for `0/0`, which the tunnel's halves are not.
pub fn get_default(v6: bool, seq: i32, pid: i32) -> Vec<u8> {
	let zero = if v6 {IpAddr::V6(Ipv6Addr::UNSPECIFIED)} else {IpAddr::V4(Ipv4Addr::UNSPECIFIED)};
	build(RTM_GET, RTF_UP, seq, pid, 0, &[(RTA_DST, sockaddr(zero)), (RTA_NETMASK, sockaddr(zero))])
}

/// What the header of a message says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {pub kind: u8, pub index: u16, pub flags: i32, pub addrs: i32, pub pid: i32, pub seq: i32, pub errno: i32}

pub fn head(message: &[u8]) -> Option<Head> {
	if message.len() < HEADER || message[2] != RTM_VERSION {return None}
	let int = |at: usize| i32::from_ne_bytes(message[at..at + 4].try_into().expect("four bytes"));
	Some(Head {kind: message[3], index: u16::from_ne_bytes([message[4], message[5]]), flags: int(8), addrs: int(12), pid: int(16), seq: int(20), errno: int(24)})
}

/// The socket addresses of a message, by their bit. Stops at an address that runs past the message.
pub fn addresses(message: &[u8]) -> Vec<(i32, Vec<u8>)> {
	let Some(head) = head(message) else {return Vec::new()};
	let (mut found, mut at) = (Vec::new(), HEADER);
	for shift in 0..8 {
		let bit = 1 << shift;
		if head.addrs & bit == 0 {continue}
		let Some(&length) = message.get(at) else {break};
		let end = at + round(length as usize);
		if end > message.len() {break}
		found.push((bit, message[at..at + (length as usize).min(end - at)].to_vec()));
		at = end;
	}
	found
}

/// The address a socket address holds: None for a link-level one or one of another family. A mask may be cut short (the length byte stops at its last nonzero byte), and what is missing is zeros.
pub fn ip_of(raw: &[u8]) -> Option<IpAddr> {
	let at = |range: std::ops::Range<usize>| -> Vec<u8> {range.map(|index| raw.get(index).copied().unwrap_or(0)).collect()};
	match raw.get(1)? {
		&AF_INET => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(at(4..8)).ok()?))),
		&AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(at(8..24)).ok()?))),
		_ => None,
	}
}

/// The prefix a mask means, or None if it is not a prefix.
pub fn prefix_of(mask: IpAddr) -> Option<u8> {
	let (bits, length) = match mask {IpAddr::V4(v4) => (u128::from(u32::from(v4)) << 96, 32), IpAddr::V6(v6) => (u128::from(v6), 128)};
	let ones = bits.leading_ones();
	let expected = if ones == 0 {0} else {u128::MAX << (128 - ones)};
	Some(ones as u8).filter(|ones| bits == expected && *ones <= length)
}

/// The interface and the gateway an answer to `get_default` names. The gateway is None for a default route that is an interface route.
pub fn default_of(reply: &[u8]) -> Option<(u32, Option<IpAddr>)> {
	let head = head(reply).filter(|head| head.errno == 0 && head.kind == RTM_GET && head.index != 0)?;
	let gateway = addresses(reply).into_iter().find(|(bit, _)| *bit == RTA_GATEWAY).and_then(|(_, raw)| ip_of(&raw));
	Some((u32::from(head.index), gateway))
}

/// Whether a message of the routing socket is a change of the device's networks that the engine is to be told of: an interface or an address changed, or a route did, by someone else than this process. The entries the kernel makes for neighbors and for hosts it cloned from a route (`RTF_LLINFO`, `RTF_WASCLONED`) come all the time and mean nothing.
pub fn matters(message: &[u8], own_pid: i32) -> bool {
	let Some(head) = head(message) else {return false};
	match head.kind {
		RTM_IFINFO | RTM_IFINFO2 | RTM_NEWADDR | RTM_DELADDR => true,
		RTM_ADD | RTM_DELETE | RTM_CHANGE => head.pid != own_pid && head.flags & (RTF_LLINFO | RTF_WASCLONED) == 0,
		_ => false,
	}
}

#[cfg(target_os = "macos")]
pub use socket::{apply, default_route, RouteSocket};

#[cfg(target_os = "macos")]
mod socket {
	use super::*;
	use std::io;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

	/// A routing socket. Blocking with a short read timeout, for the one-shot questions; the watch makes its own non-blocking one.
	pub struct RouteSocket {pub fd: OwnedFd}

	impl RouteSocket {
		pub fn open(nonblocking: bool) -> io::Result<Self> {
			// SAFETY: `socket` takes three integers and returns a descriptor or -1; nothing is read from or written to memory of ours.
			let raw = unsafe {libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC)};
			if raw < 0 {return Err(io::Error::last_os_error())}
			// SAFETY: `raw` is a descriptor just returned and not owned by anything else.
			let fd = unsafe {OwnedFd::from_raw_fd(raw)};
			// SAFETY: `fcntl` with these commands takes integers only, on a descriptor that is open.
			unsafe {
				if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0 {return Err(io::Error::last_os_error())}
				if nonblocking && libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) < 0 {return Err(io::Error::last_os_error())}
			}
			if !nonblocking {
				let timeout = libc::timeval {tv_sec: 2, tv_usec: 0};
				// SAFETY: `SO_RCVTIMEO` reads a `timeval` of the size given, which is this live one.
				if unsafe {libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t)} < 0 {return Err(io::Error::last_os_error())}
			}
			Ok(Self {fd})
		}
		pub fn send(&self, message: &[u8]) -> io::Result<()> {
			// SAFETY: `write` reads `message.len()` bytes of the live slice.
			let written = unsafe {libc::write(self.fd.as_raw_fd(), message.as_ptr().cast(), message.len())};
			if written < 0 {Err(io::Error::last_os_error())} else {Ok(())}
		}
		pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
			// SAFETY: `read` writes at most `buffer.len()` bytes into the live slice.
			let read = unsafe {libc::read(self.fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())};
			if read < 0 {Err(io::Error::last_os_error())} else {Ok(read as usize)}
		}
	}

	/// The system's default route of a family: the interface it leaves by and the gateway. None when there is none.
	pub fn default_route(v6: bool) -> io::Result<Option<(u32, Option<IpAddr>)>> {
		let (socket, pid, seq) = (RouteSocket::open(false)?, std::process::id() as i32, 1);
		match socket.send(&get_default(v6, seq, pid)) {
			Ok(()) => {}
			Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
			Err(error) => return Err(error),
		}
		let mut buffer = vec![0u8; 2048];
		// The socket hears the other messages of the system too: the answer is the one that carries this process and this sequence.
		for _ in 0..64 {
			let read = socket.read(&mut buffer)?;
			let Some(head) = head(&buffer[..read]).filter(|head| head.kind == RTM_GET && head.pid == pid && head.seq == seq) else {continue};
			return Ok(if head.errno == 0 {default_of(&buffer[..read])} else {None});
		}
		Ok(None)
	}

	/// Adds the routes of a plan on the interface with this index. A route that was refused and is optional is returned by its network and does not fail the run; one that is not optional does, and so does a route that exists already: it is another program's, it is not removed, and the tunnel would not carry what it is meant to.
	pub fn apply(index: u32, steps: &[Step]) -> io::Result<Vec<String>> {
		let (socket, pid, mut skipped) = (RouteSocket::open(false)?, std::process::id() as i32, Vec::new());
		let index = u16::try_from(index).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the interface index does not fit a route message"))?;
		for (seq, step) in steps.iter().enumerate() {
			if let Err(error) = socket.send(&add(step, index, seq as i32 + 1, pid)) {
				if step.optional {skipped.push(step.net.to_string())} else {return Err(io::Error::new(error.kind(), format!("the route {} could not be added: {error}", step.net)))}
			}
		}
		Ok(skipped)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn step(net: &str) -> Step {Step {net: net.parse().unwrap(), optional: false}}

	#[test]
	fn socket_addresses_have_the_layout_the_kernel_reads() {
		assert_eq!(sockaddr("10.0.0.1".parse().unwrap()), [16, 2, 0, 0, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
		let v6 = sockaddr("fd00::1".parse().unwrap());
		assert_eq!((v6.len(), v6[0], v6[1], v6[8], v6[23]), (28, 28, 30, 0xfd, 1));
		let link = sockaddr_link(0x0102);
		assert_eq!((link.len(), link[0], link[1]), (20, 20, 18));
		assert_eq!(u16::from_ne_bytes([link[2], link[3]]), 0x0102);
	}

	#[test]
	fn a_net_route_carries_destination_interface_and_mask() {
		let message = add(&step("128.0.0.0/1"), 14, 7, 99);
		let found = head(&message).unwrap();
		assert_eq!((found.kind, found.index, found.flags, found.addrs, found.pid, found.seq), (RTM_ADD, 14, RTF_UP | RTF_STATIC, RTA_DST | RTA_GATEWAY | RTA_NETMASK, 99, 7));
		assert_eq!(u16::from_ne_bytes(message[..2].try_into().unwrap()) as usize, message.len());
		assert_eq!(message.len(), HEADER + 16 + 20 + 16);
		let parts = addresses(&message);
		assert_eq!(parts.len(), 3);
		assert_eq!(ip_of(&parts[0].1), Some("128.0.0.0".parse().unwrap()));
		assert_eq!(parts[1].1[1], AF_LINK);
		assert_eq!(prefix_of(ip_of(&parts[2].1).unwrap()), Some(1));
	}

	#[test]
	fn a_host_route_has_no_mask_and_the_host_flag() {
		let found = head(&add(&step("10.200.0.1/32"), 14, 1, 1)).unwrap();
		assert_eq!((found.flags, found.addrs), (RTF_UP | RTF_STATIC | RTF_HOST, RTA_DST | RTA_GATEWAY));
		let v6 = add(&step("::/1"), 14, 1, 1);
		let parts = addresses(&v6);
		assert_eq!(parts.len(), 3);
		assert_eq!(prefix_of(ip_of(&parts[2].1).unwrap()), Some(1));
		assert_eq!(ip_of(&parts[0].1), Some("::".parse().unwrap()));
	}

	#[test]
	fn the_default_question_names_the_zero_network_and_mask() {
		let parts = addresses(&get_default(false, 1, 5));
		assert_eq!(parts.len(), 2);
		assert!(parts.iter().all(|(_, raw)| ip_of(raw) == Some("0.0.0.0".parse().unwrap())));
		assert_eq!(head(&get_default(true, 1, 5)).unwrap().kind, RTM_GET);
	}

	#[test]
	fn an_answer_names_its_interface_and_gateway() {
		let mut reply = build(RTM_GET, RTF_UP, 1, 5, 4, &[(RTA_DST, sockaddr("0.0.0.0".parse().unwrap())), (RTA_GATEWAY, sockaddr("192.168.1.1".parse().unwrap())), (RTA_NETMASK, sockaddr("0.0.0.0".parse().unwrap()))]);
		assert_eq!(default_of(&reply), Some((4, Some("192.168.1.1".parse().unwrap()))));
		let via_link = build(RTM_GET, RTF_UP, 1, 5, 4, &[(RTA_DST, sockaddr("0.0.0.0".parse().unwrap())), (RTA_GATEWAY, sockaddr_link(4))]);
		assert_eq!(default_of(&via_link), Some((4, None)));
		reply[24..28].copy_from_slice(&3i32.to_ne_bytes());
		assert_eq!(default_of(&reply), None, "an error in the answer is no route");
		assert_eq!(default_of(b"short"), None);
	}

	#[test]
	fn a_mask_cut_short_by_its_length_byte_still_reads() {
		assert_eq!(ip_of(&[5, 2, 0, 0, 255]), Some("255.0.0.0".parse().unwrap()));
		assert_eq!(prefix_of("255.255.255.0".parse().unwrap()), Some(24));
		assert_eq!(prefix_of("ffff:ffff:ffff:ffff::".parse().unwrap()), Some(64));
		assert_eq!(prefix_of("0.0.0.0".parse().unwrap()), Some(0));
		assert_eq!(prefix_of("255.0.255.0".parse().unwrap()), None);
		assert_eq!(ip_of(&[20, AF_LINK, 1, 0]), None);
	}

	#[test]
	fn a_message_that_runs_past_its_end_is_cut_and_not_read_beyond() {
		let mut message = add(&step("0.0.0.0/1"), 14, 1, 1);
		message.truncate(HEADER + 16 + 4);
		assert_eq!(addresses(&message).len(), 1);
		assert!(addresses(&message[..10]).is_empty());
	}

	#[test]
	fn only_changes_of_the_networks_matter() {
		let message = |kind: u8, flags: i32, pid: i32| build(kind, flags, 0, pid, 0, &[]);
		assert!(matters(&message(RTM_IFINFO, 0, 1), 9));
		assert!(matters(&message(RTM_NEWADDR, 0, 9), 9));
		assert!(matters(&message(RTM_DELADDR, 0, 1), 9));
		assert!(matters(&message(RTM_DELETE, RTF_UP, 1), 9));
		assert!(!matters(&message(RTM_ADD, RTF_UP, 9), 9), "this process's own routes");
		assert!(!matters(&message(RTM_ADD, RTF_UP | RTF_LLINFO, 1), 9), "a neighbor entry");
		assert!(!matters(&message(RTM_DELETE, RTF_UP | RTF_WASCLONED, 1), 9));
		assert!(!matters(&message(RTM_GET, 0, 1), 9));
		assert!(!matters(b"junk", 9));
		let mut other_version = message(RTM_IFINFO, 0, 1);
		other_version[2] = 4;
		assert!(!matters(&other_version, 9));
	}
}
