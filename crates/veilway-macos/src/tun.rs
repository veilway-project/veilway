//! The tunnel's interface: a `utun`, made through the kernel control socket `com.apple.net.utun_control`. Every packet read from it or written to it carries four bytes in front, the address family in network order (`AF_INET` 2, `AF_INET6` 30), which `frame` and `unframe` add and take off.
//!
//! The kernel names the interface (`utunN`); the name asked for is `utun` (the next free one) or `utunN`, which asks for that number. The addresses and the MTU are set with `ifconfig`, a program of the system run by its fixed path with the arguments `configure_args` plans, and not through a shell.
use std::net::IpAddr;

/// The name of an interface this client can ask for: `utun`, or `utun` and a number.
pub fn valid_name(name: &str) -> bool {name.strip_prefix("utun").is_some_and(|number| number.is_empty() || (number.len() <= 4 && number.bytes().all(|byte| byte.is_ascii_digit())))}

/// The unit the control socket is asked for: 0 for the next free interface, else the number plus one.
pub fn unit_of(name: &str) -> u32 {name.strip_prefix("utun").and_then(|number| number.parse::<u32>().ok()).map_or(0, |number| number + 1)}

/// The packet with the header of its family in front. None if it is neither IPv4 nor IPv6.
pub fn frame(packet: &[u8]) -> Option<Vec<u8>> {
	let family = match packet.first()? >> 4 {4 => 2u8, 6 => 30u8, _ => return None};
	Some([&[0, 0, 0, family][..], packet].concat())
}

/// The packet in what was read, when the header names the family the packet's own version says.
pub fn unframe(read: &[u8]) -> Option<&[u8]> {
	let (header, packet) = (read.get(..4)?, read.get(4..)?);
	match (header, packet.first()? >> 4) {
		([0, 0, 0, 2], 4) | ([0, 0, 0, 30], 6) => Some(packet),
		_ => None,
	}
}

/// The `ifconfig` calls that give the interface its addresses and MTU and bring it up. A point-to-point interface takes the address and the far end: the profile's gateway of the same family, and the address itself when there is none. `alias` adds an address without removing the ones before.
pub fn configure_args(name: &str, addresses: &[IpAddr], gateways: &[IpAddr], mtu: u16) -> Vec<Vec<String>> {
	let mut calls: Vec<Vec<String>> = addresses.iter().map(|address| match address {
		IpAddr::V4(v4) => {
			let peer = gateways.iter().find(|gateway| gateway.is_ipv4()).copied().unwrap_or(IpAddr::V4(*v4));
			[name, "inet", &v4.to_string(), &peer.to_string(), "netmask", "255.255.255.255", "alias"].map(str::to_owned).to_vec()
		}
		IpAddr::V6(v6) => [name, "inet6", &v6.to_string(), "prefixlen", "128", "alias"].map(str::to_owned).to_vec(),
	}).collect();
	calls.push([name, "mtu", &mtu.to_string(), "up"].map(str::to_owned).to_vec());
	calls
}

#[cfg(target_os = "macos")]
pub use device::{configure, set_mtu, Tun};

#[cfg(target_os = "macos")]
mod device {
	use super::*;
	use crate::state::program;
	use std::ffi::CString;
	use std::io;
	use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
	use std::process::{Command, Stdio};
	use tokio::io::unix::AsyncFd;
	use tokio::io::Interest;

	/// The interface. Closing it (the process ends, or this is dropped) destroys the interface and takes its routes.
	pub struct Tun {fd: AsyncFd<OwnedFd>, pub name: String, pub index: u32}

	fn check(result: libc::c_int) -> io::Result<libc::c_int> {if result < 0 {Err(io::Error::last_os_error())} else {Ok(result)}}

	impl Tun {
		pub fn create(requested: &str) -> io::Result<Self> {
			// SAFETY: `socket` takes three integers and returns a descriptor or -1.
			let raw = check(unsafe {libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)})?;
			// SAFETY: `raw` is a descriptor just returned and not owned by anything else.
			let fd = unsafe {OwnedFd::from_raw_fd(raw)};
			// SAFETY: `ctl_info` is plain integers and a character array, for which all zeros is a value.
			let mut info: libc::ctl_info = unsafe {std::mem::zeroed()};
			for (slot, byte) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {*slot = *byte as libc::c_char}
			// SAFETY: `CTLIOCGINFO` reads the name and writes the id into the live `ctl_info` it is given.
			check(unsafe {libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info)})?;
			let address = libc::sockaddr_ctl {sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8, sc_family: libc::AF_SYSTEM as u8, ss_sysaddr: libc::AF_SYS_CONTROL as u16, sc_id: info.ctl_id, sc_unit: unit_of(requested), sc_reserved: [0; 5]};
			// SAFETY: `connect` reads `sockaddr_ctl`'s size from the live struct given.
			check(unsafe {libc::connect(fd.as_raw_fd(), (&address as *const libc::sockaddr_ctl).cast(), std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t)})?;
			let (mut name, mut length) = ([0u8; libc::IFNAMSIZ], libc::IFNAMSIZ as libc::socklen_t);
			// SAFETY: `UTUN_OPT_IFNAME` writes at most `length` bytes of a name into the live array and sets `length` to what it wrote.
			check(unsafe {libc::getsockopt(fd.as_raw_fd(), libc::SYSPROTO_CONTROL, libc::UTUN_OPT_IFNAME, name.as_mut_ptr().cast(), &mut length)})?;
			let name = String::from_utf8_lossy(&name[..name.iter().position(|byte| *byte == 0).unwrap_or(length as usize).min(libc::IFNAMSIZ)]).into_owned();
			let c_name = CString::new(name.clone()).map_err(|_| io::Error::other("the interface's name has a NUL"))?;
			// SAFETY: `if_nametoindex` reads the NUL-terminated string given.
			let index = unsafe {libc::if_nametoindex(c_name.as_ptr())};
			if index == 0 {return Err(io::Error::last_os_error())}
			// SAFETY: `fcntl` with these commands takes integers only, on a descriptor that is open.
			unsafe {
				check(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC))?;
				check(libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK))?;
			}
			Ok(Self {fd: AsyncFd::with_interest(fd, Interest::READABLE)?, name, index})
		}
		/// Writes a packet. False when the interface would block, and the packet is dropped, as a full queue does.
		pub fn write(&self, packet: &[u8]) -> io::Result<bool> {
			let Some(framed) = frame(packet) else {return Ok(false)};
			// SAFETY: `write` reads `framed.len()` bytes of the live vector.
			let written = unsafe {libc::write(self.fd.as_raw_fd(), framed.as_ptr().cast(), framed.len())};
			if written >= 0 {return Ok(true)}
			let error = io::Error::last_os_error();
			if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::ENOBUFS) {Ok(false)} else {Err(error)}
		}
		/// Reads the next packet into `buffer` and returns its length. A read that is not a packet of either family is skipped.
		pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
			let mut header = [0u8; 4];
			loop {
				let mut guard = self.fd.readable().await?;
				let result = guard.try_io(|fd| {
					let parts = [libc::iovec {iov_base: header.as_mut_ptr().cast(), iov_len: 4}, libc::iovec {iov_base: buffer.as_mut_ptr().cast(), iov_len: buffer.len()}];
					// SAFETY: `readv` writes at most the lengths given into the two live buffers.
					let read = unsafe {libc::readv(fd.as_raw_fd(), parts.as_ptr(), 2)};
					if read < 0 {Err(io::Error::last_os_error())} else {Ok(read as usize)}
				});
				match result {
					Ok(Ok(read)) if read > 4 && matches!((header, buffer[0] >> 4), ([0, 0, 0, 2], 4) | ([0, 0, 0, 30], 6)) => return Ok(read - 4),
					Ok(Ok(_)) => continue,
					Ok(Err(error)) => return Err(error),
					Err(_would_block) => continue,
				}
			}
		}
	}

	// Runs `ifconfig` with these arguments and turns its complaint into the error.
	fn ifconfig(arguments: &[String]) -> io::Result<()> {
		let output = Command::new(program("ifconfig")?).args(arguments).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output()?;
		if output.status.success() {Ok(())} else {Err(io::Error::other(format!("ifconfig {} failed: {}", arguments.join(" "), String::from_utf8_lossy(&output.stderr).trim())))}
	}

	/// Gives the interface its addresses and MTU and brings it up.
	pub fn configure(name: &str, addresses: &[IpAddr], gateways: &[IpAddr], mtu: u16) -> io::Result<()> {configure_args(name, addresses, gateways, mtu).iter().try_for_each(|call| ifconfig(call))}

	pub fn set_mtu(name: &str, mtu: u16) -> io::Result<()> {ifconfig(&[name.to_owned(), "mtu".to_owned(), mtu.to_string()])}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_interface_names_that_can_be_asked_for() {
		assert!(valid_name("utun") && valid_name("utun7") && valid_name("utun1234"));
		assert!(!valid_name("") && !valid_name("en0") && !valid_name("utun-1") && !valid_name("utun12345") && !valid_name("utun7 up") && !valid_name("lo0"));
		assert_eq!((unit_of("utun"), unit_of("utun0"), unit_of("utun7")), (0, 1, 8));
	}

	#[test]
	fn a_packet_gets_the_header_of_its_family_and_loses_it_again() {
		let v4 = [0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
		let framed = frame(&v4).unwrap();
		assert_eq!(&framed[..4], [0, 0, 0, 2]);
		assert_eq!(unframe(&framed), Some(&v4[..]));
		let v6 = [&[0x60u8][..], &[0; 39]].concat();
		let framed6 = frame(&v6).unwrap();
		assert_eq!(&framed6[..4], [0, 0, 0, 30]);
		assert_eq!(unframe(&framed6), Some(&v6[..]));
	}

	#[test]
	fn what_is_not_a_packet_of_its_family_is_refused() {
		assert!(frame(&[]).is_none() && frame(&[0x10, 0]).is_none());
		assert!(unframe(&[0, 0, 0, 2, 0x60]).is_none(), "a header for IPv4 over an IPv6 packet");
		assert!(unframe(&[0, 0, 0, 30, 0x45]).is_none());
		assert!(unframe(&[0, 0, 0, 7, 0x45]).is_none());
		assert!(unframe(&[0, 0, 0, 2]).is_none() && unframe(&[0, 0]).is_none());
	}

	#[test]
	fn the_interface_calls_give_each_address_its_far_end_and_end_with_the_mtu() {
		let addresses: Vec<IpAddr> = vec!["10.200.0.2".parse().unwrap(), "fd00::2".parse().unwrap()];
		let calls = configure_args("utun5", &addresses, &["10.200.0.1".parse().unwrap(), "fd00::1".parse().unwrap()], 1390);
		assert_eq!(calls[0].join(" "), "utun5 inet 10.200.0.2 10.200.0.1 netmask 255.255.255.255 alias");
		assert_eq!(calls[1].join(" "), "utun5 inet6 fd00::2 prefixlen 128 alias");
		assert_eq!(calls[2].join(" "), "utun5 mtu 1390 up");
		let alone = configure_args("utun5", &addresses[..1], &[], 1280);
		assert_eq!(alone[0].join(" "), "utun5 inet 10.200.0.2 10.200.0.2 netmask 255.255.255.255 alias");
	}
}
