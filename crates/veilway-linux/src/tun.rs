//! The TUN device: whole IP packets in and out, no packet information header.
use crate::netlink::Rt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

// `_IOW('T', 202, int)`. The number is the same on x86, ARM and RISC-V, the architectures Veilway builds for; mips and powerpc encode the direction differently and are not targets.
const TUNSETIFF: u32 = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

// `struct ifreq` for this one request: the name, then the flags at the start of the union. 40 bytes as the kernel's is on 64-bit systems, and larger than it on 32-bit ones, where it reads less.
#[repr(C)]
struct IfReq {name: [u8; libc::IFNAMSIZ], flags: libc::c_short, rest: [u8; 22]}

pub struct Tun {file: AsyncFd<File>, pub name: String, pub index: u32}

/// Whether `name` can name a network device and can be put in a firewall rule between quotes.
pub fn valid_name(name: &str) -> bool {!name.is_empty() && name.len() < libc::IFNAMSIZ && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))}

impl Tun {
	/// Makes a device that exists as long as this descriptor does: a process that dies takes the device and its routes with it, and the rules and blackhole routes of the client are what hold the traffic then.
	pub fn create(name: &str, rt: &mut Rt) -> io::Result<Self> {
		if !valid_name(name) {return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{name:?} is not a name a network device can have")))}
		let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open("/dev/net/tun").map_err(|error| io::Error::new(error.kind(), format!("cannot open /dev/net/tun ({error}): the program needs CAP_NET_ADMIN and a container needs --device /dev/net/tun")))?;
		let mut request = IfReq {name: [0; libc::IFNAMSIZ], flags: IFF_TUN | IFF_NO_PI, rest: [0; 22]};
		request.name[..name.len()].copy_from_slice(name.as_bytes());
		// SAFETY: `file` is an open descriptor for the length of the call, and `request` is a live, exclusively borrowed struct at least as large as the `struct ifreq` this request reads and writes; the kernel touches nothing else of ours.
		if unsafe {libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut request as *mut IfReq)} < 0 {return Err(io::Error::last_os_error())}
		let name = String::from_utf8_lossy(request.name.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned();
		let index = rt.index_of(&name)?;
		Ok(Self {file: AsyncFd::with_interest(file, Interest::READABLE)?, name, index})
	}
	/// The next packet the system sent into the tunnel.
	pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {self.file.async_io(Interest::READABLE, |mut file| file.read(buf)).await}
	/// Hands a packet to the system. False when the device's queue is full and the packet was dropped, which is what any interface does.
	pub fn write(&self, packet: &[u8]) -> io::Result<bool> {
		match (&*self.file.get_ref()).write(packet) {
			Ok(_) => Ok(true),
			Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
			Err(error) => Err(error),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_names_a_device_can_have_pass() {
		assert!(valid_name("vw0") && valid_name("veilway-1.x"));
		assert!(!valid_name("") && !valid_name("a-name-that-is-too-long") && !valid_name("vw 0") && !valid_name("vw\"0") && !valid_name("vw/0"));
	}
}
