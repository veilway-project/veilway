//! The watch on the device's networks: a routing socket that the kernel writes every change of an interface, an address or a route to. `changed` returns when one that matters (`rtsock::matters`) came, and the caller reads the networks again.
use crate::rtsock::{matters, RouteSocket};
use std::io;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub struct Watch {fd: AsyncFd<RouteSocket>, pid: i32}

impl AsRawFd for RouteSocket {
	fn as_raw_fd(&self) -> std::os::fd::RawFd {self.fd.as_raw_fd()}
}

impl Watch {
	pub fn open() -> io::Result<Self> {Ok(Self {fd: AsyncFd::with_interest(RouteSocket::open(true)?, Interest::READABLE)?, pid: std::process::id() as i32})}
	/// Waits for the next change that matters. A socket that overflowed (`ENOBUFS`) lost messages, which is a change as far as anyone can tell.
	pub async fn changed(&self) -> io::Result<()> {
		let mut buffer = vec![0u8; 4096];
		loop {
			let mut guard = self.fd.readable().await?;
			match guard.try_io(|socket| socket.get_ref().read(&mut buffer)) {
				Ok(Ok(read)) if matters(&buffer[..read], self.pid) => return Ok(()),
				Ok(Ok(_)) => {}
				Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => return Ok(()),
				Ok(Err(error)) => return Err(error),
				Err(_would_block) => {}
			}
		}
	}
}
