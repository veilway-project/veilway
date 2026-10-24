//! Keeps the engine's sockets off its own tunnel without a route for the node (threat model gap G12): each is bound to the physical interface the best default route leaves by, with `IP_UNICAST_IF` for IPv4 and `IPV6_UNICAST_IF` for IPv6. The route lookup of such a socket only considers that interface, so the tunnel's routes, however wide, never catch it, and the kill switch (`firewall`) lets this program's connection to the node out.
//!
//! The interface is read again when the device's networks change (`run`), and a socket made after that is bound to the new one. One that is open keeps the old; the engine ends and reopens its sessions when the networks move.
use std::io;
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use veilway_transport::Hook;
use windows_sys::Win32::Networking::WinSock::{getsockopt, setsockopt, AF_INET6, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOL_SOCKET, SO_PROTOCOL_INFOW, WSAPROTOCOL_INFOW};

fn set(socket: usize, level: i32, option: i32, value: u32) -> io::Result<()> {
	// SAFETY: `socket` is open for the length of the call (the caller holds it), and the value is a live four-byte integer, the size the option takes.
	if unsafe {setsockopt(socket, level, option, (&value as *const u32).cast(), 4)} == 0 {Ok(())} else {Err(io::Error::last_os_error())}
}

/// The hook for the engine's sockets. `physical` is the index of the interface, 0 while there is none, and then a socket is refused and the attempt ends as offline.
pub fn hook(physical: Arc<AtomicU32>) -> Hook {
	Arc::new(move |socket| {
		let index = physical.load(Ordering::Relaxed);
		if index == 0 {return Err(io::Error::new(io::ErrorKind::NotConnected, "the device has no network outside the tunnel"))}
		let raw = socket.as_raw_socket() as usize;
		// IPv4 takes the index in network byte order and IPv6 in host order.
		// The family is read from the socket's protocol info: `IPV6_V6ONLY` reads true on an IPv4 socket too on Windows, which sent every IPv4 socket down the IPv6 branch, where the option is refused (the attempts ended as offline).
		// SAFETY: `info` is a live, zeroed WSAPROTOCOL_INFOW and `size` its length, which the call fills for the open socket.
		let mut info: WSAPROTOCOL_INFOW = unsafe {std::mem::zeroed()};
		let mut size = std::mem::size_of::<WSAPROTOCOL_INFOW>() as i32;
		if unsafe {getsockopt(raw, SOL_SOCKET, SO_PROTOCOL_INFOW, (&mut info as *mut WSAPROTOCOL_INFOW).cast(), &mut size)} != 0 {return Err(io::Error::last_os_error())}
		if info.iAddressFamily == i32::from(AF_INET6) {
			set(raw, IPPROTO_IPV6, IPV6_UNICAST_IF, index)?;
			// A dual-stack socket reaches IPv4 destinations too. The system may refuse the IPv4 option on it, which then is not needed.
			let _ = set(raw, IPPROTO_IP, IP_UNICAST_IF, index.to_be());
			Ok(())
		} else {
			set(raw, IPPROTO_IP, IP_UNICAST_IF, index.to_be())
		}
	})
}
