//! Keeps the engine's sockets off its own tunnel without a route for the node (threat model gap G12): each is bound to the physical interface the system's default route leaves by, with `IP_BOUND_IF` for IPv4 and `IPV6_BOUND_IF` for IPv6. The route lookup of such a socket only considers that interface, so the tunnel's routes, however wide, never catch it, and the kill switch (`firewall`) lets its connection to the node out by address and port.
//!
//! The interface is read again when the device's networks change (`run`), and a socket made after that is bound to the new one. One that is open keeps the old; the engine ends and reopens its sessions when the networks move.
use std::io;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use veilway_transport::Hook;

/// The hook for the engine's sockets. `physical` is the index of the interface, 0 while there is none, and then a socket is refused and the attempt ends as offline.
pub fn hook(physical: Arc<AtomicU32>) -> Hook {
	Arc::new(move |socket| {
		let Some(index) = NonZeroU32::new(physical.load(Ordering::Relaxed)) else {return Err(io::Error::new(io::ErrorKind::NotConnected, "the device has no network outside the tunnel"))};
		// The option exists on an IPv6 socket and only there, which is how the family of a socket that is not bound yet is told.
		if socket.only_v6().is_ok() {
			socket.bind_device_by_index_v6(Some(index))?;
			// A dual-stack socket reaches IPv4 destinations too. The system may refuse the IPv4 option on it, which then is not needed.
			let _ = socket.bind_device_by_index_v4(Some(index));
			Ok(())
		} else {
			socket.bind_device_by_index_v4(Some(index))
		}
	})
}
