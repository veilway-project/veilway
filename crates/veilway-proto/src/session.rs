//! Session activity and timers (transports page, "Session activity and timers"): the one copy of the table and of the definition of activity, for the engine and the client. Nothing here runs a timer.
use crate::{uniform, NoRandom, Random};
use std::{ops::RangeInclusive, time::Duration};

/// "First tunnel packet deadline: 10 s after the proof was accepted." A pending session that is not established by then is ended.
pub const FIRST_PACKET: Duration = Duration::from_secs(10);
/// "A device may have 2 pending sessions, and further proofs are refused while it has."
pub const PENDING: usize = 2;
/// "Client liveness limit": an idle keepalive (or a `fronted` request) that got nothing back within this time means the session is lost.
pub const LIVENESS: Duration = Duration::from_secs(10);
/// The client's idle keepalive goes out after a send silence drawn from this range, in milliseconds, unless the profile sets another.
pub const KEEPALIVE: RangeInclusive<u32> = 20_000..=40_000;
/// The bounds inside which a profile may set the idle keepalive range, in milliseconds.
pub const KEEPALIVE_BOUNDS: RangeInclusive<u32> = 10_000..=60_000;
/// The node's echo of a lone keepalive goes out after a delay drawn from this range, in milliseconds.
pub const ECHO: RangeInclusive<u32> = 0..=3_000;
/// A chunk that would hold exactly one WireGuard keepalive is held back for a delay drawn from this range, in milliseconds.
pub const LONE_KEEPALIVE: RangeInclusive<u32> = 0..=3_000;
/// The client starts a new WireGuard handshake when it sends on a tunnel whose last handshake is older than a time drawn from this range, in milliseconds.
pub const REKEY: RangeInclusive<u32> = 60_000..=110_000;

/// The obfuscated transports, as far as their timers differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {UdpObfs, Tls, Ws, Fronted}

impl Transport {
	/// "The node ends a session with no activity for" this long.
	pub fn idle(self) -> Duration {
		Duration::from_secs(match self {
			Self::UdpObfs => 180,
			Self::Tls | Self::Ws => 300,
			Self::Fronted => 60,
		})
	}
	/// Whether the transport has the client's idle keepalive and the node's echo. `fronted` has neither: its polling is the activity.
	pub fn keepalive(self) -> bool {self != Self::Fronted}
	/// "A session is active at a moment when the receiver accepts from it a chunk that cannot be a replay."
	/// `opened` says a chunk opened at the expected number on `tls` and `ws`. On `fronted` it says a request was accepted, which this crate cannot tell yet: `chunk::Opener` does not do what a `fronted` body needs. `wireguard` says the chunk held a WireGuard packet that authenticated, which is the only thing that counts on `udp-obfs`, where a recorded chunk opens again.
	pub fn activity(self, opened: bool, wireguard: bool) -> bool {opened && (wireguard || self != Self::UdpObfs)}
}

/// A delay drawn uniformly from one of the ranges above. The table gives its ranges in seconds and milliseconds without a step: draws are made in whole milliseconds.
pub fn delay(range: &RangeInclusive<u32>, random: &mut Random) -> Result<Duration, NoRandom> {Ok(Duration::from_millis(uniform(*range.start(), *range.end(), random)?.into()))}

/// The idle keepalive range of a profile, in milliseconds, if it is one a profile may set: not empty and inside `KEEPALIVE_BOUNDS`.
pub fn keepalive(range: RangeInclusive<u32>) -> Option<RangeInclusive<u32>> {(range.start() <= range.end() && KEEPALIVE_BOUNDS.contains(range.start()) && KEEPALIVE_BOUNDS.contains(range.end())).then_some(range)}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_table() {
		assert_eq!([Transport::UdpObfs, Transport::Tls, Transport::Ws, Transport::Fronted].map(|transport| (transport.idle().as_secs(), transport.keepalive())), [(180, true), (300, true), (300, true), (60, false)]);
		// "The longest keepalive range a profile may set, 60 s, is well below the shortest idle time of a transport that uses keepalives, 180 s."
		assert!(Duration::from_millis((*KEEPALIVE_BOUNDS.end()).into()) < Transport::UdpObfs.idle());
		assert!(KEEPALIVE_BOUNDS.contains(KEEPALIVE.start()) && KEEPALIVE_BOUNDS.contains(KEEPALIVE.end()));
	}

	#[test]
	fn activity_is_a_chunk_that_cannot_be_a_replay() {
		for transport in [Transport::Tls, Transport::Ws, Transport::Fronted] {
			assert!(transport.activity(true, false) && transport.activity(true, true));
			assert!(!transport.activity(false, false) && !transport.activity(false, true));
		}
		assert!(Transport::UdpObfs.activity(true, true));
		assert!(!Transport::UdpObfs.activity(true, false) && !Transport::UdpObfs.activity(false, true) && !Transport::UdpObfs.activity(false, false));
	}

	#[test]
	fn delays_and_profile_ranges() {
		let mut top = |bytes: &mut [u8]| {
			bytes.copy_from_slice(&20_000u32.to_be_bytes());
			Ok(())
		};
		assert_eq!(delay(&KEEPALIVE, &mut top), Ok(Duration::from_secs(40)));
		assert_eq!(delay(&ECHO, &mut top), Ok(Duration::from_millis(20_000 % 3_001)));
		assert_eq!(keepalive(10_000..=60_000), Some(10_000..=60_000));
		assert_eq!(keepalive(30_000..=30_000), Some(30_000..=30_000));
		assert_eq!([keepalive(9_999..=60_000), keepalive(10_000..=60_001), keepalive(RangeInclusive::new(40_000, 20_000))], [None, None, None]);
	}
}
