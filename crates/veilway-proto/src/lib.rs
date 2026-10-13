//! Wire formats of the Veilway protocol, as pure code: no sockets, no clocks and no randomness of its own. Time and random bytes are parameters.
//!
//! Only the parts the protocol overview lists as "Settled enough to implement" are here: the keys (`keys`), chunk framing and padding (`chunk`), the control channel's messages (`control`) with its opening exchange (`opening`), the timer table (`session`), the stream proof (`proof`), the packets of `udp-obfs` (`udp_obfs`), the replay rule and the replay file (`replay`), the request line of a stream listener (`request`) and the bodies of `fronted` (`fronted`), and of the subscription format the link, the signed document, the request and what a client decides (`subscription`). There is no listener, no socket and no file here. The specification is a draft that nobody outside the project has reviewed, so nothing here is a security claim.
#![forbid(unsafe_code)]

pub mod chunk;
pub mod control;
pub mod fronted;
pub mod keys;
pub mod opening;
pub mod proof;
pub mod replay;
pub mod request;
pub mod session;
pub mod subscription;
pub mod udp_obfs;

/// The one answer to everything that is not a valid proof, opening packet or data packet for this node. It says nothing about the cause, and a caller must not try to learn one: a refused stream request takes the unauthenticated path and a refused datagram is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

impl std::fmt::Display for Refused {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.write_str("refused")}
}

impl std::error::Error for Refused {}

/// The caller's random source failed, or kept giving values that no uniform draw could use, or a draw was asked from a range that holds no number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoRandom;

impl std::fmt::Display for NoRandom {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.write_str("no random bytes")}
}

impl std::error::Error for NoRandom {}

/// Where every random byte of this crate comes from: a function that fills the slice it is given. In production it must be the system's secure source. Tests pass a fixed sequence.
pub type Random<'a> = dyn FnMut(&mut [u8]) -> Result<(), NoRandom> + 'a;

/// A number drawn uniformly from `low` to `high`, both included, which is how every range of the specification is read ("uniform 0 to 63 bytes" has 64 outcomes).
/// Values that would favour the low end of the range are drawn again, so the result has no modulo bias. A range with `low` above `high` is an error and draws nothing.
pub fn uniform(low: u32, high: u32, random: &mut Random) -> Result<u32, NoRandom> {
	if low > high {return Err(NoRandom)}
	let span = u64::from(high - low) + 1;
	let limit = (1u64 << 32) / span * span;
	// A working source is refused with probability below one half per draw, so 64 refusals in a row mean it is broken.
	for _ in 0..64 {
		let mut bytes = [0; 4];
		random(&mut bytes)?;
		let value = u64::from(u32::from_be_bytes(bytes));
		if value < limit {return Ok(low + (value % span) as u32)}
	}
	Err(NoRandom)
}

// The cryptographic operations of the node-side openers, in the order they ran on this thread. A timing test is not possible in unit tests, so the tests of `proof` and `udp_obfs` compare these sequences instead: every refusal must show the same one as an accepted input.
#[cfg(test)]
pub(crate) mod trace {
	use std::cell::RefCell;

	thread_local! {static OPS: RefCell<Vec<&'static str>> = const {RefCell::new(Vec::new())};}

	pub(crate) fn op(name: &'static str) {OPS.with_borrow_mut(|ops| ops.push(name))}

	pub(crate) fn take() -> Vec<&'static str> {OPS.take()}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_draw_stays_in_its_range_and_reaches_both_ends() {
		let mut state = 0x9e3779b97f4a7c15u64;
		let mut random = |bytes: &mut [u8]| {
			for byte in bytes {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*byte = state as u8;
			}
			Ok(())
		};
		let mut seen = [false; 7];
		for _ in 0..2000 {
			let value = uniform(3, 9, &mut random).unwrap();
			assert!((3..=9).contains(&value));
			seen[(value - 3) as usize] = true;
		}
		assert_eq!(seen, [true; 7]);
		assert_eq!(uniform(5, 5, &mut random), Ok(5));
		assert_eq!(uniform(0, u32::MAX, &mut |bytes: &mut [u8]| {bytes.fill(0xff); Ok(())}), Ok(u32::MAX));
	}

	#[test]
	fn a_source_that_fails_or_is_stuck_is_an_error() {
		assert_eq!(uniform(0, 9, &mut |_: &mut [u8]| Err(NoRandom)), Err(NoRandom));
		assert_eq!(uniform(0, 9, &mut |bytes: &mut [u8]| {bytes.fill(0xff); Ok(())}), Err(NoRandom));
		assert_eq!(uniform(0, 9, &mut |bytes: &mut [u8]| {bytes.copy_from_slice(&[0, 0, 0, 27]); Ok(())}), Ok(7));
		// A range that holds no number is refused before a byte is drawn.
		assert_eq!(uniform(9, 3, &mut |_: &mut [u8]| panic!("a draw from an empty range")), Err(NoRandom));
		assert_eq!(crate::session::delay(&std::ops::RangeInclusive::new(9, 3), &mut |_: &mut [u8]| panic!("a draw from an empty range")), Err(NoRandom));
	}
}
