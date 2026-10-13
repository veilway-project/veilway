//! Wire formats of the Veilway protocol, as pure code: no sockets, no clocks and no randomness of its own. Time and random bytes are parameters.
//!
//! Only the parts the protocol overview lists as "Settled enough to implement" are here: the control key (`keys`), chunk framing and padding (`chunk`), the control channel's messages (`control`) with its opening exchange (`opening`), and the timer table (`session`). The specification is a draft that nobody outside the project has reviewed, so nothing here is a security claim.
#![forbid(unsafe_code)]

pub mod chunk;
pub mod control;
pub mod keys;
pub mod opening;
pub mod session;

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
