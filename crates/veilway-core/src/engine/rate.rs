//! Speed limits of a user, one bucket for each direction that all of the user's devices, sessions and doors share.
//! A bucket is one atomic, the time at which the user's rate has caught up with what they sent (GCRA), so a take costs a compare-and-swap and a user without a limit costs a branch.
//! The burst is one second of the rate and at least `MIN_BURST` bytes, and has no setting.
//! Where the node holds the TCP stream it paces: the stream is read slower, so the sender's window closes and nothing is lost. Where it only sees packets it polices: a packet over the rate is dropped.
//! The control channel, DNS and what the node answers itself are charged and never dropped, see `Shared::charge`.
use super::plan::User;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// The least a burst may be, in bytes: one full-size packet and a little more, so that a slow rate still carries whole packets.
pub const MIN_BURST: u64 = 65536;
const NS: u64 = 1_000_000_000;
/// How much of a stream is read before the bucket is asked, when a limit paces it.
const CHUNK: usize = 16384;

/// What a user's limits keep while the node runs. It belongs to the user's name, like the rest of `UserState`: a reload keeps it, and a new rate is held to from the next take on, whatever the old rate left in the bucket.
/// Index 0 is up (from the device) and 1 is down.
pub struct Speed {
	origin: Instant,
	/// Nanoseconds since `origin` at which the user's rate has caught up with what they sent. Past `now` means debt.
	tat: [AtomicU64; 2],
	/// Packets dropped for the rate, by direction.
	pub limited: [AtomicU64; 2],
	/// Nanoseconds that paced streams waited, summed over connections and both directions. A wait is often well under a millisecond, so it is not kept in milliseconds.
	pub paced_ns: AtomicU64,
}

impl Default for Speed {
	fn default() -> Speed {Speed {origin: Instant::now(), tat: Default::default(), limited: Default::default(), paced_ns: AtomicU64::new(0)}}
}

impl Speed {
	pub fn now(&self) -> u64 {self.origin.elapsed().as_nanos() as u64}

	/// How long a burst lasts at `rate`, in nanoseconds.
	fn burst(rate: u64) -> u64 {rate.max(MIN_BURST).saturating_mul(NS) / rate}

	fn cost(rate: u64, bytes: usize) -> u64 {(bytes as u64).saturating_mul(NS) / rate}

	/// Police: whether `bytes` fit the rate at `now`. When they do the bucket is charged, and when not it is left alone. A bucket that holds more debt than a burst allows, as after a lower rate, counts as a full one.
	pub fn take_at(&self, now: u64, up: bool, rate: u64, bytes: usize) -> bool {
		let (bucket, burst) = (&self.tat[usize::from(!up)], Speed::burst(rate));
		let (cost, mut stored) = (Speed::cost(rate, bytes).min(burst), bucket.load(Ordering::Relaxed));
		loop {
			let new = stored.max(now).min(now.saturating_add(burst)) + cost;
			if new > now.saturating_add(burst) {return false}
			match bucket.compare_exchange_weak(stored, new, Ordering::Relaxed, Ordering::Relaxed) {
				Ok(_) => return true,
				Err(seen) => stored = seen,
			}
		}
	}

	/// Moves the bucket to `next(stored)` and gives back what it held, which is what `force_at` and `wait_at` both do.
	fn shift(&self, up: bool, next: impl Fn(u64) -> u64) -> u64 {
		let bucket = &self.tat[usize::from(!up)];
		let mut stored = bucket.load(Ordering::Relaxed);
		loop {
			match bucket.compare_exchange_weak(stored, next(stored), Ordering::Relaxed, Ordering::Relaxed) {
				Ok(before) => return before,
				Err(seen) => stored = seen,
			}
		}
	}

	/// Charges `bytes` that may not be dropped. The debt stops at a full burst, so a user who only resolves names and keeps the control channel up never owes more than the next packet has to wait for.
	pub fn force_at(&self, now: u64, up: bool, rate: u64, bytes: usize) {
		let (burst, cost) = (Speed::burst(rate), Speed::cost(rate, bytes));
		self.shift(up, |stored| (stored.max(now) + cost).min(now.saturating_add(burst)).max(stored));
	}

	/// Pace: charges `bytes` and says how long the caller waits before sending them. The first burst goes at once.
	pub fn wait_at(&self, now: u64, up: bool, rate: u64, bytes: usize) -> Duration {
		let cost = Speed::cost(rate, bytes);
		let before = self.shift(up, |stored| stored.max(now) + cost);
		Duration::from_nanos((before.max(now) + cost).saturating_sub(Speed::burst(rate)).saturating_sub(now))
	}
}

/// Waits until a stream of `user` may send `bytes` in the direction `up`, and not at all for a user without a limit that way.
pub async fn pace(user: &User, up: bool, bytes: usize) {
	let Some(rate) = user.speed[usize::from(!up)] else {return};
	let wait = user.state.speed.wait_at(user.state.speed.now(), up, rate, bytes);
	if wait.is_zero() {return}
	user.state.speed.paced_ns.fetch_add(wait.as_nanos() as u64, Ordering::Relaxed);
	tokio::time::sleep(wait).await
}

/// Carries bytes both ways between a device's stream and the connection the node made for it, like `copy_bidirectional`, and slower when the user has a limit: each chunk waits for the bucket before it is written. Without one it is `copy_bidirectional` itself.
pub async fn relay<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(device: &mut A, remote: &mut B, user: &User) -> io::Result<(u64, u64)> {
	if user.speed == [None, None] {return tokio::io::copy_bidirectional(device, remote).await}
	let ((mut from_device, mut to_device), (mut from_remote, mut to_remote)) = (tokio::io::split(device), tokio::io::split(remote));
	tokio::try_join!(pour(&mut from_device, &mut to_remote, user, true), pour(&mut from_remote, &mut to_device, user, false))
}

async fn pour<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(from: &mut R, to: &mut W, user: &User, up: bool) -> io::Result<u64> {
	let (mut buffer, mut total) = (vec![0u8; CHUNK], 0);
	loop {
		let n = from.read(&mut buffer).await?;
		if n == 0 {
			to.shutdown().await?;
			return Ok(total);
		}
		pace(user, up, n).await;
		to.write_all(&buffer[..n]).await?;
		total += n as u64;
	}
}

#[cfg(test)]
mod tests {
	use super::{pace, relay, Speed, MIN_BURST, NS};
	use crate::engine::plan::User;
	use crate::engine::UserState;
	use std::sync::atomic::Ordering;
	use std::sync::Arc;
	use std::time::Duration;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	const RATE: u64 = 1_000_000;

	fn user(speed: [Option<u64>; 2]) -> User {
		User {name: "u".to_string(), groups: Vec::new(), entitled: None, exit: None, dns: None, quota: None, period: None, expires: None, denied: None, state: Arc::new(UserState::default()), link: None, flows: 1, proxy: None, speed}
	}

	#[test]
	fn a_full_bucket_takes_a_burst_and_then_nothing_until_time_passes() {
		let speed = Speed::default();
		assert!(speed.take_at(NS, true, RATE, 600_000));
		assert!(speed.take_at(NS, true, RATE, 400_000));
		assert!(!speed.take_at(NS, true, RATE, 1));
		assert!(!speed.take_at(NS + NS / 1000 - 1, true, RATE, 1100));
		assert!(speed.take_at(NS + NS / 1000, true, RATE, 1000));
		assert!(!speed.take_at(NS + NS / 1000, true, RATE, 1));
	}

	#[test]
	fn a_slow_rate_still_has_the_least_burst() {
		let speed = Speed::default();
		assert!(speed.take_at(NS, false, 16384, MIN_BURST as usize));
		assert!(!speed.take_at(NS, false, 16384, 1));
		assert!(speed.take_at(5 * NS, false, 16384, MIN_BURST as usize));
	}

	#[test]
	fn directions_have_buckets_of_their_own() {
		let speed = Speed::default();
		assert!(speed.take_at(NS, true, RATE, 1_000_000));
		assert!(!speed.take_at(NS, true, RATE, 1));
		assert!(speed.take_at(NS, false, RATE, 1_000_000));
	}

	#[test]
	fn idle_time_does_not_save_up_more_than_a_burst() {
		let speed = Speed::default();
		assert!(speed.take_at(10 * NS, true, RATE, 1_000_000));
		assert!(!speed.take_at(10 * NS, true, RATE, 1));
		assert!(speed.take_at(1000 * NS, true, RATE, 1_000_000));
		assert!(!speed.take_at(1000 * NS, true, RATE, 1));
	}

	#[test]
	fn a_packet_over_the_whole_burst_is_held_to_the_burst() {
		let speed = Speed::default();
		assert!(speed.take_at(NS, true, RATE, 5_000_000));
		assert!(!speed.take_at(NS, true, RATE, 1));
	}

	#[test]
	fn concurrent_takes_never_get_more_than_the_burst() {
		let speed = Arc::new(Speed::default());
		let threads: Vec<_> = (0..8).map(|_| {
			let speed = speed.clone();
			std::thread::spawn(move || (0..10_000).filter(|_| speed.take_at(NS, true, RATE, 100)).count() as u64 * 100)
		}).collect();
		assert_eq!(threads.into_iter().map(|thread| thread.join().unwrap()).sum::<u64>(), 1_000_000);
	}

	#[test]
	fn a_lower_rate_counts_the_debt_of_the_old_one_as_at_most_a_burst() {
		let speed = Speed::default();
		assert!(speed.take_at(NS, true, 100_000_000, 100_000_000));
		assert!(!speed.take_at(NS, true, 100_000_000, 1));
		assert!(!speed.take_at(NS, true, RATE, 1));
		assert!(speed.take_at(2 * NS, true, RATE, 1_000_000));
	}

	#[test]
	fn a_higher_rate_lets_the_next_take_through_sooner() {
		let speed = Speed::default();
		assert!(speed.take_at(NS, true, RATE, 1_000_000));
		assert!(!speed.take_at(NS + NS / 100, true, RATE, 100_000));
		assert!(speed.take_at(NS + NS / 100, true, 100 * RATE, 100_000));
	}

	#[test]
	fn a_forced_charge_is_never_refused_and_takes_what_is_left() {
		let speed = Speed::default();
		speed.force_at(NS, true, RATE, 400_000);
		assert!(speed.take_at(NS, true, RATE, 600_000));
		speed.force_at(NS, true, RATE, 5_000_000);
		assert!(!speed.take_at(NS, true, RATE, 1));
		speed.force_at(NS, true, RATE, 1);
		assert!(speed.take_at(2 * NS, true, RATE, 1_000_000));
	}

	#[test]
	fn the_pace_wait_is_the_debt_beyond_the_burst() {
		let speed = Speed::default();
		assert_eq!(speed.wait_at(NS, true, RATE, 1_000_000), Duration::ZERO);
		assert_eq!(speed.wait_at(NS, true, RATE, 500_000), Duration::from_millis(500));
		assert_eq!(speed.wait_at(NS, true, RATE, 500_000), Duration::from_millis(1000));
		assert_eq!(speed.wait_at(NS + NS / 2, true, RATE, 0), Duration::from_millis(500));
	}

	#[tokio::test(start_paused = true)]
	async fn pace_sleeps_for_the_wait_and_counts_it() {
		let user = user([Some(RATE), None]);
		let begun = tokio::time::Instant::now();
		pace(&user, true, 1_000_000).await;
		assert_eq!(begun.elapsed(), Duration::ZERO);
		pace(&user, true, 1_000_000).await;
		assert_eq!(begun.elapsed(), Duration::from_secs(1));
		pace(&user, false, 5_000_000).await;
		assert_eq!(begun.elapsed(), Duration::from_secs(1));
		assert_eq!(user.state.speed.paced_ns.load(Ordering::Relaxed), 1_000_000_000);
	}

	#[tokio::test(start_paused = true)]
	async fn a_paced_relay_moves_every_byte_at_the_rate_and_ends_both_sides() {
		let user = user([None, Some(RATE)]);
		let ((mut device, mut node_device), (mut node_remote, mut remote)) = (tokio::io::duplex(1 << 20), tokio::io::duplex(1 << 20));
		let begun = tokio::time::Instant::now();
		let carried = tokio::spawn(async move {relay(&mut node_device, &mut node_remote, &user).await.unwrap()});
		tokio::spawn(async move {
			remote.write_all(&vec![7u8; 3_000_000]).await.unwrap();
			remote.shutdown().await.unwrap();
		});
		let mut got = Vec::new();
		device.read_to_end(&mut got).await.unwrap();
		device.shutdown().await.unwrap();
		assert_eq!(got.len(), 3_000_000);
		assert_eq!(carried.await.unwrap(), (0, 3_000_000));
		assert!(begun.elapsed() >= Duration::from_millis(1900) && begun.elapsed() <= Duration::from_millis(2100), "{:?}", begun.elapsed());
	}
}
