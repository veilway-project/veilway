//! The send queue of a session, with a limit on how long a datagram waits in it. A queue that only drops when it is full lets a
//! stream session hold seconds of traffic behind a slow path, and every flow inside then waits that long for its answers. This
//! keeps the wait near `TARGET` with CoDel (RFC 8289): once datagrams have waited longer than `TARGET` for a whole `INTERVAL`,
//! one is dropped where it leaves the queue, and the drops come closer together while the wait stays high. The flows inside see
//! a loss and slow down, at a queue of milliseconds and not of seconds. What a datagram is exempt from is the caller's to say:
//! handshakes, probes and the control channel are never dropped for their wait.

use std::time::Duration;

use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::time::Instant;

/// The wait a queue settles at under load.
pub const TARGET: Duration = Duration::from_millis(25);
/// How long the wait has to stay above `TARGET` before the first drop, and the start of the spacing between drops.
pub const INTERVAL: Duration = Duration::from_millis(100);

/// The bytes a stream connection lets the system hold unsent (`TCP_NOTSENT_LOWAT`, Linux and Android). Without it a socket's buffer, which grows to megabytes, is where datagrams wait, and their wait there is never seen.
pub const UNSENT: u32 = 16_384;

/// The receiving half of a send queue. `recv` and `try_recv` hand out what may still be sent and drop what waited too long.
pub struct Outbox<T> {
	queue: mpsc::Receiver<(T, Instant)>,
	exempt: fn(&T) -> bool,
	dropped: Box<dyn Fn() + Send + Sync>,
	codel: Codel,
}

/// A send queue of `size` items. The sender stamps each item with `Instant::now()` when it puts it in. `dropped` is called once for every item dropped for its wait.
pub fn channel<T>(size: usize, exempt: fn(&T) -> bool, dropped: Box<dyn Fn() + Send + Sync>) -> (mpsc::Sender<(T, Instant)>, Outbox<T>) {
	let (sender, queue) = mpsc::channel(size);
	(sender, Outbox {queue, exempt, dropped, codel: Codel::default()})
}

impl<T> Outbox<T> {
	/// The next item that may be sent, `None` once every sender is gone. Cancel safe: an item is dropped only between two waits.
	pub async fn recv(&mut self) -> Option<T> {
		loop {
			let (item, at) = self.queue.recv().await?;
			if (self.exempt)(&item) || self.codel.keep(Instant::now(), at, self.queue.is_empty()) {return Some(item)}
			(self.dropped)();
		}
	}

	pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
		loop {
			let (item, at) = self.queue.try_recv()?;
			if (self.exempt)(&item) || self.codel.keep(Instant::now(), at, self.queue.is_empty()) {return Ok(item)}
			(self.dropped)();
		}
	}
}

/// CoDel's state (RFC 8289 5): when the wait first stayed above the target, whether the queue is dropping, the time of its next drop, and how many it dropped this time and last time.
#[derive(Default)]
struct Codel {first_above: Option<Instant>, dropping: bool, drop_next: Option<Instant>, count: u32, last: u32}

impl Codel {
	/// Whether the item that went in at `at` and leaves at `now` is sent. `empty` says it was the last one waiting: a queue that empties is not standing, so it never drops.
	fn keep(&mut self, now: Instant, at: Instant, empty: bool) -> bool {
		let late = if now.saturating_duration_since(at) < TARGET || empty {
			self.first_above = None;
			false
		} else {
			let first = *self.first_above.get_or_insert(now + INTERVAL);
			now >= first
		};
		let next = |from: Instant, count: u32| from + INTERVAL.div_f64(f64::from(count.max(1)).sqrt());
		if self.dropping {
			if !late {
				self.dropping = false;
				return true;
			}
			let due = self.drop_next.unwrap_or(now);
			if now < due {return true}
			self.count = self.count.saturating_add(1);
			self.drop_next = Some(next(due, self.count));
			return false;
		}
		if !late {return true}
		// "If the queue was dropping a short while ago, start at the drop rate it had then, not at the start."
		let delta = self.count.saturating_sub(self.last);
		self.count = if delta > 1 && self.drop_next.is_some_and(|at| now.saturating_duration_since(at) < 16 * INTERVAL) {delta} else {1};
		(self.last, self.dropping, self.drop_next) = (self.count, true, Some(next(now, self.count)));
		false
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_queue_that_stays_short_never_drops() {
		let (mut codel, start) = (Codel::default(), Instant::now());
		assert!((0..1000u64).all(|ms| codel.keep(start + Duration::from_millis(ms), start + Duration::from_millis(ms.saturating_sub(20)), false)));
	}

	#[test]
	fn a_standing_queue_drops_after_one_interval_and_then_more_often() {
		let (mut codel, start) = (Codel::default(), Instant::now());
		// Every item has waited 200 ms, one leaves each millisecond.
		let dropped: Vec<u64> = (0..1000u64).filter(|ms| !codel.keep(start + Duration::from_millis(*ms), (start + Duration::from_millis(*ms)).checked_sub(Duration::from_millis(200)).unwrap_or(start), false)).collect();
		assert_eq!(dropped.first(), Some(&100), "the first drop comes one interval after the wait went above the target");
		let gaps: Vec<u64> = dropped.windows(2).map(|pair| pair[1] - pair[0]).collect();
		assert!(gaps.len() > 3 && gaps[gaps.len() - 1] < gaps[0] / 2, "the drops come closer together: {gaps:?}");
		assert!(dropped.len() > 5 && dropped.len() < 100, "{}", dropped.len());
	}

	#[test]
	fn the_last_item_and_a_short_wait_end_the_dropping() {
		let (mut codel, start) = (Codel::default(), Instant::now());
		let old = |ms: u64| start + Duration::from_millis(ms) - Duration::from_millis(50).min(Duration::from_millis(ms));
		for ms in 0..=130 {codel.keep(start + Duration::from_millis(ms), old(ms), false);}
		assert!(codel.dropping);
		assert!(codel.keep(start + Duration::from_millis(131), old(131), true), "a queue that empties is not standing");
		assert!(!codel.dropping);
		assert!(codel.keep(start + Duration::from_millis(500), start + Duration::from_millis(495), false));
	}

	#[tokio::test]
	async fn exempt_items_pass_whatever_their_wait() {
		let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
		let counted = count.clone();
		let (sender, mut outbox) = channel::<(u8, bool)>(16, |item| item.1, Box::new(move || {counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);}));
		let long_ago = Instant::now() - Duration::from_secs(5);
		outbox.codel.first_above = Some(long_ago);
		for item in [(1, true), (2, false), (3, true), (4, false), (5, false)] {sender.try_send((item, long_ago)).unwrap();}
		let mut got = Vec::new();
		while let Ok(item) = outbox.try_recv() {got.push(item.0)}
		assert!(got.contains(&1) && got.contains(&3), "{got:?}");
		assert_eq!(got.len() as u64 + count.load(std::sync::atomic::Ordering::Relaxed), 5);
		assert!(count.load(std::sync::atomic::Ordering::Relaxed) >= 1);
	}
}
