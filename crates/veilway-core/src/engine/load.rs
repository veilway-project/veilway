//! The load level of an exit, which the control channel tells devices ("Coarse on purpose").
//! The node looks every `EVERY`. A level changes only after the new one held for two looks in a row, so a value that crosses a threshold and comes back does not flap.
//! The first look that has a value sets the level at once. A look with no setting forgets everything.
use crate::config::{Load, LoadBy};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use veilway_proto::control::Load as Level;

/// How often the node looks.
pub const EVERY: Duration = Duration::from_secs(10);
/// The throughput of `LoadBy::Mbps` is taken over this many looks, which is 30 seconds.
const WINDOW: usize = 4;

#[derive(Default)]
struct Track {
	/// (seconds, bytes in both directions) of the last looks.
	samples: VecDeque<(u64, u64)>,
	/// The level the last look wanted, when it was not the one shown.
	pending: Option<Level>,
}

/// What the node keeps of one exit's load. It belongs to the exit's tag, like `ExitState`.
#[derive(Default)]
pub struct Meter {
	shown: AtomicU8,
	track: Mutex<Track>,
}

impl Meter {
	pub fn level(&self) -> Level {
		let shown = self.shown.load(Ordering::Relaxed);
		Level::ALL.iter().copied().find(|level| *level as u8 == shown).unwrap_or(Level::Unknown)
	}

	/// The level as the API says it: None while the exit has none to show.
	pub fn name(&self) -> Option<&'static str> {
		match self.level() {
			Level::Unknown => None,
			Level::Low => Some("low"),
			Level::Medium => Some("medium"),
			Level::High => Some("high"),
		}
	}

	/// One look at second `at`: the flows open on the exit and the bytes it has carried in both directions since start. Gives the level that is shown from here on.
	pub fn sample(&self, setting: Option<&Load>, at: u64, flows: u64, bytes: u64) -> Level {
		let mut track = self.track.lock().unwrap_or_else(|e| e.into_inner());
		let Some(setting) = setting else {
			*track = Track::default();
			self.shown.store(Level::Unknown as u8, Ordering::Relaxed);
			return Level::Unknown;
		};
		let value = match setting.by {
			LoadBy::Flows => {
				track.samples.clear();
				Some(flows)
			}
			LoadBy::Mbps => {
				track.samples.push_back((at, bytes));
				while track.samples.len() > WINDOW {track.samples.pop_front();}
				track.samples.front().filter(|(then, _)| at > *then).map(|(then, was)| bytes.saturating_sub(*was).saturating_mul(8) / 1_000_000 / (at - then))
			}
		};
		let shown = self.level();
		let Some(raw) = value.map(|value| if value >= u64::from(setting.very_busy) {Level::High} else if value >= u64::from(setting.busy) {Level::Medium} else {Level::Low}) else {return shown};
		if raw == shown {track.pending = None}
		else if shown == Level::Unknown || track.pending == Some(raw) {
			track.pending = None;
			self.shown.store(raw as u8, Ordering::Relaxed);
			return raw;
		} else {track.pending = Some(raw)}
		shown
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn by(by: LoadBy) -> Load {Load {by, busy: 10, very_busy: 50}}

	#[test]
	fn a_level_changes_after_two_looks_and_never_flaps() {
		let (meter, setting) = (Meter::default(), by(LoadBy::Flows));
		let mut seen = Vec::new();
		for (at, flows) in [(10, 5), (20, 12), (30, 5), (40, 12), (50, 12), (60, 60), (70, 5), (80, 60), (90, 60), (100, 3), (110, 3)] {seen.push(meter.sample(Some(&setting), at, flows, 0))}
		assert_eq!(seen, [Level::Low, Level::Low, Level::Low, Level::Low, Level::Medium, Level::Medium, Level::Medium, Level::Medium, Level::High, Level::High, Level::Low]);
	}

	#[test]
	fn the_first_look_with_a_value_is_shown_at_once() {
		let meter = Meter::default();
		assert_eq!((meter.level(), meter.sample(Some(&by(LoadBy::Flows)), 10, 80, 0), meter.name()), (Level::Unknown, Level::High, Some("high")));
	}

	#[test]
	fn throughput_is_taken_over_thirty_seconds() {
		let (meter, setting) = (Meter::default(), by(LoadBy::Mbps));
		let mbit = |n: u64| n * 125_000;
		assert_eq!(meter.sample(Some(&setting), 0, 0, 0), Level::Unknown, "one look has no rate yet");
		assert_eq!(meter.sample(Some(&setting), 10, 0, mbit(100)), Level::Medium, "10 Mbit/s over 10 s is the busy threshold");
		assert_eq!(meter.sample(Some(&setting), 20, 0, mbit(200)), Level::Medium);
		assert_eq!(meter.sample(Some(&setting), 30, 0, mbit(200)), Level::Medium, "6 Mbit/s over the window, the first look that wants low");
		assert_eq!(meter.sample(Some(&setting), 40, 0, mbit(200)), Level::Low, "3 Mbit/s over the window, the second look that wants low");
	}

	#[test]
	fn no_setting_forgets_the_level() {
		let meter = Meter::default();
		meter.sample(Some(&by(LoadBy::Flows)), 10, 80, 0);
		assert_eq!((meter.sample(None, 20, 80, 0), meter.name()), (Level::Unknown, None));
	}
}
