//! The device's side of MTU discovery (control channel page, "MTU discovery"): which probe goes out when, and what a size is worth, as a state machine with no socket, no clock and no random source of its own.
//!
//! The method is RFC 8899's. A size works only when a probe of that size was confirmed in both directions. The profile's `mtu` is probed first, so a path that carries it costs two probes. Otherwise the walk goes down the table of sizes below it, and a size fails after a lost probe and one lost retry. The result is the largest size that passed both ways. If even 1280 fails, this transport does not work on this path and the engine moves on under the rules of transport fallback.
//! A remembered size (7 days, per network and transport) is confirmed first with one probe in each direction, and a confirmation that fails starts the walk from the top of the table. The node answers a run of probes at most once a minute and takes at most 16 probes in each direction; the walk is built never to ask for more than that.
//! What the node says is hostile input: a token, a size or a sequence number that is not the one asked for is ignored, and the result is never above the profile's `mtu`, whatever the node says.
use tokio::time::Instant;
use veilway_proto::control::{self, ClientMessage, ErrorCode, NodeMessage, Token, PROBES, PROBE_WAIT};

/// One random byte for each size a walk can probe: the profile's `mtu` and the table below it.
pub const JITTER: usize = control::PROBE_SIZES.len() + 1;

/// What the walk asks its driver to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// A message for the control channel.
	Send(ClientMessage),
	/// A probe packet into the tunnel: the inner IP packet is exactly `size` bytes, with this token and `seq`.
	Probe {token: Token, seq: u8, size: u16},
	/// The run is over.
	Done(Outcome),
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
	/// The tunnel MTU the path carries.
	Found(u16),
	/// The node answered "not applicable": it does not probe on this transport, and the profile's `mtu` stays.
	NotApplicable,
	/// No size down to 1280 passed.
	Failed,
	/// The node is busy with a run or asked too soon, or sent what a node does not: try again in a minute.
	Later,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
	// `probe_start` is out and the token has not come.
	Token,
	// A probe of `size` is out upstream, waiting for `probe_ack`; `retried` says the retry was used.
	Up {retried: bool},
	// A `probe_down` is out, waiting for the packet.
	Down {retried: bool},
	Over,
}

pub struct Walk {
	profile: u16,
	// The tunnel's smallest MTU, from the families of its addresses.
	floor: u16,
	// Sizes still to try, in order, and the one being tried.
	sizes: Vec<u16>,
	size: u16,
	token: Option<Token>,
	seq: u8,
	step: Step,
	up: usize,
	down: usize,
	port: u16,
	due: Option<Instant>,
	remembered: Option<u16>,
	/// Random bytes of this run: each probe of the table is lowered by one of them modulo 17, so the sizes of a walk are not the same fixed list on every device and every path.
	jitter: [u8; JITTER],
}

impl Walk {
	/// Starts a run. `profile` is the signed profile's `mtu`, `floor` the tunnel's smallest MTU, `remembered` the size confirmed first, if one is held, `port` the UDP port the downstream probes come to, and `jitter` random bytes of this run (zeros probe the table's own sizes).
	pub fn start(profile: u16, floor: u16, remembered: Option<u16>, port: u16, jitter: [u8; JITTER], now: Instant) -> (Self, Vec<Action>) {
		let walk = Self {profile, floor, sizes: Vec::new(), size: 0, token: None, seq: 0, step: Step::Token, up: 0, down: 0, port, due: Some(now + PROBE_WAIT * 2), remembered, jitter};
		(walk, vec![Action::Send(ClientMessage::ProbeStart)])
	}
	pub fn port(&self) -> u16 {self.port}
	#[cfg(test)]
	fn is_over(&self) -> bool {self.step == Step::Over}
	pub fn due(&self) -> Option<Instant> {self.due}
	// Ends the run.
	fn end(&mut self, outcome: Outcome) -> Vec<Action> {
		(self.step, self.due) = (Step::Over, None);
		vec![Action::Done(outcome)]
	}
	// The probe upstream for the size in hand, with a fresh `seq`.
	fn up(&mut self, now: Instant, retried: bool) -> Vec<Action> {
		let Some(token) = self.token else {return self.end(Outcome::Later)};
		if self.up >= PROBES {return self.end(Outcome::Failed)}
		(self.seq, self.up, self.step, self.due) = (self.seq.wrapping_add(1), self.up + 1, Step::Up {retried}, Some(now + self.wait()));
		vec![Action::Probe {token, seq: self.seq, size: self.size}]
	}
	fn down(&mut self, now: Instant, retried: bool) -> Vec<Action> {
		if self.down >= PROBES {return self.end(Outcome::Failed)}
		(self.seq, self.down, self.step, self.due) = (self.seq.wrapping_add(1), self.down + 1, Step::Down {retried}, Some(now + self.wait()));
		vec![Action::Send(ClientMessage::ProbeDown {seq: self.seq, size: self.size, port: self.port})]
	}
	// The next size of the walk, or the end of it.
	fn next(&mut self, now: Instant) -> Vec<Action> {
		if self.sizes.is_empty() {return self.end(Outcome::Failed)}
		self.size = self.sizes.remove(0);
		self.up(now, false)
	}
	/// What the node said. Anything that is not the answer to the probe in hand is ignored.
	/// The wait for the probe now going out: from three quarters of `PROBE_WAIT` up to all of it, picked from this run's random bytes and the probe's number, so a lost probe is not followed by the same pause every time. Never longer than `PROBE_WAIT`, so a walk still ends inside the node's token life.
	fn wait(&self) -> std::time::Duration {PROBE_WAIT * 3 / 4 + PROBE_WAIT / 4 * u32::from(self.jitter[usize::from(self.seq) % JITTER] ^ self.seq.rotate_left(3)) / 255}
	pub fn message(&mut self, message: &NodeMessage, now: Instant) -> Vec<Action> {
		match (self.step, message) {
			(Step::Token, NodeMessage::ProbeToken {token, max_size}) => {
				self.token = Some(*token);
				let top = self.profile.min(*max_size);
				// The remembered size is confirmed first, and the table below the top follows it.
				// The node takes any size from the floor to its maximum, so each size can come down a little: the profile's own first, then the table's, never below the floor. A remembered size stays as it was confirmed.
				let mut sizes: Vec<u16> = control::probe_sizes(top, self.floor).enumerate().map(|(at, size)| size.saturating_sub(u16::from(self.jitter[at.min(JITTER - 1)] % 17)).max(self.floor)).collect();
				sizes.sort_unstable_by(|a, b| b.cmp(a));
				sizes.dedup();
				if let Some(held) = self.remembered.filter(|held| (self.floor..=top).contains(held)) {sizes.retain(|size| *size != held); sizes.insert(0, held)}
				self.sizes = sizes;
				self.next(now)
			}
			(Step::Token, NodeMessage::Error {code, answers}) if *answers == control::kind::PROBE_START => self.end(if *code == ErrorCode::NotApplicable {Outcome::NotApplicable} else {Outcome::Later}),
			(Step::Up {..}, NodeMessage::ProbeAck {seq, size}) if *seq == self.seq && *size == self.size => self.down(now, false),
			(Step::Up {..} | Step::Down {..}, NodeMessage::Error {code: ErrorCode::NotApplicable | ErrorCode::Busy, answers}) if *answers == control::kind::PROBE_DOWN => self.end(Outcome::Later),
			_ => Vec::new(),
		}
	}
	/// A probe came down the tunnel to the walk's port: the token and `seq` in it, and the size of the whole inner packet.
	pub fn arrived(&mut self, token: &Token, seq: u8, size: u16) -> Vec<Action> {
		if !matches!(self.step, Step::Down {..}) || self.token.as_ref() != Some(token) || seq != self.seq || size != self.size {return Vec::new()}
		let found = self.size;
		self.end(Outcome::Found(found))
	}
	/// Sends again what is overdue: one retry of a probe, then the size has failed.
	pub fn poll(&mut self, now: Instant) -> Vec<Action> {
		if self.due.is_none_or(|due| now < due) {return Vec::new()}
		match self.step {
			Step::Token => self.end(Outcome::Later),
			Step::Up {retried: false} => self.up(now, true),
			Step::Down {retried: false} => self.down(now, true),
			Step::Up {..} | Step::Down {..} => self.next(now),
			Step::Over => Vec::new(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_proto::control::{MTU_MIN, MTU_MIN_V4};

	const TOKEN: Token = Token([7; 8]);

	// Drives a walk against a path that carries packets up to `limit` bytes in each direction, or `up` and `down` separately.
	fn run(profile: u16, floor: u16, remembered: Option<u16>, up_limit: u16, down_limit: u16) -> (Outcome, usize, usize) {
		let mut now = Instant::now();
		let (mut walk, todo) = Walk::start(profile, floor, remembered, 51000, [0; JITTER], now);
		let (mut ups, mut downs) = (0, 0);
		let mut queue = std::collections::VecDeque::from(todo);
		loop {
			let Some(action) = queue.pop_front() else {
				now += PROBE_WAIT;
				queue.extend(walk.poll(now));
				assert!(!walk.is_over() || queue.iter().any(|action| matches!(action, Action::Done(_))), "a walk that ended without a result");
				continue;
			};
			match action {
				Action::Send(ClientMessage::ProbeStart) => queue.extend(walk.message(&NodeMessage::ProbeToken {token: TOKEN, max_size: 1440}, now)),
				Action::Probe {token, seq, size} => {
					assert_eq!(token, TOKEN);
					ups += 1;
					if size <= up_limit {queue.extend(walk.message(&NodeMessage::ProbeAck {seq, size}, now))}
				}
				Action::Send(ClientMessage::ProbeDown {seq, size, port}) => {
					assert_eq!(port, 51000);
					downs += 1;
					if size <= down_limit {queue.extend(walk.arrived(&TOKEN, seq, size))}
				}
				Action::Done(outcome) => return (outcome, ups, downs),
				Action::Send(other) => panic!("{other:?}"),
			}
		}
	}

	#[test]
	fn a_path_that_carries_the_profiles_size_costs_two_probes() {
		assert_eq!(run(1390, MTU_MIN, None, 1500, 1500), (Outcome::Found(1390), 1, 1));
	}

	#[test]
	fn the_walk_goes_down_the_table_and_the_result_is_the_largest_that_passed_both_ways() {
		// 1390 and 1360 pass up and not down, 1320 passes both.
		assert_eq!(run(1390, MTU_MIN, None, 1500, 1330).0, Outcome::Found(1320));
		assert_eq!(run(1440, MTU_MIN, None, 1365, 1500).0, Outcome::Found(1360));
		assert_eq!(run(1440, MTU_MIN, None, 1300, 1300).0, Outcome::Found(1280));
		// A size fails after a lost probe and one lost retry, and nothing is asked for more than 16 times in a direction.
		let (outcome, ups, downs) = run(1440, MTU_MIN, None, 1300, 1300);
		assert!((ups, downs) <= (PROBES, PROBES) && ups > downs, "{ups} {downs}");
		assert_eq!(outcome, Outcome::Found(1280));
		assert_eq!(run(1440, MTU_MIN, None, 1279, 1500).0, Outcome::Failed);
		assert_eq!(run(1280, MTU_MIN, None, 1500, 1500), (Outcome::Found(1280), 1, 1));
		// The result is never above the profile's, whatever the node allows.
		assert_eq!(run(1300, MTU_MIN, None, 1500, 1500).0, Outcome::Found(1300));
		// A tunnel with IPv4 addresses only goes on below 1280, down to 1080, within the 16 probes from a profile of 1420.
		assert_eq!(run(1390, MTU_MIN_V4, None, 1250, 1250).0, Outcome::Found(1240));
		let (outcome, ups, downs) = run(1420, MTU_MIN_V4, None, 1100, 1100);
		assert!((outcome, ups <= PROBES, downs) == (Outcome::Found(1080), true, 1), "{outcome:?} {ups} {downs}");
		assert_eq!(run(1390, MTU_MIN_V4, None, 1079, 1500).0, Outcome::Failed);
		assert_eq!(run(1390, MTU_MIN_V4, Some(1160), 1500, 1500), (Outcome::Found(1160), 1, 1));
		assert_eq!(run(1390, MTU_MIN, Some(1160), 1500, 1500), (Outcome::Found(1390), 1, 1));
	}

	#[test]
	fn random_bytes_lower_each_probe_by_at_most_16_and_never_below_the_floor_and_keep_the_order() {
		let sizes = |jitter: [u8; JITTER], floor: u16, remembered: Option<u16>| {
			let (mut walk, _) = Walk::start(1390, floor, remembered, 51000, jitter, Instant::now());
			walk.message(&NodeMessage::ProbeToken {token: TOKEN, max_size: 1440}, Instant::now());
			[vec![walk.size], walk.sizes.clone()].concat()
		};
		assert_eq!(sizes([0; JITTER], MTU_MIN_V4, None), vec![1390, 1360, 1320, 1280, 1240, 1160, 1080], "zeros probe the table itself");
		let all = sizes([16; JITTER], MTU_MIN_V4, None);
		assert_eq!(all, vec![1374, 1344, 1304, 1264, 1224, 1144, 1080], "each comes down by 16, and the last stops at the floor");
		let mixed = sizes([33, 255, 0, 7, 16, 1, 50, 9, 9, 9], MTU_MIN, None);
		assert!(mixed.windows(2).all(|pair| pair[0] > pair[1]) && mixed.iter().all(|size| *size >= MTU_MIN), "{mixed:?}");
		assert_eq!(sizes([16; JITTER], MTU_MIN_V4, Some(1320))[0], 1320, "a remembered size is probed as it was confirmed");
	}

	#[test]
	fn the_wait_for_a_probe_varies_between_three_quarters_of_probe_wait_and_all_of_it() {
		let waits: Vec<std::time::Duration> = (0..=255u8).map(|seq| {let (mut walk, _) = Walk::start(1390, MTU_MIN_V4, None, 51000, [0x5a, 1, 200, 255, 0, 77, 9, 130, 64, 33], Instant::now()); walk.seq = seq; walk.wait()}).collect();
		assert!(waits.iter().all(|wait| *wait >= PROBE_WAIT * 3 / 4 && *wait <= PROBE_WAIT), "{waits:?}");
		assert!(waits.iter().collect::<std::collections::BTreeSet<_>>().len() > 50, "the waits are spread out");
	}

	#[test]
	fn a_remembered_size_is_confirmed_first_and_a_failed_confirmation_starts_the_walk() {
		assert_eq!(run(1390, MTU_MIN, Some(1320), 1500, 1500), (Outcome::Found(1320), 1, 1));
		// The path got worse since: the walk goes from the top, and the confirmed size is not tried a second time.
		let (outcome, ups, _) = run(1390, MTU_MIN, Some(1360), 1340, 1340);
		assert_eq!(outcome, Outcome::Found(1320));
		assert!(ups <= PROBES);
		// A remembered size outside what the profile may be is no size to confirm.
		assert_eq!(run(1390, MTU_MIN, Some(1500), 1500, 1500), (Outcome::Found(1390), 1, 1));
		assert_eq!(run(1390, MTU_MIN, Some(900), 1500, 1500), (Outcome::Found(1390), 1, 1));
	}

	#[test]
	fn what_the_node_says_out_of_turn_or_wrong_is_ignored() {
		let now = Instant::now();
		let (mut walk, _) = Walk::start(1390, MTU_MIN, None, 51000, [0; JITTER], now);
		// Before the token nothing else counts.
		assert!(walk.message(&NodeMessage::ProbeAck {seq: 1, size: 1390}, now).is_empty());
		assert!(walk.arrived(&TOKEN, 1, 1390).is_empty());
		let actions = walk.message(&NodeMessage::ProbeToken {token: TOKEN, max_size: 1390}, now);
		assert_eq!(actions, vec![Action::Probe {token: TOKEN, seq: 1, size: 1390}]);
		// An acknowledgment of another size or sequence number is none, and a downstream packet before the upstream one passed is none.
		assert!(walk.message(&NodeMessage::ProbeAck {seq: 2, size: 1390}, now).is_empty());
		assert!(walk.message(&NodeMessage::ProbeAck {seq: 1, size: 1360}, now).is_empty());
		assert!(walk.arrived(&TOKEN, 1, 1390).is_empty());
		assert!(!walk.message(&NodeMessage::ProbeAck {seq: 1, size: 1390}, now).is_empty());
		// A packet with another token, number or size is no answer.
		assert!(walk.arrived(&Token([8; 8]), 2, 1390).is_empty());
		assert!(walk.arrived(&TOKEN, 3, 1390).is_empty());
		assert!(walk.arrived(&TOKEN, 2, 1389).is_empty());
		assert_eq!(walk.arrived(&TOKEN, 2, 1390), vec![Action::Done(Outcome::Found(1390))]);
		assert!(walk.arrived(&TOKEN, 2, 1390).is_empty() && walk.is_over() && walk.due().is_none());
	}

	#[test]
	fn the_nodes_refusals_end_the_run_without_a_result() {
		let now = Instant::now();
		for (code, outcome) in [(ErrorCode::NotApplicable, Outcome::NotApplicable), (ErrorCode::Busy, Outcome::Later), (ErrorCode::RateLimited, Outcome::Later)] {
			let (mut walk, _) = Walk::start(1390, MTU_MIN, None, 51000, [0; JITTER], now);
			assert_eq!(walk.message(&NodeMessage::Error {code, answers: control::kind::PROBE_START}, now), vec![Action::Done(outcome)]);
		}
		// An error that answers another request is not the answer to this one, and a token that never comes ends the run.
		let (mut walk, _) = Walk::start(1390, MTU_MIN, None, 51000, [0; JITTER], now);
		assert!(walk.message(&NodeMessage::Error {code: ErrorCode::Busy, answers: control::kind::SET_MTU}, now).is_empty());
		assert!(walk.poll(now).is_empty());
		assert_eq!(walk.poll(now + PROBE_WAIT * 2), vec![Action::Done(Outcome::Later)]);
	}
}
