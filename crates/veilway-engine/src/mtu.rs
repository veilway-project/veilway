//! The device's side of MTU discovery (control channel page, "MTU discovery"): which probe goes out when, and what a size is worth, as a state machine with no socket, no clock and no random source of its own.
//!
//! The method is RFC 8899's. A size works only when a probe of that size was confirmed in both directions. The profile's `mtu` is probed first, so a path that carries it costs two probes. Otherwise the walk goes down the table of sizes below it, and a size fails after a lost probe and one lost retry. The result is the largest size that passed both ways. If even 1280 fails, this transport does not work on this path and the engine moves on under the rules of transport fallback.
//! A remembered size (7 days, per network and transport) is confirmed first with one probe in each direction, and a confirmation that fails starts the walk from the top of the table. The node answers a run of probes at most once a minute and takes at most 16 probes in each direction; the walk is built never to ask for more than that.
//! What the node says is hostile input: a token, a size or a sequence number that is not the one asked for is ignored, and the result is never above the profile's `mtu`, whatever the node says.
use tokio::time::Instant;
use veilway_proto::control::{self, ClientMessage, ErrorCode, NodeMessage, Token, MTU_MIN, PROBES, PROBE_WAIT};

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
}

impl Walk {
	/// Starts a run. `profile` is the signed profile's `mtu`, `remembered` the size confirmed first, if one is held, and `port` the UDP port the downstream probes come to.
	pub fn start(profile: u16, remembered: Option<u16>, port: u16, now: Instant) -> (Self, Vec<Action>) {
		let walk = Self {profile, sizes: Vec::new(), size: 0, token: None, seq: 0, step: Step::Token, up: 0, down: 0, port, due: Some(now + PROBE_WAIT * 2), remembered};
		(walk, vec![Action::Send(ClientMessage::ProbeStart)])
	}
	pub fn port(&self) -> u16 {self.port}
	#[cfg(test)]
	fn is_over(&self) -> bool {self.step == Step::Over}
	#[cfg(test)]
	fn due(&self) -> Option<Instant> {self.due}
	// Ends the run.
	fn end(&mut self, outcome: Outcome) -> Vec<Action> {
		(self.step, self.due) = (Step::Over, None);
		vec![Action::Done(outcome)]
	}
	// The probe upstream for the size in hand, with a fresh `seq`.
	fn up(&mut self, now: Instant, retried: bool) -> Vec<Action> {
		let Some(token) = self.token else {return self.end(Outcome::Later)};
		if self.up >= PROBES {return self.end(Outcome::Failed)}
		(self.seq, self.up, self.step, self.due) = (self.seq.wrapping_add(1), self.up + 1, Step::Up {retried}, Some(now + PROBE_WAIT));
		vec![Action::Probe {token, seq: self.seq, size: self.size}]
	}
	fn down(&mut self, now: Instant, retried: bool) -> Vec<Action> {
		if self.down >= PROBES {return self.end(Outcome::Failed)}
		(self.seq, self.down, self.step, self.due) = (self.seq.wrapping_add(1), self.down + 1, Step::Down {retried}, Some(now + PROBE_WAIT));
		vec![Action::Send(ClientMessage::ProbeDown {seq: self.seq, size: self.size, port: self.port})]
	}
	// The next size of the walk, or the end of it.
	fn next(&mut self, now: Instant) -> Vec<Action> {
		if self.sizes.is_empty() {return self.end(Outcome::Failed)}
		self.size = self.sizes.remove(0);
		self.up(now, false)
	}
	/// What the node said. Anything that is not the answer to the probe in hand is ignored.
	pub fn message(&mut self, message: &NodeMessage, now: Instant) -> Vec<Action> {
		match (self.step, message) {
			(Step::Token, NodeMessage::ProbeToken {token, max_size}) => {
				self.token = Some(*token);
				let top = self.profile.min(*max_size);
				// The remembered size is confirmed first, and the table below the top follows it.
				let mut sizes: Vec<u16> = control::probe_sizes(top).collect();
				if let Some(held) = self.remembered.filter(|held| (MTU_MIN..=top).contains(held)) {sizes.retain(|size| *size != held); sizes.insert(0, held)}
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

	const TOKEN: Token = Token([7; 8]);

	// Drives a walk against a path that carries packets up to `limit` bytes in each direction, or `up` and `down` separately.
	fn run(profile: u16, remembered: Option<u16>, up_limit: u16, down_limit: u16) -> (Outcome, usize, usize) {
		let mut now = Instant::now();
		let (mut walk, todo) = Walk::start(profile, remembered, 51000, now);
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
		assert_eq!(run(1390, None, 1500, 1500), (Outcome::Found(1390), 1, 1));
	}

	#[test]
	fn the_walk_goes_down_the_table_and_the_result_is_the_largest_that_passed_both_ways() {
		// 1390 and 1360 pass up and not down, 1320 passes both.
		assert_eq!(run(1390, None, 1500, 1330).0, Outcome::Found(1320));
		assert_eq!(run(1440, None, 1365, 1500).0, Outcome::Found(1360));
		assert_eq!(run(1440, None, 1300, 1300).0, Outcome::Found(1280));
		// A size fails after a lost probe and one lost retry, and nothing is asked for more than 16 times in a direction.
		let (outcome, ups, downs) = run(1440, None, 1300, 1300);
		assert!((ups, downs) <= (PROBES, PROBES) && ups > downs, "{ups} {downs}");
		assert_eq!(outcome, Outcome::Found(1280));
		assert_eq!(run(1440, None, 1279, 1500).0, Outcome::Failed);
		assert_eq!(run(1280, None, 1500, 1500), (Outcome::Found(1280), 1, 1));
		// The result is never above the profile's, whatever the node allows.
		assert_eq!(run(1300, None, 1500, 1500).0, Outcome::Found(1300));
	}

	#[test]
	fn a_remembered_size_is_confirmed_first_and_a_failed_confirmation_starts_the_walk() {
		assert_eq!(run(1390, Some(1320), 1500, 1500), (Outcome::Found(1320), 1, 1));
		// The path got worse since: the walk goes from the top, and the confirmed size is not tried a second time.
		let (outcome, ups, _) = run(1390, Some(1360), 1340, 1340);
		assert_eq!(outcome, Outcome::Found(1320));
		assert!(ups <= PROBES);
		// A remembered size outside what the profile may be is no size to confirm.
		assert_eq!(run(1390, Some(1500), 1500, 1500), (Outcome::Found(1390), 1, 1));
		assert_eq!(run(1390, Some(900), 1500, 1500), (Outcome::Found(1390), 1, 1));
	}

	#[test]
	fn what_the_node_says_out_of_turn_or_wrong_is_ignored() {
		let now = Instant::now();
		let (mut walk, _) = Walk::start(1390, None, 51000, now);
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
			let (mut walk, _) = Walk::start(1390, None, 51000, now);
			assert_eq!(walk.message(&NodeMessage::Error {code, answers: control::kind::PROBE_START}, now), vec![Action::Done(outcome)]);
		}
		// An error that answers another request is not the answer to this one, and a token that never comes ends the run.
		let (mut walk, _) = Walk::start(1390, None, 51000, now);
		assert!(walk.message(&NodeMessage::Error {code: ErrorCode::Busy, answers: control::kind::SET_MTU}, now).is_empty());
		assert!(walk.poll(now).is_empty());
		assert_eq!(walk.poll(now + PROBE_WAIT * 2), vec![Action::Done(Outcome::Later)]);
	}
}
