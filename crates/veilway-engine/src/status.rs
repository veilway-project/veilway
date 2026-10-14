//! What an app is given of a tunnel: states, the words for what went wrong, and counters.
//!
//! Nothing here names a rating or a class. "Ratings and classes are words for operators, used in the panel and these pages. An app does not show them, because a label scares some users and makes others too sure." An app shows the connection's name and the state. The one exception, an Unsafe profile, is not a state of a running tunnel: the engine refuses to start one until the app has shown its plain warning and passed `Agree::unsafe_profile` (see `StartError`).
//! A candidate being tried is given by its place in the signed profile's lists and nothing else. The address, the name and the path of it are the provider's and are not an app's to show.
use veilway_proto::control::{ByeReason, ExitStatus, Load, Period, Severity};

/// The reason for a state, in plain words. `code` is a stable key an app translates by, `text` is the English wording: both are the engine's, never a node's or a provider's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Say {
	/// A certificate that does not pass its candidate's check, a pin included.
	CertificateMismatch,
	/// A certificate outside its validity at the time the device's clock shows.
	CertificateTime,
	/// An answer over validated TLS that was no session.
	Refused,
	/// A pinned candidate gave a time far from the device's, and the engine now uses the difference for its proofs.
	ClockWrong,
	/// No connection, a failed handshake or a cut one.
	Unreachable,
	/// No answer on a transport of datagrams.
	Silence,
	/// The device itself could not dial.
	Offline,
	/// The hour's budget of new addresses is spent.
	BudgetSpent,
	/// A session that was open is over.
	Lost,
	/// The engine can use nothing of this profile as it stands.
	NothingToTry,
	/// The path cannot carry this way of connecting even at the smallest size.
	PathTooSmall,
	QuotaUsed,
	Expired,
	Disabled,
	NodeStopping,
	/// The control channel could not be verified. The tunnel stays up.
	ControlUnverified,
	/// The control channel is not available now. The tunnel stays up.
	ControlUnavailable,
	/// The signed profile asks for a newer control channel than this app speaks.
	AppTooOld,
	/// The node speaks an older control channel than the signed profile asks for.
	NodeTooOld,
	/// What the node's addresses say is not what the profile says.
	ProfileOutOfDate,
	/// The node's clock and the device's are far apart.
	ClockDrift,
	/// The system's random source failed.
	Random,
}

impl Say {
	pub const ALL: &'static [Say] = &[Self::CertificateMismatch, Self::CertificateTime, Self::Refused, Self::ClockWrong, Self::Unreachable, Self::Silence, Self::Offline, Self::BudgetSpent, Self::Lost, Self::NothingToTry, Self::PathTooSmall, Self::QuotaUsed, Self::Expired, Self::Disabled, Self::NodeStopping, Self::ControlUnverified, Self::ControlUnavailable, Self::AppTooOld, Self::NodeTooOld, Self::ProfileOutOfDate, Self::ClockDrift, Self::Random];
	pub fn code(self) -> &'static str {
		match self {
			Self::CertificateMismatch => "certificate-mismatch",
			Self::CertificateTime => "certificate-time",
			Self::Refused => "refused",
			Self::ClockWrong => "clock-wrong",
			Self::Unreachable => "unreachable",
			Self::Silence => "silence",
			Self::Offline => "offline",
			Self::BudgetSpent => "budget-spent",
			Self::Lost => "lost",
			Self::NothingToTry => "nothing-to-try",
			Self::PathTooSmall => "path-too-small",
			Self::QuotaUsed => "quota-used",
			Self::Expired => "expired",
			Self::Disabled => "disabled",
			Self::NodeStopping => "node-stopping",
			Self::ControlUnverified => "control-unverified",
			Self::ControlUnavailable => "control-unavailable",
			Self::AppTooOld => "app-too-old",
			Self::NodeTooOld => "node-too-old",
			Self::ProfileOutOfDate => "profile-out-of-date",
			Self::ClockDrift => "clock-drift",
			Self::Random => "random",
		}
	}
	pub fn text(self) -> &'static str {
		match self {
			Self::CertificateMismatch => "The server's certificate does not match this profile. The network may be interfering.",
			Self::CertificateTime => "The date and time on this device are outside the time the server's certificate is valid for. Check the clock.",
			Self::Refused => "The server or its front answered and did not accept the connection: check the device clock and your quota, or try again later.",
			Self::ClockWrong => "The clock on this device is wrong. Connections need a correct clock: check the date and time.",
			Self::Unreachable => "Could not reach the server on this network. Trying another way.",
			Self::Silence => "The server did not answer. It may be down or the network may be blocking it.",
			Self::Offline => "This device has no working network connection.",
			Self::BudgetSpent => "Many addresses were tried on this network in the last hour. Waiting before trying more.",
			Self::Lost => "The connection to the server was lost. Reconnecting.",
			Self::NothingToTry => "Nothing in this connection can be used as it stands. Refresh the subscription or choose another connection.",
			Self::PathTooSmall => "This network cannot carry this way of connecting. Trying another way.",
			Self::QuotaUsed => "The data allowance is used up. The connection comes back when the next period starts.",
			Self::Expired => "The account has expired.",
			Self::Disabled => "The account was switched off or removed by the provider.",
			Self::NodeStopping => "The server is stopping. Reconnecting shortly.",
			Self::ControlUnverified => "The server's control channel could not be verified, so its exits, usage and notices are not shown. The tunnel stays up.",
			Self::ControlUnavailable => "The server's control channel is not available now. The tunnel stays up.",
			Self::AppTooOld => "This app is too old for this connection. Update the app.",
			Self::NodeTooOld => "The server is too old for this connection.",
			Self::ProfileOutOfDate => "This connection's settings are out of date. Refresh the subscription.",
			Self::ClockDrift => "The clock on this device and the server's are drifting apart. Check the date and time.",
			Self::Random => "The system could not give the app random numbers. Nothing was sent.",
		}
	}
}

/// A candidate being tried, by position in the signed profile: the transport's place in its list and the places of the one or two candidates that are open now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {pub transport: usize, pub candidates: Vec<usize>}

/// Why the node ended the tunnel on purpose. "Quota used up, expired, disabled or removed, the node is stopping."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {Quota, Expired, Disabled, NodeStopping}

impl Stop {
	pub fn of(reason: ByeReason) -> Self {
		match reason {
			ByeReason::Quota => Self::Quota,
			ByeReason::Expired => Self::Expired,
			ByeReason::Disabled => Self::Disabled,
			ByeReason::Stopping => Self::NodeStopping,
		}
	}
	pub fn say(self) -> Say {
		match self {
			Self::Quota => Say::QuotaUsed,
			Self::Expired => Say::Expired,
			Self::Disabled => Say::Disabled,
			Self::NodeStopping => Say::NodeStopping,
		}
	}
}

/// When the engine tries again after a `bye` ("Being cut off"). Whatever it says, the user can ask at any time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
	/// At this Unix time: the next period, or the refusal wait, or the ordinary reconnect wait.
	At(u64),
	/// Only when the user asks, or a refreshed subscription shows what changed.
	Asked,
}

/// What the tunnel is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
	/// Not started, or stopped by the user.
	Off,
	/// No session yet. `wait` is the Unix time of the next try when the engine is waiting for one, and `attempt` what is open when it is not.
	Connecting {attempt: Option<Attempt>, wait: Option<u64>},
	/// A session is open and WireGuard has answered. `exit` is the tag of the exit now in use, once the node has said which.
	Connected {exit: Option<String>},
	/// A session that was open is lost and another is being opened.
	Reconnecting {attempt: Option<Attempt>, wait: Option<u64>},
	/// The node ended the tunnel on purpose and the engine does not try again until `retry`.
	Stopped {reason: Stop, retry: Retry},
	/// Nothing can be done until the user acts.
	Failed,
}

/// An exit the node offers, as an app shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitView {
	pub tag: String,
	/// The profile's own name for it in the app's language when the signed profile has one that matches what the node sent, and the node's name, filtered, otherwise.
	pub name: String,
	/// Two uppercase ASCII letters.
	pub country: Option<[u8; 2]>,
	pub all_protocols: bool,
	/// This device's selection.
	pub selected: bool,
	/// The user's configured exit, the one used when nothing is selected.
	pub configured: bool,
	pub working: bool,
	pub load: Load,
}

/// What the node last said about the account, clamped, and the subscription's own numbers are the app's to join with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageView {pub used_bytes: u64, pub quota_bytes: u64, pub period: Period, pub period_start: u64, pub expires_at: u64, pub up_bytes: u64, pub down_bytes: u64}

/// A notice, filtered and cut, in the app's language when the profile or the subscription has the text. The severity is the node's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeView {pub severity: Severity, pub text: String, /// When the notice is the same as the subscription's own notice at this place, which the app shows once and not twice.
	pub subscription: Option<usize>}

/// What a tunnel counts. Every field only grows during a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
	/// Sessions tried, and of those the ones that opened.
	pub attempts: u64,
	pub opened: u64,
	/// How attempts and sessions ended.
	pub refused: u64,
	pub unreachable: u64,
	pub offline: u64,
	pub lost: u64,
	/// Candidates set aside as unreachable.
	pub set_aside: u64,
	/// Packets and bytes through the tunnel, as the platform sees them.
	pub packets_sent: u64,
	pub packets_received: u64,
	pub bytes_sent: u64,
	pub bytes_received: u64,
	/// Packets the platform handed in while no session was open, and packets that found a queue full or a size the session cannot carry.
	pub dropped_offline: u64,
	pub dropped_full: u64,
	/// Packets out of the tunnel that were not for this device's address and were not handed to the platform.
	pub dropped_foreign: u64,
	/// Control channels opened and ones that failed, and `bye` messages received.
	pub control_opened: u64,
	pub control_failed: u64,
	pub byes: u64,
	/// MTU probe runs finished and the size last found.
	pub probes: u64,
}

/// The whole picture an app draws from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
	pub state: State,
	/// The connection's name, as the signed profile gives it. The only label an app shows for what it is connected to.
	pub name: String,
	pub say: Option<Say>,
	pub exits: Vec<ExitView>,
	pub usage: Option<UsageView>,
	pub notices: Vec<NoticeView>,
	/// The tunnel's MTU now: the profile's, or the lower one the probing found.
	pub mtu: u16,
	/// The control channel is open and verified.
	pub control: bool,
	/// The node's addresses are not the profile's: the app refreshes the subscription.
	pub out_of_date: bool,
	pub counters: Counters,
}

impl Status {
	pub(crate) fn off(name: String, mtu: u16) -> Self {Self {state: State::Off, name, say: None, exits: Vec::new(), usage: None, notices: Vec::new(), mtu, control: false, out_of_date: false, counters: Counters::default()}}
}

/// Things that happen once, for an app that reacts to them. The state of a tunnel is in `Status`, and these are only what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
	/// The answer to a `select_exit`: `selected` is the tag now in force on the node, empty for none.
	Exit {status: ExitStatus, selected: String},
	/// The tunnel's MTU changed, and the platform sets its device to it.
	Mtu(u16),
	/// The node ended the tunnel on purpose.
	Stopped(Stop),
	/// A session opened.
	Opened,
	/// A session that was open is over.
	Lost,
}

#[cfg(test)]
mod tests {
	use super::*;

	// "Ratings and classes are words for operators ... An app does not show them."
	#[test]
	fn no_word_an_app_is_given_is_a_rating_or_a_class() {
		let mut codes: Vec<&str> = Say::ALL.iter().map(|say| say.code()).collect();
		codes.sort();
		codes.dedup();
		assert_eq!(codes.len(), Say::ALL.len());
		for say in Say::ALL {
			let (text, code) = (say.text().to_lowercase(), say.code());
			for word in ["protected", "detectable", "unsafe", "rating", "class", "cover", "obfs", "transport", "tls", "udp", "websocket", "fronted", "cdn"] {assert!(!text.contains(word) && !code.contains(word), "{say:?} says {word}")}
			assert!(!text.contains('\u{2014}') && !text.contains(" - ") && text.ends_with('.'), "{say:?}");
		}
		for stop in [Stop::Quota, Stop::Expired, Stop::Disabled, Stop::NodeStopping] {assert!(Say::ALL.contains(&stop.say()))}
	}
}
