//! The control channel's messages after the opening exchange (control channel page, "Framing" and "Messages"): encode and decode over byte slices, and the decoders for the two byte streams of a connection.
//!
//! Every body has a fixed layout. A decoder refuses whatever the page does not define: an unknown type, a body shorter or longer than its layout, a count above its limit, an unknown value of a field, a reserved bit that is set, a tag that is no tag. An encoder refuses to write what a decoder would refuse, and one message has one encoding.
//!
//! The four messages of the opening exchange are not here. `opening` reads and writes them itself, and a stream decoder for what follows exists only as the result of an exchange that opened, so a `hello` or an `auth` after the opening is an unknown type like any other.
use std::{collections::HashSet, fmt, net::{IpAddr, Ipv4Addr, Ipv6Addr}, ops::RangeInclusive, time::Duration};

/// TCP for the channel, UDP for MTU probes only, on the gateway address ("Where it is").
pub const PORT: u16 = 47873;
/// The first 8 bytes a client sends ("Opening a connection", step 2).
pub const PREFACE: [u8; 8] = [0x00, 0x56, 0x57, 0x43, 0x54, 0x4C, 0x00, 0x00];
/// The one version this crate speaks ("Versions").
pub const VERSION: u8 = 1;
/// The largest `length` of a message from a client.
pub const CLIENT_LIMIT: usize = 4_096;
/// The largest `length` of a message from a node.
pub const NODE_LIMIT: usize = 65_535;
/// The longest tag, in bytes.
pub const TAG_MAX: usize = 64;
/// The words the config's tag rule reserves. None of them is a tag on the wire.
pub const RESERVED_TAGS: [&str; 8] = ["all", "any", "block", "reject", "drop", "local", "direct", "user"];
/// The longest display name this crate writes for an exit, in bytes. The wire has no limit of its own for display text ("Framing"): this is what a node holds itself to, and 64 characters never take more.
pub const NAME_MAX: usize = 256;
/// A client shows at most this many characters of an exit's name.
pub const NAME_SHOWN: usize = 64;
/// A client shows a notice cut to this many bytes, on a character boundary. This crate writes none that is longer, though the wire would carry it.
pub const NOTICE_MAX: usize = 280;
pub const EXITS_PER_MESSAGE: usize = 64;
pub const EXITS_MAX: usize = 256;
pub const NOTICES_MAX: usize = 4;
pub const HINTS_MAX: usize = 16;
/// The smallest tunnel MTU, and the smallest probe size.
pub const MTU_MIN: u16 = 1280;
/// "MTU probe sizes: the profile's `mtu`, and those of 1280, 1320, 1360, 1390, 1420 and 1440 that are below it."
pub const PROBE_SIZES: [u16; 6] = [1280, 1320, 1360, 1390, 1420, 1440];
/// A client clamps the integers of `usage` to this before showing them ("What a malicious node can do"). `Usage::clamped` does it.
pub const USAGE_CLAMP: u64 = 9_007_199_254_740_991;

// The rest of "Numbers that are judgement calls", for the two sides to share. Nothing in this crate enforces them.
/// The client opens the channel after a delay drawn from this range, in milliseconds, after the WireGuard handshake.
pub const OPEN_DELAY: RangeInclusive<u32> = 0..=2_000;
/// Connections of one device that have not authenticated. A fifth replaces the oldest.
pub const UNAUTHENTICATED: usize = 4;
/// Authenticated connections of one device. A third replaces the oldest.
pub const AUTHENTICATED: usize = 2;
/// Messages from one device: this many at once, then one every `MESSAGE_REFILL`.
pub const MESSAGE_BURST: u32 = 10;
pub const MESSAGE_REFILL: Duration = Duration::from_secs(1);
/// `set_exit` from one device: this many at once, then one every `SET_EXIT_REFILL`.
pub const SET_EXIT_BURST: u32 = 3;
pub const SET_EXIT_REFILL: Duration = Duration::from_secs(5);
/// A new `usage` is pushed not sooner than a time drawn from this range, in milliseconds, after the last one.
pub const USAGE_PUSH: RangeInclusive<u32> = 30_000..=90_000;
/// A client applies at most one pushed snapshot message of each kind in this time.
pub const APPLY_INTERVAL: Duration = Duration::from_secs(5);
/// The channel causes at most one subscription refresh in this time.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// One MTU probe run per device in this time.
pub const PROBE_RUN_INTERVAL: Duration = Duration::from_secs(60);
pub const PROBE_TOKEN_LIFE: Duration = Duration::from_secs(30);
/// Probes in each direction of one run.
pub const PROBES: usize = 16;
/// The wait for one probe. A size fails after a lost probe and one lost retry.
pub const PROBE_WAIT: Duration = Duration::from_secs(2);
/// The client confirms its MTU again after a time drawn from this range, in milliseconds.
pub const MTU_CONFIRM: RangeInclusive<u32> = 300_000..=900_000;
/// The client remembers an MTU per network and transport for this long.
pub const MTU_REMEMBERED: Duration = Duration::from_secs(7 * 86_400);
/// The node keeps a device's MTU until the device has had no WireGuard session for this long.
pub const DEVICE_MTU_LIFE: Duration = Duration::from_secs(180);

/// The `type` byte of every message.
pub mod kind {
	pub const HELLO: u8 = 0x01;
	pub const AUTH: u8 = 0x02;
	pub const REFRESH: u8 = 0x10;
	pub const SET_EXIT: u8 = 0x11;
	pub const PROBE_START: u8 = 0x12;
	pub const PROBE_DOWN: u8 = 0x13;
	pub const SET_MTU: u8 = 0x14;
	pub const HELLO_REPLY: u8 = 0x81;
	pub const AUTH_OK: u8 = 0x82;
	pub const SESSION: u8 = 0x90;
	pub const EXITS: u8 = 0x91;
	pub const EXIT_RESULT: u8 = 0x92;
	pub const USAGE: u8 = 0x93;
	pub const NOTICES: u8 = 0x94;
	pub const HINTS: u8 = 0x95;
	pub const PROBE_TOKEN: u8 = 0x96;
	pub const PROBE_ACK: u8 = 0x97;
	pub const MTU_RESULT: u8 = 0x98;
	pub const BYE: u8 = 0x99;
	pub const ERROR: u8 = 0x9F;
	/// The requests a client may send after the opening, which are the only types an `error` may answer ("Errors").
	pub const REQUESTS: [u8; 5] = [REFRESH, SET_EXIT, PROBE_START, PROBE_DOWN, SET_MTU];
}

/// Why bytes were not read as a message. Either side closes the connection on any of these and applies nothing from the message ("Errors").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
	/// The connection did not start with the preface.
	Preface,
	/// A `length` of 0, one over the limit of its direction, one its type cannot have, or one that is not the size of the message.
	Length,
	/// An unknown `type`, or one that is not sent in this direction or at this point of the connection.
	Type,
	/// A body shorter or longer than its layout.
	Body,
	/// A count above its limit, an unknown value, a reserved bit that is set, a tag that breaks the tag rule, or a catalogue that breaks its rules.
	Value,
	/// A string that is not UTF-8.
	Text,
}

impl fmt::Display for DecodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "control message: {self:?}")}
}

impl std::error::Error for DecodeError {}

/// Why a message was not written: it holds what no peer would read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
	/// The message is longer than the limit of its direction.
	Length,
	/// A string or a list is over its limit, or a field has a value the layout cannot carry.
	Value,
}

impl fmt::Display for EncodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "control message: {self:?}")}
}

impl std::error::Error for EncodeError {}

macro_rules! wire_enum {
	($(#[$meta:meta])* $name:ident {$($(#[$doc:meta])* $variant:ident = $value:literal),+}) => {
		$(#[$meta])*
		#[derive(Debug, Clone, Copy, PartialEq, Eq)]
		pub enum $name {$($(#[$doc])* $variant = $value),+}
		impl $name {
			/// Every value the field may hold.
			pub const ALL: &'static [Self] = &[$(Self::$variant),+];
			fn read(byte: u8) -> Result<Self, DecodeError> {
				match byte {
					$($value => Ok(Self::$variant),)+
					_ => Err(DecodeError::Value),
				}
			}
		}
	};
}

wire_enum!(
	/// `load` of an exit. Coarse on purpose.
	Load {Unknown = 0, Low = 1, Medium = 2, High = 3}
);
wire_enum!(
	/// `status` of `exit_result`. A tag that does not exist and one the user is not entitled to are both `Refused`.
	ExitStatus {Selected = 0, Refused = 1, RateLimited = 2}
);
wire_enum!(
	/// `period` of `usage`.
	Period {None = 0, Daily = 1, Weekly = 2, Monthly = 3}
);
wire_enum!(
	/// `severity` of a notice.
	Severity {Information = 0, Warning = 1}
);
wire_enum!(
	/// `reason` of `bye` ("Being cut off").
	ByeReason {
		/// Quota used up.
		Quota = 1,
		Expired = 2,
		/// Disabled or removed.
		Disabled = 3,
		/// The node is stopping.
		Stopping = 4
	}
);
wire_enum!(
	/// `code` of `error` ("Errors").
	ErrorCode {RateLimited = 1, NotApplicable = 2, Busy = 3}
);

/// Whether `tag` is a tag as the config's tag rule and "Framing" define it: 1 to 64 of `a-z`, `0-9`, `_` and `-`, starting with a letter or digit, and none of the reserved words. A tag can hold nothing else, so it needs no filter before it is shown or logged.
pub fn is_tag(tag: &str) -> bool {(1..=TAG_MAX).contains(&tag.len()) && tag.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-') && !tag.starts_with(['_', '-']) && !RESERVED_TAGS.contains(&tag)}

/// Text from a node made fit to show: control, bidirectional formatting, zero-width and other invisible characters are removed first, then the rest is cut to `chars` characters and `bytes` bytes, whichever ends it sooner ("Framing" and "What a malicious node can do"). Text is cut, never refused.
/// The removed set is every control character and the format and filler characters that render as nothing or reorder text, the blank braille pattern, the object replacement character, the format controls of shorthand and of Egyptian hieroglyphs, the private use characters, whose look is whatever a font says, and the noncharacters. The config applies a list of the same kind to exit names (`veilway-core`, `config/validate.rs`), which is shorter than this one.
pub fn display(text: &str, chars: usize, bytes: usize) -> String {
	let mut shown = String::new();
	for c in text.chars().filter(|c| !c.is_control() && !matches!(c, '\u{ad}' | '\u{34f}' | '\u{61c}' | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}' | '\u{180b}'..='\u{180f}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}' | '\u{fff9}'..='\u{fffb}' | '\u{1d173}'..='\u{1d17a}' | '\u{e0000}'..='\u{e0fff}' | '\u{2800}' | '\u{fff0}'..='\u{fff8}' | '\u{fffc}' | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}' | '\u{fdd0}'..='\u{fdef}') && *c as u32 & 0xfffe != 0xfffe).take(chars) {
		if shown.len() + c.len_utf8() > bytes {break}
		shown.push(c);
	}
	shown
}

/// Display text exactly as a node sent it. It is hostile until it went through `display`, which `Exit::shown_name` and `Notice::shown_text` do with the right limits, so this type gives its content out only under a name that says what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untrusted(String);

impl Untrusted {
	/// The text as sent, unfiltered and uncut: for writing it to the wire and for comparing, never for a screen or a log line.
	pub fn as_sent(&self) -> &str {&self.0}
}

impl<T: Into<String>> From<T> for Untrusted {
	fn from(text: T) -> Self {Self(text.into())}
}

/// The token of one MTU probe run. Whoever holds a live token can have probes confirmed, so it stays out of debug output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Token(pub [u8; 8]);

impl fmt::Debug for Token {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Token(..)")}
}

/// What a client sends after the opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessage {
	/// Asks for the snapshot again.
	Refresh,
	/// An empty tag clears the selection.
	SetExit {tag: String},
	ProbeStart,
	/// Allowed only after a `probe_token` was received on this connection and while that token is live. At any other time the node answers `error` code 2. The decoder cannot know: the node that holds the token checks it.
	ProbeDown {seq: u8, size: u16, port: u16},
	SetMtu {mtu: u16},
}

/// The device's address and the gateway address of one family, as the node holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addresses<A> {pub device: A, pub gateway: A}

/// The body of `session`. A client compares it with its profile and applies none of it except a lower MTU inside its bound ("Addresses and resolver").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
	/// Unix seconds.
	pub node_time: u64,
	pub mtu: u16,
	pub v4: Option<Addresses<Ipv4Addr>>,
	pub v6: Option<Addresses<Ipv6Addr>>,
}

/// One entry of the exit catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
	pub tag: String,
	/// The display name. A node writes at most 256 bytes. A client shows `shown_name`.
	pub name: Untrusted,
	/// Two uppercase ASCII letters.
	pub country: Option<[u8; 2]>,
	/// Carries every IP protocol.
	pub all_protocols: bool,
	/// This device's selection.
	pub selected: bool,
	/// The user's configured exit.
	pub configured: bool,
	/// Working, as far as the node last measured.
	pub working: bool,
	pub load: Load,
}

impl Exit {
	/// The name as a client shows it: filtered, then cut to 64 characters.
	pub fn shown_name(&self) -> String {display(self.name.as_sent(), NAME_SHOWN, NAME_MAX)}
}

/// The body of `usage`. Times are Unix seconds, and 0 means none for `quota_bytes` and `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {pub used_bytes: u64, pub quota_bytes: u64, pub period: Period, pub period_start: u64, pub expires_at: u64, pub up_bytes: u64, pub down_bytes: u64}

impl Usage {
	/// The numbers as a client shows them: every integer clamped to `USAGE_CLAMP`.
	pub fn clamped(self) -> Self {Self {used_bytes: self.used_bytes.min(USAGE_CLAMP), quota_bytes: self.quota_bytes.min(USAGE_CLAMP), period: self.period, period_start: self.period_start.min(USAGE_CLAMP), expires_at: self.expires_at.min(USAGE_CLAMP), up_bytes: self.up_bytes.min(USAGE_CLAMP), down_bytes: self.down_bytes.min(USAGE_CLAMP)}}
}

/// Plain text from the operator's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {pub severity: Severity, pub text: Untrusted}

impl Notice {
	/// The text as a client shows it: filtered, then cut to 280 bytes.
	pub fn shown_text(&self) -> String {display(self.text.as_sent(), usize::MAX, NOTICE_MAX)}
}

/// Two positions in the lists of the signed profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint {pub transport: u8, pub candidate: u8}

/// What a node sends after the opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMessage {
	Session(Session),
	/// Part of a catalogue. `last` is set on its last message. A client gives every one of these to a `Catalogue` and shows only what that hands back.
	Exits {last: bool, entries: Vec<Exit>},
	/// `tag` is the tag now selected, empty when none.
	ExitResult {status: ExitStatus, tag: String},
	Usage(Usage),
	Notices(Vec<Notice>),
	Hints(Vec<Hint>),
	ProbeToken {token: Token, max_size: u16},
	ProbeAck {seq: u8, size: u16},
	/// The value now in force for this device.
	MtuResult {mtu: u16},
	Bye {reason: ByeReason},
	/// `answers` is the `type` of the client's request this answers.
	Error {code: ErrorCode, answers: u8},
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
	fn open(message: &'a [u8], limit: usize) -> Result<(u8, Self), DecodeError> {
		let [high, low, kind, body @ ..] = message else {return Err(DecodeError::Length)};
		let length = usize::from(u16::from_be_bytes([*high, *low]));
		if length > limit || length != body.len() + 1 {return Err(DecodeError::Length)}
		Ok((*kind, Self(body)))
	}
	fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
		if count > self.0.len() {return Err(DecodeError::Body)}
		let (head, rest) = self.0.split_at(count);
		self.0 = rest;
		Ok(head)
	}
	fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {self.take(N)?.try_into().map_err(|_| DecodeError::Body)}
	fn u8(&mut self) -> Result<u8, DecodeError> {Ok(u8::from_be_bytes(self.array()?))}
	fn u16(&mut self) -> Result<u16, DecodeError> {Ok(u16::from_be_bytes(self.array()?))}
	fn u64(&mut self) -> Result<u64, DecodeError> {Ok(u64::from_be_bytes(self.array()?))}
	// A tag has a 1 byte length and follows the tag rule. `none` says this is one of the two places where an empty tag means "no exit".
	fn tag(&mut self, none: bool) -> Result<String, DecodeError> {
		let length = usize::from(self.u8()?);
		if length > TAG_MAX {return Err(DecodeError::Value)}
		let tag = std::str::from_utf8(self.take(length)?).map_err(|_| DecodeError::Text)?;
		if is_tag(tag) || (none && tag.is_empty()) {Ok(tag.to_owned())} else {Err(DecodeError::Value)}
	}
	// Display text has a 2 byte length. Text over the limit of its field is cut when it is shown and is no malformed body, so the only bound here is the message it came in.
	fn text(&mut self) -> Result<Untrusted, DecodeError> {
		let length = usize::from(self.u16()?);
		std::str::from_utf8(self.take(length)?).map(Untrusted::from).map_err(|_| DecodeError::Text)
	}
	// "An address is a family byte (4 or 6) followed by 4 or 16 bytes."
	fn address(&mut self) -> Result<IpAddr, DecodeError> {
		match self.u8()? {
			4 => Ok(IpAddr::from(self.array::<4>()?)),
			6 => Ok(IpAddr::from(self.array::<16>()?)),
			_ => Err(DecodeError::Value),
		}
	}
	fn end(self) -> Result<(), DecodeError> {if self.0.is_empty() {Ok(())} else {Err(DecodeError::Body)}}
}

// Appends one message: `length`, `type`, then what `body` writes. Nothing stays in `out` when the body or the length is refused.
fn frame(out: &mut Vec<u8>, limit: usize, kind: u8, body: impl FnOnce(&mut Vec<u8>) -> Result<(), EncodeError>) -> Result<(), EncodeError> {
	let start = out.len();
	out.extend_from_slice(&[0, 0, kind]);
	match body(out).and_then(|_| u16::try_from(out.len() - start - 2).ok().filter(|length| usize::from(*length) <= limit).ok_or(EncodeError::Length)) {
		Ok(length) => {
			out[start..start + 2].copy_from_slice(&length.to_be_bytes());
			Ok(())
		}
		Err(error) => {
			out.truncate(start);
			Err(error)
		}
	}
}

fn tag(out: &mut Vec<u8>, tag: &str, none: bool) -> Result<(), EncodeError> {
	if !is_tag(tag) && !(none && tag.is_empty()) {return Err(EncodeError::Value)}
	out.push(tag.len() as u8);
	out.extend_from_slice(tag.as_bytes());
	Ok(())
}

// Any length that fits the message is a valid body, and a reader takes it. A node still writes no text longer than a client shows.
fn text(out: &mut Vec<u8>, text: &Untrusted, limit: usize) -> Result<(), EncodeError> {
	if text.0.len() > limit {return Err(EncodeError::Value)}
	out.extend_from_slice(&(text.0.len() as u16).to_be_bytes());
	out.extend_from_slice(text.0.as_bytes());
	Ok(())
}

// The `length` a message of each type can have. A stream decoder asks at the third byte of a message, so it never keeps the body of what could not be one.
fn client_lengths(kind: u8) -> Option<RangeInclusive<usize>> {
	Some(match kind {
		kind::REFRESH | kind::PROBE_START => 1..=1,
		kind::SET_EXIT => 2..=2 + TAG_MAX,
		kind::PROBE_DOWN => 6..=6,
		kind::SET_MTU => 3..=3,
		_ => return None,
	})
}

fn node_lengths(kind: u8) -> Option<RangeInclusive<usize>> {
	Some(match kind {
		kind::SESSION => 22..=56,
		// Display text has no bound but the message.
		kind::EXITS | kind::NOTICES => 2..=NODE_LIMIT,
		kind::EXIT_RESULT => 3..=3 + TAG_MAX,
		kind::USAGE => 50..=50,
		kind::HINTS => 2..=2 + 2 * HINTS_MAX,
		kind::PROBE_TOKEN => 11..=11,
		kind::PROBE_ACK => 4..=4,
		kind::MTU_RESULT | kind::ERROR => 3..=3,
		kind::BYE => 2..=2,
		_ => return None,
	})
}

impl ClientMessage {
	/// The `type` byte.
	pub fn kind(&self) -> u8 {
		match self {
			Self::Refresh => kind::REFRESH,
			Self::SetExit {..} => kind::SET_EXIT,
			Self::ProbeStart => kind::PROBE_START,
			Self::ProbeDown {..} => kind::PROBE_DOWN,
			Self::SetMtu {..} => kind::SET_MTU,
		}
	}
	/// Appends the whole message to `out`, from its `length` to the last byte of its body.
	pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
		frame(out, CLIENT_LIMIT, self.kind(), |out| {
			match self {
				Self::Refresh | Self::ProbeStart => {}
				Self::SetExit {tag} => self::tag(out, tag, true)?,
				Self::ProbeDown {seq, size, port} => {
					out.push(*seq);
					out.extend_from_slice(&size.to_be_bytes());
					out.extend_from_slice(&port.to_be_bytes());
				}
				Self::SetMtu {mtu} => out.extend_from_slice(&mtu.to_be_bytes()),
			}
			Ok(())
		})
	}
	/// Reads exactly one whole message, from its `length` to the last byte of its body.
	pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
		let (kind, mut body) = Reader::open(message, CLIENT_LIMIT)?;
		let decoded = match kind {
			kind::REFRESH => Self::Refresh,
			kind::SET_EXIT => Self::SetExit {tag: body.tag(true)?},
			kind::PROBE_START => Self::ProbeStart,
			kind::PROBE_DOWN => Self::ProbeDown {seq: body.u8()?, size: body.u16()?, port: body.u16()?},
			kind::SET_MTU => Self::SetMtu {mtu: body.u16()?},
			_ => return Err(DecodeError::Type),
		};
		body.end()?;
		Ok(decoded)
	}
}

impl NodeMessage {
	/// The `type` byte.
	pub fn kind(&self) -> u8 {
		match self {
			Self::Session(_) => kind::SESSION,
			Self::Exits {..} => kind::EXITS,
			Self::ExitResult {..} => kind::EXIT_RESULT,
			Self::Usage(_) => kind::USAGE,
			Self::Notices(_) => kind::NOTICES,
			Self::Hints(_) => kind::HINTS,
			Self::ProbeToken {..} => kind::PROBE_TOKEN,
			Self::ProbeAck {..} => kind::PROBE_ACK,
			Self::MtuResult {..} => kind::MTU_RESULT,
			Self::Bye {..} => kind::BYE,
			Self::Error {..} => kind::ERROR,
		}
	}
	/// Appends the whole message to `out`, from its `length` to the last byte of its body.
	pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
		frame(out, NODE_LIMIT, self.kind(), |out| {
			match self {
				Self::Session(session) => {
					if session.v4.is_none() && session.v6.is_none() {return Err(EncodeError::Value)}
					out.extend_from_slice(&session.node_time.to_be_bytes());
					out.extend_from_slice(&session.mtu.to_be_bytes());
					out.push(u8::from(session.v4.is_some()) + u8::from(session.v6.is_some()));
					for address in session.v4.iter().flat_map(|pair| [pair.device, pair.gateway]) {
						out.push(4);
						out.extend_from_slice(&address.octets());
					}
					for address in session.v6.iter().flat_map(|pair| [pair.device, pair.gateway]) {
						out.push(6);
						out.extend_from_slice(&address.octets());
					}
				}
				Self::Exits {last, entries} => {
					if entries.len() > EXITS_PER_MESSAGE {return Err(EncodeError::Value)}
					out.extend_from_slice(&[u8::from(*last), entries.len() as u8]);
					for exit in entries {
						if !exit.country.is_none_or(|country| country.iter().all(u8::is_ascii_uppercase)) {return Err(EncodeError::Value)}
						tag(out, &exit.tag, false)?;
						text(out, &exit.name, NAME_MAX)?;
						out.extend_from_slice(&exit.country.unwrap_or([0, 0]));
						out.extend_from_slice(&[u8::from(exit.all_protocols) | u8::from(exit.selected) << 1 | u8::from(exit.configured) << 2 | u8::from(exit.working) << 3, exit.load as u8]);
					}
				}
				Self::ExitResult {status, tag} => {
					out.push(*status as u8);
					self::tag(out, tag, true)?;
				}
				Self::Usage(usage) => {
					out.extend_from_slice(&usage.used_bytes.to_be_bytes());
					out.extend_from_slice(&usage.quota_bytes.to_be_bytes());
					out.push(usage.period as u8);
					for value in [usage.period_start, usage.expires_at, usage.up_bytes, usage.down_bytes] {out.extend_from_slice(&value.to_be_bytes())}
				}
				Self::Notices(notices) => {
					if notices.len() > NOTICES_MAX {return Err(EncodeError::Value)}
					out.push(notices.len() as u8);
					for notice in notices {
						out.push(notice.severity as u8);
						text(out, &notice.text, NOTICE_MAX)?;
					}
				}
				Self::Hints(hints) => {
					if hints.len() > HINTS_MAX {return Err(EncodeError::Value)}
					out.push(hints.len() as u8);
					for hint in hints {out.extend_from_slice(&[hint.transport, hint.candidate])}
				}
				Self::ProbeToken {token, max_size} => {
					out.extend_from_slice(&token.0);
					out.extend_from_slice(&max_size.to_be_bytes());
				}
				Self::ProbeAck {seq, size} => {
					out.push(*seq);
					out.extend_from_slice(&size.to_be_bytes());
				}
				Self::MtuResult {mtu} => out.extend_from_slice(&mtu.to_be_bytes()),
				Self::Bye {reason} => out.push(*reason as u8),
				Self::Error {code, answers} => {
					if !kind::REQUESTS.contains(answers) {return Err(EncodeError::Value)}
					out.extend_from_slice(&[*code as u8, *answers]);
				}
			}
			Ok(())
		})
	}
	/// Reads exactly one whole message, from its `length` to the last byte of its body.
	pub fn decode(message: &[u8]) -> Result<Self, DecodeError> {
		let (kind, mut body) = Reader::open(message, NODE_LIMIT)?;
		let decoded = match kind {
			kind::SESSION => {
				let (node_time, mtu, count) = (body.u64()?, body.u16()?, body.u8()?);
				if count != 1 && count != 2 {return Err(DecodeError::Value)}
				let (mut v4, mut v6) = (None, None);
				// "Families appear in the order IPv4 then IPv6, each at most once, and both addresses of an entry are of the same family."
				for _ in 0..count {
					match (body.address()?, body.address()?) {
						(IpAddr::V4(device), IpAddr::V4(gateway)) if v4.is_none() && v6.is_none() => v4 = Some(Addresses {device, gateway}),
						(IpAddr::V6(device), IpAddr::V6(gateway)) if v6.is_none() => v6 = Some(Addresses {device, gateway}),
						_ => return Err(DecodeError::Value),
					}
				}
				Self::Session(Session {node_time, mtu, v4, v6})
			}
			kind::EXITS => {
				let (flags, count) = (body.u8()?, usize::from(body.u8()?));
				if flags > 1 || count > EXITS_PER_MESSAGE {return Err(DecodeError::Value)}
				let mut entries = Vec::with_capacity(count);
				for _ in 0..count {
					let (tag, name, country, flags, load) = (body.tag(false)?, body.text()?, body.array::<2>()?, body.u8()?, Load::read(body.u8()?)?);
					if flags > 0x0f || (country != [0, 0] && !country.iter().all(u8::is_ascii_uppercase)) {return Err(DecodeError::Value)}
					entries.push(Exit {tag, name, country: (country != [0, 0]).then_some(country), all_protocols: flags & 1 != 0, selected: flags & 2 != 0, configured: flags & 4 != 0, working: flags & 8 != 0, load});
				}
				Self::Exits {last: flags == 1, entries}
			}
			kind::EXIT_RESULT => Self::ExitResult {status: ExitStatus::read(body.u8()?)?, tag: body.tag(true)?},
			kind::USAGE => Self::Usage(Usage {used_bytes: body.u64()?, quota_bytes: body.u64()?, period: Period::read(body.u8()?)?, period_start: body.u64()?, expires_at: body.u64()?, up_bytes: body.u64()?, down_bytes: body.u64()?}),
			kind::NOTICES => {
				let count = usize::from(body.u8()?);
				if count > NOTICES_MAX {return Err(DecodeError::Value)}
				let mut notices = Vec::with_capacity(count);
				for _ in 0..count {notices.push(Notice {severity: Severity::read(body.u8()?)?, text: body.text()?})}
				Self::Notices(notices)
			}
			kind::HINTS => {
				let count = usize::from(body.u8()?);
				if count > HINTS_MAX {return Err(DecodeError::Value)}
				let mut hints = Vec::with_capacity(count);
				for _ in 0..count {hints.push(Hint {transport: body.u8()?, candidate: body.u8()?})}
				Self::Hints(hints)
			}
			kind::PROBE_TOKEN => Self::ProbeToken {token: Token(body.array()?), max_size: body.u16()?},
			kind::PROBE_ACK => Self::ProbeAck {seq: body.u8()?, size: body.u16()?},
			kind::MTU_RESULT => Self::MtuResult {mtu: body.u16()?},
			kind::BYE => Self::Bye {reason: ByeReason::read(body.u8()?)?},
			kind::ERROR => {
				let (code, answers) = (ErrorCode::read(body.u8()?)?, body.u8()?);
				if !kind::REQUESTS.contains(&answers) {return Err(DecodeError::Value)}
				Self::Error {code, answers}
			}
			_ => return Err(DecodeError::Type),
		};
		body.end()?;
		Ok(decoded)
	}
}

// Cuts the byte stream of one direction into messages, whatever pieces it arrives in. It holds at most one message, and asks `lengths` at the third byte whether a message of that type can have that length, before it keeps anything of a body.
#[derive(Debug)]
pub(crate) struct Frames {pub(crate) buffer: Vec<u8>, lengths: fn(u8) -> Option<RangeInclusive<usize>>, preface: usize, complete: bool, failed: Option<DecodeError>}

impl Frames {
	// `preface` says the stream starts with the preface, which is checked byte by byte and then dropped.
	pub(crate) fn new(lengths: fn(u8) -> Option<RangeInclusive<usize>>, preface: bool) -> Self {Self {buffer: Vec::new(), lengths, preface: if preface {0} else {PREFACE.len()}, complete: false, failed: None}}
	pub(crate) fn fail(&mut self, error: DecodeError) -> DecodeError {
		self.failed = Some(error);
		error
	}
	// Takes bytes from the front of `input` and gives the next whole message. `None` means all of `input` was taken and more is needed. An error is final.
	pub(crate) fn read(&mut self, input: &mut &[u8]) -> Result<Option<&[u8]>, DecodeError> {
		if let Some(error) = self.failed {return Err(error)}
		if self.complete {
			self.buffer.clear();
			self.complete = false;
		}
		while let Some(expected) = PREFACE.get(self.preface) {
			let Some((byte, rest)) = input.split_first() else {return Ok(None)};
			if byte != expected {return Err(self.fail(DecodeError::Preface))}
			*input = rest;
			self.preface += 1;
		}
		let (head, rest) = input.split_at(input.len().min(3usize.saturating_sub(self.buffer.len())));
		self.buffer.extend_from_slice(head);
		*input = rest;
		let [high, low, ..] = self.buffer[..] else {return Ok(None)};
		let length = usize::from(u16::from_be_bytes([high, low]));
		if length == 0 {return Err(self.fail(DecodeError::Length))}
		let Some(&kind) = self.buffer.get(2) else {return Ok(None)};
		match (self.lengths)(kind) {
			None => return Err(self.fail(DecodeError::Type)),
			Some(lengths) if !lengths.contains(&length) => return Err(self.fail(DecodeError::Length)),
			Some(_) => {}
		}
		let (body, rest) = input.split_at(input.len().min((2 + length).saturating_sub(self.buffer.len())));
		self.buffer.extend_from_slice(body);
		*input = rest;
		if self.buffer.len() < 2 + length {return Ok(None)}
		self.complete = true;
		Ok(Some(&self.buffer[..]))
	}
}

/// The node's reader of what a client sends after the opening. It exists only as part of `opening::NodeOpened`, so there is none for a peer that has not authenticated.
#[derive(Debug)]
pub struct ClientMessages(Frames);

impl ClientMessages {
	pub(crate) fn new() -> Self {Self(Frames::new(client_lengths, false))}
	/// Takes bytes from the front of `input` and gives the next request. `None` means all of `input` was taken and more is needed. After a message, `input` holds what follows it: call again until `None`.
	/// An error is final, and every later call gives it again: the node closes the connection with no message. The largest request is 68 bytes, and nothing longer is kept.
	pub fn read(&mut self, input: &mut &[u8]) -> Result<Option<ClientMessage>, DecodeError> {
		let Some(message) = self.0.read(input)? else {return Ok(None)};
		let decoded = ClientMessage::decode(message);
		decoded.map(Some).map_err(|error| self.0.fail(error))
	}
}

/// The client's reader of what a node sends after the opening. It exists only as part of `opening::ClientOpened`, so nothing a node sent can be read before its credential was checked.
#[derive(Debug)]
pub struct NodeMessages(Frames);

impl NodeMessages {
	pub(crate) fn new() -> Self {Self(Frames::new(node_lengths, false))}
	/// Takes bytes from the front of `input` and gives the next message. `None` means all of `input` was taken and more is needed. After a message, `input` holds what follows it: call again until `None`.
	/// An error is final, and every later call gives it again: the client closes the connection and applies nothing from that message.
	pub fn read(&mut self, input: &mut &[u8]) -> Result<Option<NodeMessage>, DecodeError> {
		let Some(message) = self.0.read(input)? else {return Ok(None)};
		let decoded = NodeMessage::decode(message);
		decoded.map(Some).map_err(|error| self.0.fail(error))
	}
}

// The rules a whole catalogue keeps ("Messages"): at most 256 entries, no tag twice, at most one selected entry and at most one configured entry.
fn sound(entries: &[Exit]) -> bool {
	let mut tags = HashSet::new();
	entries.len() <= EXITS_MAX && entries.iter().all(|exit| tags.insert(exit.tag.as_str())) && entries.iter().filter(|exit| exit.selected).count() <= 1 && entries.iter().filter(|exit| exit.configured).count() <= 1
}

/// Puts the `exits` messages of one catalogue together on the client and checks it as a whole. A catalogue that breaks a rule is dropped whole, and the client closes the connection.
#[derive(Debug, Default)]
pub struct Catalogue {entries: Vec<Exit>, failed: bool}

impl Catalogue {
	/// Adds the entries of one `exits` message, and gives the whole catalogue when that message was the last. A later catalogue replaces the earlier one.
	/// Every message that is not the last carries exactly 64 entries. The last carries 1 to 64, or none when it is the only one. An error is final: what was collected is gone, and every later call fails.
	pub fn add(&mut self, last: bool, entries: Vec<Exit>) -> Result<Option<Vec<Exit>>, DecodeError> {
		let shaped = if last {!entries.is_empty() || self.entries.is_empty()} else {entries.len() == EXITS_PER_MESSAGE};
		if !self.failed && shaped && self.entries.len() + entries.len() <= EXITS_MAX {self.entries.extend(entries)} else {self.failed = true}
		if self.failed || !sound(&self.entries) {
			self.failed = true;
			self.entries = Vec::new();
			return Err(DecodeError::Value);
		}
		Ok(last.then(|| std::mem::take(&mut self.entries)))
	}
}

/// The `exits` messages of one catalogue, on the node, in its one encoding: 64 entries in every message but the last, which is marked. A catalogue with no entry is one empty message.
pub fn catalogue(entries: &[Exit]) -> Result<Vec<NodeMessage>, EncodeError> {
	if !sound(entries) {return Err(EncodeError::Value)}
	let parts = entries.len().div_ceil(EXITS_PER_MESSAGE).max(1);
	Ok((0..parts).map(|part| NodeMessage::Exits {last: part + 1 == parts, entries: entries.iter().skip(part * EXITS_PER_MESSAGE).take(EXITS_PER_MESSAGE).cloned().collect()}).collect())
}

/// The sizes a client probes, in order: the profile's `mtu`, then the sizes of the table below it, largest first ("MTU discovery", step 4). Empty for an `mtu` below 1280.
pub fn probe_sizes(mtu: u16) -> impl Iterator<Item = u16> {(mtu >= MTU_MIN).then_some(mtu).into_iter().chain(PROBE_SIZES.into_iter().rev().filter(move |size| *size < mtu))}

// The UDP payload of a probe whose inner IP packet is `size` bytes: the packet has no IP options and no extension headers, so its headers are 28 bytes on IPv4 and 48 on IPv6.
fn probe_payload(size: u16, v6: bool) -> Option<usize> {(size >= MTU_MIN).then(|| usize::from(size) - if v6 {48} else {28})}

/// Appends the UDP payload of an MTU probe whose inner IP packet is exactly `size` bytes: the token, `seq`, then the filler of zero bytes, `size` - 37 of them on IPv4 and `size` - 57 on IPv6 ("MTU discovery").
pub fn probe(token: &Token, seq: u8, size: u16, v6: bool, out: &mut Vec<u8>) -> Result<(), EncodeError> {
	let payload = probe_payload(size, v6).ok_or(EncodeError::Value)?;
	out.extend_from_slice(&token.0);
	out.push(seq);
	out.resize(out.len() + payload - 9, 0);
	Ok(())
}

/// Reads the UDP payload of an MTU probe that came in an IP packet of `size` bytes, and gives its token and `seq`. A payload that is not the one a probe of that size has is refused, which is the case when the packet carries IP options or extension headers, and so is a filler with any byte that is not zero.
pub fn read_probe(payload: &[u8], size: u16, v6: bool) -> Result<(Token, u8), DecodeError> {
	if probe_payload(size, v6) != Some(payload.len()) {return Err(DecodeError::Length)}
	let [token @ .., seq] = payload.get(..9).and_then(|head| <[u8; 9]>::try_from(head).ok()).ok_or(DecodeError::Body)?;
	if payload.iter().skip(9).any(|byte| *byte != 0) {return Err(DecodeError::Value)}
	Ok((Token(token), seq))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn unhex(text: &str) -> Vec<u8> {
		let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).map(|byte| (byte as char).to_digit(16).unwrap() as u8).collect();
		digits.chunks(2).map(|pair| pair[0] << 4 | pair[1]).collect()
	}

	fn exit(tag: &str) -> Exit {Exit {tag: tag.into(), name: "Berlin".into(), country: Some(*b"DE"), all_protocols: true, selected: false, configured: false, working: true, load: Load::Medium}}

	// Every vector is written out by hand from the tables of "Framing" and "Messages".
	fn client_vectors() -> Vec<(ClientMessage, Vec<u8>)> {
		vec![
			(ClientMessage::Refresh, unhex("0001 10")),
			(ClientMessage::SetExit {tag: "de".into()}, unhex("0004 11 02 6465")),
			(ClientMessage::SetExit {tag: String::new()}, unhex("0002 11 00")),
			(ClientMessage::ProbeStart, unhex("0001 12")),
			(ClientMessage::ProbeDown {seq: 3, size: 1390, port: 40000}, unhex("0006 13 03 056e 9c40")),
			(ClientMessage::SetMtu {mtu: 1280}, unhex("0003 14 0500")),
		]
	}

	fn node_vectors() -> Vec<(NodeMessage, Vec<u8>)> {
		let both = Session {node_time: 1_700_000_000, mtu: 1390, v4: Some(Addresses {device: Ipv4Addr::new(10, 7, 0, 2), gateway: Ipv4Addr::new(10, 7, 0, 1)}), v6: Some(Addresses {device: "fd00::2".parse().unwrap(), gateway: "fd00::1".parse().unwrap()})};
		vec![
			(NodeMessage::Session(both.clone()), unhex("0038 90 000000006553f100 056e 02 04 0a070002 04 0a070001 06 fd000000000000000000000000000002 06 fd000000000000000000000000000001")),
			(NodeMessage::Session(Session {v6: None, ..both.clone()}), unhex("0016 90 000000006553f100 056e 01 04 0a070002 04 0a070001")),
			(NodeMessage::Session(Session {v4: None, ..both}), unhex("002e 90 000000006553f100 056e 01 06 fd000000000000000000000000000002 06 fd000000000000000000000000000001")),
			(NodeMessage::Exits {last: true, entries: vec![Exit {selected: true, ..exit("de")}]}, unhex("0012 91 01 01 02 6465 0006 4265726c696e 4445 0b 02")),
			(NodeMessage::Exits {last: false, entries: vec![Exit {tag: "x".into(), name: "".into(), country: None, all_protocols: false, selected: false, configured: true, working: false, load: Load::Unknown}]}, unhex("000b 91 00 01 01 78 0000 0000 04 00")),
			(NodeMessage::Exits {last: true, entries: Vec::new()}, unhex("0003 91 01 00")),
			(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: "de".into()}, unhex("0005 92 00 02 6465")),
			(NodeMessage::ExitResult {status: ExitStatus::Refused, tag: String::new()}, unhex("0003 92 01 00")),
			(NodeMessage::Usage(Usage {used_bytes: 0x0102030405060708, quota_bytes: 0, period: Period::Monthly, period_start: 1_700_000_000, expires_at: 0, up_bytes: 2, down_bytes: 3}), unhex("0032 93 0102030405060708 0000000000000000 03 000000006553f100 0000000000000000 0000000000000002 0000000000000003")),
			(NodeMessage::Notices(vec![Notice {severity: Severity::Warning, text: "hi".into()}]), unhex("0007 94 01 01 0002 6869")),
			(NodeMessage::Notices(Vec::new()), unhex("0002 94 00")),
			(NodeMessage::Hints(vec![Hint {transport: 0, candidate: 1}, Hint {transport: 2, candidate: 3}]), unhex("0006 95 02 0001 0203")),
			(NodeMessage::Hints(Vec::new()), unhex("0002 95 00")),
			(NodeMessage::ProbeToken {token: Token([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]), max_size: 1390}, unhex("000b 96 a0a1a2a3a4a5a6a7 056e")),
			(NodeMessage::ProbeAck {seq: 3, size: 1390}, unhex("0004 97 03 056e")),
			(NodeMessage::MtuResult {mtu: 1280}, unhex("0003 98 0500")),
			(NodeMessage::Bye {reason: ByeReason::Quota}, unhex("0002 99 01")),
			(NodeMessage::Error {code: ErrorCode::RateLimited, answers: kind::SET_EXIT}, unhex("0003 9f 01 11")),
		]
	}

	#[test]
	fn every_message_byte_for_byte() {
		for (message, bytes) in client_vectors() {
			let mut out = Vec::new();
			message.encode(&mut out).unwrap();
			assert_eq!(out, bytes, "{message:?}");
			assert_eq!(ClientMessage::decode(&bytes), Ok(message));
		}
		for (message, bytes) in node_vectors() {
			let mut out = Vec::new();
			message.encode(&mut out).unwrap();
			assert_eq!(out, bytes, "{message:?}");
			assert_eq!(NodeMessage::decode(&bytes), Ok(message));
		}
	}

	// A 5 byte error and a 6 byte probe answer ("What a malicious client can do").
	#[test]
	fn the_sizes_the_page_states() {
		let node = node_vectors();
		assert_eq!((node.last().unwrap().1.len(), node[14].1.len()), (5, 6));
	}

	#[test]
	fn a_body_that_is_shorter_or_longer_than_its_layout_is_malformed() {
		for (_, bytes) in client_vectors() {
			let (mut long, mut short) = (bytes.clone(), bytes.clone());
			long.push(0);
			long[1] += 1;
			assert_eq!(ClientMessage::decode(&long), Err(DecodeError::Body), "{long:02x?}");
			short.pop();
			short[1] -= 1;
			assert!(ClientMessage::decode(&short).is_err(), "{short:02x?}");
			assert_eq!(ClientMessage::decode(&bytes[..bytes.len() - 1]), Err(DecodeError::Length));
		}
		for (_, bytes) in node_vectors() {
			let (mut long, mut short) = (bytes.clone(), bytes.clone());
			long.push(0);
			long[1] += 1;
			assert_eq!(NodeMessage::decode(&long), Err(DecodeError::Body), "{long:02x?}");
			short.pop();
			short[1] -= 1;
			assert!(NodeMessage::decode(&short).is_err(), "{short:02x?}");
			assert_eq!(NodeMessage::decode(&bytes[..bytes.len() - 1]), Err(DecodeError::Length));
		}
	}

	#[test]
	fn lengths_and_types() {
		for bytes in [&[][..], &[0], &[0, 0], &[0, 1]] {assert_eq!(ClientMessage::decode(bytes), Err(DecodeError::Length))}
		assert_eq!(NodeMessage::decode(&[0, 0]), Err(DecodeError::Length));
		// A node's type from a client, a client's type from a node, the types of the opening, and types nobody has.
		for kind in (0..=255u8).filter(|kind| !kind::REQUESTS.contains(kind)) {assert_eq!(ClientMessage::decode(&[0, 1, kind]), Err(DecodeError::Type))}
		for kind in [0x00, kind::HELLO, kind::AUTH, 0x10, 0x14, 0x80, kind::HELLO_REPLY, kind::AUTH_OK, 0x83, 0x8f, 0x9a, 0x9e, 0xa0, 0xff] {assert_eq!(NodeMessage::decode(&[0, 1, kind]), Err(DecodeError::Type))}
		let mut big = vec![0x10, 0x01, kind::SET_EXIT];
		big.resize(2 + 4097, 0);
		assert_eq!(ClientMessage::decode(&big), Err(DecodeError::Length));
		let mut largest = vec![0xff, 0xff, kind::NOTICES];
		largest.resize(2 + 65_535, 0);
		assert_eq!(NodeMessage::decode(&largest), Err(DecodeError::Body));
	}

	// The config's tag rule, on the wire in both directions. The first refused tag is the one a review got through: a letter, a right-to-left override, a newline, a NUL and a zero-width space.
	#[test]
	fn a_tag_follows_the_tag_rule() {
		let hostile = "a\u{202e}\n\0\u{200b}";
		assert_eq!(hostile.as_bytes(), unhex("61 e280ae 0a 00 e2808b"));
		let long = "a".repeat(65);
		let refused = [hostile, "", "De", "d e", "d.e", "_de", "-de", "d\u{e9}", long.as_str(), "all", "any", "block", "reject", "drop", "local", "direct", "user"];
		let accepted = ["de", "0", "d_e-9", "users", "all-in", &long[..64]];
		for tag in refused {
			assert!(!is_tag(tag), "{tag:?}");
			let (exits, result, set) = (format!("91 01 01 {:02x} {} 0000 0000 00 00", tag.len(), hex(tag)), format!("92 00 {:02x} {}", tag.len(), hex(tag)), format!("11 {:02x} {}", tag.len(), hex(tag)));
			assert_eq!(NodeMessage::decode(&framed(&exits)), Err(DecodeError::Value), "{tag:?}");
			assert_eq!(NodeMessage::decode(&framed(&result)).is_err(), !tag.is_empty(), "{tag:?}");
			assert_eq!(ClientMessage::decode(&framed(&set)).is_err(), !tag.is_empty(), "{tag:?}");
			let mut out = Vec::new();
			assert_eq!(NodeMessage::Exits {last: true, entries: vec![exit(tag)]}.encode(&mut out), Err(EncodeError::Value), "{tag:?}");
			assert_eq!(NodeMessage::ExitResult {status: ExitStatus::Selected, tag: tag.into()}.encode(&mut out).is_err(), !tag.is_empty(), "{tag:?}");
			assert_eq!(ClientMessage::SetExit {tag: tag.into()}.encode(&mut out).is_err(), !tag.is_empty(), "{tag:?}");
		}
		for tag in accepted {
			assert!(is_tag(tag), "{tag:?}");
			let mut out = Vec::new();
			ClientMessage::SetExit {tag: tag.into()}.encode(&mut out).unwrap();
			assert_eq!(ClientMessage::decode(&out), Ok(ClientMessage::SetExit {tag: tag.into()}));
			out.clear();
			NodeMessage::Exits {last: true, entries: vec![exit(tag)]}.encode(&mut out).unwrap();
			assert_eq!(NodeMessage::decode(&out), Ok(NodeMessage::Exits {last: true, entries: vec![exit(tag)]}));
		}
		assert_eq!(ClientMessage::decode(&unhex("0003 11 01 ff")), Err(DecodeError::Text));
	}

	fn hex(text: &str) -> String {text.bytes().map(|byte| format!("{byte:02x}")).collect()}

	// A message from its type and body, with the `length` they have.
	fn framed(rest: &str) -> Vec<u8> {
		let rest = unhex(rest);
		[&(rest.len() as u16).to_be_bytes()[..], &rest[..]].concat()
	}

	#[test]
	fn unknown_values_are_refused() {
		assert_eq!(ClientMessage::decode(&unhex("0003 11 02 64")), Err(DecodeError::Body));
		let refused = [
			// session: no family, three families, a family that is neither, IPv6 before IPv4, IPv4 twice, a pair of two families.
			"000c 90 000000006553f100 056e 00",
			"000c 90 000000006553f100 056e 03",
			"0016 90 000000006553f100 056e 01 05 0a070002 04 0a070001",
			"0038 90 000000006553f100 056e 02 06 fd000000000000000000000000000002 06 fd000000000000000000000000000001 04 0a070002 04 0a070001",
			"0020 90 000000006553f100 056e 02 04 0a070002 04 0a070001 04 0a070002 04 0a070001",
			"0022 90 000000006553f100 056e 01 04 0a070002 06 fd000000000000000000000000000001",
			// exits: a reserved flag bit of the message, an entry flag above bit 3, load 4, a lowercase country, half a country, a count above 64.
			"0012 91 03 01 02 6465 0006 4265726c696e 4445 0b 02",
			"0012 91 81 01 02 6465 0006 4265726c696e 4445 0b 02",
			"0012 91 01 01 02 6465 0006 4265726c696e 4445 1b 02",
			"0012 91 01 01 02 6465 0006 4265726c696e 4445 0b 04",
			"0012 91 01 01 02 6465 0006 4265726c696e 6465 0b 02",
			"0012 91 01 01 02 6465 0006 4265726c696e 4400 0b 02",
			"0003 91 01 41",
			// exit_result status 3, usage period 4, notices count 5, severity 2, hints count 17, bye 0 and 5, error code 0 and 4.
			"0003 92 03 00",
			"0032 93 0102030405060708 0000000000000000 04 000000006553f100 0000000000000000 0000000000000002 0000000000000003",
			"0002 94 05",
			"0007 94 01 02 0002 6869",
			"0002 95 11",
			"0002 99 00",
			"0002 99 05",
			"0003 9f 00 11",
			"0003 9f 04 11",
		];
		for bytes in refused {assert_eq!(NodeMessage::decode(&unhex(bytes)), Err(DecodeError::Value), "{bytes}")}
		assert_eq!(NodeMessage::decode(&unhex("0007 94 01 01 0002 c328")), Err(DecodeError::Text));
	}

	// "The type is one of 0x10 to 0x14": a bad hello or auth is never answered, and nothing a node sends is.
	#[test]
	fn an_error_answers_only_a_request() {
		for answers in 0..=255u8 {
			let (bytes, mut out) = ([0x00, 0x03, kind::ERROR, 0x01, answers], Vec::new());
			let written = NodeMessage::Error {code: ErrorCode::RateLimited, answers}.encode(&mut out);
			if (0x10..=0x14).contains(&answers) {
				assert_eq!((NodeMessage::decode(&bytes), written, &out[..]), (Ok(NodeMessage::Error {code: ErrorCode::RateLimited, answers}), Ok(()), &bytes[..]));
			} else {
				assert_eq!((NodeMessage::decode(&bytes), written), (Err(DecodeError::Value), Err(EncodeError::Value)), "{answers:#04x}");
			}
		}
	}

	#[test]
	fn an_encoder_refuses_what_a_decoder_would_refuse() {
		let mut out = vec![0xee];
		let refused = [
			NodeMessage::Session(Session {node_time: 0, mtu: 1280, v4: None, v6: None}),
			NodeMessage::Exits {last: true, entries: vec![exit("de"); 65]},
			NodeMessage::Exits {last: true, entries: vec![Exit {country: Some(*b"de"), ..exit("de")}]},
			NodeMessage::Exits {last: true, entries: vec![Exit {name: "a".repeat(257).into(), ..exit("de")}]},
			NodeMessage::Notices(vec![Notice {severity: Severity::Information, text: "".into()}; 5]),
			NodeMessage::Notices(vec![Notice {severity: Severity::Information, text: "a".repeat(281).into()}]),
			NodeMessage::Hints(vec![Hint {transport: 0, candidate: 0}; 17]),
		];
		for message in refused {assert_eq!(message.encode(&mut out), Err(EncodeError::Value), "{message:?}")}
		assert_eq!(out, [0xee]);
		// The largest messages a node writes fit their direction.
		NodeMessage::Exits {last: true, entries: vec![Exit {tag: "a".repeat(64), name: "a".repeat(256).into(), ..exit("de")}; 64]}.encode(&mut out).unwrap();
		NodeMessage::Notices(vec![Notice {severity: Severity::Warning, text: "a".repeat(280).into()}; 4]).encode(&mut out).unwrap();
		ClientMessage::SetExit {tag: "a".repeat(64)}.encode(&mut out).unwrap();
	}

	// Text over its limit is cut when shown, never a malformed body. What a client shows has no control, bidirectional or invisible character in it.
	#[test]
	fn display_text_is_filtered_and_then_cut() {
		let long_name = framed(&format!("91 01 01 02 6465 012c {} 4445 0b 02", "61".repeat(300)));
		let Ok(NodeMessage::Exits {entries, ..}) = NodeMessage::decode(&long_name) else {panic!("a long name is no malformed body")};
		assert_eq!((entries[0].name.as_sent().len(), entries[0].shown_name()), (300, "a".repeat(64)));
		let long_notice = framed(&format!("94 01 00 0190 {}", "c3a9".repeat(200)));
		let Ok(NodeMessage::Notices(notices)) = NodeMessage::decode(&long_notice) else {panic!("a long notice is no malformed body")};
		assert_eq!((notices[0].text.as_sent().len(), notices[0].shown_text()), (400, "\u{e9}".repeat(140)));
		// Filtered first: the 64 characters are counted after the invisible ones are gone.
		let hostile = Exit {name: format!("\u{202e}\u{200b}Ber\u{0}lin\r\n\u{feff}\u{2066}\u{ad}\u{61c}\u{e0041}\u{7f}\u{85}{}", "\u{200d}x".repeat(100)).into(), ..exit("de")};
		assert_eq!(hostile.shown_name(), format!("Berlin{}", "x".repeat(58)));
		let notice = Notice {severity: Severity::Warning, text: "line one\nline two\t\u{202e}tluser\u{202c} \u{1f600} \u{645}\u{631}\u{62d}\u{628}\u{627}".into()};
		assert_eq!(notice.shown_text(), "line oneline twotluser \u{1f600} \u{645}\u{631}\u{62d}\u{628}\u{627}");
		assert_eq!(display("\u{e9}\u{e9}\u{e9}", 5, 5), "\u{e9}\u{e9}");
		// The cut falls on a character boundary: a character that would cross the 280th byte is left out whole.
		let crossing = Notice {severity: Severity::Information, text: format!("{}\u{e9}tail", "a".repeat(279)).into()};
		assert_eq!(crossing.shown_text(), "a".repeat(279));
		assert_eq!(Exit {name: format!("{}\u{1f600}", "\u{645}".repeat(64)).into(), ..exit("de")}.shown_name(), "\u{645}".repeat(64));
		// Bytes that are not UTF-8 are a malformed body, in a name as in a notice or a tag.
		assert_eq!(NodeMessage::decode(&framed("91 01 01 02 6465 0002 c328 4445 0b 02")), Err(DecodeError::Text));
		assert_eq!(display("abc", 0, 9), "");
		// Characters that show nothing, or whatever a font makes of them, in the planes above the first as well.
		assert_eq!(display("a\u{2800}\u{fffc}\u{fff0}\u{fff8}\u{13430}\u{1343f}\u{1bca0}\u{1bca3}\u{e000}\u{f8ff}\u{f0000}\u{ffffd}\u{100000}\u{10fffd}\u{fdd0}\u{fdef}\u{fffe}\u{ffff}\u{1fffe}\u{10ffff}b\u{fffd}\u{27ff}\u{2801}\u{1342f}\u{1bc9f}", usize::MAX, usize::MAX), "ab\u{fffd}\u{27ff}\u{2801}\u{1342f}\u{1bc9f}");
		assert!(display(&('\0'..='\u{ffff}').collect::<String>(), usize::MAX, usize::MAX).chars().all(|c| !c.is_control() && !('\u{200b}'..='\u{200f}').contains(&c) && !('\u{2028}'..='\u{202e}').contains(&c) && !('\u{2060}'..='\u{206f}').contains(&c) && c != '\u{feff}'));
	}

	#[test]
	fn usage_is_clamped_for_display() {
		let usage = Usage {used_bytes: u64::MAX, quota_bytes: USAGE_CLAMP + 1, period: Period::Daily, period_start: u64::MAX, expires_at: USAGE_CLAMP, up_bytes: 7, down_bytes: 1 << 60};
		assert_eq!(usage.clamped(), Usage {used_bytes: USAGE_CLAMP, quota_bytes: USAGE_CLAMP, period: Period::Daily, period_start: USAGE_CLAMP, expires_at: USAGE_CLAMP, up_bytes: 7, down_bytes: USAGE_CLAMP});
	}

	#[test]
	fn a_probe_token_stays_out_of_debug_output() {
		assert_eq!(format!("{:?}", NodeMessage::ProbeToken {token: Token([0xa7; 8]), max_size: 1390}), "ProbeToken { token: Token(..), max_size: 1390 }");
	}

	#[test]
	fn the_stream_decoders_cut_at_message_ends() {
		let (mut up, mut down) = (Vec::new(), Vec::new());
		for (_, bytes) in client_vectors() {up.extend_from_slice(&bytes)}
		for (_, bytes) in node_vectors() {down.extend_from_slice(&bytes)}
		let (requests, pushes): (Vec<ClientMessage>, Vec<NodeMessage>) = (client_vectors().into_iter().map(|(message, _)| message).collect(), node_vectors().into_iter().map(|(message, _)| message).collect());
		for step in [1, 2, 3, 7, 44, down.len()] {
			let (mut client, mut node, mut seen_up, mut seen_down) = (ClientMessages::new(), NodeMessages::new(), Vec::new(), Vec::new());
			for mut piece in up.chunks(step) {
				while let Some(message) = client.read(&mut piece).unwrap() {seen_up.push(message)}
				assert!(piece.is_empty());
			}
			for mut piece in down.chunks(step) {
				while let Some(message) = node.read(&mut piece).unwrap() {seen_down.push(message)}
				assert!(piece.is_empty());
			}
			assert_eq!((&seen_up, &seen_down), (&requests, &pushes), "pieces of {step}");
		}
		let (mut decoder, mut input) = (NodeMessages::new(), &[0x00, 0x02, 0x99, 0x01, 0x00, 0x02, 0x99][..]);
		assert_eq!(decoder.read(&mut input), Ok(Some(NodeMessage::Bye {reason: ByeReason::Quota})));
		assert_eq!(input, [0x00, 0x02, 0x99]);
		assert_eq!((decoder.read(&mut input), input.len()), (Ok(None), 0));
	}

	// The limits of the two directions as the stream decoders enforce them: nothing longer than its type can be is kept, and the largest message of each direction reads.
	#[test]
	fn the_stream_decoders_refuse_at_the_third_byte_and_for_good() {
		let cases: [(&str, DecodeError); 9] = [("0000", DecodeError::Length), ("0001 01", DecodeError::Type), ("0022 01", DecodeError::Type), ("0021 02", DecodeError::Type), ("0001 90", DecodeError::Type), ("0002 10", DecodeError::Length), ("0043 11", DecodeError::Length), ("1000 11", DecodeError::Length), ("0007 13", DecodeError::Length)];
		for (head, error) in cases {
			let (mut decoder, bytes) = (ClientMessages::new(), [unhex(head), vec![0x10; 8]].concat());
			let mut input = &bytes[..];
			assert_eq!(decoder.read(&mut input), Err(error), "{head}");
			assert!(bytes.len() - input.len() <= 3 && decoder.0.buffer.len() <= 3, "{head}");
			assert_eq!(decoder.read(&mut &[0x00, 0x01, 0x10][..]), Err(error), "{head}");
		}
		let cases: [(&str, DecodeError); 8] = [("0000", DecodeError::Length), ("0001 10", DecodeError::Type), ("0022 81", DecodeError::Type), ("0021 82", DecodeError::Type), ("0039 90", DecodeError::Length), ("0033 93", DecodeError::Length), ("0003 99", DecodeError::Length), ("0044 92", DecodeError::Length)];
		for (head, error) in cases {
			let (mut decoder, bytes) = (NodeMessages::new(), [unhex(head), vec![0x10; 8]].concat());
			let mut input = &bytes[..];
			assert_eq!(decoder.read(&mut input), Err(error), "{head}");
			assert!(bytes.len() - input.len() <= 3 && decoder.0.buffer.len() <= 3, "{head}");
			assert_eq!(decoder.read(&mut &[0x00, 0x02, 0x99, 0x01][..]), Err(error), "{head}");
		}
		// A message that frames and does not decode ends the stream too.
		let mut decoder = ClientMessages::new();
		assert_eq!(decoder.read(&mut &unhex("0004 11 02 4445")[..]), Err(DecodeError::Value));
		assert_eq!(decoder.read(&mut &unhex("0001 10")[..]), Err(DecodeError::Value));
		// The largest request, 68 bytes, and the largest message of a node, 65,537 bytes.
		let mut largest = Vec::new();
		ClientMessage::SetExit {tag: "a".repeat(64)}.encode(&mut largest).unwrap();
		assert_eq!((largest.len(), ClientMessages::new().read(&mut &largest[..])), (68, Ok(Some(ClientMessage::SetExit {tag: "a".repeat(64)}))));
		let largest = framed(&format!("94 01 00 fffa {}", "61".repeat(65_530)));
		let Ok(Some(NodeMessage::Notices(notices))) = NodeMessages::new().read(&mut &largest[..]) else {panic!("the largest message of a node did not read")};
		assert_eq!((largest.len(), notices[0].text.as_sent().len(), notices[0].shown_text().len()), (65_537, 65_530, 280));
	}

	#[test]
	fn a_catalogue_has_one_encoding() {
		let entries: Vec<Exit> = (0..256).map(|index| Exit {selected: index == 3, configured: index == 200, ..exit(&format!("exit-{index}"))}).collect();
		let messages = catalogue(&entries).unwrap();
		assert_eq!(messages.iter().map(|message| matches!(message, NodeMessage::Exits {last: true, ..})).collect::<Vec<_>>(), [false, false, false, true]);
		let (mut assembled, mut whole) = (Catalogue::default(), None);
		for message in messages {
			let NodeMessage::Exits {last, entries} = message else {panic!("not an exits message")};
			assert_eq!(entries.len(), 64);
			whole = assembled.add(last, entries).unwrap();
		}
		assert_eq!(whole, Some(entries.clone()));
		// A later catalogue replaces the earlier one, and one with no exit is a single empty message.
		assert_eq!(assembled.add(true, Vec::new()), Ok(Some(Vec::new())));
		assert_eq!(assembled.add(true, entries[..5].to_vec()), Ok(Some(entries[..5].to_vec())));
		assert_eq!(catalogue(&[]).unwrap(), [NodeMessage::Exits {last: true, entries: Vec::new()}]);
		assert_eq!(catalogue(&entries[..64]).unwrap().len(), 1);
		let NodeMessage::Exits {entries: tail, ..} = &catalogue(&entries[..65]).unwrap()[1] else {panic!("not an exits message")};
		assert_eq!(tail.len(), 1);
		assert_eq!(catalogue(&[entries.clone(), vec![exit("one-more")]].concat()), Err(EncodeError::Value));
		assert_eq!(catalogue(&[exit("de"), exit("de")]), Err(EncodeError::Value));
		assert_eq!(catalogue(&[Exit {selected: true, ..exit("de")}, Exit {selected: true, ..exit("nl")}]), Err(EncodeError::Value));
		assert_eq!(catalogue(&[Exit {configured: true, ..exit("de")}, Exit {configured: true, ..exit("nl")}]), Err(EncodeError::Value));
	}

	#[test]
	fn a_catalogue_that_breaks_a_rule_is_dropped_whole_and_for_good() {
		let entries: Vec<Exit> = (0..300).map(|index| exit(&format!("exit-{index}"))).collect();
		let full = |from: usize| entries[from..from + 64].to_vec();
		// 256 entries and one message more: nothing comes back, also not from an empty last message afterwards.
		let mut catalogue = Catalogue::default();
		for part in 0..4 {assert_eq!(catalogue.add(false, full(part * 64)), Ok(None))}
		assert_eq!(catalogue.add(false, full(236)), Err(DecodeError::Value));
		assert_eq!(catalogue.add(true, Vec::new()), Err(DecodeError::Value));
		assert_eq!(catalogue.add(true, vec![exit("de")]), Err(DecodeError::Value));
		assert!(catalogue.entries.is_empty());
		let broken: [Vec<(bool, Vec<Exit>)>; 9] = [
			// A message that is not the last with fewer than 64 entries, with none, and 100,000 of those.
			vec![(false, entries[..63].to_vec())],
			vec![(false, Vec::new())],
			vec![(false, full(0)), (false, Vec::new())],
			// An empty last message after others.
			vec![(false, full(0)), (true, Vec::new())],
			// A tag twice, in one message and across two.
			vec![(true, vec![exit("de"), exit("de")])],
			vec![(false, full(0)), (true, vec![exit("exit-7")])],
			// Two selected entries, two configured entries.
			vec![(true, vec![Exit {selected: true, ..exit("de")}, Exit {selected: true, ..exit("nl")}])],
			vec![(false, (0..64).map(|index| Exit {configured: index == 0, ..entries[index].clone()}).collect()), (true, vec![Exit {configured: true, ..exit("nl")}])],
			// More than 256 in the last message.
			vec![(false, full(0)), (false, full(64)), (false, full(128)), (false, full(192)), (true, vec![exit("one-more")])],
		];
		for (case, messages) in broken.into_iter().enumerate() {
			let mut catalogue = Catalogue::default();
			let results: Vec<_> = messages.into_iter().map(|(last, entries)| catalogue.add(last, entries)).collect();
			assert_eq!(results.last(), Some(&Err(DecodeError::Value)), "case {case}");
			assert!(results[..results.len() - 1].iter().all(|result| *result == Ok(None)), "case {case}");
			assert_eq!(catalogue.add(true, vec![exit("de")]), Err(DecodeError::Value), "case {case}");
		}
		let mut catalogue = Catalogue::default();
		for _ in 0..100_000 {assert_eq!(catalogue.add(false, Vec::new()), Err(DecodeError::Value))}
		// One selected and one configured entry are what a catalogue has, on one exit or on two.
		assert!(Catalogue::default().add(true, vec![Exit {selected: true, configured: true, ..exit("de")}, exit("nl")]).unwrap().is_some());
	}

	#[test]
	fn probes() {
		assert_eq!(probe_sizes(1390).collect::<Vec<_>>(), [1390, 1360, 1320, 1280]);
		assert_eq!(probe_sizes(1500).collect::<Vec<_>>(), [1500, 1440, 1420, 1390, 1360, 1320, 1280]);
		assert_eq!(probe_sizes(1280).collect::<Vec<_>>(), [1280]);
		assert_eq!(probe_sizes(1279).count(), 0);
		let token = Token([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7]);
		let mut out = Vec::new();
		probe(&token, 3, 1280, false, &mut out).unwrap();
		// "The UDP payload is size - 28 or size - 48 bytes, and the filler is size - 37 or size - 57 bytes."
		assert_eq!((out.len(), &out[..10], out[9..].iter().filter(|byte| **byte == 0).count()), (1280 - 28, &[0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 3, 0][..], 1280 - 37));
		assert_eq!(read_probe(&out, 1280, false), Ok((token, 3)));
		// A packet with IP options or extension headers has a shorter payload for its length, and a payload of another size is no probe of this size.
		assert_eq!(read_probe(&out[..out.len() - 4], 1280, false), Err(DecodeError::Length));
		assert_eq!(read_probe(&out, 1280, true), Err(DecodeError::Length));
		assert_eq!(read_probe(&out, 1281, false), Err(DecodeError::Length));
		assert_eq!(read_probe(&out[..1279 - 28], 1279, false), Err(DecodeError::Length));
		for at in [9, 700, out.len() - 1] {
			let mut changed = out.clone();
			changed[at] = 1;
			assert_eq!(read_probe(&changed, 1280, false), Err(DecodeError::Value), "filler byte {at}");
		}
		out.clear();
		probe(&token, 4, 1390, true, &mut out).unwrap();
		assert_eq!((out.len(), out[9..].len(), read_probe(&out, 1390, true)), (1390 - 48, 1390 - 57, Ok((token, 4))));
		assert_eq!(probe(&token, 4, 1279, true, &mut out), Err(EncodeError::Value));
	}
}
