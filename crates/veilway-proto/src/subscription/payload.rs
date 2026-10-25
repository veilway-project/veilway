//! The payload of a subscription document (subscription format page, "Contents", and steps 4 to 6 of "What is checked, in order" as far as they need no clock and no stored state): strict JSON read into typed values.
//!
//! `parse` takes an `envelope::Verified` and nothing else, so what it reads was signed by a key that was held. That makes the input a provider's and not a stranger's. It does not make it friendly: every count, length and range is checked, nothing is clamped, and three kinds of unknown value are never guessed at ("Unknown members").
//!
//! What refuses what ("Wrong type, out of range, missing"): a fault in a top-level member refuses the document, a fault inside a profile refuses that profile, and a faulty card, notice, support link, listed device, exit or logo is left out. Display text is the stated exception: it is filtered and cut, never refused, except where it must not be empty. A text may come in several languages ("Text in several languages"), and a translation that does not read is dropped by itself: only `default` can make a text wrong.
use super::{envelope::{SigningKey, Verified}, exchange::{GatewayKey, KEYS_MAX}, hash, is_host, json::{self, Json, Members, Named}, key, mirror, public, visible, Kind, Secret, Tag, Text, Url, LINK_URL_MAX, STRING_MAX, TRANSLATIONS_MAX, URL_MAX};
use crate::{chunk::{NORMAL_BOUNDS, NORMAL_DEFAULT, WIDE_BOUNDS, WIDE_DEFAULT}, control::{self, display, is_tag, Period, Severity, EXITS_MAX, MTU_MIN, NOTICES_MAX, NOTICE_MAX, USAGE_CLAMP}, proof, request::PATH_MIN, session::KEEPALIVE, shape::Shape};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::HashSet, fmt, net::{IpAddr, SocketAddr}, ops::{Deref, RangeInclusive}};

pub use super::json::{JsonError, DEPTH_MAX, VALUES_MAX};

/// The one format version this crate reads ("Versioning").
pub const VERSION: u64 = 1;
/// The largest integer a document carries, 2^53 - 1: the limit the page gives `serial` and the counters, taken here for every integer without a narrower range, the times included.
pub const INTEGER_MAX: u64 = USAGE_CLAMP;
pub const PROFILES_MAX: usize = 64;
pub const TRANSPORTS_MAX: usize = 8;
/// "Candidates or endpoints per transport: 1 to 16."
pub const CANDIDATES_MAX: usize = 16;
pub const PINS_MAX: usize = 4;
pub const DEVICES_MAX: usize = 64;
pub const REFRESH_URLS_MAX: usize = 4;
pub const SUPPORT_MAX: usize = 4;
pub const CARDS_MAX: usize = 6;
/// "Logo: at most 65,536 bytes." The other half of the limit, 512 by 512 pixels, is the decoder's, which is not here.
pub const LOGO_MAX: usize = 65_536;
pub const LOGO_SIDE: u32 = 512;
/// "`update_interval`: 900 to 604,800 s, default 3,600."
pub const UPDATE_INTERVAL: RangeInclusive<u64> = 900..=604_800;
pub const UPDATE_DEFAULT: u32 = 3_600;
/// "Document lifetime (`expires_at` minus `issued_at`): at most 90 days."
pub const LIFETIME_MAX: u64 = 90 * 86_400;
/// "Width of the keepalive range in `padding`: at least 10 s."
pub const KEEPALIVE_WIDTH: u64 = 10;
pub const MTU_MAX: u64 = 1_500;
// The length of a display name, in characters, and the bytes that many characters can take.
const NAME: usize = 64;
const LABEL: usize = 32;

/// Why a verified payload is no document. The document is refused whole and the last good one stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
	/// Step 4: not strict JSON within the parsing limits.
	Json(JsonError),
	/// The payload is another JSON value than one object.
	Object,
	/// "A document with a `v` above what the client knows": the app needs an update to read this provider's subscription.
	Version,
	/// "A name in `critical` that the client does not know." Version 1 defines none.
	Critical,
	/// A `refusal` this page does not list.
	Refusal,
	/// A top-level member, by its name, that is missing, of another type or outside its range. For `usage` and `provider` it is the name of the member inside.
	Member(&'static str),
	/// `signing_keys` does not include the key that signed the document.
	Signer,
	/// "A document in which every profile was refused is refused."
	Profiles,
}

impl From<&'static str> for PayloadError {
	fn from(name: &'static str) -> Self {Self::Member(name)}
}

impl fmt::Display for PayloadError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "subscription payload: {self:?}")}
}

impl std::error::Error for PayloadError {}

macro_rules! closed {
	($(#[$meta:meta])* $name:ident {$($variant:ident = $word:literal),+}) => {
		$(#[$meta])*
		#[derive(Debug, Clone, Copy, PartialEq, Eq)]
		pub enum $name {$($variant),+}
		impl $name {
			/// Every value the field may hold.
			pub const ALL: &'static [Self] = &[$(Self::$variant),+];
			/// The value as a document writes it.
			pub fn word(self) -> &'static str {
				match self {$(Self::$variant => $word),+}
			}
			fn read(word: &str) -> Option<Self> {
				match word {
					$($word => Some(Self::$variant),)+
					_ => None,
				}
			}
		}
	};
}

closed!(
	/// `refusal` of a signed refusal ("The answer").
	Reason {DeviceLimit = "device_limit", Disabled = "disabled", Expired = "expired", RateLimited = "rate_limited", DeviceMismatch = "device_mismatch", KeyRetired = "key_retired", Released = "released", BadRequest = "bad_request"}
);
closed!(
	/// `rating_cap` of a profile. "It can only lower. There is no value that raises."
	RatingCap {Detectable = "detectable", Unsafe = "unsafe"}
);
closed!(
	/// `type` of a logo.
	LogoKind {Png = "png", Jpeg = "jpeg"}
);

/// `subscription_id`: "a string matching `[A-Za-z0-9_-]{16,64}`". It can hold nothing else, so it needs no filter before it is shown.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
	pub fn read(text: &str) -> Option<Self> {((16..=64).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')).then(|| Self(text.to_owned()))}
	pub fn as_str(&self) -> &str {&self.0}
}

/// An entry of `refresh_urls`: "a URL string, for an endpoint whose certificate is validated by its chain" or a plain `http` one, "or an object with exactly `url` and `pins`" for a pinned one. It derefs to its `Url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refresh {url: Url, pins: Vec<[u8; 32]>}

impl Refresh {
	// An entry as the reader of a document takes it: a URL string, or an object with exactly `url` and `pins`.
	fn read(item: &Json) -> Option<Self> {
		if let Json::Str(text) = item {Url::either(text, LINK_URL_MAX, true, false).map(|url| Self {url, pins: Vec::new()})} else {Members::of(item).filter(|entry| entry.0.len() == 2).and_then(|entry| Some(Self {url: Url::pinned(entry.string("url", LINK_URL_MAX).ok()??, LINK_URL_MAX, true, false)?, pins: pin_list(entry.list("pins", 1..=2).ok()??)?}))}
	}
	/// An entry from its JSON text, read by the rules a document's reader holds it to. A provider's panel uses this to refuse a setting that the apps would refuse in a signed document.
	pub fn parse(text: &str) -> Option<Self> {json::parse(text.as_bytes()).ok().and_then(|item| Self::read(&item))}
	pub fn url(&self) -> &Url {&self.url}
	/// The 1 or 2 pins a pinned entry is trusted by, none twice. Empty for an entry whose certificate is validated by its chain.
	pub fn pins(&self) -> &[[u8; 32]] {&self.pins}
	pub fn pinned(&self) -> bool {!self.pins.is_empty()}
	/// "Checked by chain, pinned, or plain."
	pub fn kind(&self) -> Kind {kind(&self.url, &self.pins)}
	/// What a user confirms, as `host:port`, for a pinned entry `host:port#pinned` and for a plain one `host:port#plain`: "a host and port together, with its kind".
	pub fn key(&self) -> String {
		match self.kind() {
			Kind::Chain => self.url.authority(),
			Kind::Pinned => format!("{}#pinned", self.url.authority()),
			Kind::Plain => format!("{}#plain", self.url.authority()),
		}
	}
}

// How an endpoint of this URL and these pins is reached.
fn kind(url: &Url, pins: &[[u8; 32]]) -> Kind {if url.is_plain() {Kind::Plain} else if pins.is_empty() {Kind::Chain} else {Kind::Pinned}}

/// `main_endpoint`: "the endpoint the provider wants this subscription to use". Naming the one the client holds asks for nothing, and naming another asks for a move ("Moving the main endpoint").
#[derive(Clone, PartialEq, Eq)]
pub struct MainEndpoint {pub url: Url, pub pins: Vec<[u8; 32]>, pub gateway_keys: Vec<GatewayKey>}

impl MainEndpoint {
	pub fn kind(&self) -> Kind {kind(&self.url, &self.pins)}
}

impl fmt::Debug for MainEndpoint {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "MainEndpoint({}, {:?}, {} keys)", self.url.host(), self.kind(), self.gateway_keys.len())}
}

impl Deref for Refresh {
	type Target = Url;
	fn deref(&self) -> &Url {&self.url}
}

/// What a verified payload is.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
	Subscription(Box<Subscription>),
	Refusal(Refusal),
}

/// A signed refusal: "a document in the same envelope whose payload has `v`, `subscription_id`, `issued_at` and `refusal`". Whether it is the stored subscription's and recent enough is for `client`, which has the stored id and the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {pub subscription_id: Id, pub issued_at: u64, pub reason: Reason}

/// Whether the device's WireGuard key was made on the device or by the provider ("Device keys").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
	/// No profile carries a `private_key`.
	Device,
	/// "Key issued by the provider": the weaker choice, in which the private key travels in every fetch and sits in the provider's database.
	Provider,
}

/// A subscription document. Its fields can be read by anyone and one can be made only by `parse`.
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct Subscription {
	pub id: Id,
	pub serial: u64,
	/// Unix seconds.
	pub issued_at: u64,
	/// Unix seconds. Later than `issued_at` by no more than `LIFETIME_MAX`.
	pub expires_at: u64,
	/// The keys a client holds once it has accepted this document: one or two, the signer among them.
	pub signing_keys: Vec<SigningKey>,
	/// "Shown as the provider's own claim, next to the fingerprint."
	pub provider: Text,
	/// Seconds between automatic refreshes.
	pub update_interval: u32,
	pub refresh_urls: Vec<Refresh>,
	/// "The gateway keys of the main endpoint, the active one first and the next one second", 1 or 2, none twice by id or by key, or empty when the document has none. Whether it may have none is for `client`: a document that has an endpoint must.
	pub gateway_keys: Vec<GatewayKey>,
	/// "The endpoint the provider wants this subscription to use." Whether it asks for a move is for `client`, which has the endpoint it holds.
	pub main_endpoint: Option<MainEndpoint>,
	/// "Base URLs of static mirrors": `https`, a host name, no pins, ending in `/`, none twice, none with the host and port of an entry of `refresh_urls`. That none has the link's endpoint's is for `client`. A static mirror receives no secret, and the user confirms it as a kind of its own (`Subscription::host_keys`).
	pub static_mirrors: Vec<Url>,
	/// "The pins of the link's endpoint", 1 or 2, none twice, or empty when the document has none. Whether it is allowed, and whether it holds a pin the client has, is for `client`: this document alone cannot say.
	pub endpoint_pins: Vec<[u8; 32]>,
	/// The profiles that read, in the provider's order.
	pub profiles: Vec<Profile>,
	/// The profiles that did not, for the app to tell the user "which profile was dropped and why".
	pub refused: Vec<RefusedProfile>,
	pub devices: Vec<Listed>,
	/// "Information for the screen, as old as the document. It decides nothing."
	pub usage: Option<Usage>,
	pub support: Vec<SupportLink>,
	/// The provider's terms and privacy policy, which the app asks the user to accept before the first connection and again when either link changes.
	pub agreement: Option<Agreement>,
	pub cards: Vec<Card>,
	pub logo: Option<Logo>,
	/// `accent` as red, green and blue. Adjusting it for contrast is the app's.
	pub accent: Option<[u8; 3]>,
	pub notices: Vec<Notice>,
	/// How many cards, notices, support links and listed devices were left out because they did not read, with one more for a usage and for a logo that was. Exits that were left out are not counted.
	pub left_out: usize,
}

impl Subscription {
	/// Whether a transport of any profile was left out for a type this version does not know: a newer app may use it.
	pub fn has_unknown_transport(&self) -> bool {self.profiles.iter().any(|profile| profile.dropped.iter().any(|drop| drop.cause == Cause::Unknown))}
	/// The text of this subscription for a notice the node of `profile` sent ("Languages" on the control channel page): the notice whose `default` is byte for byte the text the node sent, looked for "first in the `notices` of the profile it is connected through and then in the subscription's own `notices`". The app then shows `Text::pick` of it, and `None` means it shows `sent.shown_text()`.
	/// The severity is not given: it "is always the one the node sent". The number is the place in `notices` of this subscription when the match is one of its own, which is then the same notice on the screen, "not two".
	pub fn notice_text<'a>(&'a self, profile: &'a Profile, sent: &control::Notice) -> Option<(&'a Text, Option<usize>)> {profile.notices.iter().find(|notice| notice.text.is(&sent.text)).map(|notice| (&notice.text, None)).or_else(|| self.notices.iter().position(|notice| notice.text.is(&sent.text)).map(|place| (&self.notices[place].text, Some(place))))}
	/// What a user confirms for this document, as `Held` keeps it: every `Refresh::key`, then every static mirror as `mirror::host_key`.
	pub fn host_keys(&self) -> impl Iterator<Item = String> + '_ {self.refresh_urls.iter().map(Refresh::key).chain(self.static_mirrors.iter().map(mirror::host_key))}
	/// `Provider` when any profile carries a private key.
	pub fn origin(&self) -> KeyOrigin {if self.profiles.iter().any(|profile| profile.device.private_key.is_some()) {KeyOrigin::Provider} else {KeyOrigin::Device}}
	/// The addresses of every `udp` and `udp-obfs` endpoint of every profile. "A cover transport whose address is also the address of a `udp` or `udp-obfs` endpoint is capped at Detectable": the core, which computes ratings, compares each candidate's address with this set.
	/// Only the profiles' addresses, which is not the set a cap is computed from: the pinned endpoints of the link and of `refresh_urls` that are IP literals count too, and only the client knows the link. A cap uses `Held::datagram_addresses` or `Review::datagram_addresses`.
	pub fn profile_datagram_addresses(&self) -> HashSet<IpAddr> {self.profiles.iter().flat_map(|profile| &profile.transports).flat_map(|transport| if let Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) = transport {&endpoints[..]} else {&[]}).map(|dial| dial.address().ip()).collect()}
	/// The cover candidates whose address is in `datagram`, by their places in `profiles`, in the transports and in the lists of candidates as they are held (`Profile::document_place` gives the places the document wrote), as (profile, transport, candidate): "a cover transport whose address is also the address of a `udp` or `udp-obfs` endpoint is capped at Detectable". `datagram` is the set a cap is computed from, `Held::datagram_addresses` or `Review::datagram_addresses`. A `faketls` candidate is a cover candidate and is compared like any other.
	/// A cover candidate is also in the answer when its address or a name it uses (`host`, `sni`) is the address or the `host` of a `ws-plain` candidate of the subscription: "a covered transport that shares either with a `ws-plain` transport is capped at Detectable".
	pub fn capped(&self, datagram: &HashSet<IpAddr>) -> Vec<(usize, usize, usize)> {
		let plain: Vec<&Candidate> = self.profiles.iter().flat_map(|profile| &profile.transports).filter_map(|transport| if let Transport::WsPlain {stream, ..} = transport {Some(stream)} else {None}).flat_map(|stream| &stream.candidates).collect();
		let shared = |dial: &Dial, names: &[&str]| plain.iter().any(|other| other.address.address().ip() == dial.address().ip() || names.iter().any(|name| name.eq_ignore_ascii_case(&other.host)));
		let mut found = Vec::new();
		for (at, profile) in self.profiles.iter().enumerate() {
			for (place, transport) in profile.transports.iter().enumerate() {
				let addresses: Vec<(Dial, bool)> = match transport {
					Transport::Udp(_) | Transport::UdpObfs(_) | Transport::WsPlain {..} => Vec::new(),
					Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _) => stream.candidates.iter().map(|candidate| (candidate.address, shared(&candidate.address, &[&candidate.host, candidate.sni.as_deref().unwrap_or_default()]))).collect(),
					Transport::FakeTls {candidates, ..} => candidates.iter().map(|candidate| (candidate.address, shared(&candidate.address, &[&candidate.sni]))).collect(),
				};
				found.extend(addresses.iter().enumerate().filter(|(_, (dial, shared))| *shared || datagram.contains(&dial.address().ip())).map(|(candidate, _)| (at, place, candidate)));
			}
		}
		found
	}
}

/// Why a profile was refused while its document was kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
	/// An unknown `type` of the profile or of one of its transports: "not supported by this version of the app".
	Unsupported,
	/// A member, by its name, that is missing, of another type or outside its range.
	Member(&'static str),
	/// Its `id` is the `id` of another profile of the document. Neither is kept: the `id` is what the user's consents hang on, and nothing says which of the two they were given to.
	Duplicate,
}

impl From<&'static str> for Fault {
	fn from(name: &'static str) -> Self {Self::Member(name)}
}

/// A profile that was refused: its place in `profiles` of the document, its `id` if it has one that reads, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedProfile {pub position: usize, pub id: Option<String>, pub fault: Fault}

/// "A profile is what one device needs to reach one inbound."
#[derive(Clone, PartialEq)]
#[non_exhaustive]
pub struct Profile {
	/// `[a-z0-9][a-z0-9_-]{0,63}`, unique in the document.
	pub id: String,
	pub name: Text,
	/// `inbound_pub` of the protocol pages.
	pub inbound_public_key: [u8; 32],
	pub device: DeviceKeys,
	/// One per family of `device.addresses`, in the same order.
	pub gateways: Vec<IpAddr>,
	pub mtu: u16,
	/// Present whenever a `tls`, `ws`, `fronted` or `fronted-shaped` transport is listed. A `faketls` transport has a key of its own, and this one is never used in its place.
	pub transport_public_key: Option<[u8; 32]>,
	/// In the provider's order, without the ones that were left out. A hint of the control channel names one by its position in the document, which is `places`, not its position here.
	pub transports: Vec<Transport>,
	/// For each of `transports`, where the document wrote it and its candidates. Nothing that matches a position uses the index into `transports` or into a candidate list: it goes through this.
	pub places: Vec<Place>,
	/// What was left out of the profile while it was kept, in the document's order.
	pub dropped: Vec<Dropped>,
	pub stream_first: bool,
	pub parallel: u8,
	pub padding: Padding,
	/// The lowest version of the control channel the profile works with. A client that speaks none that high cannot use the profile.
	pub min_control_version: u8,
	pub rating_cap: Option<RatingCap>,
	pub exits: Vec<Exit>,
	/// The notices of this profile's node, at most 4. "The app does not show them by themselves": they are there so that `Subscription::notice_text` finds the translations of what the node sends.
	pub notices: Vec<Notice>,
}

/// Where the document wrote a transport that was kept, and each candidate of it that was kept (`endpoints` of `udp` and `udp-obfs` are all kept or the transport is refused, so for those it is 0 up).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {pub transport: usize, pub candidates: Vec<usize>}

/// Why part of a profile was left out while the profile was kept. The words are stable, for logs and for the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
	/// A candidate did not read.
	Candidate,
	/// Every candidate of a transport did not read, so the transport is left out.
	NoCandidates,
	/// A `faketls` transport without a key that reads, with a list of candidates that is not 1 to 16, or with a member it must not have.
	Faketls,
	/// A `faketls` key equal to the profile's `transport_public_key`.
	KeyOfProfile,
	/// A `faketls` or `ws-plain` key that another one of those has too. Neither is kept.
	KeyTwice,
	/// A `ws-plain` transport without a key or a cookie that read, with a member it must not have (`appearance` in version 1), or whose candidates or path did not read.
	WsPlain,
	/// A `ws-plain` transport whose host or path is one that a covered transport of the profile uses.
	Separation,
	/// A transport type this app does not know, which a newer app may.
	Unknown,
}

impl Cause {
	pub fn word(self) -> &'static str {
		match self {
			Self::Candidate => "candidate",
			Self::NoCandidates => "no_candidates",
			Self::Faketls => "faketls",
			Self::KeyOfProfile => "key_of_profile",
			Self::KeyTwice => "key_twice",
			Self::WsPlain => "ws_plain",
			Self::Separation => "separation",
			Self::Unknown => "unknown",
		}
	}
}

/// A transport (by its place in the document) that lost `count` candidates, or was itself left out, for `cause`. A transport left out for `NoCandidates` counts the candidates it had, and one left out for another cause counts 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {pub transport: usize, pub count: usize, pub cause: Cause}

impl Profile {
	/// The place in the document of candidate `candidate` of `transports[transport]`, as the profile holds them.
	pub fn document_place(&self, transport: usize, candidate: usize) -> Option<(usize, usize)> {
		let place = self.places.get(transport)?;
		Some((place.transport, *place.candidates.get(candidate)?))
	}
	/// What a position of the document, such as a hint's, names in this profile: the transport and the candidate as the profile holds them. `None` when the document's item was left out.
	pub fn find(&self, transport: usize, candidate: usize) -> Option<(usize, usize)> {
		let at = self.places.iter().position(|place| place.transport == transport)?;
		Some((at, self.places[at].candidates.iter().position(|place| *place == candidate)?))
	}
	/// The name of this profile's catalogue for an exit the node sent ("Languages" on the control channel page): the exit with the same tag, when its `default` is byte for byte the name the node sent. The app then shows `Text::pick` of it. `None` in every other case, and the app shows `sent.shown_name()`: "a signed label that has gone stale must not sit on an exit whose meaning the operator has changed".
	pub fn exit_name(&self, sent: &control::Exit) -> Option<&Text> {self.exits.iter().find(|exit| exit.tag == sent.tag).map(|exit| &exit.name).filter(|name| name.is(&sent.name))}
	/// "The same check covers the tunnel side: when a `device` address or a gateway falls inside one of the device's own networks, the profile cannot be used on that network."
	pub fn clashes(&self, networks: &[Network]) -> bool {self.device.addresses.iter().chain(&self.gateways).any(|address| own(*address, networks))}
}

/// `device` of a profile.
#[derive(Clone, PartialEq)]
pub struct DeviceKeys {
	/// `device_pub`.
	pub public_key: [u8; 32],
	/// "Present only when the provider made the key." Its public half is `public_key`.
	pub private_key: Option<Secret<32>>,
	pub preshared_key: Option<Secret<32>>,
	/// One or two: "at most one IPv4 and one IPv6, IPv4 first".
	pub addresses: Vec<IpAddr>,
	/// One or two. "The client uses the first."
	pub transport_secrets: Vec<Secret<32>>,
}

/// `padding` of a profile: the two upper bounds as `chunk::Padding::new` takes them, and the idle keepalive range in milliseconds as `session::KEEPALIVE` is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Padding {pub wide_max: u32, pub normal_max: u32, pub keepalive: RangeInclusive<u32>}

/// One transport of a profile. Its class is fixed by the transports page "and is never a field".
#[derive(Clone, PartialEq, Eq)]
pub enum Transport {
	Udp(Vec<Dial>),
	UdpObfs(Vec<Dial>),
	/// "Every candidate must have `pins`."
	Tls(Stream),
	/// "A candidate may have `pins`."
	Ws(Stream),
	/// "No candidate has `pins`."
	Fronted(Stream),
	/// A `fronted` whose requests and answers are in the shape the profile says (shapes page). Its candidates are those of `fronted`.
	FrontedShaped(Stream, Shape),
	/// Borrowed-site mode (borrowed-site page), alpha: `key` is the public key of this transport's own key on the node, `T_pub`, and the candidates are in the provider's order.
	FakeTls {key: [u8; 32], candidates: Vec<Borrowed>},
	/// WebSocket without TLS (transports page, `ws-plain`): `key` is the public half of the transport's own key on the node, `cookie` is the name the token travels under, and the candidates have an address and a `host` and nothing else.
	WsPlain {key: [u8; 32], cookie: String, stream: Stream},
}

impl Transport {
	/// The transport's type as the profile names it, which is also how a user picks one.
	pub fn name(&self) -> &'static str {
		match self {
			Self::Udp(_) => "udp",
			Self::UdpObfs(_) => "udp-obfs",
			Self::Tls(_) => "tls",
			Self::Ws(_) => "ws",
			Self::WsPlain {..} => "ws-plain",
			Self::Fronted(_) => "fronted",
			Self::FrontedShaped(..) => "fronted-shaped",
			Self::FakeTls {..} => "faketls",
		}
	}
}

/// A candidate of a `faketls` transport: the node's address, and in `sni` the name of the site the node borrows, never the node's own.
#[derive(Clone, PartialEq, Eq)]
pub struct Borrowed {pub address: Dial, pub sni: String}

/// What the three stream transports carry: 1 to 16 candidates and the path, which is "at least 12 characters" under the path rule of the config reference.
#[derive(Clone, PartialEq, Eq)]
pub struct Stream {pub path: String, pub candidates: Vec<Candidate>}

/// One fronting option ("Fronting options" on the transports page).
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
	pub address: Dial,
	/// `None` for an empty `sni`: no server name is sent.
	pub sni: Option<String>,
	pub host: String,
	/// Present exactly when `sni` is `None`, except on a self-signed candidate, which never has one.
	pub verify_name: Option<String>,
	/// An Encrypted Client Hello configuration of 1 to 1,024 bytes, as it is handed to the TLS library. It is not read here.
	pub ech: Option<Vec<u8>>,
	/// The SHA-256 of a certificate's SubjectPublicKeyInfo, 1 to 4 of them, or none: a candidate with pins is a "pinned candidate".
	pub pins: Vec<[u8; 32]>,
	/// `self_signed` of a `tls` candidate: the certificate is trusted through `pins` alone, and no chain, name or date of it is checked. Never true on another transport.
	pub self_signed: bool,
	/// `http2` of the candidate (http2 page, "Modes"): whether the client offers `h2` and speaks WebSocket over HTTP/2. Absent is `fetch`.
	pub http2: Http2,
}

/// How a candidate uses HTTP/2. `off`: `http/1.1` alone everywhere. `fetch`: `fronted` offers `h2` and `http/1.1`, `tls` and `ws` upgrade over HTTP/1.1 as before. `full`: as `fetch`, and `tls` and `ws` first try WebSocket over HTTP/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Http2 {Off, #[default] Fetch, Full}

/// An address "a client may be told to connect" to: an IP address and a port that passed the refusals made "when the document is parsed". The ones made at each connect are `Dial::own` and `Dial::private`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dial(SocketAddr);

impl Dial {
	/// Reads `192.0.2.10:51820` or `[2001:db8::10]:51820`. Refused: an address `dialable` refuses, port 0, a zone, and a port written with a leading zero.
	pub fn parse(text: &str) -> Option<Self> {text.parse().ok().filter(|address: &SocketAddr| !text.contains('%') && !text.rsplit(':').next().is_some_and(|port| port.starts_with('0')) && address.port() != 0 && dialable(address.ip())).map(Self)}
	pub fn address(&self) -> SocketAddr {self.0}
	/// "Skipped at each connect: an address inside one of the device's own networks." `networks` is what the device holds at this moment, see `own`.
	pub fn own(&self, networks: &[Network]) -> bool {own(self.0.ip(), networks)}
	/// "Asked about once per profile: any other private or shared address", see `private`.
	pub fn private(&self) -> bool {private(self.0.ip())}
}

/// Whether `address` is "private or shared", which a profile may name only with the user's yes, once: "this profile connects to a private address". The ranges are those of `geoip:private` in the config reference (`GEOIP_PRIVATE` of `veilway-core`, `config/mod.rs`, copied here because this crate does not depend on the core): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`, `fc00::/7` and `2001:db8::/32`. The caller asks it about the address of a legacy entry as well, and about every address a legacy name resolved to.
pub fn private(address: IpAddr) -> bool {
	pool(address) || match address {
		IpAddr::V4(ip) => ip.octets()[0] >= 240 || matches!(ip.octets(), [192, 0, 0 | 2, _] | [192, 88, 99, _] | [198, 18 | 19, _, _] | [198, 51, 100, _] | [203, 0, 113, _]),
		IpAddr::V6(ip) => ip.segments()[..2] == [0x2001, 0xdb8],
	}
}

/// Whether a client may be told to dial `address` at all, by a signed profile or by a legacy entry. Refused: "an address that is loopback, link-local, unspecified, multicast or broadcast, an IPv4-mapped IPv6 address", and with them what the config reference refuses for a node (`refused` and `embedded` of `veilway-core`, `engine/gate.rs`, whose list is copied here because this crate does not depend on the core): all of `0.0.0.0/8`, the site-local `fec0::/10`, and every IPv6 address that carries an IPv4 address inside it, which is IPv4-compatible and IPv4-translated, NAT64 (`64:ff9b::/96` and `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`). The node refuses such a form when the address inside is refused. A client refuses the form whole: on a network with a translator it reaches whatever IPv4 address it names, private ones included, with no question to the user.
/// A legacy entry may name a host. The caller asks this again for every address such a name resolves to, before it dials.
pub fn dialable(address: IpAddr) -> bool {
	!match address {
		IpAddr::V4(ip) => ip.octets()[0] == 0 || ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast(),
		IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.segments()[0] & 0xff80 == 0xfe80 || matches!(ip.segments(), [0, 0, 0, 0, 0, 0 | 0xffff, _, _] | [0, 0, 0, 0, 0xffff, 0, _, _] | [0x64, 0xff9b, 0, 0, 0, 0, _, _] | [0x64, 0xff9b, 1, ..] | [0x2002, ..] | [0x2001, 0, ..]),
	}
}

/// One of "the device's own networks": the network of an address the device holds on an interface that is not a tunnel, with the prefix the interface has. The address of the default gateway goes in as a network of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {address: IpAddr, prefix: u8}

impl Network {
	/// `None` for a prefix longer than the address.
	pub fn new(address: IpAddr, prefix: u8) -> Option<Self> {(prefix <= if address.is_ipv4() {32} else {128}).then_some(Self {address, prefix})}
	pub fn address(&self) -> IpAddr {self.address}
	pub fn prefix(&self) -> u8 {self.prefix}
	pub fn contains(&self, address: IpAddr) -> bool {
		match (self.address, address) {
			(IpAddr::V4(network), IpAddr::V4(address)) => u32::from(network) ^ u32::from(address) < 1u32.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0) || self.prefix == 0,
			(IpAddr::V6(network), IpAddr::V6(address)) => u128::from(network) ^ u128::from(address) < 1u128.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0) || self.prefix == 0,
			_ => false,
		}
	}
}

/// The connect-time check: whether `address` lies inside one of the device's own networks. "The check is made again at every connect, because the device's networks change when it moves", so the caller reads its interfaces each time and this function keeps nothing.
pub fn own(address: IpAddr, networks: &[Network]) -> bool {networks.iter().any(|network| network.contains(address))}

// The ranges the config reference allows for a pool, which are also the "private or shared" ranges of a dial address: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` and `fc00::/7`.
fn pool(address: IpAddr) -> bool {
	match address {
		IpAddr::V4(ip) => ip.is_private() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64),
		IpAddr::V6(ip) => ip.segments()[0] & 0xfe00 == 0xfc00,
	}
}

/// An entry of `exits`: what the user sees before connecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
	pub tag: String,
	pub name: Text,
	/// Two uppercase ASCII letters.
	pub country: Option<[u8; 2]>,
	/// "Whether the exit carries every IP protocol."
	pub full_ip: bool,
}

/// An entry of `devices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
	/// The name the user gave it. May be empty.
	pub name: Text,
	/// Unix seconds.
	pub enrolled_at: u64,
	/// True for the asking device, which at most one entry is.
	pub this: bool,
	pub pending: bool,
}

/// `usage`. `quota_bytes`, `period_start`, `expires_at` and `device_limit` are 0 for none. "A client never refuses to connect because of these numbers."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {pub used_bytes: u64, pub quota_bytes: u64, pub period: Period, pub period_start: u64, pub expires_at: u64, pub device_limit: u16}

/// An entry of `support`. The URL "is opened only after the user confirms a screen that shows that host, in the system's browser".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportLink {pub label: Text, pub url: Url}

/// `agreement`: at least one of `terms` and `privacy`. Opened like a support link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreement {pub terms: Option<Url>, pub privacy: Option<Url>}

/// An entry of `notices`, and a card of the type `notice`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {pub severity: Severity, pub text: Text}

/// A card: data, never code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Card {
	Stat {label: Text, value: Text, unit: Option<Text>},
	/// `used` is not above `total`, and `total` is above 0.
	Progress {label: Text, used: u64, total: u64},
	Notice(Notice),
	Link {label: Text, url: Url},
}

/// The logo as bytes: 1 to `LOGO_MAX` of them, and a claim about what they are. Nothing here has looked inside. "The client decodes it with size limits, refuses more than 512 by 512 pixels or anything that is not a plain still image, and re-encodes it before it is shown."
#[derive(Clone, PartialEq, Eq)]
pub struct Logo {pub kind: LogoKind, pub data: Vec<u8>}

// What a document prints of itself: what tells one document, profile or transport from another in a log, and counts. A document is the node list of a provider and the keys of a device, so no address, name, path, pin or key of it is printed by any of these.
impl fmt::Debug for Subscription {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Subscription({}, serial {}, {} profiles, {} refused)", self.id.as_str(), self.serial, self.profiles.len(), self.refused.len())}
}

impl fmt::Debug for Profile {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Profile({}, {} transports, {} exits)", self.id, self.transports.len(), self.exits.len())}
}

impl fmt::Debug for DeviceKeys {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "DeviceKeys({} addresses, {} transport secrets, ..)", self.addresses.len(), self.transport_secrets.len())}
}

impl fmt::Debug for Transport {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Udp(endpoints) => write!(f, "Udp({} endpoints)", endpoints.len()),
			Self::UdpObfs(endpoints) => write!(f, "UdpObfs({} endpoints)", endpoints.len()),
			Self::Tls(stream) => write!(f, "Tls({} candidates)", stream.candidates.len()),
			Self::Ws(stream) => write!(f, "Ws({} candidates)", stream.candidates.len()),
			Self::Fronted(stream) => write!(f, "Fronted({} candidates)", stream.candidates.len()),
			Self::FrontedShaped(stream, _) => write!(f, "FrontedShaped({} candidates)", stream.candidates.len()),
			Self::FakeTls {candidates, ..} => write!(f, "FakeTls({} candidates)", candidates.len()),
			Self::WsPlain {stream, ..} => write!(f, "WsPlain({} candidates)", stream.candidates.len()),
		}
	}
}

impl fmt::Debug for Stream {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Stream({} candidates)", self.candidates.len())}
}

impl fmt::Debug for Candidate {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Candidate({} pins{})", self.pins.len(), if self.self_signed {", self-signed"} else {""})}
}

impl fmt::Debug for Borrowed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Borrowed({:?})", self.address)}
}

impl fmt::Debug for Dial {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str(if self.0.is_ipv4() {"Dial(IPv4)"} else {"Dial(IPv6)"})}
}

impl fmt::Debug for Logo {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Logo({:?}, {} bytes)", self.kind, self.data.len())}
}

fn need<T>(name: &'static str, value: Named<Option<T>>) -> Named<T> {value?.ok_or(name)}

// Display text: filtered, then cut to `chars` characters and `bytes` bytes. It is refused only where it must show something (`filled`: a name of 1 to 64 characters) and shows nothing once the filter has run. A string of any length is taken, since what is over the limit is cut and the size of the document bounds the rest.
// "Text in several languages": a string, or an object with `default` and translations. "Only `default` can make a text wrong." Of the other members those named by a legal tag are counted in the order of the document and the first 8 are looked at. The page does not say whether a legal tag with a value that is then dropped takes one of the 8 places. Here it does, which keeps the fewest: a place is taken by the tag, whatever its value comes to.
fn text(members: Members, name: &'static str, filled: bool, chars: usize, bytes: usize) -> Named<Option<Text>> {
	let fit = |sent: &str| Some(display(sent, chars, bytes)).filter(|shown| !filled || visible(shown));
	let (sent, object) = match members.get(name) {
		None => return Ok(None),
		Some(Json::Str(sent)) => (sent, None),
		Some(Json::Obj(object)) => if let Some((_, Json::Str(sent))) = object.get("default") {(sent, Some(object))} else {return Err(name)},
		Some(_) => return Err(name),
	};
	let mut tagged: Vec<(usize, Tag, &Json)> = object.into_iter().flatten().filter_map(|(tag, (place, value))| Some((*place, Tag::read(tag)?, value))).collect();
	tagged.sort_by_key(|(place, ..)| *place);
	tagged.truncate(TRANSLATIONS_MAX);
	// "A translation that fails that requirement, or is empty after the filter, is dropped and the others stay."
	let translations = tagged.into_iter().filter_map(|(_, tag, value)| if let Json::Str(sent) = value {fit(sent).filter(|shown| !shown.is_empty()).map(|shown| (tag, shown))} else {None}).collect();
	Ok(Some(Text::translated(sent, fit(sent).ok_or(name)?, translations)))
}

// A key of 32 bytes. `read` is `key` for a secret one and `public` for a public key of X25519, which is refused when it is a point of small order, as an endpoint refuses it in a request.
fn key32(members: Members, name: &'static str, read: fn(&str) -> Option<[u8; 32]>) -> Named<Option<[u8; 32]>> {members.string(name, 44)?.map(|text| read(text).ok_or(name)).transpose()}

// Every `url` but a refresh URL: "an `https` URL with a host name, no user or password part, at most 512 characters".
fn url(members: Members) -> Option<Url> {members.string("url", URL_MAX).ok().flatten().and_then(|text| Url::parse(text, URL_MAX, true, true))}

// The pins of an endpoint: 1 or 2 hashes in standard base64, and not the same one twice, which would pass for a standby that is not there.
fn pin_list(pins: &[Json]) -> Option<Vec<[u8; 32]>> {
	let pins = pins.iter().map(|pin| if let Json::Str(text) = pin {hash(text)} else {None}).collect::<Option<Vec<_>>>()?;
	(!pins.is_empty() && pins.len() <= 2 && (pins.len() == 1 || pins[0] != pins[1])).then_some(pins)
}

// "The gateway keys of an endpoint": 1 or 2 objects with exactly `id`, an integer from 0 to 255, and `key`, an X25519 public key in the form of "Keys", none of small order and none twice by id or by key.
fn gateway_keys(members: Members, error: &'static str, required: bool) -> Named<Vec<GatewayKey>> {
	let Some(list) = members.list("gateway_keys", 1..=KEYS_MAX).map_err(|_| error)? else {return if required {Err(error)} else {Ok(Vec::new())}};
	let keys = list.iter().map(|item| Members::of(item).filter(|entry| entry.0.len() == 2).and_then(|entry| GatewayKey::new(u8::try_from(entry.uint("id", 0..=255).ok()??).ok()?, public(entry.string("key", 44).ok()??)?)).ok_or(error)).collect::<Named<Vec<_>>>()?;
	if keys.len() == 2 && (keys[0].id() == keys[1].id() || keys[0].public() == keys[1].public()) {return Err(error)}
	Ok(keys)
}

// `main_endpoint`: `url` of an `https` or an `http` endpoint, `pins` only for `https` and then the way to an IP literal, and the gateway keys behind it. A fault anywhere refuses the document.
fn main_endpoint(members: Members) -> Named<Option<MainEndpoint>> {
	let Some(entry) = members.object("main_endpoint")? else {return Ok(None)};
	let text = entry.string("url", LINK_URL_MAX).map_err(|_| "main_endpoint")?.ok_or("main_endpoint")?;
	let pins = entry.list("pins", 1..=2).map_err(|_| "main_endpoint")?.map(|pins| pin_list(pins).ok_or("main_endpoint")).transpose()?.unwrap_or_default();
	let url = (if pins.is_empty() {Url::either(text, LINK_URL_MAX, false, false)} else {Url::pinned(text, LINK_URL_MAX, false, false)}).ok_or("main_endpoint")?;
	Ok(Some(MainEndpoint {url, pins, gateway_keys: gateway_keys(entry, "main_endpoint", true)?}))
}

fn severity(members: Members) -> Option<Severity> {
	match members.string("severity", STRING_MAX) {
		Ok(Some("info")) => Some(Severity::Information),
		Ok(Some("warning")) => Some(Severity::Warning),
		_ => None,
	}
}

// "`severity` (`"info"` or `"warning"`) and `text` (display text, cut to 280 bytes)."
pub(crate) fn notice(members: Members) -> Option<Notice> {Some(Notice {severity: severity(members)?, text: text(members, "text", false, usize::MAX, NOTICE_MAX).ok()??})}

fn card(members: Members) -> Option<Card> {
	let label = || text(members, "label", false, LABEL, 4 * LABEL).ok().flatten();
	Some(match members.string("type", STRING_MAX).ok()?? {
		"stat" => Card::Stat {label: label()?, value: text(members, "value", false, 16, 64).ok()??, unit: text(members, "unit", false, 8, 32).ok()?},
		"progress" => {
			let (used, total) = (members.uint("used", 0..=INTEGER_MAX).ok()??, members.uint("total", 1..=INTEGER_MAX).ok()??);
			if used > total {return None}
			Card::Progress {label: label()?, used, total}
		}
		"notice" => Card::Notice(notice(members)?),
		"link" => Card::Link {label: label()?, url: url(members)?},
		_ => return None,
	})
}

fn logo(value: &Json) -> Option<Logo> {
	let members = Members::of(value)?;
	let (kind, data) = (LogoKind::read(members.string("type", STRING_MAX).ok()??)?, STANDARD.decode(members.string("data", LOGO_MAX.div_ceil(3) * 4).ok()??).ok()?);
	(!data.is_empty() && data.len() <= LOGO_MAX).then_some(Logo {kind, data})
}

// `usage` "decides nothing", so whatever is wrong with it leaves it out and keeps the document: a member that is missing, of another type or out of range, and an unknown `period`, which "refuses the object that holds it".
fn usage(value: &Json) -> Option<Usage> {
	let members = Members::of(value)?;
	let (number, period) = (|name: &'static str, most: u64| members.uint(name, 0..=most).ok().flatten(), match members.string("period", STRING_MAX).ok()?? {
		"none" => Period::None,
		"daily" => Period::Daily,
		"weekly" => Period::Weekly,
		"monthly" => Period::Monthly,
		_ => return None,
	});
	Some(Usage {used_bytes: number("used_bytes", INTEGER_MAX)?, quota_bytes: number("quota_bytes", INTEGER_MAX)?, period, period_start: number("period_start", INTEGER_MAX)?, expires_at: number("expires_at", INTEGER_MAX)?, device_limit: number("device_limit", 65_535)? as u16})
}

// A list whose entries that do not read are left out and counted.
fn kept<T>(members: Members, name: &'static str, limit: usize, left_out: &mut usize, read: impl Fn(Members) -> Option<T>) -> Named<Vec<T>> {
	let items = members.list(name, 0..=limit)?.unwrap_or_default();
	let good: Vec<T> = items.iter().filter_map(|item| Members::of(item).and_then(&read)).collect();
	*left_out += items.len() - good.len();
	Ok(good)
}

// "A device's name, which the user typed", is one string and never an object of translations.
fn listed(members: Members) -> Option<Listed> {Some(Listed {name: Text::shown(members.string("name", usize::MAX).ok()??, LABEL, 4 * LABEL), enrolled_at: members.uint("enrolled_at", 0..=INTEGER_MAX).ok()??, this: members.boolean("this").ok()??, pending: members.boolean("pending").ok()?.unwrap_or(false)})}

fn exit(members: Members) -> Option<Exit> {
	let country = match members.string("country", 2) {
		Ok(None) => None,
		Ok(Some(country)) => Some(<[u8; 2]>::try_from(country.as_bytes()).ok().filter(|letters| letters.iter().all(u8::is_ascii_uppercase))?),
		Err(_) => return None,
	};
	Some(Exit {tag: members.string("tag", 64).ok()?.filter(|tag| is_tag(tag))?.to_owned(), name: text(members, "name", true, NAME, 4 * NAME).ok()??, country, full_ip: members.boolean("full_ip").ok()?.unwrap_or(false)})
}

// One or two addresses of a tunnel: "at most one IPv4 and one IPv6, IPv4 first, inside the ranges the config reference allows for a pool".
pub(crate) fn addresses(members: Members, name: &'static str) -> Named<Vec<IpAddr>> {
	let read = need(name, members.list(name, 1..=2))?.iter().map(|item| if let Json::Str(text) = item {text.parse().ok().filter(|address| pool(*address))} else {None}.ok_or(name)).collect::<Named<Vec<IpAddr>>>()?;
	if read.len() == 2 && !(read[0].is_ipv4() && read[1].is_ipv6()) {return Err(name)}
	Ok(read)
}

#[derive(Clone, Copy, PartialEq)]
enum Pins {Required, Allowed, Forbidden, Plain}

// What a `faketls` transport and its candidates do not have: there is no front, no path and no certificate to check but the one the client derives. One of them refuses the candidate it is on, or the transport when it is on the transport.
const BORROWED_NOT: [&str; 8] = ["path", "host", "verify_name", "ech", "pins", "self_signed", "http2", "shape"];

fn host<'a>(members: Members<'a>, name: &'static str) -> Named<Option<&'a str>> {members.string(name, 253)?.map(|host| Some(host).filter(|host| is_host(host)).ok_or(name)).transpose()}

fn candidate(value: &Json, rule: Pins) -> Named<Candidate> {
	let members = Members::of(value).ok_or("candidates")?;
	let address = Dial::parse(need("address", members.string("address", STRING_MAX))?).ok_or("address")?;
	// A `ws-plain` candidate has an address and a `host` for the Host field: there is no TLS to name, check or pin.
	if rule == Pins::Plain {
		if let Some(name) = ["sni", "verify_name", "pins", "ech", "self_signed", "http2"].into_iter().find(|name| members.get(name).is_some()) {return Err(name)}
		return Ok(Candidate {address, sni: None, host: need("host", host(members, "host"))?.to_owned(), verify_name: None, ech: None, pins: Vec::new(), self_signed: false, http2: Http2::Fetch});
	}
	// "`self_signed` on a candidate of any other transport, or a value that is not a boolean, refuses that candidate." Only `tls` requires pins.
	let self_signed = members.boolean("self_signed")?;
	if self_signed.is_some() && rule != Pins::Required {return Err("self_signed")}
	let self_signed = self_signed.unwrap_or(false);
	// `sni` is "a host name, or empty for none", so it is a member that is always there. Only an empty one is read as none.
	let sni = Some(need("sni", members.string("sni", 253))?).filter(|sni| !sni.is_empty());
	if sni.is_some_and(|sni| !is_host(sni)) {return Err("sni")}
	let verify_name = host(members, "verify_name")?;
	// "Required when `sni` is empty and not allowed otherwise." A self-signed candidate "has no `verify_name`, since no name is checked", and its `sni` may be empty.
	if (self_signed && verify_name.is_some()) || (!self_signed && verify_name.is_some() == sni.is_some()) {return Err("verify_name")}
	// "`http2`: `off`, `fetch` (the default) or `full`." Any other value, or one that is no string, refuses the candidate.
	let http2 = match members.string("http2", 8)? {None => Http2::Fetch, Some("off") => Http2::Off, Some("fetch") => Http2::Fetch, Some("full") => Http2::Full, Some(_) => return Err("http2")};
	let ech = members.string("ech", 1_368)?.map(|text| STANDARD.decode(text).ok().filter(|ech| (1..=1_024).contains(&ech.len())).ok_or("ech")).transpose()?;
	let pins = members.list("pins", 1..=PINS_MAX)?.map(|pins| pins.iter().map(|pin| if let Json::Str(text) = pin {hash(text)} else {None}.ok_or("pins")).collect::<Named<Vec<_>>>()).transpose()?;
	if (rule == Pins::Required && pins.is_none()) || (rule == Pins::Forbidden && pins.is_some()) {return Err("pins")}
	Ok(Candidate {address, sni: sni.map(str::to_owned), host: need("host", host(members, "host"))?.to_owned(), verify_name: verify_name.map(str::to_owned), ech, pins: pins.unwrap_or_default(), self_signed, http2})
}

/// One transport as `transport` read it: the transport, or `None` when it is left out, the places in the document of the candidates (or endpoints) that were kept, and what was dropped, if anything, as a cause and a count.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Read {pub transport: Option<Transport>, pub places: Vec<usize>, pub dropped: Option<(Cause, usize)>}

/// One transport of a profile, or one that is left out: one whose candidates were all refused, or a `faketls` transport that is refused. A fault that refuses the profile is an `Err`.
/// "A candidate with a member it must not have refuses that candidate and nothing else. A transport whose candidates are all refused is left out." Every candidate is read alone, of every type, and whatever is wrong with it costs it alone. What was left out is in the answer, with the places in the document of what was kept.
pub(crate) fn transport(value: &Json) -> Result<Read, Fault> {
	let members = Members::of(value).ok_or("transports")?;
	let endpoints = || need("endpoints", members.list("endpoints", 1..=CANDIDATES_MAX))?.iter().map(|item| if let Json::Str(text) = item {Dial::parse(text)} else {None}.ok_or("endpoints")).collect::<Named<Vec<_>>>();
	// The stream that read, the places of its candidates in the document and how many candidates did not read.
	let stream = |rule: Pins| -> Named<(Option<Stream>, Vec<usize>, usize)> {
		// "`path` follows the path rule of the config reference and is at least 12 characters": it starts with `/`, is at most 256 bytes from `A-Z a-z 0-9 . _ ~ / -` and has no `..` component.
		let path = need("path", members.string("path", 256))?;
		if path.len() < PATH_MIN || !path.starts_with('/') || !path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._~/-".contains(&byte)) || path.split('/').any(|part| part == "..") {return Err("path")}
		let list = need("candidates", members.list("candidates", 1..=CANDIDATES_MAX))?;
		let (candidates, places): (Vec<Candidate>, Vec<usize>) = list.iter().enumerate().filter_map(|(at, item)| candidate(item, rule).ok().map(|found| (found, at))).unzip();
		let left = list.len() - places.len();
		Ok(((!candidates.is_empty()).then(|| Stream {path: path.to_owned(), candidates}), places, left))
	};
	// A transport that was made, or none because no candidate of it read: then the count is what it had.
	fn made(transport: Option<Transport>, places: Vec<usize>, left: usize) -> Read {Read {dropped: if transport.is_none() {Some((Cause::NoCandidates, left))} else {Some((Cause::Candidate, left)).filter(|(_, left)| *left > 0)}, transport, places}}
	let kind = need("type", members.string("type", STRING_MAX))?;
	Ok(match kind {
		"udp" | "udp-obfs" => {
			let found = endpoints()?;
			let places = (0..found.len()).collect();
			made(Some(if kind == "udp" {Transport::Udp(found)} else {Transport::UdpObfs(found)}), places, 0)
		}
		"tls" => {
			let (found, places, left) = stream(Pins::Required)?;
			made(found.map(Transport::Tls), places, left)
		}
		"ws" => {
			let (found, places, left) = stream(Pins::Allowed)?;
			made(found.map(Transport::Ws), places, left)
		}
		"fronted" => {
			let (found, places, left) = stream(Pins::Forbidden)?;
			made(found.map(Transport::Fronted), places, left)
		}
		// "A transport that has a shape has the type `fronted-shaped`", and the shape is read as the page says: a member it does not have, or a value it refuses, refuses the transport.
		"fronted-shaped" => {
			let shape = Shape::from_json(members.get("shape").ok_or("shape")?).map_err(|_| "shape")?;
			let (found, places, left) = stream(Pins::Forbidden)?;
			made(found.map(|stream| Transport::FrontedShaped(stream, shape)), places, left)
		}
		// A `ws-plain` transport is refused, and left out, for an `appearance` (no value is defined in version 1), for a key or a `cookie` that does not read, for a path that does not read and for a list with no candidate that reads. The cookie is 1 to 32 characters of `A-Z a-z 0-9 _ -`.
		"ws-plain" => {
			let (key, cookie) = (members.string("transport_public_key", 44).ok().flatten().and_then(public), members.string("cookie", 32).ok().flatten().filter(|cookie| !cookie.is_empty() && cookie.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')));
			let (Some(key), Some(cookie), None, Ok((Some(stream), places, left))) = (key, cookie, members.get("appearance"), stream(Pins::Plain)) else {return Ok(Read {transport: None, places: Vec::new(), dropped: Some((Cause::WsPlain, 1))})};
			made(Some(Transport::WsPlain {key, cookie: cookie.to_owned(), stream}), places, left)
		}
		// A `faketls` transport is refused, and left out, for a member it must not have, for a `transport_public_key` that is missing or does not read, and for a `candidates` that is not a list of 1 to 16. Its key is a public key of X25519 like the profile's, so one of small order is refused too.
		"faketls" => {
			let (key, list) = (members.string("transport_public_key", 44).ok().flatten().and_then(public), members.list("candidates", 1..=CANDIDATES_MAX).ok().flatten());
			let (Some(key), Some(list), false) = (key, list, BORROWED_NOT.iter().any(|name| members.get(name).is_some())) else {return Ok(Read {transport: None, places: Vec::new(), dropped: Some((Cause::Faketls, 1))})};
			// A candidate has `address`, read as every other candidate's, and `sni`, a host name that is required and is never empty, a wildcard or an address.
			let (candidates, places): (Vec<Borrowed>, Vec<usize>) = list.iter().enumerate().filter_map(|(at, item)| {
				let members = Members::of(item).filter(|members| !BORROWED_NOT.iter().any(|name| members.get(name).is_some()))?;
				Some((Borrowed {address: Dial::parse(members.string("address", STRING_MAX).ok()??)?, sni: members.string("sni", 253).ok()?.filter(|sni| is_host(sni))?.to_owned()}, at))
			}).unzip();
			let left = list.len() - places.len();
			made((!candidates.is_empty()).then_some(Transport::FakeTls {key, candidates}), places, left)
		}
		_ => Read {transport: None, places: Vec::new(), dropped: Some((Cause::Unknown, 1))},
	})
}

fn device(members: Members) -> Named<DeviceKeys> {
	let (public_key, private_key) = (need("public_key", key32(members, "public_key", public))?, key32(members, "private_key", key)?.map(Secret::new));
	// "Its public half must equal `public_key`, or the profile is refused." Both halves are public once the document is read, so the comparison need not be in constant time.
	if private_key.as_ref().is_some_and(|private| proof::public_key(private.expose()) != public_key) {return Err("private_key")}
	let transport_secrets = need("transport_secrets", members.list("transport_secrets", 1..=2))?.iter().map(|item| if let Json::Str(text) = item {key(text)} else {None}.map(Secret::new).ok_or("transport_secrets")).collect::<Named<_>>()?;
	Ok(DeviceKeys {public_key, private_key, preshared_key: key32(members, "preshared_key", key)?.map(Secret::new), addresses: addresses(members, "addresses")?, transport_secrets})
}

fn profile(members: Members) -> Result<Profile, Fault> {
	// The two unknown values that mean "not supported" are looked for first, so that a profile of a later version is called that and not malformed.
	if need("type", members.string("type", STRING_MAX))? != "veilway" {return Err(Fault::Unsupported)}
	let read: Vec<_> = need("transports", members.list("transports", 1..=TRANSPORTS_MAX))?.iter().map(transport).collect();
	let read = read.into_iter().collect::<Result<Vec<_>, _>>()?;
	// "A transport of a type this version does not know is left out." A profile of nothing but those is one of a later version.
	if read.iter().all(|read| matches!(read.dropped, Some((Cause::Unknown, _)))) {return Err(Fault::Unsupported)}
	let (mut kept, mut dropped) = (Vec::new(), Vec::new());
	for (at, read) in read.into_iter().enumerate() {
		if let Some((cause, count)) = read.dropped {dropped.push(Dropped {transport: at, count, cause})}
		if let Some(found) = read.transport {kept.push((found, Place {transport: at, candidates: read.places}))}
	}
	let id = need("id", members.string("id", 64))?;
	if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-') || id.starts_with(['_', '-']) {return Err(Fault::Member("id"))}
	let device = device(need("device", members.object("device"))?)?;
	let gateways = addresses(members, "gateways")?;
	// "One per family of `device.addresses`, in the same order." A gateway that is the device's own address is no gateway.
	if gateways.len() != device.addresses.len() || gateways.iter().zip(&device.addresses).any(|(gateway, address)| gateway.is_ipv4() != address.is_ipv4() || gateway == address) {return Err(Fault::Member("gateways"))}
	let transport_public_key = key32(members, "transport_public_key", public)?;
	// "A `faketls` key equal to the profile's `transport_public_key` or to another `faketls` transport's key refuses that `faketls` transport only." Of two with one key neither is kept: nothing says which of them has it right.
	// A `ws-plain` key is held to the same two rules: it is a key of its own.
	let borrowed: Vec<[u8; 32]> = kept.iter().filter_map(|(transport, _)| if let Transport::FakeTls {key, ..} | Transport::WsPlain {key, ..} = transport {Some(*key)} else {None}).collect();
	kept.retain(|(transport, place)| {
		let (Transport::FakeTls {key, ..} | Transport::WsPlain {key, ..}) = transport else {return true};
		let cause = if transport_public_key == Some(*key) {Cause::KeyOfProfile} else if borrowed.iter().filter(|other| *other == key).count() > 1 {Cause::KeyTwice} else {return true};
		// What was recorded of its candidates is moot once the transport itself is gone.
		dropped.retain(|drop| drop.transport != place.transport);
		dropped.push(Dropped {transport: place.transport, count: 1, cause});
		false
	});
	dropped.sort_by_key(|drop| drop.transport);
	let (transports, places): (Vec<Transport>, Vec<Place>) = kept.into_iter().unzip();
	// "A profile whose transports are all left out is refused."
	if transports.is_empty() {return Err(Fault::Member("transports"))}
	if transport_public_key.is_none() && transports.iter().any(|transport| matches!(transport, Transport::Tls(_) | Transport::Ws(_) | Transport::Fronted(_) | Transport::FrontedShaped(..))) {return Err(Fault::Member("transport_public_key"))}
	let padding = match members.object("padding")? {
		None => Padding {wide_max: WIDE_DEFAULT, normal_max: NORMAL_DEFAULT, keepalive: KEEPALIVE},
		Some(padding) => {
			let keepalive = match padding.list("keepalive", 2..=2)? {
				None => KEEPALIVE,
				Some([Json::Uint(low), Json::Uint(high)]) if (10..=60).contains(low) && (10..=60).contains(high) && *high >= *low + KEEPALIVE_WIDTH => *low as u32 * 1_000..=*high as u32 * 1_000,
				Some(_) => return Err(Fault::Member("keepalive")),
			};
			Padding {wide_max: padding.uint("wide_max", u64::from(*WIDE_BOUNDS.start())..=u64::from(*WIDE_BOUNDS.end()))?.map_or(WIDE_DEFAULT, |value| value as u32), normal_max: padding.uint("normal_max", u64::from(*NORMAL_BOUNDS.start())..=u64::from(*NORMAL_BOUNDS.end()))?.map_or(NORMAL_DEFAULT, |value| value as u32), keepalive}
		}
	};
	let rating_cap = members.string("rating_cap", STRING_MAX)?.map(|word| RatingCap::read(word).ok_or("rating_cap")).transpose()?;
	// An exit that does not read is left out, and so is one whose tag an earlier exit of the list has.
	let mut tags = HashSet::new();
	let exits = members.list("exits", 0..=EXITS_MAX)?.unwrap_or_default().iter().filter_map(|item| Members::of(item).and_then(exit).filter(|exit| tags.insert(exit.tag.clone()))).collect();
	// A list of another type or of more than 4 is a member of the profile out of its range. A notice in it that does not read is left out, as one at the top level is.
	let notices = members.list("notices", 0..=NOTICES_MAX)?.unwrap_or_default().iter().filter_map(|item| Members::of(item).and_then(notice)).collect();
	Ok(Profile {id: id.to_owned(), name: need("name", text(members, "name", true, NAME, 4 * NAME))?, inbound_public_key: need("inbound_public_key", key32(members, "inbound_public_key", public))?, device, gateways, mtu: need("mtu", members.uint("mtu", u64::from(MTU_MIN)..=MTU_MAX))? as u16, transport_public_key, transports, places, dropped, stream_first: members.boolean("stream_first")?.unwrap_or(false), parallel: members.uint("parallel", 1..=4)?.unwrap_or(1) as u8, padding, min_control_version: members.uint("min_control_version", 1..=255)?.unwrap_or(1) as u8, rating_cap, exits, notices})
}

/// "A `ws-plain` transport may not use a host or a path that any `tls`, `ws` or `fronted` candidate of the subscription uses": the transport is refused, in whichever profile it is, and the covered ones stay. A profile left with no transport is refused.
fn apart(profiles: Vec<(usize, Profile)>, refused: &mut Vec<RefusedProfile>) -> Vec<(usize, Profile)> {
	let covered: Vec<(String, Vec<String>)> = profiles.iter().flat_map(|(_, profile)| &profile.transports).filter_map(|transport| if let Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _) = transport {Some((stream.path.clone(), stream.candidates.iter().flat_map(|used| [Some(used.host.clone()), used.sni.clone()]).flatten().collect()))} else {None}).collect();
	profiles.into_iter().filter_map(|(position, mut profile)| {
		let gone: Vec<usize> = profile.transports.iter().enumerate().filter(|(_, transport)| matches!(transport, Transport::WsPlain {stream, ..} if covered.iter().any(|(path, names)| *path == stream.path || names.iter().any(|name| stream.candidates.iter().any(|plain| name.eq_ignore_ascii_case(&plain.host)))))).map(|(at, _)| at).collect();
		for at in gone.into_iter().rev() {
			profile.transports.remove(at);
			let place = profile.places.remove(at);
			profile.dropped.retain(|drop| drop.transport != place.transport);
			profile.dropped.push(Dropped {transport: place.transport, count: 1, cause: Cause::Separation});
		}
		profile.dropped.sort_by_key(|drop| drop.transport);
		if profile.transports.is_empty() {refused.push(RefusedProfile {position, id: Some(profile.id.clone()), fault: Fault::Member("transports")}); None} else {Some((position, profile))}
	}).collect()
}

/// Reads the payload of a verified document: steps 4 to 6 of "What is checked, in order", without the checks that need the clock or the stored document, which are `client`'s.
/// `v` and `critical` are read first, so a document of a later version is called that whatever else it holds, then `refusal`: "In a signed refusal only `v`, `subscription_id`, `issued_at` and `refusal` are required, and the other members are not read."
pub fn parse(verified: &Verified) -> Result<Payload, PayloadError> {
	let root = json::parse(verified.payload()).map_err(PayloadError::Json)?;
	let members = Members::of(&root).ok_or(PayloadError::Object)?;
	if need("v", members.uint("v", 1..=INTEGER_MAX))? != VERSION {return Err(PayloadError::Version)}
	let critical = members.list("critical", 0..=usize::MAX)?.unwrap_or_default();
	if !critical.iter().all(|name| matches!(name, Json::Str(_))) {return Err(PayloadError::Member("critical"))}
	if !critical.is_empty() {return Err(PayloadError::Critical)}
	let id = Id::read(need("subscription_id", members.string("subscription_id", 64))?).ok_or("subscription_id")?;
	let issued_at = need("issued_at", members.uint("issued_at", 0..=INTEGER_MAX))?;
	if let Some(word) = members.string("refusal", STRING_MAX)? {return Ok(Payload::Refusal(Refusal {subscription_id: id, issued_at, reason: Reason::read(word).ok_or(PayloadError::Refusal)?}))}
	let (serial, expires_at) = (need("serial", members.uint("serial", 1..=INTEGER_MAX))?, need("expires_at", members.uint("expires_at", 0..=INTEGER_MAX))?);
	if expires_at <= issued_at || expires_at - issued_at > LIFETIME_MAX {return Err(PayloadError::Member("expires_at"))}
	let signing_keys = need("signing_keys", members.list("signing_keys", 1..=2))?.iter().map(|item| if let Json::Str(text) = item {key(text).and_then(SigningKey::new)} else {None}.ok_or("signing_keys")).collect::<Named<Vec<_>>>()?;
	if signing_keys.len() == 2 && signing_keys[0] == signing_keys[1] {return Err(PayloadError::Member("signing_keys"))}
	if !signing_keys.contains(&verified.signer()) {return Err(PayloadError::Signer)}
	let provider = need("name", text(need("provider", members.object("provider"))?, "name", true, NAME, 4 * NAME))?;
	let update_interval = members.uint("update_interval", UPDATE_INTERVAL)?.map_or(UPDATE_DEFAULT, |seconds| seconds as u32);
	// A refresh URL is fetched, so it is held to the limit of a subscription URL, 256 characters, and not to the 512 of a URL that is only opened.
	let refresh_urls = members.list("refresh_urls", 0..=REFRESH_URLS_MAX)?.unwrap_or_default().iter().map(|item| Refresh::read(item).ok_or("refresh_urls")).collect::<Named<Vec<_>>>()?;
	// "A document cannot move an entry from one kind to the other": entries with one host and port are of one kind. The link's endpoint is held to the same rule by `client`.
	if refresh_urls.iter().enumerate().any(|(place, entry)| refresh_urls[..place].iter().any(|earlier| earlier.url.authority() == entry.url.authority() && earlier.kind() != entry.kind())) {return Err(PayloadError::Member("refresh_urls"))}
	// A base URL is held to the rules of a URL the token is sent to, although the token never goes there: no query, no fragment, no IP literal and no pins. One host has one role, so it is not an entry of `refresh_urls` too.
	let static_mirrors = members.list("static_mirrors", 0..=mirror::MIRRORS_MAX)?.unwrap_or_default().iter().map(|item| if let Json::Str(text) = item {Url::parse(text, mirror::BASE_MAX, false, false).filter(|_| text.ends_with('/'))} else {None}.ok_or("static_mirrors")).collect::<Named<Vec<_>>>()?;
	if static_mirrors.iter().enumerate().any(|(place, base)| static_mirrors[..place].contains(base) || refresh_urls.iter().any(|entry| entry.authority() == base.authority())) {return Err(PayloadError::Member("static_mirrors"))}
	let main_endpoint = main_endpoint(members)?;
	// "One host, one role": the endpoint of a move is not the host of a static mirror, and may be the host and port of an entry of `refresh_urls` only of the same kind.
	if main_endpoint.as_ref().is_some_and(|main| static_mirrors.iter().any(|base| base.authority() == main.url.authority()) || refresh_urls.iter().any(|entry| entry.authority() == main.url.authority() && entry.kind() != main.kind())) {return Err(PayloadError::Member("main_endpoint"))}
	let endpoint_pins = members.list("endpoint_pins", 1..=2)?.map(|pins| pin_list(pins).ok_or("endpoint_pins")).transpose()?.unwrap_or_default();
	let (mut profiles, mut refused) = (Vec::new(), Vec::new());
	for (position, item) in need("profiles", members.list("profiles", 1..=PROFILES_MAX))?.iter().enumerate() {
		match Members::of(item).ok_or(Fault::Member("profiles")).and_then(profile) {
			Ok(profile) => profiles.push((position, profile)),
			Err(fault) => refused.push(RefusedProfile {position, id: Members::of(item).and_then(|members| members.string("id", 64).ok().flatten()).filter(|id| is_tag(id)).map(str::to_owned), fault}),
		}
	}
	let profiles = apart(profiles, &mut refused);
	let twice: HashSet<String> = profiles.iter().enumerate().filter(|(index, (_, profile))| profiles[..*index].iter().any(|(_, earlier)| earlier.id == profile.id)).map(|(_, (_, profile))| profile.id.clone()).collect();
	refused.extend(profiles.iter().filter(|(_, profile)| twice.contains(&profile.id)).map(|(position, profile)| RefusedProfile {position: *position, id: Some(profile.id.clone()), fault: Fault::Duplicate}));
	refused.sort_by_key(|profile| profile.position);
	let profiles: Vec<Profile> = profiles.into_iter().map(|(_, profile)| profile).filter(|profile| !twice.contains(&profile.id)).collect();
	if profiles.is_empty() {return Err(PayloadError::Profiles)}
	let mut left_out = 0;
	let mut devices = kept(members, "devices", DEVICES_MAX, &mut left_out, listed)?;
	// Which device is this one is what the user checks the list by. When a list says it of more than one, each of those is a faulty entry and is left out like any other: nothing says which of them it is true of.
	let this = devices.iter().filter(|device| device.this).count();
	if this > 1 {
		devices.retain(|device| !device.this);
		left_out += this;
	}
	let support = kept(members, "support", SUPPORT_MAX, &mut left_out, |members| Some(SupportLink {label: text(members, "label", false, LABEL, 4 * LABEL).ok()??, url: url(members)?}))?;
	let (cards, notices) = (kept(members, "cards", CARDS_MAX, &mut left_out, card)?, kept(members, "notices", NOTICES_MAX, &mut left_out, notice)?);
	let (usage, logo) = (members.get("usage").map(usage), members.get("logo").map(logo));
	// Like `usage`, a faulty `agreement` is left out, never a reason to refuse the document.
	let agreement = members.get("agreement").map(|value| Members::of(value).and_then(|members| {let link = |name| match members.string(name, URL_MAX) {Ok(None) => Ok(None), Ok(Some(text)) => Url::parse(text, URL_MAX, true, true).map(Some).ok_or(()), Err(_) => Err(())}; let (terms, privacy) = (link("terms").ok()?, link("privacy").ok()?); (terms.is_some() || privacy.is_some()).then_some(Agreement {terms, privacy})}));
	left_out += usize::from(usage == Some(None)) + usize::from(logo == Some(None)) + usize::from(agreement == Some(None));
	let agreement = agreement.flatten();
	let (usage, logo) = (usage.flatten(), logo.flatten());
	let accent = members.string("accent", 7)?.map(|text| text.strip_prefix('#').filter(|digits| digits.len() == 6 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())).and_then(|digits| u32::from_str_radix(digits, 16).ok()).map(|colour| [(colour >> 16) as u8, (colour >> 8) as u8, colour as u8]).ok_or("accent")).transpose()?;
	Ok(Payload::Subscription(Box::new(Subscription {id, serial, issued_at, expires_at, signing_keys, provider, update_interval, refresh_urls, gateway_keys: gateway_keys(members, "gateway_keys", false)?, main_endpoint, static_mirrors, endpoint_pins, profiles, refused, devices, usage, support, agreement, cards, logo, accent, notices, left_out})))
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::{json, Value};

	// Keys of the tests are the public halves of private keys that are one byte repeated: obviously made up, and none of them all zeros.
	fn key(fill: u8) -> String {STANDARD.encode(proof::public_key(&[fill; 32]))}
	fn pin() -> String {STANDARD.encode([0x33; 32])}
	fn borrowed(address: &str, sni: &str) -> Value {json!({"address": address, "sni": sni})}
	fn faketls(fill: u8, candidates: Vec<Value>) -> Value {json!({"type": "faketls", "transport_public_key": key(fill), "candidates": candidates})}
	fn two() -> Vec<Value> {vec![borrowed("192.0.2.10:443", "www.example.com"), borrowed("[2001:db8::10]:443", "www.example.org")]}
	fn obfs() -> Value {json!({"type": "udp-obfs", "endpoints": ["192.0.2.30:51821"]})}
	// A profile with these transports and, with `node`, the profile's own `transport_public_key` of that fill.
	fn profile_of(transports: Vec<Value>, node: Option<u8>) -> Value {
		let mut profile = json!({"type": "veilway", "id": "home", "name": "Home", "inbound_public_key": key(0x12), "device": {"public_key": key(0x21), "transport_secrets": [STANDARD.encode([0x5a; 32])], "addresses": ["10.7.0.2"]}, "gateways": ["10.7.0.1"], "mtu": 1390, "transports": transports});
		if let Some(fill) = node {profile["transport_public_key"] = json!(key(fill))}
		profile
	}
	fn read(profile: &Value) -> Result<Profile, Fault> {
		let parsed = json::parse(profile.to_string().as_bytes()).unwrap();
		super::profile(Members::of(&parsed).unwrap())
	}
	// A profile as `apart` leaves it when it is the only one of the document.
	fn apart_one(profile: &Value) -> Profile {super::apart(vec![(0, read(profile).unwrap())], &mut Vec::new()).remove(0).1}
	// What a profile of one transport and a `udp-obfs` keeps of the first: `None` when it was left out.
	fn kept(transport: Value) -> Option<Transport> {
		let read = read(&profile_of(vec![transport, obfs()], Some(0x31))).unwrap();
		(read.transports.len() == 2).then(|| read.transports[0].clone())
	}
	fn snis(transport: &Option<Transport>) -> Vec<String> {if let Some(Transport::FakeTls {candidates, ..}) = transport {candidates.iter().map(|candidate| candidate.sni.clone()).collect()} else {Vec::new()}}

	#[test]
	fn a_faketls_transport_has_its_own_key_and_its_candidates_in_order() {
		// A profile whose only transport is `faketls` needs no profile-level key.
		let read = read(&profile_of(vec![faketls(0x41, two())], None)).unwrap();
		let Transport::FakeTls {key, candidates} = &read.transports[0] else {panic!("{:?}", read.transports)};
		assert_eq!((*key, read.transport_public_key), (proof::public_key(&[0x41; 32]), None));
		assert_eq!(candidates.iter().map(|candidate| (candidate.address.address().to_string(), candidate.sni.as_str())).collect::<Vec<_>>(), [("192.0.2.10:443".to_owned(), "www.example.com"), ("[2001:db8::10]:443".to_owned(), "www.example.org")]);
		// What it prints holds no address, name or key.
		assert_eq!(format!("{:?}", read.transports[0]), "FakeTls(2 candidates)");
		assert_eq!(format!("{:?}", candidates[0]), "Borrowed(Dial(IPv4))");
		// Unknown members are ignored, as in every version 1 object.
		let mut transport = faketls(0x41, vec![json!({"address": "192.0.2.10:443", "sni": "www.example.com", "weight": 3})]);
		transport["note"] = json!("x");
		assert_eq!(snis(&kept(transport)), ["www.example.com"]);
	}

	#[test]
	fn a_member_a_borrowed_site_does_not_take_refuses_the_candidate_or_the_transport_it_is_on() {
		for name in BORROWED_NOT {
			// On a candidate it drops that candidate alone.
			let mut candidates = two();
			candidates[0][name] = json!(false);
			assert_eq!(snis(&kept(faketls(0x41, candidates))), ["www.example.org"], "{name}");
			// On the transport it refuses the transport, and the profile keeps the rest.
			let mut transport = faketls(0x41, two());
			transport[name] = json!("/x");
			assert_eq!(kept(transport), None, "{name}");
		}
	}

	#[test]
	fn the_sni_of_a_candidate_is_a_host_name_and_never_empty_or_an_address() {
		let too_long = format!("{}.example.com", ["a"; 125].join("."));
		assert!(too_long.len() > 253);
		for sni in [json!(""), json!("WWW.Example.com"), json!("*.example.com"), json!("192.0.2.7"), json!("[2001:db8::1]"), json!("a..example.com"), json!("-a.example.com"), json!("www.example.com."), json!(too_long), json!(7), Value::Null] {
			assert_eq!(snis(&kept(faketls(0x41, vec![json!({"address": "192.0.2.10:443", "sni": sni.clone()}), borrowed("192.0.2.11:443", "www.example.org")]))), ["www.example.org"], "{sni}");
		}
		assert_eq!(snis(&kept(faketls(0x41, vec![json!({"address": "192.0.2.10:443"}), borrowed("192.0.2.11:443", "www.example.org")]))), ["www.example.org"]);
		// A transport whose candidates are all refused is left out.
		assert_eq!(kept(faketls(0x41, vec![borrowed("192.0.2.10:443", "")])), None);
	}

	#[test]
	fn a_faketls_transport_without_a_key_that_reads_is_left_out() {
		let mut missing = faketls(0x41, two());
		missing.as_object_mut().unwrap().remove("transport_public_key");
		assert_eq!(kept(missing), None);
		for bad in [json!(""), json!(&key(0x41)[..43]), json!(STANDARD.encode([0; 32])), json!(STANDARD.encode([0x41; 31])), json!(key(0x41).replace('=', "A")), json!(7), json!([key(0x41)])] {
			let mut transport = faketls(0x41, two());
			transport["transport_public_key"] = bad.clone();
			assert_eq!(kept(transport), None, "{bad}");
		}
		// A key on a candidate is no key of the transport: it is an unknown member there, and the transport still has none.
		assert_eq!(kept(json!({"type": "faketls", "candidates": [{"address": "192.0.2.10:443", "sni": "www.example.com", "transport_public_key": key(0x41)}]})), None);
	}

	#[test]
	fn a_transport_of_an_unknown_type_is_left_out_and_only_a_profile_of_those_is_unsupported() {
		let later = json!({"type": "later", "endpoints": ["192.0.2.50:51821"]});
		let kept = read(&profile_of(vec![later.clone(), obfs()], Some(0x31))).unwrap();
		assert_eq!((kept.transports.len(), kept.dropped.iter().map(|drop| (drop.transport, drop.count, drop.cause)).collect::<Vec<_>>(), Cause::Unknown.word()), (1, vec![(0, 1, Cause::Unknown)], "unknown"));
		assert_eq!(read(&profile_of(vec![later.clone(), later], Some(0x31))).err(), Some(Fault::Unsupported));
		let mut bad = obfs();
		bad["endpoints"] = json!([]);
		assert_eq!(read(&profile_of(vec![json!({"type": "later"}), bad], Some(0x31))).err(), Some(Fault::Member("endpoints")));
	}

	#[test]
	fn the_profile_key_is_no_fallback_for_a_faketls_key() {
		let mut transport = faketls(0x41, two());
		transport.as_object_mut().unwrap().remove("transport_public_key");
		// Its only transport left out, the profile is refused, although it has a key of its own.
		assert_eq!(read(&profile_of(vec![transport], Some(0x31))).err(), Some(Fault::Member("transports")));
	}

	#[test]
	fn a_faketls_key_that_is_another_transports_refuses_that_faketls_transport() {
		let tls = json!({"type": "tls", "path": "/assets/app-1234.js", "candidates": [{"address": "192.0.2.20:443", "sni": "node.example.com", "host": "node.example.com", "pins": [pin()]}]});
		// The profile's own key.
		let read_same = read(&profile_of(vec![faketls(0x31, two()), tls.clone()], Some(0x31))).unwrap();
		assert!(matches!(&read_same.transports[..], [Transport::Tls(_)]), "{:?}", read_same.transports);
		// Two `faketls` transports with one key are both left out, and one with a key of its own is kept.
		let read_twice = read(&profile_of(vec![faketls(0x41, two()), faketls(0x41, two()), faketls(0x42, two()), tls], Some(0x31))).unwrap();
		assert!(matches!(&read_twice.transports[..], [Transport::FakeTls {key, ..}, Transport::Tls(_)] if *key == proof::public_key(&[0x42; 32])), "{:?}", read_twice.transports);
		// Several with keys of their own are allowed.
		assert_eq!(read(&profile_of(vec![faketls(0x41, two()), faketls(0x42, two())], None)).unwrap().transports.len(), 2);
	}

	#[test]
	fn a_faketls_candidate_dials_only_where_every_candidate_may() {
		for address in [json!("127.0.0.1:443"), json!("[::1]:443"), json!("169.254.1.1:443"), json!("[fe80::1]:443"), json!("192.0.2.10:0"), json!("192.0.2.10:0443"), json!("0.0.0.0:443"), json!("[::ffff:192.0.2.10]:443"), json!("www.example.com:443"), json!("192.0.2.10"), json!(443)] {
			assert_eq!(snis(&kept(faketls(0x41, vec![json!({"address": address.clone(), "sni": "www.example.com"}), borrowed("192.0.2.11:443", "www.example.org")]))), ["www.example.org"], "{address}");
		}
	}

	#[test]
	fn a_faketls_transport_has_1_to_16_candidates() {
		let one = borrowed("192.0.2.10:443", "www.example.com");
		assert_eq!(kept(faketls(0x41, Vec::new())), None);
		assert_eq!(snis(&kept(faketls(0x41, vec![one.clone(); 16]))).len(), 16);
		assert_eq!(kept(faketls(0x41, vec![one.clone(); 17])), None);
		let mut not_a_list = faketls(0x41, Vec::new());
		not_a_list["candidates"] = one;
		assert_eq!(kept(not_a_list), None);
	}

	#[test]
	fn a_malformed_candidate_of_any_stream_transport_drops_only_itself() {
		let good = json!({"address": "192.0.2.20:443", "sni": "node.example.com", "host": "node.example.com"});
		let pinned = json!({"address": "192.0.2.21:443", "sni": "node.example.com", "host": "node.example.com", "pins": [pin()]});
		let shape = json!({"up": {"method": "GET", "in": "query"}, "down": {"mode": "poll"}});
		let mut self_signed = good.clone();
		self_signed["self_signed"] = json!(true);
		let mut bad_sni = good.clone();
		bad_sni["sni"] = json!("Node.example.com");
		// For each type: a candidate it refuses, and one it takes.
		for (kind, bad, fine) in [("tls", &good, &pinned), ("ws", &self_signed, &pinned), ("fronted", &pinned, &good), ("fronted-shaped", &pinned, &good), ("fronted-shaped", &bad_sni, &good)] {
			let mut transport = json!({"type": kind, "path": "/assets/app-1234.js", "candidates": [bad, fine]});
			if kind == "fronted-shaped" {transport["shape"] = shape.clone()}
			let Some(Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _)) = kept(transport.clone()) else {panic!("{kind}")};
			assert_eq!(stream.candidates.iter().map(|candidate| candidate.address.address().to_string()).collect::<Vec<_>>(), [fine["address"].as_str().unwrap()], "{kind}");
			// A list whose candidates are all refused leaves the transport out, and a profile whose transports are all left out is refused.
			transport["candidates"] = json!([bad]);
			assert_eq!(kept(transport.clone()), None, "{kind}");
			assert_eq!(read(&profile_of(vec![transport], Some(0x31))).err(), Some(Fault::Member("transports")), "{kind}");
		}
	}

	#[test]
	fn what_was_left_out_does_not_shift_the_places_the_document_wrote() {
		let good = json!({"address": "192.0.2.20:443", "sni": "node.example.com", "host": "node.example.com"});
		let pinned = json!({"address": "192.0.2.21:443", "sni": "node.example.com", "host": "node.example.com", "pins": [pin()]});
		let three = vec![borrowed("192.0.2.10:443", ""), borrowed("192.0.2.11:443", "www.example.com"), borrowed("192.0.2.12:443", "www.example.org")];
		let tls = json!({"type": "tls", "path": "/assets/app-1234.js", "candidates": [good, pinned]});
		let read = read(&profile_of(vec![faketls(0x41, three), tls, faketls(0x31, two()), obfs()], Some(0x31))).unwrap();
		assert_eq!(read.transports.len(), 3);
		assert_eq!(read.places, [Place {transport: 0, candidates: vec![1, 2]}, Place {transport: 1, candidates: vec![1]}, Place {transport: 3, candidates: vec![0]}]);
		assert_eq!(read.dropped, [Dropped {transport: 0, count: 1, cause: Cause::Candidate}, Dropped {transport: 1, count: 1, cause: Cause::Candidate}, Dropped {transport: 2, count: 1, cause: Cause::KeyOfProfile}]);
		// A hint names the document's places: the ones that were left out name nothing, and the others name what the profile holds now.
		let found: Vec<_> = (0..4).flat_map(|transport| (0..3).map(move |candidate| (transport, candidate))).filter_map(|(transport, candidate)| read.find(transport, candidate).map(|at| ((transport, candidate), at))).collect();
		assert_eq!(found, [((0, 1), (0, 0)), ((0, 2), (0, 1)), ((1, 1), (1, 0)), ((3, 0), (2, 0))]);
		// And the other way, from what the profile holds to what the document wrote.
		assert_eq!([read.document_place(0, 0), read.document_place(0, 1), read.document_place(1, 0), read.document_place(2, 0), read.document_place(2, 1), read.document_place(3, 0)], [Some((0, 1)), Some((0, 2)), Some((1, 1)), Some((3, 0)), None, None]);
	}

	#[test]
	fn every_drop_has_a_cause_and_a_count() {
		let bad = borrowed("192.0.2.10:443", "");
		let mut with_member = faketls(0x42, two());
		with_member["path"] = json!("/x");
		let mut no_key = faketls(0x43, two());
		no_key.as_object_mut().unwrap().remove("transport_public_key");
		let read = read(&profile_of(vec![faketls(0x41, vec![bad.clone(), bad.clone()]), with_member, no_key, faketls(0x44, two()), faketls(0x44, two()), faketls(0x45, two()), obfs()], Some(0x31))).unwrap();
		assert_eq!(read.dropped, [Dropped {transport: 0, count: 2, cause: Cause::NoCandidates}, Dropped {transport: 1, count: 1, cause: Cause::Faketls}, Dropped {transport: 2, count: 1, cause: Cause::Faketls}, Dropped {transport: 3, count: 1, cause: Cause::KeyTwice}, Dropped {transport: 4, count: 1, cause: Cause::KeyTwice}]);
		assert_eq!(read.places.iter().map(|place| place.transport).collect::<Vec<_>>(), [5, 6]);
		assert_eq!(read.dropped.iter().map(|drop| drop.cause.word()).collect::<Vec<_>>(), ["no_candidates", "faketls", "faketls", "key_twice", "key_twice"]);
		// A transport that is left out for its key keeps no record of the candidates it lost before.
		let mut halved = two();
		halved[0] = borrowed("192.0.2.10:443", "");
		let read = self::read(&profile_of(vec![faketls(0x31, halved), obfs()], Some(0x31))).unwrap();
		assert_eq!(read.dropped, [Dropped {transport: 0, count: 1, cause: Cause::KeyOfProfile}]);
		// A profile that lost nothing says so.
		let whole = self::read(&profile_of(vec![faketls(0x41, two()), obfs()], Some(0x31))).unwrap();
		assert!(whole.dropped.is_empty() && whole.find(1, 0) == Some((1, 0)));
	}

	fn plain(fill: u8, path: &str, host: &str) -> Value {json!({"type": "ws-plain", "transport_public_key": key(fill), "cookie": "sid_1-A", "path": path, "candidates": [{"address": "192.0.2.40:80", "host": host}]})}
	fn covered(kind: &str, path: &str, host: &str) -> Value {json!({"type": kind, "path": path, "candidates": [{"address": "192.0.2.41:443", "sni": host, "host": host}]})}

	#[test]
	fn a_ws_plain_transport_reads_with_its_own_key_and_a_cookie() {
		let Some(Transport::WsPlain {key: node, cookie, stream}) = kept(plain(0x51, "/plain/upgrade-1", "plain.example.com")) else {panic!("not read")};
		assert_eq!((node, cookie.as_str(), stream.path.as_str(), stream.candidates.len()), (proof::public_key(&[0x51; 32]), "sid_1-A", "/plain/upgrade-1", 1));
		assert!(stream.candidates[0].sni.is_none() && stream.candidates[0].pins.is_empty() && stream.candidates[0].host == "plain.example.com");
		let read = read(&profile_of(vec![plain(0x51, "/plain/upgrade-1", "plain.example.com")], None)).unwrap();
		assert_eq!((read.transports.len(), read.transport_public_key), (1, None));
	}

	#[test]
	fn a_ws_plain_transport_that_does_not_read_is_left_out_alone() {
		let mut cases = Vec::new();
		let cookie = |value: Value| {let mut transport = plain(0x51, "/plain/upgrade-1", "plain.example.com"); transport["cookie"] = value; transport};
		cases.extend(["", "has space", "semi;colon", "quote\"d", "equals=x", "a".repeat(33).as_str(), "caf\u{e9}"].map(|bad| cookie(json!(bad))));
		cases.extend([cookie(json!(5)), cookie(Value::Null)]);
		let mut missing = plain(0x51, "/plain/upgrade-1", "plain.example.com");
		missing.as_object_mut().unwrap().remove("cookie");
		cases.push(missing);
		let mut no_key = plain(0x51, "/plain/upgrade-1", "plain.example.com");
		no_key.as_object_mut().unwrap().remove("transport_public_key");
		cases.push(no_key);
		let mut appearance = plain(0x51, "/plain/upgrade-1", "plain.example.com");
		appearance["appearance"] = json!("anything");
		cases.push(appearance);
		for member in ["sni", "verify_name", "ech", "pins", "self_signed", "http2"] {
			let mut with = plain(0x51, "/plain/upgrade-1", "plain.example.com");
			with["candidates"][0][member] = json!("x");
			cases.push(with);
		}
		let mut no_host = plain(0x51, "/plain/upgrade-1", "plain.example.com");
		no_host["candidates"][0].as_object_mut().unwrap().remove("host");
		cases.push(no_host);
		cases.push(plain(0x51, "/short", "plain.example.com"));
		cases.push(plain(0x51, "/plain/upgrade-1", "Plain.example.com"));
		for (at, case) in cases.into_iter().enumerate() {
			let read = read(&profile_of(vec![case, obfs()], Some(0x31))).unwrap();
			assert_eq!((read.transports.len(), read.dropped.iter().map(|drop| drop.cause).collect::<Vec<_>>()), (1, vec![Cause::WsPlain]), "case {at}");
		}
	}

	#[test]
	fn a_ws_plain_key_is_a_key_of_its_own() {
		let read = read(&profile_of(vec![plain(0x31, "/plain/upgrade-1", "plain.example.com"), plain(0x52, "/plain/upgrade-2", "plain.example.org"), plain(0x53, "/plain/upgrade-3", "plain.example.net"), plain(0x53, "/plain/upgrade-4", "plain.example.dev"), faketls(0x52, two()), obfs()], Some(0x31))).unwrap();
		assert_eq!(read.dropped.iter().map(|drop| (drop.transport, drop.cause)).collect::<Vec<_>>(), [(0, Cause::KeyOfProfile), (1, Cause::KeyTwice), (2, Cause::KeyTwice), (3, Cause::KeyTwice), (4, Cause::KeyTwice)]);
	}

	#[test]
	fn a_ws_plain_host_or_path_that_a_covered_transport_uses_refuses_the_ws_plain_transport() {
		for (kind, plain_path, plain_host, covered_path, covered_host) in [("tls", "/a/shared-path", "plain.example.com", "/a/shared-path", "front.example.com"), ("ws", "/plain/upgrade-1", "front.example.com", "/covered/path-1", "front.example.com"), ("fronted", "/plain/upgrade-1", "front.example.com", "/covered/path-1", "front.example.com")] {
			let mut covered = covered(kind, covered_path, covered_host);
			if kind == "tls" {covered["candidates"][0]["pins"] = json!([pin()])}
			let plain = plain(0x51, plain_path, plain_host);
			let read = apart_one(&profile_of(vec![covered, plain, obfs()], Some(0x31)));
			assert_eq!((read.transports.len(), read.dropped.iter().map(|drop| (drop.transport, drop.cause)).collect::<Vec<_>>()), (2, vec![(1, Cause::Separation)]), "{kind} {plain_host}");
		}
		let fine = apart_one(&profile_of(vec![covered("ws", "/covered/path-1", "front.example.com"), plain(0x51, "/plain/upgrade-1", "plain.example.com"), obfs()], Some(0x31)));
		assert!(fine.dropped.is_empty() && fine.transports.len() == 3);
	}

	#[test]
	fn a_ws_plain_host_or_path_that_another_profile_uses_refuses_the_ws_plain_transport_and_a_profile_left_empty() {
		let (mut other, mut only) = (profile_of(vec![covered("ws", "/covered/path-1", "front.example.com"), obfs()], Some(0x31)), profile_of(vec![plain(0x51, "/plain/upgrade-1", "front.example.com")], None));
		other["id"] = json!("other");
		let mut refused = Vec::new();
		let kept = apart(vec![(0, read(&other).unwrap()), (1, read(&only).unwrap())], &mut refused);
		assert_eq!((kept.len(), kept[0].1.transports.len(), refused.len(), refused[0].position), (1, 2, 1, 1));
		only["transports"].as_array_mut().unwrap().push(obfs());
		let kept = apart(vec![(0, read(&other).unwrap()), (1, read(&only).unwrap())], &mut refused);
		assert_eq!((kept.len(), kept[1].1.transports.len(), kept[1].1.dropped.iter().map(|drop| drop.cause).collect::<Vec<_>>()), (2, 1, vec![Cause::Separation]));
		let by_path = apart(vec![(0, read(&other).unwrap()), (1, read(&profile_of(vec![plain(0x51, "/covered/path-1", "plain.example.com"), obfs()], None)).unwrap())], &mut refused);
		assert_eq!(by_path[1].1.transports.len(), 1);
	}
}
