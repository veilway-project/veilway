//! The payload of a subscription document (subscription format page, "Contents", and steps 4 to 6 of "What is checked, in order" as far as they need no clock and no stored state): strict JSON read into typed values.
//!
//! `parse` takes an `envelope::Verified` and nothing else, so what it reads was signed by a key that was held. That makes the input a provider's and not a stranger's. It does not make it friendly: every count, length and range is checked, nothing is clamped, and three kinds of unknown value are never guessed at ("Unknown members").
//!
//! What refuses what ("Wrong type, out of range, missing"): a fault in a top-level member refuses the document, a fault inside a profile refuses that profile, and a faulty card, notice, support link, listed device, exit or logo is left out. Display text is the stated exception: it is filtered and cut, never refused, except where it must not be empty. A text may come in several languages ("Text in several languages"), and a translation that does not read is dropped by itself: only `default` can make a text wrong.
use super::{envelope::{SigningKey, Verified}, hash, is_host, json::{self, Json, Members, Named}, key, public, visible, Secret, Tag, Text, Url, LINK_URL_MAX, STRING_MAX, TRANSLATIONS_MAX, URL_MAX};
use crate::{chunk::{NORMAL_BOUNDS, NORMAL_DEFAULT, WIDE_BOUNDS, WIDE_DEFAULT}, control::{self, display, is_tag, Period, Severity, EXITS_MAX, MTU_MIN, NOTICES_MAX, NOTICE_MAX, USAGE_CLAMP}, proof, request::PATH_MIN, session::KEEPALIVE};
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

/// An entry of `refresh_urls`: "a URL string, for an endpoint whose certificate is validated by its chain, or an object with exactly `url` and `pins`" for a pinned one. It derefs to its `Url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refresh {url: Url, pins: Vec<[u8; 32]>}

impl Refresh {
	pub fn url(&self) -> &Url {&self.url}
	/// The 1 or 2 pins a pinned entry is trusted by, none twice. Empty for an entry whose certificate is validated by its chain.
	pub fn pins(&self) -> &[[u8; 32]] {&self.pins}
	pub fn pinned(&self) -> bool {!self.pins.is_empty()}
	/// What a user confirms, as `host:port`, and for a pinned entry `host:port#pinned`: "a host and port together, with whether it is pinned".
	pub fn key(&self) -> String {if self.pinned() {format!("{}#pinned", self.url.authority())} else {self.url.authority()}}
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
	pub cards: Vec<Card>,
	pub logo: Option<Logo>,
	/// `accent` as red, green and blue. Adjusting it for contrast is the app's.
	pub accent: Option<[u8; 3]>,
	pub notices: Vec<Notice>,
	/// How many cards, notices, support links and listed devices were left out because they did not read, with one more for a usage and for a logo that was. Exits that were left out are not counted.
	pub left_out: usize,
}

impl Subscription {
	/// The text of this subscription for a notice the node of `profile` sent ("Languages" on the control channel page): the notice whose `default` is byte for byte the text the node sent, looked for "first in the `notices` of the profile it is connected through and then in the subscription's own `notices`". The app then shows `Text::pick` of it, and `None` means it shows `sent.shown_text()`.
	/// The severity is not given: it "is always the one the node sent". The number is the place in `notices` of this subscription when the match is one of its own, which is then the same notice on the screen, "not two".
	pub fn notice_text<'a>(&'a self, profile: &'a Profile, sent: &control::Notice) -> Option<(&'a Text, Option<usize>)> {profile.notices.iter().find(|notice| notice.text.is(&sent.text)).map(|notice| (&notice.text, None)).or_else(|| self.notices.iter().position(|notice| notice.text.is(&sent.text)).map(|place| (&self.notices[place].text, Some(place))))}
	/// `Provider` when any profile carries a private key.
	pub fn origin(&self) -> KeyOrigin {if self.profiles.iter().any(|profile| profile.device.private_key.is_some()) {KeyOrigin::Provider} else {KeyOrigin::Device}}
	/// The addresses of every `udp` and `udp-obfs` endpoint of every profile. "A cover transport whose address is also the address of a `udp` or `udp-obfs` endpoint is capped at Detectable": the core, which computes ratings, compares each candidate's address with this set.
	/// Only the profiles' addresses, which is not the set a cap is computed from: the pinned endpoints of the link and of `refresh_urls` that are IP literals count too, and only the client knows the link. A cap uses `Held::datagram_addresses` or `Review::datagram_addresses`.
	pub fn profile_datagram_addresses(&self) -> HashSet<IpAddr> {self.profiles.iter().flat_map(|profile| &profile.transports).flat_map(|transport| if let Transport::Udp(endpoints) | Transport::UdpObfs(endpoints) = transport {&endpoints[..]} else {&[]}).map(|dial| dial.address().ip()).collect()}
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
	/// Present whenever a `tls`, `ws` or `fronted` transport is listed.
	pub transport_public_key: Option<[u8; 32]>,
	/// In the provider's order. A hint of the control channel names one by its position here.
	pub transports: Vec<Transport>,
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

impl Profile {
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
}

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
}

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
		}
	}
}

impl fmt::Debug for Stream {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Stream({} candidates)", self.candidates.len())}
}

impl fmt::Debug for Candidate {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Candidate({} pins{})", self.pins.len(), if self.self_signed {", self-signed"} else {""})}
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

fn severity(members: Members) -> Option<Severity> {
	match members.string("severity", STRING_MAX) {
		Ok(Some("info")) => Some(Severity::Information),
		Ok(Some("warning")) => Some(Severity::Warning),
		_ => None,
	}
}

// "`severity` (`"info"` or `"warning"`) and `text` (display text, cut to 280 bytes)."
fn notice(members: Members) -> Option<Notice> {Some(Notice {severity: severity(members)?, text: text(members, "text", false, usize::MAX, NOTICE_MAX).ok()??})}

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
enum Pins {Required, Allowed, Forbidden}

fn host<'a>(members: Members<'a>, name: &'static str) -> Named<Option<&'a str>> {members.string(name, 253)?.map(|host| Some(host).filter(|host| is_host(host)).ok_or(name)).transpose()}

fn candidate(value: &Json, rule: Pins) -> Named<Candidate> {
	let members = Members::of(value).ok_or("candidates")?;
	let address = Dial::parse(need("address", members.string("address", STRING_MAX))?).ok_or("address")?;
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
	let ech = members.string("ech", 1_368)?.map(|text| STANDARD.decode(text).ok().filter(|ech| (1..=1_024).contains(&ech.len())).ok_or("ech")).transpose()?;
	let pins = members.list("pins", 1..=PINS_MAX)?.map(|pins| pins.iter().map(|pin| if let Json::Str(text) = pin {hash(text)} else {None}.ok_or("pins")).collect::<Named<Vec<_>>>()).transpose()?;
	if (rule == Pins::Required && pins.is_none()) || (rule == Pins::Forbidden && pins.is_some()) {return Err("pins")}
	Ok(Candidate {address, sni: sni.map(str::to_owned), host: need("host", host(members, "host"))?.to_owned(), verify_name: verify_name.map(str::to_owned), ech, pins: pins.unwrap_or_default(), self_signed})
}

pub(crate) fn transport(value: &Json) -> Result<Transport, Fault> {
	let members = Members::of(value).ok_or("transports")?;
	let endpoints = || need("endpoints", members.list("endpoints", 1..=CANDIDATES_MAX))?.iter().map(|item| if let Json::Str(text) = item {Dial::parse(text)} else {None}.ok_or("endpoints")).collect::<Named<Vec<_>>>();
	let stream = |rule: Pins| -> Named<Stream> {
		// "`path` follows the path rule of the config reference and is at least 12 characters": it starts with `/`, is at most 256 bytes from `A-Z a-z 0-9 . _ ~ / -` and has no `..` component.
		let path = need("path", members.string("path", 256))?;
		if path.len() < PATH_MIN || !path.starts_with('/') || !path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._~/-".contains(&byte)) || path.split('/').any(|part| part == "..") {return Err("path")}
		Ok(Stream {path: path.to_owned(), candidates: need("candidates", members.list("candidates", 1..=CANDIDATES_MAX))?.iter().map(|item| candidate(item, rule)).collect::<Named<_>>()?})
	};
	Ok(match need("type", members.string("type", STRING_MAX))? {
		"udp" => Transport::Udp(endpoints()?),
		"udp-obfs" => Transport::UdpObfs(endpoints()?),
		"tls" => Transport::Tls(stream(Pins::Required)?),
		"ws" => Transport::Ws(stream(Pins::Allowed)?),
		"fronted" => Transport::Fronted(stream(Pins::Forbidden)?),
		_ => return Err(Fault::Unsupported),
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
	if read.contains(&Err(Fault::Unsupported)) {return Err(Fault::Unsupported)}
	let transports = read.into_iter().collect::<Result<Vec<_>, _>>()?;
	let id = need("id", members.string("id", 64))?;
	if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-') || id.starts_with(['_', '-']) {return Err(Fault::Member("id"))}
	let device = device(need("device", members.object("device"))?)?;
	let gateways = addresses(members, "gateways")?;
	// "One per family of `device.addresses`, in the same order." A gateway that is the device's own address is no gateway.
	if gateways.len() != device.addresses.len() || gateways.iter().zip(&device.addresses).any(|(gateway, address)| gateway.is_ipv4() != address.is_ipv4() || gateway == address) {return Err(Fault::Member("gateways"))}
	let transport_public_key = key32(members, "transport_public_key", public)?;
	if transport_public_key.is_none() && transports.iter().any(|transport| matches!(transport, Transport::Tls(_) | Transport::Ws(_) | Transport::Fronted(_))) {return Err(Fault::Member("transport_public_key"))}
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
	Ok(Profile {id: id.to_owned(), name: need("name", text(members, "name", true, NAME, 4 * NAME))?, inbound_public_key: need("inbound_public_key", key32(members, "inbound_public_key", public))?, device, gateways, mtu: need("mtu", members.uint("mtu", u64::from(MTU_MIN)..=MTU_MAX))? as u16, transport_public_key, transports, stream_first: members.boolean("stream_first")?.unwrap_or(false), parallel: members.uint("parallel", 1..=4)?.unwrap_or(1) as u8, padding, min_control_version: members.uint("min_control_version", 1..=255)?.unwrap_or(1) as u8, rating_cap, exits, notices})
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
	let refresh_urls = members.list("refresh_urls", 0..=REFRESH_URLS_MAX)?.unwrap_or_default().iter().map(|item| if let Json::Str(text) = item {Url::parse(text, LINK_URL_MAX, true, false).map(|url| Refresh {url, pins: Vec::new()})} else {Members::of(item).filter(|entry| entry.0.len() == 2).and_then(|entry| Some(Refresh {url: Url::pinned(entry.string("url", LINK_URL_MAX).ok()??, LINK_URL_MAX, true, false)?, pins: pin_list(entry.list("pins", 1..=2).ok()??)?}))}.ok_or("refresh_urls")).collect::<Named<Vec<_>>>()?;
	// "A document cannot move an entry from one kind to the other": entries with one host and port are of one kind. The link's endpoint is held to the same rule by `client`.
	if refresh_urls.iter().enumerate().any(|(place, entry)| refresh_urls[..place].iter().any(|earlier| earlier.url.authority() == entry.url.authority() && earlier.pinned() != entry.pinned())) {return Err(PayloadError::Member("refresh_urls"))}
	let endpoint_pins = members.list("endpoint_pins", 1..=2)?.map(|pins| pin_list(pins).ok_or("endpoint_pins")).transpose()?.unwrap_or_default();
	let (mut profiles, mut refused) = (Vec::new(), Vec::new());
	for (position, item) in need("profiles", members.list("profiles", 1..=PROFILES_MAX))?.iter().enumerate() {
		match Members::of(item).ok_or(Fault::Member("profiles")).and_then(profile) {
			Ok(profile) => profiles.push((position, profile)),
			Err(fault) => refused.push(RefusedProfile {position, id: Members::of(item).and_then(|members| members.string("id", 64).ok().flatten()).filter(|id| is_tag(id)).map(str::to_owned), fault}),
		}
	}
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
	left_out += usize::from(usage == Some(None)) + usize::from(logo == Some(None));
	let (usage, logo) = (usage.flatten(), logo.flatten());
	let accent = members.string("accent", 7)?.map(|text| text.strip_prefix('#').filter(|digits| digits.len() == 6 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())).and_then(|digits| u32::from_str_radix(digits, 16).ok()).map(|colour| [(colour >> 16) as u8, (colour >> 8) as u8, colour as u8]).ok_or("accent")).transpose()?;
	Ok(Payload::Subscription(Box::new(Subscription {id, serial, issued_at, expires_at, signing_keys, provider, update_interval, refresh_urls, endpoint_pins, profiles, refused, devices, usage, support, cards, logo, accent, notices, left_out})))
}
