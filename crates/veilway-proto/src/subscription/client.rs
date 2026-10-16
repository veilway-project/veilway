//! What a client holds for a subscription and what it decides (subscription format page, "Identity", "Keys held for a subscription", "Rollback and expiry", "Offline, and when a refresh fails", "Device keys" and "Import"), as values and steps with no clock, no storage and no socket of their own.
//!
//! The caller owns the wall clock, the network and the storage. The types here carry what they can of the rules:
//!
//! - **Nothing before the first yes.** A link becomes an `Offer`, which shows what the link alone says and can do nothing else. The only way on is `proceed`, which is the user's yes: it takes the offer, and only then is a device key made and a `fetch::Request` possible. No function of this crate makes a `Request` from bytes, and none gives a client one for a link it has not said yes to.
//! - **Nothing kept before the second yes.** An answer that passed every check is a `Review`: the screen of step 3. `accept` checks the rule of a fresh import once more against what is stored at that moment, and gives the `Held` to store and the `confirm` request. `decline` gives the `release` request and nothing to keep.
//! - **A `Held` changes only through `refresh`**, which takes the body of an answer and the clock, and leaves the `Held` exactly as it was whenever it fails: "A document that fails any check changes nothing."
//! - **A legacy link stays one.** Its steps are other types, they never see a key or make a request body, and an answer that is a signed document imports nothing.
//! - **Nothing here prints a document.** A `Held`, a `Review` and everything read from a document print an id, a serial, a fingerprint and counts.
//!
//! What stays the caller's: asking the user, choosing how a request travels ("When a fetch happens"), sending a request to nothing but `Held::endpoints`, never following a redirect, and keeping a `Stored` where the platform keeps secrets.
//!
//! **What is stored is trusted as the link is.** A `Stored` holds the keys a subscription is verified under, so whoever can write the client's storage chooses the keys, the document and where the token goes. `Held::restore` checks that a stored value holds together. It cannot check that it is the one that was stored.
use super::{envelope::{self, EnvelopeError, Fingerprint, SigningKey}, exchange::GatewayKey, fetch::{DeviceName, Op, Request}, legacy::{self, Headers, LegacyError, List}, link::{Carried, Legacy, Link, Native}, mirror::{self, OpenError}, payload::{self, Fault, Id, KeyOrigin, MainEndpoint, Payload, PayloadError, Reason, Refresh, Refusal, Subscription}, DeviceSecret, Kind, Secret, Url, BODY_MAX, CARRIED_MAX, LINK_URL_MAX};
use crate::{keys::MirrorKeys, proof, uniform, NoRandom, Random};
use std::{collections::HashSet, fmt, net::IpAddr, time::Duration};

/// "Clock tolerance for `issued_at`: 300 s into the future."
pub const CLOCK_TOLERANCE: u64 = 300;
/// "Age of a signed refusal: at most 86,400 s."
pub const REFUSAL_AGE: u64 = 86_400;
/// "Grace after expiry: 30 days."
pub const GRACE: u64 = 30 * 86_400;
/// "Refresh by the user's request: at most 1 in 60 s, held by the client."
pub const USER_REFRESH: Duration = Duration::from_secs(60);
/// "Refresh after a failure: the interval, doubled per failure up to 86,400 s."
pub const BACKOFF_MAX: u64 = 86_400;
/// "Fetch timeouts: 10 s to connect, 30 s in all."
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// The most private addresses a subscription remembers a yes for.
pub const PRIVATE_MAX: usize = 16;

/// Why an answer was not taken. Every one of them leaves what is held as it was, and none of them can be accepted by the user: "There is no button that accepts it."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
	/// Steps 1 to 3. `EnvelopeError::UnknownKey` is the case with its own message: "The answer was not signed by this provider's key."
	Envelope(EnvelopeError),
	/// Steps 4 to 6, as far as the document alone decides them.
	Payload(PayloadError),
	/// A signed refusal that is this subscription's and recent. It "is never stored as the last good document and changes no profile".
	Refused(Reason),
	/// A signed refusal that is older than `REFUSAL_AGE` or from further ahead than the clock tolerance: "treated as a failed refresh, so that an old refusal cannot be replayed for long".
	StaleRefusal,
	/// A document or a refusal with another `subscription_id` than the stored one.
	OtherSubscription,
	/// "A lower one is refused."
	Rollback,
	/// "An equal serial is accepted only when the body is byte for byte the same." The same payload under another held key, or with another signature, is another body.
	Fork,
	/// A refresh with a higher serial whose `issued_at` is below the stored document's. A fresh import is judged by `issued_at` alone, so a document that went back in time would let an older one in through an import.
	Backdated,
	/// `issued_at` is "more than the clock tolerance ahead of the device's clock".
	Future,
	/// "A freshly fetched document that is already expired is refused."
	Expired,
	/// "A document without `private_key` that names another public key than the client's", or on a refresh "a `device.public_key` that differs from the stored one": for a profile the client had, and with provider-issued keys for any profile, whose key must be one the stored document had.
	DeviceKey,
	/// On a refresh, "a `private_key` where there was none".
	PrivateKey,
	/// A fresh import of a link for a stored subscription whose document was not issued later than the stored one.
	NotNewer,
	/// A whole document for a stored subscription that has a link. It has no endpoint, so taking it would leave the stored subscription unable to refresh and its device place with nobody to free it. The user removes the stored subscription first.
	HasLink,
	/// An entry of `refresh_urls` with the host and port of the link's endpoint that is of the other kind: "a document cannot move an entry from one kind to the other". The link alone decides whether its endpoint is pinned.
	EndpointKind,
	/// An import accepted on a screen that said the endpoint is checked the way the stored one is (or another way), when what is stored moved while the screen was up and that is no longer true. Nothing is stored; the import is shown again.
	Changed,
	/// A static mirror with the host and port of the link's endpoint: "One host has one role." The rest of the rule, against `refresh_urls`, is the document's own.
	MirrorHost,
	/// A static mirror's file that did not open ("How the client opens a file", steps 1 to 3). A failure of that mirror and never a revocation.
	Mirror(OpenError),
	/// `endpoint_pins` in a document whose link's endpoint is not pinned, or a list of pins, of the endpoint or of a pinned refresh entry the user has confirmed, that holds none of the pins the client holds for it: "a pin set cannot jump to keys the client has no tie to".
	Pins,
	/// A document that has an endpoint (one fetched from an endpoint, a relay mirror or a static mirror) and no `gateway_keys`: every request is sealed to one of them.
	Gateway,
	/// A document fetched from the endpoint of a confirmed move that does not pass the move: its `main_endpoint` does not name that endpoint with its URL and kind, its `endpoint_pins` leave out the move's pins, or its `gateway_keys` leave out the move's keys. A failure of that endpoint, and the main endpoint is tried after it.
	Move,
}

impl fmt::Display for Failure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "subscription: {self:?}")}
}

impl std::error::Error for Failure {}

/// The WireGuard key and the device secret a client makes for one subscription, "together". A client gets a new one only out of `NativeOffer::proceed`.
#[derive(Clone, PartialEq, Eq)]
pub struct Device {private: Secret<32>, public: [u8; 32], secret: DeviceSecret}

// The public key names the device to a provider and to whoever reads its panel.
impl fmt::Debug for Device {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Device(..)")}
}

impl Device {
	/// A device out of the storage: the private key and the secret that were kept "where a reinstall can find them again".
	pub fn restore(private: Secret<32>, secret: DeviceSecret) -> Self {Self {public: proof::public_key(private.expose()), private, secret}}
	/// `device_pub`.
	pub fn public(&self) -> &[u8; 32] {&self.public}
	pub fn private(&self) -> &Secret<32> {&self.private}
	pub fn secret(&self) -> &DeviceSecret {&self.secret}
}

/// Step 1 of an import: what a link is, before anything was sent, generated or stored. "A deep link, a QR code or a file can bring the user to this screen and can do nothing else."
#[derive(Debug)]
pub enum Offer {
	Native(NativeOffer),
	Carried(CarriedOffer),
	Legacy(LegacyOffer),
}

impl Offer {
	pub fn open(link: Link) -> Self {
		match link {
			Link::Native(link) => Self::Native(NativeOffer(link)),
			Link::Carried(link) => Self::Carried(CarriedOffer(link)),
			Link::Legacy(link) => Self::Legacy(LegacyOffer(link)),
		}
	}
}

/// A native link on the first screen.
#[derive(Debug)]
pub struct NativeOffer(Native);

impl NativeOffer {
	/// The endpoint, whose host the screen shows "with its registrable domain marked".
	pub fn endpoint(&self) -> &Url {self.0.endpoint()}
	/// The pin the link names, for the first screen: "this server uses its own certificate, which this link names", and for a host that is an address, "this server has an address and no name".
	pub fn pin(&self) -> Option<&[u8; 32]> {self.0.pin()}
	/// How the link reaches its endpoint. For a plain link the first screen adds: "this link does not use TLS. Your request stays sealed, but the network can tell that you use this app, now and later in its records."
	pub fn kind(&self) -> Kind {self.0.kind()}
	pub fn fingerprint(&self) -> Fingerprint {self.0.key().fingerprint()}
	/// The user continues. "What will be sent if the user continues: the link's token and a new key for this device, to that host."
	/// `device` is `None` for a new device, whose key and secret are drawn here and not before. It is the stored device when the user imports a link again for a subscription the app holds, so that the import takes no new place. The page does not say how a client knows that before the fetch, when the id is in the document: the caller decides, by the key and the endpoint of the link and by asking the user.
	pub fn proceed(self, device: Option<Device>, random: &mut Random) -> Result<Fetching, NoRandom> {
		let device = match device {
			Some(device) => device,
			None => {
				let (mut private, mut secret) = ([0; 32], [0; 16]);
				random(&mut private)?;
				random(&mut secret)?;
				Device::restore(Secret::new(private), Secret::new(secret))
			}
		};
		Ok(Fetching {keys: vec![self.0.key()], pins: self.0.pin().copied().into_iter().collect(), gateway: vec![self.0.gateway()], endpoint: self.0.endpoint().clone(), link: self.0, device})
	}
}

/// Step 2 of a native import: the one request with `op` `"fetch"` is out, or about to be. The keys an answer is verified under are the key of the link, or the keys a stored subscription held when its document could not be read again (`Damaged::Unread`). The request is sealed to the link's gateway key, which "cannot come from a server".
#[derive(Debug)]
pub struct Fetching {link: Native, device: Device, keys: Vec<SigningKey>, pins: Vec<[u8; 32]>, gateway: Vec<GatewayKey>, endpoint: Url}

impl Fetching {
	pub fn endpoint(&self) -> &Url {&self.endpoint}
	/// The gateway keys a request is sealed to: the link's, or on a recovery the link's again, since the document that listed others could not be read. The first is the active key, and "when an HTTP answer arrived and it was not a sealed answer that opens, it tries the second key once" (`next_key`).
	pub fn gateway(&self) -> &[GatewayKey] {&self.gateway}
	/// The pins the endpoint is checked by, for the TLS layer: the link's pin on an import, the pins held on a recovery from `Damaged::Unread`. Empty for an endpoint whose certificate is validated by its chain.
	pub fn pins(&self) -> &[[u8; 32]] {&self.pins}
	fn ask(&self, op: Op) -> Request {Request::new(self.link.token().clone(), self.keys.iter().map(SigningKey::kid).collect(), self.device.public, self.device.secret.clone(), op)}
	/// "One request with `op` `"fetch"`", naming the keys held: on a first import, "the id of the key in the link".
	pub fn request(&self) -> Request {self.ask(Op::Fetch)}
	/// The envelope an answer held once it was opened (`exchange::Sealed::open`). "A native link expects a signed document under the link's key, and anything else is a failure": it "is never read as a legacy list".
	/// `stored` is every subscription the app holds, so that the review can say whether this one replaces one of them. A failure leaves this step as it was, to try again or to `abandon`.
	pub fn answer(&self, body: &[u8], now: u64, stored: &[&Held]) -> Result<Review, Failure> {review(Some((self.link.clone(), self.device.clone())), Some(&self.endpoint), &self.pins, &self.keys, body, BODY_MAX, now, stored)}
	/// The import is given up after the request went out and before an answer could be reviewed: the `release` request, which frees the pending place if one was taken.
	pub fn abandon(self) -> Request {self.ask(Op::Release)}
}

/// A whole document on the first screen: "a document in a link" or "a file".
#[derive(Debug)]
pub struct CarriedOffer(Carried);

impl CarriedOffer {
	pub fn fingerprint(&self) -> Fingerprint {self.0.key().fingerprint()}
	pub fn in_file(&self) -> bool {self.0.in_file()}
	/// The user continues. "A whole document needs no fetch": it is verified under the key it came with, by the same rules. "It carries a provider-issued device key, since there is nothing to enrol with", so a profile without a private key refuses it.
	pub fn proceed(self, now: u64, stored: &[&Held]) -> Result<Review, Failure> {review(None, None, &[], &[self.0.key()], self.0.document(), if self.0.in_file() {BODY_MAX} else {CARRIED_MAX}, now, stored)}
}

/// A legacy link on the first screen, which says "this link cannot be verified" and "this link has no key part. If your provider gave you a Veilway link, part of it was lost on the way."
#[derive(Debug)]
pub struct LegacyOffer(Legacy);

impl LegacyOffer {
	pub fn url(&self) -> &Url {self.0.url()}
	/// The user continues. "A legacy link gets a `GET`", which "carries none of this": no token, no key, no body.
	pub fn proceed(self) -> LegacyFetching {LegacyFetching(self.0)}
}

/// A legacy fetch. It has no way to a native subscription whatever is answered.
#[derive(Debug)]
pub struct LegacyFetching(Legacy);

impl LegacyFetching {
	pub fn url(&self) -> &Url {self.0.url()}
	/// The body and the header fields of the answer. Everything read from them is unsigned.
	pub fn answer(&self, body: &[u8], fields: &[(&str, &[u8])]) -> Result<(List, Headers), LegacyError> {Ok((legacy::list(body)?, legacy::headers(fields)))}
}

fn recent(refusal: &Refusal, now: u64) -> Failure {if refusal.issued_at > now.saturating_add(CLOCK_TOLERANCE) || now.saturating_sub(refusal.issued_at) > REFUSAL_AGE {Failure::StaleRefusal} else {Failure::Refused(refusal.reason)}}

// What the clock decides about a document that was just fetched or opened.
fn timely(new: &Subscription, now: u64) -> Result<(), Failure> {if new.issued_at > now.saturating_add(CLOCK_TOLERANCE) {Err(Failure::Future)} else if new.expires_at <= now {Err(Failure::Expired)} else {Ok(())}}

// "Device keys": a profile without a private key names the client's own key, and with `old`, the stored document of a refresh, there is "no silent change" of a key and no private key where there was none.
fn keyed(new: &Subscription, device: Option<&Device>, old: Option<&Subscription>) -> Result<(), Failure> {
	for profile in &new.profiles {
		if profile.device.private_key.is_none() && device.is_none_or(|device| device.public != profile.device.public_key) {return Err(Failure::DeviceKey)}
		let Some(old) = old else {continue};
		// With provider-issued keys a profile under a new `id` could bring any key. So every key of a refresh is one the stored document had, under whatever `id`: "moving to another key takes a new import by the user".
		if old.origin() == KeyOrigin::Provider && !old.profiles.iter().any(|before| before.device.public_key == profile.device.public_key) {return Err(Failure::DeviceKey)}
		match old.profiles.iter().find(|before| before.id == profile.id) {
			Some(before) if before.device.public_key != profile.device.public_key => return Err(Failure::DeviceKey),
			Some(before) if before.device.private_key.is_none() && profile.device.private_key.is_some() => return Err(Failure::PrivateKey),
			// A profile with a new `id` is a new profile. It may not bring a private key into a subscription whose device made its own.
			None if profile.device.private_key.is_some() && old.origin() == KeyOrigin::Device => return Err(Failure::PrivateKey),
			_ => {}
		}
	}
	Ok(())
}

// The rule of "a fresh import by the user" against what is stored: whether the document replaces a stored subscription, which is one with the same id that holds the key the document verified under. It is asked when a review is made and again when it is accepted, since a refresh may have run between the two.
fn replaced<'a>(subscription: &Subscription, document: &str, key: &SigningKey, linked: bool, stored: &[&'a Held]) -> Result<Option<&'a Held>, Failure> {
	let Some(held) = stored.iter().find(|held| held.is(&subscription.id, key)) else {return Ok(None)};
	if !linked && held.origin.is_some() {return Err(Failure::HasLink)}
	// "The document is accepted when its `issued_at` is later than the stored document's, whatever its serial." The stored document itself is taken again, which is how a new token for the same document comes in.
	if subscription.issued_at <= held.subscription.issued_at && held.document != document {return Err(Failure::NotNewer)}
	Ok(Some(held))
}

// How `endpoint` is reached when `held` are the pins it is checked by: over plain HTTP, by those pins, or by its chain.
fn kind_of(endpoint: &Url, held: &[[u8; 32]]) -> Kind {if endpoint.is_plain() {Kind::Plain} else if held.is_empty() {Kind::Chain} else {Kind::Pinned}}

// Whether a `main_endpoint` names this endpoint: "URL and kind".
fn names(main: &MainEndpoint, endpoint: &Url, held: &[[u8; 32]]) -> bool {main.url.as_str() == endpoint.as_str() && main.kind() == kind_of(endpoint, held)}

// The pin rules of a document that has an endpoint, against the pins held for that endpoint, which is the main one or the one of a move: "the same rule as for the link, said per entry", so an entry with its host and port is of its kind, and "a document that has `endpoint_pins` when that endpoint is not pinned is refused", as is a list "that holds none of the pins the client holds".
fn endpoint_ok(subscription: &Subscription, endpoint: &Url, held: &[[u8; 32]]) -> Result<(), Failure> {
	let kind = kind_of(endpoint, held);
	if subscription.refresh_urls.iter().any(|entry| entry.authority() == endpoint.authority() && entry.kind() != kind) {return Err(Failure::EndpointKind)}
	// A pinned entry on the endpoint's host and port is confirmed with it, so it is trusted by the pins held for the endpoint and by none it names itself.
	if subscription.refresh_urls.iter().any(|entry| entry.pinned() && entry.authority() == endpoint.authority() && !entry.pins().iter().any(|pin| held.contains(pin))) {return Err(Failure::Pins)}
	if subscription.static_mirrors.iter().any(|base| base.authority() == endpoint.authority()) {return Err(Failure::MirrorHost)}
	if !subscription.endpoint_pins.is_empty() && (kind != Kind::Pinned || !subscription.endpoint_pins.iter().any(|pin| held.contains(pin))) {return Err(Failure::Pins)}
	Ok(())
}

// "A pinned or plain endpoint whose host is an IP literal, the main endpoint, a move's or a refresh entry's, counts as a `udp` endpoint at that address", on top of the `udp` and `udp-obfs` endpoints of the profiles. A whole document has no endpoints, whatever its `refresh_urls` say.
fn addresses(subscription: &Subscription, endpoint: Option<&Url>, moving: Option<&MainEndpoint>) -> HashSet<IpAddr> {
	let mut addresses = subscription.profile_datagram_addresses();
	if let Some(endpoint) = endpoint {addresses.extend(endpoint.literal().into_iter().chain(moving.and_then(|moving| moving.url.literal())).chain(subscription.refresh_urls.iter().filter_map(|entry| entry.literal())))}
	addresses
}

// The document of an import: verified under the keys held for it, which on a first import is the one key that came with the link, read, and judged by the clock, the device's key and the rule of a fresh import. `endpoint` is the one the request went to and `held` the pins it is checked by: the link's, or the ones stored for a recovery.
fn review(origin: Option<(Native, Device)>, endpoint: Option<&Url>, held: &[[u8; 32]], keys: &[SigningKey], document: &[u8], limit: usize, now: u64, stored: &[&Held]) -> Result<Review, Failure> {
	let verified = envelope::verify(document, keys, limit).map_err(Failure::Envelope)?;
	let subscription = match payload::parse(&verified).map_err(Failure::Payload)? {
		Payload::Refusal(refusal) => return Err(recent(&refusal, now)),
		Payload::Subscription(subscription) => *subscription,
	};
	timely(&subscription, now)?;
	keyed(&subscription, origin.as_ref().map(|(_, device)| device), None)?;
	if let Some(endpoint) = endpoint {
		if subscription.gateway_keys.is_empty() {return Err(Failure::Gateway)}
		endpoint_ok(&subscription, endpoint, held)?;
	}
	let document = String::from_utf8(document.to_vec()).map_err(|_| Failure::Envelope(EnvelopeError::Encoding))?;
	let replaces = replaced(&subscription, &document, &verified.signer(), origin.is_some(), stored)?;
	let rechecked = replaces.zip(origin.as_ref()).is_some_and(|(held, (link, _))| held.rechecked(link));
	// What the client holds for the endpoint is the document's list when it has one, and otherwise what it held.
	let pins = if origin.is_none() {Vec::new()} else if subscription.endpoint_pins.is_empty() {held.to_vec()} else {subscription.endpoint_pins.clone()};
	// "When the document asks for a move, the new host and how it is checked": naming the endpoint that was asked asks for nothing.
	let moving = endpoint.and_then(|endpoint| subscription.main_endpoint.clone().filter(|main| !names(main, endpoint, held)));
	Ok(Review {origin, endpoint: endpoint.cloned(), pins, key: verified.signer(), document, subscription, replaces: replaces.is_some(), rechecked, moving})
}

/// Step 3 of an import: a document that passed every check, for the user to confirm. Nothing of it is stored yet.
pub struct Review {origin: Option<(Native, Device)>, endpoint: Option<Url>, pins: Vec<[u8; 32]>, key: SigningKey, document: String, subscription: Subscription, replaces: bool, rechecked: bool, moving: Option<MainEndpoint>}

impl fmt::Debug for Review {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Review({:?}, {:?}, {} bytes)", self.subscription, self.key, self.document.len())}
}

/// Which stored subscription an accepted import replaces: the one with this id that holds this key. `Held::is` finds it. The caller puts the new `Held` in its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaced {pub id: Id, pub key: SigningKey}

/// What `Review::accept` gives.
#[derive(Debug)]
pub struct Accepted {
	/// The subscription to store.
	pub held: Held,
	/// The stored subscription this one replaces, "same key and same id", as it was found when the user accepted. `None` for a new subscription.
	pub replaces: Option<Replaced>,
	/// The `confirm` request, which makes the device's place permanent. `None` for a whole document, which has no endpoint.
	pub confirm: Option<Request>,
	/// Whether the replaced subscription's endpoint was checked another way, as it stood when the user accepted: see `Review::endpoint_changed`.
	pub endpoint_changed: bool,
}

/// An import the user accepted and the rules no longer allow, because what is stored changed while the confirmation was on the screen. Nothing is stored, and the pending place is given back.
#[derive(Debug)]
pub struct Declined {
	pub failure: Failure,
	/// The `release` request to send. `None` for a whole document.
	pub release: Option<Request>,
}

impl Review {
	/// The verified document: the provider's name "marked as the provider's own claim", the hosts in `refresh_urls`, the profiles, "the account's devices, as the document lists them".
	pub fn subscription(&self) -> &Subscription {&self.subscription}
	/// "The fingerprint again", of the key the document verified under.
	pub fn fingerprint(&self) -> Fingerprint {self.key.fingerprint()}
	/// "Whether this adds a new subscription or replaces a stored one", as it stood when the review was made. Which one is the one `Held::is` says yes to, for `subscription().id` and the key of `fingerprint`.
	pub fn replaces(&self) -> bool {self.replaces}
	/// "When the link replaces a stored link whose endpoint was checked another way (pinned or not, or by another pin), that it changes": the import replaces the pins held with the link's.
	pub fn endpoint_changed(&self) -> bool {self.rechecked}
	/// The pins to check the link's endpoint by once this is accepted: the document's list when it has one, otherwise the link's pin.
	pub fn pins(&self) -> &[[u8; 32]] {&self.pins}
	/// The addresses of the `udp` and `udp-obfs` endpoints of the profiles, and of the pinned or plain endpoints that are IP literals, which "count as a `udp` endpoint at that address" for the cap of a cover transport.
	pub fn datagram_addresses(&self) -> HashSet<IpAddr> {addresses(&self.subscription, self.endpoint.as_ref(), self.moving.as_ref())}
	/// The move the document asks for: "the new host and how it is checked". "Accepting the import accepts the move."
	pub fn moving(&self) -> Option<&MainEndpoint> {self.moving.as_ref()}
	/// The endpoint the request went to: the link's, unless the import recovers a subscription that had moved.
	pub fn endpoint(&self) -> Option<&Url> {self.endpoint.as_ref()}
	/// "Whether the device's key was made on this device or issued by the provider."
	pub fn origin(&self) -> KeyOrigin {self.subscription.origin()}
	/// Whether the subscription can refresh. A whole document cannot, "and the app says so".
	pub fn refreshes(&self) -> bool {self.origin.is_some()}
	fn release(origin: Option<(Native, Device)>, key: SigningKey) -> Option<Request> {origin.map(|(link, device)| Request::new(link.token().clone(), vec![key.kid()], device.public, device.secret, Op::Release))}
	/// The user accepts. `stored` is every subscription the app holds now: the rule of a fresh import is asked again, because the confirmation may have been on the screen while a refresh ran. "The client stores the subscription and sends `"confirm"`, with the name if one was typed." The hosts of `refresh_urls` and of `static_mirrors` were on the screen, so they are confirmed with it, each as its own kind, unless the subscription has no link to refresh by.
	pub fn accept(self, name: Option<DeviceName>, stored: &[&Held]) -> Result<Accepted, Box<Declined>> {
		let before = match replaced(&self.subscription, &self.document, &self.key, self.origin.is_some(), stored) {
			Ok(before) => before,
			Err(failure) => return Err(Box::new(Declined {failure, release: Self::release(self.origin, self.key)})),
		};
		let endpoint_changed = before.zip(self.origin.as_ref()).is_some_and(|(held, (link, _))| held.rechecked(link));
		// The screen said whether the endpoint is checked another way. If what is stored moved since, the user's yes was to something else, and the import must be shown again.
		if endpoint_changed != self.rechecked {return Err(Box::new(Declined {failure: Failure::Changed, release: Self::release(self.origin, self.key)}))}
		let replaces = before.map(|_| Replaced {id: self.subscription.id.clone(), key: self.key});
		let hosts = if self.origin.is_some() {self.subscription.host_keys().collect()} else {Vec::new()};
		let held = Held {origin: self.origin, endpoint: self.endpoint, moving: self.moving.map(|endpoint| Move {endpoint, confirmed: true, declined: false}), document: self.document, subscription: self.subscription, hosts, declined: Vec::new(), pins: self.pins, private: Vec::new()};
		Ok(Accepted {confirm: held.request(Op::Confirm(name)), held, replaces, endpoint_changed})
	}
	/// The user declines. "The client sends `"release"`, so that the device place is freed, and keeps nothing: not the document, not the link, not the key it made." `None` for a whole document, which took no place.
	pub fn decline(self) -> Option<Request> {Self::release(self.origin, self.key)}
}

/// A move of the main endpoint that a document asked for and the client holds pending ("Moving the main endpoint"): at most one. It is confirmed by the user's yes, or by an import that carried it, and it completes only at a document fetched from its endpoint. A no keeps the main endpoint and the move stays, where the user can still say yes for as long as documents name it.
#[derive(Clone, PartialEq, Eq)]
pub struct Move {endpoint: MainEndpoint, confirmed: bool, declined: bool}

impl Move {
	/// The endpoint, how it is checked and the gateway keys behind it, as the last document wrote them.
	pub fn endpoint(&self) -> &MainEndpoint {&self.endpoint}
	pub fn confirmed(&self) -> bool {self.confirmed}
	/// What the user is asked about is a move that is neither confirmed nor declined. The question shows the new host with its registrable domain marked, the old host, and how the new one is checked, with the plain words for `http`.
	pub fn declined(&self) -> bool {self.declined}
	/// What a user answers about: the URL and the kind, so that a document that named another move while the screen was up is not confirmed with it.
	pub fn key(&self) -> String {format!("{}#{}", self.endpoint.url.as_str(), match self.endpoint.kind() {Kind::Chain => "chain", Kind::Pinned => "pinned", Kind::Plain => "plain"})}
}

impl fmt::Debug for Move {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Move({:?}, {})", self.endpoint, if self.confirmed {"confirmed"} else if self.declined {"declined"} else {"waiting"})}
}

/// What a client holds for one subscription: the link it came by and the device made for it, unless it came as a whole document, the last good document as it was delivered, the main endpoint (the link's until a move completes) with the pins it is checked by, a move that waits, and the refresh hosts the user has confirmed, each with its port and its kind, and those the user said no to. The keys held, the id, the serial and the times are those of the last good document, so they cannot disagree with it.
#[derive(Clone, PartialEq)]
pub struct Held {origin: Option<(Native, Device)>, endpoint: Option<Url>, moving: Option<Move>, document: String, subscription: Subscription, hosts: Vec<String>, declined: Vec<String>, pins: Vec<[u8; 32]>, private: Vec<IpAddr>}

// The document holds transport secrets, and with a provider-issued key the device's private key. None of it is printed, and neither is the link.
impl fmt::Debug for Held {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Held({:?}, {:?}, {} bytes, {} confirmed hosts)", self.subscription, self.subscription.signing_keys, self.document.len(), self.hosts.len())}
}

/// What a refresh that was taken changed, for the notes the app keeps and shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Changes {
	/// The keys held are others than before: "the provider renewed its signing key". Noted with the date. "It does not ask the user anything."
	pub rotated: bool,
	/// The pins of the link's endpoint changed: "the provider renewed the certificate of its subscription server", noted with the date. The user is asked nothing.
	pub renewed: bool,
	/// Refresh hosts, as `host:port` and for a pinned entry `host:port#pinned`, and static mirrors as `host:port#static`, the user has not confirmed: "the provider added a refresh host". They are not in `Held::endpoints` until `Held::confirm_hosts`.
	pub hosts: Vec<String>,
	/// Profiles the client had that the new document leaves out, or holds in a form that was refused, by `id` and with the fault if there is one.
	pub dropped: Vec<(String, Option<Fault>)>,
	/// The list names a device that the list before it did not, by name and time of enrolment: "a device the user does not know is a sign that the link has leaked, and the app says so when the list grows". A list that is no longer has grown too when one device took the place of another.
	pub devices_grew: bool,
	/// A move completed: this document came from the endpoint of a confirmed move, which is now the main endpoint, with its kind, its pins and the gateway keys of this document. Noted with the date.
	pub moved: bool,
	/// The document names a move that waits for the user: "the provider is moving this subscription to <host>". Noted in the details, and asked at the next refresh the user starts.
	pub moving: bool,
}

/// Where a refresh that was taken came from, for the app to show and for nothing else: the link's endpoint, an entry of `refresh_urls` (a relay mirror), or a static mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
	Endpoint,
	Relay,
	Static,
	/// The endpoint of a confirmed move, which the answer completed.
	Moved,
}

impl Source {
	/// The code the apps look up, in the translations of their locale files.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Endpoint => "endpoint",
			Self::Relay => "relay",
			Self::Static => "static",
			Self::Moved => "moved",
		}
	}
}

/// What a place a request may go to is: the endpoint of a confirmed move, the main endpoint, or an entry of `refresh_urls` (a relay mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {Move, Main, Relay}

/// A place to send a sealed request: `Held::targets` gives these in the order of "Order and rate".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
	pub role: Role,
	pub url: &'a Url,
	/// The pins it is checked by: none for a certificate validated by its chain, and for a plain URL.
	pub pins: &'a [[u8; 32]],
	/// The gateway keys the request is sealed to, the active one first. The first is tried, and "when an HTTP answer arrived and it was not a sealed answer that opens" the second once (`exchange::next_key`).
	pub keys: &'a [GatewayKey],
}

/// One file of one static mirror to ask for: what `Held::static_targets` gives and `Held::refresh_static` takes back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticTarget {url: Url, base: Url, epoch: u64}

impl StaticTarget {
	/// The file URL: the base URL followed by the file name. The only thing a static fetch sends is a `GET` of it.
	pub fn url(&self) -> &Url {&self.url}
	/// The base URL the file's name and seal are bound to.
	pub fn base(&self) -> &Url {&self.base}
}

/// What a refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refreshed {
	/// The same document again, byte for byte: it "changes nothing".
	Unchanged,
	/// A newer document is the last good one now. "A new document takes effect for a profile at its next connect. A refresh never disconnects a tunnel that is up."
	Updated(Changes),
}

/// How old the last good document is ("Offline, and when a refresh fails").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
	Current,
	/// Past `expires_at`: "this subscription is out of date", shown "on the profile list and on the connect screen", and it keeps working.
	OutOfDate,
	/// More than 30 days past `expires_at`: "every connect needs one explicit confirmation".
	Stale,
}

/// Leave to connect with a profile of one subscription at one time, as far as the age of its document goes. It is not kept: the next connect asks again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit {id: Id, at: u64}

impl Permit {
	/// The subscription it was given for.
	pub fn id(&self) -> &Id {&self.id}
	/// The clock it was given at.
	pub fn at(&self) -> u64 {self.at}
}

/// The question a connect must put to the user first: the document is more than 30 days past its expiry, and "the addresses, keys and fronts in it may no longer belong to the provider".
#[derive(Debug)]
pub struct Stale(Permit);

impl Stale {
	/// The user's "one explicit confirmation", for this connect.
	pub fn confirmed(self) -> Permit {self.0}
}

/// What a `Held` is in storage. It holds the link with its token, the device's private key and the document with its secrets: it belongs in "the operating system's secret storage where the platform has one, and otherwise in a file encrypted under a key kept there". It is trusted as the link is: see the head of this module.
#[derive(Clone, PartialEq, Eq)]
pub struct Stored {
	/// The native link in its `veilway` form, and the device's private key and secret. `None` for a whole document.
	pub origin: Option<(String, Secret<32>, DeviceSecret)>,
	/// The keys held.
	pub keys: Vec<[u8; 32]>,
	/// The last good document.
	pub document: String,
	/// The confirmed hosts, each as `host:port`, `host:port#pinned` for a pinned refresh host, or `host:port#static` for a static mirror.
	pub hosts: Vec<String>,
	/// The hosts the user said no to, in the same forms, so that the app does not ask about them again while documents list them. Missing in an older vault, which is no answer. Read as untrusted: `Held::restore` keeps only hosts the document lists that are not confirmed as well.
	pub declined: Vec<String>,
	/// The pins the link's endpoint is checked by: empty for a link with no pin, otherwise 1 or 2.
	pub pins: Vec<[u8; 32]>,
	/// The private addresses the user said yes to for this subscription's endpoints. Missing in an older vault, which is no yes. Read as untrusted: `Held::restore` keeps only addresses `Held::allow_private` would.
	pub private: Vec<IpAddr>,
	/// The main endpoint when a move completed, as its URL: `None` while it is the link's. Its kind is the pins above and its scheme.
	pub endpoint: Option<String>,
	/// What the user answered about the move that waits. Its endpoint, pins and keys are the document's own `main_endpoint`, so only the answer is kept, with the `Move::key` it was given for.
	pub moving: Option<StoredMove>,
}

/// What the user answered about a move, in storage.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredMove {pub key: String, pub confirmed: bool, pub declined: bool}

impl fmt::Debug for Stored {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("Stored(..)")}
}

/// What was read from storage is not a subscription this reader holds. Either way the link, the token and the device's key are given back and not dropped: with them the user refreshes without taking a new device place.
pub enum Damaged {
	/// The document verifies under the stored keys and today's reader does not read it, which is what an update of the app that tightens a rule does to a stored subscription. The link, the device and the keys are kept: a fetch under those keys, reviewed and accepted like an import, puts the subscription back. `None` for a whole document, which has nothing to fetch with.
	Unread(Option<Box<Fetching>>),
	/// The stored value does not hold together: a key no client may hold, a link that is no native link, a document that does not verify. What was stored of the link and the device is given back as it was.
	Broken(Option<Box<(String, Secret<32>, DeviceSecret)>>),
}

impl fmt::Debug for Damaged {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str(if matches!(self, Self::Unread(_)) {"Damaged::Unread(..)"} else {"Damaged::Broken(..)"})}
}

impl fmt::Display for Damaged {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str("a stored subscription that does not read")}
}

impl std::error::Error for Damaged {}

impl Held {
	pub fn id(&self) -> &Id {&self.subscription.id}
	/// "After accepting a document the client holds exactly the keys in that list."
	pub fn keys(&self) -> &[SigningKey] {&self.subscription.signing_keys}
	/// Whether this is the subscription of that id under that key: "a subscription is identified by two things together".
	pub fn is(&self, id: &Id, key: &SigningKey) -> bool {self.subscription.id == *id && self.subscription.signing_keys.contains(key)}
	/// The last good document, read.
	pub fn subscription(&self) -> &Subscription {&self.subscription}
	/// The last good document, as it was delivered.
	pub fn document(&self) -> &str {&self.document}
	/// `None` for a subscription that came as a whole document.
	pub fn device(&self) -> Option<&Device> {self.origin.as_ref().map(|(_, device)| device)}
	/// The link this subscription was imported with, in the form providers hand out, or `None` for a whole document, which has no link. It holds the token: it goes only where the user sent it, as a share of the link and nothing else. The device's key and secret are not in it.
	pub fn link(&self) -> Option<String> {self.origin.as_ref().map(|(link, _)| link.veilway())}
	// A request of this subscription, which names the keys held.
	fn request(&self, op: Op) -> Option<Request> {self.origin.as_ref().map(|(link, device)| Request::new(link.token().clone(), self.keys().iter().map(SigningKey::kid).collect(), device.public, device.secret.clone(), op))}
	/// The request of a refresh, or `None` for a subscription that cannot refresh. When it goes out is the caller's, under "When a fetch happens".
	pub fn fetch(&self) -> Option<Request> {self.request(Op::Fetch)}
	/// A `confirm` with another name, which "replaces it".
	pub fn rename(&self, name: Option<DeviceName>) -> Option<Request> {self.request(Op::Confirm(name))}
	// The refresh URLs of the last good document with whether the user has confirmed the host and port of each. The main endpoint needs no confirmation. A subscription with no link has none: it cannot refresh, whatever its document lists.
	// A host is confirmed as host, port and its kind (`Refresh::key`), so that one listed pinned that was confirmed unpinned, or the reverse, waits again, and a change of its pins does not.
	fn listed(&self) -> impl Iterator<Item = (&Refresh, bool)> {self.endpoint.iter().flat_map(move |endpoint| self.subscription.refresh_urls.iter().map(move |entry| (entry, entry.authority() == endpoint.authority() || self.hosts.contains(&entry.key()))))}
	/// Where a request of this subscription may go, in the order to try: the endpoint of a confirmed move, the main endpoint, then the `refresh_urls` of the last good document whose host and port the user has confirmed. The token goes nowhere else. Empty for a subscription that came as a whole document.
	pub fn endpoints(&self) -> Vec<&Url> {self.targets().into_iter().map(|target| target.url).collect()}
	/// `endpoints` with what each is checked by and sealed to, which is what the TLS layer and the seal need: the pins held for the main endpoint, the pins of the entry for a refresh URL and the move's own for a move. Empty pins mean the certificate is validated by its chain, or that there is none for a plain URL; any pins mean it is not, and "there is no fallback to chain validation". A request to the main endpoint or to an entry is sealed to the `gateway_keys` of the last good document, and one to a move to the move's: "an entry of `refresh_urls` follows the panel that signed it".
	pub fn targets(&self) -> Vec<Target<'_>> {
		let Some(endpoint) = &self.endpoint else {return Vec::new()};
		let keys = &self.subscription.gateway_keys[..];
		self.moving.iter().filter(|moving| moving.confirmed).map(|moving| Target {role: Role::Move, url: &moving.endpoint.url, pins: &moving.endpoint.pins, keys: &moving.endpoint.gateway_keys}).chain(std::iter::once(Target {role: Role::Main, url: endpoint, pins: &self.pins, keys})).chain(self.listed().filter(|(_, confirmed)| *confirmed).map(|(entry, _)| Target {role: Role::Relay, url: entry.url(), pins: entry.pins(), keys})).collect()
	}
	/// The main endpoint: the link's until a move completes, and the endpoint of the last completed move after that. `None` for a subscription that came as a whole document.
	pub fn endpoint(&self) -> Option<&Url> {self.endpoint.as_ref()}
	/// How the main endpoint is reached, or `None` for a whole document.
	pub fn kind(&self) -> Option<Kind> {self.endpoint.as_ref().map(|endpoint| kind_of(endpoint, &self.pins))}
	/// The move that waits for the user's yes or no, or that is confirmed and has not completed.
	pub fn moving(&self) -> Option<&Move> {self.moving.as_ref()}
	/// The move the app asks about at the next refresh the user starts: one that is neither confirmed nor declined. "An automatic refresh asks nothing and goes to the main endpoint."
	pub fn asking(&self) -> Option<&Move> {self.moving.as_ref().filter(|moving| !moving.confirmed && !moving.declined)}
	/// The user answered the question about the move that `Move::key` named: yes, which `targets` then tries first. A move that a refresh replaced while the screen was up is not confirmed with it.
	pub fn confirm_move(&mut self, seen: &str) {if let Some(moving) = self.moving.as_mut().filter(|moving| moving.key() == seen) {(moving.confirmed, moving.declined) = (true, false)}}
	/// The user said no: the main endpoint stays, and the move stays in the details, where a yes can still be given. A confirmed move that is declined is not tried again.
	pub fn decline_move(&mut self, seen: &str) {if let Some(moving) = self.moving.as_mut().filter(|moving| moving.key() == seen) {(moving.confirmed, moving.declined) = (false, true)}}
	/// The addresses of the `udp` and `udp-obfs` endpoints of the profiles, and of the pinned or plain endpoints that are IP literals, the main endpoint's, a move's and the refresh entries', which "count as a `udp` endpoint at that address": a cover transport at one of them is capped at Detectable.
	pub fn datagram_addresses(&self) -> HashSet<IpAddr> {addresses(&self.subscription, self.endpoint.as_ref(), self.moving.as_ref().map(|moving| &moving.endpoint))}
	// Whether a link that replaces this one checks its endpoint another way: this one moved away from its own link's endpoint, it is reached another way, or it is pinned by a pin this does not hold. "Importing a link sets the main endpoint back to the link's."
	fn rechecked(&self, link: &Native) -> bool {self.origin.as_ref().is_some_and(|(own, _)| self.endpoint.as_ref() != Some(own.endpoint()) || self.kind() != Some(link.kind()) || link.pin().is_some_and(|pin| !self.pins.contains(pin)))}
	/// The refresh hosts of the last good document that wait for the user, each as `host:port`, `host:port#pinned` for a pinned entry, or `host:port#static` for a static mirror: the app "asks at the next refresh the user starts. Until then the client uses the hosts it already had."
	pub fn unconfirmed(&self) -> Vec<String> {
		let mut hosts = Vec::new();
		let waiting = self.listed().filter(|(_, confirmed)| !confirmed).map(|(entry, _)| entry.key()).chain(self.origin.iter().flat_map(|_| self.subscription.static_mirrors.iter().map(mirror::host_key)).filter(|host| !self.hosts.contains(host)));
		for host in waiting {if !hosts.contains(&host) {hosts.push(host)}}
		hosts
	}
	/// The user confirmed the hosts in `seen`, each as `unconfirmed` gave it: what the screen showed. Only hosts that wait are taken, so a host that a refresh added while the screen was up is not confirmed with it.
	pub fn confirm_hosts(&mut self, seen: &[&str]) {
		let confirmed: Vec<String> = self.unconfirmed().into_iter().filter(|host| seen.contains(&host.as_str())).collect();
		self.declined.retain(|host| !confirmed.contains(host));
		self.hosts.extend(confirmed);
	}
	/// The hosts of `unconfirmed` the user has not said no to: what the app asks about. A host the user declined is asked about again only once a document drops it and a later one lists it again.
	pub fn waiting(&self) -> Vec<String> {self.unconfirmed().into_iter().filter(|host| !self.declined.contains(host)).collect()}
	/// The refresh hosts and static mirrors the user has confirmed, in the forms of `unconfirmed`.
	pub fn confirmed(&self) -> &[String] {&self.hosts}
	/// The hosts the user said no to, in the forms of `unconfirmed`. They wait like any unconfirmed host, so `confirm_hosts` still takes them.
	pub fn declined(&self) -> &[String] {&self.declined}
	/// The user said no to the hosts in `seen`, each as `unconfirmed` or `confirmed` gave it: a waiting host is not asked about again, and a confirmed one loses its yes and is not contacted again. Only hosts the document lists are taken.
	pub fn decline_hosts(&mut self, seen: &[&str]) {
		let declined: Vec<String> = self.unconfirmed().into_iter().chain(self.hosts.iter().cloned()).filter(|host| seen.contains(&host.as_str()) && !self.declined.contains(host)).collect();
		self.hosts.retain(|host| !declined.contains(host));
		self.declined.extend(declined);
	}
	/// The envelope of the answer to a refresh, once it was opened (`exchange::Sealed::open`), at the wall clock `now`. It comes from the main endpoint, a relay mirror or a static mirror. Every check of "What is checked, in order" runs, against the keys held and the last good document. On any failure nothing here changes, and the caller shows why, "and tries again as the table of numbers says".
	pub fn refresh(&mut self, body: &[u8], now: u64) -> Result<Refreshed, Failure> {self.apply(body, now, false)}
	/// `refresh` for the envelope of an answer from the endpoint of a confirmed move. "A document fetched from the new endpoint is checked against the move, not against the main endpoint": its `main_endpoint` names that endpoint with its URL and kind, its `endpoint_pins`, when the endpoint is pinned, include a pin of the move's `pins`, and its top-level `gateway_keys` include a key of the move's. One that fails any of this is a failure of that endpoint (`Failure::Move`). One that is accepted completes the move before any later document is checked: the endpoint, its kind and its pins are the main endpoint's from then on, and so are this document's `gateway_keys`. The document that asked for the move cannot complete it, since a rule of a refresh asks for a higher serial: the new endpoint signs its own.
	pub fn refresh_moved(&mut self, body: &[u8], now: u64) -> Result<Refreshed, Failure> {self.apply(body, now, true)}
	fn apply(&mut self, body: &[u8], now: u64, moved: bool) -> Result<Refreshed, Failure> {
		let moving = if moved {Some(self.moving.as_ref().filter(|moving| moving.confirmed).ok_or(Failure::Move)?.endpoint.clone())} else {None};
		let verified = envelope::verify(body, self.keys(), BODY_MAX).map_err(Failure::Envelope)?;
		let new = match payload::parse(&verified).map_err(Failure::Payload)? {
			// "On a refresh it must carry the stored `subscription_id`, or it is a failed refresh."
			Payload::Refusal(refusal) => return Err(if refusal.subscription_id == self.subscription.id {recent(&refusal, now)} else {Failure::OtherSubscription}),
			Payload::Subscription(subscription) => *subscription,
		};
		if new.id != self.subscription.id {return Err(Failure::OtherSubscription)}
		timely(&new, now)?;
		if new.serial < self.subscription.serial {return Err(Failure::Rollback)}
		if new.serial == self.subscription.serial {return if moved {Err(Failure::Move)} else if body == self.document.as_bytes() {Ok(Refreshed::Unchanged)} else {Err(Failure::Fork)}}
		if new.issued_at < self.subscription.issued_at {return Err(Failure::Backdated)}
		keyed(&new, self.device(), Some(&self.subscription))?;
		let document = String::from_utf8(body.to_vec()).map_err(|_| Failure::Envelope(EnvelopeError::Encoding))?;
		let endpoint = self.endpoint.clone();
		if let Some(endpoint) = &endpoint {
			// "Required in every document that has an endpoint."
			if new.gateway_keys.is_empty() {return Err(Failure::Gateway)}
			// What the endpoint this document came from is checked by: the main endpoint's, or the move's.
			let (basis, held) = moving.as_ref().map_or((endpoint, &self.pins), |moving| (&moving.url, &moving.pins));
			if let Some(moving) = &moving {
				if !new.main_endpoint.as_ref().is_some_and(|main| names(main, &moving.url, &moving.pins)) || (moving.kind() == Kind::Pinned && !new.endpoint_pins.iter().any(|pin| moving.pins.contains(pin))) || !new.gateway_keys.iter().any(|key| moving.gateway_keys.contains(key)) {return Err(Failure::Move)}
			}
			endpoint_ok(&new, basis, held)?;
			// A pinned entry the user confirmed follows the same rule with the list in its `pins` (one on the endpoint's host and port was held to the endpoint's pins by `endpoint_ok`). An entry that is new, or was listed the other way, has no pins held and is taken on the signed document's word and the user's confirmation of the host.
			for entry in new.refresh_urls.iter().filter(|entry| entry.pinned() && self.hosts.contains(&entry.key())) {
				let held: Vec<&[u8; 32]> = self.subscription.refresh_urls.iter().filter(|old| old.key() == entry.key()).flat_map(Refresh::pins).collect();
				if !entry.pins().iter().any(|pin| held.contains(&pin)) {return Err(Failure::Pins)}
			}
		}
		let (endpoint, pins) = match (moving, endpoint) {
			(Some(moving), _) => (Some(moving.url.clone()), if new.endpoint_pins.is_empty() {moving.pins.clone()} else {new.endpoint_pins.clone()}),
			(None, Some(endpoint)) => (Some(endpoint), if new.endpoint_pins.is_empty() {self.pins.clone()} else {new.endpoint_pins.clone()}),
			(None, None) => (None, Vec::new()),
		};
		let mut changes = Changes {rotated: new.signing_keys != self.subscription.signing_keys, renewed: pins.len() != self.pins.len() || pins.iter().any(|pin| !self.pins.contains(pin)), hosts: Vec::new(), dropped: self.subscription.profiles.iter().filter(|old| !new.profiles.iter().any(|profile| profile.id == old.id)).map(|old| (old.id.clone(), new.refused.iter().find(|refused| refused.id.as_deref() == Some(&old.id)).map(|refused| refused.fault))).collect(), devices_grew: new.devices.iter().any(|device| !self.subscription.devices.iter().any(|old| old.name == device.name && old.enrolled_at == device.enrolled_at)), moved, moving: false};
		// "Each accepted document decides the pending move again": one that names the same move keeps it and what was answered about it, one that names another replaces it and is asked about anew, and one that names the main endpoint or leaves the member out cancels it. After a completed move the main endpoint is the new one, and a whole document has none.
		let moving = endpoint.as_ref().and_then(|endpoint| new.main_endpoint.clone().filter(|main| !names(main, endpoint, &pins))).map(|main| match self.moving.clone().filter(|before| !moved && before.endpoint.url == main.url && before.endpoint.kind() == main.kind()) {
			Some(before) => Move {endpoint: main, ..before},
			None => Move {endpoint: main, confirmed: false, declined: false},
		});
		changes.moving = moving.as_ref().is_some_and(|moving| !moving.confirmed && !moving.declined);
		(self.document, self.subscription, self.pins, self.endpoint, self.moving) = (document, new, pins, endpoint, moving);
		// A host stays confirmed only while documents list it. One that a document dropped and a later one lists again is a host "a later document adds", and is asked about again.
		let listed: Vec<String> = self.subscription.host_keys().collect();
		self.hosts.retain(|host| listed.contains(host));
		self.declined.retain(|host| listed.contains(host));
		changes.hosts = self.waiting();
		Ok(Refreshed::Updated(changes))
	}
	// `k_name` and `k_mirror` from the link's token, the device's secret and its key: "The client holds everything it needs".
	fn mirror_keys(&self) -> Option<MirrorKeys> {self.origin.as_ref().map(|(link, device)| MirrorKeys::derive(link.token().expose(), device.secret.expose(), &device.public))}
	/// The static mirrors of the last good document that the user has confirmed as static mirrors, in the document's order, each with the URL of the one file to ask it for: the name for the period of `now`, and no other ("Periods and clocks"). Empty for a subscription that came as a whole document. The caller tries them only after `targets` all failed in the same refresh, never for an import, `confirm`, `release` or a name, and sends nothing but a `GET` of the URL ("How a client fetches a static mirror").
	pub fn static_targets(&self, now: u64) -> Vec<StaticTarget> {
		let Some(keys) = self.mirror_keys() else {return Vec::new()};
		let epoch = mirror::epoch(now);
		self.subscription.static_mirrors.iter().filter(|base| self.hosts.contains(&mirror::host_key(base))).filter_map(|base| Url::parse(&format!("{}{}", base.as_str(), mirror::file_name(&keys, base.as_str(), epoch)), LINK_URL_MAX, false, false).map(|url| StaticTarget {url, base: base.clone(), epoch})).collect()
	}
	/// The body of the answer of a static mirror for `target`: opened, and then its envelope goes through `refresh`, the one path of an answer from the endpoint. Nothing about where it came from is passed on or trusted. `Unchanged` is "this mirror has nothing newer", and the caller tries the next static mirror and does not count a refresh as made. Every `Err` is a failure of that mirror and never a revocation, except `Failure::Refused`, a signed refusal that verified.
	pub fn refresh_static(&mut self, target: &StaticTarget, body: &[u8], now: u64) -> Result<Refreshed, Failure> {
		let keys = self.mirror_keys().ok_or(Failure::Mirror(OpenError::Seal))?;
		let envelope = mirror::open(&keys, target.base.as_str(), target.epoch, body).map_err(Failure::Mirror)?;
		self.refresh(&envelope, now)
	}
	pub fn standing(&self, now: u64) -> Standing {if now < self.subscription.expires_at {Standing::Current} else if now - self.subscription.expires_at <= GRACE {Standing::OutOfDate} else {Standing::Stale}}
	/// Asked at every connect with a profile of this subscription, also by "a device set to connect when it starts", which "stays disconnected until the user has confirmed".
	pub fn connect(&self, now: u64) -> Result<Permit, Stale> {
		let permit = Permit {id: self.subscription.id.clone(), at: now};
		if self.standing(now) == Standing::Stale {Err(Stale(permit))} else {Ok(permit)}
	}
	/// The value to put in storage.
	pub fn stored(&self) -> Stored {Stored {origin: self.origin.as_ref().map(|(link, device)| (link.veilway(), device.private.clone(), device.secret.clone())), keys: self.keys().iter().map(|key| *key.bytes()).collect(), document: self.document.clone(), hosts: self.hosts.clone(), declined: self.declined.clone(), pins: self.pins.clone(), private: self.private.clone(), endpoint: self.endpoint.as_ref().zip(self.origin.as_ref()).filter(|(endpoint, (link, _))| *endpoint != link.endpoint()).map(|(endpoint, _)| endpoint.as_str().to_owned()), moving: self.moving.as_ref().map(|moving| StoredMove {key: moving.key(), confirmed: moving.confirmed, declined: moving.declined})}}
	/// The private addresses the user said yes to for this subscription's endpoints: "Fetching" asks once per address, and a name that comes to another private address asks again. A fetch may dial a private address only if it is in this list.
	pub fn private_addresses(&self) -> &[IpAddr] {&self.private}
	/// Remembers the user's yes to `addresses`, the ones the question showed. Only an address that is `private` and `dialable` is kept, so a yes can never reach a loopback, link-local or other refused address. At most `PRIVATE_MAX` are kept, the oldest dropped first.
	pub fn allow_private(&mut self, addresses: &[IpAddr]) {
		for address in addresses.iter().filter(|address| payload::dialable(**address) && payload::private(**address)) {if !self.private.contains(address) {self.private.push(*address)}}
		if self.private.len() > PRIVATE_MAX {self.private.drain(..self.private.len() - PRIVATE_MAX);}
	}
	/// A `Held` out of storage. The document is verified again under the stored keys and read again, so a `Held` never holds a document that would not pass today's reader. The clock is not asked: an old document is still the last good one. A confirmed host that is no `host:port`, or that the document does not list, is not kept, and the user is asked about it again. A declined host is kept on the same terms.
	/// The stored device is not compared with the keys in the document, and the stored keys are not compared with anything: what is stored is trusted.
	pub fn restore(stored: Stored) -> Result<Self, Damaged> {
		let (Some(keys), Ok(origin)) = (stored.keys.iter().map(|key| SigningKey::new(*key)).collect::<Option<Vec<_>>>().filter(|keys| (1..=2).contains(&keys.len())), match stored.origin.as_ref().map(|(link, private, secret)| (Link::parse(link), Device::restore(private.clone(), secret.clone()))) {
			None => Ok(None),
			Some((Ok(Link::Native(link)), device)) => Ok(Some((link, device))),
			Some(_) => Err(()),
		}) else {return Err(Damaged::Broken(stored.origin.map(Box::new)))};
		// The main endpoint is the link's until a move completed, and then the one that was stored. Read as untrusted: it must be an `http` or `https` URL of the rules for a URL the token is sent to.
		let endpoint = match (&origin, &stored.endpoint) {
			(None, _) => None,
			(Some((link, _)), None) => Some(link.endpoint().clone()),
			(Some(_), Some(text)) => if stored.pins.is_empty() {Url::either(text, LINK_URL_MAX, false, false)} else {Url::pinned(text, LINK_URL_MAX, false, false)},
		};
		// The pins held are the main endpoint's: none for an endpoint with no pin, for a plain one or for a whole document, otherwise 1 or 2. An endpoint that is still the link's is pinned exactly when the link is.
		let linked = origin.as_ref().zip(endpoint.as_ref()).is_some_and(|((link, _), endpoint)| endpoint == link.endpoint());
		let fits = stored.pins.len() <= 2 && stored.pins.windows(2).all(|pair| pair[0] != pair[1]) && origin.is_some() == endpoint.is_some() && match (&origin, &endpoint) {
			(Some((link, _)), Some(_)) if linked => link.pin().is_some() == !stored.pins.is_empty(),
			(Some(_), Some(endpoint)) => !endpoint.is_plain() || stored.pins.is_empty(),
			_ => stored.pins.is_empty(),
		};
		let verified = envelope::verify(stored.document.as_bytes(), &keys, BODY_MAX).ok().filter(|_| fits);
		let Some(verified) = verified else {return Err(Damaged::Broken(stored.origin.map(Box::new)))};
		match payload::parse(&verified) {
			// Every step that stores pins stores exactly the list of the document when it has one, so pins that differ from it are storage that does not hold together, and are not trusted for a recovery fetch.
			Ok(Payload::Subscription(subscription)) if subscription.signing_keys == keys && origin.is_some() && !subscription.endpoint_pins.is_empty() && stored.pins != subscription.endpoint_pins => Err(Damaged::Broken(stored.origin.map(Box::new))),
			Ok(Payload::Subscription(subscription)) if subscription.signing_keys == keys && endpoint.as_ref().is_none_or(|endpoint| !subscription.gateway_keys.is_empty() && endpoint_ok(&subscription, endpoint, &stored.pins).is_ok()) => {
				let hosts: Vec<String> = stored.hosts.into_iter().filter(|host| subscription.host_keys().any(|listed| listed == *host)).collect();
				let mut declined: Vec<String> = stored.declined.into_iter().filter(|host| !hosts.contains(host) && subscription.host_keys().any(|listed| listed == *host)).collect();
				declined.sort();
				declined.dedup();
				// The move that waits is the document's own `main_endpoint`, with what the user answered when the same move was named.
				let moving = endpoint.as_ref().and_then(|endpoint| subscription.main_endpoint.clone().filter(|main| !names(main, endpoint, &stored.pins))).map(|main| {
					let mut moving = Move {endpoint: main, confirmed: false, declined: false};
					if let Some(answer) = stored.moving.filter(|answer| answer.key == moving.key() && !(answer.confirmed && answer.declined)) {(moving.confirmed, moving.declined) = (answer.confirmed, answer.declined)}
					moving
				});
				let mut held = Self {hosts, declined, origin, endpoint, moving, document: stored.document, subscription: *subscription, pins: stored.pins, private: Vec::new()};
				held.allow_private(&stored.private);
				Ok(held)
			}
			_ => Err(Damaged::Unread(origin.map(|(link, device)| Box::new(Fetching {gateway: vec![link.gateway()], endpoint: endpoint.unwrap_or_else(|| link.endpoint().clone()), link, device, keys, pins: stored.pins})))),
		}
	}
}

/// The wait before the next automatic refresh: `interval` is the document's `update_interval` and `failures` the number of refreshes that failed since the last one that did not. "Each wait is multiplied by a number drawn uniformly from 0.8 to 1.2", and after a failure it is "the interval, doubled per failure up to 86,400 s", and never shorter than the interval itself: a provider that asks for a refresh a week is not asked daily because one refresh failed.
pub fn wait(interval: u32, failures: u32, random: &mut Random) -> Result<Duration, NoRandom> {
	let seconds = u64::from(interval).max(u64::from(interval).checked_shl(failures).filter(|_| failures < 32).map_or(BACKOFF_MAX, |seconds| seconds.min(BACKOFF_MAX)));
	Ok(Duration::from_millis(seconds * u64::from(uniform(800, 1_200, random)?)))
}
