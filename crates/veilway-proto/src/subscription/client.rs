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
use super::{envelope::{self, EnvelopeError, Fingerprint, SigningKey}, fetch::{DeviceName, Op, Request}, is_host, legacy::{self, Headers, LegacyError, List}, link::{Carried, Legacy, Link, Native}, payload::{self, Fault, Id, KeyOrigin, Payload, PayloadError, Reason, Refusal, Subscription}, DeviceSecret, Secret, Url, BODY_MAX, CARRIED_MAX};
use crate::{proof, uniform, NoRandom, Random};
use std::{fmt, time::Duration};

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
		Ok(Fetching {keys: vec![self.0.key()], link: self.0, device})
	}
}

/// Step 2 of a native import: the one request with `op` `"fetch"` is out, or about to be. The keys an answer is verified under are the key of the link, or the keys a stored subscription held when its document could not be read again (`Damaged::Unread`).
#[derive(Debug)]
pub struct Fetching {link: Native, device: Device, keys: Vec<SigningKey>}

impl Fetching {
	pub fn endpoint(&self) -> &Url {self.link.endpoint()}
	fn ask(&self, op: Op) -> Request {Request::new(self.link.token().clone(), self.keys.iter().map(SigningKey::kid).collect(), self.device.public, self.device.secret.clone(), op)}
	/// "One request with `op` `"fetch"`", naming the keys held: on a first import, "the id of the key in the link".
	pub fn request(&self) -> Request {self.ask(Op::Fetch)}
	/// The body of the answer. "A native link expects a signed document under the link's key, and anything else is a failure": it "is never read as a legacy list".
	/// `stored` is every subscription the app holds, so that the review can say whether this one replaces one of them. A failure leaves this step as it was, to try again or to `abandon`.
	pub fn answer(&self, body: &[u8], now: u64, stored: &[&Held]) -> Result<Review, Failure> {review(Some((self.link.clone(), self.device.clone())), &self.keys, body, BODY_MAX, now, stored)}
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
	pub fn proceed(self, now: u64, stored: &[&Held]) -> Result<Review, Failure> {review(None, &[self.0.key()], self.0.document(), if self.0.in_file() {BODY_MAX} else {CARRIED_MAX}, now, stored)}
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

// The document of an import: verified under the keys held for it, which on a first import is the one key that came with the link, read, and judged by the clock, the device's key and the rule of a fresh import.
fn review(origin: Option<(Native, Device)>, keys: &[SigningKey], document: &[u8], limit: usize, now: u64, stored: &[&Held]) -> Result<Review, Failure> {
	let verified = envelope::verify(document, keys, limit).map_err(Failure::Envelope)?;
	let subscription = match payload::parse(&verified).map_err(Failure::Payload)? {
		Payload::Refusal(refusal) => return Err(recent(&refusal, now)),
		Payload::Subscription(subscription) => *subscription,
	};
	timely(&subscription, now)?;
	keyed(&subscription, origin.as_ref().map(|(_, device)| device), None)?;
	let document = String::from_utf8(document.to_vec()).map_err(|_| Failure::Envelope(EnvelopeError::Encoding))?;
	let replaces = replaced(&subscription, &document, &verified.signer(), origin.is_some(), stored)?.is_some();
	Ok(Review {origin, key: verified.signer(), document, subscription, replaces})
}

/// Step 3 of an import: a document that passed every check, for the user to confirm. Nothing of it is stored yet.
pub struct Review {origin: Option<(Native, Device)>, key: SigningKey, document: String, subscription: Subscription, replaces: bool}

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
	/// "Whether the device's key was made on this device or issued by the provider."
	pub fn origin(&self) -> KeyOrigin {self.subscription.origin()}
	/// Whether the subscription can refresh. A whole document cannot, "and the app says so".
	pub fn refreshes(&self) -> bool {self.origin.is_some()}
	fn release(origin: Option<(Native, Device)>, key: SigningKey) -> Option<Request> {origin.map(|(link, device)| Request::new(link.token().clone(), vec![key.kid()], device.public, device.secret, Op::Release))}
	/// The user accepts. `stored` is every subscription the app holds now: the rule of a fresh import is asked again, because the confirmation may have been on the screen while a refresh ran. "The client stores the subscription and sends `"confirm"`, with the name if one was typed." The hosts of `refresh_urls` were on the screen, so they are confirmed with it, unless the subscription has no link to refresh by.
	pub fn accept(self, name: Option<DeviceName>, stored: &[&Held]) -> Result<Accepted, Box<Declined>> {
		let replaces = match replaced(&self.subscription, &self.document, &self.key, self.origin.is_some(), stored) {
			Ok(replaces) => replaces.map(|_| Replaced {id: self.subscription.id.clone(), key: self.key}),
			Err(failure) => return Err(Box::new(Declined {failure, release: Self::release(self.origin, self.key)})),
		};
		let hosts = if self.origin.is_some() {self.subscription.refresh_urls.iter().map(Url::authority).collect()} else {Vec::new()};
		let held = Held {origin: self.origin, document: self.document, subscription: self.subscription, hosts};
		Ok(Accepted {confirm: held.request(Op::Confirm(name)), held, replaces})
	}
	/// The user declines. "The client sends `"release"`, so that the device place is freed, and keeps nothing: not the document, not the link, not the key it made." `None` for a whole document, which took no place.
	pub fn decline(self) -> Option<Request> {Self::release(self.origin, self.key)}
}

/// What a client holds for one subscription: the link it came by and the device made for it, unless it came as a whole document, the last good document as it was delivered, and the refresh hosts the user has confirmed, each with its port. The keys held, the id, the serial and the times are those of the last good document, so they cannot disagree with it.
#[derive(Clone, PartialEq)]
pub struct Held {origin: Option<(Native, Device)>, document: String, subscription: Subscription, hosts: Vec<String>}

// The document holds transport secrets, and with a provider-issued key the device's private key. None of it is printed, and neither is the link.
impl fmt::Debug for Held {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Held({:?}, {:?}, {} bytes, {} confirmed hosts)", self.subscription, self.subscription.signing_keys, self.document.len(), self.hosts.len())}
}

/// What a refresh that was taken changed, for the notes the app keeps and shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Changes {
	/// The keys held are others than before: "the provider renewed its signing key". Noted with the date. "It does not ask the user anything."
	pub rotated: bool,
	/// Refresh hosts, as `host:port`, the user has not confirmed: "the provider added a refresh host". They are not in `Held::endpoints` until `Held::confirm_hosts`.
	pub hosts: Vec<String>,
	/// Profiles the client had that the new document leaves out, or holds in a form that was refused, by `id` and with the fault if there is one.
	pub dropped: Vec<(String, Option<Fault>)>,
	/// The list names a device that the list before it did not, by name and time of enrolment: "a device the user does not know is a sign that the link has leaked, and the app says so when the list grows". A list that is no longer has grown too when one device took the place of another.
	pub devices_grew: bool,
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
	/// The confirmed refresh hosts, each as `host:port`.
	pub hosts: Vec<String>,
}

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
	// A request of this subscription, which names the keys held.
	fn request(&self, op: Op) -> Option<Request> {self.origin.as_ref().map(|(link, device)| Request::new(link.token().clone(), self.keys().iter().map(SigningKey::kid).collect(), device.public, device.secret.clone(), op))}
	/// The request of a refresh, or `None` for a subscription that cannot refresh. When it goes out is the caller's, under "When a fetch happens".
	pub fn fetch(&self) -> Option<Request> {self.request(Op::Fetch)}
	/// A `confirm` with another name, which "replaces it".
	pub fn rename(&self, name: Option<DeviceName>) -> Option<Request> {self.request(Op::Confirm(name))}
	// The refresh URLs of the last good document with whether the user has confirmed the host and port of each. The endpoint of the link needs no confirmation. A subscription with no link has none: it cannot refresh, whatever its document lists.
	fn listed(&self) -> impl Iterator<Item = (&Url, bool)> {self.origin.iter().flat_map(move |(link, _)| self.subscription.refresh_urls.iter().map(move |url| (url, url.authority() == link.endpoint().authority() || self.hosts.contains(&url.authority()))))}
	/// Where a request of this subscription may go, in the order to try: the endpoint of the link, then the `refresh_urls` of the last good document whose host and port the user has confirmed. The token goes nowhere else. Empty for a subscription that came as a whole document.
	pub fn endpoints(&self) -> Vec<&Url> {self.origin.iter().map(|(link, _)| link.endpoint()).chain(self.listed().filter(|(_, confirmed)| *confirmed).map(|(url, _)| url)).collect()}
	/// The refresh hosts of the last good document that wait for the user, each as `host:port`: the app "asks at the next refresh the user starts. Until then the client uses the hosts it already had."
	pub fn unconfirmed(&self) -> Vec<String> {
		let mut hosts = Vec::new();
		for host in self.listed().filter(|(_, confirmed)| !confirmed).map(|(url, _)| url.authority()) {if !hosts.contains(&host) {hosts.push(host)}}
		hosts
	}
	/// The user confirmed the hosts in `seen`, each as `host:port` as `unconfirmed` gave it: what the screen showed. Only hosts that wait are taken, so a host that a refresh added while the screen was up is not confirmed with it.
	pub fn confirm_hosts(&mut self, seen: &[&str]) {
		let confirmed: Vec<String> = self.unconfirmed().into_iter().filter(|host| seen.contains(&host.as_str())).collect();
		self.hosts.extend(confirmed);
	}
	/// The body of the answer to a refresh, at the wall clock `now`. Every check of "What is checked, in order" runs, against the keys held and the last good document. On any failure nothing here changes, and the caller shows why, "and tries again as the table of numbers says".
	pub fn refresh(&mut self, body: &[u8], now: u64) -> Result<Refreshed, Failure> {
		let verified = envelope::verify(body, self.keys(), BODY_MAX).map_err(Failure::Envelope)?;
		let new = match payload::parse(&verified).map_err(Failure::Payload)? {
			// "On a refresh it must carry the stored `subscription_id`, or it is a failed refresh."
			Payload::Refusal(refusal) => return Err(if refusal.subscription_id == self.subscription.id {recent(&refusal, now)} else {Failure::OtherSubscription}),
			Payload::Subscription(subscription) => *subscription,
		};
		if new.id != self.subscription.id {return Err(Failure::OtherSubscription)}
		timely(&new, now)?;
		if new.serial < self.subscription.serial {return Err(Failure::Rollback)}
		if new.serial == self.subscription.serial {return if body == self.document.as_bytes() {Ok(Refreshed::Unchanged)} else {Err(Failure::Fork)}}
		if new.issued_at < self.subscription.issued_at {return Err(Failure::Backdated)}
		keyed(&new, self.device(), Some(&self.subscription))?;
		let mut changes = Changes {rotated: new.signing_keys != self.subscription.signing_keys, hosts: Vec::new(), dropped: self.subscription.profiles.iter().filter(|old| !new.profiles.iter().any(|profile| profile.id == old.id)).map(|old| (old.id.clone(), new.refused.iter().find(|refused| refused.id.as_deref() == Some(&old.id)).map(|refused| refused.fault))).collect(), devices_grew: new.devices.iter().any(|device| !self.subscription.devices.iter().any(|old| old.name == device.name && old.enrolled_at == device.enrolled_at))};
		(self.document, self.subscription) = (String::from_utf8(body.to_vec()).map_err(|_| Failure::Envelope(EnvelopeError::Encoding))?, new);
		// A host stays confirmed only while documents list it. One that a document dropped and a later one lists again is a host "a later document adds", and is asked about again.
		let listed = &self.subscription.refresh_urls;
		self.hosts.retain(|host| listed.iter().any(|url| url.authority() == *host));
		changes.hosts = self.unconfirmed();
		Ok(Refreshed::Updated(changes))
	}
	pub fn standing(&self, now: u64) -> Standing {if now < self.subscription.expires_at {Standing::Current} else if now - self.subscription.expires_at <= GRACE {Standing::OutOfDate} else {Standing::Stale}}
	/// Asked at every connect with a profile of this subscription, also by "a device set to connect when it starts", which "stays disconnected until the user has confirmed".
	pub fn connect(&self, now: u64) -> Result<Permit, Stale> {
		let permit = Permit {id: self.subscription.id.clone(), at: now};
		if self.standing(now) == Standing::Stale {Err(Stale(permit))} else {Ok(permit)}
	}
	/// The value to put in storage.
	pub fn stored(&self) -> Stored {Stored {origin: self.origin.as_ref().map(|(link, device)| (link.veilway(), device.private.clone(), device.secret.clone())), keys: self.keys().iter().map(|key| *key.bytes()).collect(), document: self.document.clone(), hosts: self.hosts.clone()}}
	/// A `Held` out of storage. The document is verified again under the stored keys and read again, so a `Held` never holds a document that would not pass today's reader. The clock is not asked: an old document is still the last good one. A confirmed host that is no `host:port`, or that the document does not list, is not kept, and the user is asked about it again.
	/// The stored device is not compared with the keys in the document, and the stored keys are not compared with anything: what is stored is trusted.
	pub fn restore(stored: Stored) -> Result<Self, Damaged> {
		let (Some(keys), Ok(origin)) = (stored.keys.iter().map(|key| SigningKey::new(*key)).collect::<Option<Vec<_>>>().filter(|keys| (1..=2).contains(&keys.len())), match stored.origin.as_ref().map(|(link, private, secret)| (Link::parse(link), Device::restore(private.clone(), secret.clone()))) {
			None => Ok(None),
			Some((Ok(Link::Native(link)), device)) => Ok(Some((link, device))),
			Some(_) => Err(()),
		}) else {return Err(Damaged::Broken(stored.origin.map(Box::new)))};
		let Ok(verified) = envelope::verify(stored.document.as_bytes(), &keys, BODY_MAX) else {return Err(Damaged::Broken(stored.origin.map(Box::new)))};
		match payload::parse(&verified) {
			Ok(Payload::Subscription(subscription)) if subscription.signing_keys == keys => Ok(Self {hosts: stored.hosts.into_iter().filter(|host| host.rsplit_once(':').is_some_and(|(name, port)| is_host(name) && port.parse::<u16>().is_ok()) && subscription.refresh_urls.iter().any(|url| url.authority() == *host)).collect(), origin, document: stored.document, subscription: *subscription}),
			_ => Err(Damaged::Unread(origin.map(|(link, device)| Box::new(Fetching {link, device, keys})))),
		}
	}
}

/// The wait before the next automatic refresh: `interval` is the document's `update_interval` and `failures` the number of refreshes that failed since the last one that did not. "Each wait is multiplied by a number drawn uniformly from 0.8 to 1.2", and after a failure it is "the interval, doubled per failure up to 86,400 s", and never shorter than the interval itself: a provider that asks for a refresh a week is not asked daily because one refresh failed.
pub fn wait(interval: u32, failures: u32, random: &mut Random) -> Result<Duration, NoRandom> {
	let seconds = u64::from(interval).max(u64::from(interval).checked_shl(failures).filter(|_| failures < 32).map_or(BACKOFF_MAX, |seconds| seconds.min(BACKOFF_MAX)));
	Ok(Duration::from_millis(seconds * u64::from(uniform(800, 1_200, random)?)))
}
