//! Subscription import as a library flow (subscription format page, "Import" and "Fetching"): a link, the user's first yes, the fetch, the confirmation, and the storing, and the refresh of what is stored.
//!
//! The rules the types of `veilway-proto` carry are not repeated or bypassed here. A link becomes an `Offer`, which can do nothing; the only way on is `NativeOffer::proceed`, the user's yes, and only then a request can exist. An answer becomes a `Review` only through the checks of `client`, and is kept only after `Review::accept`. What this module adds is the part with a network and a disk: one `POST` over `https` with the rules of "How a fetch is made", and a place to keep what was accepted.
//!
//! The rules of the fetch: `https` only; the chain validated against the roots it is given, TLS 1.2 or later, and no early data; no redirect followed; no `Accept-Language`, `Accept-Encoding: identity` and an answer with a `Content-Encoding` refused; ten seconds to connect and thirty in all; the body read to its limit and not past it; the name looked up once, and an address that is loopback, link-local, unspecified, multicast, broadcast or an IPv6 form that carries an IPv4 address refused, with the address that was checked being the one dialled. **A private address** (`private` of `veilway-proto`) is dialled only if the user said yes to that exact address, for this subscription (`Held::private_addresses`) or, on a first import, in the call (`allowed`). When the endpoint's host gives no address that may be dialled and at least one private one, the step stops with `ImportError::PrivateEndpoint` and the addresses to show, and nothing is sent. A yes is to addresses and never to the host name, so a name that comes to another private address asks again. The token is in the body of the request and nowhere else.
//! **A pinned endpoint** (the link's third field, a pinned entry of `refresh_urls`) is held to its pins alone, as the transport library holds a self-signed candidate (`veilway_transport::pin_only`): TLS 1.3 only, the SHA-256 of the leaf's SubjectPublicKeyInfo is one of the pins and the handshake is signed with that key, no chain, name or date, no early data and no resumed session. The request, with the token in its body, is written only after that check passed. A mismatch is `FetchError::Pin`, never a refusal of the endpoint. A pinned host that is an IP literal is dialled with no lookup and sent no server name. `Held::targets` and `Fetching::pins` say which pins each endpoint is checked by.
//! **The vault is the platform's.** The subscriptions hold the link's token, the device's private key and the transport secrets, so they belong in the operating system's secret storage or in a file encrypted under a key kept there. `Vault` is the trait the platform implements for that. The only vault that ships in a build is none: `FileVault`, a mode-600 file with the secrets in plain base64, exists with the `unencrypted-vault` feature and in this crate's own tests, for tests.
//! A fetch outside a tunnel is the caller's to allow ("When a fetch happens"): this module makes the request it is told to make and does not decide when. With the kill switch on, the platform's hook for the socket (`Fetcher::socket`) is where it can refuse.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket};
use tokio::time::{timeout, timeout_at, Instant};
use tokio_rustls::TlsConnector;
use veilway_proto::subscription::client::{Accepted, CarriedOffer, Damaged, Declined, Device, Failure, Fetching, Held, NativeOffer, Offer, Refreshed, Review, Source, Stored, CONNECT_TIMEOUT, FETCH_TIMEOUT};
use veilway_proto::subscription::mirror;
use veilway_proto::subscription::envelope::EnvelopeError;
use veilway_proto::subscription::fetch::{DeviceName, Request};
use veilway_proto::subscription::link::{Carried, Link, LinkError};
use veilway_proto::subscription::payload::{dialable, private, PayloadError, Reason};
use veilway_proto::subscription::{DeviceSecret, Secret, Url, BODY_MAX};
use veilway_transport::http;
use veilway_transport::Hook;

/// How the name of an endpoint is looked up: once per fetch, by the resolver in force. The default is the system's, with the refusals of the page applied to what it returns. A caller that puts its own in (the tunnel's resolver, a test) is the one that applies them.
pub type Resolve = Arc<dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> + Send + Sync>;

/// The system's resolver, and the refusals of the page: an address that is loopback, link-local, unspecified or multicast is refused. A private address stays in the answer, and `Fetcher::post` dials it only with the user's yes to it. What is left of the answer is what is dialled.
pub fn system_resolver() -> Resolve {
	Arc::new(|host, port| Box::pin(async move {
		let found: Vec<SocketAddr> = lookup_host((host.as_str(), port)).await?.filter(|address| dialable(address.ip())).collect();
		if found.is_empty() {Err(io::Error::new(io::ErrorKind::PermissionDenied, "every address of the endpoint is one that may not be dialled"))} else {Ok(found)}
	}))
}

/// What an endpoint is trusted by: its certificate's chain, or the pins that came with its link or its entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
	Chain,
	/// The SHA-256 of a SubjectPublicKeyInfo, one or two.
	Pinned(Vec<[u8; 32]>),
}

impl Trust {
	/// The trust of an endpoint that is checked by `pins`: none is the chain.
	pub fn of(pins: &[[u8; 32]]) -> Self {if pins.is_empty() {Self::Chain} else {Self::Pinned(pins.to_vec())}}
}

/// Why a request got no answer to read. None of these is a signed refusal, and each leaves what the client holds as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
	/// The name did not resolve, or only to addresses that may not be dialled.
	Resolve,
	/// The host gives no address that may be dialled and these private ones (at most 8), which the user has not said yes to. Nothing was sent. `ImportError` carries it as `PrivateEndpoint`.
	Private {host: String, addresses: Vec<IpAddr>},
	/// No connection within ten seconds, or the device could not make a socket.
	Connect,
	/// The certificate did not pass.
	Certificate,
	/// A pinned endpoint's certificate matches none of its pins, or its handshake is not signed with the pinned key, or TLS 1.3 was not negotiated. Nothing was sent, and whatever the server writes is not read.
	Pin,
	/// The TLS handshake failed for another reason.
	Tls,
	/// Thirty seconds in all passed.
	Timeout,
	/// What came was no HTTP answer, or was cut short.
	NotHttp,
	/// The endpoint redirected, which is a failed fetch.
	Redirect,
	/// Any status but 200, which is how a host answers a path it does not serve.
	Status(u16),
	/// A `Content-Encoding`, which is refused.
	Encoding,
	/// A body over its limit, or a length that lies.
	Body,
}

impl FetchError {
	pub fn code(&self) -> Code {
		match self {
			Self::Private {..} => Code::PrivateAddress,
			Self::Resolve => Code::Resolve,
			Self::Connect => Code::Unreachable,
			Self::Certificate => Code::Certificate,
			Self::Tls => Code::Tls,
			Self::Timeout => Code::Timeout,
			Self::NotHttp | Self::Redirect | Self::Status(_) | Self::Encoding | Self::Body => Code::NoSubscription,
			Self::Pin => Code::Pin,
		}
	}
}

/// Why an import step did not go through. Nothing was stored, and what was held is as it was.
#[derive(Debug)]
pub enum ImportError {
	/// The text begins with neither `veilway://` nor `https://`.
	NotALink,
	/// The text begins as a link does and does not read: cut off, mistyped or changed.
	Link(LinkError),
	/// The content of a file that is no subscription file, or is over its limit.
	File(LinkError),
	/// A legacy link: it needs the compatibility add-on, which is not part of this engine.
	Legacy,
	Fetch(FetchError),
	/// An answer that did not pass the checks of `client`, or a rule that no longer allows what the user accepted.
	Subscription(Failure),
	/// A key could not be made: the system's random source failed.
	Random,
	/// The accepted subscription could not be written. The device place is released.
	Store(io::Error),
	/// The app holds as many subscriptions as a vault takes.
	Full,
	/// The endpoint is on a private address and the user has not said yes to it. The app asks, in plain words, "This subscription is on a private address (192.168.1.20). Only continue if you run this server yourself, for example at home.", and goes on with these addresses as `allowed` (an import) or through `Library::allow_private` (a refresh). Nothing was sent.
	PrivateEndpoint {host: String, addresses: Vec<IpAddr>},
}

impl From<FetchError> for ImportError {
	fn from(error: FetchError) -> Self {
		match error {
			FetchError::Private {host, addresses} => Self::PrivateEndpoint {host, addresses},
			error => Self::Fetch(error),
		}
	}
}

impl ImportError {
	pub fn code(&self) -> Code {
		match self {
			Self::NotALink => Code::NotALink,
			Self::Link(LinkError::Size) => Code::LinkTooLong,
			Self::Link(_) => Code::LinkDamaged,
			Self::File(LinkError::Size) => Code::FileTooLarge,
			Self::File(_) => Code::NotAFile,
			Self::Legacy => Code::Legacy,
			Self::Fetch(error) => error.code(),
			Self::Random => Code::Random,
			Self::Store(_) => Code::Store,
			Self::Full => Code::Full,
			Self::PrivateEndpoint {..} => Code::PrivateAddress,
			Self::Subscription(failure) => match failure {
				Failure::Refused(Reason::DeviceLimit) => Code::DeviceLimit,
				Failure::Refused(Reason::Disabled) => Code::AccountDisabled,
				Failure::Refused(Reason::Expired) => Code::AccountExpired,
				Failure::Refused(Reason::RateLimited) => Code::RateLimited,
				Failure::Refused(Reason::DeviceMismatch) => Code::DeviceMismatch,
				Failure::Refused(Reason::KeyRetired) => Code::KeyRetired,
				Failure::Refused(Reason::Released | Reason::BadRequest) => Code::BadRequest,
				Failure::Envelope(EnvelopeError::Size | EnvelopeError::Parts | EnvelopeError::Encoding) | Failure::Mirror(_) => Code::BadAnswer,
				Failure::Envelope(EnvelopeError::UnknownKey | EnvelopeError::Signature) => Code::Signature,
				Failure::Payload(PayloadError::Version | PayloadError::Critical) => Code::UpdateApp,
				Failure::Payload(_) | Failure::MirrorHost => Code::BadDocument,
				Failure::StaleRefusal => Code::StaleRefusal,
				Failure::OtherSubscription => Code::OtherSubscription,
				Failure::Rollback | Failure::Backdated | Failure::NotNewer => Code::Older,
				Failure::Fork => Code::Different,
				Failure::Expired => Code::Expired,
				Failure::Future => Code::Clock,
				Failure::DeviceKey | Failure::PrivateKey => Code::DeviceKey,
				Failure::HasLink => Code::HasLink,
				Failure::EndpointKind | Failure::Changed | Failure::Pins => Code::EndpointChanged,
			},
		}
	}
	/// The English words, for the command line.
	pub fn text(&self) -> &'static str {self.code().text()}
}

/// Why an import failed, as a stable code. An app translates the code into its own language, so the words of `text` are only the English, for the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
	NotALink,
	LinkDamaged,
	LinkTooLong,
	NotAFile,
	FileTooLarge,
	Legacy,
	Resolve,
	Unreachable,
	Timeout,
	Certificate,
	Tls,
	Pin,
	NoSubscription,
	PrivateAddress,
	Random,
	Store,
	Full,
	DeviceLimit,
	AccountDisabled,
	AccountExpired,
	RateLimited,
	DeviceMismatch,
	KeyRetired,
	BadRequest,
	Signature,
	BadAnswer,
	UpdateApp,
	BadDocument,
	StaleRefusal,
	OtherSubscription,
	Older,
	Different,
	Expired,
	Clock,
	DeviceKey,
	HasLink,
	EndpointChanged,
	FileUnreadable,
	PictureUnreadable,
	PictureLarge,
	NoQr,
	NoImport,
	KillSwitch,
}

impl Code {
	/// The code the apps look up, in the translations of their locale files.
	pub fn as_str(self) -> &'static str {
		match self {
			Self::NotALink => "not_a_link",
			Self::LinkDamaged => "link_damaged",
			Self::LinkTooLong => "link_too_long",
			Self::NotAFile => "not_a_file",
			Self::FileTooLarge => "file_too_large",
			Self::Legacy => "legacy",
			Self::Resolve => "resolve",
			Self::Unreachable => "unreachable",
			Self::Timeout => "timeout",
			Self::Certificate => "certificate",
			Self::Tls => "tls",
			Self::Pin => "pin",
			Self::NoSubscription => "no_subscription",
			Self::PrivateAddress => "private_address",
			Self::Random => "random",
			Self::Store => "store",
			Self::Full => "full",
			Self::DeviceLimit => "device_limit",
			Self::AccountDisabled => "account_disabled",
			Self::AccountExpired => "account_expired",
			Self::RateLimited => "rate_limited",
			Self::DeviceMismatch => "device_mismatch",
			Self::KeyRetired => "key_retired",
			Self::BadRequest => "bad_request",
			Self::Signature => "signature",
			Self::BadAnswer => "bad_answer",
			Self::UpdateApp => "update_app",
			Self::BadDocument => "bad_document",
			Self::StaleRefusal => "stale_refusal",
			Self::OtherSubscription => "other_subscription",
			Self::Older => "older",
			Self::Different => "different",
			Self::Expired => "expired",
			Self::Clock => "clock",
			Self::DeviceKey => "device_key",
			Self::HasLink => "has_link",
			Self::EndpointChanged => "endpoint_changed",
			Self::FileUnreadable => "file_unreadable",
			Self::PictureUnreadable => "picture_unreadable",
			Self::PictureLarge => "picture_large",
			Self::NoQr => "no_qr",
			Self::NoImport => "no_import",
			Self::KillSwitch => "kill_switch",
		}
	}
	/// The English words, for the command line.
	pub fn text(self) -> &'static str {
		match self {
			Self::NotALink => "This is not a Veilway subscription link. Check that you copied the link your provider sent.",
			Self::LinkDamaged => "This link is cut off or mistyped. Copy it again, or ask the provider for a new one.",
			Self::LinkTooLong => "This link is too long to be a subscription link. Check that nothing else was pasted with it.",
			Self::NotAFile => "This is not a Veilway subscription file, or it is damaged. Ask the provider for the file again.",
			Self::FileTooLarge => "This file is too large to be a subscription file. Ask the provider for the file again.",
			Self::Legacy => "This is a link of another kind, which cannot be checked with a key, and this app cannot import it. Ask the provider for a Veilway subscription link.",
			Self::Resolve => "The provider's server name could not be found, or it points to an address this app does not connect to. Check your internet connection, or try again later.",
			Self::Unreachable => "Could not connect to the provider's server. Check your internet connection, or try again later.",
			Self::Timeout => "The provider's server took too long to answer. Check your internet connection, then try again.",
			Self::Certificate => "The provider's server certificate is not valid. If your provider uses its own certificate, part of the link may have been lost: copy the link again.",
			Self::Tls => "A secure connection to the provider's server could not be made. Check your internet connection, then try again.",
			Self::Pin => "The provider's server does not match this link. If your provider changed its server, ask for a new link. Otherwise, something between you and the provider may be answering.",
			Self::NoSubscription => "The provider's address did not answer as a subscription server. The link may be cut off or out of date: ask the provider for a new one.",
			Self::PrivateAddress => "This subscription is on a private address. Only continue if you run this server yourself, for example at home.",
			Self::Random => "This device could not make the keys it needs. Nothing was sent. Try again.",
			Self::Store => "The subscription could not be saved on this device. Check that the system's secure storage works, then try again.",
			Self::Full => "This app already holds as many subscriptions as it can. Remove one first.",
			Self::DeviceLimit => "Every device place on this account is taken. Remove a device in the provider's panel, or ask the provider to reset the link.",
			Self::AccountDisabled => "The provider has switched this account off. Contact the provider.",
			Self::AccountExpired => "This account has expired. Renew it with the provider.",
			Self::RateLimited => "This device has asked too often. Wait a few minutes, then try again.",
			Self::DeviceMismatch => "This device has to be enrolled again. Import the link again.",
			Self::KeyRetired => "The provider has renewed its key. Ask the provider for a new link.",
			Self::BadRequest => "The provider could not process this request. Update the app and try again. If it keeps failing, contact the provider.",
			Self::Signature => "The provider's answer is not signed with the key in this link. The link may be old or tampered with. Ask the provider for a new link.",
			Self::BadAnswer => "The provider's server sent an answer this app cannot read. Try again. If it keeps failing, ask the provider for a new link.",
			Self::UpdateApp => "This subscription needs a newer version of this app. Update the app, then try again.",
			Self::BadDocument => "The provider's subscription is not one this app can read. Ask the provider to check it.",
			Self::StaleRefusal => "The provider's refusal is too old to use. Try again, and check the date and time on this device.",
			Self::OtherSubscription => "The answer is for a different subscription from this link. Check that you have the link you meant.",
			Self::Older => "The provider's answer is older than the subscription this app already holds. Try again later, or ask the provider for a new link.",
			Self::Different => "The provider's answer conflicts with the subscription this app already holds. Ask the provider for a new link.",
			Self::Expired => "This subscription has already expired. Check the date and time on this device. If they are right, ask the provider to renew it.",
			Self::Clock => "The provider's answer is dated later than this device's clock. Check the date and time on this device.",
			Self::DeviceKey => "The provider's answer does not match this device's key. Import the link again.",
			Self::HasLink => "This subscription was imported with a link. Remove it first to replace it with a whole document.",
			Self::EndpointChanged => "The provider's answer changes how its server is checked, which is not allowed without a new link. Ask the provider for a new link.",
			Self::FileUnreadable => "The file could not be read.",
			Self::PictureUnreadable => "The picture could not be read. Use a clear picture of the QR code.",
			Self::PictureLarge => "The picture is too large. Use a smaller picture or a screenshot of the QR code.",
			Self::NoQr => "No QR code was found in the picture. Use a sharp picture of the whole code.",
			Self::NoImport => "There is no import waiting. Start the import again.",
			Self::KillSwitch => "The kill switch is still on from an earlier connection, so nothing can be fetched outside the tunnel. Connect first, or disconnect to turn the kill switch off.",
		}
	}
}

/// What the fetches of an import are made with. Cloning it shares the roots.
#[derive(Clone)]
pub struct Fetcher {pub roots: Arc<rustls::RootCertStore>, pub resolve: Resolve, pub socket: Option<Hook>}

impl Fetcher {
	/// A fetcher with the system's resolver and the roots it is given.
	pub fn new(roots: Arc<rustls::RootCertStore>, socket: Option<Hook>) -> Self {Self {roots, resolve: system_resolver(), socket}}
	/// One `POST` of `body` to `url`, and the body of the answer. See the head of this module for what it does and refuses. `allowed` is the private addresses the user said yes to.
	pub async fn post(&self, url: &Url, trust: &Trust, body: &[u8], allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError> {
		timeout(FETCH_TIMEOUT, self.exchange(url, trust, Some(body), allowed)).await.unwrap_or(Err(FetchError::Timeout))
	}
	/// One plain `GET` of the file of a static mirror ("How a client fetches a static mirror"): no body, no token, no cookie, no `Referer`, no `Accept-Language`, no conditional field and no `Range`, and no `ETag` or `Last-Modified` is read or kept. Status 200 only, no redirect, the chain validated (the handshake is the one of a subscription fetch, with `http/1.1` as its ALPN, which the page states as a leak until the browser's fingerprint is used), the name looked up once, and at most 1,089,437 bytes read in the time of the size the `Content-Length` names (`mirror::time_limit`). Whether the body is a file is for `Held::refresh_static`.
	pub async fn get(&self, url: &Url, allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError> {
		timeout(mirror::time_limit(None), self.exchange(url, &Trust::Chain, None, allowed)).await.unwrap_or(Err(FetchError::Timeout))
	}
	// `body` is `Some` for the `POST` of a request and `None` for the `GET` of a static file.
	async fn exchange(&self, url: &Url, trust: &Trust, body: Option<&[u8]>, allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError> {
		let started = Instant::now();
		let (host, port, literal) = (url.host().to_owned(), url.port(), url.literal());
		// An IP literal is dialled as it is, with no lookup, and held to the same refusals as any address the system's resolver gives.
		let addresses = match literal {
			Some(ip) if dialable(ip) => vec![SocketAddr::new(ip, port)],
			Some(_) => return Err(FetchError::Resolve),
			None => (self.resolve)(host.clone(), port).await.map_err(|_| FetchError::Resolve)?,
		};
		// A private address is dialled only if the user said yes to that very address, so a name that now comes to another one asks again. What is left out is what the question shows.
		let (addresses, withheld): (Vec<SocketAddr>, Vec<SocketAddr>) = addresses.into_iter().partition(|address| !private(address.ip()) || allowed.contains(&address.ip()));
		if addresses.is_empty() {
			let mut shown = Vec::new();
			for address in withheld.iter().take(8) {if !shown.contains(&address.ip()) {shown.push(address.ip())}}
			return Err(if shown.is_empty() {FetchError::Resolve} else {FetchError::Private {host, addresses: shown}});
		}
		let mut stream = None;
		for address in addresses.into_iter().take(4) {
			let socket = if address.is_ipv4() {TcpSocket::new_v4()} else {TcpSocket::new_v6()}.map_err(|_| FetchError::Connect)?;
			if let Some(hook) = &self.socket {hook(socket2::SockRef::from(&socket)).map_err(|_| FetchError::Connect)?}
			if let Ok(Ok(connected)) = timeout(CONNECT_TIMEOUT, socket.connect(address)).await {
				stream = Some(connected);
				break;
			}
		}
		let stream = stream.ok_or(FetchError::Connect)?;
		let config = match trust {
			Trust::Chain => {
				let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().map_err(|_| FetchError::Tls)?.with_root_certificates(self.roots.clone()).with_no_client_auth();
				config.alpn_protocols = vec![b"http/1.1".to_vec()];
				config.enable_early_data = false;
				config
			}
			Trust::Pinned(pins) => veilway_transport::pin_only(pins, literal.is_none()).map_err(|_| FetchError::Pin)?,
		};
		let name = match literal {
			Some(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
			None => rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| FetchError::Tls)?,
		};
		let mut tls = TlsConnector::from(Arc::new(config)).connect(name, stream).await.map_err(|error| {
			if error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()).is_some_and(|inner| matches!(inner, rustls::Error::InvalidCertificate(_))) {if matches!(trust, Trust::Pinned(_)) {FetchError::Pin} else {FetchError::Certificate}} else if matches!(trust, Trust::Pinned(_)) && error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()).is_some_and(|inner| matches!(inner, rustls::Error::PeerIncompatible(_) | rustls::Error::PeerMisbehaved(_))) {FetchError::Pin} else {FetchError::Tls}
		})?;
		let text = url.as_str();
		let tail = &text[8 + url.host().len()..];
		let tail = tail.strip_prefix(':').map_or(tail, |rest| &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..]);
		let path = tail.split('#').next().filter(|path| !path.is_empty()).map(|path| if path.starts_with('/') {path.to_owned()} else {format!("/{path}")}).unwrap_or_else(|| "/".to_owned());
		let authority = if port == 443 {host} else {format!("{host}:{port}")};
		let request = match body {
			Some(body) => [format!("POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", body.len()).as_bytes(), body].concat(),
			None => format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").into_bytes(),
		};
		tls.write_all(&request).await.map_err(|_| FetchError::NotHttp)?;
		tls.flush().await.map_err(|_| FetchError::NotHttp)?;
		if body.is_some() {read_answer(&mut tls, BODY_MAX, started, |_| FETCH_TIMEOUT).await} else {read_answer(&mut tls, mirror::SIZES[4], started, mirror::time_limit).await}
	}
}

// Reads the head of an answer and its body, inside the bounds of the page: at most `limit` bytes of body, in the time `time` gives for the length the head names, counted from `started`.
async fn read_answer(io: &mut (impl AsyncRead + Unpin), limit: usize, started: Instant, time: fn(Option<usize>) -> Duration) -> Result<Vec<u8>, FetchError> {
	let mut buffer = Vec::new();
	let end = loop {
		if let Some(end) = http::end(&buffer) {break end}
		if buffer.len() >= http::HEAD_MAX {return Err(FetchError::NotHttp)}
		let mut chunk = [0u8; 4096];
		match io.read(&mut chunk[..(http::HEAD_MAX - buffer.len()).min(4096)]).await {
			Ok(0) | Err(_) => return Err(FetchError::NotHttp),
			Ok(count) => buffer.extend_from_slice(&chunk[..count]),
		}
	};
	let head = http::head(&buffer[..end]).ok_or(FetchError::NotHttp)?;
	if (300..400).contains(&head.status) {return Err(FetchError::Redirect)}
	if head.status != 200 {return Err(FetchError::Status(head.status))}
	if head.values("content-encoding").next().is_some() {return Err(FetchError::Encoding)}
	let (chunked, length) = (head.values("transfer-encoding").map(<[u8]>::to_vec).collect::<Vec<_>>(), head.values("content-length").map(<[u8]>::to_vec).collect::<Vec<_>>());
	let mut rest = buffer.split_off(end);
	if !chunked.is_empty() {
		if !length.is_empty() || chunked.len() != 1 || !chunked[0].eq_ignore_ascii_case(b"chunked") {return Err(FetchError::Body)}
		return timeout_at(started + time(None), unchunk(io, rest, limit)).await.unwrap_or(Err(FetchError::Timeout));
	}
	let wanted = match length.as_slice() {
		[] => None,
		[digits] if (1..=7).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit) => Some(digits.iter().fold(0usize, |number, digit| number * 10 + usize::from(digit - b'0'))),
		_ => return Err(FetchError::Body),
	};
	if wanted.is_some_and(|wanted| wanted > limit) {return Err(FetchError::Body)}
	let read = async {
		loop {
			if wanted.is_some_and(|wanted| rest.len() >= wanted) {break}
			if rest.len() > limit {return Err(FetchError::Body)}
			let mut chunk = [0u8; 8192];
			match io.read(&mut chunk).await {
				Ok(0) => break,
				Ok(count) => rest.extend_from_slice(&chunk[..count]),
				Err(_) => return Err(FetchError::NotHttp),
			}
		}
		Ok(())
	};
	timeout_at(started + time(wanted), read).await.unwrap_or(Err(FetchError::Timeout))?;
	// A length that was promised is the length that came, and a body with no length ends where the connection does.
	if wanted.is_some_and(|wanted| rest.len() != wanted) {return Err(FetchError::Body)}
	Ok(rest)
}

// The body of a chunked answer, as strictly as the page's reader of a head is: a size of plain hexadecimal digits, no extension, no trailer.
async fn unchunk(io: &mut (impl AsyncRead + Unpin), mut buffer: Vec<u8>, limit: usize) -> Result<Vec<u8>, FetchError> {
	let mut body = Vec::new();
	loop {
		let line = loop {
			if let Some(at) = buffer.windows(2).position(|pair| pair == b"\r\n") {break at}
			if buffer.len() > 16 {return Err(FetchError::Body)}
			let mut chunk = [0u8; 4096];
			match io.read(&mut chunk).await {
				Ok(0) | Err(_) => return Err(FetchError::NotHttp),
				Ok(count) => buffer.extend_from_slice(&chunk[..count]),
			}
		};
		let digits = &buffer[..line];
		if digits.is_empty() || digits.len() > 6 || !digits.iter().all(u8::is_ascii_hexdigit) {return Err(FetchError::Body)}
		let size = digits.iter().fold(0usize, |number, digit| number * 16 + (*digit as char).to_digit(16).unwrap_or(0) as usize);
		buffer.drain(..line + 2);
		if size == 0 {
			// Nothing but the last empty line may follow.
			while buffer.len() < 2 {
				let mut chunk = [0u8; 16];
				match io.read(&mut chunk).await {
					Ok(0) | Err(_) => return Err(FetchError::NotHttp),
					Ok(count) => buffer.extend_from_slice(&chunk[..count]),
				}
			}
			return if buffer == b"\r\n" {Ok(body)} else {Err(FetchError::Body)};
		}
		if body.len() + size > limit {return Err(FetchError::Body)}
		while buffer.len() < size + 2 {
			let mut chunk = [0u8; 8192];
			match io.read(&mut chunk).await {
				Ok(0) | Err(_) => return Err(FetchError::NotHttp),
				Ok(count) => buffer.extend_from_slice(&chunk[..count]),
			}
		}
		if &buffer[size..size + 2] != b"\r\n" {return Err(FetchError::Body)}
		body.extend_from_slice(&buffer[..size]);
		buffer.drain(..size + 2);
	}
}

/// Where the subscriptions the app holds are kept between runs. They hold the link with its token, the device's private key and secret, and the document with its transport secrets, so they belong in "the operating system's secret storage where the platform has one, and otherwise in a file encrypted under a key kept there". `FileVault` is the file without the encryption: it is mode 600 and nothing more, and the platform layer replaces it.
pub trait Vault: Send + Sync {
	fn load(&self) -> io::Result<Vec<Stored>>;
	fn save(&self, held: &[Stored]) -> io::Result<()>;
}

#[derive(Serialize, Deserialize)]
struct OriginWire {link: String, private: String, secret: String}

#[derive(Serialize, Deserialize)]
struct StoredWire {#[serde(default)] origin: Option<OriginWire>, keys: Vec<String>, document: String, #[serde(default)] hosts: Vec<String>, #[serde(default)] declined: Vec<String>, #[serde(default)] pins: Vec<String>, #[serde(default)] private: Vec<String>}

/// The most subscriptions a vault holds and the most it reads.
pub const HELD_MAX: usize = 64;
const VAULT_MAX: usize = 4 * BODY_MAX * 16;

fn array<const N: usize>(text: &str) -> Option<[u8; N]> {STANDARD.decode(text).ok()?.try_into().ok()}

fn from_wire(wire: StoredWire) -> Option<Stored> {
	let origin = match wire.origin {
		Some(origin) => Some((origin.link, Secret::new(array(&origin.private)?), DeviceSecret::new(array(&origin.secret)?))),
		None => None,
	};
	Some(Stored {origin, keys: wire.keys.iter().map(|key| array(key)).collect::<Option<Vec<_>>>()?, document: wire.document, hosts: wire.hosts, declined: wire.declined, pins: wire.pins.iter().map(|pin| array(pin)).collect::<Option<Vec<_>>>()?, private: wire.private.iter().filter_map(|address| address.parse().ok()).collect()})
}

/// Reads a vault file. A file that is not one is an error, and an entry that is not one is left out.
pub fn read_vault(bytes: &[u8]) -> io::Result<Vec<Stored>> {
	if bytes.len() > VAULT_MAX {return Err(io::Error::new(io::ErrorKind::InvalidData, "the file is larger than any vault"))}
	let wires: Vec<StoredWire> = serde_json::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	Ok(wires.into_iter().take(HELD_MAX).filter_map(from_wire).collect())
}

/// The bytes of a vault file.
pub fn write_vault(held: &[Stored]) -> Vec<u8> {
	let wires: Vec<StoredWire> = held.iter().take(HELD_MAX).map(|stored| StoredWire {origin: stored.origin.as_ref().map(|(link, private, secret)| OriginWire {link: link.clone(), private: STANDARD.encode(private.expose()), secret: STANDARD.encode(secret.expose())}), keys: stored.keys.iter().map(|key| STANDARD.encode(key)).collect(), document: stored.document.clone(), hosts: stored.hosts.clone(), declined: stored.declined.clone(), pins: stored.pins.iter().map(|pin| STANDARD.encode(pin)).collect(), private: stored.private.iter().map(ToString::to_string).collect()}).collect();
	serde_json::to_vec(&wires).unwrap_or_default()
}

/// A vault in one file, written whole and moved over the old one, with the link's token, the device's private key and the transport secrets in it as plain base64. Mode 600 is all that protects it. It is here for tests and for nothing that ships, and only with the `unencrypted-vault` feature: the platform layer supplies a `Vault` over the system's secret storage (Keychain, DPAPI or Credential Manager, the Android Keystore, the Secret Service), or one that encrypts `write_vault`'s bytes under a key kept in it.
#[cfg(any(test, feature = "unencrypted-vault"))]
pub struct FileVault(pub std::path::PathBuf);

#[cfg(any(test, feature = "unencrypted-vault"))]
impl Vault for FileVault {
	fn load(&self) -> io::Result<Vec<Stored>> {
		match crate::store::read_limited(&self.0, VAULT_MAX) {
			Ok(bytes) => read_vault(&bytes),
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
			Err(error) => Err(error),
		}
	}
	fn save(&self, held: &[Stored]) -> io::Result<()> {crate::store::write_atomic(&self.0, &write_vault(held))}
}

/// The subscriptions the app holds, and the vault they are kept in.
pub struct Library {vault: Box<dyn Vault>, held: Vec<Held>}

impl Library {
	/// Opens a vault. What it holds is read again by `Held::restore`, which verifies every document under the keys stored with it and reads it with today's reader. A subscription that does not read is returned beside the library, with what `Damaged` keeps of its link and device, and is not held.
	pub fn open(vault: Box<dyn Vault>) -> io::Result<(Self, Vec<Damaged>)> {
		let (mut held, mut damaged) = (Vec::new(), Vec::new());
		for stored in vault.load()? {
			match Held::restore(stored) {
				Ok(restored) => held.push(restored),
				Err(error) => damaged.push(error),
			}
		}
		Ok((Self {vault, held}, damaged))
	}
	pub fn held(&self) -> &[Held] {&self.held}
	pub fn held_mut(&mut self) -> &mut [Held] {&mut self.held}
	/// Writes the library to its vault.
	pub fn save(&self) -> io::Result<()> {self.vault.save(&self.held.iter().map(Held::stored).collect::<Vec<_>>())}
	/// Remembers the user's yes to `addresses` for the subscription at `at` and writes the library. On a failed write the yes is not kept.
	pub fn allow_private(&mut self, at: usize, addresses: &[IpAddr]) -> io::Result<()> {
		let Some(held) = self.held.get_mut(at) else {return Ok(())};
		let before = held.clone();
		held.allow_private(addresses);
		self.save().inspect_err(|_| self.held[at] = before)
	}
	/// The user's answer about the update hosts of the subscription at `at`, each in the form `Held::waiting` and `Held::confirmed` give: `allow` are confirmed, `decline` are declined or lose their yes. A host in both is declined. The library is written; on a failed write nothing is kept.
	pub fn answer_hosts(&mut self, at: usize, allow: &[&str], decline: &[&str]) -> io::Result<()> {
		let Some(held) = self.held.get_mut(at) else {return Ok(())};
		let before = held.clone();
		held.confirm_hosts(allow);
		held.decline_hosts(decline);
		self.save().inspect_err(|_| self.held[at] = before)
	}
	/// Removes a subscription, with its link, its key and its secret: "Removing a subscription in the app deletes its key, secret and link."
	pub fn remove(&mut self, id: &veilway_proto::subscription::payload::Id) -> io::Result<bool> {
		let before = self.held.len();
		self.held.retain(|held| held.id() != id);
		self.save()?;
		Ok(self.held.len() != before)
	}
}

/// The review of an answer, with the endpoint it came from, which `release` and `confirm` go back to.
pub struct Reviewed {pub review: Review, pub endpoint: Option<Url>, pub pins: Vec<[u8; 32]>, pub private: Vec<IpAddr>}

impl std::fmt::Debug for Reviewed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "Reviewed({:?})", self.review)}
}

/// Step 1: reads a text as a link. Nothing is sent, generated or stored. White space around a pasted text is cut off here, since the grammar reads a text exactly as it is.
pub fn open(text: &str) -> Result<Offer, ImportError> {
	let text = text.trim();
	if !text.starts_with("veilway://") && !text.starts_with("https://") {return Err(ImportError::NotALink)}
	match Link::parse(text).map(Offer::open).map_err(ImportError::Link)? {
		Offer::Legacy(_) => Err(ImportError::Legacy),
		offer => Ok(offer),
	}
}

/// Step 1 for the content of a file: `v1.<key>.<document>` and nothing else, bar one line end. A file is the only form that carries a document of any size, and it has no endpoint.
pub fn open_file(content: &[u8]) -> Result<Offer, ImportError> {Carried::file(content).map(|carried| Offer::open(Link::Carried(carried))).map_err(ImportError::File)}

/// The user's yes to a native link. `device` is the stored device when the import is of a link for a subscription the app holds, so that it takes no new place. The key and the secret of a new device are drawn here and not before.
pub fn proceed(offer: NativeOffer, device: Option<Device>) -> Result<Fetching, ImportError> {offer.proceed(device, &mut crate::random).map_err(|_| ImportError::Random)}

/// The user's yes to a whole document in a link or a file: there is nothing to fetch, and it is reviewed at once.
pub fn proceed_carried(offer: CarriedOffer, now: u64, library: &Library) -> Result<Reviewed, ImportError> {
	let stored: Vec<&Held> = library.held.iter().collect();
	offer.proceed(now, &stored).map(|review| Reviewed {review, endpoint: None, pins: Vec::new(), private: Vec::new()}).map_err(ImportError::Subscription)
}

impl Fetcher {
	/// Step 2 of a native import, after the user's yes: the one request with `op` `"fetch"`. A failure leaves the step as it was, to try again or to `abandon`.
	/// `allowed` is the private addresses the user said yes to for this import, as the question showed them, and nothing else: an app passes none the first time.
	pub async fn fetch(&self, fetching: &Fetching, library: &Library, now: u64, allowed: &[IpAddr]) -> Result<Reviewed, ImportError> {
		let body = self.post(fetching.endpoint(), &Trust::of(fetching.pins()), &fetching.request().body(), allowed).await?;
		let stored: Vec<&Held> = library.held.iter().collect();
		let review = fetching.answer(&body, now, &stored).map_err(ImportError::Subscription)?;
		// `confirm` and `release` go to the endpoint the way the review says it is checked, which is the document's list of pins when it has one.
		Ok(Reviewed {pins: review.pins().to_vec(), review, endpoint: Some(fetching.endpoint().clone()), private: allowed.to_vec()})
	}
	/// The import is given up after the request went out and before an answer could be reviewed: the `release` request frees the pending place. Best effort.
	pub async fn abandon(&self, fetching: Fetching, allowed: &[IpAddr]) {
		let (endpoint, trust) = (fetching.endpoint().clone(), Trust::of(fetching.pins()));
		let request = fetching.abandon();
		if let Err(error) = self.post(&endpoint, &trust, &request.body(), allowed).await {tracing::info!(?error, "the pending device place could not be released");}
	}
	/// Step 3, the user accepts. The subscription is stored first, so that the device key is not lost with a failed `confirm`, and then the place is made permanent. A rule that no longer allows it releases the place and stores nothing. A subscription that is stored and whose `confirm` did not go out is not an error: the next refresh enrols it again.
	pub async fn accept(&self, reviewed: Reviewed, name: Option<DeviceName>, library: &mut Library) -> Result<Accepted, ImportError> {
		let Reviewed {review, endpoint, pins, private} = reviewed;
		// A subscription beyond what a vault holds is refused here and not dropped when the vault is written: the place the device took is given back.
		if !review.replaces() && library.held.len() >= HELD_MAX {
			self.send(endpoint.as_ref(), &pins, review.decline(), &private).await;
			return Err(ImportError::Full);
		}
		let accepted = {
			let stored: Vec<&Held> = library.held.iter().collect();
			review.accept(name, &stored)
		};
		let mut accepted = match accepted {
			Ok(accepted) => accepted,
			Err(declined) => {
				let Declined {failure, release} = *declined;
				self.send(endpoint.as_ref(), &pins, release, &private).await;
				return Err(ImportError::Subscription(failure));
			}
		};
		accepted.held.allow_private(&private);
		let before = library.held.clone();
		match &accepted.replaces {
			Some(replaced) => {
				if let Some(at) = library.held.iter().position(|held| held.is(&replaced.id, &replaced.key)) {library.held[at] = accepted.held.clone()} else {library.held.push(accepted.held.clone())}
			}
			None => library.held.push(accepted.held.clone()),
		}
		// A subscription that could not be written is not held. Its pending device place lapses by itself, "or when the time in the table of numbers passes", since the request that frees it is not available once an import is accepted.
		if let Err(error) = library.save() {
			library.held = before;
			tracing::info!(?error, "the accepted subscription could not be saved");
			return Err(ImportError::Store(error));
		}
		// The pins the endpoint is held to now are the ones the accepted document names.
		let held_pins = accepted.held.targets().first().map(|(_, pins)| pins.to_vec()).unwrap_or(pins);
		self.send(endpoint.as_ref(), &held_pins, accepted.confirm.clone(), &private).await;
		Ok(accepted)
	}
	/// The user declines: the `release` request, and nothing kept.
	pub async fn decline(&self, reviewed: Reviewed) {
		let Reviewed {review, endpoint, pins, private} = reviewed;
		self.send(endpoint.as_ref(), &pins, review.decline(), &private).await;
	}
	// A request whose answer is not read: `confirm` and `release`. A failure is logged and is not the import's.
	async fn send(&self, endpoint: Option<&Url>, pins: &[[u8; 32]], request: Option<Request>, allowed: &[IpAddr]) {
		let (Some(endpoint), Some(request)) = (endpoint, request) else {return};
		if let Err(error) = self.post(endpoint, &Trust::of(pins), &request.body(), allowed).await {tracing::info!(?error, "a request of the import could not be sent");}
	}
	/// Refreshes the subscription at `at` and says where the answer came from. The caller decides when ("When a fetch happens"). See `Library::refresh_over` for the order and what ends a refresh.
	pub async fn refresh_from(&self, library: &mut Library, at: usize, now: u64) -> Result<(Refreshed, Source), RefreshFailed> {library.refresh_over(self, at, now).await}
	/// `refresh_from` for a caller that does not show where the answer came from.
	pub async fn refresh(&self, library: &mut Library, at: usize, now: u64) -> Result<Refreshed, ImportError> {self.refresh_from(library, at, now).await.map(|(refreshed, _)| refreshed).map_err(|failed| failed.error)}
}

/// What a refresh needs of the network: one `POST` to an endpoint and one `GET` of a static file. `Fetcher` is the one that ships, and a test puts its own in.
#[allow(async_fn_in_trait)]
pub trait Wire {
	async fn post(&self, url: &Url, trust: &Trust, body: &[u8], allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError>;
	async fn get(&self, url: &Url, allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError>;
}

impl Wire for Fetcher {
	async fn post(&self, url: &Url, trust: &Trust, body: &[u8], allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError> {Fetcher::post(self, url, trust, body, allowed).await}
	async fn get(&self, url: &Url, allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError> {Fetcher::get(self, url, allowed).await}
}

/// Why a refresh failed, for the app to show: the reason the places before the static mirrors failed, which is the one a static mirror never replaces, and how many static mirrors were asked. When that is more than none, "no mirror had a newer document" is shown beside the reason.
#[derive(Debug)]
pub struct RefreshFailed {pub error: ImportError, pub static_asked: usize}

impl From<ImportError> for RefreshFailed {
	fn from(error: ImportError) -> Self {Self {error, static_asked: 0}}
}

impl Library {
	/// Refreshes the subscription at `at` through `wire`, trying the places in the order of "Order and rate": the endpoint of its link, then the confirmed `refresh_urls` in the document's order, then the confirmed static mirrors. A subscription that came as a whole document cannot refresh.
	/// The refresh ends at the first accepted answer from the endpoint or a relay mirror (a newer document or the same bytes again), at a newer document from a static mirror, or at a signed refusal that verifies, wherever it came from. Everything else is a failure of that place and the next is tried: from a static mirror that includes the held document again ("this mirror has nothing newer", no successful refresh), an older one, a 404 and a file that does not open, none of which is a revocation. The reason of a failed refresh is the endpoint's (the last place before the static mirrors), and a static mirror changes it only to ask about a private address.
	pub async fn refresh_over(&mut self, wire: &impl Wire, at: usize, now: u64) -> Result<(Refreshed, Source), RefreshFailed> {
		let Some(held) = self.held.get(at) else {return Err(ImportError::Subscription(Failure::HasLink).into())};
		let (Some(request), targets) = (held.fetch(), held.targets().into_iter().map(|(url, pins)| (url.clone(), pins.to_vec())).collect::<Vec<_>>()) else {return Err(ImportError::Legacy.into())};
		let (mut last, allowed) = (ImportError::Fetch(FetchError::Connect), self.held[at].private_addresses().to_vec());
		for (place, (endpoint, pins)) in targets.into_iter().enumerate() {
			match wire.post(&endpoint, &Trust::of(&pins), &request.body(), &allowed).await {
				Ok(body) => match self.held[at].refresh(&body, now) {
					Ok(refreshed) => {
						self.save().map_err(ImportError::Store)?;
						return Ok((refreshed, if place == 0 {Source::Endpoint} else {Source::Relay}));
					}
					Err(Failure::Refused(reason)) => return Err(ImportError::Subscription(Failure::Refused(reason)).into()),
					Err(failure) => last = ImportError::Subscription(failure),
				},
				// A question that waits for the user is not hidden by a later endpoint that only failed.
				Err(error) => if !matches!(last, ImportError::PrivateEndpoint {..}) {last = error.into()},
			}
		}
		let mut asked = 0;
		for target in self.held[at].static_targets(now) {
			asked += 1;
			match wire.get(target.url(), &allowed).await {
				Ok(body) => match self.held[at].refresh_static(&target, &body, now) {
					Ok(Refreshed::Updated(changes)) => {
						self.save().map_err(ImportError::Store)?;
						return Ok((Refreshed::Updated(changes), Source::Static));
					}
					Err(Failure::Refused(reason)) => return Err(RefreshFailed {error: ImportError::Subscription(Failure::Refused(reason)), static_asked: asked}),
					Ok(Refreshed::Unchanged) | Err(_) => {}
				},
				Err(error @ FetchError::Private {..}) => if !matches!(last, ImportError::PrivateEndpoint {..}) {last = error.into()},
				Err(_) => {}
			}
		}
		Err(RefreshFailed {error: last, static_asked: asked})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		// The vault is read from a disk anyone with the device can write to: whatever it holds, reading it is an answer and never a panic, and what is read is what a vault may hold.
		#[test]
		fn no_bytes_make_the_vault_reader_panic_or_give_more_than_a_vault_holds(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
			if let Ok(held) = read_vault(&bytes) {prop_assert!(held.len() <= HELD_MAX)}
		}

		#[test]
		fn an_entry_that_is_written_reads_back_as_it_was(link in "[a-z0-9:/.#-]{0,40}", document in "[A-Za-z0-9._-]{0,60}", key in any::<[u8; 32]>(), secret in any::<[u8; 16]>(), host in "[a-z0-9.]{1,20}:[0-9]{1,5}") {
			let stored = Stored {origin: Some((link.clone(), Secret::new(key), DeviceSecret::new(secret))), keys: vec![key], document: document.clone(), hosts: vec![host.clone()], declined: vec![host.clone()], pins: vec![key], private: vec!["192.168.1.20".parse().unwrap()]};
			let read = read_vault(&write_vault(&[stored])).unwrap();
			prop_assert_eq!(read.len(), 1);
			prop_assert!(read[0].private == vec!["192.168.1.20".parse::<IpAddr>().unwrap()] && read[0].keys == vec![key] && read[0].pins == vec![key] && read[0].document == document && read[0].hosts == vec![host.clone()] && read[0].declined == vec![host] && read[0].origin.as_ref().is_some_and(|(found, private, device)| *found == link && private.expose() == &key && device.expose() == &secret));
		}
	}

	#[test]
	fn a_vault_that_is_not_one_is_an_error_and_an_entry_that_is_not_one_is_left_out() {
		for bytes in [&b""[..], b"{}", b"[1]", b"[{\"keys\": 5}]", b"\xff"] {assert!(read_vault(bytes).is_err(), "{:?}", String::from_utf8_lossy(bytes))}
		let good = write_vault(&[Stored {origin: None, keys: vec![[3; 32]], document: "d".into(), hosts: Vec::new(), declined: Vec::new(), pins: vec![[5; 32]], private: Vec::new()}]);
		assert_eq!(read_vault(&good).unwrap().len(), 1);
		let text = String::from_utf8(good).unwrap().replace(&STANDARD.encode([3u8; 32]), "not base64");
		assert!(read_vault(text.as_bytes()).unwrap().is_empty());
		assert!(read_vault(&vec![b' '; VAULT_MAX + 1]).is_err());
	}

	#[test]
	fn a_vault_from_before_the_private_yes_loads_with_no_yes_and_a_bad_address_is_left_out() {
		let old = br#"[{"keys": [], "document": "d", "hosts": [], "pins": []}]"#;
		assert!(read_vault(old).unwrap()[0].private.is_empty());
		let text = String::from_utf8(old.to_vec()).unwrap().replace("\"pins\": []", "\"pins\": [], \"private\": [\"10.0.0.5\", \"not an address\", \"fd00::5\", 7]");
		assert!(read_vault(text.as_bytes()).is_err());
		let text = text.replace(", 7]", "]");
		assert_eq!(read_vault(text.as_bytes()).unwrap()[0].private, ["10.0.0.5".parse::<IpAddr>().unwrap(), "fd00::5".parse().unwrap()]);
	}

	fn post(fetcher: &Fetcher, url: &str, allowed: &[IpAddr]) -> Result<Vec<u8>, FetchError> {
		let url = Url::pinned(url, 200, true, false).unwrap();
		tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
			// With a yes the dial goes on to the network, which a test does not wait for: all it needs to know is that the answer is no question.
			timeout(std::time::Duration::from_secs(2), fetcher.post(&url, &Trust::Chain, b"{}", allowed)).await.unwrap_or(Err(FetchError::Timeout))
		})
	}

	// A resolver that applies the refusals the way the system's does.
	fn named(addresses: &'static [&'static str]) -> Fetcher {
		let mut fetcher = Fetcher::new(Arc::new(rustls::RootCertStore::empty()), None);
		fetcher.resolve = Arc::new(move |_, port| Box::pin(async move {Ok(addresses.iter().map(|address| SocketAddr::new(address.parse().unwrap(), port)).filter(|address| dialable(address.ip())).collect())}));
		fetcher
	}

	fn ip(text: &str) -> IpAddr {text.parse().unwrap()}

	#[test]
	fn a_private_endpoint_asks_and_nothing_is_sent_before_the_yes() {
		let fetcher = Fetcher::new(Arc::new(rustls::RootCertStore::empty()), None);
		let asked = FetchError::Private {host: "192.168.1.20".into(), addresses: vec![ip("192.168.1.20")]};
		assert_eq!(post(&fetcher, "https://192.168.1.20/s", &[]), Err(asked.clone()));
		let ImportError::PrivateEndpoint {host, addresses} = ImportError::from(asked) else {panic!("a question")};
		assert_eq!((host.as_str(), addresses), ("192.168.1.20", vec![ip("192.168.1.20")]));
		for literal in ["https://10.1.2.3:8443/s", "https://[fd00::20]/s", "https://100.64.0.9/s"] {assert!(matches!(post(&fetcher, literal, &[]), Err(FetchError::Private {..})), "{literal}")}
		// A name asks too, with every private address it gave (and the ones that are refused left out).
		let fetcher = named(&["10.0.0.5", "127.0.0.1", "169.254.169.254", "10.0.0.6", "10.0.0.5"]);
		assert_eq!(post(&fetcher, "https://home.example.com/s", &[]), Err(FetchError::Private {host: "home.example.com".into(), addresses: vec![ip("10.0.0.5"), ip("10.0.0.6")]}));
	}

	#[test]
	fn what_may_never_be_dialled_is_refused_with_no_question_even_with_a_yes() {
		// A link cannot even name such an address, and the system's resolver drops it from any answer. A yes has no way in: `allowed` is only asked about addresses that are private.
		let resolve = system_resolver();
		let run = |host: &str| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(resolve(host.to_owned(), 443));
		for refused in ["127.0.0.1", "169.254.169.254", "169.254.1.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "::", "ff02::1", "::ffff:192.168.1.20", "64:ff9b::c0a8:114", "2002:c0a8:114::1"] {
			let literal = if refused.contains(':') {format!("https://[{refused}]/s")} else {format!("https://{refused}/s")};
			assert!(Url::pinned(&literal, 200, true, false).is_none(), "{refused}");
			assert_eq!(run(refused).map_err(|error| error.kind()), Err(io::ErrorKind::PermissionDenied), "{refused}");
		}
		assert_eq!(run("192.168.1.20").unwrap(), vec![SocketAddr::new(ip("192.168.1.20"), 443)]);
		// Private beside a refused address asks for the private one only.
		assert!(matches!(post(&named(&["169.254.169.254", "192.168.1.20"]), "https://a.example.com/s", &[]), Err(FetchError::Private {addresses, ..}) if addresses == [ip("192.168.1.20")]));
	}

	#[test]
	fn the_yes_is_to_the_addresses_shown_and_a_different_private_address_asks_again() {
		let yes = [ip("192.168.1.20")];
		assert!(!matches!(post(&Fetcher::new(Arc::new(rustls::RootCertStore::empty()), None), "https://192.168.1.20/s", &yes), Err(FetchError::Private {..} | FetchError::Resolve)));
		assert!(matches!(post(&Fetcher::new(Arc::new(rustls::RootCertStore::empty()), None), "https://192.168.1.21/s", &yes), Err(FetchError::Private {addresses, ..}) if addresses == [ip("192.168.1.21")]));
		// The host name carries no yes: the same name that now comes to another private address is asked about again.
		assert!(!matches!(post(&named(&["192.168.1.20"]), "https://home.example.com/s", &yes), Err(FetchError::Private {..} | FetchError::Resolve)));
		assert!(matches!(post(&named(&["192.168.1.99"]), "https://home.example.com/s", &yes), Err(FetchError::Private {addresses, ..}) if addresses == [ip("192.168.1.99")]));
		assert!(matches!(post(&named(&["192.168.1.20", "192.168.1.99"]), "https://home.example.com/s", &[ip("192.168.1.99")]), Ok(_) | Err(FetchError::Connect | FetchError::Timeout | FetchError::Tls | FetchError::NotHttp)));
	}

	#[test]
	fn a_chunked_body_is_read_as_strictly_as_a_head_is() {
		let run = |bytes: &[u8]| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
			let (mut near, mut far) = tokio::io::duplex(1 << 16);
			far.write_all(bytes).await.unwrap();
			drop(far);
			unchunk(&mut near, Vec::new(), BODY_MAX).await
		});
		assert_eq!(run(b"5\r\nhello\r\n0\r\n\r\n"), Ok(b"hello".to_vec()));
		assert_eq!(run(b"2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n"), Ok(b"abcde".to_vec()));
		// An extension, a size that is no hexadecimal, a trailer, a missing end and a body over its limit.
		for bytes in [&b"5;x=1\r\nhello\r\n0\r\n\r\n"[..], b"zz\r\nhello\r\n0\r\n\r\n", b"5\r\nhello\r\n0\r\nTrailer: x\r\n\r\n", b"5\r\nhello\r\n", b"5\r\nhelloXX0\r\n\r\n", b"fffffff\r\n"] {assert!(run(bytes).is_err(), "{:?}", String::from_utf8_lossy(bytes))}
	}

	#[test]
	fn every_failure_has_a_code_and_words_of_its_own() {
		let cases = [
			(ImportError::NotALink, Code::NotALink),
			(ImportError::Link(LinkError::Form), Code::LinkDamaged),
			(ImportError::Link(LinkError::Key), Code::LinkDamaged),
			(ImportError::Link(LinkError::Size), Code::LinkTooLong),
			(ImportError::File(LinkError::Form), Code::NotAFile),
			(ImportError::File(LinkError::Size), Code::FileTooLarge),
			(ImportError::Legacy, Code::Legacy),
			(ImportError::Fetch(FetchError::Resolve), Code::Resolve),
			(ImportError::Fetch(FetchError::Connect), Code::Unreachable),
			(ImportError::Fetch(FetchError::Timeout), Code::Timeout),
			(ImportError::Fetch(FetchError::Certificate), Code::Certificate),
			(ImportError::Fetch(FetchError::Tls), Code::Tls),
			(ImportError::Fetch(FetchError::Pin), Code::Pin),
			(ImportError::Fetch(FetchError::NotHttp), Code::NoSubscription),
			(ImportError::Fetch(FetchError::Status(404)), Code::NoSubscription),
			(ImportError::Fetch(FetchError::Body), Code::NoSubscription),
			(ImportError::PrivateEndpoint {host: "192.168.1.20".into(), addresses: Vec::new()}, Code::PrivateAddress),
			(ImportError::Random, Code::Random),
			(ImportError::Store(io::Error::other("the keychain refused")), Code::Store),
			(ImportError::Full, Code::Full),
			(ImportError::Subscription(Failure::Refused(Reason::DeviceLimit)), Code::DeviceLimit),
			(ImportError::Subscription(Failure::Refused(Reason::Disabled)), Code::AccountDisabled),
			(ImportError::Subscription(Failure::Refused(Reason::Expired)), Code::AccountExpired),
			(ImportError::Subscription(Failure::Refused(Reason::RateLimited)), Code::RateLimited),
			(ImportError::Subscription(Failure::Refused(Reason::DeviceMismatch)), Code::DeviceMismatch),
			(ImportError::Subscription(Failure::Refused(Reason::KeyRetired)), Code::KeyRetired),
			(ImportError::Subscription(Failure::Refused(Reason::BadRequest)), Code::BadRequest),
			(ImportError::Subscription(Failure::Envelope(EnvelopeError::UnknownKey)), Code::Signature),
			(ImportError::Subscription(Failure::Envelope(EnvelopeError::Signature)), Code::Signature),
			(ImportError::Subscription(Failure::Envelope(EnvelopeError::Encoding)), Code::BadAnswer),
			(ImportError::Subscription(Failure::Payload(PayloadError::Version)), Code::UpdateApp),
			(ImportError::Subscription(Failure::Payload(PayloadError::Object)), Code::BadDocument),
			(ImportError::Subscription(Failure::StaleRefusal), Code::StaleRefusal),
			(ImportError::Subscription(Failure::OtherSubscription), Code::OtherSubscription),
			(ImportError::Subscription(Failure::Rollback), Code::Older),
			(ImportError::Subscription(Failure::Backdated), Code::Older),
			(ImportError::Subscription(Failure::NotNewer), Code::Older),
			(ImportError::Subscription(Failure::Fork), Code::Different),
			(ImportError::Subscription(Failure::Expired), Code::Expired),
			(ImportError::Subscription(Failure::Future), Code::Clock),
			(ImportError::Subscription(Failure::PrivateKey), Code::DeviceKey),
			(ImportError::Subscription(Failure::HasLink), Code::HasLink),
			(ImportError::Subscription(Failure::Pins), Code::EndpointChanged),
		];
		for (error, code) in &cases {
			assert_eq!(error.code(), *code, "{error:?}");
			assert!(!error.text().is_empty() && error.text() == code.text(), "{error:?}");
		}
		let codes: std::collections::HashSet<&str> = cases.iter().map(|(_, code)| code.as_str()).collect();
		assert_eq!(codes.len(), 37);
	}

	#[test]
	fn the_link_that_is_not_one_and_the_file_that_is_not_one_are_told_apart() {
		assert_eq!(open("http://example.com/list").err().map(|error| error.code()), Some(Code::NotALink));
		assert_eq!(open("  ftp://example.com/list").err().map(|error| error.code()), Some(Code::NotALink));
		assert_eq!(open("veilway://sub/sub.example.com/s#short").err().map(|error| error.code()), Some(Code::LinkDamaged));
		assert_eq!(open_file(b"hello").err().map(|error| error.code()), Some(Code::NotAFile));
		assert_eq!(open_file(&vec![b'a'; BODY_MAX + 100]).err().map(|error| error.code()), Some(Code::FileTooLarge));
	}

	const BASE: &str = "https://files.example.net/vw/";
	const OTHER: &str = "https://cdn.example.org/a/";
	// 100 s after the documents of vectors.py were issued.
	const NOW: u64 = 1_700_000_100;

	fn corpus(name: &str) -> Vec<u8> {std::fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

	fn pair() -> ring::signature::Ed25519KeyPair {ring::signature::Ed25519KeyPair::from_seed_unchecked(&[0x11; 32]).unwrap()}

	fn sign(payload: &serde_json::Value) -> String {
		let key = veilway_proto::subscription::envelope::SigningKey::new(ring::signature::KeyPair::public_key(&pair()).as_ref().try_into().unwrap()).unwrap();
		veilway_proto::subscription::envelope::seal(&key, &serde_json::to_vec(payload).unwrap(), |signed| pair().sign(signed).as_ref().try_into().unwrap())
	}

	// The document of vectors.py at `serial`, listing a relay mirror and two static mirrors.
	fn listed(serial: u64) -> String {
		let key = veilway_proto::subscription::envelope::SigningKey::new(ring::signature::KeyPair::public_key(&pair()).as_ref().try_into().unwrap()).unwrap();
		let mut payload: serde_json::Value = serde_json::from_slice(veilway_proto::subscription::envelope::verify(&corpus("fuzz_sub_envelope/document")[1..], &[key], BODY_MAX).unwrap().payload()).unwrap();
		payload["serial"] = serial.into();
		payload["refresh_urls"] = serde_json::json!(["https://relay.example.net/s"]);
		payload["static_mirrors"] = serde_json::json!([BASE, OTHER]);
		sign(&payload)
	}

	fn disabled() -> String {sign(&serde_json::json!({"v": 1, "subscription_id": "example-account-0001", "issued_at": NOW - 10, "refusal": "disabled"}))}

	fn native() -> Link {Link::parse(&String::from_utf8(corpus("fuzz_deeplink/native-veilway")).unwrap()).unwrap()}

	// The client of vectors.py: device key 33..33 and device secret 44..44.
	fn fixed(bytes: &mut [u8]) -> Result<(), veilway_proto::NoRandom> {
		bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
		Ok(())
	}

	fn imported() -> Held {
		let Offer::Native(offer) = Offer::open(native()) else {panic!("a native link")};
		offer.proceed(None, &mut fixed).unwrap().answer(listed(1).as_bytes(), NOW, &[]).unwrap().accept(None, &[]).unwrap().held
	}

	fn library(name: &str, held: Held) -> Library {
		let path = std::env::temp_dir().join(format!("veilway-static-{name}-{}", std::process::id()));
		let _ = std::fs::remove_file(&path);
		let (mut library, _) = Library::open(Box::new(FileVault(path))).unwrap();
		library.held.push(held);
		library
	}

	// The file a panel writes for `document` on the static mirror of `base`, in the period of `NOW`.
	fn file(base: &str, document: &str) -> Vec<u8> {
		let Link::Native(link) = native() else {panic!("a native link")};
		let keys = veilway_proto::keys::MirrorKeys::derive(link.token().expose(), &[0x44; 16], &veilway_proto::proof::public_key(&[0x33; 32]));
		mirror::seal(&keys, base, mirror::epoch(NOW), mirror::size_for(document.len()).unwrap(), document.as_bytes(), &mut |bytes: &mut [u8]| {bytes.fill(7); Ok(())}).unwrap()
	}

	// A network of canned answers by method and host, that remembers what it was asked and in which order.
	struct Fake {answers: std::collections::HashMap<String, Result<Vec<u8>, FetchError>>, asked: std::sync::Mutex<Vec<String>>}

	impl Fake {
		fn new(answers: Vec<(&str, Result<Vec<u8>, FetchError>)>) -> Self {Self {answers: answers.into_iter().map(|(place, answer)| (place.to_owned(), answer)).collect(), asked: Default::default()}}
		fn answer(&self, method: &str, url: &Url) -> Result<Vec<u8>, FetchError> {
			let place = format!("{method} {}", url.host());
			self.asked.lock().unwrap().push(place.clone());
			self.answers.get(&place).cloned().unwrap_or(Err(FetchError::Connect))
		}
		fn asked(&self) -> Vec<String> {self.asked.lock().unwrap().clone()}
	}

	impl Wire for Fake {
		async fn post(&self, url: &Url, _: &Trust, _: &[u8], _: &[IpAddr]) -> Result<Vec<u8>, FetchError> {self.answer("POST", url)}
		async fn get(&self, url: &Url, _: &[IpAddr]) -> Result<Vec<u8>, FetchError> {self.answer("GET", url)}
	}

	fn run(library: &mut Library, fake: &Fake) -> Result<(Refreshed, Source), RefreshFailed> {tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(library.refresh_over(fake, 0, NOW))}

	fn ok(document: String) -> Result<Vec<u8>, FetchError> {Ok(document.into_bytes())}

	#[test]
	fn the_endpoint_comes_first_then_the_relay_mirrors_and_a_static_mirror_only_after_both_failed() {
		let mut library = library("order", imported());
		let fake = Fake::new(vec![("POST sub.example.com", ok(listed(2)))]);
		assert!(matches!(run(&mut library, &fake), Ok((Refreshed::Updated(_), Source::Endpoint))));
		assert_eq!(fake.asked(), ["POST sub.example.com"]);
		let mut library = self::library("order", imported());
		let fake = Fake::new(vec![("POST sub.example.com", Err(FetchError::Connect)), ("POST relay.example.net", ok(listed(2)))]);
		assert!(matches!(run(&mut library, &fake), Ok((Refreshed::Updated(_), Source::Relay))));
		assert_eq!(fake.asked(), ["POST sub.example.com", "POST relay.example.net"]);
		let mut library = self::library("order", imported());
		let fake = Fake::new(vec![("POST sub.example.com", Err(FetchError::Timeout)), ("POST relay.example.net", Err(FetchError::Status(500))), ("GET files.example.net", Ok(file(BASE, &listed(2))))]);
		assert!(matches!(run(&mut library, &fake), Ok((Refreshed::Updated(_), Source::Static))));
		assert_eq!(fake.asked(), ["POST sub.example.com", "POST relay.example.net", "GET files.example.net"]);
		assert_eq!(library.held[0].document(), listed(2));
		assert_eq!(read_vault(&write_vault(&library.held.iter().map(Held::stored).collect::<Vec<_>>())).unwrap()[0].document, listed(2));
		// The same bytes from the relay again are a successful refresh, and no static mirror is asked.
		let mut library = self::library("order", imported());
		let fake = Fake::new(vec![("POST sub.example.com", Err(FetchError::Connect)), ("POST relay.example.net", ok(listed(1)))]);
		assert!(matches!(run(&mut library, &fake), Ok((Refreshed::Unchanged, Source::Relay))));
		assert_eq!(fake.asked().len(), 2);
	}

	#[test]
	fn a_static_answer_that_is_not_a_newer_document_is_no_refresh_and_keeps_the_reason_of_the_endpoint() {
		let down = || vec![("POST sub.example.com", Err(FetchError::Timeout)), ("POST relay.example.net", Err(FetchError::Timeout))];
		// The held document again, from both mirrors: nothing newer, the endpoint's reason, and nothing changed.
		let mut library = library("nothing-newer", imported());
		let fake = Fake::new([down(), vec![("GET files.example.net", Ok(file(BASE, &listed(1)))), ("GET cdn.example.org", Ok(file(OTHER, &listed(1))))]].concat());
		let Err(failed) = run(&mut library, &fake) else {panic!("a refresh that failed")};
		assert_eq!((failed.error.code(), failed.static_asked, fake.asked().len()), (Code::Timeout, 2, 4));
		assert_eq!(library.held[0].document(), listed(1));
		// A missing file, a stale cache, a file of the wrong size, one that does not open and one with a bad signature are each a failure of that mirror: nothing is removed, and the endpoint's reason stands.
		let mut library = self::library("nothing-newer", imported());
		let bad = Fake::new([down(), vec![("GET files.example.net", Err(FetchError::Status(404))), ("GET cdn.example.org", Ok(file(OTHER, &listed(0))))]].concat());
		let Err(failed) = run(&mut library, &bad) else {panic!("a refresh that failed")};
		assert_eq!((failed.error.code(), failed.static_asked, library.held.len(), library.held[0].document() == listed(1)), (Code::Timeout, 2, 1, true));
		for body in [vec![0; 9_413], vec![0; 100], Vec::new(), file(BASE, &listed(2))[1..].to_vec(), file(OTHER, &listed(2))] {
			let fake = Fake::new([down(), vec![("GET files.example.net", Ok(body))]].concat());
			assert!(matches!(run(&mut library, &fake), Err(RefreshFailed {static_asked: 2, ..})));
			assert_eq!(library.held[0].document(), listed(1));
		}
		// The first mirror has nothing newer and the second does: the remaining mirrors are tried.
		let fake = Fake::new([down(), vec![("GET files.example.net", Ok(file(BASE, &listed(1)))), ("GET cdn.example.org", Ok(file(OTHER, &listed(2))))]].concat());
		assert!(matches!(run(&mut library, &fake), Ok((Refreshed::Updated(_), Source::Static))));
		assert_eq!(fake.asked().len(), 4);
		assert_eq!(library.held[0].document(), listed(2));
	}

	#[test]
	fn a_signed_refusal_ends_the_refresh_from_wherever_it_comes_and_nothing_else_does() {
		let mut library = library("refusal", imported());
		let fake = Fake::new(vec![("POST sub.example.com", ok(disabled())), ("POST relay.example.net", ok(listed(2))), ("GET files.example.net", Ok(file(BASE, &listed(2))))]);
		let Err(failed) = run(&mut library, &fake) else {panic!("a refusal")};
		assert_eq!((failed.error.code(), failed.static_asked, fake.asked()), (Code::AccountDisabled, 0, vec!["POST sub.example.com".to_owned()]));
		let fake = Fake::new(vec![("POST sub.example.com", Err(FetchError::Connect)), ("POST relay.example.net", Err(FetchError::Connect)), ("GET files.example.net", Ok(file(BASE, &disabled()))), ("GET cdn.example.org", Ok(file(OTHER, &listed(2))))]);
		let Err(failed) = run(&mut library, &fake) else {panic!("a refusal")};
		assert_eq!((failed.error.code(), failed.static_asked, fake.asked().len()), (Code::AccountDisabled, 1, 3));
		// A refusal is not stored as a document: what was held is held.
		assert_eq!(library.held[0].document(), listed(1));
	}

	#[test]
	fn a_static_mirror_the_user_has_not_confirmed_is_never_asked() {
		let mut stored = imported().stored();
		stored.hosts.clear();
		let mut library = library("unconfirmed", Held::restore(stored).unwrap());
		let fake = Fake::new(vec![("POST sub.example.com", Err(FetchError::Connect)), ("GET files.example.net", Ok(file(BASE, &listed(2))))]);
		let Err(failed) = run(&mut library, &fake) else {panic!("a refresh that failed")};
		assert_eq!((failed.static_asked, fake.asked()), (0, vec!["POST sub.example.com".to_owned()]));
	}

	#[test]
	fn a_no_or_a_yes_taken_back_is_saved_and_the_host_is_never_asked() {
		let mut library = library("declined", imported());
		let hosts = library.held[0].confirmed().to_vec();
		let refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
		library.answer_hosts(0, &[], &refs).unwrap();
		let fake = Fake::new(vec![("POST sub.example.com", Err(FetchError::Connect)), ("POST relay.example.net", ok(listed(2))), ("GET files.example.net", Ok(file(BASE, &listed(2))))]);
		let Err(failed) = run(&mut library, &fake) else {panic!("a refresh that failed")};
		assert_eq!((failed.static_asked, fake.asked()), (0, vec!["POST sub.example.com".to_owned()]));
		let (mut reopened, _) = Library::open(Box::new(FileVault(std::env::temp_dir().join(format!("veilway-static-declined-{}", std::process::id()))))).unwrap();
		assert_eq!((reopened.held[0].declined().len(), reopened.held[0].waiting().len(), reopened.held[0].confirmed().len()), (hosts.len(), 0, 0));
		reopened.answer_hosts(0, &refs[..1], &[]).unwrap();
		assert_eq!((reopened.held[0].confirmed(), reopened.held[0].declined().len()), (&hosts[..1], hosts.len() - 1));
	}

	#[test]
	fn a_whole_document_has_nothing_to_refresh_by() {
		let content: serde_json::Value = serde_json::from_slice(&corpus("fuzz_subscription/content")[1..]).unwrap();
		let Offer::Carried(offer) = Offer::open(Link::Carried(Carried::file(format!("v1.{}.{}", &String::from_utf8(corpus("fuzz_deeplink/file")).unwrap()[3..46], sign(&content)).as_bytes()).unwrap())) else {panic!("a document in a file")};
		let mut library = library("whole", offer.proceed(NOW, &[]).unwrap().accept(None, &[]).unwrap().held);
		let fake = Fake::new(Vec::new());
		assert!(matches!(run(&mut library, &fake), Err(RefreshFailed {error: ImportError::Legacy, static_asked: 0})) && fake.asked().is_empty());
	}

	#[test]
	fn the_source_of_a_refresh_has_a_code_of_its_own() {
		assert_eq!([Source::Endpoint, Source::Relay, Source::Static].map(Source::as_str), ["endpoint", "relay", "static"]);
	}

	async fn answer(head: &str, body: &[u8], limit: usize, time: fn(Option<usize>) -> Duration) -> Result<Vec<u8>, FetchError> {
		let (mut near, mut far) = tokio::io::duplex(1 << 21);
		far.write_all(head.as_bytes()).await.unwrap();
		far.write_all(body).await.unwrap();
		let held_open = far;
		let read = read_answer(&mut near, limit, Instant::now(), time).await;
		drop(held_open);
		read
	}

	#[test]
	fn a_static_answer_is_read_to_its_own_limit_in_the_time_of_its_size() {
		let run = |head: &str, body: &[u8]| tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap().block_on(answer(head, body, mirror::SIZES[4], mirror::time_limit));
		let largest = vec![5; mirror::SIZES[4]];
		assert_eq!(run("HTTP/1.1 200 OK\r\nContent-Length: 1089437\r\n\r\n", &largest).map(|body| body.len()), Ok(1_089_437));
		assert_eq!(run("HTTP/1.1 200 OK\r\nContent-Length: 1089438\r\n\r\n", &largest), Err(FetchError::Body));
		assert_eq!(run("HTTP/1.1 200 OK\r\nContent-Length: 9413\r\n\r\n", &largest[..9_413]).map(|body| body.len()), Ok(9_413));
		assert_eq!(run("HTTP/1.1 200 OK\r\nContent-Length: 9413\r\n\r\n", &largest[..9_414]), Err(FetchError::Body));
		assert_eq!(run("HTTP/1.1 200 OK\r\nContent-Length: 9413\r\n\r\n", &largest[..9_000]), Err(FetchError::Timeout));
		assert_eq!(run("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", b""), Err(FetchError::Status(404)));
		assert_eq!(run("HTTP/1.1 301 Moved\r\nLocation: https://elsewhere.example/\r\n\r\n", b""), Err(FetchError::Redirect));
		assert_eq!(run("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 9413\r\n\r\n", &largest[..9_413]), Err(FetchError::Encoding));
		// Without a length the body ends where the connection does, and is cut at the limit.
		assert_eq!(run("HTTP/1.1 200 OK\r\n\r\n", &vec![1; 1_089_438]), Err(FetchError::Body));
	}

	#[test]
	fn the_time_allowed_follows_the_size_the_length_names() {
		for (length, seconds) in [("9413", 30), ("36979", 30), ("140867", 60), ("538201", 120), ("1089437", 240), ("1000", 240)] {
			let runtime = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().unwrap();
			let (read, waited) = runtime.block_on(async {
				let started = Instant::now();
				(answer(&format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n"), b"", mirror::SIZES[4], mirror::time_limit).await, started.elapsed().as_secs())
			});
			assert_eq!((read, waited), (Err(FetchError::Timeout), seconds), "{length}");
		}
	}
}
