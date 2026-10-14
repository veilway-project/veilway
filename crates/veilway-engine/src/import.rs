//! Subscription import as a library flow (subscription format page, "Import" and "Fetching"): a link, the user's first yes, the fetch, the confirmation, and the storing, and the refresh of what is stored.
//!
//! The rules the types of `veilway-proto` carry are not repeated or bypassed here. A link becomes an `Offer`, which can do nothing; the only way on is `NativeOffer::proceed`, the user's yes, and only then a request can exist. An answer becomes a `Review` only through the checks of `client`, and is kept only after `Review::accept`. What this module adds is the part with a network and a disk: one `POST` over `https` with the rules of "How a fetch is made", and a place to keep what was accepted.
//!
//! The rules of the fetch: `https` only; the chain validated against the roots it is given, TLS 1.2 or later, and no early data; no redirect followed; no `Accept-Language`, `Accept-Encoding: identity` and an answer with a `Content-Encoding` refused; ten seconds to connect and thirty in all; the body read to its limit and not past it; the name looked up once, and an address that is loopback, link-local, private, unspecified or multicast refused, with the address that was checked being the one dialled. The token is in the body of the request and nowhere else.
//! **A pinned endpoint** (the link's third field, a pinned entry of `refresh_urls`) is held to its pins alone, as the transport library holds a self-signed candidate (`veilway_transport::pin_only`): TLS 1.3 only, the SHA-256 of the leaf's SubjectPublicKeyInfo is one of the pins and the handshake is signed with that key, no chain, name or date, no early data and no resumed session. The request, with the token in its body, is written only after that check passed. A mismatch is `FetchError::Pin`, never a refusal of the endpoint. A pinned host that is an IP literal is dialled with no lookup and sent no server name. `Held::targets` and `Fetching::pins` say which pins each endpoint is checked by.
//! **The vault is the platform's.** The subscriptions hold the link's token, the device's private key and the transport secrets, so they belong in the operating system's secret storage or in a file encrypted under a key kept there. `Vault` is the trait the platform implements for that. The only vault that ships in a build is none: `FileVault`, a mode-600 file with the secrets in plain base64, exists with the `unencrypted-vault` feature and in this crate's own tests, for tests.
//! A fetch outside a tunnel is the caller's to allow ("When a fetch happens"): this module makes the request it is told to make and does not decide when. With the kill switch on, the platform's hook for the socket (`Fetcher::socket`) is where it can refuse.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use veilway_proto::subscription::client::{Accepted, CarriedOffer, Damaged, Declined, Device, Failure, Fetching, Held, NativeOffer, Offer, Refreshed, Review, Stored, CONNECT_TIMEOUT, FETCH_TIMEOUT};
use veilway_proto::subscription::fetch::{DeviceName, Request};
use veilway_proto::subscription::link::{Carried, Link, LinkError};
use veilway_proto::subscription::payload::{dialable, private, Reason};
use veilway_proto::subscription::{DeviceSecret, Secret, Url, BODY_MAX};
use veilway_transport::http;
use veilway_transport::Hook;

/// How the name of an endpoint is looked up: once per fetch, by the resolver in force. The default is the system's, with the refusals of the page applied to what it returns. A caller that puts its own in (the tunnel's resolver, a test) is the one that applies them.
pub type Resolve = Arc<dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>> + Send + Sync>;

/// The system's resolver, and the refusals of the page: "An address that is loopback, link-local, private, unspecified or multicast is refused." What is left of the answer is what is dialled.
pub fn system_resolver() -> Resolve {
	Arc::new(|host, port| Box::pin(async move {
		let found: Vec<SocketAddr> = lookup_host((host.as_str(), port)).await?.filter(|address| dialable(address.ip()) && !private(address.ip())).collect();
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
	/// The name did not resolve, or only to addresses that may not be dialled.
	Resolve,
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
	/// The words an app shows.
	pub fn text(self) -> &'static str {
		match self {
			Self::Resolve => "The subscription server's name could not be looked up, or it points somewhere this app will not connect to.",
			Self::Connect => "Could not connect to the subscription server.",
			Self::Certificate => "The subscription server's certificate is not valid. If your provider uses its own certificate, part of the link may have been lost on the way.",
			Self::Tls => "The connection to the subscription server could not be made secure.",
			Self::Timeout => "The subscription server took too long to answer.",
			Self::NotHttp | Self::Redirect | Self::Status(_) | Self::Encoding | Self::Body => "The endpoint did not answer as a subscription: the link may have been reset, or something else answered in its place.",
			Self::Pin => "The subscription server's certificate does not match this link. If your provider has changed it, ask for a new link. If not, something between you and your provider answered in its place.",
		}
	}
}

/// Why an import step did not go through. Nothing was stored, and what was held is as it was.
#[derive(Debug)]
pub enum ImportError {
	/// The text is no link.
	Link(LinkError),
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
}

impl From<FetchError> for ImportError {
	fn from(error: FetchError) -> Self {Self::Fetch(error)}
}

impl ImportError {
	/// The words an app shows.
	pub fn text(&self) -> &'static str {
		match self {
			Self::Link(_) => "This is not a link this app can use.",
			Self::Legacy => "This is a link of another kind. It cannot be verified, and this app does not connect to it by itself.",
			Self::Fetch(error) => error.text(),
			Self::Random => "The system could not give the app random numbers. Nothing was sent.",
			Self::Store(_) => "The subscription could not be saved on this device.",
			Self::Full => "This app holds as many subscriptions as it can. Remove one first.",
			Self::Subscription(Failure::Refused(reason)) => match reason {
				Reason::DeviceLimit => "Every device place of this account is taken. Remove a device in the provider's panel, or ask the provider to reset the link.",
				Reason::Disabled => "The provider has switched the account off.",
				Reason::Expired => "The account has expired.",
				Reason::RateLimited => "This device has asked too often. Try again later.",
				Reason::DeviceMismatch => "This device has to be enrolled again: import the link again.",
				Reason::KeyRetired => "The provider has renewed its key. A new link is needed.",
				Reason::Released | Reason::BadRequest => "The request could not be completed. This is a fault in the app.",
			},
			Self::Subscription(Failure::Envelope(_)) => "The answer was not signed by this provider's key.",
			Self::Subscription(Failure::Rollback | Failure::Fork | Failure::Backdated | Failure::NotNewer) => "The answer is older than, or different from, the subscription this app already holds.",
			Self::Subscription(Failure::Expired | Failure::Future) => "The subscription's dates are wrong. Check the date and time on this device.",
			Self::Subscription(Failure::Pins | Failure::EndpointKind | Failure::Changed) => "The answer changes how the subscription server is checked in a way that is not allowed without a new link. If your provider has changed it, ask for a new link.",
			Self::Subscription(Failure::HasLink) => "This subscription was imported with a link. Remove it first to replace it with a whole document.",
			Self::Subscription(_) => "The answer could not be accepted.",
		}
	}
}

/// What the fetches of an import are made with. Cloning it shares the roots.
#[derive(Clone)]
pub struct Fetcher {pub roots: Arc<rustls::RootCertStore>, pub resolve: Resolve, pub socket: Option<Hook>}

impl Fetcher {
	/// A fetcher with the system's resolver and the roots it is given.
	pub fn new(roots: Arc<rustls::RootCertStore>, socket: Option<Hook>) -> Self {Self {roots, resolve: system_resolver(), socket}}
	/// One `POST` of `body` to `url`, and the body of the answer. See the head of this module for what it does and refuses.
	pub async fn post(&self, url: &Url, trust: &Trust, body: &[u8]) -> Result<Vec<u8>, FetchError> {
		timeout(FETCH_TIMEOUT, self.exchange(url, trust, body)).await.unwrap_or(Err(FetchError::Timeout))
	}
	async fn exchange(&self, url: &Url, trust: &Trust, body: &[u8]) -> Result<Vec<u8>, FetchError> {
		let (host, port, literal) = (url.host().to_owned(), url.port(), url.literal());
		// An IP literal is dialled as it is, with no lookup, and held to the same refusals as any address the system's resolver gives.
		let addresses = match literal {
			Some(ip) if dialable(ip) && !private(ip) => vec![SocketAddr::new(ip, port)],
			Some(_) => return Err(FetchError::Resolve),
			None => (self.resolve)(host.clone(), port).await.map_err(|_| FetchError::Resolve)?,
		};
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
		let request = [format!("POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", body.len()).as_bytes(), body].concat();
		tls.write_all(&request).await.map_err(|_| FetchError::NotHttp)?;
		tls.flush().await.map_err(|_| FetchError::NotHttp)?;
		read_answer(&mut tls).await
	}
}

// Reads the head of an answer and its body, inside the bounds of the page.
async fn read_answer(io: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, FetchError> {
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
		return unchunk(io, rest).await;
	}
	let wanted = match length.as_slice() {
		[] => None,
		[digits] if (1..=7).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit) => Some(digits.iter().fold(0usize, |number, digit| number * 10 + usize::from(digit - b'0'))),
		_ => return Err(FetchError::Body),
	};
	if wanted.is_some_and(|wanted| wanted > BODY_MAX) {return Err(FetchError::Body)}
	loop {
		if wanted.is_some_and(|wanted| rest.len() >= wanted) {break}
		if rest.len() > BODY_MAX {return Err(FetchError::Body)}
		let mut chunk = [0u8; 8192];
		match io.read(&mut chunk).await {
			Ok(0) => break,
			Ok(count) => rest.extend_from_slice(&chunk[..count]),
			Err(_) => return Err(FetchError::NotHttp),
		}
	}
	// A length that was promised is the length that came, and a body with no length ends where the connection does.
	if wanted.is_some_and(|wanted| rest.len() != wanted) {return Err(FetchError::Body)}
	Ok(rest)
}

// The body of a chunked answer, as strictly as the page's reader of a head is: a size of plain hexadecimal digits, no extension, no trailer.
async fn unchunk(io: &mut (impl AsyncRead + Unpin), mut buffer: Vec<u8>) -> Result<Vec<u8>, FetchError> {
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
		if body.len() + size > BODY_MAX {return Err(FetchError::Body)}
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
struct StoredWire {#[serde(default)] origin: Option<OriginWire>, keys: Vec<String>, document: String, #[serde(default)] hosts: Vec<String>, #[serde(default)] pins: Vec<String>}

/// The most subscriptions a vault holds and the most it reads.
pub const HELD_MAX: usize = 64;
const VAULT_MAX: usize = 4 * BODY_MAX * 16;

fn array<const N: usize>(text: &str) -> Option<[u8; N]> {STANDARD.decode(text).ok()?.try_into().ok()}

fn from_wire(wire: StoredWire) -> Option<Stored> {
	let origin = match wire.origin {
		Some(origin) => Some((origin.link, Secret::new(array(&origin.private)?), DeviceSecret::new(array(&origin.secret)?))),
		None => None,
	};
	Some(Stored {origin, keys: wire.keys.iter().map(|key| array(key)).collect::<Option<Vec<_>>>()?, document: wire.document, hosts: wire.hosts, pins: wire.pins.iter().map(|pin| array(pin)).collect::<Option<Vec<_>>>()?})
}

/// Reads a vault file. A file that is not one is an error, and an entry that is not one is left out.
pub fn read_vault(bytes: &[u8]) -> io::Result<Vec<Stored>> {
	if bytes.len() > VAULT_MAX {return Err(io::Error::new(io::ErrorKind::InvalidData, "the file is larger than any vault"))}
	let wires: Vec<StoredWire> = serde_json::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
	Ok(wires.into_iter().take(HELD_MAX).filter_map(from_wire).collect())
}

/// The bytes of a vault file.
pub fn write_vault(held: &[Stored]) -> Vec<u8> {
	let wires: Vec<StoredWire> = held.iter().take(HELD_MAX).map(|stored| StoredWire {origin: stored.origin.as_ref().map(|(link, private, secret)| OriginWire {link: link.clone(), private: STANDARD.encode(private.expose()), secret: STANDARD.encode(secret.expose())}), keys: stored.keys.iter().map(|key| STANDARD.encode(key)).collect(), document: stored.document.clone(), hosts: stored.hosts.clone(), pins: stored.pins.iter().map(|pin| STANDARD.encode(pin)).collect()}).collect();
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
	/// Removes a subscription, with its link, its key and its secret: "Removing a subscription in the app deletes its key, secret and link."
	pub fn remove(&mut self, id: &veilway_proto::subscription::payload::Id) -> io::Result<bool> {
		let before = self.held.len();
		self.held.retain(|held| held.id() != id);
		self.save()?;
		Ok(self.held.len() != before)
	}
}

/// The review of an answer, with the endpoint it came from, which `release` and `confirm` go back to.
pub struct Reviewed {pub review: Review, pub endpoint: Option<Url>, pub pins: Vec<[u8; 32]>}

impl std::fmt::Debug for Reviewed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {write!(f, "Reviewed({:?})", self.review)}
}

/// Step 1: reads a text as a link. Nothing is sent, generated or stored. White space around a pasted text is cut off here, since the grammar reads a text exactly as it is.
pub fn open(text: &str) -> Result<Offer, ImportError> {
	match Link::parse(text.trim()).map(Offer::open).map_err(ImportError::Link)? {
		Offer::Legacy(_) => Err(ImportError::Legacy),
		offer => Ok(offer),
	}
}

/// Step 1 for the content of a file: `v1.<key>.<document>` and nothing else, bar one line end. A file is the only form that carries a document of any size, and it has no endpoint.
pub fn open_file(content: &[u8]) -> Result<Offer, ImportError> {Carried::file(content).map(|carried| Offer::open(Link::Carried(carried))).map_err(ImportError::Link)}

/// The user's yes to a native link. `device` is the stored device when the import is of a link for a subscription the app holds, so that it takes no new place. The key and the secret of a new device are drawn here and not before.
pub fn proceed(offer: NativeOffer, device: Option<Device>) -> Result<Fetching, ImportError> {offer.proceed(device, &mut crate::random).map_err(|_| ImportError::Random)}

/// The user's yes to a whole document in a link or a file: there is nothing to fetch, and it is reviewed at once.
pub fn proceed_carried(offer: CarriedOffer, now: u64, library: &Library) -> Result<Reviewed, ImportError> {
	let stored: Vec<&Held> = library.held.iter().collect();
	offer.proceed(now, &stored).map(|review| Reviewed {review, endpoint: None, pins: Vec::new()}).map_err(ImportError::Subscription)
}

impl Fetcher {
	/// Step 2 of a native import, after the user's yes: the one request with `op` `"fetch"`. A failure leaves the step as it was, to try again or to `abandon`.
	pub async fn fetch(&self, fetching: &Fetching, library: &Library, now: u64) -> Result<Reviewed, ImportError> {
		let body = self.post(fetching.endpoint(), &Trust::of(fetching.pins()), &fetching.request().body()).await?;
		let stored: Vec<&Held> = library.held.iter().collect();
		let review = fetching.answer(&body, now, &stored).map_err(ImportError::Subscription)?;
		// `confirm` and `release` go to the endpoint the way the review says it is checked, which is the document's list of pins when it has one.
		Ok(Reviewed {pins: review.pins().to_vec(), review, endpoint: Some(fetching.endpoint().clone())})
	}
	/// The import is given up after the request went out and before an answer could be reviewed: the `release` request frees the pending place. Best effort.
	pub async fn abandon(&self, fetching: Fetching) {
		let (endpoint, trust) = (fetching.endpoint().clone(), Trust::of(fetching.pins()));
		let request = fetching.abandon();
		if let Err(error) = self.post(&endpoint, &trust, &request.body()).await {tracing::info!(?error, "the pending device place could not be released");}
	}
	/// Step 3, the user accepts. The subscription is stored first, so that the device key is not lost with a failed `confirm`, and then the place is made permanent. A rule that no longer allows it releases the place and stores nothing. A subscription that is stored and whose `confirm` did not go out is not an error: the next refresh enrols it again.
	pub async fn accept(&self, reviewed: Reviewed, name: Option<DeviceName>, library: &mut Library) -> Result<Accepted, ImportError> {
		let Reviewed {review, endpoint, pins} = reviewed;
		// A subscription beyond what a vault holds is refused here and not dropped when the vault is written: the place the device took is given back.
		if !review.replaces() && library.held.len() >= HELD_MAX {
			self.send(endpoint.as_ref(), &pins, review.decline()).await;
			return Err(ImportError::Full);
		}
		let accepted = {
			let stored: Vec<&Held> = library.held.iter().collect();
			review.accept(name, &stored)
		};
		let accepted = match accepted {
			Ok(accepted) => accepted,
			Err(declined) => {
				let Declined {failure, release} = *declined;
				self.send(endpoint.as_ref(), &pins, release).await;
				return Err(ImportError::Subscription(failure));
			}
		};
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
			return Err(ImportError::Store(error));
		}
		// The pins the endpoint is held to now are the ones the accepted document names.
		let held_pins = accepted.held.targets().first().map(|(_, pins)| pins.to_vec()).unwrap_or(pins);
		self.send(endpoint.as_ref(), &held_pins, accepted.confirm.clone()).await;
		Ok(accepted)
	}
	/// The user declines: the `release` request, and nothing kept.
	pub async fn decline(&self, reviewed: Reviewed) {
		let Reviewed {review, endpoint, pins} = reviewed;
		self.send(endpoint.as_ref(), &pins, review.decline()).await;
	}
	// A request whose answer is not read: `confirm` and `release`. A failure is logged and is not the import's.
	async fn send(&self, endpoint: Option<&Url>, pins: &[[u8; 32]], request: Option<Request>) {
		let (Some(endpoint), Some(request)) = (endpoint, request) else {return};
		if let Err(error) = self.post(endpoint, &Trust::of(pins), &request.body()).await {tracing::info!(?error, "a request of the import could not be sent");}
	}
	/// Refreshes the subscription at `at`: the endpoint of its link and then the confirmed `refresh_urls`, in order, until an answer passes every check ("goes on to the next entry of the list of endpoints"). A subscription that came as a whole document cannot refresh. The caller decides when ("When a fetch happens").
	pub async fn refresh(&self, library: &mut Library, at: usize, now: u64) -> Result<Refreshed, ImportError> {
		let Some(held) = library.held.get(at) else {return Err(ImportError::Subscription(Failure::HasLink))};
		let (Some(request), targets) = (held.fetch(), held.targets().into_iter().map(|(url, pins)| (url.clone(), pins.to_vec())).collect::<Vec<_>>()) else {return Err(ImportError::Legacy)};
		let mut last = ImportError::Fetch(FetchError::Connect);
		for (endpoint, pins) in targets {
			match self.post(&endpoint, &Trust::of(&pins), &request.body()).await {
				Ok(body) => match library.held[at].refresh(&body, now) {
					Ok(refreshed) => {
						library.save().map_err(ImportError::Store)?;
						return Ok(refreshed);
					}
					Err(failure) => last = ImportError::Subscription(failure),
				},
				Err(error) => last = ImportError::Fetch(error),
			}
		}
		Err(last)
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
			let stored = Stored {origin: Some((link.clone(), Secret::new(key), DeviceSecret::new(secret))), keys: vec![key], document: document.clone(), hosts: vec![host.clone()], pins: vec![key]};
			let read = read_vault(&write_vault(&[stored])).unwrap();
			prop_assert_eq!(read.len(), 1);
			prop_assert!(read[0].keys == vec![key] && read[0].pins == vec![key] && read[0].document == document && read[0].hosts == vec![host] && read[0].origin.as_ref().is_some_and(|(found, private, device)| *found == link && private.expose() == &key && device.expose() == &secret));
		}
	}

	#[test]
	fn a_vault_that_is_not_one_is_an_error_and_an_entry_that_is_not_one_is_left_out() {
		for bytes in [&b""[..], b"{}", b"[1]", b"[{\"keys\": 5}]", b"\xff"] {assert!(read_vault(bytes).is_err(), "{:?}", String::from_utf8_lossy(bytes))}
		let good = write_vault(&[Stored {origin: None, keys: vec![[3; 32]], document: "d".into(), hosts: Vec::new(), pins: vec![[5; 32]]}]);
		assert_eq!(read_vault(&good).unwrap().len(), 1);
		let text = String::from_utf8(good).unwrap().replace(&STANDARD.encode([3u8; 32]), "not base64");
		assert!(read_vault(text.as_bytes()).unwrap().is_empty());
		assert!(read_vault(&vec![b' '; VAULT_MAX + 1]).is_err());
	}

	#[test]
	fn a_chunked_body_is_read_as_strictly_as_a_head_is() {
		let run = |bytes: &[u8]| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
			let (mut near, mut far) = tokio::io::duplex(1 << 16);
			far.write_all(bytes).await.unwrap();
			drop(far);
			unchunk(&mut near, Vec::new()).await
		});
		assert_eq!(run(b"5\r\nhello\r\n0\r\n\r\n"), Ok(b"hello".to_vec()));
		assert_eq!(run(b"2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n"), Ok(b"abcde".to_vec()));
		// An extension, a size that is no hexadecimal, a trailer, a missing end and a body over its limit.
		for bytes in [&b"5;x=1\r\nhello\r\n0\r\n\r\n"[..], b"zz\r\nhello\r\n0\r\n\r\n", b"5\r\nhello\r\n0\r\nTrailer: x\r\n\r\n", b"5\r\nhello\r\n", b"5\r\nhelloXX0\r\n\r\n", b"fffffff\r\n"] {assert!(run(bytes).is_err(), "{:?}", String::from_utf8_lossy(bytes))}
	}
}
