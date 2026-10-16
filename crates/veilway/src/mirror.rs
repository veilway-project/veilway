//! `veilway mirror`: a relay mirror of a subscription endpoint (subscription format page, "When nothing works", `refresh_urls`).
//! It serves the endpoint's path on another address and forwards each native request to the provider's panel over HTTPS. Every document is signed, so the mirror cannot change one, but it reads every token: it is meant for servers the provider controls.
//! It sits behind the operator's own web server, which ends TLS and limits sources. A request that is not a `POST` of at most 1,024 bytes of `application/json` to exactly the path is not read further and not forwarded: the mirror hands it back to the web server with status 599, which the web server turns into the answer it gives on any path it does not serve (nginx: `proxy_intercept_errors on; error_page 599 = @unknown;`). A peer that is no trusted proxy gets no answer at all. The same holds when the upstream fails or answers anything but a document, so that the mirror says nothing about the state of the panel.
//! The panel is sent the real address of the client in `X-Veilway-Mirror: v1;name;address;timestamp;nonce;mac`. The mac is HMAC-SHA-256 under the secret shared with the panel over `veilway mirror v1`, then name, address, timestamp, nonce and the SHA-256 of the body, each after a line feed. The nonce is 16 random bytes, and the nonce, the body's hash and the mac are unpadded base64url. The panel checks the age and refuses a nonce it has seen.
//! Nothing of a request or answer is kept past the request, and no token is written to a log: the log holds the state of the upstream and nothing from a body.
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ipnet::IpNet;
use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Deserialize;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use veilway_proto::http::{self, Framing};
use veilway_proto::subscription::{fetch, BODY_MAX};

const HEAD_MAX: usize = 16_384;
const CONNECTIONS: usize = 256;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
// The body of a request that is handed back is read up to this, so that closing the socket does not reset the answer.
const DRAIN_MAX: u64 = 65_536;
/// The status that hands a request back to the web server.
const HAND_BACK: u16 = 599;
const OWN_404: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n</body>\r\n</html>\r\n";

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// The name the panel's `trusted_mirrors` lists this mirror under.
	pub name: String,
	pub listen: SocketAddr,
	/// The public path the mirror serves, which is the path of the link's endpoint on the mirror's own domain.
	pub path: String,
	/// The panel's subscription endpoint, an `https` URL with a path.
	pub upstream: String,
	/// SHA-256 of the SubjectPublicKeyInfo of the upstream's certificate, in base64, as a second condition after the chain.
	#[serde(default)]
	pub upstream_pins: Vec<String>,
	/// Addresses and networks of the web server in front. Empty is for a test with no web server: the mirror then answers by itself.
	#[serde(default)]
	pub trusted_proxies: Vec<String>,
	#[serde(default = "forwarded_header")]
	pub client_address_header: String,
	/// 32 to 64 random bytes in unpadded base64url, the same as in the panel's `trusted_mirrors`.
	pub secret: String,
}

fn forwarded_header() -> String {"X-Forwarded-For".into()}

struct Upstream {host: String, port: u16, path: String, name: ServerName<'static>}

/// A config that passed every check.
pub struct Checked {config: Config, upstream: Upstream, pins: Vec<[u8; 32]>, trusted: Vec<IpNet>, secret: Vec<u8>}

fn upstream(url: &str) -> Result<Upstream, String> {
	let rest = url.strip_prefix("https://").ok_or("expected an https URL")?;
	let (authority, path) = rest.split_once('/').map(|(authority, path)| (authority, format!("/{path}"))).ok_or("expected a path after the host")?;
	if !path.bytes().all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'?' && byte != b'#') || authority.contains('@') {return Err("expected no query, fragment, user or blanks".into())}
	let (host, port) = match authority.strip_prefix('[').and_then(|inner| inner.split_once(']')) {
		Some((host, "")) => (host, 443),
		Some((host, port)) => (host, port.strip_prefix(':').and_then(|port| port.parse().ok()).ok_or("expected a port")?),
		None => match authority.split_once(':') {Some((host, port)) => (host, port.parse().map_err(|_| "expected a port")?), None => (authority, 443)},
	};
	if host.ends_with(".invalid") {return Err("expected your panel's address, not the placeholder".into())}
	let name = ServerName::try_from(host.to_string()).map_err(|_| "expected a host name or an address")?;
	Ok(Upstream {host: host.into(), port, path, name})
}

/// The config as a file says it, with every error and warning. The file holds the secret, so it must not be readable by group or others.
pub fn load(path: &Path) -> (Option<Checked>, Vec<String>, Vec<String>) {
	let (mut errors, mut warnings) = (Vec::new(), Vec::new());
	let bytes = match std::fs::read(path) {Ok(bytes) => bytes, Err(error) => return (None, vec![format!("{}: {error}", path.display())], warnings)};
	if std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o077 != 0) {errors.push("the file can be read by group or others and holds the secret; restrict it (chmod 600)".into())}
	let config: Config = match serde_json::from_slice(&bytes) {Ok(config) => config, Err(error) => {errors.push(error.to_string()); return (None, errors, warnings)}};
	if !(1..=32).contains(&config.name.len()) || !config.name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)) {errors.push("name: expected 1 to 32 characters from a-z 0-9 - _".into())}
	if config.path.len() < 2 || config.path.len() > 128 || !config.path.starts_with('/') || config.path.ends_with('/') || config.path.contains("//") || !config.path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/-_.~".contains(&byte)) {errors.push("path: expected a path with a leading slash, no trailing slash and only letters, digits and - _ . ~ /".into())}
	let upstream = upstream(&config.upstream).inspect_err(|error| errors.push(format!("upstream: {error}"))).ok();
	let secret = URL_SAFE_NO_PAD.decode(&config.secret).ok().filter(|secret| (32..=64).contains(&secret.len()));
	if secret.is_none() {errors.push("secret: expected 32 to 64 bytes in unpadded base64url".into())}
	if config.upstream_pins.len() > 4 {errors.push("upstream_pins: expected at most 4".into())}
	let pins: Vec<[u8; 32]> = config.upstream_pins.iter().filter_map(|pin| STANDARD.decode(pin).ok().and_then(|bytes| bytes.try_into().ok())).collect();
	if pins.len() != config.upstream_pins.len() {errors.push("upstream_pins: expected SHA-256 hashes in base64".into())}
	let trusted: Vec<IpNet> = config.trusted_proxies.iter().filter_map(|net| net.parse().ok().or_else(|| net.parse::<IpAddr>().ok().map(IpNet::from))).collect();
	if trusted.len() != config.trusted_proxies.len() || config.trusted_proxies.len() > 16 {errors.push("trusted_proxies: expected at most 16 addresses or networks".into())}
	if trusted.iter().any(|net| net.prefix_len() == 0) {errors.push("trusted_proxies: expected the addresses of your own web server, not every address there is".into())}
	if config.client_address_header.is_empty() || config.client_address_header.len() > 64 || !config.client_address_header.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {errors.push("client_address_header: expected a header field name".into())}
	if trusted.is_empty() {warnings.push("trusted_proxies: empty, so the mirror has no web server in front and answers requests it will not take with a 404 of its own, which no web server of yours would give. Use this for a test only".into())}
	else if !config.listen.ip().is_loopback() {warnings.push("listen: not a loopback address, so the web server's requests reach the mirror as plain HTTP across a network".into())}
	if config.upstream_pins.is_empty() {warnings.push("upstream_pins: empty, so the chain of the panel's certificate is the only check of the upstream".into())}
	match (upstream, secret) {
		(Some(upstream), Some(secret)) if errors.is_empty() => (Some(Checked {config, upstream, pins, trusted, secret}), errors, warnings),
		_ => (None, errors, warnings),
	}
}

/// The header that tells the panel the address a request came from.
pub fn header(secret: &[u8], name: &str, address: IpAddr, at: u64, nonce: &str, body: &[u8]) -> String {
	let hash = URL_SAFE_NO_PAD.encode(digest(&SHA256, body));
	let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), format!("veilway mirror v1\n{name}\n{address}\n{at}\n{nonce}\n{hash}").as_bytes());
	format!("v1;{name};{address};{at};{nonce};{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
}

/// The length a request declares for its body, for a request in HTTP/1.0 or HTTP/1.1 that the mirror reads.
fn length(head: &[u8]) -> Option<u64> {
	let version = head.split(|byte| *byte == b'\n').next()?.strip_suffix(b"\r")?.split(|byte| *byte == b' ').nth(2)?;
	if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1") {return None}
	let Framing::Length(length) = http::request_as(head, version).body? else {return None};
	Some(length)
}

/// The length of the body of a request the mirror forwards, and None for every other request.
fn wanted(head: &[u8], path: &str) -> Option<usize> {
	let mut lines = head.split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
	let mut parts = lines.next()?.split(|byte| *byte == b' ');
	if parts.next()? != b"POST" || parts.next()? != path.as_bytes() {return None}
	let length = length(head)?;
	let mut kinds = lines.filter_map(|line| line.iter().position(|byte| *byte == b':').map(|at| (&line[..at], &line[at + 1..]))).filter(|(name, _)| name.eq_ignore_ascii_case(b"content-type"));
	let (Some((_, kind)), None) = (kinds.next(), kinds.next()) else {return None};
	(kind.trim_ascii().eq_ignore_ascii_case(b"application/json") && length <= fetch::BODY_MAX as u64).then_some(length as usize)
}

/// The upstream's chain is always validated, and its pins are a second condition behind it.
#[derive(Debug)]
struct Pinned {inner: Arc<WebPkiServerVerifier>, pins: Vec<[u8; 32]>}

impl ServerCertVerifier for Pinned {
	fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
		let verified = self.inner.verify_server_cert(end_entity, intermediates, name, ocsp, now)?;
		if self.pins.is_empty() {return Ok(verified)}
		let hash = digest(&SHA256, ParsedCertificate::try_from(end_entity)?.subject_public_key_info().as_ref());
		if self.pins.iter().any(|pin| pin.as_slice() == hash.as_ref()) {Ok(verified)} else {Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))}
	}
	fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {self.inner.verify_tls12_signature(message, cert, dss)}
	fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {self.inner.verify_tls13_signature(message, cert, dss)}
	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {self.inner.supported_verify_schemes()}
}

struct Shared {checked: Checked, tls: TlsConnector, seats: Arc<Semaphore>, refusals: Arc<Semaphore>, failing: AtomicBool}

impl Shared {
	fn new(checked: Checked, roots: RootCertStore) -> Result<Self, String> {
		let provider = Arc::new(default_provider());
		let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().map_err(|error| error.to_string())?;
		let mut config = ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|error| error.to_string())?.dangerous().with_custom_certificate_verifier(Arc::new(Pinned {inner, pins: checked.pins.clone()})).with_no_client_auth();
		config.alpn_protocols = vec![b"http/1.1".to_vec()];
		Ok(Self {checked, tls: TlsConnector::from(Arc::new(config)), seats: Arc::new(Semaphore::new(CONNECTIONS)), refusals: Arc::new(Semaphore::new(CONNECTIONS)), failing: AtomicBool::new(false)})
	}
}

/// The panel's document, or None when anything about getting it failed or the panel answered anything but a 200 document.
async fn relay(shared: &Shared, body: &[u8], client: IpAddr) -> Option<Vec<u8>> {
	let (upstream, nonce) = (&shared.checked.upstream, {let mut bytes = [0u8; 16]; SystemRandom::new().fill(&mut bytes).ok()?; URL_SAFE_NO_PAD.encode(bytes)});
	let at = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
	let signed = header(&shared.checked.secret, &shared.checked.config.name, client, at, &nonce, body);
	let host = if upstream.port == 443 {upstream.host.clone()} else {format!("{}:{}", upstream.host, upstream.port)};
	// HTTP/1.0 so that the answer is never chunked and ends at the length or at the close.
	let mut request = format!("POST {} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Veilway-Mirror: {signed}\r\nConnection: close\r\n\r\n", upstream.path, body.len()).into_bytes();
	request.extend_from_slice(body);
	let exchange = async {
		let mut stream = None;
		for address in lookup_host((upstream.host.as_str(), upstream.port)).await? {
			if let Ok(connected) = TcpStream::connect(address).await {stream = Some(connected); break}
		}
		let mut stream = shared.tls.connect(upstream.name.clone(), stream.ok_or(ErrorKind::NotConnected)?).await?;
		stream.write_all(&request).await?;
		let (mut raw, mut chunk) = (Vec::new(), [0u8; 8192]);
		loop {
			let read = match stream.read(&mut chunk).await {Ok(read) => read, Err(error) if error.kind() == ErrorKind::UnexpectedEof => 0, Err(error) => return Err(error)};
			if read == 0 {break}
			raw.extend_from_slice(&chunk[..read]);
			if raw.len() > HEAD_MAX + BODY_MAX {return Err(ErrorKind::InvalidData.into())}
		}
		Ok::<_, std::io::Error>(raw)
	};
	let raw = timeout(UPSTREAM_TIMEOUT, exchange).await.ok()?.inspect_err(|error| tracing::debug!("the upstream exchange failed: {:?}", error.kind())).ok()?;
	let head = &raw[..http::head_end(&raw)?];
	let text = std::str::from_utf8(head).ok()?;
	let mut lines = text.split("\r\n");
	let mut status = lines.next()?.split(' ');
	let (version, code) = (status.next()?, status.next()?);
	let (mut kind, mut length) = (None, None);
	for line in lines.filter(|line| !line.is_empty()) {
		let (name, value) = line.split_once(':')?;
		match name.to_ascii_lowercase().as_str() {
			"transfer-encoding" => return None,
			"content-type" => kind = Some(value.trim()),
			"content-length" => length = Some(value.trim().parse::<usize>().ok()?),
			_ => {}
		}
	}
	let body = raw[head.len()..].to_vec();
	if !version.starts_with("HTTP/1.") || code != "200" || !kind.is_some_and(|kind| kind.eq_ignore_ascii_case("application/jose")) || length.is_some_and(|length| length != body.len()) || body.len() > BODY_MAX {return None}
	Some(body)
}

/// The answer that gives a request away: the mirror's own 404 when no web server is in front of it, else the status that hands it back.
fn hand_back(own: bool) -> String {
	if own {format!("HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{OWN_404}", OWN_404.len())} else {format!("HTTP/1.1 {HAND_BACK} Hand Back\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")}
}

async fn connection(mut stream: TcpStream, from: IpAddr, shared: Arc<Shared>) {
	let (checked, trusted) = (&shared.checked, &shared.checked.trusted);
	let mut buffer = Vec::new();
	let read = async {
		let mut chunk = [0u8; 4096];
		let end = loop {
			if let Some(end) = http::head_end(&buffer) {break end}
			if buffer.len() > HEAD_MAX {return None}
			match stream.read(&mut chunk).await {Ok(0) | Err(_) => return None, Ok(read) => buffer.extend_from_slice(&chunk[..read])}
		};
		let drain = length(&buffer[..end]).unwrap_or(0).min(DRAIN_MAX) as usize;
		while buffer.len() < end + drain {
			match stream.read(&mut chunk).await {Ok(0) | Err(_) => return None, Ok(read) => buffer.extend_from_slice(&chunk[..read])}
		}
		Some(end)
	};
	let Ok(Some(end)) = timeout(READ_TIMEOUT, read).await else {return};
	let forward = wanted(&buffer[..end], &checked.config.path);
	let reply = match forward {
		Some(length) => {
			let client = if trusted.is_empty() {from} else {http::forwarded(&buffer[..end], checked.config.client_address_header.as_bytes(), |address| trusted.iter().any(|net| net.contains(&address))).unwrap_or(from)};
			relay(&shared, &buffer[end..end + length], client).await
		}
		None => None,
	};
	let Some(body) = reply else {
		if forward.is_some() && !shared.failing.swap(true, Ordering::Relaxed) {tracing::warn!("the upstream did not answer as a panel does: requests are handed back until it does")}
		let _ = timeout(READ_TIMEOUT, stream.write_all(hand_back(trusted.is_empty()).as_bytes())).await;
		return;
	};
	if shared.failing.swap(false, Ordering::Relaxed) {tracing::info!("the upstream answers again")}
	let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/jose\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
	answer.extend_from_slice(&body);
	let _ = timeout(READ_TIMEOUT, stream.write_all(&answer)).await;
}

/// A connection that finds every seat taken: it is answered and drained, never relayed.
async fn refuse(mut stream: TcpStream, shared: Arc<Shared>) {
	let _ = timeout(READ_TIMEOUT, async {
		stream.write_all(hand_back(shared.checked.trusted.is_empty()).as_bytes()).await?;
		stream.shutdown().await?;
		let mut sink = [0u8; 4096];
		while stream.read(&mut sink).await? > 0 {}
		Ok::<_, std::io::Error>(())
	}).await;
}

async fn serve(listener: TcpListener, shared: Arc<Shared>) {
	loop {
		let Ok((stream, peer)) = listener.accept().await else {
			tokio::time::sleep(Duration::from_millis(100)).await;
			continue;
		};
		let from = peer.ip().to_canonical();
		let trusted = &shared.checked.trusted;
		if !trusted.is_empty() && !trusted.iter().any(|net| net.contains(&from)) {continue}
		let shared = shared.clone();
		match shared.seats.clone().try_acquire_owned() {
			Ok(seat) => {
				tokio::spawn(async move {
					connection(stream, from, shared).await;
					drop(seat);
				});
			}
			Err(_) => {
				let Ok(refusal) = shared.refusals.clone().try_acquire_owned() else {continue};
				tokio::spawn(async move {
					refuse(stream, shared).await;
					drop(refusal);
				});
			}
		}
	}
}

/// `veilway mirror`: the exit status. With `check` it only validates the config.
pub async fn run(path: &Path, check: bool) -> i32 {
	let (checked, errors, warnings) = load(path);
	for error in &errors {eprintln!("error: {error}")}
	for warning in &warnings {eprintln!("warning: {warning}")}
	eprintln!("{}: {} errors, {} warnings", path.display(), errors.len(), warnings.len());
	let Some(checked) = checked.filter(|_| errors.is_empty()) else {return 1};
	if check {return 0}
	tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))).init();
	let roots = RootCertStore {roots: webpki_roots::TLS_SERVER_ROOTS.to_vec()};
	let (name, listen, path, host) = (checked.config.name.clone(), checked.config.listen, checked.config.path.clone(), format!("{}:{}", checked.upstream.host, checked.upstream.port));
	let shared = match Shared::new(checked, roots) {Ok(shared) => Arc::new(shared), Err(error) => {eprintln!("error: {error}"); return 1}};
	let listener = match TcpListener::bind(listen).await {Ok(listener) => listener, Err(error) => {eprintln!("error: {listen}: {error}"); return 1}};
	tracing::info!("mirror {name} serves {path} on {listen} and forwards to {host}");
	serve(listener, shared).await;
	0
}

#[cfg(test)]
mod tests {
	use super::*;
	use rustls::pki_types::PrivatePkcs8KeyDer;
	use serde_json::{json, Value};
	use std::sync::atomic::AtomicU32;
	use std::sync::Mutex;
	use tokio_rustls::TlsAcceptor;

	const SECRET: [u8; 32] = [7; 32];
	const HAND_BACK_ANSWER: &str = "HTTP/1.1 599 Hand Back\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	static FILES: AtomicU32 = AtomicU32::new(0);

	fn text(secret: &[u8]) -> String {URL_SAFE_NO_PAD.encode(secret)}

	fn base(upstream: &str) -> Value {json!({"name": "relay", "listen": "127.0.0.1:0", "path": "/sub", "upstream": upstream, "trusted_proxies": ["127.0.0.1"], "secret": text(&SECRET)})}

	fn file(config: &Value, mode: u32) -> std::path::PathBuf {
		let path = std::env::temp_dir().join(format!("veilway-mirror-{}-{}.json", std::process::id(), FILES.fetch_add(1, Ordering::Relaxed)));
		std::fs::write(&path, config.to_string()).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
		path
	}

	fn errors(config: &Value) -> Vec<String> {
		let path = file(config, 0o600);
		let (_, errors, _) = load(&path);
		std::fs::remove_file(path).unwrap();
		errors
	}

	fn post(path: &str, kind: &str, body: &str) -> String {format!("POST {path} HTTP/1.1\r\nHost: m.test\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nX-Forwarded-For: 198.51.100.5\r\n\r\n{body}", body.len())}

	#[test]
	fn the_header_matches_the_panels_vector() {
		assert_eq!(header(&SECRET, "m1", "203.0.113.9".parse().unwrap(), 1700000000, "AAAAAAAAAAAAAAAAAAAAAA", b"{\"v\":1}"), "v1;m1;203.0.113.9;1700000000;AAAAAAAAAAAAAAAAAAAAAA;l10IpkAlYVFrfLhjwdSNy8le5YSTUlyhf3eBBl-C3rs");
	assert_ne!(header(&SECRET, "m1", "203.0.113.9".parse().unwrap(), 1700000000, "AAAAAAAAAAAAAAAAAAAAAA", b"{\"v\":2}"), header(&SECRET, "m1", "203.0.113.9".parse().unwrap(), 1700000000, "AAAAAAAAAAAAAAAAAAAAAA", b"{\"v\":1}"), "the mac covers the body");
	}

	#[test]
	fn a_config_is_checked() {
		assert!(errors(&base("https://panel.example.org/sub")).is_empty());
		let with = |key: &str, value: Value| {let mut config = base("https://panel.example.org/sub"); config[key] = value; errors(&config)};
		for (key, value) in [("upstream", json!("http://panel.example.org/sub")), ("upstream", json!("https://panel.example.org")), ("upstream", json!("https://panel.example.org/sub?x=1")), ("upstream", json!("https://u@panel.example.org/sub")), ("upstream", json!("https://panel.invalid/sub")), ("path", json!("sub")), ("path", json!("/sub/")), ("path", json!("/")), ("name", json!("Relay")), ("name", json!("")), ("secret", json!(text(&[1; 16]))), ("secret", json!("not base64!")), ("upstream_pins", json!(["AAAA"])), ("trusted_proxies", json!(["nope"])), ("trusted_proxies", json!(["0.0.0.0/0"])), ("client_address_header", json!("X Forwarded")), ("listen", json!("nowhere"))] {
			assert!(!with(key, value.clone()).is_empty(), "{key} {value} is refused");
		}
		let mut unknown = base("https://panel.example.org/sub");
		unknown["extra"] = json!(1);
		assert!(!errors(&unknown).is_empty(), "a member the config does not have");
		let readable = file(&base("https://panel.example.org/sub"), 0o644);
		assert!(load(&readable).1.iter().any(|error| error.contains("chmod 600")));
		std::fs::remove_file(readable).unwrap();
		assert!(!load(Path::new("/nonexistent/mirror.json")).1.is_empty());
	}

	#[test]
	fn only_a_post_of_json_to_the_path_is_forwarded() {
		let body = "{\"v\":1}";
		let ask = |request: String| {let end = http::head_end(request.as_bytes()).unwrap(); wanted(&request.as_bytes()[..end], "/sub")};
		assert_eq!(ask(post("/sub", "application/json", body)), Some(body.len()));
		assert_eq!(ask(post("/sub", "Application/JSON", body)), Some(body.len()));
		assert_eq!(ask(post("/sub", "text/plain", body)), None, "wrong type");
		assert_eq!(ask(post("/sub", "application/json; charset=utf-8", body)), None, "a parameter is not the type");
		assert_eq!(ask(post("/other", "application/json", body)), None, "wrong path");
		assert_eq!(ask(post("/sub?x=1", "application/json", body)), None, "a query");
		assert_eq!(ask(post("/sub/", "application/json", body)), None, "a trailing slash");
		assert_eq!(ask(post("/sub", "application/json", &"x".repeat(1025))), None, "oversize");
		assert_eq!(ask(post("/sub", "application/json", &"x".repeat(1024))), Some(1024));
		assert_eq!(ask(post("/sub", "application/json", body).replacen("POST", "GET", 1)), None, "a GET");
		assert_eq!(ask(post("/sub", "application/json", body).replacen("POST", "PUT", 1)), None, "a PUT");
		assert_eq!(ask(post("/sub", "application/json", body).replacen("Content-Type: application/json", "Content-Type: application/json\r\nContent-Type: application/json", 1)), None, "two types");
		assert_eq!(ask(post("/sub", "application/json", body).replacen("Content-Type: application/json\r\n", "", 1)), None, "no type");
		assert_eq!(ask("POST /sub HTTP/1.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".into()), None, "chunked");
		assert_eq!(ask("POST /sub HTTP/1.1\r\nContent-Type: application/json\r\n\r\n".into()), None, "no length");
		assert_eq!(ask("POST /sub HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n".into()), Some(2), "HTTP/1.0 with a length");
	assert_eq!(ask("POST /sub HTTP/1.0\r\nContent-Type: application/json\r\n\r\n".into()), None, "HTTP/1.0 with no length");
	assert_eq!(ask("POST /sub HTTP/2.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n".into()), None, "another version");
	}

	struct Fake {address: SocketAddr, cert: CertificateDer<'static>, seen: Arc<Mutex<Vec<String>>>}

	impl Fake {
		fn pin(&self) -> String {STANDARD.encode(digest(&SHA256, x509_parser::parse_x509_certificate(&self.cert).unwrap().1.tbs_certificate.subject_pki.raw).as_ref())}
		fn roots(&self) -> RootCertStore {
			let mut roots = RootCertStore::empty();
			roots.add(self.cert.clone()).unwrap();
			roots
		}
		fn url(&self) -> String {format!("https://localhost:{}/panel/sub", self.address.port())}
	}

	async fn fake(status: u16, kind: &'static str, body: &'static str) -> Fake {
		let rcgen::CertifiedKey {cert, signing_key} = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
		let (der, seen) = (cert.der().clone(), Arc::new(Mutex::new(Vec::new())));
		let server = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![der.clone()], PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into()).unwrap();
		let (acceptor, listener) = (TlsAcceptor::from(Arc::new(server)), TcpListener::bind("127.0.0.1:0").await.unwrap());
		let address = listener.local_addr().unwrap();
		let recorded = seen.clone();
		tokio::spawn(async move {
			loop {
				let (stream, _) = listener.accept().await.unwrap();
				let (acceptor, recorded) = (acceptor.clone(), recorded.clone());
				tokio::spawn(async move {
					let Ok(mut stream) = acceptor.accept(stream).await else {return};
					let (mut buffer, mut chunk) = (Vec::new(), [0u8; 4096]);
					loop {
						let read = stream.read(&mut chunk).await.unwrap_or(0);
						buffer.extend_from_slice(&chunk[..read]);
						let text = String::from_utf8_lossy(&buffer).to_string();
						let Some((head, rest)) = text.split_once("\r\n\r\n") else {if read == 0 {return} else {continue}};
						let length = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).and_then(|length| length.parse::<usize>().ok()).unwrap_or(0);
						if rest.len() >= length {recorded.lock().unwrap().push(text); break}
					}
					let _ = stream.write_all(format!("HTTP/1.1 {status} Whatever\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
					let _ = stream.shutdown().await;
				});
			}
		});
		Fake {address, cert: der, seen}
	}

	async fn start(fake: &Fake, edit: impl FnOnce(&mut Value)) -> SocketAddr {
		let mut config = base(&fake.url());
		edit(&mut config);
		let path = file(&config, 0o600);
		let (checked, errors, _) = load(&path);
		std::fs::remove_file(path).unwrap();
		assert!(errors.is_empty(), "{errors:?}");
		let shared = Arc::new(Shared::new(checked.unwrap(), fake.roots()).unwrap());
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		tokio::spawn(serve(listener, shared));
		address
	}

	async fn raw(address: SocketAddr, request: &str) -> String {
		let mut stream = TcpStream::connect(address).await.unwrap();
		stream.write_all(request.as_bytes()).await.unwrap();
		let mut answer = Vec::new();
		let _ = timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;
		String::from_utf8_lossy(&answer).to_string()
	}

	#[tokio::test]
	async fn a_request_is_forwarded_with_the_clients_address_signed() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |_| {}).await;
		let answer = raw(mirror, &post("/sub", "application/json", "{\"v\":1}")).await;
		assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
		assert!(answer.contains("Content-Type: application/jose\r\n") && answer.contains("Cache-Control: no-store\r\n"));
		assert!(answer.ends_with("\r\n\r\nsigned-document"));
		let seen = upstream.seen.lock().unwrap().clone();
		assert_eq!(seen.len(), 1);
		assert!(seen[0].starts_with("POST /panel/sub HTTP/1.0\r\nHost: localhost:"));
		assert!(seen[0].ends_with("\r\n\r\n{\"v\":1}"));
		assert!(!seen[0].contains("X-Forwarded-For") && !seen[0].contains("198.51.100.5\r\n"), "nothing of the visitor's headers goes on");
		let signed = seen[0].lines().find_map(|line| line.strip_prefix("X-Veilway-Mirror: ")).unwrap();
		let fields: Vec<&str> = signed.split(';').collect();
		assert_eq!(&fields[..3], &["v1", "relay", "198.51.100.5"]);
		assert!(fields[3].parse::<u64>().unwrap().abs_diff(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) < 30);
		assert_eq!(signed, header(&SECRET, "relay", "198.51.100.5".parse().unwrap(), fields[3].parse().unwrap(), fields[4], b"{\"v\":1}"));
		raw(mirror, &post("/sub", "application/json", "{\"v\":1}")).await;
		let again = upstream.seen.lock().unwrap().clone();
		assert_ne!(again[0].split("X-Veilway-Mirror: ").nth(1).unwrap().split(';').nth(4), again[1].split("X-Veilway-Mirror: ").nth(1).unwrap().split(';').nth(4), "a new nonce each time");
	}

	#[tokio::test]
	async fn only_a_200_document_is_passed_on() {
		let signed_refusal = fake(200, "application/jose", "signed refusal").await;
		let mirror = start(&signed_refusal, |_| {}).await;
		assert!(raw(mirror, &post("/sub", "application/json", "{}")).await.ends_with("\r\n\r\nsigned refusal"), "a signed refusal is a document");
		for (status, kind) in [(404, "application/jose"), (500, "application/jose"), (200, "text/html"), (200, "application/json"), (200, "text/plain")] {
			let upstream = fake(status, kind, "panel says no").await;
			let mirror = start(&upstream, |_| {}).await;
			assert_eq!(raw(mirror, &post("/sub", "application/json", "{}")).await, HAND_BACK_ANSWER, "{status} {kind}");
			assert_eq!(upstream.seen.lock().unwrap().len(), 1);
		}
	}

	#[tokio::test]
	async fn an_http_1_0_request_with_a_length_is_forwarded() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |_| {}).await;
		let answer = raw(mirror, &post("/sub", "application/json", "{\"v\":1}").replacen("HTTP/1.1", "HTTP/1.0", 1)).await;
		assert!(answer.starts_with("HTTP/1.1 200 OK\r\n") && answer.ends_with("\r\n\r\nsigned-document"), "{answer}");
	}

	#[tokio::test]
	async fn everything_else_is_handed_back_and_never_forwarded() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |_| {}).await;
		for request in [post("/sub", "application/json", "{}").replacen("POST", "GET", 1), post("/elsewhere", "application/json", "{}"), post("/sub", "text/plain", "{}"), post("/sub", "application/json", &"x".repeat(1025)), "garbage\r\n\r\n".into()] {
			let answer = raw(mirror, &request).await;
			assert_eq!(answer, "HTTP/1.1 599 Hand Back\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "{request:?}");
		}
		assert!(upstream.seen.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn a_refused_body_is_read_so_that_its_answer_arrives() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |_| {}).await;
		assert_eq!(raw(mirror, &post("/sub", "text/plain", &"x".repeat(8000))).await, HAND_BACK_ANSWER);
	}

	#[tokio::test]
	async fn a_full_table_is_answered_and_nothing_is_relayed() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |_| {}).await;
		let mut held = Vec::new();
		for _ in 0..CONNECTIONS {held.push(TcpStream::connect(mirror).await.unwrap())}
		assert_eq!(raw(mirror, &post("/sub", "application/json", "{}")).await, HAND_BACK_ANSWER);
		assert!(upstream.seen.lock().unwrap().is_empty());
		drop(held);
	}

	#[tokio::test]
	async fn a_peer_that_is_no_trusted_proxy_gets_nothing() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |config| config["trusted_proxies"] = json!(["10.0.0.0/8"])).await;
		assert_eq!(raw(mirror, &post("/sub", "application/json", "{}")).await, "");
		assert!(upstream.seen.lock().unwrap().is_empty());
	}

	#[tokio::test]
	async fn without_a_web_server_the_mirror_answers_for_itself() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |config| config["trusted_proxies"] = json!([])).await;
		assert!(raw(mirror, "GET / HTTP/1.1\r\nHost: m.test\r\n\r\n").await.starts_with("HTTP/1.1 404 Not Found\r\n"));
		assert!(raw(mirror, &post("/sub", "application/json", "{}")).await.ends_with("signed-document"));
		assert!(upstream.seen.lock().unwrap()[0].contains("X-Veilway-Mirror: v1;relay;127.0.0.1;"), "the peer is the client when no proxy is trusted");
	}

	#[tokio::test]
	async fn the_upstream_is_held_to_its_chain_and_its_pins() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let pinned = start(&upstream, |config| config["upstream_pins"] = json!([upstream.pin()])).await;
		assert!(raw(pinned, &post("/sub", "application/json", "{}")).await.ends_with("signed-document"), "a pin that matches");
		let mismatch = start(&upstream, |config| config["upstream_pins"] = json!([STANDARD.encode([0u8; 32])])).await;
		assert!(raw(mismatch, &post("/sub", "application/json", "{}")).await.starts_with("HTTP/1.1 599"), "a pin that does not match");
		let (stranger, count) = (fake(200, "application/jose", "x").await, upstream.seen.lock().unwrap().len());
		let unknown = start(&upstream, |config| config["upstream"] = json!(stranger.url())).await;
		assert!(raw(unknown, &post("/sub", "application/json", "{}")).await.starts_with("HTTP/1.1 599"), "a chain that leads to no root held");
		assert_eq!(upstream.seen.lock().unwrap().len(), count);
		assert!(stranger.seen.lock().unwrap().is_empty(), "no byte of a request goes to a server that failed the check");
	}

	#[tokio::test]
	async fn an_upstream_that_is_down_is_handed_back() {
		let upstream = fake(200, "application/jose", "signed-document").await;
		let mirror = start(&upstream, |config| config["upstream"] = json!("https://localhost:1/panel/sub")).await;
		assert!(raw(mirror, &post("/sub", "application/json", "{}")).await.starts_with("HTTP/1.1 599"));
	}
}
