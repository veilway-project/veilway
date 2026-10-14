//! TLS to a candidate, for `tls`, `ws` and `fronted` (transports page, "`tls`", "`ws`", "Fronting options"; overview, fail-closed rule 4).
//!
//! A candidate is held to one of two checks, chosen by the candidate in the signed profile and never by the server.
//! - From an authority, the default: the chain leads to one of the caller's roots and is valid at the time the device's clock shows, for the candidate's `sni`, or for its `verify_name` when no server name is sent. On a candidate with pins, also: the SHA-256 of the leaf's SubjectPublicKeyInfo is one of them, and TLS 1.3 was negotiated.
//!   A pin is a second condition here and never a first one: a certificate that matches a pin and does not validate is refused, and so is one that validates and matches none. A certificate that signed itself is therefore refused with its pin. The one way such a certificate passes this check is as a root itself: the library takes a certificate in the root store as a trust anchor whatever it says of itself. That is the caller's doing, with the root store, and no pin brings it about.
//! - Self-signed, only where the candidate's `self_signed` is true: the leaf's key must match a pin, TLS 1.3 is required, and the chain, the name and the dates are not looked at. The handshake's signature is still verified against that pinned key, by the library's own verification for TLS 1.3, so a server that shows the pinned certificate without holding its key fails. The root store plays no part.
//!
//! Nothing here can skip a check, and no failure is tried again with fewer. Validity is held against the system's clock, never against a clock offset: an offset comes from a `Date`, and a `Date` is read only behind a certificate that was accepted.
//! The dial address, the server name and the `Host` of the request are three fields of a candidate and are used as that: the address is dialled as it is, with no lookup. The protocol offered is `http/1.1` alone, which is one more thing the handshake can be known by.
use crate::{End, Ended, Front, Hook, Refuse, Unreachable};
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::version::{TLS12, TLS13};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use socket2::SockRef;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

const UNPINNED: rustls::Error = rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);

// The key of a leaf, when its SHA-256 is one of the pins.
fn pinned(end_entity: &CertificateDer<'_>, pins: &[[u8; 32]]) -> Result<SubjectPublicKeyInfoDer<'static>, rustls::Error> {
	let key = ParsedCertificate::try_from(end_entity)?.subject_public_key_info();
	let hash = digest(&SHA256, key.as_ref());
	if pins.iter().any(|pin| pin == hash.as_ref()) {Ok(key)} else {Err(UNPINNED)}
}

// The library's own verifier, and behind it the pins: a certificate it refuses is refused, and one it accepts is held against the pins.
#[derive(Debug)]
struct Pinned {inner: Arc<WebPkiServerVerifier>, pins: Vec<[u8; 32]>}

impl ServerCertVerifier for Pinned {
	fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp_response: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
		let verified = self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
		pinned(end_entity, &self.pins).map(|_| verified)
	}
	fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {self.inner.verify_tls12_signature(message, cert, dss)}
	fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {self.inner.verify_tls13_signature(message, cert, dss)}
	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {self.inner.supported_verify_schemes()}
}

// A self-signed candidate's check: the pins, and nothing of the chain, the name or the dates. The handshake's signature is verified against the pinned key itself, with the library's function for TLS 1.3 and the signature schemes of its provider. TLS 1.2 is never offered to such a candidate, and a signature of it is refused.
#[derive(Debug)]
struct Alone {pins: Vec<[u8; 32]>, algorithms: WebPkiSupportedAlgorithms}

impl ServerCertVerifier for Alone {
	fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {pinned(end_entity, &self.pins).map(|_| ServerCertVerified::assertion())}
	fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {Err(UNPINNED)}
	fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {verify_tls13_signature_with_raw_key(message, &pinned(cert, &self.pins)?, dss, &self.algorithms)}
	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {self.algorithms.supported_schemes()}
}

/// The TLS config of an endpoint that is held to its pins alone: the check of a self-signed candidate, for the subscription page's "A pinned endpoint". TLS 1.3 only, the pin and the handshake's signature under the pinned key, no chain, no name and no date, no early data and no resumed session, so that every fetch shows its certificate. `sni` says whether a server name is sent: a host name is, an IP literal is not.
pub fn pin_only(pins: &[[u8; 32]], sni: bool) -> Result<ClientConfig, rustls::Error> {
	if pins.is_empty() {return Err(UNPINNED)}
	let provider = Arc::new(default_provider());
	let algorithms = provider.signature_verification_algorithms;
	let mut config = ClientConfig::builder_with_provider(provider).with_protocol_versions(&[&TLS13])?.dangerous().with_custom_certificate_verifier(Arc::new(Alone {pins: pins.to_vec(), algorithms})).with_no_client_auth();
	(config.enable_sni, config.enable_early_data, config.resumption, config.alpn_protocols) = (sni, false, rustls::client::Resumption::disabled(), vec![b"http/1.1".to_vec()]);
	Ok(config)
}

/// The name a candidate's certificate must be valid for: its `sni`, or its `verify_name` when no server name is sent. A host name, and never an address.
/// A self-signed candidate is held to no name. One without a `sni` is given the address it dials, because the library connects to a name: an address is never sent as a server name, and the check of such a candidate does not read it.
pub(crate) fn name(candidate: &Front) -> Result<ServerName<'static>, Refuse> {
	if candidate.self_signed && candidate.sni.is_none() {return Ok(ServerName::IpAddress(candidate.address.ip().into()))}
	candidate.sni.as_ref().or(candidate.verify_name.as_ref()).and_then(|name| ServerName::try_from(name.clone()).ok()).filter(|name| matches!(name, ServerName::DnsName(_))).ok_or(Refuse::Name)
}

/// The `Host` of a request to a candidate: its `host`, with the port of the dial address when that is not the one `https` implies.
pub(crate) fn host(candidate: &Front) -> String {if candidate.address.port() == 443 {candidate.host.clone()} else {format!("{}:{}", candidate.host, candidate.address.port())}}

/// A TCP connection to the candidate's address and a TLS handshake on it, both before `deadline`. What comes back has passed every check of this module's head, or nothing comes back.
/// A device that has no socket, no address or no route to dial with is `Offline`, and so is one whose `hook` refused the socket: neither says anything about the candidate.
pub(crate) async fn dial(candidate: &Front, roots: &Arc<RootCertStore>, hook: &Option<Hook>, deadline: Instant) -> Result<TlsStream<TcpStream>, Ended> {
	let (name, provider, pinned) = (name(candidate).map_err(|_| Ended::Unreachable(Unreachable::Certificate))?, Arc::new(default_provider()), !candidate.pins.is_empty());
	let algorithms = provider.signature_verification_algorithms;
	// "The client requires TLS 1.3 on a pinned candidate and accepts what the CDN negotiates otherwise." A self-signed candidate is a pinned one.
	let versions = if pinned {&[&TLS13][..]} else {&[&TLS13, &TLS12][..]};
	let builder = ClientConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).map_err(|_| Ended::Unreachable(Unreachable::Tls))?;
	// The library's `dangerous` door is used twice. With pins on a certificate from an authority it adds a check: the verifier is the library's own with the pins behind it. On a candidate the signed profile marks self-signed it puts the pins in the place of the chain, and only there: what the server sends never makes a candidate one of these.
	let mut config = if candidate.self_signed && pinned {builder.dangerous().with_custom_certificate_verifier(Arc::new(Alone {pins: candidate.pins.clone(), algorithms})).with_no_client_auth()} else {
		// An empty root store was refused before this was called. Should one get here, it is no check passed.
		let verifier = WebPkiServerVerifier::builder_with_provider(roots.clone(), provider).build().map_err(|_| Ended::Unreachable(Unreachable::Certificate))?;
		if pinned {builder.dangerous().with_custom_certificate_verifier(Arc::new(Pinned {inner: verifier, pins: candidate.pins.clone()})).with_no_client_auth()} else {builder.with_webpki_verifier(verifier).with_no_client_auth()}
	};
	// "Empty means no server name is sent."
	(config.enable_sni, config.alpn_protocols) = (candidate.sni.is_some(), vec![b"http/1.1".to_vec()]);
	let socket = if candidate.address.is_ipv4() {TcpSocket::new_v4()} else {TcpSocket::new_v6()}.map_err(|_| End::Offline)?;
	if let Some(hook) = hook {hook(SockRef::from(&socket)).map_err(|_| End::Offline)?}
	let stream = match timeout_at(deadline, socket.connect(candidate.address)).await {
		Ok(Ok(stream)) => stream,
		Ok(Err(error)) if matches!(error.kind(), ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable | ErrorKind::NetworkDown) => return Err(End::Offline.into()),
		Ok(Err(_)) => return Err(Ended::Unreachable(Unreachable::Connect)),
		Err(_) => return Err(Ended::Unreachable(Unreachable::Timeout)),
	};
	let _ = stream.set_nodelay(true);
	match timeout_at(deadline, TlsConnector::from(Arc::new(config)).connect(name, stream)).await {
		Ok(Ok(stream)) => Ok(stream),
		Ok(Err(error)) => Err(Ended::Unreachable(match error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
			Some(rustls::Error::InvalidCertificate(CertificateError::Expired | CertificateError::NotValidYet | CertificateError::ExpiredContext {..} | CertificateError::NotValidYetContext {..})) => Unreachable::CertificateTime,
			Some(rustls::Error::InvalidCertificate(_)) => Unreachable::Certificate,
			_ => Unreachable::Tls,
		})),
		Err(_) => Err(Ended::Unreachable(Unreachable::Timeout)),
	}
}
