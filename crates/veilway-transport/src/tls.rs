//! TLS to a candidate, for `tls`, `ws` and `fronted` (transports page, "`tls`", "`ws`", "Fronting options"; overview, fail-closed rule 4).
//!
//! A candidate is held to one of two checks, chosen by the candidate in the signed profile and never by the server.
//! - From an authority, the default: the chain leads to one of the caller's roots and is valid at the time the device's clock shows, for the candidate's `sni`, or for its `verify_name` when no server name is sent. On a candidate with pins, also: the SHA-256 of the leaf's SubjectPublicKeyInfo is one of them, and TLS 1.3 was negotiated.
//!   A pin is a second condition here and never a first one: a certificate that matches a pin and does not validate is refused, and so is one that validates and matches none. A certificate that signed itself is therefore refused with its pin. The one way such a certificate passes this check is as a root itself: the library takes a certificate in the root store as a trust anchor whatever it says of itself. That is the caller's doing, with the root store, and no pin brings it about.
//! - Self-signed, only where the candidate's `self_signed` is true: the leaf's key must match a pin, TLS 1.3 is required, and the chain, the name and the dates are not looked at. The handshake's signature is still verified against that pinned key, by the library's own verification for TLS 1.3, so a server that shows the pinned certificate without holding its key fails. The root store plays no part.
//!
//! Nothing here can skip a check, and no failure is tried again with fewer. Validity is held against the system's clock, never against a clock offset: an offset comes from a `Date`, and a `Date` is read only behind a certificate that was accepted.
//! The dial address, the server name and the `Host` of the request are three fields of a candidate and are used as that: the address is dialled as it is, with no lookup. The protocol offered is `http/1.1` alone. The hello is a browser's, made by BoringSSL (`fingerprint.rs`), and the checks below run on what it brought back, the suite included: it must be key-agreed with an AEAD (`acceptable_cipher`).
use crate::fingerprint::{self, Stream};
use crate::{offline, Ended, Front, Hook, Refuse, Unreachable};
use boring::ssl::SslVersion;
use ring::digest::{digest, SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::version::TLS13;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use socket2::SockRef;
use std::error::Error;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{timeout_at, Instant};
use tokio_boring::SslStreamBuilder;

const UNPINNED: rustls::Error = rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);

// The suites a handshake may end on: TLS 1.3's, which are all AEAD with a key agreement, and ECDHE with an AEAD. RSA key exchange and CBC are refused whatever the server picks.
fn acceptable_cipher(name: &str) -> bool {name.starts_with("TLS_") || (name.starts_with("ECDHE-") && (name.contains("GCM") || name.contains("POLY1305")))}

// The key of a leaf, when its SHA-256 is one of the pins.
fn pinned_key(end_entity: &CertificateDer<'_>, pins: &[[u8; 32]]) -> Result<SubjectPublicKeyInfoDer<'static>, rustls::Error> {
	let key = ParsedCertificate::try_from(end_entity)?.subject_public_key_info();
	let hash = digest(&SHA256, key.as_ref());
	if pins.iter().any(|pin| pin == hash.as_ref()) {Ok(key)} else {Err(UNPINNED)}
}

// A self-signed candidate's check: the pins, and nothing of the chain, the name or the dates. The handshake's signature is verified against the pinned key itself, with the library's function for TLS 1.3 and the signature schemes of its provider. TLS 1.2 is never offered to such a candidate, and a signature of it is refused.
#[derive(Debug)]
struct Alone {pins: Vec<[u8; 32]>, algorithms: WebPkiSupportedAlgorithms}

impl ServerCertVerifier for Alone {
	fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {pinned_key(end_entity, &self.pins).map(|_| ServerCertVerified::assertion())}
	fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {Err(UNPINNED)}
	fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {verify_tls13_signature_with_raw_key(message, &pinned_key(cert, &self.pins)?, dss, &self.algorithms)}
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

/// A TCP connection to the candidate's address before `deadline`, with the caller's hook run on the socket first and `TCP_NODELAY` on. The same `Offline` rule as `dial`'s: no route, no socket or a failed hook says nothing about the candidate. With `Front::connect` the connection comes from it, and its failure is what it says (see `Connect`).
pub(crate) async fn tcp(candidate: &Front, hook: &Option<Hook>, deadline: Instant) -> Result<TcpStream, Ended> {
	let stream = match &candidate.connect {
		Some(connect) => connect(candidate.address, deadline).await?,
		None => {
			let socket = if candidate.address.is_ipv4() {TcpSocket::new_v4()} else {TcpSocket::new_v6()}.map_err(|error| offline(&error))?;
			if let Some(hook) = hook {hook(SockRef::from(&socket)).map_err(|error| offline(&error))?}
			match timeout_at(deadline, socket.connect(candidate.address)).await {
				Ok(Ok(stream)) => stream,
				Ok(Err(error)) if matches!(error.kind(), ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable | ErrorKind::NetworkDown) => return Err(offline(&error).into()),
				Ok(Err(_)) => return Err(Ended::Unreachable(Unreachable::Connect)),
				Err(_) => return Err(Ended::Unreachable(Unreachable::Timeout)),
			}
		}
	};
	let _ = stream.set_nodelay(true);
	Ok(stream)
}

/// A TCP connection to the candidate's address and a TLS handshake on it, both before `deadline`. What comes back has passed every check of this module's head, or nothing comes back.
/// A device that has no socket, no address or no route to dial with is `Offline`, and so is one whose `hook` refused the socket: neither says anything about the candidate.
/// The handshake is a browser's (`fingerprint.rs`) and runs with the library's own chain check off. The checks run on what the server sent before this returns, so no byte of application data goes either way before they pass, and they are the same ones as ever: the chain, the name and the dates by rustls's verifier, the pins behind it, or for a self-signed candidate the pins alone.
pub(crate) async fn dial(candidate: &Front, roots: &Arc<RootCertStore>, hook: &Option<Hook>, deadline: Instant, h2: bool) -> Result<Stream, Ended> {
	let (name, pinned, tls) = (name(candidate).map_err(|_| Ended::Unreachable(Unreachable::Certificate))?, !candidate.pins.is_empty(), || Ended::Unreachable(Unreachable::Tls));
	// An empty root store was refused before this was called. Should one get here, it is no check passed.
	let verifier = if candidate.self_signed && pinned {None} else {Some(WebPkiServerVerifier::builder_with_provider(roots.clone(), Arc::new(default_provider())).build().map_err(|_| Ended::Unreachable(Unreachable::Certificate))?)};
	// "Empty means no server name is sent."
	let ssl = fingerprint::context().and_then(|context| fingerprint::ssl(context, &name.to_str(), candidate.sni.is_some(), h2)).map_err(|_| tls())?;
	let stream = tcp(candidate, hook, deadline).await?;
	let stream = match timeout_at(deadline, SslStreamBuilder::new(ssl, stream).connect()).await {
		Ok(Ok(stream)) => stream,
		// A server that shows the pinned certificate without its key fails here, in the handshake's signature. The library's reason is read from its error stack.
		Ok(Err(error)) => {
			let bad_signature = error.source().and_then(|source| source.downcast_ref::<boring::ssl::Error>()).and_then(|cause| cause.ssl_error()).is_some_and(|stack| stack.errors().iter().any(|error| error.library_reason(boring_sys::ERR_LIB_SSL) == Some(boring_sys::SSL_R_BAD_SIGNATURE)));
			return Err(if bad_signature {Ended::Unreachable(Unreachable::Certificate)} else {tls()})
		}
		Err(_) => return Err(Ended::Unreachable(Unreachable::Timeout)),
	};
	// "The client requires TLS 1.3 on a pinned candidate and accepts what the CDN negotiates otherwise." A self-signed candidate is a pinned one. The hello offers 1.2 as a browser's does, so a downgrade is refused here.
	if pinned && stream.ssl().version2() != Some(SslVersion::TLS1_3) {return Err(tls())}
	if !stream.ssl().current_cipher().is_some_and(|cipher| acceptable_cipher(cipher.name())) {return Err(tls())}
	// With `h2` offered the server picks `h2` or `http/1.1`, and anything else, or nothing, ends the attempt.
	if h2 && !stream.ssl().selected_alpn_protocol().is_some_and(|alpn| alpn == b"h2" || alpn == b"http/1.1") {return Err(tls())}
	let ssl = stream.ssl();
	let (Some(leaf), Some(chain)) = (ssl.peer_certificate().and_then(|leaf| leaf.to_der().ok()), ssl.peer_cert_chain()) else {return Err(Ended::Unreachable(Unreachable::Certificate))};
	let leaf = CertificateDer::from(leaf);
	let others = chain.iter().filter_map(|cert| cert.to_der().ok()).filter(|der| der.as_slice() != leaf.as_ref()).map(CertificateDer::from).collect::<Vec<_>>();
	// The library's `dangerous` door is used once, and by `Alone`. With pins on a certificate from an authority the verifier's answer is held against the pins as well. On a candidate the signed profile marks self-signed the pins stand in place of the chain, and only there: what the server sends never makes a candidate one of these.
	let verdict = match &verifier {
		Some(verifier) => verifier.verify_server_cert(&leaf, &others, &name, &[], UnixTime::now()).and_then(|_| if pinned {pinned_key(&leaf, &candidate.pins).map(|_| ())} else {Ok(())}),
		None => pinned_key(&leaf, &candidate.pins).map(|_| ()),
	};
	match verdict {
		Ok(()) => Ok(Stream(stream)),
		Err(rustls::Error::InvalidCertificate(CertificateError::Expired | CertificateError::NotValidYet | CertificateError::ExpiredContext {..} | CertificateError::NotValidYetContext {..})) => Err(Ended::Unreachable(Unreachable::CertificateTime)),
		Err(rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)) => Err(Ended::Unreachable(Unreachable::Pin)),
		Err(rustls::Error::InvalidCertificate(_)) => Err(Ended::Unreachable(Unreachable::Certificate)),
		Err(_) => Err(tls()),
	}
}

#[cfg(test)]
mod tests {
	use super::acceptable_cipher;

	#[test]
	fn a_suite_is_accepted_only_with_key_agreement_and_an_aead() {
		for (name, accepted) in [("TLS_AES_128_GCM_SHA256", true), ("TLS_CHACHA20_POLY1305_SHA256", true), ("ECDHE-ECDSA-AES128-GCM-SHA256", true), ("ECDHE-RSA-CHACHA20-POLY1305", true), ("ECDHE-RSA-AES128-SHA", false), ("ECDHE-RSA-AES256-SHA384", false), ("AES128-GCM-SHA256", false), ("DHE-RSA-AES128-GCM-SHA256", false)] {assert_eq!(acceptable_cipher(name), accepted, "{name}")}
	}
}
