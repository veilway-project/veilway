//! The ClientHello of `tls`, `ws` and `fronted`: a current Chrome's, made by BoringSSL, the library Chrome uses, so that a censor that reads the first flight sees a common browser and not the Rust TLS library's own (threat model, "Client TLS fingerprint").
//! This module only decides how a handshake is sent. Who is trusted stays in `tls`: the handshake here runs with BoringSSL's own chain check off, and `tls::dial` holds the chain, the name, the dates and the pins to the same checks as before, with the same library, before a byte of application data is sent or read. The handshake's signature is still verified by BoringSSL against the leaf's key.
//! What is matched: the cipher suites in Chrome's order, GREASE in every place Chrome puts it, extensions in a random order (as Chrome does since 110, so JA3 varies and JA4 does not), X25519MLKEM768 first among the groups with its key share next to X25519's, the signature algorithms in Chrome's order, status request, signed certificate timestamps, Brotli certificate compression, and ECH GREASE. ALPS is not sent: Chrome sends it only for a protocol in its ALPN list, and this list is `http/1.1` alone. The one thing that is not Chrome's is the ALPN: `http/1.1` alone, because this client speaks nothing else and a server that picked `h2` would break it. That is Chrome's own list for a WebSocket, and the `h1` in JA4 says so. A `fronted` session is an HTTP/1.1 client in a place where Chrome would say `h2`: that part is open.
//! A browser's hello is right for one release. The values here are Chrome 131 and later (the ML-KEM group), and a new Chrome that changes them is a change in this file and its test.
#![allow(unsafe_code)]
use boring::error::ErrorStack;
use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslSignatureAlgorithm, SslVerifyMode, SslVersion};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

// A certificate chain larger than this is not a certificate chain: the library checks the length the peer declared against what comes out.
const LARGEST_CHAIN: u64 = 1 << 20;

struct Brotli;

impl CertificateCompressor for Brotli {
	const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
	const CAN_COMPRESS: bool = false;
	const CAN_DECOMPRESS: bool = true;
	fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {io::copy(&mut brotli::Decompressor::new(input, 4096).take(LARGEST_CHAIN), output).map(|_| ())}
}

static CONTEXT: OnceLock<SslContext> = OnceLock::new();

/// The context every handshake of this crate is made from, built on first use. It has the settings of `SslConnector::builder` but not its default verify paths: BoringSSL's chain check is off, and `tls::dial` does the chain check afterwards from the roots it is given.
pub(crate) fn context() -> Result<&'static SslContext, ErrorStack> {
	if let Some(context) = CONTEXT.get() {return Ok(context)}
	let mut builder = SslContextBuilder::new(SslMethod::tls())?;
	builder.set_options((SslOptions::ALL | SslOptions::NO_COMPRESSION | SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::SINGLE_DH_USE | SslOptions::SINGLE_ECDH_USE) & !SslOptions::DONT_INSERT_EMPTY_FRAGMENTS);
	builder.set_mode(SslMode::AUTO_RETRY | SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE | SslMode::RELEASE_BUFFERS);
	builder.set_verify(SslVerifyMode::NONE);
	builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
	builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
	builder.set_grease_enabled(true);
	builder.set_permute_extensions(true);
	builder.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA")?;
	builder.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;
	builder.set_verify_algorithm_prefs(&[SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256, SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256, SslSignatureAlgorithm::RSA_PKCS1_SHA256, SslSignatureAlgorithm::ECDSA_SECP384R1_SHA384, SslSignatureAlgorithm::RSA_PSS_RSAE_SHA384, SslSignatureAlgorithm::RSA_PKCS1_SHA384, SslSignatureAlgorithm::RSA_PSS_RSAE_SHA512, SslSignatureAlgorithm::RSA_PKCS1_SHA512])?;
	builder.enable_ocsp_stapling();
	builder.enable_signed_cert_timestamps();
	builder.add_certificate_compression_algorithm(Brotli)?;
	Ok(CONTEXT.get_or_init(|| builder.build()))
}

/// One handshake's `Ssl`. `domain` is the server name when `sni` is set, and is sent as it is.
pub(crate) fn ssl(context: &SslContext, domain: &str, sni: bool) -> Result<Ssl, ErrorStack> {
	let mut ssl = Ssl::new(context)?;
	if sni {ssl.set_hostname(domain)?}
	ssl.set_alpn_protos(b"\x08http/1.1")?;
	ssl.set_enable_ech_grease(true);
	Ok(ssl)
}

/// An open session. The library reads the end of a connection that came without a `close_notify` as a clean end, and a caller here must tell the two apart (the end in order is a refusal, a cut is the path's doing), so a read that ends with none having come is `UnexpectedEof`, as rustls reports it.
pub(crate) struct Stream(pub(crate) SslStream<TcpStream>);

impl AsyncRead for Stream {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let before = buf.filled().len();
		let ready = Pin::new(&mut self.0).poll_read(cx, buf);
		// SAFETY: the SSL is live for as long as the stream is, and this only reads its state.
		if matches!(ready, Poll::Ready(Ok(()))) && buf.filled().len() == before && buf.remaining() > 0 && unsafe {boring_sys::SSL_get_shutdown(self.0.ssl().as_ptr())} & boring_sys::SSL_RECEIVED_SHUTDOWN == 0 {return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))}
		ready
	}
}

impl AsyncWrite for Stream {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {Pin::new(&mut self.0).poll_write(cx, buf)}
	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.0).poll_flush(cx)}
	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.0).poll_shutdown(cx)}
}
