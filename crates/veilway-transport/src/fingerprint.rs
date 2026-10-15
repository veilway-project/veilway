//! The ClientHello of `tls`, `ws` and `fronted`: a current Chrome's, made by BoringSSL, the library Chrome uses, so that a censor that reads the first flight sees a common browser and not the Rust TLS library's own (threat model, "Client TLS fingerprint").
//! This module only decides how a handshake is sent. Who is trusted stays in `tls`: the handshake here runs with BoringSSL's own chain check off, and `tls::dial` holds the chain, the name, the dates and the pins to the same checks as before, with the same library, before a byte of application data is sent or read. The handshake's signature is still verified by BoringSSL against the leaf's key.
//! What is matched: the cipher suites in Chrome's order, GREASE in every place Chrome puts it, extensions in a random order (as Chrome does since 110, so JA3 varies and JA4 does not), X25519MLKEM768 first among the groups with its key share next to X25519's, the signature algorithms in Chrome's order, status request, signed certificate timestamps, Brotli certificate compression, ALPS (the new codepoint), and ECH GREASE. The one thing that is not Chrome's is the ALPN: `http/1.1` alone, because this client speaks nothing else and a server that picked `h2` would break it. That is Chrome's own list for a WebSocket, and the `h1` in JA4 says so. A `fronted` session is an HTTP/1.1 client in a place where Chrome would say `h2`: that part is open.
//! A browser's hello is right for one release. The values here are Chrome 131 and later (the ML-KEM group, the ALPS codepoint), and a new Chrome that changes them is a change in this file and its test.
#![allow(unsafe_code)]
use boring::error::ErrorStack;
use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslConnector, SslMethod, SslSignatureAlgorithm, SslVerifyMode, SslVersion};
use foreign_types::ForeignTypeRef;
use std::io::{self, Read, Write};
use std::pin::Pin;
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

/// The context every handshake of this crate is made from. BoringSSL's own chain check is off: `tls::dial` does it afterwards.
pub(crate) fn connector() -> Result<SslConnector, ErrorStack> {
	let mut builder = SslConnector::builder(SslMethod::tls())?;
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
	builder.set_alpn_protos(b"\x08http/1.1")?;
	Ok(builder.build())
}

/// One handshake's `Ssl`. `domain` is the server name when `sni` is set, and is sent as it is.
pub(crate) fn ssl(connector: &SslConnector, domain: &str, sni: bool) -> Result<Ssl, ErrorStack> {
	let ssl = connector.configure()?.use_server_name_indication(sni).verify_hostname(false).into_ssl(domain)?;
	ssl.set_enable_ech_grease(true);
	// ALPS is a setting the library has no safe call for. "h2" with no settings is what Chrome sends; it is only advertised, a server that answers it gets nothing back.
	// SAFETY: `ssl` is a live SSL, and the pointers are valid for the lengths given for the time of the calls, which copy them.
	let added = unsafe {
		boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 1);
		boring_sys::SSL_add_application_settings(ssl.as_ptr(), b"h2".as_ptr(), 2, std::ptr::null(), 0)
	};
	if added != 1 {return Err(ErrorStack::get())}
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
