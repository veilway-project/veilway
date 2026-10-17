//! The client of `faketls` (borrowed-site page, "What the client puts in its hello", "How the client knows the node", "The session").
//!
//! The hello is the one BoringSSL writes for `tls` (`fingerprint.rs`), captured without a server, with `X` and the carrier put into it. BoringSSL cannot go on after a hello it did not write whole, so the TLS 1.3 handshake behind it is this module's: the two suites and the one group the node answers with, the key schedule of RFC 8446 section 7.1 over `ring`, and nothing else. A HelloRetryRequest, another suite, another group and another signature scheme end the attempt.
//! What the node sends is held to the page's rule and to nothing more: the leaf's public key must be the one the client derives, and then the CertificateVerify and the Finished must verify under it. The leaf's name, chain and dates are not looked at, and no root is read. A leaf with another key is a `Unreachable::Certificate`, and nothing about it is authenticated: the client finishes the handshake, sends a `close_notify` and no application data, and closes.
//! After the handshake the TLS record layer is the only encryption. A frame is a 2 byte length and a chunk plaintext (`chunk::write`), one frame in one record, and the activity and keepalive rules are those of `stream.rs`.
//! Every byte from the network is hostile: records are bounded before they are waited for, a handshake message is bounded before it is collected, and a certificate chain is decompressed to the length it declared and no further.
use crate::fingerprint;
use crate::{lone, pause, random, tls, unasked, wide, Answer, Ask, End, Ended, Fault, Front, Kind, Link, Port, Refusal, State, Unreachable, Want, ATTEMPT};
use boring::ssl::HandshakeError;
use ring::{aead, digest, hkdf, hmac, signature};
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::{sleep_until, timeout, timeout_at, Instant};
use veilway_proto::chunk::{self, Padding, MAX_ITEMS, MAX_PLAINTEXT};
use veilway_proto::faketls::{CarryError, Client};
use veilway_proto::session::{LIVENESS, LONE_KEEPALIVE};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// "Either side sends a TLS `close_notify`, waits up to 5 s for the other, and closes TCP."
const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// What RFC 8446 section 5.2 allows a record to hold, and the 256 bytes it allows an encrypted one to grow by.
const RECORD: usize = 16_384 + 256;
/// A handshake message beyond this is not collected. A chain is about 10 KB, and a compressed one is far smaller on the wire.
const MESSAGE: usize = 1 << 17;
/// A certificate chain that decompresses beyond this is not a chain.
const LARGEST_CHAIN: usize = 1 << 20;
/// RFC 8446 section 4.1.3: the `random` that makes a ServerHello a HelloRetryRequest, SHA-256 of "HelloRetryRequest".
const HELLO_RETRY: [u8; 32] = [0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c];
const TLS: Ended = Ended::Unreachable(Unreachable::Tls);
/// The leaf was not the one the client derives, or its signature did not verify under it.
const MISMATCH: Ended = Ended::Unreachable(Unreachable::Certificate);
// "It keeps the `X` of its last 4,096 seals in memory, and the seal function refuses an `X` on that list, ends the attempt with an internal error, and counts it."
static REUSED: AtomicU64 = AtomicU64::new(0);

/// How many hellos were refused because their `X` was one of the last 4,096 sealed: a fault of the random source, and never expected to be above 0.
pub fn reused() -> u64 {REUSED.load(Ordering::Relaxed)}

/// The one `Client` of a link, shared by every attempt and every connection of it: its memory of sealed key shares is the backstop of "Every seal gets a fresh `x`" only if it outlives the attempt. None for a link without a node transport key.
pub fn client(link: &Link) -> Option<Arc<Mutex<Client>>> {link.node.map(|node| Arc::new(Mutex::new(Client::new(&node, link.secret.expose(), &link.inbound, &link.device))))}

/// Bytes of a message, read from the front. Every read is checked, and a read past the end is `None`.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
	fn take(&mut self, count: usize) -> Option<&'a [u8]> {
		let (head, tail) = self.0.split_at_checked(count)?;
		self.0 = tail;
		Some(head)
	}
	/// A big-endian integer of `width` bytes.
	fn uint(&mut self, width: usize) -> Option<usize> {self.take(width).map(|bytes| bytes.iter().fold(0, |sum, byte| sum << 8 | usize::from(*byte)))}
	/// The bytes behind a length of `width` bytes.
	fn var(&mut self, width: usize) -> Option<&'a [u8]> {
		let count = self.uint(width)?;
		self.take(count)
	}
}

/// What BoringSSL wrote: the hello goes nowhere, and the handshake is stopped where it would wait for the server.
struct Capture(Vec<u8>);

impl Read for Capture {
	fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {Err(io::ErrorKind::WouldBlock.into())}
}

impl io::Write for Capture {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {Ok(())}
}

// The offsets, in a ClientHello handshake message, of the standalone X25519 share and of the X25519 part of the hybrid one.
fn shares(message: &[u8]) -> Option<(usize, Option<usize>)> {
	let mut hello = Cursor(message.get(4 + 2 + 32..)?);
	hello.var(1)?;
	hello.var(2)?;
	hello.var(1)?;
	let mut extensions = Cursor(hello.var(2)?);
	let at = |bytes: &[u8]| bytes.as_ptr() as usize - message.as_ptr() as usize;
	let (mut standalone, mut hybrid) = (None, None);
	while !extensions.0.is_empty() {
		let (kind, body) = (extensions.uint(2)?, extensions.var(2)?);
		if kind != 51 {continue}
		let mut list = Cursor(Cursor(body).var(2)?);
		while !list.0.is_empty() {
			let (group, key) = (list.uint(2)?, list.var(2)?);
			match (group, key.len()) {
				(0x001d, 32) => standalone = standalone.or(Some(at(key))),
				(0x11ec, 1216) => hybrid = hybrid.or(Some(at(key) + 1184)),
				_ => {}
			}
		}
	}
	Some((standalone?, hybrid))
}

/// The record of a ClientHello for the site `name`, as Chrome would send it, with a fresh `X` and the carrier sealed into it. Also the private key `x` of `X`, and the public point of the leaf the node answers with.
/// "The client draws `x` from the system random source for every hello, including a hello sent again after a failed attempt and each of parallel connections." `X` replaces the standalone share, and the X25519 part of the hybrid share too when the capture has the two equal, as the page says. The rest of the hello is BoringSSL's.
fn hello(client: &Mutex<Client>, name: &str, now: u64) -> Result<(Vec<u8>, [u8; 32], Vec<u8>), Ended> {
	let ssl = fingerprint::context().and_then(|context| fingerprint::ssl(context, name, true, true)).map_err(|_| TLS)?;
	let Err(HandshakeError::WouldBlock(started)) = ssl.connect(Capture(Vec::new())) else {return Err(TLS)};
	let mut record = started.into_source_stream().0;
	if record.len() < 9 || record[..3] != [22, 3, 1] || usize::from(u16::from_be_bytes([record[3], record[4]])) != record.len() - 5 {return Err(TLS)}
	let (message, mut x) = (&mut record[5..], [0; 32]);
	random(&mut x).map_err(|_| End::Random)?;
	let share = x25519(x, X25519_BASEPOINT_BYTES);
	let (standalone, hybrid) = shares(message).ok_or(TLS)?;
	if let Some(hybrid) = hybrid.filter(|hybrid| message[*hybrid..*hybrid + 32] == message[standalone..standalone + 32]) {message[hybrid..hybrid + 32].copy_from_slice(&share)}
	message[standalone..standalone + 32].copy_from_slice(&share);
	let mut client = client.lock().map_err(|_| End::Source)?;
	if let Err(error) = client.carry(message, &x, now) {
		if error == CarryError::Reused {REUSED.fetch_add(1, Ordering::Relaxed);}
		tracing::error!(?error, "a faketls hello was not sealed");
		return Err(End::Random.into());
	}
	let leaf = client.leaf(&x, message).ok_or(TLS)?;
	Ok((record, x, leaf))
}

/// The TLS suites the node answers with, both with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suite {Aes, Chacha}

impl Suite {
	fn algorithm(self) -> &'static aead::Algorithm {if self == Self::Aes {&aead::AES_128_GCM} else {&aead::CHACHA20_POLY1305}}
	/// RFC 8446 section 5.5: AES-GCM is used for at most 2^24.5 records under a key, and this build has no KeyUpdate, so a session ends well before that and a new one is made.
	fn records(self) -> u64 {if self == Self::Aes {1 << 24} else {1 << 60}}
}

struct Length(usize);

impl hkdf::KeyType for Length {
	fn len(&self) -> usize {self.0}
}

// HKDF-Expand-Label of RFC 8446 section 7.1.
fn expand<const N: usize>(prk: &hkdf::Prk, label: &str, context: &[u8]) -> [u8; N] {
	let mut out = [0; N];
	prk.expand(&[&(N as u16).to_be_bytes(), &[6 + label.len() as u8], b"tls13 ", label.as_bytes(), &[context.len() as u8], context], Length(N)).and_then(|okm| okm.fill(&mut out)).expect("an output of a few dozen bytes is within the limit of HKDF-SHA-256");
	out
}

// One extract of the key schedule, with the two traffic secrets under it and the secret the next extract is salted with.
fn secrets(salt: &[u8], input: &[u8], labels: [&str; 2], transcript: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
	let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(input);
	(expand(&prk, labels[0], transcript), expand(&prk, labels[1], transcript), expand(&prk, "derived", digest::digest(&digest::SHA256, &[]).as_ref()))
}

// The handshake traffic secrets of the client and the server, and the salt of the master extract, from the key agreement and the hash of the transcript through the ServerHello.
fn handshake_secrets(shared: &[u8; 32], hello: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
	let early = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0; 32]).extract(&[0; 32]);
	secrets(&expand::<32>(&early, "derived", digest::digest(&digest::SHA256, &[]).as_ref()), shared, ["c hs traffic", "s hs traffic"], hello)
}

fn finished(secret: &[u8; 32]) -> hmac::Key {hmac::Key::new(hmac::HMAC_SHA256, &expand::<32>(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret), "finished", &[]))}

/// One direction of the record layer: the key and iv of a traffic secret, and the record number, which starts at 0 with every key.
struct Keys {key: aead::LessSafeKey, iv: [u8; 12], number: u64, limit: u64}

impl Keys {
	fn new(suite: Suite, secret: &[u8; 32]) -> Self {
		let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
		let key = if suite == Suite::Aes {expand::<16>(&prk, "key", &[]).to_vec()} else {expand::<32>(&prk, "key", &[]).to_vec()};
		Self {key: aead::LessSafeKey::new(aead::UnboundKey::new(suite.algorithm(), &key).expect("the key has the length of its algorithm")), iv: expand(&prk, "iv", &[]), number: 0, limit: suite.records()}
	}
	// RFC 8446 section 5.3: the iv xor the record number, as 64 bits big-endian padded on the left.
	fn nonce(&self) -> aead::Nonce {
		let mut nonce = self.iv;
		for (byte, counter) in nonce[4..].iter_mut().zip(self.number.to_be_bytes()) {*byte ^= counter}
		aead::Nonce::assume_unique_for_key(nonce)
	}
	/// Appends one record of content type `kind` holding `plaintext`. False when the keys have sealed all they may or the plaintext does not fit a record, and then nothing is appended.
	fn seal(&mut self, kind: u8, plaintext: &[u8], out: &mut Vec<u8>) -> bool {
		if self.number >= self.limit || plaintext.len() > 16_384 {return false}
		let (start, length) = (out.len(), plaintext.len() + 1 + 16);
		out.extend_from_slice(&[23, 3, 3, (length >> 8) as u8, length as u8]);
		out.extend_from_slice(plaintext);
		out.push(kind);
		let (header, body) = out[start..].split_at_mut(5);
		let Ok(tag) = self.key.seal_in_place_separate_tag(self.nonce(), aead::Aad::from(&*header), body) else {
			out.truncate(start);
			return false;
		};
		out.extend_from_slice(tag.as_ref());
		self.number += 1;
		true
	}
	/// Opens the body of a record whose header was `header`: the content type and the content, or None for a record that does not open or holds nothing.
	fn open<'a>(&mut self, header: &[u8; 5], body: &'a mut [u8]) -> Option<(u8, &'a [u8])> {
		if self.number >= self.limit {return None}
		let plain = &*self.key.open_in_place(self.nonce(), aead::Aad::from(&header[..]), body).ok()?;
		self.number += 1;
		let end = plain.iter().rposition(|byte| *byte != 0)?;
		Some((plain[end], &plain[..end]))
	}
}

/// The bytes of the connection, cut into records. It keeps one record at the most and what one read brought behind it, and the first fault is the caller's to end the session with.
#[derive(Default)]
struct Records {buf: Vec<u8>, done: usize}

impl Records {
	fn feed(&mut self, bytes: &[u8]) {self.buf.extend_from_slice(bytes)}
	/// The next whole record with its header, or `Ok(None)` when more bytes are needed. The verdict on a header falls before a byte of the body is waited for.
	fn next(&mut self) -> Result<Option<([u8; 5], &mut [u8])>, Fault> {
		self.buf.drain(..std::mem::take(&mut self.done));
		let Some(&[kind, major, minor, high, low]) = self.buf.first_chunk::<5>() else {return Ok(None)};
		let size = usize::from(u16::from_be_bytes([high, low]));
		// RFC 8446 section 5.1: the version of a record "MUST be ignored", so only its major byte is a check of framing.
		if !(20..=23).contains(&kind) || major != 3 || size == 0 || size > RECORD {return Err(Fault::Frame)}
		if self.buf.len() < 5 + size {return Ok(None)}
		self.done = 5 + size;
		Ok(Some(([kind, major, minor, high, low], &mut self.buf[5..5 + size])))
	}
}

// The ServerHello message, whole: the suite and the X25519 share. It must echo the session id, carry nothing but `supported_versions` and `key_share`, and not be a HelloRetryRequest.
fn server_hello(message: &[u8], session: &[u8]) -> Option<(Suite, [u8; 32])> {
	let mut outer = Cursor(message);
	let (kind, body) = (outer.uint(1)?, outer.var(3)?);
	if kind != 2 || !outer.0.is_empty() {return None}
	let mut hello = Cursor(body);
	let (version, random, echoed, id, compression) = (hello.uint(2)?, hello.take(32)?, hello.var(1)?, hello.uint(2)?, hello.uint(1)?);
	let mut extensions = Cursor(hello.var(2)?);
	if version != 0x0303 || random == HELLO_RETRY || echoed != session || compression != 0 || !hello.0.is_empty() {return None}
	let suite = match id {
		0x1301 => Suite::Aes,
		0x1303 => Suite::Chacha,
		_ => return None,
	};
	let (mut versions, mut share) = (false, None);
	while !extensions.0.is_empty() {
		let (kind, data) = (extensions.uint(2)?, extensions.var(2)?);
		match kind {
			43 if !versions && data == [3, 4] => versions = true,
			51 if share.is_none() => {
				let mut entry = Cursor(data);
				let (group, key) = (entry.uint(2)?, entry.var(2)?);
				if group != 0x001d || !entry.0.is_empty() {return None}
				share = Some(<[u8; 32]>::try_from(key).ok()?);
			}
			_ => return None,
		}
	}
	share.filter(|_| versions).map(|share| (suite, share))
}

// The first certificate of a Certificate message's body (RFC 8446 section 4.4.2), whose request context must be empty.
fn first_certificate(body: &[u8]) -> Option<&[u8]> {
	let mut message = Cursor(body);
	let (context, list) = (message.var(1)?, message.var(3)?);
	if !context.is_empty() || !message.0.is_empty() {return None}
	let mut list = Cursor(list);
	let leaf = list.var(3)?;
	list.var(2)?;
	Some(leaf)
}

// The body of the Certificate that a CompressedCertificate (RFC 8879) holds, brotli only, to the length it declared and not a byte more.
fn inflate(body: &[u8]) -> Option<Vec<u8>> {
	let mut message = Cursor(body);
	let (algorithm, size, compressed) = (message.uint(2)?, message.uint(3)?, message.var(3)?);
	if algorithm != 2 || size > LARGEST_CHAIN || !message.0.is_empty() {return None}
	let mut out = Vec::new();
	brotli::Decompressor::new(compressed, 4096).take(size as u64 + 1).read_to_end(&mut out).ok()?;
	(out.len() == size).then_some(out)
}

/// A finished handshake: the keys of both directions, what the node sent behind its Finished, and whether the leaf was the one the client derives.
struct Opened {send: Keys, receive: Keys, records: Records, matched: bool}

// The next record of the handshake. A compatibility `change_cipher_spec` (RFC 8446 appendix D.4) is passed over.
async fn record<S: AsyncRead + Unpin>(io: &mut S, records: &mut Records) -> Result<([u8; 5], Vec<u8>), Ended> {
	let mut read = [0; 4096];
	loop {
		if let Some((header, body)) = records.next().map_err(|_| TLS)? {
			if header[0] != 20 {return Ok((header, body.to_vec()))}
			if body != [1] {return Err(TLS)}
			continue;
		}
		match io.read(&mut read).await {
			Ok(count) if count > 0 => records.feed(&read[..count]),
			_ => return Err(TLS),
		}
	}
}

/// The handshake behind the record `hello`, with `x` the private key of its `X` and `leaf` the public point the node's leaf must have. It ends at the client's Finished, and with a leaf that is not the node's it ends there too, with `matched` false: the caller closes the connection the way a visitor leaves.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, hello: &[u8], x: &[u8; 32], leaf: &[u8]) -> Result<Opened, Ended> {
	io.write_all(hello).await.map_err(|_| TLS)?;
	io.flush().await.map_err(|_| TLS)?;
	let (mut records, mut transcript) = (Records::default(), digest::Context::new(&digest::SHA256));
	transcript.update(&hello[5..]);
	let (header, message) = record(io, &mut records).await?;
	let (suite, share) = server_hello(&message, &hello[5 + 39..5 + 71]).filter(|_| header[0] == 22).ok_or(TLS)?;
	transcript.update(&message);
	let shared = x25519(*x, share);
	if shared == [0; 32] {return Err(TLS)}
	let (client_hs, server_hs, salt) = handshake_secrets(&shared, transcript.clone().finish().as_ref());
	let (mut client_keys, mut server_keys, mut pending, mut step, mut matched, mut point) = (Keys::new(suite, &client_hs), Keys::new(suite, &server_hs), Vec::<u8>::new(), 0, false, Vec::new());
	while step < 4 {
		let size = pending.first_chunk::<4>().map(|head: &[u8; 4]| usize::from(head[1]) << 16 | usize::from(head[2]) << 8 | usize::from(head[3]));
		if size.is_some_and(|size| size > MESSAGE) {return Err(TLS)}
		let Some(size) = size.filter(|size| pending.len() >= 4 + size) else {
			let (header, mut body) = record(io, &mut records).await?;
			let (23, Some((22, plain))) = (header[0], server_keys.open(&header, &mut body)) else {return Err(TLS)};
			pending.extend_from_slice(plain);
			continue;
		};
		let message: Vec<u8> = pending.drain(..4 + size).collect();
		let body = &message[4..];
		match (step, message[0]) {
			(0, 8) => {
				let mut extensions = Cursor(body);
				if extensions.var(2).is_none() || !extensions.0.is_empty() {return Err(TLS)}
			}
			(1, 11 | 25) => {
				let chain = if message[0] == 25 {inflate(body).ok_or(TLS)?} else {body.to_vec()};
				let der = first_certificate(&chain).ok_or(TLS)?;
				point = x509_parser::parse_x509_certificate(der).map(|(_, cert)| cert.public_key().subject_public_key.data.to_vec()).unwrap_or_default();
				matched = bool::from(point[..].ct_eq(leaf));
			}
			(2, 15) => {
				let mut verify = Cursor(body);
				let (algorithm, signed) = (verify.uint(2).ok_or(TLS)?, verify.var(2).ok_or(TLS)?);
				if !verify.0.is_empty() {return Err(TLS)}
				// RFC 8446 section 4.4.3. The signature is checked only under the key the client derived: with another key nothing here is authenticated, and the scheme could be one this build has no use for.
				let content = [&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", transcript.clone().finish().as_ref()].concat();
				if matched && (algorithm != 0x0403 || signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point).verify(&content, signed).is_err()) {return Err(MISMATCH)}
			}
			(3, 20) => if matched && hmac::verify(&finished(&server_hs), transcript.clone().finish().as_ref(), body).is_err() {return Err(TLS)},
			_ => return Err(TLS),
		}
		transcript.update(&message);
		step += 1;
	}
	if !pending.is_empty() {return Err(TLS)}
	let hash = transcript.finish();
	let (client_ap, server_ap, _) = secrets(&salt, &[0; 32], ["c ap traffic", "s ap traffic"], hash.as_ref());
	let (mut out, verify) = (vec![20, 3, 3, 0, 1, 1], hmac::sign(&finished(&client_hs), hash.as_ref()));
	if !client_keys.seal(22, &[&[20, 0, 0, 32][..], verify.as_ref()].concat(), &mut out) {return Err(TLS)}
	io.write_all(&out).await.map_err(|_| TLS)?;
	io.flush().await.map_err(|_| TLS)?;
	Ok(Opened {send: Keys::new(suite, &client_ap), receive: Keys::new(suite, &server_ap), records, matched})
}

// "Either side sends a TLS `close_notify`, waits up to 5 s for the other, and closes TCP." The wait is over at the peer's `close_notify`, at the end of the connection, and at the first thing that is no record of a session.
async fn close(rd: &mut ReadHalf<TcpStream>, wr: &mut WriteHalf<TcpStream>, send: &mut Keys, receive: &mut Keys, records: &mut Records, wait: bool) {
	let mut out = Vec::new();
	let said = send.seal(21, &[1, 0], &mut out) && timeout(CLOSE_WAIT, async {wr.write_all(&out).await.is_ok() && wr.flush().await.is_ok()}).await.unwrap_or(false);
	if said && wait {
		let _ = timeout(CLOSE_WAIT, async {
			let mut read = [0; 4096];
			loop {
				match records.next() {
					Ok(Some((header, body))) => if header[0] == 23 && matches!(receive.open(&header, body), Some((22 | 23, _))) {continue} else {return},
					Ok(None) => {}
					Err(_) => return,
				}
				match rd.read(&mut read).await {
					Ok(count) if count > 0 => records.feed(&read[..count]),
					_ => return,
				}
			}
		}).await;
	}
	let _ = timeout(CLOSE_WAIT, wr.shutdown()).await;
}

pub(crate) async fn run(port: &mut Port, link: &Link, client: &Mutex<Client>, candidate: &Front) -> Ended {
	// Everything a session needs of others is taken before anything is dialled, as in `stream.rs`.
	let (Ok(padding), Some(first)) = (Padding::new(link.padding.wide_max, link.padding.normal_max, &mut random), port.want(Want::First)) else {return End::Source.into()};
	let Ok(name) = tls::name(candidate) else {return MISMATCH};
	let (hook, clock, keepalive, dialled) = (port.env.socket.clone(), port.env.now.clone(), lone(&first), Instant::now() + ATTEMPT);
	// The hello is sealed after the connection is made, so that its timestamp is the one of the moment it is sent.
	let opening = async {
		let mut io = tls::tcp(candidate, &hook, dialled).await?;
		let (record, x, leaf) = hello(client, &name.to_str(), clock())?;
		let opened = timeout_at(dialled, handshake(&mut io, &record, &x, &leaf)).await.unwrap_or(Err(Ended::Unreachable(Unreachable::Timeout)))?;
		Ok::<_, Ended>((io, opened))
	};
	let (io, Opened {mut send, mut receive, mut records, matched}) = match unasked(&mut port.ask, opening).await {
		Some(Ok(opened)) => opened,
		Some(Err(ended)) => return ended,
		None => return End::Asked.into(),
	};
	let (mut rd, mut wr) = tokio::io::split(io);
	// "On a mismatch the client sends no alert. It finishes the handshake the way a client that accepted would, sends no application data, sends a close_notify, closes as 'Closing' says."
	if !matched {
		port.state.send_replace(State::Ended(MISMATCH));
		close(&mut rd, &mut wr, &mut send, &mut receive, &mut records, true).await;
		return MISMATCH;
	}
	let (mut read, deadline) = (vec![0u8; 16_384], Instant::now() + ATTEMPT);
	// As in `stream.rs`: `batch` is what the next frame holds, `flush` that it goes out even if it is a lone keepalive, `held` a lone keepalive on its way out with whether it is the idle one, and `awaiting` until when a frame of the node must have come.
	let (mut batch, mut flush, mut held, mut awaiting, mut carry, mut established, mut idle, mut frames) = (vec![(first, Kind::Packet {flow: 0, control: false})], true, None::<(Vec<u8>, Instant, bool)>, None::<Instant>, None::<(Vec<u8>, Kind)>, false, deadline, 0u64);
	let (mut next, mut closing, mut gone, mut cut) = (None::<(Vec<u8>, Kind)>, false, false, false);
	let ended = 'session: loop {
		batch.extend(carry.take());
		let mut used: usize = batch.iter().map(|(datagram, _)| 2 + datagram.len()).sum();
		while let Some((datagram, kind)) = next.take().or_else(|| port.out.try_recv().ok()) {
			if !port.fits(&datagram) {
				port.dropped(1);
			} else if used + 2 + datagram.len() > MAX_PLAINTEXT - 34 || batch.len() + 1 >= MAX_ITEMS {
				carry = Some((datagram, kind));
				break;
			} else {
				used += 2 + datagram.len();
				batch.push((datagram, kind));
			}
		}
		if closing {
			batch.extend(held.take().map(|(datagram, _, _)| (datagram, Kind::Packet {flow: 0, control: false})));
			flush = true;
		}
		if let ([(datagram, _)], false, None) = (&batch[..], flush, &held) {
			if lone(datagram) {
				let Ok(delay) = pause(&LONE_KEEPALIVE) else {break End::Random.into()};
				held = batch.pop().map(|(datagram, _)| (datagram, Instant::now() + delay, false));
			}
		}
		if !batch.is_empty() {
			batch.extend(held.take().map(|(datagram, _, _)| (datagram, Kind::Packet {flow: 0, control: false})));
			let (items, mut frame, mut out): (Vec<&[u8]>, _, _) = (batch.iter().map(|(datagram, _)| &datagram[..]).collect(), vec![0; 2], Vec::new());
			let Ok(extra) = padding.draw(chunk::wide(frames, batch.iter().any(|(datagram, kind)| wide(*kind, datagram)), false), items.iter().map(|item| 2 + item.len()).sum(), MAX_PLAINTEXT, &mut random) else {break End::Random.into()};
			if chunk::write(&items, extra, &mut frame).is_err() {break End::Source.into()}
			let size = (frame.len() - 2) as u16;
			frame[..2].copy_from_slice(&size.to_be_bytes());
			if !send.seal(23, &frame, &mut out) {break End::Exhausted.into()}
			frames += 1;
			if !timeout(LIVENESS, async {wr.write_all(&out).await.is_ok() && wr.flush().await.is_ok()}).await.unwrap_or(false) {
				(gone, cut) = (true, true);
				break End::Lost.into();
			}
			if batch.iter().any(|(_, kind)| *kind == Kind::Stalled) {awaiting.get_or_insert(Instant::now() + LIVENESS);}
			port.sent(batch.len());
			batch.clear();
			let Ok(silence) = pause(&link.padding.keepalive) else {break End::Random.into()};
			(flush, idle) = (false, Instant::now() + silence);
		}
		if closing {
			if carry.is_none() {break End::Asked.into()}
			continue;
		}
		loop {
			let Some((header, body)) = (match records.next() {
				Ok(record) => record,
				Err(fault) => break 'session End::Fault(fault).into(),
			}) else {break};
			if header[0] != 23 {break 'session End::Fault(Fault::Frame).into()}
			let Some((kind, plain)) = receive.open(&header, body) else {break 'session End::Fault(Fault::Frame).into()};
			match kind {
				// "A frame is a 2 byte length `n`, from 1 to 16,000, then `n` bytes of chunk plaintext." One frame is one record, and a frame with a bad length or an invalid chunk ends the session. A frame with no item is the padding-only chunk, and is activity.
				23 => {
					let Some((&[high, low], chunk)) = plain.split_first_chunk::<2>() else {break 'session End::Fault(Fault::Frame).into()};
					if usize::from(u16::from_be_bytes([high, low])) != chunk.len() || chunk.is_empty() || chunk.len() > MAX_PLAINTEXT {break 'session End::Fault(Fault::Frame).into()}
					let Ok(items) = chunk::parse(chunk) else {break 'session End::Fault(Fault::Chunk).into()};
					(established, awaiting) = (true, None);
					port.heard();
					for datagram in items {port.deliver(datagram)}
				}
				// A fatal alert from the node is its end of the connection, and there is nobody to close the session with.
				21 if plain == [1, 0] => break 'session End::Peer.into(),
				21 => {
					gone = true;
					break 'session End::Lost.into();
				}
				// "Ignore NewSessionTicket if it ever arrives": the node sends tickets of random content, and a client never resumes.
				22 => {
					let mut tickets = Cursor(plain);
					while !tickets.0.is_empty() {
						if tickets.uint(1) != Some(4) || tickets.var(3).is_none() {break 'session End::Fault(Fault::Frame).into()}
					}
				}
				_ => break 'session End::Fault(Fault::Frame).into(),
			}
		}
		let timer = [held.as_ref().map(|held| held.1), awaiting, if !established {Some(deadline)} else if held.is_none() {Some(idle)} else {None}].into_iter().flatten().min().unwrap_or(idle);
		tokio::select! {
			got = rd.read(&mut read) => match got {
				Ok(count) if count > 0 => records.feed(&read[..count]),
				// The end of the connection without a `close_notify`: anyone on the path can cause that.
				_ => {
					(gone, cut) = (true, true);
					break End::Lost.into();
				}
			},
			sent = port.out.recv() => match sent {
				Some(sent) => next = Some(sent),
				None => closing = true,
			},
			asked = port.ask.recv() => closing |= !matches!(asked, Some(Ask::Moved)),
			_ = sleep_until(timer) => {
				let now = Instant::now();
				if !established && now >= deadline {break if keepalive {End::Unanswered.into()} else {Ended::Unreachable(Unreachable::Timeout)}}
				if awaiting.is_some_and(|until| now >= until) {break End::Lost.into()}
				if let Some((datagram, _, waited)) = held.take_if(|held| now >= held.1) {
					batch.push((datagram, Kind::Packet {flow: 0, control: false}));
					flush = true;
					if waited {awaiting.get_or_insert(now + LIVENESS);}
				} else if established && held.is_none() && now >= idle {
					let (Ok(silence), Ok(delay)) = (pause(&link.padding.keepalive), pause(&LONE_KEEPALIVE)) else {break End::Random.into()};
					idle = now + silence;
					held = port.want(Want::Keepalive).map(|datagram| (datagram, now + delay, true));
				}
			}
		}
	};
	// The node vouched for itself with the leaf, so a close in order before any frame is a refusal, as on `tls`, and a connection cut before one is the path's.
	let told = match ended {
		Ended::Closed(End::Peer | End::Lost) if !established && cut => Ended::Unreachable(Unreachable::Cut),
		Ended::Closed(End::Peer | End::Lost) if !established && keepalive => End::Unanswered.into(),
		Ended::Closed(End::Peer | End::Lost) if !established => Ended::Refused(Refusal {answer: Answer::Unopened, offset: None}),
		ended => ended,
	};
	port.state.send_replace(State::Ended(told));
	if !gone {close(&mut rd, &mut wr, &mut send, &mut receive, &mut records, ended != Ended::Closed(End::Peer)).await}
	told
}

#[cfg(test)]
#[path = "faketls_test.rs"]
mod tests;
