//! The client of `faketls` (borrowed-site page, "What the client puts in its hello", "How the client knows the node", "The session").
//!
//! The hello is the one BoringSSL writes for `tls` (`fingerprint.rs`), captured without a server, with `X` and the carrier put into it. BoringSSL cannot go on after a hello it did not write whole, so the TLS 1.3 handshake behind it is this module's: the two suites and the one group the node answers with, the key schedule of RFC 8446 section 7.1 over `ring`, and nothing else. A HelloRetryRequest, another suite, another group and another signature scheme end the attempt.
//! What the node sends is held to the page's rule and to nothing more: the leaf's public key must be the one the client derives, and then the CertificateVerify and the Finished must verify under it. The leaf's name, chain and dates are not looked at, and no root is read. A leaf with another key is a `Unreachable::Certificate`, and nothing about it is authenticated: the client finishes the handshake, sends a `close_notify` and no application data, and closes.
//! After the handshake the TLS record layer is the only encryption. A frame is a 2 byte length and a chunk plaintext (`chunk::write`), one frame in one record, and the activity and keepalive rules are those of `stream.rs`.
//! Every byte from the network is hostile: records are bounded before they are waited for, a handshake message is bounded before it is collected, and a certificate chain is decompressed to the length it declared and no further.
use crate::fingerprint;
use crate::mlkem;
use crate::{lone, pause, random, tls, unasked, wide, Answer, Ask, End, Ended, Fault, Front, Kind, Link, Port, Refusal, State, Unreachable, Want, ATTEMPT};
use boring::ssl::HandshakeError;
use ring::signature;
use std::collections::HashMap;
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
use veilway_proto::tls13::{application_secrets, finished, handshake_secrets, server_hello, Cursor, Keys, Transcript, HEADER, HYBRID, KEM_CIPHERTEXT, KEM_KEY, RECORD, X25519};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// "Either side sends a TLS `close_notify`, waits up to 5 s for the other, and closes TCP."
const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// A handshake message beyond this is not collected. A chain is about 10 KB, and a compressed one is far smaller on the wire.
const MESSAGE: usize = 1 << 17;
/// A certificate chain that decompresses beyond this is not a chain.
const LARGEST_CHAIN: usize = 1 << 20;
/// How much of the network one read may take, so that the records a site sent in one go come out of one read and a burst can be told from the next.
const READ: usize = 65_536;
const TLS: Ended = Ended::Unreachable(Unreachable::Tls);
/// The leaf was not the one the client derives, or its signature did not verify under it.
const MISMATCH: Ended = Ended::Unreachable(Unreachable::Certificate);
// "It keeps the `X` of its last 4,096 seals in memory, and the seal function refuses an `X` on that list, ends the attempt with an internal error, and counts it."
static REUSED: AtomicU64 = AtomicU64::new(0);

/// How many hellos were refused because their `X` was one of the last 4,096 sealed: a fault of the random source, and never expected to be above 0.
pub fn reused() -> u64 {REUSED.load(Ordering::Relaxed)}

/// The `Client`s of a link by the key of their `faketls` transport. Clones share them, so a link that is cloned for every attempt keeps one client for each key.
#[derive(Clone, Default)]
pub struct Clients(Arc<Mutex<HashMap<[u8; 32], Arc<Mutex<Client>>>>>);

/// The one `Client` of a link for `node`, the key of one of its `faketls` transports, shared by every attempt and every connection to that key: its memory of sealed key shares is the backstop of "Every seal gets a fresh `x`" only if it outlives the attempt. Each `faketls` transport has its own key, and never the profile's `transport_public_key`.
pub fn client(link: &Link, node: &[u8; 32]) -> Arc<Mutex<Client>> {link.borrowed.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(*node).or_insert_with(|| Arc::new(Mutex::new(Client::new(node, link.secret.expose(), &link.inbound, &link.device)))).clone()}

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
				(0x11ec, 1216) => hybrid = hybrid.or(Some(at(key) + KEM_KEY)),
				_ => {}
			}
		}
	}
	Some((standalone?, hybrid))
}

/// The private halves of the hybrid share of a hello: the X25519 key behind its X25519 part, and the seed of its ML-KEM key.
pub(crate) type Hybrid = ([u8; 32], [u8; mlkem::SEED]);

/// A Chrome ClientHello record for the site `name`, made by BoringSSL without a server, with a fresh `X`: the private key `x` of it. When the hello has the hybrid share, its ML-KEM key is replaced with a fresh one and its X25519 part with `X` if the capture has the two equal, and with a key of its own if the capture draws them apart ("it reuses x for the hybrid share if the capture does, and draws a separate key if the capture does"), so that the client holds what it takes to open the node's answer in the hybrid group. Nothing is sealed into it yet.
/// "The client draws `x` from the system random source for every hello, including a hello sent again after a failed attempt and each of parallel connections." The rest of the hello is BoringSSL's.
pub(crate) fn capture(name: &str) -> Result<(Vec<u8>, [u8; 32], Option<Hybrid>), Ended> {
	let ssl = fingerprint::context().and_then(|context| fingerprint::ssl(context, name, true, true)).map_err(|_| TLS)?;
	let Err(HandshakeError::WouldBlock(started)) = ssl.connect(Capture(Vec::new())) else {return Err(TLS)};
	let mut record = started.into_source_stream().0;
	if record.len() < 9 || record[..3] != [22, 3, 1] || usize::from(u16::from_be_bytes([record[3], record[4]])) != record.len() - 5 {return Err(TLS)}
	let (message, mut x, mut hybrid) = (&mut record[5..], [0; 32], None);
	random(&mut x).map_err(|_| End::Random)?;
	let share = x25519(x, X25519_BASEPOINT_BYTES);
	let (standalone, part) = shares(message).ok_or(TLS)?;
	if let Some(part) = part {
		let (tied, (key, seed)) = (message[part..part + 32] == message[standalone..standalone + 32], mlkem::generate());
		let mut own = x;
		if !tied {random(&mut own).map_err(|_| End::Random)?}
		message[part - KEM_KEY..part].copy_from_slice(&key);
		message[part..part + 32].copy_from_slice(&x25519(own, X25519_BASEPOINT_BYTES));
		hybrid = Some((own, seed));
	}
	message[standalone..standalone + 32].copy_from_slice(&share);
	Ok((record, x, hybrid))
}

/// The record of a ClientHello for the site `name`, as Chrome would send it, with a fresh `X` and the carrier sealed into it. Also the private key `x` of `X`, the private halves of the hybrid share if there is one, and the public point of the leaf the node answers with.
fn hello(client: &Mutex<Client>, name: &str, now: u64) -> Result<(Vec<u8>, [u8; 32], Option<Hybrid>, Vec<u8>), Ended> {
	let (mut record, x, hybrid) = capture(name)?;
	let mut client = client.lock().map_err(|_| End::Source)?;
	if let Err(error) = client.carry(&mut record[5..], &x, now) {
		if error == CarryError::Reused {REUSED.fetch_add(1, Ordering::Relaxed);}
		tracing::error!(?error, "a faketls hello was not sealed");
		return Err(End::Random.into());
	}
	let leaf = client.leaf(&x, &record[5..]).ok_or(TLS)?;
	Ok((record, x, hybrid, leaf))
}

/// The bytes of the connection, cut into records. It keeps one record at the most and what one read brought behind it, and the first fault is the caller's to end the session with.
#[derive(Default)]
pub(crate) struct Records {buf: Vec<u8>, done: usize, scratch: Vec<u8>}

impl Records {
	pub(crate) fn feed(&mut self, bytes: &[u8]) {self.buf.extend_from_slice(bytes)}

	/// The next whole record with its header, or `Ok(None)` when more bytes are needed. The verdict on a header falls before a byte of the body is waited for.
	pub(crate) fn next(&mut self) -> Result<Option<([u8; HEADER], &mut [u8])>, Fault> {
		self.buf.drain(..std::mem::take(&mut self.done));
		let Some(&[kind, major, minor, high, low]) = self.buf.first_chunk::<HEADER>() else {return Ok(None)};
		let size = usize::from(u16::from_be_bytes([high, low]));
		// RFC 8446 section 5.1: the version of a record "MUST be ignored", so only its major byte is a check of framing.
		if !(20..=23).contains(&kind) || major != 3 || size == 0 || size > RECORD {return Err(Fault::Frame)}
		if self.buf.len() < HEADER + size {return Ok(None)}
		self.done = HEADER + size;
		Ok(Some(([kind, major, minor, high, low], &mut self.buf[HEADER..HEADER + size])))
	}
}

// The first certificate of a Certificate message's body (RFC 8446 section 4.4.2), whose request context must be empty, and the entries behind it, verbatim.
fn first_certificate(body: &[u8]) -> Option<(&[u8], &[u8])> {
	let mut message = Cursor(body);
	let (context, list) = (message.var(1)?, message.var(3)?);
	if !context.is_empty() || !message.0.is_empty() {return None}
	let mut list = Cursor(list);
	let leaf = list.var(3)?;
	list.var(2)?;
	Some((leaf, list.0))
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

/// What a handshake showed of the server's messages, for a probe: the EncryptedExtensions message and the certificates behind the leaf, verbatim, and whether the certificate came compressed, and how many encrypted records it took.
#[derive(Default)]
pub(crate) struct Seen {pub(crate) extensions: Vec<u8>, pub(crate) chain: Vec<u8>, pub(crate) compressed: bool, pub(crate) records: usize}

/// A finished handshake: the keys of both directions, what the node sent behind its Finished, and whether the leaf was the one the client derives.
pub(crate) struct Opened {pub(crate) send: Keys, pub(crate) receive: Keys, pub(crate) records: Records, matched: bool}

// The next record of the handshake. A compatibility `change_cipher_spec` (RFC 8446 appendix D.4) is passed over.
async fn record<S: AsyncRead + Unpin>(io: &mut S, records: &mut Records) -> Result<([u8; HEADER], Vec<u8>), Ended> {
	loop {
		if let Some((header, body)) = records.next().map_err(|_| TLS)? {
			if header[0] != 20 {return Ok((header, body.to_vec()))}
			if body != [1] {return Err(TLS)}
			continue;
		}
		if records.scratch.is_empty() {records.scratch = vec![0; READ]}
		match io.read(&mut records.scratch).await {
			Ok(count) if count > 0 => records.buf.extend_from_slice(&records.scratch[..count]),
			_ => return Err(TLS),
		}
	}
}

/// The handshake behind the record `hello`, with `x` the private key of its `X`, `hybrid` the private halves of its hybrid share if it has one, and `leaf` the public point the node's leaf must have. It ends at the client's Finished, and with a leaf that is not the node's it ends there too, with `matched` false: the caller closes the connection the way a visitor leaves. A probe passes no leaf, and `seen` is what it learns.
pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, hello: &[u8], x: &[u8; 32], hybrid: Option<&Hybrid>, leaf: &[u8], seen: &mut Seen) -> Result<Opened, Ended> {
	io.write_all(hello).await.map_err(|_| TLS)?;
	io.flush().await.map_err(|_| TLS)?;
	let mut records = Records::default();
	let (header, message) = record(io, &mut records).await?;
	let read = server_hello(&message, &hello[5 + 39..5 + 71]).filter(|_| header[0] == 22).ok_or(TLS)?;
	let (suite, point) = (read.suite, <[u8; 32]>::try_from(&read.key[read.key.len() - 32..]).map_err(|_| TLS)?);
	let (agreed, secret) = match (read.group, hybrid) {
		(X25519, _) => (x25519(*x, point), Vec::new()),
		(HYBRID, Some((own, seed))) => (x25519(*own, point), mlkem::decap(seed, &read.key[..KEM_CIPHERTEXT]).ok_or(TLS)?.to_vec()),
		_ => return Err(TLS),
	};
	if agreed == [0; 32] {return Err(TLS)}
	let shared = [&secret[..], &agreed].concat();
	let mut transcript = Transcript::new(suite);
	transcript.update(&hello[5..]);
	transcript.update(&message);
	let secrets = handshake_secrets(suite, &shared, &transcript.hash());
	let (mut client_keys, mut server_keys, mut pending, mut step, mut matched, mut point) = (Keys::new(suite, &secrets.client), Keys::new(suite, &secrets.server), Vec::<u8>::new(), 0, false, Vec::new());
	while step < 4 {
		let size = pending.first_chunk::<4>().map(|head: &[u8; 4]| usize::from(head[1]) << 16 | usize::from(head[2]) << 8 | usize::from(head[3]));
		if size.is_some_and(|size| size > MESSAGE) {return Err(TLS)}
		let Some(size) = size.filter(|size| pending.len() >= 4 + size) else {
			let (header, mut body) = record(io, &mut records).await?;
			let (23, Some((22, plain))) = (header[0], server_keys.open(&header, &mut body)) else {return Err(TLS)};
			pending.extend_from_slice(plain);
			seen.records += 1;
			continue;
		};
		let message: Vec<u8> = pending.drain(..4 + size).collect();
		let body = &message[4..];
		match (step, message[0]) {
			(0, 8) => {
				let mut extensions = Cursor(body);
				if extensions.var(2).is_none() || !extensions.0.is_empty() {return Err(TLS)}
				seen.extensions = message.clone();
			}
			(1, 11 | 25) => {
				let chain = if message[0] == 25 {inflate(body).ok_or(TLS)?} else {body.to_vec()};
				let (der, tail) = first_certificate(&chain).ok_or(TLS)?;
				point = x509_parser::parse_x509_certificate(der).map(|(_, cert)| cert.public_key().subject_public_key.data.to_vec()).unwrap_or_default();
				matched = bool::from(point[..].ct_eq(leaf));
				(seen.chain, seen.compressed) = (tail.to_vec(), message[0] == 25);
			}
			(2, 15) => {
				let mut verify = Cursor(body);
				let (algorithm, signed) = (verify.uint(2).ok_or(TLS)?, verify.var(2).ok_or(TLS)?);
				if !verify.0.is_empty() {return Err(TLS)}
				// RFC 8446 section 4.4.3. The signature is checked only under the key the client derived: with another key nothing here is authenticated, and the scheme could be one this build has no use for.
				let content = [&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", &transcript.hash()].concat();
				if matched && (algorithm != 0x0403 || signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point).verify(&content, signed).is_err()) {return Err(MISMATCH)}
			}
			(3, 20) => if matched && !bool::from(finished(suite, &secrets.server, &transcript.hash())[..].ct_eq(body)) {return Err(TLS)},
			_ => return Err(TLS),
		}
		transcript.update(&message);
		step += 1;
	}
	if !pending.is_empty() {return Err(TLS)}
	let hash = transcript.hash();
	let (client_ap, server_ap) = application_secrets(suite, &secrets.next, &hash);
	let (mut out, verify) = (vec![20, 3, 3, 0, 1, 1], finished(suite, &secrets.client, &hash));
	if !client_keys.seal(22, &[&[20, 0, 0, verify.len() as u8][..], &verify].concat(), 0, &mut out) {return Err(TLS)}
	io.write_all(&out).await.map_err(|_| TLS)?;
	io.flush().await.map_err(|_| TLS)?;
	Ok(Opened {send: Keys::new(suite, &client_ap), receive: Keys::new(suite, &server_ap), records, matched})
}

// "Either side sends a TLS `close_notify`, waits up to 5 s for the other, and closes TCP." The wait is over at the peer's `close_notify`, at the end of the connection, and at the first thing that is no record of a session.
async fn close(rd: &mut ReadHalf<TcpStream>, wr: &mut WriteHalf<TcpStream>, send: &mut Keys, receive: &mut Keys, records: &mut Records, wait: bool) {
	let mut out = Vec::new();
	let said = send.seal(21, &[1, 0], 0, &mut out) && timeout(CLOSE_WAIT, async {wr.write_all(&out).await.is_ok() && wr.flush().await.is_ok()}).await.unwrap_or(false);
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
		let (record, x, hybrid, leaf) = hello(client, &name.to_str(), clock())?;
		let opened = timeout_at(dialled, handshake(&mut io, &record, &x, hybrid.as_ref(), &leaf, &mut Seen::default())).await.unwrap_or(Err(Ended::Unreachable(Unreachable::Timeout)))?;
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
		close(&mut rd, &mut wr, &mut send, &mut receive, &mut records, true).await;
		port.state.send_replace(State::Ended(MISMATCH));
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
			if !send.seal(23, &frame, 0, &mut out) {break End::Exhausted.into()}
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
				// "Ignore NewSessionTicket if it ever arrives": the node sends tickets of random content, and a client never resumes. A KeyUpdate (RFC 8446 section 4.6.3) is none the node sends, and this build has no key to follow it with: the session ends as one whose keys have run out, and a new one is made.
				22 => {
					let mut tickets = Cursor(plain);
					while !tickets.0.is_empty() {
						match tickets.uint(1) {
							Some(4) if tickets.var(3).is_some() => {}
							Some(24) => break 'session End::Exhausted.into(),
							_ => break 'session End::Fault(Fault::Frame).into(),
						}
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
