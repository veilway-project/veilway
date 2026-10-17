//! The flight of the borrowed-site mode (borrowed-site page, "The shape of the site" and "The flight"): what a site sent for a hello, as sizes and times; what a probe keeps of it; and how the node writes a flight of its own with those sizes, in a handshake it makes itself because no TLS library lets it set the size of a record.
//!
//! `Flight::read` turns the bytes a site sent for a hello into a `Flight`: the ServerHello's choices and the length, grouping and offset of every record after it. It cannot read the encrypted records, and does not try. `answer` takes a flight (the live one, or one a probe kept) and a `Shape` and writes the node's: a ServerHello with its own key share, then encrypted records of exactly the lengths the flight has, holding EncryptedExtensions, a Certificate whose leaf is made to fill what the lengths leave, a CertificateVerify and a Finished. `Pending` is the rest of the handshake, and `afterwards` the tickets and the first application data records of the shape.
//! Nothing here reads a socket or a clock. Random bytes are a parameter, except the nonce of the one signature, which `ring` takes from a source it is handed.
use crate::chunk::MAX_PLAINTEXT;
use crate::faketls::{leaf_key, parse};
use crate::tls13::{application_secrets, finished, handshake_secrets, server_hello, server_random, write_server_hello, Keys, Secrets, Suite, Transcript, HEADER, HYBRID, KEM_CIPHERTEXT, KEM_KEY, TAG, X25519};
use crate::{uniform, NoRandom, Random};
use ring::rand::SecureRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// The longest an ECDSA P-256 signature in DER is: the CertificateVerify is made room for at that size.
const LONGEST_SIGNATURE: usize = 72;
/// The encrypted records the flight of a site may have at the most.
pub const MOST_RECORDS: usize = 64;
/// The most encrypted bytes a flight may have, which is the most the client collects of one handshake message: a site whose flight is above it is not one the client could talk to through the node, so its flight is not copied.
pub const MAX_FLIGHT: usize = 1 << 17;
/// The most bytes of a site's answer that are read at all: 64 records of the largest size.
const READ_MOST: usize = MOST_RECORDS * (HEADER + 16_384 + 256) + 1_000;

/// One record of what a site sent, as its header showed it: the ServerHello (its length), the compatibility `change_cipher_spec`, or an encrypted record (the length of its body, tag included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {Hello(usize), Ccs, Sealed(usize)}

/// The records that arrived in one read, and when: the offset from the moment the hello was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Burst {pub at: Duration, pub wire: Vec<Wire>}

/// What a site chose for one hello and the sizes, grouping and times of its flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flight {pub suite: Suite, pub group: u16, pub key_first: bool, pub bursts: Vec<Burst>}

impl Flight {
	/// The lengths of the encrypted records, in order.
	pub fn sealed(&self) -> Vec<usize> {self.bursts.iter().flat_map(|burst| &burst.wire).filter_map(|wire| if let Wire::Sealed(size) = wire {Some(*size)} else {None}).collect()}

	/// The bytes of the encrypted records, in all.
	pub fn total(&self) -> usize {self.sealed().iter().sum()}

	/// Reads what a site sent for a hello whose session id was `session`: `reads` are the reads of the connection with the offset each came at, and `limit` the most encrypted records the flight has (a probe knows how many its handshake needed; a node that cannot tell passes `MOST_RECORDS`). None when the answer is no ServerHello of the kind `server_hello` reads, has no encrypted record after it, or is above `MAX_FLIGHT`. A record is part of the burst of the read it was completed in, and a record cut off at the end is left out.
	pub fn read(reads: &[(Duration, Vec<u8>)], session: &[u8], limit: usize) -> Option<Flight> {
		let (mut parser, mut bursts) = (Parser::new(session, limit), Vec::new());
		for (at, bytes) in reads {
			let wire = parser.feed(bytes).ok()?;
			if !wire.is_empty() {bursts.push(Burst {at: *at, wire})}
		}
		let (suite, group, key_first) = parser.hello()?;
		(parser.sealed() > 0).then_some(Flight {suite, group, key_first, bursts})
	}

	/// The sizes alone, for a comparison of two flights: the ServerHello's, the compatibility record's presence, the encrypted records' lengths and how they were grouped.
	pub fn sizes(&self) -> Vec<Vec<Wire>> {self.bursts.iter().map(|burst| burst.wire.clone()).collect()}
}

/// A site's answer to a hello, read as it arrives and each byte once: `feed` takes the next bytes of the connection and gives the records they complete.
pub struct Parser {buf: Vec<u8>, session: Vec<u8>, limit: usize, taken: usize, total: usize, sealed: usize, hello: Option<(Suite, u16, bool)>, over: bool}

impl Parser {
	pub fn new(session: &[u8], limit: usize) -> Parser {Parser {buf: Vec::new(), session: session.to_vec(), limit, taken: 0, total: 0, sealed: 0, hello: None, over: false}}

	/// The ServerHello's choices, once it has been read.
	pub fn hello(&self) -> Option<(Suite, u16, bool)> {self.hello}

	/// The encrypted records read so far, and their bytes.
	pub fn sealed(&self) -> usize {self.sealed}

	pub fn total(&self) -> usize {self.total}

	/// The records the next bytes complete. Err when the answer is no ServerHello, or a flight above `MAX_FLIGHT`. Once something that is no part of a flight has been read (an alert, a record past `limit`, more than 64 records' worth of bytes) the answer is over and nothing more is taken.
	pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Wire>, ()> {
		let mut out = Vec::new();
		self.taken += bytes.len();
		if self.over || self.taken > READ_MOST {
			self.over = true;
			return Ok(out);
		}
		self.buf.extend_from_slice(bytes);
		let mut at = 0;
		while let Some(&[kind, major, _, high, low]) = self.buf.get(at..).and_then(|rest| rest.first_chunk::<HEADER>()) {
			let size = usize::from(u16::from_be_bytes([high, low]));
			let Some(body) = self.buf.get(at + HEADER..at + HEADER + size) else {break};
			if major != 3 || size == 0 || self.sealed == self.limit {
				self.over = true;
				break;
			}
			let wire = match (kind, self.hello.is_some()) {
				(22, false) => {
					let hello = server_hello(body, &self.session).ok_or(())?;
					self.hello = Some((hello.suite, hello.group, hello.key_first));
					Wire::Hello(size)
				}
				(20, true) if body == [1] && self.sealed == 0 => Wire::Ccs,
				(23, true) if size > TAG => {
					(self.sealed, self.total) = (self.sealed + 1, self.total + size);
					if self.total > MAX_FLIGHT {return Err(())}
					Wire::Sealed(size)
				}
				_ => {
					if self.hello.is_none() {return Err(())}
					self.over = true;
					break;
				}
			};
			out.push(wire);
			at += HEADER + size;
		}
		self.buf.drain(..at);
		Ok(out)
	}
}

/// How a site ended a connection: a FIN, or a reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {Fin, Reset}

/// What a site did after the client did something: how long it took, the alert it sent if any (the length of its record, its level and its description), and how it ended the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct React {pub after: Duration, pub alert: Option<(usize, u8, u8)>, pub ending: Ending}

/// What a probe keeps of a site: the flight it got, the parts of it the node repeats, and what the site did afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
	pub flight: Flight,
	/// The EncryptedExtensions message and the certificates after the leaf (each with its extensions), verbatim.
	pub extensions: Vec<u8>,
	pub chain: Vec<u8>,
	/// Whether the site sent its certificate compressed. The node never does: it is not visible in the encrypted records.
	pub compressed: bool,
	/// The NewSessionTicket records and the first application data records the site sent after the client's Finished: the length of each body and its time from that Finished.
	pub tickets: Vec<(Duration, usize)>,
	pub data: Vec<(Duration, usize)>,
	/// The site's reaction to a `close_notify`, to a record that fails to decrypt, and to a client that sent nothing. None when the probe did not do that, or the site did not react within the probe's patience.
	pub notified: Option<React>,
	pub garbage: Option<React>,
	pub idle: Option<React>,
	/// When the probe ran, in Unix seconds, and how long its TCP connection took to open, which is one round trip to the site.
	pub taken: u64,
	pub rtt: Duration,
}

impl Shape {
	/// A flight of a made-up site, for a node that has no probe yet and no live answer: one burst, one encrypted record, a ServerHello of X25519, and the reactions of a server that alerts and closes at once. The sizes and times are drawn from the ranges real sites show (an encrypted flight of 2.5 to 7.5 KB, the first byte 15 to 60 ms after the hello, two tickets of 200 to 320 bytes), so that two nodes do not share one constant. Only they are a guess.
	pub fn generic(taken: u64, random: &mut Random) -> Shape {
		let mut draw = |low: u32, high: u32| uniform(low, high, random).unwrap_or(low) as usize;
		let hello = write_server_hello(&[0; 32], Suite::Aes128, X25519, false, &[0; 32], &[0; 32]).len();
		let (flight, first, tickets) = (draw(2_500, 7_500), draw(15, 60), (draw(200, 320), draw(200, 320)));
		let end = React {after: Duration::from_millis(5), alert: Some((TAG + 3, 1, 0)), ending: Ending::Fin};
		Shape {flight: Flight {suite: Suite::Aes128, group: X25519, key_first: false, bursts: vec![Burst {at: Duration::from_millis(first as u64), wire: vec![Wire::Hello(hello), Wire::Ccs, Wire::Sealed(flight)]}]}, extensions: vec![8, 0, 0, 2, 0, 0], chain: Vec::new(), compressed: false, tickets: vec![(Duration::from_millis(1), tickets.0), (Duration::from_millis(1), tickets.1)], data: Vec::new(), notified: Some(end), garbage: Some(React {alert: Some((TAG + 3, 2, 20)), ..end}), idle: None, taken, rtt: Duration::ZERO}
	}
}

// DER (X.690) with the definite lengths DER wants.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
	let size = body.len();
	let head: Vec<u8> = if size < 128 {vec![tag, size as u8]} else if size < 256 {vec![tag, 0x81, size as u8]} else if size < 65_536 {vec![tag, 0x82, (size >> 8) as u8, size as u8]} else {vec![tag, 0x83, (size >> 16) as u8, (size >> 8) as u8, size as u8]};
	[&head[..], body].concat()
}

/// A certificate for `host` that holds the P-256 point `public`, and is signed by nothing: its signature is random bytes. Its length is the largest that does not pass `target`, which a filler extension takes up (borrowed-site page, "The throwaway leaf"). None when the certificate cannot be that small.
fn leaf(host: &str, public: &[u8], random: &mut Random, target: usize) -> Option<Vec<u8>> {
	let mut pool = vec![0; target + 100];
	random(&mut pool).ok()?;
	let (mut serial, mut r, mut s) = (pool[..16].to_vec(), pool[16..48].to_vec(), pool[48..80].to_vec());
	for number in [&mut serial[0], &mut r[0], &mut s[0]] {*number = (*number & 0x7f).max(1)}
	let name = der(0x30, &der(0x31, &der(0x30, &[&[0x06, 3, 0x55, 4, 3][..], &der(0x0c, host.as_bytes())].concat())));
	let spki = [&[0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00][..], public].concat();
	let algorithm = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
	let san = der(0x30, &[&[0x06, 3, 0x55, 0x1d, 0x11][..], &der(0x04, &der(0x30, &der(0x82, host.as_bytes())))].concat());
	let build = |filler: usize| {
		let extensions = der(0xa3, &der(0x30, &[&san[..], &der(0x30, &[&[0x06, 3, 0x55, 0x1d, 0x7f][..], &der(0x04, &pool[80..80 + filler])].concat())].concat()));
		let validity = der(0x30, &[&der(0x17, b"250101000000Z")[..], &der(0x17, b"350101000000Z")].concat());
		let tbs = der(0x30, &[&[0xa0, 3, 2, 1, 2][..], &der(0x02, &serial), &algorithm, &name, &validity, &name, &spki, &extensions].concat());
		let signature = der(0x30, &[&der(0x02, &r)[..], &der(0x02, &s)].concat());
		der(0x30, &[&tbs[..], &algorithm, &der(0x03, &[&[0][..], &signature].concat())].concat())
	};
	let mut filler = target.checked_sub(build(0).len())?;
	while filler > 0 && build(filler).len() > target {filler -= 1}
	Some(build(filler))
}

/// A handshake message: its type, a 3 byte length and the body.
fn message(kind: u8, body: &[u8]) -> Vec<u8> {[&[kind, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8][..], body].concat()}

/// The node's flight, written, and the rest of the handshake.
pub struct Made {
	/// What to write and when: the offset from the moment the hello was written to the site, and the bytes of the records of that burst.
	pub bursts: Vec<(Duration, Vec<u8>)>,
	pub pending: Pending,
}

/// A handshake that waits for the client's Finished.
pub struct Pending {suite: Suite, client: Keys, expected: Vec<u8>, salt: Vec<u8>, hash: Vec<u8>}

/// The keys of the session: what the node seals with and what it opens with.
pub struct Established {pub send: Keys, pub receive: Keys}

impl Pending {
	/// The keys the client's records are opened with until its Finished: the compatibility record is not one of them.
	pub fn keys(&mut self) -> &mut Keys {&mut self.client}

	/// The client's Finished, as the plaintext of the record it came in. None when it is not the one the transcript gives.
	pub fn finish(self, plaintext: &[u8]) -> Option<Established> {
		let expected = message(20, &self.expected);
		if !bool::from(plaintext.ct_eq(&expected)) {return None}
		let (client, server) = application_secrets(self.suite, &self.salt, &self.hash);
		Some(Established {send: Keys::new(self.suite, &server), receive: Keys::new(self.suite, &client)})
	}
}

/// What the node's handshake needs of the client's hello beyond `faketls::parse`: `X`, the session id to echo, and the hybrid share when there is one, as its ML-KEM key and the X25519 value behind it. The client holds the private keys of both: it made the key, and it drew the X25519 value (or reused `x`, when the capture ties the two).
struct Offer<'a> {x: [u8; 32], session: &'a [u8], hybrid: Option<(&'a [u8], [u8; 32])>}

fn offer(hello: &[u8]) -> Option<Offer<'_>> {
	let parsed = parse(hello)?;
	let x: [u8; 32] = hello.get(parsed.share..parsed.share + 32)?.try_into().ok()?;
	let hybrid = parsed.hybrid.and_then(|at| Some((hello.get(at.checked_sub(KEM_KEY)?..at)?, hello.get(at..at + 32)?.try_into().ok()?)));
	Some(Offer {x, session: &hello[39..71], hybrid})
}

/// Whether a hello can be answered in `group`: X25519 always, and the hybrid when the hello has the hybrid share.
pub fn answers(hello: &[u8], group: u16) -> bool {offer(hello).is_some_and(|offer| group == X25519 || (group == HYBRID && offer.hybrid.is_some()))}

/// The ServerHello of the node's flight, written, and what the rest of the handshake follows from. The ServerHello does not depend on the sizes of the records behind it, so it can be written the moment the site's own is read.
pub struct Opening {suite: Suite, record: Vec<u8>, transcript: Transcript, secrets: Secrets}

/// The ServerHello for `hello` (the handshake message, with its header) in the choices of a site: its suite, group and extension order. `encap` is the ML-KEM-768 encapsulation to the client's key, for the hybrid group. None when the hello has no usable share or the group is the hybrid and the hello has no hybrid share.
pub fn open(hello: &[u8], suite: Suite, group: u16, key_first: bool, random: &mut Random, encap: &mut dyn FnMut(&[u8]) -> Option<([u8; KEM_CIPHERTEXT], [u8; 32])>) -> Option<Opening> {
	let offer = offer(hello)?;
	let mut y = [0; 32];
	random(&mut y).ok()?;
	let (public, mut secret) = (x25519(y, X25519_BASEPOINT_BYTES), Vec::new());
	let (key, mut agreed) = match (group, offer.hybrid) {
		(X25519, _) => (public.to_vec(), x25519(y, offer.x)),
		(HYBRID, Some((kem, part))) => {
			let (ciphertext, mut kept) = encap(kem)?;
			secret = kept.to_vec();
			kept.zeroize();
			([&ciphertext[..], &public].concat(), x25519(y, part))
		}
		_ => return None,
	};
	y.zeroize();
	let ok = agreed != [0; 32];
	let mut shared = [&secret[..], &agreed].concat();
	secret.zeroize();
	agreed.zeroize();
	let server = write_server_hello(offer.session, suite, group, key_first, &server_random(random).ok()?, &key);
	let mut transcript = Transcript::new(suite);
	transcript.update(hello);
	transcript.update(&server);
	let secrets = handshake_secrets(suite, &shared, &transcript.hash());
	shared.zeroize();
	ok.then(|| Opening {suite, record: [&[22, 3, 3, (server.len() >> 8) as u8, server.len() as u8][..], &server].concat(), transcript, secrets})
}

impl Opening {
	/// The ServerHello as a record.
	pub fn record(&self) -> &[u8] {&self.record}

	/// The length of the ServerHello record's body, which the site's own must have for the flights to match.
	pub fn size(&self) -> usize {self.record.len() - HEADER}

	/// The messages after the ServerHello, made to fill encrypted records that hold `capacity` bytes of content and padding in all (a record of `n` bytes in its header holds `n - 17`). `seed` makes the throwaway leaf, as `leaf_key` does, and `host` is its name. `rng` is the source the one signature needs. None when the messages do not fit in `capacity`.
	pub fn messages(&self, shape: &Shape, seed: &[u8; 40], host: &str, capacity: usize, rng: &dyn SecureRandom, random: &mut Random) -> Option<Stream> {
		let suite = self.suite;
		let fixed = shape.extensions.len() + 13 + shape.chain.len() + 4 + 4 + LONGEST_SIGNATURE + 4 + suite.hash_len();
		let (pkcs8, point) = leaf_key(seed)?;
		let leaf = leaf(host, &point, random, capacity.checked_sub(fixed)?)?;
		let entries = [&[(leaf.len() >> 16) as u8, (leaf.len() >> 8) as u8, leaf.len() as u8][..], &leaf, &[0, 0], &shape.chain].concat();
		let certificate = message(11, &[&[0][..], &[(entries.len() >> 16) as u8, (entries.len() >> 8) as u8, entries.len() as u8], &entries].concat());
		let mut transcript = self.transcript.clone();
		transcript.update(&shape.extensions);
		transcript.update(&certificate);
		let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, rng).ok()?;
		let signed = pair.sign(rng, &[&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", &transcript.hash()].concat()).ok()?;
		let verify = message(15, &[&[4, 3][..], &(signed.as_ref().len() as u16).to_be_bytes(), signed.as_ref()].concat());
		transcript.update(&verify);
		let done = message(20, &finished(suite, &self.secrets.server, &transcript.hash()));
		transcript.update(&done);
		let hash = transcript.hash();
		let pending = Pending {suite, client: Keys::new(suite, &self.secrets.client), expected: finished(suite, &self.secrets.client, &hash), salt: self.secrets.next.clone(), hash};
		Some(Stream {keys: Keys::new(suite, &self.secrets.server), data: [&shape.extensions[..], &certificate, &verify, &done].concat(), at: 0, pending})
	}
}

/// The messages of a flight, sealed into the records of a site's flight one at a time as their sizes become known.
pub struct Stream {keys: Keys, data: Vec<u8>, at: usize, pending: Pending}

impl Stream {
	/// The next encrypted record, for a record of `size` bytes in its header: as much of the messages as it holds, and record padding behind them. None when nothing is left to put in it, or it is too small for any content.
	pub fn seal(&mut self, size: usize) -> Option<Vec<u8>> {
		let capacity = size.checked_sub(TAG + 1)?;
		let take = capacity.min(self.data.len() - self.at);
		let mut out = Vec::new();
		if take == 0 || !self.keys.seal(22, &self.data[self.at..self.at + take], capacity - take, &mut out) {return None}
		self.at += take;
		Some(out)
	}

	/// How many bytes of the messages are not in a record yet.
	pub fn left(&self) -> usize {self.data.len() - self.at}

	/// The rest of the handshake, once the messages are all sealed.
	pub fn pending(self) -> Pending {self.pending}
}

/// The node's flight for `hello`, written whole, with the lengths, grouping and offsets of `flight` and the parts of `shape`: the ServerHello, then the messages in records of the sizes the flight has. None when the flight cannot be written: see `open` and `Opening::messages`, or the ServerHello would not be the length the flight has. The caller then uses another flight.
#[allow(clippy::too_many_arguments)]
pub fn answer(hello: &[u8], flight: &Flight, shape: &Shape, seed: &[u8; 40], host: &str, rng: &dyn SecureRandom, random: &mut Random, encap: &mut dyn FnMut(&[u8]) -> Option<([u8; KEM_CIPHERTEXT], [u8; 32])>) -> Option<Made> {
	let opening = open(hello, flight.suite, flight.group, flight.key_first, random, encap)?;
	let wire = || flight.bursts.iter().flat_map(|burst| &burst.wire);
	if wire().filter(|wire| matches!(wire, Wire::Hello(_))).count() != 1 || !wire().any(|wire| *wire == Wire::Hello(opening.size())) {return None}
	let capacities: Vec<usize> = flight.sealed().iter().map(|size| size.checked_sub(TAG + 1)).collect::<Option<_>>()?;
	let record = opening.record.clone();
	let mut stream = opening.messages(shape, seed, host, capacities.iter().sum(), rng, random)?;
	let mut sealed = Vec::new();
	for size in flight.sealed() {sealed.push(stream.seal(size)?)}
	if stream.left() != 0 {return None}
	let mut sealed = sealed.into_iter();
	let bursts = flight.bursts.iter().map(|burst| (burst.at, burst.wire.iter().flat_map(|wire| match wire {
		Wire::Hello(_) => record.clone(),
		Wire::Ccs => vec![20, 3, 3, 0, 1, 1],
		Wire::Sealed(_) => sealed.next().unwrap_or_default(),
	}).collect())).collect();
	Some(Made {bursts, pending: stream.pending()})
}

/// What the node sends after the client's Finished, with the time of each from that Finished, in the order of the times: the NewSessionTicket records of `shape`, with random contents, and its first application data records as frames that hold padding only. Each is a content type and the plaintext of one record of the length the site's had. The caller seals them as it writes them, so that they are never out of order with a record of its own.
pub fn afterwards(shape: &Shape, random: &mut Random) -> Result<Vec<(Duration, u8, Vec<u8>)>, NoRandom> {
	let mut due: Vec<(Duration, bool, usize)> = shape.tickets.iter().map(|(at, size)| (*at, true, *size)).chain(shape.data.iter().map(|(at, size)| (*at, false, *size))).collect();
	due.sort_by_key(|(at, ..)| *at);
	let mut out = Vec::new();
	for (at, ticket, size) in due {
		let Some(plain) = size.checked_sub(TAG + 1) else {continue};
		if ticket {
			let Some(body) = plain.checked_sub(4 + 4 + 4 + 1 + 8 + 2 + 2).filter(|body| *body > 0) else {continue};
			let mut random_part = vec![0; 8 + 4 + body];
			random(&mut random_part)?;
			let (nonce, rest) = random_part.split_at(8);
			let (age, ticket) = rest.split_at(4);
			let inner = [&7200u32.to_be_bytes()[..], age, &[8], nonce, &(body as u16).to_be_bytes(), ticket, &[0, 0]].concat();
			out.push((at, 22, message(4, &inner)));
		} else {
			let Some(frame) = plain.checked_sub(2).filter(|frame| (1..=MAX_PLAINTEXT).contains(frame)) else {continue};
			out.push((at, 23, [&(frame as u16).to_be_bytes()[..], &vec![0; frame]].concat()));
		}
	}
	Ok(out)
}

#[cfg(test)]
#[path = "flight_test.rs"]
mod tests;
