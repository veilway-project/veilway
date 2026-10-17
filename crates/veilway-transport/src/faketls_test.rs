//! The client of `faketls` against a node that is only its keys: the key schedule against RFC 8448, the record layer against `ring`, the hello it sends against the node's reading of it, and sessions against a small TLS 1.3 server that makes the flight the page describes.
use super::*;
use crate::{Env, Refuse, Session, Target};
use rcgen::{CertificateParams, KeyPair};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rustls::RootCertStore;
use std::collections::HashSet;
use std::io::Write;
use tokio::net::TcpListener;
use veilway_proto::faketls::{hour, leaf_key, parse, Node, Outcome};
use veilway_proto::keys::{Device, Table, TagKey};
use veilway_proto::subscription::payload::Padding as Bounds;
use veilway_proto::subscription::Secret;

const SITE: &str = "site.example";
const NODE: [u8; 32] = [0x61; 32];
const INBOUND: [u8; 32] = [0x21; 32];
const DEVICE: [u8; 32] = [0x41; 32];
const SECRET: [u8; 32] = [0x11; 32];
const NOW: u64 = 1_700_000_000;
const PLAIN: Kind = Kind::Packet {flow: 0, control: false};

fn hex(text: &str) -> Vec<u8> {
	let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
	digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {hex(text).try_into().unwrap()}

fn fill<const N: usize>() -> [u8; N] {
	let mut bytes = [0; N];
	SystemRandom::new().fill(&mut bytes).unwrap();
	bytes
}

fn link() -> Link {Link {inbound: INBOUND, device: DEVICE, secret: Secret::new(SECRET), node: Some(x25519(NODE, X25519_BASEPOINT_BYTES)), mtu: 1390, padding: Bounds {wide_max: 1023, normal_max: 255, keepalive: 20_000..=20_000}}}

fn node(key: [u8; 32]) -> Node {Node::new(key, INBOUND, &mut random).unwrap()}

// The node's table of one device: its tags for the hour before, the hour of `NOW` and the hour after.
fn table() -> Table<Device<u32>> {
	let (mut table, tags) = (Table::new(), TagKey::derive(&SECRET, &INBOUND));
	for at in [hour(NOW) - 1, hour(NOW), hour(NOW) + 1] {assert!(table.hour(tags.hour_tag(at), Device::derive(7, &SECRET, &INBOUND, &DEVICE)))}
	table
}

fn front(address: std::net::SocketAddr) -> Front {Front {address, sni: Some(SITE.into()), host: String::new(), verify_name: None, pins: Vec::new(), ech: false, self_signed: false, http2: Default::default()}}

fn env() -> Env {Env {device: Arc::new(|| NOW), now: Arc::new(|| NOW), roots: Arc::new(RootCertStore::empty()), socket: None}}

// A WireGuard layer in shape: a handshake initiation of 148 bytes to open with, and a keepalive of 32.
fn source() -> crate::Source {
	Arc::new(Mutex::new(|want: Want| Some(match want {
		Want::First => [&[1, 0, 0, 0][..], &[0xee; 144]].concat(),
		Want::Keepalive => [&[4, 0, 0, 0][..], &[0; 28]].concat(),
	})))
}

fn session(address: std::net::SocketAddr) -> Session {
	let link = link();
	Session::open(&link, Target::FakeTls {candidate: front(address), client: client(&link).unwrap()}, env(), source()).unwrap()
}

#[test]
fn the_key_schedule_is_the_one_of_rfc_8448_section_3() {
	// "Simple 1-RTT Handshake": TLS_AES_128_GCM_SHA256 with X25519. The key agreement, then the schedule from the hash of the transcript through the ServerHello.
	let shared = x25519(array("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"), array("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"));
	assert_eq!(shared, array("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"));
	let (client_hs, server_hs, salt) = handshake_secrets(&shared, &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
	assert_eq!(client_hs, array("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"));
	assert_eq!(server_hs, array("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"));
	assert_eq!(salt, array("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"));
	let early = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0; 32]).extract(&[0; 32]);
	assert_eq!(expand::<32>(&early, "derived", digest::digest(&digest::SHA256, &[]).as_ref()), array("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
	assert_eq!(expand::<32>(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &server_hs), "finished", &[]), array("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"));
	// The keys and ivs of both directions, by what they seal: the same record as `ring` makes under the RFC's key and iv.
	let sealed = |secret: &[u8; 32], key: &str, iv: &str| {
		let mut keys = Keys::new(Suite::Aes, secret);
		assert_eq!(keys.iv, array::<12>(iv));
		let mut out = Vec::new();
		assert!(keys.seal(22, b"record", &mut out));
		let mut manual = [&b"record"[..], &[22]].concat();
		let tag = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &hex(key)).unwrap()).seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key(array(iv)), aead::Aad::from(&out[..5]), &mut manual).unwrap();
		assert_eq!(out[5..], [&manual[..], tag.as_ref()].concat());
	};
	sealed(&server_hs, "3fce516009c21727d0f2e4e86ee403bc", "5d313eb2671276ee13000b30");
	sealed(&client_hs, "dbfaa693d1762c5b666af5d950258d01", "5bd3c71b836e0b76bb73265f");
	// The application stage is the same `secrets` function with the master extract's salt. The RFC's hash of the transcript through the server's Finished is not reproduced here from memory, so that stage is covered only by the sessions below, where the test server shares the code.
}

#[test]
fn a_record_opens_under_the_keys_it_was_sealed_with_and_only_in_order() {
	for suite in [Suite::Aes, Suite::Chacha] {
		let secret = fill::<32>();
		let (mut sender, mut receiver) = (Keys::new(suite, &secret), Keys::new(suite, &secret));
		let (mut out, contents) = (Vec::new(), [(23, b"first".to_vec()), (22, vec![4, 0, 0, 1, 9]), (23, vec![0x55; 16_384]), (21, vec![1, 0]), (23, Vec::new())]);
		for (kind, content) in &contents {assert!(sender.seal(*kind, content, &mut out))}
		let mut at = 0;
		for (kind, content) in &contents {
			let size = 5 + usize::from(u16::from_be_bytes([out[at + 3], out[at + 4]]));
			let header: [u8; 5] = out[at..at + 5].try_into().unwrap();
			assert_eq!((header[..3].to_vec(), size - 5), (vec![23, 3, 3], content.len() + 1 + 16));
			let mut body = out[at + 5..at + size].to_vec();
			assert_eq!(receiver.open(&header, &mut body), Some((*kind, &content[..])));
			at += size;
		}
		// A record that is not the next one, one with a bit changed, one with another header, and one past the limit of the keys do not open.
		let (mut one, mut two) = (Vec::new(), Vec::new());
		assert!(sender.seal(23, b"one", &mut one) && sender.seal(23, b"two", &mut two));
		let (header_one, header_two): ([u8; 5], [u8; 5]) = (one[..5].try_into().unwrap(), two[..5].try_into().unwrap());
		assert!(receiver.open(&header_two, &mut two[5..].to_vec()).is_none());
		let mut flipped = one[5..].to_vec();
		flipped[2] ^= 1;
		assert!(receiver.open(&header_one, &mut flipped).is_none());
		let mut other = [23, 3, 1, header_one[3], header_one[4]];
		assert!(receiver.open(&other, &mut one[5..].to_vec()).is_none());
		other[2] = 3;
		assert_eq!(receiver.open(&other, &mut one[5..].to_vec()), Some((23, &b"one"[..])));
		assert_eq!(receiver.open(&header_two, &mut two[5..].to_vec()), Some((23, &b"two"[..])));
		sender.number = sender.limit;
		assert!(!sender.seal(23, b"late", &mut Vec::new()) && !Keys::new(suite, &secret).seal(23, &[0; 16_385], &mut Vec::new()));
	}
	// The nonce is the iv xor the record number, as 64 bits padded on the left, and the padding of a record is zeros behind the content type.
	let mut keys = Keys::new(Suite::Chacha, &[3; 32]);
	keys.number = 0x0102_0304_0506;
	let mut nonce = keys.iv;
	for (byte, counter) in nonce[4..].iter_mut().zip([0, 0, 1, 2, 3, 4, 5, 6]) {*byte ^= counter}
	let mut inner = [&b"padded"[..], &[23, 0, 0, 0]].concat();
	let header = [23, 3, 3, 0, 26];
	let tag = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &expand::<32>(&hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &[3; 32]), "key", &[])).unwrap()).seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&header[..]), &mut inner).unwrap();
	inner.extend_from_slice(tag.as_ref());
	assert_eq!(keys.open(&header, &mut inner), Some((23, &b"padded"[..])));
	let mut zeros = [0; 17];
	assert!(Keys::new(Suite::Aes, &[3; 32]).open(&[23, 3, 3, 0, 17], &mut zeros).is_none());
}

#[tokio::test]
async fn the_hello_is_chromes_with_a_proof_a_node_opens_and_a_key_share_that_is_new_every_time() {
	let client = client(&link()).unwrap();
	let (node, table, mut shares_seen) = (node(NODE), table(), HashSet::new());
	for _ in 0..8 {
		let (record, x, leaf) = hello(&client, SITE, NOW).unwrap();
		assert_eq!(record[..3], [22, 3, 1]);
		assert_eq!(usize::from(u16::from_be_bytes([record[3], record[4]])), record.len() - 5);
		let message = &record[5..];
		let parsed = parse(message).unwrap();
		assert_eq!((parsed.name, parsed.tls13), (SITE.as_bytes(), true));
		assert_eq!(message[parsed.share..parsed.share + 32], x25519(x, X25519_BASEPOINT_BYTES));
		// The standalone share is where the page says `X` is. BoringSSL draws its own X25519 key for the hybrid share, so the capture has the two apart and the hybrid share stays as it was (the page: "it draws a separate key if the capture does").
		let (standalone, hybrid) = shares(message).unwrap();
		assert_eq!(standalone, parsed.share);
		let hybrid = hybrid.unwrap();
		assert!(message[hybrid..hybrid + 32] != message[standalone..standalone + 32], "the capture ties the two shares: BoringSSL changed, and `hello` now puts X in both");
		let Outcome::Proved(opened) = node.open(message, &[SITE.as_bytes()], &table) else {panic!("a node did not open the proof")};
		assert_eq!((opened.timestamp, opened.share, leaf_key(&opened.seed).map(|(_, point)| point)), (NOW, x25519(x, X25519_BASEPOINT_BYTES), Some(leaf)));
		assert!(shares_seen.insert(x));
	}
	assert_eq!(reused(), 0);
	// Another node's key does not open it, and a name that is none is no hello.
	assert!(matches!(self::node([0x62; 32]).open(&hello(&client, SITE, NOW).unwrap().0[5..], &[SITE.as_bytes()], &table), Outcome::Stranger));
	assert!(matches!(node.open(&hello(&client, "other.example", NOW).unwrap().0[5..], &[SITE.as_bytes()], &table), Outcome::Stranger));
}

#[test]
fn records_are_cut_from_the_stream_and_a_bad_header_is_refused_before_its_body_is_waited_for() {
	let mut records = Records::default();
	let wire = [&[23, 3, 3, 0, 3, 1, 2, 3][..], &[22, 3, 1, 0, 1, 9]].concat();
	for byte in &wire[..7] {
		records.feed(&[*byte]);
		assert!(matches!(records.next(), Ok(None)));
	}
	records.feed(&wire[7..]);
	assert_eq!(records.next().unwrap().map(|(header, body)| (header, body.to_vec())), Some(([23, 3, 3, 0, 3], vec![1, 2, 3])));
	assert_eq!(records.next().unwrap().map(|(header, body)| (header, body.to_vec())), Some(([22, 3, 1, 0, 1], vec![9])));
	assert!(matches!(records.next(), Ok(None)));
	for header in [[24, 3, 3, 0, 1], [19, 3, 3, 0, 1], [23, 2, 3, 0, 1], [23, 3, 3, 0, 0], [23, 3, 3, 0x42, 0x01]] {
		let mut records = Records::default();
		records.feed(&header);
		assert!(matches!(records.next(), Err(Fault::Frame)), "{header:?}");
	}
	let mut largest = Records::default();
	largest.feed(&[23, 3, 3, 0x41, 0x00]);
	assert!(matches!(largest.next(), Ok(None)));
}

#[test]
fn a_server_hello_is_read_only_when_it_is_the_one_answer_a_node_gives() {
	let (session, share) = ([0x33; 32], [0x44; 32]);
	let make = |random: &[u8; 32], echoed: &[u8], suite: u16, extensions: &[u8]| {
		let body = [&[3, 3][..], random, &[echoed.len() as u8], echoed, &suite.to_be_bytes(), &[0], &(extensions.len() as u16).to_be_bytes(), extensions].concat();
		[&[2, 0, (body.len() >> 8) as u8, body.len() as u8][..], &body].concat()
	};
	let good = [&[0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32][..], &share].concat();
	assert_eq!(server_hello(&make(&[7; 32], &session, 0x1301, &good), &session), Some((Suite::Aes, share)));
	assert_eq!(server_hello(&make(&[7; 32], &session, 0x1303, &good), &session), Some((Suite::Chacha, share)));
	let swapped = [&[0, 51, 0, 36, 0, 29, 0, 32][..], &share, &[0, 43, 0, 2, 3, 4]].concat();
	assert_eq!(server_hello(&make(&[7; 32], &session, 0x1301, &swapped), &session), Some((Suite::Aes, share)));
	// Another suite or a hello retry, a group that is not X25519, a session id that is not ours, another extension, a repeated one, a missing one and bytes behind the message.
	let retry = [&[0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 29][..]].concat();
	let hybrid = [&[0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0x11, 0xec, 0, 32][..], &share].concat();
	let psk = [&good[..], &[0, 41, 0, 2, 0, 0]].concat();
	let twice = [&good[..], &good[..6]].concat();
	for (random, echoed, suite, extensions) in [(&[7; 32], &session[..], 0x1302, &good), (&[7; 32], &session[..], 0x1301, &retry), (&HELLO_RETRY, &session[..], 0x1301, &good), (&[7; 32], &session[..], 0x1301, &hybrid), (&[7; 32], &[0x34; 32][..], 0x1301, &good), (&[7; 32], &[][..], 0x1301, &good), (&[7; 32], &session[..], 0x1301, &psk), (&[7; 32], &session[..], 0x1301, &twice), (&[7; 32], &session[..], 0x1301, &good[..6].to_vec()), (&[7; 32], &session[..], 0x1301, &good[6..].to_vec())] {
		assert_eq!(server_hello(&make(random, echoed, suite, extensions), &session), None, "{suite:x} {extensions:?}");
	}
	let mut extra = make(&[7; 32], &session, 0x1301, &good);
	extra.push(0);
	assert_eq!(server_hello(&extra, &session), None);
	assert_eq!(server_hello(&extra[..extra.len() - 3], &session), None);
}

#[test]
fn a_certificate_is_read_to_its_first_entry_and_a_compressed_one_to_its_declared_length() {
	let entry = |der: &[u8]| [&(der.len() as u32).to_be_bytes()[1..], der, &[0, 0]].concat();
	let chain = [entry(b"leaf"), entry(b"authority")].concat();
	let body = [&[0][..], &(chain.len() as u32).to_be_bytes()[1..], &chain].concat();
	assert_eq!(first_certificate(&body), Some(&b"leaf"[..]));
	let mut asked = body.clone();
	asked[0] = 1;
	assert_eq!(first_certificate(&asked), None);
	assert_eq!(first_certificate(&[&body[..], &[0]].concat()), None);
	assert_eq!(first_certificate(&body[..body.len() - 20]), None);
	let mut compressed = Vec::new();
	brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22).write_all(&body).unwrap();
	let message = |algorithm: u16, size: usize, data: &[u8]| [&algorithm.to_be_bytes()[..], &(size as u32).to_be_bytes()[1..], &(data.len() as u32).to_be_bytes()[1..], data].concat();
	assert_eq!(inflate(&message(2, body.len(), &compressed)), Some(body.clone()));
	for bad in [message(1, body.len(), &compressed), message(2, body.len() - 1, &compressed), message(2, body.len() + 1, &compressed), message(2, LARGEST_CHAIN + 1, &compressed), message(2, body.len(), &compressed[..compressed.len() - 2]), [&message(2, body.len(), &compressed)[..], &[0]].concat()] {assert_eq!(inflate(&bad), None)}
	// A stream that declares little and holds a lot is read to the declared length and one byte more, and refused.
	let mut large = Vec::new();
	brotli::CompressorWriter::new(&mut large, 4096, 5, 22).write_all(&vec![7; 1 << 20]).unwrap();
	assert_eq!(inflate(&message(2, 100, &large)), None);
}

#[derive(Clone, Copy)]
enum Reply {Datagram, Raw(&'static [u8]), Garbage}

/// What the node saw of the client once the handshake was over.
#[derive(Debug, Default)]
struct Heard {finished: bool, datagrams: Vec<Vec<u8>>, close_notify: bool}

// A TLS 1.3 server that is only the page's node: it opens the proof with `node` and `table`, answers with a flight whose leaf is the derived one for a proof it opened and a random one otherwise, and records what the client does after the handshake. The records of its flight are one per message, or one stream cut every `cut` bytes, and the certificate is compressed or not.
async fn serve(listener: TcpListener, node: Node, table: Table<Device<u32>>, suite: Suite, cut: Option<usize>, compress: bool, reply: Reply) -> Heard {
	let (mut io, _) = listener.accept().await.unwrap();
	let mut records = Records::default();
	let (header, hello) = record(&mut io, &mut records).await.unwrap();
	assert_eq!(header[0], 22);
	let parsed = parse(&hello).unwrap();
	let seed = match node.open(&hello, &[SITE.as_bytes()], &table) {
		Outcome::Proved(opened) => opened.seed,
		_ => fill::<40>(),
	};
	let (pkcs8, _) = leaf_key(&seed).unwrap();
	let der = CertificateParams::new(vec![SITE.to_string()]).unwrap().self_signed(&KeyPair::try_from(&pkcs8[..]).unwrap()).unwrap().der().to_vec();
	let private = fill::<32>();
	let public = x25519(private, X25519_BASEPOINT_BYTES);
	let shared = x25519(private, hello[parsed.share..parsed.share + 32].try_into().unwrap());
	let id: u16 = if suite == Suite::Aes {0x1301} else {0x1303};
	let extensions = [&[0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32][..], &public].concat();
	let body = [&[3, 3][..], &[0x77; 32], &[32], &hello[39..71], &id.to_be_bytes(), &[0], &(extensions.len() as u16).to_be_bytes(), &extensions].concat();
	let server_hello = [&[2, 0, (body.len() >> 8) as u8, body.len() as u8][..], &body].concat();
	let mut transcript = digest::Context::new(&digest::SHA256);
	transcript.update(&hello);
	transcript.update(&server_hello);
	let (client_hs, server_hs, salt) = handshake_secrets(&shared, transcript.clone().finish().as_ref());
	let (mut client_keys, mut server_keys) = (Keys::new(suite, &client_hs), Keys::new(suite, &server_hs));
	let u24 = |value: usize| (value as u32).to_be_bytes()[1..].to_vec();
	let certificate = [&[0][..], &u24(3 + der.len() + 2), &u24(der.len()), &der, &[0, 0]].concat();
	let certificate = if compress {
		let mut compressed = Vec::new();
		brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22).write_all(&certificate).unwrap();
		[vec![25], u24(2 + 3 + 3 + compressed.len()), vec![0, 2], u24(certificate.len()), u24(compressed.len()), compressed].concat()
	} else {
		[vec![11], u24(certificate.len()), certificate].concat()
	};
	let mut messages = vec![vec![8, 0, 0, 2, 0, 0], certificate];
	messages.iter().for_each(|message| transcript.update(message));
	let content = [&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", transcript.clone().finish().as_ref()].concat();
	let signature = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &SystemRandom::new()).unwrap().sign(&SystemRandom::new(), &content).unwrap();
	let verify = [vec![15], u24(4 + signature.as_ref().len()), vec![4, 3], (signature.as_ref().len() as u16).to_be_bytes().to_vec(), signature.as_ref().to_vec()].concat();
	transcript.update(&verify);
	messages.push(verify);
	let done = hmac::sign(&finished(&server_hs), transcript.clone().finish().as_ref());
	let done = [&[20, 0, 0, 32][..], done.as_ref()].concat();
	transcript.update(&done);
	messages.push(done);
	let mut out = [&[22, 3, 3, (server_hello.len() >> 8) as u8, server_hello.len() as u8][..], &server_hello, &[20, 3, 3, 0, 1, 1]].concat();
	match cut {
		None => messages.iter().for_each(|message| assert!(server_keys.seal(22, message, &mut out))),
		Some(cut) => messages.concat().chunks(cut).for_each(|piece| assert!(server_keys.seal(22, piece, &mut out))),
	}
	io.write_all(&out).await.unwrap();
	let mut heard = Heard::default();
	let (header, mut body) = record(&mut io, &mut records).await.unwrap();
	let hash = transcript.finish();
	let (client_ap, server_ap, _) = secrets(&salt, &[0; 32], ["c ap traffic", "s ap traffic"], hash.as_ref());
	heard.finished = header[0] == 23 && client_keys.open(&header, &mut body) == Some((22, &[&[20, 0, 0, 32][..], hmac::sign(&finished(&client_hs), hash.as_ref()).as_ref()].concat()[..]));
	let (mut sender, mut receiver, mut replied) = (Keys::new(suite, &server_ap), Keys::new(suite, &client_ap), false);
	while let Ok((header, mut body)) = record(&mut io, &mut records).await {
		let Some((kind, plain)) = receiver.open(&header, &mut body) else {break};
		if kind == 21 {
			heard.close_notify = plain == [1, 0];
			let mut out = Vec::new();
			assert!(sender.seal(21, &[1, 0], &mut out));
			let _ = io.write_all(&out).await;
			break;
		}
		assert_eq!(kind, 23);
		let chunk = chunk::parse(&plain[2..]).unwrap();
		heard.datagrams.extend(chunk.map(<[u8]>::to_vec));
		if replied {continue}
		replied = true;
		let mut out = Vec::new();
		match reply {
			Reply::Datagram => {
				let mut frame = vec![0, 0];
				chunk::write(&[&[4; 40][..]], 30, &mut frame).unwrap();
				let size = (frame.len() - 2) as u16;
				frame[..2].copy_from_slice(&size.to_be_bytes());
				assert!(sender.seal(22, &[4, 0, 0, 4, 1, 2, 3, 4], &mut out) && sender.seal(23, &frame, &mut out));
			}
			Reply::Raw(frame) => assert!(sender.seal(23, frame, &mut out)),
			Reply::Garbage => out.extend_from_slice(&[&[23, 3, 3, 0, 40][..], &[0x42; 40]].concat()),
		}
		io.write_all(&out).await.unwrap();
	}
	heard
}

#[tokio::test]
async fn a_session_runs_over_a_node_with_either_suite_and_any_cut_of_its_flight() {
	for (suite, cut, compress) in [(Suite::Aes, None, false), (Suite::Chacha, Some(usize::MAX), true), (Suite::Aes, Some(37), false), (Suite::Chacha, Some(1), true)] {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let server = tokio::spawn(serve(listener, node(NODE), table(), suite, cut, compress, Reply::Datagram));
		let mut session = session(address);
		let datagram = timeout(Duration::from_secs(10), session.recv()).await.unwrap().unwrap();
		assert_eq!(datagram, [4; 40]);
		assert_eq!(session.state(), State::Established);
		assert!(session.send([&[4, 0, 0, 0][..], &[9; 60]].concat(), PLAIN));
		assert_eq!(session.close().await, Ended::Closed(End::Asked));
		let heard = server.await.unwrap();
		assert!(heard.finished && heard.close_notify, "{suite:?} {cut:?} {compress}: {heard:?}");
		assert_eq!(heard.datagrams, [[&[1, 0, 0, 0][..], &[0xee; 144]].concat(), [&[4, 0, 0, 0][..], &[9; 60]].concat()]);
	}
}

#[tokio::test]
async fn a_leaf_that_is_not_the_nodes_ends_the_attempt_after_the_handshake_with_a_close_notify_and_no_data() {
	// A device the node does not know is a hello that opened and was refused, and another node's key is a stranger's: the flight of each has a leaf nothing derives.
	for (key, table) in [(NODE, Table::new()), ([0x62; 32], table())] {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let server = tokio::spawn(serve(listener, node(key), table, Suite::Aes, None, false, Reply::Datagram));
		let mut session = session(address);
		assert_eq!(timeout(Duration::from_secs(10), session.recv()).await.unwrap(), Err(Ended::Unreachable(Unreachable::Certificate)));
		assert_eq!(session.close().await, Ended::Unreachable(Unreachable::Certificate));
		let heard = server.await.unwrap();
		assert!(heard.finished && heard.close_notify && heard.datagrams.is_empty(), "{heard:?}");
	}
}

#[tokio::test]
async fn a_frame_that_is_malformed_or_a_record_that_does_not_open_ends_the_session() {
	let frames: [(Reply, Ended); 5] = [
		(Reply::Raw(&[0, 0]), Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::Raw(&[0, 9, 0, 0]), Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::Raw(&[0]), Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::Raw(&[0, 4, 0, 10, 1, 2]), Ended::Closed(End::Fault(Fault::Chunk))),
		(Reply::Garbage, Ended::Closed(End::Fault(Fault::Frame))),
	];
	for (reply, wanted) in frames {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let server = tokio::spawn(serve(listener, node(NODE), table(), Suite::Chacha, None, false, reply));
		let mut session = session(address);
		assert_eq!(timeout(Duration::from_secs(10), session.recv()).await.unwrap(), Err(wanted));
		drop(session);
		let _ = server.await;
	}
}

#[tokio::test]
async fn a_padding_only_frame_is_a_frame_of_the_node() {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let server = tokio::spawn(serve(listener, node(NODE), table(), Suite::Aes, None, false, Reply::Raw(&[0, 3, 0, 0, 0])));
	let session = session(address);
	let mut state = session.watch();
	timeout(Duration::from_secs(10), state.wait_for(|state| *state == State::Established)).await.unwrap().unwrap();
	assert_eq!(session.numbers().received, 0);
	drop(session);
	let _ = server.await;
}

#[tokio::test]
async fn a_candidate_a_borrowed_site_does_not_take_is_refused_before_anything_is_dialled() {
	let (link, address) = (link(), "127.0.0.1:9".parse().unwrap());
	let open = |link: &Link, candidate: Front| Session::open(link, Target::FakeTls {candidate, client: client(&self::link()).unwrap()}, env(), source()).map(|_| ()).unwrap_err();
	assert_eq!(open(&link, Front {pins: vec![[1; 32]], ..front(address)}), Refuse::Candidate);
	assert_eq!(open(&link, Front {self_signed: true, ..front(address)}), Refuse::Candidate);
	assert_eq!(open(&link, Front {verify_name: Some(SITE.into()), ..front(address)}), Refuse::Candidate);
	assert_eq!(open(&link, Front {ech: true, ..front(address)}), Refuse::Ech);
	assert_eq!(open(&link, Front {sni: None, ..front(address)}), Refuse::Name);
	assert_eq!(open(&link, Front {sni: Some("192.0.2.7".into()), ..front(address)}), Refuse::Name);
	assert_eq!(open(&Link {node: None, ..self::link()}, front(address)), Refuse::NodeKey);
	assert!(client(&Link {node: None, ..self::link()}).is_none());
}
