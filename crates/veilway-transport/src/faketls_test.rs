//! The client of `faketls` against a node that is only its keys: the hello it sends against the node's reading of it, and sessions against a small TLS 1.3 server that makes the flight the page describes, and against the node's own flight writer (`veilway_proto::flight`), with either suite and either group. The key schedule and the record layer are tested in `veilway-proto`.
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
use veilway_proto::flight::{answer, Burst, Flight, Shape, Wire};
use veilway_proto::keys::{Device, Table, TagKey};
use veilway_proto::subscription::payload::Padding as Bounds;
use veilway_proto::subscription::Secret;
use veilway_proto::tls13::{write_server_hello, Suite};

const SITE: &str = "site.example";
const NODE: [u8; 32] = [0x61; 32];
const INBOUND: [u8; 32] = [0x21; 32];
const DEVICE: [u8; 32] = [0x41; 32];
const SECRET: [u8; 32] = [0x11; 32];
const NOW: u64 = 1_700_000_000;
const PLAIN: Kind = Kind::Packet {flow: 0, control: false};

fn fill<const N: usize>() -> [u8; N] {
	let mut bytes = [0; N];
	SystemRandom::new().fill(&mut bytes).unwrap();
	bytes
}

fn link() -> Link {Link {inbound: INBOUND, device: DEVICE, secret: Secret::new(SECRET), node: Some(x25519(NODE, X25519_BASEPOINT_BYTES)), mtu: 1390, padding: Bounds {wide_max: 1023, normal_max: 255, keepalive: 20_000..=20_000}, borrowed: Default::default()}}

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
	Session::open(&link, Target::FakeTls {candidate: front(address), client: client(&link, &link.node.unwrap())}, env(), source()).unwrap()
}

#[tokio::test]
async fn the_hello_is_chromes_with_a_proof_a_node_opens_and_a_key_share_that_is_new_every_time() {
	let link = link();
	let client = client(&link, &link.node.unwrap());
	let (node, table, mut shares_seen) = (node(NODE), table(), HashSet::new());
	for _ in 0..8 {
		let (record, x, kem, leaf) = hello(&client, SITE, NOW).unwrap();
		assert_eq!(record[..3], [22, 3, 1]);
		assert_eq!(usize::from(u16::from_be_bytes([record[3], record[4]])), record.len() - 5);
		let message = &record[5..];
		let parsed = parse(message).unwrap();
		assert_eq!((parsed.name, parsed.tls13), (SITE.as_bytes(), true));
		assert_eq!(message[parsed.share..parsed.share + 32], x25519(x, X25519_BASEPOINT_BYTES));
		// The standalone share is where the page says `X` is. BoringSSL draws its own X25519 key for the hybrid share, so the capture has the two apart and the client draws a key of its own for the hybrid share (the page: "it draws a separate key if the capture does"), whose ML-KEM key it also replaces.
		let (standalone, hybrid) = shares(message).unwrap();
		assert_eq!(standalone, parsed.share);
		let hybrid = hybrid.unwrap();
		let (own, seed) = kem.unwrap();
		assert_eq!(message[hybrid..hybrid + 32], x25519(own, X25519_BASEPOINT_BYTES));
		assert!(message[hybrid..hybrid + 32] != message[standalone..standalone + 32], "the capture ties the two shares: BoringSSL changed, and `hello` now puts X in both");
		let (ciphertext, secret) = mlkem::encap(&message[hybrid - KEM_KEY..hybrid]).unwrap();
		assert_eq!(mlkem::decap(&seed, &ciphertext), Some(secret));
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
fn a_certificate_is_read_to_its_first_entry_and_a_compressed_one_to_its_declared_length() {
	let entry = |der: &[u8]| [&(der.len() as u32).to_be_bytes()[1..], der, &[0, 0]].concat();
	let chain = [entry(b"leaf"), entry(b"authority")].concat();
	let body = [&[0][..], &(chain.len() as u32).to_be_bytes()[1..], &chain].concat();
	assert_eq!(first_certificate(&body), Some((&b"leaf"[..], &entry(b"authority")[..])));
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
enum Reply {Datagram, Raw(&'static [u8]), Garbage, KeyUpdate}

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
	let server_hello = write_server_hello(&hello[39..71], suite, X25519, false, &[0x77; 32], &public);
	let mut transcript = Transcript::new(suite);
	transcript.update(&hello);
	transcript.update(&server_hello);
	let secrets = handshake_secrets(suite, &shared, &transcript.hash());
	let (mut client_keys, mut server_keys) = (Keys::new(suite, &secrets.client), Keys::new(suite, &secrets.server));
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
	let content = [&[0x20; 64][..], b"TLS 1.3, server CertificateVerify\0", &transcript.hash()].concat();
	let signature = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &SystemRandom::new()).unwrap().sign(&SystemRandom::new(), &content).unwrap();
	let verify = [vec![15], u24(4 + signature.as_ref().len()), vec![4, 3], (signature.as_ref().len() as u16).to_be_bytes().to_vec(), signature.as_ref().to_vec()].concat();
	transcript.update(&verify);
	messages.push(verify);
	let verify_data = finished(suite, &secrets.server, &transcript.hash());
	let done = [&[20, 0, 0, verify_data.len() as u8][..], &verify_data].concat();
	transcript.update(&done);
	messages.push(done);
	let mut out = [&[22, 3, 3, (server_hello.len() >> 8) as u8, server_hello.len() as u8][..], &server_hello, &[20, 3, 3, 0, 1, 1]].concat();
	match cut {
		None => messages.iter().for_each(|message| assert!(server_keys.seal(22, message, 0, &mut out))),
		Some(cut) => messages.concat().chunks(cut).for_each(|piece| assert!(server_keys.seal(22, piece, 0, &mut out))),
	}
	io.write_all(&out).await.unwrap();
	let mut heard = Heard::default();
	let (header, mut body) = record(&mut io, &mut records).await.unwrap();
	let hash = transcript.hash();
	let (client_ap, server_ap) = application_secrets(suite, &secrets.next, &hash);
	let client_done = finished(suite, &secrets.client, &hash);
	heard.finished = header[0] == 23 && client_keys.open(&header, &mut body) == Some((22, &[&[20, 0, 0, client_done.len() as u8][..], &client_done].concat()[..]));
	let (mut sender, mut receiver, mut replied) = (Keys::new(suite, &server_ap), Keys::new(suite, &client_ap), false);
	while let Ok((header, mut body)) = record(&mut io, &mut records).await {
		let Some((kind, plain)) = receiver.open(&header, &mut body) else {break};
		if kind == 21 {
			heard.close_notify = plain == [1, 0];
			let mut out = Vec::new();
			assert!(sender.seal(21, &[1, 0], 0, &mut out));
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
				assert!(sender.seal(22, &[4, 0, 0, 4, 1, 2, 3, 4], 0, &mut out) && sender.seal(23, &frame, 0, &mut out));
			}
			Reply::Raw(frame) => assert!(sender.seal(23, frame, 0, &mut out)),
			Reply::Garbage => out.extend_from_slice(&[&[23, 3, 3, 0, 40][..], &[0x42; 40]].concat()),
			Reply::KeyUpdate => assert!(sender.seal(22, &[24, 0, 0, 1, 0], 0, &mut out)),
		}
		io.write_all(&out).await.unwrap();
	}
	heard
}

#[tokio::test]
async fn a_session_runs_over_a_node_with_either_suite_and_any_cut_of_its_flight() {
	for (suite, cut, compress) in [(Suite::Aes128, None, false), (Suite::Chacha, Some(usize::MAX), true), (Suite::Aes128, Some(37), false), (Suite::Chacha, Some(1), true), (Suite::Aes256, None, true), (Suite::Aes256, Some(500), false)] {
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
		let server = tokio::spawn(serve(listener, node(key), table, Suite::Aes128, None, false, Reply::Datagram));
		let mut session = session(address);
		assert_eq!(timeout(Duration::from_secs(10), session.recv()).await.unwrap(), Err(Ended::Unreachable(Unreachable::Certificate)));
		assert_eq!(session.close().await, Ended::Unreachable(Unreachable::Certificate));
		let heard = server.await.unwrap();
		assert!(heard.finished && heard.close_notify && heard.datagrams.is_empty(), "{heard:?}");
	}
}

#[tokio::test]
async fn a_frame_that_is_malformed_or_a_record_that_does_not_open_ends_the_session() {
	let frames: [(Reply, Ended); 6] = [
		(Reply::Raw(&[0, 0]), Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::Raw(&[0, 9, 0, 0]), Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::Raw(&[0]), Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::Raw(&[0, 4, 0, 10, 1, 2]), Ended::Closed(End::Fault(Fault::Chunk))),
		(Reply::Garbage, Ended::Closed(End::Fault(Fault::Frame))),
		(Reply::KeyUpdate, Ended::Closed(End::Exhausted)),
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
	let server = tokio::spawn(serve(listener, node(NODE), table(), Suite::Aes128, None, false, Reply::Raw(&[0, 3, 0, 0, 0])));
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
	let open = |link: &Link, candidate: Front| Session::open(link, Target::FakeTls {candidate, client: client(link, &self::link().node.unwrap())}, env(), source()).map(|_| ()).unwrap_err();
	assert_eq!(open(&link, Front {pins: vec![[1; 32]], ..front(address)}), Refuse::Candidate);
	assert_eq!(open(&link, Front {self_signed: true, ..front(address)}), Refuse::Candidate);
	assert_eq!(open(&link, Front {verify_name: Some(SITE.into()), ..front(address)}), Refuse::Candidate);
	assert_eq!(open(&link, Front {ech: true, ..front(address)}), Refuse::Ech);
	assert_eq!(open(&link, Front {sni: None, ..front(address)}), Refuse::Name);
	assert_eq!(open(&link, Front {sni: Some("192.0.2.7".into()), ..front(address)}), Refuse::Name);
	// The key is the transport's own, held by the client of the target: a link without `node` takes it all the same.
	let bare = Link {node: None, ..self::link()};
	assert!(Session::open(&bare, Target::FakeTls {candidate: front(address), client: client(&bare, &link.node.unwrap())}, env(), source()).is_ok());
}

#[test]
fn a_link_has_one_client_for_each_key() {
	let (link, other) = (link(), x25519([0x62; 32], X25519_BASEPOINT_BYTES));
	let key = link.node.unwrap();
	assert!(Arc::ptr_eq(&client(&link, &key), &client(&link.clone(), &key)));
	assert!(!Arc::ptr_eq(&client(&link, &key), &client(&link, &other)));
	assert!(!Arc::ptr_eq(&client(&link, &key), &client(&self::link(), &key)), "another link is another device");
}

// A node that is the page's own flight writer: it opens the proof, writes the flight of `group` and `suite` with `answer` over records of the sizes it is given, and reads the client's Finished and its first frame. What the client does is the test's to see.
async fn serve_flight(listener: TcpListener, suite: Suite, group: u16, sizes: Vec<usize>) -> Heard {
	let (mut io, _) = listener.accept().await.unwrap();
	let mut records = Records::default();
	let (_, hello) = record(&mut io, &mut records).await.unwrap();
	let (node, table) = (node(NODE), table());
	let Outcome::Proved(opened) = node.open(&hello, &[SITE.as_bytes()], &table) else {panic!("a node did not open the proof")};
	let (first, rest) = sizes.split_first().unwrap();
	let size = write_server_hello(&hello[39..71], suite, group, true, &[0; 32], &vec![0; if group == X25519 {32} else {KEM_CIPHERTEXT + 32}]).len();
	let flight = Flight {suite, group, key_first: true, bursts: vec![Burst {at: Duration::ZERO, wire: vec![Wire::Hello(size), Wire::Ccs, Wire::Sealed(*first)]}, Burst {at: Duration::from_millis(5), wire: rest.iter().map(|size| Wire::Sealed(*size)).collect()}]};
	let mut shape = Shape::generic(0, &mut random);
	shape.extensions = vec![8, 0, 0, 2, 0, 0];
	let mut made = answer(&hello, &flight, &shape, &opened.seed, SITE, &SystemRandom::new(), &mut random, &mut |key| mlkem::encap(key)).expect("the flight is written");
	for (_, bytes) in &made.bursts {io.write_all(bytes).await.unwrap()}
	let mut heard = Heard::default();
	let (header, mut body) = record(&mut io, &mut records).await.unwrap();
	let Some((22, finished)) = made.pending.keys().open(&header, &mut body) else {return heard};
	let mut session = made.pending.finish(finished).expect("the client's Finished is the expected one");
	heard.finished = true;
	let mut replied = false;
	while let Ok((header, mut body)) = record(&mut io, &mut records).await {
		let Some((kind, plain)) = session.receive.open(&header, &mut body) else {break};
		if kind == 21 {
			heard.close_notify = plain == [1, 0];
			break;
		}
		let chunk = chunk::parse(&plain[2..]).unwrap();
		heard.datagrams.extend(chunk.map(<[u8]>::to_vec));
		if replied {continue}
		replied = true;
		let mut frame = vec![0, 0];
		chunk::write(&[&[4; 40][..]], 30, &mut frame).unwrap();
		let size = (frame.len() - 2) as u16;
		frame[..2].copy_from_slice(&size.to_be_bytes());
		let mut out = Vec::new();
		assert!(session.send.seal(23, &frame, 7, &mut out));
		io.write_all(&out).await.unwrap();
	}
	heard
}

#[tokio::test]
async fn a_session_runs_over_the_flight_the_node_writes_in_either_group_with_any_suite() {
	for (suite, group, sizes) in [(Suite::Aes128, X25519, vec![3000]), (Suite::Aes256, X25519, vec![1400, 1450, 700]), (Suite::Chacha, HYBRID, vec![2500, 1000]), (Suite::Aes256, HYBRID, vec![4000])] {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let address = listener.local_addr().unwrap();
		let server = tokio::spawn(serve_flight(listener, suite, group, sizes));
		let mut session = session(address);
		let datagram = timeout(Duration::from_secs(10), session.recv()).await.unwrap().unwrap_or_else(|ended| panic!("{suite:?} {group:x}: {ended:?}"));
		assert_eq!(datagram, [4; 40]);
		assert_eq!(session.close().await, Ended::Closed(End::Asked));
		let heard = server.await.unwrap();
		assert!(heard.finished && heard.close_notify, "{suite:?} {group:x}: {heard:?}");
		assert_eq!(heard.datagrams[0], [&[1, 0, 0, 0][..], &[0xee; 144]].concat());
	}
}

#[tokio::test]
async fn a_clock_the_device_got_wrong_is_put_right_by_the_offset_the_environment_holds() {
	// `Env::now` is the device's clock with the offset a node's `Date` gave, as for every transport: a device two hours off, with the offset held, opens a session in the hour the node is in.
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();
	let server = tokio::spawn(serve_flight(listener, Suite::Aes128, X25519, vec![3000]));
	let link = link();
	let env = Env {device: Arc::new(|| NOW - 7200), now: Arc::new(|| NOW - 7200 + 7200), roots: Arc::new(RootCertStore::empty()), socket: None};
	let mut session = Session::open(&link, Target::FakeTls {candidate: front(address), client: client(&link, &link.node.unwrap())}, env, source()).unwrap();
	assert_eq!(timeout(Duration::from_secs(10), session.recv()).await.unwrap().unwrap(), [4; 40]);
	session.close().await;
	assert!(server.await.unwrap().finished);
}

// The leaf key of `veilway-proto` is pure Rust; BoringSSL, which this crate builds anyway, computes the same `d = (c mod (n - 1)) + 1` and its public point.
#[test]
fn the_leaf_key_matches_what_boringssl_computes() {
	use boring::{bn::{BigNum, BigNumContext}, ec::{EcGroup, EcPoint, PointConversionForm}, nid::Nid};
	let order = BigNum::from_hex_str("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
	for fill in [0u8, 1, 0x7f, 0xff] {
		let mut seed = [fill; 40];
		seed[0] ^= 0x5a;
		seed[39] = 7;
		let (group, mut ctx) = (EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(), BigNumContext::new().unwrap());
		let (mut modulus, mut scalar) = (BigNum::new().unwrap(), BigNum::new().unwrap());
		modulus.checked_sub(&order, &BigNum::from_u32(1).unwrap()).unwrap();
		scalar.nnmod(&BigNum::from_slice(&seed).unwrap(), &modulus, &mut ctx).unwrap();
		scalar.add_word(1).unwrap();
		let mut point = EcPoint::new(&group).unwrap();
		point.mul_generator(&group, &scalar, &mut ctx).unwrap();
		let (pkcs8, public) = leaf_key(&seed).unwrap();
		assert_eq!(public, point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx).unwrap());
		assert_eq!(&pkcs8[36..68], &scalar.to_vec_padded(32).unwrap()[..]);
	}
	assert!(leaf_key(&[0xff; 40]).is_some());
}
