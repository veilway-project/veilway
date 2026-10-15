//! The ClientHello the transport sends, captured from a listener that reads the first flight and hangs up, and measured by JA4 and JA3 (GREASE left out of both, as they define).
use crate::{tls, Front};
use ring::digest::{digest, SHA256};
use rustls::RootCertStore;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::Instant;

struct Hello {version: u16, ciphers: Vec<u16>, extensions: Vec<u16>, groups: Vec<u16>, formats: Vec<u8>, sigalgs: Vec<u16>, alpn: Vec<u8>, sni: bool, shares: Vec<u16>, ech: bool}

fn grease(value: u16) -> bool {value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff}

fn pairs(bytes: &[u8]) -> Vec<u16> {bytes.chunks(2).map(|pair| u16::from_be_bytes([pair[0], pair[1]])).filter(|value| !grease(*value)).collect()}

fn parse(record: &[u8]) -> Hello {
	let at = |from: usize| usize::from(u16::from_be_bytes([record[from], record[from + 1]]));
	let mut cursor = 5 + 4 + 2 + 32;
	cursor += 1 + usize::from(record[cursor]);
	let ciphers = pairs(&record[cursor + 2..cursor + 2 + at(cursor)]);
	cursor += 2 + at(cursor);
	cursor += 1 + usize::from(record[cursor]);
	let end = cursor + 2 + at(cursor);
	cursor += 2;
	let mut hello = Hello {version: 0x0303, ciphers, extensions: vec![], groups: vec![], formats: vec![], sigalgs: vec![], alpn: vec![], sni: false, shares: vec![], ech: false};
	while cursor < end {
		let (kind, body) = (at(cursor) as u16, &record[cursor + 4..cursor + 4 + at(cursor + 2)]);
		cursor += 4 + body.len();
		if grease(kind) {continue}
		hello.extensions.push(kind);
		match kind {
			0 => hello.sni = true,
			10 => hello.groups = pairs(&body[2..]),
			11 => hello.formats = body[1..].to_vec(),
			13 => hello.sigalgs = pairs(&body[2..]),
			16 => hello.alpn = body[3..].to_vec(),
			43 => hello.version = pairs(&body[1..]).into_iter().max().unwrap(),
			51 => {
				let (mut share, length) = (2, usize::from(u16::from_be_bytes([body[0], body[1]])) + 2);
				while share < length {
					hello.shares.push(u16::from_be_bytes([body[share], body[share + 1]]));
					share += 4 + usize::from(u16::from_be_bytes([body[share + 2], body[share + 3]]));
				}
				hello.shares.retain(|group| !grease(*group));
			}
			0xfe0d => hello.ech = true,
			_ => {}
		}
	}
	hello
}

fn first12(text: &str) -> String {digest(&SHA256, text.as_bytes()).as_ref().iter().take(6).map(|byte| format!("{byte:02x}")).collect()}

fn ja4(hello: &Hello) -> String {
	let hex = |values: &[u16]| values.iter().map(|value| format!("{value:04x}")).collect::<Vec<_>>();
	let (mut ciphers, mut extensions) = (hex(&hello.ciphers), hex(&hello.extensions.iter().copied().filter(|kind| *kind != 0 && *kind != 16).collect::<Vec<_>>()));
	(ciphers.sort(), extensions.sort());
	let alpn = if hello.alpn.len() > 1 {format!("{}{}", hello.alpn[0] as char, *hello.alpn.last().unwrap() as char)} else {"00".into()};
	let version = match hello.version {0x0304 => "13", 0x0303 => "12", _ => "00"};
	format!("t{version}{}{:02}{:02}{alpn}_{}_{}", if hello.sni {"d"} else {"i"}, hello.ciphers.len(), hello.extensions.len(), first12(&ciphers.join(",")), first12(&format!("{}_{}", extensions.join(","), hex(&hello.sigalgs).join(","))))
}

fn ja3(hello: &Hello) -> String {
	let list = |values: &[u16]| values.iter().map(u16::to_string).collect::<Vec<_>>().join("-");
	format!("771,{},{},{},{}", list(&hello.ciphers), list(&hello.extensions), list(&hello.groups), hello.formats.iter().map(u8::to_string).collect::<Vec<_>>().join("-"))
}

async fn flight(sni: Option<&str>) -> Hello {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let front = Front {address: listener.local_addr().unwrap(), sni: sni.map(str::to_owned), host: "node.test".into(), verify_name: None, pins: vec![[7; 32]], ech: false, self_signed: true};
	let dialled = tokio::spawn(async move {tls::dial(&front, &Arc::new(RootCertStore::empty()), &None, Instant::now() + Duration::from_secs(5)).await.is_err()});
	let (mut peer, _) = listener.accept().await.unwrap();
	let mut record = vec![0; 5];
	peer.read_exact(&mut record).await.unwrap();
	record.resize(5 + usize::from(u16::from_be_bytes([record[3], record[4]])), 0);
	peer.read_exact(&mut record[5..]).await.unwrap();
	drop(peer);
	assert!(dialled.await.unwrap());
	parse(&record)
}

// The target is Chrome's wss:// hello shape: Chrome 131's JA4 with ALPS left out (this client's ALPN is `http/1.1` alone, as a WebSocket sends it, so Chrome sends no ALPS). It still needs confirming against a real Chrome capture.
const TARGET: &str = "t13d1515h1_8daaf6152771_0a20fe35d3a5";

#[tokio::test]
async fn the_client_hello_is_chromes_by_ja4_and_its_extensions_move_by_ja3() {
	let mut orders = HashSet::new();
	for _ in 0..20 {
		let hello = flight(Some("node.test")).await;
		assert_eq!(ja4(&hello), TARGET);
		assert_eq!(hello.groups, [0x11ec, 0x001d, 0x0017, 0x0018]);
		assert_eq!(hello.shares, [0x11ec, 0x001d]);
		assert_eq!((hello.formats.as_slice(), hello.alpn.as_slice(), hello.ech), (&[0][..], &b"http/1.1"[..], true));
		orders.insert(ja3(&hello));
	}
	assert!(orders.len() > 1, "the extensions never moved");
}

#[tokio::test]
async fn a_candidate_with_no_server_name_sends_none() {
	let hello = flight(None).await;
	assert!(!hello.sni && ja4(&hello).starts_with("t13i1514h1_8daaf6152771_0a20fe35d3a5"));
}
