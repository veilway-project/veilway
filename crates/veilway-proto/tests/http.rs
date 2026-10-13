//! Property tests of the HTTP/1.1 framing reader (`veilway_proto::http`): what it says of an answer or a body does not depend on how the bytes were cut, an answer that is written as HTTP writes it ends at its last byte and nowhere else, and no bytes make it panic.
//! The answers are the decoy origin's, which is the operator's own server, so this is about a node that keeps working whatever that server sends, and about never handing a proxy one byte more than the answer to its request.
use proptest::{collection::vec, prelude::*, sample::{select, Index}};
use std::net::IpAddr;
use veilway_proto::http::{self, Answer, Body, Framing, Response};

// Bytes that are mostly the pieces HTTP is made of, in any order, with some that are anything.
fn pieces() -> impl Strategy<Value = Vec<u8>> {
	let known = ["HTTP/1.1 200 OK\r\n", "HTTP/1.0 200 OK\r\n", "HTTP/1.1 100 Continue\r\n\r\n", "HTTP/1.1 204 No Content\r\n", "HTTP/1.1 304 Not Modified\r\n", "HTTP/1.1 101 Switching Protocols\r\n", "GET / HTTP/1.1\r\n", "POST /f HTTP/1.1\r\n", "HEAD / HTTP/1.1\r\n", "Content-Length: 5\r\n", "Content-Length: 0\r\n", "content-length: 9223372036854775808\r\n", "Transfer-Encoding: chunked\r\n", "Connection: close\r\n", "Connection: keep-alive\r\n", "X-Forwarded-For: 198.51.100.7, 127.0.0.1\r\n", "X-Forwarded-For: [2001:db8::7]\r\n", "X: y\r\n", " folded\r\n", "\r\n", "\r\n\r\n", "5\r\nhello\r\n", "0\r\n", "a;x=1\r\n", "hello", "\n", "\r", " ", ":", "\0"];
	vec(prop_oneof![4 => select(known.to_vec()).prop_map(|piece| piece.as_bytes().to_vec()), 1 => vec(any::<u8>(), 0..6)], 0..14).prop_map(|parts| parts.concat())
}

// What a tracker says of `bytes` fed in the pieces that `cuts` make: the first thing it says that is not "more", with where the answer ended counted from the first byte, and whether the origin called it its last.
fn tracked(bodiless: bool, tunnel: bool, bytes: &[u8], cuts: &[Index]) -> (Answer, bool) {
	let mut ends: Vec<usize> = cuts.iter().map(|cut| cut.index(bytes.len() + 1)).chain([bytes.len()]).collect();
	ends.sort_unstable();
	let (mut response, mut start) = (Response::new(bodiless, tunnel), 0);
	for end in ends {
		match response.feed(&bytes[start..end]) {
			Answer::More => start = end,
			Answer::Done(used) => return (Answer::Done(start + used), response.last()),
			Answer::Open => return (Answer::Open, false),
		}
	}
	(Answer::More, false)
}

// An answer as HTTP/1.1 writes it: interim answers first, then a status with one way to say where the body ends, and the body. With it, whether the origin calls it its last, and how many of its bytes come before the body.
fn answer() -> impl Strategy<Value = (Vec<u8>, bool, usize)> {
	(0usize..3, select(vec![200u16, 201, 204, 301, 304, 400, 404, 500, 503]), any::<bool>(), vec(vec(any::<u8>(), 1..40), 0..5), vec("[A-Za-z-]{1,12}: [a-z0-9 ]{0,20}", 0..4), any::<bool>()).prop_map(|(interim, code, chunked, parts, fields, close)| {
		let (mut bytes, bodied) = ("HTTP/1.1 100 Continue\r\n\r\n".repeat(interim).into_bytes(), !matches!(code, 204 | 304));
		bytes.extend_from_slice(format!("HTTP/1.1 {code} Some Words\r\n").as_bytes());
		for field in fields.iter().filter(|field| !["content-length", "transfer-encoding", "connection"].contains(&field.split(':').next().unwrap_or_default().to_ascii_lowercase().as_str())) {bytes.extend_from_slice(format!("{field}\r\n").as_bytes())}
		if close {bytes.extend_from_slice(b"Connection: close\r\n")}
		bytes.extend_from_slice(if chunked && bodied {"Transfer-Encoding: chunked\r\n\r\n".to_string()} else {format!("Content-Length: {}\r\n\r\n", parts.concat().len())}.as_bytes());
		let head = bytes.len();
		if chunked && bodied {
			for part in &parts {bytes.extend_from_slice(&[format!("{:x}\r\n", part.len()).as_bytes(), part, b"\r\n"].concat())}
			bytes.extend_from_slice(b"0\r\nX-Trailer: one\r\n\r\n");
		} else if bodied {bytes.extend_from_slice(&parts.concat())}
		(bytes, close, head)
	})
}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(1024))]

	#[test]
	fn an_answer_is_read_the_same_however_it_is_cut(bytes in pieces(), cuts in vec(any::<Index>(), 0..12), bodiless in any::<bool>(), tunnel in any::<bool>()) {
		let (whole, cut) = (tracked(bodiless, tunnel, &bytes, &[]), tracked(bodiless, tunnel, &bytes, &cuts));
		prop_assert_eq!(whole, cut);
		if let Answer::Done(used) = whole.0 {prop_assert!(used <= bytes.len())}
	}

	// The answer ends at its last byte whatever stands behind it, so nothing behind it is ever taken for a part of it.
	#[test]
	fn an_answer_as_http_writes_it_ends_at_its_last_byte((bytes, close, _) in answer(), behind in pieces(), cuts in vec(any::<Index>(), 0..12)) {
		prop_assert_eq!(tracked(false, false, &[&bytes[..], &behind].concat(), &cuts), (Answer::Done(bytes.len()), close));
	}

	// The answer to a `HEAD` ends with its head, whatever length the head names and whatever stands behind it.
	#[test]
	fn the_answer_to_a_head_ends_with_its_head((bytes, close, head) in answer(), cuts in vec(any::<Index>(), 0..12)) {
		prop_assert_eq!(tracked(true, false, &bytes, &cuts), (Answer::Done(head), close));
	}

	#[test]
	fn a_body_is_read_the_same_however_it_is_cut(bytes in pieces(), cuts in vec(any::<Index>(), 0..12), length in prop_oneof![Just(None), (0u64..40).prop_map(Some)]) {
		let follow = |cuts: &[Index]| {
			let mut ends: Vec<usize> = cuts.iter().map(|cut| cut.index(bytes.len() + 1)).chain([bytes.len()]).collect();
			ends.sort_unstable();
			let (mut body, mut start) = (Body::new(length.map_or(Framing::Chunked, Framing::Length)), 0);
			for end in ends {
				match body.feed(&bytes[start..end]) {
					Ok((taken, true)) => return Ok(Some(start + taken)),
					Ok((taken, false)) => {
						assert_eq!(taken, end - start, "a body that is not complete left bytes behind");
						start = end;
					}
					Err(unsure) => return Err(unsure),
				}
			}
			Ok(None)
		};
		prop_assert_eq!(follow(&[]), follow(&cuts));
	}

	// A head the reader takes as framed says one thing only, and a head it does not take says nothing it could be held to.
	#[test]
	fn a_request_head_never_panics_and_says_one_thing(bytes in pieces()) {
		let request = http::request(&bytes);
		prop_assert!(request.line <= bytes.len());
		if request.body.is_some() {
			prop_assert!(bytes.ends_with(b"\r\n\r\n") && !request.tunnel && bytes[..request.line].ends_with(b" HTTP/1.1\r\n"));
			let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
			prop_assert!(text.matches("content-length").count() + text.matches("transfer-encoding").count() <= 1);
		}
		let _ = http::forwarded(&bytes, b"X-Forwarded-For", |address: IpAddr| address.is_loopback());
		let _ = http::head_end(&bytes);
	}
}
