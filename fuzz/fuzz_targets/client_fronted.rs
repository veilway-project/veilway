#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::chunk::{Padding, Sealer};
use veilway_proto::fronted::{self, Opener, BODY_MAX, BODY_MIN};
use veilway_proto::keys::ChunkKey;
use veilway_proto::NoRandom;
use veilway_transport::http::{self, HEAD_MAX};

// The answer to a `fronted` request as a client reads it (`http::response`, and then the body under the session's key). Two bytes of settings, then what the mode says:
//   0  bit 0 set: the rest is the bytes of the connection as they are. Clear: the rest is chunks as in `client_frames`, sealed here as the node seals them into one body, behind a head with that body's length. Bit 1: one bit of the answer is changed on its way. Bit 2: the head names its length twice. Bit 3: one byte stands behind the body.
//   1  where the changed bit lies, and how much of the answer has arrived when the reader is first asked
// Whatever arrives, an answer must be found at its last byte and not before it, with a body of 18 to 65,536 bytes, a verdict must not turn back into an answer when more bytes come, and the reader must give up within the bound of a head and a body. A body that opens must hold what the node sealed and nothing else.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, pick], rest)) = data.split_first_chunk::<2>() else {return};
	let (key, mut sealed, mut count): ([u8; 32], _, u8) = (std::array::from_fn(|at| at as u8), Vec::new(), 0);
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for byte in bytes {
			count = count.wrapping_mul(13).wrapping_add(7);
			*byte = count;
		}
		Ok(())
	};
	let mut answer = if flags & 1 == 1 {rest.to_vec()} else {
		let (mut sealer, mut left, mut body) = (Sealer::new(ChunkKey::new(&key), Padding::new(1023, 255, &mut random).expect("the default bounds")), rest, Vec::new());
		// "A request or response with nothing to carry holds one padding-only chunk": a body has one chunk at the least.
		loop {
			let (items, mut tail) = left.split_first().map_or((0, left), |(items, tail)| (*items, tail));
			let mut datagrams = Vec::new();
			for _ in 0..items % 5 {
				let [size, more @ ..] = tail else {break};
				let Some((datagram, more)) = more.split_at_checked(32 + usize::from(*size)) else {break};
				datagrams.push(datagram);
				tail = more;
			}
			left = tail;
			if fronted::append(&mut sealer, &datagrams, false, &mut random, &mut body).is_err() {break}
			sealed.push(datagrams.iter().map(|datagram| datagram.to_vec()).collect::<Vec<_>>());
			if left.is_empty() {break}
		}
		let length = format!("Content-Length: {}\r\n", body.len());
		[&b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"[..], length.as_bytes(), if flags & 4 != 0 {length.as_bytes()} else {b""}, b"\r\n", &body, if flags & 8 != 0 {&b"x"[..]} else {b""}].concat()
	};
	let changed = flags & 3 == 2 && !answer.is_empty();
	if changed {
		let at = usize::from(pick) * 131 % answer.len();
		answer[at] ^= 1 << (pick % 8);
	}
	let (whole, early) = (http::response(&answer), http::response(&answer[..answer.len() * usize::from(pick) / 256]));
	match &whole {
		Ok(Some(body)) => {
			assert!(body.end == answer.len() && (BODY_MIN..=BODY_MAX).contains(&body.len()) && body.start <= HEAD_MAX, "an answer was found that is none");
			assert_eq!((early, http::response(&answer[..answer.len() - 1])), (Ok(None), Ok(None)), "an answer was found before its last byte");
			assert!(http::response(&[&answer[..], b"x"].concat()).is_err(), "a byte behind an answer was taken");
		}
		Ok(None) => assert!(answer.len() < HEAD_MAX + BODY_MAX && early == Ok(None), "the reader waits for more than an answer can be"),
		Err(_) => assert!(http::response(&[&answer[..], b"x"].concat()).is_err() && http::response(&[&answer[..], &[b'x'; 300]].concat()).is_err(), "a verdict turned back into an answer"),
	}
	if flags & 1 == 0 {
		let (mut opener, mut scratch) = (Opener::new(ChunkKey::new(&key)), Vec::new());
		let opened = whole.clone().ok().flatten().and_then(|body| opener.open(&answer[body], &mut scratch).ok()).map(|opened| opened.commit().into_iter().map(|items| items.map(<[u8]>::to_vec).collect::<Vec<_>>()).collect::<Vec<_>>());
		if let Some(chunks) = &opened {assert_eq!(*chunks, sealed, "a body opened that holds what the node did not seal")}
		if !changed {assert_eq!(opened.is_some(), flags & 12 == 0, "what the node sealed did not come out, or an answer with two lengths or a byte too many did")}
	}
});
