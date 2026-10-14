#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::chunk::{Padding, Sealer, MAX_SEALED};
use veilway_proto::keys::ChunkKey;
use veilway_proto::websocket::{self, BINARY, HEADER_MAX, PING};
use veilway_proto::NoRandom;
use veilway_transport::stream::{Read, Reader};
use veilway_transport::Fault;

// The frames of a `tls` or `ws` session as a client reads them (`stream::Reader`), behind the upgrade answer. Two bytes of settings, then what the mode says:
//   0  bit 0 set: the rest is the bytes of the connection as they are. Clear: the rest is chunks, each a count of datagrams and then each datagram behind one byte of its size above 32, which are sealed here as the node seals them, one after the other, and put in frames. Bit 1: one bit of that stream is changed on its way. Bit 2: a ping stands in front of every chunk.
//   1  the size of the pieces the stream arrives in, and where the changed bit lies
// Whatever arrives, the reader must give the same frames for the stream in pieces as for the stream whole, keep less than one frame of bytes when it asks for more, and stay failed once it failed. What it gives out as datagrams must be what the node sealed, in order and with nothing in between: all of it when nothing was changed, and no more than a beginning of it when something was.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, pick], rest)) = data.split_first_chunk::<2>() else {return};
	let (key, mut stream, mut sealed, mut count): ([u8; 32], _, _, u8) = (std::array::from_fn(|at| at as u8), Vec::new(), Vec::new(), 0);
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for byte in bytes {
			count = count.wrapping_mul(13).wrapping_add(7);
			*byte = count;
		}
		Ok(())
	};
	if flags & 1 == 1 {stream = rest.to_vec()} else {
		let (mut sealer, mut left) = (Sealer::new(ChunkKey::new(&key), Padding::new(1023, 255, &mut random).expect("the default bounds")), rest);
		while let [items, tail @ ..] = left {
			let (mut datagrams, mut tail) = (Vec::new(), tail);
			for _ in 0..items % 5 {
				let [size, more @ ..] = tail else {break};
				let Some((datagram, more)) = more.split_at_checked(32 + usize::from(*size)) else {break};
				datagrams.push(datagram);
				tail = more;
			}
			left = tail;
			let mut chunk = Vec::new();
			sealer.seal(&datagrams, false, &mut random, &mut chunk).expect("a chunk of at most four datagrams seals");
			if flags & 4 != 0 {websocket::frame(PING, b"still there", None, &mut stream)}
			websocket::frame(BINARY, &chunk, None, &mut stream);
			sealed.push(datagrams.iter().map(|datagram| datagram.to_vec()).collect::<Vec<_>>());
		}
	}
	let changed = flags & 3 == 2 && !stream.is_empty();
	if changed {
		let at = usize::from(pick) * 131 % stream.len();
		stream[at] ^= 1 << (pick % 8);
	}
	// Everything the reader gives for the stream in pieces of one size: the datagrams of every chunk, the other frames, and how it ended.
	let read = |piece: usize| {
		let (mut reader, mut chunks, mut others, mut fault, mut closed) = (Reader::new(ChunkKey::new(&key), Vec::new()), Vec::new(), Vec::new(), None::<Fault>, false);
		for part in stream.chunks(piece) {
			reader.feed(part);
			while fault.is_none() && !closed {
				match reader.next() {
					Ok(Some(Read::Chunk(items))) => chunks.push(items.map(<[u8]>::to_vec).collect::<Vec<_>>()),
					Ok(Some(Read::Ping(payload))) => others.push(payload.to_vec()),
					Ok(Some(Read::Pong)) => others.push(Vec::new()),
					Ok(Some(Read::Close)) => closed = true,
					Ok(None) => break,
					Err(found) => fault = Some(found),
				}
			}
			if fault.is_some() || closed {break}
			assert!(reader.kept() < HEADER_MAX + MAX_SEALED, "{} bytes were kept while more were asked for", reader.kept());
		}
		if let Some(found) = fault {assert_eq!((reader.next().err(), reader.next().err()), (Some(found), Some(found)), "a reader that failed went on")}
		(chunks, others, fault, closed)
	};
	let (whole, pieces) = (read(stream.len().max(1)), read(usize::from(pick % 64) + 1));
	assert_eq!(whole, pieces, "the stream reads differently in pieces");
	if flags & 1 == 0 {
		let (chunks, _, fault, closed) = whole;
		assert!(chunks.len() <= sealed.len() && chunks == sealed[..chunks.len()], "a datagram came out that the node did not seal");
		if !changed {assert!(fault.is_none() && !closed && chunks.len() == sealed.len(), "what the node sealed did not all come out: {fault:?}")}
	}
});
