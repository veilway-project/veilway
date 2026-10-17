//! HTTP/2 (RFC 9113) as the stream transports speak it (http2 page): frame headers, the frames both sides write, the settings, and HPACK (RFC 7541) with the limits of the page. No IO and no clock.
//! The frames are written here and not taken from a library because the client must send Chrome's SETTINGS and pseudo-headers in Chrome's order, and the node must count every frame that carries nothing, every stream that ends early and every byte of a header block, which a library hides.
//! `gateway` is the translation of a stranger's request to HTTP/1.1 and of the origin's answer back.
use fluke_hpack::{Decoder as Hpack, Encoder as Packer};

pub mod gateway;

pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const PRIORITY: u8 = 0x2;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PUSH_PROMISE: u8 = 0x5;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;
pub const WINDOW_UPDATE: u8 = 0x8;
pub const CONTINUATION: u8 = 0x9;
pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;
pub const PADDED: u8 = 0x8;
pub const PRIORITY_FLAG: u8 = 0x20;
pub const NO_ERROR: u32 = 0x0;
pub const PROTOCOL_ERROR: u32 = 0x1;
pub const INTERNAL_ERROR: u32 = 0x2;
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
pub const SETTINGS_TIMEOUT: u32 = 0x4;
pub const STREAM_CLOSED: u32 = 0x5;
pub const FRAME_SIZE_ERROR: u32 = 0x6;
pub const REFUSED_STREAM: u32 = 0x7;
pub const CANCEL: u32 = 0x8;
pub const COMPRESSION_ERROR: u32 = 0x9;
pub const ENHANCE_YOUR_CALM: u32 = 0xb;
pub const HEADER_TABLE_SIZE: u16 = 0x1;
pub const ENABLE_PUSH: u16 = 0x2;
pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const MAX_FRAME_SIZE: u16 = 0x5;
pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
pub const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
/// The size of every frame header, and the largest payload a peer may send before it has announced a larger `MAX_FRAME_SIZE`. Neither side of this crate announces one.
pub const HEADER: usize = 9;
pub const FRAME_MAX: usize = 16_384;
/// The window of RFC 9113 (section 6.9.2) before anyone has said otherwise, and the largest a window can be.
pub const WINDOW_DEFAULT: u32 = 65_535;
pub const WINDOW_MAX: u32 = 0x7fff_ffff;

/// The nine bytes in front of every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {pub len: usize, pub kind: u8, pub flags: u8, pub stream: u32}

impl Header {
	pub fn parse(bytes: &[u8; HEADER]) -> Header {Header {len: u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize, kind: bytes[3], flags: bytes[4], stream: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) & WINDOW_MAX}}
}

/// One frame, appended to `out`. The reserved bit of the stream id is always 0.
pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8], out: &mut Vec<u8>) {
	out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
	out.extend_from_slice(&[kind, flags]);
	out.extend_from_slice(&(stream & WINDOW_MAX).to_be_bytes());
	out.extend_from_slice(payload);
}

/// A SETTINGS frame with these entries in this order: the order is what Chrome's is recognised by.
pub fn settings(entries: &[(u16, u32)], out: &mut Vec<u8>) {frame(SETTINGS, 0, 0, &entries.iter().flat_map(|(id, value)| [id.to_be_bytes().to_vec(), value.to_be_bytes().to_vec()].concat()).collect::<Vec<_>>(), out)}

pub fn window_update(stream: u32, increment: u32, out: &mut Vec<u8>) {frame(WINDOW_UPDATE, 0, stream, &increment.to_be_bytes(), out)}

pub fn rst_stream(stream: u32, code: u32, out: &mut Vec<u8>) {frame(RST_STREAM, 0, stream, &code.to_be_bytes(), out)}

pub fn goaway(last: u32, code: u32, out: &mut Vec<u8>) {frame(GOAWAY, 0, 0, &[(last & WINDOW_MAX).to_be_bytes(), code.to_be_bytes()].concat(), out)}

/// The entries of a SETTINGS payload. `None` when its length is no multiple of 6.
pub fn read_settings(payload: &[u8]) -> Option<impl Iterator<Item = (u16, u32)> + '_> {
	if payload.len() % 6 != 0 {return None}
	Some(payload.chunks_exact(6).map(|entry| (u16::from_be_bytes([entry[0], entry[1]]), u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]))))
}

/// The bytes a frame carries once its padding is taken off (RFC 9113, section 6.1), and for HEADERS its priority fields as well (section 6.2). `None` when the padding is longer than the frame.
pub fn unpad(flags: u8, payload: &[u8], priority: bool) -> Option<&[u8]> {
	let (pad, rest) = if flags & PADDED != 0 {payload.split_first().map(|(pad, rest)| (*pad as usize, rest))?} else {(0, payload)};
	let rest = if priority && flags & PRIORITY_FLAG != 0 {rest.get(5..)?} else {rest};
	rest.len().checked_sub(pad).map(|keep| &rest[..keep])
}

/// A header list: names and values as they were on the wire.
pub type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// What the size of a field counts as in `SETTINGS_MAX_HEADER_LIST_SIZE` (RFC 9113, section 6.5.2).
pub fn field_size(name: &[u8], value: &[u8]) -> usize {name.len() + value.len() + 32}

/// The decoding half of HPACK for one connection. Its dynamic table never grows past what the owner announced.
pub struct Decoder(Hpack<'static>);

/// A header block that does not decode ends the connection, because the table is shared by every stream (RFC 9113, section 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compression;

impl Decoder {
	pub fn new(table: usize) -> Decoder {
		let mut hpack = Hpack::new();
		hpack.set_max_table_size(table);
		hpack.set_max_allowed_table_size(table);
		Decoder(hpack)
	}
	/// Decodes a whole block. A list over `cap` (each field as `field_size` counts it) is decoded to its end all the same, so that the table stays in step with the peer's, and then gives `Ok(None)`: nothing of it is kept.
	pub fn decode(&mut self, block: &[u8], cap: usize) -> Result<Option<Fields>, Compression> {
		let (mut fields, mut size) = (Fields::new(), 0usize);
		self.0.decode_with_cb(block, |name, value| {
			size = size.saturating_add(field_size(&name, &value));
			if size <= cap {fields.push((name.into_owned(), value.into_owned()))}
		}).map_err(|_| Compression)?;
		Ok(if size <= cap {Some(fields)} else {None})
	}
}

/// The encoding half of HPACK for one connection. A change of the table size the peer allows is written at the start of the next block, as RFC 7541 (section 4.2) asks.
pub struct Encoder {inner: Packer<'static>, resize: Option<usize>}

impl Encoder {
	pub fn new() -> Encoder {Encoder {inner: Packer::new(), resize: None}}
	/// The peer allows a dynamic table of at most `size` bytes. Never more than the default of 4,096 is used.
	pub fn resize(&mut self, size: usize) {
		self.inner.set_max_table_size(size.min(4_096));
		self.resize = Some(size.min(4_096));
	}
	/// A block for this list, in this order.
	pub fn encode(&mut self, fields: &[(&[u8], &[u8])]) -> Vec<u8> {
		let mut block = Vec::new();
		if let Some(size) = self.resize.take() {let _ = fluke_hpack::encoder::encode_integer_into(size, 5, 0x20, &mut block);}
		block.extend(self.inner.encode(fields.iter().copied()));
		block
	}
}

impl Default for Encoder {
	fn default() -> Self {Self::new()}
}

/// HEADERS, then CONTINUATION frames as the block needs them, none larger than `FRAME_MAX`.
pub fn headers(stream: u32, block: &[u8], end_stream: bool, out: &mut Vec<u8>) {
	let mut parts = block.chunks(FRAME_MAX).peekable();
	let mut first = true;
	if parts.peek().is_none() {return frame(HEADERS, END_HEADERS | if end_stream {END_STREAM} else {0}, stream, &[], out)}
	while let Some(part) = parts.next() {
		let last = parts.peek().is_none();
		if first {frame(HEADERS, if last {END_HEADERS} else {0} | if end_stream {END_STREAM} else {0}, stream, part, out)} else {frame(CONTINUATION, if last {END_HEADERS} else {0}, stream, part, out)}
		first = false;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_frame_header_round_trips_and_drops_the_reserved_bit() {
		let mut out = Vec::new();
		frame(DATA, END_STREAM, 0x8000_0003, b"abc", &mut out);
		assert_eq!(out[..HEADER], [0, 0, 3, 0, 1, 0, 0, 0, 3]);
		assert_eq!(Header::parse(out[..HEADER].try_into().unwrap()), Header {len: 3, kind: DATA, flags: END_STREAM, stream: 3});
		assert_eq!(Header::parse(&[0xff, 0xff, 0xff, 1, 0, 0xff, 0xff, 0xff, 0xff]), Header {len: 0xff_ffff, kind: 1, flags: 0, stream: WINDOW_MAX});
	}

	#[test]
	fn settings_keep_their_order_and_a_odd_length_is_refused() {
		let mut out = Vec::new();
		settings(&[(HEADER_TABLE_SIZE, 65_536), (ENABLE_PUSH, 0), (INITIAL_WINDOW_SIZE, 6_291_456)], &mut out);
		assert_eq!(read_settings(&out[HEADER..]).unwrap().collect::<Vec<_>>(), [(1, 65_536), (2, 0), (4, 6_291_456)]);
		assert!(read_settings(&out[HEADER..HEADER + 7]).is_none());
	}

	#[test]
	fn padding_and_priority_are_taken_off() {
		assert_eq!(unpad(0, b"abc", false), Some(&b"abc"[..]));
		assert_eq!(unpad(PADDED, &[2, b'a', b'b', b'c', 0, 0], false), Some(&b"abc"[..]));
		assert_eq!(unpad(PADDED, &[9, b'a'], false), None);
		assert_eq!(unpad(PADDED, &[], false), None);
		assert_eq!(unpad(PRIORITY_FLAG, &[0, 0, 0, 1, 5, b'x'], true), Some(&b"x"[..]));
		assert_eq!(unpad(PRIORITY_FLAG, &[0, 0, 0], true), None);
	}

	#[test]
	fn hpack_round_trips_and_a_list_over_the_cap_is_decoded_and_dropped() {
		let (mut encoder, mut decoder) = (Encoder::new(), Decoder::new(4_096));
		let block = encoder.encode(&[(b":method", b"GET"), (b":path", b"/a"), (b"x-long", &[b'v'; 300])]);
		assert_eq!(decoder.decode(&block, 65_536).unwrap().unwrap().len(), 3);
		let block = encoder.encode(&[(b":method", b"GET"), (b"x-long", &[b'v'; 300])]);
		assert_eq!(decoder.decode(&block, 100), Ok(None));
		let block = encoder.encode(&[(b":method", b"POST")]);
		assert_eq!(decoder.decode(&block, 100).unwrap().unwrap(), vec![(b":method".to_vec(), b"POST".to_vec())]);
		assert_eq!(decoder.decode(&[0xff, 0xff, 0xff], 100), Err(Compression));
	}

	#[test]
	fn a_block_larger_than_a_frame_goes_in_continuations() {
		let mut out = Vec::new();
		headers(1, &vec![0x82; FRAME_MAX * 2 + 5], true, &mut out);
		let mut at = 0;
		let mut seen = Vec::new();
		while at < out.len() {
			let header = Header::parse(out[at..at + HEADER].try_into().unwrap());
			seen.push((header.kind, header.flags));
			at += HEADER + header.len;
		}
		assert_eq!(seen, [(HEADERS, END_STREAM), (CONTINUATION, 0), (CONTINUATION, END_HEADERS)]);
	}
}
