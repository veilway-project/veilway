//! The WebSocket framing of `tls` and `ws` (transports page, "WebSocket session" and "Closing"; RFC 6455): the accept value of the upgrade answer, the header of a frame, and the one Close frame. Nothing here reads a request, and nothing does IO.
//!
//! "One binary WebSocket message is one sealed chunk", in one frame: "A message longer than 16,016 bytes, a text message or a fragmented message ends the session." A reader therefore needs the header of each frame and nothing else, and decides by it before it waits for a payload.
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use std::fmt;

/// The opcodes of RFC 6455, section 5.2.
pub const CONTINUATION: u8 = 0x0;
pub const TEXT: u8 = 0x1;
pub const BINARY: u8 = 0x2;
pub const CLOSE: u8 = 0x8;
pub const PING: u8 = 0x9;
pub const PONG: u8 = 0xa;
/// The payload of a control frame is at most 125 bytes (RFC 6455, section 5.5).
pub const CONTROL_MAX: usize = 125;
/// The largest frame header: 2 bytes, 8 of extended length and 4 of mask.
pub const HEADER_MAX: usize = 14;
/// "Either side ends a session with a WebSocket Close frame with status 1000 and no reason": the payload of that frame.
pub const NORMAL: [u8; 2] = 1000u16.to_be_bytes();
/// "Wait for the peer's close frame: 5 s."
pub const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
// The value every accept is hashed with (RFC 6455, section 1.3).
const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Accept` for a `Sec-WebSocket-Key`, "with the value RFC 6455 requires": the base64 of the SHA-1 of the key as it was sent and a fixed text. SHA-1 is what the RFC names. Nothing is protected by it.
pub fn accept(key: &[u8]) -> String {STANDARD.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &[key, GUID].concat()))}

/// Why bytes are no frame header a peer of this protocol sends. A receiver treats every one the same way: the session ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
	/// A reserved bit is set. No extension is ever accepted, so none has a meaning.
	Reserved,
	/// An opcode RFC 6455 does not define.
	Opcode,
	/// A control frame that is fragmented or longer than 125 bytes.
	Control,
	/// A length that is not written in its shortest form, or has its highest bit set.
	Length,
}

impl fmt::Display for FrameError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "websocket frame: {self:?}")}
}

impl std::error::Error for FrameError {}

/// The header of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
	/// The frame is the last of its message.
	pub fin: bool,
	pub opcode: u8,
	/// The key the payload is masked with. A client masks every frame and a server none.
	pub mask: Option<[u8; 4]>,
	/// The bytes of the header itself. The payload follows them.
	pub size: usize,
	/// The bytes of the payload, as the header says. Nothing here holds it against a limit: the caller does, before it waits for that many.
	pub payload: u64,
}

/// Reads the header of the frame `bytes` begins with. `Ok(None)` while the header is not all there.
pub fn header(bytes: &[u8]) -> Result<Option<Header>, FrameError> {
	let [first, second, rest @ ..] = bytes else {return Ok(None)};
	let (fin, opcode, masked, short) = (first & 0x80 != 0, first & 0x0f, second & 0x80 != 0, u64::from(second & 0x7f));
	if first & 0x70 != 0 {return Err(FrameError::Reserved)}
	if !matches!(opcode, CONTINUATION | TEXT | BINARY | CLOSE | PING | PONG) {return Err(FrameError::Opcode)}
	if opcode >= CLOSE && (!fin || short > CONTROL_MAX as u64) {return Err(FrameError::Control)}
	let (payload, extended) = match short {
		126 => {
			let Some(length) = rest.first_chunk::<2>() else {return Ok(None)};
			(u64::from(u16::from_be_bytes(*length)), 2)
		}
		127 => {
			let Some(length) = rest.first_chunk::<8>() else {return Ok(None)};
			(u64::from_be_bytes(*length), 8)
		}
		short => (short, 0),
	};
	// "The minimal number of bytes MUST be used to encode the length", and the most significant bit of a 64 bit length is zero.
	if (extended == 2 && payload < 126) || (extended == 8 && (payload <= u64::from(u16::MAX) || payload >> 63 != 0)) {return Err(FrameError::Length)}
	let mask = if masked {
		let Some(mask) = rest.get(extended..).and_then(|rest| rest.first_chunk::<4>()) else {return Ok(None)};
		Some(*mask)
	} else {None};
	Ok(Some(Header {fin, opcode, mask, size: 2 + extended + if masked {4} else {0}, payload}))
}

/// Removes, or puts on, the mask of a payload, in place.
pub fn mask(key: [u8; 4], payload: &mut [u8]) {
	for (at, byte) in payload.iter_mut().enumerate() {*byte ^= key[at & 3]}
}

/// Appends one final frame to `out`: its header, and the payload, masked when a key is given, which is what a client does with a fresh key for every frame.
pub fn frame(opcode: u8, payload: &[u8], key: Option<[u8; 4]>, out: &mut Vec<u8>) {
	let masked = if key.is_some() {0x80} else {0};
	out.push(0x80 | opcode);
	match payload.len() {
		short @ 0..=125 => out.push(masked | short as u8),
		medium @ 126..=65535 => {
			out.push(masked | 126);
			out.extend_from_slice(&(medium as u16).to_be_bytes());
		}
		long => {
			out.push(masked | 127);
			out.extend_from_slice(&(long as u64).to_be_bytes());
		}
	}
	out.extend_from_slice(key.as_ref().map_or(&[][..], |key| &key[..]));
	let start = out.len();
	out.extend_from_slice(payload);
	if let Some(key) = key {mask(key, &mut out[start..])}
}

#[cfg(test)]
mod tests {
	use super::*;

	// The example of RFC 6455, section 1.3.
	#[test]
	fn the_accept_value_of_the_rfc() {
		assert_eq!(accept(b"dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
	}

	// The examples of RFC 6455, section 5.7.
	#[test]
	fn the_frames_of_the_rfc() {
		let mut out = Vec::new();
		frame(TEXT, b"Hello", None, &mut out);
		assert_eq!(out, [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
		out.clear();
		frame(TEXT, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d]), &mut out);
		assert_eq!(out, [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
		assert_eq!(header(&out), Ok(Some(Header {fin: true, opcode: TEXT, mask: Some([0x37, 0xfa, 0x21, 0x3d]), size: 6, payload: 5})));
		let mut payload = out[6..].to_vec();
		mask([0x37, 0xfa, 0x21, 0x3d], &mut payload);
		assert_eq!(payload, b"Hello");
		out.clear();
		frame(PING, b"Hello", None, &mut out);
		assert_eq!(out[..2], [0x89, 0x05]);
	}

	#[test]
	fn a_header_is_read_when_it_is_whole_and_says_its_length_in_one_way() {
		for (size, extended) in [(0, 0), (125, 0), (126, 2), (16_016, 2), (65_535, 2), (65_536, 8)] {
			let (mut server, mut client) = (Vec::new(), Vec::new());
			frame(BINARY, &vec![7; size], None, &mut server);
			frame(BINARY, &vec![7; size], Some([1, 2, 3, 4]), &mut client);
			assert_eq!(header(&server), Ok(Some(Header {fin: true, opcode: BINARY, mask: None, size: 2 + extended, payload: size as u64})));
			assert_eq!(header(&client), Ok(Some(Header {fin: true, opcode: BINARY, mask: Some([1, 2, 3, 4]), size: 6 + extended, payload: size as u64})));
			// Every shorter piece of the header is not one yet, and nothing of the payload is needed to read it.
			for cut in 0..6 + extended {assert_eq!(header(&client[..cut]), Ok(None), "{cut} bytes of a header of {}", 6 + extended)}
			assert!(header(&client[..6 + extended]).unwrap().is_some());
		}
		// A length in more bytes than it needs, and one with its highest bit set.
		assert_eq!(header(&[0x82, 126, 0, 125]), Err(FrameError::Length));
		assert_eq!(header(&[0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff]), Err(FrameError::Length));
		assert_eq!(header(&[0x82, 127, 0x80, 0, 0, 0, 0, 1, 0, 0]), Err(FrameError::Length));
		assert_eq!(header(&[0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]).unwrap().unwrap().payload, 65_536);
	}

	#[test]
	fn what_no_peer_of_this_protocol_sends_is_refused_at_the_header() {
		// A reserved bit, an opcode nobody defined, a control frame in pieces and one that is too long.
		for first in [0xc2, 0xa2, 0x92] {assert_eq!(header(&[first, 0]), Err(FrameError::Reserved))}
		for opcode in [3, 4, 5, 6, 7, 0xb, 0xc, 0xd, 0xe, 0xf] {assert_eq!(header(&[0x80 | opcode, 0]), Err(FrameError::Opcode))}
		assert_eq!(header(&[0x09, 0]), Err(FrameError::Control));
		assert_eq!(header(&[0x88, 126, 0, 126]), Err(FrameError::Control));
		assert_eq!(header(&[0x8a, 127]), Err(FrameError::Control));
		// A fragment of a data message is a frame, and its reader ends the session for it.
		assert_eq!(header(&[0x02, 0]), Ok(Some(Header {fin: false, opcode: BINARY, mask: None, size: 2, payload: 0})));
		assert_eq!(header(&[0x80, 0]).unwrap().unwrap().opcode, CONTINUATION);
		assert_eq!((header(&[]), header(&[0x82])), (Ok(None), Ok(None)));
	}
}
