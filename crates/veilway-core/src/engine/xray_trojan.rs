//! The node's client for the Trojan inbound the add-on runs for each Xray outbound (`xray_out`), on a Unix socket in the folder it shares with Xray. Trojan is Xray's own way in here: a password, and a request that names the destination, with no reply. One connection is one TCP flow, or one UDP flow, whose datagrams are framed in the stream.
//! Before it sends a byte the node checks that the socket is held by Xray's user. The path is made new for each start and sits in a folder only the node and Xray can enter, and this check is what is left when something else has taken the name anyway.
use super::flows::udp_header;
use super::xray_out::Reach;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UnixStream;

/// A connection to the socket of `reach`, once it is known to be held by the user the hop names.
pub(super) async fn open(reach: &Reach) -> std::io::Result<UnixStream> {
	let stream = UnixStream::connect(&reach.path).await?;
	if stream.peer_cred()?.uid() != reach.uid {return Err(std::io::Error::other("the socket is not held by the user Xray runs as"))}
	Ok(stream)
}

/// The request that opens a stream: the password as the hex of its SHA-224, CRLF, the command (1 for CONNECT, 3 for UDP), the destination as a SOCKS5 address, CRLF.
pub(super) fn head(password: &str, command: u8, dst: SocketAddr) -> Vec<u8> {
	let mut request: Vec<u8> = Sha224::digest(password.as_bytes()).iter().flat_map(|byte| format!("{byte:02x}").into_bytes()).collect();
	request.extend_from_slice(&[13, 10, command]);
	request.extend_from_slice(&udp_header(dst)[3..]);
	request.extend_from_slice(&[13, 10]);
	request
}

/// One datagram in a UDP stream: the address it is for or from, its length, CRLF, and the datagram.
pub(super) fn packet(dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
	let mut framed = udp_header(dst)[3..].to_vec();
	framed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
	framed.extend_from_slice(&[13, 10]);
	framed.extend_from_slice(payload);
	framed
}

/// What was read of a UDP stream and is not a whole frame yet. `next` can be dropped half way, as a branch of `select!` is, and loses nothing: bytes that were read stay here until a frame is whole.
#[derive(Default)]
pub(super) struct Frames(Vec<u8>);

impl Frames {
	/// The datagram of the first whole frame in `held`, and how many bytes the frame took. None while it is not whole, an error for an address type the node does not speak or a frame without its CRLF.
	fn parse(held: &[u8]) -> std::io::Result<Option<(usize, std::ops::Range<usize>)>> {
		let Some(&kind) = held.first() else {return Ok(None)};
		let address = match kind {
			1 => 4,
			4 => 16,
			3 => match held.get(1) {
				Some(&length) => 1 + usize::from(length),
				None => return Ok(None),
			},
			_ => return Err(std::io::Error::other("an address type the node does not speak")),
		};
		let head = 1 + address + 2;
		let Some(frame) = held.get(head..head + 4) else {return Ok(None)};
		if frame[2..] != [13, 10] {return Err(std::io::Error::other("a frame without its CRLF"))}
		let end = head + 4 + usize::from(u16::from_be_bytes([frame[0], frame[1]]));
		Ok((held.len() >= end).then_some((end, head + 4..end)))
	}

	/// Reads until one datagram is whole and puts it in `payload`.
	pub(super) async fn next<R: AsyncRead + Unpin>(&mut self, from: &mut R, payload: &mut Vec<u8>) -> std::io::Result<()> {
		loop {
			if let Some((end, range)) = Self::parse(&self.0)? {
				payload.clear();
				payload.extend_from_slice(&self.0[range]);
				self.0.drain(..end);
				return Ok(());
			}
			if from.read_buf(&mut self.0).await? == 0 {return Err(std::io::ErrorKind::UnexpectedEof.into())}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::AsyncWriteExt;

	#[test]
	fn a_request_is_the_hash_of_the_password_a_command_and_an_address() {
		let request = head("password", 1, "192.0.2.1:443".parse().unwrap());
		assert_eq!(&request[..56], b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
		assert_eq!(&request[56..], &[13, 10, 1, 1, 192, 0, 2, 1, 1, 187, 13, 10]);
	}

	#[tokio::test]
	async fn a_datagram_goes_in_a_frame_and_comes_out_of_one_however_the_stream_is_cut() {
		for dst in ["192.0.2.1:53", "[2001:db8::1]:53"] {
			let framed = [packet(dst.parse().unwrap(), b"hello"), packet(dst.parse().unwrap(), b"again")].concat();
			let mut frames = Frames::default();
			let mut payload = Vec::new();
			for cut in [1, 3, 7, 12] {
				let (mut reader, mut writer) = tokio::io::duplex(64);
				writer.write_all(&framed[..cut]).await.unwrap();
				// A read that is dropped half way, as `select!` does, loses nothing.
				assert!(tokio::time::timeout(std::time::Duration::from_millis(20), frames.next(&mut reader, &mut payload)).await.is_err());
				writer.write_all(&framed[cut..]).await.unwrap();
				frames.next(&mut reader, &mut payload).await.unwrap();
				assert_eq!(payload, b"hello");
				frames.next(&mut reader, &mut payload).await.unwrap();
				assert_eq!(payload, b"again");
			}
		}
		let mut payload = Vec::new();
		assert!(Frames::default().next(&mut &[9u8, 0, 0][..], &mut payload).await.is_err());
		assert!(Frames::default().next(&mut &[1u8, 1, 1, 1, 1, 0, 53, 0, 5, 0, 0, 1, 2, 3, 4, 5][..], &mut payload).await.is_err());
	}
}
