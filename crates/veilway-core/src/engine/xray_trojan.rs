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

/// Reads one framed datagram into `payload`, whatever address it names. An address type the node does not speak, or a frame without its CRLF, ends the stream with an error.
pub(super) async fn read_packet<R: AsyncRead + Unpin>(from: &mut R, payload: &mut Vec<u8>) -> std::io::Result<()> {
	let mut kind = [0u8; 1];
	from.read_exact(&mut kind).await?;
	let mut skip = [0u8; 258];
	let address = match kind[0] {
		1 => 4,
		4 => 16,
		3 => {
			from.read_exact(&mut kind).await?;
			usize::from(kind[0])
		}
		_ => return Err(std::io::Error::other("an address type the node does not speak")),
	};
	from.read_exact(&mut skip[..address + 2]).await?;
	let mut length = [0u8; 4];
	from.read_exact(&mut length).await?;
	if length[2..] != [13, 10] {return Err(std::io::Error::other("a frame without its CRLF"))}
	payload.resize(usize::from(u16::from_be_bytes([length[0], length[1]])), 0);
	from.read_exact(payload).await?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_request_is_the_hash_of_the_password_a_command_and_an_address() {
		let request = head("password", 1, "192.0.2.1:443".parse().unwrap());
		assert_eq!(&request[..56], b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01");
		assert_eq!(&request[56..], &[13, 10, 1, 1, 192, 0, 2, 1, 1, 187, 13, 10]);
	}

	#[tokio::test]
	async fn a_datagram_goes_in_a_frame_and_comes_out_of_one() {
		for dst in ["192.0.2.1:53", "[2001:db8::1]:53"] {
			let framed = packet(dst.parse().unwrap(), b"hello");
			let mut payload = Vec::new();
			read_packet(&mut &framed[..], &mut payload).await.unwrap();
			assert_eq!(payload, b"hello");
		}
		let mut payload = Vec::new();
		assert!(read_packet(&mut &[9u8, 0, 0][..], &mut payload).await.is_err());
		assert!(read_packet(&mut &[1u8, 1, 1, 1, 1, 0, 53, 0, 5, 0, 0, 1, 2, 3, 4, 5][..], &mut payload).await.is_err());
	}
}
