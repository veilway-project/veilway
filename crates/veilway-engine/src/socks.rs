//! The SOCKS5 client the Xray carrier speaks to Xray's loopback inbound (RFC 1928, with the username and password of RFC 1929). The login is new for each run and only the helper and Xray know it. Every flow of the device opens its own connection: `CONNECT` for TCP, and for UDP an `UDP ASSOCIATE` whose relay is used for that flow alone. The carrier never sends a name, only the address the stack saw.
//!
//! What Xray answers is read as hostile: the reply is a fixed shape, an address that is not a literal is refused, and a relay that is not on the loopback address of the hop is refused, so that no reply sends a datagram anywhere else.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// The whole exchange with Xray, from the connection to the reply.
pub const HANDSHAKE: Duration = Duration::from_secs(10);
const USER: &[u8] = b"veilway";
const CONNECT: u8 = 1;
const ASSOCIATE: u8 = 3;

/// Why a request to Xray did not give a flow.
#[derive(Debug)]
pub enum Fail {
	/// Xray answered "network unreachable" or "host unreachable".
	Unreachable,
	/// Xray refused, or answered with a reply that is not a success.
	Refused,
	/// The connection to Xray failed, was cut, or took too long, or its answer was not SOCKS5.
	Io(io::Error),
}

impl From<io::Error> for Fail {
	fn from(error: io::Error) -> Self {Self::Io(error)}
}

fn bad(what: &str) -> Fail {Fail::Io(io::Error::new(io::ErrorKind::InvalidData, what.to_owned()))}

/// The greeting and the login. Only the username and password method is offered, so Xray cannot answer with another.
pub async fn login(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), password: &str) -> Result<(), Fail> {
	if password.len() > 255 {return Err(bad("the login is longer than SOCKS5 allows"))}
	stream.write_all(&[5, 1, 2]).await?;
	let mut chosen = [0u8; 2];
	stream.read_exact(&mut chosen).await?;
	if chosen != [5, 2] {return Err(bad("Xray did not take the login method"))}
	let mut message = vec![1, USER.len() as u8];
	message.extend_from_slice(USER);
	message.push(password.len() as u8);
	message.extend_from_slice(password.as_bytes());
	stream.write_all(&message).await?;
	let mut answer = [0u8; 2];
	stream.read_exact(&mut answer).await?;
	if answer != [1, 0] {return Err(Fail::Refused)}
	Ok(())
}

// The address and port of a request or a datagram: type, address, port.
fn address(target: SocketAddr) -> Vec<u8> {
	let mut out = match target.ip() {
		IpAddr::V4(ip) => [&[1][..], &ip.octets()].concat(),
		IpAddr::V6(ip) => [&[4][..], &ip.octets()].concat(),
	};
	out.extend_from_slice(&target.port().to_be_bytes());
	out
}

/// The reply to a request: its code, and the address it names. Only an address literal is read.
async fn reply(stream: &mut (impl AsyncRead + Unpin)) -> Result<SocketAddr, Fail> {
	let mut head = [0u8; 4];
	stream.read_exact(&mut head).await?;
	if head[0] != 5 {return Err(bad("the reply is not SOCKS5"))}
	match head[1] {
		0 => {}
		3 | 4 => return Err(Fail::Unreachable),
		_ => return Err(Fail::Refused),
	}
	let ip = match head[3] {
		1 => {
			let mut octets = [0u8; 4];
			stream.read_exact(&mut octets).await?;
			IpAddr::from(octets)
		}
		4 => {
			let mut octets = [0u8; 16];
			stream.read_exact(&mut octets).await?;
			IpAddr::from(octets)
		}
		_ => return Err(bad("the reply names an address that is not a literal")),
	};
	let mut port = [0u8; 2];
	stream.read_exact(&mut port).await?;
	Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

async fn open(socks: SocketAddr, password: &str, command: u8, target: SocketAddr) -> Result<(TcpStream, SocketAddr), Fail> {
	let mut stream = TcpStream::connect(socks).await?;
	stream.set_nodelay(true)?;
	login(&mut stream, password).await?;
	let mut request = vec![5, command, 0];
	request.extend_from_slice(&address(target));
	stream.write_all(&request).await?;
	let bound = reply(&mut stream).await?;
	Ok((stream, bound))
}

/// A TCP connection to `target` through Xray, ready for the flow's bytes.
pub async fn connect(socks: SocketAddr, password: &str, target: SocketAddr) -> Result<TcpStream, Fail> {
	match tokio::time::timeout(HANDSHAKE, open(socks, password, CONNECT, target)).await {
		Ok(opened) => opened.map(|(stream, _)| stream),
		Err(_) => Err(Fail::Io(io::ErrorKind::TimedOut.into())),
	}
}

/// A UDP association: the connection that keeps it alive, and a socket connected to the relay Xray named. The association ends when `control` closes.
pub struct Association {
	pub control: TcpStream,
	pub relay: UdpSocket,
}

/// Asks Xray for a relay for one flow. `accept` is asked about the relay's address before a datagram is sent to it. The relay has to be on the same loopback address as the hop, whatever the reply says, and an unspecified address in the reply means the hop's own.
pub async fn associate(socks: SocketAddr, password: &str, accept: &(dyn Fn(SocketAddr) -> bool + Send + Sync)) -> Result<Association, Fail> {
	let wanted = if socks.is_ipv4() {SocketAddr::from(([0, 0, 0, 0], 0))} else {SocketAddr::from(([0u16; 8], 0))};
	let (control, named) = match tokio::time::timeout(HANDSHAKE, open(socks, password, ASSOCIATE, wanted)).await {
		Ok(opened) => opened?,
		Err(_) => return Err(Fail::Io(io::ErrorKind::TimedOut.into())),
	};
	let relay = SocketAddr::new(if named.ip().is_unspecified() {socks.ip()} else {named.ip()}, named.port());
	if relay.ip() != socks.ip() || relay.port() == 0 {return Err(bad("the relay is not on the hop's address"))}
	// Whose socket the relay is, is the platform's to say: the port is one the hop names, and another local user could hold it.
	if !accept(relay) {return Err(Fail::Refused)}
	let socket = UdpSocket::bind(SocketAddr::new(socks.ip(), 0)).await?;
	socket.connect(relay).await?;
	Ok(Association {control, relay: socket})
}

/// A datagram for the relay: no fragment, the address it is for, then the data.
pub fn wrap(target: SocketAddr, data: &[u8]) -> Vec<u8> {
	let mut out = vec![0, 0, 0];
	out.extend_from_slice(&address(target));
	out.extend_from_slice(data);
	out
}

/// The address and the data of a datagram from the relay. A fragment, a name and anything cut short is nothing.
pub fn unwrap(datagram: &[u8]) -> Option<(SocketAddr, &[u8])> {
	if datagram.len() < 4 || datagram[..3] != [0, 0, 0] {return None}
	let (ip, rest) = match datagram[3] {
		1 if datagram.len() >= 10 => (IpAddr::from(<[u8; 4]>::try_from(&datagram[4..8]).ok()?), &datagram[8..]),
		4 if datagram.len() >= 22 => (IpAddr::from(<[u8; 16]>::try_from(&datagram[4..20]).ok()?), &datagram[20..]),
		_ => return None,
	};
	Some((SocketAddr::new(ip, u16::from_be_bytes([rest[0], rest[1]])), &rest[2..]))
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::duplex;

	#[test]
	fn a_datagram_round_trips_and_a_bad_one_is_nothing() {
		let (v4, v6): (SocketAddr, SocketAddr) = ("1.1.1.1:53".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap());
		for target in [v4, v6] {
			let wrapped = wrap(target, b"data");
			assert_eq!(unwrap(&wrapped), Some((target, &b"data"[..])));
			assert_eq!(unwrap(&wrapped[..wrapped.len() - 4]), Some((target, &b""[..])));
		}
		let mut fragment = wrap(v4, b"x");
		fragment[2] = 1;
		let mut name = wrap(v4, b"x");
		name[3] = 3;
		let mut reserved = wrap(v4, b"x");
		reserved[0] = 1;
		for bad in [fragment, name, reserved, vec![], vec![0, 0, 0], vec![0, 0, 0, 1, 1, 1, 1, 1, 0], wrap(v6, b"")[..21].to_vec()] {assert_eq!(unwrap(&bad), None, "{bad:?}")}
	}

	#[tokio::test]
	async fn replies_are_read_by_their_code_and_only_literals_are_taken() {
		let read = |bytes: Vec<u8>| async move {reply(&mut &bytes[..]).await};
		assert_eq!(read(vec![5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]).await.unwrap(), "127.0.0.1:8080".parse().unwrap());
		assert_eq!(read([&[5, 0, 0, 4][..], &[0; 15], &[1, 0, 80]].concat()).await.unwrap(), "[::1]:80".parse().unwrap());
		assert!(matches!(read(vec![5, 4, 0, 1]).await, Err(Fail::Unreachable)));
		assert!(matches!(read(vec![5, 3, 0, 1]).await, Err(Fail::Unreachable)));
		assert!(matches!(read(vec![5, 5, 0, 1]).await, Err(Fail::Refused)));
		assert!(matches!(read(vec![5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 80]).await, Err(Fail::Io(_))));
		assert!(matches!(read(vec![4, 0, 0, 1, 1, 1, 1, 1, 0, 1]).await, Err(Fail::Io(_))));
		assert!(matches!(read(vec![5, 0, 0, 1, 1]).await, Err(Fail::Io(_))));
	}

	#[tokio::test]
	async fn the_login_offers_one_method_and_a_wrong_answer_is_refused() {
		let (mut client, mut hop) = duplex(256);
		let server = tokio::spawn(async move {
			let mut greeting = [0u8; 3];
			hop.read_exact(&mut greeting).await.unwrap();
			assert_eq!(greeting, [5, 1, 2]);
			hop.write_all(&[5, 2]).await.unwrap();
			let mut head = [0u8; 2];
			hop.read_exact(&mut head).await.unwrap();
			let mut rest = vec![0u8; usize::from(head[1]) + 1];
			hop.read_exact(&mut rest).await.unwrap();
			let mut password = vec![0u8; usize::from(*rest.last().unwrap())];
			hop.read_exact(&mut password).await.unwrap();
			assert_eq!((head[0], &rest[..rest.len() - 1], &password[..]), (1, &b"veilway"[..], &b"secret"[..]));
			hop.write_all(&[1, 1]).await.unwrap();
		});
		assert!(matches!(login(&mut client, "secret").await, Err(Fail::Refused)));
		server.await.unwrap();
		let (mut client, mut hop) = duplex(256);
		hop.write_all(&[5, 0xff]).await.unwrap();
		assert!(matches!(login(&mut client, "secret").await, Err(Fail::Io(_))));
		assert!(matches!(login(&mut client, &"x".repeat(256)).await, Err(Fail::Io(_))));
	}
}
