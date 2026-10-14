//! The WireGuard end of a tunnel (transports page, "WireGuard on an obfuscated transport"): one `Tunn` for the one node, and what a transport session asks of it.
//!
//! WireGuard is unchanged. What this adds is the rules around it that the page gives the client:
//! - The first datagram of a session is a keepalive of a tunnel that is already up, or else a fresh handshake initiation, and "while two candidates are raced the caller gives both the same one", so that the node accepts it once.
//! - The client sets no persistent keepalive. The idle keepalive is the transport's, and it asks for one datagram when it has sent nothing for its time.
//! - "The client starts a new WireGuard handshake when it sends a packet on a tunnel whose last handshake is older than the client rekey point" (60 to 110 s, drawn again after each handshake it starts), an idle keepalive included. The node never initiates on these transports.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use veilway_proto::session::{self, REKEY};
use veilway_proto::subscription::Secret;
use veilway_transport::{Source, Want};

/// The largest datagram WireGuard is asked to write: an IP packet at its largest and the 32 bytes of the message around it.
pub const BUFFER: usize = 65_535 + 64;

pub struct Wire {
	private: Secret<32>,
	node: [u8; 32],
	preshared: Option<Secret<32>>,
	tunn: Tunn,
	// Set for the length of a race: None while no session has asked yet, then the datagram both candidates open with.
	frozen: Option<Option<Vec<u8>>>,
	rekey: Duration,
}

fn written(result: TunnResult<'_>) -> Option<Vec<u8>> {if let TunnResult::WriteToNetwork(datagram) = result {Some(datagram.to_vec())} else {None}}

fn tunn(private: &Secret<32>, node: &[u8; 32], preshared: &Option<Secret<32>>) -> Tunn {
	let mut index = [0u8; 4];
	let _ = crate::random(&mut index);
	Tunn::new(StaticSecret::from(*private.expose()), PublicKey::from(*node), preshared.as_ref().map(|key| *key.expose()), None, u32::from_le_bytes(index) & 0x00ff_ffff, None)
}

// A source that fails gives the middle of the range, which only makes the draw less random.
fn rekey() -> Duration {session::delay(&REKEY, &mut crate::random).unwrap_or(Duration::from_secs(85))}

impl Wire {
	pub fn new(private: Secret<32>, node: [u8; 32], preshared: Option<Secret<32>>) -> Self {Self {tunn: tunn(&private, &node, &preshared), private, node, preshared, frozen: None, rekey: rekey()}}
	/// A tunnel that knows nothing of the node: the one to open with after the node has said it no longer knows this one, and after WireGuard has given the tunnel up.
	pub fn fresh(&mut self) {(self.tunn, self.frozen, self.rekey) = (tunn(&self.private, &self.node, &self.preshared), None, rekey())}
	/// Whether the tunnel has a handshake behind it, which is when it can send a keepalive and when the control channel may open.
	pub fn up(&self) -> bool {self.tunn.time_since_last_handshake().is_some()}
	/// The last handshake is older than the rekey point.
	pub fn due(&self) -> bool {self.tunn.time_since_last_handshake().is_some_and(|age| age > self.rekey)}
	/// A new handshake initiation, when the tunnel is not in the middle of one. The next rekey point is drawn.
	pub fn initiation(&mut self) -> Option<Vec<u8>> {
		self.rekey = rekey();
		written(self.tunn.format_handshake_initiation(&mut [0u8; 256], false))
	}
	/// What a session asks for. See the head of this module.
	pub fn want(&mut self, want: Want) -> Option<Vec<u8>> {
		if let (Want::First, Some(Some(frozen))) = (want, &self.frozen) {return Some(frozen.clone())}
		let datagram = if !self.up() {
			if want == Want::Keepalive {return None}
			written(self.tunn.format_handshake_initiation(&mut [0u8; 256], true))
		} else if self.due() {
			self.initiation()
		} else {
			written(self.tunn.encapsulate(&[], &mut [0u8; 256]))
		};
		if want == Want::First {
			if let Some(frozen) = &mut self.frozen {*frozen = datagram.clone()}
		}
		datagram
	}
	/// A race begins: every `Want::First` is the same datagram until `settle`.
	pub fn race(&mut self) {self.frozen = Some(None)}
	pub fn settle(&mut self) {self.frozen = None}
	pub fn tunn(&mut self) -> &mut Tunn {&mut self.tunn}
}

/// The handle a session and the engine share.
#[derive(Clone)]
pub struct Shared(Arc<Mutex<Wire>>);

impl Shared {
	pub fn new(wire: Wire) -> Self {Self(Arc::new(Mutex::new(wire)))}
	pub fn lock(&self) -> MutexGuard<'_, Wire> {self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())}
	/// The caller a session is opened with.
	pub fn source(&self) -> Source {
		let wire = self.clone();
		Arc::new(Mutex::new(move |want: Want| wire.lock().want(want)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pair() -> (Wire, Wire) {
		let (a, b) = ([0x21u8; 32], [0x10u8; 32]);
		(Wire::new(Secret::new(a), veilway_wg_public(&b), None), Wire::new(Secret::new(b), veilway_wg_public(&a), None))
	}

	fn veilway_wg_public(private: &[u8; 32]) -> [u8; 32] {PublicKey::from(&StaticSecret::from(*private)).to_bytes()}

	// Hands a datagram from one end to the other and gives what the other end wrote back and the packets it released.
	fn deliver(to: &mut Wire, datagram: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
		let (mut replies, mut packets, mut input) = (Vec::new(), Vec::new(), datagram);
		loop {
			let mut out = vec![0u8; BUFFER];
			match to.tunn().decapsulate(None, input, &mut out) {
				TunnResult::WriteToNetwork(reply) => replies.push(reply.to_vec()),
				TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
					packets.push(packet.to_vec());
					break;
				}
				_ => break,
			}
			input = &[];
		}
		(replies, packets)
	}

	#[test]
	fn a_tunnel_opens_with_an_initiation_and_then_with_a_keepalive() {
		let (mut device, mut node) = pair();
		assert!(!device.up() && device.want(Want::Keepalive).is_none());
		let first = device.want(Want::First).unwrap();
		assert_eq!(first[0], 1);
		let (replies, _) = deliver(&mut node, &first);
		assert_eq!(replies[0][0], 2);
		deliver(&mut device, &replies[0]);
		assert!(device.up());
		// With a handshake behind it the tunnel opens a session with a keepalive: a data message with nothing inside, 32 bytes.
		let keepalive = device.want(Want::First).unwrap();
		assert_eq!((keepalive[0], keepalive.len()), (4, 32));
		assert_eq!(device.want(Want::Keepalive).unwrap().len(), 32);
	}

	#[test]
	fn while_two_candidates_race_both_get_the_same_datagram_and_after_it_a_new_one() {
		let (mut device, _) = pair();
		device.race();
		let (one, two) = (device.want(Want::First).unwrap(), device.want(Want::First).unwrap());
		assert_eq!(one, two);
		device.settle();
		assert_ne!(device.want(Want::First).unwrap(), one);
		// A keepalive asked for in the race is not the frozen datagram.
		device.race();
		let first = device.want(Want::First).unwrap();
		assert!(device.want(Want::Keepalive).is_none() && device.want(Want::First).unwrap() == first);
	}

	#[test]
	fn a_tunnel_that_is_older_than_its_rekey_point_opens_with_a_new_handshake_and_a_fresh_tunnel_forgets() {
		let (mut device, mut node) = pair();
		let first = device.want(Want::First).unwrap();
		let (replies, _) = deliver(&mut node, &first);
		deliver(&mut device, &replies[0]);
		assert!(!device.due());
		device.rekey = Duration::ZERO;
		std::thread::sleep(Duration::from_millis(5));
		assert!(device.due());
		// The idle keepalive of a tunnel that is due is a handshake initiation, and the next rekey point is drawn again.
		let rekeyed = device.want(Want::Keepalive).unwrap();
		assert_eq!(rekeyed[0], 1);
		assert!(device.rekey >= Duration::from_secs(60) && device.rekey <= Duration::from_secs(110));
		device.fresh();
		assert!(!device.up());
	}
}
