//! The TUN device through Wintun: whole IP packets in and out.
//!
//! `wintun.dll` is loaded from the folder of the executable and from nowhere else (`apps/desktop/scripts/fetch-wintun.sh` puts the pinned release there), so that a DLL planted in the working directory or on `PATH` is never the one an administrator's process runs. The adapter has a fixed GUID, so Windows keeps one network profile for it and does not make a new "Unidentified network N" at every connection. Packets are read on a thread of their own, because Wintun's wait is a blocking one, and handed to the runtime through a channel.
//!
//! An adapter lives as long as the process that made it: when the process dies, Wintun removes the adapter and its routes with it, and what holds the traffic then is the kill switch.
use std::io;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::{mpsc, Mutex};
use wintun_bindings::{Adapter, Session, Wintun};

/// Enough for a burst of packets and small enough that a stall shows as dropped packets and not as memory.
const RING: u32 = 4 * 1024 * 1024;
const QUEUE: usize = 1024;
/// "Veilway" in a GUID, the same for every connection.
const GUID: u128 = 0x5657_0001_9d3c_4f1e_8b4a_5657_0000_0001;
const TYPE: &str = "Veilway";

pub struct Tun {session: Arc<Session>, _adapter: Arc<Adapter>, _wintun: Wintun, rx: Mutex<mpsc::Receiver<Vec<u8>>>, reader: Option<JoinHandle<()>>, pub name: String, pub index: u32, pub luid: u64}

/// Whether `name` can name an adapter: it is shown to the user and is passed to Wintun, which takes up to 255 characters.
pub fn valid_name(name: &str) -> bool {!name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "_-. ".contains(c))}

impl Tun {
	/// Makes the adapter, or takes the one a client that did not stop left, and starts its session.
	pub fn create(name: &str) -> io::Result<Self> {
		if !valid_name(name) {return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{name:?} is not a name a network adapter can have")))}
		let dll = std::env::current_exe()?.with_file_name("wintun.dll");
		// SAFETY: loading a DLL runs its initialization. It is the one next to this executable, which the same installer or script put there, and not a name left to the search path.
		let wintun = unsafe {wintun_bindings::load_from_path(&dll)}.map_err(|error| io::Error::other(format!("cannot load {} ({error}): wintun.dll has to be next to veilway.exe", dll.display())))?;
		let adapter = match Adapter::open(&wintun, name) {
			Ok(adapter) => adapter,
			Err(_) => Adapter::create(&wintun, name, TYPE, Some(GUID)).map_err(|error| io::Error::other(format!("cannot create the network adapter ({error}): the program needs to run as an administrator")))?,
		};
		let session = adapter.start_session(RING).map_err(|error| io::Error::other(format!("cannot start the adapter's session: {error}")))?;
		let index = adapter.get_adapter_index().map_err(io::Error::other)?;
		// SAFETY: `Value` is the 64-bit view of the LUID, which every member of the union shares.
		let luid = unsafe {adapter.get_luid().Value};
		let (tx, rx) = mpsc::channel(QUEUE);
		let source = session.clone();
		let reader = std::thread::Builder::new().name("wintun-reader".into()).spawn(move || {
			// `receive_blocking` fails once the session is shut down, which is how this thread ends.
			while let Ok(packet) = source.receive_blocking() {
				if tx.blocking_send(packet.bytes().to_vec()).is_err() {break}
			}
		})?;
		Ok(Self {session, _adapter: adapter, _wintun: wintun, rx: Mutex::new(rx), reader: Some(reader), name: name.to_owned(), index, luid})
	}
	/// The next packet the system sent into the tunnel.
	pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
		let packet = self.rx.lock().await.recv().await.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "the adapter's session ended"))?;
		if packet.len() > buf.len() {return Err(io::Error::new(io::ErrorKind::InvalidInput, "a packet is larger than the read buffer"))}
		buf[..packet.len()].copy_from_slice(&packet);
		Ok(packet.len())
	}
	/// Hands a packet to the system. False when the session's ring is full and the packet was dropped, which is what any interface does.
	pub fn write(&self, packet: &[u8]) -> io::Result<bool> {
		let Ok(length) = u16::try_from(packet.len()) else {return Ok(false)};
		let Ok(mut out) = self.session.allocate_send_packet(length) else {return Ok(false)};
		out.bytes_mut().copy_from_slice(packet);
		self.session.send_packet(out);
		Ok(true)
	}
}

impl Drop for Tun {
	fn drop(&mut self) {
		let _ = self.session.shutdown();
		if let Some(reader) = self.reader.take() {let _ = reader.join();}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_names_an_adapter_can_have_pass() {
		assert!(valid_name("Veilway") && valid_name("veilway-1.x") && valid_name("My Tunnel"));
		assert!(!valid_name("") && !valid_name(&"a".repeat(65)) && !valid_name("vw\"0") && !valid_name("vw/0") && !valid_name("vw'0"));
	}
}
