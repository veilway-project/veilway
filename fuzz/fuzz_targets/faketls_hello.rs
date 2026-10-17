#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use veilway_proto::{faketls::{parse, Client, Node}, keys::{Device, Table, TagKey}, NoRandom};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

const INBOUND: [u8; 32] = [0x21; 32];
const DEVICE: [u8; 32] = [0x41; 32];
const SECRET: [u8; 32] = [0x11; 32];
const NODE: [u8; 32] = [0x61; 32];
const SITE: &[u8] = b"site.example";
const SHARE: [u8; 32] = [0x31; 32];
const NOW: u64 = 1_700_000_000;

// The node with the hour tags of one device, and one real hello that a client sealed for that table.
struct Fixed {node: Node, table: Table<Device<usize>>, hello: Vec<u8>}

fn ext(kind: u16, body: &[u8]) -> Vec<u8> {[&kind.to_be_bytes()[..], &(body.len() as u16).to_be_bytes(), body].concat()}

// A ClientHello with the site's name, TLS 1.3 and the standalone X25519 share of `SHARE`. The carrier is zeros until a client seals it.
fn template() -> Vec<u8> {
	let name = [&[0, 0, SITE.len() as u8][..], SITE].concat();
	let name = [&(name.len() as u16).to_be_bytes()[..], &name].concat();
	let share = [&[0x00, 0x1d, 0x00, 0x20][..], &x25519(SHARE, X25519_BASEPOINT_BYTES)[..]].concat();
	let keys = [&(share.len() as u16).to_be_bytes()[..], &share].concat();
	let extensions = [ext(0, &name), ext(43, &[2, 3, 4]), ext(51, &keys)].concat();
	let body = [&[3, 3][..], &[5; 32], &[32], &[0; 32], &[0, 2, 0x13, 0x01, 1, 0], &(extensions.len() as u16).to_be_bytes(), &extensions].concat();
	[&[1, 0, (body.len() >> 8) as u8, body.len() as u8][..], &body].concat()
}

fn fixed() -> &'static Fixed {
	static FIXED: OnceLock<Fixed> = OnceLock::new();
	FIXED.get_or_init(|| {
		let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
			for (index, byte) in bytes.iter_mut().enumerate() {*byte = 0xd0 ^ (index as u8).wrapping_mul(29)}
			Ok(())
		};
		let mut table = Table::new();
		let tags = TagKey::derive(&SECRET, &INBOUND);
		for hour in [NOW / 3600 - 1, NOW / 3600, NOW / 3600 + 1] {assert!(table.hour(tags.hour_tag(hour), Device::derive(0, &SECRET, &INBOUND, &DEVICE)))}
		let mut hello = template();
		Client::new(&x25519(NODE, X25519_BASEPOINT_BYTES), &SECRET, &INBOUND, &DEVICE).carry(&mut hello, &SHARE, NOW).expect("a client seals its own hello");
		Fixed {node: Node::new(NODE, INBOUND, &mut random).expect("a random source"), table, hello}
	})
}

fuzz_target!(|data: &[u8]| {
	let fixed = fixed();
	let _ = parse(data);
	let _ = fixed.node.open(data, &[SITE], &fixed.table);
	let mut hello = fixed.hello.clone();
	if let [at, flip, ..] = data {
		let at = usize::from(*at) % hello.len();
		hello[at] ^= flip;
	}
	let _ = fixed.node.open(&hello, &[SITE], &fixed.table);
});
