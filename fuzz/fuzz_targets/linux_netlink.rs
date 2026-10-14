#![no_main]
//! What the Linux layer reads from the kernel's netlink socket (`veilway_linux::netlink`): a packet cut into messages, and the links, addresses and routes of a dump. The kernel is not hostile, but a message that does not fit its packet, an attribute of the wrong size or a prefix longer than its address must not panic the client or become a route it later tries to remove. The first byte is the setting: bit 0 picks the family and the whole byte is the table the routes are read for and the place where the rest is cut in two for the readers of a dump.
use libfuzzer_sys::fuzz_target;
use veilway_linux::netlink::{message, parse_addresses, parse_links, parse_routes, split};

fuzz_target!(|data: &[u8]| {
	let Some((&settings, rest)) = data.split_first() else {return};
	let mut payloads = Vec::new();
	let ended = split(rest, (settings & 2 == 2).then_some(u32::from(settings)), &mut payloads);
	assert!(payloads.iter().map(|payload| 16 + payload.len()).sum::<usize>() <= rest.len(), "the payloads are more than the packet");
	// What was cut out of a packet is the same when it is put back into messages and cut again.
	if let Ok(None) = ended {
		let mut wire = Vec::new();
		for payload in &payloads {
			wire.extend(message(20, 0, 0, payload));
			wire.resize(wire.len().next_multiple_of(4), 0);
		}
		let mut again = Vec::new();
		assert_eq!(split(&wire, None, &mut again).unwrap(), None);
		assert_eq!(again, payloads);
	}
	let (v6, table, at) = (settings & 1 == 1, u32::from(settings), usize::from(settings).min(rest.len()));
	let raw = vec![rest[..at].to_vec(), rest[at..].to_vec()];
	for set in [&payloads, &raw] {
		for link in parse_links(set) {assert!(!link.name.contains('\0'))}
		for address in parse_addresses(set) {assert!(address.prefix <= if address.ip.is_ipv6() {128} else {32})}
		for route in parse_routes(set, v6, table) {
			assert_eq!((route.table, route.v6), (table, v6));
			assert!(route.dst.is_none_or(|(ip, prefix)| ip.is_ipv6() == v6 && prefix <= if v6 {128} else {32}));
			assert!(route.gateway.is_none_or(|ip| ip.is_ipv6() == v6));
		}
	}
});
