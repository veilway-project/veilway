#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::engine::wg_stack;

// The userspace stack of a WireGuard outbound (`engine::wg_stack`) on what the server of the outbound sends once the tunnel has decrypted it. The input is cut into packets by a length byte before each, and a packet that starts with 0xff or 0xfe is built into a TCP segment or a UDP datagram of the open flows from what follows (flags, numbers, payload), so that the state machines see segments that belong to a connection. Whatever comes, nothing may panic, the stack never holds more than max_flows flows, and every packet it makes is a whole TCP or UDP packet from an own address to the one destination, within the MTU: never an ICMP message, never an answer to a packet it did not ask for. The clock is paused, so a timeout costs nothing.
fuzz_target!(|data: &[u8]| {
	let runtime = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
	if let Err(why) = runtime.block_on(wg_stack::drive(data)) {panic!("{why}")}
});
