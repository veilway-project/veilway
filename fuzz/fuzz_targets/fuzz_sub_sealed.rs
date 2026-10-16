#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::subscription::sealed_file::{self, HEADER};

const PASSWORD: &str = "correct horse battery";
// A file of tests/sealed_file.rs: the link of the seed `fuzz_deeplink/native-veilway`, sealed under PASSWORD at the lowest cost.
const FILE: &[u8] = include_bytes!("../corpus/fuzz_sub_sealed/file");

// The reader of a sealed file on bytes nobody sealed. The first byte picks what the rest is, by its lowest bit:
//   0  a file as it arrives. A header that asks for less or more than a client opens must be refused with no hashing, so most inputs cost nothing. A file that opens is the one the same password and header make again from the text inside it, so nothing but a file written in its one form opens.
//   1  changes to a good file, three bytes each: a position, as two bytes, and a byte that is added to the byte there. The file must open exactly when nothing is left changed, and every other result is one of the refusals.
// One hashing is 64 MiB and three passes, so this target is slow by design.
fuzz_target!(|data: &[u8]| {
	let Some((mode, rest)) = data.split_first() else {return};
	if mode & 1 == 0 {
		if let Ok(text) = sealed_file::open(PASSWORD, rest) {
			let number = |at: usize| u32::from_be_bytes(rest[at..at + 4].try_into().expect("4 bytes"));
			assert_eq!(sealed_file::seal_at((number(9), number(13), number(17)), PASSWORD, &text, rest[21..37].try_into().expect("16 bytes"), rest[37..HEADER].try_into().expect("12 bytes")).as_deref(), Ok(rest), "a file opened that was not written this way");
		}
	} else {
		let mut file = FILE.to_vec();
		for change in rest.chunks_exact(3) {
			let at = usize::from(u16::from_be_bytes([change[0], change[1]])) % file.len();
			file[at] = file[at].wrapping_add(change[2]);
		}
		assert_eq!(sealed_file::open(PASSWORD, &file).is_ok(), file == FILE, "a changed file opened, or an unchanged one did not");
	}
});
