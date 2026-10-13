#![no_main]
use libfuzzer_sys::fuzz_target;
use ring::digest::{digest, SHA256};
use std::collections::HashSet;
use veilway_proto::replay::{Failed, File, FileError, Kind, Pending, Refusal, Replay, Started, Verdict, AHEAD, MARKER, STEP, WINDOW};

// The cache size every file is read with.
const CAPACITY: usize = 64;

fn encoded(file: &File) -> Vec<u8> {
	let mut bytes = Vec::new();
	file.encode(&mut bytes).expect("a file of this size encodes");
	bytes
}

// How a write ends: on disk and reported so, not on disk and reported failed, or reported failed and on disk all the same.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Write {Synced, Lost, FailedButLanded}

// Does to the disk what the outcome says, and says whether the node is told the file is written.
fn put(disk: &mut Vec<u8>, file: &File, write: Write) -> bool {
	if write != Write::Lost {*disk = encoded(file)}
	write == Write::Synced
}

// Writes the file a pending memory asks for, with this outcome. After a reset that is not known to be on disk, the file that puts the old state back fails once more, the other way round, and is then written.
fn settle(disk: &mut Vec<u8>, pending: Pending, write: Write) -> Replay {
	if put(disk, &pending.file(), write) {return pending.written()}
	match pending.failed() {
		Failed::Usable(replay) => replay,
		Failed::Restore(pending) => {
			put(disk, &pending.file(), if write == Write::Lost {Write::FailedButLanded} else {Write::Lost});
			let Failed::Restore(pending) = pending.failed() else {panic!("a reset that is not undone gave a memory")};
			put(disk, &pending.file(), Write::Synced);
			pending.written()
		}
	}
}

// A start from what is on disk, with this outcome for the file it must write first, if it must.
fn restart(disk: &mut Vec<u8>, now: u64, capacity: usize, write: Write) -> Replay {
	match Replay::start(File::decode(disk, CAPACITY).ok(), now, capacity) {
		Started::Unclean(replay) => replay,
		Started::Clean(pending) | Started::NoFile(pending) => settle(disk, pending, write),
	}
}

// The replay file and the rule behind it. The first byte picks what the rest is, by its two low bits:
//   0  a replay file as it is found on disk
//   1  everything of a replay file before its hash. The right hash is added here, so the reader gets past it and must decide exactly as the rules of the file say.
//   2  what happens to a node, three bytes each: an event (by the value modulo 16: a proof for 0 to 7, then a clock step, the node's timer, a clean stop with its start, the same with the start killed once, a crash, a lost file, a reset), a byte of settings, and an offset or a step. The settings are the proof's key (three low bits), how the write of this event ends (bits 3 and 4: written, written, lost, reported failed and on disk all the same), the kind of key (bit 6) and whether the limits have no room (bit 7). With bit 2 of the first byte the node's timer runs after every event, with a disk that works.
//      Safety: no proof is accepted twice, none outside the window or at or below the floor, none above a limit that is not on disk, whatever the node was told about its writes. Liveness: since the last reset or lost file the floor is never more than `W` plus the step above the highest clock value seen unless a proof with such a timestamp was accepted, where the timer runs a proof within 10 s of the clock never waits for a write, and after the timer ran the limit on disk is no further ahead than the window, the floor or an accepted proof put it.
fuzz_target!(|data: &[u8]| {
	let Some((mode, rest)) = data.split_first() else {return};
	match mode & 3 {
		2 | 3 => {
			let (mut now, mut latest, mut spent, mut highest, mut disk, attentive) = (1_700_000_000u64, 1_700_000_000u64, HashSet::new(), 0u64, Vec::new(), mode & 4 != 0);
			let mut replay = restart(&mut disk, now, 4, Write::Synced);
			for event in rest.chunks_exact(3) {
				let (kind, key, timestamp, room, write) = (if event[1] & 0x40 == 0 {Kind::Stream} else {Kind::Opening}, [(event[1] & 7) % 6; 32], now.wrapping_add_signed(i64::from(event[2] as i8)), event[1] & 0x80 == 0, [Write::Synced, Write::Synced, Write::Lost, Write::FailedButLanded][usize::from(event[1] >> 3 & 3)]);
				match event[0] % 16 {
					0..=7 => {
						let (floor, mut charged) = (replay.floor(), 0);
						let mut verdict = replay.accept(kind, &key, timestamp, now, || {
							charged += 1;
							room
						});
						if let Verdict::Raise(limit) = verdict {
							assert!(charged == 0 && limit == timestamp + STEP && timestamp > replay.limit(), "a write was asked for a proof that needs none");
							assert!(!attentive || timestamp > now + AHEAD, "a proof within 10 s of the clock waited for a write");
							let file = replay.raise(limit).expect("no file is out, and the limit is below what was asked for");
							assert!(replay.raise(limit).is_none() && replay.timer(now).is_none(), "a second file was handed out while one was out");
							if put(&mut disk, &file, write) {replay.written()} else {replay.failed()}
							verdict = replay.accept(kind, &key, timestamp, now, || {
								charged += 1;
								room
							});
							assert!(if write == Write::Synced {matches!(verdict, Verdict::Accept | Verdict::Refuse(Refusal::Limited))} else {verdict == Verdict::Raise(limit)}, "a proof whose limit write ended as {write:?} met {verdict:?}");
						}
						assert_eq!(charged, usize::from(matches!(verdict, Verdict::Accept | Verdict::Refuse(Refusal::Limited))), "the limits were asked about a proof the rule refuses, or not about one it accepts");
						if verdict == Verdict::Accept {
							assert!(spent.insert((kind, key, timestamp)), "a proof was accepted twice");
							assert!(room && timestamp > floor && timestamp.abs_diff(now) <= WINDOW && File::decode(&disk, CAPACITY).is_ok_and(|file| file.limit() >= timestamp), "a proof outside the rule was accepted");
							highest = highest.max(timestamp);
						}
					}
					8 => {
						now = now.wrapping_add_signed(if event[1] & 1 == 0 {4} else {700} * i64::from(event[2] as i8));
						latest = latest.max(now);
					}
					9 => {}
					10 | 11 => {
						disk = encoded(&replay.stop());
						// The start is killed before it wrote the file again, and the next start reads the clean file once more.
						if event[0] % 16 == 11 {assert!(matches!(Replay::start(File::decode(&disk, CAPACITY).ok(), now, 4), Started::Clean(_)), "a clean file did not give a clean start")}
						replay = restart(&mut disk, now, 4, write);
					}
					12 | 13 => {
						// A crash. It finds no file when the first write of a start without one was lost, and nothing is known then but the clock, so that start is at a moment the clock is not behind where it has been.
						if File::decode(&disk, CAPACITY).is_err() {(now, highest) = (latest, 0)}
						replay = restart(&mut disk, now, 4, write);
					}
					14 => {
						(now, highest) = (latest, 0);
						disk.clear();
						replay = restart(&mut disk, now, 4, write);
					}
					_ => {
						// A reset. What was accepted above the new floor is forgotten, which is its stated cost, and from here a floor above this moment's window has to be earned again. A reset whose write is not known to be on disk has not happened.
						let before = (replay.floor(), replay.limit(), replay.len());
						replay = settle(&mut disk, replay.reset(now), write);
						if write == Write::Synced {
							spent.retain(|(_, _, timestamp)| *timestamp <= now + WINDOW);
							(latest, highest) = (now, 0);
						}
						assert_eq!((replay.floor(), replay.limit(), replay.len()), if write == Write::Synced {(now + WINDOW, now + WINDOW, 0)} else {before}, "a reset whose write ended as {write:?}");
						assert!(File::decode(&disk, CAPACITY).is_ok_and(|file| file.limit() == replay.limit() && file.floor() == replay.floor()), "after a reset the disk does not hold what the memory holds");
					}
				}
				if let Some(write) = if event[0] % 16 == 9 {Some(write)} else {attentive.then_some(Write::Synced)} {
					let synced = replay.timer(now).is_none_or(|file| {
						let synced = put(&mut disk, &file, write);
						if synced {replay.written()} else {replay.failed()}
						synced
					});
					if synced {
						let top = spent.iter().map(|(_, _, timestamp)| *timestamp).max().unwrap_or(0);
						assert!(replay.limit() >= now + AHEAD, "the limit is below rule 6 after the timer ran");
						assert!(replay.disk() <= (now + WINDOW).max(replay.floor()).max(top) + STEP, "the limit on disk is {} s ahead of the clock, and nothing accepted holds it there", replay.disk() - now);
					}
				}
				assert!(File::decode(&disk, CAPACITY).map_or(disk.is_empty(), |file| file.limit() >= replay.limit()) && replay.limit() <= replay.disk(), "the limit in use is above the limit on disk");
				assert!(replay.floor() <= (latest + WINDOW).max(highest) + STEP, "the floor is {} s above the highest clock value seen since the last reset, and no proof that high was accepted", replay.floor() - latest);
			}
			for (kind, key, timestamp) in spent {assert!(matches!(replay.accept(kind, &key, timestamp, timestamp, || true), Verdict::Refuse(_)), "a proof was accepted again")}
		}
		mode => {
			let bytes = if mode == 1 {[rest, digest(&SHA256, rest).as_ref()].concat()} else {rest.to_vec()};
			let read = File::decode(&bytes, CAPACITY);
			if mode == 1 {
				// The rules of the file, written a second time: the header, the count, and entries of a known kind at or below the limit.
				let (count, limit) = (rest.get(32..36).map(|count| u32::from_be_bytes([count[0], count[1], count[2], count[3]]) as usize), rest.get(24..32).map(|limit| u64::from_be_bytes(std::array::from_fn(|index| limit[index]))));
				let entries = || rest[36..].chunks_exact(41).all(|entry| (1..=2).contains(&entry[0]) && Some(u64::from_be_bytes(std::array::from_fn(|index| entry[33 + index]))) <= limit);
				let expected = if rest.len() < 36 {Err(FileError::Short)} else if rest[..8] != MARKER {Err(FileError::Marker)} else if rest[8..12] != [0, 0, 0, 1] {Err(FileError::Version)} else if rest[12] > 1 || rest[13..16] != [0; 3] {Err(FileError::Reserved)} else if count > Some(CAPACITY) {Err(FileError::Count)} else if count.map(|count| 36 + 41 * count) != Some(rest.len()) {Err(FileError::Length)} else if count > Some(0) && rest[12] == 0 {Err(FileError::Unclean)} else if !entries() {Err(FileError::Entry)} else {Ok(())};
				assert_eq!(read.as_ref().map(|_| ()).map_err(|error| *error), expected, "a replay file was not read as its rules say");
			}
			let Ok(file) = read else {return};
			// One file has one encoding. A memory that starts from it has its cache only from a clean file, a floor not below the file's, and a limit that is on disk or in the file the start writes first.
			assert_eq!(encoded(&file), bytes, "a replay file has a second encoding");
			assert!(file.len() <= CAPACITY && (file.clean() || file.is_empty()));
			let wanted = file.limit().max(1_700_000_020);
			match Replay::start(Some(file.clone()), 1_700_000_000, CAPACITY) {
				Started::Clean(pending) => {
					assert!(file.clean() && !pending.file().clean() && pending.file().limit() == wanted && pending.file().floor() == file.floor());
					let replay = pending.written();
					assert!(replay.floor() == file.floor() && replay.limit() == wanted && replay.len() <= file.len());
				}
				Started::Unclean(replay) => assert!(!file.clean() && replay.floor() == file.floor().max(file.limit()) && replay.limit() == file.limit() && replay.is_empty()),
				Started::NoFile(_) => panic!("a file that decoded was taken for no file"),
			}
		}
	}
});
