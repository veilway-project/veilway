//! The replay rule and the replay file (transports page, "The replay rule" and "The replay file"): one memory for every obfuscated transport of a node, as a state machine with no clock and no file of its own.
//!
//! The caller owns the wall clock, the file, its lock and its rename. The types here carry what they can of the rules that keep replay closed: a replay memory comes only from `Replay::start`, a start or a reset that must write the file first gives a `Pending` and no memory, a `File` is made only by this module, one file is out to be written at a time, and a proof is recorded only through `accept`, which charges the caller's rate limits last.
//!
//! What stays the caller's, because nothing here can see a disk:
//!
//! - It writes the files in the order they were handed out, each to a temporary file that is synced and renamed over the old one, and reports each as written or as failed before it asks for the next.
//! - "Written" means the file is on disk and synced. "Failed" means the attempt is over and nothing of it can land later: a write that only ran past its deadline is not failed until it has ended or can no longer finish. A failed write may still be on disk. Every path here is safe whether it is or not.
//! - The node's timer (`Replay::timer`) has run once, and what it handed out is written, before a listener takes its first proof.
use ring::digest::{digest, SHA256};
use std::{collections::{BTreeSet, HashMap}, fmt, time::Duration};

/// "Proof window `W`: 60 s either side of the node's clock."
pub const WINDOW: u64 = 60;
/// The limit is written "20 s above the base", and a proof above the limit starts a write of "a limit 20 s above its timestamp".
pub const STEP: u64 = 20;
/// "Whenever the limit is less than 10 s above the base, it writes a limit 20 s above the base."
pub const AHEAD: u64 = 10;
/// "Replay cache: 262,144 entries", the default of a config value.
pub const CACHE: usize = 262_144;
/// "Replay limit write: 2 s deadline." A stream proof waits this long for a higher limit to be written.
pub const WRITE_DEADLINE: Duration = Duration::from_secs(2);
/// At most this many entries leave the cache in one call, so that the proof that arrives after a pause or a forward step of the clock does not pay for a whole cache. The rest leave on the calls that follow, or when the caller's timer calls `expire`.
pub const EVICTIONS: usize = 64;
/// The first bytes of a replay file.
pub const MARKER: [u8; 8] = *b"VWREPLAY";
/// The one format version of the file.
pub const VERSION: u32 = 1;
// The file without entries: the marker, the version, the clean mark and three zero bytes, the floor, the limit and the entry count, then the hash. An entry is its kind, its key and its timestamp.
const HEADER: usize = 36;
const ENTRY: usize = 1 + 32 + 8;
const HASH: usize = 32;

/// What kind of key a cache entry has. The two kinds do not share one space: an `enc` that someone saw in flight cannot be spent as the salt of an opening packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
	/// `enc` of a stream proof.
	Stream = 1,
	/// `salt` of a `udp-obfs` opening packet.
	Opening = 2,
}

/// Why a proof is refused. This is for the node's counters and its log. The peer gets the unauthenticated path whatever it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// The timestamp is more than `W` away from the node's clock.
	Window,
	/// The timestamp is at or below the floor. When the floor is ahead of the clock this refuses honest clients, and the node says so ("When the floor is ahead of the clock").
	Floor,
	/// The key is in the cache: the proof was accepted before.
	Seen,
	/// The cache is full: "every proof is refused until entries leave".
	Full,
	/// The replay rule had nothing against the proof, and the caller's limits had no room for it ("Verifying", step 7). Nothing was recorded.
	Limited,
}

/// What the rule says about one proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
	/// The proof is recorded: it is spent from this moment.
	Accept,
	Refuse(Refusal),
	/// The proof is valid in every way the rule can see and lies above the written limit, which is "one from a client whose clock runs ahead". The limit must be raised to this value, on disk, before the proof may be accepted: write what `raise` gives for it, sync, call `written`, and ask again. On a stream transport the proof waits for that write, at most `WRITE_DEADLINE`. On `udp-obfs` the packet is dropped and the write is started. No limit of the caller was charged.
	Raise(u64),
}

/// What became of a proof that `proof::Opened::accept` or `udp_obfs::Opening::accept` took to the rule.
#[derive(Debug)]
pub enum Decision<A, P> {
	/// The proof is accepted and recorded, and this is the session it opens.
	Accepted(A),
	/// `Verdict::Raise`, with the proof to ask again with once the limit is written.
	Raise(u64, P),
	Refused(Refusal),
}

/// Which row of the table of "The replay file" a start took.
#[derive(Debug)]
pub enum Started {
	/// "Start after a clean stop": the cache, the floor and the limit are as they were. "Then the file is written again without the mark and synced before the first proof is accepted", which is why this is no memory yet.
	Clean(Pending),
	/// "Start after anything else": the cache is empty, the floor is the written limit and the limit is unchanged. Logged at info. The limit may be far behind the clock: the timer runs before the first proof.
	Unclean(Replay),
	/// "Start with no replay file, or with one that cannot be used": the floor and the limit are the wall clock plus `W`, "written and synced before the first proof is accepted". Logged at warn, or at error for a bad file.
	NoFile(Pending),
}

// What a `Pending` gives when its write failed.
enum Fallback {
	// A memory that is safe whether the file is on disk or not.
	Use(Replay),
	// After a reset: the memory as it was. It is safe only once its own floor and limit are known to be on disk again.
	Restore(Replay),
	// The write that puts the old floor and limit back failed as well: the same again.
	Again,
}

/// A replay memory that must not be used before its file is on disk: after a clean start, a start without a file, and a reset. Write `file`, sync it, and say how that went.
pub struct Pending {file: File, next: Replay, fallback: Fallback}

/// What a `Pending` gives when its write failed, which may mean that the file is on disk all the same.
#[derive(Debug)]
#[must_use]
pub enum Failed {
	/// A memory that is safe whichever file is on disk. After a clean start it is the row below that one: the cache is forgotten and the floor is the limit of the clean file. After a start without a file it is the same memory, in which nothing can be accepted before a write succeeds.
	Usable(Replay),
	/// After a reset. The reset may be on disk or not, and no memory is right for both: the old one would accept above the limit of a reset that landed, and the new one has forgotten what the old file still vouches for. This holds the file that puts the old floor and limit back. No proof is accepted until it, or one after it, is written.
	Restore(Pending),
}

impl Pending {
	/// The file to write and sync: a floor and a limit, without the clean mark.
	pub fn file(&self) -> File {self.file.clone()}
	/// The file is written and synced.
	pub fn written(self) -> Replay {self.next}
	/// The write failed.
	pub fn failed(self) -> Failed {
		match self.fallback {
			Fallback::Use(replay) => Failed::Usable(replay),
			Fallback::Restore(old) => Failed::Restore(Self {file: File {floor: old.floor, limit: old.limit, entries: None}, next: Replay {disk: old.limit, out: None, ..old}, fallback: Fallback::Again}),
			Fallback::Again => Failed::Restore(self),
		}
	}
}

impl fmt::Debug for Pending {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Pending({:?})", self.next)}
}

/// The replay memory of a node: "a cache of accepted proofs, a floor, and a limit".
///
/// It keeps two limits. `limit` is the one proofs are judged by: no file that may be on disk has a lower one. `disk` is the highest limit that may be on disk, which is what an unclean start could find and take as its floor. They are equal except between a write that lowers the limit, or one that failed, and the next write that is known to be on disk.
pub struct Replay {seen: HashMap<(Kind, [u8; 32]), u64>, order: BTreeSet<(u64, Kind, [u8; 32])>, floor: u64, limit: u64, disk: u64, out: Option<u64>, highest: Option<u64>, capacity: usize}

// The cache holds up to 262,144 keys, and none of them belongs in a log line.
impl fmt::Debug for Replay {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Replay(floor {}, limit {}, {} entries)", self.floor, self.limit, self.seen.len())}
}

impl Replay {
	// A memory with an empty cache in which no timestamp has been accepted: "the base is the wall clock alone". `disk` is the highest limit a file of its start may have left on disk.
	fn bare(floor: u64, limit: u64, disk: u64, capacity: usize) -> Self {Self {seen: HashMap::new(), order: BTreeSet::new(), floor, limit, disk, out: None, highest: None, capacity}}
	/// The only way to a replay memory. `file` is what `File::decode` gave for the node's replay file, and `None` when there is no file or when decoding failed: "An implementation must not start with an empty cache and no floor because it could not read the file." `now` is the wall clock in Unix seconds and `capacity` the configured cache size.
	/// Without a file the floor comes from the clock alone, so a clock that is behind where it has been leaves proofs the node accepted before above the floor: "A node should not start its obfuscated transports before its clock is synchronised."
	pub fn start(file: Option<File>, now: u64, capacity: usize) -> Started {
		match file {
			Some(File {floor, limit, entries: Some(entries)}) => {
				// The file that is written first carries the limit the clock asks for already, so that the start needs one write and not two.
				let written = limit.max(now.saturating_add(STEP));
				let mut next = Self::bare(floor, written, written, capacity);
				for (kind, key, timestamp) in entries {
					// An entry that is in the file twice is kept once, with its later timestamp.
					if next.seen.get(&(kind, key)).is_none_or(|kept| *kept < timestamp) {
						if let Some(kept) = next.seen.insert((kind, key), timestamp) {next.order.remove(&(kept, kind, key));}
						next.order.insert((timestamp, kind, key));
					}
				}
				// Should that write fail, the disk has the clean file or the new one, and both have at least the old limit: with the cache forgotten and that limit as the floor, nothing either file vouches for can be accepted again.
				Started::Clean(Pending {file: File {floor, limit: written, entries: None}, next, fallback: Fallback::Use(Self::bare(floor.max(limit), limit, written, capacity))})
			}
			// "The written limit. Every proof accepted before had a timestamp at or below it." The limit is "unchanged, until rule 6 asks for more".
			Some(File {floor, limit, entries: None}) => Started::Unclean(Self::bare(floor.max(limit), limit, limit, capacity)),
			// Should the write fail, nothing is on disk or this file is. Every timestamp above the floor is above the limit, so nothing is accepted before a write that is known to be there.
			None => {
				let ahead = now.saturating_add(WINDOW);
				Started::NoFile(Pending {file: File {floor: ahead, limit: ahead, entries: None}, next: Self::bare(ahead, ahead, ahead, capacity), fallback: Fallback::Use(Self::bare(ahead, ahead, ahead, capacity))})
			}
		}
	}
	/// The floor as far as entries have left the cache. A node reports it, and logs when it is ahead of the wall clock. Entries leave a few at a time, so a caller that reports the floor calls `expire` first, until it says that nothing left.
	pub fn floor(&self) -> u64 {self.floor}
	/// The limit proofs are judged by.
	pub fn limit(&self) -> u64 {self.limit}
	/// The highest limit that may be on disk: what the next unclean start could take as its floor. A node warns when it is more than `W` plus 20 s ahead of the wall clock, which the timer then brings down as far as it safely can.
	pub fn disk(&self) -> u64 {self.disk}
	/// Whether a file is out to be written: `timer` and `raise` give no other until `written` or `failed` is called.
	pub fn writing(&self) -> bool {self.out.is_some()}
	/// The number of proofs in the cache.
	pub fn len(&self) -> usize {self.seen.len()}
	pub fn is_empty(&self) -> bool {self.seen.is_empty()}
	/// Lets entries leave whose time has come, at most `EVICTIONS` of them, and says how many left: "An entry leaves the cache only when its timestamp is more than `W` behind the wall clock, and when it leaves, the floor rises to that timestamp if it was lower." `accept` does this itself. A caller's timer may do it as well, so that a full cache empties without waiting for proofs.
	/// An entry that has not left yet refuses nothing it should not: every timestamp at or below its own is outside the window by then.
	pub fn expire(&mut self, now: u64) -> usize {
		let mut left = 0;
		while let Some((oldest, kind, key)) = self.order.first().copied().filter(|(oldest, ..)| left < EVICTIONS && oldest.saturating_add(WINDOW) < now) {
			self.order.remove(&(oldest, kind, key));
			self.seen.remove(&(kind, key));
			self.floor = self.floor.max(oldest);
			left += 1;
		}
		left
	}
	// Steps 5 and 6 of "Verifying": the window, the floor and the limit, then the cache and its room. "This check records nothing."
	fn verdict(&mut self, kind: Kind, key: &[u8; 32], timestamp: u64, now: u64) -> Verdict {
		self.expire(now);
		if timestamp.saturating_add(WINDOW) < now || timestamp > now.saturating_add(WINDOW) {return Verdict::Refuse(Refusal::Window)}
		if timestamp <= self.floor {return Verdict::Refuse(Refusal::Floor)}
		if self.seen.contains_key(&(kind, *key)) {return Verdict::Refuse(Refusal::Seen)}
		if self.seen.len() >= self.capacity {return Verdict::Refuse(Refusal::Full)}
		if timestamp > self.limit {return Verdict::Raise(timestamp.saturating_add(STEP))}
		Verdict::Accept
	}
	/// Takes a proof to the rule: its key (`enc` of a stream proof, `salt` of an opening packet) with its kind, and its timestamp, at the wall clock `now`.
	/// `charge` is step 7 of "Verifying", the caller's rate limits and its count of pending sessions. It is called only when the rule would accept, and spends what it spends: "Steps 5 and 6 come before step 7 is charged. A proof that fails the replay rule spends no rate limit." The proof is recorded only when it says there was room.
	pub fn accept(&mut self, kind: Kind, key: &[u8; 32], timestamp: u64, now: u64, charge: impl FnOnce() -> bool) -> Verdict {
		let verdict = self.verdict(kind, key, timestamp, now);
		if verdict != Verdict::Accept {return verdict}
		if !charge() {return Verdict::Refuse(Refusal::Limited)}
		self.seen.insert((kind, *key), timestamp);
		self.order.insert((timestamp, kind, *key));
		self.highest = Some(self.highest.map_or(timestamp, |highest| highest.max(timestamp)));
		Verdict::Accept
	}
	// Hands out the file for a limit, unless one is out. From this moment the limit proofs are judged by is no higher than this file's, since this file may be the one on disk.
	fn hand(&mut self, limit: u64) -> Option<File> {
		if self.out.is_some() {return None}
		(self.out, self.limit) = (Some(limit), self.limit.min(limit));
		Some(File {floor: self.floor, limit, entries: None})
	}
	/// The node's timer, away from the packet path: the file to write now, or `None` when nothing is wanted or a file is out already. A caller asks about once a second, and once before its listeners take their first proof.
	///
	/// Rule 6, "The limit follows the clock": "Let the base be the wall clock, or the highest timestamp accepted since the last start, forget or reset if that is later. Whenever the limit is less than 10 s above the base, it writes a limit 20 s above the base." That is a write about every 10 s.
	///
	/// The node also lowers its own limit when that is safe. A limit on disk that is more than `W` plus 20 s ahead of the clock is the mark of a clock that was wrong, and the next unclean start would make it the floor and refuse everyone until the clock got there. Every proof this node ever accepted has a timestamp at or below the floor or is in the cache: an entry that left raised the floor to its timestamp, and what was accepted before the last start is at or below the floor that start took. So a limit 20 s above the latest of the floor, the highest timestamp in the cache and the clock is above everything a later start must refuse, and the limit comes down to it. With proofs accepted during the fault that is no lower than they reach, and only a reset goes below them. The limit in use comes down when the file is handed out, before it is written, so it is never above the limit of a file that may be on disk.
	pub fn timer(&mut self, now: u64) -> Option<File> {
		let base = self.highest.map_or(now, |highest| highest.max(now));
		let kept = self.order.last().map_or(self.floor, |(timestamp, ..)| self.floor.max(*timestamp)).max(now).saturating_add(STEP);
		let limit = if self.limit < base.saturating_add(AHEAD) {base.saturating_add(STEP)} else if self.disk > now.saturating_add(WINDOW + STEP) && kept < self.disk {kept} else {return None};
		self.hand(limit)
	}
	/// The file that raises the limit to what `Verdict::Raise` asked for, to write and sync before `written` is called. `None` when a file is out already, in which case the proof waits for that write to end and is asked again, or when the limit is that high by now.
	pub fn raise(&mut self, limit: u64) -> Option<File> {(limit > self.limit).then(|| self.hand(limit)).flatten()}
	/// The file that was handed out is written and synced: its limit is the limit, on disk and in use.
	pub fn written(&mut self) {
		if let Some(limit) = self.out.take() {(self.limit, self.disk) = (limit, limit)}
	}
	/// The write of the file that was handed out failed. It may be on disk all the same, so the limit in use stays where it is, which is no higher than that file's, and the highest limit that may be on disk is that file's if it was higher.
	pub fn failed(&mut self) {
		if let Some(limit) = self.out.take() {self.disk = self.disk.max(limit)}
	}
	/// The file of a clean stop: the cache, the floor, the limit and the clean mark.
	pub fn stop(&self) -> File {File {floor: self.floor, limit: self.limit, entries: Some(self.order.iter().map(|(timestamp, kind, key)| (*kind, *key, *timestamp)).collect())}}
	/// `veilway replay reset`: the cache is emptied, and the floor and the limit become the wall clock plus `W`, "also when that is lower than before. Written and synced before the next proof is accepted", which is why this takes the memory and gives it back through `Pending`. A file that is out is reported first.
	/// "A proof that was accepted during the fault with a timestamp above the new floor is forgotten, and whoever recorded it can use it once more."
	pub fn reset(self, now: u64) -> Pending {
		let ahead = now.saturating_add(WINDOW);
		Pending {file: File {floor: ahead, limit: ahead, entries: None}, next: Self::bare(ahead, ahead, ahead, self.capacity), fallback: Fallback::Restore(self)}
	}
}

/// Why bytes are not a replay file. Every one of these means "no usable replay file": the caller renames the file with `.bad` added, logs at error, and starts with `Replay::start(None, ..)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
	/// Shorter than a file with no entries.
	Short,
	/// Other first bytes.
	Marker,
	/// An unknown format version.
	Version,
	/// The hash at the end is not the hash of what is before it: the file is damaged or cut.
	Hash,
	/// A clean mark that is neither 0 nor 1, or a zero byte that is not zero.
	Reserved,
	/// More entries than the configured cache size, or than the count field can hold. A config that lowers the cache size below the count of the last clean file does this to that file.
	Count,
	/// The entry count does not match the length.
	Length,
	/// Entries without the clean mark.
	Unclean,
	/// An entry of an unknown kind, or with a timestamp above the limit of the file, which no node writes.
	Entry,
}

impl fmt::Display for FileError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "replay file: {self:?}")}
}

impl std::error::Error for FileError {}

/// The content of a replay file. Only this module makes one: `decode` from the bytes of a file, and a replay memory for the files it wants written. There is no empty one to reach for.
#[derive(Clone, PartialEq, Eq)]
pub struct File {floor: u64, limit: u64, entries: Option<Vec<(Kind, [u8; 32], u64)>>}

impl fmt::Debug for File {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "File(floor {}, limit {}, {})", self.floor, self.limit, self.entries.as_ref().map_or("no clean mark".to_owned(), |entries| format!("{} entries", entries.len())))}
}

impl File {
	/// Unix seconds.
	pub fn floor(&self) -> u64 {self.floor}
	/// Unix seconds.
	pub fn limit(&self) -> u64 {self.limit}
	/// Whether the file has the clean mark, and with it the cache.
	pub fn clean(&self) -> bool {self.entries.is_some()}
	/// The number of cache entries in the file.
	pub fn len(&self) -> usize {self.entries.as_ref().map_or(0, Vec::len)}
	pub fn is_empty(&self) -> bool {self.len() == 0}
	/// Appends the file to `out`, with the SHA-256 of every byte before it at the end. Nothing is appended when there are more entries than the count field can hold.
	pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FileError> {
		let (start, entries) = (out.len(), self.entries.as_deref().unwrap_or_default());
		let count = u32::try_from(entries.len()).map_err(|_| FileError::Count)?;
		out.reserve(HEADER + entries.len().saturating_mul(ENTRY) + HASH);
		out.extend_from_slice(&MARKER);
		out.extend_from_slice(&VERSION.to_be_bytes());
		out.extend_from_slice(&[u8::from(self.entries.is_some()), 0, 0, 0]);
		out.extend_from_slice(&self.floor.to_be_bytes());
		out.extend_from_slice(&self.limit.to_be_bytes());
		out.extend_from_slice(&count.to_be_bytes());
		for (kind, key, timestamp) in entries {
			out.push(*kind as u8);
			out.extend_from_slice(key);
			out.extend_from_slice(&timestamp.to_be_bytes());
		}
		let hash = digest(&SHA256, &out[start..]);
		out.extend_from_slice(hash.as_ref());
		Ok(())
	}
	/// Reads a replay file. `capacity` is the configured cache size: "The entry count is at most the configured cache size."
	/// Nothing is allocated before the length, the hash and the count have been checked, and then only as much as the entries in `bytes` take.
	pub fn decode(bytes: &[u8], capacity: usize) -> Result<Self, FileError> {
		if bytes.len() < HEADER + HASH {return Err(FileError::Short)}
		let (body, hash) = bytes.split_at(bytes.len() - HASH);
		let (long, short) = (|at: usize| u64::from_be_bytes(std::array::from_fn(|index| body[at + index])), |at: usize| u32::from_be_bytes(std::array::from_fn(|index| body[at + index])));
		if body[..8] != MARKER {return Err(FileError::Marker)}
		if short(8) != VERSION {return Err(FileError::Version)}
		// "It detects a damaged or cut file. It is not a security measure", so the comparison need not be in constant time.
		if digest(&SHA256, body).as_ref() != hash {return Err(FileError::Hash)}
		if body[12] > 1 || body[13..16] != [0; 3] {return Err(FileError::Reserved)}
		let (count, limit) = (usize::try_from(short(32)).map_err(|_| FileError::Count)?, long(24));
		if count > capacity {return Err(FileError::Count)}
		if count.checked_mul(ENTRY).and_then(|size| size.checked_add(HEADER + HASH)) != Some(bytes.len()) {return Err(FileError::Length)}
		if count > 0 && body[12] == 0 {return Err(FileError::Unclean)}
		let entries = body[HEADER..].as_chunks::<ENTRY>().0.iter().map(|entry| {
			let kind = [Kind::Stream, Kind::Opening].into_iter().find(|kind| *kind as u8 == entry[0]).ok_or(FileError::Entry)?;
			let timestamp = u64::from_be_bytes(std::array::from_fn(|index| entry[33 + index]));
			if timestamp > limit {return Err(FileError::Entry)}
			Ok((kind, std::array::from_fn(|index| entry[1 + index]), timestamp))
		}).collect::<Result<Vec<_>, _>>()?;
		Ok(Self {floor: long(16), limit, entries: (body[12] == 1).then_some(entries)})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const TIME: u64 = 1_700_000_000;

	fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

	// A file body with the hash it should have, so that a test reaches the checks behind the hash.
	fn hashed(body: &[u8]) -> Vec<u8> {[body, digest(&SHA256, body).as_ref()].concat()}

	fn clean() -> File {File {floor: TIME, limit: TIME + 20, entries: Some(vec![(Kind::Stream, [0x11; 32], TIME + 1), (Kind::Opening, [0x22; 32], TIME + 5)])}}

	fn encoded(file: &File) -> Vec<u8> {
		let mut bytes = Vec::new();
		file.encode(&mut bytes).unwrap();
		bytes
	}

	// What a node does with a file it was handed when the write succeeds: the bytes go to disk, and only then does the memory hear of it.
	fn write(replay: &mut Replay, file: Option<File>, disk: &mut Vec<u8>) {
		if let Some(file) = file {
			*disk = encoded(&file);
			replay.written();
		}
	}

	// The node's timer, with a disk that works.
	fn tick(replay: &mut Replay, now: u64, disk: &mut Vec<u8>) {
		let file = replay.timer(now);
		write(replay, file, disk);
	}

	// A memory that started without a file at `TIME - 100`, so its floor is `TIME - 40`, with its file written and the limit written up to `limit`.
	fn started(limit: u64, capacity: usize) -> Replay {
		let Started::NoFile(pending) = Replay::start(None, TIME - 100, capacity) else {panic!("a start without a file")};
		let mut replay = pending.written();
		assert_eq!((replay.floor(), replay.limit(), replay.disk()), (TIME - 40, TIME - 40, TIME - 40));
		assert!(replay.raise(limit).is_some() && replay.writing());
		replay.written();
		replay
	}

	// A stream proof whose key is `fill`, with limits that have room.
	fn take(replay: &mut Replay, fill: u8, timestamp: u64, now: u64) -> Verdict {replay.accept(Kind::Stream, &[fill; 32], timestamp, now, || true)}

	// A start from what is on disk, with every file it must write first written.
	fn restart(disk: &mut Vec<u8>, now: u64, capacity: usize) -> Replay {
		match Replay::start(File::decode(disk, capacity).ok(), now, capacity) {
			Started::Unclean(replay) => replay,
			Started::Clean(pending) | Started::NoFile(pending) => {
				*disk = encoded(&pending.file());
				pending.written()
			}
		}
	}

	// Expected bytes come from tests/vectors.py, which uses only Python's struct and hashlib.
	#[test]
	fn the_file_byte_for_byte() {
		let (with_cache, running) = (encoded(&clean()), encoded(&File {entries: None, ..clean()}));
		assert_eq!(hex(&with_cache), "56575245504c41590000000101000000000000006553f100000000006553f11400000002011111111111111111111111111111111111111111111111111111111111111111000000006553f101022222222222222222222222222222222222222222222222222222222222222222000000006553f1059e8295811967de54855162c81d916fdf316f14d5044951b8a7fd0e4d0504006a");
		assert_eq!(hex(&running), "56575245504c41590000000100000000000000006553f100000000006553f1140000000093e6923fbd94509b8118df578d24e4a23ac8d35332bbf9d79a8923a8d1a6c97c");
		// "68 bytes while the node runs", and "about 10 MiB on a clean stop" at the default cache size.
		assert_eq!((running.len(), HEADER + CACHE * ENTRY + HASH), (68, 10_747_972));
		assert_eq!(File::decode(&with_cache, 2), Ok(clean()));
		let read = File::decode(&running, 0).unwrap();
		assert_eq!((read.floor(), read.limit(), read.clean(), read.len(), read.is_empty()), (TIME, TIME + 20, false, 0, true));
		// A clean stop with an empty cache is not the same file as a running one.
		let empty = File {entries: Some(Vec::new()), ..clean()};
		assert_eq!(File::decode(&encoded(&empty), 0).map(|file| (file.clean(), file.len())), Ok((true, 0)));
		// Appending keeps what was there.
		let mut out = vec![0xee];
		clean().encode(&mut out).unwrap();
		assert_eq!((out[0], &out[1..]), (0xee, &with_cache[..]));
	}

	#[test]
	fn a_file_that_cannot_be_used_is_a_typed_error() {
		let good = encoded(&clean());
		let body = &good[..good.len() - HASH];
		let changed = |at: usize, value: u8| {
			let mut body = body.to_vec();
			body[at] = value;
			hashed(&body)
		};
		assert_eq!(File::decode(&changed(0, b'X'), 9), Err(FileError::Marker));
		assert_eq!(File::decode(&changed(11, 2), 9), Err(FileError::Version));
		assert_eq!(File::decode(&changed(8, 1), 9), Err(FileError::Version));
		assert_eq!(File::decode(&changed(12, 2), 9), Err(FileError::Reserved));
		for zero in 13..16 {assert_eq!(File::decode(&changed(zero, 1), 9), Err(FileError::Reserved))}
		assert_eq!(File::decode(&good, 1), Err(FileError::Count));
		assert_eq!(File::decode(&changed(35, 3), 9), Err(FileError::Length));
		assert_eq!(File::decode(&changed(35, 1), 9), Err(FileError::Length));
		assert_eq!(File::decode(&changed(32, 1), usize::MAX), Err(FileError::Length));
		assert_eq!(File::decode(&hashed(&[body, &[0; 41]].concat()), 9), Err(FileError::Length));
		assert_eq!(File::decode(&changed(12, 0), 9), Err(FileError::Unclean));
		assert_eq!(File::decode(&[&good[..], &[0]].concat(), 9), Err(FileError::Hash));
		// A kind that is not defined, and an entry above the limit of its own file: no node writes either.
		for kind in [0, 3, 0xff] {assert_eq!(File::decode(&changed(HEADER, kind), 9), Err(FileError::Entry))}
		assert_eq!(File::decode(&changed(HEADER + 40, 0x15), 9), Err(FileError::Entry));
		assert!(File::decode(&changed(HEADER + 40, 0x14), 9).is_ok());
		// A cut at every length, and a change of every bit, is an error of some kind. No bytes but the file's own decode.
		for size in 0..good.len() {assert!(File::decode(&good[..size], 9).is_err(), "{size} bytes")}
		assert_eq!((File::decode(&[], 9), File::decode(&good[..67], 9), File::decode(&good[..68], 9)), (Err(FileError::Short), Err(FileError::Short), Err(FileError::Hash)));
		for bit in 0..good.len() * 8 {
			let mut flipped = good.clone();
			flipped[bit / 8] ^= 1 << (bit % 8);
			assert!(File::decode(&flipped, 9).is_err(), "bit {bit}");
		}
	}

	#[test]
	fn the_window_the_floor_and_the_cache() {
		let mut replay = started(TIME + 100, 3);
		// "A proof is accepted only if its timestamp is within `W` of the node's wall clock", both ends included. Nothing here is recorded: the limits say no.
		assert_eq!([TIME - 61, TIME - 60, TIME + 60, TIME + 61].map(|timestamp| replay.accept(Kind::Stream, &[1; 32], timestamp, TIME, || false)), [Verdict::Refuse(Refusal::Window), Verdict::Refuse(Refusal::Floor), Verdict::Refuse(Refusal::Limited), Verdict::Refuse(Refusal::Window)]);
		// "A proof whose timestamp is at or below the floor is refused."
		assert_eq!([TIME - 40, TIME - 39].map(|timestamp| replay.accept(Kind::Stream, &[1; 32], timestamp, TIME, || false)), [Verdict::Refuse(Refusal::Floor), Verdict::Refuse(Refusal::Limited)]);
		assert!(replay.is_empty());
		// An accepted proof is spent, with any timestamp.
		assert_eq!((take(&mut replay, 1, TIME, TIME), replay.len()), (Verdict::Accept, 1));
		assert_eq!([TIME, TIME + 1].map(|timestamp| take(&mut replay, 1, timestamp, TIME)), [Verdict::Refuse(Refusal::Seen); 2]);
		// "When the cache is full, every proof is refused until entries leave."
		assert_eq!([2, 3, 4].map(|fill| take(&mut replay, fill, TIME + u64::from(fill), TIME)), [Verdict::Accept, Verdict::Accept, Verdict::Refuse(Refusal::Full)]);
		assert_eq!(take(&mut replay, 4, TIME + 4, TIME + 60), Verdict::Refuse(Refusal::Full));
		// "An entry leaves the cache only when its timestamp is more than `W` behind the wall clock, and when it leaves, the floor rises to that timestamp."
		assert_eq!((take(&mut replay, 4, TIME + 4, TIME + 61), replay.floor(), replay.len()), (Verdict::Accept, TIME, 3));
		assert_eq!(take(&mut replay, 1, TIME, TIME + 61), Verdict::Refuse(Refusal::Window));
		assert_eq!(take(&mut replay, 1, TIME, TIME + 40), Verdict::Refuse(Refusal::Floor));
		// A clock that steps back does not bring an entry back, and does not lower the floor.
		assert_eq!((take(&mut replay, 2, TIME + 2, TIME), replay.floor()), (Verdict::Refuse(Refusal::Seen), TIME));
	}

	// "Steps 5 and 6 come before step 7 is charged. A proof that fails the replay rule spends no rate limit. Otherwise one old token from a log, sent once a second, would keep a device's allowance empty."
	#[test]
	fn the_limits_are_charged_last_and_only_for_a_proof_the_rule_would_accept() {
		let (mut replay, mut charged) = (started(TIME + 20, 2), 0);
		let mut ask = |replay: &mut Replay, fill: u8, timestamp: u64, now: u64, room: bool| replay.accept(Kind::Stream, &[fill; 32], timestamp, now, || {
			charged += 1;
			room
		});
		// A token from an old log, one at the floor, one above the written limit: none of them reaches the limits.
		assert_eq!(ask(&mut replay, 1, TIME - 86_400, TIME, true), Verdict::Refuse(Refusal::Window));
		assert_eq!(ask(&mut replay, 1, TIME - 40, TIME, true), Verdict::Refuse(Refusal::Floor));
		assert_eq!(ask(&mut replay, 1, TIME + 21, TIME, true), Verdict::Raise(TIME + 41));
		// Limits without room: charged once, nothing recorded, and the same proof is good when there is room.
		assert_eq!(ask(&mut replay, 1, TIME, TIME, false), Verdict::Refuse(Refusal::Limited));
		assert_eq!(ask(&mut replay, 1, TIME, TIME, true), Verdict::Accept);
		// A replay and a full cache do not reach them either.
		assert_eq!(ask(&mut replay, 1, TIME, TIME, true), Verdict::Refuse(Refusal::Seen));
		assert_eq!(ask(&mut replay, 2, TIME, TIME, true), Verdict::Accept);
		assert_eq!(ask(&mut replay, 3, TIME, TIME, true), Verdict::Refuse(Refusal::Full));
		assert_eq!((charged, replay.len()), (3, 2));
	}

	// An `enc` and a salt of the same bytes are two keys.
	#[test]
	fn the_two_kinds_of_key_do_not_share_one_space() {
		let mut replay = started(TIME + 20, 9);
		assert_eq!(replay.accept(Kind::Stream, &[1; 32], TIME, TIME, || true), Verdict::Accept);
		assert_eq!(replay.accept(Kind::Opening, &[1; 32], TIME, TIME, || true), Verdict::Accept);
		assert_eq!([Kind::Stream, Kind::Opening].map(|kind| replay.accept(kind, &[1; 32], TIME + 1, TIME, || true)), [Verdict::Refuse(Refusal::Seen); 2]);
		// Both come back from a clean file as what they were.
		let Started::Clean(pending) = Replay::start(File::decode(&encoded(&replay.stop()), 9).ok(), TIME, 9) else {panic!("a clean start")};
		let mut replay = pending.written();
		assert_eq!([Kind::Stream, Kind::Opening].map(|kind| replay.accept(kind, &[1; 32], TIME + 1, TIME, || true)), [Verdict::Refuse(Refusal::Seen); 2]);
	}

	#[test]
	fn nothing_is_accepted_above_the_written_limit() {
		let mut replay = started(TIME + 20, 9);
		assert_eq!(take(&mut replay, 1, TIME + 20, TIME), Verdict::Accept);
		// One second above: the limit must be on disk first, 20 s above the timestamp.
		assert_eq!(take(&mut replay, 2, TIME + 21, TIME), Verdict::Raise(TIME + 41));
		assert_eq!((replay.len(), replay.limit()), (1, TIME + 20));
		// A proof that fails anything else starts no write.
		assert_eq!(take(&mut replay, 1, TIME + 21, TIME), Verdict::Refuse(Refusal::Seen));
		assert_eq!(take(&mut replay, 2, TIME + 61, TIME), Verdict::Refuse(Refusal::Window));
		// The file for the write holds the new limit, and the memory does not until it is told the file is on disk.
		let file = replay.raise(TIME + 41).unwrap();
		assert_eq!((file.floor(), file.limit(), file.clean(), replay.limit()), (TIME - 40, TIME + 41, false, TIME + 20));
		assert_eq!(take(&mut replay, 2, TIME + 21, TIME), Verdict::Raise(TIME + 41));
		replay.written();
		assert_eq!((replay.limit(), replay.disk(), take(&mut replay, 2, TIME + 21, TIME)), (TIME + 41, TIME + 41, Verdict::Accept));
		// There is no file for a limit that is not above the one in use, and telling the memory of a write nobody was handed changes nothing.
		assert!(replay.raise(TIME).is_none() && replay.raise(TIME + 41).is_none() && !replay.writing());
		replay.written();
		replay.failed();
		assert_eq!((replay.limit(), replay.disk()), (TIME + 41, TIME + 41));
		assert_eq!(take(&mut replay, 3, u64::MAX, u64::MAX), Verdict::Raise(u64::MAX));
	}

	// Two files that land in the other order than they were made would leave the lower limit on disk under a memory that holds the higher. There is one file at a time, so there is no such pair.
	#[test]
	fn one_file_is_out_at_a_time() {
		let (mut replay, now, mut disk) = (started(TIME, 9), TIME, Vec::new());
		// The timer makes its file, for 20 s above the clock, and is slow to write it.
		let slow = replay.timer(now).unwrap();
		assert_eq!((slow.limit(), replay.writing()), (now + 20, true));
		// A proof from a client whose clock is 60 s fast asks for a higher limit. No file is made for it while the timer's is out, and none for the timer again.
		assert_eq!(take(&mut replay, 1, now + 60, now), Verdict::Raise(now + 80));
		assert!(replay.raise(now + 80).is_none() && replay.timer(now).is_none());
		assert_eq!((take(&mut replay, 1, now + 60, now), replay.limit()), (Verdict::Raise(now + 80), now));
		// The timer's write ends. Now the proof's file is made and written, and the proof is accepted.
		disk.clone_from(&encoded(&slow));
		replay.written();
		let file = replay.raise(now + 80);
		write(&mut replay, file, &mut disk);
		assert_eq!((take(&mut replay, 1, now + 60, now), File::decode(&disk, 9).unwrap().limit()), (Verdict::Accept, now + 80));
		// A crash 30 s later: the proof is at or below the floor.
		let mut crashed = restart(&mut disk, now + 30, 9);
		tick(&mut crashed, now + 30, &mut disk);
		assert_eq!(take(&mut crashed, 1, now + 60, now + 30), Verdict::Refuse(Refusal::Floor));
	}

	// A write that is reported failed may be on disk. The limit in use is then the lower of the two that may be there, and the timer goes on from it.
	#[test]
	fn a_limit_write_that_failed_is_safe_whether_it_landed_or_not() {
		for landed in [false, true] {
			let (mut replay, now, mut disk) = (started(TIME, 9), TIME, Vec::new());
			tick(&mut replay, now, &mut disk);
			assert_eq!(take(&mut replay, 1, now + 40, now), Verdict::Raise(now + 60));
			let file = replay.raise(now + 60).unwrap();
			if landed {disk = encoded(&file)}
			replay.failed();
			assert_eq!((replay.limit(), replay.disk(), replay.writing()), (now + 20, now + 60, false));
			// The proof is still above the limit in use. With a write that works it is accepted, and after a crash it is refused.
			assert_eq!(take(&mut replay, 1, now + 40, now), Verdict::Raise(now + 60));
			let file = replay.raise(now + 60);
			write(&mut replay, file, &mut disk);
			assert_eq!((take(&mut replay, 1, now + 40, now), replay.limit(), replay.disk()), (Verdict::Accept, now + 60, now + 60));
			let mut crashed = restart(&mut disk, now + 1, 9);
			assert_eq!(take(&mut crashed, 1, now + 40, now + 1), Verdict::Refuse(Refusal::Floor));
		}
	}

	// Rule 6: "The node keeps the written limit at least 10 s and at most 20 s above the base: whenever the limit is less than 10 s above the base, it writes a limit 20 s above the base."
	#[test]
	fn the_limit_follows_the_clock_and_the_highest_accepted_timestamp() {
		let wanted = |replay: &mut Replay, now: u64| {
			let limit = replay.timer(now).map(|file| file.limit());
			replay.failed();
			limit
		};
		// The base is the clock alone until a proof is accepted.
		let mut replay = started(TIME + 20, 9);
		assert_eq!([TIME, TIME + 10, TIME + 11, TIME + 500].map(|now| wanted(&mut replay, now)), [None, None, Some(TIME + 31), Some(TIME + 520)]);
		// An accepted timestamp ahead of the clock is the base.
		let mut replay = started(TIME + 20, 9);
		assert_eq!((take(&mut replay, 1, TIME + 10, TIME), replay.timer(TIME)), (Verdict::Accept, None));
		assert_eq!(take(&mut replay, 2, TIME + 11, TIME), Verdict::Accept);
		let file = replay.timer(TIME).unwrap();
		assert_eq!((file.limit(), file.floor()), (TIME + 31, TIME - 40));
		replay.written();
		assert_eq!((replay.timer(TIME), wanted(&mut replay, TIME + 22)), (None, Some(TIME + 42)));
		assert_eq!(Replay::bare(0, u64::MAX - 5, u64::MAX - 5, 9).timer(u64::MAX).map(|file| file.limit()), Some(u64::MAX));
	}

	// "An honest proof carries about the current time and is below the limit, so it never waits for a write." A quiet node: proofs 30 s apart, the caller's timer runs once a second.
	#[test]
	fn an_honest_proof_on_a_quiet_node_never_waits_for_a_write() {
		let (mut replay, mut disk, mut writes) = (started(TIME, 16), Vec::new(), 0);
		for now in TIME..TIME + 1500 {
			if let Some(file) = replay.timer(now) {
				assert!((now + 10..=now + 20).contains(&file.limit()));
				write(&mut replay, Some(file), &mut disk);
				writes += 1;
			}
			assert!((now + 10..=now + 20).contains(&replay.limit()), "the limit is {} s above the clock", replay.limit() - now);
			if now % 30 == 0 {assert_eq!(take(&mut replay, (now / 30 % 250) as u8, now, now), Verdict::Accept)}
		}
		// "About every 10 s while the node runs": a caller that asks once a second writes every 11 s.
		assert!((130..=140).contains(&writes), "{writes} writes in 1500 s");
	}

	// Rule 7: "The floor is never used as if it were an accepted timestamp. Without this rule a node that crashes and restarts in a loop would raise its floor by 20 s per restart with no proof and no clock fault."
	#[test]
	fn a_crash_loop_does_not_raise_the_floor() {
		let (now, mut disk) = (TIME, Vec::new());
		let mut replay = restart(&mut disk, now, 16);
		for _ in 0..100 {
			// What a node does at start: its timer runs. Then it is killed. No proof was accepted and the clock did not move.
			tick(&mut replay, now, &mut disk);
			replay = restart(&mut disk, now, 16);
			assert_eq!(replay.floor(), now + WINDOW);
		}
		// The same with a clock that moves a second per crash, for long enough to pass the first floor: the floor stays within the step of the clock.
		for now in TIME..TIME + 600 {
			tick(&mut replay, now, &mut disk);
			replay = restart(&mut disk, now, 16);
			assert!(replay.floor() <= (now + STEP).max(TIME + WINDOW), "the floor is {} s ahead of the clock", replay.floor() - now);
		}
		let now = TIME + 600;
		assert_eq!((take(&mut replay, 1, now + 20, now + 20), take(&mut replay, 2, now + 60, now + 60)), (Verdict::Raise(now + 40), Verdict::Raise(now + 80)));
	}

	// The rows of the table of "The replay file".
	#[test]
	fn every_start_keeps_what_was_accepted_refused() {
		let (mut replay, mut disk) = (started(TIME + 20, 9), Vec::new());
		disk.clone_from(&encoded(&File {floor: replay.floor(), limit: replay.limit(), entries: None}));
		for (fill, timestamp) in [(1, TIME + 1), (2, TIME + 5), (3, TIME + 20)] {assert_eq!(take(&mut replay, fill, timestamp, TIME), Verdict::Accept)}
		let stopped = encoded(&replay.stop());
		assert_eq!(File::decode(&stopped, 9).map(|file| (file.clean(), file.len())), Ok((true, 3)));
		// A clean stop: all of it is back once the file is written again without its mark, and "no refusal because of the restart". That file has the limit the clock asks for already, so the first proof after the start does not wait for a second write.
		let Started::Clean(pending) = Replay::start(File::decode(&stopped, 9).ok(), TIME + 9, 9) else {panic!("a clean start")};
		let unmarked = pending.file();
		assert_eq!((unmarked.floor(), unmarked.limit(), unmarked.clean()), (TIME - 40, TIME + 29, false));
		let mut clean = pending.written();
		assert_eq!((clean.floor(), clean.limit(), clean.disk(), clean.len(), clean.timer(TIME + 9)), (TIME - 40, TIME + 29, TIME + 29, 3, None));
		assert_eq!([1, 2, 3].map(|fill| take(&mut clean, fill, TIME + 19, TIME + 9)), [Verdict::Refuse(Refusal::Seen); 3]);
		assert_eq!(take(&mut clean, 4, TIME + 9, TIME + 9), Verdict::Accept);
		// A start long after the stop: the same, with the limit where the clock is.
		let Started::Clean(late) = Replay::start(File::decode(&stopped, 9).ok(), TIME + 400, 9) else {panic!("a clean start")};
		assert_eq!((late.file().limit(), take(&mut late.written(), 4, TIME + 400, TIME + 400)), (TIME + 420, Verdict::Accept));
		// A clean start that is killed before that write: the file on disk is still the clean one, and the next start reads the same cache.
		let Started::Clean(killed) = Replay::start(File::decode(&stopped, 9).ok(), TIME + 9, 9) else {panic!("a clean start")};
		drop(killed);
		let Started::Clean(pending) = Replay::start(File::decode(&stopped, 9).ok(), TIME + 10, 9) else {panic!("a clean start")};
		let mut again = pending.written();
		assert_eq!([(1, TIME + 1), (2, TIME + 5), (3, TIME + 20)].map(|(fill, timestamp)| take(&mut again, fill, timestamp, TIME + 10)), [Verdict::Refuse(Refusal::Seen); 3]);
		// The file could not be written again without its mark: "the row below applies". The cache is forgotten, the floor is the written limit, and nothing has been accepted yet.
		let Started::Clean(pending) = Replay::start(File::decode(&stopped, 9).ok(), TIME + 9, 9) else {panic!("a clean start")};
		let Failed::Usable(mut forgot) = pending.failed() else {panic!("a clean start whose write failed gives a memory")};
		assert_eq!((forgot.floor(), forgot.limit(), forgot.disk(), forgot.len()), (TIME + 20, TIME + 20, TIME + 29, 0));
		assert_eq!([(1, TIME + 1), (2, TIME + 5), (3, TIME + 20)].map(|(fill, timestamp)| take(&mut forgot, fill, timestamp, TIME + 9)), [Verdict::Refuse(Refusal::Floor); 3]);
		// A crash: "The written limit. Every proof accepted before had a timestamp at or below it." The limit is unchanged. A client with a right clock is refused until the clock passes the floor.
		let Started::Unclean(mut crashed) = Replay::start(File::decode(&disk, 9).ok(), TIME + 9, 9) else {panic!("an unclean start")};
		assert_eq!((crashed.floor(), crashed.limit(), crashed.disk(), crashed.len(), crashed.timer(TIME + 9)), (TIME + 20, TIME + 20, TIME + 20, 0, None));
		assert_eq!([(1, TIME + 1), (2, TIME + 5), (3, TIME + 20)].map(|(fill, timestamp)| take(&mut crashed, fill, timestamp, TIME + 9)), [Verdict::Refuse(Refusal::Floor); 3]);
		assert_eq!((take(&mut crashed, 6, TIME + 9, TIME + 9), take(&mut crashed, 6, TIME + 21, TIME + 21)), (Verdict::Refuse(Refusal::Floor), Verdict::Raise(TIME + 41)));
		// A crash and a start much later, where the timer has run before the first proof, as the caller must have it: no wait.
		let mut late = restart(&mut disk.clone(), TIME + 400, 9);
		assert_eq!(take(&mut late, 6, TIME + 400, TIME + 400), Verdict::Raise(TIME + 420));
		tick(&mut late, TIME + 400, &mut disk.clone());
		assert_eq!(take(&mut late, 6, TIME + 400, TIME + 400), Verdict::Accept);
		// No file, or one that cannot be used: the floor and the limit are the clock plus `W`, and "every proof is refused for `W`".
		assert!(File::decode(&stopped[..stopped.len() - 1], 9).is_err());
		let Started::NoFile(pending) = Replay::start(None, TIME + 9, 9) else {panic!("a start without a file")};
		assert_eq!((pending.file().floor(), pending.file().limit(), pending.file().clean()), (TIME + 69, TIME + 69, false));
		let mut lost = pending.written();
		assert_eq!([TIME + 1, TIME + 20, TIME + 69].map(|timestamp| take(&mut lost, 1, timestamp, TIME + 9)), [Verdict::Refuse(Refusal::Floor); 3]);
		assert_eq!(take(&mut lost, 1, TIME + 70, TIME + 70), Verdict::Raise(TIME + 90));
	}

	// The three writes a `Pending` asks for, each reported failed, each with the file on disk all the same and without it. Nothing that was accepted before or after is accepted again, whatever a later crash finds.
	#[test]
	fn a_start_or_a_reset_whose_write_failed_is_safe_whether_it_landed_or_not() {
		for landed in [false, true] {
			// A clean start. The memory that comes back has forgotten the cache and has the clean file's limit as its floor: the one proof it can take needs a limit write first.
			let (mut replay, mut disk) = (started(TIME + 20, 9), Vec::new());
			assert_eq!(take(&mut replay, 1, TIME + 20, TIME), Verdict::Accept);
			disk.clone_from(&encoded(&replay.stop()));
			let Started::Clean(pending) = Replay::start(File::decode(&disk, 9).ok(), TIME + 9, 9) else {panic!("a clean start")};
			if landed {disk = encoded(&pending.file())}
			let Failed::Usable(mut replay) = pending.failed() else {panic!("a clean start whose write failed gives a memory")};
			assert_eq!((take(&mut replay, 1, TIME + 20, TIME + 9), take(&mut replay, 2, TIME + 20, TIME + 9), take(&mut replay, 2, TIME + 21, TIME + 9)), (Verdict::Refuse(Refusal::Floor), Verdict::Refuse(Refusal::Floor), Verdict::Raise(TIME + 41)));
			let mut crashed = restart(&mut disk.clone(), TIME + 10, 9);
			assert!(matches!(take(&mut crashed, 1, TIME + 20, TIME + 10), Verdict::Refuse(_)));
			let file = replay.raise(TIME + 41);
			write(&mut replay, file, &mut disk);
			assert_eq!(take(&mut replay, 2, TIME + 21, TIME + 9), Verdict::Accept);
			let mut crashed = restart(&mut disk, TIME + 10, 9);
			assert_eq!([(1, TIME + 20), (2, TIME + 21)].map(|(fill, timestamp)| take(&mut crashed, fill, timestamp, TIME + 10)), [Verdict::Refuse(Refusal::Floor); 2]);
			// A start without a file. Nothing is accepted before a write that is known to be on disk.
			let (Started::NoFile(pending), mut disk) = (Replay::start(None, TIME, 9), Vec::new()) else {panic!("a start without a file")};
			if landed {disk = encoded(&pending.file())}
			let Failed::Usable(mut replay) = pending.failed() else {panic!("a start without a file whose write failed gives a memory")};
			assert_eq!((take(&mut replay, 1, TIME + 60, TIME + 60), take(&mut replay, 1, TIME + 61, TIME + 61)), (Verdict::Refuse(Refusal::Floor), Verdict::Raise(TIME + 81)));
			let file = replay.raise(TIME + 81);
			write(&mut replay, file, &mut disk);
			assert_eq!(take(&mut replay, 1, TIME + 61, TIME + 61), Verdict::Accept);
			assert_eq!(take(&mut restart(&mut disk, TIME + 62, 9), 1, TIME + 61, TIME + 62), Verdict::Refuse(Refusal::Floor));
			// A reset, after a clock fault that took the limit a day up with no proof accepted there. No memory comes back: the old floor and limit are written again first.
			let (mut replay, mut disk, now) = (started(TIME, 9), Vec::new(), TIME + 200);
			for second in TIME..TIME + 100 {tick(&mut replay, second, &mut disk)}
			let file = replay.raise(TIME + 86_500);
			write(&mut replay, file, &mut disk);
			let old = (replay.floor(), replay.limit());
			let pending = replay.reset(now);
			if landed {disk = encoded(&pending.file())}
			let Failed::Restore(pending) = pending.failed() else {panic!("a reset whose write failed gave a memory")};
			assert_eq!((pending.file().floor(), pending.file().limit(), pending.file().clean()), (old.0, old.1, false));
			// A crash at this moment finds the old file or the reset, and either floor is one the node can start from.
			assert_eq!(restart(&mut disk.clone(), now, 9).floor(), if landed {now + 60} else {old.1});
			// That write fails as well, and lands or does not: the same file is asked for again, as often as it takes.
			let Failed::Restore(pending) = pending.failed() else {panic!("a reset that is not undone gave a memory")};
			let Failed::Restore(pending) = pending.failed() else {panic!("a reset that is not undone gave a memory")};
			assert_eq!((pending.file().floor(), pending.file().limit()), old);
			disk = encoded(&pending.file());
			let mut replay = pending.written();
			assert_eq!((replay.floor(), replay.limit(), replay.disk(), replay.writing()), (old.0, old.1, old.1, false));
			// The node runs on for an hour and accepts a proof. Then it crashes, and the same proof is refused.
			let later = now + 3_600;
			for second in now..=later {tick(&mut replay, second, &mut disk)}
			assert_eq!(take(&mut replay, 7, later, later), Verdict::Accept);
			assert!(File::decode(&disk, 9).unwrap().limit() >= later);
			let mut crashed = restart(&mut disk, later + 1, 9);
			tick(&mut crashed, later + 1, &mut disk);
			assert_eq!(take(&mut crashed, 7, later, later + 1), Verdict::Refuse(Refusal::Floor));
		}
	}

	// A file is not trusted beyond its hash and its rules: a floor above its limit holds, and an entry that is there twice is kept once, with its later timestamp.
	#[test]
	fn a_file_that_does_not_add_up_is_read_on_the_safe_side() {
		let file = File {floor: TIME, limit: TIME + 30, entries: Some(vec![(Kind::Stream, [1; 32], TIME + 30), (Kind::Stream, [1; 32], TIME + 9), (Kind::Stream, [2; 32], TIME + 2), (Kind::Stream, [2; 32], TIME + 3)])};
		let Started::Clean(pending) = Replay::start(Some(file), TIME, 1) else {panic!("a clean start")};
		let mut replay = pending.written();
		assert_eq!((replay.limit(), replay.len(), replay.stop().entries.unwrap()), (TIME + 30, 2, vec![(Kind::Stream, [2; 32], TIME + 3), (Kind::Stream, [1; 32], TIME + 30)]));
		// More entries than the cache may hold: nothing is dropped, and nothing new is accepted until they have left.
		assert_eq!(take(&mut replay, 3, TIME + 4, TIME), Verdict::Refuse(Refusal::Full));
		let Started::Unclean(replay) = Replay::start(Some(File {floor: TIME + 50, limit: TIME, entries: None}), TIME, 9) else {panic!("an unclean start")};
		assert_eq!((replay.floor(), replay.limit()), (TIME + 50, TIME));
		let Started::Clean(pending) = Replay::start(Some(File {floor: TIME + 50, limit: TIME, entries: Some(Vec::new())}), TIME, 9) else {panic!("a clean start")};
		assert!(matches!(pending.failed(), Failed::Usable(replay) if replay.floor() == TIME + 50));
	}

	// "`veilway replay reset`": the cache is emptied, and the floor and the limit are the wall clock plus `W`, "also when that is lower than before". What was accepted above that floor is forgotten, which is the cost the command states.
	#[test]
	fn a_reset_ends_the_outage_and_a_crash_does_not_bring_it_back() {
		// A clock fault: the node's clock ran a day ahead, and proofs with those timestamps were accepted.
		let (mut replay, fault, mut disk) = (started(TIME + 20, 9), TIME + 86_400, Vec::new());
		assert_eq!(take(&mut replay, 1, fault, fault), Verdict::Raise(fault + 20));
		let file = replay.raise(fault + 20);
		write(&mut replay, file, &mut disk);
		assert_eq!((take(&mut replay, 1, fault, fault), take(&mut replay, 2, fault + 20, fault + 70)), (Verdict::Accept, Verdict::Accept));
		// The clock is right again, and the floor is ahead of it: honest proofs are refused. The timer lowers nothing: proofs up there were accepted, and one is still in the cache.
		let now = TIME + 100;
		assert_eq!((replay.floor(), take(&mut replay, 3, now, now)), (fault, Verdict::Refuse(Refusal::Floor)));
		tick(&mut replay, now, &mut disk);
		assert_eq!((replay.limit(), replay.timer(now)), (fault + 40, None));
		let pending = replay.reset(now);
		assert_eq!((pending.file().floor(), pending.file().limit(), pending.file().clean()), (now + 60, now + 60, false));
		disk = encoded(&pending.file());
		let mut replay = pending.written();
		assert_eq!((replay.floor(), replay.len(), replay.limit(), replay.disk(), replay.timer(now)), (now + 60, 0, now + 60, now + 60, None));
		assert_eq!(take(&mut replay, 3, now + 60, now + 60), Verdict::Refuse(Refusal::Floor));
		// 61 s later honest clients are in, with the limit written as rule 6 asks. Then the node is killed.
		tick(&mut replay, now + 61, &mut disk);
		assert_eq!((replay.limit(), take(&mut replay, 3, now + 61, now + 61)), (now + 81, Verdict::Accept));
		let mut crashed = restart(&mut disk, now + 62, 9);
		assert_eq!((crashed.floor(), take(&mut crashed, 3, now + 61, now + 62)), (now + 81, Verdict::Refuse(Refusal::Floor)));
		// The outage is not back: the clock passes the floor within the step.
		tick(&mut crashed, now + 82, &mut disk);
		assert_eq!(take(&mut crashed, 4, now + 82, now + 82), Verdict::Accept);
	}

	// One wrong reading of the clock by the timer, a day ahead, and no proof accepted at that time. Without more, the next crash would make that limit the floor and refuse everyone for a day. The node lowers the limit itself as soon as the clock is right again.
	#[test]
	fn a_limit_that_a_wrong_clock_raised_comes_back_down() {
		let (mut replay, mut disk) = (started(TIME, 9), Vec::new());
		for second in TIME..TIME + 100 {tick(&mut replay, second, &mut disk)}
		assert_eq!(take(&mut replay, 1, TIME + 99, TIME + 99), Verdict::Accept);
		tick(&mut replay, TIME + 100 + 86_400, &mut disk);
		assert_eq!((replay.limit(), File::decode(&disk, 9).unwrap().limit()), (TIME + 86_520, TIME + 86_520));
		// The clock is right a second later. The file that lowers the limit is 20 s above the latest of the floor, the cache and the clock, and the limit in use is down before the file is written.
		let now = TIME + 101;
		let file = replay.timer(now).unwrap();
		assert_eq!((file.limit(), replay.limit(), replay.disk(), replay.writing()), (now + 20, now + 20, TIME + 86_520, true));
		// That write fails without landing. The limit in use stays down, and the timer asks again, because the one on disk may still be up.
		replay.failed();
		assert_eq!((replay.limit(), replay.disk()), (now + 20, TIME + 86_520));
		tick(&mut replay, now, &mut disk);
		assert_eq!((replay.limit(), replay.disk(), File::decode(&disk, 9).unwrap().limit(), replay.timer(now)), (now + 20, now + 20, now + 20, None));
		// A crash 100 s later costs the ordinary 20 s at most, and what was accepted stays refused.
		for second in now..now + 100 {tick(&mut replay, second, &mut disk)}
		assert_eq!(take(&mut replay, 2, now + 99, now + 99), Verdict::Accept);
		let mut crashed = restart(&mut disk, now + 100, 9);
		assert!(crashed.floor() <= now + 100 + STEP);
		assert_eq!([(1, TIME + 99), (2, now + 99)].map(|(fill, timestamp)| take(&mut crashed, fill, timestamp, now + 100)), [Verdict::Refuse(Refusal::Window), Verdict::Refuse(Refusal::Floor)]);
		// The limit of an honest client whose clock is a minute fast is `W` plus 20 s ahead and stays: that is no fault.
		let mut replay = started(TIME, 9);
		assert_eq!(take(&mut replay, 1, TIME + 60, TIME), Verdict::Raise(TIME + 80));
		let file = replay.raise(TIME + 80);
		write(&mut replay, file, &mut disk);
		assert_eq!((take(&mut replay, 1, TIME + 60, TIME), replay.timer(TIME), replay.limit()), (Verdict::Accept, None, TIME + 80));
	}

	// With proofs accepted during the fault the limit comes down only as far as they allow: never below anything that was accepted, in the cache or already behind the floor.
	#[test]
	fn a_limit_never_comes_down_below_what_was_accepted() {
		let (mut replay, mut disk, fault) = (started(TIME, 9), Vec::new(), TIME + 86_400);
		// During the fault the clock runs on for five minutes. One proof is accepted early and has left the cache by the end, one is accepted late and is still in it.
		for second in fault..fault + 300 {
			tick(&mut replay, second, &mut disk);
			if second == fault + 5 || second == fault + 290 {assert_eq!(take(&mut replay, (second % 250) as u8, second, second), Verdict::Accept)}
		}
		assert_eq!((replay.expire(fault + 300), replay.floor(), replay.len(), replay.limit()), (0, fault + 5, 1, fault + 317));
		// The clock is right again. The limit comes down to 20 s above the proof that is in the cache, which is 7 s lower, and no further.
		let now = TIME + 400;
		tick(&mut replay, now, &mut disk);
		assert_eq!((replay.limit(), replay.disk(), replay.timer(now)), (fault + 310, fault + 310, None));
		let mut crashed = restart(&mut disk, now + 1, 9);
		assert_eq!((crashed.floor(), take(&mut crashed, ((fault + 290) % 250) as u8, fault + 290, fault + 290)), (fault + 310, Verdict::Refuse(Refusal::Floor)));
		// After an unclean start the old limit is the floor, and the limit does not come down below a floor either: only a reset does that.
		assert_eq!(crashed.timer(now + 1), None);
	}

	// One proof after a pause does not pay for a whole cache: at most 64 entries leave per call, and the ones that stay refuse nothing they should not.
	#[test]
	fn entries_leave_a_few_at_a_time() {
		let mut replay = started(TIME + 20, 500);
		for index in 0..200u8 {assert_eq!(take(&mut replay, index, TIME + u64::from(index % 20), TIME), Verdict::Accept)}
		let later = TIME + 1000;
		assert!(replay.raise(later + 20).is_some());
		replay.written();
		assert_eq!((take(&mut replay, 250, later, later), replay.len()), (Verdict::Accept, 200 - EVICTIONS + 1));
		// A proof that was accepted is refused whether or not its entry has left yet.
		for index in 0..200u8 {assert!(matches!(replay.accept(Kind::Stream, &[index; 32], TIME + u64::from(index % 20), TIME + 60, || true), Verdict::Refuse(_)))}
		assert_eq!((replay.len(), replay.expire(later), replay.expire(later), replay.expire(later), replay.expire(later)), (200 - EVICTIONS + 1, EVICTIONS, EVICTIONS, 200 - 3 * EVICTIONS, 0));
		assert_eq!((replay.len(), replay.floor()), (1, TIME + 19));
	}

	#[test]
	fn a_cache_is_not_printed() {
		let mut replay = started(TIME + 20, 9);
		take(&mut replay, 0xab, TIME, TIME);
		assert_eq!(format!("{replay:?}"), format!("Replay(floor {}, limit {}, 1 entries)", TIME - 40, TIME + 20));
		assert_eq!((format!("{:?}", replay.stop()), format!("{:?}", replay.raise(TIME + 21).unwrap())), (format!("File(floor {}, limit {}, 1 entries)", TIME - 40, TIME + 20), format!("File(floor {}, limit {}, no clean mark)", TIME - 40, TIME + 21)));
		let pending = replay.reset(TIME);
		assert_eq!(format!("{pending:?}"), format!("Pending(Replay(floor {}, limit {}, 0 entries))", TIME + 60, TIME + 60));
		assert_eq!(format!("{:?}", pending.failed()), format!("Restore(Pending(Replay(floor {}, limit {}, 1 entries)))", TIME - 40, TIME + 20));
	}
}
