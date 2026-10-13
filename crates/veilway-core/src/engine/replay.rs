//! The replay memory of the node as it runs: the file, its lock and its one writer around the rule in `veilway_proto::replay` (transports page, "The replay rule", "Writing the replay file", "The replay file" and "When the floor is ahead of the clock").
//! The rule itself is that crate's. What is here is what it leaves to its caller: the disk, the clock, and saying loudly when honest clients are refused.
//! One memory serves the process, from the first config that has an obfuscated transport until the node stops, so a reload does not empty it.
//! No packet ever waits for the disk: the packet path takes the memory for as long as the rule takes to answer, and every write is made by the one task of `run`.
use anyhow::{anyhow, bail};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::{oneshot, watch, Notify};
use tokio::time::MissedTickBehavior;
use veilway_proto::replay::{self as rule, Failed, Pending, Replay, Started, STEP, WINDOW, WRITE_DEADLINE};

/// "A caller asks about once a second": how often the node's timer looks at the limit and lets entries leave the cache.
const TIMER_EVERY: Duration = Duration::from_secs(1);
/// "Logged at error, at most once a minute": how far apart the log lines of a state that lasts are.
const SAY_AGAIN: Duration = Duration::from_secs(60);
/// How many times `Replay::expire` is called in one run of the timer, with the memory held: 64 entries each, so a cache that empties after a clock step takes a few seconds and holds no packet up for long.
const EXPIRE_ROUNDS: usize = 64;
/// How long a clean stop waits for the file with the cache. A disk that hangs leaves the file as a kill would, which is safe.
pub const LAST_WRITE: Duration = Duration::from_secs(5);
/// How long a reset waits for its file before it says that its fate is not known.
const RESET_WAIT: Duration = Duration::from_secs(10);

/// The node's clock as the rule reads it: Unix seconds. A clock before 1970 is 0, which refuses every proof.
pub fn seconds(now: OffsetDateTime) -> u64 {now.unix_timestamp().max(0) as u64}

/// The replay memory at one moment, for the control API, the log and tests. No key of the cache is in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayStatus {
	/// False while no proof is taken at all: a reset whose file is not known to be on disk, or a node that is stopping.
	pub ready: bool,
	pub clock: u64,
	pub floor: u64,
	/// The limit proofs are judged by.
	pub limit: u64,
	/// The highest limit that may be on disk, which an unclean start would take as its floor.
	pub disk: u64,
	pub entries: usize,
	pub capacity: usize,
	/// Whether the floor is ahead of the clock in a way no start explains: further than the window and the step, or risen while the node ran. Every honest proof is refused until the clock passes it or the operator resets.
	pub floor_ahead: bool,
	/// How many seconds the floor is ahead of the clock, whatever the cause: for that long every proof with a right clock is refused. After a start or a reset it is at most the window and the step, and it is no fault.
	pub wait: u64,
	/// Proofs refused at the floor while `floor_ahead` held.
	pub refused_floor_ahead: u64,
	pub writes: u64,
	pub write_failures: u64,
	/// Writes that ran past the deadline of 2 s.
	pub slow_writes: u64,
	/// How often the node brought its own limit down after a clock that had been ahead (rule 9).
	pub lowered: u64,
	pub resets: u64,
}

/// What a reset did, see `Guard::reset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reset {
	/// The cache is empty and the floor and the limit are this value, on disk.
	Done(u64),
	/// The file of the reset could not be written, so it may or may not be on disk. The node accepts no proof until it has written the old floor and limit back, and the reset has to be asked for again.
	Unwritten,
	/// The write of the reset has not ended yet, and the reset is in force when it does. It must not be asked for again: `ReplayStatus::resets` grows by one when it has landed, and `ready` says whether proofs are taken.
	Writing,
	/// Another reset has not reached the disk yet, or the node is stopping.
	Busy,
}

enum Memory {
	Ready(Replay),
	/// A file must be on disk before any proof is taken. The task of `run` holds it.
	Unready,
	Stopped,
}

#[derive(Default)]
struct Counters {refused_floor_ahead: AtomicU64, writes: AtomicU64, write_failures: AtomicU64, slow_writes: AtomicU64, lowered: AtomicU64, resets: AtomicU64}

/// The replay memory of a node with its file.
pub struct Guard {
	path: PathBuf,
	capacity: usize,
	/// The lock file, held for as long as the node may write the replay file. Every write holds it too, so it is given back only when the last write has ended.
	lock: Mutex<Option<Arc<File>>>,
	memory: Mutex<Memory>,
	/// The highest limit a proof asked for since the timer last ran, 0 for none.
	wanted: AtomicU64,
	wake: Notify,
	resets: Mutex<Option<oneshot::Sender<Reset>>>,
	ahead: AtomicBool,
	/// The floor the last start or reset took. While the floor is still that one and no further ahead of the clock than a start can put it, it is what a start costs and no fault.
	began: AtomicU64,
	/// Counts the writes that have ended, well or not, for whoever holds a proof back until the limit it asked for is on disk.
	ended: watch::Sender<u64>,
	/// When a write that ran past its deadline was last logged.
	slow: Mutex<Option<Instant>>,
	/// The floor, the limit, the highest limit on disk and the entries as the timer last saw them, for a status while the memory is not ready.
	seen: Mutex<(u64, u64, u64, usize)>,
	counters: Counters,
}

/// The file next to `path` with `suffix` behind its name.
fn beside(path: &Path, suffix: &str) -> PathBuf {
	let mut name = path.as_os_str().to_owned();
	name.push(suffix);
	PathBuf::from(name)
}

/// Puts a replay file in the place of the one at `path`: "Every write goes to a temporary file in the same directory, is synced, and is renamed over the old file, with mode 600." The directory is synced after that, so a limit that was answered for is still there after a power loss.
fn write(path: &Path, file: &rule::File) -> io::Result<()> {
	let (mut bytes, tmp) = (Vec::new(), beside(path, ".tmp"));
	file.encode(&mut bytes).map_err(io::Error::other)?;
	// What a write that was cut short left behind may have any mode, and `create_new` never follows a link somebody put in its place.
	let _ = fs::remove_file(&tmp);
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
	let mut out = options.open(&tmp)?;
	out.write_all(&bytes)?;
	out.sync_all()?;
	fs::rename(&tmp, path)?;
	#[cfg(unix)]
	File::open(path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
	Ok(())
}

/// What stands at the path of a replay file.
#[derive(Debug)]
pub enum Found {
	/// Nothing. The node then refuses every proof for the window after its start.
	Absent,
	/// Something that is no regular file. The node does not start an obfuscated transport on it.
	Alone(String),
	/// A file that cannot be used, and why. The node moves it aside and starts as if there were none.
	Bad(String),
	Good(rule::File),
}

/// Reads the replay file at `path` and changes nothing. `capacity` is the configured cache size, which bounds what is read: "The entry count is at most the configured cache size."
pub fn inspect(path: &Path, capacity: usize) -> Found {
	match fs::symlink_metadata(path) {
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Found::Absent,
		Err(e) => return Found::Alone(format!("it cannot be looked at ({})", e.kind())),
		Ok(meta) if !meta.is_file() => return Found::Alone("it is not a regular file".to_string()),
		Ok(_) => {}
	}
	let read = || -> anyhow::Result<rule::File> {
		let (file, mut bytes, most) = (File::open(path).map_err(|e| anyhow!("it cannot be opened ({})", e.kind()))?, Vec::new(), 68 + capacity as u64 * 41);
		// Whoever can write the file can lower its floor, and with it open replay for everything the node accepted.
		#[cfg(unix)]
		anyhow::ensure!(std::os::unix::fs::MetadataExt::mode(&file.metadata()?) & 0o022 == 0, "group or others can write it");
		anyhow::ensure!(file.take(most + 1).read_to_end(&mut bytes).map_err(|e| anyhow!("it cannot be read ({})", e.kind()))? as u64 <= most, "it is larger than a replay file of {capacity} entries");
		Ok(rule::File::decode(&bytes, capacity)?)
	};
	read().map_or_else(|e| Found::Bad(format!("{e:#}")), Found::Good)
}

/// Whether a node holds the lock of the replay file at `path` right now. None when that cannot be found out.
pub fn held(path: &Path) -> Option<bool> {
	match File::open(beside(path, ".lock")) {
		Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
		Err(_) => None,
		Ok(lock) => match lock.try_lock() {
			Ok(()) => Some(false),
			Err(TryLockError::WouldBlock) => Some(true),
			Err(TryLockError::Error(_)) => None,
		},
	}
}

impl Guard {
	fn memory(&self) -> MutexGuard<'_, Memory> {self.memory.lock().unwrap_or_else(|e| e.into_inner())}

	/// Takes the replay file at `path` for this node: the lock, what the file says, and every write the rule wants before a listener takes its first proof. `now` is the wall clock in Unix seconds and `capacity` the configured cache size.
	/// It blocks on the disk, so it runs off the runtime's own threads. An error is "No writable path for the file, or the lock is held": the node then starts no obfuscated transport.
	/// The lock is on a file of its own, `<path>.lock`: the replay file is replaced by a rename at every write, and a lock on it would stay with the file that was replaced.
	pub fn open(path: &Path, capacity: usize, now: u64) -> anyhow::Result<Guard> {
		let shown = path.display();
		// Looked at before anything is made next to it: a path that is no place for a replay file gets no lock file either.
		if let Found::Alone(why) = inspect(path, capacity) {bail!("replay file {shown}: {why}. The node writes its replay file there and nothing else may stand at the path")}
		let mut options = OpenOptions::new();
		options.write(true).create(true).truncate(false);
		// A link in the place of the lock file is not followed, and a pipe there is not waited for: the lock is on a regular file next to the replay file and on nothing else.
		#[cfg(unix)]
		std::os::unix::fs::OpenOptionsExt::custom_flags(std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600), libc::O_NOFOLLOW | libc::O_NONBLOCK);
		let lock = options.open(beside(path, ".lock")).and_then(|lock| if lock.metadata()?.is_file() {Ok(lock)} else {Err(io::Error::other("it is not a regular file"))}).map_err(|e| anyhow!("replay file {shown}: its lock file cannot be made next to it ({e}). An obfuscated transport needs a replay file in a directory the node can write, with nothing but the node's own lock file at that name: name a path with --replay"))?;
		// Tried a few times: `held` takes the lock for a moment to find out whether a node has it, and a node that has only just gone away gives it back when its last write has ended.
		let mut tries = 10;
		loop {
			match lock.try_lock() {
				Ok(()) => break,
				Err(TryLockError::WouldBlock) if tries > 1 => tries -= 1,
				Err(TryLockError::WouldBlock) => bail!("replay file {shown}: another node holds its lock. Two nodes never share a replay file: a proof one of them accepted could be used once more on the other"),
				Err(TryLockError::Error(e)) => bail!("replay file {shown}: its lock cannot be taken ({})", e.kind()),
			}
			std::thread::sleep(Duration::from_millis(20));
		}
		let (file, bad) = match inspect(path, capacity) {
			Found::Absent => (None, false),
			Found::Alone(why) => bail!("replay file {shown}: {why}. The node writes its replay file there and nothing else may stand at the path"),
			Found::Good(file) => (Some(file), false),
			// "An unusable file is renamed with `.bad` added, logged at error, and handled exactly as no replay file."
			Found::Bad(why) => {
				let aside = beside(path, ".bad");
				match fs::rename(path, &aside) {
					Ok(()) => tracing::error!("replay file {shown}: {why}. It is kept as {} and the node starts as it does without a replay file: every proof is refused for {WINDOW}s", aside.display()),
					Err(stuck) => bail!("replay file {shown}: {why}, and it could not be moved aside ({})", stuck.kind()),
				}
				(None, true)
			}
		};
		let mut replay = match Replay::start(file, now, capacity) {
			Started::Unclean(replay) => {
				tracing::info!("replay file {shown}: the node did not stop cleanly, so its cache is empty and proofs with a timestamp up to {} are refused, which is {}s from now", replay.floor(), replay.floor().saturating_sub(now));
				replay
			}
			Started::Clean(pending) => match write(path, &pending.file()) {
				Ok(()) => {
					let replay = pending.written();
					tracing::info!("replay file {shown}: read after a clean stop, {} proofs in the cache", replay.len());
					replay
				}
				Err(e) => {
					let Failed::Usable(replay) = pending.failed() else {bail!("replay file {shown}: it could not be written at start ({})", e.kind())};
					tracing::error!("replay file {shown}: it could not be written at start ({}), so the cache it held is forgotten and proofs with a timestamp up to {} are refused", e.kind(), replay.floor());
					replay
				}
			},
			Started::NoFile(pending) => match write(path, &pending.file()) {
				Ok(()) => {
					if !bad {tracing::warn!("replay file {shown}: there was none, so one is made and every proof is refused for {WINDOW}s. That is right for a node that never ran here. A replay file that was lost on a node whose clock is behind where it has been reopens replay for what the node accepted before")}
					pending.written()
				}
				Err(e) => {
					let Failed::Usable(replay) = pending.failed() else {bail!("replay file {shown}: it could not be written at start ({})", e.kind())};
					tracing::error!("replay file {shown}: it could not be written at start ({}), and there was none: no proof is accepted until a write goes through", e.kind());
					replay
				}
			},
		};
		// "After any start, the timer has run once and its file is written before a listener takes its first proof."
		let counters = Counters::default();
		if let Some(file) = replay.timer(now) {
			match write(path, &file) {
				Ok(()) => {
					replay.written();
					counters.writes.fetch_add(1, Ordering::Relaxed);
				}
				Err(e) => {
					replay.failed();
					counters.write_failures.fetch_add(1, Ordering::Relaxed);
					tracing::error!("replay file {shown}: its limit could not be written at start ({}), so no proof above {} is accepted until a write goes through", e.kind(), replay.limit());
				}
			}
		}
		let seen = (replay.floor(), replay.limit(), replay.disk(), replay.len());
		Ok(Guard {path: path.to_path_buf(), capacity, lock: Mutex::new(Some(Arc::new(lock))), ahead: AtomicBool::new(replay.floor().saturating_sub(now) > WINDOW + STEP), began: AtomicU64::new(replay.floor()), ended: watch::Sender::new(0), slow: Mutex::default(), memory: Mutex::new(Memory::Ready(replay)), wanted: AtomicU64::new(0), wake: Notify::new(), resets: Mutex::default(), seen: Mutex::new(seen), counters})
	}

	/// Whether a floor that is ahead of the clock is a fault and no start: it is further ahead than the window and the step, which is the most a start or a reset puts it, or it is not the floor the last start or reset took, so it rose while the node ran.
	fn fault(&self, floor: u64, clock: u64) -> bool {floor > clock && (floor - clock > WINDOW + STEP || floor != self.began.load(Ordering::Relaxed))}

	/// Changes whenever a write of the file has ended, well or not. Whoever keeps a proof that asked for a higher limit takes it to the rule again then.
	pub fn writes(&self) -> watch::Receiver<u64> {self.ended.subscribe()}

	/// What `run` does for a proof that asked for a higher limit, with a write that goes through at once: for a memory without a file, whose timer is its harness.
	#[doc(hidden)]
	pub fn serve(&self, clock: u64) {
		let wanted = self.wanted.swap(0, Ordering::Relaxed);
		self.with(|memory| {
			memory.expire(clock);
			if (wanted > 0).then(|| memory.raise(wanted)).flatten().or_else(|| memory.timer(clock)).is_some() {memory.written()}
		});
		self.ended.send_modify(|ended| *ended += 1);
	}

	/// A memory without a file, as one that started without a file `ahead` seconds ago and wrote every limit it wanted since. For the harness of a fuzz target and for tests that need no disk: a node never has one.
	#[doc(hidden)]
	pub fn unwritten(capacity: usize, now: u64) -> Guard {
		let Started::NoFile(pending) = Replay::start(None, now.saturating_sub(2 * WINDOW), capacity) else {unreachable!("a start without a file")};
		let mut replay = pending.written();
		if replay.timer(now).is_some() {replay.written()}
		Guard {path: PathBuf::new(), capacity, lock: Mutex::default(), began: AtomicU64::new(replay.floor()), ended: watch::Sender::new(0), slow: Mutex::default(), memory: Mutex::new(Memory::Ready(replay)), wanted: AtomicU64::new(0), wake: Notify::new(), resets: Mutex::default(), ahead: AtomicBool::new(false), seen: Mutex::default(), counters: Counters::default()}
	}

	/// The cache size the memory was started with.
	pub fn capacity(&self) -> usize {self.capacity}

	/// Takes one proof to the rule. None while no proof is taken at all. `f` runs with the memory held, so it does nothing but ask the rule and charge the caller's own limits.
	pub fn with<R>(&self, f: impl FnOnce(&mut Replay) -> R) -> Option<R> {if let Memory::Ready(replay) = &mut *self.memory() {Some(f(replay))} else {None}}

	/// `Verdict::Raise`: the limit a proof asked for. The write is the timer task's, which is woken for it, and nothing on the packet path waits for it: a listener keeps the proof and takes it to the rule again when `writes` says a write has ended.
	pub fn want(&self, limit: u64) {
		self.wanted.fetch_max(limit, Ordering::Relaxed);
		self.wake.notify_one();
	}

	/// Counts a proof that was refused at the floor while the floor is ahead of the clock: "counts every proof refused for that reason".
	pub fn refused_at_floor(&self) {
		if self.ahead.load(Ordering::Relaxed) {self.counters.refused_floor_ahead.fetch_add(1, Ordering::Relaxed);}
	}

	pub fn status(&self, clock: u64) -> ReplayStatus {
		let (ready, (floor, limit, disk, entries)) = match &*self.memory() {
			Memory::Ready(replay) => (true, (replay.floor(), replay.limit(), replay.disk(), replay.len())),
			_ => (false, *self.seen.lock().unwrap_or_else(|e| e.into_inner())),
		};
		let count = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
		ReplayStatus {ready, clock, floor, limit, disk, entries, capacity: self.capacity, floor_ahead: self.fault(floor, clock), wait: floor.saturating_sub(clock), refused_floor_ahead: count(&self.counters.refused_floor_ahead), writes: count(&self.counters.writes), write_failures: count(&self.counters.write_failures), slow_writes: count(&self.counters.slow_writes), lowered: count(&self.counters.lowered), resets: count(&self.counters.resets)}
	}

	/// Writes one file off the runtime's own threads and waits for the write to end, however long that takes: "A write that has only run past its deadline has not failed until then."
	async fn put(&self, file: rule::File) -> io::Result<()> {
		let Some(lock) = self.lock.lock().unwrap_or_else(|e| e.into_inner()).clone() else {return Err(io::Error::other("the node gave its replay file back"))};
		let path = self.path.clone();
		let mut writing = tokio::task::spawn_blocking(move || {
			let _held = lock;
			write(&path, &file)
		});
		let joined = match tokio::time::timeout(WRITE_DEADLINE, &mut writing).await {
			Ok(joined) => joined,
			Err(_) => {
				self.counters.slow_writes.fetch_add(1, Ordering::Relaxed);
				let said = self.slow.lock().unwrap_or_else(|e| e.into_inner()).replace(Instant::now());
				if said.is_none_or(|said| said.elapsed() >= SAY_AGAIN) {tracing::error!("replay file {}: a write has taken more than {}s and the node waits for it to end. Until it does the limit cannot rise, and once the clock has passed the limit no proof is accepted. Saying so once a minute while writes are this slow", self.path.display(), WRITE_DEADLINE.as_secs())}
				writing.await
			}
		};
		joined.unwrap_or_else(|e| Err(io::Error::other(e)))
	}

	/// The node's timer and its one writer, until the memory is stopped. About once a second, and at once when a proof asked for a higher limit or a reset was asked for:
	/// entries leave the cache, the limit follows the clock (rule 6) and comes down after a clock that was ahead (rule 9), and whatever file that takes is written before the next is made.
	pub async fn run(self: Arc<Self>, now: fn() -> OffsetDateTime) {
		let (mut tick, mut pending, mut answer) = (tokio::time::interval(TIMER_EVERY), None::<Pending>, None::<oneshot::Sender<Reset>>);
		tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
		let (mut said_ahead, mut said_failed, shown) = (None::<Instant>, None::<Instant>, self.path.display().to_string());
		loop {
			tokio::select! {
				_ = tick.tick() => {}
				_ = self.wake.notified() => {}
			}
			let clock = seconds(now());
			let mut asked = self.resets.lock().unwrap_or_else(|e| e.into_inner()).take();
			// What is written in this round: a file the memory waits for, or one the timer wants. `before` is the highest limit that may have been on disk when the timer made its file.
			let (file, before, reset) = {
				let mut memory = self.memory();
				let resetting = asked.is_some() && pending.is_none() && matches!(*memory, Memory::Ready(_));
				match (&mut *memory, &pending) {
					(Memory::Stopped, _) => {
						if let Some(asked) = asked.take() {let _ = asked.send(Reset::Busy);}
						return;
					}
					(Memory::Unready, None) => (None, 0, None),
					(_, Some(waiting)) => (Some(waiting.file()), 0, None),
					(slot, None) if resetting => {
						// "A file that is out is reported first": this task is the only writer and has none out here.
						let Memory::Ready(replay) = std::mem::replace(slot, Memory::Unready) else {unreachable!("the memory was ready")};
						*self.seen.lock().unwrap_or_else(|e| e.into_inner()) = (replay.floor(), replay.limit(), replay.disk(), replay.len());
						tracing::warn!("replay: reset at the operator's word. The cache of {} proofs is emptied and the floor and the limit go from {} and {} to {}: every proof is refused for {WINDOW}s, and a proof that was accepted with a timestamp above the new floor can be used once more", replay.len(), replay.floor(), replay.limit(), clock.saturating_add(WINDOW));
						let reset = replay.reset(clock);
						(Some(reset.file()), 0, Some(reset))
					}
					(Memory::Ready(replay), None) => {
						for _ in 0..EXPIRE_ROUNDS {if replay.expire(clock) == 0 {break}}
						// The floor a start or a reset took is no fault while it is no further ahead than they put it: the start said how long it lasts, and the reset is not the answer to it.
						let (wanted, before, ahead) = (self.wanted.swap(0, Ordering::Relaxed), replay.disk(), self.fault(replay.floor(), clock));
						let file = (wanted > 0).then(|| replay.raise(wanted)).flatten().or_else(|| replay.timer(clock));
						*self.seen.lock().unwrap_or_else(|e| e.into_inner()) = (replay.floor(), replay.limit(), replay.disk(), replay.len());
						// "Whenever the floor is ahead of the wall clock, the node logs at error, at most once a minute, with the distance. It logs at info when the state ends."
						if ahead && said_ahead.is_none_or(|said| said.elapsed() >= SAY_AGAIN) {
							said_ahead = Some(Instant::now());
							tracing::error!("replay: the floor is {}s ahead of the node's clock (floor {}, clock {clock}), which is more than a start leaves or not where the last start put it, so every proof is refused until the clock passes it. This follows a clock that ran ahead. `veilway replay reset` ends it at the price it names", replay.floor() - clock, replay.floor());
						}
						if !ahead && said_ahead.take().is_some() {tracing::info!("replay: the floor is no longer ahead of the node's clock (floor {}, clock {clock}), so proofs are accepted again", replay.floor())}
						self.ahead.store(ahead, Ordering::Relaxed);
						(file, before, None)
					}
				}
			};
			// A reset that is asked for while the memory waits for a file has to be asked for again.
			match (reset, asked) {
				(Some(reset), asked) => (pending, answer) = (Some(reset), asked),
				(None, Some(asked)) => drop(asked.send(Reset::Busy)),
				(None, None) => {}
			}
			let Some(file) = file else {continue};
			let (limit, written) = (file.limit(), self.put(file).await);
			match &written {
				Ok(()) => {
					self.counters.writes.fetch_add(1, Ordering::Relaxed);
					if said_failed.take().is_some() {tracing::info!("replay file {shown}: it is written again")}
				}
				// "The node accepts no proof once the clock has passed the limit in use, within about 20 s. Logged at error, at most once a minute, and counted."
				Err(e) => {
					let failed = self.counters.write_failures.fetch_add(1, Ordering::Relaxed) + 1;
					if said_failed.is_none_or(|said| said.elapsed() >= SAY_AGAIN) {
						said_failed = Some(Instant::now());
						tracing::error!("replay file {shown}: it could not be written ({e}), so the limit cannot rise and within about {STEP}s no proof is accepted. {failed} write(s) have failed since start. Trying again every second and saying so every minute");
					}
				}
			}
			let mut memory = self.memory();
			match (&mut *memory, pending.take()) {
				(Memory::Stopped, _) => return,
				(Memory::Ready(replay), None) => {
					if written.is_ok() {replay.written()} else {replay.failed()}
					// "It logs at info each time rule 9 brings the limit down."
					if written.is_ok() && limit < before {
						self.counters.lowered.fetch_add(1, Ordering::Relaxed);
						tracing::info!("replay: the limit on disk was {before}, more than {}s ahead of the node's clock, and is brought down to {limit}. A clock that ran ahead leaves this behind", WINDOW + STEP);
					}
				}
				(slot, Some(waiting)) if written.is_ok() => {
					let replay = waiting.written();
					// Whoever asked may have stopped waiting and been told that the write was still out. The reset is done all the same, and counted, which is what they were told to look at.
					if let Some(answer) = answer.take() {
						self.counters.resets.fetch_add(1, Ordering::Relaxed);
						// The floor a reset took is one the node chose, like the floor of a start.
						self.began.store(replay.floor(), Ordering::Relaxed);
						let _ = answer.send(Reset::Done(replay.floor()));
					} else {tracing::info!("replay file {shown}: the floor {} and the limit {} are on disk again, and proofs are taken again", replay.floor(), replay.limit())}
					*slot = Memory::Ready(replay);
				}
				// "If the write fails, the reset may or may not be on disk. The node then writes the old floor and limit again and accepts no proof until one of the two writes is known to be on disk. If that write fails too, it writes the same file again."
				(slot, Some(waiting)) => match waiting.failed() {
					Failed::Usable(replay) => *slot = Memory::Ready(replay),
					Failed::Restore(again) => {
						if let Some(answer) = answer.take() {let _ = answer.send(Reset::Unwritten);}
						pending = Some(again);
					}
				},
				(Memory::Unready, None) => {}
			}
			self.ended.send_modify(|ended| *ended += 1);
		}
	}

	/// `veilway replay reset`: the cache is emptied and the floor and the limit become the wall clock plus the window, and no proof is accepted until that is on disk. Nothing else of the node is touched, usage and quotas included.
	pub async fn reset(&self) -> Reset {
		let (ask, answer) = oneshot::channel();
		{
			let mut resets = self.resets.lock().unwrap_or_else(|e| e.into_inner());
			if resets.is_some() || !matches!(*self.memory(), Memory::Ready(_)) {return Reset::Busy}
			*resets = Some(ask);
		}
		self.wake.notify_one();
		match tokio::time::timeout(RESET_WAIT, answer).await {
			Ok(Ok(reset)) => reset,
			Ok(Err(_)) => Reset::Busy,
			// The write is still out and may land: whoever asked is told so, and not to ask again.
			Err(_) => Reset::Writing,
		}
	}

	/// A clean stop: from here no proof is taken, and the cache, the floor and the limit go to the file with the clean mark. Then the lock is given back.
	/// With a write still out, or a memory that waits for one, nothing is written: the file stays as a kill would leave it, which the next start reads as an unclean one.
	pub async fn stop(&self) {
		let (memory, lock) = (std::mem::replace(&mut *self.memory(), Memory::Stopped), self.lock.lock().unwrap_or_else(|e| e.into_inner()).take());
		self.wake.notify_one();
		let (Memory::Ready(replay), Some(lock)) = (memory, lock) else {return};
		if replay.writing() {return tracing::warn!("replay file {}: a write was still out when the node stopped, so the cache is not written and the next start is an unclean one", self.path.display())}
		let (path, file, entries) = (self.path.clone(), replay.stop(), replay.len());
		let written = tokio::time::timeout(LAST_WRITE, tokio::task::spawn_blocking(move || {
			let _held = lock;
			write(&path, &file)
		})).await;
		match written {
			Ok(Ok(Ok(()))) => tracing::info!("replay file {}: written with its cache of {entries} proofs for a clean start", self.path.display()),
			Ok(Ok(Err(e))) => tracing::error!("replay file {}: the cache could not be written at the stop ({}), so the next start is an unclean one", self.path.display(), e.kind()),
			_ => tracing::error!("replay file {}: the cache was not written within {}s of the stop, so the next start may be an unclean one", self.path.display(), LAST_WRITE.as_secs()),
		}
	}

	/// What a node that goes away without a clean stop leaves: no proof is taken any more, nothing is written, and the lock is given back once the write that is out has ended.
	pub fn abandon(&self) {
		*self.memory() = Memory::Stopped;
		self.lock.lock().unwrap_or_else(|e| e.into_inner()).take();
		self.wake.notify_one();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_proto::replay::{Kind, Refusal, Verdict};

	const TIME: u64 = 1_700_000_000;

	fn scratch(test: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-replay-{}-{test}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir.join("veilway-replay")
	}

	fn take(guard: &Guard, fill: u8, timestamp: u64, now: u64) -> Option<Verdict> {guard.with(|replay| replay.accept(Kind::Opening, &[fill; 32], timestamp, now, || true))}

	fn on_disk(path: &Path) -> rule::File {
		let Found::Good(file) = inspect(path, 1024) else {panic!("no usable replay file at {}", path.display())};
		file
	}

	#[test]
	fn a_first_start_makes_the_file_and_refuses_for_the_window() {
		let path = scratch("first");
		let guard = Guard::open(&path, 1024, TIME).unwrap();
		let file = on_disk(&path);
		assert_eq!((file.floor(), file.limit(), file.clean()), (TIME + WINDOW, TIME + WINDOW, false));
		#[cfg(unix)]
		assert_eq!(std::os::unix::fs::MetadataExt::mode(&fs::metadata(&path).unwrap()) & 0o777, 0o600);
		assert_eq!(take(&guard, 1, TIME, TIME), Some(Verdict::Refuse(Refusal::Floor)));
		assert_eq!(take(&guard, 1, TIME + WINDOW, TIME + WINDOW), Some(Verdict::Refuse(Refusal::Floor)));
		// The floor a start took is what the start costs: the status says how long it lasts and does not call it a fault, and a proof refused at it is not counted as one refused for a clock that ran ahead.
		let status = guard.status(TIME);
		assert_eq!((status.ready, status.floor, status.limit, status.disk, status.floor_ahead, status.wait, status.capacity), (true, TIME + WINDOW, TIME + WINDOW, TIME + WINDOW, false, WINDOW, 1024));
		guard.refused_at_floor();
		assert_eq!((guard.status(TIME + WINDOW).wait, guard.status(TIME).refused_floor_ahead), (0, 0));
		// The same floor is a fault for a clock that is further behind it than any start leaves it.
		assert!(guard.status(TIME - STEP - 1).floor_ahead);
	}

	// A path that is no place for a replay file gets no lock file next to it, and a link or anything else in the place of the lock file is not followed.
	#[test]
	fn a_path_that_is_refused_leaves_nothing_behind_and_the_lock_is_a_regular_file_of_the_node() {
		let (lock, before) = (Path::new("/dev/null.lock"), Path::new("/dev/null.lock").exists());
		let refused = Guard::open(Path::new("/dev/null"), 1024, TIME).err().expect("a node took /dev/null").to_string();
		assert!(refused.contains("not a regular file") && (before || !lock.exists()), "{refused}");
		// A replay path that is a link is no regular file either.
		let path = scratch("links");
		let real = path.parent().unwrap().join("real");
		Guard::open(&real, 1024, TIME).unwrap().abandon();
		std::os::unix::fs::symlink(&real, &path).unwrap();
		assert!(Guard::open(&path, 1024, TIME).is_err_and(|e| e.to_string().contains("not a regular file")) && !beside(&path, ".lock").exists());
		// A lock file that is a link to somebody else's file: the node does not lock that file, and does not start.
		let (other, victim) = (scratch("links-lock"), path.parent().unwrap().join("victim"));
		fs::write(&victim, b"keep").unwrap();
		std::os::unix::fs::symlink(&victim, beside(&other, ".lock")).unwrap();
		let refused = Guard::open(&other, 1024, TIME).err().expect("a node took a link for its lock file").to_string();
		assert!(refused.contains("lock file cannot be made") && fs::read(&victim).unwrap() == b"keep" && !other.exists(), "{refused}");
		fs::remove_file(beside(&other, ".lock")).unwrap();
		fs::create_dir(beside(&other, ".lock")).unwrap();
		assert!(Guard::open(&other, 1024, TIME).is_err() && !other.exists());
	}

	#[test]
	fn two_nodes_never_share_a_file_and_the_lock_goes_with_the_node() {
		let path = scratch("lock");
		let first = Guard::open(&path, 1024, TIME).unwrap();
		assert_eq!(held(&path), Some(true));
		let refused = Guard::open(&path, 1024, TIME).err().expect("a second node took the file").to_string();
		assert!(refused.contains("another node holds its lock"), "{refused}");
		first.abandon();
		assert_eq!((held(&path), first.with(|_| ()), first.status(TIME).ready), (Some(false), None, false));
		Guard::open(&path, 1024, TIME).unwrap();
	}

	#[test]
	fn a_path_the_node_cannot_write_is_an_error() {
		let path = scratch("unwritable");
		let nowhere = path.parent().unwrap().join("missing").join("veilway-replay");
		let refused = Guard::open(&nowhere, 1024, TIME).err().expect("a node started on a path it cannot write").to_string();
		assert!(refused.contains("lock file cannot be made") && refused.contains("--replay"), "{refused}");
		// Something that is no regular file is left as it is.
		fs::create_dir(&path).unwrap();
		let refused = Guard::open(&path, 1024, TIME).err().expect("a node took a directory for its replay file").to_string();
		assert!(refused.contains("not a regular file") && path.is_dir(), "{refused}");
	}

	#[test]
	fn a_file_that_cannot_be_used_is_moved_aside_and_is_never_empty_state() {
		for (case, bytes) in [("cut", &b"VWREPLAY\0\0\0\x01"[..]), ("other", &b"not a replay file at all, but long enough to be one of sixty-eight bytes"[..])] {
			let path = scratch(case);
			fs::write(&path, bytes).unwrap();
			let guard = Guard::open(&path, 1024, TIME).unwrap();
			assert_eq!(fs::read(beside(&path, ".bad")).unwrap(), bytes);
			// "An implementation must not start with an empty cache and no floor because it could not read the file."
			assert_eq!((guard.status(TIME).floor, take(&guard, 1, TIME, TIME)), (TIME + WINDOW, Some(Verdict::Refuse(Refusal::Floor))));
			assert_eq!(on_disk(&path).floor(), TIME + WINDOW);
		}
	}

	#[tokio::test]
	async fn a_clean_stop_keeps_the_cache_and_a_kill_keeps_the_limit() {
		let path = scratch("stops");
		let guard = Guard::open(&path, 1024, TIME - 100).unwrap();
		guard.with(|replay| {
			let file = replay.timer(TIME);
			assert!(file.is_some());
			write(&path, &file.unwrap()).unwrap();
			replay.written();
		});
		assert_eq!(take(&guard, 1, TIME, TIME), Some(Verdict::Accept));
		guard.stop().await;
		let file = on_disk(&path);
		assert_eq!((file.clean(), file.len(), file.limit(), held(&path)), (true, 1, TIME + STEP, Some(false)));
		assert_eq!(take(&guard, 2, TIME, TIME), None);
		// A clean start reads the cache, and its first file has no mark: a crash right after it must not make a stale cache look clean.
		let guard = Guard::open(&path, 1024, TIME + 5).unwrap();
		assert_eq!((on_disk(&path).clean(), take(&guard, 1, TIME, TIME + 5), take(&guard, 2, TIME + 5, TIME + 5)), (false, Some(Verdict::Refuse(Refusal::Seen)), Some(Verdict::Accept)));
		// A kill: nothing is written. The next start has an empty cache and the written limit for a floor, so both proofs are refused there.
		guard.abandon();
		let guard = Guard::open(&path, 1024, TIME + 6).unwrap();
		assert_eq!(guard.status(TIME + 6).floor, TIME + 5 + STEP);
		assert_eq!([(1, TIME), (2, TIME + 5)].map(|(fill, timestamp)| take(&guard, fill, timestamp, TIME + 6)), [Some(Verdict::Refuse(Refusal::Floor)); 2]);
		assert_eq!(take(&guard, 3, TIME + 5 + STEP + 1, TIME + 6), Some(Verdict::Raise(TIME + 5 + 2 * STEP + 1)));
	}

	// A directory where the temporary file goes makes every write fail, also for root.
	#[test]
	fn a_start_whose_first_write_fails_accepts_nothing_it_could_regret() {
		let path = scratch("first-write");
		fs::create_dir(beside(&path, ".tmp")).unwrap();
		// No file and no write: the floor and the limit are the clock plus the window, and every timestamp above the floor is above the limit.
		let guard = Guard::open(&path, 1024, TIME).unwrap();
		assert!(!path.exists());
		assert_eq!([TIME + WINDOW, TIME + WINDOW + 1].map(|timestamp| take(&guard, 1, timestamp, TIME + WINDOW)), [Some(Verdict::Refuse(Refusal::Floor)), Some(Verdict::Raise(TIME + WINDOW + 1 + STEP))]);
		guard.abandon();
		// After a clean stop: "If that write fails, the cache is forgotten and the floor becomes the clean file's limit."
		fs::remove_dir(beside(&path, ".tmp")).unwrap();
		let guard = Guard::open(&path, 1024, TIME).unwrap();
		guard.with(|replay| {
			write(&path, &replay.raise(TIME + 200).unwrap()).unwrap();
			replay.written();
		});
		assert_eq!(take(&guard, 1, TIME + 150, TIME + 100), Some(Verdict::Accept));
		tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(guard.stop());
		fs::create_dir(beside(&path, ".tmp")).unwrap();
		let guard = Guard::open(&path, 1024, TIME + 100).unwrap();
		assert_eq!((guard.status(TIME + 100).floor, guard.status(TIME + 100).entries, take(&guard, 1, TIME + 150, TIME + 140)), (TIME + 200, 0, Some(Verdict::Refuse(Refusal::Floor))));
	}

	/// Waits until the memory holds `limit` as its limit, which is when it has heard that the file with it is written.
	async fn limit(guard: &Guard, limit: u64) {
		let started = Instant::now();
		while guard.status(0).limit != limit {
			assert!(started.elapsed() < Duration::from_secs(10), "the limit never became {limit}: {:?}", guard.status(0));
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn the_timer_writes_the_limit_and_a_write_that_fails_is_counted_and_tried_again() {
		static CLOCK: AtomicU64 = AtomicU64::new(TIME);
		let path = scratch("timer");
		let guard = Arc::new(Guard::open(&path, 1024, TIME - 100).unwrap());
		assert_eq!(on_disk(&path).limit(), TIME - 100 + WINDOW);
		let running = tokio::spawn(guard.clone().run(|| OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::SeqCst) as i64).unwrap()));
		limit(&guard, TIME + STEP).await;
		assert_eq!((on_disk(&path).limit(), take(&guard, 1, TIME, TIME)), (TIME + STEP, Some(Verdict::Accept)));
		// A proof from a client whose clock runs ahead: dropped, and the write it asks for is started.
		assert_eq!(take(&guard, 2, TIME + 30, TIME), Some(Verdict::Raise(TIME + 50)));
		guard.want(TIME + 50);
		limit(&guard, TIME + 50).await;
		assert_eq!((on_disk(&path).limit(), take(&guard, 2, TIME + 30, TIME)), (TIME + 50, Some(Verdict::Accept)));
		// The disk stops taking writes. The limit stays, and once the clock has passed it nothing is accepted.
		fs::create_dir(beside(&path, ".tmp")).unwrap();
		CLOCK.store(TIME + 60, Ordering::SeqCst);
		while guard.status(TIME + 60).write_failures < 2 {tokio::time::sleep(Duration::from_millis(20)).await}
		assert_eq!((guard.status(TIME + 60).limit, on_disk(&path).limit(), take(&guard, 3, TIME + 60, TIME + 60)), (TIME + 50, TIME + 50, Some(Verdict::Raise(TIME + 80))));
		fs::remove_dir(beside(&path, ".tmp")).unwrap();
		limit(&guard, TIME + 80).await;
		assert_eq!((on_disk(&path).limit(), take(&guard, 3, TIME + 60, TIME + 60)), (TIME + 80, Some(Verdict::Accept)));
		guard.stop().await;
		running.await.unwrap();
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn a_reset_empties_the_cache_and_one_that_cannot_be_written_puts_the_old_values_back() {
		static CLOCK: AtomicU64 = AtomicU64::new(TIME);
		let path = scratch("reset");
		let guard = Arc::new(Guard::open(&path, 1024, TIME - 100).unwrap());
		tokio::spawn(guard.clone().run(|| OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::SeqCst) as i64).unwrap()));
		limit(&guard, TIME + STEP).await;
		assert_eq!(take(&guard, 1, TIME, TIME), Some(Verdict::Accept));
		// The disk takes no write: the reset is not known to be on disk, nothing is accepted, and the node goes on writing the old values back.
		fs::create_dir(beside(&path, ".tmp")).unwrap();
		assert_eq!(guard.reset().await, Reset::Unwritten);
		assert_eq!((take(&guard, 2, TIME + 1, TIME), guard.status(TIME).ready, guard.reset().await), (None, false, Reset::Busy));
		fs::remove_dir(beside(&path, ".tmp")).unwrap();
		while !guard.status(TIME).ready {tokio::time::sleep(Duration::from_millis(20)).await}
		// The old memory is back: the proof it accepted is still spent.
		assert_eq!((guard.status(TIME).floor, take(&guard, 1, TIME, TIME), guard.status(TIME).resets), (TIME - 100 + WINDOW, Some(Verdict::Refuse(Refusal::Seen)), 0));
		// A reset that is written: the cache is empty and everything is refused for the window.
		assert_eq!(guard.reset().await, Reset::Done(TIME + WINDOW));
		let file = on_disk(&path);
		assert_eq!((file.floor(), file.limit(), guard.status(TIME).entries, guard.status(TIME).resets), (TIME + WINDOW, TIME + WINDOW, 0, 1));
		assert_eq!(take(&guard, 1, TIME, TIME), Some(Verdict::Refuse(Refusal::Floor)));
		CLOCK.store(TIME + WINDOW + 1, Ordering::SeqCst);
		while guard.status(0).limit < TIME + WINDOW + 1 {tokio::time::sleep(Duration::from_millis(20)).await}
		assert_eq!(take(&guard, 4, TIME + WINDOW + 1, TIME + WINDOW + 1), Some(Verdict::Accept));
		guard.abandon();
	}

	// "The wall clock jumps forward": the limit follows it up, and rule 9 brings it down once the clock is corrected. A crash before that makes the faulty time the floor, which is the state the node is loud about.
	#[tokio::test(flavor = "multi_thread")]
	async fn a_limit_a_wrong_clock_left_comes_down_and_a_floor_ahead_of_the_clock_is_said() {
		static CLOCK: AtomicU64 = AtomicU64::new(TIME + 3600);
		let path = scratch("ahead");
		let guard = Arc::new(Guard::open(&path, 1024, TIME - 100).unwrap());
		tokio::spawn(guard.clone().run(|| OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::SeqCst) as i64).unwrap()));
		limit(&guard, TIME + 3600 + STEP).await;
		CLOCK.store(TIME, Ordering::SeqCst);
		// The limit in use comes down when the file is handed out, and the write is counted when it has ended.
		while guard.status(TIME).lowered != 1 {tokio::time::sleep(Duration::from_millis(20)).await}
		assert_eq!((guard.status(TIME).limit, on_disk(&path).limit(), guard.status(TIME).floor_ahead, take(&guard, 1, TIME, TIME)), (TIME + STEP, TIME + STEP, false, Some(Verdict::Accept)));
		// The same fault, and a kill before the clock is corrected.
		CLOCK.store(TIME + 3600, Ordering::SeqCst);
		limit(&guard, TIME + 3600 + STEP).await;
		guard.abandon();
		while held(&path) != Some(false) {tokio::time::sleep(Duration::from_millis(20)).await}
		CLOCK.store(TIME, Ordering::SeqCst);
		let guard = Arc::new(Guard::open(&path, 1024, TIME).unwrap());
		tokio::spawn(guard.clone().run(|| OffsetDateTime::from_unix_timestamp(CLOCK.load(Ordering::SeqCst) as i64).unwrap()));
		let status = guard.status(TIME);
		assert_eq!((status.floor, status.floor_ahead, take(&guard, 2, TIME, TIME)), (TIME + 3600 + STEP, true, Some(Verdict::Refuse(Refusal::Floor))));
		tokio::time::sleep(Duration::from_millis(1200)).await;
		guard.refused_at_floor();
		assert_eq!(guard.status(TIME).refused_floor_ahead, 1);
		// Only a reset ends it.
		assert_eq!(guard.reset().await, Reset::Done(TIME + WINDOW));
		CLOCK.store(TIME + WINDOW + 1, Ordering::SeqCst);
		while guard.status(0).limit < TIME + WINDOW + 1 {tokio::time::sleep(Duration::from_millis(20)).await}
		assert_eq!(take(&guard, 2, TIME + WINDOW + 1, TIME + WINDOW + 1), Some(Verdict::Accept));
		guard.abandon();
	}
}
