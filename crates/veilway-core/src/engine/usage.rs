//! What users have used: the periods a quota count starts over in, and the state file that carries the counts across reloads and restarts.
//! The config document never holds any of it. The file is keyed by user name, like everything else the engine keeps for a user.
use super::{Shared, Traffic, UserState};
use crate::config::MAX_QUOTA_BYTES;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// The only version of the file this build reads and writes.
pub const VERSION: u64 = 1;
/// A state file larger than this is not read. An entry takes at most 253 bytes, so the file of a config with as many users as a config may have stays below it.
pub const MAX_FILE_BYTES: u64 = 16 << 20;
/// The largest count the file holds, which is the largest integer JSON carries exactly. A count above it is this one.
pub const MAX_COUNT: u64 = MAX_QUOTA_BYTES;
/// How far apart the writes of the file are while nothing asks for one sooner.
pub const WRITE_EVERY: Duration = Duration::from_secs(10);
/// How far apart the log lines of a row of failed writes are.
const SAY_AGAIN: Duration = Duration::from_secs(600);
/// How long a shutdown waits for the last write. A disk that hangs must not hold up what the node gives back to the host, nor the process.
pub const LAST_WRITE: Duration = Duration::from_secs(5);
const DAY: i64 = 86400;

/// The start of the day, the week and the month `now` lies in, in Unix seconds and in the order of `QuotaPeriod`. All three begin at 00:00 UTC, a week on Monday and a month on the 1st.
pub fn starts(now: OffsetDateTime) -> [i64; 3] {
	let day = now.unix_timestamp().div_euclid(DAY) * DAY;
	// 1 January 1970 was a Thursday, the fourth day of its week.
	let (weekday, monthday) = ((day / DAY + 3).rem_euclid(7), OffsetDateTime::from_unix_timestamp(day).map_or(1, |at| i64::from(at.day())));
	[day, day - weekday * DAY, day - (monthday - 1) * DAY]
}

/// A count as the file holds it. Any number that stands there is taken for a count and none is trusted: one below zero is zero, and one above `MAX_COUNT` is `MAX_COUNT`.
#[derive(Clone, Copy, Serialize)]
#[serde(transparent)]
struct Count(u64);

impl<'de> Deserialize<'de> for Count {
	fn deserialize<D: Deserializer<'de>>(from: D) -> Result<Count, D::Error> {
		let number = serde_json::Number::deserialize(from)?;
		Ok(Count(number.as_u64().unwrap_or_else(|| number.as_f64().map_or(0, |float| float as u64)).min(MAX_COUNT)))
	}
}

/// The start of a quota period as the file holds it, in Unix seconds. It is clamped like a count, on either side of zero.
#[derive(Clone, Copy, Serialize)]
#[serde(transparent)]
struct Start(i64);

impl<'de> Deserialize<'de> for Start {
	fn deserialize<D: Deserializer<'de>>(from: D) -> Result<Start, D::Error> {
		let number = serde_json::Number::deserialize(from)?;
		Ok(Start(number.as_i64().unwrap_or_else(|| number.as_f64().map_or(0, |float| float as i64)).clamp(-(MAX_COUNT as i64), MAX_COUNT as i64)))
	}
}

/// One user in the file: the bytes held against `quota_bytes` since `period_start` (0 for a user who never had a `quota_period`), and what the user sent and received in all.
#[derive(Serialize, Deserialize)]
struct Entry {used_bytes: Count, period_start: Start, up_bytes: Count, up_packets: Count, down_bytes: Count, down_packets: Count}

#[derive(Serialize)]
struct Document {version: u64, users: BTreeMap<String, Entry>}

/// The file as it is read. Each entry is left as the text it is and looked at by itself, so one that is no entry costs its own user their count and nobody else theirs.
#[derive(Deserialize)]
struct Stored<'a> {version: u64, #[serde(borrow)] users: BTreeMap<String, &'a RawValue>}

/// Where the state file is and what is known of it. Without a path usage lives in memory only.
pub struct Saver {
	pub(super) path: Option<PathBuf>,
	/// The bytes of the last write that went through. Empty while the file is not known to hold what the node last put together.
	pub(super) written: Vec<u8>,
	/// When a row of failed writes was last logged. None while writes go through.
	pub(super) failing: Option<Instant>,
}

/// What the state file at `path` says of each user, and whether the node may write there. A file that is not there says nothing, which is how a node starts for the first time.
/// A file that cannot be read, is too large, is no state file of this version, or that group or others can write is moved aside under its name with `.bad` behind it and mode 600, and says nothing either: the node starts counting from zero and never stays down for it.
/// Only a regular file is ever read, moved or written over. Anything else at the path (a directory, a link, a device, a pipe) is left as it is, and the node keeps usage in memory.
/// An entry that is no entry is passed over: its user starts from zero and everybody else keeps what the file says.
pub fn load(path: &Path) -> (Vec<(String, UserState)>, bool) {
	let alone = |why: String| {
		tracing::error!("state file {}: {why}. It is left as it is and nothing is written there: usage is kept in memory and is gone when the node stops", path.display());
		(Vec::new(), false)
	};
	// Looked at before it is opened, and without following a link: somebody who names `/dev/null` or a directory for no state file must find it there afterwards.
	match fs::symlink_metadata(path) {
		Err(e) if e.kind() == io::ErrorKind::NotFound => return (Vec::new(), true),
		Err(e) => return alone(format!("it cannot be looked at ({})", e.kind())),
		Ok(meta) if !meta.is_file() => return alone("it is not a regular file".to_string()),
		Ok(_) => {}
	}
	let mut options = OpenOptions::new();
	options.read(true);
	// Something else may stand there by now. A link is not followed, a pipe is not waited for, and what was opened is looked at once more.
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
	let opened = options.open(path).and_then(|file| Ok((file.metadata()?, file)));
	#[cfg(unix)]
	if opened.as_ref().is_err_and(|e| e.raw_os_error() == Some(libc::ELOOP)) {return alone("it is not a regular file".to_string())}
	if opened.as_ref().is_ok_and(|(meta, _)| !meta.is_file()) {return alone("it is not a regular file".to_string())}
	let read = || -> anyhow::Result<(usize, Vec<(String, UserState)>)> {
		let (meta, file) = match &opened {
			Ok((meta, file)) => (meta, file),
			Err(e) => anyhow::bail!("it cannot be opened ({})", e.kind()),
		};
		// Whoever can write the file can give any user any usage, and with it take a user's quota away or hand it back.
		#[cfg(unix)]
		anyhow::ensure!(std::os::unix::fs::MetadataExt::mode(meta) & 0o022 == 0, "group or others can write it");
		let mut bytes = Vec::new();
		anyhow::ensure!(meta.len() <= MAX_FILE_BYTES && file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)? as u64 <= MAX_FILE_BYTES, "it is larger than {} MiB", MAX_FILE_BYTES >> 20);
		let stored: Stored = serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("it is not a state file ({:?} at line {} column {})", e.classify(), e.line(), e.column()))?;
		anyhow::ensure!(stored.version == VERSION, "it has version {} and this build reads version {VERSION}", stored.version);
		let entries = stored.users.len();
		let users: Vec<(String, UserState)> = stored.users.into_iter().filter_map(|(name, raw)| serde_json::from_str::<Entry>(raw.get()).ok().map(|entry| (name, UserState {
			traffic: Traffic {up_packets: AtomicU64::new(entry.up_packets.0), up_bytes: AtomicU64::new(entry.up_bytes.0), down_packets: AtomicU64::new(entry.down_packets.0), down_bytes: AtomicU64::new(entry.down_bytes.0)},
			used: AtomicU64::new(entry.used_bytes.0),
			since: AtomicI64::new(entry.period_start.0),
			..UserState::default()
		}))).collect();
		Ok((entries - users.len(), users))
	};
	match read() {
		Ok((skipped, users)) => {
			if skipped > 0 {tracing::error!("state file {}: {skipped} of its entries are not what a node writes for a user. Those users start from zero and everybody else keeps what the file says", path.display())}
			(users, true)
		}
		Err(e) => {
			let mut bad = path.as_os_str().to_owned();
			bad.push(".bad");
			let replaced = fs::symlink_metadata(&bad).is_ok();
			match fs::rename(path, &bad) {
				Ok(()) => {
					// Names and usage are for nobody else under the new name either. The mode is set through the handle, so it is the file that was looked at whose mode changes, whatever stands at either name by now,
					// and only once the file is out of the way: a file that could not be trusted must not come back as one that can.
					#[cfg(unix)]
					if let Ok((_, file)) = &opened {let _ = file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));}
					tracing::error!("state file {}: {e:#}. It is kept as {}{} and every user's usage starts from zero", path.display(), Path::new(&bad).display(), if replaced {", in the place of an older file of that name"} else {""})
				}
				Err(stuck) => tracing::error!("state file {}: {e:#}. It could not be moved aside ({}) and every user's usage starts from zero", path.display(), stuck.kind()),
			}
			(Vec::new(), true)
		}
	}
}

/// Writes the usage of every user of the plan in force to the state file, unless that is what the file already holds. Users the plan does not name are not in it, so an entry goes with the commit that removed its user.
/// The file is replaced whole: a temporary file next to it with mode 600, synced, then renamed over it. A write that fails is counted and tried again the next time, and logged once and then every `SAY_AGAIN` for as long as writes keep failing.
/// With `last` nothing is written after this, which is how an engine that was shut down leaves the file to whoever starts next.
pub async fn save(shared: &Shared, last: bool) {
	let mut saver = shared.saver.lock().await;
	// Taken before the write is waited for: whoever gives up on a last write that hangs has still had the last one.
	let Some(path) = (if last {saver.path.take()} else {saver.path.clone()}) else {return};
	let (plan, written, target) = (shared.plan(), std::mem::take(&mut saver.written), path.clone());
	// Put together and written off the runtime's own threads, so no packet waits for a disk.
	let done = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
		let count = |counter: &AtomicU64| Count(counter.load(Ordering::Relaxed).min(MAX_COUNT));
		let bytes = serde_json::to_vec(&Document {version: VERSION, users: plan.users.iter().map(|user| {
			let (state, traffic) = (&user.state, &user.state.traffic);
			(user.name.clone(), Entry {used_bytes: count(&state.used), period_start: Start(state.since.load(Ordering::Relaxed)), up_bytes: count(&traffic.up_bytes), up_packets: count(&traffic.up_packets), down_bytes: count(&traffic.down_bytes), down_packets: count(&traffic.down_packets)})
		}).collect()})?;
		if bytes == written {return Ok(written)}
		let mut tmp = target.clone().into_os_string();
		tmp.push(".tmp");
		// What a write that was cut short left behind may have any mode, and `create_new` never follows a link somebody put in its place.
		let _ = fs::remove_file(&tmp);
		let mut options = OpenOptions::new();
		options.write(true).create_new(true);
		#[cfg(unix)]
		std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
		let mut file = options.open(&tmp)?;
		file.write_all(&bytes)?;
		file.sync_all()?;
		fs::rename(&tmp, &target)?;
		Ok(bytes)
	}).await.unwrap_or_else(|e| Err(io::Error::other(e)));
	match done {
		Ok(bytes) => {
			if saver.failing.take().is_some() {tracing::info!("state file {}: it is written again", path.display())}
			saver.written = bytes;
		}
		// Nothing counts as written now, so the next round writes whether or not anything has changed by then.
		Err(e) => {
			let failed = shared.unwritten.fetch_add(1, Ordering::Relaxed) + 1;
			// A node that cannot write gives every user their quota again at its next start, so this is not said once and then never again.
			if saver.failing.is_none_or(|said| said.elapsed() >= SAY_AGAIN) {
				saver.failing = Some(Instant::now());
				tracing::error!("state file {}: it could not be written ({e}), so usage since the last write is lost if the node stops now. {failed} write(s) have failed since start. Trying again every {}s and saying so every {} minutes", path.display(), WRITE_EVERY.as_secs(), SAY_AGAIN.as_secs() / 60);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::{Config, MAX_NAME_BYTES, MAX_USERS};
	use crate::engine::Options;
	use time::format_description::well_known::Rfc3339;

	fn at(stamp: &str) -> i64 {OffsetDateTime::parse(stamp, &Rfc3339).unwrap().unix_timestamp()}

	fn starts_at(stamp: &str) -> [i64; 3] {starts(OffsetDateTime::parse(stamp, &Rfc3339).unwrap())}

	#[test]
	fn a_day_starts_at_midnight_utc_whatever_offset_the_clock_has() {
		assert_eq!(starts_at("2026-01-14T12:00:00Z")[0], at("2026-01-14T00:00:00Z"));
		assert_eq!(starts_at("2026-01-14T00:00:00Z")[0], at("2026-01-14T00:00:00Z"));
		assert_eq!(starts_at("2026-01-14T23:59:59Z")[0], at("2026-01-14T00:00:00Z"));
		// 01:00 in Tehran is still the day before in UTC.
		assert_eq!(starts_at("2026-01-15T01:00:00+03:30")[0], at("2026-01-14T00:00:00Z"));
		assert_eq!(starts_at("2026-01-14T22:00:00-05:00")[0], at("2026-01-15T00:00:00Z"));
	}

	#[test]
	fn a_week_starts_on_monday() {
		// 12 to 18 January 2026 is a week from Monday to Sunday.
		for day in 12..=18 {assert_eq!(starts_at(&format!("2026-01-{day}T15:30:00Z"))[1], at("2026-01-12T00:00:00Z"), "day {day}")}
		assert_eq!(starts_at("2026-01-11T23:59:59Z")[1], at("2026-01-05T00:00:00Z"));
		assert_eq!(starts_at("2026-01-19T00:00:00Z")[1], at("2026-01-19T00:00:00Z"));
		// A week that began in the year before, and one that began in the month before across a leap day.
		assert_eq!(starts_at("2026-01-01T08:00:00Z")[1], at("2025-12-29T00:00:00Z"));
		assert_eq!(starts_at("2024-03-02T08:00:00Z")[1], at("2024-02-26T00:00:00Z"));
		// Before 1970 the arithmetic runs through negative numbers. 29 December 1969 was a Monday.
		assert_eq!(starts_at("1969-12-31T23:59:59Z")[1], at("1969-12-29T00:00:00Z"));
		assert_eq!(starts_at("1969-12-28T12:00:00Z")[1], at("1969-12-22T00:00:00Z"));
	}

	#[test]
	fn a_month_starts_on_the_first_whatever_its_length() {
		for (stamp, first) in [
			("2026-01-31T23:59:59Z", "2026-01-01T00:00:00Z"),
			("2026-02-28T23:59:59Z", "2026-02-01T00:00:00Z"),
			("2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z"),
			("2026-04-30T12:00:00Z", "2026-04-01T00:00:00Z"),
			("2024-02-29T23:59:59Z", "2024-02-01T00:00:00Z"),
			("2024-03-01T00:00:00Z", "2024-03-01T00:00:00Z"),
			("2000-02-29T12:00:00Z", "2000-02-01T00:00:00Z"),
			("2100-02-28T23:59:59Z", "2100-02-01T00:00:00Z"),
			("2100-03-01T00:00:00Z", "2100-03-01T00:00:00Z"),
			("2025-12-31T23:59:59Z", "2025-12-01T00:00:00Z"),
			("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
			("1969-12-31T23:59:59Z", "1969-12-01T00:00:00Z"),
		] {assert_eq!(starts_at(stamp)[2], at(first), "{stamp}")}
	}

	#[test]
	fn every_period_ends_where_the_next_one_starts() {
		// One second before each boundary and the boundary itself, over two years with a leap day in them.
		let (mut day, end) = (at("2023-12-25T00:00:00Z"), at("2026-01-10T00:00:00Z"));
		while day < end {
			let (before, after) = (starts(OffsetDateTime::from_unix_timestamp(day - 1).unwrap()), starts(OffsetDateTime::from_unix_timestamp(day).unwrap()));
			let date = OffsetDateTime::from_unix_timestamp(day).unwrap();
			assert_eq!((before[0], after[0]), (day - DAY, day));
			assert_eq!(after[1] != before[1], date.weekday() == time::Weekday::Monday, "{date}");
			assert_eq!(after[2] != before[2], date.day() == 1, "{date}");
			assert!(after[1] <= day && day - after[1] < 7 * DAY && after[2] <= day && day - after[2] < 31 * DAY, "{date}");
			day += DAY;
		}
	}

	#[test]
	fn a_count_in_the_file_is_clamped_and_never_refused() {
		let entry: Entry = serde_json::from_str(r#"{"used_bytes":18446744073709551615,"period_start":0,"up_bytes":1e30,"up_packets":-5,"down_bytes":9007199254740992,"down_packets":12.9}"#).unwrap();
		assert_eq!((entry.used_bytes.0, entry.up_bytes.0, entry.up_packets.0, entry.down_bytes.0, entry.down_packets.0), (MAX_COUNT, MAX_COUNT, 0, MAX_COUNT, 12));
		assert!(serde_json::from_str::<Entry>(r#"{"used_bytes":"7","period_start":0,"up_bytes":0,"up_packets":0,"down_bytes":0,"down_packets":0}"#).is_err(), "a string was taken for a count");
	}

	#[test]
	fn the_file_of_the_largest_config_is_one_this_build_reads() {
		let entry = || Entry {used_bytes: Count(MAX_COUNT), period_start: Start(-(MAX_COUNT as i64)), up_bytes: Count(MAX_COUNT), up_packets: Count(MAX_COUNT), down_bytes: Count(MAX_COUNT), down_packets: Count(MAX_COUNT)};
		let users: BTreeMap<String, Entry> = (0..MAX_USERS).map(|user| (format!("{user:0>width$}", width = MAX_NAME_BYTES), entry())).collect();
		assert!(serde_json::to_vec(&Document {version: VERSION, users}).unwrap().len() as u64 <= MAX_FILE_BYTES);
	}

	/// A new directory for one test, which removes it when it is done.
	fn scratch(test: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-usage-{}-{test}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn an_entry_that_is_no_entry_costs_nobody_else_their_count() {
		let (dir, good) = (scratch("lenient"), r#"{"used_bytes":7,"period_start":5,"up_bytes":4,"up_packets":1,"down_bytes":3,"down_packets":1}"#);
		let (path, most) = (dir.join("state.json"), MAX_COUNT as i64);
		for (case, other, start) in [
			("as the node writes it", good.to_string(), Some(5)),
			("a period start above every count", good.replace(":5,", ":10000000000000000000,"), Some(most)),
			("a period start below every count", good.replace(":5,", ":-1e30,"), Some(-most)),
			("a period start with a fraction", good.replace(":5,", ":1.5,"), Some(1)),
			("a period start that is null", good.replace(":5,", ":null,"), None),
			("a field twice", good.replace('{', r#"{"up_bytes":1,"#), None),
			("a number no float holds", good.replace(":7,", ":1e400,"), None),
			("no object", "0".to_string(), None),
		] {
			fs::write(&path, format!(r#"{{"version":1,"users":{{"a":{good},"b":{other}}}}}"#)).unwrap();
			let (users, writable) = load(&path);
			let since = |name: &str| users.iter().find(|(user, _)| user == name).map(|(_, state)| (state.since.load(Ordering::Relaxed), state.used()));
			assert_eq!((since("a"), since("b").map(|(start, _)| start), writable, dir.join("state.json.bad").exists()), (Some((5, 7)), start, true, false), "{case}");
		}
		fs::remove_dir_all(&dir).unwrap();
	}

	#[cfg(unix)]
	#[test]
	fn a_file_that_was_moved_aside_is_for_the_node_alone() {
		use std::os::unix::fs::PermissionsExt;
		let dir = scratch("bad-mode");
		let (path, bad) = (dir.join("state.json"), dir.join("state.json.bad"));
		// The second file takes the place of the first under the same name.
		for mode in [0o644, 0o666] {
			fs::write(&path, format!("no state file, mode {mode:o}")).unwrap();
			fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
			let (users, writable) = load(&path);
			assert!(users.is_empty() && writable);
			assert_eq!((fs::read_to_string(&bad).unwrap(), fs::metadata(&bad).unwrap().permissions().mode() & 0o777, path.exists()), (format!("no state file, mode {mode:o}"), 0o600, false));
		}
		fs::remove_dir_all(&dir).unwrap();
	}

	#[cfg(unix)]
	#[test]
	fn what_is_no_regular_file_is_neither_read_nor_moved_nor_written_over() {
		let dir = scratch("special");
		let (path, target, entry) = (dir.join("state.json"), dir.join("elsewhere.json"), r#"{"used_bytes":7,"period_start":0,"up_bytes":7,"up_packets":1,"down_bytes":0,"down_packets":0}"#);
		fs::write(&target, format!(r#"{{"version":1,"users":{{"a":{entry}}}}}"#)).unwrap();
		assert_eq!(load(&target).0.len(), 1);
		// A link to a file the node would read, a link to a device, a socket and a directory. None is followed, opened or renamed.
		for case in ["link", "device", "socket", "directory"] {
			let _socket = match case {
				"link" => std::os::unix::fs::symlink(&target, &path).map(|_| None).unwrap(),
				"device" => std::os::unix::fs::symlink("/dev/null", &path).map(|_| None).unwrap(),
				"socket" => Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
				_ => fs::create_dir(&path).map(|_| None).unwrap(),
			};
			let before = fs::symlink_metadata(&path).unwrap().file_type();
			let (users, writable) = load(&path);
			assert!(users.is_empty() && !writable, "{case}: what stands at the path was read or may be written over");
			assert_eq!((fs::symlink_metadata(&path).unwrap().file_type(), dir.join("state.json.bad").exists(), fs::read_dir(&dir).unwrap().count()), (before, false, 2), "{case}");
			if case == "directory" {fs::remove_dir(&path).unwrap()} else {fs::remove_file(&path).unwrap()}
		}
		assert!(fs::metadata("/dev/null").is_ok_and(|null| !null.is_file()) && load(&target).0.len() == 1);
		fs::remove_dir_all(&dir).unwrap();
	}

	/// A write that hangs on its disk holds the saver for as long as it hangs, which is what this test does in its place.
	#[tokio::test]
	async fn a_shutdown_does_not_wait_for_a_write_that_hangs() {
		let (dir, node, device) = (scratch("shutdown"), veilway_wg::generate_key(), veilway_wg::generate_key());
		let config = Config::parse(serde_json::json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&node), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "127.0.0.1:20990"}]}],
			"outbounds": [{"tag": "proxy", "type": "socks5", "server": "127.0.0.1:20991"}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "proxy"}}],
			"routing": {"default": "main", "rules": []},
			"users": [{"name": "a", "exits": "all", "devices": [{"name": "device", "public_key": veilway_wg::encode_key(&veilway_wg::public_key(&device)), "addresses": ["10.7.0.2"]}]}]
		}).to_string().as_bytes()).ok().expect("the test config does not parse");
		let engine = crate::engine::start(&config, Options {state: Some(dir.join("state.json")), ..Options::new("")}).await.unwrap();
		let shared = engine.shared.clone();
		let _stuck = shared.saver.lock().await;
		assert!(tokio::time::timeout(Duration::from_secs(8), engine.shutdown()).await.is_ok(), "the shutdown waited for the state file");
		fs::remove_dir_all(&dir).unwrap();
	}
}
