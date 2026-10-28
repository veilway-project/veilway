//! The country address lists behind `geoip:<cc>`: one text file the release carries (`veilway-geoip.txt`, made by `scripts/geoip.sh` from the five registries' delegation files and signed with the other assets),
//! installed by `veilway.sh` next to the node. The file is read as hostile input: a header `veilway-geoip 1 <YYYY-MM-DD>`, then one line each, fields split by one space, in no required order:
//! `<cc> 4 <first IPv4 address> <count of addresses>` or `<cc> 6 <IPv6 network address> <prefix length>`. A network with host bits set is refused, not masked. Overlapping and adjacent ranges are merged.
//! Every line is checked whether the config names its country or not, and only the countries a rule names are kept.
use super::{Config, IpEntry};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Sub;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use time::{Date, Month, OffsetDateTime};

pub const DEFAULT_PATH: &str = "/usr/local/lib/veilway/geoip.txt";
pub const MAX_BYTES: u64 = 16 << 20;
/// Lines of the file, the header included.
pub const MAX_LINES: usize = 1_000_000;
/// Validation warns about a list older than this.
pub const STALE_DAYS: i64 = 180;
const HEADER: &str = "veilway-geoip 1 ";

static PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
type Identity = (PathBuf, BTreeSet<[u8; 2]>, Option<SystemTime>, u64, u64);
/// The last list read, by the file's identity and the countries kept, so that validating a config and compiling it read the file once.
static CACHE: Mutex<Option<(Identity, Arc<Loaded>)>> = Mutex::new(None);

/// Where `load` reads the list from, which the binary sets from `--geoip` before it reads a config.
pub fn set_path(path: PathBuf) {*PATH.lock().unwrap_or_else(|e| e.into_inner()) = Some(path)}

pub fn path() -> PathBuf {PATH.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))}

/// The countries the rules of a config name, enabled or not.
pub fn named(config: &Config) -> BTreeSet<[u8; 2]> {config.routing.rules.iter().flat_map(|rule| rule.ip.iter().flatten()).filter_map(|entry| if let IpEntry::Country(cc) = entry {Some(*cc)} else {None}).collect()}

/// The addresses of one country as sorted, merged ranges that never touch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ranges {pub v4: Vec<(u32, u32)>, pub v6: Vec<(u128, u128)>}

impl Ranges {
	pub fn contains(&self, ip: IpAddr) -> bool {match ip {IpAddr::V4(ip) => find(&self.v4, u32::from(ip)), IpAddr::V6(ip) => find(&self.v6, u128::from(ip))}}
}

fn find<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
	let at = ranges.partition_point(|range| range.0 <= x);
	at > 0 && ranges[at - 1].1 >= x
}

fn merged<T: Ord + Copy + Sub<Output = T> + From<u8>>(mut list: Vec<(T, T)>) -> Vec<(T, T)> {
	list.sort_unstable();
	let mut out: Vec<(T, T)> = Vec::with_capacity(list.len());
	for (start, end) in list {
		// `start - 1` is only reached when `start` is past the last end, so it is at least 1.
		match out.last_mut() {
			Some(last) if start <= last.1 || start - T::from(1) == last.1 => last.1 = last.1.max(end),
			_ => out.push((start, end)),
		}
	}
	out
}

#[derive(Debug, PartialEq, Eq)]
pub struct Loaded {
	pub date: Date,
	/// Countries the file lists, whether a rule names them or not.
	pub listed: usize,
	/// The ranges of the countries a rule names that the file has any for.
	pub sets: HashMap<[u8; 2], Arc<Ranges>>,
}

impl Loaded {
	pub fn age_days(&self, now: OffsetDateTime) -> i64 {(now.date() - self.date).whole_days()}
}

/// Reads a list from its bytes, keeping the countries in `wanted`. The error says which line is wrong and never holds the line.
pub fn parse(bytes: &[u8], wanted: &BTreeSet<[u8; 2]>) -> Result<Loaded, String> {
	if bytes.len() as u64 > MAX_BYTES {return Err(format!("it is over {MAX_BYTES} bytes"))}
	let text = std::str::from_utf8(bytes).map_err(|_| "it is not text".to_string())?;
	let mut lines = text.strip_suffix('\n').ok_or("its last line has no end")?.split('\n');
	let date = lines.next().and_then(|line| line.strip_prefix(HEADER)).filter(|date| date.len() == 10 && date.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 {b == b'-'} else {b.is_ascii_digit()}))
		.and_then(|date| Date::from_calendar_date(date[..4].parse().ok()?, Month::try_from(date[5..7].parse::<u8>().ok()?).ok()?, date[8..].parse().ok()?).ok()).ok_or("its first line is not `veilway-geoip 1 <YYYY-MM-DD>`")?;
	let (mut seen, mut kept): (HashSet<[u8; 2]>, HashMap<[u8; 2], (Vec<(u32, u32)>, Vec<(u128, u128)>)>) = (HashSet::new(), HashMap::new());
	for (i, line) in lines.enumerate() {
		let n = i + 2;
		if n > MAX_LINES {return Err(format!("it has more than {MAX_LINES} lines"))}
		let bad = |why: &str| format!("line {n}: {why}");
		let fields: Vec<&str> = line.split(' ').collect();
		let [cc, family, address, size] = fields[..] else {return Err(bad("expected four fields separated by one space"))};
		let cc = match cc.as_bytes() {[a @ b'a'..=b'z', b @ b'a'..=b'z'] => [*a, *b], _ => return Err(bad("expected a country of two lowercase letters"))};
		let size = if size.len() <= 10 && !size.starts_with('0') && size.bytes().all(|b| b.is_ascii_digit()) {size.parse::<u64>().ok()} else {None}.ok_or_else(|| bad("expected a count or a prefix length in digits, from 1"))?;
		seen.insert(cc);
		let ranges = wanted.contains(&cc).then(|| kept.entry(cc).or_default());
		match family {
			"4" => {
				let start = u64::from(u32::from(address.parse::<Ipv4Addr>().map_err(|_| bad("expected an IPv4 address"))?));
				if size > 1 << 32 || start + size > 1 << 32 {return Err(bad("expected a count of 1 to 2^32 that stays inside the address space"))}
				if let Some(ranges) = ranges {ranges.0.push((start as u32, (start + size - 1) as u32))}
			}
			"6" => {
				let start = u128::from(address.parse::<Ipv6Addr>().map_err(|_| bad("expected an IPv6 address"))?);
				if size > 128 {return Err(bad("expected a prefix length of 1 to 128"))}
				let host = u128::MAX.checked_shr(size as u32).unwrap_or(0);
				if start & host != 0 {return Err(bad("expected an IPv6 network with no host bits set"))}
				if let Some(ranges) = ranges {ranges.1.push((start, start | host))}
			}
			_ => return Err(bad("expected the family 4 or 6")),
		}
	}
	Ok(Loaded {date, listed: seen.len(), sets: kept.into_iter().map(|(cc, (v4, v6))| (cc, Arc::new(Ranges {v4: merged(v4), v6: merged(v6)}))).collect()})
}

/// Reads the list at `path()`, keeping the countries in `wanted`. The error names the file and says how to get a good one.
pub fn load(wanted: &BTreeSet<[u8; 2]>) -> Result<Arc<Loaded>, String> {
	let path = path();
	let fail = |why: String| format!("the country address list {} {why}; `veilway.sh update node` installs it", path.display());
	let mut file = File::open(&path).map_err(|e| fail(format!("cannot be read ({})", e.kind())))?;
	let meta = file.metadata().map_err(|e| fail(format!("cannot be read ({})", e.kind())))?;
	#[cfg(unix)]
	let inode = meta.ino();
	#[cfg(not(unix))]
	let inode = 0;
	let identity = (path.clone(), wanted.clone(), meta.modified().ok(), meta.len(), inode);
	if let Some((_, loaded)) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).as_ref().filter(|(was, _)| *was == identity) {return Ok(loaded.clone())}
	let mut bytes = Vec::new();
	file.by_ref().take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| fail(format!("cannot be read ({})", e.kind())))?;
	let loaded = Arc::new(parse(&bytes, wanted).map_err(|why| fail(format!("is not valid ({why})")))?);
	*CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((identity, loaded.clone()));
	Ok(loaded)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn only(cc: &str) -> BTreeSet<[u8; 2]> {BTreeSet::from([[cc.as_bytes()[0], cc.as_bytes()[1]]])}

	fn ranges(text: &str, cc: &str) -> Arc<Ranges> {parse(text.as_bytes(), &only(cc)).unwrap().sets[&[cc.as_bytes()[0], cc.as_bytes()[1]]].clone()}

	const GOOD: &str = "veilway-geoip 1 2026-10-28\nde 4 5.0.0.0 256\nde 4 5.0.1.0 256\nde 4 5.0.0.128 10\nde 4 9.0.0.0 1\nde 6 2001:db8:: 32\nfr 4 0.0.0.0 4294967296\n";

	#[test]
	fn merges_overlaps_and_neighbors() {
		let de = ranges(GOOD, "de");
		assert_eq!(de.v4, vec![(0x05000000, 0x050001ff), (0x09000000, 0x09000000)]);
		assert_eq!(de.v6, vec![(0x20010db8 << 96, (0x20010db8 << 96) | (u128::MAX >> 32))]);
	}

	#[test]
	fn lookup_edges() {
		let de = ranges(GOOD, "de");
		for (ip, yes) in [("4.255.255.255", false), ("5.0.0.0", true), ("5.0.1.255", true), ("5.0.2.0", false), ("8.255.255.255", false), ("9.0.0.0", true), ("9.0.0.1", false), ("0.0.0.0", false), ("255.255.255.255", false), ("2001:db8::", true), ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true), ("2001:db9::", false), ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", false)] {
			assert_eq!(de.contains(ip.parse().unwrap()), yes, "{ip}");
		}
	}

	#[test]
	fn whole_address_space_and_the_top_edge() {
		let all = ranges("veilway-geoip 1 2026-10-28\nzz 4 0.0.0.0 4294967296\nzz 6 :: 1\nzz 6 8000:: 1\n", "zz");
		assert_eq!((all.v4.clone(), all.v6.clone()), (vec![(0, u32::MAX)], vec![(0, u128::MAX)]));
		assert!(all.contains("255.255.255.255".parse().unwrap()) && all.contains("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
		let host = ranges("veilway-geoip 1 2026-10-28\nzz 4 255.255.255.255 1\nzz 6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 128\n", "zz");
		assert_eq!((host.v4.clone(), host.v6.clone()), (vec![(u32::MAX, u32::MAX)], vec![(u128::MAX, u128::MAX)]));
	}

	#[test]
	fn keeps_only_named_countries_and_counts_the_rest() {
		let loaded = parse(GOOD.as_bytes(), &only("fr")).unwrap();
		assert_eq!((loaded.listed, loaded.sets.len(), loaded.date.to_string().as_str()), (2, 1, "2026-10-28"));
		assert!(parse(GOOD.as_bytes(), &only("tr")).unwrap().sets.is_empty());
	}

	#[test]
	fn refuses_what_is_malformed() {
		let wrong = |text: &str| parse(text.as_bytes(), &only("de")).unwrap_err();
		let head = "veilway-geoip 1 2026-10-28\n";
		for (text, line) in [
			("de 4 5.0.0.0 256\n".to_string(), None), ("veilway-geoip 2 2026-10-28\n".to_string(), None), ("veilway-geoip 1 2026-13-28\n".to_string(), None), ("veilway-geoip 1 2026-10-2\n".to_string(), None), ("veilway-geoip 1 2026-10-28".to_string(), None), ("veilway-geoip 1 2026-10-28 \n".to_string(), None), (String::new(), None), ("\n".to_string(), None),
			(format!("{head}\n"), Some(2)), (format!("{head}de 4 5.0.0.0\n"), Some(2)), (format!("{head}de 4 5.0.0.0 256 x\n"), Some(2)), (format!("{head}de  4 5.0.0.0 256\n"), Some(2)), (format!("{head}de 4 5.0.0.0 256\r\n"), Some(2)),
			(format!("{head}DE 4 5.0.0.0 256\n"), Some(2)), (format!("{head}d 4 5.0.0.0 256\n"), Some(2)), (format!("{head}deu 4 5.0.0.0 256\n"), Some(2)), (format!("{head}d1 4 5.0.0.0 256\n"), Some(2)),
			(format!("{head}de 5 5.0.0.0 256\n"), Some(2)), (format!("{head}de 4 5.0.0 256\n"), Some(2)), (format!("{head}de 4 05.0.0.0 256\n"), Some(2)), (format!("{head}de 4 2001:db8:: 256\n"), Some(2)), (format!("{head}de 6 5.0.0.0 24\n"), Some(2)),
			(format!("{head}de 4 5.0.0.0 0\n"), Some(2)), (format!("{head}de 4 5.0.0.0 -1\n"), Some(2)), (format!("{head}de 4 5.0.0.0 +1\n"), Some(2)), (format!("{head}de 4 5.0.0.0 0256\n"), Some(2)), (format!("{head}de 4 5.0.0.0 4294967297\n"), Some(2)), (format!("{head}de 4 5.0.0.0 99999999999999999999\n"), Some(2)),
			(format!("{head}de 4 255.255.255.255 2\n"), Some(2)), (format!("{head}de 4 128.0.0.0 2147483649\n"), Some(2)), (format!("{head}de 4 0.0.0.0 4294967297\n"), Some(2)),
			(format!("{head}de 6 2001:db8:: 0\n"), Some(2)), (format!("{head}de 6 2001:db8:: 129\n"), Some(2)), (format!("{head}de 6 2001:db8::1 32\n"), Some(2)), (format!("{head}de 6 ::1 127\n"), Some(2)), (format!("{head}de 6 ::1 128\nde 6 ::1 129\n"), Some(3)),
			(format!("{head}fr 4 1.0.0.0 1\nde 4 5.0.0.0 256\nde 4 5.0.0.0 x\n"), Some(4)),
		] {
			let message = wrong(&text);
			assert!(line.is_none_or(|n| message.starts_with(&format!("line {n}:"))), "{text:?}: {message}");
			assert!(!message.contains("5.0.0.0") && !message.contains("2001"), "{message}");
		}
		assert!(parse(b"veilway-geoip 1 2026-10-28\nde 4 5.0.0.0 \xff\n", &only("de")).unwrap_err().contains("not text"));
	}

	#[test]
	fn lines_of_countries_nobody_named_are_checked_too() {
		assert!(parse("veilway-geoip 1 2026-10-28\nfr 4 1.0.0.0 0\n".as_bytes(), &only("de")).is_err());
		assert!(parse("veilway-geoip 1 2026-10-28\nfr 6 2001:db8::1 32\n".as_bytes(), &only("de")).is_err());
	}

	#[test]
	fn size_limits() {
		let head = "veilway-geoip 1 2026-10-28\n";
		let lines = |count: usize| format!("{head}{}", "de 4 5.0.0.0 1\n".repeat(count - 1));
		assert!(parse(lines(MAX_LINES).as_bytes(), &only("de")).is_ok());
		assert!(parse(lines(MAX_LINES + 1).as_bytes(), &only("de")).unwrap_err().contains("more than"));
		assert!(parse(&vec![b'a'; MAX_BYTES as usize + 1], &only("de")).unwrap_err().contains("over"));
		let mut full = format!("{head}de 4 5.0.0.0 1\n").into_bytes();
		full.resize(MAX_BYTES as usize + 1, b'\n');
		assert!(parse(&full, &only("de")).unwrap_err().contains("over"));
	}

	#[test]
	fn age_counts_days() {
		let loaded = parse(GOOD.as_bytes(), &only("de")).unwrap();
		let now = |text: &str| OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap();
		assert_eq!((loaded.age_days(now("2026-10-28T00:00:00Z")), loaded.age_days(now("2027-04-26T12:00:00Z"))), (0, 180));
	}
}
