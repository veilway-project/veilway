//! Config version 1: the typed model, strict parsing, validation and reloading. `crate::engine` compiles a validated document into its plan.
mod model;
mod parse;
mod reload;
mod validate;

pub use model::*;
pub(crate) use model::domain;
pub use reload::*;
use ring::rand::{SecureRandom, SystemRandom};
use schemars::generate::SchemaSettings;
use schemars::transform::{RecursiveTransform, Transform};
use schemars::Schema;
use serde_json::{json, Value};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

pub const VERSION: u64 = 1;
pub const MAX_FILE_BYTES: u64 = 64 << 20;
/// JSON values (scalars, lists and objects) in one document. Each costs memory however short its text is, so the file size alone is no bound.
pub const MAX_JSON_NODES: usize = 8_000_000;
pub const MAX_INBOUNDS: usize = 64;
pub const MAX_XRAY_INBOUNDS: usize = 16;
/// Outbounds of the `xray` type: each is a loopback listener of the add-on's one process.
pub const MAX_XRAY_OUTBOUNDS: usize = 16;
/// A proxy inbound (`socks5`, `http`, `mixed`): the connections it holds, how many one source may have, how many may be logging in, and the length of a user's `proxy_password`.
pub const MAX_PROXY_INBOUND_CONNECTIONS: u32 = 65536;
pub const DEFAULT_PROXY_CONNECTIONS: u32 = 1024;
pub const DEFAULT_PROXY_PER_SOURCE: u32 = 64;
pub const DEFAULT_PROXY_HANDSHAKES: u32 = 256;
pub const MIN_PROXY_PASSWORD: usize = 16;
pub const MAX_PROXY_PASSWORD: usize = 128;
pub const MAX_TRANSPORTS: usize = 8;
pub const MAX_OUTBOUNDS: usize = 256;
/// The most `socks5` outbounds one `via` chain may hold, counting the outbound that starts it.
pub const MAX_CHAIN: usize = 8;
pub const MAX_EXITS: usize = 256;
pub const MAX_GROUPS: usize = 256;
pub const MAX_RULES: usize = 4096;
pub const MAX_RULE_ENTRIES: usize = 1024;
pub const MAX_USERS: usize = 65536;
pub const MAX_DEVICES: usize = 16;
pub const MAX_DEVICE_ADDRESSES: usize = 16;
/// A device has two transport secrets only while one is rotated out (protocol overview, "Rotation").
pub const MAX_TRANSPORT_SECRETS: usize = 2;
/// The control channel carries at most this many notices, of at most this many bytes each.
pub const MAX_NOTICES: usize = 4;
pub const MAX_NOTICE_BYTES: usize = 280;
/// The addresses a node names to its profiles, at most this many.
pub const MAX_PUBLIC_ADDRESSES: usize = 8;
pub const MAX_DNS_SERVERS: usize = 4;
pub const MAX_DNS_SETS: usize = 32;
pub const MAX_INBOUND_ADDRESSES: usize = 2;
/// Node links page, "Numbers that are judgement calls": "Links on one node: at most 64", "Parallel links behind one `chain` exit: 1 to 4", and "Flows of one link at the exit: 16,384 by default, set by the exit's operator", which no operator sets above what the flow table holds.
pub const MAX_LINKS: usize = 64;
pub const MAX_CHAIN_LINKS: usize = 4;
pub const DEFAULT_LINK_FLOWS: u32 = 16384;
pub const MAX_LINK_FLOWS: u32 = 65536;
/// Node links page, "Tunnels": at most 64 tunnels, 1 to 64 networks in `sources`, `max_connections` 1 to 4096 with 256 by default, and "at most 16 of them for one client address".
pub const MAX_TUNNELS: usize = 64;
/// Other providers' subscriptions a node uses as exits, at most this many.
pub const MAX_UPSTREAMS: usize = 8;
pub const MAX_TUNNEL_SOURCES: usize = 64;
pub const MAX_TUNNEL_CONNECTIONS: u32 = 4096;
pub const DEFAULT_TUNNEL_CONNECTIONS: u32 = 256;
pub const TUNNEL_PER_CLIENT: usize = 16;
/// "The `max_connections` of all tunnels together come to at most 16,384, a quarter of the flow table."
pub const MAX_TUNNEL_TOTAL: u64 = 16384;
/// The endpoints or candidates of one transport a link dials, and the pins of one candidate, as a profile of a subscription has them.
pub const MAX_LINK_CANDIDATES: usize = 16;
pub const MAX_LINK_PINS: usize = 4;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_EXIT_NAME_CHARS: usize = 64;
pub const MAX_INTERFACE_BYTES: usize = 15;
pub const MAX_WS_PATH_BYTES: usize = 256;
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_LABEL_BYTES: usize = 63;
pub const MAX_CREDENTIAL_BYTES: usize = 255;
pub const MAX_QUOTA_BYTES: u64 = 9007199254740991;
pub const KEY_CHARS: usize = 44;
pub const MIN_MTU: u16 = 1280;
pub const MAX_MTU: u16 = 1500;
pub const DEFAULT_MTU: u16 = 1420;
/// The default `mtu` of a `veilway` inbound with a `udp-obfs` transport: 1500 less the 48 bytes of IPv6 and UDP and the 62 of WireGuard and the envelope.
pub const DEFAULT_MTU_OBFS: u16 = 1390;
pub const MIN_REPLAY_CACHE: u32 = 1024;
pub const MAX_REPLAY_CACHE: u32 = 1 << 20;
pub const DEFAULT_REPLAY_CACHE: u32 = 262_144;
pub const MAX_PROOF_RATE: u32 = 65536;
pub const DEFAULT_PROOFS_PER_SOURCE: ProofRate = ProofRate {burst: 256, rate: 32};
pub const MAX_SESSIONS: u32 = 1 << 20;
pub const DEFAULT_SESSIONS: u32 = 16384;
/// An inbound has two node transport keys only while one is rotated out (protocol overview, "Rotation").
pub const MAX_TRANSPORT_KEYS: usize = 2;
/// The pools of a stream listener (transports page, "Node capacity numbers"): "Undecided connections: 512, and 64 per source. Relayed connections: 1,024."
pub const MAX_UNDECIDED: u32 = 65536;
pub const DEFAULT_UNDECIDED: u32 = 512;
pub const DEFAULT_UNDECIDED_PER_SOURCE: u32 = 64;
/// No more than this, because the listener looks at every relayed connection, with the pool held, to find the one to close for room.
pub const MAX_RELAYED: u32 = 65536;
pub const DEFAULT_RELAYED: u32 = 1024;
/// The borrowed-site transport (`faketls`, borrowed-site page, "Numbers that are judgement calls"): strangers relayed to the site, 256 in all by default, and new connections to the site a second, 16 by default. The upper bound of the second is the config's own.
pub const DEFAULT_SITE_RELAYED: u32 = 256;
pub const DEFAULT_SITE_RATE: u32 = 16;
pub const MAX_SITE_RATE: u32 = 1024;
pub const DEFAULT_SITE_PORT: u16 = 443;
/// "`site.names`: optional extra server names that a user's hello may carry, at most 4."
pub const MAX_SITE_NAMES: usize = 4;
/// The pools of the proxy path (transports page, "Node capacity numbers"): "Proxy connections: twice the `fronted` sessions", and "Decoy requests in flight per source on the proxy path: 16".
/// The page's "`fronted` sessions: 4,096" is not the default here. A session keeps its last response for the repeat, up to `FRONTED_KEPT` bytes, so a full pool of 4,096 holds 256 MiB of them, which a host with 1 GB does not carry next to everything else. The default is 1,024, which is 64 MiB when full, and a pool above `LARGE_FRONTED_SESSIONS` is a warning that says what it holds.
pub const MAX_PROXY_CONNECTIONS: u32 = 65536;
pub const MAX_FRONTED_SESSIONS: u32 = 65536;
pub const DEFAULT_FRONTED_SESSIONS: u32 = 1024;
/// Shapes page, "Numbers that are judgement calls": "Shaped sessions: 256 per listen address, counted among the 1,024 `fronted` sessions. Validation warns above 256." and "Memory of one shaped session: at most 603,136 bytes".
pub const DEFAULT_SHAPED_SESSIONS: u32 = 256;
pub const SHAPED_SESSION_BYTES: u64 = 603_136;
pub const LARGE_FRONTED_SESSIONS: u32 = 4096;
pub const FRONTED_KEPT: u64 = 65536;
pub const MAX_DECOY_REQUESTS: u32 = 65536;
pub const DEFAULT_DECOY_REQUESTS: u32 = 16;
pub const MAX_TRUSTED_PROXIES: usize = 64;
/// "Request path: at least 12 characters."
pub const MIN_PROOF_PATH_BYTES: usize = 12;
pub const MAX_UPGRADE_HEADERS: usize = 16;
pub const MAX_HEADER_NAME_BYTES: usize = 64;
pub const MAX_COOKIE_NAME_BYTES: usize = 32;
/// "The default list is `Server`, `Date` on a `tls` listener."
pub const DEFAULT_UPGRADE_HEADERS: [&str; 2] = ["Server", "Date"];
/// "Validation refuses a list that names" one of these: the fields the node writes itself, and those that would change how the answer is read.
pub const UPGRADE_HEADERS_REFUSED: [&str; 10] = ["upgrade", "connection", "sec-websocket-accept", "set-cookie", "content-length", "transfer-encoding", "content-type", "content-encoding", "trailer", "keep-alive"];
pub const MIN_TCP_IDLE_SECS: u32 = 10;
pub const MAX_TCP_IDLE_SECS: u32 = 86400;
pub const MIN_UDP_IDLE_SECS: u32 = 5;
pub const MAX_UDP_IDLE_SECS: u32 = 3600;
pub const DEFAULT_TCP_IDLE_SECS: u32 = 7200;
pub const DEFAULT_UDP_IDLE_SECS: u32 = 60;
pub const DEFAULT_INTERFACE: &str = "veilway0";
pub const MIN_POOL_PREFIX_V4: u8 = 16;
pub const MAX_POOL_PREFIX_V4: u8 = 30;
pub const MIN_POOL_PREFIX_V6: u8 = 48;
pub const MAX_POOL_PREFIX_V6: u8 = 126;
/// Errors and warnings kept by a report, each. The rest are only counted.
pub const MAX_DIAGNOSTICS: usize = 100;
/// Bytes of an unknown key shown in a diagnostic before it is cut.
pub const MAX_KEY_SHOWN: usize = 64;
/// Distinct combinations of entitlement, groups and inbounds among users that the rule entitlement warning counts over. Above this the warning is skipped, so its cost never grows with users times rules.
pub const MAX_ENTITLEMENT_CLASSES: usize = 4096;
/// Entry comparisons the shadowed rule check may spend before it stops.
pub const SHADOW_BUDGET: usize = 20_000_000;
pub const RESERVED_TAGS: [&str; 8] = ["all", "any", "block", "reject", "drop", "local", "direct", "user"];
/// Not a tag of an inbound: the `ip` entry `tunnel:users` stands for every inbound.
pub const RESERVED_INBOUND_TAG: &str = "users";
/// The schema patterns of a tag and of a user, device or group name.
pub const TAG_PATTERN: &str = "^[a-z0-9][a-z0-9_-]{0,63}$";
pub const NAME_PATTERN: &str = "^[a-z0-9][a-z0-9._-]{0,63}$";
pub const DOMAIN_PATTERN: &str = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$";
/// Ranges an inbound pool must lie inside.
pub const POOL_RANGES: [&str; 5] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"];
/// What the `ip` entry `geoip:private` stands for: every private and special-purpose range.
pub const GEOIP_PRIVATE: [&str; 13] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "fc00::/7", "2001:db8::/32"];

/// One problem: where it is and what was expected there. It never carries a value from the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {pub path: String, pub message: String}

impl fmt::Display for Diagnostic {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if self.path.is_empty() {f.write_str(&self.message)} else {write!(f, "{}: {}", self.path, self.message)}
	}
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
	pub errors: Vec<Diagnostic>,
	pub warnings: Vec<Diagnostic>,
	/// Errors found beyond the first `MAX_DIAGNOSTICS`.
	pub more_errors: usize,
	pub more_warnings: usize,
	/// The shadowed rule check ran out of budget before it compared every pair of rules.
	pub shadow_cut_short: bool,
	/// The file can be read by group or others. Only `load` sets it, next to the warning that says so.
	pub readable: bool,
	/// The revision of the bytes `load` read, for a file that could be read.
	pub revision: Option<Revision>,
}

impl Report {
	pub(crate) fn error(&mut self, path: impl Into<String>, message: impl Into<String>) {
		if self.errors.len() < MAX_DIAGNOSTICS {self.errors.push(Diagnostic {path: path.into(), message: message.into()})} else {self.more_errors += 1}
	}

	pub(crate) fn warning(&mut self, path: impl Into<String>, message: impl Into<String>) {
		if self.warnings.len() < MAX_DIAGNOSTICS {self.warnings.push(Diagnostic {path: path.into(), message: message.into()})} else {self.more_warnings += 1}
	}
}

/// Reads, parses and validates a config file. The config is returned only when the report has no errors. `shadow` also runs the shadowed rule check when there are none.
pub fn load(path: &Path, shadow: bool) -> (Option<Config>, Report) {
	let mut bytes = Vec::new();
	let read = File::open(path).and_then(|file| {
		#[cfg(unix)]
		let readable = file.metadata()?.mode() & 0o044 != 0;
		#[cfg(not(unix))]
		let readable = false;
		file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).map(|_| readable)
	});
	let (readable, revision) = (read.as_ref().is_ok_and(|readable| *readable), read.is_ok().then(|| Revision::of(&bytes)));
	let parsed = read.map_err(|e| Diagnostic {path: String::new(), message: format!("cannot read the config file: {}", e.kind())}).and_then(|_| Config::parse(&bytes));
	let (config, mut report) = match parsed {
		Ok(config) => {
			let report = config.validate(shadow);
			(report.errors.is_empty().then_some(config), report)
		}
		Err(e) => (None, Report {errors: vec![e], ..Report::default()}),
	};
	(report.readable, report.revision) = (readable, revision);
	if readable {report.warning("", "the config file can be read by group or others; `veilway run` refuses that unless started with --allow-readable-config")}
	(config, report)
}

static REPLACING: Mutex<()> = Mutex::new(());

/// Puts a config document in the place of the config file: a temporary file next to it with mode 600, synced, then renamed over it, and the directory synced after that,
/// so a node that is killed halfway starts with the old file or the new one, and a rename that was answered for is still there after a power loss.
/// A path that is a link is followed first: the link stays and the file it names is replaced. The bytes hold keys and passwords.
/// The temporary file has a name of this one write, so two writes never meet in it, and no file is ever removed that this write did not make: a name that is taken is an error. A write that is killed halfway leaves its temporary file behind.
pub fn save(path: &Path, bytes: &[u8]) -> io::Result<()> {
	// Windows refuses with "access denied" or a sharing violation for as long as another write of this file, a reader or a scanner holds it, so what it refuses is tried again for a moment.
	let busy = |e: &io::Error, tries: u32| cfg!(windows) && tries < 400 && (e.kind() == io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(32));
	// Which step refused is in the error: Windows says no more than "access denied".
	let at = |step: &'static str| move |e: io::Error| io::Error::new(e.kind(), format!("{step}: {e}"));
	let mut tries = 0;
	let target = loop {
		match fs::canonicalize(path) {
			Err(e) if e.kind() == io::ErrorKind::NotFound => break path.to_path_buf(),
			Err(e) if busy(&e, tries) => {tries += 1; std::thread::sleep(Duration::from_millis(10))}
			target => break target.map_err(at("resolving the config path"))?,
		}
	};
	let (mut name, mut tmp) = ([0u8; 8], target.clone().into_os_string());
	SystemRandom::new().fill(&mut name).map_err(|_| io::Error::other("the system gave no random name for the temporary file"))?;
	tmp.push(format!(".{}.tmp", name.iter().map(|byte| format!("{byte:02x}")).collect::<String>()));
	let mut options = fs::OpenOptions::new();
	// `create_new` never follows a link and never opens what is already there.
	options.write(true).create_new(true);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
	let mut tries = 0;
	let mut file = loop {
		match options.open(&tmp) {
			Err(e) if busy(&e, tries) => {tries += 1; std::thread::sleep(Duration::from_millis(10))}
			opened => break opened.map_err(at("creating the temporary file"))?,
		}
	};
	let written = file.write_all(bytes).map_err(at("writing the temporary file")).and_then(|_| file.sync_all().map_err(at("syncing the temporary file"))).and_then(|_| {
		drop(file);
		// Windows can refuse a rename over a file that another rename is replacing, so the writes of this process take turns here and only the writing of their bytes overlaps. A write of another process can still meet this one, and then the retry is what gets through.
		let _turn = REPLACING.lock().unwrap_or_else(|e| e.into_inner());
		let mut tries = 0;
		loop {
			match fs::rename(&tmp, &target) {
				Err(e) if busy(&e, tries) => {tries += 1; std::thread::sleep(Duration::from_millis(10))}
				done => break done.map_err(at("replacing the config file")),
			}
		}
	});
	if written.is_err() {
		let _ = fs::remove_file(&tmp);
		return written;
	}
	#[cfg(unix)]
	File::open(target.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
	Ok(())
}

/// A new device transport secret as a config writes it: 32 bytes from the system's secure random source, in base64. One goes into `transport_secrets` of a device and into that device's profile, and nowhere else.
pub fn transport_secret() -> io::Result<String> {
	let mut secret = [0u8; 32];
	SystemRandom::new().fill(&mut secret).map_err(|_| io::Error::other("the system gave no random bytes"))?;
	Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret))
}

/// The system's secure random source in the shape `veilway-proto` takes one, for whoever pairs a node link from here.
pub fn random(bytes: &mut [u8]) -> Result<(), veilway_proto::NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| veilway_proto::NoRandom)}

/// A new node transport key as a config writes it, and its public half as a profile carries it: an X25519 key from the system's secure random source, in base64. The private half goes into `transport_keys` of one inbound of one node, and nowhere else.
pub fn transport_key() -> io::Result<(String, String)> {
	let mut key = [0u8; 32];
	SystemRandom::new().fill(&mut key).map_err(|_| io::Error::other("the system gave no random bytes"))?;
	let encode = |bytes: &[u8; 32]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
	Ok((encode(&key), encode(&veilway_proto::proof::public_key(&key))))
}

/// Whether a connection to a decoy origin at `origin` arrives at a stream listener of the node at `listen`: the same address and port, or one of them the wildcard and the other an address of this host for certain (loopback, or the wildcard, which a connect takes for this host). An address written as IPv4 inside IPv6 is the IPv4 one, and the IPv6 wildcard listens for IPv4 too where the host says so.
/// A wildcard listener does not refuse an origin on another host with the same port: whether an address is this host's is not known here, and such a loop only fails a TLS handshake.
pub fn loops(listen: SocketAddr, origin: SocketAddr) -> bool {
	let ((here, there), local) = ((listen.ip().to_canonical(), origin.ip().to_canonical()), |ip: IpAddr| ip.is_loopback() || ip.is_unspecified());
	listen.port() == origin.port() && (here == there || (here.is_unspecified() && local(there) || there.is_unspecified() && local(here)) && (here.is_ipv4() == there.is_ipv4() || here == IpAddr::V6(Ipv6Addr::UNSPECIFIED)))
}

/// The JSON Schema of config version 1, as committed in `schema/config.v1.json`.
pub fn schema() -> String {
	let mut schema = SchemaSettings::draft2020_12().into_generator().into_root_schema_for::<Config>();
	// An optional key is left out, never null, so the null alternative schemars adds for every Option is removed.
	RecursiveTransform(|schema: &mut Schema| {
		let Some(object) = schema.as_object_mut() else {return};
		if let Some(Value::Array(types)) = object.get_mut("type") {
			types.retain(|t| t != "null");
			if let [only] = types.as_slice() {
				let only = only.clone();
				object.insert("type".to_string(), only);
			}
		}
		if let Some(Value::Array(any)) = object.get_mut("anyOf") {
			any.retain(|s| s.get("type").is_none_or(|t| t != "null"));
			if let [Value::Object(only)] = any.as_slice() {
				let only = only.clone();
				object.remove("anyOf");
				object.extend(only);
			}
		}
		// A list never holds the same entry twice, except a range of two numbers (`[low, high]` of a shape), whose ends may be equal, and a reserved word is never a tag, wherever a tag is written.
		let range = object.get("minItems") == Some(&json!(2)) && object.get("maxItems") == Some(&json!(2)) && object.get("items").and_then(|items| items.get("type")).is_some_and(|t| t == "integer");
		if object.get("type").is_some_and(|t| t == "array") && !range {object.insert("uniqueItems".to_string(), Value::Bool(true));}
		if object.get("pattern").is_some_and(|p| p == TAG_PATTERN) {object.insert("not".to_string(), json!({"enum": RESERVED_TAGS}));}
	}).transform(&mut schema);
	if let Some(Value::Array(reserved)) = schema.pointer_mut("/$defs/Inbound/properties/tag/not/enum") {reserved.push(json!(RESERVED_INBOUND_TAG))}
	format!("{:#}\n", schema.as_value())
}
