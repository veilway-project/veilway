//! Config version 1: the typed model, strict parsing, validation and reloading. `crate::engine` compiles a validated document into its plan.
mod model;
mod parse;
mod reload;
mod validate;

pub use model::*;
pub(crate) use model::domain;
pub use reload::*;
use schemars::generate::SchemaSettings;
use schemars::transform::{RecursiveTransform, Transform};
use schemars::Schema;
use serde_json::{json, Value};
use std::fmt;
use std::fs::File;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const VERSION: u64 = 1;
pub const MAX_FILE_BYTES: u64 = 64 << 20;
/// JSON values (scalars, lists and objects) in one document. Each costs memory however short its text is, so the file size alone is no bound.
pub const MAX_JSON_NODES: usize = 8_000_000;
pub const MAX_INBOUNDS: usize = 64;
pub const MAX_TRANSPORTS: usize = 8;
pub const MAX_OUTBOUNDS: usize = 256;
pub const MAX_EXITS: usize = 256;
pub const MAX_GROUPS: usize = 256;
pub const MAX_RULES: usize = 4096;
pub const MAX_RULE_ENTRIES: usize = 1024;
pub const MAX_USERS: usize = 65536;
pub const MAX_DEVICES: usize = 16;
pub const MAX_DEVICE_ADDRESSES: usize = 16;
pub const MAX_DNS_SERVERS: usize = 4;
pub const MAX_INBOUND_ADDRESSES: usize = 2;
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
		// A list never holds the same entry twice, and a reserved word is never a tag, wherever a tag is written.
		if object.get("type").is_some_and(|t| t == "array") {object.insert("uniqueItems".to_string(), Value::Bool(true));}
		if object.get("pattern").is_some_and(|p| p == TAG_PATTERN) {object.insert("not".to_string(), json!({"enum": RESERVED_TAGS}));}
	}).transform(&mut schema);
	if let Some(Value::Array(reserved)) = schema.pointer_mut("/$defs/Inbound/properties/tag/not/enum") {reserved.push(json!(RESERVED_INBOUND_TAG))}
	format!("{:#}\n", schema.as_value())
}
