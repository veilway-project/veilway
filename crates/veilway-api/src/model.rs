//! What the API says, as types: every response body and every event payload, and the one request body that is no config document. The OpenAPI document is generated from these, so a field that is added here is in the document.
//! None of them has a field for a secret, a destination or a DNS name.
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeMap;
use veilway_core::config::{self, Key, QuotaPeriod};
use veilway_core::{CutOff, Totals};

/// A public key the way a config writes it.
pub(crate) fn key(public: &Key) -> String {serde_json::to_value(public).ok().and_then(|key| key.as_str().map(str::to_string)).unwrap_or_default()}

/// The one shape of every answer that is not a success.
#[derive(Serialize, JsonSchema)]
pub struct ErrorBody {pub error: Failure}

#[derive(Serialize, JsonSchema)]
pub struct Failure {
	/// Stable, for programs.
	pub code: String,
	/// One plain sentence, for people.
	pub message: String,
	/// For a config that was refused, every error with the path of its field. For a stale revision, one entry with the path `revision` and the revision that runs.
	pub details: Vec<Problem>,
}

/// One problem of a config document: where it is and what was expected there. It never holds a value from the document.
#[derive(Serialize, JsonSchema)]
pub struct Problem {pub path: String, pub message: String}

#[derive(Serialize, JsonSchema)]
pub struct Report {
	pub errors: Vec<Problem>,
	pub warnings: Vec<Problem>,
	/// Errors beyond the first hundred, which are only counted.
	pub more_errors: usize,
	pub more_warnings: usize,
	/// The check for rules covered by an earlier rule stopped at its budget.
	pub shadow_cut_short: bool,
}

impl From<&config::Report> for Report {
	fn from(report: &config::Report) -> Report {
		let problems = |list: &[config::Diagnostic]| list.iter().map(|problem| Problem {path: problem.path.clone(), message: problem.message.clone()}).collect();
		Report {errors: problems(&report.errors), warnings: problems(&report.warnings), more_errors: report.more_errors, more_warnings: report.more_warnings, shadow_cut_short: report.shadow_cut_short}
	}
}

/// Tags or names of one kind.
#[derive(Serialize, JsonSchema)]
pub struct Changes {pub added: Vec<String>, pub changed: Vec<String>, pub removed: Vec<String>}

impl From<&config::Changes> for Changes {
	fn from(changes: &config::Changes) -> Changes {Changes {added: changes.added.clone(), changed: changes.changed.clone(), removed: changes.removed.clone()}}
}

#[derive(Serialize, JsonSchema)]
pub struct InboundChange {
	pub tag: String,
	/// The tunnel restarts and every session of it drops.
	pub restart: bool,
	/// Indexes into the transports of the running inbound.
	pub transports_stopped: Vec<usize>,
	/// Indexes into the transports of the new inbound.
	pub transports_started: Vec<usize>,
}

/// Devices are named by their public key.
#[derive(Serialize, JsonSchema)]
pub struct UserChange {
	pub name: String,
	pub devices_added: Vec<String>,
	pub devices_removed: Vec<String>,
	pub devices_readdressed: Vec<String>,
	pub devices_rekeyed: Vec<String>,
	/// The user could connect and no longer can.
	pub lost_access: bool,
}

/// What an apply adds, changes and removes, by tag and name.
#[derive(Serialize, JsonSchema)]
pub struct Diff {
	pub inbounds: Changes,
	pub outbounds: Changes,
	pub exits: Changes,
	pub rules: Changes,
	pub users: Changes,
	pub dns: bool,
	pub log: bool,
	pub routing_default: bool,
	pub rules_reordered: bool,
	pub inbound_changes: Vec<InboundChange>,
	pub user_changes: Vec<UserChange>,
}

impl From<&config::Diff> for Diff {
	fn from(diff: &config::Diff) -> Diff {
		let keys = |list: &[Key]| list.iter().map(key).collect();
		Diff {
			inbounds: (&diff.inbounds).into(),
			outbounds: (&diff.outbounds).into(),
			exits: (&diff.exits).into(),
			rules: (&diff.rules).into(),
			users: (&diff.users).into(),
			dns: diff.dns,
			log: diff.log,
			routing_default: diff.routing_default,
			rules_reordered: diff.rules_reordered,
			inbound_changes: diff.inbound_changes.iter().map(|change| InboundChange {tag: change.tag.clone(), restart: change.restart, transports_stopped: change.transports_stopped.clone(), transports_started: change.transports_started.clone()}).collect(),
			user_changes: diff.user_changes.iter().map(|change| UserChange {name: change.name.clone(), devices_added: keys(&change.devices_added), devices_removed: keys(&change.devices_removed), devices_readdressed: keys(&change.devices_readdressed), devices_rekeyed: keys(&change.devices_rekeyed), lost_access: change.lost_access}).collect(),
		}
	}
}

/// A config version 1 document. Its own schema is `schema/config.v1.json`, with one difference: here every secret (`private_key`, `preshared_key`, `username`, `password`) may hold the marker `<redacted>`.
#[derive(Serialize)]
#[serde(transparent)]
pub struct Document(pub Value);

impl JsonSchema for Document {
	fn schema_name() -> Cow<'static, str> {"Document".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "object", "description": "A config version 1 document, see schema/config.v1.json. In an answer every secret (private_key, preshared_key, username, password) holds the marker \"<redacted>\". In a request the marker stands for the value the same object has in the running config: the inbound with that tag, the device with that public_key, the socks5 outbound with that tag and that server. An outbound whose server is new or has changed needs its username and password written out."})}
}

#[derive(Serialize, JsonSchema)]
pub struct Status {
	pub version: String,
	/// Starts at 1 and grows by one with every config that is put in force.
	pub generation: u64,
	/// What `If-Match` takes: 64 hex digits that name the bytes of the running config. Only this run of the node gives them this name: nobody else can work it out from a document, and after a restart the same config has another one.
	pub revision: String,
	pub uptime_secs: u64,
	pub inbounds: usize,
	pub exits: usize,
	pub users: usize,
	/// Flows in the flow table right now.
	pub flows: usize,
}

#[derive(Serialize, JsonSchema)]
pub struct Running {pub revision: String, pub generation: u64, pub document: Document}

#[derive(Serialize, JsonSchema)]
pub struct Validation {pub valid: bool, pub report: Report}

#[derive(Serialize, JsonSchema)]
pub struct Difference {
	pub valid: bool,
	pub report: Report,
	/// Against the running config. Null for a document that is not valid.
	pub diff: Option<Diff>,
}

#[derive(Serialize, JsonSchema)]
pub struct Applied {
	pub revision: String,
	pub generation: u64,
	/// False when the config is in force and could not be written to the config file: a restart would come back with the config before. Sending the same document again tries the write again.
	/// A write that was given up on after 10 seconds is not stopped, so the file may still come to hold this config. It never goes back to an older one.
	pub saved: bool,
	/// Why the write failed, as the system names it.
	pub save_error: Option<String>,
	pub diff: Diff,
	/// The warnings of the config that is now in force.
	pub report: Report,
}

/// Inner IP packets and their bytes since the node first knew the name. Up is from the device into the node.
#[derive(Serialize, JsonSchema)]
pub struct Traffic {pub up_bytes: u64, pub up_packets: u64, pub down_bytes: u64, pub down_packets: u64}

impl From<Totals> for Traffic {
	fn from(totals: Totals) -> Traffic {Traffic {up_bytes: totals.up_bytes, up_packets: totals.up_packets, down_bytes: totals.down_bytes, down_packets: totals.down_packets}}
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Denied {Disabled, Expired, Quota}

#[derive(Serialize, JsonSchema)]
pub struct Device {
	pub name: String,
	pub public_key: String,
	pub addresses: Vec<String>,
	/// Seconds since the session the device has was made. Null without a session.
	pub handshake_age_secs: Option<u64>,
}

#[derive(Serialize, JsonSchema)]
pub struct User {
	pub name: String,
	pub enabled: bool,
	/// Why the user cannot connect right now. Null for a user who can.
	pub denied: Option<Denied>,
	pub expires_at: Option<String>,
	pub quota_bytes: Option<u64>,
	pub quota_period: Option<QuotaPeriod>,
	/// Bytes in both directions since `period_start`, which is what `quota_bytes` is held against.
	pub used_bytes: u64,
	/// When the count last started over, in Unix seconds. 0 for a user who never had a `quota_period`, or who had none when their usage was last reset.
	pub period_start: i64,
	/// The tag of the DNS set that names the user, or else one of their groups. Null when no set does: the user's queries then go to the set that names the inbound they come through, or to `dns.servers`.
	pub dns_set: Option<String>,
	pub traffic: Traffic,
	pub devices: Vec<Device>,
}

#[derive(Serialize, JsonSchema)]
pub struct Users {pub users: Vec<User>}

/// The body of a usage reset. A request without a body is one with every field left out.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetUsage {#[serde(default)] pub totals: bool}

// Written out by hand: the generator describes what the node writes, where a field is always there, and this is something the node reads, where it may be left out.
impl JsonSchema for ResetUsage {
	fn schema_name() -> Cow<'static, str> {"ResetUsage".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "object", "description": "What a usage reset zeroes besides the quota count. The body may be left out altogether.", "properties": {"totals": {"type": "boolean", "default": false, "description": "Whether traffic, what the user sent and received in all, goes back to zero as well. Left out or false, only used_bytes and period_start start over."}}, "additionalProperties": false})}
}

/// The counters of one user, inbound or exit, with how fast they grew over the last seconds.
#[derive(Serialize, JsonSchema)]
pub struct Rated {
	/// The user's name, or the tag of the inbound or exit.
	pub name: String,
	pub traffic: Traffic,
	pub up_bytes_per_sec: u64,
	pub down_bytes_per_sec: u64,
}

/// What the node's resolver did with the DNS queries of its tunnels since start.
#[derive(Serialize, JsonSchema)]
pub struct Dns {pub answered: u64, pub refused: u64, pub failed: u64, pub malformed: u64, pub throttled: u64}

#[derive(Serialize, JsonSchema)]
pub struct Stats {
	/// The seconds the rates were taken over: 5 once the node has run that long, 0 before its second sample.
	pub window_secs: u64,
	pub users: Vec<Rated>,
	pub inbounds: Vec<Rated>,
	pub exits: Vec<Rated>,
	/// Packets that were not carried since start, by reason.
	pub drops: BTreeMap<String, u64>,
	pub dns: Dns,
	pub flows: usize,
	/// WebSocket connections dropped because they never finished the upgrade, and refused at accept.
	pub ws_stalled: u64,
	pub ws_refused: u64,
	/// Writes of the usage state file that failed since start.
	pub state_write_failures: u64,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {Udp, Ws}

/// A device with a live session on one inbound. The address the device connects from is not part of it.
#[derive(Serialize, JsonSchema)]
pub struct Session {
	pub user: String,
	pub device: String,
	pub public_key: String,
	pub inbound: String,
	/// Null when the transport the device came over is gone.
	pub transport: Option<Transport>,
	pub handshake_age_secs: u64,
	/// The flows of the device, through all its inbounds together.
	pub flows: usize,
}

#[derive(Serialize, JsonSchema)]
pub struct Sessions {pub sessions: Vec<Session>}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Backend {Netstack, L3, Block}

#[derive(Serialize, JsonSchema)]
pub struct Exit {
	pub tag: String,
	pub name: String,
	pub backend: Backend,
	/// The tag of the outbound of a netstack backend.
	pub outbound: Option<String>,
	/// Whether the SOCKS5 proxy of the exit relays UDP as far as the node knows. Null for an exit without one.
	pub udp: Option<bool>,
	/// Seconds since the proxy last refused to relay UDP. The node tries again once a minute. Null while `udp` is not false.
	pub udp_down_secs: Option<u64>,
	/// How often the proxy switched between relaying UDP and not.
	pub udp_flips: u64,
	/// Whether the interface of an l3 backend is up. While it is not, what is routed to the exit is answered as unreachable and the node tries to bring the interface up again: 2 seconds after it went down, then after twice the wait each time, once a minute at most. Null for any other backend.
	pub interface_up: Option<bool>,
	/// Seconds since the interface went down. Null while `interface_up` is not false.
	pub interface_down_secs: Option<u64>,
	/// How often the interface switched between up and down.
	pub interface_flips: u64,
	pub traffic: Traffic,
}

#[derive(Serialize, JsonSchema)]
pub struct Exits {pub exits: Vec<Exit>}

/// The data of a `config_applied` event.
#[derive(Serialize, JsonSchema)]
pub struct ConfigApplied {pub generation: u64, pub revision: String, pub diff: Diff}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stage {Validate, Prepare}

/// The data of a `config_refused` event: a reload or an apply that left the running config in force.
#[derive(Serialize, JsonSchema)]
pub struct ConfigRefused {pub stage: Stage, pub errors: usize}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reason {Disabled, Expired, Quota, Removed}

impl From<CutOff> for Reason {
	fn from(reason: CutOff) -> Reason {
		match reason {
			CutOff::Disabled => Reason::Disabled,
			CutOff::Expired => Reason::Expired,
			CutOff::Quota => Reason::Quota,
			CutOff::Removed => Reason::Removed,
		}
	}
}

/// The data of a `user_cut_off` event.
#[derive(Serialize, JsonSchema)]
pub struct UserCutOff {pub user: String, pub reason: Reason}

/// The data of a `user_restored` event.
#[derive(Serialize, JsonSchema)]
pub struct UserRestored {pub user: String}

/// The data of a `usage_reset` event: the user's quota count was started over through the API, and with `totals` their traffic counters went back to zero as well. A user who was out of quota gets a `user_restored` right behind it.
#[derive(Serialize, JsonSchema)]
pub struct UsageReset {pub user: String, pub totals: bool}

/// The data of an `exit_udp_changed` event.
#[derive(Serialize, JsonSchema)]
pub struct ExitUdpChanged {pub exit: String, pub udp: bool}

/// The data of a `lagged` event: this many events, the ones whose ids are missing before the next event, never reached the reader. It was too slow for them, or the node made them faster than it keeps them for anybody. It has no id.
#[derive(Serialize, JsonSchema)]
pub struct Lagged {pub missed: u64}
