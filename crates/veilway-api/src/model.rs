//! What the API says, as types: every response body and every event payload, and the one request body that is no config document. The OpenAPI document is generated from these, so a field that is added here is in the document.
//! None of them has a field for a secret, a destination or a DNS name.
use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::BTreeMap;
use veilway_core::config::{self, Key, QuotaPeriod};
use veilway_core::engine::upstream::{Phase, Report as Carrying, Reviewing};
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
	/// Kept devices whose transport secrets changed.
	pub devices_secrets_changed: Vec<String>,
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
	pub notices: bool,
	pub public_addresses: bool,
	/// `replay` changed. The rate per source is in force at once, the cache size from the next start of the node.
	pub replay: bool,
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
			notices: diff.notices,
			public_addresses: diff.public_addresses,
			replay: diff.replay,
			inbound_changes: diff.inbound_changes.iter().map(|change| InboundChange {tag: change.tag.clone(), restart: change.restart, transports_stopped: change.transports_stopped.clone(), transports_started: change.transports_started.clone()}).collect(),
			user_changes: diff.user_changes.iter().map(|change| UserChange {name: change.name.clone(), devices_added: keys(&change.devices_added), devices_removed: keys(&change.devices_removed), devices_readdressed: keys(&change.devices_readdressed), devices_rekeyed: keys(&change.devices_rekeyed), devices_secrets_changed: keys(&change.devices_secrets_changed), lost_access: change.lost_access}).collect(),
		}
	}
}

/// A config version 1 document. Its own schema is `schema/config.v1.json`, with one difference: here every secret (`private_key`, `preshared_key`, `username`, `password`, `proxy_password`) may hold the marker `<redacted>`, and every entry of `transport_secrets` a marker that names it, `<redacted:` with eight hex digits and `>`.
#[derive(Serialize)]
#[serde(transparent)]
pub struct Document(pub Value);

impl JsonSchema for Document {
	fn schema_name() -> Cow<'static, str> {"Document".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "object", "description": "A config version 1 document, see schema/config.v1.json. In an answer every secret (private_key, preshared_key, username, password, proxy_password) holds the marker \"<redacted>\", and every entry of transport_secrets holds a marker that names it, \"<redacted:\" with eight hex digits and \">\". In a request a marker stands for the value the same object has in the running config: the inbound with that tag, the device with that public_key, the socks5 outbound with that tag and that server, the user with that name (proxy_password). A marker in transport_secrets stands for the secret of that device which it names, wherever it is in the list: an entry that is left out is removed, and a marker that names no secret of the device is an error. An outbound whose server is new or has changed needs its username and password written out."})}
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
	/// The certificate of every `tls` transport, one for each listen address, with its pin: the ones the node made for transports with `"self_signed": true` (`self_signed` true), and the ones read from the `cert` file of the others (`self_signed` false: a chain from an authority, the pin is the second condition). Empty for a node that has none.
	pub certificates: Vec<SelfSigned>,
	/// The node's public addresses, as the config names them: host names or IP addresses, with no port. A profile is given these, each with the port of one of its transports. Empty for a node that names none.
	pub public_addresses: Vec<config::Host>,
	pub addons: Addons,
}

#[derive(Serialize, JsonSchema)]
pub struct Addons {pub xray: XrayAddon}

#[derive(Serialize, JsonSchema)]
pub struct XrayAddon {
	/// Whether the add-on's executable is in the add-on folder.
	pub installed: bool,
	/// The release of Xray-core this node runs.
	pub release: String,
}

/// The certificate of a `tls` listener, with the pin of its key.
#[derive(Serialize, JsonSchema)]
pub struct SelfSigned {
	/// The listen address, as the config writes it.
	pub listen: String,
	/// The SHA-256 of the key's SubjectPublicKeyInfo, in standard base64: the pin a profile's or a link's candidate carries. For a self-signed certificate it stays the same when the certificate is made anew.
	pub pin: String,
	/// True for a certificate the node made itself: the candidate that pins it is marked `self_signed`, and the pin is its only check. False for a certificate from the config's `cert` file: the chain is checked as well and the candidate is not marked `self_signed`.
	pub self_signed: bool,
	/// Unix seconds. For a self-signed certificate the node makes it anew with the same key 20 days before `not_after`.
	pub not_before: i64,
	/// Unix seconds. For a self-signed certificate 80 to 100 days after `not_before`, drawn per certificate, and clients do not check it.
	pub not_after: i64,
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

/// The counters of one outbound: those of the exits that leave through it, added up, with what the node knows of its proxy.
/// The node learns whether a proxy relays UDP once for each exit, from the flows of that exit, so two exits through one proxy can know different things for a while. This is what they know together.
#[derive(Serialize, JsonSchema)]
pub struct OutboundStats {
	/// The tag of the outbound.
	pub name: String,
	/// The sum of `traffic` over the exits whose backend names this outbound, all zero for an outbound no exit uses. It holds everything those exits count, which includes what their `unsupported` policy sent around the proxy with `"direct"`.
	pub traffic: Traffic,
	/// The sums of the rates of those exits.
	pub up_bytes_per_sec: u64,
	pub down_bytes_per_sec: u64,
	/// Whether the SOCKS5 proxy relays UDP as far as the node knows: false while any exit through it was last refused. Null for an outbound that is no SOCKS5 proxy.
	pub udp: Option<bool>,
	/// Seconds since the proxy last refused to relay UDP for any of its exits. Null while `udp` is not false.
	pub udp_down_secs: Option<u64>,
	/// How often the proxy switched between relaying UDP and not, added up over its exits. Exits that learn of one change each count it.
	pub udp_flips: u64,
	/// How long the proxy took to answer the greeting of the last flow that dialled it, in milliseconds. Null for a direct outbound, and until a flow has used the proxy. A reload starts it over.
	pub latency_ms: Option<u64>,
	/// Unix seconds when `latency_ms` was measured.
	pub measured_at: Option<i64>,
	/// Why an `xray` outbound cannot carry a flow now, in words: the add-on is not installed or not running, Xray ended and starts again, or the name of its server does not resolve to an address the node may dial. Every exit through it is down with the same reason. Null while it carries, and for an outbound that is not `xray`.
	pub down_reason: Option<String>,
}

/// What the node's resolver did with the DNS queries of its tunnels since start.
#[derive(Serialize, JsonSchema)]
pub struct Dns {pub answered: u64, pub refused: u64, pub failed: u64, pub malformed: u64, pub throttled: u64}

/// What the control channel of the `veilway` inbounds did since start. Everything but `open` only grows.
#[derive(Serialize, JsonSchema)]
pub struct Control {
	/// TCP connections to the control port that the node took, and those that proved a transport secret of their device.
	pub accepted: u64,
	pub authenticated: u64,
	/// Connections closed for a wrong credential.
	pub auth_failed: u64,
	/// Connections closed for a message that was malformed, not allowed where it came, or outside its bounds.
	pub malformed: u64,
	/// Connections closed because the opening exchange was not done within 10 seconds.
	pub timed_out: u64,
	/// Connections closed to make room for a newer one of the same device.
	pub replaced: u64,
	/// Requests answered "rate limited".
	pub rate_limited: u64,
	/// Exit selections that were taken, that were refused, and that a reload dropped.
	pub exits_selected: u64,
	pub exits_refused: u64,
	pub exits_dropped: u64,
	/// MTU probe runs that were started, probes from devices that were confirmed, probes the node sent, and datagrams to the probe port that were no probe of a live run.
	pub probe_runs: u64,
	pub probes_confirmed: u64,
	pub probes_sent: u64,
	pub probes_refused: u64,
	/// MTUs that devices set.
	pub mtus_set: u64,
	/// `bye` messages written before a cut-off or a stop.
	pub byes: u64,
	/// Authenticated connections open right now.
	pub open: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct Stats {
	/// The seconds the rates were taken over: 5 once the node has run that long, 0 before its second sample.
	pub window_secs: u64,
	pub users: Vec<Rated>,
	pub inbounds: Vec<Rated>,
	pub exits: Vec<Rated>,
	/// Every outbound of the running config, in its order. An exit with an `l3` or `block` backend has no outbound and is in none of them.
	pub outbounds: Vec<OutboundStats>,
	/// Packets that were not carried since start, by reason.
	pub drops: BTreeMap<String, u64>,
	pub dns: Dns,
	pub flows: usize,
	/// WebSocket connections dropped because they never finished the upgrade, and refused at accept.
	pub ws_stalled: u64,
	pub ws_refused: u64,
	/// Writes of the usage state file that failed since start.
	pub state_write_failures: u64,
	/// Datagrams the node made for a device and no socket took, over every transport of every inbound. A socket of a `veilway` inbound never fragments, so a packet larger than the host's interface carries is counted here and not sent: lower the inbound's `mtu` when this grows.
	pub send_failed: u64,
	pub control: Control,
	/// Every tunnel that runs, in the order of the config. A tunnel that a reload changed starts counting over.
	pub tunnels: Vec<TunnelStats>,
	/// Every proxy inbound (`socks5`, `http`, `mixed`) that runs, in the order of the config. An inbound that a reload changed starts counting over. Its bytes are in `inbounds` as well.
	pub proxies: Vec<ProxyStats>,
	pub udp_obfs: UdpObfs,
	pub stream: Stream,
	/// The replay memory of the obfuscated transports. Null for a node that never ran one, which keeps no replay memory.
	pub replay: Option<Replay>,
}

/// What the stream listeners of the `tls` transports, and of the `ws` and `fronted` transports of `veilway` inbounds, did since start, and what they hold right now. Everything but `undecided`, `relayed`, `pending`, `sessions`, `proxies`, `decoys` and `fronted` only grows. Whoever is not a user gets the decoy origin's answer whatever the reason, and no reason holds an address, a path, a token or a key.
#[derive(Serialize, JsonSchema)]
pub struct Stream {
	/// Connections that have not been decided yet, right now: inside their TLS handshake or their request line.
	pub undecided: usize,
	/// Connections that are relayed to a decoy origin right now.
	pub relayed: usize,
	/// Sessions whose proof was accepted and on which WireGuard has not authenticated yet, right now.
	pub pending: usize,
	/// Established sessions right now.
	pub sessions: usize,
	/// Connections the listeners took from the system, and failures to take one, which is what a host that is out of file descriptors shows.
	pub accepted: u64,
	pub accept_failed: u64,
	/// Connections that broke before they were decided, with an error that is no close: a reset inside the request line, or a connection whose own address could not be read.
	pub broken: u64,
	/// TLS handshakes that failed, that did not finish within 10 seconds, and that were closed to make room in the undecided pool.
	pub handshake_failed: u64,
	pub handshake_slow: u64,
	pub handshake_displaced: u64,
	/// Connections decided "not a user", by the class of the reason: a byte that cannot be part of a user's request line or a line above 4,096 bytes, `stranger_syntax`. A line that was not complete within 10 seconds, `stranger_slow`. A peer that closed its side first, `stranger_closed`. A connection decided at once to make room in the undecided pool, `stranger_displaced`. A connection whose decoy origin said something or closed while the request line was not complete, `stranger_origin`. A complete request line that is no proof of a device, `stranger_proof`, which is where a wrong path, a wrong token and a removed device are counted alike.
	pub stranger_syntax: u64,
	pub stranger_slow: u64,
	pub stranger_closed: u64,
	pub stranger_displaced: u64,
	pub stranger_origin: u64,
	pub stranger_proof: u64,
	/// Proofs of a device that were refused all the same, each of which took the decoy path too. By the replay rule: a timestamp outside the window of 60 seconds, at or below the floor, a token that was accepted before, and any while the cache is full.
	pub refused_window: u64,
	pub refused_floor: u64,
	pub refused_seen: u64,
	pub refused_cache_full: u64,
	/// A timestamp above the written limit whose write did not end within 2 seconds or for which 64 other proofs waited already, and proofs that came while the node took none at all.
	pub refused_limit: u64,
	pub refused_no_replay: u64,
	/// By a limit: the listener's session pool is full, the device has 2 pending sessions, or the device's or the source's allowance of accepted proofs is spent.
	pub refused_pool: u64,
	pub refused_pending: u64,
	pub refused_device_rate: u64,
	pub refused_source_rate: u64,
	/// Connections that were connected to a decoy origin and relayed, relayed connections that were closed to make room for another, and strangers that were closed with no answer because the origin could not be reached. While `decoy_down` grows the node can be told from its decoy.
	pub relays: u64,
	pub relays_evicted: u64,
	pub decoy_down: u64,
	/// Proofs that were accepted, proofs that waited for the write of a higher limit, users whose request head was over a limit or no WebSocket upgrade, sessions that became established, and sessions that could not because the session pool had filled up since their proof.
	pub proofs_accepted: u64,
	pub proofs_waited: u64,
	pub head_refused: u64,
	pub established: u64,
	pub establish_full: u64,
	/// Inside sessions: handshake initiations above a session's allowance, datagrams WireGuard did not take as a packet of the session's device, datagrams for a device that were dropped because the send queue of its connection held 256, and chunks the node sent.
	pub handshakes: u64,
	pub tunnel: u64,
	pub queue_full: u64,
	pub chunks_sent: u64,
	/// Sessions that ended, by reason: no WireGuard packet within 10 seconds of the proof, no chunk for 300 seconds, every chunk number used, the device's ninth session, a device or transport secret the config no longer has, a connection that closed or a peer that closed the session, a chunk that did not open or a frame the protocol does not allow, and a transport the config no longer has.
	pub ended_deadline: u64,
	pub ended_idle: u64,
	pub ended_packets: u64,
	pub ended_displaced: u64,
	pub ended_revoked: u64,
	pub ended_closed: u64,
	pub ended_invalid: u64,
	pub ended_unserved: u64,
	/// How often the header fields of the upgrade answer were learnt from a decoy origin, and how often that failed. While the last try failed, the upgrade answer carries only `Date` of `upgrade_headers`.
	pub upgrade_learned: u64,
	pub upgrade_learn_failed: u64,
	/// The proxy path of the `ws` and `fronted` listeners, right now: connections of trusted proxies, requests on them that are in a decoy origin's hands or whose body is still read with nothing proven, and established `fronted` sessions.
	pub proxies: usize,
	pub decoys: usize,
	pub fronted: usize,
	/// Connections taken from a trusted proxy, and requests read on them. `proxy_unnamed` are those of them, on a listener with a `client_address_header`, in which that header named no source: the proxy itself stood for the visitor, so the limits per source were one limit for all of them. `proxy_idle` are connections closed after 300 seconds without a request.
	pub proxy_accepted: u64,
	pub proxy_requests: u64,
	pub proxy_unnamed: u64,
	pub proxy_idle: u64,
	/// Requests handed to a decoy origin on the proxy path. `forwards_unframed` are those of them the node could not tell the end of, which it relayed to the end of the origin's answer and then closed the proxy's connection behind. `forwards_cut` are connections closed at once because one source had more than its share of requests waiting, or all strangers together more than half the proxy pool.
	pub forwards: u64,
	pub forwards_unframed: u64,
	pub forwards_cut: u64,
	/// Requests of the proxy path decided "not a user" for a reason only that path has: a head above 16,384 bytes or not complete within 10 seconds, a `fronted` request that names a session with a number out of order or while another request of it is in flight, one whose body was late, did not open or was a repeat with other bytes, and an opening request whose session no WireGuard packet established.
	pub stranger_head: u64,
	pub stranger_session: u64,
	pub stranger_body: u64,
	pub stranger_unestablished: u64,
	/// `fronted` requests that were accepted, and repeats of the last accepted request that were answered with the stored response.
	pub polls: u64,
	pub poll_repeats: u64,
	/// Requests of trusted proxies that were HTTP/1.0. None of them can be a user's: a web server that speaks HTTP/1.0 to the node shuts every user out, and has to be told to speak HTTP/1.1.
	pub proxy_http10: u64,
	/// Requests that were sent to a decoy origin once more on a new connection, because the connection kept from the request before had been closed by the origin. `origin_dropped` are connections to a decoy origin that the node dropped between two requests because the origin said something or closed them there: nothing of that is passed on to the proxy.
	pub forwards_redialed: u64,
	pub origin_dropped: u64,
	/// `fronted-shaped` sessions that are established right now (`fronted` counts them as well), and event streams that are live right now.
	pub shaped: usize,
	pub streams: usize,
	/// `fronted-shaped` requests that were accepted, repeats of one answered with its stored answer, repeats answered with the late answer of 80 bytes, event streams that were started, events and heartbeats written to them, and stream requests that their session's allowance of 4 at once and 1 a second had no room for.
	pub shaped_polls: u64,
	pub shaped_repeats: u64,
	pub shaped_late: u64,
	pub shaped_streams: u64,
	pub shaped_events: u64,
	pub shaped_beats: u64,
	pub shaped_limited: u64,
}

impl From<veilway_core::StreamTotals> for Stream {
	fn from(totals: veilway_core::StreamTotals) -> Stream {
		Stream {
			undecided: totals.undecided, relayed: totals.relayed, pending: totals.pending, sessions: totals.sessions, accepted: totals.accepted, accept_failed: totals.accept_failed, broken: totals.broken, handshake_failed: totals.handshake_failed, handshake_slow: totals.handshake_slow, handshake_displaced: totals.handshake_displaced,
			stranger_syntax: totals.stranger_syntax, stranger_slow: totals.stranger_slow, stranger_closed: totals.stranger_closed, stranger_displaced: totals.stranger_displaced, stranger_origin: totals.stranger_origin, stranger_proof: totals.stranger_proof,
			refused_window: totals.refused_window, refused_floor: totals.refused_floor, refused_seen: totals.refused_seen, refused_cache_full: totals.refused_cache_full, refused_limit: totals.refused_limit, refused_no_replay: totals.refused_no_replay, refused_pool: totals.refused_pool, refused_pending: totals.refused_pending, refused_device_rate: totals.refused_device_rate, refused_source_rate: totals.refused_source_rate,
			relays: totals.relays, relays_evicted: totals.relays_evicted, decoy_down: totals.decoy_down, proofs_accepted: totals.proofs_accepted, proofs_waited: totals.proofs_waited, head_refused: totals.head_refused, established: totals.established, establish_full: totals.establish_full,
			handshakes: totals.handshakes, tunnel: totals.tunnel, queue_full: totals.queue_full, chunks_sent: totals.chunks_sent,
			ended_deadline: totals.ended_deadline, ended_idle: totals.ended_idle, ended_packets: totals.ended_packets, ended_displaced: totals.ended_displaced, ended_revoked: totals.ended_revoked, ended_closed: totals.ended_closed, ended_invalid: totals.ended_invalid, ended_unserved: totals.ended_unserved,
			upgrade_learned: totals.upgrade_learned, upgrade_learn_failed: totals.upgrade_learn_failed,
			proxies: totals.proxies, decoys: totals.decoys, fronted: totals.fronted, proxy_accepted: totals.proxy_accepted, proxy_requests: totals.proxy_requests, proxy_unnamed: totals.proxy_unnamed, proxy_idle: totals.proxy_idle, forwards: totals.forwards, forwards_unframed: totals.forwards_unframed, forwards_cut: totals.forwards_cut,
			stranger_head: totals.stranger_head, stranger_session: totals.stranger_session, stranger_body: totals.stranger_body, stranger_unestablished: totals.stranger_unestablished, polls: totals.polls, poll_repeats: totals.poll_repeats,
			proxy_http10: totals.proxy_http10, forwards_redialed: totals.forwards_redialed, origin_dropped: totals.origin_dropped,
			shaped: totals.shaped, streams: totals.streams, shaped_polls: totals.shaped_polls, shaped_repeats: totals.shaped_repeats, shaped_late: totals.shaped_late, shaped_streams: totals.shaped_streams, shaped_events: totals.shaped_events, shaped_beats: totals.shaped_beats, shaped_limited: totals.shaped_limited,
		}
	}
}

/// What one proxy inbound counted since it started. Everything but `open` only grows.
#[derive(Serialize, JsonSchema)]
pub struct ProxyStats {
	/// The tag of the inbound.
	pub name: String,
	/// Connections the inbound took, and those open right now.
	pub opened: u64,
	pub open: usize,
	/// Logins that were refused: no such user, a wrong password, a user the inbound does not admit.
	pub refused_logins: u64,
	/// UDP datagrams dropped because they did not come from the address and port the client named for its association, which is what a client behind a NAT that rewrites ports is refused for.
	pub refused_udp_source: u64,
	/// Connections turned away at the inbound's `connections`, at a source's `per_source` and at `handshakes`, and logins refused unheard because a source had failed too many to that name.
	pub refused_limit: u64,
	pub refused_source: u64,
	pub refused_busy: u64,
	pub refused_blocked: u64,
	/// Bytes the clients sent to their destinations and got back.
	pub up_bytes: u64,
	pub down_bytes: u64,
}

/// What one tunnel counted since it started. Everything but `open` only grows.
#[derive(Serialize, JsonSchema)]
pub struct TunnelStats {
	/// The tag of the tunnel.
	pub name: String,
	/// TCP connections or UDP sessions the tunnel took, and those open right now.
	pub opened: u64,
	pub open: usize,
	/// Connections refused (TCP) and datagrams dropped (UDP): from an address in none of `sources`, past `max_connections`, past the 16 of one source, past 8 new ones a second for one source, while the `chain` exit was down, and for want of a translated port.
	pub refused_sources: u64,
	pub refused_limit: u64,
	pub refused_client: u64,
	pub refused_rate: u64,
	pub refused_down: u64,
	pub refused_full: u64,
	/// TCP connections the far side did not open within 10 seconds or refused.
	pub connect_failed: u64,
	/// TCP connections that a reset or the link going down ended, and those closed after an hour with no byte.
	pub reset: u64,
	pub idled: u64,
	/// Packets from the link that a full queue or an unknown session could not take, and datagrams that did not fit the link.
	pub dropped: u64,
	/// Bytes of the clients' own data towards the far side (up) and back (down).
	pub up_bytes: u64,
	pub down_bytes: u64,
	/// Inner IP packets sent into the link and taken out of it for the tunnel.
	pub up_packets: u64,
	pub down_packets: u64,
}

/// What the `udp-obfs` transports did since start, and what they hold right now. Everything but `pending`, `sessions` and `tags` only grows. A datagram that is dropped gets no answer whatever the reason, and no reason holds an address, a tag or a key.
#[derive(Serialize, JsonSchema)]
pub struct UdpObfs {
	/// Sessions whose opening packet was accepted and on which WireGuard has not authenticated yet, right now.
	pub pending: usize,
	/// Established sessions right now, with those that a newer session of the same source replaced and that are still readable for 10 seconds.
	pub sessions: usize,
	/// Epoch tags in the tag tables right now: three for each transport secret of each device that may connect.
	pub tags: usize,
	/// Opening packets that were accepted, and sessions that became established.
	pub opened: u64,
	pub established: u64,
	/// Packets the listeners made for a socket. Every one is a data packet of an established session, so a node that only strangers talk to has 0 here.
	pub sent: u64,
	/// Opening packets that were kept for the write of a higher limit and taken to the replay rule again when it had ended, and opening packets a limit refused whose salt was recorded as spent, so that nobody who saw one can use it later.
	pub waited: u64,
	pub spent: u64,
	/// Datagrams dropped, by reason: shorter than a data packet, `short`. No data packet of a session at its source and a tag that is not in the tag table, `unknown`, which is where every datagram of a stranger is counted. A tag that is in the table on a packet that does not open, `open_failed`: its sender holds a tag of this epoch without the device's secret, or the packet was changed on its way.
	pub short: u64,
	pub unknown: u64,
	pub open_failed: u64,
	/// Opening packets of a device that the replay rule refused: a timestamp outside the window of 60 seconds, at or below the floor, a packet that was accepted before, and any while the cache is full.
	pub window: u64,
	pub floor: u64,
	pub seen: u64,
	pub cache_full: u64,
	/// Opening packets with a timestamp above the written limit that were dropped: the listener already kept 64 others, or no write ended within 2 seconds. And those that came while the node took no proof at all.
	pub limit: u64,
	pub no_replay: u64,
	/// Opening packets refused by a limit: the source has sessions of 4 other devices, the listener's session pool is full, the device has 2 pending sessions, or the device's or the source's allowance of accepted proofs is spent.
	pub source_devices: u64,
	pub pool: u64,
	pub pending_full: u64,
	pub device_rate: u64,
	pub source_rate: u64,
	/// Handshake initiations above a session's allowance, datagrams inside a session that WireGuard did not take as a packet of the session's device, and packets the node could not make.
	pub handshakes: u64,
	pub tunnel: u64,
	pub unsendable: u64,
	/// Sessions that ended, by reason: no WireGuard packet within 10 seconds of the opening packet, no activity for 180 seconds, 2^31 packets sent, a newer session of the same source and device, the device's ninth session, and a device or transport secret the config no longer has.
	pub ended_deadline: u64,
	pub ended_idle: u64,
	pub ended_packets: u64,
	pub ended_replaced: u64,
	pub ended_displaced: u64,
	pub ended_revoked: u64,
	/// How often a tag table was built for a new epoch, how often that was late, how often a build did not end, and tags that were left out because another secret had the same.
	pub table_rebuilds: u64,
	pub table_rebuilds_late: u64,
	pub table_build_failures: u64,
	pub tag_collisions: u64,
}

/// The replay memory of the node. Times are Unix seconds on the node's clock.
#[derive(Serialize, JsonSchema)]
pub struct Replay {
	/// False while no proof is accepted at all: a reset whose file is not known to be on disk.
	pub ready: bool,
	pub clock: u64,
	/// A proof with a timestamp at or below the floor is refused.
	pub floor: u64,
	/// A proof with a timestamp above the limit is not accepted before a higher limit is written.
	pub limit: u64,
	/// The highest limit that may be on disk, which a start after a kill takes as its floor.
	pub disk_limit: u64,
	pub entries: usize,
	pub capacity: usize,
	/// The floor is ahead of the clock in a way no start explains: more than 80 seconds, or risen while the node ran. Every proof of a client with a right clock is refused until the clock passes the floor or the replay memory is reset. After a start or a reset the floor is up to 80 seconds ahead, which is what they cost and is false here.
	pub floor_ahead: bool,
	/// How many seconds the floor is ahead of the clock, whatever the cause: for that long proofs with a right clock are refused. 0 on a node that takes them.
	pub refusing_secs: u64,
	/// Proofs refused at the floor while `floor_ahead` was true.
	pub refused_floor_ahead: u64,
	/// Writes of the replay file that went through, that failed, and that took more than 2 seconds.
	pub writes: u64,
	pub write_failures: u64,
	pub slow_writes: u64,
	/// How often the node brought its own limit down after a clock that had run ahead.
	pub limit_lowered: u64,
	pub resets: u64,
}

impl From<veilway_core::ReplayStatus> for Replay {
	fn from(status: veilway_core::ReplayStatus) -> Replay {Replay {ready: status.ready, clock: status.clock, floor: status.floor, limit: status.limit, disk_limit: status.disk, entries: status.entries, capacity: status.capacity, floor_ahead: status.floor_ahead, refusing_secs: status.wait, refused_floor_ahead: status.refused_floor_ahead, writes: status.writes, write_failures: status.write_failures, slow_writes: status.slow_writes, limit_lowered: status.lowered, resets: status.resets}}
}

/// The transport a device came over, as the config names it: `ws` is the relay of a `wireguard` inbound, and on a `veilway` inbound the native WebSocket session behind the operator's web server.
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {Udp, Ws, #[serde(rename = "udp-obfs")] UdpObfs, Tls, Fronted, #[serde(rename = "fronted-shaped")] FrontedShaped, #[serde(rename = "faketls")] FakeTls, #[serde(rename = "ws-plain")] WsPlain}

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
	/// The exit the device chose on the control channel for the action `"user"`. Null for a device that chose none and leaves through its user's exit.
	pub selected_exit: Option<String>,
	/// The authenticated control connections the device has open.
	pub control_connections: usize,
	/// The MTU the device set on the control channel. Null for a device that set none, whose tunnel has the `mtu` of its inbound.
	pub mtu: Option<u16>,
}

#[derive(Serialize, JsonSchema)]
pub struct Sessions {pub sessions: Vec<Session>}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InboundKind {Wireguard, Veilway}

/// One transport of an inbound, with the rating a profile of it gets.
#[derive(Serialize, JsonSchema)]
pub struct InboundTransport {
	pub transport: Transport,
	/// False for a transport the config switched off: it does not listen.
	pub enabled: bool,
	pub rating: config::Rating,
	/// Only on a `tls` transport that is listening: the SHA-256 of the key's SubjectPublicKeyInfo of its certificate, in standard base64, the pin a link or a profile carries for it.
	pub pin: Option<String>,
	/// Only when the node found that the pin is not the one it served before, for 30 days after: the pin that was served before. A link or a profile that pins it fails until it is paired or refreshed again.
	pub previous_pin: Option<String>,
	/// Unix seconds: when the node found the new key (at a start, a reload or when the certificate file was read again). The node does not refuse the certificate.
	pub key_changed_at: Option<i64>,
}

/// An inbound with what a client profile takes from it. No private key.
#[derive(Serialize, JsonSchema)]
pub struct InboundInfo {
	pub tag: String,
	pub kind: InboundKind,
	/// False for an inbound the config switched off: it does not listen and takes no device.
	pub enabled: bool,
	/// The WireGuard public key of the inbound.
	pub public_key: Key,
	/// The public half of the node transport key a profile carries. Null for an inbound with no `transport_keys`.
	pub transport_public_key: Option<Key>,
	pub transports: Vec<InboundTransport>,
}

#[derive(Serialize, JsonSchema)]
pub struct Inbounds {
	pub inbounds: Vec<InboundInfo>,
	/// The node's public addresses, as `GET /v1/status` gives them.
	pub public_addresses: Vec<config::Host>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Backend {Netstack, L3, Block, Chain, Upstream}

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
	/// The node links of a chain backend, by tag, which `/v1/links` reports on. Empty for every other backend.
	pub links: Vec<String>,
	/// Whether one of those links is up. While none is, what is routed to the exit is answered as unreachable and leaves no other way. Null for every other backend.
	pub link_up: Option<bool>,
	/// How long the proxy of the outbound took to answer the greeting of the last flow that dialled it, in milliseconds. Null for a direct outbound, for an exit with no SOCKS5 outbound, and until a flow has used the proxy. A reload starts it over.
	pub latency_ms: Option<u64>,
	/// Unix seconds when `latency_ms` was measured.
	pub measured_at: Option<i64>,
	/// The `load` setting of the exit in the config. Null when the exit reports no load to apps.
	pub load: Option<veilway_core::config::Load>,
	/// The level apps are told: "low", "medium" or "high". Null while the exit has no `load` setting and until the node has looked twice, which it does every 10 seconds.
	pub load_level: Option<String>,
	pub traffic: Traffic,
}

#[derive(Serialize, JsonSchema)]
pub struct Exits {pub exits: Vec<Exit>}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
	/// A WireGuard handshake completed within the last 180 seconds.
	Up,
	/// The node dials and has no session yet, or it is dialled and has heard no handshake yet.
	Connecting,
	/// The node dials and no candidate of the other node answers.
	Unreachable,
	/// The node dials and the other node answers and does not take the proof.
	Refused,
	/// The node dials and the certificate of the other node has a key that matches none of the pins of the candidate it dialled: the other node has a new key, and the link has to be paired again. It is no network problem.
	PinMismatch,
	/// No handshake for 24 hours, so the other node has ended the link or one of the two is misconfigured, or this node cut the link off for its quota or its expiry (`denied`). A node that dials tries once a day from here on.
	Ended,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkHalf {
	/// This node has the users and sends their packets into the link, through an exit with a chain backend.
	Entry,
	/// What arrives from the link leaves from this node, under its own gate, rules and limits.
	Exit,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkRole {
	/// The link connects to an inbound of this node.
	Listener,
	/// This node dials the other one.
	Dialler,
}

/// Which side of a managed link this node is.
#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkManage {
	/// This node manages the other one.
	Peer,
	/// The other node manages this one.
	ByPeer,
}

/// One node link. It holds no key and no secret.
#[derive(Serialize, JsonSchema)]
pub struct Link {
	pub tag: String,
	pub id: veilway_core::config::LinkId,
	pub half: LinkHalf,
	pub role: LinkRole,
	/// Null for a link that is not managed.
	pub manage: Option<LinkManage>,
	pub state: LinkState,
	/// Seconds the link has been in `state`.
	pub state_secs: u64,
	/// Seconds since the link's tunnel last completed a handshake. Null without a session.
	pub handshake_secs: Option<u64>,
	/// On the node that dials: the transport it is at, and the places of that transport and of its candidate or endpoint in the other node's list, from 0. Null on the node that is dialled.
	pub transport: Option<Transport>,
	pub transport_index: Option<usize>,
	pub candidate_index: Option<usize>,
	/// The system refused an outer packet of the link for its size within the last 600 seconds, which suggests the link's mtu is too high for the path. Anyone on the path can forge such a report, so it only warns.
	pub size_warning: bool,
	/// On the exit half: why this node cut the link off. Null for a link that may run.
	pub denied: Option<Denied>,
	/// On the entry half: the exit with a chain backend the link is behind.
	pub exit: Option<String>,
	/// The flows the link carries: the translations of the entry half, or the flows of the exit half in the flow table.
	pub flows: usize,
	/// Packets that came out of the link and were not carried: on the entry half what answers no flow, on the exit half what the gate, the source check or a limit refused.
	pub dropped: u64,
	/// How often `state` changed.
	pub state_flips: u64,
	/// Inner packets. Up is what this node sent into the link, down what it took out of it.
	pub traffic: Traffic,
	/// What the management connections of the link count. All zero on a link that is not managed.
	pub management: Management,
}

/// The management connections of one link, which carry the control API of the other node, or this node's to it. Everything but `open` only grows, and none of it is in `traffic`'s numbers of a user.
#[derive(Serialize, JsonSchema)]
pub struct Management {
	/// Connections taken, and open now.
	pub opened: u64,
	pub open: u64,
	/// Refused: a fifth connection, a connection attempt from the other node to a node that manages (which has no listener), a node with no control API to serve, and a stray packet.
	pub refused: u64,
	/// Connections that were reset by the other node or got no answer within 10 seconds.
	pub failed: u64,
	/// Connections a reset ended, and those closed after 120 seconds of silence.
	pub reset: u64,
	pub idled: u64,
	/// Packets that a full queue of a connection dropped.
	pub dropped: u64,
	/// Requests turned away because their route or method is not on the list a managed node serves.
	pub denied: u64,
	/// Bytes of the requests this node sent through the link and of the answers it took out of it.
	pub up_bytes: u64,
	pub down_bytes: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct Links {pub links: Vec<Link>}

/// What the operator hands the node to look at the subscription of another provider: the link, and the WireGuard private key and the device secret the panel made for this node's device. The node uses them to fetch and never says them back. `via` is the tag of a `direct` or `socks5` outbound of the running config to reach the provider through, and `allow_private` is the setting the review judges the profiles by.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPreviewRequest {pub link: String, pub private_key: String, pub device_secret: String, #[serde(default)] pub via: Option<String>, #[serde(default)] pub allow_private: bool}

// Written out by hand, like `ResetUsage`: it is read by the node, where a field may be left out.
impl JsonSchema for UpstreamPreviewRequest {
	fn schema_name() -> Cow<'static, str> {"UpstreamPreviewRequest".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "object", "description": "What the node needs to fetch the subscription of another provider with a device the panel made. The key and the secret are used for the fetch and are never in any answer, log or error.", "properties": {
		"link": {"type": "string", "description": "A native veilway://sub/ link. Carried, file, legacy and plain-address forms are refused."},
		"private_key": {"type": "string", "description": "The WireGuard private key of the device, 44 characters of standard base64 as a config writes a key."},
		"device_secret": {"type": "string", "description": "The device secret, 16 bytes as 22 characters of base64url."},
		"via": {"type": "string", "description": "The tag of a direct or socks5 outbound of the running config the provider is reached through. Left out: from the node itself."},
		"allow_private": {"type": "boolean", "default": false, "description": "Whether the node is to be allowed to dial private addresses of the profiles. It decides which profiles the review marks as refused."}
	}, "required": ["link", "private_key", "device_secret"], "additionalProperties": false})}
}

/// The answer to a preview: the document the provider sent, verified under the key of the link, as the operator reads it before saying yes. Fetching it took a place at the provider. The place is given back when the preview is declined or runs out, and made permanent by the config that names the same link and device within `expires_in_secs`.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamPreview {
	pub id: String,
	/// How long the node keeps the document for the config that names it.
	pub expires_in_secs: u64,
	/// The provider's own name for itself, shown as its claim next to the fingerprint.
	pub provider: String,
	/// The fingerprint of the key the document is signed with, which is the one in the link and the one for `signing_key` of the config.
	pub fingerprint: String,
	pub serial: u64,
	/// When the document stops being current, in Unix seconds.
	pub expires_at: i64,
	pub quota: Option<UpstreamQuota>,
	/// When the account ends, in Unix seconds. Null for never or unknown.
	pub account_expires_at: Option<i64>,
	/// How many devices the account may have, null for no limit or unknown, and how many the document lists.
	pub device_limit: Option<u16>,
	pub devices: usize,
	/// The classes of transports the profiles list: the operator's consent is asked for each besides `cover`.
	pub classes: Vec<config::UpstreamClass>,
	pub profiles: Vec<UpstreamProfile>,
}

/// What the provider says an account has used and has. A quota of 0 is none.
#[derive(Default, Serialize, JsonSchema)]
pub struct UpstreamQuota {
	pub used_bytes: u64,
	pub quota_bytes: u64,
	/// What the provider's control channel says besides, once it is open: how often the quota starts over, when the period began and the account ends (Unix seconds), and the bytes of the device's own traffic, up and down.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub period: Option<UpstreamPeriod>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub period_start: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub account_expires_at: Option<i64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub up_bytes: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub down_bytes: Option<u64>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPeriod {None, Daily, Weekly, Monthly}

/// An exit the provider offers, with its name as plain text.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamExitState {
	pub tag: String,
	pub name: String,
	/// Two uppercase letters.
	pub country: Option<String>,
	pub all_protocols: bool,
	/// This node's device has this exit selected at the provider.
	pub selected: bool,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamSeverity {Information, Warning}

/// A notice of the provider, as plain text.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamNotice {pub severity: UpstreamSeverity, pub text: String}

/// A profile of the provider's document and whether this node can use it now. Never an address.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamProfileState {
	pub id: String,
	pub name: String,
	pub usable: bool,
	/// Plain words for why not. Empty when it is usable.
	pub reason: String,
}

/// What the config chooses on an upstream: null is automatic.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamChoiceState {
	pub profile: Option<String>,
	pub failover: bool,
	pub transport: Option<String>,
	/// The exit of the provider that is asked for now, which may be one the operator just switched to.
	pub exit: Option<String>,
}

/// One profile of a provider's document.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamProfile {
	pub id: String,
	pub name: String,
	/// In the provider's order.
	pub transports: Vec<Transport>,
	pub classes: Vec<config::UpstreamClass>,
	/// What a censor can see, worked out by the node.
	pub rating: config::Rating,
	/// Private addresses the profile names to dial.
	pub private_addresses: Vec<String>,
	pub mtu: u16,
	/// The exits the provider lists for the profile, by tag and name.
	pub exits: Vec<UpstreamExit>,
	/// Why this node would not use the profile under the request's settings. Null when it would.
	pub refused: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct UpstreamExit {pub tag: String, pub name: String}

/// The kind of transport the node's names for a transport of a document stand for.
fn transport_of(name: &str) -> Transport {
	match name {
		"udp" => Transport::Udp,
		"udp-obfs" => Transport::UdpObfs,
		"tls" => Transport::Tls,
		"ws" => Transport::Ws,
		"fronted" => Transport::Fronted,
		"fronted-shaped" => Transport::FrontedShaped,
		"faketls" => Transport::FakeTls,
		_ => Transport::WsPlain,
	}
}

impl From<&Reviewing> for UpstreamPreview {
	fn from(reviewing: &Reviewing) -> UpstreamPreview {
		UpstreamPreview {
			id: reviewing.id.clone(), expires_in_secs: reviewing.ttl.as_secs(), provider: reviewing.provider.clone(), fingerprint: reviewing.fingerprint.clone(), serial: reviewing.serial,
			expires_at: reviewing.expires_at as i64,
			quota: reviewing.quota.map(|(used_bytes, quota_bytes)| UpstreamQuota {used_bytes, quota_bytes, ..Default::default()}),
			account_expires_at: Some(reviewing.account_expires_at as i64).filter(|at| *at > 0),
			device_limit: Some(reviewing.device_limit).filter(|limit| *limit > 0),
			devices: reviewing.devices,
			classes: reviewing.classes.clone(),
			profiles: reviewing.profiles.iter().map(|profile| UpstreamProfile {
				id: profile.id.clone(), name: profile.name.clone(), transports: profile.transports.iter().map(|name| transport_of(name)).collect(), classes: profile.classes.clone(), rating: profile.rating,
				private_addresses: profile.private.iter().map(ToString::to_string).collect(), mtu: profile.mtu,
				exits: profile.exits.iter().map(|(tag, name)| UpstreamExit {tag: tag.clone(), name: name.clone()}).collect(),
				refused: profile.refused.clone(),
			}).collect(),
		}
	}
}

/// What a decline of a preview did: the provider was told to release the place.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamDeclined {pub id: String}

/// What the node is doing for one upstream. Nothing in it is a key, a secret, a token or the link.
#[derive(Serialize, JsonSchema)]
pub struct Upstream {
	pub tag: String,
	pub state: UpstreamStatus,
	/// Plain words for why the state is what it is. Empty while it is up.
	pub reason: String,
	/// Seconds the upstream has been in `state`.
	pub state_secs: u64,
	pub provider: Option<String>,
	/// The fingerprint of the signing key the document in force is signed under. After the provider rotated its key this is the new one, which `signing_key` and the link in the upstream's config do not name until the operator confirms it.
	pub signing_key: Option<String>,
	/// The profile in use, and the transport it is connected over.
	pub profile: Option<String>,
	pub transport: Option<Transport>,
	/// The exit of the provider in use, and the exits it offers.
	pub exit: Option<String>,
	pub offered_exits: Vec<String>,
	/// The exits the provider offers, at most 16, once the control channel is open.
	pub exits: Vec<UpstreamExitState>,
	/// What the provider says to the device, as plain text.
	pub notices: Vec<String>,
	/// The same notices with the severity the provider gave them.
	pub provider_notices: Vec<UpstreamNotice>,
	pub quota: Option<UpstreamQuota>,
	/// What the tunnel itself says: connecting, reconnecting, connected, stopped:<reason> (quota, expired, disabled or node-stopping) or failed. Null while no tunnel exists.
	pub engine_state: Option<String>,
	/// Seconds the tunnel has been connected. Null while it is not.
	pub connected_secs: Option<u64>,
	/// The types of transport the profile in use lists.
	pub transports: Vec<Transport>,
	/// Every profile of the document held, in the order they are tried, and whether each is usable.
	pub profiles: Vec<UpstreamProfileState>,
	pub choice: UpstreamChoiceState,
	/// When the document stops being current and when it was last refreshed, in Unix seconds.
	pub expires_at: Option<i64>,
	pub refreshed_at: Option<i64>,
	/// Why the last refresh failed. Null once one has gone through.
	pub refresh_error: Option<String>,
	/// The largest packet the carrier takes now. Null until a profile is in use.
	pub mtu: Option<u16>,
	/// A move of the provider's endpoint, and refresh hosts, that the provider announced and the operator has not confirmed. The old endpoint and hosts are used meanwhile.
	pub pending_move: Option<String>,
	pub pending_hosts: Vec<String>,
	pub counters: UpstreamCounters,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamStatus {Fetching, Connecting, Up, Down}

/// Totals since the node started, or since the upstream first ran.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamCounters {
	/// Packets handed to the provider's tunnel, and packets it had no room or no session for.
	pub sent: u64,
	pub unsent: u64,
	/// Flows refused because the upstream was down.
	pub refused: u64,
	/// Packets out of the tunnel that answered no live flow of a device, and were dropped.
	pub dropped: u64,
	/// Changes between up and not up, and starts of the tunnel over again.
	pub state_flips: u64,
	pub starts: u64,
	pub refreshes: u64,
	pub refresh_failures: u64,
	pub traffic: Traffic,
}

impl From<Carrying> for Upstream {
	fn from(report: Carrying) -> Upstream {
		Upstream {
			tag: report.tag,
			state: match report.phase {Phase::Fetching => UpstreamStatus::Fetching, Phase::Connecting => UpstreamStatus::Connecting, Phase::Up => UpstreamStatus::Up, Phase::Down => UpstreamStatus::Down},
			reason: report.reason, state_secs: report.since.as_secs(), provider: report.provider, signing_key: report.signing_key, profile: report.profile,
			transport: report.transport.map(transport_of), exit: report.exit, offered_exits: report.offered, notices: report.notices,
			exits: report.exits.into_iter().map(|exit| UpstreamExitState {tag: exit.tag, name: exit.name, country: exit.country, all_protocols: exit.all_protocols, selected: exit.selected}).collect(),
			provider_notices: report.notice_list.into_iter().map(|(severity, text)| UpstreamNotice {severity: if severity == "warning" {UpstreamSeverity::Warning} else {UpstreamSeverity::Information}, text}).collect(),
			quota: report.usage.map(|(used_bytes, quota_bytes)| UpstreamQuota {used_bytes, quota_bytes, period: report.account.as_ref().map(|account| match account.period {"daily" => UpstreamPeriod::Daily, "weekly" => UpstreamPeriod::Weekly, "monthly" => UpstreamPeriod::Monthly, _ => UpstreamPeriod::None}), period_start: report.account.as_ref().map(|account| account.period_start as i64), account_expires_at: report.account.as_ref().map(|account| account.expires_at as i64), up_bytes: report.account.as_ref().map(|account| account.up_bytes), down_bytes: report.account.as_ref().map(|account| account.down_bytes)}),
			engine_state: report.engine_state, connected_secs: report.connected_secs,
			transports: report.transports.into_iter().map(transport_of).collect(),
			profiles: report.profiles.into_iter().map(|profile| UpstreamProfileState {id: profile.id, name: profile.name, usable: profile.usable, reason: profile.reason}).collect(),
			choice: UpstreamChoiceState {profile: report.choice.profile, failover: report.choice.failover, transport: report.choice.transport, exit: report.choice.exit},
			expires_at: report.expires_at.map(|at| at as i64), refreshed_at: report.refreshed_at.map(|at| at as i64), refresh_error: report.refresh_error,
			mtu: Some(report.mtu).filter(|mtu| *mtu > 0), pending_move: report.pending_move, pending_hosts: report.pending_hosts,
			counters: UpstreamCounters {sent: report.sent, unsent: report.unsent, refused: report.refused, dropped: report.dropped, state_flips: report.flips, starts: report.starts, refreshes: report.refreshes, refresh_failures: report.refresh_failures, traffic: report.traffic.into()},
		}
	}
}

#[derive(Serialize, JsonSchema)]
pub struct Upstreams {pub upstreams: Vec<Upstream>}

/// What a removal did. `confirmed` says whether the provider took the word that the device left; when it did not, the place stays until the provider removes it. The upstream is not run again by a config that still names it.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamRemoved {pub tag: String, pub confirmed: bool}

/// What the operator chooses on an upstream. A field that is left out stays as it is, and null is automatic: no pinned profile, no failover, every transport, the provider's default exit. The link, the keys, `allow`, `allow_private` and `via` are not part of it and cannot be changed this way.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamChoice {
	#[serde(default, deserialize_with = "set")] pub profile: Option<Option<String>>,
	#[serde(default, deserialize_with = "set")] pub failover: Option<Option<bool>>,
	#[serde(default, deserialize_with = "set")] pub transport: Option<Option<String>>,
	#[serde(default, deserialize_with = "set")] pub exit: Option<Option<String>>,
}

/// A field that is present is `Some`, whether its value is null or not.
fn set<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(from: D) -> Result<Option<Option<T>>, D::Error> {Option::<T>::deserialize(from).map(Some)}

// Written out by hand, like `UpstreamConfirm`.
impl JsonSchema for UpstreamChoice {
	fn schema_name() -> Cow<'static, str> {"UpstreamChoice".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "object", "description": "What to choose on an upstream. A field that is left out stays as it is, and null is automatic. The change goes through the same checks and the same apply as a config document does, and is written to the config file. Only the exit is taken on the running tunnel; any other field makes the tunnel again.", "properties": {
		"profile": {"type": ["string", "null"], "description": "The profile of the provider's document to use. Null: every profile is tried in the document's order, starting with the last one that carried."},
		"failover": {"type": ["boolean", "null"], "description": "Whether the other profiles are tried when the named one cannot be used. Null is false."},
		"transport": {"type": ["string", "null"], "description": "The type of transport to connect over: udp, udp-obfs, tls, ws, ws-plain, fronted or fronted-shaped. Null: the engine picks from every transport of the profile."},
		"exit": {"type": ["string", "null"], "description": "The tag of the provider's exit to leave through. Null: the provider's default."}
	}, "additionalProperties": false})}
}

/// What a choice on an upstream came to: the config now in force, and whether only the exit changed, so that the tunnel was kept and asked for the other exit.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamChosen {pub tag: String, pub revision: String, pub generation: u64, pub live: bool}

/// What a confirmation of the operator is for. A body that is left out confirms both.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfirm {#[serde(default, rename = "move")] pub moving: Option<bool>, #[serde(default)] pub hosts: Option<bool>}

// Written out by hand, like `ResetUsage`.
impl JsonSchema for UpstreamConfirm {
	fn schema_name() -> Cow<'static, str> {"UpstreamConfirm".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {json_schema!({"type": "object", "description": "What the operator confirms: the move of the provider's endpoint the node reported as pending, and the refresh hosts it reported. A field that is left out is false when the other one is given, and the body may be left out altogether, which confirms both.", "properties": {
		"move": {"type": "boolean", "description": "Follow the move to the new endpoint: the next refresh tries it first."},
		"hosts": {"type": "boolean", "description": "Take the new refresh hosts and static mirrors the provider announced."}
	}, "additionalProperties": false})}
}

/// What a confirmation did: false for each thing that did not wait for it.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamConfirmed {pub moved: bool, pub hosts: bool}

/// The tag of an upstream the node was asked to connect again.
#[derive(Serialize, JsonSchema)]
pub struct UpstreamRetried {pub tag: String}

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

/// The data of an `exit_working_changed` event: the proxy of an exit stopped letting the node in (`working` false), or lets it in again. Devices without a choice of exit leave through another exit meanwhile.
#[derive(Serialize, JsonSchema)]
pub struct ExitWorkingChanged {pub exit: String, pub working: bool}

/// The data of a `lagged` event: this many events, the ones whose ids are missing before the next event, never reached the reader. It was too slow for them, or the node made them faster than it keeps them for anybody. It has no id.
#[derive(Serialize, JsonSchema)]
pub struct Lagged {pub missed: u64}
