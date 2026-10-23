//! The routes: one table that both the router and the OpenAPI document are built from, and the handlers behind it.
use crate::model::{self, key};
use crate::{Api, Frame};
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, Request, State};
use axum::handler::Handler;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{on, MethodFilter, MethodRouter};
use futures_util::{stream, StreamExt};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::de::IgnoredAny;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use time::OffsetDateTime;
use tokio::sync::broadcast::error::RecvError;
use veilway_core::config::{ApplyError, Config, Diff, Outbound, Snapshot, NAME_PATTERN};
use veilway_core::engine::upstream::{PreviewError, PreviewRequest};
use veilway_core::engine::link::Status;
use veilway_core::{Denied, Over, Reason, Reset};

pub(crate) const EVENTS: &str = "/v1/events";
const CONFIG: &str = "/v1/config";
/// What the path of a usage reset begins and ends with, around the name of its user.
const USERS: &str = "/v1/users/";
const RESET: &str = "/usage/reset";
const REPLAY_RESET: &str = "/v1/replay/reset";
const UPSTREAMS: &str = "/v1/upstreams";
/// A preview fetches from a provider, which takes as long as the provider does. It keeps the time itself, see `preview_upstream`.
const PREVIEW: &str = "/v1/upstreams/preview";
/// How many times the body limit a request may send before the node stops taking its body off the connection.
const DRAIN: usize = 4;

/// One route as the router serves it and as the OpenAPI document describes it.
pub(crate) struct Route {
	pub method: Method,
	pub path: &'static str,
	pub operation: &'static str,
	pub summary: &'static str,
	pub handler: MethodRouter<Arc<Api>>,
	/// The schema of the body the request carries, and whether it has to carry one. None for a request without a body.
	pub body: Option<(Schema, bool)>,
	/// Every status the route answers with, each with what it means. Without a schema the body is no JSON document: the event stream.
	pub responses: Vec<(StatusCode, &'static str, Option<Schema>)>,
}

/// An answer that is not a success, in the one shape every such answer has.
pub(crate) struct Failure {status: StatusCode, code: &'static str, message: String, details: Vec<model::Problem>, revision: Option<String>}

impl Failure {
	pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Failure {Failure {status, code, message: message.into(), details: Vec::new(), revision: None}}

	fn refused(report: &veilway_core::config::Report) -> Failure {
		Failure {details: model::Report::from(report).errors, ..Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "config_invalid", format!("The document has {} errors and nothing was changed.", report.errors.len() + report.more_errors))}
	}

	fn late(api: &Api) -> Failure {Failure::new(StatusCode::REQUEST_TIMEOUT, "request_timeout", format!("The request was not finished within {} seconds. Nothing was changed.", api.limits.request.as_secs()))}

	fn stale(current: String) -> Failure {
		Failure {details: vec![model::Problem {path: "revision".to_string(), message: current.clone()}], revision: Some(current), ..Failure::new(StatusCode::CONFLICT, "stale_revision", "The running config is not the one If-Match names. Read it again and apply the change to what runs now.")}
	}
}

impl IntoResponse for Failure {
	fn into_response(self) -> Response {
		let mut response = json(self.status, &model::ErrorBody {error: model::Failure {code: self.code.to_string(), message: self.message, details: self.details}});
		if let Some(tag) = self.revision.and_then(|revision| HeaderValue::from_str(&format!("\"{revision}\"")).ok()) {response.headers_mut().insert(ETAG, tag);}
		response
	}
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
	match serde_json::to_vec(body) {
		Ok(bytes) => (status, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], bytes).into_response(),
		Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], r#"{"error":{"code":"internal","message":"The answer could not be written.","details":[]}}"#).into_response(),
	}
}

/// The body of a request that carries a JSON document, read up to the limit and no further. With `optional` a request without a body is taken too, as no bytes, whatever it says its type is.
async fn document(api: &Api, request: Request, optional: bool) -> Result<Vec<u8>, Failure> {
	let typed = request.headers().get(CONTENT_TYPE).and_then(|kind| kind.to_str().ok()).is_some_and(|kind| kind.split(';').next().is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json")));
	let mut large = request.headers().get(CONTENT_LENGTH).and_then(|length| length.to_str().ok()).and_then(|length| length.parse::<usize>().ok()).is_some_and(|length| length > api.limits.body);
	// A body that is not wanted is still taken off the connection, and thrown away, up to a few times the limit: a client that is still sending when its connection closes may never see why it was refused. Past that the connection is cut.
	let (mut body, mut bytes, mut read) = (request.into_body().into_data_stream(), Vec::new(), 0usize);
	while let Some(chunk) = body.next().await {
		let chunk = chunk.map_err(|_| Failure::new(StatusCode::BAD_REQUEST, "bad_request", "The body could not be read to its end."))?;
		read = read.saturating_add(chunk.len());
		large |= read > api.limits.body;
		if read > api.limits.body.saturating_mul(DRAIN) {break}
		if typed && !large {bytes.extend_from_slice(&chunk)}
	}
	if optional && read == 0 {return Ok(bytes)}
	if !typed {return Err(Failure::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type", "The body must be sent as application/json."))}
	if large {return Err(Failure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", format!("The body is larger than {} bytes.", api.limits.body)))}
	// A body that is no JSON at all is a request that went wrong. One that is JSON and no valid config is a document to report on.
	if serde_json::from_slice::<IgnoredAny>(&bytes).is_err() {return Err(Failure::new(StatusCode::BAD_REQUEST, "bad_json", "The body is not one JSON document."))}
	Ok(bytes)
}

/// Reads a document against the running config, which is where a `<redacted>` marker takes its value from, validates it and compares the two. It runs off the runtime's own threads: a large document takes a while.
/// The config comes back only when it has no errors. `shadow` also looks for rules an earlier rule covers.
/// Only so many documents are checked at once, see `CHECKS`: another waits here for its turn. The turn goes into the check and is given back when the check has really ended, not when its request stops waiting for it.
async fn check(api: &Api, snapshot: Snapshot, bytes: Vec<u8>, shadow: bool) -> Result<(Option<(Config, Diff)>, veilway_core::config::Report), Failure> {
	let unfinished = || Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "The check of the document did not finish.");
	let turn = api.checks.clone().acquire_owned().await.map_err(|_| unfinished())?;
	tokio::task::spawn_blocking(move || {
		let _turn = turn;
		match Config::parse_keeping(&bytes, &snapshot.config) {
			Ok((config, spelled)) => {
				let report = config.validate(shadow);
				let diff = report.errors.is_empty().then(|| {
					let mut diff = Diff::between(&snapshot.config, &config, OffsetDateTime::now_utc());
					// An outbound whose user name or password the document spells out is a changed one whatever they are. "Not changed" would tell whoever guessed a password that the guess was right.
					diff.outbounds.changed = config.outbounds.iter().map(|outbound| match outbound {
						Outbound::Direct {tag, ..} | Outbound::Socks5 {tag, ..} => tag,
					}).filter(|tag| diff.outbounds.changed.contains(tag) || (spelled.contains(tag) && !diff.outbounds.added.contains(tag))).cloned().collect();
					diff
				});
				(diff.map(|diff| (config, diff)), report)
			}
			Err(report) => (None, report),
		}
	}).await.map_err(|_| unfinished())
}

async fn status(State(api): State<Arc<Api>>) -> Response {
	let (snapshot, plan) = (api.engine.snapshot(), api.engine.plan());
	json(StatusCode::OK, &model::Status {version: env!("CARGO_PKG_VERSION").to_string(), generation: snapshot.generation, revision: snapshot.revision.to_string(), uptime_secs: api.engine.uptime().as_secs(), inbounds: plan.listening, exits: plan.exits.len(), users: plan.people, flows: api.engine.flows(), certificates: api.engine.certificates().into_iter().map(|made| model::SelfSigned {listen: made.listen.to_string(), pin: made.pin_text(), not_before: made.not_before, not_after: made.not_after}).collect(), public_addresses: snapshot.config.public_addresses.clone(), addons: model::Addons {xray: model::XrayAddon {installed: api.engine.xray_installed(), release: veilway_core::engine::xray::RELEASE.to_string()}}})
}

async fn running(State(api): State<Arc<Api>>) -> Response {
	let snapshot = api.engine.snapshot();
	let mut response = json(StatusCode::OK, &model::Running {revision: snapshot.revision.to_string(), generation: snapshot.generation, document: model::Document(snapshot.config.redacted())});
	if let Ok(tag) = HeaderValue::from_str(&format!("\"{}\"", snapshot.revision)) {response.headers_mut().insert(ETAG, tag);}
	response
}

async fn validate(State(api): State<Arc<Api>>, request: Request) -> Response {
	let bytes = match document(&api, request, false).await {
		Ok(bytes) => bytes,
		Err(failure) => return failure.into_response(),
	};
	match check(&api, api.engine.snapshot(), bytes, true).await {
		Ok((config, report)) => json(StatusCode::OK, &model::Validation {valid: config.is_some(), report: (&report).into()}),
		Err(failure) => failure.into_response(),
	}
}

async fn difference(State(api): State<Arc<Api>>, request: Request) -> Response {
	let bytes = match document(&api, request, false).await {
		Ok(bytes) => bytes,
		Err(failure) => return failure.into_response(),
	};
	match check(&api, api.engine.snapshot(), bytes, false).await {
		Ok((config, report)) => json(StatusCode::OK, &model::Difference {valid: config.is_some(), report: (&report).into(), diff: config.map(|(_, diff)| (&diff).into())}),
		Err(failure) => failure.into_response(),
	}
}

async fn apply(State(api): State<Arc<Api>>, request: Request) -> Response {
	// The revision is compared as text: what is not the revision that runs is stale, whatever it is.
	let given = request.headers().get(IF_MATCH).map(|given| given.to_str().unwrap_or_default().trim().trim_matches('"').to_string());
	// The time a request gets is held against everything up to the moment the engine is given the config, and a request that runs out of it there has changed nothing.
	// From that moment the answer waits for the engine however long it takes, see `deadline`: the engine finishes what it has begun whether or not anybody waits, so "too slow" would be said of a config that then goes into force.
	let checked = tokio::time::timeout(api.limits.request, async {
		// The body is read before anything is answered, see `document`.
		let bytes = document(&api, request, false).await?;
		let given = given.ok_or_else(|| Failure::new(StatusCode::PRECONDITION_REQUIRED, "precondition_required", "An apply needs the header If-Match with the revision of the config the change was made on."))?;
		let snapshot = api.engine.snapshot();
		if given != snapshot.revision.to_string() {return Err(Failure::stale(snapshot.revision.to_string()))}
		let (config, report) = check(&api, snapshot.clone(), bytes, false).await?;
		let (config, _) = config.ok_or_else(|| Failure::refused(&report))?;
		// What is applied and saved is the document with its real secrets, written out again by this build: the bytes that were sent may hold markers.
		let mut bytes = serde_json::to_vec_pretty(&config).map_err(|_| Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "The document could not be written out."))?;
		bytes.push(b'\n');
		Ok((bytes, snapshot))
	}).await;
	let (bytes, snapshot) = match checked {
		Ok(Ok(checked)) => checked,
		Ok(Err(failure)) => return failure.into_response(),
		Err(_) => return Failure::late(&api).into_response(),
	};
	match api.engine.apply(bytes, snapshot.revision, &api.config).await {
		Ok((applied, saved)) => {
			if let Err(e) = &saved {tracing::error!("control api: config generation {} is in force and could not be written to {} ({}): a restart comes back with the config before", applied.snapshot.generation, api.config.display(), e.kind())}
			let mut response = json(StatusCode::OK, &model::Applied {revision: applied.snapshot.revision.to_string(), generation: applied.snapshot.generation, saved: saved.is_ok(), save_error: saved.err().map(|e| e.kind().to_string()), diff: (&applied.diff).into(), report: (&applied.report).into()});
			if let Ok(tag) = HeaderValue::from_str(&format!("\"{}\"", applied.snapshot.revision)) {response.headers_mut().insert(ETAG, tag);}
			response
		}
		Err(ApplyError::Stale {current}) => Failure::stale(current.to_string()).into_response(),
		Err(ApplyError::Invalid(report)) => Failure::refused(&report).into_response(),
		// The engine's own words: they name tags and field paths and never a value from the document.
		Err(ApplyError::Prepare(e)) => Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "config_not_prepared", format!("The node could not prepare the config and nothing was changed: {e:#}")).into_response(),
	}
}

/// Every user of the running config, or the one called `only`, with what the engine counts for them. For one user the engine is asked about that user alone.
fn users_of(api: &Api, only: Option<&str>) -> Vec<model::User> {
	let (snapshot, counted, peers) = (api.engine.snapshot(), only.map_or_else(|| api.engine.counters().users, |name| api.engine.usage(name).into_iter().collect()), api.engine.peers(only));
	let usage: HashMap<&str, &veilway_core::Usage> = counted.iter().map(|usage| (usage.name.as_str(), usage)).collect();
	// A device with an address in several inbounds has a session with each. The youngest is the one that says when it was last there.
	let mut handshakes: HashMap<[u8; 32], Duration> = HashMap::new();
	for (public, age) in peers.iter().filter_map(|peer| peer.handshake.map(|age| (peer.public_key, age))) {
		handshakes.entry(public).and_modify(|youngest| *youngest = age.min(*youngest)).or_insert(age);
	}
	// For every user the sets are indexed once. For one user they are gone through as they are, and nothing is built.
	let (sets, named) = (&snapshot.config.dns.sets, only.is_none().then(|| snapshot.config.dns.named()));
	snapshot.config.users.iter().filter(|user| only.is_none_or(|only| user.name == only)).map(|user| {
		let usage = usage.get(user.name.as_str());
		model::User {
			name: user.name.clone(),
			enabled: user.enabled != Some(false),
			denied: usage.and_then(|usage| usage.denied).map(|denied| match denied {
				Denied::Disabled => model::Denied::Disabled,
				Denied::Expired => model::Denied::Expired,
				Denied::Quota => model::Denied::Quota,
			}),
			expires_at: user.expires_at.as_ref().and_then(|at| serde_json::to_value(at).ok()).and_then(|at| at.as_str().map(str::to_string)),
			quota_bytes: user.quota_bytes,
			quota_period: user.quota_period,
			used_bytes: usage.map_or(0, |usage| usage.used_bytes),
			period_start: usage.map_or(0, |usage| usage.period_start),
			dns_set: match &named {
				Some([of_user, of_group, _]) => of_user.get(user.name.as_str()).or_else(|| user.groups.iter().find_map(|group| of_group.get(group.as_str()))).map(|set| &sets[*set]),
				None => sets.iter().find(|set| set.users.contains(&user.name)).or_else(|| sets.iter().find(|set| user.groups.iter().any(|group| set.groups.contains(group)))),
			}.map(|set| set.tag.clone()),
			traffic: usage.map(|usage| usage.traffic).unwrap_or_default().into(),
			devices: user.devices.iter().map(|device| model::Device {name: device.name.clone(), public_key: key(&device.public_key), addresses: device.addresses.iter().map(|address| address.0.to_string()).collect(), handshake_age_secs: handshakes.get(&device.public_key.0).map(Duration::as_secs)}).collect(),
		}
	}).collect()
}

async fn users(State(api): State<Arc<Api>>) -> Response {json(StatusCode::OK, &model::Users {users: users_of(&api, None)})}

async fn user(State(api): State<Arc<Api>>, name: Result<Path<String>, PathRejection>) -> Response {
	match name.ok().and_then(|Path(name)| users_of(&api, Some(&name)).pop()) {
		Some(user) => json(StatusCode::OK, &user),
		None => Failure::new(StatusCode::NOT_FOUND, "user_not_found", "The running config has no user of that name.").into_response(),
	}
}

/// Starts a user's quota count over, see `Engine::reset_usage`. Like an apply it keeps the time itself: the body has the time a request gets, and once the engine has been asked the answer waits for it,
/// so "too slow" is never said of a reset that then happens. The engine waits for a reload that is under way and for one write of the state file, which it gives up on by itself.
async fn reset_usage(State(api): State<Arc<Api>>, name: Result<Path<String>, PathRejection>, request: Request) -> Response {
	let missing = || Failure::new(StatusCode::NOT_FOUND, "user_not_found", "The running config has no user of that name.").into_response();
	// The body is read before anything is answered, see `document`.
	let bytes = match tokio::time::timeout(api.limits.request, document(&api, request, true)).await {
		Ok(Ok(bytes)) => bytes,
		Ok(Err(failure)) => return failure.into_response(),
		Err(_) => return Failure::late(&api).into_response(),
	};
	// Only an object is a body: left to itself the type would also be read from a list.
	let Some(asked) = (if bytes.is_empty() {Some(model::ResetUsage::default())} else {serde_json::from_slice::<serde_json::Value>(&bytes).ok().filter(serde_json::Value::is_object).and_then(|body| serde_json::from_value::<model::ResetUsage>(body).ok())}) else {return Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "body_invalid", "The body of a usage reset is an object with at most the field totals, which is true or false. Nothing was changed.").into_response()};
	let Ok(Path(name)) = name else {return missing()};
	if api.engine.reset_usage(&name, asked.totals).await.is_none() {return missing()}
	users_of(&api, Some(&name)).pop().map_or_else(missing, |user| json(StatusCode::OK, &user))
}

/// `veilway replay reset`, see `Engine::reset_replay`. Like a usage reset the answer waits for the node once it has been asked: the node gives up on the write by itself and says so.
async fn reset_replay(State(api): State<Arc<Api>>) -> Response {
	match api.engine.reset_replay().await {
		None => Failure::new(StatusCode::CONFLICT, "replay_absent", "The node has run no obfuscated transport, so it keeps no replay memory and there is nothing to reset. Nothing was changed.").into_response(),
		Some(Reset::Busy) => Failure::new(StatusCode::CONFLICT, "replay_busy", "An earlier reset is not known to be on disk yet, or the node is stopping. Until then the node accepts no proof. Ask again in a moment.").into_response(),
		Some(Reset::Unwritten) => Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "replay_unwritten", "The replay file could not be written, so the reset may or may not be on disk. The node accepts no proof until it has written the floor and the limit it had back, and then they are in force again. Make the replay file writable and ask again.").into_response(),
		Some(Reset::Writing) => Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "replay_writing", "The write of the reset has not ended yet. The reset is in force when it does: do not ask for it again. GET /v1/stats shows it: replay.resets grows by one when the reset has landed, and replay.ready is false while the node accepts no proof.").into_response(),
		Some(Reset::Done(_)) => api.engine.replay().map_or_else(|| Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "The replay memory was reset and could not be read back.").into_response(), |status| json(StatusCode::OK, &model::Replay::from(status))),
	}
}

async fn stats(State(api): State<Arc<Api>>) -> Response {json(StatusCode::OK, &api.stats())}

fn no_upstream() -> Response {Failure::new(StatusCode::NOT_FOUND, "upstream_not_found", "The running config has no upstream of that tag. Nothing was changed.").into_response()}

async fn upstreams(State(api): State<Arc<Api>>) -> Response {json(StatusCode::OK, &model::Upstreams {upstreams: api.engine.upstreams().into_iter().map(model::Upstream::from).collect()})}

/// Looks at the subscription of another provider with the device the body gives, see `Engine::upstream_preview`. The fetch takes a place at the provider and runs to its end whether or not this request is still there: a preview nobody takes is given back after ten minutes.
async fn preview_upstream(State(api): State<Arc<Api>>, request: Request) -> Response {
	let bytes = match tokio::time::timeout(api.limits.request, document(&api, request, false)).await {
		Ok(Ok(bytes)) => bytes,
		Ok(Err(failure)) => return failure.into_response(),
		Err(_) => return Failure::late(&api).into_response(),
	};
	// Only an object is a body, and what is wrong with it is never quoted: it holds a private key.
	let Some(asked) = serde_json::from_slice::<serde_json::Value>(&bytes).ok().filter(serde_json::Value::is_object).and_then(|body| serde_json::from_value::<model::UpstreamPreviewRequest>(body).ok()) else {return Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "body_invalid", "The body of a preview is an object with link, private_key and device_secret, and at most via and allow_private. Nothing was fetched.").into_response()};
	match api.engine.upstream_preview(PreviewRequest {link: asked.link, private_key: asked.private_key, device_secret: asked.device_secret, via: asked.via, allow_private: asked.allow_private}).await {
		Ok(reviewing) => json(StatusCode::OK, &model::UpstreamPreview::from(&reviewing)),
		Err(PreviewError::Invalid(why)) => Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "body_invalid", format!("{why}. Nothing was fetched.")).into_response(),
		Err(PreviewError::Provider(why)) => Failure::new(StatusCode::BAD_GATEWAY, "provider_failed", format!("The provider could not be asked, or its answer did not pass the checks: {why}")).into_response(),
		Err(PreviewError::Full) => Failure::new(StatusCode::CONFLICT, "previews_full", "Four previews already wait for a config, or for an answer. Decline one, or wait for one to run out. Nothing was fetched.").into_response(),
	}
}

/// The operator says no to a preview: the provider is told to release the place.
async fn decline_preview(State(api): State<Arc<Api>>, id: Result<Path<String>, PathRejection>) -> Response {
	match id {
		Ok(Path(id)) if api.engine.upstream_decline(&id).await => json(StatusCode::OK, &model::UpstreamDeclined {id}),
		_ => Failure::new(StatusCode::NOT_FOUND, "preview_not_found", "No preview of that id waits. It was declined, taken by a config, or ran out.").into_response(),
	}
}

/// Removes an upstream: the provider is told the device left, for at most ten seconds, and its document leaves the state file. A config that is applied afterwards without the upstream finishes the removal; a reload alone, without this call, never tells the provider anything.
async fn remove_upstream(State(api): State<Arc<Api>>, tag: Result<Path<String>, PathRejection>) -> Response {
	let Ok(Path(tag)) = tag else {return no_upstream()};
	match api.engine.upstream_leave(&tag).await {
		Some(confirmed) => json(StatusCode::OK, &model::UpstreamRemoved {tag, confirmed}),
		None => no_upstream(),
	}
}

async fn confirm_upstream(State(api): State<Arc<Api>>, tag: Result<Path<String>, PathRejection>, request: Request) -> Response {
	let bytes = match tokio::time::timeout(api.limits.request, document(&api, request, true)).await {
		Ok(Ok(bytes)) => bytes,
		Ok(Err(failure)) => return failure.into_response(),
		Err(_) => return Failure::late(&api).into_response(),
	};
	let Some(asked) = (if bytes.is_empty() {Some(model::UpstreamConfirm::default())} else {serde_json::from_slice::<serde_json::Value>(&bytes).ok().filter(serde_json::Value::is_object).and_then(|body| serde_json::from_value::<model::UpstreamConfirm>(body).ok())}) else {return Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "body_invalid", "The body of a confirmation is an object with at most move and hosts, which are true or false. Nothing was changed.").into_response()};
	let Ok(Path(tag)) = tag else {return no_upstream()};
	let (moving, hosts) = match (asked.moving, asked.hosts) {
		(None, None) => (true, true),
		(moving, hosts) => (moving.unwrap_or(false), hosts.unwrap_or(false)),
	};
	match api.engine.upstream_confirm(&tag, moving, hosts).await {
		None => no_upstream(),
		Some(Ok((moved, hosts))) => json(StatusCode::OK, &model::UpstreamConfirmed {moved, hosts}),
		Some(Err(_)) => Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "state_unwritten", "The answer could not be written to the state file of the upstreams, so it is not kept.").into_response(),
	}
}

async fn retry_upstream(State(api): State<Arc<Api>>, tag: Result<Path<String>, PathRejection>) -> Response {
	match tag {
		Ok(Path(tag)) if api.engine.upstream_again(&tag) => json(StatusCode::OK, &model::UpstreamRetried {tag}),
		_ => no_upstream(),
	}
}

async fn sessions(State(api): State<Arc<Api>>) -> Response {
	json(StatusCode::OK, &model::Sessions {sessions: api.engine.peers(None).into_iter().filter_map(|peer| Some(model::Session {
		handshake_age_secs: peer.handshake?.as_secs(),
		user: peer.user,
		device: peer.device,
		public_key: key(&veilway_core::config::Key(peer.public_key)),
		inbound: peer.inbound,
		transport: peer.over.map(|over| match over {
			Over::Udp => model::Transport::Udp,
			Over::Ws | Over::WsNative => model::Transport::Ws,
			Over::UdpObfs => model::Transport::UdpObfs,
			Over::Tls => model::Transport::Tls,
			Over::Fronted => model::Transport::Fronted,
			Over::FrontedShaped => model::Transport::FrontedShaped,
			Over::FakeTls => model::Transport::FakeTls,
			Over::WsPlain => model::Transport::WsPlain,
		}),
		flows: peer.flows,
		selected_exit: peer.exit,
		control_connections: peer.control,
		mtu: peer.mtu,
	})).collect()})
}

async fn exits(State(api): State<Arc<Api>>) -> Response {
	let (snapshot, counters, health, links, latencies) = (api.engine.snapshot(), api.engine.counters(), api.engine.exit_health(), api.engine.links(), api.engine.latencies());
	json(StatusCode::OK, &model::Exits {exits: snapshot.config.exits.iter().map(|exit| {
		let (health, outbound) = (health.iter().find(|health| health.exit == exit.tag), if let veilway_core::config::Backend::Netstack(netstack) = &exit.backend {Some(netstack.outbound.clone())} else {None});
		// Only a SOCKS5 proxy can refuse to relay UDP, so only an exit through one has anything to say here.
		let proxied = outbound.as_ref().is_some_and(|tag| snapshot.config.outbounds.iter().any(|outbound| matches!(outbound, Outbound::Socks5 {tag: of, ..} if of == tag)));
		let down = health.and_then(|health| health.no_udp).filter(|_| proxied);
		let latency = outbound.as_ref().and_then(|tag| latencies.get(tag)).copied();
		model::Exit {
			tag: exit.tag.clone(),
			name: exit.name.clone().unwrap_or_else(|| exit.tag.clone()),
			backend: match exit.backend {
				veilway_core::config::Backend::Netstack(_) => model::Backend::Netstack,
				veilway_core::config::Backend::L3(_) => model::Backend::L3,
				veilway_core::config::Backend::Block {} => model::Backend::Block,
				veilway_core::config::Backend::Chain(_) => model::Backend::Chain,
				veilway_core::config::Backend::Upstream(_) => model::Backend::Upstream,
			},
			outbound,
			udp: proxied.then_some(down.is_none()),
			udp_down_secs: down.map(|down| down.as_secs()),
			udp_flips: health.map_or(0, |health| health.udp_flips),
			interface_up: health.and_then(|health| health.interface_down).map(|down| down.is_none()),
			interface_down_secs: health.and_then(|health| health.interface_down).flatten().map(|down| down.as_secs()),
			interface_flips: health.map_or(0, |health| health.interface_flips),
			links: if let veilway_core::config::Backend::Chain(chain) = &exit.backend {chain.links.clone()} else {Vec::new()},
			link_up: if let veilway_core::config::Backend::Chain(chain) = &exit.backend {Some(links.iter().any(|link| chain.links.contains(&link.tag) && link.status == Status::Up))} else {None},
			latency_ms: latency.map(|(took, _)| took.as_millis() as u64),
			measured_at: latency.and_then(|(_, at)| at.duration_since(UNIX_EPOCH).ok()).map(|since| since.as_secs() as i64),
			traffic: counters.exits.iter().find(|(tag, _)| *tag == exit.tag).map(|(_, totals)| *totals).unwrap_or_default().into(),
		}
	}).collect()})
}

async fn inbounds(State(api): State<Arc<Api>>) -> Response {
	let snapshot = api.engine.snapshot();
	json(StatusCode::OK, &model::Inbounds {inbounds: snapshot.config.inbounds.iter().map(|inbound| model::InboundInfo {
		tag: inbound.tag.clone(),
		kind: match inbound.kind {veilway_core::config::InboundType::Wireguard => model::InboundKind::Wireguard, veilway_core::config::InboundType::Veilway => model::InboundKind::Veilway},
		public_key: inbound.public_key(),
		transport_public_key: inbound.transport_public_key(),
		transports: inbound.transports.iter().map(|transport| model::InboundTransport {
			transport: match transport {
				veilway_core::config::Transport::Udp {..} => model::Transport::Udp,
				veilway_core::config::Transport::Ws {..} | veilway_core::config::Transport::WsNative {..} => model::Transport::Ws,
				veilway_core::config::Transport::UdpObfs {..} => model::Transport::UdpObfs,
				veilway_core::config::Transport::Tls {..} => model::Transport::Tls,
				veilway_core::config::Transport::Fronted {..} => model::Transport::Fronted,
				veilway_core::config::Transport::FrontedShaped {..} => model::Transport::FrontedShaped,
				veilway_core::config::Transport::FakeTls {..} => model::Transport::FakeTls,
				veilway_core::config::Transport::WsPlain {..} => model::Transport::WsPlain,
			},
			rating: transport.rating(),
		}).collect(),
	}).collect(), public_addresses: snapshot.config.public_addresses.clone()})
}

async fn links(State(api): State<Arc<Api>>) -> Response {
	json(StatusCode::OK, &model::Links {links: api.engine.links().into_iter().map(|link| model::Link {
		tag: link.tag, id: veilway_core::config::LinkId(link.id),
		half: if link.entry {model::LinkHalf::Entry} else {model::LinkHalf::Exit},
		role: if link.listener {model::LinkRole::Listener} else {model::LinkRole::Dialler},
		state: match link.status {
			Status::Up => model::LinkState::Up,
			Status::Connecting => model::LinkState::Connecting,
			Status::Unreachable => model::LinkState::Unreachable,
			Status::Refused => model::LinkState::Refused,
			Status::Ended => model::LinkState::Ended,
		},
		state_secs: link.since.as_secs(), handshake_secs: link.handshake.map(|age| age.as_secs()),
		transport: link.transport.map(|(name, ..)| match name {
			"udp" => model::Transport::Udp,
			"udp-obfs" => model::Transport::UdpObfs,
			"tls" => model::Transport::Tls,
			_ => model::Transport::Ws,
		}),
		transport_index: link.transport.map(|(_, at, _)| at), candidate_index: link.transport.map(|(.., candidate)| candidate),
		size_warning: link.warning,
		denied: link.denied.map(|denied| match denied {
			Denied::Disabled => model::Denied::Disabled,
			Denied::Expired => model::Denied::Expired,
			Denied::Quota => model::Denied::Quota,
		}),
		exit: link.exit, flows: link.flows, dropped: link.dropped, state_flips: link.flips, traffic: link.traffic.into(),
	}).collect()})
}

/// The event stream. Every reader has its own place in the node's buffer of events and never holds the node up: one that falls behind loses the oldest and is told how many in a `lagged` event.
/// How many is counted from the ids, which have no gaps where nothing was lost: every event that went missing since the last one this reader was sent, whether this reader was too slow for it or the node itself could not keep it.
async fn events(State(api): State<Arc<Api>>) -> Response {
	let Ok(slot) = api.streams.clone().try_acquire_owned() else {return Failure::new(StatusCode::SERVICE_UNAVAILABLE, "too_many_streams", format!("The node already serves {} event streams.", api.limits.streams)).into_response()};
	// Subscribed before the last id is read, see the task that sends the frames. `held` is the frame a `lagged` event went out ahead of.
	let frames = api.events.subscribe();
	let stream = stream::unfold((frames, api.sent.load(Ordering::Relaxed), None::<Arc<Frame>>, api.clone(), slot), |(mut frames, last, mut held, api, slot)| async move {
		let frame = match held.take() {
			Some(frame) => frame,
			None => loop {
				match frames.recv().await {
					Ok(frame) => break frame,
					Err(RecvError::Lagged(_)) => {}
					Err(RecvError::Closed) => return None,
				}
			},
		};
		let missed = frame.id.saturating_sub(last.saturating_add(1));
		let event = if missed > 0 {Event::default().event("lagged").data(serde_json::to_string(&model::Lagged {missed}).unwrap_or_default())} else {Event::default().id(frame.id.to_string()).event(frame.kind).data(frame.data.clone().unwrap_or_else(|| api.latest()))};
		Some((Ok::<Event, Infallible>(event), (frames, if missed > 0 {frame.id - 1} else {frame.id}, (missed > 0).then_some(frame), api, slot)))
	});
	Sse::new(stream).keep_alive(KeepAlive::new().interval(api.limits.keep_alive).text("keepalive")).into_response()
}

async fn openapi() -> Response {(StatusCode::OK, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], crate::openapi()).into_response()}

pub(crate) async fn unknown() -> Response {Failure::new(StatusCode::NOT_FOUND, "not_found", "The control API has no such route. GET /v1/openapi.json lists them.").into_response()}

pub(crate) async fn not_allowed() -> Response {Failure::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "The route does not take this method. GET /v1/openapi.json lists what it takes.").into_response()}

/// Ends a request that has not been answered in time. The event stream is no such request: it is held to how fast its reader takes what it is sent, see `Stalled`.
/// An apply keeps the time itself, see `apply`: it must never be ended here while the engine is putting its config in force. So does a usage reset, see `reset_usage`, and a reset of the replay memory, which the node gives up on by itself.
pub(crate) async fn deadline(State(api): State<Arc<Api>>, request: Request, next: Next) -> Response {
	let path = request.uri().path();
	if path == EVENTS || (path == CONFIG && request.method() == Method::PUT) || (request.method() == Method::POST && (path == REPLAY_RESET || path == PREVIEW || path.strip_prefix(USERS).is_some_and(|rest| rest.ends_with(RESET)))) {return next.run(request).await}
	tokio::time::timeout(api.limits.request, next.run(request)).await.unwrap_or_else(|_| Failure::late(&api).into_response())
}

/// What an event of the engine is called on the stream, and its data.
pub(crate) fn frame(id: u64, event: veilway_core::Event) -> Frame {
	let (kind, data) = match event {
		veilway_core::Event::ConfigApplied {generation, revision, diff} => ("config_applied", serde_json::to_string(&model::ConfigApplied {generation, revision: revision.to_string(), diff: (&*diff).into()})),
		veilway_core::Event::ConfigRefused {stage, errors} => ("config_refused", serde_json::to_string(&model::ConfigRefused {stage: match stage {
			veilway_core::Stage::Validate => model::Stage::Validate,
			veilway_core::Stage::Prepare => model::Stage::Prepare,
		}, errors})),
		veilway_core::Event::UserCutOff {user, reason} => ("user_cut_off", serde_json::to_string(&model::UserCutOff {user, reason: reason.into()})),
		veilway_core::Event::UserRestored {user} => ("user_restored", serde_json::to_string(&model::UserRestored {user})),
		veilway_core::Event::ExitUdpChanged {exit, udp} => ("exit_udp_changed", serde_json::to_string(&model::ExitUdpChanged {exit, udp})),
		veilway_core::Event::ExitWorkingChanged {exit, working} => ("exit_working_changed", serde_json::to_string(&model::ExitWorkingChanged {exit, working})),
		veilway_core::Event::UsageReset {user, totals} => ("usage_reset", serde_json::to_string(&model::UsageReset {user, totals})),
	};
	Frame {id, kind, data: Some(data.unwrap_or_default().into())}
}

/// The data of each event the stream sends, by the name of the event.
pub(crate) fn event_schemas(schemas: &mut SchemaGenerator) -> Vec<(&'static str, Schema)> {
	vec![
		("config_applied", schemas.subschema_for::<model::ConfigApplied>()),
		("config_refused", schemas.subschema_for::<model::ConfigRefused>()),
		("user_cut_off", schemas.subschema_for::<model::UserCutOff>()),
		("user_restored", schemas.subschema_for::<model::UserRestored>()),
		("exit_udp_changed", schemas.subschema_for::<model::ExitUdpChanged>()),
		("exit_working_changed", schemas.subschema_for::<model::ExitWorkingChanged>()),
		("usage_reset", schemas.subschema_for::<model::UsageReset>()),
		("stats", schemas.subschema_for::<model::Stats>()),
		("lagged", schemas.subschema_for::<model::Lagged>()),
	]
}

/// One row of the table. `T` is what the route answers a request that went well with, `document` says the request carries a config document, and every route may also answer that a request took too long or that the node is full.
fn route<T: JsonSchema, H: Handler<X, Arc<Api>>, X: 'static>(schemas: &mut SchemaGenerator, method: Method, path: &'static str, operation: &'static str, summary: &'static str, handler: H, document: bool, failures: &[(StatusCode, &'static str)]) -> Route {
	let failure = schemas.subschema_for::<model::ErrorBody>();
	let mut responses = vec![(StatusCode::OK, "The answer.", Some(schemas.subschema_for::<T>()))];
	if document {responses.extend([(StatusCode::BAD_REQUEST, "The body is not one JSON document, or could not be read to its end."), (StatusCode::PAYLOAD_TOO_LARGE, "The body is larger than 4 MiB."), (StatusCode::UNSUPPORTED_MEDIA_TYPE, "The body was not sent as application/json.")].map(|(status, meaning)| (status, meaning, Some(failure.clone()))))}
	responses.extend(failures.iter().map(|(status, meaning)| (*status, *meaning, Some(failure.clone()))));
	responses.extend([(StatusCode::REQUEST_TIMEOUT, "The request was not finished within 30 seconds."), (StatusCode::SERVICE_UNAVAILABLE, "The node already serves as many connections, or as many event streams, as it takes at once.")].map(|(status, meaning)| (status, meaning, Some(failure.clone()))));
	Route {handler: on(MethodFilter::try_from(method.clone()).unwrap_or(MethodFilter::GET), handler), method, path, operation, summary, body: document.then(|| (schemas.subschema_for::<model::Document>(), true)), responses}
}

/// Every route of the API. The router serves exactly these and the OpenAPI document describes exactly these.
pub(crate) fn routes(schemas: &mut SchemaGenerator) -> Vec<Route> {
	let mut stream = route::<model::Stats, _, _>(schemas, Method::GET, EVENTS, "events", "Server-Sent Events: config_applied, config_refused, user_cut_off, user_restored, usage_reset, exit_udp_changed, and stats once a second. Each has an increasing id. A reader that is too slow loses events and gets a lagged event, which has no id, saying how many. A comment line every 15 seconds keeps the stream alive.", events, false, &[]);
	stream.responses[0] = (StatusCode::OK, "The stream. The data of each event is one JSON document, see x-events.", None);
	let mut put = route::<model::Applied, _, _>(schemas, Method::PUT, CONFIG, "applyConfig", "Puts a config in force, the way a reload on SIGHUP does, and writes it to the config file. If-Match must name the revision the change was made on. A document that is refused changes nothing. An outbound keeps its username and password for a marker only while its server is the same.", apply, true, &[(StatusCode::CONFLICT, "The running config is not the one If-Match names. The details and the ETag hold the revision that runs."), (StatusCode::UNPROCESSABLE_ENTITY, "The document is not a valid config, or the node could not prepare it. Nothing was changed."), (StatusCode::PRECONDITION_REQUIRED, "The header If-Match is missing.")]);
	for response in put.responses.iter_mut().filter(|(status, ..)| *status == StatusCode::REQUEST_TIMEOUT) {response.1 = "The document was not read and checked within 30 seconds. Nothing was changed: once the node has begun to put a config in force, the answer waits for it however long that takes, and is never this one."}
	let mut reset = route::<model::User, _, _>(schemas, Method::POST, "/v1/users/{name}/usage/reset", "resetUsage", "Starts a user's quota count over: used_bytes is 0 and period_start is the start of the quota period the node's clock is in, or 0 for a user without a quota_period. A user who was out of quota may connect again at once, with no reload. traffic stays as it is unless the body says {\"totals\": true}, and the body may be left out. The state file is written before the answer. The same request again changes nothing more. The answer is the user as GET /v1/users/{name} gives them.", reset_usage, true, &[(StatusCode::NOT_FOUND, "The running config has no user of that name. Nothing was changed."), (StatusCode::UNPROCESSABLE_ENTITY, "The body is JSON and not what a usage reset takes. Nothing was changed.")]);
	reset.body = Some((schemas.subschema_for::<model::ResetUsage>(), false));
	for response in reset.responses.iter_mut().filter(|(status, ..)| *status == StatusCode::REQUEST_TIMEOUT) {response.1 = "The body was not read within 30 seconds. Nothing was changed: once the node has begun the reset, the answer waits for it and is never this one."}
	let mut preview = route::<model::UpstreamPreview, _, _>(schemas, Method::POST, PREVIEW, "previewUpstream", "Fetches the subscription of another provider from this node, with the device the body gives, and shows what the document holds. The fetch is the enrollment: it takes a place at the provider, so the provider sees this node's address and never the panel's. The document is verified under the key in the link, kept in memory for ten minutes under the id, and nothing is written to the config or the state file. A config that names the same link and device within that time takes the document and makes the place permanent without asking the provider again. At most four previews wait. The private key and the device secret are never in an answer.", preview_upstream, true, &[(StatusCode::UNPROCESSABLE_ENTITY, "A part of the body is not what a preview takes, or names an outbound the running config does not have. Nothing was fetched."), (StatusCode::BAD_GATEWAY, "The provider could not be asked, or its answer did not pass the checks, for instance because it is signed by another key than the link's, or the account has no device place left. The code is provider_failed and the message says why in plain words. Nothing was kept."), (StatusCode::CONFLICT, "Four previews already wait. Nothing was fetched.")]);
	preview.body = Some((schemas.subschema_for::<model::UpstreamPreviewRequest>(), true));
	for response in preview.responses.iter_mut().filter(|(status, ..)| *status == StatusCode::REQUEST_TIMEOUT) {response.1 = "The body was not read within 30 seconds. Nothing was fetched: once the node has begun to fetch, the answer waits for the provider and is never this one."}
	let mut confirm = route::<model::UpstreamConfirmed, _, _>(schemas, Method::POST, "/v1/upstreams/{tag}/confirm", "confirmUpstream", "Confirms what the node reported as pending for the upstream: the move of the provider's endpoint, which the next refresh then tries first, and the refresh hosts and static mirrors the provider added. Until then the node keeps using the endpoint and hosts it had. Without a body both are confirmed; with one, a field that is left out is false. The answer says what had been waiting.", confirm_upstream, true, &[(StatusCode::NOT_FOUND, "The running config has no upstream of that tag. Nothing was changed."), (StatusCode::UNPROCESSABLE_ENTITY, "The body is JSON and not what a confirmation takes. Nothing was changed."), (StatusCode::INTERNAL_SERVER_ERROR, "state_unwritten: the state file of the upstreams could not be written, so the answer is not kept.")]);
	confirm.body = Some((schemas.subschema_for::<model::UpstreamConfirm>(), false));
	vec![
		route::<model::Status, _, _>(schemas, Method::GET, "/v1/status", "status", "What runs: the version, the config in force and how much of everything there is.", status, false, &[]),
		route::<model::Running, _, _>(schemas, Method::GET, "/v1/config", "getConfig", "The running config with every secret replaced by the marker \"<redacted>\", and its revision, which is also the ETag.", running, false, &[]),
		put,
		route::<model::Validation, _, _>(schemas, Method::POST, "/v1/config/validate", "validateConfig", "Validates a document and changes nothing. Errors and warnings name the path of a field and never its value.", validate, true, &[]),
		route::<model::Difference, _, _>(schemas, Method::POST, "/v1/config/diff", "diffConfig", "What an apply of the document would add, change and remove, by tag and name. Nothing changes. An outbound whose username or password is written out, and not left as the marker, is listed as changed whatever they are.", difference, true, &[]),
		route::<model::Users, _, _>(schemas, Method::GET, "/v1/users", "listUsers", "Every user of the running config with their usage, counters and devices.", users, false, &[]),
		route::<model::User, _, _>(schemas, Method::GET, "/v1/users/{name}", "getUser", "One user.", user, false, &[(StatusCode::NOT_FOUND, "The running config has no user of that name.")]),
		reset,
		route::<model::Replay, _, _>(schemas, Method::POST, REPLAY_RESET, "resetReplay", "Resets the replay memory of the obfuscated transports: the cache of accepted proofs is emptied, and the floor and the limit become the node's clock plus 60 seconds, written to the replay file before the next proof is accepted. It ends the state in which the floor is ahead of the clock. It costs two things: every client is refused for 60 seconds, and a proof that was accepted with a timestamp above the new floor is forgotten, so whoever recorded it can use it once more when the clock reaches that timestamp. Nothing else of the node is touched, usage and quotas included. The answer is the replay memory after the reset.", reset_replay, false, &[(StatusCode::CONFLICT, "The node keeps no replay memory because it has run no obfuscated transport, or an earlier reset is not known to be on disk yet. Nothing was changed."), (StatusCode::INTERNAL_SERVER_ERROR, "replay_unwritten: the replay file could not be written, so the reset may or may not be on disk. The node accepts no proof until it has written the floor and the limit it had back, and the reset has to be asked for again. replay_writing: the write has not ended within 10 seconds and the reset is in force when it does, so it must not be asked for again: replay.resets of GET /v1/stats grows by one when it has landed.")]),
		route::<model::Stats, _, _>(schemas, Method::GET, "/v1/stats", "stats", "Every counter at one moment, with rates in bytes per second over the last 5 seconds.", stats, false, &[]),
		route::<model::Sessions, _, _>(schemas, Method::GET, "/v1/sessions", "listSessions", "The devices with a live session.", sessions, false, &[]),
		route::<model::Exits, _, _>(schemas, Method::GET, "/v1/exits", "listExits", "Every exit with what the node knows of its upstream, and its counters.", exits, false, &[]),
		route::<model::Inbounds, _, _>(schemas, Method::GET, "/v1/inbounds", "listInbounds", "Every inbound of the running config with its WireGuard public key, the public half of its node transport key, and the rating of each transport: what a censor can see of a profile of it. No private key.", inbounds, false, &[]),
		route::<model::Links, _, _>(schemas, Method::GET, "/v1/links", "listLinks", "Every enabled node link with its state and its counters. No key and no secret.", links, false, &[]),
		route::<model::Upstreams, _, _>(schemas, Method::GET, UPSTREAMS, "listUpstreams", "Every enabled upstream, the subscription of another provider that an exit uses, with its state and the reason, the provider's name, the profile, transport and exit in use, its quota and notices as plain text, the largest packet it takes, the fingerprint of the signing key its document is signed under, when its document was last refreshed and why a refresh failed, a move of the provider's endpoint or new refresh hosts that wait for the operator, and its counters. No key, no secret and no link.", upstreams, false, &[]),
		preview,
		route::<model::UpstreamDeclined, _, _>(schemas, Method::POST, "/v1/upstreams/preview/{id}/decline", "declinePreview", "Says no to a preview: the provider is told to release the place the preview took, and the node keeps nothing.", decline_preview, false, &[(StatusCode::NOT_FOUND, "No preview of that id waits: it was declined, a config took it, or it ran out.")]),
		route::<model::UpstreamRemoved, _, _>(schemas, Method::DELETE, "/v1/upstreams/{tag}", "removeUpstream", "Removes an upstream: the provider is told that the device left, for at most ten seconds, and the document and the keys leave the state file. The answer says whether the provider took the word. When it did not, the document stays in the state file and the same call again tells the provider again; the answer is 404 only when the running config has no such upstream, so a removal that was not confirmed can be retried while the config still names it. The upstream stops, and a config that still names it does not start it again, not even after a restart (a tombstone in the state file keeps it down until a config that no longer names it that way has been in force); apply a config without it to finish. A config applied without the upstream, with no call to this route, never tells the provider anything.", remove_upstream, false, &[(StatusCode::NOT_FOUND, "The running config has no upstream of that tag. Nothing was changed.")]),
		confirm,
		route::<model::UpstreamRetried, _, _>(schemas, Method::POST, "/v1/upstreams/{tag}/retry", "retryUpstream", "Asks the upstream to connect again now, at the operator's word: every wait it was in starts over.", retry_upstream, false, &[(StatusCode::NOT_FOUND, "The running config has no upstream of that tag. Nothing was changed.")]),
		stream,
		route::<BTreeMap<String, serde_json::Value>, _, _>(schemas, Method::GET, "/v1/openapi.json", "openapi", "This document.", openapi, false, &[]),
	]
}

/// The schema of a path parameter, by its name.
pub(crate) fn parameter(name: &str) -> serde_json::Value {serde_json::json!({"name": name, "in": "path", "required": true, "schema": if name == "name" {serde_json::json!({"type": "string", "pattern": NAME_PATTERN})} else {serde_json::json!({"type": "string"})}})}

impl Api {
	/// The counters of the node now, with the rates the samples of the last seconds give.
	pub(crate) fn stats(&self) -> model::Stats {
		let (counters, samples) = (self.engine.counters(), self.samples.lock().unwrap_or_else(|e| e.into_inner()));
		let (mut rates, mut window) = (HashMap::new(), 0);
		if let (Some(old), Some(new)) = (samples.front(), samples.back()) {
			let secs = new.at.saturating_duration_since(old.at).as_secs_f64();
			if secs > 0.0 {
				let before: HashMap<(u8, &str), (u64, u64)> = old.names.iter().zip(&old.bytes).map(|((kind, name), bytes)| ((*kind, name.as_str()), *bytes)).collect();
				window = secs.round() as u64;
				// A name the older sample does not have has no rate yet.
				rates = new.names.iter().zip(&new.bytes).filter_map(|((kind, name), (up, down))| before.get(&(*kind, name.as_str())).map(|(was_up, was_down)| ((*kind, name.as_str()), ((up.saturating_sub(*was_up) as f64 / secs) as u64, (down.saturating_sub(*was_down) as f64 / secs) as u64)))).collect();
			}
		}
		let rated = |kind: u8, name: &str, totals: veilway_core::Totals| {
			let (up, down) = rates.get(&(kind, name)).copied().unwrap_or_default();
			model::Rated {name: name.to_string(), traffic: totals.into(), up_bytes_per_sec: up, down_bytes_per_sec: down}
		};
		// An outbound counts nothing itself: its numbers are those of its exits, added up here. Exits are matched by tag, because the document and the counters are read one after the other and a reload may come in between.
		let (snapshot, health, latencies) = (self.engine.snapshot(), self.engine.exit_health(), self.engine.latencies());
		let through: HashMap<&str, &str> = snapshot.config.exits.iter().filter_map(|exit| if let veilway_core::config::Backend::Netstack(netstack) = &exit.backend {Some((exit.tag.as_str(), netstack.outbound.as_str()))} else {None}).collect();
		let mut sums: HashMap<&str, (veilway_core::Totals, (u64, u64), Option<Duration>, u64)> = HashMap::new();
		for (tag, totals) in &counters.exits {
			let Some(sum) = through.get(tag.as_str()).map(|outbound| sums.entry(*outbound).or_default()) else {continue};
			let (up, down) = rates.get(&(crate::EXIT, tag.as_str())).copied().unwrap_or_default();
			(sum.0, sum.1) = (veilway_core::Totals {up_packets: sum.0.up_packets + totals.up_packets, up_bytes: sum.0.up_bytes + totals.up_bytes, down_packets: sum.0.down_packets + totals.down_packets, down_bytes: sum.0.down_bytes + totals.down_bytes}, (sum.1.0 + up, sum.1.1 + down));
		}
		for health in &health {
			let Some(sum) = through.get(health.exit.as_str()).map(|outbound| sums.entry(*outbound).or_default()) else {continue};
			(sum.2, sum.3) = ([sum.2, health.no_udp].into_iter().flatten().min(), sum.3 + health.udp_flips);
		}
		let (dns, control, obfs) = (self.engine.dns(), self.engine.control(), self.engine.obfs());
		model::Stats {
			window_secs: window,
			users: counters.users.iter().map(|usage| rated(crate::USER, &usage.name, usage.traffic)).collect(),
			inbounds: counters.inbounds.iter().map(|(tag, totals)| rated(crate::INBOUND, tag, *totals)).collect(),
			exits: counters.exits.iter().map(|(tag, totals)| rated(crate::EXIT, tag, *totals)).collect(),
			outbounds: snapshot.config.outbounds.iter().map(|outbound| {
				let (tag, proxied) = match outbound {
					Outbound::Direct {tag, ..} => (tag, false),
					Outbound::Socks5 {tag, ..} => (tag, true),
				};
				let (totals, (up, down), refused, flips) = sums.get(tag.as_str()).copied().unwrap_or_default();
				// Only a SOCKS5 proxy can refuse to relay UDP, as in `exits`.
				let refused = refused.filter(|_| proxied);
				let latency = latencies.get(tag).copied();
				model::OutboundStats {name: tag.clone(), traffic: totals.into(), up_bytes_per_sec: up, down_bytes_per_sec: down, udp: proxied.then_some(refused.is_none()), udp_down_secs: refused.map(|since| since.as_secs()), udp_flips: if proxied {flips} else {0}, latency_ms: latency.map(|(took, _)| took.as_millis() as u64), measured_at: latency.and_then(|(_, at)| at.duration_since(UNIX_EPOCH).ok()).map(|since| since.as_secs() as i64)}
			}).collect(),
			drops: Reason::ALL.iter().map(|reason| (reason.name().to_string(), self.engine.dropped(*reason))).collect(),
			dns: model::Dns {answered: dns.answered, refused: dns.refused, failed: dns.failed, malformed: dns.malformed, throttled: dns.throttled},
			flows: self.engine.flows(),
			ws_stalled: self.engine.ws_stalled(),
			ws_refused: self.engine.ws_refused(),
			state_write_failures: self.engine.state_write_failures(),
			send_failed: self.engine.send_failures(),
			control: model::Control {accepted: control.accepted, authenticated: control.authenticated, auth_failed: control.auth_failed, malformed: control.malformed, timed_out: control.timed_out, replaced: control.replaced, rate_limited: control.rate_limited, exits_selected: control.exits_selected, exits_refused: control.exits_refused, exits_dropped: control.exits_dropped, probe_runs: control.probe_runs, probes_confirmed: control.probes_confirmed, probes_sent: control.probes_sent, probes_refused: control.probes_refused, mtus_set: control.mtus_set, byes: control.byes, open: control.open},
			proxies: self.engine.proxies().into_iter().map(|(name, t)| model::ProxyStats {name, opened: t.opened, open: t.open, refused_logins: t.refused_logins, refused_limit: t.refused_limit, refused_source: t.refused_source, refused_busy: t.refused_busy, refused_blocked: t.refused_blocked, up_bytes: t.up_bytes, down_bytes: t.down_bytes}).collect(),
			tunnels: self.engine.tunnels().into_iter().map(|(name, t)| model::TunnelStats {name, opened: t.opened, open: t.open, refused_sources: t.refused_sources, refused_limit: t.refused_limit, refused_client: t.refused_client, refused_rate: t.refused_rate, refused_down: t.refused_down, refused_full: t.refused_full, connect_failed: t.connect_failed, reset: t.reset, idled: t.idled, dropped: t.dropped, up_bytes: t.up_bytes, down_bytes: t.down_bytes, up_packets: t.up_packets, down_packets: t.down_packets}).collect(),
			udp_obfs: model::UdpObfs {
				pending: obfs.pending, sessions: obfs.sessions, tags: obfs.tags, opened: obfs.opened, established: obfs.established, sent: obfs.sent, waited: obfs.waited, spent: obfs.spent, short: obfs.short, unknown: obfs.unknown, open_failed: obfs.open_failed, window: obfs.window, floor: obfs.floor, seen: obfs.seen, cache_full: obfs.cache_full, limit: obfs.limit, no_replay: obfs.no_replay,
				source_devices: obfs.source_devices, pool: obfs.pool, pending_full: obfs.pending_full, device_rate: obfs.device_rate, source_rate: obfs.source_rate, handshakes: obfs.handshakes, tunnel: obfs.tunnel, unsendable: obfs.unsendable,
				ended_deadline: obfs.ended_deadline, ended_idle: obfs.ended_idle, ended_packets: obfs.ended_packets, ended_replaced: obfs.ended_replaced, ended_displaced: obfs.ended_displaced, ended_revoked: obfs.ended_revoked, table_rebuilds: obfs.table_rebuilds, table_rebuilds_late: obfs.table_rebuilds_late, table_build_failures: obfs.table_build_failures, tag_collisions: obfs.tag_collisions,
			},
			stream: self.engine.stream().into(),
			replay: self.engine.replay().map(model::Replay::from),
		}
	}
}
