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
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::broadcast::error::RecvError;
use veilway_core::config::{ApplyError, Config, Diff, Outbound, Snapshot, NAME_PATTERN};
use veilway_core::{Denied, Over, Reason};

pub(crate) const EVENTS: &str = "/v1/events";
const CONFIG: &str = "/v1/config";
/// How many times the body limit a request may send before the node stops taking its body off the connection.
const DRAIN: usize = 4;

/// One route as the router serves it and as the OpenAPI document describes it.
pub(crate) struct Route {
	pub method: Method,
	pub path: &'static str,
	pub operation: &'static str,
	pub summary: &'static str,
	pub handler: MethodRouter<Arc<Api>>,
	/// Whether the request carries a config document.
	pub document: bool,
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

/// The body of a request that carries a config document, read up to the limit and no further.
async fn document(api: &Api, request: Request) -> Result<Vec<u8>, Failure> {
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
	json(StatusCode::OK, &model::Status {version: env!("CARGO_PKG_VERSION").to_string(), generation: snapshot.generation, revision: snapshot.revision.to_string(), uptime_secs: api.engine.uptime().as_secs(), inbounds: plan.inbounds.len(), exits: plan.exits.len(), users: plan.users.len(), flows: api.engine.flows()})
}

async fn running(State(api): State<Arc<Api>>) -> Response {
	let snapshot = api.engine.snapshot();
	let mut response = json(StatusCode::OK, &model::Running {revision: snapshot.revision.to_string(), generation: snapshot.generation, document: model::Document(snapshot.config.redacted())});
	if let Ok(tag) = HeaderValue::from_str(&format!("\"{}\"", snapshot.revision)) {response.headers_mut().insert(ETAG, tag);}
	response
}

async fn validate(State(api): State<Arc<Api>>, request: Request) -> Response {
	let bytes = match document(&api, request).await {
		Ok(bytes) => bytes,
		Err(failure) => return failure.into_response(),
	};
	match check(&api, api.engine.snapshot(), bytes, true).await {
		Ok((config, report)) => json(StatusCode::OK, &model::Validation {valid: config.is_some(), report: (&report).into()}),
		Err(failure) => failure.into_response(),
	}
}

async fn difference(State(api): State<Arc<Api>>, request: Request) -> Response {
	let bytes = match document(&api, request).await {
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
		let bytes = document(&api, request).await?;
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

async fn stats(State(api): State<Arc<Api>>) -> Response {json(StatusCode::OK, &api.stats())}

async fn sessions(State(api): State<Arc<Api>>) -> Response {
	json(StatusCode::OK, &model::Sessions {sessions: api.engine.peers(None).into_iter().filter_map(|peer| Some(model::Session {
		handshake_age_secs: peer.handshake?.as_secs(),
		user: peer.user,
		device: peer.device,
		public_key: key(&veilway_core::config::Key(peer.public_key)),
		inbound: peer.inbound,
		transport: peer.over.map(|over| match over {
			Over::Udp => model::Transport::Udp,
			Over::Ws => model::Transport::Ws,
		}),
		flows: peer.flows,
	})).collect()})
}

async fn exits(State(api): State<Arc<Api>>) -> Response {
	let (snapshot, counters, health) = (api.engine.snapshot(), api.engine.counters(), api.engine.exit_health());
	json(StatusCode::OK, &model::Exits {exits: snapshot.config.exits.iter().map(|exit| {
		let (health, outbound) = (health.iter().find(|health| health.exit == exit.tag), if let veilway_core::config::Backend::Netstack(netstack) = &exit.backend {Some(netstack.outbound.clone())} else {None});
		// Only a SOCKS5 proxy can refuse to relay UDP, so only an exit through one has anything to say here.
		let proxied = outbound.as_ref().is_some_and(|tag| snapshot.config.outbounds.iter().any(|outbound| matches!(outbound, Outbound::Socks5 {tag: of, ..} if of == tag)));
		let down = health.and_then(|health| health.no_udp).filter(|_| proxied);
		model::Exit {
			tag: exit.tag.clone(),
			name: exit.name.clone().unwrap_or_else(|| exit.tag.clone()),
			backend: match exit.backend {
				veilway_core::config::Backend::Netstack(_) => model::Backend::Netstack,
				veilway_core::config::Backend::L3(_) => model::Backend::L3,
				veilway_core::config::Backend::Block {} => model::Backend::Block,
			},
			outbound,
			udp: proxied.then_some(down.is_none()),
			udp_down_secs: down.map(|down| down.as_secs()),
			udp_flips: health.map_or(0, |health| health.udp_flips),
			interface_up: health.and_then(|health| health.interface_down).map(|down| down.is_none()),
			interface_down_secs: health.and_then(|health| health.interface_down).flatten().map(|down| down.as_secs()),
			interface_flips: health.map_or(0, |health| health.interface_flips),
			traffic: counters.exits.iter().find(|(tag, _)| *tag == exit.tag).map(|(_, totals)| *totals).unwrap_or_default().into(),
		}
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
/// An apply keeps the time itself, see `apply`: it must never be ended here while the engine is putting its config in force.
pub(crate) async fn deadline(State(api): State<Arc<Api>>, request: Request, next: Next) -> Response {
	if request.uri().path() == EVENTS || (request.uri().path() == CONFIG && request.method() == Method::PUT) {return next.run(request).await}
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
		("stats", schemas.subschema_for::<model::Stats>()),
		("lagged", schemas.subschema_for::<model::Lagged>()),
	]
}

/// One row of the table. `T` is what the route answers a request that went well with, and every route may also answer that a request took too long or that the node is full.
fn route<T: JsonSchema, H: Handler<X, Arc<Api>>, X: 'static>(schemas: &mut SchemaGenerator, method: Method, path: &'static str, operation: &'static str, summary: &'static str, handler: H, document: bool, failures: &[(StatusCode, &'static str)]) -> Route {
	let failure = schemas.subschema_for::<model::ErrorBody>();
	let mut responses = vec![(StatusCode::OK, "The answer.", Some(schemas.subschema_for::<T>()))];
	if document {responses.extend([(StatusCode::BAD_REQUEST, "The body is not one JSON document, or could not be read to its end."), (StatusCode::PAYLOAD_TOO_LARGE, "The body is larger than 4 MiB."), (StatusCode::UNSUPPORTED_MEDIA_TYPE, "The body was not sent as application/json.")].map(|(status, meaning)| (status, meaning, Some(failure.clone()))))}
	responses.extend(failures.iter().map(|(status, meaning)| (*status, *meaning, Some(failure.clone()))));
	responses.extend([(StatusCode::REQUEST_TIMEOUT, "The request was not finished within 30 seconds."), (StatusCode::SERVICE_UNAVAILABLE, "The node already serves as many connections, or as many event streams, as it takes at once.")].map(|(status, meaning)| (status, meaning, Some(failure.clone()))));
	Route {handler: on(MethodFilter::try_from(method.clone()).unwrap_or(MethodFilter::GET), handler), method, path, operation, summary, document, responses}
}

/// Every route of the API. The router serves exactly these and the OpenAPI document describes exactly these.
pub(crate) fn routes(schemas: &mut SchemaGenerator) -> Vec<Route> {
	let mut stream = route::<model::Stats, _, _>(schemas, Method::GET, EVENTS, "events", "Server-Sent Events: config_applied, config_refused, user_cut_off, user_restored, exit_udp_changed, and stats once a second. Each has an increasing id. A reader that is too slow loses events and gets a lagged event, which has no id, saying how many. A comment line every 15 seconds keeps the stream alive.", events, false, &[]);
	stream.responses[0] = (StatusCode::OK, "The stream. The data of each event is one JSON document, see x-events.", None);
	let mut put = route::<model::Applied, _, _>(schemas, Method::PUT, CONFIG, "applyConfig", "Puts a config in force, the way a reload on SIGHUP does, and writes it to the config file. If-Match must name the revision the change was made on. A document that is refused changes nothing. An outbound keeps its username and password for a marker only while its server is the same.", apply, true, &[(StatusCode::CONFLICT, "The running config is not the one If-Match names. The details and the ETag hold the revision that runs."), (StatusCode::UNPROCESSABLE_ENTITY, "The document is not a valid config, or the node could not prepare it. Nothing was changed."), (StatusCode::PRECONDITION_REQUIRED, "The header If-Match is missing.")]);
	for response in put.responses.iter_mut().filter(|(status, ..)| *status == StatusCode::REQUEST_TIMEOUT) {response.1 = "The document was not read and checked within 30 seconds. Nothing was changed: once the node has begun to put a config in force, the answer waits for it however long that takes, and is never this one."}
	vec![
		route::<model::Status, _, _>(schemas, Method::GET, "/v1/status", "status", "What runs: the version, the config in force and how much of everything there is.", status, false, &[]),
		route::<model::Running, _, _>(schemas, Method::GET, "/v1/config", "getConfig", "The running config with every secret replaced by the marker \"<redacted>\", and its revision, which is also the ETag.", running, false, &[]),
		put,
		route::<model::Validation, _, _>(schemas, Method::POST, "/v1/config/validate", "validateConfig", "Validates a document and changes nothing. Errors and warnings name the path of a field and never its value.", validate, true, &[]),
		route::<model::Difference, _, _>(schemas, Method::POST, "/v1/config/diff", "diffConfig", "What an apply of the document would add, change and remove, by tag and name. Nothing changes. An outbound whose username or password is written out, and not left as the marker, is listed as changed whatever they are.", difference, true, &[]),
		route::<model::Users, _, _>(schemas, Method::GET, "/v1/users", "listUsers", "Every user of the running config with their usage, counters and devices.", users, false, &[]),
		route::<model::User, _, _>(schemas, Method::GET, "/v1/users/{name}", "getUser", "One user.", user, false, &[(StatusCode::NOT_FOUND, "The running config has no user of that name.")]),
		route::<model::Stats, _, _>(schemas, Method::GET, "/v1/stats", "stats", "Every counter at one moment, with rates in bytes per second over the last 5 seconds.", stats, false, &[]),
		route::<model::Sessions, _, _>(schemas, Method::GET, "/v1/sessions", "listSessions", "The devices with a live session.", sessions, false, &[]),
		route::<model::Exits, _, _>(schemas, Method::GET, "/v1/exits", "listExits", "Every exit with what the node knows of its upstream, and its counters.", exits, false, &[]),
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
		let dns = self.engine.dns();
		model::Stats {
			window_secs: window,
			users: counters.users.iter().map(|usage| rated(crate::USER, &usage.name, usage.traffic)).collect(),
			inbounds: counters.inbounds.iter().map(|(tag, totals)| rated(crate::INBOUND, tag, *totals)).collect(),
			exits: counters.exits.iter().map(|(tag, totals)| rated(crate::EXIT, tag, *totals)).collect(),
			drops: Reason::ALL.iter().map(|reason| (reason.name().to_string(), self.engine.dropped(*reason))).collect(),
			dns: model::Dns {answered: dns.answered, refused: dns.refused, failed: dns.failed, malformed: dns.malformed, throttled: dns.throttled},
			flows: self.engine.flows(),
			ws_stalled: self.engine.ws_stalled(),
			ws_refused: self.engine.ws_refused(),
			state_write_failures: self.engine.state_write_failures(),
		}
	}
}
