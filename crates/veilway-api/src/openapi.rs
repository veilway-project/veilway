//! The OpenAPI 3.1 document of the control API, generated from the route table and the types of the answers, so it cannot say anything else than what the router serves.
//! It is committed as `openapi.json` next to this crate's manifest, which is what the TypeScript SDK is generated from, and a test fails when that file is not what this produces.
use crate::routes::{event_schemas, parameter, routes};
use axum::http::StatusCode;
use schemars::generate::SchemaSettings;
use serde_json::{json, Map, Value};

/// The document, as the text of `openapi.json`.
pub fn openapi() -> String {
	let mut schemas = SchemaSettings::draft2020_12().with(|settings| (settings.definitions_path, settings.meta_schema) = ("/components/schemas".into(), None)).for_serialize().into_generator();
	let mut paths = Map::new();
	for route in routes(&mut schemas) {
		let responses: Map<String, Value> = route.responses.iter().map(|(status, meaning, schema)| (status.as_u16().to_string(), match schema {
			Some(schema) => json!({"description": meaning, "content": {"application/json": {"schema": schema}}}),
			None => json!({"description": meaning, "content": {"text/event-stream": {"schema": {"type": "string"}}}}),
		})).collect();
		// The wildcard of the relay route is a plain path parameter in the document.
		let path = route.path.replace("{*", "{");
		let mut parameters: Vec<Value> = path.split('/').filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}')).map(parameter).collect();
		// A route that can answer that the precondition is missing is a route that takes one.
		if route.responses.iter().any(|(status, ..)| *status == StatusCode::PRECONDITION_REQUIRED) {parameters.push(json!({"name": "If-Match", "in": "header", "required": true, "description": "The revision of the config the change was made on, as GET /v1/config gave it, with or without quotes.", "schema": {"type": "string"}}))}
		let mut operation = json!({"operationId": route.operation, "summary": route.summary, "parameters": parameters, "responses": responses});
		if let Some((schema, required)) = &route.body {operation["requestBody"] = json!({"required": required, "content": {"application/json": {"schema": schema}}})}
		paths.entry(path).or_insert_with(|| json!({}))[route.method.as_str().to_lowercase()] = operation;
	}
	let events: Map<String, Value> = event_schemas(&mut schemas).into_iter().map(|(name, schema)| (name.to_string(), json!(schema))).collect();
	let document = json!({
		"openapi": "3.1.0",
		"info": {
			"title": "Veilway control API",
			"version": env!("CARGO_PKG_VERSION"),
			"description": "HTTP/1.1 and JSON on the unix socket of a node. Whoever can open the socket is the administrator: there is no other authentication. Every answer that is not a success has the shape of ErrorBody. No answer and no event holds a secret."
		},
		"paths": paths,
		"components": {"schemas": schemas.take_definitions(true)},
		"x-events": events
	});
	format!("{document:#}\n")
}
