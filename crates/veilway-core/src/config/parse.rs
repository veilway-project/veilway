//! Strict JSON reading. serde's own error texts quote the offending value, so nothing here passes one through:
//! the document is first read into a small tree, then deserialized by a deserializer whose error type only
//! ever says where the problem is and what was expected.
use super::{Config, Diagnostic, HostPort, Key, Outbound, Report, Secret, MAX_FILE_BYTES, MAX_JSON_NODES, MAX_KEY_SHOWN, REDACTED};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::{self, DeserializeSeed, Deserializer, Expected, IgnoredAny, IntoDeserializer, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::Deserialize;
use std::cell::Cell;
use std::collections::btree_map;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// `Negative` and `Fraction` keep no value: no key of the format takes one.
enum Json {Null, Bool(bool), Uint(u64), Negative, Fraction, Str(String), Arr(Vec<Json>), Obj(BTreeMap<String, Json>)}

/// Builds the tree, records in the first cell which strict rule a document broke and counts values in the second.
#[derive(Clone, Copy)]
struct Build<'c>(&'c Cell<&'static str>, &'c Cell<usize>);

impl<'de> DeserializeSeed<'de> for Build<'_> {
	type Value = Json;
	// Every value costs a tree node however short its text is, so the file size cap alone does not bound memory.
	fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Json, D::Error> {
		self.1.set(self.1.get() + 1);
		if self.1.get() > MAX_JSON_NODES {
			self.0.set("more than 8000000 values");
			return Err(de::Error::custom(""));
		}
		d.deserialize_any(self)
	}
}

impl<'de> Visitor<'de> for Build<'_> {
	type Value = Json;
	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("a JSON value")}
	fn visit_unit<E: de::Error>(self) -> Result<Json, E> {Ok(Json::Null)}
	fn visit_bool<E: de::Error>(self, v: bool) -> Result<Json, E> {Ok(Json::Bool(v))}
	fn visit_u64<E: de::Error>(self, v: u64) -> Result<Json, E> {Ok(Json::Uint(v))}
	fn visit_i64<E: de::Error>(self, v: i64) -> Result<Json, E> {Ok(u64::try_from(v).map_or(Json::Negative, Json::Uint))}
	fn visit_f64<E: de::Error>(self, _: f64) -> Result<Json, E> {Ok(Json::Fraction)}
	fn visit_str<E: de::Error>(self, v: &str) -> Result<Json, E> {
		if v.contains('\0') {
			self.0.set("a NUL character inside a string");
			return Err(E::custom(""));
		}
		Ok(Json::Str(v.to_owned()))
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
		let mut items = Vec::new();
		while let Some(item) = seq.next_element_seed(self)? {items.push(item)}
		Ok(Json::Arr(items))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
		let mut entries = BTreeMap::new();
		while let Some(key) = map.next_key::<String>()? {
			let broken = if key.contains('\0') {"a NUL character inside a key"} else if entries.contains_key(&key) {"a duplicate key"} else {""};
			if !broken.is_empty() {
				self.0.set(broken);
				return Err(de::Error::custom(""));
			}
			entries.insert(key, map.next_value_seed(self)?);
		}
		Ok(Json::Obj(entries))
	}
}

/// A key as it may appear in a diagnostic: escaped, and cut at `MAX_KEY_SHOWN` bytes.
fn shown(key: &str) -> String {
	let mut end = key.len().min(MAX_KEY_SHOWN);
	while !key.is_char_boundary(end) {end -= 1}
	format!("{}{}", key[..end].escape_default(), if end < key.len() {"..."} else {""})
}

#[derive(Clone, Copy)]
enum Path<'a> {Root, Key(&'a Path<'a>, &'a str), Index(&'a Path<'a>, usize)}

impl fmt::Display for Path<'_> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Path::Root => Ok(()),
			Path::Key(Path::Root, key) => f.write_str(&shown(key)),
			Path::Key(parent, key) => write!(f, "{parent}.{}", shown(key)),
			Path::Index(parent, i) => write!(f, "{parent}[{i}]"),
		}
	}
}

#[derive(Debug)]
struct DeError {path: Option<String>, message: String}

impl fmt::Display for DeError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str(&self.message)}
}

impl std::error::Error for DeError {}

impl de::Error for DeError {
	// The text of a custom error is written by whoever raised it and may quote the input, so it is dropped.
	fn custom<T: fmt::Display>(_: T) -> DeError {DeError {path: None, message: "invalid value".to_string()}}
	fn invalid_type(found: Unexpected, expected: &dyn Expected) -> DeError {
		let found = match found {
			Unexpected::Bool(_) => "true or false",
			Unexpected::Unsigned(_) => "an integer",
			Unexpected::Signed(_) => "a negative integer",
			Unexpected::Float(_) => "a number that is not a plain integer",
			Unexpected::Str(_) | Unexpected::Char(_) => "a string",
			Unexpected::Unit | Unexpected::Option => "null",
			Unexpected::Seq => "a list",
			Unexpected::Map => "an object",
			_ => "another kind of value",
		};
		DeError {path: None, message: format!("expected {expected}, found {found}")}
	}
	fn invalid_value(_: Unexpected, expected: &dyn Expected) -> DeError {DeError {path: None, message: format!("expected {expected}")}}
	fn invalid_length(_: usize, expected: &dyn Expected) -> DeError {DeError {path: None, message: format!("expected {expected}")}}
	fn unknown_variant(_: &str, expected: &'static [&'static str]) -> DeError {
		DeError {path: None, message: format!("unknown value, expected one of: {}; the config may be newer than this build", expected.join(", "))}
	}
	fn unknown_field(field: &str, _: &'static [&'static str]) -> DeError {
		DeError {path: None, message: format!("unknown key \"{}\"; the config may be newer than this build", shown(field))}
	}
	fn missing_field(field: &'static str) -> DeError {DeError {path: None, message: format!("missing required key `{field}`")}}
	fn duplicate_field(field: &'static str) -> DeError {DeError {path: None, message: format!("duplicate key `{field}`")}}
}

#[derive(Clone, Copy)]
struct De<'a> {json: &'a Json, path: &'a Path<'a>}

impl De<'_> {
	/// The innermost deserializer that sees an error stamps its own path on it.
	fn at(&self, mut e: DeError) -> DeError {
		e.path.get_or_insert_with(|| self.path.to_string());
		e
	}

	fn mismatch<T>(&self, expected: &dyn Expected) -> Result<T, DeError> {
		let found = match self.json {
			Json::Null => Unexpected::Unit,
			Json::Bool(b) => Unexpected::Bool(*b),
			Json::Uint(n) => Unexpected::Unsigned(*n),
			Json::Negative => Unexpected::Signed(-1),
			Json::Fraction => Unexpected::Float(0.0),
			Json::Str(s) => Unexpected::Str(s),
			Json::Arr(_) => Unexpected::Seq,
			Json::Obj(_) => Unexpected::Map,
		};
		Err(self.at(de::Error::invalid_type(found, expected)))
	}

	fn uint<'de, V: Visitor<'de>>(self, max: u64, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Uint(n) if *n <= max => visitor.visit_u64(*n).map_err(|e| self.at(e)),
			Json::Uint(_) => Err(self.at(de::Error::invalid_value(Unexpected::Other("integer"), &format!("an integer from 0 to {max}").as_str()))),
			_ => self.mismatch(&format!("an integer from 0 to {max}").as_str()),
		}
	}
}

impl<'de> Deserializer<'de> for De<'_> {
	type Error = DeError;
	fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Null => visitor.visit_unit(),
			Json::Bool(b) => visitor.visit_bool(*b),
			Json::Uint(n) => visitor.visit_u64(*n),
			Json::Negative | Json::Fraction => return self.mismatch(&visitor),
			Json::Str(s) => visitor.visit_str(s),
			Json::Arr(items) => visitor.visit_seq(Items {iter: items.iter().enumerate(), path: self.path}),
			Json::Obj(entries) => visitor.visit_map(Entries {iter: entries.iter(), value: None, path: self.path}),
		}.map_err(|e| self.at(e))
	}
	fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Bool(b) => visitor.visit_bool(*b).map_err(|e| self.at(e)),
			_ => self.mismatch(&"true or false"),
		}
	}
	fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {self.uint(u8::MAX as u64, visitor)}
	fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {self.uint(u16::MAX as u64, visitor)}
	fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {self.uint(u32::MAX as u64, visitor)}
	fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {self.uint(u64::MAX, visitor)}
	// `deserialize_str` is what the format's own value types call, so a mismatch names what they expect. `String` calls `deserialize_string`.
	fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Str(s) => visitor.visit_str(s).map_err(|e| self.at(e)),
			_ => self.mismatch(&visitor),
		}
	}
	fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Str(s) => visitor.visit_str(s).map_err(|e| self.at(e)),
			_ => self.mismatch(&"a string"),
		}
	}
	// An optional key is left out. A null is a wrong value, not an absent one.
	fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {visitor.visit_some(self)}
	fn deserialize_newtype_struct<V: Visitor<'de>>(self, _: &'static str, visitor: V) -> Result<V::Value, DeError> {visitor.visit_newtype_struct(self)}
	fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Arr(_) => self.deserialize_any(visitor),
			_ => self.mismatch(&"a list"),
		}
	}
	fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Obj(_) => self.deserialize_any(visitor),
			_ => self.mismatch(&"an object"),
		}
	}
	fn deserialize_struct<V: Visitor<'de>>(self, _: &'static str, _: &'static [&'static str], visitor: V) -> Result<V::Value, DeError> {self.deserialize_map(visitor)}
	fn deserialize_enum<V: Visitor<'de>>(self, _: &'static str, variants: &'static [&'static str], visitor: V) -> Result<V::Value, DeError> {
		match self.json {
			Json::Str(s) => visitor.visit_enum(s.as_str().into_deserializer()).map_err(|e| self.at(e)),
			_ => self.mismatch(&format!("one of: {}", variants.join(", ")).as_str()),
		}
	}
	serde::forward_to_deserialize_any! {i8 i16 i32 i64 i128 u128 f32 f64 char bytes byte_buf unit unit_struct tuple tuple_struct identifier ignored_any}
}

struct Items<'a> {iter: std::iter::Enumerate<std::slice::Iter<'a, Json>>, path: &'a Path<'a>}

impl<'de> SeqAccess<'de> for Items<'_> {
	type Error = DeError;
	fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, DeError> {
		// A value type may fail after its own deserializer returned, so the path is stamped here as well.
		self.iter.next().map(|(i, json)| seed.deserialize(De {json, path: &Path::Index(self.path, i)}).map_err(|e| De {json, path: &Path::Index(self.path, i)}.at(e))).transpose()
	}
}

struct Entries<'a> {iter: btree_map::Iter<'a, String, Json>, value: Option<(&'a str, &'a Json)>, path: &'a Path<'a>}

impl<'de> MapAccess<'de> for Entries<'_> {
	type Error = DeError;
	fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, DeError> {
		let Some((key, json)) = self.iter.next() else {return Ok(None)};
		self.value = Some((key, json));
		seed.deserialize(key.as_str().into_deserializer()).map(Some)
	}
	fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, DeError> {
		match self.value.take() {
			Some((key, json)) => seed.deserialize(De {json, path: &Path::Key(self.path, key)}).map_err(|e| De {json, path: &Path::Key(self.path, key)}.at(e)),
			None => Err(de::Error::custom("")),
		}
	}
}

/// The tree of one document under the strict JSON rules.
fn tree(bytes: &[u8]) -> Result<Json, Diagnostic> {
	let fail = |message: String| Diagnostic {path: String::new(), message};
	if bytes.len() as u64 > MAX_FILE_BYTES {return Err(fail(format!("expected a document of at most {} MiB", MAX_FILE_BYTES >> 20)))}
	if bytes.starts_with(b"\xef\xbb\xbf") {return Err(fail("expected a document without a byte order mark".to_string()))}
	let text = std::str::from_utf8(bytes).map_err(|e| fail(format!("expected UTF-8, found an invalid sequence at byte {}", e.valid_up_to())))?;
	// A config is an object. Anything else is refused for what it is before a tree of it is built: a list of short values takes many times the memory of its text, and whoever sends one gets nothing for it but this.
	let first = text.trim_start_matches([' ', '\t', '\n', '\r']).bytes().next();
	if first != Some(b'{') {
		return Err(fail(match (serde_json::from_str::<IgnoredAny>(text), first) {
			(Err(e), _) => format!("expected one JSON document, found a syntax error at line {} column {}", e.line(), e.column()),
			(Ok(_), Some(b'[')) => "expected an object, found a list".to_string(),
			(Ok(_), Some(b'"')) => "expected an object, found a string".to_string(),
			(Ok(_), Some(b't' | b'f')) => "expected an object, found true or false".to_string(),
			(Ok(_), Some(b'n')) => "expected an object, found null".to_string(),
			(Ok(_), _) => "expected an object, found a number".to_string(),
		}));
	}
	let (broken, nodes) = (Cell::new(""), Cell::new(0));
	let mut reader = serde_json::Deserializer::from_str(text);
	let json = Build(&broken, &nodes).deserialize(&mut reader).map_err(|e| {
		fail(format!("expected one JSON document, found {} at line {} column {}", if broken.get().is_empty() {"a syntax error"} else {broken.get()}, e.line(), e.column()))
	})?;
	reader.end().map_err(|e| fail(format!("expected one JSON document, found data after it at line {} column {}", e.line(), e.column())))?;
	Ok(json)
}

impl Config {
	/// Reads one document under the strict JSON rules. The result is not validated yet: call `validate`.
	pub fn parse(bytes: &[u8]) -> Result<Config, Diagnostic> {
		let json = tree(bytes)?;
		Config::deserialize(De {json: &json, path: &Path::Root}).map_err(|e| Diagnostic {path: e.path.unwrap_or_default(), message: e.message})
	}

	/// `parse` for a document in which a secret may hold `REDACTED` in the place of its value, which is how the control API shows a config and takes it back.
	/// The marker stands for the value of the same object in `running`: the `private_key` of the inbound with that tag, the `preshared_key` of the device with that `public_key`,
	/// and the `username` and `password` of the socks5 outbound with that tag and that `server`. The server is part of it because that is who the node sends them to: kept for another one, they would go to whoever the document names.
	/// A marker `running` has no value for is an error at the path of its field, and so is the marker anywhere else, where it is no valid value. The result holds the real secrets.
	/// Next to it come the tags of the outbounds whose `username` or `password` the document spells out, which is what lets a caller say "changed" for them without saying whether they are what runs.
	pub fn parse_keeping(bytes: &[u8], running: &Config) -> Result<(Config, Vec<String>), Report> {
		let (mut json, mut report, mut spelled) = (tree(bytes).map_err(|e| Report {errors: vec![e], ..Report::default()})?, Report::default(), Vec::new());
		let marked = |object: &BTreeMap<String, Json>, key: &str| matches!(object.get(key), Some(Json::Str(value)) if value == REDACTED);
		let named = |object: &BTreeMap<String, Json>, key: &str| match object.get(key) {
			Some(Json::Str(name)) => Some(name.clone()),
			_ => None,
		};
		// A document that is no object has no secret to keep, and `deserialize` says what is wrong with it.
		let mut nothing = BTreeMap::new();
		let root = if let Json::Obj(root) = &mut json {root} else {&mut nothing};
		if let Some(Json::Arr(inbounds)) = root.get_mut("inbounds") {
			for (i, inbound) in inbounds.iter_mut().enumerate() {
				let Json::Obj(inbound) = inbound else {continue};
				if !marked(inbound, "private_key") {continue}
				match named(inbound, "tag").and_then(|tag| running.inbounds.iter().find(|was| was.tag == tag)) {
					Some(was) => drop(inbound.insert("private_key".to_string(), Json::Str(STANDARD.encode(was.private_key.expose().0)))),
					None => report.error(format!("inbounds[{i}].private_key"), "expected a key: the marker stands for the key of the running inbound with this tag, and no inbound runs under it"),
				}
			}
		}
		if let Some(Json::Arr(outbounds)) = root.get_mut("outbounds") {
			for (i, outbound) in outbounds.iter_mut().enumerate() {
				let Json::Obj(outbound) = outbound else {continue};
				let (tag, server) = (named(outbound, "tag"), outbound.get("server").and_then(|json| HostPort::deserialize(De {json, path: &Path::Root}).ok()));
				if ["username", "password"].iter().any(|key| outbound.contains_key(*key) && !marked(outbound, *key)) {spelled.extend(tag.clone())}
				for key in ["username", "password"] {
					if !marked(outbound, key) {continue}
					let kept = tag.as_ref().zip(server.as_ref()).and_then(|(tag, server)| running.outbounds.iter().find_map(|was| match was {
						Outbound::Socks5 {tag: of, server: at, username, password} if of == tag && at == server => if key == "username" {username.as_ref()} else {password.as_ref()},
						_ => None,
					}));
					match kept {
						Some(kept) => drop(outbound.insert(key.to_string(), Json::Str(kept.expose().clone()))),
						None => report.error(format!("outbounds[{i}].{key}"), format!("expected a {key}: the marker stands for the {key} of the running socks5 outbound with this tag and this server, and no such outbound runs with one. For a server that is new or has changed, the {key} has to be sent itself")),
					}
				}
			}
		}
		if let Some(Json::Arr(users)) = root.get_mut("users") {
			let shared: HashMap<[u8; 32], &Secret<Key>> = running.users.iter().flat_map(|user| &user.devices).filter_map(|device| device.preshared_key.as_ref().map(|key| (device.public_key.0, key))).collect();
			for (u, user) in users.iter_mut().enumerate() {
				let Json::Obj(user) = user else {continue};
				let Some(Json::Arr(devices)) = user.get_mut("devices") else {continue};
				for (d, device) in devices.iter_mut().enumerate() {
					let Json::Obj(device) = device else {continue};
					if !marked(device, "preshared_key") {continue}
					match named(device, "public_key").and_then(|key| <[u8; 32]>::try_from(STANDARD.decode(key).ok()?).ok()).and_then(|key| shared.get(&key)) {
						Some(kept) => drop(device.insert("preshared_key".to_string(), Json::Str(STANDARD.encode(kept.expose().0)))),
						None => report.error(format!("users[{u}].devices[{d}].preshared_key"), "expected a key: the marker stands for the preshared key of the running device with this public_key, and no device runs under it with one"),
					}
				}
			}
		}
		if !report.errors.is_empty() {return Err(report)}
		Config::deserialize(De {json: &json, path: &Path::Root}).map(|config| (config, spelled)).map_err(|e| Report {errors: vec![Diagnostic {path: e.path.unwrap_or_default(), message: e.message}], ..Report::default()})
	}
}
