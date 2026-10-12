//! Strict JSON reading. serde's own error texts quote the offending value, so nothing here passes one through:
//! the document is first read into a small tree, then deserialized by a deserializer whose error type only
//! ever says where the problem is and what was expected.
use super::{Config, Diagnostic, MAX_FILE_BYTES, MAX_JSON_NODES, MAX_KEY_SHOWN};
use serde::de::{self, DeserializeSeed, Deserializer, Expected, IntoDeserializer, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::Deserialize;
use std::cell::Cell;
use std::collections::btree_map;
use std::collections::BTreeMap;
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

impl Config {
	/// Reads one document under the strict JSON rules. The result is not validated yet: call `validate`.
	pub fn parse(bytes: &[u8]) -> Result<Config, Diagnostic> {
		let fail = |message: String| Diagnostic {path: String::new(), message};
		if bytes.len() as u64 > MAX_FILE_BYTES {return Err(fail(format!("expected a document of at most {} MiB", MAX_FILE_BYTES >> 20)))}
		if bytes.starts_with(b"\xef\xbb\xbf") {return Err(fail("expected a document without a byte order mark".to_string()))}
		let text = std::str::from_utf8(bytes).map_err(|e| fail(format!("expected UTF-8, found an invalid sequence at byte {}", e.valid_up_to())))?;
		let (broken, nodes) = (Cell::new(""), Cell::new(0));
		let mut reader = serde_json::Deserializer::from_str(text);
		let json = Build(&broken, &nodes).deserialize(&mut reader).map_err(|e| {
			fail(format!("expected one JSON document, found {} at line {} column {}", if broken.get().is_empty() {"a syntax error"} else {broken.get()}, e.line(), e.column()))
		})?;
		reader.end().map_err(|e| fail(format!("expected one JSON document, found data after it at line {} column {}", e.line(), e.column())))?;
		Config::deserialize(De {json: &json, path: &Path::Root}).map_err(|e| Diagnostic {path: e.path.unwrap_or_default(), message: e.message})
	}
}
