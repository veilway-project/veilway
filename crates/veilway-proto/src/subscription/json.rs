//! Strict JSON for a payload and a request body ("Contents": "duplicate keys, a byte order mark, data after the document, invalid UTF-8 and a NUL inside a string are errors, and where an integer is expected only an integer token is accepted"), within the parsing limits of the table of numbers.
//!
//! The text is read by `serde_json` into a small tree, the way the config is read. What `serde_json` gives: it refuses a byte order mark, data after the document, invalid UTF-8, a raw control character and a lone surrogate, and it tells an integer token from every other number. What it does not give, and this module adds: it keeps the last of two equal keys, it takes `\u0000`, it nests 128 deep and it has no limit on the number of values. The depth is checked before a container is entered, so `serde_json` never nests deeper than this module lets it.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::{cell::Cell, collections::BTreeMap, fmt, ops::RangeInclusive};

/// "JSON nesting depth: at most 8." The payload object itself is the first level, and the pins of a candidate are the eighth.
pub const DEPTH_MAX: usize = 8;
/// "JSON values in a document: at most 20,000." Every value counts, the containers too.
pub const VALUES_MAX: usize = 20_000;

/// Which strict rule a text broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
	/// Not one JSON value: bad syntax, a byte order mark, data after the document, invalid UTF-8, a raw control character, a lone surrogate, a number no reader can hold.
	Syntax,
	/// Two members of one object with the same name.
	Duplicate,
	/// A NUL inside a string or a name.
	Nul,
	/// Nested deeper than `DEPTH_MAX`.
	Depth,
	/// More than `VALUES_MAX` values.
	Values,
	/// A member name longer than `STRING_MAX`.
	Name,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
	Null,
	Bool(bool),
	/// An integer token that is not negative.
	Uint(u64),
	/// Every other number: negative, with a fraction or an exponent, or too large. No member takes one, so its value is not kept.
	Number,
	Str(String),
	Arr(Vec<Json>),
	Obj(BTreeMap<String, Json>),
}

#[derive(Clone, Copy)]
struct Build<'c> {broken: &'c Cell<Option<JsonError>>, values: &'c Cell<usize>, depth: usize}

impl Build<'_> {
	fn fail<E: de::Error>(&self, error: JsonError) -> E {
		self.broken.set(Some(error));
		E::custom("")
	}
	fn enter<E: de::Error>(self) -> Result<Self, E> {if self.depth < DEPTH_MAX {Ok(Self {depth: self.depth + 1, ..self})} else {Err(self.fail(JsonError::Depth))}}
}

impl<'de> DeserializeSeed<'de> for Build<'_> {
	type Value = Json;
	fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Json, D::Error> {
		self.values.set(self.values.get() + 1);
		if self.values.get() > VALUES_MAX {return Err(self.fail(JsonError::Values))}
		deserializer.deserialize_any(self)
	}
}

impl<'de> Visitor<'de> for Build<'_> {
	type Value = Json;
	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("a JSON value")}
	fn visit_unit<E: de::Error>(self) -> Result<Json, E> {Ok(Json::Null)}
	fn visit_bool<E: de::Error>(self, value: bool) -> Result<Json, E> {Ok(Json::Bool(value))}
	fn visit_u64<E: de::Error>(self, value: u64) -> Result<Json, E> {Ok(Json::Uint(value))}
	fn visit_i64<E: de::Error>(self, value: i64) -> Result<Json, E> {Ok(u64::try_from(value).map_or(Json::Number, Json::Uint))}
	fn visit_f64<E: de::Error>(self, _: f64) -> Result<Json, E> {Ok(Json::Number)}
	fn visit_str<E: de::Error>(self, value: &str) -> Result<Json, E> {if value.contains('\0') {Err(self.fail(JsonError::Nul))} else {Ok(Json::Str(value.to_owned()))}}
	fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
		let (inner, mut items) = (self.enter()?, Vec::new());
		while let Some(item) = seq.next_element_seed(inner)? {items.push(item)}
		Ok(Json::Arr(items))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
		let (inner, mut members) = (self.enter()?, BTreeMap::new());
		while let Some(name) = map.next_key::<String>()? {
			if let Some(error) = if name.contains('\0') {Some(JsonError::Nul)} else if name.len() > super::STRING_MAX {Some(JsonError::Name)} else if members.contains_key(&name) {Some(JsonError::Duplicate)} else {None} {return Err(self.fail(error))}
			members.insert(name, map.next_value_seed(inner)?);
		}
		Ok(Json::Obj(members))
	}
}

/// Reads one JSON value that is the whole of `text`.
pub(crate) fn parse(text: &[u8]) -> Result<Json, JsonError> {
	let (broken, values) = (Cell::new(None), Cell::new(0));
	let mut reader = serde_json::Deserializer::from_slice(text);
	let read = Build {broken: &broken, values: &values, depth: 0}.deserialize(&mut reader).and_then(|value| reader.end().map(|_| value));
	read.map_err(|_| broken.get().unwrap_or(JsonError::Syntax))
}

/// What a member is refused with: its name, as the page writes it. A name is a word of this crate and never text from the document.
pub(crate) type Named<T> = Result<T, &'static str>;

/// The members of one object. Each reader gives `None` for a member that is absent, and the member's name as the error when it has another type or lies outside its range. `null` is another type, never an absent member.
#[derive(Clone, Copy)]
pub(crate) struct Members<'a>(pub(crate) &'a BTreeMap<String, Json>);

impl<'a> Members<'a> {
	pub(crate) fn of(value: &'a Json) -> Option<Self> {if let Json::Obj(members) = value {Some(Self(members))} else {None}}
	pub(crate) fn uint(&self, name: &'static str, range: RangeInclusive<u64>) -> Named<Option<u64>> {
		match self.0.get(name) {
			None => Ok(None),
			Some(Json::Uint(value)) if range.contains(value) => Ok(Some(*value)),
			Some(_) => Err(name),
		}
	}
	/// A string of at most `limit` bytes.
	pub(crate) fn string(&self, name: &'static str, limit: usize) -> Named<Option<&'a str>> {
		match self.0.get(name) {
			None => Ok(None),
			Some(Json::Str(value)) if value.len() <= limit => Ok(Some(value)),
			Some(_) => Err(name),
		}
	}
	pub(crate) fn boolean(&self, name: &'static str) -> Named<Option<bool>> {
		match self.0.get(name) {
			None => Ok(None),
			Some(Json::Bool(value)) => Ok(Some(*value)),
			Some(_) => Err(name),
		}
	}
	/// A list whose length lies in `count`.
	pub(crate) fn list(&self, name: &'static str, count: RangeInclusive<usize>) -> Named<Option<&'a [Json]>> {
		match self.0.get(name) {
			None => Ok(None),
			Some(Json::Arr(items)) if count.contains(&items.len()) => Ok(Some(items)),
			Some(_) => Err(name),
		}
	}
	pub(crate) fn object(&self, name: &'static str) -> Named<Option<Members<'a>>> {
		match self.0.get(name) {
			None => Ok(None),
			Some(value) => Members::of(value).map(Some).ok_or(name),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn what_the_strict_rules_refuse() {
		let nested = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
		for (text, error) in [
			(&b"{\"a\":1,\"a\":2}"[..], JsonError::Duplicate),
			(b"{\"a\":{\"b\":1,\"c\":2,\"b\":1}}", JsonError::Duplicate),
			// The same name, written once with an escape.
			(b"{\"a\":1,\"\\u0061\":2}", JsonError::Duplicate),
			(b"\xef\xbb\xbf{}", JsonError::Syntax),
			(b"{} {}", JsonError::Syntax),
			(b"{}x", JsonError::Syntax),
			(b"", JsonError::Syntax),
			(b"{\"a\":\"\xff\"}", JsonError::Syntax),
			(b"{\"a\":\"\xc0\x80\"}", JsonError::Syntax),
			(b"{\"a\":\"\\ud800\"}", JsonError::Syntax),
			(b"{\"a\":\"\x01\"}", JsonError::Syntax),
			(b"{\"a\":\"\x00\"}", JsonError::Syntax),
			(b"{\"a\":\"\\u0000\"}", JsonError::Nul),
			(b"{\"\\u0000\":1}", JsonError::Nul),
			(b"{\"a\":1e999}", JsonError::Syntax),
			(b"{'a':1}", JsonError::Syntax),
			(b"{\"a\":1,}", JsonError::Syntax),
			(b"{\"a\":01}", JsonError::Syntax),
			(b"{\"a\":NaN}", JsonError::Syntax),
			(nested(DEPTH_MAX + 1).as_bytes(), JsonError::Depth),
			(nested(100_000).as_bytes(), JsonError::Depth),
			(format!("[{}1]", "1,".repeat(VALUES_MAX - 1)).as_bytes(), JsonError::Values),
			(format!("{{\"{}\":1}}", "a".repeat(crate::subscription::STRING_MAX + 1)).as_bytes(), JsonError::Name),
		] {assert_eq!(parse(text), Err(error), "{}", String::from_utf8_lossy(&text[..text.len().min(40)]))}
		assert!(parse(nested(DEPTH_MAX).as_bytes()).is_ok() && parse(format!("[{}1]", "1,".repeat(VALUES_MAX - 2)).as_bytes()).is_ok() && parse(format!("{{\"{}\":1}}", "a".repeat(crate::subscription::STRING_MAX)).as_bytes()).is_ok());
	}

	// What `serde_json` does by itself with the four things this module adds a rule for, so that the day it changes shows here.
	#[test]
	fn what_the_library_alone_would_take() {
		let alone = |text: &str| serde_json::from_str::<serde_json::Value>(text);
		assert_eq!(alone("{\"a\":1,\"a\":2}").unwrap()["a"], 2);
		assert_eq!(alone("{\"a\":\"\\u0000\"}").unwrap()["a"], "\0");
		assert!(alone(&format!("{}1{}", "[".repeat(100), "]".repeat(100))).is_ok() && alone(&format!("[{}1]", "1,".repeat(VALUES_MAX))).is_ok());
		assert!(alone("{\"a\":1.0}").unwrap()["a"].is_f64() && alone("{\"a\":-0}").unwrap()["a"].is_f64());
	}

	#[test]
	fn only_an_integer_token_is_an_integer() {
		let number = |text: &str| parse(format!("{{\"a\":{text}}}").as_bytes()).map(|value| Members::of(&value).unwrap().uint("a", 0..=u64::MAX));
		for text in ["0", "1", "9007199254740991", "18446744073709551615"] {assert_eq!(number(text), Ok(Ok(Some(text.parse().unwrap()))), "{text}")}
		for text in ["1.0", "1e0", "1E2", "-1", "-0", "0.0", "18446744073709551616", "\"1\"", "true", "null", "[1]"] {assert_eq!(number(text), Ok(Err("a")), "{text}")}
		assert_eq!(parse(b"{\"a\":5}").map(|value| Members::of(&value).unwrap().uint("a", 6..=9)), Ok(Err("a")));
		assert_eq!(parse(b"{\"b\":5}").map(|value| Members::of(&value).unwrap().uint("a", 6..=9)), Ok(Ok(None)));
	}
}
