//! The request of a native fetch (subscription format page, "The request"): the JSON that is sealed to the provider's gateway (`exchange`), written by a client and read by the gateway.
//!
//! The two sides are two types. A `Request` is what a client sends: it comes only out of the steps of `client`, after the user's first yes, and nothing makes one from bytes. A `Received` is what an endpoint read from a body, and nothing sends one. The answer is a document in the same envelope: a subscription or a signed refusal, both read by `payload::parse` and judged by `client`.
use super::{envelope::Kid, exchange::{self, GatewayKey, SealError, Sealed}, json::{self, Json, Members}, key_text, payload::INTEGER_MAX, public, sealed, unsealed, DeviceSecret, Text, Token};
use crate::Random;
use std::fmt;

/// "The JSON is at most 1,022 bytes, which leaves room in a plaintext of 1,024." The largest a client writes is under 600 bytes, with a name of 32 characters that are all written as escapes.
pub const BODY_MAX: usize = super::exchange::JSON_MAX;
/// "`device_name`: display text, at most 32 characters."
pub const NAME_MAX: usize = 32;

/// The name a user typed for a device: filtered and cut as display text, and never empty. "Only what the user typed. The client never fills it from the system."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName(Text);

impl DeviceName {
	/// `None` when nothing is left of what was typed: "Absent when the user typed nothing."
	pub fn typed(text: &str) -> Option<Self> {Some(Self(Text::shown(text, NAME_MAX, 4 * NAME_MAX))).filter(|name| !name.0.is_empty())}
	pub fn as_str(&self) -> &str {self.0.as_str()}
}

/// `op` of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
	Fetch,
	/// "Makes the place permanent, stores the name if one is sent."
	Confirm(Option<DeviceName>),
	/// Frees a pending place. "`release` never removes a confirmed device."
	Release,
}

// The one body a request has: the members in the order of the page's table, with no white space. `t` is the device's clock when the request is sealed.
fn written(token: &Token, t: u64, kids: &[Kid], device_public_key: &[u8; 32], device_secret: &DeviceSecret, op: &Op) -> Vec<u8> {
	let (op, name) = match op {
		Op::Fetch => ("fetch", None),
		Op::Confirm(name) => ("confirm", name.as_ref()),
		Op::Release => ("release", None),
	};
	// A string cannot fail to be written as JSON.
	let name = name.map_or(String::new(), |name| format!(",\"device_name\":{}", serde_json::to_string(name.as_str()).unwrap_or_default()));
	format!("{{\"v\":1,\"t\":{t},\"token\":\"{}\",\"kids\":[{}],\"device_public_key\":\"{}\",\"device_secret\":\"{}\",\"op\":\"{op}\"{name}}}", sealed(token.expose()), kids.iter().map(|kid| format!("\"{}\"", kid.text())).collect::<Vec<_>>().join(","), key_text(device_public_key), sealed(device_secret.expose())).into_bytes()
}

/// The request of a client. It holds the token and the device secret, so it prints neither and is written only by `body` or sealed by `seal`, for the one connection to an endpoint of the subscription.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {token: Token, kids: Vec<Kid>, device_public_key: [u8; 32], device_secret: DeviceSecret, op: Op}

impl fmt::Debug for Request {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Request({:?}, {} key ids, ..)", self.op, self.kids.len())}
}

impl Request {
	// The only place a request is made. `kids` is one or two: "the key ids of the signing keys the client holds for this subscription".
	pub(crate) fn new(token: Token, kids: Vec<Kid>, device_public_key: [u8; 32], device_secret: DeviceSecret, op: Op) -> Self {Self {token, kids, device_public_key, device_secret, op}}
	pub fn kids(&self) -> &[Kid] {&self.kids}
	pub fn op(&self) -> &Op {&self.op}
	/// The JSON that goes into the seal, with `t` the device's clock in Unix seconds, "and never a time taken from an answer". Nothing is sent as it stands.
	pub fn body(&self, t: u64) -> Vec<u8> {written(&self.token, t, &self.kids, &self.device_public_key, &self.device_secret, &self.op)}
	/// "Sealing a request": the 1,073 bytes of the `POST` to `key`, with a new ephemeral key from `random` every time, retries included, and the means to open the answer to this request and no other.
	pub fn seal(&self, key: &GatewayKey, t: u64, random: &mut Random) -> Result<Sealed, SealError> {exchange::seal(key, &self.body(t), random)}
}

/// Why a body is no request. The two cases get different answers from an endpoint ("The answer").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
	/// "A body that is not this JSON object", or one whose token cannot be read: the endpoint answers exactly as on a path it does not serve.
	Unreadable,
	/// The token and `t` read, and another member is missing or malformed, or the device key is all zero or of small order. If the token is a valid one and `t` is in the window, the gateway answers the signed refusal `"bad_request"`. If not, it answers as for `Unreadable`.
	Malformed(Token, u64),
}

impl fmt::Display for RequestError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {f.write_str(if matches!(self, Self::Unreadable) {"subscription request: unreadable"} else {"subscription request: malformed"})}
}

impl std::error::Error for RequestError {}

/// A request as the gateway read it from a sealed body. It cannot be sent: it is no `Request`, and it has no part in the steps of a client.
#[derive(Clone, PartialEq, Eq)]
pub struct Received {token: Token, t: u64, kids: Vec<Kid>, device_public_key: [u8; 32], device_secret: DeviceSecret, op: Op}

impl fmt::Debug for Received {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "Received({:?}, {} key ids, ..)", self.op, self.kids.len())}
}

impl Received {
	/// Reads the JSON out of a seal: strict JSON, one object with the members of the page's table and no other, each in its one form. "The request body is hostile input to the panel."
	/// A member this crate does not know is a malformed request, where a document's is ignored: the page says nothing of how a request grows, and an endpoint that skipped a member could not know what it was asked.
	/// The name is filtered as display text here, before it is stored: "after the same filter the client applies".
	pub fn read(body: &[u8]) -> Result<Self, RequestError> {
		let root = Some(body).filter(|body| body.len() <= BODY_MAX).and_then(|body| json::parse(body).ok()).ok_or(RequestError::Unreadable)?;
		let members = Members::of(&root).ok_or(RequestError::Unreadable)?;
		let token = members.string("token", 22).ok().flatten().and_then(unsealed).map(Token::new).ok_or(RequestError::Unreadable)?;
		let t = members.uint("t", 0..=INTEGER_MAX).ok().flatten().ok_or(RequestError::Unreadable)?;
		let rest = (|| -> Option<Self> {
			if members.0.keys().any(|name| !["v", "t", "token", "kids", "device_public_key", "device_secret", "op", "device_name"].contains(&name.as_str())) || members.uint("v", 1..=1).ok()?.is_none() {return None}
			let kids = members.list("kids", 1..=2).ok()??.iter().map(|kid| if let Json::Str(text) = kid {Kid::read(text)} else {None}).collect::<Option<Vec<_>>>()?;
			let op = match (members.string("op", 7).ok()??, members.string("device_name", usize::MAX).ok()?) {
				("fetch", None) => Op::Fetch,
				("release", None) => Op::Release,
				("confirm", None) => Op::Confirm(None),
				("confirm", Some(name)) => Op::Confirm(Some(DeviceName::typed(name)?)),
				_ => return None,
			};
			if kids.len() == 2 && kids[0] == kids[1] {return None}
			Some(Self {token: token.clone(), t, kids, device_public_key: public(members.string("device_public_key", 44).ok()??)?, device_secret: DeviceSecret::new(unsealed(members.string("device_secret", 22).ok()??)?), op})
		})();
		rest.ok_or(RequestError::Malformed(token, t))
	}
	/// The token, to look the account up by. It is compared in constant time.
	pub fn token(&self) -> &Token {&self.token}
	/// The device's clock when it sealed the request, Unix seconds: "the gateway acts on a request only when its `t` is within 300 s of the gateway's clock".
	pub fn t(&self) -> u64 {self.t}
	pub fn kids(&self) -> &[Kid] {&self.kids}
	pub fn device_public_key(&self) -> &[u8; 32] {&self.device_public_key}
	pub fn device_secret(&self) -> &DeviceSecret {&self.device_secret}
	pub fn op(&self) -> &Op {&self.op}
	/// The one body a client writes for this request. A body that reads is not always this one: a name is filtered as it is read, and JSON allows white space and escapes. An endpoint that wants to act only on what a client of this crate writes compares the body with this.
	pub fn canonical(&self) -> Vec<u8> {written(&self.token, self.t, &self.kids, &self.device_public_key, &self.device_secret, &self.op)}
}
