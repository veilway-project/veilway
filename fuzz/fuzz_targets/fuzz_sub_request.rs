#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::subscription::fetch::{Op, Received, RequestError, BODY_MAX, NAME_MAX};

// The body of a `POST` as a subscription endpoint gets it, from anyone. The whole input is the body.
// A body that reads must have one body a client writes for it, which reads back as the same request, and its name must be display text within its length. A body that is over the limit, or whose token does not read, is told apart from one that is only malformed, because the two get different answers.
fuzz_target!(|data: &[u8]| {
	match Received::read(data) {
		Ok(request) => {
			assert!(data.len() <= BODY_MAX && (1..=2).contains(&request.kids().len()) && *request.device_public_key() != [0; 32], "a request outside its limits");
			assert!(!matches!(request.op(), Op::Confirm(Some(name)) if name.as_str().is_empty() || name.as_str().chars().count() > NAME_MAX || name.as_str().chars().any(char::is_control)), "a device name that is no display text");
			assert_eq!(Received::read(&request.canonical()).as_ref(), Ok(&request), "a request did not read back from the body a client writes for it");
		}
		Err(RequestError::Malformed(_)) => assert!(data.len() <= BODY_MAX, "a body over the limit was read as far as its token"),
		Err(RequestError::Unreadable) => {}
	}
});
