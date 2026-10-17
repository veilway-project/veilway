//! The kernel takes the rule of Xray's user (`uidrange`, attribute 20) and gives it back by the name a delete uses. Needs CAP_NET_ADMIN (`docker run --cap-add NET_ADMIN`); without it the test has nothing to try. It uses a priority and a user id of its own, so a client that runs in the same network namespace is not touched.
#![cfg(target_os = "linux")]
use std::io::ErrorKind;
use veilway_linux::netlink::{Rt, Rule, TABLE_MAIN};

fn listed() -> Option<String> {std::process::Command::new("ip").args(["rule", "show"]).output().ok().map(|output| String::from_utf8_lossy(&output.stdout).into_owned())}

#[test]
fn the_kernel_takes_a_rule_of_a_user_and_a_delete_by_its_name_removes_it() {
	let mut rt = Rt::open().unwrap();
	let rule = Rule {priority: 5199, uid: Some(4_242_424), table: TABLE_MAIN, ..Rule::default()};
	match rt.add_rule(&rule) {
		Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
		other => other.unwrap(),
	}
	if let Some(text) = listed() {assert!(text.contains("5199:") && text.contains("uidrange 4242424-4242424 lookup main"), "{text}")}
	// A cleanup does not know the user id, and names the rule by its priority and its table.
	assert_eq!(rt.delete_rule(&Rule {priority: 5199, table: TABLE_MAIN, ..Rule::default()}).unwrap(), 1);
	if let Some(text) = listed() {assert!(!text.contains("5199:"), "{text}")}
	assert_eq!(rt.delete_rule(&rule).unwrap(), 0, "nothing is wrong if it is not there");
}
