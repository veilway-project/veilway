#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::config::Config;

fuzz_target!(|data: &[u8]| {
	let Ok(config) = Config::parse(data) else {return};
	let errors = config.validate(true).errors.len();
	let json = serde_json::to_vec(&config).expect("a parsed config serializes");
	let again = Config::parse(&json).expect("the serialized config parses again");
	assert_eq!(again.validate(true).errors.len(), errors, "the round trip changed the validation result");
});
