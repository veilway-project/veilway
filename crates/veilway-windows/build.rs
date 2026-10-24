use ring::digest::{digest, SHA256};
use std::{env, fs};

/// SHA-256 of `wintun/bin/amd64/wintun.dll` in wintun-0.14.1.zip, whose own hash `apps/desktop/scripts/fetch-wintun.sh` pins.
const WINTUN_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

fn main() {
	println!("cargo:rustc-env=VEILWAY_WINTUN_SHA256={WINTUN_SHA256}");
	println!("cargo:rerun-if-env-changed=VEILWAY_WINTUN_DLL");
	if env::var_os("CARGO_FEATURE_EMBEDDED_WINTUN").is_none() || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {return}
	let path = env::var("VEILWAY_WINTUN_DLL").expect("the embedded-wintun feature needs VEILWAY_WINTUN_DLL: the amd64 wintun.dll of wintun-0.14.1");
	println!("cargo:rerun-if-changed={path}");
	let bytes = fs::read(&path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
	let found: String = digest(&SHA256, &bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
	assert_eq!(found, WINTUN_SHA256, "{path} is not the pinned wintun.dll 0.14.1");
}
