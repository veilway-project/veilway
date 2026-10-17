//! Xray-core as the desktop apps run it for legacy profiles ("Xray in the desktop apps"): the release and its pins, which profiles can connect (`profile`) and the document the child reads from standard input (`document`). No IO here.
pub mod document;
pub mod profile;

/// The release of Xray-core the apps and the node run.
pub const RELEASE: &str = "v26.3.27";

/// The SHA-256 of a target's archive as the release publishes it, and of the `xray` executable the archive holds. A target without a pair is not installed.
pub struct Pin {
	pub target: &'static str,
	pub archive: &'static str,
	pub executable: &'static str,
}

// Linux: the archive values are from the installer's pins (scripts/veilway.sh) and the executables from the node's (engine/xray.rs). macOS and Windows: the archive values are the `.dgst` files of the release, each checked against its archive, and the executables are the `xray` or `xray.exe` entry of that archive, hashed as delivered.
pub const PINS: [Pin; 6] = [
	Pin {target: "linux-64", archive: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae", executable: "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"},
	Pin {target: "linux-arm64-v8a", archive: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c", executable: "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04"},
	Pin {target: "macos-64", archive: "f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203", executable: "afd0eaebb77994a18f29b00c5f50a4f7fbb77da06e24352d43035f3cad3c3786"},
	Pin {target: "macos-arm64-v8a", archive: "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf", executable: "5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404"},
	Pin {target: "windows-64", archive: "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad", executable: "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1"},
	Pin {target: "windows-arm64-v8a", archive: "35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88", executable: "e3340409afd87c1cd928e19208c78cb7271e9f95777aa5122db30759b6d2dc81"},
];

pub fn pin(target: &str) -> Option<&'static Pin> {PINS.iter().find(|pin| pin.target == target)}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pins_are_lowercase_sha256_and_targets_are_distinct() {
		for pin in &PINS {
			assert!(pin.archive.len() == 64 && pin.executable.len() == 64, "{}", pin.target);
			assert!(pin.archive.bytes().chain(pin.executable.bytes()).all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()), "{}", pin.target);
		}
		assert_eq!(PINS.iter().filter(|pin| pin.target == "linux-64").count(), 1);
		assert!(pin("freebsd-64").is_none());
	}
}
