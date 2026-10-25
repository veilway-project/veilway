//! Xray-core as the desktop apps run it for legacy profiles ("Xray in the desktop apps"): the release and its pins, which profiles can connect (`profile`) and the document the child reads from standard input (`document`). No IO here.
pub mod document;
pub mod profile;

/// The release of Xray-core the apps and the node run.
pub const RELEASE: &str = "v26.10.21";

/// The SHA-256 of a target's archive as the release publishes it, and of the `xray` executable the archive holds. A target without a pair is not installed.
pub struct Pin {
	pub target: &'static str,
	pub archive: &'static str,
	pub executable: &'static str,
}

// Linux: the archive values are from the installer's pins (scripts/veilway.sh) and the executables from the node's (engine/xray.rs). macOS and Windows: the archive values are the `.dgst` files of the release, each checked against its archive, and the executables are the `xray` or `xray.exe` entry of that archive, hashed as delivered.
pub const PINS: [Pin; 6] = [
	Pin {target: "linux-64", archive: "0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978", executable: "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e"},
	Pin {target: "linux-arm64-v8a", archive: "d1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c", executable: "dc3324f437132d70d29ddadea19b202949c2d1230b5d90dac469b03f68829c8b"},
	Pin {target: "macos-64", archive: "8e5169b429e76ce5f550c8294db465bc259f30c158ba900aa40802b76ad2f66e", executable: "c91e9832e57eb0ef3bc84d1846a05585b30d24eda99429aa4d9a656063eb6a57"},
	Pin {target: "macos-arm64-v8a", archive: "926cc55fda2a8757dabe4f22dc98772f218ace025f101bd0b68aee232e59d5dc", executable: "94a9bfc0df6a0462552d535861f8a1580a0a6c94f7b0d30fe312daa0024ede2e"},
	Pin {target: "windows-64", archive: "fc58c39ee2f2717b4c54d28d374362389e5319b20ae44aea76ea45a5243ec827", executable: "c77a00eb84fb93ae044c2d771a1cabcc033b81e487253fbc35b12df6879c1e15"},
	Pin {target: "windows-arm64-v8a", archive: "bb44af3380c9975f951ce7645c04d56ab600040e68f23974a2806e08e0a3f872", executable: "bf47164a9be92afc87f50f1e22d25730f044222bfd6cedf9a524201379be023f"},
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
