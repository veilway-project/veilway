//! The kill switch across a reboot. The pf rules are in the kernel, and a reboot empties the kernel: a connection that crashed (and so left the rules in force) and then a restart would leave the device with no kill switch and no tunnel.
//!
//! So a connection with the kill switch on writes a marker, the tunnel-less ruleset it first installed (`kept.rules` in the data folder, root's, mode 0600), and makes sure a LaunchDaemon exists (`/Library/LaunchDaemons/com.veilway.restore.plist`, `RunAtLoad`) that runs `veilway restore` at every boot. `restore` loads the marker's rules if the marker is there, and does nothing if it is not. The marker is removed only by a clean stop or by `cleanup` (`veilway disconnect`), which also lift the rules, so the rules and the marker are in force together. The daemon is left in place: without a marker it does nothing.
//!
//! The daemon runs the program as root at boot, so the program is only named in the plist if it, and every folder above it, is root's and closed to others: a plist that named a binary a user can replace would be a way to root. The marker is read only if it is a regular file of root's with mode 0600, and only if every line of it is a `pass` or a `block` rule, which is all `Rules::ruleset` writes.
use crate::state::{chain_problem, secure_dir};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use veilway_engine::store::write_atomic;

pub const DAEMON_DIR: &str = "/Library/LaunchDaemons";
pub const LABEL: &str = "com.veilway.restore";
const MARKER: &str = "kept.rules";
const RULES_MAX: usize = 64 * 1024;

fn xml_escape(text: &str) -> String {text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")}

/// The property list of the LaunchDaemon: it runs `veilway restore` at load, once, and its output goes to a log of root's.
pub fn plist(exe: &Path) -> String {
	format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>{LABEL}</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{}</string>\n\t\t<string>restore</string>\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>StandardErrorPath</key>\n\t<string>/var/log/veilway-restore.log</string>\n\t<key>StandardOutPath</key>\n\t<string>/var/log/veilway-restore.log</string>\n</dict>\n</plist>\n", xml_escape(&exe.display().to_string()))
}

/// Whether a ruleset is only rules of the kind `Rules::ruleset` writes: a marker that anyone had a hand in is not loaded as a pf script.
pub fn valid_ruleset(text: &str) -> bool {!text.is_empty() && text.len() <= RULES_MAX && text.ends_with('\n') && text.lines().all(|line| line.starts_with("pass ") || line.starts_with("block "))}

/// Writes the marker: the rules to load at boot.
pub fn keep(state_dir: &Path, ruleset: &str) -> io::Result<()> {
	if !valid_ruleset(ruleset) {return Err(io::Error::new(io::ErrorKind::InvalidInput, "the ruleset is not one that can be kept"))}
	secure_dir(state_dir, 0o700)?;
	let path = state_dir.join(MARKER);
	write_atomic(&path, ruleset.as_bytes())?;
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
}

/// The marker's rules, if there is one. A marker that is a link, is not root's, is open to others or holds anything but rules is an error and is not loaded.
pub fn kept(state_dir: &Path) -> io::Result<Option<String>> {
	let path = state_dir.join(MARKER);
	match fs::symlink_metadata(&path) {
		Ok(meta) if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o077 == 0 && meta.len() as usize <= RULES_MAX => {
			let text = fs::read_to_string(&path)?;
			if valid_ruleset(&text) {Ok(Some(text))} else {Err(io::Error::new(io::ErrorKind::InvalidData, format!("{} is not a ruleset of the client", path.display())))}
		}
		Ok(_) => Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a file of root that only root can use", path.display()))),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
		Err(error) => Err(error),
	}
}

/// Takes the marker away. Nothing is wrong if it is not there.
pub fn forget(state_dir: &Path) -> io::Result<()> {
	match fs::remove_file(state_dir.join(MARKER)) {
		Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
		_ => Ok(()),
	}
}

// The program, resolved, if it and every folder above it is root's and closed to others.
fn trusted_exe(exe: &Path) -> io::Result<PathBuf> {
	let real = fs::canonicalize(exe)?;
	let meta = fs::metadata(&real)?;
	if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a file of root that others cannot write", real.display())))}
	let chain = real.ancestors().skip(1).map(|folder| fs::metadata(folder).map(|meta| (folder.to_owned(), meta.uid(), meta.mode()))).collect::<io::Result<Vec<_>>>()?;
	match chain_problem(&chain, 0) {None => Ok(real), Some(problem) => Err(io::Error::new(io::ErrorKind::PermissionDenied, problem))}
}

/// Writes the plist into `dir` if it is not there as it should be. True when it wrote. An existing file that is not a regular file is an error and is never followed.
pub fn write_plist(dir: &Path, exe: &Path) -> io::Result<bool> {
	let (path, wanted) = (dir.join(format!("{LABEL}.plist")), plist(exe));
	match fs::symlink_metadata(&path) {
		Ok(meta) if !meta.is_file() => return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a regular file", path.display()))),
		Ok(meta) if meta.mode() & 0o777 == 0o644 && fs::read_to_string(&path).is_ok_and(|found| found == wanted) => return Ok(false),
		Ok(_) => {}
		Err(error) if error.kind() == io::ErrorKind::NotFound => {}
		Err(error) => return Err(error),
	}
	write_atomic(&path, wanted.as_bytes())?;
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
	Ok(true)
}

/// Makes the daemon that restores the kill switch at boot, naming this program.
pub fn install_daemon() -> io::Result<bool> {
	let exe = trusted_exe(&std::env::current_exe()?)?;
	secure_dir(Path::new(DAEMON_DIR), 0o755)?;
	write_plist(Path::new(DAEMON_DIR), &exe)
}

/// Arms the reboot: the marker, and the daemon that reads it.
pub fn arm(state_dir: &Path, ruleset: &str) -> io::Result<()> {
	keep(state_dir, ruleset)?;
	if install_daemon()? {tracing::info!("the LaunchDaemon that restores the kill switch at boot was installed");}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn scratch(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-mac-persist-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn the_plist_runs_restore_at_load_and_names_the_program_escaped() {
		let text = plist(Path::new("/usr/local/bin/veilway"));
		assert!(text.contains("<key>Label</key>\n\t<string>com.veilway.restore</string>"));
		assert!(text.contains("<string>/usr/local/bin/veilway</string>\n\t\t<string>restore</string>"));
		assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"));
		assert!(!text.contains("KeepAlive") && text.ends_with("</plist>\n"));
		let odd = plist(Path::new("/opt/a&b<c>/veilway"));
		assert!(odd.contains("/opt/a&amp;b&lt;c&gt;/veilway") && !odd.contains("a&b"));
	}

	#[test]
	fn only_rules_of_the_clients_kind_are_a_ruleset() {
		assert!(valid_ruleset("pass quick on lo0 all\nblock drop quick inet all\n"));
		assert!(!valid_ruleset("") && !valid_ruleset("pass quick on lo0 all") && !valid_ruleset("pass all\n\nblock all\n"));
		assert!(!valid_ruleset("pass all\nset skip on lo0\n") && !valid_ruleset("pass all\nanchor \"x\"\n") && !valid_ruleset("include \"/tmp/x\"\n"));
		assert!(!valid_ruleset(&"pass all\n".repeat(10_000)));
	}

	#[test]
	fn the_plist_is_written_once_rewritten_when_changed_and_never_through_a_link() {
		let dir = scratch("plist");
		assert!(write_plist(&dir, Path::new("/usr/local/bin/veilway")).unwrap());
		assert!(!write_plist(&dir, Path::new("/usr/local/bin/veilway")).unwrap());
		assert_eq!(fs::metadata(dir.join("com.veilway.restore.plist")).unwrap().mode() & 0o777, 0o644);
		assert!(write_plist(&dir, Path::new("/opt/veilway")).unwrap(), "a moved program is written again");
		fs::remove_file(dir.join("com.veilway.restore.plist")).unwrap();
		std::os::unix::fs::symlink("/etc/passwd", dir.join("com.veilway.restore.plist")).unwrap();
		assert!(write_plist(&dir, Path::new("/opt/veilway")).is_err());
	}

	#[test]
	fn a_program_a_user_could_replace_is_not_named() {
		let dir = scratch("exe");
		let exe = dir.join("veilway");
		fs::write(&exe, b"x").unwrap();
		let error = trusted_exe(&exe).unwrap_err();
		assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
	}

	#[test]
	fn the_marker_is_kept_read_back_and_forgotten() {
		if !rustix::process::geteuid().is_root() {return}
		let dir = scratch("marker").join("data");
		assert_eq!(kept(&dir).unwrap(), None);
		keep(&dir, "pass quick on lo0 all\nblock drop quick inet all\n").unwrap();
		assert_eq!(kept(&dir).unwrap().as_deref(), Some("pass quick on lo0 all\nblock drop quick inet all\n"));
		fs::set_permissions(dir.join(MARKER), fs::Permissions::from_mode(0o644)).unwrap();
		assert!(kept(&dir).is_err(), "open to others");
		fs::set_permissions(dir.join(MARKER), fs::Permissions::from_mode(0o600)).unwrap();
		fs::write(dir.join(MARKER), "anchor \"x\"\n").unwrap();
		assert!(kept(&dir).is_err(), "not rules");
		forget(&dir).unwrap();
		forget(&dir).unwrap();
		assert_eq!(kept(&dir).unwrap(), None);
		assert!(keep(&dir, "set skip on lo0\n").is_err());
	}
}
