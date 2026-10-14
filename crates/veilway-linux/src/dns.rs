//! The system's resolver, pointed at the tunnel's while a connection is up.
//!
//! The servers are the tunnel's gateways, which the signed profile names and which are reachable only through the tunnel's device: when the tunnel drops, a query goes into a device that carries nothing, and is not answered. Where systemd-resolved runs, it is told through `resolvectl` to send every name to the tunnel's device (the routing domain `~.`), and that setting is read back from time to time: applications that resolve through it (nss-resolve, or the stub file) ask it, and it would otherwise ask the physical link's servers. Where `/etc/resolv.conf` is not resolved's stub file (no resolved, a static file, or the uplink file with the servers of every link, which applications read directly), `/etc/resolv.conf` is written as well, with what was there kept before the file is touched, and put back only if what is there still is ours. A watch on the file puts it right again when something rewrites it. In all cases the kill switch drops a query to any other server (`firewall`), so a setting that is changed behind our back costs lookups and not privacy.
//!
//! The copy of the file that was replaced is kept in a directory that survives a reboot (`/var/lib/veilway`, root only), not in `/run`: `/etc/resolv.conf` survives a reboot with the tunnel's gateway in it, and the copy is what lets `veilway disconnect` put it back after a machine that was connected lost power or restarted.
use crate::state::program;
use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use rustix::io::read;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

const MARK: &str = "# Written by Veilway while a connection is up. It is put back when the connection ends.";
const RESOLV: &str = "/etc/resolv.conf";
/// The file systemd-resolved makes for applications that should resolve through it. The other file it makes, `/run/systemd/resolve/resolv.conf`, lists the servers of every link and is read by applications directly.
const STUB: &str = "/run/systemd/resolve/stub-resolv.conf";
/// The most servers a resolver reads from the file.
const SERVERS_MAX: usize = 3;
const SAVED: &str = "resolv.conf.saved";

/// What was in the way before, enough to put it back.
#[derive(Serialize, Deserialize)]
struct Saved {symlink: Option<PathBuf>, content: Vec<u8>, mode: u32}

/// What putting the file back came to, for the words `veilway disconnect` says.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Restored {
	/// There was no saved copy: nothing of the file was changed.
	#[default]
	Nothing,
	/// The file is as it was before the connection.
	Put,
	/// Something else wrote the file while the connection was up, and it is left as that program made it.
	LeftAlone,
	/// The saved copy did not read and was moved aside as `resolv.conf.bad`: the file is as it is.
	Damaged,
}

pub struct Pinned {resolved: bool, file: bool, link: String, resolv: PathBuf, saved: PathBuf}

/// The file's text for these servers.
pub fn content(servers: &[IpAddr]) -> String {servers.iter().take(SERVERS_MAX).fold(format!("{MARK}\n"), |text, server| text + &format!("nameserver {server}\n"))}

fn resolvectl(args: &[&str]) -> io::Result<String> {
	let output = Command::new(program("resolvectl")?).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;
	if output.status.success() {Ok(String::from_utf8_lossy(&output.stdout).into_owned())} else {Err(io::Error::other(format!("resolvectl {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim())))}
}

/// Whether `real`, where `/etc/resolv.conf` leads to, is the stub file.
fn is_stub(real: &Path) -> bool {real == Path::new(STUB)}

// A file moved over the old one, or written in place where it cannot be moved over: the file is a mount in a container, which can be written and not replaced.
fn put(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
	let temporary = path.with_extension("veilway-new");
	let _ = fs::remove_file(&temporary);
	fs::write(&temporary, content)?;
	fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
	if fs::rename(&temporary, path).is_err() {
		let _ = fs::remove_file(&temporary);
		fs::write(path, content)?;
	}
	Ok(())
}

fn apply(link: &str, servers: &[IpAddr]) -> io::Result<()> {
	let names: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
	let mut dns = vec!["dns", link];
	dns.extend(names.iter().map(String::as_str));
	resolvectl(&dns)?;
	resolvectl(&["domain", link, "~."])?;
	resolvectl(&["default-route", link, "yes"])?;
	let _ = resolvectl(&["flush-caches"]);
	Ok(())
}

impl Pinned {
	/// Points the system's resolver at `servers`. `link` is the tunnel's device, `state_dir` is where the file that was in the way is kept.
	pub fn pin(state_dir: &Path, link: &str, servers: &[IpAddr]) -> io::Result<Self> {Self::pin_at(Path::new(RESOLV), state_dir, link, servers, true)}
	fn pin_at(resolv: &Path, state_dir: &Path, link: &str, servers: &[IpAddr], detect: bool) -> io::Result<Self> {
		let saved = state_dir.join(SAVED);
		// A client that crashed left the file as it made it: the original is in the saved copy and not in the file.
		if saved.exists() {Self::undo_at(resolv, &saved)?;}
		if servers.is_empty() {return Err(io::Error::new(io::ErrorKind::InvalidInput, "the profile names no gateway to use as the resolver"))}
		let resolved = detect && resolvectl(&["status"]).is_ok();
		if resolved {apply(link, servers)?}
		// The file too, unless resolved runs and the file is its stub, which sends every lookup to resolved.
		let file = !(resolved && fs::canonicalize(resolv).is_ok_and(|real| is_stub(&real)));
		if file {
			let before = Saved {symlink: fs::read_link(resolv).ok(), content: fs::read(resolv).unwrap_or_default(), mode: fs::metadata(resolv).map_or(0o644, |meta| meta.permissions().mode() & 0o777)};
			// The original is kept before the file is touched: a crash between the two writes leaves a file that is ours and a copy that puts it back, and not a file that is ours with nothing to put back.
			veilway_engine::store::write_atomic(&saved, &serde_json::to_vec(&before).map_err(io::Error::other)?)?;
			put(resolv, content(servers).as_bytes(), 0o644)?;
		}
		Ok(Self {resolved, file, link: link.to_owned(), resolv: resolv.to_owned(), saved})
	}
	pub fn describe(&self) -> &'static str {
		match (self.resolved, self.file) {
			(true, false) => "systemd-resolved",
			(true, true) => "systemd-resolved and /etc/resolv.conf",
			_ => "/etc/resolv.conf",
		}
	}
	/// Puts the settings right again if something changed them (a DHCP client rewrites the file, a network manager clears a link's servers). True when it had to.
	pub fn verify(&self, servers: &[IpAddr]) -> io::Result<bool> {
		let mut fixed = false;
		if self.resolved {
			let (dns, domain) = (resolvectl(&["dns", &self.link])?, resolvectl(&["domain", &self.link])?);
			if !(servers.iter().all(|server| dns.contains(&server.to_string())) && domain.contains("~.")) {
				apply(&self.link, servers)?;
				fixed = true;
			}
		}
		if self.file && !fs::read_to_string(&self.resolv).is_ok_and(|text| text.starts_with(MARK)) {
			put(&self.resolv, content(servers).as_bytes(), 0o644)?;
			fixed = true;
		}
		Ok(fixed)
	}
	/// Ends the pinning: the file back as it was if it still is ours, and the link's settings dropped in resolved.
	pub fn restore(self) -> io::Result<Restored> {
		if self.resolved {let _ = resolvectl(&["revert", &self.link]);}
		if self.file {Self::undo_at(&self.resolv, &self.saved)} else {Ok(Restored::Nothing)}
	}
	/// What `restore` does for a client that is gone: the saved file, if there is one.
	pub fn restore_leftover(state_dir: &Path) -> io::Result<Restored> {
		let saved = state_dir.join(SAVED);
		if !saved.exists() {return Ok(Restored::Nothing)}
		Self::undo_at(Path::new(RESOLV), &saved)
	}
	fn undo_at(resolv: &Path, saved: &Path) -> io::Result<Restored> {
		let Ok(kept) = serde_json::from_slice::<Saved>(&fs::read(saved)?) else {
			// A copy that does not read is put aside and not an error: it would keep every later start and stop from finishing, and what it held cannot be put back.
			let aside = saved.with_extension("bad");
			tracing::warn!("{} does not read and was moved to {}: the resolver settings are left as they are", saved.display(), aside.display());
			fs::rename(saved, aside)?;
			return Ok(Restored::Damaged);
		};
		let ours = fs::read_to_string(resolv).is_ok_and(|text| text.starts_with(MARK));
		if ours {
			match &kept.symlink {
				Some(target) => {
					let temporary = resolv.with_extension("veilway-link");
					let _ = fs::remove_file(&temporary);
					symlink(target, &temporary)?;
					fs::rename(&temporary, resolv)?;
				}
				None => put(resolv, &kept.content, kept.mode)?,
			}
		} else {
			tracing::warn!("{} was changed by something else while the connection was up and is left as it is", resolv.display());
		}
		fs::remove_file(saved)?;
		Ok(if ours {Restored::Put} else {Restored::LeftAlone})
	}
}

/// A watch on `/etc/resolv.conf`: it returns when the file, or its name in the directory, changes, which is when a DHCP client or a network manager rewrites it. A write to any other file of the directory is not a change.
pub struct Watch {fd: AsyncFd<OwnedFd>, file: PathBuf, directory: i32}

// What the file itself is watched for: the directory reports a rename over it, and the file reports a write into a file that is a mount or was replaced.
const FILE_EVENTS: WatchFlags = WatchFlags::MODIFY.union(WatchFlags::CLOSE_WRITE).union(WatchFlags::ATTRIB).union(WatchFlags::DELETE_SELF).union(WatchFlags::MOVE_SELF);

/// Whether a buffer of inotify events holds one that concerns the file: one on a watch other than the directory's, or one about the file's name. The events are `struct inotify_event`: a watch, a mask, a cookie and the length of a name that follows, padded with zeros.
fn concerns(events: &[u8], directory: i32, name: &str) -> bool {
	let mut rest = events;
	while rest.len() >= 16 {
		let (wd, len) = (i32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]), u32::from_ne_bytes([rest[12], rest[13], rest[14], rest[15]]) as usize);
		let Some(field) = rest.get(16..16usize.saturating_add(len)) else {return true};
		if wd != directory || field.split(|byte| *byte == 0).next() == Some(name.as_bytes()) {return true}
		rest = &rest[16 + len..];
	}
	false
}

impl Watch {
	pub fn open() -> io::Result<Self> {Self::at(Path::new(RESOLV))}
	fn at(file: &Path) -> io::Result<Self> {
		let fd = inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)?;
		let directory = inotify::add_watch(&fd, file.parent().unwrap_or(Path::new("/")), WatchFlags::CREATE | WatchFlags::MOVED_TO | WatchFlags::MOVED_FROM | WatchFlags::DELETE | WatchFlags::MODIFY | WatchFlags::CLOSE_WRITE)?;
		let _ = inotify::add_watch(&fd, file, FILE_EVENTS);
		Ok(Self {fd: AsyncFd::with_interest(fd, Interest::READABLE)?, file: file.to_owned(), directory})
	}
	pub async fn changed(&self) -> io::Result<()> {
		let (mut buf, name) = ([0u8; 4096], self.file.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_owned());
		loop {
			let got = self.fd.async_io(Interest::READABLE, |fd| read(fd, &mut buf).map_err(io::Error::from)).await?;
			let mut relevant = concerns(&buf[..got], self.directory, &name);
			// What else is waiting is part of the same burst.
			while let Ok(more) = read(self.fd.get_ref(), &mut buf) {relevant |= concerns(&buf[..more], self.directory, &name)}
			if relevant {
				// The file may be a new one now, with an inode the watch has not seen.
				let _ = inotify::add_watch(self.fd.get_ref(), &self.file, FILE_EVENTS);
				return Ok(());
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn scratch(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-dns-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	fn servers() -> Vec<IpAddr> {vec!["10.7.0.1".parse().unwrap(), "fd07::1".parse().unwrap()]}

	#[test]
	fn the_file_names_the_servers_under_the_mark() {
		assert_eq!(content(&servers()), format!("{MARK}\nnameserver 10.7.0.1\nnameserver fd07::1\n"));
		let many: Vec<IpAddr> = (1..=5).map(|n| format!("10.7.0.{n}").parse().unwrap()).collect();
		assert_eq!(content(&many).matches("nameserver").count(), SERVERS_MAX);
	}

	#[test]
	fn only_the_stub_file_means_applications_resolve_through_resolved() {
		assert!(is_stub(Path::new("/run/systemd/resolve/stub-resolv.conf")));
		assert!(!is_stub(Path::new("/run/systemd/resolve/resolv.conf")), "that file lists the uplink's servers, which applications read directly");
		assert!(!is_stub(Path::new("/etc/resolv.conf")));
	}

	#[test]
	fn a_file_is_replaced_and_put_back_as_it_was() {
		let dir = scratch("file");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		let pinned = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		assert_eq!(fs::read_to_string(&resolv).unwrap(), content(&servers()));
		pinned.restore().unwrap();
		assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 192.0.2.53\n");
		assert!(!dir.join(SAVED).exists());
	}

	#[test]
	fn the_original_is_kept_before_the_file_is_touched() {
		let dir = scratch("first");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		// A saved copy and an untouched file is the state a crash right after the first write leaves: the next start puts nothing wrong back.
		veilway_engine::store::write_atomic(&dir.join(SAVED), &serde_json::to_vec(&Saved {symlink: None, content: fs::read(&resolv).unwrap(), mode: 0o644}).unwrap()).unwrap();
		let again = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		again.restore().unwrap();
		assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 192.0.2.53\n");
	}

	#[test]
	fn a_symlink_comes_back_as_a_symlink() {
		let dir = scratch("link");
		let (resolv, target) = (dir.join("resolv.conf"), dir.join("stub"));
		fs::write(&target, "nameserver 127.0.0.53\n").unwrap();
		symlink(&target, &resolv).unwrap();
		let pinned = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
		pinned.restore().unwrap();
		assert_eq!(fs::read_link(&resolv).unwrap(), target);
	}

	#[test]
	fn the_words_for_what_was_put_back_are_told_apart() {
		let dir = scratch("restored");
		let resolv = dir.join("resolv.conf");
		assert_eq!(Pinned::restore_leftover(&dir).unwrap(), Restored::Nothing);
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		let pinned = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		assert_eq!((pinned.describe(), pinned.restore().unwrap()), ("/etc/resolv.conf", Restored::Put));
		let other = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		fs::write(&resolv, "nameserver 198.51.100.1\n").unwrap();
		assert_eq!(other.restore().unwrap(), Restored::LeftAlone);
	}

	#[test]
	fn only_events_about_the_file_wake_the_watch() {
		// `struct inotify_event`: wd, mask, cookie, len, then the name padded with zeros.
		let event = |wd: i32, name: &[u8]| {
			let mut bytes = [wd.to_ne_bytes(), 2u32.to_ne_bytes(), 0u32.to_ne_bytes(), (name.len() as u32).to_ne_bytes()].concat();
			bytes.extend_from_slice(name);
			bytes
		};
		assert!(!concerns(&event(1, b"hosts\0\0\0"), 1, "resolv.conf"));
		assert!(concerns(&event(1, b"resolv.conf\0\0\0\0\0"), 1, "resolv.conf"));
		assert!(concerns(&event(2, b""), 1, "resolv.conf"), "an event on the file's own watch");
		let mut burst = event(1, b"hosts\0\0\0");
		burst.extend(event(1, b"resolv.conf\0\0\0\0\0"));
		assert!(concerns(&burst, 1, "resolv.conf"));
		assert!(concerns(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255], 1, "resolv.conf"), "a length that does not fit is not skipped");
	}

	#[test]
	fn a_file_somebody_else_wrote_in_the_meantime_is_left_alone() {
		let dir = scratch("other");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		let pinned = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		fs::write(&resolv, "nameserver 198.51.100.1\n").unwrap();
		pinned.restore().unwrap();
		assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 198.51.100.1\n");
	}

	#[test]
	fn a_rewritten_file_is_set_right_again() {
		let dir = scratch("verify");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		let pinned = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		assert!(!pinned.verify(&servers()).unwrap());
		fs::write(&resolv, "nameserver 198.51.100.1\n").unwrap();
		assert!(pinned.verify(&servers()).unwrap());
		assert_eq!(fs::read_to_string(&resolv).unwrap(), content(&servers()));
	}

	#[test]
	fn a_second_pin_after_a_crash_keeps_the_first_original() {
		let dir = scratch("crash");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		std::mem::forget(Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap());
		let again = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		again.restore().unwrap();
		assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 192.0.2.53\n");
	}

	#[test]
	fn a_saved_copy_that_does_not_read_is_put_aside_and_does_not_stop_anything() {
		let dir = scratch("damaged");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		fs::write(dir.join(SAVED), "not json").unwrap();
		assert_eq!(Pinned::undo_at(&resolv, &dir.join(SAVED)).unwrap(), Restored::Damaged);
		assert!(!dir.join(SAVED).exists() && dir.join("resolv.conf.bad").exists());
		let pinned = Pinned::pin_at(&resolv, &dir, "vw0", &servers(), false).unwrap();
		pinned.restore().unwrap();
		assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 192.0.2.53\n");
	}

	#[test]
	fn no_server_is_an_error_and_changes_nothing() {
		let dir = scratch("none");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		assert!(Pinned::pin_at(&resolv, &dir, "vw0", &[], false).is_err());
		assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 192.0.2.53\n");
	}

	#[tokio::test]
	async fn a_rewrite_of_the_file_wakes_the_watch() {
		let dir = scratch("watch");
		let resolv = dir.join("resolv.conf");
		fs::write(&resolv, "nameserver 192.0.2.53\n").unwrap();
		let watch = Watch::at(&resolv).unwrap();
		let writer = resolv.clone();
		tokio::spawn(async move {
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
			fs::write(&writer, "nameserver 198.51.100.1\n").unwrap();
		});
		tokio::time::timeout(std::time::Duration::from_secs(5), watch.changed()).await.expect("no wake").unwrap();
		let replacer = resolv.clone();
		tokio::spawn(async move {
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
			put(&replacer, b"nameserver 203.0.113.1\n", 0o644).unwrap();
		});
		tokio::time::timeout(std::time::Duration::from_secs(5), watch.changed()).await.expect("no wake for a replaced file").unwrap();
	}
}
