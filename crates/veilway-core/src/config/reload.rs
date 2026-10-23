//! Reloading: the running config behind a watch channel, the diff between two configs and the two-phase apply.
//! Nothing here holds or logs a value from a document except tags, user names and device public keys.
use super::{Backend, Config, Diagnostic, Exit, Key, Link, Outbound, Policy, Report, Rule, Transport, User, DEFAULT_INTERFACE, DEFAULT_TCP_IDLE_SECS, DEFAULT_UDP_IDLE_SECS, MAX_FILE_BYTES};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use time::OffsetDateTime;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{watch, OwnedMutexGuard};
use tokio::task::spawn_blocking;
use tracing::{info, warn};

/// Tags or names of one kind that a log line lists before it only counts the rest.
pub const MAX_NAMES_LOGGED: usize = 32;

/// The key of every revision of this process, made when the first one is asked for and never shown.
static KEY: LazyLock<hmac::Key> = LazyLock::new(|| {
	let mut key = [0u8; 32];
	// The system's generator does not fail on a system the node runs on. Should it, the seed std gives the hash maps of the process is what is left, which is still nothing anybody outside it knows.
	if SystemRandom::new().fill(&mut key).is_err() {
		for (i, chunk) in key.chunks_mut(8).enumerate() {chunk.copy_from_slice(&RandomState::new().hash_one(i).to_le_bytes())}
	}
	hmac::Key::new(hmac::HMAC_SHA256, &key)
});

/// Names the exact bytes a config was loaded from, for this process alone: their HMAC-SHA-256 under `KEY`.
/// The bytes hold keys and passwords, and a revision is shown to whoever may see the config without them. A plain hash would let them try a guess of a password against it, so it is keyed,
/// and a revision means nothing to another process: a node that starts again on the same file calls it something else.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Revision([u8; 32]);

impl Revision {
	pub fn of(bytes: &[u8]) -> Revision {
		let mut hash = [0; 32];
		hash.copy_from_slice(hmac::sign(&KEY, bytes).as_ref());
		Revision(hash)
	}
}

impl fmt::Display for Revision {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))}
}

impl fmt::Debug for Revision {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {write!(f, "Revision({self})")}
}

/// What stands in the place of one transport secret in a document the control API shows: the marker with eight hex digits that name the secret, for this process alone. They are the start of its HMAC-SHA-256 under `KEY`, behind a label no config begins with,
/// so they tell two secrets of a device apart and tell nobody anything about either. A marker that comes back stands for the secret of the same device that has these digits, wherever it stands in the list, see `Config::parse_keeping`.
pub(crate) fn marker(secret: &[u8; 32]) -> String {format!("<redacted:{}>", hmac::sign(&KEY, &[&b"veilway transport secret marker\0"[..], secret].concat()).as_ref().iter().take(4).map(|byte| format!("{byte:02x}")).collect::<String>())}

/// One config as it runs. Cloning it is cheap.
#[derive(Clone, Debug)]
pub struct Snapshot {
	pub config: Arc<Config>,
	pub revision: Revision,
	/// Starts at 1 and grows by one with every commit.
	pub generation: u64,
	/// What `validate` said about this config: its warnings. It has no errors.
	pub report: Arc<Report>,
}

/// Tags or names of one kind: `added` and `changed` in the order of the new document, `removed` in the order of the old one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {pub added: Vec<String>, pub changed: Vec<String>, pub removed: Vec<String>}

impl fmt::Display for Changes {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let mut any = false;
		for (label, names) in [("added", &self.added), ("changed", &self.changed), ("removed", &self.removed)] {
			if names.is_empty() {continue}
			write!(f, "{}{label} {}", if any {"; "} else {""}, names[..names.len().min(MAX_NAMES_LOGGED)].join(", "))?;
			if names.len() > MAX_NAMES_LOGGED {write!(f, " and {} more", names.len() - MAX_NAMES_LOGGED)?}
			any = true;
		}
		if any {Ok(())} else {f.write_str("none")}
	}
}

/// What a changed inbound needs. With `restart` the whole tunnel restarts and its sessions drop, so every transport restarts whatever the two lists say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundChange {
	pub tag: String,
	/// `private_key`, the set of `address` networks or the effective `mtu` changed.
	pub restart: bool,
	/// Indexes into the old inbound's `transports` that are not in the new one.
	pub transports_stopped: Vec<usize>,
	/// Indexes into the new inbound's `transports` that are not in the old one.
	pub transports_started: Vec<usize>,
}

/// What changed for a user present in both configs. A device is the same device when its public key is the same, whatever its name or position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserChange {
	pub name: String,
	pub devices_added: Vec<Key>,
	pub devices_removed: Vec<Key>,
	/// Kept devices whose set of addresses changed.
	pub devices_readdressed: Vec<Key>,
	/// Kept devices whose preshared key was set, changed or removed.
	pub devices_rekeyed: Vec<Key>,
	/// Kept devices whose transport secrets are not the ones they were, in whatever order. A control connection that proved itself with a secret that is gone is ended.
	pub devices_secrets_changed: Vec<Key>,
	/// The user could connect and no longer can: disabled, or `expires_at` is not after the given time.
	pub lost_access: bool,
}

/// An optional key that is left out and its default written out are the same value, and so are the same entries of an inbound's `address` in another order: neither is a change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
	/// An inbound whose transports only changed order is not changed.
	pub inbounds: Changes,
	pub outbounds: Changes,
	pub exits: Changes,
	pub rules: Changes,
	pub users: Changes,
	/// Node links, by tag. A link whose `enabled` is left out and one that writes true are the same link.
	pub links: Changes,
	/// Tunnels, by tag. A tunnel with its defaults left out and the same with them written out are the same tunnel.
	pub tunnels: Changes,
	/// Upstreams, by tag. An upstream with its defaults left out and the same with them written out are the same upstream.
	pub upstreams: Changes,
	pub dns: bool,
	pub log: bool,
	pub routing_default: bool,
	/// The rules present in both configs are in a different order, which can change what they decide.
	pub rules_reordered: bool,
	pub notices: bool,
	pub public_addresses: bool,
	/// The `xray` section changed in any way.
	pub xray: bool,
	/// `replay` changed. The per-source rate is in force at once, the cache size at the next start.
	pub replay: bool,
	/// One entry per tag in `inbounds.changed`.
	pub inbound_changes: Vec<InboundChange>,
	/// One entry per name in `users.changed`.
	pub user_changes: Vec<UserChange>,
}

fn changes<T>(old: &[T], new: &[T], name: fn(&T) -> &str, same: impl Fn(&T, &T) -> bool) -> Changes {
	let before: HashMap<&str, &T> = old.iter().map(|item| (name(item), item)).collect();
	let after: HashSet<&str> = new.iter().map(name).collect();
	Changes {
		added: new.iter().filter(|item| !before.contains_key(name(item))).map(|item| name(item).to_string()).collect(),
		changed: new.iter().filter(|item| before.get(name(item)).is_some_and(|was| !same(was, item))).map(|item| name(item).to_string()).collect(),
		removed: old.iter().filter(|item| !after.contains(name(item))).map(|item| name(item).to_string()).collect(),
	}
}

impl Diff {
	/// Compares two configs object by object, by tag or name. `now` decides whether an `expires_at` has passed.
	pub fn between(old: &Config, new: &Config, now: OffsetDateTime) -> Diff {
		let mut inbounds = changes(&old.inbounds, &new.inbounds, |inbound| inbound.tag.as_str(), |was, is| was == is);
		let inbound_changes: Vec<InboundChange> = inbounds.changed.iter().filter_map(|tag| {
			let (was, is) = (old.inbounds.iter().find(|inbound| inbound.tag == *tag)?, new.inbounds.iter().find(|inbound| inbound.tag == *tag)?);
			let change = InboundChange {
				tag: tag.clone(),
				// The same networks in another order, or an absent mtu and the default written out, are the same tunnel, and a restart drops every session.
				restart: was.private_key != is.private_key || was.address.len() != is.address.len() || was.address.iter().any(|net| !is.address.contains(net)) || was.mtu() != is.mtu(),
				transports_stopped: (0..was.transports.len()).filter(|i| !is.transports.contains(&was.transports[*i])).collect(),
				transports_started: (0..is.transports.len()).filter(|i| !was.transports.contains(&is.transports[*i])).collect(),
			};
			// A changed `type` restarts nothing: the tunnel is the same, and what its gateway answers goes by the config in force.
			(change.restart || !change.transports_stopped.is_empty() || !change.transports_started.is_empty() || was.kind != is.kind || was.padding != is.padding || was.transport_keys != is.transport_keys || was.upgrade_cookie != is.upgrade_cookie || [true, false].iter().any(|tls| was.transports.iter().chain(&is.transports).any(|transport| if *tls {matches!(transport, Transport::Tls {..})} else {matches!(transport, Transport::WsNative {..})}) && was.upgrade_headers(*tls) != is.upgrade_headers(*tls))).then_some(change)
		}).collect();
		inbounds.changed.retain(|tag| inbound_changes.iter().any(|change| change.tag == *tag));
		let proxies = changes(&old.proxies, &new.proxies, |proxy| proxy.tag.as_str(), |was, is| was.effective() == is.effective());
		inbounds.added.extend(proxies.added);
		inbounds.changed.extend(proxies.changed);
		inbounds.removed.extend(proxies.removed);
		// Objects that differ as written are compared again with their defaults filled in.
		let users = changes(&old.users, &new.users, |user| user.name.as_str(), |was, is| was == is || User {enabled: Some(was.enabled != Some(false)), ..was.clone()} == User {enabled: Some(is.enabled != Some(false)), ..is.clone()});
		let (before, after): (HashMap<&str, &User>, HashMap<&str, &User>) = (old.users.iter().map(|user| (user.name.as_str(), user)).collect(), new.users.iter().map(|user| (user.name.as_str(), user)).collect());
		let able = |user: &User| user.enabled != Some(false) && user.expires_at.is_none_or(|at| at.0 > now);
		let user_changes = users.changed.iter().filter_map(|name| {
			let (was, is) = (before.get(name.as_str())?, after.get(name.as_str())?);
			let kept = || is.devices.iter().filter_map(|device| was.devices.iter().find(|w| w.public_key == device.public_key).map(|w| (w, device)));
			Some(UserChange {
				name: name.clone(),
				devices_added: is.devices.iter().filter(|device| !was.devices.iter().any(|w| w.public_key == device.public_key)).map(|device| device.public_key).collect(),
				devices_removed: was.devices.iter().filter(|device| !is.devices.iter().any(|i| i.public_key == device.public_key)).map(|device| device.public_key).collect(),
				devices_readdressed: kept().filter(|(w, device)| w.addresses.len() != device.addresses.len() || w.addresses.iter().any(|a| !device.addresses.contains(a))).map(|(_, device)| device.public_key).collect(),
				devices_rekeyed: kept().filter(|(w, device)| w.preshared_key != device.preshared_key).map(|(_, device)| device.public_key).collect(),
				devices_secrets_changed: kept().filter(|(w, device)| {
					let (was, is) = (w.transport_secrets.as_deref().unwrap_or(&[]), device.transport_secrets.as_deref().unwrap_or(&[]));
					was.len() != is.len() || was.iter().any(|secret| !is.contains(secret))
				}).map(|(_, device)| device.public_key).collect(),
				lost_access: able(was) && !able(is),
			})
		}).collect();
		let effective = |config: &Config, exit: &Exit| {
			let mut exit = exit.clone();
			if exit.name.is_none() {exit.name = Some(exit.tag.clone())}
			match &mut exit.backend {
				Backend::Netstack(netstack) => {
					if netstack.proxy_only.is_none() {netstack.proxy_only = Some(config.outbounds.iter().any(|outbound| matches!(outbound, Outbound::Socks5 {tag, ..} if *tag == netstack.outbound)))}
					netstack.tcp_idle_secs.get_or_insert(DEFAULT_TCP_IDLE_SECS);
					netstack.udp_idle_secs.get_or_insert(DEFAULT_UDP_IDLE_SECS);
					netstack.unsupported.icmp_echo.get_or_insert(Policy::Local);
					netstack.unsupported.udp.get_or_insert(Policy::Reject);
					netstack.unsupported.other.get_or_insert(Policy::Reject);
				}
				Backend::L3(l3) => {
					l3.interface.get_or_insert_with(|| DEFAULT_INTERFACE.to_string());
					l3.masquerade.get_or_insert(true);
				}
				Backend::Block {} | Backend::Chain(_) | Backend::Upstream(_) => {}
			}
			exit
		};
		let (old_rules, new_rules): (HashSet<&str>, HashSet<&str>) = (old.routing.rules.iter().map(|rule| rule.tag.as_str()).collect(), new.routing.rules.iter().map(|rule| rule.tag.as_str()).collect());
		Diff {
			inbounds,
			outbounds: changes(&old.outbounds, &new.outbounds, |outbound| match outbound {
				Outbound::Direct {tag, ..} | Outbound::Socks5 {tag, ..} => tag.as_str(),
			}, |was, is| was == is),
			exits: changes(&old.exits, &new.exits, |exit| exit.tag.as_str(), |was, is| was == is || effective(old, was) == effective(new, is)),
			rules: changes(&old.routing.rules, &new.routing.rules, |rule| rule.tag.as_str(), |was, is| was == is || Rule {enabled: Some(was.enabled != Some(false)), ..was.clone()} == Rule {enabled: Some(is.enabled != Some(false)), ..is.clone()}),
			users,
			links: changes(&old.links, &new.links, |link| link.tag.as_str(), |was, is| was == is || Link {enabled: Some(was.enabled != Some(false)), ..was.clone()} == Link {enabled: Some(is.enabled != Some(false)), ..is.clone()}),
			tunnels: changes(&old.tunnels, &new.tunnels, |tunnel| tunnel.tag.as_str(), |was, is| was.effective() == is.effective()),
			upstreams: changes(&old.upstreams, &new.upstreams, |upstream| upstream.tag.as_str(), |was, is| was.effective() == is.effective()),
			dns: old.dns.servers != new.dns.servers || old.dns.hijack.unwrap_or(true) != new.dns.hijack.unwrap_or(true) || old.dns.sets != new.dns.sets,
			// `level` and `destinations` are read with their defaults, so `Log` already holds effective values.
			log: old.log != new.log,
			routing_default: old.routing.default != new.routing.default,
			notices: old.notices != new.notices,
			public_addresses: old.public_addresses != new.public_addresses,
			xray: old.xray != new.xray,
			replay: old.replay.cache() != new.replay.cache() || old.replay.per_source() != new.replay.per_source(),
			rules_reordered: !old.routing.rules.iter().map(|rule| rule.tag.as_str()).filter(|tag| new_rules.contains(tag)).eq(new.routing.rules.iter().map(|rule| rule.tag.as_str()).filter(|tag| old_rules.contains(tag))),
			inbound_changes,
			user_changes,
		}
	}

	pub fn is_empty(&self) -> bool {*self == Diff::default()}
}

/// A commit, or an apply of the bytes that already run: then `snapshot` is the running one and `diff` is empty.
#[derive(Clone, Debug)]
pub struct Applied {
	pub snapshot: Snapshot,
	pub diff: Diff,
	/// The warnings of the config in `snapshot`. It has no errors.
	pub report: Report,
}

/// Why an apply changed nothing. The running config is whole in every case.
#[derive(Debug)]
pub enum ApplyError<E> {
	/// The running config is not the one the caller based its change on.
	Stale {current: Revision},
	/// The document cannot be read, does not parse or does not validate.
	Invalid(Report),
	Prepare(E),
}

impl<E: fmt::Display> fmt::Display for ApplyError<E> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ApplyError::Stale {..} => f.write_str("the running config changed since the given revision"),
			ApplyError::Invalid(report) => write!(f, "the new config has {} errors", report.errors.len() + report.more_errors),
			ApplyError::Prepare(e) => write!(f, "the new config could not be prepared: {e}"),
		}
	}
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ApplyError<E> {}

/// Why `reload_from` did not get as far as the document.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unread {Io(io::ErrorKind), #[cfg(unix)] Readable}

impl fmt::Display for Unread {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Unread::Io(kind) => write!(f, "cannot read the config file: {kind}"),
			#[cfg(unix)]
			Unread::Readable => f.write_str("the config file can be read by group or others and holds keys and passwords; restrict it (chmod 600) or start with --allow-readable-config"),
		}
	}
}

/// The running config. Any number of tasks read the current snapshot or wait for the next one.
pub struct Store {
	current: watch::Sender<Snapshot>,
	/// Held for a whole apply, so two applies never interleave. Owned guards, because one travels into the blocking check.
	applying: Arc<tokio::sync::Mutex<()>>,
	/// What `reload_from` last refused and logged: the revision of the bad content, or why the file was not read. The same refusal is not logged again.
	refused: Mutex<Option<Result<Revision, Unread>>>,
	/// Whether `reload_from` takes a file that group or others can read. `run` refuses such a file at start unless it was told otherwise, and a reload does what the start did.
	pub allow_readable: bool,
}

impl Store {
	/// `report` is what `validate` returned for `config` and has no errors. `revision` is `Revision::of` the bytes it was parsed from.
	pub fn new(config: Config, revision: Revision, report: Report) -> Store {
		Store {current: watch::Sender::new(Snapshot {config: Arc::new(config), revision, generation: 1, report: Arc::new(report)}), applying: Arc::default(), refused: Mutex::new(None), allow_readable: true}
	}

	pub fn current(&self) -> Snapshot {self.current.borrow().clone()}

	/// A receiver that is woken by every commit. It may skip a snapshot when commits come faster than it reads.
	pub fn subscribe(&self) -> watch::Receiver<Snapshot> {self.current.subscribe()}

	/// Parses and validates `bytes`, lets `prepare` stage the change against the new snapshot and the diff while the old config keeps running, then commits in one step.
	/// With `base_revision`, the apply is refused unseen unless that is the running revision. Bytes that already run change nothing and `prepare` is not called.
	pub async fn apply<E>(&self, bytes: Vec<u8>, base_revision: Option<Revision>, prepare: impl AsyncFnOnce(&Snapshot, &Diff) -> Result<(), E>) -> Result<Applied, ApplyError<E>> {
		self.apply_locked(self.applying.clone().lock_owned().await, bytes, base_revision, false, prepare).await
	}

	/// With `again`, bytes that already run still go through `prepare`, with the running snapshot and an empty diff, and nothing is committed.
	async fn apply_locked<E>(&self, applying: OwnedMutexGuard<()>, bytes: Vec<u8>, base_revision: Option<Revision>, again: bool, prepare: impl AsyncFnOnce(&Snapshot, &Diff) -> Result<(), E>) -> Result<Applied, ApplyError<E>> {
		let running = self.current();
		if base_revision.is_some_and(|base| base != running.revision) {return Err(ApplyError::Stale {current: running.revision})}
		let revision = Revision::of(&bytes);
		if revision == running.revision {
			let diff = Diff::default();
			if again {prepare(&running, &diff).await.map_err(ApplyError::Prepare)?}
			return Ok(Applied {report: (*running.report).clone(), snapshot: running, diff});
		}
		let old = running.config.clone();
		// A large document takes long enough to parse and compare that it must not hold a runtime worker.
		// The guard goes in and comes back out, so when the caller drops this future the lock stays held until the check has really ended.
		let checked = spawn_blocking(move || {
			let checked = Config::parse(&bytes).map_err(|e| Report {errors: vec![e], ..Report::default()}).and_then(|config| {
				let report = config.validate(false);
				if !report.errors.is_empty() {return Err(report)}
				let diff = Diff::between(&old, &config, OffsetDateTime::now_utc());
				Ok((config, report, diff))
			});
			(applying, checked)
		}).await;
		let (_applying, (config, report, diff)) = match checked {
			Ok((applying, Ok(checked))) => (applying, checked),
			Ok((_, Err(report))) => return Err(ApplyError::Invalid(report)),
			Err(_) => return Err(ApplyError::Invalid(Report {errors: vec![Diagnostic {path: String::new(), message: "the check of the new config did not finish".to_string()}], ..Report::default()})),
		};
		let snapshot = Snapshot {config: Arc::new(config), revision, generation: running.generation + 1, report: Arc::new(report.clone())};
		prepare(&snapshot, &diff).await.map_err(ApplyError::Prepare)?;
		self.current.send_replace(snapshot.clone());
		info!(generation = snapshot.generation, inbounds = %diff.inbounds, outbounds = %diff.outbounds, exits = %diff.exits, rules = %diff.rules, users = %diff.users, links = %diff.links, dns = diff.dns, log = diff.log, routing_default = diff.routing_default, rules_reordered = diff.rules_reordered, "config applied");
		Ok(Applied {snapshot, diff, report})
	}

	/// What `SIGHUP` runs: reads the file, at most `MAX_FILE_BYTES` of it, and applies it. The file is read under the lock, so overlapping reloads commit in the order they read.
	/// A file whose bytes already run still goes through `prepare`, with the running snapshot and an empty diff, so certificates are read and proxy names resolved again. Nothing is committed then and no watcher wakes.
	pub async fn reload_from<E>(&self, path: &Path, prepare: impl AsyncFnOnce(&Snapshot, &Diff) -> Result<(), E>) -> Result<Applied, ApplyError<E>> {
		let applying = self.applying.clone().lock_owned().await;
		let mut bytes = Vec::new();
		// The mode is taken from the file that is then read, not from its path, so the file cannot be swapped in between.
		let read = match File::open(path).await {
			Ok(file) => match file.metadata().await {
				#[cfg(unix)]
				Ok(meta) if !self.allow_readable && meta.mode() & 0o044 != 0 => Err(Unread::Readable),
				Ok(_) => file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).await.map_err(|e| Unread::Io(e.kind())),
				Err(e) => Err(Unread::Io(e.kind())),
			},
			Err(e) => Err(Unread::Io(e.kind())),
		};
		let (refusal, result) = match read {
			Ok(_) => (Ok(Revision::of(&bytes)), self.apply_locked(applying, bytes, None, true, prepare).await),
			Err(why) => (Err(why), Err(ApplyError::Invalid(Report {errors: vec![Diagnostic {path: String::new(), message: why.to_string()}], ..Report::default()}))),
		};
		{
			let mut refused = self.refused.lock().unwrap_or_else(|e| e.into_inner());
			match (&result, refusal) {
				(Err(ApplyError::Invalid(_)), _) if *refused == Some(refusal) => {}
				(Err(ApplyError::Invalid(_)), Err(why)) => {
					*refused = Some(refusal);
					warn!(reason = %why, "config file not read, the running config stays in force");
				}
				// Only the paths: the message of a parse error can name a key of the document.
				(Err(ApplyError::Invalid(report)), Ok(_)) => {
					*refused = Some(refusal);
					warn!(errors = report.errors.len() + report.more_errors, paths = %report.errors.iter().map(|e| if e.path.is_empty() {"(document)"} else {e.path.as_str()}).collect::<Vec<_>>().join(", "), "config file refused, the running config stays in force");
				}
				(Err(ApplyError::Prepare(_)), _) => {
					*refused = None;
					warn!("config reload stopped in prepare, the running config stays in force");
				}
				_ => *refused = None,
			}
		}
		result
	}
}
