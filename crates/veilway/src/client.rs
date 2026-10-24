//! `veilway connect`, `disconnect` and `status`: the client on Linux, macOS and Windows, driven from a terminal until an app does it. The engine and the platform layer are the libraries `veilway-engine` and `veilway-linux`, `veilway-macos` or `veilway-windows` (all are `platform` here, and answer to the same calls); what is here is the questions put to the user and the words the state is shown in.
use anyhow::{anyhow, bail, Context};
use clap::Args;
use ipnet::IpNet;
use std::future::Future;
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::signal::unix::{signal, Signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown, CtrlBreak, CtrlC, CtrlClose, CtrlLogoff, CtrlShutdown};
use veilway_engine::import::{self, Fetcher, Library};
use tokio::sync::watch;
use veilway_engine::local::{Kind, Local, LocalProxy};
use veilway_engine::{ask_text, default_roots, Agree, Check, Retry, Settings, StartError, State, Status, Store, Tunnel, ALPHA_WARNING};
#[cfg(target_os = "linux")]
use veilway_linux as platform;
#[cfg(target_os = "macos")]
use veilway_macos as platform;
#[cfg(windows)]
use veilway_windows as platform;
use platform::state::{self, Ended};
use platform::vault::SecretVault;
#[cfg(target_os = "linux")]
use platform::dns::Restored;
use platform::{Applied, Options, Routes, Stop};
use veilway_proto::subscription::client::{Held, Offer, Permit, Standing};
use veilway_proto::subscription::payload::Id;
use veilway_proto::subscription::Tag;
use veilway_proto::subscription::{legacy, payload::private};
use veilway_proto::xray::{self, profile};

#[derive(Args)]
pub struct Connect {
	/// A link or a subscription file to import first. Without it the subscription already imported is used. A vless://, vmess://, trojan:// or ss:// link connects through the Xray add-on at once, and nothing of it is kept
	source: Option<String>,
	/// Which subscription, when more than one is held: the start of its id
	#[arg(long)] subscription: Option<String>,
	/// Which connection of the subscription, when it has more than one. For pasted links of other apps: the number of the link, from 1
	#[arg(long)] profile: Option<String>,
	/// Send only this network through the tunnel (and the tunnel's own gateway), and let the rest leave as it always did. Repeat for more. Without it everything goes through the tunnel
	#[arg(long = "route")] routes: Vec<IpNet>,
	/// Let programs reach devices on the networks this device is connected to (a printer, the router) outside the tunnel: only the private subnets it is on, not the whole private ranges. The network can see that traffic. Without it the local network goes through the tunnel. Names are still only asked through the tunnel
	#[arg(long)] allow_lan: bool,
	/// With --allow-lan: also let mDNS and LLMNR out, so that names on the local network resolve. They tell the network which names this device asks for
	#[arg(long, requires = "allow_lan")] local_names: bool,
	/// Do not block what is not tunnelled when the tunnel is down or reconnecting
	#[arg(long)] no_kill_switch: bool,
	/// Allow ways of connecting that are still being tested (alpha). Says what that means and asks once; the answer is kept until --no-alpha
	#[arg(long)] alpha: bool,
	/// Switch the alpha ways of connecting off again
	#[arg(long, conflicts_with = "alpha")] no_alpha: bool,
	/// Connect without the system VPN: no network device, no routes, no change to name resolution and no kill switch. Only programs set to use the local proxy go through the tunnel, and it needs neither root nor an administrator account to hold. The proxy listens on 127.0.0.1:10808 unless --local-proxy says otherwise. Not for links of other apps
	#[arg(long)] proxy_only: bool,
	/// Listen as a local SOCKS5 and HTTP proxy at this address (for example 127.0.0.1:10808). Without --proxy-only it runs next to the VPN, and starts once the VPN is connected. An address that is not loopback needs --proxy-user, and what goes between the other device and the proxy is not encrypted
	#[arg(long)] local_proxy: Option<SocketAddr>,
	/// The user name programs must give to use the local proxy. The password is read from --proxy-password-file, never from the command line
	#[arg(long, requires = "proxy_password_file")] proxy_user: Option<String>,
	/// A file with the local proxy's password in it, which only its owner can read (chmod 600). A line break at the end is not part of it
	#[arg(long, requires = "proxy_user")] proxy_password_file: Option<PathBuf>,
	/// The name of the tunnel's network device
	#[cfg_attr(target_os = "linux", arg(long, default_value = "vw0"))]
	#[cfg_attr(target_os = "macos", arg(long, default_value = "utun"))]
	#[cfg_attr(windows, arg(long, default_value = "Veilway"))]
	interface: String,
	/// Where the client keeps its vault and what it remembers. On Linux as root: /var/lib/veilway/client, and the environment is not looked at. Otherwise $VEILWAY_DATA_DIR, else veilway in $XDG_DATA_HOME, else in ~/.local/share. On macOS: Veilway/client in /Library/Application Support, which only root can use. On Windows: Veilway\client in ProgramData, which only administrators can use
	#[arg(long)] data_dir: Option<PathBuf>,
}

fn now() -> u64 {SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())}

/// The directory for the vault and the memory of the client. A client that runs as root takes nothing from the environment, which whoever started it with `sudo -E` could have pointed anywhere, and a directory that is a link, is not its own or can be written by others is an error and is never changed to fit.
#[cfg(target_os = "linux")]
fn data_dir(given: Option<PathBuf>) -> anyhow::Result<PathBuf> {
	let dir = if rustix::process::geteuid().is_root() {given.unwrap_or_else(|| PathBuf::from("/var/lib/veilway/client"))} else {given.or_else(|| std::env::var_os("VEILWAY_DATA_DIR").map(PathBuf::from)).or_else(|| std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()).map(|value| PathBuf::from(value).join("veilway")).or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share/veilway")))).ok_or_else(|| anyhow!("there is no data directory: set HOME or name one with --data-dir"))?};
	state::secure_dir(&dir, 0o700).with_context(|| format!("cannot use {} for the client's files", dir.display()))?;
	Ok(dir)
}

/// The directory for the vault and the memory of the client on macOS: the one given, else `client` in `/Library/Application Support/Veilway`. The client changes the routes, the firewall and the resolver, which only root can do, and the directory is root's: a link, another owner or a directory others can write in is an error.
#[cfg(target_os = "macos")]
fn data_dir(given: Option<PathBuf>) -> anyhow::Result<PathBuf> {
	if !rustix::process::geteuid().is_root() {bail!("the client changes the routes, the firewall and the resolver, which only root can do: run it with sudo")}
	let dir = given.unwrap_or_else(|| Path::new(state::DATA).join("client"));
	// Every folder above it is checked too (root's, closed to others), and the resolved path is the one used.
	state::secure_tree(&dir, 0o700).with_context(|| format!("cannot use {} for the client's files", dir.display()))
}

/// What the LaunchDaemon runs at boot: the kill switch back, if a connection that did not stop left it to be.
#[cfg(target_os = "macos")]
pub async fn restore() -> anyhow::Result<()> {
	let options = Options::default();
	let lock = state::lock(&options.run_dir).await?;
	if platform::restore(&options, &lock)? {println!("The kill switch of a connection that did not stop was put back.")} else {println!("Nothing to restore.")}
	Ok(())
}

/// The directory for the vault and the memory of the client: the one given, else `Veilway\client` in ProgramData. It is made for administrators and SYSTEM only, and a link is an error.
#[cfg(windows)]
fn data_dir(given: Option<PathBuf>) -> anyhow::Result<PathBuf> {
	let dir = given.unwrap_or_else(state::default_data_dir);
	state::secure_dir(&dir, platform::acl::Access::Private).with_context(|| format!("cannot use {} for the client's files", dir.display()))?;
	Ok(dir)
}

/// The signals that end a connection: they are taken before anything is changed, so that one during the set-up or at a question does not end the process in the middle. SIGINT and SIGTERM are the user asking to stop. SIGHUP is a closed terminal, and is not.
#[cfg(unix)]
struct Signals {terminate: Signal, interrupt: Signal, hangup: Signal}

#[cfg(unix)]
impl Signals {
	fn new() -> std::io::Result<Self> {Ok(Self {terminate: signal(SignalKind::terminate())?, interrupt: signal(SignalKind::interrupt())?, hangup: signal(SignalKind::hangup())?})}
	async fn next(&mut self) -> Stop {tokio::select! {_ = self.terminate.recv() => Stop::Asked, _ = self.interrupt.recv() => Stop::Asked, _ = self.hangup.recv() => Stop::Hangup}}
}

/// The events that end a connection on Windows, taken before anything is changed. Ctrl+C, Ctrl+Break and a shutdown or logoff are the user asking to stop (`veilway disconnect` is the other way, a named event the lock holds). Closing the console window is not: nobody is there to see, and the kill switch stays.
#[cfg(windows)]
struct Signals {c: CtrlC, brk: CtrlBreak, close: CtrlClose, logoff: CtrlLogoff, shutdown: CtrlShutdown}

#[cfg(windows)]
impl Signals {
	fn new() -> std::io::Result<Self> {Ok(Self {c: ctrl_c()?, brk: ctrl_break()?, close: ctrl_close()?, logoff: ctrl_logoff()?, shutdown: ctrl_shutdown()?})}
	async fn next(&mut self) -> Stop {tokio::select! {_ = self.c.recv() => Stop::Asked, _ = self.brk.recv() => Stop::Asked, _ = self.logoff.recv() => Stop::Asked, _ = self.shutdown.recv() => Stop::Asked, _ = self.close.recv() => Stop::Hangup}}
}

/// The terminal went away while a question waited. It is not an answer, and it lifts nothing.
#[derive(Debug)]
struct HangUp;

impl std::fmt::Display for HangUp {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {f.write_str("The terminal went away.")}
}

impl std::error::Error for HangUp {}

/// A question the user answers on the terminal, and only the word yes is a yes. Anything else, and the end of the input, is no. A signal while it waits is a stop, which is an error: the caller undoes what it did.
async fn ask(question: &str, signals: &mut Signals) -> anyhow::Result<bool> {
	eprint!("{question} Type yes to continue: ");
	let _ = std::io::stderr().flush();
	let read = tokio::task::spawn_blocking(|| {
		let mut line = String::new();
		std::io::stdin().lock().read_line(&mut line).map(|read| read > 0 && line.trim().eq_ignore_ascii_case("yes"))
	});
	tokio::select! {
		answer = read => Ok(answer?.unwrap_or(false)),
		stop = signals.next() => match stop {Stop::Asked => bail!("Stopped."), Stop::Hangup => Err(HangUp.into())},
	}
}

fn size(bytes: u64) -> String {
	let (mut value, mut unit) = (bytes as f64, 0);
	while value >= 1024.0 && unit < 4 {
		value /= 1024.0;
		unit += 1;
	}
	if unit == 0 {format!("{bytes} B")} else {format!("{value:.1} {}", ["B", "KB", "MB", "GB", "TB"][unit])}
}

/// The state in one line of plain words, as the terminal prints it when it changes.
pub fn state_line(status: &Status, now: u64) -> String {
	let wait = |wait: Option<u64>| wait.map_or_else(String::new, |at| format!(" Next try in {} s.", at.saturating_sub(now)));
	match &status.state {
		State::Off => "Off.".into(),
		State::Connecting {wait: at, ..} => format!("Connecting.{}", wait(*at)),
		State::Connected {exit: Some(exit)} => format!("Connected, through the exit {exit}."),
		State::Connected {exit: None} => "Connected.".into(),
		State::Reconnecting {wait: at, ..} => format!("The connection was lost. Reconnecting.{}", wait(*at)),
		State::Stopped {reason, retry} => format!("{} {}", reason.say().text(), match retry {Retry::At(at) => format!("Trying again in {} s, or when you run connect again.", at.saturating_sub(now)), Retry::Asked => "It starts again when you run connect again.".into()}),
		State::Failed => "Failed. Nothing more can be done until you act.".into(),
	}
}

/// Everything `veilway status` shows, in plain words. It names no rating or class.
pub fn render(status: &Status, applied: &Applied, now: u64) -> String {
	let mut lines = vec![status.name.clone(), format!("State: {}", state_line(status, now))];
	if let Some(say) = status.say {lines.push(format!("Note: {}", say.text()))}
	lines.push(match (applied.kill_switch, &applied.split) {
		(true, None) => "Kill switch: on. Nothing leaves this device outside the tunnel, also while it reconnects.".to_owned(),
		(true, Some(nets)) => format!("Kill switch: on for {} only. If the tunnel is down or reconnecting those networks are blocked. All other traffic is not blocked and leaves outside the tunnel.", nets.join(", ")),
		(false, _) => "Kill switch: off. Traffic can leave outside the tunnel when it is down.".to_owned(),
	});
	lines.push(format!("Names: looked up only through the tunnel (set in {}).", applied.dns));
	lines.push(match &applied.split {None => "Routes: everything goes through the tunnel.".into(), Some(nets) => format!("Routes: only {} goes through the tunnel.", nets.join(", "))});
	if applied.allow_lan {lines.push("Local network: devices on the subnets this device is connected to are reached outside the tunnel.".into())}
	lines.push(format!("Device: {}, packet size {}.", applied.interface, status.mtu));
	if let Some(found) = &status.connection {
		let check = found.check.map(|check| match check {Check::Public => "public certificate", Check::PublicAndPin => "public certificate and pin", Check::PinnedSelfSigned => "pinned self-signed"});
		let parts = [Some(format!("{}{}", found.address, found.host.as_ref().map_or_else(String::new, |host| format!(" ({host})")))), Some(found.transport.to_owned()), found.front.as_ref().map(|front| format!("front {front}")), found.server_name.as_ref().map(|name| format!("server name {name}")), check.map(str::to_owned), found.alpha.then(|| "alpha: new and not reviewed outside the project, borrows a real site that has not agreed".to_owned()), found.since.map(|since| format!("up {} s", now.saturating_sub(since)))];
		lines.push(format!("Server: {}.", parts.into_iter().flatten().collect::<Vec<_>>().join(", ")));
	}
	let counters = status.counters;
	lines.push(format!("Traffic: {} sent, {} received.", size(counters.bytes_sent), size(counters.bytes_received)));
	if let Some(usage) = status.usage {lines.push(if usage.quota_bytes == 0 {format!("Usage: {} used, no limit.", size(usage.used_bytes))} else {format!("Usage: {} of {} used.", size(usage.used_bytes), size(usage.quota_bytes))})}
	if !status.exits.is_empty() {lines.push(format!("Exits: {}.", status.exits.iter().map(|exit| format!("{}{}", exit.name, if exit.selected || (exit.configured && !status.exits.iter().any(|other| other.selected)) {" (in use)"} else {""})).collect::<Vec<_>>().join(", ")))}
	for notice in &status.notices {lines.push(format!("From the provider: {}", notice.text))}
	if status.out_of_date {lines.push("This connection's settings are out of date. Refresh the subscription.".into())}
	if let Some(view) = status.xray {
		let flows = view.counters;
		if let Some(say) = view.say {lines.push(format!("Note: {}", say.text()))}
		lines.push(format!("Flows: {} TCP and {} UDP open, {} carried, {} failed. Through the server: {} sent, {} received.", flows.open_tcp, flows.open_udp, flows.carried_flows, flows.failed_flows, size(flows.bytes_sent), size(flows.bytes_received)));
		lines.push(format!("Not carried: {} packets of kinds other than TCP and UDP, and {} UDP flows.", flows.unsupported_packets, flows.dropped_udp_flows));
		lines.push(format!("Add-on restarts: {}.", flows.restarts));
	}
	lines.join("\n") + "\n"
}

fn languages() -> Vec<Tag> {
	std::env::var("LANGUAGE").ok().filter(|value| !value.is_empty()).or_else(|| std::env::var("LANG").ok()).into_iter().flat_map(|value| value.split(':').map(str::to_owned).collect::<Vec<_>>()).filter_map(|value| Tag::read(&value.split('.').next().unwrap_or_default().replace('_', "-"))).collect()
}

// The two questions of an import, with the third thing it needs to say: nothing is kept until the second yes.
async fn import_source(library: &mut Library, source: &str, signals: &mut Signals) -> anyhow::Result<()> {
	let offer = if Path::new(source).is_file() {import::open_file(&std::fs::read(source)?)} else {import::open(source)}.map_err(|error| anyhow!(error.text()))?;
	let (fetcher, at) = (Fetcher::new(default_roots(), None), now());
	let reviewed = match offer {
		Offer::Native(offer) => {
			eprintln!("This link belongs to the server {}.", offer.endpoint().host());
			eprintln!("The provider's fingerprint is {}.", offer.fingerprint());
			if offer.pin().is_some() {eprintln!("The server uses its own certificate, which this link names.")}
			eprintln!("If you continue, the link's token and a new key for this device are sent to that server.");
			if !ask("Continue?", signals).await? {bail!("Nothing was sent.")}
			let fetching = import::proceed(offer, None).map_err(|error| anyhow!(error.text()))?;
			let mut allowed = Vec::new();
			loop {
				match fetcher.fetch(&fetching, library, at, &allowed).await {
					Ok(reviewed) => break reviewed,
					Err(import::ImportError::PrivateEndpoint {addresses, ..}) if allowed.is_empty() => {
						eprintln!("This subscription is on a private address ({}). Only continue if you run this server yourself, for example at home.", addresses.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
						if !ask("Connect to it?", signals).await? {bail!("Nothing was sent.")}
						allowed = addresses;
					}
					Err(error) => bail!(error.text()),
				}
			}
		}
		Offer::Carried(offer) => {
			eprintln!("This {} carries a whole subscription and contacts nobody.", if offer.in_file() {"file"} else {"link"});
			eprintln!("The provider's fingerprint is {}.", offer.fingerprint());
			if !ask("Read it?", signals).await? {bail!("Nothing was read.")}
			import::proceed_carried(offer, at, library).map_err(|error| anyhow!(error.text()))?
		}
		Offer::Legacy(_) => bail!(import::ImportError::Legacy.text()),
	};
	let subscription = reviewed.review.subscription();
	eprintln!("Provider (its own claim): {}", subscription.provider.as_str());
	eprintln!("Fingerprint: {}", reviewed.review.fingerprint());
	for profile in &subscription.profiles {eprintln!("Connection: {} ({})", profile.name.as_str(), profile.id)}
	for refused in &subscription.refused {eprintln!("Left out: {refused:?}")}
	if !ask("Keep this subscription?", signals).await? {
		fetcher.decline(reviewed).await;
		bail!("Nothing was kept.");
	}
	// A vault that could not be written says why: the user has to know that no safe place for the key was found.
	fetcher.accept(reviewed, None, library).await.map_err(|error| match &error {import::ImportError::Store(cause) => anyhow!("{} {cause}", error.text()), _ => anyhow!(error.text())})?;
	eprintln!("Kept.");
	Ok(())
}

fn short(id: &Id) -> &str {&id.as_str()[..id.as_str().len().min(12)]}

/// What the user is told when a connection ended without being asked to: the kill switch stays in force, and only `veilway disconnect` lifts it.
fn kept_message(failure: &platform::Failure) -> String {
	if failure.kept {format!("{failure}. The connection ended on its own, and the kill switch is still in force, so nothing leaves this device outside the tunnel. Run `veilway disconnect` to restore your normal connection.")} else {format!("{failure}")}
}

/// Writes the status file and prints a line when the state changes, for both kinds of connection. A wait counts down, and a line is printed when the state changes and not at every second of the count.
fn announce(run: &Path, shown: &mut String, status: &Status, applied: &Applied) {
	let at = now();
	if let Err(error) = state::write_status(run, &render(status, applied, at)) {tracing::warn!(%error, "the status could not be written")}
	let key = state_line(status, 0);
	if key != *shown {
		println!("{}: {}", status.name, state_line(status, at));
		*shown = key;
	}
}

const LEGACY: [&str; 4] = ["vless://", "vmess://", "trojan://", "ss://"];

fn is_legacy(text: &str) -> bool {LEGACY.iter().any(|scheme| text.trim_start().starts_with(scheme))}

/// The text of a file that holds links of other apps, for `connect`. A link carries its credential, so it is not taken from the command line, which every user of the computer can read: it is read from a file that only its owner can read. None when `source` is no such file. A file with links in it that others can read is an error and is not used.
fn legacy_file(source: &str) -> anyhow::Result<Option<String>> {
	let path = Path::new(source);
	let Ok(meta) = std::fs::symlink_metadata(path) else {return Ok(None)};
	if !meta.is_file() || meta.len() > 1 << 20 {return Ok(None)}
	let Ok(text) = std::fs::read_to_string(path) else {return Ok(None)};
	if !is_legacy(&text) {return Ok(None)}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if meta.mode() & 0o077 != 0 {bail!("legacy_file_open: {source} holds a link with a credential and can be read by others: run chmod 600 on it")}
		if meta.uid() != 0 && std::env::var("SUDO_UID").ok().and_then(|id| id.parse::<u32>().ok()) != Some(meta.uid()) {bail!("legacy_file_owner: {source} is owned by a user who is neither root nor the one who ran sudo")}
	}
	Ok(Some(text))
}

/// `--proxy-only`: the engine's tunnel with nothing of the system under it, and the local proxy as its only door. Prints the state when it changes. Ok is a stop the user asked for.
async fn proxy_only(config: LocalProxy, settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree, stop: impl Future<Output = Stop>) -> anyhow::Result<()> {
	let tunnel = Tunnel::start(settings, held, profile, permit, agree)?;
	let local = match Local::in_tunnel(tunnel, config).await {
		Ok(local) => local,
		Err((error, tunnel)) => {
			tunnel.stop().await;
			return Err(error.into());
		}
	};
	let mut watch = local.watch().context("the proxy has no tunnel under it")?;
	eprintln!("Proxy only: listening on {}. Only programs set to use it go through the tunnel, and nothing else on this device changes.", local.addr());
	let (mut shown, mut stop) = (String::new(), std::pin::pin!(stop));
	loop {
		let status = watch.borrow_and_update().clone();
		let key = state_line(&status, 0);
		if key != shown {
			println!("{}: {}", status.name, state_line(&status, now()));
			shown = key;
		}
		tokio::select! {
			changed = watch.changed() => if changed.is_err() {bail!("the engine stopped on its own")},
			_ = stop.as_mut() => break,
		}
	}
	local.stop().await;
	Ok(())
}

/// Connects to pasted links of other apps through the Xray add-on ("Xray in the desktop apps"). Nothing of the links is kept: they are read, checked against the table of what can connect, and used for this run. Steps, in this order: the profile is checked, the add-on is found (or offered for download, with a yes), the add-on is held to its pin, the server's name is resolved and its address checked, and `veilway_xray::run` does the rest.
async fn connect_xray(args: &Connect, source: &str, data: &Path, signals: &mut Signals) -> anyhow::Result<()> {
	#[cfg(unix)]
	if !rustix::process::geteuid().is_root() {bail!("xray_needs_root: the add-on runs as an account of its own, and the tunnel and the firewall need root: run it with sudo")}
	let list = legacy::list(source.as_bytes()).map_err(|error| anyhow!("{error}"))?;
	let entry = match (&args.profile, list.entries.len()) {
		(Some(number), count) => number.parse::<usize>().ok().and_then(|number| number.checked_sub(1)).and_then(|at| list.entries.get(at)).ok_or_else(|| anyhow!("The pasted text has {count} connections, pick one with --profile and a number from 1 to {count}."))?,
		(None, 1) => &list.entries[0],
		(None, 0) => bail!("No link of a kind this app reads was found ({} skipped).", list.skipped),
		(None, count) => bail!("The pasted text has {count} connections, pick one with --profile and a number from 1 to {count}."),
	};
	let profile = profile::check(entry).map_err(|refusal| anyhow!("{}: this connection cannot be used with the add-on, so nothing was started", refusal.code()))?;
	let target = veilway_xray::target().ok_or_else(|| anyhow!("xray_missing: there is no Xray add-on for this system"))?;
	let pin = xray::pin(target).ok_or_else(|| anyhow!("xray_missing: there is no Xray add-on for this system"))?;
	let (run, addons) = (Options::default().run_dir, veilway_xray::addons_dir(data));
	// The lock is held from here to the end, also while the user is asked something: nothing else changes what is in force meanwhile.
	let lock = state::lock(&run).await?;
	if !veilway_xray::installed(&addons) {
		eprintln!("This profile needs Xray-core, a program made by another project. Veilway can download version {} from github.com/XTLS/Xray-core (at most {}) and check it against a fingerprint built into this app. It runs on your computer with limited rights and only carries this profile's traffic.", xray::RELEASE, size(veilway_xray::ARCHIVE_MAX));
		if !ask("Install and connect?", signals).await? {bail!("xray_missing: the Xray add-on is not installed. Nothing was downloaded.")}
		veilway_xray::fetch_install(&addons, target, pin, &veilway_xray::mirrors_from_env(), &std::sync::atomic::AtomicU64::new(0)).await.map_err(|(step, error)| anyhow!("{}: {error:#}", step.code()))?;
		eprintln!("Installed.");
	}
	veilway_xray::check_addon(&veilway_xray::executable(&addons), pin)?;
	let server = veilway_xray::server(&profile).await?;
	if private(server) && !ask("This connection goes to a private address, which is not on the internet. That is normal for a server on your own network and unusual otherwise. Connect?", signals).await? {bail!("Not connected.")}
	let options = Options {interface: args.interface.clone(), kill_switch: !args.no_kill_switch, allow_lan: args.allow_lan, local_names: args.local_names, routes: if args.routes.is_empty() {Routes::Full} else {Routes::Split(args.routes.clone())}, run_dir: run.clone(), ..Options::default()};
	let name = if entry.name.as_str().is_empty() {"Xray profile".to_owned()} else {entry.name.as_str().to_owned()};
	let mut shown = String::new();
	let on_status = |status: &Status, applied: &Applied| announce(&run, &mut shown, status, applied);
	#[cfg(unix)]
	let ended = signals.next();
	#[cfg(windows)]
	let ended = async {tokio::select! {reason = signals.next() => reason, () = lock.stop_asked() => Stop::Asked}};
	if let Err(failure) = veilway_xray::run(&options, &lock, profile, server, name, veilway_xray::executable(&addons), pin, on_status, ended).await {bail!(kept_message(&failure))}
	eprintln!("Disconnected. Everything is back as it was.");
	Ok(())
}

pub async fn connect(args: Connect) -> anyhow::Result<()> {
	tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))).with_writer(std::io::stderr).init();
	let (data, run) = (data_dir(args.data_dir.clone())?, Options::default().run_dir);
	let mut signals = Signals::new()?;
	let proxy = if args.proxy_only || args.local_proxy.is_some() {
		let mut config = LocalProxy::new(args.local_proxy.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 10808))), Kind::Mixed);
		if let (Some(user), Some(file)) = (&args.proxy_user, &args.proxy_password_file) {
			let meta = std::fs::symlink_metadata(file).with_context(|| format!("cannot read {}", file.display()))?;
			if !meta.is_file() || meta.len() > 4096 {bail!("{} is not a file a password can be in", file.display())}
			#[cfg(unix)]
			{
				use std::os::unix::fs::MetadataExt;
				if meta.mode() & 0o077 != 0 {bail!("proxy_password_file_open: {} can be read by others: run chmod 600 on it", file.display())}
				if meta.uid() != 0 && std::env::var("SUDO_UID").ok().and_then(|id| id.parse::<u32>().ok()) != Some(meta.uid()) {bail!("proxy_password_file_owner: {} is owned by a user who is neither root nor the one who ran sudo", file.display())}
			}
			let password = std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
			config.auth = Some((user.clone(), password.trim_end_matches(['\r', '\n']).to_owned()));
		}
		if config.auth.is_none() {
			// A login is always on, also on 127.0.0.1: other programs on this computer must not use the proxy freely. It is told once, on the standard output and not in the log.
			let mut bytes = [0u8; 40];
			ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| anyhow!("no source of random numbers was found to make the proxy's login"))?;
			let text: Vec<char> = bytes.iter().map(|byte| b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict"[(byte & 63) as usize] as char).collect();
			let (user, password) = (text[..20].iter().collect::<String>(), text[20..].iter().collect::<String>());
			println!("Local proxy login: user {user} password {password}");
			config.auth = Some((user, password));
		}
		config.check()?;
		Some(config)
	} else {None};
	if proxy.is_some() && (args.source.as_deref().is_some_and(is_legacy) || args.source.as_deref().map(legacy_file).transpose()?.flatten().is_some()) {bail!("the local proxy is not available for links of other apps, which connect through the Xray add-on")}
	if args.source.as_deref().is_some_and(is_legacy) {bail!("legacy_link_on_command_line: a link of another app carries its credential, and a command line can be read by every user of this computer. Put the link in a file that only you can read (chmod 600) and give the file to `veilway connect`")}
	if let Some(text) = args.source.as_deref().map(legacy_file).transpose()?.flatten() {return connect_xray(&args, &text, &data, &mut signals).await}
	let (mut library, damaged) = Library::open(Box::new(SecretVault::new(data.join("vault")))).map_err(|error| anyhow!("{error}"))?;
	for _ in damaged {eprintln!("A stored subscription does not read any more and is left out.")}
	if let Some(source) = &args.source {import_source(&mut library, source, &mut signals).await?}
	if library.held().is_empty() {bail!("There is no subscription yet. Run `veilway connect <link>` with the link your provider gave you.")}
	let held = match &args.subscription {
		Some(prefix) => library.held().iter().find(|held| held.id().as_str().starts_with(prefix.as_str())).ok_or_else(|| anyhow!("No subscription starts with {prefix}."))?,
		None if library.held().len() == 1 => &library.held()[0],
		None => bail!("More than one subscription is held, pick one with --subscription: {}", library.held().iter().map(|held| format!("{} ({})", short(held.id()), held.subscription().provider.as_str())).collect::<Vec<_>>().join(", ")),
	};
	let profiles = &held.subscription().profiles;
	let profile = match &args.profile {
		Some(id) => profiles.iter().find(|profile| &profile.id == id).ok_or_else(|| anyhow!("The subscription has no connection with the id {id}."))?,
		None if profiles.len() == 1 => &profiles[0],
		None => bail!("The subscription has more than one connection, pick one with --profile: {}", profiles.iter().map(|profile| format!("{} ({})", profile.id, profile.name.as_str())).collect::<Vec<_>>().join(", ")),
	};
	if held.standing(now()) != Standing::Current {eprintln!("This subscription is out of date. It keeps working; refresh it when you can.")}
	if held.subscription().has_unknown_transport() {eprintln!("This subscription offers a way of connecting this app does not know. Update the app to use it.")}
	let permit = match held.connect(now()) {
		Ok(permit) => permit,
		Err(stale) => if ask("This subscription expired more than 30 days ago, and the addresses and keys in it may no longer belong to the provider. Connect anyway?", &mut signals).await? {stale.confirmed()} else {bail!("Not connected.")},
	};
	let store = Arc::new(Store::open(data.join("client.json")));
	let mut settings = Settings::new(store.clone(), Arc::new(now), default_roots(), String::new());
	settings.languages = languages();
	if args.no_alpha {store.set_alpha_transports(false)} else if args.alpha && !store.alpha_transports() {
		if !ask(&format!("{ALPHA_WARNING} Allow it?"), &mut signals).await? {bail!("Not connected. Alpha ways of connecting stay off.")}
		store.set_alpha_transports(true);
	}
	let options = Options {interface: args.interface, kill_switch: !args.no_kill_switch, allow_lan: args.allow_lan, local_names: args.local_names, routes: if args.routes.is_empty() {Routes::Full} else {Routes::Split(args.routes)}, run_dir: run.clone(), ..Options::default()};
	// The one lock every command takes, held from here to the end, also while the user is asked something: nothing else changes what is in force meanwhile.
	// Proxy only has nothing of the system to lock or undo.
	let lock = if args.proxy_only {None} else {Some(state::lock(&run).await?)};
	let (key, mut agree) = (veilway_engine::store::profile_key(held.id().as_str(), &profile.id), Agree::default());
	loop {
		let (mut shown, (statuses, mut seen)) = (String::new(), watch::channel(None::<Status>));
		let on_status = |status: &Status, applied: &Applied| {
			statuses.send_replace(Some(status.clone()));
			announce(&run, &mut shown, status, applied);
		};
		#[cfg(unix)]
		let stop = signals.next();
		#[cfg(windows)]
		let stop = async {tokio::select! {reason = signals.next() => reason, () = async {match &lock {Some(lock) => lock.stop_asked().await, None => std::future::pending().await}} => Stop::Asked}};
		let outcome = match (&lock, &proxy) {
			(Some(lock), Some(config)) => {
				let run = platform::run(&options, lock, settings.clone(), held, &profile.id, &permit, agree, on_status, stop);
				// Beside the VPN the proxy is given the tunnel's status, and the engine refuses what it takes while the tunnel is not connected.
				let beside = async {
					if let Some(first) = seen.wait_for(Option::is_some).await.ok().and_then(|found| found.clone()) {
						let (tx, rx) = watch::channel(first);
						match Local::alongside(config.clone(), rx).await {
							Ok(local) => {
								eprintln!("Local proxy: listening on {}.", local.addr());
								while seen.changed().await.is_ok() {
									if let Some(status) = seen.borrow_and_update().clone() {tx.send_replace(status);}
								}
							}
							Err(error) => eprintln!("The local proxy did not start: {error}"),
						}
					}
					std::future::pending::<()>().await
				};
				tokio::select! {outcome = run => outcome, _ = beside => Ok(())}
			}
			(Some(lock), None) => platform::run(&options, lock, settings.clone(), held, &profile.id, &permit, agree, on_status, stop).await,
			(None, None) => bail!("proxy only needs the local proxy"),
			(None, Some(config)) => proxy_only(config.clone(), settings.clone(), held, &profile.id, &permit, agree, stop).await.map_err(|error| platform::Failure {error, kept: false}),
		};
		let _ = store.flush();
		let Err(failure) = outcome else {break};
		// The tunnel did not start because the user has still to say something. The kill switch is in force while the question waits. A no, or a stop, is the user's own end of it, and lifts what is in force; any other end is not.
		let answer = match failure.error.downcast_ref::<StartError>() {
			Some(StartError::Private) => ask("This connection goes to a private address, which is not on the internet. That is normal for a server on your own network and unusual otherwise. A yes also lets it be dialled if it is inside a network this device is on. Connect?", &mut signals).await.map(|yes| {agree.private |= yes; yes}),
			Some(StartError::Unsafe) => ask("This connection does not check who it is talking to. Anyone on the network can read and change what you send. Connect anyway?", &mut signals).await.map(|yes| {agree.unsafe_profile |= yes; yes}),
			Some(StartError::Ask(classes)) => {
				let mut all = Ok(true);
				for class in classes {
					match ask(ask_text(*class), &mut signals).await {
						Ok(true) => store.agree(&key, *class),
						Ok(false) => store.decline(&key, *class),
						Err(error) => {
							all = Err(error);
							break;
						}
					}
				}
				all
			}
			Some(StartError::Alpha) => Err(anyhow!("This connection can only be made in a way that is still being tested (alpha), and that is switched off. Run `veilway connect --alpha` to read what that means and switch it on.")),
			Some(_) | None => bail!(kept_message(&failure)),
		};
		// The terminal going away is not an answer: nobody is there, and the kill switch stays like after any other end.
		if answer.as_ref().err().is_some_and(|error| error.downcast_ref::<HangUp>().is_some()) {bail!(kept_message(&platform::Failure {error: anyhow!("the terminal went away (SIGHUP)"), kept: lock.is_some()}))}
		if !matches!(answer, Ok(true)) {
			let cleaned = lock.as_ref().map(|lock| platform::cleanup(&options, lock)).transpose();
			let _ = store.flush();
			cleaned?;
			bail!(answer.err().map_or_else(|| "Not connected.".to_owned(), |error| error.to_string()));
		}
	}
	eprintln!("Disconnected. Everything is back as it was.");
	Ok(())
}

/// `veilway remove`.
#[derive(Args)]
pub struct Remove {
	/// Which subscription, when more than one is held: the start of its id
	#[arg(long)] subscription: Option<String>,
	/// Where the client keeps its vault, as for `connect`
	#[arg(long)] data_dir: Option<PathBuf>,
}

pub async fn remove(args: Remove) -> anyhow::Result<()> {
	let data = data_dir(args.data_dir)?;
	// The lock `connect` holds for as long as it runs: a subscription in use is not removed under it.
	let _lock = state::lock(&Options::default().run_dir).await?;
	let (mut library, _) = Library::open(Box::new(SecretVault::new(data.join("vault")))).map_err(|error| anyhow!("{error}"))?;
	let id = match &args.subscription {
		Some(prefix) => library.held().iter().find(|held| held.id().as_str().starts_with(prefix.as_str())).ok_or_else(|| anyhow!("No subscription starts with {prefix}."))?,
		None if library.held().len() == 1 => &library.held()[0],
		None if library.held().is_empty() => bail!("There is no subscription to remove."),
		None => bail!("More than one subscription is held, pick one with --subscription: {}", library.held().iter().map(|held| format!("{} ({})", short(held.id()), held.subscription().provider.as_str())).collect::<Vec<_>>().join(", ")),
	}.id().clone();
	Fetcher::new(default_roots(), None).leave(&mut library, &id).await.context("the subscription could not be removed")?;
	println!("Removed. The provider was asked to free this device's place.");
	Ok(())
}

pub async fn disconnect() -> anyhow::Result<()> {
	let options = Options::default();
	// A client that runs is asked to stop, which it does the clean way. Only when none holds the lock is there anything to clean up by hand, and the lock is then taken for it: a client that starts meanwhile finds it held, and this command never touches what a running one has made.
	match state::terminate(&options.run_dir, Duration::from_secs(20)).await? {
		Ended::NotRunning => {}
		#[cfg(unix)]
		Ended::Stopped(_) => println!("The connection stopped."),
		#[cfg(windows)]
		Ended::Stopped => println!("The connection stopped."),
		#[cfg(unix)]
		Ended::Killed(_) => println!("The connection did not stop in time and was ended."),
	}
	let lock = state::lock(&options.run_dir).await?;
	let cleaned = platform::cleanup(&options, &lock)?;
	#[cfg(target_os = "linux")]
	let left: Vec<&str> = [(cleaned.kill_switch, "the kill switch"), (cleaned.routes > 0, "the routing rules and routes")].into_iter().filter(|(found, _)| *found).map(|(_, name)| name).collect();
	#[cfg(any(windows, target_os = "macos"))]
	let left: Vec<&str> = [(cleaned.kill_switch, "the kill switch"), (cleaned.resolver, "the name resolution rule")].into_iter().filter(|(found, _)| *found).map(|(_, name)| name).collect();
	if !left.is_empty() {println!("Removed what the connection left in force: {}.", left.join(", "))}
	#[cfg(target_os = "linux")]
	match cleaned.resolver {
		Restored::Put => println!("Put /etc/resolv.conf back as it was before the connection."),
		Restored::LeftAlone => println!("Another program rewrote /etc/resolv.conf while the connection was up, so it was left as that program made it. Check that it names a resolver you want."),
		Restored::Damaged => println!("The saved copy of /etc/resolv.conf could not be read, so the file was left as it is, and the copy was moved aside as resolv.conf.bad in /var/lib/veilway. Check that /etc/resolv.conf names a resolver you want."),
		Restored::Nothing => {}
	}
	#[cfg(target_os = "linux")]
	let nothing = left.is_empty() && cleaned.resolver == Restored::Nothing;
	#[cfg(any(windows, target_os = "macos"))]
	let nothing = left.is_empty();
	if nothing {println!("Nothing is in force. Your normal connection is as it was.")} else {println!("Your normal connection is back.")}
	Ok(())
}

pub fn show() -> i32 {
	let run = Options::default().run_dir;
	if state::holder(&run) != state::Holder::Free {
		match state::read_status(&run) {
			Ok(text) => print!("{text}"),
			Err(_) => println!("Starting."),
		}
		return 0;
	}
	println!("Not connected.");
	if platform::firewall::present() == Some(true) {println!("The kill switch is still in force because the connection ended without being stopped. Nothing leaves this device outside the tunnel. Run `veilway disconnect` to restore your normal connection.")}
	3
}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_engine::{Counters, Say, Stop, XrayCounters, XraySay, XrayView};

	fn status(state: State) -> Status {Status {state, name: "Home".into(), say: None, exits: Vec::new(), usage: None, notices: Vec::new(), mtu: 1390, control: false, out_of_date: false, counters: Counters::default(), connection: None, xray: None}}

	fn applied() -> Applied {Applied {interface: "vw0".into(), kill_switch: true, dns: "/etc/resolv.conf", split: None, allow_lan: false}}

	#[test]
	fn the_surface_is_plain_words_with_no_rating_class_or_transport() {
		let mut found = status(State::Connected {exit: Some("main".into())});
		found.say = Some(Say::Lost);
		let text = render(&found, &applied(), 100).to_lowercase();
		for word in ["protected", "detectable", "unsafe", "rating", "nocover", "cover", "obfs", "tls", "fronted", "websocket", "transport"] {assert!(!text.contains(word), "{word} in {text}")}
		assert!(text.contains("connected, through the exit main.") && text.contains("kill switch: on") && text.contains("looked up only through the tunnel"));
		assert!(!text.contains('\u{2014}'));
	}

	#[test]
	fn a_connection_through_the_add_on_shows_its_counters_and_its_reason_in_plain_words() {
		let mut found = status(State::Reconnecting {attempt: None, wait: None});
		found.xray = Some(XrayView {counters: XrayCounters {open_tcp: 3, open_udp: 1, failed_flows: 2, carried_flows: 40, bytes_sent: 2048, bytes_received: 4096, unsupported_packets: 5, dropped_udp_flows: 1, restarts: 2, last_restart: Some(9)}, say: Some(XraySay::Restarting)});
		let text = render(&found, &applied(), 100);
		assert!(text.contains("Note: The Xray add-on stopped and is starting again.") && text.contains("Flows: 3 TCP and 1 UDP open, 40 carried, 2 failed. Through the server: 2.0 KB sent, 4.0 KB received.") && text.contains("Not carried: 5 packets of kinds other than TCP and UDP, and 1 UDP flows.") && text.contains("Add-on restarts: 2."), "{text}");
		let lower = text.to_lowercase();
		for word in ["protected", "detectable", "unsafe", "rating", "nocover", "cover", "obfs", "fronted", "transport"] {assert!(!lower.contains(word), "{word} in {text}")}
		assert!(!render(&status(State::Off), &applied(), 0).contains("Add-on restarts"), "a native connection has no counters of the add-on");
	}

	#[test]
	fn only_links_of_other_apps_take_the_add_on_path() {
		for source in ["vless://id@host:443", "  vmess://eyJ9", "trojan://p@h:1", "ss://x@h:1"] {assert!(is_legacy(source), "{source}")}
		for source in ["https://panel.example/sub", "veilway://x", "/tmp/file", "vlessx://a"] {assert!(!is_legacy(source), "{source}")}
	}

	#[cfg(unix)]
	#[test]
	fn a_link_comes_from_a_file_only_its_owner_can_read_and_never_from_the_command_line() {
		use std::os::unix::fs::PermissionsExt;
		let dir = std::env::temp_dir().join(format!("veilway-legacy-file-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let (open, closed, native) = (dir.join("open"), dir.join("closed"), dir.join("native"));
		for (path, text, mode) in [(&open, "vless://id@host.example:443\n", 0o644), (&closed, "vless://id@host.example:443\n", 0o600), (&native, "{}", 0o644)] {
			std::fs::write(path, text).unwrap();
			std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
		}
		let error = legacy_file(open.to_str().unwrap()).unwrap_err().to_string();
		assert!(error.starts_with("legacy_file_open") && !error.contains("id@host"), "{error}");
		let owned = legacy_file(closed.to_str().unwrap());
		assert!(owned.as_ref().is_ok_and(|text| text.as_deref() == Some("vless://id@host.example:443\n")) || owned.unwrap_err().to_string().starts_with("legacy_file_owner"));
		assert_eq!(legacy_file(native.to_str().unwrap()).unwrap(), None, "a file that holds no such link is for the other path");
		assert_eq!(legacy_file(dir.join("none").to_str().unwrap()).unwrap(), None);
		assert_eq!(legacy_file("vless://id@host.example:443").unwrap(), None, "a link is no file");
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn the_server_line_gives_the_candidate_in_use_and_no_secret() {
		let mut found = status(State::Connected {exit: None});
		found.connection = Some(veilway_engine::Connection {transport: "fronted", address: "192.0.2.7:443".parse().unwrap(), host: None, front: Some("cdn.example".into()), server_name: Some("cdn.example".into()), check: Some(Check::Public), since: Some(40), alpha: false});
		let text = render(&found, &applied(), 100);
		assert!(text.contains("Server: 192.0.2.7:443, fronted, front cdn.example, server name cdn.example, public certificate, up 60 s."), "{text}");
	}

	#[test]
	fn every_state_has_its_words_and_a_wait_is_counted_down() {
		assert_eq!(state_line(&status(State::Off), 0), "Off.");
		assert_eq!(state_line(&status(State::Connecting {attempt: None, wait: Some(130)}), 100), "Connecting. Next try in 30 s.");
		assert_eq!(state_line(&status(State::Reconnecting {attempt: None, wait: None}), 0), "The connection was lost. Reconnecting.");
		assert!(state_line(&status(State::Stopped {reason: Stop::Quota, retry: Retry::Asked}), 0).contains("data allowance is used up"));
		assert!(state_line(&status(State::Failed), 0).starts_with("Failed."));
	}

	#[test]
	fn the_kill_switch_being_off_and_a_split_are_said() {
		let off = Applied {kill_switch: false, split: Some(vec!["203.0.113.0/24".into()]), allow_lan: true, ..applied()};
		let text = render(&status(State::Off), &off, 0);
		assert!(text.contains("Kill switch: off.") && text.contains("only 203.0.113.0/24 goes through the tunnel") && text.contains("Local network: devices on the subnets"));
		let split = render(&status(State::Off), &Applied {kill_switch: true, ..off}, 0);
		assert!(split.contains("Kill switch: on for 203.0.113.0/24 only.") && split.contains("All other traffic is not blocked") && !split.contains("Nothing leaves this device"));
	}

	#[test]
	fn a_connection_that_ended_on_its_own_says_the_kill_switch_stays() {
		let kept = platform::Failure {error: anyhow!("the engine stopped on its own"), kept: true};
		let text = kept_message(&kept);
		assert!(text.contains("kill switch is still in force") && text.contains("veilway disconnect"));
		assert!(!kept_message(&platform::Failure {error: anyhow!("no"), kept: false}).contains("kill switch"));
	}

	#[test]
	fn sizes_are_readable() {
		assert_eq!((size(0).as_str(), size(1536).as_str(), size(5 * 1024 * 1024).as_str()), ("0 B", "1.5 KB", "5.0 MB"));
	}
}
