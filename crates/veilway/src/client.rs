//! `veilway connect`, `disconnect` and `status`: the client on Linux, macOS and Windows, driven from a terminal until an app does it. The engine and the platform layer are the libraries `veilway-engine` and `veilway-linux`, `veilway-macos` or `veilway-windows` (all are `platform` here, and answer to the same calls); what is here is the questions put to the user and the words the state is shown in.
use anyhow::{anyhow, bail, Context};
use clap::Args;
use ipnet::IpNet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::signal::unix::{signal, Signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_logoff, ctrl_shutdown, CtrlBreak, CtrlC, CtrlClose, CtrlLogoff, CtrlShutdown};
use veilway_engine::import::{self, Fetcher, Library};
use veilway_engine::{ask_text, default_roots, Agree, Check, Retry, Settings, StartError, State, Status, Store};
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
use veilway_proto::subscription::client::{Offer, Standing};
use veilway_proto::subscription::payload::Id;
use veilway_proto::subscription::Tag;

#[derive(Args)]
pub struct Connect {
	/// A link or a subscription file to import first. Without it the subscription already imported is used
	source: Option<String>,
	/// Which subscription, when more than one is held: the start of its id
	#[arg(long)] subscription: Option<String>,
	/// Which connection of the subscription, when it has more than one
	#[arg(long)] profile: Option<String>,
	/// Send only this network through the tunnel (and the tunnel's own gateway), and let the rest leave as it always did. Repeat for more. Without it everything goes through the tunnel
	#[arg(long = "route")] routes: Vec<IpNet>,
	/// Let programs reach devices on the networks this device is connected to (a printer, the router) outside the tunnel: only the private subnets it is on, not the whole private ranges. The network can see that traffic. Without it the local network goes through the tunnel. Names are still only asked through the tunnel
	#[arg(long)] allow_lan: bool,
	/// With --allow-lan: also let mDNS and LLMNR out, so that names on the local network resolve. They tell the network which names this device asks for
	#[arg(long, requires = "allow_lan")] local_names: bool,
	/// Do not block what is not tunnelled when the tunnel is down or reconnecting
	#[arg(long)] no_kill_switch: bool,
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
		let parts = [Some(format!("{}{}", found.address, found.host.as_ref().map_or_else(String::new, |host| format!(" ({host})")))), Some(found.transport.to_owned()), found.front.as_ref().map(|front| format!("front {front}")), found.server_name.as_ref().map(|name| format!("server name {name}")), check.map(str::to_owned), found.since.map(|since| format!("up {} s", now.saturating_sub(since)))];
		lines.push(format!("Server: {}.", parts.into_iter().flatten().collect::<Vec<_>>().join(", ")));
	}
	let counters = status.counters;
	lines.push(format!("Traffic: {} sent, {} received.", size(counters.bytes_sent), size(counters.bytes_received)));
	if let Some(usage) = status.usage {lines.push(if usage.quota_bytes == 0 {format!("Usage: {} used, no limit.", size(usage.used_bytes))} else {format!("Usage: {} of {} used.", size(usage.used_bytes), size(usage.quota_bytes))})}
	if !status.exits.is_empty() {lines.push(format!("Exits: {}.", status.exits.iter().map(|exit| format!("{}{}", exit.name, if exit.selected || (exit.configured && !status.exits.iter().any(|other| other.selected)) {" (in use)"} else {""})).collect::<Vec<_>>().join(", ")))}
	for notice in &status.notices {lines.push(format!("From the provider: {}", notice.text))}
	if status.out_of_date {lines.push("This connection's settings are out of date. Refresh the subscription.".into())}
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

pub async fn connect(args: Connect) -> anyhow::Result<()> {
	tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))).with_writer(std::io::stderr).init();
	let (data, run) = (data_dir(args.data_dir.clone())?, Options::default().run_dir);
	let mut signals = Signals::new()?;
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
	let permit = match held.connect(now()) {
		Ok(permit) => permit,
		Err(stale) => if ask("This subscription expired more than 30 days ago, and the addresses and keys in it may no longer belong to the provider. Connect anyway?", &mut signals).await? {stale.confirmed()} else {bail!("Not connected.")},
	};
	let store = Arc::new(Store::open(data.join("client.json")));
	let mut settings = Settings::new(store.clone(), Arc::new(now), default_roots(), String::new());
	settings.languages = languages();
	let options = Options {interface: args.interface, kill_switch: !args.no_kill_switch, allow_lan: args.allow_lan, local_names: args.local_names, routes: if args.routes.is_empty() {Routes::Full} else {Routes::Split(args.routes)}, run_dir: run.clone(), ..Options::default()};
	// The one lock every command takes, held from here to the end, also while the user is asked something: nothing else changes what is in force meanwhile.
	let lock = state::lock(&run).await?;
	let (key, mut agree) = (veilway_engine::store::profile_key(held.id().as_str(), &profile.id), Agree::default());
	loop {
		let mut shown = String::new();
		let on_status = |status: &Status, applied: &Applied| {
			let at = now();
			if let Err(error) = state::write_status(&run, &render(status, applied, at)) {tracing::warn!(%error, "the status could not be written")}
			// A wait counts down, and a line is printed when the state changes and not at every second of the count.
			let key = state_line(status, 0);
			if key != shown {
				println!("{}: {}", status.name, state_line(status, at));
				shown = key;
			}
		};
		#[cfg(unix)]
		let stop = signals.next();
		#[cfg(windows)]
		let stop = async {tokio::select! {reason = signals.next() => reason, () = lock.stop_asked() => Stop::Asked}};
		let outcome = platform::run(&options, &lock, settings.clone(), held, &profile.id, &permit, agree, on_status, stop).await;
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
			Some(_) | None => bail!(kept_message(&failure)),
		};
		// The terminal going away is not an answer: nobody is there, and the kill switch stays like after any other end.
		if answer.as_ref().err().is_some_and(|error| error.downcast_ref::<HangUp>().is_some()) {bail!(kept_message(&platform::Failure {error: anyhow!("the terminal went away (SIGHUP)"), kept: true}))}
		if !matches!(answer, Ok(true)) {
			let cleaned = platform::cleanup(&options, &lock);
			let _ = store.flush();
			cleaned?;
			bail!(answer.err().map_or_else(|| "Not connected.".to_owned(), |error| error.to_string()));
		}
	}
	eprintln!("Disconnected. Everything is back as it was.");
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
	use veilway_engine::{Counters, Say, Stop};

	fn status(state: State) -> Status {Status {state, name: "Home".into(), say: None, exits: Vec::new(), usage: None, notices: Vec::new(), mtu: 1390, control: false, out_of_date: false, counters: Counters::default(), connection: None}}

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
	fn the_server_line_gives_the_candidate_in_use_and_no_secret() {
		let mut found = status(State::Connected {exit: None});
		found.connection = Some(veilway_engine::Connection {transport: "fronted", address: "192.0.2.7:443".parse().unwrap(), host: None, front: Some("cdn.example".into()), server_name: Some("cdn.example".into()), check: Some(Check::Public), since: Some(40)});
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
