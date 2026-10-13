//! The `l3` exit: a TUN device the kernel forwards from, so every IP protocol passes. Linux only, and the one place where the node needs a privilege (`CAP_NET_ADMIN`).
//! The device is made with one ioctl. Everything else on the host is done by running `ip` and `nft` with fixed argument lists, which is far less code than speaking netlink and leaves rules an operator can read with those same tools.
use super::Shared;
use ipnet::IpNet;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

/// How long a flow through an l3 exit is kept after its last packet once the other side has answered. No handler sees such a flow end, so its own packets decide, see `Flows::track`.
pub const TCP_IDLE: Duration = Duration::from_secs(7200);
pub const UDP_IDLE: Duration = Duration::from_secs(60);

/// How long after an l3 exit went down the node first tries to bring its interface up again. Every try that fails doubles the wait, up to `RETRY_CAP`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RETRY_FIRST: Duration = Duration::from_secs(2);
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const RETRY_CAP: Duration = Duration::from_secs(60);

/// Whether the interface of an l3 exit is there. It travels with the `Port`, so every plan that writes to the queue of the exit reads the same.
#[derive(Default)]
pub struct Health {
	/// Since when the interface is down. None while it is up. While it is set, what is routed to the exit is answered as unreachable, see `Shared::carry`.
	pub down: std::sync::Mutex<Option<Instant>>,
	/// Switches between up and down, in either direction.
	pub flips: AtomicU64,
}

/// The way into the interface of an l3 exit, the largest packet it takes, and whether the interface is there.
#[derive(Clone)]
pub struct Port {pub to: Sender<Vec<u8>>, pub mtu: u16, pub health: Arc<Health>}

/// What an l3 exit asks of the host: the exit's tag, its interface, the networks routed to it (every inbound pool, in ascending order) and its MTU (the smallest of all inbounds).
/// Two that are equal are one interface set up one way, which a reload leaves running.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wanted {pub tag: String, pub interface: String, pub masquerade: bool, pub pools: Vec<IpNet>, pub mtu: u16}

/// The packets on their way into the interface. It outlives the interface, so one that had to be closed for a reload that then failed is brought back on the queue the running config still writes to.
pub type Queue = Arc<Mutex<Receiver<Vec<u8>>>>;

#[cfg(not(target_os = "linux"))]
pub struct Running;

#[cfg(not(target_os = "linux"))]
impl Running {
	pub fn start(_shared: &Arc<Shared>, wanted: &Wanted, _from_tunnels: Queue, _health: Arc<Health>, _keep_trying: bool) -> anyhow::Result<Running> {
		anyhow::bail!("exit `{}` has an l3 backend, which needs Linux: remove that exit and everything that names it, or run the node on Linux", wanted.tag)
	}

	pub fn retry_now(&self) {}

	pub async fn close(self) {}
}

#[cfg(target_os = "linux")]
pub use linux::{survey, Running, Survey};

#[cfg(target_os = "linux")]
mod linux {
	use super::*;
	use anyhow::{anyhow, bail, ensure, Context};
	use std::fs::{self, File, OpenOptions};
	use std::io::{self, Read, Write};
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
	use std::path::Path;
	use std::process::{Command, Stdio};
	use std::sync::atomic::Ordering;
	use tokio::io::unix::AsyncFd;
	use tokio::io::Interest;
	use tokio::sync::{mpsc, Notify};
	use tokio::task::JoinHandle;

	const FORWARD_V4: &str = "/proc/sys/net/ipv4/ip_forward";
	const FORWARD_V6: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

	/// An l3 exit as the node holds it: its interface while that is up, and the keeper, the task that waits for the interface to fail and then brings it up again for as long as this lives.
	pub struct Running {device: Arc<std::sync::Mutex<Option<Device>>>, keeper: JoinHandle<()>, again: Arc<Notify>}

	/// An interface that is up: the tasks that hold its device open, and what was changed on the host for it. Dropping it takes all of that back, wherever it is dropped.
	struct Device {tasks: Vec<JoinHandle<()>>, undo: Undo}

	impl Drop for Device {
		fn drop(&mut self) {
			for task in &self.tasks {task.abort()}
			self.undo.run()
		}
	}

	/// What `start` changed on the host that does not go away with the device: the nftables table, and each sysctl with the value it had.
	#[derive(Default)]
	struct Undo {table: Option<String>, sysctls: Vec<(&'static str, String)>}

	impl Undo {
		fn run(&self) {
			if let Some(table) = &self.table {
				if let Err(e) = run("nft", &["delete", "table", "inet", table], None) {tracing::warn!("cannot remove the nftables table {table}: {e:#}")}
			}
			for (path, before) in &self.sysctls {
				if let Err(e) = fs::write(path, before) {tracing::warn!("cannot set {path} back to {before}: {}", e.kind())}
			}
		}
	}

	/// Runs a fixed program with an argument list, never through a shell. `input` goes to its standard input.
	fn run(program: &str, args: &[&str], input: Option<&str>) -> anyhow::Result<()> {
		let mut child = Command::new(program).args(args).stdin(if input.is_some() {Stdio::piped()} else {Stdio::null()}).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| anyhow!("cannot run `{program}` ({}): the l3 backend needs iproute2 and nftables on this host", e.kind()))?;
		if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {stdin.write_all(input.as_bytes())?}
		let output = child.wait_with_output()?;
		// The command is shown without its networks and numbers, which are values of the config. Its place in the config is clear from the exit the error is reported for.
		ensure!(output.status.success(), "`{program} {}` failed: {}", args.iter().filter(|arg| arg.parse::<IpNet>().is_err() && arg.parse::<u32>().is_err()).copied().collect::<Vec<_>>().join(" "), String::from_utf8_lossy(&output.stderr).trim());
		Ok(())
	}

	/// What `Running::start` needs of the host, as the host stands right now.
	#[derive(Clone, Debug, PartialEq, Eq)]
	pub struct Survey {
		/// Whether this process holds `CAP_NET_ADMIN`. None when the kernel does not say.
		pub net_admin: Option<bool>,
		/// Why `/dev/net/tun` cannot be opened, when it cannot.
		pub tun: Result<(), io::ErrorKind>,
		/// Whether `ip` and `nft` are programs on the `PATH`.
		pub ip: bool,
		pub nft: bool,
		/// For IPv4 and then IPv6: whether the host forwards, and whether this process may change that. None when the switch cannot be read.
		pub forwarding: [Option<(bool, bool)>; 2],
		/// Whether an interface of the name already exists.
		pub taken: bool,
	}

	/// Looks at everything `Running::start` would use or change for an interface named `interface`, and changes none of it: a device file opened without the request that makes an interface makes none, and a switch opened for writing and never written keeps its value.
	pub fn survey(interface: &str) -> Survey {
		let found = |program: &str| std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| fs::metadata(dir.join(program)).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)));
		Survey {
			// `CAP_NET_ADMIN` is bit 12 of the effective set.
			net_admin: fs::read_to_string("/proc/self/status").ok().and_then(|status| status.lines().find_map(|line| line.strip_prefix("CapEff:")).and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())).map(|held| held & 1 << 12 != 0),
			tun: OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open("/dev/net/tun").map(drop).map_err(|e| e.kind()),
			ip: found("ip"),
			nft: found("nft"),
			forwarding: [FORWARD_V4, FORWARD_V6].map(|path| fs::read_to_string(path).ok().map(|value| (value.trim() == "1", OpenOptions::new().write(true).open(path).is_ok()))),
			taken: Path::new("/sys/class/net").join(interface).exists(),
		}
	}

	/// Creates the interface an l3 exit wants with its MTU, routes every inbound pool to it, keeps what comes in on it away from the host itself and, with `masquerade`, turns forwarding on and adds source NAT for what leaves through other interfaces.
	/// Packets from `from_tunnels` are written to the interface, and what the kernel routes into it goes to `Shared::returned` for the exit that is the l3 exit of the plan in force. Nothing stays behind on the host when this fails.
	/// `dead` is told once when the interface can no longer be read, which is what an interface that was removed under the node looks like.
	fn up(shared: &Arc<Shared>, wanted: &Wanted, from_tunnels: &Queue, dead: &mpsc::Sender<io::ErrorKind>) -> anyhow::Result<Device> {
		let Wanted {tag, interface, masquerade, pools, mtu} = wanted;
		let tag = tag.clone();
		// Validation allows only these in a name. It is checked again here because the name goes into a kernel request and an nftables rule.
		ensure!((1..=15).contains(&interface.len()) && interface.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'), "exit `{tag}`: the interface name was not validated");
		let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open("/dev/net/tun").map_err(|e| anyhow!("exit `{tag}`: cannot open /dev/net/tun ({e}): the l3 backend needs the tun driver, and inside a container the device has to be passed in"))?;
		// `struct ifreq`: the name in 16 bytes with its NUL, then the flags as a short.
		let mut request = [0u8; 40];
		request[..interface.len()].copy_from_slice(interface.as_bytes());
		request[16..18].copy_from_slice(&((libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short).to_ne_bytes());
		// SAFETY: TUNSETIFF reads and writes one `struct ifreq`, which is 40 bytes on 64-bit Linux and 32 on 32-bit. `request` is 40 bytes, writable, and outlives the call, and the descriptor is open.
		if unsafe {libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, request.as_mut_ptr())} < 0 {
			let e = io::Error::last_os_error();
			bail!("exit `{tag}`: cannot create the interface `{interface}`: {}", if e.kind() == io::ErrorKind::PermissionDenied {"the node needs CAP_NET_ADMIN for an l3 exit".to_string()} else {format!("{e}; is the name taken by another interface?")});
		}
		let mut undo = Undo::default();
		let setup = (|| -> anyhow::Result<()> {
			run("ip", &["link", "set", "dev", interface, "mtu", &mtu.to_string(), "up"], None)?;
			for pool in pools {run("ip", &[if pool.addr().is_ipv4() {"-4"} else {"-6"}, "route", "add", &pool.to_string(), "dev", interface], None)?}
			// The kernel forwards IPv4 by the interface a packet came in on and IPv6 by one switch for the host. Answers come in on any interface, so both are host-wide here.
			for path in [FORWARD_V4, FORWARD_V6] {
				if !masquerade || !pools.iter().any(|pool| pool.addr().is_ipv4() == (path == FORWARD_V4)) {continue}
				let before = fs::read_to_string(path).with_context(|| format!("cannot read {path}"))?;
				if before.trim() == "1" {continue}
				fs::write(path, "1").map_err(|e| anyhow!("{path} is off and cannot be turned on from here ({}): turn it on for the host, or for the container with --sysctl", e.kind()))?;
				undo.sysctls.push((path, before.trim().to_string()));
				tracing::info!("exit {tag}: turned {path} on for the whole host; it is set back when the node stops, and stays on if the node is killed{}", if path == FORWARD_V6 {" (a host that takes its own IPv6 route from router advertisements needs accept_ra=2 while it forwards)"} else {""});
			}
			// The first two lines remove what a node that was killed left behind. Nothing a device sends may reach the host itself or come back out of the interface, with or without `masquerade`:
			// the engine refuses both, but it knows only the host's own unicast addresses, and the kernel also takes the broadcast address of each of its networks and the IPv6 anycast address of each prefix it routes for its own.
			let table = format!("veilway_{interface}");
			let nat = if *masquerade {format!("\tchain postrouting {{\n\t\ttype nat hook postrouting priority 100; policy accept;\n\t\tiifname \"{interface}\" oifname != \"{interface}\" masquerade\n\t}}\n")} else {String::new()};
			let rules = format!("add table inet {table}\ndelete table inet {table}\ntable inet {table} {{\n\tchain input {{\n\t\ttype filter hook input priority 0; policy accept;\n\t\tiifname \"{interface}\" drop\n\t}}\n\tchain forward {{\n\t\ttype filter hook forward priority 0; policy accept;\n\t\tiifname \"{interface}\" oifname \"{interface}\" drop\n\t}}\n{nat}}}\n");
			run("nft", &["-f", "-"], Some(&rules))?;
			undo.table = Some(table);
			Ok(())
		})();
		let tun = match setup.and_then(|_| AsyncFd::new(file).context("cannot watch the interface")) {
			Ok(tun) => Arc::new(tun),
			Err(e) => {
				undo.run();
				return Err(e.context(format!("exit `{tag}`: cannot set up the interface `{interface}`")));
			}
		};
		tracing::info!("exit {tag}: l3 on interface {interface}, mtu {mtu}, {}", if *masquerade {"forwarding and source NAT set up by the node"} else {"forwarding and NAT left to the operator, the node's table only keeps the tunnel away from the host itself"});
		let reader = tokio::spawn({
			let (shared, tun, dead) = (shared.clone(), tun.clone(), dead.clone());
			async move {
				let mut buf = vec![0u8; 65535];
				loop {
					// An interface that is gone is an error on its descriptor and nothing to read, so the error is waited for as well.
					match tun.async_io(Interest::READABLE | Interest::ERROR, |file: &File| (&*file).read(&mut buf)).await {
						Ok(n) => {
							let plan = shared.plan();
							if let Some((exit, _)) = &plan.l3 {shared.returned(&plan, *exit, buf[..n].to_vec()).await}
						}
						Err(e) => return dead.try_send(e.kind()).unwrap_or(()),
					}
				}
			}
		});
		let (from_tunnels, tag) = (from_tunnels.clone(), tag.clone());
		let writer = tokio::spawn(async move {
			let mut from_tunnels = from_tunnels.lock().await;
			while let Some(packet) = from_tunnels.recv().await {
				// The kernel takes a packet or refuses it at once, and a refused packet is lost like on any full queue.
				if let Err(e) = tun.async_io(Interest::WRITABLE, |file: &File| (&*file).write(&packet)).await {tracing::debug!("exit {tag}: the interface refused a {} byte packet: {}", packet.len(), e.kind())}
			}
		});
		Ok(Device {tasks: vec![reader, writer], undo})
	}

	impl Running {
		/// Brings the interface of an l3 exit up, see `up`, and keeps it: when it fails later the exit goes down, which `health` says, and the keeper tries to bring it up again after `RETRY_FIRST` and then after twice the wait each time, `RETRY_CAP` at most, until it is up or this is closed or dropped.
		/// A first try that fails is the error when `keep_trying` is false, and nothing is left behind. With `keep_trying` it is where the exit goes down, and this never fails.
		pub fn start(shared: &Arc<Shared>, wanted: &Wanted, from_tunnels: Queue, health: Arc<Health>, keep_trying: bool) -> anyhow::Result<Running> {
			let ((dead, mut died), again) = (mpsc::channel(1), Arc::new(Notify::new()));
			let (device, mut failed) = match up(shared, wanted, &from_tunnels, &dead) {
				Ok(device) => (Arc::new(std::sync::Mutex::new(Some(device))), None),
				Err(e) if keep_trying => (Arc::default(), Some(e)),
				Err(e) => return Err(e),
			};
			let keeper = tokio::spawn({
				let (shared, wanted, device, again) = (shared.clone(), wanted.clone(), device.clone(), again.clone());
				async move {
					loop {
						let why = match failed.take() {
							Some(why) => why,
							None => {
								let Some(kind) = died.recv().await else {return};
								let gone = device.lock().unwrap_or_else(|e| e.into_inner()).take();
								// Its tasks are waited for, so the descriptor is closed and the name is free before the first try. What it changed on the host goes as it is dropped.
								if let Some(mut gone) = gone {
									for task in &gone.tasks {task.abort()}
									for task in std::mem::take(&mut gone.tasks) {let _ = task.await;}
								}
								anyhow!("reading the interface `{}` failed ({kind}): it was removed, or its driver gave up", wanted.interface)
							}
						};
						{
							// An exit that was down already when a reload closed it and brought it back has been down since then, not since now.
							let mut down = health.down.lock().unwrap_or_else(|e| e.into_inner());
							if down.is_none() {
								*down = Some(Instant::now());
								health.flips.fetch_add(1, Ordering::Relaxed);
							}
						}
						tracing::warn!("exit {}: down, what is routed to it is answered as unreachable and the node tries again in {}s: {why:#}", wanted.tag, RETRY_FIRST.as_secs());
						let (mut wait, mut tries) = (RETRY_FIRST, 0u32);
						loop {
							tokio::select! {
								_ = tokio::time::sleep(wait) => {}
								_ = again.notified() => wait = RETRY_FIRST,
							}
							tries += 1;
							match up(&shared, &wanted, &from_tunnels, &dead) {
								Ok(up) => {
									*device.lock().unwrap_or_else(|e| e.into_inner()) = Some(up);
									let since = health.down.lock().unwrap_or_else(|e| e.into_inner()).take();
									health.flips.fetch_add(1, Ordering::Relaxed);
									tracing::info!("exit {}: up again after {}s down and {tries} tries", wanted.tag, since.map_or(0, |since| since.elapsed().as_secs()));
									break;
								}
								Err(e) => {
									wait = (wait * 2).min(RETRY_CAP);
									tracing::warn!("exit {}: still down, try {tries} failed and the next is in {}s: {e:#}", wanted.tag, wait.as_secs());
								}
							}
						}
					}
				}
			});
			Ok(Running {device, keeper, again})
		}

		/// Has an exit that is down try now, and start its waits over. It is kept for a keeper that is in the middle of a try, so it is only for an exit that is down.
		pub fn retry_now(&self) {self.again.notify_one()}

		/// Stops the exit and takes back what it changed on the host, whether its interface is up or a try to bring it up is under way: the keeper ends first, so nothing comes up behind this.
		/// The interface goes when its last handle closes, and its routes go with it.
		pub async fn close(mut self) {
			self.keeper.abort();
			let _ = (&mut self.keeper).await;
			let device = self.device.lock().unwrap_or_else(|e| e.into_inner()).take();
			if let Some(mut device) = device {
				for task in &device.tasks {task.abort()}
				for task in std::mem::take(&mut device.tasks) {let _ = task.await;}
			}
		}
	}

	/// An exit that goes without `close`, because the engine was dropped or the process unwinds, still takes back what it changed. Nothing can do that for a process that is killed.
	/// A keeper that is in the middle of a try holds the device it makes, and drops it as it ends.
	impl Drop for Running {
		fn drop(&mut self) {
			self.keeper.abort();
			self.device.lock().unwrap_or_else(|e| e.into_inner()).take();
		}
	}
}
