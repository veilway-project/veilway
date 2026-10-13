//! The `l3` exit: a TUN device the kernel forwards from, so every IP protocol passes. Linux only, and the one place where the node needs a privilege (`CAP_NET_ADMIN`).
//! The device is made with one ioctl. Everything else on the host is done by running `ip` and `nft` with fixed argument lists, which is far less code than speaking netlink and leaves rules an operator can read with those same tools.
use super::Shared;
use ipnet::IpNet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

/// How long a flow through an l3 exit is kept after its last packet once the other side has answered. No handler sees such a flow end, so its own packets decide, see `Flows::track`.
pub const TCP_IDLE: Duration = Duration::from_secs(7200);
pub const UDP_IDLE: Duration = Duration::from_secs(60);

/// The way into the interface of an l3 exit, and the largest packet it takes.
#[derive(Clone)]
pub struct Port {pub to: Sender<Vec<u8>>, pub mtu: u16}

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
	pub fn start(_shared: &Arc<Shared>, wanted: &Wanted, _from_tunnels: Queue) -> anyhow::Result<Running> {
		anyhow::bail!("exit `{}` has an l3 backend, which needs Linux: remove that exit and everything that names it, or run the node on Linux", wanted.tag)
	}

	pub async fn close(self) {}
}

#[cfg(target_os = "linux")]
pub use linux::Running;

#[cfg(target_os = "linux")]
mod linux {
	use super::*;
	use anyhow::{anyhow, bail, ensure, Context};
	use std::fs::{self, File, OpenOptions};
	use std::io::{self, Read, Write};
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::OpenOptionsExt;
	use std::process::{Command, Stdio};
	use tokio::io::unix::AsyncFd;
	use tokio::io::Interest;
	use tokio::task::JoinHandle;

	const FORWARD_V4: &str = "/proc/sys/net/ipv4/ip_forward";
	const FORWARD_V6: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

	/// A running l3 exit: the tasks that hold its device open, and what was changed on the host for it.
	pub struct Running {tasks: Vec<JoinHandle<()>>, undo: Undo}

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

	impl Running {
		/// Creates the interface an l3 exit wants with its MTU, routes every inbound pool to it, keeps what comes in on it away from the host itself and, with `masquerade`, turns forwarding on and adds source NAT for what leaves through other interfaces.
		/// Packets from `from_tunnels` are written to the interface, and what the kernel routes into it goes to `Shared::returned` for the exit that is the l3 exit of the plan in force. Nothing stays behind on the host when this fails.
		pub fn start(shared: &Arc<Shared>, wanted: &Wanted, from_tunnels: Queue) -> anyhow::Result<Running> {
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
				let (shared, tun, tag) = (shared.clone(), tun.clone(), tag.clone());
				async move {
					let mut buf = vec![0u8; 65535];
					loop {
						match tun.async_io(Interest::READABLE, |file: &File| (&*file).read(&mut buf)).await {
							Ok(n) => {
								let plan = shared.plan();
								if let Some((exit, _)) = &plan.l3 {shared.returned(&plan, *exit, buf[..n].to_vec()).await}
							}
							Err(e) => return tracing::error!("exit {tag}: reading the interface failed, the exit carries nothing from here on: {}", e.kind()),
						}
					}
				}
			});
			let writer = tokio::spawn(async move {
				let mut from_tunnels = from_tunnels.lock().await;
				while let Some(packet) = from_tunnels.recv().await {
					// The kernel takes a packet or refuses it at once, and a refused packet is lost like on any full queue.
					if let Err(e) = tun.async_io(Interest::WRITABLE, |file: &File| (&*file).write(&packet)).await {tracing::debug!("exit {tag}: the interface refused a {} byte packet: {}", packet.len(), e.kind())}
				}
			});
			Ok(Running {tasks: vec![reader, writer], undo})
		}

		/// Stops the exit and takes back what `start` changed, which is left to `Drop`. The interface goes when its last handle closes, and its routes go with it.
		pub async fn close(mut self) {
			for task in &self.tasks {task.abort()}
			for task in std::mem::take(&mut self.tasks) {let _ = task.await;}
		}
	}

	/// An exit that goes without `close`, because the engine was dropped or the process unwinds, still takes back what it changed. Nothing can do that for a process that is killed.
	impl Drop for Running {
		fn drop(&mut self) {
			for task in &self.tasks {task.abort()}
			self.undo.run()
		}
	}
}
