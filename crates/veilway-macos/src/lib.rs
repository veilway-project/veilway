//! The macOS layer of the client: what the platform-free engine (`veilway-engine`) leaves to the operating system, the counterpart of `veilway-linux` and `veilway-windows`.
//!
//! It is a crate of its own because every OS has its own kind of this layer (netlink and nftables on Linux, Wintun and the Windows Filtering Platform on Windows, a utun, the routing socket and pf here), and the `unsafe` calls into the system should sit in a crate that says what it is. The engine keeps `#![forbid(unsafe_code)]`. What is plain data (the plan of the routes, the messages of the routing socket, the pf rules, the resolver script, the interface calls, the vault's format, the folder checks) compiles and is tested on every system; what calls macOS is behind `cfg(target_os = "macos")`.
//!
//! What `run` does, in this order. (1) The kill switch goes in first, so that from the moment the user asks to connect nothing leaves but this program's own connections to the profile's nodes (`firewall`). (2) The engine starts, with a hook that binds each of its sockets to the physical interface (`sock`, `IP_BOUND_IF`), so there is no host route for the node (gap G12). (3) A utun is made and gets the profile's addresses and MTU with `ifconfig` (`tun`). (4) The kill switch is installed again with the interface's name, which lets what leaves by it out, and then the routes go in through the routing socket: the default routes in halves, both families (`routes`, `rtsock`). (5) The resolver entry of the dynamic store is pointed at the tunnel's gateways (`dns`). (6) Packets are carried between the interface and the engine, the engine is told when the device's networks change (`watch`, `networks`), and the MTU follows the engine's.
//!
//! **It fails closed.** The pf rules and the resolver entry are removed on one path only: a stop the user asked for, which is `stop` completing in `run`, or `cleanup`, which `veilway disconnect` runs. Every other end, a panic of the engine, an error of the interface, a setup step that failed, a tunnel that did not start because the user has still to say something, leaves them in force, and the `Failure` says so (invariant 24). Nothing is removed in a `Drop`, and a process that dies leaves the same as one that returns an error. The utun and its routes do go with the process, and the pf rules are what hold the traffic then. A client that runs with `kill_switch` off says so in its status and leaves only the block on port 53.
//!
//! **What is not tested.** This layer was written without a Mac. It is compile-checked on Linux (`cargo check --target aarch64-apple-darwin`, with zig as the C compiler for `ring`), which covers the code behind `cfg(target_os = "macos")` for types and names; nothing has run, and the pure parts (everything the tests above name) are what the unit tests run on Linux. The macOS runner of GitHub Actions and a real Mac are still to show: the utun (the control socket, the four-byte header, `ifconfig` with a point-to-point address), the routes (that an interface route with a link-level gateway is accepted as `route -interface` makes it, that `RTM_GET` for `0/0` answers with the primary default route and its interface, the byte layout of the messages), `IP_BOUND_IF` (that a socket bound to the physical interface is never caught by the halves), every pf rule (that `pfctl` takes the syntax, that the rules of the other anchors under `com.apple` come before ours and let nothing through that ours would block, that `quick` rules of ours decide, `no state` for DHCP, that the first install's flush of states cuts the connections that were open), `pfctl -E` and its token (the output the parser reads), the resolver entry (that `mDNSResponder` makes the match-all supplemental resolver of it the first, that `scutil` takes the empty string, that scoped queries do not go around it), the system keychain (that root can add and read the item without a prompt, what happens when the binary is replaced by a build with another signature), the folder checks on `/var/run` and `/Library/Application Support`, the routing socket's change messages, and the other traffic of macOS with the kill switch on (Apple services, captive portal detection, AirDrop, Handoff).
//!
//! **Xray (legacy profiles, `xray.rs`, `run_xray`).** The carrier is the engine's userspace stack in front of Xray's SOCKS5 inbound, and everything above is the same. Xray runs as the account `_veilwayxray`, made by `dscl` (the spec leaves open whether to use `nobody`; a dedicated account is the more conservative choice). Its socket stays out of the tunnel with `sockopt.interface` in the document, the name of the interface `IP_BOUND_IF` binds the engine's sockets to, and the supervisor restarts it when that name changes. The kill switch lets only that account's connection to the server out, by address, port, protocol and `user` (`firewall::Rules::xray`). The SOCKS port and the UDP relay are checked to belong to Xray's process through `libproc`. Not tested on a Mac: the offsets of `socket_fdinfo` that `xray::socket_from` reads (checked against the header from memory, with the total of 792 bytes as the cross-check), that `dscl` takes the steps of `xray::account_steps`, that pf takes `user` with `keep state (if-bound)` and matches the connection of a socket bound with `IP_BOUND_IF`, that a root-owned folder mode 755 under `/Library/Application Support` is enough for the account to execute the add-on, and the monitor process that kills Xray when the helper ends (`veilway-xray/src/lib.rs`).
//!
//! **Known limits.** The pf rules do not survive a reboot. A connection with the kill switch on leaves a marker (the tunnel-less ruleset) and a LaunchDaemon, installed at the first connect, runs `veilway restore` at boot to load it (`persist`); both go only with a clean stop or `cleanup`. The daemon races the system's own pf setup at boot, which nothing here has seen, and it names the program only if the program and its folders are root's. Another program that disables pf or flushes the anchor is noticed within ten seconds or at the next change of the networks, and the rules and pf are put back (`firewall::verify`). The client cannot tell its own transport socket from another root process's, so the rule for the nodes is by address, port and protocol, as on the other systems without a mark. `allow_lan` lets the LAN's ranges out only; the routes of a full tunnel do not take the physical link's on-link subnets into the tunnel, so with the kill switch off the LAN stays reachable. Inbound is blocked on every interface that is not the tunnel, except DHCP, neighbor discovery and, with local names, the LAN's answers to mDNS, LLMNR and NetBIOS. The caches of `mDNSResponder` are not flushed.
// What touches files, owners and modes, or runs the system's programs, is Unix only (the workspace builds this crate on Windows too, where only the plain data below compiles and is tested).
#[cfg(unix)]
pub mod dns;
#[cfg(unix)]
pub mod firewall;
pub mod networks;
#[cfg(unix)]
pub mod persist;
pub mod routes;
pub mod rtsock;
#[cfg(unix)]
pub mod state;
pub mod tun;
pub mod vault;
#[cfg(unix)]
pub mod xray;
#[cfg(target_os = "macos")]
mod run;
#[cfg(target_os = "macos")]
pub mod sock;
#[cfg(target_os = "macos")]
mod watch;

#[cfg(target_os = "macos")]
pub use routes::Routes;
#[cfg(target_os = "macos")]
pub use run::{cleanup, restore, run, run_xray, Applied, Cleaned, Failure, Options, Stop, XrayRun};
