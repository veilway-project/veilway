//! The Windows layer of the client: what the platform-free engine (`veilway-engine`) leaves to the operating system, the counterpart of `veilway-linux`.
//!
//! It is a crate of its own because every OS has its own kind of this layer (TUN and netlink on Linux, Wintun, the IP Helper API and the Windows Filtering Platform here), and the `unsafe` calls into the system should sit in a crate that says what it is. The engine keeps `#![forbid(unsafe_code)]`. What is plain data (the plan of the routes, the filters of the kill switch, the networks' rule, the scripts of the name policy, the vault's format) compiles and is tested on every system; what calls Windows is behind `cfg(windows)`.
//!
//! What `run` does, in this order. (1) The kill switch goes in first, so that from the moment the user asks to connect nothing leaves but this program's own connections to the profile's nodes. (2) The engine starts, with a hook that binds each of its sockets to the physical interface (`sock`), so there is no host route for the node (gap G12). (3) The Wintun adapter gets the profile's addresses, MTU and metric. (4) The kill switch is installed again with the adapter's LUID, which lets what leaves by the adapter out, and then the routes go in: the default routes in halves, both families (`routes`). (5) The name resolution policy and the adapter's DNS are pointed at the tunnel's gateways (`dns`). (6) Packets are carried between the adapter and the engine, the engine is told when the device's networks change (`watch`, `networks`), and the MTU follows the engine's.
//!
//! **It fails closed.** The kill switch (persistent filters of the Windows Filtering Platform) and the resolver rule are removed on one path only: a stop the user asked for, which is `stop` completing in `run`, or `cleanup`, which `veilway disconnect` runs. Every other end, a panic of the engine, an error of the adapter, a setup step that failed, a tunnel that did not start because the user has still to say something, leaves them in force, and the `Failure` says so (invariant 24). Nothing is removed in a `Drop`, and a process that dies leaves the same as one that returns an error. The adapter and its routes do go with the process, and the filters are what hold the traffic then. A client that runs with `kill_switch` off says so in its status and leaves nothing in force.
//!
//! **Xray (legacy profiles, `xray.rs`, `run_xray`).** The carrier is the engine's userspace stack in front of Xray's SOCKS5 inbound, and everything above is the same. Xray is started by `xray::Child::spawn` with a restricted token (the Administrators switched to deny-only, no privilege) in a job object that allows one process and kills it when the helper's handle closes; no account is made (the spec's choice). Its socket stays out of the tunnel with `sockopt.interface` in the document, the friendly name of the adapter `IP_UNICAST_IF` binds the engine's sockets to, and the supervisor restarts it when that name changes. The kill switch lets the executable of Xray reach the server by address, port and protocol (`Cond::Program`, `firewall::Rules::xray`). The SOCKS port and the UDP relay are checked to belong to Xray's process through `GetExtendedTcpTable` and `GetExtendedUdpTable`. Not tested on Windows: all of `xray::Child::spawn` (that `CreateProcessAsUserW` takes a restricted copy of the process's own token with only `SeIncreaseQuotaPrivilege` switched on, that the handle list keeps everything else out, that a job of one process takes the suspended child, that the add-ons folder's read right for users is enough for a token without the Administrators to run `xray.exe`), that a WFP application id of the add-on's path matches its connections, that the tables are read as laid out, and that Xray's `sockopt.interface` takes the friendly name under the policy of NCSI (the gate on the runner decides).
//!
//! **What is not tested.** This layer was written without a Windows machine and is compile-checked on Linux (`cargo check --target x86_64-pc-windows-gnu`); nothing here has run. The GitHub Actions Windows job and a real machine are still to show: the Wintun load and session, addresses, MTU and metrics, the routes, that the best route of a socket bound with `IP_UNICAST_IF` is the physical one, every WFP filter (that `FWPM_CONDITION_IP_LOCAL_INTERFACE` and the application id match at `ALE_AUTH_CONNECT` as the weights assume, that the filters stay across a reboot and a service restart, DHCP and the LAN), the NRPT rule and `netsh` calls on a real Windows, the change notifications, DPAPI, the ACL of the run directory, the named lock and event, and Windows Update, NCSI and the other Microsoft traffic with the kill switch on. Not built: `allow_lan` lets the LAN's ranges out through the filters only, and the routes of a full tunnel do not take the physical link's on-link subnets into the tunnel as the Linux layer's rules do, so with the kill switch off the LAN stays reachable.
pub mod acl;
pub mod dns;
pub mod firewall;
pub mod networks;
pub mod routes;
pub mod vault;
pub mod xray;
#[cfg(windows)]
pub mod ip;
#[cfg(windows)]
mod run;
#[cfg(windows)]
pub mod sock;
#[cfg(windows)]
pub mod state;
#[cfg(windows)]
pub mod tun;
#[cfg(windows)]
mod watch;

#[cfg(windows)]
pub use routes::Routes;
#[cfg(windows)]
pub use run::{cleanup, run, run_xray, Applied, Cleaned, Failure, Options, Stop, XrayRun};
