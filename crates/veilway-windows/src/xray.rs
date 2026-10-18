//! What Xray needs of Windows ("The binary", "How traffic reaches Xray", "Supervision"): the child with a restricted token in a job object that kills it, the choice of the server's address among the ones its name resolved to, the name of the physical adapter its own socket is kept on, and the look-up of who holds a loopback port.
//!
//! The spec leaves open whether Windows makes an account for Xray. This layer does not: the child runs as the user of the helper with the Administrators group switched to deny-only and every privilege taken away (`CreateRestrictedToken`), which needs no password and no account to look after. That is weaker than a user of its own against a flaw that reads this user's files, and the decision is the spec's. The job object allows one process, so Xray cannot start another, and kills it when the helper's handle to the job closes, which is when the helper ends however it ends. The token's integrity level is not lowered.
//!
//! Xray's socket stays out of the tunnel with `sockopt.interface` in the document, the friendly name of the adapter the engine's sockets are bound to (`IP_UNICAST_IF`). The kill switch lets the executable of Xray, and no other program, reach the server by address, port and protocol (`firewall::Rules::xray`).
use std::net::{IpAddr, SocketAddr};

/// The groups switched to deny-only in the child's token, by SID: the Administrators.
pub const DISABLED_SIDS: [&str; 1] = ["S-1-5-32-544"];

/// A socket of a process, as the tables of the IP Helper list them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {pub ip: IpAddr, pub port: u16, pub pid: u32}

/// The processes of the rows that would be handed a packet for `address`: the port is the same, and the local address is the same, or any address (`0.0.0.0`, `::`), or the IPv4 address written as IPv6.
pub fn holders(rows: &[Row], address: SocketAddr) -> Vec<u32> {
	rows.iter().filter(|row| {
		let ip = match row.ip {IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4), other => other};
		row.port == address.port() && (ip == address.ip() || ip.is_unspecified())
	}).map(|row| row.pid).collect()
}

/// The command line of the child: the program in quotes, as `CreateProcess` wants it when the path has spaces, and the arguments, which are fixed words and need none.
pub fn command_line(program: &str, arguments: &[&str]) -> String {
	std::iter::once(format!("\"{program}\"")).chain(arguments.iter().map(|argument| (*argument).to_owned())).collect::<Vec<_>>().join(" ")
}

#[cfg(windows)]
pub use system::{alias, listening_as, physical, usable, Child};

#[cfg(windows)]
mod system {
	use super::*;
	use std::ffi::c_void;
	use std::io;
	use std::net::{Ipv4Addr, Ipv6Addr};
	use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
	use std::path::Path;
	use std::ptr::{null, null_mut};
	use std::sync::Arc;
	use tokio::fs::File;
	use tokio::sync::watch;
	use veilway_proto::subscription::payload::{dialable, own};
	use windows_sys::Win32::Foundation::{LocalFree, SetHandleInformation, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, HANDLE_FLAG_INHERIT};
	use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID};
	use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
	use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
	use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
	use windows_sys::Win32::Security::{AdjustTokenPrivileges, CreateRestrictedToken, LookupPrivilegeValueW, DISABLE_MAX_PRIVILEGE, LUID_AND_ATTRIBUTES, SECURITY_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY};
	use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
	use windows_sys::Win32::System::Pipes::CreatePipe;
	use windows_sys::Win32::System::Threading::{CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW};

	fn wide(text: &str) -> Vec<u16> {text.encode_utf16().chain(std::iter::once(0)).collect()}

	// A handle that is closed when it is dropped.
	fn owned(handle: HANDLE) -> OwnedHandle {
		// SAFETY: the handle came from a successful call and nothing else closes it.
		unsafe {OwnedHandle::from_raw_handle(handle)}
	}

	/// The addresses of `candidates` that may be dialled: not a form `dialable` refuses, and not inside a network the device is on now. The caller uses the first one.
	pub fn usable(candidates: &[IpAddr]) -> io::Result<Vec<IpAddr>> {
		let held = crate::networks::read(None)?;
		Ok(candidates.iter().copied().filter(|address| dialable(*address) && !own(*address, &held.networks)).collect())
	}

	/// The physical adapter the engine's sockets are bound to now, by its friendly name (`Ethernet`, `Wi-Fi`): what Xray's document names, and what the supervisor restarts it for when it changes. None when the device has no network outside the tunnel.
	pub fn physical() -> io::Result<Option<String>> {crate::networks::read(None)?.interface.map(alias).transpose()}

	/// The friendly name of the adapter with this index.
	pub fn alias(index: u32) -> io::Result<String> {
		let mut luid = NET_LUID_LH {Value: 0};
		// SAFETY: `luid` is a live local the call writes to.
		let code = unsafe {ConvertInterfaceIndexToLuid(index, &mut luid)};
		if code != ERROR_SUCCESS {return Err(io::Error::from_raw_os_error(code as i32))}
		// The longest alias there is, 256 characters, and the NUL.
		let mut buffer = [0u16; 257];
		// SAFETY: `luid` is live and the buffer is live, with its length in characters passed.
		let code = unsafe {ConvertInterfaceLuidToAlias(&luid, buffer.as_mut_ptr(), buffer.len())};
		if code != ERROR_SUCCESS {return Err(io::Error::from_raw_os_error(code as i32))}
		Ok(String::from_utf16_lossy(&buffer[..buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len())]))
	}

	// A table of the IP Helper in a buffer of words: asked for its size first, then read, and again if it grew between the two calls.
	fn table(call: impl Fn(*mut c_void, *mut u32) -> u32) -> io::Result<Vec<u32>> {
		let mut size = 0u32;
		for _ in 0..8 {
			let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
			match call(if size == 0 {null_mut()} else {buffer.as_mut_ptr().cast()}, &mut size) {
				ERROR_SUCCESS => return Ok(buffer),
				ERROR_INSUFFICIENT_BUFFER => {}
				other => return Err(io::Error::from_raw_os_error(other as i32)),
			}
		}
		Err(io::Error::other("the table of sockets kept growing while it was read"))
	}

	// The port of a row: network order in the low half of a word.
	fn port(word: u32) -> u16 {u16::from_be(word as u16)}

	/// Whether every socket on `address` is process `pid`'s and there is at least one: the TCP listeners of the SOCKS port (`udp` false), or the UDP sockets of a relay (`udp` true). A process that took the port first, or shares it, makes this false whatever it answers. A failure to read the tables is an error, which the caller treats as no.
	pub fn listening_as(address: SocketAddr, pid: u32, udp: bool) -> io::Result<bool> {
		let mut rows = Vec::new();
		if udp {
			let v4 = table(|buffer, size| {
				// SAFETY: the buffer is null with size 0, or live with `size` bytes.
				unsafe {GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)}
			})?;
			// SAFETY: the table starts with its count, followed by that many rows, in the buffer that is alive here.
			rows.extend(unsafe {let found = &*v4.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>(); std::slice::from_raw_parts(found.table.as_ptr(), found.dwNumEntries as usize)}.iter().map(|row| Row {ip: Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).into(), port: port(row.dwLocalPort), pid: row.dwOwningPid}));
			let v6 = table(|buffer, size| {
				// SAFETY: as above.
				unsafe {GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0)}
			})?;
			// SAFETY: as above, for the table of IPv6.
			rows.extend(unsafe {let found = &*v6.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>(); std::slice::from_raw_parts(found.table.as_ptr(), found.dwNumEntries as usize)}.iter().map(|row| Row {ip: Ipv6Addr::from(row.ucLocalAddr).into(), port: port(row.dwLocalPort), pid: row.dwOwningPid}));
		} else {
			let v4 = table(|buffer, size| {
				// SAFETY: as above.
				unsafe {GetExtendedTcpTable(buffer, size, 0, u32::from(AF_INET), TCP_TABLE_OWNER_PID_LISTENER, 0)}
			})?;
			// SAFETY: as above, for the table of listeners.
			rows.extend(unsafe {let found = &*v4.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>(); std::slice::from_raw_parts(found.table.as_ptr(), found.dwNumEntries as usize)}.iter().map(|row| Row {ip: Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).into(), port: port(row.dwLocalPort), pid: row.dwOwningPid}));
			let v6 = table(|buffer, size| {
				// SAFETY: as above.
				unsafe {GetExtendedTcpTable(buffer, size, 0, u32::from(AF_INET6), TCP_TABLE_OWNER_PID_LISTENER, 0)}
			})?;
			// SAFETY: as above, for the table of IPv6 listeners.
			rows.extend(unsafe {let found = &*v6.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>(); std::slice::from_raw_parts(found.table.as_ptr(), found.dwNumEntries as usize)}.iter().map(|row| Row {ip: Ipv6Addr::from(row.ucLocalAddr).into(), port: port(row.dwLocalPort), pid: row.dwOwningPid}));
		}
		let found = holders(&rows, address);
		Ok(!found.is_empty() && found.iter().all(|holder| *holder == pid))
	}

	// A pipe whose two ends can be inherited, as `CreateProcess` needs the child's end to be. The caller clears the flag on its own end.
	fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
		let attributes = SECURITY_ATTRIBUTES {nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: null_mut(), bInheritHandle: 1};
		let (mut read, mut write): (HANDLE, HANDLE) = (null_mut(), null_mut());
		// SAFETY: both out pointers are live locals and the attributes are live through the call.
		if unsafe {CreatePipe(&mut read, &mut write, &attributes, 1 << 16)} == 0 {return Err(io::Error::last_os_error())}
		Ok((owned(read), owned(write)))
	}

	fn not_inherited(handle: &OwnedHandle) -> io::Result<()> {
		// SAFETY: the handle is open for the length of the call.
		if unsafe {SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0)} == 0 {Err(io::Error::last_os_error())} else {Ok(())}
	}

	// The token of the child: a restricted copy of this process's own, with the groups of `DISABLED_SIDS` deny-only and no privilege. The privilege to raise quotas is switched on in this process's token first, since starting a process with another token asks for it.
	fn restricted_token() -> io::Result<OwnedHandle> {
		let mut current: HANDLE = null_mut();
		// SAFETY: the process handle is a pseudo handle and `current` is a live local the call writes to.
		if unsafe {OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES, &mut current)} == 0 {return Err(io::Error::last_os_error())}
		let current = owned(current);
		let mut privileges = TOKEN_PRIVILEGES {PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES {Luid: Default::default(), Attributes: SE_PRIVILEGE_ENABLED}]};
		// SAFETY: the name is a null-terminated wide string and the LUID a live local. A failure here only means the privilege is not held, and starting the process says so if it was needed.
		if unsafe {LookupPrivilegeValueW(null(), wide("SeIncreaseQuotaPrivilege").as_ptr(), &mut privileges.Privileges[0].Luid)} != 0 {
			// SAFETY: the token is open, with the right to adjust, and the state is live.
			unsafe {AdjustTokenPrivileges(current.as_raw_handle(), 0, &privileges, 0, null_mut(), null_mut())};
		}
		let mut sids = Vec::new();
		for text in DISABLED_SIDS {
			let mut sid = null_mut();
			// SAFETY: the string is null-terminated and `sid` a live local the call writes a pointer to, freed below.
			if unsafe {ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid)} == 0 {return Err(io::Error::last_os_error())}
			sids.push(SID_AND_ATTRIBUTES {Sid: sid, Attributes: 0});
		}
		let mut restricted: HANDLE = null_mut();
		// SAFETY: the token is open with the right to duplicate, the SIDs are live until freed below, and `restricted` is a live local the call writes to.
		let made = unsafe {CreateRestrictedToken(current.as_raw_handle(), DISABLE_MAX_PRIVILEGE, sids.len() as u32, sids.as_ptr(), 0, null(), 0, null(), &mut restricted)};
		let error = io::Error::last_os_error();
		for sid in &sids {
			// SAFETY: each SID came from `ConvertStringSidToSidW`, which says to free it with this call, once.
			unsafe {LocalFree(sid.Sid)};
		}
		if made == 0 {Err(error)} else {Ok(owned(restricted))}
	}

	// A job that kills what is in it when its last handle closes, and allows one process.
	fn job() -> io::Result<OwnedHandle> {
		// SAFETY: no attributes and no name.
		let handle = unsafe {CreateJobObjectW(null(), null())};
		if handle.is_null() {return Err(io::Error::last_os_error())}
		let job = owned(handle);
		let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		limits.BasicLimitInformation.ActiveProcessLimit = 1;
		// SAFETY: the job is open and the struct is live, with its size passed.
		if unsafe {SetInformationJobObject(job.as_raw_handle(), JobObjectExtendedLimitInformation, (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)} == 0 {return Err(io::Error::last_os_error())}
		Ok(job)
	}

	/// The child: a process that runs with a restricted token in a job that kills it, with its standard streams as files. It answers to the calls the supervisor makes of a tokio child.
	pub struct Child {
		pub stdin: Option<File>,
		pub stdout: Option<File>,
		pub stderr: Option<File>,
		process: Arc<OwnedHandle>,
		_job: OwnedHandle,
		exit: watch::Receiver<Option<u32>>,
		pid: u32,
	}

	impl Child {
		/// Starts `program` (a path that was checked and is held open by the caller) with `arguments`: an empty environment, the system drive's root as the working directory, no window, and nothing inherited but the three ends of the pipes. The process is made suspended, put in the job, and only then let run, so that it is never outside it.
		pub fn spawn(program: &Path, arguments: &[&str], working_directory: &Path) -> io::Result<Self> {
			let token = restricted_token()?;
			let ((input, stdin), (stdout, output), (stderr, error)) = (pipe()?, pipe()?, pipe()?);
			for parent in [&stdin, &stdout, &stderr] {not_inherited(parent)?}
			let mut handles = [input.as_raw_handle(), output.as_raw_handle(), error.as_raw_handle()];
			let mut size = 0usize;
			// SAFETY: a null list asks for the size it needs, which is written to `size`; the call fails with that request, and that is not an error here.
			unsafe {InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size)};
			// Words, so that the list is aligned as a pointer is.
			let mut list = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
			// SAFETY: the buffer is live and `size` bytes long.
			if unsafe {InitializeProcThreadAttributeList(list.as_mut_ptr().cast(), 1, 0, &mut size)} == 0 {return Err(io::Error::last_os_error())}
			// SAFETY: the list is initialized, and the handles outlive the process creation below, which copies what it needs.
			if unsafe {UpdateProcThreadAttribute(list.as_mut_ptr().cast(), 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, handles.as_mut_ptr().cast(), std::mem::size_of_val(&handles), null_mut(), null())} == 0 {return Err(io::Error::last_os_error())}
			let mut startup = STARTUPINFOEXW::default();
			startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
			startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
			(startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError) = (handles[0], handles[1], handles[2]);
			startup.lpAttributeList = list.as_mut_ptr().cast();
			let (application, mut command, directory) = (wide(&program.to_string_lossy()), wide(&command_line(&program.to_string_lossy(), arguments)), wide(&working_directory.to_string_lossy()));
			// An environment of no variables: one empty entry, the end of the block.
			let environment = [0u16; 2];
			let mut created = PROCESS_INFORMATION::default();
			// SAFETY: every pointer is live through the call: the strings, the startup struct with its list of handles, the environment and the out struct. The token is open, and a restricted copy of this process's own needs no privilege to assign.
			let ok = unsafe {CreateProcessAsUserW(token.as_raw_handle(), application.as_ptr(), command.as_mut_ptr(), null(), null(), 1, CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT, environment.as_ptr().cast(), directory.as_ptr(), (&startup as *const STARTUPINFOEXW).cast(), &mut created)};
			let created_error = io::Error::last_os_error();
			// SAFETY: the list was initialized above and is deleted once, after the call that used it.
			unsafe {DeleteProcThreadAttributeList(list.as_mut_ptr().cast())};
			if ok == 0 {return Err(created_error)}
			let (process, thread) = (Arc::new(owned(created.hProcess)), owned(created.hThread));
			// Everything from here on ends the process if it fails, so that no child outlives a start that did not finish.
			let started = (|| {
				let job = job()?;
				// SAFETY: both handles are open.
				if unsafe {AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle())} == 0 {return Err(io::Error::last_os_error())}
				// SAFETY: the thread handle is open.
				if unsafe {ResumeThread(thread.as_raw_handle())} == u32::MAX {return Err(io::Error::last_os_error())}
				Ok(job)
			})();
			let job = match started {
				Ok(job) => job,
				Err(error) => {
					// SAFETY: the process handle is open.
					unsafe {TerminateProcess(process.as_raw_handle(), 1)};
					return Err(error);
				}
			};
			let (sender, exit) = watch::channel(None);
			let waited = process.clone();
			std::thread::spawn(move || {
				// SAFETY: the handle is open for as long as this thread holds its share of it.
				unsafe {WaitForSingleObject(waited.as_raw_handle(), INFINITE)};
				let mut code = 0u32;
				// SAFETY: as above, and `code` is a live local.
				unsafe {GetExitCodeProcess(waited.as_raw_handle(), &mut code)};
				sender.send_replace(Some(code));
			});
			// The child's ends of the pipes close here, so that the ends of ours see the end of the stream when it exits.
			drop((input, output, error));
			Ok(Self {stdin: Some(File::from_std(stdin.into())), stdout: Some(File::from_std(stdout.into())), stderr: Some(File::from_std(stderr.into())), process, _job: job, exit, pid: created.dwProcessId})
		}

		pub fn id(&self) -> Option<u32> {Some(self.pid)}

		/// Waits for the process to end and gives its exit code. Safe to drop and call again.
		pub async fn wait(&mut self) -> io::Result<u32> {
			let mut exit = self.exit.clone();
			let code = exit.wait_for(|code| code.is_some()).await.map_err(|_| io::Error::other("nothing waits for the process any more"))?;
			Ok((*code).unwrap_or(0))
		}

		pub fn start_kill(&mut self) -> io::Result<()> {
			// SAFETY: the process handle is open.
			if unsafe {TerminateProcess(self.process.as_raw_handle(), 1)} == 0 {Err(io::Error::last_os_error())} else {Ok(())}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_holders_of_a_loopback_port_are_every_socket_that_would_get_its_packets() {
		let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
		let row = |ip: &str, port: u16, pid: u32| Row {ip: ip.parse().unwrap(), port, pid};
		let rows = [row("127.0.0.1", 8080, 40), row("0.0.0.0", 8080, 41), row("127.0.0.2", 8080, 42), row("127.0.0.1", 8081, 43), row("::ffff:127.0.0.1", 8080, 44), row("::1", 8080, 45), row("::", 8080, 46)];
		assert_eq!(holders(&rows, address), [40, 41, 44, 46], "the same address, any address, the IPv4 address written as IPv6; not another address, another port or ::1");
		assert!(holders(&[], address).is_empty());
	}

	#[test]
	fn the_command_line_quotes_the_program_and_keeps_the_arguments_as_they_are() {
		assert_eq!(command_line("C:\\ProgramData\\Veilway\\addons\\xray\\xray.exe", &["run", "-config", "stdin:"]), "\"C:\\ProgramData\\Veilway\\addons\\xray\\xray.exe\" run -config stdin:");
		assert_eq!(command_line("x", &[]), "\"x\"");
	}

	#[test]
	fn the_administrators_are_switched_off_in_the_childs_token() {
		assert_eq!(DISABLED_SIDS, ["S-1-5-32-544"]);
	}
}
