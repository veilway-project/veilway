//! The device's own networks changing: interface, address and route change notifications of the IP Helper API (`NotifyIpInterfaceChange`, `NotifyUnicastIpAddressChange`, `NotifyRouteChange2`), all folded into one wake-up.
//!
//! The system calls the callback on a thread of its own, at any moment and often in bursts, so the callback does one thing, `Notify::notify_one`, which keeps at most one wake-up waiting. What a change means is read afterwards by the caller (`networks::read`), after it has settled. The registrations are cancelled when the `Watch` is dropped, and `CancelMibChangeNotify2` does not return while a callback runs, so nothing is called after the context is freed.
use std::io;
use std::sync::Arc;
use tokio::sync::Notify;
use windows_sys::Win32::Foundation::{HANDLE, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

pub struct Watch {notify: *const Notify, handles: Vec<HANDLE>}

// SAFETY: `notify` is a raw `Arc<Notify>`, which is Send and Sync, only dereferenced in the callbacks and in `drop`; the handles are numbers the system looks up.
unsafe impl Send for Watch {}
unsafe impl Sync for Watch {}

unsafe extern "system" fn on_interface(context: *const core::ffi::c_void, _row: *const MIB_IPINTERFACE_ROW, _kind: MIB_NOTIFICATION_TYPE) {wake(context)}

unsafe extern "system" fn on_address(context: *const core::ffi::c_void, _row: *const MIB_UNICASTIPADDRESS_ROW, _kind: MIB_NOTIFICATION_TYPE) {wake(context)}

unsafe extern "system" fn on_route(context: *const core::ffi::c_void, _row: *const MIB_IPFORWARD_ROW2, _kind: MIB_NOTIFICATION_TYPE) {wake(context)}

// SAFETY (for the three callbacks): the context is the pointer `Watch::open` registered, which stays valid until `drop` has cancelled every registration.
fn wake(context: *const core::ffi::c_void) {unsafe {(*context.cast::<Notify>()).notify_one()}}

impl Watch {
	pub fn open() -> io::Result<Self> {
		let notify = Arc::into_raw(Arc::new(Notify::new()));
		let mut watch = Self {notify, handles: Vec::new()};
		let (mut interface, mut address, mut route): (HANDLE, HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
		// SAFETY: the context outlives every registration (see the head of this file), and each handle is a live local that the call writes to. A failure drops `watch`, which cancels what was registered.
		unsafe {
			for (code, handle) in [(NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), notify.cast(), false, &mut interface), interface), (NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), notify.cast(), false, &mut address), address), (NotifyRouteChange2(AF_UNSPEC, Some(on_route), notify.cast(), false, &mut route), route)] {
				if code != ERROR_SUCCESS {return Err(io::Error::from_raw_os_error(code as i32))}
				watch.handles.push(handle);
			}
		}
		Ok(watch)
	}
	/// Completes when something changed since it last did.
	pub async fn changed(&self) -> io::Result<()> {
		// SAFETY: `notify` is alive until `drop`.
		unsafe {(*self.notify).notified().await};
		Ok(())
	}
}

impl Drop for Watch {
	fn drop(&mut self) {
		// SAFETY: every handle came from a successful registration and is cancelled once, which waits for a running callback; only then is the context given back.
		unsafe {
			for handle in &self.handles {CancelMibChangeNotify2(*handle);}
			drop(Arc::from_raw(self.notify));
		}
	}
}
