//! Windows Wintun backend.
//!
//! `wintun.dll` is loaded at runtime; nothing links against it at build time.
//! The DLL is resolved beside the executable first, then in `System32`, and a
//! missing file is a typed [`TunError::Unsupported`] naming `wintun.dll`, never
//! a panic or a no-op.
//!
//! Creating an adapter needs Administrator. [`open`] checks elevation and
//! returns [`TunError::Permission`] when the process is not elevated; it never
//! attempts to elevate. Device configuration (address, routes, DNS, MTU) is
//! applied by [`crate::apply`], not by this module.
//!
//! # Testing limitation
//!
//! This path cannot be exercised by unit tests: it needs a real, signed
//! `wintun.dll`, an elevated process and a Windows network stack. The offline
//! tests cover only the missing-DLL decision. A full run is an elevated manual
//! check.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::{Availability, Readiness, WaitHandle, WaitSources};
use crate::privilege::{elevation, Elevation};
use crate::route::Route;

/// Redistributable WireGuard LLC DLL this backend expects.
const DLL_NAME: &str = "wintun.dll";
/// Wintun session ring capacity: 4 MiB, the value the reference examples use.
const SESSION_CAPACITY: u32 = 0x40_0000;

type Handle = *mut c_void;
type WintunCreateAdapterFn = unsafe extern "system" fn(*const u16, *const u16, *const u8) -> Handle;
type WintunOpenAdapterFn = unsafe extern "system" fn(*const u16) -> Handle;
type WintunCloseAdapterFn = unsafe extern "system" fn(Handle);
type WintunStartSessionFn = unsafe extern "system" fn(Handle, u32) -> Handle;
type WintunEndSessionFn = unsafe extern "system" fn(Handle);
type WintunGetReadWaitEventFn = unsafe extern "system" fn(Handle) -> Handle;
type WintunReceivePacketFn = unsafe extern "system" fn(Handle, *mut u32) -> *mut u8;
type WintunReleaseReceivePacketFn = unsafe extern "system" fn(Handle, *const u8);
type WintunAllocateSendPacketFn = unsafe extern "system" fn(Handle, u32) -> *mut u8;
type WintunSendPacketFn = unsafe extern "system" fn(Handle, *const u8);

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = u32::MAX;
const FD_READ: i32 = 0x01;
const SOCKET_ERROR: i32 = -1;
const FD_MAX_EVENTS: usize = 10;

type HandlerRoutine = Option<unsafe extern "system" fn(u32) -> i32>;

const CTRL_C_EVENT: u32 = 0;
const CTRL_BREAK_EVENT: u32 = 1;

#[repr(C)]
#[derive(Default)]
struct WsaNetworkEvents {
    network_events: i32,
    error_code: [i32; FD_MAX_EVENTS],
}

extern "system" {
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
    fn WaitForMultipleObjects(
        count: u32,
        handles: *const Handle,
        wait_all: i32,
        milliseconds: u32,
    ) -> u32;
    fn SetConsoleCtrlHandler(handler: HandlerRoutine, add: i32) -> i32;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSACreateEvent() -> Handle;
    fn WSACloseEvent(event: Handle) -> i32;
    fn WSAEventSelect(socket: usize, event: Handle, network_events: i32) -> i32;
    fn WSAEnumNetworkEvents(socket: usize, event: Handle, events: *mut WsaNetworkEvents) -> i32;
    fn setsockopt(socket: usize, level: i32, option: i32, value: *const u8, length: i32) -> i32;
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn console_control(control: u32) -> i32 {
    match control {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            SHUTDOWN.store(true, Ordering::SeqCst);
            1
        }
        _ => 0,
    }
}

/// Ask the ESP loop to stop on Ctrl+C instead of terminating the process and
/// leaving routes behind. The handler restores normal Ctrl+C behaviour after
/// the loop returns and the process exits.
pub fn install_shutdown_handler() {
    // SAFETY: the handler has the signature Windows requires, is `'static`, and
    // only touches an atomic.
    unsafe {
        SetConsoleCtrlHandler(Some(console_control), 1);
    }
}

/// Whether Ctrl+C or Ctrl+Break was seen since the handler was installed.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Wait for the UDP socket or the Wintun read event.
///
/// Windows sockets are not directly waitable with `WaitForMultipleObjects`, so
/// the UDP socket is associated with a Winsock event for this wait. The event
/// is only a wake hint: the caller always drains the socket itself.
pub fn wait_readable(sources: WaitSources, timeout: Duration) -> io::Result<Readiness> {
    let millis = timeout.as_millis().min(u128::from(u32::MAX)) as u32;
    if sources.udp.is_none() && sources.device.is_none() {
        std::thread::sleep(timeout);
        return Ok(Readiness::default());
    }

    let mut udp_event = std::ptr::null_mut();
    if let Some(socket) = sources.udp {
        // SAFETY: creates a Winsock event owned by this function.
        let event = unsafe { WSACreateEvent() };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket is a live UDP socket handle supplied by the caller.
        if unsafe { WSAEventSelect(socket as usize, event, FD_READ) } == SOCKET_ERROR {
            let error = io::Error::last_os_error();
            // SAFETY: event was created above and is no longer used.
            unsafe {
                WSACloseEvent(event);
            }
            return Err(error);
        }
        udp_event = event;
    }

    let mut handles: [Handle; 2] = [std::ptr::null_mut(); 2];
    let mut udp_index = None;
    let mut device_index = None;
    let mut count = 0usize;
    if !udp_event.is_null() {
        udp_index = Some(count);
        handles[count] = udp_event;
        count += 1;
    }
    if let Some(device) = sources.device {
        device_index = Some(count);
        handles[count] = device as Handle;
        count += 1;
    }

    // SAFETY: every handle is a live Winsock event or Win32 waitable handle.
    let waited = unsafe { WaitForMultipleObjects(count as u32, handles.as_ptr(), 0, millis) };
    if waited == WAIT_FAILED {
        let error = io::Error::last_os_error();
        clear_udp_wait(sources.udp, udp_event);
        return Err(error);
    }

    let mut readiness = Readiness::default();
    if waited != WAIT_TIMEOUT {
        let index = (waited - WAIT_OBJECT_0) as usize;
        readiness.udp = udp_index == Some(index);
        readiness.device = device_index == Some(index);
    }
    clear_udp_wait(sources.udp, udp_event);
    Ok(readiness)
}

fn clear_udp_wait(socket: Option<WaitHandle>, event: Handle) {
    if event.is_null() {
        return;
    }
    let Some(socket) = socket else {
        return;
    };
    let mut events = WsaNetworkEvents::default();
    // SAFETY: socket and event are the pair associated above; clearing and
    // closing it returns the socket to its plain non-blocking state.
    unsafe {
        WSAEnumNetworkEvents(socket as usize, event, &mut events);
        WSAEventSelect(socket as usize, std::ptr::null_mut(), 0);
        WSACloseEvent(event);
    }
}

/// Request 4 MiB send and receive buffers, ignoring failure.
pub fn tune_udp_socket(handle: WaitHandle) {
    const SOL_SOCKET: i32 = 0xffff;
    const SO_SNDBUF: i32 = 0x1001;
    const SO_RCVBUF: i32 = 0x1002;
    const BUFFER_BYTES: i32 = 4 * 1024 * 1024;

    let value = BUFFER_BYTES.to_ne_bytes();
    let socket = handle as usize;
    // SAFETY: handle is the caller's live socket. A failed option is ignored
    // because the default buffer size still works.
    unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_SNDBUF,
            value.as_ptr(),
            value.len() as i32,
        );
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVBUF,
            value.as_ptr(),
            value.len() as i32,
        );
    }
}

/// Loaded function table. Dropping it releases the DLL.
struct WintunApi {
    module: Handle,
    create_adapter: WintunCreateAdapterFn,
    open_adapter: WintunOpenAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    get_read_wait_event: WintunGetReadWaitEventFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
}

impl WintunApi {
    fn load() -> Result<Self, TunError> {
        Self::load_from_candidates(&candidate_paths())
    }

    /// Load the first existing candidate. A missing candidate list is the
    /// missing-DLL path and returns the typed error the tests assert.
    fn load_from_candidates(candidates: &[PathBuf]) -> Result<Self, TunError> {
        let path = candidates.iter().find(|path| path.is_file());
        let Some(path) = path else {
            return Err(TunError::Unsupported(
                "wintun.dll was not found beside the executable or in System32",
            ));
        };

        let wide_path = wide(&path.to_string_lossy());
        // SAFETY: wide_path is a NUL-terminated UTF-16 string that outlives the
        // call. A null return is handled below.
        let module = unsafe { LoadLibraryW(wide_path.as_ptr()) };
        if module.is_null() {
            let error = unsafe { GetLastError() };
            return Err(TunError::Io(io::Error::from_raw_os_error(error as i32)));
        }

        // SAFETY: each symbol is resolved from the module just loaded and
        // transmuted to the exact signature declared by wintun.h.
        match unsafe { Self::resolve(module) } {
            Ok(api) => Ok(api),
            Err(error) => {
                // The partially built table was not created, so release the
                // module here instead of leaking it.
                // SAFETY: module is a live handle from LoadLibraryW.
                unsafe {
                    FreeLibrary(module);
                }
                Err(error)
            }
        }
    }

    unsafe fn resolve(module: Handle) -> Result<Self, TunError> {
        Ok(Self {
            module,
            create_adapter: symbol(module, b"WintunCreateAdapter\0")?,
            open_adapter: symbol(module, b"WintunOpenAdapter\0")?,
            close_adapter: symbol(module, b"WintunCloseAdapter\0")?,
            start_session: symbol(module, b"WintunStartSession\0")?,
            end_session: symbol(module, b"WintunEndSession\0")?,
            get_read_wait_event: symbol(module, b"WintunGetReadWaitEvent\0")?,
            receive_packet: symbol(module, b"WintunReceivePacket\0")?,
            release_receive_packet: symbol(module, b"WintunReleaseReceivePacket\0")?,
            allocate_send_packet: symbol(module, b"WintunAllocateSendPacket\0")?,
            send_packet: symbol(module, b"WintunSendPacket\0")?,
        })
    }
}

impl Drop for WintunApi {
    fn drop(&mut self) {
        if !self.module.is_null() {
            // SAFETY: the module handle came from LoadLibraryW and is freed
            // exactly once when this owned value is dropped.
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
}

unsafe fn symbol<T>(module: Handle, name: &[u8]) -> Result<T, TunError> {
    let pointer = GetProcAddress(module, name.as_ptr());
    if pointer.is_null() {
        return Err(TunError::Unsupported(
            "wintun.dll is missing a required export",
        ));
    }
    Ok(std::mem::transmute_copy::<*mut c_void, T>(&pointer))
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            paths.push(directory.join(DLL_NAME));
        }
    }
    if let Some(root) = std::env::var_os("SystemRoot") {
        paths.push(PathBuf::from(root).join("System32").join(DLL_NAME));
    }
    paths
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check_privilege(observed: Elevation) -> Result<(), TunError> {
    match observed {
        Elevation::Elevated => Ok(()),
        Elevation::NotElevated => Err(TunError::Permission(
            "Administrator is required to create a Wintun adapter".into(),
        )),
        Elevation::Unknown => Err(TunError::Permission(
            "could not determine whether the process is running as Administrator".into(),
        )),
    }
}

/// A Wintun adapter and its session.
pub struct WintunDevice {
    api: Option<WintunApi>,
    adapter: Handle,
    session: Handle,
    read_event: Handle,
    closed: bool,
}

impl WintunDevice {
    fn opened(api: WintunApi, adapter: Handle, session: Handle, read_event: Handle) -> Self {
        Self {
            api: Some(api),
            adapter,
            session,
            read_event,
            closed: false,
        }
    }

    fn parts(&mut self) -> Result<(&WintunApi, Handle, Handle), TunError> {
        if self.closed || self.api.is_none() || self.session.is_null() {
            return Err(TunError::Unsupported("the Wintun device is closed"));
        }
        let api = self.api.as_ref().expect("checked above");
        Ok((api, self.session, self.read_event))
    }
}

impl Device for WintunDevice {
    fn open(config: DeviceConfig) -> Result<Self, TunError> {
        config.validate()?;
        check_privilege(elevation())?;

        let api = WintunApi::load()?;
        let name = config.name.as_deref().unwrap_or("aevan");
        let name_wide = wide(name);
        let tunnel_wide = wide("Aevan");

        // SAFETY: both strings are NUL-terminated and the GUID is optional
        // (null asks Wintun to generate one).
        let mut adapter = unsafe { (api.open_adapter)(name_wide.as_ptr()) };
        if adapter.is_null() {
            adapter = unsafe {
                (api.create_adapter)(name_wide.as_ptr(), tunnel_wide.as_ptr(), std::ptr::null())
            };
        }
        if adapter.is_null() {
            let error = unsafe { GetLastError() };
            if error == ERROR_ACCESS_DENIED {
                return Err(TunError::Permission(
                    "Administrator is required to create a Wintun adapter".into(),
                ));
            }
            return Err(TunError::Io(io::Error::from_raw_os_error(error as i32)));
        }

        // SAFETY: adapter is a live handle owned by this device.
        let session = unsafe { (api.start_session)(adapter, SESSION_CAPACITY) };
        if session.is_null() {
            let error = unsafe { GetLastError() };
            // SAFETY: the adapter was created above and is not used again.
            unsafe {
                (api.close_adapter)(adapter);
            }
            return Err(TunError::Io(io::Error::from_raw_os_error(error as i32)));
        }

        // SAFETY: session is live. The event is optional; recv falls back to
        // polling when it is null.
        let read_event = unsafe { (api.get_read_wait_event)(session) };

        Ok(Self::opened(api, adapter, session, read_event))
    }

    fn set_addr(&mut self, _address: IpAddr, _prefix_len: u8) -> Result<(), TunError> {
        Err(TunError::Unsupported(
            "Wintun device configuration is applied by the apply layer",
        ))
    }

    fn set_mtu(&mut self, _mtu: u16) -> Result<(), TunError> {
        Err(TunError::Unsupported(
            "Wintun device configuration is applied by the apply layer",
        ))
    }

    fn set_routes(&mut self, _routes: &[Route]) -> Result<(), TunError> {
        Err(TunError::Unsupported(
            "Wintun device configuration is applied by the apply layer",
        ))
    }

    fn set_dns(&mut self, _dns: &[IpAddr]) -> Result<(), TunError> {
        Err(TunError::Unsupported(
            "Wintun device configuration is applied by the apply layer",
        ))
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, TunError> {
        let (api, session, _read_event) = self.parts()?;

        let mut size = 0u32;
        // SAFETY: session is live; size is a valid out-pointer.
        let packet = unsafe { (api.receive_packet)(session, &mut size) };
        if packet.is_null() {
            // SAFETY: reads the calling thread's last-error value.
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_ITEMS {
                return Err(TunError::Io(io::Error::from(io::ErrorKind::WouldBlock)));
            }
            return Err(TunError::Io(io::Error::from_raw_os_error(error as i32)));
        }

        let length = size as usize;
        if length > buffer.len() {
            // SAFETY: packet is still owned by the session.
            unsafe {
                (api.release_receive_packet)(session, packet);
            }
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Wintun packet of {length} bytes exceeds the buffer"),
            )));
        }
        // SAFETY: the session guarantees `size` readable bytes at `packet`;
        // release returns ownership to Wintun.
        unsafe {
            std::ptr::copy_nonoverlapping(packet, buffer.as_mut_ptr(), length);
            (api.release_receive_packet)(session, packet);
        }
        Ok(length)
    }

    fn wait_handle(&self) -> Option<isize> {
        if self.closed || self.read_event.is_null() {
            None
        } else {
            Some(self.read_event as isize)
        }
    }

    fn send(&mut self, packet: &[u8]) -> Result<usize, TunError> {
        let (api, session, _) = self.parts()?;
        let length = u32::try_from(packet.len()).map_err(|_| {
            TunError::InvalidConfig(format!("packet of {} bytes is too large", packet.len()))
        })?;

        // SAFETY: session is live and length was checked.
        let buffer = unsafe { (api.allocate_send_packet)(session, length) };
        if buffer.is_null() {
            let error = unsafe { GetLastError() };
            return Err(TunError::Io(io::Error::from_raw_os_error(error as i32)));
        }

        // SAFETY: Wintun allocated `length` writable bytes; send consumes them.
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
            (api.send_packet)(session, buffer);
        }
        Ok(packet.len())
    }

    fn close(&mut self) -> Result<(), TunError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        if let Some(api) = self.api.as_ref() {
            // SAFETY: both handles belong to this device and are ended once.
            unsafe {
                if !self.session.is_null() {
                    (api.end_session)(self.session);
                }
                if !self.adapter.is_null() {
                    (api.close_adapter)(self.adapter);
                }
            }
        }
        self.session = std::ptr::null_mut();
        self.adapter = std::ptr::null_mut();
        self.read_event = std::ptr::null_mut();
        // Dropping the API frees the DLL.
        self.api = None;
        Ok(())
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Open the Windows L3 backend.
pub fn open(config: DeviceConfig) -> Result<Box<dyn Device>, TunError> {
    Ok(Box::new(WintunDevice::open(config)?))
}

/// Look for the redistributable `wintun.dll` without loading it.
pub fn probe() -> Availability {
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(DLL_NAME)))
        .is_some_and(|path| path.exists());

    let in_system32 = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("System32").join(DLL_NAME))
        .is_some_and(|path| path.exists());

    let present = beside_exe || in_system32;
    let reason = if present {
        "wintun.dll found; adapter creation needs Administrator".to_owned()
    } else {
        format!("{DLL_NAME} was not found beside aevan.exe or in System32")
    };

    Availability {
        backend: "windows-wintun",
        device_present: present,
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_dll_is_a_typed_unsupported_error_that_names_it() {
        let error = WintunApi::load_from_candidates(&[])
            .err()
            .expect("an empty candidate list cannot load");
        assert!(matches!(error, TunError::Unsupported(_)));
        assert!(error.to_string().contains(DLL_NAME));
    }

    #[test]
    fn a_nonexistent_candidate_is_also_missing() {
        let path = std::env::temp_dir()
            .join("aevan-no-such-wintun")
            .join(DLL_NAME);
        let error = WintunApi::load_from_candidates(&[path])
            .err()
            .expect("a nonexistent candidate cannot load");
        assert!(matches!(error, TunError::Unsupported(_)));
        assert!(error.to_string().contains(DLL_NAME));
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        let encoded = wide("aevan");
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(
            &encoded[..5],
            &[
                b'a' as u16,
                b'e' as u16,
                b'v' as u16,
                b'a' as u16,
                b'n' as u16
            ]
        );
    }

    #[test]
    fn privilege_refusal_is_generic_and_never_elevates() {
        assert!(matches!(
            check_privilege(Elevation::NotElevated),
            Err(TunError::Permission(_))
        ));
        assert!(matches!(
            check_privilege(Elevation::Unknown),
            Err(TunError::Permission(_))
        ));
        assert!(check_privilege(Elevation::Elevated).is_ok());
    }

    #[test]
    fn a_closed_device_refuses_packet_operations() {
        let mut device = WintunDevice {
            api: None,
            adapter: std::ptr::null_mut(),
            session: std::ptr::null_mut(),
            read_event: std::ptr::null_mut(),
            closed: true,
        };
        let mut buffer = [0u8; 4];
        assert!(matches!(
            device.recv(&mut buffer),
            Err(TunError::Unsupported(_))
        ));
        assert!(matches!(
            device.send(&buffer),
            Err(TunError::Unsupported(_))
        ));
        assert!(device.close().is_ok(), "close is idempotent");
    }
}
