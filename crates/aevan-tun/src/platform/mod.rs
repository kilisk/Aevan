//! Per-OS TUN backends.
//!
//! All three supported platforms now have a real device backend behind the
//! same [`crate::Device`] trait:
//!
//! * Windows uses `wintun.dll` and returns its read-wait event from
//!   [`crate::Device::wait_handle`].
//! * macOS opens a `utun` control socket and frames each packet with a 4-byte
//!   address-family header.
//! * Linux opens `/dev/net/tun` with `IFF_NO_PI`, so packets are raw IP.
//!
//! macOS and Linux need root to create the interface; `probe` reports the
//! prerequisite honestly and `open` returns a typed
//! [`crate::TunError::Permission`] instead of elevating. There is no `todo!()`
//! and no implicit privilege escalation. A full end-to-end tunnel on macOS and
//! Linux still needs a human on real hardware; CI proves only that the device
//! opens by running the `tun_smoke` example under `sudo`.

use std::io;
use std::time::Duration;

use crate::device::{Device, DeviceConfig};
use crate::error::TunError;

/// A raw platform handle the data plane can wait on.
///
/// On Windows a UDP entry is a `SOCKET` and a device entry is a `HANDLE`; on
/// Unix both are file descriptors. The value is only meaningful to the
/// platform's readiness backend.
pub type WaitHandle = isize;

/// Handles the ESP loop waits on when both directions are idle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaitSources {
    /// UDP socket handle, when the caller has one.
    pub udp: Option<WaitHandle>,
    /// Device read event/file descriptor, when the backend exposes one.
    pub device: Option<WaitHandle>,
}

/// Which source became readable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Readiness {
    /// The UDP socket may have a datagram.
    pub udp: bool,
    /// The device may have a packet.
    pub device: bool,
}

/// Wait until either source is readable or `timeout` elapses.
///
/// The wait is bounded, so a shutdown request is observed within one timeout
/// period even if no traffic wakes the loop.
pub fn wait_readable(sources: WaitSources, timeout: Duration) -> io::Result<Readiness> {
    imp::wait_readable(sources, timeout)
}

/// Request large UDP send and receive buffers on an existing socket.
///
/// Failure is intentionally ignored: the data plane still works with the
/// operating system's default buffer sizes.
pub fn tune_udp_socket(handle: WaitHandle) {
    imp::tune_udp_socket(handle)
}

/// What the platform probe can establish without opening a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    /// Backend name (`windows-wintun`, `macos-utun`, `linux-tun`, ...).
    pub backend: &'static str,
    /// Whether the platform prerequisite (driver, character device) exists.
    pub device_present: bool,
    /// Human-readable explanation, including the M2 deferral.
    pub reason: Option<String>,
}

/// Report device availability for the current platform. Never opens a device.
pub fn probe() -> Availability {
    imp::probe()
}

/// Open the current platform's L3 backend.
///
/// macOS and Linux return [`TunError::Permission`] when the process is not
/// root; Linux returns [`TunError::Unsupported`] when `/dev/net/tun` is absent.
pub fn open(config: DeviceConfig) -> Result<Box<dyn Device>, TunError> {
    imp::open(config)
}

/// Install a Ctrl+C handler that lets the foreground connector tear down
/// cleanly. Platforms without a handler leave the process default in place.
pub fn install_shutdown_handler() {
    imp::install_shutdown_handler()
}

/// Whether the shutdown handler has observed Ctrl+C.
pub fn shutdown_requested() -> bool {
    imp::shutdown_requested()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as imp;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(target_os = "macos")]
pub use macos::UtunDevice;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(target_os = "linux")]
pub use linux::LinuxTunDevice;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
mod other;
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
use other as imp;
