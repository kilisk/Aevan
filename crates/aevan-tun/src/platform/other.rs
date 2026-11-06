//! Fallback for platforms without an L3 backend.
#![allow(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::{Availability, Readiness, WaitHandle, WaitSources};
use crate::route::Route;

/// No event primitive is available here; sleep for the bounded timeout.
pub fn wait_readable(_sources: WaitSources, timeout: Duration) -> io::Result<Readiness> {
    std::thread::sleep(timeout);
    Ok(Readiness::default())
}

/// No socket tuning is available on this platform.
pub fn tune_udp_socket(_handle: WaitHandle) {}

/// Placeholder device for unsupported platforms.
#[allow(dead_code)]
pub struct UnsupportedDevice;

fn unsupported() -> TunError {
    TunError::Unsupported("no TUN backend for this platform")
}

impl Device for UnsupportedDevice {
    fn open(_config: DeviceConfig) -> Result<Self, TunError> {
        Err(unsupported())
    }

    fn set_addr(&mut self, _address: IpAddr, _prefix_len: u8) -> Result<(), TunError> {
        Err(unsupported())
    }

    fn set_mtu(&mut self, _mtu: u16) -> Result<(), TunError> {
        Err(unsupported())
    }

    fn set_routes(&mut self, _routes: &[Route]) -> Result<(), TunError> {
        Err(unsupported())
    }

    fn set_dns(&mut self, _dns: &[IpAddr]) -> Result<(), TunError> {
        Err(unsupported())
    }

    fn recv(&mut self, _buffer: &mut [u8]) -> Result<usize, TunError> {
        Err(unsupported())
    }

    fn send(&mut self, _packet: &[u8]) -> Result<usize, TunError> {
        Err(unsupported())
    }

    fn close(&mut self) -> Result<(), TunError> {
        Ok(())
    }
}

/// M0 always fails; the type documents the intended return shape.
pub fn open(_config: DeviceConfig) -> Result<Box<dyn Device>, TunError> {
    Err(unsupported())
}

/// No handler is installed on this platform; Ctrl+C uses the default.
pub fn install_shutdown_handler() {}

/// Always false: the default Ctrl+C action terminates the process.
pub fn shutdown_requested() -> bool {
    false
}

/// No platform prerequisite is known.
pub fn probe() -> Availability {
    Availability {
        backend: "unsupported",
        device_present: false,
        reason: Some("no TUN backend for this platform".into()),
    }
}
