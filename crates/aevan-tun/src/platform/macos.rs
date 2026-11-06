//! macOS `utun` backend — **M2**.
//!
//! Creating a `utun` interface needs a `PF_SYSTEM` socket and root (or a
//! privileged launchd helper). M0 is a typed stub; NetworkExtension is an
//! explicit non-goal. `unsafe` is permitted in
//! this module from M2 onward; there is none yet.
#![allow(unsafe_code)]

use std::net::IpAddr;

use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::Availability;
use crate::route::Route;

pub use super::unix::{tune_udp_socket, wait_readable};

/// Placeholder for the `utun` device. Never constructed at M0.
#[allow(dead_code)]
pub struct UtunDevice;

fn unsupported() -> TunError {
    TunError::Unsupported("macOS utun backend lands in M2")
}

impl Device for UtunDevice {
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

/// No handler is installed on this platform yet; Ctrl+C uses the default.
pub fn install_shutdown_handler() {}

/// Always false: the default Ctrl+C action terminates the process.
pub fn shutdown_requested() -> bool {
    false
}

/// No side-effect-free prerequisite is checked at M0.
pub fn probe() -> Availability {
    Availability {
        backend: "macos-utun",
        device_present: false,
        reason: Some("utun requires a PF_SYSTEM socket and root; backend lands in M2".into()),
    }
}
