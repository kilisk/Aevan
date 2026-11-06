//! Linux `/dev/net/tun` backend — **M2**.
//!
//! M0 only checks for the character device and returns a typed
//! [`TunError::Unsupported`]. The real backend needs `CAP_NET_ADMIN` (or a
//! systemd service with polkit) and uses netlink for routes.
//! `unsafe` is permitted in this module from M2 onward; there is none yet.
#![allow(unsafe_code)]

use std::net::IpAddr;
use std::path::Path;

use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::Availability;
use crate::route::Route;

pub use super::unix::{tune_udp_socket, wait_readable};

/// Placeholder for the `/dev/net/tun` device. Never constructed at M0.
#[allow(dead_code)]
pub struct LinuxTunDevice;

fn unsupported() -> TunError {
    TunError::Unsupported("Linux TUN backend lands in M2")
}

impl Device for LinuxTunDevice {
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

/// Check for `/dev/net/tun` without opening it.
pub fn probe() -> Availability {
    let present = Path::new("/dev/net/tun").exists();
    let reason = if present {
        "/dev/net/tun exists; netlink routes and DNS land in M2".to_owned()
    } else {
        "/dev/net/tun is missing; load the tun module or use a kernel with CONFIG_TUN".to_owned()
    };

    Availability {
        backend: "linux-tun",
        device_present: present,
        reason: Some(reason),
    }
}
