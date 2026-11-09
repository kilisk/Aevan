//! Linux `/dev/net/tun` backend.
//!
//! The device is opened with `O_RDWR | O_CLOEXEC | O_NONBLOCK` and attached to
//! a TUN interface with `TUNSETIFF`. The requested name is `aevan%d`, so the
//! kernel assigns the unit (for example `aevan0`); the assigned name is read
//! back from the same `ifreq`. `IFF_TUN | IFF_NO_PI` selects a layer-3 device
//! without the 4-byte packet-information prefix, so reads and writes are raw IP
//! packets.
//!
//! Creating the interface needs `CAP_NET_ADMIN` (root). `EPERM`/`EACCES` from
//! `open` or the ioctl becomes [`TunError::Permission`] naming root and
//! `CAP_NET_ADMIN`; this module never elevates. Address, MTU, route and DNS
//! changes are forwarded to the [`crate::apply`] applier.
//!
//! A missing `/dev/net/tun` is a typed [`TunError::Unsupported`] telling the
//! caller to load the `tun` module, not a generic I/O error.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_short, c_ulong};
use std::path::Path;

use crate::apply::Applier;
use crate::command::RealCommandRunner;
use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::Availability;
use crate::privilege::{elevation, Elevation};
use crate::rollback::{Change, RollbackBackend};
use crate::route::Route;

pub use super::unix::{tune_udp_socket, wait_readable};

/// Linux `TUNSETIFF` = `_IOW('T', 202, int)`.
const TUNSETIFF: c_ulong = 0x4004_54CA;
/// `IFF_TUN`: a layer-3 tunnel device.
const IFF_TUN: c_short = 0x0001;
/// `IFF_NO_PI`: no packet-information header.
const IFF_NO_PI: c_short = 0x1000;
/// `IFNAMSIZ`.
const IFNAMSIZ: usize = 16;
/// The kernel-assigned name template passed to `TUNSETIFF`.
const NAME_TEMPLATE: &[u8] = b"aevan%d";
/// Character device that the `tun` module provides.
const DEV_NET_TUN: &str = "/dev/net/tun";

/// `struct ifreq` from `<net/if.h>`.
///
/// Only `ifr_name` and `ifr_flags` are used, but the kernel copies the whole
/// 40-byte structure on 64-bit targets, so the trailing union is represented
/// as explicit padding.
#[repr(C)]
struct IfReq {
    name: [c_char; IFNAMSIZ],
    flags: c_short,
    _padding: [u8; 22],
}

fn last_error(context: &'static str) -> TunError {
    map_error(io::Error::last_os_error(), context)
}

fn map_error(error: io::Error, context: &'static str) -> TunError {
    match error.raw_os_error() {
        Some(code) if code == libc::EPERM || code == libc::EACCES => TunError::Permission(format!(
            "{context} requires root or CAP_NET_ADMIN; run with sudo"
        )),
        Some(code) if code == libc::ENOENT => TunError::Unsupported(
            "/dev/net/tun is missing; the tun kernel module is not loaded (run `modprobe tun`) \
             or the kernel was built without CONFIG_TUN",
        ),
        _ => TunError::Io(error),
    }
}

fn missing_device() -> TunError {
    TunError::Unsupported(
        "/dev/net/tun does not exist; the tun kernel module is not loaded (run `modprobe tun`) \
         or the kernel was built without CONFIG_TUN",
    )
}

/// Open `/dev/net/tun`, attach a TUN interface and return the descriptor and
/// the kernel-assigned name.
fn open_tun() -> Result<(c_int, String), TunError> {
    if !Path::new(DEV_NET_TUN).exists() {
        return Err(missing_device());
    }

    let path = CString::new(DEV_NET_TUN).expect("the device path has no interior NUL");
    // SAFETY: `path` is a NUL-terminated path that outlives the call; the flags
    // are plain integers and a negative result is handled below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(last_error("opening /dev/net/tun"));
    }

    match attach(fd) {
        Ok(name) => Ok((fd, name)),
        Err(error) => {
            // SAFETY: `fd` was opened above and is not used again.
            unsafe {
                libc::close(fd);
            }
            Err(error)
        }
    }
}

fn attach(fd: c_int) -> Result<String, TunError> {
    let mut request = IfReq {
        name: [0; IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        _padding: [0; 22],
    };
    for (slot, byte) in request.name.iter_mut().zip(NAME_TEMPLATE.iter()) {
        *slot = *byte as c_char;
    }

    // SAFETY: `request` is a live `struct ifreq` of the size the kernel
    // expects and `fd` is the live character device.
    let result = unsafe { libc::ioctl(fd, TUNSETIFF, &mut request) };
    if result < 0 {
        return Err(last_error("attaching a TUN interface with TUNSETIFF"));
    }

    let bytes: Vec<u8> = request
        .name
        .iter()
        .take_while(|character| **character != 0)
        .map(|character| *character as u8)
        .collect();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// An attached Linux TUN interface and its configuration applier.
pub struct LinuxTunDevice {
    fd: c_int,
    name: String,
    applier: Option<Box<dyn Applier>>,
    routes: Vec<Route>,
    dns: Vec<IpAddr>,
    closed: bool,
}

impl LinuxTunDevice {
    /// Kernel-assigned interface name, such as `aevan0`.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn applier_mut(&mut self) -> Result<&mut Box<dyn Applier>, TunError> {
        if self.closed {
            return Err(TunError::Unsupported("the TUN device is closed"));
        }
        self.applier
            .as_mut()
            .ok_or(TunError::Unsupported("the TUN device is closed"))
    }

    fn check_open(&self) -> Result<(), TunError> {
        if self.closed || self.fd < 0 {
            Err(TunError::Unsupported("the TUN device is closed"))
        } else {
            Ok(())
        }
    }
}

impl Device for LinuxTunDevice {
    fn open(config: DeviceConfig) -> Result<Self, TunError> {
        config.validate()?;
        let (fd, name) = open_tun()?;
        let applier = crate::apply::platform_applier_unchecked(Box::new(RealCommandRunner), &name);
        Ok(Self {
            fd,
            name,
            applier: Some(applier),
            routes: Vec::new(),
            dns: Vec::new(),
            closed: false,
        })
    }

    fn set_addr(&mut self, address: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        let change = Change::SetAddr {
            old: None,
            new: Some((address, prefix_len)),
        };
        self.applier_mut()?.apply(&change)
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), TunError> {
        let change = Change::SetMtu {
            old: None,
            new: Some(mtu),
        };
        self.applier_mut()?.apply(&change)
    }

    fn set_routes(&mut self, routes: &[Route]) -> Result<(), TunError> {
        let change = Change::SetRoutes {
            old: self.routes.clone(),
            new: routes.to_vec(),
        };
        self.applier_mut()?.apply(&change)?;
        self.routes = routes.to_vec();
        Ok(())
    }

    fn set_dns(&mut self, dns: &[IpAddr]) -> Result<(), TunError> {
        let change = Change::SetDns {
            old: self.dns.clone(),
            new: dns.to_vec(),
            context: crate::rollback::DnsContext::Unspecified,
        };
        self.applier_mut()?.apply(&change)?;
        self.dns = dns.to_vec();
        Ok(())
    }

    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, TunError> {
        self.check_open()?;
        // SAFETY: `fd` is a live TUN descriptor and `buffer` is exclusively
        // borrowed writable storage of the length passed.
        let result = unsafe {
            libc::read(
                self.fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if result < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        Ok(result as usize)
    }

    fn send(&mut self, packet: &[u8]) -> Result<usize, TunError> {
        self.check_open()?;
        // SAFETY: `fd` is a live TUN descriptor and `packet` describes
        // initialised bytes of the length passed.
        let result = unsafe {
            libc::write(
                self.fd,
                packet.as_ptr().cast::<libc::c_void>(),
                packet.len(),
            )
        };
        if result < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        if result as usize != packet.len() {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "the TUN device accepted {} of {} packet bytes",
                    result,
                    packet.len()
                ),
            )));
        }
        Ok(packet.len())
    }

    fn wait_handle(&self) -> Option<isize> {
        if self.closed || self.fd < 0 {
            None
        } else {
            Some(self.fd as isize)
        }
    }

    fn close(&mut self) -> Result<(), TunError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.applier = None;
        if self.fd < 0 {
            return Ok(());
        }
        let fd = std::mem::replace(&mut self.fd, -1);
        // SAFETY: `fd` is the live descriptor created by `open` and is closed
        // exactly once because `closed` was set above.
        let result = unsafe { libc::close(fd) };
        if result < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for LinuxTunDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Open the Linux L3 backend.
pub fn open(config: DeviceConfig) -> Result<Box<dyn Device>, TunError> {
    Ok(Box::new(LinuxTunDevice::open(config)?))
}

/// No handler is installed on this platform; Ctrl+C uses the default.
pub fn install_shutdown_handler() {}

/// Always false: the default Ctrl+C action terminates the process.
pub fn shutdown_requested() -> bool {
    false
}

/// Report whether `/dev/net/tun` exists and whether root is held.
pub fn probe() -> Availability {
    let present = Path::new(DEV_NET_TUN).exists();
    let reason = if !present {
        "/dev/net/tun is missing; load the tun kernel module (`modprobe tun`) or use a kernel with CONFIG_TUN"
            .to_owned()
    } else {
        match elevation() {
            Elevation::Elevated => {
                "/dev/net/tun exists and root is held; CAP_NET_ADMIN is available to create a tun interface"
                    .to_owned()
            }
            Elevation::NotElevated => {
                "/dev/net/tun exists; creating a tun interface requires root or CAP_NET_ADMIN"
                    .to_owned()
            }
            Elevation::Unknown => {
                "/dev/net/tun exists; could not determine whether root or CAP_NET_ADMIN is held"
                    .to_owned()
            }
        }
    };

    Availability {
        backend: "linux-tun",
        device_present: present,
        reason: Some(reason),
    }
}
