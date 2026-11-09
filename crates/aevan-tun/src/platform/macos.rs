//! macOS `utun` backend.
//!
//! A `utun` interface is a `PF_SYSTEM` control socket. The sequence is:
//! `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`, resolve
//! `com.apple.net.utun_control` with `CTLIOCGINFO`, then `connect` a
//! `sockaddr_ctl` to it. The kernel assigns the unit (`sc_unit = 0`), and
//! `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)` reads the assigned name.
//!
//! # Framing
//!
//! Every read and write carries a 4-byte address-family header in network byte
//! order before the IP packet: `AF_INET` (2) for IPv4 and `AF_INET6` (30) for
//! IPv6. [`recv`](Device::recv) strips and validates it, and
//! [`send`](Device::send) prepends it from the packet's version nibble. The
//! pure helpers [`strip_frame`] and [`frame_into`] hold that logic so it can be
//! unit-tested without a device.
//!
//! # Privileges
//!
//! Creating a `utun` interface needs root. A socket or `connect` failure with
//! `EPERM`/`EACCES` becomes [`TunError::Permission`] naming `sudo`; this module
//! never elevates. Address, MTU, route and DNS changes are forwarded to the
//! [`crate::apply`] applier.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_ulong};

use crate::apply::Applier;
use crate::command::RealCommandRunner;
use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::Availability;
use crate::privilege::{elevation, Elevation};
use crate::rollback::{Change, RollbackBackend};
use crate::route::Route;

pub use super::unix::{tune_udp_socket, wait_readable};

/// Darwin `PF_SYSTEM` / `AF_SYSTEM`.
const PF_SYSTEM: c_int = 32;
/// Darwin `AF_SYS_CONTROL`.
const AF_SYS_CONTROL: c_int = 2;
/// Darwin `SYSPROTO_CONTROL`.
const SYSPROTO_CONTROL: c_int = 2;
/// Darwin `UTUN_OPT_IFNAME`.
const UTUN_OPT_IFNAME: c_int = 2;
/// Darwin `AF_INET`, as written into the packet header.
const AF_INET: u32 = 2;
/// Darwin `AF_INET6`, as written into the packet header.
const AF_INET6: u32 = 30;
/// Number of bytes in `struct ctl_info::ctl_name`.
const CTL_INFO_NAME_BYTES: usize = 96;
/// Kernel `UTUN_OPT_IFNAME` buffer; the kernel needs at most `IFNAMSIZ` bytes.
const UTUN_NAME_BYTES: usize = 32;
/// Largest frame read from the kernel: a full IPv6 packet plus the header.
const MAX_FRAME: usize = 4 + 65_536;

/// `CTLIOCGINFO`, computed from `_IOWR('N', 3, struct ctl_info)`.
///
/// Darwin's `_IOC(inout, group, num, len)` is
/// `inout | ((len & 0x1fff) << 16) | (group << 8) | num`, with
/// `_IOWR` using `IOC_IN | IOC_OUT` = `0xc000_0000`. For
/// `struct ctl_info { u32 ctl_id; char ctl_name[96]; }` the size is
/// `4 + 96 = 100 = 0x64`, the group is `'N' = 0x4e` and the number is `3`:
///
/// ```text
/// 0xc0000000 | (0x64 << 16) | (0x4e << 8) | 3 = 0xc0644e03
/// ```
const CTLIOCGINFO: c_ulong = 0xC064_4E03;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [c_char; CTL_INFO_NAME_BYTES],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

fn invalid_data(message: String) -> TunError {
    TunError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

/// Strip and validate the 4-byte address-family header.
///
/// The returned slice borrows the input and contains only the IP packet. A
/// short frame, an unknown family, a missing packet, or a family that disagrees
/// with the packet's version nibble is a typed [`TunError`] rather than data
/// passed up the stack.
pub(crate) fn strip_frame(frame: &[u8]) -> Result<&[u8], TunError> {
    if frame.len() < 4 {
        return Err(invalid_data(format!(
            "utun frame of {} bytes is shorter than its 4-byte address-family header",
            frame.len()
        )));
    }
    let family = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let packet = &frame[4..];
    let expected_version = match family {
        AF_INET => 4,
        AF_INET6 => 6,
        other => {
            return Err(invalid_data(format!(
                "utun frame has unsupported address family {other}"
            )))
        }
    };
    let Some(first) = packet.first() else {
        return Err(invalid_data(
            "utun frame has an address-family header but no IP packet".into(),
        ));
    };
    let version = first >> 4;
    if version != expected_version {
        return Err(invalid_data(format!(
            "utun frame says address family {family} but the packet is IPv{version}"
        )));
    }
    Ok(packet)
}

/// Prepend the address-family header for `packet` into `out`.
///
/// The family comes from the packet's version nibble. An empty packet or an
/// unsupported version is a typed [`TunError`].
pub(crate) fn frame_into(packet: &[u8], out: &mut Vec<u8>) -> Result<(), TunError> {
    let Some(first) = packet.first() else {
        return Err(invalid_data("cannot frame an empty IP packet".into()));
    };
    let family = match first >> 4 {
        4 => AF_INET,
        6 => AF_INET6,
        version => {
            return Err(invalid_data(format!(
                "cannot frame unsupported IP version {version}"
            )))
        }
    };
    out.clear();
    out.extend_from_slice(&family.to_be_bytes());
    out.extend_from_slice(packet);
    Ok(())
}

fn last_error(context: &'static str) -> TunError {
    map_error(io::Error::last_os_error(), context)
}

fn map_error(error: io::Error, context: &'static str) -> TunError {
    match error.raw_os_error() {
        Some(code) if code == libc::EPERM || code == libc::EACCES => {
            TunError::Permission(format!("{context} requires root; run with sudo"))
        }
        _ => TunError::Io(error),
    }
}

fn set_nonblocking(fd: c_int) -> Result<(), TunError> {
    // SAFETY: `fd` is the live control socket owned by the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(last_error("reading the utun socket flags"));
    }
    // SAFETY: same live descriptor; the option value is an integer.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(last_error("setting the utun socket non-blocking"));
    }
    // Close-on-exec is best effort: it does not affect I/O, but keeps the
    // tunnel descriptor out of unrelated children.
    // SAFETY: same live descriptor.
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags >= 0 {
        // SAFETY: same live descriptor.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC);
        }
    }
    Ok(())
}

fn read_interface_name(fd: c_int) -> Result<String, TunError> {
    let mut buffer = [0u8; UTUN_NAME_BYTES];
    let mut length = buffer.len() as libc::socklen_t;
    // SAFETY: `fd` is a connected utun control socket and `buffer`/`length`
    // describe writable storage of the size passed.
    let result = unsafe {
        libc::getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            buffer.as_mut_ptr().cast::<c_void>(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(last_error("reading the utun interface name"));
    }
    let limit = (length as usize).min(buffer.len());
    let end = buffer[..limit]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(limit);
    Ok(String::from_utf8_lossy(&buffer[..end]).into_owned())
}

/// Create and connect the control socket, returning the assigned interface
/// name.
fn connect_control() -> Result<(c_int, String), TunError> {
    // SAFETY: a plain socket call; a negative return is handled below.
    let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(last_error("creating a utun control socket"));
    }

    let result = configure(fd);
    match result {
        Ok(name) => Ok((fd, name)),
        Err(error) => {
            // SAFETY: `fd` was created above and is not used again.
            unsafe {
                libc::close(fd);
            }
            Err(error)
        }
    }
}

fn configure(fd: c_int) -> Result<String, TunError> {
    let mut info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0; CTL_INFO_NAME_BYTES],
    };
    const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
    for (slot, byte) in info.ctl_name.iter_mut().zip(CONTROL_NAME.iter()) {
        *slot = *byte as c_char;
    }
    // SAFETY: `info` is a valid, exclusively borrowed `struct ctl_info` and
    // `fd` is the live socket created by the caller.
    let result = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) };
    if result < 0 {
        return Err(last_error("resolving the utun kernel control"));
    }

    let address = SockaddrCtl {
        sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
        sc_family: PF_SYSTEM as u8,
        ss_sysaddr: AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: 0,
        sc_reserved: [0; 5],
    };
    // SAFETY: `address` is a fully initialised `sockaddr_ctl` whose length is
    // passed explicitly; `fd` is live.
    let result = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(address).cast::<libc::sockaddr>(),
            std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(last_error("connecting the utun kernel control"));
    }

    let name = read_interface_name(fd)?;
    set_nonblocking(fd)?;
    Ok(name)
}

/// A connected `utun` interface and its configuration applier.
pub struct UtunDevice {
    fd: c_int,
    name: String,
    applier: Option<Box<dyn Applier>>,
    routes: Vec<Route>,
    dns: Vec<IpAddr>,
    read_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
    closed: bool,
}

impl UtunDevice {
    /// Kernel-assigned interface name, such as `utun3`.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn applier_mut(&mut self) -> Result<&mut Box<dyn Applier>, TunError> {
        if self.closed {
            return Err(TunError::Unsupported("the utun device is closed"));
        }
        self.applier
            .as_mut()
            .ok_or(TunError::Unsupported("the utun device is closed"))
    }

    fn check_open(&self) -> Result<(), TunError> {
        if self.closed || self.fd < 0 {
            Err(TunError::Unsupported("the utun device is closed"))
        } else {
            Ok(())
        }
    }
}

impl Device for UtunDevice {
    fn open(config: DeviceConfig) -> Result<Self, TunError> {
        config.validate()?;
        let (fd, name) = connect_control()?;
        let applier = crate::apply::platform_applier_unchecked(Box::new(RealCommandRunner), &name);
        Ok(Self {
            fd,
            name,
            applier: Some(applier),
            routes: Vec::new(),
            dns: Vec::new(),
            read_buffer: vec![0u8; MAX_FRAME],
            send_buffer: Vec::with_capacity(MAX_FRAME),
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
        // SAFETY: `fd` is live and `read_buffer` is exclusively borrowed
        // writable storage of the length passed.
        let result = unsafe {
            libc::read(
                self.fd,
                self.read_buffer.as_mut_ptr().cast::<c_void>(),
                self.read_buffer.len(),
            )
        };
        if result < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        let packet = strip_frame(&self.read_buffer[..result as usize])?;
        if packet.len() > buffer.len() {
            return Err(invalid_data(format!(
                "utun packet of {} bytes exceeds the {} byte buffer",
                packet.len(),
                buffer.len()
            )));
        }
        buffer[..packet.len()].copy_from_slice(packet);
        Ok(packet.len())
    }

    fn send(&mut self, packet: &[u8]) -> Result<usize, TunError> {
        self.check_open()?;
        frame_into(packet, &mut self.send_buffer)?;
        // SAFETY: `fd` is live and `send_buffer` describes initialised bytes
        // of the length passed.
        let result = unsafe {
            libc::write(
                self.fd,
                self.send_buffer.as_ptr().cast::<c_void>(),
                self.send_buffer.len(),
            )
        };
        if result < 0 {
            return Err(TunError::Io(io::Error::last_os_error()));
        }
        if result as usize != self.send_buffer.len() {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "utun accepted {} of {} frame bytes",
                    result,
                    self.send_buffer.len()
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

impl Drop for UtunDevice {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Open the macOS L3 backend.
pub fn open(config: DeviceConfig) -> Result<Box<dyn Device>, TunError> {
    Ok(Box::new(UtunDevice::open(config)?))
}

/// No handler is installed on this platform; Ctrl+C uses the default.
pub fn install_shutdown_handler() {}

/// Always false: the default Ctrl+C action terminates the process.
pub fn shutdown_requested() -> bool {
    false
}

/// Report whether a `utun` interface can be created.
///
/// The kernel control always exists on macOS; the missing piece is root. The
/// reason states which piece is missing rather than claiming availability.
pub fn probe() -> Availability {
    let reason = match elevation() {
        Elevation::Elevated => {
            "utun is provided by the macOS kernel and root is held; a device can be opened".to_owned()
        }
        Elevation::NotElevated => {
            "utun is provided by the macOS kernel; creating an interface requires root (run with sudo)"
                .to_owned()
        }
        Elevation::Unknown => {
            "utun is provided by the macOS kernel; could not determine whether root is held"
                .to_owned()
        }
    };

    Availability {
        backend: "macos-utun",
        device_present: true,
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet() -> Vec<u8> {
        vec![0x45, 0x00, 0x00, 0x14, 0xde, 0xad]
    }

    fn ipv6_packet() -> Vec<u8> {
        vec![0x60, 0x00, 0x00, 0x00, 0xbe, 0xef]
    }

    #[test]
    fn an_ipv4_frame_is_stripped_to_its_packet() {
        let packet = ipv4_packet();
        let mut frame = AF_INET.to_be_bytes().to_vec();
        frame.extend_from_slice(&packet);
        assert_eq!(strip_frame(&frame).expect("valid frame"), packet.as_slice());
    }

    #[test]
    fn an_ipv6_frame_is_stripped_to_its_packet() {
        let packet = ipv6_packet();
        let mut frame = AF_INET6.to_be_bytes().to_vec();
        frame.extend_from_slice(&packet);
        assert_eq!(strip_frame(&frame).expect("valid frame"), packet.as_slice());
    }

    #[test]
    fn a_truncated_frame_is_rejected() {
        for frame in [&[][..], &[0][..], &[0, 0, 2][..]] {
            let error = strip_frame(frame).expect_err("short frame");
            assert!(matches!(error, TunError::Io(_)));
            assert!(error.to_string().contains("shorter than"));
        }
    }

    #[test]
    fn an_empty_packet_after_the_header_is_rejected() {
        let error = strip_frame(&AF_INET.to_be_bytes()).expect_err("header only");
        assert!(error.to_string().contains("no IP packet"));
    }

    #[test]
    fn a_family_version_mismatch_is_rejected() {
        let mut frame = AF_INET.to_be_bytes().to_vec();
        frame.extend_from_slice(&ipv6_packet());
        let error = strip_frame(&frame).expect_err("IPv4 header carries IPv6");
        assert!(error.to_string().contains("IPv6"));

        let mut frame = AF_INET6.to_be_bytes().to_vec();
        frame.extend_from_slice(&ipv4_packet());
        let error = strip_frame(&frame).expect_err("IPv6 header carries IPv4");
        assert!(error.to_string().contains("IPv4"));
    }

    #[test]
    fn an_unknown_address_family_is_rejected() {
        let mut frame = 9u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&ipv4_packet());
        let error = strip_frame(&frame).expect_err("unknown family");
        assert!(error.to_string().contains("unsupported address family"));
    }

    #[test]
    fn framing_prepends_the_ipv4_family() {
        let packet = ipv4_packet();
        let mut frame = Vec::new();
        frame_into(&packet, &mut frame).expect("frame");
        let mut expected = AF_INET.to_be_bytes().to_vec();
        expected.extend_from_slice(&packet);
        assert_eq!(frame, expected);
    }

    #[test]
    fn framing_prepends_the_ipv6_family() {
        let packet = ipv6_packet();
        let mut frame = Vec::new();
        frame_into(&packet, &mut frame).expect("frame");
        let mut expected = AF_INET6.to_be_bytes().to_vec();
        expected.extend_from_slice(&packet);
        assert_eq!(frame, expected);
    }

    #[test]
    fn framing_replaces_previous_contents() {
        let packet = ipv4_packet();
        let mut frame = vec![0xaa; 64];
        frame_into(&packet, &mut frame).expect("frame");
        assert_eq!(frame.len(), 4 + packet.len());
    }

    #[test]
    fn framing_rejects_an_empty_packet() {
        let mut frame = Vec::new();
        let error = frame_into(&[], &mut frame).expect_err("empty packet");
        assert!(error.to_string().contains("empty IP packet"));
    }

    #[test]
    fn framing_rejects_an_unknown_version() {
        let mut frame = Vec::new();
        let error = frame_into(&[0x55, 0, 0, 0], &mut frame).expect_err("version 5");
        assert!(error.to_string().contains("unsupported IP version 5"));
    }
}
