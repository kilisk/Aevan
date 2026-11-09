//! macOS `utun` backend — **M2**.
//!
//! Creating a `utun` interface needs a `PF_SYSTEM` socket and root (or a
//! privileged launchd helper). M0 is a typed stub; NetworkExtension is an
//! explicit non-goal.
//!
//! # Framing
//!
//! Every read and write on a `utun` socket carries a 4-byte address-family
//! header in network byte order before the IP packet: `AF_INET` (2) for IPv4
//! and `AF_INET6` (30) for IPv6. The pure helpers [`strip_frame`] and
//! [`frame_into`] hold that logic so it can be unit-tested without a device.
#![allow(unsafe_code)]

use std::io;
use std::net::IpAddr;

use crate::device::{Device, DeviceConfig};
use crate::error::TunError;
use crate::platform::Availability;
use crate::route::Route;

pub use super::unix::{tune_udp_socket, wait_readable};

/// Darwin `AF_INET`, as written into the packet header.
const AF_INET: u32 = 2;
/// Darwin `AF_INET6`, as written into the packet header.
const AF_INET6: u32 = 30;

#[allow(dead_code)]
fn invalid_data(message: String) -> TunError {
    TunError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

/// Strip and validate the 4-byte address-family header.
///
/// The returned slice borrows the input and contains only the IP packet. A
/// short frame, an unknown family, a missing packet, or a family that disagrees
/// with the packet's version nibble is a typed [`TunError`] rather than data
/// passed up the stack.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
