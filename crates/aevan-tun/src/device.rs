//! The [`Device`] trait, its configuration and a no-op backend for tests.

use std::net::IpAddr;

use crate::error::TunError;
use crate::route::Route;

/// Everything needed to open and configure an L3 device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceConfig {
    /// Optional device name. Backends may ignore it.
    pub name: Option<String>,
    /// Assigned tunnel address.
    pub address: Option<IpAddr>,
    /// Prefix length for [`DeviceConfig::address`].
    pub prefix_len: u8,
    /// Maximum transmission unit; zero means "backend default".
    pub mtu: u16,
    /// Routes to install.
    pub routes: Vec<Route>,
    /// DNS servers to configure.
    pub dns: Vec<IpAddr>,
}

impl DeviceConfig {
    /// Validate the configuration without touching the operating system.
    pub fn validate(&self) -> Result<(), TunError> {
        if let Some(address) = self.address {
            let max_prefix = match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if self.prefix_len > max_prefix {
                return Err(TunError::InvalidConfig(format!(
                    "prefix /{} is invalid for {address}",
                    self.prefix_len
                )));
            }
        } else if self.prefix_len != 0 {
            return Err(TunError::InvalidConfig(
                "a prefix length was supplied without an address".into(),
            ));
        }

        if self.mtu != 0 && self.mtu < 576 {
            return Err(TunError::InvalidConfig(format!(
                "MTU {} is below the IPv4 minimum of 576",
                self.mtu
            )));
        }

        Ok(())
    }
}

/// A layer-3 tunnel device.
///
/// Implementations are per-OS and live behind [`crate::platform`]. The trait is
/// synchronous: the async supervisor in `aevan-daemon` drives it on a blocking
/// worker.
pub trait Device {
    /// Open the device and apply the static configuration.
    fn open(config: DeviceConfig) -> Result<Self, TunError>
    where
        Self: Sized;

    /// Set or replace the interface address and prefix.
    fn set_addr(&mut self, address: IpAddr, prefix_len: u8) -> Result<(), TunError>;

    /// Set the interface MTU.
    fn set_mtu(&mut self, mtu: u16) -> Result<(), TunError>;

    /// Replace the route set.
    fn set_routes(&mut self, routes: &[Route]) -> Result<(), TunError>;

    /// Replace the DNS server list.
    fn set_dns(&mut self, dns: &[IpAddr]) -> Result<(), TunError>;

    /// Receive one packet. Returns the number of bytes written to `buffer`.
    fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, TunError>;

    /// Send one packet. Returns the number of bytes accepted.
    fn send(&mut self, packet: &[u8]) -> Result<usize, TunError>;

    /// The interface name the OS actually assigned, once opened.
    ///
    /// macOS assigns a `utunN` unit dynamically, so a configured name is only a
    /// hint: anything that configures the interface (address, MTU, routes, DNS)
    /// must use this value or it will configure a different interface.
    fn name(&self) -> Option<&str> {
        None
    }

    /// A raw platform handle that becomes readable when a packet is waiting.
    ///
    /// The ESP loop waits on this together with the UDP socket so an idle
    /// device does not require a polling sleep. Wintun returns its read-wait
    /// event; backends without a waitable handle return `None`.
    fn wait_handle(&self) -> Option<isize> {
        None
    }

    /// Close the device. Implementations must be idempotent.
    fn close(&mut self) -> Result<(), TunError>;
}

/// A backend that records configuration and never touches the OS.
///
/// Used by unit tests and by `aevan doctor` to prove the trait wiring without
/// requiring elevation. Packet operations return [`TunError::Unsupported`].
#[derive(Debug, Default)]
pub struct NoopBackend {
    opened_with: Option<DeviceConfig>,
    address: Option<(IpAddr, u8)>,
    mtu: Option<u16>,
    routes: Vec<Route>,
    dns: Vec<IpAddr>,
    closed: bool,
}

impl NoopBackend {
    /// Configuration passed to [`Device::open`].
    pub fn opened_with(&self) -> Option<&DeviceConfig> {
        self.opened_with.as_ref()
    }

    /// Last address set on the device.
    pub fn address(&self) -> Option<(IpAddr, u8)> {
        self.address
    }

    /// Last MTU set on the device.
    pub fn mtu(&self) -> Option<u16> {
        self.mtu
    }

    /// Last route set applied.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Last DNS set applied.
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }

    /// Whether [`Device::close`] has run.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

impl Device for NoopBackend {
    fn open(config: DeviceConfig) -> Result<Self, TunError> {
        config.validate()?;
        Ok(Self {
            opened_with: Some(config),
            ..Self::default()
        })
    }

    fn set_addr(&mut self, address: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(TunError::InvalidConfig(format!(
                "prefix /{prefix_len} is invalid for {address}"
            )));
        }
        self.address = Some((address, prefix_len));
        Ok(())
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), TunError> {
        if mtu != 0 && mtu < 576 {
            return Err(TunError::InvalidConfig(format!(
                "MTU {mtu} is below the IPv4 minimum of 576"
            )));
        }
        self.mtu = Some(mtu);
        Ok(())
    }

    fn set_routes(&mut self, routes: &[Route]) -> Result<(), TunError> {
        self.routes = routes.to_vec();
        Ok(())
    }

    fn set_dns(&mut self, dns: &[IpAddr]) -> Result<(), TunError> {
        self.dns = dns.to_vec();
        Ok(())
    }

    fn recv(&mut self, _buffer: &mut [u8]) -> Result<usize, TunError> {
        Err(TunError::Unsupported(
            "the no-op backend has no packet source",
        ))
    }

    fn send(&mut self, _packet: &[u8]) -> Result<usize, TunError> {
        Err(TunError::Unsupported(
            "the no-op backend has no packet sink",
        ))
    }

    fn close(&mut self) -> Result<(), TunError> {
        self.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43))
    }

    #[test]
    fn noop_backend_records_configuration() {
        let route = Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route");
        let config = DeviceConfig {
            name: Some("aevan0".into()),
            address: Some(address()),
            prefix_len: 24,
            mtu: 1396,
            routes: vec![route.clone()],
            dns: vec![IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))],
        };

        let mut device = NoopBackend::open(config.clone()).expect("open");
        assert_eq!(device.opened_with(), Some(&config));

        device.set_addr(address(), 24).expect("addr");
        device.set_mtu(1396).expect("mtu");
        device
            .set_routes(std::slice::from_ref(&route))
            .expect("routes");
        device
            .set_dns(&[IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))])
            .expect("dns");

        assert_eq!(device.address(), Some((address(), 24)));
        assert_eq!(device.mtu(), Some(1396));
        assert_eq!(device.routes(), &[route]);
        assert_eq!(device.dns().len(), 1);
        assert!(!device.is_closed());

        device.close().expect("close");
        device.close().expect("close is idempotent");
        assert!(device.is_closed());
    }

    #[test]
    fn packet_operations_are_unsupported() {
        let mut device = NoopBackend::default();
        let mut buffer = [0u8; 4];
        assert!(matches!(
            device.recv(&mut buffer),
            Err(TunError::Unsupported(_))
        ));
        assert!(matches!(
            device.send(&buffer),
            Err(TunError::Unsupported(_))
        ));
    }

    #[test]
    fn invalid_configuration_is_refused() {
        let bad_prefix = DeviceConfig {
            address: Some(address()),
            prefix_len: 33,
            ..DeviceConfig::default()
        };
        assert!(matches!(
            NoopBackend::open(bad_prefix),
            Err(TunError::InvalidConfig(_))
        ));

        let prefix_without_address = DeviceConfig {
            prefix_len: 24,
            ..DeviceConfig::default()
        };
        assert!(matches!(
            NoopBackend::open(prefix_without_address),
            Err(TunError::InvalidConfig(_))
        ));

        let tiny_mtu = DeviceConfig {
            mtu: 100,
            ..DeviceConfig::default()
        };
        assert!(matches!(
            NoopBackend::open(tiny_mtu),
            Err(TunError::InvalidConfig(_))
        ));
    }
}
