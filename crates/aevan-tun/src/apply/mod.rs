//! Per-OS route, address, MTU and DNS application.
//!
//! Every applier turns a [`crate::rollback::Change`] into one or more program
//! invocations through a [`CommandRunner`] and implements
//! [`crate::rollback::RollbackBackend`], so [`crate::rollback::Session`] drives
//! both setup and teardown. The inverse of each step is
//! [`crate::rollback::Change::inverse`]; the session applies that inverse in
//! reverse order on rollback or on drop.
//!
//! The per-OS modules are compiled behind `cfg`:
//!
//! * Windows: `netsh interface ipv4` (address, subinterface MTU, DNS servers,
//!   routes). `netsh interface ipv4 delete route` backs out a route.
//! * Linux: `ip addr add|del`, `ip link set ... mtu`, `ip route add|del`.
//!   systemd-resolved/resolvconf DNS integration is a documented TODO.
//! * macOS: `ifconfig utunN`, `route -n add|delete`. `scutil` DNS integration
//!   is a documented TODO.
//!
//! No applier elevates. [`platform_applier`] checks the platform prerequisite
//! first and returns [`crate::TunError::Permission`] or
//! [`crate::TunError::Unsupported`] instead of running a command that is
//! certain to fail.

use crate::command::{CommandRunner, Output};
use crate::error::TunError;
use crate::privilege::Elevation;
use crate::rollback::{Change, RollbackBackend};

/// An applier for one platform.
pub trait Applier: RollbackBackend {
    /// Stable backend name, for logs and tests.
    fn backend_name(&self) -> &'static str;
}

impl RollbackBackend for Box<dyn Applier> {
    fn apply(&mut self, change: &Change) -> Result<(), TunError> {
        (**self).apply(change)
    }
}

/// Build the current platform's applier after checking its prerequisite.
///
/// `interface` is the device name the commands target. It must match the name
/// used to open the device.
pub fn platform_applier(
    runner: Box<dyn CommandRunner>,
    interface: &str,
) -> Result<Box<dyn Applier>, TunError> {
    Ok(Box::new(imp::PlatformApplier::open(runner, interface)?))
}

/// Build the current platform's applier without the prerequisite check.
///
/// Recovery uses this because it probes device presence before deciding
/// whether elevation is needed. A probe such as `netsh interface show
/// interface` needs no Administrator. Ordinary callers must use
/// [`platform_applier`], which checks the prerequisite first.
pub fn platform_applier_unchecked(
    runner: Box<dyn CommandRunner>,
    interface: &str,
) -> Box<dyn Applier> {
    Box::new(imp::PlatformApplier::new(runner, interface))
}

/// Check the platform prerequisite using an already-observed elevation value.
///
/// Windows and macOS act on the observation; Linux checks `/dev/net/tun`,
/// which does not itself require elevation. Tests use this to assert recovery
/// ordering without touching the real process token.
pub fn check_prerequisites_observed(observed: Elevation) -> Result<(), TunError> {
    imp::check_prerequisites_observed(observed)
}

/// Turn a device configuration into the ordered setup plan.
///
/// Order is address, MTU, routes, DNS. Each returned [`Change`] records its own
/// inverse, so a failed step only rolls back what was already applied.
pub fn plan(config: &crate::device::DeviceConfig) -> Vec<Change> {
    let mut changes = Vec::new();
    if let Some(address) = config.address {
        changes.push(Change::SetAddr {
            old: None,
            new: Some((address, config.prefix_len)),
        });
    }
    if config.mtu != 0 {
        changes.push(Change::SetMtu {
            old: None,
            new: Some(config.mtu),
        });
    }
    for route in &config.routes {
        changes.push(Change::AddRoute(route.clone()));
    }
    if !config.dns.is_empty() {
        changes.push(Change::SetDns {
            old: Vec::new(),
            new: config.dns.clone(),
        });
    }
    changes
}

/// Human-readable step name for error reporting.
pub fn step_name(change: &Change) -> &'static str {
    match change {
        Change::SetAddr { .. } => "address",
        Change::SetMtu { .. } => "mtu",
        Change::SetRoutes { .. } | Change::AddRoute(_) | Change::RemoveRoute(_) => "route",
        Change::SetDns { .. } => "dns",
    }
}

/// Dotted-quad netmask for an IPv4 prefix length.
///
/// Only the Windows netsh backend needs a dotted netmask; the Unix backends
/// take the prefix length directly.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn ipv4_mask(prefix_len: u8) -> Option<std::net::Ipv4Addr> {
    if prefix_len > 32 {
        return None;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Some(std::net::Ipv4Addr::from(mask))
}

/// Run one command and turn a non-zero exit into a typed I/O error.
pub(crate) fn run_checked(
    runner: &mut dyn CommandRunner,
    program: &str,
    args: &[String],
) -> Result<(), TunError> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = runner.run(program, &borrowed)?;
    if output.status.success() {
        return Ok(());
    }
    Err(command_failure(program, &output))
}

/// Turn a failed command into a typed error whose text can be classified as
/// "already absent" by [`TunError::is_already_absent`].
pub(crate) fn command_failure(program: &str, output: &Output) -> TunError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // netsh sometimes writes its diagnostic to stdout rather than stderr, so
    // prefer stderr but fall back to stdout before reporting only the status.
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    let detail = if detail.is_empty() {
        format!("{program} exited with {}", output.status)
    } else {
        format!("{program} exited with {}: {detail}", output.status)
    };
    TunError::Io(std::io::Error::other(detail))
}

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as imp;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod other;
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
use other as imp;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceConfig;
    use crate::rollback::Session;
    use crate::route::Route;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn the_plan_is_address_mtu_routes_dns_in_that_order() {
        let route = Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route");
        let config = DeviceConfig {
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43))),
            prefix_len: 24,
            mtu: 1396,
            routes: vec![route.clone()],
            dns: vec![IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))],
            ..DeviceConfig::default()
        };

        let changes = plan(&config);
        assert_eq!(changes.len(), 4);
        assert!(matches!(changes[0], Change::SetAddr { .. }));
        assert!(matches!(changes[1], Change::SetMtu { .. }));
        assert_eq!(changes[2], Change::AddRoute(route));
        assert!(matches!(changes[3], Change::SetDns { .. }));
    }

    #[test]
    fn the_plan_skips_absent_values() {
        let changes = plan(&DeviceConfig::default());
        assert!(changes.is_empty());
    }

    #[test]
    fn an_unchecked_plan_can_be_rolled_back_through_a_session() {
        // Uses the platform applier without requiring privilege. The command
        // runner records, so this test never touches the network stack.
        let runner = crate::command::RecordingRunner::new();
        let applier = platform_applier_unchecked(Box::new(runner.clone()), "aevan");
        let mut session = Session::new(applier);
        session
            .apply(Change::SetMtu {
                old: None,
                new: Some(1396),
            })
            .expect("mtu");
        session.rollback().expect("rollback");
        assert!(session.is_closed());
        // The runner recorded at least the forward command on every platform
        // that has an implementation.
        assert!(
            !runner.calls().is_empty()
                || cfg!(not(any(
                    target_os = "windows",
                    target_os = "linux",
                    target_os = "macos"
                )))
        );
    }

    #[test]
    fn ipv4_masks_cover_the_prefix_range() {
        assert_eq!(ipv4_mask(0), Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(ipv4_mask(24), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(ipv4_mask(32), Some(Ipv4Addr::new(255, 255, 255, 255)));
        assert_eq!(ipv4_mask(33), None);
    }
}
