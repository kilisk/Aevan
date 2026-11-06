//! macOS applier: `ifconfig` and `route`.
//!
//! The `utunN` interface is created by the device backend. This applier only
//! configures it. DNS through `scutil` is a documented TODO and is refused with
//! a typed [`TunError::Unsupported`] instead of silently doing nothing.

use std::net::IpAddr;

use super::{ipv4_mask, run_checked};
use crate::command::CommandRunner;
use crate::error::TunError;
use crate::rollback::{Change, RollbackBackend};
use crate::route::Route;

/// macOS `ifconfig`/`route` applier.
pub struct PlatformApplier {
    runner: Box<dyn CommandRunner>,
    interface: String,
}

impl PlatformApplier {
    /// Build the applier.
    pub fn new(runner: Box<dyn CommandRunner>, interface: &str) -> Self {
        Self {
            runner,
            interface: interface.to_owned(),
        }
    }

    /// Build the applier after the privilege check.
    pub fn open(runner: Box<dyn CommandRunner>, interface: &str) -> Result<Self, TunError> {
        check_prerequisites()?;
        Ok(Self::new(runner, interface))
    }

    fn set_addr(&mut self, address: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        let IpAddr::V4(address) = address else {
            return Err(TunError::Unsupported(
                "the macOS applier applies IPv4 addresses only",
            ));
        };
        let mask = ipv4_mask(prefix_len).ok_or_else(|| {
            TunError::InvalidConfig(format!("prefix /{prefix_len} is invalid for IPv4"))
        })?;
        run_checked(
            self.runner.as_mut(),
            "ifconfig",
            &[
                self.interface.clone(),
                "inet".into(),
                format!("{address}"),
                format!("{address}"),
                "netmask".into(),
                format!("{mask}"),
            ],
        )
    }

    fn delete_addr(&mut self, address: IpAddr) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "ifconfig",
            &[
                self.interface.clone(),
                "inet".into(),
                format!("{address}"),
                "-alias".into(),
            ],
        )
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "ifconfig",
            &[self.interface.clone(), "mtu".into(), format!("{mtu}")],
        )
    }

    fn route(&mut self, verb: &str, route: &Route) -> Result<(), TunError> {
        let mut args = vec![
            "-n".into(),
            verb.into(),
            "-net".into(),
            format!("{}/{}", route.destination, route.prefix_len),
        ];
        match route.gateway {
            Some(gateway) => args.push(format!("{gateway}")),
            None => {
                args.push("-interface".into());
                args.push(self.interface.clone());
            }
        }
        run_checked(self.runner.as_mut(), "route", &args)
    }
}

impl RollbackBackend for PlatformApplier {
    fn apply(&mut self, change: &Change) -> Result<(), TunError> {
        match change {
            Change::SetAddr { old, new } => match new {
                Some((address, prefix_len)) => self.set_addr(*address, *prefix_len),
                None => match old {
                    Some((address, _)) => self.delete_addr(*address),
                    None => Ok(()),
                },
            },
            Change::SetMtu { new, .. } => match new {
                Some(mtu) => self.set_mtu(*mtu),
                // The previous MTU is unknown; removing the device restores
                // the interface default, so there is nothing to run.
                None => Ok(()),
            },
            Change::SetRoutes { old, new } => {
                let diff = crate::route::diff_routes(old, new);
                for route in &diff.to_remove {
                    self.route("delete", route)?;
                }
                for route in &diff.to_add {
                    self.route("add", route)?;
                }
                Ok(())
            }
            // A documented TODO: scutil resolver entries are per-domain and
            // need a restore journal of their own.
            Change::SetDns { .. } => Err(TunError::Unsupported(
                "macOS DNS application through scutil is not implemented yet",
            )),
            Change::AddRoute(route) => self.route("add", route),
            Change::RemoveRoute(route) => self.route("delete", route),
        }
    }
}

impl super::Applier for PlatformApplier {
    fn backend_name(&self) -> &'static str {
        "macos-ifconfig"
    }
}

/// Check the macOS prerequisite for applying configuration.
pub fn check_prerequisites() -> Result<(), TunError> {
    check_prerequisites_observed(crate::privilege::elevation())
}

/// Check the macOS prerequisite using an already-observed elevation value.
pub fn check_prerequisites_observed(observed: crate::privilege::Elevation) -> Result<(), TunError> {
    match observed {
        crate::privilege::Elevation::Elevated => Ok(()),
        _ => Err(TunError::Permission(
            "root elevation is required to configure a utun interface".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RecordingRunner;
    use crate::rollback::Session;
    use std::net::Ipv4Addr;

    #[test]
    fn ifconfig_and_route_vectors_are_separate_arguments() {
        let runner = RecordingRunner::new();
        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "utun3",
        ));
        session
            .apply(Change::SetAddr {
                old: None,
                new: Some((IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43)), 24)),
            })
            .expect("address");
        session
            .apply(Change::AddRoute(
                Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route"),
            ))
            .expect("route");
        session.rollback().expect("rollback");

        let calls: Vec<Vec<String>> = runner.calls().into_iter().map(|call| call.args).collect();
        assert_eq!(
            calls[0],
            vec![
                "utun3",
                "inet",
                "10.251.98.43",
                "10.251.98.43",
                "netmask",
                "255.255.255.0",
            ]
        );
        assert_eq!(
            calls[1],
            vec!["-n", "add", "-net", "10.0.0.0/8", "-interface", "utun3"]
        );
        assert_eq!(
            calls[2],
            vec!["-n", "delete", "-net", "10.0.0.0/8", "-interface", "utun3"]
        );
    }

    #[test]
    fn dns_is_a_typed_todo_and_is_not_applied() {
        let runner = RecordingRunner::new();
        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let result = applier.apply(&Change::SetDns {
            old: Vec::new(),
            new: vec![IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))],
        });
        assert!(matches!(result, Err(TunError::Unsupported(_))));
        assert!(runner.calls().is_empty());
    }
}
