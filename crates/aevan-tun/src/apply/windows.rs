//! Windows applier: `netsh interface ipv4`.
//!
//! The argument vectors are data, not a shell string. `netsh` receives one
//! argument per `name=value` token, which is the form the tool documents.
//! Creating the Wintun adapter still needs Administrator; this module checks
//! elevation before it runs anything.

use std::net::IpAddr;

use super::{ipv4_mask, run_checked};
use crate::command::CommandRunner;
use crate::error::TunError;
use crate::privilege::{elevation, Elevation};
use crate::rollback::{Change, RollbackBackend, UndoOutcome};
use crate::route::Route;

/// Windows `netsh` applier.
pub struct PlatformApplier {
    runner: Box<dyn CommandRunner>,
    interface: String,
}

impl PlatformApplier {
    /// Build the applier without checking privilege. Production callers use
    /// [`super::platform_applier`].
    pub fn new(runner: Box<dyn CommandRunner>, interface: &str) -> Self {
        Self {
            runner,
            interface: interface.to_owned(),
        }
    }

    /// Build the applier after checking for Administrator.
    pub fn open(runner: Box<dyn CommandRunner>, interface: &str) -> Result<Self, TunError> {
        check_prerequisites()?;
        Ok(Self::new(runner, interface))
    }

    fn set_addr(&mut self, address: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        let IpAddr::V4(address) = address else {
            return Err(TunError::Unsupported(
                "the Windows applier applies IPv4 addresses only",
            ));
        };
        let mask = ipv4_mask(prefix_len).ok_or_else(|| {
            TunError::InvalidConfig(format!("prefix /{prefix_len} is invalid for IPv4"))
        })?;
        run_checked(
            self.runner.as_mut(),
            "netsh",
            &[
                "interface".into(),
                "ipv4".into(),
                "set".into(),
                "address".into(),
                format!("name={}", self.interface),
                "source=static".into(),
                format!("address={address}"),
                format!("mask={mask}"),
                "gateway=none".into(),
                "store=active".into(),
            ],
        )
    }

    fn delete_addr(&mut self, address: IpAddr) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "netsh",
            &[
                "interface".into(),
                "ipv4".into(),
                "delete".into(),
                "address".into(),
                format!("name={}", self.interface),
                format!("address={address}"),
            ],
        )
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "netsh",
            &[
                "interface".into(),
                "ipv4".into(),
                "set".into(),
                "subinterface".into(),
                format!("interface={}", self.interface),
                format!("mtu={mtu}"),
                "store=active".into(),
            ],
        )
    }

    fn set_dns(&mut self, servers: &[IpAddr]) -> Result<(), TunError> {
        if servers.is_empty() {
            return run_checked(
                self.runner.as_mut(),
                "netsh",
                &[
                    "interface".into(),
                    "ipv4".into(),
                    "set".into(),
                    "dnsservers".into(),
                    format!("name={}", self.interface),
                    "source=dhcp".into(),
                ],
            );
        }

        for (offset, server) in servers.iter().enumerate() {
            let IpAddr::V4(server) = server else {
                return Err(TunError::Unsupported(
                    "the Windows applier applies IPv4 DNS servers only",
                ));
            };
            if offset == 0 {
                run_checked(
                    self.runner.as_mut(),
                    "netsh",
                    &[
                        "interface".into(),
                        "ipv4".into(),
                        "set".into(),
                        "dnsservers".into(),
                        format!("name={}", self.interface),
                        "source=static".into(),
                        format!("address={server}"),
                        "register=primary".into(),
                        "validate=no".into(),
                    ],
                )?;
            } else {
                let index = offset + 1;
                run_checked(
                    self.runner.as_mut(),
                    "netsh",
                    &[
                        "interface".into(),
                        "ipv4".into(),
                        "add".into(),
                        "dnsservers".into(),
                        format!("name={}", self.interface),
                        format!("address={server}"),
                        format!("index={index}"),
                        "validate=no".into(),
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn add_route(&mut self, route: &Route) -> Result<(), TunError> {
        let interface = self.interface.clone();
        self.add_route_on(&interface, route)
    }

    fn add_route_on(&mut self, interface: &str, route: &Route) -> Result<(), TunError> {
        let mut args = self.route_args_on(interface, "add", route)?;
        if let Some(gateway) = route.gateway {
            args.push(format!("nexthop={gateway}"));
        }
        if route.metric != 0 {
            args.push(format!("metric={}", route.metric));
        }
        run_checked(self.runner.as_mut(), "netsh", &args)
    }

    fn delete_route(&mut self, route: &Route) -> Result<(), TunError> {
        let interface = self.interface.clone();
        self.delete_route_on(&interface, route)
    }

    fn delete_route_on(&mut self, interface: &str, route: &Route) -> Result<(), TunError> {
        let mut args = self.route_args_on(interface, "delete", route)?;
        if let Some(gateway) = route.gateway {
            args.push(format!("nexthop={gateway}"));
        }
        run_checked(self.runner.as_mut(), "netsh", &args)
    }

    /// Whether the interface alias still exists. This is the cheap check that
    /// lets recovery skip every device-scoped inverse after a hard kill.
    fn interface_present(&mut self) -> Result<bool, TunError> {
        let output = self.runner.run(
            "netsh",
            &[
                "interface",
                "show",
                "interface",
                &format!("name={}", self.interface),
            ],
        )?;
        if output.status.success() {
            return Ok(true);
        }
        // A missing alias is an ordinary "not registered"/"not found" answer.
        // Any other failure (for example access denied) must stay a real error
        // so recovery retains the journal instead of deleting evidence.
        let error = super::command_failure("netsh", &output);
        if error.is_already_absent() {
            Ok(false)
        } else {
            Err(error)
        }
    }

    fn delete_or_absent(&mut self, result: Result<(), TunError>) -> Result<UndoOutcome, TunError> {
        match result {
            Ok(()) => Ok(UndoOutcome::RolledBack),
            Err(error) if error.is_already_absent() => Ok(UndoOutcome::AlreadyAbsent),
            Err(error) => Err(error),
        }
    }

    fn undo_inverse(&mut self, inverse: Change) -> Result<UndoOutcome, TunError> {
        match inverse {
            Change::SetAddr {
                old: Some((address, _)),
                new: None,
            } => {
                let result = self.delete_addr(address);
                self.delete_or_absent(result)
            }
            Change::SetMtu { new: None, .. } => {
                // The previous MTU is unknown; closing the adapter restores
                // the interface default, so there is nothing to run.
                Ok(UndoOutcome::RolledBack)
            }
            Change::SetRoutes { old, new } => {
                let diff = crate::route::diff_routes(&old, &new);
                let mut rolled_back = false;
                for route in &diff.to_remove {
                    let result = self.delete_route(route);
                    if self.delete_or_absent(result)? == UndoOutcome::RolledBack {
                        rolled_back = true;
                    }
                }
                for route in &diff.to_add {
                    self.add_route(route)?;
                    rolled_back = true;
                }
                Ok(if rolled_back {
                    UndoOutcome::RolledBack
                } else {
                    UndoOutcome::AlreadyAbsent
                })
            }
            Change::RemoveRoute(route) => {
                let result = self.delete_route(&route);
                self.delete_or_absent(result)
            }
            other => {
                self.apply(&other)?;
                Ok(UndoOutcome::RolledBack)
            }
        }
    }

    fn route_args_on(
        &self,
        interface: &str,
        verb: &str,
        route: &Route,
    ) -> Result<Vec<String>, TunError> {
        let IpAddr::V4(destination) = route.destination else {
            return Err(TunError::Unsupported(
                "the Windows applier applies IPv4 routes only",
            ));
        };
        Ok(vec![
            "interface".into(),
            "ipv4".into(),
            verb.into(),
            "route".into(),
            format!("{destination}/{}", route.prefix_len),
            format!("interface={interface}"),
        ])
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
                    self.delete_route(route)?;
                }
                for route in &diff.to_add {
                    self.add_route(route)?;
                }
                Ok(())
            }
            Change::SetDns { new, .. } => self.set_dns(new),
            Change::AddRoute(route) => self.add_route(route),
            Change::RemoveRoute(route) => self.delete_route(route),
            Change::ReplaceRoute {
                route,
                displaced,
                restore,
            } => {
                let displaced_route = displaced.to_route()?;
                if *restore {
                    match self.delete_route(route) {
                        Ok(()) => {}
                        Err(error) if error.is_already_absent() => {}
                        Err(error) => return Err(error),
                    }
                    self.add_route_on(&displaced.interface, &displaced_route)
                } else {
                    match self.delete_route_on(&displaced.interface, &displaced_route) {
                        Ok(()) => {}
                        Err(error) if error.is_already_absent() => {}
                        Err(error) => return Err(error),
                    }
                    self.add_route(route)
                }
            }
        }
    }

    fn device_present(&mut self) -> Result<bool, TunError> {
        self.interface_present()
    }

    fn undo(&mut self, change: &Change) -> Result<UndoOutcome, TunError> {
        if !self.interface_present()? {
            return Ok(UndoOutcome::AlreadyAbsent);
        }
        self.undo_inverse(change.inverse())
    }
}

impl super::Applier for PlatformApplier {
    fn backend_name(&self) -> &'static str {
        "windows-netsh"
    }
}

/// Check the Windows prerequisite for applying configuration.
pub fn check_prerequisites() -> Result<(), TunError> {
    check_prerequisites_observed(elevation())
}

/// Check the Windows prerequisite using an already-observed elevation value.
pub fn check_prerequisites_observed(observed: Elevation) -> Result<(), TunError> {
    check_privilege(observed)
}

/// Pure privilege check, so tests can assert the refusal without elevation.
pub fn check_privilege(observed: Elevation) -> Result<(), TunError> {
    match observed {
        Elevation::Elevated => Ok(()),
        Elevation::NotElevated => Err(TunError::Permission(
            "Administrator elevation is required to configure the Wintun adapter".into(),
        )),
        Elevation::Unknown => Err(TunError::Permission(
            "could not determine whether the process is running as Administrator".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RecordingRunner;
    use crate::rollback::{RollbackBackend, Session};
    use std::net::Ipv4Addr;

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn calls(runner: &RecordingRunner) -> Vec<Vec<String>> {
        runner.calls().into_iter().map(|call| call.args).collect()
    }

    #[test]
    fn not_elevated_is_a_typed_permission_error() {
        assert!(matches!(
            check_privilege(Elevation::NotElevated),
            Err(TunError::Permission(_))
        ));
        assert!(matches!(
            check_privilege(Elevation::Unknown),
            Err(TunError::Permission(_))
        ));
        assert!(check_privilege(Elevation::Elevated).is_ok());
    }

    #[test]
    fn address_and_rollback_use_the_exact_netsh_vectors() {
        let runner = RecordingRunner::new();
        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "Aevan",
        ));

        session
            .apply(Change::SetAddr {
                old: None,
                new: Some((v4([10, 251, 98, 43]), 24)),
            })
            .expect("apply address");
        session.rollback().expect("rollback");

        let calls = calls(&runner);
        assert_eq!(
            calls[0],
            vec![
                "interface",
                "ipv4",
                "set",
                "address",
                "name=Aevan",
                "source=static",
                "address=10.251.98.43",
                "mask=255.255.255.0",
                "gateway=none",
                "store=active",
            ]
        );
        assert_eq!(
            calls[1],
            vec![
                "interface",
                "ipv4",
                "delete",
                "address",
                "name=Aevan",
                "address=10.251.98.43",
            ]
        );
        assert!(runner.calls().iter().all(|call| call.program == "netsh"));
    }

    #[test]
    fn route_add_and_delete_use_netsh_delete_route_for_the_inverse() {
        let runner = RecordingRunner::new();
        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "Aevan",
        ));
        let route = Route::on_link(v4([10, 0, 0, 0]), 8).expect("route");

        session.apply(Change::AddRoute(route)).expect("add");
        session.rollback().expect("rollback");

        let calls = calls(&runner);
        assert_eq!(
            calls[0],
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "10.0.0.0/8",
                "interface=Aevan",
            ]
        );
        assert_eq!(
            calls[1],
            vec![
                "interface",
                "ipv4",
                "delete",
                "route",
                "10.0.0.0/8",
                "interface=Aevan",
            ]
        );
    }

    #[test]
    fn dns_set_and_restore_use_the_exact_netsh_vectors() {
        let runner = RecordingRunner::new();
        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "Aevan",
        ));
        session
            .apply(Change::SetDns {
                old: Vec::new(),
                new: vec![v4([10, 251, 3, 18]), v4([10, 249, 10, 13])],
                context: crate::rollback::DnsContext::Unspecified,
            })
            .expect("apply dns");
        session.rollback().expect("rollback");

        let calls = calls(&runner);
        assert_eq!(
            calls[0],
            vec![
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                "name=Aevan",
                "source=static",
                "address=10.251.3.18",
                "register=primary",
                "validate=no",
            ]
        );
        assert_eq!(
            calls[1],
            vec![
                "interface",
                "ipv4",
                "add",
                "dnsservers",
                "name=Aevan",
                "address=10.249.10.13",
                "index=2",
                "validate=no",
            ]
        );
        assert_eq!(
            calls[2],
            vec![
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                "name=Aevan",
                "source=dhcp",
            ]
        );
    }

    #[test]
    fn rollback_order_is_the_reverse_of_apply() {
        let runner = RecordingRunner::new();
        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "Aevan",
        ));
        session
            .apply(Change::SetAddr {
                old: None,
                new: Some((v4([10, 251, 98, 43]), 24)),
            })
            .expect("address");
        session
            .apply(Change::SetMtu {
                old: None,
                new: Some(1396),
            })
            .expect("mtu");
        session
            .apply(Change::AddRoute(
                Route::on_link(v4([10, 0, 0, 0]), 8).expect("route"),
            ))
            .expect("route");
        session
            .apply(Change::SetDns {
                old: Vec::new(),
                new: vec![v4([10, 251, 3, 18])],
                context: crate::rollback::DnsContext::Unspecified,
            })
            .expect("dns");
        session.rollback().expect("rollback");

        let calls = calls(&runner);
        // Forward: address, mtu, route, dns. Reverse: dns, route, mtu(none),
        // address.
        assert_eq!(calls.len(), 7);
        assert_eq!(calls[0][2], "set");
        assert_eq!(calls[0][3], "address");
        assert_eq!(calls[1][3], "subinterface");
        assert_eq!(calls[2][2], "add");
        assert_eq!(calls[2][3], "route");
        assert_eq!(calls[3][3], "dnsservers");
        assert_eq!(calls[4][2], "set");
        assert_eq!(calls[4][3], "dnsservers");
        assert_eq!(calls[5][2], "delete");
        assert_eq!(calls[5][3], "route");
        assert_eq!(calls[6][2], "delete");
        assert_eq!(calls[6][3], "address");
    }

    #[test]
    fn ipv6_is_refused_without_running_a_command() {
        let runner = RecordingRunner::new();
        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "Aevan");
        let result = applier.apply(&Change::SetAddr {
            old: None,
            new: Some((IpAddr::V6("2001:db8::1".parse().expect("v6")), 64)),
        });
        assert!(matches!(result, Err(TunError::Unsupported(_))));
        assert!(runner.calls().is_empty());
    }
}
