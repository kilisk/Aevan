//! Linux applier: `ip` for address, MTU and routes.
//!
//! DNS integration through systemd-resolved or `resolvconf` is a documented
//! TODO: this build refuses it with a typed [`TunError::Unsupported`] rather
//! than silently leaving the resolver pointing at the wrong servers. The
//! `/dev/net/tun` prerequisite is checked before any command runs.

use std::net::IpAddr;
use std::path::Path;

use super::run_checked;
use crate::command::CommandRunner;
use crate::error::TunError;
use crate::rollback::{Change, RollbackBackend};
use crate::route::Route;

/// Linux `ip` applier.
pub struct PlatformApplier {
    runner: Box<dyn CommandRunner>,
    interface: String,
}

impl PlatformApplier {
    /// Build the applier without checking `/dev/net/tun`.
    pub fn new(runner: Box<dyn CommandRunner>, interface: &str) -> Self {
        Self {
            runner,
            interface: interface.to_owned(),
        }
    }

    /// Build the applier after checking for `/dev/net/tun`.
    pub fn open(runner: Box<dyn CommandRunner>, interface: &str) -> Result<Self, TunError> {
        check_prerequisites()?;
        Ok(Self::new(runner, interface))
    }

    fn addr(&mut self, verb: &str, address: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "ip",
            &[
                "addr".into(),
                verb.into(),
                format!("{address}/{prefix_len}"),
                "dev".into(),
                self.interface.clone(),
            ],
        )
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "ip",
            &[
                "link".into(),
                "set".into(),
                "dev".into(),
                self.interface.clone(),
                "mtu".into(),
                format!("{mtu}"),
            ],
        )
    }

    fn route(&mut self, verb: &str, route: &Route) -> Result<(), TunError> {
        let mut args = vec![
            "route".into(),
            verb.into(),
            format!("{}/{}", route.destination, route.prefix_len),
            "dev".into(),
            self.interface.clone(),
        ];
        if let Some(gateway) = route.gateway {
            args.push("via".into());
            args.push(format!("{gateway}"));
        }
        if route.metric != 0 {
            args.push("metric".into());
            args.push(format!("{}", route.metric));
        }
        run_checked(self.runner.as_mut(), "ip", &args)
    }
}

impl RollbackBackend for PlatformApplier {
    fn apply(&mut self, change: &Change) -> Result<(), TunError> {
        match change {
            Change::SetAddr { old, new } => match new {
                Some((address, prefix_len)) => self.addr("add", *address, *prefix_len),
                None => match old {
                    Some((address, prefix_len)) => self.addr("del", *address, *prefix_len),
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
                    self.route("del", route)?;
                }
                for route in &diff.to_add {
                    self.route("add", route)?;
                }
                Ok(())
            }
            // A documented TODO: implementing this requires knowing whether
            // systemd-resolved, resolvconf or NetworkManager owns the link.
            Change::SetDns { .. } => Err(TunError::Unsupported(
                "Linux DNS application (systemd-resolved/resolvconf) is not implemented yet",
            )),
            Change::AddRoute(route) => self.route("add", route),
            Change::RemoveRoute(route) => self.route("del", route),
        }
    }
}

impl super::Applier for PlatformApplier {
    fn backend_name(&self) -> &'static str {
        "linux-ip"
    }
}

/// Check the Linux prerequisite for applying configuration.
pub fn check_prerequisites() -> Result<(), TunError> {
    if Path::new("/dev/net/tun").exists() {
        Ok(())
    } else {
        Err(TunError::Unsupported(
            "/dev/net/tun is missing; load the tun module or use a kernel with CONFIG_TUN",
        ))
    }
}

/// Check the Linux prerequisite. The observed elevation value is irrelevant:
/// this platform checks for `/dev/net/tun` instead.
pub fn check_prerequisites_observed(
    _observed: crate::privilege::Elevation,
) -> Result<(), TunError> {
    check_prerequisites()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::RecordingRunner;
    use crate::rollback::Session;
    use std::net::Ipv4Addr;

    #[test]
    fn address_route_and_mtu_use_ip_with_separate_arguments() {
        let runner = RecordingRunner::new();
        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "aevan0",
        ));
        session
            .apply(Change::SetAddr {
                old: None,
                new: Some((IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43)), 24)),
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
                Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route"),
            ))
            .expect("route");
        session.rollback().expect("rollback");

        let calls: Vec<Vec<String>> = runner.calls().into_iter().map(|call| call.args).collect();
        assert_eq!(
            calls[0],
            vec!["addr", "add", "10.251.98.43/24", "dev", "aevan0"]
        );
        assert_eq!(
            calls[1],
            vec!["link", "set", "dev", "aevan0", "mtu", "1396"]
        );
        assert_eq!(
            calls[2],
            vec!["route", "add", "10.0.0.0/8", "dev", "aevan0"]
        );
        assert_eq!(
            calls[3],
            vec!["route", "del", "10.0.0.0/8", "dev", "aevan0"]
        );
        // Rollback undoes the address but emits nothing for the MTU: the change
        // recorded `old: None`, so there is no previous value to restore, and a
        // rollback step with nothing to undo is skipped rather than re-issuing
        // the value we applied.
        assert_eq!(
            calls[4],
            vec!["addr", "del", "10.251.98.43/24", "dev", "aevan0"]
        );
        assert_eq!(
            calls.len(),
            5,
            "no command may be issued for an empty restore"
        );
    }

    #[test]
    fn dns_is_a_typed_todo_and_is_not_applied() {
        let runner = RecordingRunner::new();
        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "aevan0");
        let result = applier.apply(&Change::SetDns {
            old: Vec::new(),
            new: vec![IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))],
            context: crate::rollback::DnsContext::Unspecified,
        });
        assert!(matches!(result, Err(TunError::Unsupported(_))));
        assert!(runner.calls().is_empty());
    }
}
