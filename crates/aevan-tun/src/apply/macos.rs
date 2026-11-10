//! macOS applier: `ifconfig`, `route` and `networksetup`.
//!
//! The `utunN` interface is created by the device backend. This applier only
//! configures it.
//!
//! DNS is applied to the primary network service, not to the tunnel link:
//! `networksetup` only has interface-wide settings, and the gateway pushes
//! servers without search domains, so per-domain split DNS is not available.
//! That is the honest behaviour for a split-route tunnel. The current servers
//! and the chosen service are captured before apply and stored in the journal,
//! so revert restores exactly what was there even if the service order changes.

use std::net::IpAddr;

use super::{ipv4_mask, run_checked};
use crate::command::{CommandRunner, Output};
use crate::error::TunError;
use crate::rollback::{Change, DnsContext, RollbackBackend, UndoOutcome};
use crate::route::{Route, RouteRecord};

const EMPTY_DNS_MARKER: &str = "There aren't any DNS Servers set on";

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

    /// Run one route command and log its exact argument vector and exit
    /// status. A route add or delete must never be skipped silently.
    fn run_route(&mut self, args: &[String]) -> Result<Output, TunError> {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.runner.run("route", &borrowed)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::info!(
            program = "route",
            args = ?args,
            status = %output.status,
            success = output.status.success(),
            stderr = stderr.trim(),
            "route command"
        );
        Ok(output)
    }

    fn checked_route(&mut self, args: &[String]) -> Result<(), TunError> {
        let output = self.run_route(args)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(super::command_failure("route", &output))
        }
    }

    fn add_route(&mut self, interface: &str, route: &Route, ifscope: bool) -> Result<(), TunError> {
        let mut args = vec![
            "-n".into(),
            "add".into(),
            "-net".into(),
            format!("{}/{}", route.destination, route.prefix_len),
        ];
        match route.gateway {
            Some(gateway) => args.push(format!("{gateway}")),
            None => {
                args.push("-interface".into());
                args.push(interface.to_owned());
            }
        }
        if ifscope {
            args.push("-ifscope".into());
            args.push(interface.to_owned());
        }
        self.checked_route(&args)
    }

    fn delete_route(
        &mut self,
        interface: &str,
        route: &Route,
        ifscope: bool,
    ) -> Result<(), TunError> {
        let mut args = vec![
            "-n".into(),
            "delete".into(),
            "-net".into(),
            format!("{}/{}", route.destination, route.prefix_len),
        ];
        match route.gateway {
            Some(gateway) => args.push(format!("{gateway}")),
            None => {
                args.push("-interface".into());
                args.push(interface.to_owned());
            }
        }
        if ifscope {
            args.push("-ifscope".into());
            args.push(interface.to_owned());
        }
        self.checked_route(&args)
    }

    fn add_our_route(&mut self, route: &Route, ifscope: bool) -> Result<(), TunError> {
        let interface = self.interface.clone();
        self.add_route(&interface, route, ifscope)
    }

    fn delete_our_route(
        &mut self,
        route: &Route,
        ifscope: bool,
        lenient: bool,
    ) -> Result<(), TunError> {
        let interface = self.interface.clone();
        match self.delete_route(&interface, route, ifscope) {
            Ok(()) => Ok(()),
            Err(error) if lenient && error.is_already_absent() => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read the exact route for `route`'s prefix from the live table.
    ///
    /// A less-specific route is not a conflict and is not returned.
    fn current_route(&mut self, route: &Route) -> Result<Option<RouteRecord>, TunError> {
        let args = vec![
            "-n".into(),
            "get".into(),
            format!("{}/{}", route.destination, route.prefix_len),
        ];
        let text = match self.capture("route", &args)? {
            Some(text) => text,
            None => return Ok(None),
        };
        Ok(parse_route_record(&text).filter(|record| record.same_prefix(route)))
    }

    /// The exact prefix is already owned by a different interface.
    fn conflicting_route(&mut self, route: &Route) -> Result<Option<RouteRecord>, TunError> {
        match self.current_route(route)? {
            Some(record) if record.interface != self.interface => Ok(Some(record)),
            _ => Ok(None),
        }
    }

    /// Delete the foreign route recorded before the journal entry was written.
    fn delete_record(&mut self, record: &RouteRecord) -> Result<(), TunError> {
        let route = record.to_route()?;
        match self.delete_route(&record.interface, &route, record.is_ifscoped()) {
            Ok(()) => Ok(()),
            Err(error) if error.is_already_absent() => Ok(()),
            Err(error) => Err(TunError::Io(std::io::Error::other(format!(
                "cannot delete the conflicting route {} on {}: {error}",
                record.cidr(),
                record.interface
            )))),
        }
    }

    /// Put a displaced route back. A route already matching the record makes
    /// this idempotent after a partial recovery.
    fn restore_record(&mut self, record: &RouteRecord) -> Result<(), TunError> {
        let route = record.to_route()?;
        if let Some(current) = self.current_route(&route)? {
            if current.interface == record.interface {
                return Ok(());
            }
        }
        self.add_route(&record.interface, &route, record.is_ifscoped())
    }

    /// Re-read the table and fail when a pushed route is not where it belongs.
    fn verify_route(&mut self, route: &Route) -> Result<(), TunError> {
        match self.current_route(route)? {
            Some(record) => {
                if let Some(gateway) = route.gateway {
                    if record.gateway == Some(gateway) {
                        Ok(())
                    } else {
                        Err(TunError::Io(std::io::Error::other(format!(
                            "route {} was not applied with gateway {}; it uses {:?}",
                            record.cidr(),
                            gateway,
                            record.gateway
                        ))))
                    }
                } else if record.interface == self.interface {
                    Ok(())
                } else {
                    Err(TunError::Io(std::io::Error::other(format!(
                        "route {} was not applied to {}; it is on {}",
                        record.cidr(),
                        self.interface,
                        record.interface
                    ))))
                }
            }
            None => Err(TunError::Io(std::io::Error::other(format!(
                "route {}/{} is missing after apply",
                route.destination, route.prefix_len
            )))),
        }
    }

    /// Add a route, replacing a foreign exact-prefix route when the platform
    /// reports that the prefix already exists. A route already on our own
    /// interface is accepted as-is and never deleted.
    fn install_our_route(
        &mut self,
        route: &Route,
        ifscope: bool,
        allow_replace: bool,
    ) -> Result<(), TunError> {
        match self.add_our_route(route, ifscope) {
            Ok(()) => Ok(()),
            Err(error) => {
                let Some(record) = self.current_route(route)? else {
                    return Err(error);
                };
                if record.interface == self.interface {
                    return Ok(());
                }
                if !allow_replace {
                    return Err(error);
                }
                self.delete_record(&record)?;
                self.add_our_route(route, true)
            }
        }
    }

    fn capture(&mut self, program: &str, args: &[String]) -> Result<Option<String>, TunError> {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.runner.run(program, &borrowed)?;
        if output.status.success() {
            Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
        } else {
            Ok(None)
        }
    }

    /// Interface of the default route, when the system reports one.
    fn default_interface(&mut self) -> Option<String> {
        let text = self
            .capture("route", &["-n".into(), "get".into(), "default".into()])
            .ok()??;
        parse_default_interface(&text)
    }

    /// Service name for a device from `networksetup -listnetworkserviceorder`.
    fn service_for_interface(&mut self, interface: &str) -> Option<String> {
        let text = self
            .capture("networksetup", &["-listnetworkserviceorder".into()])
            .ok()??;
        let matches: Vec<String> = parse_service_order(&text)
            .into_iter()
            .filter(|(_, device)| device == interface)
            .map(|(service, _)| service)
            .collect();
        match matches.len() {
            1 => matches.into_iter().next(),
            _ => None,
        }
    }

    /// First enabled service from `networksetup -listallnetworkservices`.
    fn first_enabled_service(&mut self) -> Result<String, TunError> {
        let text = self
            .capture("networksetup", &["-listallnetworkservices".into()])?
            .ok_or_else(|| {
                TunError::Io(std::io::Error::other(
                    "networksetup could not list network services",
                ))
            })?;
        parse_first_enabled_service(&text).ok_or(TunError::Unsupported(
            "macOS reports no enabled network service for DNS",
        ))
    }

    /// Primary service: default-route interface first, then the first enabled
    /// service when the mapping is missing or ambiguous.
    fn primary_service(&mut self) -> Result<String, TunError> {
        if let Some(interface) = self.default_interface() {
            if let Some(service) = self.service_for_interface(&interface) {
                return Ok(service);
            }
        }
        self.first_enabled_service()
    }

    fn service_for(&mut self, context: &DnsContext) -> Result<String, TunError> {
        match context {
            DnsContext::MacosService(service) => Ok(service.clone()),
            _ => self.primary_service(),
        }
    }

    fn get_dns(&mut self, service: &str) -> Result<Vec<IpAddr>, TunError> {
        let text = self
            .capture(
                "networksetup",
                &["-getdnsservers".into(), service.to_owned()],
            )?
            .ok_or_else(|| {
                TunError::Io(std::io::Error::other(format!(
                    "networksetup could not read the DNS servers for {service}"
                )))
            })?;
        Ok(parse_dns_servers(&text))
    }

    fn set_dns(&mut self, service: &str, servers: &[IpAddr]) -> Result<(), TunError> {
        let mut args = vec!["-setdnsservers".to_owned(), service.to_owned()];
        if servers.is_empty() {
            args.push("Empty".to_owned());
        } else {
            args.extend(servers.iter().map(|server| server.to_string()));
        }
        run_checked(self.runner.as_mut(), "networksetup", &args)
    }

    /// Flush the resolver cache. A failure is a warning, never a step failure:
    /// the DNS settings are already what the plan asked for.
    fn flush_dns(&mut self) {
        for (program, args) in [
            ("dscacheutil", vec!["-flushcache"]),
            ("killall", vec!["-HUP", "mDNSResponder"]),
        ] {
            match self.runner.run(program, &args) {
                Ok(output) if output.status.success() => {}
                Ok(output) => warn_flush(program, &super::command_failure(program, &output)),
                Err(error) => warn_flush(program, &error),
            }
        }
    }

    fn apply_dns(&mut self, context: &DnsContext, new: &[IpAddr]) -> Result<(), TunError> {
        let service = self.service_for(context)?;
        self.set_dns(&service, new)?;
        self.flush_dns();
        Ok(())
    }

    fn revert_dns(
        &mut self,
        old: &[IpAddr],
        context: &DnsContext,
    ) -> Result<UndoOutcome, TunError> {
        match self.apply_dns(context, old) {
            Ok(()) => Ok(UndoOutcome::RolledBack),
            Err(error) if error.is_already_absent() => Ok(UndoOutcome::AlreadyAbsent),
            Err(error) => Err(error),
        }
    }
}

fn warn_flush(program: &str, error: &TunError) {
    tracing::warn!(program, %error, "macOS DNS cache flush failed; continuing");
}

/// Parse the `route -n get <prefix>` document.
///
/// Only an exact destination/mask pair is returned. `destination:` and `mask:`
/// are always present for an exact IPv4 route; the interface and gateway are
/// optional depending on whether the route is on-link or through a next hop.
fn parse_route_record(text: &str) -> Option<RouteRecord> {
    let mut destination: Option<IpAddr> = None;
    let mut mask: Option<IpAddr> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut interface: Option<String> = None;
    let mut flags = String::new();

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("destination:") {
            destination = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("mask:") {
            mask = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("gateway:") {
            gateway = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("interface:") {
            interface = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("flags:") {
            flags = rest
                .trim()
                .trim_matches(|character| character == '<' || character == '>')
                .to_owned();
        }
    }

    let destination = destination?;
    let interface = interface?;
    let prefix_len = match (destination, mask) {
        (IpAddr::V4(_), Some(IpAddr::V4(mask))) => u32::from(mask).leading_ones() as u8,
        (IpAddr::V6(_), Some(IpAddr::V6(mask))) => u128::from(mask).leading_ones() as u8,
        _ => return None,
    };
    Some(RouteRecord {
        destination,
        prefix_len,
        gateway,
        interface,
        flags,
        metric: 0,
    })
}

fn parse_default_interface(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("interface:")?;
        let interface = rest.trim();
        (!interface.is_empty()).then(|| interface.to_owned())
    })
}

/// Pair each service name with the device from the following
/// `(Hardware Port: ..., Device: enN)` line.
fn parse_service_order(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('(') {
            if let Some(close) = rest.find(')') {
                let inside = &rest[..close];
                let after = rest[close + 1..].trim();
                if inside
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_digit())
                {
                    current = Some(after.to_owned());
                    continue;
                }
            }
        }
        if let (Some(service), Some(device)) = (current.clone(), device_from_line(trimmed)) {
            pairs.push((service, device));
            current = None;
        }
    }
    pairs
}

fn device_from_line(line: &str) -> Option<String> {
    let index = line.find("Device:")?;
    let rest = line[index + "Device:".len()..].trim();
    let device = rest.split([',', ')']).next()?.trim();
    (!device.is_empty()).then(|| device.to_owned())
}

fn parse_first_enabled_service(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.to_ascii_lowercase().contains("asterisk"))
        .find(|line| !line.starts_with('*'))
        .map(str::to_owned)
}

fn parse_dns_servers(text: &str) -> Vec<IpAddr> {
    if text.contains(EMPTY_DNS_MARKER) {
        return Vec::new();
    }
    text.lines()
        .filter_map(|line| line.trim().parse::<IpAddr>().ok())
        .collect()
}

impl RollbackBackend for PlatformApplier {
    fn prepare(&mut self, change: &mut Change) -> Result<(), TunError> {
        match change {
            Change::SetDns { old, new, context } => {
                if new.is_empty() || !matches!(context, DnsContext::Unspecified) {
                    return Ok(());
                }
                let service = self.primary_service()?;
                *old = self.get_dns(&service)?;
                *context = DnsContext::MacosService(service);
            }
            Change::AddRoute(route) => {
                let route = route.clone();
                if let Some(displaced) = self.conflicting_route(&route)? {
                    *change = Change::ReplaceRoute {
                        route,
                        displaced,
                        restore: false,
                    };
                }
            }
            _ => {}
        }
        Ok(())
    }

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
                    self.delete_our_route(route, false, false)?;
                }
                for route in &diff.to_add {
                    self.install_our_route(route, false, true)?;
                }
                for route in new {
                    self.verify_route(route)?;
                }
                Ok(())
            }
            Change::SetDns { context, new, .. } => {
                if new.is_empty() {
                    // Regression safety: an empty forward list is a revert.
                    self.revert_dns(new, context).map(|_| ())
                } else {
                    self.apply_dns(context, new)
                }
            }
            Change::AddRoute(route) => {
                self.install_our_route(route, false, true)?;
                self.verify_route(route)
            }
            Change::RemoveRoute(route) => self.delete_our_route(route, false, true),
            Change::ReplaceRoute {
                route,
                displaced,
                restore,
            } => {
                if *restore {
                    // Delete ours first, then put the original back.
                    self.delete_our_route(route, true, true)?;
                    self.restore_record(displaced)
                } else {
                    self.delete_record(displaced)?;
                    if let Err(error) = self.add_our_route(route, true) {
                        let _ = self.restore_record(displaced);
                        return Err(error);
                    }
                    if let Err(error) = self.verify_route(route) {
                        let _ = self.delete_our_route(route, true, true);
                        let _ = self.restore_record(displaced);
                        return Err(error);
                    }
                    Ok(())
                }
            }
        }
    }

    fn undo(&mut self, change: &Change) -> Result<UndoOutcome, TunError> {
        match change {
            Change::SetDns { old, context, .. } => self.revert_dns(old, context),
            other => {
                self.apply(&other.inverse())?;
                Ok(UndoOutcome::RolledBack)
            }
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
        runner.respond("route", "");
        runner.respond(
            "route",
            "destination: 10.0.0.0
mask: 255.0.0.0
interface: utun3
flags: <UP,DONE,STATIC>
",
        );
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
            vec!["-n", "get", "10.0.0.0/8"],
            "apply verifies the route by re-reading the table"
        );
        assert_eq!(
            calls[3],
            vec!["-n", "delete", "-net", "10.0.0.0/8", "-interface", "utun3"]
        );
    }

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn service_map(interface: &str, service: &str) -> String {
        format!(
            "An asterisk (*) denotes that a network service is disabled.\n\
             (1) {service}\n\
             (Hardware Port: Ethernet, Device: {interface})\n"
        )
    }

    fn queue_primary_service(runner: &RecordingRunner, interface: &str, service: &str) {
        runner.respond(
            "route",
            &format!("   route to: default\n  interface: {interface}\n"),
        );
        runner.respond("networksetup", &service_map(interface, service));
    }

    #[test]
    fn dns_apply_records_the_old_servers_and_sets_the_new_list() {
        let runner = RecordingRunner::new();
        queue_primary_service(&runner, "en0", "Wi-Fi");
        runner.respond("networksetup", "10.0.0.53\n10.0.0.54\n");

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![v4([10, 251, 3, 18]), v4([10, 249, 10, 13])],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        applier.apply(&change).expect("apply dns");

        assert_eq!(
            change,
            Change::SetDns {
                old: vec![v4([10, 0, 0, 53]), v4([10, 0, 0, 54])],
                new: vec![v4([10, 251, 3, 18]), v4([10, 249, 10, 13])],
                context: DnsContext::MacosService("Wi-Fi".into()),
            }
        );

        let calls = runner.calls();
        let networksetup: Vec<Vec<String>> = calls
            .iter()
            .filter(|call| call.program == "networksetup")
            .map(|call| call.args.clone())
            .collect();
        assert_eq!(networksetup[0], vec!["-listnetworkserviceorder"]);
        assert_eq!(networksetup[1], vec!["-getdnsservers", "Wi-Fi"]);
        assert_eq!(
            networksetup[2],
            vec!["-setdnsservers", "Wi-Fi", "10.251.3.18", "10.249.10.13"]
        );
        // Both flush commands are attempted after the set.
        assert!(calls
            .iter()
            .any(|call| call.program == "dscacheutil" && call.args == vec!["-flushcache"]));
        assert!(calls
            .iter()
            .any(|call| call.program == "killall" && call.args == vec!["-HUP", "mDNSResponder"]));
    }

    #[test]
    fn revert_restores_the_recorded_servers() {
        let runner = RecordingRunner::new();
        queue_primary_service(&runner, "en0", "Wi-Fi");

        let mut session = Session::new(crate::apply::platform_applier_unchecked(
            Box::new(runner.clone()),
            "utun3",
        ));
        session
            .apply(Change::SetDns {
                old: vec![v4([10, 0, 0, 53])],
                new: vec![v4([10, 251, 3, 18])],
                context: DnsContext::MacosService("Wi-Fi".into()),
            })
            .expect("apply");
        session.rollback().expect("rollback");

        let networksetup: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .filter(|call| call.program == "networksetup")
            .map(|call| call.args)
            .collect();
        assert_eq!(
            networksetup[0],
            vec!["-setdnsservers", "Wi-Fi", "10.251.3.18"]
        );
        assert_eq!(
            networksetup[1],
            vec!["-setdnsservers", "Wi-Fi", "10.0.0.53"]
        );
    }

    #[test]
    fn revert_of_empty_previous_dns_uses_the_empty_marker() {
        let runner = RecordingRunner::new();
        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let change = Change::SetDns {
            old: Vec::new(),
            new: vec![v4([10, 251, 3, 18])],
            context: DnsContext::MacosService("Wi-Fi".into()),
        };
        applier.undo(&change).expect("revert");

        let networksetup: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .filter(|call| call.program == "networksetup")
            .map(|call| call.args)
            .collect();
        assert_eq!(networksetup, vec![vec!["-setdnsservers", "Wi-Fi", "Empty"]]);
    }

    #[test]
    fn a_failed_flush_does_not_fail_the_step() {
        let runner = RecordingRunner::new();
        runner.respond_failure("dscacheutil", "flush failed");
        runner.respond_failure("killall", "no such process");

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let change = Change::SetDns {
            old: Vec::new(),
            new: vec![v4([10, 251, 3, 18])],
            context: DnsContext::MacosService("Wi-Fi".into()),
        };
        applier.apply(&change).expect("flush failures are warnings");
        assert!(runner
            .calls()
            .iter()
            .any(|call| call.program == "dscacheutil"));
        assert!(runner.calls().iter().any(|call| call.program == "killall"));
    }

    #[test]
    fn ambiguous_service_mapping_falls_back_to_the_first_enabled_service() {
        let runner = RecordingRunner::new();
        runner.respond("route", "interface: en0\n");
        runner.respond(
            "networksetup",
            "(1) Office\n(Hardware Port: Ethernet, Device: en0)\n\
             (2) Lab\n(Hardware Port: USB, Device: en0)\n",
        );
        runner.respond(
            "networksetup",
            "An asterisk (*) denotes that a network service is disabled.\n\
             *Disabled\n\
             Wi-Fi\n\
             Ethernet\n",
        );

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![v4([10, 251, 3, 18])],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        assert_eq!(
            change,
            Change::SetDns {
                old: Vec::new(),
                new: vec![v4([10, 251, 3, 18])],
                context: DnsContext::MacosService("Wi-Fi".into()),
            }
        );
    }

    fn foreign_route_text() -> &'static str {
        "   route to: 10.0.0.0
         destination: 10.0.0.0
                mask: 255.0.0.0
             gateway: 192.168.1.1
           interface: en0
               flags: <UP,GATEWAY,DONE,STATIC>
"
    }

    fn our_route_text() -> &'static str {
        "   route to: 10.0.0.0
         destination: 10.0.0.0
                mask: 255.0.0.0
           interface: utun3
               flags: <UP,DONE,STATIC>
"
    }

    fn pushed_route() -> Route {
        Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route")
    }

    fn route_calls(runner: &RecordingRunner) -> Vec<Vec<String>> {
        runner
            .calls()
            .into_iter()
            .filter(|call| call.program == "route")
            .map(|call| call.args)
            .collect()
    }

    #[test]
    fn a_foreign_route_is_recorded_deleted_and_ours_is_added() {
        let runner = RecordingRunner::new();
        // prepare reads the foreign route; apply deletes it, adds ours and
        // re-reads the table to verify.
        runner.respond("route", foreign_route_text());
        runner.respond("route", "");
        runner.respond("route", "");
        runner.respond("route", our_route_text());

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");

        let Change::ReplaceRoute {
            route,
            displaced,
            restore,
        } = &change
        else {
            panic!("expected ReplaceRoute, got {change:?}");
        };
        assert_eq!(route, &pushed_route());
        assert_eq!(displaced.destination, v4([10, 0, 0, 0]));
        assert_eq!(displaced.prefix_len, 8);
        assert_eq!(displaced.gateway, Some(v4([192, 168, 1, 1])));
        assert_eq!(displaced.interface, "en0");
        assert!(displaced.flags.contains("GATEWAY"));
        assert!(!restore);

        applier.apply(&change).expect("replace");
        let calls = route_calls(&runner);
        assert_eq!(calls[0], vec!["-n", "get", "10.0.0.0/8"]);
        assert_eq!(
            calls[1],
            vec!["-n", "delete", "-net", "10.0.0.0/8", "192.168.1.1",]
        );
        assert_eq!(
            calls[2],
            vec![
                "-n",
                "add",
                "-net",
                "10.0.0.0/8",
                "-interface",
                "utun3",
                "-ifscope",
                "utun3",
            ]
        );
        assert_eq!(calls[3], vec!["-n", "get", "10.0.0.0/8"]);
    }

    #[test]
    fn a_route_already_on_our_interface_is_left_alone() {
        let runner = RecordingRunner::new();
        runner.respond("route", our_route_text());

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");
        assert_eq!(change, Change::AddRoute(pushed_route()));

        runner.respond("route", "");
        runner.respond("route", our_route_text());
        applier.apply(&change).expect("add");
        let calls = route_calls(&runner);
        assert!(
            calls
                .iter()
                .all(|args| !args.contains(&"delete".to_owned())),
            "a route on our own interface must never be deleted: {calls:?}"
        );
    }

    #[test]
    fn restoring_a_displaced_route_deletes_ours_first_and_puts_the_original_back() {
        let runner = RecordingRunner::new();
        runner.respond("route", foreign_route_text());
        runner.respond("route", "");
        runner.respond("route", "");
        runner.respond("route", our_route_text());

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");
        applier.apply(&change).expect("replace");
        let before = route_calls(&runner).len();

        // Restore: delete our scoped route, read the table, add the original.
        runner.respond("route", "");
        runner.respond("route", "");
        runner.respond("route", "");
        applier.undo(&change).expect("restore");
        let calls = route_calls(&runner);
        let restore = &calls[before..];
        assert_eq!(
            restore[0],
            vec![
                "-n",
                "delete",
                "-net",
                "10.0.0.0/8",
                "-interface",
                "utun3",
                "-ifscope",
                "utun3",
            ]
        );
        assert_eq!(restore[1], vec!["-n", "get", "10.0.0.0/8"]);
        assert_eq!(
            restore[2],
            vec!["-n", "add", "-net", "10.0.0.0/8", "192.168.1.1"]
        );
    }

    #[test]
    fn a_failed_delete_names_the_conflicting_interface() {
        let runner = RecordingRunner::new();
        runner.respond("route", foreign_route_text());
        runner.respond_failure("route", "Operation not permitted");

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");
        let error = applier.apply(&change).expect_err("delete must fail");
        assert!(error.to_string().contains("en0"), "{error}");
        assert!(
            !route_calls(&runner)
                .iter()
                .any(|args| args.contains(&"add".to_owned())),
            "ours must not be added after a refused delete"
        );
    }

    #[test]
    fn verification_fails_when_the_route_is_missing_after_add() {
        let runner = RecordingRunner::new();
        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "utun3");
        // The add succeeds and the verification read returns no route.
        let error = applier
            .apply(&Change::AddRoute(pushed_route()))
            .expect_err("a missing route must fail apply");
        assert!(error.to_string().contains("missing after apply"), "{error}");
    }
}
