//! Linux applier: `ip` for address, MTU and routes plus the DNS manager.
//!
//! DNS is applied through the first manager found at runtime:
//!
//! 1. systemd-resolved (`resolvectl` with a live `/run/systemd/resolve` socket):
//!    `resolvectl dns <link> ...` and `resolvectl domain <link> ~.`, reverted
//!    with `resolvectl revert <link>`.
//! 2. `resolvconf`: `resolvconf -a <link>` fed a nameserver block on stdin,
//!    reverted with `resolvconf -d <link>`.
//! 3. no manager: back up `/etc/resolv.conf` to `/etc/resolv.conf.aevan.bak`
//!    once and write a new file; revert restores the backup byte-for-byte.
//!
//! The choice is captured in the journal, so revert uses the same mechanism
//! even when the environment changes between apply and teardown. DNS is
//! manager-dependent: systemd-resolved is per-link, `resolvconf` is per-interface
//! and the file fallback is host-wide. The `/dev/net/tun` prerequisite is
//! checked before any command runs.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::run_checked;
use crate::command::{CommandRunner, Output};
use crate::error::TunError;
use crate::rollback::{Change, DnsContext, RollbackBackend, UndoOutcome};
use crate::route::{Route, RouteRecord};

/// systemd-resolved's private socket, used to confirm the daemon is live.
const RESOLVED_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve";
/// Host resolver configuration used by the no-manager fallback.
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// One-time backup beside the host resolver configuration.
const RESOLV_CONF_BACKUP: &str = "/etc/resolv.conf.aevan.bak";

/// File-system and executable probes used to select a DNS manager.
///
/// It is a trait so offline tests can answer without touching `/etc` or the
/// host's real PATH.
pub trait DnsHost {
    /// Whether `program` resolves on PATH.
    fn command_exists(&self, program: &str) -> bool;
    /// Whether `path` exists.
    fn path_exists(&self, path: &Path) -> bool;
    /// Read a whole file.
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
    /// Write a whole file with `mode`.
    fn write(&self, path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()>;
    /// Remove a file; a missing file is an error the caller classifies.
    fn remove(&self, path: &Path) -> std::io::Result<()>;
}

/// The real host: PATH, the file system and `/etc/resolv.conf`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealDnsHost;

impl DnsHost for RealDnsHost {
    fn command_exists(&self, program: &str) -> bool {
        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&path).any(|directory| directory.join(program).is_file())
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn write(&self, path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    fn remove(&self, path: &Path) -> std::io::Result<()> {
        std::fs::remove_file(path)
    }
}

/// Linux `ip` applier.
pub struct PlatformApplier {
    runner: Box<dyn CommandRunner>,
    interface: String,
    host: Box<dyn DnsHost>,
    resolv_conf: PathBuf,
    backup: PathBuf,
}

impl PlatformApplier {
    /// Build the applier without checking `/dev/net/tun`.
    pub fn new(runner: Box<dyn CommandRunner>, interface: &str) -> Self {
        Self {
            runner,
            interface: interface.to_owned(),
            host: Box::new(RealDnsHost),
            resolv_conf: PathBuf::from(RESOLV_CONF),
            backup: PathBuf::from(RESOLV_CONF_BACKUP),
        }
    }

    #[cfg(test)]
    fn with_host(
        runner: Box<dyn CommandRunner>,
        interface: &str,
        host: Box<dyn DnsHost>,
        resolv_conf: PathBuf,
        backup: PathBuf,
    ) -> Self {
        Self {
            runner,
            interface: interface.to_owned(),
            host,
            resolv_conf,
            backup,
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

    /// Run one `ip route` command and log its exact argument vector and exit
    /// status. A route add or delete must never be skipped silently.
    fn run_route(&mut self, args: &[String]) -> Result<Output, TunError> {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.runner.run("ip", &borrowed)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::info!(
            program = "ip",
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
            Err(super::command_failure("ip", &output))
        }
    }

    fn route_args(interface: &str, verb: &str, route: &Route) -> Vec<String> {
        let mut args = vec![
            "route".into(),
            verb.into(),
            format!("{}/{}", route.destination, route.prefix_len),
            "dev".into(),
            interface.to_owned(),
        ];
        if let Some(gateway) = route.gateway {
            args.push("via".into());
            args.push(format!("{gateway}"));
        }
        if route.metric != 0 {
            args.push("metric".into());
            args.push(format!("{}", route.metric));
        }
        args
    }

    fn add_route(&mut self, interface: &str, route: &Route) -> Result<(), TunError> {
        let args = Self::route_args(interface, "add", route);
        self.checked_route(&args)
    }

    fn delete_route(&mut self, interface: &str, route: &Route) -> Result<(), TunError> {
        let args = Self::route_args(interface, "del", route);
        self.checked_route(&args)
    }

    fn add_our_route(&mut self, route: &Route) -> Result<(), TunError> {
        let interface = self.interface.clone();
        self.add_route(&interface, route)
    }

    fn delete_our_route(&mut self, route: &Route, lenient: bool) -> Result<(), TunError> {
        let interface = self.interface.clone();
        match self.delete_route(&interface, route) {
            Ok(()) => Ok(()),
            Err(error) if lenient && error.is_already_absent() => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read the exact route for `route`'s prefix from the live table.
    fn current_route(&mut self, route: &Route) -> Result<Option<RouteRecord>, TunError> {
        let cidr = format!("{}/{}", route.destination, route.prefix_len);
        let args = ["route", "show", cidr.as_str()];
        let output = self.runner.run("ip", &args)?;
        if !output.status.success() {
            return Err(super::command_failure("ip", &output));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(parse_route_record(&text, route))
    }

    /// The exact prefix is already owned by a different interface.
    fn conflicting_route(&mut self, route: &Route) -> Result<Option<RouteRecord>, TunError> {
        match self.current_route(route)? {
            Some(record) if record.interface != self.interface => Ok(Some(record)),
            _ => Ok(None),
        }
    }

    fn delete_record(&mut self, record: &RouteRecord) -> Result<(), TunError> {
        let route = record.to_route()?;
        match self.delete_route(&record.interface, &route) {
            Ok(()) => Ok(()),
            Err(error) if error.is_already_absent() => Ok(()),
            Err(error) => Err(TunError::Io(std::io::Error::other(format!(
                "cannot delete the conflicting route {} on {}: {error}",
                record.cidr(),
                record.interface
            )))),
        }
    }

    fn restore_record(&mut self, record: &RouteRecord) -> Result<(), TunError> {
        let route = record.to_route()?;
        if let Some(current) = self.current_route(&route)? {
            if current.interface == record.interface {
                return Ok(());
            }
        }
        self.add_route(&record.interface, &route)
    }

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
    fn install_our_route(&mut self, route: &Route, allow_replace: bool) -> Result<(), TunError> {
        match self.add_our_route(route) {
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
                self.add_our_route(route)
            }
        }
    }

    /// Select the DNS mechanism once, when the change is applied.
    fn detect(&self) -> DnsContext {
        if self.host.command_exists("resolvectl")
            && self.host.path_exists(Path::new(RESOLVED_SOCKET))
        {
            DnsContext::LinuxResolved
        } else if self.host.command_exists("resolvconf") {
            DnsContext::LinuxResolvconf
        } else {
            DnsContext::LinuxFile
        }
    }

    fn apply_resolved(&mut self, servers: &[IpAddr]) -> Result<(), TunError> {
        let mut args = vec!["dns".to_owned(), self.interface.clone()];
        args.extend(servers.iter().map(|server| server.to_string()));
        run_checked(self.runner.as_mut(), "resolvectl", &args)?;
        run_checked(
            self.runner.as_mut(),
            "resolvectl",
            &["domain".to_owned(), self.interface.clone(), "~.".to_owned()],
        )
    }

    fn revert_resolved(&mut self) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "resolvectl",
            &["revert".to_owned(), self.interface.clone()],
        )
    }

    fn apply_resolvconf(&mut self, servers: &[IpAddr]) -> Result<(), TunError> {
        let mut block = String::new();
        for server in servers {
            block.push_str("nameserver ");
            block.push_str(&server.to_string());
            block.push('\n');
        }
        let args = ["-a", self.interface.as_str()];
        let output = self
            .runner
            .run_with_input("resolvconf", &args, block.as_bytes())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(super::command_failure("resolvconf", &output))
        }
    }

    fn revert_resolvconf(&mut self) -> Result<(), TunError> {
        run_checked(
            self.runner.as_mut(),
            "resolvconf",
            &["-d".to_owned(), self.interface.clone()],
        )
    }

    /// Back up `/etc/resolv.conf` only when no backup from an earlier run
    /// exists. An existing backup is the restore source and is never replaced.
    fn ensure_backup(&mut self) -> Result<(), TunError> {
        if self.host.path_exists(&self.backup) {
            tracing::warn!(
                path = %self.backup.display(),
                "existing resolv.conf backup found; reusing it as the restore source"
            );
            return Ok(());
        }
        let bytes = match self.host.read(&self.resolv_conf) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(TunError::Io(error)),
        };
        self.host
            .write(&self.backup, &bytes, 0o644)
            .map_err(TunError::Io)
    }

    fn apply_file(&mut self, servers: &[IpAddr]) -> Result<(), TunError> {
        self.ensure_backup()?;
        let mut text = format!(
            "# Managed by aevan. Original saved to {}.\n",
            self.backup.display()
        );
        for server in servers {
            text.push_str("nameserver ");
            text.push_str(&server.to_string());
            text.push('\n');
        }
        self.host
            .write(&self.resolv_conf, text.as_bytes(), 0o644)
            .map_err(TunError::Io)
    }

    fn revert_file(&mut self) -> Result<UndoOutcome, TunError> {
        if !self.host.path_exists(&self.backup) {
            return Ok(UndoOutcome::AlreadyAbsent);
        }
        let bytes = self.host.read(&self.backup).map_err(TunError::Io)?;
        self.host
            .write(&self.resolv_conf, &bytes, 0o644)
            .map_err(TunError::Io)?;
        match self.host.remove(&self.backup) {
            Ok(()) => Ok(UndoOutcome::RolledBack),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(UndoOutcome::AlreadyAbsent)
            }
            Err(error) => Err(TunError::Io(error)),
        }
    }

    fn revert_dns(&mut self, context: &DnsContext) -> Result<UndoOutcome, TunError> {
        let result = match context {
            DnsContext::LinuxResolved => self.revert_resolved(),
            DnsContext::LinuxResolvconf => self.revert_resolvconf(),
            DnsContext::LinuxFile => return self.revert_file(),
            // An older journal or an unset context: choose the current manager
            // and revert through it.
            _ => match self.detect() {
                DnsContext::LinuxResolved => self.revert_resolved(),
                DnsContext::LinuxResolvconf => self.revert_resolvconf(),
                _ => return self.revert_file(),
            },
        };
        match result {
            Ok(()) => Ok(UndoOutcome::RolledBack),
            Err(error) if error.is_already_absent() => Ok(UndoOutcome::AlreadyAbsent),
            Err(error) => Err(error),
        }
    }
}

impl RollbackBackend for PlatformApplier {
    fn prepare(&mut self, change: &mut Change) -> Result<(), TunError> {
        match change {
            Change::SetDns { old, new, context } => {
                if new.is_empty() || !matches!(context, DnsContext::Unspecified) {
                    return Ok(());
                }
                // The old servers are not needed: every Linux mechanism restores
                // its own previous state (`resolvectl revert`, `resolvconf -d`, or
                // the saved file). Keep the change shape unchanged and record only
                // the mechanism.
                let _ = old;
                *context = self.detect();
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
                    self.delete_our_route(route, false)?;
                }
                for route in &diff.to_add {
                    self.install_our_route(route, true)?;
                }
                for route in new {
                    self.verify_route(route)?;
                }
                Ok(())
            }
            Change::SetDns { context, new, .. } => {
                if new.is_empty() {
                    self.revert_dns(context).map(|_| ())
                } else {
                    match context {
                        DnsContext::LinuxResolved => self.apply_resolved(new),
                        DnsContext::LinuxResolvconf => self.apply_resolvconf(new),
                        DnsContext::LinuxFile => self.apply_file(new),
                        _ => match self.detect() {
                            DnsContext::LinuxResolved => self.apply_resolved(new),
                            DnsContext::LinuxResolvconf => self.apply_resolvconf(new),
                            _ => self.apply_file(new),
                        },
                    }
                }
            }
            Change::AddRoute(route) => {
                self.install_our_route(route, true)?;
                self.verify_route(route)
            }
            Change::RemoveRoute(route) => self.delete_our_route(route, true),
            Change::ReplaceRoute {
                route,
                displaced,
                restore,
            } => {
                if *restore {
                    // Delete ours first, then put the original back.
                    self.delete_our_route(route, true)?;
                    self.restore_record(displaced)
                } else {
                    self.delete_record(displaced)?;
                    if let Err(error) = self.add_our_route(route) {
                        let _ = self.restore_record(displaced);
                        return Err(error);
                    }
                    if let Err(error) = self.verify_route(route) {
                        let _ = self.delete_our_route(route, true);
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
            Change::SetDns { context, .. } => self.revert_dns(context),
            other => {
                self.apply(&other.inverse())?;
                Ok(UndoOutcome::RolledBack)
            }
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

/// Parse the exact route line for `wanted` from `ip route show <cidr>`.
///
/// Linux reports one route per line. A line for a different prefix (or no
/// line at all) is not a conflict.
fn parse_route_record(text: &str, wanted: &Route) -> Option<RouteRecord> {
    let wanted_cidr = format!("{}/{}", wanted.destination, wanted.prefix_len);
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next()? != wanted_cidr {
            continue;
        }
        let mut gateway = None;
        let mut interface = None;
        let mut metric = 0;
        let mut flags = Vec::new();
        while let Some(token) = tokens.next() {
            match token {
                "via" => gateway = tokens.next().and_then(|value| value.parse().ok()),
                "dev" => interface = tokens.next().map(str::to_owned),
                "metric" => {
                    metric = tokens
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0)
                }
                other => flags.push(other.to_owned()),
            }
        }
        let interface = interface?;
        return Some(RouteRecord {
            destination: wanted.destination,
            prefix_len: wanted.prefix_len,
            gateway,
            interface,
            flags: flags.join(" "),
            metric,
        });
    }
    None
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
        runner.respond("ip", "");
        runner.respond("ip", "");
        runner.respond("ip", "");
        runner.respond(
            "ip",
            "10.0.0.0/8 dev aevan0 scope link
",
        );
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
            vec!["route", "show", "10.0.0.0/8"],
            "apply verifies the route by re-reading the table"
        );
        assert_eq!(
            calls[4],
            vec!["route", "del", "10.0.0.0/8", "dev", "aevan0"]
        );
        // Rollback undoes the address but emits nothing for the MTU: the change
        // recorded `old: None`, so there is no previous value to restore, and a
        // rollback step with nothing to undo is skipped rather than re-issuing
        // the value we applied.
        assert_eq!(
            calls[5],
            vec!["addr", "del", "10.251.98.43/24", "dev", "aevan0"]
        );
        assert_eq!(
            calls.len(),
            6,
            "no command may be issued for an empty restore"
        );
    }

    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct FakeHost {
        commands: Rc<RefCell<HashSet<String>>>,
        files: Rc<RefCell<HashMap<PathBuf, Vec<u8>>>>,
    }

    impl FakeHost {
        fn command(&self, name: &str) {
            self.commands.borrow_mut().insert(name.to_owned());
        }

        fn file(&self, path: &str, bytes: &[u8]) {
            self.files
                .borrow_mut()
                .insert(PathBuf::from(path), bytes.to_vec());
        }

        fn contains(&self, path: &str) -> bool {
            self.files.borrow().contains_key(&PathBuf::from(path))
        }

        fn bytes(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(&PathBuf::from(path)).cloned()
        }
    }

    impl DnsHost for FakeHost {
        fn command_exists(&self, program: &str) -> bool {
            self.commands.borrow().contains(program)
        }

        fn path_exists(&self, path: &Path) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }

        fn write(&self, path: &Path, bytes: &[u8], _mode: u32) -> std::io::Result<()> {
            self.files
                .borrow_mut()
                .insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }

        fn remove(&self, path: &Path) -> std::io::Result<()> {
            self.files
                .borrow_mut()
                .remove(path)
                .map(|_| ())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    fn server() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))
    }

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn applier(runner: &RecordingRunner, host: FakeHost) -> PlatformApplier {
        PlatformApplier::with_host(
            Box::new(runner.clone()),
            "aevan0",
            Box::new(host),
            PathBuf::from("/etc/resolv.conf"),
            PathBuf::from("/etc/resolv.conf.aevan.bak"),
        )
    }

    fn context(change: &Change) -> &DnsContext {
        match change {
            Change::SetDns { context, .. } => context,
            other => panic!("expected SetDns, got {other:?}"),
        }
    }

    #[test]
    fn resolved_sets_dns_and_a_routing_domain_then_reverts() {
        let runner = RecordingRunner::new();
        let host = FakeHost::default();
        host.command("resolvectl");
        host.file(RESOLVED_SOCKET, b"");
        let mut applier = applier(&runner, host);

        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![server()],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        assert_eq!(context(&change), &DnsContext::LinuxResolved);
        applier.apply(&change).expect("apply");
        applier.undo(&change).expect("revert");

        let calls: Vec<Vec<String>> = runner
            .calls()
            .into_iter()
            .map(|call| {
                let mut args = vec![call.program];
                args.extend(call.args);
                args
            })
            .collect();
        assert_eq!(calls[0], vec!["resolvectl", "dns", "aevan0", "10.251.3.18"]);
        assert_eq!(calls[1], vec!["resolvectl", "domain", "aevan0", "~."]);
        assert_eq!(calls[2], vec!["resolvectl", "revert", "aevan0"]);
    }

    #[test]
    fn the_remembered_resolved_mechanism_is_used_for_revert() {
        let runner = RecordingRunner::new();
        let host = FakeHost::default();
        host.command("resolvectl");
        host.file(RESOLVED_SOCKET, b"");
        let shared = host.clone();
        let mut applier = applier(&runner, host);

        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![server()],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        applier.apply(&change).expect("apply");

        // The environment changed after apply.
        shared.commands.borrow_mut().clear();
        shared.command("resolvconf");

        applier.undo(&change).expect("revert");
        assert!(runner
            .calls()
            .iter()
            .all(|call| call.program == "resolvectl"));
        assert!(runner
            .calls()
            .iter()
            .any(|call| call.args == vec!["revert", "aevan0"]));
    }

    #[test]
    fn resolvconf_writes_a_nameserver_block_on_stdin_and_deletes_on_revert() {
        let runner = RecordingRunner::new();
        let host = FakeHost::default();
        host.command("resolvconf");
        let mut applier = applier(&runner, host);

        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![server(), IpAddr::V4(Ipv4Addr::new(10, 249, 10, 13))],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        assert_eq!(context(&change), &DnsContext::LinuxResolvconf);
        applier.apply(&change).expect("apply");
        applier.undo(&change).expect("revert");

        let calls = runner.calls();
        assert_eq!(calls[0].program, "resolvconf");
        assert_eq!(calls[0].args, vec!["-a", "aevan0"]);
        assert_eq!(
            calls[0].input,
            b"nameserver 10.251.3.18\nnameserver 10.249.10.13\n"
        );
        assert_eq!(calls[1].program, "resolvconf");
        assert_eq!(calls[1].args, vec!["-d", "aevan0"]);
    }

    #[test]
    fn the_file_fallback_creates_one_backup_and_restores_it_byte_for_byte() {
        let runner = RecordingRunner::new();
        let host = FakeHost::default();
        let original = b"nameserver 1.1.1.1\nsearch example.test\noptions edns0\n";
        host.file(RESOLV_CONF, original);
        let mut applier = applier(&runner, host.clone());

        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![server()],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        assert_eq!(context(&change), &DnsContext::LinuxFile);

        applier.apply(&change).expect("apply");

        assert_eq!(
            host.bytes(RESOLV_CONF_BACKUP).as_deref(),
            Some(original.as_slice())
        );
        let managed = host.bytes(RESOLV_CONF).expect("managed file");
        assert!(String::from_utf8_lossy(&managed).contains("nameserver 10.251.3.18"));

        // A second apply must not overwrite the existing backup.
        applier.apply(&change).expect("second apply");
        assert_eq!(
            host.bytes(RESOLV_CONF_BACKUP).as_deref(),
            Some(original.as_slice())
        );

        applier.undo(&change).expect("revert");
        assert_eq!(
            host.bytes(RESOLV_CONF).as_deref(),
            Some(original.as_slice())
        );
        assert!(!host.contains(RESOLV_CONF_BACKUP));
        assert!(
            runner.calls().is_empty(),
            "the file fallback runs no command"
        );
    }

    #[test]
    fn an_existing_backup_from_a_crashed_run_is_the_restore_source() {
        let runner = RecordingRunner::new();
        let host = FakeHost::default();
        host.file(RESOLV_CONF, b"nameserver 10.251.3.18\n");
        host.file(RESOLV_CONF_BACKUP, b"nameserver 9.9.9.9\n");
        let mut applier = applier(&runner, host.clone());

        let mut change = Change::SetDns {
            old: Vec::new(),
            new: vec![server()],
            context: DnsContext::Unspecified,
        };
        applier.prepare(&mut change).expect("prepare");
        applier.apply(&change).expect("apply");
        assert_eq!(
            host.bytes(RESOLV_CONF_BACKUP).as_deref(),
            Some(b"nameserver 9.9.9.9\n".as_slice())
        );

        applier.undo(&change).expect("revert");
        assert_eq!(
            host.bytes(RESOLV_CONF).as_deref(),
            Some(b"nameserver 9.9.9.9\n".as_slice())
        );
        assert!(!host.contains(RESOLV_CONF_BACKUP));
    }

    fn foreign_route_line() -> &'static str {
        "10.0.0.0/8 via 192.168.1.1 dev wlan0 proto dhcp metric 600
"
    }

    fn our_route_line() -> &'static str {
        "10.0.0.0/8 dev aevan0 scope link
"
    }

    fn pushed_route() -> Route {
        Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route")
    }

    fn route_calls(runner: &RecordingRunner) -> Vec<Vec<String>> {
        runner
            .calls()
            .into_iter()
            .filter(|call| {
                call.program == "ip" && call.args.first().map(String::as_str) == Some("route")
            })
            .map(|call| call.args)
            .collect()
    }

    #[test]
    fn a_foreign_route_is_recorded_deleted_and_ours_is_added() {
        let runner = RecordingRunner::new();
        // prepare reads the foreign route; apply deletes it, adds ours and
        // re-reads the table to verify.
        runner.respond("ip", foreign_route_line());
        runner.respond("ip", "");
        runner.respond("ip", "");
        runner.respond("ip", our_route_line());

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "aevan0");
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
        assert_eq!(displaced.interface, "wlan0");
        assert_eq!(displaced.metric, 600);
        assert!(!restore);

        applier.apply(&change).expect("replace");
        let calls = route_calls(&runner);
        assert_eq!(calls[0], vec!["route", "show", "10.0.0.0/8"]);
        assert_eq!(
            calls[1],
            vec![
                "route",
                "del",
                "10.0.0.0/8",
                "dev",
                "wlan0",
                "via",
                "192.168.1.1",
                "metric",
                "600",
            ]
        );
        assert_eq!(
            calls[2],
            vec!["route", "add", "10.0.0.0/8", "dev", "aevan0"]
        );
        assert_eq!(calls[3], vec!["route", "show", "10.0.0.0/8"]);
    }

    #[test]
    fn a_route_already_on_our_interface_is_left_alone() {
        let runner = RecordingRunner::new();
        runner.respond("ip", our_route_line());

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "aevan0");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");
        assert_eq!(change, Change::AddRoute(pushed_route()));

        runner.respond("ip", "");
        runner.respond("ip", our_route_line());
        applier.apply(&change).expect("add");
        let calls = route_calls(&runner);
        assert!(
            calls.iter().all(|args| !args.contains(&"del".to_owned())),
            "a route on our own interface must never be deleted: {calls:?}"
        );
    }

    #[test]
    fn restoring_a_displaced_route_deletes_ours_first_and_puts_the_original_back() {
        let runner = RecordingRunner::new();
        runner.respond("ip", foreign_route_line());
        runner.respond("ip", "");
        runner.respond("ip", "");
        runner.respond("ip", our_route_line());

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "aevan0");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");
        applier.apply(&change).expect("replace");
        let before = route_calls(&runner).len();

        runner.respond("ip", "");
        runner.respond("ip", "");
        runner.respond("ip", "");
        applier.undo(&change).expect("restore");
        let calls = route_calls(&runner);
        let restore = &calls[before..];
        assert_eq!(
            restore[0],
            vec!["route", "del", "10.0.0.0/8", "dev", "aevan0"]
        );
        assert_eq!(restore[1], vec!["route", "show", "10.0.0.0/8"]);
        assert_eq!(
            restore[2],
            vec![
                "route",
                "add",
                "10.0.0.0/8",
                "dev",
                "wlan0",
                "via",
                "192.168.1.1",
                "metric",
                "600",
            ]
        );
    }

    #[test]
    fn a_failed_delete_names_the_conflicting_interface() {
        let runner = RecordingRunner::new();
        runner.respond("ip", foreign_route_line());
        runner.respond_failure("ip", "RTNETLINK answers: Operation not permitted");

        let mut applier =
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "aevan0");
        let mut change = Change::AddRoute(pushed_route());
        applier.prepare(&mut change).expect("prepare");
        let error = applier.apply(&change).expect_err("delete must fail");
        assert!(error.to_string().contains("wlan0"), "{error}");
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
            crate::apply::platform_applier_unchecked(Box::new(runner.clone()), "aevan0");
        let error = applier
            .apply(&Change::AddRoute(pushed_route()))
            .expect_err("a missing route must fail apply");
        assert!(error.to_string().contains("missing after apply"), "{error}");
    }
}
