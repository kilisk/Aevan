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
use crate::command::CommandRunner;
use crate::error::TunError;
use crate::rollback::{Change, DnsContext, RollbackBackend, UndoOutcome};
use crate::route::Route;

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
        if let Change::SetDns { old, new, context } = change {
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
                    self.route("del", route)?;
                }
                for route in &diff.to_add {
                    self.route("add", route)?;
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
            Change::AddRoute(route) => self.route("add", route),
            Change::RemoveRoute(route) => self.route("del", route),
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

}
