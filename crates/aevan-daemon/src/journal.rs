//! Write-ahead journal for route, DNS, MTU and address changes.
//!
//! Before each configuration change is applied, it is appended to a small JSON
//! journal in the per-user config directory. A clean teardown removes the file.
//! If the daemon is killed, the next start replays the inverses in reverse
//! order and logs every step.
//!
//! The journal is owner-only where the platform supports Unix modes; on Windows
//! the per-user configuration directory ACL is the operative control, matching
//! the profile store.

use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use aevan_core::{AevanError, AevanResult};
use aevan_tun::apply;
use aevan_tun::{
    Change, Elevation, RealCommandRunner, RollbackBackend, Route, RouteRecord, TunError,
    UndoOutcome,
};

use crate::protocol::{RecoveryFailure, RecoveryReport};
use crate::state::unix_now;

/// Journal file name inside the per-user configuration directory.
pub const JOURNAL_FILE: &str = "aevand.journal";
/// Version of the journal document.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// Full journal path for a config directory.
pub fn journal_path(config_dir: &Path) -> PathBuf {
    config_dir.join(JOURNAL_FILE)
}

/// A route in serializable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRoute {
    /// Destination network.
    pub destination: IpAddr,
    /// Prefix length.
    pub prefix_len: u8,
    /// Optional next hop; absent means on-link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// Metric.
    pub metric: u32,
}

impl From<&Route> for JournalRoute {
    fn from(route: &Route) -> Self {
        Self {
            destination: route.destination,
            prefix_len: route.prefix_len,
            gateway: route.gateway,
            metric: route.metric,
        }
    }
}

impl JournalRoute {
    fn to_route(&self) -> Result<Route, String> {
        Route::new(self.destination, self.prefix_len, self.gateway, self.metric)
            .map_err(|error| error.to_string())
    }
}

/// A displaced route in serializable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRouteRecord {
    /// Destination network.
    pub destination: IpAddr,
    /// Prefix length.
    pub prefix_len: u8,
    /// Optional next hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// Interface that owned the route.
    pub interface: String,
    /// Platform flags.
    #[serde(default)]
    pub flags: String,
    /// Route metric.
    #[serde(default)]
    pub metric: u32,
}

impl From<&RouteRecord> for JournalRouteRecord {
    fn from(record: &RouteRecord) -> Self {
        Self {
            destination: record.destination,
            prefix_len: record.prefix_len,
            gateway: record.gateway,
            interface: record.interface.clone(),
            flags: record.flags.clone(),
            metric: record.metric,
        }
    }
}

impl JournalRouteRecord {
    fn to_record(&self) -> Result<RouteRecord, String> {
        let route = Route::new(self.destination, self.prefix_len, self.gateway, self.metric)
            .map_err(|error| error.to_string())?;
        Ok(RouteRecord {
            destination: route.destination,
            prefix_len: route.prefix_len,
            gateway: route.gateway,
            interface: self.interface.clone(),
            flags: self.flags.clone(),
            metric: route.metric,
        })
    }
}

/// Serializable form of [`aevan_tun::DnsContext`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalDnsContext {
    /// No platform state was captured.
    #[default]
    Unspecified,
    /// macOS network service used for the change.
    MacosService {
        /// Service name.
        service: String,
    },
    /// Linux systemd-resolved.
    LinuxResolved,
    /// Linux `resolvconf`.
    LinuxResolvconf,
    /// Linux `/etc/resolv.conf` fallback.
    LinuxFile,
}

impl From<&aevan_tun::DnsContext> for JournalDnsContext {
    fn from(context: &aevan_tun::DnsContext) -> Self {
        match context {
            aevan_tun::DnsContext::Unspecified => Self::Unspecified,
            aevan_tun::DnsContext::MacosService(service) => Self::MacosService {
                service: service.clone(),
            },
            aevan_tun::DnsContext::LinuxResolved => Self::LinuxResolved,
            aevan_tun::DnsContext::LinuxResolvconf => Self::LinuxResolvconf,
            aevan_tun::DnsContext::LinuxFile => Self::LinuxFile,
        }
    }
}

impl From<&JournalDnsContext> for aevan_tun::DnsContext {
    fn from(context: &JournalDnsContext) -> Self {
        match context {
            JournalDnsContext::Unspecified => Self::Unspecified,
            JournalDnsContext::MacosService { service } => Self::MacosService(service.clone()),
            JournalDnsContext::LinuxResolved => Self::LinuxResolved,
            JournalDnsContext::LinuxResolvconf => Self::LinuxResolvconf,
            JournalDnsContext::LinuxFile => Self::LinuxFile,
        }
    }
}

/// A serializable [`Change`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalChange {
    /// Address/prefix changed.
    SetAddr {
        /// Previous value.
        old: Option<(IpAddr, u8)>,
        /// New value.
        new: Option<(IpAddr, u8)>,
    },
    /// MTU changed.
    SetMtu {
        /// Previous value.
        old: Option<u16>,
        /// New value.
        new: Option<u16>,
    },
    /// Whole route set changed.
    SetRoutes {
        /// Previous set.
        old: Vec<JournalRoute>,
        /// New set.
        new: Vec<JournalRoute>,
    },
    /// DNS set changed.
    SetDns {
        /// Previous set.
        old: Vec<IpAddr>,
        /// New set.
        new: Vec<IpAddr>,
        /// Platform state captured at apply time.
        #[serde(default)]
        context: JournalDnsContext,
    },
    /// One route added.
    AddRoute {
        /// The route.
        route: JournalRoute,
    },
    /// One route removed.
    RemoveRoute {
        /// The route.
        route: JournalRoute,
    },
    /// A pushed route replaced a conflicting route on another interface.
    ReplaceRoute {
        /// Our route.
        route: JournalRoute,
        /// The route found before the replacement.
        displaced: JournalRouteRecord,
        /// Whether this record is the restore direction.
        restore: bool,
    },
}

impl From<&Change> for JournalChange {
    fn from(change: &Change) -> Self {
        match change {
            Change::SetAddr { old, new } => Self::SetAddr {
                old: *old,
                new: *new,
            },
            Change::SetMtu { old, new } => Self::SetMtu {
                old: *old,
                new: *new,
            },
            Change::SetRoutes { old, new } => Self::SetRoutes {
                old: old.iter().map(JournalRoute::from).collect(),
                new: new.iter().map(JournalRoute::from).collect(),
            },
            Change::SetDns { old, new, context } => Self::SetDns {
                old: old.clone(),
                new: new.clone(),
                context: JournalDnsContext::from(context),
            },
            Change::AddRoute(route) => Self::AddRoute {
                route: JournalRoute::from(route),
            },
            Change::RemoveRoute(route) => Self::RemoveRoute {
                route: JournalRoute::from(route),
            },
            Change::ReplaceRoute {
                route,
                displaced,
                restore,
            } => Self::ReplaceRoute {
                route: JournalRoute::from(route),
                displaced: JournalRouteRecord::from(displaced),
                restore: *restore,
            },
        }
    }
}

impl JournalChange {
    /// Convert back into an applyable change.
    pub fn to_change(&self) -> Result<Change, String> {
        match self {
            Self::SetAddr { old, new } => Ok(Change::SetAddr {
                old: *old,
                new: *new,
            }),
            Self::SetMtu { old, new } => Ok(Change::SetMtu {
                old: *old,
                new: *new,
            }),
            Self::SetRoutes { old, new } => Ok(Change::SetRoutes {
                old: old
                    .iter()
                    .map(JournalRoute::to_route)
                    .collect::<Result<_, _>>()?,
                new: new
                    .iter()
                    .map(JournalRoute::to_route)
                    .collect::<Result<_, _>>()?,
            }),
            Self::SetDns { old, new, context } => Ok(Change::SetDns {
                old: old.clone(),
                new: new.clone(),
                context: aevan_tun::DnsContext::from(context),
            }),
            Self::AddRoute { route } => Ok(Change::AddRoute(route.to_route()?)),
            Self::RemoveRoute { route } => Ok(Change::RemoveRoute(route.to_route()?)),
            Self::ReplaceRoute {
                route,
                displaced,
                restore,
            } => Ok(Change::ReplaceRoute {
                route: route.to_route()?,
                displaced: displaced.to_record()?,
                restore: *restore,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalDocument {
    schema_version: u32,
    device: String,
    pid: u32,
    created_unix: u64,
    #[serde(default)]
    changes: Vec<JournalChange>,
}

/// An open journal. Dropping it does not delete the file; only a clean
/// teardown calls [`Journal::remove`].
pub struct Journal {
    path: PathBuf,
    document: JournalDocument,
}

impl Journal {
    /// Create the journal before the first change is applied.
    pub fn create(path: PathBuf, device: impl Into<String>) -> AevanResult<Self> {
        let journal = Self {
            path,
            document: JournalDocument {
                schema_version: JOURNAL_SCHEMA_VERSION,
                device: device.into(),
                pid: std::process::id(),
                created_unix: unix_now(),
                changes: Vec::new(),
            },
        };
        journal.persist()?;
        Ok(journal)
    }

    /// Path of this journal.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Device the changes belong to.
    pub fn device(&self) -> &str {
        &self.document.device
    }

    /// Record a change before applying it.
    pub fn record(&mut self, change: &Change) -> AevanResult<()> {
        self.document.changes.push(JournalChange::from(change));
        self.persist()
    }

    /// Forget the last record because applying it failed and had no effect.
    pub fn forget_last(&mut self) -> AevanResult<()> {
        self.document.changes.pop();
        self.persist()
    }

    /// Delete the journal after a clean teardown.
    pub fn remove(self) -> AevanResult<()> {
        remove_file(&self.path)
    }

    fn persist(&self) -> AevanResult<()> {
        let text = serde_json::to_vec_pretty(&self.document)
            .map_err(|error| AevanError::Config(format!("cannot serialise journal: {error}")))?;
        write_private(&self.path, &text)
    }
}

/// Read a journal without applying it.
pub fn load(path: &Path) -> AevanResult<JournalDocumentView> {
    let bytes = fs::read(path)
        .map_err(|error| AevanError::Config(format!("cannot read {}: {error}", path.display())))?;
    let document: JournalDocument = serde_json::from_slice(&bytes).map_err(|error| {
        AevanError::Config(format!("invalid journal {}: {error}", path.display()))
    })?;
    if document.schema_version != JOURNAL_SCHEMA_VERSION {
        return Err(AevanError::Unsupported(format!(
            "journal schema {} is not supported (expected {JOURNAL_SCHEMA_VERSION})",
            document.schema_version
        )));
    }
    Ok(JournalDocumentView {
        device: document.device,
        pid: document.pid,
        created_unix: document.created_unix,
        changes: document.changes,
    })
}

/// Read-only journal facts used by the daemon during recovery.
#[derive(Debug, Clone)]
pub struct JournalDocumentView {
    /// Device the changes belong to.
    pub device: String,
    /// Process that wrote the journal.
    pub pid: u32,
    /// Creation time in Unix seconds.
    pub created_unix: u64,
    /// Recorded changes, oldest first.
    pub changes: Vec<JournalChange>,
}

/// Roll back a journal with an injected backend.
///
/// The test seam asserts the successful path as if elevation had already been
/// established. Production recovery uses [`recover_with_elevation`], which
/// observes it for real.
pub fn recover_with(path: &Path, backend: &mut dyn RollbackBackend) -> AevanResult<RecoveryReport> {
    recover_with_elevation(path, backend, Elevation::Elevated)
}

/// Roll back a journal with an injected backend and an observed elevation.
///
/// Ordering is deliberately presence, privilege, then platform commands. A
/// missing device means every device-scoped change is already undone, so no
/// platform command and no elevation is needed. Per-step inverses may also
/// report that their target was already absent; both cases count as
/// `skipped_absent`, not failures.
///
/// When the device is still present, the journal describes live state. Without
/// elevation the function returns [`AevanError::Privilege`] before touching
/// anything and leaves the journal in place.
pub fn recover_with_elevation(
    path: &Path,
    backend: &mut dyn RollbackBackend,
    observed: Elevation,
) -> AevanResult<RecoveryReport> {
    let document = load(path)?;
    let mut report = RecoveryReport {
        journal: Some(path.display().to_string()),
        ..RecoveryReport::default()
    };
    if document.changes.is_empty() {
        remove_file(path)?;
        report.removed = true;
        return Ok(report);
    }
    // Presence first: enumerating the interface alias needs no Administrator.
    if !backend.device_present().map_err(tun_error)? {
        report.skipped_absent = document.changes.len();
        remove_file(path)?;
        report.removed = true;
        return Ok(report);
    }
    // Live state remains. Check elevation before running any inverse, and
    // keep the journal when it is missing.
    apply::check_prerequisites_observed(observed).map_err(tun_error)?;
    for change in document.changes.iter().rev() {
        let change = match change.to_change() {
            Ok(change) => change,
            Err(error) => {
                report.failures.push(RecoveryFailure {
                    step: "decode".into(),
                    reason: format!("decode journal change: {error}"),
                });
                continue;
            }
        };
        let step = apply::step_name(&change);
        match backend.undo(&change) {
            Ok(UndoOutcome::RolledBack) => report.rolled_back += 1,
            Ok(UndoOutcome::AlreadyAbsent) => report.skipped_absent += 1,
            Err(error) if error.is_already_absent() => report.skipped_absent += 1,
            Err(error) => report.failures.push(RecoveryFailure {
                step: step.to_owned(),
                reason: error.to_string(),
            }),
        }
    }
    if report.failures.is_empty() {
        remove_file(path)?;
        report.removed = true;
    }
    Ok(report)
}

/// Recover a journal through the current platform applier.
///
/// Returns `Ok(None)` when no journal exists. A malformed journal, missing
/// elevation for still-live state, or a failed inverse is an error and leaves
/// the file in place; the daemon logs it and refuses a new connect until the
/// file is resolved.
pub fn recover(path: &Path) -> AevanResult<Option<RecoveryReport>> {
    if !path.exists() {
        return Ok(None);
    }
    let document = load(path)?;
    // A crash between journal creation and the first change leaves an empty
    // journal. Nothing was applied, so no platform applier (and no privilege)
    // is needed to remove it.
    if document.changes.is_empty() {
        remove_file(path)?;
        return Ok(Some(RecoveryReport {
            removed: true,
            journal: Some(path.display().to_string()),
            ..RecoveryReport::default()
        }));
    }
    // Build the applier without its privilege check. Recovery probes device
    // presence first and only then requires elevation for live state.
    let mut applier =
        apply::platform_applier_unchecked(Box::new(RealCommandRunner), &document.device);
    recover_with_elevation(path, &mut *applier, aevan_tun::elevation()).map(Some)
}

fn tun_error(error: TunError) -> AevanError {
    match error {
        TunError::Permission(message) => AevanError::Privilege(message.to_owned()),
        TunError::Unsupported(message) => AevanError::Unsupported(message.to_owned()),
        TunError::InvalidConfig(message) => AevanError::Config(message),
        TunError::Io(error) => AevanError::Io(error),
    }
}

fn remove_file(path: &Path) -> AevanResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AevanError::Io(error)),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> AevanResult<()> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AevanError::Io)?;
    }
    let temp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temp)
            .map_err(AevanError::Io)?;
        file.write_all(bytes).map_err(AevanError::Io)?;
        file.sync_all().map_err(AevanError::Io)?;
    }
    fs::rename(&temp, path).map_err(AevanError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> AevanResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AevanError::Io)?;
    }
    let temp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .map_err(AevanError::Io)?;
        file.write_all(bytes).map_err(AevanError::Io)?;
        file.sync_all().map_err(AevanError::Io)?;
    }
    // Windows cannot rename over an existing file.
    let _ = fs::remove_file(path);
    fs::rename(&temp, path).map_err(AevanError::Io)?;
    Ok(())
}

/// Current time as Unix seconds, for journal metadata.
#[allow(dead_code)]
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct Recorder {
        applied: Rc<RefCell<Vec<Change>>>,
    }

    impl RollbackBackend for Recorder {
        fn apply(&mut self, change: &Change) -> Result<(), TunError> {
            self.applied.borrow_mut().push(change.clone());
            Ok(())
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aevan-daemon-{label}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn route(octet: u8) -> Route {
        Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, octet, 0)), 16).expect("route")
    }

    fn dns(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 251, 3, octet))
    }

    fn changes() -> Vec<Change> {
        vec![
            Change::SetAddr {
                old: None,
                new: Some((dns(1), 32)),
            },
            Change::SetMtu {
                old: None,
                new: Some(1396),
            },
            Change::AddRoute(route(1)),
            Change::SetDns {
                old: Vec::new(),
                new: vec![dns(18)],
                context: aevan_tun::DnsContext::Unspecified,
            },
        ]
    }

    #[test]
    fn journal_starts_empty_and_records_each_change_before_apply() {
        let dir = TempDir::new("record");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");

        assert!(path.exists());
        assert!(load(&path).expect("load").changes.is_empty());

        for (index, change) in changes().into_iter().enumerate() {
            journal.record(&change).expect("record");
            assert_eq!(
                load(&path).expect("load").changes.len(),
                index + 1,
                "each applied change is persisted before the next"
            );
        }

        let document = load(&path).expect("load");
        assert_eq!(document.changes.len(), 4);
        assert_eq!(document.device, "aevan");
    }

    #[test]
    fn every_change_variant_round_trips_through_json() {
        let changes = vec![
            Change::SetAddr {
                old: Some((dns(1), 24)),
                new: Some((dns(2), 32)),
            },
            Change::SetMtu {
                old: Some(1500),
                new: Some(1396),
            },
            Change::SetRoutes {
                old: vec![route(1)],
                new: vec![route(2)],
            },
            Change::SetDns {
                old: vec![dns(1)],
                new: vec![dns(18)],
                context: aevan_tun::DnsContext::MacosService("Wi-Fi".into()),
            },
            Change::AddRoute(route(3)),
            Change::RemoveRoute(route(4)),
            Change::ReplaceRoute {
                route: route(5),
                displaced: RouteRecord {
                    destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                    prefix_len: 8,
                    gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    interface: "en0".into(),
                    flags: "UP,GATEWAY,DONE,STATIC".into(),
                    metric: 600,
                },
                restore: false,
            },
        ];
        for change in changes {
            let journal_change = JournalChange::from(&change);
            let text = serde_json::to_string(&journal_change).expect("serialise");
            let parsed: JournalChange = serde_json::from_str(&text).expect("parse");
            assert_eq!(parsed.to_change().expect("to change"), change, "{text}");
        }
    }

    #[test]
    fn a_failed_step_can_be_forgotten() {
        let dir = TempDir::new("forget");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");
        journal.record(&changes()[0]).expect("record");
        journal.forget_last().expect("forget");
        assert!(load(&path).expect("load").changes.is_empty());
    }

    #[test]
    fn clean_teardown_removes_the_journal() {
        let dir = TempDir::new("remove");
        let path = journal_path(&dir.0);
        let journal = Journal::create(path.clone(), "aevan").expect("create");
        assert!(path.exists());
        journal.remove().expect("remove");
        assert!(!path.exists());
    }

    #[test]
    fn recovery_reverses_still_applied_changes_in_reverse_order_and_removes_the_file() {
        let dir = TempDir::new("recover");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");
        for change in changes() {
            journal.record(&change).expect("record");
        }
        drop(journal);

        let recorder = Recorder::default();
        let report = recover_with(&path, &mut recorder.clone()).expect("recover");

        assert_eq!(report.rolled_back, 4);
        assert!(report.failures.is_empty());
        assert!(report.removed);
        assert!(!path.exists());

        let applied = recorder.applied.borrow().clone();
        assert_eq!(applied.len(), 4);
        assert_eq!(
            applied[0],
            Change::SetDns {
                old: vec![dns(18)],
                new: Vec::new(),
                context: aevan_tun::DnsContext::Unspecified,
            }
        );
        assert_eq!(applied[1], Change::RemoveRoute(route(1)));
        assert_eq!(
            applied[2],
            Change::SetMtu {
                old: Some(1396),
                new: None
            }
        );
        assert_eq!(
            applied[3],
            Change::SetAddr {
                old: Some((dns(1), 32)),
                new: None
            }
        );
    }

    #[test]
    fn a_failed_inverse_keeps_the_journal() {
        struct Failing;
        impl RollbackBackend for Failing {
            fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
                Err(TunError::Permission("denied".into()))
            }
        }

        let dir = TempDir::new("failed");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");
        journal.record(&changes()[0]).expect("record");
        drop(journal);

        let report = recover_with(&path, &mut Failing).expect("recover");
        assert_eq!(report.rolled_back, 0);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].step, "address");
        assert!(report.failures[0].reason.contains("denied"));
        assert!(!report.removed);
        assert!(path.exists());
    }

    #[test]
    fn a_device_absent_journal_is_skipped_without_calling_the_backend() {
        #[derive(Default)]
        struct DeviceAbsent {
            touched: Rc<RefCell<Vec<Change>>>,
        }

        impl RollbackBackend for DeviceAbsent {
            fn apply(&mut self, change: &Change) -> Result<(), TunError> {
                self.touched.borrow_mut().push(change.clone());
                Ok(())
            }

            fn device_present(&mut self) -> Result<bool, TunError> {
                Ok(false)
            }
        }

        let dir = TempDir::new("device-absent");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");
        for change in changes() {
            journal.record(&change).expect("record");
        }
        drop(journal);

        let mut backend = DeviceAbsent::default();
        let touched = backend.touched.clone();
        // Absence must be established before the privilege check, so recovery
        // succeeds with no elevation at all.
        let report = recover_with_elevation(&path, &mut backend, Elevation::NotElevated)
            .expect("an absent device needs no privilege");

        assert_eq!(report.rolled_back, 0);
        assert_eq!(report.skipped_absent, 4);
        assert_eq!(report.failed(), 0);
        assert!(report.removed);
        assert!(!path.exists());
        assert!(
            touched.borrow().is_empty(),
            "no platform command may run when the device is absent"
        );
    }

    // Linux checks `/dev/net/tun` rather than elevation for this seam.
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn live_state_without_elevation_refuses_and_keeps_the_journal() {
        #[derive(Default)]
        struct Live {
            touched: Rc<RefCell<usize>>,
        }

        impl RollbackBackend for Live {
            fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
                Ok(())
            }

            fn device_present(&mut self) -> Result<bool, TunError> {
                Ok(true)
            }

            fn undo(&mut self, _change: &Change) -> Result<UndoOutcome, TunError> {
                *self.touched.borrow_mut() += 1;
                Ok(UndoOutcome::RolledBack)
            }
        }

        let dir = TempDir::new("live-no-elevation");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");
        for change in changes() {
            journal.record(&change).expect("record");
        }
        drop(journal);

        let mut backend = Live::default();
        let touched = backend.touched.clone();
        let error = recover_with_elevation(&path, &mut backend, Elevation::NotElevated)
            .expect_err("live state requires elevation");

        assert!(matches!(error, AevanError::Privilege(_)));
        assert!(
            error.to_string().contains("elevation"),
            "the refusal must name elevation: {error}"
        );
        assert!(path.exists(), "the live journal must be retained");
        assert_eq!(*touched.borrow(), 0, "no inverse may run without elevation");
    }

    #[test]
    fn an_already_absent_delete_is_counted_as_skipped_not_failed() {
        struct AlreadyAbsent;
        impl RollbackBackend for AlreadyAbsent {
            fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
                Err(TunError::Io(std::io::Error::other(
                    "The system cannot find the file specified.",
                )))
            }

            fn undo(&mut self, _change: &Change) -> Result<UndoOutcome, TunError> {
                Err(TunError::Io(std::io::Error::other(
                    "The system cannot find the file specified.",
                )))
            }
        }

        let dir = TempDir::new("already-absent");
        let path = journal_path(&dir.0);
        let mut journal = Journal::create(path.clone(), "aevan").expect("create");
        journal.record(&changes()[2]).expect("record route");
        drop(journal);

        let report = recover_with(&path, &mut AlreadyAbsent).expect("recover");
        assert_eq!(report.rolled_back, 0);
        assert_eq!(report.skipped_absent, 1);
        assert_eq!(report.failed(), 0);
        assert!(report.removed);
        assert!(!path.exists());
    }

    #[test]
    fn a_clean_and_a_dirty_journal_are_distinguished_by_the_same_report() {
        #[derive(Clone, Default)]
        struct Mixed {
            calls: Rc<RefCell<usize>>,
        }
        impl RollbackBackend for Mixed {
            fn apply(&mut self, _change: &Change) -> Result<(), TunError> {
                *self.calls.borrow_mut() += 1;
                Ok(())
            }

            fn undo(&mut self, _change: &Change) -> Result<UndoOutcome, TunError> {
                *self.calls.borrow_mut() += 1;
                Err(TunError::Permission("denied".into()))
            }
        }

        let clean_dir = TempDir::new("reset-clean");
        let clean_path = journal_path(&clean_dir.0);
        let mut clean = Journal::create(clean_path.clone(), "aevan").expect("create");
        for change in changes() {
            clean.record(&change).expect("record");
        }
        drop(clean);
        let clean_report = recover_with(&clean_path, &mut Recorder::default()).expect("clean");
        assert!(clean_report.is_complete());
        assert!(clean_report.removed);
        assert!(!clean_path.exists());

        let dirty_dir = TempDir::new("reset-dirty");
        let dirty_path = journal_path(&dirty_dir.0);
        let mut dirty = Journal::create(dirty_path.clone(), "aevan").expect("create");
        dirty.record(&changes()[0]).expect("record");
        drop(dirty);
        let dirty_report = recover_with(&dirty_path, &mut Mixed::default()).expect("dirty");
        assert!(!dirty_report.is_complete());
        assert_eq!(dirty_report.failed(), 1);
        assert!(!dirty_report.removed);
        assert!(dirty_path.exists());
    }

    #[test]
    fn an_empty_journal_is_removed_without_needing_a_backend() {
        let dir = TempDir::new("empty");
        let path = journal_path(&dir.0);
        let journal = Journal::create(path.clone(), "aevan").expect("create");
        drop(journal);

        let report = recover(&path).expect("recover").expect("journal");
        assert_eq!(report.rolled_back, 0);
        assert!(report.failures.is_empty());
        assert!(report.removed);
        assert!(!path.exists());
    }

    #[test]
    fn a_malformed_journal_is_a_typed_error() {
        let dir = TempDir::new("bad");
        let path = journal_path(&dir.0);
        fs::write(&path, b"not json").expect("write");
        assert!(matches!(load(&path), Err(AevanError::Config(_))));
    }

    #[cfg(unix)]
    #[test]
    fn the_journal_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("mode");
        let path = journal_path(&dir.0);
        let journal = Journal::create(path.clone(), "aevan").expect("create");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(journal);
    }
}
