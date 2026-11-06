//! Daemon controller: one connection at a time, guarded before any credential is
//! sent, with a blocking connector and an async control surface.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;
use zeroize::Zeroizing;

use aevan_core::{AevanError, AevanResult, Profile, ProfileStore};

use crate::auth::{self, AuthCredentials};
use crate::connector::{self, ConnectOptions, ConnectionInfo, TunnelControl};
use crate::journal;
use crate::logs::LogHub;
use crate::protocol::StatusReport;
use crate::state::{unix_now, DaemonState, SessionInfo, SharedStatus};

/// Longest teardown the control surface waits for before reporting failure.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(30);

struct ConnectionHandle {
    stop: Arc<AtomicBool>,
    done: oneshot::Receiver<()>,
}

/// The running daemon.
pub struct Daemon {
    status: Arc<SharedStatus>,
    logs: LogHub,
    connection: Mutex<Option<ConnectionHandle>>,
    shutdown_requested: AtomicBool,
    shutdown: Notify,
    journal_path: PathBuf,
}

impl Daemon {
    /// Build a daemon for `config_dir`.
    pub fn new(config_dir: &Path, logs: LogHub) -> Self {
        Self {
            status: Arc::new(SharedStatus::new()),
            logs,
            connection: Mutex::new(None),
            shutdown_requested: AtomicBool::new(false),
            shutdown: Notify::new(),
            journal_path: journal::journal_path(config_dir),
        }
    }

    /// The shared log hub.
    pub fn logs(&self) -> &LogHub {
        &self.logs
    }

    /// Current status snapshot.
    ///
    /// If the journal disappeared while the daemon was in
    /// `recovery-incomplete` (for example an operator removed it after fixing
    /// the platform state), the state clears automatically.
    pub fn snapshot(&self) -> StatusReport {
        if matches!(self.status.state(), DaemonState::RecoveryIncomplete)
            && !self.journal_path.exists()
        {
            self.status.clear_recovery();
        }
        self.status.snapshot()
    }

    /// Mark an unrecovered journal as a failure visible to `status`.
    pub fn mark_recovery_failed(&self, reason: impl Into<String>) {
        self.status.set_failed(reason);
    }

    /// Record an incomplete recovery with its machine-readable counts.
    pub fn mark_recovery_incomplete(&self, report: crate::protocol::RecoveryReport) {
        self.status.set_recovery_incomplete(report);
    }

    /// Re-run crash recovery for an operator (`aevan reset`).
    ///
    /// Refuses while a tunnel is live: the journal describes live state then,
    /// and rolling it back would tear down a working connection. Deletes the
    /// journal only when no genuine failure remains.
    pub async fn recover(&self) -> AevanResult<crate::protocol::RecoveryReport> {
        let state = self.status.state();
        if !state.can_recover() {
            return Err(AevanError::AlreadyInState(format!(
                "cannot retry journal recovery while the daemon is {state}"
            )));
        }
        // An idle daemon with a journal on disk is not the usual recovery
        // case: the journal may belong to another live foreground connector.
        // Refuse rather than rolling back state this daemon does not own.
        if matches!(state, DaemonState::Disconnected) && self.journal_path.exists() {
            return Err(AevanError::AlreadyInState(format!(
                "an unrecovered journal is present at {}; refusing to roll it back while the daemon is idle",
                self.journal_path.display()
            )));
        }
        let path = self.journal_path.clone();
        let journal_path = path.display().to_string();
        let recovered = tokio::task::spawn_blocking(move || journal::recover(&path))
            .await
            .map_err(|error| {
                AevanError::Config(format!("the recovery worker stopped: {error}"))
            })??;
        let report = recovered.unwrap_or_else(|| {
            let mut report = crate::protocol::RecoveryReport::clean();
            report.journal = Some(journal_path);
            report
        });
        if report.failed() > 0 {
            self.status.set_recovery_incomplete(report.clone());
        } else {
            self.status.clear_recovery();
        }
        Ok(report)
    }

    fn select_profile(&self, name: Option<&str>) -> AevanResult<Profile> {
        let store = ProfileStore::load(&ProfileStore::default_path()?)?;
        match name {
            Some(name) => store
                .get(name)
                .cloned()
                .ok_or_else(|| AevanError::Config(format!("profile '{name}' was not found"))),
            None => store.default_profile().cloned().ok_or_else(|| {
                AevanError::Config(
                    "no profile is selected; add one with `aevan profile add` or pass a profile name"
                        .into(),
                )
            }),
        }
    }

    /// Connect once. The guard is taken before the blocking task starts.
    pub async fn connect(
        &self,
        profile_name: Option<String>,
        username: Option<String>,
        password: Zeroizing<String>,
        token: Option<Zeroizing<String>>,
    ) -> AevanResult<StatusReport> {
        let profile = self.select_profile(profile_name.as_deref())?;

        // The guard is checked twice: here for a clear message, then inside
        // reserve_connect under one lock so a concurrent call cannot slip in.
        let state = self.status.state();
        if !state.can_connect() {
            return Err(AevanError::AlreadyInState(format!(
                "the daemon is already {state}"
            )));
        }
        if self.journal_path.exists() {
            return Err(AevanError::Config(format!(
                "an unrecovered journal is present at {}; refusing a new connect",
                self.journal_path.display()
            )));
        }

        let username = match username {
            Some(username) if !username.trim().is_empty() => username,
            _ => profile.username.clone().ok_or_else(|| {
                AevanError::Config(
                    "the connect request has no username and the profile has none".into(),
                )
            })?,
        };
        if password.is_empty() {
            return Err(AevanError::Config("password must not be empty".into()));
        }

        self.status.reserve_connect(&profile.name)?;
        // Drop a handle left by an ended connection.
        let _ = self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();

        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let control = DaemonControl::new(self.status.clone(), stop.clone(), ready_tx);

        let task = ConnectionTask {
            profile,
            username,
            password,
            token,
            status: self.status.clone(),
            control,
            journal_path: self.journal_path.clone(),
            done: done_tx,
        };
        tokio::task::spawn_blocking(move || run_connection(task));

        *self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ConnectionHandle {
            stop,
            done: done_rx,
        });

        match ready_rx.await {
            Ok(Ok(_info)) => {
                let snapshot = self.status.snapshot();
                if snapshot.state != "connected" {
                    return Err(AevanError::Network(format!(
                        "the tunnel ended before the connect request completed (state: {})",
                        snapshot.state
                    )));
                }
                Ok(snapshot)
            }
            Ok(Err(error)) => {
                let _ = self
                    .connection
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                Err(error)
            }
            Err(_) => {
                let _ = self
                    .connection
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                self.status
                    .set_failed("the connector stopped before reporting a result");
                Err(AevanError::Config(
                    "the connector stopped before reporting a result".into(),
                ))
            }
        }
    }

    /// Disconnect the live tunnel.
    pub async fn disconnect(&self, profile: Option<&str>, _all: bool) -> AevanResult<StatusReport> {
        let state = self.status.state();
        if !state.can_disconnect() {
            return Err(AevanError::AlreadyInState(format!(
                "the daemon is already {state}"
            )));
        }
        if let Some(profile) = profile {
            let current = self.status.snapshot().profile;
            if current.as_deref() != Some(profile) {
                return Err(AevanError::AlreadyInState(format!(
                    "the daemon is not connected with profile '{profile}'"
                )));
            }
        }

        self.status.begin_disconnecting()?;
        let handle = self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.stop.store(true, Ordering::SeqCst);
            if timeout(TEARDOWN_TIMEOUT, handle.done).await.is_err() {
                self.status
                    .set_failed("teardown did not finish within 30 seconds");
                return Err(AevanError::Network(
                    "teardown did not finish within 30 seconds".into(),
                ));
            }
        }
        if matches!(self.status.state(), DaemonState::Disconnecting) {
            self.status.set_disconnected();
        }
        Ok(self.status.snapshot())
    }

    /// Ask the accept loop to stop and signal the live tunnel.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.shutdown.notify_one();
    }

    /// Whether shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Wait for a shutdown request.
    pub async fn wait_for_shutdown(&self) {
        self.shutdown.notified().await;
    }

    /// Stop the live tunnel for process shutdown.
    pub async fn stop_connection(&self) {
        let handle = self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            if self.status.state().can_disconnect() {
                let _ = self.status.begin_disconnecting();
            }
            handle.stop.store(true, Ordering::SeqCst);
            if timeout(TEARDOWN_TIMEOUT, handle.done).await.is_err() {
                tracing::warn!("teardown did not finish during shutdown");
            }
        }
    }
}

struct ConnectionTask {
    profile: Profile,
    username: String,
    password: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
    status: Arc<SharedStatus>,
    control: DaemonControl,
    journal_path: PathBuf,
    done: oneshot::Sender<()>,
}

/// Run the blocking half: authenticate once, then hand off to the connector.
fn run_connection(task: ConnectionTask) {
    let ConnectionTask {
        profile,
        username,
        password,
        token,
        status,
        control,
        journal_path,
        done,
    } = task;

    let result = auth::authenticate(
        &profile,
        AuthCredentials::new(username, password, token),
        || Ok(None),
    )
    .and_then(|mut session| {
        if control.should_stop() {
            return Err(AevanError::AlreadyInState("connect cancelled".into()));
        }
        status.begin_connecting();
        connector::connect_session(
            &profile,
            &mut session,
            &control,
            ConnectOptions { dry_run: false },
            Some(&journal_path),
        )
    });

    let stopped = control.should_stop();
    match &result {
        Ok(()) => status.set_disconnected(),
        Err(_) if stopped => status.set_disconnected(),
        Err(error) => {
            status.set_failed(error.to_string());
            control.fail_ready(error);
        }
    }
    let _ = done.send(());
}

/// [`TunnelControl`] implementation backed by the daemon's shared state.
struct DaemonControl {
    status: Arc<SharedStatus>,
    stop: Arc<AtomicBool>,
    ready: Mutex<Option<oneshot::Sender<Result<ConnectionInfo, AevanError>>>>,
}

impl DaemonControl {
    fn new(
        status: Arc<SharedStatus>,
        stop: Arc<AtomicBool>,
        ready: oneshot::Sender<Result<ConnectionInfo, AevanError>>,
    ) -> Self {
        Self {
            status,
            stop,
            ready: Mutex::new(Some(ready)),
        }
    }

    fn fail_ready(&self, error: &AevanError) {
        if let Some(sender) = self
            .ready
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = sender.send(Err(AevanError::from_exit_code(
                error.exit_code(),
                error.to_string(),
            )));
        }
    }
}

impl TunnelControl for DaemonControl {
    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn connected(&self, info: &ConnectionInfo) {
        self.status.set_connected(SessionInfo {
            profile: info.profile.clone(),
            device: info.device.clone(),
            address: info.address,
            prefix_len: info.prefix_len,
            mtu: info.mtu,
            route_count: info.route_count,
            dns: info.dns.clone(),
            connected_unix: unix_now(),
        });
        if let Some(sender) = self
            .ready
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = sender.send(Ok(info.clone()));
        }
    }

    fn stats(&self, bytes_in: u64, bytes_out: u64) {
        self.status.set_bytes(bytes_in, bytes_out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn status() -> Arc<SharedStatus> {
        Arc::new(SharedStatus::new())
    }

    #[test]
    fn the_daemon_control_updates_state_and_ready() {
        let status = status();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = oneshot::channel();
        let control = DaemonControl::new(status.clone(), stop.clone(), tx);

        let info = ConnectionInfo {
            profile: "example".into(),
            device: "aevan".into(),
            address: Some("10.251.98.141".parse().expect("address")),
            prefix_len: 32,
            mtu: Some(1396),
            route_count: 4,
            dns: vec!["10.251.3.18".parse().expect("dns")],
        };
        control.connected(&info);

        assert_eq!(status.state(), DaemonState::Connected);
        assert_eq!(status.snapshot().address.as_deref(), Some("10.251.98.141"));
        let ready = rx.try_recv().expect("ready").expect("ok");
        assert_eq!(ready, info);

        control.stats(12, 34);
        let snapshot = status.snapshot();
        assert_eq!(snapshot.bytes_in, 12);
        assert_eq!(snapshot.bytes_out, 34);

        stop.store(true, Ordering::SeqCst);
        assert!(control.should_stop());
    }

    #[test]
    fn failed_ready_preserves_the_exit_code() {
        let status = status();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = oneshot::channel();
        let control = DaemonControl::new(status, stop, tx);

        control.fail_ready(&AevanError::AuthRejected("denied".into()));
        let error = rx.try_recv().expect("ready").expect_err("error");
        assert_eq!(error.exit_code(), 3);
    }
}
