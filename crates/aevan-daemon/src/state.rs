//! The daemon's connection state machine and the state shared with the control
//! server.
//!
//! The daemon owns one observable state machine for M3 and admits one
//! connection at a time: [`SharedStatus::reserve_connect`] is the single-attempt
//! guard, and it runs before any credential is sent so a second `connect` can
//! never reach the gateway.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aevan_core::{AevanError, AevanResult};

use crate::protocol::{RecoveryReport, StatusReport};

/// Observable daemon state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonState {
    /// No tunnel is active.
    Disconnected,
    /// Credentials are being submitted (exactly one attempt).
    Authenticating,
    /// Authenticated; the oNCP handshake and device configuration are running.
    Connecting,
    /// The tunnel is up.
    Connected,
    /// Teardown is restoring routes, DNS and the device.
    Disconnecting,
    /// Crash recovery left an interrupted journal that is not fully undone.
    RecoveryIncomplete,
    /// The last attempt failed; no tunnel is active.
    Failed {
        /// Human-readable reason. Never contains credentials.
        reason: String,
    },
}

impl DaemonState {
    /// Stable lower-case name used by the control protocol.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Authenticating => "authenticating",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::RecoveryIncomplete => "recovery-incomplete",
            Self::Failed { .. } => "failed",
        }
    }

    /// Failure reason, when the state is [`DaemonState::Failed`].
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Failed { reason } => Some(reason),
            _ => None,
        }
    }

    /// Whether an active tunnel exists.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Whether a new connect request may begin.
    pub fn can_connect(&self) -> bool {
        matches!(self, Self::Disconnected | Self::Failed { .. })
    }

    /// Whether a disconnect request is meaningful.
    pub fn can_disconnect(&self) -> bool {
        matches!(
            self,
            Self::Authenticating | Self::Connecting | Self::Connected
        )
    }

    /// Whether journal recovery may run without disturbing a live tunnel.
    pub fn can_recover(&self) -> bool {
        matches!(
            self,
            Self::Disconnected | Self::RecoveryIncomplete | Self::Failed { .. }
        )
    }

    /// Whether a status poll should keep running.
    pub fn should_poll(&self) -> bool {
        matches!(
            self,
            Self::Authenticating
                | Self::Connecting
                | Self::Connected
                | Self::Disconnecting
                | Self::RecoveryIncomplete
        )
    }
}

impl std::fmt::Display for DaemonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Details of a live tunnel, reported by `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Profile name the tunnel was established with.
    pub profile: String,
    /// Tunnel device name.
    pub device: String,
    /// Assigned address.
    pub address: Option<IpAddr>,
    /// Prefix length for [`SessionInfo::address`].
    pub prefix_len: u8,
    /// Negotiated MTU.
    pub mtu: Option<u16>,
    /// Number of applied routes.
    pub route_count: usize,
    /// Applied DNS servers.
    pub dns: Vec<IpAddr>,
    /// Unix time when the tunnel became usable.
    pub connected_unix: u64,
}

/// State and counters shared by the control server and the blocking connector.
#[derive(Debug)]
pub struct SharedStatus {
    state: Mutex<DaemonState>,
    session: Mutex<Option<SessionInfo>>,
    profile: Mutex<Option<String>>,
    recovery: Mutex<Option<RecoveryReport>>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Default for SharedStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedStatus {
    /// A daemon with no connection.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(DaemonState::Disconnected),
            session: Mutex::new(None),
            profile: Mutex::new(None),
            recovery: Mutex::new(None),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        }
    }

    /// Current state.
    pub fn state(&self) -> DaemonState {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set_state(&self, state: DaemonState) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = state;
    }

    /// Claim the connection slot.
    ///
    /// This is the guard: it both checks and transitions under one lock, so two
    /// concurrent connects cannot both observe `Disconnected`. A rejected call
    /// returns exit code 5 and sends nothing to the gateway.
    pub fn reserve_connect(&self, profile: &str) -> AevanResult<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.can_connect() {
            return Err(AevanError::AlreadyInState(format!(
                "the daemon is already {state}"
            )));
        }
        *self
            .profile
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(profile.to_owned());
        *self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        *self
            .recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        *state = DaemonState::Authenticating;
        Ok(())
    }

    /// Move from authenticating to connecting, as the handshake starts.
    pub fn begin_connecting(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*state, DaemonState::Authenticating) {
            *state = DaemonState::Connecting;
        }
    }

    /// Record a live tunnel.
    pub fn set_connected(&self, session: SessionInfo) {
        *self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(session);
        self.clear_recovery_report();
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.set_state(DaemonState::Connected);
    }

    /// Move to `Disconnecting`. Returns exit code 5 when that is meaningless.
    pub fn begin_disconnecting(&self) -> AevanResult<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.can_disconnect() {
            return Err(AevanError::AlreadyInState(format!(
                "the daemon is already {state}"
            )));
        }
        *state = DaemonState::Disconnecting;
        Ok(())
    }

    /// Record a failed attempt.
    pub fn set_failed(&self, reason: impl Into<String>) {
        *self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.clear_recovery_report();
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.set_state(DaemonState::Failed {
            reason: reason.into(),
        });
    }

    /// Record a clean teardown.
    pub fn set_disconnected(&self) {
        *self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.clear_recovery_report();
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.set_state(DaemonState::Disconnected);
    }

    /// Record an interrupted journal that still has live state.
    pub fn set_recovery_incomplete(&self, report: RecoveryReport) {
        *self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        *self
            .recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(report);
        self.set_state(DaemonState::RecoveryIncomplete);
    }

    /// Clear recovery facts and leave `recovery-incomplete` for `Disconnected`.
    pub fn clear_recovery(&self) {
        self.clear_recovery_report();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*state, DaemonState::RecoveryIncomplete) {
            *state = DaemonState::Disconnected;
        }
    }

    fn clear_recovery_report(&self) {
        *self
            .recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Update the byte counters.
    pub fn set_bytes(&self, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.store(bytes_in, Ordering::Relaxed);
        self.bytes_out.store(bytes_out, Ordering::Relaxed);
    }

    /// Build the `status` report.
    pub fn snapshot(&self) -> StatusReport {
        let state = self.state();
        let session = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let profile = self
            .profile
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        let connected = state.is_connected();
        let now = unix_now();
        let recovery = self
            .recovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        StatusReport {
            state: state.name().to_owned(),
            reason: state.reason().map(str::to_owned),
            profile: session
                .as_ref()
                .map(|session| session.profile.clone())
                .or(profile),
            device: session.as_ref().map(|session| session.device.clone()),
            address: session
                .as_ref()
                .and_then(|session| session.address.map(|address| address.to_string())),
            prefix_len: session.as_ref().and_then(|session| {
                if session.address.is_some() {
                    Some(session.prefix_len)
                } else {
                    None
                }
            }),
            mtu: session.as_ref().and_then(|session| session.mtu),
            route_count: session
                .as_ref()
                .map(|session| session.route_count)
                .unwrap_or(0),
            dns: session
                .as_ref()
                .map(|session| {
                    session
                        .dns
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            bytes_in: if connected {
                self.bytes_in.load(Ordering::Relaxed)
            } else {
                0
            },
            bytes_out: if connected {
                self.bytes_out.load(Ordering::Relaxed)
            } else {
                0
            },
            uptime_secs: if connected {
                session
                    .as_ref()
                    .map(|session| now.saturating_sub(session.connected_unix))
                    .unwrap_or(0)
            } else {
                0
            },
            recovery,
        }
    }
}

/// Seconds since the Unix epoch, never negative.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionInfo {
        SessionInfo {
            profile: "example".into(),
            device: "aevan".into(),
            address: Some("10.251.98.141".parse().expect("address")),
            prefix_len: 32,
            mtu: Some(1396),
            route_count: 4,
            dns: vec!["10.251.3.18".parse().expect("dns")],
            connected_unix: unix_now(),
        }
    }

    #[test]
    fn state_names_are_the_documented_ones() {
        assert_eq!(DaemonState::Disconnected.name(), "disconnected");
        assert_eq!(DaemonState::Authenticating.name(), "authenticating");
        assert_eq!(DaemonState::Connecting.name(), "connecting");
        assert_eq!(DaemonState::Connected.name(), "connected");
        assert_eq!(DaemonState::Disconnecting.name(), "disconnecting");
        assert_eq!(
            DaemonState::RecoveryIncomplete.name(),
            "recovery-incomplete"
        );
        assert_eq!(
            DaemonState::Failed {
                reason: "tls".into()
            }
            .name(),
            "failed"
        );
    }

    #[test]
    fn connected_is_the_only_live_state() {
        assert!(DaemonState::Connected.is_connected());
        for state in [
            DaemonState::Disconnected,
            DaemonState::Authenticating,
            DaemonState::Connecting,
            DaemonState::Disconnecting,
            DaemonState::RecoveryIncomplete,
            DaemonState::Failed {
                reason: String::new(),
            },
        ] {
            assert!(!state.is_connected(), "{state} must not be live");
        }
    }

    #[test]
    fn connect_and_disconnect_guards_match_the_contract() {
        assert!(DaemonState::Disconnected.can_connect());
        assert!(DaemonState::Failed { reason: "x".into() }.can_connect());
        for state in [
            DaemonState::Authenticating,
            DaemonState::Connecting,
            DaemonState::Connected,
            DaemonState::Disconnecting,
            DaemonState::RecoveryIncomplete,
        ] {
            assert!(!state.can_connect(), "{state} must reject connect");
        }

        for state in [
            DaemonState::Authenticating,
            DaemonState::Connecting,
            DaemonState::Connected,
        ] {
            assert!(state.can_disconnect(), "{state} must accept disconnect");
        }
        assert!(!DaemonState::Disconnected.can_disconnect());
        assert!(!DaemonState::Disconnecting.can_disconnect());
        assert!(!DaemonState::Failed { reason: "x".into() }.can_disconnect());
        assert!(!DaemonState::RecoveryIncomplete.can_disconnect());
        assert!(DaemonState::RecoveryIncomplete.can_recover());
        assert!(!DaemonState::Connected.can_recover());
    }

    #[test]
    fn the_guard_rejects_a_second_connect_with_exit_5() {
        let status = SharedStatus::new();
        status.reserve_connect("example").expect("first connect");

        let error = status
            .reserve_connect("example")
            .expect_err("second connect");
        assert!(matches!(error, AevanError::AlreadyInState(_)));
        assert_eq!(error.exit_code(), 5);
        assert_eq!(status.state(), DaemonState::Authenticating);
    }

    #[test]
    fn the_guard_rejects_connect_while_connected_and_after_teardown_allows_it() {
        let status = SharedStatus::new();
        status.reserve_connect("example").expect("reserve");
        status.begin_connecting();
        status.set_connected(session());
        assert_eq!(status.state(), DaemonState::Connected);

        let error = status.reserve_connect("example").expect_err("connected");
        assert_eq!(error.exit_code(), 5);

        status.begin_disconnecting().expect("disconnect");
        status.set_disconnected();
        assert!(status.reserve_connect("example").is_ok());
    }

    #[test]
    fn disconnect_while_disconnected_is_exit_5() {
        let status = SharedStatus::new();
        let error = status.begin_disconnecting().expect_err("nothing to stop");
        assert_eq!(error.exit_code(), 5);
    }

    #[test]
    fn snapshot_reports_the_documented_fields_without_key_material() {
        let status = SharedStatus::new();
        status.reserve_connect("example").expect("reserve");
        status.begin_connecting();
        status.set_connected(session());
        status.set_bytes(123, 456);

        let report = status.snapshot();
        assert_eq!(report.state, "connected");
        assert_eq!(report.profile.as_deref(), Some("example"));
        assert_eq!(report.address.as_deref(), Some("10.251.98.141"));
        assert_eq!(report.prefix_len, Some(32));
        assert_eq!(report.mtu, Some(1396));
        assert_eq!(report.route_count, 4);
        assert_eq!(report.dns, vec!["10.251.3.18".to_owned()]);
        assert_eq!(report.bytes_in, 123);
        assert_eq!(report.bytes_out, 456);
        assert_eq!(report.uptime_secs, 0);

        let json = serde_json::to_string(&report).expect("json");
        for secret in ["password", "token", "key", "spi", "cookie"] {
            assert!(!json.contains(secret), "status leaked {secret}: {json}");
        }
    }
}
