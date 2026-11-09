#![deny(unsafe_code)]
//! Connector supervisor, control socket and crash recovery for `aevan` (M3).
//!
//! The daemon owns the whole tunnel lifecycle:
//!
//! 1. [`auth`] performs exactly one credential attempt, shared with the CLI.
//! 2. [`connector`] performs one oNCP handshake, writes the [`journal`] before
//!    changing routes/DNS/MTU, applies the configuration, runs ESP and tears
//!    down.
//! 3. [`runtime`] enforces the single-connection guard and exposes the state
//!    machine to the control surface.
//! 4. [`protocol`] and [`server`] implement the versioned JSON-line control
//!    endpoint; [`client`] is the blocking CLI side.
//!
//! The binary is `aevand` (`src/main.rs`).

pub mod auth;
pub mod autostart;
pub mod client;
pub mod connector;
pub mod elevate;
pub mod journal;
pub mod launchd;
pub mod logs;
pub mod pipe_security;
pub mod protocol;
pub mod runtime;
pub mod server;
pub mod state;

pub use client::{daemon_binary_beside_executable, start_daemon, ClientError};
pub use connector::{ApplyPlan, ConnectOptions, ConnectionInfo, TunnelControl};
pub use elevate::StartOutcome;
pub use journal::Journal;
pub use logs::{Level, LogHub, LogLayer};
pub use protocol::{
    LogRecord, RecoveryFailure, RecoveryReport, Request, Response, SecretString, StatusReport,
    SCHEMA_VERSION,
};
pub use runtime::Daemon;
pub use state::{DaemonState, SessionInfo, SharedStatus};

/// Milestone implemented by this crate.
pub const MILESTONE: &str = "M3";

/// Build the multi-threaded runtime the daemon uses.
pub fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_can_be_built_without_starting_work() {
        let runtime = build_runtime().expect("runtime");
        drop(runtime);
    }

    #[test]
    fn the_public_schema_version_is_stable() {
        assert_eq!(SCHEMA_VERSION, 2);
    }
}
