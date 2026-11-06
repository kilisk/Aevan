#![deny(unsafe_code)]
//! L3 device abstraction, route diffing and rollback for `aevan`.
//!
//! The [`Device`] surface is fixed. This crate ships the trait,
//! a no-op backend for tests and a reverted-change stack that is idempotent and
//! also runs from [`Drop`]. The real per-OS backends (Wintun, `utun`,
//! `/dev/net/tun`) are M2: [`platform`] exposes typed [`TunError::Unsupported`]
//! stubs and an honest availability probe.
//!
//! This crate is the only place where platform code will need `unsafe` in a
//! later milestone. The shared code below denies it; the per-OS modules opt out
//! explicitly so the M2 implementations can make that decision locally.

pub mod apply;
pub mod command;
pub mod device;
pub mod error;
pub mod platform;
pub mod privilege;
pub mod rollback;
pub mod route;

pub use apply::{platform_applier, Applier};
pub use command::{CommandCall, CommandRunner, Output, RealCommandRunner, RecordingRunner};
pub use device::{Device, DeviceConfig, NoopBackend};
pub use error::TunError;
pub use platform::{Availability, Readiness, WaitHandle, WaitSources};
pub use privilege::{elevation, Elevation};
pub use rollback::{Change, RollbackBackend, Session, UndoOutcome};
pub use route::{diff_routes, Route, RouteDiff};
