#![deny(unsafe_code)]
//! L3 device abstraction, route diffing and rollback for `aevan`.
//!
//! The [`Device`] surface is fixed. This crate ships the trait,
//! a no-op backend for tests and a reverted-change stack that is idempotent and
//! also runs from [`Drop`]. The per-OS backends are real: Wintun on Windows,
//! `utun` on macOS and `/dev/net/tun` on Linux. [`platform`] also exposes an
//! honest availability probe; macOS and Linux need root to create a device.
//!
//! This crate is the only place where platform code uses `unsafe`. The shared
//! code below denies it; the per-OS modules opt out explicitly so the raw
//! kernel interfaces stay confined to one file per platform.

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
pub use rollback::{Change, DnsContext, RollbackBackend, Session, UndoOutcome};
pub use route::{diff_routes, Route, RouteDiff};
