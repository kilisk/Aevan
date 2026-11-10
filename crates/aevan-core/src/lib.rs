#![deny(unsafe_code)]
//! Core types shared by every `aevan` crate.
//!
//! This crate deliberately contains no network or platform logic. It owns the
//! connection-profile model, the connect state machine types, the error
//! taxonomy (including the public exit codes) and the log-redaction helpers.
//!
//! Credentials must never be passed to these types as command-line arguments,
//! environment variables or log fields. [`redact`] exists so that diagnostic
//! output can be made safe before it is printed or persisted.

pub mod capabilities;
pub mod error;
pub mod paths;
pub mod profile;
pub mod redact;
pub mod state;
pub mod timezone;

pub use capabilities::{Capability, Platform, CAPABILITIES};
pub use error::{exit_code, AevanError, AevanResult};
pub use paths::{default_config_path, default_profiles_path};
pub use profile::{Profile, ProfileStore, RealmSource, SplitTunnelIntent};
pub use state::State;
pub use timezone::local_utc_offset_minutes;
