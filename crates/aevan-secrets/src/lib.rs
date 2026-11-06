#![deny(unsafe_code)]
//! Secret storage and one-time passwords.
//!
//! Passwords are never persisted by default, a TOTP secret lives only in the
//! OS keyring, and codes are generated per attempt (single use, never cached).
//!
//! M0 provides the abstraction, an in-memory store for tests, a keyring-backed
//! store (used once `--remember` lands at M3) and RFC 6238 TOTP with SHA-1,
//! six digits and a 30-second period. Nothing here writes a password to disk.

pub mod store;
pub mod totp;

pub use store::{KeyringStore, MemoryStore, Secret, SecretError, SecretStore};
pub use totp::{decode_base32, hotp, Totp, TotpError, DEFAULT_DIGITS, DEFAULT_PERIOD};
