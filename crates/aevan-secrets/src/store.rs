//! Secret storage abstraction.
//!
//! [`MemoryStore`] exists for tests and for the lifetime of a single process.
//! [`KeyringStore`] is the production path; it is wired into the CLI at M3 when
//! `--remember` becomes available. No implementation here writes secrets to a
//! profile file or a log.

use std::collections::HashMap;

use zeroize::Zeroizing;

/// A secret string that zeroizes its buffer on drop.
///
/// The type intentionally does not implement `Debug`, `Display`, `Serialize`
/// or `Clone`, so it cannot leak through a log statement or a copied config.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrow the plaintext. Callers must not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length in bytes (not characters).
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

/// Errors from a secret backend. Messages never echo the secret value.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The platform has no usable secret service.
    #[error("secret storage is unavailable: {0}")]
    Unavailable(String),
    /// The backend rejected the operation.
    #[error("secret storage error: {0}")]
    Backend(String),
}

/// A minimal secret store keyed by service and account.
pub trait SecretStore {
    /// Fetch a secret, or `None` if it does not exist.
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, SecretError>;

    /// Store or replace a secret.
    fn set(&mut self, service: &str, account: &str, secret: Secret) -> Result<(), SecretError>;

    /// Remove a secret. Removing a missing entry is not an error.
    fn delete(&mut self, service: &str, account: &str) -> Result<(), SecretError>;
}

/// In-memory store used by tests and by a single foreground session.
#[derive(Default)]
pub struct MemoryStore {
    entries: HashMap<(String, String), Secret>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, SecretError> {
        // The trait returns an owned secret; rebuild it from the stored value.
        Ok(self
            .entries
            .get(&(service.to_owned(), account.to_owned()))
            .map(|secret| Secret::new(secret.expose().to_owned())))
    }

    fn set(&mut self, service: &str, account: &str, secret: Secret) -> Result<(), SecretError> {
        self.entries
            .insert((service.to_owned(), account.to_owned()), secret);
        Ok(())
    }

    fn delete(&mut self, service: &str, account: &str) -> Result<(), SecretError> {
        self.entries
            .remove(&(service.to_owned(), account.to_owned()));
        Ok(())
    }
}

/// OS keyring backed store.
///
/// The `keyring` crate is built without platform features at M0; on a platform
/// without a configured backend the operation returns
/// [`SecretError::Unavailable`] instead of panicking.
pub struct KeyringStore;

impl KeyringStore {
    /// Construct the store.
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeyringStore {
    fn default() -> Self {
        Self::new()
    }
}

fn map_keyring_error(error: keyring::Error) -> SecretError {
    match error {
        keyring::Error::NoEntry => SecretError::Backend("no entry".into()),
        other => SecretError::Unavailable(other.to_string()),
    }
}

impl SecretStore for KeyringStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, SecretError> {
        let entry = keyring::Entry::new(service, account).map_err(map_keyring_error)?;
        match entry.get_password() {
            Ok(password) => Ok(Some(Secret::new(password))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(error)),
        }
    }

    fn set(&mut self, service: &str, account: &str, secret: Secret) -> Result<(), SecretError> {
        let entry = keyring::Entry::new(service, account).map_err(map_keyring_error)?;
        entry
            .set_password(secret.expose())
            .map_err(map_keyring_error)
    }

    fn delete(&mut self, service: &str, account: &str) -> Result<(), SecretError> {
        let entry = keyring::Entry::new(service, account).map_err(map_keyring_error)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_keyring_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trips() {
        let mut store = MemoryStore::new();
        assert!(store.is_empty());

        store
            .set("aevan", "example/password", Secret::new("hunter2"))
            .expect("set");
        assert_eq!(store.len(), 1);

        let fetched = store
            .get("aevan", "example/password")
            .expect("get")
            .expect("present");
        assert_eq!(fetched.expose(), "hunter2");

        store.delete("aevan", "example/password").expect("delete");
        assert!(store
            .get("aevan", "example/password")
            .expect("get")
            .is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn deleting_a_missing_entry_is_ok() {
        let mut store = MemoryStore::new();
        store.delete("aevan", "missing").expect("delete");
    }

    #[test]
    fn secret_reports_shape_without_exposing_in_errors() {
        let secret = Secret::new("abc");
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
        let empty = Secret::from("");
        assert!(empty.is_empty());
    }
}
