//! Secret storage abstraction.
//!
//! [`MemoryStore`] exists for tests and for the lifetime of a single process.
//! [`KeyringStore`] is the Windows production path. [`FileStore`] is the
//! owner-only file backend used on macOS and Linux, where this build does not
//! compile a keyring backend. No implementation here writes a secret to a
//! profile file or a log.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

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
    /// The owner-only file backend could not be read or written.
    #[error("cannot access the secret store at {path}: {source}")]
    Io {
        /// Store path, so the caller can name it without guessing.
        path: PathBuf,
        /// Underlying I/O failure, including permission denied.
        #[source]
        source: std::io::Error,
    },
    /// The file exists but its contents are not the expected document.
    #[error("the secret store at {path} is corrupt: {detail}")]
    Corrupt {
        /// Store path.
        path: PathBuf,
        /// Decoder detail; never contains a secret value.
        detail: String,
    },
}

fn io_error(path: &Path, source: std::io::Error) -> SecretError {
    SecretError::Io {
        path: path.to_path_buf(),
        source,
    }
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

/// Owner-only file backed store.
///
/// The document is a JSON object keyed by service and then account. On Unix the
/// containing directory is created with mode 0700 and the file is written with
/// mode 0600. Values are written only through [`Secret`], so this type has no
/// `Debug` implementation that could expose one.
pub struct FileStore {
    path: PathBuf,
}

type Entries = BTreeMap<String, BTreeMap<String, String>>;

impl FileStore {
    /// Use `path` as the single owner-only document.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The document path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_entries(&self) -> Result<Entries, SecretError> {
        match std::fs::read(&self.path) {
            Ok(bytes) if bytes.is_empty() => Ok(Entries::new()),
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| SecretError::Corrupt {
                path: self.path.clone(),
                detail: error.to_string(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Entries::new()),
            Err(error) => Err(io_error(&self.path, error)),
        }
    }

    fn write_entries(&self, entries: &Entries) -> Result<(), SecretError> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        create_private_directory(parent)?;
        let bytes = serde_json::to_vec_pretty(entries).map_err(|error| SecretError::Corrupt {
            path: self.path.clone(),
            detail: error.to_string(),
        })?;
        write_private_file(&self.path, &bytes)
    }
}

impl SecretStore for FileStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Secret>, SecretError> {
        let entries = self.read_entries()?;
        Ok(entries
            .get(service)
            .and_then(|accounts| accounts.get(account))
            .map(|secret| Secret::new(secret.clone())))
    }

    fn set(&mut self, service: &str, account: &str, secret: Secret) -> Result<(), SecretError> {
        let mut entries = self.read_entries()?;
        entries
            .entry(service.to_owned())
            .or_default()
            .insert(account.to_owned(), secret.expose().to_owned());
        self.write_entries(&entries)
    }

    fn delete(&mut self, service: &str, account: &str) -> Result<(), SecretError> {
        let mut entries = self.read_entries()?;
        let Some(accounts) = entries.get_mut(service) else {
            return Ok(());
        };
        if accounts.remove(account).is_none() {
            return Ok(());
        }
        if accounts.is_empty() {
            entries.remove(service);
        }
        self.write_entries(&entries)
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), SecretError> {
    use std::os::unix::fs::DirBuilderExt;

    if path.exists() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), SecretError> {
    std::fs::create_dir_all(path).map_err(|error| io_error(path, error))
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SecretError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true).mode(0o600);
    let mut file = options.open(path).map_err(|error| io_error(path, error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, error))?;
    file.flush().map_err(|error| io_error(path, error))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SecretError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    let mut file = options.open(path).map_err(|error| io_error(path, error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(path, error))?;
    file.flush().map_err(|error| io_error(path, error))
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

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let unique = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "aevan-secrets-{label}-{}-{nanos}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn file_store_round_trips_and_replaces_cleanly() {
        let temp = TempDir::new("round-trip");
        let path = temp.path().join("aevan").join("secrets.json");
        let mut store = FileStore::new(&path);
        assert!(store
            .get("aevan", "example/totp")
            .expect("read empty")
            .is_none());

        store
            .set("aevan", "example/totp", Secret::new("JBSWY3DPEHPK3PXP"))
            .expect("save");
        let reloaded = FileStore::new(&path)
            .get("aevan", "example/totp")
            .expect("reload")
            .expect("present");
        assert_eq!(reloaded.expose(), "JBSWY3DPEHPK3PXP");

        store
            .set("aevan", "example/totp", Secret::new("GEZDGNBVGY3TQOJQ"))
            .expect("replace");
        let replaced = FileStore::new(&path)
            .get("aevan", "example/totp")
            .expect("reload replacement")
            .expect("present");
        assert_eq!(replaced.expose(), "GEZDGNBVGY3TQOJQ");
        assert!(FileStore::new(&path)
            .get("aevan", "other/totp")
            .expect("other entry")
            .is_none());
    }

    #[test]
    fn file_store_delete_is_idempotent() {
        let temp = TempDir::new("delete");
        let path = temp.path().join("secrets.json");
        let mut store = FileStore::new(&path);
        store
            .set("aevan", "example/totp", Secret::new("JBSWY3DPEHPK3PXP"))
            .expect("save");
        store.delete("aevan", "example/totp").expect("delete");
        assert!(store.get("aevan", "example/totp").expect("read").is_none());
        store.delete("aevan", "example/totp").expect("delete again");
    }

    #[cfg(unix)]
    #[test]
    fn file_store_creates_owner_only_directory_and_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new("modes");
        let directory = temp.path().join("aevan");
        let path = directory.join("secrets.json");
        let mut store = FileStore::new(&path);
        store
            .set("aevan", "example/totp", Secret::new("JBSWY3DPEHPK3PXP"))
            .expect("save");

        let directory_mode = std::fs::metadata(&directory)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&path)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_is_a_typed_error() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new("read-only");
        let directory = temp.path().join("read-only");
        std::fs::create_dir_all(&directory).expect("create directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("make read-only");

        let mut store = FileStore::new(directory.join("secrets.json"));
        let result = store.set("aevan", "example/totp", Secret::new("JBSWY3DPEHPK3PXP"));

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore permissions");
        let error = result.expect_err("a read-only directory cannot store the secret");
        assert!(matches!(error, SecretError::Io { .. }));
        let rendered = error.to_string();
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn an_invalid_store_document_is_a_typed_error_without_the_value() {
        let temp = TempDir::new("corrupt");
        let path = temp.path().join("secrets.json");
        std::fs::write(&path, b"{ this is not json").expect("write corrupt store");
        let store = FileStore::new(&path);
        let error = match store.get("aevan", "example/totp") {
            Ok(_) => panic!("the corrupt document must not decode"),
            Err(error) => error,
        };
        assert!(matches!(error, SecretError::Corrupt { .. }));
        assert!(!error.to_string().contains("this is not json"));
    }
}
