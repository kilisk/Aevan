//! Connection profiles and their TOML store.
//!
//! A profile contains no secrets. Passwords and TOTP secrets belong to the OS
//! keyring (`aevan-secrets`) and are only requested at connect time.
//!
//! The profile file must be private and
//! refuse a group/world-writable file. Unix permissions are enforced here; on
//! Windows the user-profile ACL is the operative control (see
//! `docs/PLATFORM-NOTES.md`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{AevanError, AevanResult};

/// What the user wants the tunnel to route.
///
/// The gateway is authoritative: [`SplitTunnelIntent::Gateway`] means "apply
/// only the routes the gateway pushes". `All` is an
/// explicit default-route override, and `Custom` is a user-provided list of
/// CIDR strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelIntent {
    /// Apply only the routes supplied by the gateway (the default).
    #[default]
    Gateway,
    /// Route all traffic through the tunnel.
    All,
    /// Apply the listed CIDR routes in addition to the gateway routes.
    Custom(Vec<String>),
}

/// One gateway profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable, user-visible profile name.
    pub name: String,
    /// Gateway URL, for example `https://vpn.example.net/example_realm`.
    pub url: String,
    /// Authentication realm required by the gateway.
    ///
    /// An empty value means "detect it from the gateway on first use". The
    /// gateway advertises the realm on its sign-in page, so the field is
    /// optional.
    #[serde(default)]
    pub realm: String,
    /// Optional username. Never a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Split-tunnel intent.
    #[serde(default)]
    pub split_tunnel: SplitTunnelIntent,
}

impl Profile {
    /// Build a profile and validate it.
    pub fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        realm: impl Into<String>,
    ) -> AevanResult<Self> {
        let profile = Self {
            name: name.into(),
            url: url.into(),
            realm: realm.into(),
            username: None,
            split_tunnel: SplitTunnelIntent::default(),
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Validate the profile fields without touching the network.
    pub fn validate(&self) -> AevanResult<()> {
        if self.name.trim().is_empty() {
            return Err(AevanError::Config("profile name must not be empty".into()));
        }
        if self.name.chars().any(char::is_whitespace) {
            return Err(AevanError::Config(
                "profile name must not contain whitespace".into(),
            ));
        }
        if !self.url.starts_with("https://") {
            return Err(AevanError::Config(format!(
                "profile '{}' URL must start with https://",
                self.name
            )));
        }
        if self.url.contains(char::is_whitespace) {
            return Err(AevanError::Config(format!(
                "profile '{}' URL must not contain whitespace",
                self.name
            )));
        }
        if self.realm.contains(char::is_whitespace) {
            return Err(AevanError::Config(format!(
                "profile '{}' realm must not contain whitespace",
                self.name
            )));
        }
        if let SplitTunnelIntent::Custom(routes) = &self.split_tunnel {
            if routes.iter().any(|route| route.trim().is_empty()) {
                return Err(AevanError::Config(format!(
                    "profile '{}' has an empty split-tunnel route",
                    self.name
                )));
            }
        }
        Ok(())
    }

    /// Path-like identifier used for keyring entries and logs.
    pub fn key(&self) -> &str {
        &self.name
    }

    /// Whether the profile carries a realm instead of asking for detection.
    pub fn has_realm(&self) -> bool {
        !self.realm.trim().is_empty()
    }
}

/// Where a profile's realm came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmSource {
    /// The profile already carried the realm.
    Configured,
    /// The realm was read from the gateway on first use.
    Detected,
}

impl RealmSource {
    /// Whether this run performed detection.
    pub fn is_detected(self) -> bool {
        matches!(self, Self::Detected)
    }
}

/// All profiles plus the selected default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStore {
    /// Name of the default profile, if one is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Profiles keyed by name.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ProfileStore {
    /// Load the store from `path`.
    ///
    /// A missing file yields an empty store. An existing file must be private
    /// on Unix; a group/world-writable file is refused rather than read.
    pub fn load(path: &Path) -> AevanResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        check_private_permissions(path)?;
        let text = fs::read_to_string(path).map_err(|error| {
            AevanError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let store: Self = toml::from_str(&text)?;
        for profile in store.profiles.values() {
            profile.validate()?;
        }
        if let Some(default) = &store.default {
            if !store.profiles.contains_key(default) {
                return Err(AevanError::Config(format!(
                    "default profile '{default}' is not present in {}",
                    path.display()
                )));
            }
        }
        Ok(store)
    }

    /// Serialise and write the store to `path`, creating parent directories and
    /// applying owner-only permissions where the platform supports them.
    pub fn save(&self, path: &Path) -> AevanResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AevanError::Config(format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        let text = toml::to_string_pretty(self)?;
        fs::write(path, text).map_err(|error| {
            AevanError::Config(format!("cannot write {}: {error}", path.display()))
        })?;
        set_private_permissions(path)?;
        Ok(())
    }

    /// Insert a profile, refusing a duplicate name.
    pub fn add(&mut self, profile: Profile) -> AevanResult<()> {
        profile.validate()?;
        if self.profiles.contains_key(&profile.name) {
            return Err(AevanError::Config(format!(
                "profile '{}' already exists",
                profile.name
            )));
        }
        self.profiles.insert(profile.name.clone(), profile);
        Ok(())
    }

    /// Insert or replace a profile.
    pub fn upsert(&mut self, profile: Profile) -> AevanResult<()> {
        profile.validate()?;
        self.profiles.insert(profile.name.clone(), profile);
        Ok(())
    }

    /// Look up a profile by name.
    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// Resolve the realm for `name`, detecting it when the profile has none.
    ///
    /// The returned [`RealmSource`] says whether detection ran. The store is
    /// updated in memory when it did; the caller saves the store to persist the
    /// value for later runs. An explicit realm is never passed to `detect`.
    pub fn ensure_realm<F>(&mut self, name: &str, detect: F) -> AevanResult<(String, RealmSource)>
    where
        F: FnOnce(&str) -> AevanResult<String>,
    {
        let profile = self
            .profiles
            .get(name)
            .cloned()
            .ok_or_else(|| AevanError::Config(format!("profile '{name}' was not found")))?;

        if profile.has_realm() {
            return Ok((profile.realm, RealmSource::Configured));
        }

        let realm = detect(&profile.url)?.trim().to_owned();
        if realm.is_empty() {
            return Err(AevanError::Config(
                "the sign-in page did not advertise a realm; pass --realm <value>".into(),
            ));
        }

        let mut detected = profile;
        detected.realm = realm.clone();
        detected.validate()?;
        self.profiles.insert(name.to_owned(), detected);
        Ok((realm, RealmSource::Detected))
    }

    /// Remove a profile. Clears the default if it named the removed profile.
    pub fn remove(&mut self, name: &str) -> Option<Profile> {
        if self.default.as_deref() == Some(name) {
            self.default = None;
        }
        self.profiles.remove(name)
    }

    /// Select the default profile, which must already exist.
    pub fn set_default(&mut self, name: &str) -> AevanResult<()> {
        if !self.profiles.contains_key(name) {
            return Err(AevanError::Config(format!(
                "cannot select missing profile '{name}' as default"
            )));
        }
        self.default = Some(name.to_owned());
        Ok(())
    }

    /// Resolve the default profile.
    pub fn default_profile(&self) -> Option<&Profile> {
        self.default
            .as_deref()
            .and_then(|name| self.profiles.get(name))
    }

    /// A profile by explicit name, falling back to the default.
    pub fn select(&self, name: Option<&str>) -> Option<&Profile> {
        match name {
            Some(name) => self.profiles.get(name),
            None => self.default_profile(),
        }
    }

    /// The conventional store path for this user.
    pub fn default_path() -> AevanResult<PathBuf> {
        crate::paths::default_profiles_path()
    }
}

/// Refuse a profile file that group or world users can modify.
#[cfg(unix)]
pub fn check_private_permissions(path: &Path) -> AevanResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(AevanError::Config(format!(
            "{} is group/world-writable (mode {mode:o}); run `chmod 600 {}`",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

/// Windows and other platforms rely on the per-user directory ACL.
#[cfg(not(unix))]
pub fn check_private_permissions(_path: &Path) -> AevanResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> AevanResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> AevanResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("aevan-core-{label}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample() -> Profile {
        Profile::new(
            "example",
            "https://vpn.example.net/example_realm",
            "example_realm",
        )
        .expect("profile")
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = TempDir::new("roundtrip");
        let path = dir.file("profiles.toml");

        let mut store = ProfileStore::default();
        let mut profile = sample();
        profile.username = Some("example_user".into());
        profile.split_tunnel = SplitTunnelIntent::Custom(vec!["10.0.0.0/8".into()]);
        store.add(profile).expect("add");
        store.set_default("example").expect("default");
        store.save(&path).expect("save");

        let loaded = ProfileStore::load(&path).expect("load");
        assert_eq!(loaded, store);
        assert_eq!(loaded.default.as_deref(), Some("example"));
        assert_eq!(
            loaded
                .get("example")
                .and_then(|profile| profile.username.as_deref()),
            Some("example_user")
        );
    }

    #[test]
    fn missing_file_is_an_empty_store() {
        let dir = TempDir::new("missing");
        let store = ProfileStore::load(&dir.file("nope.toml")).expect("load");
        assert!(store.profiles.is_empty());
        assert!(store.default.is_none());
    }

    #[test]
    fn duplicate_add_is_refused_but_upsert_replaces() {
        let mut store = ProfileStore::default();
        store.add(sample()).expect("add");
        assert!(store.add(sample()).is_err());

        let mut replacement = sample();
        replacement.realm = "other".into();
        store.upsert(replacement).expect("upsert");
        assert_eq!(store.get("example").expect("profile").realm, "other");
    }

    #[test]
    fn default_must_exist() {
        let mut store = ProfileStore::default();
        assert!(store.set_default("ghost").is_err());
        store.add(sample()).expect("add");
        store.set_default("example").expect("default");
        assert_eq!(store.default_profile().map(Profile::key), Some("example"));
    }

    #[test]
    fn removing_the_default_clears_it() {
        let mut store = ProfileStore::default();
        store.add(sample()).expect("add");
        store.set_default("example").expect("default");
        assert!(store.remove("example").is_some());
        assert!(store.default.is_none());
        assert!(store.get("example").is_none());
    }

    #[test]
    fn rejects_invalid_fields() {
        assert!(Profile::new("", "https://example.net/", "realm").is_err());
        assert!(Profile::new("has space", "https://example.net/", "realm").is_err());
        assert!(Profile::new("name", "http://example.net/", "realm").is_err());
        assert!(Profile::new("name", "https://example.net/", "bad realm").is_err());

        let mut profile = sample();
        profile.split_tunnel = SplitTunnelIntent::Custom(vec![" ".into()]);
        assert!(profile.validate().is_err());
    }

    #[test]
    fn an_empty_realm_is_valid_and_round_trips() {
        let dir = TempDir::new("empty-realm");
        let path = dir.file("profiles.toml");

        let mut store = ProfileStore::default();
        let profile = Profile::new("auto", "https://vpn.example.net/staff", "").expect("profile");
        store.add(profile).expect("add");
        store.save(&path).expect("save");

        let text = fs::read_to_string(&path).expect("read");
        assert!(text.contains("realm = \"\""), "{text}");

        let loaded = ProfileStore::load(&path).expect("load");
        let loaded = loaded.get("auto").expect("profile");
        assert!(loaded.realm.is_empty());
        assert!(!loaded.has_realm());
    }

    #[test]
    fn a_missing_realm_deserialises_as_detect() {
        let text = r#"
            [profiles.auto]
            name = "auto"
            url = "https://vpn.example.net/staff"
        "#;
        let store: ProfileStore = toml::from_str(text).expect("store");
        let profile = store.get("auto").expect("profile");
        assert!(profile.realm.is_empty());
        assert!(!profile.has_realm());
    }

    #[test]
    fn detection_runs_once_and_is_persisted() {
        use std::cell::Cell;

        let dir = TempDir::new("detect-once");
        let path = dir.file("profiles.toml");

        let mut store = ProfileStore::default();
        store
            .add(Profile::new("auto", "https://vpn.example.net/staff", "").expect("profile"))
            .expect("add");

        let calls = Cell::new(0);
        let (realm, source) = store
            .ensure_realm("auto", |url| {
                calls.set(calls.get() + 1);
                assert_eq!(url, "https://vpn.example.net/staff");
                Ok("mygovnet_staff".into())
            })
            .expect("detect");
        assert_eq!(realm, "mygovnet_staff");
        assert_eq!(source, RealmSource::Detected);
        assert_eq!(calls.get(), 1);
        assert_eq!(store.get("auto").expect("profile").realm, "mygovnet_staff");

        store.save(&path).expect("save");

        let mut reloaded = ProfileStore::load(&path).expect("load");
        let (realm, source) = reloaded
            .ensure_realm("auto", |_| {
                panic!("a stored realm must not be detected again")
            })
            .expect("configured");
        assert_eq!(realm, "mygovnet_staff");
        assert_eq!(source, RealmSource::Configured);
    }

    #[test]
    fn an_explicit_realm_is_never_replaced_by_detection() {
        let mut store = ProfileStore::default();
        store.add(sample()).expect("add");

        let (realm, source) = store
            .ensure_realm("example", |_| {
                panic!("an explicit realm must not trigger detection")
            })
            .expect("configured");
        assert_eq!(realm, "example_realm");
        assert_eq!(source, RealmSource::Configured);
        assert_eq!(
            store.get("example").expect("profile").realm,
            "example_realm"
        );
    }

    #[test]
    fn ensure_realm_reports_a_missing_profile() {
        let mut store = ProfileStore::default();
        let error = store
            .ensure_realm("ghost", |_| Ok("realm".into()))
            .expect_err("missing profile");
        assert!(matches!(error, AevanError::Config(_)));
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("mode");
        let path = dir.file("profiles.toml");
        ProfileStore::default().save(&path).expect("save");

        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_world_writable_store() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("world-writable");
        let path = dir.file("profiles.toml");
        fs::write(&path, "").expect("write");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o666);
        fs::set_permissions(&path, permissions).expect("chmod");

        let error = ProfileStore::load(&path).expect_err("must refuse");
        assert!(matches!(error, AevanError::Config(_)));
    }
}
