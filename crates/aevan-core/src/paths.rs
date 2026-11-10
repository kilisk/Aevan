//! Well-known locations for the profile store.
//!
//! The layout is intentionally boring and local: one TOML file under the
//! per-user configuration directory. Secrets are never stored in the profile
//! file. Windows keeps a TOTP secret in Credential Manager; macOS and Linux use
//! a separate owner-only file under the same configuration directory.

use std::path::PathBuf;

use crate::{AevanError, AevanResult};

/// File name of the profile store inside the configuration directory.
pub const PROFILES_FILE: &str = "profiles.toml";

/// File name of the owner-only secret store used on macOS and Linux.
pub const SECRETS_FILE: &str = "secrets.json";

/// Directory used for per-user configuration.
pub fn config_dir() -> AevanResult<PathBuf> {
    if let Some(dir) = std::env::var_os("AEVAN_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    base_config_dir()
}

#[cfg(target_os = "windows")]
fn base_config_dir() -> AevanResult<PathBuf> {
    let base = std::env::var_os("APPDATA").ok_or_else(|| {
        AevanError::Config("APPDATA is not set; cannot locate the profile store".into())
    })?;
    Ok(PathBuf::from(base).join("aevan"))
}

#[cfg(target_os = "macos")]
fn base_config_dir() -> AevanResult<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        AevanError::Config("HOME is not set; cannot locate the profile store".into())
    })?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("aevan"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn base_config_dir() -> AevanResult<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(base).join("aevan"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        AevanError::Config("HOME is not set; cannot locate the profile store".into())
    })?;
    Ok(PathBuf::from(home).join(".config").join("aevan"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn base_config_dir() -> AevanResult<PathBuf> {
    Err(AevanError::Unsupported(
        "no configuration directory convention for this platform".into(),
    ))
}

/// Full path of the profile store (`<config_dir>/profiles.toml`).
pub fn default_profiles_path() -> AevanResult<PathBuf> {
    Ok(config_dir()?.join(PROFILES_FILE))
}

/// Alias kept for callers that only care about "the config file".
pub fn default_config_path() -> AevanResult<PathBuf> {
    default_profiles_path()
}

/// Full path of the owner-only secret store (`<config_dir>/secrets.json`).
pub fn default_secrets_path() -> AevanResult<PathBuf> {
    Ok(config_dir()?.join(SECRETS_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_path_ends_with_the_expected_file() {
        match default_profiles_path() {
            Ok(path) => assert!(path.ends_with(PROFILES_FILE)),
            Err(error) => {
                // A test runner without HOME/APPDATA is a valid environment;
                // the error must be the typed configuration error, not a panic.
                assert!(matches!(error, AevanError::Config(_)));
            }
        }
    }

    #[test]
    fn secrets_path_ends_with_the_expected_file() {
        match default_secrets_path() {
            Ok(path) => assert!(path.ends_with(SECRETS_FILE)),
            Err(error) => assert!(matches!(error, AevanError::Config(_))),
        }
    }
}
