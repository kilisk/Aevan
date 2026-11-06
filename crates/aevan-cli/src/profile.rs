//! `aevan profile` — manage the non-secret connection profiles.
//!
//! Profiles hold only the gateway URL, realm, optional username and split-tunnel
//! intent. Passwords, tokens and TOTP secrets are never written here; those are
//! requested at connect time and belong to the OS keyring.

use std::path::Path;

use clap::ValueEnum;
use serde::Serialize;

use aevan_core::{AevanError, AevanResult, Profile, ProfileStore, SplitTunnelIntent};
use aevan_proto::Url;

use crate::common;

/// The split-tunnel choice accepted on the command line.
///
/// The profile schema itself stores a [`SplitTunnelIntent`]; this is only the
/// user-facing spelling of the three supported modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SplitTunnelChoice {
    /// Only route the gateway-provided (included) routes.
    Include,
    /// Route everything except explicitly excluded routes.
    Exclude,
    /// Do not split the tunnel.
    None,
}

#[derive(Debug, Serialize)]
struct ProfileDocument {
    schema_version: u32,
    #[serde(flatten)]
    profile: Profile,
}

#[derive(Debug, Serialize)]
struct ListReport {
    schema_version: u32,
    default: Option<String>,
    profiles: Vec<Profile>,
}

#[derive(Debug, Serialize)]
struct RemoveReport {
    schema_version: u32,
    removed: String,
}

/// Add a profile to the conventional store.
pub fn add(
    name: &str,
    url: &str,
    realm: &str,
    user: Option<&str>,
    split_tunnel: Option<SplitTunnelChoice>,
    json: bool,
) -> AevanResult<()> {
    let path = ProfileStore::default_path()?;
    let document = add_at(&path, name, url, realm, user, split_tunnel)?;

    if json {
        print_json(&document)
    } else {
        println!("added profile '{}'", document.profile.name);
        Ok(())
    }
}

/// List the profiles in the conventional store.
pub fn list(json: bool) -> AevanResult<()> {
    let path = ProfileStore::default_path()?;
    let report = list_at(&path)?;

    if json {
        print_json(&report)
    } else {
        print_list(&report);
        Ok(())
    }
}

/// Show one profile from the conventional store.
pub fn show(name: &str, json: bool) -> AevanResult<()> {
    let path = ProfileStore::default_path()?;
    let document = show_at(&path, name)?;

    if json {
        print_json(&document)
    } else {
        print_profile(&document.profile);
        Ok(())
    }
}

/// Remove one profile from the conventional store.
pub fn rm(name: &str, json: bool) -> AevanResult<()> {
    let path = ProfileStore::default_path()?;
    let report = rm_at(&path, name)?;

    if json {
        print_json(&report)
    } else {
        println!("removed profile '{}'", report.removed);
        Ok(())
    }
}

fn add_at(
    path: &Path,
    name: &str,
    url: &str,
    realm: &str,
    user: Option<&str>,
    split_tunnel: Option<SplitTunnelChoice>,
) -> AevanResult<ProfileDocument> {
    validate_url(name, url)?;
    validate_realm(name, realm)?;

    let username = user
        .map(str::trim)
        .filter(|user| !user.is_empty())
        .map(str::to_owned);

    let mut profile = Profile::new(name, url.trim(), realm.trim())?;
    profile.username = username;
    profile.split_tunnel = split_tunnel_intent(split_tunnel);
    profile.validate()?;

    let mut store = ProfileStore::load(path)?;
    store.add(profile.clone())?;
    store.save(path)?;

    Ok(ProfileDocument {
        schema_version: common::SCHEMA_VERSION,
        profile,
    })
}

fn list_at(path: &Path) -> AevanResult<ListReport> {
    let store = ProfileStore::load(path)?;
    let mut profiles: Vec<Profile> = store.profiles.values().cloned().collect();
    profiles.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(ListReport {
        schema_version: common::SCHEMA_VERSION,
        default: store.default,
        profiles,
    })
}

fn show_at(path: &Path, name: &str) -> AevanResult<ProfileDocument> {
    let store = ProfileStore::load(path)?;
    let profile = store.get(name).cloned().ok_or_else(|| missing(name))?;

    Ok(ProfileDocument {
        schema_version: common::SCHEMA_VERSION,
        profile,
    })
}

fn rm_at(path: &Path, name: &str) -> AevanResult<RemoveReport> {
    let mut store = ProfileStore::load(path)?;
    if store.remove(name).is_none() {
        return Err(missing(name));
    }
    store.save(path)?;

    Ok(RemoveReport {
        schema_version: common::SCHEMA_VERSION,
        removed: name.to_owned(),
    })
}

fn validate_url(name: &str, raw: &str) -> AevanResult<()> {
    let url = Url::parse(raw).map_err(|error| {
        AevanError::Config(format!("profile '{name}' has an invalid URL: {error}"))
    })?;
    if !url.is_https() {
        return Err(AevanError::Config(format!(
            "profile '{name}' URL must use https"
        )));
    }
    Ok(())
}

fn validate_realm(name: &str, realm: &str) -> AevanResult<()> {
    let realm = realm.trim();
    if realm.is_empty() {
        return Err(AevanError::Config(format!(
            "profile '{name}' realm must not be empty"
        )));
    }
    if !realm
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        return Err(AevanError::Config(format!(
            "profile '{name}' realm '{realm}' is not a valid realm name"
        )));
    }
    Ok(())
}

fn split_tunnel_intent(choice: Option<SplitTunnelChoice>) -> SplitTunnelIntent {
    match choice {
        // Omitted or "include" means: apply only the routes the gateway pushes.
        None | Some(SplitTunnelChoice::Include) => SplitTunnelIntent::Gateway,
        // "exclude" and "none" both route all traffic; the profile schema has no
        // exclusion list to carry.
        Some(SplitTunnelChoice::Exclude) | Some(SplitTunnelChoice::None) => SplitTunnelIntent::All,
    }
}

fn missing(name: &str) -> AevanError {
    AevanError::Config(format!("profile '{name}' was not found"))
}

fn print_json<T: Serialize>(value: &T) -> AevanResult<()> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| AevanError::Config(format!("cannot serialise profile output: {error}")))?;
    println!("{text}");
    Ok(())
}

fn split_tunnel_label(intent: &SplitTunnelIntent) -> &'static str {
    match intent {
        SplitTunnelIntent::Gateway => "gateway",
        SplitTunnelIntent::All => "all",
        SplitTunnelIntent::Custom(_) => "custom",
    }
}

fn print_list(report: &ListReport) {
    if report.profiles.is_empty() {
        println!("no profiles");
        return;
    }

    println!("aevan profiles (schema {})", report.schema_version);
    for profile in &report.profiles {
        let marker = if report.default.as_deref() == Some(profile.name.as_str()) {
            "*"
        } else {
            " "
        };
        print!(
            "{marker} {}  {}  realm={}  split-tunnel={}",
            profile.name,
            profile.url,
            profile.realm,
            split_tunnel_label(&profile.split_tunnel)
        );
        if let Some(username) = &profile.username {
            print!("  user={username}");
        }
        println!();
    }
}

fn print_profile(profile: &Profile) {
    println!("profile {}", profile.name);
    println!("  url: {}", profile.url);
    println!("  realm: {}", profile.realm);
    println!(
        "  username: {}",
        profile.username.as_deref().unwrap_or("(none)")
    );
    println!(
        "  split tunnel: {}",
        split_tunnel_label(&profile.split_tunnel)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "aevan-cli-profile-{label}-{}-{nanos}",
                std::process::id()
            ));
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

    const URL: &str = "https://vpn.example.net/example_realm";
    const REALM: &str = "example_realm";

    fn assert_config_error(error: AevanError, needle: &str) {
        assert!(matches!(error, AevanError::Config(_)), "{error:?}");
        assert!(
            error.to_string().contains(needle),
            "{error} does not mention {needle}"
        );
    }

    #[test]
    fn round_trips_add_list_show_remove() {
        let dir = TempDir::new("roundtrip");
        let path = dir.file("profiles.toml");

        let added = add_at(&path, "example", URL, REALM, Some("example_user"), None).expect("add");
        assert_eq!(added.profile.name, "example");
        assert_eq!(added.profile.username.as_deref(), Some("example_user"));

        let listed = list_at(&path).expect("list");
        assert_eq!(listed.profiles.len(), 1);
        assert_eq!(listed.profiles[0].name, "example");

        let shown = show_at(&path, "example").expect("show");
        assert_eq!(shown.profile, added.profile);

        let removed = rm_at(&path, "example").expect("remove");
        assert_eq!(removed.removed, "example");
        assert!(list_at(&path).expect("list").profiles.is_empty());

        let store = ProfileStore::load(&path).expect("load");
        assert!(store.get("example").is_none());
    }

    #[test]
    fn duplicate_add_is_refused() {
        let dir = TempDir::new("duplicate");
        let path = dir.file("profiles.toml");

        add_at(&path, "example", URL, REALM, None, None).expect("add");
        let error = add_at(&path, "example", URL, REALM, None, None).expect_err("duplicate");
        assert_config_error(error, "example");
    }

    #[test]
    fn missing_show_and_remove_are_refused() {
        let dir = TempDir::new("missing");
        let path = dir.file("profiles.toml");

        let show_error = show_at(&path, "ghost").expect_err("show missing");
        assert_config_error(show_error, "ghost");

        let remove_error = rm_at(&path, "ghost").expect_err("remove missing");
        assert_config_error(remove_error, "ghost");
    }

    #[test]
    fn list_is_sorted_by_name() {
        let dir = TempDir::new("sorted");
        let path = dir.file("profiles.toml");

        for name in ["zeta", "alpha", "mike"] {
            add_at(&path, name, URL, REALM, None, None).expect("add");
        }

        let listed = list_at(&path).expect("list");
        let names: Vec<_> = listed
            .profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();
        assert_eq!(names, ["alpha", "mike", "zeta"]);
    }

    #[test]
    fn round_trip_store_contains_no_secret_keys() {
        let dir = TempDir::new("no-secrets");
        let path = dir.file("profiles.toml");

        add_at(
            &path,
            "example",
            URL,
            REALM,
            Some("example_user"),
            Some(SplitTunnelChoice::Include),
        )
        .expect("add");

        assert_no_secret_keys(&path);

        // Reload and rewrite to prove the round trip still carries no secrets.
        let store = ProfileStore::load(&path).expect("load");
        store.save(&path).expect("save");
        assert_no_secret_keys(&path);
    }

    fn assert_no_secret_keys(path: &Path) {
        let text = fs::read_to_string(path).expect("read store");
        let lower = text.to_ascii_lowercase();
        for key in ["password", "passwd", "token", "totp", "secret"] {
            assert!(
                !lower.contains(key),
                "profile store leaked '{key}':\n{text}"
            );
        }
    }

    #[test]
    fn rejects_non_https_and_userinfo_urls() {
        let dir = TempDir::new("bad-url");
        let path = dir.file("profiles.toml");

        let http = add_at(&path, "example", "http://example.net/", REALM, None, None)
            .expect_err("http must be rejected");
        assert_config_error(http, "example");

        let userinfo = add_at(
            &path,
            "example",
            "https://user:pass@example.net/",
            REALM,
            None,
            None,
        )
        .expect_err("userinfo must be rejected");
        assert_config_error(userinfo, "example");
    }

    #[test]
    fn rejects_a_bad_realm() {
        let dir = TempDir::new("bad-realm");
        let path = dir.file("profiles.toml");

        let empty = add_at(&path, "example", URL, "", None, None).expect_err("empty realm");
        assert_config_error(empty, "example");

        let spaced =
            add_at(&path, "example", URL, "bad realm", None, None).expect_err("spaced realm");
        assert_config_error(spaced, "example");
    }
}
