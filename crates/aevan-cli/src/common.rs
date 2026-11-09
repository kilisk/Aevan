//! Shared CLI helpers for profile selection and error mapping.

use aevan_core::{AevanError, AevanResult, Profile, ProfileStore};
use aevan_daemon::StatusReport;
use aevan_proto::{ProtoError, Url};

/// Version of every `--json` document in this binary.
pub const SCHEMA_VERSION: u32 = 1;

/// Version of the redacted `handshake.json` dump.
///
/// Bumped to 2 when the dump gained the per-endpoint probe list and cookie
/// metadata. Existing fields keep their names and meaning.
pub const DUMP_SCHEMA_VERSION: u32 = 2;

/// Load the profile store from its conventional location.
pub fn load_store() -> AevanResult<ProfileStore> {
    ProfileStore::load(&ProfileStore::default_path()?)
}

/// Select a named profile, or the default when no name is given.
pub fn select_profile(name: Option<&str>) -> AevanResult<Profile> {
    let store = load_store()?;
    match name {
        Some(name) => store
            .get(name)
            .cloned()
            .ok_or_else(|| AevanError::Config(format!("profile '{name}' was not found"))),
        None => store.default_profile().cloned().ok_or_else(|| {
            AevanError::Config(
                "no profile is selected; add one with `aevan profile add` or pass a profile name"
                    .into(),
            )
        }),
    }
}

/// Parse a gateway URL, reporting a configuration error rather than a network
/// error for malformed input.
pub fn parse_url(raw: &str) -> AevanResult<Url> {
    Url::parse(raw).map_err(|error| AevanError::Config(error.to_string()))
}

/// Resolve `--url` first, then a profile URL.
pub fn resolve_url(explicit: Option<&str>, profile: Option<&str>) -> AevanResult<Url> {
    if let Some(raw) = explicit {
        return parse_url(raw);
    }
    let profile = select_profile(profile)?;
    parse_url(&profile.url)
}

/// Map a protocol failure to the public exit-code taxonomy.
pub fn network_error(error: ProtoError) -> AevanError {
    match error {
        ProtoError::InvalidUrl(message) => AevanError::Config(format!("invalid URL: {message}")),
        other => AevanError::Network(other.to_string()),
    }
}

/// Print a daemon status snapshot and the endpoint that answered it.
pub fn print_status(status: &StatusReport, json: bool, endpoint: &str) {
    if json {
        #[derive(serde::Serialize)]
        struct Document<'a> {
            schema_version: u32,
            ok: bool,
            command: &'static str,
            endpoint: &'a str,
            status: &'a StatusReport,
        }
        let document = Document {
            schema_version: SCHEMA_VERSION,
            ok: true,
            command: "status",
            endpoint,
            status,
        };
        match serde_json::to_string_pretty(&document) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("aevan: cannot serialise status: {error}"),
        }
        return;
    }

    println!("state: {}", status.state);
    println!("endpoint: {endpoint}");
    if let Some(reason) = &status.reason {
        println!("reason: {reason}");
    }
    if let Some(profile) = &status.profile {
        println!("profile: {profile}");
    }
    if let Some(device) = &status.device {
        println!("device: {device}");
    }
    if let Some(address) = &status.address {
        match status.prefix_len {
            Some(prefix) => println!("address: {address}/{prefix}"),
            None => println!("address: {address}"),
        }
    }
    if let Some(mtu) = status.mtu {
        println!("mtu: {mtu}");
    }
    println!("routes: {}", status.route_count);
    println!(
        "dns: {}",
        if status.dns.is_empty() {
            "none".to_owned()
        } else {
            status.dns.join(", ")
        }
    );
    println!("bytes: in {} / out {}", status.bytes_in, status.bytes_out);
    println!("uptime: {}s", status.uptime_secs);
}
