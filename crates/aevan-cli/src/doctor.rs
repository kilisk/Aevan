//! `aevan doctor` — diagnose TLS, HTTP, the TUN layer and privileges.
//!
//! The command is deliberately diagnostic: it never sends credentials, never
//! creates a device and never changes routes or DNS. A failed probe is reported
//! in the output and does not abort the command; callers read `ok` (or the human
//! summary) rather than relying only on the exit status.

use std::time::Duration;

use serde::Serialize;

use aevan_core::{AevanError, AevanResult, Profile, ProfileStore};
use aevan_proto::{inspect_https, HttpResponse, TlsObservation, Url};
use aevan_tun::platform;

/// Version of the `doctor --json` document.
pub const SCHEMA_VERSION: u32 = 1;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    ok: bool,
    url: Option<String>,
    realm: RealmReport,
    tls: TlsReport,
    http: HttpReport,
    tun: TunReport,
    privilege: &'static str,
    summary: String,
}

#[derive(Debug, Serialize)]
struct RealmReport {
    status: &'static str,
    value: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct TlsReport {
    status: &'static str,
    protocol: Option<String>,
    chain: Vec<CertReport>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertReport {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
}

#[derive(Debug, Serialize)]
struct HttpReport {
    status: &'static str,
    status_code: Option<u16>,
    reason: Option<String>,
    realm_field_present: Option<bool>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct TunReport {
    status: &'static str,
    backend: &'static str,
    device_present: bool,
    reason: Option<String>,
}

impl TlsReport {
    fn skipped(reason: &str) -> Self {
        Self {
            status: "skipped",
            protocol: None,
            chain: Vec::new(),
            error: Some(reason.to_owned()),
        }
    }

    fn failed(error: String) -> Self {
        Self {
            status: "error",
            protocol: None,
            chain: Vec::new(),
            error: Some(error),
        }
    }

    fn from_observation(observation: &TlsObservation) -> Self {
        Self {
            status: "ok",
            protocol: Some(observation.protocol.clone()),
            chain: observation
                .chain
                .iter()
                .map(|certificate| CertReport {
                    subject: certificate.subject.clone(),
                    issuer: certificate.issuer.clone(),
                    not_before: certificate.not_before.clone(),
                    not_after: certificate.not_after.clone(),
                })
                .collect(),
            error: None,
        }
    }
}

impl HttpReport {
    fn skipped(reason: &str) -> Self {
        Self {
            status: "skipped",
            status_code: None,
            reason: None,
            realm_field_present: None,
            error: Some(reason.to_owned()),
        }
    }

    fn from_response(response: &HttpResponse) -> Self {
        Self {
            status: "ok",
            status_code: Some(response.status_code),
            reason: Some(response.reason.clone()),
            realm_field_present: Some(response.has_realm_field()),
            error: None,
        }
    }
}

impl RealmReport {
    fn configured(value: impl Into<String>) -> Self {
        Self {
            status: "configured",
            value: Some(value.into()),
            error: None,
        }
    }

    fn detected(value: impl Into<String>) -> Self {
        Self {
            status: "detected",
            value: Some(value.into()),
            error: None,
        }
    }

    fn skipped(reason: &str) -> Self {
        Self {
            status: "skipped",
            value: None,
            error: Some(reason.to_owned()),
        }
    }

    fn failed(error: impl Into<String>) -> Self {
        Self {
            status: "error",
            value: None,
            error: Some(error.into()),
        }
    }

    fn label(&self) -> String {
        match (self.status, self.value.as_deref()) {
            ("configured" | "detected", Some(value)) => format!("{value} ({})", self.status),
            (_, Some(value)) => value.to_owned(),
            (_, None) => format!("unknown ({})", self.error.as_deref().unwrap_or("no detail")),
        }
    }
}

/// Run the doctor command. Returns `Ok(())` for a completed diagnosis; failures
/// are represented by `ok: false` in the report rather than an error.
pub fn run(url_arg: Option<&str>, profile: Option<&str>, json: bool) -> AevanResult<()> {
    let (url, selected_profile) = resolve_target(url_arg, profile)?;
    let realm = resolve_realm(selected_profile.as_ref(), url.as_ref());
    let availability = platform::probe();
    let elevation = aevan_tun::elevation();

    let (tls, http, network_ok) = match &url {
        None => (
            TlsReport::skipped("no --url and no default profile"),
            HttpReport::skipped("no --url and no default profile"),
            true,
        ),
        Some(url) => match inspect_https(url, PROBE_TIMEOUT) {
            Ok(inspection) => (
                TlsReport::from_observation(&inspection.tls),
                HttpReport::from_response(&inspection.http),
                true,
            ),
            Err(error) => (
                TlsReport::failed(error.to_string()),
                HttpReport::skipped("TLS did not complete"),
                false,
            ),
        },
    };

    let tun = TunReport {
        status: "unavailable",
        backend: availability.backend,
        device_present: availability.device_present,
        reason: availability.reason,
    };

    let mut report = Report {
        schema_version: SCHEMA_VERSION,
        ok: network_ok,
        url: url.as_ref().map(ToString::to_string),
        realm,
        tls,
        http,
        tun,
        privilege: elevation.as_str(),
        summary: String::new(),
    };
    report.summary = report.build_summary();

    if json {
        let json = serde_json::to_string_pretty(&report).map_err(|error| {
            AevanError::Config(format!("cannot serialise doctor output: {error}"))
        })?;
        println!("{json}");
    } else {
        print_human(&report);
    }

    Ok(())
}

fn resolve_target(
    explicit: Option<&str>,
    profile: Option<&str>,
) -> AevanResult<(Option<Url>, Option<Profile>)> {
    let path = ProfileStore::default_path()?;
    let store = ProfileStore::load(&path)?;
    let selected = match profile {
        Some(name) => Some(store.get(name).cloned().ok_or_else(|| {
            AevanError::Config(format!("profile '{name}' not found in {}", path.display()))
        })?),
        None => store.default_profile().cloned(),
    };

    let url = match explicit {
        Some(raw) => Some(parse_url(raw)?),
        None => selected
            .as_ref()
            .map(|profile| parse_url(&profile.url))
            .transpose()?,
    };
    Ok((url, selected))
}

/// Report the configured realm, or detect one when the profile has none.
///
/// Detection is one credential-free `GET`; doctor does not persist it.
fn resolve_realm(profile: Option<&Profile>, url: Option<&Url>) -> RealmReport {
    if let Some(profile) = profile {
        if profile.has_realm() {
            return RealmReport::configured(profile.realm.clone());
        }
    }

    match url {
        Some(url) => match aevan_proto::detect_realm(url) {
            Ok(realm) => RealmReport::detected(realm),
            Err(error) => RealmReport::failed(error.to_string()),
        },
        None => RealmReport::skipped("no gateway URL"),
    }
}

fn parse_url(raw: &str) -> AevanResult<Url> {
    Url::parse(raw).map_err(|error| AevanError::Config(error.to_string()))
}

impl Report {
    fn build_summary(&self) -> String {
        let tls = match self.tls.status {
            "ok" => format!(
                "tls ok ({}; {} certificate(s))",
                self.tls.protocol.as_deref().unwrap_or("unknown"),
                self.tls.chain.len()
            ),
            "skipped" => "tls skipped".to_owned(),
            _ => format!(
                "tls failed: {}",
                self.tls.error.as_deref().unwrap_or("unknown error")
            ),
        };

        let http = match self.http.status {
            "ok" => {
                let code = self
                    .http
                    .status_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "?".to_owned());
                let reason = self.http.reason.as_deref().unwrap_or("");
                let realm = match self.http.realm_field_present {
                    Some(true) => "present",
                    Some(false) => "absent",
                    None => "unknown",
                };
                format!("http {code} {reason} (realm field {realm})")
            }
            "skipped" => "http skipped".to_owned(),
            _ => format!(
                "http failed: {}",
                self.http.error.as_deref().unwrap_or("unknown error")
            ),
        };

        format!(
            "{tls}; {http}; realm {}; tun {} ({}); privilege {}",
            self.realm.label(),
            self.tun.status,
            self.tun.backend,
            self.privilege
        )
    }
}

fn print_human(report: &Report) {
    println!("aevan doctor (schema {})", report.schema_version);
    println!("  url: {}", report.url.as_deref().unwrap_or("(none)"));
    println!("  realm: {}", report.realm.label());

    match report.tls.status {
        "ok" => {
            println!(
                "  tls: ok ({}; {} certificate(s))",
                report.tls.protocol.as_deref().unwrap_or("unknown"),
                report.tls.chain.len()
            );
            for (index, certificate) in report.tls.chain.iter().enumerate() {
                println!("    [{index}] subject: {}", certificate.subject);
                println!("        issuer:  {}", certificate.issuer);
                println!(
                    "        valid:   {} .. {}",
                    certificate.not_before, certificate.not_after
                );
            }
        }
        status => println!(
            "  tls: {status} ({})",
            report.tls.error.as_deref().unwrap_or("no detail")
        ),
    }

    match report.http.status {
        "ok" => println!(
            "  http: ok ({} {}; realm field {})",
            report.http.status_code.unwrap_or(0),
            report.http.reason.as_deref().unwrap_or(""),
            match report.http.realm_field_present {
                Some(true) => "present",
                Some(false) => "absent",
                None => "unknown",
            }
        ),
        status => println!(
            "  http: {status} ({})",
            report.http.error.as_deref().unwrap_or("no detail")
        ),
    }

    println!(
        "  tun: {} ({}); device present: {}; {}",
        report.tun.status,
        report.tun.backend,
        report.tun.device_present,
        report.tun.reason.as_deref().unwrap_or("no detail")
    );
    println!("  privilege: {}", report.privilege);
    println!("  summary: {}", report.summary);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_realm_is_reported_without_a_request() {
        let profile = Profile::new("example", "https://vpn.example.net/staff", "mygovnet_staff")
            .expect("profile");

        let realm = resolve_realm(Some(&profile), None);
        assert_eq!(realm.status, "configured");
        assert_eq!(realm.value.as_deref(), Some("mygovnet_staff"));
        assert_eq!(realm.label(), "mygovnet_staff (configured)");
    }

    #[test]
    fn no_profile_and_no_url_reports_no_realm() {
        let realm = resolve_realm(None, None);
        assert_eq!(realm.status, "skipped");
        assert!(realm.value.is_none());
    }
}
