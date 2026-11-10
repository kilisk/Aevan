//! `aevan config` — stage 3, typed oNCP configuration.
//!
//! With `--from-file` (or `-` for stdin) the command is completely offline and
//! is the replay path for a saved binary KMP/TLV blob. With `--live` it performs
//! exactly one authentication attempt, then probes the Network Connect launch
//! path and the legacy oNCP entry in that single session. Without either, it reads
//! the configuration cached by a successful `aevan login` in this process.
//!
//! NC configuration is binary oNCP, not a text body. A text file is rejected
//! with an explanation that points at the synthetic fixture.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use aevan_core::{AevanError, AevanResult, Profile};
use aevan_nc::NcpConfig;
use aevan_proto::{HttpClient, HttpTransport, Url};

use crate::{common, dump, login, probe};

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    source: String,
    config: NcpConfig,
}

/// `aevan config --live` with its resolved profile.
#[derive(Debug)]
struct ConfigLive {
    profile: Profile,
}

impl ConfigLive {
    fn new(profile_name: Option<&str>) -> AevanResult<Self> {
        let (profile, _) = common::select_profile_with_realm(profile_name)?;
        Ok(Self { profile })
    }
}

/// Run the config command.
pub fn run(
    profile: Option<&str>,
    from_file: Option<&str>,
    live: bool,
    dump_dir: Option<&str>,
    keep_session: bool,
    json: bool,
) -> AevanResult<()> {
    if live && from_file.is_some() {
        return Err(AevanError::Config(
            "--live and --from-file are mutually exclusive".into(),
        ));
    }
    if !live && dump_dir.is_some() {
        return Err(AevanError::Config("--dump-dir requires --live".into()));
    }
    if !live && keep_session {
        return Err(AevanError::Config("--keep-session requires --live".into()));
    }
    if live {
        return run_live(ConfigLive::new(profile)?, dump_dir, keep_session, json);
    }

    let (source, config) = match from_file {
        Some("-") => {
            let mut body = Vec::new();
            std::io::stdin().read_to_end(&mut body)?;
            ("stdin".to_owned(), parse(&body)?)
        }
        Some(path) => {
            let body = fs::read(path)
                .map_err(|error| AevanError::Config(format!("cannot read {path}: {error}")))?;
            (path.to_owned(), parse(&body)?)
        }
        None => {
            let config = aevan_nc::last_ncp_config().ok_or_else(|| {
                AevanError::Config(
                    "no NCP config from a login in this process; pass --from-file PATH, - or --live"
                        .into(),
                )
            })?;
            ("last-login".to_owned(), config)
        }
    };

    print_report(
        &Report {
            schema_version: common::SCHEMA_VERSION,
            source,
            config,
        },
        json,
    )
}

fn run_live(
    live: ConfigLive,
    dump_dir: Option<&str>,
    keep_session: bool,
    json: bool,
) -> AevanResult<()> {
    let mut session = login::authenticate_profile(&live.profile, false)?;

    let gateway = common::parse_url(&live.profile.url)?;
    let hostname = local_hostname();

    let mut oncp = probe::LiveOncpRunner;
    let run = probe::run_probes(
        &mut session.client,
        &gateway,
        &hostname,
        &mut oncp,
        probe::PROBE_TIMEOUT,
    );

    let config = run.config.clone();
    let handshake = run.handshake.clone();
    let failure = if config.is_none() {
        Some(probe::failure_summary(&run))
    } else {
        None
    };

    let cookie_values = session.client.cookie_jar().secret_values();
    let logout = perform_logout(&mut session.client, &gateway, keep_session);

    if let Some(directory) = dump_dir {
        let input = dump::DumpInput {
            redirects: &session.probe.redirects,
            login_status: session.final_response.status_code,
            login_reason: &session.final_response.reason,
            login_headers: &session.final_response.headers,
            token_submitted: session.token_submitted,
            login_fields: &session.login_field_names,
            continuation: session.continuation.as_ref(),
            probes: &run.probes,
            probes_stopped_early: run.stopped_early,
            cookie_values: &cookie_values,
            logout,
            handshake: handshake.as_ref(),
            config: config.as_ref(),
            error: failure.as_deref(),
        };
        let document = dump::render(&input);
        let path = dump::write_dump(Path::new(directory), &document)?;
        eprintln!("dump: {}", path.display());
    }

    let Some(config) = config else {
        return Err(AevanError::Unsupported(
            failure.unwrap_or_else(|| "no probe returned a KMP 301".into()),
        ));
    };

    print_report(
        &Report {
            schema_version: common::SCHEMA_VERSION,
            source: "live".to_owned(),
            config,
        },
        json,
    )
}

fn perform_logout<T: HttpTransport>(
    client: &mut HttpClient<T>,
    gateway: &Url,
    keep_session: bool,
) -> dump::LogoutDump {
    if keep_session {
        tracing::debug!("session retained by --keep-session");
        return dump::LogoutDump::skipped();
    }

    let url = match gateway.join("/dana-na/auth/logout.cgi") {
        Ok(url) => url,
        Err(error) => {
            tracing::debug!(%error, "logout URL could not be built");
            return dump::LogoutDump::from_error(&error.to_string());
        }
    };

    match client.get_once(&url) {
        Ok(response) => {
            tracing::debug!(status = response.status_code, "logout request completed");
            dump::LogoutDump::from_response(&response)
        }
        Err(error) => {
            tracing::debug!(%error, "logout request failed");
            dump::LogoutDump::from_error(&error.to_string())
        }
    }
}

pub(crate) fn local_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "aevan".to_owned())
}

fn print_report(report: &Report, json: bool) -> AevanResult<()> {
    if json {
        let text = serde_json::to_string_pretty(report)
            .map_err(|error| AevanError::Config(format!("cannot serialise NCP config: {error}")))?;
        println!("{text}");
    } else {
        print_human(report);
    }
    Ok(())
}

fn parse(body: &[u8]) -> AevanResult<NcpConfig> {
    NcpConfig::parse_binary(body).map_err(|error| AevanError::Unsupported(error.to_string()))
}

fn print_human(report: &Report) {
    let config = &report.config;
    println!(
        "aevan config (schema {}; source {})",
        report.schema_version, report.source
    );
    if let Some(ipv4) = &config.ipv4 {
        println!(
            "  ipv4: {}{}{}",
            ipv4.address,
            ipv4.netmask
                .map(|mask| format!(" netmask {mask}"))
                .unwrap_or_default(),
            ipv4.prefix_len
                .map(|prefix| format!("/{prefix}"))
                .unwrap_or_default()
        );
    }
    if let Some(ipv6) = &config.ipv6 {
        println!(
            "  ipv6: {}{}",
            ipv6.address,
            ipv6.prefix_len
                .map(|prefix| format!("/{prefix}"))
                .unwrap_or_default()
        );
    }
    if let Some(gateway) = &config.gateway {
        println!("  gateway: {gateway}");
    }
    let routes = config
        .split_routes
        .iter()
        .map(|route| format!("{}/{}", route.network, route.prefix_len))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  split routes: [{}]", routes);
    let excludes = config
        .exclude_routes
        .iter()
        .map(|route| format!("{}/{}", route.network, route.prefix_len))
        .collect::<Vec<_>>()
        .join(", ");
    println!("  exclude routes: [{}]", excludes);
    let dns = config
        .dns
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    println!("  dns: [{}]", dns);
    let wins = config
        .wins
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    println!("  wins: [{}]", wins);
    println!(
        "  mtu: {}",
        config
            .mtu
            .map(|mtu| mtu.to_string())
            .unwrap_or_else(|| "-".to_owned())
    );
    if let Some(esp) = &config.esp {
        println!(
            "  esp: {}/{} on udp/{}",
            esp.encryption
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            esp.authentication
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            esp.udp_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "-".to_owned())
        );
        println!(
            "  esp lifetime: {} bytes / {} seconds; replay protection: {}; outbound SPI: {}",
            esp.lifetime_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            esp.lifetime_seconds
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            esp.replay_protection
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            esp.outbound_spi
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "-".to_owned())
        );
    }
    println!(
        "  fallback timeout: {}",
        config
            .fallback_timeout_secs
            .map(|seconds| format!("{seconds}s"))
            .unwrap_or_else(|| "-".to_owned())
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_proto::{HttpResponse, ScriptedTransport};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn keep_session_skips_the_logout_request() {
        let transport = ScriptedTransport::new([]);
        let mut client = HttpClient::new(transport);
        let gateway = Url::parse("https://example.net/example_realm/").expect("url");

        let logout = perform_logout(&mut client, &gateway, true);

        assert_eq!(logout.state, "skipped");
        assert!(logout.status_code.is_none());
        assert!(client.transport().requests().is_empty());
    }

    #[test]
    fn logout_makes_exactly_one_get_with_the_session_cookies() {
        let transport = ScriptedTransport::new([HttpResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: vec![("Set-Cookie".into(), "DSID=secret; Path=/".into())],
            body: Vec::new(),
        }]);
        let mut client = HttpClient::new(transport);
        let gateway = Url::parse("https://example.net/example_realm/").expect("url");

        let logout = perform_logout(&mut client, &gateway, false);

        assert_eq!(logout.state, "attempted");
        assert_eq!(logout.status_code, Some(200));
        assert_eq!(logout.headers[0].value, "[REDACTED]");
        let requests = client.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url.path_and_query, "/dana-na/auth/logout.cgi");
    }

    #[test]
    fn config_live_refuses_without_a_profile() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory =
            std::env::temp_dir().join(format!("aevan-config-live-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&directory);

        let previous = std::env::var_os("AEVAN_CONFIG_DIR");
        std::env::set_var("AEVAN_CONFIG_DIR", &directory);
        let result = ConfigLive::new(None);
        match previous {
            Some(value) => std::env::set_var("AEVAN_CONFIG_DIR", value),
            None => std::env::remove_var("AEVAN_CONFIG_DIR"),
        }
        let _ = std::fs::remove_dir_all(&directory);

        let error = result.expect_err("must refuse without a profile");
        assert!(matches!(error, AevanError::Config(_)));
        assert!(error.to_string().contains("profile"));
    }
}
